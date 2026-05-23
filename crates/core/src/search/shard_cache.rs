//! on-device LRU shard cache.
//!
//! `docs/DESIGN.md §7` and call for
//! avoiding repeated decryption of the same cold index shard
//! when the user issues two searches in a row that fan out to
//! the same `(conversation_id, time_bucket)` pair. The cold
//! fan-out in [`crate::search::query_engine::QueryEngine::execute_search_with_cold_source`]
//! consults a [`ShardCache`] before paying for transport +
//! decrypt; on a cache hit the cached `Vec<FtsRow>` /
//! `Vec<FuzzyRow>` is reused directly.
//!
//! The cache is **bounded by an explicit byte budget** (default
//! 50 MB). Eviction is least-recently-used: the moment an
//! insert pushes [`ShardCache::current_bytes`] past the budget,
//! the cache evicts entries in the order they were last
//! `get` / `put`-touched until the size drops back under the
//! limit. Tracking is approximate — we charge each entry the
//! sum of `mem::size_of_val` over its row vector — but the
//! number is stable and lets the orchestration layer reason
//! about "the cache holds at most ~50 MB on device".
//!
//! The cache is also **kind-tagged**: a `(conv, bucket)` pair
//! can hold a `Text`, `Fuzzy`, *and* `Bloom` entry simultaneously
//! because the cold path fetches all three independently and a
//! repeated query touches the same trio.

use std::collections::HashMap;
use std::mem;

use crate::formats::search_shard::IndexType;
use crate::models::resource_gate::{DeviceResources, ResourceGate};
use crate::search::query_engine::ColdShardSource;
use crate::search::shard_builder::{BloomFilter, FtsRow, FuzzyRow};
use crate::Error;

/// Default cache budget: 50 MB.
pub const DEFAULT_SHARD_CACHE_BUDGET_BYTES: usize = 50 * 1024 * 1024;

/// Composite key identifying a single decrypted shard payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShardCacheKey {
    /// Conversation the shard belongs to (plaintext id, not the
    /// keyed hash — the cache is on-device only).
    pub conversation_id: String,
    /// Coarse time bucket the shard covers (e.g. `"2026-04"`).
    pub time_bucket: String,
    /// Which kind of index the shard contains.
    pub index_type: IndexType,
}

impl ShardCacheKey {
    /// Convenience constructor.
    pub fn new(
        conversation_id: impl Into<String>,
        time_bucket: impl Into<String>,
        index_type: IndexType,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            time_bucket: time_bucket.into(),
            index_type,
        }
    }
}

/// One cached, already-decrypted shard payload.
///
/// Only the kinds that the cold fan-out actually consults today
/// (`Text`, `Fuzzy`, `Bloom`) carry a payload variant — `Vector`
/// and `Media` shards are not yet hot in the search path so they
/// don't get a `CachedShard` representation here.
#[derive(Debug, Clone)]
pub enum CachedShard {
    /// Decrypted text-index rows.
    Text(Vec<FtsRow>),
    /// Decrypted fuzzy-token rows.
    Fuzzy(Vec<FuzzyRow>),
    /// Decrypted bloom filter, ready for `maybe_contains` checks.
    Bloom(BloomFilter),
}

impl CachedShard {
    /// Approximate on-heap cost of the payload, used to enforce
    /// the cache's [`ShardCache`] budget. Stable so the test
    /// suite can assert on size accounting.
    pub fn approximate_bytes(&self) -> usize {
        match self {
            CachedShard::Text(rows) => approximate_text_rows_bytes(rows),
            CachedShard::Fuzzy(rows) => approximate_fuzzy_rows_bytes(rows),
            CachedShard::Bloom(filter) => approximate_bloom_filter_bytes(filter),
        }
    }
}

fn approximate_text_rows_bytes(rows: &[FtsRow]) -> usize {
    // Use `String::len` (logical byte length) rather than
    // `String::capacity` so the accounting is deterministic
    // across rebuilds: cloning a `Vec<FtsRow>` produces strings
    // whose `capacity` equals `len`, while `format!` /
    // `String::with_capacity(_)` constructed inputs may carry
    // a slightly larger allocator-rounded capacity.
    let mut total = mem::size_of_val(rows);
    for row in rows {
        total += row.message_id.len()
            + row.conversation_id.len()
            + row.sender_id.len()
            + row.text_content.len();
    }
    total
}

fn approximate_fuzzy_rows_bytes(rows: &[FuzzyRow]) -> usize {
    let mut total = mem::size_of_val(rows);
    for row in rows {
        total += row.token.len() + row.script.len() + row.message_id.len();
    }
    total
}

fn approximate_bloom_filter_bytes(filter: &BloomFilter) -> usize {
    // The on-heap cost of a `BloomFilter` is dominated by the bit
    // vector. Using the `bit_count` rather than `Vec::capacity` so
    // accounting is deterministic across rebuilds with the same
    // sizing parameters.
    mem::size_of::<BloomFilter>() + (filter.bit_count() as usize).div_ceil(8)
}

/// One entry in the cache: payload + monotonic last-touch counter.
#[derive(Debug, Clone)]
struct Entry {
    shard: CachedShard,
    bytes: usize,
    last_used: u64,
}

/// LRU-eviction shard cache.
///
/// Backed by a `HashMap<ShardCacheKey, Entry>` plus a monotonic
/// counter (`tick`). Each `get` / `put` advances the counter and
/// stamps the touched entry; eviction sorts by stamp ascending
/// and drops entries until `current_bytes <= max_bytes`.
///
/// The implementation is intentionally simple — the expected
/// cache size is in the low hundreds of entries, so the
/// `O(n log n)` per-eviction cost of a sort is fine.
#[derive(Debug)]
pub struct ShardCache {
    entries: HashMap<ShardCacheKey, Entry>,
    bytes: usize,
    max_bytes: usize,
    tick: u64,
}

impl ShardCache {
    /// Build a cache with the supplied byte budget. Pass
    /// [`DEFAULT_SHARD_CACHE_BUDGET_BYTES`] for the documented
    /// 50 MB default.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
            max_bytes,
            tick: 0,
        }
    }

    /// Build a cache with the documented 50 MB default budget.
    pub fn with_default_budget() -> Self {
        Self::new(DEFAULT_SHARD_CACHE_BUDGET_BYTES)
    }

    /// Look up an entry. Returns `Some(&CachedShard)` and stamps
    /// the entry as most-recently-used on hit, `None` on miss.
    pub fn get(&mut self, key: &ShardCacheKey) -> Option<&CachedShard> {
        self.tick = self.tick.saturating_add(1);
        let tick = self.tick;
        let entry = self.entries.get_mut(key)?;
        entry.last_used = tick;
        Some(&entry.shard)
    }

    /// Insert (or overwrite) an entry. Triggers LRU eviction when
    /// the new size pushes [`Self::current_bytes`] above the
    /// configured budget.
    pub fn put(&mut self, key: ShardCacheKey, shard: CachedShard) {
        self.tick = self.tick.saturating_add(1);
        let bytes = shard.approximate_bytes();
        if let Some(prev) = self.entries.remove(&key) {
            self.bytes = self.bytes.saturating_sub(prev.bytes);
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.entries.insert(
            key,
            Entry {
                shard,
                bytes,
                last_used: self.tick,
            },
        );
        self.evict_lru();
    }

    /// Evict least-recently-used entries until
    /// `current_bytes <= max_bytes`.
    pub fn evict_lru(&mut self) {
        if self.bytes <= self.max_bytes {
            return;
        }
        let mut by_age: Vec<(ShardCacheKey, u64)> = self
            .entries
            .iter()
            .map(|(k, e)| (k.clone(), e.last_used))
            .collect();
        by_age.sort_by_key(|(_, t)| *t);
        for (key, _) in by_age {
            if self.bytes <= self.max_bytes {
                break;
            }
            if let Some(entry) = self.entries.remove(&key) {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
            }
        }
    }

    /// Drop every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }

    /// Approximate current on-heap usage in bytes.
    pub fn current_bytes(&self) -> usize {
        self.bytes
    }

    /// Configured byte budget.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Number of entries currently held in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds zero entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ShardCache {
    fn default() -> Self {
        Self::with_default_budget()
    }
}

/// idle-time shard
/// cache warming.
///
/// Pre-fetches and decrypts cold shards for the supplied
/// `(conversation_id, time_bucket)` pairs into the shared
/// [`ShardCache`], but only when [`ResourceGate::should_warm_shards`]
/// agrees the device is genuinely idle. Returns the number of
/// entries that were freshly populated; entries already present
/// in the cache are left alone.
///
/// The function is a no-op (returns `Ok(0)`) when:
///
/// * the resource gate refuses (battery / thermal / metered net),
/// * `recent` is empty,
/// * `cache.max_bytes == 0`.
///
/// Errors from the cold source are surfaced unchanged so the
/// caller can decide whether to back off; partial progress made
/// before the error is preserved in the cache.
pub fn warm_shard_cache(
    cache: &mut ShardCache,
    cold_source: &dyn ColdShardSource,
    gate: &ResourceGate,
    resources: &DeviceResources,
    recent: &[(String, String)],
) -> Result<usize, Error> {
    if !gate.should_warm_shards(resources) {
        return Ok(0);
    }
    if recent.is_empty() {
        return Ok(0);
    }
    if cache.max_bytes() == 0 {
        return Ok(0);
    }

    let mut populated = 0usize;
    for (conv, bucket) in recent {
        let bloom_key = ShardCacheKey::new(conv, bucket, IndexType::Bloom);
        if cache.get(&bloom_key).is_none() {
            if let Some(filter) = cold_source.fetch_bloom_shard(conv, bucket)? {
                cache.put(bloom_key, CachedShard::Bloom(filter));
                populated += 1;
            }
        }
        let text_key = ShardCacheKey::new(conv, bucket, IndexType::Text);
        if cache.get(&text_key).is_none() {
            let rows = cold_source.fetch_text_rows(conv, bucket)?;
            if !rows.is_empty() {
                cache.put(text_key, CachedShard::Text(rows));
                populated += 1;
            }
        }
        let fuzzy_key = ShardCacheKey::new(conv, bucket, IndexType::Fuzzy);
        if cache.get(&fuzzy_key).is_none() {
            let rows = cold_source.fetch_fuzzy_rows(conv, bucket)?;
            if !rows.is_empty() {
                cache.put(fuzzy_key, CachedShard::Fuzzy(rows));
                populated += 1;
            }
        }
    }
    Ok(populated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_text_rows(n: usize, payload_size: usize) -> Vec<FtsRow> {
        (0..n)
            .map(|i| FtsRow {
                message_id: format!("msg-{i:08}"),
                conversation_id: "conv-A".to_string(),
                sender_id: "alice".to_string(),
                created_at_ms: 1_700_000_000_000 + i as i64,
                text_content: "x".repeat(payload_size),
            })
            .collect()
    }

    fn key(conv: &str, bucket: &str, kind: IndexType) -> ShardCacheKey {
        ShardCacheKey::new(conv, bucket, kind)
    }

    #[test]
    fn shard_cache_put_get_round_trip() {
        let mut cache = ShardCache::new(1024 * 1024);
        let rows = fake_text_rows(4, 32);
        cache.put(
            key("conv-A", "2026-04", IndexType::Text),
            CachedShard::Text(rows.clone()),
        );
        let got = cache
            .get(&key("conv-A", "2026-04", IndexType::Text))
            .expect("hit");
        match got {
            CachedShard::Text(stored) => assert_eq!(stored, &rows),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn shard_cache_evicts_lru_when_over_budget() {
        // Entry approximate cost: at least the payload (rows),
        // which dominates `mem::size_of::<FtsRow>` for non-tiny
        // payloads. Pick a budget that fits exactly two entries.
        let entry_bytes = CachedShard::Text(fake_text_rows(8, 1024)).approximate_bytes();
        let mut cache = ShardCache::new(entry_bytes * 2 + entry_bytes / 2);
        cache.put(
            key("conv-A", "2026-01", IndexType::Text),
            CachedShard::Text(fake_text_rows(8, 1024)),
        );
        cache.put(
            key("conv-A", "2026-02", IndexType::Text),
            CachedShard::Text(fake_text_rows(8, 1024)),
        );
        // Touch 2026-01 so 2026-02 becomes the LRU candidate.
        let _ = cache.get(&key("conv-A", "2026-01", IndexType::Text));
        cache.put(
            key("conv-A", "2026-03", IndexType::Text),
            CachedShard::Text(fake_text_rows(8, 1024)),
        );
        // 2026-02 is the least-recently-used and must be gone.
        assert!(cache
            .get(&key("conv-A", "2026-02", IndexType::Text))
            .is_none());
        // 2026-01 (recently touched) and 2026-03 (just inserted)
        // are still present.
        assert!(cache
            .get(&key("conv-A", "2026-01", IndexType::Text))
            .is_some());
        assert!(cache
            .get(&key("conv-A", "2026-03", IndexType::Text))
            .is_some());
        assert!(cache.current_bytes() <= cache.max_bytes());
    }

    #[test]
    fn shard_cache_clear_empties_all() {
        let mut cache = ShardCache::new(1024 * 1024);
        cache.put(
            key("conv-A", "2026-04", IndexType::Text),
            CachedShard::Text(fake_text_rows(2, 16)),
        );
        cache.put(
            key("conv-A", "2026-04", IndexType::Fuzzy),
            CachedShard::Fuzzy(vec![FuzzyRow {
                token: "tok".into(),
                script: "Latn".into(),
                message_id: "msg".into(),
            }]),
        );
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.current_bytes(), 0);
    }

    #[test]
    fn shard_cache_respects_max_bytes() {
        // Budget = 0 forces every insert to evict immediately.
        let mut cache = ShardCache::new(0);
        cache.put(
            key("conv-A", "2026-04", IndexType::Text),
            CachedShard::Text(fake_text_rows(8, 1024)),
        );
        assert_eq!(cache.current_bytes(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn shard_cache_overwrite_updates_size_accounting() {
        let small_rows = fake_text_rows(2, 16);
        let big_rows = fake_text_rows(8, 1024);
        let mut cache = ShardCache::new(usize::MAX);
        cache.put(
            key("conv-A", "2026-04", IndexType::Text),
            CachedShard::Text(small_rows.clone()),
        );
        let small_bytes = cache.current_bytes();
        cache.put(
            key("conv-A", "2026-04", IndexType::Text),
            CachedShard::Text(big_rows.clone()),
        );
        // Overwriting must not double-count the previous entry.
        assert_eq!(
            cache.current_bytes(),
            CachedShard::Text(big_rows).approximate_bytes()
        );
        assert!(cache.current_bytes() > small_bytes);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn shard_cache_distinguishes_index_types_for_same_bucket() {
        let mut cache = ShardCache::new(1024 * 1024);
        cache.put(
            key("conv-A", "2026-04", IndexType::Text),
            CachedShard::Text(fake_text_rows(2, 8)),
        );
        cache.put(
            key("conv-A", "2026-04", IndexType::Fuzzy),
            CachedShard::Fuzzy(vec![FuzzyRow {
                token: "alpha".into(),
                script: "Latn".into(),
                message_id: "m".into(),
            }]),
        );
        assert!(cache
            .get(&key("conv-A", "2026-04", IndexType::Text))
            .is_some());
        assert!(cache
            .get(&key("conv-A", "2026-04", IndexType::Fuzzy))
            .is_some());
        assert!(cache
            .get(&key("conv-A", "2026-04", IndexType::Bloom))
            .is_none());
    }

    // ---------------------------------------------------------------
    // warm_shard_cache
    // ---------------------------------------------------------------

    use crate::models::resource_gate::{NetworkType, ThermalState};
    use std::cell::Cell;

    /// Minimal in-memory `ColdShardSource` for the warming tests.
    /// Differs from the search engine's `FakeColdSource` only in
    /// that it lives inside `shard_cache::tests` (super-module
    /// privacy) and exposes a knob for "no buckets configured".
    #[derive(Default)]
    struct WarmFakeColdSource {
        text: HashMap<(String, String), Vec<FtsRow>>,
        fuzzy: HashMap<(String, String), Vec<FuzzyRow>>,
        bloom: HashMap<(String, String), BloomFilter>,
        text_calls: Cell<usize>,
        fuzzy_calls: Cell<usize>,
        bloom_calls: Cell<usize>,
    }
    impl WarmFakeColdSource {
        fn with_text(mut self, conv: &str, bucket: &str, rows: Vec<FtsRow>) -> Self {
            self.text.insert((conv.into(), bucket.into()), rows);
            self
        }
    }
    impl ColdShardSource for WarmFakeColdSource {
        fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
            Ok(self.text.keys().cloned().collect())
        }
        fn fetch_text_rows(&self, c: &str, b: &str) -> Result<Vec<FtsRow>, Error> {
            self.text_calls.set(self.text_calls.get() + 1);
            Ok(self
                .text
                .get(&(c.to_string(), b.to_string()))
                .cloned()
                .unwrap_or_default())
        }
        fn fetch_fuzzy_rows(&self, c: &str, b: &str) -> Result<Vec<FuzzyRow>, Error> {
            self.fuzzy_calls.set(self.fuzzy_calls.get() + 1);
            Ok(self
                .fuzzy
                .get(&(c.to_string(), b.to_string()))
                .cloned()
                .unwrap_or_default())
        }
        fn fetch_bloom_shard(&self, c: &str, b: &str) -> Result<Option<BloomFilter>, Error> {
            self.bloom_calls.set(self.bloom_calls.get() + 1);
            Ok(self.bloom.get(&(c.to_string(), b.to_string())).cloned())
        }
    }

    fn idle_resources() -> DeviceResources {
        DeviceResources {
            battery_level: 0.95,
            is_charging: true,
            thermal_state: ThermalState::Nominal,
            network_type: NetworkType::WiFi,
        }
    }

    #[test]
    fn warm_shard_cache_populates_cache_for_recent_conversations() {
        let mut cache = ShardCache::new(1024 * 1024);
        let source =
            WarmFakeColdSource::default().with_text("conv-A", "2026-04", fake_text_rows(2, 64));
        let gate = ResourceGate::default();
        let n = warm_shard_cache(
            &mut cache,
            &source,
            &gate,
            &idle_resources(),
            &[("conv-A".to_string(), "2026-04".to_string())],
        )
        .unwrap();
        assert!(n >= 1, "at least one entry must be inserted");
        assert!(cache
            .get(&key("conv-A", "2026-04", IndexType::Text))
            .is_some());
    }

    #[test]
    fn warm_shard_cache_respects_resource_gate() {
        let mut cache = ShardCache::new(1024 * 1024);
        let source =
            WarmFakeColdSource::default().with_text("conv-A", "2026-04", fake_text_rows(2, 64));
        // Cellular + uncharged → gate refuses.
        let resources = DeviceResources {
            battery_level: 0.5,
            is_charging: false,
            thermal_state: ThermalState::Nominal,
            network_type: NetworkType::Cellular,
        };
        let n = warm_shard_cache(
            &mut cache,
            &source,
            &ResourceGate::default(),
            &resources,
            &[("conv-A".to_string(), "2026-04".to_string())],
        )
        .unwrap();
        assert_eq!(n, 0);
        assert_eq!(source.text_calls.get(), 0, "no transport calls when gated");
        assert!(cache.is_empty());
    }

    #[test]
    fn warm_shard_cache_noop_when_no_cold_buckets() {
        let mut cache = ShardCache::new(1024 * 1024);
        let source = WarmFakeColdSource::default();
        let n = warm_shard_cache(
            &mut cache,
            &source,
            &ResourceGate::default(),
            &idle_resources(),
            &[],
        )
        .unwrap();
        assert_eq!(n, 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn warm_shard_cache_respects_cache_budget() {
        // Zero-byte budget: warming must still gate-check OK and
        // then early-return without any transport call.
        let mut cache = ShardCache::new(0);
        let source =
            WarmFakeColdSource::default().with_text("conv-A", "2026-04", fake_text_rows(2, 64));
        let n = warm_shard_cache(
            &mut cache,
            &source,
            &ResourceGate::default(),
            &idle_resources(),
            &[("conv-A".to_string(), "2026-04".to_string())],
        )
        .unwrap();
        assert_eq!(n, 0);
        assert_eq!(source.text_calls.get(), 0);
        assert!(cache.is_empty());
    }
}
