//! In-memory LRU cache for decrypted media originals.
//!
//! `docs/DESIGN.md §5.4` (storage budget) and `docs/DESIGN.md
//! §8.5` (rehydration) call out a local on-disk cache for media
//! originals so the hydration path does not re-pay AEAD work for
//! recently viewed assets. lands the bookkeeping side of
//! the cache — the LRU index that tracks resident asset sizes and
//! evicts the oldest entries when the budget is exceeded. The
//! actual on-disk eviction (`fs::remove_file`) is wired in by the
//! eviction pipeline in along with the
//! `media_state = Evicted` transition.
//!
//! The cache is intentionally *index-only*: it stores
//! `(asset_id, size_bytes)` pairs and an LRU ordering, but does not
//! own the underlying bytes. The caller is responsible for serving
//! plaintext to consumers and is the one that calls
//! [`MediaCache::insert`] / [`MediaCache::touch`] /
//! [`MediaCache::remove`] when the on-disk state changes.
//!
//! Implementation: a `HashMap<asset_id, size>` for O(1) size lookup
//! plus a `VecDeque<asset_id>` for LRU ordering. Both `touch` and
//! `insert` are O(N) in the worst case (the deque scan to remove
//! the existing position) but N is bounded by the number of cached
//! assets, which is typically <= a few thousand. This avoids
//! pulling in an extra crate (`linked-hash-map`, `indexmap`) for
//! the surface; if the LRU ever shows up in a profile we
//! can swap the implementation behind the same `MediaCache` API
//! without rippling changes through callers.

use std::collections::{HashMap, VecDeque};

/// Bookkeeping entry inside [`MediaCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheEntry {
    /// Resident size in bytes.
    size_bytes: u64,
}

/// Local LRU cache for decrypted media originals.
///
/// Tracks `(asset_id, size_bytes)` pairs with a configurable byte
/// budget; when [`Self::insert`] would exceed the budget,
/// [`Self::evict_to_budget`] runs implicitly to make room. The
/// eviction order is "least recently used first" — `touch` /
/// `insert` move an asset to the most-recently-used end.
#[derive(Debug, Clone)]
pub struct MediaCache {
    entries: HashMap<String, CacheEntry>,
    /// LRU ordering: front = least recently used, back = most
    /// recently used.
    order: VecDeque<String>,
    current_bytes: u64,
    max_bytes: u64,
}

impl MediaCache {
    /// Create a new [`MediaCache`] with `max_bytes` as the byte
    /// budget. `max_bytes = 0` is legal and means "always evict on
    /// insert" — the cache is essentially disabled but still
    /// callable for code that tolerates a zero-budget configuration.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            current_bytes: 0,
            max_bytes,
        }
    }

    /// Configured byte budget passed to [`Self::new`].
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Total bytes currently tracked across all resident entries.
    pub fn current_bytes(&self) -> u64 {
        self.current_bytes
    }

    /// Number of resident entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether `asset_id` is currently resident.
    pub fn contains(&self, asset_id: &str) -> bool {
        self.entries.contains_key(asset_id)
    }

    /// Insert (or overwrite) `asset_id` at the most-recently-used
    /// end. Returns the asset_ids of any entries evicted to make
    /// room for the new one.
    ///
    /// Re-inserting an existing `asset_id` updates its size and
    /// promotes it to the most-recently-used end.
    pub fn insert(&mut self, asset_id: String, size_bytes: u64) -> Vec<String> {
        // If the asset is already resident, drop its old size from
        // the running total before re-inserting.
        if let Some(prev) = self.entries.remove(&asset_id) {
            self.current_bytes = self.current_bytes.saturating_sub(prev.size_bytes);
            self.remove_from_order(&asset_id);
        }
        self.entries
            .insert(asset_id.clone(), CacheEntry { size_bytes });
        self.order.push_back(asset_id);
        self.current_bytes = self.current_bytes.saturating_add(size_bytes);
        self.evict_to_budget()
    }

    /// Mark `asset_id` as most-recently-used. Has no effect if the
    /// asset is not resident.
    pub fn touch(&mut self, asset_id: &str) {
        if !self.entries.contains_key(asset_id) {
            return;
        }
        self.remove_from_order(asset_id);
        self.order.push_back(asset_id.to_string());
    }

    /// Remove `asset_id` from the cache. Returns the number of bytes
    /// freed (`0` when the asset is not resident).
    pub fn remove(&mut self, asset_id: &str) -> u64 {
        if let Some(entry) = self.entries.remove(asset_id) {
            self.current_bytes = self.current_bytes.saturating_sub(entry.size_bytes);
            self.remove_from_order(asset_id);
            entry.size_bytes
        } else {
            0
        }
    }

    /// Evict least-recently-used entries until [`Self::current_bytes`]
    /// is at or below [`Self::max_bytes`]. Returns the asset_ids of
    /// every entry that was evicted, in eviction order (oldest
    /// first).
    pub fn evict_to_budget(&mut self) -> Vec<String> {
        let mut evicted = Vec::new();
        while self.current_bytes > self.max_bytes {
            let Some(asset_id) = self.order.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&asset_id) {
                self.current_bytes = self.current_bytes.saturating_sub(entry.size_bytes);
                evicted.push(asset_id);
            }
        }
        evicted
    }

    /// Iterate over the current entries in LRU order
    /// (least-recently-used first). Useful for debugging / metrics
    /// dumps.
    pub fn iter_lru(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.order.iter().filter_map(|asset_id| {
            self.entries
                .get(asset_id)
                .map(|e| (asset_id.as_str(), e.size_bytes))
        })
    }

    fn remove_from_order(&mut self, asset_id: &str) {
        if let Some(pos) = self.order.iter().position(|s| s == asset_id) {
            self.order.remove(pos);
        }
    }
}

impl Default for MediaCache {
    /// Default cache with a 256 MiB budget. leaves the real
    /// budget to the caller — production builds set it from the
    /// platform-side storage-budget configuration. The default
    /// exists so tests / scratch code don't have to invent a value.
    fn default() -> Self {
        Self::new(256 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_retrieve() {
        let mut cache = MediaCache::new(1024);
        assert!(!cache.contains("a"));
        let evicted = cache.insert("a".into(), 100);
        assert!(evicted.is_empty());
        assert!(cache.contains("a"));
        assert_eq!(cache.entry_count(), 1);
        assert_eq!(cache.current_bytes(), 100);
    }

    #[test]
    fn insert_overwrites_size_and_promotes() {
        let mut cache = MediaCache::new(1024);
        cache.insert("a".into(), 100);
        cache.insert("b".into(), 100);
        // Re-inserting "a" with a different size updates the total
        // and promotes it to the MRU end.
        let evicted = cache.insert("a".into(), 250);
        assert!(evicted.is_empty());
        assert_eq!(cache.current_bytes(), 100 + 250);
        // Force eviction; "b" should leave first because "a" was
        // just promoted.
        cache.insert("c".into(), 700);
        assert!(!cache.contains("b"));
        assert!(cache.contains("a"));
    }

    #[test]
    fn touch_promotes_entry() {
        let mut cache = MediaCache::new(300);
        cache.insert("a".into(), 100);
        cache.insert("b".into(), 100);
        cache.insert("c".into(), 100);
        // Without touch, "a" would be evicted next.
        cache.touch("a");
        let evicted = cache.insert("d".into(), 100);
        assert_eq!(evicted, vec!["b".to_string()]);
        assert!(cache.contains("a"));
        assert!(!cache.contains("b"));
    }

    #[test]
    fn touch_missing_is_noop() {
        let mut cache = MediaCache::new(1024);
        cache.touch("nonexistent");
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.current_bytes(), 0);
    }

    #[test]
    fn lru_eviction_order() {
        let mut cache = MediaCache::new(300);
        cache.insert("a".into(), 100);
        cache.insert("b".into(), 100);
        cache.insert("c".into(), 100);
        // Insert "d" to force one eviction; LRU is "a".
        let evicted = cache.insert("d".into(), 100);
        assert_eq!(evicted, vec!["a".to_string()]);
        assert_eq!(cache.entry_count(), 3);
        assert_eq!(cache.current_bytes(), 300);
        assert!(cache.contains("b") && cache.contains("c") && cache.contains("d"));
    }

    #[test]
    fn remove_frees_space() {
        let mut cache = MediaCache::new(300);
        cache.insert("a".into(), 200);
        let freed = cache.remove("a");
        assert_eq!(freed, 200);
        assert_eq!(cache.current_bytes(), 0);
        assert_eq!(cache.entry_count(), 0);
        assert!(!cache.contains("a"));
    }

    #[test]
    fn remove_missing_returns_zero() {
        let mut cache = MediaCache::new(300);
        let freed = cache.remove("never-seen");
        assert_eq!(freed, 0);
    }

    #[test]
    fn evict_to_budget_drops_multiple_lru_entries() {
        let mut cache = MediaCache::new(1000);
        for i in 0..10 {
            cache.insert(format!("a{i}"), 100);
        }
        assert_eq!(cache.current_bytes(), 1000);
        // Insert an oversized entry that requires evicting several.
        let evicted = cache.insert("big".into(), 600);
        assert_eq!(evicted, vec!["a0", "a1", "a2", "a3", "a4", "a5"]);
        assert_eq!(cache.current_bytes(), 1000);
        assert!(cache.contains("big"));
    }

    #[test]
    fn empty_cache_operations() {
        let mut cache = MediaCache::new(1024);
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.current_bytes(), 0);
        assert!(!cache.contains("anything"));
        assert_eq!(cache.evict_to_budget(), Vec::<String>::new());
        assert_eq!(cache.remove("anything"), 0);
        cache.touch("anything");
    }

    #[test]
    fn zero_budget_evicts_immediately() {
        let mut cache = MediaCache::new(0);
        let evicted = cache.insert("a".into(), 100);
        assert_eq!(evicted, vec!["a".to_string()]);
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.current_bytes(), 0);
    }

    #[test]
    fn iter_lru_returns_lru_order() {
        let mut cache = MediaCache::new(1024);
        cache.insert("a".into(), 1);
        cache.insert("b".into(), 2);
        cache.insert("c".into(), 3);
        cache.touch("a"); // a is now MRU; LRU order is b, c, a.
        let collected: Vec<(String, u64)> = cache
            .iter_lru()
            .map(|(id, sz)| (id.to_string(), sz))
            .collect();
        assert_eq!(
            collected,
            vec![
                ("b".to_string(), 2),
                ("c".to_string(), 3),
                ("a".to_string(), 1),
            ]
        );
    }

    #[test]
    fn default_budget_is_set() {
        let cache = MediaCache::default();
        assert_eq!(cache.max_bytes(), 256 * 1024 * 1024);
        assert_eq!(cache.current_bytes(), 0);
    }
}
