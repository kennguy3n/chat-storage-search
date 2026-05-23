//! Unified query engine combining FTS5, fuzzy search, and structured
//! filters.
//!
//! `docs/DESIGN.md §12` defines the [`SearchQuery`] /
//! [`SearchScope`] / [`SearchResult`] surface. This module
//! implements the local-store half: the engine reads from
//! `search_fts` for free-text queries, fans the same query out to
//! the script-aware fuzzy index
//! ([`FuzzySearchEngine`]) for typo / partial / cross-script matches,
//! applies the structured filters (sender / conversation / date range
//! / content kind) as SQL `WHERE` clauses against `message_skeleton`,
//! and merges the two using a `message_id`-keyed dedup.
//!
//! When the query string is empty the engine returns skeleton rows
//! ordered by recency. When it is non-empty the engine intersects
//! the FTS5 + fuzzy hits with the structured filters and returns the
//! union ordered by `rank_score` (highest-relevance first).
//!
//! Ranking weights follow `docs/DESIGN.md §7.5`: BM25 is weighted
//! at `2.0` and fuzzy-token-overlap at `1.0`, so a fuzzy-only hit
//! always ranks below an FTS hit on the same query — and a row that
//! matches both engines accumulates both contributions.
//!
//! [`SearchScope::IncludeCold`] now flags rows whose
//! `message_skeleton.body_state = 'remote_archive_only'` with
//! `SearchResult::is_cold = true` so the orchestration layer can
//! enqueue them into the [`crate::offload::HydrationQueue`] at
//! priority `SearchResultTap`.
//!
//! The cold-bucket fan-out is wired through the
//! [`ColdShardSource`] trait — see
//! [`QueryEngine::execute_search_with_cold_source`]. The
//! orchestration layer ([`crate::core_impl::CoreImpl`]) implements
//! the trait by:
//!
//! 1. Scanning `archive_segment_map` for `(conversation_id,
//!    time_bucket)` pairs whose local bodies are offloaded but a
//!    verified search shard exists,
//! 2. Calling
//!    [`crate::transport::TransportClient::fetch_index_shards`] for
//!    each bucket × `(text|fuzzy)` shard type,
//! 3. Decrypting each blob with
//!    [`crate::search::shard_builder::restore_text_search_shard`] /
//!    [`crate::search::shard_builder::restore_fuzzy_search_shard`].
//!
//! The trait keeps the engine independent of the transport / key
//! derivation stack so QueryEngine can be unit-tested with a
//! deterministic in-memory fake.
//!
//! [`SearchScope::LocalOnly`] always returns `is_cold = false` and
//! never invokes the cold source, preserving the offline-only
//! contract.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use rusqlite::{params_from_iter, types::Value};
use uuid::Uuid;

use crate::config::TenantSearchPolicy;
use crate::formats::search_shard::IndexType;
use crate::local_store::db::{
    read_list_conversations_by_column, ConversationFilterColumn, DbResult,
};
use crate::search::fuzzy_search::{FuzzySearchEngine, FuzzyTokenizer};
use crate::search::shard_builder::{BloomFilter, FtsRow, FuzzyRow};
use crate::search::shard_cache::{CachedShard, ShardCache, ShardCacheKey};
use crate::search::text_search::TextSearchEngine;
use crate::search::tokenizer::{fuzzy_min_overlap, ScriptClass};
use crate::{ContentKind, Error, SearchQuery, SearchResult, SearchScope, SearchTarget};
use rusqlite::Connection;

/// BM25 contribution weight in the merged rank score
/// (`docs/DESIGN.md §7.5`).
pub(crate) const BM25_WEIGHT: f64 = 2.0;

/// Fuzzy-token-overlap contribution weight in the merged rank score
/// (`docs/DESIGN.md §7.5`).
pub(crate) const FUZZY_WEIGHT: f64 = 1.0;

/// Semantic / cosine-similarity contribution weight in the merged
/// rank score (`docs/DESIGN.md §7.5`). Sits between BM25 (`2.0`)
/// and fuzzy (`1.0`) so the on-device reranker leans on
/// surface-form matches when both signals are available, but
/// still surfaces semantic-only hits when FTS misses.
///
pub(crate) const SEMANTIC_WEIGHT: f64 = 1.5;

/// Recency-decay weight in the merged rank score
/// (`docs/DESIGN.md §7.5` — `recency_boost`).
pub(crate) const RECENCY_WEIGHT: f64 = 0.5;

/// Half-life of the recency-decay function in days. Mirrors
/// [`crate::offload::scoring`]'s 30-day half-life so search and
/// eviction agree on what "recent" means.
pub(crate) const RECENCY_HALF_LIFE_DAYS: f64 = 30.0;

/// Multiplicative content-kind weight applied to the merged rank
/// (`docs/DESIGN.md §7.5`). Text bodies are fully searchable; the
/// thumbnails / OCR rows that back media messages are coarser, so
/// media gets a lighter weight.
pub(crate) const TEXT_KIND_WEIGHT: f64 = 1.0;
/// See [`TEXT_KIND_WEIGHT`].
pub(crate) const MEDIA_KIND_WEIGHT: f64 = 0.8;

/// Map a `message_skeleton.kind` string to the multiplicative
/// content-kind weight used by the ranker. The canonical
/// vocabulary is whatever
/// [`crate::local_store::schema::MessageKind::as_str`] writes
/// today `"text"`, `"media"`, or `"system"`. Unknown / missing
/// kinds default to [`TEXT_KIND_WEIGHT`] so cold-only rows that
/// appear before the local skeleton lands still rank sensibly.
///
/// This is the single source of truth for the kind→weight
/// mapping. Both [`QueryEngine::apply_recency_and_kind_weight`]
/// (FTS / fuzzy lane) and
/// [`QueryEngine::execute_search_with_semantic`] (semantic-only
/// lane) call it so the two paths cannot drift on this mapping
/// the bug fixed in 187c666 was exactly that drift, where the
/// semantic-only branch matched on `MediaDescriptor.kind`
/// vocabulary (`"image" | "video" | "audio" | "file"`) instead
/// of `MessageKind` vocabulary, silently demoting media hits to
/// `TEXT_KIND_WEIGHT`.
pub(crate) fn kind_str_to_weight(kind: &str) -> f64 {
    match kind {
        "text" => TEXT_KIND_WEIGHT,
        "media" => MEDIA_KIND_WEIGHT,
        _ => TEXT_KIND_WEIGHT,
    }
}

/// Skeleton-row projection used by
/// [`QueryEngine::execute_search_with_semantic`] to materialize
/// semantic-only hits.
///
/// Carries `kind` so the recency × content-kind multiplier
/// can be applied without a second round trip — see the merge
/// loop in
/// [`QueryEngine::execute_search_with_semantic`].
#[derive(Debug, Clone)]
struct SemanticSkeletonInfo {
    conversation_id: String,
    sender_id: String,
    created_at_ms: i64,
    kind: String,
}

/// Source of decrypted search-shard rows for cold
/// (`body_state = 'remote_archive_only'`) buckets.
///
/// Implementations live in the orchestration layer
/// (`core_impl.rs`); QueryEngine consumes the trait so the cold
/// fan-out path can be unit-tested without a transport client.
pub trait ColdShardSource {
    /// Return the `(conversation_id, time_bucket)` pairs whose
    /// bodies are currently offloaded and whose shards live on
    /// the backend. Order does not matter; QueryEngine
    /// deduplicates anyway.
    fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error>;

    /// Fetch and decrypt the text-index shard for the given
    /// `(conversation_id, time_bucket)`. Implementations should
    /// return `Ok(Vec::new)` when no shard exists for the
    /// pair — that is a legitimate "no results" signal, not an
    /// error.
    fn fetch_text_rows(
        &self,
        conversation_id: &str,
        time_bucket: &str,
    ) -> Result<Vec<FtsRow>, Error>;

    /// Fetch and decrypt the fuzzy-token shard for the given
    /// `(conversation_id, time_bucket)`. Same `Ok(empty)` =
    /// "no shard" contract as
    /// [`Self::fetch_text_rows`].
    fn fetch_fuzzy_rows(
        &self,
        conversation_id: &str,
        time_bucket: &str,
    ) -> Result<Vec<FuzzyRow>, Error>;

    /// fetch and decrypt the
    /// bloom-filter shard for `(conversation_id, time_bucket)`.
    ///
    /// The bloom shard is consulted by the cold fan-out *before*
    /// the (much larger) text and fuzzy shards: if the filter
    /// rejects every query token the bucket is skipped without
    /// any further transport calls.
    ///
    /// Implementations should return:
    /// * `Ok(Some(filter))` on a successful round-trip,
    /// * `Ok(None)` when the backend has no bloom shard for the
    ///   pair (graceful degradation — the cold path falls
    ///   through to the text / fuzzy fetches),
    /// * `Err(_)` only for hard errors that should propagate.
    ///
    /// The default implementation returns `Ok(None)` so existing
    /// `ColdShardSource` impls (and test fakes) keep compiling
    /// without opting into the bloom path. Production
    /// implementations override this to call
    /// [`crate::transport::TransportClient::fetch_index_shards`]
    /// for [`IndexType::Bloom`] and decrypt with
    /// [`crate::search::shard_builder::restore_bloom_shard`].
    fn fetch_bloom_shard(
        &self,
        _conversation_id: &str,
        _time_bucket: &str,
    ) -> Result<Option<BloomFilter>, Error> {
        Ok(None)
    }
}

/// does the YYYY-MM `time_bucket`
/// string overlap the optional `[date_from, date_to]` window?
///
/// The bucket grammar matches what the personal-archive segment
/// builder writes (`docs/DESIGN.md §5.2`): `YYYY-MM` for monthly
/// buckets. The function parses the bucket into a half-open
/// `[start_ms, end_ms)` range covering the entire month and
/// returns `true` whenever the bucket and `[date_from, date_to]`
/// overlap. Malformed or unparseable bucket strings fall back to
/// `true` so the caller never silently drops a bucket whose
/// timestamps it can't reason about — the caller's per-row
/// `date_filter_matches` still has the final say.
pub fn bucket_overlaps_date_range(
    bucket: &str,
    date_from: Option<i64>,
    date_to: Option<i64>,
) -> bool {
    if date_from.is_none() && date_to.is_none() {
        return true;
    }
    let Some((start_ms, end_ms_exclusive)) = parse_bucket_range_ms(bucket) else {
        // Unrecognized bucket grammar — fall back to "include".
        return true;
    };
    if let Some(to) = date_to {
        if start_ms > to {
            return false;
        }
    }
    if let Some(from) = date_from {
        // `end_ms_exclusive` is one millisecond past the last
        // millisecond inside the bucket; a bucket ending at
        // `end_ms_exclusive` whose `from` equals `end_ms_exclusive`
        // contains zero in-range milliseconds.
        if end_ms_exclusive <= from {
            return false;
        }
    }
    true
}

/// Parse a `YYYY-MM` bucket into its half-open millisecond
/// range. Returns `None` for any malformed input.
fn parse_bucket_range_ms(bucket: &str) -> Option<(i64, i64)> {
    let (year_str, month_str) = bucket.split_once('-')?;
    if year_str.len() != 4 || month_str.len() != 2 {
        return None;
    }
    let year: i32 = year_str.parse().ok()?;
    let month: u32 = month_str.parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let start_ms = days_from_civil(year, month, 1) * 86_400_000;
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1u32)
    } else {
        (year, month + 1)
    };
    let end_ms_exclusive = days_from_civil(next_year, next_month, 1) * 86_400_000;
    Some((start_ms, end_ms_exclusive))
}

/// wrap
/// [`ColdShardSource::fetch_text_rows`] with a [`ShardCache`]
/// lookup / populate cycle. On a cache hit no transport call is
/// made; on a miss the rows are fetched, decrypted, and inserted
/// into the cache before being returned to the caller.
fn cold_source_fetch_text_with_cache(
    src: &dyn ColdShardSource,
    cache: Option<&Mutex<ShardCache>>,
    conv: &str,
    bucket: &str,
) -> Result<Vec<FtsRow>, Error> {
    let key = ShardCacheKey::new(conv, bucket, IndexType::Text);
    if let Some(c) = cache {
        if let Ok(mut guard) = c.lock() {
            if let Some(CachedShard::Text(rows)) = guard.get(&key) {
                return Ok(rows.clone());
            }
        }
    }
    let rows = src.fetch_text_rows(conv, bucket)?;
    if let Some(c) = cache {
        if let Ok(mut guard) = c.lock() {
            guard.put(key, CachedShard::Text(rows.clone()));
        }
    }
    Ok(rows)
}

/// Cache-aware twin of [`cold_source_fetch_text_with_cache`] for
/// fuzzy shards.
fn cold_source_fetch_fuzzy_with_cache(
    src: &dyn ColdShardSource,
    cache: Option<&Mutex<ShardCache>>,
    conv: &str,
    bucket: &str,
) -> Result<Vec<FuzzyRow>, Error> {
    let key = ShardCacheKey::new(conv, bucket, IndexType::Fuzzy);
    if let Some(c) = cache {
        if let Ok(mut guard) = c.lock() {
            if let Some(CachedShard::Fuzzy(rows)) = guard.get(&key) {
                return Ok(rows.clone());
            }
        }
    }
    let rows = src.fetch_fuzzy_rows(conv, bucket)?;
    if let Some(c) = cache {
        if let Ok(mut guard) = c.lock() {
            guard.put(key, CachedShard::Fuzzy(rows.clone()));
        }
    }
    Ok(rows)
}

/// Cache-aware twin of [`cold_source_fetch_text_with_cache`] for
/// bloom shards. Returns `Ok(None)` for **all three** of the
/// following cases:
/// 1. the bloom shard is not in the cache and the transport
///    reports no shard for `(conversation, bucket)`,
/// 2. the bloom shard is not in the cache and the transport
///    raised a soft error (404, network blip, decode failure),
/// 3. cache acquisition failed.
///
/// In every case the bucket loop falls through to the full
/// text/fuzzy fetches (graceful degradation, per the
/// `ColdShardSource::fetch_bloom_shard` trait contract). The
/// signature still returns `Result` for symmetry with the text /
/// fuzzy variants and to keep the door open for a future
/// "loud error" path, but the function itself never propagates
/// transport errors today.
fn cold_source_fetch_bloom_with_cache(
    src: &dyn ColdShardSource,
    cache: Option<&Mutex<ShardCache>>,
    conv: &str,
    bucket: &str,
) -> Result<Option<BloomFilter>, Error> {
    let key = ShardCacheKey::new(conv, bucket, IndexType::Bloom);
    if let Some(c) = cache {
        if let Ok(mut guard) = c.lock() {
            if let Some(CachedShard::Bloom(filter)) = guard.get(&key) {
                return Ok(Some(filter.clone()));
            }
        }
    }
    let result = match src.fetch_bloom_shard(conv, bucket) {
        Ok(r) => r,
        // Swallow transport errors: bloom is an optimization, not
        // a correctness path. The cold loop falls through to the
        // full text/fuzzy fetches when the bloom probe yields
        // `None`, so an `Err` here is observationally identical
        // to "no shard available". Returning `Ok(None)` keeps the
        // function self-contained against any future caller that
        // might `?`-propagate or `.unwrap` the result.
        Err(_) => return Ok(None),
    };
    if let Some(filter) = &result {
        if let Some(c) = cache {
            if let Ok(mut guard) = c.lock() {
                guard.put(key, CachedShard::Bloom(filter.clone()));
            }
        }
    }
    Ok(result)
}

/// prefetched payload
/// for one cold bucket.
///
/// The parallel fetch path materializes one
/// [`BucketPrefetch`] per `(conversation_id, time_bucket)` pair
/// **before** running the merge loop, so the (mostly
/// transport-bound) decrypt/fetch step can be parallelized with
/// `std::thread::scope` while the (mostly compute-bound) merge
/// step stays single-threaded against the shared
/// `HashMap<String, SearchResult>` accumulator. `bloom` mirrors
/// the in-loop bloom probe: `Ok(Some(filter))` means the bucket
/// fetched a bloom shard, `Ok(None)` means no shard was
/// returned (graceful degradation), and `Err(_)` means the
/// transport hard-errored on bloom — the merge loop treats
/// `Err` as "no shard" so a single broken bucket cannot poison
/// the whole search. `text` / `fuzzy` are also `Result` so the
/// merge loop can `?`-propagate hard transport errors that the
/// fail-open layer above already let through.
struct BucketPrefetch {
    /// Source `conversation_id` — kept for diagnostics / future
    /// fail-open logging hooks even though the merge loop reads
    /// the conversation id off the per-row `FtsRow` instead.
    #[allow(dead_code)]
    conv: String,
    /// Source `time_bucket` — see [`Self::conv`].
    #[allow(dead_code)]
    bucket: String,
    bloom: Result<Option<BloomFilter>, Error>,
    text: Result<Vec<FtsRow>, Error>,
    fuzzy: Result<Vec<FuzzyRow>, Error>,
}

/// parallel-fetch the
/// `(bloom, text, fuzzy)` shard triple for every supplied
/// `(conversation_id, time_bucket)` pair.
///
/// Spawns up to `concurrency` worker threads via
/// `std::thread::scope` and feeds them a shared
/// [`std::sync::atomic::AtomicUsize`] cursor over the bucket
/// list. Each worker repeatedly:
///
/// 1. Atomically increments the cursor to claim a bucket index,
/// 2. Fetches the bloom shard (with the supplied `shard_cache`),
/// 3. If `require_bloom_shards` is set and the probe failed,
///    skips the bucket (`text` / `fuzzy` left as `Ok(empty)`),
/// 4. Otherwise fetches the text + fuzzy shards.
///
/// Errors are surfaced per-bucket — a transport failure on one
/// bucket does not abort the others. The merge loop in
/// [`QueryEngine::execute_search_with_cold_source_full`] is
/// what ultimately re-runs the per-bucket bloom check before
/// touching the rows.
///
/// Output order is **stable**: the returned vector mirrors the
/// input `buckets` order, so the merge loop sees the same
/// fan-out the sequential path would have produced — modulo
/// the parallel transport calls.
fn parallel_fetch_buckets(
    cold_source: &(dyn ColdShardSource + Send + Sync),
    shard_cache: Option<&Mutex<ShardCache>>,
    buckets: &[(String, String)],
    require_bloom_shards: bool,
    q_words: &[String],
    concurrency: usize,
) -> Vec<BucketPrefetch> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let n = buckets.len();
    if n == 0 {
        return Vec::new();
    }
    // Pre-allocate one slot per bucket so workers can write
    // their result by index without coordinating.
    let slots: Vec<Mutex<Option<BucketPrefetch>>> = (0..n).map(|_| Mutex::new(None)).collect();
    let cursor = AtomicUsize::new(0);
    let workers = concurrency.max(1).min(n);

    std::thread::scope(|s| {
        for _ in 0..workers {
            let cursor_ref = &cursor;
            let slots_ref = &slots;
            let buckets_ref = buckets;
            let cs = cold_source;
            let sc = shard_cache;
            let q_words_ref = q_words;
            s.spawn(move || loop {
                let i = cursor_ref.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                let (conv, bucket) = &buckets_ref[i];
                let bloom = cold_source_fetch_bloom_with_cache(cs, sc, conv, bucket);
                // Bloom pre-check: when `require_bloom_shards` is
                // set and the probe missed (`Err` or `Ok(None)`),
                // OR when a non-empty `q_words` produces zero
                // bloom hits, the bucket cannot match and we
                // skip the (much larger) text + fuzzy fetches.
                // Mirrors the in-loop check in
                // `execute_search_with_cold_source_full` so the
                // parallel and sequential paths take the same
                // shortcut.
                let bloom_rejects = if require_bloom_shards && !matches!(bloom, Ok(Some(_))) {
                    true
                } else if let Ok(Some(filter)) = &bloom {
                    !q_words_ref.is_empty() && !q_words_ref.iter().any(|w| filter.maybe_contains(w))
                } else {
                    false
                };
                let (text, fuzzy) = if bloom_rejects {
                    (Ok(Vec::new()), Ok(Vec::new()))
                } else {
                    (
                        cold_source_fetch_text_with_cache(cs, sc, conv, bucket),
                        cold_source_fetch_fuzzy_with_cache(cs, sc, conv, bucket),
                    )
                };
                let prefetch = BucketPrefetch {
                    conv: conv.clone(),
                    bucket: bucket.clone(),
                    bloom,
                    text,
                    fuzzy,
                };
                if let Ok(mut guard) = slots_ref[i].lock() {
                    *guard = Some(prefetch);
                }
            });
        }
    });

    slots
        .into_iter()
        .filter_map(|m| m.into_inner().ok().flatten())
        .collect()
}

/// Convert a (year, month, day) tuple to days since 1970-01-01
/// using Howard Hinnant's `days_from_civil` algorithm. Avoids a
/// chrono dependency in the search crate.
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u32;
    let m = m as i32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u32;
    (era as i64) * 146_097 + (doe as i64) - 719_468
}

// ---------------------------------------------------------------------------
// QueryEngine
// ---------------------------------------------------------------------------

/// Unified search engine.
///
/// Borrows a raw [`Connection`] (rather than a `LocalStoreDb` /
/// `LocalStoreReader`) so it can be driven from either the
/// writer's connection or a connection checked out of
/// [`crate::local_store::db::LocalStoreReaderPool`]. The
/// `icu_available` flag is passed in explicitly because it is a
/// schema-time property of the database — see
/// [`crate::local_store::db::LocalStoreReader::icu_available`]
/// for the reader-side accessor.
///
/// `QueryEngine` itself only issues `SELECT` statements; the
/// fuzzy-index *writes* that happen alongside the search path
/// (e.g. `FuzzyIndexWriter::index_message`) live in the
/// writer-locked sections of `core_impl` / `message::processor`,
/// not in `QueryEngine`.
#[derive(Debug)]
pub struct QueryEngine<'a> {
    conn: &'a Connection,
    icu_available: bool,
}

impl<'a> QueryEngine<'a> {
    /// Construct a new engine bound to the given connection.
    ///
    /// `icu_available` selects the FTS5 tokenizer path the engine
    /// will assume. Pass `db.icu_available` for a writer
    /// connection or `reader.icu_available` for a pool reader.
    pub fn new(conn: &'a Connection, icu_available: bool) -> Self {
        Self {
            conn,
            icu_available,
        }
    }

    /// Run a unified search and return the matching rows.
    ///
    /// Default cap on returned rows is 200; callers that need more
    /// pass [`Self::execute_search_with_limit`].
    pub fn execute_search(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
    ) -> DbResult<Vec<SearchResult>> {
        self.execute_search_with_limit(query, scope, 200)
    }

    /// Run a unified search with an explicit limit.
    pub fn execute_search_with_limit(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
        limit: usize,
    ) -> DbResult<Vec<SearchResult>> {
        let trimmed = query.query_string.trim();
        let mut out = if trimmed.is_empty() {
            self.execute_structured_only(query, limit)?
        } else {
            self.execute_fts_and_fuzzy_with_filters(query, trimmed, limit)?
        };
        if matches!(scope, SearchScope::IncludeCold) {
            self.mark_cold_results(&mut out)?;
        }
        Ok(out)
    }

    /// run a unified search scoped to the
    /// supplied [`SearchTarget`]. Equivalent to setting
    /// `query.target = target` and calling
    /// [`Self::execute_search`], but works for the new variants
    /// (`ConversationGroup`, `Channel`, `Starred`, `Unread`) by
    /// pre-resolving the conversation set through the supplied
    /// [`crate::search::search_target::ConversationGroupResolver`]
    /// before SQL is built.
    ///
    /// `limit` is the row cap; pass `200` to match the default
    /// [`Self::execute_search`] behaviour.
    pub fn execute_search_with_target(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
        target: &SearchTarget,
        resolver: &dyn crate::search::search_target::ConversationGroupResolver,
        limit: usize,
    ) -> DbResult<Vec<SearchResult>> {
        // Resolve the target to a concrete conversation set (or
        // `None` for Global). We materialize the set into the
        // query as a `ConversationGroup` so the existing
        // `push_target_filter` SQL helper can take over without
        // needing a parallel resolver-aware path.
        let resolved = resolve_target_to_conversation_set_with_resolver(
            target, self.conn, resolver,
        )
        .map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
        })?;
        let mut narrowed = query.clone();
        narrowed.target = match resolved {
            None => SearchTarget::Global,
            Some(set) => SearchTarget::ConversationGroup(
                set.into_iter()
                    .filter_map(|s| Uuid::parse_str(&s).ok())
                    .collect(),
            ),
        };
        self.execute_search_with_limit(&narrowed, scope, limit)
    }

    /// Run a unified search and fan out to the personal archive
    /// via `cold_source` when [`SearchScope::IncludeCold`] is set.
    ///
    /// This is the entry point: cold buckets are
    /// resolved by [`ColdShardSource::cold_buckets`], shards are
    /// fetched + decrypted by the source, and the in-process
    /// FTS-like + fuzzy fan-out is merged into the local result
    /// set with `is_cold = true`.
    ///
    /// Behaviour summary:
    /// * [`SearchScope::LocalOnly`] never invokes the cold source
    ///   this is the offline-only contract from
    ///   `docs/DESIGN.md §12`.
    /// * Empty query strings short-circuit to the structured-only
    ///   path; cold fan-out only runs on free-text queries.
    /// * Non-text `query.content_kind` values short-circuit to
    ///   the local result set. The cold path only ships text +
    ///   fuzzy cold shards, so a media-only query has no cold
    ///   contribution to merge; consulting the cold source would
    ///   leak text-shard hits through the kind filter.
    /// * Errors from the cold source bubble out of this call;
    ///   callers that want graceful degradation should pass an
    ///   adapter that swallows transient transport failures.
    pub fn execute_search_with_cold_source(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
        cold_source: &dyn ColdShardSource,
    ) -> Result<Vec<SearchResult>, Error> {
        self.execute_search_with_cold_source_and_limit(query, scope, cold_source, 200)
    }

    /// [`Self::execute_search_with_cold_source`] with an explicit
    /// row cap on the merged output.
    pub fn execute_search_with_cold_source_and_limit(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
        cold_source: &dyn ColdShardSource,
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        self.execute_search_with_cold_source_full(
            query,
            scope,
            cold_source,
            &TenantSearchPolicy::default(),
            None,
            limit,
        )
    }

    /// full cold fan-out entry
    /// point that threads a per-tenant
    /// [`TenantSearchPolicy`] and an optional on-device
    /// [`ShardCache`] through the bucket loop.
    ///
    /// Invariants on top of
    /// [`Self::execute_search_with_cold_source_and_limit`]:
    /// * `policy.allow_global_search == false` blocks
    ///   [`SearchTarget::Global`] queries (returns local-only).
    /// * `policy.max_cold_buckets_per_search` caps the per-query
    ///   bucket fan-out after date pruning + bloom pre-check.
    /// * `policy.require_bloom_shards == true` skips any bucket
    ///   whose bloom shard is missing or fails to fetch.
    /// * `policy.allow_cross_tenant_results` is enforced
    ///   upstream of the engine: a non-Global `SearchTarget`
    ///   already narrows the cold-bucket set, and a Global query
    ///   under a B2B tenant's policy is expected to be rejected
    ///   by `allow_global_search = false` rather than by an
    ///   independent cross-tenant block. The field is preserved
    ///   for forward compatibility with the per-bucket
    ///   tenant-stamp scheme described in
    ///   `docs/DESIGN.md §7.7`.
    /// * `shard_cache`, when supplied, is consulted before each
    ///   transport fetch and populated after each successful
    ///   decrypt. The cache is keyed by
    ///   `(conversation_id, time_bucket, IndexType)`.
    pub fn execute_search_with_cold_source_full(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
        cold_source: &dyn ColdShardSource,
        policy: &TenantSearchPolicy,
        shard_cache: Option<&Mutex<ShardCache>>,
        limit: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        // Local results first. mark_cold_results runs inside
        // execute_search_with_limit when scope is IncludeCold so
        // any local row whose body is offloaded already carries
        // is_cold = true. `e.into` here routes through the
        // `From<DbError> for SearchError` impl in `search/mod.rs`,
        // which preserves `DbError::Rusqlite` as the typed
        // `SearchError::Sqlite` variant (so future retry / routing
        // logic can pattern-match on the underlying
        // `rusqlite::Error` without re-parsing a stringified form).
        let local = self
            .execute_search_with_limit(query, scope, limit)
            .map_err(|e| Error::Search(e.into()))?;

        // LocalOnly is the offline-only contract — never call the
        // cold source.
        if !matches!(scope, SearchScope::IncludeCold) {
            return Ok(local);
        }

        let trimmed = query.query_string.trim();
        if trimmed.is_empty() {
            // Structured-only queries do not fan out to encrypted
            // shards: the fuzzy / FTS contributions are zero
            // anyway.
            return Ok(local);
        }

        // Only ships text + fuzzy cold shards. When the
        // caller has explicitly narrowed the search to a non-text
        // content kind (Image / Video / Audio / Document), the
        // cold path has nothing to contribute — and worse,
        // returning text-shard hits here would silently violate
        // the `content_kind` filter that the local pass already
        // enforced via `allowed_skeleton_ids`. Short-circuit
        // before consulting `cold_source` so the cold fan-out
        // never runs for media-only queries.
        if let Some(kind) = query.content_kind {
            if !matches!(kind, ContentKind::Text | ContentKind::Any) {
                return Ok(local);
            }
        }

        // TenantSearchPolicy
        // enforcement #1: block Global queries when the active
        // policy disallows them. We check this *before* paying
        // for `cold_buckets` so a forbidden Global search is
        // cheap.
        //
        // `allow_cross_tenant_results` is enforced upstream of
        // the engine: any non-Global `SearchTarget` already
        // narrows the cold-bucket set through the resolver-based
        // `target_set` filter below, so a `Tenant(t)` query
        // cannot pull in other tenants' buckets even when the
        // policy is left at its default. The field is therefore
        // documentation / future-use only inside this engine
        // see the rustdoc on
        // [`TenantSearchPolicy::allow_cross_tenant_results`].
        let effective_target = query.effective_target();
        let is_global_target = matches!(effective_target, SearchTarget::Global);
        if is_global_target && !policy.allow_global_search {
            return Ok(local);
        }

        let buckets = cold_source.cold_buckets()?;
        if buckets.is_empty() {
            return Ok(local);
        }

        // If a conversation_filter is set, skip every bucket whose
        // conversation_id does not match.
        let conv_filter = query.conversation_filter.map(|c| c.to_string());
        // also respect the SearchTarget scope:
        // when the query carries an explicit non-Global target,
        // skip every cold bucket whose conversation_id is outside
        // the resolved target set. This keeps the cold fan-out
        // honest to the same scoping the local pass enforces.
        //
        // Resolution semantics (matches `resolve_target_to_conversation_set`'s
        // documented contract — see the `Ok(None)` rustdoc on that
        // helper):
        //
        // * `Ok(None)` → `SearchTarget::Global`. No
        // additional restriction; every
        // cold bucket is in scope.
        // * `Ok(Some(non_empty))` → restrict to those buckets.
        // * `Ok(Some(empty))` → **fail-closed**: the target
        // resolved to zero conversations
        // (e.g. `Starred` / `Unread`
        // with the default
        // `NoopConversationGroupResolver`,
        // or a `Conversation(uuid)` that
        // does not exist). Drop every
        // cold bucket so the cold pass
        // stays consistent with the
        // local pass — `push_target_filter`
        // emits `1=0` for an empty
        // resolution, so the local
        // pass returns zero rows; the
        // cold pass mirrors that.
        // * `Err(_)` → transient resolver error. Fall
        // back to "no extra restriction"
        // (`None`) so a flaky resolver
        // cannot mask cold hits the
        // conversation_filter or the
        // local pass would otherwise
        // surface.
        // The explicit `Ok(opt) => opt` / `Err(_) => None` arms here
        // exactly mirror the semantics in the comment above. We keep
        // the match form rather than `Result::unwrap_or_default` so
        // the per-arm rustdoc above lines up 1:1 with each pattern.
        #[allow(clippy::manual_unwrap_or_default)]
        let target_set: Option<HashSet<String>> =
            match resolve_target_to_conversation_set(&query.effective_target(), self.conn) {
                Ok(opt) => opt,
                Err(_) => None,
            };
        let buckets: Vec<(String, String)> = buckets
            .into_iter()
            .filter(|(c, _)| conv_filter.as_deref().is_none_or(|cf| cf == c.as_str()))
            .filter(|(c, _)| {
                target_set
                    .as_ref()
                    .is_none_or(|set| set.contains(c.as_str()))
            })
 // bucket-level
 // date pruning. Drop any bucket whose YYYY-MM range
 // falls entirely outside the query's date window
 // before paying for a transport round-trip. This is a
 // pure no-op when neither `date_from` nor `date_to` is
 // set.
            .filter(|(_, bucket)| {
                bucket_overlaps_date_range(bucket.as_str(), query.date_from, query.date_to)
            })
            .collect();
        if buckets.is_empty() {
            return Ok(local);
        }
        // TenantSearchPolicy enforcement #3: cap the cold-bucket
        // fan-out so a misbehaving query (e.g. a Global search
        // over a tenant with thousands of buckets) cannot pin the
        // device for minutes. We truncate after date pruning so
        // the budget covers buckets that actually need fetching.
        let buckets: Vec<(String, String)> = buckets
            .into_iter()
            .take(policy.max_cold_buckets_per_search)
            .collect();

        let mut by_id: HashMap<String, SearchResult> = HashMap::new();
        for r in local {
            by_id.insert(r.message_id.to_string(), r);
        }

        // Snapshot the IDs that came from the local FTS / fuzzy
        // pass. Their `rank_score` already had the Task-3 recency
        // × kind weighting applied inside
        // [`Self::execute_fts_and_fuzzy_with_filters`], so the
        // cold-only re-weighting step at the end of this method
        // must skip them — otherwise any message that surfaces in
        // both local and cold paths would have recency × kind
        // applied twice.
        let local_ids: HashSet<String> = by_id.keys().cloned().collect();

        // Tokenize once: the same query is reused for every
        // (conversation_id, time_bucket) pair.
        let q_words = lowercase_word_set(trimmed);
        let q_tokens = FuzzyTokenizer::generate_tokens(trimmed);
        // Group fuzzy tokens by script so the cold path applies
        // the same per-script overlap threshold as
        // [`FuzzySearchEngine::search_fuzzy`].
        let mut q_by_script: HashMap<ScriptClass, HashSet<String>> = HashMap::new();
        for t in &q_tokens {
            q_by_script
                .entry(t.script)
                .or_default()
                .insert(t.token.clone());
        }
        let q_count_fuzzy: f64 = q_by_script.values().map(|s| s.len()).sum::<usize>() as f64;

        for (conv, bucket) in buckets {
            // bloom-filter
            // pre-check. Consult the bloom shard for this bucket
            // and skip the bucket entirely when it rejects every
            // query token. Empty `q_words` (e.g. a query that
            // tokenizes only into fuzzy tokens) bypasses the
            // pre-check so we don't accidentally drop fuzzy-only
            // hits.
            let bloom =
                cold_source_fetch_bloom_with_cache(cold_source, shard_cache, &conv, &bucket);
            if policy.require_bloom_shards && !matches!(bloom, Ok(Some(_))) {
                continue;
            }
            if let Ok(Some(filter)) = &bloom {
                if !q_words.is_empty() && !q_words.iter().any(|w| filter.maybe_contains(w)) {
                    continue;
                }
            }

            // Cache lookup → fall back to transport on miss.
            let fts_rows =
                cold_source_fetch_text_with_cache(cold_source, shard_cache, &conv, &bucket)?;
            let fuzzy_rows =
                cold_source_fetch_fuzzy_with_cache(cold_source, shard_cache, &conv, &bucket)?;

            merge_bucket_rows_into_by_id(
                &mut by_id,
                query,
                &fts_rows,
                &fuzzy_rows,
                &q_words,
                &q_by_script,
                q_count_fuzzy,
            );
        }

        let mut out: Vec<SearchResult> = by_id.into_values().collect();

        // Apply the Task 3 recency × kind weighting to the rows
        // that came exclusively from the cold path. Rows that
        // were also surfaced by local FTS / fuzzy already had
        // recency × kind applied inside
        // [`Self::execute_fts_and_fuzzy_with_filters`] — we must
        // not re-weight them or the score would be doubled.
        self.apply_cold_recency_weight(&mut out, &local_ids);

        out.sort_by(|a, b| {
            b.rank_score
                .partial_cmp(&a.rank_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        out.truncate(limit);
        Ok(out)
    }

    /// parallel-fetch
    /// twin of
    /// [`Self::execute_search_with_cold_source_full`].
    ///
    /// Identical contract to the sequential entry point, except
    /// the per-bucket `(bloom, text, fuzzy)` fetches are issued
    /// in parallel through a [`std::thread::scope`] worker pool
    /// of at most `concurrency` threads. The merge step itself
    /// stays single-threaded — the parallelism is in the
    /// (transport-bound) shard fetch / decrypt path, which
    /// `docs/DESIGN.md §7.5` calls out as the hot critical
    /// section in the multi-bucket fan-out. Setting
    /// `concurrency = 1` collapses the path back to the
    /// sequential loop while still threading the same code path.
    ///
    /// The trait bound is `Send + Sync` so the source can be
    /// shared across worker threads. Implementations that hold
    /// `RefCell` / non-`Sync` interior state (e.g.
    /// [`crate::search::cold_shard_source::GracefulCold`]) must
    /// continue to use the sequential entry point.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_search_with_cold_source_full_parallel(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
        cold_source: &(dyn ColdShardSource + Send + Sync),
        policy: &TenantSearchPolicy,
        shard_cache: Option<&Mutex<ShardCache>>,
        limit: usize,
        concurrency: usize,
    ) -> Result<Vec<SearchResult>, Error> {
        // Reuse every short-circuit and bucket-resolution branch
        // from the sequential method up through the bucket list.
        // This keeps the two paths' behaviour aligned (same
        // `LocalOnly` short-circuit, same `allow_global_search`
        // gate, same target_set / date pruning / policy cap)
        // and limits the parallel-specific code to the
        // fetch + merge fan-out. `e.into` preserves the typed
        // `SearchError::Sqlite` path for rusqlite-driven failures
        // (same rationale as the sequential cold-source method).
        let local = self
            .execute_search_with_limit(query, scope, limit)
            .map_err(|e| Error::Search(e.into()))?;
        if !matches!(scope, SearchScope::IncludeCold) {
            return Ok(local);
        }
        let trimmed = query.query_string.trim();
        if trimmed.is_empty() {
            return Ok(local);
        }
        if let Some(kind) = query.content_kind {
            if !matches!(kind, ContentKind::Text | ContentKind::Any) {
                return Ok(local);
            }
        }
        let effective_target = query.effective_target();
        let is_global_target = matches!(effective_target, SearchTarget::Global);
        if is_global_target && !policy.allow_global_search {
            return Ok(local);
        }

        let buckets = cold_source.cold_buckets()?;
        if buckets.is_empty() {
            return Ok(local);
        }
        let conv_filter = query.conversation_filter.map(|c| c.to_string());
        #[allow(clippy::manual_unwrap_or_default)]
        let target_set: Option<HashSet<String>> =
            match resolve_target_to_conversation_set(&query.effective_target(), self.conn) {
                Ok(opt) => opt,
                Err(_) => None,
            };
        let buckets: Vec<(String, String)> = buckets
            .into_iter()
            .filter(|(c, _)| conv_filter.as_deref().is_none_or(|cf| cf == c.as_str()))
            .filter(|(c, _)| {
                target_set
                    .as_ref()
                    .is_none_or(|set| set.contains(c.as_str()))
            })
            .filter(|(_, bucket)| {
                bucket_overlaps_date_range(bucket.as_str(), query.date_from, query.date_to)
            })
            .collect();
        if buckets.is_empty() {
            return Ok(local);
        }
        let buckets: Vec<(String, String)> = buckets
            .into_iter()
            .take(policy.max_cold_buckets_per_search)
            .collect();

        let mut by_id: HashMap<String, SearchResult> = HashMap::new();
        for r in local {
            by_id.insert(r.message_id.to_string(), r);
        }
        let local_ids: HashSet<String> = by_id.keys().cloned().collect();

        let q_words = lowercase_word_set(trimmed);
        let q_tokens = FuzzyTokenizer::generate_tokens(trimmed);
        let mut q_by_script: HashMap<ScriptClass, HashSet<String>> = HashMap::new();
        for t in &q_tokens {
            q_by_script
                .entry(t.script)
                .or_default()
                .insert(t.token.clone());
        }
        let q_count_fuzzy: f64 = q_by_script.values().map(|s| s.len()).sum::<usize>() as f64;

        // Parallel fetch — `parallel_fetch_buckets` honors the
        // bloom pre-check internally so a bucket the bloom
        // rejects costs only the bloom round-trip, never the
        // full text/fuzzy fetch.
        let prefetched = parallel_fetch_buckets(
            cold_source,
            shard_cache,
            &buckets,
            policy.require_bloom_shards,
            &q_words,
            concurrency,
        );

        for entry in prefetched {
            // Re-apply the bloom gating policy at the merge
            // boundary so the parallel and sequential paths
            // produce byte-for-byte identical `by_id` updates.
            // `parallel_fetch_buckets` already short-circuited
            // the text/fuzzy fetches when the bloom rejected,
            // so this loop just refuses to merge the empty
            // result through the rest of the pipeline. A
            // transport error on bloom is fail-open: we treat
            // it as "no shard available" and let the
            // text/fuzzy results decide the bucket.
            if policy.require_bloom_shards && !matches!(entry.bloom, Ok(Some(_))) {
                continue;
            }
            if let Ok(Some(filter)) = &entry.bloom {
                if !q_words.is_empty() && !q_words.iter().any(|w| filter.maybe_contains(w)) {
                    continue;
                }
            }
            // Per-bucket fail-open on the text/fuzzy fetches:
            // a single broken bucket (404, decrypt failure,
            // …) is logged at the cold-source layer (graceful
            // wrappers swallow soft errors) but still yields
            // an `Err` here for hard failures. Skip the bucket
            // rather than aborting the whole search.
            let (Ok(fts_rows), Ok(fuzzy_rows)) = (entry.text, entry.fuzzy) else {
                continue;
            };
            merge_bucket_rows_into_by_id(
                &mut by_id,
                query,
                &fts_rows,
                &fuzzy_rows,
                &q_words,
                &q_by_script,
                q_count_fuzzy,
            );
        }

        let mut out: Vec<SearchResult> = by_id.into_values().collect();
        self.apply_cold_recency_weight(&mut out, &local_ids);
        out.sort_by(|a, b| {
            b.rank_score
                .partial_cmp(&a.rank_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        out.truncate(limit);
        Ok(out)
    }

    /// streaming
    /// search variant.
    ///
    /// Drives the same bucket fan-out as
    /// [`Self::execute_search_with_cold_source_full`] but emits
    /// a [`crate::SearchEvent`] callback after each state
    /// change (local results, each cold bucket, final
    /// completion). The callback is invoked synchronously on
    /// the calling thread between (sequential) fetches — there
    /// is no implicit threading here. Wire callers can
    /// re-dispatch from the callback as needed.
    ///
    /// `SearchScope::LocalOnly` searches emit
    /// [`SearchEvent::LocalResults`] followed immediately by
    /// [`SearchEvent::SearchComplete`] (no cold events) so the
    /// UI can keep one listener regardless of scope.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_search_streaming<F: FnMut(crate::SearchEvent)>(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
        cold_source: &dyn ColdShardSource,
        policy: &TenantSearchPolicy,
        shard_cache: Option<&Mutex<ShardCache>>,
        limit: usize,
        mut emit: F,
    ) -> Result<Vec<SearchResult>, Error> {
        // `e.into` preserves the typed `SearchError::Sqlite`
        // path for rusqlite-driven failures, matching the
        // sequential / parallel cold-source paths above.
        let local = self
            .execute_search_with_limit(query, scope, limit)
            .map_err(|e| Error::Search(e.into()))?;
        emit(crate::SearchEvent::LocalResults(local.clone()));

        // Replicate every short-circuit branch from the
        // sequential cold path so LocalOnly / empty / non-text
        // / Global+!allow searches still emit a SearchComplete.
        let cold_disabled = !matches!(scope, SearchScope::IncludeCold);
        let trimmed = query.query_string.trim();
        let kind_blocks_cold = matches!(query.content_kind, Some(k)
            if !matches!(k, ContentKind::Text | ContentKind::Any));
        let global_blocked =
            matches!(query.effective_target(), SearchTarget::Global) && !policy.allow_global_search;

        if cold_disabled || trimmed.is_empty() || kind_blocks_cold || global_blocked {
            emit(crate::SearchEvent::SearchComplete {
                total_results: local.clone(),
                cold_buckets_fetched: 0,
                cold_buckets_skipped: 0,
            });
            return Ok(local);
        }

        // Cold-bucket enumeration is the only fallible step
        // between the `LocalResults` emission above and the
        // `SearchComplete` emissions below. To honor the
        // documented "SearchComplete is emitted exactly once"
        // contract on `crate::SearchEvent`, treat a
        // `cold_buckets` failure as a fail-open: emit
        // `SearchComplete` carrying the local results so the
        // listener has a terminal signal, then propagate the
        // underlying error to the synchronous return value.
        let buckets = match cold_source.cold_buckets() {
            Ok(b) => b,
            Err(e) => {
                emit(crate::SearchEvent::SearchComplete {
                    total_results: local.clone(),
                    cold_buckets_fetched: 0,
                    cold_buckets_skipped: 0,
                });
                return Err(e);
            }
        };
        let conv_filter = query.conversation_filter.map(|c| c.to_string());
        #[allow(clippy::manual_unwrap_or_default)]
        let target_set: Option<HashSet<String>> =
            match resolve_target_to_conversation_set(&query.effective_target(), self.conn) {
                Ok(opt) => opt,
                Err(_) => None,
            };
        let buckets: Vec<(String, String)> = buckets
            .into_iter()
            .filter(|(c, _)| conv_filter.as_deref().is_none_or(|cf| cf == c.as_str()))
            .filter(|(c, _)| {
                target_set
                    .as_ref()
                    .is_none_or(|set| set.contains(c.as_str()))
            })
            .filter(|(_, bucket)| {
                bucket_overlaps_date_range(bucket.as_str(), query.date_from, query.date_to)
            })
            .take(policy.max_cold_buckets_per_search)
            .collect();

        if buckets.is_empty() {
            emit(crate::SearchEvent::SearchComplete {
                total_results: local.clone(),
                cold_buckets_fetched: 0,
                cold_buckets_skipped: 0,
            });
            return Ok(local);
        }

        let mut by_id: HashMap<String, SearchResult> = HashMap::new();
        for r in local.iter() {
            by_id.insert(r.message_id.to_string(), r.clone());
        }
        let local_ids: HashSet<String> = by_id.keys().cloned().collect();

        let q_words = lowercase_word_set(trimmed);
        let q_tokens = FuzzyTokenizer::generate_tokens(trimmed);
        let mut q_by_script: HashMap<ScriptClass, HashSet<String>> = HashMap::new();
        for t in &q_tokens {
            q_by_script
                .entry(t.script)
                .or_default()
                .insert(t.token.clone());
        }
        let q_count_fuzzy: f64 = q_by_script.values().map(|s| s.len()).sum::<usize>() as f64;

        let mut fetched: usize = 0;
        let mut skipped: usize = 0;

        for (conv, bucket) in buckets {
            // Snapshot the current message-id set so we can
            // compute the per-bucket delta after the merge.
            let pre_ids: HashSet<String> = by_id.keys().cloned().collect();

            let bloom =
                cold_source_fetch_bloom_with_cache(cold_source, shard_cache, &conv, &bucket);
            if policy.require_bloom_shards && !matches!(bloom, Ok(Some(_))) {
                skipped += 1;
                emit(crate::SearchEvent::ColdBucketComplete {
                    conversation_id: conv,
                    time_bucket: bucket,
                    new_hits: Vec::new(),
                });
                continue;
            }
            if let Ok(Some(filter)) = &bloom {
                if !q_words.is_empty() && !q_words.iter().any(|w| filter.maybe_contains(w)) {
                    skipped += 1;
                    emit(crate::SearchEvent::ColdBucketComplete {
                        conversation_id: conv,
                        time_bucket: bucket,
                        new_hits: Vec::new(),
                    });
                    continue;
                }
            }

            let fts_rows =
                match cold_source_fetch_text_with_cache(cold_source, shard_cache, &conv, &bucket) {
                    Ok(v) => v,
                    Err(_) => {
                        // Per-bucket fail-open mirror: skip
                        // this bucket and emit an empty delta
                        // so downstream listeners still see a
                        // bucket-complete event.
                        skipped += 1;
                        emit(crate::SearchEvent::ColdBucketComplete {
                            conversation_id: conv,
                            time_bucket: bucket,
                            new_hits: Vec::new(),
                        });
                        continue;
                    }
                };
            let fuzzy_rows = match cold_source_fetch_fuzzy_with_cache(
                cold_source,
                shard_cache,
                &conv,
                &bucket,
            ) {
                Ok(v) => v,
                Err(_) => {
                    skipped += 1;
                    emit(crate::SearchEvent::ColdBucketComplete {
                        conversation_id: conv,
                        time_bucket: bucket,
                        new_hits: Vec::new(),
                    });
                    continue;
                }
            };

            merge_bucket_rows_into_by_id(
                &mut by_id,
                query,
                &fts_rows,
                &fuzzy_rows,
                &q_words,
                &q_by_script,
                q_count_fuzzy,
            );
            fetched += 1;

            // Compute the delta — every message_id that wasn't
            // in `pre_ids` was newly introduced by this bucket.
            let new_hits: Vec<SearchResult> = by_id
                .iter()
                .filter(|(k, _)| !pre_ids.contains(*k))
                .map(|(_, v)| v.clone())
                .collect();
            emit(crate::SearchEvent::ColdBucketComplete {
                conversation_id: conv,
                time_bucket: bucket,
                new_hits,
            });
        }

        let mut out: Vec<SearchResult> = by_id.into_values().collect();
        self.apply_cold_recency_weight(&mut out, &local_ids);
        out.sort_by(|a, b| {
            b.rank_score
                .partial_cmp(&a.rank_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        out.truncate(limit);
        emit(crate::SearchEvent::SearchComplete {
            total_results: out.clone(),
            cold_buckets_fetched: fetched,
            cold_buckets_skipped: skipped,
        });
        Ok(out)
    }

    /// Cold-path variant of [`Self::apply_recency_and_kind_weight`]
    /// that skips the `message_skeleton` lookup. Re-weights only
    /// the rows whose `message_id` is **not** in `local_ids`
    /// those rows came exclusively from the cold path and have
    /// not had Task 3 applied yet. Rows that exist in both local
    /// and cold (i.e. their ID is in `local_ids`) had recency ×
    /// kind applied during the local FTS / fuzzy pass and must
    /// not be re-weighted here.
    fn apply_cold_recency_weight(&self, results: &mut [SearchResult], local_ids: &HashSet<String>) {
        if results.is_empty() {
            return;
        }
        let now_ms = results.iter().map(|r| r.created_at_ms).max().unwrap_or(0);
        let lambda = std::f64::consts::LN_2 / RECENCY_HALF_LIFE_DAYS;
        for r in results.iter_mut() {
            if local_ids.contains(&r.message_id.to_string()) {
                continue;
            }
            let age_ms = (now_ms - r.created_at_ms).max(0) as f64;
            let age_days = age_ms / 86_400_000.0;
            let recency_score = (-lambda * age_days).exp();
            let recency_factor = (1.0 - RECENCY_WEIGHT) + RECENCY_WEIGHT * recency_score;
            // Cold-only rows are decrypted text shards by
            // construction (only ships text + fuzzy cold
            // paths), so we pin the kind weight to
            // `TEXT_KIND_WEIGHT`.
            r.rank_score *= recency_factor * TEXT_KIND_WEIGHT;
        }
    }

    /// Stamp `SearchResult::is_cold = true` on every row whose
    /// owning skeleton has `body_state = 'remote_archive_only'`.
    /// Rows whose body is `local_plain_available` /
    /// `local_encrypted_available` keep `is_cold = false` so the
    /// hydration queue does not chase already-resident bodies.
    fn mark_cold_results(&self, results: &mut [SearchResult]) -> DbResult<()> {
        if results.is_empty() {
            return Ok(());
        }
        let ids: Vec<String> = results.iter().map(|r| r.message_id.to_string()).collect();
        let placeholders = (0..ids.len())
            .map(|i| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT message_id, body_state
               FROM message_skeleton
              WHERE message_id IN ({placeholders})"
        );
        let conn = self.conn;
        let mut stmt = conn.prepare(&sql)?;
        let mut binds: Vec<Value> = Vec::with_capacity(ids.len());
        for id in &ids {
            binds.push(Value::Text(id.clone()));
        }
        let mut state_by_id: HashMap<String, String> = HashMap::new();
        let rows = stmt.query_map(params_from_iter(binds.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for r in rows {
            let (mid, state) = r?;
            state_by_id.insert(mid, state);
        }
        for result in results.iter_mut() {
            if let Some(state) = state_by_id.get(&result.message_id.to_string()) {
                if state == "remote_archive_only" {
                    result.is_cold = true;
                }
            }
        }
        Ok(())
    }

    // ----------------------------------------------------------------
    // Semantic reranking
    // ----------------------------------------------------------------

    /// Run a unified search and merge in cosine-similarity hits
    /// from the on-device `search_vector` table.
    ///
    /// `text_embedder` is the [`TextEmbedder`] previously
    /// installed via
    /// [`crate::core_impl::CoreImpl::install_text_embedder`].
    /// When `text_embedder.embed` succeeds, the engine fans the
    /// query embedding through
    /// [`crate::search::semantic_search::SemanticSearchEngine`]
    /// and merges the hits into the FTS / fuzzy candidate set:
    ///
    /// * Rows that already had an FTS or fuzzy hit have
    ///   `cosine * SEMANTIC_WEIGHT` added to `rank_score`. The
    ///   FTS / fuzzy pass already folded recency × content-kind
    ///   into the row, so the semantic contribution stacks on
    ///   top without re-applying that multiplier.
    /// * Rows that **only** appear via semantic search are added
    ///   to the result set with `rank_score =
    ///   cosine * SEMANTIC_WEIGHT * recency_factor *
    ///   kind_weight`. The recency anchor is the maximum
    ///   `created_at_ms` across the combined candidate set
    ///   FTS / fuzzy hits in `local` plus the semantic-only
    ///   skeletons — so the half-life decay is honoured. (An
    ///   earlier bug computed the anchor from a single-element
    ///   slice, which collapsed `age_ms` to `0` and made the
    ///   factor always `1.0`.)
    ///
    /// When `text_embedder.embed` fails (or the query is
    /// empty / `embed` returns
    /// [`crate::Error::NotImplemented`]), the engine falls back
    /// to the FTS-only path.
    ///
    /// `is_cold` is stamped against the **merged** result set
    /// when `scope == IncludeCold`. Semantic-only hits whose
    /// owning skeleton has `body_state = 'remote_archive_only'`
    /// are flagged so the `HydrationQueue` can enqueue the cold
    /// body for hydration at `SearchResultTap` priority — the
    /// initial materialization defaults `is_cold: false` because
    /// the skeleton-fetch projection does not include
    /// `body_state`.
    ///
    /// `query.sender_filter`, `query.date_from`, `query.date_to`,
    /// and `query.content_kind` apply uniformly to both lanes:
    /// the FTS / fuzzy lane filters via `allowed_skeleton_ids`
    /// during candidate building, and the semantic-only lane
    /// re-runs `allowed_skeleton_ids` against the
    /// `SemanticMatch::message_id` set before materializing
    /// fresh `SearchResult`s. Without that guard a query like
    /// `{ sender_filter: Some("alice"), date_from: Some(yesterday) }`
    /// would surface alice's FTS hits plus arbitrary
    /// semantic-only hits from any sender / any date.
    ///
    /// `model_version` defaults to
    /// [`crate::models::embeddings::XLMR_MODEL_VERSION`] when
    /// `None` is passed.
    pub fn execute_search_with_semantic(
        &self,
        query: &SearchQuery,
        scope: &SearchScope,
        text_embedder: &dyn crate::models::embeddings::TextEmbedder,
        model_version: Option<&str>,
        limit: usize,
    ) -> DbResult<Vec<SearchResult>> {
        let mut local = self.execute_search_with_limit(query, scope, limit)?;
        let trimmed = query.query_string.trim();
        if trimmed.is_empty() {
            return Ok(local);
        }
        // Embed the query. If the embedder is a Noop / failure,
        // fall back to the FTS-only path silently.
        let q_emb = match text_embedder.embed(trimmed) {
            Ok(v) => v,
            Err(_) => return Ok(local),
        };
        let mv = model_version.unwrap_or(crate::models::embeddings::XLMR_MODEL_VERSION);
        let conn = self.conn;
        let semantic = crate::search::semantic_search::SemanticSearchEngine::new(conn);
        let conv_filter_str = query.conversation_filter.map(|c| c.to_string());
        let hits = match semantic.search_semantic(
            &q_emb,
            conv_filter_str.as_deref(),
            limit.max(1),
            Some(mv),
        ) {
            Ok(h) => h,
            Err(_) => return Ok(local),
        };
        if hits.is_empty() {
            return Ok(local);
        }

        let mut by_id: HashMap<String, usize> = HashMap::new();
        for (idx, r) in local.iter().enumerate() {
            by_id.insert(r.message_id.to_string(), idx);
        }

        // Bulk-fetch skeleton metadata for any semantic-only hit
        // we'll need to materialize as a fresh SearchResult. The
        // projection includes `kind` so the recency × content-kind
        // multiplier can be applied inline without a second round
        // trip.
        let new_ids: Vec<String> = hits
            .iter()
            .filter(|h| !by_id.contains_key(&h.message_id))
            .map(|h| h.message_id.clone())
            .collect();
        // Apply the structured filters (`sender_filter`,
        // `date_from`, `date_to`, `content_kind`) to the
        // semantic-only candidate set the same way the
        // FTS / fuzzy pass does via `allowed_skeleton_ids`.
        // FTS / fuzzy hits are already in `local` and were
        // filtered by `execute_search_with_limit`; this guards
        // the *semantic-only* path so a query like
        // `{ sender_filter: Some("alice"),
        // date_from: Some(yesterday) }` cannot leak hits
        // from other senders or outside the date window.
        // `allowed_skeleton_ids` returns `None` when no
        // structured filter is set — keep the candidate set
        // intact in that case.
        let new_ids: Vec<String> = match self.allowed_skeleton_ids(query, &new_ids)? {
            Some(allowed) => new_ids
                .into_iter()
                .filter(|m| allowed.contains(m))
                .collect(),
            None => new_ids,
        };
        let new_skeletons = if !new_ids.is_empty() {
            self.fetch_skeleton_columns_for_semantic(&new_ids)?
        } else {
            HashMap::new()
        };

        // Anchor `now_ms` against the combined candidate set
        // FTS / fuzzy hits already in `local` plus any
        // semantic-only hit the bulk fetch resolved. This matches
        // `apply_cold_recency_weight`'s pattern. Anchoring on a
        // single-element slice (the previous bug) collapsed
        // `age_ms` to `0` for every semantic-only hit and made
        // `recency_factor` always `1.0`, defeating the
        // `RECENCY_HALF_LIFE_DAYS` decay.
        let now_ms: i64 = local
            .iter()
            .map(|r| r.created_at_ms)
            .chain(new_skeletons.values().map(|s| s.created_at_ms))
            .max()
            .unwrap_or(0);
        let lambda = std::f64::consts::LN_2 / RECENCY_HALF_LIFE_DAYS;

        for hit in hits {
            let raw_similarity = hit.similarity as f64;
            let semantic_contribution = raw_similarity * SEMANTIC_WEIGHT;
            if let Some(&idx) = by_id.get(&hit.message_id) {
                // FTS / fuzzy already applied recency × kind in
                // `execute_search_with_limit`; just stack the
                // semantic contribution on top.
                local[idx].rank_score += semantic_contribution;
                // expose the
                // raw cosine similarity so the reranker
                // (`rerank_with_semantic`) and downstream
                // consumers can reason about the semantic
                // contribution independently of the merged
                // ranking formula.
                local[idx].semantic_score = Some(raw_similarity);
                continue;
            }
            // Semantic-only hit: build a fresh SearchResult.
            let Some(meta) = new_skeletons.get(&hit.message_id) else {
                continue;
            };
            let Ok(message_uuid) = Uuid::parse_str(&hit.message_id) else {
                continue;
            };
            let Ok(conv_uuid) = Uuid::parse_str(&meta.conversation_id) else {
                continue;
            };
            // Inline the same recency × content-kind multiplier
            // that `apply_recency_and_kind_weight` produces, but
            // anchored on the combined-set `now_ms` rather than
            // re-deriving it from a single-element slice.
            let age_ms = (now_ms - meta.created_at_ms).max(0) as f64;
            let age_days = age_ms / 86_400_000.0;
            let recency_score = (-lambda * age_days).exp();
            let recency_factor = (1.0 - RECENCY_WEIGHT) + RECENCY_WEIGHT * recency_score;
            let kind_w = kind_str_to_weight(meta.kind.as_str());
            let weighted = semantic_contribution * recency_factor * kind_w;
            local.push(SearchResult {
                message_id: message_uuid,
                conversation_id: conv_uuid,
                sender_id: meta.sender_id.clone(),
                created_at_ms: meta.created_at_ms,
                rank_score: weighted,
                is_cold: false,
                snippet: None,
                semantic_score: Some(raw_similarity),
            });
        }
        // Re-sort: descending rank_score, then created_at DESC,
        // then message_id for determinism.
        local.sort_by(|a, b| {
            b.rank_score
                .partial_cmp(&a.rank_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        local.truncate(limit);
        // Re-stamp `is_cold` against the merged set. Semantic-
        // only rows pushed onto `local` were materialized with
        // `is_cold: false` because `fetch_skeleton_columns_for_semantic`
        // doesn't read `body_state`; without this pass an
        // offloaded message (`body_state = 'remote_archive_only'`)
        // whose vector still lives in `search_vector` would
        // surface with `is_cold = false`, and the
        // `HydrationQueue` would never enqueue it for
        // `SearchResultTap`-priority body fetch. The FTS / fuzzy
        // rows in `local` were already marked once by
        // `execute_search_with_limit`; `mark_cold_results` is
        // idempotent.
        if matches!(scope, SearchScope::IncludeCold) {
            self.mark_cold_results(&mut local)?;
        }
        Ok(local)
    }

    /// Re-score an existing [`SearchResult`] set against the
    /// supplied query embedding, using the same brute-force
    /// cosine-similarity engine that powers
    /// [`Self::execute_search_with_semantic`].
    /// the "on-device reranking" item from
    ///
    /// The pass is purely local: it reads from `search_vector`
    /// and never fans to the cold archive, regardless of
    /// `scope`. When `scope == SearchScope::IncludeCold` the
    /// caller is expected to have already populated the
    /// cold-hit subset (via [`Self::execute_search_with_cold_source_and_limit`]
    /// or similar) — this method only updates the rows whose
    /// `message_id` has a matching row in `search_vector`.
    /// Cold rows whose embeddings have not yet been hydrated
    /// keep their existing `rank_score` and `semantic_score`.
    ///
    /// `model_version` defaults to
    /// [`crate::models::embeddings::XLMR_MODEL_VERSION`] when
    /// `None` is supplied.
    ///
    /// The method:
    ///
    /// 1. L2-renormalizes `query_embedding` defensively.
    /// 2. Reads every `search_vector` row whose
    ///    `model_version` matches.
    /// 3. For each input result whose `message_id` has a
    ///    matching row, computes raw cosine similarity, sets
    ///    `semantic_score = Some(sim)`, and adds
    ///    `sim * SEMANTIC_WEIGHT` to `rank_score`.
    /// 4. Re-sorts by descending `rank_score`,
    ///    descending `created_at_ms`, ascending `message_id`.
    pub fn rerank_with_semantic(
        &self,
        results: &mut [SearchResult],
        query_embedding: &[f32],
        model_version: Option<&str>,
        scope: &SearchScope,
    ) -> DbResult<()> {
        if results.is_empty() || query_embedding.is_empty() {
            return Ok(());
        }
        let mv = model_version.unwrap_or(crate::models::embeddings::XLMR_MODEL_VERSION);

        // respect SearchScope::LocalOnly by
        // never fanning beyond `search_vector`. The brute-force
        // sweep below only reads local SQLite rows, so this is
        // satisfied unconditionally — the scope match is kept
        // explicit so future "fan to remote" branches must
        // re-decide whether to honor LocalOnly.
        match scope {
            SearchScope::LocalOnly | SearchScope::IncludeCold => {}
        }

        // Use a parameterized `IN (...)` clause keyed
        // by `message_id` so the lookup is O(k · log N) against
        // the `(message_id, model_version)` primary-key index
        // instead of an O(N) sweep across every embedding for
        // this `model_version`. This matches the pattern in
        // [`Self::fetch_skeleton_columns_for_semantic`] and
        // [`apply_recency_and_kind_weight`].
        let ids: Vec<String> = results.iter().map(|r| r.message_id.to_string()).collect();
        // Bind layout: ?1 = model_version, ?2..?{N+1} = message_ids.
        let placeholders = (0..ids.len())
            .map(|i| format!("?{}", i + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT message_id, embedding FROM search_vector
              WHERE model_version = ?1
                AND message_id IN ({placeholders})"
        );
        let conn = self.conn;
        let mut stmt = conn.prepare(&sql)?;
        let mut binds: Vec<Value> = Vec::with_capacity(ids.len() + 1);
        binds.push(Value::Text(mv.to_string()));
        for id in &ids {
            binds.push(Value::Text(id.clone()));
        }
        let mut by_id: HashMap<String, Vec<u8>> = HashMap::new();
        let mut rows = stmt.query(params_from_iter(binds.iter()))?;
        while let Some(row) = rows.next()? {
            let mid: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            by_id.insert(mid, blob);
        }

        let q = crate::search::semantic_search::l2_normalize(query_embedding);
        for r in results.iter_mut() {
            let key = r.message_id.to_string();
            let Some(blob) = by_id.get(&key) else {
                continue;
            };
            let stored = crate::models::embeddings::dequantize_int8_for_search(blob);
            if stored.is_empty() || stored.len() != q.len() {
                continue;
            }
            let sim = crate::search::semantic_search::cosine(&q, &stored) as f64;
            r.semantic_score = Some(sim);
            r.rank_score += sim * SEMANTIC_WEIGHT;
        }

        // Re-sort: descending rank_score, then created_at DESC,
        // then message_id for determinism. Same ordering as
        // `execute_search_with_semantic`.
        results.sort_by(|a, b| {
            b.rank_score
                .partial_cmp(&a.rank_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        Ok(())
    }

    fn fetch_skeleton_columns_for_semantic(
        &self,
        ids: &[String],
    ) -> DbResult<HashMap<String, SemanticSkeletonInfo>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = (0..ids.len())
            .map(|i| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT message_id, conversation_id, sender_id, created_at_ms, kind
               FROM message_skeleton
              WHERE message_id IN ({placeholders})"
        );
        let conn = self.conn;
        let mut stmt = conn.prepare(&sql)?;
        let mut binds: Vec<Value> = Vec::with_capacity(ids.len());
        for id in ids {
            binds.push(Value::Text(id.clone()));
        }
        let mut out: HashMap<String, SemanticSkeletonInfo> = HashMap::new();
        for r in stmt.query_map(params_from_iter(binds.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })? {
            let (mid, conv, sender, ts, kind) = r?;
            out.insert(
                mid,
                SemanticSkeletonInfo {
                    conversation_id: conv,
                    sender_id: sender,
                    created_at_ms: ts,
                    kind,
                },
            );
        }
        Ok(out)
    }

    // ----------------------------------------------------------------
    // Structured-only path (no FTS query string)
    // ----------------------------------------------------------------

    fn execute_structured_only(
        &self,
        query: &SearchQuery,
        limit: usize,
    ) -> DbResult<Vec<SearchResult>> {
        let mut sql = String::from(
            "SELECT message_id, conversation_id, sender_id, created_at_ms
             FROM message_skeleton",
        );
        let mut clauses: Vec<String> = Vec::new();
        let mut binds: Vec<Value> = Vec::new();
        push_structured_filters(query, &mut clauses, &mut binds);
        push_target_filter(
            &query.effective_target(),
            self.conn,
            &mut clauses,
            &mut binds,
        );
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY created_at_ms DESC LIMIT ?");
        binds.push(Value::Integer(limit as i64));

        let conn = self.conn;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(binds.iter()), |row| {
                let mid: String = row.get(0)?;
                let cid: String = row.get(1)?;
                let sid: String = row.get(2)?;
                let ts: i64 = row.get(3)?;
                Ok((mid, cid, sid, ts))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut out = Vec::with_capacity(rows.len());
        for (mid, cid, sid, ts) in rows {
            let mid_uuid = Uuid::parse_str(&mid).unwrap_or(Uuid::nil());
            let cid_uuid = Uuid::parse_str(&cid).unwrap_or(Uuid::nil());
            out.push(SearchResult {
                message_id: mid_uuid,
                conversation_id: cid_uuid,
                sender_id: sid,
                created_at_ms: ts,
                snippet: None,
                rank_score: 0.0,
                is_cold: false,
                semantic_score: None,
            });
        }
        Ok(out)
    }

    // ----------------------------------------------------------------
    // FTS + fuzzy + structured-filters path
    // ----------------------------------------------------------------

    fn execute_fts_and_fuzzy_with_filters(
        &self,
        query: &SearchQuery,
        query_string: &str,
        limit: usize,
    ) -> DbResult<Vec<SearchResult>> {
        let fts_engine = TextSearchEngine::new(self.conn, self.icu_available);
        let fuzzy_engine = FuzzySearchEngine::new(self.conn);
        // Over-fetch each engine so the post-filter / dedup still has
        // enough rows to satisfy `limit`. 4× is a heuristic; the
        // structured-only path applies a hard ceiling.
        let fetch = limit.saturating_mul(4).max(limit);
        let fts_hits = fts_engine.search_fts(query_string, fetch)?;
        let fuzzy_hits = fuzzy_engine.search_fuzzy(query_string, fetch)?;
        if fts_hits.is_empty() && fuzzy_hits.is_empty() {
            return Ok(Vec::new());
        }

        // Apply the structured filters across the union of FTS and
        // fuzzy candidates. We pass the candidate ids in once so
        // structured filtering is a single SQL round-trip.
        let candidate_ids: Vec<String> = fts_hits
            .iter()
            .map(|h| h.message_id.clone())
            .chain(fuzzy_hits.iter().map(|f| f.message_id.clone()))
            .collect();
        let allowed_ids = self.allowed_skeleton_ids(query, &candidate_ids)?;

        // Merge FTS hits first — they carry conversation / sender /
        // created_at_ms inline, so we never need a per-row skeleton
        // lookup for them.
        let mut by_id: HashMap<String, SearchResult> = HashMap::new();
        for h in fts_hits {
            if let Some(allow) = &allowed_ids {
                if !allow.contains(&h.message_id) {
                    continue;
                }
            }
            let mid_uuid = Uuid::parse_str(&h.message_id).unwrap_or(Uuid::nil());
            let cid_uuid = Uuid::parse_str(&h.conversation_id).unwrap_or(Uuid::nil());
            // FTS5's bm25 returns negative values — more negative is
            // more relevant. Flip the sign and weight per
            // `docs/DESIGN.md §7.5`.
            by_id.insert(
                h.message_id.clone(),
                SearchResult {
                    message_id: mid_uuid,
                    conversation_id: cid_uuid,
                    sender_id: h.sender_id,
                    created_at_ms: h.created_at_ms,
                    snippet: Some(h.snippet),
                    rank_score: -h.bm25_score * BM25_WEIGHT,
                    is_cold: false,
                    semantic_score: None,
                },
            );
        }

        // Resolve skeleton info for any fuzzy-only hit so we can
        // synthesize a SearchResult row without a snippet.
        let fuzzy_only_ids: Vec<String> = fuzzy_hits
            .iter()
            .filter(|f| !by_id.contains_key(&f.message_id))
            .map(|f| f.message_id.clone())
            .collect();
        let skel_info = if fuzzy_only_ids.is_empty() {
            HashMap::new()
        } else {
            self.fetch_skeleton_basic_info(&fuzzy_only_ids)?
        };

        for f in fuzzy_hits {
            if let Some(allow) = &allowed_ids {
                if !allow.contains(&f.message_id) {
                    continue;
                }
            }
            if let Some(existing) = by_id.get_mut(&f.message_id) {
                // Both engines hit this row: accumulate the fuzzy
                // contribution on top of the FTS rank.
                existing.rank_score += f.score * FUZZY_WEIGHT;
            } else if let Some(info) = skel_info.get(&f.message_id) {
                let mid_uuid = Uuid::parse_str(&f.message_id).unwrap_or(Uuid::nil());
                let cid_uuid = Uuid::parse_str(&info.conversation_id).unwrap_or(Uuid::nil());
                by_id.insert(
                    f.message_id.clone(),
                    SearchResult {
                        message_id: mid_uuid,
                        conversation_id: cid_uuid,
                        sender_id: info.sender_id.clone(),
                        created_at_ms: info.created_at_ms,
                        // Fuzzy rows do not produce highlighted
                        // snippets — those come from FTS5's snippet.
                        snippet: None,
                        rank_score: f.score * FUZZY_WEIGHT,
                        is_cold: false,
                        semantic_score: None,
                    },
                );
            }
            // If the skeleton lookup turned up nothing, the row was
            // tombstoned out from under us between the fuzzy index
            // and the skeleton table; drop it silently.
        }

        let mut out: Vec<SearchResult> = by_id.into_values().collect();

        // Apply the ranking-formula extensions:
        // recency decay + per-kind weight. The base BM25 + fuzzy
        // contributions are already accumulated in `rank_score`
        // above; this pass folds in the multiplicative factors
        // before the deterministic sort.
        self.apply_recency_and_kind_weight(&mut out)?;

        // Higher rank_score first; tie-break on created_at_ms DESC so
        // the order is deterministic.
        out.sort_by(|a, b| {
            b.rank_score
                .partial_cmp(&a.rank_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        out.truncate(limit);
        Ok(out)
    }

    /// Multiply each result's `rank_score` by its recency-decay
    /// factor and content-kind weight (`docs/DESIGN.md §7.5`).
    ///
    /// The reference timestamp anchoring "now" is the most-recent
    /// `created_at_ms` in the result set. This keeps the function
    /// deterministic for a given input and mirrors the offline
    /// orchestration that drives offload scoring.
    ///
    /// Recency factor uses [`RECENCY_WEIGHT`] as the floor so an
    /// ancient hit still surfaces — see the constant docs for the
    /// rationale.
    fn apply_recency_and_kind_weight(&self, results: &mut [SearchResult]) -> DbResult<()> {
        if results.is_empty() {
            return Ok(());
        }
        // Reference time = max(created_at_ms). The newest row
        // anchors `recency_score = 1.0`.
        let now_ms = results.iter().map(|r| r.created_at_ms).max().unwrap_or(0);

        // Bulk-fetch the `kind` column for every row in a single
        // round trip.
        let ids: Vec<String> = results.iter().map(|r| r.message_id.to_string()).collect();
        let placeholders = (0..ids.len())
            .map(|i| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT message_id, kind
               FROM message_skeleton
              WHERE message_id IN ({placeholders})"
        );
        let conn = self.conn;
        let mut stmt = conn.prepare(&sql)?;
        let mut binds: Vec<Value> = Vec::with_capacity(ids.len());
        for id in &ids {
            binds.push(Value::Text(id.clone()));
        }
        let mut kind_by_id: HashMap<String, String> = HashMap::new();
        for r in stmt.query_map(params_from_iter(binds.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (mid, kind) = r?;
            kind_by_id.insert(mid, kind);
        }

        let lambda = std::f64::consts::LN_2 / RECENCY_HALF_LIFE_DAYS;
        for r in results.iter_mut() {
            let age_ms = (now_ms - r.created_at_ms).max(0) as f64;
            let age_days = age_ms / 86_400_000.0;
            // recency_score in (0, 1]: 1.0 for the newest row,
            // exponentially decaying with a 30-day half-life.
            let recency_score = (-lambda * age_days).exp();
            // Floor the multiplicative factor at
            // `1 - RECENCY_WEIGHT` so old hits never collapse to
            // zero rank — they should still rank below newer
            // identical-relevance hits but stay visible.
            let recency_factor = (1.0 - RECENCY_WEIGHT) + RECENCY_WEIGHT * recency_score;
            // Default to text weight when the row is missing
            // from `message_skeleton` (cold-only rows can be
            // surfaced before the skeleton lands locally).
            let kind_w = kind_by_id
                .get(&r.message_id.to_string())
                .map(|k| kind_str_to_weight(k.as_str()))
                .unwrap_or(TEXT_KIND_WEIGHT);
            r.rank_score *= recency_factor * kind_w;
        }
        Ok(())
    }

    /// Run the structured filter query and return the set of
    /// `message_id`s allowed by the filters. `None` means "no
    /// structured filters applied — every row is allowed".
    fn allowed_skeleton_ids(
        &self,
        query: &SearchQuery,
        candidate_message_ids: &[String],
    ) -> DbResult<Option<HashSet<String>>> {
        let mut clauses: Vec<String> = Vec::new();
        let mut binds: Vec<Value> = Vec::new();
        push_structured_filters(query, &mut clauses, &mut binds);
        push_target_filter(
            &query.effective_target(),
            self.conn,
            &mut clauses,
            &mut binds,
        );
        if clauses.is_empty() {
            return Ok(None);
        }
        if candidate_message_ids.is_empty() {
            return Ok(Some(HashSet::new()));
        }

        // Restrict the structured query to the candidate set so we
        // never scan the full skeleton table.
        let placeholders = (0..candidate_message_ids.len())
            .map(|i| format!("?{}", binds.len() + i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        for mid in candidate_message_ids {
            binds.push(Value::Text(mid.clone()));
        }

        let mut sql = String::from("SELECT message_id FROM message_skeleton WHERE ");
        sql.push_str(&clauses.join(" AND "));
        sql.push_str(" AND message_id IN (");
        sql.push_str(&placeholders);
        sql.push(')');

        let conn = self.conn;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(binds.iter()), |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        Ok(Some(rows))
    }

    /// Fetch skeleton basic info (`conversation_id`, `sender_id`,
    /// `created_at_ms`) for `message_ids`. Returns one entry per
    /// message id that exists in `message_skeleton`; missing ids are
    /// silently dropped.
    fn fetch_skeleton_basic_info(
        &self,
        message_ids: &[String],
    ) -> DbResult<HashMap<String, SkeletonBasicInfo>> {
        if message_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = (0..message_ids.len())
            .map(|i| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT message_id, conversation_id, sender_id, created_at_ms
               FROM message_skeleton
              WHERE message_id IN ({placeholders})"
        );
        let conn = self.conn;
        let mut stmt = conn.prepare(&sql)?;
        let mut binds: Vec<Value> = Vec::with_capacity(message_ids.len());
        for mid in message_ids {
            binds.push(Value::Text(mid.clone()));
        }
        let rows = stmt
            .query_map(params_from_iter(binds.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    SkeletonBasicInfo {
                        conversation_id: row.get(1)?,
                        sender_id: row.get(2)?,
                        created_at_ms: row.get(3)?,
                    },
                ))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()?;
        Ok(rows)
    }
}

/// Skeleton columns the merged search path needs for fuzzy-only
/// matches that have no inline FTS row to read from.
#[derive(Debug)]
struct SkeletonBasicInfo {
    conversation_id: String,
    sender_id: String,
    created_at_ms: i64,
}

// ---------------------------------------------------------------------------
// Filter SQL builder
// ---------------------------------------------------------------------------

fn push_structured_filters(query: &SearchQuery, clauses: &mut Vec<String>, binds: &mut Vec<Value>) {
    if let Some(sender) = &query.sender_filter {
        clauses.push(format!("sender_id = ?{}", binds.len() + 1));
        binds.push(Value::Text(sender.clone()));
    }
    if let Some(conv) = &query.conversation_filter {
        clauses.push(format!("conversation_id = ?{}", binds.len() + 1));
        binds.push(Value::Text(conv.to_string()));
    }
    if let Some(from) = query.date_from {
        clauses.push(format!("created_at_ms >= ?{}", binds.len() + 1));
        binds.push(Value::Integer(from));
    }
    if let Some(to) = query.date_to {
        clauses.push(format!("created_at_ms <= ?{}", binds.len() + 1));
        binds.push(Value::Integer(to));
    }
    if let Some(kind) = query.content_kind {
        let kind_sql = content_kind_to_sql(kind);
        if let Some(k) = kind_sql {
            clauses.push(format!("kind = ?{}", binds.len() + 1));
            binds.push(Value::Text(k.to_string()));
        }
    }
}

/// resolve a [`SearchTarget`] into a concrete set of
/// conversation ids the query engine should scope to. Returns
/// `Ok(None)` for [`SearchTarget::Global`] (no filter); every
/// other variant returns `Ok(Some(set))`. An empty set is a
/// valid outcome — the query engine treats it as "no
/// conversations to search" rather than as "no filter".
pub fn resolve_target_to_conversation_set(
    target: &SearchTarget,
    conn: &Connection,
) -> SearchResultSet<Option<HashSet<String>>> {
    resolve_target_to_conversation_set_with_resolver(
        target,
        conn,
        &crate::search::search_target::NoopConversationGroupResolver::new(),
    )
}

/// resolution variant that consults a
/// [`crate::search::search_target::ConversationGroupResolver`]
/// for the new variants
/// (`ConversationGroup` / `Channel` / `Starred` / `Unread`).
/// Schema-backed variants ignore the resolver and continue to
/// hit the same DB helpers as before.
pub fn resolve_target_to_conversation_set_with_resolver(
    target: &SearchTarget,
    conn: &Connection,
    resolver: &dyn crate::search::search_target::ConversationGroupResolver,
) -> SearchResultSet<Option<HashSet<String>>> {
    use crate::SearchTarget as T;
    match target {
        T::Global => Ok(None),
        T::Conversation(c) => {
            let mut s = HashSet::new();
            s.insert(c.to_string());
            Ok(Some(s))
        }
        T::ConversationGroup(group) => Ok(Some(group.iter().map(|c| c.to_string()).collect())),
        T::Channel(channel_id) => Ok(Some(resolver.resolve_channel(channel_id)?)),
        T::Community(community) => {
            let convs = read_list_conversations_by_column(
                conn,
                ConversationFilterColumn::Community,
                &community.to_string(),
            )
            .map_err(|e| {
                Error::Search(crate::search::SearchError::from_db_with_context(
                    e,
                    "list community convs",
                ))
            })?;
            Ok(Some(convs.into_iter().map(|c| c.conversation_id).collect()))
        }
        T::Domain(domain) => {
            let convs = read_list_conversations_by_column(
                conn,
                ConversationFilterColumn::Domain,
                &domain.to_string(),
            )
            .map_err(|e| {
                Error::Search(crate::search::SearchError::from_db_with_context(
                    e,
                    "list domain convs",
                ))
            })?;
            Ok(Some(convs.into_iter().map(|c| c.conversation_id).collect()))
        }
        T::Tenant(tenant) => {
            let convs =
                read_list_conversations_by_column(conn, ConversationFilterColumn::Tenant, tenant)
                    .map_err(|e| {
                    Error::Search(crate::search::SearchError::from_db_with_context(
                        e,
                        "list tenant convs",
                    ))
                })?;
            Ok(Some(convs.into_iter().map(|c| c.conversation_id).collect()))
        }
        T::B2cAll => {
            let convs =
                read_list_conversations_by_column(conn, ConversationFilterColumn::Scope, "b2c")
                    .map_err(|e| {
                        Error::Search(crate::search::SearchError::from_db_with_context(
                            e,
                            "list b2c convs",
                        ))
                    })?;
            Ok(Some(convs.into_iter().map(|c| c.conversation_id).collect()))
        }
        T::Starred => Ok(Some(resolver.resolve_starred()?)),
        T::Unread => Ok(Some(resolver.resolve_unread()?)),
    }
}

/// Result alias used by [`resolve_target_to_conversation_set`].
type SearchResultSet<T> = std::result::Result<T, Error>;

/// append a `conversation_id IN (…)` filter clause for
/// the supplied [`SearchTarget`]. No-op for [`SearchTarget::Global`]
/// (no filter wanted). For every other variant — including
/// [`SearchTarget::Conversation`] — the target is resolved into a
/// concrete set of `conversation_id`s and emitted as an IN-clause.
/// An empty resolution adds `1=0` so the WHERE clause
/// short-circuits to "no rows" rather than falling through to a
/// global scan. If the legacy `conversation_filter` is also set,
/// the AND of the two clauses is the (correct) more-restrictive
/// behavior; in the normal case where they agree the duplicate
/// IN-clause collapses cleanly.
fn push_target_filter(
    target: &SearchTarget,
    conn: &Connection,
    clauses: &mut Vec<String>,
    binds: &mut Vec<Value>,
) {
    if matches!(target, SearchTarget::Global) {
        return;
    }
    let resolved = match resolve_target_to_conversation_set(target, conn) {
        Ok(r) => r,
        Err(_) => {
            // Resolution failed (e.g. transient SQL error). Fail
            // closed: emit `1=0` so the search returns no rows
            // rather than silently fanning back out to Global.
            clauses.push("1=0".to_string());
            return;
        }
    };
    let Some(set) = resolved else { return };
    if set.is_empty() {
        clauses.push("1=0".to_string());
        return;
    }
    let placeholders = (0..set.len())
        .map(|i| format!("?{}", binds.len() + i + 1))
        .collect::<Vec<_>>()
        .join(", ");
    clauses.push(format!("conversation_id IN ({placeholders})"));
    for c in set {
        binds.push(Value::Text(c));
    }
}

/// Lowercase + de-duplicate the bare ASCII / Unicode "words" of a
/// query string. Used by the cold-bucket fan-out path
/// ([`QueryEngine::execute_search_with_cold_source`]) to produce a
/// minimal FTS-like word set without re-running FTS5.
fn lowercase_word_set(query: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for raw in query.split(|c: char| c.is_whitespace() || c.is_ascii_punctuation()) {
        if raw.is_empty() {
            continue;
        }
        let lower: String = raw.chars().flat_map(char::to_lowercase).collect();
        if lower.is_empty() {
            continue;
        }
        if seen.insert(lower.clone()) {
            out.push(lower);
        }
    }
    out
}

/// `true` when `sender_id` survives the optional sender filter on
/// `query`.
fn sender_filter_matches(query: &SearchQuery, sender_id: &str) -> bool {
    match &query.sender_filter {
        Some(s) => s == sender_id,
        None => true,
    }
}

/// `true` when `created_at_ms` falls inside the optional
/// `date_from`..`date_to` window on `query`.
fn date_filter_matches(query: &SearchQuery, created_at_ms: i64) -> bool {
    if let Some(from) = query.date_from {
        if created_at_ms < from {
            return false;
        }
    }
    if let Some(to) = query.date_to {
        if created_at_ms > to {
            return false;
        }
    }
    true
}

/// Merge a cold-bucket contribution into the running result set,
/// keyed by `message_id`. If the row already exists (e.g. it was
/// also surfaced by the local FTS / fuzzy path) we accumulate the
/// rank score and **leave `is_cold` untouched** — the body is
/// already local, so the row must not enter the cold-only
/// re-weighting path nor be enqueued for hydration. Otherwise we
/// synthesize a fresh row with `is_cold = true`.
/// shared merge helper
/// for one bucket's `(fts_rows, fuzzy_rows)` payload.
///
/// Both the sequential and parallel cold fan-out paths funnel
/// through this function so the per-bucket scoring rules (BM25,
/// fuzzy per-script overlap, sender / date filter, fuzzy-only
/// metadata lookup) live in exactly one place. Output is
/// merged into `by_id` via [`merge_cold_hit`], which dedupes
/// against the local-result set.
fn merge_bucket_rows_into_by_id(
    by_id: &mut HashMap<String, SearchResult>,
    query: &SearchQuery,
    fts_rows: &[FtsRow],
    fuzzy_rows: &[FuzzyRow],
    q_words: &[String],
    q_by_script: &HashMap<ScriptClass, HashSet<String>>,
    q_count_fuzzy: f64,
) {
    // Build a metadata lookup so fuzzy-only hits can synthesise
    // a SearchResult without re-fetching skeletons.
    let mut meta_by_id: HashMap<String, &FtsRow> = HashMap::new();
    for row in fts_rows {
        meta_by_id.insert(row.message_id.clone(), row);
    }

    for row in fts_rows {
        if !sender_filter_matches(query, &row.sender_id) {
            continue;
        }
        if !date_filter_matches(query, row.created_at_ms) {
            continue;
        }
        let lower = row.text_content.to_lowercase();
        let mut matched = 0usize;
        for w in q_words {
            if lower.contains(w) {
                matched += 1;
            }
        }
        if matched == 0 {
            continue;
        }
        let bm25_like = matched as f64;
        let rank = bm25_like * BM25_WEIGHT;
        merge_cold_hit(
            by_id,
            &row.message_id,
            &row.conversation_id,
            &row.sender_id,
            row.created_at_ms,
            rank,
        );
    }

    if q_count_fuzzy <= 0.0 {
        return;
    }
    // counts[message_id][script] = matched (token, script) pairs
    // from this bucket's fuzzy shard.
    let mut counts: HashMap<String, HashMap<ScriptClass, u32>> = HashMap::new();
    for fr in fuzzy_rows {
        let class = ScriptClass::from_iso_15924(&fr.script);
        let Some(set) = q_by_script.get(&class) else {
            continue;
        };
        if !set.contains(&fr.token) {
            continue;
        }
        *counts
            .entry(fr.message_id.clone())
            .or_default()
            .entry(class)
            .or_insert(0) += 1;
    }
    for (mid, per_script) in counts {
        let Some(info) = meta_by_id.get(&mid) else {
            continue;
        };
        if !sender_filter_matches(query, &info.sender_id) {
            continue;
        }
        if !date_filter_matches(query, info.created_at_ms) {
            continue;
        }
        // Per-script gating mirrors FuzzySearchEngine::search_fuzzy:
        // a row passes when at least one script's overlap fraction
        // clears the per-script threshold. Total matched across
        // all scripts feeds the rank.
        let mut total_matched: u32 = 0;
        let mut accepted = false;
        for (script, q_set) in q_by_script {
            let m = per_script.get(script).copied().unwrap_or(0);
            let q_n = q_set.len() as u32;
            if q_n == 0 {
                continue;
            }
            let frac = f64::from(m) / f64::from(q_n);
            if frac >= fuzzy_min_overlap(*script) {
                accepted = true;
            }
            total_matched += m;
        }
        if !accepted {
            continue;
        }
        let score = f64::from(total_matched) / q_count_fuzzy;
        let rank = score * FUZZY_WEIGHT;
        merge_cold_hit(
            by_id,
            &mid,
            &info.conversation_id,
            &info.sender_id,
            info.created_at_ms,
            rank,
        );
    }
}

fn merge_cold_hit(
    by_id: &mut HashMap<String, SearchResult>,
    message_id: &str,
    conversation_id: &str,
    sender_id: &str,
    created_at_ms: i64,
    rank: f64,
) {
    if let Some(existing) = by_id.get_mut(message_id) {
        existing.rank_score += rank;
        // Do NOT flip `is_cold`: a row that is already in the
        // local FTS / fuzzy result set has its body resident on
        // device, so flagging it cold would (a) trigger a
        // duplicate Task 3 recency × kind multiplication in
        // [`QueryEngine::apply_cold_recency_weight`] and (b) push
        // a spurious P0 hydration request through
        // `enqueue_cold_results_for_hydration`.
        return;
    }
    let mid_uuid = Uuid::parse_str(message_id).unwrap_or(Uuid::nil());
    let cid_uuid = Uuid::parse_str(conversation_id).unwrap_or(Uuid::nil());
    by_id.insert(
        message_id.to_string(),
        SearchResult {
            message_id: mid_uuid,
            conversation_id: cid_uuid,
            sender_id: sender_id.to_string(),
            created_at_ms,
            snippet: None,
            rank_score: rank,
            is_cold: true,
            semantic_score: None,
        },
    );
}

/// Map [`ContentKind`] to the canonical `message_skeleton.kind`
/// value. [`ContentKind::Any`] returns `None` — no filter is
/// applied.
fn content_kind_to_sql(kind: ContentKind) -> Option<&'static str> {
    match kind {
        ContentKind::Text => Some("text"),
        // Image / Video / Audio / Document all live under the
        // `media` skeleton kind in will refine
        // this once the media-search index is wired up; today we
        // map all four to "media".
        ContentKind::Image | ContentKind::Video | ContentKind::Audio | ContentKind::Document => {
            Some("media")
        }
        ContentKind::Any => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store::db::LocalStoreDb;

    use std::collections::HashMap;

    use rusqlite::params;

    /// Allow `clippy::too_many_arguments` for the dedicated test
    /// fixture insert. Splitting into a struct adds no clarity.
    #[allow(clippy::too_many_arguments)]
    fn insert_fixture(
        db: &LocalStoreDb,
        message_id: &str,
        conversation_id: &str,
        sender_id: &str,
        created_at_ms: i64,
        kind: &str,
        text: Option<&str>,
        seed_conversation: &mut HashMap<String, ()>,
    ) {
        let conn = db.connection();
        if !seed_conversation.contains_key(conversation_id) {
            conn.execute(
                "INSERT INTO conversation (
                    conversation_id, title_cipher, pinned, muted,
                    last_message_id, last_activity_ms
                 ) VALUES (?1, NULL, 0, 0, NULL, ?2)",
                params![conversation_id, created_at_ms],
            )
            .unwrap();
            seed_conversation.insert(conversation_id.to_string(), ());
        }
        conn.execute(
            "INSERT INTO message_skeleton (
                message_id, conversation_id, sender_id, created_at_ms,
                received_at_ms, kind, body_state
             ) VALUES (?1, ?2, ?3, ?4, ?4, ?5, 'local_plain_available')",
            params![message_id, conversation_id, sender_id, created_at_ms, kind],
        )
        .unwrap();
        if let Some(t) = text {
            conn.execute(
                "INSERT INTO message_body (message_id, text_content)
                 VALUES (?1, ?2)",
                params![message_id, t],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO search_fts(
                    message_id, conversation_id, sender_id,
                    created_at_ms, text_content
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![message_id, conversation_id, sender_id, created_at_ms, t],
            )
            .unwrap();
        }
    }

    fn uuid_fixture(idx: u32) -> Uuid {
        // Build a deterministic UUID from a counter so test
        // fixtures don't depend on monotonic clocks.
        let bytes = {
            let mut b = [0u8; 16];
            b[12..].copy_from_slice(&idx.to_be_bytes());
            b
        };
        Uuid::from_bytes(bytes)
    }

    fn populated_db() -> LocalStoreDb {
        let db = LocalStoreDb::open_in_memory(&[0xCD; 32]).unwrap();
        let mut conv_seen: HashMap<String, ()> = HashMap::new();
        // Three users, two conversations, varying timestamps and kinds.
        let conv_a = uuid_fixture(1).to_string();
        let conv_b = uuid_fixture(2).to_string();
        let rows: [(&str, &str, i64, &str, Option<&str>); 6] = [
            ("alice", &conv_a, 1_000, "text", Some("hello world")),
            ("bob", &conv_a, 2_000, "text", Some("hello there")),
            ("alice", &conv_b, 3_000, "text", Some("good morning team")),
            ("carol", &conv_b, 4_000, "text", Some("good night")),
            ("alice", &conv_a, 5_000, "media", None),
            (
                "bob",
                &conv_b,
                6_000,
                "text",
                Some("meeting at 3pm in the conference room"),
            ),
        ];
        for (next_id, (sender, conv, ts, kind, text)) in (100u32..).zip(rows) {
            insert_fixture(
                &db,
                &uuid_fixture(next_id).to_string(),
                conv,
                sender,
                ts,
                kind,
                text,
                &mut conv_seen,
            );
        }
        db
    }

    #[test]
    fn structured_only_filter_by_sender() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            sender_filter: Some("alice".into()),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(results.len(), 3);
        for r in &results {
            assert_eq!(r.sender_id, "alice");
            assert!(!r.is_cold);
            assert_eq!(r.rank_score, 0.0);
        }
        // Newest first.
        for w in results.windows(2) {
            assert!(w[0].created_at_ms >= w[1].created_at_ms);
        }
    }

    #[test]
    fn structured_only_filter_by_date_range() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            date_from: Some(2_000),
            date_to: Some(4_000),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.created_at_ms >= 2_000 && r.created_at_ms <= 4_000);
        }
    }

    #[test]
    fn structured_only_filter_by_conversation() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv_a = uuid_fixture(1);
        let q = SearchQuery {
            conversation_filter: Some(conv_a),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(results.len(), 3);
        for r in &results {
            assert_eq!(r.conversation_id, conv_a);
        }
    }

    #[test]
    fn structured_only_filter_by_content_kind() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q_media = SearchQuery {
            content_kind: Some(ContentKind::Image),
            ..Default::default()
        };
        let media_results = engine
            .execute_search(&q_media, &SearchScope::LocalOnly)
            .unwrap();
        assert_eq!(media_results.len(), 1, "one media row in fixture");

        let q_text = SearchQuery {
            content_kind: Some(ContentKind::Text),
            ..Default::default()
        };
        let text_results = engine
            .execute_search(&q_text, &SearchScope::LocalOnly)
            .unwrap();
        assert_eq!(text_results.len(), 5);

        let q_any = SearchQuery {
            content_kind: Some(ContentKind::Any),
            ..Default::default()
        };
        let any_results = engine
            .execute_search(&q_any, &SearchScope::LocalOnly)
            .unwrap();
        assert_eq!(any_results.len(), 6);
    }

    #[test]
    fn fts_with_sender_filter() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            sender_filter: Some("alice".into()),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert!(!results.is_empty());
        for r in &results {
            assert_eq!(r.sender_id, "alice");
            assert!(r.snippet.is_some());
            assert!(r.rank_score > 0.0, "rank flipped sign");
        }
    }

    #[test]
    fn fts_with_date_range() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "good".into(),
            date_from: Some(3_500),
            date_to: Some(5_000),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(results.len(), 1, "only 'good night' falls in range");
        assert_eq!(results[0].sender_id, "carol");
    }

    #[test]
    fn fts_with_conversation_filter() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv_b = uuid_fixture(2);
        let q = SearchQuery {
            query_string: "meeting".into(),
            conversation_filter: Some(conv_b),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].conversation_id, conv_b);
    }

    #[test]
    fn search_local_only_does_not_attempt_cold_fetch() {
        // Invariant: LocalOnly returns purely local rows
        // (is_cold = false) without touching any archive code.
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert!(results.iter().all(|r| !r.is_cold));
    }

    #[test]
    fn search_include_cold_returns_local_for_now() {
        // Invariant: IncludeCold is a forward-compat marker;
        // no archive fan-out lands until /
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let results = engine
            .execute_search(&q, &SearchScope::IncludeCold)
            .unwrap();
        assert!(results.iter().all(|r| !r.is_cold));
    }

    #[test]
    fn empty_query_with_no_filters_returns_all_recent() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery::default();
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(results.len(), 6);
        // ORDER BY created_at_ms DESC.
        for w in results.windows(2) {
            assert!(w[0].created_at_ms >= w[1].created_at_ms);
        }
    }

    #[test]
    fn fts_query_with_no_match_returns_empty() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "doesnotappear".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn limit_caps_result_count() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery::default();
        let results = engine
            .execute_search_with_limit(&q, &SearchScope::LocalOnly, 2)
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    // ----------------------------------------------------------------
    // Fuzzy-merged search — Task 2
    // ----------------------------------------------------------------
    //
    // These tests insert messages via MessagePersister so both FTS
    // and search_fuzzy are populated automatically (per Task 1's
    // wiring). The QueryEngine then runs the unified search path
    // and asserts on the merged ranking + dedup behavior.

    use crate::message::processor::{IngestedMessage, MessagePersister};

    fn fuzzy_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0xFA; 32]).unwrap()
    }

    fn seed_conv(db: &LocalStoreDb, id: Uuid) {
        db.insert_conversation(&crate::local_store::schema::Conversation {
            conversation_id: id.to_string(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
            ..Default::default()
        })
        .unwrap();
    }

    fn persist(p: &MessagePersister<'_>, conv: Uuid, sender: &str, ts: i64, text: &str) -> Uuid {
        let mid = Uuid::now_v7();
        p.persist_ingested_message(&IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: sender.into(),
            created_at_ms: ts,
            text_content: Some(text.into()),
            media_descriptors: vec![],
            reply_to: None,
        })
        .expect("persist");
        mid
    }

    #[test]
    fn fuzzy_search_finds_typo_matches() {
        // FTS5's "lighthose" query would NOT match an indexed
        // "lighthouse keeper" row (different word). The script-aware
        // fuzzy index, however, shares 5 of 7 trigrams between the
        // two strings, so the unified engine surfaces the row.
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);
        let mid = persist(&p, conv, "alice", 1_000, "lighthouse keeper");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthose".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert!(
            results.iter().any(|r| r.message_id == mid),
            "fuzzy should surface a near-miss against an FTS-only term; got {results:?}"
        );
    }

    #[test]
    fn combined_fts_and_fuzzy_deduplicates() {
        // When the same row matches both engines, the merged result
        // set must contain it exactly once.
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);
        let mid = persist(&p, conv, "alice", 1_000, "lighthouse keeper");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let hits_for_mid = results.iter().filter(|r| r.message_id == mid).count();
        assert_eq!(
            hits_for_mid, 1,
            "exact-term query should produce exactly one merged row; got {results:?}"
        );
    }

    #[test]
    fn fuzzy_results_have_lower_rank_than_exact() {
        // Insert two messages: one is an FTS5 exact match for the
        // query word, the other only matches via fuzzy n-grams.
        // The exact-match row must outrank the fuzzy-only row.
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);
        let mid_exact = persist(&p, conv, "alice", 1_000, "lighthouse keeper");
        let mid_fuzzy = persist(&p, conv, "bob", 2_000, "lighthose typeo only");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();

        let exact_pos = results
            .iter()
            .position(|r| r.message_id == mid_exact)
            .expect("exact-match row must be present");
        let fuzzy_pos = results
            .iter()
            .position(|r| r.message_id == mid_fuzzy)
            .expect("fuzzy-only row must be present");
        assert!(
            exact_pos < fuzzy_pos,
            "exact match must rank above fuzzy: {results:?}"
        );
        assert!(
            results[exact_pos].rank_score > results[fuzzy_pos].rank_score,
            "exact rank_score must exceed fuzzy rank_score: {:?} vs {:?}",
            results[exact_pos].rank_score,
            results[fuzzy_pos].rank_score
        );
    }

    #[test]
    fn fuzzy_only_results_carry_skeleton_metadata() {
        // Fuzzy hits do not flow through search_fts — we have to
        // hydrate conversation_id / sender_id / created_at_ms from
        // message_skeleton. Verify that hydration is wired up.
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);
        let mid = persist(&p, conv, "alice", 1_700_000_000_000, "lighthouse keeper");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthose".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let row = results.iter().find(|r| r.message_id == mid).expect("hit");
        assert_eq!(row.conversation_id, conv);
        assert_eq!(row.sender_id, "alice");
        assert_eq!(row.created_at_ms, 1_700_000_000_000);
        // Fuzzy-only rows have no FTS5 snippet to attach.
        assert!(row.snippet.is_none());
        assert!(row.rank_score > 0.0);
    }

    #[test]
    fn fuzzy_search_respects_structured_filters() {
        // Apply sender_filter on top of the merged FTS+fuzzy path
        // and verify only matching senders survive.
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);
        let _alice_mid = persist(&p, conv, "alice", 1_000, "lighthouse keeper");
        let bob_mid = persist(&p, conv, "bob", 2_000, "lighthose typeo only");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            sender_filter: Some("bob".into()),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].message_id, bob_mid);
        assert_eq!(results[0].sender_id, "bob");
    }

    // -------------------------------------------------------------------
    // Cold-result hydration (Task 7)
    // -------------------------------------------------------------------

    /// Mark `message_id` as offloaded by transitioning its
    /// `body_state` to `remote_archive_only` directly. The full
    /// state-machine path is `local_plain_available` →
    /// `remote_archive_only`, but for the test we just need the
    /// row to read back as cold.
    fn flip_to_remote_archive_only(db: &LocalStoreDb, message_id: &str) {
        db.connection()
            .execute(
                "UPDATE message_skeleton SET body_state = 'remote_archive_only'
                  WHERE message_id = ?1",
                params![message_id],
            )
            .unwrap();
    }

    #[test]
    fn include_cold_marks_offloaded_results_as_cold() {
        let db = populated_db();
        // Pick the row at ts=2_000 ("hello there") and offload it.
        let cold_mid = db
            .connection()
            .query_row(
                "SELECT message_id FROM message_skeleton WHERE created_at_ms = 2000",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap();
        flip_to_remote_archive_only(&db, &cold_mid);

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let cold_results = engine
            .execute_search(&q, &SearchScope::IncludeCold)
            .unwrap();
        let warm_results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();

        // Both scopes return the same row set today (no archive
        // fan-out yet); only IncludeCold flags the offloaded row.
        let cold_flagged = cold_results
            .iter()
            .filter(|r| r.message_id.to_string() == cold_mid)
            .filter(|r| r.is_cold)
            .count();
        let warm_flagged = warm_results
            .iter()
            .filter(|r| r.message_id.to_string() == cold_mid)
            .filter(|r| r.is_cold)
            .count();
        assert_eq!(cold_flagged, 1, "IncludeCold must flag the cold row");
        assert_eq!(warm_flagged, 0, "LocalOnly must NEVER flag rows as cold");
    }

    #[test]
    fn include_cold_leaves_local_rows_untouched() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let results = engine
            .execute_search(&q, &SearchScope::IncludeCold)
            .unwrap();
        assert!(!results.is_empty());
        for r in &results {
            assert!(!r.is_cold, "no row was offloaded; nothing should be cold");
        }
    }

    #[test]
    fn include_cold_marks_structured_only_results() {
        let db = populated_db();
        let cold_mid = db
            .connection()
            .query_row(
                "SELECT message_id FROM message_skeleton WHERE created_at_ms = 4000",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap();
        flip_to_remote_archive_only(&db, &cold_mid);

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        // Structured-only: empty query string, sender filter only.
        let q = SearchQuery {
            sender_filter: Some("carol".into()),
            ..Default::default()
        };
        let results = engine
            .execute_search(&q, &SearchScope::IncludeCold)
            .unwrap();
        assert!(!results.is_empty());
        for r in &results {
            if r.message_id.to_string() == cold_mid {
                assert!(r.is_cold, "structured-only path must also flag cold rows");
            } else {
                assert!(!r.is_cold);
            }
        }
    }

    // -------------------------------------------------------------------
    // Cold-bucket fan-out via ColdShardSource
    // -------------------------------------------------------------------

    use std::cell::Cell;

    /// In-memory [`ColdShardSource`] used to drive the cold fan-out
    /// without a transport client. Tracks how many fetches it
    /// served so tests can assert on the LocalOnly invariant.
    struct FakeColdSource {
        buckets: Vec<(String, String)>,
        text: HashMap<(String, String), Vec<FtsRow>>,
        fuzzy: HashMap<(String, String), Vec<FuzzyRow>>,
        text_calls: Cell<usize>,
        fuzzy_calls: Cell<usize>,
    }
    impl FakeColdSource {
        fn new() -> Self {
            Self {
                buckets: Vec::new(),
                text: HashMap::new(),
                fuzzy: HashMap::new(),
                text_calls: Cell::new(0),
                fuzzy_calls: Cell::new(0),
            }
        }
        fn with_text(mut self, conv: &str, bucket: &str, rows: Vec<FtsRow>) -> Self {
            let key = (conv.to_string(), bucket.to_string());
            if !self.buckets.contains(&key) {
                self.buckets.push(key.clone());
            }
            self.text.insert(key, rows);
            self
        }
        fn with_fuzzy(mut self, conv: &str, bucket: &str, rows: Vec<FuzzyRow>) -> Self {
            let key = (conv.to_string(), bucket.to_string());
            if !self.buckets.contains(&key) {
                self.buckets.push(key.clone());
            }
            self.fuzzy.insert(key, rows);
            self
        }
    }
    impl ColdShardSource for FakeColdSource {
        fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
            Ok(self.buckets.clone())
        }
        fn fetch_text_rows(
            &self,
            conversation_id: &str,
            time_bucket: &str,
        ) -> Result<Vec<FtsRow>, Error> {
            self.text_calls.set(self.text_calls.get() + 1);
            Ok(self
                .text
                .get(&(conversation_id.to_string(), time_bucket.to_string()))
                .cloned()
                .unwrap_or_default())
        }
        fn fetch_fuzzy_rows(
            &self,
            conversation_id: &str,
            time_bucket: &str,
        ) -> Result<Vec<FuzzyRow>, Error> {
            self.fuzzy_calls.set(self.fuzzy_calls.get() + 1);
            Ok(self
                .fuzzy
                .get(&(conversation_id.to_string(), time_bucket.to_string()))
                .cloned()
                .unwrap_or_default())
        }
    }

    fn cold_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0xC0; 32]).unwrap()
    }

    #[test]
    fn cold_source_includecold_returns_decrypted_shard_hits() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());

        let conv = Uuid::now_v7();
        let cold_mid = Uuid::now_v7();
        let cold_text = "lighthouse beacon shines";
        let source = FakeColdSource::new().with_text(
            &conv.to_string(),
            "2026-01",
            vec![FtsRow {
                message_id: cold_mid.to_string(),
                conversation_id: conv.to_string(),
                sender_id: "alice".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: cold_text.into(),
            }],
        );

        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        assert_eq!(results.len(), 1, "cold shard should surface one row");
        let row = &results[0];
        assert_eq!(row.message_id, cold_mid);
        assert_eq!(row.conversation_id, conv);
        assert!(row.is_cold);
        assert!(row.rank_score > 0.0);
    }

    #[test]
    fn cold_source_localonly_never_fetches_shards() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());

        let conv = Uuid::now_v7();
        let source = FakeColdSource::new().with_text(
            &conv.to_string(),
            "2026-01",
            vec![FtsRow {
                message_id: Uuid::now_v7().to_string(),
                conversation_id: conv.to_string(),
                sender_id: "alice".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: "lighthouse beacon".into(),
            }],
        );

        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::LocalOnly, &source)
            .unwrap();
        assert!(results.is_empty());
        assert_eq!(
            source.text_calls.get(),
            0,
            "LocalOnly must never fetch text shards",
        );
        assert_eq!(
            source.fuzzy_calls.get(),
            0,
            "LocalOnly must never fetch fuzzy shards",
        );
    }

    #[test]
    fn cold_source_merges_with_local_results() {
        // Local + cold results for the same query string. Local row
        // is a strong FTS hit; cold row is a fresh contribution
        // from a separate (conv, bucket) pair. Both should appear
        // in the merged result set; only the cold one carries
        // is_cold = true.
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let local_conv = Uuid::now_v7();
        seed_conv(&db, local_conv);
        let local_mid = persist(
            &p,
            local_conv,
            "alice",
            1_700_000_000_000,
            "lighthouse keeper",
        );

        let engine = QueryEngine::new(db.connection(), db.icu_available());

        let cold_conv = Uuid::now_v7();
        let cold_mid = Uuid::now_v7();
        let source = FakeColdSource::new().with_text(
            &cold_conv.to_string(),
            "2026-01",
            vec![FtsRow {
                message_id: cold_mid.to_string(),
                conversation_id: cold_conv.to_string(),
                sender_id: "bob".into(),
                created_at_ms: 1_600_000_000_000,
                text_content: "lighthouse on the cliff".into(),
            }],
        );

        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        assert_eq!(results.len(), 2, "merged set: local + cold = 2");

        let local_row = results
            .iter()
            .find(|r| r.message_id == local_mid)
            .expect("local row");
        let cold_row = results
            .iter()
            .find(|r| r.message_id == cold_mid)
            .expect("cold row");
        assert!(!local_row.is_cold);
        assert!(cold_row.is_cold);
    }

    #[test]
    fn cold_source_fuzzy_only_match_uses_text_metadata_for_skeleton() {
        // The fuzzy shard surfaces a hit whose message_id never
        // appears in the local store. We need the matching FTS row
        // (which carries sender / conversation / created_at_ms) so
        // the synthetic SearchResult has full metadata.
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());

        let cold_conv = Uuid::now_v7();
        let cold_mid = Uuid::now_v7();
        let fts_row = FtsRow {
            message_id: cold_mid.to_string(),
            conversation_id: cold_conv.to_string(),
            sender_id: "carol".into(),
            created_at_ms: 1_650_000_000_000,
            text_content: "lighthouse keeper".into(),
        };
        // Build the n-grams for "lighthose" so the fuzzy match
        // overlaps with the indexed "lighthouse" row.
        let mut fuzzy_rows = Vec::new();
        for fk in FuzzyTokenizer::generate_tokens("lighthouse") {
            fuzzy_rows.push(FuzzyRow {
                token: fk.token,
                script: fk.script.to_iso_15924().into(),
                message_id: cold_mid.to_string(),
            });
        }
        let source = FakeColdSource::new()
            .with_text(&cold_conv.to_string(), "2026-01", vec![fts_row])
            .with_fuzzy(&cold_conv.to_string(), "2026-01", fuzzy_rows);

        let q = SearchQuery {
            query_string: "lighthose".into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        let row = results
            .iter()
            .find(|r| r.message_id == cold_mid)
            .expect("fuzzy cold hit");
        assert!(row.is_cold);
        assert_eq!(row.sender_id, "carol");
        assert_eq!(row.created_at_ms, 1_650_000_000_000);
    }

    #[test]
    fn cold_source_filters_by_conversation() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());

        let target_conv = Uuid::now_v7();
        let other_conv = Uuid::now_v7();
        let target_mid = Uuid::now_v7();
        let other_mid = Uuid::now_v7();
        let source = FakeColdSource::new()
            .with_text(
                &target_conv.to_string(),
                "2026-01",
                vec![FtsRow {
                    message_id: target_mid.to_string(),
                    conversation_id: target_conv.to_string(),
                    sender_id: "alice".into(),
                    created_at_ms: 1,
                    text_content: "lighthouse".into(),
                }],
            )
            .with_text(
                &other_conv.to_string(),
                "2026-01",
                vec![FtsRow {
                    message_id: other_mid.to_string(),
                    conversation_id: other_conv.to_string(),
                    sender_id: "bob".into(),
                    created_at_ms: 2,
                    text_content: "lighthouse elsewhere".into(),
                }],
            );

        let q = SearchQuery {
            query_string: "lighthouse".into(),
            conversation_filter: Some(target_conv),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].message_id, target_mid);
    }

    // -------------------------------------------------------------------
    // Ranking formula: recency decay + content-kind weight
    // ( — `docs/DESIGN.md §7.5`)
    // -------------------------------------------------------------------

    #[test]
    fn ranking_recent_message_outranks_identical_old_message() {
        // Two messages with identical text and content but
        // different created_at_ms — the recent one must rank above
        // the old one purely on recency decay.
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);
        // 365 days apart in ms.
        let old_ts = 1_600_000_000_000_i64;
        let new_ts = old_ts + 365 * 24 * 60 * 60 * 1000;
        let mid_old = persist(&p, conv, "alice", old_ts, "lighthouse keeper");
        let mid_new = persist(&p, conv, "alice", new_ts, "lighthouse keeper");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let pos_old = results
            .iter()
            .position(|r| r.message_id == mid_old)
            .unwrap();
        let pos_new = results
            .iter()
            .position(|r| r.message_id == mid_new)
            .unwrap();
        assert!(
            pos_new < pos_old,
            "newer identical hit must rank above older identical hit: {results:?}",
        );
        assert!(
            results[pos_new].rank_score > results[pos_old].rank_score,
            "rank_score must reflect recency decay",
        );
    }

    #[test]
    fn ranking_exact_recent_beats_fuzzy_old() {
        // Recent FTS exact hit vs old fuzzy-only hit: BM25 +
        // recency together must dominate fuzzy-only.
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);
        let recent_ts = 1_700_000_000_000_i64;
        let ancient_ts = 1_400_000_000_000_i64;
        let mid_recent_exact = persist(&p, conv, "alice", recent_ts, "lighthouse keeper");
        let mid_old_fuzzy = persist(&p, conv, "bob", ancient_ts, "lighthose typeo only");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let pos_exact = results
            .iter()
            .position(|r| r.message_id == mid_recent_exact)
            .unwrap();
        let pos_fuzzy = results
            .iter()
            .position(|r| r.message_id == mid_old_fuzzy)
            .unwrap();
        assert!(pos_exact < pos_fuzzy);
        assert!(results[pos_exact].rank_score > results[pos_fuzzy].rank_score);
    }

    #[test]
    fn ranking_is_deterministic_for_same_inputs() {
        // Run the same query against the same DB twice; results
        // must be byte-identical (rank_score and order).
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);
        for i in 0..10 {
            persist(
                &p,
                conv,
                "alice",
                1_700_000_000_000_i64 + i * 1_000,
                "lighthouse keeper",
            );
        }

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let r1 = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let r2 = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.message_id, b.message_id);
            assert_eq!(a.rank_score.to_bits(), b.rank_score.to_bits());
        }
    }

    #[test]
    fn ranking_text_outranks_media_for_equal_recency() {
        // Same created_at_ms, both surface via the same query
        // word, but one is text and one is media. The text row
        // must rank above the media row (kind weight 1.0 vs 0.8).
        let db = fuzzy_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv);

        let ts = 1_700_000_000_000_i64;
        let mid_text = persist(&p, conv, "alice", ts, "lighthouse keeper");

        // Insert a media skeleton + FTS row by hand for the media
        // case — the persister API does not currently emit
        // kind=media rows.
        let mid_media = Uuid::now_v7();
        db.connection()
            .execute(
                "INSERT INTO message_skeleton(
                     message_id, conversation_id, sender_id,
                     created_at_ms, received_at_ms, kind, body_state)
                 VALUES (?1, ?2, ?3, ?4, ?4, 'media', 'local_plain_available')",
                rusqlite::params![mid_media.to_string(), conv.to_string(), "bob", ts,],
            )
            .unwrap();
        db.connection()
            .execute(
                "INSERT INTO search_fts(
                     message_id, conversation_id, sender_id,
                     created_at_ms, text_content)
                 VALUES (?1, ?2, 'bob', ?3, 'lighthouse caption')",
                rusqlite::params![mid_media.to_string(), conv.to_string(), ts,],
            )
            .unwrap();

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let pos_text = results
            .iter()
            .position(|r| r.message_id == mid_text)
            .unwrap();
        let pos_media = results
            .iter()
            .position(|r| r.message_id == mid_media)
            .unwrap();
        assert!(
            pos_text < pos_media,
            "text outranks media at equal recency / equal FTS hit",
        );
    }

    // -----: semantic reranking ----------------------

    use crate::models::embeddings::{
        EmbeddingCache, LocalStoreEmbeddingCache, MockTextEmbedder, NoopTextEmbedder, TextEmbedder,
        XLMR_MODEL_VERSION,
    };

    #[test]
    fn semantic_weight_constant_matches_proposal() {
        // DESIGN.md §7.5 ranking formula constants. Kept as
        // runtime asserts (rather than `const { … }` blocks) so a
        // future tweak to the constants surfaces as a normal
        // test failure with a useful diff.
        let bm25: f64 = BM25_WEIGHT;
        let fuzzy: f64 = FUZZY_WEIGHT;
        let semantic: f64 = SEMANTIC_WEIGHT;
        assert!((bm25 - 2.0).abs() < f64::EPSILON);
        assert!((fuzzy - 1.0).abs() < f64::EPSILON);
        assert!((semantic - 1.5).abs() < f64::EPSILON);
        assert!(semantic > fuzzy);
        assert!(semantic < bm25);
    }

    #[test]
    fn semantic_reranker_falls_back_when_embedder_is_noop() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let plain = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let noop = NoopTextEmbedder;
        let with_semantic = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &noop, None, 200)
            .unwrap();
        let plain_ids: Vec<Uuid> = plain.iter().map(|r| r.message_id).collect();
        let semantic_ids: Vec<Uuid> = with_semantic.iter().map(|r| r.message_id).collect();
        assert_eq!(plain_ids, semantic_ids);
    }

    #[test]
    fn semantic_reranker_short_circuits_on_empty_query() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery::default();
        let mock = MockTextEmbedder::default();
        let res = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 10)
            .unwrap();
        // Same as the plain-FTS empty-query path: structured-only.
        let plain = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert_eq!(res.len(), plain.len());
    }

    #[test]
    fn semantic_reranker_surfaces_semantic_only_hits() {
        let db = populated_db();
        let mock = MockTextEmbedder::default();
        // Pick the message that the mock encoder will rank highest
        // for the query "good morning team": the message itself.
        // Insert a vector for that message into search_vector.
        let conn = db.connection();
        let target_text = "good morning team";
        let target_msg_id: String = conn
            .query_row(
                "SELECT m.message_id FROM message_skeleton m
                 JOIN message_body b ON b.message_id = m.message_id
                 WHERE b.text_content = ?1 LIMIT 1",
                rusqlite::params![target_text],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let cache = LocalStoreEmbeddingCache::new(conn);
        cache
            .put(
                &target_msg_id,
                XLMR_MODEL_VERSION,
                &mock.embed(target_text).unwrap(),
            )
            .unwrap();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        // Query that misses on FTS but matches semantically — use
        // the same mock embedding so cosine ~ 1.0.
        let q = SearchQuery {
            query_string: target_text.into(),
            ..Default::default()
        };
        let with_semantic = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 200)
            .unwrap();
        let target_uuid = Uuid::parse_str(&target_msg_id).unwrap();
        assert!(with_semantic.iter().any(|r| r.message_id == target_uuid));
    }

    #[test]
    fn semantic_reranker_combines_scores_for_dual_hits() {
        let db = populated_db();
        let mock = MockTextEmbedder::default();
        let conn = db.connection();
        // Pick a message whose text contains "hello".
        let target_msg_id: String = conn
            .query_row(
                "SELECT m.message_id FROM message_skeleton m
                 JOIN message_body b ON b.message_id = m.message_id
                 WHERE b.text_content = 'hello world' LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let cache = LocalStoreEmbeddingCache::new(conn);
        cache
            .put(
                &target_msg_id,
                XLMR_MODEL_VERSION,
                &mock.embed("hello world").unwrap(),
            )
            .unwrap();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello world".into(),
            ..Default::default()
        };
        let plain = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let with_semantic = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 200)
            .unwrap();
        let target_uuid = Uuid::parse_str(&target_msg_id).unwrap();
        let plain_score = plain
            .iter()
            .find(|r| r.message_id == target_uuid)
            .map(|r| r.rank_score)
            .unwrap_or(0.0);
        let merged_score = with_semantic
            .iter()
            .find(|r| r.message_id == target_uuid)
            .map(|r| r.rank_score)
            .unwrap_or(0.0);
        assert!(
            merged_score > plain_score,
            "semantic contribution should raise the dual-hit row's rank ({merged_score} vs {plain_score})",
        );
    }

    #[test]
    fn semantic_only_hit_recency_decays_against_combined_anchor() {
        // Regression test for the recency-anchor bug fixed in
        // this commit: `execute_search_with_semantic` previously
        // called `apply_recency_and_kind_weight(std::slice::from_mut(&mut sr))`
        // per semantic-only hit, which made `now_ms` equal the
        // row's own `created_at_ms`, collapsed `age_ms` to `0`,
        // and pinned `recency_factor` at `1.0`. A 90-day-old
        // semantic-only hit therefore had its score boosted to
        // `cosine * SEMANTIC_WEIGHT * 1.0` instead of being
        // decayed by the 30-day half-life. This test forces the
        // anchor to come from a fresher row in the combined
        // candidate set and asserts the stale row's score is
        // demonstrably below the un-decayed value.

        let db = LocalStoreDb::open_in_memory(&[0xCD; 32]).unwrap();
        let mut conv_seen: HashMap<String, ()> = HashMap::new();
        let conv = uuid_fixture(1).to_string();

        // 90-day gap so `recency_factor` is well below the
        // floor's halfway point.
        let recent_ms: i64 = 90 * 86_400_000;
        let stale_ms: i64 = 0;
        let recent_msg = uuid_fixture(101).to_string();
        let stale_msg = uuid_fixture(102).to_string();

        // Anchor row: skeleton-only (no FTS body) so the FTS
        // pass returns an empty `local`. The semantic merge has
        // to derive its `now_ms` from the combined candidate
        // set on its own.
        insert_fixture(
            &db,
            &recent_msg,
            &conv,
            "alice",
            recent_ms,
            "text",
            None,
            &mut conv_seen,
        );
        insert_fixture(
            &db,
            &stale_msg,
            &conv,
            "bob",
            stale_ms,
            "text",
            None,
            &mut conv_seen,
        );

        // Plant identical mock embeddings for both messages so
        // both round-trip with cosine ≈ 1.0 against the query
        // embedding.
        let mock = MockTextEmbedder::default();
        let q_text = "find this stale message";
        let q_emb = mock.embed(q_text).unwrap();
        let cache = LocalStoreEmbeddingCache::new(db.connection());
        cache.put(&recent_msg, XLMR_MODEL_VERSION, &q_emb).unwrap();
        cache.put(&stale_msg, XLMR_MODEL_VERSION, &q_emb).unwrap();

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: q_text.into(),
            ..Default::default()
        };
        let with_semantic = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 200)
            .unwrap();

        let recent_uuid = Uuid::parse_str(&recent_msg).unwrap();
        let stale_uuid = Uuid::parse_str(&stale_msg).unwrap();
        let recent_score = with_semantic
            .iter()
            .find(|r| r.message_id == recent_uuid)
            .map(|r| r.rank_score)
            .expect("anchor (recent) semantic-only hit should surface");
        let stale_score = with_semantic
            .iter()
            .find(|r| r.message_id == stale_uuid)
            .map(|r| r.rank_score)
            .expect("90-day-old semantic-only hit should surface");

        // Numeric envelope:
        // cosine ≈ 1.0 (round-trips via the INT8 codec at
        // >0.999 fidelity).
        // SEMANTIC_WEIGHT = 1.5
        // kind_weight = 1.0 (text)
        // For the anchor row, age = 0, so recency_factor = 1.0
        // and rank_score ≈ 1.5.
        // For the 90-day row, age_days = 90,
        // recency_score = exp(-90 * ln(2) / 30) = 1/8 = 0.125,
        // recency_factor = 0.5 + 0.5 * 0.125 = 0.5625,
        // rank_score ≈ 1.5 * 0.5625 ≈ 0.844.
        let undecayed = SEMANTIC_WEIGHT;
        assert!(
            (recent_score - undecayed).abs() < 0.05,
            "anchor row should sit at ≈ SEMANTIC_WEIGHT (1.5); got {recent_score:.4}",
        );
        // The bug under test made stale_score ≈ recent_score.
        // Demand a clear gap: at least 30% below the un-decayed
        // value, well above the floor (recency_factor ≥ 0.5
        // → rank_score ≥ 0.75).
        assert!(
            stale_score < undecayed * 0.7,
            "90-day-old semantic-only hit must be recency-decayed: \
             got {stale_score:.4}, expected < {:.4} \
             (un-decayed = {undecayed:.4})",
            undecayed * 0.7,
        );
        assert!(
            stale_score > undecayed * 0.45,
            "score floor invariant violated: \
             got {stale_score:.4} (floor ≈ {:.4})",
            undecayed * 0.5,
        );
        // And the stale hit must rank below the anchor.
        assert!(
            stale_score < recent_score,
            "stale hit should rank strictly below anchor: \
             stale {stale_score:.4} vs anchor {recent_score:.4}",
        );
    }

    #[test]
    fn semantic_only_hit_marks_cold_for_offloaded_body() {
        // Regression test: `execute_search_with_semantic`
        // materializes semantic-only hits with `is_cold: false`
        // because `fetch_skeleton_columns_for_semantic` does not
        // project `body_state`. Without a final cold-marking
        // pass against the merged set, an offloaded message
        // (`body_state = 'remote_archive_only'`) whose vector
        // still lives in `search_vector` would surface with
        // `is_cold = false` and the `HydrationQueue` would
        // never enqueue it for `SearchResultTap`-priority
        // hydration.
        //
        // This test seeds a single skeleton-only message,
        // flips its `body_state` to `remote_archive_only`,
        // plants a matching mock embedding, and asserts the
        // returned `SearchResult` has `is_cold = true` under
        // `SearchScope::IncludeCold`.

        let db = LocalStoreDb::open_in_memory(&[0xCD; 32]).unwrap();
        let mut conv_seen: HashMap<String, ()> = HashMap::new();
        let conv = uuid_fixture(1).to_string();
        let mid = uuid_fixture(201).to_string();

        insert_fixture(
            &db,
            &mid,
            &conv,
            "alice",
            10_000,
            "text",
            None,
            &mut conv_seen,
        );
        flip_to_remote_archive_only(&db, &mid);

        let mock = MockTextEmbedder::default();
        let q_text = "needle in cold archive";
        let q_emb = mock.embed(q_text).unwrap();
        let cache = LocalStoreEmbeddingCache::new(db.connection());
        cache.put(&mid, XLMR_MODEL_VERSION, &q_emb).unwrap();

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: q_text.into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_semantic(&q, &SearchScope::IncludeCold, &mock, None, 50)
            .unwrap();

        let target = Uuid::parse_str(&mid).unwrap();
        let row = results
            .iter()
            .find(|r| r.message_id == target)
            .expect("offloaded semantic-only hit should surface under IncludeCold");
        assert!(
            row.is_cold,
            "semantic-only hit for `remote_archive_only` body must carry is_cold = true \
             so HydrationQueue can enqueue it",
        );
    }

    #[test]
    fn semantic_only_hit_stays_warm_under_local_only_scope() {
        // Even when a body has been offloaded, `LocalOnly`
        // searches must NOT stamp `is_cold = true` — the
        // hydration queue is intentionally bypassed in that
        // scope, and stamping cold would mislead callers about
        // whether the result needs a network round trip.
        let db = LocalStoreDb::open_in_memory(&[0xCD; 32]).unwrap();
        let mut conv_seen: HashMap<String, ()> = HashMap::new();
        let conv = uuid_fixture(1).to_string();
        let mid = uuid_fixture(202).to_string();

        insert_fixture(
            &db,
            &mid,
            &conv,
            "alice",
            10_000,
            "text",
            None,
            &mut conv_seen,
        );
        flip_to_remote_archive_only(&db, &mid);

        let mock = MockTextEmbedder::default();
        let q_text = "warm-only scope skips cold marking";
        let q_emb = mock.embed(q_text).unwrap();
        let cache = LocalStoreEmbeddingCache::new(db.connection());
        cache.put(&mid, XLMR_MODEL_VERSION, &q_emb).unwrap();

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: q_text.into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 50)
            .unwrap();

        let target = Uuid::parse_str(&mid).unwrap();
        let row = results
            .iter()
            .find(|r| r.message_id == target)
            .expect("semantic-only hit should still surface under LocalOnly");
        assert!(
            !row.is_cold,
            "LocalOnly scope must not stamp is_cold (got is_cold = true)",
        );
    }

    // -----------------------------------------------------------------
    // Structured filters propagate to the semantic-only lane
    // -----------------------------------------------------------------

    /// Build two skeleton-only messages and plant identical mock
    /// embeddings for both so semantic search returns both with
    /// cosine ≈ 1.0. Returns `(allowed_uuid, blocked_uuid)`
    /// the caller pairs them with a filter to assert the
    /// blocked one is dropped.
    fn seed_two_semantic_only_hits(
        db: &LocalStoreDb,
        allowed: (&str, i64, &str, &str), // (sender, created_at_ms, kind, msg_id_str)
        blocked: (&str, i64, &str, &str),
        q_text: &str,
    ) -> (Uuid, Uuid) {
        let mut conv_seen: HashMap<String, ()> = HashMap::new();
        let conv = uuid_fixture(1).to_string();
        insert_fixture(
            db,
            allowed.3,
            &conv,
            allowed.0,
            allowed.1,
            allowed.2,
            None,
            &mut conv_seen,
        );
        insert_fixture(
            db,
            blocked.3,
            &conv,
            blocked.0,
            blocked.1,
            blocked.2,
            None,
            &mut conv_seen,
        );
        let mock = MockTextEmbedder::default();
        let q_emb = mock.embed(q_text).unwrap();
        let cache = LocalStoreEmbeddingCache::new(db.connection());
        cache.put(allowed.3, XLMR_MODEL_VERSION, &q_emb).unwrap();
        cache.put(blocked.3, XLMR_MODEL_VERSION, &q_emb).unwrap();
        (
            Uuid::parse_str(allowed.3).unwrap(),
            Uuid::parse_str(blocked.3).unwrap(),
        )
    }

    #[test]
    fn semantic_only_hit_respects_sender_filter() {
        // Regression: `execute_search_with_semantic` previously
        // pushed every semantic-only hit onto `local` without
        // running it through `allowed_skeleton_ids`, so a query
        // with `sender_filter: Some("alice")` would surface
        // bob's semantic-only hits too.
        let db = LocalStoreDb::open_in_memory(&[0xCD; 32]).unwrap();
        let allowed_mid = uuid_fixture(301).to_string();
        let blocked_mid = uuid_fixture(302).to_string();
        let q_text = "needle";
        let (allowed, blocked) = seed_two_semantic_only_hits(
            &db,
            ("alice", 10_000, "text", &allowed_mid),
            ("bob", 11_000, "text", &blocked_mid),
            q_text,
        );

        let mock = MockTextEmbedder::default();
        let engine = QueryEngine::new(db.connection(), db.icu_available());

        // With the sender filter set, only alice's semantic-only
        // hit should surface.
        let q = SearchQuery {
            query_string: q_text.into(),
            sender_filter: Some("alice".into()),
            ..Default::default()
        };
        let filtered = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 50)
            .unwrap();
        assert!(
            filtered.iter().any(|r| r.message_id == allowed),
            "alice's semantic-only hit must pass the sender filter",
        );
        assert!(
            !filtered.iter().any(|r| r.message_id == blocked),
            "bob's semantic-only hit must NOT leak through sender_filter = alice",
        );

        // Sanity: with no filter, both hits surface.
        let q_no_filter = SearchQuery {
            query_string: q_text.into(),
            ..Default::default()
        };
        let unfiltered = engine
            .execute_search_with_semantic(&q_no_filter, &SearchScope::LocalOnly, &mock, None, 50)
            .unwrap();
        assert!(unfiltered.iter().any(|r| r.message_id == allowed));
        assert!(unfiltered.iter().any(|r| r.message_id == blocked));
    }

    #[test]
    fn semantic_only_hit_respects_date_window() {
        // Regression: `date_from` / `date_to` must filter
        // semantic-only hits, not just the FTS / fuzzy lane.
        let db = LocalStoreDb::open_in_memory(&[0xCD; 32]).unwrap();
        let allowed_mid = uuid_fixture(303).to_string();
        let blocked_mid = uuid_fixture(304).to_string();
        let q_text = "needle";
        // Allowed row inside the window, blocked row well below
        // it.
        let (allowed, blocked) = seed_two_semantic_only_hits(
            &db,
            ("alice", 5_000, "text", &allowed_mid),
            ("alice", 1_000, "text", &blocked_mid),
            q_text,
        );

        let mock = MockTextEmbedder::default();
        let engine = QueryEngine::new(db.connection(), db.icu_available());

        let q = SearchQuery {
            query_string: q_text.into(),
            date_from: Some(4_000),
            date_to: Some(6_000),
            ..Default::default()
        };
        let filtered = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 50)
            .unwrap();
        assert!(
            filtered.iter().any(|r| r.message_id == allowed),
            "in-window semantic-only hit must pass the date filter",
        );
        assert!(
            !filtered.iter().any(|r| r.message_id == blocked),
            "out-of-window semantic-only hit must NOT leak through date_from / date_to",
        );

        // Sanity: with no filter, both hits surface.
        let q_no_filter = SearchQuery {
            query_string: q_text.into(),
            ..Default::default()
        };
        let unfiltered = engine
            .execute_search_with_semantic(&q_no_filter, &SearchScope::LocalOnly, &mock, None, 50)
            .unwrap();
        assert!(unfiltered.iter().any(|r| r.message_id == allowed));
        assert!(unfiltered.iter().any(|r| r.message_id == blocked));
    }

    #[test]
    fn semantic_only_hit_respects_content_kind_filter() {
        // Regression: `content_kind` must filter semantic-only
        // hits. `ContentKind::Text` maps to skeleton kind
        // `"text"`; `ContentKind::Image|Video|Audio|Document`
        // map to `"media"`. The non-text path in
        // `execute_fts_and_fuzzy_with_filters` short-circuits
        // FTS for media kinds (line 270-272 above) and relies
        // on `allowed_skeleton_ids` for filtering the
        // structured-only / fuzzy / semantic legs.
        let db = LocalStoreDb::open_in_memory(&[0xCD; 32]).unwrap();
        let allowed_mid = uuid_fixture(305).to_string();
        let blocked_mid = uuid_fixture(306).to_string();
        let q_text = "needle";
        let (allowed, blocked) = seed_two_semantic_only_hits(
            &db,
            ("alice", 10_000, "text", &allowed_mid),
            ("alice", 11_000, "media", &blocked_mid),
            q_text,
        );

        let mock = MockTextEmbedder::default();
        let engine = QueryEngine::new(db.connection(), db.icu_available());

        let q = SearchQuery {
            query_string: q_text.into(),
            content_kind: Some(ContentKind::Text),
            ..Default::default()
        };
        let filtered = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 50)
            .unwrap();
        assert!(
            filtered.iter().any(|r| r.message_id == allowed),
            "text semantic-only hit must pass content_kind = Text",
        );
        assert!(
            !filtered.iter().any(|r| r.message_id == blocked),
            "media semantic-only hit must NOT leak through content_kind = Text",
        );

        // Sanity: with `ContentKind::Any`, both hits surface.
        let q_any = SearchQuery {
            query_string: q_text.into(),
            content_kind: Some(ContentKind::Any),
            ..Default::default()
        };
        let unfiltered = engine
            .execute_search_with_semantic(&q_any, &SearchScope::LocalOnly, &mock, None, 50)
            .unwrap();
        assert!(unfiltered.iter().any(|r| r.message_id == allowed));
        assert!(unfiltered.iter().any(|r| r.message_id == blocked));
    }

    #[test]
    fn semantic_only_media_hit_uses_media_kind_weight() {
        // Regression: the kind-weight match arm in
        // `execute_search_with_semantic` previously matched on
        // `"image" | "video" | "audio" | "file"` — vocabulary
        // borrowed from `MediaDescriptor.kind`, not the canonical
        // `MessageKind::as_str` strings actually written into
        // `message_skeleton.kind` ("text" | "media" | "system").
        // Media-typed semantic-only hits silently fell through
        // the `_` arm and got `TEXT_KIND_WEIGHT (= 1.0)` instead
        // of `MEDIA_KIND_WEIGHT (= 0.8)` — overranked by 25%.
        //
        // This test seeds two skeleton-only rows at the same
        // timestamp (so `recency_factor = 1.0` and only the
        // kind weight differs), one `kind = "text"` and one
        // `kind = "media"`, plants identical mock embeddings,
        // and asserts:
        //
        // * text rank_score ≈ SEMANTIC_WEIGHT * TEXT_KIND_WEIGHT = 1.50
        // * media rank_score ≈ SEMANTIC_WEIGHT * MEDIA_KIND_WEIGHT = 1.20
        //
        // The buggy code produced 1.50 for both. Tolerances
        // absorb INT8-quant cosine fidelity (> 0.999).
        let db = LocalStoreDb::open_in_memory(&[0xCD; 32]).unwrap();
        let text_mid = uuid_fixture(401).to_string();
        let media_mid = uuid_fixture(402).to_string();
        let q_text = "needle";
        let (text_uuid, media_uuid) = seed_two_semantic_only_hits(
            &db,
            ("alice", 10_000, "text", &text_mid),
            ("alice", 10_000, "media", &media_mid),
            q_text,
        );

        let mock = MockTextEmbedder::default();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: q_text.into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 50)
            .unwrap();

        let text_score = results
            .iter()
            .find(|r| r.message_id == text_uuid)
            .map(|r| r.rank_score)
            .expect("text semantic-only hit should surface");
        let media_score = results
            .iter()
            .find(|r| r.message_id == media_uuid)
            .map(|r| r.rank_score)
            .expect("media semantic-only hit should surface");

        let expected_text = SEMANTIC_WEIGHT * TEXT_KIND_WEIGHT;
        let expected_media = SEMANTIC_WEIGHT * MEDIA_KIND_WEIGHT;
        let tol = 0.05;

        assert!(
            (text_score - expected_text).abs() < tol,
            "text rank_score {text_score:.4} should be ≈ {expected_text:.4}",
        );
        assert!(
            (media_score - expected_media).abs() < tol,
            "media rank_score {media_score:.4} should be ≈ {expected_media:.4}; \
             buggy code (matching on \"image\"/\"video\"/\"audio\"/\"file\") would \
             have produced {expected_text:.4}",
        );

        // Tight invariant: the ratio must reflect the kind
        // weight ratio (1.0 / 0.8 = 1.25), independent of any
        // INT8 quant noise.
        let ratio = text_score / media_score;
        let expected_ratio = TEXT_KIND_WEIGHT / MEDIA_KIND_WEIGHT;
        assert!(
            (ratio - expected_ratio).abs() < 0.01,
            "rank_score ratio {ratio:.4} should be ≈ {expected_ratio:.4} \
             (= TEXT_KIND_WEIGHT / MEDIA_KIND_WEIGHT)",
        );
    }

    #[test]
    fn kind_str_to_weight_canonical_mapping() {
        // The helper is the single source of truth for the
        // skeleton-kind → ranker-weight mapping. Pin the
        // canonical `MessageKind::as_str` vocabulary
        // anything else collapses to TEXT_KIND_WEIGHT so cold
        // / unknown rows stay visible.
        assert_eq!(kind_str_to_weight("text"), TEXT_KIND_WEIGHT);
        assert_eq!(kind_str_to_weight("media"), MEDIA_KIND_WEIGHT);
        assert_eq!(kind_str_to_weight("system"), TEXT_KIND_WEIGHT);
        // Vocabulary that previously slipped through the dead
        // arm in `execute_search_with_semantic` — pin them as
        // unknown / text-weight so a future regression on the
        // semantic-only path cannot silently re-route media
        // hits through these strings.
        assert_eq!(kind_str_to_weight("image"), TEXT_KIND_WEIGHT);
        assert_eq!(kind_str_to_weight("video"), TEXT_KIND_WEIGHT);
        assert_eq!(kind_str_to_weight("audio"), TEXT_KIND_WEIGHT);
        assert_eq!(kind_str_to_weight("file"), TEXT_KIND_WEIGHT);
        assert_eq!(kind_str_to_weight(""), TEXT_KIND_WEIGHT);
    }

    // -----------------------------------------------------------
    // `semantic_score`
    // population + `rerank_with_semantic` coverage.
    // -----------------------------------------------------------

    #[test]
    fn semantic_score_populated_for_semantic_hits() {
        let db = populated_db();
        let mock = MockTextEmbedder::default();
        let conn = db.connection();
        let target_msg_id: String = conn
            .query_row(
                "SELECT m.message_id FROM message_skeleton m
                 JOIN message_body b ON b.message_id = m.message_id
                 WHERE b.text_content = 'hello world' LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let cache = LocalStoreEmbeddingCache::new(conn);
        cache
            .put(
                &target_msg_id,
                XLMR_MODEL_VERSION,
                &mock.embed("hello world").unwrap(),
            )
            .unwrap();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello world".into(),
            ..Default::default()
        };
        let with_semantic = engine
            .execute_search_with_semantic(&q, &SearchScope::LocalOnly, &mock, None, 200)
            .unwrap();
        let target_uuid = Uuid::parse_str(&target_msg_id).unwrap();
        let target = with_semantic
            .iter()
            .find(|r| r.message_id == target_uuid)
            .expect("target row present");
        let sim = target.semantic_score.expect("semantic_score populated");
        // Self-similarity through the mock encoder is ~1.0.
        assert!(sim > 0.99, "expected near-1.0 self-similarity, got {sim}");
    }

    #[test]
    fn semantic_score_none_for_fts_only_hits() {
        let db = populated_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let plain = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert!(!plain.is_empty());
        for r in &plain {
            assert!(
                r.semantic_score.is_none(),
                "FTS-only hit must not carry semantic_score: {r:?}",
            );
        }
    }

    #[test]
    fn rerank_with_semantic_adjusts_ordering() {
        let db = populated_db();
        let mock = MockTextEmbedder::default();
        let conn = db.connection();
        // Pull two messages whose text both contain "hello".
        let row_a_id: String = conn
            .query_row(
                "SELECT m.message_id FROM message_skeleton m
                 JOIN message_body b ON b.message_id = m.message_id
                 WHERE b.text_content = 'hello world' LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let row_b_id: String = conn
            .query_row(
                "SELECT m.message_id FROM message_skeleton m
                 JOIN message_body b ON b.message_id = m.message_id
                 WHERE b.text_content = 'hello there' LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let cache = LocalStoreEmbeddingCache::new(conn);
        // Only `row_b_id` gets an embedding that exactly matches
        // the query — so reranking should move it up.
        cache
            .put(
                &row_b_id,
                XLMR_MODEL_VERSION,
                &mock.embed("hello there").unwrap(),
            )
            .unwrap();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let mut plain = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let plain_a_score = plain
            .iter()
            .find(|r| r.message_id.to_string() == row_a_id)
            .map(|r| r.rank_score)
            .unwrap_or(0.0);
        let plain_b_score = plain
            .iter()
            .find(|r| r.message_id.to_string() == row_b_id)
            .map(|r| r.rank_score)
            .unwrap_or(0.0);

        let q_emb = mock.embed("hello there").unwrap();
        engine
            .rerank_with_semantic(&mut plain, &q_emb, None, &SearchScope::LocalOnly)
            .unwrap();

        let row_b_uuid = Uuid::parse_str(&row_b_id).unwrap();
        let row_b = plain
            .iter()
            .find(|r| r.message_id == row_b_uuid)
            .expect("row_b present");
        // After rerank `row_b` carries a populated semantic_score
        // and a strictly greater rank_score than before.
        let sim_b = row_b
            .semantic_score
            .expect("rerank populates semantic_score for rows with embeddings");
        assert!(sim_b > 0.99);
        assert!(
            row_b.rank_score > plain_b_score,
            "rerank must not lower a known-good row (was {plain_b_score}, now {})",
            row_b.rank_score,
        );
        // `row_a` has no embedding — its rank_score is unchanged.
        let row_a_uuid = Uuid::parse_str(&row_a_id).unwrap();
        let row_a = plain
            .iter()
            .find(|r| r.message_id == row_a_uuid)
            .expect("row_a present");
        assert!(row_a.semantic_score.is_none());
        assert!((row_a.rank_score - plain_a_score).abs() < f64::EPSILON);
        // Re-sorted: b comes before a now because its score
        // strictly increased.
        let pos_b = plain
            .iter()
            .position(|r| r.message_id == row_b_uuid)
            .unwrap();
        let pos_a = plain
            .iter()
            .position(|r| r.message_id == row_a_uuid)
            .unwrap();
        assert!(
            pos_b < pos_a,
            "rerank should reorder b ahead of a (positions {pos_b} vs {pos_a})",
        );
    }

    #[test]
    fn rerank_respects_local_only_scope() {
        // The reranker is purely local; supplying `LocalOnly` and
        // `IncludeCold` over the same input must produce
        // identical updated `rank_score`s for rows whose
        // embeddings live in `search_vector`. (`IncludeCold`
        // only changes the cold-fan branch on the *query*, not
        // the rerank pass.)
        let db = populated_db();
        let mock = MockTextEmbedder::default();
        let conn = db.connection();
        let target_id: String = conn
            .query_row(
                "SELECT m.message_id FROM message_skeleton m
                 JOIN message_body b ON b.message_id = m.message_id
                 WHERE b.text_content = 'hello world' LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let cache = LocalStoreEmbeddingCache::new(conn);
        cache
            .put(
                &target_id,
                XLMR_MODEL_VERSION,
                &mock.embed("hello world").unwrap(),
            )
            .unwrap();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let q_emb = mock.embed("hello world").unwrap();

        let mut local = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        engine
            .rerank_with_semantic(&mut local, &q_emb, None, &SearchScope::LocalOnly)
            .unwrap();

        let mut cold = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        engine
            .rerank_with_semantic(&mut cold, &q_emb, None, &SearchScope::IncludeCold)
            .unwrap();

        assert_eq!(local.len(), cold.len());
        let target_uuid = Uuid::parse_str(&target_id).unwrap();
        let local_target = local.iter().find(|r| r.message_id == target_uuid).unwrap();
        let cold_target = cold.iter().find(|r| r.message_id == target_uuid).unwrap();
        assert_eq!(local_target.semantic_score, cold_target.semantic_score);
        assert!(
            (local_target.rank_score - cold_target.rank_score).abs() < f64::EPSILON,
            "LocalOnly and IncludeCold must produce identical rank_score updates",
        );
    }
}

// ---------------------------------------------------------------------------
// SearchTarget integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod phase8_target_tests {
    use super::*;
    use std::cell::Cell;

    use crate::local_store::db::LocalStoreDb;
    use crate::local_store::schema::Conversation;
    use crate::message::processor::{IngestedMessage, MessagePersister};

    fn fresh_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0xB8; 32]).unwrap()
    }

    fn cold_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0xC1; 32]).unwrap()
    }

    fn seed_conv(
        db: &LocalStoreDb,
        id: Uuid,
        community_id: &str,
        domain_id: &str,
        tenant_id: &str,
        scope: &str,
    ) {
        db.insert_conversation(&Conversation {
            conversation_id: id.to_string(),
            community_id: community_id.into(),
            domain_id: domain_id.into(),
            tenant_id: tenant_id.into(),
            scope: scope.into(),
            ..Default::default()
        })
        .unwrap();
    }

    fn persist(p: &MessagePersister<'_>, conv: Uuid, ts: i64, text: &str) -> Uuid {
        let mid = Uuid::now_v7();
        p.persist_ingested_message(&IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "alice".into(),
            created_at_ms: ts,
            text_content: Some(text.into()),
            media_descriptors: vec![],
            reply_to: None,
        })
        .expect("persist");
        mid
    }

    #[test]
    fn resolve_target_to_conversation_set_returns_correct_sets_for_each_variant() {
        let db = fresh_db();
        let community = Uuid::now_v7();
        let domain = Uuid::now_v7();
        let conv_a = Uuid::now_v7();
        let conv_b = Uuid::now_v7();
        let conv_c = Uuid::now_v7();
        seed_conv(
            &db,
            conv_a,
            &community.to_string(),
            &domain.to_string(),
            "tenant-1",
            "b2b",
        );
        seed_conv(&db, conv_b, &community.to_string(), "", "tenant-1", "b2b");
        seed_conv(&db, conv_c, "", "", "", "b2c");

        // Global → None
        assert!(
            resolve_target_to_conversation_set(&SearchTarget::Global, db.connection())
                .unwrap()
                .is_none()
        );
        // Conversation → singleton set
        let s = resolve_target_to_conversation_set(
            &SearchTarget::Conversation(conv_a),
            db.connection(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.len(), 1);
        assert!(s.contains(&conv_a.to_string()));
        // Community → conv_a + conv_b
        let s = resolve_target_to_conversation_set(
            &SearchTarget::Community(community),
            db.connection(),
        )
        .unwrap()
        .unwrap();
        assert!(s.contains(&conv_a.to_string()));
        assert!(s.contains(&conv_b.to_string()));
        assert!(!s.contains(&conv_c.to_string()));
        // Domain → conv_a only
        let s = resolve_target_to_conversation_set(&SearchTarget::Domain(domain), db.connection())
            .unwrap()
            .unwrap();
        assert_eq!(s.len(), 1);
        assert!(s.contains(&conv_a.to_string()));
        // Tenant → conv_a + conv_b
        let s = resolve_target_to_conversation_set(
            &SearchTarget::Tenant("tenant-1".into()),
            db.connection(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.len(), 2);
        // B2cAll → conv_c only
        let s = resolve_target_to_conversation_set(&SearchTarget::B2cAll, db.connection())
            .unwrap()
            .unwrap();
        assert_eq!(s.len(), 1);
        assert!(s.contains(&conv_c.to_string()));
    }

    #[test]
    fn search_with_community_target_filters_to_community_conversations() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let community = Uuid::now_v7();
        let conv_in = Uuid::now_v7();
        let conv_out = Uuid::now_v7();
        seed_conv(&db, conv_in, &community.to_string(), "", "tenant-x", "b2b");
        seed_conv(&db, conv_out, "", "", "tenant-y", "b2c");
        let _ = persist(&p, conv_in, 1, "shared content meeting");
        let mid_out = persist(&p, conv_out, 2, "shared content meeting");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "meeting".into(),
            target: SearchTarget::Community(community),
            ..Default::default()
        };
        let hits = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert!(!hits.is_empty(), "community target must surface ≥1 hit");
        for h in &hits {
            assert_ne!(
                h.message_id, mid_out,
                "out-of-community message must not surface"
            );
        }
    }

    #[test]
    fn search_with_conversation_target_only_filters_to_that_conversation() {
        // contract: setting `target = SearchTarget::Conversation(c)`
        // *without* the legacy `conversation_filter` field must scope the
        // search to that single conversation. Regression for the case
        // where `push_target_filter` previously skipped the
        // `Conversation(_)` arm and silently fanned back out to global.
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv_in = Uuid::now_v7();
        let conv_out = Uuid::now_v7();
        seed_conv(&db, conv_in, "", "", "", "b2c");
        seed_conv(&db, conv_out, "", "", "", "b2c");
        let mid_in = persist(&p, conv_in, 1, "shared content meeting");
        let mid_out = persist(&p, conv_out, 2, "shared content meeting");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "meeting".into(),
            target: SearchTarget::Conversation(conv_in),
            // legacy field intentionally left None — this is the
            // bug-regression case.
            conversation_filter: None,
            ..Default::default()
        };
        let hits = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let ids: std::collections::HashSet<Uuid> = hits.iter().map(|h| h.message_id).collect();
        assert!(
            ids.contains(&mid_in),
            "in-conversation hit must surface (got {:?})",
            ids
        );
        assert!(
            !ids.contains(&mid_out),
            "out-of-conversation hit must NOT surface (got {:?})",
            ids
        );
    }

    #[test]
    fn search_with_global_target_returns_all_conversations() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv_a = Uuid::now_v7();
        let conv_b = Uuid::now_v7();
        seed_conv(&db, conv_a, "ca", "", "", "b2c");
        seed_conv(&db, conv_b, "cb", "", "", "b2c");
        let mid_a = persist(&p, conv_a, 1, "global content meeting");
        let mid_b = persist(&p, conv_b, 2, "global content meeting");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "meeting".into(),
            target: SearchTarget::Global,
            ..Default::default()
        };
        let hits = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        let ids: std::collections::HashSet<Uuid> = hits.iter().map(|h| h.message_id).collect();
        assert!(ids.contains(&mid_a));
        assert!(ids.contains(&mid_b));
    }

    #[test]
    fn search_with_empty_community_target_returns_no_rows() {
        // SearchTarget::Community(uuid) where the uuid does not
        // match any conversation must short-circuit to "no rows"
        // rather than fall back to global search.
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conv(&db, conv, "ca", "", "", "b2c");
        let _ = persist(&p, conv, 1, "global content meeting");

        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: "meeting".into(),
            target: SearchTarget::Community(Uuid::now_v7()),
            ..Default::default()
        };
        let hits = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert!(hits.is_empty(), "empty community must return zero hits");
    }

    #[test]
    fn conversation_hierarchy_columns_round_trip() {
        let db = fresh_db();
        let conv = Uuid::now_v7();
        let community = Uuid::now_v7();
        seed_conv(&db, conv, &community.to_string(), "", "tenant-z", "b2b");
        let stored = db
            .get_conversation(&conv.to_string())
            .unwrap()
            .expect("conversation must round-trip");
        assert_eq!(stored.community_id, community.to_string());
        assert_eq!(stored.tenant_id, "tenant-z");
        assert_eq!(stored.scope, "b2b");
    }

    // -------------------------------------------------------------------
    // Tasks 1, 2, 5
    // -------------------------------------------------------------------

    fn ms_for(year: i32, month: u32, day: u32) -> i64 {
        super::days_from_civil(year, month, day) * 86_400_000
    }

    #[test]
    fn bucket_overlaps_with_no_date_filters_returns_true() {
        assert!(super::bucket_overlaps_date_range("2026-04", None, None));
    }

    #[test]
    fn bucket_overlaps_rejects_bucket_before_date_from() {
        // Bucket = March 2026 ends at 2026-04-01T00:00:00Z. A
        // `date_from` set to April 1st must drop it.
        assert!(!super::bucket_overlaps_date_range(
            "2026-03",
            Some(ms_for(2026, 4, 1)),
            None,
        ));
    }

    #[test]
    fn bucket_overlaps_rejects_bucket_after_date_to() {
        // Bucket = May 2026 starts at 2026-05-01T00:00:00Z. A
        // `date_to` set to April 30th must drop it.
        assert!(!super::bucket_overlaps_date_range(
            "2026-05",
            None,
            Some(ms_for(2026, 4, 30)),
        ));
    }

    #[test]
    fn bucket_overlaps_accepts_overlapping_bucket() {
        // April 2026 bucket overlaps a window from April 10 to
        // May 5: bucket end > from, bucket start <= to.
        assert!(super::bucket_overlaps_date_range(
            "2026-04",
            Some(ms_for(2026, 4, 10)),
            Some(ms_for(2026, 5, 5)),
        ));
    }

    #[test]
    fn bucket_overlaps_handles_malformed_bucket_gracefully() {
        // Bogus bucket grammar must fall back to "include" so we
        // never silently drop hits we cannot reason about.
        assert!(super::bucket_overlaps_date_range(
            "not-a-bucket",
            Some(ms_for(2026, 4, 1)),
            Some(ms_for(2026, 4, 30)),
        ));
        assert!(super::bucket_overlaps_date_range(
            "2026-13",
            Some(ms_for(2026, 4, 1)),
            None,
        ));
    }

    /// Bloom-aware fake cold source. Tracks how many text /
    /// fuzzy fetches were served; exposes a knob for "force
    /// fetch_bloom_shard to fail".
    struct BloomFakeColdSource {
        buckets: Vec<(String, String)>,
        text: HashMap<(String, String), Vec<FtsRow>>,
        fuzzy: HashMap<(String, String), Vec<FuzzyRow>>,
        bloom: HashMap<(String, String), BloomFilter>,
        bloom_should_fail: bool,
        text_calls: Cell<usize>,
        fuzzy_calls: Cell<usize>,
        bloom_calls: Cell<usize>,
    }
    impl BloomFakeColdSource {
        fn new() -> Self {
            Self {
                buckets: Vec::new(),
                text: HashMap::new(),
                fuzzy: HashMap::new(),
                bloom: HashMap::new(),
                bloom_should_fail: false,
                text_calls: Cell::new(0),
                fuzzy_calls: Cell::new(0),
                bloom_calls: Cell::new(0),
            }
        }
        fn with_text(mut self, conv: &str, bucket: &str, rows: Vec<FtsRow>) -> Self {
            let key = (conv.to_string(), bucket.to_string());
            if !self.buckets.contains(&key) {
                self.buckets.push(key.clone());
            }
            self.text.insert(key, rows);
            self
        }
        fn with_bloom(mut self, conv: &str, bucket: &str, words: &[&str]) -> Self {
            let key = (conv.to_string(), bucket.to_string());
            if !self.buckets.contains(&key) {
                self.buckets.push(key.clone());
            }
            let owned: Vec<String> = words.iter().map(|s| s.to_lowercase()).collect();
            let filter = BloomFilter::from_words(&owned, owned.len().max(8));
            self.bloom.insert(key, filter);
            self
        }
        fn with_bloom_failure(mut self) -> Self {
            self.bloom_should_fail = true;
            self
        }
    }
    impl ColdShardSource for BloomFakeColdSource {
        fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
            Ok(self.buckets.clone())
        }
        fn fetch_text_rows(&self, conv: &str, bucket: &str) -> Result<Vec<FtsRow>, Error> {
            self.text_calls.set(self.text_calls.get() + 1);
            Ok(self
                .text
                .get(&(conv.to_string(), bucket.to_string()))
                .cloned()
                .unwrap_or_default())
        }
        fn fetch_fuzzy_rows(&self, conv: &str, bucket: &str) -> Result<Vec<FuzzyRow>, Error> {
            self.fuzzy_calls.set(self.fuzzy_calls.get() + 1);
            Ok(self
                .fuzzy
                .get(&(conv.to_string(), bucket.to_string()))
                .cloned()
                .unwrap_or_default())
        }
        fn fetch_bloom_shard(
            &self,
            conv: &str,
            bucket: &str,
        ) -> Result<Option<BloomFilter>, Error> {
            self.bloom_calls.set(self.bloom_calls.get() + 1);
            if self.bloom_should_fail {
                return Err(Error::Search("simulated transport failure".into()));
            }
            Ok(self
                .bloom
                .get(&(conv.to_string(), bucket.to_string()))
                .cloned())
        }
    }

    fn cold_text_row(conv: &str, mid: &str, text: &str) -> FtsRow {
        FtsRow {
            message_id: mid.to_string(),
            conversation_id: conv.to_string(),
            sender_id: "alice".to_string(),
            created_at_ms: ms_for(2026, 4, 15),
            text_content: text.to_string(),
        }
    }

    #[test]
    fn bloom_precheck_skips_bucket_when_all_tokens_rejected() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mid = Uuid::now_v7().to_string();
        let source = BloomFakeColdSource::new()
            .with_text(&conv, "2026-04", vec![cold_text_row(&conv, &mid, "lighthouse beacon")])
 // The bloom shard advertises words that have nothing
 // to do with the query; pre-check must reject the
 // bucket before we call fetch_text_rows.
            .with_bloom(&conv, "2026-04", &["alpha", "beta", "gamma"]);
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let _ = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        assert_eq!(source.bloom_calls.get(), 1, "bloom must be consulted");
        assert_eq!(
            source.text_calls.get(),
            0,
            "bloom rejection must short-circuit text fetch"
        );
    }

    #[test]
    fn bloom_precheck_passes_bucket_when_any_token_matches() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mid = Uuid::now_v7().to_string();
        let source = BloomFakeColdSource::new()
            .with_text(
                &conv,
                "2026-04",
                vec![cold_text_row(&conv, &mid, "lighthouse beacon")],
            )
            .with_bloom(&conv, "2026-04", &["alpha", "lighthouse", "gamma"]);
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        assert_eq!(source.bloom_calls.get(), 1);
        assert_eq!(source.text_calls.get(), 1);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn bloom_precheck_falls_through_when_bloom_shard_missing() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mid = Uuid::now_v7().to_string();
        // No `with_bloom(...)` call → fetch_bloom_shard returns
        // Ok(None). The pre-check must not skip the bucket.
        let source = BloomFakeColdSource::new().with_text(
            &conv,
            "2026-04",
            vec![cold_text_row(&conv, &mid, "lighthouse beacon")],
        );
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        assert_eq!(source.bloom_calls.get(), 1);
        assert_eq!(source.text_calls.get(), 1, "fall-through to text fetch");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn bloom_precheck_falls_through_on_transport_error() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mid = Uuid::now_v7().to_string();
        let source = BloomFakeColdSource::new()
            .with_text(
                &conv,
                "2026-04",
                vec![cold_text_row(&conv, &mid, "lighthouse beacon")],
            )
            .with_bloom_failure();
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        // A failing bloom fetch must not abort the search; the
        // cold path falls through to the full shards and the
        // call still returns the one matching row.
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        assert_eq!(source.bloom_calls.get(), 1);
        assert_eq!(source.text_calls.get(), 1);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn cold_source_fetch_bloom_with_cache_swallows_transport_errors() {
        // Function-level regression for the batch 6
        // contract on `cold_source_fetch_bloom_with_cache`:
        // even when the underlying `ColdShardSource::fetch_bloom_shard`
        // returns `Err(_)`, the helper must yield `Ok(None)` so
        // any future caller that `?`-propagates or `.unwrap`s
        // the result still gets the documented graceful-degradation
        // behaviour. Pairs with `bloom_precheck_falls_through_on_transport_error`,
        // which exercises the same code path through the public
        // `execute_search_with_cold_source` API.
        let conv = "conv-1";
        let bucket = "2026-04";
        let source = BloomFakeColdSource::new().with_bloom_failure();
        let result = cold_source_fetch_bloom_with_cache(&source, None, conv, bucket);
        assert!(
            matches!(result, Ok(None)),
            "transport errors must be swallowed into Ok(None); got {:?}",
            result.as_ref().map(|r| r.as_ref().map(|_| "Some(_)")),
        );
        assert_eq!(
            source.bloom_calls.get(),
            1,
            "the helper must still issue exactly one bloom fetch attempt"
        );
    }

    #[test]
    fn cold_search_with_date_range_skips_irrelevant_buckets() {
        // Two buckets: 2026-01 (out of range) and 2026-04 (in
        // range). The query's date_from / date_to must drop the
        // first bucket without ever fetching its text / fuzzy
        // shards.
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mid_jan = Uuid::now_v7().to_string();
        let mid_apr = Uuid::now_v7().to_string();
        let mut row_jan = cold_text_row(&conv, &mid_jan, "lighthouse keeper");
        row_jan.created_at_ms = ms_for(2026, 1, 15);
        let mut row_apr = cold_text_row(&conv, &mid_apr, "lighthouse beacon");
        row_apr.created_at_ms = ms_for(2026, 4, 15);
        let source = BloomFakeColdSource::new()
            .with_text(&conv, "2026-01", vec![row_jan])
            .with_text(&conv, "2026-04", vec![row_apr]);
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            date_from: Some(ms_for(2026, 4, 1)),
            date_to: Some(ms_for(2026, 4, 30)),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
            .unwrap();
        assert_eq!(
            source.text_calls.get(),
            1,
            "only the in-range bucket is fetched"
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].message_id.to_string(), mid_apr);
    }

    #[test]
    fn tenant_policy_blocks_global_search_when_disabled() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mid = Uuid::now_v7().to_string();
        let source = BloomFakeColdSource::new().with_text(
            &conv,
            "2026-04",
            vec![cold_text_row(&conv, &mid, "lighthouse")],
        );
        let policy = TenantSearchPolicy {
            allow_global_search: false,
            ..TenantSearchPolicy::default()
        };
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            target: SearchTarget::Global,
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source_full(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
            )
            .unwrap();
        assert!(results.is_empty(), "global search must be blocked");
        assert_eq!(source.text_calls.get(), 0);
    }

    #[test]
    fn tenant_policy_caps_cold_bucket_count() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mut source = BloomFakeColdSource::new();
        for month in 1..=6 {
            let bucket = format!("2026-{month:02}");
            let mid = Uuid::now_v7().to_string();
            let mut row = cold_text_row(&conv, &mid, "lighthouse");
            row.created_at_ms = ms_for(2026, month, 15);
            source = source.with_text(&conv, &bucket, vec![row]);
        }
        let policy = TenantSearchPolicy {
            // Allow Global so the cap is what we're testing.
            allow_global_search: true,
            allow_cross_tenant_results: true,
            max_cold_buckets_per_search: 2,
            require_bloom_shards: false,
        };
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            target: SearchTarget::Global,
            ..Default::default()
        };
        let _ = engine
            .execute_search_with_cold_source_full(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
            )
            .unwrap();
        assert_eq!(
            source.text_calls.get(),
            2,
            "policy must cap fan-out at 2 buckets"
        );
    }

    #[test]
    fn tenant_policy_requires_bloom_when_configured() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mid = Uuid::now_v7().to_string();
        // Bucket without a bloom shard — under
        // require_bloom_shards = true the bucket is skipped.
        let source = BloomFakeColdSource::new().with_text(
            &conv,
            "2026-04",
            vec![cold_text_row(&conv, &mid, "lighthouse")],
        );
        let policy = TenantSearchPolicy {
            allow_global_search: true,
            allow_cross_tenant_results: true,
            max_cold_buckets_per_search: 50,
            require_bloom_shards: true,
        };
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            target: SearchTarget::Global,
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source_full(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
            )
            .unwrap();
        assert!(results.is_empty(), "missing bloom must skip bucket");
        assert_eq!(source.text_calls.get(), 0);
    }

    #[test]
    fn shard_cache_hit_avoids_transport_fetch() {
        let db = cold_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7().to_string();
        let mid = Uuid::now_v7().to_string();
        let source = BloomFakeColdSource::new().with_text(
            &conv,
            "2026-04",
            vec![cold_text_row(&conv, &mid, "lighthouse")],
        );
        let cache = std::sync::Mutex::new(ShardCache::new(usize::MAX));
        let policy = TenantSearchPolicy::default();
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..Default::default()
        };
        // First call populates cache.
        let _ = engine
            .execute_search_with_cold_source_full(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                Some(&cache),
                200,
            )
            .unwrap();
        let after_first = source.text_calls.get();
        // Second call must be a pure cache hit.
        let _ = engine
            .execute_search_with_cold_source_full(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                Some(&cache),
                200,
            )
            .unwrap();
        assert_eq!(
            source.text_calls.get(),
            after_first,
            "repeated search must not refetch text shard"
        );
    }

    // -----------------------------------------------------------------
    // parallel-fetch tests.
    // -----------------------------------------------------------------

    /// `Send + Sync` cold source for the parallel-fetch tests.
    /// Uses [`std::sync::atomic::AtomicUsize`] counters and a
    /// [`std::sync::Mutex`]-guarded "max concurrent" gauge so
    /// the tests can assert on real concurrency behaviour.
    struct CountingParallelSource {
        buckets: Vec<(String, String)>,
        text: HashMap<(String, String), Vec<FtsRow>>,
        fuzzy: HashMap<(String, String), Vec<FuzzyRow>>,
        text_calls: std::sync::atomic::AtomicUsize,
        in_flight: std::sync::atomic::AtomicUsize,
        peak_in_flight: std::sync::atomic::AtomicUsize,
        fail_buckets: HashSet<(String, String)>,
        fetch_delay_ms: u64,
    }
    impl CountingParallelSource {
        fn new() -> Self {
            Self {
                buckets: Vec::new(),
                text: HashMap::new(),
                fuzzy: HashMap::new(),
                text_calls: std::sync::atomic::AtomicUsize::new(0),
                in_flight: std::sync::atomic::AtomicUsize::new(0),
                peak_in_flight: std::sync::atomic::AtomicUsize::new(0),
                fail_buckets: HashSet::new(),
                fetch_delay_ms: 0,
            }
        }
        fn with_delay_ms(mut self, ms: u64) -> Self {
            self.fetch_delay_ms = ms;
            self
        }
        fn with_text(mut self, conv: &str, bucket: &str, rows: Vec<FtsRow>) -> Self {
            let key = (conv.to_string(), bucket.to_string());
            if !self.buckets.contains(&key) {
                self.buckets.push(key.clone());
            }
            self.text.insert(key, rows);
            self
        }
        fn fail_for(mut self, conv: &str, bucket: &str) -> Self {
            let key = (conv.to_string(), bucket.to_string());
            if !self.buckets.contains(&key) {
                self.buckets.push(key.clone());
            }
            self.fail_buckets.insert(key);
            self
        }
        fn enter(&self) {
            use std::sync::atomic::Ordering::SeqCst;
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            // Update peak_in_flight to the running maximum.
            self.peak_in_flight.fetch_max(now, SeqCst);
        }
        fn leave(&self) {
            use std::sync::atomic::Ordering::SeqCst;
            self.in_flight.fetch_sub(1, SeqCst);
        }
    }
    impl ColdShardSource for CountingParallelSource {
        fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
            Ok(self.buckets.clone())
        }
        fn fetch_text_rows(&self, conv: &str, bucket: &str) -> Result<Vec<FtsRow>, Error> {
            use std::sync::atomic::Ordering::SeqCst;
            self.enter();
            self.text_calls.fetch_add(1, SeqCst);
            let key = (conv.to_string(), bucket.to_string());
            if self.fetch_delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(self.fetch_delay_ms));
            }
            let res = if self.fail_buckets.contains(&key) {
                Err(Error::Search("simulated text failure".into()))
            } else {
                Ok(self.text.get(&key).cloned().unwrap_or_default())
            };
            self.leave();
            res
        }
        fn fetch_fuzzy_rows(&self, conv: &str, bucket: &str) -> Result<Vec<FuzzyRow>, Error> {
            self.enter();
            let key = (conv.to_string(), bucket.to_string());
            let out = self.fuzzy.get(&key).cloned().unwrap_or_default();
            self.leave();
            Ok(out)
        }
    }

    fn parallel_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0xC1; 32]).unwrap()
    }

    fn make_fts_row(message_id: Uuid, conv: Uuid, text: &str, ms: i64) -> FtsRow {
        FtsRow {
            message_id: message_id.to_string(),
            conversation_id: conv.to_string(),
            sender_id: "alice".into(),
            created_at_ms: ms,
            text_content: text.into(),
        }
    }

    #[test]
    fn parallel_fetch_returns_same_results_as_sequential() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7();
        let mut source_seq = CountingParallelSource::new();
        let mut source_par = CountingParallelSource::new();
        for i in 0..10 {
            let mid = Uuid::now_v7();
            let bucket = format!("2026-{:02}", (i % 12) + 1);
            let row = make_fts_row(mid, conv, "lighthouse beacon shines", 1_700_000_000_000 + i);
            source_seq = source_seq.with_text(&conv.to_string(), &bucket, vec![row.clone()]);
            source_par = source_par.with_text(&conv.to_string(), &bucket, vec![row]);
        }
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let seq = engine
            .execute_search_with_cold_source_full(
                &q,
                &SearchScope::IncludeCold,
                &source_seq,
                &policy,
                None,
                200,
            )
            .unwrap();
        let par = engine
            .execute_search_with_cold_source_full_parallel(
                &q,
                &SearchScope::IncludeCold,
                &source_par,
                &policy,
                None,
                200,
                4,
            )
            .unwrap();
        let seq_ids: Vec<String> = seq.iter().map(|r| r.message_id.to_string()).collect();
        let par_ids: Vec<String> = par.iter().map(|r| r.message_id.to_string()).collect();
        assert_eq!(seq_ids, par_ids);
        assert_eq!(seq.len(), par.len());
    }

    #[test]
    fn parallel_fetch_respects_concurrency_limit() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7();
        let mut source = CountingParallelSource::new().with_delay_ms(20);
        for i in 0..8 {
            let mid = Uuid::now_v7();
            let bucket = format!("2026-{:02}", (i % 12) + 1);
            let row = make_fts_row(mid, conv, "alpha", 1_700_000_000_000 + i);
            source = source.with_text(&conv.to_string(), &bucket, vec![row]);
        }
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let _ = engine
            .execute_search_with_cold_source_full_parallel(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
                3,
            )
            .unwrap();
        let peak = source
            .peak_in_flight
            .load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            peak <= 3,
            "peak_in_flight = {peak}, expected ≤ 3 (concurrency limit)"
        );
    }

    #[test]
    fn parallel_fetch_survives_single_bucket_error() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7();
        let conv_str = conv.to_string();
        let good_mid = Uuid::now_v7();
        let source = CountingParallelSource::new()
            .with_text(
                &conv_str,
                "2026-01",
                vec![make_fts_row(
                    good_mid,
                    conv,
                    "alpha beta",
                    1_700_000_000_000,
                )],
            )
            .with_text(&conv_str, "2026-02", vec![])
            .fail_for(&conv_str, "2026-02");
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let res = engine
            .execute_search_with_cold_source_full_parallel(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
                4,
            )
            .unwrap();
        // The "good" bucket's hit must still surface even
        // though the other bucket hard-errored.
        let ids: Vec<String> = res.iter().map(|r| r.message_id.to_string()).collect();
        assert!(
            ids.iter().any(|id| id == &good_mid.to_string()),
            "expected good_mid in results: {ids:?}"
        );
    }

    #[test]
    fn parallel_fetch_empty_buckets_returns_empty() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let source = CountingParallelSource::new();
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let res = engine
            .execute_search_with_cold_source_full_parallel(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
                4,
            )
            .unwrap();
        assert!(res.is_empty());
        assert_eq!(
            source.text_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn parallel_fetch_local_only_skips_cold_source() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7();
        let conv_str = conv.to_string();
        let source = CountingParallelSource::new().with_text(
            &conv_str,
            "2026-01",
            vec![make_fts_row(
                Uuid::now_v7(),
                conv,
                "alpha",
                1_700_000_000_000,
            )],
        );
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let _ = engine
            .execute_search_with_cold_source_full_parallel(
                &q,
                &SearchScope::LocalOnly,
                &source,
                &policy,
                None,
                200,
                4,
            )
            .unwrap();
        assert_eq!(
            source.text_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "LocalOnly must never invoke the cold source"
        );
    }

    // -----------------------------------------------------------------
    // streaming-search tests.
    // -----------------------------------------------------------------

    #[test]
    fn streaming_search_emits_local_results_first() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7();
        let conv_str = conv.to_string();
        let source = CountingParallelSource::new().with_text(
            &conv_str,
            "2026-01",
            vec![FtsRow {
                message_id: Uuid::now_v7().to_string(),
                conversation_id: conv_str.clone(),
                sender_id: "alice".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: "alpha".into(),
            }],
        );
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let mut events: Vec<crate::SearchEvent> = Vec::new();
        let _ = engine
            .execute_search_streaming(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
                |e| events.push(e),
            )
            .unwrap();
        assert!(
            matches!(events.first(), Some(crate::SearchEvent::LocalResults(_))),
            "first event must be LocalResults, got: {events:?}"
        );
    }

    #[test]
    fn streaming_search_emits_search_complete_last() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let source = CountingParallelSource::new();
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let mut events: Vec<crate::SearchEvent> = Vec::new();
        let _ = engine
            .execute_search_streaming(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
                |e| events.push(e),
            )
            .unwrap();
        assert!(matches!(
            events.last(),
            Some(crate::SearchEvent::SearchComplete { .. })
        ));
    }

    #[test]
    fn streaming_search_emits_cold_bucket_complete_per_bucket() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7();
        let conv_str = conv.to_string();
        let mut source = CountingParallelSource::new();
        for bucket in ["2026-01", "2026-02", "2026-03"] {
            let mid = Uuid::now_v7();
            source = source.with_text(
                &conv_str,
                bucket,
                vec![FtsRow {
                    message_id: mid.to_string(),
                    conversation_id: conv_str.clone(),
                    sender_id: "alice".into(),
                    created_at_ms: 1_700_000_000_000,
                    text_content: "alpha".into(),
                }],
            );
        }
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let mut events: Vec<crate::SearchEvent> = Vec::new();
        let _ = engine
            .execute_search_streaming(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
                |e| events.push(e),
            )
            .unwrap();
        let bucket_events = events
            .iter()
            .filter(|e| matches!(e, crate::SearchEvent::ColdBucketComplete { .. }))
            .count();
        assert_eq!(bucket_events, 3, "got: {events:?}");
    }

    #[test]
    fn streaming_search_local_only_skips_cold_events() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let conv = Uuid::now_v7();
        let conv_str = conv.to_string();
        let source = CountingParallelSource::new().with_text(
            &conv_str,
            "2026-01",
            vec![FtsRow {
                message_id: Uuid::now_v7().to_string(),
                conversation_id: conv_str.clone(),
                sender_id: "alice".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: "alpha".into(),
            }],
        );
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let mut events: Vec<crate::SearchEvent> = Vec::new();
        let _ = engine
            .execute_search_streaming(
                &q,
                &SearchScope::LocalOnly,
                &source,
                &policy,
                None,
                200,
                |e| events.push(e),
            )
            .unwrap();
        // LocalOnly should emit ONLY LocalResults + SearchComplete.
        assert_eq!(events.len(), 2, "got: {events:?}");
        assert!(matches!(events[0], crate::SearchEvent::LocalResults(_)));
        assert!(matches!(
            events[1],
            crate::SearchEvent::SearchComplete { .. }
        ));
    }

    /// Regression: `execute_search_streaming` could violate the
    /// "SearchComplete is emitted exactly once" contract: when
    /// `cold_source.cold_buckets` returned an `Err`, the
    /// previous code propagated the error via `?` *after*
    /// `LocalResults` had already been emitted, leaving
    /// callback listeners with no terminal event. The fix emits
    /// a fail-open `SearchComplete` carrying the local results
    /// before propagating the error, so the listener always
    /// sees both edges (local → complete) regardless of
    /// transport state.
    #[test]
    fn streaming_search_emits_search_complete_when_cold_buckets_fails() {
        #[derive(Debug)]
        struct FailingBucketsSource;
        impl ColdShardSource for FailingBucketsSource {
            fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
                Err(Error::Transport("simulated cold-buckets failure".into()))
            }
            fn fetch_text_rows(&self, _conv: &str, _bucket: &str) -> Result<Vec<FtsRow>, Error> {
                Ok(Vec::new())
            }
            fn fetch_fuzzy_rows(&self, _conv: &str, _bucket: &str) -> Result<Vec<FuzzyRow>, Error> {
                Ok(Vec::new())
            }
        }

        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let source = FailingBucketsSource;
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let mut events: Vec<crate::SearchEvent> = Vec::new();
        let res = engine.execute_search_streaming(
            &q,
            &SearchScope::IncludeCold,
            &source,
            &policy,
            None,
            200,
            |e| events.push(e),
        );
        assert!(
            matches!(res, Err(Error::Transport(_))),
            "expected the underlying cold_buckets() error to propagate, got {res:?}"
        );
        // Listener must see both LocalResults and SearchComplete
        // exactly once, in that order.
        assert_eq!(events.len(), 2, "got: {events:?}");
        assert!(matches!(events[0], crate::SearchEvent::LocalResults(_)));
        match &events[1] {
            crate::SearchEvent::SearchComplete {
                cold_buckets_fetched,
                cold_buckets_skipped,
                ..
            } => {
                assert_eq!(*cold_buckets_fetched, 0);
                assert_eq!(*cold_buckets_skipped, 0);
            }
            other => panic!("expected SearchComplete, got: {other:?}"),
        }
    }

    #[test]
    fn streaming_search_no_cold_buckets_emits_complete_immediately() {
        let db = parallel_db();
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let source = CountingParallelSource::new();
        let q = SearchQuery {
            query_string: "alpha".into(),
            ..SearchQuery::default()
        };
        let policy = TenantSearchPolicy::default();
        let mut events: Vec<crate::SearchEvent> = Vec::new();
        let _ = engine
            .execute_search_streaming(
                &q,
                &SearchScope::IncludeCold,
                &source,
                &policy,
                None,
                200,
                |e| events.push(e),
            )
            .unwrap();
        assert_eq!(events.len(), 2, "got: {events:?}");
        assert!(matches!(events[0], crate::SearchEvent::LocalResults(_)));
        match &events[1] {
            crate::SearchEvent::SearchComplete {
                cold_buckets_fetched,
                cold_buckets_skipped,
                ..
            } => {
                assert_eq!(*cold_buckets_fetched, 0);
                assert_eq!(*cold_buckets_skipped, 0);
            }
            other => panic!("expected SearchComplete, got: {other:?}"),
        }
    }
}
