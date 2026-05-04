//! Unified query engine combining FTS5, fuzzy search, and structured
//! filters.
//!
//! `docs/PROPOSAL.md §12` defines the [`SearchQuery`] /
//! [`SearchScope`] / [`SearchResult`] surface. Phase 1 lands the
//! local-store half: the engine reads from `search_fts` for free-text
//! queries, fans the same query out to the script-aware fuzzy index
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
//! Ranking weights follow `docs/PROPOSAL.md §7.5`: BM25 is weighted
//! at `2.0` and fuzzy-token-overlap at `1.0`, so a fuzzy-only hit
//! always ranks below an FTS hit on the same query — and a row that
//! matches both engines accumulates both contributions.
//!
//! [`SearchScope::IncludeCold`] now flags rows whose
//! `message_skeleton.body_state = 'remote_archive_only'` with
//! `SearchResult::is_cold = true` so the orchestration layer can
//! enqueue them into the [`crate::offload::HydrationQueue`] at
//! priority `SearchResultTap` (Phase 5, Task 7).
//!
//! The cold-bucket fan-out (Phase 5, Task 1) is wired through the
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

use rusqlite::{params_from_iter, types::Value};
use uuid::Uuid;

use crate::local_store::db::{DbResult, LocalStoreDb};
use crate::search::fuzzy_search::{FuzzySearchEngine, FuzzyTokenizer};
use crate::search::shard_builder::{FtsRow, FuzzyRow};
use crate::search::text_search::TextSearchEngine;
use crate::search::tokenizer::{fuzzy_min_overlap, ScriptClass};
use crate::{ContentKind, Error, SearchQuery, SearchResult, SearchScope};

/// BM25 contribution weight in the merged rank score
/// (`docs/PROPOSAL.md §7.5`).
pub(crate) const BM25_WEIGHT: f64 = 2.0;

/// Fuzzy-token-overlap contribution weight in the merged rank score
/// (`docs/PROPOSAL.md §7.5`).
pub(crate) const FUZZY_WEIGHT: f64 = 1.0;

/// Recency-decay weight in the merged rank score
/// (`docs/PROPOSAL.md §7.5` — `recency_boost`).
pub(crate) const RECENCY_WEIGHT: f64 = 0.5;

/// Half-life of the recency-decay function in days. Mirrors
/// [`crate::offload::scoring`]'s 30-day half-life so search and
/// eviction agree on what "recent" means.
pub(crate) const RECENCY_HALF_LIFE_DAYS: f64 = 30.0;

/// Multiplicative content-kind weight applied to the merged rank
/// (`docs/PROPOSAL.md §7.5`). Text bodies are fully searchable; the
/// thumbnails / OCR rows that back media messages are coarser, so
/// media gets a lighter weight.
pub(crate) const TEXT_KIND_WEIGHT: f64 = 1.0;
/// See [`TEXT_KIND_WEIGHT`].
pub(crate) const MEDIA_KIND_WEIGHT: f64 = 0.8;

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
    /// return `Ok(Vec::new())` when no shard exists for the
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
}

// ---------------------------------------------------------------------------
// QueryEngine
// ---------------------------------------------------------------------------

/// Unified search engine. Borrows a [`LocalStoreDb`]; cheap to
/// reconstruct per call.
#[derive(Debug)]
pub struct QueryEngine<'a> {
    db: &'a LocalStoreDb,
}

impl<'a> QueryEngine<'a> {
    /// Construct a new engine bound to the given database.
    pub fn new(db: &'a LocalStoreDb) -> Self {
        Self { db }
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

    /// Run a unified search and fan out to the personal archive
    /// via `cold_source` when [`SearchScope::IncludeCold`] is set.
    ///
    /// This is the Phase 5, Task 1 entry point: cold buckets are
    /// resolved by [`ColdShardSource::cold_buckets`], shards are
    /// fetched + decrypted by the source, and the in-process
    /// FTS-like + fuzzy fan-out is merged into the local result
    /// set with `is_cold = true`.
    ///
    /// Behaviour summary:
    /// * [`SearchScope::LocalOnly`] never invokes the cold source —
    ///   this is the offline-only contract from
    ///   `docs/PROPOSAL.md §12`.
    /// * Empty query strings short-circuit to the structured-only
    ///   path; cold fan-out only runs on free-text queries.
    /// * Non-text `query.content_kind` values short-circuit to
    ///   the local result set. Phase 5 only ships text + fuzzy
    ///   cold shards, so a media-only query has no cold
    ///   contribution to merge; consulting the cold source would
    ///   leak text-shard hits through the kind filter.
    /// * Errors from the cold source bubble out of this call —
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
        // Local results first. mark_cold_results runs inside
        // execute_search_with_limit when scope is IncludeCold so
        // any local row whose body is offloaded already carries
        // is_cold = true.
        let local = self
            .execute_search_with_limit(query, scope, limit)
            .map_err(|e| Error::Search(e.to_string()))?;

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

        // Phase 5 only ships text + fuzzy cold shards. When the
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

        let buckets = cold_source.cold_buckets()?;
        if buckets.is_empty() {
            return Ok(local);
        }

        // If a conversation_filter is set, skip every bucket whose
        // conversation_id does not match.
        let conv_filter = query.conversation_filter.map(|c| c.to_string());
        let buckets: Vec<(String, String)> = buckets
            .into_iter()
            .filter(|(c, _)| conv_filter.as_deref().is_none_or(|cf| cf == c.as_str()))
            .collect();
        if buckets.is_empty() {
            return Ok(local);
        }

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
        // [`FuzzySearchEngine::search_fuzzy`] (Phase 5, Task 2).
        let mut q_by_script: HashMap<ScriptClass, HashSet<String>> = HashMap::new();
        for t in &q_tokens {
            q_by_script
                .entry(t.script)
                .or_default()
                .insert(t.token.clone());
        }
        let q_count_fuzzy: f64 = q_by_script.values().map(|s| s.len()).sum::<usize>() as f64;

        for (conv, bucket) in buckets {
            let fts_rows = cold_source.fetch_text_rows(&conv, &bucket)?;
            let fuzzy_rows = cold_source.fetch_fuzzy_rows(&conv, &bucket)?;

            // Build a metadata lookup so fuzzy-only hits can
            // synthesise a SearchResult without re-fetching
            // skeletons.
            let mut meta_by_id: HashMap<String, &FtsRow> = HashMap::new();
            for row in &fts_rows {
                meta_by_id.insert(row.message_id.clone(), row);
            }

            for row in &fts_rows {
                if !sender_filter_matches(query, &row.sender_id) {
                    continue;
                }
                if !date_filter_matches(query, row.created_at_ms) {
                    continue;
                }
                let lower = row.text_content.to_lowercase();
                let mut matched = 0usize;
                for w in &q_words {
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
                    &mut by_id,
                    &row.message_id,
                    &row.conversation_id,
                    &row.sender_id,
                    row.created_at_ms,
                    rank,
                );
            }

            if q_count_fuzzy > 0.0 {
                // counts[message_id][script] = matched (token,
                // script) pairs from this bucket's fuzzy shard.
                let mut counts: HashMap<String, HashMap<ScriptClass, u32>> = HashMap::new();
                for fr in &fuzzy_rows {
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
                    // Per-script gating mirrors
                    // FuzzySearchEngine::search_fuzzy: a row passes
                    // when at least one script's overlap fraction
                    // clears the per-script threshold. Total
                    // matched across all scripts feeds the rank.
                    let mut total_matched: u32 = 0;
                    let mut accepted = false;
                    for (script, q_set) in &q_by_script {
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
                        &mut by_id,
                        &mid,
                        &info.conversation_id,
                        &info.sender_id,
                        info.created_at_ms,
                        rank,
                    );
                }
            }
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

    /// Cold-path variant of [`Self::apply_recency_and_kind_weight`]
    /// that skips the `message_skeleton` lookup. Re-weights only
    /// the rows whose `message_id` is **not** in `local_ids` —
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
            // construction (Phase 5 only ships text + fuzzy cold
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
        let conn = self.db.connection();
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
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY created_at_ms DESC LIMIT ?");
        binds.push(Value::Integer(limit as i64));

        let conn = self.db.connection();
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
        let fts_engine = TextSearchEngine::new(self.db);
        let fuzzy_engine = FuzzySearchEngine::new(self.db);
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
            // FTS5's bm25() returns negative values — more negative is
            // more relevant. Flip the sign and weight per
            // `docs/PROPOSAL.md §7.5`.
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
                        // snippets — those come from FTS5's snippet().
                        snippet: None,
                        rank_score: f.score * FUZZY_WEIGHT,
                        is_cold: false,
                    },
                );
            }
            // If the skeleton lookup turned up nothing, the row was
            // tombstoned out from under us between the fuzzy index
            // and the skeleton table; drop it silently.
        }

        let mut out: Vec<SearchResult> = by_id.into_values().collect();

        // Apply the Phase 5, Task 3 ranking-formula extensions:
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
    /// factor and content-kind weight (Phase 5, Task 3 —
    /// `docs/PROPOSAL.md §7.5`).
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
        let conn = self.db.connection();
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
            let kind_w = kind_by_id
                .get(&r.message_id.to_string())
                .map(|k| match k.as_str() {
                    "text" => TEXT_KIND_WEIGHT,
                    "media" => MEDIA_KIND_WEIGHT,
                    _ => TEXT_KIND_WEIGHT,
                })
                // Default to text weight when the row is missing
                // from `message_skeleton` (cold-only rows can be
                // surfaced before the skeleton lands locally).
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

        let conn = self.db.connection();
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
        let conn = self.db.connection();
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
        // `media` skeleton kind in Phase 1. Phase 2 will refine
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
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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
        // Phase 1 invariant: LocalOnly returns purely local rows
        // (is_cold = false) without touching any archive code.
        let db = populated_db();
        let engine = QueryEngine::new(&db);
        let q = SearchQuery {
            query_string: "hello".into(),
            ..Default::default()
        };
        let results = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
        assert!(results.iter().all(|r| !r.is_cold));
    }

    #[test]
    fn search_include_cold_returns_local_for_now() {
        // Phase 1 invariant: IncludeCold is a forward-compat marker;
        // no archive fan-out lands until Phase 3 / Phase 5.
        let db = populated_db();
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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
        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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
    // Cold-bucket fan-out via ColdShardSource (Phase 5, Task 1)
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
        let engine = QueryEngine::new(&db);

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
        let engine = QueryEngine::new(&db);

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

        let engine = QueryEngine::new(&db);

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
        let engine = QueryEngine::new(&db);

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
        let engine = QueryEngine::new(&db);

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
    // (Phase 5, Task 3 — `docs/PROPOSAL.md §7.5`)
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

        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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

        let engine = QueryEngine::new(&db);
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
}
