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
//! priority `SearchResultTap` (Phase 5, Task 7). The actual
//! archive fan-out (downloading the offloaded body before the
//! query returns) still lands in a follow-up — `is_cold = true`
//! is the wire signal that the body is *available* in the
//! archive but not currently in the local store.
//! [`SearchScope::LocalOnly`] always returns `is_cold = false`,
//! preserving the offline-only contract.

use std::collections::{HashMap, HashSet};

use rusqlite::{params_from_iter, types::Value};
use uuid::Uuid;

use crate::local_store::db::{DbResult, LocalStoreDb};
use crate::search::fuzzy_search::FuzzySearchEngine;
use crate::search::text_search::TextSearchEngine;
use crate::{ContentKind, SearchQuery, SearchResult, SearchScope};

/// BM25 contribution weight in the merged rank score
/// (`docs/PROPOSAL.md §7.5`).
const BM25_WEIGHT: f64 = 2.0;

/// Fuzzy-token-overlap contribution weight in the merged rank score
/// (`docs/PROPOSAL.md §7.5`).
const FUZZY_WEIGHT: f64 = 1.0;

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
}
