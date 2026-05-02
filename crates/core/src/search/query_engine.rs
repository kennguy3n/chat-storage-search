//! Unified query engine combining FTS5 with structured filters.
//!
//! `docs/PROPOSAL.md §12` defines the [`SearchQuery`] /
//! [`SearchScope`] / [`SearchResult`] surface. Phase 1 lands the
//! local-store half: the engine reads from `search_fts` for free-text
//! queries, applies the structured filters (sender / conversation /
//! date range / content kind) as SQL `WHERE` clauses against
//! `message_skeleton`, and merges the two using a JOIN keyed on
//! `message_id`.
//!
//! When the query string is empty the engine returns skeleton rows
//! ordered by recency. When it is non-empty the engine intersects
//! the FTS5 hits with the structured filters and returns the union
//! ordered by BM25 (highest-relevance first).
//!
//! [`SearchScope::IncludeCold`] is treated identically to
//! [`SearchScope::LocalOnly`] for now — the personal-archive fan-out
//! lands later in Phase 3 / Phase 5. Both scopes return only local
//! rows in Phase 1, with `is_cold = false`.

use std::collections::HashSet;

use rusqlite::{params_from_iter, types::Value};
use uuid::Uuid;

use crate::local_store::db::{DbResult, LocalStoreDb};
use crate::search::text_search::TextSearchEngine;
use crate::{ContentKind, SearchQuery, SearchResult, SearchScope};

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
        _scope: &SearchScope,
        limit: usize,
    ) -> DbResult<Vec<SearchResult>> {
        // SearchScope::IncludeCold is documented as the default but
        // the cold (archive) fan-out lands in Phase 3 / Phase 5; for
        // Phase 1 the only difference is that LocalOnly explicitly
        // forbids any future archive call. Both scopes return local
        // rows here, with `is_cold = false`.

        let trimmed = query.query_string.trim();
        if trimmed.is_empty() {
            self.execute_structured_only(query, limit)
        } else {
            self.execute_fts_with_filters(query, trimmed, limit)
        }
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
    // FTS + structured-filters path
    // ----------------------------------------------------------------

    fn execute_fts_with_filters(
        &self,
        query: &SearchQuery,
        query_string: &str,
        limit: usize,
    ) -> DbResult<Vec<SearchResult>> {
        let fts_engine = TextSearchEngine::new(self.db);
        // Pull a generous over-fetch so post-filtering still has
        // enough rows to satisfy `limit`. 4× is a heuristic; the
        // structured-only path applies a hard ceiling.
        let fetch = limit.saturating_mul(4).max(limit);
        let hits = fts_engine.search_fts(query_string, fetch)?;
        if hits.is_empty() {
            return Ok(Vec::new());
        }

        // Apply the structured filters by `message_id` set
        // intersection.
        let allowed_ids = self.allowed_skeleton_ids(query, &hits)?;

        let mut out = Vec::with_capacity(limit.min(hits.len()));
        for h in hits {
            if let Some(allow) = &allowed_ids {
                if !allow.contains(&h.message_id) {
                    continue;
                }
            }
            let mid_uuid = Uuid::parse_str(&h.message_id).unwrap_or(Uuid::nil());
            let cid_uuid = Uuid::parse_str(&h.conversation_id).unwrap_or(Uuid::nil());
            // FTS5's bm25() returns negative values — more negative is
            // more relevant. Flip the sign so the public surface
            // says "higher = better".
            out.push(SearchResult {
                message_id: mid_uuid,
                conversation_id: cid_uuid,
                sender_id: h.sender_id,
                created_at_ms: h.created_at_ms,
                snippet: Some(h.snippet),
                rank_score: -h.bm25_score,
                is_cold: false,
            });
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Run the structured filter query and return the set of
    /// `message_id`s allowed by the filters. `None` means "no
    /// structured filters applied — every row is allowed".
    fn allowed_skeleton_ids(
        &self,
        query: &SearchQuery,
        candidates: &[crate::search::text_search::FtsMatch],
    ) -> DbResult<Option<HashSet<String>>> {
        let mut clauses: Vec<String> = Vec::new();
        let mut binds: Vec<Value> = Vec::new();
        push_structured_filters(query, &mut clauses, &mut binds);
        if clauses.is_empty() {
            return Ok(None);
        }

        // Restrict the structured query to the FTS candidate set so
        // we never scan the full skeleton table.
        let placeholders = (0..candidates.len())
            .map(|i| format!("?{}", binds.len() + i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        for h in candidates {
            binds.push(Value::Text(h.message_id.clone()));
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
}
