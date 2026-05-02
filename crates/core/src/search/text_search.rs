//! FTS5 text search engine.
//!
//! `docs/PROPOSAL.md §3.3` mandates SQLite FTS5 with the
//! [`tokenize = 'icu'`](crate::search::tokenizer::FTS5_TOKENIZE_ICU)
//! tokenizer for multilingual full-text search; the schema bring-up
//! in [`crate::local_store::db`] falls back to
//! [`tokenize = 'unicode61 remove_diacritics 2'`](crate::search::tokenizer::FTS5_TOKENIZE_UNICODE61)
//! when the SQLCipher build does not link against ICU.
//!
//! This module wraps the FTS5 virtual table behind a small typed
//! API:
//!
//! * [`FtsMatch`] — one match row with snippet + BM25 score.
//! * [`TextSearchEngine`] — borrows a [`LocalStoreDb`] and runs
//!   [`bm25`-ordered](https://www.sqlite.org/fts5.html#the_bm25_function)
//!   queries against `search_fts`.
//! * Query-parsing helpers that escape FTS5 syntax for free-text
//!   queries while preserving explicit operators (`NEAR`, `*`,
//!   `"phrase"`).

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::local_store::db::{DbError, DbResult, LocalStoreDb};
use crate::search::tokenizer::{FallbackMode, FTS5_TOKENIZE_ICU, FTS5_TOKENIZE_UNICODE61};

// ---------------------------------------------------------------------------
// FtsMatch
// ---------------------------------------------------------------------------

/// One row returned from the FTS5 search engine.
///
/// `bm25_score` is the raw `bm25(search_fts)` output: more negative
/// is **more relevant** (FTS5 returns negative values; the unified
/// search engine in `query_engine.rs` flips the sign so callers see
/// "higher = better").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FtsMatch {
    /// Stable message identifier (string form of the UUID v7).
    pub message_id: String,
    /// Owning conversation.
    pub conversation_id: String,
    /// Sender identifier.
    pub sender_id: String,
    /// Wall-clock millisecond timestamp set by the sender.
    pub created_at_ms: i64,
    /// Highlighted snippet around the match (FTS5 `snippet()`).
    pub snippet: String,
    /// Raw `bm25(search_fts)` score. Lower (more negative) is more
    /// relevant.
    pub bm25_score: f64,
}

// ---------------------------------------------------------------------------
// Schema fallback
// ---------------------------------------------------------------------------

/// Returns the FTS5 `tokenize = '...'` clause that matches the
/// schema this connection was created with.
///
/// `docs/PROPOSAL.md §3.3`: see [`FallbackMode`] and the constants
/// [`FTS5_TOKENIZE_ICU`] / [`FTS5_TOKENIZE_UNICODE61`].
pub fn schema_fallback_mode(db: &LocalStoreDb) -> FallbackMode {
    if db.icu_available() {
        FallbackMode::Icu
    } else {
        FallbackMode::Unicode61
    }
}

// ---------------------------------------------------------------------------
// TextSearchEngine
// ---------------------------------------------------------------------------

/// FTS5 search engine over the `search_fts` virtual table.
#[derive(Debug)]
pub struct TextSearchEngine<'a> {
    db: &'a LocalStoreDb,
}

impl<'a> TextSearchEngine<'a> {
    /// Construct a new engine bound to the given database.
    pub fn new(db: &'a LocalStoreDb) -> Self {
        Self { db }
    }

    /// Returns the [`FallbackMode`] this engine is operating in.
    pub fn tokenizer_mode(&self) -> FallbackMode {
        schema_fallback_mode(self.db)
    }

    /// Run an FTS5 search, returning at most `limit` matches in
    /// best-rank-first order.
    ///
    /// `query` is interpreted as user free-text:
    ///
    /// * Empty / whitespace-only input returns an empty result set
    ///   without touching the database (an empty FTS5 `MATCH`
    ///   expression is a syntax error otherwise).
    /// * Quoted phrases (`"hello world"`) are passed through.
    /// * Trailing `*` keeps prefix-search semantics.
    /// * Bare special characters are escaped so a stray `:` or `^`
    ///   in a paste does not blow up the FTS5 query parser.
    pub fn search_fts(&self, query: &str, limit: usize) -> DbResult<Vec<FtsMatch>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        let fts_expr = build_fts_query(trimmed);
        if fts_expr.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT message_id, conversation_id, sender_id, created_at_ms,
                    snippet(search_fts, 4, '<b>', '</b>', '...', 32) AS snippet,
                    bm25(search_fts) AS rank
             FROM search_fts
             WHERE search_fts MATCH ?1
             ORDER BY rank
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![fts_expr, limit as i64], |row| {
                Ok(FtsMatch {
                    message_id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    sender_id: row.get(2)?,
                    created_at_ms: row.get(3)?,
                    snippet: row.get(4)?,
                    bm25_score: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Look up a single FTS row by `message_id`. Useful for joining
    /// FTS hits with the structured search results in the unified
    /// query engine.
    pub fn lookup_fts_text(&self, message_id: &str) -> DbResult<Option<String>> {
        self.db
            .connection()
            .query_row(
                "SELECT text_content FROM search_fts WHERE message_id = ?1",
                params![message_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(DbError::from)
    }
}

// ---------------------------------------------------------------------------
// Query parsing
// ---------------------------------------------------------------------------

/// Convert a user-typed query into an FTS5 `MATCH` expression.
///
/// FTS5 parses syntactic operators (`AND`, `OR`, `NOT`, `NEAR`,
/// `"phrase"`, `*`, `:`, `^`, `-`) directly. Free-text input is
/// quoted token-by-token so the user does not accidentally invoke
/// those operators with stray punctuation, while explicit operators
/// (a leading `"` or a trailing `*`) are preserved.
pub fn build_fts_query(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Pass quoted phrases through verbatim — the user has already
    // told FTS5 what to do.
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        return trimmed.to_string();
    }
    let mut tokens = Vec::new();
    for raw in trimmed.split_whitespace() {
        let token = raw;
        // Preserve trailing `*` (prefix search). Quote only the
        // alphabetic stem so `"hello"*` still works.
        if let Some(stem) = token.strip_suffix('*') {
            if stem.is_empty() {
                continue;
            }
            tokens.push(format!("\"{}\"*", escape_fts_quote(stem)));
        } else if token == "AND" || token == "OR" || token == "NOT" || token == "NEAR" {
            tokens.push(token.to_string());
        } else {
            tokens.push(format!("\"{}\"", escape_fts_quote(token)));
        }
    }
    tokens.join(" ")
}

/// Escape any `"` inside an FTS5 quoted phrase. FTS5 supports doubled
/// `""` as a single literal `"`.
fn escape_fts_quote(s: &str) -> String {
    s.replace('"', "\"\"")
}

/// Returns the `tokenize = '...'` literal expected for the supplied
/// fallback mode. Mirrors the constants in
/// [`crate::search::tokenizer`] but accepts a dynamic value — useful
/// when the choice of mode is made at runtime by a probe instead of
/// statically by the schema.
pub fn tokenize_clause(mode: FallbackMode) -> &'static str {
    match mode {
        FallbackMode::Icu => FTS5_TOKENIZE_ICU,
        FallbackMode::Unicode61 => FTS5_TOKENIZE_UNICODE61,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0xAB; 32]).unwrap()
    }

    /// Insert a synthetic conversation + skeleton + body + FTS row.
    fn insert_fixture(db: &LocalStoreDb, idx: u32, text: &str) -> String {
        let mid = format!("msg-{idx:04}");
        let cid = format!("conv-{idx:04}");
        let sid = format!("user-{:02}", idx % 3);
        let ts = 1_700_000_000_000_i64 + idx as i64 * 1000;
        let conn = db.connection();
        conn.execute(
            "INSERT INTO conversation (
                conversation_id, title_cipher, pinned, muted,
                last_message_id, last_activity_ms
             ) VALUES (?1, NULL, 0, 0, NULL, ?2)",
            params![cid, ts],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_skeleton (
                message_id, conversation_id, sender_id, created_at_ms,
                received_at_ms, kind, body_state
             ) VALUES (?1, ?2, ?3, ?4, ?4, 'text', 'local_plain_available')",
            params![mid, cid, sid, ts],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_body (message_id, text_content)
             VALUES (?1, ?2)",
            params![mid, text],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO search_fts(
                message_id, conversation_id, sender_id, created_at_ms, text_content
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![mid, cid, sid, ts, text],
        )
        .unwrap();
        mid
    }

    #[test]
    fn build_fts_query_handles_empty_and_whitespace() {
        assert_eq!(build_fts_query(""), "");
        assert_eq!(build_fts_query("   \n\t  "), "");
    }

    #[test]
    fn build_fts_query_quotes_bare_tokens() {
        assert_eq!(build_fts_query("hello"), "\"hello\"");
        assert_eq!(build_fts_query("hello world"), "\"hello\" \"world\"");
    }

    #[test]
    fn build_fts_query_preserves_explicit_phrase() {
        assert_eq!(build_fts_query("\"hello world\""), "\"hello world\"");
    }

    #[test]
    fn build_fts_query_preserves_prefix_star() {
        assert_eq!(build_fts_query("hello*"), "\"hello\"*");
        assert_eq!(build_fts_query("hello* world"), "\"hello\"* \"world\"");
    }

    #[test]
    fn build_fts_query_preserves_explicit_operators() {
        let q = build_fts_query("hello AND world");
        assert!(q.contains("AND"), "operator AND should pass through: {q}");
    }

    #[test]
    fn build_fts_query_escapes_embedded_quote() {
        let q = build_fts_query("say\"hi");
        // The single embedded quote must be doubled.
        assert!(q.contains("\"\""), "quote must be doubled: {q}");
    }

    #[test]
    fn search_fts_returns_empty_for_empty_query() {
        let db = test_db();
        let engine = TextSearchEngine::new(&db);
        assert!(engine.search_fts("", 10).unwrap().is_empty());
        assert!(engine.search_fts("   ", 10).unwrap().is_empty());
    }

    #[test]
    fn search_fts_returns_match_in_bm25_order() {
        let db = test_db();
        // Five fixtures with varying overlap with the query.
        insert_fixture(&db, 1, "alpha bravo");
        insert_fixture(&db, 2, "alpha alpha alpha bravo");
        insert_fixture(&db, 3, "charlie delta");
        insert_fixture(&db, 4, "alpha");
        insert_fixture(&db, 5, "alpha bravo charlie");

        let engine = TextSearchEngine::new(&db);
        let hits = engine.search_fts("alpha", 10).unwrap();
        assert!(!hits.is_empty(), "must return at least one hit");
        // The top hit should be a row that contains "alpha" most
        // densely. Fixture 2 is "alpha alpha alpha bravo".
        assert_eq!(hits[0].message_id, "msg-0002");
        // BM25 returns negative values; lower = better. The list
        // must be sorted ascending.
        for w in hits.windows(2) {
            assert!(w[0].bm25_score <= w[1].bm25_score);
        }
        // The "charlie delta" fixture must not appear.
        assert!(hits.iter().all(|h| h.message_id != "msg-0003"));
    }

    #[test]
    fn search_fts_supports_prefix_query() {
        let db = test_db();
        insert_fixture(&db, 1, "hello there");
        insert_fixture(&db, 2, "helmets save lives");
        insert_fixture(&db, 3, "world peace");

        let engine = TextSearchEngine::new(&db);
        let hits = engine.search_fts("hel*", 10).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.as_str()).collect();
        assert!(ids.contains(&"msg-0001"));
        assert!(ids.contains(&"msg-0002"));
        assert!(!ids.contains(&"msg-0003"));
    }

    #[test]
    fn search_fts_returns_snippet() {
        let db = test_db();
        insert_fixture(&db, 1, "the quick brown fox jumps over the lazy dog");
        let engine = TextSearchEngine::new(&db);
        let hits = engine.search_fts("brown", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(
            hits[0].snippet.contains("<b>brown</b>"),
            "snippet={}",
            hits[0].snippet
        );
    }

    #[test]
    fn search_fts_handles_special_characters() {
        let db = test_db();
        insert_fixture(&db, 1, "user@example.com sent a note");
        insert_fixture(&db, 2, "no email here");

        let engine = TextSearchEngine::new(&db);
        // A bare "@" used to be a query-parser error; build_fts_query
        // wraps the token in quotes so the search still runs.
        let hits = engine.search_fts("user@example.com", 10).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.as_str()).collect();
        assert!(ids.contains(&"msg-0001"));
    }

    #[test]
    fn search_fts_respects_limit() {
        let db = test_db();
        for i in 1..=5 {
            insert_fixture(&db, i, "hit hit hit");
        }
        let engine = TextSearchEngine::new(&db);
        let hits = engine.search_fts("hit", 3).unwrap();
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn tokenize_clause_returns_expected_strings() {
        assert_eq!(tokenize_clause(FallbackMode::Icu), FTS5_TOKENIZE_ICU);
        assert_eq!(
            tokenize_clause(FallbackMode::Unicode61),
            FTS5_TOKENIZE_UNICODE61
        );
    }

    #[test]
    fn tokenizer_mode_matches_db_state() {
        let db = test_db();
        let engine = TextSearchEngine::new(&db);
        // Whatever the build supports — ICU on a build that links
        // it, Unicode61 otherwise — the engine and the db agree.
        let mode = engine.tokenizer_mode();
        assert_eq!(
            mode == FallbackMode::Icu,
            db.icu_available(),
            "engine and db must agree on tokenizer mode"
        );
    }
}
