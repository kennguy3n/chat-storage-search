//! FTS5 text search engine.
//!
//! `docs/DESIGN.md §3.3` mandates SQLite FTS5 with the
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
//! * [`TextSearchEngine`] — borrows a raw [`rusqlite::Connection`]
//!   and runs
//!   [`bm25`-ordered](https://www.sqlite.org/fts5.html#the_bm25_function)
//!   queries against `search_fts`. Taking a `&Connection` (rather
//!   than a `&LocalStoreDb`) lets the engine run against either the
//!   writer's connection or a
//!   [`crate::local_store::db::LocalStoreReader`] checked out of the
//!   pool — the FTS query path is pure-SELECT, so reader-pool
//!   service is the common case.
//! * Query-parsing helpers that escape FTS5 syntax for free-text
//!   queries while preserving explicit operators (`NEAR`, `*`,
//!   `"phrase"`).

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::local_store::db::{DbError, DbResult};
use crate::search::tokenizer::{FallbackMode, FTS5_TOKENIZE_ICU, FTS5_TOKENIZE_UNICODE61};
use rusqlite::Connection;

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
    /// Highlighted snippet around the match (FTS5 `snippet`).
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
/// `docs/DESIGN.md §3.3`: see [`FallbackMode`] and the constants
/// [`FTS5_TOKENIZE_ICU`] / [`FTS5_TOKENIZE_UNICODE61`].
pub fn fallback_mode_for(icu_available: bool) -> FallbackMode {
    if icu_available {
        FallbackMode::Icu
    } else {
        FallbackMode::Unicode61
    }
}

// ---------------------------------------------------------------------------
// TextSearchEngine
// ---------------------------------------------------------------------------

/// FTS5 search engine over the `search_fts` virtual table.
///
/// Borrows a raw [`Connection`] (rather than a `LocalStoreDb`) so
/// both the writer's own connection and a read-only connection
/// from [`crate::local_store::db::LocalStoreReaderPool`] can
/// drive the FTS5 search path uniformly. The
/// `icu_available` flag is plumbed in explicitly because it is a
/// schema-time property of the database the connection is open
/// against — see
/// [`crate::local_store::db::LocalStoreReader::icu_available`].
#[derive(Debug)]
pub struct TextSearchEngine<'a> {
    conn: &'a Connection,
    icu_available: bool,
}

impl<'a> TextSearchEngine<'a> {
    /// Construct a new engine bound to the given connection.
    ///
    /// `icu_available` selects the FTS5 query path: the ICU
    /// tokenizer when `true`, the `unicode61` fallback when
    /// `false`. In production this is always sourced from
    /// `LocalStoreDb::icu_available` (writer) or
    /// `LocalStoreReader::icu_available` (pool reader).
    pub fn new(conn: &'a Connection, icu_available: bool) -> Self {
        Self {
            conn,
            icu_available,
        }
    }

    /// Returns the [`FallbackMode`] this engine is operating in.
    pub fn tokenizer_mode(&self) -> FallbackMode {
        fallback_mode_for(self.icu_available)
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

        let mut stmt = self.conn.prepare(
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
        self.conn
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
    // First pass: classify each whitespace-separated token as a
    // (potential) operator vs. a positive term. We hold back the
    // string form until the second pass so we can demote orphan
    // operators that aren't flanked by terms.
    let raw_tokens: Vec<RawFtsToken> = trimmed
        .split_whitespace()
        .filter_map(|raw| {
            if let Some(stem) = raw.strip_suffix('*') {
                if stem.is_empty() {
                    None
                } else {
                    Some(RawFtsToken::Term(format!(
                        "\"{}\"*",
                        escape_fts_quote(stem)
                    )))
                }
            } else if matches!(raw, "AND" | "OR" | "NOT" | "NEAR") {
                Some(RawFtsToken::Operator(raw.to_string()))
            } else {
                Some(RawFtsToken::Term(format!("\"{}\"", escape_fts_quote(raw))))
            }
        })
        .collect();

    // Second pass: an operator keyword only stays a syntactic
    // operator when both of its neighbors are positive terms. Bare
    // `NOT`, leading `AND hello`, trailing `hello AND`, and adjacent
    // `AND OR` all collapse to literal terms — `"hello AND world"`
    // still binds via the explicit `AND`. This keeps `sqlite3_prepare`
    // from bouncing the query on otherwise-reasonable user input.
    let mut tokens = Vec::with_capacity(raw_tokens.len());
    for (idx, tok) in raw_tokens.iter().enumerate() {
        match tok {
            RawFtsToken::Term(s) => tokens.push(s.clone()),
            RawFtsToken::Operator(op) => {
                let prev_is_term = idx
                    .checked_sub(1)
                    .and_then(|i| raw_tokens.get(i))
                    .map(|t| matches!(t, RawFtsToken::Term(_)))
                    .unwrap_or(false);
                let next_is_term = raw_tokens
                    .get(idx + 1)
                    .map(|t| matches!(t, RawFtsToken::Term(_)))
                    .unwrap_or(false);
                if prev_is_term && next_is_term {
                    tokens.push(op.clone());
                } else {
                    tokens.push(format!("\"{}\"", escape_fts_quote(op)));
                }
            }
        }
    }
    tokens.join(" ")
}

/// Internal classification used by [`build_fts_query`] to decide
/// whether each whitespace-separated input chunk is a positive term
/// or a (provisional) FTS5 binary operator.
#[derive(Debug)]
enum RawFtsToken {
    /// A token that should always appear as-is in the final
    /// expression — already quoted / star-suffixed.
    Term(String),
    /// One of `AND` / `OR` / `NOT` / `NEAR`. Whether it stays a
    /// syntactic operator depends on its neighbors.
    Operator(String),
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
    use crate::local_store::db::LocalStoreDb;

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

    /// Reflects the FTS5 grammar: `AND` / `OR` / `NOT` / `NEAR` are
    /// only valid as binary infix between two positive terms. When
    /// the user types one as a free-text token (bare `NOT`, leading
    /// `AND hello`, trailing `hello AND`, adjacent `AND OR`,
    /// autocorrected `Not available`, …) it must be demoted to a
    /// literal term — otherwise `sqlite3_prepare_v2` rejects the
    /// expression with a syntax error and bubbles a `DbError` up to
    /// the caller.
    #[test]
    fn build_fts_query_demotes_orphan_operators() {
        assert_eq!(build_fts_query("NOT"), "\"NOT\"");
        assert_eq!(build_fts_query("AND"), "\"AND\"");
        assert_eq!(build_fts_query("NEAR"), "\"NEAR\"");
        assert_eq!(build_fts_query("NOT available"), "\"NOT\" \"available\"");
        assert_eq!(build_fts_query("hello AND"), "\"hello\" \"AND\"");
        assert_eq!(build_fts_query("AND hello"), "\"AND\" \"hello\"");
        assert_eq!(build_fts_query("AND OR"), "\"AND\" \"OR\"");
        assert_eq!(
            build_fts_query("hello AND OR world"),
            "\"hello\" \"AND\" \"OR\" \"world\""
        );
        // Sanity: a real binary infix still binds.
        assert_eq!(
            build_fts_query("hello AND world"),
            "\"hello\" AND \"world\""
        );
    }

    /// Every input from `build_fts_query_demotes_orphan_operators`
    /// must round-trip through `sqlite3_prepare_v2` cleanly when
    /// fed to FTS5 — otherwise we just regressed to the original
    /// bug. We exercise a few representative cases against a real
    /// FTS5 table here.
    #[test]
    fn search_fts_accepts_demoted_operators_without_error() {
        let db = test_db();
        insert_fixture(&db, 1, "available now");
        insert_fixture(&db, 2, "hello world");
        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
        for input in ["NOT", "AND", "NEAR", "NOT available", "hello AND", "AND OR"] {
            let r = engine.search_fts(input, 10);
            assert!(
                r.is_ok(),
                "{input:?} should be a valid FTS expression now: {r:?}"
            );
        }
    }

    #[test]
    fn search_fts_returns_empty_for_empty_query() {
        let db = test_db();
        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
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

        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
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

        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
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
        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
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

        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
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
        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
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
        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
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
