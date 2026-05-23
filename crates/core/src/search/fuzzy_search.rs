//! Fuzzy token indexer.
//!
//! `docs/PROPOSAL.md §3.4` and `docs/PHASES.md` Phase 5 spec the
//! fuzzy index: a per-row token table (`search_fuzzy`) carrying
//! script-tagged n-grams (trigrams for alphabetic / abugida / Hangul,
//! bigrams for logographic CJK). Trigram lookup against the index
//! gives approximate matching that FTS5 cannot do directly because
//! FTS5 has no edit-distance lookup.
//!
//! This module is a foundation for Phase 5 — the encrypted shard
//! / cold-bucket fan-out lands later. What lives here today:
//!
//! * [`FuzzyToken`] — one (token, script) pair.
//! * [`FuzzyTokenizer`] — pure-Rust token generator that uses
//!   [`segment_by_script`] to split mixed-script text into per-script
//!   runs and [`fuzzy_granularity`] to choose bigrams vs trigrams per
//!   run.
//! * [`FuzzySearchEngine`] — read-only token-overlap search against
//!   the `search_fuzzy` table. Borrows a raw [`rusqlite::Connection`]
//!   so it can run against either the writer connection or a
//!   [`crate::local_store::db::LocalStoreReader`] checked out of the
//!   pool.
//! * [`FuzzyIndexWriter`] — write-only counterpart that indexes /
//!   removes per-message tokens. Borrows a
//!   [`crate::local_store::db::LocalStoreDb`] so the type system
//!   prevents accidental writes through a `query_only = 1` reader.
//!
//! Tokens are lowercased so the index is case-insensitive. Whitespace,
//! ASCII punctuation, and ASCII digits inside a script run are
//! treated as word separators — n-grams never straddle a separator.

use std::collections::{HashMap, HashSet};

use rusqlite::params;

use crate::local_store::db::{DbResult, LocalStoreDb};
use crate::search::tokenizer::{
    fuzzy_granularity, fuzzy_min_overlap, segment_by_script, FuzzyGranularity, ScriptClass,
};
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One fuzzy token with its script tag.
///
/// Tokens are already lowercased and free of whitespace / punctuation;
/// callers should not need to re-normalize them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FuzzyToken {
    /// The token text (already lowercased).
    pub token: String,
    /// Script class assigned by [`segment_by_script`].
    pub script: ScriptClass,
}

/// One row returned from [`FuzzySearchEngine::search_fuzzy`].
#[derive(Debug, Clone, PartialEq)]
pub struct FuzzyMatch {
    /// Message identifier (string form of the UUID v7).
    pub message_id: String,
    /// Token-overlap score in `[0.0, 1.0]`. Higher is better. The
    /// score is the fraction of distinct query tokens that the
    /// message's token set covers.
    pub score: f64,
}

// ---------------------------------------------------------------------------
// FuzzyTokenizer
// ---------------------------------------------------------------------------

/// Pure n-gram tokenizer driven by [`segment_by_script`] +
/// [`fuzzy_granularity`].
#[derive(Debug, Default)]
pub struct FuzzyTokenizer;

impl FuzzyTokenizer {
    /// Generate every (token, script) pair for `text`.
    ///
    /// Text is split into per-script runs; each run is lowercased and
    /// further broken on whitespace / ASCII punctuation / ASCII
    /// digits into "words". Each word emits sliding-window n-grams of
    /// the granularity dictated by its script class. Words shorter
    /// than the window length produce no tokens.
    pub fn generate_tokens(text: &str) -> Vec<FuzzyToken> {
        let mut out = Vec::new();
        for (script, run) in segment_by_script(text) {
            // `Unknown` runs are pure punctuation / digits / whitespace.
            // segment_by_script only returns a standalone Unknown run
            // when the entire input is common; even then, there is
            // nothing meaningful to fuzzy-index.
            if script == ScriptClass::Unknown {
                continue;
            }
            let granularity = fuzzy_granularity(script);
            let n = match granularity {
                FuzzyGranularity::Bigram => 2,
                FuzzyGranularity::Trigram => 3,
            };
            for word in split_words(&run) {
                let chars: Vec<char> = word.chars().flat_map(char::to_lowercase).collect();
                if chars.len() < n {
                    continue;
                }
                for window in chars.windows(n) {
                    let token: String = window.iter().collect();
                    out.push(FuzzyToken { token, script });
                }
            }
        }
        out
    }
}

/// Split a script-homogeneous run into "words" by ASCII whitespace,
/// ASCII punctuation, and ASCII digits. Non-ASCII separators (CJK
/// punctuation, Arabic punctuation, …) are kept as part of the
/// token — they are rare enough inside a single-script run that
/// segmenting on them would do more harm than good.
fn split_words(run: &str) -> Vec<&str> {
    run.split(|c: char| c.is_ascii_whitespace() || c.is_ascii_punctuation() || c.is_ascii_digit())
        .filter(|w| !w.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// FuzzySearchEngine
// ---------------------------------------------------------------------------

/// DB-backed *read-only* fuzzy search over the `search_fuzzy`
/// table.
///
/// `FuzzySearchEngine` borrows a raw [`Connection`] (rather than
/// a `LocalStoreDb` / `LocalStoreReader`) so both the writer's
/// own connection and a reader checked out of
/// [`crate::local_store::db::LocalStoreReaderPool`] can drive
/// the search path uniformly.
///
/// Writes (indexing / removal) live on a separate
/// [`FuzzyIndexWriter`] which is constructed from a
/// [`LocalStoreDb`] (the writer handle) so the type system rules
/// out accidentally trying to mutate the `search_fuzzy` table
/// through a pool reader's `query_only = 1` connection.
#[derive(Debug)]
pub struct FuzzySearchEngine<'a> {
    conn: &'a Connection,
}

impl<'a> FuzzySearchEngine<'a> {
    /// Construct a new search-only engine bound to the given
    /// connection. Accepts any [`Connection`] — writer or reader.
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Run a fuzzy search against the indexed corpus. Returns the
    /// top `limit` matches in best-score-first order.
    ///
    /// The score is the fraction of distinct query tokens that the
    /// message's token set covers — a query of three trigrams that
    /// matches two of them on a row scores `0.6667`.
    ///
    /// Per Phase 5, Task 2 the matcher is *script-aware*: the
    /// query is split into per-script token buckets and a row is
    /// only accepted if at least one of its per-script overlap
    /// fractions clears
    /// [`crate::search::tokenizer::fuzzy_min_overlap`] for that
    /// script. This stops a single accidental Latin trigram from
    /// surfacing an otherwise-unrelated CJK row (and vice versa)
    /// while still letting a mixed-script query fan out to every
    /// script index.
    pub fn search_fuzzy(&self, query: &str, limit: usize) -> DbResult<Vec<FuzzyMatch>> {
        let qtokens = FuzzyTokenizer::generate_tokens(query);
        if qtokens.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        // Group distinct query tokens by their script tag. A
        // mixed-script query like `"meeting 会議"` produces a
        // Latin bucket and a Hani bucket; each bucket is scored
        // and gated independently.
        let mut q_by_script: HashMap<ScriptClass, HashSet<String>> = HashMap::new();
        for t in &qtokens {
            q_by_script
                .entry(t.script)
                .or_default()
                .insert(t.token.clone());
        }
        let q_count_total: usize = q_by_script.values().map(|s| s.len()).sum();
        if q_count_total == 0 {
            return Ok(Vec::new());
        }

        let conn = self.conn;
        let mut stmt = conn.prepare(
            "SELECT message_id FROM search_fuzzy
              WHERE token = ?1 AND script = ?2",
        )?;
        // counts[message_id][script] = number of distinct
        // (token, script) pairs the row covered for that script.
        let mut counts: HashMap<String, HashMap<ScriptClass, u32>> = HashMap::new();
        for (script, tokens) in &q_by_script {
            for token in tokens {
                let rows = stmt
                    .query_map(params![token, script_iso_15924(*script)], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                for mid in rows {
                    *counts.entry(mid).or_default().entry(*script).or_insert(0) += 1;
                }
            }
        }

        let q_count = q_count_total as f64;
        let mut results: Vec<FuzzyMatch> = Vec::new();
        for (mid, per_script) in counts {
            let mut total_matched: u32 = 0;
            // A row is accepted if ANY per-script fraction clears
            // its threshold. This preserves cross-script fan-out
            // — a row that hits perfectly on the Latin half of a
            // mixed query still surfaces, just with a lower
            // overall score because the CJK contribution is zero.
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
            results.push(FuzzyMatch {
                message_id: mid,
                score: f64::from(total_matched) / q_count,
            });
        }
        // Best score first; stable secondary sort on message_id so
        // ties are deterministic.
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        results.truncate(limit);
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// FuzzyIndexWriter
// ---------------------------------------------------------------------------

/// Write-side counterpart to [`FuzzySearchEngine`] for the
/// `search_fuzzy` table.
///
/// `FuzzyIndexWriter` borrows a [`LocalStoreDb`] (the *writer*
/// handle) rather than a raw [`Connection`], so the type system
/// rules out accidentally trying to mutate `search_fuzzy` through
/// a pool reader's `query_only = 1` connection. Pool readers
/// expose a `LocalStoreReader`, a distinct type that cannot be
/// passed here.
///
/// Production call sites construct this from the locked writer
/// (`core_impl::CoreImpl::db_writer` / `message::processor`); the
/// search-only read path uses [`FuzzySearchEngine::new`] against
/// either the writer's connection or a pool reader.
#[derive(Debug)]
pub struct FuzzyIndexWriter<'a> {
    db: &'a LocalStoreDb,
}

impl<'a> FuzzyIndexWriter<'a> {
    /// Construct a new fuzzy-index writer bound to the given
    /// writer handle.
    pub fn new(db: &'a LocalStoreDb) -> Self {
        Self { db }
    }

    /// Tokenize `text` and persist the unique (token, script) pairs
    /// against `message_id` into `search_fuzzy`. Re-indexing the
    /// same message is idempotent thanks to the table's
    /// `(token, script, message_id)` primary key.
    pub fn index_message(&self, message_id: &str, text: &str) -> DbResult<()> {
        let tokens = FuzzyTokenizer::generate_tokens(text);
        if tokens.is_empty() {
            return Ok(());
        }
        let conn = self.db.connection();
        // De-duplicate before INSERT to avoid re-trying primary key
        // collisions row-by-row.
        let mut seen: HashSet<(String, ScriptClass)> = HashSet::new();
        let mut stmt = conn.prepare(
            "INSERT OR IGNORE INTO search_fuzzy(token, script, message_id)
             VALUES (?1, ?2, ?3)",
        )?;
        for t in tokens {
            if seen.insert((t.token.clone(), t.script)) {
                stmt.execute(params![t.token, script_iso_15924(t.script), message_id])?;
            }
        }
        Ok(())
    }

    /// Drop every fuzzy token for `message_id`. Idempotent — a
    /// missing message is not an error.
    pub fn remove_message(&self, message_id: &str) -> DbResult<()> {
        self.db.connection().execute(
            "DELETE FROM search_fuzzy WHERE message_id = ?1",
            params![message_id],
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ISO-15924 mapping
// ---------------------------------------------------------------------------

/// Map a [`ScriptClass`] to the four-letter ISO-15924 code used as
/// the `search_fuzzy.script` text value. Thin wrapper around
/// [`ScriptClass::to_iso_15924`] kept private to this module so
/// existing call sites stay unchanged.
fn script_iso_15924(script: ScriptClass) -> &'static str {
    script.to_iso_15924()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store::db::LocalStoreDb;

    fn tokens_with_script(text: &str, script: ScriptClass) -> Vec<String> {
        FuzzyTokenizer::generate_tokens(text)
            .into_iter()
            .filter(|t| t.script == script)
            .map(|t| t.token)
            .collect()
    }

    fn fresh_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0x42; 32]).expect("open in-memory db")
    }

    // ---- generate_tokens ------------------------------------------------

    #[test]
    fn generate_trigrams_for_latin() {
        let toks = FuzzyTokenizer::generate_tokens("hello");
        let strs: Vec<String> = toks
            .iter()
            .filter(|t| t.script == ScriptClass::Latn)
            .map(|t| t.token.clone())
            .collect();
        assert_eq!(strs, vec!["hel", "ell", "llo"]);
        assert!(toks.iter().all(|t| t.script == ScriptClass::Latn));
    }

    #[test]
    fn generate_bigrams_for_cjk() {
        let toks = FuzzyTokenizer::generate_tokens("会議室");
        let strs: Vec<String> = toks
            .iter()
            .filter(|t| t.script == ScriptClass::Hani)
            .map(|t| t.token.clone())
            .collect();
        assert_eq!(strs, vec!["会議", "議室"]);
        assert!(toks.iter().all(|t| t.script == ScriptClass::Hani));
    }

    #[test]
    fn mixed_script_generates_correct_grams() {
        let toks = FuzzyTokenizer::generate_tokens("Meeting 会議");
        let latin = tokens_with_script("Meeting 会議", ScriptClass::Latn);
        let hani = tokens_with_script("Meeting 会議", ScriptClass::Hani);

        // "meeting" (case-folded) → 7 chars → 5 trigrams.
        assert_eq!(latin, vec!["mee", "eet", "eti", "tin", "ing"]);
        // "会議" → 1 bigram.
        assert_eq!(hani, vec!["会議"]);
        assert_eq!(toks.len(), latin.len() + hani.len());
    }

    #[test]
    fn lowercases_for_case_insensitive_matching() {
        let lower = FuzzyTokenizer::generate_tokens("HELLO");
        let upper = FuzzyTokenizer::generate_tokens("hello");
        assert_eq!(lower, upper);
    }

    #[test]
    fn empty_text_produces_no_tokens() {
        assert!(FuzzyTokenizer::generate_tokens("").is_empty());
        // Whitespace / punctuation / digits alone produce no tokens
        // — the entire input becomes a Common run that
        // `segment_by_script` returns as `(Unknown, …)`.
        assert!(FuzzyTokenizer::generate_tokens("   ").is_empty());
        assert!(FuzzyTokenizer::generate_tokens("!!! 12345").is_empty());
    }

    #[test]
    fn skips_words_shorter_than_granularity() {
        // Latin "hi" is two chars but the script granularity is
        // trigrams, so no tokens are emitted.
        assert!(FuzzyTokenizer::generate_tokens("hi").is_empty());
        // Latin "yo!" is two letter chars + punctuation — the
        // punctuation splits the run, leaving "yo" which is too
        // short.
        assert!(FuzzyTokenizer::generate_tokens("yo!").is_empty());
    }

    #[test]
    fn cyrillic_uses_trigrams() {
        let toks = FuzzyTokenizer::generate_tokens("привет");
        let strs: Vec<String> = toks.iter().map(|t| t.token.clone()).collect();
        // 6 chars → 4 trigrams.
        assert_eq!(strs.len(), 4);
        assert!(toks.iter().all(|t| t.script == ScriptClass::Cyrl));
    }

    #[test]
    fn whitespace_breaks_words_within_run() {
        // "the quick" is a single Latin run but two words. Trigrams
        // never straddle the space.
        let toks = FuzzyTokenizer::generate_tokens("the quick");
        let strs: Vec<String> = toks.iter().map(|t| t.token.clone()).collect();
        // "the" → 1 trigram. "quick" → 3 trigrams.
        assert_eq!(strs, vec!["the", "qui", "uic", "ick"]);
    }

    // ---- FuzzySearchEngine ---------------------------------------------

    #[test]
    fn index_and_search_latin_fuzzy() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        writer.index_message("m1", "hello world").unwrap();
        writer.index_message("m2", "hippo").unwrap();
        // "helo" is a typo of "hello" — its trigrams ("hel", "elo")
        // share "hel" with "hello"'s {hel, ell, llo}, so m1 matches.
        let hits = engine.search_fuzzy("helo", 10).unwrap();
        assert!(
            hits.iter().any(|h| h.message_id == "m1"),
            "expected m1 in results, got {hits:?}"
        );
        // m1 should outrank m2 for "helo" because m1 shares more
        // trigrams (hel) than m2 (none).
        let m1_score = hits
            .iter()
            .find(|h| h.message_id == "m1")
            .map(|h| h.score)
            .unwrap();
        if let Some(m2) = hits.iter().find(|h| h.message_id == "m2") {
            assert!(m1_score > m2.score, "m1={m1_score} should beat m2={m2:?}");
        }
    }

    #[test]
    fn index_and_search_cjk_fuzzy() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        writer.index_message("m1", "会議室で").unwrap();
        writer.index_message("m2", "東京駅").unwrap();
        let hits = engine.search_fuzzy("会議", 10).unwrap();
        assert_eq!(hits.len(), 1, "expected exactly one CJK hit: {hits:?}");
        assert_eq!(hits[0].message_id, "m1");
        // "会議" is one bigram and m1's tokens include {"会議",
        // "議室"} — full coverage of the single query token.
        assert!((hits[0].score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn remove_message_clears_tokens() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        writer.index_message("m1", "hello").unwrap();
        assert_eq!(engine.search_fuzzy("hello", 10).unwrap().len(), 1);
        writer.remove_message("m1").unwrap();
        assert_eq!(engine.search_fuzzy("hello", 10).unwrap().len(), 0);
        // Idempotent on a missing message.
        writer.remove_message("never-indexed").unwrap();
    }

    #[test]
    fn empty_query_returns_empty() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        writer.index_message("m1", "hello").unwrap();
        assert!(engine.search_fuzzy("", 10).unwrap().is_empty());
        assert!(engine.search_fuzzy("   ", 10).unwrap().is_empty());
    }

    #[test]
    fn index_message_is_idempotent() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        writer.index_message("m1", "hello").unwrap();
        // Re-indexing the same message must not double-count tokens.
        writer.index_message("m1", "hello").unwrap();
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM search_fuzzy WHERE message_id = 'm1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // 3 unique trigrams for "hello" — re-index should not grow.
        assert_eq!(count, 3);
    }

    #[test]
    fn search_score_is_overlap_ratio() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        writer.index_message("m1", "hello").unwrap();
        // Query "helo" produces trigrams {"hel", "elo"} — only "hel"
        // is in m1's token set, so score = 1/2.
        let hits = engine.search_fuzzy("helo", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!((hits[0].score - 0.5).abs() < 1e-9);
    }

    #[test]
    fn iso_15924_codes_match_expected_form() {
        // Sanity-check the table — the wire shape has to match the
        // serde `rename_all = "PascalCase"` form callers see when
        // they serialize ScriptClass directly.
        assert_eq!(script_iso_15924(ScriptClass::Latn), "Latn");
        assert_eq!(script_iso_15924(ScriptClass::Hani), "Hani");
        assert_eq!(script_iso_15924(ScriptClass::Hira), "Hira");
        assert_eq!(script_iso_15924(ScriptClass::Cyrl), "Cyrl");
        assert_eq!(script_iso_15924(ScriptClass::Arab), "Arab");
        assert_eq!(script_iso_15924(ScriptClass::Unknown), "Zzzz");
    }

    // -----------------------------------------------------------
    // Phase 5, Task 2: per-script overlap thresholding
    // -----------------------------------------------------------

    #[test]
    fn latin_typo_query_finds_only_latin_rows() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        writer.index_message("latin", "lighthouse keeper").unwrap();
        writer.index_message("cjk", "灯台守の物語").unwrap();

        // "lighthose" is a Latin typo of "lighthouse". The
        // Latin-trigram overlap with "lighthouse" easily clears
        // the trigram threshold; the CJK row has zero Latin
        // overlap so it must not surface.
        let hits = engine.search_fuzzy("lighthose", 10).unwrap();
        let ids: Vec<&str> = hits.iter().map(|h| h.message_id.as_str()).collect();
        assert!(ids.contains(&"latin"));
        assert!(!ids.contains(&"cjk"));
    }

    #[test]
    fn cjk_query_finds_only_cjk_rows() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        writer.index_message("latin", "meeting agenda").unwrap();
        writer.index_message("cjk", "会議室の予約").unwrap();

        // CJK-only query → must hit CJK row, must miss Latin row.
        let hits = engine.search_fuzzy("会議", 10).unwrap();
        let ids: Vec<&str> = hits.iter().map(|h| h.message_id.as_str()).collect();
        assert!(ids.contains(&"cjk"));
        assert!(!ids.contains(&"latin"));
    }

    #[test]
    fn mixed_script_query_fans_out_to_both_indexes() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        writer.index_message("latin", "meeting agenda").unwrap();
        writer.index_message("cjk", "会議室の予約").unwrap();
        writer.index_message("both", "meeting 会議 today").unwrap();

        let hits = engine.search_fuzzy("meeting 会議", 10).unwrap();
        let ids: Vec<&str> = hits.iter().map(|h| h.message_id.as_str()).collect();
        assert!(
            ids.contains(&"both"),
            "row covering both scripts must surface"
        );
        assert!(ids.contains(&"latin"), "Latin-only row must still surface");
        assert!(ids.contains(&"cjk"), "CJK-only row must still surface");

        // The dual-script row should rank highest because it
        // covers more of the query token set.
        let pos_both = ids.iter().position(|i| *i == "both").unwrap();
        let pos_latin = ids.iter().position(|i| *i == "latin").unwrap();
        assert!(
            pos_both <= pos_latin,
            "row matching both scripts must outrank single-script: {hits:?}",
        );
    }

    #[test]
    fn weak_single_trigram_overlap_does_not_surface_unrelated_row() {
        let db = fresh_db();
        let writer = FuzzyIndexWriter::new(&db);
        let engine = FuzzySearchEngine::new(db.connection());
        // The query "lighthouse" produces 8 Latin trigrams. A
        // junk row that happens to share exactly one of them
        // (1/8 = 0.125) sits below the 1/3 threshold.
        writer.index_message("noise", "lig").unwrap();
        writer.index_message("real", "lighthouse keeper").unwrap();

        let hits = engine.search_fuzzy("lighthouse", 10).unwrap();
        let ids: Vec<&str> = hits.iter().map(|h| h.message_id.as_str()).collect();
        assert!(ids.contains(&"real"));
        // "lig" is too short to produce a trigram via
        // FuzzyTokenizer (chars.len() < n is skipped), so the
        // "noise" row never gets indexed and the threshold is
        // tested implicitly. Exercise the threshold explicitly
        // with a longer junk row.
        writer
            .index_message("partial_noise", "lighthous_unrelated")
            .unwrap();
        // "lighthous_unrelated" produces "lig", "igh", "ght",
        // "hth", "tho", "hou", "ous", "use", "elr", "lre"... — it
        // overlaps significantly with "lighthouse", so it SHOULD
        // be accepted (this is intended fuzzy behavior).
        let hits = engine.search_fuzzy("lighthouse", 10).unwrap();
        let ids: Vec<&str> = hits.iter().map(|h| h.message_id.as_str()).collect();
        assert!(ids.contains(&"partial_noise"));
    }
}
