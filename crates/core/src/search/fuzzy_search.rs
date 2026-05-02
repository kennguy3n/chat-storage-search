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
//! * [`FuzzySearchEngine`] — DB-backed wrapper that indexes / removes
//!   per-message tokens and runs a token-overlap search against the
//!   `search_fuzzy` table.
//!
//! Tokens are lowercased so the index is case-insensitive. Whitespace,
//! ASCII punctuation, and ASCII digits inside a script run are
//! treated as word separators — n-grams never straddle a separator.

use std::collections::{HashMap, HashSet};

use rusqlite::params;

use crate::local_store::db::{DbResult, LocalStoreDb};
use crate::search::tokenizer::{
    fuzzy_granularity, segment_by_script, FuzzyGranularity, ScriptClass,
};

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

/// DB-backed fuzzy index over the `search_fuzzy` table.
#[derive(Debug)]
pub struct FuzzySearchEngine<'a> {
    db: &'a LocalStoreDb,
}

impl<'a> FuzzySearchEngine<'a> {
    /// Construct a new engine bound to the given database.
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

    /// Run a fuzzy search against the indexed corpus. Returns the
    /// top `limit` matches in best-score-first order.
    ///
    /// The score is the fraction of distinct query tokens that the
    /// message's token set covers — a query of three trigrams that
    /// matches two of them on a row scores `0.6667`.
    pub fn search_fuzzy(&self, query: &str, limit: usize) -> DbResult<Vec<FuzzyMatch>> {
        let qtokens = FuzzyTokenizer::generate_tokens(query);
        if qtokens.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        // Distinct query tokens drive the scoring denominator; we
        // never reward a row twice for the same query token.
        let mut q_unique: HashSet<(String, ScriptClass)> = HashSet::new();
        for t in &qtokens {
            q_unique.insert((t.token.clone(), t.script));
        }
        let q_count = q_unique.len() as f64;

        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "SELECT message_id FROM search_fuzzy
              WHERE token = ?1 AND script = ?2",
        )?;
        let mut counts: HashMap<String, u32> = HashMap::new();
        for (token, script) in q_unique {
            let rows = stmt
                .query_map(params![token, script_iso_15924(script)], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for mid in rows {
                *counts.entry(mid).or_insert(0) += 1;
            }
        }
        let mut results: Vec<FuzzyMatch> = counts
            .into_iter()
            .map(|(message_id, c)| FuzzyMatch {
                message_id,
                score: f64::from(c) / q_count,
            })
            .collect();
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
// ISO-15924 mapping
// ---------------------------------------------------------------------------

/// Map a [`ScriptClass`] to the four-letter ISO-15924 code used as
/// the `search_fuzzy.script` text value. Mirrors the serde
/// `rename_all = "PascalCase"` shape on [`ScriptClass`] so writers
/// here and serde-readers elsewhere agree on the wire form.
fn script_iso_15924(script: ScriptClass) -> &'static str {
    match script {
        ScriptClass::Latn => "Latn",
        ScriptClass::Cyrl => "Cyrl",
        ScriptClass::Grek => "Grek",
        ScriptClass::Hani => "Hani",
        ScriptClass::Hira => "Hira",
        ScriptClass::Kana => "Kana",
        ScriptClass::Hang => "Hang",
        ScriptClass::Arab => "Arab",
        ScriptClass::Hebr => "Hebr",
        ScriptClass::Deva => "Deva",
        ScriptClass::Beng => "Beng",
        ScriptClass::Thai => "Thai",
        ScriptClass::Khmr => "Khmr",
        ScriptClass::Laoo => "Laoo",
        ScriptClass::Mymr => "Mymr",
        ScriptClass::Unknown => "Zzzz",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        let engine = FuzzySearchEngine::new(&db);
        engine.index_message("m1", "hello world").unwrap();
        engine.index_message("m2", "hippo").unwrap();
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
        let engine = FuzzySearchEngine::new(&db);
        engine.index_message("m1", "会議室で").unwrap();
        engine.index_message("m2", "東京駅").unwrap();
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
        let engine = FuzzySearchEngine::new(&db);
        engine.index_message("m1", "hello").unwrap();
        assert_eq!(engine.search_fuzzy("hello", 10).unwrap().len(), 1);
        engine.remove_message("m1").unwrap();
        assert_eq!(engine.search_fuzzy("hello", 10).unwrap().len(), 0);
        // Idempotent on a missing message.
        engine.remove_message("never-indexed").unwrap();
    }

    #[test]
    fn empty_query_returns_empty() {
        let db = fresh_db();
        let engine = FuzzySearchEngine::new(&db);
        engine.index_message("m1", "hello").unwrap();
        assert!(engine.search_fuzzy("", 10).unwrap().is_empty());
        assert!(engine.search_fuzzy("   ", 10).unwrap().is_empty());
    }

    #[test]
    fn index_message_is_idempotent() {
        let db = fresh_db();
        let engine = FuzzySearchEngine::new(&db);
        engine.index_message("m1", "hello").unwrap();
        // Re-indexing the same message must not double-count tokens.
        engine.index_message("m1", "hello").unwrap();
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
        let engine = FuzzySearchEngine::new(&db);
        engine.index_message("m1", "hello").unwrap();
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
}
