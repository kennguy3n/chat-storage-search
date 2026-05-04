//! Multilingual tokenization spec.
//!
//! `docs/PROPOSAL.md §3.3` and §3.4 lock the tokenization contract:
//!
//! * **Primary tokenizer.** SQLite FTS5 with `tokenize = 'icu'`. ICU
//!   performs script-aware word segmentation (CJK / Thai / Khmer /
//!   Lao / Myanmar have no whitespace word boundaries), NFKC
//!   normalization, case folding, and accent folding. ICU is statically
//!   linked so every Phase-1 build pays the binary-size cost in
//!   exchange for usable multilingual search.
//! * **Fallback tokenizer.** `tokenize = 'unicode61 remove_diacritics 2'`
//!   on platforms where ICU cannot be linked. The fallback is
//!   acceptable for Latin / Cyrillic / Greek input only — CJK / Thai /
//!   Khmer / Lao / Myanmar search becomes effectively unusable, so the
//!   fallback path is documented but never the default.
//! * **Fuzzy index.** Lives outside FTS5 (FTS5 has no edit-distance
//!   lookup). Trigram tokens for alphabetic / abugida / Hangul scripts;
//!   bigram tokens for logographic CJK (Han / Hiragana / Katakana). The
//!   per-row script tag drives query-side script-aware Levenshtein
//!   merging.
//!
//! This module is intentionally a **spec / glue layer** — the actual
//! ICU bindings land with the SQLCipher integration in Phase 1. What
//! this module provides today:
//!
//! * `TokenizerConfig`, `NormalizationMode`, `FallbackMode` — the
//!   knobs the Phase-1 integration will pass into ICU.
//! * `ScriptClass` — the ISO-15924 enumeration the fuzzy index tags
//!   each row with.
//! * `FuzzyGranularity` and `fuzzy_granularity` — the per-script
//!   trigram-vs-bigram decision.
//! * `fts5_tokenizer_config`, `fts5_tokenizer_config_for` — the
//!   `tokenize = '...'` literal that goes into the FTS5 `CREATE
//!   VIRTUAL TABLE` statement.
//! * `detect_script`, `segment_by_script` — pure-Rust helpers that
//!   split mixed-script text into per-script runs without depending on
//!   ICU. Same Unicode-range table the fuzzy indexer uses to tag rows.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FTS5 tokenizer literals
// ---------------------------------------------------------------------------

/// FTS5 `tokenize` clause for the primary (ICU) tokenizer.
pub const FTS5_TOKENIZE_ICU: &str = "tokenize = 'icu'";

/// FTS5 `tokenize` clause for the fallback (`unicode61`) tokenizer.
///
/// `remove_diacritics 2` is the most permissive of the three
/// `unicode61` settings — it removes diacritics for both ASCII Latin
/// and the Latin-1 / Extended-A / Extended-B blocks, matching what
/// users expect when typing accent-stripped Spanish, Portuguese,
/// Vietnamese, etc.
pub const FTS5_TOKENIZE_UNICODE61: &str = "tokenize = 'unicode61 remove_diacritics 2'";

/// Returns the FTS5 `tokenize = '...'` literal for the **primary**
/// tokenizer (ICU).
///
/// `docs/PROPOSAL.md §3.3` mandates ICU as the primary tokenizer. Use
/// [`fts5_tokenizer_config_for`] to select the fallback explicitly.
pub fn fts5_tokenizer_config() -> String {
    fts5_tokenizer_config_for(FallbackMode::Icu)
}

/// Returns the FTS5 `tokenize = '...'` literal for the requested mode.
///
/// `docs/PROPOSAL.md §3.3`:
/// * [`FallbackMode::Icu`] → `tokenize = 'icu'`
/// * [`FallbackMode::Unicode61`] → `tokenize = 'unicode61 remove_diacritics 2'`
pub fn fts5_tokenizer_config_for(mode: FallbackMode) -> String {
    match mode {
        FallbackMode::Icu => FTS5_TOKENIZE_ICU.to_string(),
        FallbackMode::Unicode61 => FTS5_TOKENIZE_UNICODE61.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Unicode normalization mode applied before tokenization.
///
/// `docs/PROPOSAL.md §3.3` requires NFKC normalization so that
/// compatibility-equivalent characters (e.g. half-width katakana
/// `ｱ` ⇔ `ア`, mathematical alphanumerics, ligatures) collapse into
/// a canonical form before tokens are emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationMode {
    /// NFKC — compatibility decomposition, then canonical composition.
    /// **Default and only supported mode in Phase 1.**
    Nfkc,
    /// No normalization. Available so test harnesses can isolate the
    /// tokenizer's behavior from the normalizer's.
    None,
}

/// Which FTS5 tokenizer is in use.
///
/// `docs/PROPOSAL.md §3.3` defines ICU as primary and `unicode61` as
/// the fallback for platforms where ICU cannot be linked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackMode {
    /// `tokenize = 'icu'`. The primary tokenizer.
    Icu,
    /// `tokenize = 'unicode61 remove_diacritics 2'`. The fallback,
    /// only acceptable when ICU is not available.
    Unicode61,
}

/// ICU tokenizer configuration knobs.
///
/// The Phase-1 SQLCipher integration projects this struct into the
/// FTS5 tokenizer's `tokenize = 'icu', ...` arguments and into the
/// non-FTS fuzzy / vector pipelines that share the same normalization
/// pre-pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenizerConfig {
    /// ICU locale identifier. `"und"` (BCP-47 "undetermined") is the
    /// default — multilingual content does not have a single locale,
    /// and ICU's word-break rules are script-aware regardless. Setting
    /// a specific locale (`"th-TH"`, `"ja-JP"`, …) only changes
    /// locale-specific tailoring (e.g. case-folding edge cases for
    /// Turkish dotted-I).
    pub locale: String,

    /// Unicode normalization mode applied before tokenization.
    pub normalization: NormalizationMode,

    /// Whether to apply Unicode case folding (`ABC` ⇔ `abc`,
    /// `İ` ⇔ `i̇`, …). Case-insensitive search requires this.
    pub case_fold: bool,

    /// Whether to fold combining diacritics (`café` ⇔ `cafe`,
    /// `naïve` ⇔ `naive`). Required for the Latin / Cyrillic / Greek
    /// fuzzy paths to behave consistently when users type
    /// accent-stripped queries.
    pub fold_accents: bool,

    /// Which FTS5 tokenizer this configuration targets. Phase 1
    /// always picks [`FallbackMode::Icu`]; the fallback is documented
    /// here so a Phase-1+ build that opts out of ICU has a
    /// well-defined config to point at.
    pub fallback: FallbackMode,
}

impl Default for TokenizerConfig {
    fn default() -> Self {
        Self {
            locale: "und".to_string(),
            normalization: NormalizationMode::Nfkc,
            case_fold: true,
            fold_accents: true,
            fallback: FallbackMode::Icu,
        }
    }
}

// ---------------------------------------------------------------------------
// Script classification
// ---------------------------------------------------------------------------

/// ISO-15924 script code (subset).
///
/// The variants here are exactly the scripts the multilingual fuzzy
/// index distinguishes. Adding more scripts is a forward-compatible
/// change because every fuzzy row carries the script tag as a column
/// (`docs/PROPOSAL.md §3.2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ScriptClass {
    /// Latin (Latn). Used for English, Spanish, Vietnamese,
    /// Indonesian, etc.
    Latn,
    /// Cyrillic (Cyrl). Russian, Ukrainian, Bulgarian, etc.
    Cyrl,
    /// Greek and Coptic (Grek).
    Grek,
    /// CJK Unified Ideographs (Hani). The shared Han ideographic block
    /// used by Chinese, Japanese (kanji), and Korean (hanja).
    Hani,
    /// Hiragana (Hira). Japanese phonetic syllabary.
    Hira,
    /// Katakana (Kana). Japanese phonetic syllabary.
    Kana,
    /// Hangul (Hang). Korean.
    Hang,
    /// Arabic (Arab). Arabic, Persian, Urdu, etc.
    Arab,
    /// Hebrew (Hebr).
    Hebr,
    /// Devanagari (Deva). Hindi, Marathi, Nepali, etc.
    Deva,
    /// Bengali (Beng). Bengali, Assamese.
    Beng,
    /// Thai (Thai).
    Thai,
    /// Khmer (Khmr).
    Khmr,
    /// Lao (Laoo).
    Laoo,
    /// Myanmar (Mymr). Burmese, Shan, etc.
    Mymr,
    /// Anything else — including ASCII whitespace, ASCII digits,
    /// punctuation, and codepoints outside the explicit blocks above.
    /// `segment_by_script` treats `Unknown` runs as "common" filler
    /// that attaches to a neighboring substantive run rather than
    /// becoming its own segment.
    Unknown,
}

impl ScriptClass {
    /// Map a [`ScriptClass`] to the four-letter ISO-15924 code used
    /// as the wire form on `search_fuzzy.script` and on the
    /// per-row tag inside encrypted fuzzy shards. The inverse is
    /// [`Self::from_iso_15924`].
    ///
    /// `docs/PROPOSAL.md §3.2`.
    #[must_use]
    pub fn to_iso_15924(self) -> &'static str {
        match self {
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

    /// Parse an ISO-15924 four-letter code back into a
    /// [`ScriptClass`]. Unknown codes (including the Zzzz "uncoded
    /// script" sentinel) collapse to [`ScriptClass::Unknown`].
    #[must_use]
    pub fn from_iso_15924(code: &str) -> ScriptClass {
        match code {
            "Latn" => ScriptClass::Latn,
            "Cyrl" => ScriptClass::Cyrl,
            "Grek" => ScriptClass::Grek,
            "Hani" => ScriptClass::Hani,
            "Hira" => ScriptClass::Hira,
            "Kana" => ScriptClass::Kana,
            "Hang" => ScriptClass::Hang,
            "Arab" => ScriptClass::Arab,
            "Hebr" => ScriptClass::Hebr,
            "Deva" => ScriptClass::Deva,
            "Beng" => ScriptClass::Beng,
            "Thai" => ScriptClass::Thai,
            "Khmr" => ScriptClass::Khmr,
            "Laoo" => ScriptClass::Laoo,
            "Mymr" => ScriptClass::Mymr,
            _ => ScriptClass::Unknown,
        }
    }
}

/// Granularity of fuzzy tokens for a script class.
///
/// `docs/PROPOSAL.md §3.4`:
///
/// * **Trigram** for scripts where words are typically ≥ 3 characters
///   (Latin, Cyrillic, Greek, Arabic, Hebrew, Devanagari, Bengali,
///   Hangul when treated graphemically, Thai / Khmer / Lao / Myanmar
///   abugidas).
/// * **Bigram** for logographic CJK runs (Han, Hiragana, Katakana),
///   where words are commonly 1–3 characters and trigrams are too
///   coarse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzyGranularity {
    /// 2-character n-grams.
    Bigram,
    /// 3-character n-grams.
    Trigram,
}

/// Minimum per-script fuzzy overlap fraction required for a row
/// to be accepted as a fuzzy match (Phase 5, Task 2).
///
/// `docs/PROPOSAL.md §3.4` makes the granularity decision purely
/// a function of the script — bigrams for logographic CJK,
/// trigrams elsewhere — but says nothing about thresholding. The
/// rationale for tighter CJK gating:
///
/// * A bigram is a stronger signal than a trigram (fewer rare
///   bigrams in CJK, so a single overlap is highly informative).
///   Loose thresholding would surface unrelated rows.
/// * A trigram in Latin / Cyrillic / ... is a weaker signal but a
///   typo of a common 5-7 character word still preserves several
///   trigrams; loose thresholding lets `meetng` find `meeting`.
///
/// Rationale for the specific numbers:
///
/// * Bigrams (CJK): require ≥ 0.5 of the per-script query bigrams.
///   A two-bigram CJK query needs at least one to match — otherwise
///   the row is dropped.
/// * Trigrams (Latin etc.): require ≥ 1/3 of the per-script query
///   trigrams. A 7-trigram word like "lighthouse" with two
///   transposed trigrams (≈ 5 / 7 ≈ 0.71) clears the bar; an
///   accidental 1 / 7 hit on a junk row does not.
#[must_use]
pub fn fuzzy_min_overlap(script: ScriptClass) -> f64 {
    match fuzzy_granularity(script) {
        FuzzyGranularity::Bigram => 0.5,
        FuzzyGranularity::Trigram => 1.0 / 3.0,
    }
}

/// Map a [`ScriptClass`] to its [`FuzzyGranularity`] per
/// `docs/PROPOSAL.md §3.4`.
///
/// The decision is purely a function of the script — it does not
/// depend on the user's query, the current locale, or the FTS5
/// fallback mode. The same mapping is used at index-build time
/// (which n-grams to emit per row) and at query time (which n-grams
/// to look up).
pub fn fuzzy_granularity(script: ScriptClass) -> FuzzyGranularity {
    match script {
        // Logographic CJK — short words, trigrams are too coarse.
        ScriptClass::Hani | ScriptClass::Hira | ScriptClass::Kana => FuzzyGranularity::Bigram,
        // Everything else: alphabetic, abugida, Hangul (graphemic),
        // and the catch-all `Unknown` fall back to trigrams.
        ScriptClass::Latn
        | ScriptClass::Cyrl
        | ScriptClass::Grek
        | ScriptClass::Hang
        | ScriptClass::Arab
        | ScriptClass::Hebr
        | ScriptClass::Deva
        | ScriptClass::Beng
        | ScriptClass::Thai
        | ScriptClass::Khmr
        | ScriptClass::Laoo
        | ScriptClass::Mymr
        | ScriptClass::Unknown => FuzzyGranularity::Trigram,
    }
}

/// Classify a single Unicode codepoint into a [`ScriptClass`].
///
/// Uses Unicode block ranges (not the full ICU script-property
/// database). The Phase-1 fuzzy indexer that ships with ICU bindings
/// will additionally consult ICU's per-codepoint script property to
/// catch the long tail (e.g. CJK extensions G–H, supplementary
/// historical blocks); the table here intentionally covers only the
/// blocks that matter for the `docs/PROPOSAL.md §3.4` fuzzy split.
pub fn detect_script(c: char) -> ScriptClass {
    let cp = c as u32;
    match cp {
        // Latin — Basic Latin letters, Latin-1 Supplement, Latin
        // Extended-A / B, Latin Extended Additional.
        0x0041..=0x005A | 0x0061..=0x007A => ScriptClass::Latn,
        0x00C0..=0x024F => ScriptClass::Latn,
        0x1E00..=0x1EFF => ScriptClass::Latn,

        // Greek and Coptic + Greek Extended.
        0x0370..=0x03FF => ScriptClass::Grek,
        0x1F00..=0x1FFF => ScriptClass::Grek,

        // Cyrillic + Cyrillic Supplement + Cyrillic Extended-A / B.
        0x0400..=0x052F => ScriptClass::Cyrl,
        0x2DE0..=0x2DFF => ScriptClass::Cyrl,
        0xA640..=0xA69F => ScriptClass::Cyrl,

        // Hebrew + Alphabetic Presentation Forms (Hebrew subset).
        0x0590..=0x05FF => ScriptClass::Hebr,
        0xFB1D..=0xFB4F => ScriptClass::Hebr,

        // Arabic + Arabic Supplement + Arabic Extended-A + Presentation
        // Forms-A / B.
        0x0600..=0x06FF => ScriptClass::Arab,
        0x0750..=0x077F => ScriptClass::Arab,
        0x08A0..=0x08FF => ScriptClass::Arab,
        0xFB50..=0xFDFF => ScriptClass::Arab,
        0xFE70..=0xFEFF => ScriptClass::Arab,

        // Devanagari.
        0x0900..=0x097F => ScriptClass::Deva,

        // Bengali.
        0x0980..=0x09FF => ScriptClass::Beng,

        // Thai.
        0x0E00..=0x0E7F => ScriptClass::Thai,

        // Lao.
        0x0E80..=0x0EFF => ScriptClass::Laoo,

        // Myanmar.
        0x1000..=0x109F => ScriptClass::Mymr,

        // Khmer.
        0x1780..=0x17FF => ScriptClass::Khmr,

        // Hiragana.
        0x3040..=0x309F => ScriptClass::Hira,

        // Katakana + Katakana Phonetic Extensions.
        0x30A0..=0x30FF => ScriptClass::Kana,
        0x31F0..=0x31FF => ScriptClass::Kana,

        // Hangul Jamo + Hangul Compatibility Jamo + Hangul Jamo
        // Extended-A + Hangul Syllables.
        0x1100..=0x11FF => ScriptClass::Hang,
        0x3130..=0x318F => ScriptClass::Hang,
        0xA960..=0xA97F => ScriptClass::Hang,
        0xAC00..=0xD7AF => ScriptClass::Hang,

        // CJK Unified Ideographs (BMP + extensions A, B, C–F).
        0x3400..=0x4DBF => ScriptClass::Hani,
        0x4E00..=0x9FFF => ScriptClass::Hani,
        0x20000..=0x2A6DF => ScriptClass::Hani,
        0x2A700..=0x2EBEF => ScriptClass::Hani,

        _ => ScriptClass::Unknown,
    }
}

/// Split mixed-script text into per-script runs.
///
/// Each substantive script transition starts a new run. ASCII
/// whitespace, digits, punctuation, and other [`ScriptClass::Unknown`]
/// codepoints are treated as "common" filler — they attach to the
/// current run rather than producing their own [`ScriptClass::Unknown`]
/// segments. Trailing common filler attaches to the last run; if the
/// input is entirely common, a single [`ScriptClass::Unknown`] run is
/// returned.
///
/// Example: `"Meeting at 3pm 会議室で"` becomes
/// `[(Latn, "Meeting at 3pm "), (Hani, "会議室"), (Hira, "で")]`.
pub fn segment_by_script(text: &str) -> Vec<(ScriptClass, String)> {
    let mut runs: Vec<(ScriptClass, String)> = Vec::new();
    let mut pending_common = String::new();

    for c in text.chars() {
        let cls = detect_script(c);
        if cls == ScriptClass::Unknown {
            pending_common.push(c);
            continue;
        }
        match runs.last_mut() {
            Some(last) if last.0 == cls => {
                last.1.push_str(&pending_common);
                last.1.push(c);
                pending_common.clear();
            }
            Some(last) => {
                // Script transition: pending common (whitespace,
                // punctuation, digits) attaches to the **outgoing**
                // run, not the new one. This keeps the space after
                // a Latin word inside the Latin run rather than
                // letting it float to the start of the next-script
                // run.
                last.1.push_str(&pending_common);
                pending_common.clear();
                let mut s = String::with_capacity(c.len_utf8());
                s.push(c);
                runs.push((cls, s));
            }
            None => {
                // No prior run — common filler before the first
                // substantive char becomes part of that first run.
                let mut s = String::with_capacity(pending_common.len() + c.len_utf8());
                s.push_str(&pending_common);
                s.push(c);
                pending_common.clear();
                runs.push((cls, s));
            }
        }
    }

    if !pending_common.is_empty() {
        if let Some(last) = runs.last_mut() {
            last.1.push_str(&pending_common);
        } else {
            runs.push((ScriptClass::Unknown, pending_common));
        }
    }

    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- detect_script -----------------------------------------------------

    #[test]
    fn detect_script_latin_letters() {
        for c in ['A', 'Z', 'a', 'z', 'M', 'q'] {
            assert_eq!(detect_script(c), ScriptClass::Latn, "{c}");
        }
    }

    #[test]
    fn detect_script_latin_extended() {
        // Vietnamese diacritics, Spanish ñ, French ç, German ß.
        for c in ['ñ', 'ç', 'ß', 'ế', 'ơ'] {
            assert_eq!(detect_script(c), ScriptClass::Latn, "{c}");
        }
    }

    #[test]
    fn detect_script_cjk() {
        assert_eq!(detect_script('中'), ScriptClass::Hani);
        assert_eq!(detect_script('文'), ScriptClass::Hani);
        assert_eq!(detect_script('会'), ScriptClass::Hani);
        assert_eq!(detect_script('議'), ScriptClass::Hani);
        assert_eq!(detect_script('室'), ScriptClass::Hani);
    }

    #[test]
    fn detect_script_hiragana_katakana_distinct() {
        assert_eq!(detect_script('あ'), ScriptClass::Hira);
        assert_eq!(detect_script('で'), ScriptClass::Hira);
        assert_eq!(detect_script('ア'), ScriptClass::Kana);
        assert_eq!(detect_script('カ'), ScriptClass::Kana);
    }

    #[test]
    fn detect_script_hangul() {
        assert_eq!(detect_script('한'), ScriptClass::Hang);
        assert_eq!(detect_script('국'), ScriptClass::Hang);
        // Hangul Jamo
        assert_eq!(detect_script('ᄀ'), ScriptClass::Hang);
        // Hangul Compatibility Jamo
        assert_eq!(detect_script('ㄱ'), ScriptClass::Hang);
    }

    #[test]
    fn detect_script_arabic() {
        for c in ['ا', 'ب', 'م', 'ر'] {
            assert_eq!(detect_script(c), ScriptClass::Arab, "{c}");
        }
    }

    #[test]
    fn detect_script_hebrew() {
        for c in ['א', 'ב', 'ש', 'ת'] {
            assert_eq!(detect_script(c), ScriptClass::Hebr, "{c}");
        }
    }

    #[test]
    fn detect_script_cyrillic() {
        for c in ['А', 'Я', 'а', 'я', 'Ж', 'ё'] {
            assert_eq!(detect_script(c), ScriptClass::Cyrl, "{c}");
        }
    }

    #[test]
    fn detect_script_greek() {
        for c in ['Α', 'Ω', 'α', 'ω', 'π'] {
            assert_eq!(detect_script(c), ScriptClass::Grek, "{c}");
        }
    }

    #[test]
    fn detect_script_thai_lao_khmer_myanmar() {
        assert_eq!(detect_script('ก'), ScriptClass::Thai);
        assert_eq!(detect_script('ฯ'), ScriptClass::Thai);
        assert_eq!(detect_script('ກ'), ScriptClass::Laoo);
        assert_eq!(detect_script('က'), ScriptClass::Mymr);
        assert_eq!(detect_script('ក'), ScriptClass::Khmr);
    }

    #[test]
    fn detect_script_devanagari_bengali() {
        assert_eq!(detect_script('अ'), ScriptClass::Deva);
        assert_eq!(detect_script('क'), ScriptClass::Deva);
        assert_eq!(detect_script('অ'), ScriptClass::Beng);
        assert_eq!(detect_script('ক'), ScriptClass::Beng);
    }

    #[test]
    fn detect_script_unknown_for_common_chars() {
        // ASCII whitespace, digits, punctuation are Common — bucketed
        // into Unknown so segment_by_script can fold them into the
        // current run.
        for c in [' ', '\t', '\n', '0', '9', '!', '?', '.', ','] {
            assert_eq!(detect_script(c), ScriptClass::Unknown, "{c:?}");
        }
        // Emoji and other unassigned-to-script characters.
        assert_eq!(detect_script('😀'), ScriptClass::Unknown);
    }

    // --- segment_by_script -------------------------------------------------

    #[test]
    fn segment_by_script_pure_latin() {
        let runs = segment_by_script("Hello world");
        assert_eq!(runs, vec![(ScriptClass::Latn, "Hello world".to_string())]);
    }

    #[test]
    fn segment_by_script_pure_cjk() {
        let runs = segment_by_script("会議室");
        assert_eq!(runs, vec![(ScriptClass::Hani, "会議室".to_string())]);
    }

    #[test]
    fn segment_by_script_mixed_latin_cjk_hira() {
        // The canonical PROPOSAL.md §3.3 example.
        let runs = segment_by_script("Meeting at 3pm 会議室で");
        assert_eq!(
            runs,
            vec![
                (ScriptClass::Latn, "Meeting at 3pm ".to_string()),
                (ScriptClass::Hani, "会議室".to_string()),
                (ScriptClass::Hira, "で".to_string()),
            ]
        );
    }

    #[test]
    fn segment_by_script_arabic_then_latin() {
        let runs = segment_by_script("مرحبا hello");
        assert_eq!(
            runs,
            vec![
                (ScriptClass::Arab, "مرحبا ".to_string()),
                (ScriptClass::Latn, "hello".to_string()),
            ]
        );
    }

    #[test]
    fn segment_by_script_cyrillic_and_latin() {
        let runs = segment_by_script("Привет world!");
        assert_eq!(
            runs,
            vec![
                (ScriptClass::Cyrl, "Привет ".to_string()),
                (ScriptClass::Latn, "world!".to_string()),
            ]
        );
    }

    #[test]
    fn segment_by_script_hangul_alone() {
        let runs = segment_by_script("안녕하세요");
        assert_eq!(runs, vec![(ScriptClass::Hang, "안녕하세요".to_string())]);
    }

    #[test]
    fn segment_by_script_thai_then_devanagari() {
        let runs = segment_by_script("สวัสดี नमस्ते");
        assert_eq!(
            runs,
            vec![
                (ScriptClass::Thai, "สวัสดี ".to_string()),
                (ScriptClass::Deva, "नमस्ते".to_string()),
            ]
        );
    }

    #[test]
    fn segment_by_script_only_common_returns_unknown_run() {
        let runs = segment_by_script("   123 !!! 😀");
        assert_eq!(
            runs,
            vec![(ScriptClass::Unknown, "   123 !!! 😀".to_string())]
        );
    }

    #[test]
    fn segment_by_script_empty_returns_empty() {
        assert_eq!(segment_by_script(""), Vec::<(ScriptClass, String)>::new());
    }

    #[test]
    fn segment_by_script_runs_total_back_to_input() {
        // Whatever the run boundaries, concatenating the run strings
        // must reproduce the input — segment_by_script never drops
        // codepoints.
        for input in [
            "Meeting at 3pm 会議室で",
            "Привет world! 你好",
            "café ☕ नमस्ते",
            "한국어 + English + 中文",
        ] {
            let runs = segment_by_script(input);
            let joined: String = runs.iter().map(|(_, s)| s.as_str()).collect();
            assert_eq!(joined, input, "round trip failed for {input:?}");
        }
    }

    // --- fuzzy_granularity --------------------------------------------------

    #[test]
    fn fuzzy_granularity_logographic_cjk_is_bigram() {
        for s in [ScriptClass::Hani, ScriptClass::Hira, ScriptClass::Kana] {
            assert_eq!(fuzzy_granularity(s), FuzzyGranularity::Bigram, "{s:?}");
        }
    }

    #[test]
    fn fuzzy_granularity_alphabetic_is_trigram() {
        for s in [
            ScriptClass::Latn,
            ScriptClass::Cyrl,
            ScriptClass::Grek,
            ScriptClass::Arab,
            ScriptClass::Hebr,
            ScriptClass::Deva,
            ScriptClass::Beng,
            ScriptClass::Thai,
            ScriptClass::Khmr,
            ScriptClass::Laoo,
            ScriptClass::Mymr,
        ] {
            assert_eq!(fuzzy_granularity(s), FuzzyGranularity::Trigram, "{s:?}");
        }
    }

    #[test]
    fn fuzzy_granularity_hangul_is_trigram() {
        // PROPOSAL.md §3.4: Hangul "when treated graphemically".
        assert_eq!(
            fuzzy_granularity(ScriptClass::Hang),
            FuzzyGranularity::Trigram
        );
    }

    #[test]
    fn fuzzy_granularity_unknown_falls_back_to_trigram() {
        assert_eq!(
            fuzzy_granularity(ScriptClass::Unknown),
            FuzzyGranularity::Trigram
        );
    }

    // --- FTS5 config strings -----------------------------------------------

    #[test]
    fn fts5_tokenizer_config_is_icu_by_default() {
        assert_eq!(fts5_tokenizer_config(), "tokenize = 'icu'");
    }

    #[test]
    fn fts5_tokenizer_config_for_icu() {
        assert_eq!(
            fts5_tokenizer_config_for(FallbackMode::Icu),
            "tokenize = 'icu'"
        );
    }

    #[test]
    fn fts5_tokenizer_config_for_unicode61() {
        assert_eq!(
            fts5_tokenizer_config_for(FallbackMode::Unicode61),
            "tokenize = 'unicode61 remove_diacritics 2'"
        );
    }

    // --- TokenizerConfig ----------------------------------------------------

    #[test]
    fn tokenizer_config_default_is_multilingual_safe() {
        let c = TokenizerConfig::default();
        assert_eq!(c.locale, "und");
        assert_eq!(c.normalization, NormalizationMode::Nfkc);
        assert!(c.case_fold);
        assert!(c.fold_accents);
        assert_eq!(c.fallback, FallbackMode::Icu);
    }

    #[test]
    fn tokenizer_config_round_trips_through_serde_json() {
        let c = TokenizerConfig {
            locale: "ja-JP".to_string(),
            normalization: NormalizationMode::Nfkc,
            case_fold: true,
            fold_accents: false,
            fallback: FallbackMode::Unicode61,
        };
        let s = serde_json::to_string(&c).expect("serialize");
        let back: TokenizerConfig = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(c, back);
    }

    #[test]
    fn fallback_mode_round_trips_through_serde_json() {
        for m in [FallbackMode::Icu, FallbackMode::Unicode61] {
            let s = serde_json::to_string(&m).expect("serialize");
            let back: FallbackMode = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(m, back);
        }
    }

    #[test]
    fn script_class_round_trips_through_serde_json() {
        let all = [
            ScriptClass::Latn,
            ScriptClass::Cyrl,
            ScriptClass::Grek,
            ScriptClass::Hani,
            ScriptClass::Hira,
            ScriptClass::Kana,
            ScriptClass::Hang,
            ScriptClass::Arab,
            ScriptClass::Hebr,
            ScriptClass::Deva,
            ScriptClass::Beng,
            ScriptClass::Thai,
            ScriptClass::Khmr,
            ScriptClass::Laoo,
            ScriptClass::Mymr,
            ScriptClass::Unknown,
        ];
        for s in all {
            let json = serde_json::to_string(&s).expect("serialize");
            let back: ScriptClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(s, back, "round trip: {s:?}");
        }
    }
}
