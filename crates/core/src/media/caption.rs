//! Multilingual caption / filename / MIME-type handling.
//!
//! `docs/DESIGN.md §3.4` (multilingual tokenization) and
//! `docs/DESIGN.md §8.2` (size-class padding) make it explicit
//! that KChat cannot ASCII-fold or English-bias any user-controlled
//! string that crosses the wire. Captions, filenames, and MIME
//! types all flow through media descriptors / `media_search_index`
//! / archive segments and end up in script-aware FTS5 / fuzzy
//! indices, so they must round-trip *every* script unchanged.
//!
//! This module lands the on-ingress normalization that the media
//! pipeline applies before persisting:
//!
//! * [`normalize_caption`] runs Unicode NFC + whitespace
//!   normalization. Used for the message-layer caption field and
//!   for `media_search_index` `kind = 'caption'` rows.
//! * [`sanitize_filename`] applies NFC, strips characters that are
//!   illegal across major filesystems (FAT32 / NTFS / ext4 / APFS),
//!   preserves the file extension, and respects character
//!   boundaries when truncating to 255 bytes UTF-8.
//! * [`validate_mime_type`] enforces the basic `type/subtype`
//!   shape per [RFC 6838 §4.2].
//!
//! No path here is allowed to assume Latin-1, English-only, or
//! single-script input. CJK, Arabic, Thai, Cyrillic, Devanagari,
//! and mixed-script inputs all flow through unchanged (modulo NFC
//! and illegal-character stripping).

use unicode_normalization::UnicodeNormalization;

/// Maximum byte length of a sanitized filename. Matches the
/// 255-byte limit enforced by ext4 / APFS / NTFS for individual
/// path segments.
const MAX_FILENAME_BYTES: usize = 255;

/// Default filename returned by [`sanitize_filename`] when the
/// input strips down to an empty string (e.g. the whole input was
/// illegal characters or whitespace).
const DEFAULT_FILENAME: &str = "unnamed";

/// Characters considered illegal in common filesystems.
///
/// The set is the union of:
///
/// * NUL byte and any control character (per `char::is_control`).
/// * Path separators (`/`, `\`).
/// * Windows-reserved characters (`:`, `*`, `?`, `"`, `<`, `>`,
///   `|`).
const ILLEGAL_FILENAME_CHARS: &[char] = &['/', '\\', ':', '*', '?', '"', '<', '>', '|'];

/// Apply Unicode NFC normalization and collapse whitespace runs.
///
/// `docs/DESIGN.md §3.4` calls out NFC as the canonical form for
/// any UTF-8 string the local store persists; without it, the same
/// caption typed with composed (`é`, `\u{00E9}`) vs. decomposed
/// (`e` + combining acute, `e\u{0301}`) characters would tokenize
/// to different FTS5 rows and miss each other on search.
///
/// Whitespace handling: leading and trailing whitespace are
/// trimmed, and internal whitespace runs are collapsed to a single
/// space. This is intentionally locale-neutral — Unicode whitespace
/// (`char::is_whitespace`) covers ASCII space, tab, newline, CR,
/// form feed, vertical tab, and the multilingual whitespace block
/// (NBSP, ideographic space, etc.).
pub fn normalize_caption(caption: &str) -> String {
    let normalized: String = caption.nfc().collect();
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_was_space = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !prev_was_space {
                out.push(' ');
                prev_was_space = true;
            }
        } else {
            out.push(ch);
            prev_was_space = false;
        }
    }
    out
}

/// Sanitize a user-supplied filename for safe round-trip through
/// the local store and any cloud sink.
///
/// `docs/DESIGN.md §3.4` (multilingual tokenization) and §8.2
/// (size-class padding) are the authoritative sources. The
/// pipeline:
///
/// 1. Apply Unicode NFC (so the same filename composed in two
///    different ways persists as the same byte sequence).
/// 2. Strip control characters (any `char::is_control` codepoint,
///    including NUL `\0`, BEL `\x07`, escape `\x1B`, …).
/// 3. Drop [`ILLEGAL_FILENAME_CHARS`] (path separators + the
///    Windows-reserved set) outright. Replacing them with `_`
///    would mask the boundary between independent path segments
///    (e.g. `a/b/c` → `a_b_c`); dropping them surfaces the
///    sanitizer's intervention to UI / logs without inventing
///    new content.
/// 4. Trim leading / trailing whitespace + dots (the dot prefix is
///    a hidden-file marker on POSIX; keeping it would bleed UI
///    intent into the storage layer). Internal spaces are kept
///    verbatim — CJK / Arabic / Thai filenames embed spaces and
///    middle-dots as routine punctuation.
/// 5. Truncate to [`MAX_FILENAME_BYTES`] while *preserving the
///    extension* and respecting UTF-8 character boundaries.
/// 6. If the result is empty (whole input was illegal / whitespace),
///    return [`DEFAULT_FILENAME`].
///
/// This function never panics on multi-byte codepoints — the
/// truncation step uses `char_indices` and never splits a
/// codepoint mid-byte.
pub fn sanitize_filename(filename: &str) -> String {
    let normalized: String = filename.nfc().collect();

    let mut sanitized = String::with_capacity(normalized.len());
    for ch in normalized.chars() {
        if ch.is_control() {
            // Drop control characters outright.
            continue;
        }
        if ILLEGAL_FILENAME_CHARS.contains(&ch) {
            // Drop illegal characters outright rather than collapsing
            // them into a single substitute char — see the doc
            // comment above for rationale.
            continue;
        }
        sanitized.push(ch);
    }

    let trimmed = sanitized
        .trim_matches(|c: char| c.is_whitespace() || c == '.')
        .to_string();
    if trimmed.is_empty() {
        return DEFAULT_FILENAME.to_string();
    }

    truncate_preserving_extension(&trimmed)
}

/// Truncate `name` to at most [`MAX_FILENAME_BYTES`] bytes while
/// preserving the file extension and respecting UTF-8 character
/// boundaries. Names already within the limit are returned as-is.
fn truncate_preserving_extension(name: &str) -> String {
    if name.len() <= MAX_FILENAME_BYTES {
        return name.to_string();
    }

    let (stem, ext) = match name.rsplit_once('.') {
        // Treat a trailing-dot input as having no extension.
        Some((stem, ext)) if !ext.is_empty() && !stem.is_empty() => (stem, ext),
        _ => (name, ""),
    };

    let dot_len = if ext.is_empty() { 0 } else { 1 };
    let ext_byte_budget = ext.len();
    if MAX_FILENAME_BYTES <= ext_byte_budget + dot_len {
        // Pathological case: extension alone exceeds the limit.
        // Fall back to truncating the whole name to a char boundary.
        return truncate_to_byte_budget(name, MAX_FILENAME_BYTES);
    }
    let stem_budget = MAX_FILENAME_BYTES - ext_byte_budget - dot_len;
    let truncated_stem = truncate_to_byte_budget(stem, stem_budget);
    if ext.is_empty() {
        truncated_stem
    } else {
        format!("{truncated_stem}.{ext}")
    }
}

fn truncate_to_byte_budget(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut last_boundary = 0usize;
    for (idx, _ch) in s.char_indices() {
        if idx > max_bytes {
            break;
        }
        last_boundary = idx;
    }
    s[..last_boundary].to_string()
}

/// Validate a MIME-type string against the basic `type/subtype`
/// shape from RFC 6838 §4.2.
///
/// Accepts:
///
/// * Exactly one `/` separating the type and subtype.
/// * Both halves non-empty and made up of ASCII alphanumerics or
///   any of `+`, `-`, `.`, `_` (the RFC `restricted-name-chars`
///   set the media engine actually emits).
///
/// This is *not* a full RFC 6838 grammar — the broader set of
/// allowed characters (e.g. `!`, `#`) is handled by the network
/// layer. The stricter subset here matches what the media engine
/// itself produces and is enough to fast-fail malformed input
/// before it reaches the descriptor.
pub fn validate_mime_type(mime: &str) -> bool {
    let Some((ty, sub)) = mime.split_once('/') else {
        return false;
    };
    if ty.is_empty() || sub.is_empty() {
        return false;
    }
    if sub.contains('/') {
        return false;
    }
    let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.' | '_');
    ty.chars().all(valid_char) && sub.chars().all(valid_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // normalize_caption
    // -----------------------------------------------------------------

    #[test]
    fn nfc_normalization_of_decomposed_characters() {
        // Decomposed: 'e' + combining acute accent (U+0301) -> 'é'.
        let decomposed = "caf\u{0065}\u{0301}";
        let composed = "caf\u{00E9}";
        assert_ne!(decomposed, composed); // byte-different
        let n = normalize_caption(decomposed);
        assert_eq!(n, composed);
    }

    #[test]
    fn whitespace_collapse_and_trim() {
        let raw = "  hello   world  \n\t!  ";
        assert_eq!(normalize_caption(raw), "hello world !");
    }

    #[test]
    fn empty_caption_round_trips_to_empty() {
        assert_eq!(normalize_caption(""), "");
        assert_eq!(normalize_caption("   \t\n  "), "");
    }

    #[test]
    fn cjk_caption_round_trip() {
        // Chinese, Japanese, Korean.
        let chinese = "你好，世界";
        let japanese = "こんにちは世界";
        let korean = "안녕하세요 세계";
        assert_eq!(normalize_caption(chinese), chinese);
        assert_eq!(normalize_caption(japanese), japanese);
        assert_eq!(normalize_caption(korean), korean);
    }

    #[test]
    fn arabic_caption_round_trip() {
        // Includes RTL + ligatures; NFC must not reorder.
        let arabic = "السلام عليكم";
        assert_eq!(normalize_caption(arabic), arabic);
    }

    #[test]
    fn mixed_script_caption_preserves_runs() {
        let mixed = "Hello, 世界! مرحبا. Привіт";
        assert_eq!(normalize_caption(mixed), mixed);
    }

    #[test]
    fn thai_devanagari_cyrillic_preserved() {
        let thai = "สวัสดี";
        let devanagari = "नमस्ते";
        let cyrillic = "Привет";
        assert_eq!(normalize_caption(thai), thai);
        assert_eq!(normalize_caption(devanagari), devanagari);
        assert_eq!(normalize_caption(cyrillic), cyrillic);
    }

    // -----------------------------------------------------------------
    // sanitize_filename
    // -----------------------------------------------------------------

    #[test]
    fn sanitize_strips_illegal_chars() {
        let raw = "evil/path\\name:with*illegal?chars\"<>|.txt";
        let cleaned = sanitize_filename(raw);
        // Every illegal char becomes '_'.
        for &ch in ILLEGAL_FILENAME_CHARS {
            assert!(!cleaned.contains(ch), "leaked '{ch}' in {cleaned:?}");
        }
        // Extension preserved.
        assert!(cleaned.ends_with(".txt"));
    }

    #[test]
    fn sanitize_strips_control_characters() {
        let raw = "good\u{0000}name\u{0007}.png";
        let cleaned = sanitize_filename(raw);
        assert_eq!(cleaned, "goodname.png");
    }

    #[test]
    fn sanitize_preserves_extension_on_truncation() {
        let stem: String = "a".repeat(300);
        let raw = format!("{stem}.png");
        let cleaned = sanitize_filename(&raw);
        assert!(cleaned.len() <= MAX_FILENAME_BYTES);
        assert!(cleaned.ends_with(".png"));
        // Stem must have been truncated, not the extension.
        assert!(cleaned.starts_with("aaaaa"));
    }

    #[test]
    fn sanitize_truncation_respects_char_boundary() {
        // Each '世' is 3 bytes UTF-8. 90 of them is 270 bytes >
        // MAX_FILENAME_BYTES; truncation must land on a 3-byte
        // boundary, never split a codepoint.
        let stem: String = "世".repeat(90);
        let raw = format!("{stem}.jpg");
        let cleaned = sanitize_filename(&raw);
        assert!(cleaned.len() <= MAX_FILENAME_BYTES);
        // The result must remain valid UTF-8 — `String::from_utf8`
        // on its bytes must succeed.
        let _ = String::from_utf8(cleaned.as_bytes().to_vec()).unwrap();
        assert!(cleaned.ends_with(".jpg"));
    }

    #[test]
    fn sanitize_empty_input_returns_default() {
        assert_eq!(sanitize_filename(""), DEFAULT_FILENAME);
        assert_eq!(sanitize_filename("   "), DEFAULT_FILENAME);
        assert_eq!(sanitize_filename("///"), DEFAULT_FILENAME);
    }

    #[test]
    fn sanitize_preserves_cjk_filename() {
        let raw = "報告書.pdf";
        let cleaned = sanitize_filename(raw);
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn sanitize_preserves_arabic_filename() {
        let raw = "ملف.docx";
        let cleaned = sanitize_filename(raw);
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn sanitize_preserves_mixed_script_filename() {
        let raw = "report-报告-تقرير.txt";
        let cleaned = sanitize_filename(raw);
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn sanitize_applies_nfc() {
        let decomposed = "caf\u{0065}\u{0301}.png";
        let composed = "caf\u{00E9}.png";
        assert_eq!(sanitize_filename(decomposed), composed);
    }

    #[test]
    fn sanitize_trims_leading_dots() {
        // ".hidden" is a hidden file on POSIX; storage layer should
        // not preserve that intent.
        assert_eq!(sanitize_filename(".hidden"), "hidden");
        assert_eq!(sanitize_filename("..config"), "config");
    }

    #[test]
    fn sanitize_handles_no_extension() {
        let stem: String = "a".repeat(300);
        let cleaned = sanitize_filename(&stem);
        assert!(cleaned.len() <= MAX_FILENAME_BYTES);
        assert!(!cleaned.contains('.'));
    }

    // -----------------------------------------------------------------
    // validate_mime_type
    // -----------------------------------------------------------------

    #[test]
    fn validate_mime_accepts_common_types() {
        assert!(validate_mime_type("image/png"));
        assert!(validate_mime_type("image/jpeg"));
        assert!(validate_mime_type("video/mp4"));
        assert!(validate_mime_type("application/octet-stream"));
        assert!(validate_mime_type("application/vnd.kchat.media+cbor"));
        assert!(validate_mime_type("text/plain"));
        assert!(validate_mime_type("audio/x-wav"));
    }

    #[test]
    fn validate_mime_rejects_malformed() {
        assert!(!validate_mime_type(""));
        assert!(!validate_mime_type("image"));
        assert!(!validate_mime_type("/png"));
        assert!(!validate_mime_type("image/"));
        assert!(!validate_mime_type("image/png/extra"));
        assert!(!validate_mime_type("image png"));
        assert!(!validate_mime_type("image/png "));
        assert!(!validate_mime_type("img@ge/png"));
        assert!(!validate_mime_type("image/p\u{00E9}ng")); // non-ASCII
    }
}
