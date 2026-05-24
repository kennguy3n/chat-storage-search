//! `OnnxWhisperTranscriber` — real Whisper encoder/decoder
//! inference loop behind the `onnx-runtime` cargo feature.
//!
//! `docs/DESIGN.md §7.6 / §7.7`. The Whisper pipeline runs in
//! three stages:
//!
//! 1. **Preprocessing** — bytes → 16 kHz mono PCM → log-mel
//!    `[80 × 3000]`. Implemented in
//!    [`crate::models::whisper_audio`] (pure CPU, no ORT, always
//!    compiled).
//! 2. **Encoder** — `encoder_model.onnx` consumes the log-mel
//!    grid as `input_features [1, 80, 3000]` and emits
//!    `last_hidden_state [1, 1500, d_model]` (audio time-axis
//!    is halved by Whisper's two stride-2 conv layers). The
//!    encoder runs once per audio buffer.
//! 3. **Decoder** — `decoder_model.onnx` consumes
//!    `(input_ids [1, prefix_len], encoder_hidden_states)` and
//!    emits `logits [1, prefix_len, vocab_size]`. We greedy-
//!    decode (argmax over the last position) one token at a
//!    time, appending each token to `input_ids` and re-running
//!    the decoder, until we hit `<|endoftext|>` or the
//!    `max_decode_tokens` ceiling.
//!
//! ## What lives in this module
//!
//! * Pure helpers — special-token resolver, decoder-prefix
//!   builder, argmax greedy-step, timestamp-token parser,
//!   token-stream → segment splitter, vocabulary-size sniffer.
//!   These are unit-tested on every host (no ORT required).
//! * `OnnxWhisperTranscriber` — the long-lived wrapper holding
//!   the encoder session, decoder session, [`tokenizers::Tokenizer`],
//!   and [`crate::models::whisper_audio::WhisperMelKernel`].
//!   Gated behind `feature = "onnx-runtime"`.
//! * Always-compiled stub `OnnxWhisperTranscriber` for builds
//!   without the feature so consumers can name the type
//!   unconditionally.
//!
//! ## Why no KV-cache
//!
//! Whisper's HuggingFace ONNX export ships both `decoder_model.onnx`
//! (full re-run per step) and `decoder_with_past_model.onnx`
//! (KV-cache). The KV-cache variant is faster (O(n) instead of
//! O(n²) for n decoded tokens) but the cache-tensor naming
//! convention (`past_key_values.0.decoder.key`, …) is fragile
//! across exports and Whisper transcripts are short (≤ 224
//! tokens per 30 s window). We use the no-KV-cache form for
//! correctness and forward-compatibility; the KV-cache path is
//! a future performance follow-up.
//!
//! ## Why no MLX backend (yet)
//!
//! `docs/DESIGN.md §7.6` calls for Apple MLX on Apple Silicon
//! and ONNX everywhere else. This module is the ONNX path; the
//! MLX bridge is tracked separately and lands together with the
//! `mlx-rs` crate integration.

use crate::models::whisper::TranscriptionSegment;
use crate::models::whisper_audio::{WHISPER_N_FRAMES, WHISPER_SAMPLE_RATE};

// Stub-only imports for builds without the `onnx-runtime` feature.
// These are pulled in by the `OnnxWhisperTranscriber` stub at the
// bottom of the file; gating them per-feature keeps `unused-import`
// warnings out of the `onnx-runtime` build.
#[cfg(not(feature = "onnx-runtime"))]
use crate::models::whisper::{TranscriptionResult, WhisperTranscriber};

// ---------------------------------------------------------------------------
// Whisper constants
// ---------------------------------------------------------------------------

/// Number of audio frames the encoder emits — half the
/// preprocessing frame count because Whisper's encoder front-end
/// has two stride-2 convolutions. The decoder consumes these as
/// `encoder_hidden_states[:, 1500, d_model]`.
pub const WHISPER_ENCODER_FRAMES: usize = WHISPER_N_FRAMES / 2;

/// Whisper's per-window decoder context limit. The original
/// `multilingual.tiktoken` vocabulary is sized for 448 tokens
/// of prefix; our greedy loop refuses to emit beyond this both
/// to bound runtime and to avoid wandering into garbage tokens
/// past the trained context.
pub const WHISPER_MAX_DECODE_TOKENS: usize = 448;

/// Token spacing (in seconds) of Whisper's timestamp tokens.
/// `<|0.00|>` is `TIMESTAMP_BEGIN`, `<|0.02|>` is
/// `TIMESTAMP_BEGIN + 1`, `<|0.04|>` is `TIMESTAMP_BEGIN + 2`,
/// and so on up to `<|30.00|>` at `TIMESTAMP_BEGIN + 1500`.
pub const WHISPER_TIMESTAMP_STEP_SECONDS: f32 = 0.02;

/// Token spacing in milliseconds (== 20 ms). Stored as `u64`
/// rather than recomputed from the seconds constant so the
/// segment-builder math stays integer-only.
pub const WHISPER_TIMESTAMP_STEP_MS: u64 = 20;

// ---------------------------------------------------------------------------
// Pure: WhisperTask
// ---------------------------------------------------------------------------

/// Whisper decoder task — either transcribe (source language)
/// or translate (always to English).
///
/// Maps to one of the two special tokens (`<|transcribe|>` /
/// `<|translate|>`) the decoder prefix carries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WhisperTask {
    /// Transcribe in source language. Default behaviour.
    #[default]
    Transcribe,
    /// Translate the source audio to English.
    Translate,
}

// ---------------------------------------------------------------------------
// Pure: WhisperSpecialTokens
// ---------------------------------------------------------------------------

/// Resolved special-token ids for one Whisper tokenizer.
///
/// Whisper's tokenizer ships a couple of dozen control tokens
/// (`<|startoftranscript|>`, `<|en|>`, `<|transcribe|>`,
/// `<|notimestamps|>`, `<|0.00|>`, …). Numeric ids differ
/// slightly between multilingual / English-only and across
/// vocab revs, so we resolve them by name at construction time
/// rather than hard-coding the multilingual offsets.
#[derive(Debug, Clone)]
pub struct WhisperSpecialTokens {
    /// `<|endoftext|>` (the EOS token; same id as in GPT-2).
    pub end_of_text: u32,
    /// `<|startoftranscript|>` — first prefix token.
    pub start_of_transcript: u32,
    /// `<|transcribe|>`.
    pub transcribe: u32,
    /// `<|translate|>`.
    pub translate: u32,
    /// `<|notimestamps|>` — suppresses timestamp emission.
    pub no_timestamps: u32,
    /// `<|nospeech|>` (a.k.a. `<|nocaptions|>` on some
    /// exports) — emitted by the decoder for silence windows.
    /// `None` if the vocabulary doesn't expose it.
    pub no_speech: Option<u32>,
    /// `<|0.00|>` — first timestamp token. Subsequent timestamp
    /// tokens are at `timestamp_begin + i` for the `i`-th
    /// 20 ms step.
    pub timestamp_begin: u32,
    /// Mapping from BCP-47 / ISO-639-1 language code (`"en"`,
    /// `"zh"`, `"es"`, …) to the per-language token id. Used to
    /// pin the decoder prefix to a known language without
    /// running language detection.
    pub languages: std::collections::BTreeMap<String, u32>,
}

/// Whisper's full canonical language list — the 99 languages
/// `tokenize.py` declares plus `<|nospeech|>`. Used by
/// [`WhisperSpecialTokens::resolve_from_added_tokens`] to
/// scan the tokenizer's added-token list for which subset is
/// actually present (English-only exports only expose `"en"`).
///
/// Stored as `(iso_code, label)` tuples but only `iso_code` is
/// material for resolution — the labels are kept so
/// telemetry can render human-readable values.
pub const WHISPER_LANGUAGE_CODES: &[&str] = &[
    "en", "zh", "de", "es", "ru", "ko", "fr", "ja", "pt", "tr", "pl", "ca", "nl", "ar", "sv", "it",
    "id", "hi", "fi", "vi", "he", "uk", "el", "ms", "cs", "ro", "da", "hu", "ta", "no", "th", "ur",
    "hr", "bg", "lt", "la", "mi", "ml", "cy", "sk", "te", "fa", "lv", "bn", "sr", "az", "sl", "kn",
    "et", "mk", "br", "eu", "is", "hy", "ne", "mn", "bs", "kk", "sq", "sw", "gl", "mr", "pa", "si",
    "km", "sn", "yo", "so", "af", "oc", "ka", "be", "tg", "sd", "gu", "am", "yi", "lo", "uz", "fo",
    "ht", "ps", "tk", "nn", "mt", "sa", "lb", "my", "bo", "tl", "mg", "as", "tt", "haw", "ln",
    "ha", "ba", "jw", "su",
];

impl WhisperSpecialTokens {
    /// Resolve every special token from the
    /// `(name, id)` map a tokenizer surfaces as its
    /// "added_tokens".
    ///
    /// Returns `None` for the required tokens that the
    /// vocabulary doesn't expose; the caller should reject the
    /// model rather than guessing offsets. Optional tokens
    /// (`<|nospeech|>`) are filled in with `None` when missing.
    pub fn resolve_from_added_tokens(
        added_tokens: &[(String, u32)],
    ) -> std::result::Result<Self, String> {
        let lookup = |needle: &str| {
            added_tokens
                .iter()
                .find(|(name, _)| name == needle)
                .map(|(_, id)| *id)
        };

        let end_of_text = lookup("<|endoftext|>")
            .ok_or_else(|| "Whisper vocab missing `<|endoftext|>`".to_string())?;
        let start_of_transcript = lookup("<|startoftranscript|>")
            .ok_or_else(|| "Whisper vocab missing `<|startoftranscript|>`".to_string())?;
        let transcribe = lookup("<|transcribe|>")
            .ok_or_else(|| "Whisper vocab missing `<|transcribe|>`".to_string())?;
        let translate = lookup("<|translate|>")
            .ok_or_else(|| "Whisper vocab missing `<|translate|>`".to_string())?;
        let no_timestamps = lookup("<|notimestamps|>")
            .ok_or_else(|| "Whisper vocab missing `<|notimestamps|>`".to_string())?;
        let timestamp_begin = lookup("<|0.00|>")
            .ok_or_else(|| "Whisper vocab missing timestamp anchor `<|0.00|>`".to_string())?;
        // `<|nospeech|>` and the older `<|nocaptions|>` are the
        // same semantic role; accept either.
        let no_speech = lookup("<|nospeech|>").or_else(|| lookup("<|nocaptions|>"));

        let mut languages = std::collections::BTreeMap::new();
        for code in WHISPER_LANGUAGE_CODES {
            let needle = format!("<|{code}|>");
            if let Some(id) = lookup(&needle) {
                languages.insert((*code).to_string(), id);
            }
        }
        if languages.is_empty() {
            return Err("Whisper vocab exposes no `<|lang|>` tokens".to_string());
        }

        Ok(Self {
            end_of_text,
            start_of_transcript,
            transcribe,
            translate,
            no_timestamps,
            no_speech,
            timestamp_begin,
            languages,
        })
    }

    /// Look up a language token id by ISO code. Returns `None`
    /// for codes the loaded vocab does not expose (e.g. an
    /// English-only Whisper rejects `"zh"`).
    pub fn language_token(&self, code: &str) -> Option<u32> {
        self.languages.get(code).copied()
    }
}

// ---------------------------------------------------------------------------
// Pure: decoder prefix builder
// ---------------------------------------------------------------------------

/// Build the initial decoder input-ids prefix for one
/// transcription pass.
///
/// Whisper was trained on prefixes shaped
/// `[SOT, <|lang|>, <|task|>, <|notimestamps|>?]`. The
/// `<|lang|>` slot is mandatory in practice — Whisper's
/// reference implementation always pre-detects the language
/// via a separate single-step decoder pass and threads the
/// resulting language token into this position before the
/// real decode loop starts. Production callers in this crate
/// follow the same protocol via
/// [`OnnxWhisperTranscriber::detect_language`].
///
/// `language = None` is preserved as a low-level escape hatch
/// for callers that intentionally want to omit the language
/// slot (for example: external language detection that hasn't
/// run yet, or custom decoder protocols). Note that omitting
/// the language slot produces a prefix Whisper was NOT trained
/// against (`[SOT, <|task|>, ...]`); the model will still
/// decode but quality typically degrades. The greedy loop in
/// this module suppresses every language token from the body
/// argmax, so `language = None` will NOT cause the decoder to
/// "auto-emit" a language token as the first body token —
/// pre-detection via the dedicated path is the only way to
/// recover a language code from Whisper.
///
/// `with_timestamps = false` appends `<|notimestamps|>` so the
/// decoder emits plain text tokens. With timestamps the prefix
/// stops at the task token and the decoder will start emitting
/// timestamp tokens directly.
pub fn build_decoder_prefix(
    special: &WhisperSpecialTokens,
    language: Option<u32>,
    task: WhisperTask,
    with_timestamps: bool,
) -> Vec<u32> {
    let mut prefix = Vec::with_capacity(4);
    prefix.push(special.start_of_transcript);
    if let Some(lang) = language {
        prefix.push(lang);
    }
    let task_token = match task {
        WhisperTask::Transcribe => special.transcribe,
        WhisperTask::Translate => special.translate,
    };
    prefix.push(task_token);
    if !with_timestamps {
        prefix.push(special.no_timestamps);
    }
    prefix
}

// ---------------------------------------------------------------------------
// Pure: argmax greedy step
// ---------------------------------------------------------------------------

/// Argmax of the last position of a Whisper decoder logits
/// tensor, with optional suppression masks applied first.
///
/// Inputs:
///
/// * `logits` — flat row-major `[1, seq_len, vocab_size]`. Only
///   the final position
///   (`(seq_len - 1) * vocab_size .. seq_len * vocab_size`) is
///   consulted; earlier positions correspond to the prefix
///   that's already been decided.
/// * `seq_len` — prefix length (matches `input_ids.len()`).
/// * `vocab_size` — vocabulary cardinality
///   (`logits.len() / seq_len`).
/// * `suppress` — token ids whose logits are clamped to
///   `f32::NEG_INFINITY` before argmax. Typically the prefix
///   control tokens (`<|startoftranscript|>`, language tokens,
///   `<|notimestamps|>`, …) so the greedy decoder cannot emit
///   them as content.
///
/// Returns the picked token id. Ties go to the lower id
/// (`Vec::iter().enumerate()` natural order).
pub fn argmax_next_token(
    logits: &[f32],
    seq_len: usize,
    vocab_size: usize,
    suppress: &[u32],
) -> Option<u32> {
    if seq_len == 0 || vocab_size == 0 {
        return None;
    }
    // Use `checked_mul` defensively: in practice
    // `seq_len * vocab_size` is at most ~448 * ~52000 ≈ 23 M
    // and fits in even a 32-bit `usize`, but a malformed shape
    // from the decoder should surface as `None` instead of
    // panicking on overflow.
    let expected = seq_len.checked_mul(vocab_size)?;
    if logits.len() < expected {
        return None;
    }
    let start = (seq_len - 1).checked_mul(vocab_size)?;
    let row = &logits[start..start + vocab_size];

    let mut best_idx = 0usize;
    let mut best_val = f32::NEG_INFINITY;
    for (idx, &v) in row.iter().enumerate() {
        // Skip suppressed token ids. We pay the inner-loop
        // membership cost (linear scan of a typically <10-element
        // `suppress` slice) because materialising a HashSet here
        // would dominate the cost of a single decode step. The
        // suppression list is small and stable across the loop;
        // tests pin its membership.
        if suppress.iter().any(|&s| s as usize == idx) {
            continue;
        }
        if v > best_val {
            best_val = v;
            best_idx = idx;
        }
    }
    if best_val == f32::NEG_INFINITY {
        // Every position was suppressed — degenerate case, but
        // surface it explicitly so the decoder loop can bail.
        return None;
    }
    Some(best_idx as u32)
}

/// Pure helper for Whisper-style language detection.
///
/// Whisper's reference implementation (`whisper.decoding.detect_language`)
/// runs the decoder once with a prefix of just `[SOT]` (a single
/// token), reads the position-0 logits, masks every token id
/// that is NOT a language token to `-inf`, and argmaxes. This
/// helper implements the masked argmax in pure Rust so the
/// production transcribe pipeline can pre-resolve the language
/// before the greedy decode loop starts (matching Whisper's
/// training-time prefix layout `[SOT, <|lang|>, <|task|>,
/// <|notimestamps|>?]`).
///
/// Inputs:
///
/// * `logits_row` — the position-0 logits row, length
///   `vocab_size`. Callers extract this from the full decoder
///   output (`logits[0..vocab_size]`).
/// * `language_token_ids` — the set of valid language token
///   ids (typically `special.languages.values()`). Tokens NOT
///   in this set are masked to `-inf` before argmax.
///
/// Returns the picked language token id (which is guaranteed
/// to be a member of `language_token_ids`), or `None` if
/// either input is empty or every candidate id is out of
/// range of the logits row.
pub fn argmax_language_token(logits_row: &[f32], language_token_ids: &[u32]) -> Option<u32> {
    if logits_row.is_empty() || language_token_ids.is_empty() {
        return None;
    }
    let mut best_id: Option<u32> = None;
    let mut best_val = f32::NEG_INFINITY;
    for &id in language_token_ids {
        let idx = id as usize;
        if idx >= logits_row.len() {
            // Defensive: silently skip ids past the logits row.
            // This can only happen if `language_token_ids`
            // disagrees with the decoder's vocab size — the
            // caller's `vocab_size` invariant is the contract,
            // we just don't panic if it is violated.
            continue;
        }
        let v = logits_row[idx];
        if v > best_val {
            best_val = v;
            best_id = Some(id);
        }
    }
    best_id
}

// ---------------------------------------------------------------------------
// Pure: timestamp helpers + segment builder
// ---------------------------------------------------------------------------

/// Convert a timestamp token id to a millisecond offset.
///
/// Returns `None` for token ids that aren't in the timestamp
/// range. Whisper timestamps span
/// `[timestamp_begin, timestamp_begin + 1500]` (inclusive on
/// the upper bound — `<|30.00|>` IS a valid timestamp token).
pub fn timestamp_token_to_ms(token: u32, timestamp_begin: u32) -> Option<u64> {
    if token < timestamp_begin {
        return None;
    }
    let offset = token - timestamp_begin;
    // `<|30.00|>` is the upper bound for a 30-second window.
    // Tokens past that are out of range; we reject them so the
    // segment builder can flag malformed token streams.
    if offset > 1_500 {
        return None;
    }
    Some(u64::from(offset) * WHISPER_TIMESTAMP_STEP_MS)
}

/// Split a decoded token stream into
/// [`TranscriptionSegment`]s using Whisper's paired-timestamp
/// convention.
///
/// Whisper's timestamp-mode output looks like
/// `[<|0.00|>, text, text, <|2.30|>, <|2.30|>, text, ...,
/// <|5.40|>, <|endoftext|>]`. Pairs of consecutive timestamp
/// tokens (`<|start|>` then `<|end|>`) bracket each segment.
/// The token IDs in between are GPT-2 BPE tokens that the
/// caller MUST decode into text via the tokenizer.
///
/// `decode` is invoked once per segment with the body token
/// ids; pass a closure that wraps `tokenizers::Tokenizer::decode`
/// with the right `skip_special_tokens = true` flag. Any
/// non-paired timestamps (a single timestamp followed by
/// `<|endoftext|>`, or an unmatched leading timestamp) are
/// silently flushed into a final partial segment so the caller
/// gets useful output even for malformed streams — Whisper
/// occasionally truncates segments at the end of a 30 s window.
///
/// Tokens before the first timestamp (in non-timestamp mode,
/// the entire stream) are emitted as a single segment with
/// `start_ms = 0`, `end_ms = 0`.
pub fn segments_from_tokens<F>(
    tokens: &[u32],
    timestamp_begin: u32,
    end_of_text: u32,
    mut decode: F,
) -> Vec<TranscriptionSegment>
where
    F: FnMut(&[u32]) -> String,
{
    let mut segments = Vec::new();
    // Look at runs of "non-special" tokens delimited by either
    // paired timestamp tokens or end-of-text.
    //
    // We track the "in-flight" segment's start_ms (`None` until
    // we see a leading timestamp) and the body tokens
    // accumulated since the last delimiter.
    let mut current_start: Option<u64> = None;
    let mut body: Vec<u32> = Vec::new();

    for &tok in tokens {
        if tok == end_of_text {
            break;
        }
        if let Some(ms) = timestamp_token_to_ms(tok, timestamp_begin) {
            match current_start {
                None => {
                    // Leading timestamp opens a segment. If there are
                    // body tokens already buffered (e.g. tokenizer
                    // emitted text before the first timestamp), flush
                    // them as a `start_ms = 0` segment.
                    if !body.is_empty() {
                        let text = decode(&body).trim().to_string();
                        if !text.is_empty() {
                            segments.push(TranscriptionSegment {
                                start_ms: 0,
                                end_ms: 0,
                                text,
                            });
                        }
                        body.clear();
                    }
                    current_start = Some(ms);
                }
                Some(start_ms) => {
                    // Closing timestamp. Emit the segment.
                    let text = decode(&body).trim().to_string();
                    if !text.is_empty() {
                        segments.push(TranscriptionSegment {
                            start_ms,
                            end_ms: ms,
                            text,
                        });
                    }
                    body.clear();
                    current_start = None;
                }
            }
        } else {
            body.push(tok);
        }
    }

    // Tail: unclosed segment. Whisper sometimes truncates the
    // final segment at the end of the 30 s window; flush
    // whatever we have so the caller does not lose it.
    if !body.is_empty() {
        let text = decode(&body).trim().to_string();
        if !text.is_empty() {
            let start_ms = current_start.unwrap_or(0);
            segments.push(TranscriptionSegment {
                start_ms,
                end_ms: start_ms,
                text,
            });
        }
    }

    segments
}

// ---------------------------------------------------------------------------
// `OnnxWhisperTranscriber` — feature-gated real wrapper
// ---------------------------------------------------------------------------

/// Default tokenizer artifact filename (HuggingFace convention).
///
/// Whisper exports ship a `tokenizer.json` alongside the
/// `encoder_model.onnx` / `decoder_model.onnx` pair. The
/// constructor resolves this filename relative to the encoder
/// model's parent directory; callers that need a different
/// layout can use the `_with_tokenizer` constructor.
pub const WHISPER_DEFAULT_TOKENIZER_FILENAME: &str = "tokenizer.json";

/// Default decoder artifact filename. Mirrors the
/// `WHISPER_DEFAULT_TOKENIZER_FILENAME` convention so single-
/// argument constructors can locate the decoder by name.
pub const WHISPER_DEFAULT_DECODER_FILENAME: &str = "decoder_model.onnx";

/// Default encoder artifact filename.
pub const WHISPER_DEFAULT_ENCODER_FILENAME: &str = "encoder_model.onnx";

#[cfg(feature = "onnx-runtime")]
mod with_ort {
    use super::{
        WhisperSpecialTokens, WhisperTask, WHISPER_DEFAULT_DECODER_FILENAME,
        WHISPER_DEFAULT_ENCODER_FILENAME, WHISPER_DEFAULT_TOKENIZER_FILENAME,
        WHISPER_ENCODER_FRAMES, WHISPER_MAX_DECODE_TOKENS,
    };
    use crate::models::embeddings_onnx::{
        map_ort_error, select_provider, OnnxExecutionProvider, OnnxProviderReport, OrtDirectMlProbe,
    };
    use crate::models::whisper::{TranscriptionResult, TranscriptionSegment, WhisperTranscriber};
    use crate::models::whisper_audio::{
        whisper_log_mel_from_wav, WhisperMelKernel, WHISPER_N_FRAMES, WHISPER_N_MELS,
    };
    use crate::models::ModelError;
    use crate::Result;
    use ort::ep::{ExecutionProvider, CPU};
    use ort::session::Session;
    use ort::value::Tensor;
    use std::path::Path;

    /// Create one encoder/decoder ONNX session using the same
    /// best-effort DirectML → CPU EP state machine as
    /// [`crate::models::embeddings_onnx::create_xlmr_session`].
    fn create_whisper_session(
        model_path: &Path,
        op: &'static str,
    ) -> Result<(Session, OnnxProviderReport)> {
        let intent = select_provider(&OrtDirectMlProbe);
        let mut builder = Session::builder().map_err(map_ort_error)?;

        let actual_provider = match intent.provider {
            OnnxExecutionProvider::DirectMl => {
                #[cfg(target_os = "windows")]
                {
                    use ort::ep::DirectML;
                    if DirectML::default().register(&mut builder).is_ok() {
                        OnnxExecutionProvider::DirectMl
                    } else {
                        let _ = CPU::default().register(&mut builder);
                        OnnxExecutionProvider::Cpu
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    // `select_provider` is supposed to short-
                    // circuit to CPU off Windows; reaching this
                    // branch off-Windows means a probe lied —
                    // degrade gracefully.
                    let _ = CPU::default().register(&mut builder);
                    OnnxExecutionProvider::Cpu
                }
            }
            OnnxExecutionProvider::Cpu => {
                let _ = CPU::default().register(&mut builder);
                OnnxExecutionProvider::Cpu
            }
        };

        let _ = op; // op is currently informational; logged at
                    // the wrapper level so encoder / decoder
                    // error sites carry distinct names.
        let session = builder
            .commit_from_file(model_path)
            .map_err(map_ort_error)?;
        Ok((
            session,
            OnnxProviderReport {
                provider: actual_provider,
                directml_attempted: intent.directml_attempted,
            },
        ))
    }

    /// Long-lived ONNX Runtime wrapper for Whisper transcription.
    ///
    /// Holds the encoder and decoder sessions plus a single
    /// [`tokenizers::Tokenizer`] and [`WhisperMelKernel`]. Each
    /// [`Self::transcribe`] call:
    ///
    /// 1. Runs `whisper_log_mel_from_wav` to get the
    ///    `[80 × 3000]` log-mel grid.
    /// 2. Runs the encoder once.
    /// 3. Greedy-decodes one token at a time until `<|endoftext|>`
    ///    or `WHISPER_MAX_DECODE_TOKENS`.
    /// 4. Decodes the emitted token stream into text + segments
    ///    via [`super::segments_from_tokens`].
    ///
    /// The struct is `Send + Sync`-friendly: `Session` is `Send`
    /// in the pinned `ort 2.0.0-rc.12`, and we wrap each session
    /// in its own `Mutex` so concurrent transcribe calls
    /// serialise without contending on the same lock. The
    /// tokenizer's `encode` / `decode` are `&self`-callable and
    /// sit outside the locks.
    pub struct OnnxWhisperTranscriber {
        encoder: std::sync::Mutex<Session>,
        decoder: std::sync::Mutex<Session>,
        tokenizer: tokenizers::Tokenizer,
        mel_kernel: WhisperMelKernel,
        special: WhisperSpecialTokens,
        encoder_report: OnnxProviderReport,
        decoder_report: OnnxProviderReport,
        /// Default decoder task. `transcribe` reads this unless
        /// overridden through the configuration setters.
        task: WhisperTask,
        /// Language to pin in the decoder prefix. `None` means
        /// "let Whisper auto-detect" (which in greedy decoding
        /// just means the first emitted token will be the
        /// language token, and the result reports it).
        language: Option<String>,
        /// Whether to emit `<|notimestamps|>` in the prefix.
        with_timestamps: bool,
        /// Maximum decode-loop iteration count. Defaults to
        /// [`WHISPER_MAX_DECODE_TOKENS`].
        max_decode_tokens: usize,
        /// Vocabulary cardinality sniffed from the tokenizer at
        /// construction time. Used to validate decoder logits
        /// tensor shapes.
        vocab_size: usize,
    }

    impl std::fmt::Debug for OnnxWhisperTranscriber {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("OnnxWhisperTranscriber")
                .field("encoder_report", &self.encoder_report)
                .field("decoder_report", &self.decoder_report)
                .field("task", &self.task)
                .field("language", &self.language)
                .field("with_timestamps", &self.with_timestamps)
                .field("max_decode_tokens", &self.max_decode_tokens)
                .field("vocab_size", &self.vocab_size)
                .finish_non_exhaustive()
        }
    }

    impl OnnxWhisperTranscriber {
        /// Build a Whisper transcriber from the canonical
        /// HuggingFace layout: `encoder_model.onnx`,
        /// `decoder_model.onnx`, `tokenizer.json` colocated in
        /// the same directory as `encoder_dir`.
        ///
        /// Returns the typed [`crate::Error::Model`] variant on
        /// any of the standard failure modes:
        /// * encoder / decoder session load (`ModelError::Ort`)
        /// * tokenizer parse / missing artifact (`ModelError::Tokenizer`)
        /// * special-token resolution failure (`ModelError::Tokenizer`
        ///   with `op = "whisper_special_tokens"`)
        pub fn new(encoder_dir: &Path) -> Result<Self> {
            let encoder_path = encoder_dir.join(WHISPER_DEFAULT_ENCODER_FILENAME);
            let decoder_path = encoder_dir.join(WHISPER_DEFAULT_DECODER_FILENAME);
            let tokenizer_path = encoder_dir.join(WHISPER_DEFAULT_TOKENIZER_FILENAME);
            Self::new_with_paths(&encoder_path, &decoder_path, &tokenizer_path)
        }

        /// Build a Whisper transcriber from explicit paths to
        /// the three artifacts. Useful in tests that stage
        /// artifacts at non-canonical locations.
        pub fn new_with_paths(
            encoder_path: &Path,
            decoder_path: &Path,
            tokenizer_path: &Path,
        ) -> Result<Self> {
            let (encoder, encoder_report) =
                create_whisper_session(encoder_path, "whisper_encoder_session_create")?;
            let (decoder, decoder_report) =
                create_whisper_session(decoder_path, "whisper_decoder_session_create")?;

            let tokenizer = load_whisper_tokenizer(tokenizer_path)?;
            let special = resolve_special_tokens(&tokenizer)?;
            let vocab_size = tokenizer.get_vocab_size(true);

            Ok(Self {
                encoder: std::sync::Mutex::new(encoder),
                decoder: std::sync::Mutex::new(decoder),
                tokenizer,
                mel_kernel: WhisperMelKernel::new(),
                special,
                encoder_report,
                decoder_report,
                task: WhisperTask::Transcribe,
                language: None,
                with_timestamps: true,
                max_decode_tokens: WHISPER_MAX_DECODE_TOKENS,
                vocab_size,
            })
        }

        /// Override the default decoder task. Returns `self`
        /// for builder-style chaining at the call site.
        pub fn with_task(mut self, task: WhisperTask) -> Self {
            self.task = task;
            self
        }

        /// Pin the decoder prefix to a specific source language
        /// (BCP-47 / ISO-639-1 code, e.g. `"en"`, `"zh"`).
        /// Pass `None` for auto-detect (default behaviour).
        ///
        /// Unknown codes are returned through
        /// [`crate::Error::Model`] / [`ModelError::Tokenizer`]
        /// so callers learn loudly about typos rather than
        /// silently getting a misdetected transcript.
        pub fn with_language(mut self, language: Option<&str>) -> Result<Self> {
            if let Some(code) = language {
                if self.special.language_token(code).is_none() {
                    return Err(crate::Error::Model(ModelError::Tokenizer {
                        op: "whisper_with_language",
                        detail: format!("language `{code}` not exposed by this Whisper vocabulary"),
                    }));
                }
                self.language = Some(code.to_string());
            } else {
                self.language = None;
            }
            Ok(self)
        }

        /// Enable / disable timestamp-token emission. Default
        /// is `true` (`<|notimestamps|>` is OMITTED from the
        /// prefix). With timestamps disabled the transcript
        /// arrives as a single segment with `start_ms = end_ms = 0`.
        pub fn with_timestamps(mut self, enabled: bool) -> Self {
            self.with_timestamps = enabled;
            self
        }

        /// Override the decode-loop iteration ceiling. Defaults
        /// to [`WHISPER_MAX_DECODE_TOKENS`] (448 — Whisper's
        /// trained context limit).
        pub fn with_max_decode_tokens(mut self, max: usize) -> Self {
            self.max_decode_tokens = max.max(1);
            self
        }

        /// Execution-provider report for the encoder session.
        pub fn encoder_provider_report(&self) -> OnnxProviderReport {
            self.encoder_report
        }

        /// Execution-provider report for the decoder session.
        pub fn decoder_provider_report(&self) -> OnnxProviderReport {
            self.decoder_report
        }

        /// Resolved special-token table for the loaded
        /// tokenizer. Exposed for telemetry / debugging.
        pub fn special_tokens(&self) -> &WhisperSpecialTokens {
            &self.special
        }

        /// Vocabulary cardinality.
        pub fn vocab_size(&self) -> usize {
            self.vocab_size
        }

        /// Run the encoder over the log-mel grid.
        fn run_encoder(&self, mel: Vec<f32>) -> Result<Vec<f32>> {
            debug_assert_eq!(mel.len(), WHISPER_N_MELS * WHISPER_N_FRAMES);
            let mel_tensor = Tensor::from_array((
                vec![1_i64, WHISPER_N_MELS as i64, WHISPER_N_FRAMES as i64],
                mel,
            ))
            .map_err(map_ort_error)?;

            let mut encoder = self.encoder.lock().map_err(|_| {
                crate::Error::Model(ModelError::LockPoisoned("whisper_encoder_session"))
            })?;
            let outputs = encoder
                .run(ort::inputs!["input_features" => mel_tensor])
                .map_err(map_ort_error)?;
            // The encoder export emits its single hidden-state
            // output under one of `last_hidden_state` /
            // `hidden_states` / index 0. We pull the first
            // output by index to be format-agnostic.
            let out = outputs
                .iter()
                .next()
                .ok_or_else(|| {
                    crate::Error::Model(ModelError::Ort {
                        op: "whisper_encoder_no_output",
                        detail: "encoder run returned zero outputs".into(),
                    })
                })?
                .1;
            let (shape, data) = out.try_extract_tensor::<f32>().map_err(map_ort_error)?;
            // Encoder output must be exactly `[1, WHISPER_ENCODER_FRAMES,
            // d_model]` — 3 dims, batch == 1, time axis == 1500. The
            // total-element-count check below catches "data length
            // disagrees with shape", but only AFTER asserting the
            // rank+leading-dims pin down the (batch, time) axes the
            // greedy loop later assumes. Without the rank check a
            // tensor shaped `[N, T, d_model]` with N*T == 1500 (e.g.
            // `[3, 500, d_model]`) would slip through the length
            // equality, mis-layout the hidden states, and corrupt the
            // decoder cross-attention silently.
            let shape_slice: &[i64] = shape.as_ref();
            if shape_slice.len() != 3
                || shape_slice[0] != 1
                || shape_slice[1] != WHISPER_ENCODER_FRAMES as i64
            {
                return Err(crate::Error::Model(ModelError::Ort {
                    op: "whisper_encoder_output_shape",
                    detail: format!(
                        "encoder output expected `[1, {}, d_model]`, got `{:?}`",
                        WHISPER_ENCODER_FRAMES, shape
                    ),
                }));
            }
            let d_model_dim = shape_inner_dim(shape_slice)?;
            let expected_len =
                WHISPER_ENCODER_FRAMES
                    .checked_mul(d_model_dim)
                    .ok_or_else(|| {
                        // d_model * WHISPER_ENCODER_FRAMES overflows
                        // usize only on degenerate shapes; surface
                        // a typed error rather than panic.

                        crate::Error::Model(ModelError::Ort {
                            op: "whisper_encoder_output_shape",
                            detail: format!("encoder output shape overflow: {shape:?}"),
                        })
                    })?;
            if data.len() != expected_len {
                return Err(crate::Error::Model(ModelError::Ort {
                    op: "whisper_encoder_output_shape",
                    detail: format!(
                        "encoder output length {} does not match expected {} from shape {:?}",
                        data.len(),
                        expected_len,
                        shape
                    ),
                }));
            }
            Ok(data.to_vec())
        }

        /// Wrap the encoder hidden-state buffer into an ORT
        /// `Tensor<f32>` once per transcription. The decoder
        /// re-runs many times (up to `max_decode_tokens`)
        /// against the same hidden state, so we construct the
        /// tensor once and pass it by reference each iteration
        /// rather than copying the ~768 KB hidden state on every
        /// greedy step.
        fn build_hidden_tensor(
            &self,
            encoder_hidden: Vec<f32>,
            encoder_d_model: usize,
        ) -> Result<Tensor<f32>> {
            Tensor::from_array((
                vec![1_i64, WHISPER_ENCODER_FRAMES as i64, encoder_d_model as i64],
                encoder_hidden,
            ))
            .map_err(map_ort_error)
        }

        /// Run the decoder once over the current prefix and a
        /// pre-built encoder hidden-state tensor; return the
        /// logits as a flat row-major `Vec<f32>` of length
        /// `prefix.len() * vocab_size`.
        ///
        /// `hidden_tensor` is borrowed (not consumed) so the
        /// caller can reuse it across every greedy iteration
        /// without paying the cost of copying the encoder
        /// hidden state on each step.
        fn run_decoder(&self, prefix: &[u32], hidden_tensor: &Tensor<f32>) -> Result<Vec<f32>> {
            // Whisper decoder expects `input_ids` as i64.
            let input_ids: Vec<i64> = prefix.iter().map(|&t| i64::from(t)).collect();
            let prefix_len = input_ids.len();
            let ids_tensor = Tensor::from_array((vec![1_i64, prefix_len as i64], input_ids))
                .map_err(map_ort_error)?;

            let mut decoder = self.decoder.lock().map_err(|_| {
                crate::Error::Model(ModelError::LockPoisoned("whisper_decoder_session"))
            })?;
            let outputs = decoder
                .run(ort::inputs![
                    "input_ids" => ids_tensor,
                    "encoder_hidden_states" => hidden_tensor,
                ])
                .map_err(map_ort_error)?;
            let out = outputs
                .iter()
                .next()
                .ok_or_else(|| {
                    crate::Error::Model(ModelError::Ort {
                        op: "whisper_decoder_no_output",
                        detail: "decoder run returned zero outputs".into(),
                    })
                })?
                .1;
            let (shape, data) = out.try_extract_tensor::<f32>().map_err(map_ort_error)?;
            let total = prefix_len.checked_mul(self.vocab_size).ok_or_else(|| {
                crate::Error::Model(ModelError::Ort {
                    op: "whisper_decoder_output_overflow",
                    detail: "prefix_len * vocab_size overflowed usize".into(),
                })
            })?;
            if data.len() != total {
                return Err(crate::Error::Model(ModelError::Ort {
                    op: "whisper_decoder_output_shape",
                    detail: format!(
                        "decoder output length {} does not match prefix_len * vocab_size = {total} (shape {shape:?})",
                        data.len()
                    ),
                }));
            }
            Ok(data.to_vec())
        }

        /// Whisper-style language detection.
        ///
        /// Runs the decoder once with a single-token prefix
        /// `[SOT]`, reads the position-0 logits, and argmaxes
        /// over the language token ids. This mirrors
        /// `whisper.decoding.detect_language` and produces the
        /// language token id that the production decode loop
        /// then threads into its `[SOT, <|lang|>, <|task|>,
        /// <|notimestamps|>?]` prefix.
        ///
        /// Returns a typed [`ModelError::Ort`] when the decoder
        /// emits no language-token logits (degenerate model) so
        /// callers can distinguish detection failure from
        /// downstream decode failure in telemetry.
        fn detect_language(&self, hidden_tensor: &Tensor<f32>) -> Result<u32> {
            let probe_prefix = [self.special.start_of_transcript];
            let logits = self.run_decoder(&probe_prefix, hidden_tensor)?;
            // `run_decoder` already validated that `data.len()
            // == prefix_len * vocab_size`; with a single-token
            // prefix the position-0 row is the whole buffer.
            let row = &logits[..self.vocab_size];
            let language_ids: Vec<u32> = self.special.languages.values().copied().collect();
            super::argmax_language_token(row, &language_ids).ok_or_else(|| {
                crate::Error::Model(ModelError::Ort {
                    op: "whisper_detect_language",
                    detail: "decoder emitted no language-token logits during detection".into(),
                })
            })
        }
    }

    impl WhisperTranscriber for OnnxWhisperTranscriber {
        fn transcribe(&self, audio_data: &[u8], mime_type: &str) -> Result<TranscriptionResult> {
            if !mime_type.starts_with("audio/") {
                return Err(crate::Error::Model(ModelError::MediaDecode {
                    op: "whisper_transcribe",
                    detail: format!(
                        "OnnxWhisperTranscriber rejects non-audio mime_type: {mime_type}"
                    ),
                }));
            }

            // 1. Preprocessing: bytes → [80, 3000] log-mel.
            let mel = whisper_log_mel_from_wav(audio_data, &self.mel_kernel)?;

            // 2. Encoder: [1, 80, 3000] → [1, 1500, d_model].
            let encoder_hidden = self.run_encoder(mel)?;
            // d_model is whatever the encoder emits — we sniffed
            // the total length and the leading dims are fixed,
            // so divide out to recover it.
            if encoder_hidden.is_empty() || encoder_hidden.len() % WHISPER_ENCODER_FRAMES != 0 {
                return Err(crate::Error::Model(ModelError::Ort {
                    op: "whisper_encoder_output_shape",
                    detail: format!(
                        "encoder output length {} not divisible by encoder frames {WHISPER_ENCODER_FRAMES}",
                        encoder_hidden.len()
                    ),
                }));
            }
            let encoder_d_model = encoder_hidden.len() / WHISPER_ENCODER_FRAMES;

            // 3. Wrap the encoder hidden state in an ORT tensor
            //    ONCE. The decoder re-runs up to
            //    `max_decode_tokens` times against the same
            //    hidden state, so building the tensor inside the
            //    loop would copy ~768 KB of f32s per iteration
            //    (up to ~340 MB of transient allocations for a
            //    full 448-token decode against whisper-base).
            let hidden_tensor = self.build_hidden_tensor(encoder_hidden, encoder_d_model)?;

            // 4. Resolve the language token.
            //
            //    Whisper was trained with prefixes shaped
            //    `[SOT, <|lang|>, <|task|>, <|notimestamps|>?]`
            //    — the language slot is mandatory in practice.
            //    If the caller pinned a language via
            //    [`OnnxWhisperTranscriber::with_language`] we
            //    use that; otherwise we run Whisper's standard
            //    detection protocol (one decoder pass over a
            //    `[SOT]` prefix, argmax over language tokens at
            //    position 0).
            let (language_token, detected_language) = if let Some(code) = self.language.as_deref() {
                // `with_language` rejects unknown codes at
                // configure-time, so this lookup cannot fail
                // here. We still surface a typed error
                // defensively rather than panic if the
                // tokenizer was swapped out between
                // `with_language` and `transcribe`.
                let id = self.special.language_token(code).ok_or_else(|| {
                    crate::Error::Model(ModelError::Tokenizer {
                        op: "whisper_transcribe_language",
                        detail: format!(
                            "pinned language `{code}` not exposed by the loaded Whisper vocab"
                        ),
                    })
                })?;
                (id, Some(code.to_string()))
            } else {
                let id = self.detect_language(&hidden_tensor)?;
                let code = self
                    .special
                    .languages
                    .iter()
                    .find(|(_, &v)| v == id)
                    .map(|(code, _)| code.clone());
                (id, code)
            };

            // 5. Build the real decode prefix, now that we have
            //    a language token in hand.
            let suppress = self.build_suppression_set();
            let mut prefix = super::build_decoder_prefix(
                &self.special,
                Some(language_token),
                self.task,
                self.with_timestamps,
            );
            let prefix_initial_len = prefix.len();

            // 6. Greedy decode loop.
            let mut emitted: Vec<u32> = Vec::new();
            for _ in 0..self.max_decode_tokens {
                let logits = self.run_decoder(&prefix, &hidden_tensor)?;
                let next =
                    super::argmax_next_token(&logits, prefix.len(), self.vocab_size, &suppress)
                        .ok_or_else(|| {
                            crate::Error::Model(ModelError::Ort {
                                op: "whisper_decoder_argmax",
                                detail:
                                    "every vocabulary position was suppressed; refusing to advance"
                                        .into(),
                            })
                        })?;
                if next == self.special.end_of_text {
                    break;
                }
                emitted.push(next);
                prefix.push(next);
            }

            // 7. Decode token stream → text + segments.
            let tokenizer = &self.tokenizer;
            let decode =
                |body: &[u32]| -> String { tokenizer.decode(body, true).unwrap_or_default() };
            let mut segments = super::segments_from_tokens(
                &emitted,
                self.special.timestamp_begin,
                self.special.end_of_text,
                decode,
            );
            // Without timestamps the segment builder won't have
            // produced anything because no timestamp tokens are
            // in the stream; flush the whole body as a single
            // segment.
            if segments.is_empty() && !emitted.is_empty() {
                let text = tokenizer.decode(&emitted, true).unwrap_or_default();
                let text = text.trim().to_string();
                if !text.is_empty() {
                    segments.push(TranscriptionSegment {
                        start_ms: 0,
                        end_ms: 0,
                        text,
                    });
                }
            }
            let text = segments
                .iter()
                .map(|s| s.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let text = text.trim().to_string();

            let _ = prefix_initial_len; // captured for future
                                        // telemetry; currently
                                        // informational.

            Ok(TranscriptionResult {
                text,
                language: detected_language,
                segments,
            })
        }
    }

    impl OnnxWhisperTranscriber {
        /// Build the token-id suppression list for greedy
        /// decoding: every special token EXCEPT timestamps and
        /// `<|endoftext|>`. We allow `<|endoftext|>` so the
        /// decoder can terminate; we allow timestamp tokens so
        /// timestamp-mode decoding still works.
        ///
        /// Note: language tokens are unconditionally suppressed
        /// here. The production transcribe pipeline pre-resolves
        /// the language via [`OnnxWhisperTranscriber::detect_language`]
        /// (or via the explicit `with_language` setter) and
        /// threads the resulting language token into the decoder
        /// prefix. Once language is in the prefix it should never
        /// appear in the body, so the suppression is correct.
        fn build_suppression_set(&self) -> Vec<u32> {
            let mut suppress = vec![
                self.special.start_of_transcript,
                self.special.transcribe,
                self.special.translate,
                self.special.no_timestamps,
            ];
            if let Some(ns) = self.special.no_speech {
                suppress.push(ns);
            }
            suppress.extend(self.special.languages.values().copied());
            // Do NOT suppress `end_of_text` or timestamp tokens.
            suppress.sort_unstable();
            suppress.dedup();
            suppress
        }
    }

    /// Load a HuggingFace tokenizer from disk, wrapping any
    /// parse / I/O failure in [`ModelError::Tokenizer`].
    fn load_whisper_tokenizer(path: &Path) -> Result<tokenizers::Tokenizer> {
        tokenizers::Tokenizer::from_file(path).map_err(|e| {
            crate::Error::Model(ModelError::Tokenizer {
                op: "whisper_tokenizer_load",
                detail: e.to_string(),
            })
        })
    }

    /// Resolve [`WhisperSpecialTokens`] from a loaded
    /// tokenizer's added-token table.
    fn resolve_special_tokens(tokenizer: &tokenizers::Tokenizer) -> Result<WhisperSpecialTokens> {
        let added: Vec<(String, u32)> = tokenizer
            .get_added_tokens_decoder()
            .into_iter()
            .map(|(id, tok)| (tok.content, id))
            .collect();
        WhisperSpecialTokens::resolve_from_added_tokens(&added).map_err(|detail| {
            crate::Error::Model(ModelError::Tokenizer {
                op: "whisper_special_tokens",
                detail,
            })
        })
    }

    /// Pluck the inner-most dimension out of an ORT shape, used
    /// to extract `d_model` from the encoder's
    /// `[1, 1500, d_model]` output. Returns `Err` on
    /// dynamic-dim (`-1`) shapes — the encoder graph is fully
    /// static for Whisper.
    fn shape_inner_dim(shape: &[i64]) -> Result<usize> {
        let last = shape.last().copied().ok_or_else(|| {
            crate::Error::Model(ModelError::Ort {
                op: "whisper_encoder_output_shape",
                detail: "encoder output tensor has no dimensions".into(),
            })
        })?;
        if last <= 0 {
            return Err(crate::Error::Model(ModelError::Ort {
                op: "whisper_encoder_output_shape",
                detail: format!(
                    "encoder output last dim is non-positive ({last}); dynamic dims unsupported"
                ),
            }));
        }
        Ok(last as usize)
    }

    // Local consts re-imported for the `_ =` discard pattern.
    use crate::models::whisper_audio::WHISPER_SAMPLE_RATE;
    const _: u32 = WHISPER_SAMPLE_RATE; // compile-time sanity
}

#[cfg(feature = "onnx-runtime")]
pub use with_ort::OnnxWhisperTranscriber;

// ---------------------------------------------------------------------------
// Stub for builds without the `onnx-runtime` feature
// ---------------------------------------------------------------------------

/// Always-`NotImplemented` `OnnxWhisperTranscriber` stub for
/// builds without the `onnx-runtime` cargo feature.
///
/// Mirrors the [`crate::models::embeddings_onnx::OnnxTextEmbedder`]
/// stub pattern so consumer crates can name
/// `OnnxWhisperTranscriber` unconditionally.
#[cfg(not(feature = "onnx-runtime"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct OnnxWhisperTranscriber;

#[cfg(not(feature = "onnx-runtime"))]
impl OnnxWhisperTranscriber {
    /// Always returns [`crate::Error::NotImplemented`].
    pub fn new(_encoder_dir: &std::path::Path) -> crate::Result<Self> {
        Err(crate::Error::NotImplemented(
            "onnx_whisper_transcriber.new (onnx-runtime feature disabled)",
        ))
    }

    /// Always returns [`crate::Error::NotImplemented`].
    pub fn new_with_paths(
        _encoder: &std::path::Path,
        _decoder: &std::path::Path,
        _tokenizer: &std::path::Path,
    ) -> crate::Result<Self> {
        Err(crate::Error::NotImplemented(
            "onnx_whisper_transcriber.new_with_paths (onnx-runtime feature disabled)",
        ))
    }
}

#[cfg(not(feature = "onnx-runtime"))]
impl WhisperTranscriber for OnnxWhisperTranscriber {
    fn transcribe(
        &self,
        _audio_data: &[u8],
        _mime_type: &str,
    ) -> crate::Result<TranscriptionResult> {
        Err(crate::Error::NotImplemented(
            "onnx_whisper_transcriber.transcribe (onnx-runtime feature disabled)",
        ))
    }
}

// Sanity check so `WHISPER_SAMPLE_RATE` is reachable for
// downstream callers that wire the ingest pipeline.
const _: u32 = WHISPER_SAMPLE_RATE;

// ---------------------------------------------------------------------------
// Tests — all pure-helper logic exercised on every host.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic added-tokens table with every Whisper
    /// special token at a fixed offset so the resolver tests
    /// can pin numeric ids.
    fn synthetic_added_tokens(timestamp_begin: u32) -> Vec<(String, u32)> {
        let mut t = vec![
            ("<|endoftext|>".to_string(), 50_256),
            ("<|startoftranscript|>".to_string(), 50_257),
            ("<|en|>".to_string(), 50_258),
            ("<|zh|>".to_string(), 50_259),
            ("<|de|>".to_string(), 50_260),
            ("<|es|>".to_string(), 50_261),
            ("<|translate|>".to_string(), 50_357),
            ("<|transcribe|>".to_string(), 50_358),
            ("<|notimestamps|>".to_string(), 50_362),
            ("<|nospeech|>".to_string(), 50_361),
        ];
        for i in 0..=1_500_u32 {
            t.push((format!("<|{:.2}|>", i as f32 * 0.02), timestamp_begin + i));
        }
        t
    }

    #[test]
    fn special_tokens_resolve_round_trip() {
        let timestamp_begin = 50_363;
        let added = synthetic_added_tokens(timestamp_begin);
        let resolved = WhisperSpecialTokens::resolve_from_added_tokens(&added)
            .expect("resolve must succeed for a complete vocab");
        assert_eq!(resolved.end_of_text, 50_256);
        assert_eq!(resolved.start_of_transcript, 50_257);
        assert_eq!(resolved.transcribe, 50_358);
        assert_eq!(resolved.translate, 50_357);
        assert_eq!(resolved.no_timestamps, 50_362);
        assert_eq!(resolved.no_speech, Some(50_361));
        assert_eq!(resolved.timestamp_begin, timestamp_begin);
        // 4 language tokens added in our fixture.
        assert_eq!(resolved.languages.len(), 4);
        assert_eq!(resolved.language_token("en"), Some(50_258));
        assert_eq!(resolved.language_token("zh"), Some(50_259));
        assert_eq!(resolved.language_token("zz"), None);
    }

    #[test]
    fn special_tokens_resolve_accepts_nocaptions_alias() {
        let timestamp_begin = 50_363;
        let mut added = synthetic_added_tokens(timestamp_begin);
        // Replace `<|nospeech|>` with the older `<|nocaptions|>`.
        added.retain(|(name, _)| name != "<|nospeech|>");
        added.push(("<|nocaptions|>".to_string(), 50_361));
        let resolved = WhisperSpecialTokens::resolve_from_added_tokens(&added).unwrap();
        assert_eq!(resolved.no_speech, Some(50_361));
    }

    #[test]
    fn special_tokens_resolve_tolerates_missing_nospeech() {
        let timestamp_begin = 50_363;
        let mut added = synthetic_added_tokens(timestamp_begin);
        added.retain(|(name, _)| name != "<|nospeech|>");
        let resolved = WhisperSpecialTokens::resolve_from_added_tokens(&added).unwrap();
        assert_eq!(resolved.no_speech, None);
    }

    #[test]
    fn special_tokens_resolve_rejects_missing_required_token() {
        let timestamp_begin = 50_363;
        let mut added = synthetic_added_tokens(timestamp_begin);
        // Drop the required `<|startoftranscript|>` token.
        added.retain(|(name, _)| name != "<|startoftranscript|>");
        let err = WhisperSpecialTokens::resolve_from_added_tokens(&added).unwrap_err();
        assert!(err.contains("startoftranscript"), "unexpected error: {err}");
    }

    #[test]
    fn special_tokens_resolve_rejects_empty_language_set() {
        // Vocabulary with all required control tokens but no
        // `<|lang|>` tokens at all — refused by design because
        // Whisper would have nothing to do.
        let added = vec![
            ("<|endoftext|>".to_string(), 50_256),
            ("<|startoftranscript|>".to_string(), 50_257),
            ("<|transcribe|>".to_string(), 50_358),
            ("<|translate|>".to_string(), 50_357),
            ("<|notimestamps|>".to_string(), 50_362),
            ("<|0.00|>".to_string(), 50_363),
        ];
        let err = WhisperSpecialTokens::resolve_from_added_tokens(&added).unwrap_err();
        assert!(err.contains("`<|lang|>`"), "unexpected error: {err}");
    }

    #[test]
    fn decoder_prefix_with_language_transcribe_no_timestamps() {
        let timestamp_begin = 50_363;
        let added = synthetic_added_tokens(timestamp_begin);
        let s = WhisperSpecialTokens::resolve_from_added_tokens(&added).unwrap();
        let prefix =
            build_decoder_prefix(&s, s.language_token("en"), WhisperTask::Transcribe, false);
        assert_eq!(
            prefix,
            vec![s.start_of_transcript, 50_258, s.transcribe, s.no_timestamps]
        );
    }

    #[test]
    fn decoder_prefix_translate_with_timestamps() {
        let timestamp_begin = 50_363;
        let added = synthetic_added_tokens(timestamp_begin);
        let s = WhisperSpecialTokens::resolve_from_added_tokens(&added).unwrap();
        let prefix = build_decoder_prefix(&s, s.language_token("zh"), WhisperTask::Translate, true);
        // With timestamps -> no `<|notimestamps|>` tail.
        assert_eq!(prefix, vec![s.start_of_transcript, 50_259, s.translate]);
    }

    #[test]
    fn decoder_prefix_omits_language_slot_when_none() {
        // Low-level escape hatch: `build_decoder_prefix` still
        // accepts `language = None` for callers that intend to
        // omit the slot. Production transcribe NEVER uses this
        // path — it pre-detects via `detect_language` and always
        // passes `Some(lang)`. The test pins the documented
        // escape-hatch behaviour.
        let timestamp_begin = 50_363;
        let added = synthetic_added_tokens(timestamp_begin);
        let s = WhisperSpecialTokens::resolve_from_added_tokens(&added).unwrap();
        let prefix = build_decoder_prefix(&s, None, WhisperTask::Transcribe, false);
        assert_eq!(
            prefix,
            vec![s.start_of_transcript, s.transcribe, s.no_timestamps]
        );
    }

    #[test]
    fn argmax_picks_max_logit_at_last_position() {
        // Sequence of length 2, vocab 5. Two prefix rows of zeros
        // and a final row whose maximum is at index 3.
        let mut logits = vec![0.0_f32; 2 * 5];
        logits[5 + 3] = 7.0;
        let pick = argmax_next_token(&logits, 2, 5, &[]).unwrap();
        assert_eq!(pick, 3);
    }

    #[test]
    fn argmax_ignores_suppressed_positions() {
        // Final row has its max at index 4 but 4 is suppressed,
        // second-max at index 1.
        let mut logits = vec![0.0_f32; 5];
        logits[1] = 3.0;
        logits[4] = 9.9;
        let pick = argmax_next_token(&logits, 1, 5, &[4]).unwrap();
        assert_eq!(pick, 1);
    }

    #[test]
    fn argmax_returns_none_when_all_suppressed() {
        let logits = vec![0.0_f32; 5];
        let pick = argmax_next_token(&logits, 1, 5, &[0, 1, 2, 3, 4]);
        assert_eq!(pick, None);
    }

    #[test]
    fn argmax_rejects_short_logits_buffer() {
        // Caller declares seq_len = 3, vocab_size = 4 (12
        // elements expected), but we only pass 8 — must
        // return None instead of panicking.
        let logits = vec![0.0_f32; 8];
        let pick = argmax_next_token(&logits, 3, 4, &[]);
        assert_eq!(pick, None);
    }

    #[test]
    fn argmax_language_token_picks_highest_scoring_language() {
        // Vocab of 12. Language tokens at ids {3, 7, 10}.
        // Whisper would put `<|en|>` at the highest logit
        // (here id 7, score 5.0); plain content tokens have
        // higher absolute scores but must be ignored because
        // they're not in `language_token_ids`.
        let mut row = vec![0.0_f32; 12];
        row[0] = 9.9; // content
        row[3] = 2.0; // language
        row[5] = 8.5; // content
        row[7] = 5.0; // language — winner
        row[10] = 1.0; // language
        let pick = argmax_language_token(&row, &[3, 7, 10]).unwrap();
        assert_eq!(pick, 7);
    }

    #[test]
    fn argmax_language_token_returns_none_for_empty_inputs() {
        assert_eq!(argmax_language_token(&[], &[3, 7]), None);
        assert_eq!(argmax_language_token(&[1.0, 2.0, 3.0], &[]), None);
    }

    #[test]
    fn argmax_language_token_skips_ids_past_logits_row() {
        // ids 3 and 100 both reference into a 5-wide row;
        // id 100 is past the row and must be silently skipped
        // (defensive — vocab mismatches should not panic).
        let row = vec![0.0_f32, 1.0, 2.0, 7.0, 3.0];
        let pick = argmax_language_token(&row, &[3, 100]).unwrap();
        assert_eq!(pick, 3);
    }

    #[test]
    fn argmax_language_token_returns_none_when_every_id_out_of_range() {
        let row = vec![0.0_f32; 5];
        // Every candidate is past the row → no in-range
        // language id → None.
        assert_eq!(argmax_language_token(&row, &[10, 20, 30]), None);
    }

    #[test]
    fn timestamp_token_to_ms_rejects_below_anchor() {
        assert_eq!(timestamp_token_to_ms(50_360, 50_363), None);
    }

    #[test]
    fn timestamp_token_to_ms_rejects_above_max_window() {
        assert_eq!(timestamp_token_to_ms(50_363 + 1_501, 50_363), None);
    }

    #[test]
    fn timestamp_token_to_ms_returns_milliseconds() {
        assert_eq!(timestamp_token_to_ms(50_363, 50_363), Some(0));
        assert_eq!(timestamp_token_to_ms(50_363 + 1, 50_363), Some(20));
        assert_eq!(timestamp_token_to_ms(50_363 + 50, 50_363), Some(1_000));
        assert_eq!(timestamp_token_to_ms(50_363 + 1_500, 50_363), Some(30_000));
    }

    #[test]
    fn segments_from_tokens_pairs_timestamps_into_segments() {
        // Stream: <|0.00|> A B <|1.00|> <|1.00|> C D <|2.00|> <|eot|>
        let timestamp_begin: u32 = 50_363;
        let end_of_text: u32 = 50_256;
        let stream = vec![
            timestamp_begin,
            1_001,
            1_002,
            timestamp_begin + 50, // 1.00 s
            timestamp_begin + 50,
            2_001,
            2_002,
            timestamp_begin + 100, // 2.00 s
            end_of_text,
        ];
        // Trivial decoder: maps each id to "tNNNN" so we can
        // assert what the segment body decoded to.
        let segments = segments_from_tokens(&stream, timestamp_begin, end_of_text, |body| {
            body.iter()
                .map(|t| format!("t{t}"))
                .collect::<Vec<_>>()
                .join(" ")
        });
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].start_ms, 0);
        assert_eq!(segments[0].end_ms, 1_000);
        assert_eq!(segments[0].text, "t1001 t1002");
        assert_eq!(segments[1].start_ms, 1_000);
        assert_eq!(segments[1].end_ms, 2_000);
        assert_eq!(segments[1].text, "t2001 t2002");
    }

    #[test]
    fn segments_from_tokens_flushes_unclosed_tail() {
        // Stream truncated mid-segment: <|0.00|> A B <|eot|>
        let timestamp_begin: u32 = 50_363;
        let end_of_text: u32 = 50_256;
        let stream = vec![timestamp_begin, 1_001, 1_002, end_of_text];
        let segments = segments_from_tokens(&stream, timestamp_begin, end_of_text, |body| {
            body.iter()
                .map(|t| format!("t{t}"))
                .collect::<Vec<_>>()
                .join(" ")
        });
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].start_ms, 0);
        assert_eq!(segments[0].end_ms, 0);
        assert_eq!(segments[0].text, "t1001 t1002");
    }

    #[test]
    fn segments_from_tokens_returns_empty_for_empty_stream() {
        let segments = segments_from_tokens(&[], 50_363, 50_256, |_| String::new());
        assert!(segments.is_empty());
    }

    #[test]
    fn segments_from_tokens_skips_empty_body_segments() {
        // Stream with timestamp pair but no body tokens — should
        // not produce a segment.
        let timestamp_begin: u32 = 50_363;
        let end_of_text: u32 = 50_256;
        let stream = vec![timestamp_begin, timestamp_begin + 10, end_of_text];
        let segments = segments_from_tokens(&stream, timestamp_begin, end_of_text, |_| {
            String::new() // empty decode result
        });
        assert!(segments.is_empty());
    }

    #[test]
    fn whisper_constants_match_audio_module() {
        // WHISPER_ENCODER_FRAMES must be exactly half the
        // preprocessing frame count.
        assert_eq!(WHISPER_ENCODER_FRAMES, WHISPER_N_FRAMES / 2);
        assert_eq!(WHISPER_TIMESTAMP_STEP_MS, 20);
        // The 99 language codes plus `nospeech` get tested
        // structurally — `en` MUST appear first and the array
        // MUST not have duplicates.
        assert_eq!(WHISPER_LANGUAGE_CODES[0], "en");
        let mut sorted: Vec<&str> = WHISPER_LANGUAGE_CODES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            WHISPER_LANGUAGE_CODES.len(),
            "WHISPER_LANGUAGE_CODES contains duplicates"
        );
        assert_eq!(
            WHISPER_LANGUAGE_CODES.len(),
            99,
            "Whisper supports 99 languages"
        );
    }

    // ---- Stub-only tests (feature off) ----

    #[cfg(not(feature = "onnx-runtime"))]
    #[test]
    fn stub_new_reports_feature_gate() {
        let err =
            OnnxWhisperTranscriber::new(&std::path::PathBuf::from("/nonexistent")).unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }

    #[cfg(not(feature = "onnx-runtime"))]
    #[test]
    fn stub_transcribe_reports_feature_gate() {
        let stub = OnnxWhisperTranscriber;
        let err = stub.transcribe(b"audio", "audio/wav").unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }
}
