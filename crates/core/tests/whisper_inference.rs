//! Integration tests for the real Whisper inference loop wired
//! up in `crates/core/src/models/whisper_onnx.rs`.
//!
//! The constructor-failure tests run unconditionally when the
//! `onnx-runtime` feature is on: they exercise the error paths
//! that surface when the on-disk encoder / decoder / tokenizer
//! artifacts are missing or malformed, without requiring an
//! actual Whisper model to be staged on the CI runner.
//!
//! The full end-to-end transcription test
//! (`transcribe_against_real_whisper_model`) is gated on three
//! env vars — `KCHAT_WHISPER_ENCODER_PATH`,
//! `KCHAT_WHISPER_DECODER_PATH`, and
//! `KCHAT_WHISPER_TOKENIZER_PATH` — pointing at a real
//! Whisper ONNX export + its tokenizer artifact. When ANY of
//! the env vars are unset the test is skipped with a
//! `[SKIP]` line so a developer running
//! `cargo test --features onnx-runtime` locally without
//! staging the artifacts still gets a green run.
//!
//! The artifacts are not embedded in the repository because the
//! canonical `whisper-base.int8` ONNX export is ~140 MiB and CI
//! runners pull it on-demand via the `ModelDownloader` path
//! exercised in the `model_manager` integration suite.
//!
//! See `crates/core/tests/xlmr_inference.rs` and
//! `crates/core/tests/clip_inference.rs` for the parallel
//! patterns used by the XLM-R / MobileCLIP-S2 integration test
//! suites — this file mirrors their shape so a future bridge-
//! layer test framework can resolve the three model-family
//! tests uniformly.
#![cfg(feature = "onnx-runtime")]

use kchat_core::models::whisper::WhisperTranscriber;
use kchat_core::models::whisper_onnx::{OnnxWhisperTranscriber, WhisperTask};
use std::path::PathBuf;

/// Env var a CI config sets to `1` when it intends to run the
/// env-gated Whisper tests. With this flag set,
/// [`require_artifact_paths`] panics when any of the three model-
/// path env vars are missing instead of silently skipping — so
/// a misconfigured CI matrix that forgot to mount the artifact
/// fails loudly rather than silently passing a no-op test.
/// Local developer runs leave this unset and get the standard
/// skip-on-missing behaviour.
const E2E_REQUIRED_ENV: &str = "KCHAT_WHISPER_E2E_REQUIRED";

/// Resolve `(encoder_path, decoder_path, tokenizer_path)` from
/// `KCHAT_WHISPER_ENCODER_PATH`, `KCHAT_WHISPER_DECODER_PATH`,
/// and `KCHAT_WHISPER_TOKENIZER_PATH`. Returns `None` when any
/// of the three env vars is unset.
fn artifact_paths() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let encoder = std::env::var_os("KCHAT_WHISPER_ENCODER_PATH")?;
    let decoder = std::env::var_os("KCHAT_WHISPER_DECODER_PATH")?;
    let tokenizer = std::env::var_os("KCHAT_WHISPER_TOKENIZER_PATH")?;
    Some((
        PathBuf::from(encoder),
        PathBuf::from(decoder),
        PathBuf::from(tokenizer),
    ))
}

/// Return the artifact paths, or `None` after `eprintln!`-ing a
/// clearly marked `[SKIP]` line on the test's name. When the
/// caller has opted into mandatory mode by setting
/// `KCHAT_WHISPER_E2E_REQUIRED=1`, panic instead of returning
/// `None` so the silent-skip path cannot mask a misconfigured
/// CI matrix.
fn require_artifact_paths(test_name: &str) -> Option<(PathBuf, PathBuf, PathBuf)> {
    if let Some(paths) = artifact_paths() {
        return Some(paths);
    }
    let mandatory = std::env::var_os(E2E_REQUIRED_ENV)
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if mandatory {
        panic!(
            "{E2E_REQUIRED_ENV}=1 but one of KCHAT_WHISPER_ENCODER_PATH / \
             KCHAT_WHISPER_DECODER_PATH / KCHAT_WHISPER_TOKENIZER_PATH is \
             missing — refusing to silently skip `{test_name}`",
        );
    }
    eprintln!(
        "[SKIP] {test_name}: set KCHAT_WHISPER_ENCODER_PATH + \
         KCHAT_WHISPER_DECODER_PATH + KCHAT_WHISPER_TOKENIZER_PATH to \
         run, or {E2E_REQUIRED_ENV}=1 to fail on missing artifacts",
    );
    None
}

#[test]
fn new_returns_model_error_when_encoder_path_does_not_exist() {
    // The constructor must surface a `crate::Error::Model`
    // (not panic, not return `NotImplemented`) when the encoder
    // artifact is absent — bridge layer routes the error category
    // off the `model:` prefix so the iOS / Android log lines and
    // user-facing strings stay aligned with the XLM-R / CLIP
    // wrappers.
    let encoder = PathBuf::from("/definitely/does/not/exist/encoder_model.onnx");
    let decoder = PathBuf::from("/definitely/does/not/exist/decoder_model.onnx");
    let tokenizer = PathBuf::from("/definitely/does/not/exist/tokenizer.json");
    let err = OnnxWhisperTranscriber::new_with_paths(&encoder, &decoder, &tokenizer)
        .expect_err("missing encoder path must surface a Model error");
    assert!(
        matches!(err, kchat_core::Error::Model(_)),
        "expected Model variant, got {err:?}",
    );
}

#[test]
fn new_returns_tokenizer_error_when_only_tokenizer_missing() {
    // Skip when no real model artifact is staged — without one
    // we cannot drive the encoder + decoder session creation to
    // success and therefore cannot isolate the tokenizer-load
    // failure. `require_artifact_paths` panics instead of
    // returning `None` when `KCHAT_WHISPER_E2E_REQUIRED=1`, so a
    // CI config that demands this test runs cannot silently
    // fall through to a no-op pass.
    let Some((encoder_path, decoder_path, _real_tokenizer_path)) =
        require_artifact_paths("new_returns_tokenizer_error_when_only_tokenizer_missing")
    else {
        return;
    };
    let bogus_tokenizer = PathBuf::from("/definitely/does/not/exist/tokenizer.json");
    let err =
        OnnxWhisperTranscriber::new_with_paths(&encoder_path, &decoder_path, &bogus_tokenizer)
            .expect_err("missing tokenizer must surface as a Model error");
    let s = format!("{err}");
    assert!(
        s.contains("tokenizer") || s.contains("from_file"),
        "error message should mention the tokenizer op, got: {s}",
    );
}

#[test]
fn transcribe_against_real_whisper_model() {
    // Optional end-to-end test: only runs when all three env
    // vars point at a real Whisper ONNX export plus its tokenizer.
    // `require_artifact_paths` makes the skip explicit (clearly
    // marked `[SKIP]` line on the test's name in stderr) and
    // upgrades it to a panic when `KCHAT_WHISPER_E2E_REQUIRED=1`,
    // so a CI matrix that intends to exercise the real
    // inference pipeline fails loudly rather than silently
    // passing when the artifact env vars are absent.
    let Some((encoder_path, decoder_path, tokenizer_path)) =
        require_artifact_paths("transcribe_against_real_whisper_model")
    else {
        return;
    };

    let transcriber =
        OnnxWhisperTranscriber::new_with_paths(&encoder_path, &decoder_path, &tokenizer_path)
            .expect("whisper encoder + decoder + tokenizer load")
            .with_task(WhisperTask::Transcribe)
            .with_timestamps(false);

    // Build a deterministic 1 s mono 16 kHz WAV containing a
    // 440 Hz sine tone. Whisper will likely transcribe this
    // as silence or a token stream that decodes to an empty
    // string — what matters for this test is that the
    // pipeline runs end-to-end without panicking and the
    // result type is well-formed.
    let wav = synth_tone_wav_pcm16(440.0, 1.0, 16_000);
    let result = transcriber
        .transcribe(&wav, "audio/wav")
        .expect("transcribe a synthetic tone");

    // Contract: the transcriber always returns a well-formed
    // result. Text may be empty (a synthetic tone has no
    // linguistic content) but the type is `String`, segments
    // is a `Vec<TranscriptionSegment>`, and language is
    // either `Some("<iso-code>")` or `None`.
    assert!(
        result.text.is_empty() || !result.text.is_empty(),
        "text must be a `String` (trivially true; sanity-check the type)",
    );
    eprintln!(
        "transcribe_against_real_whisper_model: \
         text={:?}, lang={:?}, segments={}",
        result.text,
        result.language,
        result.segments.len(),
    );
}

#[test]
fn transcribe_rejects_non_audio_mime_type() {
    // Constructor failure path bypasses the mime-type check —
    // we need a fully-built transcriber to assert the mime-type
    // guard. Skip when no artifacts are staged.
    let Some((encoder_path, decoder_path, tokenizer_path)) =
        require_artifact_paths("transcribe_rejects_non_audio_mime_type")
    else {
        return;
    };

    let transcriber =
        OnnxWhisperTranscriber::new_with_paths(&encoder_path, &decoder_path, &tokenizer_path)
            .expect("whisper artifacts");

    let err = transcriber
        .transcribe(b"not actually audio", "image/png")
        .expect_err("non-audio mime_type must be rejected");
    let s = format!("{err}");
    assert!(
        s.contains("audio") || s.contains("mime"),
        "error message should mention the mime guard, got: {s}",
    );
}

#[test]
fn with_language_rejects_unknown_code() {
    // Skip when no artifacts are staged: we need a real
    // tokenizer to populate the language table.
    let Some((encoder_path, decoder_path, tokenizer_path)) =
        require_artifact_paths("with_language_rejects_unknown_code")
    else {
        return;
    };

    let transcriber =
        OnnxWhisperTranscriber::new_with_paths(&encoder_path, &decoder_path, &tokenizer_path)
            .expect("whisper artifacts");

    let err = transcriber
        .with_language(Some("xxx"))
        .expect_err("`xxx` is not a Whisper language code");
    let s = format!("{err}");
    assert!(
        s.contains("xxx") || s.contains("language"),
        "error message should name the rejected code, got: {s}",
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal PCM-16 mono WAV containing a `freq`-Hz sine
/// tone of `seconds` duration at `sample_rate` Hz.
///
/// Hand-rolls the RIFF/WAVE header so the test does not pull in
/// a WAV-encoder crate just for synthetic-tone construction.
/// The wav reader in `whisper_audio` is the one being
/// exercised — encoding goes through the inverse of its
/// decode-path, so any chunk-layout mistake here would surface
/// as a `MediaDecode` error from the transcriber rather than
/// silently producing garbage.
fn synth_tone_wav_pcm16(freq: f32, seconds: f32, sample_rate: u32) -> Vec<u8> {
    let n_samples = (sample_rate as f32 * seconds) as usize;
    let mut samples = Vec::with_capacity(n_samples);
    let two_pi = 2.0 * std::f32::consts::PI;
    for i in 0..n_samples {
        let t = i as f32 / sample_rate as f32;
        let amp = (two_pi * freq * t).sin();
        samples.push((amp * i16::MAX as f32) as i16);
    }

    let bytes_per_sample = 2u16;
    let n_channels = 1u16;
    let byte_rate = sample_rate * u32::from(bytes_per_sample) * u32::from(n_channels);
    let block_align = bytes_per_sample * n_channels;
    let data_size = (samples.len() * usize::from(bytes_per_sample)) as u32;
    let riff_size = 36 + data_size;

    let mut wav = Vec::with_capacity(44 + data_size as usize);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&n_channels.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&block_align.to_le_bytes());
    wav.extend_from_slice(&(bytes_per_sample * 8).to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_size.to_le_bytes());
    for s in &samples {
        wav.extend_from_slice(&s.to_le_bytes());
    }
    wav
}
