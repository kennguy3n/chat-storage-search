//! Integration tests for the real XLM-R inference loop wired up
//! in `crates/core/src/models/embeddings_onnx.rs`.
//!
//! The constructor-failure tests run unconditionally when the
//! `onnx-runtime` feature is on: they exercise the error paths
//! that surface when the on-disk `.onnx` or `tokenizer.json`
//! artifact is missing or malformed, without requiring an actual
//! XLM-R model to be staged on the CI runner.
//!
//! The full end-to-end inference test
//! (`embed_text_against_real_xlmr_model`) is gated on two env
//! vars — `KCHAT_XLMR_MODEL_PATH` and
//! `KCHAT_XLMR_TOKENIZER_PATH` — pointing at a real XLM-R ONNX
//! export + its tokenizer artifact. When the env vars are unset
//! the test is skipped with a `println!` so a developer running
//! `cargo test --features onnx-runtime` locally without staging
//! the artifact still gets a green run rather than a confusing
//! file-not-found failure. The artifact is not embedded in the
//! repository because the canonical XLM-R INT8 model is ~50 MiB
//! and CI runners pull it on-demand via the `ModelDownloader`
//! path exercised in the `model_manager` integration suite.
#![cfg(feature = "onnx-runtime")]

use kchat_core::models::embeddings::XLMR_EMBEDDING_DIM;
use kchat_core::models::embeddings_onnx::OnnxTextEmbedder;
use std::path::PathBuf;

/// Env var a CI config sets to `1` when it intends to run the env-gated
/// XLM-R tests. With this flag set, [`require_artifact_paths`] panics
/// when `KCHAT_XLMR_MODEL_PATH` or `KCHAT_XLMR_TOKENIZER_PATH` is
/// missing instead of skipping — so a misconfigured CI matrix that
/// forgot to mount the artifact fails loudly rather than silently
/// passing a no-op test. Local developer runs leave this unset and
/// get the standard skip-on-missing behaviour.
const E2E_REQUIRED_ENV: &str = "KCHAT_XLMR_E2E_REQUIRED";

/// Resolve `(model_path, tokenizer_path)` from `KCHAT_XLMR_MODEL_PATH`
/// and `KCHAT_XLMR_TOKENIZER_PATH`. Returns `None` when either env var
/// is unset; the test caller decides whether to skip (default) or fail
/// (when `KCHAT_XLMR_E2E_REQUIRED=1` makes the test mandatory).
fn artifact_paths() -> Option<(PathBuf, PathBuf)> {
    let model = std::env::var_os("KCHAT_XLMR_MODEL_PATH")?;
    let tokenizer = std::env::var_os("KCHAT_XLMR_TOKENIZER_PATH")?;
    Some((PathBuf::from(model), PathBuf::from(tokenizer)))
}

/// Return the artifact paths, or `None` after `eprintln!`-ing a clearly
/// marked `[SKIP]` line on the test's name. When the caller has opted
/// into mandatory mode by setting `KCHAT_XLMR_E2E_REQUIRED=1`, panic
/// instead of returning `None` so the silent-skip path cannot mask a
/// misconfigured CI matrix.
fn require_artifact_paths(test_name: &str) -> Option<(PathBuf, PathBuf)> {
    if let Some(paths) = artifact_paths() {
        return Some(paths);
    }
    let mandatory = std::env::var_os(E2E_REQUIRED_ENV)
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if mandatory {
        panic!(
            "{E2E_REQUIRED_ENV}=1 but KCHAT_XLMR_MODEL_PATH / \
             KCHAT_XLMR_TOKENIZER_PATH are missing — refusing to \
             silently skip `{test_name}`",
        );
    }
    eprintln!(
        "[SKIP] {test_name}: set KCHAT_XLMR_MODEL_PATH + \
         KCHAT_XLMR_TOKENIZER_PATH to run, or {E2E_REQUIRED_ENV}=1 to \
         fail on missing artifacts",
    );
    None
}

#[test]
fn new_returns_model_error_when_model_path_does_not_exist() {
    // The constructor must surface a `crate::Error::Model`
    // (not panic, not return `NotImplemented`) when the model
    // artifact is absent — bridge layer routes the error category
    // off the `model:` prefix so the iOS / Android log lines and
    // user-facing strings stay aligned.
    let err = OnnxTextEmbedder::new(&PathBuf::from(
        "/definitely/does/not/exist/xlmr-v1-int8.onnx",
    ))
    .expect_err("missing model path must surface a Model error");
    assert!(
        matches!(err, kchat_core::Error::Model(_)),
        "expected Model variant, got {err:?}",
    );
}

#[test]
fn new_with_tokenizer_returns_model_error_when_tokenizer_path_does_not_exist() {
    // Same contract as the model-path case: a missing tokenizer
    // artifact must surface as a Model error (specifically a
    // ModelError::Tokenizer variant once we have a real model
    // path to load past the session-create step) rather than a
    // panic or NotImplemented.
    let model = PathBuf::from("/definitely/does/not/exist/xlmr.onnx");
    let tok = PathBuf::from("/definitely/does/not/exist/tokenizer.json");
    let err = OnnxTextEmbedder::new_with_tokenizer(&model, &tok)
        .expect_err("missing tokenizer + model must surface a Model error");
    assert!(
        matches!(err, kchat_core::Error::Model(_)),
        "expected Model variant, got {err:?}",
    );
}

#[test]
fn new_with_tokenizer_returns_tokenizer_error_when_only_tokenizer_missing() {
    // Skip when no real model artifact is staged — without one
    // we cannot drive the session-create step to success and
    // therefore cannot isolate the tokenizer-load failure.
    // `require_artifact_paths` panics instead of returning `None`
    // when `KCHAT_XLMR_E2E_REQUIRED=1`, so a CI config that demands
    // this test runs cannot silently fall through to a no-op pass.
    let Some((model_path, _real_tokenizer_path)) = require_artifact_paths(
        "new_with_tokenizer_returns_tokenizer_error_when_only_tokenizer_missing",
    ) else {
        return;
    };
    let bogus_tokenizer = PathBuf::from("/definitely/does/not/exist/tokenizer.json");
    let err = OnnxTextEmbedder::new_with_tokenizer(&model_path, &bogus_tokenizer)
        .expect_err("missing tokenizer must surface as a Model error");
    let s = format!("{err}");
    assert!(
        s.contains("tokenizer") || s.contains("from_file"),
        "error message should mention the tokenizer op, got: {s}",
    );
}

#[test]
fn embed_text_against_real_xlmr_model() {
    // Optional end-to-end test: only runs when both env vars
    // point at a real XLM-R ONNX export and its tokenizer.
    // `require_artifact_paths` makes the skip explicit (clearly
    // marked `[SKIP]` line on the test's name in stderr) and
    // upgrades it to a panic when `KCHAT_XLMR_E2E_REQUIRED=1`, so a
    // CI matrix that intends to exercise the real inference pipeline
    // fails loudly rather than silently passing when the artifact
    // env vars are absent.
    let Some((model_path, tokenizer_path)) =
        require_artifact_paths("embed_text_against_real_xlmr_model")
    else {
        return;
    };

    let embedder = OnnxTextEmbedder::new_with_tokenizer(&model_path, &tokenizer_path)
        .expect("xlmr session + tokenizer load")
        .with_max_length(64);

    let v_a = embedder.embed_text("Hello, world!").expect("embed a");
    let v_b = embedder.embed_text("Hello, world!").expect("embed b");

    // Contract: dimension matches the rest of the search pipeline,
    // determinism is end-to-end, and the embedding is L2-normalised.
    assert_eq!(v_a.len(), XLMR_EMBEDDING_DIM);
    assert_eq!(v_a, v_b, "XLM-R inference must be deterministic");
    let norm: f32 = v_a.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!(
        (norm - 1.0).abs() < 1e-4,
        "embedding must be L2-normalised; got norm {norm}",
    );

    // Different inputs produce different embeddings — pins the
    // tokenizer + session round-trip and catches a "loop
    // returns constant" regression.
    let v_c = embedder
        .embed_text("totally unrelated text")
        .expect("embed c");
    assert_ne!(
        v_a, v_c,
        "different inputs must produce different embeddings"
    );
}
