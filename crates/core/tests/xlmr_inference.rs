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

/// Returns `(model_path, tokenizer_path)` from env vars, or
/// `None` if either is unset. Centralised so the optional
/// integration test stays terse.
fn artifact_paths() -> Option<(PathBuf, PathBuf)> {
    let model = std::env::var_os("KCHAT_XLMR_MODEL_PATH")?;
    let tokenizer = std::env::var_os("KCHAT_XLMR_TOKENIZER_PATH")?;
    Some((PathBuf::from(model), PathBuf::from(tokenizer)))
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
    let Some((model_path, _real_tokenizer_path)) = artifact_paths() else {
        eprintln!(
            "skipping new_with_tokenizer_returns_tokenizer_error_when_only_tokenizer_missing — \
             set KCHAT_XLMR_MODEL_PATH + KCHAT_XLMR_TOKENIZER_PATH to run"
        );
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
    let Some((model_path, tokenizer_path)) = artifact_paths() else {
        eprintln!(
            "skipping embed_text_against_real_xlmr_model — \
             set KCHAT_XLMR_MODEL_PATH + KCHAT_XLMR_TOKENIZER_PATH to run"
        );
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
