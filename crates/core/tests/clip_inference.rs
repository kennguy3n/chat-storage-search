//! End-to-end MobileCLIP-S2 image inference smoke tests.
//!
//! These tests exercise the **real**
//! [`kchat_core::models::clip::OnnxImageEmbedder`] inference
//! loop end-to-end: decode a tiny in-memory PNG / JPEG →
//! shorter-edge resize → centre crop → CHW float32 normalise →
//! `session.run` → L2-normalise.
//!
//! They require a real MobileCLIP-S2 `.onnx` artifact on disk
//! (the prebuilt download from Apple's `apple/ml-mobileclip`
//! release page, re-exported to ONNX via
//! `mobileclip_export_onnx.py`). Default behaviour is **skip
//! with `eprintln!`** when the artifact path env var is not
//! set, so the test does not break developer machines that
//! lack the model. Setting `KCHAT_CLIP_E2E_REQUIRED=1`
//! upgrades the skip to a **panic** so CI runs targeting the
//! e2e environment surface the missing artifact instead of
//! silently masking it.
//!
//! Env vars:
//!
//! * `KCHAT_CLIP_MODEL_PATH` — path to the MobileCLIP-S2
//!   `.onnx` file (required for the test body to run).
//! * `KCHAT_CLIP_INPUT_NAME` — optional override for the
//!   ONNX input tensor name; defaults to
//!   [`MOBILECLIP_DEFAULT_INPUT_NAME`].
//! * `KCHAT_CLIP_E2E_REQUIRED` — when set to `1` / `true`,
//!   missing env vars or artifacts become hard failures.
//!
//! This mirrors the env-gated pattern used by the XLM-R
//! integration tests (`xlmr_inference.rs`) so both encoders
//! have a uniform on-ramp for opt-in artifact-based testing.

#![cfg(feature = "onnx-runtime")]

use std::env;
use std::io::Cursor;
use std::path::PathBuf;

use kchat_core::models::clip::{
    ImageEmbedder, OnnxImageEmbedder, MOBILECLIP_DEFAULT_INPUT_NAME, MOBILECLIP_S2_EMBEDDING_DIM,
};

/// Returns `Some(PathBuf)` when the model env var is set and
/// the artifact exists, or `None` (with an `eprintln!`) when
/// the test should skip. Panics if `KCHAT_CLIP_E2E_REQUIRED=1`
/// is set and the artifact is missing.
fn resolve_model_path() -> Option<PathBuf> {
    let required = env::var("KCHAT_CLIP_E2E_REQUIRED")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false);
    let Ok(raw) = env::var("KCHAT_CLIP_MODEL_PATH") else {
        if required {
            panic!(
                "KCHAT_CLIP_E2E_REQUIRED=1 but KCHAT_CLIP_MODEL_PATH is not set; \
                 cannot run end-to-end MobileCLIP-S2 inference test"
            );
        }
        eprintln!(
            "skipping clip_inference e2e: KCHAT_CLIP_MODEL_PATH not set \
             (set KCHAT_CLIP_E2E_REQUIRED=1 to upgrade this skip to a panic)"
        );
        return None;
    };
    let path = PathBuf::from(raw);
    if !path.exists() {
        if required {
            panic!(
                "KCHAT_CLIP_E2E_REQUIRED=1 but KCHAT_CLIP_MODEL_PATH points at a missing file: {}",
                path.display()
            );
        }
        eprintln!(
            "skipping clip_inference e2e: KCHAT_CLIP_MODEL_PATH points at a missing file: {}",
            path.display()
        );
        return None;
    }
    Some(path)
}

/// Build a tiny in-memory test image (32×32 magenta) as PNG.
///
/// MobileCLIP-S2's preprocessing handles the upsample to 256
/// shorter-edge then centre crop to 224×224, so a 32×32 input
/// is fine — the embedding will not be visually meaningful but
/// the inference loop exercises every stage.
fn synth_png() -> Vec<u8> {
    let mut buf = Vec::new();
    let img: image::RgbImage =
        image::ImageBuffer::from_fn(32, 32, |_x, _y| image::Rgb([200, 30, 200]));
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
        .expect("encode synthetic png");
    buf
}

#[test]
fn embeds_a_synthetic_png_and_returns_unit_vector() {
    let Some(path) = resolve_model_path() else {
        return;
    };
    let mut emb = OnnxImageEmbedder::new(&path).expect("construct OnnxImageEmbedder");
    if let Ok(name) = env::var("KCHAT_CLIP_INPUT_NAME") {
        emb = emb.with_input_name(name);
    }
    // Provider report should reflect *some* registered EP; the
    // exact provider depends on the host (DirectML on Windows,
    // CPU elsewhere).
    let report = emb.provider_report();
    eprintln!(
        "clip e2e: input_name={:?}, provider={:?}, directml_attempted={}",
        emb.input_name(),
        report.provider,
        report.directml_attempted
    );

    let png = synth_png();
    let v = emb
        .embed_image(&png, "image/png")
        .expect("MobileCLIP-S2 inference must succeed on a valid PNG");

    assert_eq!(
        v.len(),
        MOBILECLIP_S2_EMBEDDING_DIM,
        "MobileCLIP-S2 output length must equal the documented dim"
    );
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!(
        (norm - 1.0).abs() < 1e-3,
        "embedding must be L2-normalised; got norm={norm}"
    );
    assert!(
        v.iter().all(|x| x.is_finite()),
        "all components must be finite"
    );
}

#[test]
fn distinct_images_produce_distinct_embeddings() {
    let Some(path) = resolve_model_path() else {
        return;
    };
    let mut emb = OnnxImageEmbedder::new(&path).expect("construct OnnxImageEmbedder");
    if let Ok(name) = env::var("KCHAT_CLIP_INPUT_NAME") {
        emb = emb.with_input_name(name);
    }

    // Two visually distinct synthetic images: pure magenta
    // vs. pure cyan. MobileCLIP-S2's contrastive training
    // ensures these land far apart on the embedding manifold.
    let magenta = {
        let mut buf = Vec::new();
        let img: image::RgbImage =
            image::ImageBuffer::from_pixel(64, 64, image::Rgb([200, 30, 200]));
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
            .expect("encode magenta png");
        buf
    };
    let cyan = {
        let mut buf = Vec::new();
        let img: image::RgbImage =
            image::ImageBuffer::from_pixel(64, 64, image::Rgb([30, 200, 200]));
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
            .expect("encode cyan png");
        buf
    };

    let a = emb
        .embed_image(&magenta, "image/png")
        .expect("magenta embed");
    let b = emb.embed_image(&cyan, "image/png").expect("cyan embed");

    // Cosine similarity of two distinct images should be
    // strictly less than 1.0 (and in practice well below
    // ~0.99 for these very different inputs).
    let cos: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    assert!(
        cos.is_finite(),
        "cosine similarity must be finite; got {cos}"
    );
    assert!(
        cos < 0.999,
        "magenta vs cyan should not be near-identical; got cos={cos}"
    );
}

#[test]
fn rejects_non_image_mime_with_typed_error() {
    let Some(path) = resolve_model_path() else {
        return;
    };
    let emb = OnnxImageEmbedder::new(&path).expect("construct OnnxImageEmbedder");
    let err = emb
        .embed_image(b"not actually an image", "text/plain")
        .expect_err("non-image/* mime must surface a typed error");
    assert!(matches!(err, kchat_core::Error::Model(_)));
}

#[test]
fn default_input_name_constant_matches_apple_export_convention() {
    // Hard pin so a future refactor doesn't silently switch
    // the default input name to something Apple's reference
    // export pipeline does not produce.
    assert_eq!(MOBILECLIP_DEFAULT_INPUT_NAME, "pixel_values");
}
