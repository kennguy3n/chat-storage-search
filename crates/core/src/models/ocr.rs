//! Platform OCR bridge.
//!
//! `docs/DESIGN.md §7.6` calls for on-device OCR routed through
//! the platform-native vision stacks (Apple `VNRecognizeText`, ML
//! Kit on Android, `Windows.Media.Ocr` / Tesseract on Windows).
//! Those backends live outside the Rust core, so this module
//! defines the [`OcrBridge`] trait — an object-safe `Send + Sync`
//! seam that the platform glue (Swift / Kotlin / C++) implements.
//!
//! The trait surface is deliberately thin: one input (image bytes
//! plus MIME type) and one output (a vector of [`OcrResult`]).
//! The caller is responsible for fanning the recognized text out
//! into the `media_search_index` table (see
//! [`crate::local_store::db::LocalStoreDb::insert_media_search_index`]).
//!
//! Adds resource gating in front of the bridge call (see
//! [`crate::models::resource_gate::ResourceGate::should_run_ocr`]).
//! For now the gating decision is the orchestrator's
//! responsibility.

use crate::Result;

/// One recognized-text region produced by an [`OcrBridge`] call.
///
/// `text` is the recognized string. `language` is a BCP-47 tag
/// when the platform reports it (e.g. `"en"`, `"zh-Hans"`,
/// `"ja"`); `None` means the platform did not detect a language
/// or the bridge does not surface that capability.
/// `confidence` is in `[0.0, 1.0]`.
#[derive(Debug, Clone, PartialEq)]
pub struct OcrResult {
    /// Recognized text for this region.
    pub text: String,
    /// Detected language as a BCP-47 tag, when the platform
    /// surfaces one.
    pub language: Option<String>,
    /// Per-region confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Optional bounding box in image-pixel space.
    pub bounding_box: Option<BoundingBox>,
}

/// Image-pixel-space bounding box for an [`OcrResult`].
///
/// Coordinates are top-left-origin in the same coordinate space
/// as the input image (i.e. `(x, y)` is the top-left corner and
/// `(width, height)` extends right / down). Stored as `f32` so
/// platforms that report sub-pixel anchors (e.g. iOS Vision)
/// don't lose precision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BoundingBox {
    /// Left edge, in image-pixel units.
    pub x: f32,
    /// Top edge, in image-pixel units.
    pub y: f32,
    /// Width of the box, in image-pixel units.
    pub width: f32,
    /// Height of the box, in image-pixel units.
    pub height: f32,
}

/// Object-safe seam for the platform OCR backend.
///
/// `recognize_text` runs the platform's text-recognition stack
/// over `image_data` and returns the recognized regions. The
/// trait is `Send + Sync` so the orchestration layer can stash
/// it inside the `Mutex<Option<Arc<dyn OcrBridge>>>` slot on
/// [`crate::core_impl::CoreImpl`] and fan out from background
/// workers.
pub trait OcrBridge: std::fmt::Debug + Send + Sync {
    /// Run OCR over `image_data`. `mime_type` carries the
    /// platform's MIME hint (`"image/jpeg"`, `"image/png"`, …)
    /// so the bridge can dispatch to the right decoder. Returns
    /// `Ok(vec![])` when the image contained no recognizable
    /// text — that is a successful run with zero hits, not an
    /// error.
    fn recognize_text(&self, image_data: &[u8], mime_type: &str) -> Result<Vec<OcrResult>>;
}

/// Always-`NotImplemented` `OcrBridge` for builds without a
/// platform glue layer.
///
/// Useful in unit tests and during early bring-up: a `CoreImpl`
/// that has not had a real bridge installed but still wants to
/// exercise the OCR-aware codepaths can fall back to this stub.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopOcrBridge;

impl OcrBridge for NoopOcrBridge {
    fn recognize_text(&self, _image_data: &[u8], _mime_type: &str) -> Result<Vec<OcrResult>> {
        Err(crate::Error::NotImplemented("ocr_bridge"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test bridge that always returns the same canned hits.
    /// Mirrors the production contract: `Send + Sync` + object-
    /// safe so we can store it behind a `&dyn OcrBridge`.
    #[derive(Debug)]
    struct FakeBridge {
        hits: Vec<OcrResult>,
    }

    impl OcrBridge for FakeBridge {
        fn recognize_text(&self, _image_data: &[u8], _mime_type: &str) -> Result<Vec<OcrResult>> {
            Ok(self.hits.clone())
        }
    }

    #[test]
    fn noop_bridge_returns_not_implemented() {
        let bridge = NoopOcrBridge;
        let err = bridge.recognize_text(b"unused", "image/png").unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented("ocr_bridge")));
    }

    #[test]
    fn fake_bridge_round_trips_hits_through_dyn_dispatch() {
        let bridge = FakeBridge {
            hits: vec![
                OcrResult {
                    text: "Hello, world".into(),
                    language: Some("en".into()),
                    confidence: 0.95,
                    bounding_box: Some(BoundingBox {
                        x: 10.0,
                        y: 20.0,
                        width: 100.0,
                        height: 30.0,
                    }),
                },
                OcrResult {
                    text: "你好世界".into(),
                    language: Some("zh-Hans".into()),
                    confidence: 0.87,
                    bounding_box: None,
                },
            ],
        };
        let dynref: &dyn OcrBridge = &bridge;
        let hits = dynref.recognize_text(b"unused", "image/jpeg").unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].text, "Hello, world");
        assert_eq!(hits[0].language.as_deref(), Some("en"));
        assert!((hits[0].confidence - 0.95).abs() < 1e-6);
        assert_eq!(hits[1].language.as_deref(), Some("zh-Hans"));
    }

    #[test]
    fn bounding_box_is_copy_and_eq() {
        // Compile-time checks — these all depend on Copy / Eq /
        // Clone on BoundingBox.
        let a = BoundingBox {
            x: 1.0,
            y: 2.0,
            width: 3.0,
            height: 4.0,
        };
        let b = a;
        assert_eq!(a, b);
    }
}
