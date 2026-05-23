//! On-device ONNX Runtime session creator for the MobileCLIP-S2
//! image / video encoder.
//!
//! `docs/DESIGN.md §7.6` and §7.7. MobileCLIP-S2 is the
//! image-side encoder that pairs with the XLM-R text encoder for
//! cross-modal semantic search (a query is text-embedded and
//! matched against image embeddings via HNSW). This module hosts
//! the `ort::Session` creator that mirrors the DirectML → CPU
//! best-effort pattern in [`crate::models::embeddings_onnx`]
//! (which also owns the shared EP-selection state machine — see
//! that module for the detailed contract).
//!
//! Re-exports the EP-selection types from `embeddings_onnx` so
//! call sites that only depend on `models::clip` still see the
//! full provider surface.

pub use crate::models::embeddings_onnx::{
    select_provider, DirectMlProbe, OnnxExecutionProvider, OnnxProviderReport,
};

// `OrtDirectMlProbe` and the `OrtSessionResult` alias only exist
// when the `onnx-runtime` cargo feature is enabled (they bring
// `ort` types into scope), so the re-exports must be gated to
// match.
#[cfg(feature = "onnx-runtime")]
pub use crate::models::embeddings_onnx::OrtDirectMlProbe;
#[cfg(feature = "onnx-runtime")]
use crate::models::embeddings_onnx::OrtSessionResult;

/// Canonical `model_version` tag for the MobileCLIP-S2
/// image / video encoder shipped to devices.
///
/// `docs/DESIGN.md §7.6.1` (cross-pipeline embedding cache):
/// any future encoder upgrade (e.g. `mobileclip_s2@v2`) MUST
/// bump this constant so the version-mismatch invariant on
/// [`crate::models::embeddings::EmbeddingCache::get`]
/// invalidates stale rows automatically.
pub const MOBILECLIP_S2_MODEL_VERSION: &str = "mobileclip_s2@v1";

/// Output dimensionality of the MobileCLIP-S2 image encoder.
///
/// `docs/DESIGN.md §7.6`. The cache itself does not enforce
/// this dimension — it only requires the dequantized blob
/// length to match what was written — but callers SHOULD assert
/// against this constant before consuming a cached vector to
/// catch dimension drift across encoder upgrades.
pub const MOBILECLIP_S2_EMBEDDING_DIM: usize = 512;

/// Canonical on-disk filename for the INT8 MobileCLIP-S2
/// artifact.. The trailing
/// `.onnx` suffix lets `ModelManager::resolve_destination` work
/// uniformly across encoders.
pub const MOBILECLIP_S2_INT8_FILENAME: &str = "mobileclip_s2-v1-int8.onnx";

/// Canonical on-disk filename for the INT4 (`MatMulNBits`)
/// MobileCLIP-S2 artifact shipped to tight-storage devices.
pub const MOBILECLIP_S2_INT4_FILENAME: &str = "mobileclip_s2-v1-int4.onnx";

#[cfg(all(target_os = "windows", feature = "onnx-runtime"))]
mod windows_directml {
    use super::{OnnxExecutionProvider, OnnxProviderReport, OrtDirectMlProbe, OrtSessionResult};
    use crate::models::embeddings_onnx::select_provider;
    use ort::ep::{DirectML, ExecutionProvider, CPU};
    use ort::session::Session;
    use std::path::Path;

    /// Create an `ort::Session` for MobileCLIP-S2 loaded from
    /// `model_path`.
    ///
    /// Same DirectML → CPU best-effort contract as
    /// [`crate::models::embeddings_onnx::create_xlmr_session`]:
    /// DirectML registration is attempted first, with CPU as
    /// the fallback if registration fails. The returned
    /// [`OnnxProviderReport`] reflects the EP actually
    /// registered, not the original intent.
    ///
    /// wires the preview-asset → image-tensor encode
    /// step (downsample to 224×224 RGB, NCHW float32,
    /// ImageNet-style normalization) — that lives in a
    /// follow-up alongside the [`crate::models::embeddings`]
    /// inference loop.
    pub fn create_mobileclip_session(
        model_path: &Path,
    ) -> OrtSessionResult<(Session, OnnxProviderReport)> {
        let intent = select_provider(&OrtDirectMlProbe);
        let mut builder = Session::builder()?;

        let actual_provider = match intent.provider {
            OnnxExecutionProvider::DirectMl => {
                if DirectML::default().register(&mut builder).is_ok() {
                    OnnxExecutionProvider::DirectMl
                } else {
                    let _ = CPU::default().register(&mut builder);
                    OnnxExecutionProvider::Cpu
                }
            }
            OnnxExecutionProvider::Cpu => {
                let _ = CPU::default().register(&mut builder);
                OnnxExecutionProvider::Cpu
            }
        };

        let session = builder.commit_from_file(model_path)?;
        Ok((
            session,
            OnnxProviderReport {
                provider: actual_provider,
                directml_attempted: intent.directml_attempted,
            },
        ))
    }
}

#[cfg(all(target_os = "windows", feature = "onnx-runtime"))]
pub use windows_directml::create_mobileclip_session;

#[cfg(all(not(target_os = "windows"), feature = "onnx-runtime"))]
mod posix_cpu {
    use super::{OnnxProviderReport, OrtDirectMlProbe, OrtSessionResult};
    use crate::models::embeddings_onnx::select_provider;
    use ort::ep::{ExecutionProvider, CPU};
    use ort::session::Session;
    use std::path::Path;

    /// macOS / Linux flavor of the MobileCLIP-S2 session
    /// creator. Always registers the CPU EP. The cross-platform
    /// inference seam (CoreML EP on Apple, NNAPI EP on Android)
    /// is layered above this; this entry point focuses on the
    /// Windows DirectML path called out in
    /// `docs/ARCHITECTURE.md §11.4`.
    pub fn create_mobileclip_session(
        model_path: &Path,
    ) -> OrtSessionResult<(Session, OnnxProviderReport)> {
        let report = select_provider(&OrtDirectMlProbe);
        let mut builder = Session::builder()?;
        let _ = CPU::default().register(&mut builder);
        let session = builder.commit_from_file(model_path)?;
        Ok((session, report))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "onnx-runtime"))]
pub use posix_cpu::create_mobileclip_session;

/// INT4 (`MatMulNBits`)
/// flavor of [`create_mobileclip_session`].
///
/// The actual `MatMulNBits` graph optimization in `ort` is
/// applied automatically at session-load time when the `.onnx`
/// model file already carries `MatMulNBits` nodes (which our
/// INT4 export pipeline produces). This helper is therefore
/// structurally identical to [`create_mobileclip_session`]
/// the EP-selection state machine and CPU fallback are the
/// same. The function exists as a named seam so future graph-
/// optimization tweaks (`SessionBuilder::with_optimization_level`
/// / `with_intra_threads`) can land without touching the
/// INT8 path.
#[cfg(feature = "onnx-runtime")]
pub fn create_mobileclip_session_int4(
    model_path: &std::path::Path,
) -> crate::models::embeddings_onnx::OrtSessionResult<(
    ort::session::Session,
    crate::models::embeddings_onnx::OnnxProviderReport,
)> {
    create_mobileclip_session(model_path)
}

/// INT4 session-creator
/// stub for builds without the `onnx-runtime` cargo feature.
///
/// Returns [`crate::Error::NotImplemented`] so callers can
/// pre-flight `feature = "onnx-runtime"` without a `cfg`-fence.
#[cfg(not(feature = "onnx-runtime"))]
pub fn create_mobileclip_session_int4(_model_path: &std::path::Path) -> crate::Result<()> {
    Err(crate::Error::NotImplemented(
        "create_mobileclip_session_int4 requires onnx-runtime feature",
    ))
}

/// EP-aware named seam
/// over [`create_mobileclip_session`].
///
/// Mirrors [`crate::models::embeddings_onnx::create_xlmr_session_with_ep`]:
/// callers pass an [`crate::models::ep_tuning::ExecutionProvider`]
/// chosen from the host
/// [`crate::models::ep_tuning::EpFallbackChain`], and the helper
/// drives the existing platform-aware best-effort fallback.
#[cfg(feature = "onnx-runtime")]
pub fn create_mobileclip_session_with_ep(
    model_path: &std::path::Path,
    ep: crate::models::ep_tuning::ExecutionProvider,
) -> crate::models::embeddings_onnx::OrtSessionResult<(
    ort::session::Session,
    crate::models::embeddings_onnx::OnnxProviderReport,
)> {
    let _ = ep;
    create_mobileclip_session(model_path)
}

/// stub for the
/// EP-aware seam when the `onnx-runtime` feature is off.
#[cfg(not(feature = "onnx-runtime"))]
pub fn create_mobileclip_session_with_ep(
    _model_path: &std::path::Path,
    _ep: crate::models::ep_tuning::ExecutionProvider,
) -> crate::Result<()> {
    Err(crate::Error::NotImplemented(
        "create_mobileclip_session_with_ep requires onnx-runtime feature",
    ))
}

// ---------------------------------------------------------------------------
// ImageEmbedder trait
// ---------------------------------------------------------------------------

use crate::Result;

/// On-device image-embedding seam used by the media-ingest
/// pipeline (`docs/DESIGN.md §7.6`, ).
///
/// Object-safe + `Send + Sync` so [`crate::core_impl::CoreImpl`]
/// can stash it inside `Mutex<Option<Box<dyn ImageEmbedder>>>`.
/// Implementations MUST return an L2-normalized vector of length
/// [`MOBILECLIP_S2_EMBEDDING_DIM`] for the canonical encoder.
///
/// The MIME hint is a courtesy: implementations are free to
/// sniff the leading bytes and ignore the hint, but using it
/// short-circuits the image-codec dispatch in the common case.
pub trait ImageEmbedder: std::fmt::Debug + Send + Sync {
    /// Run image inference over `image_data`. `mime_type` is the
    /// source MIME hint (`"image/jpeg"`, `"image/png"`,
    /// `"image/webp"`, …). Implementations SHOULD reject non-
    /// image MIME types with [`crate::Error::Model`] rather than
    /// returning a degenerate embedding.
    fn embed_image(&self, image_data: &[u8], mime_type: &str) -> Result<Vec<f32>>;
}

/// Always-`NotImplemented` `ImageEmbedder` for builds without a
/// real MobileCLIP-S2 model wired in.
///
/// `embed_image` returns
/// [`crate::Error::NotImplemented("image_embedder")`](crate::Error::NotImplemented).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopImageEmbedder;

impl ImageEmbedder for NoopImageEmbedder {
    fn embed_image(&self, _image_data: &[u8], _mime_type: &str) -> Result<Vec<f32>> {
        Err(crate::Error::NotImplemented("image_embedder"))
    }
}

/// Deterministic test [`ImageEmbedder`] that hashes
/// `(mime_type, image_data)` into a reproducible, L2-normalized
/// vector.
///
/// Used by the unit tests to stand in for a real
/// MobileCLIP-S2 encoder. Same construction as
/// [`crate::models::embeddings::MockTextEmbedder`]: BLAKE3 of
/// the input seeds an LCG, and the resulting `dim`-length f32
/// vector is L2-normalized.
#[derive(Debug, Clone, Copy)]
pub struct MockImageEmbedder {
    dim: usize,
}

impl Default for MockImageEmbedder {
    fn default() -> Self {
        Self {
            dim: MOBILECLIP_S2_EMBEDDING_DIM,
        }
    }
}

impl MockImageEmbedder {
    /// Build a [`MockImageEmbedder`] that emits `dim`-length
    /// vectors. Default constructor uses
    /// [`MOBILECLIP_S2_EMBEDDING_DIM`].
    pub fn with_dim(dim: usize) -> Self {
        assert!(dim > 0, "MockImageEmbedder dim must be > 0");
        Self { dim }
    }

    /// Embedding dimensionality the mock emits.
    pub fn dim(&self) -> usize {
        self.dim
    }
}

impl ImageEmbedder for MockImageEmbedder {
    fn embed_image(&self, image_data: &[u8], mime_type: &str) -> Result<Vec<f32>> {
        if !mime_type.starts_with("image/") {
            return Err(crate::Error::Model(
                crate::models::ModelError::MediaDecode {
                    op: "embed_image",
                    detail: format!("MockImageEmbedder rejects non-image mime_type: {mime_type}"),
                },
            ));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(mime_type.as_bytes());
        hasher.update(&[0]);
        hasher.update(image_data);
        let hash = hasher.finalize();
        let seed_bytes = &hash.as_bytes()[..4];
        let mut x =
            u32::from_le_bytes([seed_bytes[0], seed_bytes[1], seed_bytes[2], seed_bytes[3]]);
        if x == 0 {
            x = 1;
        }
        let mut raw: Vec<f32> = Vec::with_capacity(self.dim);
        for _ in 0..self.dim {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            raw.push((x as i32) as f32 / i32::MAX as f32);
        }
        let norm: f32 = raw.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 1e-12 {
            for v in &mut raw {
                *v /= norm;
            }
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding_dim_is_documented_clip_s2() {
        // Sanity: matches `docs/DESIGN.md §7.6` (~40 MB INT4
        // / ~80 MB INT8). 512 is the documented MobileCLIP-S2
        // image-embedding dimension.
        assert_eq!(MOBILECLIP_S2_EMBEDDING_DIM, 512);
    }

    #[test]
    fn model_version_tag_is_versioned() {
        // The `@vN` suffix is the cache-invalidation lever; bump
        // it whenever the encoder is replaced. See
        // `docs/DESIGN.md §7.6.1`.
        assert!(
            MOBILECLIP_S2_MODEL_VERSION.contains('@'),
            "model version tag must include an @vN suffix"
        );
    }

    #[test]
    fn ep_types_reexported() {
        // Re-export sanity: callers depending only on
        // `models::clip` should still be able to name the EP
        // selection types.
        let report = select_provider(&AlwaysFalseProbe);
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
    }

    struct AlwaysFalseProbe;
    impl DirectMlProbe for AlwaysFalseProbe {
        fn directml_available(&self) -> bool {
            false
        }
    }

    // -----: ImageEmbedder coverage --------------

    #[test]
    fn noop_image_embedder_returns_not_implemented() {
        let emb = NoopImageEmbedder;
        let err = emb.embed_image(b"bytes", "image/png").unwrap_err();
        assert!(matches!(
            err,
            crate::Error::NotImplemented("image_embedder")
        ));
    }

    #[test]
    fn mock_image_embedder_is_deterministic_and_normalized() {
        let emb = MockImageEmbedder::default();
        let a = emb.embed_image(b"AAA", "image/png").expect("a");
        let b = emb.embed_image(b"AAA", "image/png").expect("b");
        assert_eq!(a, b);
        assert_eq!(a.len(), MOBILECLIP_S2_EMBEDDING_DIM);
        let norm: f32 = a.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-3);
    }

    #[test]
    fn mock_image_embedder_distinct_inputs_diverge() {
        let emb = MockImageEmbedder::default();
        let a = emb.embed_image(b"AAA", "image/png").unwrap();
        let b = emb.embed_image(b"BBB", "image/png").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn mock_image_embedder_rejects_non_image_mime() {
        let emb = MockImageEmbedder::default();
        let err = emb.embed_image(b"unused", "text/plain").unwrap_err();
        assert!(matches!(err, crate::Error::Model(_)));
    }

    #[test]
    fn image_embedder_trait_is_object_safe() {
        let mock = MockImageEmbedder::default();
        let dynref: &dyn ImageEmbedder = &mock;
        let v = dynref.embed_image(b"X", "image/jpeg").unwrap();
        assert_eq!(v.len(), MOBILECLIP_S2_EMBEDDING_DIM);
    }
}
