//! On-device ONNX Runtime session creator for the MobileCLIP-S2
//! image / video encoder.
//!
//! `docs/PROPOSAL.md §7.6` and §7.7. MobileCLIP-S2 is the
//! image-side encoder that pairs with the XLM-R text encoder for
//! cross-modal semantic search (a query is text-embedded and
//! matched against image embeddings via HNSW). Phase 6 lands the
//! actual inference loop; this module is the Phase 6 scaffold
//! for the `ort::Session` creator that mirrors the DirectML →
//! CPU best-effort pattern in
//! [`crate::models::embeddings_onnx`] (which also owns the
//! shared EP-selection state machine — see that module for the
//! detailed contract).
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
/// `docs/PROPOSAL.md §7.6.1` (cross-pipeline embedding cache):
/// any future encoder upgrade (e.g. `mobileclip_s2@v2`) MUST
/// bump this constant so the version-mismatch invariant on
/// [`crate::models::embeddings::EmbeddingCache::get`]
/// invalidates stale rows automatically.
pub const MOBILECLIP_S2_MODEL_VERSION: &str = "mobileclip_s2@v1";

/// Output dimensionality of the MobileCLIP-S2 image encoder.
///
/// `docs/PROPOSAL.md §7.6`. The cache itself does not enforce
/// this dimension — it only requires the dequantized blob
/// length to match what was written — but callers SHOULD assert
/// against this constant before consuming a cached vector to
/// catch dimension drift across encoder upgrades.
pub const MOBILECLIP_S2_EMBEDDING_DIM: usize = 512;

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
    /// Phase 6 wires the preview-asset → image-tensor encode
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
    /// inference seam (CoreML EP on Apple, NNAPI EP on
    /// Android) lands later in Phase 6 — this scaffold focuses
    /// on the Windows DirectML path called out in
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding_dim_is_documented_clip_s2() {
        // Sanity: matches `docs/PROPOSAL.md §7.6` (~40 MB INT4
        // / ~80 MB INT8). 512 is the documented MobileCLIP-S2
        // image-embedding dimension.
        assert_eq!(MOBILECLIP_S2_EMBEDDING_DIM, 512);
    }

    #[test]
    fn model_version_tag_is_versioned() {
        // The `@vN` suffix is the cache-invalidation lever; bump
        // it whenever the encoder is replaced. See
        // `docs/PROPOSAL.md §7.6.1`.
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
}
