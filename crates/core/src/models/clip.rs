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
/// artifact. The trailing `.onnx` suffix lets
/// `ModelManager::resolve_destination` work uniformly across
/// encoders.
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
    /// The image-tensor encode step (downsample to 224×224 RGB,
    /// NCHW float32, ImageNet-style normalization) lives in a
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
/// pipeline (`docs/DESIGN.md §7.6`).
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

// ---------------------------------------------------------------------------
// OnnxImageEmbedder — real MobileCLIP-S2 image inference loop.
//
// (`docs/DESIGN.md §7.6`, `docs/ARCHITECTURE.md §11.4`). Mirrors
// the `OnnxTextEmbedder` wrapper in `embeddings_onnx.rs`: one
// long-lived `ort::Session` per encoder, EP-aware via the
// shared `OnnxProviderReport`, and a typed `Error::Model` path
// for every failure mode (decode / lock / inference / shape).
//
// Inference loop:
//
//   raw bytes
//     │  mime sniff + image-crate decode
//     ▼
//   RGB8 buffer
//     │  shorter-edge resize to 256, center crop 224×224
//     │  (matches Apple MobileCLIP-S2 reference preprocessing —
//     │   short edge to 256 then central 224 crop, not naive
//     │   force-resize, because the latter degrades cosine
//     │   similarity vs. the reference embeddings).
//     ▼
//   CHW float32 tensor, OpenCLIP per-channel
//   normalization (mean = [0.48145466, 0.4578275, 0.40821073],
//   std = [0.26862954, 0.26130258, 0.27577711])
//     │  Tensor::from_array([1, 3, 224, 224], data)
//     ▼
//   session.run([INPUT_NAME → pixel_values])
//     │  output[0] = image_features [1, 512]
//     ▼
//   defensive L2-normalise (MobileCLIP-S2's exported head may or
//   may not pre-normalise depending on the export script — the
//   downstream cosine reranker assumes unit vectors so we
//   re-normalise on the host).
// ---------------------------------------------------------------------------

/// Input height MobileCLIP-S2's `pixel_values` tensor expects.
///
/// Pinned to 224 to match Apple's `apple/ml-mobileclip` reference
/// (`mobileclip_s2.yaml` → `image_size: 224`). A model that was
/// exported at a different resolution must produce its own
/// wrapper rather than reusing this one — the resize step would
/// silently distort the pixel grid otherwise.
pub const MOBILECLIP_INPUT_HEIGHT: u32 = 224;

/// Input width MobileCLIP-S2's `pixel_values` tensor expects.
pub const MOBILECLIP_INPUT_WIDTH: u32 = 224;

/// Number of input channels (RGB) the MobileCLIP-S2 graph expects.
pub const MOBILECLIP_INPUT_CHANNELS: usize = 3;

/// Shorter-edge resize target that precedes the 224×224 centre
/// crop. Matches Apple's reference preprocessing — picking 256
/// (≈ 1.143× the crop size) keeps a small safety margin so the
/// centre crop does not have to discard significant content from
/// landscape / portrait inputs, while staying close enough to
/// 224 that the resize itself isn't a heavy downsample.
pub const MOBILECLIP_RESIZE_SHORTER_EDGE: u32 = 256;

/// Per-channel pixel mean used for OpenCLIP-style normalisation.
///
/// Sourced from the OpenAI CLIP preprocessing constants
/// (`open_clip/constants.py::OPENAI_DATASET_MEAN`); Apple's
/// `apple/ml-mobileclip` reuses these verbatim for MobileCLIP-S2
/// (`mobileclip/clip.py::_OPENAI_DATASET_MEAN`), so the host
/// preprocessing must match or the embeddings will be off-
/// manifold relative to the cross-modal XLM-R↔MobileCLIP space
/// produced by `kennguy3n/slm-guardrail`'s contrastive training.
pub const MOBILECLIP_RGB_MEAN: [f32; 3] = [0.481_454_66, 0.457_827_5, 0.408_210_73];

/// Per-channel pixel std used for OpenCLIP-style normalisation.
///
/// Sourced from `OPENAI_DATASET_STD` (`0.26862954`, `0.26130258`,
/// `0.27577711`); see [`MOBILECLIP_RGB_MEAN`] for the cross-
/// pipeline contract. The literals here are written at the
/// precision representable in `f32` — `0.261_302_58_f32` and
/// `0.275_777_11_f32` would round to the same `f32` bit pattern
/// as the trailing digit hints below, but clippy's
/// `excessive_precision` lint surfaces the redundancy explicitly,
/// so we write the canonical-rounded forms.
pub const MOBILECLIP_RGB_STD: [f32; 3] = [0.268_629_54, 0.261_302_6, 0.275_777_1];

/// Default input tensor name in Apple's reference MobileCLIP-S2
/// ONNX export (`pixel_values`). Callers using a custom export
/// pipeline that picked a different name override via
/// [`OnnxImageEmbedder::with_input_name`].
pub const MOBILECLIP_DEFAULT_INPUT_NAME: &str = "pixel_values";

/// Long-lived ONNX Runtime wrapper for the MobileCLIP-S2 image
/// encoder.
///
/// Construction loads the model from disk and registers the
/// preferred execution provider (DirectML on Windows when
/// available, CPU everywhere else). Subsequent
/// [`Self::embed_image`] calls reuse the same session — the
/// `ort::Session` holds the per-graph state (allocator,
/// optimised graph, EP context) so per-call cost is just image
/// decode + resize + normalise + inference + final
/// L2-normalise, not a full session rebuild.
///
/// The struct is `Send + Sync`-friendly *given* that
/// `ort::Session` is `Send` in the version we pin; the wrapper
/// carries a `Mutex` around the session to short-borrow it for
/// inference without forcing `&mut self` through the
/// [`ImageEmbedder`] trait.
#[cfg(feature = "onnx-runtime")]
pub struct OnnxImageEmbedder {
    session: std::sync::Mutex<ort::session::Session>,
    report: OnnxProviderReport,
    /// Name of the input tensor in the loaded `.onnx` graph;
    /// defaults to [`MOBILECLIP_DEFAULT_INPUT_NAME`].
    input_name: String,
}

#[cfg(feature = "onnx-runtime")]
impl std::fmt::Debug for OnnxImageEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnnxImageEmbedder")
            .field("report", &self.report)
            .field("input_name", &self.input_name)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "onnx-runtime")]
impl OnnxImageEmbedder {
    /// Create a new MobileCLIP-S2 wrapper backed by the model at
    /// `model_path`.
    ///
    /// Errors map through
    /// [`crate::models::embeddings_onnx::map_ort_error`] so the
    /// public surface is a single [`crate::Error::Model`]
    /// variant, regardless of whether DirectML registration,
    /// model load, or graph optimisation failed.
    pub fn new(model_path: &std::path::Path) -> Result<Self> {
        let (session, report) = create_mobileclip_session(model_path).map_err(
            crate::models::embeddings_onnx::map_ort_error("session_create"),
        )?;
        Ok(Self {
            session: std::sync::Mutex::new(session),
            report,
            input_name: MOBILECLIP_DEFAULT_INPUT_NAME.to_string(),
        })
    }

    /// EP-aware constructor mirroring
    /// [`create_mobileclip_session_with_ep`]. Lets the caller
    /// thread an [`crate::models::ep_tuning::ExecutionProvider`]
    /// choice from the host EP fallback chain.
    pub fn new_with_ep(
        model_path: &std::path::Path,
        ep: crate::models::ep_tuning::ExecutionProvider,
    ) -> Result<Self> {
        let (session, report) = create_mobileclip_session_with_ep(model_path, ep).map_err(
            crate::models::embeddings_onnx::map_ort_error("session_create_with_ep"),
        )?;
        Ok(Self {
            session: std::sync::Mutex::new(session),
            report,
            input_name: MOBILECLIP_DEFAULT_INPUT_NAME.to_string(),
        })
    }

    /// Override the input tensor name used by [`Self::embed_image`].
    ///
    /// MobileCLIP-S2 ONNX exports from different tooling
    /// (`apple/ml-mobileclip`'s `mobileclip_export_onnx.py` vs.
    /// `optimum-cli export onnx --task feature-extraction`) name
    /// the image input differently. Default is
    /// [`MOBILECLIP_DEFAULT_INPUT_NAME`] (`pixel_values`); call
    /// this before the first `embed_image` to switch to e.g.
    /// `"image"` or `"input"`.
    pub fn with_input_name(mut self, name: impl Into<String>) -> Self {
        self.input_name = name.into();
        self
    }

    /// Execution-provider report captured at session-create time.
    pub fn provider_report(&self) -> OnnxProviderReport {
        self.report
    }

    /// Input tensor name the wrapper passes to `session.run`.
    pub fn input_name(&self) -> &str {
        &self.input_name
    }
}

#[cfg(feature = "onnx-runtime")]
impl ImageEmbedder for OnnxImageEmbedder {
    /// Run MobileCLIP-S2 inference on the `image_data` bytes and
    /// return the L2-normalised image embedding of dimension
    /// [`MOBILECLIP_S2_EMBEDDING_DIM`].
    ///
    /// Inference loop:
    ///
    /// 1. [`mobileclip_image_format_for_mime`] validates the MIME
    ///    hint and picks an [`image::ImageFormat`] for the
    ///    decoder. Non-`image/*` MIME types and unsupported
    ///    formats produce a typed
    ///    [`crate::models::ModelError::MediaDecode`] error
    ///    instead of being silently fed to the encoder.
    /// 2. [`image::ImageReader`] decodes the bytes; the result
    ///    is converted to an RGB8 buffer (mobileclip ignores
    ///    alpha, and the export bakes RGB ordering into the
    ///    graph).
    /// 3. [`mobileclip_resize_and_center_crop`] shorter-edge
    ///    resizes to [`MOBILECLIP_RESIZE_SHORTER_EDGE`] then
    ///    centre-crops to 224×224. This matches Apple's
    ///    reference preprocessing — a force-resize to 224×224
    ///    would distort the aspect ratio and shift the
    ///    embedding off-manifold relative to the contrastive
    ///    training distribution.
    /// 4. [`mobileclip_chw_float_tensor`] converts the cropped
    ///    `RgbImage` (HWC u8) into a CHW float32 buffer with
    ///    OpenCLIP per-channel normalisation
    ///    ([`MOBILECLIP_RGB_MEAN`] / [`MOBILECLIP_RGB_STD`]).
    /// 5. `ort::value::Tensor::from_array` materialises the
    ///    `[1, 3, 224, 224]` input tensor; `session.run` produces
    ///    the projected image features at output index 0 with
    ///    shape `[1, hidden]`.
    /// 6. The wrapper validates `hidden == MOBILECLIP_S2_EMBEDDING_DIM`
    ///    inline before copying the features into an owned
    ///    `Vec<f32>` — refuses to write a wrong-shape blob into
    ///    the embedding cache.
    /// 7. [`mobileclip_l2_normalize_in_place`] L2-normalises the
    ///    output defensively (Apple's reference export does
    ///    pre-normalise, but optimum-cli exports may strip the
    ///    final normalise op; the host re-normalises so cosine
    ///    similarity reduces to dot product downstream
    ///    regardless of which export pipeline produced the
    ///    artifact).
    fn embed_image(&self, image_data: &[u8], mime_type: &str) -> Result<Vec<f32>> {
        use crate::models::ModelError;

        let format = mobileclip_image_format_for_mime(mime_type)?;

        let mut reader = image::ImageReader::new(std::io::Cursor::new(image_data));
        reader.set_format(format);
        let decoded = reader.decode().map_err(|e| {
            crate::Error::Model(ModelError::MediaDecode {
                op: "decode",
                detail: e.to_string(),
            })
        })?;
        let rgb = decoded.to_rgb8();
        if rgb.width() == 0 || rgb.height() == 0 {
            return Err(crate::Error::Model(ModelError::MediaDecode {
                op: "decode",
                detail: format!(
                    "decoded image has zero-sized dimension: {}x{}",
                    rgb.width(),
                    rgb.height()
                ),
            }));
        }

        let cropped = mobileclip_resize_and_center_crop(&rgb);
        debug_assert_eq!(cropped.width(), MOBILECLIP_INPUT_WIDTH);
        debug_assert_eq!(cropped.height(), MOBILECLIP_INPUT_HEIGHT);

        let tensor_data = mobileclip_chw_float_tensor(&cropped);
        debug_assert_eq!(
            tensor_data.len(),
            MOBILECLIP_INPUT_CHANNELS
                * (MOBILECLIP_INPUT_HEIGHT as usize)
                * (MOBILECLIP_INPUT_WIDTH as usize)
        );

        // Build the [1, 3, 224, 224] input tensor. The data vec
        // is moved into the tensor (mobileclip does not reuse
        // it after `session.run`).
        let input_tensor = ort::value::Tensor::from_array((
            vec![
                1_i64,
                MOBILECLIP_INPUT_CHANNELS as i64,
                MOBILECLIP_INPUT_HEIGHT as i64,
                MOBILECLIP_INPUT_WIDTH as i64,
            ],
            tensor_data,
        ))
        .map_err(crate::models::embeddings_onnx::map_ort_error(
            "input_tensor_build",
        ))?;

        // Hold the session lock across `run` AND tensor extraction:
        // `SessionOutputs<'s>` borrows from the session, so the
        // copy into an owned `Vec<f32>` must happen inside the
        // critical section — same pattern as
        // `OnnxTextEmbedder::embed_text`. We L2-normalise after
        // dropping the lock to keep the critical section as
        // short as possible (the normalise pass is pure data,
        // no session state).
        let mut features = {
            let mut session = self.session.lock().map_err(|_| {
                crate::Error::Model(ModelError::LockPoisoned("onnx_image_embedder_session"))
            })?;
            let outputs = session
                .run(ort::inputs![self.input_name.as_str() => input_tensor])
                .map_err(crate::models::embeddings_onnx::map_ort_error("infer"))?;

            // Guard `outputs[0]` — see equivalent guard in
            // `OnnxTextEmbedder::embed_text`. A bare index panic
            // would poison the session mutex and break every
            // subsequent inference call.
            if outputs.len() == 0 {
                return Err(crate::Error::Model(ModelError::Custom(
                    "mobileclip session returned zero outputs; expected image_features at index 0"
                        .to_string(),
                )));
            }
            let (out_shape, hidden) = outputs[0].try_extract_tensor::<f32>().map_err(
                crate::models::embeddings_onnx::map_ort_error("output_extract"),
            )?;
            // MobileCLIP-S2 image_features shape is `[1, hidden]`
            // (post-projection); the visual encoder's pre-
            // projection last_hidden_state would be `[1, seq,
            // hidden]` but Apple's reference export only emits
            // the projected features as output 0.
            if out_shape.len() != 2 || out_shape[0] != 1 {
                return Err(crate::Error::Model(ModelError::Custom(format!(
                    "mobileclip session returned unexpected output shape {out_shape:?}; expected [1, hidden]"
                ))));
            }
            if out_shape[1] < 0 {
                return Err(crate::Error::Model(ModelError::Custom(format!(
                    "mobileclip session returned negative hidden dimension in output shape {out_shape:?}; \
                     expected fully resolved [1, hidden]"
                ))));
            }
            let hidden_size = out_shape[1] as usize;
            if hidden_size != MOBILECLIP_S2_EMBEDDING_DIM {
                return Err(crate::Error::Model(ModelError::Custom(format!(
                    "mobileclip session produced hidden_size={hidden_size}, \
                     expected MOBILECLIP_S2_EMBEDDING_DIM={MOBILECLIP_S2_EMBEDDING_DIM}; \
                     refusing to write a wrong-shape blob to the embedding cache"
                ))));
            }
            if hidden.len() != hidden_size {
                return Err(crate::Error::Model(ModelError::Custom(format!(
                    "mobileclip output buffer mismatch: hidden.len={} vs hidden_size={}",
                    hidden.len(),
                    hidden_size,
                ))));
            }
            hidden.to_vec()
        };

        mobileclip_l2_normalize_in_place(&mut features);
        Ok(features)
    }
}

/// Map a MIME type to the [`image::ImageFormat`] that decodes
/// it, gated to the formats MobileCLIP-S2 actually supports
/// on-device today (PNG + JPEG, matching the thumbnail
/// generator at `crates/core/src/media/thumbnail.rs`).
///
/// WebP / HEIC / AVIF support would just be a feature-flag flip
/// on the `image` crate plus an extra match arm; left as a
/// follow-up so this PR's `image` dep tree stays unchanged.
#[cfg(feature = "onnx-runtime")]
fn mobileclip_image_format_for_mime(mime_type: &str) -> Result<image::ImageFormat> {
    if !mime_type.starts_with("image/") {
        return Err(crate::Error::Model(
            crate::models::ModelError::MediaDecode {
                op: "select_format",
                detail: format!("MobileCLIP-S2 expects an image/* mime_type, got {mime_type:?}"),
            },
        ));
    }
    match mime_type {
        "image/png" => Ok(image::ImageFormat::Png),
        "image/jpeg" | "image/jpg" => Ok(image::ImageFormat::Jpeg),
        other => Err(crate::Error::Model(
            crate::models::ModelError::MediaDecode {
                op: "select_format",
                detail: format!(
                    "MobileCLIP-S2 image decoder does not support {other:?} \
                     (supported: image/png, image/jpeg)"
                ),
            },
        )),
    }
}

/// Apply Apple's reference MobileCLIP-S2 preprocessing geometry:
/// shorter-edge resize to [`MOBILECLIP_RESIZE_SHORTER_EDGE`],
/// then a centre crop down to 224×224.
///
/// Matches `mobileclip/clip.py::_create_preprocess` from
/// `apple/ml-mobileclip`. A naive force-resize to 224×224 would
/// distort the aspect ratio of non-square inputs and shift the
/// embedding off-manifold relative to the contrastive training
/// distribution, hurting cross-modal retrieval quality even
/// when the model itself is unchanged.
#[cfg(feature = "onnx-runtime")]
fn mobileclip_resize_and_center_crop(rgb: &image::RgbImage) -> image::RgbImage {
    let (w, h) = (rgb.width(), rgb.height());
    debug_assert!(w > 0 && h > 0);
    let shorter = w.min(h);
    let scale = MOBILECLIP_RESIZE_SHORTER_EDGE as f64 / shorter as f64;
    // Use `f64` arithmetic to avoid silent precision drift on
    // very-tall or very-wide images (e.g. a 6000×4000 portrait
    // mapped through `f32 * f32` then `as u32`). Floor + clamp
    // to >= 1 so we never produce a zero-sized dimension that
    // would make `imageops::resize` panic.
    let new_w = ((w as f64) * scale).round().max(1.0) as u32;
    let new_h = ((h as f64) * scale).round().max(1.0) as u32;
    let resized = image::imageops::resize(rgb, new_w, new_h, image::imageops::FilterType::Triangle);

    // Centre crop to exactly 224×224. If the resize landed on
    // exactly 256 on the shorter edge, the longer edge is >= 256
    // by construction, so both crop offsets are non-negative and
    // the crop stays in-bounds.
    let crop_x = new_w.saturating_sub(MOBILECLIP_INPUT_WIDTH) / 2;
    let crop_y = new_h.saturating_sub(MOBILECLIP_INPUT_HEIGHT) / 2;
    image::imageops::crop_imm(
        &resized,
        crop_x,
        crop_y,
        MOBILECLIP_INPUT_WIDTH,
        MOBILECLIP_INPUT_HEIGHT,
    )
    .to_image()
}

/// Convert an `RgbImage` (HWC u8) of shape 224×224×3 into a CHW
/// float32 buffer of length 3 × 224 × 224 with per-channel
/// OpenCLIP normalisation ([`MOBILECLIP_RGB_MEAN`] /
/// [`MOBILECLIP_RGB_STD`]).
///
/// MobileCLIP-S2's ONNX graph expects NCHW float32 input; the
/// `image` crate gives us HWC u8, so the host has to do both
/// the layout transpose AND the byte-to-float conversion. Done
/// in a single linear scan over the 3 × 224 × 224 = 150 528
/// pixel triplets to keep cache behaviour predictable
/// (channel-outer ordering matches the layout the tensor
/// will land in).
#[cfg(feature = "onnx-runtime")]
fn mobileclip_chw_float_tensor(rgb: &image::RgbImage) -> Vec<f32> {
    let h = MOBILECLIP_INPUT_HEIGHT as usize;
    let w = MOBILECLIP_INPUT_WIDTH as usize;
    let c = MOBILECLIP_INPUT_CHANNELS;
    debug_assert_eq!(rgb.width(), MOBILECLIP_INPUT_WIDTH);
    debug_assert_eq!(rgb.height(), MOBILECLIP_INPUT_HEIGHT);
    let mut out = Vec::with_capacity(c * h * w);
    let pixels = rgb.as_raw();
    for channel in 0..c {
        let mean = MOBILECLIP_RGB_MEAN[channel];
        let std = MOBILECLIP_RGB_STD[channel];
        for y in 0..h {
            for x in 0..w {
                // `image::RgbImage::as_raw()` is row-major HWC:
                // pixel at (y, x), channel `channel` is at
                // index `(y * w + x) * 3 + channel`.
                let idx = (y * w + x) * 3 + channel;
                let raw = pixels[idx] as f32 / 255.0;
                out.push((raw - mean) / std);
            }
        }
    }
    out
}

/// L2-normalise a slice in place. Mirrors the helper used by
/// [`crate::models::embeddings_onnx::OnnxTextEmbedder`] so the
/// two encoders' output post-processing stays consistent
/// (cosine reranking on the search side does dot products and
/// assumes unit vectors).
///
/// Tiny norms (`< 1e-12`) leave the vector untouched rather
/// than producing `NaN` / `inf` from a divide-by-near-zero;
/// the downstream cosine-distance code is then free to treat
/// the result as a degenerate-but-finite vector instead of
/// poisoning the cache with non-finite floats.
#[cfg(feature = "onnx-runtime")]
fn mobileclip_l2_normalize_in_place(v: &mut [f32]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-12 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Always-`NotImplemented` `OnnxImageEmbedder` stub for builds
/// without the `onnx-runtime` cargo feature.
///
/// `OnnxImageEmbedder` exists in both feature configurations so
/// downstream code can name the type unconditionally — it just
/// errors out on construction without the feature. The trait
/// impl below forwards to a no-feature `embed_image` that
/// returns the same `NotImplemented` shape, keeping the
/// `Arc<dyn ImageEmbedder>` slot in `CoreImpl` valid in both
/// configurations.
#[cfg(not(feature = "onnx-runtime"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct OnnxImageEmbedder;

#[cfg(not(feature = "onnx-runtime"))]
impl OnnxImageEmbedder {
    /// Always returns
    /// [`crate::Error::NotImplemented`](crate::Error::NotImplemented):
    /// the `onnx-runtime` cargo feature is required for the
    /// real session creator.
    pub fn new(_model_path: &std::path::Path) -> Result<Self> {
        Err(crate::Error::NotImplemented(
            "onnx_image_embedder.new (onnx-runtime feature disabled)",
        ))
    }
}

#[cfg(not(feature = "onnx-runtime"))]
impl ImageEmbedder for OnnxImageEmbedder {
    /// Always returns
    /// [`crate::Error::NotImplemented`](crate::Error::NotImplemented).
    fn embed_image(&self, _image_data: &[u8], _mime_type: &str) -> Result<Vec<f32>> {
        Err(crate::Error::NotImplemented(
            "onnx_image_embedder.embed_image (onnx-runtime feature disabled)",
        ))
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

    // ---------- OnnxImageEmbedder preprocessing coverage ----------

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn mime_lookup_rejects_non_image() {
        let err = mobileclip_image_format_for_mime("text/plain").unwrap_err();
        assert!(matches!(err, crate::Error::Model(_)));
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn mime_lookup_accepts_png_and_jpeg() {
        assert!(matches!(
            mobileclip_image_format_for_mime("image/png").unwrap(),
            image::ImageFormat::Png
        ));
        assert!(matches!(
            mobileclip_image_format_for_mime("image/jpeg").unwrap(),
            image::ImageFormat::Jpeg
        ));
        assert!(matches!(
            mobileclip_image_format_for_mime("image/jpg").unwrap(),
            image::ImageFormat::Jpeg
        ));
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn mime_lookup_rejects_unsupported_image_format() {
        // WebP / HEIC / AVIF would compile only with extra
        // `image`-crate features; with the current dep tree the
        // function must surface the gap as a typed error rather
        // than silently downgrading to PNG.
        let err = mobileclip_image_format_for_mime("image/webp").unwrap_err();
        assert!(matches!(err, crate::Error::Model(_)));
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn resize_and_center_crop_lands_on_224_square_for_landscape() {
        // 800×400 → shorter-edge 256 with scale 256/400 = 0.64
        // → 512×256 → centre crop 224×224 at offset (144, 16).
        let img = image::RgbImage::from_pixel(800, 400, image::Rgb([10, 20, 30]));
        let cropped = mobileclip_resize_and_center_crop(&img);
        assert_eq!(cropped.width(), MOBILECLIP_INPUT_WIDTH);
        assert_eq!(cropped.height(), MOBILECLIP_INPUT_HEIGHT);
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn resize_and_center_crop_lands_on_224_square_for_portrait() {
        let img = image::RgbImage::from_pixel(300, 900, image::Rgb([200, 200, 200]));
        let cropped = mobileclip_resize_and_center_crop(&img);
        assert_eq!(cropped.width(), MOBILECLIP_INPUT_WIDTH);
        assert_eq!(cropped.height(), MOBILECLIP_INPUT_HEIGHT);
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn resize_and_center_crop_handles_already_square_input() {
        // A square that's already smaller than 256 should still
        // upsample to the shorter-edge target so the centre crop
        // has the expected source area.
        let img = image::RgbImage::from_pixel(180, 180, image::Rgb([50, 60, 70]));
        let cropped = mobileclip_resize_and_center_crop(&img);
        assert_eq!(cropped.width(), MOBILECLIP_INPUT_WIDTH);
        assert_eq!(cropped.height(), MOBILECLIP_INPUT_HEIGHT);
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn chw_tensor_has_expected_length_and_layout() {
        // A constant grey image → all channels post-normalise
        // should evaluate to `(0.5 - mean_c) / std_c`, which is
        // distinct per channel because the OpenCLIP constants
        // differ across R / G / B.
        let img = image::RgbImage::from_pixel(
            MOBILECLIP_INPUT_WIDTH,
            MOBILECLIP_INPUT_HEIGHT,
            image::Rgb([128, 128, 128]),
        );
        let tensor = mobileclip_chw_float_tensor(&img);
        let plane = (MOBILECLIP_INPUT_HEIGHT as usize) * (MOBILECLIP_INPUT_WIDTH as usize);
        assert_eq!(tensor.len(), MOBILECLIP_INPUT_CHANNELS * plane);
        for channel in 0..MOBILECLIP_INPUT_CHANNELS {
            let expected =
                (128.0_f32 / 255.0 - MOBILECLIP_RGB_MEAN[channel]) / MOBILECLIP_RGB_STD[channel];
            // Sample the first and last pixels of the channel's
            // plane — every value should match exactly because
            // the input is constant.
            assert!((tensor[channel * plane] - expected).abs() < 1e-6);
            assert!((tensor[channel * plane + plane - 1] - expected).abs() < 1e-6);
        }
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn chw_tensor_normalises_channels_distinctly() {
        // A pure-red pixel (R=255, G=0, B=0) lands on different
        // post-normalise values per channel; cross-channel
        // equality would be a bug in the layout transpose.
        let img = image::RgbImage::from_pixel(
            MOBILECLIP_INPUT_WIDTH,
            MOBILECLIP_INPUT_HEIGHT,
            image::Rgb([255, 0, 0]),
        );
        let tensor = mobileclip_chw_float_tensor(&img);
        let plane = (MOBILECLIP_INPUT_HEIGHT as usize) * (MOBILECLIP_INPUT_WIDTH as usize);
        let r = tensor[0];
        let g = tensor[plane];
        let b = tensor[2 * plane];
        // Red channel saturated → ((1.0 - 0.481) / 0.269) ≈
        // 1.93. Green / blue zero → ((0.0 - mean) / std) → ≈
        // -1.71 / -1.48. The three must be distinct.
        assert!((r - 1.93).abs() < 0.05);
        assert!((g + 1.71).abs() < 0.05);
        assert!((b + 1.48).abs() < 0.05);
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn l2_normalize_in_place_unitises_finite_vectors() {
        let mut v: Vec<f32> = (1..=8).map(|x| x as f32).collect();
        mobileclip_l2_normalize_in_place(&mut v);
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6, "norm = {norm}");
    }

    #[cfg(feature = "onnx-runtime")]
    #[test]
    fn l2_normalize_in_place_leaves_zero_vector_unchanged() {
        let mut v = vec![0.0_f32; 8];
        mobileclip_l2_normalize_in_place(&mut v);
        // Below-tolerance norms must NOT divide-by-near-zero and
        // produce NaN / inf — the embedding cache rejects non-
        // finite floats downstream, so leaving the vector as-is
        // is the correct degenerate-input behaviour.
        assert!(v.iter().all(|x| x.is_finite()));
        assert_eq!(v, vec![0.0; 8]);
    }

    #[cfg(not(feature = "onnx-runtime"))]
    #[test]
    fn onnx_image_embedder_stub_returns_not_implemented_on_construct() {
        use std::path::PathBuf;
        let err = OnnxImageEmbedder::new(&PathBuf::from("/nonexistent.onnx")).unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }

    #[cfg(not(feature = "onnx-runtime"))]
    #[test]
    fn onnx_image_embedder_stub_returns_not_implemented_on_embed() {
        let stub = OnnxImageEmbedder;
        let err = stub.embed_image(b"unused", "image/png").unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }
}
