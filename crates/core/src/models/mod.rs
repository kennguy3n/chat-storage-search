//! `models` module — on-device ML model management.
//!
//! `docs/DESIGN.md §7.6` lays out the on-device ML model set:
//! `XLM-R` for multilingual text embeddings, `MobileCLIP-S2` for
//! image / video embeddings, and `Whisper-base` / `Whisper-tiny`
//! for audio transcription. This module wires those models to
//! ONNX Runtime via the [`ort`](https://crates.io/crates/ort)
//! crate and hosts the model manager (lazy download, versioning,
//! INT8 / INT4 quantization, integrity-checked artifacts).
//!
//! Submodules:
//!
//! * [`embeddings`] — XLM-R text-embedding seam **and** the
//!   cross-pipeline [`embeddings::EmbeddingCache`] trait
//!   (`docs/DESIGN.md §7.6.1`). The trait surface and the default
//!   `search_vector`-backed implementation land now so the
//!   guardrail (`kennguy3n/slm-guardrail`) and search pipelines
//!   can start sharing one XLM-R inference per message ahead of
//!   the ONNX integration.
//! * [`embeddings_onnx`] — the XLM-R
//!   `ort::Session` creator with the best-effort DirectML → CPU
//!   execution-provider state machine for Windows
//!   (`docs/ARCHITECTURE.md §11.4`). The EP-selection function is
//!   pure Rust so it is unit-tested on any host; the actual
//!   `ort::Session` glue is gated behind the `onnx-runtime` cargo
//!   feature.
//! * [`clip`] — the MobileCLIP-S2
//!   `ort::Session` creator. Re-uses the EP-selection state
//!   machine from [`embeddings_onnx`] for the same DirectML → CPU
//!   pattern.
//! * [`whisper`] — the Apple-MLX-preferred
//!   Whisper backend selector. On Apple Silicon (`macOS` / `iOS`
//!   `aarch64`) `Whisper-base` runs through MLX
//!   ([`mlx-community/whisper-base-mlx`](https://huggingface.co/mlx-community/whisper-base-mlx)),
//!   which routes to the Neural Engine; everywhere else the
//!   pipeline falls back to ONNX Runtime CPU EP. The backend
//!   selection mirrors the DirectML → CPU pattern in
//!   [`embeddings_onnx`] / [`clip`] but pivots on
//!   `cfg(target_arch = "aarch64", target_os = "macos" | "ios")`
//!   instead of `cfg(target_os = "windows")`.

pub mod clip;
pub mod document;
pub mod embeddings;
pub mod embeddings_onnx;
pub mod ep_tuning;
pub mod http_downloader;
pub mod model_manager;
pub mod ocr;
pub mod resource_gate;
pub mod video;
pub mod whisper;

/// On-device ML error type wrapped by [`crate::Error::Model`].
///
/// Surfaces ONNX Runtime / MLX session errors, tokenizer failures,
/// image / video decode failures, and EP-tuning cache I/O. New
/// failure modes should prefer a typed variant over
/// [`ModelError::Custom`].
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    /// An ONNX Runtime call failed (session create, input bind,
    /// inference). `op` names the call site (`"session_create"`,
    /// `"infer"`, …).
    #[error("ort ({op}): {detail}")]
    Ort {
        /// ORT operation that failed.
        op: &'static str,
        /// Free-form detail captured from the upstream `ort` crate.
        detail: String,
    },

    /// A tokenizer call failed (load, encode, decode).
    #[error("tokenizer ({op}): {detail}")]
    Tokenizer {
        /// Tokenizer operation that failed.
        op: &'static str,
        /// Free-form detail captured from the tokenizer crate.
        detail: String,
    },

    /// An image / video decode call failed.
    #[error("media decode ({op}): {detail}")]
    MediaDecode {
        /// Decode operation that failed.
        op: &'static str,
        /// Free-form detail captured from the codec.
        detail: String,
    },

    /// An EP-tuning cache file could not be read / written.
    #[error("ep cache ({op}): {source}")]
    EpCache {
        /// EP-cache operation that failed.
        op: &'static str,
        #[source]
        /// Upstream I/O error.
        source: std::io::Error,
    },

    /// The requested model artifact is not present in the on-device
    /// cache (download required).
    #[error("model `{0}` not cached")]
    NotCached(&'static str),

    /// A `Mutex` / `RwLock` guarding a model-subsystem resource was
    /// poisoned by a panicking thread. Carries the resource name so
    /// callers can route on it (`"model_manager_registry"`,
    /// `"ep_benchmark_runner"`, `"clip_session"`, \u2026).
    ///
    /// This mirrors [`crate::local_store::StorageError::LockPoisoned`]
    /// but keeps model-subsystem lock failures on the `model`
    /// category at the bridge layer (`Error::Model`) rather than
    /// silently re-categorising them onto `storage`. Bridge consumers
    /// (Android / iOS) route the JSON `category` field; a
    /// `ModelManager` registry lock poisoning is a model-subsystem
    /// invariant violation, not a storage-driver failure, so the
    /// category must stay `"model"`.
    #[error("`{0}` lock poisoned")]
    LockPoisoned(&'static str),

    /// Free-form fallback. New failure modes should prefer a typed
    /// variant.
    #[error("{0}")]
    Custom(String),
}

impl ModelError {
    /// Construct a [`ModelError::Custom`] from anything convertible
    /// to [`String`].
    pub fn msg(msg: impl Into<String>) -> Self {
        ModelError::Custom(msg.into())
    }
}
