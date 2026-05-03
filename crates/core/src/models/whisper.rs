//! On-device Whisper transcription scaffold — Apple MLX
//! (preferred on Apple Silicon) with ONNX Runtime as the
//! cross-platform fallback.
//!
//! `docs/PROPOSAL.md §7.6` (on-device ML models) and §7.7
//! (platform ML execution). On Apple Silicon (`macOS` and `iOS`
//! `aarch64`), `Whisper-base` runs through Apple MLX
//! ([`mlx-community/whisper-base-mlx`](https://huggingface.co/mlx-community/whisper-base-mlx)),
//! which routes inference to the Neural Engine for
//! significantly lower latency and battery cost than ONNX
//! Runtime CPU EP. On every other target — Intel macOS,
//! Windows, Linux, and Android — the pipeline falls back to
//! the multilingual `whisper-base.int8.onnx` artifact through
//! ONNX Runtime, mirroring the
//! [`crate::models::embeddings_onnx`] DirectML → CPU
//! best-effort pattern.
//!
//! This module is the Phase 6 scaffolding. The actual
//! inference loops (audio → mel-spectrogram → encoder/decoder
//! → token stream → text) are intentionally NOT wired here yet
//! — they land alongside the MLX bridge crate (`mlx-rs`) and
//! the ONNX whisper inference glue in a follow-up. What lands
//! now is:
//!
//! * The pure [`select_whisper_backend`] state machine over
//!   an [`AppleSiliconProbe`] trait — exhaustively unit-tested
//!   on every host (Linux CI, Intel macOS, Windows, Apple
//!   Silicon).
//! * The canonical `model_version` tags
//!   ([`WHISPER_BASE_MLX_MODEL_VERSION`] /
//!   [`WHISPER_BASE_ONNX_MODEL_VERSION`]) and Hugging Face
//!   model-repo identifiers
//!   ([`WHISPER_BASE_MLX_MODEL_REPO`] /
//!   [`WHISPER_BASE_ONNX_ARTIFACT`]) used by the model manager
//!   when deciding which artifact to download per device.
//! * The [`WhisperBackend`] enum the model manager and the
//!   transcription orchestrator consume.
//!
//! Whisper is **not** quantized to INT4 — see PROPOSAL §7.6.
//! INT8 ONNX (~140 MB) is the floor for the ONNX path; the
//! MLX path consumes the upstream `mlx-community` weights as
//! published.

// ---------------------------------------------------------------------------
// Canonical model identifiers
// ---------------------------------------------------------------------------

/// Canonical `model_version` tag for the MLX-flavored
/// `Whisper-base` artifact shipped to Apple Silicon devices.
///
/// `docs/PROPOSAL.md §7.6.1` (cross-pipeline cache versioning
/// pattern). The MLX path is keyed independently from the ONNX
/// path so that a device that hops between MLX (Apple Silicon)
/// and ONNX (e.g. an Intel-Mac desktop binary running on the
/// same iCloud account) does not silently consume a transcript
/// computed under a different decoder family. Bump this constant
/// whenever the upstream MLX checkpoint is rev'd.
pub const WHISPER_BASE_MLX_MODEL_VERSION: &str = "whisper_base_mlx@v1";

/// Canonical `model_version` tag for the ONNX-flavored
/// `Whisper-base` artifact shipped to non-Apple-Silicon devices.
pub const WHISPER_BASE_ONNX_MODEL_VERSION: &str = "whisper_base_onnx_int8@v1";

/// Hugging Face repo identifier for the MLX-quantized
/// `Whisper-base` artifact.
///
/// The model manager downloads this repo on Apple Silicon
/// targets only (see [`select_whisper_backend`]). Mirrors the
/// MLX SLM strategy adopted in
/// [`kennguy3n/slm-chat-demo`](https://github.com/kennguy3n/slm-chat-demo)
/// and [`kennguy3n/cv-guard`](https://github.com/kennguy3n/cv-guard)
/// — Whisper joins the same MLX-on-Apple-Silicon track those
/// repos established for the SLM stack.
pub const WHISPER_BASE_MLX_MODEL_REPO: &str = "mlx-community/whisper-base-mlx";

/// Filename of the ONNX-quantized `Whisper-base` artifact
/// downloaded on every non-Apple-Silicon target.
///
/// `docs/PROPOSAL.md §7.6` — INT8 is the floor for Whisper;
/// INT4 is intentionally NOT supported because the audio
/// transcription quality regression at INT4 is too large.
pub const WHISPER_BASE_ONNX_ARTIFACT: &str = "whisper-base.int8.onnx";

// ---------------------------------------------------------------------------
// Backend-selection state machine — always compiled, no `mlx-rs` /
// no `ort` dependency, exhaustively unit-tested on any host.
// ---------------------------------------------------------------------------

/// Identifier for the Whisper backend that was actually
/// selected for a given device.
///
/// `Mlx` is only selected on Apple Silicon (`macOS` / `iOS`
/// `aarch64`) when the [`AppleSiliconProbe`] reports the
/// platform supports MLX inference. `Onnx` is the universal
/// fallback and is always available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WhisperBackend {
    /// Apple MLX — preferred on Apple Silicon. Routes to the
    /// Neural Engine; consumes
    /// [`WHISPER_BASE_MLX_MODEL_REPO`].
    Mlx,
    /// ONNX Runtime — cross-platform fallback. Consumes
    /// [`WHISPER_BASE_ONNX_ARTIFACT`].
    Onnx,
}

impl WhisperBackend {
    /// Stable, telemetry-friendly name for the selected
    /// backend.
    ///
    /// Matches the strings emitted by the analogous SLM and
    /// CLIP backends across the platform (`"MLX"` /
    /// `"ONNX"`) so any future cross-product telemetry
    /// pipeline can reuse the same dimensions.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mlx => "MLX",
            Self::Onnx => "ONNX",
        }
    }

    /// Canonical `model_version` tag the model manager
    /// writes to disk and the transcription orchestrator
    /// hashes into the cache key alongside `(media_asset_id)`.
    ///
    /// MLX and ONNX transcripts are versioned independently
    /// so the cache cannot leak a transcript across decoder
    /// families.
    pub const fn model_version(self) -> &'static str {
        match self {
            Self::Mlx => WHISPER_BASE_MLX_MODEL_VERSION,
            Self::Onnx => WHISPER_BASE_ONNX_MODEL_VERSION,
        }
    }
}

/// Result of [`select_whisper_backend`] — which backend was
/// selected and whether the MLX probe was even consulted on
/// this host.
///
/// `mlx_attempted` is `false` on non-Apple-Silicon targets (we
/// short-circuit to ONNX without probing) and `true` on
/// `macOS` / `iOS` `aarch64` regardless of the outcome (so
/// telemetry can distinguish "MLX probe ran and reported
/// unavailable" from "MLX not applicable on this OS at all").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WhisperBackendReport {
    /// The backend that should be (or was) selected for the
    /// session.
    pub backend: WhisperBackend,
    /// `true` if the [`AppleSiliconProbe`] was consulted on
    /// this host.
    pub mlx_attempted: bool,
}

/// Cheap probe of MLX availability on Apple Silicon.
///
/// Factored out of [`select_whisper_backend`] so the
/// backend-selection state machine can be exhaustively
/// unit-tested on non-Apple hosts without requiring an MLX
/// runtime to be installed. The production probe lives in
/// [`MlxAppleSiliconProbe`] and is gated behind
/// `cfg(all(target_arch = "aarch64", any(target_os = "macos",
/// target_os = "ios")))`.
///
/// Implementations MUST be cheap (no allocation, no I/O
/// beyond what MLX does internally) and MUST NOT panic on
/// failure — any error path inside the probe is reported as
/// `false`, which falls back to ONNX.
pub trait AppleSiliconProbe {
    /// Return `true` if MLX inference is available on the
    /// current host, `false` otherwise.
    fn mlx_available(&self) -> bool;
}

/// Pure backend-selection function. Returns the backend that
/// should be used for a Whisper session given a probe of MLX
/// availability.
///
/// On non-Apple-Silicon targets the result is always
/// [`WhisperBackend::Onnx`] — the MLX branch is
/// `cfg(all(target_arch = "aarch64", any(target_os = "macos",
/// target_os = "ios")))` gated to mirror what the production
/// MLX bridge can actually link against. On Apple Silicon
/// the MLX backend is preferred when the probe reports
/// availability; otherwise we fall back to ONNX.
///
/// The probe is taken by reference (with `?Sized` so
/// dyn-objects work) because the production probe is a
/// zero-sized type and the test stub holds a single `bool`.
pub fn select_whisper_backend<P: AppleSiliconProbe + ?Sized>(probe: &P) -> WhisperBackendReport {
    #[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
    {
        if probe.mlx_available() {
            return WhisperBackendReport {
                backend: WhisperBackend::Mlx,
                mlx_attempted: true,
            };
        }
        WhisperBackendReport {
            backend: WhisperBackend::Onnx,
            mlx_attempted: true,
        }
    }
    #[cfg(not(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios"))))]
    {
        // Probe is irrelevant off Apple Silicon; consume it
        // to avoid an unused-parameter warning under
        // `#[deny(unused)]`.
        let _ = probe;
        WhisperBackendReport {
            backend: WhisperBackend::Onnx,
            mlx_attempted: false,
        }
    }
}

/// Hugging Face repo / artifact identifier the model manager
/// downloads for a given backend.
///
/// `docs/PROPOSAL.md §7.6` — Apple Silicon downloads
/// [`WHISPER_BASE_MLX_MODEL_REPO`]; every other target
/// downloads [`WHISPER_BASE_ONNX_ARTIFACT`]. The split avoids
/// shipping ~140 MB of ONNX weights to devices that will
/// never load them.
pub fn whisper_base_artifact_for(backend: WhisperBackend) -> &'static str {
    match backend {
        WhisperBackend::Mlx => WHISPER_BASE_MLX_MODEL_REPO,
        WhisperBackend::Onnx => WHISPER_BASE_ONNX_ARTIFACT,
    }
}

// ---------------------------------------------------------------------------
// Production probe — Apple Silicon only.
//
// The MLX runtime detection is intentionally compile-time on Apple
// Silicon: any `aarch64` `macOS` / `iOS` build that links Whisper
// SHOULD also link the MLX bridge, so MLX is "available" iff the
// build target is Apple Silicon. A real device-level probe (Neural
// Engine present, MLX shared library loadable, …) lands together
// with the `mlx-rs` integration in a follow-up.
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
mod apple_silicon {
    use super::AppleSiliconProbe;

    /// Production [`AppleSiliconProbe`] for Apple Silicon
    /// builds. Currently a compile-time `true` — replaced
    /// with a runtime `mlx-rs` availability check in the
    /// follow-up that wires actual inference.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct MlxAppleSiliconProbe;

    impl AppleSiliconProbe for MlxAppleSiliconProbe {
        fn mlx_available(&self) -> bool {
            true
        }
    }
}

#[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
pub use apple_silicon::MlxAppleSiliconProbe;

#[cfg(not(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios"))))]
mod non_apple_silicon {
    use super::AppleSiliconProbe;

    /// Non-Apple-Silicon [`AppleSiliconProbe`] — MLX never
    /// available. Provided for parity so callers can name
    /// the same type across platforms when wiring telemetry.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct MlxAppleSiliconProbe;

    impl AppleSiliconProbe for MlxAppleSiliconProbe {
        fn mlx_available(&self) -> bool {
            false
        }
    }
}

#[cfg(not(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios"))))]
pub use non_apple_silicon::MlxAppleSiliconProbe;

// ---------------------------------------------------------------------------
// Tests — exercise `select_whisper_backend` exhaustively. The
// real MLX / ONNX inference loops are not unit-testable without
// a real MLX runtime + a real .onnx fixture, so they are
// deferred to the Phase 6 integration test suite.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub probe with an injected boolean so the
    /// backend-selection state machine can be exercised on
    /// any host.
    struct StubProbe(bool);
    impl AppleSiliconProbe for StubProbe {
        fn mlx_available(&self) -> bool {
            self.0
        }
    }

    #[test]
    fn backend_name_is_stable() {
        assert_eq!(WhisperBackend::Mlx.name(), "MLX");
        assert_eq!(WhisperBackend::Onnx.name(), "ONNX");
    }

    #[test]
    fn model_version_tags_distinguish_backends() {
        // The MLX and ONNX transcripts MUST be cached under
        // distinct version tags so a transcript produced on
        // one decoder family cannot be served back on the
        // other after a device hop. See PROPOSAL §7.6.1.
        assert_ne!(
            WhisperBackend::Mlx.model_version(),
            WhisperBackend::Onnx.model_version()
        );
        assert!(WhisperBackend::Mlx.model_version().contains('@'));
        assert!(WhisperBackend::Onnx.model_version().contains('@'));
    }

    #[test]
    fn artifact_repo_split_per_backend() {
        // Apple Silicon devices download MLX weights from
        // Hugging Face; everyone else downloads the ONNX
        // INT8 artifact. The split avoids shipping ~140 MB
        // of unused weights to either side.
        assert_eq!(
            whisper_base_artifact_for(WhisperBackend::Mlx),
            "mlx-community/whisper-base-mlx"
        );
        assert_eq!(
            whisper_base_artifact_for(WhisperBackend::Onnx),
            "whisper-base.int8.onnx"
        );
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn mlx_preferred_when_available_on_apple_silicon() {
        let report = select_whisper_backend(&StubProbe(true));
        assert_eq!(report.backend, WhisperBackend::Mlx);
        assert!(report.mlx_attempted);
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn onnx_fallback_when_mlx_unavailable_on_apple_silicon() {
        let report = select_whisper_backend(&StubProbe(false));
        assert_eq!(report.backend, WhisperBackend::Onnx);
        assert!(
            report.mlx_attempted,
            "the probe should still be consulted on Apple Silicon"
        );
    }

    #[cfg(not(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios"))))]
    #[test]
    fn mlx_never_attempted_off_apple_silicon_even_if_probe_lies() {
        // Even a probe that returns `true` must be ignored
        // off Apple Silicon: the MLX runtime is only
        // available on `aarch64` `macOS` / `iOS`.
        let report = select_whisper_backend(&StubProbe(true));
        assert_eq!(report.backend, WhisperBackend::Onnx);
        assert!(!report.mlx_attempted);
    }

    #[cfg(not(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios"))))]
    #[test]
    fn onnx_selected_off_apple_silicon_with_unavailable_probe() {
        let report = select_whisper_backend(&StubProbe(false));
        assert_eq!(report.backend, WhisperBackend::Onnx);
        assert!(!report.mlx_attempted);
    }

    #[test]
    fn select_backend_accepts_dyn_probe() {
        // Sanity: the `?Sized` bound means
        // `&dyn AppleSiliconProbe` works too, which keeps
        // the seam friendly to runtime probe injection
        // (e.g. forcing ONNX via a config flag for A/B
        // benchmarking).
        let probe: &dyn AppleSiliconProbe = &StubProbe(false);
        let report = select_whisper_backend(probe);
        assert_eq!(report.backend, WhisperBackend::Onnx);
    }
}
