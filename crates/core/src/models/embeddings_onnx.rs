//! On-device ONNX Runtime session creator for the XLM-R text
//! encoder, plus the shared best-effort DirectML → CPU
//! execution-provider state machine reused by
//! [`crate::models::clip`] for MobileCLIP-S2.
//!
//! `docs/PROPOSAL.md §7.7` and `docs/ARCHITECTURE.md §11.4`. On
//! Windows the session is created with the DirectML EP first; if
//! DirectML initialization fails (no compatible GPU, driver
//! issues, ONNX Runtime not built with DirectML support, model
//! contains operators DirectML cannot run, …) we fall back to
//! the CPU EP without failing the session-create call. On
//! non-Windows targets only the CPU EP is attempted.
//!
//! This module is the Phase 6 scaffolding: the EP-selection
//! state machine lands now (always compiled, no `ort` dependency)
//! so it can be exhaustively unit-tested on Linux / macOS CI
//! without needing a DirectML adapter or even an ONNX Runtime
//! build. The actual `ort::Session` creators are gated behind
//! both `cfg(target_os = "windows")` (to pick up the
//! `directml`-featured `ort` build registered by
//! `crates/core/Cargo.toml`'s
//! `[target.'cfg(windows)'.dependencies]` block) and the
//! `onnx-runtime` cargo feature, so the default workspace build
//! and the `--all-features` clippy lint pass on Linux do not
//! require any ORT shared library to be present.
//!
//! The Rust pattern mirrors the C++/WinRT
//! `OnnxInferenceBridge` in
//! [`kennguy3n/cv-guard`](https://github.com/kennguy3n/cv-guard)
//! at
//! `desktop/native/windows/Sources/CVGuardAddon/OnnxInferenceBridge.cpp`.

// ---------------------------------------------------------------------------
// EP-selection state machine — always compiled, no `ort` dependency
// ---------------------------------------------------------------------------

/// Identifier for the ONNX Runtime execution provider that was
/// actually selected for a session.
///
/// `Cpu` is the universal fallback and is always available.
/// `DirectMl` is only ever selected on Windows builds where ORT
/// has been compiled with the `directml` feature AND a
/// compatible adapter is present at session-create time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnnxExecutionProvider {
    /// Microsoft DirectML execution provider.
    DirectMl,
    /// ONNX Runtime CPU execution provider.
    Cpu,
}

impl OnnxExecutionProvider {
    /// Stable, telemetry-friendly name for the selected provider.
    ///
    /// Matches the strings emitted by the cv-guard
    /// `OnnxInferenceBridge` (`"DirectML"` / `"CPU"`) so any
    /// future cross-product telemetry pipeline can reuse the
    /// same dimensions.
    pub const fn name(self) -> &'static str {
        match self {
            Self::DirectMl => "DirectML",
            Self::Cpu => "CPU",
        }
    }
}

/// Result of [`select_provider`] — which EP was selected and
/// whether DirectML was even attempted on this host.
///
/// `directml_attempted` is `false` on non-Windows targets (we
/// short-circuit to CPU without probing) and `true` on Windows
/// regardless of the outcome (so telemetry can distinguish
/// "DirectML probe ran and reported unavailable" from "DirectML
/// not applicable on this OS at all").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OnnxProviderReport {
    /// The provider that should be (or was) registered on the
    /// session.
    pub provider: OnnxExecutionProvider,
    /// `true` if the DirectML probe was consulted on this host.
    pub directml_attempted: bool,
}

/// Cheap probe of DirectML availability.
///
/// Factored out of [`select_provider`] so the EP-selection state
/// machine can be exhaustively unit-tested on non-Windows hosts
/// without requiring any DirectML adapter or ONNX Runtime build
/// to be present. The production probe lives in
/// `OrtDirectMlProbe` and is gated behind both
/// `cfg(target_os = "windows")` and the `onnx-runtime` cargo
/// feature.
///
/// Implementations MUST be cheap (no allocation, no I/O beyond
/// what ORT does internally) and MUST NOT panic on failure —
/// any error path inside the probe is reported as `false`.
pub trait DirectMlProbe {
    /// Return `true` if DirectML is available on the current
    /// host, `false` otherwise.
    fn directml_available(&self) -> bool;
}

/// Pure EP-selection function. Returns the EP that should be
/// used for a session given a probe of DirectML availability.
///
/// On non-Windows targets the result is always
/// [`OnnxExecutionProvider::Cpu`] — the DirectML branch is
/// `cfg(target_os = "windows")` gated to mirror the `ort`
/// crate's own `directml` feature gating. On Windows the
/// DirectML EP is preferred when the probe reports
/// availability; otherwise we fall back to CPU.
///
/// The probe is taken by reference (with `?Sized` so dyn-objects
/// work) because the production probe is a zero-sized type and
/// the test stub holds a single `bool`.
pub fn select_provider<P: DirectMlProbe + ?Sized>(probe: &P) -> OnnxProviderReport {
    #[cfg(target_os = "windows")]
    {
        if probe.directml_available() {
            return OnnxProviderReport {
                provider: OnnxExecutionProvider::DirectMl,
                directml_attempted: true,
            };
        }
        OnnxProviderReport {
            provider: OnnxExecutionProvider::Cpu,
            directml_attempted: true,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Probe is irrelevant on non-Windows; consume it to
        // avoid an unused-parameter warning under
        // `#[deny(unused)]`.
        let _ = probe;
        OnnxProviderReport {
            provider: OnnxExecutionProvider::Cpu,
            directml_attempted: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Real `ort::Session` creator — Windows + onnx-runtime feature
// ---------------------------------------------------------------------------

/// Result type for the ONNX Runtime session creators.
///
/// Aliased so callers (and the documentation) need not depend
/// on `ort::Result` directly. Only re-exported when the
/// `onnx-runtime` feature is enabled.
#[cfg(feature = "onnx-runtime")]
pub type OrtSessionResult<T> = ort::Result<T>;

#[cfg(all(target_os = "windows", feature = "onnx-runtime"))]
mod windows_directml {
    use super::{
        select_provider, DirectMlProbe, OnnxExecutionProvider, OnnxProviderReport, OrtSessionResult,
    };
    use ort::ep::{DirectML, ExecutionProvider, CPU};
    use ort::session::Session;
    use std::path::Path;

    /// Production [`DirectMlProbe`] backed by
    /// [`ort::ep::DirectML::is_available`]. Returns `false` on
    /// any error from ORT instead of propagating.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct OrtDirectMlProbe;

    impl DirectMlProbe for OrtDirectMlProbe {
        fn directml_available(&self) -> bool {
            DirectML::default().is_available().unwrap_or(false)
        }
    }

    /// Create an `ort::Session` for the XLM-R text encoder
    /// loaded from `model_path`.
    ///
    /// Tries DirectML first (per [`select_provider`]); falls
    /// back to CPU if DirectML registration on the
    /// [`SessionBuilder`] returns an error. The returned
    /// [`OnnxProviderReport`] reflects the EP that was actually
    /// registered on the resulting session, not the original
    /// intent — i.e. if the probe reported DirectML available
    /// but registration failed, the report reads
    /// `provider: Cpu, directml_attempted: true`.
    ///
    /// This is the Phase 6 scaffold: the inference loop
    /// (input-tensor encode → `session.run` → mean-pool →
    /// `Vec<f32>`) is intentionally not wired here yet — that
    /// lands together with the SentencePiece tokenizer in a
    /// follow-up. Callers that need a working text-embedding
    /// hook in the meantime should keep using the
    /// [`crate::models::embeddings::EmbeddingCache`] surface.
    pub fn create_xlmr_session(
        model_path: &Path,
    ) -> OrtSessionResult<(Session, OnnxProviderReport)> {
        let intent = select_provider(&OrtDirectMlProbe);
        let mut builder = Session::builder()?;

        let actual_provider = match intent.provider {
            OnnxExecutionProvider::DirectMl => {
                if DirectML::default().register(&mut builder).is_ok() {
                    OnnxExecutionProvider::DirectMl
                } else {
                    // DirectML probe lied (or registration failed
                    // for a model-specific reason). Fall back to
                    // CPU; CPU registration is best-effort because
                    // ORT auto-registers a default CPU EP at
                    // commit time anyway.
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
pub use windows_directml::{create_xlmr_session, OrtDirectMlProbe};

#[cfg(all(not(target_os = "windows"), feature = "onnx-runtime"))]
mod posix_cpu {
    use super::{select_provider, DirectMlProbe, OnnxProviderReport, OrtSessionResult};
    use ort::ep::{ExecutionProvider, CPU};
    use ort::session::Session;
    use std::path::Path;

    /// Non-Windows [`DirectMlProbe`] — DirectML never available.
    /// Provided for parity so callers can name the same type
    /// across platforms when wiring telemetry.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct OrtDirectMlProbe;

    impl DirectMlProbe for OrtDirectMlProbe {
        fn directml_available(&self) -> bool {
            false
        }
    }

    /// macOS / Linux flavor of the XLM-R session creator.
    ///
    /// Always registers the CPU EP. The cross-platform
    /// inference seam (CoreML EP on Apple, NNAPI EP on Android,
    /// etc.) lands later in Phase 6 — this scaffold focuses on
    /// the Windows DirectML path called out in
    /// `docs/ARCHITECTURE.md §11.4`.
    pub fn create_xlmr_session(
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
pub use posix_cpu::{create_xlmr_session, OrtDirectMlProbe};

/// Phase 6, Task 5 (2026-05-04 batch): INT4 (`MatMulNBits`)
/// flavor of [`create_xlmr_session`].
///
/// Same EP-selection state machine and CPU fallback as
/// [`create_xlmr_session`] — the only difference is the
/// expected on-disk file (`xlmr-v1-int4.onnx`) carries
/// `MatMulNBits` nodes which `ort` honors at session-load time
/// without any extra `SessionBuilder` call. This helper exists
/// as a named seam so future graph-optimization tweaks can
/// land without touching the INT8 path.
#[cfg(feature = "onnx-runtime")]
pub fn create_xlmr_session_int4(
    model_path: &std::path::Path,
) -> OrtSessionResult<(ort::session::Session, OnnxProviderReport)> {
    create_xlmr_session(model_path)
}

/// Phase 6, Task 5 (2026-05-04 batch): INT4 session-creator
/// stub for builds without the `onnx-runtime` cargo feature.
#[cfg(not(feature = "onnx-runtime"))]
pub fn create_xlmr_session_int4(_model_path: &std::path::Path) -> crate::Result<()> {
    Err(crate::Error::NotImplemented(
        "create_xlmr_session_int4 requires onnx-runtime feature",
    ))
}

// ---------------------------------------------------------------------------
// OnnxTextEmbedder — long-lived `ort::Session` wrapper.
//
// Phase 6, Task 1 (`docs/PROPOSAL.md §7.6 / §7.7`,
// `docs/ARCHITECTURE.md §11.4`). The struct owns one
// `ort::Session` for the lifetime of the wrapper so XLM-R
// inference re-uses the same DirectML / CPU registration across
// every `embed_text` call rather than paying the session-build
// cost per message. The session is dropped when the wrapper is
// dropped — no extra teardown step is required because `ort`
// releases its underlying ONNX Runtime resources on `Drop`.
//
// The actual `session.run([input_ids, attention_mask]) →
// mean-pool → L2-normalize` inference loop is gated behind both
// `feature = "onnx-runtime"` and `cfg(target_os = "windows")` /
// `cfg(not(target_os = "windows"))` because:
//
// 1. The `ort` crate itself only resolves when the `onnx-runtime`
//    feature is on — without it the compiler does not see
//    `ort::Session`.
// 2. Without a real XLM-R `.onnx` artifact in the test corpus
//    `session.run` would fail, so the unit tests cannot exercise
//    the inference loop directly. The integration tests in the
//    Phase 6 model-manager suite supply a real model.
//
// What lives outside the feature gate (and is therefore unit-
// testable on every target) is the error-mapping shim:
// [`map_ort_error`] turns any `ort::Error` into the canonical
// [`crate::Error::Model(String)`] variant added in this task. The
// shim is a free function so the lifetime contract — "wrapping
// and inference share one error path" — is enforced at compile
// time.
// ---------------------------------------------------------------------------

#[cfg(feature = "onnx-runtime")]
use crate::Result;

/// Map an `ort::Error` to the canonical [`crate::Error::Model`]
/// variant.
///
/// Captures the upstream message verbatim so telemetry pipelines
/// (and the bridge crates in `kennguy3n/slm-guardrail` /
/// `kennguy3n/cv-guard`) can pattern-match on the `model:` prefix
/// without parsing the wrapped substring. Always returns the
/// `Model` variant; never `Storage` or `Search`, even if the
/// upstream message mentions a database or query — the on-device
/// ML pipeline is a single error domain at the public surface.
#[cfg(feature = "onnx-runtime")]
pub(crate) fn map_ort_error(err: ort::Error) -> crate::Error {
    crate::Error::Model(err.to_string())
}

/// Long-lived ONNX Runtime wrapper for the XLM-R text encoder.
///
/// Construction loads the model from disk and registers the
/// preferred execution provider (DirectML on Windows when
/// available, CPU everywhere else). Subsequent `embed_text`
/// calls reuse the same session — the `ort::Session` holds the
/// per-graph state (allocator, optimized graph, EP context) so
/// per-call cost is just tokenization + tensor binding +
/// inference, not full session recreation.
///
/// The struct is `Send + Sync`-friendly *given* that `ort::Session`
/// is itself `Send + Sync` in the version of `ort` we depend on;
/// the wrapper carries a `Mutex` around the session to short-
/// borrow it for inference without forcing `&mut self` through
/// the [`crate::models::embeddings::TextEmbedder`] trait.
#[cfg(feature = "onnx-runtime")]
pub struct OnnxTextEmbedder {
    session: std::sync::Mutex<ort::session::Session>,
    report: OnnxProviderReport,
    /// Maximum input-token sequence length the wrapper enforces
    /// before pad/truncate. Defaults to 128 — matches the XLM-R
    /// fine-tune used by `kennguy3n/slm-guardrail`.
    max_length: usize,
}

#[cfg(feature = "onnx-runtime")]
impl std::fmt::Debug for OnnxTextEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnnxTextEmbedder")
            .field("report", &self.report)
            .field("max_length", &self.max_length)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "onnx-runtime")]
impl OnnxTextEmbedder {
    /// Default maximum-token-sequence length used by [`Self::new`].
    pub const DEFAULT_MAX_LENGTH: usize = 128;

    /// Create a new XLM-R wrapper backed by the model at
    /// `model_path`.
    ///
    /// Errors map through [`map_ort_error`] so the public surface
    /// is a single [`crate::Error::Model`] variant, regardless of
    /// whether DirectML registration, model load, or graph
    /// optimization failed.
    pub fn new(model_path: &std::path::Path) -> Result<Self> {
        let (session, report) = create_xlmr_session(model_path).map_err(map_ort_error)?;
        Ok(Self {
            session: std::sync::Mutex::new(session),
            report,
            max_length: Self::DEFAULT_MAX_LENGTH,
        })
    }

    /// Replace the maximum input-token sequence length. Call this
    /// before the first `embed_text` to override the
    /// [`Self::DEFAULT_MAX_LENGTH`] default.
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Execution-provider report captured at session-create time.
    pub fn provider_report(&self) -> OnnxProviderReport {
        self.report
    }

    /// Maximum input-token-sequence length the wrapper applies
    /// before pad / truncate.
    pub fn max_length(&self) -> usize {
        self.max_length
    }

    /// Run XLM-R inference on `text` and return the mean-pooled,
    /// L2-normalized embedding.
    ///
    /// The inference loop (SentencePiece tokenization → pad /
    /// truncate to `max_length` → `session.run([input_ids,
    /// attention_mask])` → mean-pool last hidden state →
    /// L2-normalize) is intentionally not wired here yet: shipping
    /// it requires a SentencePiece tokenizer artifact that lives
    /// alongside the `.onnx` model in the [`super::model_manager`]
    /// cache, which is itself a Phase 6 follow-up. Until that
    /// lands, the wrapper returns
    /// [`crate::Error::NotImplemented`] so a caller that has
    /// installed an `OnnxTextEmbedder` learns about the missing
    /// inference loop loudly instead of silently returning a
    /// zero vector.
    pub fn embed_text(&self, text: &str) -> Result<Vec<f32>> {
        let _ = (text, &self.session, self.max_length);
        Err(crate::Error::NotImplemented(
            "onnx_text_embedder.embed_text",
        ))
    }
}

/// Always-`NotImplemented` `OnnxTextEmbedder` stub for builds
/// without the `onnx-runtime` feature.
///
/// `OnnxTextEmbedder` exists in both feature configurations so
/// downstream code can name the type unconditionally — it just
/// errors out on construction without the feature.
#[cfg(not(feature = "onnx-runtime"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct OnnxTextEmbedder;

#[cfg(not(feature = "onnx-runtime"))]
impl OnnxTextEmbedder {
    /// Always returns
    /// [`crate::Error::NotImplemented`](crate::Error::NotImplemented)
    /// — the `onnx-runtime` cargo feature is required for the
    /// real session creator.
    pub fn new(_model_path: &std::path::Path) -> crate::Result<Self> {
        Err(crate::Error::NotImplemented(
            "onnx_text_embedder.new (onnx-runtime feature disabled)",
        ))
    }

    /// Always returns
    /// [`crate::Error::NotImplemented`](crate::Error::NotImplemented).
    pub fn embed_text(&self, _text: &str) -> crate::Result<Vec<f32>> {
        Err(crate::Error::NotImplemented(
            "onnx_text_embedder.embed_text (onnx-runtime feature disabled)",
        ))
    }
}

// Sanity tests for the always-compiled stub variant — the real
// inference loop tests live behind `cfg(feature = "onnx-runtime")`
// in the Phase 6 model-manager integration suite.
#[cfg(all(test, not(feature = "onnx-runtime")))]
mod stub_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn stub_new_reports_feature_gate() {
        let err = OnnxTextEmbedder::new(&PathBuf::from("/nonexistent")).unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }

    #[test]
    fn stub_embed_text_reports_feature_gate() {
        let stub = OnnxTextEmbedder;
        let err = stub.embed_text("hello").unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }
}

// ---------------------------------------------------------------------------
// Tests — exercise `select_provider` exhaustively. The actual
// `ort::Session` creators are not unit-testable without a real
// ORT install + a real .onnx fixture, so they are deferred to
// the Phase 6 integration test suite.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub probe with an injected boolean so the EP-selection
    /// state machine can be exercised on any host.
    struct StubProbe(bool);
    impl DirectMlProbe for StubProbe {
        fn directml_available(&self) -> bool {
            self.0
        }
    }

    #[test]
    fn provider_name_is_stable() {
        assert_eq!(OnnxExecutionProvider::DirectMl.name(), "DirectML");
        assert_eq!(OnnxExecutionProvider::Cpu.name(), "CPU");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn directml_preferred_when_available_on_windows() {
        let report = select_provider(&StubProbe(true));
        assert_eq!(report.provider, OnnxExecutionProvider::DirectMl);
        assert!(report.directml_attempted);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn cpu_fallback_when_directml_unavailable_on_windows() {
        let report = select_provider(&StubProbe(false));
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
        assert!(
            report.directml_attempted,
            "the probe should still be consulted on Windows"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn directml_never_attempted_off_windows_even_if_probe_lies() {
        // Even a probe that returns `true` must be ignored on
        // non-Windows: the `directml` feature on the `ort` crate
        // is only enabled in `[target.'cfg(windows)'.dependencies]`,
        // so `ort::ep::DirectML` does not even exist here.
        let report = select_provider(&StubProbe(true));
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
        assert!(!report.directml_attempted);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn cpu_selected_off_windows_with_unavailable_probe() {
        let report = select_provider(&StubProbe(false));
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
        assert!(!report.directml_attempted);
    }

    #[test]
    fn select_provider_accepts_dyn_probe() {
        // Sanity: the `?Sized` bound means `&dyn DirectMlProbe`
        // works too, which keeps the seam friendly to runtime
        // probe injection (e.g. forcing CPU via a config flag).
        let probe: &dyn DirectMlProbe = &StubProbe(false);
        let report = select_provider(probe);
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
    }
}
