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
