//! Desktop ML execution-provider selection adapter.
//!
//! `docs/ARCHITECTURE.md §11.4` mandates per-platform EP
//! selection: CoreML on macOS, DirectML on Windows (when a GPU
//! is present), CPU on Linux and as the universal fallback.
//! [`DesktopExecutionProviderSelector`] is the desktop-side
//! adapter that pre-fills [`Platform::MacOs`] / [`Platform::Windows`]
//! / [`Platform::Linux`] from the host `cfg!(target_os = …)` and
//! delegates to the cross-platform
//! [`ExecutionProviderSelector`] in
//! `crates/core/src/models/ep_tuning.rs`.
//!
//! Why a thin adapter rather than re-exporting?
//!
//! * The `desktop` crate is what's actually compiled into the
//!   macOS / Windows / Linux binary, so it's the natural place to
//!   bind compile-time platform detection.
//! * Tests can still drive the underlying state machine by
//!   constructing [`DeviceCapabilities`] manually and calling
//!   [`DesktopExecutionProviderSelector::select_for_platform`].

use kchat_core::models::ep_tuning::{
    DeviceCapabilities, EpFallbackChain, ExecutionProvider, ExecutionProviderSelector, Platform,
};

/// Detect the platform the desktop binary is currently running
/// on. Returns [`Platform::MacOs`] / [`Platform::Windows`] /
/// [`Platform::Linux`] / [`Platform::Unknown`] depending on the
/// `target_os` cfg.
pub const fn host_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOs
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        Platform::Unknown
    }
}

/// Desktop-side wrapper around [`ExecutionProviderSelector`]
/// that pre-fills the host platform from the `target_os` cfg.
#[derive(Debug, Default)]
pub struct DesktopExecutionProviderSelector {
    inner: ExecutionProviderSelector,
}

impl DesktopExecutionProviderSelector {
    /// Construct an empty selector. Production callers register
    /// per-EP benchmarks through
    /// [`ExecutionProviderSelector::record_benchmark`] reachable
    /// via [`Self::inner_mut`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Pick an EP for the host platform using the supplied
    /// [`DeviceCapabilities`]. The capabilities `os` field is
    /// **ignored** in favour of the host platform detected from
    /// `cfg!(target_os = …)`; the rest of the struct (GPU /
    /// NPU presence, vendor, arch) is forwarded verbatim.
    pub fn select(&self, capabilities: &DeviceCapabilities) -> ExecutionProvider {
        self.inner.select_ep(host_platform(), capabilities)
    }

    /// Like [`Self::select`] but lets callers override the
    /// platform — useful for tests that want to assert the
    /// state machine produces the right EP for a hypothetical
    /// platform.
    pub fn select_for_platform(
        &self,
        platform: Platform,
        capabilities: &DeviceCapabilities,
    ) -> ExecutionProvider {
        self.inner.select_ep(platform, capabilities)
    }

    /// Borrow the underlying state machine for benchmark recording.
    pub fn inner_mut(&mut self) -> &mut ExecutionProviderSelector {
        &mut self.inner
    }

    /// Borrow the underlying state machine.
    pub fn inner(&self) -> &ExecutionProviderSelector {
        &self.inner
    }
}

/// GPU detection stub.
///
/// On Windows, the production build will probe DirectX / DXGI to
/// confirm a DirectML-compatible adapter is present. This stub
/// returns `false` so the desktop binary degrades cleanly to CPU
/// until the platform-bridge follow-up lands. Tests can call
/// [`detect_gpu_available_with_override`] to force the answer.
pub fn detect_gpu_available() -> bool {
    detect_gpu_available_with_override(None)
}

/// Test hook that lets the unit tests force the GPU-availability
/// answer without touching real platform APIs.
pub fn detect_gpu_available_with_override(force: Option<bool>) -> bool {
    force.unwrap_or(false)
}

/// build the host-platform
/// [`EpFallbackChain`] for desktop.
///
/// Combines [`host_platform`] with [`detect_gpu_available`] to
/// produce a fallback chain the desktop ONNX session loaders can
/// walk through. Returns CPU-only on Windows when no GPU is
/// detected, [`CoreMl`, `Cpu`] on macOS, [`Cpu`] on Linux.
pub fn host_fallback_chain() -> EpFallbackChain {
    let platform = host_platform();
    let has_gpu = detect_gpu_available();
    let caps = DeviceCapabilities {
        has_gpu,
        // The desktop binary doesn't expose an NPU — the iOS /
        // Android bridges do that.
        has_npu: false,
        gpu_vendor: None,
        os: platform,
        // Desktop is x86_64 on Windows / Linux and aarch64 on
        // Apple Silicon, but the EP state machine doesn't
        // pivot on arch — pin to a placeholder.
        arch: kchat_core::models::ep_tuning::Arch::X86_64,
    };
    EpFallbackChain::for_platform(platform, &caps)
}

/// convenience entry
/// point that the desktop ONNX-session creation path calls into.
///
/// Returns the `(host_platform, primary_ep, fallback_chain)`
/// triple the session creator needs. The actual `ort::Session`
/// build lives in [`kchat_core::models::embeddings_onnx`] behind
/// the `onnx-runtime` cargo feature; this function is the
/// always-compiled, always-testable wiring that hands the
/// session-builder its configuration.
pub fn create_desktop_session_config() -> (Platform, ExecutionProvider, EpFallbackChain) {
    let chain = host_fallback_chain();
    let primary = chain.primary();
    (host_platform(), primary, chain)
}

/// end-to-end desktop
/// session helper for the XLM-R text encoder.
///
/// Walks [`host_fallback_chain`] to pick the primary EP, then
/// hands `(model_path, ep)` to
/// [`kchat_core::models::embeddings_onnx::create_xlmr_session_with_ep`].
/// On Windows + DirectML this attempts DirectML first and falls
/// back to CPU; on macOS / Linux it registers the CPU EP.
///
/// The function is feature-gated on `onnx-runtime` because the
/// underlying `ort::Session` only exists with that feature; tests
/// without `--features onnx-runtime` exercise the always-compiled
/// state-machine pieces ([`host_fallback_chain`],
/// [`create_desktop_session_config`]).
#[cfg(feature = "onnx-runtime")]
pub fn create_desktop_session(
    model_path: &std::path::Path,
) -> kchat_core::models::embeddings_onnx::OrtSessionResult<(
    kchat_core::models::embeddings_onnx::OrtSession,
    kchat_core::models::embeddings_onnx::OnnxProviderReport,
)> {
    let (_, primary, _chain) = create_desktop_session_config();
    kchat_core::models::embeddings_onnx::create_xlmr_session_with_ep(model_path, primary)
}

/// stub for the
/// always-on shape when the `onnx-runtime` feature is off.
#[cfg(not(feature = "onnx-runtime"))]
pub fn create_desktop_session(_model_path: &std::path::Path) -> kchat_core::Result<()> {
    Err(kchat_core::Error::NotImplemented(
        "create_desktop_session requires onnx-runtime feature",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kchat_core::models::ep_tuning::Arch;

    #[test]
    fn host_platform_matches_target_os_cfg() {
        let host = host_platform();
        if cfg!(target_os = "macos") {
            assert_eq!(host, Platform::MacOs);
        } else if cfg!(target_os = "windows") {
            assert_eq!(host, Platform::Windows);
        } else if cfg!(target_os = "linux") {
            assert_eq!(host, Platform::Linux);
        } else {
            assert_eq!(host, Platform::Unknown);
        }
    }

    #[test]
    fn select_for_platform_routes_macos_to_coreml_with_npu() {
        let s = DesktopExecutionProviderSelector::new();
        let caps = DeviceCapabilities::apple_silicon_mac();
        assert_eq!(
            s.select_for_platform(Platform::MacOs, &caps),
            ExecutionProvider::CoreMl
        );
    }

    #[test]
    fn select_for_platform_routes_windows_with_gpu_to_directml() {
        let s = DesktopExecutionProviderSelector::new();
        let caps = DeviceCapabilities::windows_with_gpu("nvidia");
        assert_eq!(
            s.select_for_platform(Platform::Windows, &caps),
            ExecutionProvider::DirectMl
        );
    }

    #[test]
    fn select_for_platform_falls_back_to_cpu_on_linux() {
        let s = DesktopExecutionProviderSelector::new();
        let caps = DeviceCapabilities::cpu_only(Platform::Linux, Arch::X86_64);
        assert_eq!(
            s.select_for_platform(Platform::Linux, &caps),
            ExecutionProvider::Cpu
        );
    }

    #[test]
    fn select_uses_host_platform_for_real_dispatch() {
        let s = DesktopExecutionProviderSelector::new();
        // The host is whatever the test runner is compiled
        // for. We don't know its capabilities, but the result
        // must be one of the legal EPs.
        let caps = DeviceCapabilities::cpu_only(host_platform(), Arch::X86_64);
        let ep = s.select(&caps);
        assert!(matches!(
            ep,
            ExecutionProvider::CoreMl
                | ExecutionProvider::DirectMl
                | ExecutionProvider::Nnapi
                | ExecutionProvider::Cpu
                | ExecutionProvider::MetalPerformanceShaders
        ));
    }

    #[test]
    fn detect_gpu_available_default_false() {
        // Stub returns `false` until the platform-bridge probe
        // lands.
        assert!(!detect_gpu_available());
    }

    #[test]
    fn detect_gpu_available_override_returns_forced_value() {
        assert!(detect_gpu_available_with_override(Some(true)));
        assert!(!detect_gpu_available_with_override(Some(false)));
    }

    #[test]
    fn desktop_ml_ep_selector_matches_core_selector() {
        // Drive the same input through both selectors — the
        // desktop wrapper must produce the same answer as the
        // raw core selector for any explicit platform/caps
        // pair.
        let desktop = DesktopExecutionProviderSelector::new();
        let core = ExecutionProviderSelector::new();
        for caps in [
            DeviceCapabilities::apple_silicon_mac(),
            DeviceCapabilities::apple_silicon_ios(),
            DeviceCapabilities::android_with_npu(),
            DeviceCapabilities::windows_with_gpu("nvidia"),
            DeviceCapabilities::cpu_only(Platform::Linux, Arch::X86_64),
        ] {
            for platform in [
                Platform::MacOs,
                Platform::Ios,
                Platform::Android,
                Platform::Windows,
                Platform::Linux,
            ] {
                assert_eq!(
                    desktop.select_for_platform(platform, &caps),
                    core.select_ep(platform, &caps),
                    "mismatch for platform={platform:?} caps={caps:?}"
                );
            }
        }
    }

    #[test]
    fn host_fallback_chain_is_non_empty_and_ends_in_cpu() {
        let chain = host_fallback_chain();
        let slice = chain.as_slice();
        assert!(!slice.is_empty());
        assert_eq!(slice.last().copied().unwrap(), ExecutionProvider::Cpu);
    }

    #[test]
    fn create_desktop_session_config_reports_host_platform() {
        let (platform, primary, chain) = create_desktop_session_config();
        assert_eq!(platform, host_platform());
        // The primary EP and the chain's primary must agree.
        assert_eq!(primary, chain.primary());
    }

    #[test]
    fn desktop_ml_ep_selector_windows_with_gpu_returns_directml() {
        let s = DesktopExecutionProviderSelector::new();
        let caps = DeviceCapabilities::windows_with_gpu("nvidia");
        assert_eq!(
            s.select_for_platform(Platform::Windows, &caps),
            ExecutionProvider::DirectMl
        );
    }

    #[test]
    fn desktop_ml_ep_selector_windows_without_gpu_returns_cpu() {
        let s = DesktopExecutionProviderSelector::new();
        let caps = DeviceCapabilities::cpu_only(Platform::Windows, Arch::X86_64);
        assert_eq!(
            s.select_for_platform(Platform::Windows, &caps),
            ExecutionProvider::Cpu
        );
    }
}
