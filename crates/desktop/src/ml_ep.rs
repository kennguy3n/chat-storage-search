//! Desktop ML execution-provider selection adapter — Phase 7,
//! batch-5 (2026-05-04).
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
    DeviceCapabilities, ExecutionProvider, ExecutionProviderSelector, Platform,
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
}
