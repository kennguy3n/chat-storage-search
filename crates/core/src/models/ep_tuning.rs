//! Platform ML execution-provider selection state machine —
//! Phase 7, batch-5 (2026-05-04).
//!
//! `docs/ARCHITECTURE.md §11.4` calls for a per-platform
//! ONNX Runtime execution-provider (EP) selection policy:
//!
//! * **macOS**: CoreML EP (Apple Neural Engine when available) →
//!   CPU fallback.
//! * **iOS**: CoreML EP → CPU fallback.
//! * **Android**: NNAPI EP → CPU fallback.
//! * **Windows**: DirectML EP (when a GPU is present) → CPU
//!   fallback.
//! * **Linux**: CPU only.
//!
//! This module lands the **pure-Rust** state machine. The actual
//! `ort::SessionBuilder::with_execution_providers` calls live in
//! [`crate::models::embeddings_onnx`] and [`crate::models::clip`]
//! behind the `onnx-runtime` cargo feature; this state machine is
//! always compiled so the per-platform routing decision is unit-
//! testable on any host.
//!
//! ## Why this is in `core` rather than `desktop`
//!
//! [`crate::models`] also covers iOS / Android — every bridge
//! crate has its own platform pinned at compile time, but the
//! decision policy is identical and we don't want three copies of
//! it. Desktop callers wrap [`ExecutionProviderSelector`] with the
//! `desktop::ml_ep` adapter that pre-fills [`Platform::MacOs`] /
//! [`Platform::Windows`] / [`Platform::Linux`] from the host
//! `cfg!(target_os = …)`; bridge callers do the same for iOS /
//! Android. See `crates/desktop/src/ml_ep.rs`.

use serde::{Deserialize, Serialize};

/// One ONNX Runtime execution provider the selection state
/// machine can return. Mirrors the `ort::ep::ExecutionProvider`
/// surface but is independent of the `ort` crate so this module
/// compiles without the `onnx-runtime` cargo feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionProvider {
    /// Apple CoreML EP — Neural Engine when available, GPU on
    /// older Apple Silicon, CPU on Intel Macs.
    CoreMl,
    /// Android Neural Networks API EP.
    Nnapi,
    /// Microsoft DirectML EP — GPU-accelerated, requires DirectML
    /// SDK at build time.
    DirectMl,
    /// Apple Metal Performance Shaders EP — used as an explicit
    /// CoreML alternative for callers that want to skip the
    /// Neural Engine fallback chain.
    MetalPerformanceShaders,
    /// CPU EP — always available, the universal fallback.
    Cpu,
}

impl ExecutionProvider {
    /// Stable string tag suitable for telemetry / logs.
    pub fn tag(self) -> &'static str {
        match self {
            ExecutionProvider::CoreMl => "coreml",
            ExecutionProvider::Nnapi => "nnapi",
            ExecutionProvider::DirectMl => "directml",
            ExecutionProvider::MetalPerformanceShaders => "metal_performance_shaders",
            ExecutionProvider::Cpu => "cpu",
        }
    }
}

/// Host platform the model is being loaded on. Mirrors the
/// platform list in `docs/ARCHITECTURE.md §11.4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    /// Apple macOS (any architecture — Apple Silicon or Intel).
    MacOs,
    /// Apple iOS / iPadOS.
    Ios,
    /// Google Android.
    Android,
    /// Microsoft Windows.
    Windows,
    /// Generic Linux.
    Linux,
    /// Unknown / unrecognized platform — selection always
    /// degrades to [`ExecutionProvider::Cpu`].
    Unknown,
}

/// Host CPU architecture. Mirrors the rustc `target_arch` values
/// the model bridges actually inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Arch {
    /// 64-bit x86 — the Windows / Linux desktop majority.
    X86_64,
    /// 64-bit ARM — Apple Silicon, modern Android.
    Aarch64,
    /// Anything else (32-bit ARM, RISC-V, etc.). Always falls
    /// back to CPU.
    Other,
}

/// Caller-supplied snapshot of the host's hardware capabilities.
/// Production callers populate this from runtime probes (e.g.
/// `IOServiceGetMatchingService(kIOServiceMatching("AGPU"))` on
/// macOS, `nvidia-smi` / DXGI on Windows, `getprop` on Android).
/// Tests instantiate it directly to exercise every branch of the
/// selection state machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    /// `true` if the host has a discrete or integrated GPU
    /// reachable through the platform's ML EP.
    pub has_gpu: bool,
    /// `true` if the host has a dedicated NPU (Apple Neural
    /// Engine, Qualcomm Hexagon, etc.).
    pub has_npu: bool,
    /// Optional GPU vendor string ("apple", "nvidia", "amd",
    /// "intel", …). Unused by the default policy but recorded so
    /// downstream telemetry / overrides can pivot on it.
    pub gpu_vendor: Option<String>,
    /// Host platform.
    pub os: Platform,
    /// Host architecture.
    pub arch: Arch,
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        Self {
            has_gpu: false,
            has_npu: false,
            gpu_vendor: None,
            os: Platform::Unknown,
            arch: Arch::Other,
        }
    }
}

impl DeviceCapabilities {
    /// CPU-only baseline for the supplied platform/arch — every
    /// selection ends in [`ExecutionProvider::Cpu`].
    pub fn cpu_only(os: Platform, arch: Arch) -> Self {
        Self {
            has_gpu: false,
            has_npu: false,
            gpu_vendor: None,
            os,
            arch,
        }
    }

    /// Fully-featured Apple Silicon Mac: GPU + NPU available.
    pub fn apple_silicon_mac() -> Self {
        Self {
            has_gpu: true,
            has_npu: true,
            gpu_vendor: Some("apple".into()),
            os: Platform::MacOs,
            arch: Arch::Aarch64,
        }
    }

    /// Fully-featured Apple Silicon iOS device: GPU + NPU
    /// available.
    pub fn apple_silicon_ios() -> Self {
        Self {
            has_gpu: true,
            has_npu: true,
            gpu_vendor: Some("apple".into()),
            os: Platform::Ios,
            arch: Arch::Aarch64,
        }
    }

    /// Modern Android device with a vendor NPU (Hexagon / NPU).
    pub fn android_with_npu() -> Self {
        Self {
            has_gpu: true,
            has_npu: true,
            gpu_vendor: Some("qualcomm".into()),
            os: Platform::Android,
            arch: Arch::Aarch64,
        }
    }

    /// Windows desktop with a discrete GPU.
    pub fn windows_with_gpu(vendor: &str) -> Self {
        Self {
            has_gpu: true,
            has_npu: false,
            gpu_vendor: Some(vendor.to_string()),
            os: Platform::Windows,
            arch: Arch::X86_64,
        }
    }
}

/// One recorded benchmark sample for a `(platform, EP)` pair.
/// Production code records the median latency over a small batch
/// of warm-up runs; tests can build [`EpBenchmark`] directly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpBenchmark {
    /// Platform the sample was recorded on.
    pub platform: Platform,
    /// Execution provider the sample was recorded under.
    pub ep: ExecutionProvider,
    /// Median wall-clock per-inference latency in microseconds.
    pub median_latency_us: u64,
    /// Number of inference calls aggregated into the median.
    pub samples: u32,
}

impl EpBenchmark {
    /// Helper constructor for tests — the production probe builds
    /// these incrementally as it warms up.
    pub fn new(
        platform: Platform,
        ep: ExecutionProvider,
        median_latency_us: u64,
        samples: u32,
    ) -> Self {
        Self {
            platform,
            ep,
            median_latency_us,
            samples,
        }
    }
}

/// Per-platform execution-provider selector with a benchmark
/// memory.
///
/// The default policy is the deterministic state machine from
/// `docs/ARCHITECTURE.md §11.4`:
///
/// * macOS: NPU → CoreML, GPU-only → CoreML, otherwise CPU.
/// * iOS: NPU/GPU → CoreML, otherwise CPU.
/// * Android: NPU → NNAPI, GPU-only → NNAPI, otherwise CPU.
/// * Windows: GPU → DirectML, otherwise CPU.
/// * Linux: CPU.
/// * Unknown: CPU.
///
/// Recorded [`EpBenchmark`] samples are stored on the selector but
/// the default policy is **deterministic** — the state machine
/// returns the platform-canonical EP regardless of historical
/// latency. Production callers can wrap the selector with their
/// own benchmark-driven policy by reading
/// [`Self::recorded_benchmarks`].
#[derive(Debug, Default)]
pub struct ExecutionProviderSelector {
    benchmarks: Vec<EpBenchmark>,
}

impl ExecutionProviderSelector {
    /// Construct an empty selector with no recorded benchmarks.
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the deterministic selection state machine for the
    /// supplied platform/capabilities pair. See the type-level
    /// docs for the exact policy.
    pub fn select_ep(
        &self,
        platform: Platform,
        capabilities: &DeviceCapabilities,
    ) -> ExecutionProvider {
        match platform {
            Platform::MacOs | Platform::Ios => {
                if capabilities.has_npu || capabilities.has_gpu {
                    ExecutionProvider::CoreMl
                } else {
                    ExecutionProvider::Cpu
                }
            }
            Platform::Android => {
                if capabilities.has_npu || capabilities.has_gpu {
                    ExecutionProvider::Nnapi
                } else {
                    ExecutionProvider::Cpu
                }
            }
            Platform::Windows => {
                if capabilities.has_gpu {
                    ExecutionProvider::DirectMl
                } else {
                    ExecutionProvider::Cpu
                }
            }
            Platform::Linux | Platform::Unknown => ExecutionProvider::Cpu,
        }
    }

    /// Record one [`EpBenchmark`] sample. Production callers run
    /// this from the model warm-up path so the selector
    /// accumulates a per-platform latency profile.
    pub fn record_benchmark(&mut self, sample: EpBenchmark) {
        self.benchmarks.push(sample);
    }

    /// All recorded benchmarks, in insertion order.
    pub fn recorded_benchmarks(&self) -> &[EpBenchmark] {
        &self.benchmarks
    }
}

/// Trait wrapper around [`ExecutionProviderSelector`] so callers
/// can swap in test doubles (e.g. an [`NoopEpSelector`] that
/// always returns CPU).
pub trait EpSelector: Send + Sync + std::fmt::Debug {
    /// Select an EP for the supplied platform/capabilities pair.
    fn select_ep(&self, platform: Platform, capabilities: &DeviceCapabilities)
        -> ExecutionProvider;
}

impl EpSelector for ExecutionProviderSelector {
    fn select_ep(
        &self,
        platform: Platform,
        capabilities: &DeviceCapabilities,
    ) -> ExecutionProvider {
        ExecutionProviderSelector::select_ep(self, platform, capabilities)
    }
}

/// Test-only selector that always returns [`ExecutionProvider::Cpu`].
/// Useful for unit tests that need to assert the orchestration
/// layer falls back cleanly when no accelerator is available.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEpSelector;

impl NoopEpSelector {
    /// `const fn` constructor.
    pub const fn new() -> Self {
        Self
    }
}

impl EpSelector for NoopEpSelector {
    fn select_ep(
        &self,
        _platform: Platform,
        _capabilities: &DeviceCapabilities,
    ) -> ExecutionProvider {
        ExecutionProvider::Cpu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_accel() -> DeviceCapabilities {
        DeviceCapabilities {
            has_gpu: false,
            has_npu: false,
            gpu_vendor: None,
            os: Platform::Unknown,
            arch: Arch::Other,
        }
    }

    #[test]
    fn macos_with_npu_selects_coreml() {
        let s = ExecutionProviderSelector::new();
        let caps = DeviceCapabilities::apple_silicon_mac();
        assert_eq!(
            s.select_ep(Platform::MacOs, &caps),
            ExecutionProvider::CoreMl
        );
    }

    #[test]
    fn macos_without_accelerator_falls_back_to_cpu() {
        let s = ExecutionProviderSelector::new();
        let caps = DeviceCapabilities::cpu_only(Platform::MacOs, Arch::X86_64);
        assert_eq!(s.select_ep(Platform::MacOs, &caps), ExecutionProvider::Cpu);
    }

    #[test]
    fn ios_selects_coreml_when_accelerator_present() {
        let s = ExecutionProviderSelector::new();
        let caps = DeviceCapabilities::apple_silicon_ios();
        assert_eq!(s.select_ep(Platform::Ios, &caps), ExecutionProvider::CoreMl);
    }

    #[test]
    fn ios_without_accelerator_falls_back_to_cpu() {
        let s = ExecutionProviderSelector::new();
        assert_eq!(
            s.select_ep(
                Platform::Ios,
                &DeviceCapabilities::cpu_only(Platform::Ios, Arch::Aarch64)
            ),
            ExecutionProvider::Cpu
        );
    }

    #[test]
    fn android_with_npu_selects_nnapi() {
        let s = ExecutionProviderSelector::new();
        let caps = DeviceCapabilities::android_with_npu();
        assert_eq!(
            s.select_ep(Platform::Android, &caps),
            ExecutionProvider::Nnapi
        );
    }

    #[test]
    fn android_with_gpu_only_still_selects_nnapi() {
        let s = ExecutionProviderSelector::new();
        let mut caps = DeviceCapabilities::android_with_npu();
        caps.has_npu = false;
        assert_eq!(
            s.select_ep(Platform::Android, &caps),
            ExecutionProvider::Nnapi
        );
    }

    #[test]
    fn android_without_accelerator_falls_back_to_cpu() {
        let s = ExecutionProviderSelector::new();
        let caps = DeviceCapabilities::cpu_only(Platform::Android, Arch::Aarch64);
        assert_eq!(
            s.select_ep(Platform::Android, &caps),
            ExecutionProvider::Cpu
        );
    }

    #[test]
    fn windows_with_gpu_selects_directml() {
        let s = ExecutionProviderSelector::new();
        let caps = DeviceCapabilities::windows_with_gpu("nvidia");
        assert_eq!(
            s.select_ep(Platform::Windows, &caps),
            ExecutionProvider::DirectMl
        );
    }

    #[test]
    fn windows_without_gpu_falls_back_to_cpu() {
        let s = ExecutionProviderSelector::new();
        let caps = DeviceCapabilities::cpu_only(Platform::Windows, Arch::X86_64);
        assert_eq!(
            s.select_ep(Platform::Windows, &caps),
            ExecutionProvider::Cpu
        );
    }

    #[test]
    fn linux_always_cpu_even_with_gpu() {
        let s = ExecutionProviderSelector::new();
        let caps = DeviceCapabilities {
            has_gpu: true,
            has_npu: false,
            gpu_vendor: Some("nvidia".into()),
            os: Platform::Linux,
            arch: Arch::X86_64,
        };
        assert_eq!(s.select_ep(Platform::Linux, &caps), ExecutionProvider::Cpu);
    }

    #[test]
    fn unknown_platform_always_cpu() {
        let s = ExecutionProviderSelector::new();
        assert_eq!(
            s.select_ep(Platform::Unknown, &no_accel()),
            ExecutionProvider::Cpu
        );
    }

    #[test]
    fn benchmark_recording_round_trips() {
        let mut s = ExecutionProviderSelector::new();
        s.record_benchmark(EpBenchmark::new(
            Platform::Windows,
            ExecutionProvider::DirectMl,
            420,
            16,
        ));
        s.record_benchmark(EpBenchmark::new(
            Platform::Windows,
            ExecutionProvider::Cpu,
            1_840,
            16,
        ));
        let recorded = s.recorded_benchmarks();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].ep, ExecutionProvider::DirectMl);
        assert_eq!(recorded[0].median_latency_us, 420);
        assert_eq!(recorded[1].ep, ExecutionProvider::Cpu);
    }

    #[test]
    fn ep_selector_is_object_safe_through_box_dyn() {
        let s: Box<dyn EpSelector> = Box::new(ExecutionProviderSelector::new());
        let caps = DeviceCapabilities::apple_silicon_mac();
        assert_eq!(
            s.select_ep(Platform::MacOs, &caps),
            ExecutionProvider::CoreMl
        );
        let n: Box<dyn EpSelector> = Box::new(NoopEpSelector::new());
        assert_eq!(n.select_ep(Platform::MacOs, &caps), ExecutionProvider::Cpu);
    }

    #[test]
    fn execution_provider_tag_is_stable() {
        assert_eq!(ExecutionProvider::CoreMl.tag(), "coreml");
        assert_eq!(ExecutionProvider::Nnapi.tag(), "nnapi");
        assert_eq!(ExecutionProvider::DirectMl.tag(), "directml");
        assert_eq!(
            ExecutionProvider::MetalPerformanceShaders.tag(),
            "metal_performance_shaders"
        );
        assert_eq!(ExecutionProvider::Cpu.tag(), "cpu");
    }

    #[test]
    fn device_capabilities_round_trips_through_serde_json() {
        let caps = DeviceCapabilities::windows_with_gpu("nvidia");
        let json = serde_json::to_string(&caps).unwrap();
        let back: DeviceCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(caps, back);
    }
}
