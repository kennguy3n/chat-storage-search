//! Platform ML execution-provider selection state machine
//!.
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

/// prioritized list of
/// execution providers to try when constructing an ONNX session.
///
/// `docs/ARCHITECTURE.md §11.4` calls for the desktop / mobile
/// model bridges to attempt their preferred accelerator EP
/// first, then *fall back* to CPU on EP-initialization failure.
/// [`ExecutionProviderSelector::select_ep`] only returns the
/// preferred EP — it does not encode the fallback ladder. This
/// type does.
///
/// ## Per-platform chains
///
/// * **macOS / iOS**: `[CoreMl, Cpu]` when an accelerator is
///   present, otherwise `[Cpu]`.
/// * **Android**: `[Nnapi, Cpu]` when an accelerator is present,
///   otherwise `[Cpu]`.
/// * **Windows**: `[DirectMl, Cpu]` when a GPU is present,
///   otherwise `[Cpu]`.
/// * **Linux / Unknown**: `[Cpu]`.
///
/// The chain is always non-empty — the last entry is always
/// [`ExecutionProvider::Cpu`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpFallbackChain {
    eps: Vec<ExecutionProvider>,
}

impl EpFallbackChain {
    /// Build the fallback chain for the supplied platform /
    /// capabilities pair.
    pub fn for_platform(platform: Platform, capabilities: &DeviceCapabilities) -> Self {
        let selector = ExecutionProviderSelector::new();
        let preferred = selector.select_ep(platform, capabilities);
        let mut eps = Vec::new();
        if preferred != ExecutionProvider::Cpu {
            eps.push(preferred);
        }
        eps.push(ExecutionProvider::Cpu);
        Self { eps }
    }

    /// Iterate over the chain in priority order (most-preferred
    /// EP first, CPU last).
    pub fn as_slice(&self) -> &[ExecutionProvider] {
        &self.eps
    }

    /// Most-preferred EP — always equal to
    /// `as_slice().first().unwrap()`.
    pub fn primary(&self) -> ExecutionProvider {
        self.eps[0]
    }

    /// Final fallback EP — always
    /// [`ExecutionProvider::Cpu`].
    pub fn cpu_fallback(&self) -> ExecutionProvider {
        *self.eps.last().expect("chain is non-empty by construction")
    }

    /// walk the chain
    /// and return the first EP that is not in `failed`.
    ///
    /// Used by the always-compiled "session falls back to CPU on
    /// EP failure" wiring: production session creators build the
    /// host fallback chain via [`Self::for_platform`], try the
    /// primary EP, and on registration failure remember it in a
    /// local set + retry through this helper. CPU is the
    /// guaranteed fallback because the chain always ends in
    /// [`ExecutionProvider::Cpu`] which is never marked failed.
    pub fn select_first_available(
        &self,
        failed: &std::collections::HashSet<ExecutionProvider>,
    ) -> ExecutionProvider {
        for ep in &self.eps {
            // CPU is the universal fallback — we never mark it as
            // failed even if the caller does, because returning
            // anything else from a chain that ends in CPU would
            // violate the invariant on this type.
            if *ep == ExecutionProvider::Cpu {
                return *ep;
            }
            if !failed.contains(ep) {
                return *ep;
            }
        }
        ExecutionProvider::Cpu
    }
}

// ---------------------------------------------------------------
// on-device EP benchmark
// capture + persistent cache + auto-selection.
// ---------------------------------------------------------------

/// Object-safe trait the orchestration layer calls into to
/// measure how a model performs under a particular execution
/// provider. Production implementations spin up a real
/// `ort::Session`; tests use [`NoopEpBenchmarkRunner`] or build
/// a deterministic [`MockEpBenchmarkRunner`].
pub trait EpBenchmarkRunner: Send + Sync + std::fmt::Debug {
    /// Measure the supplied `(ep, model)` combination and return
    /// the resulting [`EpBenchmark`]. Errors propagate so the
    /// caller can fall back to the next EP in the chain when an
    /// accelerator EP fails to initialize.
    fn run_benchmark(
        &self,
        ep: ExecutionProvider,
        model: &crate::models::model_manager::ModelArtifact,
    ) -> std::result::Result<EpBenchmark, crate::Error>;
}

/// Noop benchmark runner — every call returns the same fixed
/// benchmark. Useful when the platform bridge cannot run a real
/// inference (CI, headless smoke tests).
#[derive(Debug, Clone, Copy)]
pub struct NoopEpBenchmarkRunner {
    /// Latency reported in the synthetic benchmark.
    pub median_latency_us: u64,
    /// Sample count reported in the synthetic benchmark.
    pub samples: u32,
}

impl Default for NoopEpBenchmarkRunner {
    fn default() -> Self {
        Self {
            median_latency_us: 1_000,
            samples: 1,
        }
    }
}

impl EpBenchmarkRunner for NoopEpBenchmarkRunner {
    fn run_benchmark(
        &self,
        ep: ExecutionProvider,
        _model: &crate::models::model_manager::ModelArtifact,
    ) -> std::result::Result<EpBenchmark, crate::Error> {
        Ok(EpBenchmark::new(
            Platform::Unknown,
            ep,
            self.median_latency_us,
            self.samples,
        ))
    }
}

/// Mock runner that returns hardcoded latencies per EP. Used by
/// unit tests to drive [`select_best_ep`] without spinning up a
/// real ONNX session.
#[derive(Debug, Default, Clone)]
pub struct MockEpBenchmarkRunner {
    /// `(ep, latency_us)` pairs the runner reports verbatim.
    pub latencies: std::collections::HashMap<ExecutionProvider, u64>,
}

impl MockEpBenchmarkRunner {
    /// Construct an empty mock runner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the synthetic latency for `ep`. Returns `self` so the
    /// builder can be chained.
    pub fn with_latency(mut self, ep: ExecutionProvider, latency_us: u64) -> Self {
        self.latencies.insert(ep, latency_us);
        self
    }
}

impl EpBenchmarkRunner for MockEpBenchmarkRunner {
    fn run_benchmark(
        &self,
        ep: ExecutionProvider,
        _model: &crate::models::model_manager::ModelArtifact,
    ) -> std::result::Result<EpBenchmark, crate::Error> {
        let latency = self.latencies.get(&ep).copied().unwrap_or(10_000);
        Ok(EpBenchmark::new(Platform::Unknown, ep, latency, 1))
    }
}

/// Persistent cache of `(ep, model_id) → EpBenchmark` mappings.
///
/// Production callers persist the cache to a JSON file on disk so
/// the auto-selection decision survives process restarts.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct EpBenchmarkCache {
    /// Optional model-version stamp the cache is valid for. When
    /// the orchestration layer rotates the underlying model
    /// artifact, [`Self::invalidate_for_model_version_change`]
    /// drops every entry whose stored version no longer matches.
    pub model_version: Option<String>,
    /// `(ep, model_id) → EpBenchmark` map. The map is keyed by
    /// `(EP, model_id)` because the same EP can have very
    /// different latency profiles for different models.
    pub entries: Vec<EpBenchmarkCacheEntry>,
}

/// One cached benchmark entry — `(ep, model_id, benchmark)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EpBenchmarkCacheEntry {
    /// EP the entry was recorded under.
    pub ep: ExecutionProvider,
    /// Model id the entry was recorded for.
    pub model_id: String,
    /// Recorded benchmark.
    pub benchmark: EpBenchmark,
}

impl EpBenchmarkCache {
    /// Construct an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) the benchmark for `(ep, model_id)`.
    pub fn insert(&mut self, ep: ExecutionProvider, model_id: &str, benchmark: EpBenchmark) {
        self.entries
            .retain(|e| !(e.ep == ep && e.model_id == model_id));
        self.entries.push(EpBenchmarkCacheEntry {
            ep,
            model_id: model_id.to_string(),
            benchmark,
        });
    }

    /// Lookup the benchmark for `(ep, model_id)`.
    pub fn get(&self, ep: ExecutionProvider, model_id: &str) -> Option<&EpBenchmark> {
        self.entries
            .iter()
            .find(|e| e.ep == ep && e.model_id == model_id)
            .map(|e| &e.benchmark)
    }

    /// Every cached benchmark for the supplied `model_id`.
    pub fn benchmarks_for_model(&self, model_id: &str) -> Vec<EpBenchmark> {
        self.entries
            .iter()
            .filter(|e| e.model_id == model_id)
            .map(|e| e.benchmark.clone())
            .collect()
    }

    /// Persist the cache to `path` as CBOR. CBOR is used (not
    /// JSON) because the core crate already depends on a CBOR
    /// codec (`ciborium`, via [`crate::cbor`]) and CBOR survives
    /// schema evolution slightly more gracefully for this kind
    /// of typed cache.
    pub fn persist_to_path(&self, path: &std::path::Path) -> std::result::Result<(), crate::Error> {
        let bytes = crate::cbor::to_vec(self)
            .map_err(|e| crate::Error::Storage(format!("ep-cache serialize: {e}").into()))?;
        std::fs::write(path, bytes).map_err(|e| {
            crate::Error::Storage(format!("ep-cache write {}: {e}", path.display()).into())
        })
    }

    /// Load a cache from `path`.
    ///
    /// Behaviour:
    ///
    /// * **Missing file** — returns [`Self::default`] (cold-start
    ///   cache). This is the steady-state behaviour on first run.
    /// * **I/O error reading the file** — returns
    ///   [`crate::Error::Storage`]. I/O errors are operationally
    ///   meaningful (disk full, permission denied, hardware fault)
    ///   and should bubble up so the caller can surface them in
    ///   logs / telemetry.
    /// * **Parse failure (corrupt CBOR, format change, bit-rot)**
    ///   returns [`Self::default`] with a single stderr note. The
    ///   cache is a performance optimisation, not authoritative
    ///   state: re-benchmarking on the next run re-populates it.
    ///   Hard-failing on parse error would brick a device with a
    ///   corrupted cache file even though the user could trivially
    ///   recover by deleting it, so we choose the recover-and-warn
    ///   path here.
    pub fn load_from_path(path: &std::path::Path) -> std::result::Result<Self, crate::Error> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path).map_err(|e| {
            crate::Error::Storage(format!("ep-cache read {}: {e}", path.display()).into())
        })?;
        match crate::cbor::from_slice::<Self>(&bytes) {
            Ok(cache) => Ok(cache),
            Err(e) => {
                // A corrupt cache must NOT brick the device — the
                // file is a perf optimisation, not authoritative
                // state. Fall back to an empty cache; the next EP
                // benchmark run will re-populate it. Emit a one-line
                // note on stderr so the situation is visible to
                // operators inspecting logs.
                eprintln!(
                    "[kchat-core/ep-cache] parse failure at {}: {e}; falling back to empty cache",
                    path.display()
                );
                Ok(Self::default())
            }
        }
    }

    /// Drop every entry whose `model_version` does not match
    /// `current`. Updates [`Self::model_version`] to `current`
    /// after the prune.
    pub fn invalidate_for_model_version_change(&mut self, current: &str) {
        if self.model_version.as_deref() != Some(current) {
            self.entries.clear();
            self.model_version = Some(current.to_string());
        }
    }
}

/// Pick the EP with the lowest median latency from `benchmarks`.
/// Falls back to the first entry of `fallback_chain` if no
/// benchmark is provided. The returned EP is guaranteed to be
/// present in `fallback_chain` when the chain is non-empty.
pub fn select_best_ep(
    benchmarks: &[EpBenchmark],
    fallback_chain: &[ExecutionProvider],
) -> ExecutionProvider {
    // Restrict candidates to EPs the platform actually supports
    // (anything in the fallback chain).
    let chain_set: std::collections::HashSet<ExecutionProvider> =
        fallback_chain.iter().copied().collect();
    let mut best: Option<&EpBenchmark> = None;
    for b in benchmarks {
        if !chain_set.contains(&b.ep) {
            continue;
        }
        match best {
            None => best = Some(b),
            Some(cur) if b.median_latency_us < cur.median_latency_us => best = Some(b),
            _ => {}
        }
    }
    if let Some(b) = best {
        return b.ep;
    }
    fallback_chain
        .first()
        .copied()
        .unwrap_or(ExecutionProvider::Cpu)
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

    // -----------------------------------------------------------
    // EpFallbackChain.
    // -----------------------------------------------------------

    #[test]
    fn ep_fallback_chain_macos_prefers_coreml() {
        let chain = EpFallbackChain::for_platform(
            Platform::MacOs,
            &DeviceCapabilities::apple_silicon_mac(),
        );
        assert_eq!(
            chain.as_slice(),
            &[ExecutionProvider::CoreMl, ExecutionProvider::Cpu]
        );
    }

    #[test]
    fn ep_fallback_chain_ios_prefers_coreml() {
        let chain =
            EpFallbackChain::for_platform(Platform::Ios, &DeviceCapabilities::apple_silicon_ios());
        assert_eq!(
            chain.as_slice(),
            &[ExecutionProvider::CoreMl, ExecutionProvider::Cpu]
        );
    }

    #[test]
    fn ep_fallback_chain_windows_with_gpu_prefers_directml() {
        let chain = EpFallbackChain::for_platform(
            Platform::Windows,
            &DeviceCapabilities::windows_with_gpu("nvidia"),
        );
        assert_eq!(
            chain.as_slice(),
            &[ExecutionProvider::DirectMl, ExecutionProvider::Cpu]
        );
    }

    #[test]
    fn ep_fallback_chain_linux_cpu_only() {
        let chain = EpFallbackChain::for_platform(
            Platform::Linux,
            &DeviceCapabilities::cpu_only(Platform::Linux, Arch::X86_64),
        );
        assert_eq!(chain.as_slice(), &[ExecutionProvider::Cpu]);
    }

    #[test]
    fn ep_fallback_chain_android_prefers_nnapi() {
        let chain = EpFallbackChain::for_platform(
            Platform::Android,
            &DeviceCapabilities::android_with_npu(),
        );
        assert_eq!(
            chain.as_slice(),
            &[ExecutionProvider::Nnapi, ExecutionProvider::Cpu]
        );
    }

    #[test]
    fn ep_fallback_chain_no_accel_is_cpu_only() {
        let chain = EpFallbackChain::for_platform(Platform::MacOs, &no_accel());
        assert_eq!(chain.as_slice(), &[ExecutionProvider::Cpu]);
        assert_eq!(chain.primary(), ExecutionProvider::Cpu);
        assert_eq!(chain.cpu_fallback(), ExecutionProvider::Cpu);
    }

    #[test]
    fn create_session_falls_back_to_cpu_on_ep_failure() {
        // with the
        // primary EP marked failed, `select_first_available`
        // must walk the chain and return CPU. Mirrors the
        // session-creation contract: if `DirectML.register`
        // returns an error, the next attempt registers `CPU`.
        let chain = EpFallbackChain::for_platform(
            Platform::Windows,
            &DeviceCapabilities::windows_with_gpu("nvidia"),
        );
        assert_eq!(chain.primary(), ExecutionProvider::DirectMl);

        let mut failed = std::collections::HashSet::new();
        failed.insert(ExecutionProvider::DirectMl);
        assert_eq!(
            chain.select_first_available(&failed),
            ExecutionProvider::Cpu
        );
    }

    #[test]
    fn select_first_available_returns_primary_when_no_failures() {
        let chain = EpFallbackChain::for_platform(
            Platform::MacOs,
            &DeviceCapabilities::apple_silicon_mac(),
        );
        let failed = std::collections::HashSet::<ExecutionProvider>::new();
        assert_eq!(
            chain.select_first_available(&failed),
            ExecutionProvider::CoreMl
        );
    }

    // -----------------------------------------------------------
    // EP-benchmark tests.
    // -----------------------------------------------------------

    fn make_bench(ep: ExecutionProvider, latency_us: u64) -> EpBenchmark {
        EpBenchmark::new(Platform::Unknown, ep, latency_us, 5)
    }

    #[test]
    fn select_best_ep_picks_lowest_latency() {
        let benches = vec![
            make_bench(ExecutionProvider::Cpu, 4_000),
            make_bench(ExecutionProvider::CoreMl, 1_000),
        ];
        let chain = vec![ExecutionProvider::CoreMl, ExecutionProvider::Cpu];
        assert_eq!(select_best_ep(&benches, &chain), ExecutionProvider::CoreMl);
    }

    #[test]
    fn select_best_ep_falls_back_when_no_benchmarks() {
        let chain = vec![ExecutionProvider::DirectMl, ExecutionProvider::Cpu];
        assert_eq!(select_best_ep(&[], &chain), ExecutionProvider::DirectMl);
    }

    #[test]
    fn select_best_ep_ignores_eps_outside_chain() {
        // CoreML benchmark is fastest but the chain doesn't
        // contain it (e.g. running on Linux). Result should be
        // chain[0] = Cpu.
        let benches = vec![make_bench(ExecutionProvider::CoreMl, 100)];
        let chain = vec![ExecutionProvider::Cpu];
        assert_eq!(select_best_ep(&benches, &chain), ExecutionProvider::Cpu);
    }

    #[test]
    fn ep_benchmark_cache_persist_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.cbor");
        let mut cache = EpBenchmarkCache::new();
        cache.insert(
            ExecutionProvider::CoreMl,
            "xlmr",
            make_bench(ExecutionProvider::CoreMl, 1_500),
        );
        cache.persist_to_path(&path).unwrap();
        let loaded = EpBenchmarkCache::load_from_path(&path).unwrap();
        assert_eq!(cache, loaded);
    }

    #[test]
    fn ep_benchmark_cache_load_missing_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.cbor");
        let loaded = EpBenchmarkCache::load_from_path(&path).unwrap();
        assert!(loaded.entries.is_empty());
    }

    #[test]
    fn ep_benchmark_cache_load_corrupt_falls_back_to_empty() {
        // A corrupt cache file (e.g. bit-rot, partial write, format
        // change after upgrade) must NOT brick the caller. The cache
        // is a perf optimisation; re-benchmarking on the next run
        // re-populates it. The hard-error contract would force the
        // user to manually delete the file to recover.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.cbor");
        // 0xFF / 0xFF / 0xFF is not a valid start of any CBOR major
        // type; ciborium will surface a Syntax error here.
        std::fs::write(&path, [0xff, 0xff, 0xff, 0xff]).unwrap();

        let loaded = EpBenchmarkCache::load_from_path(&path)
            .expect("corrupt cache must fall back, not error");
        assert!(loaded.entries.is_empty());
        assert!(loaded.model_version.is_none());
    }

    #[test]
    fn ep_benchmark_cache_invalidates_on_model_version_change() {
        let mut cache = EpBenchmarkCache::new();
        cache.model_version = Some("xlmr@v1".into());
        cache.insert(
            ExecutionProvider::CoreMl,
            "xlmr",
            make_bench(ExecutionProvider::CoreMl, 1_500),
        );
        cache.invalidate_for_model_version_change("xlmr@v2");
        assert_eq!(cache.model_version.as_deref(), Some("xlmr@v2"));
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn noop_benchmark_runner_returns_fixed_result() {
        use crate::models::model_manager::{ModelArtifact, Quantization};
        let runner = NoopEpBenchmarkRunner::default();
        let artifact = ModelArtifact {
            model_id: "xlmr".into(),
            model_version: "xlmr@v1".into(),
            file_path: std::path::PathBuf::from("/dev/null"),
            size_bytes: 0,
            quantization: Quantization::Int8,
            sha256: [0u8; 32],
        };
        let bench = runner
            .run_benchmark(ExecutionProvider::Cpu, &artifact)
            .unwrap();
        assert_eq!(bench.median_latency_us, 1_000);
        assert_eq!(bench.ep, ExecutionProvider::Cpu);
    }

    #[test]
    fn mock_benchmark_runner_returns_configured_latency() {
        use crate::models::model_manager::{ModelArtifact, Quantization};
        let runner = MockEpBenchmarkRunner::new()
            .with_latency(ExecutionProvider::CoreMl, 800)
            .with_latency(ExecutionProvider::Cpu, 4_500);
        let artifact = ModelArtifact {
            model_id: "xlmr".into(),
            model_version: "xlmr@v1".into(),
            file_path: std::path::PathBuf::from("/dev/null"),
            size_bytes: 0,
            quantization: Quantization::Int8,
            sha256: [0u8; 32],
        };
        let coreml = runner
            .run_benchmark(ExecutionProvider::CoreMl, &artifact)
            .unwrap();
        assert_eq!(coreml.median_latency_us, 800);
        let cpu = runner
            .run_benchmark(ExecutionProvider::Cpu, &artifact)
            .unwrap();
        assert_eq!(cpu.median_latency_us, 4_500);
    }

    #[test]
    fn model_manager_benchmark_ep_delegates_to_runner() {
        use crate::models::model_manager::{
            ModelArtifact, ModelManager, ModelManagerConfig, Quantization,
        };
        let dir = tempfile::tempdir().unwrap();
        let cfg = ModelManagerConfig {
            models_dir: dir.path().to_path_buf(),
            ..ModelManagerConfig::default()
        };
        let mgr = ModelManager::new(cfg);
        let artifact = ModelArtifact {
            model_id: "xlmr".into(),
            model_version: "xlmr@v1".into(),
            file_path: dir.path().join("xlmr.onnx"),
            size_bytes: 0,
            quantization: Quantization::Int8,
            sha256: [0u8; 32],
        };
        mgr.register_model(artifact).unwrap();
        let runner = MockEpBenchmarkRunner::new().with_latency(ExecutionProvider::Cpu, 4_200);
        let bench = mgr
            .benchmark_ep("xlmr", ExecutionProvider::Cpu, &runner)
            .unwrap();
        assert_eq!(bench.median_latency_us, 4_200);
    }

    #[test]
    fn model_manager_select_optimal_ep_uses_cache() {
        use crate::models::model_manager::{ModelManager, ModelManagerConfig};
        let dir = tempfile::tempdir().unwrap();
        let cfg = ModelManagerConfig {
            models_dir: dir.path().to_path_buf(),
            ..ModelManagerConfig::default()
        };
        let mgr = ModelManager::new(cfg);
        let mut cache = EpBenchmarkCache::new();
        cache.insert(
            ExecutionProvider::CoreMl,
            "xlmr",
            make_bench(ExecutionProvider::CoreMl, 1_500),
        );
        cache.insert(
            ExecutionProvider::Cpu,
            "xlmr",
            make_bench(ExecutionProvider::Cpu, 4_000),
        );
        let chain = vec![ExecutionProvider::CoreMl, ExecutionProvider::Cpu];
        let best = mgr.select_optimal_ep("xlmr", &cache, &chain);
        assert_eq!(best, ExecutionProvider::CoreMl);
    }
}
