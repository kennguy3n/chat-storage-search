//! Resource-gated background processing — Phase 6, Task 6.
//!
//! `docs/PROPOSAL.md §7.6` calls for ML inference + model
//! downloads to be gated on battery / charging / thermal /
//! network state so the device stays cool and responsive even
//! while the search index is catching up.
//!
//! This module defines the gate as **pure functions** that take
//! a [`DeviceResources`] snapshot. The orchestration layer is
//! responsible for sampling the snapshot via the platform
//! [`ResourceProbe`] (Apple `ProcessInfo` + `UIDevice`,
//! Android `PowerManager` / `BatteryManager`, Windows
//! `Windows.System.Power`, …). Keeping the gate logic pure
//! makes it deterministic and trivially unit-testable.
//!
//! ## Cost classes
//!
//! 1. **Embedding** (XLM-R, MobileCLIP-S2): seconds of CPU/GPU,
//!    runs per message. Loosest gate.
//! 2. **OCR**: hundreds of milliseconds per image, but the
//!    platform stack is heavily optimized.
//! 3. **Transcription** (Whisper): tens of seconds per minute of
//!    audio, fan-locked. Strictest gate.
//! 4. **Model download**: large transfer; gated on Wi-Fi by
//!    default to avoid surprise data charges.

/// Snapshot of the device's resource state at a single instant.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeviceResources {
    /// Battery level in `[0.0, 1.0]`. `1.0` means "battery
    /// reports full". The gate also applies even when the
    /// device is plugged in; an unmetered desktop should report
    /// `1.0` with `is_charging = true`.
    pub battery_level: f32,
    /// Whether the device is currently drawing wall power.
    pub is_charging: bool,
    /// Coarse thermal state reported by the OS.
    pub thermal_state: ThermalState,
    /// Active network reachability.
    pub network_type: NetworkType,
}

impl DeviceResources {
    /// "All-clear" snapshot: full battery, charging, nominal
    /// thermal, on Wi-Fi. Useful as the default in tests and
    /// during early bring-up where no probe is installed yet.
    pub const fn all_clear() -> Self {
        Self {
            battery_level: 1.0,
            is_charging: true,
            thermal_state: ThermalState::Nominal,
            network_type: NetworkType::WiFi,
        }
    }
}

impl Default for DeviceResources {
    fn default() -> Self {
        Self::all_clear()
    }
}

/// Coarse thermal state. The numeric ordering matches the
/// platform conventions: a higher variant is hotter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThermalState {
    /// Cool / nominal. Default tier; everything is allowed.
    Nominal,
    /// Slightly warm. Loose gates still allow embedding / OCR.
    Fair,
    /// Hot. Only the loosest work runs; heavy work is paused.
    Serious,
    /// Throttling. Nothing runs.
    Critical,
}

/// Active network reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    /// No reachable network.
    None,
    /// Cellular / mobile-data link. Metered by default.
    Cellular,
    /// Wi-Fi. Unmetered by default.
    WiFi,
    /// Wired Ethernet (desktop). Unmetered.
    Ethernet,
}

impl NetworkType {
    /// Whether this link is "unmetered" for download-gating
    /// purposes. Wi-Fi and Ethernet are; cellular is not.
    pub fn is_unmetered(&self) -> bool {
        matches!(self, NetworkType::WiFi | NetworkType::Ethernet)
    }
}

/// Resource-gating policy.
///
/// `min_battery` is the floor that any gate uses unless the
/// device is plugged in (`require_charging_for_heavy = true`
/// is enforced in addition for heavy gates).
#[derive(Debug, Clone, Copy)]
pub struct ResourcePolicy {
    /// Minimum battery level required when *not* charging.
    /// Defaults to `0.20` — runs above 20 %.
    pub min_battery: f32,
    /// Whether transcription / model-download gates should
    /// require the device to be plugged in.
    pub require_charging_for_heavy: bool,
    /// Maximum thermal state the gate accepts. The gate runs
    /// only when `resources.thermal_state <= max_thermal`.
    pub max_thermal: ThermalState,
    /// Whether model downloads should require an unmetered
    /// link (Wi-Fi / Ethernet).
    pub require_wifi_for_download: bool,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            min_battery: 0.20,
            require_charging_for_heavy: true,
            max_thermal: ThermalState::Fair,
            require_wifi_for_download: true,
        }
    }
}

/// Gate over [`DeviceResources`] snapshots.
///
/// The struct holds a [`ResourcePolicy`] so callers can swap
/// policies per environment (an iOS background task gate vs. a
/// desktop "always allowed" gate, for example).
#[derive(Debug, Clone, Copy)]
pub struct ResourceGate {
    policy: ResourcePolicy,
}

impl ResourceGate {
    /// Build a gate with the supplied policy.
    pub const fn new(policy: ResourcePolicy) -> Self {
        Self { policy }
    }

    /// Borrow the active policy.
    pub fn policy(&self) -> &ResourcePolicy {
        &self.policy
    }

    /// Whether on-device text / image embedding work should run.
    ///
    /// Loosest gate: blocks only on explicit `Critical` thermal
    /// or on a non-charging device below `min_battery`.
    pub fn should_run_embedding(&self, r: &DeviceResources) -> bool {
        if r.thermal_state >= ThermalState::Critical {
            return false;
        }
        if !r.is_charging && r.battery_level < self.policy.min_battery {
            return false;
        }
        true
    }

    /// Whether platform OCR work should run.
    ///
    /// Same loose gate as embedding.
    pub fn should_run_ocr(&self, r: &DeviceResources) -> bool {
        // OCR cost is comparable to embedding for the supported
        // platforms (Apple Vision, ML Kit, Windows Media OCR).
        self.should_run_embedding(r)
    }

    /// Whether Whisper-style audio transcription should run.
    ///
    /// Strictest gate: requires charging when
    /// `require_charging_for_heavy` is set, blocks on `Serious`
    /// thermal, requires battery `>= min_battery`.
    pub fn should_run_transcription(&self, r: &DeviceResources) -> bool {
        if r.thermal_state >= ThermalState::Serious {
            return false;
        }
        if self.policy.require_charging_for_heavy && !r.is_charging {
            return false;
        }
        if r.battery_level < self.policy.min_battery {
            return false;
        }
        true
    }

    /// Whether a model-download transfer should kick off.
    ///
    /// Defaults: Wi-Fi (or Ethernet) only, charging required,
    /// thermal `<= Fair`.
    pub fn should_download_model(&self, r: &DeviceResources) -> bool {
        if r.thermal_state > self.policy.max_thermal {
            return false;
        }
        if self.policy.require_charging_for_heavy && !r.is_charging {
            return false;
        }
        if self.policy.require_wifi_for_download && !r.network_type.is_unmetered() {
            return false;
        }
        if r.network_type == NetworkType::None {
            return false;
        }
        true
    }
}

impl Default for ResourceGate {
    fn default() -> Self {
        Self::new(ResourcePolicy::default())
    }
}

/// Object-safe seam for the platform resource probe.
///
/// `current_resources` MUST return synchronously without
/// blocking — the implementation is expected to read cached
/// platform observers (`ProcessInfo.thermalState`,
/// `BatteryManager.BATTERY_STATUS_*`, …) rather than spinning
/// up a fresh sample.
pub trait ResourceProbe: std::fmt::Debug + Send + Sync {
    /// Sample the device's current resource state.
    fn current_resources(&self) -> DeviceResources;
}

/// Probe stub that always reports the "all-clear" snapshot.
///
/// Used in tests and during early bring-up; downstream gates
/// always allow work in this configuration.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopResourceProbe;

impl ResourceProbe for NoopResourceProbe {
    fn current_resources(&self) -> DeviceResources {
        DeviceResources::all_clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(battery: f32, charging: bool, thermal: ThermalState, net: NetworkType) -> DeviceResources {
        DeviceResources {
            battery_level: battery,
            is_charging: charging,
            thermal_state: thermal,
            network_type: net,
        }
    }

    #[test]
    fn defaults_match_documented_policy() {
        let p = ResourcePolicy::default();
        assert!((p.min_battery - 0.20).abs() < 1e-6);
        assert!(p.require_charging_for_heavy);
        assert!(p.require_wifi_for_download);
        assert_eq!(p.max_thermal, ThermalState::Fair);
    }

    #[test]
    fn embedding_runs_under_normal_conditions() {
        let g = ResourceGate::default();
        assert!(g.should_run_embedding(&DeviceResources::all_clear()));
    }

    #[test]
    fn embedding_blocks_on_critical_thermal() {
        let g = ResourceGate::default();
        let res = r(1.0, true, ThermalState::Critical, NetworkType::WiFi);
        assert!(!g.should_run_embedding(&res));
    }

    #[test]
    fn embedding_blocks_on_low_battery_when_unplugged() {
        let g = ResourceGate::default();
        let res = r(0.10, false, ThermalState::Nominal, NetworkType::WiFi);
        assert!(!g.should_run_embedding(&res));
    }

    #[test]
    fn embedding_runs_on_low_battery_when_charging() {
        let g = ResourceGate::default();
        let res = r(0.05, true, ThermalState::Nominal, NetworkType::Cellular);
        assert!(g.should_run_embedding(&res));
    }

    #[test]
    fn ocr_matches_embedding_gate() {
        let g = ResourceGate::default();
        let res = r(0.10, false, ThermalState::Nominal, NetworkType::WiFi);
        assert_eq!(
            g.should_run_ocr(&res),
            g.should_run_embedding(&res),
            "OCR gate must match embedding gate"
        );
    }

    #[test]
    fn transcription_blocks_on_serious_thermal() {
        let g = ResourceGate::default();
        let res = r(1.0, true, ThermalState::Serious, NetworkType::WiFi);
        assert!(!g.should_run_transcription(&res));
    }

    #[test]
    fn transcription_requires_charging_by_default() {
        let g = ResourceGate::default();
        let res = r(1.0, false, ThermalState::Nominal, NetworkType::WiFi);
        assert!(!g.should_run_transcription(&res));
    }

    #[test]
    fn transcription_runs_when_charging_and_cool() {
        let g = ResourceGate::default();
        let res = r(0.50, true, ThermalState::Nominal, NetworkType::WiFi);
        assert!(g.should_run_transcription(&res));
    }

    #[test]
    fn model_download_requires_unmetered_link() {
        let g = ResourceGate::default();
        let cellular = r(1.0, true, ThermalState::Nominal, NetworkType::Cellular);
        let wifi = r(1.0, true, ThermalState::Nominal, NetworkType::WiFi);
        assert!(!g.should_download_model(&cellular));
        assert!(g.should_download_model(&wifi));
    }

    #[test]
    fn model_download_blocks_on_no_network() {
        let g = ResourceGate::default();
        let none = r(1.0, true, ThermalState::Nominal, NetworkType::None);
        assert!(!g.should_download_model(&none));
    }

    #[test]
    fn battery_at_threshold_is_inclusive() {
        // At exactly the threshold the gate should allow work —
        // the documented contract is "below `min_battery`".
        let g = ResourceGate::default();
        let res = r(0.20, false, ThermalState::Nominal, NetworkType::WiFi);
        assert!(g.should_run_embedding(&res));
    }

    #[test]
    fn thermal_at_max_boundary_allowed_for_download() {
        // `should_download_model` checks `> max_thermal`, so
        // `Fair` (== max_thermal default) must still be allowed.
        let g = ResourceGate::default();
        let res = r(1.0, true, ThermalState::Fair, NetworkType::WiFi);
        assert!(g.should_download_model(&res));
    }

    #[test]
    fn noop_probe_reports_all_clear() {
        let p = NoopResourceProbe;
        let res = p.current_resources();
        assert_eq!(res, DeviceResources::all_clear());
    }

    #[test]
    fn resource_probe_trait_is_object_safe() {
        let p = NoopResourceProbe;
        let dynref: &dyn ResourceProbe = &p;
        let res = dynref.current_resources();
        assert!(res.is_charging);
    }

    #[test]
    fn network_type_unmetered_helper() {
        assert!(!NetworkType::Cellular.is_unmetered());
        assert!(NetworkType::WiFi.is_unmetered());
        assert!(NetworkType::Ethernet.is_unmetered());
        assert!(!NetworkType::None.is_unmetered());
    }
}
