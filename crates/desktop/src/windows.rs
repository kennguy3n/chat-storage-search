//! Windows-specific desktop integration.
//!
//! The three seams here are:
//!
//! * [`WindowsSearchBridge`] — outbound interface to the Windows
//!   Search indexer. Mirrors [`super::macos::SpotlightBridge`]
//!   verbatim so the desktop orchestration layer can install a
//!   bridge per platform with the same call sites.
//! * [`WindowsSchedulerBridge`] — outbound interface to
//!   `IBackgroundTrigger` / Task Scheduler. Implements the
//!   [`BackgroundScheduler`] trait re-exported from
//!   `kchat-core`. Returns
//!   [`Error::NotImplemented`] from every method until the
//!   real WinRT glue is wired up.
//! * [`WindowsMlConfig`] — declarative configuration the
//!   desktop layer hands to the ML model manager so the runtime
//!   knows that no GPU is assumed (DirectML is best-effort and
//!   falls back to CPU EP), and that INT4 is the default tier
//!   for tight-storage devices.
//!
//! All trait seams are object-safe (`Box<dyn...>`) and
//! `Send + Sync`.
//!
//! References:
//! * `docs/DESIGN.md §7.4` — Windows Search anchors.
//! * — desktop integration.
//! * `docs/ARCHITECTURE.md §11.4` — DirectML EP fallback to CPU.

use kchat_core::scheduler::BackgroundScheduler;
use kchat_core::Error;

// ---------------------------------------------------------------------------
// WindowsSearchBridge — outbound search-index seam
// ---------------------------------------------------------------------------

/// Object-safe outbound trait that kchat-desktop calls into to
/// keep the Windows Search index in sync with the local
/// kchat-core message log. Mirrors
/// [`crate::macos::SpotlightBridge`] so call sites can be
/// written generically and only differ by which platform impl
/// is installed at startup.
pub trait WindowsSearchBridge: Send + Sync + std::fmt::Debug {
    /// Index (or replace) the Windows Search entry for
    /// `message_id`.
    fn index_message(
        &self,
        message_id: &str,
        conversation_title: &str,
        body: &str,
        sender: &str,
        timestamp_ms: i64,
    ) -> Result<(), Error>;

    /// Drop the Windows Search entry for a single message.
    /// Idempotent.
    fn remove_message(&self, message_id: &str) -> Result<(), Error>;

    /// Drop every Windows Search entry that belongs to a
    /// conversation. Used during conversation deletion.
    fn remove_conversation(&self, conversation_id: &str) -> Result<(), Error>;
}

/// placeholder Windows Search bridge.
///
/// Every method silently succeeds (`Ok()`).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopWindowsSearchBridge;

impl NoopWindowsSearchBridge {
    /// Construct a fresh [`NoopWindowsSearchBridge`].
    pub const fn new() -> Self {
        Self
    }
}

impl WindowsSearchBridge for NoopWindowsSearchBridge {
    fn index_message(
        &self,
        _message_id: &str,
        _conversation_title: &str,
        _body: &str,
        _sender: &str,
        _timestamp_ms: i64,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn remove_message(&self, _message_id: &str) -> Result<(), Error> {
        Ok(())
    }
    fn remove_conversation(&self, _conversation_id: &str) -> Result<(), Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WindowsSchedulerBridge — outbound IBackgroundTrigger seam
// ---------------------------------------------------------------------------

/// placeholder for the Windows
/// `IBackgroundTrigger` / Task Scheduler bridge. Every method
/// returns [`Error::NotImplemented`] so the orchestration layer
/// can distinguish "no bridge installed" from "scheduler
/// accepted the task" while the real WinRT glue is being
/// authored.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsSchedulerBridge;

impl WindowsSchedulerBridge {
    /// Construct a fresh [`WindowsSchedulerBridge`].
    pub const fn new() -> Self {
        Self
    }
}

impl BackgroundScheduler for WindowsSchedulerBridge {
    fn schedule_backup(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("windows_scheduler"))
    }
    fn schedule_archive_compaction(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("windows_scheduler"))
    }
    fn schedule_index_maintenance(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("windows_scheduler"))
    }
    fn cancel_all(&self) -> Result<(), Error> {
        Err(Error::NotImplemented("windows_scheduler"))
    }
    fn is_task_pending(&self, _task_id: &str) -> Result<bool, Error> {
        Err(Error::NotImplemented("windows_scheduler"))
    }
}

// ---------------------------------------------------------------------------
// WindowsMlConfig — Windows-specific ML constraints
// ---------------------------------------------------------------------------

/// Declarative configuration the desktop layer hands to the ML
/// model manager so the runtime knows what to expect on
/// Windows hardware.
///
/// * `assume_gpu == false`: kchat MUST NOT assume a discrete
///   GPU is present. The ONNX Runtime EP-selection state
///   machine in `kchat_core::models::embeddings_onnx` attempts
///   the DirectML EP first and falls back to the CPU EP when
///   creation fails — this struct documents that contract.
/// * `prefer_int4_default == true`: tight-storage Windows
///   devices (laptops with small SSDs, 8 GB RAM) get the INT4
///   model tier by default. Larger devices can flip the
///   `prefer_int4_default` flag and rely on
///   `ModelManager::select_quantization` to upgrade to INT8.
/// * `directml_best_effort == true`: DirectML is *attempted*
///   but never required. If `ort::ep::DirectML` cannot
///   initialise (driver mismatch, GPU disabled in BIOS, …)
///   the runtime falls back to the CPU EP and search keeps
///   working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsMlConfig {
    /// Whether the desktop layer is allowed to assume a GPU is
    /// present. Always `false` on Windows.
    pub assume_gpu: bool,
    /// Whether INT4 is the default tier the model manager
    /// should pick when no explicit storage budget is supplied.
    pub prefer_int4_default: bool,
    /// Whether the DirectML EP attempt is best-effort. When
    /// `true`, failure to create the DirectML EP is non-fatal
    /// and the runtime falls back to the CPU EP.
    pub directml_best_effort: bool,
}

impl Default for WindowsMlConfig {
    fn default() -> Self {
        Self {
            assume_gpu: false,
            prefer_int4_default: true,
            directml_best_effort: true,
        }
    }
}

impl WindowsMlConfig {
    /// Build a CPU-only config. Equivalent to
    /// [`WindowsMlConfig::default`] today; explicit
    /// constructor for forward compatibility once a
    /// GPU-assumed variant exists.
    pub const fn cpu_only() -> Self {
        Self {
            assume_gpu: false,
            prefer_int4_default: true,
            directml_best_effort: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_search_bridge_noop_returns_ok() {
        let b = NoopWindowsSearchBridge::new();
        assert!(b.index_message("m1", "ct", "body", "alice", 0).is_ok());
        assert!(b.remove_message("m1").is_ok());
        assert!(b.remove_conversation("c1").is_ok());
    }

    #[test]
    fn windows_scheduler_bridge_noop_returns_not_implemented() {
        let s = WindowsSchedulerBridge::new();
        assert!(matches!(
            s.schedule_backup(60_000),
            Err(Error::NotImplemented("windows_scheduler"))
        ));
        assert!(matches!(
            s.schedule_archive_compaction(60_000),
            Err(Error::NotImplemented("windows_scheduler"))
        ));
        assert!(matches!(
            s.schedule_index_maintenance(60_000),
            Err(Error::NotImplemented("windows_scheduler"))
        ));
        assert!(matches!(
            s.cancel_all(),
            Err(Error::NotImplemented("windows_scheduler"))
        ));
        assert!(matches!(
            s.is_task_pending("backup"),
            Err(Error::NotImplemented("windows_scheduler"))
        ));
    }

    #[test]
    fn windows_ml_config_defaults_to_cpu_only() {
        let c = WindowsMlConfig::default();
        assert!(!c.assume_gpu);
        assert!(c.prefer_int4_default);
        assert!(c.directml_best_effort);

        let cpu = WindowsMlConfig::cpu_only();
        assert_eq!(c, cpu);
    }

    #[test]
    fn windows_search_bridge_is_object_safe() {
        let _b: Box<dyn WindowsSearchBridge> = Box::new(NoopWindowsSearchBridge::new());
    }

    #[test]
    fn windows_scheduler_is_object_safe() {
        let _s: Box<dyn BackgroundScheduler> = Box::new(WindowsSchedulerBridge::new());
    }
}
