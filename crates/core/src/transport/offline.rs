//! Offline-detection seam — Phase 7, Task 6 of the 2026-05-04
//! batch.
//!
//! `docs/PHASES.md` Phase 7 enumerates "edge-case handling
//! (offline, interrupted, partial, corrupted, missing)" as a
//! gating item. This module lands the offline-detection seam:
//! a `Send + Sync` trait the orchestration layer queries before
//! making outbound network calls (incremental backup, archive
//! fetch on hydration). Implementations are supplied by the
//! platform glue (Reachability on iOS, ConnectivityManager on
//! Android, NCSI on Windows, NetworkManager on Linux).
//!
//! The detector is intentionally fail-open: when no detector is
//! installed, [`crate::core_impl::CoreImpl::is_online`] returns
//! `true` so the existing Phase 1–5 code paths keep their
//! "always assume online" behavior. Only when a detector is
//! installed do the offline branches in
//! [`crate::core_impl::CoreImpl::run_incremental_backup`] and
//! [`crate::core_impl::CoreImpl::hydrate_message`] kick in.

use std::sync::atomic::{AtomicBool, Ordering};

/// Object-safe + `Send + Sync` offline-detection seam.
///
/// Implementations report whether the device currently has
/// network connectivity. Cheap / synchronous: this is called on
/// every backup-loop iteration and every cold-message
/// hydration, so it MUST NOT block on a real network probe;
/// the platform glue is expected to cache the system
/// connectivity flag and update it from the platform's
/// reachability callback.
pub trait OfflineDetector: std::fmt::Debug + Send + Sync {
    /// `true` when the device is online (Wi-Fi or cellular
    /// reachable); `false` when it is offline.
    fn is_online(&self) -> bool;
}

/// Always-online [`OfflineDetector`] — the default in production
/// when the platform glue has not yet installed a real detector.
///
/// Mirrors [`crate::transport::NoopTransportClient`] — the noop
/// shape lets unit tests construct a `CoreImpl` without standing
/// up a connectivity probe.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopOfflineDetector;

impl OfflineDetector for NoopOfflineDetector {
    fn is_online(&self) -> bool {
        true
    }
}

/// Test-only [`OfflineDetector`] that always reports offline.
///
/// Used by `crates/core/tests/failure_scenarios.rs` to drive
/// the offline-during-backup / offline-during-hydration paths
/// deterministically.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysOfflineDetector;

impl OfflineDetector for AlwaysOfflineDetector {
    fn is_online(&self) -> bool {
        false
    }
}

/// Test-only [`OfflineDetector`] whose state can be toggled at
/// runtime.
///
/// Used by tests that need to walk through a backup deferred ⇒
/// reconnect ⇒ upload sequence in one process: install the
/// detector with `is_online = false`, run the backup (it
/// defers), flip to `true`, run the backup again (it uploads).
#[derive(Debug, Default)]
pub struct ToggleOfflineDetector {
    online: AtomicBool,
}

impl ToggleOfflineDetector {
    /// Construct a [`ToggleOfflineDetector`] with the given
    /// initial state.
    pub fn new(online: bool) -> Self {
        Self {
            online: AtomicBool::new(online),
        }
    }

    /// Update the reported online state.
    pub fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::SeqCst);
    }
}

impl OfflineDetector for ToggleOfflineDetector {
    fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_offline_detector_reports_online() {
        let d = NoopOfflineDetector;
        assert!(d.is_online());
    }

    #[test]
    fn always_offline_detector_reports_offline() {
        let d = AlwaysOfflineDetector;
        assert!(!d.is_online());
    }

    #[test]
    fn toggle_offline_detector_round_trip() {
        let d = ToggleOfflineDetector::new(true);
        assert!(d.is_online());
        d.set_online(false);
        assert!(!d.is_online());
        d.set_online(true);
        assert!(d.is_online());
    }

    #[test]
    fn offline_detector_trait_is_object_safe() {
        let d = AlwaysOfflineDetector;
        let dynref: &dyn OfflineDetector = &d;
        assert!(!dynref.is_online());
    }
}
