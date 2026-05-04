//! Desktop in-process background scheduler — Phase 7, batch-5
//! (2026-05-04).
//!
//! `docs/PHASES.md` Phase 7 calls for a desktop scheduler that
//! runs the recurring kchat loops on a Rust-native worker
//! thread when no platform scheduler bridge
//! (`NSBackgroundActivityScheduler` on macOS, Windows Task
//! Scheduler on Windows) is wired in. The desktop binary can
//! always opt into the platform scheduler later by replacing
//! the installed [`BackgroundScheduler`] on `CoreImpl`.
//!
//! [`DesktopScheduler`] is a thin re-export wrapper around the
//! cross-platform [`InProcessScheduler`] from
//! `crates/core/src/scheduler/in_process.rs`. The wrapper
//! exists for two reasons:
//!
//! 1. The desktop crate is the consumer that's expected to
//!    install the in-process scheduler — keeping a desktop-side
//!    type lets us add desktop-specific configuration (UI hints,
//!    log levels) without touching the core scheduler module.
//! 2. The macOS / Windows production scheduler will eventually
//!    replace the wrapper without changing the public name; the
//!    desktop layer continues to refer to `DesktopScheduler` and
//!    swap the impl underneath.

use std::ops::Deref;
use std::sync::Arc;

use kchat_core::scheduler::{BackgroundScheduler, InProcessScheduler, TaskHandler, TaskType};
use kchat_core::Error;

/// Desktop wrapper around [`InProcessScheduler`]. Implements
/// [`BackgroundScheduler`] by delegating to the wrapped core
/// scheduler.
#[derive(Debug)]
pub struct DesktopScheduler {
    inner: Arc<InProcessScheduler>,
}

impl Default for DesktopScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl DesktopScheduler {
    /// Build a fresh desktop scheduler with no handlers and no
    /// scheduled tasks.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(InProcessScheduler::new()),
        }
    }

    /// Build a desktop scheduler that wraps an existing
    /// [`InProcessScheduler`]. Useful when the orchestration
    /// layer already created the core scheduler and wants to
    /// reach it through both the `BackgroundScheduler` trait
    /// surface and the desktop-specific surface.
    pub fn from_inner(inner: Arc<InProcessScheduler>) -> Self {
        Self { inner }
    }

    /// Borrow the inner [`InProcessScheduler`]. Callers reach
    /// through this to register handlers via
    /// [`InProcessScheduler::set_handler`].
    pub fn inner(&self) -> &InProcessScheduler {
        &self.inner
    }

    /// `Arc::clone` of the inner [`InProcessScheduler`]. The
    /// desktop layer hands the clone to `CoreImpl::install_scheduler`
    /// while keeping a local reference for handler registration.
    pub fn inner_arc(&self) -> Arc<InProcessScheduler> {
        Arc::clone(&self.inner)
    }

    /// Convenience wrapper around
    /// [`InProcessScheduler::set_handler`].
    pub fn set_handler<H: TaskHandler>(&self, task: TaskType, handler: H) {
        self.inner.set_handler(task, handler);
    }
}

impl Deref for DesktopScheduler {
    type Target = InProcessScheduler;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl BackgroundScheduler for DesktopScheduler {
    fn schedule_backup(&self, interval_ms: u64) -> Result<(), Error> {
        self.inner.schedule_backup(interval_ms)
    }
    fn schedule_archive_compaction(&self, interval_ms: u64) -> Result<(), Error> {
        self.inner.schedule_archive_compaction(interval_ms)
    }
    fn schedule_index_maintenance(&self, interval_ms: u64) -> Result<(), Error> {
        self.inner.schedule_index_maintenance(interval_ms)
    }
    fn schedule_media_cache_eviction(&self, interval_ms: u64) -> Result<(), Error> {
        self.inner.schedule_media_cache_eviction(interval_ms)
    }
    fn cancel_all(&self) -> Result<(), Error> {
        self.inner.cancel_all()
    }
    fn is_task_pending(&self, task_id: &str) -> Result<bool, Error> {
        self.inner.is_task_pending(task_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn desktop_scheduler_runs_handler_via_background_scheduler_trait() {
        let s = DesktopScheduler::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        s.set_handler(TaskType::IncrementalBackup, move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let trait_object: &dyn BackgroundScheduler = &s;
        trait_object.schedule_backup(20).expect("schedule");
        // Wait for at least one tick.
        let start = std::time::Instant::now();
        while counter.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(counter.load(Ordering::SeqCst) >= 1);
        trait_object.cancel_all().expect("cancel");
    }

    #[test]
    fn desktop_scheduler_can_be_held_inside_arc_dyn() {
        let s: Arc<dyn BackgroundScheduler> = Arc::new(DesktopScheduler::new());
        // Object-safety smoke test — schedule + cancel through
        // the trait object without touching the wrapper.
        s.schedule_index_maintenance(20).expect("schedule");
        s.cancel_all().expect("cancel");
    }
}
