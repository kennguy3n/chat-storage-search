//! Background-task scheduler foundation (Phase 5/7, Task 9).
//!
//! `docs/PROPOSAL.md §6` calls out that the offload / backup /
//! index-maintenance / model-warmup pipelines must run on
//! battery- and network-aware *background* schedules — not on
//! the foreground UI thread. iOS surfaces this through
//! `BGTaskScheduler` (`BGProcessingTask`, `BGAppRefreshTask`)
//! and Android through `WorkManager` (`PeriodicWorkRequest`).
//!
//! The Rust core does not own those primitives — it cannot
//! reach into Swift / Kotlin. Instead this module defines the
//! **policy surface** the platform bridges fill in:
//!
//! * [`BackgroundScheduler`] — object-safe trait the
//!   orchestration layer calls. One method per Phase-5/7
//!   recurring task: incremental backup, archive compaction,
//!   index maintenance, plus blanket cancel / pending-check.
//! * [`ScheduledTask`] — per-task descriptor returned to the
//!   bridge on `schedule_*`.
//! * [`TaskType`] — enum of every recurring task the core
//!   emits.
//! * [`NoopScheduler`] — placeholder returning
//!   `Error::NotImplemented("scheduler")` until a real bridge is
//!   installed.
//! * [`IosBgTaskBridge`] / [`AndroidWorkManagerBridge`] —
//!   platform-bridge traits implemented in Swift / Kotlin and
//!   exposed back to Rust through the FFI layer.
//!
//! `CoreImpl` carries an `Mutex<Option<Box<dyn
//! BackgroundScheduler>>>` slot
//! ([`crate::core_impl::CoreImpl::install_scheduler`]); installs
//! at app boot, no-ops without a bridge installed.

use serde::{Deserialize, Serialize};

use crate::Error;

// ---------------------------------------------------------------------------
// TaskType — enumerated recurring background tasks
// ---------------------------------------------------------------------------

/// Recurring background task kinds emitted by the core.
///
/// Variants map 1:1 onto Phase 5 / Phase 7 maintenance loops in
/// `docs/PROPOSAL.md §6`. The serde representation uses
/// `snake_case` so the wire form matches the rest of the
/// crate's CBOR / JSON conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    /// Roll forward the incremental-backup manifest chain
    /// (`docs/PROPOSAL.md §10`).
    IncrementalBackup,
    /// Compact / merge personal-archive segments
    /// (`docs/PROPOSAL.md §5`).
    ArchiveCompaction,
    /// FTS / fuzzy / vector index housekeeping
    /// (`docs/PROPOSAL.md §7`).
    IndexMaintenance,
    /// Evict older media off-device per the storage budget
    /// (`docs/PROPOSAL.md §6.4`).
    MediaCacheEviction,
    /// Pre-warm on-device models so search-result-tap latency
    /// stays under the §12 budget.
    ModelWarmup,
}

impl TaskType {
    /// Default task id string used by the orchestration layer
    /// when it does not need a per-instance id (e.g. the
    /// "current backup" rolled over by `IncrementalBackup`).
    pub fn default_task_id(self) -> &'static str {
        match self {
            TaskType::IncrementalBackup => "kchat.scheduler.incremental_backup",
            TaskType::ArchiveCompaction => "kchat.scheduler.archive_compaction",
            TaskType::IndexMaintenance => "kchat.scheduler.index_maintenance",
            TaskType::MediaCacheEviction => "kchat.scheduler.media_cache_eviction",
            TaskType::ModelWarmup => "kchat.scheduler.model_warmup",
        }
    }
}

// ---------------------------------------------------------------------------
// ScheduledTask — per-task descriptor
// ---------------------------------------------------------------------------

/// Descriptor for one scheduled background task. Returned to the
/// bridge so it can echo the schedule back into the platform
/// scheduler (`BGTaskScheduler` request / `WorkManager`
/// PeriodicWorkRequest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledTask {
    /// Identifier the bridge uses to look up / cancel the task.
    pub task_id: String,
    /// Which Phase-5/7 maintenance loop this task drives.
    pub task_type: TaskType,
    /// Cadence in milliseconds (e.g. 86_400_000 for daily).
    /// `0` is disallowed; callers that want "run once and stop"
    /// schedule a task and immediately call
    /// [`BackgroundScheduler::cancel_all`].
    pub interval_ms: u64,
    /// Wall-clock millisecond timestamp of the most recent
    /// execution, or `None` if the task has not run yet.
    pub last_run_ms: Option<i64>,
    /// Wall-clock millisecond timestamp of the next scheduled
    /// execution.
    pub next_run_ms: i64,
}

impl ScheduledTask {
    /// Build a task descriptor with `next_run_ms = now + interval`.
    pub fn new(task_type: TaskType, interval_ms: u64, now_ms: i64) -> Self {
        Self {
            task_id: task_type.default_task_id().into(),
            task_type,
            interval_ms,
            last_run_ms: None,
            next_run_ms: now_ms.saturating_add(interval_ms as i64),
        }
    }
}

// ---------------------------------------------------------------------------
// BackgroundScheduler — orchestration-side trait
// ---------------------------------------------------------------------------

/// Object-safe scheduler trait the orchestration layer calls.
///
/// Implementors are expected to be platform bridges
/// ([`IosBgTaskBridge`], [`AndroidWorkManagerBridge`]) — the
/// Rust core never owns the actual wall-clock timer. Every
/// method is fallible because the underlying platform scheduler
/// can refuse a request (rate-limit, missing permission, …) and
/// the core needs to surface that to the user.
pub trait BackgroundScheduler: Send + Sync + std::fmt::Debug {
    /// Schedule the [`TaskType::IncrementalBackup`] loop with
    /// the given cadence.
    fn schedule_backup(&self, interval_ms: u64) -> Result<(), Error>;

    /// Schedule the [`TaskType::ArchiveCompaction`] loop with
    /// the given cadence.
    fn schedule_archive_compaction(&self, interval_ms: u64) -> Result<(), Error>;

    /// Schedule the [`TaskType::IndexMaintenance`] loop with
    /// the given cadence.
    fn schedule_index_maintenance(&self, interval_ms: u64) -> Result<(), Error>;

    /// Cancel every kchat-owned scheduled task. Used during
    /// account teardown, device deregistration, and the
    /// `cancel_all` test harness.
    fn cancel_all(&self) -> Result<(), Error>;

    /// Whether `task_id` is currently scheduled. Used by the
    /// orchestration layer to skip a re-schedule when the
    /// platform already has the task in its queue.
    fn is_task_pending(&self, task_id: &str) -> Result<bool, Error>;
}

// ---------------------------------------------------------------------------
// NoopScheduler — placeholder
// ---------------------------------------------------------------------------

/// Phase-0 placeholder scheduler. Every method returns
/// `Err(Error::NotImplemented("scheduler"))` so the orchestration
/// layer never silently drops a schedule request when no real
/// bridge is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopScheduler;

impl NoopScheduler {
    /// Construct a fresh `NoopScheduler`.
    pub const fn new() -> Self {
        Self
    }
}

impl BackgroundScheduler for NoopScheduler {
    fn schedule_backup(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("scheduler"))
    }
    fn schedule_archive_compaction(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("scheduler"))
    }
    fn schedule_index_maintenance(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("scheduler"))
    }
    fn cancel_all(&self) -> Result<(), Error> {
        Err(Error::NotImplemented("scheduler"))
    }
    fn is_task_pending(&self, _task_id: &str) -> Result<bool, Error> {
        Err(Error::NotImplemented("scheduler"))
    }
}

// ---------------------------------------------------------------------------
// Platform bridge traits (Swift / Kotlin glue)
// ---------------------------------------------------------------------------

/// iOS-side bridge wrapping `BGTaskScheduler`. Swift fills in
/// the implementation and exposes it to Rust via the FFI layer.
pub trait IosBgTaskBridge: Send + Sync + std::fmt::Debug {
    /// Submit a `BGProcessingTaskRequest` for the given task.
    fn submit_processing_task(&self, task: &ScheduledTask) -> Result<(), Error>;
    /// Cancel a previously-submitted task by id.
    fn cancel_task(&self, task_id: &str) -> Result<(), Error>;
    /// Whether `task_id` is queued in `BGTaskScheduler`.
    fn is_pending(&self, task_id: &str) -> Result<bool, Error>;
}

/// Phase-0 placeholder for `BGTaskScheduler` integration.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopIosBgTaskBridge;

impl IosBgTaskBridge for NoopIosBgTaskBridge {
    fn submit_processing_task(&self, _task: &ScheduledTask) -> Result<(), Error> {
        Err(Error::NotImplemented("scheduler"))
    }
    fn cancel_task(&self, _task_id: &str) -> Result<(), Error> {
        Err(Error::NotImplemented("scheduler"))
    }
    fn is_pending(&self, _task_id: &str) -> Result<bool, Error> {
        Err(Error::NotImplemented("scheduler"))
    }
}

/// Android-side bridge wrapping `WorkManager`. Kotlin fills in
/// the implementation and exposes it to Rust via the FFI layer.
pub trait AndroidWorkManagerBridge: Send + Sync + std::fmt::Debug {
    /// Enqueue a `PeriodicWorkRequest` for the given task.
    fn enqueue_periodic(&self, task: &ScheduledTask) -> Result<(), Error>;
    /// Cancel a previously-enqueued task by id.
    fn cancel_unique_work(&self, task_id: &str) -> Result<(), Error>;
    /// Whether `task_id` is queued in `WorkManager`.
    fn is_enqueued(&self, task_id: &str) -> Result<bool, Error>;
}

/// Phase-0 placeholder for `WorkManager` integration.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAndroidWorkManagerBridge;

impl AndroidWorkManagerBridge for NoopAndroidWorkManagerBridge {
    fn enqueue_periodic(&self, _task: &ScheduledTask) -> Result<(), Error> {
        Err(Error::NotImplemented("scheduler"))
    }
    fn cancel_unique_work(&self, _task_id: &str) -> Result<(), Error> {
        Err(Error::NotImplemented("scheduler"))
    }
    fn is_enqueued(&self, _task_id: &str) -> Result<bool, Error> {
        Err(Error::NotImplemented("scheduler"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: the trait must be object-safe so
    /// `CoreImpl` can store it as `Box<dyn BackgroundScheduler>`.
    #[test]
    fn background_scheduler_is_object_safe() {
        let _scheduler: Box<dyn BackgroundScheduler> = Box::new(NoopScheduler::new());
    }

    #[test]
    fn ios_bg_task_bridge_is_object_safe() {
        let _bridge: Box<dyn IosBgTaskBridge> = Box::<NoopIosBgTaskBridge>::default();
    }

    #[test]
    fn android_work_manager_bridge_is_object_safe() {
        let _bridge: Box<dyn AndroidWorkManagerBridge> =
            Box::<NoopAndroidWorkManagerBridge>::default();
    }

    #[test]
    fn noop_scheduler_returns_not_implemented_for_every_method() {
        let s = NoopScheduler::new();
        assert!(matches!(
            s.schedule_backup(60_000),
            Err(Error::NotImplemented("scheduler"))
        ));
        assert!(matches!(
            s.schedule_archive_compaction(60_000),
            Err(Error::NotImplemented("scheduler"))
        ));
        assert!(matches!(
            s.schedule_index_maintenance(60_000),
            Err(Error::NotImplemented("scheduler"))
        ));
        assert!(matches!(
            s.cancel_all(),
            Err(Error::NotImplemented("scheduler"))
        ));
        assert!(matches!(
            s.is_task_pending("kchat.scheduler.incremental_backup"),
            Err(Error::NotImplemented("scheduler"))
        ));
    }

    #[test]
    fn noop_ios_bridge_returns_not_implemented() {
        let b = NoopIosBgTaskBridge;
        let task = ScheduledTask::new(TaskType::IncrementalBackup, 60_000, 1_000);
        assert!(matches!(
            b.submit_processing_task(&task),
            Err(Error::NotImplemented("scheduler"))
        ));
        assert!(matches!(
            b.cancel_task("foo"),
            Err(Error::NotImplemented("scheduler"))
        ));
        assert!(matches!(
            b.is_pending("foo"),
            Err(Error::NotImplemented("scheduler"))
        ));
    }

    #[test]
    fn noop_android_bridge_returns_not_implemented() {
        let b = NoopAndroidWorkManagerBridge;
        let task = ScheduledTask::new(TaskType::ArchiveCompaction, 60_000, 1_000);
        assert!(matches!(
            b.enqueue_periodic(&task),
            Err(Error::NotImplemented("scheduler"))
        ));
        assert!(matches!(
            b.cancel_unique_work("foo"),
            Err(Error::NotImplemented("scheduler"))
        ));
        assert!(matches!(
            b.is_enqueued("foo"),
            Err(Error::NotImplemented("scheduler"))
        ));
    }

    #[test]
    fn task_type_round_trips_through_serde() {
        let cases = [
            TaskType::IncrementalBackup,
            TaskType::ArchiveCompaction,
            TaskType::IndexMaintenance,
            TaskType::MediaCacheEviction,
            TaskType::ModelWarmup,
        ];
        for t in cases {
            let json = serde_json::to_string(&t).expect("encode");
            let back: TaskType = serde_json::from_str(&json).expect("decode");
            assert_eq!(back, t);
        }
    }

    #[test]
    fn scheduled_task_new_advances_next_run_by_interval() {
        let t = ScheduledTask::new(TaskType::IndexMaintenance, 86_400_000, 1_000_000);
        assert_eq!(t.task_type, TaskType::IndexMaintenance);
        assert_eq!(t.task_id, "kchat.scheduler.index_maintenance");
        assert_eq!(t.interval_ms, 86_400_000);
        assert_eq!(t.last_run_ms, None);
        assert_eq!(t.next_run_ms, 1_000_000 + 86_400_000);
    }

    #[test]
    fn scheduled_task_round_trips_through_serde() {
        let t = ScheduledTask::new(TaskType::ModelWarmup, 60_000, 0);
        let json = serde_json::to_string(&t).expect("encode");
        let back: ScheduledTask = serde_json::from_str(&json).expect("decode");
        assert_eq!(back, t);
    }

    #[test]
    fn default_task_ids_are_unique_and_namespaced() {
        let ids: std::collections::HashSet<&'static str> = [
            TaskType::IncrementalBackup,
            TaskType::ArchiveCompaction,
            TaskType::IndexMaintenance,
            TaskType::MediaCacheEviction,
            TaskType::ModelWarmup,
        ]
        .into_iter()
        .map(TaskType::default_task_id)
        .collect();
        assert_eq!(ids.len(), 5, "every TaskType must have a unique task_id");
        for id in ids {
            assert!(
                id.starts_with("kchat.scheduler."),
                "namespaced task_id required, got {id}"
            );
        }
    }
}
