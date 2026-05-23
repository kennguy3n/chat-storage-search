//! Integration tests for the in-process background scheduler
//!
//! These tests exercise the public `BackgroundScheduler` trait
//! surface end-to-end: schedule a handler, wait for it to fire,
//! cancel, verify it stops. They live in `tests/` rather than
//! the in-tree unit tests so they're a coherent demonstration
//! of how the desktop orchestration layer is expected to wire
//! the scheduler up.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kchat_core::scheduler::{BackgroundScheduler, InProcessScheduler, NoopScheduler, TaskType};

fn wait_for_at_least(counter: &Arc<AtomicU32>, min: u32, timeout: Duration) -> u32 {
    let start = Instant::now();
    loop {
        let v = counter.load(Ordering::SeqCst);
        if v >= min {
            return v;
        }
        if Instant::now() - start >= timeout {
            return v;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn in_process_scheduler_runs_every_task_kind_through_trait_object() {
    let s = InProcessScheduler::new();
    let counters: [Arc<AtomicU32>; 4] = [
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    ];
    let task_types = [
        TaskType::IncrementalBackup,
        TaskType::ArchiveCompaction,
        TaskType::IndexMaintenance,
        TaskType::MediaCacheEviction,
    ];

    for (idx, &task) in task_types.iter().enumerate() {
        let c = Arc::clone(&counters[idx]);
        s.set_handler(task, move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
    }

    let handle: Arc<dyn BackgroundScheduler> = Arc::new(s);
    handle.schedule_backup(20).unwrap();
    handle.schedule_archive_compaction(20).unwrap();
    handle.schedule_index_maintenance(20).unwrap();
    handle.schedule_media_cache_eviction(20).unwrap();

    for (idx, _) in task_types.iter().enumerate() {
        let observed = wait_for_at_least(&counters[idx], 1, Duration::from_secs(3));
        assert!(
            observed >= 1,
            "handler {idx} ({:?}) did not fire — observed {observed} ticks",
            task_types[idx]
        );
    }

    assert!(handle
        .is_task_pending("kchat.scheduler.incremental_backup")
        .unwrap());
    assert!(handle
        .is_task_pending("kchat.scheduler.archive_compaction")
        .unwrap());
    assert!(handle
        .is_task_pending("kchat.scheduler.index_maintenance")
        .unwrap());
    assert!(handle
        .is_task_pending("kchat.scheduler.media_cache_eviction")
        .unwrap());

    handle.cancel_all().unwrap();

    let snapshots: Vec<u32> = counters.iter().map(|c| c.load(Ordering::SeqCst)).collect();
    std::thread::sleep(Duration::from_millis(80));
    let later: Vec<u32> = counters.iter().map(|c| c.load(Ordering::SeqCst)).collect();
    assert_eq!(
        snapshots, later,
        "handlers must not run after cancel_all returns"
    );
}

#[test]
fn duplicate_schedule_calls_are_silently_deduplicated() {
    let s = InProcessScheduler::new();
    let counter = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&counter);
    s.set_handler(TaskType::IncrementalBackup, move || {
        c.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    // Three schedules → one worker.
    s.schedule_backup(30).unwrap();
    s.schedule_backup(30).unwrap();
    s.schedule_backup(30).unwrap();
    assert!(s.is_task_pending_kind(TaskType::IncrementalBackup));
    let v = wait_for_at_least(&counter, 1, Duration::from_secs(2));
    assert!(v >= 1);
    s.cancel_all().unwrap();
}

#[test]
fn graceful_shutdown_via_drop_stops_workers() {
    let counter = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&counter);
    {
        let s = InProcessScheduler::new();
        s.set_handler(TaskType::ArchiveCompaction, move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        s.schedule_archive_compaction(20).unwrap();
        wait_for_at_least(&counter, 1, Duration::from_secs(2));
    }
    let snapshot = counter.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(80));
    let later = counter.load(Ordering::SeqCst);
    assert_eq!(snapshot, later, "Drop must have shut down the worker");
}

#[test]
fn noop_scheduler_returns_not_implemented_for_every_method() {
    let s: Arc<dyn BackgroundScheduler> = Arc::new(NoopScheduler::new());
    assert!(matches!(
        s.schedule_backup(1_000),
        Err(kchat_core::Error::NotImplemented("scheduler"))
    ));
    assert!(matches!(
        s.schedule_archive_compaction(1_000),
        Err(kchat_core::Error::NotImplemented("scheduler"))
    ));
    assert!(matches!(
        s.schedule_index_maintenance(1_000),
        Err(kchat_core::Error::NotImplemented("scheduler"))
    ));
    assert!(matches!(
        s.schedule_media_cache_eviction(1_000),
        Err(kchat_core::Error::NotImplemented("scheduler"))
    ));
    assert!(matches!(
        s.cancel_all(),
        Err(kchat_core::Error::NotImplemented("scheduler"))
    ));
    assert!(matches!(
        s.is_task_pending("foo"),
        Err(kchat_core::Error::NotImplemented("scheduler"))
    ));
}
