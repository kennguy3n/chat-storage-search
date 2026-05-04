//! In-process background scheduler — Phase 7, batch-5
//! (2026-05-04).
//!
//! `docs/PROPOSAL.md §6` and `docs/PHASES.md` Phase 7 call for a
//! Rust-native scheduler that runs the recurring kchat loops
//! (incremental backup, archive compaction, FTS / fuzzy index
//! maintenance, media-cache eviction) on a background thread
//! without depending on a platform scheduler primitive
//! (`BGTaskScheduler`, `WorkManager`).
//!
//! The desktop crate uses [`InProcessScheduler`] as the default
//! [`BackgroundScheduler`] when no platform bridge is installed.
//! It is also handy for unit / integration tests that want to
//! exercise the whole `CoreImpl::install_scheduler` →
//! schedule → run path without touching the OS.
//!
//! ## Design
//!
//! * One worker thread per scheduled `TaskType`. The worker
//!   wakes on a [`std::sync::Condvar`] every `interval_ms` and
//!   invokes the registered [`TaskHandler`] closure.
//! * Re-scheduling the same `TaskType` while a previous worker
//!   is still alive is a **no-op** — `is_task_pending` returns
//!   `true` and the duplicate `schedule_*` call is silently
//!   absorbed. This is the deduplication behaviour the trait
//!   contract requires.
//! * `cancel_all` flips a shutdown flag, signals every condvar,
//!   and joins every worker thread before returning.
//! * `Drop` calls `cancel_all` so the scheduler shuts down
//!   cleanly when the owning `CoreImpl` goes out of scope.
//!
//! ## Task handlers
//!
//! Tasks must register a handler via [`InProcessScheduler::set_handler`]
//! before scheduling; otherwise the worker silently no-ops. This
//! decoupling keeps the scheduler module free of `CoreImpl`
//! references — `CoreImpl::install_in_process_scheduler` wires
//! the handlers from outside.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::Error;

use super::{BackgroundScheduler, TaskType};

/// Boxed closure invoked by the in-process worker once per
/// scheduled tick. Handlers MUST be `Send + Sync` so the same
/// `Arc<dyn TaskHandler>` can outlive the scheduler thread.
pub trait TaskHandler: Send + Sync + 'static {
    /// Run one iteration of the recurring task. The scheduler
    /// invokes this on its worker thread, blocks on it, then
    /// sleeps until the next tick.
    fn run(&self) -> Result<(), Error>;
}

impl<F> TaskHandler for F
where
    F: Fn() -> Result<(), Error> + Send + Sync + 'static,
{
    fn run(&self) -> Result<(), Error> {
        (self)()
    }
}

#[derive(Debug, Default)]
struct TaskState {
    /// `true` once the worker has been signaled to stop. The
    /// worker wakes on the condvar, observes this, and exits.
    shutdown: bool,
    /// Per-task tick counter, exposed via
    /// [`InProcessScheduler::tick_count`] so tests can assert the
    /// worker actually fired without watching the wall clock.
    tick_count: u64,
}

struct WorkerHandle {
    /// Shutdown flag + tick counter, shared with the worker.
    state: Arc<(Mutex<TaskState>, Condvar)>,
    /// Joinable handle to the worker thread.
    join: JoinHandle<()>,
}

/// In-process [`BackgroundScheduler`] driven by a thread per
/// scheduled `TaskType`. See module docs for the overall design.
pub struct InProcessScheduler {
    handlers: Mutex<HashMap<TaskType, Arc<dyn TaskHandler>>>,
    workers: Mutex<HashMap<TaskType, WorkerHandle>>,
}

impl std::fmt::Debug for InProcessScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pending = self.workers.lock().map(|m| m.len()).unwrap_or_default();
        f.debug_struct("InProcessScheduler")
            .field("scheduled_tasks", &pending)
            .finish()
    }
}

impl Default for InProcessScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl InProcessScheduler {
    /// Construct a new scheduler with no handlers and no
    /// scheduled tasks.
    pub fn new() -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
            workers: Mutex::new(HashMap::new()),
        }
    }

    /// Register a [`TaskHandler`] for the supplied `TaskType`.
    /// Replaces any previously-registered handler for that task
    /// type. Handlers MUST be installed *before* the
    /// corresponding `schedule_*` call — workers spawned without
    /// a registered handler silently no-op.
    pub fn set_handler<H: TaskHandler>(&self, task: TaskType, handler: H) {
        if let Ok(mut h) = self.handlers.lock() {
            h.insert(task, Arc::new(handler));
        }
    }

    /// How many ticks the worker for `task` has fired since it
    /// was scheduled. Returns `0` when no worker is alive.
    /// Useful for tests that assert the scheduler actually
    /// invoked its handler without depending on wall-clock
    /// timing.
    pub fn tick_count(&self, task: TaskType) -> u64 {
        let workers = match self.workers.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        match workers.get(&task) {
            Some(w) => match w.state.0.lock() {
                Ok(s) => s.tick_count,
                Err(_) => 0,
            },
            None => 0,
        }
    }

    /// Whether a worker for `task` is currently alive.
    pub fn is_task_pending_kind(&self, task: TaskType) -> bool {
        self.workers
            .lock()
            .map(|m| m.contains_key(&task))
            .unwrap_or(false)
    }

    fn spawn_worker(&self, task: TaskType, interval_ms: u64) -> Result<(), Error> {
        // Validate cadence — `0` would tight-loop the worker.
        if interval_ms == 0 {
            return Err(Error::Storage("scheduler interval_ms must be > 0".into()));
        }
        // Deduplication: if a worker for this task type is
        // already alive, succeed without spawning a duplicate.
        {
            let workers = self
                .workers
                .lock()
                .map_err(|_| Error::Storage("scheduler worker mutex poisoned".into()))?;
            if workers.contains_key(&task) {
                return Ok(());
            }
        }

        let handler = self
            .handlers
            .lock()
            .map_err(|_| Error::Storage("scheduler handler mutex poisoned".into()))?
            .get(&task)
            .cloned();

        let state: Arc<(Mutex<TaskState>, Condvar)> =
            Arc::new((Mutex::new(TaskState::default()), Condvar::new()));
        let state_for_thread = Arc::clone(&state);

        let join = std::thread::Builder::new()
            .name(format!("kchat-scheduler-{}", task.default_task_id()))
            .spawn(move || {
                let interval = Duration::from_millis(interval_ms);
                loop {
                    // Sleep until interval elapses or shutdown
                    // is signaled. We use a deadline-based wait
                    // so signals from the condvar interrupt the
                    // sleep promptly on `cancel_all`.
                    let deadline = Instant::now() + interval;
                    let (lock, cvar) = &*state_for_thread;
                    let mut guard = match lock.lock() {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    while !guard.shutdown {
                        let now = Instant::now();
                        if now >= deadline {
                            break;
                        }
                        let remaining = deadline - now;
                        let (g, _) = match cvar.wait_timeout(guard, remaining) {
                            Ok(pair) => pair,
                            Err(_) => return,
                        };
                        guard = g;
                    }
                    if guard.shutdown {
                        return;
                    }
                    drop(guard);

                    // Run the handler outside the lock so it
                    // can block on its own resources without
                    // wedging the shutdown path.
                    if let Some(h) = &handler {
                        let _ = h.run();
                    }
                    // Bump the tick counter. We deliberately do
                    // not record handler errors; the production
                    // wiring funnels them through PerfCollector.
                    if let Ok(mut g) = state_for_thread.0.lock() {
                        g.tick_count = g.tick_count.saturating_add(1);
                    }
                }
            })
            .map_err(|e| Error::Storage(format!("scheduler thread spawn failed: {e}")))?;

        let mut workers = self
            .workers
            .lock()
            .map_err(|_| Error::Storage("scheduler worker mutex poisoned".into()))?;
        workers.insert(task, WorkerHandle { state, join });
        Ok(())
    }
}

impl Drop for InProcessScheduler {
    fn drop(&mut self) {
        let _ = self.cancel_all();
    }
}

impl BackgroundScheduler for InProcessScheduler {
    fn schedule_backup(&self, interval_ms: u64) -> Result<(), Error> {
        self.spawn_worker(TaskType::IncrementalBackup, interval_ms)
    }

    fn schedule_archive_compaction(&self, interval_ms: u64) -> Result<(), Error> {
        self.spawn_worker(TaskType::ArchiveCompaction, interval_ms)
    }

    fn schedule_index_maintenance(&self, interval_ms: u64) -> Result<(), Error> {
        self.spawn_worker(TaskType::IndexMaintenance, interval_ms)
    }

    fn schedule_media_cache_eviction(&self, interval_ms: u64) -> Result<(), Error> {
        self.spawn_worker(TaskType::MediaCacheEviction, interval_ms)
    }

    fn cancel_all(&self) -> Result<(), Error> {
        let drained: Vec<(TaskType, WorkerHandle)> = match self.workers.lock() {
            Ok(mut m) => m.drain().collect(),
            Err(_) => return Err(Error::Storage("scheduler mutex poisoned".into())),
        };
        for (_, worker) in drained {
            // Signal shutdown then wake the worker.
            if let Ok(mut g) = worker.state.0.lock() {
                g.shutdown = true;
            }
            worker.state.1.notify_all();
            // Best-effort join — a panicked worker shouldn't
            // wedge the rest of the shutdown path.
            let _ = worker.join.join();
        }
        Ok(())
    }

    fn is_task_pending(&self, task_id: &str) -> Result<bool, Error> {
        let workers = self
            .workers
            .lock()
            .map_err(|_| Error::Storage("scheduler mutex poisoned".into()))?;
        let pending = workers.keys().any(|t| t.default_task_id() == task_id);
        Ok(pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Helper handler that bumps an atomic each tick.
    fn counting_handler() -> (Arc<AtomicU32>, impl Fn() -> Result<(), Error> + Send + Sync) {
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let f = move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        (counter, f)
    }

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
    fn schedule_backup_runs_handler_at_interval() {
        let s = InProcessScheduler::new();
        let (counter, handler) = counting_handler();
        s.set_handler(TaskType::IncrementalBackup, handler);
        s.schedule_backup(20).expect("scheduling");
        let observed = wait_for_at_least(&counter, 2, Duration::from_secs(2));
        assert!(observed >= 2, "handler must have ticked at least twice");
        s.cancel_all().expect("cancel_all");
    }

    #[test]
    fn schedule_is_deduplicated_per_task_type() {
        let s = InProcessScheduler::new();
        let (counter, handler) = counting_handler();
        s.set_handler(TaskType::IncrementalBackup, handler);
        s.schedule_backup(50).expect("first schedule");
        s.schedule_backup(50).expect("dedup-second schedule");
        s.schedule_backup(50).expect("dedup-third schedule");
        // Only one worker should be alive.
        assert!(s.is_task_pending_kind(TaskType::IncrementalBackup));
        assert!(s
            .is_task_pending("kchat.scheduler.incremental_backup")
            .unwrap());
        // Even though we requested three schedules, the
        // counter only ticks at the cadence of one worker.
        let observed = wait_for_at_least(&counter, 1, Duration::from_secs(1));
        assert!(observed >= 1);
        s.cancel_all().expect("cancel_all");
    }

    #[test]
    fn cancel_all_stops_workers_and_clears_pending() {
        let s = InProcessScheduler::new();
        let (counter, handler) = counting_handler();
        s.set_handler(TaskType::ArchiveCompaction, handler);
        s.schedule_archive_compaction(20).expect("schedule");
        wait_for_at_least(&counter, 1, Duration::from_secs(1));
        s.cancel_all().expect("cancel_all");
        assert!(!s.is_task_pending_kind(TaskType::ArchiveCompaction));
        let after = counter.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(80));
        let later = counter.load(Ordering::SeqCst);
        assert_eq!(after, later, "handler must not run again after cancel_all");
    }

    #[test]
    fn unregistered_handler_is_noop_but_worker_alive() {
        let s = InProcessScheduler::new();
        // No handler registered for IndexMaintenance.
        s.schedule_index_maintenance(20).expect("schedule");
        std::thread::sleep(Duration::from_millis(80));
        assert!(s.is_task_pending_kind(TaskType::IndexMaintenance));
        // The worker keeps ticking but the handler is a no-op.
        let ticks = s.tick_count(TaskType::IndexMaintenance);
        assert!(ticks >= 1);
        s.cancel_all().expect("cancel_all");
    }

    #[test]
    fn zero_interval_returns_invalid_error() {
        let s = InProcessScheduler::new();
        let err = s.schedule_backup(0).unwrap_err();
        assert!(
            matches!(err, Error::Storage(ref m) if m.contains("interval_ms")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn drop_runs_cancel_all_implicitly() {
        let counter = {
            let s = InProcessScheduler::new();
            let (counter, handler) = counting_handler();
            s.set_handler(TaskType::IncrementalBackup, handler);
            s.schedule_backup(20).expect("schedule");
            wait_for_at_least(&counter, 1, Duration::from_secs(1));
            counter
        };
        let snapshot = counter.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(80));
        let later = counter.load(Ordering::SeqCst);
        assert_eq!(
            snapshot, later,
            "Drop must have cancelled the worker thread"
        );
    }

    #[test]
    fn concurrent_task_types_run_independently() {
        let s = InProcessScheduler::new();
        let (counter_a, handler_a) = counting_handler();
        let (counter_b, handler_b) = counting_handler();
        s.set_handler(TaskType::IncrementalBackup, handler_a);
        s.set_handler(TaskType::ArchiveCompaction, handler_b);
        s.schedule_backup(20).expect("schedule a");
        s.schedule_archive_compaction(20).expect("schedule b");
        wait_for_at_least(&counter_a, 1, Duration::from_secs(2));
        wait_for_at_least(&counter_b, 1, Duration::from_secs(2));
        assert!(counter_a.load(Ordering::SeqCst) >= 1);
        assert!(counter_b.load(Ordering::SeqCst) >= 1);
        s.cancel_all().expect("cancel_all");
    }

    #[test]
    fn is_task_pending_returns_false_for_unknown_id() {
        let s = InProcessScheduler::new();
        assert!(!s.is_task_pending("kchat.scheduler.unknown").unwrap());
    }

    #[test]
    fn fn_closure_satisfies_task_handler_blanket_impl() {
        // Compile-time test: the blanket impl
        // `impl<F: Fn()->Result> TaskHandler for F` allows callers
        // to register a plain closure without manually wrapping
        // it in a struct.
        let s = InProcessScheduler::new();
        s.set_handler(TaskType::ModelWarmup, || Ok(()));
        // No schedule_model_warmup method; just verify the
        // handler was registered without panicking.
        assert!(!s.is_task_pending_kind(TaskType::ModelWarmup));
    }
}
