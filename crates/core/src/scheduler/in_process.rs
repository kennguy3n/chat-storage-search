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

use super::{BackgroundScheduler, OneOffTask, TaskConstraints, TaskType};

/// Phase 7 (2026-05-04 batch 10) — Task 9: device-state probe
/// the in-process scheduler consults before draining a one-off
/// task. Production callers wire this into a platform battery /
/// network monitor; tests pass a hand-rolled `bool` snapshot.
pub trait ResourceProbe {
    /// Whether the current device state satisfies every flag
    /// set on `constraints`. Default impl checks the trait's
    /// per-method bools below.
    fn satisfies(&self, constraints: &TaskConstraints) -> bool {
        if constraints.require_wifi && !self.has_wifi() {
            return false;
        }
        if constraints.require_charging && !self.is_charging() {
            return false;
        }
        if constraints.require_idle && !self.is_idle() {
            return false;
        }
        true
    }
    /// Whether the device is on Wi-Fi (or equivalent un-metered
    /// network).
    fn has_wifi(&self) -> bool;
    /// Whether the device is charging.
    fn is_charging(&self) -> bool;
    /// Whether the device is idle (screen off / no foreground
    /// app).
    fn is_idle(&self) -> bool;
}

/// Test/desktop-default [`ResourceProbe`] that reports a fixed
/// snapshot of the device state. Useful for unit tests that
/// want to drive the scheduler through synthetic
/// "WiFi=off, charging=on" combinations.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticResourceProbe {
    /// Reported by [`ResourceProbe::has_wifi`].
    pub has_wifi: bool,
    /// Reported by [`ResourceProbe::is_charging`].
    pub is_charging: bool,
    /// Reported by [`ResourceProbe::is_idle`].
    pub is_idle: bool,
}

impl StaticResourceProbe {
    /// "Everything available" — the maximally permissive probe.
    pub fn all_available() -> Self {
        Self {
            has_wifi: true,
            is_charging: true,
            is_idle: true,
        }
    }

    /// "Nothing available" — every constraint will be denied.
    pub fn none_available() -> Self {
        Self {
            has_wifi: false,
            is_charging: false,
            is_idle: false,
        }
    }
}

impl ResourceProbe for StaticResourceProbe {
    fn has_wifi(&self) -> bool {
        self.has_wifi
    }
    fn is_charging(&self) -> bool {
        self.is_charging
    }
    fn is_idle(&self) -> bool {
        self.is_idle
    }
}

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
    /// Phase 7 (2026-05-04 batch 10) — Task 9 one-shot queue.
    /// Each entry is the `(task, constraints)` pair the
    /// orchestrator enqueued; `run_pending_one_off_tasks` drains
    /// this queue and invokes the registered one-off handler.
    one_offs: Mutex<Vec<(OneOffTask, TaskConstraints)>>,
    /// Optional handler invoked once per drained entry. Wired
    /// in by `CoreImpl::install_in_process_scheduler` on the
    /// orchestration side.
    one_off_handler: Mutex<Option<Arc<OneOffTaskHandler>>>,
}

/// Phase 7 (2026-05-04 batch 10) — Task 9 one-off task handler.
///
/// Invoked from `run_pending_one_off_tasks` for each task whose
/// constraints are currently satisfied. Returns `Ok(())` on
/// success or an [`Error`] on failure (the scheduler logs and
/// drops the task — retry-on-failure is the platform bridge's
/// responsibility).
pub type OneOffTaskHandler =
    dyn Fn(&OneOffTask, &TaskConstraints) -> Result<(), Error> + Send + Sync;

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
            one_offs: Mutex::new(Vec::new()),
            one_off_handler: Mutex::new(None),
        }
    }

    /// Phase 7 (2026-05-04 batch 10) — Task 9: install the
    /// one-off task handler. The orchestration layer wires
    /// `CoreImpl::execute_media_migration` /
    /// `CoreImpl::warm_shard_cache` through this hook.
    pub fn set_one_off_handler<F>(&self, handler: F)
    where
        F: Fn(&OneOffTask, &TaskConstraints) -> Result<(), Error> + Send + Sync + 'static,
    {
        if let Ok(mut h) = self.one_off_handler.lock() {
            *h = Some(Arc::new(handler));
        }
    }

    /// Phase 7 (2026-05-04 batch 10) — Task 9: number of one-off
    /// tasks currently waiting in the queue.
    pub fn pending_one_off_count(&self) -> usize {
        self.one_offs.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Phase 7 (2026-05-04 batch 10) — Task 9: drain every
    /// queued one-off task whose constraints are satisfied
    /// against `probe`, invoke the registered handler, and
    /// return the number of tasks executed. Tasks whose
    /// constraints are *not* met stay in the queue.
    ///
    /// `probe` reports the current device state. The scheduler
    /// uses it to decide whether each task's
    /// [`TaskConstraints::require_wifi`] /
    /// [`TaskConstraints::require_charging`] /
    /// [`TaskConstraints::require_idle`] are satisfied.
    pub fn run_pending_one_off_tasks<P: ResourceProbe>(&self, probe: &P) -> Result<usize, Error> {
        let handler = match self.one_off_handler.lock() {
            Ok(g) => g.as_ref().map(Arc::clone),
            Err(_) => return Err(Error::Storage("scheduler mutex poisoned".into())),
        };
        let drained: Vec<(OneOffTask, TaskConstraints)> = {
            let mut q = self
                .one_offs
                .lock()
                .map_err(|_| Error::Storage("scheduler mutex poisoned".into()))?;
            // Partition: keep the deferred tasks, drain the
            // ready ones.
            let (ready, deferred): (Vec<_>, Vec<_>) =
                q.drain(..).partition(|(_, c)| probe.satisfies(c));
            *q = deferred;
            ready
        };
        let count = drained.len();
        if let Some(h) = handler {
            for (task, constraints) in &drained {
                // Errors from one task don't poison the rest of
                // the drain.
                let _ = h(task, constraints);
            }
        }
        Ok(count)
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
        // Hold the workers lock for the entire spawn — dedup
        // check, thread spawn, and handle insert happen
        // atomically so two concurrent
        // `schedule_*` callers cannot both pass the dedup
        // check, both spawn worker threads, and have one
        // overwrite the other in `workers.insert` (which would
        // orphan the first worker because its shutdown
        // state Arc would no longer be reachable from
        // `cancel_all`).
        //
        // We acquire the handlers lock first to avoid any
        // possibility of a `cancel_all` ↔ `spawn_worker`
        // deadlock — `cancel_all` only ever takes the
        // workers lock, never handlers.
        let handler = self
            .handlers
            .lock()
            .map_err(|_| Error::Storage("scheduler handler mutex poisoned".into()))?
            .get(&task)
            .cloned();

        let mut workers = self
            .workers
            .lock()
            .map_err(|_| Error::Storage("scheduler worker mutex poisoned".into()))?;

        // Deduplication: if a worker for this task type is
        // already alive, succeed without spawning a duplicate.
        if workers.contains_key(&task) {
            return Ok(());
        }

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

    fn schedule_one_off_task(
        &self,
        task: OneOffTask,
        constraints: TaskConstraints,
    ) -> Result<(), Error> {
        let mut q = self
            .one_offs
            .lock()
            .map_err(|_| Error::Storage("scheduler mutex poisoned".into()))?;
        q.push((task, constraints));
        Ok(())
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

    /// Regression for the dedup TOCTOU race: two threads racing
    /// on the same `TaskType` must not both spawn a worker and
    /// have one overwrite the other in `workers.insert`. After
    /// the contention settles, exactly one worker must be
    /// alive and `cancel_all` must reach it (no orphans).
    #[test]
    fn schedule_dedup_is_atomic_under_concurrent_callers() {
        use std::sync::Barrier;

        for _ in 0..20 {
            let s = Arc::new(InProcessScheduler::new());
            let (counter, handler) = counting_handler();
            s.set_handler(TaskType::IncrementalBackup, handler);

            // Force every spawned thread to call `schedule_backup`
            // at the same instant — this is what tickled the
            // original TOCTOU between the dedup check and the
            // insert.
            let n_callers = 8usize;
            let barrier = Arc::new(Barrier::new(n_callers));
            let mut handles = Vec::with_capacity(n_callers);
            for _ in 0..n_callers {
                let s = Arc::clone(&s);
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    s.schedule_backup(20).expect("schedule");
                }));
            }
            for h in handles {
                h.join().expect("join caller");
            }

            assert!(s.is_task_pending_kind(TaskType::IncrementalBackup));

            // Wait for at least one tick so we know the surviving
            // worker is actually wired to the counter.
            wait_for_at_least(&counter, 1, Duration::from_secs(1));

            // Cancel and confirm the counter stops advancing.
            // If a duplicate worker had been orphaned by a
            // race, this assertion would flake — the orphan
            // would keep ticking after cancel.
            s.cancel_all().expect("cancel_all");
            let snapshot = counter.load(Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(60));
            let later = counter.load(Ordering::SeqCst);
            assert_eq!(
                snapshot, later,
                "cancel_all must reach every spawned worker — no orphans",
            );
        }
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

    // ---------------------------------------------------------
    // Phase 7 (2026-05-04 batch 10) — Task 9 one-off scheduling.
    // ---------------------------------------------------------

    use super::super::{MediaMigrationPlanSnapshot, OneOffTask, TaskConstraints};

    fn fake_migration_task() -> OneOffTask {
        OneOffTask::MediaMigration {
            plan: MediaMigrationPlanSnapshot {
                source_sink: "kchat_backend".into(),
                target_sink: "zk_object_fabric".into(),
                item_count: 4,
            },
        }
    }

    #[test]
    fn schedule_one_off_task_enqueues_into_pending_queue() {
        let s = InProcessScheduler::new();
        assert_eq!(s.pending_one_off_count(), 0);
        s.schedule_one_off_task(fake_migration_task(), TaskConstraints::wifi_and_charging())
            .unwrap();
        assert_eq!(s.pending_one_off_count(), 1);
    }

    #[test]
    fn run_pending_one_off_tasks_executes_and_drains_when_constraints_met() {
        let s = InProcessScheduler::new();
        let runs = Arc::new(AtomicU32::new(0));
        let r = Arc::clone(&runs);
        s.set_one_off_handler(move |_task, _c| {
            r.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        s.schedule_one_off_task(fake_migration_task(), TaskConstraints::wifi_and_charging())
            .unwrap();
        let n = s
            .run_pending_one_off_tasks(&StaticResourceProbe::all_available())
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(s.pending_one_off_count(), 0);
    }

    #[test]
    fn run_pending_one_off_tasks_respects_wifi_constraint() {
        let s = InProcessScheduler::new();
        let runs = Arc::new(AtomicU32::new(0));
        let r = Arc::clone(&runs);
        s.set_one_off_handler(move |_t, _c| {
            r.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        s.schedule_one_off_task(fake_migration_task(), TaskConstraints::wifi_and_charging())
            .unwrap();
        // No Wi-Fi → task must remain queued.
        let probe = StaticResourceProbe {
            has_wifi: false,
            is_charging: true,
            is_idle: false,
        };
        let n = s.run_pending_one_off_tasks(&probe).unwrap();
        assert_eq!(n, 0);
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        assert_eq!(s.pending_one_off_count(), 1);
    }

    #[test]
    fn run_pending_one_off_tasks_respects_charging_constraint() {
        let s = InProcessScheduler::new();
        s.set_one_off_handler(|_t, _c| Ok(()));
        s.schedule_one_off_task(fake_migration_task(), TaskConstraints::wifi_and_charging())
            .unwrap();
        let probe = StaticResourceProbe {
            has_wifi: true,
            is_charging: false,
            is_idle: false,
        };
        let n = s.run_pending_one_off_tasks(&probe).unwrap();
        assert_eq!(n, 0);
        assert_eq!(s.pending_one_off_count(), 1);
    }

    #[test]
    fn task_constraints_default_is_unrestrictive() {
        let c = TaskConstraints::default();
        assert!(!c.require_wifi);
        assert!(!c.require_charging);
        assert!(!c.require_idle);
        assert_eq!(c.max_retry_count, 3);
        // Even an empty probe satisfies the default.
        assert!(StaticResourceProbe::none_available().satisfies(&c));
    }
}
