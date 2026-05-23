//! Lightweight performance-tracing helpers.
//!
//! Cross-platform performance profiling and optimization data is
//! gathered through this module's Rust-side scaffold:
//!
//! * [`PerfTrace`] — one start/end span with a free-form
//!   metadata bag (typically things like `messages = "10000"`,
//!   `results = "37"`, `freed_bytes = "1048576"`).
//! * [`PerfCollector`] — object-safe + `Send + Sync` sink trait
//!   the orchestration layer fans into. Implementations supply
//!   the actual buffering / aggregation strategy.
//! * [`NoopPerfCollector`] — discards every trace; the default
//!   when no collector is installed.
//! * [`InMemoryPerfCollector`] — buffers traces in a
//!   `Mutex<Vec<PerfTrace>>` so tests can assert against the
//!   recorded sequence.
//!
//! Hot paths in [`crate::core_impl::CoreImpl`] (`ingest_messages`,
//! `search`, `run_incremental_backup`, `enforce_storage_budget`)
//! emit traces via [`crate::core_impl::CoreImpl::install_perf_collector`].
//! When no collector is installed the instrumentation is a
//! single un-taken atomic load — the instrumentation is cheap
//! enough to leave on in production.
//!
//! `start_ns` / `end_ns` are wall-clock nanoseconds since
//! [`std::time::SystemTime::UNIX_EPOCH`]; the values are NOT
//! intended to be cross-device-comparable (different clocks,
//! different leap-second handling) — they exist purely to
//! reconstruct the local span the caller cares about.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// One start/end span recorded by an instrumented hot path.
///
/// Construct via [`PerfTrace::new`] (records `start_ns` from the
/// system clock) and finish with [`PerfTrace::finish`] (records
/// `end_ns` and any tail metadata) right before passing it into
/// [`PerfCollector::record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfTrace {
    /// Operation name (e.g. `"ingest_messages"`,
    /// `"search"`, `"run_incremental_backup"`,
    /// `"enforce_storage_budget"`).
    pub operation: String,
    /// Start of the span — nanoseconds since UNIX epoch.
    pub start_ns: u64,
    /// End of the span — nanoseconds since UNIX epoch.
    /// Equal to `start_ns` until [`PerfTrace::finish`] is
    /// called.
    pub end_ns: u64,
    /// Free-form key/value metadata (e.g.
    /// `{"messages": "10000"}` for `ingest_messages`,
    /// `{"results": "37"}` for `search`).
    pub metadata: HashMap<String, String>,
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl PerfTrace {
    /// Open a new span with the supplied operation name. The
    /// `start_ns` field is captured immediately; `end_ns`
    /// matches `start_ns` until [`Self::finish`] is called.
    pub fn new(operation: impl Into<String>) -> Self {
        let start = now_ns();
        Self {
            operation: operation.into(),
            start_ns: start,
            end_ns: start,
            metadata: HashMap::new(),
        }
    }

    /// Add one metadata key/value pair to the span.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Insert one metadata key/value pair in place.
    pub fn insert_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Close the span by snapshotting the current wall-clock
    /// time into `end_ns`. Idempotent — calling `finish` again
    /// just bumps `end_ns` to the new wall-clock time.
    pub fn finish(&mut self) {
        self.end_ns = now_ns();
    }

    /// Wall-clock duration of the span in nanoseconds. Returns
    /// 0 when the span has not been finished or when the system
    /// clock went backwards.
    pub fn duration_ns(&self) -> u64 {
        self.end_ns.saturating_sub(self.start_ns)
    }
}

/// Object-safe + `Send + Sync` sink for [`PerfTrace`] records.
///
/// Implementations decide whether to buffer, aggregate,
/// stream-export, or discard incoming traces. The
/// [`Self::snapshot`] method exposes the buffered set for
/// [`crate::core_impl::CoreImpl::collect_perf_stats`]; collectors
/// that do not buffer (e.g. [`NoopPerfCollector`]) MAY return
/// the empty vector.
pub trait PerfCollector: std::fmt::Debug + Send + Sync {
    /// Record one [`PerfTrace`].
    fn record(&self, trace: PerfTrace);

    /// Return a copy of every trace seen by this collector
    /// since construction. Default: empty vector.
    fn snapshot(&self) -> Vec<PerfTrace> {
        Vec::new()
    }
}

/// [`PerfCollector`] that discards every trace.
///
/// The default behavior when no collector is installed
/// instrumentation paths that pass traces into a noop collector
/// pay only the `record` call cost.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPerfCollector;

impl PerfCollector for NoopPerfCollector {
    fn record(&self, _trace: PerfTrace) {
        // intentionally empty
    }
}

/// [`PerfCollector`] that buffers every trace in a
/// `Mutex<Vec<PerfTrace>>`.
///
/// Used by the unit / integration tests to assert
/// against the recorded sequence. Production callers SHOULD
/// install a collector that streams traces into the platform's
/// real telemetry sink instead of leaking memory.
#[derive(Debug, Default)]
pub struct InMemoryPerfCollector {
    buffer: Mutex<Vec<PerfTrace>>,
}

impl InMemoryPerfCollector {
    /// Construct a fresh, empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain every buffered trace, leaving the collector empty.
    pub fn drain(&self) -> Vec<PerfTrace> {
        match self.buffer.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(_) => Vec::new(),
        }
    }
}

impl PerfCollector for InMemoryPerfCollector {
    fn record(&self, trace: PerfTrace) {
        if let Ok(mut guard) = self.buffer.lock() {
            guard.push(trace);
        }
    }

    fn snapshot(&self) -> Vec<PerfTrace> {
        match self.buffer.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }
}

/// aggregated summary over a
/// set of [`PerfTrace`]s for a single operation.
///
/// Percentiles are computed via the nearest-rank method with a
/// 1-based index — for `count = 100` traces, `p95_ns` is the
/// 95th-smallest duration. This matches the convention used
/// downstream in `docs/DESIGN.md §7.5` and the criterion
/// benchmarks under `crates/core/benches/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfSummary {
    /// Operation name (`PerfTrace::operation`).
    pub operation: String,
    /// Number of traces aggregated.
    pub count: usize,
    /// 50th percentile duration in nanoseconds.
    pub p50_ns: u64,
    /// 95th percentile duration in nanoseconds.
    pub p95_ns: u64,
    /// 99th percentile duration in nanoseconds.
    pub p99_ns: u64,
    /// Slowest single duration in nanoseconds.
    pub max_ns: u64,
    /// Total duration in nanoseconds (sum of every span). Useful
    /// for back-of-envelope "% of wall-clock" plots.
    pub total_ns: u64,
}

/// per-operation p95 budget.
///
/// Plug into [`check_budgets`] alongside a `Vec<PerfSummary>`
/// to detect operations whose measured p95 exceeds the
/// configured ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfBudget {
    /// Operation name to match against
    /// [`PerfSummary::operation`].
    pub operation: String,
    /// Maximum allowed p95 duration in nanoseconds.
    pub p95_budget_ns: u64,
}

impl PerfBudget {
    /// Convenience constructor.
    pub fn new(operation: impl Into<String>, p95_budget_ns: u64) -> Self {
        Self {
            operation: operation.into(),
            p95_budget_ns,
        }
    }
}

/// One detected violation: the named operation's p95 exceeds
/// the configured budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetViolation {
    /// Operation that exceeded its budget.
    pub operation: String,
    /// Measured p95 duration in nanoseconds.
    pub measured_p95_ns: u64,
    /// Configured p95 budget in nanoseconds.
    pub budget_p95_ns: u64,
}

impl BudgetViolation {
    /// `measured - budget` (saturating). Useful for "how much
    /// over budget were we" plots.
    pub fn overshoot_ns(&self) -> u64 {
        self.measured_p95_ns.saturating_sub(self.budget_p95_ns)
    }
}

/// Compute the nearest-rank percentile for `pct` ∈ `[0, 100]`
/// from a sorted slice of durations.
fn nearest_rank_percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let n = sorted.len();
    // Nearest-rank with a 1-based index. `idx` is the 1-based
    // position of the percentile; we clamp into `[1, n]` and
    // subtract 1 to convert to a 0-based slice index.
    let idx = ((pct / 100.0) * n as f64).ceil() as usize;
    let idx = idx.clamp(1, n) - 1;
    sorted[idx]
}

/// Build a [`PerfSummary`] from the supplied trace vector. The
/// caller is responsible for filtering to a single
/// `operation` — the summary just blindly aggregates whatever
/// it is handed.
pub fn summarize_traces(operation: &str, traces: &[PerfTrace]) -> Option<PerfSummary> {
    if traces.is_empty() {
        return None;
    }
    let mut durations: Vec<u64> = traces.iter().map(|t| t.duration_ns()).collect();
    durations.sort_unstable();
    let total_ns: u64 = durations
        .iter()
        .copied()
        .fold(0u64, |a, b| a.saturating_add(b));
    let p50 = nearest_rank_percentile(&durations, 50.0);
    let p95 = nearest_rank_percentile(&durations, 95.0);
    let p99 = nearest_rank_percentile(&durations, 99.0);
    let max_ns = *durations.last().unwrap_or(&0);
    Some(PerfSummary {
        operation: operation.to_string(),
        count: traces.len(),
        p50_ns: p50,
        p95_ns: p95,
        p99_ns: p99,
        max_ns,
        total_ns,
    })
}

impl InMemoryPerfCollector {
    /// Compute one [`PerfSummary`] per distinct operation seen
    /// by this collector. Operations with zero traces are
    /// skipped. Output is sorted by operation name for stable
    /// comparison in tests.
    pub fn summarize(&self) -> Vec<PerfSummary> {
        use std::collections::BTreeMap;
        let snap = self.snapshot();
        let mut grouped: BTreeMap<String, Vec<PerfTrace>> = BTreeMap::new();
        for t in snap {
            grouped.entry(t.operation.clone()).or_default().push(t);
        }
        grouped
            .into_iter()
            .filter_map(|(op, traces)| summarize_traces(&op, &traces))
            .collect()
    }

    /// Compute the [`PerfSummary`] for a specific operation, if
    /// any traces have been recorded for it.
    pub fn summarize_operation(&self, op: &str) -> Option<PerfSummary> {
        let snap = self.snapshot();
        let filtered: Vec<PerfTrace> = snap.into_iter().filter(|t| t.operation == op).collect();
        summarize_traces(op, &filtered)
    }
}

/// Compare [`PerfSummary`]s against [`PerfBudget`]s and return
/// every operation whose measured p95 exceeds its budget. A
/// summary with no matching budget is skipped (no opinion); a
/// budget with no matching summary is also skipped (the
/// operation simply has not been exercised yet).
pub fn check_budgets(summaries: &[PerfSummary], budgets: &[PerfBudget]) -> Vec<BudgetViolation> {
    let mut out: Vec<BudgetViolation> = Vec::new();
    for b in budgets {
        for s in summaries {
            if s.operation != b.operation {
                continue;
            }
            if s.p95_ns > b.p95_budget_ns {
                out.push(BudgetViolation {
                    operation: s.operation.clone(),
                    measured_p95_ns: s.p95_ns,
                    budget_p95_ns: b.p95_budget_ns,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perf_trace_finish_advances_end_ns() {
        let mut t = PerfTrace::new("op");
        let s = t.start_ns;
        // The system clock may not advance between two calls
        // on a fast machine, so just assert end_ns >= start_ns
        // post-finish.
        t.finish();
        assert!(t.end_ns >= s);
        assert_eq!(t.duration_ns(), t.end_ns - s);
    }

    #[test]
    fn perf_trace_metadata_round_trip() {
        let t = PerfTrace::new("op")
            .with_metadata("messages", "10")
            .with_metadata("results", "3");
        assert_eq!(t.metadata.get("messages").map(String::as_str), Some("10"));
        assert_eq!(t.metadata.get("results").map(String::as_str), Some("3"));
    }

    #[test]
    fn noop_perf_collector_does_not_error() {
        let c = NoopPerfCollector;
        let mut t = PerfTrace::new("op");
        t.finish();
        c.record(t);
        assert!(c.snapshot().is_empty());
    }

    #[test]
    fn in_memory_perf_collector_round_trip() {
        let c = InMemoryPerfCollector::new();
        let mut a = PerfTrace::new("ingest");
        a.insert_metadata("messages", "5");
        a.finish();
        let mut b = PerfTrace::new("search");
        b.insert_metadata("results", "2");
        b.finish();
        c.record(a.clone());
        c.record(b.clone());
        let snap = c.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].operation, "ingest");
        assert_eq!(snap[1].operation, "search");
        // Drain empties the buffer.
        let drained = c.drain();
        assert_eq!(drained.len(), 2);
        assert!(c.snapshot().is_empty());
    }

    #[test]
    fn perf_collector_trait_is_object_safe() {
        let c = InMemoryPerfCollector::new();
        let dynref: &dyn PerfCollector = &c;
        let mut t = PerfTrace::new("op");
        t.finish();
        dynref.record(t);
        assert_eq!(dynref.snapshot().len(), 1);
    }

    /// Build a synthetic trace with a fixed duration in
    /// nanoseconds. Bypasses the wall-clock to keep the
    /// percentile assertions deterministic.
    fn synthetic_trace(op: &str, duration_ns: u64) -> PerfTrace {
        PerfTrace {
            operation: op.to_string(),
            start_ns: 0,
            end_ns: duration_ns,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn perf_summary_empty_returns_none() {
        let c = InMemoryPerfCollector::new();
        assert!(c.summarize().is_empty());
        assert!(c.summarize_operation("nope").is_none());
        assert!(summarize_traces("nope", &[]).is_none());
    }

    #[test]
    fn perf_summary_computes_correct_p95() {
        let c = InMemoryPerfCollector::new();
        // 100 traces with durations 1..=100 ns. With
        // nearest-rank, p95 = 95th-smallest = 95 ns.
        for i in 1..=100u64 {
            c.record(synthetic_trace("op", i));
        }
        let s = c.summarize_operation("op").expect("100 traces summarize");
        assert_eq!(s.count, 100);
        assert_eq!(s.p50_ns, 50);
        assert_eq!(s.p95_ns, 95);
        assert_eq!(s.p99_ns, 99);
        assert_eq!(s.max_ns, 100);
        assert_eq!(s.total_ns, (1..=100u64).sum::<u64>());
    }

    #[test]
    fn perf_summary_groups_by_operation() {
        let c = InMemoryPerfCollector::new();
        c.record(synthetic_trace("ingest", 10));
        c.record(synthetic_trace("ingest", 20));
        c.record(synthetic_trace("search", 100));
        let summaries = c.summarize();
        assert_eq!(summaries.len(), 2);
        // BTreeMap iteration → sorted by op name.
        assert_eq!(summaries[0].operation, "ingest");
        assert_eq!(summaries[0].count, 2);
        assert_eq!(summaries[1].operation, "search");
        assert_eq!(summaries[1].count, 1);
    }

    #[test]
    fn perf_summary_single_trace() {
        let c = InMemoryPerfCollector::new();
        c.record(synthetic_trace("solo", 42));
        let s = c.summarize_operation("solo").unwrap();
        assert_eq!(s.p50_ns, 42);
        assert_eq!(s.p95_ns, 42);
        assert_eq!(s.p99_ns, 42);
        assert_eq!(s.max_ns, 42);
        assert_eq!(s.total_ns, 42);
    }

    #[test]
    fn perf_budget_violation_detected() {
        let c = InMemoryPerfCollector::new();
        for i in 1..=100u64 {
            c.record(synthetic_trace("hot_path", i * 1_000_000));
        }
        let summaries = c.summarize();
        let budgets = vec![PerfBudget::new("hot_path", 50_000_000)];
        let violations = check_budgets(&summaries, &budgets);
        assert_eq!(violations.len(), 1);
        let v = &violations[0];
        assert_eq!(v.operation, "hot_path");
        assert_eq!(v.measured_p95_ns, 95_000_000);
        assert_eq!(v.budget_p95_ns, 50_000_000);
        assert_eq!(v.overshoot_ns(), 45_000_000);
    }

    #[test]
    fn perf_budget_all_pass() {
        let c = InMemoryPerfCollector::new();
        for i in 1..=10u64 {
            c.record(synthetic_trace("fast", i));
        }
        let summaries = c.summarize();
        let budgets = vec![PerfBudget::new("fast", 1_000_000)];
        let violations = check_budgets(&summaries, &budgets);
        assert!(violations.is_empty());
    }

    #[test]
    fn perf_budget_no_match_skipped() {
        // Operation "alpha" has summaries; "beta" has a
        // budget but no traces. No violations.
        let c = InMemoryPerfCollector::new();
        c.record(synthetic_trace("alpha", 100));
        let summaries = c.summarize();
        let budgets = vec![PerfBudget::new("beta", 1)];
        assert!(check_budgets(&summaries, &budgets).is_empty());
    }
}
