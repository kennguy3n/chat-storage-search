//! Lightweight performance-tracing helpers — Phase 7, Task 8 of
//! the 2026-05-04 batch.
//!
//! `docs/PHASES.md` Phase 7 calls for "performance profiling and
//! optimization" as a gating item. This module lands the
//! Rust-side scaffold:
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
/// The default behavior when no collector is installed —
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
/// Used by the Phase 7 unit / integration tests to assert
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
}
