//! Read-only dedup analytics integration with `kennguy3n/zk-object-fabric`'s
//! ContentIndex (Phase 7, batch-5 — 2026-05-04).
//!
//! `docs/PHASES.md` Phase 7 calls for "dedup analytics integration
//! with `kennguy3n/zk-object-fabric`'s ContentIndex metrics
//! (read-only telemetry, no plaintext leaks)". This module lands
//! the trait surface and the `Noop` placeholder.
//!
//! ## Privacy contract
//!
//! The trait surface is deliberately **opaque-ciphertext-only**:
//!
//! * The probe takes a `tenant_id` opaque string — it MUST be a
//!   server-side tenant identifier the upstream ContentIndex
//!   already knows about. The probe MUST NOT receive plaintext
//!   from the local store, derived plaintext (FTS5 tokens,
//!   embedding vectors), or media bytes.
//! * The returned [`DedupStats`] / [`StorageSavings`] are
//!   ciphertext-side aggregates: object counts, byte counts, and
//!   millisecond timestamps. The struct intentionally does **not**
//!   expose per-object identifiers, sample object hashes, or any
//!   field that could side-channel local plaintext through the
//!   transport boundary.
//! * Implementations are read-only: the trait has no `record_*`
//!   or `set_*` method. The local core never writes to the
//!   ContentIndex through this surface.
//!
//! ## Object safety
//!
//! [`DedupAnalytics`] is `Send + Sync + std::fmt::Debug` and uses
//! only object-safe method shapes (no generics, no `Self`-returning
//! methods) so the orchestration layer can hold an
//! `Arc<dyn DedupAnalytics>` and dispatch from any worker.

use serde::{Deserialize, Serialize};

use crate::Result;

/// Aggregate dedup ratio for one tenant, as reported by the
/// upstream ContentIndex.
///
/// All counts are **ciphertext-side** — the ContentIndex sees only
/// opaque, convergently-encrypted blobs. `dedup_ratio_percent` is
/// `(1.0 - unique_bytes / total_bytes) * 100`, clamped into
/// `[0.0, 100.0]`. A tenant with `total_bytes == 0` returns
/// `dedup_ratio_percent == 0.0` (rather than NaN) so callers can
/// safely sort / display the value without special-casing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DedupStats {
    /// Total number of object references the tenant has uploaded
    /// (counting duplicates).
    pub total_objects: u64,
    /// Number of distinct object hashes the tenant's references
    /// resolved to (i.e. after dedup).
    pub unique_objects: u64,
    /// `(1.0 - unique_bytes / total_bytes) * 100`, clamped into
    /// `[0.0, 100.0]`.
    pub dedup_ratio_percent: f64,
    /// Sum of plaintext-equivalent byte lengths across every
    /// object reference (counting duplicates).
    pub total_bytes: u64,
    /// Sum of plaintext-equivalent byte lengths across the
    /// distinct object hashes (i.e. after dedup).
    pub unique_bytes: u64,
}

/// Storage-side savings for one tenant, computed by the upstream
/// ContentIndex as the delta between `total_bytes` and
/// `unique_bytes`.
///
/// `bytes_saved == total_bytes - unique_bytes`;
/// `objects_deduped == total_objects - unique_objects`.
/// `last_updated_ms` is the ContentIndex-side wall-clock millisecond
/// the snapshot was computed; the local core MUST NOT use it as a
/// security-critical timestamp.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct StorageSavings {
    /// `total_bytes - unique_bytes`. `0` when the tenant is below
    /// the ContentIndex's snapshot window.
    pub bytes_saved: u64,
    /// `total_objects - unique_objects`. `0` when the tenant is
    /// below the ContentIndex's snapshot window.
    pub objects_deduped: u64,
    /// Wall-clock millisecond timestamp of the upstream snapshot.
    pub last_updated_ms: i64,
}

impl DedupStats {
    /// Helper: derive a `DedupStats` from raw `(total, unique,
    /// total_bytes, unique_bytes)` counters. Computes the
    /// `dedup_ratio_percent` field defensively (NaN- and
    /// zero-division-safe). Production implementations may
    /// short-circuit and populate the fields directly.
    pub fn from_counts(
        total_objects: u64,
        unique_objects: u64,
        total_bytes: u64,
        unique_bytes: u64,
    ) -> Self {
        let dedup_ratio_percent = if total_bytes == 0 {
            0.0
        } else {
            let ratio = 1.0 - (unique_bytes as f64 / total_bytes as f64);
            (ratio.clamp(0.0, 1.0)) * 100.0
        };
        Self {
            total_objects,
            unique_objects,
            dedup_ratio_percent,
            total_bytes,
            unique_bytes,
        }
    }
}

impl StorageSavings {
    /// Helper: derive a `StorageSavings` from raw counts. Saturating
    /// subtraction is used so a momentarily inconsistent snapshot
    /// (where `unique > total` due to in-flight deletes) returns
    /// `0` rather than panicking on underflow.
    pub fn from_counts(
        total_objects: u64,
        unique_objects: u64,
        total_bytes: u64,
        unique_bytes: u64,
        last_updated_ms: i64,
    ) -> Self {
        Self {
            bytes_saved: total_bytes.saturating_sub(unique_bytes),
            objects_deduped: total_objects.saturating_sub(unique_objects),
            last_updated_ms,
        }
    }
}

/// One dedup-related event captured at the ZKOF sink boundary.
/// Phase 7 (2026-05-04 batch 10 — Task 10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupEvent {
    /// An object was uploaded to the ZK Object Fabric. When
    /// `was_deduped` is `true`, Pattern C convergent encryption
    /// short-circuited the upload (the object hash already
    /// existed in the ContentIndex). When `false`, the upload
    /// added a new unique object.
    ObjectUploaded {
        /// Plaintext-equivalent byte length of the uploaded
        /// object.
        size_bytes: u64,
        /// `true` → Pattern C cache hit (no new bytes uploaded).
        was_deduped: bool,
    },
    /// An object reference was deleted. `size_bytes` is the
    /// plaintext-equivalent byte length of the reference (not
    /// the underlying unique object — multiple references can
    /// share the same unique blob).
    ObjectDeleted {
        /// Plaintext-equivalent byte length of the deleted
        /// reference.
        size_bytes: u64,
    },
}

impl DedupEvent {
    /// Plaintext-equivalent byte length of the event regardless
    /// of variant. Used by the dashboard to aggregate uploads
    /// and deletes into a single bytes-touched figure.
    pub fn size_bytes(&self) -> u64 {
        match self {
            Self::ObjectUploaded { size_bytes, .. } => *size_bytes,
            Self::ObjectDeleted { size_bytes } => *size_bytes,
        }
    }
}

/// One frame of the dedup dashboard surfaced through
/// [`crate::core_impl::CoreImpl::get_dedup_dashboard`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DedupDashboard {
    /// Server-side dedup snapshot.
    pub stats: DedupStats,
    /// Server-side savings snapshot.
    pub savings: StorageSavings,
    /// Most recent `DedupEvent` records the local probe captured
    /// (capped at the probe's configured ring size).
    pub recent_events: Vec<DedupEvent>,
}

/// Read-only telemetry probe for the upstream ZK Object Fabric
/// ContentIndex.
///
/// **Object-safe**, `Send + Sync`, `Debug`. The trait is designed
/// so callers can hold an `Arc<dyn DedupAnalytics>` and dispatch
/// from any worker. See module docs for the privacy contract.
pub trait DedupAnalytics: Send + Sync + std::fmt::Debug {
    /// Read the current dedup ratio for the supplied tenant.
    ///
    /// `tenant_id` MUST be a server-side tenant identifier the
    /// upstream ContentIndex recognizes. The probe MUST NOT
    /// receive plaintext, FTS tokens, embedding vectors, or media
    /// bytes from the local store.
    fn query_dedup_ratio(&self, tenant_id: &str) -> Result<DedupStats>;

    /// Read the cumulative storage savings for the supplied
    /// tenant. Same privacy contract as
    /// [`Self::query_dedup_ratio`].
    fn query_storage_savings(&self, tenant_id: &str) -> Result<StorageSavings>;

    /// Phase 7 (2026-05-04 batch 10 — Task 10): record one
    /// dedup-related event. The default implementation no-ops so
    /// existing probes (notably [`NoopDedupAnalytics`]) keep
    /// compiling. The [`InProcessDedupAnalytics`] /
    /// [`ZkofDedupAnalytics`] implementations override this to
    /// store the event in their ring buffer.
    fn record_event(&self, _event: DedupEvent) -> Result<()> {
        Ok(())
    }

    /// Snapshot of the events most recently passed to
    /// [`Self::record_event`]. Default impl returns an empty
    /// vec so callers can safely consume the surface even when
    /// no probe is installed.
    fn recent_events(&self) -> Vec<DedupEvent> {
        Vec::new()
    }
}

/// `DedupAnalytics` placeholder used before any production probe
/// lands. Every method returns
/// [`crate::Error::NotImplemented("dedup_analytics")`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDedupAnalytics;

impl NoopDedupAnalytics {
    /// `const fn` constructor so callers can build the placeholder
    /// in `static` contexts.
    pub const fn new() -> Self {
        Self
    }
}

impl DedupAnalytics for NoopDedupAnalytics {
    fn query_dedup_ratio(&self, _tenant_id: &str) -> Result<DedupStats> {
        Err(crate::Error::NotImplemented("dedup_analytics"))
    }

    fn query_storage_savings(&self, _tenant_id: &str) -> Result<StorageSavings> {
        Err(crate::Error::NotImplemented("dedup_analytics"))
    }
}

/// Test-only fixed-stats probe — returns the supplied snapshot for
/// every tenant. Useful for end-to-end tests that need the
/// `CoreImpl` orchestration to receive a deterministic
/// [`DedupStats`] without standing up a real ZKOF backend.
#[derive(Debug, Clone)]
pub struct FixedDedupAnalytics {
    stats: DedupStats,
    savings: StorageSavings,
}

impl FixedDedupAnalytics {
    /// Build a fixed probe seeded with the supplied stats /
    /// savings snapshot.
    pub fn new(stats: DedupStats, savings: StorageSavings) -> Self {
        Self { stats, savings }
    }
}

impl DedupAnalytics for FixedDedupAnalytics {
    fn query_dedup_ratio(&self, _tenant_id: &str) -> Result<DedupStats> {
        Ok(self.stats.clone())
    }

    fn query_storage_savings(&self, _tenant_id: &str) -> Result<StorageSavings> {
        Ok(self.savings.clone())
    }
}

/// Phase 7 (2026-05-04 batch 10 — Task 10) — in-process probe
/// that aggregates [`DedupEvent`] records emitted by the backup
/// and media sinks into a [`DedupStats`] / [`StorageSavings`]
/// snapshot.
///
/// `query_dedup_ratio` / `query_storage_savings` derive their
/// counts from the recorded events, so this probe never reaches
/// out to the network. Production deployments swap this for a
/// `ZkofDedupAnalytics` that talks to the live ContentIndex; the
/// in-process probe is the production fallback when the
/// ContentIndex is unreachable.
#[derive(Debug)]
pub struct InProcessDedupAnalytics {
    inner: std::sync::Mutex<InProcessState>,
    /// Maximum number of recent events retained in the ring
    /// buffer. Defaults to 512.
    pub recent_capacity: usize,
}

impl Default for InProcessDedupAnalytics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct InProcessState {
    total_objects: u64,
    unique_objects: u64,
    total_bytes: u64,
    unique_bytes: u64,
    last_updated_ms: i64,
    recent: std::collections::VecDeque<DedupEvent>,
}

impl InProcessDedupAnalytics {
    /// Construct a fresh probe with the default ring-buffer
    /// capacity (512 events).
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(InProcessState::default()),
            recent_capacity: 512,
        }
    }

    /// Construct a probe with a custom ring-buffer capacity.
    pub fn with_capacity(recent_capacity: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(InProcessState::default()),
            recent_capacity: recent_capacity.max(1),
        }
    }
}

impl DedupAnalytics for InProcessDedupAnalytics {
    fn query_dedup_ratio(&self, _tenant_id: &str) -> Result<DedupStats> {
        let g = self
            .inner
            .lock()
            .map_err(|_| crate::Error::Storage("dedup analytics poisoned".into()))?;
        Ok(DedupStats::from_counts(
            g.total_objects,
            g.unique_objects,
            g.total_bytes,
            g.unique_bytes,
        ))
    }

    fn query_storage_savings(&self, _tenant_id: &str) -> Result<StorageSavings> {
        let g = self
            .inner
            .lock()
            .map_err(|_| crate::Error::Storage("dedup analytics poisoned".into()))?;
        Ok(StorageSavings::from_counts(
            g.total_objects,
            g.unique_objects,
            g.total_bytes,
            g.unique_bytes,
            g.last_updated_ms,
        ))
    }

    fn record_event(&self, event: DedupEvent) -> Result<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| crate::Error::Storage("dedup analytics poisoned".into()))?;
        match &event {
            DedupEvent::ObjectUploaded {
                size_bytes,
                was_deduped,
            } => {
                g.total_objects = g.total_objects.saturating_add(1);
                g.total_bytes = g.total_bytes.saturating_add(*size_bytes);
                if !was_deduped {
                    g.unique_objects = g.unique_objects.saturating_add(1);
                    g.unique_bytes = g.unique_bytes.saturating_add(*size_bytes);
                }
            }
            DedupEvent::ObjectDeleted { size_bytes } => {
                g.total_objects = g.total_objects.saturating_sub(1);
                g.total_bytes = g.total_bytes.saturating_sub(*size_bytes);
            }
        }
        if g.recent.len() >= self.recent_capacity {
            g.recent.pop_front();
        }
        g.recent.push_back(event);
        Ok(())
    }

    fn recent_events(&self) -> Vec<DedupEvent> {
        self.inner
            .lock()
            .map(|g| g.recent.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Phase 7 (2026-05-04 batch 10 — Task 10) — ZK Object Fabric
/// dedup-analytics probe that wraps a live `S3Client` and reads
/// the upstream `metadata/content_index/stats` snapshot.
///
/// The probe is layered on top of an [`InProcessDedupAnalytics`]
/// so it can surface the local recent-events ring even when the
/// ContentIndex is unreachable. `query_dedup_ratio` /
/// `query_storage_savings` first attempt to read the upstream
/// snapshot, then fall back to the in-process aggregate.
#[derive(Debug)]
pub struct ZkofDedupAnalytics {
    client: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client>,
    bucket: String,
    fallback: InProcessDedupAnalytics,
    /// Maximum byte length of the ContentIndex snapshot the
    /// probe is willing to fetch. Defaults to 64 KiB — large
    /// enough for any plausible JSON / CBOR snapshot.
    pub max_snapshot_bytes: u64,
}

impl ZkofDedupAnalytics {
    /// Construct a probe against the supplied ZKOF bucket.
    pub fn new(
        client: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client>,
        bucket: String,
    ) -> Self {
        Self {
            client,
            bucket,
            fallback: InProcessDedupAnalytics::new(),
            max_snapshot_bytes: 64 * 1024,
        }
    }

    /// ContentIndex snapshot key. Stored as a constant so the
    /// orchestration layer and the test harness agree on the
    /// upstream key shape.
    pub fn snapshot_key() -> &'static str {
        "metadata/content_index/stats"
    }

    fn parse_stats(bytes: &[u8]) -> Result<DedupStats> {
        let parsed: DedupStats = crate::cbor::from_slice(bytes)
            .map_err(|e| crate::Error::Storage(format!("dedup snapshot parse: {e}")))?;
        Ok(parsed)
    }

    fn fetch_snapshot(&self) -> Result<Vec<u8>> {
        self.client
            .get_object_range(
                &self.bucket,
                Self::snapshot_key(),
                0..self.max_snapshot_bytes,
            )
            .map_err(|e| crate::Error::Storage(format!("dedup snapshot fetch: {e}")))
    }
}

impl DedupAnalytics for ZkofDedupAnalytics {
    fn query_dedup_ratio(&self, tenant_id: &str) -> Result<DedupStats> {
        match self.fetch_snapshot() {
            Ok(bytes) => Self::parse_stats(&bytes),
            Err(_) => self.fallback.query_dedup_ratio(tenant_id),
        }
    }

    fn query_storage_savings(&self, tenant_id: &str) -> Result<StorageSavings> {
        match self.fetch_snapshot() {
            Ok(bytes) => {
                let stats = Self::parse_stats(&bytes)?;
                Ok(StorageSavings::from_counts(
                    stats.total_objects,
                    stats.unique_objects,
                    stats.total_bytes,
                    stats.unique_bytes,
                    0,
                ))
            }
            Err(_) => self.fallback.query_storage_savings(tenant_id),
        }
    }

    fn record_event(&self, event: DedupEvent) -> Result<()> {
        self.fallback.record_event(event)
    }

    fn recent_events(&self) -> Vec<DedupEvent> {
        self.fallback.recent_events()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn dedup_analytics_is_object_safe_through_arc_dyn() {
        // If this compiles the trait is object-safe.
        let probe: Arc<dyn DedupAnalytics> = Arc::new(NoopDedupAnalytics::new());
        let err = probe.query_dedup_ratio("tenant-1").unwrap_err();
        assert!(matches!(
            err,
            crate::Error::NotImplemented("dedup_analytics")
        ));
        let err2 = probe.query_storage_savings("tenant-1").unwrap_err();
        assert!(matches!(
            err2,
            crate::Error::NotImplemented("dedup_analytics")
        ));
    }

    #[test]
    fn dedup_stats_from_counts_handles_zero_total_safely() {
        let stats = DedupStats::from_counts(0, 0, 0, 0);
        assert_eq!(stats.total_objects, 0);
        assert_eq!(stats.unique_objects, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.unique_bytes, 0);
        assert_eq!(stats.dedup_ratio_percent, 0.0);
    }

    #[test]
    fn dedup_stats_from_counts_clamps_into_unit_interval_percent() {
        // 10 references, 4 distinct, 100 KiB total, 40 KiB unique →
        // 60% saved.
        let stats = DedupStats::from_counts(10, 4, 100_000, 40_000);
        assert_eq!(stats.total_objects, 10);
        assert_eq!(stats.unique_objects, 4);
        assert!((stats.dedup_ratio_percent - 60.0).abs() < 1e-6);
        // Defensive clamp: even an inconsistent snapshot can't
        // produce a negative ratio.
        let weird = DedupStats::from_counts(1, 5, 100, 500);
        assert_eq!(weird.dedup_ratio_percent, 0.0);
    }

    #[test]
    fn storage_savings_from_counts_saturates_on_inconsistent_snapshot() {
        // The ContentIndex may briefly show `unique > total` while
        // a delete is in flight. We must saturate to 0 rather than
        // panic on underflow.
        let savings = StorageSavings::from_counts(1, 5, 100, 500, 1_700_000_000_000);
        assert_eq!(savings.bytes_saved, 0);
        assert_eq!(savings.objects_deduped, 0);
        assert_eq!(savings.last_updated_ms, 1_700_000_000_000);
    }

    #[test]
    fn dedup_stats_round_trips_through_serde_json() {
        let stats = DedupStats::from_counts(10, 4, 1024, 256);
        let json = serde_json::to_string(&stats).unwrap();
        let back: DedupStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }

    #[test]
    fn storage_savings_round_trips_through_serde_json() {
        let savings = StorageSavings::from_counts(10, 4, 1024, 256, 1_700_000_000_000);
        let json = serde_json::to_string(&savings).unwrap();
        let back: StorageSavings = serde_json::from_str(&json).unwrap();
        assert_eq!(savings, back);
    }

    #[test]
    fn fixed_dedup_analytics_returns_seeded_snapshot() {
        let stats = DedupStats::from_counts(10, 4, 100, 40);
        let savings = StorageSavings::from_counts(10, 4, 100, 40, 1_700_000_000_000);
        let probe: Arc<dyn DedupAnalytics> =
            Arc::new(FixedDedupAnalytics::new(stats.clone(), savings.clone()));
        assert_eq!(probe.query_dedup_ratio("tenant-x").unwrap(), stats);
        assert_eq!(probe.query_storage_savings("tenant-x").unwrap(), savings);
    }

    // ----------------------------------------------------------------
    // Phase 7 (2026-05-04 batch 10) — Task 10 tests
    // ----------------------------------------------------------------

    #[test]
    fn noop_dedup_analytics_record_event_does_not_panic() {
        // The default `record_event` impl on the trait must be
        // a no-op for `NoopDedupAnalytics` — recording into a
        // probe that hasn't been wired up should never crash.
        let probe: Arc<dyn DedupAnalytics> = Arc::new(NoopDedupAnalytics::new());
        probe
            .record_event(DedupEvent::ObjectUploaded {
                size_bytes: 1024,
                was_deduped: false,
            })
            .expect("record_event noop");
        assert!(probe.recent_events().is_empty());
    }

    #[test]
    fn in_process_dedup_analytics_aggregates_uploads_and_deletes() {
        let probe = InProcessDedupAnalytics::new();
        probe
            .record_event(DedupEvent::ObjectUploaded {
                size_bytes: 100,
                was_deduped: false,
            })
            .unwrap();
        probe
            .record_event(DedupEvent::ObjectUploaded {
                size_bytes: 100,
                was_deduped: true,
            })
            .unwrap();
        probe
            .record_event(DedupEvent::ObjectUploaded {
                size_bytes: 50,
                was_deduped: false,
            })
            .unwrap();
        let stats = probe.query_dedup_ratio("tenant-1").unwrap();
        assert_eq!(stats.total_objects, 3);
        assert_eq!(stats.unique_objects, 2);
        assert_eq!(stats.total_bytes, 250);
        assert_eq!(stats.unique_bytes, 150);
        // 1 - 150/250 = 0.4 → 40%
        assert!((stats.dedup_ratio_percent - 40.0).abs() < 1e-6);

        let savings = probe.query_storage_savings("tenant-1").unwrap();
        assert_eq!(savings.bytes_saved, 100);
        assert_eq!(savings.objects_deduped, 1);
    }

    /// Regression for the BUG-0002 finding: `Default::default()`
    /// must produce the same recent-buffer behaviour as `new()`
    /// (capacity 512), not the broken `recent_capacity: 0` that
    /// the auto-derived `Default` produced.
    #[test]
    fn in_process_dedup_analytics_default_matches_new_capacity() {
        let probe = InProcessDedupAnalytics::default();
        assert_eq!(probe.recent_capacity, 512);
        // Record more than the (broken) capacity-0 ring would
        // hold but well under 512: every event must be retained.
        for size in 0u64..16 {
            probe
                .record_event(DedupEvent::ObjectUploaded {
                    size_bytes: size,
                    was_deduped: false,
                })
                .unwrap();
        }
        assert_eq!(probe.recent_events().len(), 16);
    }

    #[test]
    fn in_process_dedup_analytics_recent_events_capped_at_capacity() {
        let probe = InProcessDedupAnalytics::with_capacity(2);
        for size in [10, 20, 30] {
            probe
                .record_event(DedupEvent::ObjectUploaded {
                    size_bytes: size,
                    was_deduped: false,
                })
                .unwrap();
        }
        let recent = probe.recent_events();
        assert_eq!(recent.len(), 2);
        // Oldest event should have been evicted.
        assert!(matches!(
            recent[0],
            DedupEvent::ObjectUploaded { size_bytes: 20, .. }
        ));
        assert!(matches!(
            recent[1],
            DedupEvent::ObjectUploaded { size_bytes: 30, .. }
        ));
    }

    #[test]
    fn dedup_event_size_bytes_extracts_payload() {
        assert_eq!(
            DedupEvent::ObjectUploaded {
                size_bytes: 42,
                was_deduped: false
            }
            .size_bytes(),
            42
        );
        assert_eq!(DedupEvent::ObjectDeleted { size_bytes: 9 }.size_bytes(), 9);
    }

    #[test]
    fn dedup_dashboard_round_trips_through_serde_json() {
        let dashboard = DedupDashboard {
            stats: DedupStats::from_counts(10, 4, 1000, 400),
            savings: StorageSavings::from_counts(10, 4, 1000, 400, 1_700_000_000_000),
            recent_events: vec![
                DedupEvent::ObjectUploaded {
                    size_bytes: 100,
                    was_deduped: false,
                },
                DedupEvent::ObjectDeleted { size_bytes: 100 },
            ],
        };
        let json = serde_json::to_string(&dashboard).unwrap();
        let back: DedupDashboard = serde_json::from_str(&json).unwrap();
        assert_eq!(dashboard, back);
    }

    /// Mock S3Client returning a pre-baked CBOR-encoded
    /// `DedupStats` for `metadata/content_index/stats` and an
    /// `Error::NotFound` for everything else.
    #[derive(Debug)]
    struct MockSnapshotS3 {
        snapshot: Vec<u8>,
    }
    impl crate::media::sinks::zk_fabric::S3Client for MockSnapshotS3 {
        fn put_object(
            &self,
            _bucket: &str,
            _key: &str,
            _bytes: &[u8],
        ) -> std::result::Result<(), crate::Error> {
            Ok(())
        }
        fn get_object_range(
            &self,
            _bucket: &str,
            key: &str,
            _range: std::ops::Range<u64>,
        ) -> std::result::Result<Vec<u8>, crate::Error> {
            if key == ZkofDedupAnalytics::snapshot_key() {
                Ok(self.snapshot.clone())
            } else {
                Err(crate::Error::Storage("not found".into()))
            }
        }
        fn delete_object(
            &self,
            _bucket: &str,
            _key: &str,
        ) -> std::result::Result<(), crate::Error> {
            Ok(())
        }
    }

    #[test]
    fn zkof_dedup_analytics_query_stats_parses_cbor_snapshot() {
        let upstream = DedupStats::from_counts(100, 60, 1024, 614);
        let bytes = crate::cbor::to_vec(&upstream).unwrap();
        let s3 = Arc::new(MockSnapshotS3 { snapshot: bytes });
        let probe = ZkofDedupAnalytics::new(s3, "tenant-bucket".into());
        let got = probe.query_dedup_ratio("tenant-1").unwrap();
        assert_eq!(got, upstream);
    }

    #[test]
    fn zkof_dedup_analytics_query_savings_computes_savings() {
        let upstream = DedupStats::from_counts(100, 60, 1024, 614);
        let bytes = crate::cbor::to_vec(&upstream).unwrap();
        let s3 = Arc::new(MockSnapshotS3 { snapshot: bytes });
        let probe = ZkofDedupAnalytics::new(s3, "tenant-bucket".into());
        let savings = probe.query_storage_savings("tenant-1").unwrap();
        // 1024 - 614 = 410 bytes_saved
        assert_eq!(savings.bytes_saved, 410);
        assert_eq!(savings.objects_deduped, 40);
    }

    #[test]
    fn zkof_dedup_analytics_falls_back_to_local_when_s3_unavailable() {
        #[derive(Debug)]
        struct FailingS3;
        impl crate::media::sinks::zk_fabric::S3Client for FailingS3 {
            fn put_object(
                &self,
                _: &str,
                _: &str,
                _: &[u8],
            ) -> std::result::Result<(), crate::Error> {
                Err(crate::Error::Storage("offline".into()))
            }
            fn get_object_range(
                &self,
                _: &str,
                _: &str,
                _: std::ops::Range<u64>,
            ) -> std::result::Result<Vec<u8>, crate::Error> {
                Err(crate::Error::Storage("offline".into()))
            }
            fn delete_object(&self, _: &str, _: &str) -> std::result::Result<(), crate::Error> {
                Err(crate::Error::Storage("offline".into()))
            }
        }
        let probe = ZkofDedupAnalytics::new(Arc::new(FailingS3), "tenant-bucket".into());
        // Seed local fallback with a known event.
        probe
            .record_event(DedupEvent::ObjectUploaded {
                size_bytes: 50,
                was_deduped: false,
            })
            .unwrap();
        let stats = probe.query_dedup_ratio("tenant-1").unwrap();
        assert_eq!(stats.total_objects, 1);
        assert_eq!(stats.unique_bytes, 50);
        assert_eq!(probe.recent_events().len(), 1);
    }
}
