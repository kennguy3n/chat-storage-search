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
}
