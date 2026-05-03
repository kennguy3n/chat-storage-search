//! Storage budget enforcement.
//!
//! `docs/PROPOSAL.md §5.4` and `docs/ARCHITECTURE.md §8.2` describe
//! the storage-budget assessment loop that the offload pipeline
//! calls on app launch / on demand. This module turns the
//! quantitative side of that loop into pure functions that can be
//! exercised in unit tests:
//!
//! 1. Probe SQLCipher for per-table byte usage,
//! 2. Compare the totals against a declared
//!    [`StorageBudget`],
//! 3. Surface a [`PressureLevel`] (`None` < `Warning`
//!    < `Critical` < `Extreme`) that drives the eviction
//!    pipeline (see [`super::scoring`] / [`super::eviction`]).
//!
//! The budget itself is decoupled from the concrete eviction
//! strategy — every level just states *how much* needs to go
//! without specifying *what* should go first.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::Error;

/// User-configurable storage budget.
///
/// `max_bytes` is the hard ceiling. The two thresholds expressed as
/// percentages (`0..=100`) split the budget into three operating
/// regions:
///
/// * `usage <= warning_threshold_pct%` → [`PressureLevel::None`]
/// * `usage <= critical_threshold_pct%` → [`PressureLevel::Warning`]
/// * `usage <= 100%` → [`PressureLevel::Critical`]
/// * `usage  > 100%` → [`PressureLevel::Extreme`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBudget {
    /// Hard ceiling for total local storage, in bytes.
    pub max_bytes: u64,
    /// Percentage of `max_bytes` at which to start the warning
    /// region. Must satisfy `0 <= warning < critical <= 100`.
    pub warning_threshold_pct: u8,
    /// Percentage of `max_bytes` at which to start the critical
    /// region. Must satisfy `warning < critical <= 100`.
    pub critical_threshold_pct: u8,
}

impl StorageBudget {
    /// Default budget: 8 GiB ceiling, warn at 75%, critical at 90%.
    pub fn default_recommended() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024 * 1024,
            warning_threshold_pct: 75,
            critical_threshold_pct: 90,
        }
    }

    fn warning_bytes(&self) -> u64 {
        self.max_bytes * (self.warning_threshold_pct as u64) / 100
    }

    fn critical_bytes(&self) -> u64 {
        self.max_bytes * (self.critical_threshold_pct as u64) / 100
    }
}

/// Per-storage-class breakdown produced by
/// [`StorageBudgetEnforcer::assess`].
///
/// `total_bytes` is the sum of the class-specific buckets and is
/// what the assessor compares against the budget. Individual
/// buckets are exposed so the eviction pipeline can pick the
/// right candidate set per pressure level (see PROPOSAL §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StorageUsage {
    /// Sum of every bucket below.
    pub total_bytes: u64,
    /// `message_skeleton` + `message_body`.
    pub message_bytes: u64,
    /// `media_asset.bytes_local`.
    pub media_bytes: u64,
    /// `search_fts` + `search_fuzzy` + `search_vector` +
    /// `media_search_index`.
    pub index_bytes: u64,
    /// Process-side caches not stored in SQLite (Phase 5+ wires a
    /// non-zero number once the on-disk media cache lands; for
    /// now reported as 0).
    pub cache_bytes: u64,
}

/// Assessment result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetAssessment {
    /// Observed usage.
    pub usage: StorageUsage,
    /// Declared budget.
    pub budget: StorageBudget,
    /// Negative when over-budget (Extreme pressure).
    pub headroom_bytes: i64,
    /// Pressure level the orchestration layer should react to.
    pub pressure_level: PressureLevel,
}

/// Pressure level derived from [`StorageUsage`] vs.
/// [`StorageBudget`]. Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureLevel {
    /// `usage <= warning_threshold`. Nothing to do.
    None,
    /// `warning_threshold < usage <= critical_threshold`. Begin
    /// background eviction of cold thumbnails / text.
    Warning,
    /// `critical_threshold < usage <= max_bytes`. Aggressive
    /// eviction: documents, voice, images.
    Critical,
    /// `usage > max_bytes`. Emergency eviction (videos + anything
    /// not pinned), hydration prefetches paused.
    Extreme,
}

impl PressureLevel {
    /// Return whether this pressure level demands eviction work.
    pub fn requires_eviction(self) -> bool {
        !matches!(self, PressureLevel::None)
    }
}

/// Stateless storage budget enforcer.
///
/// Holds no internal cache — every call re-queries the database.
/// Phase 4+ may layer a debounced cache on top once the
/// orchestration layer is in place.
#[derive(Debug, Default, Clone, Copy)]
pub struct StorageBudgetEnforcer;

impl StorageBudgetEnforcer {
    /// Build a stateless enforcer.
    pub fn new() -> Self {
        Self
    }

    /// Probe `db` for per-bucket usage, compare against `budget`,
    /// and return the resulting [`BudgetAssessment`].
    pub fn assess(
        &self,
        db: &Connection,
        budget: &StorageBudget,
    ) -> Result<BudgetAssessment, Error> {
        let usage = collect_storage_usage(db)?;
        Ok(self.assess_with_usage(usage, budget))
    }

    /// Assemble a [`BudgetAssessment`] from a pre-computed
    /// [`StorageUsage`]. Useful when the orchestration layer
    /// already has the numbers from elsewhere.
    pub fn assess_with_usage(
        &self,
        usage: StorageUsage,
        budget: &StorageBudget,
    ) -> BudgetAssessment {
        let pressure_level = pressure_level(&usage, budget);
        let headroom_bytes = compute_headroom(&usage, budget);
        BudgetAssessment {
            usage,
            budget: *budget,
            headroom_bytes,
            pressure_level,
        }
    }
}

/// `budget.max_bytes - usage.total_bytes`, signed so callers can
/// distinguish "over budget" from "exactly at budget" (and so the
/// extreme-pressure branch can cleanly emit a target byte count).
pub fn compute_headroom(usage: &StorageUsage, budget: &StorageBudget) -> i64 {
    let max = budget.max_bytes as i128;
    let used = usage.total_bytes as i128;
    let diff = max - used;
    diff.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Map `usage.total_bytes` onto a [`PressureLevel`] using
/// `budget`'s thresholds.
pub fn pressure_level(usage: &StorageUsage, budget: &StorageBudget) -> PressureLevel {
    if usage.total_bytes > budget.max_bytes {
        PressureLevel::Extreme
    } else if usage.total_bytes > budget.critical_bytes() {
        PressureLevel::Critical
    } else if usage.total_bytes > budget.warning_bytes() {
        PressureLevel::Warning
    } else {
        PressureLevel::None
    }
}

/// Aggregate per-bucket byte usage from the SQLCipher store.
///
/// Uses heuristic sums of `LENGTH(...)` over the SQL columns each
/// bucket owns. Exact disk usage (which would include SQLite's
/// page overhead) is not what the offload pipeline cares about —
/// the budget enforcement loop only needs a reasonable proxy that
/// updates as content arrives / departs.
pub fn collect_storage_usage(conn: &Connection) -> Result<StorageUsage, Error> {
    let message_bytes = scalar_u64(
        conn,
        "SELECT
            COALESCE((SELECT SUM(LENGTH(text_content)) FROM message_body), 0)
          + COALESCE((SELECT COUNT(*) * 256 FROM message_skeleton), 0)",
    )?;
    let media_bytes = scalar_u64(
        conn,
        "SELECT COALESCE(SUM(bytes_local), 0) FROM media_asset",
    )?;
    let fts_bytes = scalar_u64(
        conn,
        "SELECT COALESCE(SUM(LENGTH(text_content)), 0) FROM search_fts",
    )?;
    let fuzzy_bytes = scalar_u64(
        conn,
        "SELECT COALESCE(SUM(LENGTH(token)) + 8, 0) FROM search_fuzzy",
    )?;
    let vector_bytes = scalar_u64(
        conn,
        "SELECT COALESCE(SUM(LENGTH(embedding)), 0) FROM search_vector",
    )?;
    let media_search_bytes = scalar_u64(
        conn,
        "SELECT COALESCE(SUM(LENGTH(text)), 0) FROM media_search_index",
    )?;
    let index_bytes = fts_bytes + fuzzy_bytes + vector_bytes + media_search_bytes;
    let cache_bytes = 0u64;
    let total_bytes = message_bytes + media_bytes + index_bytes + cache_bytes;
    Ok(StorageUsage {
        total_bytes,
        message_bytes,
        media_bytes,
        index_bytes,
        cache_bytes,
    })
}

fn scalar_u64(conn: &Connection, sql: &str) -> Result<u64, Error> {
    let v: i64 = conn
        .query_row(sql, [], |row| row.get(0))
        .map_err(|e| Error::Storage(e.to_string()))?;
    Ok(v.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_1k() -> StorageBudget {
        // 1 KiB ceiling, warn at 50%, critical at 80%.
        StorageBudget {
            max_bytes: 1024,
            warning_threshold_pct: 50,
            critical_threshold_pct: 80,
        }
    }

    fn usage_with(total: u64) -> StorageUsage {
        StorageUsage {
            total_bytes: total,
            message_bytes: 0,
            media_bytes: total,
            index_bytes: 0,
            cache_bytes: 0,
        }
    }

    #[test]
    fn no_pressure_when_under_warning_threshold() {
        let usage = usage_with(100);
        assert_eq!(pressure_level(&usage, &budget_1k()), PressureLevel::None);
    }

    #[test]
    fn warning_pressure_at_threshold() {
        let usage = usage_with(600);
        assert_eq!(pressure_level(&usage, &budget_1k()), PressureLevel::Warning);
    }

    #[test]
    fn critical_pressure_at_threshold() {
        let usage = usage_with(900);
        assert_eq!(
            pressure_level(&usage, &budget_1k()),
            PressureLevel::Critical
        );
    }

    #[test]
    fn extreme_pressure_when_over_budget() {
        let usage = usage_with(2000);
        assert_eq!(pressure_level(&usage, &budget_1k()), PressureLevel::Extreme);
    }

    #[test]
    fn headroom_calculation_correct() {
        let budget = budget_1k();
        assert_eq!(compute_headroom(&usage_with(0), &budget), 1024);
        assert_eq!(compute_headroom(&usage_with(1024), &budget), 0);
        assert_eq!(compute_headroom(&usage_with(2048), &budget), -1024);
    }

    #[test]
    fn requires_eviction_only_above_warning() {
        assert!(!PressureLevel::None.requires_eviction());
        assert!(PressureLevel::Warning.requires_eviction());
        assert!(PressureLevel::Critical.requires_eviction());
        assert!(PressureLevel::Extreme.requires_eviction());
    }

    #[test]
    fn assess_with_usage_round_trips() {
        let enforcer = StorageBudgetEnforcer::new();
        let usage = usage_with(700);
        let assessment = enforcer.assess_with_usage(usage, &budget_1k());
        assert_eq!(assessment.usage, usage);
        assert_eq!(assessment.budget, budget_1k());
        assert_eq!(assessment.pressure_level, PressureLevel::Warning);
        assert_eq!(assessment.headroom_bytes, 324);
    }

    #[test]
    fn collect_storage_usage_reports_zero_on_empty_store() {
        let db = crate::local_store::db::LocalStoreDb::open_in_memory(&[0x42; 32]).unwrap();
        let usage = collect_storage_usage(db.connection()).unwrap();
        assert_eq!(usage.media_bytes, 0);
        assert_eq!(usage.index_bytes, 0);
        // message_bytes is 0 because the skeleton table is empty
        // (the per-row 256-byte estimate only applies to existing
        // rows).
        assert_eq!(usage.message_bytes, 0);
    }
}
