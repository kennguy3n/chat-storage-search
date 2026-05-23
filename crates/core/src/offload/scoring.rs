//! Eviction scoring formula (`docs/DESIGN.md §5.4`).
//!
//! Higher score → evict first. Three signals combine into the
//! single [`compute_eviction_score`] number:
//!
//! 1. **Content kind weight** — videos and documents weigh the
//!    most, text the least.
//! 2. **Recency decay** — the older the asset's
//!    `last_accessed_ms`, the higher its eviction priority. A 30-day
//!    half-life keeps recently-accessed content sticky without
//!    ever fully pinning it.
//! 3. **Size bonus** — bigger candidates win small ties so a
//!    pressure sweep frees up bytes faster.
//!
//! `is_pinned == true` candidates always score `f64::NEG_INFINITY`
//! so the eviction planner skips them; this is a defensive
//! belt-and-braces alongside the explicit pin filter in
//! [`super::eviction::plan_eviction`].

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::local_store::state_machines::ArchiveState;
use crate::offload::budget::PressureLevel;

/// Coarse content classification used by the eviction scorer.
///
/// `docs/DESIGN.md §5.4` lists the priority order
/// `video → documents → images → voice → thumbnails → cold text`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    /// Video (mp4, mov, webm, …).
    Video,
    /// Document (pdf, docx, …).
    Document,
    /// Image (jpg, png, …) — the original, not the thumbnail.
    Image,
    /// Voice memo (m4a, opus, …).
    Voice,
    /// Image thumbnail.
    Thumbnail,
    /// Cold text body (no media attached).
    Text,
}

impl ContentKind {
    /// Eviction-priority weight used by [`compute_eviction_score`].
    /// Higher is dropped first.
    pub fn weight(self) -> f64 {
        match self {
            ContentKind::Video => 1.0,
            ContentKind::Document => 0.9,
            ContentKind::Image => 0.7,
            ContentKind::Voice => 0.5,
            ContentKind::Thumbnail => 0.3,
            ContentKind::Text => 0.1,
        }
    }

    /// Whether this content kind is eligible for eviction at the
    /// given [`PressureLevel`].
    ///
    /// `docs/DESIGN.md §5.4` reserves the lowest tiers for
    /// severe pressure: image / voice / video / document originals
    /// move under any pressure greater than `None`, but
    /// **thumbnails** are only evictable under `Critical` /
    /// `Extreme`, and **cold text bodies** only under `Extreme`.
    /// The intent is to keep timeline rendering fidelity until the
    /// budget enforcer truly has no other choice.
    pub fn is_eligible_for_pressure(self, pressure: PressureLevel) -> bool {
        match self {
            // Hot media (originals) — eligible whenever there is
            // any pressure at all.
            ContentKind::Video
            | ContentKind::Document
            | ContentKind::Image
            | ContentKind::Voice => !matches!(pressure, PressureLevel::None),
            // Thumbnails are kept around for timeline rendering
            // until pressure is at least `Critical`.
            ContentKind::Thumbnail => {
                matches!(pressure, PressureLevel::Critical | PressureLevel::Extreme)
            }
            // Cold text bodies are the very last resort
            // evicting them costs a search-fts /
            // search-fuzzy reindex on rehydration.
            ContentKind::Text => matches!(pressure, PressureLevel::Extreme),
        }
    }
}

/// Weights table mirroring the priority order in
/// `docs/DESIGN.md §5.4`.
pub const CONTENT_KIND_WEIGHTS: [(ContentKind, f64); 6] = [
    (ContentKind::Video, 1.0),
    (ContentKind::Document, 0.9),
    (ContentKind::Image, 0.7),
    (ContentKind::Voice, 0.5),
    (ContentKind::Thumbnail, 0.3),
    (ContentKind::Text, 0.1),
];

/// One candidate the eviction planner considers.
///
/// Eviction is per-asset, not per-message: a single message can
/// own multiple `media_asset` rows (the original plus a thumbnail,
/// or several attachments) and each is evicted independently.
/// `asset_id` is what [`super::eviction::execute_eviction`] keys
/// the `UPDATE` on; `message_id` is kept for scoring / observability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictionCandidate {
    /// `media_asset.asset_id` — the row the eviction UPDATE will
    /// match on.
    pub asset_id: Uuid,
    /// Owning message.
    pub message_id: Uuid,
    /// Owning conversation.
    pub conversation_id: Uuid,
    /// Coarse content kind.
    pub content_kind: ContentKind,
    /// Bytes the candidate currently holds locally — what
    /// eviction would free.
    pub bytes: u64,
    /// Wall-clock millisecond timestamp of the most recent access.
    pub last_accessed_ms: i64,
    /// Pinned candidates are excluded from eviction.
    pub is_pinned: bool,
    /// Archive state at the time of scoring. Eviction is only
    /// safe once the candidate is `archive_verified`.
    pub archive_state: ArchiveState,
    /// `media_asset.storage_sink` — tiered eviction policy
    /// (see [`super::eviction::EvictionTier`]) consults this to
    /// decide whether the candidate's original lives on a user
    /// cloud (cloud-offload first) or only on the KChat backend
    /// (full eviction). Canonical values mirror
    /// [`crate::config::StorageSink`]: `"kchat_backend"`,
    /// `"icloud"`, `"google_drive"`, `"zk_object_fabric"`.
    pub storage_sink: String,
}

const RECENCY_HALF_LIFE_MS: f64 = 30.0 * 24.0 * 60.0 * 60.0 * 1000.0; // 30 days
const SIZE_BONUS_DIVISOR: f64 = 16.0 * 1024.0 * 1024.0; // 16 MiB

/// Compute the eviction score for `candidate` at `now_ms`.
///
/// Higher scores evict first. Pinned candidates short-circuit to
/// [`f64::NEG_INFINITY`].
pub fn compute_eviction_score(candidate: &EvictionCandidate, now_ms: i64) -> f64 {
    if candidate.is_pinned {
        return f64::NEG_INFINITY;
    }

    let kind_weight = candidate.content_kind.weight();

    let age_ms = (now_ms - candidate.last_accessed_ms).max(0) as f64;
    let recency = 1.0 - 0.5_f64.powf(age_ms / RECENCY_HALF_LIFE_MS);

    let size_bonus = (candidate.bytes as f64) / SIZE_BONUS_DIVISOR;

    kind_weight * 1.0 + recency * 0.5 + size_bonus * 0.1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(kind: ContentKind, bytes: u64, last_accessed_ms: i64) -> EvictionCandidate {
        EvictionCandidate {
            asset_id: Uuid::now_v7(),
            message_id: Uuid::now_v7(),
            conversation_id: Uuid::now_v7(),
            content_kind: kind,
            bytes,
            last_accessed_ms,
            is_pinned: false,
            archive_state: ArchiveState::ArchiveVerified,
            storage_sink: "kchat_backend".to_string(),
        }
    }

    #[test]
    fn video_scores_higher_than_text() {
        let now = 0i64;
        let v = compute_eviction_score(&candidate(ContentKind::Video, 1024, 0), now);
        let t = compute_eviction_score(&candidate(ContentKind::Text, 1024, 0), now);
        assert!(v > t, "video={v} text={t}");
    }

    #[test]
    fn older_content_scores_higher() {
        let now = 60i64 * 24 * 60 * 60 * 1000;
        let fresh = compute_eviction_score(&candidate(ContentKind::Image, 1024, now), now);
        let old = compute_eviction_score(&candidate(ContentKind::Image, 1024, 0), now);
        assert!(old > fresh, "old={old} fresh={fresh}");
    }

    #[test]
    fn pinned_content_scores_neg_inf() {
        let mut c = candidate(ContentKind::Video, 1024, 0);
        c.is_pinned = true;
        let score = compute_eviction_score(&c, 1_000_000);
        assert_eq!(score, f64::NEG_INFINITY);
    }

    #[test]
    fn pinned_candidate_scores_minimum() {
        // §5.4 invariant: pinned candidates must always sort to
        // the bottom of any eviction plan, regardless of how
        // attractive the rest of their signals look. Spec asks for
        // `f64::MIN` (or anything lower); the implementation
        // returns `f64::NEG_INFINITY` which is strictly smaller
        // both satisfy the contract that the planner never picks
        // a pinned row.
        let now = 365 * 24 * 60 * 60 * 1000_i64;
        // Highest-priority kind, oldest possible age, biggest
        // size — what would normally be the top of the queue.
        let mut top = candidate(ContentKind::Video, 1024 * 1024 * 1024, 0);
        top.is_pinned = true;
        // A very ordinary unpinned candidate to compare against.
        let ordinary = candidate(ContentKind::Text, 1024, now);

        let pinned_score = compute_eviction_score(&top, now);
        let ordinary_score = compute_eviction_score(&ordinary, now);

        assert!(pinned_score <= f64::MIN);
        assert!(
            pinned_score < ordinary_score,
            "pinned={pinned_score} ordinary={ordinary_score}"
        );
    }

    #[test]
    fn size_bonus_discriminates_ties() {
        let small = compute_eviction_score(&candidate(ContentKind::Image, 1, 0), 0);
        let large = compute_eviction_score(&candidate(ContentKind::Image, 100 * 1024 * 1024, 0), 0);
        assert!(large > small);
    }

    #[test]
    fn content_kind_weights_are_distinct_and_ordered() {
        let mut weights: Vec<f64> = CONTENT_KIND_WEIGHTS.iter().map(|(_, w)| *w).collect();
        weights.sort_by(|a, b| b.partial_cmp(a).unwrap());
        // Sorted descending matches the input order:
        assert_eq!(
            weights,
            CONTENT_KIND_WEIGHTS
                .iter()
                .map(|(_, w)| *w)
                .collect::<Vec<f64>>()
        );
    }

    // -------------------------------------------------------------
    // PressureLevel-gated eligibility (`§5.4`).
    // -------------------------------------------------------------
    #[test]
    fn no_pressure_evicts_nothing() {
        for kind in [
            ContentKind::Video,
            ContentKind::Document,
            ContentKind::Image,
            ContentKind::Voice,
            ContentKind::Thumbnail,
            ContentKind::Text,
        ] {
            assert!(
                !kind.is_eligible_for_pressure(PressureLevel::None),
                "{kind:?} ineligible under None"
            );
        }
    }

    #[test]
    fn warning_pressure_evicts_originals_only() {
        for kind in [
            ContentKind::Video,
            ContentKind::Document,
            ContentKind::Image,
            ContentKind::Voice,
        ] {
            assert!(
                kind.is_eligible_for_pressure(PressureLevel::Warning),
                "{kind:?} eligible under Warning"
            );
        }
        assert!(!ContentKind::Thumbnail.is_eligible_for_pressure(PressureLevel::Warning));
        assert!(!ContentKind::Text.is_eligible_for_pressure(PressureLevel::Warning));
    }

    #[test]
    fn critical_pressure_includes_thumbnails_excludes_text() {
        for kind in [
            ContentKind::Video,
            ContentKind::Document,
            ContentKind::Image,
            ContentKind::Voice,
            ContentKind::Thumbnail,
        ] {
            assert!(
                kind.is_eligible_for_pressure(PressureLevel::Critical),
                "{kind:?} eligible under Critical"
            );
        }
        assert!(!ContentKind::Text.is_eligible_for_pressure(PressureLevel::Critical));
    }

    #[test]
    fn extreme_pressure_includes_cold_text() {
        for kind in [
            ContentKind::Video,
            ContentKind::Document,
            ContentKind::Image,
            ContentKind::Voice,
            ContentKind::Thumbnail,
            ContentKind::Text,
        ] {
            assert!(
                kind.is_eligible_for_pressure(PressureLevel::Extreme),
                "{kind:?} eligible under Extreme"
            );
        }
    }
}
