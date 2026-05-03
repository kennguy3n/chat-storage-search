//! Phase-4 backup compaction policy.
//!
//! Implements the **daily → weekly → monthly** strategy described
//! in `docs/PHASES.md` Phase 4: as backup segments age, the
//! orchestrator periodically merges adjacent same-tier segments
//! into a single, denser segment. Merging applies tombstones so
//! deleted-message events do not get carried forward — the
//! compacted segment only contains the still-live events.
//!
//! The module is policy-only: it does not call the segment
//! builder, the manifest writer, or the upload transport. The
//! orchestration layer wires it together.
//!
//! Workflow:
//!
//! 1. Stash a list of [`BackupSegmentRef`] from the active manifest
//!    chain.
//! 2. Call [`CompactionPolicy::plan`] with the current wall-clock
//!    time → [`CompactionPlan`] describing which segments are
//!    candidates for which target tier.
//! 3. For each `CompactionGroup`:
//!    - Decrypt the source segments (via
//!      [`crate::backup::segment_builder::decrypt_backup_segment`]),
//!    - Concatenate their event lists,
//!    - Run [`apply_tombstones`] to drop deleted message rows,
//!    - Re-emit a single sealed segment via
//!      [`crate::backup::segment_builder::BackupSegmentBuilder::build_segment`].
//! 4. Persist the new segment ids + the superseded segment ids
//!    onto the next backup manifest.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use super::event_journal::{BackupEvent, BackupEventType};

/// Tier a segment currently lives in. The compaction graph is
/// strictly `Daily → Weekly → Monthly`; lower tiers age into the
/// next one over time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompactionTier {
    /// Original delta segment produced by the segment builder.
    Daily,
    /// Compacted weekly segment (merged daily segments).
    Weekly,
    /// Compacted monthly segment (merged weekly segments).
    Monthly,
}

impl CompactionTier {
    /// Tier this one ages into. `Monthly` does not compact further.
    pub fn next_tier(self) -> Option<CompactionTier> {
        match self {
            CompactionTier::Daily => Some(CompactionTier::Weekly),
            CompactionTier::Weekly => Some(CompactionTier::Monthly),
            CompactionTier::Monthly => None,
        }
    }
}

/// One row from the backup-segment map, viewed from the
/// compaction planner's perspective.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSegmentRef {
    /// Segment identifier.
    pub segment_id: Uuid,
    /// Tier the segment currently sits in.
    pub tier: CompactionTier,
    /// Earliest event timestamp covered by the segment (ms epoch).
    pub min_event_ms: i64,
    /// Latest event timestamp covered by the segment (ms epoch).
    pub max_event_ms: i64,
    /// Number of events sealed in the segment.
    pub event_count: usize,
}

/// Policy thresholds. Segments older than `daily_to_weekly_ms`
/// from `now` are eligible to roll up into Weekly; segments older
/// than `weekly_to_monthly_ms` are eligible to roll up into
/// Monthly.
#[derive(Debug, Clone, Copy)]
pub struct CompactionPolicy {
    /// Daily → Weekly age threshold.
    pub daily_to_weekly_ms: i64,
    /// Weekly → Monthly age threshold.
    pub weekly_to_monthly_ms: i64,
    /// Minimum segments in a group before compaction kicks in.
    /// Set to `2` to avoid rewriting a single-segment group.
    pub min_group_size: usize,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        const DAY_MS: i64 = 86_400 * 1_000;
        Self {
            // Daily segments older than 7 days roll up.
            daily_to_weekly_ms: 7 * DAY_MS,
            // Weekly segments older than 30 days roll up.
            weekly_to_monthly_ms: 30 * DAY_MS,
            min_group_size: 2,
        }
    }
}

impl CompactionPolicy {
    /// Plan compaction over `segments`, given a wall-clock `now_ms`.
    ///
    /// The planner is deterministic: for the same inputs it
    /// produces the same plan, including the order of the groups
    /// (sorted by `(tier, min_event_ms)`).
    pub fn plan(&self, segments: &[BackupSegmentRef], now_ms: i64) -> CompactionPlan {
        // Bucket by `(source_tier, week_start_or_month_start)`.
        let mut buckets: BTreeMap<(CompactionTier, i64), Vec<BackupSegmentRef>> = BTreeMap::new();
        for seg in segments {
            let bucket_key = match seg.tier {
                CompactionTier::Daily => {
                    if now_ms - seg.max_event_ms < self.daily_to_weekly_ms {
                        // Too young — leave untouched.
                        continue;
                    }
                    week_start_ms(seg.min_event_ms)
                }
                CompactionTier::Weekly => {
                    if now_ms - seg.max_event_ms < self.weekly_to_monthly_ms {
                        continue;
                    }
                    month_start_ms(seg.min_event_ms)
                }
                CompactionTier::Monthly => continue,
            };
            buckets
                .entry((seg.tier, bucket_key))
                .or_default()
                .push(seg.clone());
        }

        let mut groups = Vec::new();
        for ((source_tier, _bucket_key), mut members) in buckets {
            if members.len() < self.min_group_size {
                continue;
            }
            // Stable order so re-emitted segment Merkle roots are
            // deterministic across runs that see the same input.
            members.sort_by_key(|s| (s.min_event_ms, s.segment_id));
            let target_tier = source_tier
                .next_tier()
                .expect("Monthly is filtered out above");
            groups.push(CompactionGroup {
                source_tier,
                target_tier,
                members,
            });
        }

        CompactionPlan { groups }
    }
}

/// Output of [`CompactionPolicy::plan`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompactionPlan {
    /// One group per `(source_tier, time_bucket)` that crossed
    /// `min_group_size`.
    pub groups: Vec<CompactionGroup>,
}

impl CompactionPlan {
    /// Whether the plan does anything.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Flat list of every segment_id that the plan supersedes.
    pub fn superseded_segment_ids(&self) -> Vec<Uuid> {
        self.groups
            .iter()
            .flat_map(|g| g.members.iter().map(|s| s.segment_id))
            .collect()
    }
}

/// One bucket of segments to merge into a single output segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionGroup {
    /// Tier the source segments are in.
    pub source_tier: CompactionTier,
    /// Tier the merged segment will land in.
    pub target_tier: CompactionTier,
    /// Source segments, ordered by `(min_event_ms, segment_id)`.
    pub members: Vec<BackupSegmentRef>,
}

/// Apply tombstone events to `events` in place and return the
/// surviving event list.
///
/// A tombstone is any event whose `event_type` matches one of the
/// "deleted" variants. Compaction drops:
///
/// * The tombstone itself.
/// * Any earlier event for the same `(conversation_id, message_id)`
///   pair that the tombstone supersedes.
///
/// `MessageDeleted` deletes by `(conversation_id, message_id)`;
/// `ConversationDeleted` deletes every event with that
/// `conversation_id`; `MediaDeleted` deletes earlier
/// `MediaReceived` rows for the same message.
pub fn apply_tombstones(events: Vec<BackupEvent>) -> Vec<BackupEvent> {
    // Pass 1: collect tombstones.
    let mut deleted_messages: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();
    let mut deleted_conversations: BTreeSet<Uuid> = BTreeSet::new();
    let mut deleted_media: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();

    for ev in &events {
        match ev.event_type {
            BackupEventType::MessageDeleted => {
                if let (Some(conv), Some(mid)) = (ev.conversation_id, ev.message_id) {
                    deleted_messages.insert((conv, mid));
                }
            }
            BackupEventType::ConversationDeleted => {
                if let Some(conv) = ev.conversation_id {
                    deleted_conversations.insert(conv);
                }
            }
            BackupEventType::MediaDeleted => {
                if let (Some(conv), Some(mid)) = (ev.conversation_id, ev.message_id) {
                    deleted_media.insert((conv, mid));
                }
            }
            _ => {}
        }
    }

    // Pass 2: filter survivors.
    events
        .into_iter()
        .filter(|ev| {
            // Drop the tombstones themselves.
            match ev.event_type {
                BackupEventType::MessageDeleted
                | BackupEventType::ConversationDeleted
                | BackupEventType::MediaDeleted => return false,
                _ => {}
            }

            // Drop conversation-level deletions.
            if let Some(conv) = ev.conversation_id {
                if deleted_conversations.contains(&conv) {
                    return false;
                }
            }

            // Drop per-message message-events for tombstoned messages.
            if matches!(
                ev.event_type,
                BackupEventType::MessageReceived | BackupEventType::MessageEdited
            ) {
                if let (Some(conv), Some(mid)) = (ev.conversation_id, ev.message_id) {
                    if deleted_messages.contains(&(conv, mid)) {
                        return false;
                    }
                }
            }

            // Drop media-receives for tombstoned media.
            if matches!(ev.event_type, BackupEventType::MediaReceived) {
                if let (Some(conv), Some(mid)) = (ev.conversation_id, ev.message_id) {
                    if deleted_media.contains(&(conv, mid)) {
                        return false;
                    }
                }
            }

            true
        })
        .collect()
}

/// Truncate `t_ms` (epoch ms) to the start of its calendar week
/// (Monday 00:00 UTC). Used as a coarse bucket key — the
/// implementation does not rely on chrono and is monotonic.
fn week_start_ms(t_ms: i64) -> i64 {
    // 1970-01-01 was a Thursday — `4 * DAY` shifts the week
    // origin to Monday so `t_ms / WEEK_MS` is week-aligned.
    const DAY_MS: i64 = 86_400 * 1_000;
    const WEEK_MS: i64 = 7 * DAY_MS;
    let shifted = t_ms.saturating_sub(4 * DAY_MS);
    (shifted / WEEK_MS) * WEEK_MS + 4 * DAY_MS
}

/// Truncate `t_ms` to the start of its calendar month, using a
/// 30-day approximation. Same caveat as
/// [`crate::archive::segment_builder::default_time_bucket`]:
/// good enough for compaction bucketing, not a calendar engine.
fn month_start_ms(t_ms: i64) -> i64 {
    const DAY_MS: i64 = 86_400 * 1_000;
    const MONTH_MS: i64 = 30 * DAY_MS;
    (t_ms / MONTH_MS) * MONTH_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(ty: BackupEventType, conv: Uuid, mid: Option<Uuid>, ts_ms: i64) -> BackupEvent {
        BackupEvent {
            event_type: ty,
            conversation_id: Some(conv),
            message_id: mid,
            payload: vec![],
            created_at_ms: ts_ms,
        }
    }

    fn seg(tier: CompactionTier, min_ms: i64, max_ms: i64) -> BackupSegmentRef {
        BackupSegmentRef {
            segment_id: Uuid::now_v7(),
            tier,
            min_event_ms: min_ms,
            max_event_ms: max_ms,
            event_count: 1,
        }
    }

    #[test]
    fn empty_input_produces_empty_plan() {
        let policy = CompactionPolicy::default();
        let plan = policy.plan(&[], 1_777_000_000_000);
        assert!(plan.is_empty());
    }

    #[test]
    fn fresh_daily_segments_are_left_alone() {
        let policy = CompactionPolicy::default();
        let now = 1_777_000_000_000;
        let recent = seg(CompactionTier::Daily, now - 1_000, now - 500);
        let plan = policy.plan(&[recent], now);
        assert!(plan.is_empty());
    }

    #[test]
    fn aged_daily_segments_in_same_bucket_compact() {
        let policy = CompactionPolicy::default();
        const DAY: i64 = 86_400 * 1_000;
        let now = 100 * DAY;
        // Two segments, both >7d old, both within the same week
        // bucket → eligible.
        let s1 = seg(CompactionTier::Daily, 80 * DAY, 80 * DAY + 1_000);
        let s2 = seg(CompactionTier::Daily, 80 * DAY + 2_000, 80 * DAY + 3_000);
        let plan = policy.plan(&[s1.clone(), s2.clone()], now);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].members.len(), 2);
        assert_eq!(plan.groups[0].source_tier, CompactionTier::Daily);
        assert_eq!(plan.groups[0].target_tier, CompactionTier::Weekly);
        assert_eq!(plan.superseded_segment_ids().len(), 2);
    }

    #[test]
    fn singleton_below_min_group_size_does_not_compact() {
        let policy = CompactionPolicy::default();
        const DAY: i64 = 86_400 * 1_000;
        let now = 100 * DAY;
        let solo = seg(CompactionTier::Daily, 80 * DAY, 80 * DAY + 1_000);
        let plan = policy.plan(&[solo], now);
        assert!(plan.is_empty());
    }

    #[test]
    fn weekly_segments_age_into_monthly() {
        let policy = CompactionPolicy::default();
        const DAY: i64 = 86_400 * 1_000;
        let now = 100 * DAY;
        let s1 = seg(CompactionTier::Weekly, 30 * DAY, 30 * DAY + 1_000);
        let s2 = seg(CompactionTier::Weekly, 30 * DAY + 2_000, 30 * DAY + 3_000);
        let plan = policy.plan(&[s1, s2], now);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].source_tier, CompactionTier::Weekly);
        assert_eq!(plan.groups[0].target_tier, CompactionTier::Monthly);
    }

    #[test]
    fn monthly_segments_are_terminal() {
        let policy = CompactionPolicy::default();
        const DAY: i64 = 86_400 * 1_000;
        let now = 365 * DAY;
        let s1 = seg(CompactionTier::Monthly, DAY, DAY);
        let s2 = seg(CompactionTier::Monthly, 2 * DAY, 2 * DAY);
        let plan = policy.plan(&[s1, s2], now);
        assert!(plan.is_empty());
    }

    #[test]
    fn message_deleted_drops_message_received_and_message_edited() {
        let conv = Uuid::now_v7();
        let mid = Uuid::now_v7();
        let other_mid = Uuid::now_v7();
        let events = vec![
            evt(BackupEventType::MessageReceived, conv, Some(mid), 1),
            evt(BackupEventType::MessageEdited, conv, Some(mid), 2),
            evt(BackupEventType::MessageReceived, conv, Some(other_mid), 3),
            evt(BackupEventType::MessageDeleted, conv, Some(mid), 4),
        ];
        let survivors = apply_tombstones(events);
        // Only the unrelated MessageReceived survives.
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].message_id, Some(other_mid));
    }

    #[test]
    fn conversation_deleted_drops_every_event_in_conversation() {
        let conv_a = Uuid::now_v7();
        let conv_b = Uuid::now_v7();
        let events = vec![
            evt(
                BackupEventType::MessageReceived,
                conv_a,
                Some(Uuid::now_v7()),
                1,
            ),
            evt(
                BackupEventType::MediaReceived,
                conv_a,
                Some(Uuid::now_v7()),
                2,
            ),
            evt(
                BackupEventType::MessageReceived,
                conv_b,
                Some(Uuid::now_v7()),
                3,
            ),
            evt(BackupEventType::ConversationDeleted, conv_a, None, 4),
        ];
        let survivors = apply_tombstones(events);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].conversation_id, Some(conv_b));
    }

    #[test]
    fn media_deleted_drops_only_media_received_for_same_message() {
        let conv = Uuid::now_v7();
        let mid = Uuid::now_v7();
        let events = vec![
            evt(BackupEventType::MessageReceived, conv, Some(mid), 1),
            evt(BackupEventType::MediaReceived, conv, Some(mid), 2),
            evt(BackupEventType::MediaDeleted, conv, Some(mid), 3),
        ];
        let survivors = apply_tombstones(events);
        // The text body event survives; only the MediaReceived /
        // MediaDeleted pair is dropped.
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].event_type, BackupEventType::MessageReceived);
    }

    #[test]
    fn week_and_month_boundaries_are_distinct_buckets() {
        let policy = CompactionPolicy {
            daily_to_weekly_ms: 0,
            weekly_to_monthly_ms: 0,
            min_group_size: 2,
        };
        const DAY: i64 = 86_400 * 1_000;
        // Two segments in different weeks must NOT compact even
        // though both are aged.
        let s1 = seg(CompactionTier::Daily, 0, DAY);
        let s2 = seg(CompactionTier::Daily, 30 * DAY, 31 * DAY);
        let plan = policy.plan(&[s1, s2], 365 * DAY);
        assert!(
            plan.is_empty(),
            "different week buckets should not group, got {plan:?}"
        );
    }
}
