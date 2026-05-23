//! Archive compaction.
//!
//! Periodically the orchestration layer needs to shrink the
//! archive footprint per `(account, conversation, time_bucket)`:
//! collect every aged delta segment, apply tombstones, re-seal as
//! a single compact segment, and transition the obsolete segments
//! to [`crate::local_store::state_machines::ArchiveState::ArchiveCompacted`].
//! Storage cost trends toward the *post-tombstone* size of the
//! conversation, not the cumulative arrival history.
//!
//! This module provides the shared building blocks for that work;
//! [`crate::core_impl::CoreImpl::compact_archive`] is the
//! orchestration layer that wires them against the local store
//! and the transport / S3 backends.
//!
//! The module is intentionally separate from
//! [`crate::backup::compaction`]:
//!
//! * Backup compaction merges by tier (Daily → Weekly → Monthly)
//!   over a *global* segment ledger.
//! * Archive compaction merges by `(conversation_id, time_bucket)`
//!   every segment in a bucket collapses into one compact
//!   segment, regardless of age — once the bucket is "closed"
//!   (all events past the bucket's right-edge have been
//!   journaled). The state machine guard is the segment row's
//!   `archive_state`: only `ArchiveVerified` rows are eligible.

use std::collections::BTreeSet;

use uuid::Uuid;

use super::event_journal::{ArchiveEvent, ArchiveEventType};

/// Apply the archive-flavored tombstone semantics over `events`.
///
/// Mirrors [`crate::backup::compaction::apply_tombstones`] but
/// dispatches on [`ArchiveEventType`] instead of
/// [`crate::backup::event_journal::BackupEventType`]. The drop
/// rules:
///
/// * `MessageDeleted(conv, mid)` — drops every earlier event with
///   the same `(conv, mid)` (including any `MediaReceived` rows).
/// * `ConversationDeleted(conv)` — drops every event tied to that
///   conversation.
/// * The tombstone events themselves are filtered out so the
///   compact segment is purely the post-delete picture.
///
/// Order is preserved among survivors. The event-set is consumed
/// because the function takes ownership of the `Vec` for
/// allocation reuse.
pub fn apply_archive_tombstones(events: Vec<ArchiveEvent>) -> Vec<ArchiveEvent> {
    let mut deleted_messages: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();
    let mut deleted_conversations: BTreeSet<Uuid> = BTreeSet::new();

    for ev in &events {
        match ev.event_type {
            ArchiveEventType::MessageDeleted => {
                if let Some(mid) = ev.message_id {
                    deleted_messages.insert((ev.conversation_id, mid));
                }
            }
            ArchiveEventType::ConversationDeleted => {
                deleted_conversations.insert(ev.conversation_id);
            }
            _ => {}
        }
    }

    events
        .into_iter()
        .filter(|ev| {
            // Drop the tombstones themselves.
            match ev.event_type {
                ArchiveEventType::MessageDeleted | ArchiveEventType::ConversationDeleted => {
                    return false;
                }
                _ => {}
            }
            // Drop conversation-wide tombstoned events.
            if deleted_conversations.contains(&ev.conversation_id) {
                return false;
            }
            // Drop per-message tombstoned events. A `MessageDeleted`
            // tombstone supersedes every earlier event for the
            // same `(conversation_id, message_id)` pair, including
            // any `MediaReceived` rows attached to that message.
            if let Some(mid) = ev.message_id {
                if deleted_messages.contains(&(ev.conversation_id, mid)) {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Result of an archive-compaction run, returned by
/// [`crate::core_impl::CoreImpl::compact_archive`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArchiveCompactionResult {
    /// `(conversation_id, time_bucket)` rows the orchestrator
    /// inspected (always `1` per call today; reserved for the
    /// future "compact all eligible buckets" sweep).
    pub buckets_inspected: u64,
    /// Buckets that produced a compact segment (i.e. ≥2 source
    /// segments were merged).
    pub buckets_compacted: u64,
    /// Total source segments superseded (sum across all
    /// `buckets_compacted` groups).
    pub segments_superseded: u64,
    /// Compact segments emitted (always equals
    /// `buckets_compacted`).
    pub segments_emitted: u64,
    /// Sum of `ciphertext.len` across the source segments that
    /// were superseded — a coarse "bytes saved before re-emission"
    /// measure.
    pub bytes_before: u64,
    /// `ciphertext.len` of the new compact segments. Pair with
    /// `bytes_before` for a savings ratio.
    pub bytes_after: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(ty: ArchiveEventType, conv: Uuid, mid: Option<Uuid>, ts_ms: i64) -> ArchiveEvent {
        ArchiveEvent {
            event_type: ty,
            conversation_id: conv,
            message_id: mid,
            payload: vec![],
            created_at_ms: ts_ms,
        }
    }

    #[test]
    fn apply_archive_tombstones_drops_deleted_message_and_its_history() {
        let conv = Uuid::now_v7();
        let mid = Uuid::now_v7();
        let other_mid = Uuid::now_v7();
        let events = vec![
            evt(ArchiveEventType::MessageReceived, conv, Some(mid), 1),
            evt(ArchiveEventType::MessageEdited, conv, Some(mid), 2),
            evt(ArchiveEventType::MessageReceived, conv, Some(other_mid), 3),
            evt(ArchiveEventType::MessageDeleted, conv, Some(mid), 4),
        ];
        let survivors = apply_archive_tombstones(events);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].message_id, Some(other_mid));
    }

    #[test]
    fn apply_archive_tombstones_drops_conversation_wide_history() {
        let dead_conv = Uuid::now_v7();
        let live_conv = Uuid::now_v7();
        let mid = Uuid::now_v7();
        let live_mid = Uuid::now_v7();
        let events = vec![
            evt(ArchiveEventType::MessageReceived, dead_conv, Some(mid), 1),
            evt(ArchiveEventType::MediaReceived, dead_conv, Some(mid), 2),
            evt(
                ArchiveEventType::MessageReceived,
                live_conv,
                Some(live_mid),
                3,
            ),
            evt(ArchiveEventType::ConversationDeleted, dead_conv, None, 4),
        ];
        let survivors = apply_archive_tombstones(events);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].conversation_id, live_conv);
    }

    #[test]
    fn apply_archive_tombstones_drops_orphan_media_received_for_deleted_message() {
        let conv = Uuid::now_v7();
        let mid = Uuid::now_v7();
        let events = vec![
            evt(ArchiveEventType::MessageReceived, conv, Some(mid), 1),
            evt(ArchiveEventType::MediaReceived, conv, Some(mid), 2),
            evt(ArchiveEventType::MessageDeleted, conv, Some(mid), 3),
        ];
        let survivors = apply_archive_tombstones(events);
        assert!(
            survivors.is_empty(),
            "MessageDeleted must drop the orphan MediaReceived too"
        );
    }

    #[test]
    fn apply_archive_tombstones_is_noop_without_tombstones() {
        let conv = Uuid::now_v7();
        let mid = Uuid::now_v7();
        let events = vec![
            evt(ArchiveEventType::MessageReceived, conv, Some(mid), 1),
            evt(ArchiveEventType::MessageEdited, conv, Some(mid), 2),
            evt(ArchiveEventType::MediaReceived, conv, Some(mid), 3),
        ];
        let survivors = apply_archive_tombstones(events.clone());
        assert_eq!(survivors, events);
    }
}
