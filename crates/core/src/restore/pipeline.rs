//! Phase-4 skeleton-first restore pipeline.
//!
//! Orchestrates the priority-ordered restore strategy described
//! in `docs/PROPOSAL.md §11` and `docs/PHASES.md` Phase 4. The
//! pipeline runs the steps sequentially:
//!
//! 1. [`RestorePipeline::restore_conversation_list`] —
//!    extract conversation metadata from the latest manifest.
//! 2. [`RestorePipeline::restore_timeline_skeletons`] —
//!    decrypt backup segments, materialise [`SkeletonRow`] rows
//!    with `body_state = RemoteArchiveOnly`.
//! 3. [`RestorePipeline::restore_search_index_shards`] —
//!    placeholder; Phase 4 wires shard segments in a follow-up.
//! 4. [`RestorePipeline::restore_recent_bodies`] —
//!    decrypt bodies for messages within a recency window.
//! 5. [`RestorePipeline::enable_lazy_media_restore`] —
//!    flip restore state to `MediaLazyRestoreEnabled`; media
//!    downloads on demand.
//!
//! Each step transitions the persisted [`RestoreState`] via
//! [`crate::restore::state_machine::transition`].
//!
//! `CoreImpl::restore_from_backup` is the binding glue between
//! this pipeline and the public [`crate::KChatCore`] API.

use std::collections::BTreeMap;

use rusqlite::Connection;
use uuid::Uuid;

use crate::backup::event_journal::{BackupEvent, BackupEventType};
use crate::backup::segment_builder::{decrypt_backup_segment, BuiltBackupSegment};
use crate::crypto::key_hierarchy::KeyMaterial;
use crate::formats::manifest::BackupManifest;
use crate::local_store::state_machines::{BodyState, RestoreState};
use crate::Error;

use super::state_machine;

/// Identifier-only conversation row reconstructed from the
/// backup-segment event stream. The full
/// [`crate::local_store::schema::Conversation`] row is built by
/// the orchestration layer using local-store metadata; the
/// pipeline restores only the canonical id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredConversation {
    /// Conversation identifier.
    pub conversation_id: Uuid,
}

/// Skeleton row reconstructed from a backup-segment event. The
/// body is `None` until the recent-messages step replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonRow {
    /// Owning conversation.
    pub conversation_id: Uuid,
    /// Message identifier.
    pub message_id: Uuid,
    /// Wall-clock millisecond timestamp from the originating event.
    pub created_at_ms: i64,
    /// Initial body lifecycle. Skeletons land as
    /// [`BodyState::RemoteArchiveOnly`]; the recent-messages step
    /// flips them to [`BodyState::LocalPlainAvailable`] when the
    /// body is hydrated.
    pub body_state: BodyState,
}

/// Hydrated message body. Produced by the recent-messages
/// restore step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredBody {
    /// Foreign key back into the skeleton.
    pub message_id: Uuid,
    /// CBOR-encoded payload from the originating
    /// [`BackupEvent::payload`].
    pub payload: Vec<u8>,
}

/// Outcome of a successful pipeline run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreSummary {
    /// Conversations reconstructed from the manifest stream.
    pub conversations: Vec<RestoredConversation>,
    /// Skeleton rows materialised from segment events.
    pub skeletons: Vec<SkeletonRow>,
    /// Bodies hydrated for "recent" messages.
    pub recent_bodies: Vec<RestoredBody>,
    /// Final restore state. The pipeline aims for
    /// [`RestoreState::FullRestoreComplete`].
    pub final_state: Option<RestoreState>,
}

/// Skeleton-first restore pipeline.
///
/// Stateless — every method takes its inputs explicitly. The
/// pipeline persists state transitions via
/// [`crate::restore::state_machine`] but does not own any
/// cache.
#[derive(Debug, Default, Clone, Copy)]
pub struct RestorePipeline;

impl RestorePipeline {
    /// Construct a pipeline.
    pub fn new() -> Self {
        Self
    }

    /// Step 1: extract the conversation list from the latest
    /// manifest. Today the conversation set is the union of
    /// every event's `conversation_id`; a future iteration will
    /// pull the canonical conversation table from a dedicated
    /// `Conversations` segment.
    pub fn restore_conversation_list(
        &self,
        manifests: &[BackupManifest],
        events: &[BackupEvent],
    ) -> Vec<RestoredConversation> {
        // Today the manifest itself does not carry conversation
        // rows directly — the segment_map references segments
        // which contain the events. We surface the union here so
        // the orchestrator has one list to materialise into the
        // conversation table.
        let _ = manifests; // referenced for the public contract
        let mut seen: BTreeMap<Uuid, ()> = BTreeMap::new();
        for ev in events {
            if let Some(cid) = ev.conversation_id {
                seen.insert(cid, ());
            }
        }
        seen.into_keys()
            .map(|conversation_id| RestoredConversation { conversation_id })
            .collect()
    }

    /// Step 2: reconstruct skeleton rows from already-decrypted
    /// events. The pipeline does not deduplicate by message_id;
    /// the orchestrator is expected to apply tombstones via
    /// [`crate::backup::compaction::apply_tombstones`] before
    /// calling this method.
    pub fn restore_timeline_skeletons(&self, events: &[BackupEvent]) -> Vec<SkeletonRow> {
        events
            .iter()
            .filter_map(|ev| match ev.event_type {
                BackupEventType::MessageReceived => {
                    let conversation_id = ev.conversation_id?;
                    let message_id = ev.message_id?;
                    Some(SkeletonRow {
                        conversation_id,
                        message_id,
                        created_at_ms: ev.created_at_ms,
                        body_state: BodyState::RemoteArchiveOnly,
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// Step 3: search index shards. Phase-4 placeholder — search
    /// shard segments are wired in a follow-up. The signature is
    /// already in place so the orchestrator does not change when
    /// the implementation lands.
    pub fn restore_search_index_shards(&self) -> Result<(), Error> {
        // No-op today.
        Ok(())
    }

    /// Step 4: hydrate bodies for messages within `recency_window_ms`
    /// of `now_ms`. Mutates the supplied skeleton rows in place
    /// (`body_state` flips to [`BodyState::LocalPlainAvailable`])
    /// and returns the matching [`RestoredBody`] entries.
    pub fn restore_recent_bodies(
        &self,
        events: &[BackupEvent],
        skeletons: &mut [SkeletonRow],
        now_ms: i64,
        recency_window_ms: i64,
    ) -> Vec<RestoredBody> {
        let cutoff = now_ms.saturating_sub(recency_window_ms);

        let mut hydrated = Vec::new();
        for ev in events {
            if !matches!(ev.event_type, BackupEventType::MessageReceived) {
                continue;
            }
            if ev.created_at_ms < cutoff {
                continue;
            }
            let mid = match ev.message_id {
                Some(m) => m,
                None => continue,
            };
            for sk in skeletons.iter_mut() {
                if sk.message_id == mid {
                    sk.body_state = BodyState::LocalPlainAvailable;
                    hydrated.push(RestoredBody {
                        message_id: mid,
                        payload: ev.payload.clone(),
                    });
                    break;
                }
            }
        }
        hydrated
    }

    /// Step 5: flip the persisted state to
    /// [`RestoreState::MediaLazyRestoreEnabled`]. Older media
    /// downloads on demand once this returns.
    pub fn enable_lazy_media_restore(&self, conn: &Connection) -> Result<RestoreState, Error> {
        state_machine::transition(conn, RestoreState::MediaLazyRestoreEnabled, None)
    }

    /// Drive every step in priority order, persisting the
    /// matching restore-state transition between steps. The
    /// pipeline assumes the caller has already advanced the
    /// state to [`RestoreState::ManifestVerified`].
    pub fn run(
        &self,
        conn: &Connection,
        manifests: &[BackupManifest],
        sealed_segments: &[BuiltBackupSegment],
        k_backup_segment: &KeyMaterial,
        now_ms: i64,
        recency_window_ms: i64,
    ) -> Result<RestoreSummary, Error> {
        // Decrypt every supplied segment up-front — a corrupted
        // segment must surface here before we touch persistence.
        let mut events: Vec<BackupEvent> = Vec::new();
        for seg in sealed_segments {
            let payload = decrypt_backup_segment(seg, k_backup_segment)?;
            events.extend(payload.events);
        }
        events.sort_by_key(|e| e.created_at_ms);

        // 1) Conversation list.
        let conversations = self.restore_conversation_list(manifests, &events);

        // 2) Timeline skeletons.
        let mut skeletons = self.restore_timeline_skeletons(&events);
        state_machine::transition(conn, RestoreState::SkeletonRestored, None)?;

        // 3) Search index shards (placeholder).
        self.restore_search_index_shards()?;
        state_machine::transition(conn, RestoreState::SearchRestored, None)?;

        // 4) Recent bodies.
        let recent_bodies =
            self.restore_recent_bodies(&events, &mut skeletons, now_ms, recency_window_ms);
        state_machine::transition(conn, RestoreState::RecentMessagesRestored, None)?;

        // 5) Lazy media restore.
        let media_state = self.enable_lazy_media_restore(conn)?;
        // Final terminal state — the orchestration layer marks the
        // restore complete once lazy media is wired.
        let final_state = state_machine::transition(conn, RestoreState::FullRestoreComplete, None)?;

        let _ = media_state;

        Ok(RestoreSummary {
            conversations,
            skeletons,
            recent_bodies,
            final_state: Some(final_state),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
    use crate::backup::segment_builder::{BackupSegmentBuildRequest, BackupSegmentBuilder};
    use crate::crypto::key_hierarchy::{
        derive_backup_manifest, derive_backup_root, derive_backup_segment, KeyMaterial,
    };
    use crate::formats::SegmentType;
    use crate::local_store::db::LocalStoreDb;
    use ed25519_dalek::SigningKey;

    fn fresh_db_at_manifest_verified() -> LocalStoreDb {
        let db = LocalStoreDb::open_in_memory(&[0x77; 32]).expect("open in-memory");
        // Walk to ManifestVerified — Task 8 owns this state machine.
        for st in [
            RestoreState::IdentityRestored,
            RestoreState::RootKeysUnwrapped,
            RestoreState::ManifestVerified,
        ] {
            state_machine::transition(db.connection(), st, None).unwrap();
        }
        db
    }

    fn fresh_keys() -> (KeyMaterial, KeyMaterial) {
        let identity = KeyMaterial::from_bytes([0xEE; 32]);
        let backup_root = derive_backup_root(&identity).unwrap();
        let k_seg = derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).unwrap();
        let k_man = derive_backup_manifest(&backup_root, b"pipeline").unwrap();
        (k_seg, k_man)
    }

    fn evt(ty: BackupEventType, conv: Uuid, mid: Uuid, ts_ms: i64) -> BackupEvent {
        BackupEvent {
            event_type: ty,
            conversation_id: Some(conv),
            message_id: Some(mid),
            payload: format!("msg-{ts_ms}").into_bytes(),
            created_at_ms: ts_ms,
        }
    }

    #[test]
    fn run_full_pipeline_walks_to_full_restore_complete() {
        let db = fresh_db_at_manifest_verified();
        let (k_seg, k_man) = fresh_keys();
        let signing = SigningKey::from_bytes(&[0x44; 32]);

        let conv_a = Uuid::now_v7();
        let now_ms = 1_777_000_000_000_i64;
        let recent = evt(
            BackupEventType::MessageReceived,
            conv_a,
            Uuid::now_v7(),
            now_ms - 1_000,
        );
        let stale = evt(
            BackupEventType::MessageReceived,
            conv_a,
            Uuid::now_v7(),
            now_ms - 365 * 86_400 * 1_000,
        );
        let segment = BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: vec![recent.clone(), stale.clone()],
                    segment_type: SegmentType::Events,
                },
                &k_seg,
            )
            .unwrap();
        let sealed_manifest = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: std::slice::from_ref(&segment),
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-A".into(),
            },
            &signing,
            &k_man,
        )
        .unwrap();

        let summary = RestorePipeline::new()
            .run(
                db.connection(),
                &[sealed_manifest.manifest],
                &[segment],
                &k_seg,
                now_ms,
                7 * 86_400 * 1_000, // one-week recency window
            )
            .unwrap();

        assert_eq!(summary.final_state, Some(RestoreState::FullRestoreComplete));
        assert_eq!(summary.conversations.len(), 1);
        assert_eq!(summary.conversations[0].conversation_id, conv_a);
        assert_eq!(summary.skeletons.len(), 2);
        // Only the recent body was hydrated — the stale one stays as
        // a skeleton.
        assert_eq!(summary.recent_bodies.len(), 1);
        assert_eq!(
            summary.recent_bodies[0].message_id,
            recent.message_id.unwrap()
        );
    }

    #[test]
    fn restore_conversation_list_dedupes() {
        let conv_a = Uuid::now_v7();
        let conv_b = Uuid::now_v7();
        let events = vec![
            evt(BackupEventType::MessageReceived, conv_a, Uuid::now_v7(), 1),
            evt(BackupEventType::MessageReceived, conv_a, Uuid::now_v7(), 2),
            evt(BackupEventType::MessageReceived, conv_b, Uuid::now_v7(), 3),
        ];
        let convs = RestorePipeline::new().restore_conversation_list(&[], &events);
        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn skeletons_are_remote_archive_only_until_body_arrives() {
        let conv_a = Uuid::now_v7();
        let mid = Uuid::now_v7();
        let events = vec![evt(BackupEventType::MessageReceived, conv_a, mid, 1)];
        let skeletons = RestorePipeline::new().restore_timeline_skeletons(&events);
        assert_eq!(skeletons.len(), 1);
        assert_eq!(skeletons[0].body_state, BodyState::RemoteArchiveOnly);
    }

    #[test]
    fn restore_recent_bodies_flips_state_inside_window() {
        let conv_a = Uuid::now_v7();
        let mid_recent = Uuid::now_v7();
        let mid_stale = Uuid::now_v7();
        let now = 1_000_000_i64;
        let events = vec![
            evt(
                BackupEventType::MessageReceived,
                conv_a,
                mid_recent,
                now - 100,
            ),
            evt(
                BackupEventType::MessageReceived,
                conv_a,
                mid_stale,
                now - 100_000,
            ),
        ];
        let mut skeletons = RestorePipeline::new().restore_timeline_skeletons(&events);
        let bodies =
            RestorePipeline::new().restore_recent_bodies(&events, &mut skeletons, now, 1_000);
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].message_id, mid_recent);
        let recent_skel = skeletons
            .iter()
            .find(|s| s.message_id == mid_recent)
            .unwrap();
        assert_eq!(recent_skel.body_state, BodyState::LocalPlainAvailable);
        let stale_skel = skeletons
            .iter()
            .find(|s| s.message_id == mid_stale)
            .unwrap();
        assert_eq!(stale_skel.body_state, BodyState::RemoteArchiveOnly);
    }

    #[test]
    fn enable_lazy_media_restore_advances_persisted_state() {
        let db = fresh_db_at_manifest_verified();
        // Walk through the state machine to MediaLazyRestoreEnabled prereqs.
        for st in [
            RestoreState::SkeletonRestored,
            RestoreState::SearchRestored,
            RestoreState::RecentMessagesRestored,
        ] {
            state_machine::transition(db.connection(), st, None).unwrap();
        }
        let st = RestorePipeline::new()
            .enable_lazy_media_restore(db.connection())
            .unwrap();
        assert_eq!(st, RestoreState::MediaLazyRestoreEnabled);
    }

    #[test]
    fn run_propagates_decrypt_errors() {
        let db = fresh_db_at_manifest_verified();
        let (k_seg, _k_man) = fresh_keys();
        let other_key = derive_backup_segment(
            &derive_backup_root(&KeyMaterial::from_bytes([0x88; 32])).unwrap(),
            &Uuid::now_v7().into_bytes(),
        )
        .unwrap();

        let segment = BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: vec![evt(
                        BackupEventType::MessageReceived,
                        Uuid::now_v7(),
                        Uuid::now_v7(),
                        1,
                    )],
                    segment_type: SegmentType::Events,
                },
                &k_seg,
            )
            .unwrap();

        // Run with the wrong key.
        let res = RestorePipeline::new().run(
            db.connection(),
            &[],
            &[segment],
            &other_key,
            1_000_000,
            1_000_000,
        );
        assert!(res.is_err(), "expected decrypt error, got {res:?}");
    }
}
