//! Eviction planner & executor (`docs/PROPOSAL.md §5.4`).
//!
//! Given a list of [`EvictionCandidate`]s and a target byte count,
//! [`plan_eviction`] sorts by score and accumulates candidates
//! until the freed-bytes total meets the target. The plan is a
//! pure data structure — [`execute_eviction`] turns it into actual
//! state-machine transitions on the local store.
//!
//! Two filters always apply, regardless of pressure level:
//!
//! 1. `is_pinned == true` candidates are excluded.
//! 2. Only candidates with `archive_state == ArchiveVerified` are
//!    eligible — evicting an asset that has not yet been safely
//!    uploaded would lose it permanently.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::local_store::state_machines::ArchiveState;
use crate::Error;

use super::scoring::{compute_eviction_score, EvictionCandidate};

/// Result of [`plan_eviction`].
#[derive(Debug, Clone, PartialEq)]
pub struct EvictionPlan {
    /// Candidates the planner picked, in eviction order
    /// (highest-score first), paired with their score.
    pub candidates: Vec<(EvictionCandidate, f64)>,
    /// Byte budget the caller asked the planner to free.
    pub target_bytes: u64,
    /// Sum of `candidate.bytes` across `candidates`. May exceed
    /// `target_bytes` (last candidate added pushes us over).
    pub total_bytes: u64,
}

/// Result of [`execute_eviction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvictionResult {
    /// Bytes actually freed.
    pub freed_bytes: u64,
    /// Number of media assets that were evicted.
    pub evicted_count: u32,
}

/// Plan eviction.
///
/// Filters out pinned and not-yet-archived candidates, scores the
/// remainder, sorts descending, and accumulates until
/// `target_bytes` is reached or the candidate pool is exhausted.
pub fn plan_eviction(
    candidates: Vec<EvictionCandidate>,
    target_bytes: u64,
    now_ms: i64,
) -> EvictionPlan {
    let mut scored: Vec<(EvictionCandidate, f64)> = candidates
        .into_iter()
        .filter(|c| !c.is_pinned)
        .filter(|c| c.archive_state == ArchiveState::ArchiveVerified)
        .map(|c| {
            let s = compute_eviction_score(&c, now_ms);
            (c, s)
        })
        .collect();
    scored.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

    let mut chosen = Vec::new();
    let mut accumulated = 0u64;
    for (cand, score) in scored {
        if accumulated >= target_bytes {
            break;
        }
        accumulated = accumulated.saturating_add(cand.bytes);
        chosen.push((cand, score));
    }

    EvictionPlan {
        candidates: chosen,
        target_bytes,
        total_bytes: accumulated,
    }
}

/// Apply `plan` to the local store.
///
/// For every candidate in `plan.candidates`, this issues an
/// `UPDATE media_asset SET media_state = 'evicted', bytes_local = 0
///   WHERE asset_id = ?1`. The string literal must match
/// [`MediaState::as_str`](crate::local_store::state_machines::MediaState)
/// — `'evicted'` is the canonical state for assets whose local data
/// has been reclaimed by the storage budget enforcer.
///
/// Eviction is per-asset (not per-message). `media_asset` is keyed
/// by `asset_id`, with `message_id` as a non-unique foreign key, so
/// a message can own several rows (the original blob + a thumbnail,
/// or multiple attachments). Keying the UPDATE on `message_id`
/// would evict every asset on the message in a single statement
/// while only crediting one candidate's `bytes` to `freed_bytes`,
/// silently undercounting both `freed_bytes` and `evicted_count`.
///
/// The orchestration layer is expected to wrap the call in its own
/// transaction.
pub fn execute_eviction(conn: &Connection, plan: &EvictionPlan) -> Result<EvictionResult, Error> {
    let mut freed = 0u64;
    let mut evicted = 0u32;
    for (cand, _) in &plan.candidates {
        let updated = conn
            .execute(
                "UPDATE media_asset
                    SET media_state = 'evicted',
                        bytes_local = 0
                  WHERE asset_id = ?1",
                params![cand.asset_id.to_string()],
            )
            .map_err(|e| Error::Storage(e.to_string()))?;
        // `asset_id` is the table's primary key, so `updated` is
        // either 0 (row not found) or 1.
        if updated > 0 {
            freed = freed.saturating_add(cand.bytes);
            evicted = evicted.saturating_add(1);
        }
    }
    Ok(EvictionResult {
        freed_bytes: freed,
        evicted_count: evicted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offload::scoring::ContentKind;
    use uuid::Uuid;

    fn cand(kind: ContentKind, bytes: u64, age_ms: i64) -> EvictionCandidate {
        EvictionCandidate {
            asset_id: Uuid::now_v7(),
            message_id: Uuid::now_v7(),
            conversation_id: Uuid::now_v7(),
            content_kind: kind,
            bytes,
            last_accessed_ms: -age_ms,
            is_pinned: false,
            archive_state: ArchiveState::ArchiveVerified,
        }
    }

    #[test]
    fn plan_eviction_stops_at_target_bytes() {
        let cands = vec![
            cand(ContentKind::Video, 1000, 0),
            cand(ContentKind::Document, 1000, 0),
            cand(ContentKind::Image, 1000, 0),
        ];
        let plan = plan_eviction(cands, 1500, 0);
        assert_eq!(plan.candidates.len(), 2);
        assert!(plan.total_bytes >= 1500);
    }

    #[test]
    fn pinned_content_excluded_from_eviction() {
        let mut pinned = cand(ContentKind::Video, 1000, 0);
        pinned.is_pinned = true;
        let cands = vec![pinned, cand(ContentKind::Text, 500, 0)];
        let plan = plan_eviction(cands, 10_000, 0);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.total_bytes, 500);
        assert_eq!(plan.candidates[0].0.content_kind, ContentKind::Text);
    }

    #[test]
    fn only_archived_content_eligible() {
        let mut not_archived = cand(ContentKind::Video, 1000, 0);
        not_archived.archive_state = ArchiveState::NotArchived;
        let cands = vec![not_archived, cand(ContentKind::Text, 100, 0)];
        let plan = plan_eviction(cands, 10_000, 0);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].0.content_kind, ContentKind::Text);
    }

    #[test]
    fn eviction_priority_order_matches_spec() {
        // One candidate per content kind, all the same age & size.
        let cands = vec![
            cand(ContentKind::Text, 1000, 0),
            cand(ContentKind::Thumbnail, 1000, 0),
            cand(ContentKind::Voice, 1000, 0),
            cand(ContentKind::Image, 1000, 0),
            cand(ContentKind::Document, 1000, 0),
            cand(ContentKind::Video, 1000, 0),
        ];
        let plan = plan_eviction(cands, u64::MAX, 0);
        let order: Vec<ContentKind> = plan
            .candidates
            .iter()
            .map(|(c, _)| c.content_kind)
            .collect();
        assert_eq!(
            order,
            vec![
                ContentKind::Video,
                ContentKind::Document,
                ContentKind::Image,
                ContentKind::Voice,
                ContentKind::Thumbnail,
                ContentKind::Text,
            ]
        );
    }

    #[test]
    fn execute_eviction_sums_evicted_count() {
        // Use a fresh in-memory db so we can verify the UPDATE
        // is a no-op for unknown message_ids (and the result
        // reports zero).
        let db = crate::local_store::db::LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let plan = plan_eviction(
            vec![
                cand(ContentKind::Video, 1000, 0),
                cand(ContentKind::Text, 100, 0),
            ],
            10_000,
            0,
        );
        let result = execute_eviction(db.connection(), &plan).unwrap();
        // No matching media_asset rows, so nothing was freed.
        assert_eq!(result.evicted_count, 0);
        assert_eq!(result.freed_bytes, 0);
    }

    #[test]
    fn empty_plan_executes_to_zero_result() {
        let db = crate::local_store::db::LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let plan = EvictionPlan {
            candidates: Vec::new(),
            target_bytes: 0,
            total_bytes: 0,
        };
        let result = execute_eviction(db.connection(), &plan).unwrap();
        assert_eq!(result, EvictionResult::default());
    }

    #[test]
    fn execute_eviction_writes_canonical_evicted_state() {
        // The bug this regression-tests: `execute_eviction` previously
        // wrote `media_state = 'archive_only'`, which is not a valid
        // `MediaState` string and would make the column unparseable.
        use crate::local_store::db::LocalStoreDb;
        use crate::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
        use crate::local_store::state_machines::{
            ArchiveState, BackupState, BodyState, MediaState,
        };

        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        db.insert_conversation(&Conversation {
            conversation_id: "c-evict".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
        })
        .unwrap();

        let mid = Uuid::now_v7();
        let asset_uuid = Uuid::now_v7();
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: mid.to_string(),
            conversation_id: "c-evict".into(),
            sender_id: "s".into(),
            created_at_ms: 1,
            received_at_ms: 1,
            kind: MessageKind::Media,
            body_state: BodyState::LocalPlainAvailable,
            media_state: Some(MediaState::OriginalLocal),
            archive_state: ArchiveState::ArchiveVerified,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        })
        .unwrap();
        db.insert_media_asset(&MediaAsset {
            asset_id: asset_uuid.to_string(),
            message_id: mid.to_string(),
            mime_type: "image/png".into(),
            bytes_total: 1024,
            bytes_local: 1024,
            media_state: MediaState::OriginalLocal,
            wrapped_k_asset: vec![0u8; 40],
            chunk_count: 1,
            merkle_root: vec![0u8; 32],
            blob_id: "blob-1".into(),
            storage_sink: "kchat_backend".into(),
        })
        .unwrap();

        let plan = EvictionPlan {
            candidates: vec![(
                EvictionCandidate {
                    asset_id: asset_uuid,
                    message_id: mid,
                    conversation_id: Uuid::now_v7(),
                    content_kind: ContentKind::Image,
                    bytes: 1024,
                    last_accessed_ms: 0,
                    is_pinned: false,
                    archive_state: ArchiveState::ArchiveVerified,
                },
                1.0,
            )],
            target_bytes: 1024,
            total_bytes: 1024,
        };
        let result = execute_eviction(db.connection(), &plan).unwrap();
        assert_eq!(result.evicted_count, 1);
        assert_eq!(result.freed_bytes, 1024);

        // The persisted state must round-trip through MediaState's
        // parser. Reading via get_media_asset (which calls
        // MediaState::try_from(&str)) is the regression hook.
        let asset = db
            .get_media_asset(&asset_uuid.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(asset.media_state, MediaState::Evicted);
        assert_eq!(asset.bytes_local, 0);
    }

    #[test]
    fn execute_eviction_keys_by_asset_id_not_message_id() {
        // Bug guard: the planner emits one candidate per asset.
        // Previously the SQL keyed on `message_id`, so a message
        // with two assets would have BOTH rows updated when only
        // ONE candidate ran — but `freed_bytes` / `evicted_count`
        // would still credit just one. Switching to `asset_id`
        // makes each UPDATE affect exactly one row, so two
        // candidates → two updated rows → accurate accounting.
        // This test seeds two `media_asset` rows under the same
        // `message_id` and asserts that running a plan with only
        // ONE of them leaves the other untouched.
        use crate::local_store::db::LocalStoreDb;
        use crate::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
        use crate::local_store::state_machines::{
            ArchiveState, BackupState, BodyState, MediaState,
        };

        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        db.insert_conversation(&Conversation {
            conversation_id: "c-multi".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
        })
        .unwrap();

        let mid = Uuid::now_v7();
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: mid.to_string(),
            conversation_id: "c-multi".into(),
            sender_id: "s".into(),
            created_at_ms: 1,
            received_at_ms: 1,
            kind: MessageKind::Media,
            body_state: BodyState::LocalPlainAvailable,
            media_state: Some(MediaState::OriginalLocal),
            archive_state: ArchiveState::ArchiveVerified,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        })
        .unwrap();

        // Two assets under the same message: an "original" and a
        // matching thumbnail. Eviction should drop ONLY the asset
        // we put in the plan.
        let original = Uuid::now_v7();
        let thumb = Uuid::now_v7();
        for (asset_uuid, blob_id, bytes) in [
            (original, "blob-original", 4096_i64),
            (thumb, "blob-thumb", 256_i64),
        ] {
            db.insert_media_asset(&MediaAsset {
                asset_id: asset_uuid.to_string(),
                message_id: mid.to_string(),
                mime_type: "image/png".into(),
                bytes_total: bytes,
                bytes_local: bytes,
                media_state: MediaState::OriginalLocal,
                wrapped_k_asset: vec![0u8; 40],
                chunk_count: 1,
                merkle_root: vec![0u8; 32],
                blob_id: blob_id.into(),
                storage_sink: "kchat_backend".into(),
            })
            .unwrap();
        }

        // Plan only evicts the original.
        let plan = EvictionPlan {
            candidates: vec![(
                EvictionCandidate {
                    asset_id: original,
                    message_id: mid,
                    conversation_id: Uuid::now_v7(),
                    content_kind: ContentKind::Image,
                    bytes: 4096,
                    last_accessed_ms: 0,
                    is_pinned: false,
                    archive_state: ArchiveState::ArchiveVerified,
                },
                1.0,
            )],
            target_bytes: 4096,
            total_bytes: 4096,
        };
        let result = execute_eviction(db.connection(), &plan).unwrap();
        assert_eq!(result.evicted_count, 1, "only one asset in plan");
        assert_eq!(result.freed_bytes, 4096);

        let original_row = db.get_media_asset(&original.to_string()).unwrap().unwrap();
        assert_eq!(original_row.media_state, MediaState::Evicted);
        assert_eq!(original_row.bytes_local, 0);

        // The thumbnail must be untouched. With the previous
        // `WHERE message_id = ?` the thumbnail would also have
        // been evicted.
        let thumb_row = db.get_media_asset(&thumb.to_string()).unwrap().unwrap();
        assert_eq!(thumb_row.media_state, MediaState::OriginalLocal);
        assert_eq!(thumb_row.bytes_local, 256);
    }
}
