//! Integration tests for cross-sink media migration —
//! Phase 7, batch-5 (2026-05-04).
//!
//! Driven through [`crate::core_impl::CoreImpl::plan_media_migration`]
//! / [`crate::core_impl::CoreImpl::migrate_media_sink`] so the
//! tests double as acceptance criteria for the public surface.

use std::collections::HashMap;
use std::sync::Mutex;

use std::path::PathBuf;

use kchat_core::config::{KChatCoreConfig, Platform};
use kchat_core::core_impl::CoreImpl;
use kchat_core::crypto::aead::BlobClass;
use kchat_core::crypto::content_hash::content_hash;
use kchat_core::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
use kchat_core::local_store::state_machines::{ArchiveState, BackupState, BodyState, MediaState};
use kchat_core::media::migration::{
    InMemoryMigrationProgress, MediaMigrationPlan, MigrationItemOutcome, NoopMigrationProgress,
};
use kchat_core::media::sinks::{MediaBlobReference, MediaBlobSink};
use uuid::Uuid;

const KEY: [u8; 32] = [0x55; 32];

#[derive(Debug, Default)]
struct InMemorySink {
    sink_tag: String,
    store: Mutex<HashMap<(String, u32), Vec<u8>>>,
}
impl InMemorySink {
    fn new(tag: &str) -> Self {
        Self {
            sink_tag: tag.to_string(),
            store: Mutex::new(HashMap::new()),
        }
    }
    fn seed(&self, blob_id: &str, chunks: &[Vec<u8>]) {
        let mut s = self.store.lock().unwrap();
        for (idx, c) in chunks.iter().enumerate() {
            s.insert((blob_id.to_string(), idx as u32), c.clone());
        }
    }
    fn len(&self) -> usize {
        self.store.lock().unwrap().len()
    }
}
impl MediaBlobSink for InMemorySink {
    fn upload_media_chunks(
        &self,
        asset_id: &str,
        _blob_class: BlobClass,
        chunks: &[&[u8]],
        expected_merkle_root: [u8; 32],
    ) -> kchat_core::Result<MediaBlobReference> {
        let mut store = self.store.lock().unwrap();
        for (idx, c) in chunks.iter().enumerate() {
            store.insert((asset_id.to_string(), idx as u32), c.to_vec());
        }
        Ok(MediaBlobReference {
            blob_id: asset_id.to_string(),
            storage_sink: self.sink_tag.clone(),
            sink_metadata: Some(expected_merkle_root.to_vec()),
        })
    }
    fn fetch_media_chunk(
        &self,
        blob_ref: &MediaBlobReference,
        chunk_idx: u32,
    ) -> kchat_core::Result<Vec<u8>> {
        let store = self.store.lock().unwrap();
        store
            .get(&(blob_ref.blob_id.clone(), chunk_idx))
            .cloned()
            .ok_or_else(|| {
                kchat_core::Error::Storage(format!(
                    "missing chunk {}/{chunk_idx}",
                    blob_ref.blob_id
                ))
            })
    }
    fn delete_media_blob(&self, blob_ref: &MediaBlobReference) -> kchat_core::Result<()> {
        let mut store = self.store.lock().unwrap();
        store.retain(|(b, _), _| b != &blob_ref.blob_id);
        Ok(())
    }
}

fn open_core() -> CoreImpl {
    let cfg = KChatCoreConfig::new(
        PathBuf::from("/tmp/kchat-media-migration-tests"),
        Platform::MacOs,
        "tenant-media-migration-tests",
    );
    let core = CoreImpl::new_in_memory(cfg, KEY).unwrap();
    core.with_db(|db| {
        db.insert_conversation(&Conversation {
            conversation_id: "conv-1".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 0,
            ..Default::default()
        })
        .unwrap();
    });
    core
}

fn seed_asset(core: &CoreImpl, sink: &str, chunks: &[Vec<u8>], sink_impl: &InMemorySink) -> String {
    let asset_id = Uuid::now_v7().to_string();
    let message_id = Uuid::now_v7().to_string();
    let merkle_root = content_hash(
        &chunks
            .iter()
            .flat_map(|c| c.iter().copied())
            .collect::<Vec<u8>>(),
    )
    .to_vec();
    sink_impl.seed(&asset_id, chunks);
    core.with_db(|db| {
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: message_id.clone(),
            conversation_id: "conv-1".into(),
            sender_id: "user-1".into(),
            created_at_ms: 100,
            received_at_ms: 100,
            kind: MessageKind::Text,
            body_state: BodyState::LocalPlainAvailable,
            media_state: None,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        })
        .unwrap();
        db.insert_media_asset(&MediaAsset {
            asset_id: asset_id.clone(),
            message_id,
            mime_type: "image/png".into(),
            bytes_total: chunks.iter().map(|c| c.len() as i64).sum(),
            bytes_local: 0,
            media_state: MediaState::OriginalLocal,
            wrapped_k_asset: vec![0u8; 48],
            chunk_count: chunks.len() as i32,
            merkle_root,
            blob_id: asset_id.clone(),
            storage_sink: sink.to_string(),
        })
        .unwrap();
    });
    asset_id
}

#[test]
fn plan_and_execute_round_trip_through_core_impl() {
    let core = open_core();
    let icloud = InMemorySink::new("icloud");
    let drive = InMemorySink::new("google_drive");
    let _a = seed_asset(&core, "icloud", &[vec![1; 32], vec![2; 32]], &icloud);
    let _b = seed_asset(&core, "icloud", &[vec![3; 16]], &icloud);

    let plan: MediaMigrationPlan = core.plan_media_migration("icloud", "google_drive").unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan.total_chunks(), 3);

    let progress = InMemoryMigrationProgress::new();
    let report = core
        .migrate_media_sink(&plan, &icloud, &drive, &progress, false)
        .unwrap();
    assert_eq!(report.migrated(), 2);
    assert_eq!(report.failed(), 0);

    // Local store now points at google_drive for every row.
    core.with_db(|db| {
        let leftover = db.list_media_assets_by_storage_sink("icloud").unwrap();
        assert!(leftover.is_empty());
        let migrated = db
            .list_media_assets_by_storage_sink("google_drive")
            .unwrap();
        assert_eq!(migrated.len(), 2);
    });
    assert_eq!(progress.completed().len(), 2);
}

#[test]
fn re_running_migration_is_idempotent() {
    let core = open_core();
    let icloud = InMemorySink::new("icloud");
    let drive = InMemorySink::new("google_drive");
    let _a = seed_asset(&core, "icloud", &[vec![1; 32]], &icloud);
    let plan = core.plan_media_migration("icloud", "google_drive").unwrap();
    let progress = NoopMigrationProgress;
    core.migrate_media_sink(&plan, &icloud, &drive, &progress, false)
        .unwrap();

    // Second run: every item is already on google_drive so nothing
    // moves, no failures, but the same plan may be safely re-applied.
    let report = core
        .migrate_media_sink(&plan, &icloud, &drive, &progress, false)
        .unwrap();
    assert_eq!(report.already_on_target(), 1);
    assert_eq!(report.migrated(), 0);
    assert_eq!(report.failed(), 0);
}

#[test]
fn plan_with_same_source_and_target_returns_empty() {
    let core = open_core();
    let plan = core.plan_media_migration("icloud", "icloud").unwrap();
    assert!(plan.is_empty());
}

#[test]
fn delete_after_success_drains_source_sink_chunks() {
    let core = open_core();
    let icloud = InMemorySink::new("icloud");
    let drive = InMemorySink::new("google_drive");
    let _a = seed_asset(&core, "icloud", &[vec![1; 32]], &icloud);
    let plan = core.plan_media_migration("icloud", "google_drive").unwrap();
    let progress = NoopMigrationProgress;
    let report = core
        .migrate_media_sink(&plan, &icloud, &drive, &progress, true)
        .unwrap();
    assert_eq!(report.migrated(), 1);
    assert_eq!(icloud.len(), 0, "source sink should have been drained");
}

#[test]
fn migration_outcome_failed_leaves_local_store_untouched() {
    let core = open_core();
    let icloud = InMemorySink::new("icloud");
    let _a = seed_asset(&core, "icloud", &[vec![1; 32]], &icloud);

    // Sink that always returns an error on upload — exercises
    // the Failed branch of the executor.
    #[derive(Debug)]
    struct BrokenSink;
    impl MediaBlobSink for BrokenSink {
        fn upload_media_chunks(
            &self,
            _: &str,
            _: BlobClass,
            _: &[&[u8]],
            _: [u8; 32],
        ) -> kchat_core::Result<MediaBlobReference> {
            Err(kchat_core::Error::Storage("broken".into()))
        }
        fn fetch_media_chunk(&self, _: &MediaBlobReference, _: u32) -> kchat_core::Result<Vec<u8>> {
            Err(kchat_core::Error::Storage("broken".into()))
        }
        fn delete_media_blob(&self, _: &MediaBlobReference) -> kchat_core::Result<()> {
            Err(kchat_core::Error::Storage("broken".into()))
        }
    }
    let plan = core.plan_media_migration("icloud", "google_drive").unwrap();
    let progress = NoopMigrationProgress;
    let report = core
        .migrate_media_sink(&plan, &icloud, &BrokenSink, &progress, false)
        .unwrap();
    assert_eq!(report.failed(), 1);
    for (_, outcome) in &report.items {
        assert!(matches!(outcome, MigrationItemOutcome::Failed(_)));
    }
    core.with_db(|db| {
        let still = db.list_media_assets_by_storage_sink("icloud").unwrap();
        assert_eq!(still.len(), 1, "Failed migrations must not move the row");
    });
}
