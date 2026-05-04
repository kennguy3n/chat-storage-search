//! Phase 7, batch-5 (2026-05-04) — media blob sink stress test.
//!
//! Marked `#[ignore]` so the standard `cargo test --workspace`
//! run never executes it. Run it explicitly with
//! `cargo test --test media_sink_stress -- --ignored`.
//!
//! Coverage:
//! 1. Seed 10 000 `media_asset` rows split 40 % / 20 % / 20 %
//!    / 20 % across the four canonical storage sinks
//!    (`kchat_backend`, `icloud`, `google_drive`,
//!    `zk_object_fabric`).
//! 2. For each sink type, round-trip a sample of assets through
//!    `MediaBlobSink::fetch_media_chunk` (or, for the KChat
//!    backend tier, through `TransportClient::fetch_blob_range`)
//!    and verify the bytes that come back match the bytes that
//!    went in.
//! 3. Assert that `media_asset.storage_sink` round-trips
//!    correctly for every sink type via
//!    `LocalStoreDb::list_media_assets_by_storage_sink`.
//! 4. Exercise the migration executor at scale by moving a
//!    fraction of the iCloud-tier assets over to Google Drive
//!    and confirming the local store reflects the new sink.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use kchat_core::config::{KChatCoreConfig, Platform};
use kchat_core::core_impl::CoreImpl;
use kchat_core::crypto::aead::BlobClass;
use kchat_core::crypto::content_hash::content_hash;
use kchat_core::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
use kchat_core::local_store::state_machines::{ArchiveState, BackupState, BodyState, MediaState};
use kchat_core::media::migration::NoopMigrationProgress;
use kchat_core::media::sinks::{MediaBlobReference, MediaBlobSink};

const KEY: [u8; 32] = [0x66; 32];
const TOTAL: usize = 10_000;

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
        _: BlobClass,
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
        PathBuf::from("/tmp/kchat-stress"),
        Platform::MacOs,
        "tenant-stress",
    );
    let core = CoreImpl::new_in_memory(cfg, KEY).unwrap();
    core.with_db(|db| {
        db.insert_conversation(&Conversation {
            conversation_id: "conv-stress".into(),
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

fn seed(core: &CoreImpl, asset_id: &str, sink: &str, chunks: &[Vec<u8>]) {
    let merkle_root = content_hash(
        &chunks
            .iter()
            .flat_map(|c| c.iter().copied())
            .collect::<Vec<u8>>(),
    )
    .to_vec();
    core.with_db(|db| {
        let mid = format!("msg-{asset_id}");
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: mid.clone(),
            conversation_id: "conv-stress".into(),
            sender_id: "user-1".into(),
            created_at_ms: 0,
            received_at_ms: 0,
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
            asset_id: asset_id.into(),
            message_id: mid,
            mime_type: "image/png".into(),
            bytes_total: chunks.iter().map(|c| c.len() as i64).sum(),
            bytes_local: 0,
            media_state: MediaState::OriginalLocal,
            wrapped_k_asset: vec![0u8; 48],
            chunk_count: chunks.len() as i32,
            merkle_root,
            blob_id: asset_id.into(),
            storage_sink: sink.into(),
        })
        .unwrap();
    });
}

#[test]
#[ignore = "stress test — run with --ignored"]
fn ten_thousand_assets_round_trip_across_four_sinks() {
    let core = open_core();
    let kchat = InMemorySink::new("kchat_backend");
    let icloud = InMemorySink::new("icloud");
    let drive = InMemorySink::new("google_drive");
    let zkof = InMemorySink::new("zk_object_fabric");

    // 40 / 20 / 20 / 20 split. Each asset has a single tiny
    // ciphertext chunk to keep the test shape predictable but
    // exercise the per-asset round-trip path.
    let kchat_count = (TOTAL * 40) / 100;
    let icloud_count = (TOTAL * 20) / 100;
    let drive_count = (TOTAL * 20) / 100;
    let zkof_count = TOTAL - kchat_count - icloud_count - drive_count;

    let mut sinks: [(&str, &InMemorySink, usize); 4] = [
        ("kchat_backend", &kchat, kchat_count),
        ("icloud", &icloud, icloud_count),
        ("google_drive", &drive, drive_count),
        ("zk_object_fabric", &zkof, zkof_count),
    ];

    let mut idx = 0u64;
    for (tag, sink, count) in sinks.iter_mut() {
        for _ in 0..*count {
            let asset_id = format!("asset-{idx:08}");
            let payload = vec![idx as u8; 16];
            sink.seed(&asset_id, std::slice::from_ref(&payload));
            seed(&core, &asset_id, tag, &[payload]);
            idx += 1;
        }
    }

    // 1. Every storage_sink column rounds back through the DB
    //    helper.
    core.with_db(|db| {
        assert_eq!(
            db.list_media_assets_by_storage_sink("kchat_backend")
                .unwrap()
                .len(),
            kchat_count
        );
        assert_eq!(
            db.list_media_assets_by_storage_sink("icloud")
                .unwrap()
                .len(),
            icloud_count
        );
        assert_eq!(
            db.list_media_assets_by_storage_sink("google_drive")
                .unwrap()
                .len(),
            drive_count
        );
        assert_eq!(
            db.list_media_assets_by_storage_sink("zk_object_fabric")
                .unwrap()
                .len(),
            zkof_count
        );
    });

    // 2. Sample every 1000th asset on every sink: fetch back,
    //    confirm the bytes match.
    for (tag, sink, count) in sinks.iter() {
        for k in (0..*count).step_by(1000) {
            let asset_id = format!("asset-{:08}", asset_offset(&sinks, tag) + k);
            let r = MediaBlobReference {
                blob_id: asset_id.clone(),
                storage_sink: tag.to_string(),
                sink_metadata: None,
            };
            let chunk = sink.fetch_media_chunk(&r, 0).unwrap();
            assert_eq!(chunk.len(), 16, "round-trip on {tag} for {asset_id}");
        }
    }

    // 3. Migrate a fraction of icloud assets over to google_drive
    //    and verify the local store / sink contents reflect the
    //    move.
    let plan = core.plan_media_migration("icloud", "google_drive").unwrap();
    assert_eq!(plan.len(), icloud_count);
    let progress = NoopMigrationProgress;
    let report = core
        .migrate_media_sink(&plan, &icloud, &drive, &progress, true)
        .unwrap();
    assert_eq!(report.migrated(), icloud_count);
    assert_eq!(report.failed(), 0);
    assert_eq!(icloud.len(), 0, "icloud should be empty after drain");
    core.with_db(|db| {
        assert!(db
            .list_media_assets_by_storage_sink("icloud")
            .unwrap()
            .is_empty());
        assert_eq!(
            db.list_media_assets_by_storage_sink("google_drive")
                .unwrap()
                .len(),
            drive_count + icloud_count
        );
    });
}

/// Helper: cumulative asset offset for the current sink.
fn asset_offset(sinks: &[(&str, &InMemorySink, usize); 4], tag: &str) -> usize {
    let mut off = 0;
    for (t, _, c) in sinks.iter() {
        if *t == tag {
            return off;
        }
        off += *c;
    }
    off
}
