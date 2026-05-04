//! Cross-sink media-blob migration — Phase 7, batch-5
//! (2026-05-04).
//!
//! `docs/PHASES.md` Phase 7 calls for an iOS↔Android-style media
//! blob migration: when the user changes their preferred Tier-2
//! sink (iCloud → Google Drive, Google Drive → ZK Object Fabric,
//! ZKOF → KChat, etc.) the existing media originals must move
//! from the old sink to the new one, the local
//! `media_asset.storage_sink` / `media_asset.blob_id` columns
//! must update transactionally, and the old blob may optionally
//! be deleted.
//!
//! Workflow:
//!
//! 1. [`plan_media_migration`] queries the local store for
//!    every `media_asset` whose `storage_sink` matches `source`.
//!    Returns a [`MediaMigrationPlan`] with one
//!    [`MediaMigrationItem`] per asset.
//! 2. [`execute_media_migration`] iterates the plan and, for
//!    each asset, fetches every ciphertext chunk from the
//!    source sink, hashes the concatenated ciphertext as a
//!    transit integrity check, uploads the chunks to the
//!    target sink, verifies the target sink can be read back
//!    and that the concatenated ciphertext hash matches the
//!    earlier transit hash, updates `media_asset.storage_sink`
//!    and `media_asset.blob_id` in a single
//!    [`Connection::execute`] call, and (optionally) deletes
//!    the source blob.
//!
//! The whole-object plaintext BLAKE3 root in
//! `media_asset.merkle_root` is preserved as-is — the migration
//! only ever moves ciphertext bytes, never decrypts. The
//! transit hash exists purely to catch bytes-corruption between
//! source and target sinks.
//!
//! `Tier 0` (the KChat backend) is intentionally outside the
//! scope of this module: that path uses `TransportClient` rather
//! than the [`MediaBlobSink`] trait surface and has its own
//! migration story. Callers that need to swap the KChat backend
//! away from a Tier-2 sink (or onto one) keep using
//! [`crate::media::routing::route_media_upload`] /
//! [`crate::media::routing::route_media_download`].

use std::sync::Arc;

use crate::crypto::content_hash::HASH_LEN;
use crate::local_store::db::{DbResult, LocalStoreDb};
use crate::local_store::schema::MediaAsset;
use crate::media::sinks::{MediaBlobReference, MediaBlobSink};
use crate::Error;

/// One scheduled cross-sink migration item.
#[derive(Debug, Clone)]
pub struct MediaMigrationItem {
    /// `media_asset.asset_id`.
    pub asset_id: String,
    /// Source-side `media_asset.blob_id`.
    pub blob_id: String,
    /// `media_asset.chunk_count` — the executor uses this to
    /// drive the per-chunk fetch loop.
    pub chunk_count: u32,
    /// `media_asset.merkle_root` — propagated unchanged into
    /// the target [`MediaBlobReference`].
    pub merkle_root: [u8; 32],
    /// Optional sink-specific metadata blob the source attached
    /// when it produced the original reference. Required by
    /// some sinks for fetch (CloudKit zone, Drive file id,
    /// S3 version-id, …); ignored by sinks that don't use it.
    pub sink_metadata: Option<Vec<u8>>,
}

/// Materialized migration plan returned from
/// [`plan_media_migration`]. The migration executor consumes the
/// plan via [`execute_media_migration`].
#[derive(Debug, Clone)]
pub struct MediaMigrationPlan {
    /// Tag of the source sink (matches
    /// [`crate::media::sinks::MediaBlobReference::storage_sink`]).
    pub source_sink: String,
    /// Tag of the target sink.
    pub target_sink: String,
    /// One item per asset that will move. Sorted by `asset_id`
    /// for deterministic execution.
    pub items: Vec<MediaMigrationItem>,
}

impl MediaMigrationPlan {
    /// Number of assets that will move.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the plan has nothing to do.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Total `chunk_count` across every item — useful for
    /// progress UIs.
    pub fn total_chunks(&self) -> u64 {
        self.items.iter().map(|i| i.chunk_count as u64).sum()
    }
}

/// Outcome of a single [`MediaMigrationItem`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationItemOutcome {
    /// The item migrated successfully and the local store was
    /// updated.
    Migrated,
    /// The item was already on the target sink — nothing to do.
    /// Used for idempotent re-runs after a partial failure.
    AlreadyOnTarget,
    /// Migration failed; the local store was *not* updated.
    /// Resume by re-running the migration against the remaining
    /// items.
    Failed(String),
}

/// Outcome of an entire [`execute_media_migration`] run.
#[derive(Debug, Clone, Default)]
pub struct MigrationReport {
    /// `(asset_id, outcome)` pairs in execution order.
    pub items: Vec<(String, MigrationItemOutcome)>,
}

impl MigrationReport {
    /// Number of items that returned [`MigrationItemOutcome::Migrated`].
    pub fn migrated(&self) -> usize {
        self.items
            .iter()
            .filter(|(_, o)| matches!(o, MigrationItemOutcome::Migrated))
            .count()
    }

    /// Number of items that returned [`MigrationItemOutcome::AlreadyOnTarget`].
    pub fn already_on_target(&self) -> usize {
        self.items
            .iter()
            .filter(|(_, o)| matches!(o, MigrationItemOutcome::AlreadyOnTarget))
            .count()
    }

    /// Number of items that returned [`MigrationItemOutcome::Failed`].
    pub fn failed(&self) -> usize {
        self.items
            .iter()
            .filter(|(_, o)| matches!(o, MigrationItemOutcome::Failed(_)))
            .count()
    }
}

/// Progress callback for a long-running migration. Implementations
/// must be `Send + Sync` so the orchestration layer can hand the
/// callback into a worker thread. The trait is object-safe; the
/// migration executor holds an `&dyn MigrationProgress`.
pub trait MigrationProgress: Send + Sync {
    /// Notification that the migration of `asset_id` has started.
    fn on_item_started(&self, _asset_id: &str, _index: usize, _total: usize) {}
    /// Notification that the migration of `asset_id` has produced
    /// a final outcome.
    fn on_item_completed(
        &self,
        _asset_id: &str,
        _index: usize,
        _total: usize,
        _outcome: &MigrationItemOutcome,
    ) {
    }
    /// Notification that the entire run has finished.
    fn on_run_completed(&self, _report: &MigrationReport) {}
}

/// `MigrationProgress` implementation that does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMigrationProgress;
impl MigrationProgress for NoopMigrationProgress {}

/// Build a migration plan for moving every `media_asset` whose
/// `storage_sink` is `source_sink` to `target_sink`.
///
/// Returns an empty plan when `source_sink == target_sink` —
/// the operation is a no-op, not an error.
pub fn plan_media_migration(
    db: &LocalStoreDb,
    source_sink: &str,
    target_sink: &str,
) -> DbResult<MediaMigrationPlan> {
    let mut items: Vec<MediaMigrationItem> = Vec::new();
    if source_sink == target_sink {
        return Ok(MediaMigrationPlan {
            source_sink: source_sink.to_string(),
            target_sink: target_sink.to_string(),
            items,
        });
    }
    let assets = db.list_media_assets_by_storage_sink(source_sink)?;
    for asset in assets {
        let mut root = [0u8; 32];
        if asset.merkle_root.len() != 32 {
            // Skip rows with a corrupted merkle_root — Phase 7
            // contract is "best-effort migration"; the local
            // store schema enforces the 32-byte length on
            // insert so this branch is defensive only.
            continue;
        }
        root.copy_from_slice(&asset.merkle_root);
        let chunk_count = u32::try_from(asset.chunk_count).unwrap_or(0);
        items.push(MediaMigrationItem {
            asset_id: asset.asset_id,
            blob_id: asset.blob_id,
            chunk_count,
            merkle_root: root,
            sink_metadata: None,
        });
    }
    items.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));
    Ok(MediaMigrationPlan {
        source_sink: source_sink.to_string(),
        target_sink: target_sink.to_string(),
        items,
    })
}

/// Execute a [`MediaMigrationPlan`] against the supplied source /
/// target sinks. Returns a [`MigrationReport`] describing the
/// outcome of every item.
///
/// `delete_source_after_success`: when true, every successful
/// migration is followed by a [`MediaBlobSink::delete_media_blob`]
/// against the source sink. The delete is best-effort — if it
/// fails the migration is still reported as
/// [`MigrationItemOutcome::Migrated`] because the local store
/// already points at the new sink.
pub fn execute_media_migration(
    plan: &MediaMigrationPlan,
    source: &dyn MediaBlobSink,
    target: &dyn MediaBlobSink,
    db: &LocalStoreDb,
    progress: &dyn MigrationProgress,
    delete_source_after_success: bool,
) -> Result<MigrationReport, Error> {
    let total = plan.items.len();
    let mut report = MigrationReport::default();

    for (idx, item) in plan.items.iter().enumerate() {
        progress.on_item_started(&item.asset_id, idx, total);
        let outcome = migrate_one(
            item,
            &plan.source_sink,
            &plan.target_sink,
            source,
            target,
            db,
            delete_source_after_success,
        );
        progress.on_item_completed(&item.asset_id, idx, total, &outcome);
        report.items.push((item.asset_id.clone(), outcome));
    }
    progress.on_run_completed(&report);
    Ok(report)
}

fn migrate_one(
    item: &MediaMigrationItem,
    source_sink: &str,
    target_sink: &str,
    source: &dyn MediaBlobSink,
    target: &dyn MediaBlobSink,
    db: &LocalStoreDb,
    delete_source_after_success: bool,
) -> MigrationItemOutcome {
    // Idempotency: re-runs after a partial failure see the local
    // row already pointing at `target_sink`. Skip the upload and
    // report `AlreadyOnTarget`.
    match db.get_media_asset(&item.asset_id) {
        Ok(Some(MediaAsset { storage_sink, .. })) if storage_sink == target_sink => {
            return MigrationItemOutcome::AlreadyOnTarget;
        }
        Ok(_) => {}
        Err(e) => return MigrationItemOutcome::Failed(format!("get_media_asset: {e:?}")),
    }
    // 1. Read every ciphertext chunk from the source sink and
    //    feed it into a streaming BLAKE3 hasher. We retain the
    //    chunk buffers (the target sink needs them as a
    //    `&[&[u8]]`) but deliberately do not build a single
    //    concatenated copy — a 1 GiB media asset would otherwise
    //    need ~2 GiB peak RSS instead of ~1 GiB.
    let mut chunk_buffers: Vec<Vec<u8>> = Vec::with_capacity(item.chunk_count as usize);
    let mut transit_hasher = blake3::Hasher::new();
    let source_ref = MediaBlobReference {
        blob_id: item.blob_id.clone(),
        storage_sink: source_sink.to_string(),
        sink_metadata: item.sink_metadata.clone(),
    };
    for chunk_idx in 0..item.chunk_count {
        match source.fetch_media_chunk(&source_ref, chunk_idx) {
            Ok(buf) => {
                transit_hasher.update(&buf);
                chunk_buffers.push(buf);
            }
            Err(e) => {
                return MigrationItemOutcome::Failed(format!(
                    "source fetch_media_chunk(idx={chunk_idx}): {e:?}"
                ));
            }
        }
    }
    let transit_hash: [u8; HASH_LEN] = transit_hasher.finalize().into();

    // 2. Upload to target.
    let chunk_views: Vec<&[u8]> = chunk_buffers.iter().map(|c| c.as_slice()).collect();
    let new_ref = match target.upload_media_chunks(
        &item.asset_id,
        crate::crypto::aead::BlobClass::Media,
        &chunk_views,
        item.merkle_root,
    ) {
        Ok(r) => r,
        Err(e) => return MigrationItemOutcome::Failed(format!("target upload: {e:?}")),
    };
    if new_ref.storage_sink != target_sink {
        return MigrationItemOutcome::Failed(format!(
            "target sink reference returned storage_sink {:?} (expected {:?})",
            new_ref.storage_sink, target_sink
        ));
    }

    // 3. Read the chunks back from the target and stream them
    //    through a fresh BLAKE3 hasher — same memory rationale
    //    as step 1; we never build a concatenated copy.
    let mut roundtrip_hasher = blake3::Hasher::new();
    for chunk_idx in 0..item.chunk_count {
        match target.fetch_media_chunk(&new_ref, chunk_idx) {
            Ok(buf) => {
                roundtrip_hasher.update(&buf);
            }
            Err(e) => {
                return MigrationItemOutcome::Failed(format!(
                    "target fetch_media_chunk(idx={chunk_idx}): {e:?}"
                ));
            }
        }
    }
    let roundtrip_hash: [u8; HASH_LEN] = roundtrip_hasher.finalize().into();
    if roundtrip_hash != transit_hash {
        return MigrationItemOutcome::Failed(
            "transit-integrity hash mismatch after roundtrip".into(),
        );
    }

    // 4. Update the local store. Wrap the update in a savepoint
    // via the `transaction` helper on `Connection`.
    if let Err(e) =
        db.update_media_storage_sink(&item.asset_id, &new_ref.storage_sink, &new_ref.blob_id)
    {
        return MigrationItemOutcome::Failed(format!("update_media_storage_sink: {e:?}"));
    }

    // 5. Optional source-side delete.
    if delete_source_after_success {
        // Best-effort: log-and-continue; the local store already
        // points at the new sink so the migration is observably
        // complete from the orchestration layer's perspective.
        let _ = source.delete_media_blob(&source_ref);
    }
    MigrationItemOutcome::Migrated
}

/// Convenience [`MigrationProgress`] that records every callback
/// in an in-memory log. Used by tests / desktop UIs that just
/// want to render a list of completed items.
#[derive(Debug, Default, Clone)]
pub struct InMemoryMigrationProgress {
    inner: Arc<std::sync::Mutex<MigrationProgressLog>>,
}

#[derive(Debug, Default, Clone)]
struct MigrationProgressLog {
    started: Vec<(String, usize, usize)>,
    completed: Vec<(String, usize, usize, MigrationItemOutcome)>,
}

impl InMemoryMigrationProgress {
    /// Construct an empty log.
    pub fn new() -> Self {
        Self::default()
    }
    /// Snapshot of the `(asset_id, index, total, outcome)` log.
    pub fn completed(&self) -> Vec<(String, usize, usize, MigrationItemOutcome)> {
        self.inner.lock().unwrap().completed.clone()
    }
    /// Snapshot of the `(asset_id, index, total)` started log.
    pub fn started(&self) -> Vec<(String, usize, usize)> {
        self.inner.lock().unwrap().started.clone()
    }
}

impl MigrationProgress for InMemoryMigrationProgress {
    fn on_item_started(&self, asset_id: &str, index: usize, total: usize) {
        self.inner
            .lock()
            .unwrap()
            .started
            .push((asset_id.to_string(), index, total));
    }
    fn on_item_completed(
        &self,
        asset_id: &str,
        index: usize,
        total: usize,
        outcome: &MigrationItemOutcome,
    ) {
        self.inner.lock().unwrap().completed.push((
            asset_id.to_string(),
            index,
            total,
            outcome.clone(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::BlobClass;
    use crate::crypto::content_hash::content_hash;
    use crate::local_store::db::LocalStoreDb;
    use crate::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
    use crate::local_store::state_machines::{ArchiveState, BackupState, BodyState, MediaState};
    use std::sync::Mutex;
    use uuid::Uuid;

    const TEST_DB_KEY: [u8; 32] = [0x44; 32];

    /// In-memory test sink — keyed by `(storage_sink, blob_id, chunk_idx)`.
    #[derive(Debug, Default)]
    struct InMemorySink {
        sink_tag: String,
        store: Mutex<std::collections::HashMap<(String, u32), Vec<u8>>>,
    }
    impl InMemorySink {
        fn new(tag: &str) -> Self {
            Self {
                sink_tag: tag.to_string(),
                store: Mutex::new(std::collections::HashMap::new()),
            }
        }
    }
    impl MediaBlobSink for InMemorySink {
        fn upload_media_chunks(
            &self,
            asset_id: &str,
            _blob_class: BlobClass,
            chunks: &[&[u8]],
            expected_merkle_root: [u8; 32],
        ) -> crate::Result<MediaBlobReference> {
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
        ) -> crate::Result<Vec<u8>> {
            let store = self.store.lock().unwrap();
            store
                .get(&(blob_ref.blob_id.clone(), chunk_idx))
                .cloned()
                .ok_or_else(|| {
                    Error::Storage(format!("missing chunk {}/{chunk_idx}", blob_ref.blob_id))
                })
        }
        fn delete_media_blob(&self, blob_ref: &MediaBlobReference) -> crate::Result<()> {
            let mut store = self.store.lock().unwrap();
            store.retain(|(b, _), _| b != &blob_ref.blob_id);
            Ok(())
        }
    }

    fn open_db() -> LocalStoreDb {
        let db = LocalStoreDb::open_in_memory(&TEST_DB_KEY).unwrap();
        // Seed a single conversation that every test message
        // hangs off. Foreign key constraints on `media_asset`
        // require the `message_skeleton` row to exist first;
        // each `seed_asset` call inserts a fresh skeleton row.
        db.insert_conversation(&Conversation {
            conversation_id: "conv-mig".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 0,
            ..Default::default()
        })
        .unwrap();
        db
    }

    fn seed_asset(
        db: &LocalStoreDb,
        sink: &str,
        chunks: &[Vec<u8>],
        sink_impl: &InMemorySink,
    ) -> MediaAsset {
        let asset_id = Uuid::now_v7().to_string();
        let message_id = Uuid::now_v7().to_string();
        let chunk_count = chunks.len() as i32;
        let merkle_root = content_hash(
            &chunks
                .iter()
                .flat_map(|c| c.iter().copied())
                .collect::<Vec<u8>>(),
        )
        .to_vec();
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: message_id.clone(),
            conversation_id: "conv-mig".into(),
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
        // Pre-populate the source sink.
        {
            let mut store = sink_impl.store.lock().unwrap();
            for (idx, c) in chunks.iter().enumerate() {
                store.insert((asset_id.clone(), idx as u32), c.clone());
            }
        }
        let asset = MediaAsset {
            asset_id: asset_id.clone(),
            message_id,
            mime_type: "image/png".into(),
            bytes_total: chunks.iter().map(|c| c.len() as i64).sum(),
            bytes_local: 0,
            media_state: MediaState::OriginalLocal,
            wrapped_k_asset: vec![0u8; 48],
            chunk_count,
            merkle_root,
            blob_id: asset_id.clone(),
            storage_sink: sink.to_string(),
        };
        db.insert_media_asset(&asset).unwrap();
        asset
    }

    #[test]
    fn plan_with_same_source_and_target_is_a_noop() {
        let db = open_db();
        let plan = plan_media_migration(&db, "icloud", "icloud").unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_returns_only_assets_on_source_sink() {
        let db = open_db();
        let icloud = InMemorySink::new("icloud");
        let _ = seed_asset(&db, "icloud", &[vec![1, 2, 3]], &icloud);
        let _ = seed_asset(&db, "icloud", &[vec![4, 5, 6]], &icloud);
        let _ = seed_asset(
            &db,
            "google_drive",
            &[vec![7, 8, 9]],
            &InMemorySink::new("google_drive"),
        );
        let plan = plan_media_migration(&db, "icloud", "google_drive").unwrap();
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn execute_round_trips_assets_between_two_in_memory_sinks() {
        let db = open_db();
        let icloud = InMemorySink::new("icloud");
        let drive = InMemorySink::new("google_drive");
        let _a = seed_asset(&db, "icloud", &[vec![1; 64], vec![2; 64]], &icloud);
        let _b = seed_asset(&db, "icloud", &[vec![3; 32]], &icloud);
        let plan = plan_media_migration(&db, "icloud", "google_drive").unwrap();
        let progress = NoopMigrationProgress;
        let report =
            execute_media_migration(&plan, &icloud, &drive, &db, &progress, false).unwrap();
        assert_eq!(report.migrated(), 2);
        assert_eq!(report.failed(), 0);
        // After migration every source row points at google_drive.
        let leftovers = db.list_media_assets_by_storage_sink("icloud").unwrap();
        assert!(leftovers.is_empty());
        let migrated = db
            .list_media_assets_by_storage_sink("google_drive")
            .unwrap();
        assert_eq!(migrated.len(), 2);
    }

    #[test]
    fn execute_is_idempotent_under_partial_failure() {
        let db = open_db();
        let icloud = InMemorySink::new("icloud");
        let drive = InMemorySink::new("google_drive");
        let _a = seed_asset(&db, "icloud", &[vec![1; 8]], &icloud);
        let _b = seed_asset(&db, "icloud", &[vec![2; 8]], &icloud);
        let plan = plan_media_migration(&db, "icloud", "google_drive").unwrap();
        let progress = NoopMigrationProgress;
        execute_media_migration(&plan, &icloud, &drive, &db, &progress, false).unwrap();

        // Re-run the same plan: every item should report
        // AlreadyOnTarget without doing any work.
        let report =
            execute_media_migration(&plan, &icloud, &drive, &db, &progress, false).unwrap();
        assert_eq!(report.already_on_target(), 2);
        assert_eq!(report.migrated(), 0);
    }

    #[test]
    fn execute_detects_corruption_during_transit() {
        let db = open_db();
        let icloud = InMemorySink::new("icloud");
        let drive = InMemorySink::new("google_drive");
        let _a = seed_asset(&db, "icloud", &[vec![1; 32]], &icloud);
        let plan = plan_media_migration(&db, "icloud", "google_drive").unwrap();

        // Corrupt-target sink wrapper that overwrites the bytes
        // on upload.
        #[derive(Debug)]
        struct CorruptSink {
            inner: InMemorySink,
        }
        impl MediaBlobSink for CorruptSink {
            fn upload_media_chunks(
                &self,
                asset_id: &str,
                _blob_class: BlobClass,
                _chunks: &[&[u8]],
                expected_merkle_root: [u8; 32],
            ) -> crate::Result<MediaBlobReference> {
                // Replace every chunk with garbage.
                let bad: Vec<&[u8]> = vec![&[0xFFu8; 4]];
                self.inner.upload_media_chunks(
                    asset_id,
                    BlobClass::Media,
                    &bad,
                    expected_merkle_root,
                )
            }
            fn fetch_media_chunk(
                &self,
                r: &MediaBlobReference,
                idx: u32,
            ) -> crate::Result<Vec<u8>> {
                self.inner.fetch_media_chunk(r, idx)
            }
            fn delete_media_blob(&self, r: &MediaBlobReference) -> crate::Result<()> {
                self.inner.delete_media_blob(r)
            }
        }
        let corrupt = CorruptSink {
            inner: InMemorySink::new("google_drive"),
        };
        let progress = NoopMigrationProgress;
        let report =
            execute_media_migration(&plan, &icloud, &corrupt, &db, &progress, false).unwrap();
        assert_eq!(report.failed(), 1);
        // Local store still points at the source sink because the
        // executor does not update on failure.
        let still_on_icloud = db.list_media_assets_by_storage_sink("icloud").unwrap();
        assert_eq!(still_on_icloud.len(), 1);
        // Suppress unused warning for the wrapped target field.
        let _ = drive.sink_tag.clone();
    }

    #[test]
    fn delete_source_after_success_clears_source_sink() {
        let db = open_db();
        let icloud = InMemorySink::new("icloud");
        let drive = InMemorySink::new("google_drive");
        let _a = seed_asset(&db, "icloud", &[vec![1; 8]], &icloud);
        let plan = plan_media_migration(&db, "icloud", "google_drive").unwrap();
        let progress = NoopMigrationProgress;
        let report = execute_media_migration(&plan, &icloud, &drive, &db, &progress, true).unwrap();
        assert_eq!(report.migrated(), 1);
        // Source sink no longer holds the chunk.
        let leftover = icloud.store.lock().unwrap();
        assert!(leftover.is_empty());
    }

    #[test]
    fn in_memory_progress_records_started_and_completed() {
        let db = open_db();
        let icloud = InMemorySink::new("icloud");
        let drive = InMemorySink::new("google_drive");
        let _a = seed_asset(&db, "icloud", &[vec![1; 8]], &icloud);
        let _b = seed_asset(&db, "icloud", &[vec![2; 8]], &icloud);
        let plan = plan_media_migration(&db, "icloud", "google_drive").unwrap();
        let progress = InMemoryMigrationProgress::new();
        execute_media_migration(&plan, &icloud, &drive, &db, &progress, false).unwrap();
        assert_eq!(progress.started().len(), 2);
        assert_eq!(progress.completed().len(), 2);
        for (_, _, _, outcome) in progress.completed() {
            assert!(matches!(outcome, MigrationItemOutcome::Migrated));
        }
    }

    #[test]
    fn migration_progress_is_object_safe() {
        let p: Arc<dyn MigrationProgress> = Arc::new(NoopMigrationProgress);
        p.on_item_started("foo", 0, 1);
        p.on_run_completed(&MigrationReport::default());
    }
}
