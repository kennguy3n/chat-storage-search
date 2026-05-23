//! End-to-end integration test for the storage budget
//! enforcement pipeline.
//!
//! `docs/DESIGN.md §5.4` and the "tiered
//! eviction" entry tie the budget enforcer, the eviction priority
//! order, and the tiered (cloud-offload-first) policy together
//! into one pipeline:
//!
//! 1. [`crate::offload::budget::StorageBudgetEnforcer`] reads
//!    `media_asset.bytes_local` and surfaces a
//!    [`crate::offload::budget::PressureLevel`].
//! 2. [`crate::offload::eviction::collect_eviction_candidates`]
//!    surfaces a candidate pool, excluding pinned conversations
//!    and non-archived assets.
//! 3. [`crate::offload::eviction::plan_tiered_eviction`] splits the
//!    pool into a cloud-offload pass and a full-eviction pass and
//!    burns through the byte budget cheap-first.
//! 4. [`crate::offload::eviction::execute_eviction`] applies the
//!    plans, transitioning each affected `media_asset.media_state`
//!    to `'evicted'` and zeroing `bytes_local`.
//!
//! Each per-module unit test in `src/offload/{budget,scoring,
//! eviction}.rs` covers exactly one layer of this pipeline; this
//! integration test seeds a fully-shaped `LocalStoreDb` and walks
//! every layer in order so a future regression in any one of them
//! shows up here, not just at the unit-test boundary.

use std::collections::HashMap;

use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
use kchat_core::local_store::state_machines::{ArchiveState, BackupState, BodyState, MediaState};
use kchat_core::offload::budget::{PressureLevel, StorageBudget, StorageBudgetEnforcer};
use kchat_core::offload::eviction::{
    collect_eviction_candidates, execute_eviction, plan_tiered_eviction, EvictionTier,
};
use uuid::Uuid;

const DB_KEY: [u8; 32] = [0x77; 32];

/// `min_offload_age_ms` knob — keep the test fixtures younger than
/// this and they will be excluded from the candidate pool. The
/// integration test deliberately seeds rows older than the cutoff
/// so the eviction surface is non-empty.
const MIN_OFFLOAD_AGE_MS: i64 = 24 * 60 * 60 * 1000;

/// `now_ms` for the test scenario. Fixed at 7 days past
/// `MIN_OFFLOAD_AGE_MS` so every seeded row clears the cutoff.
fn now_ms() -> i64 {
    // 7 days expressed in ms, well past the 24h cutoff.
    7 * 24 * 60 * 60 * 1000
}

/// Lightweight registry that maps a logical fixture label
/// (e.g. `"a-cloud"`) to the UUID actually persisted to
/// `media_asset.asset_id`. Schema validation rejects non-UUID
/// strings, so the integration tests pre-mint a UUID per label.
#[derive(Debug, Default)]
struct Fixture {
    conv_ids: HashMap<&'static str, Uuid>,
    asset_ids: HashMap<&'static str, Uuid>,
    message_ids: HashMap<&'static str, Uuid>,
}

impl Fixture {
    fn conv(&mut self, label: &'static str) -> Uuid {
        *self.conv_ids.entry(label).or_insert_with(Uuid::now_v7)
    }
    fn asset(&mut self, label: &'static str) -> Uuid {
        *self.asset_ids.entry(label).or_insert_with(Uuid::now_v7)
    }
    fn message(&mut self, label: &'static str) -> Uuid {
        *self.message_ids.entry(label).or_insert_with(Uuid::now_v7)
    }
    fn asset_lookup(&self, label: &'static str) -> &Uuid {
        self.asset_ids
            .get(label)
            .unwrap_or_else(|| panic!("asset label not registered: {label}"))
    }
}

fn insert_conversation(db: &LocalStoreDb, id: &Uuid, pinned: bool) {
    db.insert_conversation(&Conversation {
        conversation_id: id.to_string(),
        title_cipher: None,
        pinned,
        muted: false,
        last_message_id: None,
        last_activity_ms: 1,
        ..Default::default()
    })
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn insert_media_message(
    db: &LocalStoreDb,
    conv_id: &Uuid,
    message_id: &Uuid,
    asset_id: &Uuid,
    mime_type: &str,
    bytes_local: i64,
    archive_state: ArchiveState,
    storage_sink: &str,
    media_state: MediaState,
    created_at_ms: i64,
) {
    db.insert_message_skeleton(&MessageSkeleton {
        message_id: message_id.to_string(),
        conversation_id: conv_id.to_string(),
        sender_id: "sender".into(),
        created_at_ms,
        received_at_ms: created_at_ms,
        kind: MessageKind::Media,
        body_state: BodyState::LocalPlainAvailable,
        media_state: Some(media_state),
        archive_state,
        backup_state: BackupState::NotBackedUp,
        reply_to: None,
        edited_at_ms: None,
        deleted_at_ms: None,
    })
    .unwrap();

    db.insert_media_asset(&MediaAsset {
        asset_id: asset_id.to_string(),
        message_id: message_id.to_string(),
        mime_type: mime_type.into(),
        bytes_total: bytes_local,
        bytes_local,
        media_state,
        wrapped_k_asset: vec![0u8; 40],
        chunk_count: 1,
        merkle_root: vec![0u8; 32],
        blob_id: format!("blob-{asset_id}"),
        storage_sink: storage_sink.into(),
    })
    .unwrap();
}

/// Tight budget that keeps the math easy:
///
/// * `max_bytes` = 100 KiB
/// * `warning_threshold` = 50 % → 50 KiB
/// * `critical_threshold`= 75 % → 75 KiB
fn tight_budget() -> StorageBudget {
    StorageBudget {
        max_bytes: 100 * 1024,
        warning_threshold_pct: 50,
        critical_threshold_pct: 75,
    }
}

fn fresh_db() -> LocalStoreDb {
    LocalStoreDb::open_in_memory(&DB_KEY).expect("open_in_memory")
}

fn run_pipeline(
    db: &LocalStoreDb,
    budget: StorageBudget,
) -> (PressureLevel, kchat_core::offload::eviction::EvictionResult) {
    let enforcer = StorageBudgetEnforcer::new();
    let assessment = enforcer.assess(db.connection(), &budget).unwrap();
    if !assessment.pressure_level.requires_eviction() {
        return (
            assessment.pressure_level,
            kchat_core::offload::eviction::EvictionResult::default(),
        );
    }
    let target = assessment.eviction_target_bytes();
    let candidates =
        collect_eviction_candidates(db.connection(), MIN_OFFLOAD_AGE_MS, now_ms()).unwrap();
    let plan = plan_tiered_eviction(candidates, target, now_ms(), assessment.pressure_level);
    let cloud = execute_eviction(db.connection(), &plan.cloud_offload).unwrap();
    let full = execute_eviction(db.connection(), &plan.full_eviction).unwrap();
    let combined = kchat_core::offload::eviction::EvictionResult {
        freed_bytes: cloud.freed_bytes.saturating_add(full.freed_bytes),
        evicted_count: cloud.evicted_count.saturating_add(full.evicted_count),
    };
    (assessment.pressure_level, combined)
}

fn lookup_asset(db: &LocalStoreDb, fixture: &Fixture, label: &'static str) -> MediaAsset {
    db.get_media_asset(&fixture.asset_lookup(label).to_string())
        .unwrap()
        .unwrap()
}

#[test]
fn pressure_none_evicts_nothing() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let conv = fix.conv("c1");
    insert_conversation(&db, &conv, false);

    insert_media_message(
        &db,
        &conv,
        &fix.message("m1"),
        &fix.asset("a1"),
        "image/png",
        1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );

    let (pressure, result) = run_pipeline(&db, tight_budget());
    assert_eq!(pressure, PressureLevel::None);
    assert_eq!(result.evicted_count, 0);
    assert_eq!(result.freed_bytes, 0);

    let asset = lookup_asset(&db, &fix, "a1");
    assert_eq!(asset.media_state, MediaState::OriginalLocal);
    assert_eq!(asset.bytes_local, 1024);
}

#[test]
fn pinned_conversation_assets_are_never_evicted() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let pinned_conv = fix.conv("pinned");
    let regular_conv = fix.conv("regular");
    insert_conversation(&db, &pinned_conv, true);
    insert_conversation(&db, &regular_conv, false);

    // 60 KiB pinned + 60 KiB regular = 120 KiB > 100 KiB → Extreme.
    insert_media_message(
        &db,
        &pinned_conv,
        &fix.message("m-pinned"),
        &fix.asset("a-pinned"),
        "video/mp4",
        60 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );
    insert_media_message(
        &db,
        &regular_conv,
        &fix.message("m-regular"),
        &fix.asset("a-regular"),
        "video/mp4",
        60 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );

    let (pressure, result) = run_pipeline(&db, tight_budget());
    assert_eq!(pressure, PressureLevel::Extreme);
    assert!(result.evicted_count >= 1, "regular asset must be evicted");

    let pinned = lookup_asset(&db, &fix, "a-pinned");
    assert_eq!(pinned.media_state, MediaState::OriginalLocal);
    assert_eq!(pinned.bytes_local, 60 * 1024);

    let regular = lookup_asset(&db, &fix, "a-regular");
    assert_eq!(regular.media_state, MediaState::Evicted);
    assert_eq!(regular.bytes_local, 0);
}

#[test]
fn non_archived_assets_are_never_evicted() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let conv = fix.conv("c1");
    insert_conversation(&db, &conv, false);

    insert_media_message(
        &db,
        &conv,
        &fix.message("m-archived"),
        &fix.asset("a-archived"),
        "video/mp4",
        60 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-pending"),
        &fix.asset("a-pending"),
        "video/mp4",
        60 * 1024,
        ArchiveState::NotArchived,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );

    let (_, result) = run_pipeline(&db, tight_budget());
    assert_eq!(result.evicted_count, 1);
    let archived = lookup_asset(&db, &fix, "a-archived");
    assert_eq!(archived.media_state, MediaState::Evicted);
    let pending = lookup_asset(&db, &fix, "a-pending");
    assert_eq!(pending.media_state, MediaState::OriginalLocal);
}

#[test]
fn priority_order_video_before_image_before_voice() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let conv = fix.conv("c1");
    insert_conversation(&db, &conv, false);

    // Each clip is 30 KiB; total 90 KiB → 90% > 75% critical → Critical.
    // Eviction target = total - critical_bytes = 90 - 75 = 15 KiB.
    // Candidates ordered by content-kind weight: video first.
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-img"),
        &fix.asset("a-img"),
        "image/png",
        30 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-vid"),
        &fix.asset("a-vid"),
        "video/mp4",
        30 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-voice"),
        &fix.asset("a-voice"),
        "audio/m4a",
        30 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );

    let (pressure, result) = run_pipeline(&db, tight_budget());
    assert_eq!(pressure, PressureLevel::Critical);
    // Only one asset needs to be evicted to free 15 KiB; the video
    // wins by content-kind weight.
    assert_eq!(result.evicted_count, 1);
    assert_eq!(result.freed_bytes, 30 * 1024);
    let vid = lookup_asset(&db, &fix, "a-vid");
    assert_eq!(vid.media_state, MediaState::Evicted);
    let img = lookup_asset(&db, &fix, "a-img");
    assert_eq!(img.media_state, MediaState::OriginalLocal);
    let voice = lookup_asset(&db, &fix, "a-voice");
    assert_eq!(voice.media_state, MediaState::OriginalLocal);
}

#[test]
fn tiered_eviction_drains_cloud_offload_before_full_eviction() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let conv = fix.conv("c1");
    insert_conversation(&db, &conv, false);

    // 60 KiB on iCloud + 60 KiB on KChat backend = 120 KiB →
    // Extreme. Target = 120 - 100 = 20 KiB. Cloud pool covers
    // the budget; the KChat-backend asset must remain.
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-cloud"),
        &fix.asset("a-cloud"),
        "video/mp4",
        60 * 1024,
        ArchiveState::ArchiveVerified,
        "icloud",
        MediaState::OriginalLocal,
        0,
    );
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-backend"),
        &fix.asset("a-backend"),
        "video/mp4",
        60 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );

    // Tier-classification spot check before the pipeline runs.
    let cands = collect_eviction_candidates(db.connection(), MIN_OFFLOAD_AGE_MS, now_ms()).unwrap();
    let cloud = cands
        .iter()
        .find(|c| c.storage_sink == "icloud")
        .expect("cloud candidate");
    let backend = cands
        .iter()
        .find(|c| c.storage_sink == "kchat_backend")
        .expect("backend candidate");
    assert_eq!(EvictionTier::classify(cloud), EvictionTier::CloudOffload);
    assert_eq!(EvictionTier::classify(backend), EvictionTier::FullEviction);

    let (_, result) = run_pipeline(&db, tight_budget());
    assert_eq!(result.evicted_count, 1);
    let cloud_row = lookup_asset(&db, &fix, "a-cloud");
    assert_eq!(cloud_row.media_state, MediaState::Evicted);
    let backend_row = lookup_asset(&db, &fix, "a-backend");
    assert_eq!(backend_row.media_state, MediaState::OriginalLocal);
}

#[test]
fn tiered_eviction_falls_through_when_cloud_pool_is_too_small() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let conv = fix.conv("c1");
    insert_conversation(&db, &conv, false);

    // 5 KiB on iCloud + 60 KiB on backend + 60 KiB on backend =
    // 125 KiB → Extreme. Target = 25 KiB. Cloud only frees 5 KiB
    // (under target); planner falls through to evict 1 backend
    // asset (60 KiB).
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-cloud"),
        &fix.asset("a-cloud"),
        "video/mp4",
        5 * 1024,
        ArchiveState::ArchiveVerified,
        "icloud",
        MediaState::OriginalLocal,
        0,
    );
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-b1"),
        &fix.asset("a-b1"),
        "video/mp4",
        60 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-b2"),
        &fix.asset("a-b2"),
        "video/mp4",
        60 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );

    let (_, result) = run_pipeline(&db, tight_budget());
    assert_eq!(result.evicted_count, 2);
    let cloud_row = lookup_asset(&db, &fix, "a-cloud");
    assert_eq!(cloud_row.media_state, MediaState::Evicted);
    let backend_evicted = ["a-b1", "a-b2"]
        .into_iter()
        .filter(|label| lookup_asset(&db, &fix, label).media_state == MediaState::Evicted)
        .count();
    assert_eq!(backend_evicted, 1, "exactly one backend asset evicted");
}

#[test]
fn freed_bytes_and_evicted_count_match_actual_evictions() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let conv = fix.conv("c1");
    insert_conversation(&db, &conv, false);

    // Three videos at 30 KiB each = 90 KiB → Critical.
    // Target = 15 KiB. Plan picks one video.
    let labels: [&'static str; 3] = ["a1", "a2", "a3"];
    let messages: [&'static str; 3] = ["m1", "m2", "m3"];
    for i in 0..3 {
        insert_media_message(
            &db,
            &conv,
            &fix.message(messages[i]),
            &fix.asset(labels[i]),
            "video/mp4",
            30 * 1024,
            ArchiveState::ArchiveVerified,
            "kchat_backend",
            MediaState::OriginalLocal,
            0,
        );
    }

    let (_, result) = run_pipeline(&db, tight_budget());
    assert_eq!(result.evicted_count, 1);
    assert_eq!(result.freed_bytes, 30 * 1024);

    // The actual count of `media_state = 'evicted'` rows must
    // match `evicted_count`.
    let row_count: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM media_asset WHERE media_state = 'evicted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(row_count as u32, result.evicted_count);

    let evicted_local: i64 = db
        .connection()
        .query_row(
            "SELECT COALESCE(SUM(bytes_local), 0) FROM media_asset WHERE media_state = 'evicted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(evicted_local, 0);
}

#[test]
fn extreme_pressure_evicts_video_first_under_severe_overload() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let conv = fix.conv("c1");
    insert_conversation(&db, &conv, false);

    // Single 200 KiB video → 200 % usage → Extreme. The video is
    // the only candidate and gets dropped.
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-vid"),
        &fix.asset("a-vid"),
        "video/mp4",
        200 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );

    let (pressure, result) = run_pipeline(&db, tight_budget());
    assert_eq!(pressure, PressureLevel::Extreme);
    assert_eq!(result.evicted_count, 1);
    let vid = lookup_asset(&db, &fix, "a-vid");
    assert_eq!(vid.media_state, MediaState::Evicted);
}

#[test]
fn warning_pressure_evicts_originals_only() {
    let db = fresh_db();
    let mut fix = Fixture::default();
    let conv = fix.conv("c1");
    insert_conversation(&db, &conv, false);

    // 60 KiB image (>50 KiB warning, <75 KiB critical) → Warning.
    // Target = 60 - 50 = 10 KiB. The image is the only candidate.
    insert_media_message(
        &db,
        &conv,
        &fix.message("m-img"),
        &fix.asset("a-img"),
        "image/png",
        60 * 1024,
        ArchiveState::ArchiveVerified,
        "kchat_backend",
        MediaState::OriginalLocal,
        0,
    );

    let (pressure, result) = run_pipeline(&db, tight_budget());
    assert_eq!(pressure, PressureLevel::Warning);
    assert_eq!(result.evicted_count, 1);
    assert!(result.freed_bytes >= 10 * 1024);
}
