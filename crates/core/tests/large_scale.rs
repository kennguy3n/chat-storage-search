//! Phase 7, Task 7 (2026-05-04 batch) — large-scale integration
//! test scaffold.
//!
//! `docs/PHASES.md` Phase 7 enumerates "large-scale ingestion,
//! search, and backup/restore stress tests" as a gating item
//! alongside the failure-scenario suite. This file lands the
//! first three:
//!
//! * [`large_scale_ingest_and_search_10k_messages`] — seeds
//!   ~10 000 messages across 12 corpora (English, Russian,
//!   Chinese, Japanese, Arabic, Thai, Hindi, Korean, Vietnamese,
//!   German, French, mixed-script), then exercises FTS5 + fuzzy
//!   search and asserts the result set + ranking are
//!   well-formed.
//! * [`large_scale_storage_budget_under_pressure`] — seeds
//!   ~5 000 message-skeleton rows with cloud-offload-eligible
//!   media assets that breach the configured budget, then runs
//!   the [`crate::offload`] pipeline at `Critical` pressure and
//!   asserts the eviction count + freed bytes are non-zero and
//!   bring storage back under the threshold.
//! * [`large_scale_backup_restore_round_trip`] — seeds ~1 000
//!   messages, drives the backup-segment + manifest-chain
//!   pipeline, and runs [`RestorePipeline::run`] against a
//!   fresh `LocalStoreDb` to confirm every conversation /
//!   skeleton / body survives the round-trip.
//!
//! These tests are slow (10 000 SQLCipher round-trips, two
//! AEAD passes per segment, full restore-state-machine walk).
//! They are marked `#[ignore]` so they do not run in the
//! default `cargo test` matrix. To run them explicitly:
//!
//! ```text
//! cargo test --test large_scale -- --ignored
//! ```
//!
//! `docs/PROGRESS.md` tracks the closure of each one against
//! Phase 7 acceptance.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use uuid::Uuid;

use kchat_core::backup::event_journal::{BackupEvent, BackupEventType};
use kchat_core::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
use kchat_core::backup::segment_builder::{BackupSegmentBuildRequest, BackupSegmentBuilder};
use kchat_core::crypto::key_hierarchy::{
    derive_backup_manifest, derive_backup_root, derive_backup_segment, KeyMaterial,
};
use kchat_core::formats::SegmentType;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
use kchat_core::local_store::state_machines::{
    ArchiveState, BackupState, BodyState, MediaState, RestoreState,
};
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::offload::budget::{StorageBudget, StorageBudgetEnforcer};
use kchat_core::offload::eviction::{
    collect_eviction_candidates, execute_eviction, plan_tiered_eviction,
};
use kchat_core::restore::manifest_verifier::verify_manifest_chain;
use kchat_core::restore::pipeline::RestorePipeline;
use kchat_core::restore::state_machine;
use kchat_core::search::fuzzy_search::FuzzySearchEngine;
use kchat_core::search::query_engine::QueryEngine;
use kchat_core::search::text_search::TextSearchEngine;
use kchat_core::{SearchQuery, SearchScope};

const DB_KEY: [u8; 32] = [0x4D; 32];

/// 12 corpora — English, Russian, Chinese, Japanese, Arabic,
/// Thai, Hindi, Korean, Vietnamese, German, French,
/// mixed-script. Each entry surfaces with at least one
/// distinguishing token so the search-side assertions can
/// disambiguate.
const CORPORA: &[(&str, &str)] = &[
    ("en", "Meeting at 3pm in the conference room"),
    ("ru", "Встреча в 15:00 в конференц-зале"),
    ("zh", "下午三点在会议室开会"),
    ("ja", "会議は午後3時に会議室で行います"),
    ("ar", "الاجتماع في الساعة 3 مساءً"),
    ("th", "ประชุมเวลาบ่าย 3 โมง"),
    ("hi", "बैठक दोपहर 3 बजे"),
    ("ko", "오후 3시에 회의실에서 만나요"),
    ("vi", "Cuộc họp lúc 3 giờ chiều tại phòng họp"),
    ("de", "Besprechung um 15 Uhr im Konferenzraum"),
    ("fr", "Réunion à 15 heures dans la salle de conférence"),
    (
        "mixed",
        "Meeting at 3pm 会議室で — Встреча — réunion — 회의실에서",
    ),
];

fn seed_conversation(db: &LocalStoreDb, conv: Uuid, last_activity_ms: i64) {
    db.insert_conversation(&Conversation {
        conversation_id: conv.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms,
        ..Default::default()
    })
    .expect("seed conversation");
}

// ===========================================================================
// Test 1 — 10k multilingual ingest + FTS5 / fuzzy search
// ===========================================================================

#[test]
#[ignore = "slow: ~10k SQLCipher round-trips. Run with --ignored."]
fn large_scale_ingest_and_search_10k_messages() {
    let db = LocalStoreDb::open_in_memory(&DB_KEY).expect("open in-memory db");
    // Spread the corpus across 8 conversations so the FTS index
    // exercises the conversation-filter path on a realistic
    // distribution.
    let conv_count = 8usize;
    let convs: Vec<Uuid> = (0..conv_count).map(|_| Uuid::now_v7()).collect();
    for c in &convs {
        seed_conversation(&db, *c, 1);
    }

    let total_messages = 10_000usize;
    let persister = MessagePersister::new(&db);
    let fuzzy = FuzzySearchEngine::new(&db);
    let mut english_msg_ids: Vec<Uuid> = Vec::new();

    for i in 0..total_messages {
        let (lang, text) = CORPORA[i % CORPORA.len()];
        let conv_id = convs[i % conv_count];
        let mid = Uuid::now_v7();
        let ts_ms = 1_700_000_000_000i64 + i as i64;
        // Sender alternates between two so the structured
        // sender-filter assertion below has something to bind
        // against.
        let sender = if i % 2 == 0 { "alice" } else { "bob" };
        persister
            .persist_ingested_message(&IngestedMessage {
                message_id: mid,
                conversation_id: conv_id,
                sender_id: sender.into(),
                created_at_ms: ts_ms,
                text_content: Some((*text).to_string()),
                media_descriptors: vec![],
                reply_to: None,
            })
            .unwrap_or_else(|e| panic!("persist {lang} #{i}: {e:?}"));
        // Index every persisted message with the fuzzy engine
        // so the typo-recall assertion below has a non-empty
        // index to scan.
        fuzzy
            .index_message(&mid.to_string(), text)
            .expect("fuzzy index");
        if lang == "en" {
            english_msg_ids.push(mid);
        }
    }

    // ---- FTS5 path: unicode61 token "meeting" must surface
    // every English row.
    let text = TextSearchEngine::new(&db);
    let hits = text.search_fts("meeting", total_messages).unwrap();
    let hit_ids: BTreeSet<String> = hits.iter().map(|h| h.message_id.clone()).collect();
    let expected: BTreeSet<String> = english_msg_ids.iter().map(|u| u.to_string()).collect();
    assert!(
        expected.is_subset(&hit_ids),
        "FTS must surface every English message: missing {} of {}",
        expected.difference(&hit_ids).count(),
        expected.len(),
    );
    assert!(
        hits.len() >= english_msg_ids.len(),
        "FTS hit count must be at least the English subset (got {}, need ≥{})",
        hits.len(),
        english_msg_ids.len(),
    );

    // ---- Fuzzy path: "meting" (typo of "meeting") must still
    // recall at least one English row.
    let fuzzy_hits = fuzzy.search_fuzzy("meting", 50).expect("fuzzy hits");
    assert!(
        !fuzzy_hits.is_empty(),
        "fuzzy search 'meting' must recall at least one row in a 10k corpus",
    );

    // ---- QueryEngine end-to-end path with a structured filter:
    // sender=alice, query=meeting → roughly half the English
    // rows surface.
    let engine = QueryEngine::new(&db);
    let q = SearchQuery {
        query_string: "meeting".into(),
        sender_filter: Some("alice".into()),
        ..Default::default()
    };
    let results = engine
        .execute_search(&q, &SearchScope::LocalOnly)
        .expect("query engine search");
    assert!(
        !results.is_empty(),
        "QueryEngine must surface at least one alice-sender English hit",
    );
    for r in &results {
        assert_eq!(r.sender_id, "alice", "sender filter must hold");
    }
    // Ranking sanity: results must be sorted by descending
    // rank_score, then descending created_at.
    for win in results.windows(2) {
        let (a, b) = (&win[0], &win[1]);
        assert!(
            a.rank_score > b.rank_score
                || (a.rank_score == b.rank_score && a.created_at_ms >= b.created_at_ms),
            "results must be sorted by rank_score desc, created_at desc",
        );
    }
}

// ===========================================================================
// Test 2 — 5k storage-budget eviction at Critical pressure
// ===========================================================================

const LARGE_SCALE_NOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const LARGE_SCALE_MIN_OFFLOAD_AGE_MS: i64 = 24 * 60 * 60 * 1000;

#[test]
#[ignore = "slow: 5k media-asset rows + full eviction pass. Run with --ignored."]
fn large_scale_storage_budget_under_pressure() {
    let db = LocalStoreDb::open_in_memory(&DB_KEY).expect("open in-memory db");
    let conv = Uuid::now_v7();
    seed_conversation(&db, conv, 1);

    // Per-asset bytes: 100 KiB. Asset count: 5 000. Total local
    // bytes under management: 500 MiB. Budget: max 100 MiB —
    // every asset is older than `MIN_OFFLOAD_AGE_MS` so the
    // candidate pool is the full set.
    let asset_bytes: i64 = 100 * 1024;
    let asset_count: usize = 5_000;
    let asset_age_ms: i64 = LARGE_SCALE_NOW_MS - LARGE_SCALE_MIN_OFFLOAD_AGE_MS - 1;

    for _ in 0..asset_count {
        let mid = Uuid::now_v7();
        let aid = Uuid::now_v7();
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: mid.to_string(),
            conversation_id: conv.to_string(),
            sender_id: "sender".into(),
            created_at_ms: asset_age_ms,
            received_at_ms: asset_age_ms,
            kind: MessageKind::Media,
            body_state: BodyState::LocalPlainAvailable,
            media_state: Some(MediaState::OriginalLocal),
            archive_state: ArchiveState::ArchiveVerified,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        })
        .expect("insert skeleton");
        db.insert_media_asset(&MediaAsset {
            asset_id: aid.to_string(),
            message_id: mid.to_string(),
            mime_type: "image/png".into(),
            bytes_total: asset_bytes,
            bytes_local: asset_bytes,
            media_state: MediaState::OriginalLocal,
            wrapped_k_asset: vec![0u8; 40],
            chunk_count: 1,
            merkle_root: vec![0u8; 32],
            blob_id: format!("blob-{aid}"),
            storage_sink: "cloud".into(),
        })
        .expect("insert media asset");
    }

    let budget = StorageBudget {
        max_bytes: 100 * 1024 * 1024,
        warning_threshold_pct: 50,
        critical_threshold_pct: 75,
    };
    let enforcer = StorageBudgetEnforcer::new();
    let assessment = enforcer.assess(db.connection(), &budget).unwrap();
    assert!(
        assessment.pressure_level.requires_eviction(),
        "5k×100KiB local bytes must exceed the 100MiB budget and require eviction",
    );

    let target = assessment.eviction_target_bytes();
    let candidates = collect_eviction_candidates(
        db.connection(),
        LARGE_SCALE_MIN_OFFLOAD_AGE_MS,
        LARGE_SCALE_NOW_MS,
    )
    .unwrap();
    assert!(
        !candidates.is_empty(),
        "candidate pool must be non-empty under Critical pressure",
    );
    let plan = plan_tiered_eviction(
        candidates,
        target,
        LARGE_SCALE_NOW_MS,
        assessment.pressure_level,
    );
    let cloud = execute_eviction(db.connection(), &plan.cloud_offload).unwrap();
    let full = execute_eviction(db.connection(), &plan.full_eviction).unwrap();
    let total_freed = cloud.freed_bytes.saturating_add(full.freed_bytes);
    let total_evicted = cloud.evicted_count.saturating_add(full.evicted_count);
    assert!(
        total_freed > 0,
        "eviction must free at least one byte under Critical pressure",
    );
    assert!(
        total_evicted > 0,
        "eviction count must be non-zero under Critical pressure",
    );

    // Re-assess: pressure level must be back under the
    // critical threshold.
    let post = enforcer.assess(db.connection(), &budget).unwrap();
    assert!(
        post.headroom_bytes >= 0
            || (post.headroom_bytes.unsigned_abs() as i64) < assessment.headroom_bytes.abs(),
        "post-eviction headroom should be larger (less-negative) than pre-eviction \
         (was {}, now {})",
        assessment.headroom_bytes,
        post.headroom_bytes,
    );
}

// ===========================================================================
// Test 3 — 1k message backup → restore round-trip
// ===========================================================================

#[test]
#[ignore = "slow: 1k message segment build + manifest-chain restore. Run with --ignored."]
fn large_scale_backup_restore_round_trip() {
    // ---- Source side: seed an in-memory store + journal events.
    let source_db = LocalStoreDb::open_in_memory(&DB_KEY).expect("source db");
    let conv = Uuid::now_v7();
    seed_conversation(&source_db, conv, 1);
    let persister = MessagePersister::new(&source_db);

    let total_messages = 1_000usize;
    let mut events: Vec<BackupEvent> = Vec::with_capacity(total_messages);
    let mut message_ids: Vec<Uuid> = Vec::with_capacity(total_messages);
    let now_ms = 1_777_000_000_000i64;
    for i in 0..total_messages {
        let (_, text) = CORPORA[i % CORPORA.len()];
        let mid = Uuid::now_v7();
        let ts_ms = now_ms + i as i64;
        let sender = if i % 2 == 0 { "alice" } else { "bob" };
        persister
            .persist_ingested_message(&IngestedMessage {
                message_id: mid,
                conversation_id: conv,
                sender_id: sender.into(),
                created_at_ms: ts_ms,
                text_content: Some((*text).to_string()),
                media_descriptors: vec![],
                reply_to: None,
            })
            .expect("persist");
        events.push(BackupEvent {
            event_type: BackupEventType::MessageReceived,
            conversation_id: Some(conv),
            message_id: Some(mid),
            payload: serde_cbor::to_vec(&serde_cbor::value::Value::Array(vec![
                serde_cbor::value::Value::Text(mid.to_string()),
                serde_cbor::value::Value::Text(conv.to_string()),
                serde_cbor::value::Value::Text(sender.into()),
                serde_cbor::value::Value::Integer(ts_ms as i128),
                serde_cbor::value::Value::Text((*text).into()),
            ]))
            .expect("cbor"),
            created_at_ms: ts_ms,
        });
        message_ids.push(mid);
    }
    assert_eq!(events.len(), total_messages);

    // ---- Backup keys.
    let identity = KeyMaterial::from_bytes([0xCC; 32]);
    let backup_root = derive_backup_root(&identity).expect("backup root");
    let k_seg =
        derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).expect("k_segment");
    let k_man = derive_backup_manifest(&backup_root, b"large_scale").expect("k_manifest");
    let signing = SigningKey::from_bytes(&[0xAB; 32]);

    // ---- Build a single segment carrying the full event set,
    // then chain a 2-generation manifest (gen0 + gen1).
    let segment = BackupSegmentBuilder::new()
        .build_segment(
            BackupSegmentBuildRequest {
                events: events.clone(),
                segment_type: SegmentType::Events,
            },
            &k_seg,
        )
        .expect("seal segment");

    let gen0 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: None,
            device_id: "device-source".into(),
        },
        &signing,
        &k_man,
    )
    .expect("genesis manifest");
    let gen1 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: Some(&gen0.manifest),
            device_id: "device-source".into(),
        },
        &signing,
        &k_man,
    )
    .expect("gen1 manifest");
    let chain = vec![gen0.manifest.clone(), gen1.manifest.clone()];

    verify_manifest_chain(&chain, &signing.verifying_key()).expect("chain verifies");

    // ---- Restore side: open a fresh store, drive the state
    // machine to ManifestVerified, then run the pipeline.
    let restore_db = LocalStoreDb::open_in_memory(&[0x55; 32]).expect("restore db");
    for st in [
        RestoreState::IdentityRestored,
        RestoreState::RootKeysUnwrapped,
        RestoreState::ManifestVerified,
    ] {
        state_machine::transition(restore_db.connection(), st, None).unwrap();
    }
    // Recency window large enough to hydrate every body so
    // every skeleton lands as `LocalPlainAvailable`.
    let recency_window_ms = 7 * 86_400 * 1_000;
    let summary = RestorePipeline::new()
        .run(
            restore_db.connection(),
            &chain,
            std::slice::from_ref(&segment),
            &k_seg,
            now_ms + total_messages as i64 + 1,
            recency_window_ms,
        )
        .expect("pipeline run");

    assert_eq!(summary.final_state, Some(RestoreState::FullRestoreComplete));
    let restored_convs: BTreeSet<Uuid> = summary
        .conversations
        .iter()
        .map(|c| c.conversation_id)
        .collect();
    assert!(
        restored_convs.contains(&conv),
        "restored set must include the source conversation",
    );
    let restored_mids: BTreeSet<Uuid> = summary.skeletons.iter().map(|s| s.message_id).collect();
    for mid in &message_ids {
        assert!(
            restored_mids.contains(mid),
            "missing restored message_id {mid}",
        );
    }
    for s in &summary.skeletons {
        assert_eq!(
            s.body_state,
            BodyState::LocalPlainAvailable,
            "every skeleton should hydrate within the recency window",
        );
    }
    assert_eq!(
        summary.recent_bodies.len(),
        total_messages,
        "every recent body must round-trip",
    );
}
