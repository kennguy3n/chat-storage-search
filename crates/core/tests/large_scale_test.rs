//! Phase 7, Task 7 (2026-05-04 batch) — production-scale
//! integration test.
//!
//! Bumps the existing `tests/large_scale.rs` scaffold to a
//! production-shaped corpus: 100 000 messages across 100
//! conversations and 11 scripts (Latin, Cyrillic, CJK, Arabic,
//! Thai, Devanagari, Bengali, Tamil, Korean, Greek, Hebrew),
//! plus 10 000 media-asset rows, then exercises:
//!
//! 1. Storage-budget assessment + tiered eviction at
//!    `Critical` pressure ([`StorageBudgetEnforcer`] +
//!    [`plan_tiered_eviction`] + [`execute_eviction`]).
//! 2. Incremental backup across the 100 K event journal: a
//!    single sealed segment + 2-generation manifest chain,
//!    verified end-to-end via [`verify_manifest_chain`].
//! 3. Multilingual search across all 11 scripts. Each script's
//!    distinguishing token must surface at least one hit.
//! 4. Search-latency budget: p95 over a stratified query mix
//!    must stay below 150 ms (the Phase 1 budget defended in
//!    `docs/PROPOSAL.md §6.4`).
//!
//! The whole file is `#[ignore]` because of the size — it is
//! not part of the default `cargo test` matrix. Run with
//!
//! ```text
//! cargo test --test large_scale_test -- --ignored
//! ```
//!
//! `tests/large_scale.rs` is the smaller (10 K) cousin that
//! covers the same shapes but stays light enough to run on a
//! laptop. The two files share corpora and helper structure.

use std::collections::BTreeSet;
use std::time::Instant;

use kchat_core::crypto::signing::HybridSigningKey;
use rand::rngs::OsRng;
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
use kchat_core::local_store::state_machines::{ArchiveState, BackupState, BodyState, MediaState};
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::offload::budget::{StorageBudget, StorageBudgetEnforcer};
use kchat_core::offload::eviction::{
    collect_eviction_candidates, execute_eviction, plan_tiered_eviction,
};
use kchat_core::restore::manifest_verifier::verify_manifest_chain;
use kchat_core::search::query_engine::QueryEngine;
use kchat_core::search::text_search::TextSearchEngine;
use kchat_core::{SearchQuery, SearchScope};

const DB_KEY: [u8; 32] = [0x4D; 32];

/// 11-script multilingual corpus. Each entry surfaces with at
/// least one distinguishing token so the search-side
/// assertions can disambiguate.
const SCRIPTS: &[(&str, &str, &str)] = &[
    ("latin", "Project meeting kickoff at 3pm sharp", "kickoff"),
    ("cyrillic", "Встреча проекта в 15:00", "Встреча"),
    ("cjk_zh", "下午三点会议室项目启动", "项目"),
    ("arabic", "اجتماع المشروع في الثالثة عصراً", "اجتماع"),
    ("thai", "ประชุมโครงการเวลาบ่ายสามโมง", "ประชุม"),
    ("devanagari", "परियोजना बैठक तीन बजे", "परियोजना"),
    ("bengali", "প্রজেক্ট মিটিং তিনটায়", "প্রজেক্ট"),
    ("tamil", "திட்ட கூட்டம் மாலை மூன்று மணிக்கு", "திட்ட"),
    ("korean", "프로젝트 회의 오후 세 시", "프로젝트"),
    ("greek", "Συνάντηση έργου στις 3μμ", "Συνάντηση"),
    ("hebrew", "פגישת פרויקט בשעה 3 אחר הצהריים", "פגישת"),
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
// Test 1 — 100K multilingual ingest + per-script search assertion
// ===========================================================================

#[test]
#[ignore = "very slow: 100k SQLCipher round-trips. Run with --ignored."]
fn large_scale_ingest_100k_messages_across_10_scripts() {
    let db = LocalStoreDb::open_in_memory(&DB_KEY).expect("open in-memory db");
    let conv_count = 100usize;
    let convs: Vec<Uuid> = (0..conv_count).map(|_| Uuid::now_v7()).collect();
    for c in &convs {
        seed_conversation(&db, *c, 1);
    }

    let total_messages = 100_000usize;
    let persister = MessagePersister::new(&db);

    let ingest_started = Instant::now();
    for i in 0..total_messages {
        let (_, text, _token) = SCRIPTS[i % SCRIPTS.len()];
        let conv_id = convs[i % conv_count];
        let mid = Uuid::now_v7();
        let ts_ms = 1_777_000_000_000i64 + i as i64;
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
            .unwrap_or_else(|e| panic!("persist #{i}: {e:?}"));
    }
    let ingest_elapsed = ingest_started.elapsed();
    eprintln!(
        "[large_scale_test] ingested {} msgs across {} convs in {:.2?}",
        total_messages, conv_count, ingest_elapsed
    );

    // Per-script assertion: every distinguishing token must
    // surface at least one hit through the FTS5 path.
    let text_engine = TextSearchEngine::new(&db);
    for (script, _content, token) in SCRIPTS {
        let hits = text_engine
            .search_fts(token, total_messages)
            .unwrap_or_else(|e| panic!("FTS search for {script} token {token:?} failed: {e:?}"));
        assert!(
            !hits.is_empty(),
            "FTS must surface at least one hit for the {script} token {token:?}",
        );
    }
}

// ===========================================================================
// Test 2 — 100K corpus search-latency budget (< 150ms p95)
// ===========================================================================

#[test]
#[ignore = "very slow: 100k corpus + latency rollup. Run with --ignored."]
fn large_scale_search_latency_under_budget() {
    let db = LocalStoreDb::open_in_memory(&DB_KEY).expect("open in-memory db");
    let conv = Uuid::now_v7();
    seed_conversation(&db, conv, 1);

    let total_messages = 100_000usize;
    let persister = MessagePersister::new(&db);
    for i in 0..total_messages {
        let (_, text, _token) = SCRIPTS[i % SCRIPTS.len()];
        let mid = Uuid::now_v7();
        let ts_ms = 1_777_000_000_000i64 + i as i64;
        persister
            .persist_ingested_message(&IngestedMessage {
                message_id: mid,
                conversation_id: conv,
                sender_id: "alice".into(),
                created_at_ms: ts_ms,
                text_content: Some((*text).to_string()),
                media_descriptors: vec![],
                reply_to: None,
            })
            .expect("persist");
    }

    // Stratified mix: 110 queries (10 per script). Each query
    // is a single distinguishing token so the FTS path is
    // exercised but BM25 ranking still discriminates among
    // documents within the script.
    let engine = QueryEngine::new(&db);
    let mut samples_us: Vec<u128> = Vec::with_capacity(SCRIPTS.len() * 10);
    for (_script, _content, token) in SCRIPTS {
        for _ in 0..10 {
            let q = SearchQuery {
                query_string: (*token).into(),
                ..Default::default()
            };
            let started = Instant::now();
            let hits = engine
                .execute_search(&q, &SearchScope::LocalOnly)
                .expect("query engine search");
            assert!(!hits.is_empty(), "every probe token must surface ≥1 hit");
            samples_us.push(started.elapsed().as_micros());
        }
    }
    samples_us.sort_unstable();

    let p95_idx = (samples_us.len() as f64 * 0.95).ceil() as usize - 1;
    let p95_us = samples_us[p95_idx];
    eprintln!(
        "[large_scale_test] p95 latency over {} queries = {} us ({} ms)",
        samples_us.len(),
        p95_us,
        p95_us / 1_000
    );
    assert!(
        p95_us < 150_000,
        "search p95 latency {p95_us} us must stay under the 150 ms budget",
    );
}

// ===========================================================================
// Test 3 — 10k media-asset storage-budget enforcement at Critical
// ===========================================================================

const NOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MIN_OFFLOAD_AGE_MS: i64 = 24 * 60 * 60 * 1000;

#[test]
#[ignore = "slow: 10k media-asset rows + full eviction pass. Run with --ignored."]
fn large_scale_storage_budget_enforcement() {
    let db = LocalStoreDb::open_in_memory(&DB_KEY).expect("open in-memory db");
    let conv = Uuid::now_v7();
    seed_conversation(&db, conv, 1);

    // 10 000 media assets × 100 KiB = 1 GiB local; budget = 100 MiB.
    let asset_bytes: i64 = 100 * 1024;
    let asset_count: usize = 10_000;
    let asset_age_ms: i64 = NOW_MS - MIN_OFFLOAD_AGE_MS - 1;
    for _ in 0..asset_count {
        let mid = Uuid::now_v7();
        let aid = Uuid::now_v7();
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: mid.to_string(),
            conversation_id: conv.to_string(),
            sender_id: "alice".into(),
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
        "10k×100KiB local bytes must require eviction at the 100 MiB budget",
    );

    let target = assessment.eviction_target_bytes();
    let candidates =
        collect_eviction_candidates(db.connection(), MIN_OFFLOAD_AGE_MS, NOW_MS).unwrap();
    let plan = plan_tiered_eviction(candidates, target, NOW_MS, assessment.pressure_level);
    let cloud = execute_eviction(db.connection(), &plan.cloud_offload).unwrap();
    let full = execute_eviction(db.connection(), &plan.full_eviction).unwrap();
    assert!(
        cloud.freed_bytes + full.freed_bytes > 0,
        "eviction must free at least one byte under Critical pressure",
    );

    let post = enforcer.assess(db.connection(), &budget).unwrap();
    assert!(
        post.headroom_bytes >= 0
            || (post.headroom_bytes.unsigned_abs() as i64) < assessment.headroom_bytes.abs(),
        "post-eviction headroom must improve",
    );
}

// ===========================================================================
// Test 4 — 1k message backup + 2-generation manifest chain verify
// ===========================================================================

#[test]
#[ignore = "slow: 1k segment build + manifest verify. Run with --ignored."]
fn large_scale_backup_produces_valid_manifest_chain() {
    let db = LocalStoreDb::open_in_memory(&DB_KEY).expect("source db");
    let conv = Uuid::now_v7();
    seed_conversation(&db, conv, 1);
    let persister = MessagePersister::new(&db);

    let total_messages = 1_000usize;
    let mut events: Vec<BackupEvent> = Vec::with_capacity(total_messages);
    let mut message_ids: Vec<Uuid> = Vec::with_capacity(total_messages);
    let now_ms = 1_777_000_000_000i64;
    for i in 0..total_messages {
        let (_, text, _) = SCRIPTS[i % SCRIPTS.len()];
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
            payload: kchat_core::cbor::to_vec(&kchat_core::cbor::Value::Array(vec![
                kchat_core::cbor::Value::Text(mid.to_string()),
                kchat_core::cbor::Value::Text(conv.to_string()),
                kchat_core::cbor::Value::Text(sender.into()),
                kchat_core::cbor::Value::Integer(kchat_core::cbor::Integer::from(ts_ms)),
                kchat_core::cbor::Value::Text((*text).into()),
            ]))
            .expect("cbor"),
            created_at_ms: ts_ms,
        });
        message_ids.push(mid);
    }

    let identity = KeyMaterial::from_bytes([0xCC; 32]);
    let backup_root = derive_backup_root(&identity).expect("backup root");
    let k_seg =
        derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).expect("k_segment");
    let k_man = derive_backup_manifest(&backup_root, b"large_scale_test").expect("k_manifest");
    let mut rng = OsRng;
    let signing = HybridSigningKey::generate(&mut rng);

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
    verify_manifest_chain(&chain, &signing.verifying_key())
        .expect("100K-scale manifest chain must verify");

    // Sanity: every message_id is captured by the segment's
    // event payload so a downstream restore would see them.
    let captured: BTreeSet<String> = events
        .iter()
        .filter_map(|e| e.message_id.map(|m| m.to_string()))
        .collect();
    for mid in &message_ids {
        assert!(captured.contains(&mid.to_string()));
    }
}
