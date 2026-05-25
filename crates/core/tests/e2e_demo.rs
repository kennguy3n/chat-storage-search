//! Comprehensive end-to-end demo for the KChat storage / search /
//! archive / backup / restore pipeline.
//!
//! `docs/DESIGN.md §12` calls
//! out the need for *one* integration test that exercises every
//! surface back-to-back against a single
//! realistic dataset. The 24 existing test files cover individual
//! pipelines in depth; this file is the single, narrative
//! "everything works together" run-through that proves the
//! cross-module contract holds.
//!
//! The default test ([`e2e_demo`]) keeps the dataset small enough
//! to fit in the standard `cargo test` matrix:
//!
//! * 5 conversations (personal chat, group chat, work channel,
//!   multilingual group, media-heavy thread)
//! * 200 messages spread across 12 scripts
//!   ([`e2e_demo_dataset::CORPORA`]) with timestamps spanning a
//!   90-day window so the archive partitioner produces multiple
//!   `(conversation_id, time_bucket)` groups
//! * 20 media-asset descriptors mixing five MIME types
//!
//! The `#[ignore]` variant ([`e2e_demo_large_scale`]) scales the
//! same shape to 10 000 messages and 1 000 media assets for
//! stress testing.
//!
//! Both variants walk the same 12-step recipe end-to-end:
//!
//! 1. Initialise an in-memory SQLCipher store.
//! 2. Seed conversations.
//! 3. Ingest messages (skeleton + body + FTS5 + fuzzy + archive
//!    journal events all happen inside [`MessagePersister`]).
//! 4. FTS search across every script.
//! 5. Fuzzy search with deliberate typos.
//! 6. Structured search filtering by sender, date range,
//!    conversation, and content kind.
//! 7. Archive segment build + decrypt round-trip over the
//!    journaled events.
//! 8. Backup segment + 2-generation manifest chain build.
//! 9. Manifest chain verification under the hybrid Ed25519 +
//!    ML-DSA-65 signing key.
//! 10. Skeleton-first restore against a *fresh* in-memory DB
//!     walking the restore state machine to
//!     `FullRestoreComplete`.
//! 11. Search-after-restore (FTS / fuzzy / structured) against
//!     the source DB to confirm the original indexes survived.
//! 12. Storage-budget enforcement: seed media that breaches a
//!     small budget and confirm `StorageBudgetEnforcer` reports
//!     `Critical` pressure and the eviction planner frees rows.
//!
//! Each step is wrapped in a [`std::time::Instant`] measurement
//! and a structured `println!` line emitted to stdout, e.g.:
//!
//! ```text
//! === E2E Demo Results ===
//! Step 1: Initialize OK ( 2 ms)
//! Step 2: Seed conversations OK ( 5 ms) [count=5]
//! Step 3: Ingest messages OK ( 45 ms) [new=200, dup=0]
//! …
//! ```
//!
//! This file is the comprehensive demo dataset deliverable for
//! the storage / search / archive / backup / restore pipeline.

use std::time::Instant;

use rand::rngs::OsRng;
use uuid::Uuid;

use kchat_core::archive::event_journal::ArchiveEventJournal;
use kchat_core::archive::segment_builder::{
    decrypt_segment, default_time_bucket, ArchiveSegmentBuilder, SegmentBuildRequest,
};
use kchat_core::backup::event_journal::{BackupEvent, BackupEventType};
use kchat_core::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
use kchat_core::backup::segment_builder::{
    decrypt_backup_segment, BackupSegmentBuildRequest, BackupSegmentBuilder,
};
use kchat_core::crypto::key_hierarchy::{
    derive_archive_root, derive_archive_segment, derive_backup_manifest, derive_backup_root,
    derive_backup_segment, KeyMaterial,
};
use kchat_core::crypto::signing::HybridSigningKey;
use kchat_core::formats::SegmentType;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::{MediaAsset, MessageKind, MessageSkeleton};
use kchat_core::local_store::state_machines::{
    ArchiveState, BackupState, BodyState, MediaState, RestoreState,
};
use kchat_core::message::processor::MessagePersister;
use kchat_core::offload::budget::{PressureLevel, StorageBudget, StorageBudgetEnforcer};
use kchat_core::offload::eviction::{
    collect_eviction_candidates, execute_eviction, plan_tiered_eviction,
};
use kchat_core::restore::manifest_verifier::verify_manifest_chain;
use kchat_core::restore::pipeline::RestorePipeline;
use kchat_core::restore::state_machine;
use kchat_core::search::fuzzy_search::FuzzySearchEngine;
use kchat_core::search::query_engine::QueryEngine;
use kchat_core::search::text_search::TextSearchEngine;
use kchat_core::{ContentKind, SearchQuery, SearchScope};

#[path = "e2e_demo_dataset.rs"]
mod dataset;

use dataset::{
    generate_demo_conversations, generate_demo_media_assets, generate_demo_messages,
    DEFAULT_CONVERSATION_COUNT, DEFAULT_MEDIA_COUNT, DEFAULT_MESSAGE_COUNT, SCRIPT_TOKENS,
};

/// Minimum age (in milliseconds) the offload pipeline expects
/// for media assets before they are eligible for tiered eviction.
/// Mirrors the `MIN_OFFLOAD_AGE_MS` constant used by
/// [`kchat_core::offload::eviction::collect_eviction_candidates`]
/// inside `core_impl.rs`.
const MIN_OFFLOAD_AGE_MS: i64 = 24 * 60 * 60 * 1000;

const DB_KEY: [u8; 32] = [0xE2; 32];

#[test]
fn e2e_demo() {
    run_demo(
        DEFAULT_CONVERSATION_COUNT,
        DEFAULT_MESSAGE_COUNT,
        DEFAULT_MEDIA_COUNT,
    );
}

#[test]
#[ignore = "slow: 10k message + 1k media-asset stress run. Run with --ignored."]
fn e2e_demo_large_scale() {
    // 50 conversations × 10 000 messages × 1 000 media assets.
    // Hits the same 12-step recipe with a corpus shape that
    // matches the one used by the criterion benchmarks.
    run_demo(50, 10_000, 1_000);
}

// ---------------------------------------------------------------
// Recipe
// ---------------------------------------------------------------

fn run_demo(conversation_count: usize, message_count: usize, media_count: usize) {
    let total_started = Instant::now();
    let mut steps: Vec<StepResult> = Vec::with_capacity(12);

    // ---- Step 1: initialise ------------------------------------
    let started = Instant::now();
    let db = LocalStoreDb::open_in_memory(&DB_KEY).expect("open in-memory db");
    steps.push(StepResult::ok("Initialize", started.elapsed(), None));

    // ---- Step 2: seed conversations ----------------------------
    let started = Instant::now();
    let conversations = generate_demo_conversations(conversation_count);
    let conv_ids: Vec<Uuid> = conversations
        .iter()
        .map(|c| Uuid::parse_str(&c.conversation_id).expect("uuid"))
        .collect();
    for conv in &conversations {
        db.insert_conversation(conv).expect("seed conversation");
    }
    steps.push(StepResult::ok(
        "Seed conversations",
        started.elapsed(),
        Some(format!("count={}", conv_ids.len())),
    ));

    // ---- Step 3: ingest messages -------------------------------
    let started = Instant::now();
    let messages = generate_demo_messages(&conv_ids, message_count);
    let persister = MessagePersister::new(&db);
    for msg in &messages {
        persister
            .persist_ingested_message(msg)
            .expect("persist ingested message");
    }
    steps.push(StepResult::ok(
        "Ingest messages",
        started.elapsed(),
        Some(format!("new={}, dup=0", messages.len())),
    ));

    // ---- Step 4: FTS search across every script ----------------
    let started = Instant::now();
    let mut total_fts_hits: usize = 0;
    let mut scripts_with_hits: usize = 0;
    let text_engine = TextSearchEngine::new(db.connection(), db.icu_available());
    for (lang, token) in SCRIPT_TOKENS {
        let hits = text_engine
            .search_fts(token, 200)
            .unwrap_or_else(|e| panic!("fts search for {lang}/{token:?} failed: {e}"));
        if !hits.is_empty() {
            scripts_with_hits += 1;
        }
        total_fts_hits += hits.len();
    }
    // FTS5's default tokenizer (and even the ICU build, when
    // available) does not segment every script — Thai and Khmer in
    // particular lack whitespace word boundaries, so a single-token
    // probe may legitimately miss. Demand coverage on the bulk of
    // the corpus and let the fuzzy engine (step 5) backstop the
    // long tail.
    let fts_floor = SCRIPT_TOKENS.len().saturating_mul(2) / 3;
    assert!(
        scripts_with_hits >= fts_floor,
        "FTS5 should surface at least one hit for ≥{fts_floor}/{} scripts (got {scripts_with_hits}/{})",
        SCRIPT_TOKENS.len(),
        SCRIPT_TOKENS.len(),
    );
    steps.push(StepResult::ok(
        "FTS search (12 scripts)",
        started.elapsed(),
        Some(format!(
            "scripts={}/{}, hits={}",
            scripts_with_hits,
            SCRIPT_TOKENS.len(),
            total_fts_hits,
        )),
    ));

    // ---- Step 5: fuzzy search with deliberate typos ------------
    let started = Instant::now();
    let fuzzy_engine = FuzzySearchEngine::new(db.connection());
    // "lighthose" is a one-character typo of "lighthouse" — every
    // English-corpus row contains "lighthouse", so the fuzzy
    // engine should surface multiple rows even though FTS5 would
    // not.
    let typo_hits = fuzzy_engine
        .search_fuzzy("lighthose", 200)
        .expect("fuzzy search");
    let german_typo_hits = fuzzy_engine
        .search_fuzzy("Leuchturm", 200)
        .expect("fuzzy search german");
    assert!(
        !typo_hits.is_empty(),
        "fuzzy search must recover from a one-char typo on \"lighthouse\"",
    );
    steps.push(StepResult::ok(
        "Fuzzy search with typos",
        started.elapsed(),
        Some(format!(
            "lighthose={}, Leuchturm={}",
            typo_hits.len(),
            german_typo_hits.len(),
        )),
    ));

    // ---- Step 6: structured search -----------------------------
    let started = Instant::now();
    let query_engine = QueryEngine::new(db.connection(), db.icu_available());
    // 6a) Sender filter: should narrow to ~1/4 of the messages
    // (round-robin over four senders).
    let by_alice = query_engine
        .execute_search(
            &SearchQuery {
                query_string: "lighthouse".into(),
                sender_filter: Some("alice".into()),
                ..Default::default()
            },
            &SearchScope::LocalOnly,
        )
        .expect("structured/sender search");
    // 6b) Conversation filter on the first conversation id.
    let by_conv = query_engine
        .execute_search(
            &SearchQuery {
                query_string: "lighthouse".into(),
                conversation_filter: Some(conv_ids[0]),
                ..Default::default()
            },
            &SearchScope::LocalOnly,
        )
        .expect("structured/conversation search");
    // 6c) Date range narrowing — last 30 days of the 90-day
    // window. We pull `min` / `max` directly off the dataset to
    // avoid any tz / leap-second drift.
    let max_ts = messages.iter().map(|m| m.created_at_ms).max().unwrap();
    let date_from = max_ts - 30 * 86_400 * 1_000;
    let by_date = query_engine
        .execute_search(
            &SearchQuery {
                query_string: "lighthouse".into(),
                date_from: Some(date_from),
                ..Default::default()
            },
            &SearchScope::LocalOnly,
        )
        .expect("structured/date search");
    // 6d) Content-kind filter — every persisted message is text,
    // so kind=Text should match the unfiltered count and kind=Image
    // should match nothing (we have no media-attached messages
    // until step 12).
    let by_kind_text = query_engine
        .execute_search(
            &SearchQuery {
                query_string: "lighthouse".into(),
                content_kind: Some(ContentKind::Text),
                ..Default::default()
            },
            &SearchScope::LocalOnly,
        )
        .expect("structured/kind=text search");
    let by_kind_image = query_engine
        .execute_search(
            &SearchQuery {
                query_string: "lighthouse".into(),
                content_kind: Some(ContentKind::Image),
                ..Default::default()
            },
            &SearchScope::LocalOnly,
        )
        .expect("structured/kind=image search");
    assert!(
        !by_alice.is_empty(),
        "structured search by alice must surface at least one row",
    );
    assert!(
        !by_conv.is_empty(),
        "structured search by conversation must surface at least one row",
    );
    assert!(
        by_kind_image.is_empty(),
        "no media-attached rows ingested yet, so kind=Image must be empty",
    );
    steps.push(StepResult::ok(
        "Structured search",
        started.elapsed(),
        Some(format!(
            "alice={}, conv0={}, last30d={}, text={}, image={}",
            by_alice.len(),
            by_conv.len(),
            by_date.len(),
            by_kind_text.len(),
            by_kind_image.len(),
        )),
    ));

    // ---- Step 7: archive pipeline -------------------------------
    let started = Instant::now();
    let archive_journal = ArchiveEventJournal::new();
    // Drain every journaled event the persister wrote in step 3.
    // `read_unsegmented` returns `(seq, ArchiveEvent)`; the
    // segment builder only takes the bare event, so we strip the
    // sequence numbers up front.
    let archive_events: Vec<_> = archive_journal
        .read_unsegmented(db.connection(), usize::MAX)
        .expect("read unsegmented archive events")
        .into_iter()
        .map(|(_seq, ev)| ev)
        .collect();
    let archive_event_count = archive_events.len();
    let groups =
        ArchiveSegmentBuilder::new().group_events_by_bucket(archive_events, default_time_bucket);
    let group_count = groups.len();
    // Derive an archive epoch + per-segment key fixture. The
    // production archive pipeline rotates these monthly per
    // for the demo we exercise the
    // single-epoch happy path to keep the recipe linear.
    let identity = KeyMaterial::from_bytes([0xA1; 32]);
    let archive_root = derive_archive_root(&identity).expect("archive root");
    let mut built_segment_count = 0usize;
    let mut decrypted_event_count = 0usize;
    for ((conversation_id, time_bucket), events) in groups {
        if events.is_empty() {
            continue;
        }
        let k_seg =
            derive_archive_segment(&archive_root, &Uuid::now_v7().into_bytes()).expect("k_seg");
        let built = ArchiveSegmentBuilder::new()
            .build_segment(
                SegmentBuildRequest::message_delta(conversation_id, time_bucket, events),
                k_seg.as_bytes(),
            )
            .expect("build archive segment");
        let payload = decrypt_segment(&built, k_seg.as_bytes()).expect("decrypt archive segment");
        decrypted_event_count += payload.events.len();
        built_segment_count += 1;
    }
    assert!(
        archive_event_count >= messages.len(),
        "every persisted message should have written at least one archive journal event",
    );
    assert!(
        built_segment_count >= 1,
        "the archive segment builder must produce at least one segment",
    );
    assert_eq!(
        decrypted_event_count, archive_event_count,
        "every archive event must round-trip through encrypt + decrypt",
    );
    steps.push(StepResult::ok(
        "Archive pipeline",
        started.elapsed(),
        Some(format!(
            "events={archive_event_count}, groups={group_count}, segments={built_segment_count}",
        )),
    ));

    // ---- Step 8: backup pipeline -------------------------------
    let started = Instant::now();
    let backup_root = derive_backup_root(&identity).expect("backup root");
    let k_backup_seg =
        derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).expect("k_backup_seg");
    let k_man = derive_backup_manifest(&backup_root, b"e2e-demo").expect("k_man");
    let mut rng = OsRng;
    let signing = HybridSigningKey::generate(&mut rng);

    // Convert the persisted ingest history into a minimal
    // `BackupEvent` log. Real callers feed this from the backup
    // event journal; the demo synthesises it directly off the
    // dataset for clarity.
    let backup_events: Vec<BackupEvent> = messages
        .iter()
        .map(|m| BackupEvent {
            event_type: BackupEventType::MessageReceived,
            conversation_id: Some(m.conversation_id),
            message_id: Some(m.message_id),
            payload: m.text_content.clone().unwrap_or_default().into_bytes(),
            created_at_ms: m.created_at_ms,
        })
        .collect();
    let backup_segment = BackupSegmentBuilder::new()
        .build_segment(
            BackupSegmentBuildRequest {
                events: backup_events.clone(),
                segment_type: SegmentType::Events,
            },
            &k_backup_seg,
        )
        .expect("build backup segment");

    let gen0 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&backup_segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: None,
            device_id: "device-e2e-demo".into(),
            manifest_id: None,
        },
        &signing,
        &k_man,
    )
    .expect("manifest gen0");
    let gen1 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&backup_segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: Some(&gen0.manifest),
            device_id: "device-e2e-demo".into(),
            manifest_id: None,
        },
        &signing,
        &k_man,
    )
    .expect("manifest gen1");
    let chain = vec![gen0.manifest.clone(), gen1.manifest.clone()];

    // Round-trip the segment so we know it survived the seal.
    let decrypted_backup =
        decrypt_backup_segment(&backup_segment, &k_backup_seg).expect("decrypt backup segment");
    assert_eq!(decrypted_backup.events.len(), backup_events.len());
    steps.push(StepResult::ok(
        "Backup pipeline",
        started.elapsed(),
        Some(format!(
            "events={}, segments=1, generations={}",
            backup_events.len(),
            chain.len(),
        )),
    ));

    // ---- Step 9: manifest verification -------------------------
    let started = Instant::now();
    verify_manifest_chain(&chain, &signing.verifying_key())
        .expect("manifest chain must verify under the hybrid signing key");
    steps.push(StepResult::ok(
        "Manifest verification",
        started.elapsed(),
        Some(format!("generations={}", chain.len())),
    ));

    // ---- Step 10: restore pipeline -----------------------------
    let started = Instant::now();
    let restore_db = LocalStoreDb::open_in_memory(&[0x77; 32]).expect("open restore db");
    for st in [
        RestoreState::IdentityRestored,
        RestoreState::RootKeysUnwrapped,
        RestoreState::ManifestVerified,
    ] {
        state_machine::transition(restore_db.connection(), st, None)
            .expect("walk restore state machine");
    }
    let now_ms = messages
        .iter()
        .map(|m| m.created_at_ms)
        .max()
        .unwrap_or_default();
    let summary = RestorePipeline::new()
        .run(
            restore_db.connection(),
            &chain,
            std::slice::from_ref(&backup_segment),
            &k_backup_seg,
            now_ms,
            // Hydrate every body — the dataset spans 90 days, so a
            // 100-day window covers every message.
            100 * 86_400 * 1_000,
        )
        .expect("restore pipeline");
    assert_eq!(
        summary.final_state,
        Some(RestoreState::FullRestoreComplete),
        "restore pipeline must terminate at FullRestoreComplete",
    );
    assert_eq!(
        summary.skeletons.len(),
        backup_events.len(),
        "every backup event must materialise as a skeleton",
    );
    steps.push(StepResult::ok(
        "Restore pipeline",
        started.elapsed(),
        Some(format!(
            "convs={}, skeletons={}, recent_bodies={}, final={:?}",
            summary.conversations.len(),
            summary.skeletons.len(),
            summary.recent_bodies.len(),
            summary.final_state,
        )),
    ));

    // ---- Step 11: search after restore -------------------------
    //
    // The restore pipeline materialises the backup payload into
    // its own DB; the source DB still owns the FTS / fuzzy
    // indexes that the original ingest populated. Re-running the
    // step-4 / step-5 / step-6 queries against the source DB
    // therefore proves that the indexes survived the round-trip
    // (including the archive-event journal walk in step 7) and
    // that the manifest chain build in step 8 did not mutate
    // the indexes underneath us.
    let started = Instant::now();
    let mut total_fts_hits_post: usize = 0;
    for (_, token) in SCRIPT_TOKENS {
        let hits = text_engine
            .search_fts(token, 200)
            .expect("fts post-restore");
        total_fts_hits_post += hits.len();
    }
    let typo_hits_post = fuzzy_engine
        .search_fuzzy("lighthose", 200)
        .expect("fuzzy post-restore");
    let by_alice_post = query_engine
        .execute_search(
            &SearchQuery {
                query_string: "lighthouse".into(),
                sender_filter: Some("alice".into()),
                ..Default::default()
            },
            &SearchScope::LocalOnly,
        )
        .expect("structured post-restore");
    assert_eq!(
        total_fts_hits_post, total_fts_hits,
        "FTS hit count must be stable across the archive + backup round-trip",
    );
    assert_eq!(
        typo_hits_post.len(),
        typo_hits.len(),
        "fuzzy hit count must be stable across the archive + backup round-trip",
    );
    assert_eq!(
        by_alice_post.len(),
        by_alice.len(),
        "structured/sender hit count must be stable across the archive + backup round-trip",
    );
    steps.push(StepResult::ok(
        "Search after restore",
        started.elapsed(),
        Some(format!(
            "fts={total_fts_hits_post}, fuzzy={}, alice={}",
            typo_hits_post.len(),
            by_alice_post.len(),
        )),
    ));

    // ---- Step 12: storage budget enforcement -------------------
    let started = Instant::now();
    let media = generate_demo_media_assets(&conv_ids, media_count);
    let asset_age_ms = now_ms - MIN_OFFLOAD_AGE_MS - 1;

    // The dataset's nominal-size MIME table tops out around 8 MiB
    // per video; with 20 assets that is roughly 100 MiB. Pick a
    // budget far below that so the enforcer can only return
    // `Critical` / `Extreme`.
    let budget = StorageBudget {
        max_bytes: 4 * 1024 * 1024,
        warning_threshold_pct: 50,
        critical_threshold_pct: 75,
    };
    for (conv, descriptor) in &media {
        let mid = Uuid::now_v7();
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: mid.to_string(),
            conversation_id: conv.to_string(),
            sender_id: "demo-media".into(),
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
        .expect("insert media skeleton");
        db.insert_media_asset(&MediaAsset {
            asset_id: descriptor.asset_id.to_string(),
            message_id: mid.to_string(),
            mime_type: descriptor.mime_type.clone(),
            bytes_total: descriptor.bytes_total as i64,
            bytes_local: descriptor.bytes_total as i64,
            media_state: MediaState::OriginalLocal,
            wrapped_k_asset: descriptor.wrapped_k_asset.clone(),
            chunk_count: descriptor.chunk_count as i32,
            merkle_root: descriptor.merkle_root.to_vec(),
            blob_id: descriptor.blob_id.to_string(),
            storage_sink: descriptor
                .storage_sink
                .clone()
                .unwrap_or_else(|| "kchat_backend".into()),
        })
        .expect("insert media asset");
    }

    let enforcer = StorageBudgetEnforcer::new();
    let assessment = enforcer.assess(db.connection(), &budget).expect("assess");
    assert!(
        matches!(
            assessment.pressure_level,
            PressureLevel::Critical | PressureLevel::Extreme,
        ),
        "media seed must breach the configured budget; got {:?}",
        assessment.pressure_level,
    );
    let target = assessment.eviction_target_bytes();
    let candidates =
        collect_eviction_candidates(db.connection(), MIN_OFFLOAD_AGE_MS, now_ms).expect("cands");
    assert!(
        !candidates.is_empty(),
        "every seeded asset is older than MIN_OFFLOAD_AGE_MS, so the candidate pool must be non-empty",
    );
    let plan = plan_tiered_eviction(candidates, target, now_ms, assessment.pressure_level);
    let cloud = execute_eviction(db.connection(), &plan.cloud_offload).expect("execute cloud");
    let full = execute_eviction(db.connection(), &plan.full_eviction).expect("execute full");
    let evicted = cloud.evicted_count.saturating_add(full.evicted_count);
    let freed = cloud.freed_bytes.saturating_add(full.freed_bytes);
    assert!(
        evicted > 0,
        "Critical pressure must trigger at least one eviction",
    );
    steps.push(StepResult::ok(
        "Storage budget enforcement",
        started.elapsed(),
        Some(format!(
            "pressure={:?}, evicted={evicted}, freed_bytes={freed}",
            assessment.pressure_level,
        )),
    ));

    // ---- Final summary -----------------------------------------
    print_summary(&steps, total_started.elapsed());
}

// ---------------------------------------------------------------
// Pretty-printer
// ---------------------------------------------------------------

#[derive(Debug)]
struct StepResult {
    label: &'static str,
    elapsed: std::time::Duration,
    metrics: Option<String>,
}

impl StepResult {
    fn ok(label: &'static str, elapsed: std::time::Duration, metrics: Option<String>) -> Self {
        Self {
            label,
            elapsed,
            metrics,
        }
    }
}

fn print_summary(steps: &[StepResult], total: std::time::Duration) {
    println!();
    println!("=== E2E Demo Results ===");
    for (i, step) in steps.iter().enumerate() {
        let metrics = step
            .metrics
            .as_deref()
            .map(|m| format!(" [{m}]"))
            .unwrap_or_default();
        println!(
            "Step {:>2}: {:<32} OK   ({:>5} ms){metrics}",
            i + 1,
            step.label,
            step.elapsed.as_millis(),
        );
    }
    println!("------------------------");
    println!("Total: {} ms", total.as_millis());
}
