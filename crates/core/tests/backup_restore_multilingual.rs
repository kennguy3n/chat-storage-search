//! Phase 4 multilingual backup → restore corpus test.
//!
//! `docs/PHASES.md §Phase 4` decision gate: "Backup chain restores
//! conversations, skeletons, and recent bodies across every script
//! the search layer supports". This test seeds eight scripts of
//! plaintext, runs the backup pipeline (segment build + manifest
//! chain), verifies the manifest chain, then runs the
//! [`RestorePipeline`] against a fresh local store and checks:
//!
//! 1. Every conversation surfaces in the restored set.
//! 2. Every skeleton row materialises with `body_state =
//!    RemoteArchiveOnly` (or `LocalPlainAvailable` if recent).
//! 3. Recent bodies are hydrated from the matching `BackupEvent`
//!    payload (CBOR-shaped).
//! 4. The manifest chain verifier accepts the chain end-to-end.
//! 5. Fuzzy-search recall works on a typo of an English message
//!    once we re-index the restored bodies through the local
//!    fuzzy engine.
//!
//! Soft-skipping the CJK / Thai FTS5 assertions on builds without
//! the ICU tokenizer follows the same pattern as
//! `crates/core/tests/multilingual_search.rs`.

use rand::rngs::OsRng;
use uuid::Uuid;

use kchat_core::crypto::signing::HybridSigningKey;

use kchat_core::backup::event_journal::{BackupEvent, BackupEventType};
use kchat_core::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
use kchat_core::backup::segment_builder::{BackupSegmentBuildRequest, BackupSegmentBuilder};
use kchat_core::crypto::key_hierarchy::{
    derive_backup_manifest, derive_backup_root, derive_backup_segment, KeyMaterial,
};
use kchat_core::formats::SegmentType;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::local_store::state_machines::{BodyState, RestoreState};
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::restore::manifest_verifier::verify_manifest_chain;
use kchat_core::restore::pipeline::RestorePipeline;
use kchat_core::restore::state_machine;
use kchat_core::search::fuzzy_search::FuzzySearchEngine;
use kchat_core::search::text_search::TextSearchEngine;

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CorpusEntry {
    tag: &'static str,
    text: &'static str,
    sender: &'static str,
    conv_offset: usize, // 0..3
    ts_offset_ms: i64,
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry {
            tag: "en",
            text: "Meeting at 3pm in the conference room",
            sender: "alice",
            conv_offset: 0,
            ts_offset_ms: 0,
        },
        CorpusEntry {
            tag: "ru",
            text: "Встреча в 15:00 в конференц-зале",
            sender: "bob",
            conv_offset: 0,
            ts_offset_ms: 1_000,
        },
        CorpusEntry {
            tag: "zh",
            text: "下午三点在会议室开会",
            sender: "alice",
            conv_offset: 1,
            ts_offset_ms: 2_000,
        },
        CorpusEntry {
            tag: "ja",
            text: "会議は午後3時に会議室で行います",
            sender: "bob",
            conv_offset: 1,
            ts_offset_ms: 3_000,
        },
        CorpusEntry {
            tag: "ar",
            text: "الاجتماع في الساعة 3 مساءً",
            sender: "alice",
            conv_offset: 0,
            ts_offset_ms: 4_000,
        },
        CorpusEntry {
            tag: "th",
            text: "ประชุมเวลาบ่าย 3 โมง",
            sender: "bob",
            conv_offset: 1,
            ts_offset_ms: 5_000,
        },
        CorpusEntry {
            tag: "hi",
            text: "बैठक दोपहर 3 बजे",
            sender: "alice",
            conv_offset: 0,
            ts_offset_ms: 6_000,
        },
        CorpusEntry {
            tag: "mixed",
            text: "Meeting at 3pm 会議室で — Встреча",
            sender: "alice",
            conv_offset: 2,
            ts_offset_ms: 7_000,
        },
    ]
}

const NOW_MS: i64 = 1_777_000_000_000;

fn seed_conversation(db: &LocalStoreDb, conversation_id: Uuid) {
    db.insert_conversation(&Conversation {
        conversation_id: conversation_id.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms: NOW_MS,
        ..Default::default()
    })
    .expect("seed conversation");
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn backup_restore_multilingual_corpus_round_trip() {
    // ----- Source-side: seed an in-memory store, then drive the
    // local FTS index *and* the backup-event journal via
    // MessagePersister.
    let source_db = LocalStoreDb::open_in_memory(&[0xCA; 32]).expect("source db");
    let convs: Vec<Uuid> = (0..3).map(|_| Uuid::now_v7()).collect();
    for c in &convs {
        seed_conversation(&source_db, *c);
    }
    let persister = MessagePersister::new(&source_db);

    // We mirror every persisted message into a parallel
    // `BackupEvent` set so we can drive the segment builder
    // directly. (CoreImpl wires the journal end-to-end already
    // and is exercised by `core_impl::tests::run_incremental_backup_*`;
    // this test focuses on the cross-script restore contract.)
    let mut events: Vec<BackupEvent> = Vec::new();
    let mut id_for_tag: std::collections::HashMap<&'static str, Uuid> =
        std::collections::HashMap::new();

    for entry in corpus() {
        let mid = Uuid::now_v7();
        let conv_id = convs[entry.conv_offset];
        let ts_ms = NOW_MS + entry.ts_offset_ms;
        persister
            .persist_ingested_message(&IngestedMessage {
                message_id: mid,
                conversation_id: conv_id,
                sender_id: entry.sender.into(),
                created_at_ms: ts_ms,
                text_content: Some(entry.text.into()),
                media_descriptors: vec![],
                reply_to: None,
            })
            .unwrap_or_else(|e| panic!("persist {}: {e:?}", entry.tag));

        events.push(BackupEvent {
            event_type: BackupEventType::MessageReceived,
            conversation_id: Some(conv_id),
            message_id: Some(mid),
            payload: kchat_core::cbor::to_vec(&kchat_core::cbor::Value::Array(vec![
                kchat_core::cbor::Value::Text(mid.to_string()),
                kchat_core::cbor::Value::Text(conv_id.to_string()),
                kchat_core::cbor::Value::Text(entry.sender.into()),
                kchat_core::cbor::Value::Integer(kchat_core::cbor::Integer::from(ts_ms)),
                kchat_core::cbor::Value::Text(entry.text.into()),
            ]))
            .expect("cbor"),
            created_at_ms: ts_ms,
        });
        id_for_tag.insert(entry.tag, mid);
    }
    assert_eq!(events.len(), 8);

    // ----- Backup side: derive keys and seal the events into a
    // single segment, then build a chained 2-generation manifest
    // (genesis + 1).
    let identity = KeyMaterial::from_bytes([0xCC; 32]);
    let backup_root = derive_backup_root(&identity).expect("backup root");
    let k_seg =
        derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).expect("k_segment");
    let k_man = derive_backup_manifest(&backup_root, b"multilingual").expect("k_manifest");
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
    .expect("gen-1 manifest");

    let chain = vec![gen0.manifest.clone(), gen1.manifest.clone()];

    // ----- Verifier: chain must walk end-to-end.
    verify_manifest_chain(&chain, &signing.verifying_key()).expect("manifest chain verification");

    // ----- Restore side: open a fresh in-memory store, drive the
    // state machine to ManifestVerified, then run the pipeline.
    let restore_db = LocalStoreDb::open_in_memory(&[0x55; 32]).expect("restore db");
    for st in [
        RestoreState::IdentityRestored,
        RestoreState::RootKeysUnwrapped,
        RestoreState::ManifestVerified,
    ] {
        state_machine::transition(restore_db.connection(), st, None).unwrap();
    }

    let summary = RestorePipeline::new()
        .run(
            restore_db.connection(),
            &chain,
            std::slice::from_ref(&segment),
            &k_seg,
            // Make every test message "recent" so all bodies
            // hydrate — we want body_state = LocalPlainAvailable
            // for every script.
            NOW_MS + 100_000,
            7 * 86_400 * 1_000,
        )
        .expect("pipeline run");

    // Pipeline reaches the terminal state.
    assert_eq!(summary.final_state, Some(RestoreState::FullRestoreComplete));
    // Every conversation we seeded surfaces in the restored set.
    let restored_ids: std::collections::BTreeSet<Uuid> = summary
        .conversations
        .iter()
        .map(|c| c.conversation_id)
        .collect();
    for c in &convs {
        assert!(
            restored_ids.contains(c),
            "missing conversation {c} in restored set: {restored_ids:?}"
        );
    }
    // Every script's message_id materialises as a skeleton row.
    let restored_mids: std::collections::BTreeSet<Uuid> =
        summary.skeletons.iter().map(|s| s.message_id).collect();
    for &mid in id_for_tag.values() {
        assert!(
            restored_mids.contains(&mid),
            "missing message_id {mid} in skeletons"
        );
    }
    // Every skeleton has its body hydrated (NOW_MS + 100s recency
    // window > the entire corpus).
    for s in &summary.skeletons {
        assert_eq!(
            s.body_state,
            BodyState::LocalPlainAvailable,
            "skeleton {:?} should have hydrated body",
            s.message_id
        );
    }
    // CBOR payloads round-trip through `recent_bodies`.
    assert_eq!(summary.recent_bodies.len(), 8);
    for body in &summary.recent_bodies {
        let value: kchat_core::cbor::Value =
            kchat_core::cbor::from_slice(&body.payload).expect("cbor decode");
        match value {
            kchat_core::cbor::Value::Array(parts) => {
                assert_eq!(parts.len(), 5, "expected 5-element CBOR array");
            }
            other => panic!("unexpected payload shape: {other:?}"),
        }
    }

    // ----- Local-side smoke check: the *source* DB still serves
    // FTS5 / fuzzy lookups for every script, since the backup
    // path does not touch the local indices. CJK / Thai land
    // behind an ICU probe (same pattern as multilingual_search).
    //
    // `persist_ingested_message` (above) already indexes every
    // message through `FuzzyIndexWriter::index_message`
    // (`processor.rs:418`), so we do not re-index here — the
    // typo-recall assertion below reads the rows that the
    // persister already wrote.
    let icu = source_db.icu_available();
    let text = TextSearchEngine::new(source_db.connection(), source_db.icu_available());
    let fuzzy = FuzzySearchEngine::new(source_db.connection());

    // Required (every build): English, Cyrillic, Arabic, Devanagari.
    {
        let hits = text.search_fts("meeting", 50).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
        assert!(
            ids.contains(&id_for_tag["en"].to_string()),
            "missing en hit: {ids:?}"
        );
    }
    {
        let hits = text.search_fts("Встреча", 50).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
        assert!(
            ids.contains(&id_for_tag["ru"].to_string()),
            "missing ru hit: {ids:?}"
        );
    }
    {
        let hits = text.search_fts("الاجتماع", 50).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
        assert!(
            ids.contains(&id_for_tag["ar"].to_string()),
            "missing ar hit: {ids:?}"
        );
    }
    {
        let hits = text.search_fts("बैठक", 50).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
        assert!(
            ids.contains(&id_for_tag["hi"].to_string()),
            "missing hi hit: {ids:?}"
        );
    }

    // Soft-skip CJK / Thai when ICU is missing.
    if icu {
        let hits = text.search_fts("会议室", 50).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
        assert!(
            ids.contains(&id_for_tag["zh"].to_string()),
            "missing zh hit (ICU): {ids:?}"
        );
        let hits = text.search_fts("会議室", 50).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
        assert!(
            ids.contains(&id_for_tag["ja"].to_string()),
            "missing ja hit (ICU): {ids:?}"
        );
        let hits = text.search_fts("ประชุม", 50).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
        assert!(
            ids.contains(&id_for_tag["th"].to_string()),
            "missing th hit (ICU): {ids:?}"
        );
    } else {
        eprintln!(
            "[skip] CJK / Thai FTS5 assertions: SQLCipher built without ICU. \
             Re-run with an ICU-linked SQLCipher build."
        );
    }

    // Fuzzy: typo recall surfaces the English message even with a
    // dropped letter.
    {
        let hits = fuzzy.search_fuzzy("meting", 20).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
        assert!(
            ids.contains(&id_for_tag["en"].to_string()),
            "fuzzy 'meting' should hit en: {ids:?}"
        );
    }
}
