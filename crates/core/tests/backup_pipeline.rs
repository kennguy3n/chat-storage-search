//! End-to-end integration test for the Phase-4 backup → restore
//! round-trip. Builds a small chain of segments + manifests
//! through the public surface of `kchat_core::backup` and replays
//! them through the restore pipeline + manifest chain verifier.
//!
//! This is the cross-module contract test for Phase-4: any change
//! that breaks segment ↔ manifest ↔ verifier ↔ pipeline
//! interoperability surfaces here.

use ed25519_dalek::SigningKey;
use uuid::Uuid;

use kchat_core::backup::event_journal::{BackupEvent, BackupEventType};
use kchat_core::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
use kchat_core::backup::segment_builder::{
    decrypt_backup_segment, BackupSegmentBuildRequest, BackupSegmentBuilder,
};
use kchat_core::crypto::key_hierarchy::{
    derive_backup_manifest, derive_backup_root, derive_backup_segment, KeyMaterial,
};
use kchat_core::formats::SegmentType;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::state_machines::RestoreState;
use kchat_core::restore::manifest_verifier::verify_manifest_chain;
use kchat_core::restore::pipeline::RestorePipeline;
use kchat_core::restore::state_machine;

#[test]
fn backup_to_restore_round_trip_walks_to_full_complete() {
    // ----- Backup side: build segments + a 2-generation manifest chain.
    let identity = KeyMaterial::from_bytes([0xCC; 32]);
    let backup_root = derive_backup_root(&identity).unwrap();
    let k_seg = derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).unwrap();
    let k_man = derive_backup_manifest(&backup_root, b"integration").unwrap();
    let signing = SigningKey::from_bytes(&[0xAB; 32]);

    let conv = Uuid::now_v7();
    let now_ms = 1_777_000_000_000_i64;
    let recent_msg = Uuid::now_v7();
    let stale_msg = Uuid::now_v7();

    let recent = BackupEvent {
        event_type: BackupEventType::MessageReceived,
        conversation_id: Some(conv),
        message_id: Some(recent_msg),
        payload: b"hello recent".to_vec(),
        created_at_ms: now_ms - 1_000,
    };
    let stale = BackupEvent {
        event_type: BackupEventType::MessageReceived,
        conversation_id: Some(conv),
        message_id: Some(stale_msg),
        payload: b"hello stale".to_vec(),
        created_at_ms: now_ms - 365 * 86_400 * 1_000,
    };

    let segment = BackupSegmentBuilder::new()
        .build_segment(
            BackupSegmentBuildRequest {
                events: vec![recent.clone(), stale.clone()],
                segment_type: SegmentType::Events,
            },
            &k_seg,
        )
        .unwrap();

    let gen0 = build_backup_manifest(
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

    let gen1 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: Some(&gen0.manifest),
            device_id: "device-A".into(),
        },
        &signing,
        &k_man,
    )
    .unwrap();

    let chain = vec![gen0.manifest.clone(), gen1.manifest.clone()];

    // ----- Verifier: walk the chain end-to-end.
    verify_manifest_chain(&chain, &signing.verifying_key())
        .expect("manifest chain must verify under the signing key");

    // ----- Round-trip: decrypt the segment so we know it survived.
    let payload = decrypt_backup_segment(&segment, &k_seg).unwrap();
    assert_eq!(payload.events.len(), 2);

    // ----- Restore side: walk the state machine to ManifestVerified,
    // then drive the skeleton-first pipeline through to terminal
    // FullRestoreComplete.
    let db = LocalStoreDb::open_in_memory(&[0x55; 32]).expect("open in-memory");
    for st in [
        RestoreState::IdentityRestored,
        RestoreState::RootKeysUnwrapped,
        RestoreState::ManifestVerified,
    ] {
        state_machine::transition(db.connection(), st, None).unwrap();
    }

    let summary = RestorePipeline::new()
        .run(
            db.connection(),
            &chain,
            std::slice::from_ref(&segment),
            &k_seg,
            now_ms,
            7 * 86_400 * 1_000, // one-week recency window
        )
        .expect("pipeline should succeed end-to-end");

    assert_eq!(summary.final_state, Some(RestoreState::FullRestoreComplete));
    assert_eq!(summary.conversations.len(), 1);
    assert_eq!(summary.conversations[0].conversation_id, conv);
    // Two skeleton rows; only the recent one had its body hydrated.
    assert_eq!(summary.skeletons.len(), 2);
    assert_eq!(summary.recent_bodies.len(), 1);
    assert_eq!(summary.recent_bodies[0].message_id, recent_msg);
    assert_eq!(summary.recent_bodies[0].payload, b"hello recent".to_vec());
}

#[test]
fn manifest_verifier_catches_chain_break_on_restore() {
    let identity = KeyMaterial::from_bytes([0xDD; 32]);
    let backup_root = derive_backup_root(&identity).unwrap();
    let k_seg = derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).unwrap();
    let k_man = derive_backup_manifest(&backup_root, b"chain-break").unwrap();
    let signing = SigningKey::from_bytes(&[0xCD; 32]);

    let event = BackupEvent {
        event_type: BackupEventType::MessageReceived,
        conversation_id: Some(Uuid::now_v7()),
        message_id: Some(Uuid::now_v7()),
        payload: b"x".to_vec(),
        created_at_ms: 1,
    };
    let segment = BackupSegmentBuilder::new()
        .build_segment(
            BackupSegmentBuildRequest {
                events: vec![event],
                segment_type: SegmentType::Events,
            },
            &k_seg,
        )
        .unwrap();

    let gen0 = build_backup_manifest(
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

    // Forge a generation-1 manifest with an all-zeros previous_manifest_hash
    // so the chain link is broken. Re-sign so signature alone cannot
    // explain the failure.
    let mut forged = gen0.manifest.clone();
    forged.generation = 1;
    forged.previous_manifest_hash = [0u8; 32];
    kchat_core::formats::manifest::sign_backup_manifest(&mut forged, &signing).unwrap();

    let chain = vec![gen0.manifest, forged];
    let err = verify_manifest_chain(&chain, &signing.verifying_key()).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("chain break") || msg.contains("hash"),
        "expected chain break error, got {msg}"
    );
}

#[test]
fn search_shards_round_trip_through_pipeline() {
    use kchat_core::crypto::key_hierarchy::{derive_search_root, derive_text_index_shard};
    use kchat_core::restore::pipeline::SealedSearchShardEntry;
    use kchat_core::search::shard_builder::{
        build_fuzzy_search_shard, build_text_search_shard, FtsRow, FuzzyRow,
    };

    // ----- Build text + fuzzy shards covering one conversation /
    // bucket so we can ensure both replays land cleanly in one
    // pipeline call.
    let identity = KeyMaterial::from_bytes([0xAA; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let text_shard_id = Uuid::now_v7();
    let fuzzy_shard_id = Uuid::now_v7();
    let k_text = derive_text_index_shard(&search_root, text_shard_id.as_bytes()).unwrap();
    let k_fuzzy = derive_text_index_shard(&search_root, fuzzy_shard_id.as_bytes()).unwrap();
    let conv_hash_key = KeyMaterial::from_bytes([0xBB; 32]);

    let conv_id = Uuid::now_v7().to_string();
    let mid = Uuid::now_v7().to_string();
    let fts_rows = vec![FtsRow {
        message_id: mid.clone(),
        conversation_id: conv_id.clone(),
        sender_id: "alice".into(),
        created_at_ms: 1_700_000_000,
        text_content: "lighthouse beacon shines".into(),
    }];
    let fuzzy_rows = vec![
        FuzzyRow {
            token: "lig".into(),
            script: "Latn".into(),
            message_id: mid.clone(),
        },
        FuzzyRow {
            token: "igh".into(),
            script: "Latn".into(),
            message_id: mid.clone(),
        },
    ];
    let text_built =
        build_text_search_shard(fts_rows, &conv_id, "2026-04", &k_text, &conv_hash_key)
            .expect("build text shard");
    let fuzzy_built =
        build_fuzzy_search_shard(fuzzy_rows, &conv_id, "2026-04", &k_fuzzy, &conv_hash_key)
            .expect("build fuzzy shard");

    // ----- Replay both shards through the pipeline.
    let mut db = LocalStoreDb::open_in_memory(&[0x66; 32]).expect("open in-memory");
    let entries = vec![
        SealedSearchShardEntry {
            shard: &text_built.shard,
            k_shard: &text_built.k_shard,
        },
        SealedSearchShardEntry {
            shard: &fuzzy_built.shard,
            k_shard: &fuzzy_built.k_shard,
        },
    ];
    let summary = RestorePipeline::new()
        .restore_search_index_shards_with_replay(db.connection_mut(), &entries)
        .expect("replay");
    assert_eq!(summary.len(), 2);
    assert_eq!(
        summary.iter().map(|s| s.rows_inserted).sum::<usize>(),
        3,
        "1 FTS row + 2 fuzzy rows"
    );

    // ----- FTS search must return the restored row.
    let fts_count: i64 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM search_fts WHERE search_fts MATCH ?1",
            rusqlite::params!["lighthouse"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fts_count, 1);

    // ----- Fuzzy must contain the n-grams.
    let fuzzy_count: i64 = db
        .connection()
        .query_row(
            "SELECT count(*) FROM search_fuzzy WHERE message_id = ?1",
            rusqlite::params![mid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fuzzy_count, 2);
}
