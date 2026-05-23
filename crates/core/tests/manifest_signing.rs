//! Integration test for manifest signing, verification, and the
//! `previous_manifest_hash` chain. Runs the public surface of
//! `crate::formats::manifest` end-to-end so a future schema
//! change in `BackupManifest` / `ArchiveManifest` also breaks this
//! test (rather than just the in-module unit tests).

use rand::rngs::OsRng;
use uuid::Uuid;

use kchat_core::crypto::signing::{HybridSigningKey, HybridVerifyingKey};
use kchat_core::formats::manifest::{
    compute_archive_manifest_hash, compute_manifest_hash, sign_archive_manifest,
    sign_backup_manifest, sign_manifest, verify_archive_manifest, verify_backup_manifest,
    verify_manifest, ArchiveManifest, BackupManifest, ManifestMediaRef, ManifestSegmentRef,
    ManifestShardRef, Tombstone, ARCHIVE_MANIFEST_MAGIC, BACKUP_MANIFEST_MAGIC,
    GENESIS_PREVIOUS_HASH, MANIFEST_VERSION,
};
use kchat_core::formats::search_shard::IndexType;
use kchat_core::formats::SegmentType;

fn keys() -> (HybridSigningKey, HybridVerifyingKey) {
    let mut rng = OsRng;
    let sk = HybridSigningKey::generate(&mut rng);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn segment_ref(seed: u8) -> ManifestSegmentRef {
    ManifestSegmentRef {
        segment_id: Uuid::now_v7(),
        segment_type: SegmentType::Events,
        ciphertext_sha256: [seed; 32],
        size: 1024 + u64::from(seed),
    }
}

fn archive_segment_ref(seed: u8) -> ManifestSegmentRef {
    ManifestSegmentRef {
        segment_id: Uuid::now_v7(),
        segment_type: SegmentType::MessageDelta,
        ciphertext_sha256: [seed; 32],
        size: 4096 + u64::from(seed),
    }
}

fn shard_ref(seed: u8) -> ManifestShardRef {
    ManifestShardRef {
        shard_id: Uuid::now_v7(),
        index_type: IndexType::Text,
        ciphertext_sha256: [seed; 32],
        time_bucket: format!("2026-{:02}", (seed % 12) + 1),
    }
}

fn media_ref(seed: u8) -> ManifestMediaRef {
    ManifestMediaRef {
        asset_id: Uuid::now_v7(),
        blob_id: Uuid::now_v7(),
        merkle_root: [seed ^ 0xA5; 32],
        wrapped_k_asset: vec![seed; 40],
    }
}

fn tombstone(seed: u8) -> Tombstone {
    Tombstone {
        kind: "message".to_string(),
        id: format!("msg_{seed:04}"),
        deleted_at_ms: 1_714_651_200_000 + i64::from(seed),
    }
}

fn build_backup_manifest(generation: u64, previous_manifest_hash: [u8; 32]) -> BackupManifest {
    BackupManifest {
        magic: BACKUP_MANIFEST_MAGIC.to_string(),
        version: MANIFEST_VERSION,
        manifest_id: Uuid::now_v7(),
        generation,
        previous_manifest_hash,
        segments: vec![segment_ref(0x10), segment_ref(0x11)],
        search_index_shards: vec![shard_ref(0x20)],
        media_references: vec![media_ref(0x30)],
        tombstones: vec![tombstone(0x40)],
        merkle_root: [0x55; 32],
        manifest_signature: Vec::new(),
        pqc_signature: Vec::new(),
    }
}

fn build_archive_manifest(generation: u64, previous_manifest_hash: [u8; 32]) -> ArchiveManifest {
    ArchiveManifest {
        magic: ARCHIVE_MANIFEST_MAGIC.to_string(),
        version: MANIFEST_VERSION,
        manifest_id: Uuid::now_v7(),
        generation,
        previous_manifest_hash,
        segments: vec![archive_segment_ref(0x60)],
        search_index_shards: vec![shard_ref(0x70)],
        media_references: vec![media_ref(0x80)],
        tombstones: vec![tombstone(0x90)],
        wrapped_prior_epoch_keys: vec![],
        merkle_root: [0x66; 32],
        manifest_signature: Vec::new(),
        pqc_signature: Vec::new(),
    }
}

#[test]
fn backup_manifest_chain_walks_three_generations() {
    let (sk, vk) = keys();

    // Generation 0 (genesis).
    let mut gen0 = build_backup_manifest(0, GENESIS_PREVIOUS_HASH);
    sign_backup_manifest(&mut gen0, &sk).unwrap();
    verify_backup_manifest(&gen0, &vk).unwrap();
    assert_eq!(gen0.previous_manifest_hash, GENESIS_PREVIOUS_HASH);
    let h0 = compute_manifest_hash(&gen0).unwrap();

    // Generation 1 chains to gen0.
    let mut gen1 = build_backup_manifest(1, h0);
    sign_backup_manifest(&mut gen1, &sk).unwrap();
    verify_backup_manifest(&gen1, &vk).unwrap();
    assert_eq!(gen1.previous_manifest_hash, h0);
    let h1 = compute_manifest_hash(&gen1).unwrap();

    // Generation 2 chains to gen1.
    let mut gen2 = build_backup_manifest(2, h1);
    sign_backup_manifest(&mut gen2, &sk).unwrap();
    verify_backup_manifest(&gen2, &vk).unwrap();
    assert_eq!(gen2.previous_manifest_hash, h1);

    // Each link is distinct.
    assert_ne!(h0, h1);
    assert_ne!(h0, [0u8; 32]);
    assert_ne!(h1, [0u8; 32]);
}

#[test]
fn archive_manifest_chain_walks_three_generations() {
    let (sk, vk) = keys();

    let mut gen0 = build_archive_manifest(0, GENESIS_PREVIOUS_HASH);
    sign_archive_manifest(&mut gen0, &sk).unwrap();
    verify_archive_manifest(&gen0, &vk).unwrap();
    let h0 = compute_archive_manifest_hash(&gen0).unwrap();

    let mut gen1 = build_archive_manifest(1, h0);
    sign_archive_manifest(&mut gen1, &sk).unwrap();
    verify_archive_manifest(&gen1, &vk).unwrap();
    let h1 = compute_archive_manifest_hash(&gen1).unwrap();

    let mut gen2 = build_archive_manifest(2, h1);
    sign_archive_manifest(&mut gen2, &sk).unwrap();
    verify_archive_manifest(&gen2, &vk).unwrap();

    assert_eq!(gen0.previous_manifest_hash, GENESIS_PREVIOUS_HASH);
    assert_eq!(gen1.previous_manifest_hash, h0);
    assert_eq!(gen2.previous_manifest_hash, h1);
    assert_ne!(h0, h1);
}

#[test]
fn cross_chain_attack_is_rejected() {
    // A backup manifest's signature must not verify under the
    // archive verifying key, even when both keys are derived from
    // the same SigningKey API. This catches any future regression
    // that conflates the two manifest types in the canonical
    // signing payload.
    let (sk, vk) = keys();

    let mut backup = build_backup_manifest(1, [0xAA; 32]);
    sign_backup_manifest(&mut backup, &sk).unwrap();

    // Tampering with the magic string (i.e. trying to "rebrand" a
    // backup manifest as an archive manifest) must invalidate the
    // signature.
    let mut tampered = backup.clone();
    tampered.magic = ARCHIVE_MANIFEST_MAGIC.to_string();
    let res = verify_backup_manifest(&tampered, &vk);
    assert!(res.is_err(), "magic-rebrand verified: {res:?}");
}

#[test]
fn raw_sign_verify_round_trip() {
    let (sk, vk) = keys();
    let payload = b"externally-canonicalised-manifest-bytes";
    let sig = sign_manifest(payload, &sk).expect("hybrid sign");
    let ed_bytes = sig.ed25519_bytes();
    let pqc_bytes = sig.pqc_bytes();
    verify_manifest(payload, &ed_bytes, &pqc_bytes, &vk).expect("verify");
}

#[test]
fn raw_verify_rejects_bit_flip() {
    let (sk, vk) = keys();
    let payload = b"signed-payload";
    let sig = sign_manifest(payload, &sk).expect("hybrid sign");
    let mut tampered = payload.to_vec();
    tampered[0] ^= 0x01;
    let ed_bytes = sig.ed25519_bytes();
    let pqc_bytes = sig.pqc_bytes();
    let res = verify_manifest(&tampered, &ed_bytes, &pqc_bytes, &vk);
    assert!(res.is_err(), "bit-flip verified: {res:?}");
}

/// New hybrid coverage: round-trip works, but flipping just the
/// PQC leg of the signature also rejects — mirrors the Ed25519
/// bit-flip case for the post-quantum branch.
#[test]
fn raw_verify_rejects_pqc_bit_flip() {
    let (sk, vk) = keys();
    let payload = b"signed-payload-2";
    let sig = sign_manifest(payload, &sk).expect("hybrid sign");
    let mut bad_pqc = sig.pqc_bytes();
    bad_pqc[0] ^= 0x01;
    let ed_bytes = sig.ed25519_bytes();
    let res = verify_manifest(payload, &ed_bytes, &bad_pqc, &vk);
    assert!(res.is_err(), "pqc bit-flip verified: {res:?}");
}

/// New hybrid coverage: a manifest signed under the right
/// Ed25519 key but the wrong ML-DSA-65 key (and vice versa) must
/// be rejected.
#[test]
fn manifest_with_mismatched_pqc_pubkey_fails() {
    let (sk, _vk) = keys();
    let (_other_sk, other_vk) = keys();
    let mut manifest = build_backup_manifest(0, GENESIS_PREVIOUS_HASH);
    sign_backup_manifest(&mut manifest, &sk).unwrap();

    let mixed =
        HybridVerifyingKey::from_parts(*sk.verifying_key().ed25519(), other_vk.ml_dsa().clone());
    let res = verify_backup_manifest(&manifest, &mixed);
    assert!(
        res.is_err(),
        "hybrid verify accepted mismatched ML-DSA pubkey: {res:?}"
    );
}

#[test]
fn manifest_with_mismatched_ed25519_pubkey_fails() {
    let (sk, _vk) = keys();
    let (_other_sk, other_vk) = keys();
    let mut manifest = build_backup_manifest(0, GENESIS_PREVIOUS_HASH);
    sign_backup_manifest(&mut manifest, &sk).unwrap();

    let mixed =
        HybridVerifyingKey::from_parts(*other_vk.ed25519(), sk.verifying_key().ml_dsa().clone());
    let res = verify_backup_manifest(&manifest, &mixed);
    assert!(
        res.is_err(),
        "hybrid verify accepted mismatched Ed25519 pubkey: {res:?}"
    );
}
