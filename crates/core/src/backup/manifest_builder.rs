//! Phase-4 backup manifest chain builder.
//!
//! Mirror of
//! [`crate::archive::manifest_builder::build_archive_manifest`] for
//! the **backup** chain. Pulls a list of
//! [`crate::backup::segment_builder::BuiltBackupSegment`]s and the
//! previous backup manifest (if any), produces a
//! [`crate::formats::manifest::BackupManifest`], signs it with the
//! caller-supplied Ed25519 device key, and AEAD-seals it under
//! `K_backup_manifest`.
//!
//! Chain discipline:
//!
//! * **Genesis** (`previous = None`): `generation = 0` and
//!   `previous_manifest_hash = [0u8; 32]`
//!   ([`crate::formats::manifest::GENESIS_PREVIOUS_HASH`]).
//! * **Subsequent**: `generation = prev.generation + 1` and
//!   `previous_manifest_hash = compute_manifest_hash(prev)`.
//!
//! `merkle_root` is the BLAKE3 of every segment's plaintext
//! `merkle_root` concatenated in the order the orchestrator
//! supplied — the field name is "merkle root" by convention but is
//! computed as a flat hash, mirroring §6.3 of `docs/PROPOSAL.md`.
//!
//! The output is a [`SealedBackupManifest`]: the signed manifest
//! plus its AEAD ciphertext, ready to upload alongside the
//! segment blobs.

use blake3::Hasher;
use ed25519_dalek::{Signature, SigningKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::aead::xchacha20_poly1305::{open, seal, NONCE_LEN};
use crate::crypto::key_hierarchy::KeyMaterial;
use crate::crypto::CryptoError;
use crate::formats::manifest::{
    compute_manifest_hash, sign_backup_manifest, BackupManifest, ManifestMediaRef,
    ManifestSegmentRef, ManifestShardRef, Tombstone, BACKUP_MANIFEST_MAGIC, GENESIS_PREVIOUS_HASH,
    MANIFEST_VERSION,
};
use crate::Error;

use super::segment_builder::BuiltBackupSegment;

/// Bundle returned by [`build_backup_manifest`]: the signed
/// manifest plus its AEAD seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBackupManifest {
    /// The signed [`BackupManifest`] (clear text — segment / shard
    /// / media references are not secrets, only the body of the
    /// manifest is sealed).
    pub manifest: BackupManifest,
    /// Ed25519 signature produced during [`sign_backup_manifest`].
    pub signature: Signature,
    /// 24-byte XChaCha20-Poly1305 nonce sealing
    /// [`Self::ciphertext`].
    pub nonce: [u8; NONCE_LEN],
    /// AEAD ciphertext over the canonical CBOR encoding of
    /// [`Self::manifest`] under `K_backup_manifest`.
    pub ciphertext: Vec<u8>,
}

/// Inputs to [`build_backup_manifest`].
#[derive(Debug, Clone)]
pub struct BackupManifestBuildRequest<'a> {
    /// Sealed segments to commit under this manifest.
    pub segments: &'a [BuiltBackupSegment],
    /// Search index shards committed under this manifest. Empty
    /// today — Phase 4 will wire shard-segment encoding in a
    /// later task.
    pub search_index_shards: Vec<ManifestShardRef>,
    /// Media object references committed under this manifest.
    /// Populated as media uploads are verified by the routing
    /// layer.
    pub media_references: Vec<ManifestMediaRef>,
    /// Tombstones committed under this manifest.
    pub tombstones: Vec<Tombstone>,
    /// Optional previous manifest in the chain. `None` produces a
    /// genesis manifest.
    pub previous: Option<&'a BackupManifest>,
    /// Stable device id stamped into the AEAD AAD so the
    /// orchestrator can attribute manifests to the device that
    /// produced them.
    pub device_id: String,
}

/// Build a single backup-manifest record.
///
/// `signing_key` is the Ed25519 device key.
/// `k_backup_manifest` is `K_backup_manifest` — derived from
/// `K_backup_root` via
/// [`crate::crypto::key_hierarchy::derive_backup_manifest_key`].
pub fn build_backup_manifest(
    request: BackupManifestBuildRequest<'_>,
    signing_key: &SigningKey,
    k_backup_manifest: &KeyMaterial,
) -> Result<SealedBackupManifest, Error> {
    let (generation, previous_manifest_hash) = match request.previous {
        None => (0u64, GENESIS_PREVIOUS_HASH),
        Some(prev) => {
            let next = prev
                .generation
                .checked_add(1)
                .ok_or_else(|| Error::Storage("backup manifest generation overflow".into()))?;
            let hash = compute_manifest_hash(prev).map_err(Error::Crypto)?;
            (next, hash)
        }
    };

    let segment_refs: Vec<ManifestSegmentRef> = request
        .segments
        .iter()
        .map(|s| ManifestSegmentRef {
            segment_id: s.segment_id,
            segment_type: s.segment_type,
            ciphertext_sha256: sha256(&s.ciphertext),
            size: s.ciphertext.len() as u64,
        })
        .collect();

    let merkle_root = compute_segment_merkle_root(request.segments);

    let mut manifest = BackupManifest {
        magic: BACKUP_MANIFEST_MAGIC.to_string(),
        version: MANIFEST_VERSION,
        manifest_id: Uuid::now_v7(),
        generation,
        previous_manifest_hash,
        segments: segment_refs,
        search_index_shards: request.search_index_shards,
        media_references: request.media_references,
        tombstones: request.tombstones,
        merkle_root,
        manifest_signature: Vec::new(),
    };

    let signature = sign_backup_manifest(&mut manifest, signing_key).map_err(Error::Crypto)?;

    // AEAD-seal the canonical CBOR of the (now-signed) manifest.
    let manifest_bytes = serde_cbor::to_vec(&manifest)
        .map_err(|_| Error::Crypto(CryptoError::Frame("manifest CBOR encode failed".into())))?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let aad = build_manifest_aad(
        &manifest.manifest_id,
        generation,
        &merkle_root,
        &request.device_id,
    );
    let ciphertext =
        seal(k_backup_manifest.as_bytes(), &nonce, &manifest_bytes, &aad).map_err(Error::Crypto)?;

    Ok(SealedBackupManifest {
        manifest,
        signature,
        nonce,
        ciphertext,
    })
}

/// AEAD AAD for a backup manifest seal:
/// `BACKUP_MANIFEST_MAGIC || manifest_id(16) || generation(8 LE) ||
///  merkle_root(32) || device_id(UTF-8)`.
pub fn build_manifest_aad(
    manifest_id: &Uuid,
    generation: u64,
    merkle_root: &[u8; 32],
    device_id: &str,
) -> Vec<u8> {
    let magic = BACKUP_MANIFEST_MAGIC.as_bytes();
    let mut aad = Vec::with_capacity(magic.len() + 16 + 8 + 32 + device_id.len());
    aad.extend_from_slice(magic);
    aad.extend_from_slice(manifest_id.as_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.extend_from_slice(merkle_root);
    aad.extend_from_slice(device_id.as_bytes());
    aad
}

/// Open the AEAD-sealed manifest produced by
/// [`build_backup_manifest`]. The restore pipeline (Task 10) and
/// the unit tests both call this.
pub fn open_sealed_backup_manifest(
    sealed: &SealedBackupManifest,
    k_backup_manifest: &KeyMaterial,
    device_id: &str,
) -> Result<BackupManifest, Error> {
    let aad = build_manifest_aad(
        &sealed.manifest.manifest_id,
        sealed.manifest.generation,
        &sealed.manifest.merkle_root,
        device_id,
    );
    let plaintext = open(
        k_backup_manifest.as_bytes(),
        &sealed.nonce,
        &sealed.ciphertext,
        &aad,
    )
    .map_err(Error::Crypto)?;
    let manifest: BackupManifest = serde_cbor::from_slice(&plaintext)
        .map_err(|e| Error::Storage(format!("manifest CBOR decode: {e}")))?;
    Ok(manifest)
}

/// Compute the manifest's `merkle_root`: BLAKE3 over each
/// segment's plaintext `merkle_root` concatenated in order. Empty
/// segment lists hash the empty input — useful for the
/// pathological "no segments this generation" case.
fn compute_segment_merkle_root(segments: &[BuiltBackupSegment]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for s in segments {
        hasher.update(&s.merkle_root);
    }
    *hasher.finalize().as_bytes()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::event_journal::{BackupEvent, BackupEventType};
    use crate::backup::segment_builder::{BackupSegmentBuildRequest, BackupSegmentBuilder};
    use crate::crypto::key_hierarchy::{
        derive_backup_manifest, derive_backup_root, derive_backup_segment, KeyMaterial,
    };
    use crate::formats::manifest::verify_backup_manifest;
    use crate::formats::SegmentType;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    fn fake_signing_key() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[0x11; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn fresh_keys() -> (KeyMaterial, KeyMaterial) {
        let identity = KeyMaterial::from_bytes([0xCC; 32]);
        let backup_root = derive_backup_root(&identity).expect("derive backup root");
        let segment_id = Uuid::now_v7();
        let k_backup_segment =
            derive_backup_segment(&backup_root, &segment_id.into_bytes()).expect("seg");
        let k_backup_manifest =
            derive_backup_manifest(&backup_root, b"manifest-genesis").expect("manifest key");
        // Re-use `k_backup_segment` as the segment-builder input
        // and `k_backup_manifest` as the manifest sealer.
        (k_backup_segment, k_backup_manifest)
    }

    fn fake_segment(k_backup_segment: &KeyMaterial) -> BuiltBackupSegment {
        let event = BackupEvent {
            event_type: BackupEventType::MessageReceived,
            conversation_id: Some(Uuid::now_v7()),
            message_id: Some(Uuid::now_v7()),
            payload: vec![0xAB, 0xCD],
            created_at_ms: 1_777_000_000_000,
        };
        let req = BackupSegmentBuildRequest {
            events: vec![event],
            segment_type: SegmentType::Events,
        };
        BackupSegmentBuilder::new()
            .build_segment(req, k_backup_segment)
            .expect("seal segment")
    }

    #[test]
    fn genesis_manifest_has_zero_generation_and_zero_previous_hash() {
        let (sk, vk) = fake_signing_key();
        let (k_seg, k_man) = fresh_keys();
        let s1 = fake_segment(&k_seg);
        let s2 = fake_segment(&k_seg);

        let sealed = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[s1.clone(), s2.clone()],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();

        assert_eq!(sealed.manifest.generation, 0);
        assert_eq!(
            sealed.manifest.previous_manifest_hash,
            GENESIS_PREVIOUS_HASH
        );
        assert_eq!(sealed.manifest.segments.len(), 2);

        verify_backup_manifest(&sealed.manifest, &vk).expect("genesis signature");
    }

    #[test]
    fn chained_manifest_links_to_previous_via_compute_manifest_hash() {
        let (sk, vk) = fake_signing_key();
        let (k_seg, k_man) = fresh_keys();

        let gen0 = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();

        let gen1 = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: Some(&gen0.manifest),
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();

        assert_eq!(gen1.manifest.generation, 1);
        let expected_prev = compute_manifest_hash(&gen0.manifest).unwrap();
        assert_eq!(gen1.manifest.previous_manifest_hash, expected_prev);

        verify_backup_manifest(&gen1.manifest, &vk).expect("gen1 signature");
    }

    #[test]
    fn signature_verifies_under_corresponding_public_key() {
        let (sk, vk) = fake_signing_key();
        let (k_seg, k_man) = fresh_keys();
        let sealed = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();
        verify_backup_manifest(&sealed.manifest, &vk).expect("verify");
    }

    #[test]
    fn signature_fails_under_wrong_public_key() {
        let (sk, _vk) = fake_signing_key();
        let other_vk = SigningKey::from_bytes(&[0x22; 32]).verifying_key();
        let (k_seg, k_man) = fresh_keys();
        let sealed = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();
        let res = verify_backup_manifest(&sealed.manifest, &other_vk);
        assert!(res.is_err(), "wrong-key verify accepted: {res:?}");
    }

    #[test]
    fn aead_seal_and_open_round_trip() {
        let (sk, _vk) = fake_signing_key();
        let (k_seg, k_man) = fresh_keys();
        let sealed = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();
        let opened = open_sealed_backup_manifest(&sealed, &k_man, "device-A").unwrap();
        assert_eq!(opened, sealed.manifest);
    }

    #[test]
    fn aead_open_with_wrong_device_id_fails() {
        let (sk, _vk) = fake_signing_key();
        let (k_seg, k_man) = fresh_keys();
        let sealed = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();
        let err = open_sealed_backup_manifest(&sealed, &k_man, "device-B").unwrap_err();
        match err {
            Error::Crypto(_) => {}
            other => panic!("expected Crypto, got {other:?}"),
        }
    }

    #[test]
    fn three_generation_chain_walks_cleanly() {
        let (sk, vk) = fake_signing_key();
        let (k_seg, k_man) = fresh_keys();

        let gen0 = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();

        let gen1 = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: Some(&gen0.manifest),
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();

        let gen2 = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: Some(&gen1.manifest),
                device_id: "device-A".into(),
            },
            &sk,
            &k_man,
        )
        .unwrap();

        for sealed in [&gen0, &gen1, &gen2] {
            verify_backup_manifest(&sealed.manifest, &vk).expect("each generation verifies");
        }

        assert_eq!(gen0.manifest.generation, 0);
        assert_eq!(gen1.manifest.generation, 1);
        assert_eq!(gen2.manifest.generation, 2);

        let h0 = compute_manifest_hash(&gen0.manifest).unwrap();
        let h1 = compute_manifest_hash(&gen1.manifest).unwrap();
        assert_eq!(gen1.manifest.previous_manifest_hash, h0);
        assert_eq!(gen2.manifest.previous_manifest_hash, h1);
    }
}
