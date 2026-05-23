//! Phase-3 archive manifest chain builder.
//!
//! Pulls a list of [`crate::archive::segment_builder::BuiltSegment`]s
//! and the previous manifest (if any), produces an
//! [`crate::formats::manifest::ArchiveManifest`], signs it with the
//! caller-supplied **hybrid Ed25519 + ML-DSA-65 device key**, and
//! AEAD-seals it under `K_archive_manifest` derived from the
//! active epoch key.
//!
//! The chain discipline matches the backup manifest:
//!
//! * **Genesis** (`previous = None`): `generation = 0` and
//!   `previous_manifest_hash = [0u8; 32]`
//!   ([`crate::formats::manifest::GENESIS_PREVIOUS_HASH`]).
//! * **Subsequent**: `generation = prev.generation + 1` and
//!   `previous_manifest_hash = compute_archive_manifest_hash(prev)`.
//!
//! `merkle_root` is the BLAKE3 of every segment's plaintext
//! `merkle_root` concatenated in the order the orchestrator
//! supplied — the field name is "merkle root" by convention but is
//! computed as a flat hash, mirroring §6.3 of `docs/PROPOSAL.md`.
//!
//! The output is a [`SealedArchiveManifest`]: the signed manifest
//! plus its AEAD ciphertext, ready to upload alongside the segment
//! blobs.

use blake3::Hasher;
use rand::RngCore;
use uuid::Uuid;

use crate::crypto::aead::xchacha20_poly1305::{seal, NONCE_LEN};
use crate::crypto::signing::HybridSigningKey;
use crate::crypto::CryptoError;
use crate::formats::manifest::{
    compute_archive_manifest_hash, sign_archive_manifest, ArchiveManifest, HybridManifestSignature,
    ManifestMediaRef, ManifestSegmentRef, ManifestShardRef, Tombstone, WrappedEpochKeyRef,
    ARCHIVE_MANIFEST_MAGIC, GENESIS_PREVIOUS_HASH, MANIFEST_VERSION,
};
use crate::Error;

use super::segment_builder::BuiltSegment;

/// Bundle returned by [`build_archive_manifest`]: the signed
/// manifest plus its AEAD seal.
///
/// `HybridManifestSignature` does not implement `PartialEq`/`Eq`
/// (the underlying ML-DSA-65 signature type doesn't), so we only
/// derive `Debug`/`Clone` here — callers compare the manifest
/// body and reverify the signatures separately.
#[derive(Debug, Clone)]
pub struct SealedArchiveManifest {
    /// The signed [`ArchiveManifest`] (clear text — segment / shard
    /// / media references are not secrets, only the body of the
    /// manifest is sealed). Both Ed25519 and ML-DSA-65 signatures
    /// live inside this struct.
    pub manifest: ArchiveManifest,
    /// Hybrid Ed25519 + ML-DSA-65 signatures produced during
    /// [`sign_archive_manifest`]. The same bytes are stored in
    /// `manifest.manifest_signature` and `manifest.pqc_signature`.
    pub signature: HybridManifestSignature,
    /// 24-byte XChaCha20-Poly1305 nonce sealing
    /// [`Self::ciphertext`].
    pub nonce: [u8; NONCE_LEN],
    /// AEAD ciphertext over the canonical CBOR encoding of
    /// [`Self::manifest`] under `K_archive_manifest`.
    pub ciphertext: Vec<u8>,
}

/// Inputs to [`build_archive_manifest`].
#[derive(Debug, Clone)]
pub struct ManifestBuildRequest<'a> {
    /// Sealed segments to commit under this manifest.
    pub segments: &'a [BuiltSegment],
    /// Search index shards committed under this manifest. Empty
    /// today — Phase 3 wires shard-segment encoding in a later
    /// task.
    pub search_index_shards: Vec<ManifestShardRef>,
    /// Media object references committed under this manifest. The
    /// upload orchestrator (Task 5) supplies these once a media
    /// blob is verified.
    pub media_references: Vec<ManifestMediaRef>,
    /// Tombstones committed under this manifest.
    pub tombstones: Vec<Tombstone>,
    /// Wrapped prior epoch keys carried into this manifest.
    ///
    /// `docs/PROPOSAL.md §2.1` (cross-epoch decryption): every
    /// retired epoch's key bytes are wrapped under
    /// `K_archive_root` (AES-256-KW) and recorded in the next
    /// archive manifest so future restore paths can unwrap and
    /// open prior-epoch segments. The orchestrator pulls these
    /// from
    /// [`crate::archive::epoch_keys::EpochKeyManager::take_pending_wrapped_prior_keys`]
    /// each time it cuts a manifest. Empty `Vec` is the typical
    /// case (no rotation since the last manifest); the field
    /// rides through unchanged via `#[serde(default)]` on
    /// [`ArchiveManifest::wrapped_prior_epoch_keys`].
    pub wrapped_prior_epoch_keys: Vec<WrappedEpochKeyRef>,
    /// Optional previous manifest in the chain. `None` produces a
    /// genesis manifest.
    pub previous: Option<&'a ArchiveManifest>,
}

/// Build a single archive-manifest record.
///
/// `signing_key` is the device's hybrid Ed25519 + ML-DSA-65
/// signing key (see [`HybridSigningKey`]).
/// `k_archive_manifest` is the AEAD key derived from the active
/// epoch key
/// (`K_archive_manifest = HKDF(K_archive_epoch, "kchat-archive-manifest-v1")`).
pub fn build_archive_manifest(
    request: ManifestBuildRequest<'_>,
    signing_key: &HybridSigningKey,
    k_archive_manifest: &[u8; 32],
) -> Result<SealedArchiveManifest, Error> {
    let (generation, previous_manifest_hash) = match request.previous {
        None => (0u64, GENESIS_PREVIOUS_HASH),
        Some(prev) => {
            let next = prev
                .generation
                .checked_add(1)
                .ok_or_else(|| Error::Storage("archive manifest generation overflow".into()))?;
            let hash = compute_archive_manifest_hash(prev).map_err(Error::Crypto)?;
            (next, hash)
        }
    };

    let segment_refs: Vec<ManifestSegmentRef> = request
        .segments
        .iter()
        .map(|s| {
            let ciphertext_sha256 = sha256(&s.ciphertext);
            ManifestSegmentRef {
                segment_id: s.segment_id,
                segment_type: s.segment_type,
                ciphertext_sha256,
                size: s.ciphertext.len() as u64,
            }
        })
        .collect();

    let merkle_root = compute_segment_merkle_root(request.segments);

    let mut manifest = ArchiveManifest {
        magic: ARCHIVE_MANIFEST_MAGIC.to_string(),
        version: MANIFEST_VERSION,
        manifest_id: Uuid::now_v7(),
        generation,
        previous_manifest_hash,
        segments: segment_refs,
        search_index_shards: request.search_index_shards,
        media_references: request.media_references,
        tombstones: request.tombstones,
        wrapped_prior_epoch_keys: request.wrapped_prior_epoch_keys,
        merkle_root,
        manifest_signature: Vec::new(),
        pqc_signature: Vec::new(),
    };

    let signature = sign_archive_manifest(&mut manifest, signing_key).map_err(Error::Crypto)?;

    // AEAD-seal the canonical CBOR of the (now-signed) manifest.
    let manifest_bytes = crate::cbor::to_vec(&manifest)
        .map_err(|_| Error::Crypto(CryptoError::Frame("manifest CBOR encode failed".into())))?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let aad = build_manifest_aad(&manifest.manifest_id, generation, &merkle_root);
    let ciphertext =
        seal(k_archive_manifest, &nonce, &manifest_bytes, &aad).map_err(Error::Crypto)?;

    Ok(SealedArchiveManifest {
        manifest,
        signature,
        nonce,
        ciphertext,
    })
}

/// AEAD AAD for an archive manifest seal:
/// `"KCHAT_ARC_MANIFEST_V1" || manifest_id(16) || generation(8 LE) || merkle_root(32)`.
pub fn build_manifest_aad(manifest_id: &Uuid, generation: u64, merkle_root: &[u8; 32]) -> Vec<u8> {
    const MAGIC: &[u8] = ARCHIVE_MANIFEST_MAGIC.as_bytes();
    let mut aad = Vec::with_capacity(MAGIC.len() + 16 + 8 + 32);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(manifest_id.as_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.extend_from_slice(merkle_root);
    aad
}

/// Open the AEAD-sealed manifest produced by
/// [`build_archive_manifest`]. Tests call this to round-trip the
/// ciphertext; the restore path will use it once Task 10's
/// hydrate wiring lands.
pub fn open_sealed_archive_manifest(
    sealed: &SealedArchiveManifest,
    k_archive_manifest: &[u8; 32],
) -> Result<ArchiveManifest, Error> {
    use crate::crypto::aead::xchacha20_poly1305::open;
    let aad = build_manifest_aad(
        &sealed.manifest.manifest_id,
        sealed.manifest.generation,
        &sealed.manifest.merkle_root,
    );
    let plaintext =
        open(k_archive_manifest, &sealed.nonce, &sealed.ciphertext, &aad).map_err(Error::Crypto)?;
    let manifest: ArchiveManifest = crate::cbor::from_slice(&plaintext)
        .map_err(|e| Error::Storage(format!("manifest CBOR decode: {e}")))?;
    Ok(manifest)
}

/// Compute the manifest's `merkle_root`: BLAKE3 over each
/// segment's plaintext `merkle_root` concatenated in order. Empty
/// segment lists hash the empty input — useful for the
/// pathological "no segments this generation" case.
fn compute_segment_merkle_root(segments: &[BuiltSegment]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for s in segments {
        hasher.update(&s.merkle_root);
    }
    *hasher.finalize().as_bytes()
}

/// SHA-256 of `bytes`. The manifest's
/// [`ManifestSegmentRef::ciphertext_sha256`] field is documented
/// as "SHA-256 of the segment's `ciphertext`" — keep this helper
/// local so the spec wording is the single source of truth.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
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
    use crate::archive::event_journal::{ArchiveEvent, ArchiveEventType};
    use crate::archive::segment_builder::{ArchiveSegmentBuilder, SegmentBuildRequest};
    use crate::crypto::signing::{HybridSigningKey, HybridVerifyingKey};
    use crate::formats::manifest::{compute_archive_manifest_hash, verify_archive_manifest};
    use rand::rngs::OsRng;

    /// Test helper: a fresh hybrid signing key per call. The
    /// existing tests only assert verification accepts/rejects
    /// the right keys, so a per-call random keypair is fine.
    fn fake_signing_key() -> HybridSigningKey {
        let mut rng = OsRng;
        HybridSigningKey::generate(&mut rng)
    }

    fn fake_segment(conv: Uuid, bucket: &str) -> BuiltSegment {
        let event = ArchiveEvent {
            event_type: ArchiveEventType::MessageReceived,
            conversation_id: conv,
            message_id: Some(Uuid::now_v7()),
            payload: vec![0xAB, 0xCD],
            created_at_ms: 1_777_000_000_000,
        };
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: bucket.into(),
            events: vec![event],
            segment_type: crate::formats::SegmentType::MessageDelta,
        };
        ArchiveSegmentBuilder::new()
            .build_segment(req, &[0x33; 32])
            .expect("seal segment")
    }

    fn k_manifest() -> [u8; 32] {
        [0x77; 32]
    }

    #[test]
    fn build_genesis_manifest() {
        let conv = Uuid::now_v7();
        let segs = vec![fake_segment(conv, "2026-04")];
        let req = ManifestBuildRequest {
            segments: &segs,
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            wrapped_prior_epoch_keys: vec![],
            previous: None,
        };
        let sealed = build_archive_manifest(req, &fake_signing_key(), &k_manifest()).unwrap();
        assert_eq!(sealed.manifest.generation, 0);
        assert_eq!(sealed.manifest.previous_manifest_hash, [0u8; 32]);
        assert_eq!(sealed.manifest.segments.len(), 1);
        assert_eq!(sealed.manifest.segments[0].segment_id, segs[0].segment_id);
        assert_eq!(
            sealed.manifest.segments[0].size as usize,
            segs[0].ciphertext.len()
        );
        assert!(sealed.manifest.has_valid_header());
    }

    #[test]
    fn build_chained_manifest() {
        let conv = Uuid::now_v7();
        let key = fake_signing_key();
        let km = k_manifest();

        // Generation 0.
        let segs0 = vec![fake_segment(conv, "2026-04")];
        let gen0 = build_archive_manifest(
            ManifestBuildRequest {
                segments: &segs0,
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                wrapped_prior_epoch_keys: vec![],
                previous: None,
            },
            &key,
            &km,
        )
        .unwrap();

        // Generation 1.
        let segs1 = vec![fake_segment(conv, "2026-05")];
        let gen1 = build_archive_manifest(
            ManifestBuildRequest {
                segments: &segs1,
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                wrapped_prior_epoch_keys: vec![WrappedEpochKeyRef {
                    epoch_id: "2026-04".into(),
                    wrapped_key: vec![0xAA; 40],
                }],
                previous: Some(&gen0.manifest),
            },
            &key,
            &km,
        )
        .unwrap();

        assert_eq!(gen1.manifest.generation, 1);
        let expected = compute_archive_manifest_hash(&gen0.manifest).unwrap();
        assert_eq!(
            gen1.manifest.previous_manifest_hash, expected,
            "chain anchor must hash gen0"
        );
    }

    #[test]
    fn manifest_signature_verifies() {
        let conv = Uuid::now_v7();
        let key = fake_signing_key();
        let segs = vec![fake_segment(conv, "2026-04")];
        let sealed = build_archive_manifest(
            ManifestBuildRequest {
                segments: &segs,
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                wrapped_prior_epoch_keys: vec![],
                previous: None,
            },
            &key,
            &k_manifest(),
        )
        .unwrap();
        let vk: HybridVerifyingKey = key.verifying_key();
        verify_archive_manifest(&sealed.manifest, &vk).expect("good signature");

        // Wrong key → reject.
        let mut rng = OsRng;
        let other_vk = HybridSigningKey::generate(&mut rng).verifying_key();
        verify_archive_manifest(&sealed.manifest, &other_vk).expect_err("wrong vk should fail");
    }

    #[test]
    fn wrong_key_fails_manifest_open() {
        let conv = Uuid::now_v7();
        let segs = vec![fake_segment(conv, "2026-04")];
        let sealed = build_archive_manifest(
            ManifestBuildRequest {
                segments: &segs,
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                wrapped_prior_epoch_keys: vec![],
                previous: None,
            },
            &fake_signing_key(),
            &k_manifest(),
        )
        .unwrap();

        // Round-trip with the right key.
        let opened = open_sealed_archive_manifest(&sealed, &k_manifest()).unwrap();
        assert_eq!(opened, sealed.manifest);

        // Wrong key fails.
        let bad_key = [0x99; 32];
        let err = open_sealed_archive_manifest(&sealed, &bad_key).unwrap_err();
        assert!(
            matches!(err, Error::Crypto(_)),
            "expected Crypto error, got {err:?}"
        );
    }
}
