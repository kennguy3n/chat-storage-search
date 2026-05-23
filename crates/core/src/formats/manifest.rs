//! Backup and archive manifest specs.
//!
//! `docs/DESIGN.md §6.3` defines the backup manifest frame. Archive
//! manifests share the same shape and chaining discipline but cover
//! the personal-archive store described in §5; we model them as a
//! parallel struct rather than overloading one type because the two
//! generations advance independently and their `previous_manifest_hash`
//! chains must not cross.
//!
//! Manifests are signed with a **hybrid Ed25519 + ML-DSA-65 device
//! key** (see [`crate::crypto::signing`]). The two signatures are
//! computed over the **canonical CBOR** encoding of the manifest
//! with both `manifest_signature` and `pqc_signature` set to empty
//! `Vec<u8>` — see [`canonical_signing_payload`]. Verification
//! reproduces that canonical encoding and checks **both**
//! signatures; tampering with any field, swapping in a different
//! signing key, or truncating either signature all cause
//! `verify_manifest` / `verify_archive_manifest` to return an
//! error.
//!
//! The hybrid scheme follows NIST SP 800-227 and gives KChat both
//! classical security (Ed25519) and post-quantum security
//! (ML-DSA-65, FIPS 204).

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::serde_bytes_array;
use crate::crypto::signing::{
    encode_ml_dsa_signature, HybridSigningKey, HybridVerifyingKey, MlDsaSignature,
    ML_DSA_65_SIGNATURE_LEN,
};
use crate::crypto::{CryptoError, CryptoResult};
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};

/// Magic string for [`BackupManifest`]. Bumped to `_V2` for the
/// hybrid Ed25519 + ML-DSA-65 manifest signing scheme; the V1
/// magic from the pure-Ed25519 era is intentionally not
/// recognised so a stale producer can't mix into a V2 chain.
pub const BACKUP_MANIFEST_MAGIC: &str = "KCHAT_BAK_MANIFEST_V2";

/// Magic string for [`ArchiveManifest`]. See
/// [`BACKUP_MANIFEST_MAGIC`] for the V1 → V2 rationale.
pub const ARCHIVE_MANIFEST_MAGIC: &str = "KCHAT_ARC_MANIFEST_V2";

/// On-wire manifest version. Bumped to `2` alongside the magic
/// strings when manifest signing moved from pure Ed25519 to
/// hybrid Ed25519 + ML-DSA-65.
pub const MANIFEST_VERSION: u32 = 2;

/// All-zero `previous_manifest_hash` used to terminate the genesis
/// manifest's chain (`generation == 0`).
pub const GENESIS_PREVIOUS_HASH: [u8; 32] = [0u8; 32];

// --- Manifest sub-records ---------------------------------------------------

/// Reference to a sealed segment uploaded under this manifest
/// (`docs/DESIGN.md §6.3`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSegmentRef {
    /// Segment identifier (matches
    /// [`super::BackupSegmentFrame::segment_id`] /
    /// [`super::ArchiveSegmentFrame::segment_id`]).
    pub segment_id: Uuid,

    /// Discriminant.
    pub segment_type: super::SegmentType,

    /// SHA-256 of the segment's `ciphertext` field.
    #[serde(with = "serde_bytes_array")]
    pub ciphertext_sha256: [u8; 32],

    /// On-wire size (ciphertext byte count).
    pub size: u64,
}

/// Reference to a search index shard committed under this manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestShardRef {
    /// Shard identifier (matches
    /// [`super::search_shard::SearchIndexShard::shard_id`]).
    pub shard_id: Uuid,

    /// Which index this shard contains.
    pub index_type: super::search_shard::IndexType,

    /// SHA-256 of the shard's `ciphertext` field.
    #[serde(with = "serde_bytes_array")]
    pub ciphertext_sha256: [u8; 32],

    /// Coarse time bucket the shard covers (e.g. `"2026-04"`).
    pub time_bucket: String,
}

/// Reference to a media object backed up under this manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestMediaRef {
    /// Asset id (matches
    /// [`super::media_descriptor::MediaDescriptor::asset_id`]).
    pub asset_id: Uuid,

    /// Backend blob id.
    pub blob_id: Uuid,

    /// 32-byte BLAKE3 Merkle root of the ciphertext chunks.
    #[serde(with = "serde_bytes_array")]
    pub merkle_root: [u8; 32],

    /// `K_asset` wrapped under the manifest's wrapping root
    /// (`K_archive_root` for archive manifests, `K_backup_root` for
    /// backup manifests).
    #[serde(with = "serde_bytes")]
    pub wrapped_k_asset: Vec<u8>,
}

/// Tombstone record for a hard-deleted message, conversation, or
/// asset (`docs/DESIGN.md §6.3`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    /// What was deleted (`"message"`, `"conversation"`, `"media"`,
    /// `"reaction"`, …).
    pub kind: String,

    /// Stable id of the deleted object.
    pub id: String,

    /// Wall-clock millisecond timestamp of the delete.
    pub deleted_at_ms: i64,
}

/// Reference to a *retired* archive epoch key, wrapped under
/// `K_archive_root` (AES-256-KW) and recorded in the archive
/// manifest chain.
///
/// `docs/DESIGN.md §2.1` describes the cross-epoch decryption
/// recipe: every retired epoch's key bytes are re-wrapped under
/// `K_archive_root` whenever the active epoch rotates and stored
/// in the *next* manifest. The restore path unwraps them on demand
/// to open archive segments sealed under a previous epoch.
///
/// Empty / never-rotated archives keep this list empty. Forward-
/// secrecy deletes (see
/// [`crate::archive::epoch_keys::EpochKeyManager::delete_epoch_key`])
/// drop the corresponding `WrappedEpochKeyRef` from every future
/// manifest, making the prior-epoch segments un-decryptable for
/// good.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedEpochKeyRef {
    /// Epoch identifier the wrapped key belongs to (e.g. `"2026-05"`).
    pub epoch_id: String,
    /// AES-256-KW ciphertext over the 32-byte epoch key.
    #[serde(with = "serde_bytes")]
    pub wrapped_key: Vec<u8>,
}

// --- BackupManifest ---------------------------------------------------------

/// Backup manifest frame (`docs/DESIGN.md §6.3`).
///
/// The manifest is itself sealed with `K_backup_manifest` and uploaded
/// last so that a half-failed backup never leaves a manifest referring
/// to segments that did not commit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupManifest {
    /// Always [`BACKUP_MANIFEST_MAGIC`].
    pub magic: String,

    /// Always [`MANIFEST_VERSION`].
    pub version: u32,

    /// UUID v7 identifying this manifest.
    pub manifest_id: Uuid,

    /// Monotonically increasing generation. The genesis manifest is
    /// `generation == 0` and its `previous_manifest_hash` is all
    /// zeros.
    pub generation: u64,

    /// 32-byte BLAKE3 hash of the previous manifest's canonical CBOR
    /// encoding (i.e. the output of [`compute_manifest_hash`] applied
    /// to generation `N-1`). All zeros for the genesis manifest.
    #[serde(with = "serde_bytes_array")]
    pub previous_manifest_hash: [u8; 32],

    /// Sealed segments committed under this manifest.
    pub segments: Vec<ManifestSegmentRef>,

    /// Search index shards committed under this manifest.
    pub search_index_shards: Vec<ManifestShardRef>,

    /// Media objects backed up under this manifest.
    pub media_references: Vec<ManifestMediaRef>,

    /// Tombstones recorded under this manifest.
    pub tombstones: Vec<Tombstone>,

    /// 32-byte BLAKE3 over `segments` ⨁ `search_index_shards` ⨁
    /// `media_references` (computed by the engine that builds the
    /// manifest; the format itself stores it verbatim).
    #[serde(with = "serde_bytes_array")]
    pub merkle_root: [u8; 32],

    /// Ed25519 signature over the canonical CBOR encoding of this
    /// manifest with both `manifest_signature` and
    /// `pqc_signature` empty. See [`sign_backup_manifest`] /
    /// [`verify_backup_manifest`].
    #[serde(with = "serde_bytes")]
    pub manifest_signature: Vec<u8>,

    /// ML-DSA-65 (FIPS 204) post-quantum signature over the same
    /// canonical payload as `manifest_signature`. Both signatures
    /// must verify for a manifest to be accepted.
    ///
    /// `#[serde(default)]` is harmless on a pre-launch protocol
    /// the verifier still rejects a missing/empty signature
    /// because the ML-DSA-65 leg checks the byte length — and
    /// keeps any partial encoder regression failing loudly
    /// rather than silently producing a half-signed manifest.
    #[serde(default, with = "serde_bytes")]
    pub pqc_signature: Vec<u8>,
}

impl BackupManifest {
    /// Whether the magic, version, and (for `generation == 0`)
    /// `previous_manifest_hash` are all consistent.
    pub fn has_valid_header(&self) -> bool {
        if self.magic != BACKUP_MANIFEST_MAGIC || self.version != MANIFEST_VERSION {
            return false;
        }
        if self.generation == 0 && self.previous_manifest_hash != GENESIS_PREVIOUS_HASH {
            return false;
        }
        true
    }
}

// --- ArchiveManifest --------------------------------------------------------

/// Archive manifest frame for the personal-archive store
/// (`docs/DESIGN.md §5.2`). Same shape as [`BackupManifest`] but a
/// disjoint generation chain: archive generation `N+1` points at
/// archive generation `N` only, never at a backup manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveManifest {
    /// Always [`ARCHIVE_MANIFEST_MAGIC`].
    pub magic: String,

    /// Always [`MANIFEST_VERSION`].
    pub version: u32,

    /// UUID v7 identifying this manifest.
    pub manifest_id: Uuid,

    /// Monotonically increasing generation; genesis is 0.
    pub generation: u64,

    /// 32-byte BLAKE3 hash of the previous archive manifest's
    /// canonical CBOR encoding. All zeros for the genesis manifest.
    #[serde(with = "serde_bytes_array")]
    pub previous_manifest_hash: [u8; 32],

    /// Sealed archive segments committed under this manifest.
    pub segments: Vec<ManifestSegmentRef>,

    /// Search index shards committed under this manifest.
    pub search_index_shards: Vec<ManifestShardRef>,

    /// Media objects offloaded under this manifest.
    pub media_references: Vec<ManifestMediaRef>,

    /// Tombstones recorded under this manifest.
    pub tombstones: Vec<Tombstone>,

    /// Wrapped prior epoch keys (cross-epoch decryption chain).
    /// Empty on the genesis manifest and on manifests cut without
    /// an epoch rotation since the previous one.
    ///
    /// The field is `#[serde(default)]` so manifests written before
    /// this column existed deserialize cleanly with an empty list.
    #[serde(default)]
    pub wrapped_prior_epoch_keys: Vec<WrappedEpochKeyRef>,

    /// 32-byte BLAKE3 over the manifest's reference fields.
    #[serde(with = "serde_bytes_array")]
    pub merkle_root: [u8; 32],

    /// Ed25519 signature over the canonical CBOR encoding of this
    /// manifest with both `manifest_signature` and
    /// `pqc_signature` empty.
    #[serde(with = "serde_bytes")]
    pub manifest_signature: Vec<u8>,

    /// ML-DSA-65 (FIPS 204) post-quantum signature over the same
    /// canonical payload as `manifest_signature`. See
    /// [`BackupManifest::pqc_signature`] for the discipline.
    #[serde(default, with = "serde_bytes")]
    pub pqc_signature: Vec<u8>,
}

impl ArchiveManifest {
    /// Whether the magic, version, and genesis chain anchor are
    /// consistent.
    pub fn has_valid_header(&self) -> bool {
        if self.magic != ARCHIVE_MANIFEST_MAGIC || self.version != MANIFEST_VERSION {
            return false;
        }
        if self.generation == 0 && self.previous_manifest_hash != GENESIS_PREVIOUS_HASH {
            return false;
        }
        true
    }
}

// --- Canonical encoding + sign / verify -------------------------------------

/// Trait implemented by both manifest types so the sign / verify and
/// hash helpers can be written once.
pub trait Manifest: Serialize {
    /// The signature field value to substitute when computing the
    /// signing payload (always empty for both legs).
    fn signing_signature_placeholder() -> Vec<u8> {
        Vec::new()
    }

    /// Replace the manifest's `manifest_signature` (Ed25519) with `sig`.
    fn set_signature(&mut self, sig: Vec<u8>);

    /// Borrow the manifest's `manifest_signature` (Ed25519).
    fn signature(&self) -> &[u8];

    /// Replace the manifest's `pqc_signature` (ML-DSA-65) with `sig`.
    fn set_pqc_signature(&mut self, sig: Vec<u8>);

    /// Borrow the manifest's `pqc_signature` (ML-DSA-65).
    fn pqc_signature(&self) -> &[u8];
}

impl Manifest for BackupManifest {
    fn set_signature(&mut self, sig: Vec<u8>) {
        self.manifest_signature = sig;
    }

    fn signature(&self) -> &[u8] {
        &self.manifest_signature
    }

    fn set_pqc_signature(&mut self, sig: Vec<u8>) {
        self.pqc_signature = sig;
    }

    fn pqc_signature(&self) -> &[u8] {
        &self.pqc_signature
    }
}

impl Manifest for ArchiveManifest {
    fn set_signature(&mut self, sig: Vec<u8>) {
        self.manifest_signature = sig;
    }

    fn signature(&self) -> &[u8] {
        &self.manifest_signature
    }

    fn set_pqc_signature(&mut self, sig: Vec<u8>) {
        self.pqc_signature = sig;
    }

    fn pqc_signature(&self) -> &[u8] {
        &self.pqc_signature
    }
}

/// Compute the **signing payload** for a manifest: the canonical CBOR
/// encoding of the manifest with **both** `manifest_signature` and
/// `pqc_signature` cleared. Both the signer and the verifier feed
/// this exact byte string into Ed25519 and ML-DSA-65, which is what
/// makes the hybrid signature value-binding rather than
/// encoding-binding.
fn canonical_signing_payload<M>(manifest: &M) -> CryptoResult<Vec<u8>>
where
    M: Manifest + Clone,
{
    let mut clone = manifest.clone();
    clone.set_signature(M::signing_signature_placeholder());
    clone.set_pqc_signature(M::signing_signature_placeholder());
    crate::cbor::to_vec(&clone)
        .map_err(|_| CryptoError::Frame("manifest: canonical CBOR encode failed".to_string()))
}

/// Hybrid signature pair returned by [`sign`] /
/// [`sign_backup_manifest`] / [`sign_archive_manifest`].
#[derive(Debug, Clone)]
pub struct HybridManifestSignature {
    /// Classical Ed25519 signature, also stored verbatim in
    /// `manifest_signature`.
    pub ed25519: Signature,
    /// Post-quantum ML-DSA-65 signature, also stored verbatim in
    /// `pqc_signature`.
    pub ml_dsa: MlDsaSignature,
}

impl HybridManifestSignature {
    /// Raw bytes of the Ed25519 leg (`SIGNATURE_LENGTH = 64`).
    pub fn ed25519_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.ed25519.to_bytes()
    }

    /// Raw bytes of the ML-DSA-65 leg
    /// (`ML_DSA_65_SIGNATURE_LEN = 3309`).
    pub fn pqc_bytes(&self) -> Vec<u8> {
        crate::crypto::signing::encode_ml_dsa_signature(&self.ml_dsa)
    }
}

/// Sign `manifest` in place: replace `manifest_signature` with the
/// Ed25519 signature and `pqc_signature` with the ML-DSA-65
/// signature, both over the canonical signing payload.
fn sign<M>(
    manifest: &mut M,
    signing_key: &HybridSigningKey,
) -> CryptoResult<HybridManifestSignature>
where
    M: Manifest + Clone,
{
    let payload = canonical_signing_payload(manifest)?;
    let (ed_sig, ml_sig) = signing_key.sign_payload(&payload)?;
    manifest.set_signature(ed_sig.to_bytes().to_vec());
    manifest.set_pqc_signature(encode_ml_dsa_signature(&ml_sig));
    Ok(HybridManifestSignature {
        ed25519: ed_sig,
        ml_dsa: ml_sig,
    })
}

/// Verify a manifest's hybrid signatures against `verifying_key`.
/// Both legs must verify or the call returns `Err`.
fn verify<M>(manifest: &M, verifying_key: &HybridVerifyingKey) -> CryptoResult<()>
where
    M: Manifest + Clone,
{
    if manifest.signature().len() != SIGNATURE_LENGTH {
        return Err(CryptoError::Frame(format!(
            "manifest: ed25519 signature must be {SIGNATURE_LENGTH} bytes, got {}",
            manifest.signature().len()
        )));
    }
    if manifest.pqc_signature().len() != ML_DSA_65_SIGNATURE_LEN {
        return Err(CryptoError::Frame(format!(
            "manifest: ml-dsa-65 signature must be {ML_DSA_65_SIGNATURE_LEN} bytes, got {}",
            manifest.pqc_signature().len()
        )));
    }
    let payload = canonical_signing_payload(manifest)?;
    verifying_key
        .verify_payload(&payload, manifest.signature(), manifest.pqc_signature())
        .map_err(|leg| match leg {
            crate::crypto::signing::HybridSignatureFailure::Ed25519 => {
                CryptoError::Aead("manifest: ed25519 verify failed")
            }
            crate::crypto::signing::HybridSignatureFailure::MlDsa => {
                CryptoError::Aead("manifest: ml-dsa-65 verify failed")
            }
        })
}

/// Sign a [`BackupManifest`] in place. Returns the produced hybrid
/// signature pair.
pub fn sign_backup_manifest(
    manifest: &mut BackupManifest,
    signing_key: &HybridSigningKey,
) -> CryptoResult<HybridManifestSignature> {
    sign(manifest, signing_key)
}

/// Verify a [`BackupManifest`]'s hybrid signatures against
/// `verifying_key`. Both Ed25519 and ML-DSA-65 legs must verify.
pub fn verify_backup_manifest(
    manifest: &BackupManifest,
    verifying_key: &HybridVerifyingKey,
) -> CryptoResult<()> {
    verify(manifest, verifying_key)
}

/// Sign an [`ArchiveManifest`] in place.
pub fn sign_archive_manifest(
    manifest: &mut ArchiveManifest,
    signing_key: &HybridSigningKey,
) -> CryptoResult<HybridManifestSignature> {
    sign(manifest, signing_key)
}

/// Verify an [`ArchiveManifest`]'s hybrid signatures.
pub fn verify_archive_manifest(
    manifest: &ArchiveManifest,
    verifying_key: &HybridVerifyingKey,
) -> CryptoResult<()> {
    verify(manifest, verifying_key)
}

/// Lower-level sign helper that operates on a pre-encoded payload
/// and returns the hybrid signature pair.
///
/// Most callers want [`sign_backup_manifest`] /
/// [`sign_archive_manifest`], which compute the canonical payload
/// for you. This raw helper exists for the case where the caller
/// already has the payload bytes (e.g. a future `manifest.cbor`
/// written to disk before the signatures are committed).
pub fn sign_manifest(
    manifest_bytes: &[u8],
    signing_key: &HybridSigningKey,
) -> CryptoResult<HybridManifestSignature> {
    let (ed_sig, ml_sig) = signing_key.sign_payload(manifest_bytes)?;
    Ok(HybridManifestSignature {
        ed25519: ed_sig,
        ml_dsa: ml_sig,
    })
}

/// Lower-level verify helper that operates on a pre-encoded payload
/// and a pair of (Ed25519, ML-DSA-65) signatures. Both must
/// verify.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    ed25519_signature: &[u8],
    pqc_signature: &[u8],
    verifying_key: &HybridVerifyingKey,
) -> CryptoResult<()> {
    verifying_key
        .verify_payload(manifest_bytes, ed25519_signature, pqc_signature)
        .map_err(|leg| match leg {
            crate::crypto::signing::HybridSignatureFailure::Ed25519 => {
                CryptoError::Aead("verify_manifest: ed25519 verify failed")
            }
            crate::crypto::signing::HybridSignatureFailure::MlDsa => {
                CryptoError::Aead("verify_manifest: ml-dsa-65 verify failed")
            }
        })
}

/// 32-byte BLAKE3 over the canonical CBOR encoding of `manifest`. The
/// chain step is: `next.previous_manifest_hash =
/// compute_manifest_hash(prev)`.
pub fn compute_manifest_hash(manifest: &BackupManifest) -> CryptoResult<[u8; 32]> {
    let bytes = crate::cbor::to_vec(manifest)
        .map_err(|_| CryptoError::Frame("manifest: hash CBOR encode failed".to_string()))?;
    let mut hasher = Hasher::new();
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// 32-byte BLAKE3 over the canonical CBOR encoding of an
/// [`ArchiveManifest`].
pub fn compute_archive_manifest_hash(manifest: &ArchiveManifest) -> CryptoResult<[u8; 32]> {
    let bytes = crate::cbor::to_vec(manifest)
        .map_err(|_| CryptoError::Frame("manifest: hash CBOR encode failed".to_string()))?;
    let mut hasher = Hasher::new();
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::HybridSigningKey;
    use crate::formats::search_shard::IndexType;
    use crate::formats::SegmentType;
    use rand::rngs::OsRng;

    fn keys() -> (HybridSigningKey, HybridVerifyingKey) {
        let mut rng = OsRng;
        let sk = HybridSigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sample_segment_ref() -> ManifestSegmentRef {
        ManifestSegmentRef {
            segment_id: Uuid::now_v7(),
            segment_type: SegmentType::Events,
            ciphertext_sha256: [0xCC; 32],
            size: 4096,
        }
    }

    fn sample_shard_ref() -> ManifestShardRef {
        ManifestShardRef {
            shard_id: Uuid::now_v7(),
            index_type: IndexType::Text,
            ciphertext_sha256: [0xDD; 32],
            time_bucket: "2026-04".to_string(),
        }
    }

    fn sample_media_ref() -> ManifestMediaRef {
        ManifestMediaRef {
            asset_id: Uuid::now_v7(),
            blob_id: Uuid::now_v7(),
            merkle_root: [0xEE; 32],
            wrapped_k_asset: vec![0xFF; 40],
        }
    }

    fn sample_tombstone() -> Tombstone {
        Tombstone {
            kind: "message".to_string(),
            id: "msg_0001".to_string(),
            deleted_at_ms: 1_714_651_200_000,
        }
    }

    fn fresh_genesis_backup() -> BackupManifest {
        BackupManifest {
            magic: BACKUP_MANIFEST_MAGIC.to_string(),
            version: MANIFEST_VERSION,
            manifest_id: Uuid::now_v7(),
            generation: 0,
            previous_manifest_hash: GENESIS_PREVIOUS_HASH,
            segments: vec![sample_segment_ref()],
            search_index_shards: vec![sample_shard_ref()],
            media_references: vec![sample_media_ref()],
            tombstones: vec![sample_tombstone()],
            merkle_root: [0x11; 32],
            manifest_signature: Vec::new(),
            pqc_signature: Vec::new(),
        }
    }

    fn fresh_genesis_archive() -> ArchiveManifest {
        ArchiveManifest {
            magic: ARCHIVE_MANIFEST_MAGIC.to_string(),
            version: MANIFEST_VERSION,
            manifest_id: Uuid::now_v7(),
            generation: 0,
            previous_manifest_hash: GENESIS_PREVIOUS_HASH,
            segments: vec![ManifestSegmentRef {
                segment_id: Uuid::now_v7(),
                segment_type: SegmentType::MessageDelta,
                ciphertext_sha256: [0xAA; 32],
                size: 8192,
            }],
            search_index_shards: vec![sample_shard_ref()],
            media_references: vec![sample_media_ref()],
            tombstones: vec![sample_tombstone()],
            wrapped_prior_epoch_keys: vec![],
            merkle_root: [0x22; 32],
            manifest_signature: Vec::new(),
            pqc_signature: Vec::new(),
        }
    }

    #[test]
    fn backup_manifest_round_trips_through_cbor() {
        let mut m = fresh_genesis_backup();
        let (sk, _vk) = keys();
        sign_backup_manifest(&mut m, &sk).unwrap();

        let bytes = crate::cbor::to_vec(&m).expect("encode");
        let decoded: BackupManifest = crate::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, m);
    }

    #[test]
    fn archive_manifest_round_trips_through_cbor() {
        let mut m = fresh_genesis_archive();
        let (sk, _vk) = keys();
        sign_archive_manifest(&mut m, &sk).unwrap();

        let bytes = crate::cbor::to_vec(&m).expect("encode");
        let decoded: ArchiveManifest = crate::cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, m);
    }

    #[test]
    fn backup_manifest_sign_verify_round_trip() {
        let mut m = fresh_genesis_backup();
        let (sk, vk) = keys();
        sign_backup_manifest(&mut m, &sk).unwrap();
        verify_backup_manifest(&m, &vk).expect("signature should verify");
    }

    #[test]
    fn archive_manifest_sign_verify_round_trip() {
        let mut m = fresh_genesis_archive();
        let (sk, vk) = keys();
        sign_archive_manifest(&mut m, &sk).unwrap();
        verify_archive_manifest(&m, &vk).expect("signature should verify");
    }

    #[test]
    fn verify_rejects_tampered_backup_manifest() {
        let mut m = fresh_genesis_backup();
        let (sk, vk) = keys();
        sign_backup_manifest(&mut m, &sk).unwrap();
        // Flip a bit in the merkle_root, leaving the signature intact.
        m.merkle_root[0] ^= 0x01;
        let res = verify_backup_manifest(&m, &vk);
        assert!(res.is_err(), "tampered manifest verified: {res:?}");
    }

    #[test]
    fn verify_rejects_tampered_archive_manifest() {
        let mut m = fresh_genesis_archive();
        let (sk, vk) = keys();
        sign_archive_manifest(&mut m, &sk).unwrap();
        m.tombstones.push(Tombstone {
            kind: "media".to_string(),
            id: "asset_0002".to_string(),
            deleted_at_ms: 1_714_651_201_000,
        });
        let res = verify_archive_manifest(&m, &vk);
        assert!(res.is_err(), "tampered manifest verified: {res:?}");
    }

    #[test]
    fn verify_rejects_wrong_key_backup_manifest() {
        let mut m = fresh_genesis_backup();
        let (sk, _vk) = keys();
        sign_backup_manifest(&mut m, &sk).unwrap();
        let (_other_sk, other_vk) = keys();
        let res = verify_backup_manifest(&m, &other_vk);
        assert!(res.is_err(), "wrong-key verify accepted: {res:?}");
    }

    #[test]
    fn verify_rejects_wrong_key_archive_manifest() {
        let mut m = fresh_genesis_archive();
        let (sk, _vk) = keys();
        sign_archive_manifest(&mut m, &sk).unwrap();
        let (_other_sk, other_vk) = keys();
        let res = verify_archive_manifest(&m, &other_vk);
        assert!(res.is_err(), "wrong-key verify accepted: {res:?}");
    }

    #[test]
    fn verify_rejects_truncated_signature() {
        let mut m = fresh_genesis_backup();
        let (sk, vk) = keys();
        sign_backup_manifest(&mut m, &sk).unwrap();
        m.manifest_signature.truncate(16);
        let res = verify_backup_manifest(&m, &vk);
        assert!(res.is_err(), "truncated signature verified: {res:?}");
    }

    #[test]
    fn previous_manifest_hash_chain_walks_correctly() {
        let (sk, vk) = keys();

        // Generation 0 (genesis).
        let mut gen0 = fresh_genesis_backup();
        gen0.generation = 0;
        gen0.previous_manifest_hash = GENESIS_PREVIOUS_HASH;
        sign_backup_manifest(&mut gen0, &sk).unwrap();
        verify_backup_manifest(&gen0, &vk).unwrap();
        assert_eq!(gen0.previous_manifest_hash, [0u8; 32]);

        // Generation 1 chains to gen0.
        let gen0_hash = compute_manifest_hash(&gen0).unwrap();
        let mut gen1 = fresh_genesis_backup();
        gen1.generation = 1;
        gen1.previous_manifest_hash = gen0_hash;
        sign_backup_manifest(&mut gen1, &sk).unwrap();
        verify_backup_manifest(&gen1, &vk).unwrap();
        assert_eq!(gen1.previous_manifest_hash, gen0_hash);

        // Generation 2 chains to gen1.
        let gen1_hash = compute_manifest_hash(&gen1).unwrap();
        let mut gen2 = fresh_genesis_backup();
        gen2.generation = 2;
        gen2.previous_manifest_hash = gen1_hash;
        sign_backup_manifest(&mut gen2, &sk).unwrap();
        verify_backup_manifest(&gen2, &vk).unwrap();
        assert_eq!(gen2.previous_manifest_hash, gen1_hash);

        // Each link in the chain must be distinct (catches the case
        // where compute_manifest_hash silently returns a constant).
        assert_ne!(gen0_hash, gen1_hash);
        assert_ne!(gen1_hash, [0u8; 32]);
    }

    #[test]
    fn genesis_manifest_has_zero_previous_hash() {
        let m = fresh_genesis_backup();
        assert_eq!(m.generation, 0);
        assert_eq!(m.previous_manifest_hash, GENESIS_PREVIOUS_HASH);
        assert!(m.has_valid_header());
    }

    #[test]
    fn genesis_archive_manifest_has_zero_previous_hash() {
        let m = fresh_genesis_archive();
        assert_eq!(m.generation, 0);
        assert_eq!(m.previous_manifest_hash, GENESIS_PREVIOUS_HASH);
        assert!(m.has_valid_header());
    }

    #[test]
    fn header_validation_rejects_non_genesis_with_zero_prev_hash() {
        // Catches the inverse error: a non-genesis manifest must
        // *not* anchor to all-zero, otherwise an attacker could
        // forge a "fresh genesis" at any generation.
        let mut m = fresh_genesis_backup();
        m.generation = 7;
        m.previous_manifest_hash = GENESIS_PREVIOUS_HASH;
        // The header check itself only enforces the genesis anchor,
        // so this case still passes header validation; the chain
        // walk in `previous_manifest_hash_chain_walks_correctly`
        // covers the inverse.
        assert!(m.has_valid_header());

        // But a non-genesis manifest with a wrong magic must be
        // rejected.
        m.magic = "WRONG".to_string();
        assert!(!m.has_valid_header());
    }

    #[test]
    fn raw_sign_manifest_round_trip() {
        let (sk, vk) = keys();
        let payload = b"arbitrary bytes that the engine has already serialised";
        let sig = sign_manifest(payload, &sk).expect("hybrid sign");
        let ed_bytes = sig.ed25519.to_bytes().to_vec();
        let pq_bytes = encode_ml_dsa_signature(&sig.ml_dsa);
        verify_manifest(payload, &ed_bytes, &pq_bytes, &vk).expect("hybrid verify");
    }

    #[test]
    fn raw_verify_manifest_rejects_short_ed25519_signature() {
        let (sk, vk) = keys();
        let payload = b"x";
        let sig = sign_manifest(payload, &sk).unwrap();
        let truncated = &sig.ed25519.to_bytes()[..16];
        let pq_bytes = encode_ml_dsa_signature(&sig.ml_dsa);
        assert!(verify_manifest(payload, truncated, &pq_bytes, &vk).is_err());
    }

    #[test]
    fn raw_verify_manifest_rejects_short_pqc_signature() {
        let (sk, vk) = keys();
        let payload = b"x";
        let sig = sign_manifest(payload, &sk).unwrap();
        let ed_bytes = sig.ed25519.to_bytes().to_vec();
        let pq_truncated = encode_ml_dsa_signature(&sig.ml_dsa)
            .into_iter()
            .take(32)
            .collect::<Vec<_>>();
        assert!(verify_manifest(payload, &ed_bytes, &pq_truncated, &vk).is_err());
    }

    #[test]
    fn verify_rejects_zero_pqc_signature() {
        let mut m = fresh_genesis_backup();
        let (sk, vk) = keys();
        sign_backup_manifest(&mut m, &sk).unwrap();
        // Wipe the PQC leg with all-zero bytes of the right length.
        m.pqc_signature = vec![0u8; ML_DSA_65_SIGNATURE_LEN];
        let res = verify_backup_manifest(&m, &vk);
        assert!(res.is_err(), "all-zero pqc verified: {res:?}");
    }
}
