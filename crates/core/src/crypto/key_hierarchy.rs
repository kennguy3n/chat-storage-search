//! HKDF-SHA256 key derivation tree rooted at `K_user_master`.
//!
//! Layout (from `docs/PROPOSAL.md §2.1`):
//!
//! ```text
//! K_user_master
//!  ├── K_archive_root          (info = "kchat-archive-root-v1")
//!  │     ├── K_archive_segment(segment_id)   (info = "kchat-archive-segment-v1" || segment_id)
//!  │     └── K_archive_manifest(manifest_id) (info = "kchat-archive-manifest-v1" || manifest_id)
//!  ├── K_backup_root           (info = "kchat-backup-root-v1")
//!  │     ├── K_backup_segment(segment_id)    (info = "kchat-backup-segment-v1" || segment_id)
//!  │     └── K_backup_manifest(manifest_id)  (info = "kchat-backup-manifest-v1" || manifest_id)
//!  ├── K_search_root           (info = "kchat-search-root-v1")
//!  │     ├── K_text_index_shard(shard_id)    (info = "kchat-text-index-shard-v1" || shard_id)
//!  │     ├── K_vector_index_shard(shard_id)  (info = "kchat-vector-index-shard-v1" || shard_id)
//!  │     └── K_media_index_shard(shard_id)   (info = "kchat-media-index-shard-v1" || shard_id)
//!  └── K_profile_private_data  (info = "kchat-profile-private-data-v1")
//! ```
//!
//! All derivations are HKDF-SHA256 with `salt = None` and the
//! versioned `info` strings above. Output length is fixed at
//! [`KEY_LEN`] (32 bytes). Versioned `info` strings let a future
//! rotation derive a disjoint key space without colliding with
//! deployed manifests.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CryptoError, CryptoResult};

/// Length of every key in the hierarchy, in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Versioned HKDF `info` strings. Changing any of these is a breaking
/// derivation-tree change and must bump the `-vN` suffix.
pub mod info {
    pub const ARCHIVE_ROOT: &[u8] = b"kchat-archive-root-v1";
    pub const BACKUP_ROOT: &[u8] = b"kchat-backup-root-v1";
    pub const SEARCH_ROOT: &[u8] = b"kchat-search-root-v1";
    pub const PROFILE_PRIVATE_DATA: &[u8] = b"kchat-profile-private-data-v1";

    pub const ARCHIVE_SEGMENT: &[u8] = b"kchat-archive-segment-v1";
    pub const ARCHIVE_MANIFEST: &[u8] = b"kchat-archive-manifest-v1";
    pub const BACKUP_SEGMENT: &[u8] = b"kchat-backup-segment-v1";
    pub const BACKUP_MANIFEST: &[u8] = b"kchat-backup-manifest-v1";
    pub const TEXT_INDEX_SHARD: &[u8] = b"kchat-text-index-shard-v1";
    pub const VECTOR_INDEX_SHARD: &[u8] = b"kchat-vector-index-shard-v1";
    pub const MEDIA_INDEX_SHARD: &[u8] = b"kchat-media-index-shard-v1";
    /// Phase 8 (2026-05-04 batch) — bloom-filter shard.
    pub const BLOOM_INDEX_SHARD: &[u8] = b"kchat-bloom-index-shard-v1";

    /// Phase-3 epoch-rotated archive key. `info` =
    /// `b"kchat-archive-epoch-v1" || epoch_id`.
    pub const ARCHIVE_EPOCH: &[u8] = b"kchat-archive-epoch-v1";
}

/// Owned, zeroizing 32-byte key material. Dropping a [`KeyMaterial`]
/// scrubs its bytes; cloning copies them into a new `KeyMaterial`
/// that scrubs on its own drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial([u8; KEY_LEN]);

impl KeyMaterial {
    /// Build a `KeyMaterial` from a 32-byte array.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Try to build a `KeyMaterial` from a slice. Errors when the
    /// slice is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidInput(
                "KeyMaterial::from_slice: expected 32 bytes",
            ));
        }
        let mut buf = [0u8; KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// Borrow the key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Length of the key in bytes (always [`KEY_LEN`]).
    #[inline]
    pub fn len(&self) -> usize {
        KEY_LEN
    }

    /// `KeyMaterial` is never empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl AsRef<[u8]> for KeyMaterial {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Avoid leaking key bytes through `Debug` output.
impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("len", &KEY_LEN)
            .finish()
    }
}

/// Derive a 32-byte child key from `parent` using HKDF-SHA256.
///
/// `info` is the versioned label (e.g. [`info::ARCHIVE_ROOT`]); for
/// per-object sub-keys it is the parent label concatenated with the
/// stable identifier (e.g. `b"kchat-archive-segment-v1" || segment_id`).
/// HKDF is `salt = None` for every derivation in the hierarchy.
pub fn derive(parent: &[u8], info: &[u8]) -> CryptoResult<KeyMaterial> {
    let hk = Hkdf::<Sha256>::new(None, parent);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::Kdf("hkdf-sha256 expand failed"))?;
    Ok(KeyMaterial::from_bytes(okm))
}

fn derive_with_id(parent: &[u8], label: &[u8], id: &[u8]) -> CryptoResult<KeyMaterial> {
    let mut info = Vec::with_capacity(label.len() + id.len());
    info.extend_from_slice(label);
    info.extend_from_slice(id);
    derive(parent, &info)
}

/// Derive `K_archive_root` from `K_user_master`.
pub fn derive_archive_root(master: &KeyMaterial) -> CryptoResult<KeyMaterial> {
    derive(master.as_bytes(), info::ARCHIVE_ROOT)
}

/// Derive `K_backup_root` from `K_user_master`.
pub fn derive_backup_root(master: &KeyMaterial) -> CryptoResult<KeyMaterial> {
    derive(master.as_bytes(), info::BACKUP_ROOT)
}

/// Derive `K_search_root` from `K_user_master`.
pub fn derive_search_root(master: &KeyMaterial) -> CryptoResult<KeyMaterial> {
    derive(master.as_bytes(), info::SEARCH_ROOT)
}

/// Derive `K_profile_private_data` from `K_user_master`.
pub fn derive_profile_private_data(master: &KeyMaterial) -> CryptoResult<KeyMaterial> {
    derive(master.as_bytes(), info::PROFILE_PRIVATE_DATA)
}

/// Derive `K_archive_segment(segment_id)` from `K_archive_root`.
pub fn derive_archive_segment(
    archive_root: &KeyMaterial,
    segment_id: &[u8],
) -> CryptoResult<KeyMaterial> {
    derive_with_id(archive_root.as_bytes(), info::ARCHIVE_SEGMENT, segment_id)
}

/// Derive `K_archive_manifest(manifest_id)` from `K_archive_root`.
pub fn derive_archive_manifest(
    archive_root: &KeyMaterial,
    manifest_id: &[u8],
) -> CryptoResult<KeyMaterial> {
    derive_with_id(archive_root.as_bytes(), info::ARCHIVE_MANIFEST, manifest_id)
}

/// Derive `K_backup_segment(segment_id)` from `K_backup_root`.
pub fn derive_backup_segment(
    backup_root: &KeyMaterial,
    segment_id: &[u8],
) -> CryptoResult<KeyMaterial> {
    derive_with_id(backup_root.as_bytes(), info::BACKUP_SEGMENT, segment_id)
}

/// Derive `K_backup_manifest(manifest_id)` from `K_backup_root`.
pub fn derive_backup_manifest(
    backup_root: &KeyMaterial,
    manifest_id: &[u8],
) -> CryptoResult<KeyMaterial> {
    derive_with_id(backup_root.as_bytes(), info::BACKUP_MANIFEST, manifest_id)
}

/// Derive `K_text_index_shard(shard_id)` from `K_search_root`.
pub fn derive_text_index_shard(
    search_root: &KeyMaterial,
    shard_id: &[u8],
) -> CryptoResult<KeyMaterial> {
    derive_with_id(search_root.as_bytes(), info::TEXT_INDEX_SHARD, shard_id)
}

/// Derive `K_vector_index_shard(shard_id)` from `K_search_root`.
pub fn derive_vector_index_shard(
    search_root: &KeyMaterial,
    shard_id: &[u8],
) -> CryptoResult<KeyMaterial> {
    derive_with_id(search_root.as_bytes(), info::VECTOR_INDEX_SHARD, shard_id)
}

/// Derive `K_media_index_shard(shard_id)` from `K_search_root`.
pub fn derive_media_index_shard(
    search_root: &KeyMaterial,
    shard_id: &[u8],
) -> CryptoResult<KeyMaterial> {
    derive_with_id(search_root.as_bytes(), info::MEDIA_INDEX_SHARD, shard_id)
}

/// Derive `K_bloom_index_shard(shard_id)` from `K_search_root`.
/// Phase 8 (2026-05-04 batch) — used to seal per-bucket bloom
/// filter shards built by [`crate::search::shard_builder::build_bloom_shard`].
pub fn derive_bloom_index_shard(
    search_root: &KeyMaterial,
    shard_id: &[u8],
) -> CryptoResult<KeyMaterial> {
    derive_with_id(search_root.as_bytes(), info::BLOOM_INDEX_SHARD, shard_id)
}

// ---------------------------------------------------------------------------
// Phase-3: epoch-rotated archive keys
// ---------------------------------------------------------------------------

/// Derive `K_archive_epoch(epoch_id)` from `K_archive_root`.
///
/// `docs/PHASES.md` Phase 3 calls for an extra epoch indirection
/// between `K_archive_root` and the per-segment / per-manifest
/// keys: each "epoch" gets its own subkey so the orchestration
/// layer can rotate without re-deriving every leaf key.
///
/// HKDF info = [`info::ARCHIVE_EPOCH`] concatenated with
/// `epoch_id.as_bytes()`.
pub fn derive_archive_epoch_key(
    k_archive_root: &KeyMaterial,
    epoch_id: &str,
) -> CryptoResult<KeyMaterial> {
    derive_with_id(
        k_archive_root.as_bytes(),
        info::ARCHIVE_EPOCH,
        epoch_id.as_bytes(),
    )
}

/// Derive `K_archive_segment(segment_id)` from a (possibly rotated)
/// epoch key. Versioned under [`info::ARCHIVE_SEGMENT`] so the
/// segment-level info string matches the non-epoch derivation.
pub fn derive_archive_segment_key(
    k_archive_epoch: &KeyMaterial,
    segment_id: &str,
) -> CryptoResult<KeyMaterial> {
    derive_with_id(
        k_archive_epoch.as_bytes(),
        info::ARCHIVE_SEGMENT,
        segment_id.as_bytes(),
    )
}

/// Derive `K_archive_manifest(manifest_id)` from an epoch key.
pub fn derive_archive_manifest_key(
    k_archive_epoch: &KeyMaterial,
    manifest_id: &str,
) -> CryptoResult<KeyMaterial> {
    derive_with_id(
        k_archive_epoch.as_bytes(),
        info::ARCHIVE_MANIFEST,
        manifest_id.as_bytes(),
    )
}

/// AES-256-KW wrap an epoch key under `K_archive_root` so the
/// orchestration layer can persist prior-epoch keys in the
/// manifest chain (and unwrap them again on hydration).
pub fn wrap_epoch_key(
    k_archive_root: &KeyMaterial,
    k_archive_epoch: &KeyMaterial,
) -> CryptoResult<Vec<u8>> {
    super::key_wrap::wrap_key(k_archive_root.as_bytes(), k_archive_epoch.as_bytes())
}

/// AES-256-KW unwrap a wrapped epoch key produced by
/// [`wrap_epoch_key`].
pub fn unwrap_epoch_key(k_archive_root: &KeyMaterial, wrapped: &[u8]) -> CryptoResult<KeyMaterial> {
    let raw = super::key_wrap::unwrap_key(k_archive_root.as_bytes(), wrapped)?;
    Ok(KeyMaterial::from_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> KeyMaterial {
        KeyMaterial::from_bytes([0xAB; KEY_LEN])
    }

    #[test]
    fn derive_is_deterministic() {
        let m = master();
        let a = derive_archive_root(&m).unwrap();
        let b = derive_archive_root(&m).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derived_keys_are_always_32_bytes() {
        let m = master();
        let candidates = [
            derive_archive_root(&m).unwrap(),
            derive_backup_root(&m).unwrap(),
            derive_search_root(&m).unwrap(),
            derive_profile_private_data(&m).unwrap(),
        ];
        for k in &candidates {
            assert_eq!(k.len(), KEY_LEN);
        }
    }

    #[test]
    fn distinct_info_strings_produce_distinct_keys() {
        let m = master();
        let archive = derive_archive_root(&m).unwrap();
        let backup = derive_backup_root(&m).unwrap();
        let search = derive_search_root(&m).unwrap();
        let profile = derive_profile_private_data(&m).unwrap();
        assert_ne!(archive.as_bytes(), backup.as_bytes());
        assert_ne!(archive.as_bytes(), search.as_bytes());
        assert_ne!(archive.as_bytes(), profile.as_bytes());
        assert_ne!(backup.as_bytes(), search.as_bytes());
        assert_ne!(backup.as_bytes(), profile.as_bytes());
        assert_ne!(search.as_bytes(), profile.as_bytes());
    }

    #[test]
    fn distinct_segment_ids_produce_distinct_keys() {
        let m = master();
        let archive_root = derive_archive_root(&m).unwrap();
        let s1 = derive_archive_segment(&archive_root, b"segment-001").unwrap();
        let s2 = derive_archive_segment(&archive_root, b"segment-002").unwrap();
        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn segment_and_manifest_keys_differ() {
        let m = master();
        let archive_root = derive_archive_root(&m).unwrap();
        let seg = derive_archive_segment(&archive_root, b"id-1").unwrap();
        let man = derive_archive_manifest(&archive_root, b"id-1").unwrap();
        assert_ne!(seg.as_bytes(), man.as_bytes());
    }

    #[test]
    fn distinct_masters_produce_distinct_subtrees() {
        let m1 = KeyMaterial::from_bytes([0x01; KEY_LEN]);
        let m2 = KeyMaterial::from_bytes([0x02; KEY_LEN]);
        let a1 = derive_archive_root(&m1).unwrap();
        let a2 = derive_archive_root(&m2).unwrap();
        assert_ne!(a1.as_bytes(), a2.as_bytes());
    }

    #[test]
    fn debug_does_not_leak_key_bytes() {
        let m = master();
        let s = format!("{m:?}");
        // The hex representation of the key (e.g. "abababab...") must
        // not appear in the Debug output.
        assert!(!s.contains("abab"), "Debug leaked key bytes: {s}");
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(KeyMaterial::from_slice(&[0u8; 31]).is_err());
        assert!(KeyMaterial::from_slice(&[0u8; 33]).is_err());
        assert!(KeyMaterial::from_slice(&[0u8; 32]).is_ok());
    }

    // ---------------------------------------------------------------
    // Phase-3: epoch-rotated archive keys
    // ---------------------------------------------------------------

    #[test]
    fn epoch_key_derivation_is_deterministic() {
        let root = derive_archive_root(&master()).unwrap();
        let a = derive_archive_epoch_key(&root, "2026-04").unwrap();
        let b = derive_archive_epoch_key(&root, "2026-04").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_epoch_ids_produce_different_keys() {
        let root = derive_archive_root(&master()).unwrap();
        let april = derive_archive_epoch_key(&root, "2026-04").unwrap();
        let may = derive_archive_epoch_key(&root, "2026-05").unwrap();
        assert_ne!(april.as_bytes(), may.as_bytes());
    }

    #[test]
    fn epoch_key_wrap_unwrap_round_trip() {
        let root = derive_archive_root(&master()).unwrap();
        let epoch = derive_archive_epoch_key(&root, "2026-04").unwrap();
        let wrapped = wrap_epoch_key(&root, &epoch).unwrap();
        let unwrapped = unwrap_epoch_key(&root, &wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), epoch.as_bytes());
    }

    #[test]
    fn segment_key_from_epoch_is_deterministic() {
        let root = derive_archive_root(&master()).unwrap();
        let epoch = derive_archive_epoch_key(&root, "2026-04").unwrap();
        let s1 = derive_archive_segment_key(&epoch, "seg-1").unwrap();
        let s2 = derive_archive_segment_key(&epoch, "seg-1").unwrap();
        assert_eq!(s1.as_bytes(), s2.as_bytes());
        let s_other = derive_archive_segment_key(&epoch, "seg-2").unwrap();
        assert_ne!(s_other.as_bytes(), s1.as_bytes());
    }

    #[test]
    fn cross_epoch_segment_decrypt() {
        // Encrypt under epoch A's segment key, persist the wrapped
        // epoch-A key, unwrap, re-derive the segment key, and
        // confirm decryption succeeds.
        use crate::crypto::aead::xchacha20_poly1305::{open, seal, NONCE_LEN};
        let root = derive_archive_root(&master()).unwrap();
        let epoch_a = derive_archive_epoch_key(&root, "2026-04").unwrap();
        let seg_key = derive_archive_segment_key(&epoch_a, "seg-A").unwrap();
        let plaintext = b"archive segment payload from epoch A";
        let nonce = [0x11u8; NONCE_LEN];
        let ciphertext = seal(seg_key.as_bytes(), &nonce, plaintext, b"aad").unwrap();

        // Persist the wrapped epoch key, then drop the in-memory
        // copy and rebuild it from the wrapped form.
        let wrapped = wrap_epoch_key(&root, &epoch_a).unwrap();
        drop(epoch_a);
        let recovered_epoch = unwrap_epoch_key(&root, &wrapped).unwrap();
        let recovered_seg = derive_archive_segment_key(&recovered_epoch, "seg-A").unwrap();
        let pt = open(recovered_seg.as_bytes(), &nonce, &ciphertext, b"aad").unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn epoch_segment_and_manifest_keys_differ() {
        let root = derive_archive_root(&master()).unwrap();
        let epoch = derive_archive_epoch_key(&root, "2026-04").unwrap();
        let seg = derive_archive_segment_key(&epoch, "id-1").unwrap();
        let man = derive_archive_manifest_key(&epoch, "id-1").unwrap();
        assert_ne!(seg.as_bytes(), man.as_bytes());
    }

    #[test]
    fn derive_bloom_index_shard_is_deterministic() {
        let root = derive_search_root(&master()).unwrap();
        let a = derive_bloom_index_shard(&root, b"shard-1").unwrap();
        let b = derive_bloom_index_shard(&root, b"shard-1").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let other = derive_bloom_index_shard(&root, b"shard-2").unwrap();
        assert_ne!(a.as_bytes(), other.as_bytes());
    }

    #[test]
    fn derive_bloom_index_shard_differs_from_text_and_vector() {
        let root = derive_search_root(&master()).unwrap();
        let bloom = derive_bloom_index_shard(&root, b"shard-1").unwrap();
        let text = derive_text_index_shard(&root, b"shard-1").unwrap();
        let vector = derive_vector_index_shard(&root, b"shard-1").unwrap();
        assert_ne!(bloom.as_bytes(), text.as_bytes());
        assert_ne!(bloom.as_bytes(), vector.as_bytes());
        assert_ne!(text.as_bytes(), vector.as_bytes());
    }
}
