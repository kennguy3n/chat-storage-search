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
}
