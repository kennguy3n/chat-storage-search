//! AES-256-KW key wrapping (NIST 800-38F / RFC 3394).
//!
//! Phase 0 implements the construction the higher layers depend on:
//! a `K_asset` (32 bytes) wrapped under one of `K_local_db`,
//! `K_archive_root`, or `K_backup_root` (also 32 bytes) so that the
//! ciphertext alone never reveals the asset key. The wrapped output
//! is exactly **40 bytes** — the input key plus an 8-byte integrity
//! check value.
//!
//! Pipeline:
//! 1. The wrapping root comes from
//!    [`crate::crypto::key_hierarchy::KeyMaterial`] (`K_local_db` for
//!    local-only wraps; `K_archive_root` / `K_backup_root` for the
//!    archive and backup paths described in `docs/PROPOSAL.md §2.1`
//!    and `§5` / `§6`).
//! 2. AES-256-KW seals the 32-byte asset key. Tampering with any
//!    byte of the wrapped output, or unwrapping with the wrong
//!    wrapping key, fails with [`CryptoError::Aead`].
//!
//! Phase 1 will layer the platform-specific wraps for `K_local_db`
//! itself (Keychain on iOS / macOS, Keystore on Android, DPAPI on
//! Windows) on top of the same `wrap_key` / `unwrap_key` primitives.

use aes_kw::Kek;

use super::key_hierarchy::{KeyMaterial, KEY_LEN};
use super::{CryptoError, CryptoResult};

/// AES-256-KW wrap of a 32-byte key produces 40 bytes (32 + 8-byte
/// integrity check value).
pub const WRAPPED_KEY_LEN: usize = KEY_LEN + 8;

/// Wrap `key_to_wrap` under `wrapping_key` using AES-256-KW
/// (RFC 3394). Output is exactly [`WRAPPED_KEY_LEN`] bytes.
pub fn wrap_key(
    wrapping_key: &[u8; KEY_LEN],
    key_to_wrap: &[u8; KEY_LEN],
) -> CryptoResult<Vec<u8>> {
    let kek = Kek::from(*wrapping_key);
    let mut out = vec![0u8; WRAPPED_KEY_LEN];
    kek.wrap(key_to_wrap, &mut out)
        .map_err(|_| CryptoError::Aead("aes-kw wrap failed"))?;
    Ok(out)
}

/// Unwrap a 32-byte key from `wrapped_key` using AES-256-KW. The
/// wrapped input must be exactly [`WRAPPED_KEY_LEN`] bytes; the
/// integrity check value mismatching (wrong wrapping key, tampered
/// ciphertext) produces [`CryptoError::Aead`].
pub fn unwrap_key(wrapping_key: &[u8; KEY_LEN], wrapped_key: &[u8]) -> CryptoResult<[u8; KEY_LEN]> {
    if wrapped_key.len() != WRAPPED_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "aes-kw unwrap: wrapped key must be 40 bytes",
        ));
    }
    let kek = Kek::from(*wrapping_key);
    let mut out = [0u8; KEY_LEN];
    kek.unwrap(wrapped_key, &mut out)
        .map_err(|_| CryptoError::Aead("aes-kw unwrap failed"))?;
    Ok(out)
}

/// Wrap `k_asset` under a hierarchy root (`K_local_db`,
/// `K_archive_root`, or `K_backup_root`).
///
/// Convenience over [`wrap_key`] that takes the wrapping root as the
/// hierarchy's [`KeyMaterial`] type so callers don't have to
/// re-extract the bytes.
pub fn wrap_k_asset(k_asset: &[u8; KEY_LEN], wrapping_root: &KeyMaterial) -> CryptoResult<Vec<u8>> {
    wrap_key(wrapping_root.as_bytes(), k_asset)
}

/// Unwrap a `K_asset` produced by [`wrap_k_asset`] under the same
/// hierarchy root.
pub fn unwrap_k_asset(wrapped: &[u8], wrapping_root: &KeyMaterial) -> CryptoResult<[u8; KEY_LEN]> {
    unwrap_key(wrapping_root.as_bytes(), wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_hierarchy::{derive_archive_root, derive_backup_root, KeyMaterial};

    fn fresh_kek() -> [u8; KEY_LEN] {
        // Distinct, deterministic test KEK. Real usage derives the
        // KEK via HKDF — see `key_hierarchy`.
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(31);
        }
        k
    }

    fn fresh_k_asset() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8) ^ 0xA5;
        }
        k
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let kek = fresh_kek();
        let k_asset = fresh_k_asset();
        let wrapped = wrap_key(&kek, &k_asset).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
        let unwrapped = unwrap_key(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, k_asset);
    }

    #[test]
    fn wrong_wrapping_key_is_rejected() {
        let kek = fresh_kek();
        let k_asset = fresh_k_asset();
        let wrapped = wrap_key(&kek, &k_asset).unwrap();

        let mut wrong_kek = kek;
        wrong_kek[0] ^= 0x01;
        let res = unwrap_key(&wrong_kek, &wrapped);
        assert!(res.is_err(), "wrong-KEK unwrap accepted: {res:?}");
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let kek = fresh_kek();
        let k_asset = fresh_k_asset();
        let mut wrapped = wrap_key(&kek, &k_asset).unwrap();
        // Flip a bit in the integrity-check region (last 8 bytes).
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        let res = unwrap_key(&kek, &wrapped);
        assert!(res.is_err(), "tampered wrap accepted: {res:?}");
    }

    #[test]
    fn tampered_wrapped_key_payload_is_rejected() {
        let kek = fresh_kek();
        let k_asset = fresh_k_asset();
        let mut wrapped = wrap_key(&kek, &k_asset).unwrap();
        // Flip a bit in the wrapped key body.
        wrapped[8] ^= 0x80;
        let res = unwrap_key(&kek, &wrapped);
        assert!(res.is_err(), "tampered wrap payload accepted: {res:?}");
    }

    #[test]
    fn wrong_length_wrapped_input_is_rejected() {
        let kek = fresh_kek();
        let too_short = vec![0u8; WRAPPED_KEY_LEN - 1];
        assert!(unwrap_key(&kek, &too_short).is_err());
        let too_long = vec![0u8; WRAPPED_KEY_LEN + 1];
        assert!(unwrap_key(&kek, &too_long).is_err());
    }

    #[test]
    fn wrap_k_asset_round_trip_under_archive_root() {
        let master = KeyMaterial::from_bytes([0xAB; KEY_LEN]);
        let archive_root = derive_archive_root(&master).unwrap();
        let k_asset = fresh_k_asset();

        let wrapped = wrap_k_asset(&k_asset, &archive_root).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
        let unwrapped = unwrap_k_asset(&wrapped, &archive_root).unwrap();
        assert_eq!(unwrapped, k_asset);
    }

    #[test]
    fn archive_root_and_backup_root_produce_distinct_wraps() {
        let master = KeyMaterial::from_bytes([0xCD; KEY_LEN]);
        let archive_root = derive_archive_root(&master).unwrap();
        let backup_root = derive_backup_root(&master).unwrap();
        let k_asset = fresh_k_asset();

        let wrapped_archive = wrap_k_asset(&k_asset, &archive_root).unwrap();
        let wrapped_backup = wrap_k_asset(&k_asset, &backup_root).unwrap();
        assert_ne!(wrapped_archive, wrapped_backup);

        // Each wrap unwraps under its own root and only that root.
        let unwrapped_archive = unwrap_k_asset(&wrapped_archive, &archive_root).unwrap();
        let unwrapped_backup = unwrap_k_asset(&wrapped_backup, &backup_root).unwrap();
        assert_eq!(unwrapped_archive, k_asset);
        assert_eq!(unwrapped_backup, k_asset);

        assert!(unwrap_k_asset(&wrapped_archive, &backup_root).is_err());
        assert!(unwrap_k_asset(&wrapped_backup, &archive_root).is_err());
    }

    #[test]
    fn wrap_is_deterministic_for_the_same_kek_and_input() {
        // RFC 3394 with the standard IV is deterministic — there is
        // no nonce. Two wraps of the same key under the same KEK
        // produce bit-identical output.
        let kek = fresh_kek();
        let k_asset = fresh_k_asset();
        let a = wrap_key(&kek, &k_asset).unwrap();
        let b = wrap_key(&kek, &k_asset).unwrap();
        assert_eq!(a, b);
    }
}
