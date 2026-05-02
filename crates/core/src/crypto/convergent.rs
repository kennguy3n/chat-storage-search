//! ZK Object Fabric **Pattern C** convergent encryption.
//!
//! This module is the Rust mirror of the Go reference at
//! `kennguy3n/zk-object-fabric/encryption/client_sdk/`. Output is
//! **bit-identical** to the Go SDK; cross-language test vectors live
//! at `crates/core/tests/pattern_c_interop_vectors.rs` and lock that
//! contract.
//!
//! Pipeline (`docs/PROPOSAL.md §3.14`, `§8.4`):
//! 1. Caller computes `BLAKE3(plaintext)` (full object, not per chunk).
//! 2. [`derive_convergent_dek`] → `HKDF-SHA256(secret = content_hash,
//!    salt = tenant_id, info = "zkof-convergent-dek-v1")` → 32 bytes.
//! 3. For each [`DEFAULT_CHUNK_SIZE`]-byte chunk, derive the nonce
//!    via [`derive_convergent_nonce`] →
//!    `HKDF-SHA256(secret = DEK, salt = nil,
//!    info = "zkof-nonce-v1" || u64_BE(chunk_index))` → first 24 bytes.
//! 4. Seal the chunk with XChaCha20-Poly1305 (AAD = empty).
//! 5. Frame: `[24-byte nonce][4-byte BE ciphertext_len][ciphertext+tag]`.
//!
//! The decryptor walks frames sequentially, reading the nonce off
//! the wire — no manifest required.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

use super::key_hierarchy::KeyMaterial;
use super::{CryptoError, CryptoResult};

/// Default plaintext chunk size (16 MiB). Matches
/// `client_sdk.DefaultChunkSize` in `sdk.go`.
pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// HKDF info string for [`derive_convergent_dek`]. Versioned so a
/// future rotation derives a disjoint key space.
pub const CONVERGENT_DEK_INFO: &str = "zkof-convergent-dek-v1";

/// HKDF info prefix for [`derive_convergent_nonce`]. The full info
/// is `CONVERGENT_NONCE_INFO || u64_BE(chunk_index)`.
pub const CONVERGENT_NONCE_INFO: &str = "zkof-nonce-v1";

/// Canonical algorithm string for SDK-sealed objects. Matches
/// `client_sdk.ContentAlgorithm`.
pub const CONTENT_ALGORITHM: &str = "xchacha20-poly1305";

/// Bytes reserved at the head of every ciphertext frame: 24-byte
/// XChaCha20-Poly1305 nonce + 4-byte big-endian ciphertext length.
pub const CHUNK_HEADER_SIZE: usize = 24 + 4;

/// XChaCha20-Poly1305 authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Derive a convergent DEK for the given content hash and tenant.
///
/// `HKDF-SHA256(secret = content_hash, salt = tenant_id_bytes,
/// info = "zkof-convergent-dek-v1")` → 32 bytes.
///
/// Mirrors `client_sdk.DeriveConvergentDEK` (`keygen.go` lines
/// 53–67). Empty `content_hash` or empty `tenant_id` is rejected,
/// matching the Go behaviour.
pub fn derive_convergent_dek(content_hash: &[u8], tenant_id: &str) -> CryptoResult<KeyMaterial> {
    if content_hash.is_empty() {
        return Err(CryptoError::InvalidInput(
            "convergent DEK: contentHash is required",
        ));
    }
    if tenant_id.is_empty() {
        return Err(CryptoError::InvalidInput(
            "convergent DEK: tenantID is required",
        ));
    }
    let salt = tenant_id.as_bytes();
    let info = CONVERGENT_DEK_INFO.as_bytes();
    let hk = Hkdf::<Sha256>::new(Some(salt), content_hash);
    let mut dek = [0u8; 32];
    hk.expand(info, &mut dek)
        .map_err(|_| CryptoError::Kdf("convergent DEK: hkdf expand failed"))?;
    Ok(KeyMaterial::from_bytes(dek))
}

/// Derive the deterministic per-chunk nonce in convergent-nonce mode.
///
/// `HKDF-SHA256(secret = DEK, salt = nil,
/// info = "zkof-nonce-v1" || u64_BE(chunk_index))` → first
/// `nonce_size` bytes.
///
/// Mirrors `client_sdk.deriveConvergentNonce` (`sdk.go` lines
/// 128–144). For XChaCha20-Poly1305, `nonce_size` = 24.
pub fn derive_convergent_nonce(
    dek: &[u8],
    chunk_index: u64,
    nonce_size: usize,
) -> CryptoResult<Vec<u8>> {
    let mut info = Vec::with_capacity(CONVERGENT_NONCE_INFO.len() + 8);
    info.extend_from_slice(CONVERGENT_NONCE_INFO.as_bytes());
    info.extend_from_slice(&chunk_index.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut nonce = vec![0u8; nonce_size];
    hk.expand(&info, &mut nonce)
        .map_err(|_| CryptoError::Kdf("convergent nonce: hkdf expand failed"))?;
    Ok(nonce)
}

/// Resolve `chunk_size` the same way the Go SDK does (zero → default).
fn effective_chunk_size(chunk_size: usize) -> usize {
    if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    }
}

/// Seal `plaintext` with Pattern C convergent encryption and return
/// the framed ciphertext stream.
///
/// `dek` must be 32 bytes (typically the output of
/// [`derive_convergent_dek`]). `chunk_size` of `0` selects
/// [`DEFAULT_CHUNK_SIZE`].
///
/// Empty plaintext produces zero frames (and an empty `Vec`),
/// matching the Go SDK: `EncryptObject` returns an EOF reader for
/// empty input.
pub fn encrypt_object_pattern_c(
    plaintext: &[u8],
    dek: &[u8],
    chunk_size: usize,
) -> CryptoResult<Vec<u8>> {
    if dek.len() != 32 {
        return Err(CryptoError::InvalidInput("Pattern C: DEK must be 32 bytes"));
    }
    let chunk_size = effective_chunk_size(chunk_size);
    let key: &chacha20poly1305::Key = dek.into();
    let cipher = XChaCha20Poly1305::new(key);

    let mut out = Vec::new();
    let mut chunk_index: u64 = 0;
    let mut offset = 0usize;
    while offset < plaintext.len() {
        let end = (offset + chunk_size).min(plaintext.len());
        let chunk = &plaintext[offset..end];

        let nonce_bytes = derive_convergent_nonce(dek, chunk_index, 24)?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: chunk,
                    aad: &[],
                },
            )
            .map_err(|_| CryptoError::Aead("Pattern C: seal failed"))?;

        // Frame header: nonce (24) || ciphertext_len (u32 BE).
        out.extend_from_slice(&nonce_bytes);
        let ct_len_u32: u32 = sealed.len().try_into().map_err(|_| {
            CryptoError::Frame(format!("ciphertext length {} exceeds u32", sealed.len()))
        })?;
        out.extend_from_slice(&ct_len_u32.to_be_bytes());
        out.extend_from_slice(&sealed);

        offset = end;
        chunk_index += 1;
    }
    Ok(out)
}

/// Decrypt a Pattern C framed ciphertext stream produced by
/// [`encrypt_object_pattern_c`] (or the Go SDK).
///
/// `chunk_size` matches the encrypter's chunk size and is used only
/// to bound the per-frame ciphertext length sanity check (the wire
/// format is self-describing — the nonce is in the frame header).
pub fn decrypt_object_pattern_c(
    ciphertext: &[u8],
    dek: &[u8],
    chunk_size: usize,
) -> CryptoResult<Vec<u8>> {
    if dek.len() != 32 {
        return Err(CryptoError::InvalidInput("Pattern C: DEK must be 32 bytes"));
    }
    let chunk_size = effective_chunk_size(chunk_size);
    let key: &chacha20poly1305::Key = dek.into();
    let cipher = XChaCha20Poly1305::new(key);

    let max_ct: u32 = (chunk_size + TAG_LEN)
        .try_into()
        .map_err(|_| CryptoError::Frame(format!("chunk_size {chunk_size} exceeds u32 range")))?;
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < ciphertext.len() {
        if ciphertext.len() - cursor < CHUNK_HEADER_SIZE {
            return Err(CryptoError::Frame(format!(
                "truncated frame header at offset {cursor}"
            )));
        }
        let nonce = &ciphertext[cursor..cursor + 24];
        let len_bytes: [u8; 4] = ciphertext[cursor + 24..cursor + 28].try_into().unwrap();
        let ct_len = u32::from_be_bytes(len_bytes);
        if ct_len == 0 || ct_len > max_ct {
            return Err(CryptoError::Frame(format!(
                "frame length {ct_len} out of bounds (max {max_ct})"
            )));
        }
        let ct_len_usize = ct_len as usize;
        let body_start = cursor + CHUNK_HEADER_SIZE;
        let body_end = body_start + ct_len_usize;
        if body_end > ciphertext.len() {
            return Err(CryptoError::Frame(format!(
                "frame body truncated: need {body_end}, have {}",
                ciphertext.len()
            )));
        }
        let body = &ciphertext[body_start..body_end];
        let pt = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: &[],
                },
            )
            .map_err(|_| CryptoError::Aead("Pattern C: open failed"))?;
        out.extend_from_slice(&pt);
        cursor = body_end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dek_is_deterministic() {
        let h = b"blake3:cafebabe";
        let a = derive_convergent_dek(h, "tnt_abc").unwrap();
        let b = derive_convergent_dek(h, "tnt_abc").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn dek_length_is_32() {
        let dek = derive_convergent_dek(b"\x01\x02", "tnt").unwrap();
        assert_eq!(dek.len(), 32);
    }

    #[test]
    fn distinct_tenants_produce_distinct_deks() {
        let h = b"blake3:deadbeef";
        let a = derive_convergent_dek(h, "tnt_a").unwrap();
        let b = derive_convergent_dek(h, "tnt_b").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn distinct_hashes_produce_distinct_deks() {
        let a = derive_convergent_dek(b"hash-a", "tnt").unwrap();
        let b = derive_convergent_dek(b"hash-b", "tnt").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn empty_inputs_rejected() {
        assert!(derive_convergent_dek(b"", "tnt").is_err());
        assert!(derive_convergent_dek(b"h", "").is_err());
    }

    #[test]
    fn convergent_nonce_is_deterministic() {
        let dek = derive_convergent_dek(b"h", "tnt").unwrap();
        let n1 = derive_convergent_nonce(dek.as_bytes(), 0, 24).unwrap();
        let n2 = derive_convergent_nonce(dek.as_bytes(), 0, 24).unwrap();
        assert_eq!(n1, n2);
    }

    #[test]
    fn distinct_chunk_indices_produce_distinct_nonces() {
        let dek = derive_convergent_dek(b"h", "tnt").unwrap();
        let n0 = derive_convergent_nonce(dek.as_bytes(), 0, 24).unwrap();
        let n1 = derive_convergent_nonce(dek.as_bytes(), 1, 24).unwrap();
        assert_ne!(n0, n1);
    }

    #[test]
    fn encrypt_decrypt_round_trip_single_chunk() {
        let plaintext = b"hello pattern c";
        let content_hash = crate::crypto::content_hash::content_hash(plaintext);
        let dek = derive_convergent_dek(&content_hash, "tnt-rt").unwrap();
        let ct = encrypt_object_pattern_c(plaintext, dek.as_bytes(), 64).unwrap();
        assert_ne!(&ct[..], &plaintext[..]);
        let pt = decrypt_object_pattern_c(&ct, dek.as_bytes(), 64).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn encrypt_decrypt_round_trip_multi_chunk() {
        let plaintext = vec![0xAB; 128];
        let content_hash = crate::crypto::content_hash::content_hash(&plaintext);
        let dek = derive_convergent_dek(&content_hash, "multi-chunk-tenant").unwrap();
        let ct = encrypt_object_pattern_c(&plaintext, dek.as_bytes(), 64).unwrap();
        // Two 64-byte chunks → two frames.
        let frame_len = CHUNK_HEADER_SIZE + 64 + TAG_LEN;
        assert_eq!(ct.len(), 2 * frame_len);
        let pt = decrypt_object_pattern_c(&ct, dek.as_bytes(), 64).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_decrypt_round_trip_odd_tail() {
        let plaintext = vec![0xCD; 100];
        let dek = KeyMaterial::from_bytes([0x42; 32]);
        let ct = encrypt_object_pattern_c(&plaintext, dek.as_bytes(), 64).unwrap();
        // 64 + 36 = 100 bytes of plaintext over two frames.
        let pt = decrypt_object_pattern_c(&ct, dek.as_bytes(), 64).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn empty_plaintext_yields_zero_frames() {
        let dek = KeyMaterial::from_bytes([0x42; 32]);
        let ct = encrypt_object_pattern_c(b"", dek.as_bytes(), 64).unwrap();
        assert!(ct.is_empty());
        let pt = decrypt_object_pattern_c(&ct, dek.as_bytes(), 64).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn convergence_same_inputs_produce_identical_ciphertext() {
        let plaintext = b"abcdabcdabcdabcdabcdabcdabcd";
        let content_hash = crate::crypto::content_hash::content_hash(plaintext);
        let dek1 = derive_convergent_dek(&content_hash, "tnt").unwrap();
        let dek2 = derive_convergent_dek(&content_hash, "tnt").unwrap();
        let ct1 = encrypt_object_pattern_c(plaintext, dek1.as_bytes(), 16).unwrap();
        let ct2 = encrypt_object_pattern_c(plaintext, dek2.as_bytes(), 16).unwrap();
        assert_eq!(
            ct1, ct2,
            "convergent encryption must produce identical bytes"
        );
    }

    #[test]
    fn wrong_dek_rejected() {
        let plaintext = b"hello";
        let dek = KeyMaterial::from_bytes([0x11; 32]);
        let wrong = KeyMaterial::from_bytes([0x22; 32]);
        let ct = encrypt_object_pattern_c(plaintext, dek.as_bytes(), 64).unwrap();
        assert!(decrypt_object_pattern_c(&ct, wrong.as_bytes(), 64).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let plaintext = b"hello";
        let dek = KeyMaterial::from_bytes([0x33; 32]);
        let mut ct = encrypt_object_pattern_c(plaintext, dek.as_bytes(), 64).unwrap();
        // Flip a byte inside the first ciphertext body (after the
        // 28-byte frame header).
        ct[CHUNK_HEADER_SIZE] ^= 0x01;
        assert!(decrypt_object_pattern_c(&ct, dek.as_bytes(), 64).is_err());
    }

    #[test]
    fn truncated_frame_rejected() {
        let plaintext = b"hello world";
        let dek = KeyMaterial::from_bytes([0x44; 32]);
        let ct = encrypt_object_pattern_c(plaintext, dek.as_bytes(), 64).unwrap();
        let truncated = &ct[..ct.len() - 5];
        assert!(decrypt_object_pattern_c(truncated, dek.as_bytes(), 64).is_err());
    }

    #[test]
    fn nonce_for_chunk_zero_matches_first_frame() {
        // Mirrors TestEncryptObject_ConvergentNonce_MatchesDeriveHelper
        // in the Go SDK.
        let dek = derive_convergent_dek(b"h", "tnt").unwrap();
        let want = derive_convergent_nonce(dek.as_bytes(), 0, 24).unwrap();
        let ct = encrypt_object_pattern_c(b"x", dek.as_bytes(), 16).unwrap();
        let got = &ct[..24];
        assert_eq!(got, want.as_slice());
    }
}
