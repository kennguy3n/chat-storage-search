//! AEAD constructions used by KChat.
//!
//! * [`xchacha20_poly1305`] — default AEAD for chunk-level seal/open.
//!   24-byte nonce, 16-byte Poly1305 tag.
//! * [`aes_256_gcm`] — platform-accelerated alternative used where the
//!   hardware path is materially faster (e.g. AES-NI on Windows /
//!   x86_64). 12-byte nonce, 16-byte GCM tag.
//!
//! [`build_kchat_chunk_aad`] constructs the per-chunk Additional
//! Authenticated Data described in `docs/PROPOSAL.md §8.3`. Pattern
//! C (ZK Object Fabric) does *not* use this AAD — see
//! [`crate::crypto::convergent`] for that codepath.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use super::{CryptoError, CryptoResult};

/// Magic prefix that locks the KChat per-chunk AAD scheme to
/// version 1. Bumping this prefix is a wire-format break.
pub const KCHAT_BLOB_CHUNK_AAD_MAGIC: &[u8] = b"KCHAT_BLOB_CHUNK_V1";

/// Object class encoded in [`build_kchat_chunk_aad`]. Numeric values
/// are the canonical varint payloads from `docs/PROPOSAL.md §8.3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BlobClass {
    Media = 1,
    ArchiveSegment = 2,
    SearchIndexShard = 3,
    BackupSegment = 4,
    Manifest = 5,
}

impl BlobClass {
    /// Numeric tag used in the AAD encoding.
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// XChaCha20-Poly1305 AEAD (default chunk seal). 32-byte key,
/// 24-byte nonce, 16-byte Poly1305 tag.
pub mod xchacha20_poly1305 {
    use super::*;

    /// Nonce length (24 bytes).
    pub const NONCE_LEN: usize = 24;
    /// Authentication tag length (16 bytes).
    pub const TAG_LEN: usize = 16;
    /// Key length (32 bytes).
    pub const KEY_LEN: usize = 32;

    /// Seal `plaintext` and return `ciphertext || tag`.
    pub fn seal(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new(key.into());
        cipher
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Aead("xchacha20-poly1305 seal failed"))
    }

    /// Open `ciphertext || tag` with `aad` and return the plaintext.
    pub fn open(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new(key.into());
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Aead("xchacha20-poly1305 open failed"))
    }
}

/// AES-256-GCM AEAD (platform-accelerated alternative). 32-byte key,
/// 12-byte nonce, 16-byte GCM tag.
pub mod aes_256_gcm {
    use super::*;
    use aes_gcm::Nonce;

    /// Nonce length (12 bytes).
    pub const NONCE_LEN: usize = 12;
    /// Authentication tag length (16 bytes).
    pub const TAG_LEN: usize = 16;
    /// Key length (32 bytes).
    pub const KEY_LEN: usize = 32;

    /// Seal `plaintext` and return `ciphertext || tag`.
    pub fn seal(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Aead("aes-256-gcm seal failed"))
    }

    /// Open `ciphertext || tag` with `aad` and return the plaintext.
    pub fn open(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Aead("aes-256-gcm open failed"))
    }
}

/// Encode an unsigned varint (LEB128) into `out`.
fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            return;
        }
    }
}

/// Build the KChat per-chunk AAD used for media, archive segments,
/// backup segments, search index shards, and manifests on KChat's
/// own backend (see `docs/PROPOSAL.md §8.3`).
///
/// AAD = `"KCHAT_BLOB_CHUNK_V1" || blob_id(16)
///        || blob_class(varint) || chunk_no(u32 BE)
///        || chunk_count(u32 BE) || merkle_root(32)`
///
/// This AAD is *not* used by ZK Object Fabric Pattern C uploads,
/// which use empty AAD; see [`crate::crypto::convergent`].
pub fn build_kchat_chunk_aad(
    blob_id: &[u8; 16],
    blob_class: BlobClass,
    chunk_no: u32,
    chunk_count: u32,
    ciphertext_merkle_root: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KCHAT_BLOB_CHUNK_AAD_MAGIC.len() + 16 + 5 + 4 + 4 + 32);
    aad.extend_from_slice(KCHAT_BLOB_CHUNK_AAD_MAGIC);
    aad.extend_from_slice(blob_id);
    write_varint(blob_class.as_u32() as u64, &mut aad);
    aad.extend_from_slice(&chunk_no.to_be_bytes());
    aad.extend_from_slice(&chunk_count.to_be_bytes());
    aad.extend_from_slice(ciphertext_merkle_root);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key32() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn xchacha20_round_trip() {
        let key = key32();
        let nonce = [7u8; 24];
        let aad = b"kchat-test-aad";
        let pt = b"the quick brown fox";
        let ct = xchacha20_poly1305::seal(&key, &nonce, pt, aad).unwrap();
        assert_ne!(ct.as_slice(), pt.as_slice());
        let got = xchacha20_poly1305::open(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(got.as_slice(), pt.as_slice());
    }

    #[test]
    fn xchacha20_wrong_key_rejected() {
        let key = key32();
        let mut wrong = key;
        wrong[0] ^= 0xFF;
        let nonce = [1u8; 24];
        let ct = xchacha20_poly1305::seal(&key, &nonce, b"hi", b"").unwrap();
        assert!(xchacha20_poly1305::open(&wrong, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn xchacha20_tampered_ciphertext_rejected() {
        let key = key32();
        let nonce = [2u8; 24];
        let mut ct = xchacha20_poly1305::seal(&key, &nonce, b"hi", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(xchacha20_poly1305::open(&key, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn xchacha20_aad_mismatch_rejected() {
        let key = key32();
        let nonce = [3u8; 24];
        let ct = xchacha20_poly1305::seal(&key, &nonce, b"hi", b"aad-A").unwrap();
        assert!(xchacha20_poly1305::open(&key, &nonce, &ct, b"aad-B").is_err());
    }

    #[test]
    fn aes_gcm_round_trip() {
        let key = key32();
        let nonce = [5u8; 12];
        let pt = b"hello aes-gcm";
        let ct = aes_256_gcm::seal(&key, &nonce, pt, b"aad").unwrap();
        let got = aes_256_gcm::open(&key, &nonce, &ct, b"aad").unwrap();
        assert_eq!(got.as_slice(), pt.as_slice());
    }

    #[test]
    fn aes_gcm_wrong_key_rejected() {
        let key = key32();
        let mut wrong = key;
        wrong[0] ^= 0xFF;
        let nonce = [6u8; 12];
        let ct = aes_256_gcm::seal(&key, &nonce, b"hi", b"").unwrap();
        assert!(aes_256_gcm::open(&wrong, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn aes_gcm_tampered_ciphertext_rejected() {
        let key = key32();
        let nonce = [7u8; 12];
        let mut ct = aes_256_gcm::seal(&key, &nonce, b"hi", b"").unwrap();
        ct[1] ^= 0x10;
        assert!(aes_256_gcm::open(&key, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn aes_gcm_aad_mismatch_rejected() {
        let key = key32();
        let nonce = [8u8; 12];
        let ct = aes_256_gcm::seal(&key, &nonce, b"hi", b"aad-A").unwrap();
        assert!(aes_256_gcm::open(&key, &nonce, &ct, b"aad-B").is_err());
    }

    #[test]
    fn kchat_aad_layout_is_stable() {
        let blob_id = [0xAA; 16];
        let merkle = [0xBB; 32];
        let aad = build_kchat_chunk_aad(&blob_id, BlobClass::Media, 7, 42, &merkle);
        // Magic
        assert!(aad.starts_with(KCHAT_BLOB_CHUNK_AAD_MAGIC));
        let mut cursor = KCHAT_BLOB_CHUNK_AAD_MAGIC.len();
        // blob_id
        assert_eq!(&aad[cursor..cursor + 16], &blob_id[..]);
        cursor += 16;
        // blob_class varint = 1 (media) — single byte 0x01
        assert_eq!(aad[cursor], 0x01);
        cursor += 1;
        // chunk_no = 7 (u32 BE)
        assert_eq!(&aad[cursor..cursor + 4], &7u32.to_be_bytes());
        cursor += 4;
        // chunk_count = 42 (u32 BE)
        assert_eq!(&aad[cursor..cursor + 4], &42u32.to_be_bytes());
        cursor += 4;
        // merkle root (32 bytes)
        assert_eq!(&aad[cursor..cursor + 32], &merkle[..]);
        cursor += 32;
        assert_eq!(
            cursor,
            aad.len(),
            "AAD length must be exactly the sum of fields"
        );
    }

    #[test]
    fn kchat_aad_distinct_chunks_produce_distinct_aad() {
        let blob_id = [0u8; 16];
        let merkle = [0u8; 32];
        let a = build_kchat_chunk_aad(&blob_id, BlobClass::ArchiveSegment, 0, 10, &merkle);
        let b = build_kchat_chunk_aad(&blob_id, BlobClass::ArchiveSegment, 1, 10, &merkle);
        assert_ne!(a, b);
    }

    #[test]
    fn kchat_aad_distinct_blob_classes_produce_distinct_aad() {
        let blob_id = [0u8; 16];
        let merkle = [0u8; 32];
        let media = build_kchat_chunk_aad(&blob_id, BlobClass::Media, 0, 1, &merkle);
        let backup = build_kchat_chunk_aad(&blob_id, BlobClass::BackupSegment, 0, 1, &merkle);
        assert_ne!(media, backup);
    }
}
