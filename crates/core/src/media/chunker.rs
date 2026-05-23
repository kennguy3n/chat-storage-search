//! Media chunker: split, AEAD-seal, and verify media plaintext for the
//! KChat-internal blob path.
//!
//! `docs/DESIGN.md §8.1` (chunk sizes), `§8.2` (size-class padding),
//! and `§8.3` (per-chunk AAD layout) are the authoritative sources for
//! the contracts implemented here. This module does *not* cover the ZK
//! Object Fabric Pattern C path — that lives in
//! [`crate::crypto::convergent`] and uses an empty AAD with a
//! HKDF-derived nonce, not the `KCHAT_BLOB_CHUNK_V1` AAD.
//!
//! Pipeline (from [`chunk_and_encrypt`]):
//!
//! 1. Optionally [`pad_to_size_class`] the plaintext (`§8.2`).
//! 2. Compute the BLAKE3 root over the (padded) plaintext via
//!    [`crate::crypto::content_hash::content_hash`]. BLAKE3 itself is
//!    a Merkle construction so the one-shot digest *is* the Merkle
//!    root over the leaves.
//! 3. Split the (padded) plaintext into `chunk_size`-byte pieces; the
//!    last chunk may be smaller. The empty input still produces a
//!    single zero-length chunk so the AAD chain (`chunk_count >= 1`)
//!    stays well-defined.
//! 4. For every chunk: build the per-chunk AAD with
//!    [`crate::crypto::aead::build_kchat_chunk_aad`] (`§8.3`) and seal
//!    with XChaCha20-Poly1305 under `K_asset` and a deterministic
//!    24-byte nonce derived from the chunk index. Because `K_asset`
//!    is fresh-random per asset (see [`crate::media::processor`]),
//!    deterministic per-chunk nonces never collide on the same key.
//! 5. SHA-256 the **ciphertext** of every chunk so the rehydration
//!    path can fast-fail on tampering before attempting an AEAD open.
//!
//! [`verify_and_decrypt`] is the rehydration inverse: it checks the
//! per-chunk SHA-256 fast-fail, AEAD-opens every chunk under the same
//! AAD, concatenates the plaintext, and re-verifies the BLAKE3 root.

use sha2::{Digest, Sha256};

use crate::crypto::aead::{build_kchat_chunk_aad, xchacha20_poly1305, BlobClass};
use crate::crypto::content_hash;
use crate::Error;

/// Default media chunk size: 16 MiB. Matches Pattern C
/// (`client_sdk.DefaultChunkSize` from
/// `kennguy3n/zk-object-fabric/encryption/client_sdk/sdk.go`) so the
/// KChat-internal and ZK Object Fabric paths share a chunk granularity
/// even though their AAD schemes differ. See `docs/DESIGN.md §8.1`
/// and `§8.4`.
pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// 8-byte big-endian length prefix written by [`pad_to_size_class`] so
/// [`unpad_from_size_class`] can recover the original plaintext slice.
const SIZE_CLASS_PREFIX_LEN: usize = 8;

/// Size classes (in bytes) used by [`pad_to_size_class`].
///
/// `docs/DESIGN.md §8.2` enumerates 4 KB through 256 MB; we extend the
/// ladder by 1 KiB on the low end (small text-like attachments / voice
/// notes) and 1 GiB on the high end (long-form video) so the ladder
/// covers the full media-blob size range without introducing a
/// degenerate "no padding" case for sub-4 KiB inputs. Any input that
/// exceeds 1 GiB rounds up to the next power of two — see
/// [`pad_to_size_class`].
const SIZE_CLASSES: &[usize] = &[
    1024,               // 1 KiB
    4 * 1024,           // 4 KiB
    16 * 1024,          // 16 KiB
    64 * 1024,          // 64 KiB
    256 * 1024,         // 256 KiB
    1024 * 1024,        // 1 MiB
    4 * 1024 * 1024,    // 4 MiB
    16 * 1024 * 1024,   // 16 MiB
    64 * 1024 * 1024,   // 64 MiB
    256 * 1024 * 1024,  // 256 MiB
    1024 * 1024 * 1024, // 1 GiB
];

/// One AEAD-sealed chunk plus its over-the-ciphertext SHA-256.
///
/// The Poly1305 tag protects against bit-flips that change the
/// authenticated payload, and the SHA-256 protects against a flipped
/// chunk being submitted to AEAD-open at all. The transport layer
/// echoes the same SHA-256 in [`crate::transport::ChunkReceipt`] so
/// the upload pipeline can detect mid-stream corruption before
/// committing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedChunk {
    /// AEAD ciphertext (`ciphertext || Poly1305 tag`) for this chunk.
    pub ciphertext: Vec<u8>,
    /// SHA-256 of [`Self::ciphertext`].
    pub chunk_sha256: [u8; 32],
}

/// Output of [`chunk_and_encrypt`]: every sealed chunk plus the
/// whole-object BLAKE3 root used in the per-chunk AAD.
///
/// `merkle_root` is computed over the plaintext (post-padding when
/// `pad = true`) so the rehydration path can verify it against the
/// concatenated plaintext that comes out of [`verify_and_decrypt`]
/// without re-running padding logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkedMedia {
    /// Sealed chunks in order; chunk 0 first.
    pub sealed_chunks: Vec<SealedChunk>,
    /// 32-byte BLAKE3 root over the (padded) plaintext.
    pub merkle_root: [u8; 32],
    /// Total number of chunks (`u32` — matches the AAD wire format).
    pub chunk_count: u32,
}

/// Round `plaintext.len + 8` up to the next size class from the
/// table in `docs/DESIGN.md §8.2` and return the padded buffer.
///
/// Layout: `[8-byte BE original-length][plaintext][zero padding]`.
/// The 8-byte prefix is what [`unpad_from_size_class`] uses to
/// recover the original slice; it is *inside* the AEAD seal because
/// the chunker calls this *before* [`chunk_and_encrypt`].
///
/// Inputs whose padded size exceeds the largest tabulated class
/// (1 GiB + 8 B) round up to the next power-of-two-aligned class so
/// callers never see a panic for over-sized inputs. In practice the
/// 16 MiB default chunk size means a single padded media blob caps
/// out at the 256 MiB / 1 GiB classes.
pub fn pad_to_size_class(plaintext: &[u8]) -> Vec<u8> {
    let target = next_size_class(plaintext.len() + SIZE_CLASS_PREFIX_LEN);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(target, 0);
    out
}

/// Strip the size-class padding written by [`pad_to_size_class`] and
/// return the original plaintext slice. Errors when the recorded
/// length exceeds the padded buffer or the prefix is missing.
pub fn unpad_from_size_class(padded: &[u8]) -> Result<&[u8], Error> {
    if padded.len() < SIZE_CLASS_PREFIX_LEN {
        return Err(Error::Storage(
            "unpad_from_size_class: padded buffer shorter than 8-byte length prefix".into(),
        ));
    }
    let mut len_bytes = [0u8; SIZE_CLASS_PREFIX_LEN];
    len_bytes.copy_from_slice(&padded[..SIZE_CLASS_PREFIX_LEN]);
    let original_len = u64::from_be_bytes(len_bytes) as usize;
    let payload = &padded[SIZE_CLASS_PREFIX_LEN..];
    if original_len > payload.len() {
        return Err(Error::Storage(
            "unpad_from_size_class: recorded length exceeds padded payload".into(),
        ));
    }
    Ok(&payload[..original_len])
}

fn next_size_class(target: usize) -> usize {
    for &class in SIZE_CLASSES {
        if class >= target {
            return class;
        }
    }
    // Fallback for inputs larger than 1 GiB: round up to the next
    // power of two so we still produce a deterministic class without
    // panicking. This is rarely hit — a single media blob should not
    // exceed 1 GiB in practice — but the chunker contract is
    // size-agnostic.
    target.next_power_of_two()
}

/// Build the deterministic 24-byte XChaCha20-Poly1305 nonce for a
/// given chunk index. `K_asset` is fresh-random per asset (see
/// [`crate::media::processor::process_media`]) so a deterministic
/// per-chunk nonce never collides on the same key.
///
/// Layout: `[16 zero bytes][8-byte BE chunk_idx as u64]`. The leading
/// zeros leave the nonce visually distinct from a Pattern C
/// HKDF-derived nonce so wire-level dumps can be told apart.
fn chunk_nonce(chunk_idx: u32) -> [u8; xchacha20_poly1305::NONCE_LEN] {
    let mut nonce = [0u8; xchacha20_poly1305::NONCE_LEN];
    let idx_bytes = (chunk_idx as u64).to_be_bytes();
    nonce[xchacha20_poly1305::NONCE_LEN - idx_bytes.len()..].copy_from_slice(&idx_bytes);
    nonce
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Chunk `plaintext` into `chunk_size`-byte pieces (last may be
/// shorter), AEAD-seal every chunk under `k_asset` with the per-chunk
/// AAD from `docs/DESIGN.md §8.3`, and return the sealed chunks plus
/// the BLAKE3 Merkle root over the (padded) plaintext.
///
/// `blob_id` is the 16-byte identifier mixed into the AAD; the caller
/// (typically [`crate::media::processor::process_media`]) generates a
/// UUID v7 and forwards its bytes here.
///
/// `pad = true` runs [`pad_to_size_class`] on the plaintext before
/// chunking so the on-wire blob length only reveals the size class.
/// `pad = false` chunks `plaintext` verbatim.
pub fn chunk_and_encrypt(
    plaintext: &[u8],
    k_asset: &[u8; 32],
    blob_id: &[u8; 16],
    blob_class: BlobClass,
    chunk_size: usize,
    pad: bool,
) -> Result<ChunkedMedia, Error> {
    if chunk_size == 0 {
        return Err(Error::Storage(
            "chunk_and_encrypt: chunk_size must be non-zero".into(),
        ));
    }

    let owned_padded;
    let padded: &[u8] = if pad {
        owned_padded = pad_to_size_class(plaintext);
        &owned_padded
    } else {
        plaintext
    };

    let merkle_root = content_hash::content_hash(padded);

    // Empty plaintext still produces a single zero-length chunk so
    // chunk_count >= 1 holds.
    let total_chunks = if padded.is_empty() {
        1
    } else {
        padded.len().div_ceil(chunk_size)
    };
    let chunk_count: u32 = u32::try_from(total_chunks)
        .map_err(|_| Error::Storage("chunk_and_encrypt: chunk_count exceeds u32::MAX".into()))?;

    let mut sealed_chunks = Vec::with_capacity(total_chunks);
    for chunk_idx in 0..total_chunks {
        let start = chunk_idx * chunk_size;
        let end = (start + chunk_size).min(padded.len());
        let chunk_pt: &[u8] = if padded.is_empty() {
            &[]
        } else {
            &padded[start..end]
        };

        let aad = build_kchat_chunk_aad(
            blob_id,
            blob_class,
            chunk_idx as u32,
            chunk_count,
            &merkle_root,
        );
        let nonce = chunk_nonce(chunk_idx as u32);
        let ciphertext = xchacha20_poly1305::seal(k_asset, &nonce, chunk_pt, &aad)
            .map_err(crate::Error::from)?;
        let chunk_sha256 = sha256_of(&ciphertext);
        sealed_chunks.push(SealedChunk {
            ciphertext,
            chunk_sha256,
        });
    }

    Ok(ChunkedMedia {
        sealed_chunks,
        merkle_root,
        chunk_count,
    })
}

/// Verify and decrypt the output of [`chunk_and_encrypt`].
///
/// 1. **Fast-fail SHA-256 check** — recompute SHA-256 over each
///    chunk's ciphertext and compare against
///    [`SealedChunk::chunk_sha256`]. If any chunk fails we abort
///    *before* attempting any AEAD open so torn / re-ordered uploads
///    don't burn AEAD work.
/// 2. **AEAD open** — for each chunk, rebuild the §8.3 AAD with
///    `expected_merkle_root` and call XChaCha20-Poly1305 open. The
///    AAD binds `chunk_idx` and `chunk_count`, so a swapped chunk
///    fails authentication.
/// 3. **Whole-object verification** — concatenate the decrypted
///    plaintext chunks and verify the BLAKE3 root matches
///    `expected_merkle_root`.
///
/// `expected_merkle_root` is the value the descriptor / archive
/// manifest carries for this asset. Returns the concatenated
/// plaintext on success — note that the caller is responsible for
/// running [`unpad_from_size_class`] when [`chunk_and_encrypt`] was
/// invoked with `pad = true`.
pub fn verify_and_decrypt(
    sealed_chunks: &[SealedChunk],
    expected_merkle_root: [u8; 32],
    k_asset: &[u8; 32],
    blob_id: &[u8; 16],
    blob_class: BlobClass,
) -> Result<Vec<u8>, Error> {
    if sealed_chunks.is_empty() {
        return Err(Error::Storage(
            "verify_and_decrypt: sealed_chunks must contain at least one chunk".into(),
        ));
    }
    let chunk_count: u32 = u32::try_from(sealed_chunks.len())
        .map_err(|_| Error::Storage("verify_and_decrypt: chunk_count exceeds u32::MAX".into()))?;

    // 1) SHA-256 fast-fail before any AEAD work.
    for (idx, chunk) in sealed_chunks.iter().enumerate() {
        let recomputed = sha256_of(&chunk.ciphertext);
        if recomputed != chunk.chunk_sha256 {
            return Err(Error::Storage(
                format!("verify_and_decrypt: chunk {idx} ciphertext SHA-256 mismatch").into(),
            ));
        }
    }

    // 2) AEAD open + plaintext concatenation.
    let mut plaintext = Vec::new();
    for (chunk_idx, chunk) in sealed_chunks.iter().enumerate() {
        let aad = build_kchat_chunk_aad(
            blob_id,
            blob_class,
            chunk_idx as u32,
            chunk_count,
            &expected_merkle_root,
        );
        let nonce = chunk_nonce(chunk_idx as u32);
        let pt = xchacha20_poly1305::open(k_asset, &nonce, &chunk.ciphertext, &aad)
            .map_err(crate::Error::from)?;
        plaintext.extend_from_slice(&pt);
    }

    // 3) Whole-object BLAKE3 root verification.
    let recomputed_root = content_hash::content_hash(&plaintext);
    if recomputed_root != expected_merkle_root {
        return Err(Error::Storage(
            "verify_and_decrypt: whole-object BLAKE3 root mismatch".into(),
        ));
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_k_asset() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(2);
        }
        k
    }

    fn fixed_blob_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        id
    }

    // ---------------------------------------------------------------
    // Task 1 — chunk_and_encrypt
    // ---------------------------------------------------------------

    #[test]
    fn single_chunk_round_trip() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = b"the quick brown fox jumps over the lazy dog".to_vec();
        let out =
            chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false).unwrap();
        assert_eq!(out.chunk_count, 1);
        assert_eq!(out.sealed_chunks.len(), 1);
        // Determinism of the BLAKE3 root.
        let again =
            chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false).unwrap();
        assert_eq!(out.merkle_root, again.merkle_root);
    }

    #[test]
    fn multi_chunk_splits_correctly() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let chunk_size = 1024;
        // 3.5 chunks worth of plaintext.
        let pt = vec![0xCDu8; chunk_size * 3 + chunk_size / 2];
        let out = chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, chunk_size, false).unwrap();
        assert_eq!(out.chunk_count, 4);
        assert_eq!(out.sealed_chunks.len(), 4);
        // First three chunks have ciphertext length = chunk_size +
        // Poly1305 tag.
        for chunk in &out.sealed_chunks[..3] {
            assert_eq!(
                chunk.ciphertext.len(),
                chunk_size + xchacha20_poly1305::TAG_LEN
            );
        }
        // Last chunk shorter.
        assert_eq!(
            out.sealed_chunks[3].ciphertext.len(),
            chunk_size / 2 + xchacha20_poly1305::TAG_LEN
        );
    }

    #[test]
    fn empty_plaintext() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let out =
            chunk_and_encrypt(&[], &k, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false).unwrap();
        // Empty plaintext still produces one zero-length chunk so
        // the AAD chain (chunk_count >= 1) stays well-defined.
        assert_eq!(out.chunk_count, 1);
        assert_eq!(out.sealed_chunks.len(), 1);
        // Ciphertext is the Poly1305 tag only.
        assert_eq!(
            out.sealed_chunks[0].ciphertext.len(),
            xchacha20_poly1305::TAG_LEN
        );
    }

    #[test]
    fn chunk_sha256_is_over_ciphertext() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = b"hash-over-ciphertext-not-plaintext".to_vec();
        let out =
            chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false).unwrap();
        let chunk = &out.sealed_chunks[0];
        assert_eq!(chunk.chunk_sha256, sha256_of(&chunk.ciphertext));
        // And NOT the SHA-256 of the plaintext.
        assert_ne!(chunk.chunk_sha256, sha256_of(&pt));
    }

    #[test]
    fn different_k_asset_produces_different_ciphertext() {
        let blob = fixed_blob_id();
        let pt = b"determinism only holds for the same K_asset".to_vec();
        let k1 = fixed_k_asset();
        let mut k2 = fixed_k_asset();
        k2[0] ^= 0x01;
        let out1 = chunk_and_encrypt(&pt, &k1, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false)
            .unwrap();
        let out2 = chunk_and_encrypt(&pt, &k2, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false)
            .unwrap();
        assert_ne!(
            out1.sealed_chunks[0].ciphertext,
            out2.sealed_chunks[0].ciphertext
        );
        // The plaintext BLAKE3 root is K_asset-independent so they
        // do match.
        assert_eq!(out1.merkle_root, out2.merkle_root);
    }

    #[test]
    fn aad_mismatch_prevents_decrypt() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = b"AAD must match".to_vec();
        let out =
            chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false).unwrap();
        // Tampering with the AAD = decrypting with a different
        // blob_class. AEAD open must reject.
        let bad_aad =
            build_kchat_chunk_aad(&blob, BlobClass::ArchiveSegment, 0, 1, &out.merkle_root);
        let nonce = chunk_nonce(0);
        let res = xchacha20_poly1305::open(&k, &nonce, &out.sealed_chunks[0].ciphertext, &bad_aad);
        assert!(res.is_err(), "AAD-mismatch open accepted: {res:?}");
    }

    // ---------------------------------------------------------------
    // Task 2 — pad_to_size_class / unpad_from_size_class
    // ---------------------------------------------------------------

    #[test]
    fn pad_round_trip() {
        for size in [0usize, 1, 7, 500, 5000, 65_536, 1_500_000] {
            let pt = vec![0xAB; size];
            let padded = pad_to_size_class(&pt);
            let recovered = unpad_from_size_class(&padded).unwrap();
            assert_eq!(recovered, pt.as_slice(), "size = {size}");
        }
    }

    #[test]
    fn padding_reaches_next_class() {
        // 500 bytes (+ 8 prefix = 508) → 1 KiB class.
        assert_eq!(pad_to_size_class(&vec![0u8; 500]).len(), 1024);
        // 5000 bytes (+ 8 = 5008) → 16 KiB class.
        assert_eq!(pad_to_size_class(&vec![0u8; 5000]).len(), 16 * 1024);
        // 1 MiB exactly + 8-byte prefix → 4 MiB class.
        assert_eq!(
            pad_to_size_class(&vec![0u8; 1024 * 1024]).len(),
            4 * 1024 * 1024
        );
        // 2 KiB + 8 = 2056 → 4 KiB class.
        assert_eq!(pad_to_size_class(&vec![0u8; 2048]).len(), 4 * 1024);
    }

    #[test]
    fn unpad_rejects_corrupted_length() {
        let pt = b"hello".to_vec();
        let mut padded = pad_to_size_class(&pt);
        // Set the recorded length to something larger than the
        // padded buffer minus 8.
        let huge = (padded.len() as u64 + 1).to_be_bytes();
        padded[..8].copy_from_slice(&huge);
        let res = unpad_from_size_class(&padded);
        assert!(res.is_err(), "tampered length accepted: {res:?}");
    }

    #[test]
    fn zero_length_input_pads_correctly() {
        let padded = pad_to_size_class(&[]);
        assert_eq!(padded.len(), 1024);
        // First 8 bytes are u64::to_be_bytes(0).
        assert_eq!(&padded[..8], &0u64.to_be_bytes());
        // Trailing bytes are all zeros.
        assert!(padded[8..].iter().all(|&b| b == 0));
        let recovered = unpad_from_size_class(&padded).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn padding_in_chunk_and_encrypt_round_trips_through_verify() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = b"mid-sized content that needs padding to a class".to_vec();
        let out =
            chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, true).unwrap();
        // The merkle_root is over the *padded* bytes; verify_and_decrypt
        // returns the padded plaintext, then we strip the prefix.
        let padded = verify_and_decrypt(
            &out.sealed_chunks,
            out.merkle_root,
            &k,
            &blob,
            BlobClass::Media,
        )
        .unwrap();
        let recovered = unpad_from_size_class(&padded).unwrap();
        assert_eq!(recovered, pt.as_slice());
    }

    // ---------------------------------------------------------------
    // Task 4 — verify_and_decrypt
    // ---------------------------------------------------------------

    #[test]
    fn verify_and_decrypt_round_trip() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = (0u8..=255u8).cycle().take(1024 * 7 + 5).collect::<Vec<_>>();
        let out = chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, 1024, false).unwrap();
        let recovered = verify_and_decrypt(
            &out.sealed_chunks,
            out.merkle_root,
            &k,
            &blob,
            BlobClass::Media,
        )
        .unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn tampered_ciphertext_fails_sha256() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = vec![0xEEu8; 1024 * 3];
        let mut out = chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, 1024, false).unwrap();
        // Tamper with the second chunk's ciphertext. SHA-256 on
        // ciphertext is the fast-fail; AEAD open is never reached.
        out.sealed_chunks[1].ciphertext[0] ^= 0x01;
        let res = verify_and_decrypt(
            &out.sealed_chunks,
            out.merkle_root,
            &k,
            &blob,
            BlobClass::Media,
        );
        match res {
            Err(Error::Storage(msg)) => {
                assert!(
                    msg.to_string().contains("SHA-256"),
                    "unexpected error: {msg}"
                )
            }
            other => panic!("expected SHA-256 mismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampered_chunk_order_fails() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = vec![0x33u8; 1024 * 3];
        let mut out = chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, 1024, false).unwrap();
        // Swap chunk 0 and chunk 1. SHA-256 is per-chunk so it
        // still matches; AEAD open fails because chunk_idx is in
        // the AAD.
        out.sealed_chunks.swap(0, 1);
        let res = verify_and_decrypt(
            &out.sealed_chunks,
            out.merkle_root,
            &k,
            &blob,
            BlobClass::Media,
        );
        assert!(res.is_err(), "swapped chunk order accepted: {res:?}");
    }

    #[test]
    fn wrong_merkle_root_fails() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = b"merkle-bound AAD".to_vec();
        let out =
            chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false).unwrap();
        let mut bad_root = out.merkle_root;
        bad_root[0] ^= 0xFF;
        let res = verify_and_decrypt(&out.sealed_chunks, bad_root, &k, &blob, BlobClass::Media);
        assert!(res.is_err(), "wrong merkle root accepted: {res:?}");
    }

    #[test]
    fn wrong_key_fails() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let pt = b"AEAD bound to K_asset".to_vec();
        let out =
            chunk_and_encrypt(&pt, &k, &blob, BlobClass::Media, DEFAULT_CHUNK_SIZE, false).unwrap();
        let mut wrong = k;
        wrong[0] ^= 0x01;
        let res = verify_and_decrypt(
            &out.sealed_chunks,
            out.merkle_root,
            &wrong,
            &blob,
            BlobClass::Media,
        );
        assert!(res.is_err(), "wrong K_asset accepted: {res:?}");
    }

    #[test]
    fn empty_sealed_chunks_rejected() {
        let k = fixed_k_asset();
        let blob = fixed_blob_id();
        let res = verify_and_decrypt(&[], [0u8; 32], &k, &blob, BlobClass::Media);
        assert!(res.is_err());
    }
}
