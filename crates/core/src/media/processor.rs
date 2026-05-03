//! Media processor: turn a plaintext blob into the on-wire / on-disk
//! representation expected by the rest of the core.
//!
//! `docs/PROPOSAL.md §3.2` (the `media_asset` row), `§5.7` (tiered
//! media storage), and `§8` (chunking + AEAD) are the authoritative
//! sources for the end-to-end flow that [`process_media`] implements:
//!
//! 1. Generate a fresh-random 256-bit `K_asset`.
//! 2. Split the plaintext into AEAD-sealed chunks via
//!    [`crate::media::chunker::chunk_and_encrypt`] (with optional
//!    `§8.2` size-class padding).
//! 3. Wrap `K_asset` under `wrapping_key` using AES-256-KW
//!    (`crate::crypto::key_wrap::wrap_key` — see `docs/PROPOSAL.md
//!    §7` and `crates/core/src/crypto/key_wrap.rs`).
//! 4. Build the [`MediaDescriptor`] the local store and the archive
//!    / backup engines round-trip through CBOR.
//!
//! The wrapping key is typed as a raw `&[u8; 32]` so callers can pass
//! `K_local_db`, `K_archive_root`, or `K_backup_root` byte slices
//! directly without forcing a [`crate::crypto::key_hierarchy::KeyMaterial`]
//! conversion at the call site. `K_asset` itself lives in a
//! [`Zeroizing<[u8; 32]>`] so a panic mid-way still scrubs the key
//! before unwinding.

use rand::RngCore;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::aead::BlobClass;
use crate::crypto::key_hierarchy::KEY_LEN;
use crate::crypto::key_wrap::wrap_key;
use crate::formats::media_descriptor::MediaDescriptor;
use crate::media::chunker::{chunk_and_encrypt, SealedChunk, DEFAULT_CHUNK_SIZE};
use crate::Error;

/// Output of [`process_media`]: everything the local store and the
/// upload pipeline need to persist + ship the asset.
///
/// `descriptor` is the CBOR-encodable wire format. `sealed_chunks`
/// is what [`crate::media::upload::upload_chunked_media`] feeds into
/// the [`crate::transport::TransportClient`]. `k_asset_raw` is the
/// fresh-random asset key that produced the chunks; the caller may
/// keep it around for an eager-decrypt local cache and is responsible
/// for dropping it (the [`Zeroizing`] wrapper scrubs on drop).
#[derive(Debug)]
pub struct MediaProcessResult {
    /// Asset descriptor with `merkle_root`, `chunk_count`,
    /// `wrapped_k_asset`, and the message-layer fields.
    pub descriptor: MediaDescriptor,
    /// AEAD-sealed chunks ready for upload. Order matches
    /// [`MediaDescriptor::chunk_count`].
    pub sealed_chunks: Vec<SealedChunk>,
    /// Fresh-random `K_asset` that sealed the chunks. Zeroized on
    /// drop. The wrapped form is also stored on
    /// [`MediaDescriptor::wrapped_k_asset`].
    pub k_asset_raw: Zeroizing<[u8; KEY_LEN]>,
}

/// Run the full chunk-encrypt + key-wrap + descriptor pipeline for a
/// single media plaintext.
///
/// `wrapping_key` is the bytes of one of `K_local_db`,
/// `K_archive_root`, or `K_backup_root` (32 bytes); see
/// `docs/PROPOSAL.md §7` and the
/// [`crate::crypto::key_hierarchy`] module. `pad = true` runs the
/// `§8.2` size-class padding so the on-wire blob length only reveals
/// the size class.
pub fn process_media(
    plaintext: &[u8],
    mime_type: &str,
    wrapping_key: &[u8; KEY_LEN],
    blob_class: BlobClass,
    pad: bool,
) -> Result<MediaProcessResult, Error> {
    // 1) Generate K_asset.
    let mut k_asset_buf = Zeroizing::new([0u8; KEY_LEN]);
    rand::thread_rng().fill_bytes(k_asset_buf.as_mut_slice());

    // 2) Allocate identifiers up front so the chunker AAD agrees
    //    with the descriptor.
    let asset_id = Uuid::now_v7();
    let blob_id = Uuid::now_v7();
    let blob_id_bytes: [u8; 16] = *blob_id.as_bytes();

    // 3) Chunk + AEAD-seal.
    let chunked = chunk_and_encrypt(
        plaintext,
        &k_asset_buf,
        &blob_id_bytes,
        blob_class,
        DEFAULT_CHUNK_SIZE,
        pad,
    )?;

    // 4) Wrap K_asset under the configured root.
    let wrapped_k_asset = wrap_key(wrapping_key, &k_asset_buf).map_err(crate::Error::from)?;

    // 5) Assemble the descriptor.
    let descriptor = MediaDescriptor {
        asset_id,
        mime_type: mime_type.to_string(),
        bytes_total: plaintext.len() as u64,
        chunk_count: chunked.chunk_count,
        merkle_root: chunked.merkle_root,
        blob_id,
        wrapped_k_asset,
        storage_sink: None,
    };

    Ok(MediaProcessResult {
        descriptor,
        sealed_chunks: chunked.sealed_chunks,
        k_asset_raw: k_asset_buf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_wrap::unwrap_key;
    use crate::media::chunker::{unpad_from_size_class, verify_and_decrypt};

    fn fixed_wrapping_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5A;
        }
        k
    }

    #[test]
    fn process_media_round_trip() {
        let wrapping = fixed_wrapping_key();
        let pt = b"a small media blob to round-trip through process_media".to_vec();
        let res = process_media(&pt, "image/png", &wrapping, BlobClass::Media, false).unwrap();

        // 1) Unwrap K_asset and confirm we recover the same key the
        //    chunker used.
        let unwrapped = unwrap_key(&wrapping, &res.descriptor.wrapped_k_asset).unwrap();
        assert_eq!(&unwrapped, res.k_asset_raw.as_ref());

        // 2) Decrypt every chunk under the same blob_id / class /
        //    merkle_root and confirm the plaintext matches.
        let blob_id_bytes: [u8; 16] = *res.descriptor.blob_id.as_bytes();
        let decrypted = verify_and_decrypt(
            &res.sealed_chunks,
            res.descriptor.merkle_root,
            &unwrapped,
            &blob_id_bytes,
            BlobClass::Media,
        )
        .unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn process_media_descriptor_fields() {
        let wrapping = fixed_wrapping_key();
        let pt = vec![0xABu8; 1234];
        let res = process_media(&pt, "video/mp4", &wrapping, BlobClass::Media, false).unwrap();

        assert_eq!(res.descriptor.mime_type, "video/mp4");
        assert_eq!(res.descriptor.bytes_total, pt.len() as u64);
        assert_eq!(res.descriptor.chunk_count, 1);
        assert_eq!(
            res.descriptor.wrapped_k_asset.len(),
            crate::crypto::key_wrap::WRAPPED_KEY_LEN
        );
        assert!(res.descriptor.storage_sink.is_none());
        // asset_id / blob_id are UUID v7 and therefore distinct.
        assert_ne!(res.descriptor.asset_id, res.descriptor.blob_id);
    }

    #[test]
    fn process_media_with_padding() {
        let wrapping = fixed_wrapping_key();
        let pt = b"padded plaintext".to_vec();
        let res = process_media(&pt, "image/png", &wrapping, BlobClass::Media, true).unwrap();

        // Unwrap K_asset, decrypt, and strip the size-class prefix.
        let unwrapped = unwrap_key(&wrapping, &res.descriptor.wrapped_k_asset).unwrap();
        let blob_id_bytes: [u8; 16] = *res.descriptor.blob_id.as_bytes();
        let padded = verify_and_decrypt(
            &res.sealed_chunks,
            res.descriptor.merkle_root,
            &unwrapped,
            &blob_id_bytes,
            BlobClass::Media,
        )
        .unwrap();
        // Padded plaintext is at least 1 KiB (smallest size class).
        assert!(padded.len() >= 1024);
        let recovered = unpad_from_size_class(&padded).unwrap();
        assert_eq!(recovered, pt.as_slice());
    }

    #[test]
    fn different_calls_produce_different_k_asset() {
        let wrapping = fixed_wrapping_key();
        let pt = b"same plaintext, different K_asset".to_vec();
        let a = process_media(&pt, "image/png", &wrapping, BlobClass::Media, false).unwrap();
        let b = process_media(&pt, "image/png", &wrapping, BlobClass::Media, false).unwrap();
        // K_asset is fresh-random per call.
        assert_ne!(a.k_asset_raw.as_ref(), b.k_asset_raw.as_ref());
        // …and so is the ciphertext, even though the plaintext is
        // identical.
        assert_ne!(
            a.sealed_chunks[0].ciphertext, b.sealed_chunks[0].ciphertext,
            "fresh K_asset must produce distinct ciphertext"
        );
        // The plaintext BLAKE3 root *does* match (K_asset-independent).
        assert_eq!(a.descriptor.merkle_root, b.descriptor.merkle_root);
    }
}
