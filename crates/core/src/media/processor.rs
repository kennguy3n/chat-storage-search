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
use crate::local_store::db::LocalStoreDb;
use crate::local_store::state_machines::MediaState;
use crate::media::chunker::{chunk_and_encrypt, SealedChunk, DEFAULT_CHUNK_SIZE};
use crate::media::thumbnail::{ThumbnailGenerator, DEFAULT_MAX_DIMENSION};
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
    /// Initial [`MediaState`] the caller should persist into
    /// `media_asset.media_state` for this asset. `process_media`
    /// always returns [`MediaState::ThumbnailOnly`] — the original
    /// has been chunked + AEAD-sealed in memory but not yet
    /// uploaded; the upload pipeline transitions it onward through
    /// the legal-transitions matrix in
    /// [`MediaState::try_transition`].
    pub initial_media_state: MediaState,
    /// Optional **plaintext** thumbnail bytes (PNG) generated from
    /// `plaintext` for image MIME types (`image/png`, `image/jpeg`).
    ///
    /// `Some(_)` for supported image inputs that decode + downscale
    /// successfully via [`ThumbnailGenerator::generate_thumbnail`].
    /// `None` when the MIME type is not a supported image type
    /// (e.g. `video/mp4`, `application/pdf`) or when thumbnail
    /// generation fails — thumbnail failures are deliberately
    /// non-fatal so the original media still uploads even if the
    /// preview is unavailable. The caller is responsible for
    /// chunking + AEAD-sealing the thumbnail bytes through
    /// [`crate::media::chunker::chunk_and_encrypt`] (or a second
    /// `process_media` call) before persisting them — the bytes
    /// here are the *plaintext* PNG that fits in a single chunk.
    pub thumbnail_bytes: Option<Vec<u8>>,
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

    // 6) Optional thumbnail. Errors are non-fatal — the original
    //    media still uploads cleanly without a preview, and
    //    non-image MIME types (`video/*`, `application/*`, `audio/*`)
    //    deliberately collapse to `None` so the caller can branch on
    //    the optional without inspecting the error variant.
    let thumbnail_bytes = ThumbnailGenerator::new()
        .generate_thumbnail(plaintext, mime_type, DEFAULT_MAX_DIMENSION)
        .ok()
        .map(|t| t.thumbnail_bytes);

    Ok(MediaProcessResult {
        descriptor,
        sealed_chunks: chunked.sealed_chunks,
        k_asset_raw: k_asset_buf,
        initial_media_state: MediaState::ThumbnailOnly,
        thumbnail_bytes,
    })
}

/// Apply a [`MediaState`] transition to the `media_asset` row for
/// `asset_id`, going through [`MediaState::try_transition`] before
/// the SQL UPDATE.
///
/// `from` is the state the caller believes the asset is currently
/// in; the helper verifies it matches the persisted `media_state`
/// before applying the transition. This catches racing callers that
/// would otherwise silently overwrite each other's state changes.
///
/// Returns:
///
/// * [`Error::Storage`] when no asset row matches `asset_id`.
/// * [`Error::Storage`] when the persisted `media_state` does not
///   match the caller-provided `from` (concurrent transition).
/// * [`Error::Storage`] when `(from, to)` is not a legal pair per
///   [`MediaState::try_transition`].
pub fn transition_media_state(
    db: &LocalStoreDb,
    asset_id: &str,
    from: MediaState,
    to: MediaState,
) -> Result<(), Error> {
    MediaState::try_transition(from, to)
        .map_err(|e| Error::Storage(format!("media_state transition: {e}").into()))?;
    let asset = db
        .get_media_asset(asset_id)
        .map_err(|e| Error::Storage(format!("media_state lookup: {e}").into()))?
        .ok_or_else(|| {
            Error::Storage(
                format!("transition_media_state: no media_asset row for asset_id {asset_id:?}")
                    .into(),
            )
        })?;
    if asset.media_state != from {
        return Err(Error::Storage(
            format!(
                "transition_media_state: expected media_state = {from} for {asset_id:?}, found {}",
                asset.media_state
            )
            .into(),
        ));
    }
    let rows = db
        .update_media_state(asset_id, to)
        .map_err(|e| Error::Storage(format!("media_state update: {e}").into()))?;
    if rows == 0 {
        return Err(Error::Storage(
            format!("transition_media_state: update affected 0 rows for asset_id {asset_id:?}")
                .into(),
        ));
    }
    Ok(())
}

/// Wire `media_state = OriginalLocal` after a successful download.
///
/// Convenience over [`transition_media_state`] for the
/// `RemoteOriginal → DownloadInProgress → OriginalLocal` (or
/// `Evicted → DownloadInProgress → OriginalLocal`) tail. The caller
/// is expected to have already applied the
/// `→ DownloadInProgress` transition before fetching ciphertext;
/// this helper closes out the second half.
pub fn mark_downloaded(db: &LocalStoreDb, asset_id: &str) -> Result<(), Error> {
    transition_media_state(
        db,
        asset_id,
        MediaState::DownloadInProgress,
        MediaState::OriginalLocal,
    )
}

/// Wire `media_state = Evicted` after the eviction pipeline removes
/// the on-disk plaintext for an asset. Mirrors the
/// `OriginalLocal → Evicted` transition in
/// [`MediaState::try_transition`].
pub fn mark_evicted(db: &LocalStoreDb, asset_id: &str) -> Result<(), Error> {
    transition_media_state(db, asset_id, MediaState::OriginalLocal, MediaState::Evicted)
}

/// Wire `media_state = Deleted` after a delete-for-everyone or local
/// delete-cascade for an asset. Only legal from `OriginalLocal` per
/// [`MediaState::try_transition`].
pub fn mark_deleted(db: &LocalStoreDb, asset_id: &str) -> Result<(), Error> {
    transition_media_state(db, asset_id, MediaState::OriginalLocal, MediaState::Deleted)
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
        // `as_ref::<[u8]>()` to disambiguate now that `hybrid_array`
        // (pulled in by `ml-dsa`) also implements
        // `AsRef<Array<T, U>> for [T; N]`.
        assert_eq!(&unwrapped[..], &res.k_asset_raw[..]);

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
        assert_ne!(&a.k_asset_raw[..], &b.k_asset_raw[..]);
        // …and so is the ciphertext, even though the plaintext is
        // identical.
        assert_ne!(
            a.sealed_chunks[0].ciphertext, b.sealed_chunks[0].ciphertext,
            "fresh K_asset must produce distinct ciphertext"
        );
        // The plaintext BLAKE3 root *does* match (K_asset-independent).
        assert_eq!(a.descriptor.merkle_root, b.descriptor.merkle_root);
    }

    // -----------------------------------------------------------------
    // State-machine integration
    // -----------------------------------------------------------------

    use crate::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
    use crate::local_store::state_machines::{ArchiveState, BackupState, BodyState};

    fn fresh_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[7u8; 32]).unwrap()
    }

    fn seed_asset(db: &LocalStoreDb, asset_id: &str, state: MediaState) {
        let conv = Conversation {
            conversation_id: "c-state".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
            ..Default::default()
        };
        let _ = db.insert_conversation(&conv);
        let skel = MessageSkeleton {
            message_id: format!("m-{asset_id}"),
            conversation_id: "c-state".into(),
            sender_id: "s".into(),
            created_at_ms: 1,
            received_at_ms: 1,
            kind: MessageKind::Media,
            body_state: BodyState::LocalPlainAvailable,
            media_state: Some(state),
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        let _ = db.insert_message_skeleton(&skel);
        db.insert_media_asset(&MediaAsset {
            asset_id: asset_id.into(),
            message_id: format!("m-{asset_id}"),
            mime_type: "image/png".into(),
            bytes_total: 64,
            bytes_local: 64,
            media_state: state,
            wrapped_k_asset: vec![0u8; 40],
            chunk_count: 1,
            merkle_root: vec![0u8; 32],
            blob_id: format!("blob-{asset_id}"),
            storage_sink: "kchat_backend".into(),
        })
        .unwrap();
    }

    #[test]
    fn process_media_returns_thumbnail_only_initial_state() {
        let wrapping = fixed_wrapping_key();
        let res = process_media(b"hi", "image/png", &wrapping, BlobClass::Media, false).unwrap();
        assert_eq!(res.initial_media_state, MediaState::ThumbnailOnly);
    }

    #[test]
    fn transition_media_state_legal_succeeds() {
        let db = fresh_db();
        seed_asset(&db, "a-1", MediaState::ThumbnailOnly);
        transition_media_state(
            &db,
            "a-1",
            MediaState::ThumbnailOnly,
            MediaState::RemoteOriginal,
        )
        .unwrap();
        let row = db.get_media_asset("a-1").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::RemoteOriginal);
    }

    #[test]
    fn transition_media_state_illegal_errors() {
        let db = fresh_db();
        seed_asset(&db, "a-2", MediaState::ThumbnailOnly);
        // ThumbnailOnly → Deleted is not in the legal set.
        let err =
            transition_media_state(&db, "a-2", MediaState::ThumbnailOnly, MediaState::Deleted)
                .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.to_string().contains("transition"), "{msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
        // The DB row must not have changed.
        let row = db.get_media_asset("a-2").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::ThumbnailOnly);
    }

    #[test]
    fn transition_media_state_persists_in_db() {
        let db = fresh_db();
        seed_asset(&db, "a-3", MediaState::DownloadInProgress);
        transition_media_state(
            &db,
            "a-3",
            MediaState::DownloadInProgress,
            MediaState::OriginalLocal,
        )
        .unwrap();
        let row = db.get_media_asset("a-3").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::OriginalLocal);
    }

    #[test]
    fn transition_media_state_missing_asset_errors() {
        let db = fresh_db();
        let err = transition_media_state(
            &db,
            "never-seen",
            MediaState::ThumbnailOnly,
            MediaState::OriginalLocal,
        )
        .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.to_string().contains("no media_asset row"), "{msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn transition_media_state_wrong_from_errors() {
        let db = fresh_db();
        seed_asset(&db, "a-5", MediaState::ThumbnailOnly);
        let err =
            transition_media_state(&db, "a-5", MediaState::OriginalLocal, MediaState::Evicted)
                .unwrap_err();
        match err {
            Error::Storage(msg) => {
                assert!(msg.to_string().contains("expected media_state"), "{msg}")
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn mark_downloaded_closes_out_download_in_progress() {
        let db = fresh_db();
        seed_asset(&db, "a-6", MediaState::DownloadInProgress);
        mark_downloaded(&db, "a-6").unwrap();
        let row = db.get_media_asset("a-6").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::OriginalLocal);
    }

    #[test]
    fn mark_evicted_transitions_original_local() {
        let db = fresh_db();
        seed_asset(&db, "a-7", MediaState::OriginalLocal);
        mark_evicted(&db, "a-7").unwrap();
        let row = db.get_media_asset("a-7").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::Evicted);
    }

    #[test]
    fn mark_deleted_transitions_original_local() {
        let db = fresh_db();
        seed_asset(&db, "a-8", MediaState::OriginalLocal);
        mark_deleted(&db, "a-8").unwrap();
        let row = db.get_media_asset("a-8").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::Deleted);
    }

    // -----------------------------------------------------------------
    // Phase-2 finishing pass: thumbnail wiring on `process_media`.
    // -----------------------------------------------------------------
    use image::{ImageBuffer, ImageFormat as TestImageFormat, Rgb, Rgba};
    use std::io::Cursor as TestCursor;

    fn make_png(w: u32, h: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(w, h, |x, y| {
            Rgba([
                ((x * 255) / w.max(1)) as u8,
                ((y * 255) / h.max(1)) as u8,
                ((x ^ y) & 0xFF) as u8,
                0xFF,
            ])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut TestCursor::new(&mut out), TestImageFormat::Png)
            .expect("encode png");
        out
    }

    fn make_jpeg(w: u32, h: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(w, h, |x, y| {
            Rgb([
                ((x * 255) / w.max(1)) as u8,
                ((y * 255) / h.max(1)) as u8,
                ((x ^ y) & 0xFF) as u8,
            ])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut TestCursor::new(&mut out), TestImageFormat::Jpeg)
            .expect("encode jpeg");
        out
    }

    #[test]
    fn process_media_emits_thumbnail_for_png() {
        let wrapping = fixed_wrapping_key();
        let pt = make_png(640, 480);
        let res = process_media(&pt, "image/png", &wrapping, BlobClass::Media, false).unwrap();
        let thumb = res
            .thumbnail_bytes
            .as_ref()
            .expect("png input must yield a thumbnail");
        // PNG magic bytes — every thumbnail re-encodes as PNG
        // regardless of input MIME.
        assert_eq!(&thumb[..8], b"\x89PNG\r\n\x1A\n");
        // Thumbnail is bounded by `DEFAULT_MAX_DIMENSION` so it fits
        // inside a single AEAD chunk; for a 640×480 source it lands
        // well under the source size.
        assert!(
            thumb.len() < pt.len(),
            "thumb {} >= src {}",
            thumb.len(),
            pt.len()
        );
    }

    #[test]
    fn process_media_emits_thumbnail_for_jpeg() {
        let wrapping = fixed_wrapping_key();
        let pt = make_jpeg(800, 600);
        let res = process_media(&pt, "image/jpeg", &wrapping, BlobClass::Media, false).unwrap();
        let thumb = res
            .thumbnail_bytes
            .as_ref()
            .expect("jpeg input must yield a thumbnail");
        assert_eq!(&thumb[..8], b"\x89PNG\r\n\x1A\n");
    }

    #[test]
    fn process_media_thumbnail_respects_max_dimension() {
        let wrapping = fixed_wrapping_key();
        let pt = make_png(1024, 1024);
        let res = process_media(&pt, "image/png", &wrapping, BlobClass::Media, false).unwrap();
        let thumb = res.thumbnail_bytes.as_ref().expect("thumbnail");
        // Decode the thumbnail and verify both dimensions fit inside
        // the bound the processor wires in
        // (`media::thumbnail::DEFAULT_MAX_DIMENSION`).
        let decoded = image::ImageReader::new(TestCursor::new(thumb))
            .with_guessed_format()
            .unwrap()
            .decode()
            .expect("decode thumbnail");
        let (w, h) = (decoded.width(), decoded.height());
        let bound = crate::media::thumbnail::DEFAULT_MAX_DIMENSION;
        assert!(w <= bound, "thumbnail width {w} > bound {bound}");
        assert!(h <= bound, "thumbnail height {h} > bound {bound}");
    }

    #[test]
    fn process_media_no_thumbnail_for_video_mime() {
        let wrapping = fixed_wrapping_key();
        // Non-image MIME types — and inputs that don't decode as the
        // declared image format — collapse to `None` rather than
        // erroring out, so the original media still uploads cleanly.
        let pt = vec![0xAB; 4096];
        let res = process_media(&pt, "video/mp4", &wrapping, BlobClass::Media, false).unwrap();
        assert!(
            res.thumbnail_bytes.is_none(),
            "video/mp4 must not yield a thumbnail"
        );
    }

    #[test]
    fn process_media_no_thumbnail_for_document_mime() {
        let wrapping = fixed_wrapping_key();
        let pt = vec![0xCD; 8192];
        let res =
            process_media(&pt, "application/pdf", &wrapping, BlobClass::Media, false).unwrap();
        assert!(res.thumbnail_bytes.is_none());
    }

    #[test]
    fn process_media_no_thumbnail_when_image_corrupt() {
        let wrapping = fixed_wrapping_key();
        // PNG MIME but garbage payload — thumbnail generation fails
        // and `process_media` swallows it, returning `None` so the
        // sealed-original path is unaffected.
        let res =
            process_media(&[0u8; 16], "image/png", &wrapping, BlobClass::Media, false).unwrap();
        assert!(res.thumbnail_bytes.is_none());
        // The original chunks + descriptor are still produced.
        assert_eq!(res.descriptor.bytes_total, 16);
    }
}
