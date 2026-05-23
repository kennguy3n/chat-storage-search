//! End-to-end integration test for the Phase-2 media pipeline.
//!
//! `docs/PHASES.md` Phase 2 ties together five separate modules
//! (`media::processor`, `media::chunker`, `media::cache`,
//! `media::caption`, `media::routing`); this test exercises the
//! happy path that connects them so a future regression in any one
//! of the pieces shows up here, not just in the per-module unit
//! tests.

use kchat_core::crypto::aead::BlobClass;
use kchat_core::crypto::key_wrap::unwrap_key;
use kchat_core::media::cache::MediaCache;
use kchat_core::media::caption::{normalize_caption, sanitize_filename};
use kchat_core::media::chunker::{chunk_and_encrypt, unpad_from_size_class, DEFAULT_CHUNK_SIZE};
use kchat_core::media::processor::process_media;
use kchat_core::media::routing::{route_media_download, route_media_upload, KCHAT_BACKEND_SINK};
use kchat_core::media::sinks::{MediaBlobReference, MediaBlobSink, NoopMediaBlobSink};
use kchat_core::media::thumbnail::ThumbnailGenerator;
use kchat_core::transport::NoopTransportClient;
use kchat_core::{CommitBlobResponse, KChatCoreConfig};

const WRAPPING_KEY: [u8; 32] = [0x42; 32];

fn config_with_default_sink() -> KChatCoreConfig {
    use kchat_core::config::Platform;
    use std::path::PathBuf;
    KChatCoreConfig::new(
        PathBuf::from("/tmp/kchat-media-pipeline-tests"),
        Platform::MacOs,
        "tenant-test",
    )
}

#[test]
fn process_media_round_trips_through_verify_and_decrypt() {
    let plaintext = (0..(DEFAULT_CHUNK_SIZE / 4))
        .map(|i| ((i * 7) & 0xFF) as u8)
        .collect::<Vec<u8>>();
    let processed = process_media(
        &plaintext,
        "image/jpeg",
        &WRAPPING_KEY,
        BlobClass::Media,
        false,
    )
    .expect("process_media");

    // Descriptor sanity: identifiers, size, chunk_count, root.
    let descriptor = &processed.descriptor;
    assert_eq!(descriptor.mime_type, "image/jpeg");
    assert_eq!(descriptor.bytes_total, plaintext.len() as u64);
    assert!(descriptor.chunk_count >= 1);
    assert_eq!(descriptor.merkle_root.len(), 32);
    assert!(!descriptor.wrapped_k_asset.is_empty());

    // Round-trip the wrapped K_asset.
    let recovered_k_asset =
        unwrap_key(&WRAPPING_KEY, &descriptor.wrapped_k_asset).expect("unwrap_key");
    assert_eq!(recovered_k_asset, *processed.k_asset_raw);

    // Verify the sealed chunks decrypt back to the input bytes.
    use kchat_core::media::chunker::verify_and_decrypt;
    let decrypted = verify_and_decrypt(
        &processed.sealed_chunks,
        descriptor.merkle_root,
        &recovered_k_asset,
        descriptor.blob_id.as_bytes(),
        BlobClass::Media,
    )
    .expect("verify_and_decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn process_media_with_padding_round_trips() {
    let plaintext = b"alpha beta gamma delta epsilon".to_vec();
    let processed = process_media(
        &plaintext,
        "application/pdf",
        &WRAPPING_KEY,
        BlobClass::Media,
        true,
    )
    .expect("process_media");

    let recovered_k_asset =
        unwrap_key(&WRAPPING_KEY, &processed.descriptor.wrapped_k_asset).expect("unwrap_key");
    use kchat_core::media::chunker::verify_and_decrypt;
    let decrypted = verify_and_decrypt(
        &processed.sealed_chunks,
        processed.descriptor.merkle_root,
        &recovered_k_asset,
        processed.descriptor.blob_id.as_bytes(),
        BlobClass::Media,
    )
    .expect("verify_and_decrypt");
    let unpadded = unpad_from_size_class(&decrypted).expect("unpad");
    assert_eq!(unpadded, plaintext);
}

#[test]
fn small_blob_yields_single_chunk() {
    let plaintext = b"tiny payload".to_vec();
    let processed = process_media(
        &plaintext,
        "text/plain",
        &WRAPPING_KEY,
        BlobClass::Media,
        false,
    )
    .expect("process_media");
    assert_eq!(processed.descriptor.chunk_count, 1);
    assert_eq!(processed.sealed_chunks.len(), 1);
}

#[test]
fn large_blob_yields_multiple_chunks_via_chunker() {
    // Use the chunker directly with a small chunk size so we can
    // assert multi-chunk behaviour without allocating a 16 MiB
    // buffer in the test runner.
    let chunk_size = 64usize;
    let plaintext: Vec<u8> = (0..1024).map(|i| (i & 0xFF) as u8).collect();
    let k_asset = [0x33; 32];
    let blob_id = [0x07; 16];
    let chunked = chunk_and_encrypt(
        &plaintext,
        &k_asset,
        &blob_id,
        BlobClass::Media,
        chunk_size,
        false,
    )
    .expect("chunk_and_encrypt");
    assert!(
        chunked.chunk_count > 1,
        "expected multiple chunks, got {}",
        chunked.chunk_count
    );

    use kchat_core::media::chunker::verify_and_decrypt;
    let decrypted = verify_and_decrypt(
        &chunked.sealed_chunks,
        chunked.merkle_root,
        &k_asset,
        &blob_id,
        BlobClass::Media,
    )
    .expect("verify_and_decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn media_cache_insert_touch_evict_cycle() {
    let mut cache = MediaCache::new(1024);
    assert_eq!(cache.entry_count(), 0);

    cache.insert("a".to_string(), 400);
    cache.insert("b".to_string(), 400);
    assert!(cache.contains("a"));
    assert!(cache.contains("b"));
    assert_eq!(cache.current_bytes(), 800);

    cache.touch("a");
    let evicted = cache.insert("c".to_string(), 400);
    // Inserting `c` pushes total over budget; LRU is `b` since `a`
    // was just touched.
    assert_eq!(evicted, vec!["b"]);
    assert!(!cache.contains("b"));
    assert!(cache.contains("a"));
    assert!(cache.contains("c"));

    let freed = cache.remove("a");
    assert_eq!(freed, 400);
    assert!(!cache.contains("a"));
}

#[test]
fn caption_normalization_handles_multilingual_text() {
    // CJK + composed/decomposed Latin diacritics + multi-script
    // mixing, with extra whitespace and NBSP in the middle.
    let cjk_decomposed = "  café résumé  日本語\u{3000}тест العربية  ";
    let normalized = normalize_caption(cjk_decomposed);
    assert!(normalized.contains("café"));
    assert!(normalized.contains("日本語"));
    assert!(normalized.contains("тест"));
    assert!(normalized.contains("العربية"));
    // Whitespace runs collapse to single spaces.
    assert!(!normalized.contains("  "));
    // No leading / trailing whitespace.
    assert_eq!(normalized.trim(), normalized);
}

#[test]
fn sanitize_filename_handles_multilingual_inputs() {
    // CJK
    let cjk = sanitize_filename("写真.jpg");
    assert!(cjk.contains("写真"));
    assert!(cjk.ends_with(".jpg"));

    // Arabic (right-to-left script).
    let arabic = sanitize_filename("صورة.png");
    assert!(arabic.contains("صورة"));
    assert!(arabic.ends_with(".png"));

    // Cyrillic.
    let cyr = sanitize_filename("картинка.jpeg");
    assert!(cyr.contains("картинка"));
    assert!(cyr.ends_with(".jpeg"));

    // Path separator + control char dropped.
    let mixed = sanitize_filename("a/b\x07.txt");
    assert!(!mixed.contains('/'));
    assert!(!mixed.contains('\x07'));
}

#[derive(Debug, Default)]
struct CapturingMediaBlobSink {
    /// Stash uploaded chunks per asset_id so `fetch_media_chunk`
    /// can return them.
    uploads: std::sync::Mutex<std::collections::HashMap<String, Vec<Vec<u8>>>>,
}

impl MediaBlobSink for CapturingMediaBlobSink {
    fn upload_media_chunks(
        &self,
        asset_id: &str,
        _blob_class: BlobClass,
        chunks: &[&[u8]],
        _expected_merkle_root: [u8; 32],
    ) -> kchat_core::Result<MediaBlobReference> {
        let owned: Vec<Vec<u8>> = chunks.iter().map(|c| c.to_vec()).collect();
        self.uploads
            .lock()
            .unwrap()
            .insert(asset_id.to_string(), owned);
        Ok(MediaBlobReference {
            blob_id: asset_id.to_string(),
            storage_sink: "zk_object_fabric".to_string(),
            sink_metadata: None,
        })
    }

    fn fetch_media_chunk(
        &self,
        blob_ref: &MediaBlobReference,
        chunk_idx: u32,
    ) -> kchat_core::Result<Vec<u8>> {
        let guard = self.uploads.lock().unwrap();
        let chunks = guard.get(&blob_ref.blob_id).ok_or_else(|| {
            kchat_core::Error::Storage(format!("unknown asset {:?}", blob_ref.blob_id).into())
        })?;
        chunks.get(chunk_idx as usize).cloned().ok_or_else(|| {
            kchat_core::Error::Storage(format!("chunk_idx {chunk_idx} out of range").into())
        })
    }

    fn delete_media_blob(&self, blob_ref: &MediaBlobReference) -> kchat_core::Result<()> {
        self.uploads.lock().unwrap().remove(&blob_ref.blob_id);
        Ok(())
    }
}

#[test]
fn route_media_upload_dispatches_to_noop_for_thumbnails() {
    let plaintext = b"thumb bytes".to_vec();
    let processed = process_media(
        &plaintext,
        "image/png",
        &WRAPPING_KEY,
        BlobClass::Media,
        false,
    )
    .expect("process_media");

    let transport = NoopTransportClient;
    let sink = CapturingMediaBlobSink::default();
    let cfg = config_with_default_sink();

    // `is_thumbnail = true` always Tier 0, regardless of sink
    // configuration. NoopTransportClient errors on `init_blob_upload`
    // so we expect a transport error here — that's the correct
    // routing decision (we *did* dispatch to Tier 0).
    let res = route_media_upload(
        &cfg,
        &transport,
        Some(&sink),
        &processed.descriptor.asset_id.to_string(),
        &processed.sealed_chunks,
        processed.descriptor.merkle_root,
        BlobClass::Media,
        true,
    );
    assert!(res.is_err(), "expected Tier-0 NoopTransportClient error");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("transport") || err.contains("not implemented") || err.contains("Noop"),
        "expected transport-layer error, got {err}"
    );
}

#[test]
fn route_media_download_rejects_storage_sink_mismatch() {
    let blob_ref = MediaBlobReference {
        blob_id: "blob-1".to_string(),
        storage_sink: "zk_object_fabric".to_string(),
        sink_metadata: None,
    };
    let res = route_media_download(
        KCHAT_BACKEND_SINK,
        &NoopTransportClient,
        Some(&NoopMediaBlobSink),
        &blob_ref,
        0,
    );
    let err = res.expect_err("mismatch must error");
    assert!(err.to_string().contains("does not match"));
}

#[test]
fn thumbnail_round_trips_through_chunk_and_encrypt() {
    use image::{ImageBuffer, ImageFormat, Rgba};
    use std::io::Cursor;

    // Generate a test PNG.
    let img = ImageBuffer::from_fn(128, 128, |x, y| {
        Rgba([
            ((x * 2) & 0xFF) as u8,
            ((y * 2) & 0xFF) as u8,
            ((x ^ y) & 0xFF) as u8,
            0xFF,
        ])
    });
    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .unwrap();

    // Generate a thumbnail and feed it through the chunk + encrypt
    // pipeline (the same pipeline `process_media` uses for the
    // original).
    let thumb = ThumbnailGenerator::new()
        .generate_thumbnail(&png, "image/png", 64)
        .expect("thumbnail");
    assert!(!thumb.thumbnail_bytes.is_empty());
    assert!(thumb.width <= 64);
    assert!(thumb.height <= 64);

    let processed = process_media(
        &thumb.thumbnail_bytes,
        &thumb.mime_type,
        &WRAPPING_KEY,
        BlobClass::Media,
        false,
    )
    .expect("process thumbnail");
    let recovered = unwrap_key(&WRAPPING_KEY, &processed.descriptor.wrapped_k_asset).unwrap();
    use kchat_core::media::chunker::verify_and_decrypt;
    let decrypted = verify_and_decrypt(
        &processed.sealed_chunks,
        processed.descriptor.merkle_root,
        &recovered,
        processed.descriptor.blob_id.as_bytes(),
        BlobClass::Media,
    )
    .expect("verify_and_decrypt thumbnail");
    assert_eq!(decrypted, thumb.thumbnail_bytes);
}

#[test]
fn commit_blob_response_is_publicly_re_exported() {
    // Smoke check the public re-export so the integration test
    // catches accidental removals of a wire-format type.
    let resp = CommitBlobResponse {
        blob_id: "blob".to_string(),
        chunk_count: 1,
        merkle_root: [0; 32],
    };
    assert_eq!(resp.chunk_count, 1);
}
