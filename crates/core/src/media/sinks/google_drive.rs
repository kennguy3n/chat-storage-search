//! Google Drive media blob sink — Phase 3 wiring.
//!
//! `docs/PROPOSAL.md §5.7` (tiered media storage) routes media
//! originals to user-cloud Tier 2; `docs/PROPOSAL.md §10.2` pins
//! the Android / desktop routing contract onto the Drive API.
//! The actual Drive HTTP traffic lives on the Android (Java) /
//! desktop bridge side, so the sink is a thin routing layer that
//! delegates byte-level operations to a platform-bridge trait —
//! [`GoogleDriveBridge`] — that the bridge crates implement.
//!
//! Drive file id = the asset id at upload time; the bridge
//! returns the canonical Drive file id (which may differ if the
//! Drive backend assigns its own) and the sink stores it in
//! [`MediaBlobReference::sink_metadata`].
//!
//! Byte-range computation for chunk fetch is identical to the
//! KChat-backend transport
//! ([`crate::media::download::DEFAULT_CHUNK_CIPHERTEXT_SIZE`])
//! — chunk `n` spans
//! `[n * DEFAULT_CHUNK_CIPHERTEXT_SIZE, (n + 1) *
//! DEFAULT_CHUNK_CIPHERTEXT_SIZE)`. The bridge is expected to
//! clamp the trailing range against the committed object length
//! so the (possibly shorter) last chunk fetches correctly with
//! the same formula.
//!
//! The sink is **transport-only** — encryption, Merkle hashing,
//! and key wrapping are the media engine's job. The sink hands
//! ciphertext bytes to the bridge and reads them back verbatim.

use std::ops::Range;
use std::sync::Arc;

use super::{MediaBlobReference, MediaBlobSink};
use crate::crypto::aead::BlobClass;
use crate::media::download::DEFAULT_CHUNK_CIPHERTEXT_SIZE;
use crate::Error;

/// Storage sink tag persisted to `media_asset.storage_sink` for
/// blobs handled by [`GoogleDriveMediaBlobSink`]. Pinned to the
/// same canonical value as
/// [`crate::config::StorageSink::GoogleDrive`].
pub const GOOGLE_DRIVE_SINK_TAG: &str = "google_drive";

/// Object-safe platform bridge for Google Drive file storage.
/// The Android / desktop bridge crates provide the concrete
/// implementations; the Rust core only sees a trait object.
///
/// All methods are byte-level: the bridge sees ciphertext only.
pub trait GoogleDriveBridge: Send + Sync + std::fmt::Debug {
    /// Upload `bytes` as a single Drive file under the configured
    /// folder. The bridge passes `asset_id` as a hint for the
    /// file name; the returned string is the canonical Drive
    /// file id. The sink stores this id in
    /// [`MediaBlobReference::sink_metadata`] so the rehydration
    /// path can drive subsequent fetches against it.
    fn upload_file(&self, asset_id: &str, bytes: &[u8]) -> Result<String, Error>;

    /// Fetch the byte range `[start, end)` of the Drive file with
    /// id `file_id`. The returned `Vec` may be shorter than
    /// `range.len()` if `range` extends past the file's end.
    fn download_file_range(&self, file_id: &str, range: Range<u64>) -> Result<Vec<u8>, Error>;

    /// Idempotently delete the Drive file with id `file_id`. A
    /// delete against an already-deleted (or never-existed) file
    /// must succeed, matching the eviction pipeline's retry
    /// contract.
    fn delete_file(&self, file_id: &str) -> Result<(), Error>;
}

/// Stub `GoogleDriveBridge` returning [`Error::NotImplemented`]
/// from every method. Used as a Phase-3 placeholder until the
/// Android / desktop bridges land.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopGoogleDriveBridge;

impl GoogleDriveBridge for NoopGoogleDriveBridge {
    fn upload_file(&self, _asset_id: &str, _bytes: &[u8]) -> Result<String, Error> {
        Err(Error::NotImplemented("NoopGoogleDriveBridge::upload_file"))
    }

    fn download_file_range(&self, _file_id: &str, _range: Range<u64>) -> Result<Vec<u8>, Error> {
        Err(Error::NotImplemented(
            "NoopGoogleDriveBridge::download_file_range",
        ))
    }

    fn delete_file(&self, _file_id: &str) -> Result<(), Error> {
        Err(Error::NotImplemented("NoopGoogleDriveBridge::delete_file"))
    }
}

/// Encode `(drive_file_id, chunk_count, expected_merkle_root)`
/// into the [`MediaBlobReference::sink_metadata`] field so the
/// rehydration path can re-derive the byte ranges and locate the
/// Drive file id without a second database round-trip.
///
/// Layout — fixed 4-byte big-endian chunk count, followed by the
/// 32-byte ciphertext Merkle root, followed by the Drive file id
/// in UTF-8.
fn encode_metadata(drive_file_id: &str, chunk_count: u32, merkle_root: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + drive_file_id.len());
    out.extend_from_slice(&chunk_count.to_be_bytes());
    out.extend_from_slice(&merkle_root);
    out.extend_from_slice(drive_file_id.as_bytes());
    out
}

fn decode_metadata(metadata: &[u8]) -> Result<(String, u32, [u8; 32]), Error> {
    if metadata.len() < 4 + 32 {
        return Err(Error::Storage(
            "GoogleDriveMediaBlobSink: sink_metadata too short".into(),
        ));
    }
    let mut chunk_count_bytes = [0u8; 4];
    chunk_count_bytes.copy_from_slice(&metadata[0..4]);
    let chunk_count = u32::from_be_bytes(chunk_count_bytes);

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&metadata[4..36]);

    let drive_file_id = std::str::from_utf8(&metadata[36..])
        .map_err(|_| {
            Error::Storage("GoogleDriveMediaBlobSink: drive_file_id not valid UTF-8".into())
        })?
        .to_string();
    Ok((drive_file_id, chunk_count, merkle_root))
}

fn chunk_range(chunk_idx: u32) -> Range<u64> {
    let start = (chunk_idx as u64) * (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
    let end = start + (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
    start..end
}

/// `MediaBlobSink` implementation routing through a
/// [`GoogleDriveBridge`].
#[derive(Debug, Clone)]
pub struct GoogleDriveMediaBlobSink {
    bridge: Arc<dyn GoogleDriveBridge>,
}

impl GoogleDriveMediaBlobSink {
    /// Construct a sink that delegates byte-level operations to
    /// `bridge`.
    pub fn new(bridge: Arc<dyn GoogleDriveBridge>) -> Self {
        Self { bridge }
    }
}

impl MediaBlobSink for GoogleDriveMediaBlobSink {
    fn upload_media_chunks(
        &self,
        asset_id: &str,
        _blob_class: BlobClass,
        chunks: &[&[u8]],
        expected_merkle_root: [u8; 32],
    ) -> crate::Result<MediaBlobReference> {
        let chunk_count = u32::try_from(chunks.len()).map_err(|_| {
            Error::Storage(
                format!(
                    "GoogleDriveMediaBlobSink::upload_media_chunks: too many chunks ({})",
                    chunks.len()
                )
                .into(),
            )
        })?;

        let total_size: usize = chunks.iter().map(|c| c.len()).sum();
        let mut blob = Vec::with_capacity(total_size);
        for chunk in chunks {
            blob.extend_from_slice(chunk);
        }

        let drive_file_id = self.bridge.upload_file(asset_id, &blob)?;

        Ok(MediaBlobReference {
            blob_id: asset_id.to_string(),
            storage_sink: GOOGLE_DRIVE_SINK_TAG.to_string(),
            sink_metadata: Some(encode_metadata(
                &drive_file_id,
                chunk_count,
                expected_merkle_root,
            )),
        })
    }

    fn fetch_media_chunk(
        &self,
        blob_ref: &MediaBlobReference,
        chunk_idx: u32,
    ) -> crate::Result<Vec<u8>> {
        if blob_ref.storage_sink != GOOGLE_DRIVE_SINK_TAG {
            return Err(Error::Storage(
                format!(
                    "GoogleDriveMediaBlobSink::fetch_media_chunk: storage_sink mismatch {:?}",
                    blob_ref.storage_sink
                )
                .into(),
            ));
        }
        let drive_file_id = match &blob_ref.sink_metadata {
            Some(meta) => decode_metadata(meta)?.0,
            None => blob_ref.blob_id.clone(),
        };
        self.bridge
            .download_file_range(&drive_file_id, chunk_range(chunk_idx))
    }

    fn delete_media_blob(&self, blob_ref: &MediaBlobReference) -> crate::Result<()> {
        if blob_ref.storage_sink != GOOGLE_DRIVE_SINK_TAG {
            return Err(Error::Storage(
                format!(
                    "GoogleDriveMediaBlobSink::delete_media_blob: storage_sink mismatch {:?}",
                    blob_ref.storage_sink
                )
                .into(),
            ));
        }
        let drive_file_id = match &blob_ref.sink_metadata {
            Some(meta) => decode_metadata(meta)?.0,
            None => blob_ref.blob_id.clone(),
        };
        self.bridge.delete_file(&drive_file_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory `GoogleDriveBridge` used by every test in this
    /// module. Stores blobs in a `BTreeMap<file_id, bytes>` and
    /// supports byte-range reads (clamping past the object
    /// length, matching the production contract).
    #[derive(Debug, Default)]
    struct InMemoryBridge {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        next_id: Mutex<u32>,
        uploads: Mutex<u32>,
        downloads: Mutex<u32>,
        deletes: Mutex<u32>,
    }

    impl GoogleDriveBridge for InMemoryBridge {
        fn upload_file(&self, _asset_id: &str, bytes: &[u8]) -> Result<String, Error> {
            *self.uploads.lock().unwrap() += 1;
            // Simulate Drive assigning a server-side file id that
            // is *not* the same as the asset id, so the round-trip
            // tests assert the metadata writer + reader path
            // genuinely carries the bridge-assigned id rather than
            // shadowing it from `blob_id`.
            let mut next = self.next_id.lock().unwrap();
            *next += 1;
            let file_id = format!("drive-file-{}", *next);
            self.objects
                .lock()
                .unwrap()
                .insert(file_id.clone(), bytes.to_vec());
            Ok(file_id)
        }

        fn download_file_range(&self, file_id: &str, range: Range<u64>) -> Result<Vec<u8>, Error> {
            *self.downloads.lock().unwrap() += 1;
            let objects = self.objects.lock().unwrap();
            let bytes = objects.get(file_id).ok_or_else(|| {
                Error::Storage(format!("InMemoryBridge: no file {file_id}").into())
            })?;
            let start = range.start as usize;
            let end = (range.end as usize).min(bytes.len());
            if start > end {
                return Ok(Vec::new());
            }
            Ok(bytes[start..end].to_vec())
        }

        fn delete_file(&self, file_id: &str) -> Result<(), Error> {
            *self.deletes.lock().unwrap() += 1;
            self.objects.lock().unwrap().remove(file_id);
            Ok(())
        }
    }

    fn fresh_sink() -> (GoogleDriveMediaBlobSink, Arc<InMemoryBridge>) {
        let bridge = Arc::new(InMemoryBridge::default());
        let sink = GoogleDriveMediaBlobSink::new(bridge.clone());
        (sink, bridge)
    }

    #[test]
    fn google_drive_bridge_trait_is_object_safe() {
        let _b: Box<dyn GoogleDriveBridge> = Box::new(NoopGoogleDriveBridge);
        let _a: Arc<dyn GoogleDriveBridge> = Arc::new(NoopGoogleDriveBridge);
    }

    #[test]
    fn media_blob_sink_trait_is_object_safe() {
        let (sink, _bridge) = fresh_sink();
        let _dyn_sink: Arc<dyn MediaBlobSink> = Arc::new(sink);
    }

    #[test]
    fn noop_bridge_returns_not_implemented_for_every_method() {
        let stub = NoopGoogleDriveBridge;
        assert!(matches!(
            stub.upload_file("asset", &[]).unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.download_file_range("file", 0..1).unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.delete_file("file").unwrap_err(),
            Error::NotImplemented(_)
        ));
    }

    #[test]
    fn upload_writes_one_drive_file_per_asset_and_carries_assigned_file_id() {
        let (sink, bridge) = fresh_sink();
        let chunks: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i + 1; 4]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let merkle = [0xAB; 32];
        let blob_ref = sink
            .upload_media_chunks("asset-1", BlobClass::Media, &chunk_refs, merkle)
            .expect("upload");
        assert_eq!(blob_ref.blob_id, "asset-1");
        assert_eq!(blob_ref.storage_sink, GOOGLE_DRIVE_SINK_TAG);
        let meta = blob_ref.sink_metadata.as_ref().expect("metadata recorded");
        let (file_id, chunk_count, decoded_merkle) = decode_metadata(meta).unwrap();
        assert_eq!(chunk_count, 3);
        assert_eq!(decoded_merkle, merkle);
        // Drive-assigned id starts with "drive-file-" and is *not*
        // the asset id verbatim.
        assert!(file_id.starts_with("drive-file-"), "got {file_id}");
        assert_eq!(*bridge.uploads.lock().unwrap(), 1);
    }

    #[test]
    fn round_trip_via_bridge_returns_uploaded_bytes() {
        let stride = DEFAULT_CHUNK_CIPHERTEXT_SIZE;
        let chunk0 = vec![0x10u8; stride];
        let chunk1 = vec![0x20u8; stride];
        let trailing = vec![0x30u8; 8];
        let (sink, _bridge) = fresh_sink();
        let blob_ref = sink
            .upload_media_chunks(
                "asset-bytes",
                BlobClass::Media,
                &[chunk0.as_slice(), chunk1.as_slice(), trailing.as_slice()],
                [0; 32],
            )
            .unwrap();

        let got0 = sink.fetch_media_chunk(&blob_ref, 0).unwrap();
        assert_eq!(got0.len(), stride);
        assert!(got0.iter().all(|b| *b == 0x10));

        let got1 = sink.fetch_media_chunk(&blob_ref, 1).unwrap();
        assert_eq!(got1.len(), stride);
        assert!(got1.iter().all(|b| *b == 0x20));

        let got2 = sink.fetch_media_chunk(&blob_ref, 2).unwrap();
        assert_eq!(got2.len(), 8);
        assert!(got2.iter().all(|b| *b == 0x30));
    }

    #[test]
    fn delete_purges_drive_file_idempotently() {
        let (sink, bridge) = fresh_sink();
        let blob_ref = sink
            .upload_media_chunks("asset-del", BlobClass::Media, &[&[1, 2]], [0u8; 32])
            .unwrap();
        sink.delete_media_blob(&blob_ref).unwrap();
        sink.delete_media_blob(&blob_ref).unwrap();
        assert_eq!(*bridge.deletes.lock().unwrap(), 2);
        assert!(bridge.objects.lock().unwrap().is_empty());
    }

    #[test]
    fn fetch_with_wrong_storage_sink_is_an_error() {
        let (sink, _bridge) = fresh_sink();
        let blob_ref = MediaBlobReference {
            blob_id: "asset-x".into(),
            storage_sink: "icloud".into(),
            sink_metadata: None,
        };
        let err = sink.fetch_media_chunk(&blob_ref, 0).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(
                msg.to_string().contains("storage_sink mismatch"),
                "got {msg}"
            ),
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn delete_with_wrong_storage_sink_is_an_error() {
        let (sink, _bridge) = fresh_sink();
        let blob_ref = MediaBlobReference {
            blob_id: "asset-x".into(),
            storage_sink: "kchat_backend".into(),
            sink_metadata: None,
        };
        let err = sink.delete_media_blob(&blob_ref).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(
                msg.to_string().contains("storage_sink mismatch"),
                "got {msg}"
            ),
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn metadata_round_trips_drive_file_id_chunk_count_and_merkle_root() {
        let merkle = [0xCD; 32];
        let meta = encode_metadata("drive-file-42", 7, merkle);
        let (drive_file_id, chunk_count, decoded_merkle) = decode_metadata(&meta).unwrap();
        assert_eq!(drive_file_id, "drive-file-42");
        assert_eq!(chunk_count, 7);
        assert_eq!(decoded_merkle, merkle);
    }

    #[test]
    fn decode_metadata_rejects_too_short_input() {
        let err = decode_metadata(&[0u8; 10]).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.to_string().contains("too short"), "got {msg}"),
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn bridge_error_propagates_through_upload() {
        #[derive(Debug)]
        struct FailingBridge;
        impl GoogleDriveBridge for FailingBridge {
            fn upload_file(&self, _: &str, _: &[u8]) -> Result<String, Error> {
                Err(Error::Storage("simulated Drive outage".into()))
            }
            fn download_file_range(&self, _: &str, _: Range<u64>) -> Result<Vec<u8>, Error> {
                Err(Error::Storage("noop".into()))
            }
            fn delete_file(&self, _: &str) -> Result<(), Error> {
                Ok(())
            }
        }
        let sink = GoogleDriveMediaBlobSink::new(Arc::new(FailingBridge));
        let err = sink
            .upload_media_chunks("asset", BlobClass::Media, &[&[1, 2, 3]], [0u8; 32])
            .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(
                msg.to_string().contains("simulated Drive outage"),
                "got {msg}"
            ),
            other => panic!("expected Storage, got {other:?}"),
        }
    }
}
