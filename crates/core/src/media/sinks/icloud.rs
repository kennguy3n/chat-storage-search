//! iCloud media blob sink — wiring.
//!
//! `docs/DESIGN.md §5.7` (tiered media storage) routes media
//! originals to user-cloud Tier 2; `docs/DESIGN.md §10.2` pins
//! the iOS / macOS routing contract onto CloudKit's file-storage
//! API. The actual CloudKit traffic lives on the Swift side
//! (CloudKit is not available from Rust), so the sink is a thin
//! routing layer that delegates byte-level operations to a
//! platform-bridge trait — [`ICloudBlobBridge`] — that the iOS /
//! macOS bridge crate implements.
//!
//! CloudKit record name = the asset id (string). The bridge is
//! free to choose any zone / database it likes; the sink does
//! not interpret the metadata it returns.
//!
//! Byte-range computation for chunk fetch is identical to the
//! KChat-backend transport
//! ([`crate::media::download::DEFAULT_CHUNK_CIPHERTEXT_SIZE`])
//! chunk `n` spans
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
/// blobs handled by [`ICloudMediaBlobSink`]. Pinned to the same
/// canonical value as
/// [`crate::config::StorageSink::ICloud`].
pub const ICLOUD_SINK_TAG: &str = "icloud";

/// Object-safe platform bridge for iCloud (CloudKit) file
/// storage. The iOS / macOS bridge crate provides the concrete
/// implementation; the Rust core only sees a trait object.
///
/// All methods are byte-level: the bridge sees ciphertext only.
pub trait ICloudBlobBridge: Send + Sync + std::fmt::Debug {
    /// Upload `bytes` as a single CloudKit asset keyed by
    /// `record_name`. Returns the CloudKit record name (or
    /// equivalent identifier) the bridge ended up using; the
    /// sink writes this string into
    /// [`MediaBlobReference::sink_metadata`] so the rehydration
    /// path can drive subsequent fetches against the same
    /// record.
    fn upload_file(&self, record_name: &str, bytes: &[u8]) -> Result<String, Error>;

    /// Fetch the byte range `[start, end)` of the CloudKit asset
    /// keyed by `record_name`. The returned `Vec` may be shorter
    /// than `range.len()` if `range` extends past the asset's
    /// end (matching the KChat transport's clamping contract).
    fn download_file_range(&self, record_name: &str, range: Range<u64>) -> Result<Vec<u8>, Error>;

    /// Idempotently delete the CloudKit asset keyed by
    /// `record_name`. A delete against an already-deleted (or
    /// never-existed) record must succeed, matching the eviction
    /// pipeline's retry contract.
    fn delete_file(&self, record_name: &str) -> Result<(), Error>;
}

/// Stub `ICloudBlobBridge` returning [`Error::NotImplemented`]
/// from every method. Used as a placeholder until the
/// iOS / macOS bridge lands.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopICloudBridge;

impl ICloudBlobBridge for NoopICloudBridge {
    fn upload_file(&self, _record_name: &str, _bytes: &[u8]) -> Result<String, Error> {
        Err(Error::NotImplemented("NoopICloudBridge::upload_file"))
    }

    fn download_file_range(
        &self,
        _record_name: &str,
        _range: Range<u64>,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::NotImplemented(
            "NoopICloudBridge::download_file_range",
        ))
    }

    fn delete_file(&self, _record_name: &str) -> Result<(), Error> {
        Err(Error::NotImplemented("NoopICloudBridge::delete_file"))
    }
}

/// Encode `(record_name, chunk_count, expected_merkle_root)`
/// into the [`MediaBlobReference::sink_metadata`] field so the
/// rehydration path can re-derive the byte ranges and locate the
/// CloudKit record without a second database round-trip.
///
/// Layout — fixed 4-byte big-endian chunk count, followed by the
/// 32-byte ciphertext Merkle root, followed by the CloudKit
/// record name in UTF-8.
fn encode_metadata(record_name: &str, chunk_count: u32, merkle_root: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + record_name.len());
    out.extend_from_slice(&chunk_count.to_be_bytes());
    out.extend_from_slice(&merkle_root);
    out.extend_from_slice(record_name.as_bytes());
    out
}

fn decode_metadata(metadata: &[u8]) -> Result<(String, u32, [u8; 32]), Error> {
    if metadata.len() < 4 + 32 {
        return Err(Error::Storage(
            "ICloudMediaBlobSink: sink_metadata too short".into(),
        ));
    }
    let mut chunk_count_bytes = [0u8; 4];
    chunk_count_bytes.copy_from_slice(&metadata[0..4]);
    let chunk_count = u32::from_be_bytes(chunk_count_bytes);

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&metadata[4..36]);

    let record_name = std::str::from_utf8(&metadata[36..])
        .map_err(|_| Error::Storage("ICloudMediaBlobSink: record_name not valid UTF-8".into()))?
        .to_string();
    Ok((record_name, chunk_count, merkle_root))
}

fn chunk_range(chunk_idx: u32) -> Range<u64> {
    let start = (chunk_idx as u64) * (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
    let end = start + (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
    start..end
}

/// `MediaBlobSink` implementation routing through an
/// [`ICloudBlobBridge`].
#[derive(Debug, Clone)]
pub struct ICloudMediaBlobSink {
    bridge: Arc<dyn ICloudBlobBridge>,
}

impl ICloudMediaBlobSink {
    /// Construct a sink that delegates byte-level operations to
    /// `bridge`.
    pub fn new(bridge: Arc<dyn ICloudBlobBridge>) -> Self {
        Self { bridge }
    }
}

impl MediaBlobSink for ICloudMediaBlobSink {
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
                    "ICloudMediaBlobSink::upload_media_chunks: too many chunks ({})",
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

        let record_name = self.bridge.upload_file(asset_id, &blob)?;

        Ok(MediaBlobReference {
            blob_id: asset_id.to_string(),
            storage_sink: ICLOUD_SINK_TAG.to_string(),
            sink_metadata: Some(encode_metadata(
                &record_name,
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
        if blob_ref.storage_sink != ICLOUD_SINK_TAG {
            return Err(Error::Storage(
                format!(
                    "ICloudMediaBlobSink::fetch_media_chunk: storage_sink mismatch {:?}",
                    blob_ref.storage_sink
                )
                .into(),
            ));
        }
        let record_name = match &blob_ref.sink_metadata {
            Some(meta) => decode_metadata(meta)?.0,
            None => blob_ref.blob_id.clone(),
        };
        self.bridge
            .download_file_range(&record_name, chunk_range(chunk_idx))
    }

    fn delete_media_blob(&self, blob_ref: &MediaBlobReference) -> crate::Result<()> {
        if blob_ref.storage_sink != ICLOUD_SINK_TAG {
            return Err(Error::Storage(
                format!(
                    "ICloudMediaBlobSink::delete_media_blob: storage_sink mismatch {:?}",
                    blob_ref.storage_sink
                )
                .into(),
            ));
        }
        let record_name = match &blob_ref.sink_metadata {
            Some(meta) => decode_metadata(meta)?.0,
            None => blob_ref.blob_id.clone(),
        };
        self.bridge.delete_file(&record_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory `ICloudBlobBridge` used by every test in this
    /// module. Stores blobs in a `BTreeMap<record_name, bytes>`
    /// and supports byte-range reads (clamping past the object
    /// length, matching the production contract).
    #[derive(Debug, Default)]
    struct InMemoryBridge {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        uploads: Mutex<u32>,
        downloads: Mutex<u32>,
        deletes: Mutex<u32>,
    }

    impl ICloudBlobBridge for InMemoryBridge {
        fn upload_file(&self, record_name: &str, bytes: &[u8]) -> Result<String, Error> {
            *self.uploads.lock().unwrap() += 1;
            self.objects
                .lock()
                .unwrap()
                .insert(record_name.to_string(), bytes.to_vec());
            // Echo back the record name verbatim so the round-trip
            // tests can assert end-to-end that the metadata writer
            // and reader agree.
            Ok(record_name.to_string())
        }

        fn download_file_range(
            &self,
            record_name: &str,
            range: Range<u64>,
        ) -> Result<Vec<u8>, Error> {
            *self.downloads.lock().unwrap() += 1;
            let objects = self.objects.lock().unwrap();
            let bytes = objects.get(record_name).ok_or_else(|| {
                Error::Storage(format!("InMemoryBridge: no record {record_name}").into())
            })?;
            let start = range.start as usize;
            let end = (range.end as usize).min(bytes.len());
            if start > end {
                return Ok(Vec::new());
            }
            Ok(bytes[start..end].to_vec())
        }

        fn delete_file(&self, record_name: &str) -> Result<(), Error> {
            *self.deletes.lock().unwrap() += 1;
            // Idempotent: missing keys are not an error.
            self.objects.lock().unwrap().remove(record_name);
            Ok(())
        }
    }

    fn fresh_sink() -> (ICloudMediaBlobSink, Arc<InMemoryBridge>) {
        let bridge = Arc::new(InMemoryBridge::default());
        let sink = ICloudMediaBlobSink::new(bridge.clone());
        (sink, bridge)
    }

    #[test]
    fn icloud_blob_bridge_trait_is_object_safe() {
        let _b: Box<dyn ICloudBlobBridge> = Box::new(NoopICloudBridge);
        let _a: Arc<dyn ICloudBlobBridge> = Arc::new(NoopICloudBridge);
    }

    #[test]
    fn media_blob_sink_trait_is_object_safe() {
        let (sink, _bridge) = fresh_sink();
        let _dyn_sink: Arc<dyn MediaBlobSink> = Arc::new(sink);
    }

    #[test]
    fn noop_bridge_returns_not_implemented_for_every_method() {
        let stub = NoopICloudBridge;
        assert!(matches!(
            stub.upload_file("rec", &[]).unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.download_file_range("rec", 0..1).unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.delete_file("rec").unwrap_err(),
            Error::NotImplemented(_)
        ));
    }

    #[test]
    fn upload_writes_one_object_per_asset() {
        let (sink, bridge) = fresh_sink();
        let chunks: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i + 1; 4]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let merkle = [0xAB; 32];
        let blob_ref = sink
            .upload_media_chunks("asset-7", BlobClass::Media, &chunk_refs, merkle)
            .expect("upload");
        assert_eq!(blob_ref.blob_id, "asset-7");
        assert_eq!(blob_ref.storage_sink, ICLOUD_SINK_TAG);
        assert!(blob_ref.sink_metadata.is_some());
        // One CloudKit record per asset, regardless of chunk count.
        assert_eq!(*bridge.uploads.lock().unwrap(), 1);

        let objects = bridge.objects.lock().unwrap();
        let stored = objects.get("asset-7").expect("record uploaded");
        assert_eq!(stored.len(), 12);
        assert_eq!(&stored[0..4], &[1, 1, 1, 1]);
        assert_eq!(&stored[4..8], &[2, 2, 2, 2]);
        assert_eq!(&stored[8..12], &[3, 3, 3, 3]);
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
    fn delete_purges_record_idempotently() {
        let (sink, bridge) = fresh_sink();
        let blob_ref = sink
            .upload_media_chunks("asset-del", BlobClass::Media, &[&[1, 2]], [0u8; 32])
            .unwrap();
        sink.delete_media_blob(&blob_ref).unwrap();
        // Idempotent second call must succeed.
        sink.delete_media_blob(&blob_ref).unwrap();
        assert_eq!(*bridge.deletes.lock().unwrap(), 2);
        assert!(bridge.objects.lock().unwrap().is_empty());
    }

    #[test]
    fn fetch_with_wrong_storage_sink_is_an_error() {
        let (sink, _bridge) = fresh_sink();
        let blob_ref = MediaBlobReference {
            blob_id: "asset-x".into(),
            storage_sink: "google_drive".into(),
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
    fn metadata_round_trips_record_name_chunk_count_and_merkle_root() {
        let merkle = [0xCD; 32];
        let meta = encode_metadata("rec-42", 7, merkle);
        let (rec, chunk_count, decoded_merkle) = decode_metadata(&meta).unwrap();
        assert_eq!(rec, "rec-42");
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
        impl ICloudBlobBridge for FailingBridge {
            fn upload_file(&self, _: &str, _: &[u8]) -> Result<String, Error> {
                Err(Error::Storage("simulated CloudKit outage".into()))
            }
            fn download_file_range(&self, _: &str, _: Range<u64>) -> Result<Vec<u8>, Error> {
                Err(Error::Storage("noop".into()))
            }
            fn delete_file(&self, _: &str) -> Result<(), Error> {
                Ok(())
            }
        }
        let sink = ICloudMediaBlobSink::new(Arc::new(FailingBridge));
        let err = sink
            .upload_media_chunks("asset", BlobClass::Media, &[&[1, 2, 3]], [0u8; 32])
            .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(
                msg.to_string().contains("simulated CloudKit outage"),
                "got {msg}"
            ),
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn noop_bridge_round_trip_through_sink_surfaces_not_implemented() {
        // An `ICloudMediaBlobSink` wrapping the `NoopICloudBridge`
        // must surface `Error::NotImplemented` from every method
        // on the public sink trait.
        let sink = ICloudMediaBlobSink::new(Arc::new(NoopICloudBridge));
        assert!(matches!(
            sink.upload_media_chunks("a", BlobClass::Media, &[&[]], [0u8; 32])
                .unwrap_err(),
            Error::NotImplemented(_)
        ));
    }
}
