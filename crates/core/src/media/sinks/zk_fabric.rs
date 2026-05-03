//! ZK Object Fabric media blob sink — Phase 3 wiring.
//!
//! `docs/PROPOSAL.md §5.7` (tiered media storage) routes media
//! originals to the user-cloud Tier 2; `docs/PROPOSAL.md §10.2`
//! pins the wire format for the ZKOF backend onto S3 PutObject /
//! GetObject / DeleteObject. Each chunk is one S3 object keyed
//! at:
//!
//! ```text
//! media/{asset_id}/chunk-{chunk_idx:08}
//! ```
//!
//! The sink is **transport-only** — encryption, Merkle hashing,
//! and key wrapping are the media engine's job. The sink hands
//! ciphertext bytes to S3 and reads them back verbatim.
//!
//! The Phase-3 wire-up keeps the sink behind a small
//! [`S3Client`] trait so the rest of the media pipeline can be
//! exercised against an in-memory fake. The real HTTP / SDK
//! client lands in a follow-up (the ZKOF crate at
//! `kennguy3n/zk-object-fabric` will provide a concrete
//! [`S3Client`] implementation).

use std::sync::Arc;

use super::{MediaBlobReference, MediaBlobSink};
use crate::crypto::aead::BlobClass;
use crate::Error;

/// Storage sink tag persisted to `media_asset.storage_sink` for
/// blobs handled by [`ZkObjectFabricSink`]. Pinned to the same
/// canonical value as
/// [`crate::config::StorageSink::ZkObjectFabric`].
pub const ZK_OBJECT_FABRIC_SINK_TAG: &str = "zk_object_fabric";

/// Object-safe S3 surface the ZKOF sink needs.
///
/// Trimmed down to the three operations the Phase-3 wire-up
/// actually issues:
///
/// * `put_object` — PutObject (multipart inside the impl when the
///   chunk exceeds the SDK's single-shot threshold).
/// * `get_object` — GetObject; the `range` parameter is the
///   inclusive byte range — `None` reads the whole object.
/// * `delete_object` — DeleteObject; idempotent per the eviction
///   pipeline contract on [`MediaBlobSink::delete_media_blob`].
///
/// The trait is `Send + Sync` so a single `Arc<dyn S3Client>` can
/// be shared across worker threads.
pub trait S3Client: Send + Sync + std::fmt::Debug {
    /// Upload `bytes` to `(bucket, key)` as a single S3 object.
    /// The caller hands a slice; the impl is free to chunk
    /// internally.
    fn put_object(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<(), Error>;

    /// Fetch the entire object at `(bucket, key)`.
    fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, Error>;

    /// Delete every object whose key starts with `key_prefix`.
    /// Used for the per-asset chunk fan-out: every
    /// `media/{asset_id}/chunk-*` lives under the asset prefix.
    fn delete_objects_with_prefix(&self, bucket: &str, key_prefix: &str) -> Result<(), Error>;
}

/// Stub `S3Client` returning [`Error::NotImplemented`] from every
/// method. The Phase-3 dispatch surface is exercised against this
/// stub so the sink wiring is testable without a real S3 round
/// trip.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopS3Client;

impl S3Client for NoopS3Client {
    fn put_object(&self, _bucket: &str, _key: &str, _bytes: &[u8]) -> Result<(), Error> {
        Err(Error::NotImplemented("NoopS3Client::put_object"))
    }

    fn get_object(&self, _bucket: &str, _key: &str) -> Result<Vec<u8>, Error> {
        Err(Error::NotImplemented("NoopS3Client::get_object"))
    }

    fn delete_objects_with_prefix(&self, _bucket: &str, _key_prefix: &str) -> Result<(), Error> {
        Err(Error::NotImplemented(
            "NoopS3Client::delete_objects_with_prefix",
        ))
    }
}

/// Per-asset key prefix: `media/{asset_id}/`.
fn asset_key_prefix(asset_id: &str) -> String {
    format!("media/{asset_id}/")
}

/// Per-chunk key: `media/{asset_id}/chunk-{idx:08}`.
fn chunk_key(asset_id: &str, chunk_idx: u32) -> String {
    format!("media/{asset_id}/chunk-{chunk_idx:08}")
}

/// Encode `(asset_id, chunk_count, expected_merkle_root)` into
/// the [`MediaBlobReference::sink_metadata`] field so the
/// rehydration path can re-derive the per-chunk keys without a
/// second database round-trip.
///
/// Layout — fixed 4-byte big-endian chunk count, followed by
/// the 32-byte ciphertext Merkle root, followed by the asset id
/// in UTF-8:
///
/// ```text
/// 0      4              36
/// ┌──────┬──────────────┬──────────────────────────────────┐
/// │chunks│ merkle_root  │ asset_id (utf-8)                 │
/// │  u32 │  [u8; 32]    │ variable                         │
/// └──────┴──────────────┴──────────────────────────────────┘
/// ```
fn encode_metadata(asset_id: &str, chunk_count: u32, merkle_root: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + asset_id.len());
    out.extend_from_slice(&chunk_count.to_be_bytes());
    out.extend_from_slice(&merkle_root);
    out.extend_from_slice(asset_id.as_bytes());
    out
}

fn decode_metadata(metadata: &[u8]) -> Result<(String, u32, [u8; 32]), Error> {
    if metadata.len() < 4 + 32 {
        return Err(Error::Storage(
            "ZkObjectFabricSink: sink_metadata too short".into(),
        ));
    }
    let mut chunk_count_bytes = [0u8; 4];
    chunk_count_bytes.copy_from_slice(&metadata[0..4]);
    let chunk_count = u32::from_be_bytes(chunk_count_bytes);

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&metadata[4..36]);

    let asset_id = std::str::from_utf8(&metadata[36..])
        .map_err(|_| Error::Storage("ZkObjectFabricSink: asset_id not valid UTF-8".into()))?
        .to_string();
    Ok((asset_id, chunk_count, merkle_root))
}

/// `MediaBlobSink` implementation routing through an
/// [`S3Client`].
#[derive(Debug, Clone)]
pub struct ZkObjectFabricSink {
    s3: Arc<dyn S3Client>,
    bucket: String,
}

impl ZkObjectFabricSink {
    /// Construct a sink that uploads / fetches / deletes against
    /// `bucket` through `s3`.
    pub fn new(s3: Arc<dyn S3Client>, bucket: impl Into<String>) -> Self {
        Self {
            s3,
            bucket: bucket.into(),
        }
    }

    /// Bucket name this sink targets. Surfaced for diagnostics
    /// and tests.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}

impl MediaBlobSink for ZkObjectFabricSink {
    fn upload_media_chunks(
        &self,
        asset_id: &str,
        _blob_class: BlobClass,
        chunks: &[&[u8]],
        expected_merkle_root: [u8; 32],
    ) -> crate::Result<MediaBlobReference> {
        let chunk_count = u32::try_from(chunks.len()).map_err(|_| {
            Error::Storage(format!(
                "ZkObjectFabricSink::upload_media_chunks: too many chunks ({})",
                chunks.len()
            ))
        })?;
        for (idx, bytes) in chunks.iter().enumerate() {
            let key = chunk_key(asset_id, idx as u32);
            self.s3.put_object(&self.bucket, &key, bytes)?;
        }
        Ok(MediaBlobReference {
            blob_id: asset_id.to_string(),
            storage_sink: ZK_OBJECT_FABRIC_SINK_TAG.to_string(),
            sink_metadata: Some(encode_metadata(asset_id, chunk_count, expected_merkle_root)),
        })
    }

    fn fetch_media_chunk(
        &self,
        blob_ref: &MediaBlobReference,
        chunk_idx: u32,
    ) -> crate::Result<Vec<u8>> {
        if blob_ref.storage_sink != ZK_OBJECT_FABRIC_SINK_TAG {
            return Err(Error::Storage(format!(
                "ZkObjectFabricSink::fetch_media_chunk: storage_sink mismatch {:?}",
                blob_ref.storage_sink
            )));
        }
        // Prefer the metadata-encoded asset id when present so
        // rehydration is a pure local-key derivation; fall back
        // to `blob_id` when no metadata is recorded.
        let asset_id = match &blob_ref.sink_metadata {
            Some(meta) => decode_metadata(meta)?.0,
            None => blob_ref.blob_id.clone(),
        };
        let key = chunk_key(&asset_id, chunk_idx);
        self.s3.get_object(&self.bucket, &key)
    }

    fn delete_media_blob(&self, blob_ref: &MediaBlobReference) -> crate::Result<()> {
        if blob_ref.storage_sink != ZK_OBJECT_FABRIC_SINK_TAG {
            return Err(Error::Storage(format!(
                "ZkObjectFabricSink::delete_media_blob: storage_sink mismatch {:?}",
                blob_ref.storage_sink
            )));
        }
        let asset_id = match &blob_ref.sink_metadata {
            Some(meta) => decode_metadata(meta)?.0,
            None => blob_ref.blob_id.clone(),
        };
        self.s3
            .delete_objects_with_prefix(&self.bucket, &asset_key_prefix(&asset_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory `S3Client` used by every test in this module.
    /// Stores objects as `BTreeMap<key, bytes>` keyed on the
    /// supplied bucket — every `(bucket, key)` pair is unique.
    #[derive(Debug, Default)]
    struct InMemoryS3 {
        objects: Mutex<BTreeMap<(String, String), Vec<u8>>>,
        // Counters surfaced for tests.
        puts: Mutex<u32>,
        gets: Mutex<u32>,
        deletes: Mutex<u32>,
    }

    impl S3Client for InMemoryS3 {
        fn put_object(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<(), Error> {
            *self.puts.lock().unwrap() += 1;
            self.objects
                .lock()
                .unwrap()
                .insert((bucket.to_string(), key.to_string()), bytes.to_vec());
            Ok(())
        }

        fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, Error> {
            *self.gets.lock().unwrap() += 1;
            self.objects
                .lock()
                .unwrap()
                .get(&(bucket.to_string(), key.to_string()))
                .cloned()
                .ok_or_else(|| {
                    Error::Storage(format!("InMemoryS3: no object at ({bucket}, {key})"))
                })
        }

        fn delete_objects_with_prefix(&self, bucket: &str, key_prefix: &str) -> Result<(), Error> {
            *self.deletes.lock().unwrap() += 1;
            let mut objects = self.objects.lock().unwrap();
            objects.retain(|(b, k), _| !(b == bucket && k.starts_with(key_prefix)));
            Ok(())
        }
    }

    fn fresh_sink() -> (ZkObjectFabricSink, Arc<InMemoryS3>) {
        let s3 = Arc::new(InMemoryS3::default());
        let sink = ZkObjectFabricSink::new(s3.clone(), "zk-bucket");
        (sink, s3)
    }

    #[test]
    fn upload_round_trips_per_chunk_keys() {
        let (sink, s3) = fresh_sink();
        let chunks: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i; 4]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let merkle = [0xAA; 32];
        let blob_ref = sink
            .upload_media_chunks("asset-7", BlobClass::Media, &chunk_refs, merkle)
            .expect("upload");
        assert_eq!(blob_ref.blob_id, "asset-7");
        assert_eq!(blob_ref.storage_sink, ZK_OBJECT_FABRIC_SINK_TAG);
        assert!(blob_ref.sink_metadata.is_some());
        assert_eq!(*s3.puts.lock().unwrap(), 3);

        // Each chunk landed at the canonical key.
        let objects = s3.objects.lock().unwrap();
        for i in 0..3 {
            let key = chunk_key("asset-7", i);
            let stored = objects
                .get(&("zk-bucket".to_string(), key))
                .expect("chunk uploaded");
            assert_eq!(stored.as_slice(), chunks[i as usize].as_slice());
        }
    }

    #[test]
    fn fetch_chunk_returns_uploaded_bytes() {
        let (sink, _s3) = fresh_sink();
        let chunks: Vec<Vec<u8>> = (0u8..2).map(|i| vec![i + 1; 8]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let blob_ref = sink
            .upload_media_chunks("asset-9", BlobClass::Media, &chunk_refs, [0xBB; 32])
            .unwrap();
        for (i, expected) in chunks.iter().enumerate() {
            let got = sink.fetch_media_chunk(&blob_ref, i as u32).unwrap();
            assert_eq!(&got, expected, "chunk {i} round-trip mismatch");
        }
    }

    #[test]
    fn delete_purges_every_chunk_for_asset() {
        let (sink, s3) = fresh_sink();
        let chunks: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 4]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let blob_ref = sink
            .upload_media_chunks("asset-d", BlobClass::Media, &chunk_refs, [0u8; 32])
            .unwrap();
        assert_eq!(s3.objects.lock().unwrap().len(), 4);
        sink.delete_media_blob(&blob_ref).unwrap();
        assert_eq!(s3.objects.lock().unwrap().len(), 0);
        assert_eq!(*s3.deletes.lock().unwrap(), 1);
    }

    #[test]
    fn delete_does_not_touch_other_assets() {
        let (sink, s3) = fresh_sink();
        let _ = sink
            .upload_media_chunks("asset-keep", BlobClass::Media, &[&[1, 2]], [0u8; 32])
            .unwrap();
        let blob_ref = sink
            .upload_media_chunks("asset-go", BlobClass::Media, &[&[9, 9]], [0u8; 32])
            .unwrap();
        assert_eq!(s3.objects.lock().unwrap().len(), 2);
        sink.delete_media_blob(&blob_ref).unwrap();
        let remaining = s3.objects.lock().unwrap();
        assert_eq!(remaining.len(), 1);
        assert!(remaining
            .keys()
            .any(|(_, k)| k == &chunk_key("asset-keep", 0)));
    }

    #[test]
    fn fetch_with_wrong_storage_sink_is_an_error() {
        let (sink, _s3) = fresh_sink();
        let blob_ref = MediaBlobReference {
            blob_id: "asset-x".into(),
            storage_sink: "i_cloud".into(),
            sink_metadata: None,
        };
        let err = sink.fetch_media_chunk(&blob_ref, 0).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("storage_sink mismatch"), "got {msg}"),
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn delete_with_wrong_storage_sink_is_an_error() {
        let (sink, _s3) = fresh_sink();
        let blob_ref = MediaBlobReference {
            blob_id: "asset-x".into(),
            storage_sink: "google_drive".into(),
            sink_metadata: None,
        };
        let err = sink.delete_media_blob(&blob_ref).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("storage_sink mismatch"), "got {msg}"),
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn metadata_round_trips_asset_id_chunk_count_and_merkle_root() {
        let merkle = [0xCD; 32];
        let meta = encode_metadata("asset-42", 7, merkle);
        let (asset_id, chunk_count, decoded_merkle) = decode_metadata(&meta).unwrap();
        assert_eq!(asset_id, "asset-42");
        assert_eq!(chunk_count, 7);
        assert_eq!(decoded_merkle, merkle);
    }

    #[test]
    fn decode_metadata_rejects_too_short_input() {
        let err = decode_metadata(&[0u8; 10]).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("too short"), "got {msg}"),
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn s3_error_propagates_through_upload() {
        #[derive(Debug)]
        struct FailingS3;
        impl S3Client for FailingS3 {
            fn put_object(&self, _: &str, _: &str, _: &[u8]) -> Result<(), Error> {
                Err(Error::Storage("simulated S3 outage".into()))
            }
            fn get_object(&self, _: &str, _: &str) -> Result<Vec<u8>, Error> {
                Err(Error::Storage("noop".into()))
            }
            fn delete_objects_with_prefix(&self, _: &str, _: &str) -> Result<(), Error> {
                Ok(())
            }
        }
        let sink = ZkObjectFabricSink::new(Arc::new(FailingS3), "zk-bucket");
        let err = sink
            .upload_media_chunks("asset", BlobClass::Media, &[&[1, 2, 3]], [0u8; 32])
            .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("simulated S3 outage"), "got {msg}"),
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn noop_s3_client_returns_not_implemented() {
        let stub = NoopS3Client;
        assert!(matches!(
            stub.put_object("b", "k", &[]).unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.get_object("b", "k").unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.delete_objects_with_prefix("b", "k").unwrap_err(),
            Error::NotImplemented(_)
        ));
    }

    #[test]
    fn sink_uses_configured_bucket() {
        let s3 = Arc::new(InMemoryS3::default());
        let sink = ZkObjectFabricSink::new(s3.clone(), "alt-bucket");
        assert_eq!(sink.bucket(), "alt-bucket");
        sink.upload_media_chunks("asset-b", BlobClass::Media, &[&[1]], [0u8; 32])
            .unwrap();
        let objects = s3.objects.lock().unwrap();
        assert!(
            objects.keys().all(|(b, _)| b == "alt-bucket"),
            "every put must land in the configured bucket"
        );
    }
}
