//! ZK Object Fabric media blob sink — Phase 3 wiring.
//!
//! `docs/PROPOSAL.md §5.7` (tiered media storage) routes media
//! originals to the user-cloud Tier 2; `docs/PROPOSAL.md §10.2`
//! pins the wire format for the ZKOF backend onto S3 PutObject /
//! GetObject (with `Range`) / DeleteObject. The chunks coming
//! into [`MediaBlobSink::upload_media_chunks`] are already
//! ciphertext under `K_asset` (per `docs/PROPOSAL.md §8`); the
//! sink concatenates them in chunk order and uploads them as a
//! **single** S3 object so the rehydration path can drive byte-
//! range GETs against deterministic offsets.
//!
//! Object key: `media/{asset_id}`.
//!
//! Byte-range computation for chunk fetch is identical to the
//! KChat-backend transport
//! ([`crate::media::download::DEFAULT_CHUNK_CIPHERTEXT_SIZE`])
//! — chunk `n` spans
//! `[n * DEFAULT_CHUNK_CIPHERTEXT_SIZE, (n + 1) * DEFAULT_CHUNK_CIPHERTEXT_SIZE)`.
//! The S3 endpoint is expected to clamp the trailing range
//! against the committed object length, matching the KChat
//! transport contract, so the (possibly shorter) last chunk
//! still fetches correctly with the same formula.
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

use std::ops::Range;
use std::sync::Arc;

use super::{MediaBlobReference, MediaBlobSink};
use crate::crypto::aead::BlobClass;
use crate::media::download::DEFAULT_CHUNK_CIPHERTEXT_SIZE;
use crate::Error;

/// Storage sink tag persisted to `media_asset.storage_sink` for
/// blobs handled by [`ZkObjectFabricSink`]. Pinned to the same
/// canonical value as
/// [`crate::config::StorageSink::ZkObjectFabric`].
pub const ZK_OBJECT_FABRIC_SINK_TAG: &str = "zk_object_fabric";

/// ZKOF tenant credentials and bucket a [`ZkObjectFabricSink`]
/// uploads against.
///
/// `docs/PROPOSAL.md §10.2` pins the routing contract: every ZKOF
/// tenant is keyed on `(endpoint_url, access_key, secret_key,
/// bucket)`. The sink does not interpret the credentials — it
/// hands them to the [`S3Client`] implementation which is
/// expected to sign requests with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkFabricSinkConfig {
    /// HTTPS endpoint URL of the ZKOF gateway, e.g.
    /// `https://zkof.example.com`. No trailing slash.
    pub endpoint_url: String,
    /// S3 access key id.
    pub access_key: String,
    /// S3 secret access key.
    pub secret_key: String,
    /// S3 bucket name. Must satisfy the S3 bucket-naming rules
    /// (3–63 chars, lowercase alphanumerics, dashes; no
    /// underscores).
    pub bucket: String,
}

impl ZkFabricSinkConfig {
    /// Reject configurations with empty fields, an obviously
    /// malformed bucket name, or an `endpoint_url` that does not
    /// start with `http://` or `https://`. Surface a single
    /// [`Error::Storage`] describing the first violation found.
    pub fn validate(&self) -> Result<(), Error> {
        if self.endpoint_url.is_empty() {
            return Err(Error::Storage(
                "ZkFabricSinkConfig: endpoint_url must not be empty".into(),
            ));
        }
        if !self.endpoint_url.starts_with("http://") && !self.endpoint_url.starts_with("https://") {
            return Err(Error::Storage(format!(
                "ZkFabricSinkConfig: endpoint_url must start with http:// or https:// (got {:?})",
                self.endpoint_url
            )));
        }
        if self.access_key.is_empty() {
            return Err(Error::Storage(
                "ZkFabricSinkConfig: access_key must not be empty".into(),
            ));
        }
        if self.secret_key.is_empty() {
            return Err(Error::Storage(
                "ZkFabricSinkConfig: secret_key must not be empty".into(),
            ));
        }
        if self.bucket.len() < 3 || self.bucket.len() > 63 {
            return Err(Error::Storage(format!(
                "ZkFabricSinkConfig: bucket must be 3..=63 chars (got {})",
                self.bucket.len()
            )));
        }
        if !self
            .bucket
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(Error::Storage(format!(
                "ZkFabricSinkConfig: bucket {:?} contains characters outside [a-z0-9-]",
                self.bucket
            )));
        }
        Ok(())
    }
}

/// Object-safe S3 surface the ZKOF sink needs.
///
/// Trimmed down to the three operations the Phase-3 wire-up
/// actually issues:
///
/// * `put_object` — `PutObject`. The impl is free to fall back
///   to multipart upload internally for blobs that exceed its
///   single-shot threshold; the sink hands one contiguous byte
///   slice and treats success as atomic.
/// * `get_object_range` — `GetObject` with an HTTP `Range:
///   bytes=start-end` header. The endpoint is expected to clamp
///   `end` against the actual object length, mirroring the KChat
///   transport contract.
/// * `delete_object` — `DeleteObject`. Must be idempotent: a
///   delete against an already-deleted (or never-existed) key
///   must succeed, since the eviction pipeline retries on
///   transient failure (see
///   [`MediaBlobSink::delete_media_blob`]).
///
/// The trait is `Send + Sync` so a single `Arc<dyn S3Client>` can
/// be shared across worker threads.
pub trait S3Client: Send + Sync + std::fmt::Debug {
    /// Upload `bytes` to `(bucket, key)` as a single S3 object.
    fn put_object(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<(), Error>;

    /// Fetch the bytes at `(bucket, key)` covered by `range`. The
    /// returned `Vec` may be shorter than `range.len()` if `range`
    /// extends past the object's end (S3 `Range:` clamping).
    fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        range: Range<u64>,
    ) -> Result<Vec<u8>, Error>;

    /// Idempotently delete `(bucket, key)`.
    fn delete_object(&self, bucket: &str, key: &str) -> Result<(), Error>;

    /// List every key under `prefix` in `bucket`. Used by the
    /// backup sink to enumerate manifest IDs at restore time.
    /// Defaults to [`Error::NotImplemented`] so existing
    /// media-sink implementations are not forced to implement
    /// listing — only the backup sink path requires it.
    fn list_objects(&self, _bucket: &str, _prefix: &str) -> Result<Vec<String>, Error> {
        Err(Error::NotImplemented("S3Client::list_objects"))
    }
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

    fn get_object_range(
        &self,
        _bucket: &str,
        _key: &str,
        _range: Range<u64>,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::NotImplemented("NoopS3Client::get_object_range"))
    }

    fn delete_object(&self, _bucket: &str, _key: &str) -> Result<(), Error> {
        Err(Error::NotImplemented("NoopS3Client::delete_object"))
    }
}

/// Per-asset object key: `media/{asset_id}`.
fn asset_key(asset_id: &str) -> String {
    format!("media/{asset_id}")
}

/// Encode `(asset_id, chunk_count, expected_merkle_root)` into
/// the [`MediaBlobReference::sink_metadata`] field so the
/// rehydration path can re-derive the byte ranges without a
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

/// Byte range covering chunk `chunk_idx` of a blob whose chunks
/// were sealed at [`crate::media::chunker::DEFAULT_CHUNK_SIZE`].
///
/// `[chunk_idx * DEFAULT_CHUNK_CIPHERTEXT_SIZE, (chunk_idx + 1) *
/// DEFAULT_CHUNK_CIPHERTEXT_SIZE)`. Mirrors
/// [`crate::media::download::chunk_range`] (which is private to
/// the download module).
fn chunk_range(chunk_idx: u32) -> Range<u64> {
    let start = (chunk_idx as u64) * (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
    let end = start + (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
    start..end
}

/// `MediaBlobSink` implementation routing through an
/// [`S3Client`] against a [`ZkFabricSinkConfig`].
#[derive(Debug, Clone)]
pub struct ZkObjectFabricSink {
    s3: Arc<dyn S3Client>,
    config: ZkFabricSinkConfig,
    /// Phase 7 (2026-05-04 batch 10 — Task 10) — optional
    /// dedup-analytics probe. When set, every successful
    /// `upload_media_chunks` records a
    /// [`crate::transport::dedup_analytics::DedupEvent::ObjectUploaded`]
    /// and every successful `delete_media_blob` records an
    /// [`crate::transport::dedup_analytics::DedupEvent::ObjectDeleted`].
    dedup_analytics: Option<Arc<dyn crate::transport::dedup_analytics::DedupAnalytics>>,
}

impl ZkObjectFabricSink {
    /// Construct a sink that uploads / fetches / deletes against
    /// `config.bucket` through `s3`. The config is validated
    /// before the sink is constructed so callers get an early
    /// failure on misconfigured tenants.
    pub fn new(s3: Arc<dyn S3Client>, config: ZkFabricSinkConfig) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            s3,
            config,
            dedup_analytics: None,
        })
    }

    /// Phase 7 (2026-05-04 batch 10 — Task 10): builder helper
    /// that attaches a dedup-analytics probe. Returns `self` for
    /// fluent construction.
    pub fn with_dedup_analytics(
        mut self,
        probe: Arc<dyn crate::transport::dedup_analytics::DedupAnalytics>,
    ) -> Self {
        self.dedup_analytics = Some(probe);
        self
    }

    /// Bucket name this sink targets.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Endpoint URL this sink targets.
    pub fn endpoint_url(&self) -> &str {
        &self.config.endpoint_url
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

        // Concatenate every chunk in order. The chunks are already
        // ciphertext under K_asset (the media engine sealed them
        // before handing them to the sink) so concatenating is
        // safe — the only invariant we have to preserve is the
        // chunk-index → byte-range mapping, which the upload-side
        // formula matches symmetrically with `chunk_range`.
        let total_size: usize = chunks.iter().map(|c| c.len()).sum();
        let mut blob = Vec::with_capacity(total_size);
        for chunk in chunks {
            blob.extend_from_slice(chunk);
        }

        let key = asset_key(asset_id);
        let blob_size = blob.len() as u64;
        self.s3.put_object(&self.config.bucket, &key, &blob)?;
        if let Some(probe) = self.dedup_analytics.as_ref() {
            let _ = probe.record_event(
                crate::transport::dedup_analytics::DedupEvent::ObjectUploaded {
                    size_bytes: blob_size,
                    was_deduped: false,
                },
            );
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
        let key = asset_key(&asset_id);
        let range = chunk_range(chunk_idx);
        self.s3.get_object_range(&self.config.bucket, &key, range)
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
            .delete_object(&self.config.bucket, &asset_key(&asset_id))?;
        if let Some(probe) = self.dedup_analytics.as_ref() {
            let _ = probe.record_event(
                crate::transport::dedup_analytics::DedupEvent::ObjectDeleted { size_bytes: 0 },
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn fresh_config() -> ZkFabricSinkConfig {
        ZkFabricSinkConfig {
            endpoint_url: "https://zkof.example.com".into(),
            access_key: "AKIA".into(),
            secret_key: "SECRET".into(),
            bucket: "zkof-test-bucket".into(),
        }
    }

    /// In-memory `S3Client` used by every test in this module.
    /// Stores objects as `BTreeMap<(bucket, key), bytes>` and
    /// supports byte-range reads (clamping past the object
    /// length, matching the production contract).
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

        fn get_object_range(
            &self,
            bucket: &str,
            key: &str,
            range: Range<u64>,
        ) -> Result<Vec<u8>, Error> {
            *self.gets.lock().unwrap() += 1;
            let objects = self.objects.lock().unwrap();
            let bytes = objects
                .get(&(bucket.to_string(), key.to_string()))
                .ok_or_else(|| {
                    Error::Storage(format!("InMemoryS3: no object at ({bucket}, {key})"))
                })?;
            let start = range.start as usize;
            let end = (range.end as usize).min(bytes.len());
            if start > end {
                return Ok(Vec::new());
            }
            Ok(bytes[start..end].to_vec())
        }

        fn delete_object(&self, bucket: &str, key: &str) -> Result<(), Error> {
            *self.deletes.lock().unwrap() += 1;
            // Idempotent: missing keys are not an error.
            self.objects
                .lock()
                .unwrap()
                .remove(&(bucket.to_string(), key.to_string()));
            Ok(())
        }
    }

    fn fresh_sink() -> (ZkObjectFabricSink, Arc<InMemoryS3>) {
        let s3 = Arc::new(InMemoryS3::default());
        let sink = ZkObjectFabricSink::new(s3.clone(), fresh_config()).expect("config valid");
        (sink, s3)
    }

    #[test]
    fn s3_client_trait_is_object_safe() {
        let _b: Box<dyn S3Client> = Box::new(NoopS3Client);
        let _a: Arc<dyn S3Client> = Arc::new(NoopS3Client);
    }

    #[test]
    fn config_validate_accepts_well_formed_config() {
        fresh_config().validate().expect("valid config");
    }

    #[test]
    fn config_validate_rejects_empty_endpoint() {
        let mut cfg = fresh_config();
        cfg.endpoint_url.clear();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("endpoint_url"));
    }

    #[test]
    fn config_validate_rejects_non_http_endpoint() {
        let mut cfg = fresh_config();
        cfg.endpoint_url = "ftp://zkof.example.com".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("http://"), "got {err}");
    }

    #[test]
    fn config_validate_rejects_short_bucket() {
        let mut cfg = fresh_config();
        cfg.bucket = "ab".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("bucket"));
    }

    #[test]
    fn config_validate_rejects_bucket_with_uppercase() {
        let mut cfg = fresh_config();
        cfg.bucket = "Bucket".into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("[a-z0-9-]"), "got {err}");
    }

    #[test]
    fn config_validate_rejects_empty_credentials() {
        let mut cfg = fresh_config();
        cfg.access_key.clear();
        assert!(cfg.validate().is_err());

        let mut cfg = fresh_config();
        cfg.secret_key.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn sink_constructor_rejects_invalid_config() {
        let s3 = Arc::new(InMemoryS3::default());
        let mut cfg = fresh_config();
        cfg.endpoint_url.clear();
        assert!(ZkObjectFabricSink::new(s3, cfg).is_err());
    }

    #[test]
    fn upload_writes_one_object_per_asset() {
        let (sink, s3) = fresh_sink();
        let chunks: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i + 1; 4]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let merkle = [0xAA; 32];
        let blob_ref = sink
            .upload_media_chunks("asset-7", BlobClass::Media, &chunk_refs, merkle)
            .expect("upload");
        assert_eq!(blob_ref.blob_id, "asset-7");
        assert_eq!(blob_ref.storage_sink, ZK_OBJECT_FABRIC_SINK_TAG);
        assert!(blob_ref.sink_metadata.is_some());
        // One PutObject per asset, regardless of chunk count.
        assert_eq!(*s3.puts.lock().unwrap(), 1);

        // The single object holds the concatenated chunk bytes
        // at the canonical key.
        let objects = s3.objects.lock().unwrap();
        let key = asset_key("asset-7");
        let stored = objects
            .get(&("zkof-test-bucket".to_string(), key))
            .expect("asset uploaded");
        assert_eq!(stored.len(), 12);
        assert_eq!(&stored[0..4], &[1, 1, 1, 1]);
        assert_eq!(&stored[4..8], &[2, 2, 2, 2]);
        assert_eq!(&stored[8..12], &[3, 3, 3, 3]);
    }

    #[test]
    fn fetch_chunk_returns_byte_range_aligned_slice() {
        // Make each chunk exactly DEFAULT_CHUNK_CIPHERTEXT_SIZE
        // bytes so the production formula's range produces full
        // chunks back. Use small synthetic chunks so the test
        // stays cheap.
        let stride = DEFAULT_CHUNK_CIPHERTEXT_SIZE;
        let chunk0 = vec![0x10u8; stride];
        let chunk1 = vec![0x20u8; stride];
        let trailing = vec![0x30u8; 8]; // short trailing chunk
        let chunks = [chunk0.as_slice(), chunk1.as_slice(), trailing.as_slice()];
        let (sink, _s3) = fresh_sink();
        let blob_ref = sink
            .upload_media_chunks("asset-bytes", BlobClass::Media, &chunks, [0; 32])
            .unwrap();

        let got0 = sink.fetch_media_chunk(&blob_ref, 0).unwrap();
        assert_eq!(got0.len(), stride);
        assert!(got0.iter().all(|b| *b == 0x10));

        let got1 = sink.fetch_media_chunk(&blob_ref, 1).unwrap();
        assert_eq!(got1.len(), stride);
        assert!(got1.iter().all(|b| *b == 0x20));

        // The trailing chunk fetches with the same formula but
        // the InMemoryS3 clamps the range against the object
        // length, matching production S3 `Range` semantics.
        let got2 = sink.fetch_media_chunk(&blob_ref, 2).unwrap();
        assert_eq!(got2.len(), 8);
        assert!(got2.iter().all(|b| *b == 0x30));
    }

    #[test]
    fn delete_purges_the_single_asset_object() {
        let (sink, s3) = fresh_sink();
        let chunks: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 4]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let blob_ref = sink
            .upload_media_chunks("asset-d", BlobClass::Media, &chunk_refs, [0u8; 32])
            .unwrap();
        assert_eq!(s3.objects.lock().unwrap().len(), 1);
        sink.delete_media_blob(&blob_ref).unwrap();
        assert_eq!(s3.objects.lock().unwrap().len(), 0);
        assert_eq!(*s3.deletes.lock().unwrap(), 1);
    }

    #[test]
    fn delete_is_idempotent() {
        let (sink, _s3) = fresh_sink();
        let blob_ref = sink
            .upload_media_chunks("asset-z", BlobClass::Media, &[&[1, 2]], [0u8; 32])
            .unwrap();
        // First delete succeeds.
        sink.delete_media_blob(&blob_ref).unwrap();
        // Second delete must also succeed (idempotent contract).
        sink.delete_media_blob(&blob_ref).unwrap();
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
        assert!(remaining.keys().any(|(_, k)| k == &asset_key("asset-keep")));
    }

    #[test]
    fn fetch_with_wrong_storage_sink_is_an_error() {
        let (sink, _s3) = fresh_sink();
        let blob_ref = MediaBlobReference {
            blob_id: "asset-x".into(),
            storage_sink: "icloud".into(),
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
            fn get_object_range(&self, _: &str, _: &str, _: Range<u64>) -> Result<Vec<u8>, Error> {
                Err(Error::Storage("noop".into()))
            }
            fn delete_object(&self, _: &str, _: &str) -> Result<(), Error> {
                Ok(())
            }
        }
        let sink = ZkObjectFabricSink::new(Arc::new(FailingS3), fresh_config()).unwrap();
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
            stub.get_object_range("b", "k", 0..1).unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.delete_object("b", "k").unwrap_err(),
            Error::NotImplemented(_)
        ));
    }

    #[test]
    fn sink_uses_configured_bucket_and_endpoint() {
        let s3 = Arc::new(InMemoryS3::default());
        let mut cfg = fresh_config();
        cfg.bucket = "alt-bucket".into();
        cfg.endpoint_url = "https://alt.zkof.example.com".into();
        let sink = ZkObjectFabricSink::new(s3.clone(), cfg).unwrap();
        assert_eq!(sink.bucket(), "alt-bucket");
        assert_eq!(sink.endpoint_url(), "https://alt.zkof.example.com");
        sink.upload_media_chunks("asset-b", BlobClass::Media, &[&[1]], [0u8; 32])
            .unwrap();
        let objects = s3.objects.lock().unwrap();
        assert!(
            objects.keys().all(|(b, _)| b == "alt-bucket"),
            "every put must land in the configured bucket"
        );
    }

    #[test]
    fn media_blob_sink_trait_object_round_trip() {
        // Confirm the sink can be used through `Arc<dyn
        // MediaBlobSink>` so the media engine can hold one.
        let (sink, _s3) = fresh_sink();
        let dyn_sink: Arc<dyn MediaBlobSink> = Arc::new(sink);
        let blob_ref = dyn_sink
            .upload_media_chunks("asset-trait", BlobClass::Media, &[&[7, 8, 9]], [0; 32])
            .unwrap();
        assert_eq!(blob_ref.storage_sink, ZK_OBJECT_FABRIC_SINK_TAG);
    }

    #[test]
    fn upload_media_chunks_records_dedup_event() {
        use crate::transport::dedup_analytics::DedupAnalytics;
        let s3 = Arc::new(InMemoryS3::default());
        let probe = Arc::new(crate::transport::dedup_analytics::InProcessDedupAnalytics::new());
        let sink = ZkObjectFabricSink::new(s3, fresh_config())
            .unwrap()
            .with_dedup_analytics(probe.clone());
        sink.upload_media_chunks(
            "asset-dedup",
            BlobClass::Media,
            &[&[1, 2, 3, 4, 5]],
            [0u8; 32],
        )
        .unwrap();
        let stats = probe.query_dedup_ratio("tenant-x").unwrap();
        assert_eq!(stats.total_objects, 1);
        assert_eq!(stats.total_bytes, 5);
        let recent = probe.recent_events();
        assert_eq!(recent.len(), 1);
        assert!(matches!(
            recent[0],
            crate::transport::dedup_analytics::DedupEvent::ObjectUploaded {
                size_bytes: 5,
                was_deduped: false
            }
        ));
    }
}
