//! Media upload / download routing between the KChat backend and an
//! optional [`MediaBlobSink`] (`docs/PROPOSAL.md §5.7`).
//!
//! Tiered media storage:
//!
//! * **Tier 0 — KChat backend** (always): thumbnails, key wraps,
//!   media descriptors, archive segments, search index shards.
//! * **Tier 2 — User cloud** (optional): media originals on iCloud /
//!   Google Drive / ZK Object Fabric.
//!
//! [`route_media_upload`] decides at runtime whether a given asset's
//! ciphertext chunks go to Tier 0 (the KChat
//! [`crate::transport::TransportClient`] surface) or Tier 2 (an
//! injected [`crate::media::sinks::MediaBlobSink`]):
//!
//! * `is_thumbnail == true` → always Tier 0 (thumbnails are
//!   client-rendered teasers and the user-cloud sinks would slow
//!   them down with extra round-trips).
//! * `is_thumbnail == false` + `config.media_blob_sink.is_some()` +
//!   `media_blob_sink.is_some()` → Tier 2.
//! * Otherwise → Tier 0 (fallback when the user has not configured
//!   a personal cloud sink).
//!
//! [`route_media_download`] dispatches the inverse fetch from a
//! `media_asset.storage_sink` tag — `"kchat_backend"` →
//! [`crate::transport::TransportClient::fetch_blob_range`], anything
//! else → [`crate::media::sinks::MediaBlobSink::fetch_media_chunk`].

use crate::config::KChatCoreConfig;
use crate::crypto::aead::BlobClass;
use crate::media::chunker::SealedChunk;
use crate::media::download::DEFAULT_CHUNK_CIPHERTEXT_SIZE;
use crate::media::sinks::{MediaBlobReference, MediaBlobSink};
use crate::media::upload::upload_chunked_media;
use crate::transport::TransportClient;
use crate::Error;

/// Storage-sink tag used when the asset's chunks live on the KChat
/// backend (Tier 0). Mirrors
/// [`crate::local_store::schema::MediaAsset::storage_sink`] /
/// [`crate::media::sinks::MediaBlobReference::storage_sink`] for
/// `kchat_backend`-tagged rows.
pub const KCHAT_BACKEND_SINK: &str = "kchat_backend";

/// Decide between Tier 0 (KChat backend) and Tier 2 (user cloud)
/// for a media-original or thumbnail upload, run the chosen path,
/// and return the [`MediaBlobReference`] the local store persists.
///
/// `asset_id` is the descriptor / `media_asset.asset_id` value;
/// Tier 2 sinks key uploads by it. Tier 0 ignores it (the upload
/// pipeline assigns `media_asset.blob_id` from
/// [`crate::transport::BlobUploadHandle::blob_id`] instead) but the
/// signature still takes it so callers don't have to special-case
/// the routing decision before calling this function.
///
/// Routing rules (`docs/PROPOSAL.md §5.7`):
///
/// * `is_thumbnail == true` → always Tier 0.
/// * `is_thumbnail == false` and `config.media_blob_sink.is_some()`
///   and `media_blob_sink.is_some()` → Tier 2.
/// * Otherwise → Tier 0.
#[allow(clippy::too_many_arguments)]
pub fn route_media_upload(
    config: &KChatCoreConfig,
    transport: &dyn TransportClient,
    media_blob_sink: Option<&dyn MediaBlobSink>,
    asset_id: &str,
    sealed_chunks: &[SealedChunk],
    merkle_root: [u8; 32],
    blob_class: BlobClass,
    is_thumbnail: bool,
) -> Result<MediaBlobReference, Error> {
    if !is_thumbnail && config.media_blob_sink.is_some() {
        if let Some(sink) = media_blob_sink {
            let chunk_views: Vec<&[u8]> = sealed_chunks
                .iter()
                .map(|c| c.ciphertext.as_slice())
                .collect();
            return sink.upload_media_chunks(asset_id, blob_class, &chunk_views, merkle_root);
        }
    }

    // Tier 0 fallback for thumbnails, missing config, or missing
    // sink instance.
    let result = upload_chunked_media(transport, sealed_chunks, merkle_root, blob_class)?;
    Ok(MediaBlobReference {
        blob_id: result.blob_id,
        storage_sink: KCHAT_BACKEND_SINK.to_string(),
        sink_metadata: None,
    })
}

/// Fetch the ciphertext of chunk `chunk_idx` of a previously
/// uploaded asset, dispatching on
/// [`MediaBlobReference::storage_sink`].
///
/// * `"kchat_backend"` → [`TransportClient::fetch_blob_range`] over
///   the deterministic per-chunk byte range from the chunker.
/// * any other tag → [`MediaBlobSink::fetch_media_chunk`].
///
/// Errors with a [`crate::Error::Storage`] when the required sink
/// is not configured (i.e. the asset was uploaded through a Tier 2
/// sink that the current process did not load).
pub fn route_media_download(
    storage_sink: &str,
    transport: &dyn TransportClient,
    media_blob_sink: Option<&dyn MediaBlobSink>,
    blob_ref: &MediaBlobReference,
    chunk_idx: u32,
) -> Result<Vec<u8>, Error> {
    if blob_ref.storage_sink != storage_sink {
        return Err(Error::Storage(
            format!(
                "route_media_download: blob_ref.storage_sink {:?} does not match {:?}",
                blob_ref.storage_sink, storage_sink
            )
            .into(),
        ));
    }
    if storage_sink == KCHAT_BACKEND_SINK {
        let start = (chunk_idx as u64) * (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
        let end = start + (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
        return transport.fetch_blob_range(&blob_ref.blob_id, start..end);
    }
    let Some(sink) = media_blob_sink else {
        return Err(Error::Storage(format!(
            "route_media_download: storage_sink {storage_sink:?} requires a MediaBlobSink but none was provided"
        ).into()));
    };
    sink.fetch_media_chunk(blob_ref, chunk_idx)
}

#[cfg(test)]
mod tests {
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use super::*;
    use crate::config::{Platform, StorageSink};
    use crate::media::chunker::SealedChunk;
    use crate::media::sinks::{MediaBlobReference, MediaBlobSink};
    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportResult,
    };

    // -----------------------------------------------------------------
    // Test doubles
    // -----------------------------------------------------------------

    /// Captures every call the upload pipeline makes so the tests
    /// can assert routing decisions.
    #[derive(Debug, Default)]
    struct StubTransport {
        init_response: Mutex<Option<TransportResult<BlobUploadHandle>>>,
        commit_response: Mutex<Option<TransportResult<CommitBlobResponse>>>,
        fetch_response: Mutex<Option<TransportResult<Vec<u8>>>>,
        upload_calls: Mutex<u32>,
        fetch_calls: Mutex<u32>,
    }

    impl StubTransport {
        fn new() -> Self {
            Self::default()
        }

        fn with_init(self, response: TransportResult<BlobUploadHandle>) -> Self {
            *self.init_response.lock().unwrap() = Some(response);
            self
        }

        fn with_commit(self, response: TransportResult<CommitBlobResponse>) -> Self {
            *self.commit_response.lock().unwrap() = Some(response);
            self
        }

        fn with_fetch(self, response: TransportResult<Vec<u8>>) -> Self {
            *self.fetch_response.lock().unwrap() = Some(response);
            self
        }

        fn upload_calls(&self) -> u32 {
            *self.upload_calls.lock().unwrap()
        }

        fn fetch_calls(&self) -> u32 {
            *self.fetch_calls.lock().unwrap()
        }
    }

    impl TransportClient for StubTransport {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> TransportResult<FetchMessagesResponse> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn init_blob_upload(
            &self,
            _size: u64,
            _blob_class: BlobClass,
            _expected_merkle_root: [u8; 32],
        ) -> TransportResult<BlobUploadHandle> {
            self.init_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(crate::Error::NotImplemented("transport")))
        }

        fn upload_chunk(
            &self,
            blob_id: &str,
            chunk_idx: u32,
            _ciphertext: &[u8],
            sha256: [u8; 32],
        ) -> TransportResult<ChunkReceipt> {
            *self.upload_calls.lock().unwrap() += 1;
            Ok(ChunkReceipt {
                blob_id: blob_id.to_string(),
                chunk_idx,
                sha256,
            })
        }

        fn commit_blob(&self, _blob_id: &str) -> TransportResult<CommitBlobResponse> {
            self.commit_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(crate::Error::NotImplemented("transport")))
        }

        fn fetch_blob_range(&self, _blob_id: &str, _range: Range<u64>) -> TransportResult<Vec<u8>> {
            *self.fetch_calls.lock().unwrap() += 1;
            self.fetch_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(crate::Error::NotImplemented("transport")))
        }

        fn fetch_archive_manifests(
            &self,
            _after_generation: Option<u64>,
        ) -> TransportResult<Vec<EncryptedManifest>> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn fetch_archive_segment(&self, _segment_id: &str) -> TransportResult<Vec<u8>> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn fetch_index_shards(
            &self,
            _conversation_hash: &str,
            _bucket: &str,
            _shard_type: &str,
        ) -> TransportResult<Vec<u8>> {
            Err(crate::Error::NotImplemented("transport"))
        }
    }

    /// Records every call so the tests can assert routing.
    #[derive(Debug, Default)]
    struct StubSink {
        upload_calls: Mutex<u32>,
        fetch_calls: Mutex<u32>,
        delete_calls: Mutex<u32>,
        fetch_response: Mutex<Option<crate::Result<Vec<u8>>>>,
    }

    impl StubSink {
        fn new() -> Self {
            Self::default()
        }

        fn with_fetch(self, response: crate::Result<Vec<u8>>) -> Self {
            *self.fetch_response.lock().unwrap() = Some(response);
            self
        }

        fn upload_calls(&self) -> u32 {
            *self.upload_calls.lock().unwrap()
        }

        fn fetch_calls(&self) -> u32 {
            *self.fetch_calls.lock().unwrap()
        }
    }

    impl MediaBlobSink for StubSink {
        fn upload_media_chunks(
            &self,
            asset_id: &str,
            _blob_class: BlobClass,
            _chunks: &[&[u8]],
            _expected_merkle_root: [u8; 32],
        ) -> crate::Result<MediaBlobReference> {
            *self.upload_calls.lock().unwrap() += 1;
            Ok(MediaBlobReference {
                blob_id: format!("sink-blob-{asset_id}"),
                storage_sink: "icloud".to_string(),
                sink_metadata: Some(b"icloud-meta".to_vec()),
            })
        }

        fn fetch_media_chunk(
            &self,
            _blob_ref: &MediaBlobReference,
            _chunk_idx: u32,
        ) -> crate::Result<Vec<u8>> {
            *self.fetch_calls.lock().unwrap() += 1;
            self.fetch_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(crate::Error::NotImplemented("media_blob_sink")))
        }

        fn delete_media_blob(&self, _blob_ref: &MediaBlobReference) -> crate::Result<()> {
            *self.delete_calls.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn dummy_chunks(n: usize) -> Vec<SealedChunk> {
        (0..n)
            .map(|i| {
                let ciphertext = vec![i as u8 + 1; 32];
                let sha256: [u8; 32] = {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(&ciphertext);
                    h.finalize().into()
                };
                SealedChunk {
                    ciphertext,
                    chunk_sha256: sha256,
                }
            })
            .collect()
    }

    fn cfg_no_sink() -> KChatCoreConfig {
        KChatCoreConfig::new(PathBuf::from("/tmp/kchat"), Platform::MacOs, "tenant-test")
    }

    fn cfg_with_sink() -> KChatCoreConfig {
        cfg_no_sink().with_media_blob_sink(Some(StorageSink::ICloud {
            container_path: "iCloud.com.kchat.media".to_string(),
        }))
    }

    fn handle(blob_id: &str) -> BlobUploadHandle {
        BlobUploadHandle {
            blob_id: blob_id.to_string(),
            blob_class: BlobClass::Media,
            expires_at_ms: 0,
        }
    }

    fn commit(blob_id: &str, chunk_count: u32, merkle: [u8; 32]) -> CommitBlobResponse {
        CommitBlobResponse {
            blob_id: blob_id.to_string(),
            chunk_count,
            merkle_root: merkle,
        }
    }

    // -----------------------------------------------------------------
    // route_media_upload
    // -----------------------------------------------------------------

    #[test]
    fn thumbnail_always_routes_to_transport() {
        let merkle = [0x11u8; 32];
        let chunks = dummy_chunks(2);
        let transport = StubTransport::new()
            .with_init(Ok(handle("thumb-blob")))
            .with_commit(Ok(commit("thumb-blob", 2, merkle)));
        // Even though both config and sink are present, the
        // `is_thumbnail = true` flag forces Tier 0.
        let cfg = cfg_with_sink();
        let sink = StubSink::new();

        let r = route_media_upload(
            &cfg,
            &transport,
            Some(&sink),
            "asset-1",
            &chunks,
            merkle,
            BlobClass::Media,
            true,
        )
        .unwrap();
        assert_eq!(r.blob_id, "thumb-blob");
        assert_eq!(r.storage_sink, KCHAT_BACKEND_SINK);
        assert!(r.sink_metadata.is_none());
        assert_eq!(transport.upload_calls(), 2);
        assert_eq!(sink.upload_calls(), 0);
    }

    #[test]
    fn original_routes_to_sink_when_configured() {
        let merkle = [0x22u8; 32];
        let chunks = dummy_chunks(3);
        let transport = StubTransport::new(); // staged nothing → must not be called
        let cfg = cfg_with_sink();
        let sink = StubSink::new();

        let r = route_media_upload(
            &cfg,
            &transport,
            Some(&sink),
            "asset-2",
            &chunks,
            merkle,
            BlobClass::Media,
            false,
        )
        .unwrap();
        assert_eq!(r.storage_sink, "icloud");
        assert_eq!(r.blob_id, "sink-blob-asset-2");
        assert_eq!(sink.upload_calls(), 1);
        assert_eq!(transport.upload_calls(), 0);
    }

    #[test]
    fn original_falls_back_to_transport_when_no_config_sink() {
        let merkle = [0x33u8; 32];
        let chunks = dummy_chunks(1);
        let transport = StubTransport::new()
            .with_init(Ok(handle("transport-blob")))
            .with_commit(Ok(commit("transport-blob", 1, merkle)));
        let cfg = cfg_no_sink();
        let sink = StubSink::new();

        let r = route_media_upload(
            &cfg,
            &transport,
            Some(&sink),
            "asset-3",
            &chunks,
            merkle,
            BlobClass::Media,
            false,
        )
        .unwrap();
        assert_eq!(r.storage_sink, KCHAT_BACKEND_SINK);
        assert_eq!(r.blob_id, "transport-blob");
        assert_eq!(sink.upload_calls(), 0);
    }

    #[test]
    fn original_falls_back_when_sink_instance_missing() {
        // Config says "use a sink" but the caller didn't inject one
        // — fall back to transport instead of erroring.
        let merkle = [0x44u8; 32];
        let chunks = dummy_chunks(1);
        let transport = StubTransport::new()
            .with_init(Ok(handle("fallback-blob")))
            .with_commit(Ok(commit("fallback-blob", 1, merkle)));
        let cfg = cfg_with_sink();

        let r = route_media_upload(
            &cfg,
            &transport,
            None,
            "asset-4",
            &chunks,
            merkle,
            BlobClass::Media,
            false,
        )
        .unwrap();
        assert_eq!(r.storage_sink, KCHAT_BACKEND_SINK);
        assert_eq!(r.blob_id, "fallback-blob");
    }

    // -----------------------------------------------------------------
    // route_media_download
    // -----------------------------------------------------------------

    #[test]
    fn download_dispatches_kchat_to_transport() {
        let payload = b"fake-cipher".to_vec();
        let transport = StubTransport::new().with_fetch(Ok(payload.clone()));
        let blob_ref = MediaBlobReference {
            blob_id: "blob-1".to_string(),
            storage_sink: KCHAT_BACKEND_SINK.to_string(),
            sink_metadata: None,
        };
        let got = route_media_download(KCHAT_BACKEND_SINK, &transport, None, &blob_ref, 0).unwrap();
        assert_eq!(got, payload);
        assert_eq!(transport.fetch_calls(), 1);
    }

    #[test]
    fn download_dispatches_other_sink_to_media_blob_sink() {
        let payload = b"sink-cipher".to_vec();
        let sink = StubSink::new().with_fetch(Ok(payload.clone()));
        let transport = StubTransport::new();
        let blob_ref = MediaBlobReference {
            blob_id: "i-blob-1".to_string(),
            storage_sink: "icloud".to_string(),
            sink_metadata: None,
        };
        let got = route_media_download("icloud", &transport, Some(&sink), &blob_ref, 2).unwrap();
        assert_eq!(got, payload);
        assert_eq!(sink.fetch_calls(), 1);
        assert_eq!(transport.fetch_calls(), 0);
    }

    #[test]
    fn download_errors_when_sink_required_but_missing() {
        let transport = StubTransport::new();
        let blob_ref = MediaBlobReference {
            blob_id: "z-blob".to_string(),
            storage_sink: "zk_object_fabric".to_string(),
            sink_metadata: None,
        };
        let err =
            route_media_download("zk_object_fabric", &transport, None, &blob_ref, 0).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.to_string().contains("MediaBlobSink"), "{msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn download_errors_on_storage_sink_mismatch() {
        let transport = StubTransport::new();
        let sink = StubSink::new();
        let blob_ref = MediaBlobReference {
            blob_id: "blob-x".to_string(),
            storage_sink: "icloud".to_string(),
            sink_metadata: None,
        };
        let err = route_media_download(KCHAT_BACKEND_SINK, &transport, Some(&sink), &blob_ref, 0)
            .unwrap_err();
        match err {
            Error::Storage(msg) => {
                assert!(msg.to_string().contains("does not match"), "{msg}");
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }
}
