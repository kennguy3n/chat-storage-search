//! Archive backend routing.
//!
//! `docs/PROPOSAL.md §10.1` defines two archive backends:
//!
//! * [`crate::config::ArchiveBackend::KChat`] — the default
//!   PostgreSQL blob service reached via [`TransportClient`]; it
//!   implements `init_blob_upload → upload_chunk → commit_blob` for
//!   uploads and `fetch_archive_segment` /
//!   `fetch_archive_manifests` for downloads.
//! * [`crate::config::ArchiveBackend::Zkof`] — the ZK Object Fabric
//!   variant that maps the same operations onto S3 PutObject /
//!   GetObject. The Phase-3 wire-up keeps the dispatch logic real
//!   but stubs the actual S3 client; the HTTP implementation lands
//!   in a follow-up.
//!
//! This module owns the dispatch — every archive uploader /
//! downloader in the codebase routes through one of the
//! `route_archive_*` entry points so swapping the backend at config
//! time is a one-line change.
//!
//! ```text
//! ┌──────────────────┐    ArchiveBackend::KChat    ┌──────────────────┐
//! │ archive engine   │ ─────────────────────────▶  │ TransportClient  │
//! │ (segment/        │                              │ (KChat backend)  │
//! │  manifest)       │ ─────────────────────────▶  ┌──────────────────┐
//! └──────────────────┘    ArchiveBackend::Zkof    │ ZkofArchiveAdapter│
//!                                                  │ (S3, stubbed)    │
//!                                                  └──────────────────┘
//! ```

use crate::archive::manifest_builder::SealedArchiveManifest;
use crate::archive::segment_builder::BuiltSegment;
use crate::archive::upload::upload_archive_segment;
use crate::config::{ArchiveBackend, KChatCoreConfig};
use crate::transport::TransportClient;
use crate::Error;

/// ZKOF / S3 adapter for archive operations. The HTTP client is
/// stubbed under [`StubZkofArchiveAdapter`] for Phase 3 — every
/// method returns [`Error::NotImplemented`] so the rest of the
/// pipeline can be exercised against the dispatch surface without
/// a real S3 round-trip.
///
/// `docs/PROPOSAL.md §10.2` — segments map to S3 PutObject keyed
/// on `archive/segments/{segment_id}`, manifests map to
/// `archive/manifests/{generation}`.
pub trait ZkofArchiveAdapter: Send + Sync {
    /// Upload a segment to S3 (PutObject). Returns the storage key
    /// the adapter chose (typically `archive/segments/{segment_id}`).
    fn upload_segment(&self, segment: &BuiltSegment) -> Result<String, Error>;

    /// Download a segment by id (GetObject). Returns the encrypted
    /// segment bytes; decryption happens upstream.
    fn fetch_segment(&self, segment_id: &str) -> Result<Vec<u8>, Error>;

    /// Upload a sealed manifest (PutObject) keyed on its
    /// generation number.
    fn upload_manifest(&self, manifest: &SealedArchiveManifest) -> Result<(), Error>;
}

/// Stub adapter that returns [`Error::NotImplemented`] for every
/// method. The real HTTP client lands when the ZKOF crate gains
/// its S3 driver.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubZkofArchiveAdapter;

impl ZkofArchiveAdapter for StubZkofArchiveAdapter {
    fn upload_segment(&self, _segment: &BuiltSegment) -> Result<String, Error> {
        Err(Error::NotImplemented(
            "StubZkofArchiveAdapter::upload_segment",
        ))
    }

    fn fetch_segment(&self, _segment_id: &str) -> Result<Vec<u8>, Error> {
        Err(Error::NotImplemented(
            "StubZkofArchiveAdapter::fetch_segment",
        ))
    }

    fn upload_manifest(&self, _manifest: &SealedArchiveManifest) -> Result<(), Error> {
        Err(Error::NotImplemented(
            "StubZkofArchiveAdapter::upload_manifest",
        ))
    }
}

/// Route an archive segment upload to the configured backend.
///
/// * [`ArchiveBackend::KChat`] → [`upload_archive_segment`] over
///   the supplied `transport`. Returns the `blob_id` the transport
///   assigned at `init_blob_upload`.
/// * [`ArchiveBackend::Zkof`] → [`ZkofArchiveAdapter::upload_segment`]
///   on the supplied adapter. Returns the storage key.
pub fn route_archive_upload(
    config: &KChatCoreConfig,
    transport: &dyn TransportClient,
    zkof_adapter: &dyn ZkofArchiveAdapter,
    segment: &BuiltSegment,
) -> Result<String, Error> {
    match config.archive_backend {
        ArchiveBackend::KChat => upload_archive_segment(transport, segment),
        ArchiveBackend::Zkof => zkof_adapter.upload_segment(segment),
    }
}

/// Route an archive segment download to the configured backend.
pub fn route_archive_download(
    config: &KChatCoreConfig,
    transport: &dyn TransportClient,
    zkof_adapter: &dyn ZkofArchiveAdapter,
    segment_id: &str,
) -> Result<Vec<u8>, Error> {
    match config.archive_backend {
        ArchiveBackend::KChat => transport.fetch_archive_segment(segment_id),
        ArchiveBackend::Zkof => zkof_adapter.fetch_segment(segment_id),
    }
}

/// Route a manifest upload to the configured backend.
///
/// The KChat backend's manifest-upload endpoint is *not* part of
/// the [`TransportClient`] surface today — only the *fetch* side
/// (`fetch_archive_manifests`) is wired in Phase 1 / 2. Until the
/// upload endpoint lands the KChat path returns
/// [`Error::NotImplemented`] with a descriptive label so the
/// dispatch surface stays honest. The ZKOF path delegates straight
/// to [`ZkofArchiveAdapter::upload_manifest`].
pub fn route_manifest_upload(
    config: &KChatCoreConfig,
    _transport: &dyn TransportClient,
    zkof_adapter: &dyn ZkofArchiveAdapter,
    manifest: &SealedArchiveManifest,
) -> Result<(), Error> {
    match config.archive_backend {
        ArchiveBackend::KChat => Err(Error::NotImplemented(
            "route_manifest_upload: KChat manifest upload endpoint",
        )),
        ArchiveBackend::Zkof => zkof_adapter.upload_manifest(manifest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use uuid::Uuid;

    use crate::config::Platform;
    use crate::crypto::aead::{xchacha20_poly1305, BlobClass};
    use crate::formats::manifest::{
        ArchiveManifest, ARCHIVE_MANIFEST_MAGIC, GENESIS_PREVIOUS_HASH, MANIFEST_VERSION,
    };
    use crate::formats::SegmentType;
    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportClient as TransportClientTrait, TransportResult,
    };
    use ed25519_dalek::{Signature, SIGNATURE_LENGTH};

    /// In-memory transport that stores a single archive segment
    /// upload via init/upload/commit and serves
    /// `fetch_archive_segment` from a configured byte buffer.
    #[derive(Debug, Default)]
    struct CapturingTransport {
        last_blob_id: Mutex<Option<String>>,
        last_chunks: Mutex<Vec<Vec<u8>>>,
        commit_root: Mutex<[u8; 32]>,
        fetched: Mutex<Vec<String>>,
        fetched_response: Mutex<Vec<u8>>,
    }

    impl CapturingTransport {
        fn with_fetch(bytes: Vec<u8>) -> Self {
            Self {
                fetched_response: Mutex::new(bytes),
                ..Default::default()
            }
        }
    }

    impl TransportClientTrait for CapturingTransport {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> TransportResult<FetchMessagesResponse> {
            Err(Error::NotImplemented("transport"))
        }

        fn init_blob_upload(
            &self,
            _size: u64,
            blob_class: BlobClass,
            ciphertext_root: [u8; 32],
        ) -> TransportResult<BlobUploadHandle> {
            *self.commit_root.lock().unwrap() = ciphertext_root;
            let id = format!("blob-{}", Uuid::now_v7());
            *self.last_blob_id.lock().unwrap() = Some(id.clone());
            Ok(BlobUploadHandle {
                blob_id: id,
                blob_class,
                expires_at_ms: 0,
            })
        }

        fn upload_chunk(
            &self,
            blob_id: &str,
            chunk_idx: u32,
            ciphertext: &[u8],
            sha256: [u8; 32],
        ) -> TransportResult<ChunkReceipt> {
            self.last_chunks.lock().unwrap().push(ciphertext.to_vec());
            Ok(ChunkReceipt {
                blob_id: blob_id.to_string(),
                chunk_idx,
                sha256,
            })
        }

        fn commit_blob(&self, blob_id: &str) -> TransportResult<CommitBlobResponse> {
            Ok(CommitBlobResponse {
                blob_id: blob_id.to_string(),
                chunk_count: 1,
                merkle_root: *self.commit_root.lock().unwrap(),
            })
        }

        fn fetch_blob_range(&self, _blob_id: &str, _range: Range<u64>) -> TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_archive_manifests(
            &self,
            _after_generation: Option<u64>,
        ) -> TransportResult<Vec<EncryptedManifest>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_archive_segment(&self, segment_id: &str) -> TransportResult<Vec<u8>> {
            self.fetched.lock().unwrap().push(segment_id.to_string());
            Ok(self.fetched_response.lock().unwrap().clone())
        }

        fn fetch_index_shards(
            &self,
            _conversation_hash: &str,
            _bucket: &str,
            _shard_type: &str,
        ) -> TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }
    }

    /// Adapter that records every dispatched call so tests can
    /// assert routing decisions without any actual S3 work.
    #[derive(Debug, Default)]
    struct RecordingZkofAdapter {
        uploaded_segments: Mutex<Vec<Uuid>>,
        fetched_segments: Mutex<Vec<String>>,
        uploaded_manifests: Mutex<u32>,
    }

    impl ZkofArchiveAdapter for RecordingZkofAdapter {
        fn upload_segment(&self, segment: &BuiltSegment) -> Result<String, Error> {
            self.uploaded_segments
                .lock()
                .unwrap()
                .push(segment.segment_id);
            Ok(format!("zkof-key-{}", segment.segment_id))
        }

        fn fetch_segment(&self, segment_id: &str) -> Result<Vec<u8>, Error> {
            self.fetched_segments
                .lock()
                .unwrap()
                .push(segment_id.to_string());
            Ok(b"zkof-bytes".to_vec())
        }

        fn upload_manifest(&self, _manifest: &SealedArchiveManifest) -> Result<(), Error> {
            *self.uploaded_manifests.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn fresh_segment() -> BuiltSegment {
        BuiltSegment {
            segment_id: Uuid::now_v7(),
            conversation_id: Uuid::now_v7(),
            time_bucket: "2026-05".into(),
            segment_type: SegmentType::MessageDelta,
            nonce: [0u8; xchacha20_poly1305::NONCE_LEN],
            ciphertext: vec![0xAB; 64],
            merkle_root: [0u8; 32],
            event_count: 1,
        }
    }

    fn fresh_config(backend: ArchiveBackend) -> KChatCoreConfig {
        KChatCoreConfig::new(PathBuf::from("/tmp/dummy"), Platform::MacOs, "tenant")
            .with_archive_backend(backend)
    }

    fn stub_manifest() -> SealedArchiveManifest {
        SealedArchiveManifest {
            manifest: ArchiveManifest {
                magic: ARCHIVE_MANIFEST_MAGIC.to_string(),
                version: MANIFEST_VERSION,
                manifest_id: Uuid::now_v7(),
                generation: 0,
                previous_manifest_hash: GENESIS_PREVIOUS_HASH,
                segments: vec![],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                wrapped_prior_epoch_keys: vec![],
                merkle_root: [0u8; 32],
                manifest_signature: vec![],
            },
            signature: Signature::from_bytes(&[0u8; SIGNATURE_LENGTH]),
            nonce: [0u8; xchacha20_poly1305::NONCE_LEN],
            ciphertext: vec![],
        }
    }

    #[test]
    fn upload_routes_kchat_to_transport() {
        let config = fresh_config(ArchiveBackend::KChat);
        let transport = CapturingTransport::default();
        let adapter = RecordingZkofAdapter::default();
        let segment = fresh_segment();
        let blob_id =
            route_archive_upload(&config, &transport, &adapter, &segment).expect("route upload");
        assert!(blob_id.starts_with("blob-"));
        assert!(transport.last_blob_id.lock().unwrap().is_some());
        assert_eq!(transport.last_chunks.lock().unwrap().len(), 1);
        assert!(adapter.uploaded_segments.lock().unwrap().is_empty());
    }

    #[test]
    fn upload_routes_zkof_to_adapter() {
        let config = fresh_config(ArchiveBackend::Zkof);
        let transport = CapturingTransport::default();
        let adapter = RecordingZkofAdapter::default();
        let segment = fresh_segment();
        let key = route_archive_upload(&config, &transport, &adapter, &segment).expect("route");
        assert_eq!(key, format!("zkof-key-{}", segment.segment_id));
        assert!(transport.last_blob_id.lock().unwrap().is_none());
        assert_eq!(adapter.uploaded_segments.lock().unwrap().len(), 1);
    }

    #[test]
    fn download_routes_kchat_to_transport() {
        let config = fresh_config(ArchiveBackend::KChat);
        let transport = CapturingTransport::with_fetch(vec![1, 2, 3]);
        let adapter = RecordingZkofAdapter::default();
        let bytes =
            route_archive_download(&config, &transport, &adapter, "seg-1").expect("download");
        assert_eq!(bytes, vec![1, 2, 3]);
        assert_eq!(transport.fetched.lock().unwrap().as_slice(), &["seg-1"]);
        assert!(adapter.fetched_segments.lock().unwrap().is_empty());
    }

    #[test]
    fn download_routes_zkof_to_adapter() {
        let config = fresh_config(ArchiveBackend::Zkof);
        let transport = CapturingTransport::default();
        let adapter = RecordingZkofAdapter::default();
        let bytes =
            route_archive_download(&config, &transport, &adapter, "seg-9").expect("download");
        assert_eq!(bytes, b"zkof-bytes");
        assert!(transport.fetched.lock().unwrap().is_empty());
        assert_eq!(
            adapter.fetched_segments.lock().unwrap().as_slice(),
            &["seg-9"]
        );
    }

    #[test]
    fn manifest_upload_kchat_returns_not_implemented() {
        let config = fresh_config(ArchiveBackend::KChat);
        let transport = CapturingTransport::default();
        let adapter = RecordingZkofAdapter::default();
        let manifest = stub_manifest();
        let err = route_manifest_upload(&config, &transport, &adapter, &manifest).unwrap_err();
        assert!(matches!(err, Error::NotImplemented(_)), "got {err:?}");
    }

    #[test]
    fn manifest_upload_zkof_routes_to_adapter() {
        let config = fresh_config(ArchiveBackend::Zkof);
        let transport = CapturingTransport::default();
        let adapter = RecordingZkofAdapter::default();
        let manifest = stub_manifest();
        route_manifest_upload(&config, &transport, &adapter, &manifest).expect("route");
        assert_eq!(*adapter.uploaded_manifests.lock().unwrap(), 1);
    }

    #[test]
    fn stub_zkof_adapter_returns_not_implemented_for_every_method() {
        let stub = StubZkofArchiveAdapter;
        let segment = fresh_segment();
        let manifest = stub_manifest();
        assert!(matches!(
            stub.upload_segment(&segment).unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.fetch_segment("x").unwrap_err(),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            stub.upload_manifest(&manifest).unwrap_err(),
            Error::NotImplemented(_)
        ));
    }
}
