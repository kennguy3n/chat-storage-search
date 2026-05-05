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

use std::sync::Arc;

use crate::archive::download::encode_archive_segment_blob;
use crate::archive::manifest_builder::SealedArchiveManifest;
use crate::archive::segment_builder::BuiltSegment;
use crate::archive::upload::upload_archive_segment;
use crate::config::{ArchiveBackend, KChatCoreConfig};
use crate::crypto::content_hash::content_hash;
use crate::crypto::convergent::{
    decrypt_object_pattern_c, derive_convergent_dek, encrypt_object_pattern_c, DEFAULT_CHUNK_SIZE,
};
use crate::media::sinks::zk_fabric::{S3Client, ZkFabricSinkConfig};
use crate::transport::TransportClient;
use crate::Error;

/// Object key prefix for archive segment ciphertext: per
/// `docs/PROPOSAL.md §10.2`, every segment lives at
/// `archive/segments/{segment_id}` in the ZKOF bucket.
pub const ZKOF_ARCHIVE_SEGMENT_KEY_PREFIX: &str = "archive/segments/";

/// Object key prefix for archive manifest CBOR bundles. Manifests
/// are keyed on their `manifest_id` (a UUID) so two distinct
/// generations cannot accidentally clobber each other.
pub const ZKOF_ARCHIVE_MANIFEST_KEY_PREFIX: &str = "archive/manifests/";

fn zkof_archive_segment_key(segment_id: &str) -> String {
    format!("{ZKOF_ARCHIVE_SEGMENT_KEY_PREFIX}{segment_id}")
}

fn zkof_archive_manifest_key(manifest_id: &str) -> String {
    format!("{ZKOF_ARCHIVE_MANIFEST_KEY_PREFIX}{manifest_id}")
}

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

/// Production [`ZkofArchiveAdapter`] backed by an [`S3Client`].
///
/// Mirrors [`crate::backup::sinks::zk_fabric::ZkofBackupSink`]
/// for the **archive** pipeline: every payload is wrapped in a
/// Pattern C convergent-encryption frame keyed by the configured
/// tenant id before it crosses the S3 boundary, so duplicate
/// archive segments dedup on the cloud side without the cloud
/// ever holding the per-tenant `K_archive_*` keys.
///
/// Object key layout (matches `docs/PROPOSAL.md §10.2`):
///
/// ```text
/// archive/segments/{segment_id}     — segment blob
///                                     (encode_archive_segment_blob)
/// archive/manifests/{manifest_id}   — sealed manifest CBOR
/// ```
///
/// Both layers (the AEAD seal under `K_archive_segment` /
/// `K_archive_manifest` and the Pattern C convergent layer here)
/// are independent — losing either is not enough to read the
/// bytes back.
#[derive(Debug, Clone)]
pub struct S3ZkofArchiveAdapter {
    s3: Arc<dyn S3Client>,
    config: ZkFabricSinkConfig,
    tenant_id: String,
}

impl S3ZkofArchiveAdapter {
    /// Construct an adapter bound to the supplied S3 client,
    /// ZKOF config, and tenant id.
    ///
    /// The tenant id is fed into the Pattern C DEK derivation so
    /// two tenants encrypting the same plaintext produce
    /// different ciphertexts (no cross-tenant dedup).
    pub fn new(
        s3: Arc<dyn S3Client>,
        config: ZkFabricSinkConfig,
        tenant_id: impl Into<String>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let tenant_id = tenant_id.into();
        if tenant_id.is_empty() {
            return Err(Error::Storage(
                "S3ZkofArchiveAdapter: tenant_id must not be empty".into(),
            ));
        }
        Ok(Self {
            s3,
            config,
            tenant_id,
        })
    }

    /// S3 bucket the adapter targets.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Tenant id stamped into Pattern C DEK derivation.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Convergent-seal `plaintext` with this adapter's tenant id.
    /// Exposed for tests / determinism vectors.
    pub fn pattern_c_seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = content_hash(plaintext);
        let dek = derive_convergent_dek(&hash, &self.tenant_id)
            .map_err(|e| Error::Storage(format!("S3ZkofArchiveAdapter: derive DEK: {e}")))?;
        encrypt_object_pattern_c(plaintext, dek.as_bytes(), DEFAULT_CHUNK_SIZE)
            .map_err(|e| Error::Storage(format!("S3ZkofArchiveAdapter: pattern C seal: {e}")))
    }

    /// Pattern C `open` — inverse of [`Self::pattern_c_seal`].
    /// Requires the original plaintext's BLAKE3 hash because the
    /// DEK is content-derived; the caller hands it the hash via
    /// the manifest / segment metadata. Exposed for tests.
    pub fn pattern_c_open(
        &self,
        ciphertext: &[u8],
        plaintext_hash: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        let dek = derive_convergent_dek(plaintext_hash, &self.tenant_id)
            .map_err(|e| Error::Storage(format!("S3ZkofArchiveAdapter: derive DEK: {e}")))?;
        decrypt_object_pattern_c(ciphertext, dek.as_bytes(), DEFAULT_CHUNK_SIZE)
            .map_err(|e| Error::Storage(format!("S3ZkofArchiveAdapter: pattern C open: {e}")))
    }
}

impl ZkofArchiveAdapter for S3ZkofArchiveAdapter {
    fn upload_segment(&self, segment: &BuiltSegment) -> Result<String, Error> {
        // Encode the on-the-wire segment blob (matching the KChat
        // upload contract) so the same `decrypt_archive_segment`
        // helper opens both backends.
        let blob = encode_archive_segment_blob(
            &segment.segment_id,
            &segment.merkle_root,
            &segment.nonce,
            &segment.ciphertext,
        );
        let sealed = self.pattern_c_seal(&blob)?;
        let key = zkof_archive_segment_key(&segment.segment_id.to_string());
        self.s3.put_object(&self.config.bucket, &key, &sealed)?;
        Ok(key)
    }

    fn fetch_segment(&self, segment_id: &str) -> Result<Vec<u8>, Error> {
        let key = zkof_archive_segment_key(segment_id);
        // Pattern C is content-addressed: the adapter does not
        // own the plaintext hash, so it returns the raw
        // convergent bytes. The orchestrator (which holds the
        // ledger row carrying the plaintext hash) finishes the
        // open via [`Self::pattern_c_open`] before decoding.
        // Mirrors [`ZkofBackupSink::fetch_backup_segment`].
        self.s3
            .get_object_range(&self.config.bucket, &key, 0..u64::MAX)
    }

    fn upload_manifest(&self, manifest: &SealedArchiveManifest) -> Result<(), Error> {
        let cbor = encode_sealed_archive_manifest(manifest)?;
        let sealed = self.pattern_c_seal(&cbor)?;
        let key = zkof_archive_manifest_key(&manifest.manifest.manifest_id.to_string());
        self.s3.put_object(&self.config.bucket, &key, &sealed)
    }
}

/// CBOR-encode a [`SealedArchiveManifest`] for cross-backend
/// transport. The inner [`ArchiveManifest`] already implements
/// `Serialize` and now carries both the Ed25519 and ML-DSA-65
/// signatures inline (`manifest_signature` and `pqc_signature`),
/// so the wire shape just needs the manifest body plus the AEAD
/// nonce / ciphertext.
#[derive(serde::Serialize, serde::Deserialize)]
struct WireSealedArchiveManifest {
    manifest: crate::formats::manifest::ArchiveManifest,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

/// Encode a [`SealedArchiveManifest`] into the on-the-wire CBOR
/// shape used by [`S3ZkofArchiveAdapter::upload_manifest`].
/// Exposed (crate-internal) so tests can round-trip through the
/// same encoder.
pub(crate) fn encode_sealed_archive_manifest(
    manifest: &SealedArchiveManifest,
) -> Result<Vec<u8>, Error> {
    let wire = WireSealedArchiveManifest {
        manifest: manifest.manifest.clone(),
        nonce: manifest.nonce.to_vec(),
        ciphertext: manifest.ciphertext.clone(),
    };
    serde_cbor::to_vec(&wire)
        .map_err(|e| Error::Storage(format!("S3ZkofArchiveAdapter: cbor encode manifest: {e}")))
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
    use crate::crypto::signing::{HybridSigningKey, ML_DSA_65_SIGNATURE_LEN};
    use crate::formats::manifest::{
        sign_archive_manifest, ArchiveManifest, ARCHIVE_MANIFEST_MAGIC, GENESIS_PREVIOUS_HASH,
        MANIFEST_VERSION,
    };
    use crate::formats::SegmentType;
    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportClient as TransportClientTrait, TransportResult,
    };
    use ed25519_dalek::SIGNATURE_LENGTH;
    use rand::rngs::OsRng;

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
        // Build a real manifest, sign it with a fresh hybrid key,
        // and return the sealed bundle. We don't try to fabricate
        // signature bytes by hand any more — ML-DSA-65 signatures
        // are 3309 bytes of structured material with no
        // "all-zero" valid form, so producing them via the actual
        // `sign_archive_manifest` is both simpler and more
        // honest.
        let mut rng = OsRng;
        let signing_key = HybridSigningKey::generate(&mut rng);
        let mut manifest = ArchiveManifest {
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
            pqc_signature: vec![],
        };
        let signature = sign_archive_manifest(&mut manifest, &signing_key)
            .expect("hybrid sign archive manifest in stub");
        debug_assert_eq!(manifest.manifest_signature.len(), SIGNATURE_LENGTH);
        debug_assert_eq!(manifest.pqc_signature.len(), ML_DSA_65_SIGNATURE_LEN);
        SealedArchiveManifest {
            manifest,
            signature,
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

    // -----------------------------------------------------------------
    // S3-backed adapter — round-trip + key-layout integration tests.
    // -----------------------------------------------------------------

    use std::collections::BTreeMap;
    use std::sync::Arc as StdArc;

    /// Minimal in-memory S3 implementing the same contract as the
    /// production gateway: byte-range reads clamp past the object
    /// length and `list_objects` returns sorted keys.
    #[derive(Debug, Default)]
    struct InMemoryS3 {
        objects: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    }

    impl S3Client for InMemoryS3 {
        fn put_object(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<(), Error> {
            self.objects
                .lock()
                .unwrap()
                .insert((bucket.into(), key.into()), bytes.to_vec());
            Ok(())
        }

        fn get_object_range(
            &self,
            bucket: &str,
            key: &str,
            range: Range<u64>,
        ) -> Result<Vec<u8>, Error> {
            let objects = self.objects.lock().unwrap();
            let bytes = objects
                .get(&(bucket.into(), key.into()))
                .ok_or_else(|| Error::Storage(format!("no such object: {bucket}/{key}")))?;
            let start = range.start.min(bytes.len() as u64) as usize;
            let end = range.end.min(bytes.len() as u64) as usize;
            Ok(bytes[start..end].to_vec())
        }

        fn list_objects(&self, bucket: &str, prefix: &str) -> Result<Vec<String>, Error> {
            let objects = self.objects.lock().unwrap();
            let mut out: Vec<String> = objects
                .keys()
                .filter(|(b, k)| b == bucket && k.starts_with(prefix))
                .map(|(_, k)| k.clone())
                .collect();
            out.sort();
            Ok(out)
        }

        fn delete_object(&self, bucket: &str, key: &str) -> Result<(), Error> {
            self.objects
                .lock()
                .unwrap()
                .remove(&(bucket.into(), key.into()));
            Ok(())
        }
    }

    fn fresh_zkof_config() -> ZkFabricSinkConfig {
        ZkFabricSinkConfig {
            endpoint_url: "https://zkof.example.com".into(),
            access_key: "AKIA-TEST".into(),
            secret_key: "secret".into(),
            bucket: "kchat-archive".into(),
        }
    }

    #[test]
    fn s3_zkof_archive_adapter_rejects_empty_tenant() {
        let s3 = StdArc::new(InMemoryS3::default());
        let err = S3ZkofArchiveAdapter::new(s3, fresh_zkof_config(), "").unwrap_err();
        assert!(matches!(err, Error::Storage(msg) if msg.contains("tenant_id")));
    }

    #[test]
    fn s3_zkof_archive_adapter_segment_round_trip() {
        // Build a real BuiltSegment, push it through the adapter,
        // pull it back, Pattern-C-open it, and verify the on-the-
        // wire blob round-trips bit-for-bit.
        let s3: StdArc<dyn S3Client> = StdArc::new(InMemoryS3::default());
        let adapter =
            S3ZkofArchiveAdapter::new(s3.clone(), fresh_zkof_config(), "tenant-roundtrip").unwrap();
        let segment = fresh_segment();
        let key = adapter.upload_segment(&segment).expect("upload");
        let expected_key = format!("archive/segments/{}", segment.segment_id);
        assert_eq!(key, expected_key);

        let fetched = adapter
            .fetch_segment(&segment.segment_id.to_string())
            .expect("fetch");
        let plaintext_blob = encode_archive_segment_blob(
            &segment.segment_id,
            &segment.merkle_root,
            &segment.nonce,
            &segment.ciphertext,
        );
        let blob_hash = content_hash(&plaintext_blob);
        let opened = adapter.pattern_c_open(&fetched, &blob_hash).expect("open");
        assert_eq!(opened, plaintext_blob);
    }

    #[test]
    fn s3_zkof_archive_adapter_manifest_keyed_by_id() {
        let s3: StdArc<dyn S3Client> = StdArc::new(InMemoryS3::default());
        let adapter =
            S3ZkofArchiveAdapter::new(s3.clone(), fresh_zkof_config(), "tenant-mfst").unwrap();
        let manifest = stub_manifest();
        adapter.upload_manifest(&manifest).expect("upload manifest");
        // The S3 key must be `archive/manifests/{manifest_id}` —
        // pull it back via list_objects to confirm.
        let keys = s3
            .list_objects(adapter.bucket(), ZKOF_ARCHIVE_MANIFEST_KEY_PREFIX)
            .expect("list");
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0],
            format!("archive/manifests/{}", manifest.manifest.manifest_id)
        );
    }

    #[test]
    fn s3_zkof_archive_adapter_routes_via_route_archive_upload() {
        let config = fresh_config(ArchiveBackend::Zkof);
        let s3: StdArc<dyn S3Client> = StdArc::new(InMemoryS3::default());
        let adapter = S3ZkofArchiveAdapter::new(s3, fresh_zkof_config(), "tenant-route").unwrap();
        let transport = CapturingTransport::default();
        let segment = fresh_segment();
        let key =
            route_archive_upload(&config, &transport, &adapter, &segment).expect("route upload");
        assert!(key.starts_with(ZKOF_ARCHIVE_SEGMENT_KEY_PREFIX));
        assert!(transport.last_blob_id.lock().unwrap().is_none());
    }
}
