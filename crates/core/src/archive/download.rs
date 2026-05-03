//! Phase-3 archive segment download + decrypt pipeline.
//!
//! The inverse of [`crate::archive::segment_builder`]:
//!
//! 1. [`download_archive_segment`] — fetch the encrypted ciphertext
//!    bytes via [`crate::transport::TransportClient::fetch_archive_segment`].
//! 2. [`decrypt_archive_segment`] — AEAD-open under
//!    `K_archive_segment` (XChaCha20-Poly1305), zstd-decompress,
//!    return the plaintext CBOR bytes.
//! 3. [`decode_archive_segment`] — CBOR-decode the plaintext into
//!    a typed [`ArchiveSegmentPayload`] (or any
//!    `serde::de::DeserializeOwned`).
//! 4. [`fetch_and_decrypt_segment`] — convenience wrapper that
//!    chains the first two steps.
//!
//! `docs/PROPOSAL.md §6.3` and §10.1 spell out the wire format the
//! reverse pipeline must round-trip; the unit tests below build a
//! segment with [`crate::archive::segment_builder::ArchiveSegmentBuilder`]
//! and decrypt it end-to-end via this module so any drift in the
//! compression / AEAD framing is caught at the binary level.

use std::sync::Arc;

use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::crypto::aead::xchacha20_poly1305::{open, NONCE_LEN};
use crate::crypto::content_hash::content_hash;
use crate::crypto::CryptoError;
use crate::local_store::schema::StorageBackend;
use crate::media::sinks::zk_fabric::{S3Client, ZkFabricSinkConfig};
use crate::transport::TransportClient;
use crate::Error;

use super::segment_builder::{ArchiveSegmentPayload, ARCHIVE_SEGMENT_PAYLOAD_MAGIC};

/// Header placed at the front of a serialized archive segment
/// before AEAD-seal. The on-disk layout produced by
/// [`crate::archive::segment_builder::ArchiveSegmentBuilder::build_segment`]
/// is:
///
/// ```text
///   [16 bytes]  segment_id        (UUID v7 raw bytes)
///   [32 bytes]  merkle_root       (BLAKE3 over plaintext payload)
///   [24 bytes]  nonce             (XChaCha20-Poly1305 nonce)
///   [N  bytes]  ciphertext        (sealed zstd(cbor(...)))
/// ```
///
/// Distinguishing the framing from the raw ciphertext keeps the
/// transport surface generic — callers can pass the entire blob
/// returned by `fetch_archive_segment` to
/// [`decrypt_archive_segment`] without having to remember a
/// separate header schema.
pub const ARCHIVE_SEGMENT_BLOB_HEADER_LEN: usize = 16 + 32 + NONCE_LEN;

/// Encode the on-the-wire archive segment blob:
/// `segment_id || merkle_root || nonce || ciphertext`.
///
/// Pairs with [`decode_archive_segment_blob`] / the
/// [`fetch_and_decrypt_segment`] download path.
pub fn encode_archive_segment_blob(
    segment_id: &Uuid,
    merkle_root: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ARCHIVE_SEGMENT_BLOB_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(segment_id.as_bytes());
    out.extend_from_slice(merkle_root);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Decoded view of an archive segment blob. The `nonce` and
/// `ciphertext` slices borrow from the input buffer to avoid
/// re-allocation on the decrypt path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedArchiveSegmentBlob<'a> {
    /// UUID v7 segment identifier.
    pub segment_id: Uuid,
    /// 32-byte BLAKE3 over the plaintext payload.
    pub merkle_root: [u8; 32],
    /// 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Sealed zstd(cbor(...)) bytes.
    pub ciphertext: &'a [u8],
}

/// Decode the on-the-wire archive segment blob layout produced by
/// [`encode_archive_segment_blob`].
pub fn decode_archive_segment_blob(bytes: &[u8]) -> Result<DecodedArchiveSegmentBlob<'_>, Error> {
    if bytes.len() < ARCHIVE_SEGMENT_BLOB_HEADER_LEN {
        return Err(Error::Storage(format!(
            "archive segment blob is {} bytes (expected at least {})",
            bytes.len(),
            ARCHIVE_SEGMENT_BLOB_HEADER_LEN
        )));
    }
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&bytes[0..16]);
    let segment_id = Uuid::from_bytes(id_bytes);

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&bytes[16..48]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[48..ARCHIVE_SEGMENT_BLOB_HEADER_LEN]);

    let ciphertext = &bytes[ARCHIVE_SEGMENT_BLOB_HEADER_LEN..];
    Ok(DecodedArchiveSegmentBlob {
        segment_id,
        merkle_root,
        nonce,
        ciphertext,
    })
}

/// Pull the encrypted bytes for `segment_id` from `transport`.
///
/// This is a thin wrapper around
/// [`crate::transport::TransportClient::fetch_archive_segment`] —
/// the decryption / decompression / decode happens in the
/// follow-on functions in this module so the transport can be
/// mocked in isolation.
pub fn download_archive_segment(
    transport: &dyn TransportClient,
    segment_id: &str,
) -> Result<Vec<u8>, Error> {
    transport.fetch_archive_segment(segment_id)
}

/// AEAD-open + zstd-decompress an archive segment blob under
/// `k_archive_segment`.
///
/// `bytes` is expected to be the on-the-wire blob (header +
/// ciphertext) produced by
/// [`crate::archive::segment_builder::ArchiveSegmentBuilder::build_segment`].
/// Returns the **plaintext CBOR bytes** of the
/// [`ArchiveSegmentPayload`]. The plaintext BLAKE3 is verified
/// against the header `merkle_root` so a tampered or
/// wrong-keyed blob fails before the caller sees any decoded
/// payload.
pub fn decrypt_archive_segment(
    bytes: &[u8],
    k_archive_segment: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let decoded = decode_archive_segment_blob(bytes)?;
    let aad = build_segment_aad(&decoded.segment_id, &decoded.merkle_root);
    let compressed =
        open(k_archive_segment, &decoded.nonce, decoded.ciphertext, &aad).map_err(Error::Crypto)?;
    let cbor = zstd::stream::decode_all(&compressed[..])
        .map_err(|e| Error::Storage(format!("archive segment zstd decode: {e}")))?;
    if content_hash(&cbor) != decoded.merkle_root {
        return Err(Error::Storage(
            "archive segment plaintext merkle_root mismatch".into(),
        ));
    }
    Ok(cbor)
}

/// CBOR-decode the plaintext bytes returned by
/// [`decrypt_archive_segment`] into any `serde::de::DeserializeOwned`.
///
/// The caller picks the destination type — the most common is
/// [`ArchiveSegmentPayload`], which carries the magic /
/// `conversation_id` / `time_bucket` / events. This helper exists
/// so the restore engine can ride the same code path against
/// alternative payload shapes (skeleton-only segments, search
/// shard segments, etc.) once those land.
pub fn decode_archive_segment<T: DeserializeOwned>(plaintext_cbor: &[u8]) -> Result<T, Error> {
    let payload: T = serde_cbor::from_slice(plaintext_cbor)
        .map_err(|e| Error::Storage(format!("archive segment cbor decode: {e}")))?;
    Ok(payload)
}

/// CBOR-decode an [`ArchiveSegmentPayload`] and verify the magic
/// bytes match the canonical [`ARCHIVE_SEGMENT_PAYLOAD_MAGIC`].
/// Use this for the standard segment shape; fall through to
/// [`decode_archive_segment`] for custom payload types.
pub fn decode_archive_segment_payload(
    plaintext_cbor: &[u8],
) -> Result<ArchiveSegmentPayload, Error> {
    let payload: ArchiveSegmentPayload = decode_archive_segment(plaintext_cbor)?;
    if payload.magic != ARCHIVE_SEGMENT_PAYLOAD_MAGIC {
        return Err(Error::Storage(
            "archive segment payload magic mismatch".into(),
        ));
    }
    Ok(payload)
}

/// Convenience wrapper: fetch the encrypted bytes for `segment_id`
/// from `transport` and AEAD-open + zstd-decompress them under
/// `k_archive_segment`. Returns the **plaintext CBOR bytes** —
/// pass them through [`decode_archive_segment_payload`] /
/// [`decode_archive_segment`] to land a typed payload.
pub fn fetch_and_decrypt_segment(
    transport: &dyn TransportClient,
    segment_id: &str,
    k_archive_segment: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let blob = download_archive_segment(transport, segment_id)?;
    decrypt_archive_segment(&blob, k_archive_segment)
}

// ---------------------------------------------------------------------------
// Phase-4 (Task 8): storage_backend-aware fetch routing.
// ---------------------------------------------------------------------------

/// Routing seam for archive-segment fetches.
///
/// `archive_segment_map.storage_backend` (`docs/PROPOSAL.md §10.1`)
/// records which backend an archive segment was uploaded under.
/// On the download path the orchestrator must route the fetch to
/// the matching backend — the legacy KChat blob service via
/// [`TransportClient::fetch_archive_segment`], or the ZK Object
/// Fabric tier via an [`S3Client`] and a configured
/// [`ZkFabricSinkConfig`].
///
/// This struct holds both fetcher implementations behind a single
/// borrow so the prefetch + rehydrate paths can dispatch in a
/// single step.
#[derive(Clone)]
pub struct ArchiveSegmentRouter<'a> {
    /// Always populated. Used when `storage_backend ==
    /// kchat_backend` (the default).
    pub transport: &'a dyn TransportClient,
    /// Optional ZKOF S3 client. Required when any segment row in
    /// `archive_segment_map` uses
    /// [`StorageBackend::ZkObjectFabric`]; absent when every row
    /// is on the legacy KChat backend.
    pub s3: Option<Arc<dyn S3Client>>,
    /// Optional ZKOF tenant configuration. Mirrors `s3` — the
    /// orchestrator either supplies both fields or neither.
    pub zkof_config: Option<ZkFabricSinkConfig>,
}

impl<'a> std::fmt::Debug for ArchiveSegmentRouter<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveSegmentRouter")
            .field("has_s3", &self.s3.is_some())
            .field("zkof_config", &self.zkof_config)
            .finish()
    }
}

impl<'a> ArchiveSegmentRouter<'a> {
    /// Build a router that only knows about the legacy KChat
    /// backend. Use when no segment row references
    /// [`StorageBackend::ZkObjectFabric`].
    pub fn kchat_only(transport: &'a dyn TransportClient) -> Self {
        Self {
            transport,
            s3: None,
            zkof_config: None,
        }
    }

    /// Build a router that can route to either the KChat backend
    /// or the ZKOF tier.
    pub fn with_zkof(
        transport: &'a dyn TransportClient,
        s3: Arc<dyn S3Client>,
        zkof_config: ZkFabricSinkConfig,
    ) -> Self {
        Self {
            transport,
            s3: Some(s3),
            zkof_config: Some(zkof_config),
        }
    }

    /// Fetch the encrypted archive-segment blob for `segment_id`
    /// from the backend named by `storage_backend`.
    ///
    /// Returns [`Error::Storage`] when the row references
    /// [`StorageBackend::ZkObjectFabric`] but the router was
    /// built without an S3 client (i.e. via [`Self::kchat_only`]).
    pub fn fetch(
        &self,
        storage_backend: StorageBackend,
        segment_id: &str,
    ) -> Result<Vec<u8>, Error> {
        match storage_backend {
            StorageBackend::KChatBackend => self.transport.fetch_archive_segment(segment_id),
            StorageBackend::ZkObjectFabric => {
                let s3 = self.s3.as_ref().ok_or_else(|| {
                    Error::Storage(
                        "ArchiveSegmentRouter: zk_object_fabric segment without s3 client".into(),
                    )
                })?;
                let cfg = self.zkof_config.as_ref().ok_or_else(|| {
                    Error::Storage(
                        "ArchiveSegmentRouter: zk_object_fabric segment without ZkFabricSinkConfig"
                            .into(),
                    )
                })?;
                let key = format!("archive/segments/{segment_id}");
                // Mirrors `ZkofBackupSink::fetch_backup_segment`:
                // S3 clamps the range to the object's length so
                // the magic-end is the simplest "fetch all" idiom.
                s3.get_object_range(&cfg.bucket, &key, 0..u64::MAX)
            }
        }
    }
}

/// Convenience wrapper: route a fetch through
/// [`ArchiveSegmentRouter::fetch`] and decrypt under
/// `k_archive_segment`. Mirrors [`fetch_and_decrypt_segment`].
pub fn fetch_and_decrypt_segment_for_backend(
    router: &ArchiveSegmentRouter<'_>,
    storage_backend: StorageBackend,
    segment_id: &str,
    k_archive_segment: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let blob = router.fetch(storage_backend, segment_id)?;
    decrypt_archive_segment(&blob, k_archive_segment)
}

/// Compute the AEAD AAD for an archive segment open. Mirror image
/// of `archive::segment_builder::build_segment_aad` (kept private
/// in that module to avoid leaking the AAD recipe).
fn build_segment_aad(segment_id: &Uuid, merkle_root: &[u8; 32]) -> Vec<u8> {
    const MAGIC: &[u8] = b"KCHAT_ARCHIVE_SEGMENT_V1";
    let mut aad = Vec::with_capacity(MAGIC.len() + 16 + 32);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(segment_id.as_bytes());
    aad.extend_from_slice(merkle_root);
    aad
}

// Re-export `CryptoError` so consumers can pattern-match on it
// without pulling the full `crate::crypto` surface.
pub use crate::crypto::CryptoError as ArchiveDownloadCryptoError;

/// Map a [`crate::Error`] returned by the decrypt path back to the
/// [`CryptoError`] discriminant when applicable. Useful for tests
/// that want to assert "open failed because the AEAD tag was
/// invalid" without leaking the `Error::Crypto` wrapper.
pub fn classify_decrypt_error(err: &Error) -> Option<&CryptoError> {
    match err {
        Error::Crypto(e) => Some(e),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::event_journal::{ArchiveEvent, ArchiveEventType};
    use crate::archive::segment_builder::{ArchiveSegmentBuilder, SegmentBuildRequest};
    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportClient, TransportResult,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ops::Range;
    use std::sync::Mutex;

    use crate::crypto::aead::BlobClass;

    // ---- Fixture transport ------------------------------------------------
    //
    // Mirrors `crates/core/src/archive/prefetch.rs::FixtureTransport` but
    // is scoped private to this test module. Returns canned
    // `fetch_archive_segment` payloads keyed on `segment_id` and tracks
    // call counts for assertions.

    #[derive(Default)]
    struct FixtureTransport {
        segments: Mutex<HashMap<String, Vec<u8>>>,
        fail_segments: Mutex<HashMap<String, Error>>,
        calls: Mutex<RefCell<usize>>,
    }

    impl FixtureTransport {
        fn new() -> Self {
            Self::default()
        }

        fn put(&self, segment_id: &str, blob: Vec<u8>) {
            self.segments
                .lock()
                .unwrap()
                .insert(segment_id.to_string(), blob);
        }

        fn fail(&self, segment_id: &str, err: Error) {
            self.fail_segments
                .lock()
                .unwrap()
                .insert(segment_id.to_string(), err);
        }

        fn call_count(&self) -> usize {
            *self.calls.lock().unwrap().borrow()
        }
    }

    impl TransportClient for FixtureTransport {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> TransportResult<FetchMessagesResponse> {
            Err(Error::NotImplemented("test transport: fetch_messages"))
        }

        fn init_blob_upload(
            &self,
            _size: u64,
            _blob_class: BlobClass,
            _expected_merkle_root: [u8; 32],
        ) -> TransportResult<BlobUploadHandle> {
            Err(Error::NotImplemented("test transport: init_blob_upload"))
        }

        fn upload_chunk(
            &self,
            _blob_id: &str,
            _chunk_idx: u32,
            _ciphertext: &[u8],
            _sha256: [u8; 32],
        ) -> TransportResult<ChunkReceipt> {
            Err(Error::NotImplemented("test transport: upload_chunk"))
        }

        fn commit_blob(&self, _blob_id: &str) -> TransportResult<CommitBlobResponse> {
            Err(Error::NotImplemented("test transport: commit_blob"))
        }

        fn fetch_blob_range(&self, _blob_id: &str, _range: Range<u64>) -> TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("test transport: fetch_blob_range"))
        }

        fn fetch_archive_manifests(
            &self,
            _after_generation: Option<u64>,
        ) -> TransportResult<Vec<EncryptedManifest>> {
            Err(Error::NotImplemented(
                "test transport: fetch_archive_manifests",
            ))
        }

        fn fetch_archive_segment(&self, segment_id: &str) -> TransportResult<Vec<u8>> {
            *self.calls.lock().unwrap().borrow_mut() += 1;
            if let Some(err) = self.fail_segments.lock().unwrap().get(segment_id) {
                return Err(match err {
                    Error::NotImplemented(s) => Error::NotImplemented(s),
                    Error::Storage(s) => Error::Storage(s.clone()),
                    other => Error::Storage(other.to_string()),
                });
            }
            self.segments
                .lock()
                .unwrap()
                .get(segment_id)
                .cloned()
                .ok_or_else(|| Error::Storage(format!("missing segment {segment_id}")))
        }

        fn fetch_index_shards(
            &self,
            _conversation_hash: &str,
            _bucket: &str,
            _shard_type: &str,
        ) -> TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("test transport: fetch_index_shards"))
        }
    }

    // ---- Helpers ----------------------------------------------------------

    fn sample_event(conv: Uuid, ms: i64, ty: ArchiveEventType) -> ArchiveEvent {
        ArchiveEvent {
            event_type: ty,
            conversation_id: conv,
            message_id: Some(Uuid::now_v7()),
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
            created_at_ms: ms,
        }
    }

    fn build_blob(k: &[u8; 32]) -> (Uuid, Vec<u8>, ArchiveSegmentPayload) {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: "2026-05".into(),
            events: vec![
                sample_event(conv, 1, ArchiveEventType::MessageReceived),
                sample_event(conv, 2, ArchiveEventType::MessageEdited),
            ],
        };
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), k)
            .unwrap();
        let blob = encode_archive_segment_blob(
            &built.segment_id,
            &built.merkle_root,
            &built.nonce,
            &built.ciphertext,
        );
        let expected_payload = ArchiveSegmentPayload {
            magic: ARCHIVE_SEGMENT_PAYLOAD_MAGIC.to_vec(),
            conversation_id: conv.to_string(),
            time_bucket: "2026-05".into(),
            events: req.events,
        };
        (built.segment_id, blob, expected_payload)
    }

    // ---- Tests ------------------------------------------------------------

    #[test]
    fn encode_decode_blob_round_trip_preserves_components() {
        let id = Uuid::now_v7();
        let merkle_root = [0xABu8; 32];
        let nonce = [0xCDu8; NONCE_LEN];
        let ciphertext = b"SOME-CIPHERTEXT".to_vec();
        let bytes = encode_archive_segment_blob(&id, &merkle_root, &nonce, &ciphertext);
        let dec = decode_archive_segment_blob(&bytes).unwrap();
        assert_eq!(dec.segment_id, id);
        assert_eq!(dec.merkle_root, merkle_root);
        assert_eq!(dec.nonce, nonce);
        assert_eq!(dec.ciphertext, &ciphertext[..]);
    }

    #[test]
    fn decode_blob_rejects_truncated_input() {
        let too_short = vec![0u8; ARCHIVE_SEGMENT_BLOB_HEADER_LEN - 1];
        let err = decode_archive_segment_blob(&too_short).unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn fetch_and_decrypt_round_trip_through_segment_builder() {
        let k = [0x77u8; 32];
        let (segment_id, blob, expected_payload) = build_blob(&k);

        let transport = FixtureTransport::new();
        transport.put(&segment_id.to_string(), blob);

        let plaintext = fetch_and_decrypt_segment(&transport, &segment_id.to_string(), &k).unwrap();
        let payload = decode_archive_segment_payload(&plaintext).unwrap();
        assert_eq!(payload, expected_payload);
        assert_eq!(transport.call_count(), 1);
    }

    #[test]
    fn decrypt_with_wrong_key_fails_aead_open() {
        let k = [0x11u8; 32];
        let wrong_k = [0x22u8; 32];
        let (_segment_id, blob, _expected_payload) = build_blob(&k);

        let err = decrypt_archive_segment(&blob, &wrong_k).unwrap_err();
        let cls = classify_decrypt_error(&err);
        assert!(
            cls.is_some(),
            "expected an AEAD CryptoError but got {err:?}"
        );
    }

    #[test]
    fn decrypt_corrupted_ciphertext_fails_aead_open() {
        let k = [0x55u8; 32];
        let (_segment_id, mut blob, _expected_payload) = build_blob(&k);
        // Flip a single bit in the AEAD ciphertext region (skip
        // past the header to land on the sealed bytes).
        blob[ARCHIVE_SEGMENT_BLOB_HEADER_LEN] ^= 0x01;
        let err = decrypt_archive_segment(&blob, &k).unwrap_err();
        let cls = classify_decrypt_error(&err);
        assert!(
            cls.is_some(),
            "expected an AEAD CryptoError but got {err:?}"
        );
    }

    #[test]
    fn decrypt_corrupted_merkle_root_breaks_aad() {
        let k = [0x09u8; 32];
        let (_segment_id, mut blob, _expected_payload) = build_blob(&k);
        // Flip the first byte of the merkle_root header field; this
        // changes the AAD so the AEAD-open MUST fail before we even
        // reach the plaintext-hash mismatch path.
        blob[16] ^= 0x80;
        let err = decrypt_archive_segment(&blob, &k).unwrap_err();
        let cls = classify_decrypt_error(&err);
        assert!(
            cls.is_some(),
            "expected an AEAD CryptoError but got {err:?}"
        );
    }

    #[test]
    fn fetch_and_decrypt_propagates_transport_error() {
        let k = [0x66u8; 32];
        let (segment_id, _blob, _) = build_blob(&k);

        let transport = FixtureTransport::new();
        transport.fail(
            &segment_id.to_string(),
            Error::Storage("transport unavailable".into()),
        );

        let err = fetch_and_decrypt_segment(&transport, &segment_id.to_string(), &k).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("transport unavailable"), "got {msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
        assert_eq!(transport.call_count(), 1);
    }

    #[test]
    fn decode_archive_segment_payload_rejects_wrong_magic() {
        let k = [0x44u8; 32];
        let (_segment_id, blob, _expected_payload) = build_blob(&k);
        let plaintext = decrypt_archive_segment(&blob, &k).unwrap();

        // Successful round-trip via the typed decoder.
        let payload = decode_archive_segment_payload(&plaintext).unwrap();
        assert_eq!(payload.magic, ARCHIVE_SEGMENT_PAYLOAD_MAGIC);

        // Now feed a CBOR blob that has a *different* magic — the
        // typed decoder must reject it.
        let mut tampered = ArchiveSegmentPayload {
            magic: b"NOT_A_KCHAT_SEGMENT".to_vec(),
            conversation_id: payload.conversation_id.clone(),
            time_bucket: payload.time_bucket.clone(),
            events: payload.events.clone(),
        };
        tampered.events.clear();
        let cbor = serde_cbor::to_vec(&tampered).unwrap();
        let err = decode_archive_segment_payload(&cbor).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("magic mismatch"), "got {msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn decode_archive_segment_generic_round_trips_through_serde_cbor() {
        let k = [0x99u8; 32];
        let (_segment_id, blob, expected_payload) = build_blob(&k);
        let plaintext = decrypt_archive_segment(&blob, &k).unwrap();

        let payload: ArchiveSegmentPayload = decode_archive_segment(&plaintext).unwrap();
        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn download_archive_segment_returns_transport_bytes_verbatim() {
        let transport = FixtureTransport::new();
        transport.put("seg-blob-1", b"raw-bytes".to_vec());
        let bytes = download_archive_segment(&transport, "seg-blob-1").unwrap();
        assert_eq!(bytes, b"raw-bytes");
        assert_eq!(transport.call_count(), 1);
    }
}
