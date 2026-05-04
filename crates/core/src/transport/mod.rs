//! `transport` module — Phase 1 abstraction over the MLS delivery
//! store and the broader Phase-2/3/4 transport surface.
//!
//! Two trait shapes live here:
//!
//! * [`DeliveryClient`] is the **narrow** Phase-1 trait used by
//!   [`crate::core_impl::CoreImpl::ingest_remote_messages`]. It
//!   carries a single cursor-paginated `fetch_messages` method and
//!   ships with a test-only [`MockDeliveryClient`] mock.
//! * [`TransportClient`] is the **broader** trait surface specified
//!   by `docs/PROPOSAL.md §10` and `docs/ARCHITECTURE.md §10`,
//!   covering MLS message fetch, chunked blob upload (init / chunk
//!   / commit), blob range fetch, archive manifest / segment fetch,
//!   and search-index shard fetch. It is locked in Phase 1 so the
//!   Phase-2 media engine, the Phase-3 archive engine, and the
//!   Phase-4 backup / restore engines can already type their inputs
//!   against the final shape; production HTTP / gRPC / MLS-blob
//!   implementations land in those phases. [`NoopTransportClient`]
//!   is the Phase-1 placeholder — every method returns
//!   `Err(crate::Error::NotImplemented("transport"))`.
//!
//! `docs/PROPOSAL.md §10` and `docs/ARCHITECTURE.md §10.4` describe
//! the cursor-based fetch contract: the local core asks the
//! transport for the messages newer than its last delivery cursor,
//! the transport returns a page plus the next cursor, and the core
//! persists each `RawDeliveryMessage` through the
//! [`crate::message::processor::MessagePersister`].
//!
//! The shape of this module's public re-exports is intentionally
//! narrow so it can grow without breaking downstream callers.

pub mod offline;

use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::crypto::aead::BlobClass;
use crate::formats::media_descriptor::MediaDescriptor;

/// Network / delivery-store errors surfaced through
/// [`DeliveryClient`].
///
/// Variants are intentionally coarse — the transport layer is
/// expected to flatten provider-specific HTTP / gRPC / MLS errors
/// into one of the three categories below so the upper layers can
/// route on intent (retry the request, prompt for re-auth, surface
/// to the user) without parsing free-form text.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// A network-level failure — DNS, TCP, TLS, timeout, retryable
    /// 5xx without an explicit reason. Callers may retry with
    /// backoff.
    #[error("network: {0}")]
    Network(String),

    /// The credential / token was rejected. Callers should refresh
    /// the credential before retrying.
    #[error("auth: {0}")]
    Auth(String),

    /// Server-reported, non-retryable failure (4xx other than auth,
    /// payload corruption, missing conversation, …).
    #[error("server: {0}")]
    Server(String),
}

/// One MLS-decrypted message returned by [`DeliveryClient::fetch_messages`].
///
/// `RawDeliveryMessage` is intentionally **string-typed** for ids:
/// the transport layer is responsible for whatever id format the
/// delivery store uses, and the upper layers parse them into
/// [`uuid::Uuid`] before persisting. This keeps the transport
/// trait portable across HTTP / gRPC / MLS-blob backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawDeliveryMessage {
    /// Stable message identifier (UUID v7 string).
    pub message_id: String,
    /// Owning conversation (UUID string).
    pub conversation_id: String,
    /// Sender identifier — opaque from this library's perspective.
    pub sender_id: String,
    /// Wall-clock millisecond timestamp set by the sender.
    pub created_at_ms: i64,
    /// Plaintext text body, when present.
    pub text_content: Option<String>,
    /// Zero or more media descriptors per `docs/PROPOSAL.md §3.2`.
    pub media_descriptors: Vec<MediaDescriptor>,
    /// Identifier of the message this is a reply to, if any.
    pub reply_to: Option<String>,
}

/// One page of [`RawDeliveryMessage`]s plus the cursor the caller
/// should pass on the next [`DeliveryClient::fetch_messages`]
/// invocation.
///
/// `next_cursor == None` signals the delivery store has no more
/// messages newer than the highest `created_at_ms` returned in
/// `messages`.
#[derive(Debug, Clone, Default)]
pub struct FetchResult {
    /// Messages returned by this fetch, in delivery-store order.
    pub messages: Vec<RawDeliveryMessage>,
    /// Opaque cursor for the next call, or `None` if the store is
    /// drained.
    pub next_cursor: Option<String>,
}

/// Transport-layer abstraction over the MLS delivery store.
///
/// **Object-safe.** The trait carries no generic methods and no
/// `Self`-typed return values, so `Box<dyn DeliveryClient>` is a
/// valid type — that's exactly how
/// [`crate::core_impl::CoreImpl::with_transport`] receives the
/// implementation.
pub trait DeliveryClient: Send + Sync {
    /// Pull the next page of messages for `conversation_id`,
    /// resuming after `after_cursor`. `after_cursor == None` means
    /// "start from the device's last known cursor" — implementers
    /// that persist their own cursor state may interpret this as
    /// "from the beginning".
    fn fetch_messages(
        &self,
        conversation_id: &str,
        after_cursor: Option<&str>,
    ) -> Result<FetchResult, TransportError>;
}

// ---------------------------------------------------------------------------
// Test-only mock
// ---------------------------------------------------------------------------

/// In-memory test double for [`DeliveryClient`].
///
/// Tests call [`MockDeliveryClient::with_response`] to pre-stage one
/// or more `(after_cursor → FetchResult)` mappings, then hand the
/// mock to `CoreImpl::with_transport`. Each call to
/// [`MockDeliveryClient::fetch_messages`] also records the
/// `after_cursor` it was invoked with so the test can assert that
/// the upper layers forwarded the cursor verbatim.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MockDeliveryClient {
    inner: std::sync::Mutex<MockState>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct MockState {
    /// Pre-staged responses. Keyed by the optional `after_cursor`
    /// the upper layer will pass — `None` matches the first call.
    responses: Vec<(Option<String>, Result<FetchResult, TransportError>)>,
    /// Recorded `after_cursor` arguments, in call order.
    seen_cursors: Vec<Option<String>>,
}

#[cfg(test)]
impl MockDeliveryClient {
    /// Construct a new, empty mock. Tests stage responses with
    /// [`MockDeliveryClient::with_response`].
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(MockState::default()),
        }
    }

    /// Pre-stage a single response. Responses are consumed in FIFO
    /// order; the `after_cursor` argument on each
    /// [`MockDeliveryClient::fetch_messages`] call must match the
    /// `after_cursor` recorded here, otherwise the test fails fast.
    pub fn with_response(
        self,
        after_cursor: Option<&str>,
        response: Result<FetchResult, TransportError>,
    ) -> Self {
        {
            let mut state = self.inner.lock().expect("mock state poisoned");
            state
                .responses
                .push((after_cursor.map(|s| s.to_string()), response));
        }
        self
    }

    /// Snapshot the recorded cursors so far. Call sites use this to
    /// assert the upper layer forwarded `after_cursor` verbatim.
    pub fn seen_cursors(&self) -> Vec<Option<String>> {
        self.inner
            .lock()
            .expect("mock state poisoned")
            .seen_cursors
            .clone()
    }
}

#[cfg(test)]
impl DeliveryClient for MockDeliveryClient {
    fn fetch_messages(
        &self,
        _conversation_id: &str,
        after_cursor: Option<&str>,
    ) -> Result<FetchResult, TransportError> {
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.seen_cursors.push(after_cursor.map(|s| s.to_string()));
        if state.responses.is_empty() {
            return Err(TransportError::Server(
                "MockDeliveryClient: no response staged".into(),
            ));
        }
        let (expected_cursor, response) = state.responses.remove(0);
        let actual_cursor = after_cursor.map(|s| s.to_string());
        assert_eq!(
            expected_cursor, actual_cursor,
            "MockDeliveryClient: unexpected after_cursor",
        );
        response
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_error_display_strings() {
        assert!(TransportError::Network("dns".into())
            .to_string()
            .starts_with("network:"));
        assert!(TransportError::Auth("token".into())
            .to_string()
            .starts_with("auth:"));
        assert!(TransportError::Server("500".into())
            .to_string()
            .starts_with("server:"));
    }

    #[test]
    fn fetch_result_default_is_empty() {
        let r = FetchResult::default();
        assert!(r.messages.is_empty());
        assert!(r.next_cursor.is_none());
    }

    #[test]
    fn delivery_client_is_object_safe() {
        // Compile-time check: trait must support dynamic dispatch
        // for `CoreImpl::with_transport` to take a
        // `Box<dyn DeliveryClient>`.
        let _b: Box<dyn DeliveryClient> = Box::new(MockDeliveryClient::new());
    }

    #[test]
    fn mock_delivery_client_returns_staged_response() {
        let raw = RawDeliveryMessage {
            message_id: "m-1".into(),
            conversation_id: "c-1".into(),
            sender_id: "u-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("hello".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        let staged = FetchResult {
            messages: vec![raw.clone()],
            next_cursor: Some("cursor-1".into()),
        };
        let mock = MockDeliveryClient::new().with_response(None, Ok(staged.clone()));
        let got = mock.fetch_messages("c-1", None).expect("mock response");
        assert_eq!(got.messages, staged.messages);
        assert_eq!(got.next_cursor, staged.next_cursor);
        assert_eq!(mock.seen_cursors(), vec![None]);
    }

    #[test]
    fn mock_delivery_client_records_cursor() {
        let mock = MockDeliveryClient::new()
            .with_response(None, Ok(FetchResult::default()))
            .with_response(Some("cursor-1"), Ok(FetchResult::default()));
        mock.fetch_messages("c-1", None).unwrap();
        mock.fetch_messages("c-1", Some("cursor-1")).unwrap();
        assert_eq!(
            mock.seen_cursors(),
            vec![None, Some("cursor-1".to_string())]
        );
    }

    #[test]
    fn mock_delivery_client_can_return_error() {
        let mock = MockDeliveryClient::new()
            .with_response(None, Err(TransportError::Network("offline".into())));
        let err = mock.fetch_messages("c-1", None).unwrap_err();
        assert!(matches!(err, TransportError::Network(_)));
    }

    #[test]
    fn raw_delivery_message_default_shape() {
        // Smoke test that the public field set is still constructable
        // — guards against accidental field renames breaking the
        // bridge layer.
        let _ = RawDeliveryMessage {
            message_id: String::new(),
            conversation_id: String::new(),
            sender_id: String::new(),
            created_at_ms: 0,
            text_content: None,
            media_descriptors: vec![],
            reply_to: None,
        };
    }
}

// ---------------------------------------------------------------------------
// TransportClient — broader surface (`docs/PROPOSAL.md §10`)
// ---------------------------------------------------------------------------

/// Cursor-paginated MLS message fetch response.
///
/// Returned by [`TransportClient::fetch_messages`]. Mirrors
/// [`FetchResult`] but carries the canonical name from
/// `docs/PROPOSAL.md §10` so the broader trait shape can grow
/// independently of the narrow [`DeliveryClient`] used by
/// [`crate::core_impl::CoreImpl::ingest_remote_messages`] today.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchMessagesResponse {
    /// Messages returned by this fetch, in delivery-store order.
    pub messages: Vec<RawDeliveryMessage>,
    /// Opaque cursor for the next call, or `None` if the store is
    /// drained.
    pub next_cursor: Option<String>,
}

/// Handle returned from [`TransportClient::init_blob_upload`].
///
/// `blob_id` is the server-assigned identifier the client uses for
/// every subsequent `upload_chunk` and `commit_blob` call. The
/// `expires_at_ms` field bounds how long the upload session
/// remains live so callers can fail fast on expired handles
/// instead of repeatedly probing the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobUploadHandle {
    /// Server-assigned blob identifier.
    pub blob_id: String,
    /// Class of object being uploaded — must match the value passed
    /// to [`TransportClient::init_blob_upload`].
    pub blob_class: BlobClass,
    /// Wall-clock millisecond timestamp at which the upload
    /// handle expires.
    pub expires_at_ms: i64,
}

/// Receipt acknowledging a single chunk landing on the server.
///
/// Returned by [`TransportClient::upload_chunk`]. The server
/// echoes the `chunk_idx` and `sha256` it stored so the client can
/// detect a mid-stream corruption (mismatched digest) before
/// committing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkReceipt {
    /// Blob identifier from [`BlobUploadHandle::blob_id`].
    pub blob_id: String,
    /// Zero-based chunk index that was stored.
    pub chunk_idx: u32,
    /// SHA-256 of the **ciphertext** the server received.
    pub sha256: [u8; 32],
}

/// Server-side commit confirmation for a chunked blob upload.
///
/// Returned by [`TransportClient::commit_blob`]. The
/// `merkle_root` is the BLAKE3 Merkle root the server computed
/// over the committed chunks; the client compares it against the
/// `expected_merkle_root` it passed to
/// [`TransportClient::init_blob_upload`] to detect cross-chunk
/// corruption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitBlobResponse {
    /// Blob identifier from [`BlobUploadHandle::blob_id`].
    pub blob_id: String,
    /// Number of chunks the server actually committed.
    pub chunk_count: u32,
    /// BLAKE3 Merkle root over the committed ciphertext chunks.
    pub merkle_root: [u8; 32],
}

/// One archive manifest pulled by
/// [`TransportClient::fetch_archive_manifests`].
///
/// `payload` is the **encrypted** manifest bytes; decryption /
/// signature verification is the archive engine's job, not the
/// transport layer's. `previous_manifest_hash` is surfaced
/// pre-decryption so the engine can chain-verify generations
/// without holding multiple decrypted manifests in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedManifest {
    /// Manifest generation number — strictly increases per device.
    pub generation: u64,
    /// 32-byte hash of the previous manifest in the chain. The
    /// genesis manifest sets this to all zeros.
    pub previous_manifest_hash: [u8; 32],
    /// Encrypted manifest bytes (CBOR + AEAD).
    pub payload: Vec<u8>,
}

/// Top-level error type for [`TransportClient`].
///
/// The `TransportClient` surface returns the **crate-level**
/// [`crate::Result`] / [`crate::Error`] rather than
/// [`TransportError`] so it composes cleanly with the rest of
/// the public API: `CoreImpl` already propagates
/// `Error::NotImplemented` and `Error::Transport`, and the
/// [`NoopTransportClient`] placeholder maps to
/// `Error::NotImplemented("transport")` for every method.
pub type TransportResult<T> = crate::Result<T>;

/// Phase-1 transport surface — `docs/PROPOSAL.md §10`,
/// `docs/ARCHITECTURE.md §10`.
///
/// **Async note.** The methods are declared as synchronous
/// `Result<_>`-returning functions for now, matching the pattern in
/// [`crate::KChatCore`] (see `crates/core/src/lib.rs` lines
/// 329-333). Phase 2+ flips them to `async fn` once the production
/// HTTP / gRPC / MLS-blob clients land.
///
/// **Object-safe.** No generic methods, no `Self`-typed return
/// values, so `Box<dyn TransportClient>` is a valid type. Callers
/// are expected to inject the trait object the same way
/// [`crate::core_impl::CoreImpl::with_transport`] receives the
/// narrow [`DeliveryClient`].
pub trait TransportClient: Send + Sync {
    /// Pull the next page of MLS messages for `conversation_id`,
    /// resuming after `after_cursor`. Mirrors
    /// [`DeliveryClient::fetch_messages`] but returns the
    /// canonical [`FetchMessagesResponse`] shape.
    fn fetch_messages(
        &self,
        conversation_id: &str,
        after_cursor: Option<&str>,
    ) -> TransportResult<FetchMessagesResponse>;

    /// Open a chunked blob upload session for `size` ciphertext
    /// bytes of `blob_class`. The client commits to the
    /// `expected_merkle_root` up front so the server can reject
    /// the commit early if the per-chunk uploads diverge from the
    /// declared root.
    fn init_blob_upload(
        &self,
        size: u64,
        blob_class: BlobClass,
        expected_merkle_root: [u8; 32],
    ) -> TransportResult<BlobUploadHandle>;

    /// Push one ciphertext chunk to the server. `sha256` is the
    /// SHA-256 of the ciphertext bytes; the server stores both the
    /// bytes and the digest so an out-of-band corruption check can
    /// be raised before the commit.
    fn upload_chunk(
        &self,
        blob_id: &str,
        chunk_idx: u32,
        ciphertext: &[u8],
        sha256: [u8; 32],
    ) -> TransportResult<ChunkReceipt>;

    /// Finalize the upload session opened by
    /// [`Self::init_blob_upload`]. The returned `merkle_root`
    /// must equal the `expected_merkle_root` passed to
    /// `init_blob_upload`; otherwise the caller surfaces an
    /// integrity error and discards the blob.
    fn commit_blob(&self, blob_id: &str) -> TransportResult<CommitBlobResponse>;

    /// Fetch a byte range of a previously committed blob. Used by
    /// the Phase-3 archive / Phase-4 restore engines for
    /// scroll-back rehydration and partial-segment download.
    fn fetch_blob_range(&self, blob_id: &str, range: Range<u64>) -> TransportResult<Vec<u8>>;

    /// Pull every archive manifest with `generation > after_generation`.
    /// `after_generation == None` means "from genesis" and is used
    /// once at first-run time; subsequent calls pass the local
    /// device's last-seen generation.
    fn fetch_archive_manifests(
        &self,
        after_generation: Option<u64>,
    ) -> TransportResult<Vec<EncryptedManifest>>;

    /// Fetch a whole archive segment by id. The returned bytes are
    /// the encrypted segment payload (CBOR + AEAD); decryption
    /// happens in the archive engine.
    fn fetch_archive_segment(&self, segment_id: &str) -> TransportResult<Vec<u8>>;

    /// Fetch the encrypted search-index shards covering
    /// `(conversation_hash, bucket, shard_type)`. Returned bytes
    /// are the concatenated shard payloads in
    /// `docs/PROPOSAL.md §7.8` framing.
    fn fetch_index_shards(
        &self,
        conversation_hash: &str,
        bucket: &str,
        shard_type: &str,
    ) -> TransportResult<Vec<u8>>;

    /// Upload one encrypted search-index shard for the supplied
    /// `(conversation_hash, bucket, shard_type)` triple. The bytes
    /// are the CBOR-encoded
    /// [`crate::formats::search_shard::SearchIndexShard`] frame —
    /// the AEAD seal is already wrapped around the FTS / fuzzy
    /// payload by [`crate::search::shard_builder::build_text_search_shard`]
    /// and friends, so the transport layer only needs to ferry
    /// opaque bytes.
    ///
    /// `shard_type` matches the `shard_type` parameter of
    /// [`Self::fetch_index_shards`] (`"text"`, `"fuzzy"`, …) so
    /// the upload + fetch sides agree on a single addressing
    /// scheme.
    ///
    /// Default impl returns
    /// [`crate::Error::NotImplemented("transport_upload_index_shard")`]
    /// so existing implementations don't need to bump.
    fn upload_index_shard(
        &self,
        _conversation_hash: &str,
        _bucket: &str,
        _shard_type: &str,
        _ciphertext: &[u8],
    ) -> TransportResult<()> {
        Err(crate::Error::NotImplemented("transport_upload_index_shard"))
    }
}

/// Phase-1 placeholder [`TransportClient`] implementation.
///
/// Every method returns
/// `Err(crate::Error::NotImplemented("transport"))`. `CoreImpl`
/// uses this as the default until a production transport is
/// installed by Phase 2+ work, so callers can already type their
/// inputs against the final shape without waiting for the real
/// HTTP / gRPC / MLS-blob client to land.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTransportClient;

impl NoopTransportClient {
    /// Construct a new [`NoopTransportClient`].
    pub const fn new() -> Self {
        Self
    }
}

impl TransportClient for NoopTransportClient {
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
        Err(crate::Error::NotImplemented("transport"))
    }

    fn upload_chunk(
        &self,
        _blob_id: &str,
        _chunk_idx: u32,
        _ciphertext: &[u8],
        _sha256: [u8; 32],
    ) -> TransportResult<ChunkReceipt> {
        Err(crate::Error::NotImplemented("transport"))
    }

    fn commit_blob(&self, _blob_id: &str) -> TransportResult<CommitBlobResponse> {
        Err(crate::Error::NotImplemented("transport"))
    }

    fn fetch_blob_range(&self, _blob_id: &str, _range: Range<u64>) -> TransportResult<Vec<u8>> {
        Err(crate::Error::NotImplemented("transport"))
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

// ---------------------------------------------------------------------------
// MockTransportClient — programmable test double
// ---------------------------------------------------------------------------

/// In-memory programmable [`TransportClient`] mock, sized to the
/// Phase 5 + Phase 7 test surfaces.
///
/// `MockTransportClient` covers the two transport
/// surfaces the encrypted-shard pipeline cares about:
///
/// 1. [`TransportClient::fetch_index_shards`] — backed by a
///    `(conversation_hash, bucket, shard_type) → ciphertext` map
///    seeded with [`MockTransportClient::stage_index_shard`]. An
///    unset entry returns `Ok(Vec::new())`, matching the
///    "no shard uploaded yet" contract documented on
///    [`TransportClient::fetch_index_shards`] and exercised by
///    the cold-result hydration path in
///    [`crate::search::query_engine::QueryEngine::execute_search_with_cold_source`].
///
/// 2. [`TransportClient::upload_index_shard`] — captures the
///    uploaded `(triple, ciphertext)` so tests can assert the
///    upload pipeline produced exactly the bytes the build step
///    sealed.
///
/// Programmable failure injection is supplied via
/// [`MockTransportClient::fail_index_shard_fetch_with`] and
/// [`MockTransportClient::fail_index_shard_upload_with`] so the
/// Phase-7 failure-suite tests (`docs/PHASES.md §Phase 7`) can
/// drive transport errors without spinning up a custom mock per
/// scenario.
///
/// Every other [`TransportClient`] method (`fetch_messages`,
/// `init_blob_upload`, …) returns
/// `Err(crate::Error::NotImplemented("transport"))` so this mock
/// does not silently mask call-sites that need a different
/// transport surface.
#[derive(Debug, Default)]
pub struct MockTransportClient {
    inner: std::sync::Mutex<MockTransportState>,
}

#[derive(Debug, Default)]
struct MockTransportState {
    /// Pre-staged shard responses, keyed by
    /// `(conversation_hash, bucket, shard_type)`.
    fetch_responses: std::collections::HashMap<(String, String, String), Vec<u8>>,
    /// Recorded `fetch_index_shards` calls, in order.
    fetch_calls: Vec<(String, String, String)>,
    /// Recorded `upload_index_shard` calls, in order.
    upload_calls: Vec<(String, String, String, Vec<u8>)>,
    /// Programmable, key-scoped failure for shard fetches. When set
    /// for a `(hash, bucket, type)` triple the next call to
    /// `fetch_index_shards` for that triple returns
    /// `Err(Error::Transport(message))` and the entry is consumed.
    fail_fetch_once: std::collections::HashMap<(String, String, String), String>,
    /// Programmable, key-scoped failure for shard uploads. When set
    /// for a triple the next call to `upload_index_shard` returns
    /// `Err(Error::Transport(message))` and the entry is consumed.
    fail_upload_once: std::collections::HashMap<(String, String, String), String>,
}

impl MockTransportClient {
    /// Construct a new, empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-stage one ciphertext shard response for the supplied
    /// `(conversation_hash, bucket, shard_type)`.
    pub fn stage_index_shard(
        &self,
        conversation_hash: &str,
        bucket: &str,
        shard_type: &str,
        ciphertext: Vec<u8>,
    ) {
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.fetch_responses.insert(
            (conversation_hash.into(), bucket.into(), shard_type.into()),
            ciphertext,
        );
    }

    /// Programme the next `fetch_index_shards` call for
    /// `(conversation_hash, bucket, shard_type)` to fail with
    /// `Error::Transport(message)`. The failure is consumed on
    /// the first matching call, so subsequent calls fall back to
    /// any staged ciphertext.
    pub fn fail_index_shard_fetch_with(
        &self,
        conversation_hash: &str,
        bucket: &str,
        shard_type: &str,
        message: impl Into<String>,
    ) {
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.fail_fetch_once.insert(
            (conversation_hash.into(), bucket.into(), shard_type.into()),
            message.into(),
        );
    }

    /// Programme the next `upload_index_shard` call for the
    /// supplied triple to fail with `Error::Transport(message)`.
    pub fn fail_index_shard_upload_with(
        &self,
        conversation_hash: &str,
        bucket: &str,
        shard_type: &str,
        message: impl Into<String>,
    ) {
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.fail_upload_once.insert(
            (conversation_hash.into(), bucket.into(), shard_type.into()),
            message.into(),
        );
    }

    /// Snapshot the recorded `fetch_index_shards` calls.
    pub fn fetch_calls(&self) -> Vec<(String, String, String)> {
        self.inner
            .lock()
            .expect("mock state poisoned")
            .fetch_calls
            .clone()
    }

    /// Snapshot the recorded `upload_index_shard` calls. Each entry
    /// is `(conversation_hash, bucket, shard_type, ciphertext)`.
    pub fn upload_calls(&self) -> Vec<(String, String, String, Vec<u8>)> {
        self.inner
            .lock()
            .expect("mock state poisoned")
            .upload_calls
            .clone()
    }
}

impl TransportClient for MockTransportClient {
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
        Err(crate::Error::NotImplemented("transport"))
    }

    fn upload_chunk(
        &self,
        _blob_id: &str,
        _chunk_idx: u32,
        _ciphertext: &[u8],
        _sha256: [u8; 32],
    ) -> TransportResult<ChunkReceipt> {
        Err(crate::Error::NotImplemented("transport"))
    }

    fn commit_blob(&self, _blob_id: &str) -> TransportResult<CommitBlobResponse> {
        Err(crate::Error::NotImplemented("transport"))
    }

    fn fetch_blob_range(&self, _blob_id: &str, _range: Range<u64>) -> TransportResult<Vec<u8>> {
        Err(crate::Error::NotImplemented("transport"))
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
        conversation_hash: &str,
        bucket: &str,
        shard_type: &str,
    ) -> TransportResult<Vec<u8>> {
        let mut state = self.inner.lock().expect("mock state poisoned");
        let key = (
            conversation_hash.to_string(),
            bucket.to_string(),
            shard_type.to_string(),
        );
        state.fetch_calls.push(key.clone());
        if let Some(msg) = state.fail_fetch_once.remove(&key) {
            return Err(crate::Error::Transport(msg));
        }
        Ok(state.fetch_responses.get(&key).cloned().unwrap_or_default())
    }

    fn upload_index_shard(
        &self,
        conversation_hash: &str,
        bucket: &str,
        shard_type: &str,
        ciphertext: &[u8],
    ) -> TransportResult<()> {
        let mut state = self.inner.lock().expect("mock state poisoned");
        let key = (
            conversation_hash.to_string(),
            bucket.to_string(),
            shard_type.to_string(),
        );
        if let Some(msg) = state.fail_upload_once.remove(&key) {
            // Record the failed attempt anyway so callers can
            // detect the retry pattern.
            state.upload_calls.push((
                conversation_hash.into(),
                bucket.into(),
                shard_type.into(),
                ciphertext.to_vec(),
            ));
            return Err(crate::Error::Transport(msg));
        }
        state.upload_calls.push((
            conversation_hash.into(),
            bucket.into(),
            shard_type.into(),
            ciphertext.to_vec(),
        ));
        // Cross-wire: a successful upload also seeds the fetch
        // response so the round-trip read path returns the same
        // bytes that were just uploaded.
        state.fetch_responses.insert(key, ciphertext.to_vec());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TransportClient tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod transport_client_tests {
    use super::*;

    fn assert_not_implemented<T: std::fmt::Debug>(res: TransportResult<T>) {
        match res {
            Err(crate::Error::NotImplemented("transport")) => {}
            other => panic!("expected Err(NotImplemented(\"transport\")), got {other:?}"),
        }
    }

    #[test]
    fn transport_client_is_object_safe() {
        // Compile-time check: the trait must support dynamic
        // dispatch so callers can hold a `Box<dyn TransportClient>`.
        let _b: Box<dyn TransportClient> = Box::new(NoopTransportClient::new());
    }

    #[test]
    fn noop_transport_fetch_messages_is_not_implemented() {
        let t = NoopTransportClient::new();
        assert_not_implemented(t.fetch_messages("c-1", None));
        assert_not_implemented(t.fetch_messages("c-1", Some("cursor")));
    }

    #[test]
    fn noop_transport_blob_upload_path_is_not_implemented() {
        let t = NoopTransportClient::new();
        assert_not_implemented(t.init_blob_upload(1024, BlobClass::Media, [0u8; 32]));
        assert_not_implemented(t.upload_chunk("blob-1", 0, &[0xAA; 16], [0u8; 32]));
        assert_not_implemented(t.commit_blob("blob-1"));
    }

    #[test]
    fn noop_transport_blob_range_is_not_implemented() {
        let t = NoopTransportClient::new();
        assert_not_implemented(t.fetch_blob_range("blob-1", 0..16));
    }

    #[test]
    fn noop_transport_archive_path_is_not_implemented() {
        let t = NoopTransportClient::new();
        assert_not_implemented(t.fetch_archive_manifests(None));
        assert_not_implemented(t.fetch_archive_manifests(Some(7)));
        assert_not_implemented(t.fetch_archive_segment("segment-1"));
    }

    #[test]
    fn noop_transport_index_shard_is_not_implemented() {
        let t = NoopTransportClient::new();
        assert_not_implemented(t.fetch_index_shards("hash-1", "2026-04", "fts"));
    }

    #[test]
    fn fetch_messages_response_round_trips_through_serde() {
        let r = FetchMessagesResponse {
            messages: vec![RawDeliveryMessage {
                message_id: "m-1".into(),
                conversation_id: "c-1".into(),
                sender_id: "u-1".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: Some("hello".into()),
                media_descriptors: vec![],
                reply_to: None,
            }],
            next_cursor: Some("cursor-1".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: FetchMessagesResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn blob_upload_handle_round_trips_through_serde() {
        let h = BlobUploadHandle {
            blob_id: "blob-9".into(),
            blob_class: BlobClass::ArchiveSegment,
            expires_at_ms: 1_700_000_000_999,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: BlobUploadHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn chunk_receipt_round_trips_through_serde() {
        let c = ChunkReceipt {
            blob_id: "blob-9".into(),
            chunk_idx: 4,
            sha256: [0xAB; 32],
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: ChunkReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn commit_blob_response_round_trips_through_serde() {
        let c = CommitBlobResponse {
            blob_id: "blob-9".into(),
            chunk_count: 5,
            merkle_root: [0xCD; 32],
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: CommitBlobResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn encrypted_manifest_round_trips_through_serde() {
        let m = EncryptedManifest {
            generation: 12,
            previous_manifest_hash: [0xEF; 32],
            payload: vec![0x01, 0x02, 0x03],
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: EncryptedManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn blob_class_round_trips_through_serde() {
        // Spot-check every variant so the snake_case representation
        // is locked down.
        for (variant, expected) in [
            (BlobClass::Media, "\"media\""),
            (BlobClass::ArchiveSegment, "\"archive_segment\""),
            (BlobClass::SearchIndexShard, "\"search_index_shard\""),
            (BlobClass::BackupSegment, "\"backup_segment\""),
            (BlobClass::Manifest, "\"manifest\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected, "for variant {variant:?}");
            let back: BlobClass = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }
}
