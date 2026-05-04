//! kchat-core — platform-agnostic core for the KChat storage and
//! search engine.
//!
//! Phase 0 establishes the on-disk and on-wire crypto contract:
//! BLAKE3 content hashing, the [`crypto::key_hierarchy`] HKDF-SHA256
//! derivation tree, the AEAD constructions in [`crypto::aead`], the
//! Pattern C convergent encryption in [`crypto::convergent`]
//! (bit-identical to the Go SDK at
//! `kennguy3n/zk-object-fabric/encryption/client_sdk`), the
//! AES-256-KW key wrapping in [`crypto::key_wrap`], and the
//! multilingual tokenization spec in [`search::tokenizer`].
//!
//! [`formats`] holds the CBOR wire-format types — backup / archive
//! segment frames, manifest frames (with Ed25519 signatures and the
//! `previous_manifest_hash` chain), the media descriptor, and the
//! search index shard — that travel between the device and the
//! KChat backend / ZK Object Fabric backup sink.
//!
//! Phase 1 starts the on-device persistence layer:
//!
//! * [`local_store::schema`] — typed Rust row structs for every
//!   SQLCipher table, plus the `SCHEMA_SQL` constant carrying the
//!   `CREATE TABLE` statements verbatim from
//!   `docs/ARCHITECTURE.md §4`.
//! * [`local_store::state_machines`] — the `body_state`,
//!   `media_state`, `archive_state`, `backup_state`, and
//!   `restore_state` enums with `try_transition`, `Display` /
//!   `FromStr`, and serde support.
//! * [`message::processor`] — `IngestedMessage`, `OutboxEntry`,
//!   `IngestResult`, and the pure-Rust validators the Phase-1
//!   SQLCipher integration will sit behind.
//!
//! The remaining higher-level modules (`media`, `archive`, `backup`,
//! `offload`, `restore`, `models`, `transport`, `scheduler`) are
//! stubbed in Phase 0 and filled in as later phases land. See
//! `docs/PHASES.md` for the schedule.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod archive;
pub mod backup;
pub mod config;
pub mod core_impl;
pub mod crypto;
pub mod desktop_index;
pub mod formats;
pub mod local_store;
pub mod media;
pub mod message;
pub mod models;
pub mod offload;
pub mod perf;
pub mod restore;
pub mod scheduler;
pub mod search;
pub mod transport;

pub use config::KChatCoreConfig;
pub use core_impl::CoreImpl;
pub use formats::media_descriptor::MediaDescriptor;
pub use local_store::schema::TimelineRow;
pub use transport::{
    BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest, FetchMessagesResponse,
    NoopTransportClient, TransportClient,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::message::processor::IngestResult;

/// Top-level error type for the core library. Phase 0 carried crypto
/// and configuration errors only; Phase 1 widens the surface for
/// storage / search / message / transport failures so the bridge
/// crates can pattern-match on the right variant.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A crypto primitive (key derivation, AEAD seal/open, hashing)
    /// failed.
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),

    /// A storage-layer call failed (SQLCipher open, AEAD-seal-on-write,
    /// schema migration, …).
    #[error("storage: {0}")]
    Storage(String),

    /// A search-layer call failed (FTS5 query parse, fuzzy / vector
    /// fan-out, ranking, …).
    #[error("search: {0}")]
    Search(String),

    /// A message-pipeline call failed (validation, idempotency,
    /// outbox bookkeeping).
    #[error("message: {0}")]
    Message(String),

    /// A transport-layer call failed (blob fetch, archive manifest
    /// fetch, MLS delivery cursor, …).
    #[error("transport: {0}")]
    Transport(String),

    /// An on-device ML model call failed (ONNX Runtime session
    /// create / inference, tokenizer, image decode, …). Phase 6 —
    /// `docs/PROPOSAL.md §7.6 / §7.7`. Wraps the upstream `ort` /
    /// tokenizer / image-codec error message verbatim so callers
    /// can surface it in telemetry without parsing free-form text.
    #[error("model: {0}")]
    Model(String),

    /// The requested API is part of the public trait surface but its
    /// implementation has not landed yet. The string is the method
    /// name (e.g. `"send_media"`) so callers can pattern-match on
    /// which capability is missing without parsing free-form text.
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}

/// Crate-wide [`Result`] alias.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Public API types — `docs/PROPOSAL.md §12`
// ---------------------------------------------------------------------------

/// Top-level content-kind filter for [`SearchQuery`].
///
/// `docs/PROPOSAL.md §12`. Maps to the `kind` column on
/// `message_skeleton` and to the `kind` field on the media search
/// rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    /// Plain text bodies.
    Text,
    /// Image attachments.
    Image,
    /// Video attachments.
    Video,
    /// Audio attachments.
    Audio,
    /// Document attachments (PDF, etc.).
    Document,
    /// Any kind — the search engine fans the query out across all
    /// indexes.
    #[default]
    Any,
}

/// Search-fan-out scope.
///
/// `docs/PROPOSAL.md §12` mandates [`SearchScope::IncludeCold`] as
/// the default — the personal archive is always part of search. The
/// `LocalOnly` variant exists for callers that must guarantee an
/// offline result (no network calls into the archive client).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchScope {
    /// Search the local store only (no archive fan-out).
    LocalOnly,
    /// Search the local store **and** the personal archive.
    /// Default — see `docs/PROPOSAL.md §12`.
    #[default]
    IncludeCold,
}

/// Search target. Phase 8 (2026-05-04 batch) — selects which
/// slice of the conversation hierarchy a search query applies
/// to. Variants:
///
/// * [`SearchTarget::Conversation`] — single conversation, used
///   to back the legacy `conversation_filter` field.
/// * [`SearchTarget::ConversationGroup`] — explicit list of
///   conversation ids (Phase 8, batch-5 — 2026-05-04). The
///   query engine treats the variant as the materialized set
///   directly and skips the resolver.
/// * [`SearchTarget::Channel`] — single channel id; the
///   resolver is responsible for mapping it to a conversation
///   set.
/// * [`SearchTarget::Community`] / [`SearchTarget::Domain`] —
///   filter to the conversations attached to a community or a
///   domain (b2b hierarchy levels).
/// * [`SearchTarget::Tenant`] — filter to every conversation
///   owned by a tenant string.
/// * [`SearchTarget::B2cAll`] — every conversation with
///   `scope = "b2c"`.
/// * [`SearchTarget::Starred`] — every conversation the user
///   has starred (Phase 8, batch-5 — 2026-05-04). Resolution
///   is delegated to a
///   [`crate::search::search_target::ConversationGroupResolver`]
///   because the starred-state is held by the orchestration
///   layer rather than the local store schema.
/// * [`SearchTarget::Unread`] — every conversation that has
///   unread messages (same delegation contract as
///   [`SearchTarget::Starred`]).
/// * [`SearchTarget::Global`] (default) — no filter; the
///   query engine returns results from every conversation
///   visible to the local store. `AllConversations` is an
///   alias used in the Phase-8 task spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SearchTarget {
    /// Single-conversation filter.
    Conversation(Uuid),
    /// Phase 8, batch-5 — explicit conversation-id list.
    ConversationGroup(Vec<Uuid>),
    /// Phase 8, batch-5 — channel-level filter. Resolution is
    /// delegated to the registered
    /// [`crate::search::search_target::ConversationGroupResolver`].
    Channel(Uuid),
    /// Community-level filter (matches `community_id`).
    Community(Uuid),
    /// Domain-level filter (matches `domain_id`).
    Domain(Uuid),
    /// Tenant-level filter (matches `tenant_id`).
    Tenant(String),
    /// Every conversation with `scope = "b2c"`.
    B2cAll,
    /// Phase 8, batch-5 — every conversation the user has
    /// starred. Resolution is delegated to the registered
    /// [`crate::search::search_target::ConversationGroupResolver`].
    Starred,
    /// Phase 8, batch-5 — every conversation with unread
    /// messages. Same resolver-delegation contract as
    /// [`SearchTarget::Starred`].
    Unread,
    /// No filter — search every conversation.
    #[default]
    Global,
}

impl SearchTarget {
    /// Phase-8 task-spec alias: the spec uses the name
    /// `AllConversations` for the global / no-filter variant.
    /// `Global` is the long-standing canonical name; this
    /// constant is provided so call sites that prefer the
    /// spec name compile cleanly.
    pub const fn all_conversations() -> Self {
        Self::Global
    }
}

/// Top-level search query.
///
/// `docs/PROPOSAL.md §12` defines the field shape; the unified
/// query engine (`search/query_engine.rs`, lands in Phase 5)
/// fans the query out to FTS5, fuzzy, vector, and media indexes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    /// User-typed query string. May interleave scripts.
    pub query_string: String,
    /// Optional sender filter.
    pub sender_filter: Option<String>,
    /// Optional conversation filter. Phase 8 (2026-05-04
    /// batch) introduces [`SearchQuery::target`] as the
    /// preferred filter; this field stays as a deprecated
    /// alias that maps onto
    /// [`SearchTarget::Conversation`] when [`Self::target`]
    /// is [`SearchTarget::Global`].
    pub conversation_filter: Option<Uuid>,
    /// Inclusive lower-bound `created_at_ms`.
    pub date_from: Option<i64>,
    /// Inclusive upper-bound `created_at_ms`.
    pub date_to: Option<i64>,
    /// Content-kind filter.
    pub content_kind: Option<ContentKind>,
    /// Phase 8 conversation-hierarchy target. `Global`
    /// (default) when omitted from the wire payload —
    /// `#[serde(default)]` keeps backward compat with v0
    /// callers that only sent `conversation_filter`.
    #[serde(default)]
    pub target: SearchTarget,
}

impl SearchQuery {
    /// Resolve the effective target for this query. Phase 8
    /// preserves the legacy `conversation_filter` field by
    /// mapping it to [`SearchTarget::Conversation`] when the
    /// new `target` is left at its default ([`SearchTarget::Global`]).
    pub fn effective_target(&self) -> SearchTarget {
        if matches!(self.target, SearchTarget::Global) {
            if let Some(c) = self.conversation_filter {
                return SearchTarget::Conversation(c);
            }
        }
        self.target.clone()
    }
}

/// One result row from the unified search engine.
///
/// `rank_score` is the merged (FTS / fuzzy / vector / recency /
/// pinned) score; the ranking formula lands with the search engine
/// implementation in Phase 5.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchResult {
    /// Stable message identifier.
    pub message_id: Uuid,
    /// Owning conversation.
    pub conversation_id: Uuid,
    /// Sender identifier.
    pub sender_id: String,
    /// Wall-clock millisecond timestamp set by the sender.
    pub created_at_ms: i64,
    /// Optional snippet around the match.
    pub snippet: Option<String>,
    /// Merged rank score. Higher is better.
    pub rank_score: f64,
    /// Whether this result came from the personal-archive
    /// (`is_cold = true`) or from the local store
    /// (`is_cold = false`).
    pub is_cold: bool,
    /// Raw cosine similarity between the query embedding and the
    /// row's stored embedding, when this hit went through the
    /// semantic-search engine. `None` for pure FTS / fuzzy hits.
    /// Phase 6, Task 4 (2026-05-04 batch). The reranker
    /// ([`crate::search::query_engine::QueryEngine::rerank_with_semantic`])
    /// reads this field for ordering decisions.
    #[serde(default)]
    pub semantic_score: Option<f64>,
}

/// Phase 8 (2026-05-04 batch 10) — Task 2: streaming search
/// event surface.
///
/// `docs/PROPOSAL.md §7.5` calls for the search UX to render
/// the local FTS / fuzzy hits immediately while the cold-bucket
/// fan-out completes in the background. The
/// [`crate::search::query_engine::QueryEngine::execute_search_streaming`]
/// /
/// [`crate::CoreImpl::search_streaming`]
/// callback API emits one of these per state change so the
/// platform bridges (iOS UniFFI callback interface, Android JNI
/// listener) can drive a progressive results list:
///
/// 1. [`SearchEvent::LocalResults`] — emitted exactly once per
///    search, immediately after the local FTS / fuzzy / semantic
///    pass. The payload is the local-only result set with
///    `is_cold = false` rows pre-merged.
/// 2. [`SearchEvent::ColdBucketComplete`] — emitted once per
///    cold bucket as the bucket's text + fuzzy shards arrive,
///    decrypt, and merge into the running result set.
///    `new_hits` carries only the *additional* rows surfaced by
///    this bucket (already deduped against any earlier event's
///    payload).
/// 3. [`SearchEvent::SearchComplete`] — emitted exactly once
///    per search, after every cold bucket has been processed
///    or skipped. The payload contains the final fully-merged
///    + reranked list plus the bucket-fan-out counters.
///
/// `SearchScope::LocalOnly` searches emit only
/// [`SearchEvent::LocalResults`] followed by
/// [`SearchEvent::SearchComplete`] so the UI can keep using the
/// same listener regardless of scope.
#[derive(Debug, Clone, PartialEq)]
pub enum SearchEvent {
    /// Local FTS / fuzzy / semantic results. Always emitted
    /// first, even when the local result set is empty.
    LocalResults(Vec<SearchResult>),
    /// One cold bucket completed and contributed `new_hits`
    /// rows to the running result set. `new_hits` is deduped
    /// against the local set and any earlier cold bucket — it
    /// is the *delta* introduced by this bucket.
    ColdBucketComplete {
        /// Owning conversation.
        conversation_id: String,
        /// Coarse-grained `time_bucket` ID (e.g. `"2026-04"`).
        time_bucket: String,
        /// Rows newly surfaced by this bucket. Empty when the
        /// bucket fetched but produced no hits.
        new_hits: Vec<SearchResult>,
    },
    /// Final event for every search. `total_results` is the
    /// fully-merged + reranked list (truncated to the search
    /// limit). The two counters reflect how the bucket fan-out
    /// resolved against the bloom pre-check / per-bucket
    /// fail-open path.
    SearchComplete {
        /// Final merged + reranked result list, truncated to
        /// the [`SearchQuery`] limit.
        total_results: Vec<SearchResult>,
        /// Number of cold buckets whose `(text, fuzzy)` shards
        /// were actually fetched and merged.
        cold_buckets_fetched: usize,
        /// Number of cold buckets that were resolved but
        /// skipped — typically because the bloom pre-check
        /// rejected the bucket or a transport hard-error
        /// triggered the per-bucket fail-open branch.
        cold_buckets_skipped: usize,
    },
}

/// Why the rehydration / restore path is loading a body or media
/// asset.
///
/// `docs/PROPOSAL.md §5.5` defines the priority ladder. Variants are
/// listed in priority order — declaration order matches `P0..P5`,
/// which the [`PartialOrd`] / [`Ord`] derives use for comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydrationReason {
    /// P0 — user tapped a search result.
    SearchResultTap,
    /// P1 — user opened a media asset full-screen.
    MediaFullScreen,
    /// P2 — message scrolled into the visible viewport.
    VisibleViewport,
    /// P3 — adjacent-window prefetch around the viewport.
    AdjacentPrefetch,
    /// P4 — background restore (post-restore lazy fill).
    BackgroundRestore,
    /// P5 — opportunistic / background-budget fill.
    OpportunisticFill,
}

/// Why a backup is being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupReason {
    /// Periodic scheduled backup.
    Scheduled,
    /// User pressed "Back up now".
    UserInitiated,
    /// Background task running in a low-battery window.
    LowBattery,
}

/// Why an offload / cache-eviction sweep was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePressureReason {
    /// OS reported low disk.
    SystemLowStorage,
    /// User-configured cap exceeded.
    UserCapExceeded,
    /// App launch sweep (idempotent).
    AppLaunch,
}

/// Newtype around a UUID-v7 client message id (outbox key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientMessageId(pub Uuid);

impl ClientMessageId {
    /// Mint a fresh client message id (UUID v7).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ClientMessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// Opaque MLS delivery-store cursor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeliveryCursor(pub String);

// ---------------------------------------------------------------------------
// Phase-1 placeholder result / source types
// ---------------------------------------------------------------------------
//
// `docs/PROPOSAL.md §12` specifies a richer return shape for each of
// these APIs; until the matching Phase-2 / Phase-3 / Phase-4 engines
// land, the trait carries zero-field placeholders that round-trip
// through serde so bridge crates can already pin the types in their
// FFI surface.

/// Result of [`KChatCore::hydrate_message`].
///
/// Phase 3 widens the placeholder to carry the rehydrated body
/// (when one exists), the originating skeleton metadata, and a
/// `is_cold` flag the renderer can use to decide whether to wait
/// on a background fetch. Subsequent phases (3+ / Phase 4) will
/// extend this with decrypted media descriptors and hydration
/// provenance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydratedMessage {
    /// Stable message identifier the request was for.
    pub message_id: Option<Uuid>,
    /// Owning conversation, when the skeleton is locally known.
    pub conversation_id: Option<Uuid>,
    /// Plaintext body when the message body is locally available.
    /// `None` for messages whose body is offloaded, deleted, or
    /// otherwise unavailable.
    pub text_content: Option<String>,
    /// `true` when the message body is not local (offloaded /
    /// remote-archive-only). The hydration request has been
    /// queued; the renderer should display the skeleton in a cold
    /// state until the archive fetch lands.
    pub is_cold: bool,
    /// `true` when the hydration request was answered while the
    /// device was offline — the body is not available locally,
    /// the archive fetch was skipped because the
    /// [`crate::transport::offline::OfflineDetector`] reported
    /// offline, and the renderer should display an offline cold
    /// state until reconnection retriggers hydration. Phase 7,
    /// Task 6 (2026-05-04 batch).
    #[serde(default)]
    pub offline: bool,
}

/// Result of [`KChatCore::send_media`].
///
/// Phase 2 carries the freshly-minted [`ClientMessageId`], the
/// [`MediaDescriptor`] the rest of the system round-trips through
/// CBOR, and the `asset_id` (UUID v7) that the local-store
/// `media_asset` row keys on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMediaResult {
    /// Identifier of the freshly-minted outbox / message row.
    pub client_message_id: ClientMessageId,
    /// `media_asset.asset_id` for the persisted asset.
    pub asset_id: Uuid,
    /// Asset descriptor ready to ship through MLS to the rest of
    /// the conversation.
    pub descriptor: MediaDescriptor,
}

/// Result of [`KChatCore::run_incremental_backup`].
///
/// Populated by [`crate::core_impl::CoreImpl::run_incremental_backup`]
/// once the backup engine wiring is installed (Task 3 of the
/// Phase 3/4 batch). Default is the no-events / no-keys-installed
/// shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupResult {
    /// Number of sealed [`crate::backup::segment_builder::BuiltBackupSegment`]
    /// records the run produced. Each segment seals a contiguous
    /// range of [`crate::backup::event_journal::BackupEvent`]s.
    #[serde(default)]
    pub segments_built: u64,
    /// How many of the sealed segments were uploaded through the
    /// configured [`crate::transport::TransportClient`]. Always
    /// `<= segments_built`. Will be `0` when no transport is
    /// installed (the segments are built but the caller is
    /// expected to upload them out-of-band).
    #[serde(default)]
    pub segments_uploaded: u64,
    /// Total backup events sealed across all segments produced by
    /// this run.
    #[serde(default)]
    pub events_segmented: u64,
    /// `generation` of the manifest committed by this run, when a
    /// manifest was produced. `None` for noop runs.
    #[serde(default)]
    pub manifest_generation: Option<u64>,
    /// Whether the manifest produced by this run was uploaded
    /// through the configured transport.
    #[serde(default)]
    pub manifest_uploaded: bool,
    /// `true` when the run was deferred because the device was
    /// offline at the time
    /// [`KChatCore::run_incremental_backup`] was called. The
    /// segments (if any) were sealed locally; the upload step
    /// was skipped and is expected to retry on reconnection.
    /// Phase 7, Task 6 (2026-05-04 batch).
    #[serde(default)]
    pub deferred: bool,
}

/// Result of [`KChatCore::enforce_storage_budget`].
///
/// Phase 3 carries the byte / row counts the eviction planner
/// produced. The full offload contract (archive segment refs
/// created, manifest deltas, …) lands as the archive upload path
/// fills in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffloadResult {
    /// Total plaintext bytes the eviction sweep freed from the
    /// local store.
    pub freed_bytes: u64,
    /// Number of `media_asset` rows the eviction sweep demoted.
    /// Eviction is per-asset (one row per `asset_id`) — see
    /// `crate::offload::eviction::execute_eviction`.
    pub evicted_count: u32,
}

/// Result of [`KChatCore::restore_from_backup`].
///
/// Phase-1 placeholder. The full restore contract (manifest chain
/// verified, segments installed, deferred rehydration plan, …)
/// lands with the restore engine in Phase 4.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreResult {}

/// Source descriptor for [`KChatCore::restore_from_backup`].
///
/// Phase-1 placeholder. The full source contract (backup root key
/// reference, manifest chain head, transport handle for the backup
/// sink, …) lands with the restore engine in Phase 4.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSource {}

/// Result of [`KChatCore::register_device`].
///
/// Phase-1 placeholder. The full registration contract (MLS
/// credential bundle, KeyPackage handle, server-assigned device
/// id, attestation evidence, …) lands when the MLS / device-key
/// layer arrives later in Phase 1 / Phase 2.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistration {}

/// Public, schema-stable view of a stored message.
///
/// `MessageView` is the return shape of
/// [`KChatCore::get_message`] and
/// [`KChatCore::get_conversation_messages`]. It deliberately mirrors
/// only the fields needed to render a chat bubble — sender, time,
/// reply-to, edit / delete stamps, and the (optional) plaintext body
/// — without leaking the internal `local_store::schema` types
/// through the public API. Phase-2+ engines extend this with
/// hydrated media descriptors, hydration provenance, and rich
/// metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageView {
    /// Stable message identifier.
    pub message_id: Uuid,
    /// Owning conversation.
    pub conversation_id: Uuid,
    /// Stable sender identifier.
    pub sender_id: String,
    /// Wall-clock millisecond timestamp set by the sender.
    pub created_at_ms: i64,
    /// Wall-clock millisecond timestamp at which this device
    /// received (or originated) the message.
    pub received_at_ms: i64,
    /// Identifier of the message this is a reply to, if any.
    pub reply_to: Option<Uuid>,
    /// Wall-clock millisecond timestamp of the most recent edit, if
    /// any.
    pub edited_at_ms: Option<i64>,
    /// Wall-clock millisecond timestamp of deletion, if any.
    pub deleted_at_ms: Option<i64>,
    /// Plaintext body. `None` for media-only messages and for
    /// `delete_for_everyone` tombstones whose body row has been
    /// dropped.
    pub text_content: Option<String>,
}

// ---------------------------------------------------------------------------
// KChatCore trait
// ---------------------------------------------------------------------------

/// Public core trait — `docs/PROPOSAL.md §12`.
///
/// **Async note.** The methods below are declared as synchronous
/// `Result<_>`-returning functions for now. Phase 1 turns them into
/// proper `async fn`s (or `Pin<Box<dyn Future>>`-returning functions
/// behind `async_trait`) once the SQLCipher / transport plumbing
/// exists for them to actually do I/O. Bridge crates are expected
/// to track the Phase 1 iteration of this trait.
pub trait KChatCore: Send + Sync {
    /// Returns the configuration this core was initialized with.
    fn config(&self) -> &KChatCoreConfig;

    /// Open / migrate the local store, unwrap `K_local_db`, hydrate
    /// the in-memory caches, and bring the restore state machine
    /// to a steady state.
    fn initialize(&mut self, config: KChatCoreConfig) -> Result<()>;

    /// Register this device with the MLS / identity layer for
    /// `device_id`. Returns a [`DeviceRegistration`] handle the
    /// caller persists.
    ///
    /// **Phase-1 stub.** The full MLS credential / KeyPackage
    /// publication pipeline lands later in Phase 1 / Phase 2.
    /// Until then this method returns
    /// `Err(Error::NotImplemented("register_device"))`.
    fn register_device(&self, device_id: &str) -> Result<DeviceRegistration>;

    /// Create an outbox entry for an outbound text message and
    /// return its [`ClientMessageId`].
    fn send_text(
        &self,
        conversation_id: Uuid,
        text: &str,
        reply_to: Option<Uuid>,
    ) -> Result<ClientMessageId>;

    /// Pull MLS messages from the delivery store and persist them
    /// into the local skeleton / body / media tables.
    ///
    /// `after_cursor` is the delivery-store position to resume
    /// from; `None` means "start from the device's last known
    /// cursor".
    fn ingest_remote_messages(
        &self,
        conversation_id: Uuid,
        after_cursor: Option<DeliveryCursor>,
    ) -> Result<IngestResult>;

    /// Run a unified search across FTS5, fuzzy, vector, and media
    /// indexes (and, if `scope == IncludeCold`, the personal
    /// archive).
    fn search(&self, query: SearchQuery, scope: SearchScope) -> Result<Vec<SearchResult>>;

    /// Replace the text body of an existing local-plain message and
    /// keep the FTS / fuzzy indexes in sync. Errors with
    /// [`Error::Message`] when `message_id` does not exist, the
    /// message is in a non-editable [`crate::local_store::state_machines::BodyState`],
    /// or `new_text` is empty.
    fn edit_message(&self, message_id: Uuid, new_text: &str) -> Result<()>;

    /// Soft-delete a message locally. The body row is kept so the
    /// message remains restorable, but the FTS / fuzzy rows are
    /// removed so the message stops appearing in search.
    fn delete_for_me(&self, message_id: Uuid) -> Result<()>;

    /// Tombstone a message for everyone. The body row is removed so
    /// the plaintext is gone, the FTS / fuzzy rows are removed, and
    /// the skeleton stays in place with
    /// `body_state = deleted_for_everyone` so the timeline can
    /// render a tombstone.
    fn delete_for_everyone(&self, message_id: Uuid) -> Result<()>;

    /// Delete `conversation_id` along with every dependent row —
    /// message skeletons, message bodies, FTS rows, fuzzy tokens,
    /// and media-asset rows. Errors with [`Error::Storage`] when
    /// the conversation does not exist so callers can distinguish
    /// "not found" from "removed" without parsing free-form text.
    ///
    /// Backed by the cascade implemented in
    /// `LocalStoreDb::delete_conversation`, which runs every
    /// dependent delete inside a single `SAVEPOINT` for atomicity.
    fn delete_conversation(&self, conversation_id: Uuid) -> Result<()>;

    /// Fetch a single message (skeleton + optional body text) by id.
    /// Returns `Ok(None)` when no such message exists.
    fn get_message(&self, message_id: Uuid) -> Result<Option<MessageView>>;

    /// Return the most recent messages in `conversation_id`,
    /// ordered newest-first. `before_ms` is an optional pagination
    /// cursor — only messages with `created_at_ms < before_ms` are
    /// returned. `limit` caps the page size.
    fn get_conversation_messages(
        &self,
        conversation_id: Uuid,
        before_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<MessageView>>;

    /// Send an outbound media message: chunk + AEAD-seal the
    /// in-memory `plaintext`, persist a `media_asset` row + media
    /// skeleton, and stage the descriptor for MLS distribution.
    ///
    /// `message_id` is the caller-minted UUID v7 the new
    /// [`ClientMessageId`] is built around — bridge layers that
    /// need to pre-allocate the id (so the UI can render a pending
    /// bubble before the encrypt step finishes) supply it directly;
    /// the in-process [`CoreImpl`] still mints fresh ids when the
    /// caller doesn't care.
    ///
    /// Phase 2 wires this to
    /// [`crate::media::processor::process_media`] and the
    /// [`crate::media::thumbnail::ThumbnailGenerator`]. The actual
    /// upload to the configured [`TransportClient`] /
    /// [`crate::media::sinks::MediaBlobSink`] is deferred —
    /// [`SendMediaResult::descriptor`] is the wire form callers ship
    /// through MLS.
    fn send_media(
        &self,
        conversation_id: Uuid,
        message_id: Uuid,
        plaintext: Vec<u8>,
        mime_type: &str,
        caption: Option<&str>,
    ) -> Result<SendMediaResult>;

    /// Hydrate a previously offloaded message back into the local
    /// store. `reason` is recorded in the rehydration journal so
    /// rate-limited offload eviction can take the most-recent reason
    /// into account.
    ///
    /// **Phase-1 stub.** The rehydration pipeline lands in Phase 3.
    /// Until then this method returns
    /// `Err(Error::NotImplemented("hydrate_message"))`.
    fn hydrate_message(&self, message_id: Uuid, reason: &str) -> Result<HydratedMessage>;

    /// Walk the backup event journal, pack new segments, and push
    /// them to the configured backup sink.
    ///
    /// **Phase-1 stub.** The backup engine lands in Phase 4. Until
    /// then this method returns
    /// `Err(Error::NotImplemented("run_incremental_backup"))`.
    fn run_incremental_backup(&self, reason: &str) -> Result<BackupResult>;

    /// Apply the storage budget defined by [`KChatCoreConfig`] —
    /// demote message bodies to the offload tier, drop FTS / fuzzy
    /// rows on demoted messages, and rewrite the backup journal.
    ///
    /// **Phase-1 stub.** The offload engine lands in Phase 3. Until
    /// then this method returns
    /// `Err(Error::NotImplemented("enforce_storage_budget"))`.
    fn enforce_storage_budget(&self, reason: &str) -> Result<OffloadResult>;

    /// Verify the manifest chain pointed at by `source` and replay
    /// every journal segment back into the local store.
    ///
    /// **Phase-1 stub.** The restore engine lands in Phase 4. Until
    /// then this method returns
    /// `Err(Error::NotImplemented("restore_from_backup"))`.
    fn restore_from_backup(&self, source: BackupSource) -> Result<RestoreResult>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_query_constructs_with_default() {
        let q = SearchQuery::default();
        assert!(q.query_string.is_empty());
        assert!(q.sender_filter.is_none());
        assert!(q.conversation_filter.is_none());
        assert!(q.date_from.is_none());
        assert!(q.date_to.is_none());
        assert!(q.content_kind.is_none());
    }

    #[test]
    fn search_query_round_trips_through_serde() {
        let q = SearchQuery {
            query_string: "会議室".to_string(),
            sender_filter: Some("user-1".to_string()),
            conversation_filter: Some(Uuid::now_v7()),
            date_from: Some(1_700_000_000_000),
            date_to: Some(1_800_000_000_000),
            content_kind: Some(ContentKind::Text),
            target: SearchTarget::Global,
        };
        let json = serde_json::to_string(&q).unwrap();
        let back: SearchQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn search_target_default_is_global() {
        assert_eq!(SearchTarget::default(), SearchTarget::Global);
    }

    #[test]
    fn search_target_round_trips_through_serde_for_every_variant() {
        let cases = vec![
            SearchTarget::Conversation(Uuid::now_v7()),
            SearchTarget::Community(Uuid::now_v7()),
            SearchTarget::Domain(Uuid::now_v7()),
            SearchTarget::Tenant("t1".into()),
            SearchTarget::B2cAll,
            SearchTarget::Global,
        ];
        for t in cases {
            let json = serde_json::to_string(&t).unwrap();
            let back: SearchTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn backward_compat_conversation_filter_maps_to_search_target() {
        // Phase 8: when only `conversation_filter` is set (legacy
        // wire payload, no `target`), `effective_target()` must
        // surface as `SearchTarget::Conversation(c)`.
        let conv = Uuid::now_v7();
        let q = SearchQuery {
            conversation_filter: Some(conv),
            ..Default::default()
        };
        assert_eq!(q.effective_target(), SearchTarget::Conversation(conv));
        // When `target` is set explicitly to a non-Global value
        // the new field takes precedence.
        let other = Uuid::now_v7();
        let q = SearchQuery {
            conversation_filter: Some(conv),
            target: SearchTarget::Community(other),
            ..Default::default()
        };
        assert_eq!(q.effective_target(), SearchTarget::Community(other));
    }

    #[test]
    fn search_query_target_defaults_to_global_when_missing_from_serde_payload() {
        // Legacy wire payloads have no `target` field; serde must
        // decode them with the default value.
        let payload = r#"{"query_string":"hi"}"#;
        let q: SearchQuery = serde_json::from_str(payload).unwrap();
        assert_eq!(q.target, SearchTarget::Global);
    }

    #[test]
    fn search_scope_default_is_include_cold() {
        // PROPOSAL.md §12: default scope must be IncludeCold so that
        // the personal archive is always part of search.
        assert_eq!(SearchScope::default(), SearchScope::IncludeCold);
    }

    #[test]
    fn content_kind_default_is_any() {
        assert_eq!(ContentKind::default(), ContentKind::Any);
    }

    #[test]
    fn hydration_reason_priority_order_matches_p0_p5() {
        // Declaration order maps to P0–P5; PartialOrd / Ord derive
        // gives ordering by declaration position. Lower = higher
        // priority.
        let priority = [
            HydrationReason::SearchResultTap,
            HydrationReason::MediaFullScreen,
            HydrationReason::VisibleViewport,
            HydrationReason::AdjacentPrefetch,
            HydrationReason::BackgroundRestore,
            HydrationReason::OpportunisticFill,
        ];
        for w in priority.windows(2) {
            assert!(
                w[0] < w[1],
                "expected {:?} (P{}) < {:?} (P{})",
                w[0],
                priority.iter().position(|x| x == &w[0]).unwrap(),
                w[1],
                priority.iter().position(|x| x == &w[1]).unwrap(),
            );
        }
    }

    #[test]
    fn search_result_round_trips_through_serde() {
        let r = SearchResult {
            message_id: Uuid::now_v7(),
            conversation_id: Uuid::now_v7(),
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            snippet: Some("hello".into()),
            rank_score: 0.875,
            is_cold: false,
            semantic_score: Some(0.4),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn backup_reason_round_trips_through_serde() {
        for r in [
            BackupReason::Scheduled,
            BackupReason::UserInitiated,
            BackupReason::LowBattery,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            let back: BackupReason = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn storage_pressure_reason_round_trips_through_serde() {
        for r in [
            StoragePressureReason::SystemLowStorage,
            StoragePressureReason::UserCapExceeded,
            StoragePressureReason::AppLaunch,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            let back: StoragePressureReason = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn client_message_id_is_v7() {
        let id = ClientMessageId::new();
        assert_eq!(id.0.get_version_num(), 7);
    }

    #[test]
    fn delivery_cursor_serde_is_transparent() {
        let c = DeliveryCursor("opaque-123".to_string());
        // #[serde(transparent)] makes the cursor serialize as the
        // bare inner string, which is what callers should see when
        // they round-trip through JSON.
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"opaque-123\"");
        let back: DeliveryCursor = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn error_variants_construct() {
        // Pure smoke test that the new variants compile and Display.
        let e = Error::Storage("boom".into());
        assert!(format!("{e}").contains("storage:"));
        let e = Error::Search("q".into());
        assert!(format!("{e}").contains("search:"));
        let e = Error::Message("m".into());
        assert!(format!("{e}").contains("message:"));
        let e = Error::Transport("t".into());
        assert!(format!("{e}").contains("transport:"));
        let e = Error::Model("xlmr".into());
        assert!(format!("{e}").contains("model: xlmr"));
        let e = Error::NotImplemented("send_media");
        assert!(format!("{e}").contains("not yet implemented: send_media"));
    }

    // ----------------------------------------------------------------
    // Phase-1 placeholder result / source types — Task 3
    // ----------------------------------------------------------------

    #[test]
    fn hydrated_message_round_trips_through_serde() {
        let v = HydratedMessage::default();
        let json = serde_json::to_string(&v).unwrap();
        let back: HydratedMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn backup_result_round_trips_through_serde() {
        let v = BackupResult::default();
        let json = serde_json::to_string(&v).unwrap();
        let back: BackupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn offload_result_round_trips_through_serde() {
        let v = OffloadResult::default();
        let json = serde_json::to_string(&v).unwrap();
        let back: OffloadResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn restore_result_round_trips_through_serde() {
        let v = RestoreResult::default();
        let json = serde_json::to_string(&v).unwrap();
        let back: RestoreResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn backup_source_round_trips_through_serde() {
        let v = BackupSource::default();
        let json = serde_json::to_string(&v).unwrap();
        let back: BackupSource = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn device_registration_round_trips_through_serde() {
        let v = DeviceRegistration::default();
        let json = serde_json::to_string(&v).unwrap();
        let back: DeviceRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}
