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
pub mod formats;
pub mod local_store;
pub mod media;
pub mod message;
pub mod models;
pub mod offload;
pub mod restore;
pub mod scheduler;
pub mod search;
pub mod transport;

pub use config::KChatCoreConfig;
pub use core_impl::CoreImpl;

use std::path::Path;

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
    /// Optional conversation filter.
    pub conversation_filter: Option<Uuid>,
    /// Inclusive lower-bound `created_at_ms`.
    pub date_from: Option<i64>,
    /// Inclusive upper-bound `created_at_ms`.
    pub date_to: Option<i64>,
    /// Content-kind filter.
    pub content_kind: Option<ContentKind>,
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
/// Phase-1 placeholder. The full hydration contract
/// (decrypted body, decrypted media descriptors, hydration
/// provenance) lands when the rehydration / restore engines arrive
/// in Phase 2 / Phase 4.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydratedMessage {}

/// Result of [`KChatCore::run_incremental_backup`].
///
/// Phase-1 placeholder. The full backup contract (segment count,
/// manifest hash, byte budget consumed, …) lands with the backup
/// engine in Phase 4.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupResult {}

/// Result of [`KChatCore::enforce_storage_budget`].
///
/// Phase-1 placeholder. The full offload contract (rows demoted,
/// bytes freed, archive segment refs created, …) lands with the
/// offload engine in Phase 3.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffloadResult {}

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

    /// Send an outbound media message: copy / encrypt the file at
    /// `local_file`, persist a media descriptor + body row, and
    /// queue the resulting outbox entry. Returns the new message's
    /// [`ClientMessageId`].
    ///
    /// **Phase-1 stub.** The media-send pipeline (chunking, MLS
    /// encryption, descriptor signing) lands in Phase 2. Until then
    /// this method returns
    /// `Err(Error::NotImplemented("send_media"))`.
    fn send_media(
        &self,
        conversation_id: Uuid,
        local_file: &Path,
        caption: Option<&str>,
    ) -> Result<ClientMessageId>;

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
        };
        let json = serde_json::to_string(&q).unwrap();
        let back: SearchQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
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
}
