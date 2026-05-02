//! Concrete [`KChatCore`] implementation.
//!
//! `docs/PROPOSAL.md §12` specifies the public API trait;
//! [`CoreImpl`] is the Phase-1 in-process implementation that wires
//! the trait to the SQLCipher [`LocalStoreDb`], the
//! [`MessagePersister`] for outbox / ingest persistence, and the
//! [`QueryEngine`] for unified FTS5 + structured search.
//!
//! What is wired in Phase 1:
//!
//! * [`CoreImpl::new`] opens (or creates) `{data_dir}/kchat.db` with
//!   the supplied 32-byte `K_local_db`.
//! * [`KChatCore::config`] returns the stored configuration.
//! * [`KChatCore::initialize`] re-opens the local store at the
//!   supplied configuration's `data_dir` using the key that was
//!   passed to [`CoreImpl::new`].
//! * [`KChatCore::send_text`] mints an [`OutboxEntry`] via
//!   [`MessageProcessor::create_outbox_entry`] and persists it via
//!   [`MessagePersister::persist_outbox_entry`].
//! * [`KChatCore::search`] delegates to
//!   [`QueryEngine::execute_search`].
//!
//! What is **not** yet wired:
//!
//! * The transport-driven [`KChatCore::ingest_remote_messages`] is a
//!   stub returning [`IngestResult::default()`] — the MLS delivery
//!   client lands later in Phase 1. For now, callers (and tests) use
//!   the inherent [`CoreImpl::ingest_messages`] entry point that
//!   takes an in-memory slice of [`IngestedMessage`] values directly.
//! * Async surface: the trait is currently synchronous; converting
//!   to `async fn` is queued for once the I/O paths are in place.

use std::path::Path;
use std::sync::Mutex;

use uuid::Uuid;

use zeroize::Zeroizing;

use crate::config::KChatCoreConfig;
use crate::local_store::db::LocalStoreDb;
use crate::local_store::schema::{Conversation, MessageBody, MessageSkeleton};
use crate::message::processor::{
    IngestResult, IngestedMessage, MessagePersister, MessageProcessor, ProcessorError,
};
use crate::search::query_engine::QueryEngine;
use crate::transport::{DeliveryClient, RawDeliveryMessage};
use crate::{
    BackupResult, BackupSource, ClientMessageId, DeliveryCursor, Error, HydratedMessage, KChatCore,
    MessageView, OffloadResult, RestoreResult, Result, SearchQuery, SearchResult, SearchScope,
};

// ---------------------------------------------------------------------------
// CoreImpl
// ---------------------------------------------------------------------------

/// Concrete [`KChatCore`] implementation backed by a single
/// [`LocalStoreDb`].
///
/// `CoreImpl` is `Send + Sync` — the underlying [`rusqlite::Connection`]
/// is held inside a [`Mutex`] so the trait's `&self` methods can
/// short-borrow the connection without making the public surface
/// `&mut self`.
pub struct CoreImpl {
    config: KChatCoreConfig,
    db: Mutex<LocalStoreDb>,
    /// 32-byte `K_local_db` retained so [`KChatCore::initialize`]
    /// can re-open the database at a different `data_dir` without
    /// requiring the caller to re-supply the key.
    key: Zeroizing<[u8; 32]>,
    /// Optional MLS delivery-store client. When `None`,
    /// [`KChatCore::ingest_remote_messages`] returns
    /// [`Error::Transport`] — see
    /// [`CoreImpl::with_transport`] / [`CoreImpl::set_delivery_client`]
    /// for how callers wire one in.
    delivery_client: Mutex<Option<Box<dyn DeliveryClient>>>,
}

impl std::fmt::Debug for CoreImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreImpl")
            .field("config", &self.config)
            .field("db", &"<LocalStoreDb>")
            .field("key", &"<redacted>")
            .field("delivery_client", &"<dyn DeliveryClient>")
            .finish()
    }
}

impl CoreImpl {
    /// Construct a new core, opening the SQLCipher database at
    /// `{config.data_dir}/kchat.db` with `key`. No transport
    /// client is wired — see [`CoreImpl::with_transport`] /
    /// [`CoreImpl::set_delivery_client`] to add one.
    pub fn new(config: KChatCoreConfig, key: [u8; 32]) -> Result<Self> {
        let db = LocalStoreDb::open(&config.data_dir, &key)
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(Self {
            config,
            db: Mutex::new(db),
            key: Zeroizing::new(key),
            delivery_client: Mutex::new(None),
        })
    }

    /// Construct a new core backed by an in-memory database. Test-only.
    #[cfg(test)]
    pub fn new_in_memory(config: KChatCoreConfig, key: [u8; 32]) -> Result<Self> {
        let db = LocalStoreDb::open_in_memory(&key).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(Self {
            config,
            db: Mutex::new(db),
            key: Zeroizing::new(key),
            delivery_client: Mutex::new(None),
        })
    }

    /// Construct a new core with an MLS delivery-store client wired
    /// in from the start. Equivalent to calling
    /// [`CoreImpl::new`] followed by
    /// [`CoreImpl::set_delivery_client`].
    pub fn with_transport(
        config: KChatCoreConfig,
        key: [u8; 32],
        client: Box<dyn DeliveryClient>,
    ) -> Result<Self> {
        let core = Self::new(config, key)?;
        core.set_delivery_client(client);
        Ok(core)
    }

    /// Install (or replace) the MLS delivery-store client used by
    /// [`KChatCore::ingest_remote_messages`].
    pub fn set_delivery_client(&self, client: Box<dyn DeliveryClient>) {
        *self
            .delivery_client
            .lock()
            .expect("delivery client mutex poisoned") = Some(client);
    }

    /// Persist a slice of MLS-decrypted messages into the local
    /// store.
    ///
    /// Each message is run through [`MessagePersister::persist_ingested_message`].
    /// Duplicates (same `message_id`) increment `duplicate_count`
    /// without raising an error — every other [`ProcessorError`] is
    /// surfaced.
    ///
    /// This is the **inherent** entry point used in Phase 1 while
    /// the transport-driven [`KChatCore::ingest_remote_messages`]
    /// trait method is still a stub.
    pub fn ingest_messages(&self, messages: &[IngestedMessage]) -> Result<IngestResult> {
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        let mut result = IngestResult::default();
        for msg in messages {
            match persister.persist_ingested_message(msg) {
                Ok(_) => result.new_messages += 1,
                Err(ProcessorError::DuplicateMessage) => result.duplicate_count += 1,
                Err(e) => return Err(Error::Message(e.to_string())),
            }
        }
        Ok(result)
    }

    /// Borrow the local store for read-only inspection. Test-only.
    /// Production callers should go through the public API.
    #[cfg(test)]
    fn with_db<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&LocalStoreDb) -> T,
    {
        let db = self.db.lock().expect("db mutex poisoned");
        f(&db)
    }

    // ----------------------------------------------------------------
    // Conversation management — Task 4 (`docs/PROPOSAL.md §12`)
    // ----------------------------------------------------------------

    /// Insert a new `conversation` row with the given id and optional
    /// title. The conversation is created un-pinned, un-muted, with
    /// `last_activity_ms` initialized to the supplied wall-clock
    /// timestamp.
    ///
    /// **Phase-1 note.** Title encryption (`K_local_db`-AEAD-sealed
    /// `title_cipher`) lands with the conversation-metadata
    /// roadmap in Phase 2. For now `title` is stored verbatim as
    /// UTF-8 bytes so the bridge can already round-trip the field
    /// through the public API.
    pub fn create_conversation(
        &self,
        conversation_id: Uuid,
        title: Option<&str>,
        last_activity_ms: i64,
    ) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let conv = Conversation {
            conversation_id: conversation_id.to_string(),
            title_cipher: title.map(|t| t.as_bytes().to_vec()),
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms,
        };
        db.insert_conversation(&conv)
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    /// List every conversation, pinned-first then by descending
    /// `last_activity_ms`.
    pub fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.list_conversations()
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Fetch a single conversation by id. Returns `Ok(None)` when
    /// the row does not exist.
    pub fn get_conversation(&self, conversation_id: Uuid) -> Result<Option<Conversation>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.get_conversation(&conversation_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Update the `pinned` flag for `conversation_id`. Errors with
    /// [`Error::Storage`] when the row does not exist so callers can
    /// surface the failure to the user instead of silently no-op'ing.
    pub fn update_conversation_pin(&self, conversation_id: Uuid, pinned: bool) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let n = db
            .update_conversation_pin(&conversation_id.to_string(), pinned)
            .map_err(|e| Error::Storage(e.to_string()))?;
        if n == 0 {
            return Err(Error::Storage(format!(
                "no conversation with id={conversation_id}"
            )));
        }
        Ok(())
    }

    /// Update the `muted` flag for `conversation_id`. Errors with
    /// [`Error::Storage`] when the row does not exist.
    pub fn update_conversation_mute(&self, conversation_id: Uuid, muted: bool) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let n = db
            .update_conversation_mute(&conversation_id.to_string(), muted)
            .map_err(|e| Error::Storage(e.to_string()))?;
        if n == 0 {
            return Err(Error::Storage(format!(
                "no conversation with id={conversation_id}"
            )));
        }
        Ok(())
    }
}

impl KChatCore for CoreImpl {
    fn config(&self) -> &KChatCoreConfig {
        &self.config
    }

    fn initialize(&mut self, config: KChatCoreConfig) -> Result<()> {
        let db = LocalStoreDb::open(&config.data_dir, &self.key)
            .map_err(|e| Error::Storage(e.to_string()))?;
        self.config = config;
        self.db = Mutex::new(db);
        // The delivery client survives a re-init: it is bound to
        // the device / account, not the on-disk store location.
        Ok(())
    }

    fn send_text(
        &self,
        conversation_id: Uuid,
        text: &str,
        reply_to: Option<Uuid>,
    ) -> Result<ClientMessageId> {
        let entry = MessageProcessor::create_outbox_entry(conversation_id, text, reply_to)
            .map_err(|e| Error::Message(e.to_string()))?;
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        let mid = persister
            .persist_outbox_entry(&entry)
            .map_err(|e| Error::Message(e.to_string()))?;
        Ok(mid)
    }

    fn ingest_remote_messages(
        &self,
        conversation_id: Uuid,
        after_cursor: Option<DeliveryCursor>,
    ) -> Result<IngestResult> {
        // Snapshot the configured delivery client. We hold the
        // mutex only for the duration of the fetch dispatch so the
        // database mutex below can be acquired without nesting.
        let fetch = {
            let guard = self.delivery_client.lock().map_err(poisoned)?;
            let client = guard
                .as_ref()
                .ok_or_else(|| Error::Transport("no delivery client configured".to_string()))?;
            let cursor_owned = after_cursor.as_ref().map(|c| c.0.clone());
            client.fetch_messages(&conversation_id.to_string(), cursor_owned.as_deref())
        };
        let fetched = fetch.map_err(|e| Error::Transport(e.to_string()))?;

        // Convert each RawDeliveryMessage to an IngestedMessage and
        // route through the inherent ingest_messages entry point so
        // FTS / fuzzy / journal / conversation-metadata writes all
        // happen inside the existing per-message SAVEPOINT.
        let mut converted: Vec<IngestedMessage> = Vec::with_capacity(fetched.messages.len());
        for raw in &fetched.messages {
            converted.push(raw_delivery_to_ingested(raw)?);
        }
        let result = self.ingest_messages(&converted)?;
        // The transport's `next_cursor` is intentionally not
        // surfaced through `IngestResult` in Phase 1 — the
        // typed cursor field lands with the result-shape
        // expansion in Phase 2. Tests that need to pin the
        // cursor pass-through assert it through
        // [`crate::transport::MockDeliveryClient::seen_cursors`].
        let _ = fetched.next_cursor;
        Ok(result)
    }

    fn search(&self, query: SearchQuery, scope: SearchScope) -> Result<Vec<SearchResult>> {
        let db = self.db.lock().map_err(poisoned)?;
        let engine = QueryEngine::new(&db);
        engine
            .execute_search(&query, &scope)
            .map_err(|e| Error::Search(e.to_string()))
    }

    fn edit_message(&self, message_id: Uuid, new_text: &str) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        persister
            .edit_message(&message_id.to_string(), new_text)
            .map_err(|e| Error::Message(e.to_string()))
    }

    fn delete_for_me(&self, message_id: Uuid) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        persister
            .delete_for_me(&message_id.to_string())
            .map_err(|e| Error::Message(e.to_string()))
    }

    fn delete_for_everyone(&self, message_id: Uuid) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        persister
            .delete_for_everyone(&message_id.to_string())
            .map_err(|e| Error::Message(e.to_string()))
    }

    fn get_message(&self, message_id: Uuid) -> Result<Option<MessageView>> {
        let db = self.db.lock().map_err(poisoned)?;
        let pair = db
            .get_message_with_body(&message_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))?;
        match pair {
            None => Ok(None),
            Some((skel, body)) => Ok(Some(skeleton_and_body_to_view(skel, body)?)),
        }
    }

    fn get_conversation_messages(
        &self,
        conversation_id: Uuid,
        before_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<MessageView>> {
        let db = self.db.lock().map_err(poisoned)?;
        let skels = db
            .get_conversation_messages(&conversation_id.to_string(), before_ms, limit)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let mut out = Vec::with_capacity(skels.len());
        for skel in skels {
            let body = db
                .get_message_body(&skel.message_id)
                .map_err(|e| Error::Storage(e.to_string()))?;
            out.push(skeleton_and_body_to_view(skel, body)?);
        }
        Ok(out)
    }

    fn send_media(
        &self,
        _conversation_id: Uuid,
        _local_file: &Path,
        _caption: Option<&str>,
    ) -> Result<ClientMessageId> {
        // Phase-1 stub: media chunking, AEAD encryption, descriptor
        // signing, and outbox bookkeeping land in Phase 2 alongside
        // the media-search index.
        Err(Error::NotImplemented("send_media"))
    }

    fn hydrate_message(&self, _message_id: Uuid, _reason: &str) -> Result<HydratedMessage> {
        // Phase-1 stub: rehydration arrives with the offload engine
        // in Phase 3.
        Err(Error::NotImplemented("hydrate_message"))
    }

    fn run_incremental_backup(&self, _reason: &str) -> Result<BackupResult> {
        // Phase-1 stub: backup segment packing + manifest signing
        // arrives in Phase 4.
        Err(Error::NotImplemented("run_incremental_backup"))
    }

    fn enforce_storage_budget(&self, _reason: &str) -> Result<OffloadResult> {
        // Phase-1 stub: storage-budget enforcement / offload tier
        // demotion arrives in Phase 3.
        Err(Error::NotImplemented("enforce_storage_budget"))
    }

    fn restore_from_backup(&self, _source: BackupSource) -> Result<RestoreResult> {
        // Phase-1 stub: backup restore + journal replay arrives in
        // Phase 4.
        Err(Error::NotImplemented("restore_from_backup"))
    }
}

fn poisoned<T>(_e: std::sync::PoisonError<T>) -> Error {
    Error::Storage("local store mutex poisoned".to_string())
}

/// Convert a transport-level [`RawDeliveryMessage`] into the local
/// [`IngestedMessage`] shape. UUID strings are parsed here; on
/// failure we surface the error as [`Error::Transport`] because the
/// id format is dictated by the delivery store.
fn raw_delivery_to_ingested(raw: &RawDeliveryMessage) -> Result<IngestedMessage> {
    let message_id = Uuid::parse_str(&raw.message_id)
        .map_err(|e| Error::Transport(format!("invalid message_id: {e}")))?;
    let conversation_id = Uuid::parse_str(&raw.conversation_id)
        .map_err(|e| Error::Transport(format!("invalid conversation_id: {e}")))?;
    let reply_to = match &raw.reply_to {
        None => None,
        Some(s) => Some(
            Uuid::parse_str(s).map_err(|e| Error::Transport(format!("invalid reply_to: {e}")))?,
        ),
    };
    Ok(IngestedMessage {
        message_id,
        conversation_id,
        sender_id: raw.sender_id.clone(),
        created_at_ms: raw.created_at_ms,
        text_content: raw.text_content.clone(),
        media_descriptors: raw.media_descriptors.clone(),
        reply_to,
    })
}

/// Map a `(MessageSkeleton, Option<MessageBody>)` pair from the
/// `LocalStoreDb` into the public [`MessageView`] shape, parsing
/// id strings back into `Uuid` and propagating parse failures as
/// [`Error::Storage`] (the strings are persisted by us, so a
/// parse failure indicates a corrupted store).
fn skeleton_and_body_to_view(
    skel: MessageSkeleton,
    body: Option<MessageBody>,
) -> Result<MessageView> {
    let message_id = Uuid::parse_str(&skel.message_id)
        .map_err(|e| Error::Storage(format!("invalid message_id in store: {e}")))?;
    let conversation_id = Uuid::parse_str(&skel.conversation_id)
        .map_err(|e| Error::Storage(format!("invalid conversation_id in store: {e}")))?;
    let reply_to = match &skel.reply_to {
        None => None,
        Some(s) => Some(
            Uuid::parse_str(s)
                .map_err(|e| Error::Storage(format!("invalid reply_to in store: {e}")))?,
        ),
    };
    let text_content = body.and_then(|b| b.text_content);
    Ok(MessageView {
        message_id,
        conversation_id,
        sender_id: skel.sender_id,
        created_at_ms: skel.created_at_ms,
        received_at_ms: skel.received_at_ms,
        reply_to,
        edited_at_ms: skel.edited_at_ms,
        deleted_at_ms: skel.deleted_at_ms,
        text_content,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::Platform;
    use crate::message::processor::IngestedMessage;

    const TEST_KEY: [u8; 32] = [0x42; 32];

    fn test_config() -> KChatCoreConfig {
        KChatCoreConfig::new(
            PathBuf::from("/tmp/kchat-core-impl-tests"),
            Platform::MacOs,
            "tenant-test",
        )
    }

    fn fresh_core() -> CoreImpl {
        CoreImpl::new_in_memory(test_config(), TEST_KEY).expect("core")
    }

    fn seed_conversation(core: &CoreImpl, conv: &Uuid) {
        core.with_db(|db| {
            let conv_row = crate::local_store::schema::Conversation {
                conversation_id: conv.to_string(),
                title_cipher: None,
                pinned: false,
                muted: false,
                last_message_id: None,
                last_activity_ms: 1,
            };
            db.insert_conversation(&conv_row).unwrap();
        });
    }

    #[test]
    fn core_impl_initialize_and_send_text() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mid = core.send_text(conv, "hello world", None).expect("send");
        assert_eq!(mid.0.get_version_num(), 7);

        // Skeleton must exist with body_state=local_plain_available.
        core.with_db(|db| {
            let skel = db
                .get_message_skeleton(&mid.0.to_string())
                .unwrap()
                .expect("skeleton");
            assert_eq!(
                skel.body_state,
                crate::local_store::state_machines::BodyState::LocalPlainAvailable
            );
            let body = db
                .get_message_body(&mid.0.to_string())
                .unwrap()
                .expect("body");
            assert_eq!(body.text_content.as_deref(), Some("hello world"));
        });
    }

    #[test]
    fn core_impl_search_returns_persisted_messages() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        core.send_text(conv, "alpha beta gamma", None).unwrap();
        core.send_text(conv, "delta epsilon zeta", None).unwrap();

        let q = SearchQuery {
            query_string: "epsilon".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn core_impl_ingest_and_search_round_trip() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let msgs = vec![
            IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: Some("the quick brown fox".into()),
                media_descriptors: vec![],
                reply_to: None,
            },
            IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: "user-2".into(),
                created_at_ms: 1_700_000_000_001,
                text_content: Some("jumps over the lazy dog".into()),
                media_descriptors: vec![],
                reply_to: None,
            },
        ];
        let result = core.ingest_messages(&msgs).expect("ingest");
        assert_eq!(result.new_messages, 2);
        assert_eq!(result.duplicate_count, 0);

        let q = SearchQuery {
            query_string: "quick".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 1);

        let q = SearchQuery {
            query_string: "lazy".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn core_impl_duplicate_rejection() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("only once".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        let r1 = core.ingest_messages(std::slice::from_ref(&msg)).unwrap();
        assert_eq!(r1.new_messages, 1);
        assert_eq!(r1.duplicate_count, 0);

        let r2 = core.ingest_messages(std::slice::from_ref(&msg)).unwrap();
        assert_eq!(r2.new_messages, 0);
        assert_eq!(r2.duplicate_count, 1);
    }

    #[test]
    fn core_impl_initialize_swaps_data_dir() {
        // initialize() re-opens the database at the new config's
        // data_dir using the stored K_local_db. Use a tempdir so the
        // re-open is real I/O, not in-memory.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = KChatCoreConfig::new(tmp.path().to_path_buf(), Platform::MacOs, "tenant-test");
        let mut core = CoreImpl::new(cfg, TEST_KEY).expect("core");

        let tmp2 = tempfile::tempdir().unwrap();
        let cfg2 = KChatCoreConfig::new(tmp2.path().to_path_buf(), Platform::MacOs, "tenant-test");
        core.initialize(cfg2.clone()).expect("re-open");
        assert_eq!(core.config().data_dir, cfg2.data_dir);

        // Database is fresh — sending a message after re-init still
        // works.
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        core.send_text(conv, "after reinit", None).unwrap();
    }

    #[test]
    fn core_impl_ingest_remote_without_transport_errors() {
        let core = fresh_core();
        let err = core
            .ingest_remote_messages(Uuid::now_v7(), None)
            .unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "got {err:?}");
    }

    #[test]
    fn core_impl_send_text_rejects_empty_string() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let err = core.send_text(conv, "", None).unwrap_err();
        assert!(matches!(err, Error::Message(_)), "got {err:?}");
    }

    #[test]
    fn core_impl_config_round_trips() {
        let core = fresh_core();
        assert_eq!(core.config().tenant_id, "tenant-test");
        assert_eq!(core.config().platform, Platform::MacOs);
    }

    // ----------------------------------------------------------------
    // Phase-1 stub trait methods — Task 3
    // ----------------------------------------------------------------

    #[test]
    fn send_media_returns_not_implemented() {
        let core = fresh_core();
        let err = core
            .send_media(Uuid::now_v7(), Path::new("/tmp/none"), Some("caption"))
            .unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented("send_media")),
            "got {err:?}"
        );
    }

    #[test]
    fn hydrate_message_returns_not_implemented() {
        let core = fresh_core();
        let err = core
            .hydrate_message(Uuid::now_v7(), "search-result-tap")
            .unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented("hydrate_message")),
            "got {err:?}"
        );
    }

    #[test]
    fn run_incremental_backup_returns_not_implemented() {
        let core = fresh_core();
        let err = core.run_incremental_backup("scheduled").unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented("run_incremental_backup")),
            "got {err:?}"
        );
    }

    #[test]
    fn enforce_storage_budget_returns_not_implemented() {
        let core = fresh_core();
        let err = core.enforce_storage_budget("app-launch").unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented("enforce_storage_budget")),
            "got {err:?}"
        );
    }

    #[test]
    fn restore_from_backup_returns_not_implemented() {
        let core = fresh_core();
        let err = core
            .restore_from_backup(BackupSource::default())
            .unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented("restore_from_backup")),
            "got {err:?}"
        );
    }

    // ----------------------------------------------------------------
    // Conversation management — Task 4
    // ----------------------------------------------------------------

    #[test]
    fn create_and_list_conversations() {
        let core = fresh_core();
        let c_old = Uuid::now_v7();
        let c_mid = Uuid::now_v7();
        let c_new = Uuid::now_v7();
        core.create_conversation(c_old, Some("old"), 1_000).unwrap();
        core.create_conversation(c_mid, None, 2_000).unwrap();
        core.create_conversation(c_new, Some("new"), 3_000).unwrap();

        let list = core.list_conversations().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].conversation_id, c_new.to_string());
        assert_eq!(list[1].conversation_id, c_mid.to_string());
        assert_eq!(list[2].conversation_id, c_old.to_string());
        assert_eq!(list[0].title_cipher.as_deref(), Some(b"new" as &[u8]));
        assert_eq!(list[1].title_cipher, None);
    }

    #[test]
    fn get_conversation_returns_none_for_missing() {
        let core = fresh_core();
        assert_eq!(core.get_conversation(Uuid::now_v7()).unwrap(), None);
    }

    #[test]
    fn pin_and_mute_round_trip() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        core.create_conversation(conv, Some("daily-standup"), 1_000)
            .unwrap();
        let row = core.get_conversation(conv).unwrap().unwrap();
        assert!(!row.pinned);
        assert!(!row.muted);

        core.update_conversation_pin(conv, true).unwrap();
        core.update_conversation_mute(conv, true).unwrap();
        let row = core.get_conversation(conv).unwrap().unwrap();
        assert!(row.pinned);
        assert!(row.muted);

        core.update_conversation_pin(conv, false).unwrap();
        core.update_conversation_mute(conv, false).unwrap();
        let row = core.get_conversation(conv).unwrap().unwrap();
        assert!(!row.pinned);
        assert!(!row.muted);
    }

    #[test]
    fn pin_missing_conversation_errors() {
        let core = fresh_core();
        let err = core
            .update_conversation_pin(Uuid::now_v7(), true)
            .unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn mute_missing_conversation_errors() {
        let core = fresh_core();
        let err = core
            .update_conversation_mute(Uuid::now_v7(), true)
            .unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn list_conversations_orders_pinned_first() {
        let core = fresh_core();
        let c_a = Uuid::now_v7();
        let c_b = Uuid::now_v7();
        core.create_conversation(c_a, None, 1_000).unwrap();
        core.create_conversation(c_b, None, 2_000).unwrap();
        core.update_conversation_pin(c_a, true).unwrap();

        let list = core.list_conversations().unwrap();
        assert_eq!(list[0].conversation_id, c_a.to_string());
        assert!(list[0].pinned);
        assert_eq!(list[1].conversation_id, c_b.to_string());
    }

    // ----------------------------------------------------------------
    // Task 1 — edit / delete on the KChatCore trait
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_edit_message_updates_body_and_search() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core
            .send_text(conv, "the rain in spain", None)
            .expect("send");

        // Sanity: the original token is searchable.
        let q = SearchQuery {
            query_string: "rain".to_string(),
            ..SearchQuery::default()
        };
        assert_eq!(
            core.search(q, SearchScope::LocalOnly).unwrap().len(),
            1,
            "original text should be searchable"
        );

        core.edit_message(mid.0, "the snow in moscow")
            .expect("edit");

        // Body text reflects the edit.
        core.with_db(|db| {
            let body = db
                .get_message_body(&mid.0.to_string())
                .unwrap()
                .expect("body");
            assert_eq!(body.text_content.as_deref(), Some("the snow in moscow"));
            let skel = db
                .get_message_skeleton(&mid.0.to_string())
                .unwrap()
                .expect("skel");
            assert!(skel.edited_at_ms.is_some());
        });

        // Old token no longer matches; new token does.
        let q_old = SearchQuery {
            query_string: "rain".to_string(),
            ..SearchQuery::default()
        };
        assert!(
            core.search(q_old, SearchScope::LocalOnly)
                .unwrap()
                .is_empty(),
            "old text must not be searchable after edit"
        );
        let q_new = SearchQuery {
            query_string: "snow".to_string(),
            ..SearchQuery::default()
        };
        assert_eq!(
            core.search(q_new, SearchScope::LocalOnly).unwrap().len(),
            1,
            "new text must be searchable after edit"
        );
    }

    #[test]
    fn core_impl_delete_for_me_removes_from_search() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "secret plans", None).expect("send");

        core.delete_for_me(mid.0).expect("delete");

        let q = SearchQuery {
            query_string: "secret".to_string(),
            ..SearchQuery::default()
        };
        assert!(
            core.search(q, SearchScope::LocalOnly).unwrap().is_empty(),
            "delete_for_me must remove the message from search"
        );

        // Body row is preserved for delete_for_me.
        core.with_db(|db| {
            let body = db.get_message_body(&mid.0.to_string()).unwrap();
            assert!(body.is_some(), "body must survive delete_for_me");
        });
    }

    #[test]
    fn core_impl_delete_for_everyone_removes_body() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core
            .send_text(conv, "tombstone material", None)
            .expect("send");

        core.delete_for_everyone(mid.0).expect("delete");

        // Skeleton stays so the timeline can render a tombstone, but
        // the body row is gone.
        core.with_db(|db| {
            let skel = db
                .get_message_skeleton(&mid.0.to_string())
                .unwrap()
                .expect("skel");
            assert_eq!(
                skel.body_state,
                crate::local_store::state_machines::BodyState::DeletedForEveryone
            );
            let body = db.get_message_body(&mid.0.to_string()).unwrap();
            assert!(
                body.is_none(),
                "body must be dropped on delete_for_everyone"
            );
        });
    }

    #[test]
    fn core_impl_edit_nonexistent_message_errors() {
        let core = fresh_core();
        let err = core.edit_message(Uuid::now_v7(), "anything").unwrap_err();
        assert!(matches!(err, Error::Message(_)), "got {err:?}");
    }

    // ----------------------------------------------------------------
    // Task 2 — get_message / get_conversation_messages
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_get_message_round_trip() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "round trip", None).expect("send");

        let view = core.get_message(mid.0).expect("get_message").expect("view");
        assert_eq!(view.message_id, mid.0);
        assert_eq!(view.conversation_id, conv);
        assert_eq!(view.text_content.as_deref(), Some("round trip"));
        assert_eq!(view.sender_id, "self");
        assert!(view.edited_at_ms.is_none());
        assert!(view.deleted_at_ms.is_none());

        // Missing id round-trips to None.
        assert!(core.get_message(Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn core_impl_get_conversation_messages_pagination() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Insert 5 messages with strictly-increasing created_at_ms
        // via the inherent batch ingest path so timestamps are
        // deterministic.
        let mut ids = Vec::new();
        for i in 0..5 {
            let msg = IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: format!("u-{i}"),
                created_at_ms: 1_700_000_000_000 + i as i64,
                text_content: Some(format!("msg {i}")),
                media_descriptors: vec![],
                reply_to: None,
            };
            ids.push(msg.message_id);
            let r = core.ingest_messages(std::slice::from_ref(&msg)).unwrap();
            assert_eq!(r.new_messages, 1);
        }

        // Newest-first, limit honored.
        let page1 = core.get_conversation_messages(conv, None, 3).unwrap();
        assert_eq!(page1.len(), 3);
        assert_eq!(page1[0].message_id, ids[4]);
        assert_eq!(page1[1].message_id, ids[3]);
        assert_eq!(page1[2].message_id, ids[2]);

        // Pagination via before_ms returns the older slice.
        let cursor = page1.last().unwrap().created_at_ms;
        let page2 = core
            .get_conversation_messages(conv, Some(cursor), 10)
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].message_id, ids[1]);
        assert_eq!(page2[1].message_id, ids[0]);

        // limit == 0 returns nothing.
        assert!(
            core.get_conversation_messages(conv, None, 0)
                .unwrap()
                .is_empty(),
            "limit=0 returns nothing"
        );
    }

    // ----------------------------------------------------------------
    // Task 4 — ingest_remote_messages wired to transport
    // ----------------------------------------------------------------

    fn raw_msg(conv: Uuid, mid: Uuid, ts: i64, text: &str) -> crate::transport::RawDeliveryMessage {
        crate::transport::RawDeliveryMessage {
            message_id: mid.to_string(),
            conversation_id: conv.to_string(),
            sender_id: "remote-sender".into(),
            created_at_ms: ts,
            text_content: Some(text.into()),
            media_descriptors: vec![],
            reply_to: None,
        }
    }

    #[test]
    fn core_impl_ingest_remote_with_mock_transport() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let m3 = Uuid::now_v7();
        let staged = crate::transport::FetchResult {
            messages: vec![
                raw_msg(conv, m1, 1_700_000_000_000, "alpha hello"),
                raw_msg(conv, m2, 1_700_000_000_001, "beta hello"),
                raw_msg(conv, m3, 1_700_000_000_002, "gamma hello"),
            ],
            next_cursor: Some("after-3".into()),
        };
        let mock = crate::transport::MockDeliveryClient::new().with_response(None, Ok(staged));
        core.set_delivery_client(Box::new(mock));

        let r = core
            .ingest_remote_messages(conv, None)
            .expect("ingest_remote");
        assert_eq!(r.new_messages, 3);
        assert_eq!(r.duplicate_count, 0);

        let q = SearchQuery {
            query_string: "hello".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 3, "all three messages must be searchable");
    }

    #[test]
    fn core_impl_ingest_remote_deduplicates() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let payload = vec![
            raw_msg(conv, m1, 1_700_000_000_000, "dup-a"),
            raw_msg(conv, m2, 1_700_000_000_001, "dup-b"),
        ];
        let mock = crate::transport::MockDeliveryClient::new()
            .with_response(
                None,
                Ok(crate::transport::FetchResult {
                    messages: payload.clone(),
                    next_cursor: None,
                }),
            )
            .with_response(
                Some("retry-1"),
                Ok(crate::transport::FetchResult {
                    messages: payload,
                    next_cursor: None,
                }),
            );
        core.set_delivery_client(Box::new(mock));

        let r1 = core.ingest_remote_messages(conv, None).unwrap();
        assert_eq!(r1.new_messages, 2);
        assert_eq!(r1.duplicate_count, 0);

        let cursor = DeliveryCursor("retry-1".to_string());
        let r2 = core
            .ingest_remote_messages(conv, Some(cursor))
            .expect("retry");
        assert_eq!(r2.new_messages, 0);
        assert_eq!(r2.duplicate_count, 2);
    }

    #[test]
    fn core_impl_ingest_remote_passes_cursor() {
        // The mock's `with_response(after_cursor, …)` records the
        // expected `after_cursor` for the next call and asserts it
        // matches the actual `after_cursor` argument inside
        // `MockDeliveryClient::fetch_messages`. So if
        // `CoreImpl::ingest_remote_messages` did *not* forward the
        // caller's cursor verbatim, the mock would panic and this
        // test would fail.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mock = crate::transport::MockDeliveryClient::new().with_response(
            Some("cursor-from-caller"),
            Ok(crate::transport::FetchResult::default()),
        );
        core.set_delivery_client(Box::new(mock));

        let cursor = DeliveryCursor("cursor-from-caller".to_string());
        let r = core
            .ingest_remote_messages(conv, Some(cursor))
            .expect("ingest_remote with cursor");
        assert_eq!(r.new_messages, 0);
        assert_eq!(r.duplicate_count, 0);
    }

    // ----------------------------------------------------------------
    // Task 5 — list_conversations reflects latest activity
    // ----------------------------------------------------------------

    #[test]
    fn list_conversations_reflects_latest_message_activity() {
        let core = fresh_core();
        let c_old = Uuid::now_v7();
        let c_new = Uuid::now_v7();
        core.create_conversation(c_old, Some("old"), 1_000).unwrap();
        core.create_conversation(c_new, Some("new"), 2_000).unwrap();

        // Newest-first: c_new is on top to start with.
        let list = core.list_conversations().unwrap();
        assert_eq!(list[0].conversation_id, c_new.to_string());
        assert_eq!(list[1].conversation_id, c_old.to_string());

        // Sending into c_old should bump its last_activity_ms past
        // c_new and move it to the top.
        let mid = core.send_text(c_old, "moves to top", None).unwrap();

        let list = core.list_conversations().unwrap();
        assert_eq!(list[0].conversation_id, c_old.to_string());
        assert_eq!(list[1].conversation_id, c_new.to_string());
        assert_eq!(
            list[0].last_message_id.as_deref(),
            Some(mid.0.to_string()).as_deref()
        );
        assert!(list[0].last_activity_ms >= 1_000);
    }
}
