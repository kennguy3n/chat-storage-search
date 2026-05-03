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

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use zeroize::Zeroizing;

use crate::config::KChatCoreConfig;
use crate::crypto::aead::BlobClass;
use crate::local_store::db::LocalStoreDb;
use crate::local_store::schema::{
    Conversation, MediaAsset, MessageBody, MessageKind, MessageSkeleton,
};
use crate::local_store::state_machines::{ArchiveState, BackupState, BodyState};
use crate::media::processor::process_media;
use crate::media::thumbnail::{ThumbnailGenerator, DEFAULT_MAX_DIMENSION};
use crate::message::processor::{
    IngestResult, IngestedMessage, MessagePersister, MessageProcessor, ProcessorError,
};
use crate::offload::budget::{StorageBudget, StorageBudgetEnforcer};
use crate::offload::eviction::{execute_eviction, plan_eviction};
use crate::search::query_engine::QueryEngine;
use crate::transport::{DeliveryClient, RawDeliveryMessage};
use crate::{
    BackupResult, BackupSource, ClientMessageId, DeliveryCursor, DeviceRegistration, Error,
    HydratedMessage, KChatCore, MessageView, OffloadResult, RestoreResult, Result, SearchQuery,
    SearchResult, SearchScope, SendMediaResult,
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

    /// Return the messages in `conversation_id` as a flat
    /// timeline view (skeleton fields + optional plaintext body),
    /// ordered newest-first. `before_ms`, when `Some`, restricts
    /// the page to messages with `created_at_ms < before_ms`;
    /// `limit` caps the returned page.
    ///
    /// Wraps [`LocalStoreDb::get_timeline`].
    pub fn get_timeline(
        &self,
        conversation_id: Uuid,
        before_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<crate::TimelineRow>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.get_timeline(&conversation_id.to_string(), before_ms, limit)
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Fetch a single message's skeleton plus its (optional) body
    /// in one DB round-trip. Returns `Ok(None)` when no skeleton
    /// row matches `message_id`, or `Ok(Some((skel, None)))` when
    /// the skeleton exists but the body has been dropped (e.g.
    /// after [`KChatCore::delete_for_everyone`]).
    ///
    /// Distinct from the trait-level [`KChatCore::get_message`]
    /// (which returns the public [`MessageView`] shape): this
    /// inherent method exposes the **raw** schema rows so binding
    /// crates and integration tests can pin lifecycle state
    /// without re-shaping through `MessageView`. Wraps
    /// [`LocalStoreDb::get_message_with_body`].
    pub fn get_message_with_body(
        &self,
        message_id: Uuid,
    ) -> Result<Option<(MessageSkeleton, Option<MessageBody>)>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.get_message_with_body(&message_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Fetch a single message's body, if any. Returns `Ok(None)`
    /// when no body row exists for `message_id` (the message may
    /// not exist, may be media-only, or its body may have been
    /// dropped by [`KChatCore::delete_for_everyone`]).
    ///
    /// Used by the hydration display path. Wraps
    /// [`LocalStoreDb::get_message_body`].
    pub fn get_message_body(&self, message_id: Uuid) -> Result<Option<MessageBody>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.get_message_body(&message_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))
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

    fn register_device(&self, _device_id: &str) -> Result<DeviceRegistration> {
        // Phase-1 stub: MLS credential / KeyPackage publication and
        // device-key derivation arrive when the MLS layer lands
        // later in Phase 1 / Phase 2.
        Err(Error::NotImplemented("register_device"))
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
        let mut result = self.ingest_messages(&converted)?;
        // Propagate the transport cursor through `IngestResult` so
        // bridge layers can drive paginated drains without poking
        // into the transport mock.
        result.next_cursor = fetched.next_cursor;
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

    fn delete_conversation(&self, conversation_id: Uuid) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let n = db
            .delete_conversation(&conversation_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))?;
        if n == 0 {
            return Err(Error::Storage(format!(
                "no conversation with id={conversation_id}"
            )));
        }
        Ok(())
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
        conversation_id: Uuid,
        message_id: Uuid,
        plaintext: Vec<u8>,
        mime_type: &str,
        caption: Option<&str>,
    ) -> Result<SendMediaResult> {
        if plaintext.is_empty() {
            return Err(Error::Message(
                "send_media: plaintext must not be empty".into(),
            ));
        }
        if mime_type.is_empty() {
            return Err(Error::Message(
                "send_media: mime_type must not be empty".into(),
            ));
        }

        // 1) Run the chunk + AEAD seal pipeline. The wrapping key is
        //    `K_local_db` (the bytes already retained on `self.key`)
        //    so the wrapped `K_asset` is recoverable from the local
        //    store alone — Phase 3 will rewrap under
        //    `K_archive_root` when an asset is offloaded.
        let processed = process_media(&plaintext, mime_type, &self.key, BlobClass::Media, true)?;

        // 2) Optionally generate a thumbnail. Errors during thumbnail
        //    generation are non-fatal — the timeline can render the
        //    media row without a thumbnail today, and Phase 6 will
        //    plug in the vision / OCR pipelines that produce richer
        //    previews.
        let _thumbnail = ThumbnailGenerator::new()
            .generate_thumbnail(&plaintext, mime_type, DEFAULT_MAX_DIMENSION)
            .ok();

        let now = now_ms_for_send_media();
        let descriptor = processed.descriptor.clone();
        let asset_id = descriptor.asset_id;
        let blob_id = descriptor.blob_id;

        // 3) Persist skeleton + body + media_asset rows inside a
        //    single SAVEPOINT so a failure mid-write doesn't leave
        //    dangling references.
        let db = self.db.lock().map_err(poisoned)?;
        let conn = db.connection();
        conn.execute_batch("SAVEPOINT send_media;")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = (|| -> Result<SendMediaResult> {
            let skel = MessageSkeleton {
                message_id: message_id.to_string(),
                conversation_id: conversation_id.to_string(),
                sender_id: "self".to_string(),
                created_at_ms: now,
                received_at_ms: now,
                kind: MessageKind::Media,
                body_state: BodyState::LocalPlainAvailable,
                media_state: Some(processed.initial_media_state),
                archive_state: ArchiveState::NotArchived,
                backup_state: BackupState::NotBackedUp,
                reply_to: None,
                edited_at_ms: None,
                deleted_at_ms: None,
            };
            db.insert_message_skeleton(&skel)
                .map_err(|e| Error::Storage(e.to_string()))?;

            // Caption (if any) is persisted as the message body so
            // the existing search / edit paths see it.
            if let Some(caption) = caption {
                let body = MessageBody {
                    message_id: skel.message_id.clone(),
                    text_content: Some(caption.to_string()),
                    detected_language: None,
                    rich_meta: None,
                };
                db.insert_message_body(&body)
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }

            let asset = MediaAsset {
                asset_id: asset_id.to_string(),
                message_id: skel.message_id.clone(),
                mime_type: mime_type.to_string(),
                bytes_total: descriptor.bytes_total as i64,
                // Phase 2 keeps the original locally until the
                // upload pipeline confirms — `bytes_local` matches
                // `bytes_total` for now.
                bytes_local: descriptor.bytes_total as i64,
                media_state: processed.initial_media_state,
                wrapped_k_asset: descriptor.wrapped_k_asset.clone(),
                chunk_count: descriptor.chunk_count as i32,
                merkle_root: descriptor.merkle_root.to_vec(),
                blob_id: blob_id.to_string(),
                storage_sink: descriptor
                    .storage_sink
                    .clone()
                    .unwrap_or_else(|| "kchat_backend".to_string()),
            };
            db.insert_media_asset(&asset)
                .map_err(|e| Error::Storage(e.to_string()))?;

            Ok(SendMediaResult {
                client_message_id: ClientMessageId(message_id),
                asset_id,
                descriptor,
            })
        })();

        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE send_media;")
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK TO send_media; RELEASE send_media;");
            }
        }
        result
    }

    fn hydrate_message(&self, message_id: Uuid, _reason: &str) -> Result<HydratedMessage> {
        // Phase-3 foundation: serve from local storage when a body is
        // already present, otherwise return the skeleton with
        // `is_cold = true`. The remote archive fetch path is still
        // queued for `Task 10+` once the manifest reader lands.
        let db = self.db.lock().map_err(poisoned)?;
        let row = db
            .get_message_with_body(&message_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))?;
        let Some((skeleton, body)) = row else {
            return Ok(HydratedMessage::default());
        };
        if skeleton.body_state == BodyState::DeletedForEveryone {
            return Err(Error::Message(
                "hydrate_message: message has been deleted for everyone".to_string(),
            ));
        }
        let conversation_id = Uuid::parse_str(&skeleton.conversation_id).ok();
        let message_id_uuid = Uuid::parse_str(&skeleton.message_id).ok();
        let is_local = matches!(
            skeleton.body_state,
            BodyState::LocalPlainAvailable | BodyState::LocalEncryptedAvailable
        );
        let text_content = body.as_ref().and_then(|b| b.text_content.clone());
        Ok(HydratedMessage {
            message_id: message_id_uuid,
            conversation_id,
            text_content: if is_local { text_content } else { None },
            is_cold: !is_local,
        })
    }

    fn run_incremental_backup(&self, _reason: &str) -> Result<BackupResult> {
        // Phase-1 stub: backup segment packing + manifest signing
        // arrives in Phase 4.
        Err(Error::NotImplemented("run_incremental_backup"))
    }

    fn enforce_storage_budget(&self, _reason: &str) -> Result<OffloadResult> {
        // Phase-3 foundation: assess pressure and execute an
        // empty plan when no candidates are surfaced. Wiring the
        // actual candidate-collection query is queued for once
        // the message_skeleton<->media_asset join is finalised.
        let db = self.db.lock().map_err(poisoned)?;
        let enforcer = StorageBudgetEnforcer::new();
        let budget = StorageBudget::default_recommended();
        let assessment = enforcer.assess(db.connection(), &budget)?;
        if !assessment.pressure_level.requires_eviction() {
            return Ok(OffloadResult {
                freed_bytes: 0,
                evicted_count: 0,
            });
        }
        let target_bytes = (-assessment.headroom_bytes).max(0) as u64;
        let plan = plan_eviction(Vec::new(), target_bytes, now_ms_for_send_media());
        let result = execute_eviction(db.connection(), &plan)?;
        Ok(OffloadResult {
            freed_bytes: result.freed_bytes,
            evicted_count: result.evicted_count,
        })
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

/// Wall-clock millisecond timestamp.
///
/// Mirrors `crate::message::processor::now_ms` (which is private)
/// so the `send_media` / `hydrate_message` paths can stamp
/// `received_at_ms` / `created_at_ms` without poking through the
/// processor module.
fn now_ms_for_send_media() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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

    fn fake_image_bytes() -> Vec<u8> {
        // 8 × 8 PNG with a varied gradient so the encoder produces a
        // reasonable byte count (uniform-colour PNGs collapse to a
        // few dozen bytes which doesn't exercise the chunker).
        use image::{ImageBuffer, ImageFormat, Rgba};
        use std::io::Cursor;
        let img = ImageBuffer::from_fn(64, 64, |x, y| {
            Rgba([
                ((x * 4) & 0xFF) as u8,
                ((y * 4) & 0xFF) as u8,
                ((x ^ y) & 0xFF) as u8,
                0xFF,
            ])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn send_media_persists_media_asset_and_descriptor() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let payload = fake_image_bytes();
        let bytes_total = payload.len() as u64;

        let res = core
            .send_media(conv, mid, payload, "image/png", Some("vacation"))
            .expect("send_media");
        assert_eq!(res.client_message_id.0, mid);
        assert_eq!(res.descriptor.bytes_total, bytes_total);
        assert_eq!(res.descriptor.mime_type, "image/png");
        assert!(res.descriptor.chunk_count >= 1);

        core.with_db(|db| {
            let asset = db
                .get_media_asset(&res.asset_id.to_string())
                .unwrap()
                .expect("asset row");
            assert_eq!(asset.message_id, mid.to_string());
            assert_eq!(asset.mime_type, "image/png");
            assert_eq!(asset.bytes_total as u64, bytes_total);
            assert_eq!(asset.chunk_count as u32, res.descriptor.chunk_count);
            assert_eq!(asset.merkle_root.len(), 32);
        });
    }

    #[test]
    fn send_media_creates_skeleton_with_media_state() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        core.with_db(|db| {
            let skel = db
                .get_message_skeleton(&mid.to_string())
                .unwrap()
                .expect("skeleton");
            assert_eq!(skel.kind, MessageKind::Media);
            assert!(skel.media_state.is_some());
            assert_eq!(
                skel.body_state,
                crate::local_store::state_machines::BodyState::LocalPlainAvailable
            );
        });
    }

    #[test]
    fn send_media_round_trips_through_get_message() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(
            conv,
            mid,
            fake_image_bytes(),
            "image/png",
            Some("captioned"),
        )
        .expect("send_media");

        let view = core.get_message(mid).unwrap().expect("view");
        assert_eq!(view.text_content.as_deref(), Some("captioned"));
    }

    #[test]
    fn send_media_rejects_empty_plaintext() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let err = core
            .send_media(conv, Uuid::now_v7(), Vec::new(), "image/png", None)
            .unwrap_err();
        assert!(matches!(err, Error::Message(_)), "got {err:?}");
    }

    // ----------------------------------------------------------------
    // hydrate_message + enforce_storage_budget — Task 10
    // ----------------------------------------------------------------

    #[test]
    fn hydrate_local_message_returns_body() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "hello hydration", None).unwrap();
        let hydrated = core
            .hydrate_message(mid.0, "search_result_tap")
            .expect("hydrate");
        assert!(!hydrated.is_cold);
        assert_eq!(hydrated.text_content.as_deref(), Some("hello hydration"));
        assert_eq!(hydrated.message_id, Some(mid.0));
        assert_eq!(hydrated.conversation_id, Some(conv));
    }

    #[test]
    fn hydrate_unknown_message_returns_default() {
        let core = fresh_core();
        let result = core
            .hydrate_message(Uuid::now_v7(), "search_result_tap")
            .expect("hydrate");
        assert_eq!(result, HydratedMessage::default());
    }

    #[test]
    fn hydrate_deleted_message_returns_error() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "to-be-deleted", None).unwrap();
        // Force the body_state into DeletedForEveryone so the
        // hydrate path takes the error branch.
        core.with_db(|db| {
            db.connection()
                .execute(
                    "UPDATE message_skeleton SET body_state = 'deleted_for_everyone' WHERE message_id = ?1",
                    rusqlite::params![mid.0.to_string()],
                )
                .unwrap();
        });
        let err = core
            .hydrate_message(mid.0, "search_result_tap")
            .unwrap_err();
        assert!(matches!(err, Error::Message(_)), "got {err:?}");
    }

    #[test]
    fn hydrate_cold_message_returns_skeleton_with_cold_flag() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "cold-body", None).unwrap();
        // Move the body to remote_archive_only so hydrate sees it
        // as cold.
        core.with_db(|db| {
            db.connection()
                .execute(
                    "UPDATE message_skeleton SET body_state = 'remote_archive_only' WHERE message_id = ?1",
                    rusqlite::params![mid.0.to_string()],
                )
                .unwrap();
        });
        let hydrated = core
            .hydrate_message(mid.0, "background_restore")
            .expect("hydrate");
        assert!(hydrated.is_cold);
        assert!(hydrated.text_content.is_none());
        assert_eq!(hydrated.message_id, Some(mid.0));
    }

    #[test]
    fn enforce_storage_budget_returns_zero_under_pressure_threshold() {
        let core = fresh_core();
        // Empty store — no pressure, so the result is zero.
        let result = core.enforce_storage_budget("app_launch").expect("enforce");
        assert_eq!(result.evicted_count, 0);
        assert_eq!(result.freed_bytes, 0);
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

    #[test]
    fn core_impl_ingest_remote_propagates_next_cursor() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let staged = crate::transport::FetchResult {
            messages: vec![raw_msg(
                conv,
                Uuid::now_v7(),
                1_700_000_000_000,
                "cursor-prop",
            )],
            next_cursor: Some("cursor-abc".into()),
        };
        let mock = crate::transport::MockDeliveryClient::new().with_response(None, Ok(staged));
        core.set_delivery_client(Box::new(mock));

        let r = core
            .ingest_remote_messages(conv, None)
            .expect("ingest_remote");
        assert_eq!(r.new_messages, 1);
        assert_eq!(r.next_cursor.as_deref(), Some("cursor-abc"));
    }

    #[test]
    fn core_impl_ingest_remote_none_cursor_when_drained() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mock = crate::transport::MockDeliveryClient::new().with_response(
            None,
            Ok(crate::transport::FetchResult {
                messages: vec![],
                next_cursor: None,
            }),
        );
        core.set_delivery_client(Box::new(mock));

        let r = core
            .ingest_remote_messages(conv, None)
            .expect("ingest_remote");
        assert_eq!(r.new_messages, 0);
        assert!(r.next_cursor.is_none());
    }

    #[test]
    fn core_impl_ingest_messages_inherent_leaves_next_cursor_none() {
        // The inherent `ingest_messages(&[…])` entry point has no
        // transport context, so `next_cursor` must remain `None`.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let r = core
            .ingest_messages(&[IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: Some("inherent".into()),
                media_descriptors: vec![],
                reply_to: None,
            }])
            .expect("ingest");
        assert_eq!(r.new_messages, 1);
        assert!(r.next_cursor.is_none());
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

    // ----------------------------------------------------------------
    // Task 3 — get_timeline (CoreImpl)
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_get_timeline_round_trip_after_send_text() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mid = core.send_text(conv, "first message", None).unwrap();

        let rows = core.get_timeline(conv, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id, mid.0.to_string());
        assert_eq!(rows[0].conversation_id, conv.to_string());
        assert_eq!(rows[0].text_content.as_deref(), Some("first message"));
    }

    #[test]
    fn core_impl_get_timeline_round_trip_after_ingest_messages() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let msgs = vec![
            IngestedMessage {
                message_id: m1,
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: Some("ingested one".into()),
                media_descriptors: vec![],
                reply_to: None,
            },
            IngestedMessage {
                message_id: m2,
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_500,
                text_content: Some("ingested two".into()),
                media_descriptors: vec![],
                reply_to: None,
            },
        ];
        core.ingest_messages(&msgs).expect("ingest");

        let rows = core.get_timeline(conv, None, 10).unwrap();
        assert_eq!(rows.len(), 2);
        // Newest-first.
        assert_eq!(rows[0].message_id, m2.to_string());
        assert_eq!(rows[1].message_id, m1.to_string());
    }

    #[test]
    fn core_impl_get_timeline_paginates_across_pages() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mut msgs = Vec::new();
        for i in 0..5 {
            msgs.push(IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_000 + i,
                text_content: Some(format!("page msg {i}")),
                media_descriptors: vec![],
                reply_to: None,
            });
        }
        core.ingest_messages(&msgs).expect("ingest");

        let page1 = core.get_timeline(conv, None, 2).unwrap();
        assert_eq!(page1.len(), 2);
        let cursor = page1.last().unwrap().created_at_ms;

        let page2 = core.get_timeline(conv, Some(cursor), 2).unwrap();
        assert_eq!(page2.len(), 2);
        assert!(page2.iter().all(|r| r.created_at_ms < cursor));

        let cursor2 = page2.last().unwrap().created_at_ms;
        let page3 = core.get_timeline(conv, Some(cursor2), 2).unwrap();
        assert_eq!(page3.len(), 1);

        let empty = core
            .get_timeline(conv, Some(page3[0].created_at_ms), 2)
            .unwrap();
        assert!(empty.is_empty());
    }

    // ----------------------------------------------------------------
    // Task 4 — get_message_with_body / get_message_body
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_get_message_returns_none_for_missing() {
        let core = fresh_core();
        assert!(core
            .get_message_with_body(Uuid::now_v7())
            .unwrap()
            .is_none());
    }

    #[test]
    fn core_impl_get_message_returns_skeleton_and_body_after_send_text() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "hi there", None).unwrap();

        let (skel, body) = core
            .get_message_with_body(mid.0)
            .unwrap()
            .expect("found message");
        assert_eq!(skel.message_id, mid.0.to_string());
        assert_eq!(skel.conversation_id, conv.to_string());
        let body = body.expect("body present");
        assert_eq!(body.text_content.as_deref(), Some("hi there"));
    }

    #[test]
    fn core_impl_get_message_returns_skeleton_only_after_delete_for_everyone() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "tombstone fodder", None).unwrap();

        core.delete_for_everyone(mid.0).expect("delete");

        let (skel, body) = core
            .get_message_with_body(mid.0)
            .unwrap()
            .expect("skel still present");
        assert_eq!(skel.message_id, mid.0.to_string());
        assert_eq!(
            skel.body_state,
            crate::local_store::state_machines::BodyState::DeletedForEveryone
        );
        assert!(body.is_none(), "body row dropped");
    }

    #[test]
    fn core_impl_get_message_body_returns_none_for_missing() {
        let core = fresh_core();
        assert!(core.get_message_body(Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn core_impl_get_message_body_returns_body_after_ingest() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mid = Uuid::now_v7();
        let msgs = vec![IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("body via ingest".into()),
            media_descriptors: vec![],
            reply_to: None,
        }];
        core.ingest_messages(&msgs).expect("ingest");

        let body = core.get_message_body(mid).unwrap().expect("body present");
        assert_eq!(body.text_content.as_deref(), Some("body via ingest"));
    }

    // ----------------------------------------------------------------
    // Task 5 — delete_conversation
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_delete_conversation_removes_messages_and_search() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let m_send = core.send_text(conv, "send-text alpha", None).expect("send");
        let m_ingest = Uuid::now_v7();
        core.ingest_messages(&[IngestedMessage {
            message_id: m_ingest,
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("ingested beta".into()),
            media_descriptors: vec![],
            reply_to: None,
        }])
        .expect("ingest");

        // Pre-delete sanity: search hits both rows.
        let pre = core
            .search(
                SearchQuery {
                    query_string: "alpha".into(),
                    ..SearchQuery::default()
                },
                SearchScope::LocalOnly,
            )
            .unwrap();
        assert_eq!(pre.len(), 1);

        core.delete_conversation(conv).expect("delete_conversation");

        // Conversation row gone.
        assert!(core.get_conversation(conv).unwrap().is_none());

        // Both messages gone.
        assert!(core.get_message_with_body(m_send.0).unwrap().is_none());
        assert!(core.get_message_with_body(m_ingest).unwrap().is_none());

        // No search hits for either token.
        for token in ["alpha", "beta"] {
            let hits = core
                .search(
                    SearchQuery {
                        query_string: token.into(),
                        ..SearchQuery::default()
                    },
                    SearchScope::LocalOnly,
                )
                .unwrap();
            assert!(
                hits.is_empty(),
                "expected no hits for `{token}` after delete_conversation"
            );
        }
    }

    #[test]
    fn core_impl_delete_conversation_errors_on_missing_id() {
        let core = fresh_core();
        let err = core.delete_conversation(Uuid::now_v7()).unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn core_impl_delete_conversation_removes_all_data() {
        // Mirrors `core_impl_delete_conversation_removes_messages_and_search`
        // but pins the cascade end-to-end on the raw `LocalStoreDb`
        // rows: conversation, skeleton, body, FTS, fuzzy.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // One outbox-minted message (send_text) + one ingested
        // message — exercises both write paths through the cascade.
        let m_send = core.send_text(conv, "delta epsilon", None).expect("send");
        let m_ingest = Uuid::now_v7();
        core.ingest_messages(&[IngestedMessage {
            message_id: m_ingest,
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("zeta eta".into()),
            media_descriptors: vec![],
            reply_to: None,
        }])
        .expect("ingest");

        core.delete_conversation(conv).expect("delete_conversation");

        // Conversation row + every message row + every body row
        // gone. Test directly through the `LocalStoreDb` to defeat
        // any future `MessageView` reshape that hides rows but
        // leaves them persisted.
        core.with_db(|db| {
            assert!(db.get_conversation(&conv.to_string()).unwrap().is_none());
            assert!(db
                .get_message_skeleton(&m_send.0.to_string())
                .unwrap()
                .is_none());
            assert!(db
                .get_message_skeleton(&m_ingest.to_string())
                .unwrap()
                .is_none());
            assert!(db
                .get_message_body(&m_send.0.to_string())
                .unwrap()
                .is_none());
            assert!(db
                .get_message_body(&m_ingest.to_string())
                .unwrap()
                .is_none());
        });
    }

    #[test]
    fn core_impl_delete_conversation_search_cleanup() {
        // Verify FTS + fuzzy hits drop out of search after a
        // conversation is deleted. Distinct from
        // `core_impl_delete_conversation_removes_messages_and_search`
        // because it pre-asserts both FTS *and* fuzzy hits for
        // multiple tokens before deletion, then asserts they are
        // gone afterward.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        core.send_text(conv, "alphafox-unique", None)
            .expect("send a");
        core.send_text(conv, "betagolf-unique", None)
            .expect("send b");

        for token in ["alphafox", "betagolf"] {
            let hits = core
                .search(
                    SearchQuery {
                        query_string: token.into(),
                        ..SearchQuery::default()
                    },
                    SearchScope::LocalOnly,
                )
                .unwrap();
            assert_eq!(hits.len(), 1, "pre-delete: {token}");
        }

        core.delete_conversation(conv).expect("delete_conversation");

        for token in ["alphafox", "betagolf"] {
            let hits = core
                .search(
                    SearchQuery {
                        query_string: token.into(),
                        ..SearchQuery::default()
                    },
                    SearchScope::LocalOnly,
                )
                .unwrap();
            assert!(hits.is_empty(), "post-delete: {token}");
        }
    }

    // ----------------------------------------------------------------
    // Task 4 — register_device stub
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_register_device_returns_not_implemented() {
        let core = fresh_core();
        let err = core.register_device("device-abc").unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented("register_device")),
            "got {err:?}",
        );
    }
}
