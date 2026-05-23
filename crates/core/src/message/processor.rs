//! Message processor — skeleton.
//!
//! `docs/DESIGN.md §11` describes the
//! ingest / outbox pipeline:
//!
//! * The library consumes **already-decrypted** MLS application
//!   messages (this module's `IngestedMessage`).
//! * Idempotency is keyed by `message_id` — re-ingesting the same
//!   message must be a no-op.
//! * The outbox carries client-originated text sends until MLS
//!   delivery confirms. `OutboxEntry::client_message_id` is a UUID
//!   v7 so monotonic ordering survives crashes.
//!
//! The deliverable scoped to this module is the **types and pure
//! validators**; the database-backed implementation lives in
//! [`MessagePersister`] below.

use std::collections::HashSet;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::archive::event_journal::{ArchiveEvent, ArchiveEventJournal, ArchiveEventType};
use crate::formats::media_descriptor::MediaDescriptor;
use crate::local_store::db::{DbError, LocalStoreDb};
use crate::local_store::schema::{
    BackupEventJournalEntry, MediaAsset, MessageBody, MessageKind, MessageSkeleton,
};
use crate::local_store::state_machines::{
    ArchiveState, BackupState, BodyState, MediaState, StateTransitionError,
};
use crate::search::fuzzy_search::FuzzyIndexWriter;
use crate::ClientMessageId;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by the [`MessageProcessor`].
///
/// Deliberately does **not** derive `Clone` / `PartialEq` / `Eq`:
/// the wrapped `rusqlite::Error` (via [`DbError`]) is not
/// equality-comparable, and a stringified-on-clone variant would
/// silently break the reflexivity contract `Eq` requires. Tests use
/// `matches!` and downstream callers should pattern-match on the
/// variants directly.
#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    /// The ingested message failed validation (empty id, empty
    /// conversation id, non-positive timestamps, …).
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// The message has already been ingested.
    #[error("duplicate message")]
    DuplicateMessage,

    /// A storage-layer call failed. Specific causes (database
    /// busy, AEAD open failure, …) are surfaced as a stringified
    /// description.
    #[error("storage: {0}")]
    StorageError(String),

    /// A `rusqlite` call failed inside [`MessagePersister`].
    #[error("db: {0}")]
    Db(#[from] DbError),

    /// A body-state transition rejected by the state machine.
    #[error("illegal state transition: {0}")]
    IllegalTransition(#[from] StateTransitionError),
}

// ---------------------------------------------------------------------------
// Ingest pipeline types
// ---------------------------------------------------------------------------

/// MLS-decrypted application message, ready to be persisted.
///
/// The `media_descriptors` carry zero or more
/// [`MediaDescriptor`]s — one per attached media object. Text-only
/// messages have an empty `Vec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestedMessage {
    /// Stable message identifier set by the sender (UUID v7).
    pub message_id: Uuid,
    /// Owning conversation.
    pub conversation_id: Uuid,
    /// Sender identifier (string — KChat's identity layer owns the
    /// shape; from this library's perspective it is opaque).
    pub sender_id: String,
    /// Wall-clock millisecond timestamp set by the sender.
    pub created_at_ms: i64,
    /// Plaintext text body. `None` for media-only messages.
    pub text_content: Option<String>,
    /// Zero or more media descriptors (`docs/DESIGN.md §3.2`).
    pub media_descriptors: Vec<MediaDescriptor>,
    /// Identifier of the message this is a reply to, if any.
    pub reply_to: Option<Uuid>,
}

/// Result of ingesting a batch of MLS messages.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestResult {
    /// Newly-inserted skeleton rows.
    pub new_messages: u32,
    /// Existing skeleton rows updated (e.g. edits).
    pub updated_messages: u32,
    /// Duplicates skipped on the basis of `message_id`.
    pub duplicate_count: u32,
    /// Opaque transport cursor pointing at the next page of
    /// messages, or `None` when the delivery store is drained.
    /// Populated by
    /// [`crate::core_impl::CoreImpl::ingest_remote_messages`] from
    /// the underlying [`crate::transport::FetchResult::next_cursor`];
    /// the inherent
    /// [`crate::core_impl::CoreImpl::ingest_messages`] entry point
    /// (which has no transport context) leaves it as `None`.
    pub next_cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// Outbox
// ---------------------------------------------------------------------------

/// Outbox-entry lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    /// Created locally; not yet handed to MLS.
    Pending,
    /// Handed to MLS; awaiting delivery confirmation.
    Sending,
    /// MLS confirmed delivery. The skeleton row's
    /// `body_state` advances from delivery-store-only to
    /// local-plain-available.
    Sent,
    /// MLS reported a permanent failure. UI surfaces a retry.
    Failed,
}

/// Pending text send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEntry {
    /// Client-side message identifier (UUID v7 — monotonic).
    pub client_message_id: Uuid,
    /// Owning conversation.
    pub conversation_id: Uuid,
    /// Plaintext text body.
    pub text_content: String,
    /// Identifier of the message this is a reply to, if any.
    pub reply_to: Option<Uuid>,
    /// Wall-clock millisecond timestamp when the entry was created.
    pub created_at_ms: i64,
    /// Lifecycle state.
    pub status: OutboxStatus,
}

// ---------------------------------------------------------------------------
// MessageProcessor
// ---------------------------------------------------------------------------

/// Pure-Rust validators / helpers used by the message
/// processor. The DB-backed `MessageProcessor` instance lands when
/// SQLCipher integration ships; the static helpers here are usable
/// today and are what the unit tests exercise.
#[derive(Debug, Default)]
pub struct MessageProcessor {
    _private: (),
}

impl MessageProcessor {
    /// Construct a placeholder processor.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Validate that `msg` has the minimum fields required to be
    /// persisted.
    ///
    /// Layers additional checks (sender membership in the
    /// MLS group, conversation existence, edit-vs-create
    /// disambiguation) on top of this baseline. The checks here are
    /// the ones that always apply, regardless of MLS context.
    pub fn validate_ingest(msg: &IngestedMessage) -> Result<(), ProcessorError> {
        if msg.message_id.is_nil() {
            return Err(ProcessorError::InvalidMessage(
                "message_id must not be nil".into(),
            ));
        }
        if msg.conversation_id.is_nil() {
            return Err(ProcessorError::InvalidMessage(
                "conversation_id must not be nil".into(),
            ));
        }
        if msg.sender_id.is_empty() {
            return Err(ProcessorError::InvalidMessage(
                "sender_id must not be empty".into(),
            ));
        }
        if msg.created_at_ms <= 0 {
            return Err(ProcessorError::InvalidMessage(format!(
                "created_at_ms must be positive (got {})",
                msg.created_at_ms
            )));
        }
        if msg.text_content.is_none() && msg.media_descriptors.is_empty() {
            return Err(ProcessorError::InvalidMessage(
                "message has neither text nor media".into(),
            ));
        }
        if let Some(text) = &msg.text_content {
            if text.is_empty() {
                return Err(ProcessorError::InvalidMessage(
                    "text_content must not be empty when present".into(),
                ));
            }
        }
        Ok(())
    }

    /// Whether `message_id` has already been ingested.
    pub fn is_duplicate(message_id: &Uuid, existing_ids: &HashSet<Uuid>) -> bool {
        existing_ids.contains(message_id)
    }

    /// Build a new outbox entry with a fresh UUID v7
    /// `client_message_id`. The `created_at_ms` field is sourced from
    /// the local clock at call time.
    ///
    /// `text` must be non-empty — empty sends are rejected at this
    /// boundary rather than being silently dropped further downstream.
    pub fn create_outbox_entry(
        conversation_id: Uuid,
        text: &str,
        reply_to: Option<Uuid>,
    ) -> Result<OutboxEntry, ProcessorError> {
        if text.is_empty() {
            return Err(ProcessorError::InvalidMessage(
                "outbox text_content must not be empty".into(),
            ));
        }
        Ok(OutboxEntry {
            client_message_id: Uuid::now_v7(),
            conversation_id,
            text_content: text.to_string(),
            reply_to,
            created_at_ms: now_ms(),
            status: OutboxStatus::Pending,
        })
    }
}

/// Wall-clock millisecond timestamp.
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// MessagePersister — DB-backed counterpart to MessageProcessor
// ---------------------------------------------------------------------------

/// DB-backed persistence helper that wires the pure validators above
/// to a [`LocalStoreDb`] connection.
///
/// The persister is intentionally stateless apart from its borrow on
/// `LocalStoreDb`: every public method acquires a transaction
/// internally, performs all writes (skeleton + body + FTS row +
/// backup-event-journal entry), and commits as a single unit so a
/// crash mid-ingest cannot leave the FTS index out of sync with the
/// skeleton table.
#[derive(Debug)]
pub struct MessagePersister<'a> {
    db: &'a LocalStoreDb,
}

impl<'a> MessagePersister<'a> {
    /// Construct a new persister against the supplied database
    /// connection.
    pub fn new(db: &'a LocalStoreDb) -> Self {
        Self { db }
    }

    /// Persist an MLS-decrypted [`IngestedMessage`].
    ///
    /// Inside one transaction the persister:
    ///
    /// 1. Validates the message via [`MessageProcessor::validate_ingest`].
    /// 2. Rejects duplicates (existing `message_skeleton` row keyed
    ///    on `message_id`).
    /// 3. Inserts the skeleton (`body_state = local_plain_available`)
    ///    and, when `text_content.is_some`, a `message_body` row.
    /// 4. Inserts an FTS5 row into `search_fts` for text messages so
    ///    the row is searchable as soon as the transaction commits.
    /// 5. Writes a `"message_received"` entry into
    ///    `backup_event_journal` (CBOR payload: `[message_id,
    ///    conversation_id, sender_id, created_at_ms]`).
    pub fn persist_ingested_message(&self, msg: &IngestedMessage) -> Result<(), ProcessorError> {
        MessageProcessor::validate_ingest(msg)?;
        let conn = self.db.connection();
        // Duplicate check before opening the transaction so the
        // common "already-ingested" case returns immediately without
        // taking a write lock.
        if self.skeleton_exists(&msg.message_id.to_string())? {
            return Err(ProcessorError::DuplicateMessage);
        }

        // Transaction boundary: skeleton + body + FTS + journal.
        // SAVEPOINT is used so this works against connections held
        // immutably (Connection::transaction wants &mut).
        conn.execute_batch("SAVEPOINT persist_ingest;")
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        let result = self.persist_ingested_message_inner(msg);
        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE persist_ingest;")
                    .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK TO persist_ingest; RELEASE persist_ingest;");
            }
        }
        result
    }

    fn persist_ingested_message_inner(&self, msg: &IngestedMessage) -> Result<(), ProcessorError> {
        // When a message arrives with both text and media descriptors,
        // media takes priority for the row's `kind` because the offload /
        // archive / hydration paths key off `MessageKind::Media` to drive
        // thumbnail-then-original flows. The text body is still persisted
        // and indexed below.
        let kind = if !msg.media_descriptors.is_empty() {
            MessageKind::Media
        } else if msg.text_content.is_some() {
            MessageKind::Text
        } else {
            // validate_ingest already rejects this combination, but
            // double-check rather than risk a malformed row.
            return Err(ProcessorError::InvalidMessage(
                "message has neither text nor media".into(),
            ));
        };

        // `docs/DESIGN.md §5.7`: a message arriving with a
        // `MediaDescriptor` carries the *thumbnail* + the
        // backend-side metadata for the original. The original
        // bytes haven't been pulled yet, so the skeleton lands in
        // `MediaState::ThumbnailOnly` whenever any descriptor is
        // attached, regardless of whether a text body is also
        // present, so the skeleton's `media_state` stays consistent
        // with the per-asset `media_asset.media_state` rows.
        let initial_media_state = if !msg.media_descriptors.is_empty() {
            Some(MediaState::ThumbnailOnly)
        } else {
            None
        };
        let skel = MessageSkeleton {
            message_id: msg.message_id.to_string(),
            conversation_id: msg.conversation_id.to_string(),
            sender_id: msg.sender_id.clone(),
            created_at_ms: msg.created_at_ms,
            received_at_ms: now_ms(),
            kind,
            body_state: BodyState::LocalPlainAvailable,
            media_state: initial_media_state,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: msg.reply_to.map(|u| u.to_string()),
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        self.db.insert_message_skeleton(&skel)?;

        // For each descriptor attached to the inbound MLS payload,
        // land a `media_asset` row. Defaults to the
        // `kchat_backend` storage sink when the sender did not set
        // one — matches `docs/DESIGN.md §5.7`'s "default sink"
        // policy.
        for desc in &msg.media_descriptors {
            let asset = MediaAsset {
                asset_id: desc.asset_id.to_string(),
                message_id: skel.message_id.clone(),
                mime_type: desc.mime_type.clone(),
                bytes_total: desc.bytes_total as i64,
                bytes_local: 0,
                media_state: MediaState::ThumbnailOnly,
                wrapped_k_asset: desc.wrapped_k_asset.clone(),
                chunk_count: desc.chunk_count as i32,
                merkle_root: desc.merkle_root.to_vec(),
                blob_id: desc.blob_id.to_string(),
                storage_sink: desc
                    .storage_sink
                    .clone()
                    .unwrap_or_else(|| "kchat_backend".to_string()),
            };
            self.db.insert_media_asset(&asset)?;
        }

        if let Some(text) = &msg.text_content {
            let body = MessageBody {
                message_id: skel.message_id.clone(),
                text_content: Some(text.clone()),
                detected_language: None,
                rich_meta: None,
            };
            self.db.insert_message_body(&body)?;
            self.insert_fts_row(
                &skel.message_id,
                &skel.conversation_id,
                &skel.sender_id,
                skel.created_at_ms,
                text,
            )?;
            FuzzyIndexWriter::new(self.db).index_message(&skel.message_id, text)?;
        }

        // Bump the owning conversation's last_message_id /
        // last_activity_ms so list_conversations reflects the
        // freshly-arrived message. A missing conversation row is
        // not an error here — leaves conversation creation
        // to the caller, and pre-existing tests insert a skeleton
        // before its conversation has been registered.
        self.db.update_conversation_last_message(
            &skel.conversation_id,
            &skel.message_id,
            skel.created_at_ms,
        )?;

        let payload = encode_event_payload(
            &skel.message_id,
            &skel.conversation_id,
            &skel.sender_id,
            skel.created_at_ms,
        );
        let entry = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "message_received".into(),
            conversation_id: Some(skel.conversation_id.clone()),
            message_id: Some(skel.message_id.clone()),
            payload: payload.clone(),
            created_at_ms: now_ms(),
        };
        self.db.insert_backup_event(&entry)?;

        // Mirror the backup-side event into the archive
        // event journal so the segment builder will pick this
        // message up on its next drain. The write happens inside
        // the same `SAVEPOINT persist_ingest;` boundary opened by
        // `persist_ingested_message`, so a rollback discards both
        // journals together. The archive payload carries the
        // full `text_content` so the cold-hit hydration
        // path can extract the body — see
        // `crate::archive::body_payload`.
        let archive_payload = crate::archive::body_payload::encode(msg.text_content.as_deref())
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        let archive_event = ArchiveEvent {
            event_type: ArchiveEventType::MessageReceived,
            conversation_id: msg.conversation_id,
            message_id: Some(msg.message_id),
            payload: archive_payload,
            created_at_ms: skel.created_at_ms,
        };
        ArchiveEventJournal::new()
            .write_event(self.db.connection(), &archive_event)
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Persist a client-originated outbox entry.
    ///
    /// The outbox entry's `client_message_id` becomes the skeleton's
    /// `message_id`. `body_state` is set to
    /// [`BodyState::LocalPlainAvailable`] because the user's plain
    /// text is on disk from the moment the entry is created. The
    /// returned [`ClientMessageId`] is the same UUID v7 already on
    /// the entry — handing it back is a convenience for callers that
    /// pipe the outbox creation directly into the persister.
    pub fn persist_outbox_entry(
        &self,
        entry: &OutboxEntry,
    ) -> Result<ClientMessageId, ProcessorError> {
        if entry.text_content.is_empty() {
            return Err(ProcessorError::InvalidMessage(
                "outbox text_content must not be empty".into(),
            ));
        }
        if entry.client_message_id.get_version_num() != 7 {
            return Err(ProcessorError::InvalidMessage(
                "client_message_id must be a UUID v7".into(),
            ));
        }
        let mid = entry.client_message_id.to_string();
        if self.skeleton_exists(&mid)? {
            return Err(ProcessorError::DuplicateMessage);
        }

        let conn = self.db.connection();
        conn.execute_batch("SAVEPOINT persist_outbox;")
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        let result = self.persist_outbox_entry_inner(entry);
        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE persist_outbox;")
                    .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK TO persist_outbox; RELEASE persist_outbox;");
            }
        }
        result?;
        Ok(ClientMessageId(entry.client_message_id))
    }

    fn persist_outbox_entry_inner(&self, entry: &OutboxEntry) -> Result<(), ProcessorError> {
        let mid = entry.client_message_id.to_string();
        let conv = entry.conversation_id.to_string();
        let skel = MessageSkeleton {
            message_id: mid.clone(),
            conversation_id: conv.clone(),
            // Outbox sender id is the placeholder "self"
            // KChat's identity layer fills the real id in once the
            // device-side identity wiring lands.
            sender_id: "self".into(),
            created_at_ms: entry.created_at_ms,
            received_at_ms: entry.created_at_ms,
            kind: MessageKind::Text,
            body_state: BodyState::LocalPlainAvailable,
            media_state: None,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: entry.reply_to.map(|u| u.to_string()),
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        self.db.insert_message_skeleton(&skel)?;
        let body = MessageBody {
            message_id: mid.clone(),
            text_content: Some(entry.text_content.clone()),
            detected_language: None,
            rich_meta: None,
        };
        self.db.insert_message_body(&body)?;
        self.insert_fts_row(
            &mid,
            &conv,
            "self",
            entry.created_at_ms,
            &entry.text_content,
        )?;
        FuzzyIndexWriter::new(self.db).index_message(&mid, &entry.text_content)?;

        // Bump the owning conversation's last_message_id /
        // last_activity_ms so the conversation list surfaces the
        // freshly-sent outbox entry. See
        // `persist_ingested_message_inner` for the matching ingest
        // side.
        self.db
            .update_conversation_last_message(&conv, &mid, entry.created_at_ms)?;

        let payload = encode_event_payload(&mid, &conv, "self", entry.created_at_ms);
        let journal = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "outbox_pending".into(),
            conversation_id: Some(conv.clone()),
            message_id: Some(mid.clone()),
            payload: payload.clone(),
            created_at_ms: now_ms(),
        };
        self.db.insert_backup_event(&journal)?;

        // Mirror the send into the archive event journal as a
        // `MessageReceived` event — from the personal archive's
        // point of view, an outbox-originated message lands in
        // the local store the same way an MLS-ingested one does.
        // The write rides inside `SAVEPOINT persist_outbox;`.
        // The archive payload carries the full `text_content`
        // (cold-hit hydration) — see
        // `crate::archive::body_payload`.
        let archive_payload = crate::archive::body_payload::encode(Some(&entry.text_content))
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        let archive_event = ArchiveEvent {
            event_type: ArchiveEventType::MessageReceived,
            conversation_id: entry.conversation_id,
            message_id: Some(entry.client_message_id),
            payload: archive_payload,
            created_at_ms: entry.created_at_ms,
        };
        ArchiveEventJournal::new()
            .write_event(self.db.connection(), &archive_event)
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Whether `client_message_id` (or, equivalently, an
    /// already-ingested `message_id`) exists in `message_skeleton`.
    pub fn check_duplicate(&self, client_message_id: &str) -> Result<bool, ProcessorError> {
        self.skeleton_exists(client_message_id)
    }

    /// Mark an outbox entry as having been confirmed by the MLS
    /// delivery layer. The confirmation is recorded as an
    /// `"outbox_sent"` entry in `backup_event_journal`; a later
    /// iteration lifts it into a dedicated outbox-status column.
    pub fn mark_sent(&self, client_message_id: &str) -> Result<(), ProcessorError> {
        // Look up the row to confirm it exists and to populate the
        // event payload. We do not change body_state — the message
        // was already local_plain_available at create time.
        let conn = self.db.connection();
        let lookup: Option<(String, String, i64)> = conn
            .query_row(
                "SELECT conversation_id, sender_id, created_at_ms
                 FROM message_skeleton WHERE message_id = ?1",
                params![client_message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        let (conv, sender, created_at) = match lookup {
            Some(v) => v,
            None => {
                return Err(ProcessorError::InvalidMessage(format!(
                    "no outbox entry with client_message_id={client_message_id}"
                )));
            }
        };
        let payload = encode_event_payload(client_message_id, &conv, &sender, created_at);
        let entry = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "outbox_sent".into(),
            conversation_id: Some(conv),
            message_id: Some(client_message_id.to_string()),
            payload,
            created_at_ms: now_ms(),
        };
        self.db.insert_backup_event(&entry)?;
        Ok(())
    }

    /// Replace the text body of an existing local-plain message and
    /// keep the FTS index in sync.
    ///
    /// Inside one `SAVEPOINT` boundary the persister:
    ///
    /// 1. Loads the skeleton (must exist; `body_state` must be
    ///    [`BodyState::LocalPlainAvailable`]).
    /// 2. Updates `message_body.text_content` and
    ///    `message_skeleton.edited_at_ms`.
    /// 3. Refreshes the `search_fts` row by deleting the old entry
    ///    and re-inserting with the new text.
    /// 4. Writes a `"message_edited"` entry to
    ///    `backup_event_journal` (CBOR map carrying `message_id` and
    ///    `edited_at_ms`).
    ///
    /// `new_text` must be non-empty.
    pub fn edit_message(&self, message_id: &str, new_text: &str) -> Result<(), ProcessorError> {
        if new_text.is_empty() {
            return Err(ProcessorError::InvalidMessage(
                "edit text_content must not be empty".into(),
            ));
        }
        let skel = self.db.get_message_skeleton(message_id)?.ok_or_else(|| {
            ProcessorError::InvalidMessage(format!("no message with id={message_id}"))
        })?;
        if skel.body_state != BodyState::LocalPlainAvailable {
            return Err(ProcessorError::InvalidMessage(format!(
                "edit requires body_state=local_plain_available, found {}",
                skel.body_state
            )));
        }

        let edited_at_ms = now_ms();
        let conn = self.db.connection();
        conn.execute_batch("SAVEPOINT edit_message;")
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        let result = self.edit_message_inner(&skel, new_text, edited_at_ms);
        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE edit_message;")
                    .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK TO edit_message; RELEASE edit_message;");
            }
        }
        result
    }

    fn edit_message_inner(
        &self,
        skel: &MessageSkeleton,
        new_text: &str,
        edited_at_ms: i64,
    ) -> Result<(), ProcessorError> {
        self.db
            .update_message_body_text(&skel.message_id, new_text)?;
        self.db
            .update_skeleton_edited(&skel.message_id, edited_at_ms)?;
        self.db.delete_fts_row(&skel.message_id)?;
        self.insert_fts_row(
            &skel.message_id,
            &skel.conversation_id,
            &skel.sender_id,
            skel.created_at_ms,
            new_text,
        )?;
        let fuzzy = FuzzyIndexWriter::new(self.db);
        fuzzy.remove_message(&skel.message_id)?;
        fuzzy.index_message(&skel.message_id, new_text)?;
        // Invalidate the pre-edit embedding so semantic search
        // does not surface the old text. Re-embedding is the
        // CoreImpl ingest path's job (it owns the
        // `TextEmbedder` slot) and runs lazily on the next
        // ingest tick / cache miss; here we only ensure no
        // stale row remains.
        self.db.delete_vector_row(&skel.message_id)?;
        let payload = encode_edit_event_payload(&skel.message_id, edited_at_ms);
        let entry = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "message_edited".into(),
            conversation_id: Some(skel.conversation_id.clone()),
            message_id: Some(skel.message_id.clone()),
            payload,
            created_at_ms: edited_at_ms,
        };
        self.db.insert_backup_event(&entry)?;

        // Archive-side mirror of the edit. Rides inside
        // `SAVEPOINT edit_message;` so a downstream failure
        // discards both journal writes. The archive payload
        // carries the *edited* body text inside the
        // `KCHAT_ARCHIVE_BODY_PAYLOAD_V1` envelope so the Phase
        // 5 cold-hit hydration path lands the post-edit body
        // when the segment is re-fetched from cold storage.
        let conversation_id = Uuid::parse_str(&skel.conversation_id).map_err(|e| {
            ProcessorError::StorageError(format!("invalid conversation_id in store: {e}"))
        })?;
        let message_id = Uuid::parse_str(&skel.message_id).map_err(|e| {
            ProcessorError::StorageError(format!("invalid message_id in store: {e}"))
        })?;
        let archive_payload = crate::archive::body_payload::encode(Some(new_text))
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        let archive_event = ArchiveEvent {
            event_type: ArchiveEventType::MessageEdited,
            conversation_id,
            message_id: Some(message_id),
            payload: archive_payload,
            created_at_ms: edited_at_ms,
        };
        ArchiveEventJournal::new()
            .write_event(self.db.connection(), &archive_event)
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Soft-delete a message locally (`delete-for-me`). The body row
    /// is kept so the message remains restorable, but the FTS row is
    /// removed so the message stops appearing in search.
    ///
    /// Inside one `SAVEPOINT` boundary:
    ///
    /// 1. Loads the skeleton; `try_transition(body_state, DeletedForMe)`
    ///    must succeed.
    /// 2. Updates `body_state` to [`BodyState::DeletedForMe`] and
    ///    `deleted_at_ms` to now.
    /// 3. Removes the `search_fts` row.
    /// 4. Writes a `"message_deleted"` journal entry with
    ///    `{"scope": "for_me"}`.
    pub fn delete_for_me(&self, message_id: &str) -> Result<(), ProcessorError> {
        self.delete_inner(message_id, DeleteScope::ForMe)
    }

    /// Tombstone a message for everyone (`delete-for-everyone`). The
    /// body row is removed so the plaintext is gone; the FTS row is
    /// removed so the message stops appearing in search; the
    /// skeleton stays in place with `body_state = deleted_for_everyone`
    /// so the timeline can render a tombstone.
    ///
    /// Same `SAVEPOINT` shape as [`Self::delete_for_me`], but the
    /// state machine transition is to [`BodyState::DeletedForEveryone`]
    /// and the `message_body` row is also dropped.
    pub fn delete_for_everyone(&self, message_id: &str) -> Result<(), ProcessorError> {
        self.delete_inner(message_id, DeleteScope::ForEveryone)
    }

    fn delete_inner(&self, message_id: &str, scope: DeleteScope) -> Result<(), ProcessorError> {
        let skel = self.db.get_message_skeleton(message_id)?.ok_or_else(|| {
            ProcessorError::InvalidMessage(format!("no message with id={message_id}"))
        })?;
        let target = match scope {
            DeleteScope::ForMe => BodyState::DeletedForMe,
            DeleteScope::ForEveryone => BodyState::DeletedForEveryone,
        };
        // try_transition validates the legal-transition table; the
        // returned state is always equal to `target` on success.
        BodyState::try_transition(skel.body_state, target)?;

        let deleted_at_ms = now_ms();
        let conn = self.db.connection();
        conn.execute_batch("SAVEPOINT delete_message;")
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        let result = self.delete_inner_tx(&skel, scope, target, deleted_at_ms);
        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE delete_message;")
                    .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK TO delete_message; RELEASE delete_message;");
            }
        }
        result
    }

    fn delete_inner_tx(
        &self,
        skel: &MessageSkeleton,
        scope: DeleteScope,
        target: BodyState,
        deleted_at_ms: i64,
    ) -> Result<(), ProcessorError> {
        self.db
            .update_skeleton_deleted(&skel.message_id, deleted_at_ms, target)?;
        self.db.delete_fts_row(&skel.message_id)?;
        // Drop the cross-pipeline embedding row so a deleted
        // message no longer surfaces via
        // `QueryEngine::execute_search_with_semantic`. The FTS /
        // fuzzy / vector cleanup is symmetric across the three
        // search lanes; without this, `SemanticSearchEngine`
        // would still find the orphan vector row and
        // `fetch_skeleton_columns_for_semantic` (which does not
        // filter on `body_state`) would materialize it.
        self.db.delete_vector_row(&skel.message_id)?;
        FuzzyIndexWriter::new(self.db).remove_message(&skel.message_id)?;
        if matches!(scope, DeleteScope::ForEveryone) {
            self.db.delete_message_body(&skel.message_id)?;
        }
        let payload = encode_delete_event_payload(&skel.message_id, scope.label());
        let entry = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "message_deleted".into(),
            conversation_id: Some(skel.conversation_id.clone()),
            message_id: Some(skel.message_id.clone()),
            payload: payload.clone(),
            created_at_ms: deleted_at_ms,
        };
        self.db.insert_backup_event(&entry)?;

        // For each media asset attached to the deleted message,
        // emit an explicit `media_deleted` backup event. The
        // compaction planner already drops orphan `MediaReceived`
        // rows under a `MessageDeleted` tombstone, but writing one
        // explicit `MediaDeleted` per asset keeps the backup
        // taxonomy aligned with `BackupEventType::MediaDeleted` and
        // lets downstream consumers (restore, compaction across
        // non-adjacent segments) reason about media without having
        // to walk the skeleton table. Multi-asset messages emit one
        // event per asset.
        let attached_assets = self
            .db
            .list_media_assets_by_message(&skel.message_id)
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        for asset in &attached_assets {
            let media_payload =
                encode_media_delete_event_payload(&asset.asset_id, &skel.message_id);
            let media_entry = BackupEventJournalEntry {
                event_seq: 0,
                event_type: "media_deleted".into(),
                conversation_id: Some(skel.conversation_id.clone()),
                message_id: Some(skel.message_id.clone()),
                payload: media_payload,
                created_at_ms: deleted_at_ms,
            };
            self.db.insert_backup_event(&media_entry)?;
        }

        // Archive-side delete event. Rides inside
        // `SAVEPOINT delete_message;`.
        let conversation_id = Uuid::parse_str(&skel.conversation_id).map_err(|e| {
            ProcessorError::StorageError(format!("invalid conversation_id in store: {e}"))
        })?;
        let message_id = Uuid::parse_str(&skel.message_id).map_err(|e| {
            ProcessorError::StorageError(format!("invalid message_id in store: {e}"))
        })?;
        let archive_event = ArchiveEvent {
            event_type: ArchiveEventType::MessageDeleted,
            conversation_id,
            message_id: Some(message_id),
            payload,
            created_at_ms: deleted_at_ms,
        };
        ArchiveEventJournal::new()
            .write_event(self.db.connection(), &archive_event)
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn skeleton_exists(&self, message_id: &str) -> Result<bool, ProcessorError> {
        let count: i64 = self
            .db
            .connection()
            .query_row(
                "SELECT count(*) FROM message_skeleton WHERE message_id = ?1",
                params![message_id],
                |row| row.get(0),
            )
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        Ok(count > 0)
    }

    fn insert_fts_row(
        &self,
        message_id: &str,
        conversation_id: &str,
        sender_id: &str,
        created_at_ms: i64,
        text: &str,
    ) -> Result<(), ProcessorError> {
        self.db
            .connection()
            .execute(
                "INSERT INTO search_fts(
                    message_id, conversation_id, sender_id,
                    created_at_ms, text_content
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![message_id, conversation_id, sender_id, created_at_ms, text],
            )
            .map_err(|e| ProcessorError::StorageError(e.to_string()))?;
        Ok(())
    }
}

/// Whether a delete affects only the local user (`delete-for-me`)
/// or everyone in the conversation (`delete-for-everyone`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeleteScope {
    ForMe,
    ForEveryone,
}

impl DeleteScope {
    fn label(self) -> &'static str {
        match self {
            DeleteScope::ForMe => "for_me",
            DeleteScope::ForEveryone => "for_everyone",
        }
    }
}

/// Encode the CBOR map payload for a `"message_edited"` journal
/// entry: `{ "message_id": <str>, "edited_at_ms": <int> }`.
fn encode_edit_event_payload(message_id: &str, edited_at_ms: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    // Map of 2 entries.
    out.push(0xa2);
    push_cbor_text(&mut out, "message_id");
    push_cbor_text(&mut out, message_id);
    push_cbor_text(&mut out, "edited_at_ms");
    push_cbor_int(&mut out, edited_at_ms);
    out
}

/// Encode the CBOR map payload for a `"message_deleted"` journal
/// entry: `{ "message_id": <str>, "scope": "for_me" | "for_everyone" }`.
fn encode_delete_event_payload(message_id: &str, scope: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    // Map of 2 entries.
    out.push(0xa2);
    push_cbor_text(&mut out, "message_id");
    push_cbor_text(&mut out, message_id);
    push_cbor_text(&mut out, "scope");
    push_cbor_text(&mut out, scope);
    out
}

/// Encode the CBOR map payload for a `"media_deleted"` journal
/// entry: `{ "asset_id": <str>, "message_id": <str> }`. Emitted from
/// `delete_message` when the deleted message had attached media so
/// the backup-side tombstone taxonomy stays explicit
/// (`BackupEventType::MediaDeleted`).
fn encode_media_delete_event_payload(asset_id: &str, message_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    // Map of 2 entries.
    out.push(0xa2);
    push_cbor_text(&mut out, "asset_id");
    push_cbor_text(&mut out, asset_id);
    push_cbor_text(&mut out, "message_id");
    push_cbor_text(&mut out, message_id);
    out
}

/// Encode a `[message_id, conversation_id, sender_id, created_at_ms]`
/// CBOR array. Used as the payload for the
/// `"message_received"` / `"outbox_pending"` / `"outbox_sent"`
/// event-journal entries.
pub(crate) fn encode_event_payload(
    message_id: &str,
    conversation_id: &str,
    sender_id: &str,
    created_at_ms: i64,
) -> Vec<u8> {
    // Hand-rolled, dependency-free CBOR encoder for the small fixed
    // shape used here. Avoids leaning on the generic CBOR codec
    // (`crate::cbor`) for one writer path and is exercised by the
    // persister tests below.
    let mut out = Vec::with_capacity(64);
    // Array of 4
    out.push(0x84);
    push_cbor_text(&mut out, message_id);
    push_cbor_text(&mut out, conversation_id);
    push_cbor_text(&mut out, sender_id);
    push_cbor_int(&mut out, created_at_ms);
    out
}

fn push_cbor_text(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len < 24 {
        out.push(0x60 | len as u8);
    } else if len <= u8::MAX as usize {
        out.push(0x78);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(0x79);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x7a);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

fn push_cbor_int(out: &mut Vec<u8>, v: i64) {
    if v >= 0 {
        push_cbor_uint(out, v as u64);
    } else {
        let n = (-(v + 1)) as u64;
        push_cbor_uint_with_major(out, 1, n);
    }
}

fn push_cbor_uint(out: &mut Vec<u8>, v: u64) {
    push_cbor_uint_with_major(out, 0, v)
}

fn push_cbor_uint_with_major(out: &mut Vec<u8>, major: u8, v: u64) {
    let m = major << 5;
    if v < 24 {
        out.push(m | v as u8);
    } else if v <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(v as u8);
    } else if v <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> IngestedMessage {
        IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: Uuid::now_v7(),
            sender_id: "user-1".to_string(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("hello".to_string()),
            media_descriptors: vec![],
            reply_to: None,
        }
    }

    #[test]
    fn validate_ingest_accepts_minimal_text_message() {
        let msg = sample_message();
        MessageProcessor::validate_ingest(&msg).expect("valid");
    }

    #[test]
    fn validate_ingest_rejects_nil_message_id() {
        let mut msg = sample_message();
        msg.message_id = Uuid::nil();
        assert!(matches!(
            MessageProcessor::validate_ingest(&msg),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    #[test]
    fn validate_ingest_rejects_nil_conversation_id() {
        let mut msg = sample_message();
        msg.conversation_id = Uuid::nil();
        assert!(matches!(
            MessageProcessor::validate_ingest(&msg),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    #[test]
    fn validate_ingest_rejects_empty_sender_id() {
        let mut msg = sample_message();
        msg.sender_id = String::new();
        assert!(matches!(
            MessageProcessor::validate_ingest(&msg),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    #[test]
    fn validate_ingest_rejects_non_positive_timestamp() {
        for bad_ts in [-1, 0] {
            let mut msg = sample_message();
            msg.created_at_ms = bad_ts;
            assert!(
                matches!(
                    MessageProcessor::validate_ingest(&msg),
                    Err(ProcessorError::InvalidMessage(_))
                ),
                "ts={bad_ts}"
            );
        }
    }

    #[test]
    fn validate_ingest_rejects_empty_text_when_no_media() {
        let mut msg = sample_message();
        msg.text_content = Some(String::new());
        assert!(matches!(
            MessageProcessor::validate_ingest(&msg),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    #[test]
    fn validate_ingest_rejects_empty_payload() {
        // No text and no media — there is nothing to persist.
        let mut msg = sample_message();
        msg.text_content = None;
        msg.media_descriptors = vec![];
        assert!(matches!(
            MessageProcessor::validate_ingest(&msg),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    #[test]
    fn validate_ingest_accepts_media_only_message() {
        let mut msg = sample_message();
        msg.text_content = None;
        msg.media_descriptors = vec![MediaDescriptor {
            asset_id: Uuid::now_v7(),
            mime_type: "image/jpeg".into(),
            bytes_total: 1024,
            chunk_count: 1,
            merkle_root: [0u8; 32],
            blob_id: Uuid::now_v7(),
            wrapped_k_asset: vec![0u8; 40],
            storage_sink: None,
        }];
        MessageProcessor::validate_ingest(&msg).expect("valid media-only");
    }

    #[test]
    fn is_duplicate_detects_existing() {
        let id = Uuid::now_v7();
        let mut set = HashSet::new();
        set.insert(id);
        assert!(MessageProcessor::is_duplicate(&id, &set));
        let other = Uuid::now_v7();
        assert!(!MessageProcessor::is_duplicate(&other, &set));
    }

    #[test]
    fn create_outbox_entry_basics() {
        let conv = Uuid::now_v7();
        let entry = MessageProcessor::create_outbox_entry(conv, "hi", None).expect("valid");
        assert_eq!(entry.conversation_id, conv);
        assert_eq!(entry.text_content, "hi");
        assert!(entry.reply_to.is_none());
        assert_eq!(entry.status, OutboxStatus::Pending);
        // UUID v7 has version 0b0111 in the high nibble of the
        // 7th byte (offset 6) — sanity-check we got v7, not v4.
        assert_eq!(entry.client_message_id.get_version_num(), 7);
    }

    #[test]
    fn create_outbox_entry_rejects_empty_text() {
        let conv = Uuid::now_v7();
        assert!(matches!(
            MessageProcessor::create_outbox_entry(conv, "", None),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    #[test]
    fn create_outbox_entry_uuids_are_monotonic() {
        // UUID v7 is time-ordered. Generating a sequence and sorting
        // it must preserve creation order.
        let conv = Uuid::now_v7();
        let mut ids = Vec::new();
        for i in 0..32 {
            // Force a 1ms gap so the timestamp portion advances; the
            // v7 spec also includes a sub-millisecond counter, but
            // deferring 1ms makes the test independent of that.
            std::thread::sleep(std::time::Duration::from_millis(1));
            let e = MessageProcessor::create_outbox_entry(conv, &format!("m{i}"), None).unwrap();
            ids.push(e.client_message_id);
        }
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "UUID v7 ids should already be sorted");
    }

    #[test]
    fn outbox_status_round_trips_through_serde() {
        for s in [
            OutboxStatus::Pending,
            OutboxStatus::Sending,
            OutboxStatus::Sent,
            OutboxStatus::Failed,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: OutboxStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn ingest_result_default_is_zero() {
        let r = IngestResult::default();
        assert_eq!(r.new_messages, 0);
        assert_eq!(r.updated_messages, 0);
        assert_eq!(r.duplicate_count, 0);
        assert!(r.next_cursor.is_none());
    }

    #[test]
    fn ingest_result_round_trips_through_serde_with_next_cursor() {
        let r = IngestResult {
            new_messages: 3,
            updated_messages: 1,
            duplicate_count: 2,
            next_cursor: Some("cursor-abc".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: IngestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn ingested_message_round_trips_through_serde() {
        let msg = sample_message();
        let json = serde_json::to_string(&msg).unwrap();
        let back: IngestedMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, back);
    }

    // -----------------------------------------------------------------
    // MessagePersister
    // -----------------------------------------------------------------

    fn fresh_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0x42; 32]).expect("open in-memory db")
    }

    fn seed_conversation(db: &LocalStoreDb, conv_id: &Uuid) {
        let conv = crate::local_store::schema::Conversation {
            conversation_id: conv_id.to_string(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
            ..Default::default()
        };
        db.insert_conversation(&conv).unwrap();
    }

    #[test]
    fn persist_ingested_message_writes_skeleton_body_fts_and_journal() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("hello world".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");

        let mid = msg.message_id.to_string();
        let skel = db.get_message_skeleton(&mid).unwrap().expect("skeleton");
        assert_eq!(skel.message_id, mid);
        assert_eq!(skel.body_state, BodyState::LocalPlainAvailable);
        let body = db.get_message_body(&mid).unwrap().expect("body");
        assert_eq!(body.text_content.as_deref(), Some("hello world"));

        // FTS row.
        let fts_count: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM search_fts WHERE message_id = ?1",
                params![mid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fts_count, 1);

        // Backup event journal entry.
        let event_count: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM backup_event_journal
                 WHERE event_type = 'message_received'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);
    }

    #[test]
    fn persist_ingested_message_rejects_duplicate() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("first".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).unwrap();
        let err = p.persist_ingested_message(&msg).unwrap_err();
        assert!(
            matches!(err, ProcessorError::DuplicateMessage),
            "expected DuplicateMessage; got {err:?}"
        );

        // FTS / journal must not have been written twice.
        let fts_count: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM search_fts WHERE message_id = ?1",
                params![msg.message_id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fts_count, 1);
    }

    fn sample_descriptor(seed: u8) -> MediaDescriptor {
        MediaDescriptor {
            asset_id: Uuid::now_v7(),
            mime_type: "image/jpeg".into(),
            bytes_total: 1_000_000 + u64::from(seed),
            chunk_count: 4,
            merkle_root: [seed; 32],
            blob_id: Uuid::now_v7(),
            wrapped_k_asset: vec![seed; 40],
            storage_sink: None,
        }
    }

    #[test]
    fn persist_ingested_message_with_media_descriptor_writes_media_asset() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let desc = sample_descriptor(0x7A);
        let asset_id = desc.asset_id.to_string();
        let blob_id = desc.blob_id.to_string();
        let bytes_total = desc.bytes_total;
        let chunk_count = desc.chunk_count;
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: None,
            media_descriptors: vec![desc],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");

        let mid = msg.message_id.to_string();
        let skel = db.get_message_skeleton(&mid).unwrap().expect("skeleton");
        assert_eq!(skel.kind, MessageKind::Media);
        assert_eq!(skel.media_state, Some(MediaState::ThumbnailOnly));

        let asset = db.get_media_asset(&asset_id).unwrap().expect("asset row");
        assert_eq!(asset.message_id, mid);
        assert_eq!(asset.media_state, MediaState::ThumbnailOnly);
        assert_eq!(asset.bytes_total, bytes_total as i64);
        assert_eq!(asset.chunk_count, chunk_count as i32);
        assert_eq!(asset.blob_id, blob_id);
        assert_eq!(asset.storage_sink, "kchat_backend", "default sink");
    }

    #[test]
    fn persist_ingested_message_without_descriptor_writes_no_media_asset() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("just text".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");
        let count: i64 = db
            .connection()
            .query_row("SELECT count(*) FROM media_asset", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn persist_text_plus_media_message_sets_media_state_on_skeleton() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let desc = sample_descriptor(0x21);
        let asset_id = desc.asset_id.to_string();
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("caption with media".into()),
            media_descriptors: vec![desc],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");

        let mid = msg.message_id.to_string();
        let skel = db.get_message_skeleton(&mid).unwrap().expect("skeleton");
        // Media must take priority over text for kind classification, and
        // the skeleton's media_state must agree with the per-asset row
        // even when a text caption is also present.
        assert_eq!(skel.kind, MessageKind::Media);
        assert_eq!(skel.media_state, Some(MediaState::ThumbnailOnly));

        let asset = db.get_media_asset(&asset_id).unwrap().expect("asset");
        assert_eq!(asset.media_state, MediaState::ThumbnailOnly);

        // Text body still persists and is searchable via FTS.
        let body = db.get_message_body(&mid).unwrap().expect("body");
        assert_eq!(body.text_content.as_deref(), Some("caption with media"));
        let fts_hit: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM search_fts WHERE search_fts MATCH ?1",
                params!["caption"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fts_hit, 1, "FTS must index the caption");
    }

    #[test]
    fn persist_ingested_message_with_descriptor_storage_sink_override() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mut desc = sample_descriptor(0x33);
        desc.storage_sink = Some("zk_object_fabric".into());
        let asset_id = desc.asset_id.to_string();
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1,
            text_content: None,
            media_descriptors: vec![desc],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");
        let asset = db.get_media_asset(&asset_id).unwrap().expect("asset");
        assert_eq!(asset.storage_sink, "zk_object_fabric");
    }

    #[test]
    fn persist_ingested_message_with_descriptor_is_idempotent() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let desc = sample_descriptor(0x09);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1,
            text_content: None,
            media_descriptors: vec![desc],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");
        let err = p.persist_ingested_message(&msg).unwrap_err();
        assert!(matches!(err, ProcessorError::DuplicateMessage));
        let count: i64 = db
            .connection()
            .query_row("SELECT count(*) FROM media_asset", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "second insert must roll back the asset");
    }

    #[test]
    fn persist_ingested_message_rejects_invalid() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mut msg = IngestedMessage {
            message_id: Uuid::nil(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("hello".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        assert!(matches!(
            p.persist_ingested_message(&msg),
            Err(ProcessorError::InvalidMessage(_))
        ));
        msg.message_id = Uuid::now_v7();
        msg.text_content = None;
        assert!(matches!(
            p.persist_ingested_message(&msg),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    #[test]
    fn persist_outbox_entry_inserts_skeleton_body_and_returns_uuid() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let entry = MessageProcessor::create_outbox_entry(conv, "outgoing", None).unwrap();
        let mid = p.persist_outbox_entry(&entry).expect("persist outbox");

        assert_eq!(mid.0.get_version_num(), 7);
        assert_eq!(mid.0, entry.client_message_id);

        let skel = db
            .get_message_skeleton(&entry.client_message_id.to_string())
            .unwrap()
            .expect("skeleton");
        assert_eq!(skel.body_state, BodyState::LocalPlainAvailable);
        assert_eq!(skel.kind, MessageKind::Text);

        let body = db
            .get_message_body(&entry.client_message_id.to_string())
            .unwrap()
            .expect("body");
        assert_eq!(body.text_content.as_deref(), Some("outgoing"));
    }

    #[test]
    fn persist_outbox_entry_rejects_empty_text_and_non_v7() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let entry_empty = OutboxEntry {
            client_message_id: Uuid::now_v7(),
            conversation_id: conv,
            text_content: String::new(),
            reply_to: None,
            created_at_ms: 100,
            status: OutboxStatus::Pending,
        };
        assert!(matches!(
            p.persist_outbox_entry(&entry_empty),
            Err(ProcessorError::InvalidMessage(_))
        ));
        let entry_v4 = OutboxEntry {
            client_message_id: Uuid::nil(),
            conversation_id: conv,
            text_content: "hi".into(),
            reply_to: None,
            created_at_ms: 100,
            status: OutboxStatus::Pending,
        };
        assert!(matches!(
            p.persist_outbox_entry(&entry_v4),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    #[test]
    fn check_duplicate_reflects_persisted_state() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("hi".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        let mid = msg.message_id.to_string();
        assert!(!p.check_duplicate(&mid).unwrap());
        p.persist_ingested_message(&msg).unwrap();
        assert!(p.check_duplicate(&mid).unwrap());
    }

    #[test]
    fn mark_sent_writes_journal_entry() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let entry = MessageProcessor::create_outbox_entry(conv, "ping", None).unwrap();
        p.persist_outbox_entry(&entry).unwrap();
        p.mark_sent(&entry.client_message_id.to_string()).unwrap();
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM backup_event_journal WHERE event_type = 'outbox_sent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn mark_sent_rejects_unknown_id() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        assert!(matches!(
            p.mark_sent("does-not-exist"),
            Err(ProcessorError::InvalidMessage(_))
        ));
    }

    // -----------------------------------------------------------------
    // edit_message / delete_for_me / delete_for_everyone
    // -----------------------------------------------------------------

    fn fts_count(db: &LocalStoreDb, message_id: &str) -> i64 {
        db.connection()
            .query_row(
                "SELECT count(*) FROM search_fts WHERE message_id = ?1",
                params![message_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn fts_text_match_count(db: &LocalStoreDb, term: &str) -> i64 {
        db.connection()
            .query_row(
                "SELECT count(*) FROM search_fts WHERE search_fts MATCH ?1",
                params![term],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn journal_count(db: &LocalStoreDb, event_type: &str) -> i64 {
        db.connection()
            .query_row(
                "SELECT count(*) FROM backup_event_journal WHERE event_type = ?1",
                params![event_type],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn persist_text_message(p: &MessagePersister<'_>, conv: Uuid, text: &str) -> Uuid {
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some(text.into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");
        msg.message_id
    }

    #[test]
    fn edit_message_updates_body_and_fts() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "old text snippet");
        let mid_s = mid.to_string();

        // Old text is searchable.
        assert_eq!(fts_text_match_count(&db, "old"), 1);
        assert_eq!(fts_text_match_count(&db, "fresh"), 0);

        p.edit_message(&mid_s, "fresh text snippet").expect("edit");

        // Body row carries new text; old text no longer searchable.
        let body = db.get_message_body(&mid_s).unwrap().expect("body");
        assert_eq!(body.text_content.as_deref(), Some("fresh text snippet"));
        assert_eq!(fts_text_match_count(&db, "old"), 0);
        assert_eq!(fts_text_match_count(&db, "fresh"), 1);

        // Skeleton edited_at_ms is set.
        let skel = db.get_message_skeleton(&mid_s).unwrap().expect("skeleton");
        assert!(
            skel.edited_at_ms.unwrap() > 0,
            "edited_at_ms should be populated"
        );
    }

    #[test]
    fn edit_message_rejects_deleted_message() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "hello");
        let mid_s = mid.to_string();

        p.delete_for_me(&mid_s).expect("delete");
        let err = p.edit_message(&mid_s, "world").unwrap_err();
        assert!(
            matches!(err, ProcessorError::InvalidMessage(_)),
            "expected InvalidMessage; got {err:?}"
        );
    }

    #[test]
    fn edit_message_rejects_missing_id() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let err = p.edit_message("does-not-exist", "hi").unwrap_err();
        assert!(matches!(err, ProcessorError::InvalidMessage(_)));
    }

    #[test]
    fn edit_message_rejects_empty_text() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "hello");
        let err = p.edit_message(&mid.to_string(), "").unwrap_err();
        assert!(matches!(err, ProcessorError::InvalidMessage(_)));
    }

    #[test]
    fn edit_writes_journal_entry() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "hello");
        assert_eq!(journal_count(&db, "message_edited"), 0);
        p.edit_message(&mid.to_string(), "goodbye").unwrap();
        assert_eq!(journal_count(&db, "message_edited"), 1);
    }

    #[test]
    fn delete_for_me_transitions_state_and_removes_fts() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "hello");
        let mid_s = mid.to_string();

        p.delete_for_me(&mid_s).expect("delete_for_me");
        let skel = db.get_message_skeleton(&mid_s).unwrap().expect("skeleton");
        assert_eq!(skel.body_state, BodyState::DeletedForMe);
        assert!(skel.deleted_at_ms.unwrap() > 0);

        // FTS row gone.
        assert_eq!(fts_count(&db, &mid_s), 0);
        // Body row preserved (delete-for-me is restorable).
        assert!(db.get_message_body(&mid_s).unwrap().is_some());
    }

    #[test]
    fn delete_for_everyone_removes_body_and_fts() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "secret");
        let mid_s = mid.to_string();

        p.delete_for_everyone(&mid_s).expect("delete_for_everyone");
        let skel = db.get_message_skeleton(&mid_s).unwrap().expect("skeleton");
        assert_eq!(skel.body_state, BodyState::DeletedForEveryone);
        assert!(skel.deleted_at_ms.unwrap() > 0);

        assert_eq!(fts_count(&db, &mid_s), 0);
        assert!(db.get_message_body(&mid_s).unwrap().is_none());
    }

    #[test]
    fn delete_writes_journal_entry() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid_a = persist_text_message(&p, conv, "a-text");
        let mid_b = persist_text_message(&p, conv, "b-text");

        p.delete_for_me(&mid_a.to_string()).unwrap();
        p.delete_for_everyone(&mid_b.to_string()).unwrap();

        assert_eq!(journal_count(&db, "message_deleted"), 2);
    }

    #[test]
    fn delete_with_attached_media_emits_media_deleted_event() {
        // Persist an inbound message with one attached media
        // descriptor, then delete it. The persister must emit BOTH a
        // `message_deleted` and a `media_deleted` backup event so the
        // backup-side tombstone taxonomy stays explicit
        // (`BackupEventType::MediaDeleted`).
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);

        let mid = Uuid::now_v7();
        let asset_id = Uuid::now_v7();
        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("with media".into()),
            media_descriptors: vec![MediaDescriptor {
                asset_id,
                mime_type: "image/jpeg".into(),
                bytes_total: 1024,
                chunk_count: 1,
                merkle_root: [0u8; 32],
                blob_id: Uuid::now_v7(),
                wrapped_k_asset: vec![0u8; 40],
                storage_sink: None,
            }],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");

        // Sanity: text-message-only deletes do NOT emit media_deleted.
        let bare_mid = persist_text_message(&p, conv, "no media here");
        p.delete_for_me(&bare_mid.to_string()).unwrap();
        assert_eq!(journal_count(&db, "media_deleted"), 0);

        // Delete the media-attached message.
        p.delete_for_everyone(&mid.to_string()).unwrap();

        assert_eq!(journal_count(&db, "message_deleted"), 2);
        assert_eq!(journal_count(&db, "media_deleted"), 1);
    }

    #[test]
    fn delete_with_multi_asset_message_emits_one_media_deleted_per_asset() {
        // Multi-asset messages must emit one `media_deleted` backup
        // event per attached asset (not just one for the first
        // asset). `LocalStoreDb::list_media_assets_by_message`
        // returns every row deterministically ordered by `asset_id`.
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);

        let mid = Uuid::now_v7();
        let asset_a = Uuid::now_v7();
        let asset_b = Uuid::now_v7();
        let asset_c = Uuid::now_v7();
        let make_desc = |asset_id: Uuid| MediaDescriptor {
            asset_id,
            mime_type: "image/jpeg".into(),
            bytes_total: 1024,
            chunk_count: 1,
            merkle_root: [0u8; 32],
            blob_id: Uuid::now_v7(),
            wrapped_k_asset: vec![0u8; 40],
            storage_sink: None,
        };
        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("with three media".into()),
            media_descriptors: vec![make_desc(asset_a), make_desc(asset_b), make_desc(asset_c)],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");

        // Sanity-check the helper that drives the iteration.
        let attached = db
            .list_media_assets_by_message(&mid.to_string())
            .expect("list");
        assert_eq!(attached.len(), 3);

        p.delete_for_everyone(&mid.to_string()).unwrap();

        assert_eq!(journal_count(&db, "message_deleted"), 1);
        assert_eq!(
            journal_count(&db, "media_deleted"),
            3,
            "one media_deleted event per attached asset",
        );
    }

    #[test]
    fn delete_for_me_rejects_missing_id() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let err = p.delete_for_me("does-not-exist").unwrap_err();
        assert!(matches!(err, ProcessorError::InvalidMessage(_)));
    }

    #[test]
    fn delete_for_me_rejects_already_deleted() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "hello");
        p.delete_for_me(&mid.to_string()).unwrap();
        let err = p.delete_for_me(&mid.to_string()).unwrap_err();
        assert!(
            matches!(err, ProcessorError::IllegalTransition(_)),
            "expected IllegalTransition; got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // Fuzzy index maintenance — Task 1
    // -----------------------------------------------------------------

    fn fuzzy_count(db: &LocalStoreDb, message_id: &str) -> i64 {
        db.connection()
            .query_row(
                "SELECT count(*) FROM search_fuzzy WHERE message_id = ?1",
                params![message_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn fuzzy_token_match_count(db: &LocalStoreDb, token: &str, message_id: &str) -> i64 {
        db.connection()
            .query_row(
                "SELECT count(*) FROM search_fuzzy
                  WHERE token = ?1 AND message_id = ?2",
                params![token, message_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn persist_ingested_message_indexes_fuzzy_tokens() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "lighthouse keeper");
        let mid_s = mid.to_string();

        // The fuzzy index must carry every distinct trigram of the
        // lowercased text against this message id.
        assert!(
            fuzzy_count(&db, &mid_s) > 0,
            "expected search_fuzzy rows for {mid_s}"
        );
        assert_eq!(fuzzy_token_match_count(&db, "lig", &mid_s), 1);
        assert_eq!(fuzzy_token_match_count(&db, "use", &mid_s), 1);
        assert_eq!(fuzzy_token_match_count(&db, "kee", &mid_s), 1);
    }

    #[test]
    fn edit_message_updates_fuzzy_tokens() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "lighthouse keeper");
        let mid_s = mid.to_string();

        // Pre-edit: original trigrams are present.
        assert_eq!(fuzzy_token_match_count(&db, "lig", &mid_s), 1);
        assert_eq!(fuzzy_token_match_count(&db, "kee", &mid_s), 1);

        p.edit_message(&mid_s, "fresh banana smoothie")
            .expect("edit");

        // Post-edit: old trigrams are gone, new trigrams are present.
        assert_eq!(fuzzy_token_match_count(&db, "lig", &mid_s), 0);
        assert_eq!(fuzzy_token_match_count(&db, "kee", &mid_s), 0);
        assert_eq!(fuzzy_token_match_count(&db, "fre", &mid_s), 1);
        assert_eq!(fuzzy_token_match_count(&db, "ban", &mid_s), 1);
        assert_eq!(fuzzy_token_match_count(&db, "smo", &mid_s), 1);
    }

    #[test]
    fn delete_for_me_removes_fuzzy_tokens() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "lighthouse keeper");
        let mid_s = mid.to_string();
        assert!(fuzzy_count(&db, &mid_s) > 0);

        p.delete_for_me(&mid_s).expect("delete_for_me");
        assert_eq!(fuzzy_count(&db, &mid_s), 0);
    }

    #[test]
    fn delete_for_everyone_removes_fuzzy_tokens() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "lighthouse keeper");
        let mid_s = mid.to_string();
        assert!(fuzzy_count(&db, &mid_s) > 0);

        p.delete_for_everyone(&mid_s).expect("delete_for_everyone");
        assert_eq!(fuzzy_count(&db, &mid_s), 0);
    }

    // -----------------------------------------------------------------
    // search_vector cleanup on delete / edit
    // -----------------------------------------------------------------

    fn vector_count(db: &LocalStoreDb, message_id: &str) -> i64 {
        db.connection()
            .query_row(
                "SELECT count(*) FROM search_vector WHERE message_id = ?1",
                params![message_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn put_test_embedding(db: &LocalStoreDb, message_id: &str) {
        use crate::models::embeddings::{
            EmbeddingCache, LocalStoreEmbeddingCache, XLMR_MODEL_VERSION,
        };
        let cache = LocalStoreEmbeddingCache::new(db.connection());
        // Deterministic 384-dim unit vector.
        let mut v = vec![0.0_f32; 384];
        v[0] = 1.0;
        cache.put(message_id, XLMR_MODEL_VERSION, &v).unwrap();
    }

    #[test]
    fn delete_for_me_removes_search_vector_row() {
        // Regression: per-message delete must drop the
        // cross-pipeline embedding so semantic search does not
        // continue to surface a deleted message. Conversation-
        // level delete already handles this; the per-message
        // path was the gap.
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "lighthouse keeper");
        let mid_s = mid.to_string();
        put_test_embedding(&db, &mid_s);
        assert_eq!(vector_count(&db, &mid_s), 1);

        p.delete_for_me(&mid_s).expect("delete_for_me");
        assert_eq!(
            vector_count(&db, &mid_s),
            0,
            "delete_for_me must drop search_vector row alongside FTS / fuzzy"
        );
    }

    #[test]
    fn delete_for_everyone_removes_search_vector_row() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "lighthouse keeper");
        let mid_s = mid.to_string();
        put_test_embedding(&db, &mid_s);
        assert_eq!(vector_count(&db, &mid_s), 1);

        p.delete_for_everyone(&mid_s).expect("delete_for_everyone");
        assert_eq!(
            vector_count(&db, &mid_s),
            0,
            "delete_for_everyone must drop search_vector row alongside FTS / fuzzy"
        );
    }

    #[test]
    fn edit_message_invalidates_search_vector_row() {
        // Regression: the edit path reindexes FTS / fuzzy from
        // the new text but, before this fix, left the old
        // embedding in `search_vector`. Semantic search would
        // then return matches based on the pre-edit text.
        // Re-embedding is `CoreImpl::ingest_messages`'s job
        // (it owns the `TextEmbedder` slot) — here we only
        // assert the stale row is gone.
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "lighthouse keeper");
        let mid_s = mid.to_string();
        put_test_embedding(&db, &mid_s);
        assert_eq!(vector_count(&db, &mid_s), 1);

        p.edit_message(&mid_s, "fresh banana smoothie")
            .expect("edit");
        assert_eq!(
            vector_count(&db, &mid_s),
            0,
            "edit_message must invalidate the pre-edit search_vector row"
        );
    }

    #[test]
    fn persist_outbox_entry_indexes_fuzzy_tokens() {
        // The outbox path also writes through to FTS5, so it must
        // keep the fuzzy index in lock-step.
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let entry = MessageProcessor::create_outbox_entry(conv, "lighthouse keeper", None).unwrap();
        let cmid = p.persist_outbox_entry(&entry).unwrap();
        assert!(fuzzy_count(&db, &cmid.0.to_string()) > 0);
    }

    // -----------------------------------------------------------------
    // Conversation metadata auto-update
    // -----------------------------------------------------------------

    #[test]
    fn persist_ingested_message_updates_conversation_metadata() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_500,
            text_content: Some("first arrival".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");

        let row = db
            .get_conversation(&conv.to_string())
            .unwrap()
            .expect("conv");
        assert_eq!(
            row.last_message_id.as_deref(),
            Some(msg.message_id.to_string()).as_deref()
        );
        assert_eq!(row.last_activity_ms, 1_700_000_000_500);
    }

    #[test]
    fn persist_outbox_entry_updates_conversation_metadata() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let entry = MessageProcessor::create_outbox_entry(conv, "outbox bump", None).unwrap();
        let created_at = entry.created_at_ms;
        let cmid = p.persist_outbox_entry(&entry).unwrap();

        let row = db
            .get_conversation(&conv.to_string())
            .unwrap()
            .expect("conv");
        assert_eq!(
            row.last_message_id.as_deref(),
            Some(cmid.0.to_string()).as_deref()
        );
        assert_eq!(row.last_activity_ms, created_at);
    }

    // -----------------------------------------------------------------
    // archive event journal mirroring (Task 1)
    //
    // Every persist / edit / delete entry-point must mirror its
    // backup-side journal write into the
    // `archive_event_journal`. The tests below assert the row count
    // and event_type tag; full payload round-tripping is covered by
    // the archive event journal's own unit tests.
    // -----------------------------------------------------------------

    fn archive_event_count(db: &LocalStoreDb, event_type: &str) -> i64 {
        db.connection()
            .query_row(
                "SELECT count(*) FROM archive_event_journal WHERE event_type = ?1",
                params![event_type],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn persist_ingested_message_writes_archive_event() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("hello archive".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        p.persist_ingested_message(&msg).expect("persist");
        assert_eq!(archive_event_count(&db, "message_received"), 1);
    }

    #[test]
    fn persist_outbox_entry_writes_archive_event() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let entry = MessageProcessor::create_outbox_entry(conv, "outbox archive", None).unwrap();
        p.persist_outbox_entry(&entry).expect("persist outbox");
        assert_eq!(archive_event_count(&db, "message_received"), 1);
    }

    #[test]
    fn edit_message_writes_archive_event() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "before edit");
        p.edit_message(&mid.to_string(), "after edit")
            .expect("edit");
        assert_eq!(archive_event_count(&db, "message_edited"), 1);
        // The receive event should still be there from the
        // initial persist.
        assert_eq!(archive_event_count(&db, "message_received"), 1);
    }

    /// cold-hit hydration regression
    /// (PR-#33 review feedback): the archive-side payload of a
    /// `message_edited` event must carry the *edited* body
    /// inside the `KCHAT_ARCHIVE_BODY_PAYLOAD_V1` envelope, not
    /// the legacy `{message_id, edited_at_ms}` shape — otherwise
    /// `CoreImpl::hydrate_cold_search_results` would silently
    /// land the pre-edit body on edited cold messages.
    #[test]
    fn edit_message_archive_payload_carries_edited_body_text() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "before edit");

        p.edit_message(&mid.to_string(), "after edit")
            .expect("edit");

        // Pull the most recent archive-event-journal row whose
        // `event_type = 'message_edited'` and decode it via the
        // production `try_decode_text` helper that the cold-hit
        // hydration path uses.
        let payload: Vec<u8> = db
            .connection()
            .query_row(
                "SELECT payload FROM archive_event_journal \
                 WHERE event_type = 'message_edited' \
                 ORDER BY event_seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .expect("row");
        let decoded = crate::archive::body_payload::try_decode_text(&payload);
        assert_eq!(
            decoded.as_deref(),
            Some("after edit"),
            "edit's archive payload must round-trip the *edited* body text"
        );

        // The backup-event-journal still uses the legacy
        // `{message_id, edited_at_ms}` shape — backups don't
        // need the body to drive the edit dispatch and we keep
        // that contract stable.
        let backup_payload: Vec<u8> = db
            .connection()
            .query_row(
                "SELECT payload FROM backup_event_journal \
                 WHERE event_type = 'message_edited' \
                 ORDER BY event_seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .expect("backup row");
        assert!(
            crate::archive::body_payload::try_decode_text(&backup_payload).is_none(),
            "backup payload remains the legacy edit shape; \
             try_decode_text must NOT match"
        );
    }

    #[test]
    fn delete_for_everyone_writes_archive_event() {
        let db = fresh_db();
        let p = MessagePersister::new(&db);
        let conv = Uuid::now_v7();
        seed_conversation(&db, &conv);
        let mid = persist_text_message(&p, conv, "deletable");
        p.delete_for_everyone(&mid.to_string()).expect("delete");
        assert_eq!(archive_event_count(&db, "message_deleted"), 1);
    }
}
