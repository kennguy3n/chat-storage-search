//! Message processor — Phase 1 skeleton.
//!
//! `docs/PROPOSAL.md §11` and `docs/PHASES.md` Phase 1 describe the
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
//! Phase 0's deliverable is the **types and pure validators** here,
//! not the database-backed implementation. The database glue lands
//! when SQLCipher integration arrives in Phase 1.

use std::collections::HashSet;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::formats::media_descriptor::MediaDescriptor;
use crate::local_store::db::{DbError, LocalStoreDb};
use crate::local_store::schema::{
    BackupEventJournalEntry, MessageBody, MessageKind, MessageSkeleton,
};
use crate::local_store::state_machines::{ArchiveState, BackupState, BodyState};
use crate::ClientMessageId;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by the [`MessageProcessor`].
#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    /// The ingested message failed validation (empty id, empty
    /// conversation id, non-positive timestamps, …).
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// The message has already been ingested.
    #[error("duplicate message")]
    DuplicateMessage,

    /// A storage-layer call failed. Phase 1 surfaces specific causes
    /// (database busy, AEAD open failure, …) through the wrapped
    /// [`DbError`].
    #[error("storage: {0}")]
    StorageError(String),

    /// A `rusqlite` call failed inside [`MessagePersister`].
    #[error("db: {0}")]
    Db(#[from] DbError),
}

impl PartialEq for ProcessorError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (
                ProcessorError::DuplicateMessage,
                ProcessorError::DuplicateMessage
            ),
        ) || match (self, other) {
            (ProcessorError::InvalidMessage(a), ProcessorError::InvalidMessage(b)) => a == b,
            (ProcessorError::StorageError(a), ProcessorError::StorageError(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for ProcessorError {}

impl Clone for ProcessorError {
    fn clone(&self) -> Self {
        match self {
            ProcessorError::InvalidMessage(s) => ProcessorError::InvalidMessage(s.clone()),
            ProcessorError::DuplicateMessage => ProcessorError::DuplicateMessage,
            ProcessorError::StorageError(s) => ProcessorError::StorageError(s.clone()),
            ProcessorError::Db(e) => ProcessorError::StorageError(e.to_string()),
        }
    }
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
    /// Zero or more media descriptors (`docs/PROPOSAL.md §3.2`).
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

/// Pure-Rust validators / helpers used by the Phase 1 message
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
    /// Phase 1 layers additional checks (sender membership in the
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
    ///    and, when `text_content.is_some()`, a `message_body` row.
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
        let kind = if msg.text_content.is_some() {
            MessageKind::Text
        } else if !msg.media_descriptors.is_empty() {
            MessageKind::Media
        } else {
            // validate_ingest already rejects this combination, but
            // double-check rather than risk a malformed row.
            return Err(ProcessorError::InvalidMessage(
                "message has neither text nor media".into(),
            ));
        };

        let skel = MessageSkeleton {
            message_id: msg.message_id.to_string(),
            conversation_id: msg.conversation_id.to_string(),
            sender_id: msg.sender_id.clone(),
            created_at_ms: msg.created_at_ms,
            received_at_ms: now_ms(),
            kind,
            body_state: BodyState::LocalPlainAvailable,
            media_state: None,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: msg.reply_to.map(|u| u.to_string()),
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        self.db.insert_message_skeleton(&skel)?;

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
        }

        let payload = encode_event_payload(
            &skel.message_id,
            &skel.conversation_id,
            &skel.sender_id,
            skel.created_at_ms,
        );
        let entry = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "message_received".into(),
            payload,
            created_at_ms: now_ms(),
        };
        self.db.insert_backup_event(&entry)?;
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
            // Phase 1 outbox sender id is the placeholder "self" —
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

        let payload = encode_event_payload(&mid, &conv, "self", entry.created_at_ms);
        let journal = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "outbox_pending".into(),
            payload,
            created_at_ms: now_ms(),
        };
        self.db.insert_backup_event(&journal)?;
        Ok(())
    }

    /// Whether `client_message_id` (or, equivalently, an
    /// already-ingested `message_id`) exists in `message_skeleton`.
    pub fn check_duplicate(&self, client_message_id: &str) -> Result<bool, ProcessorError> {
        self.skeleton_exists(client_message_id)
    }

    /// Mark an outbox entry as having been confirmed by the MLS
    /// delivery layer. Phase 1 records this as an `"outbox_sent"`
    /// entry in `backup_event_journal`; later phases lift it into a
    /// dedicated outbox-status column.
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
            payload,
            created_at_ms: now_ms(),
        };
        self.db.insert_backup_event(&entry)?;
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

/// Encode a `[message_id, conversation_id, sender_id, created_at_ms]`
/// CBOR array. Used as the payload for the
/// `"message_received"` / `"outbox_pending"` / `"outbox_sent"`
/// event-journal entries.
fn encode_event_payload(
    message_id: &str,
    conversation_id: &str,
    sender_id: &str,
    created_at_ms: i64,
) -> Vec<u8> {
    // Hand-rolled, dependency-free CBOR encoder for the small fixed
    // shape used here. Avoids leaning on `serde_cbor` for one writer
    // path and is exercised by the persister tests below.
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
        assert_eq!(err, ProcessorError::DuplicateMessage);

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
}
