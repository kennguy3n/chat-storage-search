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

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::formats::media_descriptor::MediaDescriptor;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by the [`MessageProcessor`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcessorError {
    /// The ingested message failed validation (empty id, empty
    /// conversation id, non-positive timestamps, …).
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// The message has already been ingested.
    #[error("duplicate message")]
    DuplicateMessage,

    /// A storage-layer call failed. Phase 1 surfaces specific causes
    /// (database busy, AEAD open failure, …); the variant here is a
    /// placeholder so trait signatures can use `Result<_, ProcessorError>`
    /// before that work lands.
    #[error("storage: {0}")]
    StorageError(String),
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
}
