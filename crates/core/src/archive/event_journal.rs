//! Phase-3 archive event journal.
//!
//! `docs/PHASES.md` Phase 3 lists the archive event journal as the
//! first deliverable: every durable mutation that the local store
//! commits (message arrived, edit applied, delete acknowledged,
//! media asset created) writes a typed event into this journal. The
//! [`crate::archive::segment_builder::ArchiveSegmentBuilder`] consumes
//! the unread tail in [`ArchiveEventType`] order, packs it into a
//! per-conversation, per-time-bucket [`SegmentType::MessageDelta`]
//! / [`SegmentType::TimelineSkeleton`] segment, and advances the
//! cursor.
//!
//! The journal lives in two tables (see
//! [`crate::local_store::schema::SCHEMA_SQL`]):
//!
//! * `archive_event_journal` — append-only log keyed on
//!   `event_seq AUTOINCREMENT`.
//! * `archive_event_cursor` — single-row table holding the
//!   most-recently-segmented `event_seq`. Reading past the cursor
//!   yields the events that the segment builder has not yet
//!   uploaded.
//!
//! Notes:
//! * Read paths are purely lock-free SELECTs; writes happen inside
//!   the caller's transaction so an aborted message persist
//!   doesn't leave a dangling archive event behind.
//! * Payloads are CBOR-encoded structs that the segment builder
//!   re-emits inside the AEAD-sealed segment ciphertext; the
//!   journal table itself is *not* encrypted (the ciphertext lives
//!   inside SQLCipher already, and per-row AEAD would prevent the
//!   cursor / sequence-number invariants from being maintained).

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Error;

/// Type tag for an archive event.
///
/// `docs/PROPOSAL.md §6.4` (archive event taxonomy) lists the
/// canonical set; new variants are a wire-format change because
/// the segment builder dispatches on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveEventType {
    /// A new message skeleton + body landed in the local store.
    MessageReceived,
    /// An existing message body's text was edited.
    MessageEdited,
    /// A message was deleted (`delete_for_me` or
    /// `delete_for_everyone`).
    MessageDeleted,
    /// A new media asset was registered for an existing message.
    MediaReceived,
    /// A new conversation was created.
    ConversationCreated,
    /// A conversation row was deleted.
    ConversationDeleted,
}

impl ArchiveEventType {
    /// Canonical snake_case representation used in the SQL column.
    pub fn as_str(self) -> &'static str {
        match self {
            ArchiveEventType::MessageReceived => "message_received",
            ArchiveEventType::MessageEdited => "message_edited",
            ArchiveEventType::MessageDeleted => "message_deleted",
            ArchiveEventType::MediaReceived => "media_received",
            ArchiveEventType::ConversationCreated => "conversation_created",
            ArchiveEventType::ConversationDeleted => "conversation_deleted",
        }
    }

    /// Parse a snake_case string back into an event type.
    pub fn parse_snake_case(s: &str) -> Result<Self, Error> {
        Ok(match s {
            "message_received" => Self::MessageReceived,
            "message_edited" => Self::MessageEdited,
            "message_deleted" => Self::MessageDeleted,
            "media_received" => Self::MediaReceived,
            "conversation_created" => Self::ConversationCreated,
            "conversation_deleted" => Self::ConversationDeleted,
            other => {
                return Err(Error::Storage(format!(
                    "unknown archive event_type {other:?}"
                )))
            }
        })
    }
}

/// One logical archive event.
///
/// `event_seq` is set by the database (AUTOINCREMENT) — caller
/// supplies the rest. `payload` is application-defined CBOR; the
/// segment builder re-emits it inside the encrypted segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveEvent {
    /// Type tag.
    pub event_type: ArchiveEventType,
    /// Owning conversation.
    pub conversation_id: Uuid,
    /// Originating message, when the event has one.
    pub message_id: Option<Uuid>,
    /// Application-defined CBOR payload.
    pub payload: Vec<u8>,
    /// Wall-clock millisecond timestamp the event was journaled.
    pub created_at_ms: i64,
}

/// Result of [`ArchiveEventJournal::write_event`] — the
/// AUTOINCREMENT `event_seq` the row was assigned.
pub type ArchiveEventSeq = i64;

/// Phase-3 archive event journal.
///
/// Stateless reader / writer over an existing SQLCipher
/// [`Connection`]. Borrowing the connection rather than owning it
/// keeps the journal compatible with the persister's SAVEPOINT
/// boundaries — the caller decides whether the write happens
/// inside or outside a transaction.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArchiveEventJournal;

impl ArchiveEventJournal {
    /// Construct a new journal handle.
    pub fn new() -> Self {
        Self
    }

    /// Append `event` to `archive_event_journal`. Returns the
    /// AUTOINCREMENT `event_seq` the database assigned.
    ///
    /// The caller controls transactionality — call from inside a
    /// SAVEPOINT to bind the event to the rest of the persisted
    /// state.
    pub fn write_event(
        &self,
        conn: &Connection,
        event: &ArchiveEvent,
    ) -> Result<ArchiveEventSeq, Error> {
        conn.execute(
            "INSERT INTO archive_event_journal(
                event_type, conversation_id, message_id, payload, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.event_type.as_str(),
                event.conversation_id.to_string(),
                event.message_id.map(|u| u.to_string()),
                event.payload,
                event.created_at_ms,
            ],
        )
        .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    /// Read at most `limit` events with `event_seq > after_seq`,
    /// in ascending sequence order.
    ///
    /// Pass `after_seq = 0` to read from the start of the journal.
    pub fn read_events_since(
        &self,
        conn: &Connection,
        after_seq: ArchiveEventSeq,
        limit: usize,
    ) -> Result<Vec<(ArchiveEventSeq, ArchiveEvent)>, Error> {
        let mut stmt = conn
            .prepare(
                "SELECT event_seq, event_type, conversation_id, message_id,
                        payload, created_at_ms
                   FROM archive_event_journal
                  WHERE event_seq > ?1
                  ORDER BY event_seq ASC
                  LIMIT ?2",
            )
            .map_err(|e| Error::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(params![after_seq, limit as i64], |row| {
                let seq: i64 = row.get(0)?;
                let type_str: String = row.get(1)?;
                let conv_str: String = row.get(2)?;
                let mid_str: Option<String> = row.get(3)?;
                let payload: Vec<u8> = row.get(4)?;
                let created_at_ms: i64 = row.get(5)?;
                Ok((seq, type_str, conv_str, mid_str, payload, created_at_ms))
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut out = Vec::new();
        for row in rows {
            let (seq, type_str, conv_str, mid_str, payload, created_at_ms) =
                row.map_err(|e| Error::Storage(e.to_string()))?;
            let event_type = ArchiveEventType::parse_snake_case(&type_str)?;
            let conversation_id = Uuid::parse_str(&conv_str)
                .map_err(|e| Error::Storage(format!("invalid conversation_id: {e}")))?;
            let message_id = mid_str
                .map(|s| {
                    Uuid::parse_str(&s)
                        .map_err(|e| Error::Storage(format!("invalid message_id: {e}")))
                })
                .transpose()?;
            out.push((
                seq,
                ArchiveEvent {
                    event_type,
                    conversation_id,
                    message_id,
                    payload,
                    created_at_ms,
                },
            ));
        }
        Ok(out)
    }

    /// Return the current `archive_event_cursor.cursor_seq`. Returns
    /// `0` when no cursor row has been written yet.
    pub fn read_cursor(&self, conn: &Connection) -> Result<ArchiveEventSeq, Error> {
        conn.query_row(
            "SELECT cursor_seq FROM archive_event_cursor WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|e| Error::Storage(e.to_string()))
        .map(|opt| opt.unwrap_or(0))
    }

    /// Persist `new_cursor` as the most-recently-segmented
    /// `event_seq`. Idempotent for a given value.
    ///
    /// A non-monotonic update (`new_cursor < current`) is rejected
    /// — moving the cursor backwards would re-publish events the
    /// segment builder already emitted.
    pub fn advance_cursor(
        &self,
        conn: &Connection,
        new_cursor: ArchiveEventSeq,
    ) -> Result<(), Error> {
        let current = self.read_cursor(conn)?;
        if new_cursor < current {
            return Err(Error::Storage(format!(
                "archive cursor cannot go backwards (current={current}, requested={new_cursor})"
            )));
        }
        conn.execute(
            "INSERT INTO archive_event_cursor(id, cursor_seq) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET cursor_seq = excluded.cursor_seq",
            params![new_cursor],
        )
        .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    /// Convenience helper: read every event after the current
    /// cursor up to `limit`. Useful for the segment builder's drain
    /// loop.
    pub fn read_unsegmented(
        &self,
        conn: &Connection,
        limit: usize,
    ) -> Result<Vec<(ArchiveEventSeq, ArchiveEvent)>, Error> {
        let cursor = self.read_cursor(conn)?;
        self.read_events_since(conn, cursor, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store::db::LocalStoreDb;

    fn fresh_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0x42; 32]).expect("open in-memory")
    }

    fn sample_event(conv: Uuid) -> ArchiveEvent {
        ArchiveEvent {
            event_type: ArchiveEventType::MessageReceived,
            conversation_id: conv,
            message_id: Some(Uuid::now_v7()),
            payload: vec![0xAA, 0xBB, 0xCC],
            created_at_ms: 1_777_000_000_000,
        }
    }

    #[test]
    fn write_and_read_round_trip() {
        let db = fresh_db();
        let journal = ArchiveEventJournal::new();
        let conv = Uuid::now_v7();
        let e = sample_event(conv);

        let seq = journal.write_event(db.connection(), &e).unwrap();
        assert!(seq > 0);

        let events = journal.read_events_since(db.connection(), 0, 100).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, seq);
        assert_eq!(events[0].1, e);
    }

    #[test]
    fn read_events_since_filters_correctly() {
        let db = fresh_db();
        let journal = ArchiveEventJournal::new();
        let conv = Uuid::now_v7();
        let mut seqs = Vec::new();
        for _ in 0..5 {
            seqs.push(
                journal
                    .write_event(db.connection(), &sample_event(conv))
                    .unwrap(),
            );
        }
        seqs.sort();

        // After seq[1] should yield events 2,3,4 (3 rows).
        let after = seqs[1];
        let events = journal
            .read_events_since(db.connection(), after, 100)
            .unwrap();
        assert_eq!(events.len(), 3);
        for (i, (seq, _)) in events.iter().enumerate() {
            assert_eq!(*seq, seqs[i + 2]);
        }

        // limit truncates.
        let limited = journal.read_events_since(db.connection(), 0, 2).unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn advance_cursor_persists() {
        let db = fresh_db();
        let journal = ArchiveEventJournal::new();
        // Default cursor is 0.
        assert_eq!(journal.read_cursor(db.connection()).unwrap(), 0);

        journal.advance_cursor(db.connection(), 5).unwrap();
        assert_eq!(journal.read_cursor(db.connection()).unwrap(), 5);

        // Idempotent at same value.
        journal.advance_cursor(db.connection(), 5).unwrap();
        assert_eq!(journal.read_cursor(db.connection()).unwrap(), 5);

        journal.advance_cursor(db.connection(), 10).unwrap();
        assert_eq!(journal.read_cursor(db.connection()).unwrap(), 10);

        // Non-monotonic updates are rejected.
        let err = journal.advance_cursor(db.connection(), 9).unwrap_err();
        assert!(err.to_string().contains("backwards"));
    }

    #[test]
    fn event_type_serde_round_trip() {
        for ty in [
            ArchiveEventType::MessageReceived,
            ArchiveEventType::MessageEdited,
            ArchiveEventType::MessageDeleted,
            ArchiveEventType::MediaReceived,
            ArchiveEventType::ConversationCreated,
            ArchiveEventType::ConversationDeleted,
        ] {
            assert_eq!(
                ArchiveEventType::parse_snake_case(ty.as_str()).unwrap(),
                ty
            );
            // serde round-trip too.
            let json = serde_json::to_string(&ty).unwrap();
            let back: ArchiveEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ty);
        }
    }

    #[test]
    fn read_unsegmented_drains_after_cursor() {
        let db = fresh_db();
        let journal = ArchiveEventJournal::new();
        let conv = Uuid::now_v7();
        let s1 = journal
            .write_event(db.connection(), &sample_event(conv))
            .unwrap();
        let _s2 = journal
            .write_event(db.connection(), &sample_event(conv))
            .unwrap();
        let _s3 = journal
            .write_event(db.connection(), &sample_event(conv))
            .unwrap();

        // Cursor at 0 → drain returns all 3.
        let drained = journal.read_unsegmented(db.connection(), 100).unwrap();
        assert_eq!(drained.len(), 3);

        // Advance cursor past the first → drain returns 2.
        journal.advance_cursor(db.connection(), s1).unwrap();
        let drained = journal.read_unsegmented(db.connection(), 100).unwrap();
        assert_eq!(drained.len(), 2);
    }

    #[test]
    fn unknown_event_type_string_errors() {
        let err = ArchiveEventType::parse_snake_case("totally_not_a_type").unwrap_err();
        assert!(err.to_string().contains("unknown archive event_type"));
    }
}
