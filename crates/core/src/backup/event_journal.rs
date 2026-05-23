//! Phase-4 backup event journal.
//!
//! Mirror of [`crate::archive::event_journal::ArchiveEventJournal`]
//! that feeds the **backup** segment builder rather than the
//! per-conversation archive pipeline. The two journals carry the
//! same event types but are advanced by independent cursors —
//! the personal archive and the cloud backup are sealed with
//! different keys (`K_archive_*` vs `K_backup_*`) and shipped on
//! independent schedules.
//!
//! Storage: `backup_event_journal` (append-only) +
//! `backup_event_cursor` (single-row, advanced by the segment
//! builder). Both tables are defined in
//! [`crate::local_store::schema::SCHEMA_SQL`].
//!
//! See `docs/PROPOSAL.md §6.4` (backup event taxonomy) and
//! `docs/PHASES.md` Phase 4 for context.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Error;

/// Type tag for a backup event. Matches the canonical set in
/// `docs/PROPOSAL.md §6.4`. Adding a variant is a wire-format
/// change because the segment builder dispatches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupEventType {
    /// A new message skeleton + body landed in the local store.
    MessageReceived,
    /// An existing message body's text was edited.
    MessageEdited,
    /// A message was deleted (`delete_for_me` or
    /// `delete_for_everyone`).
    MessageDeleted,
    /// A new media asset was registered for an existing message.
    MediaReceived,
    /// A media asset was deleted (eviction or
    /// `delete_for_everyone`).
    MediaDeleted,
    /// A new conversation was created.
    ConversationCreated,
    /// A conversation row was deleted.
    ConversationDeleted,
}

impl BackupEventType {
    /// Canonical snake_case representation persisted in the SQL
    /// `event_type` column.
    pub fn as_str(self) -> &'static str {
        match self {
            BackupEventType::MessageReceived => "message_received",
            BackupEventType::MessageEdited => "message_edited",
            BackupEventType::MessageDeleted => "message_deleted",
            BackupEventType::MediaReceived => "media_received",
            BackupEventType::MediaDeleted => "media_deleted",
            BackupEventType::ConversationCreated => "conversation_created",
            BackupEventType::ConversationDeleted => "conversation_deleted",
        }
    }

    /// Parse a snake_case string back into an event type.
    pub fn parse_snake_case(s: &str) -> Result<Self, Error> {
        Ok(match s {
            "message_received" => Self::MessageReceived,
            "message_edited" => Self::MessageEdited,
            "message_deleted" => Self::MessageDeleted,
            "media_received" => Self::MediaReceived,
            "media_deleted" => Self::MediaDeleted,
            "conversation_created" => Self::ConversationCreated,
            "conversation_deleted" => Self::ConversationDeleted,
            other => {
                return Err(Error::Storage(
                    format!("unknown backup event_type {other:?}").into(),
                ))
            }
        })
    }
}

/// One logical backup event.
///
/// `event_seq` is set by the database (AUTOINCREMENT) — caller
/// supplies the rest. `payload` is application-defined CBOR; the
/// segment builder re-emits it inside the encrypted segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEvent {
    /// Type tag.
    pub event_type: BackupEventType,
    /// Owning conversation, when the event has one.
    pub conversation_id: Option<Uuid>,
    /// Originating message, when the event has one.
    pub message_id: Option<Uuid>,
    /// Application-defined CBOR payload.
    pub payload: Vec<u8>,
    /// Wall-clock millisecond timestamp the event was journaled.
    pub created_at_ms: i64,
}

/// Result of [`BackupEventJournal::write_event`] — the
/// AUTOINCREMENT `event_seq` the row was assigned.
pub type BackupEventSeq = i64;

/// Phase-4 backup event journal.
///
/// Stateless reader / writer over an existing SQLCipher
/// [`Connection`]. Borrowing the connection rather than owning
/// it keeps the journal compatible with the persister's
/// SAVEPOINT boundaries — the caller decides whether the write
/// happens inside or outside a transaction.
#[derive(Debug, Default, Clone, Copy)]
pub struct BackupEventJournal;

impl BackupEventJournal {
    /// Construct a new journal handle.
    pub fn new() -> Self {
        Self
    }

    /// Append `event` to `backup_event_journal`. Returns the
    /// AUTOINCREMENT `event_seq` the database assigned.
    ///
    /// The caller controls transactionality — call from inside a
    /// SAVEPOINT to bind the event to the rest of the persisted
    /// state.
    pub fn write_event(
        &self,
        conn: &Connection,
        event: &BackupEvent,
    ) -> Result<BackupEventSeq, Error> {
        conn.execute(
            "INSERT INTO backup_event_journal(
                event_type, conversation_id, message_id, payload, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.event_type.as_str(),
                event.conversation_id.map(|u| u.to_string()),
                event.message_id.map(|u| u.to_string()),
                event.payload,
                event.created_at_ms,
            ],
        )
        .map_err(|e| Error::Storage(e.to_string().into()))?;
        Ok(conn.last_insert_rowid())
    }

    /// Read at most `limit` events with `event_seq > after_seq`,
    /// in ascending sequence order.
    ///
    /// Pass `after_seq = 0` to read from the start of the journal.
    pub fn read_events_since(
        &self,
        conn: &Connection,
        after_seq: BackupEventSeq,
        limit: usize,
    ) -> Result<Vec<(BackupEventSeq, BackupEvent)>, Error> {
        let mut stmt = conn
            .prepare(
                "SELECT event_seq, event_type, conversation_id, message_id,
                        payload, created_at_ms
                   FROM backup_event_journal
                  WHERE event_seq > ?1
                  ORDER BY event_seq ASC
                  LIMIT ?2",
            )
            .map_err(|e| Error::Storage(e.to_string().into()))?;
        let rows = stmt
            .query_map(params![after_seq, limit as i64], |row| {
                let seq: i64 = row.get(0)?;
                let type_str: String = row.get(1)?;
                let conv_str: Option<String> = row.get(2)?;
                let mid_str: Option<String> = row.get(3)?;
                let payload: Vec<u8> = row.get(4)?;
                let created_at_ms: i64 = row.get(5)?;
                Ok((seq, type_str, conv_str, mid_str, payload, created_at_ms))
            })
            .map_err(|e| Error::Storage(e.to_string().into()))?;

        let mut out = Vec::new();
        for row in rows {
            let (seq, type_str, conv_str, mid_str, payload, created_at_ms) =
                row.map_err(|e| Error::Storage(e.to_string().into()))?;
            // Skip rows whose `event_type` is not part of the
            // typed taxonomy. Legacy phases wrote ad-hoc tags
            // such as `"outbox_pending"` / `"outbox_sent"`
            // directly to the journal that the segment builder
            // does not need to dispatch on — surfacing a hard
            // error here would freeze the drain loop.
            let event_type = match BackupEventType::parse_snake_case(&type_str) {
                Ok(ty) => ty,
                Err(_) => continue,
            };
            let conversation_id = conv_str
                .map(|s| {
                    Uuid::parse_str(&s).map_err(|e| {
                        Error::Storage(crate::local_store::StorageError::InvalidId {
                            kind: "conversation_id",
                            source: e,
                        })
                    })
                })
                .transpose()?;
            let message_id = mid_str
                .map(|s| {
                    Uuid::parse_str(&s).map_err(|e| {
                        Error::Storage(crate::local_store::StorageError::InvalidId {
                            kind: "message_id",
                            source: e,
                        })
                    })
                })
                .transpose()?;
            out.push((
                seq,
                BackupEvent {
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

    /// Return the current `backup_event_cursor.cursor_seq`.
    /// Returns `0` when no cursor row has been written yet.
    pub fn read_cursor(&self, conn: &Connection) -> Result<BackupEventSeq, Error> {
        conn.query_row(
            "SELECT cursor_seq FROM backup_event_cursor WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|e| Error::Storage(e.to_string().into()))
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
        new_cursor: BackupEventSeq,
    ) -> Result<(), Error> {
        let current = self.read_cursor(conn)?;
        if new_cursor < current {
            return Err(Error::Storage(
                format!(
                    "backup cursor cannot go backwards (current={current}, requested={new_cursor})"
                )
                .into(),
            ));
        }
        conn.execute(
            "INSERT INTO backup_event_cursor(id, cursor_seq) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET cursor_seq = excluded.cursor_seq",
            params![new_cursor],
        )
        .map_err(|e| Error::Storage(e.to_string().into()))?;
        Ok(())
    }

    /// Convenience helper: read every event after the current
    /// cursor up to `limit`. Useful for the segment builder's
    /// drain loop.
    pub fn read_unsegmented(
        &self,
        conn: &Connection,
        limit: usize,
    ) -> Result<Vec<(BackupEventSeq, BackupEvent)>, Error> {
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

    fn sample_event(conv: Uuid) -> BackupEvent {
        BackupEvent {
            event_type: BackupEventType::MessageReceived,
            conversation_id: Some(conv),
            message_id: Some(Uuid::now_v7()),
            payload: vec![0xAA, 0xBB, 0xCC],
            created_at_ms: 1_777_000_000_000,
        }
    }

    #[test]
    fn write_and_read_round_trip() {
        let db = fresh_db();
        let journal = BackupEventJournal::new();
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
        let journal = BackupEventJournal::new();
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
    fn advance_cursor_persists_and_blocks_backwards_motion() {
        let db = fresh_db();
        let journal = BackupEventJournal::new();
        // Default cursor is 0.
        assert_eq!(journal.read_cursor(db.connection()).unwrap(), 0);

        journal.advance_cursor(db.connection(), 5).unwrap();
        assert_eq!(journal.read_cursor(db.connection()).unwrap(), 5);

        // Idempotent at the same value.
        journal.advance_cursor(db.connection(), 5).unwrap();
        assert_eq!(journal.read_cursor(db.connection()).unwrap(), 5);

        journal.advance_cursor(db.connection(), 10).unwrap();
        assert_eq!(journal.read_cursor(db.connection()).unwrap(), 10);

        // Backwards motion is rejected.
        let err = journal.advance_cursor(db.connection(), 9).unwrap_err();
        assert!(
            err.to_string().contains("backwards"),
            "expected 'backwards' message, got {err}"
        );
    }

    #[test]
    fn event_type_serde_round_trip() {
        for ty in [
            BackupEventType::MessageReceived,
            BackupEventType::MessageEdited,
            BackupEventType::MessageDeleted,
            BackupEventType::MediaReceived,
            BackupEventType::MediaDeleted,
            BackupEventType::ConversationCreated,
            BackupEventType::ConversationDeleted,
        ] {
            assert_eq!(BackupEventType::parse_snake_case(ty.as_str()).unwrap(), ty);
            let json = serde_json::to_string(&ty).unwrap();
            let back: BackupEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ty);
        }
    }

    #[test]
    fn read_unsegmented_drains_after_cursor() {
        let db = fresh_db();
        let journal = BackupEventJournal::new();
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
        let err = BackupEventType::parse_snake_case("totally_not_a_type").unwrap_err();
        assert!(err.to_string().contains("unknown backup event_type"));
    }

    #[test]
    fn read_skips_legacy_event_types_not_in_taxonomy() {
        // Mirror the pre-Phase-4 wiring that wrote
        // `"outbox_pending"` / `"outbox_sent"` strings to the
        // journal directly (see `MessagePersister::persist_outbox_entry_inner`).
        // The typed journal must skip them rather than blow up.
        use rusqlite::params;
        let db = fresh_db();
        let journal = BackupEventJournal::new();

        // One legacy row, one typed row.
        db.connection()
            .execute(
                "INSERT INTO backup_event_journal
                    (event_type, conversation_id, message_id, payload, created_at_ms)
                 VALUES ('outbox_pending', NULL, NULL, ?1, 0)",
                params![Vec::<u8>::new()],
            )
            .unwrap();
        let conv = Uuid::now_v7();
        let _ = journal
            .write_event(db.connection(), &sample_event(conv))
            .unwrap();

        // The typed read returns only the recognised taxonomy
        // row; the legacy `outbox_pending` row is silently
        // skipped.
        let events = journal.read_events_since(db.connection(), 0, 100).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1.event_type, BackupEventType::MessageReceived);
    }

    #[test]
    fn null_conversation_and_message_ids_round_trip() {
        let db = fresh_db();
        let journal = BackupEventJournal::new();
        let event = BackupEvent {
            event_type: BackupEventType::ConversationCreated,
            conversation_id: None,
            message_id: None,
            payload: vec![],
            created_at_ms: 0,
        };
        let seq = journal.write_event(db.connection(), &event).unwrap();
        let events = journal.read_events_since(db.connection(), 0, 100).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, seq);
        assert!(events[0].1.conversation_id.is_none());
        assert!(events[0].1.message_id.is_none());
    }
}
