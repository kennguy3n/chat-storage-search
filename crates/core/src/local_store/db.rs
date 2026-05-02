//! SQLCipher-backed local store database connection.
//!
//! `docs/PROPOSAL.md §7` and `docs/ARCHITECTURE.md §4` describe the
//! on-device persistence layer:
//!
//! * The database file lives at `{data_dir}/kchat.db`.
//! * It is encrypted by SQLCipher (bundled via `rusqlite`'s
//!   `bundled-sqlcipher-vendored-openssl` feature, so no system C
//!   library is required).
//! * The 32-byte `K_local_db` from
//!   [`crate::crypto::key_hierarchy`] is set with `PRAGMA key`. The
//!   platform-specific wrap of `K_local_db` (Keychain / Keystore /
//!   DPAPI) is layered above this struct and lands later in Phase 1.
//! * Schema bring-up runs [`super::schema::SCHEMA_SQL`]. If the build
//!   does not ship the FTS5 ICU tokenizer the schema is rewritten to
//!   the [`unicode61` fallback](crate::search::tokenizer::FTS5_TOKENIZE_UNICODE61)
//!   automatically — see [`LocalStoreDb::open_in_memory`] /
//!   [`LocalStoreDb::open`] for the detection logic and
//!   [`create_schema_with_unicode61_fallback`] for the public helper.
//!
//! The CRUD helpers exposed here are deliberately low-level:
//! `insert_*`, `get_*`, `update_body_state`. The higher-level
//! engines (`message::processor::MessagePersister`,
//! `search::query_engine::QueryEngine`) wrap these calls in
//! transactions, FTS5 maintenance, and event-journal entries.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use super::schema::{
    BackupEventJournalEntry, Conversation, MessageBody, MessageKind, MessageSkeleton, SCHEMA_SQL,
};
use super::state_machines::{ArchiveState, BackupState, BodyState, MediaState};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned from the [`LocalStoreDb`] surface.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// `rusqlite` returned an error (open, prepare, execute, …).
    #[error("rusqlite: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    /// A row's text column did not parse as one of the canonical
    /// state-machine values.
    #[error("invalid state value: {0}")]
    InvalidState(String),

    /// I/O error around the data directory (creating it, opening the
    /// database file).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// `Result` alias used by the database surface.
pub type DbResult<T> = std::result::Result<T, DbError>;

// ---------------------------------------------------------------------------
// Schema fallback helper
// ---------------------------------------------------------------------------

/// Returns a copy of [`SCHEMA_SQL`] with the FTS5 `tokenize = 'icu'`
/// clause rewritten to the documented `unicode61` fallback.
///
/// `docs/PROPOSAL.md §3.3`: ICU is the primary tokenizer. If the
/// SQLCipher build does not link against ICU (e.g. the
/// `bundled-sqlcipher-vendored-openssl` configuration this crate
/// uses by default), the FTS5 virtual table cannot be created with
/// `tokenize = 'icu'`. This helper substitutes the alternate literal
/// from [`crate::search::tokenizer::FTS5_TOKENIZE_UNICODE61`] so the
/// schema bring-up succeeds and Latin / Cyrillic / Greek / Arabic
/// search works. CJK / Thai / Khmer / Lao / Myanmar word segmentation
/// requires ICU and is not available on this path.
pub fn create_schema_with_unicode61_fallback() -> String {
    SCHEMA_SQL.replace(
        "tokenize = 'icu'",
        "tokenize = 'unicode61 remove_diacritics 2'",
    )
}

/// Whether the underlying SQLCipher build provides the FTS5 ICU
/// tokenizer.
///
/// The probe is non-destructive: it creates and immediately drops a
/// throw-away temporary virtual table.
fn fts5_icu_available(conn: &Connection) -> bool {
    let probed =
        conn.execute_batch("CREATE VIRTUAL TABLE temp.__icu_probe USING fts5(c, tokenize='icu');");
    if probed.is_ok() {
        // Best-effort cleanup — ignore failure.
        let _ = conn.execute_batch("DROP TABLE temp.__icu_probe;");
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// LocalStoreDb
// ---------------------------------------------------------------------------

/// SQLCipher-backed local-store connection wrapper.
///
/// One instance maps 1:1 with the `kchat.db` file (or the in-memory
/// database used by tests). Cloning is intentionally not supported —
/// `Connection` is not `Send`-cheap and Phase 1 keeps the model
/// "one connection per core instance".
#[derive(Debug)]
pub struct LocalStoreDb {
    conn: Connection,
    /// Resolved on-disk path. `None` for `:memory:` databases.
    path: Option<PathBuf>,
    /// Whether the FTS5 ICU tokenizer was available at open time.
    /// `false` means the schema was created with the `unicode61`
    /// fallback.
    icu_available: bool,
}

impl LocalStoreDb {
    /// Open or create the encrypted local-store database at
    /// `{data_dir}/kchat.db`.
    ///
    /// `data_dir` is created (recursively) if it does not exist.
    /// `key` is the 32-byte `K_local_db` from the key hierarchy.
    pub fn open(data_dir: &Path, key: &[u8; 32]) -> DbResult<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("kchat.db");
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        let icu_available = init_connection(&conn, key)?;
        Ok(Self {
            conn,
            path: Some(path),
            icu_available,
        })
    }

    /// Open an ephemeral in-memory database, suitable for tests.
    pub fn open_in_memory(key: &[u8; 32]) -> DbResult<Self> {
        let conn = Connection::open_in_memory()?;
        let icu_available = init_connection(&conn, key)?;
        Ok(Self {
            conn,
            path: None,
            icu_available,
        })
    }

    /// Borrow the underlying `rusqlite::Connection` for ad-hoc
    /// queries / transactions.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Mutable accessor used by helpers that need to start a
    /// transaction (`Connection::transaction`).
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Resolved on-disk path. `None` for `:memory:` databases.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// `true` when the schema was created with the FTS5 ICU
    /// tokenizer, `false` when the `unicode61` fallback was used.
    pub fn icu_available(&self) -> bool {
        self.icu_available
    }

    /// Close the database, surfacing any pending error.
    pub fn close(self) -> DbResult<()> {
        self.conn.close().map_err(|(_, e)| DbError::Rusqlite(e))?;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Conversation
    // ---------------------------------------------------------------

    /// Insert a row into `conversation`.
    pub fn insert_conversation(&self, conv: &Conversation) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO conversation (
                conversation_id, title_cipher, pinned, muted,
                last_message_id, last_activity_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                conv.conversation_id,
                conv.title_cipher,
                conv.pinned as i64,
                conv.muted as i64,
                conv.last_message_id,
                conv.last_activity_ms,
            ],
        )?;
        Ok(())
    }

    /// Insert a row into `message_skeleton`.
    pub fn insert_message_skeleton(&self, skel: &MessageSkeleton) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO message_skeleton (
                message_id, conversation_id, sender_id,
                created_at_ms, received_at_ms, kind,
                body_state, media_state, archive_state, backup_state,
                reply_to, edited_at_ms, deleted_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
             )",
            params![
                skel.message_id,
                skel.conversation_id,
                skel.sender_id,
                skel.created_at_ms,
                skel.received_at_ms,
                skel.kind.as_str(),
                skel.body_state.to_string(),
                skel.media_state.map(|s| s.to_string()),
                skel.archive_state.to_string(),
                skel.backup_state.to_string(),
                skel.reply_to,
                skel.edited_at_ms,
                skel.deleted_at_ms,
            ],
        )?;
        Ok(())
    }

    /// Insert a row into `message_body`.
    pub fn insert_message_body(&self, body: &MessageBody) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO message_body (
                message_id, text_content, detected_language, rich_meta
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                body.message_id,
                body.text_content,
                body.detected_language,
                body.rich_meta,
            ],
        )?;
        Ok(())
    }

    /// Fetch a conversation by id, if present.
    pub fn get_conversation(&self, conversation_id: &str) -> DbResult<Option<Conversation>> {
        self.conn
            .query_row(
                "SELECT conversation_id, title_cipher, pinned, muted,
                        last_message_id, last_activity_ms
                 FROM conversation
                 WHERE conversation_id = ?1",
                params![conversation_id],
                |row| {
                    Ok(Conversation {
                        conversation_id: row.get(0)?,
                        title_cipher: row.get(1)?,
                        pinned: row.get::<_, i64>(2)? != 0,
                        muted: row.get::<_, i64>(3)? != 0,
                        last_message_id: row.get(4)?,
                        last_activity_ms: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(DbError::from)
    }

    /// List every conversation row, newest activity first.
    ///
    /// Pinned conversations come first (still ordered by activity)
    /// because the public KChatCore surface treats pinning as a
    /// recency-override flag.
    pub fn list_conversations(&self) -> DbResult<Vec<Conversation>> {
        let mut stmt = self.conn.prepare(
            "SELECT conversation_id, title_cipher, pinned, muted,
                    last_message_id, last_activity_ms
               FROM conversation
              ORDER BY pinned DESC, last_activity_ms DESC, conversation_id ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Conversation {
                    conversation_id: row.get(0)?,
                    title_cipher: row.get(1)?,
                    pinned: row.get::<_, i64>(2)? != 0,
                    muted: row.get::<_, i64>(3)? != 0,
                    last_message_id: row.get(4)?,
                    last_activity_ms: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Toggle the `pinned` flag for `conversation_id`. Returns the
    /// number of rows that were updated (`0` when the conversation
    /// does not exist).
    pub fn update_conversation_pin(&self, conversation_id: &str, pinned: bool) -> DbResult<usize> {
        let n = self.conn.execute(
            "UPDATE conversation SET pinned = ?1 WHERE conversation_id = ?2",
            params![pinned as i64, conversation_id],
        )?;
        Ok(n)
    }

    /// Toggle the `muted` flag for `conversation_id`. Returns the
    /// number of rows that were updated (`0` when the conversation
    /// does not exist).
    pub fn update_conversation_mute(&self, conversation_id: &str, muted: bool) -> DbResult<usize> {
        let n = self.conn.execute(
            "UPDATE conversation SET muted = ?1 WHERE conversation_id = ?2",
            params![muted as i64, conversation_id],
        )?;
        Ok(n)
    }

    /// Fetch a message skeleton by id, if present.
    pub fn get_message_skeleton(&self, message_id: &str) -> DbResult<Option<MessageSkeleton>> {
        let row = self
            .conn
            .query_row(
                "SELECT message_id, conversation_id, sender_id,
                        created_at_ms, received_at_ms, kind,
                        body_state, media_state, archive_state, backup_state,
                        reply_to, edited_at_ms, deleted_at_ms
                 FROM message_skeleton
                 WHERE message_id = ?1",
                params![message_id],
                |row| {
                    let kind: String = row.get(5)?;
                    let body_state: String = row.get(6)?;
                    let media_state: Option<String> = row.get(7)?;
                    let archive_state: String = row.get(8)?;
                    let backup_state: String = row.get(9)?;
                    Ok((MessageSkeletonRaw {
                        message_id: row.get(0)?,
                        conversation_id: row.get(1)?,
                        sender_id: row.get(2)?,
                        created_at_ms: row.get(3)?,
                        received_at_ms: row.get(4)?,
                        kind,
                        body_state,
                        media_state,
                        archive_state,
                        backup_state,
                        reply_to: row.get(10)?,
                        edited_at_ms: row.get(11)?,
                        deleted_at_ms: row.get(12)?,
                    },))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((raw,)) => Ok(Some(raw.into_skeleton()?)),
        }
    }

    /// Fetch a message body by id, if present.
    pub fn get_message_body(&self, message_id: &str) -> DbResult<Option<MessageBody>> {
        self.conn
            .query_row(
                "SELECT message_id, text_content, detected_language, rich_meta
                 FROM message_body
                 WHERE message_id = ?1",
                params![message_id],
                |row| {
                    Ok(MessageBody {
                        message_id: row.get(0)?,
                        text_content: row.get(1)?,
                        detected_language: row.get(2)?,
                        rich_meta: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(DbError::from)
    }

    /// Update `message_skeleton.body_state` for `message_id`.
    pub fn update_body_state(&self, message_id: &str, new_state: BodyState) -> DbResult<()> {
        self.conn.execute(
            "UPDATE message_skeleton SET body_state = ?1 WHERE message_id = ?2",
            params![new_state.to_string(), message_id],
        )?;
        Ok(())
    }

    /// Replace `message_body.text_content` for `message_id`.
    ///
    /// Used by the edit pipeline. The FTS row has to be maintained
    /// separately by the caller — see
    /// [`crate::message::processor::MessagePersister::edit_message`].
    pub fn update_message_body_text(&self, message_id: &str, new_text: &str) -> DbResult<()> {
        self.conn.execute(
            "UPDATE message_body SET text_content = ?1 WHERE message_id = ?2",
            params![new_text, message_id],
        )?;
        Ok(())
    }

    /// Stamp `message_skeleton.edited_at_ms` for `message_id`.
    pub fn update_skeleton_edited(&self, message_id: &str, edited_at_ms: i64) -> DbResult<()> {
        self.conn.execute(
            "UPDATE message_skeleton SET edited_at_ms = ?1 WHERE message_id = ?2",
            params![edited_at_ms, message_id],
        )?;
        Ok(())
    }

    /// Update both `body_state` and `deleted_at_ms` for `message_id`
    /// in a single statement.
    pub fn update_skeleton_deleted(
        &self,
        message_id: &str,
        deleted_at_ms: i64,
        new_body_state: BodyState,
    ) -> DbResult<()> {
        self.conn.execute(
            "UPDATE message_skeleton
                SET body_state = ?1, deleted_at_ms = ?2
              WHERE message_id = ?3",
            params![new_body_state.to_string(), deleted_at_ms, message_id],
        )?;
        Ok(())
    }

    /// Delete the `message_body` row for `message_id`. Used by the
    /// `delete_for_everyone` pipeline; `delete_for_me` keeps the
    /// body row in place so the message remains restorable.
    pub fn delete_message_body(&self, message_id: &str) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM message_body WHERE message_id = ?1",
            params![message_id],
        )?;
        Ok(())
    }

    /// Remove the `search_fts` row for `message_id`. Idempotent —
    /// a missing row is not an error.
    pub fn delete_fts_row(&self, message_id: &str) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM search_fts WHERE message_id = ?1",
            params![message_id],
        )?;
        Ok(())
    }

    /// Update the conversation row's `last_message_id` and
    /// `last_activity_ms` columns. Used by
    /// [`crate::message::processor::MessagePersister`] after
    /// inserting a fresh skeleton so the conversation list reflects
    /// the most recent activity.
    ///
    /// Returns the number of rows updated; `0` when no conversation
    /// with `conversation_id` exists.
    pub fn update_conversation_last_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        activity_ms: i64,
    ) -> DbResult<usize> {
        let n = self.conn.execute(
            "UPDATE conversation
                SET last_message_id = ?1, last_activity_ms = ?2
              WHERE conversation_id = ?3",
            params![message_id, activity_ms, conversation_id],
        )?;
        Ok(n)
    }

    /// Return the messages in `conversation_id`, ordered by
    /// `created_at_ms DESC`. `before_ms`, when `Some`, restricts the
    /// page to messages with `created_at_ms < before_ms`. `limit`
    /// caps the returned page.
    pub fn get_conversation_messages(
        &self,
        conversation_id: &str,
        before_ms: Option<i64>,
        limit: usize,
    ) -> DbResult<Vec<MessageSkeleton>> {
        let mut stmt;
        let rows = if let Some(before) = before_ms {
            stmt = self.conn.prepare(
                "SELECT message_id, conversation_id, sender_id,
                        created_at_ms, received_at_ms, kind,
                        body_state, media_state, archive_state, backup_state,
                        reply_to, edited_at_ms, deleted_at_ms
                   FROM message_skeleton
                  WHERE conversation_id = ?1 AND created_at_ms < ?2
                  ORDER BY created_at_ms DESC
                  LIMIT ?3",
            )?;
            stmt.query_map(
                params![conversation_id, before, limit as i64],
                decode_skeleton_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt = self.conn.prepare(
                "SELECT message_id, conversation_id, sender_id,
                        created_at_ms, received_at_ms, kind,
                        body_state, media_state, archive_state, backup_state,
                        reply_to, edited_at_ms, deleted_at_ms
                   FROM message_skeleton
                  WHERE conversation_id = ?1
                  ORDER BY created_at_ms DESC
                  LIMIT ?2",
            )?;
            stmt.query_map(params![conversation_id, limit as i64], decode_skeleton_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut out = Vec::with_capacity(rows.len());
        for raw in rows {
            out.push(raw.into_skeleton()?);
        }
        Ok(out)
    }

    /// Fetch a message skeleton plus its (optional) body in one go.
    /// Returns `Ok(None)` when the skeleton does not exist, or
    /// `Ok(Some((skel, None)))` when the skeleton exists but the
    /// body row has been dropped (e.g. `delete_for_everyone`).
    pub fn get_message_with_body(
        &self,
        message_id: &str,
    ) -> DbResult<Option<(MessageSkeleton, Option<MessageBody>)>> {
        let row = self
            .conn
            .query_row(
                "SELECT s.message_id, s.conversation_id, s.sender_id,
                        s.created_at_ms, s.received_at_ms, s.kind,
                        s.body_state, s.media_state, s.archive_state,
                        s.backup_state, s.reply_to, s.edited_at_ms,
                        s.deleted_at_ms,
                        b.text_content, b.detected_language, b.rich_meta
                   FROM message_skeleton s
                   LEFT JOIN message_body b ON b.message_id = s.message_id
                  WHERE s.message_id = ?1",
                params![message_id],
                |row| {
                    let raw = decode_skeleton_row(row)?;
                    let text_content: Option<String> = row.get(13)?;
                    let detected_language: Option<String> = row.get(14)?;
                    let rich_meta: Option<Vec<u8>> = row.get(15)?;
                    let body_present = text_content.is_some()
                        || detected_language.is_some()
                        || rich_meta.is_some();
                    let body = if body_present {
                        Some(MessageBody {
                            message_id: raw.message_id.clone(),
                            text_content,
                            detected_language,
                            rich_meta,
                        })
                    } else {
                        None
                    };
                    Ok((raw, body))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((raw, body)) => Ok(Some((raw.into_skeleton()?, body))),
        }
    }

    /// Insert a row into `backup_event_journal`. The `event_seq`
    /// field is `AUTOINCREMENT` in the schema; the value provided
    /// here is honored if non-zero, otherwise the backend assigns
    /// one and the inserted row's id is returned via
    /// [`Connection::last_insert_rowid`] (mirroring `event_seq`).
    pub fn insert_backup_event(&self, entry: &BackupEventJournalEntry) -> DbResult<()> {
        if entry.event_seq == 0 {
            self.conn.execute(
                "INSERT INTO backup_event_journal (event_type, payload, created_at_ms)
                 VALUES (?1, ?2, ?3)",
                params![entry.event_type, entry.payload, entry.created_at_ms],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO backup_event_journal (event_seq, event_type, payload, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    entry.event_seq,
                    entry.event_type,
                    entry.payload,
                    entry.created_at_ms
                ],
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Connection bring-up
// ---------------------------------------------------------------------------

/// Run the post-open setup: `PRAGMA key`, `PRAGMA foreign_keys`,
/// schema bring-up (with unicode61 fallback), and a sanity check.
/// Returns whether the FTS5 ICU tokenizer was available.
fn init_connection(conn: &Connection, key: &[u8; 32]) -> DbResult<bool> {
    set_key(conn, key)?;
    // Foreign keys must be enabled per-connection in SQLite.
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    // Force-decrypt with a trivial query so a wrong key surfaces
    // immediately rather than lurking until the first table access.
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")?;

    let icu_available = fts5_icu_available(conn);
    let schema = if icu_available {
        SCHEMA_SQL.to_string()
    } else {
        create_schema_with_unicode61_fallback()
    };
    conn.execute_batch(&schema)?;
    Ok(icu_available)
}

/// Set `PRAGMA key = x'...'` from a 32-byte raw key.
fn set_key(conn: &Connection, key: &[u8; 32]) -> DbResult<()> {
    let mut hex = String::with_capacity(64);
    for b in key {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    let pragma = format!("PRAGMA key = \"x'{hex}'\";");
    conn.execute_batch(&pragma)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal raw-row decoding
// ---------------------------------------------------------------------------

struct MessageSkeletonRaw {
    message_id: String,
    conversation_id: String,
    sender_id: String,
    created_at_ms: i64,
    received_at_ms: i64,
    kind: String,
    body_state: String,
    media_state: Option<String>,
    archive_state: String,
    backup_state: String,
    reply_to: Option<String>,
    edited_at_ms: Option<i64>,
    deleted_at_ms: Option<i64>,
}

/// Decode the leading 13 columns of a `message_skeleton` row into a
/// [`MessageSkeletonRaw`]. Used by row-by-row queries
/// (`get_message_skeleton`, `get_conversation_messages`,
/// `get_message_with_body`).
fn decode_skeleton_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageSkeletonRaw> {
    Ok(MessageSkeletonRaw {
        message_id: row.get(0)?,
        conversation_id: row.get(1)?,
        sender_id: row.get(2)?,
        created_at_ms: row.get(3)?,
        received_at_ms: row.get(4)?,
        kind: row.get(5)?,
        body_state: row.get(6)?,
        media_state: row.get(7)?,
        archive_state: row.get(8)?,
        backup_state: row.get(9)?,
        reply_to: row.get(10)?,
        edited_at_ms: row.get(11)?,
        deleted_at_ms: row.get(12)?,
    })
}

impl MessageSkeletonRaw {
    fn into_skeleton(self) -> DbResult<MessageSkeleton> {
        let kind = match self.kind.as_str() {
            "text" => MessageKind::Text,
            "media" => MessageKind::Media,
            "system" => MessageKind::System,
            other => return Err(DbError::InvalidState(format!("kind={other}"))),
        };
        let body_state: BodyState = self
            .body_state
            .parse()
            .map_err(|_| DbError::InvalidState(format!("body_state={}", self.body_state)))?;
        let media_state = match self.media_state {
            None => None,
            Some(s) => Some(
                s.parse::<MediaState>()
                    .map_err(|_| DbError::InvalidState(format!("media_state={s}")))?,
            ),
        };
        let archive_state: ArchiveState = self
            .archive_state
            .parse()
            .map_err(|_| DbError::InvalidState(format!("archive_state={}", self.archive_state)))?;
        let backup_state: BackupState = self
            .backup_state
            .parse()
            .map_err(|_| DbError::InvalidState(format!("backup_state={}", self.backup_state)))?;
        Ok(MessageSkeleton {
            message_id: self.message_id,
            conversation_id: self.conversation_id,
            sender_id: self.sender_id,
            created_at_ms: self.created_at_ms,
            received_at_ms: self.received_at_ms,
            kind,
            body_state,
            media_state,
            archive_state,
            backup_state,
            reply_to: self.reply_to,
            edited_at_ms: self.edited_at_ms,
            deleted_at_ms: self.deleted_at_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store::schema::TABLES;

    fn test_key() -> [u8; 32] {
        [0x42; 32]
    }

    fn fresh_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&test_key()).expect("open in-memory db")
    }

    #[test]
    fn open_in_memory_brings_up_every_documented_table() {
        let db = fresh_db();
        let conn = db.connection();
        for table in TABLES {
            let exists: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master
                     WHERE name = ?1 AND (type = 'table' OR type = 'virtual')",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists > 0, "missing table: {table}");
        }
    }

    #[test]
    fn pragma_key_is_set_and_db_is_encrypted() {
        let db = fresh_db();
        let cipher: String = db
            .connection()
            .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
            .unwrap();
        assert!(
            !cipher.is_empty(),
            "PRAGMA cipher_version returned an empty string \
             — sqlcipher build is broken"
        );
    }

    #[test]
    fn open_creates_directory_and_persists_file() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("nested").join("db");
        let db = LocalStoreDb::open(&nested, &test_key()).expect("open");
        assert!(db.path().unwrap().exists(), "db file should exist on disk");
        db.close().unwrap();
    }

    #[test]
    fn insert_and_fetch_conversation() {
        let db = fresh_db();
        let conv = Conversation {
            conversation_id: "conv-1".into(),
            title_cipher: Some(vec![1, 2, 3]),
            pinned: true,
            muted: false,
            last_message_id: Some("msg-1".into()),
            last_activity_ms: 1_700_000_000_000,
        };
        db.insert_conversation(&conv).unwrap();
        let back = db.get_conversation("conv-1").unwrap().expect("present");
        assert_eq!(back, conv);
    }

    #[test]
    fn insert_and_fetch_message_skeleton_and_body() {
        let db = fresh_db();
        let conv = Conversation {
            conversation_id: "conv-1".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
        };
        db.insert_conversation(&conv).unwrap();
        let skel = MessageSkeleton {
            message_id: "msg-1".into(),
            conversation_id: "conv-1".into(),
            sender_id: "user-1".into(),
            created_at_ms: 100,
            received_at_ms: 110,
            kind: MessageKind::Text,
            body_state: BodyState::LocalPlainAvailable,
            media_state: None,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        db.insert_message_skeleton(&skel).unwrap();
        let body = MessageBody {
            message_id: "msg-1".into(),
            text_content: Some("hello".into()),
            detected_language: Some("en".into()),
            rich_meta: None,
        };
        db.insert_message_body(&body).unwrap();
        assert_eq!(db.get_message_skeleton("msg-1").unwrap(), Some(skel));
        assert_eq!(db.get_message_body("msg-1").unwrap(), Some(body));
        assert!(db.get_message_skeleton("missing").unwrap().is_none());
        assert!(db.get_message_body("missing").unwrap().is_none());
    }

    #[test]
    fn update_body_state_changes_the_row() {
        let db = fresh_db();
        let conv = Conversation {
            conversation_id: "c".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
        };
        db.insert_conversation(&conv).unwrap();
        let skel = MessageSkeleton {
            message_id: "m".into(),
            conversation_id: "c".into(),
            sender_id: "s".into(),
            created_at_ms: 1,
            received_at_ms: 1,
            kind: MessageKind::Text,
            body_state: BodyState::LocalPlainAvailable,
            media_state: None,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        db.insert_message_skeleton(&skel).unwrap();
        db.update_body_state("m", BodyState::DeletedForMe).unwrap();
        let back = db.get_message_skeleton("m").unwrap().unwrap();
        assert_eq!(back.body_state, BodyState::DeletedForMe);
    }

    #[test]
    fn insert_backup_event_autoincrements_seq() {
        let db = fresh_db();
        let entry = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "message_received".into(),
            payload: vec![0xa1, 0xa2],
            created_at_ms: 1_700_000_000_000,
        };
        db.insert_backup_event(&entry).unwrap();
        let row: (i64, String, Vec<u8>, i64) = db
            .connection()
            .query_row(
                "SELECT event_seq, event_type, payload, created_at_ms
                 FROM backup_event_journal LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert!(
            row.0 >= 1,
            "event_seq should autoincrement (>=1), got {}",
            row.0
        );
        assert_eq!(row.1, "message_received");
        assert_eq!(row.2, entry.payload);
        assert_eq!(row.3, entry.created_at_ms);
    }

    #[test]
    fn foreign_key_constraint_rejects_orphan_body() {
        let db = fresh_db();
        // No conversation, no skeleton — message_body insert must
        // fail on the FK to message_skeleton.
        let body = MessageBody {
            message_id: "orphan".into(),
            text_content: Some("x".into()),
            detected_language: None,
            rich_meta: None,
        };
        let err = db.insert_message_body(&body).unwrap_err();
        match err {
            DbError::Rusqlite(rusqlite::Error::SqliteFailure(e, _)) => {
                assert!(
                    e.code == rusqlite::ErrorCode::ConstraintViolation,
                    "expected FK constraint violation, got {:?}",
                    e
                );
            }
            other => panic!("expected sqlite FK failure, got {other:?}"),
        }
    }

    #[test]
    fn close_returns_ok() {
        fresh_db().close().expect("close ok");
    }

    #[test]
    fn unicode61_fallback_string_replaces_icu_literal() {
        let s = create_schema_with_unicode61_fallback();
        assert!(!s.contains("tokenize = 'icu'"));
        assert!(s.contains("tokenize = 'unicode61 remove_diacritics 2'"));
    }

    fn seed_skeleton_with_body(db: &LocalStoreDb, mid: &str, conv: &str, text: &str) {
        let conversation = Conversation {
            conversation_id: conv.to_string(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
        };
        db.insert_conversation(&conversation).unwrap();
        let skel = MessageSkeleton {
            message_id: mid.into(),
            conversation_id: conv.into(),
            sender_id: "user-1".into(),
            created_at_ms: 100,
            received_at_ms: 110,
            kind: MessageKind::Text,
            body_state: BodyState::LocalPlainAvailable,
            media_state: None,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        db.insert_message_skeleton(&skel).unwrap();
        let body = MessageBody {
            message_id: mid.into(),
            text_content: Some(text.into()),
            detected_language: None,
            rich_meta: None,
        };
        db.insert_message_body(&body).unwrap();
    }

    #[test]
    fn update_message_body_text_replaces_content() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m", "c", "old");
        db.update_message_body_text("m", "new").unwrap();
        let body = db.get_message_body("m").unwrap().expect("body");
        assert_eq!(body.text_content.as_deref(), Some("new"));
    }

    #[test]
    fn update_skeleton_edited_stamps_timestamp() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m", "c", "x");
        db.update_skeleton_edited("m", 12_345).unwrap();
        let skel = db.get_message_skeleton("m").unwrap().expect("skeleton");
        assert_eq!(skel.edited_at_ms, Some(12_345));
    }

    #[test]
    fn update_skeleton_deleted_sets_state_and_timestamp() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m", "c", "x");
        db.update_skeleton_deleted("m", 9_999, BodyState::DeletedForEveryone)
            .unwrap();
        let skel = db.get_message_skeleton("m").unwrap().expect("skeleton");
        assert_eq!(skel.body_state, BodyState::DeletedForEveryone);
        assert_eq!(skel.deleted_at_ms, Some(9_999));
    }

    #[test]
    fn delete_message_body_removes_row() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m", "c", "x");
        db.delete_message_body("m").unwrap();
        assert!(db.get_message_body("m").unwrap().is_none());
    }

    #[test]
    fn delete_fts_row_is_idempotent() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m", "c", "x");
        db.connection()
            .execute(
                "INSERT INTO search_fts(
                    message_id, conversation_id, sender_id,
                    created_at_ms, text_content
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params!["m", "c", "user-1", 100i64, "x"],
            )
            .unwrap();
        db.delete_fts_row("m").unwrap();
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM search_fts WHERE message_id = ?1",
                params!["m"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        // Second delete on a missing row is still Ok.
        db.delete_fts_row("m").unwrap();
    }

    // -----------------------------------------------------------------
    // Conversation management — Task 4
    // -----------------------------------------------------------------

    fn build_conv(id: &str, last_activity_ms: i64, pinned: bool) -> Conversation {
        Conversation {
            conversation_id: id.into(),
            title_cipher: None,
            pinned,
            muted: false,
            last_message_id: None,
            last_activity_ms,
        }
    }

    #[test]
    fn list_conversations_orders_by_pinned_then_activity() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-old", 1_000, false))
            .unwrap();
        db.insert_conversation(&build_conv("c-mid", 2_000, false))
            .unwrap();
        db.insert_conversation(&build_conv("c-new", 3_000, false))
            .unwrap();
        // Pinned conversation rises to the top regardless of recency.
        db.insert_conversation(&build_conv("c-pin", 500, true))
            .unwrap();

        let list = db.list_conversations().unwrap();
        let ids: Vec<&str> = list.iter().map(|c| c.conversation_id.as_str()).collect();
        assert_eq!(ids, ["c-pin", "c-new", "c-mid", "c-old"]);
    }

    #[test]
    fn list_conversations_returns_empty_for_fresh_db() {
        let db = fresh_db();
        assert!(db.list_conversations().unwrap().is_empty());
    }

    #[test]
    fn update_conversation_pin_round_trip() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        let n = db.update_conversation_pin("c-1", true).unwrap();
        assert_eq!(n, 1);
        let row = db.get_conversation("c-1").unwrap().unwrap();
        assert!(row.pinned);
        let n = db.update_conversation_pin("c-1", false).unwrap();
        assert_eq!(n, 1);
        let row = db.get_conversation("c-1").unwrap().unwrap();
        assert!(!row.pinned);
    }

    #[test]
    fn update_conversation_pin_returns_zero_for_missing_id() {
        let db = fresh_db();
        let n = db.update_conversation_pin("does-not-exist", true).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn update_conversation_mute_round_trip() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        let n = db.update_conversation_mute("c-1", true).unwrap();
        assert_eq!(n, 1);
        let row = db.get_conversation("c-1").unwrap().unwrap();
        assert!(row.muted);
        let n = db.update_conversation_mute("c-1", false).unwrap();
        assert_eq!(n, 1);
        let row = db.get_conversation("c-1").unwrap().unwrap();
        assert!(!row.muted);
    }

    #[test]
    fn update_conversation_mute_returns_zero_for_missing_id() {
        let db = fresh_db();
        let n = db.update_conversation_mute("does-not-exist", true).unwrap();
        assert_eq!(n, 0);
    }

    // -----------------------------------------------------------------
    // Timeline retrieval API
    // -----------------------------------------------------------------

    /// Insert a skeleton + body, fixing every timestamp / sender so
    /// the test asserts only the columns it cares about.
    fn seed_timeline_message(
        db: &LocalStoreDb,
        mid: &str,
        conv: &str,
        created_at_ms: i64,
        text: &str,
    ) {
        let skel = MessageSkeleton {
            message_id: mid.into(),
            conversation_id: conv.into(),
            sender_id: "user-1".into(),
            created_at_ms,
            received_at_ms: created_at_ms,
            kind: MessageKind::Text,
            body_state: BodyState::LocalPlainAvailable,
            media_state: None,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        db.insert_message_skeleton(&skel).unwrap();
        let body = MessageBody {
            message_id: mid.into(),
            text_content: Some(text.into()),
            detected_language: None,
            rich_meta: None,
        };
        db.insert_message_body(&body).unwrap();
    }

    #[test]
    fn get_conversation_messages_returns_newest_first() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        seed_timeline_message(&db, "m-1", "c-1", 100, "first");
        seed_timeline_message(&db, "m-2", "c-1", 200, "second");
        seed_timeline_message(&db, "m-3", "c-1", 300, "third");

        let rows = db.get_conversation_messages("c-1", None, 10).unwrap();
        let ids: Vec<&str> = rows.iter().map(|s| s.message_id.as_str()).collect();
        assert_eq!(ids, ["m-3", "m-2", "m-1"]);
    }

    #[test]
    fn get_conversation_messages_pagination_with_before_ms() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        for (i, ts) in [100, 200, 300, 400, 500].iter().enumerate() {
            seed_timeline_message(&db, &format!("m-{i}"), "c-1", *ts, "x");
        }

        // Page 1: newest 2 — m-4 (500) then m-3 (400).
        let page1 = db.get_conversation_messages("c-1", None, 2).unwrap();
        let ids: Vec<&str> = page1.iter().map(|s| s.message_id.as_str()).collect();
        assert_eq!(ids, ["m-4", "m-3"]);

        // Page 2: before 400 — m-2 (300) then m-1 (200).
        let page2 = db.get_conversation_messages("c-1", Some(400), 2).unwrap();
        let ids: Vec<&str> = page2.iter().map(|s| s.message_id.as_str()).collect();
        assert_eq!(ids, ["m-2", "m-1"]);

        // Page 3: before 200 — only m-0 (100).
        let page3 = db.get_conversation_messages("c-1", Some(200), 2).unwrap();
        let ids: Vec<&str> = page3.iter().map(|s| s.message_id.as_str()).collect();
        assert_eq!(ids, ["m-0"]);

        // Page 4: before 100 — empty.
        assert!(db
            .get_conversation_messages("c-1", Some(100), 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn get_conversation_messages_respects_limit() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        for i in 0..5 {
            seed_timeline_message(&db, &format!("m-{i}"), "c-1", 100 + i as i64, "x");
        }

        assert_eq!(
            db.get_conversation_messages("c-1", None, 0).unwrap().len(),
            0
        );
        assert_eq!(
            db.get_conversation_messages("c-1", None, 1).unwrap().len(),
            1
        );
        assert_eq!(
            db.get_conversation_messages("c-1", None, 5).unwrap().len(),
            5
        );
        assert_eq!(
            db.get_conversation_messages("c-1", None, 100)
                .unwrap()
                .len(),
            5
        );
    }

    #[test]
    fn get_message_with_body_returns_both() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        seed_timeline_message(&db, "m-1", "c-1", 100, "hello world");

        let pair = db.get_message_with_body("m-1").unwrap().expect("present");
        assert_eq!(pair.0.message_id, "m-1");
        assert_eq!(pair.0.conversation_id, "c-1");
        let body = pair.1.expect("body present");
        assert_eq!(body.text_content.as_deref(), Some("hello world"));

        // Missing message round-trips to None.
        assert!(db.get_message_with_body("m-missing").unwrap().is_none());

        // After dropping the body row the skeleton is still
        // returned; the body half is None.
        db.delete_message_body("m-1").unwrap();
        let pair = db.get_message_with_body("m-1").unwrap().expect("present");
        assert!(pair.1.is_none(), "body must be None after delete");
    }

    // -----------------------------------------------------------------
    // Conversation metadata auto-update
    // -----------------------------------------------------------------

    #[test]
    fn update_conversation_last_message_sets_fields() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        let n = db
            .update_conversation_last_message("c-1", "m-42", 5_555)
            .unwrap();
        assert_eq!(n, 1);
        let row = db.get_conversation("c-1").unwrap().expect("conv");
        assert_eq!(row.last_message_id.as_deref(), Some("m-42"));
        assert_eq!(row.last_activity_ms, 5_555);
    }

    #[test]
    fn update_conversation_last_message_returns_zero_for_missing() {
        let db = fresh_db();
        let n = db.update_conversation_last_message("nope", "m", 1).unwrap();
        assert_eq!(n, 0);
    }
}
