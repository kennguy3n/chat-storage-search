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
    BackupEventJournalEntry, Conversation, MediaAsset, MessageBody, MessageKind, MessageSkeleton,
    StorageBackend, TimelineRow, SCHEMA_SQL,
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

/// Decode a `conversation` table row into a [`Conversation`].
/// Centralised so every read path (single-row fetch, full
/// list, hierarchy filter) sees the same column ordering and
/// the Phase-8 hierarchy fields are always populated.
fn row_to_conversation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Conversation> {
    Ok(Conversation {
        conversation_id: row.get(0)?,
        title_cipher: row.get(1)?,
        pinned: row.get::<_, i64>(2)? != 0,
        muted: row.get::<_, i64>(3)? != 0,
        last_message_id: row.get(4)?,
        last_activity_ms: row.get(5)?,
        conversation_type: row.get(6)?,
        scope: row.get(7)?,
        tenant_id: row.get(8)?,
        community_id: row.get(9)?,
        domain_id: row.get(10)?,
    })
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

    /// Insert a row into `conversation`. Phase-8 hierarchy
    /// columns ([`Conversation::conversation_type`], `scope`,
    /// `tenant_id`, `community_id`, `domain_id`) are always
    /// written so `SELECT *` round-trips the full struct.
    pub fn insert_conversation(&self, conv: &Conversation) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO conversation (
                conversation_id, title_cipher, pinned, muted,
                last_message_id, last_activity_ms,
                conversation_type, scope, tenant_id,
                community_id, domain_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                conv.conversation_id,
                conv.title_cipher,
                conv.pinned as i64,
                conv.muted as i64,
                conv.last_message_id,
                conv.last_activity_ms,
                conv.conversation_type,
                conv.scope,
                conv.tenant_id,
                conv.community_id,
                conv.domain_id,
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
                        last_message_id, last_activity_ms,
                        conversation_type, scope, tenant_id,
                        community_id, domain_id
                 FROM conversation
                 WHERE conversation_id = ?1",
                params![conversation_id],
                row_to_conversation,
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
                    last_message_id, last_activity_ms,
                    conversation_type, scope, tenant_id,
                    community_id, domain_id
               FROM conversation
              ORDER BY pinned DESC, last_activity_ms DESC, conversation_id ASC",
        )?;
        let rows = stmt
            .query_map([], row_to_conversation)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// List every conversation that belongs to `community_id`.
    /// Phase 8 helper for [`crate::SearchTarget::Community`]
    /// resolution; the WHERE clause matches the
    /// `idx_conv_community` index added to
    /// [`crate::local_store::schema::SCHEMA_SQL`].
    pub fn list_conversations_by_community(
        &self,
        community_id: &str,
    ) -> DbResult<Vec<Conversation>> {
        self.list_conversations_by_column("community_id", community_id)
    }

    /// List every conversation that belongs to `domain_id`.
    /// Phase 8 helper for [`crate::SearchTarget::Domain`].
    pub fn list_conversations_by_domain(&self, domain_id: &str) -> DbResult<Vec<Conversation>> {
        self.list_conversations_by_column("domain_id", domain_id)
    }

    /// List every conversation that belongs to `tenant_id`.
    /// Phase 8 helper for [`crate::SearchTarget::Tenant`].
    pub fn list_conversations_by_tenant(&self, tenant_id: &str) -> DbResult<Vec<Conversation>> {
        self.list_conversations_by_column("tenant_id", tenant_id)
    }

    /// List every conversation with the given `scope`. Phase 8
    /// helper for [`crate::SearchTarget::B2cAll`].
    pub fn list_conversations_by_scope(&self, scope: &str) -> DbResult<Vec<Conversation>> {
        self.list_conversations_by_column("scope", scope)
    }

    fn list_conversations_by_column(
        &self,
        column: &str,
        value: &str,
    ) -> DbResult<Vec<Conversation>> {
        // The column name is taken from a closed set of literals
        // (`tenant_id`, `community_id`, `domain_id`, `scope`)
        // chosen by the four wrapper methods above — never user
        // input — so the inline format string is safe.
        let sql = format!(
            "SELECT conversation_id, title_cipher, pinned, muted,
                    last_message_id, last_activity_ms,
                    conversation_type, scope, tenant_id,
                    community_id, domain_id
               FROM conversation
              WHERE {column} = ?1
              ORDER BY pinned DESC, last_activity_ms DESC, conversation_id ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params![value], row_to_conversation)?
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

    /// Rehydrate a cold message body in place, without touching the
    /// timeline ordering columns (`created_at_ms`, the row's
    /// position in `message_skeleton`).
    ///
    /// `docs/PROPOSAL.md §5.5` calls out that a cold message must be
    /// "filled in" without a scroll-jump on the renderer — the row
    /// is already drawn as a skeleton and the body arrives later
    /// from the archive. The full sequence runs inside a single
    /// `SAVEPOINT rehydrate_body` so a partial failure (e.g. the
    /// FTS upsert errors out) rolls back to the pre-call state and
    /// the caller can retry without observing a half-applied row:
    ///
    /// 1. UPSERT `message_body` keyed on `message_id`. Missing rows
    ///    (the body was previously evicted) get an INSERT;
    ///    existing rows have their `text_content` updated and
    ///    `detected_language` / `rich_meta` left untouched.
    /// 2. `UPDATE message_skeleton.body_state` to `new_body_state`.
    ///    The state is **not** validated against the body-state
    ///    transition matrix here because rehydration after an
    ///    archive fetch is the canonical exit from
    ///    `RemoteArchiveOnly` and does not have a pure-state
    ///    predecessor.
    /// 3. Refresh the `search_fts` row. The previous row (if any) is
    ///    dropped first so we never accumulate stale duplicates.
    ///
    /// `created_at_ms` is **never** touched by this method —
    /// `INSERT OR REPLACE` would reset the column on the FTS side,
    /// so the implementation deliberately reads the existing
    /// timestamp out of `message_skeleton` and re-inserts it
    /// verbatim. The caller is responsible for re-indexing
    /// `search_fuzzy` separately (the fuzzy tokenizer lives at
    /// [`crate::search::fuzzy_search::FuzzySearchEngine`] which
    /// already knows how to upsert idempotently).
    pub fn rehydrate_message_body(
        &self,
        message_id: &str,
        text_content: &str,
        new_body_state: BodyState,
    ) -> DbResult<()> {
        // 0) Pre-fetch the skeleton row so we have the
        //    conversation_id / sender_id / created_at_ms triple
        //    needed by the `search_fts` upsert. A missing skeleton
        //    is an error — rehydration of an unknown message would
        //    silently succeed otherwise.
        let row = self.conn.query_row(
            "SELECT conversation_id, sender_id, created_at_ms
               FROM message_skeleton
              WHERE message_id = ?1",
            params![message_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        );
        let (conversation_id, sender_id, created_at_ms) = match row {
            Ok(t) => t,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(DbError::InvalidState(format!(
                    "rehydrate_message_body: no message_skeleton row for {message_id}"
                )));
            }
            Err(e) => return Err(DbError::from(e)),
        };

        self.conn
            .execute_batch("SAVEPOINT rehydrate_body;")
            .map_err(DbError::from)?;
        let result: DbResult<()> = (|| {
            // 1) UPSERT message_body. We can't use
            //    `INSERT OR REPLACE` because that would clear
            //    `detected_language` / `rich_meta` on rows that
            //    already have them set. The `ON CONFLICT DO UPDATE`
            //    form preserves those columns.
            self.conn.execute(
                "INSERT INTO message_body
                     (message_id, text_content, detected_language, rich_meta)
                 VALUES (?1, ?2, NULL, NULL)
                 ON CONFLICT(message_id) DO UPDATE SET
                     text_content = excluded.text_content",
                params![message_id, text_content],
            )?;
            // 2) Body-state transition.
            self.conn.execute(
                "UPDATE message_skeleton SET body_state = ?1 WHERE message_id = ?2",
                params![new_body_state.to_string(), message_id],
            )?;
            // 3) Refresh search_fts.
            self.conn.execute(
                "DELETE FROM search_fts WHERE message_id = ?1",
                params![message_id],
            )?;
            self.conn.execute(
                "INSERT INTO search_fts(
                    message_id, conversation_id, sender_id,
                    created_at_ms, text_content
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    message_id,
                    conversation_id,
                    sender_id,
                    created_at_ms,
                    text_content
                ],
            )?;
            Ok(())
        })();
        match &result {
            Ok(_) => self
                .conn
                .execute_batch("RELEASE SAVEPOINT rehydrate_body;")
                .map_err(DbError::from)?,
            Err(_) => self
                .conn
                .execute_batch(
                    "ROLLBACK TO SAVEPOINT rehydrate_body;\nRELEASE SAVEPOINT rehydrate_body;",
                )
                .map_err(DbError::from)?,
        }
        result
    }

    /// Transition the `archive_state` of every message in
    /// `message_ids` to `new_state`.
    ///
    /// The transition is validated through
    /// [`ArchiveState::try_transition`] for every row before any
    /// `UPDATE` runs — an illegal predecessor on any single row
    /// rejects the whole batch with [`DbError::InvalidState`] and
    /// touches nothing. Returns the number of rows actually
    /// updated (rows whose `message_id` was not present are
    /// silently skipped).
    pub fn update_archive_state(
        &self,
        message_ids: &[String],
        new_state: ArchiveState,
    ) -> DbResult<usize> {
        update_archive_state(&self.conn, message_ids, new_state)
    }

    /// Read the typed `storage_backend` column for an
    /// `archive_segment_map` row.
    ///
    /// Returns `Ok(None)` when the segment id is unknown. The text
    /// stored on disk is normalized through
    /// [`StorageBackend::from_str`] so callers never have to
    /// re-validate the column's free-form `TEXT` value;
    /// non-canonical values surface as
    /// [`DbError::InvalidState`].
    pub fn get_segment_storage_backend(
        &self,
        segment_id: &str,
    ) -> DbResult<Option<StorageBackend>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT storage_backend FROM archive_segment_map WHERE segment_id = ?1",
                params![segment_id],
                |row| row.get(0),
            )
            .optional()?;
        match raw {
            None => Ok(None),
            Some(s) => s
                .parse::<StorageBackend>()
                .map(Some)
                .map_err(|e| DbError::InvalidState(e.to_string())),
        }
    }

    /// Update the `storage_backend` column for an
    /// `archive_segment_map` row. Returns the number of rows
    /// actually updated (0 when no segment matches).
    ///
    /// `docs/PROPOSAL.md §10.1` calls this out as the single point
    /// the orchestration layer flips a segment from the KChat
    /// backend to ZK Object Fabric — the manifest builder records
    /// the change in the next manifest, and the prefetch path
    /// dispatches by `storage_backend` on every read.
    pub fn update_segment_storage_backend(
        &self,
        segment_id: &str,
        new_backend: StorageBackend,
    ) -> DbResult<usize> {
        let rows = self.conn.execute(
            "UPDATE archive_segment_map SET storage_backend = ?1 WHERE segment_id = ?2",
            params![new_backend.as_str(), segment_id],
        )?;
        Ok(rows)
    }

    /// Insert a skeleton row pulled from a remote archive segment,
    /// **without overwriting** any pre-existing local skeleton for
    /// `message_id`.
    ///
    /// `docs/PROPOSAL.md §5.1` (skeleton-first rendering) — when
    /// the orchestration layer rehydrates a scroll-back bucket it
    /// merges the skeletons it pulls from the archive into the
    /// local store. Existing local rows always win because they
    /// carry richer state (e.g. a freshly-cached body, or media
    /// progress) than the archive-only stub.
    ///
    /// Returns `true` when a brand-new row was actually inserted,
    /// `false` when the `message_id` was already present and the
    /// archive copy was discarded.
    pub fn upsert_skeleton_from_archive(&self, skel: &MessageSkeleton) -> DbResult<bool> {
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO message_skeleton (
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
        Ok(rows == 1)
    }

    /// Insert a row into `media_asset`.
    ///
    /// `docs/PROPOSAL.md §3.2` (`media_asset` columns) and §5.7
    /// (tiered media storage) define the row's shape. The caller is
    /// responsible for funneling the
    /// [`crate::media::processor::MediaProcessResult::descriptor`]
    /// together with the chosen
    /// [`crate::media::sinks::MediaBlobReference`] into a
    /// [`MediaAsset`] before insert.
    pub fn insert_media_asset(&self, asset: &MediaAsset) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO media_asset(
                asset_id, message_id, mime_type, bytes_total, bytes_local,
                media_state, wrapped_k_asset, chunk_count, merkle_root, blob_id,
                storage_sink
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                asset.asset_id,
                asset.message_id,
                asset.mime_type,
                asset.bytes_total,
                asset.bytes_local,
                asset.media_state.to_string(),
                asset.wrapped_k_asset,
                asset.chunk_count,
                asset.merkle_root,
                asset.blob_id,
                asset.storage_sink,
            ],
        )?;
        Ok(())
    }

    /// Fetch a single `media_asset` row by `asset_id`.
    pub fn get_media_asset(&self, asset_id: &str) -> DbResult<Option<MediaAsset>> {
        self.conn
            .query_row(
                "SELECT asset_id, message_id, mime_type, bytes_total, bytes_local,
                        media_state, wrapped_k_asset, chunk_count, merkle_root, blob_id,
                        storage_sink
                   FROM media_asset
                  WHERE asset_id = ?1",
                params![asset_id],
                |row| {
                    let media_state: String = row.get(5)?;
                    let media_state = media_state.parse::<MediaState>().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                        )
                    })?;
                    Ok(MediaAsset {
                        asset_id: row.get(0)?,
                        message_id: row.get(1)?,
                        mime_type: row.get(2)?,
                        bytes_total: row.get(3)?,
                        bytes_local: row.get(4)?,
                        media_state,
                        wrapped_k_asset: row.get(6)?,
                        chunk_count: row.get(7)?,
                        merkle_root: row.get(8)?,
                        blob_id: row.get(9)?,
                        storage_sink: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(DbError::from)
    }

    /// Lookup the `media_asset` row attached to `message_id`, if
    /// any.
    ///
    /// Mirrors [`Self::get_media_asset`] but keys on the owning
    /// `message_id` rather than the `asset_id`. The hydration path
    /// (`docs/PROPOSAL.md §5.2` — lazy media rehydration on tap)
    /// pulls the asset row through this helper so the caller can
    /// inspect [`MediaState`] before deciding whether to fetch the
    /// blob.
    pub fn get_media_asset_by_message(&self, message_id: &str) -> DbResult<Option<MediaAsset>> {
        self.conn
            .query_row(
                "SELECT asset_id, message_id, mime_type, bytes_total, bytes_local,
                        media_state, wrapped_k_asset, chunk_count, merkle_root, blob_id,
                        storage_sink
                   FROM media_asset
                  WHERE message_id = ?1
                  LIMIT 1",
                params![message_id],
                |row| {
                    let media_state: String = row.get(5)?;
                    let media_state = media_state.parse::<MediaState>().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                        )
                    })?;
                    Ok(MediaAsset {
                        asset_id: row.get(0)?,
                        message_id: row.get(1)?,
                        mime_type: row.get(2)?,
                        bytes_total: row.get(3)?,
                        bytes_local: row.get(4)?,
                        media_state,
                        wrapped_k_asset: row.get(6)?,
                        chunk_count: row.get(7)?,
                        merkle_root: row.get(8)?,
                        blob_id: row.get(9)?,
                        storage_sink: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(DbError::from)
    }

    /// List every `media_asset` row attached to `message_id`,
    /// ordered by `asset_id` for deterministic iteration.
    ///
    /// Companion to [`Self::get_media_asset_by_message`], which
    /// returns at most one row. The delete path
    /// (`MessagePersister::delete_inner_tx`) calls this to emit one
    /// `BackupEventType::MediaDeleted` event per attached asset on
    /// multi-asset messages — `MessageDeleted` already covers the
    /// compaction-side filter, but explicit per-asset tombstones
    /// keep the backup taxonomy aligned with
    /// [`crate::backup::event_journal::BackupEventType::MediaDeleted`].
    pub fn list_media_assets_by_message(&self, message_id: &str) -> DbResult<Vec<MediaAsset>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT asset_id, message_id, mime_type, bytes_total, bytes_local,
                        media_state, wrapped_k_asset, chunk_count, merkle_root, blob_id,
                        storage_sink
                   FROM media_asset
                  WHERE message_id = ?1
                  ORDER BY asset_id",
            )
            .map_err(DbError::from)?;
        let rows = stmt
            .query_map(params![message_id], |row| {
                let media_state: String = row.get(5)?;
                let media_state = media_state.parse::<MediaState>().map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                    )
                })?;
                Ok(MediaAsset {
                    asset_id: row.get(0)?,
                    message_id: row.get(1)?,
                    mime_type: row.get(2)?,
                    bytes_total: row.get(3)?,
                    bytes_local: row.get(4)?,
                    media_state,
                    wrapped_k_asset: row.get(6)?,
                    chunk_count: row.get(7)?,
                    merkle_root: row.get(8)?,
                    blob_id: row.get(9)?,
                    storage_sink: row.get(10)?,
                })
            })
            .map_err(DbError::from)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(DbError::from)?);
        }
        Ok(out)
    }

    /// Update `media_asset.media_state` for `asset_id`. Returns the
    /// number of rows updated (0 when no asset matches).
    ///
    /// Mirrors [`Self::update_body_state`] but for the media
    /// lifecycle state machine in
    /// [`crate::local_store::state_machines::MediaState`]
    /// (`docs/ARCHITECTURE.md §5`). Higher-level callers should go
    /// through [`crate::media::processor::transition_media_state`]
    /// instead — that helper enforces the legal-transitions matrix
    /// before reaching the SQL UPDATE.
    pub fn update_media_state(&self, asset_id: &str, new_state: MediaState) -> DbResult<usize> {
        let rows = self.conn.execute(
            "UPDATE media_asset SET media_state = ?1 WHERE asset_id = ?2",
            params![new_state.to_string(), asset_id],
        )?;
        Ok(rows)
    }

    // ----------------------------------------------------------------
    // media_search_index helpers — Phase 6, Task 4
    // ----------------------------------------------------------------

    /// Insert one row into the `media_search_index` table.
    ///
    /// `kind` is the discriminator on the table (`"ocr"`,
    /// `"caption"`, `"transcript"`, `"tag"`); see
    /// [`crate::local_store::schema::SCHEMA_SQL`]. `language`
    /// is the BCP-47 tag the recognizer reported (when one was
    /// reported); `confidence` is in `[0.0, 1.0]`.
    ///
    /// The PK is `(asset_id, kind, text)`, so re-inserting the
    /// same recognized text for the same asset is a no-op
    /// (`INSERT OR IGNORE`). The OCR fan-out is best-effort —
    /// duplicate hits across re-runs should not error.
    pub fn insert_media_search_index(
        &self,
        asset_id: &str,
        kind: &str,
        text: &str,
        language: Option<&str>,
        confidence: Option<f32>,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO media_search_index(asset_id, kind, text, language, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![asset_id, kind, text, language, confidence],
        )?;
        Ok(())
    }

    /// Search `media_search_index` rows whose `text` contains
    /// `query` (case-insensitive `LIKE`).
    ///
    /// `kind == Some(_)` restricts the search to one
    /// discriminator (e.g. only OCR hits, only transcripts);
    /// `None` returns rows from every discriminator.
    ///
    /// `query` is treated as a literal substring: SQL `LIKE`
    /// metacharacters (`\`, `%`, `_`) inside `query` are escaped
    /// via [`escape_like_pattern`] and the prepared statement
    /// uses `ESCAPE '\'`, so a query of `"100%"` matches the
    /// literal three-character substring `100%` instead of being
    /// interpreted as `100<wildcard>`.
    ///
    /// Returns rows in unspecified order — the caller is
    /// expected to merge media hits into the master ranking
    /// pipeline (`docs/PROPOSAL.md §7.5` ranking formula),
    /// which applies its own ordering.
    pub fn search_media_index(
        &self,
        query: &str,
        kind: Option<&str>,
    ) -> DbResult<Vec<MediaSearchResult>> {
        let needle = format!("%{}%", escape_like_pattern(query));
        let rows: Vec<MediaSearchResult> = match kind {
            Some(k) => {
                let mut stmt = self.conn.prepare(
                    "SELECT asset_id, kind, text, language, confidence
                       FROM media_search_index
                      WHERE kind = ?1 AND text LIKE ?2 ESCAPE '\\' COLLATE NOCASE",
                )?;
                let it = stmt.query_map(params![k, needle], row_to_media_search_result)?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let mut stmt = self.conn.prepare(
                    "SELECT asset_id, kind, text, language, confidence
                       FROM media_search_index
                      WHERE text LIKE ?1 ESCAPE '\\' COLLATE NOCASE",
                )?;
                let it = stmt.query_map(params![needle], row_to_media_search_result)?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        Ok(rows)
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

    /// Remove the `search_vector` row for `message_id`. Idempotent —
    /// a missing row is not an error.
    ///
    /// The Phase 6 ingest path writes embeddings to `search_vector`
    /// via the cross-pipeline embedding cache. Per-message delete
    /// and edit paths must invoke this helper alongside
    /// [`Self::delete_fts_row`] to keep semantic search consistent
    /// with FTS / fuzzy: otherwise a deleted message still surfaces
    /// as a [`crate::search::semantic_search::SemanticMatch`], and
    /// an edited message's vector row carries the pre-edit text's
    /// embedding.
    pub fn delete_vector_row(&self, message_id: &str) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM search_vector WHERE message_id = ?1",
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
    /// The update is guarded by `last_activity_ms <= ?2` so that
    /// out-of-order ingests (e.g. a transport page where messages
    /// are not sorted by `created_at_ms`, or sender clock skew)
    /// cannot regress an already-newer activity timestamp or
    /// downgrade `last_message_id` to an older message.
    ///
    /// Returns the number of rows updated. `0` means either the
    /// conversation does not exist, or the existing
    /// `last_activity_ms` is already strictly newer than
    /// `activity_ms` and the call was a no-op.
    pub fn update_conversation_last_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        activity_ms: i64,
    ) -> DbResult<usize> {
        let n = self.conn.execute(
            "UPDATE conversation
                SET last_message_id = ?1, last_activity_ms = ?2
              WHERE conversation_id = ?3
                AND last_activity_ms <= ?2",
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

    /// Return the messages in `conversation_id` joined against
    /// `message_body`, ordered by `created_at_ms DESC`. `before_ms`,
    /// when `Some`, restricts the page to messages with
    /// `created_at_ms < before_ms`. `limit` caps the returned page.
    ///
    /// Each [`TimelineRow`] is a flattened skeleton + optional
    /// body-text shape so a chat-list UI can render the full
    /// timeline without an extra round-trip per message.
    pub fn get_timeline(
        &self,
        conversation_id: &str,
        before_ms: Option<i64>,
        limit: usize,
    ) -> DbResult<Vec<TimelineRow>> {
        // The query mirrors get_message_with_body's LEFT JOIN so a
        // dropped message_body row (e.g. delete_for_everyone) still
        // returns the skeleton with text_content == None. The
        // `(created_at_ms < ?2 OR ?2 IS NULL)` pattern keeps the
        // single statement valid for both paginated and non-paginated
        // calls without a runtime branch on the SQL string.
        let mut stmt = self.conn.prepare(
            "SELECT s.message_id, s.conversation_id, s.sender_id,
                    s.created_at_ms, s.kind, s.body_state,
                    s.reply_to, s.edited_at_ms, s.deleted_at_ms,
                    b.text_content
               FROM message_skeleton s
               LEFT JOIN message_body b ON b.message_id = s.message_id
              WHERE s.conversation_id = ?1
                AND (s.created_at_ms < ?2 OR ?2 IS NULL)
              ORDER BY s.created_at_ms DESC
              LIMIT ?3",
        )?;
        let raw_rows = stmt
            .query_map(params![conversation_id, before_ms, limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut out = Vec::with_capacity(raw_rows.len());
        for (
            message_id,
            conversation_id_col,
            sender_id,
            created_at_ms,
            kind_str,
            body_state_str,
            reply_to,
            edited_at_ms,
            deleted_at_ms,
            text_content,
        ) in raw_rows
        {
            let kind = match kind_str.as_str() {
                "text" => MessageKind::Text,
                "media" => MessageKind::Media,
                "system" => MessageKind::System,
                other => return Err(DbError::InvalidState(format!("kind={other}"))),
            };
            let body_state: BodyState = body_state_str
                .parse()
                .map_err(|_| DbError::InvalidState(format!("body_state={body_state_str}")))?;
            out.push(TimelineRow {
                message_id,
                conversation_id: conversation_id_col,
                sender_id,
                created_at_ms,
                kind,
                body_state,
                text_content,
                reply_to,
                edited_at_ms,
                deleted_at_ms,
            });
        }
        Ok(out)
    }

    /// Delete a conversation along with every dependent row.
    ///
    /// The cascade order is dictated by the schema's foreign-key
    /// direction (`PRAGMA foreign_keys = ON` is active so the SQL
    /// engine itself rejects an out-of-order delete): per-message
    /// search artefacts and media-search-index rows must go before
    /// their parent rows, `media_asset` must go before
    /// `message_skeleton` (because `media_asset.message_id`
    /// references it), and `message_skeleton` must go before
    /// `conversation`.
    ///
    /// 1. `media_search_index` rows for every asset attached to a
    ///    message in the conversation. Must precede the
    ///    `media_asset` delete because of the
    ///    `media_search_index.asset_id REFERENCES media_asset(asset_id)`
    ///    FK.
    /// 2. `search_fuzzy` rows for every message in the conversation.
    /// 3. `search_fts` rows for every message in the conversation.
    /// 4. `search_vector` rows for every message in the conversation.
    ///    The table has no FK against `message_skeleton`, but the
    ///    rows are message-scoped data we never want to outlive the
    ///    skeleton.
    /// 5. `media_asset` rows for every message in the conversation.
    ///    Must precede the `message_skeleton` delete because of the
    ///    `media_asset.message_id REFERENCES message_skeleton(message_id)`
    ///    FK.
    /// 6. `message_body` rows for every message in the conversation.
    /// 7. `message_skeleton` rows for the conversation.
    /// 8. The `conversation` row itself.
    ///
    /// Everything runs inside a single `SAVEPOINT` so a failure mid-way
    /// rolls back to the pre-call state — matching the pattern used by
    /// [`crate::message::processor::MessagePersister`].
    ///
    /// Returns the number of `conversation` rows deleted (`0` when no
    /// row matched, `1` on a successful cascade). Callers that want to
    /// surface a missing-conversation error inspect the return value
    /// (see [`crate::core_impl::CoreImpl::delete_conversation`]).
    pub fn delete_conversation(&self, conversation_id: &str) -> DbResult<usize> {
        let conn = &self.conn;
        conn.execute_batch("SAVEPOINT delete_conversation;")?;
        let result = self.delete_conversation_inner(conversation_id);
        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE delete_conversation;")?;
            }
            Err(_) => {
                let _ = conn
                    .execute_batch("ROLLBACK TO delete_conversation; RELEASE delete_conversation;");
            }
        }
        result
    }

    fn delete_conversation_inner(&self, conversation_id: &str) -> DbResult<usize> {
        // media_search_index → media_asset → message_skeleton chains
        // through two FKs, so it has to drain top-down before any
        // skeleton delete runs.
        self.conn.execute(
            "DELETE FROM media_search_index
              WHERE asset_id IN (
                  SELECT asset_id FROM media_asset
                   WHERE message_id IN (
                       SELECT message_id FROM message_skeleton
                        WHERE conversation_id = ?1
                   )
              )",
            params![conversation_id],
        )?;
        self.conn.execute(
            "DELETE FROM search_fuzzy
              WHERE message_id IN (
                  SELECT message_id FROM message_skeleton WHERE conversation_id = ?1
              )",
            params![conversation_id],
        )?;
        self.conn.execute(
            "DELETE FROM search_fts
              WHERE message_id IN (
                  SELECT message_id FROM message_skeleton WHERE conversation_id = ?1
              )",
            params![conversation_id],
        )?;
        self.conn.execute(
            "DELETE FROM search_vector
              WHERE message_id IN (
                  SELECT message_id FROM message_skeleton WHERE conversation_id = ?1
              )",
            params![conversation_id],
        )?;
        self.conn.execute(
            "DELETE FROM media_asset
              WHERE message_id IN (
                  SELECT message_id FROM message_skeleton WHERE conversation_id = ?1
              )",
            params![conversation_id],
        )?;
        self.conn.execute(
            "DELETE FROM message_body
              WHERE message_id IN (
                  SELECT message_id FROM message_skeleton WHERE conversation_id = ?1
              )",
            params![conversation_id],
        )?;
        self.conn.execute(
            "DELETE FROM message_skeleton WHERE conversation_id = ?1",
            params![conversation_id],
        )?;
        let n = self.conn.execute(
            "DELETE FROM conversation WHERE conversation_id = ?1",
            params![conversation_id],
        )?;
        Ok(n)
    }

    /// Insert a row into `backup_event_journal`. The `event_seq`
    /// field is `AUTOINCREMENT` in the schema; the value provided
    /// here is honored if non-zero, otherwise the backend assigns
    /// one and the inserted row's id is returned via
    /// [`Connection::last_insert_rowid`] (mirroring `event_seq`).
    pub fn insert_backup_event(&self, entry: &BackupEventJournalEntry) -> DbResult<()> {
        if entry.event_seq == 0 {
            self.conn.execute(
                "INSERT INTO backup_event_journal
                    (event_type, conversation_id, message_id, payload, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    entry.event_type,
                    entry.conversation_id,
                    entry.message_id,
                    entry.payload,
                    entry.created_at_ms,
                ],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO backup_event_journal
                    (event_seq, event_type, conversation_id, message_id, payload, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    entry.event_seq,
                    entry.event_type,
                    entry.conversation_id,
                    entry.message_id,
                    entry.payload,
                    entry.created_at_ms,
                ],
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MediaSearchResult — Phase 6, Task 4
// ---------------------------------------------------------------------------

/// One row returned by [`LocalStoreDb::search_media_index`].
///
/// Mirrors the shape of `media_search_index` (see
/// [`crate::local_store::schema::SCHEMA_SQL`]): the OCR /
/// caption / transcript / tag pipeline writes into the same
/// table, so the returned rows are discriminated by `kind`.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaSearchResult {
    /// `media_asset.asset_id` for the row.
    pub asset_id: String,
    /// `'ocr' | 'caption' | 'transcript' | 'tag'`.
    pub kind: String,
    /// Recognized text.
    pub text: String,
    /// BCP-47 language tag, when the recognizer reported one.
    pub language: Option<String>,
    /// Per-row confidence, when the recognizer reported one.
    pub confidence: Option<f32>,
}

fn row_to_media_search_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<MediaSearchResult> {
    Ok(MediaSearchResult {
        asset_id: row.get(0)?,
        kind: row.get(1)?,
        text: row.get(2)?,
        language: row.get(3)?,
        confidence: row.get(4)?,
    })
}

/// Escape SQL `LIKE` metacharacters in `pattern` so the result
/// can be wrapped in `%…%` and bound to a `text LIKE ?
/// ESCAPE '\\'` clause, matching the substring literally.
///
/// SQL `LIKE` treats `%` as "any sequence of characters" and
/// `_` as "any single character". Without this escape, a query
/// of `"100%"` or `"file_name"` produces wildcard semantics
/// rather than literal substring matching. The escape character
/// itself (`\`) must be escaped first so that `\%` in the input
/// stays literal — otherwise it would collapse to `%` and
/// re-introduce the wildcard.
///
/// Used by [`LocalStoreDb::search_media_index`].
fn escape_like_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for ch in pattern.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Free functions over `&Connection`
// ---------------------------------------------------------------------------

/// `&Connection`-keyed sibling of
/// [`LocalStoreDb::update_archive_state`]. Exposed so the archive
/// orchestration layer can drive transitions inside an existing
/// SAVEPOINT without re-borrowing the [`LocalStoreDb`] wrapper.
///
/// The set of valid transitions is enforced through
/// [`ArchiveState::try_transition`]: the linear chain
/// `not_archived → archive_pending → archive_uploaded →
/// archive_verified → archive_compacted`. Skipping a state
/// (e.g. `not_archived → archive_verified`) returns
/// [`DbError::InvalidState`] and rolls back nothing because the
/// validation pass runs before any UPDATE.
pub fn update_archive_state(
    conn: &Connection,
    message_ids: &[String],
    new_state: ArchiveState,
) -> DbResult<usize> {
    if message_ids.is_empty() {
        return Ok(0);
    }
    // Materialise the IN-clause placeholders. Repeating `?,?,?,…`
    // is the simplest way that handles arbitrary batch sizes.
    let placeholders: Vec<&str> = message_ids.iter().map(|_| "?").collect();
    let in_list = placeholders.join(",");

    // 1) Validate every existing row's predecessor.
    let select_sql = format!(
        "SELECT message_id, archive_state FROM message_skeleton WHERE message_id IN ({in_list})",
    );
    let mut stmt = conn.prepare(&select_sql)?;
    let row_iter = stmt.query_map(rusqlite::params_from_iter(message_ids.iter()), |row| {
        let mid: String = row.get(0)?;
        let state_str: String = row.get(1)?;
        Ok((mid, state_str))
    })?;
    for row in row_iter {
        let (mid, state_str) = row?;
        let from = state_str
            .parse::<ArchiveState>()
            .map_err(|e| DbError::InvalidState(format!("{mid}: {e}")))?;
        ArchiveState::try_transition(from, new_state).map_err(|e| {
            DbError::InvalidState(format!(
                "{mid}: archive_state {from} → {new_state} rejected ({e})",
            ))
        })?;
    }
    drop(stmt);

    // 2) Apply.
    let update_sql =
        format!("UPDATE message_skeleton SET archive_state = ? WHERE message_id IN ({in_list})",);
    let mut update_params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(message_ids.len() + 1);
    let new_state_str = new_state.to_string();
    update_params.push(&new_state_str);
    for id in message_ids {
        update_params.push(id);
    }
    let updated = conn.execute(&update_sql, rusqlite::params_from_iter(update_params))?;
    Ok(updated)
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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

    fn seed_media_asset(db: &LocalStoreDb, message_id: &str, asset_id: &str) -> MediaAsset {
        let conv = Conversation {
            conversation_id: "c-media".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
            ..Default::default()
        };
        // Inserting the same conversation twice would violate the
        // PK; ignore the second-call error so callers can seed
        // multiple assets in one test.
        let _ = db.insert_conversation(&conv);
        let skel = MessageSkeleton {
            message_id: message_id.into(),
            conversation_id: "c-media".into(),
            sender_id: "s".into(),
            created_at_ms: 1,
            received_at_ms: 1,
            kind: MessageKind::Media,
            body_state: BodyState::LocalPlainAvailable,
            media_state: Some(MediaState::ThumbnailOnly),
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        let _ = db.insert_message_skeleton(&skel);
        let asset = MediaAsset {
            asset_id: asset_id.into(),
            message_id: message_id.into(),
            mime_type: "image/png".into(),
            bytes_total: 100,
            bytes_local: 100,
            media_state: MediaState::ThumbnailOnly,
            wrapped_k_asset: vec![0u8; 40],
            chunk_count: 1,
            merkle_root: vec![0u8; 32],
            blob_id: format!("blob-{asset_id}"),
            storage_sink: "kchat_backend".into(),
        };
        db.insert_media_asset(&asset).unwrap();
        asset
    }

    #[test]
    fn insert_and_get_media_asset_round_trip() {
        let db = fresh_db();
        let asset = seed_media_asset(&db, "m-media", "asset-1");
        let back = db.get_media_asset("asset-1").unwrap().unwrap();
        assert_eq!(back, asset);
    }

    #[test]
    fn get_media_asset_missing_returns_none() {
        let db = fresh_db();
        assert!(db.get_media_asset("never-seen").unwrap().is_none());
    }

    #[test]
    fn update_media_state_returns_rows_affected() {
        let db = fresh_db();
        seed_media_asset(&db, "m-media", "asset-state");
        let rows = db
            .update_media_state("asset-state", MediaState::OriginalLocal)
            .unwrap();
        assert_eq!(rows, 1);
        let back = db.get_media_asset("asset-state").unwrap().unwrap();
        assert_eq!(back.media_state, MediaState::OriginalLocal);

        let rows = db
            .update_media_state("never-seen", MediaState::Deleted)
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn insert_backup_event_autoincrements_seq() {
        let db = fresh_db();
        let entry = BackupEventJournalEntry {
            event_seq: 0,
            event_type: "message_received".into(),
            conversation_id: Some("conv-x".into()),
            message_id: Some("msg-y".into()),
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
            ..Default::default()
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
    // Phase-3: rehydrate_message_body — `docs/PROPOSAL.md §5.5`.
    // -----------------------------------------------------------------

    fn fts_row_text(db: &LocalStoreDb, message_id: &str) -> Option<String> {
        db.connection()
            .query_row(
                "SELECT text_content FROM search_fts WHERE message_id = ?1",
                params![message_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .unwrap()
    }

    #[test]
    fn rehydrate_updates_existing_body_in_place() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m1", "c", "old text");
        // Seed an FTS row to mirror the in-prod state.
        db.connection()
            .execute(
                "INSERT INTO search_fts(
                    message_id, conversation_id, sender_id,
                    created_at_ms, text_content
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params!["m1", "c", "user-1", 100i64, "old text"],
            )
            .unwrap();
        let before_skel = db.get_message_skeleton("m1").unwrap().unwrap();

        db.rehydrate_message_body("m1", "rehydrated body", BodyState::LocalPlainAvailable)
            .unwrap();

        let after_body = db.get_message_body("m1").unwrap().unwrap();
        assert_eq!(after_body.text_content.as_deref(), Some("rehydrated body"));
        let after_skel = db.get_message_skeleton("m1").unwrap().unwrap();
        // body_state advanced to local_plain_available …
        assert_eq!(after_skel.body_state, BodyState::LocalPlainAvailable);
        // … but the timeline-ordering columns are untouched.
        assert_eq!(after_skel.created_at_ms, before_skel.created_at_ms);
        assert_eq!(after_skel.received_at_ms, before_skel.received_at_ms);
        // search_fts row was refreshed to match.
        assert_eq!(fts_row_text(&db, "m1").as_deref(), Some("rehydrated body"));
    }

    #[test]
    fn rehydrate_inserts_body_for_evicted_message() {
        let db = fresh_db();
        // Seed a skeleton without a body row, mimicking a row that
        // has been evicted to the archive.
        let conversation = Conversation {
            conversation_id: "c".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
            ..Default::default()
        };
        db.insert_conversation(&conversation).unwrap();
        let skel = MessageSkeleton {
            message_id: "m2".into(),
            conversation_id: "c".into(),
            sender_id: "user-1".into(),
            created_at_ms: 1_700,
            received_at_ms: 1_710,
            kind: MessageKind::Text,
            body_state: BodyState::RemoteArchiveOnly,
            media_state: None,
            archive_state: ArchiveState::ArchiveVerified,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        db.insert_message_skeleton(&skel).unwrap();

        db.rehydrate_message_body("m2", "from archive", BodyState::LocalPlainAvailable)
            .unwrap();

        let body = db.get_message_body("m2").unwrap().expect("body inserted");
        assert_eq!(body.text_content.as_deref(), Some("from archive"));
        let after = db.get_message_skeleton("m2").unwrap().unwrap();
        assert_eq!(after.body_state, BodyState::LocalPlainAvailable);
        assert_eq!(after.created_at_ms, 1_700);
        // search_fts row created.
        assert_eq!(fts_row_text(&db, "m2").as_deref(), Some("from archive"));
    }

    #[test]
    fn rehydrate_preserves_detected_language_and_rich_meta() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m3", "c", "x");
        db.connection()
            .execute(
                "UPDATE message_body SET detected_language = ?1, rich_meta = ?2
                  WHERE message_id = ?3",
                params!["es", vec![1u8, 2, 3], "m3"],
            )
            .unwrap();

        db.rehydrate_message_body("m3", "rehydrated", BodyState::LocalPlainAvailable)
            .unwrap();

        let body = db.get_message_body("m3").unwrap().unwrap();
        assert_eq!(body.text_content.as_deref(), Some("rehydrated"));
        // Existing detected_language / rich_meta survive the upsert
        // — the rehydration path only refreshes text_content.
        assert_eq!(body.detected_language.as_deref(), Some("es"));
        assert_eq!(body.rich_meta, Some(vec![1u8, 2, 3]));
    }

    #[test]
    fn rehydrate_missing_skeleton_errors_without_writing_anything() {
        let db = fresh_db();
        // No skeleton row for "ghost".
        let err = db
            .rehydrate_message_body("ghost", "text", BodyState::LocalPlainAvailable)
            .expect_err("unknown message_id must error");
        match err {
            DbError::InvalidState(msg) => assert!(msg.contains("ghost"), "got {msg}"),
            other => panic!("expected InvalidState, got {other:?}"),
        }
        assert!(db.get_message_body("ghost").unwrap().is_none());
        assert!(fts_row_text(&db, "ghost").is_none());
    }

    #[test]
    fn rehydrate_does_not_change_timeline_order() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m4", "c", "old");
        // Use a fresh conversation so list_timeline only sees
        // these two rows.
        db.connection()
            .execute(
                "INSERT INTO message_skeleton(
                    message_id, conversation_id, sender_id,
                    created_at_ms, received_at_ms, kind, body_state,
                    media_state, archive_state, backup_state, reply_to,
                    edited_at_ms, deleted_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'text',
                           'remote_archive_only', NULL, 'archive_verified',
                           'not_backed_up', NULL, NULL, NULL)",
                params!["m5", "c", "user-1", 200i64, 210i64],
            )
            .unwrap();
        let before: Vec<i64> = db
            .connection()
            .prepare("SELECT created_at_ms FROM message_skeleton ORDER BY created_at_ms ASC")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        db.rehydrate_message_body("m5", "filled in", BodyState::LocalPlainAvailable)
            .unwrap();

        let after: Vec<i64> = db
            .connection()
            .prepare("SELECT created_at_ms FROM message_skeleton ORDER BY created_at_ms ASC")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(before, after, "rehydration must not reorder timeline");
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
            ..Default::default()
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

    #[test]
    fn update_conversation_last_message_does_not_regress_on_older_message() {
        // Simulates an out-of-order transport batch: the newer
        // message (ts = 3_000) is persisted first, then the older
        // one (ts = 1_000) arrives. The older arrival must not
        // pull `last_activity_ms` backwards or replace
        // `last_message_id`, otherwise `list_conversations`
        // ordering and the conversation preview would regress.
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1, false))
            .unwrap();

        let n = db
            .update_conversation_last_message("c-1", "m-newer", 3_000)
            .unwrap();
        assert_eq!(n, 1, "first (newer) update should land");

        let n = db
            .update_conversation_last_message("c-1", "m-older", 1_000)
            .unwrap();
        assert_eq!(n, 0, "older update must be a no-op");

        let row = db.get_conversation("c-1").unwrap().expect("conv");
        assert_eq!(
            row.last_message_id.as_deref(),
            Some("m-newer"),
            "last_message_id must not regress"
        );
        assert_eq!(
            row.last_activity_ms, 3_000,
            "last_activity_ms must not regress"
        );

        // An equal-timestamp re-insert (e.g. a duplicate replay
        // surfacing the same message under a different id) is
        // still allowed so callers can refresh the pointer.
        let n = db
            .update_conversation_last_message("c-1", "m-equal", 3_000)
            .unwrap();
        assert_eq!(n, 1, "equal-timestamp update is allowed");
        let row = db.get_conversation("c-1").unwrap().expect("conv");
        assert_eq!(row.last_message_id.as_deref(), Some("m-equal"));
        assert_eq!(row.last_activity_ms, 3_000);
    }

    // -----------------------------------------------------------------
    // get_timeline
    // -----------------------------------------------------------------

    #[test]
    fn get_timeline_returns_newest_first() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        seed_timeline_message(&db, "m-1", "c-1", 100, "first");
        seed_timeline_message(&db, "m-2", "c-1", 200, "second");
        seed_timeline_message(&db, "m-3", "c-1", 300, "third");

        let rows = db.get_timeline("c-1", None, 10).unwrap();
        let ids: Vec<&str> = rows.iter().map(|r| r.message_id.as_str()).collect();
        assert_eq!(ids, ["m-3", "m-2", "m-1"]);
        let texts: Vec<Option<&str>> = rows.iter().map(|r| r.text_content.as_deref()).collect();
        assert_eq!(texts, [Some("third"), Some("second"), Some("first")]);
    }

    #[test]
    fn get_timeline_pagination_with_before_ms() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        for (i, ts) in [100, 200, 300, 400, 500].iter().enumerate() {
            seed_timeline_message(&db, &format!("m-{i}"), "c-1", *ts, "x");
        }

        let page1 = db.get_timeline("c-1", None, 2).unwrap();
        let ids: Vec<&str> = page1.iter().map(|r| r.message_id.as_str()).collect();
        assert_eq!(ids, ["m-4", "m-3"]);

        let page2 = db.get_timeline("c-1", Some(400), 2).unwrap();
        let ids: Vec<&str> = page2.iter().map(|r| r.message_id.as_str()).collect();
        assert_eq!(ids, ["m-2", "m-1"]);

        let page3 = db.get_timeline("c-1", Some(200), 2).unwrap();
        let ids: Vec<&str> = page3.iter().map(|r| r.message_id.as_str()).collect();
        assert_eq!(ids, ["m-0"]);

        assert!(db.get_timeline("c-1", Some(100), 10).unwrap().is_empty());
    }

    #[test]
    fn get_timeline_respects_limit() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        for i in 0..5 {
            seed_timeline_message(&db, &format!("m-{i}"), "c-1", 100 + i as i64, "x");
        }
        assert_eq!(db.get_timeline("c-1", None, 0).unwrap().len(), 0);
        assert_eq!(db.get_timeline("c-1", None, 1).unwrap().len(), 1);
        assert_eq!(db.get_timeline("c-1", None, 5).unwrap().len(), 5);
        assert_eq!(db.get_timeline("c-1", None, 100).unwrap().len(), 5);
    }

    #[test]
    fn get_timeline_returns_empty_for_unknown_conversation() {
        let db = fresh_db();
        assert!(db
            .get_timeline("does-not-exist", None, 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn get_timeline_carries_skeleton_metadata_and_missing_body() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-1", 1_000, false))
            .unwrap();
        seed_timeline_message(&db, "m-1", "c-1", 100, "hello");
        // Drop the body row to simulate delete_for_everyone — the
        // skeleton must still surface, with text_content == None.
        db.delete_message_body("m-1").unwrap();

        let rows = db.get_timeline("c-1", None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.message_id, "m-1");
        assert_eq!(row.conversation_id, "c-1");
        assert_eq!(row.sender_id, "user-1");
        assert_eq!(row.kind, MessageKind::Text);
        assert_eq!(row.body_state, BodyState::LocalPlainAvailable);
        assert!(row.text_content.is_none(), "body row dropped");
        assert!(row.reply_to.is_none());
    }

    // -----------------------------------------------------------------
    // delete_conversation cascade
    // -----------------------------------------------------------------

    fn count_rows(db: &LocalStoreDb, table: &str, where_clause: &str) -> i64 {
        db.connection()
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE {where_clause}"),
                [],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn delete_conversation_cascades_to_every_dependent_row() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-doomed", 1_000, false))
            .unwrap();
        db.insert_conversation(&build_conv("c-keep", 1_000, false))
            .unwrap();
        seed_timeline_message(&db, "m-d-1", "c-doomed", 100, "alpha");
        seed_timeline_message(&db, "m-d-2", "c-doomed", 200, "beta");
        seed_timeline_message(&db, "m-keep", "c-keep", 300, "gamma");

        // Stage matching FTS5 + fuzzy + vector + media rows so the
        // cascade really has something to delete in every dependent
        // table. The media tables are exercised here even though
        // Phase-1 code paths do not yet insert into them, because the
        // FK constraints between media_search_index → media_asset →
        // message_skeleton would block a future delete the moment
        // Phase-2 media support lands.
        for (mid, conv, text) in [
            ("m-d-1", "c-doomed", "alpha"),
            ("m-d-2", "c-doomed", "beta"),
            ("m-keep", "c-keep", "gamma"),
        ] {
            db.connection()
                .execute(
                    "INSERT INTO search_fts(
                        message_id, conversation_id, sender_id,
                        created_at_ms, text_content
                     ) VALUES (?1, ?2, 'user-1', 100, ?3)",
                    params![mid, conv, text],
                )
                .unwrap();
            db.connection()
                .execute(
                    "INSERT INTO search_fuzzy(token, script, message_id)
                     VALUES (?1, 'Latn', ?2)",
                    params![text, mid],
                )
                .unwrap();
            db.connection()
                .execute(
                    "INSERT INTO search_vector(message_id, embedding, model_version)
                     VALUES (?1, X'0102', 'test-v1')",
                    params![mid],
                )
                .unwrap();
            let asset_id = format!("asset-{mid}");
            db.connection()
                .execute(
                    "INSERT INTO media_asset(
                        asset_id, message_id, mime_type, bytes_total, bytes_local,
                        media_state, wrapped_k_asset, chunk_count, merkle_root, blob_id,
                        storage_sink
                     ) VALUES (?1, ?2, 'image/png', 4, 4, 'local', X'00', 1, X'00', 'blob-x',
                               'kchat_backend')",
                    params![asset_id, mid],
                )
                .unwrap();
            db.connection()
                .execute(
                    "INSERT INTO media_search_index(asset_id, kind, text)
                     VALUES (?1, 'ocr', ?2)",
                    params![asset_id, text],
                )
                .unwrap();
        }

        let n = db.delete_conversation("c-doomed").unwrap();
        assert_eq!(n, 1, "exactly one conversation row removed");

        // Doomed conversation: every dependent row gone, including
        // media_asset / media_search_index / search_vector which had
        // no explicit cleanup in the original cascade.
        assert_eq!(
            count_rows(&db, "conversation", "conversation_id = 'c-doomed'"),
            0
        );
        assert_eq!(
            count_rows(&db, "message_skeleton", "conversation_id = 'c-doomed'"),
            0
        );
        assert_eq!(
            count_rows(&db, "message_body", "message_id LIKE 'm-d-%'"),
            0
        );
        assert_eq!(
            count_rows(&db, "search_fts", "conversation_id = 'c-doomed'"),
            0
        );
        assert_eq!(
            count_rows(&db, "search_fuzzy", "message_id LIKE 'm-d-%'"),
            0
        );
        assert_eq!(
            count_rows(&db, "search_vector", "message_id LIKE 'm-d-%'"),
            0
        );
        assert_eq!(count_rows(&db, "media_asset", "message_id LIKE 'm-d-%'"), 0);
        assert_eq!(
            count_rows(&db, "media_search_index", "asset_id LIKE 'asset-m-d-%'"),
            0
        );

        // Sibling conversation untouched, including its media rows.
        assert_eq!(
            count_rows(&db, "conversation", "conversation_id = 'c-keep'"),
            1
        );
        assert_eq!(
            count_rows(&db, "message_skeleton", "message_id = 'm-keep'"),
            1
        );
        assert_eq!(count_rows(&db, "message_body", "message_id = 'm-keep'"), 1);
        assert_eq!(count_rows(&db, "search_fts", "message_id = 'm-keep'"), 1);
        assert_eq!(count_rows(&db, "search_fuzzy", "message_id = 'm-keep'"), 1);
        assert_eq!(count_rows(&db, "search_vector", "message_id = 'm-keep'"), 1);
        assert_eq!(count_rows(&db, "media_asset", "message_id = 'm-keep'"), 1);
        assert_eq!(
            count_rows(&db, "media_search_index", "asset_id = 'asset-m-keep'"),
            1
        );
    }

    #[test]
    fn delete_conversation_returns_zero_for_missing_id() {
        let db = fresh_db();
        let n = db.delete_conversation("does-not-exist").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn delete_conversation_on_empty_conversation_just_removes_the_row() {
        let db = fresh_db();
        db.insert_conversation(&build_conv("c-empty", 1_000, false))
            .unwrap();
        let n = db.delete_conversation("c-empty").unwrap();
        assert_eq!(n, 1);
        assert!(db.get_conversation("c-empty").unwrap().is_none());
    }

    // ---------------------------------------------------------------
    // update_archive_state — Task 6
    // ---------------------------------------------------------------

    fn read_archive_state(db: &LocalStoreDb, mid: &str) -> ArchiveState {
        db.get_message_skeleton(mid)
            .unwrap()
            .expect("skeleton")
            .archive_state
    }

    #[test]
    fn archive_state_transitions_through_lifecycle() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m1", "c1", "x");

        // not_archived → archive_pending
        let n = db
            .update_archive_state(&["m1".into()], ArchiveState::ArchivePending)
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(read_archive_state(&db, "m1"), ArchiveState::ArchivePending);

        // archive_pending → archive_uploaded
        db.update_archive_state(&["m1".into()], ArchiveState::ArchiveUploaded)
            .unwrap();
        assert_eq!(read_archive_state(&db, "m1"), ArchiveState::ArchiveUploaded);

        // archive_uploaded → archive_verified
        db.update_archive_state(&["m1".into()], ArchiveState::ArchiveVerified)
            .unwrap();
        assert_eq!(read_archive_state(&db, "m1"), ArchiveState::ArchiveVerified);
    }

    #[test]
    fn invalid_archive_transition_rejected() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m1", "c1", "x");
        // Skipping straight from not_archived → archive_verified
        // is illegal.
        let err = db
            .update_archive_state(&["m1".into()], ArchiveState::ArchiveVerified)
            .unwrap_err();
        assert!(matches!(err, DbError::InvalidState(_)), "got {err:?}");
        // The row must be untouched.
        assert_eq!(read_archive_state(&db, "m1"), ArchiveState::NotArchived);
    }

    #[test]
    fn batch_update_archive_state() {
        let db = fresh_db();
        // `seed_skeleton_with_body` re-inserts the conversation
        // every call, so each message rides its own conversation
        // row to avoid the UNIQUE constraint on
        // conversation.conversation_id.
        seed_skeleton_with_body(&db, "m1", "c-batch-1", "x");
        seed_skeleton_with_body(&db, "m2", "c-batch-2", "y");
        seed_skeleton_with_body(&db, "m3", "c-batch-3", "z");
        let ids = vec!["m1".into(), "m2".into(), "m3".into()];
        let n = db
            .update_archive_state(&ids, ArchiveState::ArchivePending)
            .unwrap();
        assert_eq!(n, 3);
        for mid in ["m1", "m2", "m3"] {
            assert_eq!(read_archive_state(&db, mid), ArchiveState::ArchivePending);
        }
    }

    fn seed_segment_row(db: &LocalStoreDb, segment_id: &str, storage_backend: &str) {
        db.connection()
            .execute(
                "INSERT INTO archive_segment_map(
                    segment_id, conversation_id, time_bucket, segment_type,
                    blob_id, storage_backend, merkle_root, state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    segment_id,
                    "c-seg",
                    "2026-05",
                    "message_delta",
                    format!("blob-{segment_id}"),
                    storage_backend,
                    vec![0u8; 32],
                    "archive_uploaded",
                ],
            )
            .unwrap();
    }

    #[test]
    fn get_segment_storage_backend_round_trip() {
        let db = fresh_db();
        seed_segment_row(&db, "seg-kchat", "kchat_backend");
        seed_segment_row(&db, "seg-zkof", "zk_object_fabric");
        assert_eq!(
            db.get_segment_storage_backend("seg-kchat").unwrap(),
            Some(StorageBackend::KChatBackend)
        );
        assert_eq!(
            db.get_segment_storage_backend("seg-zkof").unwrap(),
            Some(StorageBackend::ZkObjectFabric)
        );
    }

    #[test]
    fn get_segment_storage_backend_missing_returns_none() {
        let db = fresh_db();
        assert!(db
            .get_segment_storage_backend("never-seen")
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_segment_storage_backend_default_is_kchat_backend() {
        let db = fresh_db();
        // Insert a row without specifying storage_backend so the
        // schema default kicks in.
        db.connection()
            .execute(
                "INSERT INTO archive_segment_map(
                    segment_id, conversation_id, time_bucket, segment_type,
                    blob_id, merkle_root, state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    "seg-default",
                    "c-seg",
                    "2026-05",
                    "message_delta",
                    "blob-default",
                    vec![0u8; 32],
                    "archive_uploaded",
                ],
            )
            .unwrap();
        assert_eq!(
            db.get_segment_storage_backend("seg-default").unwrap(),
            Some(StorageBackend::KChatBackend)
        );
    }

    #[test]
    fn update_segment_storage_backend_returns_rows_affected() {
        let db = fresh_db();
        seed_segment_row(&db, "seg-flip", "kchat_backend");
        let n = db
            .update_segment_storage_backend("seg-flip", StorageBackend::ZkObjectFabric)
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            db.get_segment_storage_backend("seg-flip").unwrap(),
            Some(StorageBackend::ZkObjectFabric)
        );
        let n = db
            .update_segment_storage_backend("never-seen", StorageBackend::ZkObjectFabric)
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn get_segment_storage_backend_rejects_unknown_value() {
        let db = fresh_db();
        seed_segment_row(&db, "seg-bad", "frobnicator_v2");
        let err = db.get_segment_storage_backend("seg-bad").unwrap_err();
        assert!(matches!(err, DbError::InvalidState(_)), "got {err:?}");
    }

    // ----------------------------------------------------------------
    // upsert_skeleton_from_archive (Task 4 — `docs/PROPOSAL.md §5.1`)
    // ----------------------------------------------------------------

    fn archive_skeleton(mid: &str, conv: &str) -> MessageSkeleton {
        MessageSkeleton {
            message_id: mid.into(),
            conversation_id: conv.into(),
            sender_id: "remote-sender".into(),
            created_at_ms: 1_700_000_000_000,
            received_at_ms: 1_700_000_000_500,
            kind: MessageKind::Text,
            body_state: BodyState::RemoteArchiveOnly,
            media_state: None,
            archive_state: ArchiveState::ArchiveUploaded,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        }
    }

    #[test]
    fn upsert_skeleton_from_archive_inserts_new_row() {
        let db = fresh_db();
        let conv = Conversation {
            conversation_id: "c-arch".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 0,
            ..Default::default()
        };
        db.insert_conversation(&conv).unwrap();
        let skel = archive_skeleton("m-arch", "c-arch");

        assert!(
            db.upsert_skeleton_from_archive(&skel).unwrap(),
            "first insert returns true"
        );
        let stored = db.get_message_skeleton("m-arch").unwrap().unwrap();
        assert_eq!(stored.body_state, BodyState::RemoteArchiveOnly);
        assert_eq!(stored.sender_id, "remote-sender");
    }

    #[test]
    fn upsert_skeleton_from_archive_does_not_overwrite_existing_row() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m1", "c-keep", "local body");

        let mut archive_view = archive_skeleton("m1", "c-keep");
        archive_view.sender_id = "should-not-replace".into();
        let inserted = db.upsert_skeleton_from_archive(&archive_view).unwrap();
        assert!(!inserted, "INSERT OR IGNORE must skip existing rows");

        let stored = db.get_message_skeleton("m1").unwrap().unwrap();
        assert_eq!(
            stored.body_state,
            BodyState::LocalPlainAvailable,
            "local skeleton wins"
        );
        assert_eq!(stored.sender_id, "user-1");
    }

    // ----------------------------------------------------------------
    // get_media_asset_by_message (Task 5 — `docs/PROPOSAL.md §5.2`)
    // ----------------------------------------------------------------

    #[test]
    fn get_media_asset_by_message_returns_attached_asset() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m-media", "c-media", "caption");
        let asset = MediaAsset {
            asset_id: "asset-1".into(),
            message_id: "m-media".into(),
            mime_type: "image/jpeg".into(),
            bytes_total: 1024,
            bytes_local: 512,
            media_state: MediaState::ThumbnailOnly,
            wrapped_k_asset: vec![0xFE; 40],
            chunk_count: 4,
            merkle_root: vec![0xAB; 32],
            blob_id: "blob-1".into(),
            storage_sink: "kchat_backend".into(),
        };
        db.insert_media_asset(&asset).unwrap();

        let got = db
            .get_media_asset_by_message("m-media")
            .unwrap()
            .expect("asset row");
        assert_eq!(got.asset_id, "asset-1");
        assert_eq!(got.media_state, MediaState::ThumbnailOnly);
    }

    #[test]
    fn get_media_asset_by_message_returns_none_when_no_attachment() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m-text", "c-text", "no media");
        assert!(db.get_media_asset_by_message("m-text").unwrap().is_none());
        assert!(db
            .get_media_asset_by_message("m-does-not-exist")
            .unwrap()
            .is_none());
    }

    // ----------------------------------------------------------------
    // list_media_assets_by_message — multi-asset media support for
    // `MessagePersister::delete_inner_tx` (Phase 4 backup taxonomy).
    // ----------------------------------------------------------------

    #[test]
    fn list_media_assets_by_message_returns_every_asset_for_message() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m-multi", "c-multi", "caption");
        let make_asset = |asset_id: &str, blob_id: &str| MediaAsset {
            asset_id: asset_id.into(),
            message_id: "m-multi".into(),
            mime_type: "image/jpeg".into(),
            bytes_total: 1024,
            bytes_local: 512,
            media_state: MediaState::ThumbnailOnly,
            wrapped_k_asset: vec![0xFE; 40],
            chunk_count: 4,
            merkle_root: vec![0xAB; 32],
            blob_id: blob_id.into(),
            storage_sink: "kchat_backend".into(),
        };
        db.insert_media_asset(&make_asset("asset-c", "blob-c"))
            .unwrap();
        db.insert_media_asset(&make_asset("asset-a", "blob-a"))
            .unwrap();
        db.insert_media_asset(&make_asset("asset-b", "blob-b"))
            .unwrap();

        let assets = db.list_media_assets_by_message("m-multi").unwrap();
        assert_eq!(assets.len(), 3);
        // Deterministic ORDER BY asset_id.
        assert_eq!(assets[0].asset_id, "asset-a");
        assert_eq!(assets[1].asset_id, "asset-b");
        assert_eq!(assets[2].asset_id, "asset-c");
    }

    #[test]
    fn list_media_assets_by_message_returns_empty_when_no_attachment() {
        let db = fresh_db();
        seed_skeleton_with_body(&db, "m-text", "c-text", "no media");
        assert!(db
            .list_media_assets_by_message("m-text")
            .unwrap()
            .is_empty());
        assert!(db
            .list_media_assets_by_message("m-does-not-exist")
            .unwrap()
            .is_empty());
    }

    // ----- Phase 6, Task 4: media_search_index helpers --------------

    fn seed_media_asset_for_index(db: &LocalStoreDb, mid: &str, conv: &str, asset_id: &str) {
        seed_skeleton_with_body(db, mid, conv, "ignored");
        let asset = MediaAsset {
            asset_id: asset_id.into(),
            message_id: mid.into(),
            mime_type: "image/jpeg".into(),
            bytes_total: 1024,
            bytes_local: 1024,
            media_state: MediaState::ThumbnailOnly,
            wrapped_k_asset: vec![0xAB; 40],
            chunk_count: 4,
            merkle_root: vec![0xCD; 32],
            blob_id: format!("blob-{asset_id}"),
            storage_sink: "kchat_backend".into(),
        };
        db.insert_media_asset(&asset).unwrap();
    }

    #[test]
    fn media_search_index_round_trip_with_kind_filter() {
        let db = fresh_db();
        seed_media_asset_for_index(&db, "m-1", "c-1", "asset-1");
        seed_media_asset_for_index(&db, "m-2", "c-2", "asset-2");

        db.insert_media_search_index("asset-1", "ocr", "Hello, world", Some("en"), Some(0.9))
            .unwrap();
        db.insert_media_search_index(
            "asset-2",
            "transcript",
            "hello there",
            Some("en"),
            Some(0.7),
        )
        .unwrap();

        let ocr_hits = db.search_media_index("hello", Some("ocr")).unwrap();
        assert_eq!(ocr_hits.len(), 1);
        assert_eq!(ocr_hits[0].asset_id, "asset-1");
        assert_eq!(ocr_hits[0].kind, "ocr");

        let any_kind = db.search_media_index("hello", None).unwrap();
        assert_eq!(any_kind.len(), 2);
    }

    #[test]
    fn media_search_index_insert_is_idempotent() {
        let db = fresh_db();
        seed_media_asset_for_index(&db, "m-1", "c-1", "asset-1");
        // Re-insert the same (asset_id, kind, text) PK twice — the
        // INSERT OR IGNORE codepath must absorb the duplicate.
        db.insert_media_search_index("asset-1", "ocr", "duplicate", None, None)
            .unwrap();
        db.insert_media_search_index("asset-1", "ocr", "duplicate", None, None)
            .unwrap();
        let hits = db.search_media_index("duplicate", None).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn media_search_index_query_is_case_insensitive() {
        let db = fresh_db();
        seed_media_asset_for_index(&db, "m-1", "c-1", "asset-1");
        db.insert_media_search_index("asset-1", "caption", "Sunset over Tokyo", Some("en"), None)
            .unwrap();
        let upper = db.search_media_index("TOKYO", None).unwrap();
        let lower = db.search_media_index("tokyo", None).unwrap();
        assert_eq!(upper.len(), 1);
        assert_eq!(lower.len(), 1);
        assert_eq!(upper[0].asset_id, "asset-1");
    }

    #[test]
    fn media_search_index_returns_empty_on_no_match() {
        let db = fresh_db();
        seed_media_asset_for_index(&db, "m-1", "c-1", "asset-1");
        db.insert_media_search_index("asset-1", "ocr", "anything", None, None)
            .unwrap();
        assert!(db
            .search_media_index("never appears", None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn media_search_index_treats_like_metacharacters_as_literal() {
        // A user query containing SQL `LIKE` metacharacters must
        // match the literal substring rather than be interpreted
        // as a wildcard. Without escaping, `%` would match "any
        // sequence" and `_` would match "any single character",
        // so a search for `"100%"` would also surface `"100"` and
        // a search for `"file_name"` would surface `"fileXname"`.
        let db = fresh_db();
        seed_media_asset_for_index(&db, "m-1", "c-1", "asset-1");
        seed_media_asset_for_index(&db, "m-2", "c-2", "asset-2");
        seed_media_asset_for_index(&db, "m-3", "c-3", "asset-3");
        seed_media_asset_for_index(&db, "m-4", "c-4", "asset-4");
        seed_media_asset_for_index(&db, "m-5", "c-5", "asset-5");

        // `%` set: literal `100%` should match, plain `100`
        // should not (and must not get pulled in via wildcard).
        db.insert_media_search_index("asset-1", "ocr", "battery 100% charged", None, None)
            .unwrap();
        db.insert_media_search_index("asset-2", "ocr", "battery 100 charged", None, None)
            .unwrap();
        let percent = db.search_media_index("100%", None).unwrap();
        assert_eq!(percent.len(), 1);
        assert_eq!(percent[0].asset_id, "asset-1");

        // `_` set: literal `file_name` should match,
        // `fileXname` (which `_` would match as a wildcard) must
        // not.
        db.insert_media_search_index("asset-3", "caption", "see file_name.txt", None, None)
            .unwrap();
        db.insert_media_search_index("asset-4", "caption", "see fileXname.txt", None, None)
            .unwrap();
        let underscore = db.search_media_index("file_name", None).unwrap();
        assert_eq!(underscore.len(), 1);
        assert_eq!(underscore[0].asset_id, "asset-3");

        // Backslash set: a literal backslash must round-trip.
        db.insert_media_search_index("asset-5", "ocr", "path C:\\Users\\foo", None, None)
            .unwrap();
        let backslash = db.search_media_index("C:\\Users", None).unwrap();
        assert_eq!(backslash.len(), 1);
        assert_eq!(backslash[0].asset_id, "asset-5");
    }

    #[test]
    fn escape_like_pattern_escapes_all_metacharacters() {
        // Each metacharacter (`\`, `%`, `_`) is prefixed with a
        // backslash; everything else passes through unchanged.
        // Backslash MUST be escaped first so `\%` in the input
        // does not collapse to `%` (a wildcard).
        assert_eq!(super::escape_like_pattern("plain"), "plain");
        assert_eq!(super::escape_like_pattern("100%"), "100\\%");
        assert_eq!(super::escape_like_pattern("a_b"), "a\\_b");
        assert_eq!(super::escape_like_pattern("\\"), "\\\\");
        assert_eq!(super::escape_like_pattern("a\\%b"), "a\\\\\\%b");
        // Multibyte / non-ASCII passes through unchanged.
        assert_eq!(super::escape_like_pattern("héllo世界"), "héllo世界");
    }
}
