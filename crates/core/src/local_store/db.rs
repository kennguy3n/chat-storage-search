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
use std::sync::{Condvar, Mutex};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use super::schema::{
    BackupEventJournalEntry, Conversation, MediaAsset, MessageBody, MessageKind, MessageSkeleton,
    StorageBackend, TimelineRow, LATEST_USER_VERSION, MIGRATIONS, SCHEMA_SQL,
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

    /// A precondition checked inside a transaction did not hold —
    /// e.g. a monotonic-cursor advance was passed a smaller value
    /// than the persisted one. Used by
    /// [`LocalStoreDb::atomic_append_segment_and_manifest`] to
    /// reject backwards cursor motion.
    #[error("invariant violated: {0}")]
    InvariantViolation(String),
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

/// Schema-introspection variant of [`fts5_icu_available`] suitable
/// for read-only connections.
///
/// The CREATE-VIRTUAL-TABLE probe used at writer-open time is not
/// usable here for two reasons:
///   1. `LocalStoreReader` opens with `PRAGMA query_only = 1`,
///      which makes the SQLite engine reject *any* mutating
///      statement — including `CREATE` for `temp.` tables.
///   2. The reader does not run migrations, so a fresh sniff
///      against the loaded `icu` extension would not match the
///      stored schema if the writer was opened on a build with
///      different tokenizer availability.
///
/// Instead, sniff the persisted `search_fts` `CREATE VIRTUAL
/// TABLE` SQL from `sqlite_master` and check whether the writer
/// stamped the schema with the ICU tokenizer
/// ([`crate::search::tokenizer::FTS5_TOKENIZE_ICU`]) or the
/// `unicode61` fallback
/// ([`crate::search::tokenizer::FTS5_TOKENIZE_UNICODE61`]).
///
/// Returns `false` on any SQLite error or when the table does
/// not yet exist — the conservative fallback. Search-engine call
/// sites already handle the unicode61 path safely.
fn probe_fts_icu_available(conn: &Connection) -> bool {
    let sql: rusqlite::Result<Option<String>> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'search_fts'",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map(|opt| opt.flatten());
    match sql {
        Ok(Some(sql)) => sql.contains("tokenize = 'icu'") || sql.contains("tokenize='icu'"),
        Ok(None) | Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// LocalStoreDb
// ---------------------------------------------------------------------------

/// How the [`LocalStoreDb`] writer is materialised on storage.
///
/// The variant is consulted only when the writer needs to seed
/// fresh connections (currently only the reader pool); the writer
/// itself uses the [`Connection`] it carries directly.
#[derive(Debug, Clone)]
enum WriterBacking {
    /// On-disk SQLCipher database at the given path. The reader
    /// pool opens additional connections to the same path.
    OnDisk(PathBuf),
    /// In-memory database identified by the given shared-cache
    /// URI (e.g. `file:kchat_mem_<uuid>?mode=memory&cache=shared`).
    /// As long as at least one connection is alive on the URI,
    /// the in-memory pages persist; closing every connection
    /// destroys the database. Used only by `open_in_memory`.
    InMemoryShared(String),
}

/// SQLCipher-backed local-store connection wrapper.
///
/// One instance maps 1:1 with the `kchat.db` file (or the
/// shared-cache in-memory database used by tests). Cloning is
/// intentionally not supported — [`Connection`] is not
/// `Send`-cheap and the writer is held inside `Mutex<_>` at the
/// core level so a single connection per core instance is the
/// intended shape.
#[derive(Debug)]
pub struct LocalStoreDb {
    conn: Connection,
    /// Backing-store identity: on-disk path or in-memory shared-
    /// cache URI. Carried so the writer can seed reader-pool
    /// connections against the same database without the caller
    /// having to plumb the path / URI through a second time.
    backing: WriterBacking,
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
            backing: WriterBacking::OnDisk(path),
            icu_available,
        })
    }

    /// Open an ephemeral in-memory database, suitable for tests.
    ///
    /// Gated behind the `test-support` feature (always available
    /// under `cfg(test)` for the crate's own unit tests). The
    /// in-memory SQLCipher handle holds nothing persistent, so a
    /// production caller that reached it would silently lose
    /// every write across process restarts; closing the symbol
    /// off at the linker layer prevents that class of misuse —
    /// the same rationale as
    /// [`crate::core_impl::CoreImpl::new_in_memory`]. See the
    /// `test-support` feature comment in
    /// `crates/core/Cargo.toml` for the broader policy.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_in_memory(key: &[u8; 32]) -> DbResult<Self> {
        // Use a `file:?mode=memory&cache=shared` URI so the reader
        // pool can attach additional connections to the same
        // in-memory database. A `:memory:` open (the SQLite
        // default) creates a *private* in-memory db that no
        // other connection can see, which would make
        // [`Self::open_reader_pool`] hand out empty connections.
        //
        // The URI is keyed by a fresh UUID per call so concurrent
        // tests don't collide on a common shared-cache namespace.
        // As long as at least one connection (the writer + each
        // pool reader) is alive, the in-memory pages persist;
        // dropping every connection destroys the database — same
        // lifetime semantics as a `:memory:` handle.
        let uri = format!(
            "file:kchat_mem_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4().simple()
        );
        let conn = Connection::open_with_flags(
            &uri,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )?;
        let icu_available = init_connection(&conn, key)?;
        Ok(Self {
            conn,
            backing: WriterBacking::InMemoryShared(uri),
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

    /// Resolved on-disk path. `None` for in-memory databases.
    pub fn path(&self) -> Option<&Path> {
        match &self.backing {
            WriterBacking::OnDisk(p) => Some(p.as_path()),
            WriterBacking::InMemoryShared(_) => None,
        }
    }

    /// Open a fresh [`LocalStoreReaderPool`] backed by the same
    /// SQLCipher database this writer is currently open against.
    ///
    /// `key` is the 32-byte `K_local_db` the readers will set via
    /// `PRAGMA key`; in production it's the same value the writer
    /// was opened with, but it is passed explicitly because the
    /// writer does not retain a copy. `capacity` is the number of
    /// reader connections to materialise — clamped to at least 1
    /// inside [`LocalStoreReaderPool::open`].
    ///
    /// For on-disk databases the readers open against the
    /// canonical `<data_dir>/kchat.db` path. For shared-cache
    /// in-memory databases (used by `cfg(test)` / `test-support`)
    /// the readers attach to the writer's URI; pooling works the
    /// same way, just with no on-disk persistence.
    pub fn open_reader_pool(
        &self,
        key: &[u8; 32],
        capacity: usize,
    ) -> DbResult<LocalStoreReaderPool> {
        match &self.backing {
            WriterBacking::OnDisk(path) => LocalStoreReaderPool::open(path, key, capacity),
            WriterBacking::InMemoryShared(uri) => {
                LocalStoreReaderPool::open_uri(uri, key, capacity)
            }
        }
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
        read_conversation(&self.conn, conversation_id)
    }

    /// List every conversation row, newest activity first.
    ///
    /// Pinned conversations come first (still ordered by activity)
    /// because the public KChatCore surface treats pinning as a
    /// recency-override flag.
    pub fn list_conversations(&self) -> DbResult<Vec<Conversation>> {
        read_list_conversations(&self.conn)
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
        read_list_conversations_by_column(&self.conn, "community_id", community_id)
    }

    /// List every conversation that belongs to `domain_id`.
    /// Phase 8 helper for [`crate::SearchTarget::Domain`].
    pub fn list_conversations_by_domain(&self, domain_id: &str) -> DbResult<Vec<Conversation>> {
        read_list_conversations_by_column(&self.conn, "domain_id", domain_id)
    }

    /// List every conversation that belongs to `tenant_id`.
    /// Phase 8 helper for [`crate::SearchTarget::Tenant`].
    pub fn list_conversations_by_tenant(&self, tenant_id: &str) -> DbResult<Vec<Conversation>> {
        read_list_conversations_by_column(&self.conn, "tenant_id", tenant_id)
    }

    /// List every conversation with the given `scope`. Phase 8
    /// helper for [`crate::SearchTarget::B2cAll`].
    pub fn list_conversations_by_scope(&self, scope: &str) -> DbResult<Vec<Conversation>> {
        read_list_conversations_by_column(&self.conn, "scope", scope)
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
        read_message_skeleton(&self.conn, message_id)
    }

    /// Fetch a message body by id, if present.
    pub fn get_message_body(&self, message_id: &str) -> DbResult<Option<MessageBody>> {
        read_message_body(&self.conn, message_id)
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

    /// Phase 7, batch-5 — list every `media_asset` row whose
    /// `storage_sink` matches the supplied tag, ordered by
    /// `asset_id` for deterministic iteration. Used by the
    /// cross-sink media migration planner
    /// (`crate::media::migration::plan_media_migration`).
    pub fn list_media_assets_by_storage_sink(
        &self,
        storage_sink: &str,
    ) -> DbResult<Vec<MediaAsset>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT asset_id, message_id, mime_type, bytes_total, bytes_local,
                        media_state, wrapped_k_asset, chunk_count, merkle_root, blob_id,
                        storage_sink
                   FROM media_asset
                  WHERE storage_sink = ?1
                  ORDER BY asset_id",
            )
            .map_err(DbError::from)?;
        let rows = stmt
            .query_map(params![storage_sink], |row| {
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

    /// Phase 7, batch-5 — update `media_asset.storage_sink` and
    /// `media_asset.blob_id` for `asset_id`. Returns the number
    /// of rows updated (0 when no asset matches). Used by the
    /// migration executor after a successful cross-sink upload.
    pub fn update_media_storage_sink(
        &self,
        asset_id: &str,
        new_sink: &str,
        new_blob_id: &str,
    ) -> DbResult<usize> {
        let rows = self.conn.execute(
            "UPDATE media_asset
                SET storage_sink = ?1, blob_id = ?2
              WHERE asset_id = ?3",
            params![new_sink, new_blob_id, asset_id],
        )?;
        Ok(rows)
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
        read_search_media_index(&self.conn, query, kind)
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
        read_conversation_messages(&self.conn, conversation_id, before_ms, limit)
    }

    /// Fetch a message skeleton plus its (optional) body in one go.
    /// Returns `Ok(None)` when the skeleton does not exist, or
    /// `Ok(Some((skel, None)))` when the skeleton exists but the
    /// body row has been dropped (e.g. `delete_for_everyone`).
    pub fn get_message_with_body(
        &self,
        message_id: &str,
    ) -> DbResult<Option<(MessageSkeleton, Option<MessageBody>)>> {
        read_message_with_body(&self.conn, message_id)
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
        read_timeline(&self.conn, conversation_id, before_ms, limit)
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
// Backup orchestration state (Phase 5 hardening — Task 2)
// ---------------------------------------------------------------------------

/// One row of the `backup_segment_ledger` table.
///
/// Mirrors the column shape declared in
/// [`crate::local_store::schema::MIGRATION_V2_SQL`]. The fields
/// are plain data — the orchestrator layer
/// ([`crate::core_impl::CoreImpl`]) wraps / unwraps `k_segment`
/// under `K_backup_root` to materialise the in-memory
/// `TrackedBackupSegment`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSegmentLedgerRow {
    /// Sealed segment id (UUID v7).
    pub segment_id: String,
    /// Mirror of `SegmentType` ("events", "message_delta", ...).
    pub segment_type: String,
    /// 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: Vec<u8>,
    /// AEAD ciphertext (zstd-compressed CBOR).
    pub ciphertext: Vec<u8>,
    /// 32-byte BLAKE3 over the plaintext payload.
    pub merkle_root: Vec<u8>,
    /// Number of events sealed in the segment.
    pub event_count: i64,
    /// Compaction tier ("daily" | "weekly" | "monthly").
    pub tier: String,
    /// Earliest event timestamp covered (ms epoch).
    pub min_event_ms: i64,
    /// Latest event timestamp covered (ms epoch).
    pub max_event_ms: i64,
    /// 40-byte AES-256-KW (RFC 3394) of `K_backup_segment(segment_id)`
    /// under `K_backup_root`.
    pub wrapped_k_segment: Vec<u8>,
    /// Wall-clock at insertion (ms epoch).
    pub created_at_ms: i64,
}

impl LocalStoreDb {
    /// Persist the latest backup manifest to the
    /// `backup_manifest_chain` single-row table.
    ///
    /// Idempotent upsert — the table is constrained to a single
    /// row (`CHECK (id = 1)`), so subsequent calls replace the
    /// previous manifest. `manifest_cbor` is the canonical CBOR
    /// encoding (via [`crate::cbor`]) of
    /// [`crate::formats::manifest::BackupManifest`]; `generation`
    /// mirrors the manifest's `generation` field and is exposed
    /// for diagnostic queries.
    pub fn save_backup_manifest(
        &self,
        manifest_cbor: &[u8],
        generation: i64,
        updated_at_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO backup_manifest_chain (id, generation, manifest_cbor, updated_at_ms)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                generation    = excluded.generation,
                manifest_cbor = excluded.manifest_cbor,
                updated_at_ms = excluded.updated_at_ms",
            params![generation, manifest_cbor, updated_at_ms],
        )?;
        Ok(())
    }

    /// Load the latest backup manifest CBOR, if any.
    ///
    /// Returns `None` before the first backup has been persisted
    /// (the "genesis" state); the orchestrator treats this as
    /// "no previous manifest to chain under".
    pub fn load_backup_manifest(&self) -> DbResult<Option<Vec<u8>>> {
        let row = self
            .conn
            .query_row(
                "SELECT manifest_cbor FROM backup_manifest_chain WHERE id = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(row)
    }

    /// Bulk-replace the backup segment ledger.
    ///
    /// Used by the compaction path that rewrites the ledger in
    /// one shot: every existing row is removed and `rows` is
    /// inserted inside a single SAVEPOINT so a crash leaves the
    /// ledger either at the pre-compaction state or the
    /// post-compaction state — never half-applied. We use a
    /// SAVEPOINT (rather than `Connection::transaction`) because
    /// every other `LocalStoreDb` method takes `&self`; nesting
    /// inside an outer SAVEPOINT is safe.
    pub fn replace_backup_segment_ledger(&self, rows: &[BackupSegmentLedgerRow]) -> DbResult<()> {
        self.conn
            .execute_batch("SAVEPOINT replace_backup_segment_ledger;")?;
        let inner = (|| -> DbResult<()> {
            self.conn.execute("DELETE FROM backup_segment_ledger", [])?;
            for row in rows {
                insert_backup_segment_ledger_row(&self.conn, row)?;
            }
            Ok(())
        })();
        match inner {
            Ok(()) => {
                self.conn
                    .execute_batch("RELEASE SAVEPOINT replace_backup_segment_ledger;")?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT replace_backup_segment_ledger; \
                     RELEASE SAVEPOINT replace_backup_segment_ledger;",
                );
                Err(e)
            }
        }
    }

    /// Insert a single row into the backup segment ledger.
    ///
    /// Used by the incremental-backup path which appends one row
    /// per sealed segment.
    pub fn insert_backup_segment_ledger_row(&self, row: &BackupSegmentLedgerRow) -> DbResult<()> {
        insert_backup_segment_ledger_row(&self.conn, row)
    }

    /// Atomically advance the backup event cursor, append one
    /// segment row, and upsert the manifest chain tail inside a
    /// single SAVEPOINT.
    ///
    /// If any of the three steps fails, all of them are rolled
    /// back so the on-disk cursor, ledger, and manifest remain
    /// consistent. In particular, a persist failure leaves the
    /// cursor at its pre-call value so the next backup run can
    /// retry the same events.
    ///
    /// The cursor advance preserves monotonicity: passing a
    /// `cursor_seq` smaller than the persisted value is rejected
    /// with `DbError::InvariantViolation` so backup runs can
    /// never re-publish already-segmented events.
    pub fn atomic_append_segment_and_manifest(
        &self,
        segment_row: &BackupSegmentLedgerRow,
        manifest_cbor: &[u8],
        generation: i64,
        cursor_seq: i64,
        updated_at_ms: i64,
    ) -> DbResult<()> {
        self.conn
            .execute_batch("SAVEPOINT atomic_backup_persist;")?;
        let inner = (|| -> DbResult<()> {
            // Monotonic cursor advance — read inside the SAVEPOINT
            // so the check and the UPSERT see a consistent
            // snapshot.
            let current_cursor: i64 = self
                .conn
                .query_row(
                    "SELECT cursor_seq FROM backup_event_cursor WHERE id = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .unwrap_or(0);
            if cursor_seq < current_cursor {
                return Err(DbError::InvariantViolation(format!(
                    "backup cursor cannot go backwards (current={current_cursor}, requested={cursor_seq})"
                )));
            }
            self.conn.execute(
                "INSERT INTO backup_event_cursor(id, cursor_seq) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET cursor_seq = excluded.cursor_seq",
                params![cursor_seq],
            )?;
            insert_backup_segment_ledger_row(&self.conn, segment_row)?;
            self.conn.execute(
                "INSERT INTO backup_manifest_chain (id, generation, manifest_cbor, updated_at_ms)
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                    generation    = excluded.generation,
                    manifest_cbor = excluded.manifest_cbor,
                    updated_at_ms = excluded.updated_at_ms",
                params![generation, manifest_cbor, updated_at_ms],
            )?;
            Ok(())
        })();
        match inner {
            Ok(()) => {
                self.conn
                    .execute_batch("RELEASE SAVEPOINT atomic_backup_persist;")?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT atomic_backup_persist; \
                     RELEASE SAVEPOINT atomic_backup_persist;",
                );
                Err(e)
            }
        }
    }

    /// Atomically replace the entire segment ledger **and** upsert
    /// the manifest chain tail inside a single SAVEPOINT.
    ///
    /// Used by the compaction path: superseded segments are removed
    /// and compacted entries inserted. If any step fails, the
    /// entire operation rolls back so the on-disk ledger and
    /// manifest remain consistent with each other.
    pub fn atomic_replace_ledger_and_manifest(
        &self,
        rows: &[BackupSegmentLedgerRow],
        manifest_cbor: &[u8],
        generation: i64,
        updated_at_ms: i64,
    ) -> DbResult<()> {
        self.conn
            .execute_batch("SAVEPOINT atomic_compact_persist;")?;
        let inner = (|| -> DbResult<()> {
            self.conn.execute("DELETE FROM backup_segment_ledger", [])?;
            for row in rows {
                insert_backup_segment_ledger_row(&self.conn, row)?;
            }
            self.conn.execute(
                "INSERT INTO backup_manifest_chain (id, generation, manifest_cbor, updated_at_ms)
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                    generation    = excluded.generation,
                    manifest_cbor = excluded.manifest_cbor,
                    updated_at_ms = excluded.updated_at_ms",
                params![generation, manifest_cbor, updated_at_ms],
            )?;
            Ok(())
        })();
        match inner {
            Ok(()) => {
                self.conn
                    .execute_batch("RELEASE SAVEPOINT atomic_compact_persist;")?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT atomic_compact_persist; \
                     RELEASE SAVEPOINT atomic_compact_persist;",
                );
                Err(e)
            }
        }
    }

    /// Load every row in the backup segment ledger.
    ///
    /// Ordered by `created_at_ms ASC` so callers see the segments
    /// in the same order they were appended to the in-memory
    /// ledger; the compaction planner is order-insensitive but
    /// stable ordering keeps test fixtures deterministic.
    pub fn load_backup_segment_ledger(&self) -> DbResult<Vec<BackupSegmentLedgerRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT segment_id, segment_type, nonce, ciphertext, merkle_root,
                    event_count, tier, min_event_ms, max_event_ms,
                    wrapped_k_segment, created_at_ms
             FROM backup_segment_ledger
             ORDER BY created_at_ms ASC, segment_id ASC",
        )?;
        let rows = stmt.query_map([], decode_backup_segment_ledger_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

fn insert_backup_segment_ledger_row(
    conn: &Connection,
    row: &BackupSegmentLedgerRow,
) -> DbResult<()> {
    conn.execute(
        "INSERT INTO backup_segment_ledger (
            segment_id, segment_type, nonce, ciphertext, merkle_root,
            event_count, tier, min_event_ms, max_event_ms,
            wrapped_k_segment, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            row.segment_id,
            row.segment_type,
            row.nonce,
            row.ciphertext,
            row.merkle_root,
            row.event_count,
            row.tier,
            row.min_event_ms,
            row.max_event_ms,
            row.wrapped_k_segment,
            row.created_at_ms,
        ],
    )?;
    Ok(())
}

fn decode_backup_segment_ledger_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<BackupSegmentLedgerRow> {
    Ok(BackupSegmentLedgerRow {
        segment_id: row.get(0)?,
        segment_type: row.get(1)?,
        nonce: row.get(2)?,
        ciphertext: row.get(3)?,
        merkle_root: row.get(4)?,
        event_count: row.get(5)?,
        tier: row.get(6)?,
        min_event_ms: row.get(7)?,
        max_event_ms: row.get(8)?,
        wrapped_k_segment: row.get(9)?,
        created_at_ms: row.get(10)?,
    })
}

// ---------------------------------------------------------------------------
// Connection bring-up
// ---------------------------------------------------------------------------

/// Run the post-open setup for a **read-write** writer connection:
/// `PRAGMA key`, `PRAGMA foreign_keys`, `PRAGMA journal_mode = WAL`,
/// `PRAGMA busy_timeout`, schema bring-up via [`run_migrations`]
/// (with unicode61 fallback for migration v1 on platforms without
/// FTS5 ICU), and a sanity check. Returns whether the FTS5 ICU
/// tokenizer was available.
///
/// **WAL mode**: enabling Write-Ahead Logging is what unlocks the
/// [`LocalStoreReaderPool`] concurrency model. In the default
/// `rollback journal` mode SQLite locks the entire database file
/// for the duration of every transaction, so a reader and the
/// writer cannot run concurrently. Under WAL, writers append to
/// `kchat.db-wal` while readers see a consistent snapshot from
/// the main file plus the WAL up to their checkpoint — readers
/// and the writer do not block each other. The WAL is
/// persisted across process restarts via the `-wal` and `-shm`
/// sidecar files SQLite creates next to `kchat.db`. The
/// `journal_mode` setting is itself persisted in the database
/// header, so subsequent opens inherit WAL without having to
/// re-issue the pragma — we still execute it on every open so a
/// freshly-created database picks it up before any data is
/// written.
///
/// **busy_timeout**: even under WAL, a writer can momentarily
/// block another writer (e.g. during a checkpoint promotion).
/// Setting `busy_timeout = 5000` ms lets SQLite spin and retry
/// instead of immediately returning `SQLITE_BUSY` to the
/// caller — the value is large enough to cover a stop-the-world
/// checkpoint on a slow device but small enough that a genuinely
/// deadlocked configuration surfaces within seconds.
///
/// **`:memory:` caveat**: SQLite silently downgrades WAL to the
/// `MEMORY` journal mode for in-memory databases (see
/// <https://www.sqlite.org/wal.html>). The pragma still succeeds;
/// the runtime just behaves as if rollback journaling were in
/// effect. Shared-cache URIs of the form
/// `file:<name>?mode=memory&cache=shared` allow multiple
/// connections to see the same in-memory database, which is how
/// the test harness exercises the reader-pool path without an
/// on-disk file.
fn init_connection(conn: &Connection, key: &[u8; 32]) -> DbResult<bool> {
    set_key(conn, key)?;
    // Foreign keys must be enabled per-connection in SQLite.
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    // Force-decrypt with a trivial query so a wrong key surfaces
    // immediately rather than lurking until the first table access.
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")?;
    // Enable Write-Ahead Logging so the reader pool can run
    // SELECTs concurrently with the writer's INSERT/UPDATE/DELETE
    // — see the doc comment above for the rationale. For
    // `:memory:` databases SQLite returns the actual mode (which
    // is `MEMORY`) without raising an error, so this is safe to
    // run unconditionally.
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    // 5-second busy timeout: see the doc comment above. The
    // value matches the writer side of
    // [`init_reader_connection`] so a `SQLITE_BUSY` from either
    // side has the same retry budget.
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;

    let icu_available = fts5_icu_available(conn);
    run_migrations(conn, icu_available)?;
    Ok(icu_available)
}

/// Run the post-open setup for a **read-only** reader connection.
///
/// Differs from [`init_connection`] in three ways:
///   1. No `PRAGMA journal_mode = WAL` — the writer's open
///      already sticky-set WAL into the database header; a
///      reader that re-issues the pragma would observe `wal`
///      and return the same value, so the call is omitted to
///      keep reader bring-up lean.
///   2. No [`run_migrations`] call — the writer is the only path
///      that ever creates or alters tables. A reader that finds
///      the schema at an older version logs nothing and proceeds:
///      the writer will have run the migrations first, so by the
///      time the reader pool is initialised the schema is always
///      current.
///   3. The sanity-check `SELECT` still runs so an incorrect key
///      surfaces synchronously, before the connection joins the
///      pool.
///
/// **`PRAGMA query_only` is what enforces read-only**: the
/// reader is opened with `SQLITE_OPEN_READ_WRITE`, not
/// `SQLITE_OPEN_READ_ONLY`, because WAL mode requires every
/// connection to have write access to the `<db>-shm`
/// shared-memory file — see [`LocalStoreReader::open`] for the
/// full rationale. The `query_only = 1` PRAGMA replaces the
/// OS-level read-only flag: it makes the SQLite engine itself
/// reject any `INSERT` / `UPDATE` / `DELETE` / `CREATE`
/// statement issued through the connection.
fn init_reader_connection(conn: &Connection, key: &[u8; 32]) -> DbResult<()> {
    set_key(conn, key)?;
    // Foreign keys: idempotent across connections; safe to set
    // again so a debugger attaching to a pool reader sees the
    // same constraint regime as the writer.
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    // Force-decrypt: same rationale as the writer path — a wrong
    // key surfaces here rather than on the first SELECT.
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")?;
    // Matching busy_timeout so a reader that hits a checkpoint
    // contention spin sees the same retry budget as the writer.
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    // `query_only = 1` is the read-only invariant: the
    // connection itself is opened with `SQLITE_OPEN_READ_WRITE`
    // (so the WAL `-shm` file works — see
    // [`LocalStoreReader::open`]), and SQLite then rejects any
    // INSERT / UPDATE / DELETE / CREATE issued on the
    // connection at the engine layer.
    conn.execute_batch("PRAGMA query_only = 1;")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Read-only free functions
// ---------------------------------------------------------------------------
//
// Phase B.1 split: every read-only query that is exposed on both
// the writer ([`LocalStoreDb`]) and the reader pool
// ([`LocalStoreReader`] / [`LocalStoreReaderPool`]) has its body
// extracted into a `pub(crate) fn read_xxx(conn: &Connection, ...)`
// here, so there is exactly one canonical query body per logical
// read. The methods on `LocalStoreDb` and `LocalStoreReader` are
// one-line delegates over `&self.conn`, which is also the public
// boundary documented by the doc comments on those methods.
//
// Each function below only needs `&Connection`, which is the
// surface common to both writer and reader connections. The
// reader connections additionally carry `PRAGMA query_only = 1`,
// so any function listed here that attempted to mutate state
// would surface immediately as `SQLITE_READONLY` at runtime on
// the reader path — the read-vs-write separation is enforced
// at SQLite, not just at the Rust type boundary.

/// Read [`Conversation`] row keyed on `conversation_id`. See
/// [`LocalStoreDb::get_conversation`] for caller-side docs.
pub(crate) fn read_conversation(
    conn: &Connection,
    conversation_id: &str,
) -> DbResult<Option<Conversation>> {
    conn.query_row(
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

/// List every [`Conversation`] row, newest-pinned-first. See
/// [`LocalStoreDb::list_conversations`] for caller-side docs.
pub(crate) fn read_list_conversations(conn: &Connection) -> DbResult<Vec<Conversation>> {
    let mut stmt = conn.prepare(
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

/// List every [`Conversation`] whose `column` equals `value`. See
/// [`LocalStoreDb::list_conversations_by_community`] /
/// `_by_domain` / `_by_tenant` / `_by_scope` for the four
/// caller-side wrappers.
///
/// `column` must come from a closed set of literals
/// (`tenant_id`, `community_id`, `domain_id`, `scope`) chosen by
/// the caller — never user input — so the inline format string is
/// safe.
pub(crate) fn read_list_conversations_by_column(
    conn: &Connection,
    column: &str,
    value: &str,
) -> DbResult<Vec<Conversation>> {
    let sql = format!(
        "SELECT conversation_id, title_cipher, pinned, muted,
                last_message_id, last_activity_ms,
                conversation_type, scope, tenant_id,
                community_id, domain_id
           FROM conversation
          WHERE {column} = ?1
          ORDER BY pinned DESC, last_activity_ms DESC, conversation_id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![value], row_to_conversation)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Fetch a [`MessageSkeleton`] by `message_id`. See
/// [`LocalStoreDb::get_message_skeleton`].
pub(crate) fn read_message_skeleton(
    conn: &Connection,
    message_id: &str,
) -> DbResult<Option<MessageSkeleton>> {
    let row = conn
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

/// Fetch a [`MessageBody`] by `message_id`. See
/// [`LocalStoreDb::get_message_body`].
pub(crate) fn read_message_body(
    conn: &Connection,
    message_id: &str,
) -> DbResult<Option<MessageBody>> {
    conn.query_row(
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

/// Fetch skeleton + optional body by `message_id`. See
/// [`LocalStoreDb::get_message_with_body`].
pub(crate) fn read_message_with_body(
    conn: &Connection,
    message_id: &str,
) -> DbResult<Option<(MessageSkeleton, Option<MessageBody>)>> {
    let row = conn
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
                let body_present =
                    text_content.is_some() || detected_language.is_some() || rich_meta.is_some();
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

/// Return paginated messages in `conversation_id`, newest-first.
/// See [`LocalStoreDb::get_conversation_messages`].
pub(crate) fn read_conversation_messages(
    conn: &Connection,
    conversation_id: &str,
    before_ms: Option<i64>,
    limit: usize,
) -> DbResult<Vec<MessageSkeleton>> {
    let mut stmt;
    let rows = if let Some(before) = before_ms {
        stmt = conn.prepare(
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
        stmt = conn.prepare(
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

/// Return the timeline (skeleton + body text) for
/// `conversation_id`. See [`LocalStoreDb::get_timeline`].
pub(crate) fn read_timeline(
    conn: &Connection,
    conversation_id: &str,
    before_ms: Option<i64>,
    limit: usize,
) -> DbResult<Vec<TimelineRow>> {
    let mut stmt = conn.prepare(
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

/// Search `media_search_index` by substring across all kinds (or
/// a specific `kind` filter). See
/// [`LocalStoreDb::search_media_index`].
pub(crate) fn read_search_media_index(
    conn: &Connection,
    query: &str,
    kind: Option<&str>,
) -> DbResult<Vec<MediaSearchResult>> {
    let needle = format!("%{}%", escape_like_pattern(query));
    let rows: Vec<MediaSearchResult> = match kind {
        Some(k) => {
            let mut stmt = conn.prepare(
                "SELECT asset_id, kind, text, language, confidence
                   FROM media_search_index
                  WHERE kind = ?1 AND text LIKE ?2 ESCAPE '\\' COLLATE NOCASE",
            )?;
            let it = stmt.query_map(params![k, needle], row_to_media_search_result)?;
            it.collect::<rusqlite::Result<Vec<_>>>()?
        }
        None => {
            let mut stmt = conn.prepare(
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

// ---------------------------------------------------------------------------
// LocalStoreReader
// ---------------------------------------------------------------------------

/// Read-only handle to the encrypted local-store database.
///
/// Opened with `OpenFlags::SQLITE_OPEN_READ_ONLY |
/// SQLITE_OPEN_NO_MUTEX` plus `PRAGMA query_only = 1`, so the
/// SQLite engine itself rejects any `INSERT` / `UPDATE` /
/// `DELETE` / `CREATE` issued through this handle. Several
/// readers can run `SELECT` statements concurrently with the
/// writer's transactions under WAL mode — that's the concurrency
/// win this type unlocks vs. the historical single-mutex
/// [`LocalStoreDb`] layout.
///
/// The method surface is intentionally a strict subset of
/// [`LocalStoreDb`]: every method delegates to the same
/// `read_xxx(conn, ...)` free function that the corresponding
/// writer-side method calls, so there is exactly one query body
/// per logical read.
///
/// `LocalStoreReader` itself is `!Send` (because
/// `rusqlite::Connection` is `!Send` when compiled without the
/// `SQLITE_OPEN_FULLMUTEX` flag). The [`LocalStoreReaderPool`]
/// owns the readers and serialises checkout / checkin behind a
/// `Mutex<Vec<LocalStoreReader>>`, so the pool itself is `Send +
/// Sync` and can be shared across the bridge crates.
#[derive(Debug)]
pub struct LocalStoreReader {
    conn: Connection,
    /// FTS5 ICU-tokenizer availability for this connection's
    /// schema. Mirrors [`LocalStoreDb::icu_available`] and is
    /// cached at open time by sniffing `search_fts`'s tokenizer
    /// configuration via [`probe_fts_icu_available`]. Read by the
    /// search engines (`TextSearchEngine`) so they can choose
    /// between the ICU and `unicode61` query paths without
    /// having to round-trip through the writer.
    icu_available: bool,
}

impl LocalStoreReader {
    /// Open a new logically read-only connection to the
    /// encrypted database at `path`. The schema is *not* re-run
    /// — the writer is the only path that may alter the on-disk
    /// shape.
    ///
    /// **OS-level open flags**: the connection is opened with
    /// `SQLITE_OPEN_READ_WRITE | SQLITE_OPEN_NO_MUTEX` rather
    /// than the more intuitive `SQLITE_OPEN_READ_ONLY`. This is
    /// a SQLite WAL-mode requirement, not a relaxation: a WAL-
    /// mode database needs every connection (including readers)
    /// to have *write* access to the `<db>-shm` shared-memory
    /// index file so readers can register their snapshot mark
    /// against the writer's append cursor. Opening with
    /// `SQLITE_OPEN_READ_ONLY` while the WAL is non-empty makes
    /// SQLite return `SQLITE_CANTOPEN` (or `SQLITE_IOERR` on
    /// some platforms) — see <https://www.sqlite.org/wal.html>
    /// §"Read-Only Databases". The actual read-only invariant
    /// is enforced by [`init_reader_connection`]'s
    /// `PRAGMA query_only = 1`, which makes the SQLite engine
    /// itself reject any `INSERT` / `UPDATE` / `DELETE` /
    /// `CREATE` issued through this handle. Combined with the
    /// fact that the only `pub` methods on `LocalStoreReader`
    /// delegate to the `read_xxx` free functions (none of which
    /// issue mutating statements), this gives the same
    /// guarantees as the OS-level read-only flag without the
    /// WAL compatibility problem.
    pub fn open(path: &Path, key: &[u8; 32]) -> DbResult<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        init_reader_connection(&conn, key)?;
        let icu_available = probe_fts_icu_available(&conn);
        Ok(Self {
            conn,
            icu_available,
        })
    }

    /// Open a new logically read-only connection via an
    /// explicit URI. Used by the in-memory test harness with a
    /// `file:<unique-name>?mode=memory&cache=shared` URI. The
    /// `SQLITE_OPEN_URI` flag must be in the flags set or SQLite
    /// will treat the URI as a literal filename. See
    /// [`LocalStoreReader::open`] for the rationale behind
    /// `SQLITE_OPEN_READ_WRITE`.
    pub fn open_uri(uri: &str, key: &[u8; 32]) -> DbResult<Self> {
        let conn = Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )?;
        init_reader_connection(&conn, key)?;
        let icu_available = probe_fts_icu_available(&conn);
        Ok(Self {
            conn,
            icu_available,
        })
    }

    /// `true` when this reader's database has the FTS5 ICU
    /// tokenizer wired up, `false` when it falls back to the
    /// `unicode61` tokenizer. The flag is sniffed once at open
    /// time and never changes for the lifetime of the connection
    /// — schema changes go through the writer and would require
    /// re-opening the pool to take effect.
    pub fn icu_available(&self) -> bool {
        self.icu_available
    }

    /// Borrow the underlying read-only connection. Provided so
    /// callers that need to compose multiple `read_xxx` free
    /// functions inside a single deferred-read transaction can do
    /// so without re-acquiring the pool slot. Holding this
    /// borrow does NOT release the reader back to the pool — the
    /// reader stays checked out for the lifetime of `&self`.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // -------- Conversation reads --------

    /// See [`LocalStoreDb::get_conversation`].
    pub fn get_conversation(&self, conversation_id: &str) -> DbResult<Option<Conversation>> {
        read_conversation(&self.conn, conversation_id)
    }

    /// See [`LocalStoreDb::list_conversations`].
    pub fn list_conversations(&self) -> DbResult<Vec<Conversation>> {
        read_list_conversations(&self.conn)
    }

    /// See [`LocalStoreDb::list_conversations_by_community`].
    pub fn list_conversations_by_community(
        &self,
        community_id: &str,
    ) -> DbResult<Vec<Conversation>> {
        read_list_conversations_by_column(&self.conn, "community_id", community_id)
    }

    /// See [`LocalStoreDb::list_conversations_by_domain`].
    pub fn list_conversations_by_domain(&self, domain_id: &str) -> DbResult<Vec<Conversation>> {
        read_list_conversations_by_column(&self.conn, "domain_id", domain_id)
    }

    /// See [`LocalStoreDb::list_conversations_by_tenant`].
    pub fn list_conversations_by_tenant(&self, tenant_id: &str) -> DbResult<Vec<Conversation>> {
        read_list_conversations_by_column(&self.conn, "tenant_id", tenant_id)
    }

    /// See [`LocalStoreDb::list_conversations_by_scope`].
    pub fn list_conversations_by_scope(&self, scope: &str) -> DbResult<Vec<Conversation>> {
        read_list_conversations_by_column(&self.conn, "scope", scope)
    }

    // -------- Message reads --------

    /// See [`LocalStoreDb::get_message_skeleton`].
    pub fn get_message_skeleton(&self, message_id: &str) -> DbResult<Option<MessageSkeleton>> {
        read_message_skeleton(&self.conn, message_id)
    }

    /// See [`LocalStoreDb::get_message_body`].
    pub fn get_message_body(&self, message_id: &str) -> DbResult<Option<MessageBody>> {
        read_message_body(&self.conn, message_id)
    }

    /// See [`LocalStoreDb::get_message_with_body`].
    pub fn get_message_with_body(
        &self,
        message_id: &str,
    ) -> DbResult<Option<(MessageSkeleton, Option<MessageBody>)>> {
        read_message_with_body(&self.conn, message_id)
    }

    /// See [`LocalStoreDb::get_conversation_messages`].
    pub fn get_conversation_messages(
        &self,
        conversation_id: &str,
        before_ms: Option<i64>,
        limit: usize,
    ) -> DbResult<Vec<MessageSkeleton>> {
        read_conversation_messages(&self.conn, conversation_id, before_ms, limit)
    }

    /// See [`LocalStoreDb::get_timeline`].
    pub fn get_timeline(
        &self,
        conversation_id: &str,
        before_ms: Option<i64>,
        limit: usize,
    ) -> DbResult<Vec<TimelineRow>> {
        read_timeline(&self.conn, conversation_id, before_ms, limit)
    }

    // -------- Media search --------

    /// See [`LocalStoreDb::search_media_index`].
    pub fn search_media_index(
        &self,
        query: &str,
        kind: Option<&str>,
    ) -> DbResult<Vec<MediaSearchResult>> {
        read_search_media_index(&self.conn, query, kind)
    }
}

// ---------------------------------------------------------------------------
// LocalStoreReaderPool
// ---------------------------------------------------------------------------

/// Pool of [`LocalStoreReader`] connections used to serve
/// concurrent read traffic alongside the single writer.
///
/// # Concurrency model
///
/// * The writer (`LocalStoreDb`, held in `Mutex<LocalStoreDb>`)
///   takes its lock for the duration of every write transaction.
/// * The reader pool holds N `LocalStoreReader` handles in a
///   `Mutex<Vec<LocalStoreReader>>` plus a `Condvar`. A
///   [`LocalStoreReaderPool::with_reader`] call pops a reader
///   off the vec (blocking on the condvar if all readers are
///   in use), runs the supplied closure, and pushes the reader
///   back on the way out — guaranteed to run even on closure
///   panic via a drop guard.
/// * Under WAL mode the readers and writer do **not** block
///   each other; this pool is what lets the bridge crates run
///   `search()` and `get_conversation_messages()` in parallel
///   while an `ingest_messages()` transaction is committing on
///   the writer side.
///
/// # `Send` / `Sync`
///
/// `LocalStoreReader` itself is `!Send` because the embedded
/// `rusqlite::Connection` is `!Send` under the default
/// (per-connection) mutex regime SQLCipher ships with. The pool
/// wraps the vec in a `Mutex` and exposes only the
/// `with_reader(|r| ...)` closure form, so the reader's
/// `!Send`-ness never escapes the pool — `LocalStoreReaderPool`
/// itself is `Send + Sync` (because `Mutex<T>: Send` whenever
/// `T: Send`, and `Condvar` is `Send + Sync`).
#[derive(Debug)]
pub struct LocalStoreReaderPool {
    slots: Mutex<Vec<LocalStoreReader>>,
    available: Condvar,
    capacity: usize,
}

impl LocalStoreReaderPool {
    /// Open `capacity` read-only connections to the encrypted
    /// database at `path` and seed the pool with them.
    ///
    /// `capacity` must be `>= 1`; a `0` value is silently
    /// clamped to `1` (and a `warn!` is emitted by the caller in
    /// `core_impl`).
    pub fn open(path: &Path, key: &[u8; 32], capacity: usize) -> DbResult<Self> {
        let capacity = capacity.max(1);
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(LocalStoreReader::open(path, key)?);
        }
        Ok(Self {
            slots: Mutex::new(slots),
            available: Condvar::new(),
            capacity,
        })
    }

    /// Open `capacity` read-only connections via an explicit URI
    /// (used by the in-memory `cache=shared` test harness).
    pub fn open_uri(uri: &str, key: &[u8; 32], capacity: usize) -> DbResult<Self> {
        let capacity = capacity.max(1);
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(LocalStoreReader::open_uri(uri, key)?);
        }
        Ok(Self {
            slots: Mutex::new(slots),
            available: Condvar::new(),
            capacity,
        })
    }

    /// Maximum number of concurrent readers the pool was sized
    /// for at construction.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Check a reader out, run `f` with it, and return it to the
    /// pool — even if `f` panics.
    ///
    /// Blocks if every reader is currently in use, waking on the
    /// pool's `Condvar` when a checkin happens. The closure
    /// receives a `&LocalStoreReader`, never the owned value, so
    /// callers cannot accidentally hold a reader past the
    /// closure scope.
    pub fn with_reader<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&LocalStoreReader) -> R,
    {
        let reader = self.checkout();
        // Drop guard ensures the reader is returned to the pool
        // even if `f` panics. We use `Option::take()` inside the
        // guard so the explicit checkin on the success path can
        // disarm the guard before returning the result.
        struct Guard<'a> {
            pool: &'a LocalStoreReaderPool,
            reader: Option<LocalStoreReader>,
        }
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                if let Some(reader) = self.reader.take() {
                    self.pool.checkin(reader);
                }
            }
        }
        let mut guard = Guard {
            pool: self,
            reader: Some(reader),
        };
        let result = f(guard.reader.as_ref().expect("reader present"));
        // Explicit checkin on the success path so callers don't
        // pay the cost of `Drop` running through `Option::take`.
        if let Some(reader) = guard.reader.take() {
            self.checkin(reader);
        }
        result
    }

    fn checkout(&self) -> LocalStoreReader {
        let mut slots = self.slots.lock().expect("reader pool mutex poisoned");
        while slots.is_empty() {
            slots = self
                .available
                .wait(slots)
                .expect("reader pool condvar poisoned");
        }
        slots.pop().expect("non-empty checked above")
    }

    fn checkin(&self, reader: LocalStoreReader) {
        let mut slots = self.slots.lock().expect("reader pool mutex poisoned");
        slots.push(reader);
        // Wake one waiter; `notify_one` is sufficient because a
        // single returned reader can only unblock one waiting
        // checkout.
        self.available.notify_one();
    }
}

/// Read the current `PRAGMA user_version` for `conn`.
///
/// SQLite initialises `user_version` to `0` for a freshly-created
/// database, which the migration framework treats as the "no
/// migration has ever run" state.
fn read_user_version(conn: &Connection) -> DbResult<i32> {
    let v: i32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;
    Ok(v)
}

/// Write the `PRAGMA user_version` value.
///
/// SQLite does not allow positional parameters in `PRAGMA`
/// statements, so we format the integer directly. The value
/// comes from [`MIGRATIONS`] (compile-time constant) so there
/// is no injection surface.
fn write_user_version(conn: &Connection, v: i32) -> DbResult<()> {
    conn.execute_batch(&format!("PRAGMA user_version = {v};"))?;
    Ok(())
}

/// Apply every outstanding migration in [`MIGRATIONS`] to `conn`.
///
/// Reads `PRAGMA user_version`. For every entry whose target
/// version is greater than the current version, the SQL is
/// executed inside a savepoint so a failure rolls back the
/// partial schema and leaves the DB at the previous version.
/// After each successful migration `user_version` is updated to
/// the migration's target.
///
/// Migration `1` is the original [`SCHEMA_SQL`] block. On
/// platforms whose SQLCipher build does not link the FTS5 ICU
/// tokenizer the `tokenize = 'icu'` literal is rewritten to the
/// `unicode61` fallback (`icu_available = false`). Later
/// migrations are emitted verbatim.
///
/// The function is idempotent: running on a DB that is already
/// at [`LATEST_USER_VERSION`] is a no-op.
pub fn run_migrations(conn: &Connection, icu_available: bool) -> DbResult<()> {
    let mut current = read_user_version(conn)?;
    for (target, sql) in MIGRATIONS {
        if *target <= current {
            continue;
        }
        // Migration v1 contains the FTS5 ICU literal that must be
        // rewritten on platforms without ICU. Every other migration
        // is emitted verbatim.
        let owned: String;
        let sql_to_run: &str = if *target == 1 && !icu_available {
            owned = sql.replace(
                "tokenize = 'icu'",
                "tokenize = 'unicode61 remove_diacritics 2'",
            );
            owned.as_str()
        } else {
            sql
        };

        let savepoint = format!("migration_v{target}");
        conn.execute_batch(&format!("SAVEPOINT {savepoint};"))?;
        match conn.execute_batch(sql_to_run) {
            Ok(()) => match write_user_version(conn, *target) {
                Ok(()) => {
                    conn.execute_batch(&format!("RELEASE SAVEPOINT {savepoint};"))?;
                    current = *target;
                }
                Err(e) => {
                    let _ = conn.execute_batch(&format!(
                        "ROLLBACK TO SAVEPOINT {savepoint}; RELEASE SAVEPOINT {savepoint};"
                    ));
                    return Err(e);
                }
            },
            Err(e) => {
                let _ = conn.execute_batch(&format!(
                    "ROLLBACK TO SAVEPOINT {savepoint}; RELEASE SAVEPOINT {savepoint};"
                ));
                return Err(DbError::from(e));
            }
        }
    }
    debug_assert!(current == LATEST_USER_VERSION || current >= LATEST_USER_VERSION);
    Ok(())
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
    fn fresh_db_runs_all_migrations_to_latest_user_version() {
        // Fresh in-memory DB must reach `LATEST_USER_VERSION`
        // unconditionally — `init_connection` invokes
        // `run_migrations`, which iterates `MIGRATIONS` in order.
        let db = fresh_db();
        let v = read_user_version(db.connection()).unwrap();
        assert_eq!(v, LATEST_USER_VERSION);
    }

    #[test]
    fn migration_v2_adds_backup_chain_and_segment_ledger_tables() {
        // Pin Task-2 hardening: the v2 migration must materialise
        // both tables on every fresh open.
        let db = fresh_db();
        for table in ["backup_manifest_chain", "backup_segment_ledger"] {
            let exists: i64 = db
                .connection()
                .query_row(
                    "SELECT count(*) FROM sqlite_master
                     WHERE name = ?1 AND type = 'table'",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists > 0, "missing migration-v2 table: {table}");
        }
    }

    #[test]
    fn run_migrations_is_idempotent_when_already_at_latest() {
        // Running migrations again on an up-to-date DB is a no-op
        // and must not error. The PRAGMA stays unchanged.
        let db = fresh_db();
        let before = read_user_version(db.connection()).unwrap();
        run_migrations(db.connection(), db.icu_available()).unwrap();
        let after = read_user_version(db.connection()).unwrap();
        assert_eq!(before, after);
        assert_eq!(after, LATEST_USER_VERSION);
    }

    #[test]
    fn run_migrations_resumes_from_v1_fixture() {
        // Simulate a DB that was created under the v1 schema only
        // (i.e. before migration v2 existed): apply migration v1
        // by hand, set user_version=1, then call run_migrations
        // and assert it advances to LATEST_USER_VERSION and adds
        // the v2 tables without touching v1 tables.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // Match init_connection's foreign-keys / sanity-check
        // setup so the fixture mirrors a real on-disk v1 DB.
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        // Apply just migration v1, mimicking the old
        // `init_connection` that ran `SCHEMA_SQL` without setting
        // `user_version`.
        let icu_available = fts5_icu_available(&conn);
        let v1_sql = if icu_available {
            SCHEMA_SQL.to_string()
        } else {
            create_schema_with_unicode61_fallback()
        };
        conn.execute_batch(&v1_sql).unwrap();
        write_user_version(&conn, 1).unwrap();
        // Sanity: v2 tables are NOT present yet.
        let pre_v2: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE name = 'backup_segment_ledger'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pre_v2, 0);

        // Run the migration framework — it must apply v2 only.
        run_migrations(&conn, icu_available).unwrap();
        let after = read_user_version(&conn).unwrap();
        assert_eq!(after, LATEST_USER_VERSION);

        for table in ["backup_manifest_chain", "backup_segment_ledger"] {
            let exists: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master
                     WHERE name = ?1 AND type = 'table'",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists > 0, "v2 migration did not add {table}");
        }

        // v1 tables remain intact and untouched.
        for table in TABLES {
            let exists: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master
                     WHERE name = ?1 AND (type = 'table' OR type = 'virtual')",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists > 0, "v1 table dropped by v2 migration: {table}");
        }
    }

    #[test]
    fn run_migrations_failure_leaves_user_version_unchanged() {
        // Build a v1 fixture, then call `run_migrations` with a
        // doctored MIGRATIONS-style table whose SQL is malformed.
        // The savepoint rollback in `run_migrations` must leave
        // user_version pinned at the last successful migration.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        let icu_available = fts5_icu_available(&conn);
        let v1_sql = if icu_available {
            SCHEMA_SQL.to_string()
        } else {
            create_schema_with_unicode61_fallback()
        };
        conn.execute_batch(&v1_sql).unwrap();
        write_user_version(&conn, 1).unwrap();

        // Mimic `run_migrations` for a single broken migration so
        // the assertion targets the savepoint/rollback logic in
        // isolation. The real `run_migrations` has the same shape
        // — see the inner match in `run_migrations` above. We use
        // an outright syntax error (SQLite is lenient about column
        // *types* but will reject malformed DDL).
        let bad = "CREATE TABLE __not_a_table (id INTEGER); THIS IS NOT VALID SQL;";
        let savepoint = "migration_v_test";
        conn.execute_batch(&format!("SAVEPOINT {savepoint};"))
            .unwrap();
        let result = conn.execute_batch(bad);
        let _ = conn.execute_batch(&format!(
            "ROLLBACK TO SAVEPOINT {savepoint}; RELEASE SAVEPOINT {savepoint};"
        ));
        assert!(result.is_err(), "doctored migration must fail to apply");

        // user_version still pinned to the last successful
        // migration (v1) — the rollback restored consistency.
        let after = read_user_version(&conn).unwrap();
        assert_eq!(after, 1);
        // No half-built table left behind.
        let leaked: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE name = '__not_a_table'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leaked, 0);
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

    // ---------------------------------------------------------------
    // Atomic backup-persist tests
    // ---------------------------------------------------------------

    fn sample_segment_row(id: &str, now_ms: i64) -> BackupSegmentLedgerRow {
        BackupSegmentLedgerRow {
            segment_id: id.to_string(),
            segment_type: "events".to_string(),
            nonce: vec![0u8; 24],
            ciphertext: vec![0xCA, 0xFE],
            merkle_root: vec![0u8; 32],
            event_count: 3,
            tier: "daily".to_string(),
            min_event_ms: now_ms - 1000,
            max_event_ms: now_ms,
            wrapped_k_segment: vec![0xDE, 0xAD],
            created_at_ms: now_ms,
        }
    }

    #[test]
    fn atomic_append_segment_and_manifest_commits_both() {
        let db = fresh_db();
        let row = sample_segment_row("seg-1", 1000);
        let manifest = b"manifest-cbor-1";
        db.atomic_append_segment_and_manifest(&row, manifest, 0, 0, 1000)
            .expect("atomic append");
        let loaded_manifest = db.load_backup_manifest().unwrap();
        assert_eq!(loaded_manifest, Some(manifest.to_vec()));
        let ledger = db.load_backup_segment_ledger().unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].segment_id, "seg-1");
    }

    #[test]
    fn atomic_replace_ledger_and_manifest_commits_both() {
        let db = fresh_db();
        // Seed two rows first.
        let r1 = sample_segment_row("seg-old-1", 1000);
        let r2 = sample_segment_row("seg-old-2", 1001);
        db.insert_backup_segment_ledger_row(&r1).unwrap();
        db.insert_backup_segment_ledger_row(&r2).unwrap();
        db.save_backup_manifest(b"old-manifest", 0, 1000).unwrap();

        // Replace with a single compacted row + new manifest.
        let compacted = sample_segment_row("seg-compacted", 2000);
        let new_manifest = b"new-manifest";
        db.atomic_replace_ledger_and_manifest(&[compacted], new_manifest, 1, 2000)
            .expect("atomic replace");

        let loaded_manifest = db.load_backup_manifest().unwrap();
        assert_eq!(loaded_manifest, Some(new_manifest.to_vec()));
        let ledger = db.load_backup_segment_ledger().unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].segment_id, "seg-compacted");
    }

    #[test]
    fn atomic_replace_rolls_back_on_ledger_error() {
        let db = fresh_db();
        // Seed initial state.
        let r1 = sample_segment_row("seg-keep", 1000);
        db.insert_backup_segment_ledger_row(&r1).unwrap();
        db.save_backup_manifest(b"keep-manifest", 0, 1000).unwrap();

        // Try to replace with a row that has a duplicate segment_id
        // within the same batch — the second insert will violate the
        // PRIMARY KEY constraint, causing the SAVEPOINT to roll back.
        let dup = sample_segment_row("seg-dup", 2000);
        let result = db.atomic_replace_ledger_and_manifest(
            &[dup.clone(), dup],
            b"should-not-persist",
            1,
            2000,
        );
        assert!(result.is_err(), "duplicate PK must fail");

        // Both ledger and manifest must be unchanged.
        let manifest = db.load_backup_manifest().unwrap();
        assert_eq!(manifest, Some(b"keep-manifest".to_vec()));
        let ledger = db.load_backup_segment_ledger().unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].segment_id, "seg-keep");
    }

    #[test]
    fn atomic_append_rolls_back_on_duplicate_segment() {
        let db = fresh_db();
        // Seed a segment + manifest.
        let r1 = sample_segment_row("seg-existing", 1000);
        db.atomic_append_segment_and_manifest(&r1, b"manifest-v0", 0, 0, 1000)
            .unwrap();

        // Attempt to re-insert the same segment_id — PK violation.
        let dup = sample_segment_row("seg-existing", 2000);
        let result = db.atomic_append_segment_and_manifest(
            &dup,
            b"manifest-v1-should-not-persist",
            1,
            0,
            2000,
        );
        assert!(result.is_err(), "duplicate PK must fail");

        // Manifest must still be at v0, not v1.
        let manifest = db.load_backup_manifest().unwrap();
        assert_eq!(manifest, Some(b"manifest-v0".to_vec()));
        let ledger = db.load_backup_segment_ledger().unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].segment_id, "seg-existing");
    }

    // -----------------------------------------------------------
    // Phase B.1: WAL mode + LocalStoreReader / LocalStoreReaderPool
    // -----------------------------------------------------------

    fn sample_conversation(id: &str, last_activity_ms: i64) -> Conversation {
        Conversation {
            conversation_id: id.to_string(),
            title_cipher: Some(vec![0xAA; 16]),
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms,
            conversation_type: "dm".to_string(),
            scope: "b2c".to_string(),
            tenant_id: String::new(),
            community_id: String::new(),
            domain_id: String::new(),
        }
    }

    /// Helper: a fresh writer + the data directory it was opened
    /// against, so the matching reader pool can be opened over
    /// the same directory.
    fn fresh_writer_with_dir() -> (tempfile::TempDir, std::path::PathBuf, LocalStoreDb) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let db = LocalStoreDb::open(&dir, &test_key()).unwrap();
        (tmp, dir, db)
    }

    /// Helper: filesystem path the reader pool should open
    /// against, matching the `kchat.db` filename the writer's
    /// `open` materialises inside `data_dir`.
    fn db_file(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("kchat.db")
    }

    #[test]
    fn writer_open_enables_wal_journal_mode_on_disk() {
        // PRAGMA journal_mode = WAL must be sticky on the on-disk
        // database header. We probe the mode by re-opening and
        // querying the pragma.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let key = test_key();
        {
            let _db = LocalStoreDb::open(dir, &key).unwrap();
        }
        let probe = LocalStoreDb::open(dir, &key).unwrap();
        let mode: String = probe
            .connection()
            .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
            .unwrap();
        // SQLCipher returns the journal mode lowercased.
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn reader_pool_open_with_capacity_n_seeds_n_readers() {
        // The pool must materialise exactly `capacity` readers
        // up-front so checkout is O(1) and no reader is opened
        // lazily on the hot path.
        let (_tmp, dir, _writer) = fresh_writer_with_dir();
        let pool = LocalStoreReaderPool::open(&db_file(&dir), &test_key(), 3).unwrap();
        assert_eq!(pool.capacity(), 3);
        // Internal: every reader is parked in `slots` until the
        // first checkout — verify by inspecting the lock-guarded
        // length.
        assert_eq!(pool.slots.lock().unwrap().len(), 3);
    }

    #[test]
    fn reader_pool_zero_capacity_is_clamped_to_one() {
        let (_tmp, dir, _writer) = fresh_writer_with_dir();
        let pool = LocalStoreReaderPool::open(&db_file(&dir), &test_key(), 0).unwrap();
        assert_eq!(pool.capacity(), 1);
    }

    #[test]
    fn reader_observes_writes_committed_via_writer() {
        // Read-after-write across the writer/reader split. A row
        // inserted through the writer must be visible to a freshly
        // checked-out reader without any explicit synchronisation.
        let (_tmp, dir, writer) = fresh_writer_with_dir();
        writer
            .insert_conversation(&sample_conversation("conv-A", 1_000))
            .unwrap();
        let pool = LocalStoreReaderPool::open(&db_file(&dir), &test_key(), 2).unwrap();
        let observed = pool.with_reader(|r| r.list_conversations()).unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].conversation_id, "conv-A");
    }

    #[test]
    fn reader_rejects_writes_via_query_only_pragma() {
        // `PRAGMA query_only = 1` plus `SQLITE_OPEN_READ_WRITE`
        // give a logical read-only invariant: WAL `-shm` access
        // works, but the engine rejects any mutation. A direct
        // attempt to INSERT through the reader's `&Connection`
        // must fail at the SQLite engine, not silently succeed.
        let (_tmp, dir, _writer) = fresh_writer_with_dir();
        let pool = LocalStoreReaderPool::open(&db_file(&dir), &test_key(), 1).unwrap();
        let outcome: DbResult<()> = pool.with_reader(|r| {
            r.connection().execute(
                "INSERT INTO conversation (
                        conversation_id, title_cipher, pinned, muted,
                        last_activity_ms, conversation_type, scope
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params!["conv-X", vec![0u8; 16], 0i64, 0i64, 1i64, "dm", "b2c"],
            )?;
            Ok(())
        });
        let err = outcome.expect_err("read-only connection must reject INSERT");
        let msg = format!("{err}");
        assert!(
            msg.contains("readonly") || msg.contains("read-only") || msg.contains("READONLY"),
            "expected SQLITE_READONLY-style error, got: {msg}"
        );
    }

    #[test]
    fn pool_with_reader_returns_reader_after_panic() {
        // The drop-guard in `with_reader` must return the reader
        // to the pool even if the closure panics — otherwise a
        // single panic would permanently leak a slot.
        let (_tmp, dir, _writer) = fresh_writer_with_dir();
        let pool = LocalStoreReaderPool::open(&db_file(&dir), &test_key(), 1).unwrap();
        let pool_ref = &pool;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool_ref.with_reader(|_r| panic!("simulated reader failure"))
        }));
        assert!(result.is_err(), "panic must propagate");
        // The slot must be back in the pool — a subsequent
        // checkout must succeed without blocking forever.
        assert_eq!(pool.slots.lock().unwrap().len(), 1);
        let count = pool.with_reader(|r| r.list_conversations()).unwrap();
        assert_eq!(count.len(), 0);
    }

    #[test]
    fn pool_blocks_on_checkout_when_all_readers_in_use() {
        // With capacity=1, the second `with_reader` call must
        // wait on the condvar until the first releases the slot.
        // We synchronise the two threads with a parking_lot-like
        // pair so the race is deterministic.
        use std::sync::Arc;
        use std::time::Duration;

        let (_tmp, dir, _writer) = fresh_writer_with_dir();
        let pool = Arc::new(LocalStoreReaderPool::open(&db_file(&dir), &test_key(), 1).unwrap());

        // Channels: t1_has_slot -> "thread 1 has checked out
        // the reader"; t2_started -> "thread 2 has been
        // scheduled".
        let (t1_has_slot_tx, t1_has_slot_rx) = std::sync::mpsc::channel::<()>();
        let (t2_done_tx, t2_done_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let pool_t1 = Arc::clone(&pool);
        let t1 = std::thread::spawn(move || {
            pool_t1.with_reader(|_r| {
                t1_has_slot_tx.send(()).unwrap();
                // Block until the test signals release.
                release_rx.recv().unwrap();
            });
        });

        // Wait for thread 1 to check out the only reader.
        t1_has_slot_rx.recv().unwrap();

        let pool_t2 = Arc::clone(&pool);
        let t2 = std::thread::spawn(move || {
            pool_t2.with_reader(|r| {
                // Verify the reader is usable.
                let _ = r.list_conversations().unwrap();
            });
            t2_done_tx.send(()).unwrap();
        });

        // Thread 2 must NOT complete while thread 1 holds the
        // slot. Give the scheduler a moment, then assert.
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            t2_done_rx.try_recv().is_err(),
            "thread 2 must block on checkout while thread 1 holds the only reader"
        );

        // Release thread 1; thread 2 should now complete.
        release_tx.send(()).unwrap();
        t2_done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("thread 2 must wake on checkin");
        t1.join().unwrap();
        t2.join().unwrap();
    }

    #[test]
    fn reader_pool_serves_concurrent_reads_alongside_writer() {
        // The end-to-end win we're after: a writer can commit
        // a transaction while N readers run SELECTs in parallel,
        // all observing a consistent snapshot. We're not trying
        // to measure throughput here — just to verify the
        // pool's threading model holds together under load.
        use std::sync::Arc;

        let (_tmp, dir, writer) = fresh_writer_with_dir();
        for i in 0..8 {
            writer
                .insert_conversation(&sample_conversation(&format!("conv-{i}"), 1_000 + i as i64))
                .unwrap();
        }
        let pool = Arc::new(LocalStoreReaderPool::open(&db_file(&dir), &test_key(), 4).unwrap());
        let mut handles = Vec::new();
        for _ in 0..16 {
            let pool = Arc::clone(&pool);
            handles.push(std::thread::spawn(move || {
                let rows = pool.with_reader(|r| r.list_conversations()).unwrap();
                assert_eq!(rows.len(), 8);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
