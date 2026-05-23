//! `local_store` module — encrypted on-device storage surface.
//!
//! Foundation lands here:
//!
//! * [`schema`] — the SQLCipher CREATE TABLE statements
//!   (`SCHEMA_SQL`) plus the typed Rust row structs that mirror them
//!   1:1 (`Conversation`, `MessageSkeleton`, `MessageBody`,
//!   `MediaAsset`, `BackupEventJournalEntry`, `ArchiveSegmentMapEntry`,
//!   `RestoreStateEntry`).
//! * [`state_machines`] — the `body_state` / `media_state` /
//!   `archive_state` / `backup_state` / `restore_state` enums with
//!   `try_transition`, `Display` / `FromStr`, and serde support.
//!
//! The actual `rusqlite::Connection` bindings, prepared-statement
//! cache, migrations, and platform `K_local_db` wrap (Keychain /
//! Keystore / DPAPI) land later in — see.

pub mod db;
pub mod schema;
pub mod state_machines;

/// Storage-layer error type wrapped by [`crate::Error::Storage`].
///
/// Callers may pattern-match on the specific failure mode without
/// parsing free-form text. The reader pool distinguishes
/// [`StorageError::LockPoisoned`] from [`StorageError::Sqlite`], and
/// tests assert on [`StorageError::SubsystemNotInstalled`] instead
/// of `msg.to_string.contains("not installed")`.
///
/// The [`StorageError::DatabaseLocked`] / [`StorageError::DiskFull`]
/// variants exist for retry-loop callers that want to route on
/// `SQLITE_BUSY`/`SQLITE_LOCKED`/`SQLITE_FULL` without inspecting the
/// underlying [`rusqlite::Error`] extended code — see
/// [`classify_rusqlite`] for the opt-in promoter. No caller does this
/// today; the variants are reserved for the async-conversion wave
/// where the writer mutex becomes a tokio mutex with explicit retry
/// semantics.
///
/// # Construction
///
/// Most variants come from `#[from]` conversions so call sites that
/// previously did `.map_err(|e| Error::Storage(e.to_string.into))?`
/// can use the `?` operator directly once they switch to the typed
/// form:
///
/// ```ignore
/// // legacy form (still compiles via `From<String>`)
/// stmt.execute(params![..])
///.map_err(|e| Error::Storage(e.to_string.into))?;
/// // typed form (preferred)
/// stmt.execute(params![..])?;
/// ```
///
/// [`StorageError::Custom`] is the fallback for sites whose context
/// is a free-form string today; new code should prefer a typed
/// variant.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A SQLCipher / rusqlite call failed (driver error, statement
    /// prep error, prepared-statement type mismatch, …). Includes
    /// the upstream [`rusqlite::Error`] verbatim for diagnostics.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The SQLCipher driver returned `SQLITE_BUSY` / `SQLITE_LOCKED`.
    /// Callers in a retry loop should pattern-match this variant
    /// instead of the underlying [`rusqlite::Error`] error code.
    #[error("database is locked")]
    DatabaseLocked,

    /// A schema migration failed mid-flight while moving the on-disk
    /// schema between recorded versions.
    #[error("migration failed from v{from} to v{to}: {detail}")]
    MigrationFailed {
        /// Schema version the migration started from.
        from: u32,
        /// Schema version the migration was attempting to reach.
        to: u32,
        /// Free-form detail captured from the failing statement.
        detail: String,
    },

    /// The SQLCipher driver reported the underlying volume is full
    /// (`SQLITE_FULL`).
    #[error("disk full")]
    DiskFull,

    /// A row decoded from a table failed an invariant check
    /// (unparseable enum value, malformed blob, foreign-key cycle,
    /// negative version counter, …).
    #[error("corrupt row in `{table}`: {detail}")]
    CorruptRow {
        /// Name of the table the bad row was read from.
        table: &'static str,
        /// Free-form detail describing the invariant violation.
        detail: String,
    },

    /// A non-SQL I/O failure (writing an ep-cache file, reading a
    /// model file, opening a savepoint stream, …).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A CBOR encode of a persisted / wire-format payload failed.
    /// `context` names the encode site so logs identify which payload.
    #[error("cbor encode ({context}): {source}")]
    CborEncode {
        /// Static label identifying the encode site (e.g.
        /// `"archive segment"`, `"manifest"`).
        context: &'static str,
        #[source]
        /// Upstream ciborium serializer error.
        source: ciborium::ser::Error<std::io::Error>,
    },

    /// A CBOR decode of a persisted / received wire-format payload
    /// failed. `context` names the decode site so logs identify
    /// which payload.
    #[error("cbor decode ({context}): {source}")]
    CborDecode {
        /// Static label identifying the decode site (e.g.
        /// `"archive segment"`, `"manifest"`).
        context: &'static str,
        #[source]
        /// Upstream ciborium deserializer error.
        source: ciborium::de::Error<std::io::Error>,
    },

    /// A `zstd` compress / decompress call failed. `context` names
    /// the call site (encode vs decode, which shard kind, etc.).
    #[error("zstd ({context}): {source}")]
    Zstd {
        /// Static label identifying the codec call site.
        context: &'static str,
        #[source]
        /// `zstd` surfaces its errors as [`std::io::Error`].
        source: std::io::Error,
    },

    /// A string-formatted UUID could not be parsed back into a
    /// [`uuid::Uuid`]. `kind` names which id failed to parse so
    /// callers can route on it (e.g. `"message_id"` vs
    /// `"conversation_id"` vs `"asset_id"`).
    #[error("invalid {kind}: {source}")]
    InvalidId {
        /// Which kind of identifier failed to parse.
        kind: &'static str,
        #[source]
        /// Upstream UUID-parse error.
        source: uuid::Error,
    },

    /// A subsystem that callers expected to be installed at boot
    /// (e.g. `"epoch_key_manager"`, `"transport"`, `"ocr_bridge"`)
    /// was not. Distinct from [`crate::Error::NotImplemented`] in
    /// that this fires after init has supposedly completed.
    #[error("subsystem `{0}` not installed")]
    SubsystemNotInstalled(&'static str),

    /// A subsystem that is installed exactly once at boot was
    /// installed twice. Surfaced from the `install_*` write-once
    /// setters on `CoreImpl`.
    #[error("subsystem `{0}` already installed (install is write-once)")]
    SubsystemAlreadyInstalled(&'static str),

    /// A `Mutex` / `RwLock` was poisoned by a panicking thread.
    /// Carries the resource name so callers can route on it
    /// (`"scheduler"`, `"dedup_analytics"`, `"LocalStoreDb"`, …).
    #[error("`{0}` lock poisoned")]
    LockPoisoned(&'static str),

    /// The device is currently offline. Surfaced by the offline
    /// detector when a hot-path read would otherwise have made a
    /// network call.
    #[error("offline")]
    Offline,

    /// Free-form fallback for sites where the underlying error type
    /// does not (yet) merit a dedicated variant. Existing
    /// `format!("...: {e}")` patterns map to this variant; new
    /// failure modes should prefer a typed variant instead.
    #[error("{0}")]
    Custom(String),
}

impl StorageError {
    /// Construct a [`StorageError::Custom`] from anything that can be
    /// converted into a [`String`]. Equivalent to
    /// `StorageError::Custom(msg.into)`; useful at call sites that
    /// previously did `Error::Storage(msg)`.
    pub fn msg(msg: impl Into<String>) -> Self {
        StorageError::Custom(msg.into())
    }
}

/// Promote a [`rusqlite::Error`] into a typed [`StorageError`] by
/// inspecting the extended error code: `SQLITE_BUSY` and
/// `SQLITE_LOCKED` become [`StorageError::DatabaseLocked`],
/// `SQLITE_FULL` becomes [`StorageError::DiskFull`], everything else
/// stays as [`StorageError::Sqlite`]. This is exposed as a free
/// function (not a `From` impl) so callers opt in: bulk `?` paths use
/// the default `From<rusqlite::Error>` impl that always produces
/// `Sqlite(_)`; retry loops that genuinely care about
/// `DatabaseLocked` call this explicitly.
pub fn classify_rusqlite(error: rusqlite::Error) -> StorageError {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(code, _) = &error {
        match code.code {
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                return StorageError::DatabaseLocked
            }
            ErrorCode::DiskFull => return StorageError::DiskFull,
            _ => {}
        }
    }
    StorageError::Sqlite(error)
}
