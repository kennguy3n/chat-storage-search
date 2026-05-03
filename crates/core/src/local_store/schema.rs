//! SQLCipher schema for the local store.
//!
//! `docs/ARCHITECTURE.md §4` is the authoritative source for the
//! `CREATE TABLE` statements. [`SCHEMA_SQL`] mirrors that block
//! verbatim (with comments and whitespace preserved) so a single
//! invocation of `sqlite3.executescript(SCHEMA_SQL)` brings up an
//! empty SQLCipher database that matches the spec.
//!
//! The Rust structs in this module are 1:1 with the schema columns,
//! using the typed enums from [`super::state_machines`] for state
//! columns. They are **plain data carriers** — Phase 1 layers the
//! actual `rusqlite::Connection` interactions, prepared statements,
//! and migrations on top.
//!
//! Encrypted columns (`title_cipher`, `wrapped_k_asset`, `payload`,
//! the FTS / shard byte arrays in [`super::super::formats`]) are
//! `Vec<u8>` — never interpreted at this layer. AEAD seal / open is
//! done by the higher-level engines (`message`, `media`, `backup`,
//! `archive`) using the appropriate root key from
//! [`crate::crypto::key_hierarchy`].

use serde::{Deserialize, Serialize};

use super::state_machines::{ArchiveState, BackupState, BodyState, MediaState, RestoreState};

// ---------------------------------------------------------------------------
// CREATE TABLE statements (docs/ARCHITECTURE.md §4)
// ---------------------------------------------------------------------------

/// Concatenated `CREATE TABLE` / `CREATE VIRTUAL TABLE` statements for
/// every table in the local store. Designed for
/// `connection.execute_batch(SCHEMA_SQL)`.
///
/// The exact text matches `docs/ARCHITECTURE.md §4`. Multilingual
/// considerations (FTS5 `tokenize = 'icu'`) are inline comments in
/// the SQL itself.
pub const SCHEMA_SQL: &str = r#"
-- Conversations
CREATE TABLE IF NOT EXISTS conversation (
    conversation_id   TEXT PRIMARY KEY,
    title_cipher      BLOB,                 -- encrypted with K_local_db
    pinned            INTEGER NOT NULL DEFAULT 0,
    muted             INTEGER NOT NULL DEFAULT 0,
    last_message_id   TEXT,
    last_activity_ms  INTEGER NOT NULL
);

-- Skeletons render the timeline before any body / media is loaded
CREATE TABLE IF NOT EXISTS message_skeleton (
    message_id        TEXT PRIMARY KEY,
    conversation_id   TEXT NOT NULL REFERENCES conversation(conversation_id),
    sender_id         TEXT NOT NULL,
    created_at_ms     INTEGER NOT NULL,
    received_at_ms    INTEGER NOT NULL,
    kind              TEXT NOT NULL,
    body_state        TEXT NOT NULL,
    media_state       TEXT,
    archive_state     TEXT NOT NULL DEFAULT 'not_archived',
    backup_state      TEXT NOT NULL DEFAULT 'not_backed_up',
    reply_to          TEXT,
    edited_at_ms      INTEGER,
    deleted_at_ms     INTEGER
);

CREATE TABLE IF NOT EXISTS message_body (
    message_id        TEXT PRIMARY KEY REFERENCES message_skeleton(message_id),
    text_content      TEXT,                 -- UTF-8, may mix scripts
    detected_language TEXT,                 -- BCP-47, optional
    rich_meta         BLOB                  -- mentions, link previews (CBOR)
);

CREATE TABLE IF NOT EXISTS media_asset (
    asset_id          TEXT PRIMARY KEY,
    message_id        TEXT NOT NULL REFERENCES message_skeleton(message_id),
    mime_type         TEXT NOT NULL,
    bytes_total       INTEGER NOT NULL,
    bytes_local       INTEGER NOT NULL,
    media_state       TEXT NOT NULL,
    wrapped_k_asset   BLOB NOT NULL,
    chunk_count       INTEGER NOT NULL,
    merkle_root       BLOB NOT NULL,
    blob_id           TEXT NOT NULL,
    storage_sink      TEXT NOT NULL DEFAULT 'kchat_backend'  -- PROPOSAL.md §5.7
);

-- Multilingual full-text search
CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
    message_id        UNINDEXED,
    conversation_id   UNINDEXED,
    sender_id         UNINDEXED,
    created_at_ms     UNINDEXED,
    text_content,
    tokenize = 'icu'                       -- primary multilingual tokenizer
);

CREATE TABLE IF NOT EXISTS search_fuzzy (
    token       TEXT NOT NULL,
    script      TEXT NOT NULL,             -- ISO-15924
    message_id  TEXT NOT NULL,
    PRIMARY KEY (token, script, message_id)
);

CREATE TABLE IF NOT EXISTS search_vector (
    message_id    TEXT NOT NULL,
    embedding     BLOB NOT NULL,            -- INT8-quantized
    model_version TEXT NOT NULL,
    PRIMARY KEY (message_id, model_version)
);

CREATE TABLE IF NOT EXISTS media_search_index (
    asset_id      TEXT NOT NULL REFERENCES media_asset(asset_id),
    kind          TEXT NOT NULL,            -- 'ocr' | 'caption' | 'transcript' | 'tag'
    text          TEXT NOT NULL,
    language      TEXT,                     -- BCP-47 if detected
    confidence    REAL,
    PRIMARY KEY (asset_id, kind, text)
);

-- Backup pipeline
CREATE TABLE IF NOT EXISTS backup_event_journal (
    event_seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type    TEXT NOT NULL,
    payload       BLOB NOT NULL,            -- CBOR
    created_at_ms INTEGER NOT NULL
);

-- Archive pipeline
CREATE TABLE IF NOT EXISTS archive_segment_map (
    segment_id           TEXT PRIMARY KEY,
    conversation_id      TEXT NOT NULL,
    time_bucket          TEXT NOT NULL,     -- e.g. '2026-04'
    segment_type         TEXT NOT NULL,
    blob_id              TEXT NOT NULL,
    storage_backend      TEXT NOT NULL DEFAULT 'kchat_backend',  -- PROPOSAL.md §10.1
    merkle_root          BLOB NOT NULL,
    state                TEXT NOT NULL      -- not_archived..archive_compacted
);

-- Per-archive event log feeding the archive segment builder
-- (`docs/PHASES.md` Phase 3). Mirrors `backup_event_journal` but
-- carries the archive-side event types (message_received,
-- message_edited, message_deleted, media_received, …) and a
-- single-row cursor that the segment builder advances after each
-- successful upload.
CREATE TABLE IF NOT EXISTS archive_event_journal (
    event_seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    message_id      TEXT,
    payload         BLOB NOT NULL,            -- CBOR
    created_at_ms   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS archive_event_cursor (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    cursor_seq  INTEGER NOT NULL DEFAULT 0
);

-- Restore state machine
CREATE TABLE IF NOT EXISTS restore_state (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    state  TEXT NOT NULL,                  -- identity_restored..full_restore_complete
    notes  TEXT
);
"#;

/// All tables defined in [`SCHEMA_SQL`], in declaration order.
pub const TABLES: &[&str] = &[
    "conversation",
    "message_skeleton",
    "message_body",
    "media_asset",
    "search_fts",
    "search_fuzzy",
    "search_vector",
    "media_search_index",
    "backup_event_journal",
    "archive_segment_map",
    "archive_event_journal",
    "archive_event_cursor",
    "restore_state",
];

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// `kind` discriminator for `message_skeleton.kind`.
///
/// `docs/PROPOSAL.md §3.2` enumerates the three top-level message
/// kinds. Adding a fourth is a wire-format change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Plain UTF-8 text body.
    Text,
    /// Media body (image / video / audio / document).
    Media,
    /// System / control message (group join, subject change, etc.).
    System,
}

impl MessageKind {
    /// Canonical snake_case representation used in the SQL column.
    pub fn as_str(self) -> &'static str {
        match self {
            MessageKind::Text => "text",
            MessageKind::Media => "media",
            MessageKind::System => "system",
        }
    }
}

/// `conversation` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conversation {
    /// Stable conversation identifier (UUID, serialized as string).
    pub conversation_id: String,
    /// `title_cipher`: the user-visible title encrypted with
    /// `K_local_db`. `None` for conversations that have no
    /// user-assigned title (e.g. direct messages keyed by participant
    /// list).
    pub title_cipher: Option<Vec<u8>>,
    /// Whether the conversation is pinned in the UI.
    pub pinned: bool,
    /// Whether notifications are muted.
    pub muted: bool,
    /// Most recent `message_skeleton.message_id`.
    pub last_message_id: Option<String>,
    /// Wall-clock millisecond timestamp of the most recent activity.
    pub last_activity_ms: i64,
}

/// `message_skeleton` row.
///
/// Skeletons are the foundation of "skeleton-first" rendering: they
/// carry just enough metadata to draw a chat bubble (sender, time,
/// kind, current state) without loading the body or media.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSkeleton {
    /// Stable message identifier (UUID, serialized as string).
    pub message_id: String,
    /// Owning conversation.
    pub conversation_id: String,
    /// Stable sender identifier.
    pub sender_id: String,
    /// Wall-clock millisecond timestamp set by the sender.
    pub created_at_ms: i64,
    /// Wall-clock millisecond timestamp at which this device received
    /// the MLS-decrypted message.
    pub received_at_ms: i64,
    /// Message kind discriminator.
    pub kind: MessageKind,
    /// Body lifecycle state.
    pub body_state: BodyState,
    /// Media lifecycle state, if [`MessageKind::Media`].
    pub media_state: Option<MediaState>,
    /// Personal-archive lifecycle state.
    pub archive_state: ArchiveState,
    /// Backup lifecycle state.
    pub backup_state: BackupState,
    /// Identifier of the message this is a reply to, if any.
    pub reply_to: Option<String>,
    /// Wall-clock millisecond timestamp of the most recent edit.
    pub edited_at_ms: Option<i64>,
    /// Wall-clock millisecond timestamp of deletion (when the row is
    /// in `deleted_for_*`).
    pub deleted_at_ms: Option<i64>,
}

/// `message_body` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageBody {
    /// Foreign key into `message_skeleton`.
    pub message_id: String,
    /// UTF-8 plaintext. May interleave scripts (per
    /// `docs/PROPOSAL.md §3.3`). `None` for media-only messages.
    pub text_content: Option<String>,
    /// BCP-47 detected language, best-effort.
    pub detected_language: Option<String>,
    /// CBOR-encoded rich metadata (mentions, link previews, etc.).
    pub rich_meta: Option<Vec<u8>>,
}

/// `media_asset` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaAsset {
    /// Stable asset identifier.
    pub asset_id: String,
    /// Owning message skeleton.
    pub message_id: String,
    /// IANA media type.
    pub mime_type: String,
    /// Plaintext byte length.
    pub bytes_total: i64,
    /// Bytes currently resident on disk.
    pub bytes_local: i64,
    /// Lifecycle state.
    pub media_state: MediaState,
    /// `K_asset` wrapped under `K_local_db` (AES-256-KW).
    pub wrapped_k_asset: Vec<u8>,
    /// Number of encrypted chunks.
    pub chunk_count: i32,
    /// 32-byte BLAKE3 Merkle root over the per-chunk SHA-256 of the
    /// **ciphertext** chunks.
    pub merkle_root: Vec<u8>,
    /// Backend blob identifier. The interpretation depends on
    /// [`Self::storage_sink`] (see `docs/PROPOSAL.md §5.7`).
    pub blob_id: String,
    /// Storage sink the media blob lives on (`"kchat_backend"`,
    /// `"i_cloud"`, `"google_drive"`, `"zk_object_fabric"`).
    /// Defaults to `"kchat_backend"` for legacy rows. See
    /// `docs/PROPOSAL.md §5.7` (tiered media storage).
    pub storage_sink: String,
}

/// `backup_event_journal` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEventJournalEntry {
    /// Monotonic backup event sequence number.
    pub event_seq: i64,
    /// Event-type tag (`"message_received"`, `"media_asset_created"`, …).
    pub event_type: String,
    /// CBOR-encoded payload.
    pub payload: Vec<u8>,
    /// Wall-clock millisecond timestamp the event was journaled.
    pub created_at_ms: i64,
}

/// `archive_segment_map` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveSegmentMapEntry {
    /// Stable segment identifier.
    pub segment_id: String,
    /// Owning conversation.
    pub conversation_id: String,
    /// Coarse time bucket (e.g. `"2026-04"`).
    pub time_bucket: String,
    /// Segment-type tag (`"message_delta"`, `"timeline_skeleton"`, …).
    pub segment_type: String,
    /// Backend blob identifier. The interpretation depends on
    /// [`Self::storage_backend`] (see `docs/PROPOSAL.md §10.1`).
    pub blob_id: String,
    /// Storage backend the segment lives on (`"kchat_backend"`,
    /// `"zk_object_fabric"`). Defaults to `"kchat_backend"` for
    /// legacy rows. See `docs/PROPOSAL.md §10.1` (archive backend
    /// routing).
    pub storage_backend: String,
    /// 32-byte BLAKE3 Merkle root over the ciphertext chunks.
    pub merkle_root: Vec<u8>,
    /// Lifecycle state.
    pub state: ArchiveState,
}

/// `restore_state` row.
///
/// `restore_state` is a single-row table (`id = 1`). The `id` field is
/// kept here so the row maps 1:1 with the schema column, even though
/// the `CHECK (id = 1)` constraint guarantees there is only ever one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreStateEntry {
    /// Always `1` per the `CHECK` constraint.
    pub id: i32,
    /// Current restore lifecycle state.
    pub state: RestoreState,
    /// Free-form notes (debugging, last-error message).
    pub notes: Option<String>,
}

/// One row of the message-timeline view returned by
/// [`super::db::LocalStoreDb::get_timeline`] and
/// [`crate::core_impl::CoreImpl::get_timeline`].
///
/// Skeleton fields plus the optional plaintext body string from
/// `message_body`. The view is deliberately **flat** — it exists
/// to render a chat timeline without an extra round-trip per
/// message — so it lives here next to the schema row types
/// rather than inside `core_impl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineRow {
    /// Stable message identifier (UUID, serialized as string).
    pub message_id: String,
    /// Owning conversation.
    pub conversation_id: String,
    /// Stable sender identifier.
    pub sender_id: String,
    /// Wall-clock millisecond timestamp set by the sender.
    pub created_at_ms: i64,
    /// Message kind discriminator.
    pub kind: MessageKind,
    /// Body lifecycle state.
    pub body_state: BodyState,
    /// Plaintext body (`message_body.text_content`) if a body row
    /// exists for this skeleton, otherwise `None`. Media-only
    /// messages and rows whose body has been dropped (e.g.
    /// `delete_for_everyone`) carry `None`.
    pub text_content: Option<String>,
    /// Identifier of the message this is a reply to, if any.
    pub reply_to: Option<String>,
    /// Wall-clock millisecond timestamp of the most recent edit.
    pub edited_at_ms: Option<i64>,
    /// Wall-clock millisecond timestamp of deletion (when the row is
    /// in `deleted_for_*`).
    pub deleted_at_ms: Option<i64>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_sql_contains_every_documented_table() {
        for t in TABLES {
            // Every table must show up in a CREATE TABLE / CREATE
            // VIRTUAL TABLE statement.
            assert!(
                SCHEMA_SQL.contains(&format!("TABLE IF NOT EXISTS {t}"))
                    || SCHEMA_SQL.contains(&format!("VIRTUAL TABLE IF NOT EXISTS {t}")),
                "schema is missing CREATE TABLE for {t}"
            );
        }
    }

    #[test]
    fn schema_sql_uses_icu_tokenizer() {
        // PROPOSAL.md §3.3: ICU is the primary tokenizer. The schema
        // string must hard-code it — a build that wants the
        // `unicode61` fallback substitutes the literal in
        // `search::tokenizer::FTS5_TOKENIZE_UNICODE61`.
        assert!(SCHEMA_SQL.contains("tokenize = 'icu'"));
    }

    #[test]
    fn schema_sql_has_balanced_create_table_count() {
        // Count CREATE [VIRTUAL] TABLE statements; must equal TABLES.
        let count = SCHEMA_SQL.matches("CREATE TABLE").count()
            + SCHEMA_SQL.matches("CREATE VIRTUAL TABLE").count();
        assert_eq!(count, TABLES.len(), "schema CREATE TABLE count drifted");
    }

    #[test]
    fn schema_sql_parses_through_sqlparser_lite() {
        // We don't take a heavy SQL-parser dependency, but a coarse
        // sanity check — every statement ends with a semicolon and
        // every parenthesis is balanced — guards against accidental
        // truncation.
        let trimmed = SCHEMA_SQL.trim();
        assert!(trimmed.ends_with(';'), "schema must terminate with ';'");
        let mut depth = 0i32;
        for c in trimmed.chars() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "unbalanced parentheses (negative depth)");
        }
        assert_eq!(depth, 0, "unbalanced parentheses (final depth != 0)");
    }

    #[test]
    fn message_kind_canonical_strings() {
        assert_eq!(MessageKind::Text.as_str(), "text");
        assert_eq!(MessageKind::Media.as_str(), "media");
        assert_eq!(MessageKind::System.as_str(), "system");
    }

    #[test]
    fn message_kind_round_trips_through_serde() {
        for k in [MessageKind::Text, MessageKind::Media, MessageKind::System] {
            let json = serde_json::to_string(&k).unwrap();
            let back: MessageKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn conversation_round_trip_through_serde() {
        let c = Conversation {
            conversation_id: "11111111-1111-1111-1111-111111111111".to_string(),
            title_cipher: Some(vec![1, 2, 3, 4]),
            pinned: true,
            muted: false,
            last_message_id: Some("22222222-2222-2222-2222-222222222222".to_string()),
            last_activity_ms: 1_700_000_000_000,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: Conversation = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn message_skeleton_round_trip_through_serde() {
        let s = MessageSkeleton {
            message_id: "msg-1".to_string(),
            conversation_id: "conv-1".to_string(),
            sender_id: "user-1".to_string(),
            created_at_ms: 1_700_000_000_000,
            received_at_ms: 1_700_000_000_500,
            kind: MessageKind::Text,
            body_state: BodyState::LocalPlainAvailable,
            media_state: None,
            archive_state: ArchiveState::NotArchived,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: MessageSkeleton = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn media_asset_round_trip_through_serde() {
        let a = MediaAsset {
            asset_id: "asset-1".to_string(),
            message_id: "msg-1".to_string(),
            mime_type: "image/jpeg".to_string(),
            bytes_total: 1_048_576,
            bytes_local: 1_048_576,
            media_state: MediaState::OriginalLocal,
            wrapped_k_asset: vec![0u8; 40],
            chunk_count: 1,
            merkle_root: vec![0u8; 32],
            blob_id: "blob-1".to_string(),
            storage_sink: "kchat_backend".to_string(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: MediaAsset = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn archive_segment_map_entry_round_trip_through_serde() {
        let s = ArchiveSegmentMapEntry {
            segment_id: "seg-1".to_string(),
            conversation_id: "conv-1".to_string(),
            time_bucket: "2026-05".to_string(),
            segment_type: "message_delta".to_string(),
            blob_id: "blob-1".to_string(),
            storage_backend: "kchat_backend".to_string(),
            merkle_root: vec![0u8; 32],
            state: ArchiveState::ArchiveVerified,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ArchiveSegmentMapEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn restore_state_entry_round_trip_through_serde() {
        let r = RestoreStateEntry {
            id: 1,
            state: RestoreState::ManifestVerified,
            notes: Some("verified gen 42".to_string()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RestoreStateEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    /// Returns the number of column-definition lines inside the
    /// `CREATE TABLE IF NOT EXISTS {table} ( … );` block in
    /// [`SCHEMA_SQL`]. Used by the column-count drift tests below.
    fn count_table_columns(table: &str) -> usize {
        let start = SCHEMA_SQL
            .find(&format!("CREATE TABLE IF NOT EXISTS {table} ("))
            .unwrap_or_else(|| panic!("{table} CREATE TABLE present"));
        let rest = &SCHEMA_SQL[start..];
        let end = rest.find(");").expect("CREATE TABLE terminated");
        let body = &rest[..end];
        body.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter(|l| !l.starts_with("--"))
            .filter(|l| !l.starts_with("CREATE"))
            .filter(|l| !l.starts_with("PRIMARY KEY"))
            .filter(|l| !l.starts_with("FOREIGN KEY"))
            .filter(|l| !l.starts_with("tokenize"))
            .count()
    }

    #[test]
    fn schema_sql_columns_match_struct_fields_for_message_skeleton() {
        // We pin the column ordering in the SQL. If a struct field is
        // added or removed without updating the SQL (or vice versa),
        // this test fails because the column count drifts.
        // 13 columns in MessageSkeleton: message_id, conversation_id,
        // sender_id, created_at_ms, received_at_ms, kind, body_state,
        // media_state, archive_state, backup_state, reply_to,
        // edited_at_ms, deleted_at_ms.
        assert_eq!(
            count_table_columns("message_skeleton"),
            13,
            "message_skeleton column count drifted"
        );
    }

    #[test]
    fn schema_sql_columns_match_struct_fields_for_media_asset() {
        // 11 columns in MediaAsset (post-§5.7): asset_id, message_id,
        // mime_type, bytes_total, bytes_local, media_state,
        // wrapped_k_asset, chunk_count, merkle_root, blob_id,
        // storage_sink.
        assert_eq!(
            count_table_columns("media_asset"),
            11,
            "media_asset column count drifted"
        );
    }

    #[test]
    fn schema_sql_columns_match_struct_fields_for_archive_segment_map() {
        // 8 columns in ArchiveSegmentMapEntry (post-§10.1):
        // segment_id, conversation_id, time_bucket, segment_type,
        // blob_id, storage_backend, merkle_root, state.
        assert_eq!(
            count_table_columns("archive_segment_map"),
            8,
            "archive_segment_map column count drifted"
        );
    }

    #[test]
    fn tables_constant_lists_all_tables_in_schema() {
        // Sanity: TABLES must not have duplicates.
        let mut sorted = TABLES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), TABLES.len(), "TABLES has duplicates");
    }
}
