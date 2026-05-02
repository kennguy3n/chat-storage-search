//! `local_store` module — encrypted on-device storage surface.
//!
//! Phase 1 foundation lands here:
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
//! Keystore / DPAPI) land later in Phase 1 — see `docs/PHASES.md`.

pub mod schema;
pub mod state_machines;
