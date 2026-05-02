//! Key-wrapping primitives.
//!
//! Phase 0 stub. Phase 1 will land:
//! * `K_local_db` wrapping by Keychain (iOS / macOS), Keystore
//!   (Android), or DPAPI (Windows).
//! * `K_asset` wrapping by `K_archive_root` and `K_backup_root` for
//!   per-media-object archive and backup paths.
//!
//! See `docs/PROPOSAL.md §2.2` for the platform-specific posture.
