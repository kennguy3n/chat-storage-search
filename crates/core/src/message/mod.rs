//! `message` module — send / receive pipeline.
//!
//! Phase 1 lands the [`processor`] skeleton: pure-Rust validators,
//! the `IngestedMessage` / `OutboxEntry` / `IngestResult` shapes,
//! and the `MessageProcessor` placeholder that the SQLCipher-backed
//! implementation will fill in. The actual prepared-statement /
//! transaction work lands with the `local_store` SQLCipher
//! integration — see `docs/PHASES.md`.

pub mod processor;
