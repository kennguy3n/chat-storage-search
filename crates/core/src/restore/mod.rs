//! `restore` — Phase-4 restore pipeline.
//!
//! The module orchestrates the **skeleton-first** restore strategy
//! described in `docs/PROPOSAL.md §11` and `docs/PHASES.md`
//! Phase 4. It is split into three focused submodules:
//!
//! * [`state_machine`] — DB-backed
//!   [`crate::local_store::state_machines::RestoreState`] persistence
//!   helpers. The state enum itself lives in `state_machines.rs`
//!   so backup/restore + persistence agree on a single source of
//!   truth.
//! * [`manifest_verifier`] — walks the manifest chain from genesis
//!   to the latest manifest, verifying every Ed25519 signature
//!   and every `previous_manifest_hash` link.
//! * [`pipeline`] — drives the priority-ordered restore: clone
//!   conversations → skeleton timeline → search shards → recent
//!   bodies → enable lazy media restore.

pub mod manifest_verifier;
pub mod pipeline;
pub mod state_machine;
