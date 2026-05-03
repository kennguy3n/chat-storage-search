//! `archive` module — Phase 3 personal cold-storage pipeline.
//!
//! Phase 3 of `docs/PHASES.md` deliverables:
//!
//! * [`event_journal`] — append-only log of every durable mutation
//!   that should ride into the next archive segment.
//! * [`segment_builder`] — packs journal events into AEAD-sealed,
//!   per-conversation, per-time-bucket archive segments.
//!
//! See `docs/ARCHITECTURE.md §8` for the build / replay protocol
//! and `docs/PROPOSAL.md §6` for the wire-format / key-hierarchy
//! specification.

pub mod event_journal;
pub mod segment_builder;
