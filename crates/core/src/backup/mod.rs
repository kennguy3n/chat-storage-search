//! `backup` — Phase 4 backup pipeline.
//!
//! See `docs/PROPOSAL.md §6` (cloud backup) and `docs/PHASES.md`
//! Phase 4 for the high-level design. The module is structured
//! around the same pattern the archive pipeline uses on
//! [`crate::archive`]:
//!
//! * [`event_journal`] — append-only log of durable mutations
//!   plus a single-row cursor advanced by the segment builder.
//! * [`segment_builder`] — drains the journal, packs unsegmented
//!   events into a CBOR + zstd + AEAD-sealed segment.
//! * [`manifest_builder`] — Ed25519-signed, generation-chained
//!   manifest covering one or more segments.
//! * [`compaction`] — daily → weekly → monthly compaction policy
//!   that re-emits compact segments and supersedes older ones.

pub mod compaction;
pub mod event_journal;
pub mod manifest_builder;
pub mod segment_builder;
