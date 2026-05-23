//! `backup` — backup pipeline.
//!
//! See `docs/DESIGN.md §6` for the high-level design. The module
//! is structured around the same pattern the archive pipeline
//! uses in [`crate::archive`]:
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
pub(crate) mod coordinator;
pub mod event_journal;
pub mod manifest_builder;
pub mod segment_builder;
pub mod sinks;
