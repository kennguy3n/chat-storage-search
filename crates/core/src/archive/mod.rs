//! `archive` module — personal cold-storage pipeline.
//!
//! Of deliverables:
//!
//! * [`event_journal`] — append-only log of every durable mutation
//!   that should ride into the next archive segment.
//! * [`segment_builder`] — packs journal events into AEAD-sealed,
//!   per-conversation, per-time-bucket archive segments.
//!
//! See `docs/ARCHITECTURE.md §8` for the build / replay protocol
//! and `docs/DESIGN.md §6` for the wire-format / key-hierarchy
//! specification.

pub mod body_payload;
pub mod compaction;
pub(crate) mod coordinator;
pub mod download;
pub mod epoch_keys;
pub mod event_journal;
pub mod manifest_builder;
pub mod prefetch;
pub mod privacy;
pub mod routing;
pub mod segment_builder;
pub mod upload;
