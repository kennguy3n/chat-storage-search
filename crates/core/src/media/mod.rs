//! `media` module — Phase 0 stub.
//!
//! Implementation lands in a later phase. See `docs/PHASES.md` for
//! the schedule.
//!
//! [`sinks`] holds the [`sinks::MediaBlobSink`] trait surface that
//! routes media-original uploads / downloads to the configured
//! storage backend (KChat backend, iCloud, Google Drive, or ZK
//! Object Fabric). See `docs/PROPOSAL.md §5.7` for the tiered
//! media storage model.

pub mod sinks;
