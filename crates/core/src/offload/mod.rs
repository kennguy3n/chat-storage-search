//! `offload` module — storage-pressure enforcement.
//!
//! Of and `docs/DESIGN.md §5.4` lay out
//! how the local store keeps itself within its storage budget:
//!
//! * [`budget`] — observe storage usage, compare against a
//!   declared budget, surface the resulting [`PressureLevel`].
//! * [`scoring`] — score individual eviction candidates per the
//!   DESIGN.md §5.4 formula.
//! * [`eviction`] — turn a sorted list of candidates into an
//!   [`EvictionPlan`] and execute it via state-machine
//!   transitions on the local store.
//! * [`hydration`] — priority queue (P0..P5) that drives
//!   restoration of cold messages back into local storage.

pub mod budget;
pub mod eviction;
pub mod hydration;
pub mod scoring;

pub use budget::PressureLevel;
