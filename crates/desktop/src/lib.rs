//! Desktop (macOS / Windows) consumer crate for kchat-core.
//!
//! Phase 0 placeholder: re-exports the core crate so downstream
//! desktop binaries can already depend on this crate. Native
//! integration (Spotlight anchors on macOS, Windows Search anchors)
//! lands in Phase 7.

pub use kchat_core as core;
