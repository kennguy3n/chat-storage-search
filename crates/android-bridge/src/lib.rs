//! Android JNI bridge for kchat-core.
//!
//! Phase 0 placeholder: re-exports the core crate so downstream
//! tooling can already depend on the bridge crate. JNI scaffolding
//! lands in Phase 1 alongside the public API surface.

pub use kchat_core as core;
