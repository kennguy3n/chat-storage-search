//! Desktop (macOS / Windows) consumer crate for kchat-core.
//!
//! Phase 7 (2026-05-04 batch): the platform-specific integration
//! scaffolds live in [`macos`] and [`windows`]. Both modules are
//! compiled on every host so unit tests can exercise the
//! object-safety and noop-bridge behaviour without spinning up
//! the actual platform runtime. The desktop orchestration layer
//! is responsible for installing only the bridge that matches
//! the running OS — see `docs/PROPOSAL.md §7.4`.
//!
//! `pub use kchat_core as core` keeps the Phase-0 re-export so
//! downstream desktop binaries can already depend on this crate
//! and reach the rest of kchat-core through a stable name.

pub use kchat_core as core;

pub mod macos;
pub mod windows;
