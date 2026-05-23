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
//!
//! ## Tracing
//!
//! `kchat-core` emits `tracing` spans / events on every hot path
//! (Phase A.3). The desktop crate exposes
//! [`install_tracing_subscriber`] for the host binary (Tauri /
//! Slint / Electron+napi) to call once on startup; it installs a
//! plain stderr fmt subscriber driven by the `RUST_LOG` env var
//! (per-crate targets: `kchat_core`, `kchat_desktop`). If the
//! binary has already installed its own subscriber the call is a
//! no-op (`try_init` swallows the duplicate-install error).

pub use kchat_core as core;

pub mod background;
pub mod macos;
pub mod ml_ep;
pub mod spotlight;
pub mod windows;
pub mod windows_search;

use std::sync::Once;

static TRACING_INIT: Once = Once::new();

/// Install a `tracing` subscriber that routes `kchat-core` spans
/// and events to stderr.
///
/// Idempotent — safe to call from multiple desktop binary
/// entrypoints (main app, helper, indexer worker). The first
/// caller wins; subsequent calls are no-ops. The filter respects
/// the `RUST_LOG` env var.
pub fn install_tracing_subscriber() {
    use tracing_subscriber::filter::EnvFilter;
    use tracing_subscriber::util::SubscriberInitExt;

    TRACING_INIT.call_once(|| {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .finish()
            .try_init();
    });
}
