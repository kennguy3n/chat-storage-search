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
//! (Phase A.3). **Desktop binaries opt in** to seeing them by
//! calling [`install_tracing_subscriber`] once on startup —
//! unlike the iOS and Android bridges which auto-install on the
//! first `KChatCore::new` / `KChatBridgeHandle::initialize`, the
//! desktop crate is the asymmetric case because Tauri / Slint /
//! Electron+napi hosts routinely arrive with their own
//! `tracing-subscriber` (or a custom OTEL pipeline) already
//! installed, and silently overwriting it from a `kchat-core`
//! constructor would be a surprise.
//!
//! A host that wants kchat-core spans surfaced on stderr should:
//!
//! ```no_run
//! # fn main() {
//! kchat_desktop::install_tracing_subscriber();
//! // ... continue building your Tauri / Slint / Electron app
//! # }
//! ```
//!
//! Forgetting the call is fine — the spans become silent no-ops,
//! same as the `tracing` default. Per-crate filter targets are
//! `kchat_core` and `kchat_desktop` (Cargo converts crate-name
//! hyphens to underscores when forming the target name).
//! `EnvFilter` uses `::` as the hierarchy separator and does not
//! support glob expansion, so each crate must be enumerated
//! explicitly when filtering. Examples:
//!
//! * `RUST_LOG=kchat_core=debug` — everything from `kchat_core`
//!   and its modules (e.g. `kchat_core::embeddings`) at debug.
//! * `RUST_LOG=kchat_core=info,kchat_desktop=debug` — keep core
//!   at the default and crank up the desktop bridge.
//! * `RUST_LOG=kchat_core::embeddings=debug` — narrow to just
//!   the embedder code path.
//!
//! If the binary has already installed its own subscriber the
//! call is a no-op (`try_init` swallows the duplicate-install
//! error).

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
/// **This is the desktop opt-in hook.** Unlike the iOS / Android
/// bridges (which call their own internal `install_tracing_subscriber`
/// from `KChatCore::new` / `KChatBridgeHandle::initialize`),
/// desktop binaries must call this function explicitly on startup
/// to see any tracing output from `kchat-core`. Forgetting the
/// call is not a bug — the spans simply remain silent, same as
/// the `tracing` default. See the crate-level docs for filter
/// examples.
///
/// Idempotent — safe to call from multiple desktop binary
/// entrypoints (main app, helper, indexer worker). The first
/// caller wins; subsequent calls are no-ops. The filter respects
/// the `RUST_LOG` env var (default `info`).
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
