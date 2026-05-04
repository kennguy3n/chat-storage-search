//! `WindowsSearchAnchor` trait + `NoopWindowsSearchAnchor`
//! implementation for Windows Search protocol-handler
//! integration (Phase 7, batch-5 — 2026-05-04).
//!
//! `docs/PROPOSAL.md §7.4` calls for the Windows Search protocol
//! handler equivalent of macOS Spotlight: the system-wide search
//! bar surfaces kchat messages by URL anchor without dragging
//! plaintext into the system search index.
//!
//! This module is the fine-grained anchor surface; the older
//! placeholder bridge in [`crate::windows`] continues to exist
//! for the bulk-indexing contract until the production wiring
//! lands.

use kchat_core::Error;

/// Object-safe outbound trait the desktop orchestration layer
/// calls into for Windows Search integration. `Send + Sync` so
/// the bridge can sit inside an `Arc<dyn WindowsSearchAnchor>`.
pub trait WindowsSearchAnchor: Send + Sync + std::fmt::Debug {
    /// Write or replace the Windows Search protocol-handler
    /// entry for `message_id`. `display_text` carries the redacted
    /// preview the indexer should expose.
    fn index_message(&self, message_id: &str, display_text: &str) -> Result<(), Error>;

    /// Remove the protocol-handler entry for `message_id`.
    /// Idempotent — deindexing an unknown id must succeed.
    fn deindex_message(&self, message_id: &str) -> Result<(), Error>;

    /// Build the protocol-handler anchor string the desktop URL
    /// handler routes back into the kchat app. Production
    /// implementations build a `kchat://message/<id>` URL; the
    /// noop returns the message id verbatim.
    fn search_anchor(&self, message_id: &str) -> Result<String, Error>;
}

/// `WindowsSearchAnchor` placeholder used on hosts where the
/// Windows Search runtime is not available (macOS / Linux CI,
/// headless test matrix).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopWindowsSearchAnchor;

impl NoopWindowsSearchAnchor {
    /// `const fn` constructor.
    pub const fn new() -> Self {
        Self
    }
}

impl WindowsSearchAnchor for NoopWindowsSearchAnchor {
    fn index_message(&self, _message_id: &str, _display_text: &str) -> Result<(), Error> {
        Err(Error::NotImplemented("windows_search_anchor"))
    }

    fn deindex_message(&self, _message_id: &str) -> Result<(), Error> {
        Ok(())
    }

    fn search_anchor(&self, message_id: &str) -> Result<String, Error> {
        Ok(message_id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn windows_search_anchor_is_object_safe_through_arc_dyn() {
        let anchor: Arc<dyn WindowsSearchAnchor> = Arc::new(NoopWindowsSearchAnchor::new());
        let err = anchor.index_message("msg-1", "preview").unwrap_err();
        assert!(matches!(
            err,
            Error::NotImplemented("windows_search_anchor")
        ));
    }

    #[test]
    fn noop_deindex_is_idempotent_and_succeeds() {
        let anchor = NoopWindowsSearchAnchor::new();
        anchor.deindex_message("missing-id").unwrap();
    }

    #[test]
    fn noop_search_anchor_echoes_message_id() {
        let anchor = NoopWindowsSearchAnchor::new();
        assert_eq!(anchor.search_anchor("msg-42").unwrap(), "msg-42");
    }
}
