//! `SpotlightAnchor` trait + `NoopSpotlightAnchor` implementation
//! for macOS Spotlight integration (Phase 7, batch-5 — 2026-05-04).
//!
//! `docs/PROPOSAL.md §7.4` calls for app-internal Spotlight
//! anchors so the macOS system-wide search bar can surface kchat
//! messages without breaking the E2EE invariant: only metadata
//! fields the user has consented to expose flow into Spotlight,
//! and the indexed payload never leaves the device.
//!
//! ## Surface
//!
//! [`SpotlightAnchor`] is the **fine-grained** Spotlight surface
//! the desktop layer calls into per message. It is independent of
//! the placeholder [`crate::macos::SpotlightBridge`] which carries
//! the older bulk-indexing contract; both ship side by side until
//! the production wiring lands.
//!
//! Methods:
//!
//! * [`SpotlightAnchor::index_message`] — write/replace the
//!   `CSSearchableItem` for one message id.
//! * [`SpotlightAnchor::deindex_message`] — remove an item by id.
//! * [`SpotlightAnchor::search_anchor`] — return the `domain ⋅ id`
//!   anchor string the orchestration layer wires into the
//!   Spotlight URL handler.
//!
//! All methods return [`Error`] (re-exported from
//! `kchat_core`) so callers can pattern-match on the
//! `NotImplemented("spotlight_anchor")` variant without parsing
//! free-form text.

use kchat_core::Error;

/// Object-safe outbound trait the desktop orchestration layer
/// calls into for macOS Spotlight integration. `Send + Sync` so
/// the bridge can sit inside an `Arc<dyn SpotlightAnchor>`.
pub trait SpotlightAnchor: Send + Sync + std::fmt::Debug {
    /// Write or replace the Spotlight searchable item for the
    /// supplied `message_id`. `display_text` carries the redacted
    /// preview the indexer should expose; the production
    /// implementation seals it before handing the data to
    /// CoreSpotlight.
    fn index_message(&self, message_id: &str, display_text: &str) -> Result<(), Error>;

    /// Remove the Spotlight searchable item for `message_id`.
    /// Idempotent — deindexing an unknown id must succeed so the
    /// caller can run the deindex pass after a delete-for-everyone
    /// without checking the index first.
    fn deindex_message(&self, message_id: &str) -> Result<(), Error>;

    /// Build the `domain ⋅ id` anchor string the desktop URL
    /// handler routes back into the kchat app. Production
    /// implementations construct the canonical
    /// `kchat://message/<message_id>` form; the noop returns the
    /// `message_id` verbatim.
    fn search_anchor(&self, message_id: &str) -> Result<String, Error>;
}

/// `SpotlightAnchor` placeholder used on hosts where the macOS
/// Spotlight runtime is not available (Linux CI, headless test
/// matrix). Every method returns
/// [`Error::NotImplemented("spotlight_anchor")`] except for
/// [`Self::deindex_message`] which is idempotent and succeeds.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSpotlightAnchor;

impl NoopSpotlightAnchor {
    /// `const fn` constructor.
    pub const fn new() -> Self {
        Self
    }
}

impl SpotlightAnchor for NoopSpotlightAnchor {
    fn index_message(&self, _message_id: &str, _display_text: &str) -> Result<(), Error> {
        Err(Error::NotImplemented("spotlight_anchor"))
    }

    fn deindex_message(&self, _message_id: &str) -> Result<(), Error> {
        // Deindex is intentionally idempotent — the caller after
        // a delete-for-everyone must succeed regardless of
        // Spotlight state.
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
    fn spotlight_anchor_is_object_safe_through_arc_dyn() {
        let anchor: Arc<dyn SpotlightAnchor> = Arc::new(NoopSpotlightAnchor::new());
        let err = anchor.index_message("msg-1", "preview").unwrap_err();
        assert!(matches!(err, Error::NotImplemented("spotlight_anchor")));
    }

    #[test]
    fn noop_deindex_is_idempotent_and_succeeds() {
        let anchor = NoopSpotlightAnchor::new();
        anchor.deindex_message("missing-id").unwrap();
        anchor.deindex_message("another-missing-id").unwrap();
    }

    #[test]
    fn noop_search_anchor_echoes_message_id() {
        let anchor = NoopSpotlightAnchor::new();
        assert_eq!(anchor.search_anchor("msg-42").unwrap(), "msg-42");
    }
}
