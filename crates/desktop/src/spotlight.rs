//! `SpotlightAnchor` trait + `NoopSpotlightAnchor` implementation
//! for macOS Spotlight integration.
//!
//! `docs/DESIGN.md §7.4` calls for app-internal Spotlight
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

/// one Spotlight item.
///
/// `docs/DESIGN.md §7.4` calls for the macOS system-wide
/// search bar to surface kchat messages. Each indexed message is
/// represented as a [`SpotlightItem`] before it is handed to
/// `CSSearchableItem` on the platform side.
///
/// Field semantics map onto `CSSearchableItemAttributeSet`:
///
/// * `unique_id` → `CSSearchableItem.uniqueIdentifier`
///   (the kchat `message_id`).
/// * `title` → `attributeSet.title` (conversation name + sender,
///   truncated for display).
/// * `content_description` → `attributeSet.contentDescription`
///   (the redacted body preview).
/// * `display_name` → `attributeSet.displayName` (what shows up
///   in the Spotlight result list).
/// * `timestamp` → `attributeSet.contentCreationDate` (epoch
///   milliseconds).
/// * `conversation_id` → `attributeSet.relatedUniqueIdentifier`
///   so the Spotlight URL handler can route back into the right
///   conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpotlightItem {
    /// `CSSearchableItem.uniqueIdentifier` — the kchat
    /// `message_id`.
    pub unique_id: String,
    /// Conversation/sender combo shown as the result's title
    /// line.
    pub title: String,
    /// Redacted body preview shown as the result's body line.
    pub content_description: String,
    /// Display name used by the Spotlight result list.
    pub display_name: String,
    /// Epoch-ms timestamp of the message creation.
    pub timestamp: i64,
    /// Owning conversation id — wired into
    /// `relatedUniqueIdentifier` so the URL handler can route
    /// back into the correct conversation view.
    pub conversation_id: String,
}

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

    /// bulk indexing.
    ///
    /// Index every [`SpotlightItem`] in `items` in a single
    /// platform call. Production implementations issue one
    /// `CSSearchableIndex.indexSearchableItems` call so
    /// CoreSpotlight can batch the writes; the default
    /// implementation walks the slice and falls back to
    /// [`Self::index_message`] for backwards compatibility.
    fn index_items(&self, items: &[SpotlightItem]) -> Result<(), Error> {
        for item in items {
            self.index_message(&item.unique_id, &item.content_description)?;
        }
        Ok(())
    }

    /// bulk deindex.
    ///
    /// Remove every Spotlight item whose `uniqueIdentifier` is
    /// in `ids`. Idempotent in aggregate: missing ids are
    /// allowed. The default implementation defers to
    /// [`Self::deindex_message`] per id.
    fn remove_items(&self, ids: &[String]) -> Result<(), Error> {
        for id in ids {
            self.deindex_message(id)?;
        }
        Ok(())
    }

    /// nuke every
    /// kchat-owned Spotlight item.
    ///
    /// Used during sign-out / account-deletion / "factory
    /// reset" flows so no kchat metadata leaks into Spotlight
    /// after the local store is wiped. The default
    /// implementation returns [`Error::NotImplemented`]
    /// production implementations issue
    /// `CSSearchableIndex.deleteSearchableItemsWithDomainIdentifiers`
    /// for the kchat domain.
    fn remove_all(&self) -> Result<(), Error> {
        Err(Error::NotImplemented("spotlight_anchor::remove_all"))
    }
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

    // Override the default trait bodies so the noop stays
    // panic-free even when the underlying `index_message`
    // returns `NotImplemented`.
    fn index_items(&self, _items: &[SpotlightItem]) -> Result<(), Error> {
        Ok(())
    }

    fn remove_items(&self, _ids: &[String]) -> Result<(), Error> {
        Ok(())
    }

    fn remove_all(&self) -> Result<(), Error> {
        Ok(())
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

    // -----------------------------------------------------------
    // bulk Spotlight API.
    // -----------------------------------------------------------

    /// Mock anchor that records every `index_items` /
    /// `remove_items` call so unit tests can inspect what the
    /// orchestration layer dispatched.
    #[derive(Debug, Default)]
    struct RecordingAnchor {
        items: std::sync::Mutex<Vec<SpotlightItem>>,
        removed: std::sync::Mutex<Vec<String>>,
        cleared: std::sync::Mutex<bool>,
    }

    impl SpotlightAnchor for RecordingAnchor {
        fn index_message(&self, message_id: &str, display_text: &str) -> Result<(), Error> {
            self.items.lock().unwrap().push(SpotlightItem {
                unique_id: message_id.to_string(),
                title: String::new(),
                content_description: display_text.to_string(),
                display_name: String::new(),
                timestamp: 0,
                conversation_id: String::new(),
            });
            Ok(())
        }

        fn deindex_message(&self, message_id: &str) -> Result<(), Error> {
            self.removed.lock().unwrap().push(message_id.to_string());
            Ok(())
        }

        fn search_anchor(&self, message_id: &str) -> Result<String, Error> {
            Ok(message_id.to_string())
        }

        fn index_items(&self, items: &[SpotlightItem]) -> Result<(), Error> {
            self.items.lock().unwrap().extend(items.iter().cloned());
            Ok(())
        }

        fn remove_items(&self, ids: &[String]) -> Result<(), Error> {
            self.removed.lock().unwrap().extend(ids.iter().cloned());
            Ok(())
        }

        fn remove_all(&self) -> Result<(), Error> {
            *self.cleared.lock().unwrap() = true;
            self.items.lock().unwrap().clear();
            Ok(())
        }
    }

    fn sample_item(i: usize) -> SpotlightItem {
        SpotlightItem {
            unique_id: format!("msg-{i}"),
            title: format!("Title {i}"),
            content_description: format!("body {i}"),
            display_name: format!("Display {i}"),
            timestamp: 1_700_000_000_000 + i as i64,
            conversation_id: "conv-1".into(),
        }
    }

    #[test]
    fn spotlight_anchor_index_items_round_trip() {
        let anchor = RecordingAnchor::default();
        let items = vec![sample_item(1), sample_item(2), sample_item(3)];
        anchor.index_items(&items).unwrap();
        let stored = anchor.items.lock().unwrap();
        assert_eq!(stored.len(), 3);
        assert_eq!(stored[0].unique_id, "msg-1");
        assert_eq!(stored[2].timestamp, 1_700_000_000_003);
    }

    #[test]
    fn spotlight_anchor_remove_items() {
        let anchor = RecordingAnchor::default();
        anchor
            .index_items(&[sample_item(1), sample_item(2)])
            .unwrap();
        anchor
            .remove_items(&["msg-1".to_string(), "msg-2".to_string()])
            .unwrap();
        let removed = anchor.removed.lock().unwrap();
        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&"msg-1".to_string()));
    }

    #[test]
    fn spotlight_anchor_noop_does_not_panic() {
        let anchor = NoopSpotlightAnchor::new();
        anchor
            .index_items(&[sample_item(1), sample_item(2)])
            .unwrap();
        anchor
            .remove_items(&["msg-x".to_string(), "msg-y".to_string()])
            .unwrap();
        anchor.remove_all().unwrap();
    }

    #[test]
    fn spotlight_anchor_remove_all_clears_state() {
        let anchor = RecordingAnchor::default();
        anchor
            .index_items(&[sample_item(1), sample_item(2)])
            .unwrap();
        anchor.remove_all().unwrap();
        assert!(*anchor.cleared.lock().unwrap());
        assert!(anchor.items.lock().unwrap().is_empty());
    }
}
