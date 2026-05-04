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

/// Phase 7 (2026-05-04 batch 10) — Task 6: one Windows Search
/// item. Mirrors [`crate::spotlight::SpotlightItem`] field-for-
/// field so a single ingest path can fan out to either bridge
/// without per-platform branching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSearchItem {
    /// Unique id (kchat `message_id`).
    pub unique_id: String,
    /// Title line shown in the Windows Search result row.
    pub title: String,
    /// Body line / redacted preview snippet.
    pub content_description: String,
    /// Display name shown in the Windows Search result row.
    pub display_name: String,
    /// Epoch-ms timestamp of the message creation.
    pub timestamp: i64,
    /// Owning conversation id — wired into the protocol
    /// handler's URL so the kchat app can route back to the
    /// correct conversation view.
    pub conversation_id: String,
}

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

    /// Phase 7 (2026-05-04 batch 10) — Task 6: bulk indexing.
    ///
    /// Index every [`WindowsSearchItem`] in `items` in a single
    /// platform call. Default implementation walks the slice
    /// and falls back to [`Self::index_message`] for backwards
    /// compatibility.
    fn index_items(&self, items: &[WindowsSearchItem]) -> Result<(), Error> {
        for item in items {
            self.index_message(&item.unique_id, &item.content_description)?;
        }
        Ok(())
    }

    /// Phase 7 (2026-05-04 batch 10) — Task 6: bulk deindex.
    ///
    /// Remove every Windows Search entry whose unique id is in
    /// `ids`. Idempotent — missing ids are allowed. Default
    /// impl defers to [`Self::deindex_message`] per id.
    fn remove_items(&self, ids: &[String]) -> Result<(), Error> {
        for id in ids {
            self.deindex_message(id)?;
        }
        Ok(())
    }

    /// Phase 7 (2026-05-04 batch 10) — Task 6: nuke every
    /// kchat-owned Windows Search entry. Default impl returns
    /// [`Error::NotImplemented`]; the production bridge issues
    /// the matching `ICrawlScopeManager` call.
    fn remove_all(&self) -> Result<(), Error> {
        Err(Error::NotImplemented("windows_search_anchor::remove_all"))
    }
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

    // Override the default trait bodies so the noop stays
    // panic-free even when the underlying `index_message` returns
    // `NotImplemented`. Phase 7 batch 10 — Task 6.
    fn index_items(&self, _items: &[WindowsSearchItem]) -> Result<(), Error> {
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

    // -----------------------------------------------------------
    // Phase 7 (2026-05-04 batch 10) — Task 6 bulk Windows Search.
    // -----------------------------------------------------------

    #[derive(Debug, Default)]
    struct RecordingWindowsAnchor {
        items: std::sync::Mutex<Vec<WindowsSearchItem>>,
        removed: std::sync::Mutex<Vec<String>>,
        cleared: std::sync::Mutex<bool>,
    }

    impl WindowsSearchAnchor for RecordingWindowsAnchor {
        fn index_message(&self, message_id: &str, display_text: &str) -> Result<(), Error> {
            self.items.lock().unwrap().push(WindowsSearchItem {
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

        fn index_items(&self, items: &[WindowsSearchItem]) -> Result<(), Error> {
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

    fn sample_item(i: usize) -> WindowsSearchItem {
        WindowsSearchItem {
            unique_id: format!("msg-{i}"),
            title: format!("title {i}"),
            content_description: format!("body {i}"),
            display_name: format!("display {i}"),
            timestamp: 1_700_000_000_000 + i as i64,
            conversation_id: "conv-1".into(),
        }
    }

    #[test]
    fn windows_search_anchor_index_items_round_trip() {
        let anchor = RecordingWindowsAnchor::default();
        anchor
            .index_items(&[sample_item(1), sample_item(2)])
            .unwrap();
        assert_eq!(anchor.items.lock().unwrap().len(), 2);
    }

    #[test]
    fn windows_search_anchor_remove_items() {
        let anchor = RecordingWindowsAnchor::default();
        anchor
            .remove_items(&["msg-1".into(), "msg-2".into()])
            .unwrap();
        assert_eq!(anchor.removed.lock().unwrap().len(), 2);
    }

    #[test]
    fn windows_search_anchor_noop_does_not_panic() {
        let a: Arc<dyn WindowsSearchAnchor> = Arc::new(NoopWindowsSearchAnchor::new());
        a.index_items(&[sample_item(1)]).unwrap();
        a.remove_items(&["msg-x".into()]).unwrap();
        a.remove_all().unwrap();
    }
}
