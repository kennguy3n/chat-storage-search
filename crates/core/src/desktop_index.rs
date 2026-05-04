//! Desktop search-index anchors — Phase 7 (2026-05-04 batch 10).
//!
//! `docs/PROPOSAL.md §7.4` calls for kchat to feed redacted
//! message metadata into the host OS's search index so the
//! system-wide search bar can surface kchat results without
//! breaking the E2EE invariant. macOS exposes this through
//! Spotlight (`CSSearchableIndex`), Windows through Windows
//! Search (`ISearchManager` / `ISearchCatalogManager`).
//!
//! The Rust core does not own those primitives — it cannot reach
//! into AppKit / WinRT directly. Instead this module defines two
//! object-safe traits ([`SpotlightAnchor`], [`WindowsSearchAnchor`])
//! that the desktop crate / platform bridges fill in. `CoreImpl`
//! carries a slot for each so the orchestration layer can call
//! into the installed bridge without depending on the desktop
//! crate.
//!
//! The traits live in `kchat-core` rather than `kchat-desktop` so
//! every platform bridge — desktop, macOS, Windows — sees the
//! same trait definition. The desktop crate re-exports them for
//! ergonomic call sites.

use crate::Error;

// ---------------------------------------------------------------------------
// SpotlightAnchor — macOS CSSearchableItem bridge
// ---------------------------------------------------------------------------

/// One Spotlight searchable item. Maps onto
/// `CSSearchableItemAttributeSet` field-for-field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpotlightItem {
    /// `CSSearchableItem.uniqueIdentifier` — the kchat
    /// `message_id`.
    pub unique_id: String,
    /// Title line shown in the Spotlight result list.
    pub title: String,
    /// Body line shown in the Spotlight result list — the
    /// redacted preview the user opted into exposing.
    pub content_description: String,
    /// `attributeSet.displayName` — short label used by the
    /// result row.
    pub display_name: String,
    /// Epoch-ms timestamp of the message creation.
    pub timestamp: i64,
    /// Owning conversation id, written into
    /// `relatedUniqueIdentifier` so the URL handler can route
    /// back into the right conversation view.
    pub conversation_id: String,
}

/// Object-safe bridge that the orchestration layer calls for
/// macOS Spotlight integration. `Send + Sync` so the bridge can
/// sit inside an `Arc<dyn SpotlightAnchor>`.
pub trait SpotlightAnchor: Send + Sync + std::fmt::Debug {
    /// Index the supplied items into the Spotlight catalog.
    /// Production implementations issue a single
    /// `CSSearchableIndex.indexSearchableItems` call.
    fn index_items(&self, items: &[SpotlightItem]) -> Result<(), Error>;
    /// Remove every item whose `uniqueIdentifier` is in `ids`.
    /// Idempotent in aggregate — missing ids are allowed.
    fn remove_items(&self, ids: &[String]) -> Result<(), Error>;
    /// Remove every kchat-owned Spotlight item. Used during
    /// account deletion / "factory reset" flows.
    fn remove_all(&self) -> Result<(), Error>;
}

/// `SpotlightAnchor` placeholder used on hosts where the macOS
/// Spotlight runtime is not available. Every method is a
/// successful no-op so the orchestration layer can install the
/// noop unconditionally and let the platform bridge replace it
/// at runtime if Spotlight is available.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSpotlightAnchor;

impl NoopSpotlightAnchor {
    /// `const fn` constructor.
    pub const fn new() -> Self {
        Self
    }
}

impl SpotlightAnchor for NoopSpotlightAnchor {
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

// ---------------------------------------------------------------------------
// WindowsSearchAnchor — Windows Search index bridge
// ---------------------------------------------------------------------------

/// One Windows Search item. Mirrors [`SpotlightItem`] field for
/// field — the Windows Search bridge maps these onto
/// `ICrawlScopeManager` / `ISearchProtocol` URL entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSearchItem {
    /// Unique id (kchat `message_id`).
    pub unique_id: String,
    /// Title line shown in Windows Search results.
    pub title: String,
    /// Body line / preview snippet.
    pub content_description: String,
    /// Short display name used in the Windows Search row.
    pub display_name: String,
    /// Epoch-ms timestamp of the message creation.
    pub timestamp: i64,
    /// Owning conversation id.
    pub conversation_id: String,
}

/// Object-safe bridge that the orchestration layer calls for
/// Windows Search integration.
pub trait WindowsSearchAnchor: Send + Sync + std::fmt::Debug {
    /// Index the supplied items into Windows Search.
    fn index_items(&self, items: &[WindowsSearchItem]) -> Result<(), Error>;
    /// Remove items by id.
    fn remove_items(&self, ids: &[String]) -> Result<(), Error>;
    /// Remove every kchat-owned Windows Search entry.
    fn remove_all(&self) -> Result<(), Error>;
}

/// `WindowsSearchAnchor` placeholder used on hosts where the
/// Windows Search runtime is not available. Every method is a
/// successful no-op so the orchestration layer can install the
/// noop unconditionally on non-Windows platforms.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopWindowsSearchAnchor;

impl NoopWindowsSearchAnchor {
    /// `const fn` constructor.
    pub const fn new() -> Self {
        Self
    }
}

impl WindowsSearchAnchor for NoopWindowsSearchAnchor {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct RecordingSpotlight {
        items: Mutex<Vec<SpotlightItem>>,
        removed: Mutex<Vec<String>>,
        cleared: Mutex<bool>,
    }

    impl SpotlightAnchor for RecordingSpotlight {
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

    fn sample_spotlight_item(i: usize) -> SpotlightItem {
        SpotlightItem {
            unique_id: format!("msg-{i}"),
            title: format!("title {i}"),
            content_description: format!("body {i}"),
            display_name: format!("display {i}"),
            timestamp: 1_700_000_000_000 + i as i64,
            conversation_id: "conv-1".into(),
        }
    }

    #[test]
    fn spotlight_anchor_index_items_round_trip() {
        let anchor = RecordingSpotlight::default();
        let items = vec![sample_spotlight_item(1), sample_spotlight_item(2)];
        anchor.index_items(&items).unwrap();
        assert_eq!(anchor.items.lock().unwrap().len(), 2);
    }

    #[test]
    fn spotlight_anchor_remove_items() {
        let anchor = RecordingSpotlight::default();
        anchor
            .remove_items(&["msg-1".into(), "msg-2".into()])
            .unwrap();
        assert_eq!(anchor.removed.lock().unwrap().len(), 2);
    }

    #[test]
    fn spotlight_anchor_remove_all_sets_flag() {
        let anchor = RecordingSpotlight::default();
        anchor.index_items(&[sample_spotlight_item(1)]).unwrap();
        anchor.remove_all().unwrap();
        assert!(*anchor.cleared.lock().unwrap());
        assert!(anchor.items.lock().unwrap().is_empty());
    }

    #[test]
    fn spotlight_anchor_noop_does_not_panic() {
        let a: Arc<dyn SpotlightAnchor> = Arc::new(NoopSpotlightAnchor::new());
        a.index_items(&[sample_spotlight_item(1)]).unwrap();
        a.remove_items(&["msg-x".into()]).unwrap();
        a.remove_all().unwrap();
    }

    #[derive(Debug, Default)]
    struct RecordingWindows {
        items: Mutex<Vec<WindowsSearchItem>>,
        removed: Mutex<Vec<String>>,
    }

    impl WindowsSearchAnchor for RecordingWindows {
        fn index_items(&self, items: &[WindowsSearchItem]) -> Result<(), Error> {
            self.items.lock().unwrap().extend(items.iter().cloned());
            Ok(())
        }
        fn remove_items(&self, ids: &[String]) -> Result<(), Error> {
            self.removed.lock().unwrap().extend(ids.iter().cloned());
            Ok(())
        }
        fn remove_all(&self) -> Result<(), Error> {
            self.items.lock().unwrap().clear();
            Ok(())
        }
    }

    fn sample_windows_item(i: usize) -> WindowsSearchItem {
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
        let anchor = RecordingWindows::default();
        anchor
            .index_items(&[sample_windows_item(1), sample_windows_item(2)])
            .unwrap();
        assert_eq!(anchor.items.lock().unwrap().len(), 2);
    }

    #[test]
    fn windows_search_anchor_remove_items() {
        let anchor = RecordingWindows::default();
        anchor
            .remove_items(&["msg-1".into(), "msg-2".into()])
            .unwrap();
        assert_eq!(anchor.removed.lock().unwrap().len(), 2);
    }

    #[test]
    fn windows_search_anchor_noop_does_not_panic() {
        let a: Arc<dyn WindowsSearchAnchor> = Arc::new(NoopWindowsSearchAnchor::new());
        a.index_items(&[sample_windows_item(1)]).unwrap();
        a.remove_items(&["msg-x".into()]).unwrap();
        a.remove_all().unwrap();
    }
}
