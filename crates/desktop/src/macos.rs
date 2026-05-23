//! macOS-specific desktop integration.
//!
//! The two seams here are:
//!
//! * [`SpotlightBridge`] — kchat's outbound interface to the
//!   macOS Spotlight indexer. The eventual production
//!   implementation builds an `NSUserActivity` / Core Spotlight
//!   `CSSearchableItem` per message and pushes it through
//!   `CSSearchableIndex.default`. This module ships a
//!   [`NoopSpotlightBridge`] for any environment where the
//!   real platform bridge is not yet wired up (CI on Linux,
//!   unit tests, headless macOS dev builds).
//! * [`MacOsSchedulerBridge`] — kchat's outbound interface to
//!   `NSBackgroundActivityScheduler`. Implements the
//!   [`BackgroundScheduler`] trait re-exported from
//!   `kchat-core`. The eventual production implementation runs
//!   the kchat backup / archive-compaction / index-maintenance
//!   loops as `NSBackgroundActivityScheduler` activities
//!   constrained to repeating intervals.
//!
//! Both seams are object-safe (`Box<dyn...>`) and `Send + Sync`
//! so the desktop crate can park them inside an
//! `Arc<dyn SpotlightBridge>` / `Arc<dyn BackgroundScheduler>`
//! and hand them to the platform layer.
//!
//! References:
//! * `docs/DESIGN.md §7.4` — Spotlight anchors.
//! * — desktop integration.

use kchat_core::scheduler::BackgroundScheduler;
use kchat_core::Error;

// ---------------------------------------------------------------------------
// SpotlightBridge — outbound search-index seam
// ---------------------------------------------------------------------------

/// Object-safe outbound trait that kchat-desktop calls into to
/// keep the macOS Spotlight index in sync with the local
/// kchat-core message log.
///
/// Object-safety + `Send + Sync`: production callers store the
/// bridge inside an `Arc<dyn SpotlightBridge>` so background
/// schedulers can clone it cheaply.
pub trait SpotlightBridge: Send + Sync + std::fmt::Debug {
    /// Index (or replace) the Spotlight entry for `message_id`.
    /// The arguments mirror the Core Spotlight `CSSearchableItem`
    /// attributes that kchat exposes to the OS — body text, the
    /// human-readable conversation title, the sender display
    /// name, and the message timestamp in milliseconds since
    /// the Unix epoch.
    fn index_message(
        &self,
        message_id: &str,
        conversation_title: &str,
        body: &str,
        sender: &str,
        timestamp_ms: i64,
    ) -> Result<(), Error>;

    /// Drop the Spotlight entry for a single message. Idempotent:
    /// removing a non-existent entry MUST NOT error.
    fn remove_message(&self, message_id: &str) -> Result<(), Error>;

    /// Drop every Spotlight entry that belongs to a conversation.
    /// Used during conversation deletion so the OS-level index
    /// stays consistent with the local store.
    fn remove_conversation(&self, conversation_id: &str) -> Result<(), Error>;
}

/// placeholder Spotlight bridge.
///
/// Every method silently succeeds (`Ok(())`) — the desktop
/// orchestration layer can install it on Linux CI runners
/// (where Spotlight isn't available) and on dev builds that
/// don't link the real platform bridge yet, without impacting
/// the rest of the pipeline.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSpotlightBridge;

impl NoopSpotlightBridge {
    /// Construct a fresh [`NoopSpotlightBridge`].
    pub const fn new() -> Self {
        Self
    }
}

impl SpotlightBridge for NoopSpotlightBridge {
    fn index_message(
        &self,
        _message_id: &str,
        _conversation_title: &str,
        _body: &str,
        _sender: &str,
        _timestamp_ms: i64,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn remove_message(&self, _message_id: &str) -> Result<(), Error> {
        Ok(())
    }
    fn remove_conversation(&self, _conversation_id: &str) -> Result<(), Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MacOsSchedulerBridge — outbound NSBackgroundActivityScheduler seam
// ---------------------------------------------------------------------------

/// placeholder for the macOS
/// `NSBackgroundActivityScheduler` bridge. Every method returns
/// [`Error::NotImplemented`] so the orchestration layer can
/// distinguish "no bridge installed" from "scheduler accepted
/// the task" while the real Swift glue is being authored.
///
/// Production implementations wrap an actual
/// `NSBackgroundActivityScheduler` and translate cadence
/// requests into `setRepeats:` + `setInterval:` calls on the
/// shared activity object. The trait stays object-safe so the
/// production bridge can be stored behind an
/// `Arc<dyn BackgroundScheduler>`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacOsSchedulerBridge;

impl MacOsSchedulerBridge {
    /// Construct a fresh [`MacOsSchedulerBridge`].
    pub const fn new() -> Self {
        Self
    }
}

impl BackgroundScheduler for MacOsSchedulerBridge {
    fn schedule_backup(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("macos_scheduler"))
    }
    fn schedule_archive_compaction(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("macos_scheduler"))
    }
    fn schedule_index_maintenance(&self, _interval_ms: u64) -> Result<(), Error> {
        Err(Error::NotImplemented("macos_scheduler"))
    }
    fn cancel_all(&self) -> Result<(), Error> {
        Err(Error::NotImplemented("macos_scheduler"))
    }
    fn is_task_pending(&self, _task_id: &str) -> Result<bool, Error> {
        Err(Error::NotImplemented("macos_scheduler"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock Spotlight bridge that records every call so tests
    /// can verify the index / remove fan-out from the desktop
    /// orchestration layer.
    #[derive(Debug, Default)]
    struct MockSpotlightBridge {
        indexed: std::sync::Mutex<Vec<String>>,
        removed_messages: std::sync::Mutex<Vec<String>>,
        removed_conversations: std::sync::Mutex<Vec<String>>,
    }

    impl SpotlightBridge for MockSpotlightBridge {
        fn index_message(
            &self,
            message_id: &str,
            _conversation_title: &str,
            _body: &str,
            _sender: &str,
            _timestamp_ms: i64,
        ) -> Result<(), Error> {
            self.indexed.lock().unwrap().push(message_id.to_string());
            Ok(())
        }
        fn remove_message(&self, message_id: &str) -> Result<(), Error> {
            self.removed_messages
                .lock()
                .unwrap()
                .push(message_id.to_string());
            Ok(())
        }
        fn remove_conversation(&self, conversation_id: &str) -> Result<(), Error> {
            self.removed_conversations
                .lock()
                .unwrap()
                .push(conversation_id.to_string());
            Ok(())
        }
    }

    #[test]
    fn spotlight_bridge_noop_returns_ok() {
        let b = NoopSpotlightBridge::new();
        assert!(b.index_message("m1", "ct", "body", "alice", 0).is_ok());
        assert!(b.remove_message("m1").is_ok());
        assert!(b.remove_conversation("c1").is_ok());
    }

    #[test]
    fn macos_scheduler_bridge_noop_returns_not_implemented() {
        let s = MacOsSchedulerBridge::new();
        assert!(matches!(
            s.schedule_backup(60_000),
            Err(Error::NotImplemented("macos_scheduler"))
        ));
        assert!(matches!(
            s.schedule_archive_compaction(60_000),
            Err(Error::NotImplemented("macos_scheduler"))
        ));
        assert!(matches!(
            s.schedule_index_maintenance(60_000),
            Err(Error::NotImplemented("macos_scheduler"))
        ));
        assert!(matches!(
            s.cancel_all(),
            Err(Error::NotImplemented("macos_scheduler"))
        ));
        assert!(matches!(
            s.is_task_pending("backup"),
            Err(Error::NotImplemented("macos_scheduler"))
        ));
    }

    #[test]
    fn spotlight_index_and_remove_round_trip() {
        let mock = MockSpotlightBridge::default();
        mock.index_message("m1", "Project", "hello", "alice", 1)
            .unwrap();
        mock.index_message("m2", "Project", "world", "alice", 2)
            .unwrap();
        mock.remove_message("m1").unwrap();
        mock.remove_conversation("c1").unwrap();
        assert_eq!(mock.indexed.lock().unwrap().len(), 2);
        assert_eq!(mock.removed_messages.lock().unwrap().len(), 1);
        assert_eq!(mock.removed_conversations.lock().unwrap().len(), 1);
    }

    #[test]
    fn spotlight_bridge_is_object_safe() {
        // Compile-time check: `Box<dyn SpotlightBridge>` must be
        // constructible. The desktop crate stores the bridge
        // behind a trait object so the platform-specific impl
        // can be swapped at runtime.
        let _b: Box<dyn SpotlightBridge> = Box::new(NoopSpotlightBridge::new());
    }

    #[test]
    fn macos_scheduler_is_object_safe() {
        // Compile-time check: `Box<dyn BackgroundScheduler>`
        // must accept [`MacOsSchedulerBridge`].
        let _s: Box<dyn BackgroundScheduler> = Box::new(MacOsSchedulerBridge::new());
    }
}
