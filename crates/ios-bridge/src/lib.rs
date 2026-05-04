// The `uniffi::include_scaffolding!` macro pulls in machine-generated
// code that triggers a handful of clippy lints (`empty_line_after_doc_comments`,
// `too_many_arguments`, …) we have no control over. Silence them at
// crate scope so the rest of the file is still linted strictly.
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::let_and_return)]

//! iOS UniFFI bridge for `kchat-core`.
//!
//! Phase 1 scaffold. The UDL at [`src/kchat.udl`] defines the
//! cross-language surface; this module supplies the matching Rust
//! types and method implementations. The
//! `uniffi::include_scaffolding!("kchat")` macro at the bottom of
//! the file pulls in the generated lift / lower / dispatch glue
//! emitted by `build.rs`.
//!
//! Design notes
//! ------------
//!
//! * UUIDs cross the FFI as canonical hyphenated strings (see
//!   [`Uuid::parse_str`]). The bridge validates them inside every
//!   method and surfaces parse failures as
//!   [`KChatError::InvalidArgument`] so callers can pin the exact
//!   field that was malformed without parsing free-form text.
//! * The `KChatCoreConfig` / `Platform` / `SearchQuery` /
//!   `SearchResult` / `SearchScope` / `ContentKind` / `MessageView`
//!   types here are FFI-shaped wrappers around the canonical types
//!   in `kchat-core`. Each wrapper carries
//!   [`From`] / [`TryFrom`] impls back to the core type so the
//!   bridge stays the only place doing `Uuid::parse_str` / `Platform`
//!   discrimination.
//! * The `KChatCore` interface in this crate wraps
//!   [`kchat_core::CoreImpl`]. All trait methods on
//!   [`kchat_core::KChatCore`] are exposed; the inherent
//!   [`kchat_core::CoreImpl::with_transport`] entry point will be
//!   added once the transport surface is wired through UniFFI in
//!   Phase 2.

use std::path::PathBuf;
use std::sync::Mutex;

use kchat_core::config::Platform as CorePlatform;
use kchat_core::{
    BackupSource, CoreImpl, DeliveryCursor as CoreDeliveryCursor, KChatCore as KChatCoreTrait,
    KChatCoreConfig as CoreKChatCoreConfig, SearchQuery as CoreSearchQuery,
    SearchResult as CoreSearchResult, SearchScope as CoreSearchScope,
};
use uuid::Uuid;

// Silence unused-import warnings for crate re-exports we expose so
// downstream Swift / Kotlin code can address them by name without
// digging into `kchat_core` directly.
pub use kchat_core::{
    BackupResult as CoreBackupResult, ClientMessageId as CoreClientMessageId,
    ContentKind as CoreContentKind, DeviceRegistration as CoreDeviceRegistration,
    Error as CoreError, HydratedMessage as CoreHydratedMessage, MessageView as CoreMessageView,
    OffloadResult as CoreOffloadResult, RestoreResult as CoreRestoreResult,
};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// FFI-shaped error mirror of [`kchat_core::Error`].
///
/// `[Error] interface KChatError` in [`src/kchat.udl`] generates one
/// variant per category. Each variant carries a free-form message so
/// the host language can surface it to the user; structured codes can
/// be added later without breaking the FFI surface.
#[derive(Debug, thiserror::Error)]
pub enum KChatError {
    /// Bridges [`kchat_core::Error::Crypto`].
    #[error("crypto: {message}")]
    Crypto { message: String },
    /// Bridges [`kchat_core::Error::Storage`].
    #[error("storage: {message}")]
    Storage { message: String },
    /// Bridges [`kchat_core::Error::Search`].
    #[error("search: {message}")]
    Search { message: String },
    /// Bridges [`kchat_core::Error::Message`].
    #[error("message: {message}")]
    Message { message: String },
    /// Bridges [`kchat_core::Error::Transport`].
    #[error("transport: {message}")]
    Transport { message: String },
    /// Bridges [`kchat_core::Error::NotImplemented`].
    #[error("not yet implemented: {method}")]
    NotImplemented { method: String },
    /// Bridges [`kchat_core::Error::Model`].
    #[error("model: {message}")]
    Model { message: String },
    /// Argument validation failure inside the bridge layer (e.g. a
    /// malformed UUID string or wrong-length key).
    #[error("invalid argument: {message}")]
    InvalidArgument { message: String },
}

impl From<kchat_core::Error> for KChatError {
    fn from(value: kchat_core::Error) -> Self {
        match value {
            kchat_core::Error::Crypto(e) => KChatError::Crypto {
                message: e.to_string(),
            },
            kchat_core::Error::Storage(s) => KChatError::Storage { message: s },
            kchat_core::Error::Search(s) => KChatError::Search { message: s },
            kchat_core::Error::Message(s) => KChatError::Message { message: s },
            kchat_core::Error::Transport(s) => KChatError::Transport { message: s },
            kchat_core::Error::NotImplemented(m) => KChatError::NotImplemented {
                method: m.to_string(),
            },
            kchat_core::Error::Model(s) => KChatError::Model { message: s },
        }
    }
}

type Result<T> = std::result::Result<T, KChatError>;

fn parse_uuid(field: &str, value: &str) -> Result<Uuid> {
    Uuid::parse_str(value).map_err(|e| KChatError::InvalidArgument {
        message: format!("invalid {field}: {e}"),
    })
}

fn parse_uuid_opt(field: &str, value: Option<String>) -> Result<Option<Uuid>> {
    value
        .filter(|s| !s.is_empty())
        .map(|s| parse_uuid(field, &s))
        .transpose()
}

// ---------------------------------------------------------------------------
// Platform / KChatCoreConfig
// ---------------------------------------------------------------------------

/// FFI-shaped mirror of [`kchat_core::config::Platform`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Ios,
    Android,
    MacOs,
    Windows,
}

impl From<Platform> for CorePlatform {
    fn from(p: Platform) -> Self {
        match p {
            Platform::Ios => CorePlatform::Ios,
            Platform::Android => CorePlatform::Android,
            Platform::MacOs => CorePlatform::MacOs,
            Platform::Windows => CorePlatform::Windows,
        }
    }
}

impl From<CorePlatform> for Platform {
    fn from(p: CorePlatform) -> Self {
        match p {
            CorePlatform::Ios => Platform::Ios,
            CorePlatform::Android => Platform::Android,
            CorePlatform::MacOs => Platform::MacOs,
            CorePlatform::Windows => Platform::Windows,
        }
    }
}

/// FFI-shaped mirror of [`kchat_core::KChatCoreConfig`].
#[derive(Debug, Clone)]
pub struct KChatCoreConfig {
    pub data_dir: String,
    pub platform: Platform,
    pub tenant_id: String,
}

impl From<KChatCoreConfig> for CoreKChatCoreConfig {
    fn from(c: KChatCoreConfig) -> Self {
        CoreKChatCoreConfig::new(PathBuf::from(c.data_dir), c.platform.into(), c.tenant_id)
    }
}

impl From<&CoreKChatCoreConfig> for KChatCoreConfig {
    fn from(c: &CoreKChatCoreConfig) -> Self {
        KChatCoreConfig {
            data_dir: c.data_dir.to_string_lossy().into_owned(),
            platform: c.platform.into(),
            tenant_id: c.tenant_id.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Search surface
// ---------------------------------------------------------------------------

/// FFI-shaped mirror of [`kchat_core::SearchScope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    LocalOnly,
    IncludeCold,
}

impl From<SearchScope> for CoreSearchScope {
    fn from(s: SearchScope) -> Self {
        match s {
            SearchScope::LocalOnly => CoreSearchScope::LocalOnly,
            SearchScope::IncludeCold => CoreSearchScope::IncludeCold,
        }
    }
}

/// FFI-shaped mirror of [`kchat_core::ContentKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    Text,
    Image,
    Video,
    Audio,
    Document,
    Any,
}

impl From<ContentKind> for kchat_core::ContentKind {
    fn from(k: ContentKind) -> Self {
        match k {
            ContentKind::Text => kchat_core::ContentKind::Text,
            ContentKind::Image => kchat_core::ContentKind::Image,
            ContentKind::Video => kchat_core::ContentKind::Video,
            ContentKind::Audio => kchat_core::ContentKind::Audio,
            ContentKind::Document => kchat_core::ContentKind::Document,
            ContentKind::Any => kchat_core::ContentKind::Any,
        }
    }
}

/// FFI-shaped mirror of [`kchat_core::SearchQuery`].
#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub query_string: String,
    pub sender_filter: Option<String>,
    pub conversation_filter: Option<String>,
    pub date_from: Option<i64>,
    pub date_to: Option<i64>,
    pub content_kind: Option<ContentKind>,
}

impl SearchQuery {
    fn into_core(self) -> Result<CoreSearchQuery> {
        Ok(CoreSearchQuery {
            query_string: self.query_string,
            sender_filter: self.sender_filter,
            conversation_filter: parse_uuid_opt("conversation_filter", self.conversation_filter)?,
            date_from: self.date_from,
            date_to: self.date_to,
            content_kind: self.content_kind.map(Into::into),
            target: Default::default(),
        })
    }
}

/// FFI-shaped mirror of [`kchat_core::SearchResult`].
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub created_at_ms: i64,
    pub snippet: Option<String>,
    pub rank_score: f64,
    pub is_cold: bool,
}

impl From<CoreSearchResult> for SearchResult {
    fn from(r: CoreSearchResult) -> Self {
        SearchResult {
            message_id: r.message_id.to_string(),
            conversation_id: r.conversation_id.to_string(),
            sender_id: r.sender_id,
            created_at_ms: r.created_at_ms,
            snippet: r.snippet,
            rank_score: r.rank_score,
            is_cold: r.is_cold,
        }
    }
}

// ---------------------------------------------------------------------------
// Message surface
// ---------------------------------------------------------------------------

/// FFI-shaped mirror of [`kchat_core::MessageView`].
#[derive(Debug, Clone)]
pub struct MessageView {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub created_at_ms: i64,
    pub received_at_ms: i64,
    pub reply_to: Option<String>,
    pub edited_at_ms: Option<i64>,
    pub deleted_at_ms: Option<i64>,
    pub text_content: Option<String>,
}

impl From<kchat_core::MessageView> for MessageView {
    fn from(v: kchat_core::MessageView) -> Self {
        MessageView {
            message_id: v.message_id.to_string(),
            conversation_id: v.conversation_id.to_string(),
            sender_id: v.sender_id,
            created_at_ms: v.created_at_ms,
            received_at_ms: v.received_at_ms,
            reply_to: v.reply_to.map(|u| u.to_string()),
            edited_at_ms: v.edited_at_ms,
            deleted_at_ms: v.deleted_at_ms,
            text_content: v.text_content,
        }
    }
}

/// FFI-shaped mirror of [`kchat_core::ClientMessageId`].
#[derive(Debug, Clone)]
pub struct ClientMessageId {
    pub value: String,
}

impl From<kchat_core::ClientMessageId> for ClientMessageId {
    fn from(c: kchat_core::ClientMessageId) -> Self {
        ClientMessageId {
            value: c.0.to_string(),
        }
    }
}

/// FFI-shaped mirror of [`kchat_core::DeliveryCursor`].
#[derive(Debug, Clone)]
pub struct DeliveryCursor {
    pub value: String,
}

impl From<DeliveryCursor> for CoreDeliveryCursor {
    fn from(c: DeliveryCursor) -> Self {
        CoreDeliveryCursor(c.value)
    }
}

/// FFI-shaped mirror of
/// [`kchat_core::message::processor::IngestResult`].
#[derive(Debug, Clone)]
pub struct IngestResult {
    pub new_messages: u32,
    pub updated_messages: u32,
    pub duplicate_count: u32,
    pub next_cursor: Option<String>,
}

impl From<kchat_core::message::processor::IngestResult> for IngestResult {
    fn from(r: kchat_core::message::processor::IngestResult) -> Self {
        IngestResult {
            new_messages: r.new_messages,
            updated_messages: r.updated_messages,
            duplicate_count: r.duplicate_count,
            next_cursor: r.next_cursor,
        }
    }
}

/// FFI-shaped placeholder mirror of
/// [`kchat_core::DeviceRegistration`]. The full payload (MLS
/// credential bundle, KeyPackage handle, …) lands when the MLS
/// layer arrives later in Phase 1 / Phase 2; the empty struct here
/// is enough to pin the FFI shape today.
#[derive(Debug, Clone, Default)]
pub struct DeviceRegistration {}

impl From<kchat_core::DeviceRegistration> for DeviceRegistration {
    fn from(_: kchat_core::DeviceRegistration) -> Self {
        DeviceRegistration {}
    }
}

// ---------------------------------------------------------------------------
// KChatCore interface (Object)
// ---------------------------------------------------------------------------

/// UniFFI-exposed wrapper around [`kchat_core::CoreImpl`].
///
/// The wrapper holds the core in a [`Mutex`] so the sync `&self`
/// methods exposed across the FFI boundary can call the
/// `&mut self` [`kchat_core::KChatCore::initialize`] entry point.
/// Bridge tests construct one via [`KChatCore::new`] and exercise
/// every method listed in the UDL.
#[derive(Debug)]
pub struct KChatCore {
    core: Mutex<CoreImpl>,
}

/// Validate `key` is exactly 32 bytes and copy into the fixed-size
/// array that [`CoreImpl::new`] expects. Any other length is a
/// caller bug, surfaced as [`KChatError::InvalidArgument`] so the
/// host language can fix the input without parsing free-form text.
fn key_from_vec(key: Vec<u8>) -> Result<[u8; 32]> {
    let len = key.len();
    <[u8; 32]>::try_from(key).map_err(|_| KChatError::InvalidArgument {
        message: format!("expected 32-byte key, got {len}"),
    })
}

impl KChatCore {
    /// UDL `constructor` — opens the SQLCipher store at
    /// `{config.data_dir}/kchat.db` with the supplied 32-byte key.
    pub fn new(config: KChatCoreConfig, key: Vec<u8>) -> Result<Self> {
        let key = key_from_vec(key)?;
        let core = CoreImpl::new(config.into(), key)?;
        Ok(KChatCore {
            core: Mutex::new(core),
        })
    }

    fn with_core<R>(
        &self,
        f: impl FnOnce(&CoreImpl) -> std::result::Result<R, kchat_core::Error>,
    ) -> Result<R> {
        let guard = self.core.lock().map_err(|_| KChatError::Storage {
            message: "core mutex poisoned".to_string(),
        })?;
        f(&guard).map_err(KChatError::from)
    }

    pub fn initialize(&self, config: KChatCoreConfig) -> Result<()> {
        let mut guard = self.core.lock().map_err(|_| KChatError::Storage {
            message: "core mutex poisoned".to_string(),
        })?;
        guard.initialize(config.into())?;
        Ok(())
    }

    pub fn register_device(&self, device_id: String) -> Result<DeviceRegistration> {
        self.with_core(|c| c.register_device(&device_id))
            .map(Into::into)
    }

    pub fn send_text(
        &self,
        conversation_id: String,
        text: String,
        reply_to: Option<String>,
    ) -> Result<ClientMessageId> {
        let conv = parse_uuid("conversation_id", &conversation_id)?;
        let reply = parse_uuid_opt("reply_to", reply_to)?;
        self.with_core(|c| c.send_text(conv, &text, reply))
            .map(Into::into)
    }

    pub fn ingest_remote_messages(
        &self,
        conversation_id: String,
        after_cursor: Option<DeliveryCursor>,
    ) -> Result<IngestResult> {
        let conv = parse_uuid("conversation_id", &conversation_id)?;
        let cursor = after_cursor.map(CoreDeliveryCursor::from);
        self.with_core(|c| c.ingest_remote_messages(conv, cursor))
            .map(Into::into)
    }

    pub fn search(&self, query: SearchQuery, scope: SearchScope) -> Result<Vec<SearchResult>> {
        let core_query = query.into_core()?;
        let core_scope: CoreSearchScope = scope.into();
        let hits = self.with_core(|c| c.search(core_query, core_scope))?;
        Ok(hits.into_iter().map(Into::into).collect())
    }

    pub fn edit_message(&self, message_id: String, new_text: String) -> Result<()> {
        let mid = parse_uuid("message_id", &message_id)?;
        self.with_core(|c| c.edit_message(mid, &new_text))
    }

    pub fn delete_for_me(&self, message_id: String) -> Result<()> {
        let mid = parse_uuid("message_id", &message_id)?;
        self.with_core(|c| c.delete_for_me(mid))
    }

    pub fn delete_for_everyone(&self, message_id: String) -> Result<()> {
        let mid = parse_uuid("message_id", &message_id)?;
        self.with_core(|c| c.delete_for_everyone(mid))
    }

    pub fn delete_conversation(&self, conversation_id: String) -> Result<()> {
        let cid = parse_uuid("conversation_id", &conversation_id)?;
        self.with_core(|c| c.delete_conversation(cid))
    }

    pub fn get_message(&self, message_id: String) -> Result<Option<MessageView>> {
        let mid = parse_uuid("message_id", &message_id)?;
        let view = self.with_core(|c| c.get_message(mid))?;
        Ok(view.map(Into::into))
    }

    pub fn get_conversation_messages(
        &self,
        conversation_id: String,
        before_ms: Option<i64>,
        limit: u32,
    ) -> Result<Vec<MessageView>> {
        let conv = parse_uuid("conversation_id", &conversation_id)?;
        let views =
            self.with_core(|c| c.get_conversation_messages(conv, before_ms, limit as usize))?;
        Ok(views.into_iter().map(Into::into).collect())
    }
}

// Compile-time check that the unused [`BackupSource`] re-export is
// still wired so future Phase-4 expansion of the UDL doesn't have
// to re-import it.
#[allow(dead_code)]
fn _backup_source_is_in_scope() -> BackupSource {
    BackupSource::default()
}

// ---------------------------------------------------------------------------
// UniFFI scaffolding
// ---------------------------------------------------------------------------

uniffi::include_scaffolding!("kchat");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: a fresh in-memory-backed `KChatCore` for tests. We
    /// open the DB through the public constructor so the same code
    /// path the FFI exercises is the one under test.
    fn fresh_bridge() -> KChatCore {
        // tempfile-free path: SQLCipher accepts the in-memory hint
        // through `data_dir = ":memory:"` only for tests that go
        // through `CoreImpl::new_in_memory`. The public bridge
        // path hits `CoreImpl::new` which opens a real file, so
        // we point it at the OS temp dir.
        let dir = std::env::temp_dir().join(format!("kchat-ios-bridge-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = KChatCoreConfig {
            data_dir: dir.to_string_lossy().into_owned(),
            platform: Platform::Ios,
            tenant_id: "tenant-test".to_string(),
        };
        KChatCore::new(cfg, vec![0x42; 32]).expect("bridge core")
    }

    #[test]
    fn bridge_constructor_rejects_wrong_key_length() {
        let dir = std::env::temp_dir().join(format!("kchat-ios-bridge-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = KChatCoreConfig {
            data_dir: dir.to_string_lossy().into_owned(),
            platform: Platform::Ios,
            tenant_id: "tenant-test".to_string(),
        };
        let err = KChatCore::new(cfg, vec![0u8; 16]).unwrap_err();
        assert!(matches!(err, KChatError::InvalidArgument { .. }));
    }

    #[test]
    fn bridge_send_text_round_trips_through_get_message() {
        // Round-trip a text send via the FFI surface: construct
        // the bridge, seed a conversation through the canonical
        // core API (the bridge does not yet expose conversation
        // creation), call `send_text`, and assert
        // `get_message` returns the matching skeleton + body.
        let bridge = fresh_bridge();
        let conv = Uuid::now_v7();

        // Seed conversation directly through the wrapped CoreImpl
        // — `create_conversation` is an inherent method on
        // CoreImpl and not part of the FFI yet.
        {
            let core = bridge.core.lock().unwrap();
            core.create_conversation(conv, Some("FFI"), 1).unwrap();
        }

        let cmid = bridge
            .send_text(conv.to_string(), "hello FFI".into(), None)
            .expect("send_text");
        assert!(!cmid.value.is_empty());
        let parsed = Uuid::parse_str(&cmid.value).expect("uuid round-trip");
        assert_eq!(parsed.get_version_num(), 7);

        let view = bridge
            .get_message(cmid.value.clone())
            .expect("get_message")
            .expect("message present");
        assert_eq!(view.message_id, cmid.value);
        assert_eq!(view.conversation_id, conv.to_string());
        assert_eq!(view.text_content.as_deref(), Some("hello FFI"));
    }

    #[test]
    fn bridge_register_device_returns_not_implemented() {
        let bridge = fresh_bridge();
        let err = bridge.register_device("device-abc".into()).unwrap_err();
        match err {
            KChatError::NotImplemented { method } => assert_eq!(method, "register_device"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bridge_send_text_invalid_uuid_is_invalid_argument() {
        let bridge = fresh_bridge();
        let err = bridge
            .send_text("not-a-uuid".into(), "hi".into(), None)
            .unwrap_err();
        assert!(matches!(err, KChatError::InvalidArgument { .. }));
    }

    #[test]
    fn platform_round_trips() {
        for p in [
            Platform::Ios,
            Platform::Android,
            Platform::MacOs,
            Platform::Windows,
        ] {
            let core: CorePlatform = p.into();
            let back: Platform = core.into();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn search_query_into_core_parses_conversation_filter() {
        let conv = Uuid::now_v7();
        let q = SearchQuery {
            query_string: "alpha".into(),
            sender_filter: None,
            conversation_filter: Some(conv.to_string()),
            date_from: None,
            date_to: None,
            content_kind: Some(ContentKind::Text),
        };
        let core_q = q.into_core().expect("into_core");
        assert_eq!(core_q.conversation_filter, Some(conv));
        assert_eq!(core_q.content_kind, Some(kchat_core::ContentKind::Text));
    }

    #[test]
    fn search_query_into_core_rejects_garbage_uuid() {
        let q = SearchQuery {
            query_string: String::new(),
            sender_filter: None,
            conversation_filter: Some("garbage".into()),
            date_from: None,
            date_to: None,
            content_kind: None,
        };
        assert!(matches!(
            q.into_core().unwrap_err(),
            KChatError::InvalidArgument { .. }
        ));
    }
}
