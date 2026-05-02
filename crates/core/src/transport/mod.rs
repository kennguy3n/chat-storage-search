//! `transport` module — Phase 1 abstraction over the MLS delivery
//! store.
//!
//! `docs/PROPOSAL.md §10` and `docs/ARCHITECTURE.md §10.4` describe
//! the cursor-based fetch contract: the local core asks the
//! transport for the messages newer than its last delivery cursor,
//! the transport returns a page plus the next cursor, and the core
//! persists each `RawDeliveryMessage` through the
//! [`crate::message::processor::MessagePersister`].
//!
//! Phase 1 lands the trait surface and a test-only mock; Phase-2+
//! implementations layer the actual HTTP / gRPC / MLS-blob clients
//! on top of [`DeliveryClient`]. Higher-phase work (archive
//! manifest fetch, range-download, etc.) lives in sibling
//! sub-modules that will be added when those engines arrive — the
//! shape of this module's public re-exports is intentionally
//! narrow so it can grow without breaking downstream callers.

use crate::formats::media_descriptor::MediaDescriptor;

/// Network / delivery-store errors surfaced through
/// [`DeliveryClient`].
///
/// Variants are intentionally coarse — the transport layer is
/// expected to flatten provider-specific HTTP / gRPC / MLS errors
/// into one of the three categories below so the upper layers can
/// route on intent (retry the request, prompt for re-auth, surface
/// to the user) without parsing free-form text.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// A network-level failure — DNS, TCP, TLS, timeout, retryable
    /// 5xx without an explicit reason. Callers may retry with
    /// backoff.
    #[error("network: {0}")]
    Network(String),

    /// The credential / token was rejected. Callers should refresh
    /// the credential before retrying.
    #[error("auth: {0}")]
    Auth(String),

    /// Server-reported, non-retryable failure (4xx other than auth,
    /// payload corruption, missing conversation, …).
    #[error("server: {0}")]
    Server(String),
}

/// One MLS-decrypted message returned by [`DeliveryClient::fetch_messages`].
///
/// `RawDeliveryMessage` is intentionally **string-typed** for ids:
/// the transport layer is responsible for whatever id format the
/// delivery store uses, and the upper layers parse them into
/// [`uuid::Uuid`] before persisting. This keeps the transport
/// trait portable across HTTP / gRPC / MLS-blob backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDeliveryMessage {
    /// Stable message identifier (UUID v7 string).
    pub message_id: String,
    /// Owning conversation (UUID string).
    pub conversation_id: String,
    /// Sender identifier — opaque from this library's perspective.
    pub sender_id: String,
    /// Wall-clock millisecond timestamp set by the sender.
    pub created_at_ms: i64,
    /// Plaintext text body, when present.
    pub text_content: Option<String>,
    /// Zero or more media descriptors per `docs/PROPOSAL.md §3.2`.
    pub media_descriptors: Vec<MediaDescriptor>,
    /// Identifier of the message this is a reply to, if any.
    pub reply_to: Option<String>,
}

/// One page of [`RawDeliveryMessage`]s plus the cursor the caller
/// should pass on the next [`DeliveryClient::fetch_messages`]
/// invocation.
///
/// `next_cursor == None` signals the delivery store has no more
/// messages newer than the highest `created_at_ms` returned in
/// `messages`.
#[derive(Debug, Clone, Default)]
pub struct FetchResult {
    /// Messages returned by this fetch, in delivery-store order.
    pub messages: Vec<RawDeliveryMessage>,
    /// Opaque cursor for the next call, or `None` if the store is
    /// drained.
    pub next_cursor: Option<String>,
}

/// Transport-layer abstraction over the MLS delivery store.
///
/// **Object-safe.** The trait carries no generic methods and no
/// `Self`-typed return values, so `Box<dyn DeliveryClient>` is a
/// valid type — that's exactly how
/// [`crate::core_impl::CoreImpl::with_transport`] receives the
/// implementation.
pub trait DeliveryClient: Send + Sync {
    /// Pull the next page of messages for `conversation_id`,
    /// resuming after `after_cursor`. `after_cursor == None` means
    /// "start from the device's last known cursor" — implementers
    /// that persist their own cursor state may interpret this as
    /// "from the beginning".
    fn fetch_messages(
        &self,
        conversation_id: &str,
        after_cursor: Option<&str>,
    ) -> Result<FetchResult, TransportError>;
}

// ---------------------------------------------------------------------------
// Test-only mock
// ---------------------------------------------------------------------------

/// In-memory test double for [`DeliveryClient`].
///
/// Tests call [`MockDeliveryClient::with_response`] to pre-stage one
/// or more `(after_cursor → FetchResult)` mappings, then hand the
/// mock to `CoreImpl::with_transport`. Each call to
/// [`MockDeliveryClient::fetch_messages`] also records the
/// `after_cursor` it was invoked with so the test can assert that
/// the upper layers forwarded the cursor verbatim.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MockDeliveryClient {
    inner: std::sync::Mutex<MockState>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct MockState {
    /// Pre-staged responses. Keyed by the optional `after_cursor`
    /// the upper layer will pass — `None` matches the first call.
    responses: Vec<(Option<String>, Result<FetchResult, TransportError>)>,
    /// Recorded `after_cursor` arguments, in call order.
    seen_cursors: Vec<Option<String>>,
}

#[cfg(test)]
impl MockDeliveryClient {
    /// Construct a new, empty mock. Tests stage responses with
    /// [`MockDeliveryClient::with_response`].
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(MockState::default()),
        }
    }

    /// Pre-stage a single response. Responses are consumed in FIFO
    /// order; the `after_cursor` argument on each
    /// [`MockDeliveryClient::fetch_messages`] call must match the
    /// `after_cursor` recorded here, otherwise the test fails fast.
    pub fn with_response(
        self,
        after_cursor: Option<&str>,
        response: Result<FetchResult, TransportError>,
    ) -> Self {
        {
            let mut state = self.inner.lock().expect("mock state poisoned");
            state
                .responses
                .push((after_cursor.map(|s| s.to_string()), response));
        }
        self
    }

    /// Snapshot the recorded cursors so far. Call sites use this to
    /// assert the upper layer forwarded `after_cursor` verbatim.
    pub fn seen_cursors(&self) -> Vec<Option<String>> {
        self.inner
            .lock()
            .expect("mock state poisoned")
            .seen_cursors
            .clone()
    }
}

#[cfg(test)]
impl DeliveryClient for MockDeliveryClient {
    fn fetch_messages(
        &self,
        _conversation_id: &str,
        after_cursor: Option<&str>,
    ) -> Result<FetchResult, TransportError> {
        let mut state = self.inner.lock().expect("mock state poisoned");
        state.seen_cursors.push(after_cursor.map(|s| s.to_string()));
        if state.responses.is_empty() {
            return Err(TransportError::Server(
                "MockDeliveryClient: no response staged".into(),
            ));
        }
        let (expected_cursor, response) = state.responses.remove(0);
        let actual_cursor = after_cursor.map(|s| s.to_string());
        assert_eq!(
            expected_cursor, actual_cursor,
            "MockDeliveryClient: unexpected after_cursor",
        );
        response
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_error_display_strings() {
        assert!(TransportError::Network("dns".into())
            .to_string()
            .starts_with("network:"));
        assert!(TransportError::Auth("token".into())
            .to_string()
            .starts_with("auth:"));
        assert!(TransportError::Server("500".into())
            .to_string()
            .starts_with("server:"));
    }

    #[test]
    fn fetch_result_default_is_empty() {
        let r = FetchResult::default();
        assert!(r.messages.is_empty());
        assert!(r.next_cursor.is_none());
    }

    #[test]
    fn delivery_client_is_object_safe() {
        // Compile-time check: trait must support dynamic dispatch
        // for `CoreImpl::with_transport` to take a
        // `Box<dyn DeliveryClient>`.
        let _b: Box<dyn DeliveryClient> = Box::new(MockDeliveryClient::new());
    }

    #[test]
    fn mock_delivery_client_returns_staged_response() {
        let raw = RawDeliveryMessage {
            message_id: "m-1".into(),
            conversation_id: "c-1".into(),
            sender_id: "u-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("hello".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        let staged = FetchResult {
            messages: vec![raw.clone()],
            next_cursor: Some("cursor-1".into()),
        };
        let mock = MockDeliveryClient::new().with_response(None, Ok(staged.clone()));
        let got = mock.fetch_messages("c-1", None).expect("mock response");
        assert_eq!(got.messages, staged.messages);
        assert_eq!(got.next_cursor, staged.next_cursor);
        assert_eq!(mock.seen_cursors(), vec![None]);
    }

    #[test]
    fn mock_delivery_client_records_cursor() {
        let mock = MockDeliveryClient::new()
            .with_response(None, Ok(FetchResult::default()))
            .with_response(Some("cursor-1"), Ok(FetchResult::default()));
        mock.fetch_messages("c-1", None).unwrap();
        mock.fetch_messages("c-1", Some("cursor-1")).unwrap();
        assert_eq!(
            mock.seen_cursors(),
            vec![None, Some("cursor-1".to_string())]
        );
    }

    #[test]
    fn mock_delivery_client_can_return_error() {
        let mock = MockDeliveryClient::new()
            .with_response(None, Err(TransportError::Network("offline".into())));
        let err = mock.fetch_messages("c-1", None).unwrap_err();
        assert!(matches!(err, TransportError::Network(_)));
    }

    #[test]
    fn raw_delivery_message_default_shape() {
        // Smoke test that the public field set is still constructable
        // — guards against accidental field renames breaking the
        // bridge layer.
        let _ = RawDeliveryMessage {
            message_id: String::new(),
            conversation_id: String::new(),
            sender_id: String::new(),
            created_at_ms: 0,
            text_content: None,
            media_descriptors: vec![],
            reply_to: None,
        };
    }
}
