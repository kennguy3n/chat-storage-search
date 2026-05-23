//! `message` module — send / receive pipeline.
//!
//! Phase 1 lands the [`processor`] skeleton: pure-Rust validators,
//! the `IngestedMessage` / `OutboxEntry` / `IngestResult` shapes,
//! and the `MessageProcessor` placeholder that the SQLCipher-backed
//! implementation will fill in. The actual prepared-statement /
//! transaction work lands with the `local_store` SQLCipher
//! integration — see `docs/PHASES.md`.

pub mod processor;

/// Message-pipeline error type wrapped by [`crate::Error::Message`].
///
/// Covers validation failures (empty body, oversize, malformed
/// reply-to), idempotency clashes (same `message_id` seen twice on
/// a different conversation), and image / thumbnail codec failures.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// A field on an [`processor::IngestedMessage`] /
    /// [`processor::OutboxEntry`] failed its invariants
    /// (empty body, conversation/message id mismatch, oversize
    /// reply chain, …). `field` names the offending field so
    /// telemetry can attribute the failure.
    #[error("validation ({field}): {detail}")]
    Validation {
        /// Name of the field that failed validation.
        field: &'static str,
        /// Free-form detail describing the invariant violation.
        detail: String,
    },

    /// A previously-seen `message_id` was submitted with a
    /// conflicting payload (different conversation, sender,
    /// timestamp, …). Surfaced from the idempotency cache.
    #[error("idempotency clash for message {message_id}: {detail}")]
    IdempotencyClash {
        /// The clashing message id.
        message_id: String,
        /// Free-form detail describing the mismatch.
        detail: String,
    },

    /// An image / thumbnail codec call failed (decode, resize,
    /// re-encode). `op` names the codec operation.
    #[error("image codec ({op}): {detail}")]
    ImageCodec {
        /// Codec operation that failed (`"decode"`, `"encode"`,
        /// `"resize"`).
        op: &'static str,
        /// Free-form detail captured from the codec.
        detail: String,
    },

    /// Free-form fallback. New failure modes should prefer a typed
    /// variant.
    #[error("{0}")]
    Custom(String),
}

impl MessageError {
    /// Construct a [`MessageError::Custom`] from anything convertible
    /// to [`String`].
    pub fn msg(msg: impl Into<String>) -> Self {
        MessageError::Custom(msg.into())
    }
}
