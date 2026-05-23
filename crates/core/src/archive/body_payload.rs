//! Archive event body payload — cold-hydration glue.
//!
//! A search hit that lives only in the personal archive must be
//! pulled out of the encrypted segment and re-landed in the local
//! store under
//! [`crate::lib::BodyState::LocalPlainAvailable`]. The orchestration
//! layer only has the `(conversation_id, time_bucket, message_id)`
//! triple at that point, so the body bytes have to ride inside the
//! segment itself — there is no other place to keep them once the
//! local body is offloaded.
//!
//! [`crate::archive::event_journal::ArchiveEvent::payload`] is an
//! application-defined byte string. Up through PR #32 the only
//! producer was
//! [`crate::message::processor::encode_event_payload`], which
//! emits a four-element CBOR array `[message_id, conversation_id,
//! sender_id, created_at_ms]` — sufficient for the segment builder
//! and the offload bookkeeping but missing the actual text body.
//!
//! This module owns the *body-bearing* payload variant. The wire
//! format is a tagged CBOR struct so the decoder can disambiguate
//! the two payload shapes: a four-element CBOR array (legacy
//! payload) starts with `0x84`, while the body-bearing variant is
//! a CBOR map (`0xa2`). The producer ([`encode`]) writes the new
//! shape; the consumer
//! ([`crate::core_impl::CoreImpl::hydrate_cold_search_results`])
//! calls [`try_decode_text`] which returns `Some(text)` only when
//! the body-bearing variant is present, gracefully returning
//! `None` for legacy payloads or unknown shapes.
//!
//! Privacy contract: the magic constant and the `text_content`
//! field both live inside the AEAD-sealed
//! [`crate::archive::segment_builder::ArchiveSegmentBuilder`]
//! ciphertext, so the on-wire shape is never observable. Only the
//! orchestration layer reading freshly-decrypted segments sees
//! these bytes.

use serde::{Deserialize, Serialize};

use crate::Error;

/// Domain-separation magic for [`ArchiveMessageBodyPayload`]. The
/// suffix tracks the wire-format version; bumps require a
/// migration on every device that has staged but not yet
/// segmented archive events.
pub const ARCHIVE_BODY_PAYLOAD_MAGIC: &str = "KCHAT_ARCHIVE_BODY_PAYLOAD_V1";

/// Body-bearing variant of an archive event payload.
///
/// `text_content` is `None` for media-only messages (no caption).
/// The encoder always writes the optional field — a legacy
/// payload (no magic) is handled by [`try_decode_text`] returning
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveMessageBodyPayload {
    /// Always [`ARCHIVE_BODY_PAYLOAD_MAGIC`].
    pub magic: String,
    /// Plaintext body, when the message has one.
    pub text_content: Option<String>,
}

/// CBOR-encode the body-bearing payload for an archive event.
///
/// Used by the message-processor archive event writers so that
/// the freshly-archived segment carries the message body. Returns
/// `Err(Error::Storage)` only on the (effectively unreachable)
/// CBOR encoder failure.
pub fn encode(text_content: Option<&str>) -> Result<Vec<u8>, Error> {
    let payload = ArchiveMessageBodyPayload {
        magic: ARCHIVE_BODY_PAYLOAD_MAGIC.into(),
        text_content: text_content.map(|t| t.to_string()),
    };
    crate::cbor::to_vec(&payload)
        .map_err(|e| Error::Storage(format!("archive body payload encode: {e}").into()))
}

/// Best-effort decode of an archive event payload back to its
/// text body. Returns `Some(text)` when the bytes match
/// [`ArchiveMessageBodyPayload`] *and* the body is non-empty;
/// `None` for legacy 4-tuple payloads, missing magic, or
/// `text_content == None`.
///
/// Lenient by design: the cold-hit hydration path uses the
/// `Option` to decide whether to skip a particular event (e.g.
/// because it is a media-only or pre-`V1` payload). Errors are
/// swallowed so a single malformed event in a segment does not
/// abort hydration of the surrounding events.
pub fn try_decode_text(bytes: &[u8]) -> Option<String> {
    let payload: ArchiveMessageBodyPayload = crate::cbor::from_slice(bytes).ok()?;
    if payload.magic != ARCHIVE_BODY_PAYLOAD_MAGIC {
        return None;
    }
    payload.text_content.filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_text_body() {
        let bytes = encode(Some("hello lighthouse")).unwrap();
        assert_eq!(try_decode_text(&bytes).as_deref(), Some("hello lighthouse"));
    }

    #[test]
    fn returns_none_for_legacy_4_tuple_payload() {
        // The byte layout of `encode_event_payload`
        // `[message_id, conversation_id, sender_id, created_at_ms]`
        // never contains the body magic, so the decoder must
        // fall through cleanly without raising an error.
        let legacy = vec![
            0x84, // array(4)
            0x60, // text("")
            0x60, 0x60, 0x00,
        ];
        assert!(try_decode_text(&legacy).is_none());
    }

    #[test]
    fn returns_none_for_empty_body() {
        let bytes = encode(Some("")).unwrap();
        assert!(try_decode_text(&bytes).is_none());
    }

    #[test]
    fn returns_none_for_media_only_payload() {
        let bytes = encode(None).unwrap();
        assert!(try_decode_text(&bytes).is_none());
    }

    #[test]
    fn returns_none_for_garbage_bytes() {
        // Random non-CBOR bytes must not panic.
        assert!(try_decode_text(&[0xFF, 0xFF, 0xFF]).is_none());
    }
}
