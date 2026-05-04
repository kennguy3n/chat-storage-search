//! Phase-3 archive segment builder.
//!
//! Pulls events out of [`crate::archive::event_journal`], groups
//! them by `(conversation_id, time_bucket)`, encodes the group as
//! CBOR, zstd-compresses it, AEAD-seals it under
//! `K_archive_segment(segment_id)`, and emits an
//! [`crate::formats::ArchiveSegmentFrame`]-compatible
//! [`BuiltSegment`].
//!
//! The builder does **not** own the connection, the event journal,
//! or the manifest writer. The orchestration layer (Phase 3, Task
//! 10 wires it on `CoreImpl`) drives it explicitly:
//!
//! 1. `journal.read_unsegmented(...)` → `Vec<ArchiveEvent>`,
//! 2. `ArchiveSegmentBuilder::group_events_by_bucket(...)`,
//! 3. for each `(conversation_id, time_bucket)`, derive
//!    `K_archive_segment` from the active epoch key (Task 6),
//! 4. `build_segment(...)` → `BuiltSegment`,
//! 5. upload the ciphertext + persist the segment_map row,
//! 6. `journal.advance_cursor(...)`.

use std::collections::BTreeMap;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::aead::xchacha20_poly1305::{seal, NONCE_LEN};
use crate::crypto::content_hash::content_hash;
use crate::formats::SegmentType;
use crate::Error;

use super::event_journal::ArchiveEvent;

/// Domain-separation tag prepended to the CBOR payload before
/// zstd compression. Distinguishes archive segments from the
/// backup pipeline's own CBOR payloads in case of accidental
/// cross-decode.
pub const ARCHIVE_SEGMENT_PAYLOAD_MAGIC: &[u8] = b"KCHAT_ARC_SEG_PAYLOAD_V1";

/// zstd compression level. Level 3 is zstd's recommended default
/// for "fast" payloads — archive segments are batched and not
/// latency-sensitive, but going higher offers ~5% extra
/// compression at >2× the CPU cost.
pub const ZSTD_COMPRESSION_LEVEL: i32 = 3;

/// Caller-supplied bundle the builder seals into one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentBuildRequest {
    /// Conversation this segment covers.
    pub conversation_id: Uuid,
    /// Time bucket the orchestration layer picked
    /// (e.g. `"2026-04"` for monthly archives). The builder treats
    /// this as opaque — segment_map / manifest persist it
    /// verbatim.
    pub time_bucket: String,
    /// Events to seal. Must be non-empty. The builder does not
    /// re-sort the events: the journal already returns them in
    /// `event_seq` order.
    pub events: Vec<ArchiveEvent>,
    /// Discriminant for the encrypted payload. Must be an
    /// archive-segment-type variant (i.e.
    /// [`SegmentType::is_archive_segment`] returns true). Defaults
    /// to [`SegmentType::MessageDelta`] for backwards compatibility
    /// with the Phase 3 / Task 6 builder which only emitted
    /// delta-style segments.
    ///
    /// Phase 3, Task 6 (this file) extends the builder with two
    /// additional payload shapes that share the same CBOR / zstd
    /// / XChaCha20-Poly1305 pipeline:
    ///
    /// * [`SegmentType::TimelineSkeleton`] — events that landed
    ///   only the skeleton row (no body), used by the scroll-back
    ///   rehydration path.
    /// * [`SegmentType::Checkpoint`] — a full-state snapshot of
    ///   the conversation at a point in time, used as a
    ///   compaction target.
    pub segment_type: SegmentType,
}

impl SegmentBuildRequest {
    /// Construct a delta-style request — the historical default
    /// shape. Equivalent to setting
    /// `segment_type = SegmentType::MessageDelta` explicitly.
    pub fn message_delta(
        conversation_id: Uuid,
        time_bucket: impl Into<String>,
        events: Vec<ArchiveEvent>,
    ) -> Self {
        Self {
            conversation_id,
            time_bucket: time_bucket.into(),
            events,
            segment_type: SegmentType::MessageDelta,
        }
    }

    /// Construct a [`SegmentType::TimelineSkeleton`] request.
    /// `events` must be skeleton-only (the orchestration layer
    /// filters bodies out before calling).
    pub fn timeline_skeleton(
        conversation_id: Uuid,
        time_bucket: impl Into<String>,
        events: Vec<ArchiveEvent>,
    ) -> Self {
        Self {
            conversation_id,
            time_bucket: time_bucket.into(),
            events,
            segment_type: SegmentType::TimelineSkeleton,
        }
    }

    /// Construct a [`SegmentType::Checkpoint`] request — a
    /// full-state snapshot. The orchestration layer collapses all
    /// prior deltas into the supplied event list.
    pub fn checkpoint(
        conversation_id: Uuid,
        time_bucket: impl Into<String>,
        events: Vec<ArchiveEvent>,
    ) -> Self {
        Self {
            conversation_id,
            time_bucket: time_bucket.into(),
            events,
            segment_type: SegmentType::Checkpoint,
        }
    }

    /// Construct a [`SegmentType::MediaKeyDelta`] request. Carries
    /// new `K_asset` wraps under the active epoch
    /// `K_archive_root` for offloaded media in this
    /// `(conversation_id, time_bucket)` window. The orchestration
    /// layer encodes the wrapped-key blobs into [`ArchiveEvent`]
    /// payloads before calling.
    pub fn media_key_delta(
        conversation_id: Uuid,
        time_bucket: impl Into<String>,
        events: Vec<ArchiveEvent>,
    ) -> Self {
        Self {
            conversation_id,
            time_bucket: time_bucket.into(),
            events,
            segment_type: SegmentType::MediaKeyDelta,
        }
    }

    /// Construct a [`SegmentType::SearchTextIndex`] request.
    /// Carries encrypted FTS / fuzzy index shard rows for the
    /// `(conversation_id, time_bucket)` window. The orchestration
    /// layer encodes shard rows into [`ArchiveEvent`] payloads
    /// before calling.
    pub fn search_text_index(
        conversation_id: Uuid,
        time_bucket: impl Into<String>,
        events: Vec<ArchiveEvent>,
    ) -> Self {
        Self {
            conversation_id,
            time_bucket: time_bucket.into(),
            events,
            segment_type: SegmentType::SearchTextIndex,
        }
    }

    /// Construct a [`SegmentType::SearchVectorIndex`] request.
    /// Carries encrypted HNSW shard fragments / vector rows for
    /// the `(conversation_id, time_bucket)` window. The
    /// orchestration layer encodes vector rows into
    /// [`ArchiveEvent`] payloads before calling.
    pub fn search_vector_index(
        conversation_id: Uuid,
        time_bucket: impl Into<String>,
        events: Vec<ArchiveEvent>,
    ) -> Self {
        Self {
            conversation_id,
            time_bucket: time_bucket.into(),
            events,
            segment_type: SegmentType::SearchVectorIndex,
        }
    }

    /// Construct a [`SegmentType::MediaIndex`] request. Carries
    /// OCR / transcript / caption rows for media in this
    /// `(conversation_id, time_bucket)` window. The orchestration
    /// layer encodes media-search-index rows into
    /// [`ArchiveEvent`] payloads before calling.
    pub fn media_index(
        conversation_id: Uuid,
        time_bucket: impl Into<String>,
        events: Vec<ArchiveEvent>,
    ) -> Self {
        Self {
            conversation_id,
            time_bucket: time_bucket.into(),
            events,
            segment_type: SegmentType::MediaIndex,
        }
    }
}

/// Output of [`ArchiveSegmentBuilder::build_segment`]: a sealed,
/// content-addressed archive segment ready for upload to the
/// active backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltSegment {
    /// UUID v7 segment identifier.
    pub segment_id: Uuid,
    /// Conversation the segment covers.
    pub conversation_id: Uuid,
    /// Time bucket the request supplied.
    pub time_bucket: String,
    /// Variant of [`SegmentType`] this segment encodes.
    /// Propagated verbatim from
    /// [`SegmentBuildRequest::segment_type`] so callers can
    /// inspect the variant without re-decrypting the payload.
    /// Possible values today: [`SegmentType::MessageDelta`],
    /// [`SegmentType::TimelineSkeleton`], [`SegmentType::Checkpoint`].
    pub segment_type: SegmentType,
    /// 24-byte XChaCha20-Poly1305 nonce sealing `ciphertext`.
    pub nonce: [u8; NONCE_LEN],
    /// AEAD ciphertext (zstd-compressed CBOR).
    pub ciphertext: Vec<u8>,
    /// BLAKE3 over the *plaintext* payload (the
    /// `ARCHIVE_SEGMENT_PAYLOAD_MAGIC || cbor` blob). Doubles as
    /// the segment's content-addressed identifier and as the
    /// manifest-level integrity anchor.
    pub merkle_root: [u8; 32],
    /// Number of events sealed in this segment.
    pub event_count: usize,
}

/// CBOR payload sealed inside [`BuiltSegment::ciphertext`].
///
/// The orchestration layer only needs to know the on-the-wire
/// shape to round-trip during restore; the field names line up
/// with `ARCHIVE_EVENTS` from `docs/PROPOSAL.md §6.4`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveSegmentPayload {
    /// Magic bytes (always [`ARCHIVE_SEGMENT_PAYLOAD_MAGIC`]).
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// Conversation id (string-form UUID).
    pub conversation_id: String,
    /// Time bucket string.
    pub time_bucket: String,
    /// Events.
    pub events: Vec<ArchiveEvent>,
}

/// Phase-3 archive segment builder.
///
/// Stateless — every public method takes its own inputs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArchiveSegmentBuilder;

impl ArchiveSegmentBuilder {
    /// Construct a builder.
    pub fn new() -> Self {
        Self
    }

    /// Group `events` by `(conversation_id, time_bucket)` so the
    /// orchestration layer can emit one [`BuiltSegment`] per
    /// bucket. Returns a deterministic `BTreeMap` so traversal
    /// order is stable in tests.
    ///
    /// `time_bucket_for(event)` decides which bucket each event
    /// falls into — the default implementation
    /// [`default_time_bucket`] uses calendar months keyed on
    /// `created_at_ms`.
    pub fn group_events_by_bucket<F>(
        &self,
        events: Vec<ArchiveEvent>,
        time_bucket_for: F,
    ) -> BTreeMap<(Uuid, String), Vec<ArchiveEvent>>
    where
        F: Fn(&ArchiveEvent) -> String,
    {
        let mut out: BTreeMap<(Uuid, String), Vec<ArchiveEvent>> = BTreeMap::new();
        for event in events {
            let bucket = time_bucket_for(&event);
            out.entry((event.conversation_id, bucket))
                .or_default()
                .push(event);
        }
        out
    }

    /// Build a single archive segment.
    ///
    /// `k_archive_segment` is `K_archive_segment(segment_id)` —
    /// the caller derives it from the active epoch key (Task 6).
    pub fn build_segment(
        &self,
        request: SegmentBuildRequest,
        k_archive_segment: &[u8; 32],
    ) -> Result<BuiltSegment, Error> {
        if request.events.is_empty() {
            return Err(Error::Storage(
                "ArchiveSegmentBuilder::build_segment: empty events list".into(),
            ));
        }
        // Reject backup-only variants up front — the
        // archive segment frame can only carry the seven
        // archive payload variants from `docs/PROPOSAL.md §5.1`.
        if !request.segment_type.is_archive_segment() {
            return Err(Error::Storage(format!(
                "ArchiveSegmentBuilder::build_segment: {:?} is not an archive segment type",
                request.segment_type,
            )));
        }

        // 1) CBOR-encode the payload.
        let payload = ArchiveSegmentPayload {
            magic: ARCHIVE_SEGMENT_PAYLOAD_MAGIC.to_vec(),
            conversation_id: request.conversation_id.to_string(),
            time_bucket: request.time_bucket.clone(),
            events: request.events.clone(),
        };
        let cbor = serde_cbor::to_vec(&payload)
            .map_err(|e| Error::Storage(format!("archive segment cbor encode: {e}")))?;

        // 2) Compute the integrity root over the CBOR payload —
        //    *not* the compressed bytes, so segments are
        //    deterministic across zstd version updates.
        let merkle_root = content_hash(&cbor);

        // 3) zstd-compress the CBOR. `decode_all` on the read side
        //    is symmetric.
        let compressed = zstd::stream::encode_all(&cbor[..], ZSTD_COMPRESSION_LEVEL)
            .map_err(|e| Error::Storage(format!("archive segment zstd encode: {e}")))?;

        // 4) Allocate a fresh segment_id and AEAD-seal the
        //    compressed payload. AAD ties the segment_id and
        //    merkle_root to the ciphertext so swapping ciphertexts
        //    between segments fails the open.
        let segment_id = Uuid::now_v7();
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = build_segment_aad(&segment_id, &merkle_root);
        let ciphertext =
            seal(k_archive_segment, &nonce, &compressed, &aad).map_err(Error::Crypto)?;

        Ok(BuiltSegment {
            segment_id,
            conversation_id: request.conversation_id,
            time_bucket: request.time_bucket,
            segment_type: request.segment_type,
            nonce,
            ciphertext,
            merkle_root,
            event_count: request.events.len(),
        })
    }
}

/// Default monthly time bucket. Format: `YYYY-MM`. Falls back to
/// `"unknown"` when `created_at_ms` is negative or out of range.
pub fn default_time_bucket(event: &ArchiveEvent) -> String {
    default_time_bucket_for_ms(event.created_at_ms)
}

/// Same monthly-bucket computation as
/// [`default_time_bucket`] but for a raw millisecond
/// timestamp. Used by the backup pipeline (which carries
/// `BackupEvent`, not `ArchiveEvent`) to derive the
/// `(conversation_id, time_bucket)` keys it ferries search
/// shards under.
pub fn default_time_bucket_for_ms(created_at_ms: i64) -> String {
    let secs = created_at_ms / 1_000;
    if secs < 0 {
        return "unknown".into();
    }
    // Hand-roll YYYY-MM from epoch seconds without pulling chrono
    // — chrono isn't a dependency of `kchat-core` today and this
    // is a coarse bucketing heuristic, not a calendar engine.
    // We treat all months as 30 days and all years as 365 days,
    // which is fine for archive bucketing: as long as the function
    // is deterministic and monotonic, the segment builder
    // distinguishes nearby events into separate buckets.
    let total_days = secs / 86_400;
    let years_since_1970 = total_days / 365;
    let year = 1970 + years_since_1970;
    let day_of_year = total_days % 365;
    let month = 1 + (day_of_year / 30).min(11);
    format!("{year:04}-{month:02}")
}

/// Compute the AEAD AAD for an archive segment seal:
/// `"KCHAT_ARCHIVE_SEGMENT_V1" || segment_id(16) || merkle_root(32)`.
fn build_segment_aad(segment_id: &Uuid, merkle_root: &[u8; 32]) -> Vec<u8> {
    const MAGIC: &[u8] = b"KCHAT_ARCHIVE_SEGMENT_V1";
    let mut aad = Vec::with_capacity(MAGIC.len() + 16 + 32);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(segment_id.as_bytes());
    aad.extend_from_slice(merkle_root);
    aad
}

/// Decrypt + decompress a [`BuiltSegment`] back into its
/// [`ArchiveSegmentPayload`]. Used by tests today; the restore
/// path will pull this in once Task 10 wires hydrate.
pub fn decrypt_segment(
    segment: &BuiltSegment,
    k_archive_segment: &[u8; 32],
) -> Result<ArchiveSegmentPayload, Error> {
    use crate::crypto::aead::xchacha20_poly1305::open;
    let aad = build_segment_aad(&segment.segment_id, &segment.merkle_root);
    let compressed = open(k_archive_segment, &segment.nonce, &segment.ciphertext, &aad)
        .map_err(Error::Crypto)?;
    let cbor = zstd::stream::decode_all(&compressed[..])
        .map_err(|e| Error::Storage(format!("archive segment zstd decode: {e}")))?;
    let payload: ArchiveSegmentPayload = serde_cbor::from_slice(&cbor)
        .map_err(|e| Error::Storage(format!("archive segment cbor decode: {e}")))?;
    if payload.magic != ARCHIVE_SEGMENT_PAYLOAD_MAGIC {
        return Err(Error::Storage(
            "archive segment payload magic mismatch".into(),
        ));
    }
    if content_hash(&cbor) != segment.merkle_root {
        return Err(Error::Storage(
            "archive segment plaintext merkle_root mismatch".into(),
        ));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::event_journal::ArchiveEventType;

    fn event_at(conv: Uuid, ms: i64, ty: ArchiveEventType) -> ArchiveEvent {
        ArchiveEvent {
            event_type: ty,
            conversation_id: conv,
            message_id: Some(Uuid::now_v7()),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            created_at_ms: ms,
        }
    }

    #[test]
    fn build_segment_produces_valid_ciphertext() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: "2026-04".into(),
            events: vec![event_at(conv, 1, ArchiveEventType::MessageReceived)],
            segment_type: SegmentType::MessageDelta,
        };
        let k = [0x33; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req, &k)
            .expect("build");
        assert_eq!(built.event_count, 1);
        assert_eq!(built.conversation_id, conv);
        assert_eq!(built.time_bucket, "2026-04");
        assert_eq!(built.merkle_root.len(), 32);
        assert!(!built.ciphertext.is_empty());
    }

    #[test]
    fn build_segment_round_trips_through_decrypt() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: "2026-05".into(),
            events: vec![
                event_at(conv, 1, ArchiveEventType::MessageReceived),
                event_at(conv, 2, ArchiveEventType::MessageEdited),
                event_at(conv, 3, ArchiveEventType::MediaReceived),
            ],
            segment_type: SegmentType::MessageDelta,
        };
        let k = [0x77; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .unwrap();
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
        assert_eq!(payload.conversation_id, conv.to_string());
        assert_eq!(payload.time_bucket, "2026-05");
    }

    #[test]
    fn group_events_by_bucket_partitions_correctly() {
        let conv_a = Uuid::now_v7();
        let conv_b = Uuid::now_v7();
        let events = vec![
            event_at(conv_a, 1, ArchiveEventType::MessageReceived),
            event_at(conv_a, 2, ArchiveEventType::MessageReceived),
            event_at(conv_b, 3, ArchiveEventType::MessageReceived),
        ];
        // Always-the-same-bucket function, so partitioning runs
        // off conversation_id.
        let bucket = |_e: &ArchiveEvent| "X".to_string();
        let groups = ArchiveSegmentBuilder::new().group_events_by_bucket(events, bucket);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.get(&(conv_a, "X".into())).unwrap().len(), 2);
        assert_eq!(groups.get(&(conv_b, "X".into())).unwrap().len(), 1);
    }

    #[test]
    fn empty_events_returns_error() {
        let req = SegmentBuildRequest {
            conversation_id: Uuid::now_v7(),
            time_bucket: "2026-04".into(),
            events: Vec::new(),
            segment_type: SegmentType::MessageDelta,
        };
        let err = ArchiveSegmentBuilder::new()
            .build_segment(req, &[0; 32])
            .unwrap_err();
        assert!(err.to_string().contains("empty events list"));
    }

    #[test]
    fn build_segment_round_trips_timeline_skeleton_variant() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: "2026-04".into(),
            events: vec![event_at(conv, 1, ArchiveEventType::MessageReceived)],
            segment_type: SegmentType::TimelineSkeleton,
        };
        let k = [0x44; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .expect("build");
        // Regression: the BuiltSegment must echo the request's
        // segment_type, not silently fall back to MessageDelta.
        assert_eq!(built.segment_type, SegmentType::TimelineSkeleton);
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
    }

    #[test]
    fn build_segment_round_trips_checkpoint_variant() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: "2026-04".into(),
            events: vec![event_at(conv, 7, ArchiveEventType::MessageReceived)],
            segment_type: SegmentType::Checkpoint,
        };
        let k = [0x55; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .expect("build");
        assert_eq!(built.segment_type, SegmentType::Checkpoint);
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
        assert_eq!(payload.time_bucket, "2026-04");
    }

    #[test]
    fn build_segment_rejects_backup_segment_type() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: "2026-04".into(),
            events: vec![event_at(conv, 1, ArchiveEventType::MessageReceived)],
            segment_type: SegmentType::Events,
        };
        let err = ArchiveSegmentBuilder::new()
            .build_segment(req, &[0; 32])
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not an archive segment type"),
            "expected reject-on-backup-variant error, got: {msg}"
        );
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: "2026-06".into(),
            events: vec![event_at(conv, 1, ArchiveEventType::MessageReceived)],
            segment_type: SegmentType::MessageDelta,
        };
        let k1 = [0x11; 32];
        let k2 = [0x22; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req, &k1)
            .unwrap();
        assert!(decrypt_segment(&built, &k2).is_err());
    }

    #[test]
    fn default_time_bucket_is_year_month() {
        // 1_777_000_000_000 ms ≈ 2026-04-something.
        let evt = ArchiveEvent {
            event_type: ArchiveEventType::MessageReceived,
            conversation_id: Uuid::now_v7(),
            message_id: None,
            payload: Vec::new(),
            created_at_ms: 1_777_000_000_000,
        };
        let bucket = default_time_bucket(&evt);
        assert!(bucket.starts_with("20"), "got {bucket}");
        assert_eq!(bucket.len(), 7);
        assert_eq!(&bucket[4..5], "-");
    }

    // -----------------------------------------------------------
    // Phase 3, Task 6 — TimelineSkeleton + Checkpoint variants
    // -----------------------------------------------------------

    #[test]
    fn timeline_skeleton_segment_round_trips() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest::timeline_skeleton(
            conv,
            "2026-04",
            vec![
                event_at(conv, 1, ArchiveEventType::MessageReceived),
                event_at(conv, 2, ArchiveEventType::MessageReceived),
            ],
        );
        let k = [0x55; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .unwrap();
        assert_eq!(built.segment_type, SegmentType::TimelineSkeleton);
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
        assert_eq!(payload.conversation_id, conv.to_string());
    }

    #[test]
    fn checkpoint_segment_round_trips() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest::checkpoint(
            conv,
            "2026-05",
            vec![
                event_at(conv, 1, ArchiveEventType::MessageReceived),
                event_at(conv, 2, ArchiveEventType::MessageEdited),
                event_at(conv, 3, ArchiveEventType::MediaReceived),
            ],
        );
        let k = [0x66; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .unwrap();
        assert_eq!(built.segment_type, SegmentType::Checkpoint);
        assert_eq!(built.event_count, 3);
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
    }

    #[test]
    fn segment_type_is_preserved_through_cbor_round_trip() {
        // Each archive variant must round-trip its discriminant
        // through the build → decrypt cycle. Phase 3 batch-5
        // (2026-05-04) extends this to all seven archive
        // payload variants from `docs/PROPOSAL.md §5.1`.
        let conv = Uuid::now_v7();
        for variant in [
            SegmentType::MessageDelta,
            SegmentType::TimelineSkeleton,
            SegmentType::MediaKeyDelta,
            SegmentType::SearchTextIndex,
            SegmentType::SearchVectorIndex,
            SegmentType::MediaIndex,
            SegmentType::Checkpoint,
        ] {
            let req = SegmentBuildRequest {
                conversation_id: conv,
                time_bucket: "2026-07".into(),
                events: vec![event_at(conv, 1, ArchiveEventType::MessageReceived)],
                segment_type: variant,
            };
            let k = [0x91; 32];
            let built = ArchiveSegmentBuilder::new()
                .build_segment(req.clone(), &k)
                .unwrap();
            assert_eq!(built.segment_type, variant, "variant must round-trip");
            // And the payload must decrypt back to the same
            // events list under the same key.
            let payload = decrypt_segment(&built, &k).unwrap();
            assert_eq!(payload.events, req.events);
            assert_eq!(payload.conversation_id, conv.to_string());
        }
    }

    // -----------------------------------------------------------
    // Phase 3 batch-5 — media_key_delta / search_text_index /
    // search_vector_index / media_index round-trips
    // -----------------------------------------------------------

    #[test]
    fn media_key_delta_segment_round_trips() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest::media_key_delta(
            conv,
            "2026-04",
            vec![event_at(conv, 1, ArchiveEventType::MediaReceived)],
        );
        let k = [0xA1; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .unwrap();
        assert_eq!(built.segment_type, SegmentType::MediaKeyDelta);
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
        assert_eq!(payload.time_bucket, "2026-04");
    }

    #[test]
    fn search_text_index_segment_round_trips() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest::search_text_index(
            conv,
            "2026-05",
            vec![
                event_at(conv, 1, ArchiveEventType::MessageReceived),
                event_at(conv, 2, ArchiveEventType::MessageReceived),
            ],
        );
        let k = [0xA2; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .unwrap();
        assert_eq!(built.segment_type, SegmentType::SearchTextIndex);
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
    }

    #[test]
    fn search_vector_index_segment_round_trips() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest::search_vector_index(
            conv,
            "2026-06",
            vec![event_at(conv, 1, ArchiveEventType::MessageReceived)],
        );
        let k = [0xA3; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .unwrap();
        assert_eq!(built.segment_type, SegmentType::SearchVectorIndex);
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
    }

    #[test]
    fn media_index_segment_round_trips() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest::media_index(
            conv,
            "2026-07",
            vec![event_at(conv, 1, ArchiveEventType::MediaReceived)],
        );
        let k = [0xA4; 32];
        let built = ArchiveSegmentBuilder::new()
            .build_segment(req.clone(), &k)
            .unwrap();
        assert_eq!(built.segment_type, SegmentType::MediaIndex);
        let payload = decrypt_segment(&built, &k).unwrap();
        assert_eq!(payload.events, req.events);
    }

    #[test]
    fn build_segment_accepts_every_archive_segment_type() {
        let conv = Uuid::now_v7();
        let k = [0xB7; 32];
        for variant in [
            SegmentType::MessageDelta,
            SegmentType::TimelineSkeleton,
            SegmentType::MediaKeyDelta,
            SegmentType::SearchTextIndex,
            SegmentType::SearchVectorIndex,
            SegmentType::MediaIndex,
            SegmentType::Checkpoint,
        ] {
            let req = SegmentBuildRequest {
                conversation_id: conv,
                time_bucket: "2026-08".into(),
                events: vec![event_at(conv, 1, ArchiveEventType::MessageReceived)],
                segment_type: variant,
            };
            let built = ArchiveSegmentBuilder::new()
                .build_segment(req, &k)
                .unwrap_or_else(|e| panic!("variant {variant:?} must succeed: {e}"));
            assert_eq!(built.segment_type, variant);
            assert_eq!(built.event_count, 1);
        }
    }

    #[test]
    fn build_segment_rejects_backup_only_variant() {
        let conv = Uuid::now_v7();
        let req = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: "2026-04".into(),
            events: vec![event_at(conv, 1, ArchiveEventType::MessageReceived)],
            segment_type: SegmentType::Events, // backup-only
        };
        let err = ArchiveSegmentBuilder::new()
            .build_segment(req, &[0; 32])
            .unwrap_err();
        assert!(
            err.to_string().contains("not an archive segment type"),
            "got {err}",
        );
    }
}
