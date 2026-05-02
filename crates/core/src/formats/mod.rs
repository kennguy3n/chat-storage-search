//! Shared on-wire / on-disk binary formats.
//!
//! Phase 0 locks the CBOR-encoded frames and manifests that travel
//! between the device, the KChat backend, and the ZK Object Fabric
//! backup sink. Every type in this module:
//!
//! * derives `Serialize` / `Deserialize` and round-trips through
//!   `serde_cbor::to_vec` / `serde_cbor::from_slice`,
//! * carries a literal `magic` field that the deserializer can use to
//!   reject the wrong frame type,
//! * uses `#[serde(with = "serde_bytes")]` on byte arrays so CBOR
//!   emits a compact byte-string instead of an array of integers.
//!
//! See `docs/PROPOSAL.md`:
//! * §5.1 — archive segment types,
//! * §6.2 — backup segment frame,
//! * §6.3 — backup manifest frame,
//! * §7.8 — search index shard format,
//! * §3.2 — media descriptor fields.

pub mod manifest;
pub mod media_descriptor;
pub mod search_shard;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Magic bytes for [`BackupSegmentFrame`]. Exactly 12 ASCII bytes.
pub const BACKUP_SEGMENT_MAGIC: [u8; 12] = *b"KCHAT_BAK_V1";

/// Magic bytes for [`ArchiveSegmentFrame`]. Exactly 12 ASCII bytes.
pub const ARCHIVE_SEGMENT_MAGIC: [u8; 12] = *b"KCHAT_ARC_V1";

/// On-wire `version` field carried by every frame in this module.
pub const FRAME_VERSION: u16 = 1;

/// Segment-type discriminant covering both backup (`docs/PROPOSAL.md
/// §6.2`) and archive (`docs/PROPOSAL.md §5.1`) segments.
///
/// Backup segments carry a single payload type (`Events`); archive
/// segments use the seven payload variants listed in §5.1. Mixing the
/// two enums into one tagged value keeps the wire format uniform —
/// frames are always parsed with the same `SegmentType` decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentType {
    /// Backup segment payload: a CBOR-encoded slice of the backup
    /// event journal (`docs/PROPOSAL.md §6.1`).
    Events,

    /// Archive segment: new / edited / deleted message bodies for a
    /// `(conversation, time_bucket)` key.
    MessageDelta,

    /// Archive segment: compact `message_skeleton` rows used to
    /// render scroll-back without the full body.
    TimelineSkeleton,

    /// Archive segment: new `K_asset` wraps under `K_archive_root`
    /// for offloaded media.
    MediaKeyDelta,

    /// Archive segment: encrypted FTS / fuzzy index shards keyed by
    /// `(conversation_id_hash, time_bucket)`.
    SearchTextIndex,

    /// Archive segment: encrypted HNSW shard fragments keyed by
    /// `(conversation_id_hash, time_bucket)`.
    SearchVectorIndex,

    /// Archive segment: OCR / transcript / caption rows for media in
    /// this `(conversation_id_hash, time_bucket)` window.
    MediaIndex,

    /// Archive segment: periodic compaction over prior deltas for a
    /// `(conversation_id_hash, time_bucket)` window.
    Checkpoint,
}

impl SegmentType {
    /// Whether this variant is permitted in a [`BackupSegmentFrame`].
    pub fn is_backup_segment(self) -> bool {
        matches!(self, SegmentType::Events)
    }

    /// Whether this variant is permitted in an
    /// [`ArchiveSegmentFrame`].
    pub fn is_archive_segment(self) -> bool {
        !self.is_backup_segment()
    }
}

/// Backup segment frame from `docs/PROPOSAL.md §6.2`.
///
/// The payload (`ciphertext`) is the AEAD-sealed, zstd-compressed
/// CBOR encoding of a slice of the backup event journal. The frame
/// itself is **plaintext metadata** — the secret material lives
/// inside `ciphertext`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupSegmentFrame {
    /// Literal `b"KCHAT_BAK_V1"`. Reject any frame that does not
    /// match exactly.
    #[serde(with = "serde_bytes_array")]
    pub magic: [u8; 12],

    /// On-wire format version. See [`FRAME_VERSION`].
    pub version: u16,

    /// UUID v7 identifying this segment. v7 is monotonic, so the
    /// segment identifier alone provides a partial ordering across
    /// segments produced by the same device.
    pub segment_id: Uuid,

    /// Discriminant for the encrypted payload. For a backup segment
    /// this is always [`SegmentType::Events`].
    pub segment_type: SegmentType,

    /// First event sequence number covered by this segment
    /// (inclusive).
    pub event_seq_from: u64,

    /// Last event sequence number covered by this segment
    /// (inclusive).
    pub event_seq_to: u64,

    /// 24-byte XChaCha20-Poly1305 nonce used to seal `ciphertext`.
    #[serde(with = "serde_bytes_array")]
    pub nonce: [u8; 24],

    /// 32-byte BLAKE3 hash of the canonical AAD (per
    /// `docs/PROPOSAL.md §8.3`). Lets a verifier authenticate the
    /// frame's metadata before opening the AEAD.
    #[serde(with = "serde_bytes_array")]
    pub aad_hash: [u8; 32],

    /// AEAD ciphertext: `XChaCha20Poly1305(K_backup_segment, nonce,
    /// aad, zstd(cbor(events)))`.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,

    /// SHA-256 over `ciphertext`. Per-chunk integrity layer described
    /// in `docs/PROPOSAL.md §8.3` (the per-chunk SHA-256 line).
    #[serde(with = "serde_bytes_array")]
    pub ciphertext_sha256: [u8; 32],
}

impl BackupSegmentFrame {
    /// Whether the magic bytes match [`BACKUP_SEGMENT_MAGIC`] and the
    /// version is exactly [`FRAME_VERSION`].
    pub fn has_valid_header(&self) -> bool {
        self.magic == BACKUP_SEGMENT_MAGIC && self.version == FRAME_VERSION
    }
}

/// Archive segment frame mirroring [`BackupSegmentFrame`] for the
/// personal-archive path described in `docs/PROPOSAL.md §5`.
///
/// Archive segments are sealed with `K_archive_segment(segment_id)`
/// derived from `K_archive_root` (see [`crate::crypto::key_hierarchy`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveSegmentFrame {
    /// Literal `b"KCHAT_ARC_V1"`.
    #[serde(with = "serde_bytes_array")]
    pub magic: [u8; 12],

    /// On-wire format version. See [`FRAME_VERSION`].
    pub version: u16,

    /// UUID v7 identifying this segment.
    pub segment_id: Uuid,

    /// One of the seven archive segment types from
    /// `docs/PROPOSAL.md §5.1`.
    pub segment_type: SegmentType,

    /// First event sequence number covered by this segment
    /// (inclusive).
    pub event_seq_from: u64,

    /// Last event sequence number covered by this segment
    /// (inclusive).
    pub event_seq_to: u64,

    /// 24-byte XChaCha20-Poly1305 nonce used to seal `ciphertext`.
    #[serde(with = "serde_bytes_array")]
    pub nonce: [u8; 24],

    /// 32-byte BLAKE3 hash of the canonical AAD.
    #[serde(with = "serde_bytes_array")]
    pub aad_hash: [u8; 32],

    /// AEAD ciphertext sealed with `K_archive_segment(segment_id)`.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,

    /// SHA-256 over `ciphertext`.
    #[serde(with = "serde_bytes_array")]
    pub ciphertext_sha256: [u8; 32],
}

impl ArchiveSegmentFrame {
    /// Whether the magic bytes match [`ARCHIVE_SEGMENT_MAGIC`] and the
    /// version is exactly [`FRAME_VERSION`].
    pub fn has_valid_header(&self) -> bool {
        self.magic == ARCHIVE_SEGMENT_MAGIC && self.version == FRAME_VERSION
    }
}

/// `serde_bytes` for fixed-size byte arrays.
///
/// `serde_bytes` only ships impls for `Vec<u8>` and `&[u8]`; CBOR
/// otherwise serialises `[u8; N]` as an array of integers, which is
/// both wasteful (≈ 2× the bytes for a 32-byte hash) and impossible to
/// validate against a magic string. This helper round-trips fixed-size
/// arrays as a single CBOR byte-string.
pub(crate) mod serde_bytes_array {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(bytes).serialize(ser)
    }

    pub fn deserialize<'de, D, const N: usize>(de: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <serde_bytes::ByteBuf>::deserialize(de)?;
        let bytes = bytes.into_vec();
        if bytes.len() != N {
            return Err(D::Error::custom(format!(
                "expected {} bytes, got {}",
                N,
                bytes.len()
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_backup_segment() -> BackupSegmentFrame {
        BackupSegmentFrame {
            magic: BACKUP_SEGMENT_MAGIC,
            version: FRAME_VERSION,
            segment_id: Uuid::now_v7(),
            segment_type: SegmentType::Events,
            event_seq_from: 0,
            event_seq_to: 1023,
            nonce: [0x11; 24],
            aad_hash: [0x22; 32],
            ciphertext: b"sealed-zstd-cbor-events".to_vec(),
            ciphertext_sha256: [0x33; 32],
        }
    }

    fn sample_archive_segment(segment_type: SegmentType) -> ArchiveSegmentFrame {
        ArchiveSegmentFrame {
            magic: ARCHIVE_SEGMENT_MAGIC,
            version: FRAME_VERSION,
            segment_id: Uuid::now_v7(),
            segment_type,
            event_seq_from: 1024,
            event_seq_to: 2047,
            nonce: [0x44; 24],
            aad_hash: [0x55; 32],
            ciphertext: b"sealed-zstd-cbor-archive-payload".to_vec(),
            ciphertext_sha256: [0x66; 32],
        }
    }

    #[test]
    fn backup_segment_frame_round_trips_through_cbor() {
        let frame = sample_backup_segment();
        let bytes = serde_cbor::to_vec(&frame).expect("encode");
        let decoded: BackupSegmentFrame = serde_cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn backup_segment_frame_magic_is_kchat_bak_v1() {
        let frame = sample_backup_segment();
        assert_eq!(&frame.magic, b"KCHAT_BAK_V1");
        assert!(frame.has_valid_header());
    }

    #[test]
    fn backup_segment_frame_rejects_wrong_magic() {
        let mut frame = sample_backup_segment();
        frame.magic = *b"NOT_KCHAT_AA";
        assert!(!frame.has_valid_header());
    }

    #[test]
    fn archive_segment_frame_round_trips_for_every_variant() {
        for st in [
            SegmentType::MessageDelta,
            SegmentType::TimelineSkeleton,
            SegmentType::MediaKeyDelta,
            SegmentType::SearchTextIndex,
            SegmentType::SearchVectorIndex,
            SegmentType::MediaIndex,
            SegmentType::Checkpoint,
        ] {
            let frame = sample_archive_segment(st);
            let bytes = serde_cbor::to_vec(&frame).expect("encode");
            let decoded: ArchiveSegmentFrame = serde_cbor::from_slice(&bytes).expect("decode");
            assert_eq!(decoded, frame, "round-trip failed for {st:?}");
        }
    }

    #[test]
    fn archive_segment_frame_magic_is_kchat_arc_v1() {
        let frame = sample_archive_segment(SegmentType::MessageDelta);
        assert_eq!(&frame.magic, b"KCHAT_ARC_V1");
        assert!(frame.has_valid_header());
    }

    #[test]
    fn segment_type_split_matches_proposal() {
        assert!(SegmentType::Events.is_backup_segment());
        assert!(!SegmentType::Events.is_archive_segment());
        for st in [
            SegmentType::MessageDelta,
            SegmentType::TimelineSkeleton,
            SegmentType::MediaKeyDelta,
            SegmentType::SearchTextIndex,
            SegmentType::SearchVectorIndex,
            SegmentType::MediaIndex,
            SegmentType::Checkpoint,
        ] {
            assert!(st.is_archive_segment(), "{st:?}");
            assert!(!st.is_backup_segment(), "{st:?}");
        }
    }

    #[test]
    fn distinct_segments_produce_distinct_cbor() {
        let backup = sample_backup_segment();
        let archive = sample_archive_segment(SegmentType::MessageDelta);
        let backup_bytes = serde_cbor::to_vec(&backup).unwrap();
        let archive_bytes = serde_cbor::to_vec(&archive).unwrap();
        assert_ne!(backup_bytes, archive_bytes);
    }

    #[test]
    fn cbor_encodes_byte_arrays_as_byte_strings() {
        // CBOR major-type 2 (byte string) starts with 0x40..=0x5F
        // (short) or 0x58/0x59/0x5A (1/2/4-byte length prefix). For
        // the 24-byte nonce we expect 0x58 0x18 (byte string,
        // length 24) somewhere in the encoding.
        let frame = sample_backup_segment();
        let bytes = serde_cbor::to_vec(&frame).unwrap();
        assert!(
            bytes.windows(2).any(|w| w == [0x58, 0x18]),
            "expected CBOR byte-string header for the 24-byte nonce, got {:02x?}",
            bytes,
        );
    }
}
