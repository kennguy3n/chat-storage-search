//! Media descriptor wire format.
//!
//! `docs/PROPOSAL.md §3.2` (the `media_asset` schema sketch) and the
//! Phase 0 checklist define what the device persists for every media
//! object. The [`MediaDescriptor`] is the CBOR-encoded form of those
//! columns: it is what the archive segment carries when offloading
//! a media key, what the manifest carries in `media_references`, and
//! what the rehydration path needs to fetch and verify a blob.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::serde_bytes_array;

/// Encrypted-media descriptor.
///
/// The descriptor binds the high-level message-layer view of a media
/// object (`asset_id`, `mime_type`) to the storage-layer view
/// (`blob_id`, chunk count, Merkle root) and to the encrypted key
/// material (`wrapped_k_asset`).
///
/// Field-by-field provenance:
///
/// | Field             | Source                                                  |
/// | ----------------- | ------------------------------------------------------- |
/// | `asset_id`        | `media_asset.asset_id` (`docs/PROPOSAL.md §3.2`)        |
/// | `mime_type`       | `media_asset.mime_type`                                 |
/// | `bytes_total`     | `media_asset.bytes_total`                               |
/// | `chunk_count`     | `media_asset.chunk_count`                               |
/// | `merkle_root`     | `media_asset.merkle_root` (32-byte BLAKE3)              |
/// | `blob_id`         | `media_asset.blob_id` (backend blob identifier; interpretation depends on `storage_sink`) |
/// | `wrapped_k_asset` | AES-256-KW(`K_local_db` / `K_archive_root` / `K_backup_root`, `K_asset`) |
/// | `storage_sink`    | Optional `media_asset.storage_sink` tag (see `docs/PROPOSAL.md §5.7`) |
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaDescriptor {
    /// Stable identifier for the media asset.
    pub asset_id: Uuid,

    /// IANA media type (e.g. `image/jpeg`, `video/mp4`).
    pub mime_type: String,

    /// Plaintext byte length of the asset.
    pub bytes_total: u64,

    /// Number of encrypted chunks the asset was split into. Chunk
    /// sizes follow `docs/PROPOSAL.md §8.1`.
    pub chunk_count: u32,

    /// 32-byte BLAKE3 Merkle root over the per-chunk SHA-256 hashes
    /// of the **ciphertext** chunks. The rehydration path verifies
    /// this root before decrypting.
    #[serde(with = "serde_bytes_array")]
    pub merkle_root: [u8; 32],

    /// Backend blob identifier (e.g. ZK Object Fabric or KChat
    /// PostgreSQL blob row id, or a sink-specific identifier such
    /// as a CloudKit record name or Drive file ID). Plaintext
    /// metadata only. The interpretation depends on
    /// [`Self::storage_sink`]: a `"kchat_backend"` value means the
    /// blob lives in the KChat blob service, an `"icloud"` value
    /// means it lives in the user's iCloud container, and so on.
    /// See `docs/PROPOSAL.md §5.7` (tiered media storage).
    pub blob_id: Uuid,

    /// `K_asset` wrapped by the appropriate root (one of `K_local_db`,
    /// `K_archive_root`, `K_backup_root`). The wrap algorithm is
    /// AES-256-KW (RFC 3394) — see [`crate::crypto::key_wrap`].
    #[serde(with = "serde_bytes")]
    pub wrapped_k_asset: Vec<u8>,

    /// Storage sink tag for the media blob (`"kchat_backend"`,
    /// `"icloud"`, `"google_drive"`, `"zk_object_fabric"`).
    /// `None` means the blob lives on the default sink
    /// (`"kchat_backend"`); existing CBOR payloads written before
    /// this field was added decode as `None` thanks to
    /// `#[serde(default)]`. See `docs/PROPOSAL.md §5.7`.
    #[serde(default)]
    pub storage_sink: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: u8) -> MediaDescriptor {
        MediaDescriptor {
            asset_id: Uuid::now_v7(),
            mime_type: format!(
                "image/{}",
                if seed.is_multiple_of(2) {
                    "jpeg"
                } else {
                    "png"
                }
            ),
            bytes_total: 1_048_576 + u64::from(seed),
            chunk_count: 4,
            merkle_root: [seed; 32],
            blob_id: Uuid::now_v7(),
            // 40 bytes = AES-256-KW wrap of a 32-byte key.
            wrapped_k_asset: vec![seed; 40],
            storage_sink: None,
        }
    }

    #[test]
    fn media_descriptor_round_trips_through_cbor() {
        let desc = sample(0x07);
        let bytes = serde_cbor::to_vec(&desc).expect("encode");
        let decoded: MediaDescriptor = serde_cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, desc);
    }

    #[test]
    fn distinct_descriptors_produce_distinct_cbor() {
        let a = sample(0x01);
        let b = sample(0x02);
        let bytes_a = serde_cbor::to_vec(&a).unwrap();
        let bytes_b = serde_cbor::to_vec(&b).unwrap();
        assert_ne!(bytes_a, bytes_b);
    }

    #[test]
    fn all_fields_survive_round_trip() {
        let desc = MediaDescriptor {
            asset_id: Uuid::now_v7(),
            mime_type: "video/mp4".to_string(),
            bytes_total: 2 * 1024 * 1024 * 1024 + 17, // 2 GiB + 17
            chunk_count: 137,
            merkle_root: {
                let mut m = [0u8; 32];
                m.iter_mut()
                    .enumerate()
                    .for_each(|(i, b)| *b = i as u8 ^ 0xA5);
                m
            },
            blob_id: Uuid::now_v7(),
            wrapped_k_asset: (0..40u8).collect(),
            storage_sink: Some("icloud".to_string()),
        };
        let bytes = serde_cbor::to_vec(&desc).unwrap();
        let decoded: MediaDescriptor = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(decoded.asset_id, desc.asset_id);
        assert_eq!(decoded.mime_type, desc.mime_type);
        assert_eq!(decoded.bytes_total, desc.bytes_total);
        assert_eq!(decoded.chunk_count, desc.chunk_count);
        assert_eq!(decoded.merkle_root, desc.merkle_root);
        assert_eq!(decoded.blob_id, desc.blob_id);
        assert_eq!(decoded.wrapped_k_asset, desc.wrapped_k_asset);
        assert_eq!(decoded.storage_sink.as_deref(), Some("icloud"));
    }

    #[test]
    fn legacy_payload_without_storage_sink_decodes_as_none() {
        // Encode the descriptor *without* the `storage_sink` field so
        // we exercise the `#[serde(default)]` migration path that
        // pre-§5.7 CBOR payloads rely on.
        #[derive(Serialize)]
        struct LegacyMediaDescriptor {
            asset_id: Uuid,
            mime_type: String,
            bytes_total: u64,
            chunk_count: u32,
            #[serde(with = "serde_bytes_array")]
            merkle_root: [u8; 32],
            blob_id: Uuid,
            #[serde(with = "serde_bytes")]
            wrapped_k_asset: Vec<u8>,
        }

        let legacy = LegacyMediaDescriptor {
            asset_id: Uuid::now_v7(),
            mime_type: "image/jpeg".to_string(),
            bytes_total: 4096,
            chunk_count: 1,
            merkle_root: [0x42; 32],
            blob_id: Uuid::now_v7(),
            wrapped_k_asset: vec![0x99; 40],
        };
        let bytes = serde_cbor::to_vec(&legacy).unwrap();
        let decoded: MediaDescriptor = serde_cbor::from_slice(&bytes).unwrap();
        assert!(decoded.storage_sink.is_none());
        assert_eq!(decoded.asset_id, legacy.asset_id);
        assert_eq!(decoded.bytes_total, legacy.bytes_total);
    }

    #[test]
    fn merkle_root_serialised_as_cbor_byte_string() {
        // Same probe as the BackupSegmentFrame test: a 32-byte
        // byte-string is `0x58 0x20 …` in CBOR.
        let desc = sample(0xAA);
        let bytes = serde_cbor::to_vec(&desc).unwrap();
        assert!(
            bytes.windows(2).any(|w| w == [0x58, 0x20]),
            "expected CBOR byte-string header for the 32-byte Merkle root, got {:02x?}",
            bytes,
        );
    }
}
