//! backup segment builder.
//!
//! Mirror of [`crate::archive::segment_builder::ArchiveSegmentBuilder`]
//! that drains the **backup** event journal and emits AEAD-sealed
//! segments suitable for upload to the cloud-backup transport.
//!
//! The builder does **not** own the connection, the event journal,
//! or the manifest writer. The orchestration layer drives it
//! explicitly:
//!
//! 1. `journal.read_unsegmented(...)` → `Vec<BackupEvent>`,
//! 2. derive `K_backup_segment` from `K_backup_root` via
//!    [`crate::crypto::key_hierarchy::derive_backup_segment`],
//! 3. `build_segment(...)` → `BuiltBackupSegment`,
//! 4. upload the ciphertext + persist a backup-segment-map row,
//! 5. `journal.advance_cursor(...)`.
//!
//! Wire format: CBOR(`BackupSegmentPayload`) → zstd → AEAD seal
//! (XChaCha20-Poly1305) under `K_backup_segment`. AAD ties the
//! `segment_id` and the BLAKE3 Merkle root over the *plaintext*
//! payload to the ciphertext so swapping ciphertexts between
//! segments fails the open.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::aead::xchacha20_poly1305::{seal, NONCE_LEN};
use crate::crypto::content_hash::content_hash;
use crate::crypto::key_hierarchy::KeyMaterial;
use crate::formats::SegmentType;
use crate::Error;

use super::event_journal::BackupEvent;

/// Domain-separation tag prepended to the CBOR payload before
/// zstd compression. Distinguishes backup segments from the
/// archive pipeline's CBOR payloads in case of accidental
/// cross-decode.
pub const BACKUP_SEGMENT_PAYLOAD_MAGIC: &[u8] = b"KCHAT_BAK_SEG_PAYLOAD_V1";

/// AEAD AAD magic — see [`build_segment_aad`].
pub const BACKUP_SEGMENT_AAD_MAGIC: &[u8] = b"KCHAT_BACKUP_SEGMENT_V1";

/// zstd compression level (matches archive default).
pub const ZSTD_COMPRESSION_LEVEL: i32 = 3;

/// Caller-supplied bundle the builder seals into one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSegmentBuildRequest {
    /// Events to seal. Must be non-empty. The builder does not
    /// re-sort the events: the journal already returns them in
    /// `event_seq` order.
    pub events: Vec<BackupEvent>,
    /// Discriminant for the encrypted payload — pinned to a
    /// variant of [`SegmentType`] so the segment frame
    /// (`crate::formats::BackupSegmentFrame`) can carry it
    /// verbatim. See `docs/DESIGN.md §6.2`.
    pub segment_type: SegmentType,
}

/// Output of [`BackupSegmentBuilder::build_segment`]: a sealed,
/// content-addressed backup segment ready for upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltBackupSegment {
    /// UUID v7 segment identifier.
    pub segment_id: Uuid,
    /// Mirror of the request's `segment_type`.
    pub segment_type: SegmentType,
    /// 24-byte XChaCha20-Poly1305 nonce sealing `ciphertext`.
    pub nonce: [u8; NONCE_LEN],
    /// AEAD ciphertext (zstd-compressed CBOR).
    pub ciphertext: Vec<u8>,
    /// BLAKE3 over the *plaintext* payload (the
    /// `BACKUP_SEGMENT_PAYLOAD_MAGIC || cbor` blob). Doubles as
    /// the segment's content-addressed identifier and the
    /// manifest-level integrity anchor.
    pub merkle_root: [u8; 32],
    /// Number of events sealed in this segment.
    pub event_count: usize,
}

/// CBOR payload sealed inside [`BuiltBackupSegment::ciphertext`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupSegmentPayload {
    /// Magic bytes (always [`BACKUP_SEGMENT_PAYLOAD_MAGIC`]).
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// Sealed events.
    pub events: Vec<BackupEvent>,
}

/// backup segment builder.
///
/// Stateless — every public method takes its own inputs.
#[derive(Debug, Default, Clone, Copy)]
pub struct BackupSegmentBuilder;

impl BackupSegmentBuilder {
    /// Construct a builder.
    pub fn new() -> Self {
        Self
    }

    /// Build a single backup segment.
    ///
    /// `k_backup_segment` is `K_backup_segment(segment_id)`
    /// the caller derives it from `K_backup_root` via
    /// [`crate::crypto::key_hierarchy::derive_backup_segment`].
    pub fn build_segment(
        &self,
        request: BackupSegmentBuildRequest,
        k_backup_segment: &KeyMaterial,
    ) -> Result<BuiltBackupSegment, Error> {
        if request.events.is_empty() {
            return Err(Error::Storage(
                "BackupSegmentBuilder::build_segment: empty events list".into(),
            ));
        }

        // 1) CBOR-encode the payload.
        let payload = BackupSegmentPayload {
            magic: BACKUP_SEGMENT_PAYLOAD_MAGIC.to_vec(),
            events: request.events.clone(),
        };
        let cbor = crate::cbor::to_vec(&payload).map_err(|e| {
            Error::Storage(crate::local_store::StorageError::CborEncode {
                context: "backup segment",
                source: e,
            })
        })?;

        // 2) Compute the integrity root over the CBOR payload
        // *not* the compressed bytes, so segments are
        // deterministic across zstd version updates.
        let merkle_root = content_hash(&cbor);

        // 3) zstd-compress the CBOR. `decode_all` on the read
        // side is symmetric.
        let compressed =
            zstd::stream::encode_all(&cbor[..], ZSTD_COMPRESSION_LEVEL).map_err(|e| {
                Error::Storage(crate::local_store::StorageError::Zstd {
                    context: "backup segment encode",
                    source: e,
                })
            })?;

        // 4) Allocate a fresh segment_id and AEAD-seal the
        // compressed payload. AAD ties the segment_id and
        // merkle_root to the ciphertext so swapping ciphertexts
        // between segments fails the open.
        let segment_id = Uuid::now_v7();
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = build_segment_aad(&segment_id, &merkle_root);

        let ciphertext =
            seal(k_backup_segment.as_bytes(), &nonce, &compressed, &aad).map_err(Error::Crypto)?;

        Ok(BuiltBackupSegment {
            segment_id,
            segment_type: request.segment_type,
            nonce,
            ciphertext,
            merkle_root,
            event_count: request.events.len(),
        })
    }
}

/// Compute the AEAD AAD for a backup segment seal:
/// `BACKUP_SEGMENT_AAD_MAGIC || segment_id(16) || merkle_root(32)`.
fn build_segment_aad(segment_id: &Uuid, merkle_root: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BACKUP_SEGMENT_AAD_MAGIC.len() + 16 + 32);
    aad.extend_from_slice(BACKUP_SEGMENT_AAD_MAGIC);
    aad.extend_from_slice(segment_id.as_bytes());
    aad.extend_from_slice(merkle_root);
    aad
}

/// Decrypt + decompress a [`BuiltBackupSegment`] back into its
/// [`BackupSegmentPayload`]. Used by the restore pipeline (Task
/// 10) and by tests.
pub fn decrypt_backup_segment(
    segment: &BuiltBackupSegment,
    k_backup_segment: &KeyMaterial,
) -> Result<BackupSegmentPayload, Error> {
    use crate::crypto::aead::xchacha20_poly1305::open;
    let aad = build_segment_aad(&segment.segment_id, &segment.merkle_root);
    let compressed = open(
        k_backup_segment.as_bytes(),
        &segment.nonce,
        &segment.ciphertext,
        &aad,
    )
    .map_err(Error::Crypto)?;
    let cbor = zstd::stream::decode_all(&compressed[..]).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::Zstd {
            context: "backup segment decode",
            source: e,
        })
    })?;
    let payload: BackupSegmentPayload = crate::cbor::from_slice(&cbor).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborDecode {
            context: "backup segment",
            source: e,
        })
    })?;
    if payload.magic != BACKUP_SEGMENT_PAYLOAD_MAGIC {
        return Err(Error::Storage(
            "backup segment payload magic mismatch".into(),
        ));
    }
    // Re-verify the Merkle root against the decoded plaintext
    // catches a malicious sealer that signed an honest AAD over
    // a payload whose merkle_root was tampered with.
    let actual_root = content_hash(&cbor);
    if actual_root != segment.merkle_root {
        return Err(Error::Storage("backup segment merkle root mismatch".into()));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::event_journal::{BackupEvent, BackupEventType};
    use crate::crypto::key_hierarchy::{derive_backup_root, KeyMaterial};

    fn fresh_k_backup_segment() -> KeyMaterial {
        let identity = KeyMaterial::from_bytes([0xAB; 32]);
        let backup_root = derive_backup_root(&identity).expect("derive backup root");
        crate::crypto::key_hierarchy::derive_backup_segment(
            &backup_root,
            &Uuid::now_v7().into_bytes(),
        )
        .expect("derive segment key")
    }

    fn sample_events(n: usize) -> Vec<BackupEvent> {
        (0..n)
            .map(|i| BackupEvent {
                event_type: BackupEventType::MessageReceived,
                conversation_id: Some(Uuid::now_v7()),
                message_id: Some(Uuid::now_v7()),
                payload: vec![i as u8; 8],
                created_at_ms: 1_777_000_000_000 + (i as i64),
            })
            .collect()
    }

    #[test]
    fn build_and_decrypt_round_trip() {
        let key = fresh_k_backup_segment();
        let events = sample_events(3);
        let segment = BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: events.clone(),
                    segment_type: SegmentType::Events,
                },
                &key,
            )
            .unwrap();
        assert_eq!(segment.event_count, 3);
        assert_eq!(segment.segment_type, SegmentType::Events);
        let payload = decrypt_backup_segment(&segment, &key).unwrap();
        assert_eq!(payload.magic, BACKUP_SEGMENT_PAYLOAD_MAGIC);
        assert_eq!(payload.events, events);
    }

    #[test]
    fn build_rejects_empty_events() {
        let key = fresh_k_backup_segment();
        let err = BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: vec![],
                    segment_type: SegmentType::Events,
                },
                &key,
            )
            .unwrap_err();
        match err {
            Error::Storage(msg) => {
                assert!(msg.to_string().contains("empty events list"), "got {msg}")
            }
            other => panic!("expected Storage, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = fresh_k_backup_segment();
        let other_key = fresh_k_backup_segment();
        let segment = BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: sample_events(2),
                    segment_type: SegmentType::Events,
                },
                &key,
            )
            .unwrap();
        let err = decrypt_backup_segment(&segment, &other_key).unwrap_err();
        // open returns Crypto error
        match err {
            Error::Crypto(_) => {}
            other => panic!("expected Crypto error, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_with_corrupted_ciphertext_fails() {
        let key = fresh_k_backup_segment();
        let mut segment = BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: sample_events(2),
                    segment_type: SegmentType::Events,
                },
                &key,
            )
            .unwrap();
        // Flip a byte in the ciphertext.
        segment.ciphertext[0] ^= 0xFF;
        let err = decrypt_backup_segment(&segment, &key).unwrap_err();
        match err {
            Error::Crypto(_) => {}
            other => panic!("expected Crypto error, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_with_tampered_merkle_root_fails() {
        let key = fresh_k_backup_segment();
        let mut segment = BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: sample_events(2),
                    segment_type: SegmentType::Events,
                },
                &key,
            )
            .unwrap();
        // Tampering with the merkle_root forces the AAD to
        // mismatch on the open side.
        segment.merkle_root[0] ^= 0xFF;
        let err = decrypt_backup_segment(&segment, &key).unwrap_err();
        match err {
            Error::Crypto(_) => {}
            other => panic!("expected Crypto error, got {other:?}"),
        }
    }

    #[test]
    fn segments_are_unique_per_call() {
        let key = fresh_k_backup_segment();
        let req1 = BackupSegmentBuildRequest {
            events: sample_events(1),
            segment_type: SegmentType::Events,
        };
        let req2 = BackupSegmentBuildRequest {
            events: sample_events(1),
            segment_type: SegmentType::Events,
        };
        let s1 = BackupSegmentBuilder::new()
            .build_segment(req1, &key)
            .unwrap();
        let s2 = BackupSegmentBuilder::new()
            .build_segment(req2, &key)
            .unwrap();
        assert_ne!(s1.segment_id, s2.segment_id);
        assert_ne!(s1.nonce, s2.nonce);
    }

    #[test]
    fn cbor_payload_round_trips_independently() {
        let payload = BackupSegmentPayload {
            magic: BACKUP_SEGMENT_PAYLOAD_MAGIC.to_vec(),
            events: sample_events(4),
        };
        let bytes = crate::cbor::to_vec(&payload).unwrap();
        let back: BackupSegmentPayload = crate::cbor::from_slice(&bytes).unwrap();
        assert_eq!(back, payload);
    }
}
