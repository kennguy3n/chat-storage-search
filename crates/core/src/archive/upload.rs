//! Phase-3 archive segment upload orchestration.
//!
//! Wires
//! [`crate::archive::segment_builder::ArchiveSegmentBuilder::build_segment`]'s
//! output into the [`crate::transport::TransportClient`] surface:
//!
//! 1. `init_blob_upload(size, BlobClass::ArchiveSegment, root)` —
//!    declare the upload up-front, committing to the **ciphertext**
//!    Merkle root the server will verify against.
//! 2. Single `upload_chunk` (archive segments today fit comfortably
//!    under the 4 MiB chunk threshold from `docs/PROPOSAL.md §10`).
//! 3. `commit_blob` — finalise the blob; the server returns the
//!    Merkle root it computed, which we cross-check against the
//!    ciphertext root we declared.
//!
//! The plaintext [`BuiltSegment::merkle_root`] is the segment's
//! content-addressed identity; the transport layer's Merkle root
//! is over the *ciphertext* chunks. We compute the latter here so
//! the server has a concrete digest to match against.

use blake3::Hasher;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::crypto::aead::BlobClass;
use crate::transport::TransportClient;
use crate::Error;

use super::segment_builder::BuiltSegment;

/// Default storage backend tag persisted to `archive_segment_map`
/// when the orchestration layer does not pick a Pattern-C / ZK
/// fabric route. Mirrors the schema column default.
pub const DEFAULT_STORAGE_BACKEND: &str = "kchat_backend";

/// Upload `segment.ciphertext` to `transport`. Returns the
/// `blob_id` the transport assigned during
/// [`TransportClient::init_blob_upload`].
///
/// The function:
///
/// * Computes the **ciphertext** BLAKE3 Merkle root over the
///   sealed bytes (single chunk → root == hash of the full
///   ciphertext).
/// * Calls `init_blob_upload(size, BlobClass::ArchiveSegment,
///   ciphertext_root)`.
/// * Streams the ciphertext as a single
///   [`TransportClient::upload_chunk`] call.
/// * Calls `commit_blob` and rejects the response if the
///   server-returned root disagrees with the declared root —
///   any mismatch is a hard integrity failure.
pub fn upload_archive_segment(
    transport: &dyn TransportClient,
    segment: &BuiltSegment,
) -> Result<String, Error> {
    let ciphertext_root = ciphertext_merkle_root(&segment.ciphertext);

    let handle = transport.init_blob_upload(
        segment.ciphertext.len() as u64,
        BlobClass::ArchiveSegment,
        ciphertext_root,
    )?;

    let chunk_sha256 = sha256(&segment.ciphertext);
    transport.upload_chunk(&handle.blob_id, 0, &segment.ciphertext, chunk_sha256)?;

    let commit = transport.commit_blob(&handle.blob_id)?;
    if commit.merkle_root != ciphertext_root {
        return Err(Error::Storage(format!(
            "archive upload: server merkle_root mismatch (segment_id={}): \
             declared {} vs server {}",
            segment.segment_id,
            hex_encode_root(&ciphertext_root),
            hex_encode_root(&commit.merkle_root),
        )));
    }

    Ok(handle.blob_id)
}

/// Persist a single `archive_segment_map` row for `segment` after
/// a successful upload. The row's `merkle_root` column carries the
/// **plaintext** Merkle root (the segment's content-addressed
/// identity), matching the column documentation in
/// `crates/core/src/local_store/schema.rs`.
pub fn persist_segment_map_row(
    conn: &Connection,
    segment: &BuiltSegment,
    blob_id: &str,
    storage_backend: &str,
) -> Result<(), Error> {
    let segment_type_str = segment_type_as_str(segment.segment_type);
    // Initial state for a freshly-uploaded segment:
    // `archive_uploaded`. The state machine transitions to
    // `archive_verified` after Merkle verification (Task 6).
    let state_str = "archive_uploaded";
    conn.execute(
        "INSERT INTO archive_segment_map(
            segment_id, conversation_id, time_bucket,
            segment_type, blob_id, storage_backend,
            merkle_root, state
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            segment.segment_id.to_string(),
            segment.conversation_id.to_string(),
            segment.time_bucket,
            segment_type_str,
            blob_id,
            storage_backend,
            segment.merkle_root.as_slice(),
            state_str,
        ],
    )
    .map_err(|e| Error::Storage(e.to_string()))?;
    Ok(())
}

/// BLAKE3 over the full ciphertext. With a single-chunk upload,
/// the per-chunk Merkle tree degenerates to one leaf so this is
/// also the Merkle root.
fn ciphertext_merkle_root(ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(ciphertext);
    *hasher.finalize().as_bytes()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Hex-encode a 32-byte root for the diagnostic message in
/// [`upload_archive_segment`]. We avoid pulling in the `hex` crate
/// just for this; the encoder is tiny.
fn hex_encode_root(root: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in root {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn segment_type_as_str(t: crate::formats::SegmentType) -> &'static str {
    use crate::formats::SegmentType::*;
    match t {
        Events => "events",
        MessageDelta => "message_delta",
        TimelineSkeleton => "timeline_skeleton",
        MediaKeyDelta => "media_key_delta",
        SearchTextIndex => "search_text_index",
        SearchVectorIndex => "search_vector_index",
        MediaIndex => "media_index",
        Checkpoint => "checkpoint",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::event_journal::{ArchiveEvent, ArchiveEventType};
    use crate::archive::segment_builder::{ArchiveSegmentBuilder, SegmentBuildRequest};
    use crate::local_store::db::LocalStoreDb;
    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportClient, TransportResult,
    };
    use std::ops::Range;
    use std::sync::Mutex;
    use uuid::Uuid;

    /// Hand-rolled mock — the one in
    /// `crates/core/src/media/upload.rs::tests::mock_transport`
    /// is private to that module's `#[cfg(test)]` scope.
    #[derive(Debug, Default)]
    struct MockTransport {
        inner: Mutex<MockState>,
    }

    #[derive(Debug, Default)]
    struct MockState {
        committed_root: Option<[u8; 32]>,
        last_chunk: Option<Vec<u8>>,
        next_blob_id: u32,
    }

    impl MockTransport {
        fn new() -> Self {
            Self::default()
        }

        fn force_commit_root(&self, root: [u8; 32]) {
            self.inner.lock().unwrap().committed_root = Some(root);
        }
    }

    impl TransportClient for MockTransport {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> TransportResult<FetchMessagesResponse> {
            Err(Error::NotImplemented("transport"))
        }

        fn init_blob_upload(
            &self,
            _size: u64,
            _blob_class: BlobClass,
            _expected_merkle_root: [u8; 32],
        ) -> TransportResult<BlobUploadHandle> {
            let mut state = self.inner.lock().unwrap();
            state.next_blob_id += 1;
            Ok(BlobUploadHandle {
                blob_id: format!("mock-blob-{}", state.next_blob_id),
                blob_class: BlobClass::ArchiveSegment,
                expires_at_ms: 1_777_000_000_000,
            })
        }

        fn upload_chunk(
            &self,
            blob_id: &str,
            chunk_idx: u32,
            ciphertext: &[u8],
            sha256: [u8; 32],
        ) -> TransportResult<ChunkReceipt> {
            self.inner.lock().unwrap().last_chunk = Some(ciphertext.to_vec());
            Ok(ChunkReceipt {
                blob_id: blob_id.into(),
                chunk_idx,
                sha256,
            })
        }

        fn commit_blob(&self, blob_id: &str) -> TransportResult<CommitBlobResponse> {
            let state = self.inner.lock().unwrap();
            let chunk = state
                .last_chunk
                .clone()
                .ok_or_else(|| Error::Storage("MockTransport: no chunk uploaded".into()))?;
            // Either honour the explicit override or recompute the
            // ciphertext Merkle root we'd actually expect.
            let root = state
                .committed_root
                .unwrap_or_else(|| ciphertext_merkle_root(&chunk));
            Ok(CommitBlobResponse {
                blob_id: blob_id.into(),
                chunk_count: 1,
                merkle_root: root,
            })
        }

        fn fetch_blob_range(&self, _blob_id: &str, _range: Range<u64>) -> TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_archive_manifests(
            &self,
            _after_generation: Option<u64>,
        ) -> TransportResult<Vec<EncryptedManifest>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_archive_segment(&self, _segment_id: &str) -> TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_index_shards(
            &self,
            _conversation_hash: &str,
            _bucket: &str,
            _shard_type: &str,
        ) -> TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }
    }

    fn fake_segment(conv: Uuid, bucket: &str) -> BuiltSegment {
        let event = ArchiveEvent {
            event_type: ArchiveEventType::MessageReceived,
            conversation_id: conv,
            message_id: Some(Uuid::now_v7()),
            payload: vec![0xDE, 0xAD],
            created_at_ms: 1_777_000_000_000,
        };
        ArchiveSegmentBuilder::new()
            .build_segment(
                SegmentBuildRequest {
                    conversation_id: conv,
                    time_bucket: bucket.into(),
                    events: vec![event],
                },
                &[0x44; 32],
            )
            .expect("build segment")
    }

    #[test]
    fn upload_and_persist_round_trip() {
        let transport = MockTransport::new();
        let segment = fake_segment(Uuid::now_v7(), "2026-04");

        let blob_id = upload_archive_segment(&transport, &segment).expect("upload");
        assert!(blob_id.starts_with("mock-blob-"));

        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        persist_segment_map_row(db.connection(), &segment, &blob_id, DEFAULT_STORAGE_BACKEND)
            .expect("persist");

        // Read back via raw SQL — the schema's helper API is
        // tested elsewhere.
        let (
            stored_segment_id,
            stored_conv,
            stored_bucket,
            stored_type,
            stored_blob,
            stored_backend,
            stored_root,
            stored_state,
        ): (
            String,
            String,
            String,
            String,
            String,
            String,
            Vec<u8>,
            String,
        ) = db
            .connection()
            .query_row(
                "SELECT segment_id, conversation_id, time_bucket, segment_type,
                        blob_id, storage_backend, merkle_root, state
                   FROM archive_segment_map",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(stored_segment_id, segment.segment_id.to_string());
        assert_eq!(stored_conv, segment.conversation_id.to_string());
        assert_eq!(stored_bucket, segment.time_bucket);
        assert_eq!(stored_type, "message_delta");
        assert_eq!(stored_blob, blob_id);
        assert_eq!(stored_backend, DEFAULT_STORAGE_BACKEND);
        assert_eq!(stored_root, segment.merkle_root.to_vec());
        assert_eq!(stored_state, "archive_uploaded");
    }

    #[test]
    fn merkle_mismatch_on_commit_fails() {
        let transport = MockTransport::new();
        // Forge a different commit root so the verification
        // branch trips.
        transport.force_commit_root([0xFF; 32]);
        let segment = fake_segment(Uuid::now_v7(), "2026-04");
        let err = upload_archive_segment(&transport, &segment).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("server merkle_root mismatch"),
            "expected mismatch error, got {msg}"
        );
    }
}
