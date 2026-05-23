//! Chunked-blob upload pipeline.
//!
//! Drives a [`crate::transport::TransportClient`] through the
//! `init → chunk(s) → commit` sequence specified in
//! `docs/PROPOSAL.md §10.1` / `§10.2` and `docs/ARCHITECTURE.md
//! §10.1` (`POST /v1/blobs/init`, `PUT chunks/{idx}`, `POST commit`).
//!
//! The pipeline operates on the [`crate::media::chunker::SealedChunk`]
//! output of [`crate::media::chunker::chunk_and_encrypt`] — each
//! chunk already carries its over-the-ciphertext SHA-256, so the
//! upload path only has to forward the bytes plus the digest and
//! verify the server-side BLAKE3 root on commit.
//!
//! Two entry points:
//!
//! * [`upload_chunked_media`] — first-time upload; runs every chunk.
//! * [`resume_upload`] — resumes after a partial transfer; consults
//!   [`UploadState::completed_chunks`] to skip chunks the server has
//!   already received and only re-pushes the pending ones. The
//!   commit step is idempotent on retry per `docs/PHASES.md` Phase 2
//!   ("idempotent commit on retry") so resuming after a successful
//!   commit is a no-op.
//!
//! Phase 2 keeps the upload pipeline synchronous to match the
//! Phase-1 [`crate::transport::TransportClient`] surface; Phase 2+
//! flips both to `async fn` together once the production HTTP /
//! gRPC / MLS-blob client lands.

use crate::crypto::aead::BlobClass;
use crate::media::chunker::SealedChunk;
use crate::transport::TransportClient;
use crate::Error;

/// Upload-progress bookkeeping for resumable transfers.
///
/// `completed_chunks[i] == true` means chunk `i` has already been
/// uploaded to the server and acknowledged with a
/// [`crate::transport::ChunkReceipt`]. The vector length must match
/// `sealed_chunks.len()` for [`resume_upload`].
///
/// `merkle_root` is the BLAKE3 root the client committed to when it
/// first called [`crate::transport::TransportClient::init_blob_upload`];
/// it is what the resume path checks against
/// [`crate::transport::CommitBlobResponse::merkle_root`] on commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadState {
    /// Server-assigned blob id from the original
    /// [`crate::transport::BlobUploadHandle`].
    pub blob_id: String,
    /// One bit per chunk: `true` = uploaded + acknowledged.
    pub completed_chunks: Vec<bool>,
    /// Whole-object BLAKE3 root committed to at `init_blob_upload`.
    pub merkle_root: [u8; 32],
}

/// Final result of [`upload_chunked_media`] / [`resume_upload`].
///
/// `merkle_root` is the root the client computed locally;
/// `server_merkle_root` is what the server returned on commit. Both
/// must match — the upload path returns
/// [`Error::Storage`] when they disagree, but the result type also
/// surfaces both values so logging / observability can record the
/// mismatch without re-running the upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadResult {
    /// Server-assigned blob id.
    pub blob_id: String,
    /// BLAKE3 root the client computed.
    pub merkle_root: [u8; 32],
    /// BLAKE3 root the server reported on commit.
    pub server_merkle_root: [u8; 32],
}

/// Run a full `init → chunk(s) → commit` upload of `sealed_chunks`
/// and verify the server-side BLAKE3 root matches `merkle_root`.
pub fn upload_chunked_media(
    transport: &dyn TransportClient,
    sealed_chunks: &[SealedChunk],
    merkle_root: [u8; 32],
    blob_class: BlobClass,
) -> Result<UploadResult, Error> {
    if sealed_chunks.is_empty() {
        return Err(Error::Storage(
            "upload_chunked_media: sealed_chunks must contain at least one chunk".into(),
        ));
    }

    let total_size: u64 = sealed_chunks
        .iter()
        .map(|c| c.ciphertext.len() as u64)
        .sum();

    let handle = transport.init_blob_upload(total_size, blob_class, merkle_root)?;

    for (chunk_idx, chunk) in sealed_chunks.iter().enumerate() {
        let idx_u32 = u32::try_from(chunk_idx).map_err(|_| {
            Error::Storage("upload_chunked_media: chunk_idx exceeds u32::MAX".into())
        })?;
        let receipt = transport.upload_chunk(
            &handle.blob_id,
            idx_u32,
            &chunk.ciphertext,
            chunk.chunk_sha256,
        )?;
        if receipt.chunk_idx != idx_u32 {
            return Err(Error::Storage(format!(
                "upload_chunked_media: server echoed chunk_idx {got} for upload {idx_u32}",
                got = receipt.chunk_idx
            ).into()));
        }
        if receipt.sha256 != chunk.chunk_sha256 {
            return Err(Error::Storage(format!(
                "upload_chunked_media: server echoed mismatched SHA-256 for chunk {idx_u32}"
            ).into()));
        }
    }

    let commit = transport.commit_blob(&handle.blob_id)?;
    if commit.merkle_root != merkle_root {
        return Err(Error::Storage(
            "upload_chunked_media: server-side BLAKE3 root mismatch on commit".into(),
        ));
    }

    Ok(UploadResult {
        blob_id: handle.blob_id,
        merkle_root,
        server_merkle_root: commit.merkle_root,
    })
}

/// Resume an interrupted upload: skip chunks where
/// `state.completed_chunks[idx] == true`, push the rest, and run
/// commit. The function mutates `state.completed_chunks` in place so
/// a second resume call after an even-later interruption sees the
/// updated picture.
pub fn resume_upload(
    transport: &dyn TransportClient,
    state: &mut UploadState,
    sealed_chunks: &[SealedChunk],
    blob_class: BlobClass,
) -> Result<UploadResult, Error> {
    if sealed_chunks.is_empty() {
        return Err(Error::Storage(
            "resume_upload: sealed_chunks must contain at least one chunk".into(),
        ));
    }
    if state.completed_chunks.len() != sealed_chunks.len() {
        return Err(Error::Storage(format!(
            "resume_upload: completed_chunks length {state_len} != sealed_chunks length {chunks_len}",
            state_len = state.completed_chunks.len(),
            chunks_len = sealed_chunks.len(),
        ).into()));
    }

    let _ = blob_class; // The init_blob_upload call already happened on the first attempt.

    for (chunk_idx, chunk) in sealed_chunks.iter().enumerate() {
        if state.completed_chunks[chunk_idx] {
            continue;
        }
        let idx_u32 = u32::try_from(chunk_idx)
            .map_err(|_| Error::Storage("resume_upload: chunk_idx exceeds u32::MAX".into()))?;
        let receipt = transport.upload_chunk(
            &state.blob_id,
            idx_u32,
            &chunk.ciphertext,
            chunk.chunk_sha256,
        )?;
        if receipt.sha256 != chunk.chunk_sha256 || receipt.chunk_idx != idx_u32 {
            return Err(Error::Storage(format!(
                "resume_upload: receipt mismatch for chunk {idx_u32}"
            ).into()));
        }
        state.completed_chunks[chunk_idx] = true;
    }

    let commit = transport.commit_blob(&state.blob_id)?;
    if commit.merkle_root != state.merkle_root {
        return Err(Error::Storage(
            "resume_upload: server-side BLAKE3 root mismatch on commit".into(),
        ));
    }

    Ok(UploadResult {
        blob_id: state.blob_id.clone(),
        merkle_root: state.merkle_root,
        server_merkle_root: commit.merkle_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;
    use std::sync::Mutex;

    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportResult,
    };

    /// Recorded call from the mock transport, used by tests to
    /// assert the upload pipeline drove the surface in the right
    /// order with the right arguments.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum MockCall {
        Init {
            size: u64,
            blob_class: BlobClass,
            merkle_root: [u8; 32],
        },
        UploadChunk {
            blob_id: String,
            chunk_idx: u32,
            sha256: [u8; 32],
        },
        Commit {
            blob_id: String,
        },
    }

    #[derive(Debug, Default)]
    struct MockState {
        calls: Vec<MockCall>,
        // Init returns this handle; if missing, `init_blob_upload` errors.
        init_response: Option<TransportResult<BlobUploadHandle>>,
        // Commit returns this; if missing, `commit_blob` errors.
        commit_response: Option<TransportResult<CommitBlobResponse>>,
    }

    /// In-memory test double for [`TransportClient`]. Stages
    /// per-method responses up front, records every call so tests
    /// can assert the upload pipeline drove the surface correctly,
    /// and returns
    /// `Err(crate::Error::NotImplemented("transport"))` for any
    /// method the upload pipeline does not exercise.
    #[derive(Debug, Default)]
    struct MockTransportClient {
        inner: Mutex<MockState>,
    }

    impl MockTransportClient {
        fn new() -> Self {
            Self::default()
        }

        fn with_init(self, response: TransportResult<BlobUploadHandle>) -> Self {
            self.inner.lock().unwrap().init_response = Some(response);
            self
        }

        fn with_commit(self, response: TransportResult<CommitBlobResponse>) -> Self {
            self.inner.lock().unwrap().commit_response = Some(response);
            self
        }

        fn calls(&self) -> Vec<MockCall> {
            self.inner.lock().unwrap().calls.clone()
        }
    }

    impl TransportClient for MockTransportClient {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> TransportResult<FetchMessagesResponse> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn init_blob_upload(
            &self,
            size: u64,
            blob_class: BlobClass,
            expected_merkle_root: [u8; 32],
        ) -> TransportResult<BlobUploadHandle> {
            let mut state = self.inner.lock().unwrap();
            state.calls.push(MockCall::Init {
                size,
                blob_class,
                merkle_root: expected_merkle_root,
            });
            state
                .init_response
                .take()
                .unwrap_or(Err(crate::Error::Storage(
                    "MockTransportClient: no init_blob_upload response staged".into(),
                )))
        }

        fn upload_chunk(
            &self,
            blob_id: &str,
            chunk_idx: u32,
            ciphertext: &[u8],
            sha256: [u8; 32],
        ) -> TransportResult<ChunkReceipt> {
            let mut state = self.inner.lock().unwrap();
            state.calls.push(MockCall::UploadChunk {
                blob_id: blob_id.to_string(),
                chunk_idx,
                sha256,
            });
            // Sanity-check that the SHA-256 the upload pipeline
            // sent matches the SHA-256 of the bytes we observed.
            let recomputed: [u8; 32] = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(ciphertext);
                h.finalize().into()
            };
            assert_eq!(
                recomputed, sha256,
                "MockTransportClient: upload_chunk sha256 != recomputed",
            );
            Ok(ChunkReceipt {
                blob_id: blob_id.to_string(),
                chunk_idx,
                sha256,
            })
        }

        fn commit_blob(&self, blob_id: &str) -> TransportResult<CommitBlobResponse> {
            let mut state = self.inner.lock().unwrap();
            state.calls.push(MockCall::Commit {
                blob_id: blob_id.to_string(),
            });
            state
                .commit_response
                .take()
                .unwrap_or(Err(crate::Error::Storage(
                    "MockTransportClient: no commit_blob response staged".into(),
                )))
        }

        fn fetch_blob_range(&self, _blob_id: &str, _range: Range<u64>) -> TransportResult<Vec<u8>> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn fetch_archive_manifests(
            &self,
            _after_generation: Option<u64>,
        ) -> TransportResult<Vec<EncryptedManifest>> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn fetch_archive_segment(&self, _segment_id: &str) -> TransportResult<Vec<u8>> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn fetch_index_shards(
            &self,
            _conversation_hash: &str,
            _bucket: &str,
            _shard_type: &str,
        ) -> TransportResult<Vec<u8>> {
            Err(crate::Error::NotImplemented("transport"))
        }
    }

    fn dummy_chunks(count: usize) -> Vec<SealedChunk> {
        (0..count)
            .map(|i| {
                let ciphertext = vec![i as u8 + 1; 64];
                let sha256: [u8; 32] = {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(&ciphertext);
                    h.finalize().into()
                };
                SealedChunk {
                    ciphertext,
                    chunk_sha256: sha256,
                }
            })
            .collect()
    }

    fn handle(blob_id: &str) -> BlobUploadHandle {
        BlobUploadHandle {
            blob_id: blob_id.into(),
            blob_class: BlobClass::Media,
            expires_at_ms: 0,
        }
    }

    fn commit(blob_id: &str, chunk_count: u32, merkle_root: [u8; 32]) -> CommitBlobResponse {
        CommitBlobResponse {
            blob_id: blob_id.into(),
            chunk_count,
            merkle_root,
        }
    }

    #[test]
    fn upload_all_chunks_happy_path() {
        let merkle = [0x42u8; 32];
        let mock = MockTransportClient::new()
            .with_init(Ok(handle("blob-1")))
            .with_commit(Ok(commit("blob-1", 3, merkle)));
        let chunks = dummy_chunks(3);

        let res = upload_chunked_media(&mock, &chunks, merkle, BlobClass::Media).unwrap();
        assert_eq!(res.blob_id, "blob-1");
        assert_eq!(res.merkle_root, merkle);
        assert_eq!(res.server_merkle_root, merkle);

        let calls = mock.calls();
        assert_eq!(calls.len(), 5); // init + 3 chunks + commit
                                    // Init carries the total ciphertext size.
        assert_eq!(
            calls[0],
            MockCall::Init {
                size: 64 * 3,
                blob_class: BlobClass::Media,
                merkle_root: merkle,
            }
        );
        // Chunks pushed in order.
        for (call_idx, expected_idx) in [(1, 0u32), (2, 1u32), (3, 2u32)] {
            match &calls[call_idx] {
                MockCall::UploadChunk { chunk_idx, .. } => {
                    assert_eq!(*chunk_idx, expected_idx)
                }
                other => panic!("expected UploadChunk, got {other:?}"),
            }
        }
        assert_eq!(
            calls[4],
            MockCall::Commit {
                blob_id: "blob-1".into()
            }
        );
    }

    #[test]
    fn resume_skips_completed_chunks() {
        let merkle = [0x77u8; 32];
        let chunks = dummy_chunks(4);
        let mock = MockTransportClient::new().with_commit(Ok(commit("blob-7", 4, merkle)));
        let mut state = UploadState {
            blob_id: "blob-7".into(),
            // Chunks 0 and 2 already landed.
            completed_chunks: vec![true, false, true, false],
            merkle_root: merkle,
        };

        let res = resume_upload(&mock, &mut state, &chunks, BlobClass::Media).unwrap();
        assert_eq!(res.blob_id, "blob-7");

        let calls = mock.calls();
        // Two upload_chunk calls + one commit. No init.
        assert_eq!(calls.len(), 3);
        match &calls[0] {
            MockCall::UploadChunk { chunk_idx, .. } => assert_eq!(*chunk_idx, 1),
            other => panic!("expected chunk 1 upload, got {other:?}"),
        }
        match &calls[1] {
            MockCall::UploadChunk { chunk_idx, .. } => assert_eq!(*chunk_idx, 3),
            other => panic!("expected chunk 3 upload, got {other:?}"),
        }
        assert_eq!(
            calls[2],
            MockCall::Commit {
                blob_id: "blob-7".into()
            }
        );
        // The mock should have flipped state for the resumed chunks.
        assert_eq!(state.completed_chunks, vec![true, true, true, true]);
    }

    #[test]
    fn merkle_root_mismatch_on_commit_fails() {
        let client_root = [0x11u8; 32];
        let server_root = [0x22u8; 32];
        let mock = MockTransportClient::new()
            .with_init(Ok(handle("blob-9")))
            .with_commit(Ok(commit("blob-9", 1, server_root)));
        let chunks = dummy_chunks(1);
        let res = upload_chunked_media(&mock, &chunks, client_root, BlobClass::Media);
        match res {
            Err(Error::Storage(msg)) => assert!(msg.to_string().contains("BLAKE3 root mismatch"), "{msg}"),
            other => panic!("expected merkle mismatch error, got {other:?}"),
        }
    }

    #[test]
    fn empty_chunks_list_errors() {
        let mock = MockTransportClient::new();
        let res = upload_chunked_media(&mock, &[], [0u8; 32], BlobClass::Media);
        assert!(res.is_err(), "empty chunk list accepted: {res:?}");
        assert!(mock.calls().is_empty(), "no transport calls on empty input");
    }

    #[test]
    fn resume_with_all_chunks_complete_only_commits() {
        let merkle = [0x55u8; 32];
        let chunks = dummy_chunks(2);
        let mock = MockTransportClient::new().with_commit(Ok(commit("blob-x", 2, merkle)));
        let mut state = UploadState {
            blob_id: "blob-x".into(),
            completed_chunks: vec![true, true],
            merkle_root: merkle,
        };
        let res = resume_upload(&mock, &mut state, &chunks, BlobClass::Media).unwrap();
        assert_eq!(res.server_merkle_root, merkle);
        let calls = mock.calls();
        assert_eq!(calls.len(), 1, "only commit call expected");
        assert!(matches!(calls[0], MockCall::Commit { .. }));
    }

    #[test]
    fn resume_length_mismatch_errors() {
        let mock = MockTransportClient::new();
        let chunks = dummy_chunks(3);
        let mut state = UploadState {
            blob_id: "blob-y".into(),
            completed_chunks: vec![false, false],
            merkle_root: [0u8; 32],
        };
        let res = resume_upload(&mock, &mut state, &chunks, BlobClass::Media);
        assert!(res.is_err());
    }
}
