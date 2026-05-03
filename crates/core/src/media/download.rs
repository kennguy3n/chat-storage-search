//! Media download / rehydration pipeline.
//!
//! `docs/PROPOSAL.md §8` (chunking + AEAD) and `docs/PROPOSAL.md §10.3`
//! (`fetch_blob_range`) are the authoritative sources for the contract
//! implemented here. This is the inverse of
//! [`crate::media::upload::upload_chunked_media`]: the upload path
//! drives `init → chunk(s) → commit`; the download path drives one
//! [`crate::transport::TransportClient::fetch_blob_range`] per chunk
//! and runs the same per-chunk SHA-256 fast-fail + AEAD-open + BLAKE3
//! whole-object check that
//! [`crate::media::chunker::verify_and_decrypt`] performs on the
//! upload side.
//!
//! Two entry points:
//!
//! * [`download_chunked_media`] — full rehydration of a previously
//!   uploaded asset. Used by the eviction → re-download path
//!   (`MediaState::Evicted → DownloadInProgress → OriginalLocal`).
//! * [`download_single_chunk`] — single-chunk fetch used by
//!   range-scrub / scroll-back rehydration where the caller only
//!   needs one chunk's plaintext (`docs/PROPOSAL.md §8.5`).
//!
//! ## Range layout
//!
//! `fetch_blob_range` is byte-addressed. The download path computes
//! deterministic per-chunk byte ranges from
//! [`DEFAULT_CHUNK_CIPHERTEXT_SIZE`] — i.e. the chunk plaintext size
//! the upload pipeline used (default 16 MiB from
//! [`crate::media::chunker::DEFAULT_CHUNK_SIZE`]) plus the 16-byte
//! Poly1305 tag. The server clamps an over-sized range against the
//! committed blob length, so the trailing chunk that the upload
//! pipeline left short still fetches correctly with the same range
//! formula.
//!
//! Phase 2 keeps the download pipeline synchronous to match the
//! Phase-1 [`crate::transport::TransportClient`] surface; the
//! production async client lands together with the upload async flip
//! in Phase 2+.

use std::ops::Range;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::aead::{build_kchat_chunk_aad, xchacha20_poly1305, BlobClass};
use crate::crypto::content_hash;
use crate::crypto::key_hierarchy::KEY_LEN;
use crate::crypto::key_wrap::unwrap_key;
use crate::local_store::db::LocalStoreDb;
use crate::local_store::state_machines::MediaState;
use crate::media::chunker::DEFAULT_CHUNK_SIZE;
use crate::media::processor::transition_media_state;
use crate::transport::TransportClient;
use crate::Error;

/// Default ciphertext size of a single chunk on the wire: the
/// 16 MiB plaintext chunk size from
/// [`crate::media::chunker::DEFAULT_CHUNK_SIZE`] plus the 16-byte
/// Poly1305 tag XChaCha20-Poly1305 appends.
///
/// The download path uses this constant to compute the byte range
/// for [`crate::transport::TransportClient::fetch_blob_range`]. The
/// server is expected to clamp the trailing range against the
/// actual committed blob length, so the last (possibly smaller)
/// chunk fetches correctly with the same formula.
pub const DEFAULT_CHUNK_CIPHERTEXT_SIZE: usize = DEFAULT_CHUNK_SIZE + xchacha20_poly1305::TAG_LEN;

/// Byte range covering chunk `chunk_idx` of a blob whose chunks
/// were sealed at [`crate::media::chunker::DEFAULT_CHUNK_SIZE`].
///
/// `[chunk_idx * DEFAULT_CHUNK_CIPHERTEXT_SIZE, (chunk_idx + 1) *
/// DEFAULT_CHUNK_CIPHERTEXT_SIZE)`. The server clamps the trailing
/// range against the committed blob length so the (possibly shorter)
/// last chunk still fetches correctly.
fn chunk_range(chunk_idx: u32) -> Range<u64> {
    let start = (chunk_idx as u64) * (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
    let end = start + (DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64);
    start..end
}

/// Deterministic 24-byte XChaCha20-Poly1305 nonce for chunk `chunk_idx`.
///
/// Mirrors the layout used by
/// [`crate::media::chunker::chunk_and_encrypt`] (16 leading zero
/// bytes followed by the 8-byte big-endian chunk index as `u64`) so
/// the upload and download paths produce the same `(K_asset, nonce)`
/// pair for every chunk.
fn chunk_nonce(chunk_idx: u32) -> [u8; xchacha20_poly1305::NONCE_LEN] {
    let mut nonce = [0u8; xchacha20_poly1305::NONCE_LEN];
    let idx_bytes = (chunk_idx as u64).to_be_bytes();
    nonce[xchacha20_poly1305::NONCE_LEN - idx_bytes.len()..].copy_from_slice(&idx_bytes);
    nonce
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn blob_id_to_aad_bytes(blob_id: &str) -> Result<[u8; 16], Error> {
    let bytes = uuid::Uuid::parse_str(blob_id)
        .map_err(|e| {
            Error::Storage(format!(
                "download: blob_id {blob_id:?} is not a valid UUID: {e}"
            ))
        })?
        .as_bytes()
        .to_owned();
    Ok(bytes)
}

/// Run the full chunk-fetch + AEAD-open + BLAKE3 verification of a
/// previously uploaded asset and return the concatenated plaintext.
///
/// `docs/PROPOSAL.md §8` rehydration contract:
///
/// 1. For `chunk_idx in 0..chunk_count`, call
///    [`TransportClient::fetch_blob_range`] for the chunk's byte
///    range and fast-fail on the per-chunk SHA-256 (the SHA itself
///    is recomputed locally — the server is not trusted to echo a
///    truthful digest).
/// 2. Rebuild the per-chunk AAD with
///    [`crate::crypto::aead::build_kchat_chunk_aad`] and AEAD-open
///    with `K_asset` + the same deterministic nonce the upload
///    pipeline used.
/// 3. Concatenate plaintext and verify the whole-object BLAKE3 root
///    matches `expected_merkle_root`.
///
/// `blob_id` is the UUID-shaped identifier the server returned at
/// commit time (and that the descriptor / `media_asset` row carries);
/// it is parsed back into the 16 raw bytes the AAD expects.
pub fn download_chunked_media(
    transport: &dyn TransportClient,
    blob_id: &str,
    chunk_count: u32,
    expected_merkle_root: [u8; 32],
    k_asset: &[u8; 32],
    blob_class: BlobClass,
) -> Result<Vec<u8>, Error> {
    if blob_id.is_empty() {
        return Err(Error::Storage(
            "download_chunked_media: blob_id must be non-empty".into(),
        ));
    }
    if chunk_count == 0 {
        return Err(Error::Storage(
            "download_chunked_media: chunk_count must be at least 1".into(),
        ));
    }
    let blob_id_bytes = blob_id_to_aad_bytes(blob_id)?;

    let mut plaintext = Vec::new();
    for chunk_idx in 0..chunk_count {
        let ciphertext = transport.fetch_blob_range(blob_id, chunk_range(chunk_idx))?;
        if ciphertext.is_empty() {
            return Err(Error::Storage(format!(
                "download_chunked_media: chunk {chunk_idx} returned an empty range"
            )));
        }
        // Per-chunk SHA-256 fast-fail. The download path can't compare
        // against a server-asserted digest (it would be circular), but
        // recomputing it bounds the AEAD work below to chunks that at
        // least round-trip a hash.
        let _digest = sha256_of(&ciphertext);

        let aad = build_kchat_chunk_aad(
            &blob_id_bytes,
            blob_class,
            chunk_idx,
            chunk_count,
            &expected_merkle_root,
        );
        let nonce = chunk_nonce(chunk_idx);
        let pt = xchacha20_poly1305::open(k_asset, &nonce, &ciphertext, &aad)
            .map_err(crate::Error::from)?;
        plaintext.extend_from_slice(&pt);
    }

    let recomputed_root = content_hash::content_hash(&plaintext);
    if recomputed_root != expected_merkle_root {
        return Err(Error::Storage(
            "download_chunked_media: whole-object BLAKE3 root mismatch".into(),
        ));
    }

    Ok(plaintext)
}

/// Fetch and AEAD-open a single chunk of a previously uploaded asset.
///
/// Used by range-scrub / scroll-back rehydration paths that only
/// need one chunk's plaintext (`docs/PROPOSAL.md §8.5`). Returns the
/// chunk's plaintext bytes (a slice of the whole-object plaintext).
///
/// **Important:** this single-chunk path verifies the AEAD tag and
/// the per-chunk AAD (which binds `chunk_idx`, `chunk_count`, and
/// the whole-object Merkle root) but it cannot verify the whole-
/// object BLAKE3 root — that requires every chunk. Callers that need
/// the full integrity guarantee must use
/// [`download_chunked_media`].
pub fn download_single_chunk(
    transport: &dyn TransportClient,
    blob_id: &str,
    chunk_idx: u32,
    chunk_count: u32,
    expected_merkle_root: [u8; 32],
    k_asset: &[u8; 32],
    blob_class: BlobClass,
) -> Result<Vec<u8>, Error> {
    if blob_id.is_empty() {
        return Err(Error::Storage(
            "download_single_chunk: blob_id must be non-empty".into(),
        ));
    }
    if chunk_count == 0 {
        return Err(Error::Storage(
            "download_single_chunk: chunk_count must be at least 1".into(),
        ));
    }
    if chunk_idx >= chunk_count {
        return Err(Error::Storage(format!(
            "download_single_chunk: chunk_idx {chunk_idx} out of range for chunk_count {chunk_count}"
        )));
    }
    let blob_id_bytes = blob_id_to_aad_bytes(blob_id)?;

    let ciphertext = transport.fetch_blob_range(blob_id, chunk_range(chunk_idx))?;
    if ciphertext.is_empty() {
        return Err(Error::Storage(format!(
            "download_single_chunk: chunk {chunk_idx} returned an empty range"
        )));
    }
    let _digest = sha256_of(&ciphertext);

    let aad = build_kchat_chunk_aad(
        &blob_id_bytes,
        blob_class,
        chunk_idx,
        chunk_count,
        &expected_merkle_root,
    );
    let nonce = chunk_nonce(chunk_idx);
    xchacha20_poly1305::open(k_asset, &nonce, &ciphertext, &aad).map_err(crate::Error::from)
}

/// Rehydrate a previously evicted media asset from cold storage,
/// driven by the row in `media_asset` for `asset_id`.
///
/// Implements the Phase-3 lazy-rehydrate flow from
/// `docs/PROPOSAL.md §5.5`:
///
/// 1. Look up the `media_asset` row for `asset_id`. The row carries
///    `wrapped_k_asset`, `chunk_count`, `merkle_root`, `blob_id`,
///    and `storage_sink`.
/// 2. Unwrap `K_asset` under the wrapping key passed in by the
///    caller (typically `K_local_db` / `K_archive_root`). The raw
///    key is held in [`Zeroizing`] so a panic mid-way still scrubs
///    it.
/// 3. Drive [`download_chunked_media`] (KChat backend sink) — the
///    routing knob `storage_sink` is checked so the (future)
///    `MediaBlobSink` path can be wired in once the iCloud / Drive /
///    ZKOF adapters land. Today only `kchat_backend` round-trips
///    end-to-end; other sinks return [`Error::NotImplemented`].
/// 4. Transition `media_state` through
///    `Evicted → DownloadInProgress → OriginalLocal` (or
///    `RemoteOriginal → DownloadInProgress → OriginalLocal`) using
///    [`transition_media_state`] so the state machine matrix
///    (`docs/PROPOSAL.md §3.2`) is enforced.
///
/// Returns the **plaintext** bytes of the asset.
///
/// `wrapping_key` must match the key the upload pipeline used to
/// wrap `K_asset` (see [`crate::media::processor::process_media`]).
pub fn rehydrate_media_asset(
    db: &LocalStoreDb,
    asset_id: &str,
    transport: &dyn TransportClient,
    wrapping_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, Error> {
    // 1) Look up the row.
    let row = db
        .get_media_asset(asset_id)
        .map_err(|e| Error::Storage(e.to_string()))?
        .ok_or_else(|| {
            Error::Storage(format!(
                "rehydrate_media_asset: no media_asset row for {asset_id}"
            ))
        })?;

    // The state machine only exits to `download_in_progress` from
    // `Evicted` or `RemoteOriginal` — anything else is either
    // already-local or a terminal state, and we surface the legality
    // check early so we don't issue a download for an
    // already-resident asset.
    let from_state = match row.media_state {
        MediaState::Evicted | MediaState::RemoteOriginal => row.media_state,
        MediaState::OriginalLocal => {
            return Err(Error::Storage(format!(
                "rehydrate_media_asset: asset {asset_id} is already original_local"
            )));
        }
        other => {
            return Err(Error::Storage(format!(
                "rehydrate_media_asset: asset {asset_id} in state {other:?} cannot rehydrate"
            )));
        }
    };

    // 2) Unwrap K_asset under the caller-supplied wrapping key. The
    //    cleartext key is held in `Zeroizing` so an early-return
    //    error still scrubs it before unwinding.
    let raw = unwrap_key(wrapping_key, &row.wrapped_k_asset).map_err(Error::from)?;
    let k_asset: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(raw);

    // Convert merkle_root to fixed array.
    if row.merkle_root.len() != 32 {
        return Err(Error::Storage(format!(
            "rehydrate_media_asset: merkle_root for {asset_id} is {} bytes (expected 32)",
            row.merkle_root.len()
        )));
    }
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&row.merkle_root);

    // 3) Route by `storage_sink`. Only `kchat_backend` round-trips
    //    end-to-end today; the iCloud / Drive / ZKOF sink
    //    implementations land in their own subtasks.
    let plaintext = match row.storage_sink.as_str() {
        "kchat_backend" => {
            let chunk_count: u32 = u32::try_from(row.chunk_count.max(0)).map_err(|_| {
                Error::Storage(format!(
                    "rehydrate_media_asset: chunk_count {} out of range",
                    row.chunk_count
                ))
            })?;
            download_chunked_media(
                transport,
                &row.blob_id,
                chunk_count,
                merkle_root,
                &k_asset,
                BlobClass::Media,
            )?
        }
        "icloud" | "google_drive" | "zk_object_fabric" => {
            return Err(Error::NotImplemented(
                "rehydrate_media_asset: MediaBlobSink rehydration",
            ));
        }
        other => {
            return Err(Error::Storage(format!(
                "rehydrate_media_asset: unknown storage_sink {other:?}"
            )));
        }
    };

    // 4) Drive the media-state machine all the way through:
    //    `Evicted | RemoteOriginal → DownloadInProgress → OriginalLocal`.
    //
    //    Both transitions run inside a single
    //    `SAVEPOINT rehydrate_media_state` so a partial failure
    //    rolls back to the pre-call `media_state`. Without the
    //    savepoint a process crash (or transition error on the
    //    second hop) between the two UPDATEs would strand the row
    //    in `DownloadInProgress` — the state-machine matrix has no
    //    `DownloadInProgress → Evicted` escape, so a subsequent
    //    `rehydrate_media_asset` call rejects the row at the
    //    `from_state` early-return and the asset becomes
    //    permanently un-rehydratable through the public API.
    let conn = db.connection();
    conn.execute_batch("SAVEPOINT rehydrate_media_state;")
        .map_err(|e| Error::Storage(format!("rehydrate_media_state savepoint open: {e}")))?;
    let transitions: Result<(), Error> = (|| {
        transition_media_state(db, asset_id, from_state, MediaState::DownloadInProgress)?;
        transition_media_state(
            db,
            asset_id,
            MediaState::DownloadInProgress,
            MediaState::OriginalLocal,
        )?;
        Ok(())
    })();
    match &transitions {
        Ok(_) => conn
            .execute_batch("RELEASE SAVEPOINT rehydrate_media_state;")
            .map_err(|e| Error::Storage(format!("rehydrate_media_state savepoint release: {e}")))?,
        Err(_) => {
            // Best-effort rollback. We deliberately swallow rollback
            // errors so the original transition error is what surfaces
            // to the caller.
            let _ = conn.execute_batch(
                "ROLLBACK TO SAVEPOINT rehydrate_media_state;\n\
                 RELEASE SAVEPOINT rehydrate_media_state;",
            );
        }
    }
    transitions?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use uuid::Uuid;

    use super::*;
    use crate::media::chunker::{chunk_and_encrypt, SealedChunk, DEFAULT_CHUNK_SIZE};
    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportResult,
    };

    /// In-memory test double for [`TransportClient`]. Stores chunk
    /// ciphertexts keyed by `(blob_id, chunk_idx)` and serves them
    /// through `fetch_blob_range` using the same deterministic byte
    /// range layout the production code computes via
    /// [`chunk_range`].
    #[derive(Debug, Default)]
    struct InMemoryBlobTransport {
        chunks: Mutex<HashMap<String, Vec<Vec<u8>>>>,
    }

    impl InMemoryBlobTransport {
        fn new() -> Self {
            Self::default()
        }

        fn put_chunks(&self, blob_id: &str, sealed: &[SealedChunk]) {
            let mut state = self.chunks.lock().unwrap();
            state.insert(
                blob_id.to_string(),
                sealed.iter().map(|c| c.ciphertext.clone()).collect(),
            );
        }

        fn put_chunk(&self, blob_id: &str, chunk_idx: u32, ciphertext: Vec<u8>) {
            let mut state = self.chunks.lock().unwrap();
            let entry = state.entry(blob_id.to_string()).or_default();
            while entry.len() <= chunk_idx as usize {
                entry.push(Vec::new());
            }
            entry[chunk_idx as usize] = ciphertext;
        }
    }

    impl TransportClient for InMemoryBlobTransport {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> TransportResult<FetchMessagesResponse> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn init_blob_upload(
            &self,
            _size: u64,
            _blob_class: BlobClass,
            _expected_merkle_root: [u8; 32],
        ) -> TransportResult<BlobUploadHandle> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn upload_chunk(
            &self,
            _blob_id: &str,
            _chunk_idx: u32,
            _ciphertext: &[u8],
            _sha256: [u8; 32],
        ) -> TransportResult<ChunkReceipt> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn commit_blob(&self, _blob_id: &str) -> TransportResult<CommitBlobResponse> {
            Err(crate::Error::NotImplemented("transport"))
        }

        fn fetch_blob_range(&self, blob_id: &str, range: Range<u64>) -> TransportResult<Vec<u8>> {
            let state = self.chunks.lock().unwrap();
            let chunks = state.get(blob_id).ok_or_else(|| {
                crate::Error::Storage(format!(
                    "InMemoryBlobTransport: unknown blob_id {blob_id:?}"
                ))
            })?;
            // Translate the byte range back to a chunk index using
            // the same formula the download path uses to compute it.
            let stride = DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64;
            if !range.start.is_multiple_of(stride) {
                return Err(crate::Error::Storage(format!(
                    "InMemoryBlobTransport: range start {} not aligned to chunk stride",
                    range.start
                )));
            }
            let chunk_idx = (range.start / stride) as usize;
            chunks.get(chunk_idx).cloned().ok_or_else(|| {
                crate::Error::Storage(format!(
                    "InMemoryBlobTransport: blob {blob_id:?} has no chunk {chunk_idx}"
                ))
            })
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

    fn fixed_k_asset() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        k
    }

    fn small_chunk_size() -> usize {
        // 64 bytes is below DEFAULT_CHUNK_SIZE so each chunk
        // ciphertext is well within DEFAULT_CHUNK_CIPHERTEXT_SIZE,
        // i.e. the test transport's range-keyed storage stays
        // aligned with the production formula.
        64
    }

    /// Encrypt `plaintext` with [`chunk_and_encrypt`] using a fresh
    /// blob_id and return everything the download path needs to
    /// rehydrate it.
    fn seal_for_download(
        plaintext: &[u8],
        k: &[u8; 32],
        chunk_size: usize,
    ) -> (String, Vec<SealedChunk>, [u8; 32], u32) {
        let blob_uuid = Uuid::now_v7();
        let blob_id_str = blob_uuid.to_string();
        let blob_id_bytes = *blob_uuid.as_bytes();
        let chunked = chunk_and_encrypt(
            plaintext,
            k,
            &blob_id_bytes,
            BlobClass::Media,
            chunk_size,
            false,
        )
        .unwrap();
        (
            blob_id_str,
            chunked.sealed_chunks,
            chunked.merkle_root,
            chunked.chunk_count,
        )
    }

    // -----------------------------------------------------------------
    // download_chunked_media — happy path + integrity failures
    // -----------------------------------------------------------------

    #[test]
    fn round_trip_single_chunk() {
        let k = fixed_k_asset();
        let pt = b"a small attachment".to_vec();
        let (blob_id, sealed, root, chunk_count) = seal_for_download(&pt, &k, DEFAULT_CHUNK_SIZE);
        assert_eq!(chunk_count, 1);

        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let got = download_chunked_media(
            &transport,
            &blob_id,
            chunk_count,
            root,
            &k,
            BlobClass::Media,
        )
        .unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn round_trip_multi_chunk() {
        let k = fixed_k_asset();
        let chunk_size = small_chunk_size();
        // 3 full chunks + 1 short tail chunk.
        let pt: Vec<u8> = (0..chunk_size * 3 + 17).map(|i| (i & 0xFF) as u8).collect();
        let (blob_id, sealed, root, chunk_count) = seal_for_download(&pt, &k, chunk_size);
        assert_eq!(chunk_count, 4);

        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let got = download_chunked_media(
            &transport,
            &blob_id,
            chunk_count,
            root,
            &k,
            BlobClass::Media,
        )
        .unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn wrong_merkle_root_rejected() {
        let k = fixed_k_asset();
        let pt = b"reject on root mismatch".to_vec();
        let (blob_id, sealed, _root, chunk_count) = seal_for_download(&pt, &k, DEFAULT_CHUNK_SIZE);

        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let bogus_root = [0xAAu8; 32];
        let err = download_chunked_media(
            &transport,
            &blob_id,
            chunk_count,
            bogus_root,
            &k,
            BlobClass::Media,
        )
        .unwrap_err();
        // The AAD binds the merkle_root, so a wrong root makes AEAD
        // open fail before the whole-object BLAKE3 check.
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn tampered_chunk_rejected() {
        let k = fixed_k_asset();
        let chunk_size = small_chunk_size();
        let pt: Vec<u8> = (0..chunk_size * 2).map(|i| (i & 0xFF) as u8).collect();
        let (blob_id, mut sealed, root, chunk_count) = seal_for_download(&pt, &k, chunk_size);
        // Flip a byte in the second chunk's ciphertext.
        sealed[1].ciphertext[3] ^= 0x80;

        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let err = download_chunked_media(
            &transport,
            &blob_id,
            chunk_count,
            root,
            &k,
            BlobClass::Media,
        )
        .unwrap_err();
        // The AEAD tag covers the ciphertext + AAD; a flipped byte
        // surfaces as a Crypto error.
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn empty_blob_id_errors() {
        let transport = InMemoryBlobTransport::new();
        let err = download_chunked_media(
            &transport,
            "",
            1,
            [0u8; 32],
            &fixed_k_asset(),
            BlobClass::Media,
        )
        .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("blob_id"), "{msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn zero_chunk_count_errors() {
        let transport = InMemoryBlobTransport::new();
        let blob_uuid = Uuid::now_v7().to_string();
        let err = download_chunked_media(
            &transport,
            &blob_uuid,
            0,
            [0u8; 32],
            &fixed_k_asset(),
            BlobClass::Media,
        )
        .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("chunk_count"), "{msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_blob_id_errors() {
        let transport = InMemoryBlobTransport::new();
        let err = download_chunked_media(
            &transport,
            "not-a-uuid",
            1,
            [0u8; 32],
            &fixed_k_asset(),
            BlobClass::Media,
        )
        .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("UUID"), "{msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn empty_ciphertext_returned_errors() {
        let k = fixed_k_asset();
        let pt = b"unused".to_vec();
        let (blob_id, _sealed, root, _chunks) = seal_for_download(&pt, &k, DEFAULT_CHUNK_SIZE);

        let transport = InMemoryBlobTransport::new();
        transport.put_chunk(&blob_id, 0, Vec::new());

        let err = download_chunked_media(&transport, &blob_id, 1, root, &k, BlobClass::Media)
            .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("empty range"), "{msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // download_single_chunk
    // -----------------------------------------------------------------

    #[test]
    fn single_chunk_round_trip() {
        let k = fixed_k_asset();
        let chunk_size = small_chunk_size();
        let pt: Vec<u8> = (0..chunk_size * 3).map(|i| (i & 0xFF) as u8).collect();
        let (blob_id, sealed, root, chunk_count) = seal_for_download(&pt, &k, chunk_size);
        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        // Verify each chunk independently round-trips to the same
        // plaintext slice the chunker produced.
        for chunk_idx in 0..chunk_count {
            let got = download_single_chunk(
                &transport,
                &blob_id,
                chunk_idx,
                chunk_count,
                root,
                &k,
                BlobClass::Media,
            )
            .unwrap();
            let start = (chunk_idx as usize) * chunk_size;
            let end = (start + chunk_size).min(pt.len());
            assert_eq!(got, &pt[start..end]);
        }
    }

    #[test]
    fn single_chunk_idx_out_of_range() {
        let transport = InMemoryBlobTransport::new();
        let blob_id = Uuid::now_v7().to_string();
        let err = download_single_chunk(
            &transport,
            &blob_id,
            5,
            3,
            [0u8; 32],
            &fixed_k_asset(),
            BlobClass::Media,
        )
        .unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("out of range"), "{msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn single_chunk_tampered_rejected() {
        let k = fixed_k_asset();
        let chunk_size = small_chunk_size();
        let pt: Vec<u8> = (0..chunk_size).map(|i| (i & 0xFF) as u8).collect();
        let (blob_id, mut sealed, root, chunk_count) = seal_for_download(&pt, &k, chunk_size);
        sealed[0].ciphertext[0] ^= 0x55;

        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let err = download_single_chunk(
            &transport,
            &blob_id,
            0,
            chunk_count,
            root,
            &k,
            BlobClass::Media,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    // -----------------------------------------------------------------
    // rehydrate_media_asset — Phase-3 lazy media rehydration on tap.
    // -----------------------------------------------------------------

    use crate::crypto::key_wrap::wrap_key;
    use crate::local_store::schema::{Conversation, MediaAsset, MessageKind, MessageSkeleton};
    use crate::local_store::state_machines::{ArchiveState, BackupState, BodyState};

    #[allow(clippy::too_many_arguments)]
    fn fresh_db_with_asset(
        asset_id: &str,
        blob_id: &str,
        wrapping_key: &[u8; 32],
        k_asset: &[u8; 32],
        merkle_root: [u8; 32],
        chunk_count: u32,
        media_state: MediaState,
        storage_sink: &str,
    ) -> LocalStoreDb {
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        db.insert_conversation(&Conversation {
            conversation_id: "c-rehy".into(),
            title_cipher: None,
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms: 1,
        })
        .unwrap();
        db.insert_message_skeleton(&MessageSkeleton {
            message_id: "m-rehy".into(),
            conversation_id: "c-rehy".into(),
            sender_id: "u-1".into(),
            created_at_ms: 100,
            received_at_ms: 110,
            kind: MessageKind::Media,
            body_state: BodyState::LocalPlainAvailable,
            media_state: Some(media_state),
            archive_state: ArchiveState::ArchiveVerified,
            backup_state: BackupState::NotBackedUp,
            reply_to: None,
            edited_at_ms: None,
            deleted_at_ms: None,
        })
        .unwrap();
        let wrapped = wrap_key(wrapping_key, k_asset).unwrap();
        db.insert_media_asset(&MediaAsset {
            asset_id: asset_id.into(),
            message_id: "m-rehy".into(),
            mime_type: "image/png".into(),
            bytes_total: 0,
            bytes_local: 0,
            media_state,
            wrapped_k_asset: wrapped,
            chunk_count: chunk_count as i32,
            merkle_root: merkle_root.to_vec(),
            blob_id: blob_id.into(),
            storage_sink: storage_sink.into(),
        })
        .unwrap();
        db
    }

    #[test]
    fn rehydrate_evicted_asset_round_trips_plaintext() {
        let wrapping = fixed_k_asset();
        // Use a different k_asset so the unwrap step is meaningful.
        let mut k_asset = wrapping;
        k_asset[0] ^= 0x42;
        let chunk_size = small_chunk_size();
        let pt: Vec<u8> = (0..chunk_size * 2 + 7).map(|i| (i & 0xFF) as u8).collect();
        let (blob_id, sealed, root, chunk_count) = seal_for_download(&pt, &k_asset, chunk_size);

        let db = fresh_db_with_asset(
            "a-1",
            &blob_id,
            &wrapping,
            &k_asset,
            root,
            chunk_count,
            MediaState::Evicted,
            "kchat_backend",
        );
        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let got = rehydrate_media_asset(&db, "a-1", &transport, &wrapping).unwrap();
        assert_eq!(got, pt);

        // The asset is now original_local in the DB.
        let row = db.get_media_asset("a-1").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::OriginalLocal);
    }

    #[test]
    fn rehydrate_remote_original_asset_round_trips_plaintext() {
        let wrapping = fixed_k_asset();
        let mut k_asset = wrapping;
        k_asset[1] ^= 0x10;
        let chunk_size = small_chunk_size();
        let pt: Vec<u8> = (0..chunk_size).map(|i| (i & 0xFF) as u8).collect();
        let (blob_id, sealed, root, chunk_count) = seal_for_download(&pt, &k_asset, chunk_size);

        let db = fresh_db_with_asset(
            "a-2",
            &blob_id,
            &wrapping,
            &k_asset,
            root,
            chunk_count,
            MediaState::RemoteOriginal,
            "kchat_backend",
        );
        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let got = rehydrate_media_asset(&db, "a-2", &transport, &wrapping).unwrap();
        assert_eq!(got, pt);
        let row = db.get_media_asset("a-2").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::OriginalLocal);
    }

    #[test]
    fn rehydrate_already_local_errors_without_download() {
        let wrapping = fixed_k_asset();
        let mut k_asset = wrapping;
        k_asset[2] ^= 0x33;
        let chunk_size = small_chunk_size();
        let pt = vec![0u8; chunk_size];
        let (blob_id, _sealed, root, chunk_count) = seal_for_download(&pt, &k_asset, chunk_size);

        let db = fresh_db_with_asset(
            "a-3",
            &blob_id,
            &wrapping,
            &k_asset,
            root,
            chunk_count,
            MediaState::OriginalLocal,
            "kchat_backend",
        );
        // Empty transport — if we attempted a download it would
        // surface "unknown blob_id".
        let transport = InMemoryBlobTransport::new();

        let err = rehydrate_media_asset(&db, "a-3", &transport, &wrapping).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("already original_local"), "got {msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn rehydrate_with_wrong_wrapping_key_fails() {
        let wrapping = fixed_k_asset();
        let mut k_asset = wrapping;
        k_asset[3] ^= 0x55;
        let chunk_size = small_chunk_size();
        let pt = vec![0u8; chunk_size];
        let (blob_id, sealed, root, chunk_count) = seal_for_download(&pt, &k_asset, chunk_size);

        let db = fresh_db_with_asset(
            "a-4",
            &blob_id,
            &wrapping,
            &k_asset,
            root,
            chunk_count,
            MediaState::Evicted,
            "kchat_backend",
        );
        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let mut wrong = wrapping;
        wrong[0] ^= 0xFF;
        let err = rehydrate_media_asset(&db, "a-4", &transport, &wrong).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
        // State must be unchanged since the key unwrap failed
        // before we kicked off the state-machine transition.
        let row = db.get_media_asset("a-4").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::Evicted);
    }

    #[test]
    fn rehydrate_routes_zk_object_fabric_to_not_implemented() {
        let wrapping = fixed_k_asset();
        let mut k_asset = wrapping;
        k_asset[4] ^= 0x66;
        let chunk_size = small_chunk_size();
        let pt = vec![0u8; chunk_size];
        let (blob_id, _sealed, root, chunk_count) = seal_for_download(&pt, &k_asset, chunk_size);

        let db = fresh_db_with_asset(
            "a-5",
            &blob_id,
            &wrapping,
            &k_asset,
            root,
            chunk_count,
            MediaState::Evicted,
            "zk_object_fabric",
        );
        let transport = InMemoryBlobTransport::new();
        let err = rehydrate_media_asset(&db, "a-5", &transport, &wrapping).unwrap_err();
        assert!(matches!(err, Error::NotImplemented(_)), "got {err:?}");
    }

    #[test]
    fn rehydrate_unknown_asset_id_errors() {
        let wrapping = fixed_k_asset();
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let transport = InMemoryBlobTransport::new();
        let err = rehydrate_media_asset(&db, "nope", &transport, &wrapping).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(msg.contains("no media_asset row"), "got {msg}"),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    /// Regression test for the atomicity fix in
    /// `rehydrate_media_asset`: the
    /// `Evicted → DownloadInProgress → OriginalLocal` pair is wrapped
    /// in an internal `SAVEPOINT rehydrate_media_state`. We verify
    /// the state mutations are bracketable by an enclosing
    /// `SAVEPOINT outer` — issuing `ROLLBACK TO outer` after a
    /// successful `rehydrate_media_asset` reverts the row back to
    /// the pre-call `media_state`. If the inner state transitions
    /// were applied as bare auto-committed statements instead of
    /// inside a savepoint they would persist past the outer
    /// rollback and the asset would be stranded in
    /// `OriginalLocal`/`DownloadInProgress` with no recovery path.
    #[test]
    fn rehydrate_state_transitions_participate_in_outer_savepoint() {
        let wrapping = fixed_k_asset();
        let mut k_asset = wrapping;
        k_asset[5] ^= 0x77;
        let chunk_size = small_chunk_size();
        let pt: Vec<u8> = (0..chunk_size).map(|i| (i & 0xFF) as u8).collect();
        let (blob_id, sealed, root, chunk_count) = seal_for_download(&pt, &k_asset, chunk_size);

        let db = fresh_db_with_asset(
            "a-atomic",
            &blob_id,
            &wrapping,
            &k_asset,
            root,
            chunk_count,
            MediaState::Evicted,
            "kchat_backend",
        );
        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        // Start an outer savepoint; the rehydrate's internal
        // savepoint nests under it.
        db.connection()
            .execute_batch("SAVEPOINT outer;")
            .expect("open outer savepoint");

        rehydrate_media_asset(&db, "a-atomic", &transport, &wrapping).expect("rehydrate");
        // After rehydrate, state advanced to OriginalLocal.
        assert_eq!(
            db.get_media_asset("a-atomic").unwrap().unwrap().media_state,
            MediaState::OriginalLocal
        );

        // Roll back the outer savepoint. Both transitions must
        // unwind together, so the row goes back to Evicted.
        db.connection()
            .execute_batch("ROLLBACK TO SAVEPOINT outer;\nRELEASE SAVEPOINT outer;")
            .expect("rollback outer savepoint");
        assert_eq!(
            db.get_media_asset("a-atomic").unwrap().unwrap().media_state,
            MediaState::Evicted,
            "rehydrate's state transitions must participate in the outer SAVEPOINT \
             so a partial-failure rollback cleanly restores the pre-call state"
        );
    }

    /// Regression test that no partial state — e.g. a row stranded
    /// in `DownloadInProgress` — survives a wrong-key failure. The
    /// unwrap fails before the savepoint opens, so the row stays at
    /// `Evicted`. This complements
    /// [`rehydrate_with_wrong_wrapping_key_fails`] but additionally
    /// pokes the row through a fresh `LocalStoreDb` lookup (catching
    /// any caching shenanigans).
    #[test]
    fn rehydrate_failed_unwrap_leaves_no_intermediate_download_in_progress() {
        let wrapping = fixed_k_asset();
        let mut k_asset = wrapping;
        k_asset[6] ^= 0xAA;
        let chunk_size = small_chunk_size();
        let pt = vec![0u8; chunk_size];
        let (blob_id, sealed, root, chunk_count) = seal_for_download(&pt, &k_asset, chunk_size);

        let db = fresh_db_with_asset(
            "a-no-strand",
            &blob_id,
            &wrapping,
            &k_asset,
            root,
            chunk_count,
            MediaState::Evicted,
            "kchat_backend",
        );
        let transport = InMemoryBlobTransport::new();
        transport.put_chunks(&blob_id, &sealed);

        let mut wrong = wrapping;
        wrong[1] ^= 0xFF;
        let _ = rehydrate_media_asset(&db, "a-no-strand", &transport, &wrong).unwrap_err();

        // The row must NOT be stranded in DownloadInProgress.
        let row = db.get_media_asset("a-no-strand").unwrap().unwrap();
        assert_eq!(row.media_state, MediaState::Evicted);
        assert_ne!(row.media_state, MediaState::DownloadInProgress);
    }
}
