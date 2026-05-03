//! Phase-7 failure-scenario foundation suite (Task 10).
//!
//! `docs/PHASES.md` Phase 7 enumerates 8 failure scenarios that
//! must each have a self-contained reproduction in the test
//! suite before the milestone closes. This file lands the first
//! 4 — the chunked-upload, chunked-decrypt, backup-decrypt, and
//! manifest-chain paths — so future contributors can extend the
//! suite without reinventing the harness.
//!
//! Each test:
//! * uses an in-memory database / mock transport (no disk, no
//!   network)
//! * asserts a **specific error variant** (not just "an error
//!   occurred") so a regression that flips the variant fails
//!   loudly
//! * is independent — running any subset reproduces the same
//!   pass / fail outcome.

use std::ops::Range;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use uuid::Uuid;

use kchat_core::backup::event_journal::{BackupEvent, BackupEventType};
use kchat_core::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
use kchat_core::backup::segment_builder::{
    decrypt_backup_segment, BackupSegmentBuildRequest, BackupSegmentBuilder,
};
use kchat_core::crypto::aead::BlobClass;
use kchat_core::crypto::key_hierarchy::{
    derive_backup_manifest, derive_backup_root, derive_backup_segment, KeyMaterial,
};
use kchat_core::formats::SegmentType;
use kchat_core::media::chunker::{chunk_and_encrypt, verify_and_decrypt, DEFAULT_CHUNK_SIZE};
use kchat_core::media::upload::{resume_upload, upload_chunked_media, UploadState};
use kchat_core::restore::manifest_verifier::{verify_manifest_chain, VerificationError};
use kchat_core::transport::{
    BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest, FetchMessagesResponse,
    TransportClient, TransportResult,
};
use kchat_core::Error;

// ===========================================================================
// MockTransportClient — drives upload_chunked_media / resume_upload
// ===========================================================================

/// Programmable transport that:
/// * succeeds on `init_blob_upload` and the first
///   `fail_after_n_chunks` calls to `upload_chunk`
/// * returns `Error::Transport("connection reset")` on any
///   subsequent `upload_chunk`
/// * counts every call so tests can assert the resume path
///   skipped completed chunks
#[derive(Debug)]
struct MockTransportClient {
    blob_id: String,
    fail_after_n_chunks: Mutex<Option<u32>>,
    chunks_received: Mutex<Vec<u32>>,
}

impl MockTransportClient {
    fn new(blob_id: &str, fail_after: Option<u32>) -> Self {
        Self {
            blob_id: blob_id.into(),
            fail_after_n_chunks: Mutex::new(fail_after),
            chunks_received: Mutex::new(Vec::new()),
        }
    }

    fn lift_failure(&self) {
        *self.fail_after_n_chunks.lock().unwrap() = None;
    }

    fn chunks_received(&self) -> Vec<u32> {
        self.chunks_received.lock().unwrap().clone()
    }
}

impl TransportClient for MockTransportClient {
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
        blob_class: BlobClass,
        merkle_root: [u8; 32],
    ) -> TransportResult<BlobUploadHandle> {
        let _ = merkle_root; // server stashes this on its side
        Ok(BlobUploadHandle {
            blob_id: self.blob_id.clone(),
            blob_class,
            expires_at_ms: 0,
        })
    }

    fn upload_chunk(
        &self,
        blob_id: &str,
        chunk_idx: u32,
        _ciphertext: &[u8],
        sha256: [u8; 32],
    ) -> TransportResult<ChunkReceipt> {
        let mut received = self.chunks_received.lock().unwrap();
        if let Some(threshold) = *self.fail_after_n_chunks.lock().unwrap() {
            if received.len() as u32 >= threshold {
                return Err(Error::Transport("connection reset".into()));
            }
        }
        received.push(chunk_idx);
        Ok(ChunkReceipt {
            blob_id: blob_id.into(),
            chunk_idx,
            sha256,
        })
    }

    fn commit_blob(&self, blob_id: &str) -> TransportResult<CommitBlobResponse> {
        let chunks = self.chunks_received.lock().unwrap().len() as u32;
        Ok(CommitBlobResponse {
            blob_id: blob_id.into(),
            chunk_count: chunks,
            merkle_root: [0u8; 32], // overridden by tests via the merkle wrapper
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

/// Wrapper around the mock transport that returns the real
/// merkle_root on commit so the post-resume commit succeeds.
#[derive(Debug)]
struct MockTransportClientWithMerkle {
    inner: MockTransportClient,
    real_merkle_root: [u8; 32],
}

impl MockTransportClientWithMerkle {
    fn new(blob_id: &str, fail_after: Option<u32>, real_merkle_root: [u8; 32]) -> Self {
        Self {
            inner: MockTransportClient::new(blob_id, fail_after),
            real_merkle_root,
        }
    }

    fn lift_failure(&self) {
        self.inner.lift_failure();
    }

    fn chunks_received(&self) -> Vec<u32> {
        self.inner.chunks_received()
    }
}

impl TransportClient for MockTransportClientWithMerkle {
    fn fetch_messages(&self, c: &str, a: Option<&str>) -> TransportResult<FetchMessagesResponse> {
        self.inner.fetch_messages(c, a)
    }
    fn init_blob_upload(
        &self,
        size: u64,
        blob_class: BlobClass,
        merkle_root: [u8; 32],
    ) -> TransportResult<BlobUploadHandle> {
        self.inner.init_blob_upload(size, blob_class, merkle_root)
    }
    fn upload_chunk(
        &self,
        b: &str,
        idx: u32,
        ct: &[u8],
        sha: [u8; 32],
    ) -> TransportResult<ChunkReceipt> {
        self.inner.upload_chunk(b, idx, ct, sha)
    }
    fn commit_blob(&self, blob_id: &str) -> TransportResult<CommitBlobResponse> {
        let chunks = self.inner.chunks_received.lock().unwrap().len() as u32;
        Ok(CommitBlobResponse {
            blob_id: blob_id.into(),
            chunk_count: chunks,
            merkle_root: self.real_merkle_root,
        })
    }
    fn fetch_blob_range(&self, b: &str, r: Range<u64>) -> TransportResult<Vec<u8>> {
        self.inner.fetch_blob_range(b, r)
    }
    fn fetch_archive_manifests(&self, g: Option<u64>) -> TransportResult<Vec<EncryptedManifest>> {
        self.inner.fetch_archive_manifests(g)
    }
    fn fetch_archive_segment(&self, s: &str) -> TransportResult<Vec<u8>> {
        self.inner.fetch_archive_segment(s)
    }
    fn fetch_index_shards(&self, h: &str, b: &str, s: &str) -> TransportResult<Vec<u8>> {
        self.inner.fetch_index_shards(h, b, s)
    }
}

// ===========================================================================
// Scenario 1 — Chunk upload interrupted mid-stream
// ===========================================================================

#[test]
fn chunk_upload_interrupted_then_resumed_succeeds() {
    let k_asset = [0xAAu8; 32];
    let blob_id_bytes = [0xBBu8; 16];
    // 5 chunks of 1 KiB each.
    let chunk_size = 1024;
    let plaintext = vec![0xCDu8; chunk_size * 5];
    let chunked = chunk_and_encrypt(
        &plaintext,
        &k_asset,
        &blob_id_bytes,
        BlobClass::Media,
        chunk_size,
        false,
    )
    .expect("chunk_and_encrypt");
    assert_eq!(chunked.sealed_chunks.len(), 5);

    let transport =
        MockTransportClientWithMerkle::new("blob-resumable-1", Some(2), chunked.merkle_root);

    // ----- First attempt: fails after 2 chunks.
    let err = upload_chunked_media(
        &transport,
        &chunked.sealed_chunks,
        chunked.merkle_root,
        BlobClass::Media,
    )
    .expect_err("must fail with connection reset after 2 chunks");
    match err {
        Error::Transport(msg) => assert!(msg.contains("connection reset"), "got: {msg}"),
        other => panic!("expected Error::Transport, got {other:?}"),
    }

    // Server received exactly 2 chunks before the cut.
    assert_eq!(transport.chunks_received(), vec![0, 1]);

    // ----- Lift the failure and resume from the recorded state.
    transport.lift_failure();
    let mut state = UploadState {
        blob_id: "blob-resumable-1".into(),
        completed_chunks: {
            let mut cc = vec![false; 5];
            cc[0] = true;
            cc[1] = true;
            cc
        },
        merkle_root: chunked.merkle_root,
    };
    let result = resume_upload(
        &transport,
        &mut state,
        &chunked.sealed_chunks,
        BlobClass::Media,
    )
    .expect("resume_upload after interruption must succeed");
    assert_eq!(result.merkle_root, chunked.merkle_root);

    // ----- Server now has chunks 0,1 (from first attempt) + 2,3,4 (from resume).
    assert_eq!(transport.chunks_received(), vec![0, 1, 2, 3, 4]);
    // Every completion bit flipped true.
    assert!(state.completed_chunks.iter().all(|c| *c));
}

// ===========================================================================
// Scenario 2 — Corrupted chunk (Merkle / SHA-256 mismatch)
// ===========================================================================

#[test]
fn corrupted_chunk_ciphertext_fails_sha256_fast_fail() {
    let k_asset = [0x11u8; 32];
    let blob_id_bytes = [0x22u8; 16];
    let plaintext = vec![0xEFu8; 1024 * 4];
    let chunk_size = 1024;
    let mut chunked = chunk_and_encrypt(
        &plaintext,
        &k_asset,
        &blob_id_bytes,
        BlobClass::Media,
        chunk_size,
        false,
    )
    .expect("chunk_and_encrypt");

    // Tamper with one byte of chunk[1]'s ciphertext but leave its
    // recorded chunk_sha256 alone — verify_and_decrypt's SHA-256
    // fast-fail must catch this *before* any AEAD work.
    chunked.sealed_chunks[1].ciphertext[0] ^= 0xFF;

    let err = verify_and_decrypt(
        &chunked.sealed_chunks,
        chunked.merkle_root,
        &k_asset,
        &blob_id_bytes,
        BlobClass::Media,
    )
    .expect_err("tampered ciphertext must fail SHA-256 fast-fail");
    match err {
        Error::Storage(msg) => {
            assert!(
                msg.contains("SHA-256 mismatch"),
                "expected SHA-256 fast-fail, got: {msg}"
            );
            assert!(
                msg.contains("chunk 1"),
                "error must name the failing chunk index, got: {msg}"
            );
        }
        other => panic!("expected Storage(SHA-256 mismatch), got {other:?}"),
    }
}

#[test]
fn tampered_merkle_root_in_descriptor_fails_blake3_root_check() {
    let k_asset = [0x33u8; 32];
    let blob_id_bytes = [0x44u8; 16];
    let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
    let chunked = chunk_and_encrypt(
        &plaintext,
        &k_asset,
        &blob_id_bytes,
        BlobClass::Media,
        DEFAULT_CHUNK_SIZE,
        false,
    )
    .expect("chunk_and_encrypt");

    // Lie about the merkle_root the descriptor claims. The
    // per-chunk SHA-256 fast-fail still passes (untouched) and
    // AEAD open fails because the AAD binds the root.
    let mut bogus = chunked.merkle_root;
    bogus[0] ^= 0xFF;
    let err = verify_and_decrypt(
        &chunked.sealed_chunks,
        bogus,
        &k_asset,
        &blob_id_bytes,
        BlobClass::Media,
    )
    .expect_err("tampered merkle_root must fail AEAD authentication");
    // The AAD is bound to merkle_root, so AEAD open fails first.
    // Surfaces as Error::Crypto from xchacha20_poly1305::open.
    match err {
        Error::Crypto(_) => {}
        Error::Storage(msg) if msg.contains("BLAKE3") => {}
        other => panic!(
            "expected Error::Crypto (AEAD tag mismatch) or BLAKE3 root mismatch, got {other:?}"
        ),
    }
}

// ===========================================================================
// Scenario 3 — Wrong backup key on restore
// ===========================================================================

#[test]
fn wrong_backup_segment_key_fails_aead_open() {
    let identity = KeyMaterial::from_bytes([0x55; 32]);
    let backup_root = derive_backup_root(&identity).expect("backup_root");
    let segment_id = Uuid::now_v7();
    let k_seg = derive_backup_segment(&backup_root, segment_id.as_bytes()).expect("k_seg");

    let evt = BackupEvent {
        event_type: BackupEventType::MessageReceived,
        conversation_id: Some(Uuid::now_v7()),
        message_id: Some(Uuid::now_v7()),
        payload: b"secret payload".to_vec(),
        created_at_ms: 1_700_000_000,
    };
    let segment = BackupSegmentBuilder::new()
        .build_segment(
            BackupSegmentBuildRequest {
                events: vec![evt],
                segment_type: SegmentType::Events,
            },
            &k_seg,
        )
        .expect("seal");

    // Sanity: the right key opens the segment.
    let payload = decrypt_backup_segment(&segment, &k_seg).expect("right key opens");
    assert_eq!(payload.events.len(), 1);

    // Wrong K_backup_segment: bit-flip the bytes.
    let mut wrong_bytes = *k_seg.as_bytes();
    wrong_bytes[0] ^= 0xFF;
    let wrong_key = KeyMaterial::from_bytes(wrong_bytes);
    let err = decrypt_backup_segment(&segment, &wrong_key)
        .expect_err("decryption with the wrong key must fail");
    match err {
        Error::Crypto(_) => {}
        other => panic!("expected Error::Crypto (AEAD tag mismatch), got {other:?}"),
    }
}

#[test]
fn wrong_signing_key_on_manifest_chain_fails_signature_invalid() {
    let identity = KeyMaterial::from_bytes([0x66; 32]);
    let backup_root = derive_backup_root(&identity).expect("backup_root");
    let k_seg = derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).unwrap();
    let k_man = derive_backup_manifest(&backup_root, b"wrong-signing-key").unwrap();

    let signer = SigningKey::from_bytes(&[0x77; 32]);
    let imposter = SigningKey::from_bytes(&[0x88; 32]);

    let evt = BackupEvent {
        event_type: BackupEventType::MessageReceived,
        conversation_id: Some(Uuid::now_v7()),
        message_id: Some(Uuid::now_v7()),
        payload: b"x".to_vec(),
        created_at_ms: 1,
    };
    let segment = BackupSegmentBuilder::new()
        .build_segment(
            BackupSegmentBuildRequest {
                events: vec![evt],
                segment_type: SegmentType::Events,
            },
            &k_seg,
        )
        .expect("seal");

    let gen0 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: None,
            device_id: "device-A".into(),
        },
        &signer,
        &k_man,
    )
    .expect("manifest");

    // Verify under the imposter's public key — must fail.
    let chain = vec![gen0.manifest];
    let err = verify_manifest_chain(&chain, &imposter.verifying_key())
        .expect_err("imposter key must fail signature verification");
    match err {
        VerificationError::SignatureInvalid { generation } => assert_eq!(generation, 0),
        other => panic!("expected SignatureInvalid {{ generation: 0 }}, got {other:?}"),
    }
}

// ===========================================================================
// Scenario 4 — Manifest chain break detected on restore
// ===========================================================================

#[test]
fn manifest_chain_break_returns_chain_break_with_expected_and_actual() {
    let identity = KeyMaterial::from_bytes([0x99; 32]);
    let backup_root = derive_backup_root(&identity).expect("backup_root");
    let k_seg = derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).unwrap();
    let k_man = derive_backup_manifest(&backup_root, b"chain-break").unwrap();
    let signer = SigningKey::from_bytes(&[0xAA; 32]);

    let evt = BackupEvent {
        event_type: BackupEventType::MessageReceived,
        conversation_id: Some(Uuid::now_v7()),
        message_id: Some(Uuid::now_v7()),
        payload: b"x".to_vec(),
        created_at_ms: 1,
    };
    let segment = BackupSegmentBuilder::new()
        .build_segment(
            BackupSegmentBuildRequest {
                events: vec![evt],
                segment_type: SegmentType::Events,
            },
            &k_seg,
        )
        .expect("seal");

    let gen0 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: None,
            device_id: "device-A".into(),
        },
        &signer,
        &k_man,
    )
    .expect("gen0");

    let gen1 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: Some(&gen0.manifest),
            device_id: "device-A".into(),
        },
        &signer,
        &k_man,
    )
    .expect("gen1");

    let gen2 = build_backup_manifest(
        BackupManifestBuildRequest {
            segments: std::slice::from_ref(&segment),
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: Some(&gen1.manifest),
            device_id: "device-A".into(),
        },
        &signer,
        &k_man,
    )
    .expect("gen2");

    // ----- Sanity: untampered chain verifies.
    let original_chain = vec![
        gen0.manifest.clone(),
        gen1.manifest.clone(),
        gen2.manifest.clone(),
    ];
    verify_manifest_chain(&original_chain, &signer.verifying_key())
        .expect("untampered chain must verify");

    // ----- Tamper with manifest[1]'s previous_manifest_hash and
    // re-sign so the failure is the chain link, not the
    // signature.
    let mut tampered_gen1 = gen1.manifest.clone();
    let actual_garbage = [0x42u8; 32];
    tampered_gen1.previous_manifest_hash = actual_garbage;
    kchat_core::formats::manifest::sign_backup_manifest(&mut tampered_gen1, &signer)
        .expect("re-sign tampered manifest");

    // Recompute gen2 against the tampered gen1 so gen2's link is
    // legitimate; the only break is at gen1.
    let mut tampered_gen2 = gen2.manifest.clone();
    tampered_gen2.previous_manifest_hash =
        kchat_core::formats::manifest::compute_manifest_hash(&tampered_gen1)
            .expect("hash tampered gen1");
    kchat_core::formats::manifest::sign_backup_manifest(&mut tampered_gen2, &signer)
        .expect("re-sign tampered gen2");

    let chain = vec![gen0.manifest.clone(), tampered_gen1, tampered_gen2];
    let err = verify_manifest_chain(&chain, &signer.verifying_key())
        .expect_err("tampered chain must fail with ChainBreak");
    match err {
        VerificationError::ChainBreak {
            generation,
            expected,
            actual,
        } => {
            assert_eq!(generation, 1, "break must be reported at generation 1");
            assert_eq!(actual, actual_garbage, "actual hash must echo the garbage");
            let expected_hash =
                kchat_core::formats::manifest::compute_manifest_hash(&gen0.manifest)
                    .expect("hash gen0");
            assert_eq!(
                expected, expected_hash,
                "expected hash must equal compute_manifest_hash(gen0)"
            );
        }
        other => panic!("expected ChainBreak, got {other:?}"),
    }
}
