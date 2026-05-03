//! Phase-3 batch-by-bucket prefetch.
//!
//! `docs/PROPOSAL.md §5.6` calls for the rehydration engine to
//! coarsen its access-pattern metadata by fetching every archive
//! segment for a `(conversation_id, time_bucket)` key in one
//! batch instead of issuing one fetch per scroll-back gesture.
//! That way the storage backend only sees a "this user opened
//! month X for conversation Y" coarse signal rather than the
//! per-message timing fingerprint.
//!
//! [`batch_prefetch_bucket`] is the smallest building block the
//! orchestration layer needs:
//!
//! 1. Look up every `archive_segment_map.segment_id` matching
//!    `(conversation_id, time_bucket)`.
//! 2. Issue [`TransportClient::fetch_archive_segment`] once per
//!    segment id (the transport surface fetches a single segment
//!    at a time, but the calls happen back-to-back so the
//!    backend's access-log granularity is per-bucket, not
//!    per-message).
//! 3. Return the encrypted segment bytes alongside the segment
//!    metadata so the caller can decrypt and merge.

use rusqlite::{params, Connection};
use std::str::FromStr;
use uuid::Uuid;

use crate::archive::download::ArchiveSegmentRouter;
use crate::archive::privacy::{compute_padding_count, pad_with_dummy_requests, should_pad};
use crate::config::KChatCoreConfig;
use crate::local_store::schema::StorageBackend;
use crate::transport::TransportClient;
use crate::Error;

/// Reject any segment row whose `storage_backend` column is not
/// [`StorageBackend::KChatBackend`]. The KChat-only prefetch
/// entry points cannot dispatch to ZKOF (no `S3Client` is in
/// scope), so silently routing through the KChat transport would
/// 404 on every ZKOF row. Callers with mixed backends must use
/// [`batch_prefetch_bucket_with_router`] instead.
fn ensure_all_kchat_backend(rows: &[(String, String, String)]) -> Result<(), Error> {
    for (segment_id, _, storage_backend) in rows {
        let backend =
            StorageBackend::from_str(storage_backend).unwrap_or(StorageBackend::KChatBackend);
        if backend != StorageBackend::KChatBackend {
            return Err(Error::Storage(format!(
                "batch_prefetch_bucket: segment {segment_id} uses storage_backend \
                 '{storage_backend}'; the legacy KChat-only entry point cannot route \
                 it. Use batch_prefetch_bucket_with_router with an ArchiveSegmentRouter \
                 built via ArchiveSegmentRouter::with_zkof(...)."
            )));
        }
    }
    Ok(())
}

/// Encrypted archive segment payload, paired with the metadata
/// the orchestration layer needs to decrypt and merge it.
///
/// Decryption is intentionally **not** the prefetch layer's job —
/// that keeps the prefetch surface dumb (no key material in this
/// hop) and lets the calling code batch decryption against the
/// current epoch key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchedSegment {
    /// Stable segment identifier, matching
    /// `archive_segment_map.segment_id`.
    pub segment_id: String,
    /// `archive_segment_map.blob_id` — the transport-level handle
    /// the segment was uploaded under.
    pub blob_id: String,
    /// `kchat_backend` / `zk_object_fabric` / …
    /// (`docs/PROPOSAL.md §10.1`).
    pub storage_backend: String,
    /// Encrypted segment bytes (CBOR + AEAD, exactly what
    /// `TransportClient::fetch_archive_segment` returned).
    pub ciphertext: Vec<u8>,
}

/// Fetch every `archive_segment_map` row for `(conversation_id,
/// time_bucket)` and stream the matching encrypted segment
/// payloads through `transport`.
///
/// Returns one [`PrefetchedSegment`] per row in the order
/// `archive_segment_map` returns them (which is undefined absent
/// an explicit `ORDER BY`; the orchestration layer is responsible
/// for sorting if it cares). On a transport failure the whole
/// batch fails — partial returns would silently drop segments and
/// fool downstream merkle-chain verifiers.
pub fn batch_prefetch_bucket(
    conn: &Connection,
    transport: &dyn TransportClient,
    conversation_id: Uuid,
    time_bucket: &str,
) -> Result<Vec<PrefetchedSegment>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT segment_id, blob_id, storage_backend
               FROM archive_segment_map
              WHERE conversation_id = ?1 AND time_bucket = ?2",
        )
        .map_err(|e| Error::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![conversation_id.to_string(), time_bucket], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| Error::Storage(e.to_string()))?;

    let mut materialised = Vec::new();
    for row in rows {
        let (segment_id, blob_id, storage_backend) =
            row.map_err(|e| Error::Storage(e.to_string()))?;
        materialised.push((segment_id, blob_id, storage_backend));
    }

    // KChat-only entry: surface ZKOF rows as a structured error
    // so callers know to upgrade to the router-aware variant
    // instead of silently 404-ing.
    ensure_all_kchat_backend(&materialised)?;

    let mut out = Vec::with_capacity(materialised.len());
    for (segment_id, blob_id, storage_backend) in materialised {
        let ciphertext = transport.fetch_archive_segment(&segment_id)?;
        out.push(PrefetchedSegment {
            segment_id,
            blob_id,
            storage_backend,
            ciphertext,
        });
    }
    Ok(out)
}

/// Backend-aware variant of [`batch_prefetch_bucket`]. Reads
/// `archive_segment_map.storage_backend` for every row and
/// dispatches the fetch through the supplied
/// [`ArchiveSegmentRouter`] — supports
/// [`StorageBackend::ZkObjectFabric`] segments in addition to the
/// legacy KChat path.
pub fn batch_prefetch_bucket_with_router(
    conn: &Connection,
    router: &ArchiveSegmentRouter<'_>,
    conversation_id: Uuid,
    time_bucket: &str,
) -> Result<Vec<PrefetchedSegment>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT segment_id, blob_id, storage_backend
               FROM archive_segment_map
              WHERE conversation_id = ?1 AND time_bucket = ?2",
        )
        .map_err(|e| Error::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![conversation_id.to_string(), time_bucket], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| Error::Storage(e.to_string()))?;

    let mut materialised = Vec::new();
    for row in rows {
        let (segment_id, blob_id, storage_backend) =
            row.map_err(|e| Error::Storage(e.to_string()))?;
        materialised.push((segment_id, blob_id, storage_backend));
    }

    let mut out = Vec::with_capacity(materialised.len());
    for (segment_id, blob_id, storage_backend) in materialised {
        let backend =
            StorageBackend::from_str(&storage_backend).unwrap_or(StorageBackend::KChatBackend);
        let ciphertext = router.fetch(backend, &segment_id)?;
        out.push(PrefetchedSegment {
            segment_id,
            blob_id,
            storage_backend,
            ciphertext,
        });
    }
    Ok(out)
}

/// Padding-aware variant of [`batch_prefetch_bucket`].
///
/// `docs/PROPOSAL.md §5.6` — when
/// [`crate::config::PrivacyLevel::High`] is configured the
/// orchestration layer mixes dummy segment-id fetches in with the
/// real ones. The dummy ids are freshly-generated UUIDv4s; the
/// transport returns an empty payload (or a 404 the call-site
/// silently swallows). Real segments are returned in the same
/// shape as [`batch_prefetch_bucket`]; dummy fetches are dropped
/// after the round-trip lands.
///
/// When [`crate::config::PrivacyLevel::Standard`] is configured
/// this delegates straight to [`batch_prefetch_bucket`].
pub fn batch_prefetch_bucket_with_padding(
    config: &KChatCoreConfig,
    conn: &Connection,
    transport: &dyn TransportClient,
    conversation_id: Uuid,
    time_bucket: &str,
) -> Result<Vec<PrefetchedSegment>, Error> {
    if !should_pad(config) {
        return batch_prefetch_bucket(conn, transport, conversation_id, time_bucket);
    }

    // 1) Pull every real segment-id row up front so we know how
    //    many dummies to mint.
    let mut stmt = conn
        .prepare(
            "SELECT segment_id, blob_id, storage_backend
               FROM archive_segment_map
              WHERE conversation_id = ?1 AND time_bucket = ?2",
        )
        .map_err(|e| Error::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(params![conversation_id.to_string(), time_bucket], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| Error::Storage(e.to_string()))?;

    let mut real_rows: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    let mut backend_check: Vec<(String, String, String)> = Vec::new();
    for row in rows {
        let (segment_id, blob_id, storage_backend) =
            row.map_err(|e| Error::Storage(e.to_string()))?;
        backend_check.push((segment_id.clone(), blob_id.clone(), storage_backend.clone()));
        real_rows.insert(segment_id, (blob_id, storage_backend));
    }
    // KChat-only entry: surface ZKOF rows as a structured error
    // so callers know to upgrade to the router-aware variant
    // instead of silently 404-ing.
    ensure_all_kchat_backend(&backend_check)?;

    // 2) Compute how many dummies to mint and shuffle them in
    //    with the real ids.
    let real_ids: Vec<String> = real_rows.keys().cloned().collect();
    let padding_count = compute_padding_count(real_ids.len());
    let padded = pad_with_dummy_requests(&real_ids, padding_count);

    // 3) Issue one fetch per id in the padded order. Dummy
    //    fetches that error out are silently dropped — the
    //    backend will 404 on every dummy id and we don't want a
    //    single 404 to fail the whole batch.
    let mut out = Vec::with_capacity(real_rows.len());
    for id in padded {
        if let Some((blob_id, storage_backend)) = real_rows.get(&id).cloned() {
            let ciphertext = transport.fetch_archive_segment(&id)?;
            out.push(PrefetchedSegment {
                segment_id: id,
                blob_id,
                storage_backend,
                ciphertext,
            });
        } else {
            // Dummy fetch — discard the result (and any error).
            let _ = transport.fetch_archive_segment(&id);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::BlobClass;
    use crate::local_store::db::LocalStoreDb;
    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportResult,
    };
    use std::collections::HashMap;
    use std::ops::Range;
    use std::sync::Mutex;

    /// Mock transport that returns canned ciphertext per
    /// segment id.
    #[derive(Debug, Default)]
    struct FixtureTransport {
        responses: Mutex<HashMap<String, Vec<u8>>>,
        calls: Mutex<Vec<String>>,
    }

    impl FixtureTransport {
        fn install(&self, segment_id: &str, bytes: Vec<u8>) {
            self.responses
                .lock()
                .unwrap()
                .insert(segment_id.to_string(), bytes);
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl TransportClient for FixtureTransport {
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
            Err(Error::NotImplemented("transport"))
        }

        fn upload_chunk(
            &self,
            _blob_id: &str,
            _chunk_idx: u32,
            _ciphertext: &[u8],
            _sha256: [u8; 32],
        ) -> TransportResult<ChunkReceipt> {
            Err(Error::NotImplemented("transport"))
        }

        fn commit_blob(&self, _blob_id: &str) -> TransportResult<CommitBlobResponse> {
            Err(Error::NotImplemented("transport"))
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

        fn fetch_archive_segment(&self, segment_id: &str) -> TransportResult<Vec<u8>> {
            self.calls.lock().unwrap().push(segment_id.to_string());
            self.responses
                .lock()
                .unwrap()
                .get(segment_id)
                .cloned()
                .ok_or_else(|| {
                    Error::Storage(format!(
                        "FixtureTransport: no canned response for {segment_id}"
                    ))
                })
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

    fn seed_segment_map_row(
        db: &LocalStoreDb,
        segment_id: &str,
        conversation_id: &str,
        time_bucket: &str,
        blob_id: &str,
    ) {
        db.connection()
            .execute(
                "INSERT INTO archive_segment_map(
                    segment_id, conversation_id, time_bucket,
                    segment_type, blob_id, storage_backend,
                    merkle_root, state
                 ) VALUES (?1, ?2, ?3, 'message_delta', ?4,
                           'kchat_backend', ?5, 'archive_uploaded')",
                params![
                    segment_id,
                    conversation_id,
                    time_bucket,
                    blob_id,
                    [0u8; 32].as_slice(),
                ],
            )
            .unwrap();
    }

    #[test]
    fn batch_prefetch_fetches_all_segments_for_bucket() {
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let conv = Uuid::now_v7();
        let bucket = "2026-04";

        seed_segment_map_row(&db, "seg-1", &conv.to_string(), bucket, "blob-1");
        seed_segment_map_row(&db, "seg-2", &conv.to_string(), bucket, "blob-2");
        seed_segment_map_row(&db, "seg-3", &conv.to_string(), bucket, "blob-3");
        // A row in a different bucket — must be excluded.
        seed_segment_map_row(&db, "seg-other", &conv.to_string(), "2026-05", "blob-other");

        let transport = FixtureTransport::default();
        transport.install("seg-1", vec![0xAA; 8]);
        transport.install("seg-2", vec![0xBB; 8]);
        transport.install("seg-3", vec![0xCC; 8]);

        let segments =
            batch_prefetch_bucket(db.connection(), &transport, conv, bucket).expect("prefetch");
        assert_eq!(segments.len(), 3);

        let mut ids: Vec<&str> = segments.iter().map(|s| s.segment_id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, vec!["seg-1", "seg-2", "seg-3"]);

        let calls = transport.calls();
        // The bucket-mismatched row must not have been hit.
        assert!(!calls.iter().any(|c| c == "seg-other"));
    }

    #[test]
    fn batch_prefetch_empty_bucket_returns_empty() {
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let transport = FixtureTransport::default();
        let segments =
            batch_prefetch_bucket(db.connection(), &transport, Uuid::now_v7(), "2030-01")
                .expect("prefetch");
        assert!(segments.is_empty());
        assert!(transport.calls().is_empty());
    }

    fn fresh_config(privacy: crate::config::PrivacyLevel) -> crate::config::KChatCoreConfig {
        crate::config::KChatCoreConfig::new(
            std::path::PathBuf::from("/tmp/dummy"),
            crate::config::Platform::MacOs,
            "tenant",
        )
        .with_privacy_level(privacy)
    }

    /// Transport that records every fetch and serves canned
    /// payloads for known ids. Unknown ids surface as
    /// `Storage(...)` errors so the padded path's silent-drop
    /// behaviour is exercised.
    impl FixtureTransport {
        fn with_calls(&self, expected_real: usize) {
            let calls = self.calls();
            assert!(
                calls.len() >= expected_real,
                "transport must see at least the real ids ({} >= {})",
                calls.len(),
                expected_real,
            );
        }
    }

    #[test]
    fn padded_variant_with_standard_privacy_matches_unpadded() {
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let conv = Uuid::now_v7();
        let bucket = "2026-04";
        seed_segment_map_row(&db, "seg-1", &conv.to_string(), bucket, "blob-1");
        seed_segment_map_row(&db, "seg-2", &conv.to_string(), bucket, "blob-2");

        let transport = FixtureTransport::default();
        transport.install("seg-1", vec![0xAA; 8]);
        transport.install("seg-2", vec![0xBB; 8]);

        let config = fresh_config(crate::config::PrivacyLevel::Standard);
        let segments =
            batch_prefetch_bucket_with_padding(&config, db.connection(), &transport, conv, bucket)
                .expect("prefetch");
        assert_eq!(segments.len(), 2);
        assert_eq!(transport.calls().len(), 2, "no padding under Standard");
    }

    #[test]
    fn padded_variant_with_high_privacy_emits_extra_fetches() {
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let conv = Uuid::now_v7();
        let bucket = "2026-04";
        for i in 1..=3 {
            seed_segment_map_row(
                &db,
                &format!("seg-{i}"),
                &conv.to_string(),
                bucket,
                &format!("blob-{i}"),
            );
        }

        let transport = FixtureTransport::default();
        for i in 1..=3 {
            transport.install(&format!("seg-{i}"), vec![i as u8; 8]);
        }

        let config = fresh_config(crate::config::PrivacyLevel::High);
        let segments =
            batch_prefetch_bucket_with_padding(&config, db.connection(), &transport, conv, bucket)
                .expect("prefetch");

        // All three real segments must have been returned.
        assert_eq!(segments.len(), 3);
        let mut ids: Vec<&str> = segments.iter().map(|s| s.segment_id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, vec!["seg-1", "seg-2", "seg-3"]);

        // Padding count is 2 * 3 = 6, so the transport must have
        // been called 9 times total (3 real + 6 dummy). The
        // dummies error out (no canned response) but the padded
        // variant silently drops those errors.
        let calls = transport.calls();
        assert_eq!(calls.len(), 9, "padded variant must issue real + dummy");
        transport.with_calls(3);

        // Every real id must appear at least once in the call log
        // (the dummies don't, by definition).
        for real in &["seg-1", "seg-2", "seg-3"] {
            assert!(calls.iter().any(|c| c == real), "missing {real}");
        }
    }

    #[test]
    fn padded_variant_with_high_privacy_and_no_real_segments_only_emits_real_calls() {
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let conv = Uuid::now_v7();
        let bucket = "2030-01";
        let transport = FixtureTransport::default();
        let config = fresh_config(crate::config::PrivacyLevel::High);
        let segments =
            batch_prefetch_bucket_with_padding(&config, db.connection(), &transport, conv, bucket)
                .expect("prefetch");
        assert!(segments.is_empty());
        // compute_padding_count(0) == 0 → no dummies either.
        assert!(transport.calls().is_empty());
    }

    // ---------------------------------------------------------
    // Phase 4 (Task 8): storage_backend-aware routing tests.
    // ---------------------------------------------------------

    /// In-memory `S3Client` for ZKOF-routed prefetch tests.
    /// Mirrors the in-memory mock used by the backup-sink tests.
    #[derive(Debug, Default)]
    struct InMemoryS3 {
        objects: Mutex<std::collections::BTreeMap<(String, String), Vec<u8>>>,
        get_calls: Mutex<Vec<(String, String)>>,
    }

    impl InMemoryS3 {
        fn put(&self, bucket: &str, key: &str, bytes: Vec<u8>) {
            self.objects
                .lock()
                .unwrap()
                .insert((bucket.to_string(), key.to_string()), bytes);
        }

        fn get_calls(&self) -> Vec<(String, String)> {
            self.get_calls.lock().unwrap().clone()
        }
    }

    impl crate::media::sinks::zk_fabric::S3Client for InMemoryS3 {
        fn put_object(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<(), Error> {
            self.objects
                .lock()
                .unwrap()
                .insert((bucket.to_string(), key.to_string()), bytes.to_vec());
            Ok(())
        }

        fn get_object_range(
            &self,
            bucket: &str,
            key: &str,
            range: Range<u64>,
        ) -> Result<Vec<u8>, Error> {
            self.get_calls
                .lock()
                .unwrap()
                .push((bucket.to_string(), key.to_string()));
            let store = self.objects.lock().unwrap();
            let bytes = store
                .get(&(bucket.to_string(), key.to_string()))
                .ok_or_else(|| Error::Storage(format!("no such object: {bucket}/{key}")))?;
            let start = range.start.min(bytes.len() as u64) as usize;
            let end = range.end.min(bytes.len() as u64) as usize;
            Ok(bytes[start..end].to_vec())
        }

        fn delete_object(&self, _bucket: &str, _key: &str) -> Result<(), Error> {
            Err(Error::NotImplemented("InMemoryS3::delete_object"))
        }
    }

    fn seed_zkof_segment_row(
        db: &LocalStoreDb,
        segment_id: &str,
        conversation_id: &str,
        time_bucket: &str,
        blob_id: &str,
    ) {
        db.connection()
            .execute(
                "INSERT INTO archive_segment_map(
                    segment_id, conversation_id, time_bucket,
                    segment_type, blob_id, storage_backend,
                    merkle_root, state
                 ) VALUES (?1, ?2, ?3, 'message_delta', ?4,
                           'zk_object_fabric', ?5, 'archive_uploaded')",
                params![
                    segment_id,
                    conversation_id,
                    time_bucket,
                    blob_id,
                    [0u8; 32].as_slice(),
                ],
            )
            .unwrap();
    }

    #[test]
    fn fetch_segment_routes_to_transport_for_kchat_backend() {
        let transport = FixtureTransport::default();
        transport.install("seg-K", vec![0xAA; 16]);
        let router = ArchiveSegmentRouter::kchat_only(&transport);
        let bytes = router
            .fetch(StorageBackend::KChatBackend, "seg-K")
            .expect("fetch");
        assert_eq!(bytes, vec![0xAA; 16]);
        assert_eq!(transport.calls(), vec!["seg-K".to_string()]);
    }

    #[test]
    fn fetch_segment_routes_to_s3_for_zkof_backend() {
        let s3 = std::sync::Arc::new(InMemoryS3::default());
        s3.put("bucket-A", "archive/segments/seg-Z", vec![0xBB; 32]);
        let cfg = crate::media::sinks::zk_fabric::ZkFabricSinkConfig {
            endpoint_url: "https://example.invalid".into(),
            bucket: "bucket-A".into(),
            access_key: "ak".into(),
            secret_key: "sk".into(),
        };
        let transport = FixtureTransport::default();
        let router = ArchiveSegmentRouter::with_zkof(&transport, s3.clone(), cfg);
        let bytes = router
            .fetch(StorageBackend::ZkObjectFabric, "seg-Z")
            .expect("fetch");
        assert_eq!(bytes, vec![0xBB; 32]);
        // The KChat transport must NOT have been called.
        assert!(transport.calls().is_empty(), "transport must be untouched");
        // The S3 client must have been called for the right key.
        assert_eq!(
            s3.get_calls(),
            vec![("bucket-A".to_string(), "archive/segments/seg-Z".to_string())]
        );
    }

    #[test]
    fn fetch_segment_zkof_without_s3_is_storage_error() {
        let transport = FixtureTransport::default();
        let router = ArchiveSegmentRouter::kchat_only(&transport);
        let err = router
            .fetch(StorageBackend::ZkObjectFabric, "seg-Z")
            .unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.contains("zk_object_fabric")),
            "got {err:?}"
        );
    }

    #[test]
    fn prefetch_bucket_reads_storage_backend_per_row() {
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let conv = Uuid::now_v7();
        let bucket = "2026-04";
        // One legacy KChat row, one ZKOF row, in the same bucket.
        seed_segment_map_row(&db, "seg-K", &conv.to_string(), bucket, "blob-K");
        seed_zkof_segment_row(&db, "seg-Z", &conv.to_string(), bucket, "blob-Z");

        let s3 = std::sync::Arc::new(InMemoryS3::default());
        s3.put("bucket-A", "archive/segments/seg-Z", vec![0xCC; 24]);
        let cfg = crate::media::sinks::zk_fabric::ZkFabricSinkConfig {
            endpoint_url: "https://example.invalid".into(),
            bucket: "bucket-A".into(),
            access_key: "ak".into(),
            secret_key: "sk".into(),
        };
        let transport = FixtureTransport::default();
        transport.install("seg-K", vec![0xDD; 12]);

        let router = ArchiveSegmentRouter::with_zkof(&transport, s3.clone(), cfg);
        let segments = batch_prefetch_bucket_with_router(db.connection(), &router, conv, bucket)
            .expect("router prefetch");
        assert_eq!(segments.len(), 2);

        // Each row's `storage_backend` column propagates to the
        // returned PrefetchedSegment.
        let mut by_id: HashMap<&str, &PrefetchedSegment> = HashMap::new();
        for seg in &segments {
            by_id.insert(seg.segment_id.as_str(), seg);
        }
        assert_eq!(by_id["seg-K"].storage_backend, "kchat_backend");
        assert_eq!(by_id["seg-Z"].storage_backend, "zk_object_fabric");
        assert_eq!(by_id["seg-K"].ciphertext, vec![0xDD; 12]);
        assert_eq!(by_id["seg-Z"].ciphertext, vec![0xCC; 24]);

        // Each backend was reached for exactly its own segment.
        assert_eq!(transport.calls(), vec!["seg-K".to_string()]);
        assert_eq!(
            s3.get_calls(),
            vec![("bucket-A".to_string(), "archive/segments/seg-Z".to_string())]
        );
    }

    #[test]
    fn batch_prefetch_bucket_errors_explicitly_on_zkof_rows() {
        // The legacy KChat-only entry point cannot route ZKOF
        // rows (no S3Client in scope). It must surface a
        // structured `Error::Storage` pointing the caller at
        // `_with_router` rather than silently 404-ing through
        // `transport.fetch_archive_segment`.
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let conv = Uuid::now_v7();
        let bucket = "2026-04";
        seed_segment_map_row(&db, "seg-K", &conv.to_string(), bucket, "blob-K");
        seed_zkof_segment_row(&db, "seg-Z", &conv.to_string(), bucket, "blob-Z");

        let transport = FixtureTransport::default();
        transport.install("seg-K", vec![0xAA; 8]);

        let err = batch_prefetch_bucket(db.connection(), &transport, conv, bucket).unwrap_err();
        match err {
            Error::Storage(msg) => {
                assert!(msg.contains("seg-Z"), "got: {msg}");
                assert!(msg.contains("zk_object_fabric"), "got: {msg}");
                assert!(
                    msg.contains("batch_prefetch_bucket_with_router"),
                    "got: {msg}"
                );
            }
            other => panic!("expected Error::Storage, got {other:?}"),
        }
        // The transport must NOT have been called for any row —
        // the validator runs before the fetch loop, so we don't
        // even start a doomed KChat fetch on the seg-K row.
        assert!(transport.calls().is_empty());
    }

    #[test]
    fn batch_prefetch_bucket_with_padding_high_privacy_errors_on_zkof_rows() {
        // Same guard for the High-privacy padded variant: the
        // hot path inside `batch_prefetch_bucket_with_padding`
        // calls `transport.fetch_archive_segment` directly, so
        // a ZKOF row would silently 404. Validate up front.
        let db = LocalStoreDb::open_in_memory(&[0; 32]).unwrap();
        let conv = Uuid::now_v7();
        let bucket = "2026-04";
        seed_segment_map_row(&db, "seg-K", &conv.to_string(), bucket, "blob-K");
        seed_zkof_segment_row(&db, "seg-Z", &conv.to_string(), bucket, "blob-Z");

        let transport = FixtureTransport::default();
        let config = fresh_config(crate::config::PrivacyLevel::High);

        let err =
            batch_prefetch_bucket_with_padding(&config, db.connection(), &transport, conv, bucket)
                .unwrap_err();
        match err {
            Error::Storage(msg) => {
                assert!(msg.contains("zk_object_fabric"), "got: {msg}");
                assert!(
                    msg.contains("batch_prefetch_bucket_with_router"),
                    "got: {msg}"
                );
            }
            other => panic!("expected Error::Storage, got {other:?}"),
        }
        // Validator must run before any padded fetch loop.
        assert!(transport.calls().is_empty());
    }
}
