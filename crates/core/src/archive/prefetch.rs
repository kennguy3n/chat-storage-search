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
use uuid::Uuid;

use crate::archive::privacy::{compute_padding_count, pad_with_dummy_requests, should_pad};
use crate::config::KChatCoreConfig;
use crate::transport::TransportClient;
use crate::Error;

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
    for row in rows {
        let (segment_id, blob_id, storage_backend) =
            row.map_err(|e| Error::Storage(e.to_string()))?;
        real_rows.insert(segment_id, (blob_id, storage_backend));
    }

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
}
