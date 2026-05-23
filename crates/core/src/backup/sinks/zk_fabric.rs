//! ZK Object Fabric backup sink (Phase 4, Task 4).
//!
//! Mirrors [`crate::media::sinks::zk_fabric::ZkObjectFabricSink`]
//! for the **backup** pipeline. Routes sealed segment ciphertext
//! and manifest CBOR bundles through the same
//! [`crate::media::sinks::zk_fabric::S3Client`] abstraction the
//! media tier already drives — but layers Pattern C convergent
//! encryption on top so duplicate segments / manifests dedup
//! across tenants on the cloud side without the cloud needing the
//! per-tenant K_backup_root.
//!
//! Pattern C is the convergent-encryption layer described in
//! `kennguy3n/zk-object-fabric/encryption/client_sdk` (`sdk.go`).
//! The Rust implementation lives in
//! [`crate::crypto::convergent`] and is bit-identical to the Go
//! SDK — every byte the sink uploads can be decrypted by the Go
//! reference and vice versa, exercised by
//! [`crates/core/tests/pattern_c_interop_vectors.rs`].
//!
//! S3 key layout (matches `docs/PROPOSAL.md §6.5`):
//!
//! ```text
//! backups/{manifest_id}             — sealed manifest (CBOR
//!                                     of SealedBackupManifest)
//! backups/segments/{segment_id}     — sealed segment ciphertext
//! ```
//!
//! Both layers (the AEAD seal in
//! [`crate::backup::manifest_builder`] /
//! [`crate::backup::segment_builder`] under K_backup_*, and the
//! Pattern C convergent layer here) are independent — losing
//! either is not enough to read the bytes back. The Pattern C
//! layer adds dedup; the K_backup_* layer adds confidentiality
//! against the cloud operator.

use std::sync::Arc;

use super::BackupSink;
use crate::crypto::content_hash::content_hash;
use crate::crypto::convergent::{
    decrypt_object_pattern_c, derive_convergent_dek, encrypt_object_pattern_c, DEFAULT_CHUNK_SIZE,
};
use crate::media::sinks::zk_fabric::{S3Client, ZkFabricSinkConfig};
use crate::Error;

/// Storage-sink tag that the backup orchestrator persists into
/// any local tracking table (mirroring
/// [`crate::media::sinks::zk_fabric::ZK_OBJECT_FABRIC_SINK_TAG`]).
pub const ZK_OBJECT_FABRIC_BACKUP_SINK_TAG: &str = "zk_object_fabric";

/// Object key prefix for sealed segment ciphertext: per the
/// module-level layout, `backups/segments/{segment_id}`.
const SEGMENT_KEY_PREFIX: &str = "backups/segments/";

/// Object key prefix for sealed manifest bundles: per the
/// module-level layout, `backups/{manifest_id}`.
const MANIFEST_KEY_PREFIX: &str = "backups/";

fn segment_key(segment_id: &str) -> String {
    format!("{SEGMENT_KEY_PREFIX}{segment_id}")
}

fn manifest_key(manifest_id: &str) -> String {
    format!("{MANIFEST_KEY_PREFIX}{manifest_id}")
}

/// `BackupSink` implementation routing through an
/// [`S3Client`] against a [`ZkFabricSinkConfig`], wrapping every
/// payload in a Pattern C convergent-encryption frame keyed by
/// the configured tenant id.
///
/// Construction:
///
/// ```ignore
/// let s3: Arc<dyn S3Client> = Arc::new(my_s3_client);
/// let sink = ZkofBackupSink::new(s3, config, "tenant-acme")?;
/// ```
#[derive(Debug, Clone)]
pub struct ZkofBackupSink {
    s3: Arc<dyn S3Client>,
    config: ZkFabricSinkConfig,
    tenant_id: String,
    /// Phase 7 (2026-05-04 batch 10 — Task 10) — optional
    /// dedup-analytics probe. When set, every successful
    /// `upload_backup_segment` / `upload_backup_manifest` records
    /// a [`DedupEvent::ObjectUploaded`] into the probe. The flag
    /// is `None` by default so the legacy upload path is
    /// behaviorally unchanged.
    dedup_analytics: Option<Arc<dyn crate::transport::dedup_analytics::DedupAnalytics>>,
}

impl ZkofBackupSink {
    /// Construct a backup sink bound to the supplied S3 client,
    /// ZKOF config, and tenant id. The tenant id is fed into the
    /// Pattern C DEK derivation so two tenants encrypting the
    /// same plaintext produce different ciphertexts (no
    /// cross-tenant dedup).
    pub fn new(
        s3: Arc<dyn S3Client>,
        config: ZkFabricSinkConfig,
        tenant_id: impl Into<String>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let tenant_id = tenant_id.into();
        if tenant_id.is_empty() {
            return Err(Error::Storage(
                "ZkofBackupSink: tenant_id must not be empty".into(),
            ));
        }
        Ok(Self {
            s3,
            config,
            tenant_id,
            dedup_analytics: None,
        })
    }

    /// Phase 7 (2026-05-04 batch 10 — Task 10): builder helper
    /// that attaches a dedup-analytics probe. Returns `self` for
    /// fluent construction. When set, every successful upload
    /// records a [`crate::transport::dedup_analytics::DedupEvent::ObjectUploaded`]
    /// into the probe.
    pub fn with_dedup_analytics(
        mut self,
        probe: Arc<dyn crate::transport::dedup_analytics::DedupAnalytics>,
    ) -> Self {
        self.dedup_analytics = Some(probe);
        self
    }

    /// Bucket name this sink targets.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Tenant id stamped into the Pattern C DEK derivation.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Convergent-seal `plaintext` and return the framed
    /// ciphertext bytes. Exposed for tests / determinism vectors.
    pub fn pattern_c_seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = content_hash(plaintext);
        let dek = derive_convergent_dek(&hash, &self.tenant_id)
            .map_err(|e| Error::Storage(format!("ZkofBackupSink: derive DEK: {e}").into()))?;
        encrypt_object_pattern_c(plaintext, dek.as_bytes(), DEFAULT_CHUNK_SIZE)
            .map_err(|e| Error::Storage(format!("ZkofBackupSink: pattern C seal: {e}").into()))
    }

    /// Pattern C `open` — inverse of [`Self::pattern_c_seal`].
    /// Requires the original plaintext's BLAKE3 hash because the
    /// DEK is content-derived; the caller hands it the hash via
    /// the manifest / segment metadata. Exposed for tests.
    pub fn pattern_c_open(
        &self,
        ciphertext: &[u8],
        plaintext_hash: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        let dek = derive_convergent_dek(plaintext_hash, &self.tenant_id)
            .map_err(|e| Error::Storage(format!("ZkofBackupSink: derive DEK: {e}").into()))?;
        decrypt_object_pattern_c(ciphertext, dek.as_bytes(), DEFAULT_CHUNK_SIZE)
            .map_err(|e| Error::Storage(format!("ZkofBackupSink: pattern C open: {e}").into()))
    }
}

impl BackupSink for ZkofBackupSink {
    fn upload_backup_segment(&self, segment_id: &str, ciphertext: &[u8]) -> crate::Result<()> {
        let sealed = self.pattern_c_seal(ciphertext)?;
        let size_bytes = ciphertext.len() as u64;
        self.s3
            .put_object(&self.config.bucket, &segment_key(segment_id), &sealed)?;
        // Phase 7 (2026-05-04 batch 10 — Task 10): record the
        // upload into the dedup-analytics probe if installed. We
        // cannot tell from the S3 PutObject response whether the
        // convergent ciphertext already existed (there is no
        // `If-None-Match` semantics in the legacy `put_object`
        // surface), so we conservatively report `was_deduped=false`
        // — production deployments swap in an S3 client that
        // checks `HEAD` first and reports the cache hit.
        if let Some(probe) = self.dedup_analytics.as_ref() {
            let _ = probe.record_event(
                crate::transport::dedup_analytics::DedupEvent::ObjectUploaded {
                    size_bytes,
                    was_deduped: false,
                },
            );
        }
        Ok(())
    }

    fn upload_backup_manifest(&self, manifest_id: &str, sealed: &[u8]) -> crate::Result<()> {
        let convergent = self.pattern_c_seal(sealed)?;
        let size_bytes = sealed.len() as u64;
        self.s3
            .put_object(&self.config.bucket, &manifest_key(manifest_id), &convergent)?;
        if let Some(probe) = self.dedup_analytics.as_ref() {
            let _ = probe.record_event(
                crate::transport::dedup_analytics::DedupEvent::ObjectUploaded {
                    size_bytes,
                    was_deduped: false,
                },
            );
        }
        Ok(())
    }

    fn fetch_backup_manifest(&self, manifest_id: &str) -> crate::Result<Vec<u8>> {
        let key = manifest_key(manifest_id);
        // Fetch the entire object via a wide range request — the
        // S3 endpoint is expected to clamp the trailing range to
        // the actual object length (see the production contract
        // in `media::sinks::zk_fabric`).
        let bytes = self
            .s3
            .get_object_range(&self.config.bucket, &key, 0..u64::MAX)?;
        // Pattern C is content-addressed: the sink does not own
        // the plaintext hash, so it returns the raw convergent
        // bytes. The orchestrator (which holds the manifest
        // ledger row carrying the plaintext hash) finishes the
        // open via [`ZkofBackupSink::pattern_c_open`] before
        // decoding the CBOR. Phase 5 will fold the hash into
        // sink-side metadata so this method returns plaintext
        // directly.
        Ok(bytes)
    }

    fn fetch_backup_segment(&self, segment_id: &str) -> crate::Result<Vec<u8>> {
        let key = segment_key(segment_id);
        let bytes = self
            .s3
            .get_object_range(&self.config.bucket, &key, 0..u64::MAX)?;
        Ok(bytes)
    }

    fn list_backup_manifests(&self) -> crate::Result<Vec<String>> {
        let keys = self
            .s3
            .list_objects(&self.config.bucket, MANIFEST_KEY_PREFIX)?;
        // Strip the prefix and filter out segment keys (which
        // share the `backups/` prefix but live under
        // `backups/segments/`).
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(rest) = key.strip_prefix(MANIFEST_KEY_PREFIX) {
                if !rest.starts_with("segments/") {
                    out.push(rest.to_string());
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ops::Range;
    use std::sync::Mutex;

    /// In-memory `S3Client` used by every test in this module.
    /// Stores objects as `BTreeMap<(bucket, key), bytes>` and
    /// supports byte-range reads (clamping past the object
    /// length, matching the production contract).
    #[derive(Debug, Default)]
    struct InMemoryS3 {
        objects: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    }

    impl InMemoryS3 {
        fn new() -> Self {
            Self::default()
        }
    }

    impl S3Client for InMemoryS3 {
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
            let objects = self.objects.lock().unwrap();
            let bytes = objects
                .get(&(bucket.to_string(), key.to_string()))
                .ok_or_else(|| Error::Storage(format!("no such object: {bucket}/{key}").into()))?;
            let start = range.start.min(bytes.len() as u64) as usize;
            let end = range.end.min(bytes.len() as u64) as usize;
            Ok(bytes[start..end].to_vec())
        }

        fn delete_object(&self, bucket: &str, key: &str) -> Result<(), Error> {
            self.objects
                .lock()
                .unwrap()
                .remove(&(bucket.to_string(), key.to_string()));
            Ok(())
        }

        fn list_objects(&self, bucket: &str, prefix: &str) -> Result<Vec<String>, Error> {
            let objects = self.objects.lock().unwrap();
            Ok(objects
                .keys()
                .filter(|(b, k)| b == bucket && k.starts_with(prefix))
                .map(|(_, k)| k.clone())
                .collect())
        }
    }

    fn fresh_config() -> ZkFabricSinkConfig {
        ZkFabricSinkConfig {
            endpoint_url: "https://zkof.example.com".into(),
            access_key: "AKIA".into(),
            secret_key: "SECRET".into(),
            bucket: "zkof-backup-test".into(),
        }
    }

    fn fresh_sink() -> (Arc<InMemoryS3>, ZkofBackupSink) {
        let s3 = Arc::new(InMemoryS3::new());
        let sink = ZkofBackupSink::new(s3.clone(), fresh_config(), "tenant-test").unwrap();
        (s3, sink)
    }

    #[test]
    fn rejects_empty_tenant_id() {
        let s3 = Arc::new(InMemoryS3::new());
        let err = ZkofBackupSink::new(s3, fresh_config(), "").unwrap_err();
        assert!(matches!(err, Error::Storage(msg) if msg.to_string().contains("tenant_id")));
    }

    #[test]
    fn zkof_backup_sink_segment_round_trip() {
        let (_s3, sink) = fresh_sink();
        let segment_id = "seg-abcdef";
        let plaintext = b"sealed segment ciphertext under K_backup_segment".to_vec();

        sink.upload_backup_segment(segment_id, &plaintext).unwrap();
        let fetched = sink.fetch_backup_segment(segment_id).unwrap();

        // The fetched bytes are still under Pattern C — open them
        // and verify they round-trip back to the original
        // plaintext.
        let plaintext_hash = content_hash(&plaintext);
        let opened = sink.pattern_c_open(&fetched, &plaintext_hash).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn zkof_backup_sink_manifest_round_trip() {
        let (_s3, sink) = fresh_sink();
        let manifest_id = "man-12345";
        let plaintext = b"sealed manifest CBOR under K_backup_manifest".to_vec();

        sink.upload_backup_manifest(manifest_id, &plaintext)
            .unwrap();
        let fetched = sink.fetch_backup_manifest(manifest_id).unwrap();

        let plaintext_hash = content_hash(&plaintext);
        let opened = sink.pattern_c_open(&fetched, &plaintext_hash).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn pattern_c_convergent_encryption_produces_deterministic_output() {
        let (_s3, sink) = fresh_sink();
        let plaintext = b"identical input".to_vec();
        let a = sink.pattern_c_seal(&plaintext).unwrap();
        let b = sink.pattern_c_seal(&plaintext).unwrap();
        assert_eq!(a, b, "convergent encryption must be deterministic");
    }

    #[test]
    fn pattern_c_different_tenants_produce_different_ciphertexts() {
        let s3 = Arc::new(InMemoryS3::new());
        let a = ZkofBackupSink::new(s3.clone(), fresh_config(), "tenant-a").unwrap();
        let b = ZkofBackupSink::new(s3, fresh_config(), "tenant-b").unwrap();

        let plaintext = b"shared plaintext".to_vec();
        let ca = a.pattern_c_seal(&plaintext).unwrap();
        let cb = b.pattern_c_seal(&plaintext).unwrap();
        assert_ne!(ca, cb, "tenant id must be mixed into the DEK");
    }

    #[test]
    fn list_backup_manifests_returns_only_manifest_ids() {
        let (_s3, sink) = fresh_sink();
        sink.upload_backup_segment("seg-1", b"segment-A").unwrap();
        sink.upload_backup_segment("seg-2", b"segment-B").unwrap();
        sink.upload_backup_manifest("man-1", b"manifest-A").unwrap();
        sink.upload_backup_manifest("man-2", b"manifest-B").unwrap();

        let mut manifests = sink.list_backup_manifests().unwrap();
        manifests.sort();
        assert_eq!(manifests, vec!["man-1".to_string(), "man-2".to_string()]);
    }

    #[test]
    fn backup_sink_trait_is_object_safe() {
        let (_s3, sink) = fresh_sink();
        let _boxed: Box<dyn BackupSink> = Box::new(sink);
    }

    #[test]
    fn fetch_backup_manifest_with_wrong_hash_fails() {
        let (_s3, sink) = fresh_sink();
        sink.upload_backup_manifest("man-x", b"original").unwrap();
        let fetched = sink.fetch_backup_manifest("man-x").unwrap();
        // The wrong hash derives the wrong DEK and the AEAD open
        // tag-check fails.
        let bogus_hash = [0u8; 32];
        let err = sink.pattern_c_open(&fetched, &bogus_hash).unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.to_string().contains("pattern C open")),
            "got {err:?}"
        );
    }

    #[test]
    fn upload_backup_segment_records_dedup_event() {
        use crate::transport::dedup_analytics::DedupAnalytics;
        let s3 = Arc::new(InMemoryS3::new());
        let probe = Arc::new(crate::transport::dedup_analytics::InProcessDedupAnalytics::new());
        let sink = ZkofBackupSink::new(s3, fresh_config(), "tenant-test")
            .unwrap()
            .with_dedup_analytics(probe.clone());
        sink.upload_backup_segment("seg-1", b"hello").unwrap();
        sink.upload_backup_manifest("man-1", b"world").unwrap();
        let stats = probe.query_dedup_ratio("tenant-test").unwrap();
        assert_eq!(stats.total_objects, 2);
        assert_eq!(stats.total_bytes, 10);
        let recent = probe.recent_events();
        assert_eq!(recent.len(), 2);
    }
}
