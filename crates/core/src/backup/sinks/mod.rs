//! Backup sink routing seam.
//!
//! Mirrors [`crate::media::sinks`] for the **backup** pipeline:
//! `BackupSink` owns the upload / fetch / list calls the backup
//! engine needs to drive a cloud-backup tier without knowing
//! whether it is talking to the KChat backend, an iCloud / Google
//! Drive sink, or a ZK Object Fabric S3 endpoint.
//!
//! The sink operates on **already-encrypted** segment / manifest
//! ciphertext. The segment builder
//! ([`crate::backup::segment_builder::BackupSegmentBuilder`]) and
//! the manifest builder
//! ([`crate::backup::manifest_builder::build_backup_manifest`])
//! produce the AEAD-sealed bytes; the sink moves them to and from
//! the backend verbatim.
//!
//! Object key layout (per `docs/DESIGN.md §6.5` and Task 4):
//!
//! * `backups/{manifest_id}` — sealed manifest bundle (CBOR
//!   encoding of [`crate::backup::manifest_builder::SealedBackupManifest`]).
//! * `backups/segments/{segment_id}` — sealed segment ciphertext
//!   (the `ciphertext` field of [`crate::backup::segment_builder::BuiltBackupSegment`]).
//!
//! The trait is object-safe so the orchestration layer can hold a
//! single `Box<dyn BackupSink>` and dispatch from any worker.

pub mod android;
pub mod icloud;
pub mod zk_fabric;

/// Routing seam for backup uploads / fetches / lists.
///
/// `Send + Sync + Debug` so a single `Arc<dyn BackupSink>` can be
/// shared across worker threads. All methods take `&str`
/// identifiers — the sink resolves them to backend-specific keys
/// (S3 object keys, CloudKit record names, …) internally.
pub trait BackupSink: Send + Sync + std::fmt::Debug {
    /// Upload `ciphertext` for `segment_id`. The bytes are the
    /// `ciphertext` field of a
    /// [`crate::backup::segment_builder::BuiltBackupSegment`];
    /// the sink stores them verbatim.
    fn upload_backup_segment(&self, segment_id: &str, ciphertext: &[u8]) -> crate::Result<()>;

    /// Upload the CBOR encoding of
    /// [`crate::backup::manifest_builder::SealedBackupManifest`]
    /// for `manifest_id`. The encoder is the orchestration
    /// layer's responsibility — the sink does not interpret the
    /// bytes.
    fn upload_backup_manifest(&self, manifest_id: &str, sealed: &[u8]) -> crate::Result<()>;

    /// Fetch the sealed manifest CBOR bundle for `manifest_id`.
    fn fetch_backup_manifest(&self, manifest_id: &str) -> crate::Result<Vec<u8>>;

    /// Fetch the segment ciphertext for `segment_id`.
    fn fetch_backup_segment(&self, segment_id: &str) -> crate::Result<Vec<u8>>;

    /// List every manifest id known to this sink. Order is not
    /// guaranteed — the restore pipeline sorts by `generation`
    /// after decoding.
    fn list_backup_manifests(&self) -> crate::Result<Vec<String>>;
}

/// `BackupSink` placeholder used by tests / phases that have not
/// wired a real backend yet. Every method returns
/// [`crate::Error::NotImplemented("backup_sink")`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBackupSink;

impl BackupSink for NoopBackupSink {
    fn upload_backup_segment(&self, _segment_id: &str, _ciphertext: &[u8]) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("backup_sink"))
    }

    fn upload_backup_manifest(&self, _manifest_id: &str, _sealed: &[u8]) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("backup_sink"))
    }

    fn fetch_backup_manifest(&self, _manifest_id: &str) -> crate::Result<Vec<u8>> {
        Err(crate::Error::NotImplemented("backup_sink"))
    }

    fn fetch_backup_segment(&self, _segment_id: &str) -> crate::Result<Vec<u8>> {
        Err(crate::Error::NotImplemented("backup_sink"))
    }

    fn list_backup_manifests(&self) -> crate::Result<Vec<String>> {
        Err(crate::Error::NotImplemented("backup_sink"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_sink_trait_is_object_safe() {
        let sink: Box<dyn BackupSink> = Box::new(NoopBackupSink);
        // Just exercise dispatch — every method must surface the
        // canonical NotImplemented sentinel.
        assert!(matches!(
            sink.upload_backup_segment("seg-1", b"x"),
            Err(crate::Error::NotImplemented("backup_sink"))
        ));
        assert!(matches!(
            sink.upload_backup_manifest("man-1", b"x"),
            Err(crate::Error::NotImplemented("backup_sink"))
        ));
        assert!(matches!(
            sink.fetch_backup_manifest("man-1"),
            Err(crate::Error::NotImplemented("backup_sink"))
        ));
        assert!(matches!(
            sink.fetch_backup_segment("seg-1"),
            Err(crate::Error::NotImplemented("backup_sink"))
        ));
        assert!(matches!(
            sink.list_backup_manifests(),
            Err(crate::Error::NotImplemented("backup_sink"))
        ));
    }
}
