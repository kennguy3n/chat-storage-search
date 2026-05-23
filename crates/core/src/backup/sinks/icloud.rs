//! iCloud (CloudKit) backup sink ().
//!
//! Mirrors [`crate::media::sinks::icloud::ICloudMediaBlobSink`]
//! for the **backup** pipeline: routes sealed segment / manifest
//! ciphertext through a thin
//! [`ICloudBackupBridge`] trait that the iOS / macOS host fills
//! in with a real CloudKit container. The Rust core never links
//! `CloudKit.framework`; Swift code on the device implements
//! [`ICloudBackupBridge`] and hands the trait object back to the
//! core at unlock time.
//!
//! CloudKit record-name layout (matches `docs/DESIGN.md §6.5`
//! and the [`super`] module-level note):
//!
//! ```text
//! backups/{manifest_id} — sealed manifest CBOR bundle
//! backups/segments/{segment_id} — sealed segment ciphertext
//! ```
//!
//! These are the same record names the
//! [`crate::backup::sinks::zk_fabric::ZkofBackupSink`] uses for
//! S3 keys, so a manifest produced by the orchestrator can land
//! on either tier without re-encoding. The bridge sees only
//! AEAD-sealed ciphertext (the segment / manifest builder
//! produced bytes); no plaintext key material is exposed to
//! CloudKit.
//!
//! The bridge is deliberately byte-level (`upload_file`,
//! `download_file`, `list_files`, `delete_file`) so the Swift
//! side can decide whether to use `CKAsset`, `CKRecord`, or a
//! `CKAsset`-on-`CKRecord` hybrid. Listing is a hard requirement
//! because the restore path needs to discover manifest record
//! names without the orchestrator pre-knowing every UUID.

use std::sync::Arc;

use super::BackupSink;
use crate::Error;

/// Object key prefix for sealed segment ciphertext, matching the
/// [`crate::backup::sinks::zk_fabric::ZkofBackupSink`] layout.
const SEGMENT_KEY_PREFIX: &str = "backups/segments/";

/// Object key prefix for sealed manifest bundles, matching the
/// [`crate::backup::sinks::zk_fabric::ZkofBackupSink`] layout.
const MANIFEST_KEY_PREFIX: &str = "backups/";

fn segment_record_name(segment_id: &str) -> String {
    format!("{SEGMENT_KEY_PREFIX}{segment_id}")
}

fn manifest_record_name(manifest_id: &str) -> String {
    format!("{MANIFEST_KEY_PREFIX}{manifest_id}")
}

/// Storage-sink tag the orchestrator persists into any local
/// tracking table when a record lands on iCloud.
pub const ICLOUD_BACKUP_SINK_TAG: &str = "icloud_backup";

/// Platform bridge the iOS / macOS host implements with a real
/// CloudKit `CKContainer`. The trait is byte-level: the bridge
/// receives AEAD-sealed ciphertext from the segment / manifest
/// builder and stores it verbatim. All identifiers are CloudKit
/// record names, *not* iCloud Drive paths.
///
/// `Send + Sync + Debug` so a single `Arc<dyn ICloudBackupBridge>`
/// can be shared across worker threads on the Swift side and the
/// Rust core's backup engine.
pub trait ICloudBackupBridge: Send + Sync + std::fmt::Debug {
    /// Upload `data` to the CloudKit asset keyed by
    /// `record_name`. The Swift side commits the asset
    /// transactionally — partial uploads are not visible. Idempotent:
    /// uploading the same `record_name` twice overwrites the
    /// previous record (CloudKit dedup is the host's job).
    fn upload_file(&self, record_name: &str, data: &[u8]) -> Result<(), Error>;

    /// Fetch the bytes previously stored under `record_name`. The
    /// Swift side returns the full asset payload — partial
    /// fetches are not part of the contract.
    fn download_file(&self, record_name: &str) -> Result<Vec<u8>, Error>;

    /// Enumerate every record name beginning with `prefix`. The
    /// list need not be sorted; the orchestrator sorts manifests
    /// by `generation` after CBOR-decoding.
    fn list_files(&self, prefix: &str) -> Result<Vec<String>, Error>;

    /// Idempotently delete the record at `record_name`. Missing
    /// records are not an error.
    fn delete_file(&self, record_name: &str) -> Result<(), Error>;
}

/// `ICloudBackupBridge` placeholder used by tests / phases that
/// have not wired a real CloudKit container yet. Every method
/// returns [`Error::NotImplemented("icloud_backup_bridge")`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopICloudBackupBridge;

impl ICloudBackupBridge for NoopICloudBackupBridge {
    fn upload_file(&self, _record_name: &str, _data: &[u8]) -> Result<(), Error> {
        Err(Error::NotImplemented("icloud_backup_bridge"))
    }

    fn download_file(&self, _record_name: &str) -> Result<Vec<u8>, Error> {
        Err(Error::NotImplemented("icloud_backup_bridge"))
    }

    fn list_files(&self, _prefix: &str) -> Result<Vec<String>, Error> {
        Err(Error::NotImplemented("icloud_backup_bridge"))
    }

    fn delete_file(&self, _record_name: &str) -> Result<(), Error> {
        Err(Error::NotImplemented("icloud_backup_bridge"))
    }
}

/// `BackupSink` implementation routing through an iOS / macOS
/// CloudKit container.
///
/// Construction:
///
/// ```ignore
/// let bridge: Arc<dyn ICloudBackupBridge> = Arc::new(my_bridge);
/// let sink = ICloudBackupSink::new(bridge);
/// ```
#[derive(Debug, Clone)]
pub struct ICloudBackupSink {
    bridge: Arc<dyn ICloudBackupBridge>,
}

impl ICloudBackupSink {
    /// Construct a sink delegating every byte-level operation to
    /// the supplied `bridge`.
    pub fn new(bridge: Arc<dyn ICloudBackupBridge>) -> Self {
        Self { bridge }
    }

    /// Storage-sink tag stamped into any tracking table the
    /// orchestrator maintains (e.g. `backup_segment_map.sink_tag`).
    pub fn sink_tag(&self) -> &'static str {
        ICLOUD_BACKUP_SINK_TAG
    }
}

impl BackupSink for ICloudBackupSink {
    fn upload_backup_segment(&self, segment_id: &str, ciphertext: &[u8]) -> crate::Result<()> {
        self.bridge
            .upload_file(&segment_record_name(segment_id), ciphertext)
    }

    fn upload_backup_manifest(&self, manifest_id: &str, sealed: &[u8]) -> crate::Result<()> {
        self.bridge
            .upload_file(&manifest_record_name(manifest_id), sealed)
    }

    fn fetch_backup_manifest(&self, manifest_id: &str) -> crate::Result<Vec<u8>> {
        self.bridge
            .download_file(&manifest_record_name(manifest_id))
    }

    fn fetch_backup_segment(&self, segment_id: &str) -> crate::Result<Vec<u8>> {
        self.bridge.download_file(&segment_record_name(segment_id))
    }

    fn list_backup_manifests(&self) -> crate::Result<Vec<String>> {
        // Filter out segment record names — the bridge's
        // `list_files(MANIFEST_KEY_PREFIX)` returns every record
        // beginning with `backups/`, including
        // `backups/segments/...`.
        let raw = self.bridge.list_files(MANIFEST_KEY_PREFIX)?;
        let mut out = Vec::with_capacity(raw.len());
        for record in raw {
            if let Some(rest) = record.strip_prefix(MANIFEST_KEY_PREFIX) {
                if !rest.starts_with("segments/") && !rest.is_empty() {
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
    use std::sync::Mutex;

    /// In-memory bridge used by every test in this module. Stores
    /// record-name → bytes mappings under a shared `Mutex` so
    /// list / fetch / delete observe the same state across calls.
    #[derive(Debug, Default)]
    struct InMemoryICloudBridge {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        uploads: Mutex<u32>,
        downloads: Mutex<u32>,
        deletes: Mutex<u32>,
    }

    impl ICloudBackupBridge for InMemoryICloudBridge {
        fn upload_file(&self, record_name: &str, data: &[u8]) -> Result<(), Error> {
            *self.uploads.lock().unwrap() += 1;
            self.objects
                .lock()
                .unwrap()
                .insert(record_name.into(), data.to_vec());
            Ok(())
        }

        fn download_file(&self, record_name: &str) -> Result<Vec<u8>, Error> {
            *self.downloads.lock().unwrap() += 1;
            self.objects
                .lock()
                .unwrap()
                .get(record_name)
                .cloned()
                .ok_or_else(|| Error::Storage(format!("no such record: {record_name}").into()))
        }

        fn list_files(&self, prefix: &str) -> Result<Vec<String>, Error> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }

        fn delete_file(&self, record_name: &str) -> Result<(), Error> {
            *self.deletes.lock().unwrap() += 1;
            self.objects.lock().unwrap().remove(record_name);
            Ok(())
        }
    }

    #[test]
    fn icloud_backup_bridge_trait_is_object_safe() {
        let _b: Box<dyn ICloudBackupBridge> = Box::new(NoopICloudBackupBridge);
        let _a: Arc<dyn ICloudBackupBridge> = Arc::new(NoopICloudBackupBridge);
    }

    #[test]
    fn noop_bridge_surfaces_not_implemented_for_every_method() {
        let stub = NoopICloudBackupBridge;
        assert!(matches!(
            stub.upload_file("r", &[]).unwrap_err(),
            Error::NotImplemented("icloud_backup_bridge")
        ));
        assert!(matches!(
            stub.download_file("r").unwrap_err(),
            Error::NotImplemented("icloud_backup_bridge")
        ));
        assert!(matches!(
            stub.list_files("p").unwrap_err(),
            Error::NotImplemented("icloud_backup_bridge")
        ));
        assert!(matches!(
            stub.delete_file("r").unwrap_err(),
            Error::NotImplemented("icloud_backup_bridge")
        ));
    }

    #[test]
    fn segment_round_trip_uses_segments_record_prefix() {
        let bridge = Arc::new(InMemoryICloudBridge::default());
        let sink = ICloudBackupSink::new(bridge.clone());
        sink.upload_backup_segment("seg-A", b"sealed-bytes")
            .expect("upload");
        let bytes = sink.fetch_backup_segment("seg-A").expect("fetch");
        assert_eq!(bytes, b"sealed-bytes");

        // Verify the bridge actually saw the namespaced record.
        let known = bridge
            .list_files("backups/segments/")
            .expect("list segments");
        assert_eq!(known, vec!["backups/segments/seg-A".to_string()]);
        assert_eq!(*bridge.uploads.lock().unwrap(), 1);
        assert_eq!(*bridge.downloads.lock().unwrap(), 1);
    }

    #[test]
    fn manifest_round_trip_uses_top_level_backup_prefix() {
        let bridge = Arc::new(InMemoryICloudBridge::default());
        let sink = ICloudBackupSink::new(bridge.clone());
        sink.upload_backup_manifest("mfst-1", b"cbor-bytes")
            .expect("upload");
        let bytes = sink.fetch_backup_manifest("mfst-1").expect("fetch");
        assert_eq!(bytes, b"cbor-bytes");
        let raw = bridge.list_files("backups/").expect("list");
        assert_eq!(raw, vec!["backups/mfst-1".to_string()]);
    }

    #[test]
    fn list_backup_manifests_filters_segments() {
        let bridge = Arc::new(InMemoryICloudBridge::default());
        let sink = ICloudBackupSink::new(bridge);
        sink.upload_backup_manifest("mfst-1", b"m1").unwrap();
        sink.upload_backup_manifest("mfst-2", b"m2").unwrap();
        sink.upload_backup_segment("seg-1", b"s1").unwrap();
        sink.upload_backup_segment("seg-2", b"s2").unwrap();
        let mut listed = sink.list_backup_manifests().expect("list");
        listed.sort();
        assert_eq!(listed, vec!["mfst-1".to_string(), "mfst-2".to_string()]);
    }

    #[test]
    fn fetch_missing_record_surfaces_storage_error() {
        let bridge = Arc::new(InMemoryICloudBridge::default());
        let sink = ICloudBackupSink::new(bridge);
        let err = sink.fetch_backup_manifest("does-not-exist").unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn noop_bridge_round_trip_through_sink_surfaces_not_implemented() {
        let sink = ICloudBackupSink::new(Arc::new(NoopICloudBackupBridge));
        assert!(matches!(
            sink.upload_backup_segment("s", b""),
            Err(Error::NotImplemented("icloud_backup_bridge"))
        ));
        assert!(matches!(
            sink.fetch_backup_manifest("m"),
            Err(Error::NotImplemented("icloud_backup_bridge"))
        ));
        assert!(matches!(
            sink.list_backup_manifests(),
            Err(Error::NotImplemented("icloud_backup_bridge"))
        ));
    }
}
