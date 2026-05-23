//! Android backup sink.
//!
//! Mirrors [`crate::backup::sinks::icloud::ICloudBackupSink`] for
//! the Android side of the **backup** pipeline. The Rust core
//! never links the Android SDK directly; the Kotlin / Java host
//! implements [`AndroidBackupBridge`] against
//! `BackupAgent` (Auto Backup) for small manifest pointers AND
//! Storage Access Framework (SAF) document URIs for the larger
//! segment payloads, then hands the trait object back to the
//! core at unlock time.
//!
//! ## Why two channels?
//!
//! `docs/DESIGN.md §6.5` pins Android's backup story to Auto
//! Backup *plus* SAF: Auto Backup is free / quota-managed by
//! Google but capped at 25 MiB *per package*, while SAF lets the
//! user choose any document provider (Google Drive, Dropbox,
//! Nextcloud, …) and is unconstrained in size. The split is:
//!
//! ```text
//! Auto Backup ── manifest pointers (≤ 25 MiB cumulative)
//! → BackupAgent xml namespace
//!
//! SAF ── full segment ciphertext, one document URI per
//! segment, listed under a user-picked tree URI
//! ```
//!
//! The bridge is byte-level so the Kotlin side can decide on
//! `BackupHelper`, `BackupAgentHelper`, raw `ContentResolver`
//! writes, etc. Listing is required on the SAF side because the
//! restore path discovers segment URIs from the manifest at
//! restore time.

use std::sync::Arc;

use super::BackupSink;
use crate::Error;

/// Storage-sink tag the orchestrator persists into any local
/// tracking table when a record lands on Android (e.g.
/// `backup_segment_map.sink_tag`).
pub const ANDROID_BACKUP_SINK_TAG: &str = "android_backup";

/// Auto Backup key prefix for sealed manifest bundles. Matches
/// the iCloud / ZKOF layout so manifests can move between tiers
/// without the orchestrator re-keying them.
const MANIFEST_KEY_PREFIX: &str = "backups/";

/// SAF "key" prefix for sealed segment ciphertext. The Kotlin
/// side maps this prefix into a sub-folder under the user-picked
/// document tree URI.
const SEGMENT_KEY_PREFIX: &str = "backups/segments/";

fn manifest_key(manifest_id: &str) -> String {
    format!("{MANIFEST_KEY_PREFIX}{manifest_id}")
}

fn segment_uri(segment_id: &str) -> String {
    format!("{SEGMENT_KEY_PREFIX}{segment_id}")
}

/// Platform bridge the Android host implements. The trait is
/// byte-level: the bridge sees AEAD-sealed ciphertext from the
/// segment / manifest builder and stores it verbatim. Auto Backup
/// records are *small* (≤ 25 MiB total per package, per Google);
/// SAF documents have no such cap.
///
/// `Send + Sync + Debug` so a single
/// `Arc<dyn AndroidBackupBridge>` can be shared across worker
/// threads on the Kotlin side and the Rust core's backup engine.
pub trait AndroidBackupBridge: Send + Sync + std::fmt::Debug {
    /// Write `data` to Android Auto Backup under `key`. The
    /// Kotlin side typically forwards this to a `BackupHelper`
    /// callback. Idempotent: the same key may be re-written.
    fn write_auto_backup(&self, key: &str, data: &[u8]) -> Result<(), Error>;

    /// Read previously-written Auto Backup bytes for `key`. Used
    /// by the restore path to fetch manifest pointers before
    /// pulling the corresponding SAF document URIs.
    fn read_auto_backup(&self, key: &str) -> Result<Vec<u8>, Error>;

    /// Write `data` to SAF, materialising a document at `uri`.
    /// The Kotlin side resolves `uri` against the user-picked
    /// tree URI before opening a `ParcelFileDescriptor` and
    /// streaming the bytes. Idempotent.
    fn write_saf(&self, uri: &str, data: &[u8]) -> Result<(), Error>;

    /// Read the bytes previously written via
    /// [`Self::write_saf`].
    fn read_saf(&self, uri: &str) -> Result<Vec<u8>, Error>;

    /// Enumerate every SAF document URI starting with `prefix`.
    /// Used by the restore path to discover segment URIs that
    /// were not yet materialised in the manifest.
    fn list_saf(&self, prefix: &str) -> Result<Vec<String>, Error>;

    /// Enumerate every Auto Backup key beginning with `prefix`.
    /// Used by [`AndroidBackupSink::list_backup_manifests`].
    fn list_auto_backup(&self, prefix: &str) -> Result<Vec<String>, Error>;
}

/// `AndroidBackupBridge` placeholder used by tests / phases that
/// have not wired a real `BackupAgent` / SAF resolver yet. Every
/// method returns
/// [`Error::NotImplemented("android_backup_bridge")`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAndroidBackupBridge;

impl AndroidBackupBridge for NoopAndroidBackupBridge {
    fn write_auto_backup(&self, _key: &str, _data: &[u8]) -> Result<(), Error> {
        Err(Error::NotImplemented("android_backup_bridge"))
    }
    fn read_auto_backup(&self, _key: &str) -> Result<Vec<u8>, Error> {
        Err(Error::NotImplemented("android_backup_bridge"))
    }
    fn write_saf(&self, _uri: &str, _data: &[u8]) -> Result<(), Error> {
        Err(Error::NotImplemented("android_backup_bridge"))
    }
    fn read_saf(&self, _uri: &str) -> Result<Vec<u8>, Error> {
        Err(Error::NotImplemented("android_backup_bridge"))
    }
    fn list_saf(&self, _prefix: &str) -> Result<Vec<String>, Error> {
        Err(Error::NotImplemented("android_backup_bridge"))
    }
    fn list_auto_backup(&self, _prefix: &str) -> Result<Vec<String>, Error> {
        Err(Error::NotImplemented("android_backup_bridge"))
    }
}

/// `BackupSink` implementation routing through the Android
/// dual-channel bridge: manifests go through Auto Backup,
/// segments go through SAF.
#[derive(Debug, Clone)]
pub struct AndroidBackupSink {
    bridge: Arc<dyn AndroidBackupBridge>,
}

impl AndroidBackupSink {
    /// Construct a sink delegating every byte-level operation to
    /// the supplied `bridge`.
    pub fn new(bridge: Arc<dyn AndroidBackupBridge>) -> Self {
        Self { bridge }
    }

    /// Storage-sink tag stamped into any tracking table the
    /// orchestrator maintains.
    pub fn sink_tag(&self) -> &'static str {
        ANDROID_BACKUP_SINK_TAG
    }
}

impl BackupSink for AndroidBackupSink {
    fn upload_backup_segment(&self, segment_id: &str, ciphertext: &[u8]) -> crate::Result<()> {
        // Segments are routed through SAF — they are unbounded in
        // size and Auto Backup's 25 MiB cap would refuse them.
        self.bridge.write_saf(&segment_uri(segment_id), ciphertext)
    }

    fn upload_backup_manifest(&self, manifest_id: &str, sealed: &[u8]) -> crate::Result<()> {
        // Manifests are small (CBOR pointer table) and benefit
        // from the no-cost Auto Backup tier.
        self.bridge
            .write_auto_backup(&manifest_key(manifest_id), sealed)
    }

    fn fetch_backup_manifest(&self, manifest_id: &str) -> crate::Result<Vec<u8>> {
        self.bridge.read_auto_backup(&manifest_key(manifest_id))
    }

    fn fetch_backup_segment(&self, segment_id: &str) -> crate::Result<Vec<u8>> {
        self.bridge.read_saf(&segment_uri(segment_id))
    }

    fn list_backup_manifests(&self) -> crate::Result<Vec<String>> {
        // Auto Backup is the canonical manifest store on Android,
        // so list it (not SAF). Strip the `backups/` namespace
        // prefix so the orchestrator gets bare manifest ids.
        let raw = self.bridge.list_auto_backup(MANIFEST_KEY_PREFIX)?;
        let mut out = Vec::with_capacity(raw.len());
        for key in raw {
            if let Some(rest) = key.strip_prefix(MANIFEST_KEY_PREFIX) {
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

    #[derive(Debug, Default)]
    struct InMemoryAndroidBridge {
        auto_backup: Mutex<BTreeMap<String, Vec<u8>>>,
        saf: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl AndroidBackupBridge for InMemoryAndroidBridge {
        fn write_auto_backup(&self, key: &str, data: &[u8]) -> Result<(), Error> {
            self.auto_backup
                .lock()
                .unwrap()
                .insert(key.into(), data.to_vec());
            Ok(())
        }

        fn read_auto_backup(&self, key: &str) -> Result<Vec<u8>, Error> {
            self.auto_backup
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| Error::Storage(format!("no auto-backup key: {key}").into()))
        }

        fn write_saf(&self, uri: &str, data: &[u8]) -> Result<(), Error> {
            self.saf.lock().unwrap().insert(uri.into(), data.to_vec());
            Ok(())
        }

        fn read_saf(&self, uri: &str) -> Result<Vec<u8>, Error> {
            self.saf
                .lock()
                .unwrap()
                .get(uri)
                .cloned()
                .ok_or_else(|| Error::Storage(format!("no SAF uri: {uri}").into()))
        }

        fn list_saf(&self, prefix: &str) -> Result<Vec<String>, Error> {
            Ok(self
                .saf
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }

        fn list_auto_backup(&self, prefix: &str) -> Result<Vec<String>, Error> {
            Ok(self
                .auto_backup
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    #[test]
    fn android_backup_bridge_trait_is_object_safe() {
        let _b: Box<dyn AndroidBackupBridge> = Box::new(NoopAndroidBackupBridge);
        let _a: Arc<dyn AndroidBackupBridge> = Arc::new(NoopAndroidBackupBridge);
    }

    #[test]
    fn noop_bridge_returns_not_implemented_for_every_method() {
        let stub = NoopAndroidBackupBridge;
        let cases: Vec<Result<(), Error>> =
            vec![stub.write_auto_backup("k", b""), stub.write_saf("u", b"")];
        for c in cases {
            assert!(matches!(
                c.unwrap_err(),
                Error::NotImplemented("android_backup_bridge")
            ));
        }
        assert!(matches!(
            stub.read_auto_backup("k").unwrap_err(),
            Error::NotImplemented("android_backup_bridge")
        ));
        assert!(matches!(
            stub.read_saf("u").unwrap_err(),
            Error::NotImplemented("android_backup_bridge")
        ));
        assert!(matches!(
            stub.list_saf("p").unwrap_err(),
            Error::NotImplemented("android_backup_bridge")
        ));
        assert!(matches!(
            stub.list_auto_backup("p").unwrap_err(),
            Error::NotImplemented("android_backup_bridge")
        ));
    }

    #[test]
    fn manifest_round_trip_uses_auto_backup() {
        let bridge = Arc::new(InMemoryAndroidBridge::default());
        let sink = AndroidBackupSink::new(bridge.clone());
        sink.upload_backup_manifest("mfst-1", b"cbor-bytes")
            .expect("upload manifest");
        let bytes = sink.fetch_backup_manifest("mfst-1").expect("fetch");
        assert_eq!(bytes, b"cbor-bytes");

        // The data must land in Auto Backup, NOT SAF.
        assert_eq!(bridge.auto_backup.lock().unwrap().len(), 1);
        assert!(bridge.saf.lock().unwrap().is_empty());
    }

    #[test]
    fn segment_round_trip_uses_saf() {
        let bridge = Arc::new(InMemoryAndroidBridge::default());
        let sink = AndroidBackupSink::new(bridge.clone());
        sink.upload_backup_segment("seg-A", b"sealed-bytes")
            .expect("upload segment");
        let bytes = sink.fetch_backup_segment("seg-A").expect("fetch");
        assert_eq!(bytes, b"sealed-bytes");

        // Segments must land in SAF, NOT Auto Backup.
        assert!(bridge.auto_backup.lock().unwrap().is_empty());
        assert_eq!(bridge.saf.lock().unwrap().len(), 1);
    }

    #[test]
    fn list_backup_manifests_filters_segment_keys() {
        let bridge = Arc::new(InMemoryAndroidBridge::default());
        let sink = AndroidBackupSink::new(bridge);
        sink.upload_backup_manifest("mfst-A", b"a").unwrap();
        sink.upload_backup_manifest("mfst-B", b"b").unwrap();
        sink.upload_backup_segment("seg-1", b"s1").unwrap();
        let mut listed = sink.list_backup_manifests().unwrap();
        listed.sort();
        assert_eq!(listed, vec!["mfst-A".to_string(), "mfst-B".to_string()]);
    }

    #[test]
    fn fetch_missing_manifest_surfaces_storage_error() {
        let bridge = Arc::new(InMemoryAndroidBridge::default());
        let sink = AndroidBackupSink::new(bridge);
        let err = sink.fetch_backup_manifest("missing").unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn fetch_missing_segment_surfaces_storage_error() {
        let bridge = Arc::new(InMemoryAndroidBridge::default());
        let sink = AndroidBackupSink::new(bridge);
        let err = sink.fetch_backup_segment("missing").unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn noop_bridge_round_trip_through_sink_surfaces_not_implemented() {
        let sink = AndroidBackupSink::new(Arc::new(NoopAndroidBackupBridge));
        assert!(matches!(
            sink.upload_backup_segment("s", b""),
            Err(Error::NotImplemented("android_backup_bridge"))
        ));
        assert!(matches!(
            sink.fetch_backup_manifest("m"),
            Err(Error::NotImplemented("android_backup_bridge"))
        ));
        assert!(matches!(
            sink.list_backup_manifests(),
            Err(Error::NotImplemented("android_backup_bridge"))
        ));
    }
}
