//! In-memory [`crate::backup::sinks::BackupSink`] for tests.
//!
//! Gated behind the crate-internal `test-support` feature
//! (always available under `cfg(test)`). The sink stores
//! uploaded manifest / segment ciphertext in two `BTreeMap`s
//! keyed by stable id; `fetch_*` reads them back verbatim.
//! `list_backup_manifests` returns the manifest keys in sorted
//! order so tests get deterministic iteration.
//!
//! The sink is not transport — it makes no assumptions about
//! the wire format. Callers who push bytes through
//! [`Self::upload_backup_manifest`] or
//! [`Self::upload_backup_segment`] read the same bytes back via
//! the symmetric `fetch_*` methods. That contract is what makes
//! it useful for end-to-end restore tests: the segment + manifest
//! builders produce sealed bytes; this sink ferries them across
//! the trait boundary without re-encoding.
//!
//! The sink is intentionally synchronous and thread-safe via
//! `Mutex<BTreeMap<…>>`. It is not a load test target — its
//! storage is unbounded, and concurrent uploads serialise on the
//! mutex.
//!
//! Module gating lives on the `pub mod memory` declaration in
//! [`super::mod`] — there is no inner `#![cfg]` here because that
//! would be belt-and-suspenders relative to the outer gate (the
//! compiler never loads this file in non-test builds).

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::BackupSink;
use crate::{Error, Result};

/// In-memory sink that keeps manifest / segment ciphertext in
/// `BTreeMap`s. See module docs for the contract.
#[derive(Debug, Default)]
pub struct MemoryBackupSink {
    /// `manifest_id` → sealed bytes. Sorted iteration order via
    /// `BTreeMap` so tests do not rely on hash randomness.
    manifests: Mutex<BTreeMap<String, Vec<u8>>>,
    /// `segment_id` → sealed bytes.
    segments: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryBackupSink {
    /// Construct an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of manifests currently stored.
    pub fn manifest_count(&self) -> usize {
        self.manifests.lock().expect("manifests poisoned").len()
    }

    /// Number of segments currently stored.
    pub fn segment_count(&self) -> usize {
        self.segments.lock().expect("segments poisoned").len()
    }

    /// Snapshot the manifest store. Returns owned pairs so callers
    /// can iterate without holding the lock.
    pub fn snapshot_manifests(&self) -> Vec<(String, Vec<u8>)> {
        self.manifests
            .lock()
            .expect("manifests poisoned")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Snapshot the segment store.
    pub fn snapshot_segments(&self) -> Vec<(String, Vec<u8>)> {
        self.segments
            .lock()
            .expect("segments poisoned")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl BackupSink for MemoryBackupSink {
    fn upload_backup_segment(&self, segment_id: &str, ciphertext: &[u8]) -> Result<()> {
        self.segments
            .lock()
            .expect("segments poisoned")
            .insert(segment_id.to_string(), ciphertext.to_vec());
        Ok(())
    }

    fn upload_backup_manifest(&self, manifest_id: &str, sealed: &[u8]) -> Result<()> {
        self.manifests
            .lock()
            .expect("manifests poisoned")
            .insert(manifest_id.to_string(), sealed.to_vec());
        Ok(())
    }

    fn fetch_backup_manifest(&self, manifest_id: &str) -> Result<Vec<u8>> {
        self.manifests
            .lock()
            .expect("manifests poisoned")
            .get(manifest_id)
            .cloned()
            .ok_or_else(|| {
                Error::Storage(format!("memory sink: manifest {manifest_id:?} not found").into())
            })
    }

    fn fetch_backup_segment(&self, segment_id: &str) -> Result<Vec<u8>> {
        self.segments
            .lock()
            .expect("segments poisoned")
            .get(segment_id)
            .cloned()
            .ok_or_else(|| {
                Error::Storage(format!("memory sink: segment {segment_id:?} not found").into())
            })
    }

    fn list_backup_manifests(&self) -> Result<Vec<String>> {
        Ok(self
            .manifests
            .lock()
            .expect("manifests poisoned")
            .keys()
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_then_fetch_round_trips() {
        let sink = MemoryBackupSink::new();
        sink.upload_backup_manifest("m1", b"manifest-bytes")
            .unwrap();
        sink.upload_backup_segment("s1", b"segment-bytes").unwrap();
        assert_eq!(sink.fetch_backup_manifest("m1").unwrap(), b"manifest-bytes");
        assert_eq!(sink.fetch_backup_segment("s1").unwrap(), b"segment-bytes");
    }

    #[test]
    fn fetch_missing_returns_storage_error() {
        let sink = MemoryBackupSink::new();
        let err = sink.fetch_backup_manifest("absent").unwrap_err();
        assert!(matches!(err, Error::Storage(_)));
    }

    #[test]
    fn list_returns_sorted_manifest_ids() {
        let sink = MemoryBackupSink::new();
        sink.upload_backup_manifest("c", b"x").unwrap();
        sink.upload_backup_manifest("a", b"y").unwrap();
        sink.upload_backup_manifest("b", b"z").unwrap();
        assert_eq!(
            sink.list_backup_manifests().unwrap(),
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        );
    }
}
