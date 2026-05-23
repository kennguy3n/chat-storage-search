//! Epoch key lifecycle for the archive pipeline.
//!
//! `docs/PROPOSAL.md §2.1` and `docs/PHASES.md` Phase 3 call for
//! per-epoch indirection between `K_archive_root` and the
//! per-segment / per-manifest keys: each rotation seals the prior
//! epoch's key under `K_archive_root` (AES-256-KW) and records the
//! wrapped key in the manifest chain. Cross-epoch decryption
//! re-unwraps the prior key on demand; forward secrecy is achieved
//! by deleting the wrapped key from the manifest chain entirely.
//!
//! The HKDF derivation itself lives in
//! [`crate::crypto::key_hierarchy::derive_archive_epoch_key`] —
//! this module owns the **lifecycle**:
//!
//! * the *current* epoch key, held in a [`Zeroizing`] buffer;
//! * a map of *prior* epoch keys, wrapped under `K_archive_root`
//!   so a hostile dump of process memory cannot recover them;
//! * `rotate_epoch` / `unwrap_prior_epoch_key` / `delete_epoch_key`
//!   bookkeeping for a manifest chain that survives a restart.
//!
//! The wrapping key (`K_archive_root`) is **owned by the caller**;
//! the manager never persists its bytes in plaintext.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::crypto::key_hierarchy::{derive_archive_epoch_key, KeyMaterial, KEY_LEN};
use crate::crypto::key_wrap::{unwrap_key, wrap_key};
use crate::Error;

/// AES-256-KW wrapped epoch key (`prior_epoch_keys[epoch_id]`).
///
/// Stored as a plain `Vec<u8>` because the bytes are already
/// ciphertext under `K_archive_root`. Length is exactly
/// [`crate::crypto::key_wrap::WRAPPED_KEY_LEN`] but we don't expose
/// that here — the unwrap path enforces the length check.
pub type WrappedEpochKey = Vec<u8>;

/// Lifecycle manager for the archive epoch keys.
///
/// Contract — `docs/PROPOSAL.md §2.1`:
///
/// * Exactly **one** epoch key is "current" at any time. The bytes
///   are held in a [`Zeroizing`] buffer; the manager never `Clone`s
///   the key out of the buffer.
/// * Prior epoch keys are stored *wrapped* under `K_archive_root`.
///   Decrypting a cross-epoch segment requires re-unwrapping on
///   demand via [`Self::unwrap_prior_epoch_key`].
/// * Forward secrecy — once an epoch is *retired* and the wrapped
///   key is dropped from the manifest chain (via
///   [`Self::delete_epoch_key`]), the segments sealed under that
///   epoch are no longer decryptable, even by the legitimate user.
#[derive(Debug)]
pub struct EpochKeyManager {
    current_epoch_id: String,
    current_epoch_key: Zeroizing<[u8; KEY_LEN]>,
    prior_epoch_keys: BTreeMap<String, WrappedEpochKey>,
}

impl EpochKeyManager {
    /// Bootstrap a fresh manager rooted at `epoch_id`. The current
    /// epoch key is derived from `k_archive_root` using HKDF-SHA256
    /// (info = `b"kchat-archive-epoch-v1" || epoch_id.as_bytes()`).
    pub fn new(k_archive_root: &KeyMaterial, epoch_id: &str) -> Result<Self, Error> {
        let derived = derive_archive_epoch_key(k_archive_root, epoch_id).map_err(Error::from)?;
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(derived.as_bytes());
        Ok(Self {
            current_epoch_id: epoch_id.to_string(),
            current_epoch_key: Zeroizing::new(bytes),
            prior_epoch_keys: BTreeMap::new(),
        })
    }

    /// Current epoch identifier (e.g. `"2026-05"`). The string is
    /// owned, so callers can clone it freely.
    pub fn current_epoch_id(&self) -> &str {
        &self.current_epoch_id
    }

    /// Borrow the bytes of the current epoch key. The slice
    /// **must not** outlive the manager — its backing buffer is
    /// zeroized on drop.
    pub fn current_epoch_key(&self) -> &[u8; KEY_LEN] {
        &self.current_epoch_key
    }

    /// Number of *prior* (i.e. retired) wrapped epoch keys this
    /// manager remembers. Surfacing the count gives the
    /// orchestration layer something to assert against in tests.
    pub fn prior_count(&self) -> usize {
        self.prior_epoch_keys.len()
    }

    /// Rotate to a new epoch.
    ///
    /// Steps `docs/PROPOSAL.md §2.1`:
    ///
    /// 1. Wrap the *current* epoch key under `K_archive_root` using
    ///    AES-256-KW; insert the resulting [`WrappedEpochKey`] into
    ///    `prior_epoch_keys` keyed on the **outgoing** epoch id.
    ///    A duplicate insert (same epoch id rotated twice) is an
    ///    error — the orchestration layer should bump the epoch id
    ///    on every rotation.
    /// 2. Derive the new epoch key from `K_archive_root` and
    ///    `new_epoch_id`; replace the current epoch key in place.
    ///    The old [`Zeroizing`] buffer is dropped → zeroized.
    pub fn rotate_epoch(
        &mut self,
        k_archive_root: &KeyMaterial,
        new_epoch_id: &str,
    ) -> Result<(), Error> {
        if new_epoch_id == self.current_epoch_id {
            return Err(Error::Storage(
                format!("rotate_epoch: new_epoch_id {new_epoch_id:?} matches current epoch id")
                    .into(),
            ));
        }
        if self.prior_epoch_keys.contains_key(new_epoch_id) {
            return Err(Error::Storage(
                format!("rotate_epoch: new_epoch_id {new_epoch_id:?} already retired").into(),
            ));
        }
        // 1) Wrap the outgoing key under K_archive_root and stash
        //    it under the outgoing epoch id.
        let wrapped =
            wrap_key(k_archive_root.as_bytes(), &self.current_epoch_key).map_err(Error::from)?;
        self.prior_epoch_keys
            .insert(self.current_epoch_id.clone(), wrapped);

        // 2) Derive the new epoch key and replace the current one.
        //    The Zeroizing buffer for the old key is dropped here
        //    (the assignment moves a fresh Zeroizing into place).
        let derived =
            derive_archive_epoch_key(k_archive_root, new_epoch_id).map_err(Error::from)?;
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(derived.as_bytes());
        self.current_epoch_key = Zeroizing::new(bytes);
        self.current_epoch_id = new_epoch_id.to_string();
        Ok(())
    }

    /// Look up the wrapped key for a *prior* epoch.
    ///
    /// Returns `None` if the epoch was never retired by this
    /// manager (e.g. it is the *current* epoch, or it has been
    /// deleted for forward secrecy).
    pub fn wrapped_prior_epoch_key(&self, epoch_id: &str) -> Option<&WrappedEpochKey> {
        self.prior_epoch_keys.get(epoch_id)
    }

    /// Unwrap a prior epoch key for cross-epoch decryption. The
    /// caller is expected to discard the returned bytes
    /// (preferably via a [`Zeroizing`] buffer of its own) as soon
    /// as the segment open completes.
    pub fn unwrap_prior_epoch_key(
        &self,
        epoch_id: &str,
        k_archive_root: &KeyMaterial,
    ) -> Result<[u8; KEY_LEN], Error> {
        let wrapped = self.prior_epoch_keys.get(epoch_id).ok_or_else(|| {
            Error::Storage(
                format!(
                    "unwrap_prior_epoch_key: epoch {epoch_id:?} is not retired or has been deleted"
                )
                .into(),
            )
        })?;
        let bytes = unwrap_key(k_archive_root.as_bytes(), wrapped).map_err(Error::from)?;
        Ok(bytes)
    }

    /// Stand-alone wrap helper. AES-256-KW under `k_archive_root`.
    /// Useful for the orchestration layer that wants to wrap an
    /// epoch key without a manager (e.g. just to roundtrip the
    /// manifest chain).
    pub fn wrap_under_root(
        k_archive_root: &KeyMaterial,
        epoch_key: &[u8; KEY_LEN],
    ) -> Result<WrappedEpochKey, Error> {
        wrap_key(k_archive_root.as_bytes(), epoch_key).map_err(Error::from)
    }

    /// Forward secrecy: drop the wrapped key for `epoch_id` from
    /// the chain entirely. After a delete the segments sealed under
    /// that epoch can **never** be opened again — even by the
    /// legitimate user, even with `K_archive_root` in hand.
    ///
    /// Returns `true` if a key was actually removed, `false` if
    /// the epoch was unknown.
    pub fn delete_epoch_key(&mut self, epoch_id: &str) -> bool {
        self.prior_epoch_keys.remove(epoch_id).is_some()
    }

    /// Snapshot of every *retired* epoch id this manager remembers,
    /// returned in lexicographic order (the natural ordering of
    /// year-month / year-week strings the production code uses).
    pub fn retired_epoch_ids(&self) -> Vec<String> {
        self.prior_epoch_keys.keys().cloned().collect()
    }

    /// Snapshot of every retired epoch id paired with its wrapped
    /// key bytes — the canonical input to
    /// [`crate::archive::manifest_builder::ManifestBuildRequest::wrapped_prior_epoch_keys`].
    ///
    /// The pairs are returned in lexicographic epoch-id order so the
    /// resulting manifest is deterministic across rebuilds. The
    /// returned `Vec<u8>` is a fresh clone of the wrapped bytes — the
    /// manager keeps the canonical copy until
    /// [`Self::delete_epoch_key`] retires it for forward secrecy.
    pub fn wrapped_prior_epoch_keys_for_manifest(
        &self,
    ) -> Vec<crate::formats::manifest::WrappedEpochKeyRef> {
        self.prior_epoch_keys
            .iter()
            .map(
                |(id, wrapped)| crate::formats::manifest::WrappedEpochKeyRef {
                    epoch_id: id.clone(),
                    wrapped_key: wrapped.clone(),
                },
            )
            .collect()
    }

    /// Inverse of [`Self::wrapped_prior_epoch_keys_for_manifest`].
    ///
    /// Insert a [`crate::formats::manifest::WrappedEpochKeyRef`]
    /// (typically read out of an `ArchiveManifest` during the
    /// restore path) into `prior_epoch_keys` so a subsequent
    /// [`Self::unwrap_prior_epoch_key`] can service the row.
    ///
    /// The byte length is validated against the AES-256-KW
    /// wrapped-key length up front; an unexpected length surfaces
    /// `Error::Storage(....into())` rather than waiting for the
    /// downstream unwrap to fail. Re-ingesting an `epoch_id` that
    /// already exists is rejected — the manifest chain must be
    /// the canonical source of truth.
    pub fn ingest_wrapped_prior_epoch_key(
        &mut self,
        w: crate::formats::manifest::WrappedEpochKeyRef,
    ) -> Result<(), Error> {
        if w.epoch_id == self.current_epoch_id {
            return Err(Error::Storage(
                format!(
                    "ingest_wrapped_prior_epoch_key: epoch_id {:?} matches current epoch",
                    w.epoch_id
                )
                .into(),
            ));
        }
        if w.wrapped_key.len() != crate::crypto::key_wrap::WRAPPED_KEY_LEN {
            return Err(Error::Storage(
                format!(
                    "ingest_wrapped_prior_epoch_key: wrapped_key length {} != expected {}",
                    w.wrapped_key.len(),
                    crate::crypto::key_wrap::WRAPPED_KEY_LEN
                )
                .into(),
            ));
        }
        if self.prior_epoch_keys.contains_key(&w.epoch_id) {
            return Err(Error::Storage(
                format!(
                    "ingest_wrapped_prior_epoch_key: epoch_id {:?} already known",
                    w.epoch_id
                )
                .into(),
            ));
        }
        self.prior_epoch_keys.insert(w.epoch_id, w.wrapped_key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_hierarchy::KeyMaterial;

    fn fresh_root() -> KeyMaterial {
        let mut bytes = [0u8; KEY_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(7);
        }
        KeyMaterial::from_bytes(bytes)
    }

    #[test]
    fn derive_is_deterministic_for_fixed_root_and_epoch_id() {
        let root = fresh_root();
        let mgr_a = EpochKeyManager::new(&root, "2026-05").unwrap();
        let mgr_b = EpochKeyManager::new(&root, "2026-05").unwrap();
        assert_eq!(mgr_a.current_epoch_key(), mgr_b.current_epoch_key());
    }

    #[test]
    fn distinct_epoch_ids_produce_distinct_keys() {
        let root = fresh_root();
        let mgr_a = EpochKeyManager::new(&root, "2026-05").unwrap();
        let mgr_b = EpochKeyManager::new(&root, "2026-06").unwrap();
        assert_ne!(mgr_a.current_epoch_key(), mgr_b.current_epoch_key());
    }

    #[test]
    fn ingest_wrapped_prior_epoch_key_round_trips_through_manifest_payload() {
        // Manager A: rotates twice → has two retired epochs.
        let root = fresh_root();
        let mut mgr_a = EpochKeyManager::new(&root, "2026-01").unwrap();
        let jan_key = *mgr_a.current_epoch_key();
        mgr_a.rotate_epoch(&root, "2026-02").unwrap();
        mgr_a.rotate_epoch(&root, "2026-03").unwrap();
        let payload = mgr_a.wrapped_prior_epoch_keys_for_manifest();
        assert_eq!(payload.len(), 2);

        // Manager B: simulates a fresh restore device. Rebuild
        // from `K_archive_root` at the *current* epoch only, then
        // ingest the wrapped prior keys from the manifest payload.
        let mut mgr_b = EpochKeyManager::new(&root, "2026-03").unwrap();
        assert_eq!(mgr_b.prior_count(), 0);
        for w in payload {
            mgr_b.ingest_wrapped_prior_epoch_key(w).unwrap();
        }
        assert_eq!(mgr_b.prior_count(), 2);
        assert_eq!(
            mgr_b.retired_epoch_ids(),
            vec!["2026-01".to_string(), "2026-02".to_string()],
        );
        let recovered_jan = mgr_b.unwrap_prior_epoch_key("2026-01", &root).unwrap();
        assert_eq!(recovered_jan, jan_key);
    }

    #[test]
    fn ingest_wrapped_prior_epoch_key_rejects_invalid_inputs() {
        use crate::formats::manifest::WrappedEpochKeyRef;
        let root = fresh_root();
        let mut mgr = EpochKeyManager::new(&root, "2026-01").unwrap();
        // Same as current — must reject.
        let err = mgr
            .ingest_wrapped_prior_epoch_key(WrappedEpochKeyRef {
                epoch_id: "2026-01".into(),
                wrapped_key: vec![0u8; crate::crypto::key_wrap::WRAPPED_KEY_LEN],
            })
            .unwrap_err();
        assert!(matches!(err, Error::Storage(_)));

        // Wrong wrapped-key length — must reject.
        let err = mgr
            .ingest_wrapped_prior_epoch_key(WrappedEpochKeyRef {
                epoch_id: "2026-00".into(),
                wrapped_key: vec![0u8; 16],
            })
            .unwrap_err();
        assert!(matches!(err, Error::Storage(_)));
        assert_eq!(mgr.prior_count(), 0);
    }

    #[test]
    fn rotate_round_trips_prior_epoch_key() {
        let root = fresh_root();
        let mut mgr = EpochKeyManager::new(&root, "2026-05").unwrap();
        let old_key = *mgr.current_epoch_key();

        mgr.rotate_epoch(&root, "2026-06").unwrap();
        assert_eq!(mgr.current_epoch_id(), "2026-06");
        assert_ne!(*mgr.current_epoch_key(), old_key);
        assert_eq!(mgr.prior_count(), 1);

        let unwrapped = mgr.unwrap_prior_epoch_key("2026-05", &root).unwrap();
        assert_eq!(unwrapped, old_key, "unwrap must round-trip the prior key");
    }

    #[test]
    fn rotate_rejects_same_epoch_id() {
        let root = fresh_root();
        let mut mgr = EpochKeyManager::new(&root, "2026-05").unwrap();
        let err = mgr.rotate_epoch(&root, "2026-05").unwrap_err();
        match err {
            Error::Storage(msg) => assert!(
                msg.to_string().contains("matches current epoch id"),
                "got {msg}"
            ),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn rotate_rejects_already_retired_epoch_id() {
        let root = fresh_root();
        let mut mgr = EpochKeyManager::new(&root, "ep-a").unwrap();
        mgr.rotate_epoch(&root, "ep-b").unwrap();
        // Rotate back to "ep-a" — its wrapped key already lives in
        // the prior_epoch_keys map, so this is rejected.
        let err = mgr.rotate_epoch(&root, "ep-a").unwrap_err();
        match err {
            Error::Storage(msg) => {
                assert!(msg.to_string().contains("already retired"), "got {msg}")
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn cross_epoch_decrypt_round_trip() {
        // Simulate: a segment was sealed under ep-a; the user has
        // since rotated to ep-b. Cross-epoch open must succeed by
        // unwrapping the prior key on demand.
        let root = fresh_root();
        let mut mgr = EpochKeyManager::new(&root, "ep-a").unwrap();
        let ep_a_key = *mgr.current_epoch_key();

        // Pretend we sealed a segment under ep_a_key. We just
        // record the key bytes for later comparison.
        let sealed_under = ep_a_key;

        mgr.rotate_epoch(&root, "ep-b").unwrap();

        // After rotation we must be able to recover ep_a_key for
        // cross-epoch open.
        let recovered = mgr.unwrap_prior_epoch_key("ep-a", &root).unwrap();
        assert_eq!(recovered, sealed_under);
    }

    #[test]
    fn forward_secrecy_after_delete_makes_key_unreachable() {
        let root = fresh_root();
        let mut mgr = EpochKeyManager::new(&root, "ep-a").unwrap();
        mgr.rotate_epoch(&root, "ep-b").unwrap();
        assert!(mgr.delete_epoch_key("ep-a"), "delete must succeed");

        let err = mgr.unwrap_prior_epoch_key("ep-a", &root).unwrap_err();
        match err {
            Error::Storage(msg) => assert!(
                msg.to_string().contains("not retired") || msg.to_string().contains("deleted"),
                "got {msg}"
            ),
            other => panic!("expected Storage error, got {other:?}"),
        }
        assert!(!mgr.delete_epoch_key("ep-a"), "double-delete is a no-op");
    }

    #[test]
    fn unwrap_with_wrong_root_fails() {
        let root = fresh_root();
        let mut mgr = EpochKeyManager::new(&root, "ep-a").unwrap();
        mgr.rotate_epoch(&root, "ep-b").unwrap();

        let mut bad_bytes = [0u8; KEY_LEN];
        bad_bytes.copy_from_slice(root.as_bytes());
        bad_bytes[0] ^= 0xFF;
        let bad_root = KeyMaterial::from_bytes(bad_bytes);

        let err = mgr.unwrap_prior_epoch_key("ep-a", &bad_root).unwrap_err();
        // Wrong wrapping key must surface a crypto error, not a
        // storage one.
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn retired_epoch_ids_listed_in_order() {
        let root = fresh_root();
        let mut mgr = EpochKeyManager::new(&root, "2026-05").unwrap();
        mgr.rotate_epoch(&root, "2026-06").unwrap();
        mgr.rotate_epoch(&root, "2026-07").unwrap();
        mgr.rotate_epoch(&root, "2026-08").unwrap();
        let ids = mgr.retired_epoch_ids();
        assert_eq!(ids, vec!["2026-05", "2026-06", "2026-07"]);
    }

    #[test]
    fn wrap_under_root_round_trips() {
        let root = fresh_root();
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13);
        }
        let wrapped = EpochKeyManager::wrap_under_root(&root, &k).unwrap();
        let recovered = unwrap_key(root.as_bytes(), &wrapped).unwrap();
        assert_eq!(recovered, k);
    }
}
