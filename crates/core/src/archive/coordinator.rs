//! Phase B.9 archive coordinator — owns the per-`CoreImpl`
//! epoch-key state and ZKOF backend wiring that previously lived
//! directly on `CoreImpl` as `current_epoch` and `zkof_archive`
//! fields.
//!
//! Scope:
//! * `EpochKeyManager` (envelope encryption + rotation) lifecycle
//!   — install / has / current id / borrow current key / rotate /
//!   recover prior / delete prior / wrapped-prior-keys snapshot.
//! * ZKOF archive backend (S3 client + gateway config) install +
//!   `has` + builder for the per-call `ArchiveSegmentRouter`.
//!
//! `CoreImpl` delegates each of the corresponding trait surface
//! methods to this struct. There is no state held jointly with any
//! other coordinator — archive rotation is independent of backup,
//! search, and media domains — so the coordinator is owned
//! by-value on `CoreImpl` (no `Arc`/cloning overhead). The
//! `Mutex<Option<_>>` slots are intentionally re-installable
//! (epoch managers rotate; backend credentials rotate on key /
//! cred refresh) so they stay under `Mutex<Option>` rather than
//! `OnceLock` (see Phase B.2 `CoreImpl` rustdoc).

use std::sync::Mutex;

use crate::archive::epoch_keys::EpochKeyManager;
use crate::config::ArchiveBackend;
use crate::core_impl::poisoned;
use crate::crypto::key_hierarchy::{KeyMaterial, KEY_LEN};
use crate::formats::manifest::WrappedEpochKeyRef;
use crate::local_store::StorageError;
use crate::transport::TransportClient;
use crate::{Error, Result};

/// Phase-3 ZKOF archive backend (S3 client + gateway config).
/// Bundled into a single struct so install is atomic — `s3` and
/// `config` must always be installed together (Phase B.2 atomic
/// bundle, kept under `Mutex<Option>` because operators rotate
/// the bucket credentials / gateway URL without spinning up a
/// new core).
#[derive(Clone)]
pub(crate) struct ZkofArchiveBackend {
    pub(crate) s3: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client>,
    pub(crate) config: crate::media::sinks::zk_fabric::ZkFabricSinkConfig,
}

/// Owns archive-related state extracted from `CoreImpl` in Phase
/// B.9. See module docs for the surface boundary.
pub(crate) struct Coordinator {
    /// Active epoch-key manager (`archive::epoch_keys`). The
    /// manager carries the `prior_epoch_keys` map that mutates on
    /// every rotation, so it stays in `Mutex<Option>` rather than
    /// `OnceLock`.
    current_epoch: Mutex<Option<EpochKeyManager>>,
    /// Phase-3 ZKOF archive backend (S3 client + gateway config).
    /// `Mutex<Option>` for credential rotation.
    zkof_archive: Mutex<Option<ZkofArchiveBackend>>,
    /// Snapshot of `KChatCoreConfig::archive_backend` (immutable
    /// for the lifetime of a `CoreImpl`). Drives the branching in
    /// [`Self::build_router`].
    archive_backend: ArchiveBackend,
}

impl Coordinator {
    /// Build a fresh coordinator with no epoch manager / ZKOF
    /// backend installed. Both slots stay empty until the
    /// platform glue calls the corresponding installer.
    pub(crate) fn new(archive_backend: ArchiveBackend) -> Self {
        Self {
            current_epoch: Mutex::new(None),
            zkof_archive: Mutex::new(None),
            archive_backend,
        }
    }

    // ----------------------------------------------------------------
    // Phase 4 (`docs/PROPOSAL.md §6.3`) — epoch key manager lifecycle.
    // ----------------------------------------------------------------

    /// Bootstrap a fresh [`EpochKeyManager`] for the supplied
    /// `K_archive_root` and `epoch_id` and install it as the
    /// active manager. Replaces any previously installed manager.
    pub(crate) fn install_epoch_key_manager(
        &self,
        k_archive_root: &KeyMaterial,
        epoch_id: &str,
    ) -> Result<()> {
        let manager = EpochKeyManager::new(k_archive_root, epoch_id)?;
        let mut slot = self.current_epoch.lock().map_err(poisoned)?;
        *slot = Some(manager);
        Ok(())
    }

    /// Whether an epoch key manager is currently installed.
    pub(crate) fn has_epoch_key_manager(&self) -> bool {
        let slot = self
            .current_epoch
            .lock()
            .expect("current_epoch mutex poisoned");
        slot.is_some()
    }

    /// Snapshot of the currently active epoch identifier (if any).
    pub(crate) fn current_epoch_id(&self) -> Result<Option<String>> {
        let slot = self.current_epoch.lock().map_err(poisoned)?;
        Ok(slot.as_ref().map(|m| m.current_epoch_id().to_string()))
    }

    /// Borrow the bytes of the current epoch key into the supplied
    /// closure. The closure runs with the [`EpochKeyManager`]
    /// mutex held — keep its body short and side-effect free, and
    /// **never** hand the byte slice out of the closure.
    ///
    /// Returns `Error::Storage` when no manager is installed.
    pub(crate) fn with_current_epoch_key<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&[u8; KEY_LEN]) -> T,
    {
        let slot = self.current_epoch.lock().map_err(poisoned)?;
        let mgr = slot
            .as_ref()
            .ok_or_else(|| Error::Storage("no epoch key manager installed".into()))?;
        Ok(f(mgr.current_epoch_key()))
    }

    /// Rotate the active epoch under `K_archive_root`, retiring
    /// the outgoing epoch key by AES-256-KW wrapping it under
    /// `K_archive_root` and returning the wrapped bytes paired
    /// with the outgoing epoch id.
    pub(crate) fn rotate_archive_epoch(
        &self,
        k_archive_root: &KeyMaterial,
        new_epoch_id: &str,
    ) -> Result<WrappedEpochKeyRef> {
        let mut slot = self.current_epoch.lock().map_err(poisoned)?;
        let mgr = slot
            .as_mut()
            .ok_or_else(|| Error::Storage("no epoch key manager installed".into()))?;
        let outgoing_id = mgr.current_epoch_id().to_string();
        mgr.rotate_epoch(k_archive_root, new_epoch_id)?;
        let wrapped = mgr
            .wrapped_prior_epoch_key(&outgoing_id)
            .cloned()
            .ok_or_else(|| {
                Error::Storage("rotate_archive_epoch: outgoing key not retired".into())
            })?;
        Ok(WrappedEpochKeyRef {
            epoch_id: outgoing_id,
            wrapped_key: wrapped,
        })
    }

    /// Recover a prior-epoch key from its wrapped manifest entry.
    /// Returned bytes belong to the caller and should be wrapped
    /// in a `Zeroizing` buffer at the call site.
    pub(crate) fn recover_epoch_key(
        &self,
        epoch_id: &str,
        k_archive_root: &KeyMaterial,
    ) -> Result<[u8; KEY_LEN]> {
        let slot = self.current_epoch.lock().map_err(poisoned)?;
        let mgr = slot
            .as_ref()
            .ok_or_else(|| Error::Storage("no epoch key manager installed".into()))?;
        mgr.unwrap_prior_epoch_key(epoch_id, k_archive_root)
    }

    /// Forward-secrecy delete of a retired epoch key. Returns
    /// `true` if a key was actually removed from the manager.
    pub(crate) fn delete_archive_epoch_key(&self, epoch_id: &str) -> Result<bool> {
        let mut slot = self.current_epoch.lock().map_err(poisoned)?;
        let mgr = slot
            .as_mut()
            .ok_or_else(|| Error::Storage("no epoch key manager installed".into()))?;
        Ok(mgr.delete_epoch_key(epoch_id))
    }

    /// Snapshot of every retired epoch's wrapped key, ready to
    /// drop into the next manifest's
    /// [`crate::archive::manifest_builder::ManifestBuildRequest::wrapped_prior_epoch_keys`].
    pub(crate) fn wrapped_prior_epoch_keys_for_manifest(&self) -> Result<Vec<WrappedEpochKeyRef>> {
        let slot = self.current_epoch.lock().map_err(poisoned)?;
        let mgr = slot
            .as_ref()
            .ok_or_else(|| Error::Storage("no epoch key manager installed".into()))?;
        Ok(mgr.wrapped_prior_epoch_keys_for_manifest())
    }

    // ----------------------------------------------------------------
    // Phase 3 — ZKOF archive backend lifecycle + router builder.
    // ----------------------------------------------------------------

    /// Install the Phase-3 ZKOF archive backend (S3 client +
    /// gateway config). Required before
    /// `CoreImpl::rehydrate_timeline_skeletons` can route any
    /// `storage_backend = zk_object_fabric` rows.
    pub(crate) fn install_zkof_archive_backend(
        &self,
        s3: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client>,
        config: crate::media::sinks::zk_fabric::ZkFabricSinkConfig,
    ) -> Result<()> {
        config.validate()?;
        *self.zkof_archive.lock().map_err(poisoned)? = Some(ZkofArchiveBackend { s3, config });
        Ok(())
    }

    /// Whether [`Self::install_zkof_archive_backend`] has been
    /// called with a real backend.
    pub(crate) fn has_zkof_archive_backend(&self) -> bool {
        self.zkof_archive
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Build an [`crate::archive::download::ArchiveSegmentRouter`]
    /// for `transport`, folding in the installed ZKOF backend when
    /// the configured archive backend is
    /// [`ArchiveBackend::Zkof`]. Returns
    /// `Error::Storage(SubsystemNotInstalled("zkof_archive_backend"))`
    /// when ZKOF is configured but the backend wasn't installed —
    /// the typed variant lets platform glue distinguish "never
    /// installed" from "wrong backend" without parsing message
    /// text.
    pub(crate) fn build_router<'a>(
        &self,
        transport: &'a dyn TransportClient,
    ) -> Result<crate::archive::download::ArchiveSegmentRouter<'a>> {
        match self.archive_backend {
            ArchiveBackend::Zkof => {
                let backend = self
                    .zkof_archive
                    .lock()
                    .map_err(poisoned)?
                    .as_ref()
                    .cloned();
                match backend {
                    Some(ZkofArchiveBackend { s3, config }) => {
                        Ok(crate::archive::download::ArchiveSegmentRouter::with_zkof(
                            transport, s3, config,
                        ))
                    }
                    None => Err(Error::Storage(StorageError::SubsystemNotInstalled(
                        "zkof_archive_backend",
                    ))),
                }
            }
            ArchiveBackend::KChat => Ok(
                crate::archive::download::ArchiveSegmentRouter::kchat_only(transport),
            ),
        }
    }
}
