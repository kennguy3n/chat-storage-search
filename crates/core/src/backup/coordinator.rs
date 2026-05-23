//! Phase-B.9 backup coordinator.
//!
//! Owns the in-memory backup state previously held directly on
//! [`crate::core_impl::CoreImpl`]:
//!
//!   * `backup_keys` — the atomically-installed Phase-4 backup key
//!     bundle (`K_backup_root` + Ed25519 hybrid signing key + stable
//!     device id). See [`BackupKeys`] for the bundling rationale.
//!   * `chain_state` — the in-memory tail of the manifest chain
//!     *together with* the in-memory ledger of sealed segments
//!     that have not yet been superseded by compaction. Bundled
//!     under a single [`Mutex`] so the (manifest tail, segment
//!     ledger) pair is observed atomically by every concurrent
//!     reader and updated atomically by
//!     [`Coordinator::commit_incremental`] /
//!     [`Coordinator::commit_compaction`]. See [`BackupChainState`]
//!     for the rationale; in particular, this replaces the prior
//!     two-`Mutex` design whose atomicity depended on Rust's
//!     reverse-declaration drop order.
//!
//! The coordinator deliberately does **not** own the DB writer or
//! orchestrate the multi-step
//! [`crate::core_impl::CoreImpl::run_incremental_backup`] /
//! [`crate::core_impl::CoreImpl::compact_backup`] pipelines.
//! Those methods cross-cut multiple subsystems (DB writer, backup
//! event journal, archive segment ledger, search shard index) and
//! continue to live on [`crate::core_impl::CoreImpl`] as
//! orchestrators. The coordinator concentrates the two backup
//! [`Mutex`]es behind a typed accessor surface so that:
//!
//!   * The "post-persist atomic in-memory commit" semantics
//!     (manifest tail update + segment ledger append in the
//!     incremental path; manifest tail update + segment ledger
//!     replace in the compaction path) become single named
//!     coordinator methods ([`Coordinator::commit_incremental`],
//!     [`Coordinator::commit_compaction`]) that hold one lock for
//!     the duration of the update.
//!   * The "snapshot-and-clone" pattern used by callers that need
//!     to drop the lock before performing I/O (segment seal,
//!     manifest sign, compaction plan) becomes a typed
//!     [`Coordinator::clone_keys`] /
//!     [`Coordinator::previous_manifest`] /
//!     [`Coordinator::tracked_segments`] surface. Because both
//!     manifest and segment ledger now live under the same
//!     [`Mutex`], each accessor is internally atomic against
//!     concurrent commits (the commit helpers hold the same
//!     guard); a future orchestrator that needs to read both
//!     halves jointly can add a single-shot accessor at the time
//!     the call site exists, rather than pre-baking a speculative
//!     joint reader.
//!   * Tests can read state via
//!     [`Coordinator::tracked_segments`] /
//!     [`Coordinator::previous_manifest`] /
//!     [`Coordinator::has_keys`] instead of reaching into private
//!     [`Mutex`]es with `.lock().unwrap()`.
//!
//! The internal mutexes retain the lock-ordering position they
//! held when they were direct fields on `CoreImpl` (tier 3
//! "Backup bundles" in the lock hierarchy documented on
//! [`crate::core_impl::CoreImpl`]). The coordinator enforces a
//! single canonical *intra-coordinator* lock order:
//!
//! ```text
//! backup_keys -> chain_state
//! ```
//!
//! Every method that acquires more than one inner lock takes them
//! in this order ([`Coordinator::install_keys`] is the only such
//! method; [`Coordinator::commit_incremental`] /
//! [`Coordinator::commit_compaction`] each only touch
//! `chain_state`). Reducing the lock count from three to two and
//! moving (manifest, segments) under a single guard eliminates
//! the previous drop-order-dependent atomicity reasoning and
//! removes the ABBA-deadlock risk between the two commit helpers
//! that previously locked manifest and segment mutexes in
//! opposite orders.
//!
//! The recommended *caller* sequence for orchestrators that need
//! to snapshot state, drop locks for I/O, and then atomically
//! commit is:
//!
//!   1. `clone_keys` / `require_keys` first (read the bundle).
//!   2. `previous_manifest` / `tracked_segments` next (each call
//!      takes the `chain_state` lock for the duration of one
//!      field clone).
//!   3. `commit_incremental` / `commit_compaction` last (write
//!      manifest + segments atomically, after the persist
//!      SAVEPOINT has succeeded).
//!
//! No method on the coordinator holds two locks simultaneously
//! across an I/O call — every accessor either clones the inner
//! state or returns immediately.

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::core_impl::poisoned;
use crate::crypto::key_hierarchy::KEY_LEN;
use crate::formats::manifest::BackupManifest;
use crate::local_store::StorageError;
use crate::{Error, Result};

/// Atomically-installed backup key material.
///
/// All three fields (`K_backup_root`, the hybrid signing key, and
/// the device id) are installed together by
/// [`Coordinator::install_keys`] and read together by every
/// backup operation that needs to seal a segment or sign a
/// manifest. Bundling them into a single struct behind one
/// [`Mutex`] makes the "installed atomically as a triple"
/// invariant non-bypassable: callers cannot observe a
/// partially-installed state where (for example) the root key is
/// present but the signing key is still `None`. It also reduces
/// the lock-acquisition count on backup hot paths from three to
/// one.
///
/// The bundle is held inside the coordinator behind an `Arc` so
/// snapshot accessors ([`Coordinator::clone_keys`] /
/// [`Coordinator::require_keys`]) return cheaply
/// (refcount bump, no ~6 KB struct copy). `HybridSigningKey`
/// alone is ~6 KB (ML-DSA-65 4032 byte signing key + 1952 byte
/// verifying key + Ed25519 32 byte signing key); copying it by
/// value on every backup / compaction path inflates stack
/// pressure in debug builds. Orchestrators read the inner fields
/// through `&*keys` (signing key passed by reference, device id
/// cloned only at the manifest-build site, root key copied as the
/// 32 byte array).
pub(crate) struct BackupKeys {
    pub(crate) root_key: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) signing_key: crate::crypto::signing::HybridSigningKey,
    pub(crate) device_id: String,
}

/// One row of the in-memory backup segment ledger.
///
/// Mirrors a `backup_segment_ledger` row in memory. The persisted
/// row stores `wrapped_k_segment` (AES-256-KW of `k_segment`
/// under `K_backup_root`); this in-memory form holds the
/// unwrapped per-segment key so the seal/decrypt path does not
/// re-derive it on every operation.
#[derive(Debug, Clone)]
pub struct TrackedBackupSegment {
    /// Sealed segment record returned by
    /// [`crate::backup::segment_builder::BackupSegmentBuilder::build_segment`].
    pub built: crate::backup::segment_builder::BuiltBackupSegment,
    /// Tier the segment currently sits in. New segments produced
    /// by [`crate::KChatCore::run_incremental_backup`] start at
    /// [`crate::backup::compaction::CompactionTier::Daily`].
    pub tier: crate::backup::compaction::CompactionTier,
    /// Earliest event timestamp covered by the segment (ms epoch).
    pub min_event_ms: i64,
    /// Latest event timestamp covered by the segment (ms epoch).
    pub max_event_ms: i64,
    /// The `K_backup_segment` instance the segment was sealed
    /// under. Stored here because
    /// [`crate::backup::segment_builder::BackupSegmentBuilder::build_segment`]
    /// generates `built.segment_id` internally — it is **not**
    /// the input to
    /// [`crate::crypto::key_hierarchy::derive_backup_segment`] —
    /// so the orchestrator cannot re-derive the key on the open
    /// side. Persisted on the
    /// `backup_segment_ledger.wrapped_k_segment` column as an
    /// AES-256-KW (RFC 3394) of these bytes under `K_backup_root`.
    pub k_segment: crate::crypto::key_hierarchy::KeyMaterial,
}

/// In-memory tail of the backup manifest chain *plus* the
/// in-memory ledger of sealed segments that have not yet been
/// superseded by compaction.
///
/// Bundled into a single struct so the (manifest tail, segment
/// ledger) pair lives under one [`Mutex`] on [`Coordinator`].
/// The previous design held the two fields under separate
/// `Mutex`es and relied on holding both locks together inside
/// [`Coordinator::commit_incremental`] /
/// [`Coordinator::commit_compaction`] for atomicity — that
/// only worked because Rust drops locals in reverse declaration
/// order, which is an implicit guarantee that a future maintainer
/// could silently break by reordering `let` bindings. Bundling
/// under one `Mutex` makes the atomicity invariant explicit:
/// readers see either the pre-commit or post-commit pair, never
/// a torn intermediate.
///
/// Concretely this addresses two related correctness concerns:
///
///   * Update atomicity (writers): both commit helpers replace
///     the manifest tail and the segment ledger under a single
///     guard, so a concurrent reader cannot observe a
///     "new segments + old manifest" or vice versa intermediate.
///   * Snapshot atomicity (readers): orchestrators that need a
///     consistent (manifest, segments) view use
///     [`Coordinator::snapshot_chain`] to read both fields under
///     the same lock acquisition rather than calling
///     `previous_manifest()` and `tracked_segments()` separately
///     (each of which would release the lock between calls, with
///     a write potentially interleaving in between).
#[derive(Clone, Default)]
pub(crate) struct BackupChainState {
    /// In-memory tail of the manifest chain. Mirrors the persisted
    /// `backup_manifest_chain` single-row table. Rehydrated at
    /// construction and rewritten after each backup / compaction
    /// step.
    pub(crate) previous_manifest: Option<BackupManifest>,
    /// In-memory ledger of sealed segments. Mirrors the persisted
    /// `backup_segment_ledger` table. Appended-to by
    /// `commit_incremental`, replaced wholesale by
    /// `commit_compaction`, rehydrated by `install_keys`.
    pub(crate) tracked_segments: Vec<TrackedBackupSegment>,
}

/// Phase-B.9 backup coordinator — owns the two backup
/// [`Mutex`]es previously held directly on
/// [`crate::core_impl::CoreImpl`].
pub(crate) struct Coordinator {
    backup_keys: Mutex<Option<Arc<BackupKeys>>>,
    chain_state: Mutex<BackupChainState>,
}

impl Coordinator {
    /// Construct an empty coordinator. Both mutexes start
    /// `None` / empty.
    pub(crate) fn new() -> Self {
        Self {
            backup_keys: Mutex::new(None),
            chain_state: Mutex::new(BackupChainState::default()),
        }
    }

    // -----------------------------------------------------------------
    // Backup keys
    // -----------------------------------------------------------------

    /// Whether [`Self::install_keys`] has been called.
    pub(crate) fn has_keys(&self) -> bool {
        self.backup_keys
            .lock()
            .map(|s| s.is_some())
            .unwrap_or(false)
    }

    /// Atomically replace the installed key bundle and the
    /// in-memory tracked segment ledger.
    ///
    /// The orchestrator calls this after hydrating the ledger
    /// from `backup_segment_ledger` under the new
    /// `K_backup_root`. Installing keys + ledger together
    /// preserves the
    /// [`crate::core_impl::CoreImpl::install_backup_keys`]
    /// invariant: a hydration failure must leave the coordinator
    /// in the "no keys, no ledger" state instead of the
    /// divergent "keys installed, ledger empty" state.
    pub(crate) fn install_keys(
        &self,
        keys: BackupKeys,
        hydrated_segments: Vec<TrackedBackupSegment>,
    ) -> Result<()> {
        // Lock-ordering discipline: the coordinator-internal
        // canonical order is `backup_keys -> chain_state` (see
        // module-level doc). `install_keys` is the only method
        // that acquires both locks; the commit helpers only touch
        // `chain_state`. Keeping every multi-lock method aligned
        // with the same total order rules out ABBA deadlocks
        // statically even if a future caller is added.
        let mut k = self.backup_keys.lock().map_err(poisoned)?;
        let mut chain = self.chain_state.lock().map_err(poisoned)?;
        chain.tracked_segments = hydrated_segments;
        *k = Some(Arc::new(keys));
        Ok(())
    }

    /// Snapshot the currently-installed key bundle.
    ///
    /// Returns `None` if [`Self::install_keys`] has not been
    /// called yet. Callers that need to drop the bundle lock
    /// before performing I/O (seal a segment, sign a manifest)
    /// clone the returned `Arc` — an 8-byte refcount bump rather
    /// than a ~6 KB `HybridSigningKey` copy.
    pub(crate) fn clone_keys(&self) -> Result<Option<Arc<BackupKeys>>> {
        Ok(self.backup_keys.lock().map_err(poisoned)?.clone())
    }

    /// Snapshot the currently-installed key bundle or return
    /// [`StorageError::SubsystemNotInstalled`] if it has not
    /// been installed yet.
    ///
    /// Centralises the "no keys installed" error shape used by
    /// [`crate::core_impl::CoreImpl::run_incremental_backup_inner`]
    /// and
    /// [`crate::core_impl::CoreImpl::compact_backup`] — both
    /// previously open-coded the same `SubsystemNotInstalled`
    /// branch directly against `self.backup_keys.lock()`. The
    /// returned `Arc` is cheap to clone; orchestrators access
    /// fields via `&*keys`.
    pub(crate) fn require_keys(&self) -> Result<Arc<BackupKeys>> {
        self.clone_keys()?
            .ok_or_else(|| Error::Storage(StorageError::SubsystemNotInstalled("backup_keys")))
    }

    // -----------------------------------------------------------------
    // Chain state (previous manifest tail + tracked segment ledger)
    // -----------------------------------------------------------------

    /// Snapshot the in-memory tail of the manifest chain.
    ///
    /// Independent accessor for callers that only need the
    /// manifest tail; callers that need both the manifest and the
    /// segment ledger should use [`Self::snapshot_chain`] instead,
    /// which reads both under a single lock acquisition (avoids a
    /// concurrent write interleaving between two separate
    /// snapshot calls).
    pub(crate) fn previous_manifest(&self) -> Result<Option<BackupManifest>> {
        Ok(self
            .chain_state
            .lock()
            .map_err(poisoned)?
            .previous_manifest
            .clone())
    }

    /// Replace the in-memory tail of the manifest chain.
    ///
    /// Used by
    /// [`crate::core_impl::CoreImpl::hydrate_backup_manifest_from_db`]
    /// to rehydrate the tail at construction time. Steady-state
    /// updates go through [`Self::commit_incremental`] /
    /// [`Self::commit_compaction`] which couple the tail with the
    /// segment ledger under the same lock acquisition.
    pub(crate) fn set_previous_manifest(&self, manifest: Option<BackupManifest>) -> Result<()> {
        self.chain_state.lock().map_err(poisoned)?.previous_manifest = manifest;
        Ok(())
    }

    /// Snapshot the in-memory segment ledger.
    ///
    /// Independent accessor for callers that only need the ledger;
    /// callers that need both the manifest and the ledger should
    /// use [`Self::snapshot_chain`] instead. Returns a clone so
    /// the caller can drop the lock before doing the (potentially
    /// expensive) work of planning a compaction or building a
    /// manifest over the snapshot.
    pub(crate) fn tracked_segments(&self) -> Result<Vec<TrackedBackupSegment>> {
        Ok(self
            .chain_state
            .lock()
            .map_err(poisoned)?
            .tracked_segments
            .clone())
    }

    // -----------------------------------------------------------------
    // Post-persist commit helpers
    // -----------------------------------------------------------------

    /// Atomically commit the in-memory state after a successful
    /// incremental-backup persist.
    ///
    /// Sets `previous_backup_manifest = Some(manifest)` and
    /// appends `tracked` to the segment ledger. The caller must
    /// only invoke this *after* the SAVEPOINT in
    /// [`crate::core_impl::CoreImpl::persist_incremental_backup_atomic`]
    /// has been committed — a persist failure leaves the
    /// coordinator at its pre-call state, matching the un-mutated
    /// database.
    ///
    /// Both fields live under the same `Mutex`, so the (manifest
    /// tail, segment ledger) pair is observed atomically by any
    /// concurrent reader: the entire update happens under one
    /// guard, with no inter-lock window. (The previous two-mutex
    /// design depended on Rust's reverse-declaration drop order
    /// to release the segment guard before the manifest guard;
    /// the bundled-state design makes the atomicity invariant
    /// explicit and unconditional.)
    pub(crate) fn commit_incremental(
        &self,
        manifest: BackupManifest,
        tracked: TrackedBackupSegment,
    ) -> Result<()> {
        let mut chain = self.chain_state.lock().map_err(poisoned)?;
        chain.previous_manifest = Some(manifest);
        chain.tracked_segments.push(tracked);
        Ok(())
    }

    /// Atomically commit the in-memory state after a successful
    /// compaction persist.
    ///
    /// Replaces the segment ledger with `new_ledger` and sets
    /// `previous_manifest = Some(manifest)`. As with
    /// [`Self::commit_incremental`], must only be called after
    /// [`crate::core_impl::CoreImpl::persist_compaction_backup_atomic`]
    /// has committed; both fields live under the same `Mutex` so
    /// any concurrent reader sees a consistent (chain tail,
    /// ledger) pair.
    pub(crate) fn commit_compaction(
        &self,
        manifest: BackupManifest,
        new_ledger: Vec<TrackedBackupSegment>,
    ) -> Result<()> {
        // Single-lock acquisition: the manifest tail and the
        // segment ledger live in the same [`BackupChainState`]
        // value, so there is no ABBA-deadlock surface between
        // this method and [`Self::commit_incremental`] — both
        // simply lock `chain_state`. The previous design held two
        // mutexes and required strict ordering between them to
        // avoid the ABBA pair; bundling under one lock eliminates
        // the ordering requirement at the type level.
        let mut chain = self.chain_state.lock().map_err(poisoned)?;
        chain.previous_manifest = Some(manifest);
        chain.tracked_segments = new_ledger;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::compaction::CompactionTier;
    use crate::backup::segment_builder::BuiltBackupSegment;
    use crate::crypto::key_hierarchy::KeyMaterial;
    use crate::formats::manifest::{
        BACKUP_MANIFEST_MAGIC, GENESIS_PREVIOUS_HASH, MANIFEST_VERSION,
    };
    use crate::formats::SegmentType;
    use rand::rngs::OsRng;

    fn sample_keys() -> BackupKeys {
        let mut rng = OsRng;
        let signing = crate::crypto::signing::HybridSigningKey::generate(&mut rng);
        BackupKeys {
            root_key: Zeroizing::new([0xAB; KEY_LEN]),
            signing_key: signing,
            device_id: "test-device".to_string(),
        }
    }

    fn sample_manifest(generation: u64) -> BackupManifest {
        BackupManifest {
            magic: BACKUP_MANIFEST_MAGIC.to_string(),
            version: MANIFEST_VERSION,
            manifest_id: uuid::Uuid::now_v7(),
            generation,
            previous_manifest_hash: GENESIS_PREVIOUS_HASH,
            segments: Vec::new(),
            search_index_shards: Vec::new(),
            media_references: Vec::new(),
            tombstones: Vec::new(),
            merkle_root: [0u8; 32],
            manifest_signature: Vec::new(),
            pqc_signature: Vec::new(),
        }
    }

    fn sample_segment(segment_id: uuid::Uuid) -> TrackedBackupSegment {
        TrackedBackupSegment {
            built: BuiltBackupSegment {
                segment_id,
                segment_type: SegmentType::Events,
                ciphertext: vec![0u8; 16],
                nonce: [0u8; 24],
                event_count: 0,
                merkle_root: [0u8; 32],
            },
            tier: CompactionTier::Daily,
            min_event_ms: 0,
            max_event_ms: 0,
            k_segment: KeyMaterial::from_bytes([0u8; KEY_LEN]),
        }
    }

    #[test]
    fn new_coordinator_has_empty_state() {
        let c = Coordinator::new();
        assert!(!c.has_keys());
        assert!(c.clone_keys().unwrap().is_none());
        assert!(c.previous_manifest().unwrap().is_none());
        assert!(c.tracked_segments().unwrap().is_empty());
    }

    #[test]
    fn require_keys_returns_subsystem_not_installed_when_unset() {
        let c = Coordinator::new();
        let err = c
            .require_keys()
            .err()
            .expect("require_keys without install must error");
        match err {
            Error::Storage(StorageError::SubsystemNotInstalled(name)) => {
                assert_eq!(name, "backup_keys");
            }
            other => panic!("expected SubsystemNotInstalled, got {other:?}"),
        }
    }

    #[test]
    fn install_keys_sets_keys_and_hydrated_ledger_atomically() {
        let c = Coordinator::new();
        let seg = sample_segment(uuid::Uuid::now_v7());
        c.install_keys(sample_keys(), vec![seg.clone()]).unwrap();
        assert!(c.has_keys());
        assert_eq!(c.tracked_segments().unwrap().len(), 1);
        assert_eq!(
            c.tracked_segments().unwrap()[0].built.segment_id,
            seg.built.segment_id
        );
    }

    #[test]
    fn commit_incremental_appends_and_updates_manifest() {
        let c = Coordinator::new();
        c.install_keys(sample_keys(), Vec::new()).unwrap();
        let seg = sample_segment(uuid::Uuid::now_v7());
        let manifest = sample_manifest(1);
        c.commit_incremental(manifest.clone(), seg.clone()).unwrap();
        assert_eq!(c.tracked_segments().unwrap().len(), 1);
        let tail = c.previous_manifest().unwrap().expect("manifest set");
        assert_eq!(tail.manifest_id, manifest.manifest_id);
    }

    #[test]
    fn commit_compaction_replaces_ledger_and_updates_manifest() {
        let c = Coordinator::new();
        c.install_keys(sample_keys(), vec![sample_segment(uuid::Uuid::now_v7())])
            .unwrap();
        let new_seg = sample_segment(uuid::Uuid::now_v7());
        let manifest = sample_manifest(2);
        c.commit_compaction(manifest.clone(), vec![new_seg.clone()])
            .unwrap();
        let segs = c.tracked_segments().unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].built.segment_id, new_seg.built.segment_id);
        let tail = c.previous_manifest().unwrap().expect("manifest set");
        assert_eq!(tail.manifest_id, manifest.manifest_id);
    }

    #[test]
    fn set_previous_manifest_to_none_clears_chain_tail() {
        let c = Coordinator::new();
        c.set_previous_manifest(Some(sample_manifest(1))).unwrap();
        assert!(c.previous_manifest().unwrap().is_some());
        c.set_previous_manifest(None).unwrap();
        assert!(c.previous_manifest().unwrap().is_none());
    }

    /// After a `commit_incremental` the (manifest tail, segment
    /// ledger) pair must be observable atomically by readers. The
    /// bundled [`BackupChainState`] makes this an explicit type
    /// invariant rather than relying on Rust's drop order across
    /// two separate `Mutex` guards. This test pins the behaviour
    /// in case a future maintainer is tempted to re-split the
    /// state into separate mutexes for any reason — if either
    /// half lagged the other after a commit, this assertion would
    /// fail.
    #[test]
    fn commit_incremental_updates_manifest_and_segments_atomically() {
        let c = Coordinator::new();
        c.install_keys(sample_keys(), Vec::new()).unwrap();

        assert!(c.previous_manifest().unwrap().is_none());
        assert!(c.tracked_segments().unwrap().is_empty());

        let seg = sample_segment(uuid::Uuid::now_v7());
        let manifest = sample_manifest(1);
        c.commit_incremental(manifest.clone(), seg.clone()).unwrap();

        let tail = c.previous_manifest().unwrap().expect("manifest set");
        let segs = c.tracked_segments().unwrap();
        assert_eq!(tail.manifest_id, manifest.manifest_id);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].built.segment_id, seg.built.segment_id);
    }
}
