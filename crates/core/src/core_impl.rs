//! Concrete [`KChatCore`] implementation.
//!
//! `docs/PROPOSAL.md §12` specifies the public API trait;
//! [`CoreImpl`] is the Phase-1 in-process implementation that wires
//! the trait to the SQLCipher [`LocalStoreDb`], the
//! [`MessagePersister`] for outbox / ingest persistence, and the
//! [`QueryEngine`] for unified FTS5 + structured search.
//!
//! What is wired in Phase 1:
//!
//! * [`CoreImpl::new`] opens (or creates) `{data_dir}/kchat.db` with
//!   the supplied 32-byte `K_local_db`.
//! * [`KChatCore::config`] returns the stored configuration.
//! * [`KChatCore::initialize`] re-opens the local store at the
//!   supplied configuration's `data_dir` using the key that was
//!   passed to [`CoreImpl::new`].
//! * [`KChatCore::send_text`] mints an [`OutboxEntry`] via
//!   [`MessageProcessor::create_outbox_entry`] and persists it via
//!   [`MessagePersister::persist_outbox_entry`].
//! * [`KChatCore::search`] delegates to
//!   [`QueryEngine::execute_search`].
//!
//! What is **not** yet wired:
//!
//! * The transport-driven [`KChatCore::ingest_remote_messages`] is a
//!   stub returning [`IngestResult::default()`] — the MLS delivery
//!   client lands later in Phase 1. For now, callers (and tests) use
//!   the inherent [`CoreImpl::ingest_messages`] entry point that
//!   takes an in-memory slice of [`IngestedMessage`] values directly.
//! * Async surface: the trait is currently synchronous; converting
//!   to `async fn` is queued for once the I/O paths are in place.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use zeroize::Zeroizing;

use crate::archive::epoch_keys::EpochKeyManager;
use crate::archive::event_journal::{ArchiveEvent, ArchiveEventJournal, ArchiveEventType};
use crate::config::KChatCoreConfig;
use crate::crypto::aead::BlobClass;
use crate::crypto::key_hierarchy::{KeyMaterial, KEY_LEN};
use crate::formats::manifest::WrappedEpochKeyRef;
use crate::local_store::db::LocalStoreDb;
use crate::local_store::schema::{
    BackupEventJournalEntry, Conversation, MediaAsset, MessageBody, MessageKind, MessageSkeleton,
};
use crate::local_store::state_machines::{ArchiveState, BackupState, BodyState, MediaState};
use crate::media::processor::process_media;
use crate::media::thumbnail::{ThumbnailGenerator, DEFAULT_MAX_DIMENSION};
use crate::message::processor::{
    encode_event_payload, IngestResult, IngestedMessage, MessagePersister, MessageProcessor,
    ProcessorError,
};
use crate::offload::budget::{StorageBudget, StorageBudgetEnforcer};
use crate::offload::eviction::{
    collect_eviction_candidates, execute_eviction, plan_tiered_eviction,
};
use crate::offload::hydration::{HydrationQueue, HydrationRequest};
use crate::search::fuzzy_search::FuzzySearchEngine;
use crate::search::query_engine::{ColdShardSource, QueryEngine};
use crate::transport::{DeliveryClient, RawDeliveryMessage, TransportClient};
use crate::{
    BackupResult, BackupSource, ClientMessageId, DeliveryCursor, DeviceRegistration, Error,
    HydratedMessage, HydrationReason, KChatCore, MessageView, OffloadResult, RestoreResult, Result,
    SearchQuery, SearchResult, SearchScope, SendMediaResult,
};

/// Default capacity hint for [`CoreImpl::hydration_queue`]. The
/// queue grows beyond this on demand — `HydrationQueue::new`
/// only sizes the backing `Vec`.
const DEFAULT_HYDRATION_QUEUE_CAPACITY: usize = 256;

/// Cap each backup segment so an event-journal backlog does not
/// produce a single oversized seal. Mirrors the archive
/// segment cap (`docs/PROPOSAL.md §5.2`). Used by both
/// [`CoreImpl::run_incremental_backup_inner`] and the Task-1
/// shard-aware wrapper
/// [`CoreImpl::run_incremental_backup_with_search_shards`] —
/// kept in one module-level place so the two paths cannot
/// drift.
const MAX_EVENTS_PER_BACKUP_SEGMENT: usize = 4_096;

/// Slim summary of a [`BackupEvent`] that
/// [`CoreImpl::run_incremental_backup_inner`] sealed in its
/// last pass. Returned alongside the
/// [`BackupResult`] so the Task-1 shard-aware wrapper can build
/// its `(conversation_id, time_bucket) → message_ids` map from
/// the *exact* event set the inner pipeline sealed instead of a
/// separate, racy peek of `backup_event_journal`.
#[derive(Debug, Clone)]
pub(crate) struct SealedBackupEventRef {
    pub(crate) conversation_id: Uuid,
    pub(crate) message_id: Uuid,
    pub(crate) created_at_ms: i64,
}

// ---------------------------------------------------------------------------
// CoreImpl
// ---------------------------------------------------------------------------

/// Concrete [`KChatCore`] implementation backed by a single
/// [`LocalStoreDb`].
///
/// `CoreImpl` is `Send + Sync` — the underlying [`rusqlite::Connection`]
/// is held inside a [`Mutex`] so the trait's `&self` methods can
/// short-borrow the connection without making the public surface
/// `&mut self`.
pub struct CoreImpl {
    config: KChatCoreConfig,
    db: Mutex<LocalStoreDb>,
    /// 32-byte `K_local_db` retained so [`KChatCore::initialize`]
    /// can re-open the database at a different `data_dir` without
    /// requiring the caller to re-supply the key.
    key: Zeroizing<[u8; 32]>,
    /// Optional MLS delivery-store client. When `None`,
    /// [`KChatCore::ingest_remote_messages`] returns
    /// [`Error::Transport`] — see
    /// [`CoreImpl::with_transport`] / [`CoreImpl::set_delivery_client`]
    /// for how callers wire one in.
    delivery_client: Mutex<Option<Box<dyn DeliveryClient>>>,
    /// Phase-3 hydration priority queue. `hydrate_message`
    /// enqueues a request before serving from local storage so
    /// the orchestration layer can later pop pending fetches in
    /// priority order (`docs/PROPOSAL.md §5.5`).
    hydration_queue: Mutex<HydrationQueue>,
    /// Phase-3 epoch key lifecycle (`docs/PROPOSAL.md §2.1`). The
    /// manager is `None` until [`CoreImpl::install_epoch_key_manager`]
    /// is called — typically after the device unlocks
    /// `K_archive_root` from the platform keystore. The
    /// orchestration layer consults this slot every time it needs
    /// the active epoch key (segment seal, manifest seal) and
    /// every time a manifest is cut (to harvest the
    /// wrapped-prior-epoch-keys list).
    current_epoch: Mutex<Option<EpochKeyManager>>,
    /// Phase-4 backup root key (`K_backup_root`,
    /// `docs/PROPOSAL.md §6.2`). `None` until
    /// [`CoreImpl::install_backup_keys`] is called. When unset,
    /// [`KChatCore::run_incremental_backup`] short-circuits to a
    /// noop result rather than failing — the device may not have
    /// finished unlocking the backup root yet.
    backup_root_key: Mutex<Option<Zeroizing<[u8; KEY_LEN]>>>,
    /// Hybrid Ed25519 + ML-DSA-65 device signing key used to
    /// sign backup manifests (see
    /// [`crate::crypto::signing::HybridSigningKey`]). `None` until
    /// [`CoreImpl::install_backup_keys`] is called.
    backup_signing_key: Mutex<Option<crate::crypto::signing::HybridSigningKey>>,
    /// Stable device id stamped into the backup manifest AAD so
    /// the orchestrator can attribute manifests to the device that
    /// produced them.
    backup_device_id: Mutex<Option<String>>,
    /// In-memory tail of the backup manifest chain. The next
    /// manifest produced by
    /// [`KChatCore::run_incremental_backup`] chains under this one;
    /// `None` produces a genesis manifest. Mirrors the persisted
    /// `backup_manifest_chain` single-row table — rehydrated in
    /// [`Self::hydrate_backup_manifest_from_db`] at construction
    /// time and rewritten by
    /// [`Self::persist_backup_manifest`] after each backup so
    /// chain continuity survives a process restart.
    previous_backup_manifest: Mutex<Option<crate::formats::manifest::BackupManifest>>,
    /// In-memory ledger of every sealed backup segment the
    /// orchestrator currently knows about (built but not yet
    /// superseded by compaction). [`KChatCore::run_incremental_backup`]
    /// appends one entry per call; [`Self::compact_backup`] reads
    /// it, builds a [`crate::backup::compaction::CompactionPlan`],
    /// re-seals the merged groups, and rewrites the ledger with
    /// the compacted entries replacing the superseded ones.
    /// Mirrors the persisted `backup_segment_ledger` table —
    /// rehydrated in
    /// [`Self::hydrate_tracked_backup_segments_from_db`] when
    /// `K_backup_root` is installed (the per-segment keys are
    /// stored AES-256-KW-wrapped under that root) and rewritten
    /// after each backup / compaction step.
    tracked_backup_segments: Mutex<Vec<TrackedBackupSegment>>,
    /// Phase-3 ZKOF archive backend configuration. `None` until
    /// [`CoreImpl::install_zkof_archive_backend`] is called. When
    /// set together with [`Self::zkof_archive_s3`], the
    /// archive-segment router routes
    /// `archive_segment_map.storage_backend = zk_object_fabric`
    /// rows through ZKOF instead of the legacy KChat transport.
    zkof_archive_config: Mutex<Option<crate::media::sinks::zk_fabric::ZkFabricSinkConfig>>,
    /// Shared `Arc<dyn S3Client>` used by the ZKOF archive router.
    /// `None` until [`CoreImpl::install_zkof_archive_backend`] is
    /// called. Wrapped in a `Mutex<Option<_>>` (rather than
    /// `OnceCell`) so tests can install / re-install in the same
    /// process without spinning up a fresh core.
    zkof_archive_s3: Mutex<Option<std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client>>>,
    /// Phase-5 background scheduler bridge. `None` until
    /// [`CoreImpl::install_scheduler`] is called by the platform
    /// glue (Swift `BGTaskScheduler` / Kotlin `WorkManager`). The
    /// orchestration layer treats `None` as "no scheduler
    /// available — run maintenance loops on demand only".
    scheduler: Mutex<Option<Box<dyn crate::scheduler::BackgroundScheduler>>>,
    /// Phase-6 on-device text-embedding seam. `None` until
    /// [`CoreImpl::install_text_embedder`] is called. When set,
    /// the message-ingest path computes XLM-R embeddings on
    /// every text body and writes them through the
    /// [`crate::models::embeddings::EmbeddingCache`] to
    /// `search_vector`; when `None` the ingest path skips the
    /// embedding step (text is still searchable via FTS5 +
    /// fuzzy).
    text_embedder: Mutex<Option<Box<dyn crate::models::embeddings::TextEmbedder>>>,
    /// Phase-6 on-device image-embedding seam (MobileCLIP-S2).
    /// `None` until [`CoreImpl::install_image_embedder`] is
    /// called. Mirrors the [`Self::text_embedder`] wiring.
    image_embedder: Mutex<Option<Box<dyn crate::models::clip::ImageEmbedder>>>,
    /// Phase-6 platform OCR bridge. `None` until
    /// [`CoreImpl::install_ocr_bridge`] is called. Wrapped in
    /// `Arc<dyn …>` so multiple async work items can fan out
    /// against the same bridge without going through the
    /// `Mutex` for every call.
    ocr_bridge: Mutex<Option<std::sync::Arc<dyn crate::models::ocr::OcrBridge>>>,
    /// Phase-6 resource-state probe (battery, charging, thermal,
    /// network). `None` until
    /// [`CoreImpl::install_resource_probe`] is called; the
    /// resource-gated background workers treat `None` as
    /// "always allowed" so unit tests don't need to install a
    /// probe.
    resource_probe: Mutex<Option<std::sync::Arc<dyn crate::models::resource_gate::ResourceProbe>>>,
    /// Phase-6 on-device Whisper transcription seam. `None` until
    /// [`CoreImpl::install_whisper_transcriber`] is called. When
    /// set, audio media writes a transcript row into
    /// `media_search_index` during `send_media`. Mirrors
    /// [`Self::text_embedder`] / [`Self::image_embedder`] wiring.
    whisper_transcriber: Mutex<Option<Box<dyn crate::models::whisper::WhisperTranscriber>>>,
    /// Phase-6 on-device document text-extraction seam. `None`
    /// until [`CoreImpl::install_document_extractor`] is called.
    /// When set, PDF / DOCX media writes per-page text rows into
    /// `media_search_index` (kind `"caption"`) during `send_media`.
    document_extractor: Mutex<Option<Box<dyn crate::models::document::DocumentExtractor>>>,
    /// Phase-6 on-device video keyframe-sampling seam. `None`
    /// until [`CoreImpl::install_video_keyframe_sampler`] is
    /// called. Combined with [`Self::image_embedder`] this drives
    /// the video keyframe → MobileCLIP-S2 → `search_vector`
    /// pipeline in `send_media`.
    video_keyframe_sampler: Mutex<Option<Box<dyn crate::models::video::VideoKeyframeSampler>>>,
    /// Phase-6 offline-detection seam. `None` until
    /// [`CoreImpl::install_offline_detector`] is called; the
    /// orchestration layer treats `None` as "always online" so
    /// unit tests don't need to install a detector. When set,
    /// [`KChatCore::run_incremental_backup`] defers upload while
    /// offline and [`KChatCore::hydrate_message`] returns a
    /// skeleton with `offline = true` for cold messages instead
    /// of attempting an archive fetch.
    offline_detector: Mutex<Option<std::sync::Arc<dyn crate::transport::offline::OfflineDetector>>>,
    /// Phase-7 performance-trace collector. `None` until
    /// [`CoreImpl::install_perf_collector`] is called; when set,
    /// the hot paths (`ingest_messages`, `search`,
    /// `run_incremental_backup`, `enforce_storage_budget`) emit
    /// [`crate::perf::PerfTrace`] records into the collector.
    perf_collector: Mutex<Option<std::sync::Arc<dyn crate::perf::PerfCollector>>>,
    /// Phase-7 dedup-analytics probe (read-only telemetry against
    /// the upstream ZK Object Fabric ContentIndex). `None` until
    /// [`CoreImpl::install_dedup_analytics`] is called; when set,
    /// [`CoreImpl::query_dedup_stats`] /
    /// [`CoreImpl::query_storage_savings`] dispatch through it.
    /// See `crates/core/src/transport/dedup_analytics.rs` for the
    /// privacy contract.
    dedup_analytics:
        Mutex<Option<std::sync::Arc<dyn crate::transport::dedup_analytics::DedupAnalytics>>>,
    /// Phase-8 multi-scope search resolver. `None` until
    /// [`CoreImpl::install_conversation_group_resolver`] is
    /// called; the query engine treats `None` as the default
    /// [`crate::search::search_target::NoopConversationGroupResolver`]
    /// (Channel resolves to its singleton id, Starred / Unread
    /// resolve to the empty set).
    conversation_group_resolver:
        Mutex<Option<std::sync::Arc<dyn crate::search::search_target::ConversationGroupResolver>>>,
    /// Phase-7 (2026-05-04 batch 10) macOS Spotlight bridge.
    /// `None` until
    /// [`CoreImpl::install_spotlight_anchor`] is called. The
    /// `ingest_messages` path forwards a redacted summary of
    /// every newly-ingested message to the installed anchor.
    spotlight_anchor: Mutex<Option<std::sync::Arc<dyn crate::desktop_index::SpotlightAnchor>>>,
    /// Phase-7 (2026-05-04 batch 10) Windows Search bridge.
    /// `None` until
    /// [`CoreImpl::install_windows_search_anchor`] is called.
    windows_search_anchor:
        Mutex<Option<std::sync::Arc<dyn crate::desktop_index::WindowsSearchAnchor>>>,
    /// Phase-7 (2026-05-04 batch 10 — Task 8) on-device EP
    /// benchmark runner. `None` until
    /// [`CoreImpl::install_ep_benchmark_runner`] is called. When
    /// set, [`CoreImpl::run_ep_benchmark`] forwards calls into
    /// the installed runner so the platform bridge can supply a
    /// real `ort::Session`-backed implementation.
    ep_benchmark_runner:
        Mutex<Option<std::sync::Arc<dyn crate::models::ep_tuning::EpBenchmarkRunner>>>,
    /// Phase-7 (2026-05-04 batch 10 — Task 8) persistent EP
    /// benchmark cache. Defaults to an empty cache; the
    /// orchestration layer can swap a loaded cache via
    /// [`CoreImpl::install_ep_benchmark_cache`].
    ep_benchmark_cache: Mutex<crate::models::ep_tuning::EpBenchmarkCache>,
}

/// One row of [`CoreImpl::tracked_backup_segments`].
#[derive(Debug, Clone)]
pub struct TrackedBackupSegment {
    /// Sealed segment record returned by
    /// [`crate::backup::segment_builder::BackupSegmentBuilder::build_segment`].
    pub built: crate::backup::segment_builder::BuiltBackupSegment,
    /// Tier the segment currently sits in. New segments produced
    /// by [`KChatCore::run_incremental_backup`] start at
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
    /// the input to [`crate::crypto::key_hierarchy::derive_backup_segment`]
    /// — so the orchestrator cannot re-derive the key on the
    /// open side. Persisted on the
    /// `backup_segment_ledger.wrapped_k_segment` column as an
    /// AES-256-KW (RFC 3394) of these bytes under
    /// `K_backup_root` — see
    /// [`CoreImpl::hydrate_tracked_backup_segments_from_db`].
    pub k_segment: crate::crypto::key_hierarchy::KeyMaterial,
}

impl std::fmt::Debug for CoreImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreImpl")
            .field("config", &self.config)
            .field("db", &"<LocalStoreDb>")
            .field("key", &"<redacted>")
            .field("delivery_client", &"<dyn DeliveryClient>")
            .finish()
    }
}

/// Receipt returned by [`CoreImpl::upload_search_shards`].
///
/// The receipt carries per-shard success metadata *and* per-shard
/// failure messages so callers can detect "text uploaded, fuzzy
/// failed" and retry only the failing half. This is critical for
/// incremental backups where re-uploading a successful shard is
/// wasteful (and on bandwidth-constrained connections, harmful).
///
/// The two halves are independent:
///
/// * `text_shard.is_some()` ⟺ the text shard upload succeeded.
/// * `text_error.is_some()` ⟺ the text shard upload failed; the
///   string carries the upstream transport message verbatim.
///
/// At most one of `text_shard` / `text_error` is `Some` for a given
/// call (analogously for fuzzy). When the corresponding rows
/// vector was empty, both are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedSearchShards {
    /// URL-safe base64 of the keyed `conversation_id_hash` the
    /// transport ferried the shards to. The cold-result hydration
    /// path uses the same string when calling
    /// [`crate::transport::TransportClient::fetch_index_shards`].
    pub conversation_hash: String,
    /// Echo of the time bucket the request targeted.
    pub time_bucket: String,
    /// Receipt for the text shard, `None` when `fts_rows` was
    /// empty *or* when the text upload failed (in which case
    /// [`Self::text_error`] is set).
    pub text_shard: Option<UploadedShardMetadata>,
    /// Receipt for the fuzzy shard, `None` when `fuzzy_rows` was
    /// empty *or* when the fuzzy upload failed (in which case
    /// [`Self::fuzzy_error`] is set).
    pub fuzzy_shard: Option<UploadedShardMetadata>,
    /// Upstream transport error from the text shard upload, if it
    /// failed. `None` on success or when the text upload was
    /// skipped.
    pub text_error: Option<String>,
    /// Upstream transport error from the fuzzy shard upload, if it
    /// failed. `None` on success or when the fuzzy upload was
    /// skipped.
    pub fuzzy_error: Option<String>,
}

impl UploadedSearchShards {
    /// `true` when at least one shard upload failed.
    pub fn has_failures(&self) -> bool {
        self.text_error.is_some() || self.fuzzy_error.is_some()
    }

    /// First failure message (text first, fuzzy second), if any.
    /// Useful for surfacing a short banner in the UI; the full
    /// per-shard breakdown is on the receipt.
    pub fn first_error(&self) -> Option<&str> {
        self.text_error.as_deref().or(self.fuzzy_error.as_deref())
    }
}

/// One row of [`UploadedSearchShards`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedShardMetadata {
    /// Stable shard id allocated by the builder.
    pub shard_id: Uuid,
    /// Number of FTS / fuzzy rows the shard sealed.
    pub doc_count: u64,
    /// Length of the CBOR-encoded shard frame uploaded over the
    /// wire.
    pub ciphertext_len: usize,
    /// Hash of the AEAD ciphertext produced by the seal step.
    /// Surfaces `BuiltSearchShard::ciphertext_sha256` so callers
    /// can record it in their `search_shard_map` ledger and
    /// detect drift on later fetches.
    pub ciphertext_sha256: [u8; 32],
}

// URL-safe base64 helper. The single implementation lives in
// [`crate::util::base64_urlsafe_encode`] and is re-exported here
// so existing call sites stay source-compatible. The write path
// (this module) and the read path
// (`crate::search::cold_shard_source`) MUST share one alphabet
// — see `crate::util` for the rationale.
use crate::util::base64_urlsafe_encode;

impl CoreImpl {
    /// Construct a new core, opening the SQLCipher database at
    /// `{config.data_dir}/kchat.db` with `key`. No transport
    /// client is wired — see [`CoreImpl::with_transport`] /
    /// [`CoreImpl::set_delivery_client`] to add one.
    pub fn new(config: KChatCoreConfig, key: [u8; 32]) -> Result<Self> {
        let db = LocalStoreDb::open(&config.data_dir, &key)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let core = Self {
            config,
            db: Mutex::new(db),
            key: Zeroizing::new(key),
            delivery_client: Mutex::new(None),
            hydration_queue: Mutex::new(HydrationQueue::new(DEFAULT_HYDRATION_QUEUE_CAPACITY)),
            current_epoch: Mutex::new(None),
            backup_root_key: Mutex::new(None),
            backup_signing_key: Mutex::new(None),
            backup_device_id: Mutex::new(None),
            previous_backup_manifest: Mutex::new(None),
            tracked_backup_segments: Mutex::new(Vec::new()),
            zkof_archive_config: Mutex::new(None),
            zkof_archive_s3: Mutex::new(None),
            scheduler: Mutex::new(None),
            text_embedder: Mutex::new(None),
            image_embedder: Mutex::new(None),
            ocr_bridge: Mutex::new(None),
            resource_probe: Mutex::new(None),
            whisper_transcriber: Mutex::new(None),
            document_extractor: Mutex::new(None),
            video_keyframe_sampler: Mutex::new(None),
            offline_detector: Mutex::new(None),
            perf_collector: Mutex::new(None),
            dedup_analytics: Mutex::new(None),
            conversation_group_resolver: Mutex::new(None),
            spotlight_anchor: Mutex::new(None),
            windows_search_anchor: Mutex::new(None),
            ep_benchmark_runner: Mutex::new(None),
            ep_benchmark_cache: Mutex::new(crate::models::ep_tuning::EpBenchmarkCache::new()),
        };
        core.hydrate_backup_manifest_from_db()?;
        Ok(core)
    }

    /// Construct a new core backed by an in-memory database.
    ///
    /// Intended for unit / integration tests — the in-memory
    /// SQLCipher handle does not persist anywhere on disk and is
    /// not appropriate for production callers.
    #[doc(hidden)]
    pub fn new_in_memory(config: KChatCoreConfig, key: [u8; 32]) -> Result<Self> {
        let db = LocalStoreDb::open_in_memory(&key).map_err(|e| Error::Storage(e.to_string()))?;
        let core = Self {
            config,
            db: Mutex::new(db),
            key: Zeroizing::new(key),
            delivery_client: Mutex::new(None),
            hydration_queue: Mutex::new(HydrationQueue::new(DEFAULT_HYDRATION_QUEUE_CAPACITY)),
            current_epoch: Mutex::new(None),
            backup_root_key: Mutex::new(None),
            backup_signing_key: Mutex::new(None),
            backup_device_id: Mutex::new(None),
            previous_backup_manifest: Mutex::new(None),
            tracked_backup_segments: Mutex::new(Vec::new()),
            zkof_archive_config: Mutex::new(None),
            zkof_archive_s3: Mutex::new(None),
            scheduler: Mutex::new(None),
            text_embedder: Mutex::new(None),
            image_embedder: Mutex::new(None),
            ocr_bridge: Mutex::new(None),
            resource_probe: Mutex::new(None),
            whisper_transcriber: Mutex::new(None),
            document_extractor: Mutex::new(None),
            video_keyframe_sampler: Mutex::new(None),
            offline_detector: Mutex::new(None),
            perf_collector: Mutex::new(None),
            dedup_analytics: Mutex::new(None),
            conversation_group_resolver: Mutex::new(None),
            spotlight_anchor: Mutex::new(None),
            windows_search_anchor: Mutex::new(None),
            ep_benchmark_runner: Mutex::new(None),
            ep_benchmark_cache: Mutex::new(crate::models::ep_tuning::EpBenchmarkCache::new()),
        };
        core.hydrate_backup_manifest_from_db()?;
        Ok(core)
    }

    /// Construct a new core with an MLS delivery-store client wired
    /// in from the start. Equivalent to calling
    /// [`CoreImpl::new`] followed by
    /// [`CoreImpl::set_delivery_client`].
    pub fn with_transport(
        config: KChatCoreConfig,
        key: [u8; 32],
        client: Box<dyn DeliveryClient>,
    ) -> Result<Self> {
        let core = Self::new(config, key)?;
        core.set_delivery_client(client);
        Ok(core)
    }

    /// Install (or replace) the MLS delivery-store client used by
    /// [`KChatCore::ingest_remote_messages`].
    pub fn set_delivery_client(&self, client: Box<dyn DeliveryClient>) {
        *self
            .delivery_client
            .lock()
            .expect("delivery client mutex poisoned") = Some(client);
    }

    /// Number of pending hydration requests in the priority queue.
    /// Test-only inspector.
    #[cfg(test)]
    fn hydration_queue_len(&self) -> usize {
        self.hydration_queue
            .lock()
            .expect("hydration queue poisoned")
            .len()
    }

    /// Drain the hydration queue into priority order. Test-only
    /// inspector — production callers should pop with
    /// [`HydrationQueue::dequeue`] inside a worker loop.
    #[cfg(test)]
    fn hydration_queue_drain(&self) -> Vec<HydrationRequest> {
        let mut queue = self
            .hydration_queue
            .lock()
            .expect("hydration queue poisoned");
        let mut out = Vec::with_capacity(queue.len());
        while let Some(r) = queue.dequeue() {
            out.push(r);
        }
        out
    }

    // ----------------------------------------------------------------
    // Epoch key lifecycle (`docs/PROPOSAL.md §2.1`)
    // ----------------------------------------------------------------

    /// Bootstrap a fresh [`EpochKeyManager`] for the supplied
    /// `K_archive_root` and `epoch_id` and install it as the
    /// active manager. Replaces any previously installed manager
    /// — callers usually call this once at unlock time.
    ///
    /// `docs/PROPOSAL.md §2.1`: `K_archive_root` is the long-lived
    /// device-keystore wrap that the platform decrypts on unlock.
    /// The manager owns the **derived** epoch key in a `Zeroizing`
    /// buffer; the root never leaves the caller's stack.
    pub fn install_epoch_key_manager(
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
    pub fn has_epoch_key_manager(&self) -> bool {
        let slot = self
            .current_epoch
            .lock()
            .expect("current_epoch mutex poisoned");
        slot.is_some()
    }

    /// Snapshot of the currently active epoch identifier (if any).
    pub fn current_epoch_id(&self) -> Result<Option<String>> {
        let slot = self.current_epoch.lock().map_err(poisoned)?;
        Ok(slot.as_ref().map(|m| m.current_epoch_id().to_string()))
    }

    /// Borrow the bytes of the current epoch key into the supplied
    /// closure. The closure runs with the [`EpochKeyManager`]
    /// mutex held — keep its body short and side-effect free, and
    /// **never** hand the byte slice out of the closure.
    ///
    /// Returns `Error::Storage` when no manager is installed.
    pub fn with_current_epoch_key<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&[u8; KEY_LEN]) -> T,
    {
        let slot = self.current_epoch.lock().map_err(poisoned)?;
        let mgr = slot
            .as_ref()
            .ok_or_else(|| Error::Storage("no epoch key manager installed".into()))?;
        Ok(f(mgr.current_epoch_key()))
    }

    /// Rotate the active epoch under `K_archive_root`, retiring the
    /// outgoing epoch key by AES-256-KW wrapping it under
    /// `K_archive_root` and returning the wrapped bytes paired with
    /// the outgoing epoch id. The returned [`WrappedEpochKeyRef`]
    /// is intended to be funneled into the next archive manifest's
    /// `wrapped_prior_epoch_keys` slot.
    ///
    /// Returns `Error::Storage` when no manager is installed.
    pub fn rotate_archive_epoch(
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
    /// Wraps [`EpochKeyManager::unwrap_prior_epoch_key`]; the
    /// returned bytes belong to the caller and should be wrapped in
    /// a `Zeroizing` buffer at the call site.
    pub fn recover_epoch_key(
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
    pub fn delete_archive_epoch_key(&self, epoch_id: &str) -> Result<bool> {
        let mut slot = self.current_epoch.lock().map_err(poisoned)?;
        let mgr = slot
            .as_mut()
            .ok_or_else(|| Error::Storage("no epoch key manager installed".into()))?;
        Ok(mgr.delete_epoch_key(epoch_id))
    }

    /// Snapshot of every retired epoch's wrapped key, ready to drop
    /// into the next manifest's
    /// [`crate::archive::manifest_builder::ManifestBuildRequest::wrapped_prior_epoch_keys`].
    pub fn wrapped_prior_epoch_keys_for_manifest(&self) -> Result<Vec<WrappedEpochKeyRef>> {
        let slot = self.current_epoch.lock().map_err(poisoned)?;
        let mgr = slot
            .as_ref()
            .ok_or_else(|| Error::Storage("no epoch key manager installed".into()))?;
        Ok(mgr.wrapped_prior_epoch_keys_for_manifest())
    }

    /// Push every cold-flagged [`SearchResult`] into the
    /// hydration queue at priority
    /// [`HydrationReason::SearchResultTap`]. Used by
    /// [`Self::search`] when `scope == IncludeCold`. Best-effort
    /// — a poisoned queue mutex is logged-and-skipped (the
    /// search results still flow back to the caller).
    fn enqueue_cold_results_for_hydration(&self, results: &[SearchResult]) {
        let cold_iter = results.iter().filter(|r| r.is_cold);
        let now = now_ms_for_send_media();
        let mut queue = match self.hydration_queue.lock() {
            Ok(q) => q,
            Err(_) => return,
        };
        for r in cold_iter {
            queue.enqueue(crate::offload::hydration::HydrationRequest {
                message_id: r.message_id,
                conversation_id: r.conversation_id,
                reason: HydrationReason::SearchResultTap,
                requested_at_ms: now,
            });
        }
    }

    /// Run a unified search and immediately enqueue every
    /// cold-flagged result into the hydration queue at priority
    /// `SearchResultTap`. Equivalent to
    /// [`KChatCore::search`] today (since `search` already
    /// enqueues cold results when `scope == IncludeCold`) but
    /// returns a count of newly-enqueued cold rows alongside the
    /// results so the orchestration layer can update UI badges.
    pub fn search_and_prefetch_cold(
        &self,
        query: SearchQuery,
        scope: SearchScope,
    ) -> Result<(Vec<SearchResult>, usize)> {
        let db = self.db.lock().map_err(poisoned)?;
        let engine = QueryEngine::new(&db);
        let results = engine
            .execute_search(&query, &scope)
            .map_err(|e| Error::Search(e.to_string()))?;
        drop(db);
        let cold_count = results.iter().filter(|r| r.is_cold).count();
        if matches!(scope, SearchScope::IncludeCold) {
            self.enqueue_cold_results_for_hydration(&results);
        }
        Ok((results, cold_count))
    }

    /// Run a unified search with cold-bucket fan-out via
    /// `cold_source` (Phase 5, Task 1).
    ///
    /// The orchestration layer (bridge crate / async runtime) is
    /// expected to implement [`ColdShardSource`] by querying
    /// `archive_segment_map` for the `(conversation_id, time_bucket)`
    /// pairs whose bodies are offloaded but whose search shards live
    /// on the backend, calling
    /// [`crate::transport::TransportClient::fetch_index_shards`] for
    /// each pair × `(text|fuzzy)` shard type, and decrypting each blob
    /// with [`crate::search::shard_builder::restore_text_search_shard`]
    /// or [`crate::search::shard_builder::restore_fuzzy_search_shard`].
    ///
    /// `CoreImpl::search` keeps the original behavior (local-only with
    /// cold-flag marking) so callers that haven't wired up a shard
    /// source still get the offline-first contract. The new method is
    /// opt-in.
    pub fn search_with_cold_source(
        &self,
        query: SearchQuery,
        scope: SearchScope,
        cold_source: &dyn ColdShardSource,
    ) -> Result<Vec<SearchResult>> {
        let db = self.db.lock().map_err(poisoned)?;
        let engine = QueryEngine::new(&db);
        let results = engine.execute_search_with_cold_source(&query, &scope, cold_source)?;
        drop(db);
        if matches!(scope, SearchScope::IncludeCold) {
            self.enqueue_cold_results_for_hydration(&results);
        }
        Ok(results)
    }

    /// Phase 8 (2026-05-04 batch 10) — Task 2: streaming-search
    /// orchestration entry point.
    ///
    /// Wraps
    /// [`crate::search::query_engine::QueryEngine::execute_search_streaming`]
    /// so platform bridges can drive a progressive results UI.
    /// `emit` is invoked synchronously on the calling thread for
    /// every [`crate::SearchEvent`] (one
    /// [`crate::SearchEvent::LocalResults`], one
    /// [`crate::SearchEvent::ColdBucketComplete`] per bucket, one
    /// [`crate::SearchEvent::SearchComplete`]). The final return
    /// value is the same as
    /// [`Self::search_with_cold_source`] — the merged + reranked
    /// result list — so callers that don't care about the
    /// intermediate events can ignore them and treat this as a
    /// drop-in.
    ///
    /// Cold-flagged rows are still enqueued for hydration via
    /// [`crate::offload::HydrationQueue`] at priority
    /// `SearchResultTap`, mirroring the non-streaming entry
    /// point.
    pub fn search_streaming<F: FnMut(crate::SearchEvent)>(
        &self,
        query: SearchQuery,
        scope: SearchScope,
        cold_source: &dyn ColdShardSource,
        emit: F,
    ) -> Result<Vec<SearchResult>> {
        let db = self.db.lock().map_err(poisoned)?;
        let engine = QueryEngine::new(&db);
        // Use the default tenant policy here for the streaming
        // entry point — callers that need a custom policy
        // already bypass `search_streaming` for
        // `execute_search_with_cold_source_full`.
        let policy = crate::config::TenantSearchPolicy::default();
        let results = engine.execute_search_streaming(
            &query,
            &scope,
            cold_source,
            &policy,
            None,
            // Match `execute_search` (no `_with_limit`), which
            // hardcodes 200 as the engine-default cap.
            200,
            emit,
        )?;
        drop(db);
        if matches!(scope, SearchScope::IncludeCold) {
            self.enqueue_cold_results_for_hydration(&results);
        }
        Ok(results)
    }

    /// Build encrypted text + fuzzy search shards for a given
    /// `(conversation_id, time_bucket)` and ferry them to the
    /// archive backend (Phase 5, Task 2).
    ///
    /// `docs/PHASES.md §Phase 5` calls for the orchestration
    /// layer to:
    ///
    /// 1. Pull the FTS / fuzzy rows for the bucket out of local
    ///    storage,
    /// 2. seal them with `build_text_search_shard` /
    ///    `build_fuzzy_search_shard` under the active epoch's
    ///    per-shard keys,
    /// 3. upload each sealed shard via
    ///    [`crate::transport::TransportClient::upload_index_shard`],
    ///    and
    /// 4. record the upload in the local "what shards do we have
    ///    on the backend" ledger so the cold-result hydration
    ///    path
    ///    ([`Self::search_with_cold_source`]) knows to ask the
    ///    backend for them.
    ///
    /// Step 1 (loading rows out of LocalStoreDb) is the caller's
    /// responsibility — different callers source rows differently
    /// (full bucket flush vs. incremental delta vs. retry of an
    /// already-built shard) so the method takes the rows as
    /// arguments rather than re-querying the DB. Step 4 is also
    /// the caller's job until the
    /// `search_shard_map` table lands in a follow-up; the method
    /// returns an [`UploadedSearchShards`] receipt with enough
    /// metadata for the caller to record the entry.
    ///
    /// The method skips the upload entirely for empty `fts_rows`
    /// and `fuzzy_rows` so callers can call it unconditionally
    /// per bucket without worrying about empty buckets producing
    /// noise on the wire.
    ///
    /// Transport failures on either half are recorded on the
    /// returned [`UploadedSearchShards`] receipt as
    /// `text_error` / `fuzzy_error` (with the upstream message
    /// verbatim) — *not* propagated as `Result::Err`. This is the
    /// "partial upload" contract: if the text shard succeeds but
    /// the fuzzy shard fails, callers see
    /// `text_shard = Some(_), fuzzy_error = Some(_)` and can
    /// retry only the failing half. Use
    /// [`UploadedSearchShards::has_failures`] to test whether
    /// retry is needed.
    ///
    /// `Result::Err` is reserved for build-time errors that
    /// happen before any upload was attempted — CBOR encode
    /// failures, key-derivation failures inside
    /// `build_text_search_shard` /
    /// `build_fuzzy_search_shard`. These are programmer / data
    /// errors, not retryable.
    #[allow(clippy::too_many_arguments)]
    pub fn upload_search_shards(
        &self,
        transport: &dyn TransportClient,
        conversation_id: &str,
        time_bucket: &str,
        fts_rows: Vec<crate::search::shard_builder::FtsRow>,
        fuzzy_rows: Vec<crate::search::shard_builder::FuzzyRow>,
        k_text_index_shard: &crate::crypto::key_hierarchy::KeyMaterial,
        k_fuzzy_index_shard: &crate::crypto::key_hierarchy::KeyMaterial,
        conversation_hash_key: &crate::crypto::key_hierarchy::KeyMaterial,
    ) -> Result<UploadedSearchShards> {
        let conv_hash = crate::search::shard_builder::keyed_conversation_id_hash(
            conversation_id,
            conversation_hash_key,
        );
        let conv_hash_b64 = base64_urlsafe_encode(&conv_hash);

        let mut receipt = UploadedSearchShards {
            conversation_hash: conv_hash_b64.clone(),
            time_bucket: time_bucket.into(),
            text_shard: None,
            fuzzy_shard: None,
            text_error: None,
            fuzzy_error: None,
        };

        if !fts_rows.is_empty() {
            let built = crate::search::shard_builder::build_text_search_shard(
                fts_rows,
                conversation_id,
                time_bucket.to_string(),
                k_text_index_shard,
                conversation_hash_key,
            )?;
            let bytes = crate::cbor::to_vec(&built.shard).map_err(|e| {
                Error::Storage(format!("upload_search_shards: text shard cbor: {e}"))
            })?;
            match transport.upload_index_shard(&conv_hash_b64, time_bucket, "text", &bytes) {
                Ok(()) => {
                    receipt.text_shard = Some(UploadedShardMetadata {
                        shard_id: built.shard.shard_id,
                        doc_count: built.shard.doc_count,
                        ciphertext_len: bytes.len(),
                        ciphertext_sha256: built.shard.ciphertext_sha256,
                    });
                }
                Err(Error::Transport(msg)) => {
                    receipt.text_error = Some(format!("upload_search_shards text: {msg}"));
                }
                Err(other) => return Err(other),
            }
        }

        if !fuzzy_rows.is_empty() {
            let built = crate::search::shard_builder::build_fuzzy_search_shard(
                fuzzy_rows,
                conversation_id,
                time_bucket.to_string(),
                k_fuzzy_index_shard,
                conversation_hash_key,
            )?;
            let bytes = crate::cbor::to_vec(&built.shard).map_err(|e| {
                Error::Storage(format!("upload_search_shards: fuzzy shard cbor: {e}"))
            })?;
            match transport.upload_index_shard(&conv_hash_b64, time_bucket, "fuzzy", &bytes) {
                Ok(()) => {
                    receipt.fuzzy_shard = Some(UploadedShardMetadata {
                        shard_id: built.shard.shard_id,
                        doc_count: built.shard.doc_count,
                        ciphertext_len: bytes.len(),
                        ciphertext_sha256: built.shard.ciphertext_sha256,
                    });
                }
                Err(Error::Transport(msg)) => {
                    receipt.fuzzy_error = Some(format!("upload_search_shards fuzzy: {msg}"));
                }
                Err(other) => return Err(other),
            }
        }

        Ok(receipt)
    }

    /// Drive one incremental backup pass and ferry the freshly
    /// affected `(conversation_id, time_bucket)` search shards
    /// up through the supplied transport (Phase 5 / Task 1).
    ///
    /// Wraps [`Self::run_incremental_backup_inner`] with a
    /// post-seal sweep that:
    ///
    /// 1. Runs the existing incremental-backup pipeline, which
    ///    seals the events and advances the cursor. The inner
    ///    method also returns a slim
    ///    [`SealedBackupEventRef`] summary of the events it
    ///    actually sealed (`(conversation_id, message_id,
    ///    created_at_ms)` triples derived from the *same* event
    ///    list that drove the seal — no separate peek, so no
    ///    TOCTOU window vs. concurrent
    ///    `backup_event_journal.write_event` callers).
    /// 2. Groups the sealed events by
    ///    `(conversation_id, default_time_bucket_for_ms(created_at_ms))`.
    /// 3. For every affected bucket, queries the local
    ///    `search_fts` / `search_fuzzy` rows for the message ids
    ///    that just landed in the seal and routes them through
    ///    [`Self::upload_search_shards`].
    ///
    /// Returns the [`BackupResult`] from step 1 and the per-bucket
    /// [`UploadedSearchShards`] receipts from step 3 — partial
    /// upload failures are surfaced through
    /// [`UploadedSearchShards::has_failures`] just like the
    /// stand-alone path. A noop run (no events to seal) returns
    /// the default `BackupResult` and an empty receipts vector
    /// without touching the transport.
    ///
    /// `key_for_bucket` lets the caller derive
    /// `(K_text_index_shard, K_fuzzy_index_shard)` per-bucket so
    /// the orchestration layer can rotate the per-shard keys
    /// per-bucket (e.g. derived from `K_search_root` and the
    /// `(conversation_id, time_bucket)` tuple). Returning an error
    /// from the closure aborts the *upload* sweep but the backup
    /// itself has already committed at that point.
    pub fn run_incremental_backup_with_search_shards<F>(
        &self,
        transport: &dyn TransportClient,
        reason: &str,
        conversation_hash_key: &crate::crypto::key_hierarchy::KeyMaterial,
        mut key_for_bucket: F,
    ) -> Result<RunIncrementalBackupWithShards>
    where
        F: FnMut(
            &str,
            &str,
        ) -> Result<(
            crate::crypto::key_hierarchy::KeyMaterial,
            crate::crypto::key_hierarchy::KeyMaterial,
        )>,
    {
        use crate::archive::segment_builder::default_time_bucket_for_ms;
        use std::collections::BTreeMap;

        // Run the seal first and harvest the *exact* set of
        // events the inner pipeline sealed. Building
        // `bucket_map` from this list closes the TOCTOU window
        // a separate pre-seal peek would otherwise open: a
        // concurrent `backup_event_journal.write_event` call
        // landing between an outer peek and the inner re-read
        // can't cause the wrapper to miss shard coverage for
        // events the inner just sealed (the cursor has
        // advanced past those events, so no future call would
        // re-peek them either).
        let (backup, sealed_events) = self.run_incremental_backup_inner(reason)?;

        let mut bucket_map: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for sealed in &sealed_events {
            let bucket = default_time_bucket_for_ms(sealed.created_at_ms);
            bucket_map
                .entry((sealed.conversation_id.to_string(), bucket))
                .or_default()
                .push(sealed.message_id.to_string());
        }

        if bucket_map.is_empty() || backup.segments_built == 0 {
            return Ok(RunIncrementalBackupWithShards {
                backup,
                shards: Vec::new(),
            });
        }

        let mut shards = Vec::with_capacity(bucket_map.len());
        for ((conv_id, bucket), mids) in bucket_map {
            // Pull the freshly-indexed FTS + fuzzy rows for the
            // message ids in this bucket from the local store.
            // The seal reads the journal, not the search tables,
            // so the rows are still present after the cursor
            // advance.
            let (fts_rows, fuzzy_rows) = {
                let db = self.db.lock().map_err(poisoned)?;
                let conn = db.connection();
                let mut fts_rows: Vec<crate::search::shard_builder::FtsRow> = Vec::new();
                let mut fuzzy_rows: Vec<crate::search::shard_builder::FuzzyRow> = Vec::new();
                for mid in &mids {
                    // search_fts: every column is UNINDEXED apart
                    // from `text_content` so a direct SELECT works.
                    let row = conn
                        .query_row(
                            "SELECT message_id, conversation_id, sender_id, created_at_ms, text_content
                               FROM search_fts WHERE message_id = ?1",
                            rusqlite::params![mid],
                            |row| {
                                Ok((
                                    row.get::<_, String>(0)?,
                                    row.get::<_, String>(1)?,
                                    row.get::<_, String>(2)?,
                                    row.get::<_, i64>(3)?,
                                    row.get::<_, String>(4)?,
                                ))
                            },
                        )
                        .ok();
                    if let Some((
                        message_id,
                        conversation_id,
                        sender_id,
                        created_at_ms,
                        text_content,
                    )) = row
                    {
                        fts_rows.push(crate::search::shard_builder::FtsRow {
                            message_id,
                            conversation_id,
                            sender_id,
                            created_at_ms,
                            text_content,
                        });
                    }
                    let mut stmt = conn
                        .prepare(
                            "SELECT token, script, message_id FROM search_fuzzy
                              WHERE message_id = ?1",
                        )
                        .map_err(|e| Error::Storage(e.to_string()))?;
                    let rows = stmt
                        .query_map(rusqlite::params![mid], |row| {
                            Ok(crate::search::shard_builder::FuzzyRow {
                                token: row.get::<_, String>(0)?,
                                script: row.get::<_, String>(1)?,
                                message_id: row.get::<_, String>(2)?,
                            })
                        })
                        .map_err(|e| Error::Storage(e.to_string()))?;
                    for r in rows {
                        fuzzy_rows.push(r.map_err(|e| Error::Storage(e.to_string()))?);
                    }
                }
                (fts_rows, fuzzy_rows)
            };

            // Empty bucket: skip the upload entirely so we do not
            // emit an upload-call observable on the wire.
            if fts_rows.is_empty() && fuzzy_rows.is_empty() {
                continue;
            }

            let (k_text, k_fuzzy) = key_for_bucket(&conv_id, &bucket)?;
            let receipt = self.upload_search_shards(
                transport,
                &conv_id,
                &bucket,
                fts_rows,
                fuzzy_rows,
                &k_text,
                &k_fuzzy,
                conversation_hash_key,
            )?;
            shards.push(receipt);
        }

        Ok(RunIncrementalBackupWithShards { backup, shards })
    }

    /// Enqueue P3 prefetches for `visible_ids` and the surrounding
    /// adjacent-window. The window size is the slice the caller
    /// already widened — typical UI values are 5..50. See
    /// [`HydrationQueue::enqueue_prefetch_window`].
    pub fn enqueue_prefetch_window(
        &self,
        visible_ids: &[Uuid],
        conversation_id: Uuid,
        window_size: usize,
    ) -> Result<()> {
        let mut queue = self.hydration_queue.lock().map_err(poisoned)?;
        queue.enqueue_prefetch_window(
            visible_ids,
            conversation_id,
            window_size,
            now_ms_for_send_media(),
        );
        Ok(())
    }

    // ----------------------------------------------------------------
    // Timeline-skeleton rehydration on scroll-back
    // (Task 4 — `docs/PROPOSAL.md §5.1`)
    // ----------------------------------------------------------------

    /// Rehydrate every [`MessageSkeleton`] for `(conversation_id,
    /// time_bucket)` from the personal archive into the local
    /// store, returning the freshly-inserted skeletons.
    ///
    /// `docs/PROPOSAL.md §5.1` — when the user scrolls back past
    /// the local-store horizon the orchestration layer pulls the
    /// matching archive segment(s) for the bucket via
    /// [`crate::archive::prefetch::batch_prefetch_bucket`],
    /// decrypts each blob with
    /// [`crate::archive::download::decrypt_archive_segment`]
    /// (Task 3), and lands a stub skeleton row in the local
    /// store. Bodies remain remote-only ([`BodyState::RemoteArchiveOnly`])
    /// so a tap on a row triggers
    /// [`Self::hydrate_message`] on demand.
    ///
    /// `k_archive_epoch` is the epoch key currently sealing the
    /// segments — typically pulled out of
    /// [`Self::with_current_epoch_key`] once the device unlocks
    /// `K_archive_root`. Cross-epoch buckets are the caller's job
    /// — supply the correct epoch key for the bucket you are
    /// rehydrating.
    ///
    /// The function never overwrites an existing local skeleton —
    /// see [`LocalStoreDb::upsert_skeleton_from_archive`]. The
    /// returned `Vec` lists *only* the rows that landed for the
    /// first time, in `archive_segment_map` traversal order.
    pub fn rehydrate_timeline_skeletons<F>(
        &self,
        transport: &dyn TransportClient,
        conversation_id: Uuid,
        time_bucket: &str,
        key_for_segment: F,
    ) -> Result<Vec<MessageSkeleton>>
    where
        F: FnMut(&str) -> Result<[u8; 32]>,
    {
        // Pick the ZKOF-aware router whenever the caller has
        // installed a ZKOF backend AND the config opts into the
        // ZKOF archive backend. Otherwise fall back to the legacy
        // KChat-only router. This keeps the public method
        // signature stable while routing
        // `storage_backend = zk_object_fabric` rows through S3
        // automatically when the wiring is present.
        let router = self.build_archive_router(transport)?;
        self.rehydrate_timeline_skeletons_with_router(
            &router,
            conversation_id,
            time_bucket,
            key_for_segment,
        )
    }

    /// Build an [`ArchiveSegmentRouter`] honouring
    /// [`KChatCoreConfig::archive_backend`]. When the backend is
    /// [`crate::config::ArchiveBackend::Zkof`] AND
    /// [`Self::install_zkof_archive_backend`] has been called, the
    /// router knows how to route segment rows tagged
    /// `storage_backend = zk_object_fabric` through ZKOF /
    /// S3 instead of the KChat transport.
    fn build_archive_router<'a>(
        &self,
        transport: &'a dyn TransportClient,
    ) -> Result<crate::archive::download::ArchiveSegmentRouter<'a>> {
        match self.config.archive_backend {
            crate::config::ArchiveBackend::Zkof => {
                let s3 = self
                    .zkof_archive_s3
                    .lock()
                    .map_err(poisoned)?
                    .as_ref()
                    .cloned();
                let cfg = self
                    .zkof_archive_config
                    .lock()
                    .map_err(poisoned)?
                    .as_ref()
                    .cloned();
                match (s3, cfg) {
                    (Some(s3), Some(cfg)) => {
                        Ok(crate::archive::download::ArchiveSegmentRouter::with_zkof(
                            transport, s3, cfg,
                        ))
                    }
                    // ZKOF is the configured backend but the
                    // wiring is missing — surface a structured
                    // error rather than silently falling through
                    // to KChat-only.
                    _ => Err(Error::Storage(
                        "archive_backend = zkof but no ZKOF backend installed; \
                         call CoreImpl::install_zkof_archive_backend before \
                         calling rehydrate_timeline_skeletons"
                            .into(),
                    )),
                }
            }
            crate::config::ArchiveBackend::KChat => Ok(
                crate::archive::download::ArchiveSegmentRouter::kchat_only(transport),
            ),
        }
    }

    /// Install the Phase-3 ZKOF archive backend (S3 client +
    /// gateway config). Required before
    /// [`Self::rehydrate_timeline_skeletons`] can route any
    /// `storage_backend = zk_object_fabric` rows; the call is a
    /// no-op for installs against a `KChatCoreConfig` whose
    /// `archive_backend` is [`crate::config::ArchiveBackend::KChat`]
    /// but the slots stay populated so a runtime
    /// reconfiguration to ZKOF picks up the wiring without
    /// re-installing.
    pub fn install_zkof_archive_backend(
        &self,
        s3: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client>,
        config: crate::media::sinks::zk_fabric::ZkFabricSinkConfig,
    ) -> Result<()> {
        config.validate()?;
        *self.zkof_archive_s3.lock().map_err(poisoned)? = Some(s3);
        *self.zkof_archive_config.lock().map_err(poisoned)? = Some(config);
        Ok(())
    }

    /// Install a Phase-5 background scheduler bridge. The bridge
    /// is platform glue (Swift `BGTaskScheduler` on iOS, Kotlin
    /// `WorkManager` on Android) that fills in the
    /// [`crate::scheduler::BackgroundScheduler`] trait.
    ///
    /// Re-installing replaces the previous bridge — the
    /// orchestration layer is responsible for cancelling any
    /// outstanding tasks on the old bridge first via
    /// [`crate::scheduler::BackgroundScheduler::cancel_all`].
    pub fn install_scheduler(
        &self,
        scheduler: Box<dyn crate::scheduler::BackgroundScheduler>,
    ) -> Result<()> {
        *self.scheduler.lock().map_err(poisoned)? = Some(scheduler);
        Ok(())
    }

    /// Whether [`Self::install_scheduler`] has been called with a
    /// real bridge.
    pub fn has_scheduler(&self) -> bool {
        self.scheduler
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    // ----------------------------------------------------------------
    // Phase 7 (2026-05-04 batch 10) — Task 5/6 desktop search anchors.
    // ----------------------------------------------------------------

    /// Install (or replace) the macOS Spotlight bridge. The
    /// [`crate::desktop_index::SpotlightAnchor`] surface lets the
    /// orchestration layer feed redacted message metadata into
    /// `CSSearchableIndex`. Re-installing replaces the previous
    /// bridge.
    pub fn install_spotlight_anchor(
        &self,
        anchor: std::sync::Arc<dyn crate::desktop_index::SpotlightAnchor>,
    ) -> Result<()> {
        *self.spotlight_anchor.lock().map_err(poisoned)? = Some(anchor);
        Ok(())
    }

    /// Whether [`Self::install_spotlight_anchor`] has been called.
    pub fn has_spotlight_anchor(&self) -> bool {
        self.spotlight_anchor
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Push a batch of [`crate::desktop_index::SpotlightItem`]
    /// records into the installed Spotlight bridge. No-ops when
    /// no bridge is installed; surfaces the bridge's error
    /// otherwise.
    pub fn update_spotlight_index(
        &self,
        items: &[crate::desktop_index::SpotlightItem],
    ) -> Result<()> {
        let anchor = match self.spotlight_anchor.lock().map_err(poisoned)?.as_ref() {
            Some(a) => std::sync::Arc::clone(a),
            None => return Ok(()),
        };
        anchor.index_items(items)
    }

    /// Install (or replace) the Windows Search bridge.
    pub fn install_windows_search_anchor(
        &self,
        anchor: std::sync::Arc<dyn crate::desktop_index::WindowsSearchAnchor>,
    ) -> Result<()> {
        *self.windows_search_anchor.lock().map_err(poisoned)? = Some(anchor);
        Ok(())
    }

    /// Whether [`Self::install_windows_search_anchor`] has been
    /// called.
    pub fn has_windows_search_anchor(&self) -> bool {
        self.windows_search_anchor
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Push a batch of
    /// [`crate::desktop_index::WindowsSearchItem`] records into
    /// the installed Windows Search bridge. No-ops when no
    /// bridge is installed.
    pub fn update_windows_search_index(
        &self,
        items: &[crate::desktop_index::WindowsSearchItem],
    ) -> Result<()> {
        let anchor = match self
            .windows_search_anchor
            .lock()
            .map_err(poisoned)?
            .as_ref()
        {
            Some(a) => std::sync::Arc::clone(a),
            None => return Ok(()),
        };
        anchor.index_items(items)
    }

    // ----------------------------------------------------------------
    // Phase 7 (2026-05-04 batch 10) — Task 8: EP benchmark
    // capture + persistent cache + auto-selection.
    // ----------------------------------------------------------------

    /// Install (or replace) the on-device EP benchmark runner
    /// (Phase 7 Task 8). Production callers wrap their
    /// `ort::Session` factory in a runner; tests use
    /// [`crate::models::ep_tuning::NoopEpBenchmarkRunner`] or
    /// [`crate::models::ep_tuning::MockEpBenchmarkRunner`].
    pub fn install_ep_benchmark_runner(
        &self,
        runner: std::sync::Arc<dyn crate::models::ep_tuning::EpBenchmarkRunner>,
    ) -> Result<()> {
        *self.ep_benchmark_runner.lock().map_err(poisoned)? = Some(runner);
        Ok(())
    }

    /// Whether [`Self::install_ep_benchmark_runner`] has been
    /// called.
    pub fn has_ep_benchmark_runner(&self) -> bool {
        self.ep_benchmark_runner
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Run a benchmark for `(model, ep)` via the installed
    /// runner. Returns `Err(Error::NotImplemented)` when no
    /// runner is installed.
    pub fn run_ep_benchmark(
        &self,
        ep: crate::models::ep_tuning::ExecutionProvider,
        model: &crate::models::model_manager::ModelArtifact,
    ) -> Result<crate::models::ep_tuning::EpBenchmark> {
        let runner = match self.ep_benchmark_runner.lock().map_err(poisoned)?.as_ref() {
            Some(r) => std::sync::Arc::clone(r),
            None => return Err(Error::NotImplemented("ep_benchmark_runner")),
        };
        runner.run_benchmark(ep, model)
    }

    /// Replace the active EP benchmark cache. Production callers
    /// load a cache from disk on startup with
    /// [`crate::models::ep_tuning::EpBenchmarkCache::load_from_path`].
    pub fn install_ep_benchmark_cache(
        &self,
        cache: crate::models::ep_tuning::EpBenchmarkCache,
    ) -> Result<()> {
        *self.ep_benchmark_cache.lock().map_err(poisoned)? = cache;
        Ok(())
    }

    /// Snapshot of the active EP benchmark cache.
    pub fn ep_benchmark_cache(&self) -> crate::models::ep_tuning::EpBenchmarkCache {
        self.ep_benchmark_cache
            .lock()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// Run a benchmark via [`Self::run_ep_benchmark`] and
    /// persist the result into the active cache for `(ep,
    /// model_id)`. Returns the recorded benchmark.
    pub fn record_ep_benchmark(
        &self,
        ep: crate::models::ep_tuning::ExecutionProvider,
        model: &crate::models::model_manager::ModelArtifact,
    ) -> Result<crate::models::ep_tuning::EpBenchmark> {
        let bench = self.run_ep_benchmark(ep, model)?;
        let mut cache = self.ep_benchmark_cache.lock().map_err(poisoned)?;
        cache.insert(ep, &model.model_id, bench.clone());
        Ok(bench)
    }

    /// Pick the best EP for `model_id` by consulting the active
    /// cache, falling back to `fallback_chain` when no benchmark
    /// is recorded.
    pub fn select_optimal_ep(
        &self,
        model_id: &str,
        fallback_chain: &[crate::models::ep_tuning::ExecutionProvider],
    ) -> crate::models::ep_tuning::ExecutionProvider {
        let cache = self
            .ep_benchmark_cache
            .lock()
            .map(|c| c.clone())
            .unwrap_or_default();
        let benchmarks = cache.benchmarks_for_model(model_id);
        crate::models::ep_tuning::select_best_ep(&benchmarks, fallback_chain)
    }

    // ----------------------------------------------------------------
    // Phase-6 model bridges (Task 2 / 4 / 6 / 9)
    // ----------------------------------------------------------------

    /// Install (or replace) the on-device text-embedding bridge
    /// used by message ingest and the semantic-search query path
    /// (`docs/PROPOSAL.md §7.6 / §7.6.1`, Phase 6, Task 2).
    ///
    /// When set, the message-ingest path computes an XLM-R
    /// embedding for every text body and writes it through
    /// [`crate::models::embeddings::EmbeddingCache`]. When unset
    /// (the default), the embedding step is skipped — text is
    /// still searchable via FTS5 + fuzzy.
    pub fn install_text_embedder(
        &self,
        embedder: Box<dyn crate::models::embeddings::TextEmbedder>,
    ) -> Result<()> {
        *self.text_embedder.lock().map_err(poisoned)? = Some(embedder);
        Ok(())
    }

    /// Whether [`Self::install_text_embedder`] has been called
    /// with a real bridge.
    pub fn has_text_embedder(&self) -> bool {
        self.text_embedder
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Install (or replace) the on-device image-embedding bridge
    /// used by media ingest (`docs/PROPOSAL.md §7.6`, Phase 6,
    /// Task 9). When set, MobileCLIP-S2 embeddings are written to
    /// `search_vector` for image-typed media on ingest.
    pub fn install_image_embedder(
        &self,
        embedder: Box<dyn crate::models::clip::ImageEmbedder>,
    ) -> Result<()> {
        *self.image_embedder.lock().map_err(poisoned)? = Some(embedder);
        Ok(())
    }

    /// Whether [`Self::install_image_embedder`] has been called.
    pub fn has_image_embedder(&self) -> bool {
        self.image_embedder
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Install (or replace) the platform OCR bridge used by media
    /// ingest (`docs/PROPOSAL.md §7.6`, Phase 6, Task 4). Wrapped
    /// in `Arc` so multiple background workers can fan out
    /// against the same bridge without serializing through the
    /// mutex.
    pub fn install_ocr_bridge(
        &self,
        bridge: std::sync::Arc<dyn crate::models::ocr::OcrBridge>,
    ) -> Result<()> {
        *self.ocr_bridge.lock().map_err(poisoned)? = Some(bridge);
        Ok(())
    }

    /// Whether [`Self::install_ocr_bridge`] has been called.
    pub fn has_ocr_bridge(&self) -> bool {
        self.ocr_bridge
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Install (or replace) the device-resource probe used by the
    /// resource-gated background workers
    /// (`docs/PROPOSAL.md §7.6`, Phase 6, Task 6). When unset,
    /// the gate defaults to "all-clear" so unit tests don't need
    /// to install a probe.
    pub fn install_resource_probe(
        &self,
        probe: std::sync::Arc<dyn crate::models::resource_gate::ResourceProbe>,
    ) -> Result<()> {
        *self.resource_probe.lock().map_err(poisoned)? = Some(probe);
        Ok(())
    }

    /// Whether [`Self::install_resource_probe`] has been called.
    pub fn has_resource_probe(&self) -> bool {
        self.resource_probe
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Install (or replace) the on-device Whisper transcriber
    /// used by media ingest (`docs/PROPOSAL.md §7.6`, Phase 6,
    /// Task 1 of the 2026-05-04 batch). When set, audio media
    /// writes a transcript row into `media_search_index` during
    /// `send_media`.
    pub fn install_whisper_transcriber(
        &self,
        transcriber: Box<dyn crate::models::whisper::WhisperTranscriber>,
    ) -> Result<()> {
        *self.whisper_transcriber.lock().map_err(poisoned)? = Some(transcriber);
        Ok(())
    }

    /// Whether [`Self::install_whisper_transcriber`] has been
    /// called with a real bridge.
    pub fn has_whisper_transcriber(&self) -> bool {
        self.whisper_transcriber
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Install (or replace) the on-device document
    /// text-extraction bridge used by media ingest
    /// (`docs/PROPOSAL.md §7.6`, Phase 6, Task 2 of the
    /// 2026-05-04 batch). When set, PDF / DOCX media writes
    /// per-page text rows into `media_search_index` during
    /// `send_media`.
    pub fn install_document_extractor(
        &self,
        extractor: Box<dyn crate::models::document::DocumentExtractor>,
    ) -> Result<()> {
        *self.document_extractor.lock().map_err(poisoned)? = Some(extractor);
        Ok(())
    }

    /// Whether [`Self::install_document_extractor`] has been
    /// called with a real bridge.
    pub fn has_document_extractor(&self) -> bool {
        self.document_extractor
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Install (or replace) the on-device video keyframe sampler
    /// used by media ingest (`docs/PROPOSAL.md §7.6`, Phase 6,
    /// Task 3 of the 2026-05-04 batch). When set together with
    /// an [`crate::models::clip::ImageEmbedder`], video media
    /// embeds the first keyframe via MobileCLIP-S2 and writes
    /// the embedding to `search_vector` during `send_media`.
    pub fn install_video_keyframe_sampler(
        &self,
        sampler: Box<dyn crate::models::video::VideoKeyframeSampler>,
    ) -> Result<()> {
        *self.video_keyframe_sampler.lock().map_err(poisoned)? = Some(sampler);
        Ok(())
    }

    /// Whether [`Self::install_video_keyframe_sampler`] has been
    /// called with a real bridge.
    pub fn has_video_keyframe_sampler(&self) -> bool {
        self.video_keyframe_sampler
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Install (or replace) the offline-detection probe used by
    /// the backup-defer / hydrate-offline paths (Phase 7,
    /// Task 6 of the 2026-05-04 batch). Wrapped in `Arc` so
    /// multiple workers can share one detector.
    pub fn install_offline_detector(
        &self,
        detector: std::sync::Arc<dyn crate::transport::offline::OfflineDetector>,
    ) -> Result<()> {
        *self.offline_detector.lock().map_err(poisoned)? = Some(detector);
        Ok(())
    }

    /// Current online state. `true` when no detector is installed
    /// (the orchestration layer treats `None` as "always
    /// online"); otherwise delegates to the installed detector.
    pub fn is_online(&self) -> bool {
        match self.offline_detector.lock() {
            Ok(slot) => slot.as_ref().map(|d| d.is_online()).unwrap_or(true),
            Err(_) => true,
        }
    }

    /// Install (or replace) the performance-trace collector
    /// (Phase 7, Task 8 of the 2026-05-04 batch). Wrapped in
    /// `Arc` so callers can share one collector across the
    /// lifetime of the process and read out traces with
    /// [`Self::collect_perf_stats`].
    pub fn install_perf_collector(
        &self,
        collector: std::sync::Arc<dyn crate::perf::PerfCollector>,
    ) -> Result<()> {
        *self.perf_collector.lock().map_err(poisoned)? = Some(collector);
        Ok(())
    }

    /// Whether [`Self::install_perf_collector`] has been called.
    pub fn has_perf_collector(&self) -> bool {
        self.perf_collector
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Snapshot of all [`crate::perf::PerfTrace`] records
    /// recorded by the installed collector. Returns the empty
    /// vector when no collector is installed or when the
    /// installed collector does not buffer traces (e.g.
    /// [`crate::perf::NoopPerfCollector`]).
    pub fn collect_perf_stats(&self) -> Vec<crate::perf::PerfTrace> {
        let Ok(slot) = self.perf_collector.lock() else {
            return Vec::new();
        };
        match slot.as_ref() {
            Some(c) => c.snapshot(),
            None => Vec::new(),
        }
    }

    /// Phase 7 (2026-05-04 batch 10) — Task 7: per-operation
    /// p50 / p95 / p99 dashboard, derived from the installed
    /// collector's buffered traces. Returns the empty vector
    /// when no collector is installed or the collector does not
    /// buffer traces.
    pub fn get_perf_summary(&self) -> Vec<crate::perf::PerfSummary> {
        let traces = self.collect_perf_stats();
        if traces.is_empty() {
            return Vec::new();
        }
        // Group traces by operation id, then summarize each
        // group. We re-implement
        // [`InMemoryPerfCollector::summarize`] here so the
        // dashboard works against any [`crate::perf::PerfCollector`]
        // that returns a non-empty snapshot.
        let mut by_op: std::collections::HashMap<String, Vec<crate::perf::PerfTrace>> =
            std::collections::HashMap::new();
        for t in traces {
            by_op.entry(t.operation.clone()).or_default().push(t);
        }
        by_op
            .into_iter()
            .filter_map(|(op, traces)| crate::perf::summarize_traces(&op, &traces))
            .collect()
    }

    /// Phase 7 (2026-05-04 batch 10) — Task 7: budget check
    /// dashboard. Compares [`Self::get_perf_summary`] output
    /// against the supplied budgets and returns every violation.
    /// Empty `budgets` slice is allowed — the result is
    /// always empty.
    pub fn check_perf_budgets(
        &self,
        budgets: &[crate::perf::PerfBudget],
    ) -> Vec<crate::perf::BudgetViolation> {
        let summaries = self.get_perf_summary();
        crate::perf::check_budgets(&summaries, budgets)
    }

    /// Best-effort emit of one [`crate::perf::PerfTrace`] record
    /// into the installed collector. No-op when no collector is
    /// installed.
    fn record_perf_trace(&self, trace: crate::perf::PerfTrace) {
        if let Ok(slot) = self.perf_collector.lock() {
            if let Some(collector) = slot.as_ref() {
                collector.record(trace);
            }
        }
    }

    /// Install (or replace) the read-only dedup-analytics probe
    /// (Phase 7, batch-5 — 2026-05-04). Wrapped in `Arc` so
    /// multiple workers can share one probe. See
    /// `crates/core/src/transport/dedup_analytics.rs` for the
    /// privacy contract — the probe MUST NOT receive plaintext,
    /// derived plaintext (FTS tokens, embeddings), or media
    /// bytes.
    pub fn install_dedup_analytics(
        &self,
        probe: std::sync::Arc<dyn crate::transport::dedup_analytics::DedupAnalytics>,
    ) -> Result<()> {
        *self.dedup_analytics.lock().map_err(poisoned)? = Some(probe);
        Ok(())
    }

    /// Whether [`Self::install_dedup_analytics`] has been called
    /// with a real probe.
    pub fn has_dedup_analytics(&self) -> bool {
        self.dedup_analytics
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Read the current dedup-ratio snapshot for `tenant_id`.
    /// Returns [`crate::Error::NotImplemented("dedup_analytics")`]
    /// when no probe is installed (so callers can pattern-match
    /// on the missing-capability case identically to every other
    /// optional CoreImpl seam).
    pub fn query_dedup_stats(
        &self,
        tenant_id: &str,
    ) -> Result<crate::transport::dedup_analytics::DedupStats> {
        let slot = self.dedup_analytics.lock().map_err(poisoned)?;
        match slot.as_ref() {
            Some(p) => p.query_dedup_ratio(tenant_id),
            None => Err(crate::Error::NotImplemented("dedup_analytics")),
        }
    }

    /// Read the cumulative storage-savings snapshot for
    /// `tenant_id`. Same behavior as
    /// [`Self::query_dedup_stats`] — returns
    /// [`crate::Error::NotImplemented("dedup_analytics")`] when no
    /// probe is installed.
    pub fn query_storage_savings(
        &self,
        tenant_id: &str,
    ) -> Result<crate::transport::dedup_analytics::StorageSavings> {
        let slot = self.dedup_analytics.lock().map_err(poisoned)?;
        match slot.as_ref() {
            Some(p) => p.query_storage_savings(tenant_id),
            None => Err(crate::Error::NotImplemented("dedup_analytics")),
        }
    }

    /// Phase 7 (2026-05-04 batch 10 — Task 10): record one
    /// dedup event into the installed probe (if any). No-ops
    /// when no probe is installed so the upload hot paths never
    /// pay for a hashmap lookup.
    pub fn record_dedup_event(
        &self,
        event: crate::transport::dedup_analytics::DedupEvent,
    ) -> Result<()> {
        let slot = self.dedup_analytics.lock().map_err(poisoned)?;
        match slot.as_ref() {
            Some(p) => p.record_event(event),
            None => Ok(()),
        }
    }

    /// Phase 7 (2026-05-04 batch 10 — Task 10): build a
    /// [`crate::transport::dedup_analytics::DedupDashboard`] for
    /// `tenant_id`. The dashboard combines the upstream
    /// `query_dedup_ratio` / `query_storage_savings` snapshots
    /// with the local `recent_events` ring buffer.
    pub fn get_dedup_dashboard(
        &self,
        tenant_id: &str,
    ) -> Result<crate::transport::dedup_analytics::DedupDashboard> {
        let probe = match self.dedup_analytics.lock().map_err(poisoned)?.as_ref() {
            Some(p) => std::sync::Arc::clone(p),
            None => return Err(crate::Error::NotImplemented("dedup_analytics")),
        };
        Ok(crate::transport::dedup_analytics::DedupDashboard {
            stats: probe.query_dedup_ratio(tenant_id)?,
            savings: probe.query_storage_savings(tenant_id)?,
            recent_events: probe.recent_events(),
        })
    }

    /// Install (or replace) the multi-scope search resolver
    /// (Phase 8, batch-5 — 2026-05-04). Wrapped in `Arc` so the
    /// orchestration layer can share one resolver across worker
    /// threads. When no resolver is installed, the query engine
    /// uses the default
    /// [`crate::search::search_target::NoopConversationGroupResolver`].
    pub fn install_conversation_group_resolver(
        &self,
        resolver: std::sync::Arc<dyn crate::search::search_target::ConversationGroupResolver>,
    ) -> Result<()> {
        *self.conversation_group_resolver.lock().map_err(poisoned)? = Some(resolver);
        Ok(())
    }

    /// Whether [`Self::install_conversation_group_resolver`] has
    /// been called.
    pub fn has_conversation_group_resolver(&self) -> bool {
        self.conversation_group_resolver
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    /// Phase 7, batch-5 — build a media-migration plan that
    /// moves every `media_asset` row whose `storage_sink` is
    /// `source_sink` to `target_sink`. Wraps
    /// [`crate::media::migration::plan_media_migration`].
    pub fn plan_media_migration(
        &self,
        source_sink: &str,
        target_sink: &str,
    ) -> Result<crate::media::migration::MediaMigrationPlan> {
        let db = self.db.lock().map_err(poisoned)?;
        crate::media::migration::plan_media_migration(&db, source_sink, target_sink)
            .map_err(|e| crate::Error::Storage(e.to_string()))
    }

    /// Phase 7, batch-5 — execute a previously-built migration
    /// plan against the supplied sinks. The orchestration
    /// layer is responsible for constructing the plan via
    /// [`Self::plan_media_migration`] and for handing in
    /// `MediaBlobSink` impls for both the source and the
    /// target. The caller decides whether to delete the source
    /// blobs after a successful migration.
    ///
    /// The DB lock is **not** held across the migration — we
    /// hand the executor a
    /// [`crate::media::migration::LockingDbHandle`] which
    /// re-acquires `self.db` per DB call (idempotency probe +
    /// storage-sink update). The chunk-fetch / chunk-upload /
    /// roundtrip-verify phases (potentially minutes of network
    /// I/O against iCloud / Google Drive / ZKOF) run with the
    /// DB lock released so concurrent ingest / search / backup
    /// workers continue to make progress.
    pub fn migrate_media_sink(
        &self,
        plan: &crate::media::migration::MediaMigrationPlan,
        source: &dyn crate::media::sinks::MediaBlobSink,
        target: &dyn crate::media::sinks::MediaBlobSink,
        progress: &dyn crate::media::migration::MigrationProgress,
        delete_source_after_success: bool,
    ) -> Result<crate::media::migration::MigrationReport> {
        let handle = crate::media::migration::LockingDbHandle::new(&self.db);
        crate::media::migration::execute_media_migration(
            plan,
            source,
            target,
            &handle,
            progress,
            delete_source_after_success,
        )
    }

    /// Phase 7 (2026-05-04 batch 10 — Task 9): schedule the
    /// supplied [`crate::media::migration::MediaMigrationPlan`]
    /// as a one-off background task on the installed
    /// [`crate::scheduler::BackgroundScheduler`].
    ///
    /// Returns `Ok(false)` (without scheduling anything) when the
    /// plan is empty — the orchestration layer should not queue
    /// no-op work.
    ///
    /// Returns `Err(Error::NotImplemented("scheduler"))` when no
    /// scheduler is installed.
    pub fn schedule_media_migration(
        &self,
        plan: &crate::media::migration::MediaMigrationPlan,
        constraints: crate::scheduler::TaskConstraints,
    ) -> Result<bool> {
        if plan.items.is_empty() {
            return Ok(false);
        }
        let scheduler_guard = self.scheduler.lock().map_err(poisoned)?;
        let scheduler = match scheduler_guard.as_ref() {
            Some(s) => s,
            None => return Err(Error::NotImplemented("scheduler")),
        };
        let snapshot = crate::scheduler::MediaMigrationPlanSnapshot::from_plan(plan);
        scheduler
            .schedule_one_off_task(
                crate::scheduler::OneOffTask::MediaMigration { plan: snapshot },
                constraints,
            )
            .map(|_| true)
    }

    /// Plan and (when the resulting plan is non-empty) schedule
    /// a media-migration one-off task between
    /// `(source_sink, target_sink)`. Convenience wrapper that
    /// calls [`Self::plan_media_migration`] followed by
    /// [`Self::schedule_media_migration`] with
    /// [`crate::scheduler::TaskConstraints::wifi_and_charging`].
    pub fn plan_and_schedule_media_migration(
        &self,
        source_sink: &str,
        target_sink: &str,
    ) -> Result<bool> {
        let plan = self.plan_media_migration(source_sink, target_sink)?;
        self.schedule_media_migration(
            &plan,
            crate::scheduler::TaskConstraints::wifi_and_charging(),
        )
    }

    /// Run a unified search scoped to `target`. Phase-8 entry
    /// point that ferries the installed
    /// [`crate::search::search_target::ConversationGroupResolver`]
    /// (or the [`crate::search::search_target::NoopConversationGroupResolver`]
    /// default) into [`crate::search::query_engine::QueryEngine::execute_search_with_target`].
    pub fn search_with_target(
        &self,
        query: &crate::SearchQuery,
        scope: &crate::SearchScope,
        target: &crate::SearchTarget,
        limit: usize,
    ) -> Result<Vec<crate::SearchResult>> {
        let db = self.db.lock().map_err(poisoned)?;
        let installed = self
            .conversation_group_resolver
            .lock()
            .map_err(poisoned)?
            .clone();
        let resolver: std::sync::Arc<dyn crate::search::search_target::ConversationGroupResolver> =
            installed.unwrap_or_else(|| {
                std::sync::Arc::new(
                    crate::search::search_target::NoopConversationGroupResolver::new(),
                )
            });
        crate::search::query_engine::QueryEngine::new(&db)
            .execute_search_with_target(query, scope, target, resolver.as_ref(), limit)
            .map_err(|e| crate::Error::Search(e.to_string()))
    }

    /// Replay the supplied search-index shards into the local
    /// `search_fts` / `search_fuzzy` tables (Phase 4, Task 6).
    ///
    /// Wires
    /// [`crate::restore::pipeline::RestorePipeline::restore_search_index_shards_with_replay`]
    /// to the `CoreImpl` so the orchestration layer can drive a
    /// shard restore without owning a `RestorePipeline` instance.
    /// The transport-side contract on `BackupSource` does not yet
    /// carry shard segments; once it does, this entry point is the
    /// natural binding glue.
    pub fn restore_search_shards(
        &self,
        shards: &[crate::restore::pipeline::SealedSearchShardEntry<'_>],
    ) -> Result<Vec<crate::restore::pipeline::RestoredShardSummary>> {
        let mut db = self.db.lock().map_err(poisoned)?;
        crate::restore::pipeline::RestorePipeline::new()
            .restore_search_index_shards_with_replay(db.connection_mut(), shards)
    }

    /// Fan out one
    /// [`crate::search::shard_prefetch::batch_prefetch_shards`]
    /// call for `(conversation_id, time_bucket)`, AEAD-open every
    /// returned [`crate::search::shard_prefetch::PrefetchedShard`]
    /// under the shard key the caller registered for the triple,
    /// and replay the contained rows into the local
    /// `search_fts` / `search_fuzzy` tables (Phase 5, Task 2).
    ///
    /// Returns a [`RestoreColdShardsSummary`] describing how many
    /// shards came back and how many rows landed in each table.
    /// An empty bucket (no shards staged on the backend) returns
    /// the zero summary without touching the local DB. A wrong
    /// shard key surfaces as `Err(Error::Crypto)` from the
    /// underlying AEAD open.
    ///
    /// `key_registry` carries the per-shard
    /// `K_text_index_shard(shard_id)` /
    /// `K_fuzzy_index_shard(shard_id)` lookups the orchestration
    /// layer keeps in memory; missing entries cause an
    /// `Error::Storage` describing the missing triple. The
    /// `conversation_hash_key` is the per-account
    /// `K_conv_hash_key` mapped onto the wire-format
    /// `conversation_hash` the backend stores shards under.
    pub fn fetch_and_restore_cold_shards(
        &self,
        transport: &dyn TransportClient,
        conversation_id: &str,
        time_bucket: &str,
        conversation_hash_key: &crate::crypto::key_hierarchy::KeyMaterial,
        key_registry: &crate::search::cold_shard_source::ShardKeyRegistry,
    ) -> Result<RestoreColdShardsSummary> {
        use crate::formats::search_shard::{IndexType, SearchIndexShard};
        use crate::restore::pipeline::SealedSearchShardEntry;
        use crate::search::shard_prefetch::batch_prefetch_shards;

        let conv_hash = crate::search::shard_builder::keyed_conversation_id_hash(
            conversation_id,
            conversation_hash_key,
        );
        let conv_hash_b64 = base64_urlsafe_encode(&conv_hash);

        let prefetched = batch_prefetch_shards(transport, &conv_hash_b64, time_bucket)?;
        if prefetched.is_empty() {
            return Ok(RestoreColdShardsSummary {
                conversation_id: conversation_id.into(),
                time_bucket: time_bucket.into(),
                fetched_shards: 0,
                text_rows_inserted: 0,
                fuzzy_rows_inserted: 0,
            });
        }

        // Decode each ciphertext blob into a `SearchIndexShard`
        // and pair it with the shard key the registry holds for
        // the (conv, bucket, type) triple. We materialise both
        // owned vectors first so the borrowed
        // `SealedSearchShardEntry` slices below stay valid for
        // the duration of the replay call.
        let mut owned: Vec<(
            IndexType,
            SearchIndexShard,
            crate::crypto::key_hierarchy::KeyMaterial,
        )> = Vec::with_capacity(prefetched.len());
        for ps in prefetched {
            let shard: SearchIndexShard = crate::cbor::from_slice(&ps.ciphertext).map_err(|e| {
                Error::Storage(format!(
                    "fetch_and_restore_cold_shards: shard cbor decode failed for ({conversation_id}, {time_bucket}, {:?}): {e}",
                    ps.shard_type,
                ))
            })?;
            let k = key_registry
                .get(conversation_id, time_bucket, ps.shard_type)
                .ok_or_else(|| {
                    Error::Storage(format!(
                        "fetch_and_restore_cold_shards: missing shard key for ({conversation_id}, {time_bucket}, {:?})",
                        ps.shard_type,
                    ))
                })?
                .clone();
            owned.push((ps.shard_type, shard, k));
        }

        let entries: Vec<SealedSearchShardEntry<'_>> = owned
            .iter()
            .map(|(_t, shard, k)| SealedSearchShardEntry { shard, k_shard: k })
            .collect();

        let summaries = {
            let mut db = self.db.lock().map_err(poisoned)?;
            crate::restore::pipeline::RestorePipeline::new()
                .restore_search_index_shards_with_replay(db.connection_mut(), &entries)?
        };

        let mut text_rows_inserted = 0usize;
        let mut fuzzy_rows_inserted = 0usize;
        for s in &summaries {
            match s.index_type {
                IndexType::Text => text_rows_inserted += s.rows_inserted,
                IndexType::Fuzzy => fuzzy_rows_inserted += s.rows_inserted,
                _ => {} // vector / media shards currently no-op
            }
        }

        Ok(RestoreColdShardsSummary {
            conversation_id: conversation_id.into(),
            time_bucket: time_bucket.into(),
            fetched_shards: summaries.len(),
            text_rows_inserted,
            fuzzy_rows_inserted,
        })
    }

    /// Whether [`Self::install_zkof_archive_backend`] has been
    /// called.
    pub fn has_zkof_archive_backend(&self) -> bool {
        self.zkof_archive_s3
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
            && self
                .zkof_archive_config
                .lock()
                .map(|slot| slot.is_some())
                .unwrap_or(false)
    }

    /// Cold-result hydration write-back (Phase 5, Task 3).
    ///
    /// Walks the supplied [`SearchResult`] vec, picks out the
    /// rows flagged `is_cold = true`, groups them by
    /// `(conversation_id, time_bucket)`, fetches every
    /// `archive_segment_map` row that covers the bucket via
    /// [`crate::archive::prefetch::batch_prefetch_bucket_with_router`]
    /// (so `storage_backend = zk_object_fabric` rows fetch
    /// through ZKOF / S3 instead of the KChat transport),
    /// AEAD-decrypts the segment, scans the events for the
    /// requested `message_id`s, decodes the payload via
    /// [`crate::archive::body_payload::try_decode_text`], and
    /// finally calls
    /// [`Self::rehydrate_message_body_locally`] to write the
    /// body back into the local store and re-index the
    /// `search_fts` / `search_fuzzy` rows.
    ///
    /// `key_for_segment` is the same closure shape used by
    /// [`Self::rehydrate_timeline_skeletons`] — the
    /// orchestration layer maps `segment_id → epoch_key_bytes`.
    ///
    /// The call is **idempotent**: hydrating a row whose body
    /// is already
    /// [`BodyState::LocalPlainAvailable`] is a no-op (the body
    /// upsert and FTS / fuzzy refresh hit the same SAVEPOINT and
    /// re-converge to the same state). Cold rows whose archive
    /// payload predates the body-bearing variant
    /// (legacy 4-tuple [`crate::message::processor::encode_event_payload`])
    /// silently skip — see
    /// [`crate::archive::body_payload::try_decode_text`] for the
    /// fallback rule.
    ///
    /// Returns the number of message bodies that were actually
    /// rehydrated. A failure on any single message surfaces as
    /// `Err`; partial progress is allowed because each
    /// `rehydrate_message_body_locally` runs inside its own
    /// SAVEPOINT and earlier successful rehydrations stay
    /// committed even if a later one fails.
    pub fn hydrate_cold_search_results(
        &self,
        transport: &dyn TransportClient,
        results: &[SearchResult],
        mut key_for_segment: impl FnMut(&str) -> Result<[u8; 32]>,
    ) -> Result<usize> {
        use std::collections::{BTreeMap, BTreeSet};

        // Group cold (conversation_id, time_bucket) pairs to a
        // BTreeSet of message_ids the caller actually wants
        // hydrated. Using a `BTreeMap` keeps the ordering stable
        // for tests and avoids a duplicate fetch when two cold
        // hits land in the same bucket.
        let mut buckets: BTreeMap<(Uuid, String), BTreeSet<Uuid>> = BTreeMap::new();
        for r in results.iter().filter(|r| r.is_cold) {
            let bucket =
                crate::archive::segment_builder::default_time_bucket_for_ms(r.created_at_ms);
            buckets
                .entry((r.conversation_id, bucket))
                .or_default()
                .insert(r.message_id);
        }
        if buckets.is_empty() {
            return Ok(0);
        }

        // Build the backend-aware router *once* before the
        // bucket loop so a re-acquire of the ZKOF config locks
        // does not happen on every iteration. The router
        // dispatches each `archive_segment_map` row to the
        // backend named in its `storage_backend` column —
        // KChat rows go through `transport`, ZKOF rows go
        // through the installed S3 client. Mirrors the wiring
        // used by [`Self::rehydrate_timeline_skeletons`].
        let router = self.build_archive_router(transport)?;

        let mut hydrated = 0usize;
        for ((conv_id, time_bucket), wanted_ids) in buckets {
            // Phase 1: fetch every segment for the bucket. Read
            // under the DB lock just long enough to enumerate
            // the segment rows, then drop so the per-segment
            // decrypt + replay does not starve concurrent
            // readers.
            let prefetched = {
                let db = self.db.lock().map_err(poisoned)?;
                crate::archive::prefetch::batch_prefetch_bucket_with_router(
                    db.connection(),
                    &router,
                    conv_id,
                    &time_bucket,
                )?
            };

            // Phase 2: walk events; for each wanted message_id
            // try to extract a text body from the archive
            // payload and rehydrate it.
            for segment in prefetched {
                let k_bytes = key_for_segment(&segment.segment_id)?;
                let plaintext = crate::archive::download::decrypt_archive_segment(
                    &segment.ciphertext,
                    &k_bytes,
                )?;
                let payload = crate::archive::download::decode_archive_segment_payload(&plaintext)?;
                for event in payload.events {
                    let Some(mid) = event.message_id else {
                        continue;
                    };
                    if event.conversation_id != conv_id || !wanted_ids.contains(&mid) {
                        continue;
                    }
                    // Tombstones do not carry a body — leave the
                    // skeleton in its current state.
                    if !matches!(
                        event.event_type,
                        crate::archive::event_journal::ArchiveEventType::MessageReceived
                            | crate::archive::event_journal::ArchiveEventType::MessageEdited,
                    ) {
                        continue;
                    }
                    let Some(text) = crate::archive::body_payload::try_decode_text(&event.payload)
                    else {
                        continue;
                    };
                    self.rehydrate_message_body_locally(
                        mid,
                        &text,
                        BodyState::LocalPlainAvailable,
                    )?;
                    hydrated += 1;
                }
            }
        }
        Ok(hydrated)
    }

    /// Backend-aware variant of [`Self::rehydrate_timeline_skeletons`].
    /// Routes per-row fetches through the supplied
    /// [`crate::archive::download::ArchiveSegmentRouter`] so
    /// `archive_segment_map.storage_backend = zk_object_fabric` rows
    /// land via S3 instead of the legacy KChat transport.
    pub fn rehydrate_timeline_skeletons_with_router<F>(
        &self,
        router: &crate::archive::download::ArchiveSegmentRouter<'_>,
        conversation_id: Uuid,
        time_bucket: &str,
        mut key_for_segment: F,
    ) -> Result<Vec<MessageSkeleton>>
    where
        F: FnMut(&str) -> Result<[u8; 32]>,
    {
        let segments = {
            let db = self.db.lock().map_err(poisoned)?;
            crate::archive::prefetch::batch_prefetch_bucket_with_router(
                db.connection(),
                router,
                conversation_id,
                time_bucket,
            )?
        };

        let mut inserted: Vec<MessageSkeleton> = Vec::new();
        let received_at_ms = now_ms_for_send_media();
        for segment in segments {
            let k_bytes = key_for_segment(&segment.segment_id)?;
            let plaintext_cbor =
                crate::archive::download::decrypt_archive_segment(&segment.ciphertext, &k_bytes)?;
            let payload =
                crate::archive::download::decode_archive_segment_payload(&plaintext_cbor)?;

            // Drop into the DB lock once per segment so the worker
            // doesn't starve out-of-band reads while we land a
            // potentially long event list.
            let db = self.db.lock().map_err(poisoned)?;
            for event in payload.events {
                let Some(message_id) = event.message_id else {
                    continue;
                };
                if event.conversation_id != conversation_id {
                    continue;
                }
                let stub = MessageSkeleton {
                    message_id: message_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    sender_id: String::new(),
                    created_at_ms: event.created_at_ms,
                    received_at_ms,
                    kind: MessageKind::Text,
                    body_state: BodyState::RemoteArchiveOnly,
                    media_state: None,
                    archive_state: ArchiveState::ArchiveUploaded,
                    backup_state: BackupState::NotBackedUp,
                    reply_to: None,
                    edited_at_ms: None,
                    deleted_at_ms: None,
                };
                let landed = db
                    .upsert_skeleton_from_archive(&stub)
                    .map_err(|e| Error::Storage(e.to_string()))?;
                if landed {
                    inserted.push(stub);
                }
            }
        }
        Ok(inserted)
    }

    // ----------------------------------------------------------------
    // Lazy media rehydration on tap (Task 5 — `docs/PROPOSAL.md §5.5`)
    // ----------------------------------------------------------------

    /// Rehydrate the media blob attached to `message_id` from the
    /// configured sink, transitioning the asset's
    /// [`MediaState`] from `Evicted` (or `RemoteOriginal`) to
    /// `OriginalLocal` once the bytes land on disk.
    ///
    /// Wraps [`crate::media::download::rehydrate_media_asset`] but
    /// resolves the `asset_id` from the message-key by calling
    /// [`LocalStoreDb::get_media_asset_by_message`] — the public
    /// API for the on-tap UI flow described in
    /// `docs/PROPOSAL.md §5.2`.
    ///
    /// Returns `Ok(Some(plaintext))` when a download was issued,
    /// `Ok(None)` when no media row is attached to `message_id`.
    /// Already-local assets surface as `Error::Storage`, mirroring
    /// the underlying [`crate::media::download::rehydrate_media_asset`]
    /// state-machine guard.
    pub fn rehydrate_media_for_message(
        &self,
        transport: &dyn TransportClient,
        message_id: Uuid,
        wrapping_key: &[u8; KEY_LEN],
    ) -> Result<Option<Vec<u8>>> {
        let mid = message_id.to_string();

        // Phase 1: read all metadata under the db lock, then drop
        // the guard so the long-running chunked download in
        // phase 2 doesn't block concurrent
        // `send_text` / `search` / `ingest` callers
        // (Task 2 of the Phase 3/4 batch).
        let plan = {
            let db = self.db.lock().map_err(poisoned)?;
            let Some(asset) = db
                .get_media_asset_by_message(&mid)
                .map_err(|e| Error::Storage(e.to_string()))?
            else {
                return Ok(None);
            };
            crate::media::download::prepare_rehydration(&db, &asset.asset_id)?
            // MutexGuard drops here on the closing brace.
        };

        // Phase 2: chunked download, AEAD-open, BLAKE3 verify —
        // no db reference held.
        let plaintext =
            crate::media::download::execute_rehydration_download(&plan, transport, wrapping_key)?;

        // Phase 3: re-acquire the db lock and flip the state
        // machine + bytes_local under SAVEPOINT.
        {
            let db = self.db.lock().map_err(poisoned)?;
            crate::media::download::commit_rehydration(
                &db,
                &plan.asset_id,
                plan.from_state,
                plaintext.len(),
            )?;
        }

        Ok(Some(plaintext))
    }

    /// Persist a slice of MLS-decrypted messages into the local
    /// store.
    ///
    /// Each message is run through [`MessagePersister::persist_ingested_message`].
    /// Duplicates (same `message_id`) increment `duplicate_count`
    /// without raising an error — every other [`ProcessorError`] is
    /// surfaced.
    ///
    /// This is the **inherent** entry point used in Phase 1 while
    /// the transport-driven [`KChatCore::ingest_remote_messages`]
    /// trait method is still a stub.
    ///
    /// Phase 6, Task 2 / Task 10: when a [`crate::models::embeddings::TextEmbedder`]
    /// has been installed via [`Self::install_text_embedder`],
    /// each text body is embedded and written to `search_vector`
    /// via the [`crate::models::embeddings::EmbeddingCache`]
    /// surface. The embedding step is best-effort (logged on
    /// failure, never propagated) so an inference / cache hiccup
    /// cannot poison the ingest path. A pre-existing cache hit
    /// short-circuits inference — the cross-pipeline cache is
    /// shared with `kennguy3n/slm-guardrail`, so a guardrail-
    /// computed vector is not re-encoded by the search pipeline.
    // The `#[tracing::instrument]` field names below are kept in
    // lockstep with the `PerfTrace::insert_metadata` keys inside
    // the method body. The mapping is:
    //
    //   tracing field     PerfTrace key      source
    //   --------------    ---------------    ----------------------
    //   messages_in       messages_in        input slice length
    //   new_messages      new_messages       result.new_messages
    //   duplicate_count   duplicate_count    result.duplicate_count
    //   embeddings_computed embeddings_computed running counter
    //
    // Keeping the two surfaces aligned means a dashboard consumer
    // can read the same value off either source without a rename
    // table, and saves a maintainer from chasing two different
    // names for the same thing.
    #[tracing::instrument(
        skip(self, messages),
        fields(
            messages_in = messages.len(),
            new_messages = tracing::field::Empty,
            duplicate_count = tracing::field::Empty,
            embeddings_computed = tracing::field::Empty,
        ),
    )]
    pub fn ingest_messages(&self, messages: &[IngestedMessage]) -> Result<IngestResult> {
        // Phase 7, Task 8 (2026-05-04 batch): wrap the ingest hot
        // path with a [`crate::perf::PerfTrace`] so an installed
        // collector can measure end-to-end ingest latency. We
        // record `messages_in` (input batch size) and the result
        // counters once they're known. Failures still record so
        // the trace surface includes both successful and failed
        // bursts.
        //
        // The `#[tracing::instrument]` above mirrors the PerfTrace
        // surface into the OS log stream so the same hot path is
        // visible to both the in-app perf collector (PerfTrace)
        // and to a platform-native log subscriber (e.g. os_log /
        // logcat) without duplicate plumbing. The deferred
        // (`tracing::field::Empty`) fields are filled in via
        // `Span::current().record` at the same point the PerfTrace
        // metadata is recorded.
        let span = tracing::Span::current();
        let mut trace = crate::perf::PerfTrace::new("ingest_messages");
        trace.insert_metadata("messages_in", messages.len().to_string());

        let db = match self.db.lock().map_err(poisoned) {
            Ok(db) => db,
            Err(e) => {
                trace.insert_metadata("error", e.to_string());
                trace.finish();
                self.record_perf_trace(trace);
                return Err(e);
            }
        };
        let persister = MessagePersister::new(&db);
        let mut result = IngestResult::default();
        let mut embeddings_computed: usize = 0;
        for msg in messages {
            match persister.persist_ingested_message(msg) {
                Ok(_) => {
                    result.new_messages += 1;
                    // Best-effort cross-pipeline embedding (Phase 6,
                    // Task 2 / 10). Failures are absorbed because
                    // the message is already persisted; semantic
                    // search will still work for messages that DID
                    // embed successfully, and the next ingest will
                    // retry this row's embedding the moment a real
                    // embedder is installed. The bool return tells
                    // us whether a vector was actually written so
                    // the span field reflects real work done, not
                    // attempted work.
                    if self.maybe_embed_text_message(&db, msg) {
                        embeddings_computed += 1;
                    }
                }
                Err(ProcessorError::DuplicateMessage) => result.duplicate_count += 1,
                Err(e) => {
                    trace.insert_metadata("error", e.to_string());
                    trace.finish();
                    self.record_perf_trace(trace);
                    return Err(Error::Message(e.to_string()));
                }
            }
        }
        trace.insert_metadata("new_messages", result.new_messages.to_string());
        trace.insert_metadata("duplicate_count", result.duplicate_count.to_string());
        trace.insert_metadata("embeddings_computed", embeddings_computed.to_string());
        span.record("new_messages", result.new_messages);
        span.record("duplicate_count", result.duplicate_count);
        span.record("embeddings_computed", embeddings_computed);

        // Phase 7 (2026-05-04 batch 10) — Task 5/6: forward the
        // batch to any installed Spotlight / Windows Search
        // bridge. Best-effort — failures here must not roll
        // back the ingested rows.
        drop(db);
        self.maybe_index_in_desktop_search(messages);

        trace.finish();
        self.record_perf_trace(trace);
        Ok(result)
    }

    /// Best-effort cross-pipeline text embedding. Runs only when
    /// (a) a [`crate::models::embeddings::TextEmbedder`] is
    /// installed, (b) the message has a text body, and (c) the
    /// shared embedding cache does not already carry a row for
    /// `(message_id, XLMR_MODEL_VERSION)`. All errors are
    /// swallowed — see [`Self::ingest_messages`] for the
    /// rationale.
    /// Returns `true` when this call actually wrote a new vector to
    /// the embedding cache. Cache hits, missing-embedder, missing
    /// text body, poisoned mutex, and inference failure all return
    /// `false`. The caller uses this to count *real* embedding work
    /// done by an `ingest_messages` batch for the span /
    /// `PerfTrace` `embeddings_computed` field — distinct from the
    /// `new_messages` count (which counts persisted rows).
    fn maybe_embed_text_message(&self, db: &LocalStoreDb, msg: &IngestedMessage) -> bool {
        use crate::models::embeddings::{
            EmbeddingCache, LocalStoreEmbeddingCache, XLMR_MODEL_VERSION,
        };

        let Some(text) = msg.text_content.as_deref() else {
            return false;
        };
        let Ok(slot) = self.text_embedder.lock() else {
            return false;
        };
        let Some(embedder) = slot.as_ref() else {
            // No embedder installed — semantic search still works for
            // messages embedded by a previous run, but new rows will
            // not contribute vectors until `install_text_embedder` is
            // called. Trace at debug level (not warn) because the
            // unbound state is normal on cold start before the bridge
            // wires up ONNX; warning on every ingest would flood logs.
            tracing::debug!(
                target: "kchat_core::embeddings",
                model = "xlmr",
                "text_embedder not installed; skipping embedding"
            );
            return false;
        };

        let cache = LocalStoreEmbeddingCache::new(db.connection());
        let mid = msg.message_id.to_string();
        // Cache hit short-circuits inference. The guardrail
        // pipeline writes through the same SQLCipher row, so a
        // cross-pipeline hit is the norm in production.
        if let Ok(Some(_)) = cache.get(&mid, XLMR_MODEL_VERSION) {
            return false;
        }
        match embedder.embed(text) {
            Ok(vec) => cache.put(&mid, XLMR_MODEL_VERSION, &vec).is_ok(),
            Err(_) => {
                // Inference failures are absorbed: the message is
                // already searchable via FTS5 + fuzzy. Telemetry
                // for the failure path is the bridge crate's job
                // (it sees the raw embed error before installing
                // its TextEmbedder).
                false
            }
        }
    }

    /// Phase 7 (2026-05-04 batch 10) — Task 5/6: best-effort
    /// fan-out of newly ingested messages to the installed
    /// macOS Spotlight / Windows Search bridges. No-op on
    /// platforms where no bridge has been installed. Errors
    /// from the bridge are swallowed because the message has
    /// already been persisted; failure to update the OS search
    /// index must not roll back ingest.
    fn maybe_index_in_desktop_search(&self, messages: &[IngestedMessage]) {
        if messages.is_empty() {
            return;
        }
        let has_spotlight = self
            .spotlight_anchor
            .lock()
            .map(|s| s.is_some())
            .unwrap_or(false);
        let has_windows = self
            .windows_search_anchor
            .lock()
            .map(|s| s.is_some())
            .unwrap_or(false);
        if !has_spotlight && !has_windows {
            return;
        }
        // Build a redacted preview per message — first 80 chars
        // of the text body. Media-only messages are skipped to
        // avoid leaking sender identifiers without consent.
        let mut spotlight_items = Vec::new();
        let mut windows_items = Vec::new();
        for msg in messages {
            let Some(text) = msg.text_content.as_deref() else {
                continue;
            };
            let preview: String = text.chars().take(80).collect();
            let unique_id = msg.message_id.to_string();
            let conversation_id = msg.conversation_id.to_string();
            if has_spotlight {
                spotlight_items.push(crate::desktop_index::SpotlightItem {
                    unique_id: unique_id.clone(),
                    title: msg.sender_id.clone(),
                    content_description: preview.clone(),
                    display_name: msg.sender_id.clone(),
                    timestamp: msg.created_at_ms,
                    conversation_id: conversation_id.clone(),
                });
            }
            if has_windows {
                windows_items.push(crate::desktop_index::WindowsSearchItem {
                    unique_id,
                    title: msg.sender_id.clone(),
                    content_description: preview,
                    display_name: msg.sender_id.clone(),
                    timestamp: msg.created_at_ms,
                    conversation_id,
                });
            }
        }
        if has_spotlight && !spotlight_items.is_empty() {
            let _ = self.update_spotlight_index(&spotlight_items);
        }
        if has_windows && !windows_items.is_empty() {
            let _ = self.update_windows_search_index(&windows_items);
        }
    }

    /// Best-effort cross-pipeline image embedding (Phase 6,
    /// Task 9). Runs only when (a) an
    /// [`crate::models::clip::ImageEmbedder`] is installed,
    /// (b) `mime_type` advertises an image, and (c) the shared
    /// embedding cache does not already carry a row for
    /// `(message_id, MOBILECLIP_S2_MODEL_VERSION)`. All errors
    /// are swallowed — see [`Self::ingest_messages`] for the
    /// rationale.
    fn maybe_embed_image_message(
        &self,
        db: &LocalStoreDb,
        message_id: &str,
        mime_type: &str,
        plaintext: &[u8],
    ) {
        use crate::models::clip::MOBILECLIP_S2_MODEL_VERSION;
        use crate::models::embeddings::{EmbeddingCache, LocalStoreEmbeddingCache};

        if !mime_type.starts_with("image/") {
            return;
        }
        let Ok(slot) = self.image_embedder.lock() else {
            return;
        };
        let Some(embedder) = slot.as_ref() else {
            // Same rationale as `maybe_embed_text_message`: cold-start
            // before the bridge installs MobileCLIP-S2 is normal; a
            // warn-level event would flood logs. Stay at debug.
            tracing::debug!(
                target: "kchat_core::embeddings",
                model = "mobileclip_s2",
                "image_embedder not installed; skipping embedding"
            );
            return;
        };

        let cache = LocalStoreEmbeddingCache::new(db.connection());
        if let Ok(Some(_)) = cache.get(message_id, MOBILECLIP_S2_MODEL_VERSION) {
            return;
        }
        match embedder.embed_image(plaintext, mime_type) {
            Ok(vec) => {
                let _ = cache.put(message_id, MOBILECLIP_S2_MODEL_VERSION, &vec);
            }
            Err(_) => {
                // Inference failures are absorbed.
            }
        }
    }

    /// Best-effort Whisper transcription for audio media (Phase
    /// 6, Task 2 of the 2026-05-04 batch). Runs only when
    /// (a) a [`crate::models::whisper::WhisperTranscriber`] is
    /// installed, (b) `mime_type` indicates audio, and (c) the
    /// optional [`crate::models::resource_gate::ResourceProbe`]
    /// reports the device is willing to run transcription work
    /// (no probe installed = always allowed).
    ///
    /// The concatenated transcript lands in three places so the
    /// search engines all treat the audio body as a first-class
    /// searchable surface:
    ///
    /// * `media_search_index` keyed by `asset_id` with kind
    ///   `"transcript"` — for caller code that still consults
    ///   the legacy media-side index.
    /// * `search_fts` and `search_fuzzy`, keyed by `message_id`
    ///   — so a `core.search()` call ranks the audio message
    ///   alongside text bodies and OCR / caption rows.
    /// * Optionally [`crate::models::embeddings::LocalStoreEmbeddingCache`]
    ///   under `XLMR_MODEL_VERSION` when a `TextEmbedder` is
    ///   installed, so the semantic-search reranker can score
    ///   the audio body.
    ///
    /// All errors — inference failures, gate failures, and DB
    /// write failures — are absorbed; the message is already
    /// persisted and FTS-searchable through its caption.
    #[allow(clippy::too_many_arguments)]
    fn maybe_transcribe_audio_message(
        &self,
        db: &LocalStoreDb,
        message_id: &str,
        asset_id: &str,
        sender_id: &str,
        conversation_id: &str,
        created_at_ms: i64,
        mime_type: &str,
        plaintext: &[u8],
    ) {
        use crate::models::embeddings::{
            EmbeddingCache, LocalStoreEmbeddingCache, XLMR_MODEL_VERSION,
        };
        use crate::models::resource_gate::ResourceGate;
        use crate::search::fuzzy_search::FuzzySearchEngine;

        if !mime_type.starts_with("audio/") {
            return;
        }
        // Resource-gate transcription work. Whisper is the
        // strictest gate (`should_run_transcription`); skip
        // entirely when the gate refuses.
        if let Ok(slot) = self.resource_probe.lock() {
            if let Some(probe) = slot.as_ref() {
                let gate = ResourceGate::default();
                if !gate.should_run_transcription(&probe.current_resources()) {
                    return;
                }
            }
        }

        let Ok(slot) = self.whisper_transcriber.lock() else {
            return;
        };
        let Some(transcriber) = slot.as_ref() else {
            return;
        };
        let result = match transcriber.transcribe(plaintext, mime_type) {
            Ok(r) => r,
            Err(_) => return,
        };
        let transcript = result.text.trim();
        if transcript.is_empty() {
            return;
        }
        let language = result.language.as_deref();

        // (1) Legacy media-side index.
        let _ = db.insert_media_search_index(asset_id, "transcript", transcript, language, None);

        // (2) Cross-modal FTS / fuzzy index keyed by
        //     `message_id` — same shape `send_text` writes for
        //     plain text bodies. Best-effort; a duplicate row
        //     (e.g. the caption already inserted one) is
        //     harmless because `search_fts` is content-addressed
        //     by `(message_id, text_content)` from the engine's
        //     POV and the fuzzy index PK is `(token, script,
        //     message_id)`.
        let _ = db.connection().execute(
            "INSERT INTO search_fts(
                message_id, conversation_id, sender_id,
                created_at_ms, text_content
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                message_id,
                conversation_id,
                sender_id,
                created_at_ms,
                transcript,
            ],
        );
        let _ = FuzzySearchEngine::new(db).index_message(message_id, transcript);

        // (3) Optional XLM-R embedding so semantic search picks
        //     up the audio body.
        if let Ok(embedder_slot) = self.text_embedder.lock() {
            if let Some(embedder) = embedder_slot.as_ref() {
                let cache = LocalStoreEmbeddingCache::new(db.connection());
                if let Ok(None) = cache.get(message_id, XLMR_MODEL_VERSION) {
                    if let Ok(vec) = embedder.embed(transcript) {
                        let _ = cache.put(message_id, XLMR_MODEL_VERSION, &vec);
                    }
                }
            }
        }
    }

    /// Best-effort document text extraction for PDF / DOCX media
    /// (Phase 6, Task 3 of the 2026-05-04 batch). Runs only when
    /// (a) a [`crate::models::document::DocumentExtractor`] is
    /// installed and (b) `mime_type` is one of the supported
    /// document MIME types
    /// ([`crate::models::document::is_supported_document_mime`]).
    ///
    /// Each page lands in three places, mirroring the audio
    /// transcription fan-out in
    /// [`Self::maybe_transcribe_audio_message`]:
    ///
    /// * `media_search_index` keyed by `asset_id` with kind
    ///   `"caption"` and a `"[page N] …"` prefix for the legacy
    ///   media-side index.
    /// * `search_fts` and `search_fuzzy`, keyed by a synthetic
    ///   page row id (`{message_id}#page{N}`), so multilingual
    ///   document bodies show up in `core.search()` with
    ///   page-level granularity.
    /// * Optionally
    ///   [`crate::models::embeddings::LocalStoreEmbeddingCache`]
    ///   under `XLMR_MODEL_VERSION` when a `TextEmbedder` is
    ///   installed.
    ///
    /// Errors are absorbed.
    #[allow(clippy::too_many_arguments)]
    fn maybe_extract_document_pages(
        &self,
        db: &LocalStoreDb,
        message_id: &str,
        asset_id: &str,
        sender_id: &str,
        conversation_id: &str,
        created_at_ms: i64,
        mime_type: &str,
        plaintext: &[u8],
    ) {
        use crate::models::document::is_supported_document_mime;
        use crate::models::embeddings::{
            EmbeddingCache, LocalStoreEmbeddingCache, XLMR_MODEL_VERSION,
        };
        use crate::search::fuzzy_search::FuzzySearchEngine;

        if !is_supported_document_mime(mime_type) {
            return;
        }
        let Ok(slot) = self.document_extractor.lock() else {
            return;
        };
        let Some(extractor) = slot.as_ref() else {
            return;
        };
        let pages = match extractor.extract_text(plaintext, mime_type) {
            Ok(p) => p,
            Err(_) => return,
        };
        for page in pages {
            let trimmed = page.text.trim();
            if trimmed.is_empty() {
                continue;
            }
            let language = page.language.as_deref();
            let formatted = format!("[page {}] {}", page.page_number, trimmed);

            // (1) Legacy media-side caption row.
            let _ = db.insert_media_search_index(asset_id, "caption", &formatted, language, None);

            // (2) Page-level FTS / fuzzy rows keyed by a
            //     synthetic per-page id so the same `message_id`
            //     can land multiple FTS rows without colliding.
            let page_row_id = format!("{}#page{}", message_id, page.page_number);
            let _ = db.connection().execute(
                "INSERT INTO search_fts(
                    message_id, conversation_id, sender_id,
                    created_at_ms, text_content
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    page_row_id,
                    conversation_id,
                    sender_id,
                    created_at_ms,
                    trimmed,
                ],
            );
            let _ = FuzzySearchEngine::new(db).index_message(&page_row_id, trimmed);

            // (3) Optional XLM-R embedding per page.
            if let Ok(embedder_slot) = self.text_embedder.lock() {
                if let Some(embedder) = embedder_slot.as_ref() {
                    let cache = LocalStoreEmbeddingCache::new(db.connection());
                    if let Ok(None) = cache.get(&page_row_id, XLMR_MODEL_VERSION) {
                        if let Ok(vec) = embedder.embed(trimmed) {
                            let _ = cache.put(&page_row_id, XLMR_MODEL_VERSION, &vec);
                        }
                    }
                }
            }
        }
    }

    /// Best-effort video keyframe sampling + MobileCLIP-S2
    /// embedding fan-out for video media (Phase 6, Task 1 of
    /// the 2026-05-04 batch). Runs only when (a) a
    /// [`crate::models::video::VideoKeyframeSampler`] is
    /// installed, (b) an
    /// [`crate::models::clip::ImageEmbedder`] is installed, and
    /// (c) `mime_type` indicates video.
    ///
    /// Each extracted keyframe is embedded under
    /// `(message_id, "mobileclip_s2@v1_frame_{idx}")` so a
    /// single video message can land multiple cache rows. The
    /// canonical model_version row
    /// (`(message_id, MOBILECLIP_S2_MODEL_VERSION)`) is also
    /// written for the first frame so existing callers that
    /// look up the unsuffixed key continue to find a vector.
    fn maybe_embed_video_keyframes(
        &self,
        db: &LocalStoreDb,
        message_id: &str,
        mime_type: &str,
        plaintext: &[u8],
    ) {
        use crate::models::clip::MOBILECLIP_S2_MODEL_VERSION;
        use crate::models::embeddings::{EmbeddingCache, LocalStoreEmbeddingCache};

        if !mime_type.starts_with("video/") {
            return;
        }
        let Ok(sampler_slot) = self.video_keyframe_sampler.lock() else {
            return;
        };
        let Some(sampler) = sampler_slot.as_ref() else {
            return;
        };
        let Ok(embedder_slot) = self.image_embedder.lock() else {
            return;
        };
        let Some(embedder) = embedder_slot.as_ref() else {
            return;
        };

        let cache = LocalStoreEmbeddingCache::new(db.connection());

        // Sample up to 5 keyframes per PROPOSAL §7.6 default.
        let frames = match sampler.extract_keyframes(plaintext, mime_type, 5) {
            Ok(f) => f,
            Err(_) => return,
        };

        for (idx, frame) in frames.into_iter().enumerate() {
            let suffix_key = format!(
                "{}_frame_{}",
                MOBILECLIP_S2_MODEL_VERSION, frame.frame_index
            );
            // Per-frame cache hit short-circuits inference for
            // already-embedded frames.
            if let Ok(Some(_)) = cache.get(message_id, &suffix_key) {
                continue;
            }
            match embedder.embed_image(&frame.image_data, &frame.mime_type) {
                Ok(vec) => {
                    let _ = cache.put(message_id, &suffix_key, &vec);
                    // Mirror the first frame's embedding under
                    // the unsuffixed canonical model_version so
                    // callers that look up the original key
                    // (e.g. `maybe_embed_image_message`'s
                    // duplicate-detection path) still resolve.
                    if idx == 0 {
                        if let Ok(None) = cache.get(message_id, MOBILECLIP_S2_MODEL_VERSION) {
                            let _ = cache.put(message_id, MOBILECLIP_S2_MODEL_VERSION, &vec);
                        }
                    }
                }
                Err(_) => {
                    // Inference failures are absorbed.
                }
            }
        }
    }

    /// Borrow the local store for read-only inspection.
    ///
    /// Intended for unit / integration tests. Production callers
    /// should go through the public API.
    #[doc(hidden)]
    pub fn with_db<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&LocalStoreDb) -> T,
    {
        let db = self.db.lock().expect("db mutex poisoned");
        f(&db)
    }

    // ----------------------------------------------------------------
    // Conversation management — Task 4 (`docs/PROPOSAL.md §12`)
    // ----------------------------------------------------------------

    /// Insert a new `conversation` row with the given id and optional
    /// title. The conversation is created un-pinned, un-muted, with
    /// `last_activity_ms` initialized to the supplied wall-clock
    /// timestamp.
    ///
    /// **Phase-1 note.** Title encryption (`K_local_db`-AEAD-sealed
    /// `title_cipher`) lands with the conversation-metadata
    /// roadmap in Phase 2. For now `title` is stored verbatim as
    /// UTF-8 bytes so the bridge can already round-trip the field
    /// through the public API.
    pub fn create_conversation(
        &self,
        conversation_id: Uuid,
        title: Option<&str>,
        last_activity_ms: i64,
    ) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let conv = Conversation {
            conversation_id: conversation_id.to_string(),
            title_cipher: title.map(|t| t.as_bytes().to_vec()),
            pinned: false,
            muted: false,
            last_message_id: None,
            last_activity_ms,
            ..Default::default()
        };
        db.insert_conversation(&conv)
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    /// List every conversation, pinned-first then by descending
    /// `last_activity_ms`.
    pub fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.list_conversations()
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Fetch a single conversation by id. Returns `Ok(None)` when
    /// the row does not exist.
    pub fn get_conversation(&self, conversation_id: Uuid) -> Result<Option<Conversation>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.get_conversation(&conversation_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Update the `pinned` flag for `conversation_id`. Errors with
    /// [`Error::Storage`] when the row does not exist so callers can
    /// surface the failure to the user instead of silently no-op'ing.
    pub fn update_conversation_pin(&self, conversation_id: Uuid, pinned: bool) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let n = db
            .update_conversation_pin(&conversation_id.to_string(), pinned)
            .map_err(|e| Error::Storage(e.to_string()))?;
        if n == 0 {
            return Err(Error::Storage(format!(
                "no conversation with id={conversation_id}"
            )));
        }
        Ok(())
    }

    /// Update the `muted` flag for `conversation_id`. Errors with
    /// [`Error::Storage`] when the row does not exist.
    pub fn update_conversation_mute(&self, conversation_id: Uuid, muted: bool) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let n = db
            .update_conversation_mute(&conversation_id.to_string(), muted)
            .map_err(|e| Error::Storage(e.to_string()))?;
        if n == 0 {
            return Err(Error::Storage(format!(
                "no conversation with id={conversation_id}"
            )));
        }
        Ok(())
    }

    /// Return the messages in `conversation_id` as a flat
    /// timeline view (skeleton fields + optional plaintext body),
    /// ordered newest-first. `before_ms`, when `Some`, restricts
    /// the page to messages with `created_at_ms < before_ms`;
    /// `limit` caps the returned page.
    ///
    /// Wraps [`LocalStoreDb::get_timeline`].
    pub fn get_timeline(
        &self,
        conversation_id: Uuid,
        before_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<crate::TimelineRow>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.get_timeline(&conversation_id.to_string(), before_ms, limit)
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Fetch a single message's skeleton plus its (optional) body
    /// in one DB round-trip. Returns `Ok(None)` when no skeleton
    /// row matches `message_id`, or `Ok(Some((skel, None)))` when
    /// the skeleton exists but the body has been dropped (e.g.
    /// after [`KChatCore::delete_for_everyone`]).
    ///
    /// Distinct from the trait-level [`KChatCore::get_message`]
    /// (which returns the public [`MessageView`] shape): this
    /// inherent method exposes the **raw** schema rows so binding
    /// crates and integration tests can pin lifecycle state
    /// without re-shaping through `MessageView`. Wraps
    /// [`LocalStoreDb::get_message_with_body`].
    pub fn get_message_with_body(
        &self,
        message_id: Uuid,
    ) -> Result<Option<(MessageSkeleton, Option<MessageBody>)>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.get_message_with_body(&message_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Fetch a single message's body, if any. Returns `Ok(None)`
    /// when no body row exists for `message_id` (the message may
    /// not exist, may be media-only, or its body may have been
    /// dropped by [`KChatCore::delete_for_everyone`]).
    ///
    /// Used by the hydration display path. Wraps
    /// [`LocalStoreDb::get_message_body`].
    pub fn get_message_body(&self, message_id: Uuid) -> Result<Option<MessageBody>> {
        let db = self.db.lock().map_err(poisoned)?;
        db.get_message_body(&message_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Rehydrate a cold message body in place using
    /// already-decrypted plaintext. The orchestration layer calls
    /// this once it has fetched and AEAD-unsealed an archive
    /// segment for `message_id`.
    ///
    /// The full sequence — body upsert + `body_state` UPDATE +
    /// `search_fts` refresh + `search_fuzzy` reindex — runs inside
    /// a single outer `SAVEPOINT rehydrate_message_body_locally` so
    /// a partial failure (e.g. the fuzzy `index_message` errors out
    /// after `remove_message` already ran) rolls back to the
    /// pre-call state. Mirrors the
    /// [`crate::message::processor::MessagePersister::edit_message`]
    /// pattern where body / FTS / fuzzy all share one SAVEPOINT.
    ///
    /// `created_at_ms` is **never** touched, so the timeline order
    /// remains stable and the renderer does not scroll-jump.
    pub fn rehydrate_message_body_locally(
        &self,
        message_id: Uuid,
        text_content: &str,
        new_body_state: BodyState,
    ) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let conn = db.connection();
        conn.execute_batch("SAVEPOINT rehydrate_message_body_locally;")
            .map_err(|e| Error::Storage(e.to_string()))?;
        let result = (|| -> Result<()> {
            db.rehydrate_message_body(&message_id.to_string(), text_content, new_body_state)
                .map_err(|e| Error::Storage(e.to_string()))?;
            // Refresh fuzzy tokens — the engine's index_message is
            // idempotent thanks to the (token, script, message_id)
            // primary key but stale tokens from a previous body are
            // dropped first so search_fuzzy stays in sync.
            let engine = crate::search::fuzzy_search::FuzzySearchEngine::new(&db);
            engine
                .remove_message(&message_id.to_string())
                .map_err(|e| Error::Storage(e.to_string()))?;
            engine
                .index_message(&message_id.to_string(), text_content)
                .map_err(|e| Error::Storage(e.to_string()))?;
            Ok(())
        })();
        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE SAVEPOINT rehydrate_message_body_locally;")
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
            Err(_) => {
                let _ = conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT rehydrate_message_body_locally;\n\
                     RELEASE SAVEPOINT rehydrate_message_body_locally;",
                );
            }
        }
        result
    }

    // ----------------------------------------------------------------
    // Backup orchestration (Task 3 — `docs/PROPOSAL.md §6.2`)
    // ----------------------------------------------------------------

    /// Install the Phase-4 backup keys: the long-lived
    /// `K_backup_root` (root of the backup KDF tree), the Ed25519
    /// device signing key used to sign backup manifests, and the
    /// stable `device_id` stamped into every manifest's AAD.
    ///
    /// Called once after the platform keystore unlocks the user's
    /// `K_user_master`. Replaces any previously installed keys.
    /// Without these,
    /// [`KChatCore::run_incremental_backup`] returns
    /// `Error::Crypto(...)` because the segment / manifest
    /// builders cannot derive their per-record keys.
    pub fn install_backup_keys(
        &self,
        backup_root: [u8; KEY_LEN],
        signing_key: crate::crypto::signing::HybridSigningKey,
        device_id: String,
    ) -> Result<()> {
        // Phase-5 hardening: the `wrapped_k_segment` BLOB column
        // on `backup_segment_ledger` is sealed under
        // `K_backup_root`. Hydrate the in-memory ledger BEFORE
        // installing any of the key `Mutex`es, so a hydration
        // failure (corrupt row, AES-KW unwrap mismatch under a
        // different root key, etc.) leaves the orchestrator in
        // the "no keys, no ledger" state instead of the divergent
        // "keys installed, ledger empty" state. Without this
        // ordering, `has_backup_keys()` would return `true` after
        // a hydrate failure and the next backup operation would
        // proceed against an empty in-memory ledger — the first
        // compaction would then drop every pre-existing segment.
        self.hydrate_tracked_backup_segments_from_db(&backup_root)?;

        // Hydration succeeded — commit the keys.
        *self.backup_root_key.lock().map_err(poisoned)? = Some(Zeroizing::new(backup_root));
        *self.backup_signing_key.lock().map_err(poisoned)? = Some(signing_key);
        *self.backup_device_id.lock().map_err(poisoned)? = Some(device_id);
        Ok(())
    }

    /// Whether [`Self::install_backup_keys`] has been called.
    pub fn has_backup_keys(&self) -> bool {
        self.backup_root_key
            .lock()
            .map(|s| s.is_some())
            .unwrap_or(false)
    }

    // ----------------------------------------------------------------
    // Phase-5 hardening — DB-backed manifest chain / segment ledger
    // ----------------------------------------------------------------

    /// Load the latest persisted [`BackupManifest`] from
    /// `backup_manifest_chain` into the in-memory tail.
    ///
    /// Called from [`Self::new`] / [`Self::new_in_memory`] so chain
    /// continuity survives a process restart: the next call to
    /// [`KChatCore::run_incremental_backup`] chains under the
    /// manifest that the *previous* process produced.
    fn hydrate_backup_manifest_from_db(&self) -> Result<()> {
        let manifest_cbor = {
            let db = self.db.lock().map_err(poisoned)?;
            db.load_backup_manifest()
                .map_err(|e| Error::Storage(e.to_string()))?
        };
        if let Some(bytes) = manifest_cbor {
            let manifest: crate::formats::manifest::BackupManifest =
                crate::cbor::from_slice(&bytes).map_err(|e| {
                    Error::Storage(format!(
                        "backup_manifest_chain: failed to CBOR-decode persisted manifest: {e}"
                    ))
                })?;
            *self.previous_backup_manifest.lock().map_err(poisoned)? = Some(manifest);
        }
        Ok(())
    }

    /// Load every row in `backup_segment_ledger`, unwrap each
    /// `wrapped_k_segment` under the supplied `K_backup_root`, and
    /// install the result as the in-memory ledger.
    ///
    /// Called from [`Self::install_backup_keys`] — before the root
    /// is installed the wrapped keys cannot be opened, so the
    /// ledger stays empty.
    fn hydrate_tracked_backup_segments_from_db(&self, backup_root: &[u8; KEY_LEN]) -> Result<()> {
        use crate::backup::compaction::CompactionTier;
        use crate::backup::segment_builder::BuiltBackupSegment;
        use crate::crypto::aead::xchacha20_poly1305::NONCE_LEN;
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::crypto::key_wrap::unwrap_k_asset;
        use crate::formats::SegmentType;

        let rows = {
            let db = self.db.lock().map_err(poisoned)?;
            db.load_backup_segment_ledger()
                .map_err(|e| Error::Storage(e.to_string()))?
        };
        let wrapping_root = KeyMaterial::from_bytes(*backup_root);
        let mut materialised = Vec::with_capacity(rows.len());
        for row in rows {
            let segment_id = uuid::Uuid::parse_str(&row.segment_id).map_err(|e| {
                Error::Storage(format!(
                    "backup_segment_ledger: malformed segment_id={}: {e}",
                    row.segment_id
                ))
            })?;
            if row.nonce.len() != NONCE_LEN {
                return Err(Error::Storage(format!(
                    "backup_segment_ledger: nonce length {} != {NONCE_LEN}",
                    row.nonce.len()
                )));
            }
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&row.nonce);
            if row.merkle_root.len() != 32 {
                return Err(Error::Storage(format!(
                    "backup_segment_ledger: merkle_root length {} != 32",
                    row.merkle_root.len()
                )));
            }
            let mut merkle_root = [0u8; 32];
            merkle_root.copy_from_slice(&row.merkle_root);
            let segment_type = match row.segment_type.as_str() {
                "events" => SegmentType::Events,
                other => {
                    return Err(Error::Storage(format!(
                        "backup_segment_ledger: unknown segment_type={other}"
                    )))
                }
            };
            let tier = match row.tier.as_str() {
                "daily" => CompactionTier::Daily,
                "weekly" => CompactionTier::Weekly,
                "monthly" => CompactionTier::Monthly,
                other => {
                    return Err(Error::Storage(format!(
                        "backup_segment_ledger: unknown tier={other}"
                    )))
                }
            };
            let k_segment_bytes =
                unwrap_k_asset(&row.wrapped_k_segment, &wrapping_root).map_err(Error::Crypto)?;
            let k_segment = KeyMaterial::from_bytes(k_segment_bytes);
            let built = BuiltBackupSegment {
                segment_id,
                segment_type,
                nonce,
                ciphertext: row.ciphertext,
                merkle_root,
                event_count: row.event_count as usize,
            };
            materialised.push(TrackedBackupSegment {
                built,
                tier,
                min_event_ms: row.min_event_ms,
                max_event_ms: row.max_event_ms,
                k_segment,
            });
        }
        *self.tracked_backup_segments.lock().map_err(poisoned)? = materialised;
        Ok(())
    }

    /// Encode the given manifest to CBOR for DB persistence.
    fn encode_manifest_cbor(
        manifest: &crate::formats::manifest::BackupManifest,
    ) -> Result<Vec<u8>> {
        crate::cbor::to_vec(manifest).map_err(|e| {
            Error::Storage(format!(
                "backup_manifest_chain: CBOR encode of manifest failed: {e}"
            ))
        })
    }

    /// Build a [`crate::local_store::db::BackupSegmentLedgerRow`]
    /// from an in-memory [`TrackedBackupSegment`], sealing the
    /// per-segment key under `K_backup_root`.
    fn build_backup_segment_ledger_row(
        seg: &TrackedBackupSegment,
        backup_root: &crate::crypto::key_hierarchy::KeyMaterial,
        now_ms: i64,
    ) -> Result<crate::local_store::db::BackupSegmentLedgerRow> {
        use crate::crypto::key_wrap::wrap_k_asset;

        let wrapped = wrap_k_asset(seg.k_segment.as_bytes(), backup_root).map_err(Error::Crypto)?;
        let segment_type = match seg.built.segment_type {
            crate::formats::SegmentType::Events => "events",
            other => {
                return Err(Error::Storage(format!(
                "backup_segment_ledger: backup segment carried unexpected segment_type={other:?}"
            )))
            }
        };
        let tier = match seg.tier {
            crate::backup::compaction::CompactionTier::Daily => "daily",
            crate::backup::compaction::CompactionTier::Weekly => "weekly",
            crate::backup::compaction::CompactionTier::Monthly => "monthly",
        };
        Ok(crate::local_store::db::BackupSegmentLedgerRow {
            segment_id: seg.built.segment_id.to_string(),
            segment_type: segment_type.to_string(),
            nonce: seg.built.nonce.to_vec(),
            ciphertext: seg.built.ciphertext.clone(),
            merkle_root: seg.built.merkle_root.to_vec(),
            event_count: seg.built.event_count as i64,
            tier: tier.to_string(),
            min_event_ms: seg.min_event_ms,
            max_event_ms: seg.max_event_ms,
            wrapped_k_segment: wrapped,
            created_at_ms: now_ms,
        })
    }

    /// Atomically advance the backup event cursor, append one
    /// sealed segment, and upsert the manifest chain tail in a
    /// single SAVEPOINT. Acquires the DB lock once.
    ///
    /// Folding the cursor advance into the same SAVEPOINT closes
    /// the data-loss window that would otherwise exist if the
    /// cursor was advanced via autocommit before this call: a
    /// persist failure would leave the cursor past the events
    /// without ever recording the corresponding segment or
    /// manifest, so the next backup run would skip them.
    fn persist_incremental_backup_atomic(
        &self,
        seg: &TrackedBackupSegment,
        manifest: &crate::formats::manifest::BackupManifest,
        backup_root: &crate::crypto::key_hierarchy::KeyMaterial,
        cursor_seq: i64,
        now_ms: i64,
    ) -> Result<()> {
        let row = Self::build_backup_segment_ledger_row(seg, backup_root, now_ms)?;
        let cbor = Self::encode_manifest_cbor(manifest)?;
        let db = self.db.lock().map_err(poisoned)?;
        db.atomic_append_segment_and_manifest(
            &row,
            &cbor,
            manifest.generation as i64,
            cursor_seq,
            now_ms,
        )
        .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    /// Atomically replace the full segment ledger **and** upsert
    /// the manifest chain tail in a single SAVEPOINT. Acquires
    /// the DB lock once.
    fn persist_compaction_backup_atomic(
        &self,
        snapshot: &[TrackedBackupSegment],
        manifest: &crate::formats::manifest::BackupManifest,
        backup_root: &crate::crypto::key_hierarchy::KeyMaterial,
        now_ms: i64,
    ) -> Result<()> {
        let mut rows = Vec::with_capacity(snapshot.len());
        for seg in snapshot {
            rows.push(Self::build_backup_segment_ledger_row(
                seg,
                backup_root,
                now_ms,
            )?);
        }
        let cbor = Self::encode_manifest_cbor(manifest)?;
        let db = self.db.lock().map_err(poisoned)?;
        db.atomic_replace_ledger_and_manifest(&rows, &cbor, manifest.generation as i64, now_ms)
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    /// Drive one incremental backup pass.
    ///
    /// Implements `docs/PROPOSAL.md §6.2` end-to-end:
    ///
    /// 1. Read every event past the
    ///    [`crate::backup::event_journal::BackupEventJournal`]
    ///    cursor up to `MAX_EVENTS_PER_SEGMENT`. If empty, return a
    ///    [`BackupResult`] with all counters zeroed and skip the
    ///    seal-and-sign work below.
    /// 2. Derive `K_backup_segment(segment_id)` from
    ///    `K_backup_root` via
    ///    [`crate::crypto::key_hierarchy::derive_backup_segment`]
    ///    and seal the events through
    ///    [`crate::backup::segment_builder::BackupSegmentBuilder`].
    /// 3. Derive `K_backup_manifest(manifest_id)` from
    ///    `K_backup_root` via
    ///    [`crate::crypto::key_hierarchy::derive_backup_manifest`]
    ///    and build the next manifest via
    ///    [`crate::backup::manifest_builder::build_backup_manifest`],
    ///    chaining under
    ///    [`Self::previous_backup_manifest`] (or genesis at
    ///    `generation = 0`).
    /// 4. Advance the journal cursor and update the in-memory
    ///    chain tail so the next call chains under this manifest.
    ///
    /// Upload of the sealed segment / manifest ciphertext is the
    /// caller's job: this method does not own a
    /// [`crate::transport::TransportClient`] handle. Once the
    /// `BackupSink` adapter from Task 4 lands, a follow-up will
    /// extend this function to drive
    /// `BackupSink::upload_backup_segment` /
    /// `BackupSink::upload_backup_manifest` here.
    fn run_incremental_backup_inner(
        &self,
        reason: &str,
    ) -> Result<(BackupResult, Vec<SealedBackupEventRef>)> {
        use crate::backup::event_journal::BackupEventJournal;
        use crate::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
        use crate::backup::segment_builder::{BackupSegmentBuildRequest, BackupSegmentBuilder};
        use crate::crypto::key_hierarchy::{derive_backup_manifest, derive_backup_segment};
        use crate::formats::SegmentType;

        let _ = reason; // reserved for trace / metrics — see RunIncrementalBackup.reason
                        // Per-segment cap is the module-level
                        // `MAX_EVENTS_PER_BACKUP_SEGMENT`; the Task-1 wrapper
                        // shares it so the two paths never disagree on how many
                        // events a single seal contains.

        // Phase 1 — read unsegmented events (db lock).
        let (events_with_seq, last_seq) = {
            let db = self.db.lock().map_err(poisoned)?;
            let journal = BackupEventJournal::new();
            let events = journal
                .read_unsegmented(db.connection(), MAX_EVENTS_PER_BACKUP_SEGMENT)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let last_seq = events.last().map(|(seq, _)| *seq);
            (events, last_seq)
        };
        if events_with_seq.is_empty() {
            return Ok((BackupResult::default(), Vec::new()));
        }
        let last_seq = last_seq.expect("non-empty events implies a last seq");
        let events: Vec<_> = events_with_seq.into_iter().map(|(_, e)| e).collect();
        let event_count = events.len() as u64;
        // Snapshot the (conversation_id, message_id, created_at_ms)
        // tuples for the Task-1 wrapper's shard-grouping pass.
        // Built from `events` itself, so by construction it
        // covers exactly the set of events that will be sealed
        // and cursor-advanced past in this pass — no separate
        // peek, no TOCTOU window. Events that lack a
        // conversation_id / message_id are silently dropped from
        // the summary (they cannot be addressed by the search
        // shard upload anyway).
        let sealed_event_refs: Vec<SealedBackupEventRef> = events
            .iter()
            .filter_map(|e| {
                let conversation_id = e.conversation_id?;
                let message_id = e.message_id?;
                Some(SealedBackupEventRef {
                    conversation_id,
                    message_id,
                    created_at_ms: e.created_at_ms,
                })
            })
            .collect();
        let min_event_ms = events
            .iter()
            .map(|e| e.created_at_ms)
            .min()
            .expect("non-empty events implies a min");
        let max_event_ms = events
            .iter()
            .map(|e| e.created_at_ms)
            .max()
            .expect("non-empty events implies a max");

        // Phase 2 — seal the segment outside the db lock.
        let backup_root = {
            let slot = self.backup_root_key.lock().map_err(poisoned)?;
            let bytes = slot.as_ref().map(|z| **z).ok_or_else(|| {
                Error::Storage(
                    "run_incremental_backup: K_backup_root not installed (call install_backup_keys first)".into(),
                )
            })?;
            KeyMaterial::from_bytes(bytes)
        };
        let signing_key = self
            .backup_signing_key
            .lock()
            .map_err(poisoned)?
            .as_ref()
            .ok_or_else(|| {
                Error::Storage(
                    "run_incremental_backup: backup signing key not installed (call install_backup_keys first)".into(),
                )
            })?
            .clone();
        let device_id = self
            .backup_device_id
            .lock()
            .map_err(poisoned)?
            .clone()
            .unwrap_or_else(|| "unknown-device".to_string());

        let segment_id = uuid::Uuid::now_v7();
        let k_segment =
            derive_backup_segment(&backup_root, segment_id.as_bytes()).map_err(Error::Crypto)?;
        let built = BackupSegmentBuilder::new().build_segment(
            BackupSegmentBuildRequest {
                events,
                segment_type: SegmentType::Events,
            },
            &k_segment,
        )?;

        // Build the manifest chained under the in-memory tail.
        let previous_owned = self
            .previous_backup_manifest
            .lock()
            .map_err(poisoned)?
            .clone();
        let manifest_id_for_key = uuid::Uuid::now_v7();
        let k_manifest = derive_backup_manifest(&backup_root, manifest_id_for_key.as_bytes())
            .map_err(Error::Crypto)?;
        let segments = [built.clone()];
        let request = BackupManifestBuildRequest {
            segments: &segments,
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: previous_owned.as_ref(),
            device_id: device_id.clone(),
        };
        let sealed_manifest = build_backup_manifest(request, &signing_key, &k_manifest)?;
        let manifest_generation = sealed_manifest.manifest.generation;

        // `compact_backup` consumes this ledger when the
        // compaction policy decides to roll up daily segments.
        let tracked = TrackedBackupSegment {
            built: built.clone(),
            tier: crate::backup::compaction::CompactionTier::Daily,
            min_event_ms,
            max_event_ms,
            k_segment: k_segment.clone(),
        };

        // Phase-5 hardening: atomically advance the
        // `backup_event_cursor`, persist the segment ledger row,
        // and upsert the manifest chain tail inside a single
        // SAVEPOINT. The persist MUST happen before the in-memory
        // `Mutex` updates below: if persist fails, `?` propagates
        // the error and we leave the in-memory state at the
        // pre-call values (matching the un-mutated DB).
        //
        // Folding the cursor advance into the same SAVEPOINT
        // closes the data-loss window that would exist if the
        // cursor was advanced separately: a persist failure
        // would otherwise leave the cursor past the events
        // without ever recording the corresponding segment or
        // manifest, so the next backup run would skip them
        // permanently.
        let now_persist_ms = now_ms_for_send_media();
        self.persist_incremental_backup_atomic(
            &tracked,
            &sealed_manifest.manifest,
            &backup_root,
            last_seq,
            now_persist_ms,
        )?;

        // Persist succeeded — commit the in-memory state.
        *self.previous_backup_manifest.lock().map_err(poisoned)? =
            Some(sealed_manifest.manifest.clone());
        self.tracked_backup_segments
            .lock()
            .map_err(poisoned)?
            .push(tracked);

        Ok((
            BackupResult {
                segments_built: 1,
                // No transport-side BackupSink upload yet; Task 4 wires
                // `ZkofBackupSink::upload_backup_segment` /
                // `upload_backup_manifest` into this slot. Until then
                // the caller is responsible for uploading the sealed
                // bytes out-of-band.
                segments_uploaded: 0,
                events_segmented: event_count,
                manifest_generation: Some(manifest_generation),
                manifest_uploaded: false,
                deferred: false,
            },
            sealed_event_refs,
        ))
    }

    /// Drive one pass of backup compaction.
    ///
    /// Reads the current ledger of sealed segments
    /// ([`Self::tracked_backup_segments`]), asks
    /// [`crate::backup::compaction::CompactionPolicy::plan`] for
    /// the eligible groups, and for each group:
    ///
    /// 1. Decrypts every member segment under
    ///    `K_backup_segment(member.segment_id)`.
    /// 2. Concatenates the events.
    /// 3. Runs
    ///    [`crate::backup::compaction::apply_tombstones`] to drop
    ///    deleted-message events.
    /// 4. Re-seals the survivors as a single
    ///    [`crate::backup::segment_builder::BuiltBackupSegment`]
    ///    under a freshly-derived
    ///    `K_backup_segment(new_segment_id)` at the group's target
    ///    tier.
    /// 5. Replaces the superseded entries in the ledger with the
    ///    compacted entry.
    /// 6. Builds a new
    ///    [`crate::backup::manifest_builder::SealedBackupManifest`]
    ///    over the rewritten ledger and chains it under
    ///    [`Self::previous_backup_manifest`].
    pub fn compact_backup(&self, now_ms: i64) -> Result<BackupCompactionResult> {
        use crate::backup::compaction::{apply_tombstones, CompactionPolicy};
        use crate::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
        use crate::backup::segment_builder::{
            decrypt_backup_segment, BackupSegmentBuildRequest, BackupSegmentBuilder,
        };
        use crate::crypto::key_hierarchy::{derive_backup_manifest, derive_backup_segment};
        use crate::formats::SegmentType;

        let backup_root = {
            let slot = self.backup_root_key.lock().map_err(poisoned)?;
            let bytes = slot.as_ref().map(|z| **z).ok_or_else(|| {
                Error::Storage(
                    "compact_backup: K_backup_root not installed (call install_backup_keys first)"
                        .into(),
                )
            })?;
            KeyMaterial::from_bytes(bytes)
        };
        let signing_key = self
            .backup_signing_key
            .lock()
            .map_err(poisoned)?
            .as_ref()
            .ok_or_else(|| {
                Error::Storage(
                    "compact_backup: backup signing key not installed (call install_backup_keys first)".into(),
                )
            })?
            .clone();
        let device_id = self
            .backup_device_id
            .lock()
            .map_err(poisoned)?
            .clone()
            .unwrap_or_else(|| "unknown-device".to_string());

        // Snapshot the ledger and build a plan.
        let snapshot = self
            .tracked_backup_segments
            .lock()
            .map_err(poisoned)?
            .clone();
        if snapshot.is_empty() {
            return Ok(BackupCompactionResult::default());
        }
        let segment_refs: Vec<crate::backup::compaction::BackupSegmentRef> = snapshot
            .iter()
            .map(|s| crate::backup::compaction::BackupSegmentRef {
                segment_id: s.built.segment_id,
                tier: s.tier,
                min_event_ms: s.min_event_ms,
                max_event_ms: s.max_event_ms,
                event_count: s.built.event_count,
            })
            .collect();
        let plan = CompactionPolicy::default().plan(&segment_refs, now_ms);
        if plan.is_empty() {
            return Ok(BackupCompactionResult::default());
        }

        let mut groups_compacted = 0u64;
        let mut segments_superseded = 0u64;
        let mut bytes_before = 0u64;
        let mut bytes_after = 0u64;
        let mut compacted_outputs: Vec<TrackedBackupSegment> = Vec::new();
        let superseded_ids: std::collections::BTreeSet<uuid::Uuid> =
            plan.superseded_segment_ids().into_iter().collect();

        for group in &plan.groups {
            // Decrypt each source segment under its per-segment
            // key derived from K_backup_root.
            let mut events: Vec<crate::backup::event_journal::BackupEvent> = Vec::new();
            let mut group_min_ms = i64::MAX;
            let mut group_max_ms = i64::MIN;
            for member in &group.members {
                let tracked = snapshot
                    .iter()
                    .find(|s| s.built.segment_id == member.segment_id)
                    .ok_or_else(|| {
                        Error::Storage(format!(
                            "compact_backup: superseded segment {} missing from ledger",
                            member.segment_id
                        ))
                    })?;
                bytes_before += tracked.built.ciphertext.len() as u64;
                group_min_ms = group_min_ms.min(tracked.min_event_ms);
                group_max_ms = group_max_ms.max(tracked.max_event_ms);
                let payload = decrypt_backup_segment(&tracked.built, &tracked.k_segment)?;
                events.extend(payload.events);
            }
            segments_superseded += group.members.len() as u64;
            groups_compacted += 1;

            // Tombstones drop the original delete events too —
            // matching the semantics already validated in
            // `crate::backup::compaction::apply_tombstones`.
            let survivors = apply_tombstones(events);
            if survivors.is_empty() {
                // Whole group erased by tombstones; nothing to
                // re-seal.
                continue;
            }

            let new_segment_id = uuid::Uuid::now_v7();
            let k_new = derive_backup_segment(&backup_root, new_segment_id.as_bytes())
                .map_err(Error::Crypto)?;
            let built = BackupSegmentBuilder::new().build_segment(
                BackupSegmentBuildRequest {
                    events: survivors,
                    segment_type: SegmentType::Events,
                },
                &k_new,
            )?;
            bytes_after += built.ciphertext.len() as u64;
            compacted_outputs.push(TrackedBackupSegment {
                built,
                tier: group.target_tier,
                min_event_ms: group_min_ms,
                max_event_ms: group_max_ms,
                k_segment: k_new,
            });
        }

        // Build the post-compaction view as a local `Vec` without
        // mutating the in-memory ledger yet — `snapshot` is already
        // a clone of the current ledger taken at the top of this
        // method, so applying `retain` + `extend` to it produces
        // the post-compaction state without touching the `Mutex`.
        let mut new_ledger_local: Vec<TrackedBackupSegment> = snapshot;
        new_ledger_local.retain(|s| !superseded_ids.contains(&s.built.segment_id));
        new_ledger_local.extend(compacted_outputs.iter().cloned());

        // Cut a new manifest over the post-compaction ledger so
        // the chain reflects the compaction.
        let segments_for_manifest: Vec<_> =
            new_ledger_local.iter().map(|s| s.built.clone()).collect();
        let previous_owned = self
            .previous_backup_manifest
            .lock()
            .map_err(poisoned)?
            .clone();
        let manifest_id_for_key = uuid::Uuid::now_v7();
        let k_manifest = derive_backup_manifest(&backup_root, manifest_id_for_key.as_bytes())
            .map_err(Error::Crypto)?;
        let request = BackupManifestBuildRequest {
            segments: &segments_for_manifest,
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            previous: previous_owned.as_ref(),
            device_id,
        };
        let sealed_manifest = build_backup_manifest(request, &signing_key, &k_manifest)?;
        let manifest_generation = sealed_manifest.manifest.generation;

        // Phase-5 hardening: atomically rewrite the persisted
        // ledger and the manifest chain tail inside a single
        // SAVEPOINT so a crash cannot leave the ledger compacted
        // while the manifest still references the pre-compaction
        // generation. The persist MUST happen before the
        // in-memory `Mutex` updates below: if persist fails, `?`
        // propagates the error and we leave the in-memory state at
        // the pre-call values (matching the un-mutated DB).
        let now_persist_ms = now_ms_for_send_media();
        self.persist_compaction_backup_atomic(
            &new_ledger_local,
            &sealed_manifest.manifest,
            &backup_root,
            now_persist_ms,
        )?;

        // Persist succeeded — swap the in-memory state.
        *self.tracked_backup_segments.lock().map_err(poisoned)? = new_ledger_local;
        *self.previous_backup_manifest.lock().map_err(poisoned)? =
            Some(sealed_manifest.manifest.clone());

        Ok(BackupCompactionResult {
            groups_compacted,
            segments_superseded,
            segments_emitted: compacted_outputs.len() as u64,
            bytes_before,
            bytes_after,
            manifest_generation: Some(manifest_generation),
        })
    }

    // -----------------------------------------------------------------
    // Phase-3 / Phase-7 archive compaction (Task 9 — `docs/PHASES.md
    // §Phase 7`).
    // -----------------------------------------------------------------

    /// Compact the archive segments for a single
    /// `(conversation_id, time_bucket)` key.
    ///
    /// The orchestration layer:
    ///
    /// 1. Selects every `archive_segment_map` row matching
    ///    `conversation_id` / `time_bucket` whose state is
    ///    [`ArchiveState::ArchiveVerified`]. Earlier states (still
    ///    being uploaded, not yet verified) are not eligible —
    ///    re-sealing in flight would race with the integrity
    ///    cross-check.
    /// 2. Fetches each row's ciphertext via the supplied
    ///    [`crate::archive::download::ArchiveSegmentRouter`] (which
    ///    routes per-row by
    ///    [`crate::local_store::schema::StorageBackend`]).
    /// 3. Decrypts each segment via
    ///    [`crate::archive::download::decrypt_archive_segment`]
    ///    using the key returned by `key_for_segment`.
    /// 4. Concatenates events, runs
    ///    [`crate::archive::compaction::apply_archive_tombstones`].
    /// 5. Re-seals the survivors as a single archive segment via
    ///    [`crate::archive::segment_builder::ArchiveSegmentBuilder::build_segment`]
    ///    under `k_compact_segment`.
    /// 6. Calls `commit_compact` so the orchestrator can route the
    ///    upload + persist the new `archive_segment_map` row.
    /// 7. Transitions the source segments to
    ///    [`ArchiveState::ArchiveCompacted`].
    ///
    /// Returns an [`crate::archive::compaction::ArchiveCompactionResult`]
    /// summarising the run. A noop run (≤1 source segment) returns
    /// the default summary unchanged.
    pub fn compact_archive<F, C>(
        &self,
        router: &crate::archive::download::ArchiveSegmentRouter<'_>,
        conversation_id: Uuid,
        time_bucket: &str,
        k_compact_segment: &[u8; 32],
        key_for_segment: F,
        commit_compact: C,
    ) -> Result<crate::archive::compaction::ArchiveCompactionResult>
    where
        F: FnMut(&str) -> Result<[u8; 32]>,
        C: FnMut(&crate::archive::segment_builder::BuiltSegment) -> Result<()>,
    {
        // Phase 7 (2026-05-04 batch 10) — Task 7: instrument the
        // compaction hot path. The result counters land on the
        // trace metadata so downstream dashboards can correlate
        // latency with bucket size.
        let mut trace = crate::perf::PerfTrace::new("compact_archive");
        trace.insert_metadata("conversation_id", conversation_id.to_string());
        trace.insert_metadata("time_bucket", time_bucket.to_string());
        let result = self.compact_archive_inner(
            router,
            conversation_id,
            time_bucket,
            k_compact_segment,
            key_for_segment,
            commit_compact,
        );
        match result.as_ref() {
            Ok(s) => {
                trace.insert_metadata("buckets_compacted", s.buckets_compacted.to_string());
                trace.insert_metadata("segments_superseded", s.segments_superseded.to_string());
            }
            Err(e) => {
                trace.insert_metadata("error", e.to_string());
            }
        }
        trace.finish();
        self.record_perf_trace(trace);
        result
    }

    fn compact_archive_inner<F, C>(
        &self,
        router: &crate::archive::download::ArchiveSegmentRouter<'_>,
        conversation_id: Uuid,
        time_bucket: &str,
        k_compact_segment: &[u8; 32],
        mut key_for_segment: F,
        mut commit_compact: C,
    ) -> Result<crate::archive::compaction::ArchiveCompactionResult>
    where
        F: FnMut(&str) -> Result<[u8; 32]>,
        C: FnMut(&crate::archive::segment_builder::BuiltSegment) -> Result<()>,
    {
        use crate::archive::compaction::{apply_archive_tombstones, ArchiveCompactionResult};
        use crate::archive::download::{decode_archive_segment_payload, decrypt_archive_segment};
        use crate::archive::prefetch::batch_prefetch_bucket_with_router;
        use crate::archive::segment_builder::{ArchiveSegmentBuilder, SegmentBuildRequest};

        let mut summary = ArchiveCompactionResult {
            buckets_inspected: 1,
            ..Default::default()
        };

        // Phase A — read every eligible segment row + ciphertext
        // outside the db lock (the prefetch helper opens it
        // internally and releases before we decrypt).
        let prefetched = {
            let db = self.db.lock().map_err(poisoned)?;
            // Filter to `archive_verified` state up-front: only
            // segments past Merkle-cross-check are eligible for
            // compaction.
            let mut stmt = db
                .connection()
                .prepare(
                    "SELECT segment_id FROM archive_segment_map
                       WHERE conversation_id = ?1
                         AND time_bucket = ?2
                         AND state = 'archive_verified'",
                )
                .map_err(|e| Error::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(
                    rusqlite::params![conversation_id.to_string(), time_bucket],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|e| Error::Storage(e.to_string()))?;
            let mut eligible_ids: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            for row in rows {
                eligible_ids.insert(row.map_err(|e| Error::Storage(e.to_string()))?);
            }
            drop(stmt);
            if eligible_ids.len() < 2 {
                // ≤1 eligible segment: nothing to compact.
                return Ok(summary);
            }
            let prefetched = batch_prefetch_bucket_with_router(
                db.connection(),
                router,
                conversation_id,
                time_bucket,
            )?;
            // The prefetch helper returns rows for *every* state;
            // we only compact the ones in `archive_verified`.
            prefetched
                .into_iter()
                .filter(|p| eligible_ids.contains(&p.segment_id))
                .collect::<Vec<_>>()
        };

        if prefetched.len() < 2 {
            return Ok(summary);
        }

        // Phase B — decrypt every source segment and concatenate
        // the events. We track the original segment ids so we can
        // flip their state in phase E.
        let mut events: Vec<crate::archive::event_journal::ArchiveEvent> = Vec::new();
        let mut superseded_ids: Vec<String> = Vec::new();
        for prefetched_seg in &prefetched {
            summary.bytes_before += prefetched_seg.ciphertext.len() as u64;
            let k_bytes = key_for_segment(&prefetched_seg.segment_id)?;
            let plaintext_cbor = decrypt_archive_segment(&prefetched_seg.ciphertext, &k_bytes)?;
            let payload = decode_archive_segment_payload(&plaintext_cbor)?;
            events.extend(payload.events);
            superseded_ids.push(prefetched_seg.segment_id.clone());
        }

        // Phase C — apply archive-flavored tombstones, then re-seal
        // a single compact segment. If tombstones erased every
        // event we skip the build but still flip the source rows
        // to `archive_compacted`.
        let survivors = apply_archive_tombstones(events);
        let compact_segment = if survivors.is_empty() {
            None
        } else {
            let built = ArchiveSegmentBuilder::new().build_segment(
                SegmentBuildRequest::message_delta(
                    conversation_id,
                    time_bucket.to_string(),
                    survivors,
                ),
                k_compact_segment,
            )?;
            summary.bytes_after += built.ciphertext.len() as u64;
            Some(built)
        };

        // Phase D — let the orchestrator route the upload + write
        // the new segment_map row before we transition the source
        // rows. If commit_compact returns an error the source rows
        // remain at `archive_verified` and the run is retryable.
        if let Some(ref new_segment) = compact_segment {
            commit_compact(new_segment)?;
            summary.segments_emitted += 1;
        }

        // Phase E — flip every source segment to
        // `archive_compacted`. A SAVEPOINT keeps the bulk of the
        // updates atomic against concurrent reads.
        {
            let db = self.db.lock().map_err(poisoned)?;
            let conn = db.connection();
            conn.execute_batch("SAVEPOINT compact_archive;")
                .map_err(|e| Error::Storage(e.to_string()))?;
            let res = (|| -> Result<()> {
                for sid in &superseded_ids {
                    conn.execute(
                        "UPDATE archive_segment_map SET state = 'archive_compacted'
                          WHERE segment_id = ?1",
                        rusqlite::params![sid],
                    )
                    .map_err(|e| Error::Storage(e.to_string()))?;
                }
                Ok(())
            })();
            match res {
                Ok(()) => {
                    conn.execute_batch("RELEASE compact_archive;")
                        .map_err(|e| Error::Storage(e.to_string()))?;
                }
                Err(e) => {
                    let _ =
                        conn.execute_batch("ROLLBACK TO compact_archive; RELEASE compact_archive;");
                    return Err(e);
                }
            }
        }

        summary.buckets_compacted = 1;
        summary.segments_superseded = superseded_ids.len() as u64;
        Ok(summary)
    }
}

/// Summary returned by
/// [`CoreImpl::fetch_and_restore_cold_shards`]. Lists how many
/// encrypted shards came back from the backend and how many
/// rows the replay path inserted into each local search table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreColdShardsSummary {
    /// Plaintext `conversation_id` the call targeted.
    pub conversation_id: String,
    /// Coarse time bucket the call targeted.
    pub time_bucket: String,
    /// Number of [`crate::search::shard_prefetch::PrefetchedShard`]
    /// entries the prefetch returned (text + fuzzy + … in the
    /// fixed [`crate::search::shard_prefetch::PREFETCH_ORDER`]).
    /// Empty buckets return `0`.
    pub fetched_shards: usize,
    /// Rows inserted into `search_fts`.
    pub text_rows_inserted: usize,
    /// Rows inserted into `search_fuzzy`.
    pub fuzzy_rows_inserted: usize,
}

impl RestoreColdShardsSummary {
    /// `true` when the call inserted no rows in either table.
    /// Useful for the "empty bucket no-op" assertion in tests
    /// and for short-circuit logic in the orchestration layer.
    pub fn is_empty(&self) -> bool {
        self.text_rows_inserted == 0 && self.fuzzy_rows_inserted == 0
    }
}

/// Bundle returned by
/// [`CoreImpl::run_incremental_backup_with_search_shards`].
///
/// `backup` is the same [`BackupResult`] the
/// transport-less `run_incremental_backup` would have produced;
/// `shards` lists one [`UploadedSearchShards`] receipt per
/// affected `(conversation_id, time_bucket)` pair (deterministic
/// `(conv_id, bucket)`-sorted ordering — the underlying map is a
/// `BTreeMap`).
#[derive(Debug, Clone, Default)]
pub struct RunIncrementalBackupWithShards {
    /// Result of the underlying
    /// [`CoreImpl::run_incremental_backup_inner`] pass.
    pub backup: BackupResult,
    /// Per-bucket upload receipts; one entry per affected
    /// `(conversation_id, time_bucket)` that had at least one
    /// FTS / fuzzy row to seal.
    pub shards: Vec<UploadedSearchShards>,
}

impl RunIncrementalBackupWithShards {
    /// `true` when at least one shard upload failed (text or
    /// fuzzy on any bucket). Mirrors
    /// [`UploadedSearchShards::has_failures`].
    pub fn has_shard_failures(&self) -> bool {
        self.shards.iter().any(|s| s.has_failures())
    }

    /// Number of buckets with at least one successful shard
    /// upload (text *or* fuzzy).
    pub fn buckets_uploaded(&self) -> usize {
        self.shards
            .iter()
            .filter(|s| s.text_shard.is_some() || s.fuzzy_shard.is_some())
            .count()
    }
}

/// Result of [`CoreImpl::compact_backup`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupCompactionResult {
    /// Number of [`crate::backup::compaction::CompactionGroup`]s
    /// the policy planned and the orchestrator merged.
    pub groups_compacted: u64,
    /// Total source segments superseded by the compacted outputs.
    pub segments_superseded: u64,
    /// Number of new segments emitted by this run. May be smaller
    /// than `groups_compacted` if a whole group was erased by
    /// tombstones.
    pub segments_emitted: u64,
    /// Total ciphertext bytes of the superseded segments.
    pub bytes_before: u64,
    /// Total ciphertext bytes of the compacted outputs.
    pub bytes_after: u64,
    /// `generation` of the manifest cut after the rewrite. `None`
    /// when the run was a noop.
    pub manifest_generation: Option<u64>,
}

impl KChatCore for CoreImpl {
    fn config(&self) -> &KChatCoreConfig {
        &self.config
    }

    fn initialize(&mut self, config: KChatCoreConfig) -> Result<()> {
        let db = LocalStoreDb::open(&config.data_dir, &self.key)
            .map_err(|e| Error::Storage(e.to_string()))?;
        self.config = config;
        self.db = Mutex::new(db);
        // The delivery client survives a re-init: it is bound to
        // the device / account, not the on-disk store location.
        Ok(())
    }

    fn register_device(&self, _device_id: &str) -> Result<DeviceRegistration> {
        // Phase-1 stub: MLS credential / KeyPackage publication and
        // device-key derivation arrive when the MLS layer lands
        // later in Phase 1 / Phase 2.
        Err(Error::NotImplemented("register_device"))
    }

    fn send_text(
        &self,
        conversation_id: Uuid,
        text: &str,
        reply_to: Option<Uuid>,
    ) -> Result<ClientMessageId> {
        let entry = MessageProcessor::create_outbox_entry(conversation_id, text, reply_to)
            .map_err(|e| Error::Message(e.to_string()))?;
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        let mid = persister
            .persist_outbox_entry(&entry)
            .map_err(|e| Error::Message(e.to_string()))?;
        Ok(mid)
    }

    fn ingest_remote_messages(
        &self,
        conversation_id: Uuid,
        after_cursor: Option<DeliveryCursor>,
    ) -> Result<IngestResult> {
        // Snapshot the configured delivery client. We hold the
        // mutex only for the duration of the fetch dispatch so the
        // database mutex below can be acquired without nesting.
        let fetch = {
            let guard = self.delivery_client.lock().map_err(poisoned)?;
            let client = guard
                .as_ref()
                .ok_or_else(|| Error::Transport("no delivery client configured".to_string()))?;
            let cursor_owned = after_cursor.as_ref().map(|c| c.0.clone());
            client.fetch_messages(&conversation_id.to_string(), cursor_owned.as_deref())
        };
        let fetched = fetch.map_err(|e| Error::Transport(e.to_string()))?;

        // Convert each RawDeliveryMessage to an IngestedMessage and
        // route through the inherent ingest_messages entry point so
        // FTS / fuzzy / journal / conversation-metadata writes all
        // happen inside the existing per-message SAVEPOINT.
        let mut converted: Vec<IngestedMessage> = Vec::with_capacity(fetched.messages.len());
        for raw in &fetched.messages {
            converted.push(raw_delivery_to_ingested(raw)?);
        }
        let mut result = self.ingest_messages(&converted)?;
        // Propagate the transport cursor through `IngestResult` so
        // bridge layers can drive paginated drains without poking
        // into the transport mock.
        result.next_cursor = fetched.next_cursor;
        Ok(result)
    }

    // Field names mirror the `PerfTrace::insert_metadata` keys
    // below (`query_len`, `scope`, `result_count`) so dashboards
    // can read either surface interchangeably. The deferred
    // `result_count` is recorded via `Span::current().record` at
    // the same point the PerfTrace metadata is written.
    #[tracing::instrument(
        skip(self, query),
        fields(
            query_len = query.query_string.len(),
            scope = ?scope,
            result_count = tracing::field::Empty,
        ),
    )]
    fn search(&self, query: SearchQuery, scope: SearchScope) -> Result<Vec<SearchResult>> {
        // Phase 7, Task 8 (2026-05-04 batch): emit a `search`
        // [`crate::perf::PerfTrace`]. We capture `query_len`
        // (input characters), `scope`, and the resulting hit
        // count. The trace ends after the cold-hit enqueue so a
        // collector sees the wall-clock that the UI sees.
        let mut trace = crate::perf::PerfTrace::new("search");
        trace.insert_metadata("query_len", query.query_string.len().to_string());
        trace.insert_metadata(
            "scope",
            match scope {
                SearchScope::LocalOnly => "local_only".to_string(),
                SearchScope::IncludeCold => "include_cold".to_string(),
            },
        );

        let db = match self.db.lock().map_err(poisoned) {
            Ok(db) => db,
            Err(e) => {
                trace.insert_metadata("error", e.to_string());
                trace.finish();
                self.record_perf_trace(trace);
                return Err(e);
            }
        };
        let engine = QueryEngine::new(&db);
        let results = match engine.execute_search(&query, &scope) {
            Ok(r) => r,
            Err(e) => {
                trace.insert_metadata("error", e.to_string());
                trace.finish();
                self.record_perf_trace(trace);
                return Err(Error::Search(e.to_string()));
            }
        };
        drop(db);
        // When the caller requested the personal archive, enqueue
        // every cold-flagged result for hydration at priority
        // `SearchResultTap` (`docs/PROPOSAL.md §5.5`). The enqueue
        // is best-effort: if the queue mutex is poisoned we
        // surface the search results regardless so the UI can
        // render — the orchestrator will retry the enqueue on the
        // next search.
        if matches!(scope, SearchScope::IncludeCold) {
            self.enqueue_cold_results_for_hydration(&results);
        }
        trace.insert_metadata("result_count", results.len().to_string());
        tracing::Span::current().record("result_count", results.len());
        trace.finish();
        self.record_perf_trace(trace);
        Ok(results)
    }

    fn edit_message(&self, message_id: Uuid, new_text: &str) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        persister
            .edit_message(&message_id.to_string(), new_text)
            .map_err(|e| Error::Message(e.to_string()))
    }

    fn delete_for_me(&self, message_id: Uuid) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        persister
            .delete_for_me(&message_id.to_string())
            .map_err(|e| Error::Message(e.to_string()))
    }

    fn delete_for_everyone(&self, message_id: Uuid) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let persister = MessagePersister::new(&db);
        persister
            .delete_for_everyone(&message_id.to_string())
            .map_err(|e| Error::Message(e.to_string()))
    }

    fn delete_conversation(&self, conversation_id: Uuid) -> Result<()> {
        let db = self.db.lock().map_err(poisoned)?;
        let n = db
            .delete_conversation(&conversation_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))?;
        if n == 0 {
            return Err(Error::Storage(format!(
                "no conversation with id={conversation_id}"
            )));
        }
        Ok(())
    }

    fn get_message(&self, message_id: Uuid) -> Result<Option<MessageView>> {
        let db = self.db.lock().map_err(poisoned)?;
        let pair = db
            .get_message_with_body(&message_id.to_string())
            .map_err(|e| Error::Storage(e.to_string()))?;
        match pair {
            None => Ok(None),
            Some((skel, body)) => Ok(Some(skeleton_and_body_to_view(skel, body)?)),
        }
    }

    fn get_conversation_messages(
        &self,
        conversation_id: Uuid,
        before_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<MessageView>> {
        let db = self.db.lock().map_err(poisoned)?;
        let skels = db
            .get_conversation_messages(&conversation_id.to_string(), before_ms, limit)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let mut out = Vec::with_capacity(skels.len());
        for skel in skels {
            let body = db
                .get_message_body(&skel.message_id)
                .map_err(|e| Error::Storage(e.to_string()))?;
            out.push(skeleton_and_body_to_view(skel, body)?);
        }
        Ok(out)
    }

    fn send_media(
        &self,
        conversation_id: Uuid,
        message_id: Uuid,
        plaintext: Vec<u8>,
        mime_type: &str,
        caption: Option<&str>,
    ) -> Result<SendMediaResult> {
        if plaintext.is_empty() {
            return Err(Error::Message(
                "send_media: plaintext must not be empty".into(),
            ));
        }
        if mime_type.is_empty() {
            return Err(Error::Message(
                "send_media: mime_type must not be empty".into(),
            ));
        }

        // 1) Run the chunk + AEAD seal pipeline. The wrapping key is
        //    `K_local_db` (the bytes already retained on `self.key`)
        //    so the wrapped `K_asset` is recoverable from the local
        //    store alone — Phase 3 will rewrap under
        //    `K_archive_root` when an asset is offloaded.
        let processed = process_media(&plaintext, mime_type, &self.key, BlobClass::Media, true)?;

        // 2) Optionally generate a thumbnail. Errors during thumbnail
        //    generation are non-fatal — the timeline can render the
        //    media row without a thumbnail today, and Phase 6 will
        //    plug in the vision / OCR pipelines that produce richer
        //    previews.
        let _thumbnail = ThumbnailGenerator::new()
            .generate_thumbnail(&plaintext, mime_type, DEFAULT_MAX_DIMENSION)
            .ok();

        let now = now_ms_for_send_media();
        let descriptor = processed.descriptor.clone();
        let asset_id = descriptor.asset_id;
        let blob_id = descriptor.blob_id;

        // 3) Persist skeleton + body + media_asset rows inside a
        //    single SAVEPOINT so a failure mid-write doesn't leave
        //    dangling references.
        let db = self.db.lock().map_err(poisoned)?;
        let conn = db.connection();
        conn.execute_batch("SAVEPOINT send_media;")
            .map_err(|e| Error::Storage(e.to_string()))?;

        let result = (|| -> Result<SendMediaResult> {
            let skel = MessageSkeleton {
                message_id: message_id.to_string(),
                conversation_id: conversation_id.to_string(),
                sender_id: "self".to_string(),
                created_at_ms: now,
                received_at_ms: now,
                kind: MessageKind::Media,
                body_state: BodyState::LocalPlainAvailable,
                media_state: Some(processed.initial_media_state),
                archive_state: ArchiveState::NotArchived,
                backup_state: BackupState::NotBackedUp,
                reply_to: None,
                edited_at_ms: None,
                deleted_at_ms: None,
            };
            db.insert_message_skeleton(&skel)
                .map_err(|e| Error::Storage(e.to_string()))?;

            // Caption (if any) is persisted as the message body and
            // mirrored into the FTS / fuzzy indexes so it shows up
            // in `core.search()` results — same shape as the
            // `send_text` path's `MessagePersister::persist_outbox_entry_inner`
            // (see `crates/core/src/message/processor.rs:478-486`).
            if let Some(caption) = caption {
                let body = MessageBody {
                    message_id: skel.message_id.clone(),
                    text_content: Some(caption.to_string()),
                    detected_language: None,
                    rich_meta: None,
                };
                db.insert_message_body(&body)
                    .map_err(|e| Error::Storage(e.to_string()))?;
                conn.execute(
                    "INSERT INTO search_fts(
                        message_id, conversation_id, sender_id,
                        created_at_ms, text_content
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        skel.message_id,
                        skel.conversation_id,
                        skel.sender_id,
                        skel.created_at_ms,
                        caption,
                    ],
                )
                .map_err(|e| Error::Storage(e.to_string()))?;
                FuzzySearchEngine::new(&db)
                    .index_message(&skel.message_id, caption)
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }

            let asset = MediaAsset {
                asset_id: asset_id.to_string(),
                message_id: skel.message_id.clone(),
                mime_type: mime_type.to_string(),
                bytes_total: descriptor.bytes_total as i64,
                // Phase 2 keeps the original locally until the
                // upload pipeline confirms — `bytes_local` matches
                // `bytes_total` for now.
                bytes_local: descriptor.bytes_total as i64,
                media_state: processed.initial_media_state,
                wrapped_k_asset: descriptor.wrapped_k_asset.clone(),
                chunk_count: descriptor.chunk_count as i32,
                merkle_root: descriptor.merkle_root.to_vec(),
                blob_id: blob_id.to_string(),
                storage_sink: descriptor
                    .storage_sink
                    .clone()
                    .unwrap_or_else(|| "kchat_backend".to_string()),
            };
            db.insert_media_asset(&asset)
                .map_err(|e| Error::Storage(e.to_string()))?;

            // Phase 6, Task 9: best-effort MobileCLIP-S2 image
            // embedding. Runs only when (a) an
            // [`crate::models::clip::ImageEmbedder`] is installed,
            // (b) the MIME type indicates an image, and (c) the
            // shared embedding cache does not already carry a row
            // for `(message_id, MOBILECLIP_S2_MODEL_VERSION)`.
            // Failures are absorbed; the message is already
            // persisted and FTS-searchable through its caption.
            self.maybe_embed_image_message(&db, &skel.message_id, mime_type, &plaintext);

            // Phase 6, Task 2 (2026-05-04 batch): best-effort
            // Whisper transcription for audio media. Fans the
            // transcript out into `media_search_index`,
            // `search_fts`, `search_fuzzy`, and the shared XLM-R
            // embedding cache. Failures are absorbed.
            self.maybe_transcribe_audio_message(
                &db,
                &skel.message_id,
                &asset_id.to_string(),
                &skel.sender_id,
                &skel.conversation_id,
                skel.created_at_ms,
                mime_type,
                &plaintext,
            );

            // Phase 6, Task 3 (2026-05-04 batch): best-effort PDF
            // / DOCX page text extraction with page-level FTS /
            // fuzzy / XLM-R fan-out. Failures are absorbed.
            self.maybe_extract_document_pages(
                &db,
                &skel.message_id,
                &asset_id.to_string(),
                &skel.sender_id,
                &skel.conversation_id,
                skel.created_at_ms,
                mime_type,
                &plaintext,
            );

            // Phase 6, Task 3 (2026-05-04 batch): best-effort
            // video keyframe sampling + MobileCLIP-S2 embedding.
            // Runs only when (a) a sampler is installed, (b) an
            // image embedder is installed, and (c) the MIME type
            // indicates video. The first keyframe's embedding
            // lands in `search_vector` keyed
            // `(message_id, MOBILECLIP_S2_MODEL_VERSION)`;
            // failures are absorbed.
            self.maybe_embed_video_keyframes(&db, &skel.message_id, mime_type, &plaintext);

            // Bump the owning conversation's last_message_id /
            // last_activity_ms so list_conversations surfaces the
            // freshly-sent media message at the top. Mirrors
            // `MessagePersister::persist_outbox_entry_inner`.
            db.update_conversation_last_message(
                &skel.conversation_id,
                &skel.message_id,
                skel.created_at_ms,
            )
            .map_err(|e| Error::Storage(e.to_string()))?;

            // Append a backup_event_journal entry so the Phase 4
            // backup drainer sees this media message during
            // incremental backups. Same `event_type` ('outbox_pending')
            // and CBOR shape as the send_text path's
            // `MessagePersister::persist_outbox_entry_inner`
            // (`crates/core/src/message/processor.rs:496-503`).
            let payload = encode_event_payload(
                &skel.message_id,
                &skel.conversation_id,
                &skel.sender_id,
                skel.created_at_ms,
            );
            db.insert_backup_event(&BackupEventJournalEntry {
                event_seq: 0,
                event_type: "outbox_pending".into(),
                conversation_id: Some(skel.conversation_id.clone()),
                message_id: Some(skel.message_id.clone()),
                payload: payload.clone(),
                created_at_ms: skel.created_at_ms,
            })
            .map_err(|e| Error::Storage(e.to_string()))?;

            // Mirror the media send into the Phase-3 archive event
            // journal so the segment builder pulls the asset into
            // its next `MessageDelta` segment alongside any text
            // messages from the same time bucket. The write rides
            // inside the open `SAVEPOINT send_media;`.
            ArchiveEventJournal::new()
                .write_event(
                    conn,
                    &ArchiveEvent {
                        event_type: ArchiveEventType::MediaReceived,
                        conversation_id,
                        message_id: Some(message_id),
                        payload,
                        created_at_ms: skel.created_at_ms,
                    },
                )
                .map_err(|e| Error::Storage(e.to_string()))?;

            Ok(SendMediaResult {
                client_message_id: ClientMessageId(message_id),
                asset_id,
                descriptor,
            })
        })();

        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE send_media;")
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK TO send_media; RELEASE send_media;");
            }
        }
        result
    }

    // Field names mirror the `PerfTrace::insert_metadata` keys
    // below (`reason`, `is_cold`, `offline`). Deferred fields are
    // filled in via `Span::current().record` next to the matching
    // `trace.insert_metadata` calls below.
    #[tracing::instrument(
        skip(self),
        fields(
            message_id = %message_id,
            reason,
            is_cold = tracing::field::Empty,
            offline = tracing::field::Empty,
        ),
    )]
    fn hydrate_message(&self, message_id: Uuid, reason: &str) -> Result<HydratedMessage> {
        // Phase 7 (2026-05-04 batch 10) — Task 7: instrument the
        // hydrate hot path with a [`PerfTrace`] so an installed
        // collector can measure end-to-end hydration latency.
        // The closure captures `trace` mutably so the success
        // path can attach `is_cold` / `offline` metadata before
        // the surrounding match records the finished trace.
        let mut trace = crate::perf::PerfTrace::new("hydrate_message");
        trace.insert_metadata("reason", reason.to_string());

        let trace_ref = &mut trace;
        let result: Result<HydratedMessage> = (|| {
            // Phase-3 foundation: serve from local storage when a body is
            // already present, otherwise return the skeleton with
            // `is_cold = true`. The remote archive fetch path is still
            // queued for `Task 10+` once the manifest reader lands.
            let db = self.db.lock().map_err(poisoned)?;
            let row = db
                .get_message_with_body(&message_id.to_string())
                .map_err(|e| Error::Storage(e.to_string()))?;
            let Some((skeleton, body)) = row else {
                return Ok(HydratedMessage::default());
            };
            if skeleton.body_state == BodyState::DeletedForEveryone {
                return Err(Error::Message(
                    "hydrate_message: message has been deleted for everyone".to_string(),
                ));
            }
            let conversation_id = Uuid::parse_str(&skeleton.conversation_id).ok();
            let message_id_uuid = Uuid::parse_str(&skeleton.message_id).ok();
            let is_local = matches!(
                skeleton.body_state,
                BodyState::LocalPlainAvailable | BodyState::LocalEncryptedAvailable
            );
            let text_content = body.as_ref().and_then(|b| b.text_content.clone());

            // Detect whether an evicted media asset is attached. We
            // surface this so the worker can lazily re-download the
            // blob when the user taps the row (Task 5 — Phase 3
            // §5.5). The lookup is cheap (`media_asset` carries an
            // index on `message_id`) and the enqueue happens
            // unconditionally below.
            let has_evicted_media = db
                .get_media_asset_by_message(&skeleton.message_id)
                .map(|opt| {
                    opt.map(|a| matches!(a.media_state, MediaState::Evicted))
                        .unwrap_or(false)
                })
                .unwrap_or(false);

            // Enqueue a hydration request regardless of whether the
            // body is local — when the orchestration layer drains the
            // queue it will skip already-served messages, but the
            // queue still needs a record of the access for telemetry
            // and adjacent prefetch. When evicted media is attached we
            // bump the priority to [`HydrationReason::MediaFullScreen`]
            // so the worker pulls the bytes ahead of opportunistic
            // skeleton fetches.
            if let Some(conv) = conversation_id {
                let mut priority = parse_hydration_reason(reason);
                // Variant order maps to P0..P5 — *smaller* `Ord` means
                // *higher* priority. Escalate to MediaFullScreen
                // whenever the caller asked for something lower-priority
                // than P1 (MediaFullScreen).
                if has_evicted_media && priority > HydrationReason::MediaFullScreen {
                    priority = HydrationReason::MediaFullScreen;
                }
                let mut queue = self.hydration_queue.lock().map_err(poisoned)?;
                queue.enqueue(HydrationRequest {
                    message_id,
                    conversation_id: conv,
                    reason: priority,
                    requested_at_ms: now_ms_for_send_media(),
                });
            }

            // Phase 7, Task 6 (2026-05-04 batch): expose an explicit
            // `offline` flag on the hydration result so renderers
            // can distinguish "cold but reachable, fetch in flight"
            // from "cold and offline, retry on reconnect". The flag
            // is `true` only when the body is non-local AND the
            // installed `OfflineDetector` reports offline; without a
            // detector installed `is_online()` is always `true`, so
            // the flag stays `false` for callers that never wired
            // one in.
            let offline = !is_local && !self.is_online();
            trace_ref.insert_metadata("is_cold", (!is_local).to_string());
            trace_ref.insert_metadata("offline", offline.to_string());
            tracing::Span::current().record("is_cold", !is_local);
            tracing::Span::current().record("offline", offline);
            Ok(HydratedMessage {
                message_id: message_id_uuid,
                conversation_id,
                text_content: if is_local { text_content } else { None },
                is_cold: !is_local,
                offline,
            })
        })();
        if let Err(e) = result.as_ref() {
            trace.insert_metadata("error", e.to_string());
        }
        trace.finish();
        self.record_perf_trace(trace);
        result
    }

    // Field names mirror the `PerfTrace::insert_metadata` keys
    // below (`reason`, `deferred`, `segments_built`,
    // `events_segmented`). Deferred fields are filled in via
    // `Span::current().record` next to the matching
    // `trace.insert_metadata` calls below.
    #[tracing::instrument(
        skip(self),
        fields(
            reason,
            deferred = tracing::field::Empty,
            segments_built = tracing::field::Empty,
            events_segmented = tracing::field::Empty,
        ),
    )]
    fn run_incremental_backup(&self, reason: &str) -> Result<BackupResult> {
        // Phase 7, Task 8 (2026-05-04 batch): instrument the
        // backup hot path. `start_ns` is captured up front so
        // the trace covers both the offline short-circuit and
        // the full segment-build + upload path.
        let mut trace = crate::perf::PerfTrace::new("run_incremental_backup");
        trace.insert_metadata("reason", reason);

        // Phase 7, Task 6 (2026-05-04 batch): defer the upload
        // when the device is offline. The segment building is
        // unchanged — sealed segments still land in
        // `tracked_backup_segments` so the next online run
        // picks them up. The new `deferred` flag tells the
        // caller the upload step was skipped.
        if !self.is_online() {
            let result = BackupResult {
                deferred: true,
                ..BackupResult::default()
            };
            trace.insert_metadata("deferred", "true");
            tracing::Span::current().record("deferred", true);
            trace.finish();
            self.record_perf_trace(trace);
            return Ok(result);
        }
        let (mut result, _sealed) = match self.run_incremental_backup_inner(reason) {
            Ok(pair) => pair,
            Err(e) => {
                trace.insert_metadata("error", e.to_string());
                trace.finish();
                self.record_perf_trace(trace);
                return Err(e);
            }
        };
        result.deferred = false;
        trace.insert_metadata("segments_built", result.segments_built.to_string());
        trace.insert_metadata("events_segmented", result.events_segmented.to_string());
        let span = tracing::Span::current();
        span.record("deferred", false);
        span.record("segments_built", result.segments_built);
        span.record("events_segmented", result.events_segmented);
        trace.finish();
        self.record_perf_trace(trace);
        Ok(result)
    }

    // Field names mirror the `PerfTrace::insert_metadata` keys
    // below (`pressure_level`, `freed_bytes`, `evicted_count`).
    // Deferred fields are filled in via `Span::current().record`
    // next to the matching `trace.insert_metadata` calls below.
    #[tracing::instrument(
        skip(self),
        fields(
            reason = _reason,
            pressure_level = tracing::field::Empty,
            evicted_count = tracing::field::Empty,
            freed_bytes = tracing::field::Empty,
        ),
    )]
    fn enforce_storage_budget(&self, _reason: &str) -> Result<OffloadResult> {
        // Phase 7, Task 8 (2026-05-04 batch): wrap the eviction
        // hot path with [`crate::perf::PerfTrace`]. We capture
        // `pressure_level`, `evicted_count`, and `freed_bytes`
        // so callers can plot pressure-vs-recovery curves.
        let mut trace = crate::perf::PerfTrace::new("enforce_storage_budget");

        // Phase-3 foundation: assess pressure and execute an
        // empty plan when no candidates are surfaced. The body is
        // wrapped in an immediately-invoked closure so every error
        // path closes the trace before propagating, per the
        // contract documented in `docs/ARCHITECTURE.md` §11.11.
        let outcome: Result<(OffloadResult, String)> = (|| -> Result<(OffloadResult, String)> {
            let db = self.db.lock().map_err(poisoned)?;
            let enforcer = StorageBudgetEnforcer::new();
            let budget = StorageBudget::default_recommended();
            let assessment = enforcer.assess(db.connection(), &budget)?;
            let pressure_str = format!("{:?}", assessment.pressure_level);
            if !assessment.pressure_level.requires_eviction() {
                return Ok((
                    OffloadResult {
                        freed_bytes: 0,
                        evicted_count: 0,
                    },
                    pressure_str,
                ));
            }
            // `eviction_target_bytes` is threshold-relative (Warning →
            // warning_bytes, Critical → critical_bytes, Extreme →
            // max_bytes). Driving the planner directly off
            // `(-headroom).max(0)` would only produce a non-zero target
            // for Extreme pressure.
            let target_bytes = assessment.eviction_target_bytes();
            let now_ms = now_ms_for_send_media();
            // `MIN_OFFLOAD_AGE_MS`: keep media less than 24 h old
            // resident locally so the typical
            // "scroll back to yesterday" pattern does not trigger an
            // immediate refetch from cold storage. Phase 5 will lift
            // this into a per-tenant configurable knob.
            const MIN_OFFLOAD_AGE_MS: i64 = 24 * 60 * 60 * 1000;
            let candidates =
                collect_eviction_candidates(db.connection(), MIN_OFFLOAD_AGE_MS, now_ms)?;
            // Tiered eviction (`docs/PROPOSAL.md §5.4`): exhaust the
            // cloud-offload pool first; only fall through to the
            // KChat-backend pool if the cloud pass underran the budget.
            let tiered =
                plan_tiered_eviction(candidates, target_bytes, now_ms, assessment.pressure_level);
            let cloud_result = execute_eviction(db.connection(), &tiered.cloud_offload)?;
            let full_result = execute_eviction(db.connection(), &tiered.full_eviction)?;
            let out = OffloadResult {
                freed_bytes: cloud_result
                    .freed_bytes
                    .saturating_add(full_result.freed_bytes),
                evicted_count: cloud_result
                    .evicted_count
                    .saturating_add(full_result.evicted_count),
            };
            Ok((out, pressure_str))
        })();
        match outcome {
            Ok((out, pressure_str)) => {
                tracing::Span::current().record("pressure_level", pressure_str.as_str());
                tracing::Span::current().record("freed_bytes", out.freed_bytes);
                tracing::Span::current().record("evicted_count", out.evicted_count);
                trace.insert_metadata("pressure_level", pressure_str);
                trace.insert_metadata("freed_bytes", out.freed_bytes.to_string());
                trace.insert_metadata("evicted_count", out.evicted_count.to_string());

                // Phase 7 (2026-05-04 batch 10 — Task 9): when
                // configured, attempt to schedule a media
                // migration after a non-empty eviction pass. We
                // swallow scheduling errors here because the
                // eviction itself succeeded — the orchestration
                // layer surfaces scheduler outages through
                // `has_scheduler` / explicit
                // `schedule_media_migration` retries.
                if out.evicted_count > 0 {
                    if let Some((src, tgt)) = self.config.auto_migrate_after_eviction.clone() {
                        match self.plan_and_schedule_media_migration(&src, &tgt) {
                            Ok(true) => {
                                trace.insert_metadata("migration_scheduled", "true".to_string());
                            }
                            Ok(false) => {
                                trace.insert_metadata("migration_scheduled", "empty".to_string());
                            }
                            Err(e) => {
                                trace.insert_metadata("migration_scheduled", format!("error:{e}"));
                            }
                        }
                    }
                }

                trace.finish();
                self.record_perf_trace(trace);
                Ok(out)
            }
            Err(e) => {
                trace.insert_metadata("error", e.to_string());
                trace.finish();
                self.record_perf_trace(trace);
                Err(e)
            }
        }
    }

    fn restore_from_backup(&self, _source: BackupSource) -> Result<RestoreResult> {
        // Phase 7 (2026-05-04 batch 10) — Task 7: instrument the
        // restore hot path. Each transition is also recorded as a
        // `transition` metadata field for finer-grained
        // attribution.
        let mut trace = crate::perf::PerfTrace::new("restore_from_backup");

        // Phase-4 wiring: drive the restore state machine end-to-end
        // through the skeleton-first pipeline. The transport-side
        // contract on `BackupSource` (manifest chain handle, segment
        // download channel, search-shard segments, …) is still a
        // placeholder, so the pipeline currently runs with empty
        // inputs and demonstrates the orchestration is in place.
        // Search-index shards land via
        // [`CoreImpl::restore_search_shards`] today; once
        // `BackupSource` is fleshed out, the segments, manifests,
        // and shard list flow through here unchanged.
        let result = (|| -> Result<RestoreResult> {
            let db = self.db.lock().map_err(poisoned)?;
            let conn = db.connection();
            crate::restore::state_machine::reset(conn)?;
            let mut transitions = 0usize;
            for st in [
                crate::local_store::state_machines::RestoreState::IdentityRestored,
                crate::local_store::state_machines::RestoreState::RootKeysUnwrapped,
                crate::local_store::state_machines::RestoreState::ManifestVerified,
                crate::local_store::state_machines::RestoreState::SkeletonRestored,
                crate::local_store::state_machines::RestoreState::SearchRestored,
                crate::local_store::state_machines::RestoreState::RecentMessagesRestored,
                crate::local_store::state_machines::RestoreState::MediaLazyRestoreEnabled,
                crate::local_store::state_machines::RestoreState::FullRestoreComplete,
            ] {
                crate::restore::state_machine::transition(conn, st, None)?;
                transitions += 1;
            }
            let _ = transitions;
            Ok(RestoreResult::default())
        })();

        if let Err(e) = result.as_ref() {
            trace.insert_metadata("error", e.to_string());
        } else {
            trace.insert_metadata("transitions", "8".to_string());
        }
        trace.finish();
        self.record_perf_trace(trace);
        result
    }
}

fn poisoned<T>(_e: std::sync::PoisonError<T>) -> Error {
    Error::Storage("local store mutex poisoned".to_string())
}

/// Map a UI-supplied reason string to a [`HydrationReason`].
///
/// `docs/PROPOSAL.md §5.5` defines the priority ladder. Unknown
/// strings collapse to `OpportunisticFill` (P5), the lowest
/// priority — that way a stale or typo'd reason never starves a
/// real P0 search-result tap behind it.
fn parse_hydration_reason(reason: &str) -> HydrationReason {
    match reason {
        "search_result_tap" => HydrationReason::SearchResultTap,
        "media_fullscreen" | "media_full_screen" => HydrationReason::MediaFullScreen,
        "visible_viewport" => HydrationReason::VisibleViewport,
        "prefetch" | "adjacent_prefetch" => HydrationReason::AdjacentPrefetch,
        "background_restore" => HydrationReason::BackgroundRestore,
        "idle_fill" | "opportunistic_fill" => HydrationReason::OpportunisticFill,
        _ => HydrationReason::OpportunisticFill,
    }
}

/// Wall-clock millisecond timestamp.
///
/// Mirrors `crate::message::processor::now_ms` (which is private)
/// so the `send_media` / `hydrate_message` paths can stamp
/// `received_at_ms` / `created_at_ms` without poking through the
/// processor module.
fn now_ms_for_send_media() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Convert a transport-level [`RawDeliveryMessage`] into the local
/// [`IngestedMessage`] shape. UUID strings are parsed here; on
/// failure we surface the error as [`Error::Transport`] because the
/// id format is dictated by the delivery store.
fn raw_delivery_to_ingested(raw: &RawDeliveryMessage) -> Result<IngestedMessage> {
    let message_id = Uuid::parse_str(&raw.message_id)
        .map_err(|e| Error::Transport(format!("invalid message_id: {e}")))?;
    let conversation_id = Uuid::parse_str(&raw.conversation_id)
        .map_err(|e| Error::Transport(format!("invalid conversation_id: {e}")))?;
    let reply_to = match &raw.reply_to {
        None => None,
        Some(s) => Some(
            Uuid::parse_str(s).map_err(|e| Error::Transport(format!("invalid reply_to: {e}")))?,
        ),
    };
    Ok(IngestedMessage {
        message_id,
        conversation_id,
        sender_id: raw.sender_id.clone(),
        created_at_ms: raw.created_at_ms,
        text_content: raw.text_content.clone(),
        media_descriptors: raw.media_descriptors.clone(),
        reply_to,
    })
}

/// Map a `(MessageSkeleton, Option<MessageBody>)` pair from the
/// `LocalStoreDb` into the public [`MessageView`] shape, parsing
/// id strings back into `Uuid` and propagating parse failures as
/// [`Error::Storage`] (the strings are persisted by us, so a
/// parse failure indicates a corrupted store).
fn skeleton_and_body_to_view(
    skel: MessageSkeleton,
    body: Option<MessageBody>,
) -> Result<MessageView> {
    let message_id = Uuid::parse_str(&skel.message_id)
        .map_err(|e| Error::Storage(format!("invalid message_id in store: {e}")))?;
    let conversation_id = Uuid::parse_str(&skel.conversation_id)
        .map_err(|e| Error::Storage(format!("invalid conversation_id in store: {e}")))?;
    let reply_to = match &skel.reply_to {
        None => None,
        Some(s) => Some(
            Uuid::parse_str(s)
                .map_err(|e| Error::Storage(format!("invalid reply_to in store: {e}")))?,
        ),
    };
    let text_content = body.and_then(|b| b.text_content);
    Ok(MessageView {
        message_id,
        conversation_id,
        sender_id: skel.sender_id,
        created_at_ms: skel.created_at_ms,
        received_at_ms: skel.received_at_ms,
        reply_to,
        edited_at_ms: skel.edited_at_ms,
        deleted_at_ms: skel.deleted_at_ms,
        text_content,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::Platform;
    use crate::message::processor::IngestedMessage;

    const TEST_KEY: [u8; 32] = [0x42; 32];

    fn test_config() -> KChatCoreConfig {
        KChatCoreConfig::new(
            PathBuf::from("/tmp/kchat-core-impl-tests"),
            Platform::MacOs,
            "tenant-test",
        )
    }

    fn fresh_core() -> CoreImpl {
        CoreImpl::new_in_memory(test_config(), TEST_KEY).expect("core")
    }

    fn seed_conversation(core: &CoreImpl, conv: &Uuid) {
        core.with_db(|db| {
            let conv_row = crate::local_store::schema::Conversation {
                conversation_id: conv.to_string(),
                title_cipher: None,
                pinned: false,
                muted: false,
                last_message_id: None,
                last_activity_ms: 1,
                ..Default::default()
            };
            db.insert_conversation(&conv_row).unwrap();
        });
    }

    #[test]
    fn core_impl_initialize_and_send_text() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mid = core.send_text(conv, "hello world", None).expect("send");
        assert_eq!(mid.0.get_version_num(), 7);

        // Skeleton must exist with body_state=local_plain_available.
        core.with_db(|db| {
            let skel = db
                .get_message_skeleton(&mid.0.to_string())
                .unwrap()
                .expect("skeleton");
            assert_eq!(
                skel.body_state,
                crate::local_store::state_machines::BodyState::LocalPlainAvailable
            );
            let body = db
                .get_message_body(&mid.0.to_string())
                .unwrap()
                .expect("body");
            assert_eq!(body.text_content.as_deref(), Some("hello world"));
        });
    }

    #[test]
    fn core_impl_search_returns_persisted_messages() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        core.send_text(conv, "alpha beta gamma", None).unwrap();
        core.send_text(conv, "delta epsilon zeta", None).unwrap();

        let q = SearchQuery {
            query_string: "epsilon".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn core_impl_ingest_and_search_round_trip() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let msgs = vec![
            IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: Some("the quick brown fox".into()),
                media_descriptors: vec![],
                reply_to: None,
            },
            IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: "user-2".into(),
                created_at_ms: 1_700_000_000_001,
                text_content: Some("jumps over the lazy dog".into()),
                media_descriptors: vec![],
                reply_to: None,
            },
        ];
        let result = core.ingest_messages(&msgs).expect("ingest");
        assert_eq!(result.new_messages, 2);
        assert_eq!(result.duplicate_count, 0);

        let q = SearchQuery {
            query_string: "quick".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 1);

        let q = SearchQuery {
            query_string: "lazy".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn core_impl_duplicate_rejection() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("only once".into()),
            media_descriptors: vec![],
            reply_to: None,
        };
        let r1 = core.ingest_messages(std::slice::from_ref(&msg)).unwrap();
        assert_eq!(r1.new_messages, 1);
        assert_eq!(r1.duplicate_count, 0);

        let r2 = core.ingest_messages(std::slice::from_ref(&msg)).unwrap();
        assert_eq!(r2.new_messages, 0);
        assert_eq!(r2.duplicate_count, 1);
    }

    #[test]
    fn core_impl_initialize_swaps_data_dir() {
        // initialize() re-opens the database at the new config's
        // data_dir using the stored K_local_db. Use a tempdir so the
        // re-open is real I/O, not in-memory.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = KChatCoreConfig::new(tmp.path().to_path_buf(), Platform::MacOs, "tenant-test");
        let mut core = CoreImpl::new(cfg, TEST_KEY).expect("core");

        let tmp2 = tempfile::tempdir().unwrap();
        let cfg2 = KChatCoreConfig::new(tmp2.path().to_path_buf(), Platform::MacOs, "tenant-test");
        core.initialize(cfg2.clone()).expect("re-open");
        assert_eq!(core.config().data_dir, cfg2.data_dir);

        // Database is fresh — sending a message after re-init still
        // works.
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        core.send_text(conv, "after reinit", None).unwrap();
    }

    #[test]
    fn core_impl_ingest_remote_without_transport_errors() {
        let core = fresh_core();
        let err = core
            .ingest_remote_messages(Uuid::now_v7(), None)
            .unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "got {err:?}");
    }

    #[test]
    fn core_impl_send_text_rejects_empty_string() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let err = core.send_text(conv, "", None).unwrap_err();
        assert!(matches!(err, Error::Message(_)), "got {err:?}");
    }

    #[test]
    fn core_impl_config_round_trips() {
        let core = fresh_core();
        assert_eq!(core.config().tenant_id, "tenant-test");
        assert_eq!(core.config().platform, Platform::MacOs);
    }

    // ----------------------------------------------------------------
    // Phase-1 stub trait methods — Task 3
    // ----------------------------------------------------------------

    fn fake_image_bytes() -> Vec<u8> {
        // 8 × 8 PNG with a varied gradient so the encoder produces a
        // reasonable byte count (uniform-colour PNGs collapse to a
        // few dozen bytes which doesn't exercise the chunker).
        use image::{ImageBuffer, ImageFormat, Rgba};
        use std::io::Cursor;
        let img = ImageBuffer::from_fn(64, 64, |x, y| {
            Rgba([
                ((x * 4) & 0xFF) as u8,
                ((y * 4) & 0xFF) as u8,
                ((x ^ y) & 0xFF) as u8,
                0xFF,
            ])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn send_media_persists_media_asset_and_descriptor() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let payload = fake_image_bytes();
        let bytes_total = payload.len() as u64;

        let res = core
            .send_media(conv, mid, payload, "image/png", Some("vacation"))
            .expect("send_media");
        assert_eq!(res.client_message_id.0, mid);
        assert_eq!(res.descriptor.bytes_total, bytes_total);
        assert_eq!(res.descriptor.mime_type, "image/png");
        assert!(res.descriptor.chunk_count >= 1);

        core.with_db(|db| {
            let asset = db
                .get_media_asset(&res.asset_id.to_string())
                .unwrap()
                .expect("asset row");
            assert_eq!(asset.message_id, mid.to_string());
            assert_eq!(asset.mime_type, "image/png");
            assert_eq!(asset.bytes_total as u64, bytes_total);
            assert_eq!(asset.chunk_count as u32, res.descriptor.chunk_count);
            assert_eq!(asset.merkle_root.len(), 32);
        });
    }

    #[test]
    fn send_media_creates_skeleton_with_media_state() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        core.with_db(|db| {
            let skel = db
                .get_message_skeleton(&mid.to_string())
                .unwrap()
                .expect("skeleton");
            assert_eq!(skel.kind, MessageKind::Media);
            assert!(skel.media_state.is_some());
            assert_eq!(
                skel.body_state,
                crate::local_store::state_machines::BodyState::LocalPlainAvailable
            );
        });
    }

    #[test]
    fn send_media_round_trips_through_get_message() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(
            conv,
            mid,
            fake_image_bytes(),
            "image/png",
            Some("captioned"),
        )
        .expect("send_media");

        let view = core.get_message(mid).unwrap().expect("view");
        assert_eq!(view.text_content.as_deref(), Some("captioned"));
    }

    #[test]
    fn send_media_rejects_empty_plaintext() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let err = core
            .send_media(conv, Uuid::now_v7(), Vec::new(), "image/png", None)
            .unwrap_err();
        assert!(matches!(err, Error::Message(_)), "got {err:?}");
    }

    #[test]
    fn send_media_caption_is_searchable() {
        // Bug guard: the caption MUST land in `search_fts` /
        // `search_fuzzy` so `core.search()` returns the media
        // message. Without the FTS / fuzzy index path inside the
        // SAVEPOINT this returns 0 hits.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        core.send_media(
            conv,
            mid,
            fake_image_bytes(),
            "image/png",
            Some("kayaking trip with grandparents"),
        )
        .expect("send_media");

        let q = SearchQuery {
            query_string: "kayaking".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 1, "caption FTS row missing? hits={hits:?}");
        assert_eq!(hits[0].message_id, mid);
    }

    #[test]
    fn send_media_writes_backup_event_journal_entry() {
        // Bug guard: send_media must mirror send_text and append
        // a `backup_event_journal` row so the Phase 4 backup
        // drainer sees the media message. Without this, media
        // messages are silently excluded from incremental backups.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        core.with_db(|db| {
            // Single 'outbox_pending' row whose CBOR payload's
            // first text field equals message_id.
            let conn = db.connection();
            let row: (String, Vec<u8>) = conn
                .query_row(
                    "SELECT event_type, payload FROM backup_event_journal
                       ORDER BY event_seq DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .expect("journal row");
            assert_eq!(row.0, "outbox_pending");
            // CBOR text strings of length n (n < 24) are tagged
            // as 0x60 | n. The message_id UUID renders to 36
            // bytes, so the payload starts with [0x84 (array-4),
            // 0x78 (text-uint8-len), 0x24 (36)] then the bytes.
            let mid_str = mid.to_string();
            assert!(
                row.1
                    .windows(mid_str.len())
                    .any(|w| w == mid_str.as_bytes()),
                "payload missing message_id: {:?}",
                row.1
            );
        });
    }

    #[test]
    fn send_media_writes_archive_event() {
        // Phase-3 mirror of `send_media_writes_backup_event_journal_entry`:
        // the same SAVEPOINT must also append a `media_received`
        // row to `archive_event_journal` so the segment builder
        // pulls the media asset into the next archive segment.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        core.with_db(|db| {
            let count: i64 = db
                .connection()
                .query_row(
                    "SELECT count(*) FROM archive_event_journal
                       WHERE event_type = 'media_received'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1);
        });
    }

    #[test]
    fn send_media_bumps_conversation_last_activity() {
        // Bug guard: the conversation list ranks by
        // `last_activity_ms`. If `send_media` skips
        // `update_conversation_last_message`, the conversation
        // stays at `last_activity_ms = 1` (the seed value) and the
        // freshly-sent media message never appears at the top.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mid = Uuid::now_v7();
        core.send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        let convs = core.list_conversations().expect("list");
        let row = convs
            .into_iter()
            .find(|c| c.conversation_id == conv.to_string())
            .expect("seeded conversation");
        assert_eq!(
            row.last_message_id.as_deref(),
            Some(mid.to_string().as_str())
        );
        // seed value was 1; the persister's now_ms() is wall-clock,
        // so anything strictly greater than the seed is correct.
        assert!(row.last_activity_ms > 1, "last_activity_ms not bumped");
    }

    // ----------------------------------------------------------------
    // hydrate_message + enforce_storage_budget — Task 10
    // ----------------------------------------------------------------

    #[test]
    fn hydrate_local_message_returns_body() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "hello hydration", None).unwrap();
        let hydrated = core
            .hydrate_message(mid.0, "search_result_tap")
            .expect("hydrate");
        assert!(!hydrated.is_cold);
        assert_eq!(hydrated.text_content.as_deref(), Some("hello hydration"));
        assert_eq!(hydrated.message_id, Some(mid.0));
        assert_eq!(hydrated.conversation_id, Some(conv));
    }

    #[test]
    fn hydrate_unknown_message_returns_default() {
        let core = fresh_core();
        let result = core
            .hydrate_message(Uuid::now_v7(), "search_result_tap")
            .expect("hydrate");
        assert_eq!(result, HydratedMessage::default());
    }

    #[test]
    fn hydrate_deleted_message_returns_error() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "to-be-deleted", None).unwrap();
        // Force the body_state into DeletedForEveryone so the
        // hydrate path takes the error branch.
        core.with_db(|db| {
            db.connection()
                .execute(
                    "UPDATE message_skeleton SET body_state = 'deleted_for_everyone' WHERE message_id = ?1",
                    rusqlite::params![mid.0.to_string()],
                )
                .unwrap();
        });
        let err = core
            .hydrate_message(mid.0, "search_result_tap")
            .unwrap_err();
        assert!(matches!(err, Error::Message(_)), "got {err:?}");
    }

    #[test]
    fn hydrate_cold_message_returns_skeleton_with_cold_flag() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "cold-body", None).unwrap();
        // Move the body to remote_archive_only so hydrate sees it
        // as cold.
        core.with_db(|db| {
            db.connection()
                .execute(
                    "UPDATE message_skeleton SET body_state = 'remote_archive_only' WHERE message_id = ?1",
                    rusqlite::params![mid.0.to_string()],
                )
                .unwrap();
        });
        let hydrated = core
            .hydrate_message(mid.0, "background_restore")
            .expect("hydrate");
        assert!(hydrated.is_cold);
        assert!(hydrated.text_content.is_none());
        assert_eq!(hydrated.message_id, Some(mid.0));
    }

    #[test]
    fn enforce_storage_budget_returns_zero_under_pressure_threshold() {
        let core = fresh_core();
        // Empty store — no pressure, so the result is zero.
        let result = core.enforce_storage_budget("app_launch").expect("enforce");
        assert_eq!(result.evicted_count, 0);
        assert_eq!(result.freed_bytes, 0);
    }

    #[test]
    fn run_incremental_backup_with_empty_store_is_noop() {
        // Phase-4 wiring (Task 3): when no events have been
        // journaled and no backup keys are installed, the call
        // short-circuits to a default `BackupResult` rather than
        // erroring — there is nothing to seal, so there is no
        // need for keys.
        let core = fresh_core();
        let result = core
            .run_incremental_backup("scheduled")
            .expect("noop on empty store");
        assert_eq!(result, BackupResult::default());
    }

    #[test]
    fn restore_from_backup_walks_state_machine_to_full_complete() {
        let core = fresh_core();
        let result = core
            .restore_from_backup(BackupSource::default())
            .expect("restore_from_backup should walk to FullRestoreComplete");
        assert_eq!(result, RestoreResult::default());
        let db = core.db.lock().unwrap();
        let (state, _) = crate::restore::state_machine::load(db.connection())
            .unwrap()
            .expect("restore_state row should be persisted");
        assert_eq!(
            state,
            crate::local_store::state_machines::RestoreState::FullRestoreComplete
        );
    }

    // ----------------------------------------------------------------
    // Conversation management — Task 4
    // ----------------------------------------------------------------

    #[test]
    fn create_and_list_conversations() {
        let core = fresh_core();
        let c_old = Uuid::now_v7();
        let c_mid = Uuid::now_v7();
        let c_new = Uuid::now_v7();
        core.create_conversation(c_old, Some("old"), 1_000).unwrap();
        core.create_conversation(c_mid, None, 2_000).unwrap();
        core.create_conversation(c_new, Some("new"), 3_000).unwrap();

        let list = core.list_conversations().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].conversation_id, c_new.to_string());
        assert_eq!(list[1].conversation_id, c_mid.to_string());
        assert_eq!(list[2].conversation_id, c_old.to_string());
        assert_eq!(list[0].title_cipher.as_deref(), Some(b"new" as &[u8]));
        assert_eq!(list[1].title_cipher, None);
    }

    #[test]
    fn get_conversation_returns_none_for_missing() {
        let core = fresh_core();
        assert_eq!(core.get_conversation(Uuid::now_v7()).unwrap(), None);
    }

    #[test]
    fn pin_and_mute_round_trip() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        core.create_conversation(conv, Some("daily-standup"), 1_000)
            .unwrap();
        let row = core.get_conversation(conv).unwrap().unwrap();
        assert!(!row.pinned);
        assert!(!row.muted);

        core.update_conversation_pin(conv, true).unwrap();
        core.update_conversation_mute(conv, true).unwrap();
        let row = core.get_conversation(conv).unwrap().unwrap();
        assert!(row.pinned);
        assert!(row.muted);

        core.update_conversation_pin(conv, false).unwrap();
        core.update_conversation_mute(conv, false).unwrap();
        let row = core.get_conversation(conv).unwrap().unwrap();
        assert!(!row.pinned);
        assert!(!row.muted);
    }

    #[test]
    fn pin_missing_conversation_errors() {
        let core = fresh_core();
        let err = core
            .update_conversation_pin(Uuid::now_v7(), true)
            .unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn mute_missing_conversation_errors() {
        let core = fresh_core();
        let err = core
            .update_conversation_mute(Uuid::now_v7(), true)
            .unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn list_conversations_orders_pinned_first() {
        let core = fresh_core();
        let c_a = Uuid::now_v7();
        let c_b = Uuid::now_v7();
        core.create_conversation(c_a, None, 1_000).unwrap();
        core.create_conversation(c_b, None, 2_000).unwrap();
        core.update_conversation_pin(c_a, true).unwrap();

        let list = core.list_conversations().unwrap();
        assert_eq!(list[0].conversation_id, c_a.to_string());
        assert!(list[0].pinned);
        assert_eq!(list[1].conversation_id, c_b.to_string());
    }

    // ----------------------------------------------------------------
    // Task 1 — edit / delete on the KChatCore trait
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_edit_message_updates_body_and_search() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core
            .send_text(conv, "the rain in spain", None)
            .expect("send");

        // Sanity: the original token is searchable.
        let q = SearchQuery {
            query_string: "rain".to_string(),
            ..SearchQuery::default()
        };
        assert_eq!(
            core.search(q, SearchScope::LocalOnly).unwrap().len(),
            1,
            "original text should be searchable"
        );

        core.edit_message(mid.0, "the snow in moscow")
            .expect("edit");

        // Body text reflects the edit.
        core.with_db(|db| {
            let body = db
                .get_message_body(&mid.0.to_string())
                .unwrap()
                .expect("body");
            assert_eq!(body.text_content.as_deref(), Some("the snow in moscow"));
            let skel = db
                .get_message_skeleton(&mid.0.to_string())
                .unwrap()
                .expect("skel");
            assert!(skel.edited_at_ms.is_some());
        });

        // Old token no longer matches; new token does.
        let q_old = SearchQuery {
            query_string: "rain".to_string(),
            ..SearchQuery::default()
        };
        assert!(
            core.search(q_old, SearchScope::LocalOnly)
                .unwrap()
                .is_empty(),
            "old text must not be searchable after edit"
        );
        let q_new = SearchQuery {
            query_string: "snow".to_string(),
            ..SearchQuery::default()
        };
        assert_eq!(
            core.search(q_new, SearchScope::LocalOnly).unwrap().len(),
            1,
            "new text must be searchable after edit"
        );
    }

    #[test]
    fn core_impl_delete_for_me_removes_from_search() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "secret plans", None).expect("send");

        core.delete_for_me(mid.0).expect("delete");

        let q = SearchQuery {
            query_string: "secret".to_string(),
            ..SearchQuery::default()
        };
        assert!(
            core.search(q, SearchScope::LocalOnly).unwrap().is_empty(),
            "delete_for_me must remove the message from search"
        );

        // Body row is preserved for delete_for_me.
        core.with_db(|db| {
            let body = db.get_message_body(&mid.0.to_string()).unwrap();
            assert!(body.is_some(), "body must survive delete_for_me");
        });
    }

    #[test]
    fn core_impl_delete_for_everyone_removes_body() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core
            .send_text(conv, "tombstone material", None)
            .expect("send");

        core.delete_for_everyone(mid.0).expect("delete");

        // Skeleton stays so the timeline can render a tombstone, but
        // the body row is gone.
        core.with_db(|db| {
            let skel = db
                .get_message_skeleton(&mid.0.to_string())
                .unwrap()
                .expect("skel");
            assert_eq!(
                skel.body_state,
                crate::local_store::state_machines::BodyState::DeletedForEveryone
            );
            let body = db.get_message_body(&mid.0.to_string()).unwrap();
            assert!(
                body.is_none(),
                "body must be dropped on delete_for_everyone"
            );
        });
    }

    #[test]
    fn core_impl_edit_nonexistent_message_errors() {
        let core = fresh_core();
        let err = core.edit_message(Uuid::now_v7(), "anything").unwrap_err();
        assert!(matches!(err, Error::Message(_)), "got {err:?}");
    }

    // ----------------------------------------------------------------
    // Task 2 — get_message / get_conversation_messages
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_get_message_round_trip() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "round trip", None).expect("send");

        let view = core.get_message(mid.0).expect("get_message").expect("view");
        assert_eq!(view.message_id, mid.0);
        assert_eq!(view.conversation_id, conv);
        assert_eq!(view.text_content.as_deref(), Some("round trip"));
        assert_eq!(view.sender_id, "self");
        assert!(view.edited_at_ms.is_none());
        assert!(view.deleted_at_ms.is_none());

        // Missing id round-trips to None.
        assert!(core.get_message(Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn core_impl_get_conversation_messages_pagination() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Insert 5 messages with strictly-increasing created_at_ms
        // via the inherent batch ingest path so timestamps are
        // deterministic.
        let mut ids = Vec::new();
        for i in 0..5 {
            let msg = IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: format!("u-{i}"),
                created_at_ms: 1_700_000_000_000 + i as i64,
                text_content: Some(format!("msg {i}")),
                media_descriptors: vec![],
                reply_to: None,
            };
            ids.push(msg.message_id);
            let r = core.ingest_messages(std::slice::from_ref(&msg)).unwrap();
            assert_eq!(r.new_messages, 1);
        }

        // Newest-first, limit honored.
        let page1 = core.get_conversation_messages(conv, None, 3).unwrap();
        assert_eq!(page1.len(), 3);
        assert_eq!(page1[0].message_id, ids[4]);
        assert_eq!(page1[1].message_id, ids[3]);
        assert_eq!(page1[2].message_id, ids[2]);

        // Pagination via before_ms returns the older slice.
        let cursor = page1.last().unwrap().created_at_ms;
        let page2 = core
            .get_conversation_messages(conv, Some(cursor), 10)
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].message_id, ids[1]);
        assert_eq!(page2[1].message_id, ids[0]);

        // limit == 0 returns nothing.
        assert!(
            core.get_conversation_messages(conv, None, 0)
                .unwrap()
                .is_empty(),
            "limit=0 returns nothing"
        );
    }

    // ----------------------------------------------------------------
    // Task 4 — ingest_remote_messages wired to transport
    // ----------------------------------------------------------------

    fn raw_msg(conv: Uuid, mid: Uuid, ts: i64, text: &str) -> crate::transport::RawDeliveryMessage {
        crate::transport::RawDeliveryMessage {
            message_id: mid.to_string(),
            conversation_id: conv.to_string(),
            sender_id: "remote-sender".into(),
            created_at_ms: ts,
            text_content: Some(text.into()),
            media_descriptors: vec![],
            reply_to: None,
        }
    }

    #[test]
    fn core_impl_ingest_remote_with_mock_transport() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let m3 = Uuid::now_v7();
        let staged = crate::transport::FetchResult {
            messages: vec![
                raw_msg(conv, m1, 1_700_000_000_000, "alpha hello"),
                raw_msg(conv, m2, 1_700_000_000_001, "beta hello"),
                raw_msg(conv, m3, 1_700_000_000_002, "gamma hello"),
            ],
            next_cursor: Some("after-3".into()),
        };
        let mock = crate::transport::MockDeliveryClient::new().with_response(None, Ok(staged));
        core.set_delivery_client(Box::new(mock));

        let r = core
            .ingest_remote_messages(conv, None)
            .expect("ingest_remote");
        assert_eq!(r.new_messages, 3);
        assert_eq!(r.duplicate_count, 0);

        let q = SearchQuery {
            query_string: "hello".to_string(),
            ..SearchQuery::default()
        };
        let hits = core.search(q, SearchScope::LocalOnly).expect("search");
        assert_eq!(hits.len(), 3, "all three messages must be searchable");
    }

    #[test]
    fn core_impl_ingest_remote_deduplicates() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let payload = vec![
            raw_msg(conv, m1, 1_700_000_000_000, "dup-a"),
            raw_msg(conv, m2, 1_700_000_000_001, "dup-b"),
        ];
        let mock = crate::transport::MockDeliveryClient::new()
            .with_response(
                None,
                Ok(crate::transport::FetchResult {
                    messages: payload.clone(),
                    next_cursor: None,
                }),
            )
            .with_response(
                Some("retry-1"),
                Ok(crate::transport::FetchResult {
                    messages: payload,
                    next_cursor: None,
                }),
            );
        core.set_delivery_client(Box::new(mock));

        let r1 = core.ingest_remote_messages(conv, None).unwrap();
        assert_eq!(r1.new_messages, 2);
        assert_eq!(r1.duplicate_count, 0);

        let cursor = DeliveryCursor("retry-1".to_string());
        let r2 = core
            .ingest_remote_messages(conv, Some(cursor))
            .expect("retry");
        assert_eq!(r2.new_messages, 0);
        assert_eq!(r2.duplicate_count, 2);
    }

    #[test]
    fn core_impl_ingest_remote_passes_cursor() {
        // The mock's `with_response(after_cursor, …)` records the
        // expected `after_cursor` for the next call and asserts it
        // matches the actual `after_cursor` argument inside
        // `MockDeliveryClient::fetch_messages`. So if
        // `CoreImpl::ingest_remote_messages` did *not* forward the
        // caller's cursor verbatim, the mock would panic and this
        // test would fail.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mock = crate::transport::MockDeliveryClient::new().with_response(
            Some("cursor-from-caller"),
            Ok(crate::transport::FetchResult::default()),
        );
        core.set_delivery_client(Box::new(mock));

        let cursor = DeliveryCursor("cursor-from-caller".to_string());
        let r = core
            .ingest_remote_messages(conv, Some(cursor))
            .expect("ingest_remote with cursor");
        assert_eq!(r.new_messages, 0);
        assert_eq!(r.duplicate_count, 0);
    }

    #[test]
    fn core_impl_ingest_remote_propagates_next_cursor() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let staged = crate::transport::FetchResult {
            messages: vec![raw_msg(
                conv,
                Uuid::now_v7(),
                1_700_000_000_000,
                "cursor-prop",
            )],
            next_cursor: Some("cursor-abc".into()),
        };
        let mock = crate::transport::MockDeliveryClient::new().with_response(None, Ok(staged));
        core.set_delivery_client(Box::new(mock));

        let r = core
            .ingest_remote_messages(conv, None)
            .expect("ingest_remote");
        assert_eq!(r.new_messages, 1);
        assert_eq!(r.next_cursor.as_deref(), Some("cursor-abc"));
    }

    #[test]
    fn core_impl_ingest_remote_none_cursor_when_drained() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mock = crate::transport::MockDeliveryClient::new().with_response(
            None,
            Ok(crate::transport::FetchResult {
                messages: vec![],
                next_cursor: None,
            }),
        );
        core.set_delivery_client(Box::new(mock));

        let r = core
            .ingest_remote_messages(conv, None)
            .expect("ingest_remote");
        assert_eq!(r.new_messages, 0);
        assert!(r.next_cursor.is_none());
    }

    #[test]
    fn core_impl_ingest_messages_inherent_leaves_next_cursor_none() {
        // The inherent `ingest_messages(&[…])` entry point has no
        // transport context, so `next_cursor` must remain `None`.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let r = core
            .ingest_messages(&[IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: Some("inherent".into()),
                media_descriptors: vec![],
                reply_to: None,
            }])
            .expect("ingest");
        assert_eq!(r.new_messages, 1);
        assert!(r.next_cursor.is_none());
    }

    // ----------------------------------------------------------------
    // Task 5 — list_conversations reflects latest activity
    // ----------------------------------------------------------------

    #[test]
    fn list_conversations_reflects_latest_message_activity() {
        let core = fresh_core();
        let c_old = Uuid::now_v7();
        let c_new = Uuid::now_v7();
        core.create_conversation(c_old, Some("old"), 1_000).unwrap();
        core.create_conversation(c_new, Some("new"), 2_000).unwrap();

        // Newest-first: c_new is on top to start with.
        let list = core.list_conversations().unwrap();
        assert_eq!(list[0].conversation_id, c_new.to_string());
        assert_eq!(list[1].conversation_id, c_old.to_string());

        // Sending into c_old should bump its last_activity_ms past
        // c_new and move it to the top.
        let mid = core.send_text(c_old, "moves to top", None).unwrap();

        let list = core.list_conversations().unwrap();
        assert_eq!(list[0].conversation_id, c_old.to_string());
        assert_eq!(list[1].conversation_id, c_new.to_string());
        assert_eq!(
            list[0].last_message_id.as_deref(),
            Some(mid.0.to_string()).as_deref()
        );
        assert!(list[0].last_activity_ms >= 1_000);
    }

    // ----------------------------------------------------------------
    // Task 3 — get_timeline (CoreImpl)
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_get_timeline_round_trip_after_send_text() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mid = core.send_text(conv, "first message", None).unwrap();

        let rows = core.get_timeline(conv, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id, mid.0.to_string());
        assert_eq!(rows[0].conversation_id, conv.to_string());
        assert_eq!(rows[0].text_content.as_deref(), Some("first message"));
    }

    #[test]
    fn core_impl_get_timeline_round_trip_after_ingest_messages() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let msgs = vec![
            IngestedMessage {
                message_id: m1,
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_000,
                text_content: Some("ingested one".into()),
                media_descriptors: vec![],
                reply_to: None,
            },
            IngestedMessage {
                message_id: m2,
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_500,
                text_content: Some("ingested two".into()),
                media_descriptors: vec![],
                reply_to: None,
            },
        ];
        core.ingest_messages(&msgs).expect("ingest");

        let rows = core.get_timeline(conv, None, 10).unwrap();
        assert_eq!(rows.len(), 2);
        // Newest-first.
        assert_eq!(rows[0].message_id, m2.to_string());
        assert_eq!(rows[1].message_id, m1.to_string());
    }

    #[test]
    fn core_impl_get_timeline_paginates_across_pages() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mut msgs = Vec::new();
        for i in 0..5 {
            msgs.push(IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: "user-1".into(),
                created_at_ms: 1_700_000_000_000 + i,
                text_content: Some(format!("page msg {i}")),
                media_descriptors: vec![],
                reply_to: None,
            });
        }
        core.ingest_messages(&msgs).expect("ingest");

        let page1 = core.get_timeline(conv, None, 2).unwrap();
        assert_eq!(page1.len(), 2);
        let cursor = page1.last().unwrap().created_at_ms;

        let page2 = core.get_timeline(conv, Some(cursor), 2).unwrap();
        assert_eq!(page2.len(), 2);
        assert!(page2.iter().all(|r| r.created_at_ms < cursor));

        let cursor2 = page2.last().unwrap().created_at_ms;
        let page3 = core.get_timeline(conv, Some(cursor2), 2).unwrap();
        assert_eq!(page3.len(), 1);

        let empty = core
            .get_timeline(conv, Some(page3[0].created_at_ms), 2)
            .unwrap();
        assert!(empty.is_empty());
    }

    // ----------------------------------------------------------------
    // Task 4 — get_message_with_body / get_message_body
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_get_message_returns_none_for_missing() {
        let core = fresh_core();
        assert!(core
            .get_message_with_body(Uuid::now_v7())
            .unwrap()
            .is_none());
    }

    #[test]
    fn core_impl_get_message_returns_skeleton_and_body_after_send_text() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "hi there", None).unwrap();

        let (skel, body) = core
            .get_message_with_body(mid.0)
            .unwrap()
            .expect("found message");
        assert_eq!(skel.message_id, mid.0.to_string());
        assert_eq!(skel.conversation_id, conv.to_string());
        let body = body.expect("body present");
        assert_eq!(body.text_content.as_deref(), Some("hi there"));
    }

    #[test]
    fn core_impl_get_message_returns_skeleton_only_after_delete_for_everyone() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "tombstone fodder", None).unwrap();

        core.delete_for_everyone(mid.0).expect("delete");

        let (skel, body) = core
            .get_message_with_body(mid.0)
            .unwrap()
            .expect("skel still present");
        assert_eq!(skel.message_id, mid.0.to_string());
        assert_eq!(
            skel.body_state,
            crate::local_store::state_machines::BodyState::DeletedForEveryone
        );
        assert!(body.is_none(), "body row dropped");
    }

    #[test]
    fn core_impl_get_message_body_returns_none_for_missing() {
        let core = fresh_core();
        assert!(core.get_message_body(Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn core_impl_get_message_body_returns_body_after_ingest() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let mid = Uuid::now_v7();
        let msgs = vec![IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("body via ingest".into()),
            media_descriptors: vec![],
            reply_to: None,
        }];
        core.ingest_messages(&msgs).expect("ingest");

        let body = core.get_message_body(mid).unwrap().expect("body present");
        assert_eq!(body.text_content.as_deref(), Some("body via ingest"));
    }

    // ----------------------------------------------------------------
    // Task 5 — delete_conversation
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_delete_conversation_removes_messages_and_search() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        let m_send = core.send_text(conv, "send-text alpha", None).expect("send");
        let m_ingest = Uuid::now_v7();
        core.ingest_messages(&[IngestedMessage {
            message_id: m_ingest,
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("ingested beta".into()),
            media_descriptors: vec![],
            reply_to: None,
        }])
        .expect("ingest");

        // Pre-delete sanity: search hits both rows.
        let pre = core
            .search(
                SearchQuery {
                    query_string: "alpha".into(),
                    ..SearchQuery::default()
                },
                SearchScope::LocalOnly,
            )
            .unwrap();
        assert_eq!(pre.len(), 1);

        core.delete_conversation(conv).expect("delete_conversation");

        // Conversation row gone.
        assert!(core.get_conversation(conv).unwrap().is_none());

        // Both messages gone.
        assert!(core.get_message_with_body(m_send.0).unwrap().is_none());
        assert!(core.get_message_with_body(m_ingest).unwrap().is_none());

        // No search hits for either token.
        for token in ["alpha", "beta"] {
            let hits = core
                .search(
                    SearchQuery {
                        query_string: token.into(),
                        ..SearchQuery::default()
                    },
                    SearchScope::LocalOnly,
                )
                .unwrap();
            assert!(
                hits.is_empty(),
                "expected no hits for `{token}` after delete_conversation"
            );
        }
    }

    #[test]
    fn core_impl_delete_conversation_errors_on_missing_id() {
        let core = fresh_core();
        let err = core.delete_conversation(Uuid::now_v7()).unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    #[test]
    fn core_impl_delete_conversation_removes_all_data() {
        // Mirrors `core_impl_delete_conversation_removes_messages_and_search`
        // but pins the cascade end-to-end on the raw `LocalStoreDb`
        // rows: conversation, skeleton, body, FTS, fuzzy.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // One outbox-minted message (send_text) + one ingested
        // message — exercises both write paths through the cascade.
        let m_send = core.send_text(conv, "delta epsilon", None).expect("send");
        let m_ingest = Uuid::now_v7();
        core.ingest_messages(&[IngestedMessage {
            message_id: m_ingest,
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: Some("zeta eta".into()),
            media_descriptors: vec![],
            reply_to: None,
        }])
        .expect("ingest");

        core.delete_conversation(conv).expect("delete_conversation");

        // Conversation row + every message row + every body row
        // gone. Test directly through the `LocalStoreDb` to defeat
        // any future `MessageView` reshape that hides rows but
        // leaves them persisted.
        core.with_db(|db| {
            assert!(db.get_conversation(&conv.to_string()).unwrap().is_none());
            assert!(db
                .get_message_skeleton(&m_send.0.to_string())
                .unwrap()
                .is_none());
            assert!(db
                .get_message_skeleton(&m_ingest.to_string())
                .unwrap()
                .is_none());
            assert!(db
                .get_message_body(&m_send.0.to_string())
                .unwrap()
                .is_none());
            assert!(db
                .get_message_body(&m_ingest.to_string())
                .unwrap()
                .is_none());
        });
    }

    #[test]
    fn core_impl_delete_conversation_search_cleanup() {
        // Verify FTS + fuzzy hits drop out of search after a
        // conversation is deleted. Distinct from
        // `core_impl_delete_conversation_removes_messages_and_search`
        // because it pre-asserts both FTS *and* fuzzy hits for
        // multiple tokens before deletion, then asserts they are
        // gone afterward.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        core.send_text(conv, "alphafox-unique", None)
            .expect("send a");
        core.send_text(conv, "betagolf-unique", None)
            .expect("send b");

        for token in ["alphafox", "betagolf"] {
            let hits = core
                .search(
                    SearchQuery {
                        query_string: token.into(),
                        ..SearchQuery::default()
                    },
                    SearchScope::LocalOnly,
                )
                .unwrap();
            assert_eq!(hits.len(), 1, "pre-delete: {token}");
        }

        core.delete_conversation(conv).expect("delete_conversation");

        for token in ["alphafox", "betagolf"] {
            let hits = core
                .search(
                    SearchQuery {
                        query_string: token.into(),
                        ..SearchQuery::default()
                    },
                    SearchScope::LocalOnly,
                )
                .unwrap();
            assert!(hits.is_empty(), "post-delete: {token}");
        }
    }

    // ----------------------------------------------------------------
    // Task 4 — register_device stub
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_register_device_returns_not_implemented() {
        let core = fresh_core();
        let err = core.register_device("device-abc").unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented("register_device")),
            "got {err:?}",
        );
    }

    // ----------------------------------------------------------------
    // Task 8 — HydrationQueue wiring
    // ----------------------------------------------------------------

    #[test]
    fn hydrate_message_maps_reason_to_priority() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "hi", None).expect("send");

        // Drive a sequence of reasons through `hydrate_message`
        // and assert each one lands at the expected priority. We
        // re-enqueue against the same message id, so the queue
        // dedupes / upgrades — that's the documented contract
        // (a "search_result_tap" must beat a stale "prefetch").
        for (reason, expected) in [
            ("idle_fill", HydrationReason::OpportunisticFill),
            ("prefetch", HydrationReason::AdjacentPrefetch),
            ("search_result_tap", HydrationReason::SearchResultTap),
        ] {
            let _ = core.hydrate_message(mid.0, reason).expect("hydrate");
            let drained = core.hydration_queue_drain();
            assert_eq!(drained.len(), 1, "reason={reason}");
            assert_eq!(drained[0].reason, expected, "reason={reason}");
        }

        // Unknown reasons collapse to OpportunisticFill (P5).
        core.hydrate_message(mid.0, "unmapped-reason").unwrap();
        let drained = core.hydration_queue_drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].reason, HydrationReason::OpportunisticFill);
    }

    #[test]
    fn prefetch_window_enqueues_messages() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Synthesize 10 message-ids — these don't need to exist in
        // the local store, the prefetch queue is purely an
        // intent-tracking surface.
        let visible: Vec<Uuid> = (0..10).map(|_| Uuid::now_v7()).collect();
        core.enqueue_prefetch_window(&visible, conv, 50)
            .expect("enqueue prefetch window");

        assert_eq!(core.hydration_queue_len(), 10);
        let drained = core.hydration_queue_drain();
        for r in &drained {
            assert_eq!(r.reason, HydrationReason::AdjacentPrefetch);
            assert_eq!(r.conversation_id, conv);
        }
    }

    // ------------------------------------------------------------------
    // Phase-3: timeline-skeleton rehydration on CoreImpl.
    // ------------------------------------------------------------------

    #[test]
    fn rehydrate_message_body_locally_refreshes_fuzzy_index() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core
            .send_text(conv, "salt sodium chloride", None)
            .expect("send_text");
        // Sanity: a fuzzy query for "sodium" hits before
        // rehydration.
        {
            let db = core.db.lock().unwrap();
            let engine = crate::search::fuzzy_search::FuzzySearchEngine::new(&db);
            assert!(
                !engine.search_fuzzy("sodium", 5).unwrap().is_empty(),
                "pre-rehydrate fuzzy search must find original body"
            );
        }

        core.rehydrate_message_body_locally(
            mid.0,
            "completely different content about dogs",
            BodyState::LocalPlainAvailable,
        )
        .expect("rehydrate");

        // Old fuzzy tokens are gone …
        let db = core.db.lock().unwrap();
        let engine = crate::search::fuzzy_search::FuzzySearchEngine::new(&db);
        assert!(
            engine.search_fuzzy("sodium", 5).unwrap().is_empty(),
            "post-rehydrate fuzzy index must drop stale tokens"
        );
        // … and new ones match.
        assert!(
            !engine.search_fuzzy("dogs", 5).unwrap().is_empty(),
            "post-rehydrate fuzzy index must contain new tokens"
        );
    }

    #[test]
    fn rehydrate_message_body_locally_round_trips_text() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core.send_text(conv, "before", None).unwrap();

        core.rehydrate_message_body_locally(mid.0, "after", BodyState::LocalPlainAvailable)
            .expect("rehydrate");

        let body = core.get_message_body(mid.0).unwrap().expect("body present");
        assert_eq!(body.text_content.as_deref(), Some("after"));
    }

    /// Regression test for the SAVEPOINT atomicity fix in
    /// [`CoreImpl::rehydrate_message_body_locally`]: the body
    /// upsert + `body_state` UPDATE + FTS refresh + fuzzy reindex
    /// all run inside a single outer
    /// `SAVEPOINT rehydrate_message_body_locally`. We verify the
    /// whole bundle is bracketable — opening an additional
    /// `SAVEPOINT outer` around the call and issuing
    /// `ROLLBACK TO outer` afterwards reverts every side effect:
    /// the body row, the search_fts row, and (most importantly)
    /// the search_fuzzy tokens. Before the fix, the fuzzy ops
    /// ran outside the inner savepoint and were therefore
    /// auto-committed independently; if the index step crashed
    /// after the remove step, the message would lose all fuzzy
    /// coverage with no rollback. This test asserts the fuzzy
    /// state participates in the surrounding transaction.
    #[test]
    fn rehydrate_message_body_locally_participates_in_outer_savepoint() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = core
            .send_text(conv, "salt sodium chloride", None)
            .expect("send_text");

        // Snapshot pre-call body / fuzzy state so we can compare
        // against post-rollback.
        let before_body = core
            .get_message_body(mid.0)
            .unwrap()
            .expect("body present pre-call")
            .text_content
            .clone()
            .expect("text_content present");
        let pre_sodium = {
            let db = core.db.lock().unwrap();
            let engine = crate::search::fuzzy_search::FuzzySearchEngine::new(&db);
            engine.search_fuzzy("sodium", 5).unwrap().len()
        };
        assert!(pre_sodium > 0, "pre-call fuzzy index must hit \"sodium\"");

        // Open outer savepoint, run rehydrate, then ROLLBACK.
        {
            let db = core.db.lock().unwrap();
            db.connection()
                .execute_batch("SAVEPOINT outer;")
                .expect("open outer savepoint");
        }

        core.rehydrate_message_body_locally(
            mid.0,
            "completely different content about dogs",
            BodyState::LocalPlainAvailable,
        )
        .expect("rehydrate");

        // Sanity: post-rehydrate, body and fuzzy reflect new text.
        {
            let mid_body = core
                .get_message_body(mid.0)
                .unwrap()
                .unwrap()
                .text_content
                .unwrap();
            assert_eq!(mid_body, "completely different content about dogs");
            let db = core.db.lock().unwrap();
            let engine = crate::search::fuzzy_search::FuzzySearchEngine::new(&db);
            assert!(
                engine.search_fuzzy("sodium", 5).unwrap().is_empty(),
                "old fuzzy tokens cleared post-rehydrate"
            );
            assert!(
                !engine.search_fuzzy("dogs", 5).unwrap().is_empty(),
                "new fuzzy tokens indexed post-rehydrate"
            );
        }

        // Roll back outer savepoint.
        {
            let db = core.db.lock().unwrap();
            db.connection()
                .execute_batch("ROLLBACK TO SAVEPOINT outer;\nRELEASE SAVEPOINT outer;")
                .expect("rollback outer savepoint");
        }

        // Body must be restored to its pre-call text.
        let after_body = core
            .get_message_body(mid.0)
            .unwrap()
            .expect("body present post-rollback")
            .text_content
            .expect("text_content present");
        assert_eq!(
            after_body, before_body,
            "body upsert must roll back with the outer SAVEPOINT"
        );

        // Fuzzy index must be restored: \"sodium\" hits again, \"dogs\"
        // does not. If the fuzzy ops had run outside the savepoint
        // (the pre-fix shape) the new \"dogs\" tokens would survive
        // the rollback and \"sodium\" would still be missing.
        let db = core.db.lock().unwrap();
        let engine = crate::search::fuzzy_search::FuzzySearchEngine::new(&db);
        assert!(
            !engine.search_fuzzy("sodium", 5).unwrap().is_empty(),
            "fuzzy index must roll back: \"sodium\" hits again post-rollback"
        );
        assert!(
            engine.search_fuzzy("dogs", 5).unwrap().is_empty(),
            "fuzzy index must roll back: \"dogs\" tokens evicted post-rollback"
        );
    }

    // ----------------------------------------------------------------
    // Epoch key manager wiring (Task 2 — `docs/PROPOSAL.md §2.1`)
    // ----------------------------------------------------------------

    fn fresh_archive_root() -> KeyMaterial {
        let mut bytes = [0u8; KEY_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        KeyMaterial::from_bytes(bytes)
    }

    #[test]
    fn install_epoch_key_manager_replaces_active_manager() {
        let core = fresh_core();
        let root = fresh_archive_root();
        assert!(!core.has_epoch_key_manager());
        core.install_epoch_key_manager(&root, "2026-05").unwrap();
        assert!(core.has_epoch_key_manager());
        assert_eq!(
            core.current_epoch_id().unwrap(),
            Some("2026-05".to_string())
        );

        // Re-install replaces the manager with a fresh one.
        core.install_epoch_key_manager(&root, "2026-06").unwrap();
        assert_eq!(
            core.current_epoch_id().unwrap(),
            Some("2026-06".to_string())
        );
    }

    #[test]
    fn epoch_lifecycle_methods_error_without_installed_manager() {
        let core = fresh_core();
        let root = fresh_archive_root();
        let err = core.rotate_archive_epoch(&root, "2026-05").unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
        let err = core.recover_epoch_key("2026-04", &root).unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
        let err = core.delete_archive_epoch_key("2026-04").unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
        let err = core.wrapped_prior_epoch_keys_for_manifest().unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
        let err = core.with_current_epoch_key(|_| ()).unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
        assert_eq!(core.current_epoch_id().unwrap(), None);
    }

    #[test]
    fn rotate_archive_epoch_returns_wrapped_prior_key_for_manifest() {
        let core = fresh_core();
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-05").unwrap();

        // Snapshot the active key so we can verify the rotation
        // produces a *different* one.
        let before = core.with_current_epoch_key(|k| *k).unwrap();

        let wrapped = core.rotate_archive_epoch(&root, "2026-06").unwrap();
        assert_eq!(wrapped.epoch_id, "2026-05");
        assert!(!wrapped.wrapped_key.is_empty());

        let after = core.with_current_epoch_key(|k| *k).unwrap();
        assert_ne!(before, after, "rotation must derive a fresh key");
        assert_eq!(
            core.current_epoch_id().unwrap(),
            Some("2026-06".to_string())
        );

        // Manifest harvest reports the wrapped prior key.
        let prior = core.wrapped_prior_epoch_keys_for_manifest().unwrap();
        assert_eq!(prior.len(), 1);
        assert_eq!(prior[0].epoch_id, "2026-05");
        assert_eq!(prior[0].wrapped_key, wrapped.wrapped_key);

        // Recovery round-trips the original epoch key bytes.
        let recovered = core.recover_epoch_key("2026-05", &root).unwrap();
        assert_eq!(recovered, before);
    }

    #[test]
    fn delete_archive_epoch_key_zeroizes_prior_entry() {
        let core = fresh_core();
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-05").unwrap();
        core.rotate_archive_epoch(&root, "2026-06").unwrap();
        assert_eq!(
            core.wrapped_prior_epoch_keys_for_manifest().unwrap().len(),
            1
        );
        assert!(core.delete_archive_epoch_key("2026-05").unwrap());
        assert!(core
            .wrapped_prior_epoch_keys_for_manifest()
            .unwrap()
            .is_empty());
        let err = core.recover_epoch_key("2026-05", &root).unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
    }

    // ----------------------------------------------------------------
    // Timeline skeleton rehydration (Task 4) test scaffolding
    // ----------------------------------------------------------------

    use std::collections::HashMap;
    use std::ops::Range;
    use std::sync::Mutex as StdMutex;

    #[derive(Debug, Default)]
    struct FixtureTransport {
        responses: StdMutex<HashMap<String, Vec<u8>>>,
        calls: StdMutex<Vec<String>>,
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

    impl crate::transport::TransportClient for FixtureTransport {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> crate::transport::TransportResult<crate::transport::FetchMessagesResponse> {
            Err(Error::NotImplemented("transport"))
        }

        fn init_blob_upload(
            &self,
            _size: u64,
            _blob_class: BlobClass,
            _expected_merkle_root: [u8; 32],
        ) -> crate::transport::TransportResult<crate::transport::BlobUploadHandle> {
            Err(Error::NotImplemented("transport"))
        }

        fn upload_chunk(
            &self,
            _blob_id: &str,
            _chunk_idx: u32,
            _ciphertext: &[u8],
            _sha256: [u8; 32],
        ) -> crate::transport::TransportResult<crate::transport::ChunkReceipt> {
            Err(Error::NotImplemented("transport"))
        }

        fn commit_blob(
            &self,
            _blob_id: &str,
        ) -> crate::transport::TransportResult<crate::transport::CommitBlobResponse> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_blob_range(
            &self,
            _blob_id: &str,
            _range: Range<u64>,
        ) -> crate::transport::TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_archive_manifests(
            &self,
            _after_generation: Option<u64>,
        ) -> crate::transport::TransportResult<Vec<crate::transport::EncryptedManifest>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_archive_segment(
            &self,
            segment_id: &str,
        ) -> crate::transport::TransportResult<Vec<u8>> {
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
        ) -> crate::transport::TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }
    }

    /// Build a sealed segment under `key_bytes` for the supplied
    /// events and seed `archive_segment_map` + the fixture
    /// transport. Returns the segment's UUID for assertions.
    fn seal_and_seed_segment(
        core: &CoreImpl,
        transport: &FixtureTransport,
        key_bytes: &[u8; 32],
        conv: Uuid,
        bucket: &str,
        events: Vec<crate::archive::event_journal::ArchiveEvent>,
    ) -> Uuid {
        use crate::archive::download::encode_archive_segment_blob;
        use crate::archive::segment_builder::{ArchiveSegmentBuilder, SegmentBuildRequest};

        let request = SegmentBuildRequest {
            conversation_id: conv,
            time_bucket: bucket.into(),
            events,
            segment_type: crate::formats::SegmentType::MessageDelta,
        };
        let built = ArchiveSegmentBuilder::new()
            .build_segment(request, key_bytes)
            .unwrap();

        let blob = encode_archive_segment_blob(
            &built.segment_id,
            &built.merkle_root,
            &built.nonce,
            &built.ciphertext,
        );
        transport.install(&built.segment_id.to_string(), blob);

        core.with_db(|db| {
            db.connection()
                .execute(
                    "INSERT INTO archive_segment_map(
                        segment_id, conversation_id, time_bucket,
                        segment_type, blob_id, storage_backend,
                        merkle_root, state
                     ) VALUES (?1, ?2, ?3, 'message_delta', ?4,
                              'kchat_backend', ?5, 'archive_uploaded')",
                    rusqlite::params![
                        built.segment_id.to_string(),
                        conv.to_string(),
                        bucket,
                        format!("blob-{}", built.segment_id),
                        built.merkle_root.as_slice(),
                    ],
                )
                .unwrap();
        });
        built.segment_id
    }

    fn make_event(
        conv: Uuid,
        message_id: Uuid,
        ms: i64,
    ) -> crate::archive::event_journal::ArchiveEvent {
        crate::archive::event_journal::ArchiveEvent {
            event_type: crate::archive::event_journal::ArchiveEventType::MessageReceived,
            conversation_id: conv,
            message_id: Some(message_id),
            payload: vec![0xDE, 0xAD],
            created_at_ms: ms,
        }
    }

    #[test]
    fn rehydrate_timeline_skeletons_lands_archive_only_rows() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let transport = FixtureTransport::default();
        seal_and_seed_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![make_event(conv, m1, 100), make_event(conv, m2, 200)],
        );

        let inserted = core
            .rehydrate_timeline_skeletons(&transport, conv, "2026-04", |_segment_id| {
                Ok(epoch_bytes)
            })
            .expect("rehydrate");
        assert_eq!(inserted.len(), 2, "two new skeletons");
        let landed_ids: Vec<&str> = inserted.iter().map(|s| s.message_id.as_str()).collect();
        assert!(landed_ids.contains(&m1.to_string().as_str()));
        assert!(landed_ids.contains(&m2.to_string().as_str()));

        core.with_db(|db| {
            let s1 = db.get_message_skeleton(&m1.to_string()).unwrap().unwrap();
            assert_eq!(s1.body_state, BodyState::RemoteArchiveOnly);
            assert_eq!(s1.archive_state, ArchiveState::ArchiveUploaded);
        });
        // Transport was hit exactly once for the segment.
        assert_eq!(transport.calls().len(), 1);
    }

    #[test]
    fn rehydrate_timeline_skeletons_skips_existing_local_rows() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let local_id = Uuid::now_v7();
        // Pre-seed a local row with a body that the archive view
        // must not stomp.
        core.with_db(|db| {
            let skel = MessageSkeleton {
                message_id: local_id.to_string(),
                conversation_id: conv.to_string(),
                sender_id: "user-1".into(),
                created_at_ms: 50,
                received_at_ms: 60,
                kind: MessageKind::Text,
                body_state: BodyState::LocalPlainAvailable,
                media_state: None,
                archive_state: ArchiveState::NotArchived,
                backup_state: BackupState::NotBackedUp,
                reply_to: None,
                edited_at_ms: None,
                deleted_at_ms: None,
            };
            db.insert_message_skeleton(&skel).unwrap();
        });

        let new_id = Uuid::now_v7();
        let transport = FixtureTransport::default();
        seal_and_seed_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![
                make_event(conv, local_id, 100),
                make_event(conv, new_id, 200),
            ],
        );

        let inserted = core
            .rehydrate_timeline_skeletons(&transport, conv, "2026-04", |_| Ok(epoch_bytes))
            .expect("rehydrate");
        assert_eq!(inserted.len(), 1, "only the brand-new id should land");
        assert_eq!(inserted[0].message_id, new_id.to_string());

        core.with_db(|db| {
            let local = db
                .get_message_skeleton(&local_id.to_string())
                .unwrap()
                .unwrap();
            assert_eq!(
                local.body_state,
                BodyState::LocalPlainAvailable,
                "local skeleton survives rehydration"
            );
        });
    }

    #[test]
    fn rehydrate_timeline_skeletons_no_segments_is_noop() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let transport = FixtureTransport::default();
        let inserted = core
            .rehydrate_timeline_skeletons(&transport, conv, "2026-04", |_| Ok(epoch_bytes))
            .expect("rehydrate");
        assert!(inserted.is_empty());
        assert!(transport.calls().is_empty());
    }

    #[test]
    fn rehydrate_timeline_skeletons_propagates_wrong_key_failure() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let transport = FixtureTransport::default();
        seal_and_seed_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![make_event(conv, Uuid::now_v7(), 100)],
        );
        let wrong_key = [0u8; 32];
        let err = core
            .rehydrate_timeline_skeletons(&transport, conv, "2026-04", |_| Ok(wrong_key))
            .unwrap_err();
        assert!(
            matches!(err, Error::Crypto(_) | Error::Storage(_)),
            "expected crypto/storage failure, got {err:?}"
        );
    }

    // ----------------------------------------------------------------
    // ZKOF archive backend installation (Phase-3 Task 2).
    // ----------------------------------------------------------------

    #[derive(Debug, Default)]
    struct InMemoryS3 {
        objects: std::sync::Mutex<std::collections::BTreeMap<(String, String), Vec<u8>>>,
    }

    impl crate::media::sinks::zk_fabric::S3Client for InMemoryS3 {
        fn put_object(
            &self,
            bucket: &str,
            key: &str,
            bytes: &[u8],
        ) -> std::result::Result<(), Error> {
            self.objects
                .lock()
                .unwrap()
                .insert((bucket.into(), key.into()), bytes.to_vec());
            Ok(())
        }
        fn get_object_range(
            &self,
            bucket: &str,
            key: &str,
            range: std::ops::Range<u64>,
        ) -> std::result::Result<Vec<u8>, Error> {
            let objects = self.objects.lock().unwrap();
            let bytes = objects
                .get(&(bucket.into(), key.into()))
                .ok_or_else(|| Error::Storage(format!("no such object: {bucket}/{key}")))?;
            let start = range.start.min(bytes.len() as u64) as usize;
            let end = range.end.min(bytes.len() as u64) as usize;
            Ok(bytes[start..end].to_vec())
        }
        fn delete_object(&self, _bucket: &str, _key: &str) -> std::result::Result<(), Error> {
            Ok(())
        }
        fn list_objects(
            &self,
            bucket: &str,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, Error> {
            let objects = self.objects.lock().unwrap();
            Ok(objects
                .keys()
                .filter(|(b, k)| b == bucket && k.starts_with(prefix))
                .map(|(_, k)| k.clone())
                .collect())
        }
    }

    fn fresh_zkof_config() -> crate::media::sinks::zk_fabric::ZkFabricSinkConfig {
        crate::media::sinks::zk_fabric::ZkFabricSinkConfig {
            endpoint_url: "https://zkof.example.com".into(),
            access_key: "AKIA-TEST".into(),
            secret_key: "secret".into(),
            bucket: "kchat-archive".into(),
        }
    }

    #[test]
    fn install_zkof_archive_backend_round_trip() {
        let core = fresh_core();
        assert!(!core.has_zkof_archive_backend());
        let s3: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client> =
            std::sync::Arc::new(InMemoryS3::default());
        core.install_zkof_archive_backend(s3, fresh_zkof_config())
            .expect("install");
        assert!(core.has_zkof_archive_backend());
    }

    #[test]
    fn install_zkof_archive_backend_rejects_invalid_config() {
        let core = fresh_core();
        let mut bad = fresh_zkof_config();
        bad.endpoint_url.clear();
        let s3: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client> =
            std::sync::Arc::new(InMemoryS3::default());
        let err = core.install_zkof_archive_backend(s3, bad).unwrap_err();
        assert!(matches!(err, Error::Storage(_)), "got {err:?}");
        assert!(!core.has_zkof_archive_backend());
    }

    #[test]
    fn build_archive_router_zkof_without_install_returns_error() {
        let cfg = test_config().with_archive_backend(crate::config::ArchiveBackend::Zkof);
        let core = CoreImpl::new_in_memory(cfg, TEST_KEY).unwrap();
        let transport = FixtureTransport::default();
        let err = core.build_archive_router(&transport).unwrap_err();
        assert!(
            matches!(err, Error::Storage(msg) if msg.contains("ZKOF backend installed")),
            "expected install-missing storage error"
        );
    }

    /// Phase 7 / Task 8 integration: when one bucket contains a
    /// `kchat_backend` row *and* a `zk_object_fabric` row,
    /// [`CoreImpl::rehydrate_timeline_skeletons`] (which delegates
    /// to the router variant via [`CoreImpl::build_archive_router`])
    /// must dispatch each row to its own backend and land both
    /// skeletons. Verifies the production wiring of
    /// [`crate::archive::prefetch::batch_prefetch_bucket_with_router`].
    #[test]
    fn rehydrate_timeline_skeletons_with_mixed_backend_segments_routes_per_row() {
        use crate::archive::download::encode_archive_segment_blob;
        use crate::archive::segment_builder::{ArchiveSegmentBuilder, SegmentBuildRequest};

        let cfg = test_config().with_archive_backend(crate::config::ArchiveBackend::Zkof);
        let core = CoreImpl::new_in_memory(cfg, TEST_KEY).unwrap();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        // Install a ZKOF backend so the router knows how to reach
        // S3 for `zk_object_fabric` rows.
        let s3 = std::sync::Arc::new(InMemoryS3::default());
        let s3_dyn: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client> = s3.clone();
        let zkof_cfg = fresh_zkof_config();
        let zkof_bucket = zkof_cfg.bucket.clone();
        core.install_zkof_archive_backend(s3_dyn, zkof_cfg).unwrap();

        let transport = FixtureTransport::default();
        let bucket = "2026-04";

        // Row 1 — KChat backend. Seal a one-event segment, push
        // the encoded blob into the fixture transport, and seed
        // the segment-map row with `storage_backend = kchat_backend`.
        let m_kchat = Uuid::now_v7();
        let kchat_seg_id = seal_and_seed_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            bucket,
            vec![make_event(conv, m_kchat, 100)],
        );

        // Row 2 — ZKOF backend. Seal a one-event segment, push
        // the encoded blob into the in-memory S3 at the
        // `archive/segments/{segment_id}` key the router uses,
        // and seed the segment-map row with `storage_backend =
        // zk_object_fabric`.
        let m_zkof = Uuid::now_v7();
        let zkof_built = ArchiveSegmentBuilder::new()
            .build_segment(
                SegmentBuildRequest {
                    conversation_id: conv,
                    time_bucket: bucket.into(),
                    events: vec![make_event(conv, m_zkof, 200)],
                    segment_type: crate::formats::SegmentType::MessageDelta,
                },
                &epoch_bytes,
            )
            .unwrap();
        let zkof_blob = encode_archive_segment_blob(
            &zkof_built.segment_id,
            &zkof_built.merkle_root,
            &zkof_built.nonce,
            &zkof_built.ciphertext,
        );
        s3.objects.lock().unwrap().insert(
            (
                zkof_bucket.clone(),
                format!("archive/segments/{}", zkof_built.segment_id),
            ),
            zkof_blob,
        );
        core.with_db(|db| {
            db.connection()
                .execute(
                    "INSERT INTO archive_segment_map(
                        segment_id, conversation_id, time_bucket,
                        segment_type, blob_id, storage_backend,
                        merkle_root, state
                     ) VALUES (?1, ?2, ?3, 'message_delta', ?4,
                              'zk_object_fabric', ?5, 'archive_uploaded')",
                    rusqlite::params![
                        zkof_built.segment_id.to_string(),
                        conv.to_string(),
                        bucket,
                        format!("blob-{}", zkof_built.segment_id),
                        zkof_built.merkle_root.as_slice(),
                    ],
                )
                .unwrap();
        });

        // Drive the router-aware production path through the
        // public `rehydrate_timeline_skeletons` entry point.
        let inserted = core
            .rehydrate_timeline_skeletons(&transport, conv, bucket, |_segment_id| Ok(epoch_bytes))
            .expect("mixed-backend rehydrate");
        assert_eq!(inserted.len(), 2, "both backends must land skeletons");
        let landed: std::collections::BTreeSet<String> =
            inserted.into_iter().map(|s| s.message_id).collect();
        assert!(landed.contains(&m_kchat.to_string()));
        assert!(landed.contains(&m_zkof.to_string()));

        // KChat transport saw exactly the kchat segment; never
        // touched the ZKOF segment.
        let kchat_calls = transport.calls();
        assert_eq!(kchat_calls.len(), 1, "kchat fetched once: {kchat_calls:?}");
        assert_eq!(kchat_calls[0], kchat_seg_id.to_string());
        // S3 client saw exactly the ZKOF segment object key.
        let s3_objects = s3.objects.lock().unwrap();
        assert!(
            s3_objects.contains_key(&(
                zkof_bucket,
                format!("archive/segments/{}", zkof_built.segment_id),
            )),
            "zkof object remained in S3"
        );
    }

    // ----------------------------------------------------------------
    // Lazy media rehydration on tap — Task 5
    // ----------------------------------------------------------------

    fn seed_media_asset(
        core: &CoreImpl,
        conv: &Uuid,
        message_id: &Uuid,
        media_state: MediaState,
    ) -> String {
        let asset_id = format!("asset-{}", message_id);
        core.with_db(|db| {
            let skel = MessageSkeleton {
                message_id: message_id.to_string(),
                conversation_id: conv.to_string(),
                sender_id: "u-sender".into(),
                created_at_ms: 100,
                received_at_ms: 110,
                kind: MessageKind::Media,
                body_state: BodyState::LocalPlainAvailable,
                media_state: Some(media_state),
                archive_state: ArchiveState::NotArchived,
                backup_state: BackupState::NotBackedUp,
                reply_to: None,
                edited_at_ms: None,
                deleted_at_ms: None,
            };
            db.insert_message_skeleton(&skel).unwrap();
            db.insert_message_body(&MessageBody {
                message_id: message_id.to_string(),
                text_content: Some("caption".into()),
                detected_language: None,
                rich_meta: None,
            })
            .unwrap();
            db.insert_media_asset(&MediaAsset {
                asset_id: asset_id.clone(),
                message_id: message_id.to_string(),
                mime_type: "image/png".into(),
                bytes_total: 1024,
                bytes_local: 0,
                media_state,
                wrapped_k_asset: vec![0u8; 40],
                chunk_count: 1,
                merkle_root: vec![0u8; 32],
                blob_id: format!("blob-{}", message_id),
                storage_sink: "kchat_backend".into(),
            })
            .unwrap();
        });
        asset_id
    }

    /// In-memory blob transport that blocks `fetch_blob_range` on a
    /// gate channel for the duration of the (test-controlled)
    /// download phase. Exists so the concurrency test for Task 2
    /// can pin a `rehydrate_media_for_message` call inside the
    /// download phase while a second thread runs an unrelated db op
    /// against the same `CoreImpl`. Once the gate is released the
    /// transport serves chunks from a pre-staged
    /// `(blob_id, chunk_idx) -> ciphertext` map using the same
    /// deterministic byte-range layout the download path computes.
    struct GatedTransport {
        chunks: StdMutex<HashMap<String, Vec<Vec<u8>>>>,
        gate: StdMutex<Option<std::sync::mpsc::Receiver<()>>>,
        entered: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl GatedTransport {
        fn new(
            rx: std::sync::mpsc::Receiver<()>,
            entered: std::sync::Arc<std::sync::atomic::AtomicBool>,
        ) -> Self {
            Self {
                chunks: StdMutex::new(HashMap::new()),
                gate: StdMutex::new(Some(rx)),
                entered,
            }
        }

        fn put_chunks(&self, blob_id: &str, sealed: &[crate::media::chunker::SealedChunk]) {
            let mut state = self.chunks.lock().unwrap();
            state.insert(
                blob_id.to_string(),
                sealed.iter().map(|c| c.ciphertext.clone()).collect(),
            );
        }
    }

    impl crate::transport::TransportClient for GatedTransport {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> crate::transport::TransportResult<crate::transport::FetchMessagesResponse> {
            Err(Error::NotImplemented("transport"))
        }

        fn init_blob_upload(
            &self,
            _size: u64,
            _blob_class: BlobClass,
            _expected_merkle_root: [u8; 32],
        ) -> crate::transport::TransportResult<crate::transport::BlobUploadHandle> {
            Err(Error::NotImplemented("transport"))
        }

        fn upload_chunk(
            &self,
            _blob_id: &str,
            _chunk_idx: u32,
            _ciphertext: &[u8],
            _sha256: [u8; 32],
        ) -> crate::transport::TransportResult<crate::transport::ChunkReceipt> {
            Err(Error::NotImplemented("transport"))
        }

        fn commit_blob(
            &self,
            _blob_id: &str,
        ) -> crate::transport::TransportResult<crate::transport::CommitBlobResponse> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_blob_range(
            &self,
            blob_id: &str,
            range: std::ops::Range<u64>,
        ) -> crate::transport::TransportResult<Vec<u8>> {
            // Signal that we have entered the download phase, then
            // park until the test releases the gate.
            self.entered
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(rx) = self.gate.lock().unwrap().take() {
                let _ = rx.recv_timeout(std::time::Duration::from_secs(10));
            }
            // Translate the byte range back to a chunk index using
            // the same formula the download path uses to compute it.
            let stride = crate::media::download::DEFAULT_CHUNK_CIPHERTEXT_SIZE as u64;
            if !range.start.is_multiple_of(stride) {
                return Err(Error::Storage(format!(
                    "GatedTransport: range start {} is not chunk-aligned",
                    range.start
                )));
            }
            let chunk_idx = (range.start / stride) as usize;
            let chunks = self.chunks.lock().unwrap();
            let entries = chunks
                .get(blob_id)
                .ok_or_else(|| Error::Storage(format!("GatedTransport: no blob {blob_id}")))?;
            let chunk = entries.get(chunk_idx).cloned().ok_or_else(|| {
                Error::Storage(format!(
                    "GatedTransport: chunk {chunk_idx} out of range for blob {blob_id}"
                ))
            })?;
            Ok(chunk)
        }

        fn fetch_archive_manifests(
            &self,
            _after_generation: Option<u64>,
        ) -> crate::transport::TransportResult<Vec<crate::transport::EncryptedManifest>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_archive_segment(
            &self,
            _segment_id: &str,
        ) -> crate::transport::TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }

        fn fetch_index_shards(
            &self,
            _conversation_hash: &str,
            _bucket: &str,
            _shard_type: &str,
        ) -> crate::transport::TransportResult<Vec<u8>> {
            Err(Error::NotImplemented("transport"))
        }
    }

    #[test]
    fn rehydrate_media_for_message_releases_db_lock_during_download() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let core = Arc::new(fresh_core());
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Build a real chunked + AEAD-sealed blob via `process_media`
        // so the download phase actually verifies an honest
        // ciphertext + Merkle root. The wrapping key under which
        // `K_asset` was wrapped is what the rehydration call passes
        // back in.
        let wrapping = [0x37u8; 32];
        let plaintext = vec![0x55u8; 256];
        let processed = crate::media::processor::process_media(
            &plaintext,
            "image/png",
            &wrapping,
            BlobClass::Media,
            false,
        )
        .expect("process_media");
        let descriptor = &processed.descriptor;

        // Seed the message_skeleton + media_asset rows with the real
        // descriptor so `prepare_rehydration` can read them under the
        // db lock.
        let mid = Uuid::now_v7();
        let asset_id = descriptor.asset_id.to_string();
        let blob_id = descriptor.blob_id.to_string();
        let merkle_root = descriptor.merkle_root.to_vec();
        let wrapped_k_asset = descriptor.wrapped_k_asset.clone();
        let chunk_count = descriptor.chunk_count as i32;
        core.with_db(|db| {
            let skel = MessageSkeleton {
                message_id: mid.to_string(),
                conversation_id: conv.to_string(),
                sender_id: "u-sender".into(),
                created_at_ms: 100,
                received_at_ms: 110,
                kind: MessageKind::Media,
                body_state: BodyState::LocalPlainAvailable,
                media_state: Some(MediaState::Evicted),
                archive_state: ArchiveState::NotArchived,
                backup_state: BackupState::NotBackedUp,
                reply_to: None,
                edited_at_ms: None,
                deleted_at_ms: None,
            };
            db.insert_message_skeleton(&skel).unwrap();
            db.insert_media_asset(&MediaAsset {
                asset_id: asset_id.clone(),
                message_id: mid.to_string(),
                mime_type: "image/png".into(),
                bytes_total: plaintext.len() as i64,
                bytes_local: 0,
                media_state: MediaState::Evicted,
                wrapped_k_asset: wrapped_k_asset.clone(),
                chunk_count,
                merkle_root: merkle_root.clone(),
                blob_id: blob_id.clone(),
                storage_sink: "kchat_backend".into(),
            })
            .unwrap();
        });

        // Stage chunks into the gated transport, which blocks
        // `fetch_blob_range` until the test releases the gate.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let entered = Arc::new(AtomicBool::new(false));
        let transport = Arc::new(GatedTransport::new(rx, entered.clone()));
        transport.put_chunks(&blob_id, &processed.sealed_chunks);

        // Thread A: rehydrate. It will park inside `fetch_blob_range`
        // until the gate channel is pulsed. While parked, the db
        // mutex MUST be released — otherwise thread B below would
        // deadlock.
        let core_a = core.clone();
        let transport_a = transport.clone();
        let handle_a = std::thread::spawn(move || {
            core_a
                .rehydrate_media_for_message(transport_a.as_ref(), mid, &wrapping)
                .expect("rehydrate")
        });

        // Wait until thread A is actually inside the download phase
        // before testing the lock from thread B.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !entered.load(Ordering::SeqCst) {
            if Instant::now() >= deadline {
                panic!("timed out waiting for fetch_blob_range to be entered");
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        // Thread B: a quick db op. This call would block forever on
        // the db mutex if `rehydrate_media_for_message` were still
        // holding it during the download phase.
        let core_b = core.clone();
        let lock_test_started = Instant::now();
        let handle_b = std::thread::spawn(move || {
            // Use a fresh conversation id to make absolutely sure
            // this is a write that touches the same db mutex.
            core_b
                .create_conversation(Uuid::now_v7(), Some("racy"), 0)
                .expect("create_conversation must not block on the rehydrate's lock")
        });
        handle_b
            .join()
            .expect("thread B must not panic and must not deadlock");
        let lock_test_elapsed = lock_test_started.elapsed();
        // 2s is generous: in practice this completes in a few ms when
        // the lock is correctly released. Anything close to the gate
        // timeout (10s) means we deadlocked on the db lock.
        assert!(
            lock_test_elapsed < Duration::from_secs(2),
            "concurrent db op took {lock_test_elapsed:?}; the rehydrate is holding the db lock during the download phase",
        );

        // Release thread A and confirm rehydration completed.
        let _ = tx.send(());
        let plaintext_recovered = handle_a.join().expect("thread A panicked");
        assert_eq!(plaintext_recovered.as_deref(), Some(plaintext.as_slice()));

        // After phase 3 commits, the asset must be `OriginalLocal`
        // and `bytes_local` must reflect the plaintext length.
        core.with_db(|db| {
            let asset = db.get_media_asset(&asset_id).unwrap().expect("asset");
            assert_eq!(asset.media_state, MediaState::OriginalLocal);
            assert_eq!(asset.bytes_local, plaintext.len() as i64);
        });
    }

    #[test]
    fn rehydrate_media_for_message_returns_none_when_no_asset() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        // Insert a text-only skeleton (no media row).
        core.with_db(|db| {
            let skel = MessageSkeleton {
                message_id: mid.to_string(),
                conversation_id: conv.to_string(),
                sender_id: "u".into(),
                created_at_ms: 1,
                received_at_ms: 2,
                kind: MessageKind::Text,
                body_state: BodyState::LocalPlainAvailable,
                media_state: None,
                archive_state: ArchiveState::NotArchived,
                backup_state: BackupState::NotBackedUp,
                reply_to: None,
                edited_at_ms: None,
                deleted_at_ms: None,
            };
            db.insert_message_skeleton(&skel).unwrap();
        });

        let transport = FixtureTransport::default();
        let wrapping = [0x77u8; 32];
        let got = core
            .rehydrate_media_for_message(&transport, mid, &wrapping)
            .expect("rehydrate");
        assert!(got.is_none());
    }

    #[test]
    fn hydrate_message_escalates_priority_for_evicted_media() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let _asset_id = seed_media_asset(&core, &conv, &mid, MediaState::Evicted);

        // Caller-supplied reason is "prefetch" (P3); the evicted
        // media flag must escalate the enqueued reason to
        // MediaFullScreen (P1).
        let _ = core
            .hydrate_message(mid, "prefetch")
            .expect("hydrate_message");

        let mut queue = core.hydration_queue.lock().unwrap();
        let mut found = false;
        while let Some(req) = queue.dequeue() {
            if req.message_id == mid && req.reason == HydrationReason::MediaFullScreen {
                found = true;
                break;
            }
        }
        assert!(found, "expected an escalated MediaFullScreen entry");
    }

    #[test]
    fn hydrate_message_keeps_priority_when_media_is_already_local() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let _asset_id = seed_media_asset(&core, &conv, &mid, MediaState::OriginalLocal);

        let _ = core
            .hydrate_message(mid, "prefetch")
            .expect("hydrate_message");

        let mut queue = core.hydration_queue.lock().unwrap();
        let mut found = false;
        while let Some(req) = queue.dequeue() {
            if req.message_id == mid {
                assert_eq!(
                    req.reason,
                    HydrationReason::AdjacentPrefetch,
                    "non-evicted media must keep the caller-supplied priority"
                );
                found = true;
                break;
            }
        }
        assert!(found, "expected an enqueued hydration request");
    }

    #[test]
    fn manifest_builder_carries_wrapped_prior_epoch_keys_after_rotation() {
        use crate::archive::manifest_builder::{build_archive_manifest, ManifestBuildRequest};
        use crate::crypto::signing::HybridSigningKey;
        use rand::rngs::OsRng;

        let core = fresh_core();
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-05").unwrap();
        let _ = core.rotate_archive_epoch(&root, "2026-06").unwrap();

        let mut rng = OsRng;
        let signing_key = HybridSigningKey::generate(&mut rng);
        let k_manifest = [0x77u8; 32];
        let prior = core.wrapped_prior_epoch_keys_for_manifest().unwrap();
        let req = ManifestBuildRequest {
            segments: &[],
            search_index_shards: vec![],
            media_references: vec![],
            tombstones: vec![],
            wrapped_prior_epoch_keys: prior.clone(),
            previous: None,
        };
        let sealed =
            build_archive_manifest(req, &signing_key, &k_manifest).expect("build manifest");
        assert_eq!(sealed.manifest.wrapped_prior_epoch_keys, prior);
        assert!(!sealed.manifest.wrapped_prior_epoch_keys.is_empty());
    }

    // -----------------------------------------------------------------
    // Task 3: run_incremental_backup wiring (`docs/PROPOSAL.md §6.2`).
    // -----------------------------------------------------------------

    fn install_test_backup_keys(core: &CoreImpl) {
        use crate::crypto::signing::HybridSigningKey;
        use rand::rngs::OsRng;
        let backup_root = [0x33u8; 32];
        let mut rng = OsRng;
        let signing = HybridSigningKey::generate(&mut rng);
        core.install_backup_keys(backup_root, signing, "test-device".to_string())
            .expect("install backup keys");
    }

    fn seed_backup_event(core: &CoreImpl, conv: Uuid, msg: Uuid, ts_ms: i64) {
        use crate::backup::event_journal::{BackupEvent, BackupEventJournal, BackupEventType};
        core.with_db(|db| {
            BackupEventJournal::new()
                .write_event(
                    db.connection(),
                    &BackupEvent {
                        event_type: BackupEventType::MessageReceived,
                        conversation_id: Some(conv),
                        message_id: Some(msg),
                        payload: vec![0xAA, 0xBB, 0xCC],
                        created_at_ms: ts_ms,
                    },
                )
                .expect("write backup event");
        });
    }

    #[test]
    fn run_incremental_backup_with_pending_events_produces_segment() {
        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_000_000);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_001_000);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_002_000);

        let result = core
            .run_incremental_backup("scheduled")
            .expect("incremental backup");
        assert_eq!(result.segments_built, 1);
        assert_eq!(result.events_segmented, 3);
        assert_eq!(result.manifest_generation, Some(0));
        assert_eq!(result.segments_uploaded, 0);
        assert!(!result.manifest_uploaded);
    }

    #[test]
    fn run_incremental_backup_with_no_events_is_noop() {
        let core = fresh_core();
        install_test_backup_keys(&core);
        let result = core.run_incremental_backup("scheduled").expect("noop");
        assert_eq!(result, BackupResult::default());
    }

    #[test]
    fn run_incremental_backup_advances_cursor() {
        use crate::backup::event_journal::BackupEventJournal;
        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_000_000);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_001_000);

        // Sanity: cursor is 0 before the run.
        let before = core.with_db(|db| {
            BackupEventJournal::new()
                .read_cursor(db.connection())
                .unwrap()
        });
        assert_eq!(before, 0);

        core.run_incremental_backup("scheduled")
            .expect("incremental backup");

        let after = core.with_db(|db| {
            BackupEventJournal::new()
                .read_cursor(db.connection())
                .unwrap()
        });
        assert!(after >= 2, "cursor should advance past the seeded events");

        // Subsequent read must surface no events.
        let unsegmented = core.with_db(|db| {
            BackupEventJournal::new()
                .read_unsegmented(db.connection(), 100)
                .unwrap()
        });
        assert!(unsegmented.is_empty());
    }

    #[test]
    fn run_incremental_backup_idempotent_on_retry() {
        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_000_000);

        let first = core.run_incremental_backup("scheduled").expect("first run");
        assert_eq!(first.segments_built, 1);
        assert_eq!(first.events_segmented, 1);
        assert_eq!(first.manifest_generation, Some(0));

        // No new events → second run must be a noop.
        let second = core
            .run_incremental_backup("scheduled")
            .expect("second run");
        assert_eq!(second, BackupResult::default());

        // Seed one more event and confirm the chain advances.
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_001_000);
        let third = core.run_incremental_backup("scheduled").expect("third run");
        assert_eq!(third.segments_built, 1);
        assert_eq!(third.events_segmented, 1);
        // Manifest chain advanced from genesis to generation 1.
        assert_eq!(third.manifest_generation, Some(1));
    }

    #[test]
    fn run_incremental_backup_without_keys_returns_error_with_pending_events() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_000_000);

        let err = core
            .run_incremental_backup("scheduled")
            .expect_err("must fail without keys");
        match err {
            Error::Storage(msg) => {
                assert!(msg.contains("K_backup_root not installed"), "{msg}")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Task 5: compact_backup orchestration (`docs/PROPOSAL.md §6.6`).
    // -----------------------------------------------------------------

    fn seed_backup_event_with_seq(core: &CoreImpl, conv: Uuid, msg: Uuid, ts_ms: i64) -> i64 {
        use crate::backup::event_journal::{BackupEvent, BackupEventJournal, BackupEventType};
        core.with_db(|db| {
            BackupEventJournal::new()
                .write_event(
                    db.connection(),
                    &BackupEvent {
                        event_type: BackupEventType::MessageReceived,
                        conversation_id: Some(conv),
                        message_id: Some(msg),
                        payload: vec![0xAA, 0xBB, 0xCC],
                        created_at_ms: ts_ms,
                    },
                )
                .expect("write")
        })
    }

    fn seed_message_deleted(core: &CoreImpl, conv: Uuid, msg: Uuid, ts_ms: i64) -> i64 {
        use crate::backup::event_journal::{BackupEvent, BackupEventJournal, BackupEventType};
        core.with_db(|db| {
            BackupEventJournal::new()
                .write_event(
                    db.connection(),
                    &BackupEvent {
                        event_type: BackupEventType::MessageDeleted,
                        conversation_id: Some(conv),
                        message_id: Some(msg),
                        payload: vec![],
                        created_at_ms: ts_ms,
                    },
                )
                .expect("write")
        })
    }

    /// Helper: build N daily segments by running
    /// `run_incremental_backup` between event-bursts, dating the
    /// events `days_old` days before `now_ms`.
    fn build_aged_segments(core: &CoreImpl, conv: Uuid, days_old: i64, count: usize, now_ms: i64) {
        const DAY_MS: i64 = 86_400_000;
        for i in 0..count {
            let ts = now_ms - (days_old * DAY_MS) + (i as i64) * 1_000;
            seed_backup_event_with_seq(core, conv, Uuid::now_v7(), ts);
            core.run_incremental_backup("test").expect("backup");
        }
    }

    #[test]
    fn compact_backup_merges_aged_daily_segments_into_weekly() {
        const DAY_MS: i64 = 86_400_000;
        let now_ms = 1_900_000_000_000_i64;
        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Three daily segments, each 10 days old (eligible).
        build_aged_segments(&core, conv, 10, 3, now_ms);

        // Sanity: ledger has three Daily segments before the
        // compaction.
        let pre_len = core.tracked_backup_segments.lock().unwrap().len();
        assert_eq!(pre_len, 3);

        let result = core.compact_backup(now_ms).expect("compact");
        assert_eq!(result.groups_compacted, 1);
        assert_eq!(result.segments_superseded, 3);
        assert_eq!(result.segments_emitted, 1);
        // Manifest was cut over the rewritten ledger.
        assert!(result.manifest_generation.is_some());
        // bytes_after should be smaller than bytes_before (one
        // segment vs three) — modulo overheads, it's at least
        // bounded.
        assert!(result.bytes_after > 0);
        assert!(result.bytes_before > 0);

        // Ledger now has exactly one Weekly entry.
        let post = core.tracked_backup_segments.lock().unwrap().clone();
        assert_eq!(post.len(), 1);
        assert_eq!(
            post[0].tier,
            crate::backup::compaction::CompactionTier::Weekly
        );

        // Re-seal must be decryptable under the orchestrator's
        // ledger-stored segment key.
        let payload = crate::backup::segment_builder::decrypt_backup_segment(
            &post[0].built,
            &post[0].k_segment,
        )
        .unwrap();
        assert_eq!(payload.events.len(), 3);
        // Sanity: timestamps of original events are preserved.
        for ev in &payload.events {
            assert!(ev.created_at_ms <= now_ms - 7 * DAY_MS);
        }
    }

    #[test]
    fn compact_backup_noop_when_no_eligible_segments() {
        let now_ms = 1_900_000_000_000_i64;
        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Three daily segments only 1 day old — way under the
        // `daily_to_weekly_ms` threshold.
        build_aged_segments(&core, conv, 1, 3, now_ms);

        let result = core.compact_backup(now_ms).expect("compact");
        assert_eq!(result, BackupCompactionResult::default());
        // Ledger preserved.
        assert_eq!(core.tracked_backup_segments.lock().unwrap().len(), 3);
    }

    #[test]
    fn compact_backup_applies_tombstones() {
        const DAY_MS: i64 = 86_400_000;
        let now_ms = 1_900_000_000_000_i64;
        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Segment A: messages M1, M2 (10 days old).
        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        seed_backup_event_with_seq(&core, conv, m1, now_ms - 10 * DAY_MS);
        seed_backup_event_with_seq(&core, conv, m2, now_ms - 10 * DAY_MS + 1_000);
        core.run_incremental_backup("test").expect("backup A");

        // Segment B: tombstone deleting M1, plus a fresh message M3.
        let m3 = Uuid::now_v7();
        seed_message_deleted(&core, conv, m1, now_ms - 10 * DAY_MS + 2_000);
        seed_backup_event_with_seq(&core, conv, m3, now_ms - 10 * DAY_MS + 3_000);
        core.run_incremental_backup("test").expect("backup B");

        // Segment C: another message to push the group over
        // `min_group_size`.
        let m4 = Uuid::now_v7();
        seed_backup_event_with_seq(&core, conv, m4, now_ms - 10 * DAY_MS + 4_000);
        core.run_incremental_backup("test").expect("backup C");

        let result = core.compact_backup(now_ms).expect("compact");
        assert_eq!(result.groups_compacted, 1);
        assert_eq!(result.segments_superseded, 3);

        let post = core.tracked_backup_segments.lock().unwrap().clone();
        assert_eq!(post.len(), 1);
        let payload = crate::backup::segment_builder::decrypt_backup_segment(
            &post[0].built,
            &post[0].k_segment,
        )
        .unwrap();
        // The compacted segment should contain only M2, M3, M4
        // — M1 and its tombstone are dropped.
        let surviving_messages: Vec<_> =
            payload.events.iter().filter_map(|e| e.message_id).collect();
        assert!(!surviving_messages.contains(&m1));
        assert!(surviving_messages.contains(&m2));
        assert!(surviving_messages.contains(&m3));
        assert!(surviving_messages.contains(&m4));
    }

    #[test]
    fn compact_backup_with_empty_ledger_is_noop() {
        let core = fresh_core();
        install_test_backup_keys(&core);
        let result = core.compact_backup(1_900_000_000_000).expect("noop");
        assert_eq!(result, BackupCompactionResult::default());
    }

    #[test]
    fn backup_manifest_chain_and_segment_ledger_survive_restart() {
        // Phase-5 hardening (Task 2): the manifest chain tail and
        // the tracked-segment ledger must round-trip through a
        // process restart so the next call to
        // `run_incremental_backup` chains under the previous
        // manifest (no genesis fork) and `compact_backup` sees
        // the same tracked segments.
        let backup_root = [0x33u8; 32];
        let device_id = "test-device".to_string();

        // ---- Phase 1: first "process" runs an incremental backup.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = KChatCoreConfig::new(tmp.path().to_path_buf(), Platform::MacOs, "tenant-test");
        let pre_generation = {
            let core = CoreImpl::new(cfg.clone(), TEST_KEY).expect("core");
            // Same backup root on both sides so the ledger
            // re-hydrates under the same wrapping key.
            let mut rng = rand::rngs::OsRng;
            let signing = crate::crypto::signing::HybridSigningKey::generate(&mut rng);
            core.install_backup_keys(backup_root, signing, device_id.clone())
                .expect("install backup keys");

            let conv = Uuid::now_v7();
            seed_conversation(&core, &conv);
            seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_000_000);
            seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_001_000);

            let result = core
                .run_incremental_backup("scheduled")
                .expect("incremental backup");
            assert_eq!(result.segments_built, 1);
            let pre_generation = result.manifest_generation.expect("generation");
            assert_eq!(pre_generation, 0, "first manifest is genesis");

            // Sanity: in-memory state reflects the just-built backup.
            let in_memory_tracked = core
                .tracked_backup_segments
                .lock()
                .unwrap()
                .iter()
                .map(|s| s.built.segment_id)
                .collect::<Vec<_>>();
            assert_eq!(in_memory_tracked.len(), 1);
            let in_memory_manifest = core
                .previous_backup_manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.generation);
            assert_eq!(in_memory_manifest, Some(0));

            // Sanity: state actually hit the DB before we drop.
            let row_count: i64 = core.with_db(|db| {
                db.connection()
                    .query_row("SELECT COUNT(*) FROM backup_segment_ledger", [], |r| {
                        r.get(0)
                    })
                    .unwrap()
            });
            assert_eq!(row_count, 1);
            let manifest_row_count: i64 = core.with_db(|db| {
                db.connection()
                    .query_row("SELECT COUNT(*) FROM backup_manifest_chain", [], |r| {
                        r.get(0)
                    })
                    .unwrap()
            });
            assert_eq!(manifest_row_count, 1);
            pre_generation
        };

        // ---- Phase 2: simulate a process restart by opening a fresh
        // CoreImpl against the same on-disk DB. The manifest tail
        // must rehydrate from `backup_manifest_chain`; the segment
        // ledger must rehydrate from `backup_segment_ledger` once
        // the backup keys are re-installed (the ledger rows are
        // sealed under `K_backup_root`).
        let core2 = CoreImpl::new(cfg, TEST_KEY).expect("reopen core");
        // Manifest chain rehydrates eagerly in `new`.
        let manifest_after_restart = core2
            .previous_backup_manifest
            .lock()
            .unwrap()
            .as_ref()
            .map(|m| m.generation);
        assert_eq!(manifest_after_restart, Some(pre_generation));
        // Segment ledger only rehydrates once the wrapping root is
        // re-installed.
        assert!(core2.tracked_backup_segments.lock().unwrap().is_empty());

        let mut rng = rand::rngs::OsRng;
        let signing = crate::crypto::signing::HybridSigningKey::generate(&mut rng);
        core2
            .install_backup_keys(backup_root, signing, device_id.clone())
            .expect("install backup keys (post-restart)");
        let rehydrated = core2
            .tracked_backup_segments
            .lock()
            .unwrap()
            .iter()
            .map(|s| (s.built.segment_id, s.tier, s.built.event_count))
            .collect::<Vec<_>>();
        assert_eq!(rehydrated.len(), 1);
        assert_eq!(
            rehydrated[0].1,
            crate::backup::compaction::CompactionTier::Daily
        );
        assert_eq!(rehydrated[0].2, 2);

        // ---- Phase 3: a second incremental run on the restored
        // core must chain under generation N (not start a new
        // genesis chain at 0).
        let conv = Uuid::now_v7();
        seed_conversation(&core2, &conv);
        seed_backup_event(&core2, conv, Uuid::now_v7(), 1_777_000_010_000);
        let result = core2
            .run_incremental_backup("scheduled")
            .expect("incremental backup after restart");
        assert_eq!(
            result.manifest_generation,
            Some(pre_generation + 1),
            "chain must continue across process restart"
        );
    }

    /// Force any subsequent `backup_segment_ledger` write to fail
    /// by dropping the table. Used by the persist-failure tests
    /// below; after this the only safe operations on the DB are
    /// reads from other tables — anything that touches the ledger
    /// will error.
    fn drop_backup_segment_ledger_table(core: &CoreImpl) {
        core.with_db(|db| {
            db.connection()
                .execute("DROP TABLE backup_segment_ledger", [])
                .expect("drop backup_segment_ledger");
        });
    }

    #[test]
    fn run_incremental_backup_persist_failure_leaves_in_memory_state_unchanged() {
        // Phase-5 hardening: if the persist step in
        // `run_incremental_backup_inner` fails, the in-memory
        // manifest and segment ledger must remain at the
        // pre-call values **and** the persisted
        // `backup_event_cursor` must stay at its pre-call value.
        // Otherwise the next call within the same process would
        // chain under an unpersisted manifest, a restart would
        // fork the chain, and any events past the pre-failure
        // cursor would be permanently skipped on the next run
        // (because `read_unsegmented` only returns events strictly
        // greater than `last_seq`).
        use crate::backup::event_journal::BackupEventJournal;

        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_000_000);
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_001_000);

        // Pre-call in-memory state.
        assert!(core.previous_backup_manifest.lock().unwrap().is_none());
        assert!(core.tracked_backup_segments.lock().unwrap().is_empty());

        // Snapshot the pre-call cursor — should be 0 since no
        // backup has ever advanced it.
        let pre_cursor = core.with_db(|db| {
            BackupEventJournal::new()
                .read_cursor(db.connection())
                .expect("pre-call cursor read")
        });
        assert_eq!(pre_cursor, 0);

        // Force the persist to fail.
        drop_backup_segment_ledger_table(&core);

        let result = core.run_incremental_backup("scheduled");
        assert!(
            result.is_err(),
            "persist must fail when backup_segment_ledger is missing"
        );

        // In-memory state must be unchanged.
        assert!(
            core.previous_backup_manifest.lock().unwrap().is_none(),
            "previous_backup_manifest must not advance on persist failure"
        );
        assert!(
            core.tracked_backup_segments.lock().unwrap().is_empty(),
            "tracked_backup_segments must not gain entries on persist failure"
        );

        // The cursor MUST remain at the pre-call value. If it had
        // been advanced under autocommit before the atomic
        // persist (as in the previous implementation), the events
        // the failed call attempted to segment would be silently
        // dropped on the next call.
        let post_cursor = core.with_db(|db| {
            BackupEventJournal::new()
                .read_cursor(db.connection())
                .expect("post-call cursor read")
        });
        assert_eq!(
            post_cursor, pre_cursor,
            "backup_event_cursor must not advance on persist failure"
        );
    }

    #[test]
    fn compact_backup_persist_failure_leaves_in_memory_state_unchanged() {
        // Phase-5 hardening: if the persist step in
        // `compact_backup` fails, the in-memory manifest and
        // segment ledger must remain at the pre-compaction
        // values. Otherwise subsequent operations in the same
        // process operate on a ledger the DB never wrote, and a
        // restart would reload stale pre-compaction state.
        let now_ms = 1_900_000_000_000_i64;
        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Build three aged daily segments (10 days old) so the
        // compaction planner has work to do.
        build_aged_segments(&core, conv, 10, 3, now_ms);

        // Snapshot the pre-compaction in-memory state.
        let pre_ledger_ids: Vec<uuid::Uuid> = core
            .tracked_backup_segments
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.built.segment_id)
            .collect();
        assert_eq!(pre_ledger_ids.len(), 3);
        let pre_manifest_generation = core
            .previous_backup_manifest
            .lock()
            .unwrap()
            .as_ref()
            .map(|m| m.generation);
        assert!(pre_manifest_generation.is_some());

        // Force the persist to fail.
        drop_backup_segment_ledger_table(&core);

        let result = core.compact_backup(now_ms);
        assert!(
            result.is_err(),
            "persist must fail when backup_segment_ledger is missing"
        );

        // In-memory ledger must still hold the pre-compaction
        // entries — superseded segments must NOT have been
        // removed and compacted entries must NOT have been
        // appended.
        let post_ledger_ids: Vec<uuid::Uuid> = core
            .tracked_backup_segments
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.built.segment_id)
            .collect();
        assert_eq!(
            post_ledger_ids, pre_ledger_ids,
            "in-memory ledger must not change on compaction persist failure"
        );

        // Manifest tail must still be at the pre-compaction
        // generation.
        let post_manifest_generation = core
            .previous_backup_manifest
            .lock()
            .unwrap()
            .as_ref()
            .map(|m| m.generation);
        assert_eq!(
            post_manifest_generation, pre_manifest_generation,
            "manifest tail must not advance on compaction persist failure"
        );
    }

    #[test]
    fn install_backup_keys_hydration_failure_leaves_no_keys_installed() {
        // Phase-5 hardening: if
        // `hydrate_tracked_backup_segments_from_db` fails (e.g.
        // because a `wrapped_k_segment` row has been corrupted on
        // disk and the AES-KW integrity check rejects the
        // unwrap), `install_backup_keys` must return `Err` *and*
        // leave the three key `Mutex` slots empty. Otherwise
        // `has_backup_keys()` would return `true` after the
        // failure and the next backup would proceed against an
        // empty in-memory ledger — the first compaction would
        // then silently drop every pre-existing segment because
        // it would see "no superseded segments" in the snapshot.
        let backup_root = [0x33u8; 32];
        let device_id = "test-device".to_string();

        // ---- Phase 1: seed a real ledger row on disk so a
        // subsequent `install_backup_keys` on a fresh core has
        // something to hydrate.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = KChatCoreConfig::new(tmp.path().to_path_buf(), Platform::MacOs, "tenant-test");
        {
            let core = CoreImpl::new(cfg.clone(), TEST_KEY).expect("core");
            let mut rng = rand::rngs::OsRng;
            let signing = crate::crypto::signing::HybridSigningKey::generate(&mut rng);
            core.install_backup_keys(backup_root, signing, device_id.clone())
                .expect("install backup keys (seed)");
            let conv = Uuid::now_v7();
            seed_conversation(&core, &conv);
            seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_000_000);
            seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_001_000);
            core.run_incremental_backup("scheduled")
                .expect("seed incremental backup");
        }

        // ---- Phase 2: simulate a process restart, then corrupt
        // the wrapped_k_segment BLOB before installing the keys.
        // AES-KW carries an 8-byte integrity prefix, so any
        // corruption of the wrapped bytes makes the unwrap
        // fail.
        let core2 = CoreImpl::new(cfg, TEST_KEY).expect("reopen core");

        // Sanity: the manifest tail rehydrated from
        // `backup_manifest_chain` (manifest hydration runs in
        // `new` and is independent of the wrap key).
        assert!(
            core2.previous_backup_manifest.lock().unwrap().is_some(),
            "manifest tail should rehydrate eagerly"
        );

        // Corrupt every row in the segment ledger.
        core2.with_db(|db| {
            db.connection()
                .execute(
                    "UPDATE backup_segment_ledger SET wrapped_k_segment = ?",
                    rusqlite::params![vec![0xFFu8; 40]],
                )
                .expect("corrupt wrapped_k_segment");
        });

        // ---- Phase 3: installing the keys must fail because
        // hydration can no longer unwrap the segment key. The
        // three key `Mutex` slots must remain unset so
        // `has_backup_keys()` returns `false`.
        let mut rng = rand::rngs::OsRng;
        let signing = crate::crypto::signing::HybridSigningKey::generate(&mut rng);
        let result = core2.install_backup_keys(backup_root, signing, device_id);
        assert!(
            result.is_err(),
            "install_backup_keys must fail when a ledger row's wrapped_k_segment is corrupt"
        );
        assert!(
            !core2.has_backup_keys(),
            "has_backup_keys() must return false after a hydration failure — \
             otherwise the next backup would proceed with no in-memory ledger"
        );
        // Ledger must still be empty (hydration writes the
        // result in one shot at the end, so a per-row failure
        // leaves the in-memory Vec untouched).
        assert!(
            core2.tracked_backup_segments.lock().unwrap().is_empty(),
            "tracked_backup_segments must remain empty when hydration fails"
        );
    }

    // ---------------------------------------------------------------
    // Archive compaction tests (Task 9 — `docs/PHASES.md §Phase 7`)
    // ---------------------------------------------------------------

    /// Same as [`seal_and_seed_segment`] but seeds the row with
    /// `archive_state = 'archive_verified'` so it is eligible for
    /// archive compaction. Returns the segment_id.
    fn seal_and_seed_verified_segment(
        core: &CoreImpl,
        transport: &FixtureTransport,
        key_bytes: &[u8; 32],
        conv: Uuid,
        bucket: &str,
        events: Vec<crate::archive::event_journal::ArchiveEvent>,
    ) -> Uuid {
        let segment_id = seal_and_seed_segment(core, transport, key_bytes, conv, bucket, events);
        core.with_db(|db| {
            db.connection()
                .execute(
                    "UPDATE archive_segment_map SET state = 'archive_verified'
                      WHERE segment_id = ?1",
                    rusqlite::params![segment_id.to_string()],
                )
                .unwrap();
        });
        segment_id
    }

    #[test]
    fn compact_archive_merges_segments_for_same_bucket() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let m3 = Uuid::now_v7();
        let transport = FixtureTransport::default();
        let s1 = seal_and_seed_verified_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![make_event(conv, m1, 100), make_event(conv, m2, 200)],
        );
        let s2 = seal_and_seed_verified_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![make_event(conv, m3, 300)],
        );

        let router = crate::archive::download::ArchiveSegmentRouter::kchat_only(&transport);
        let mut compacts: Vec<crate::archive::segment_builder::BuiltSegment> = Vec::new();
        let result = core
            .compact_archive(
                &router,
                conv,
                "2026-04",
                &epoch_bytes,
                |_sid| Ok(epoch_bytes),
                |built| {
                    compacts.push(built.clone());
                    Ok(())
                },
            )
            .expect("compact");
        assert_eq!(result.buckets_compacted, 1);
        assert_eq!(result.segments_superseded, 2);
        assert_eq!(result.segments_emitted, 1);
        assert!(result.bytes_before > 0);
        assert!(result.bytes_after > 0);
        assert_eq!(compacts.len(), 1);

        // Decoding the new compact segment must list all three
        // messages.
        let plaintext = crate::archive::download::decrypt_archive_segment(
            &crate::archive::download::encode_archive_segment_blob(
                &compacts[0].segment_id,
                &compacts[0].merkle_root,
                &compacts[0].nonce,
                &compacts[0].ciphertext,
            ),
            &epoch_bytes,
        )
        .unwrap();
        let payload = crate::archive::download::decode_archive_segment_payload(&plaintext).unwrap();
        let mids: Vec<_> = payload.events.iter().filter_map(|e| e.message_id).collect();
        assert!(mids.contains(&m1));
        assert!(mids.contains(&m2));
        assert!(mids.contains(&m3));

        // Source rows transitioned to `archive_compacted`.
        core.with_db(|db| {
            for sid in [s1, s2] {
                let state: String = db
                    .connection()
                    .query_row(
                        "SELECT state FROM archive_segment_map WHERE segment_id = ?1",
                        rusqlite::params![sid.to_string()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(state, "archive_compacted");
            }
        });
    }

    #[test]
    fn compact_archive_applies_tombstones() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let live_mid = Uuid::now_v7();
        let dead_mid = Uuid::now_v7();
        let transport = FixtureTransport::default();
        // Segment 1 holds two messages.
        seal_and_seed_verified_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![
                make_event(conv, live_mid, 100),
                make_event(conv, dead_mid, 200),
            ],
        );
        // Segment 2 is a delete tombstone for `dead_mid`.
        let tombstone_event = crate::archive::event_journal::ArchiveEvent {
            event_type: crate::archive::event_journal::ArchiveEventType::MessageDeleted,
            conversation_id: conv,
            message_id: Some(dead_mid),
            payload: vec![],
            created_at_ms: 300,
        };
        seal_and_seed_verified_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![tombstone_event],
        );

        let router = crate::archive::download::ArchiveSegmentRouter::kchat_only(&transport);
        let mut compacts: Vec<crate::archive::segment_builder::BuiltSegment> = Vec::new();
        let _ = core
            .compact_archive(
                &router,
                conv,
                "2026-04",
                &epoch_bytes,
                |_sid| Ok(epoch_bytes),
                |built| {
                    compacts.push(built.clone());
                    Ok(())
                },
            )
            .expect("compact");
        assert_eq!(compacts.len(), 1);
        let plaintext = crate::archive::download::decrypt_archive_segment(
            &crate::archive::download::encode_archive_segment_blob(
                &compacts[0].segment_id,
                &compacts[0].merkle_root,
                &compacts[0].nonce,
                &compacts[0].ciphertext,
            ),
            &epoch_bytes,
        )
        .unwrap();
        let payload = crate::archive::download::decode_archive_segment_payload(&plaintext).unwrap();
        let mids: Vec<_> = payload.events.iter().filter_map(|e| e.message_id).collect();
        assert!(mids.contains(&live_mid), "live message survives");
        assert!(!mids.contains(&dead_mid), "tombstoned message is dropped");
        // The tombstone itself is also dropped.
        for ev in &payload.events {
            assert_ne!(
                ev.event_type,
                crate::archive::event_journal::ArchiveEventType::MessageDeleted
            );
        }
    }

    #[test]
    fn compact_archive_transitions_old_segments_to_compacted() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let transport = FixtureTransport::default();
        let s1 = seal_and_seed_verified_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![make_event(conv, m1, 100)],
        );
        let s2 = seal_and_seed_verified_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![make_event(conv, m2, 200)],
        );

        let router = crate::archive::download::ArchiveSegmentRouter::kchat_only(&transport);
        let _ = core
            .compact_archive(
                &router,
                conv,
                "2026-04",
                &epoch_bytes,
                |_sid| Ok(epoch_bytes),
                |_built| Ok(()),
            )
            .expect("compact");
        core.with_db(|db| {
            for sid in [s1, s2] {
                let state: String = db
                    .connection()
                    .query_row(
                        "SELECT state FROM archive_segment_map WHERE segment_id = ?1",
                        rusqlite::params![sid.to_string()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(state, "archive_compacted");
            }
        });
    }

    #[test]
    fn compact_archive_noop_for_single_segment() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();
        let m1 = Uuid::now_v7();
        let transport = FixtureTransport::default();
        let s1 = seal_and_seed_verified_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            "2026-04",
            vec![make_event(conv, m1, 100)],
        );

        let router = crate::archive::download::ArchiveSegmentRouter::kchat_only(&transport);
        let mut compacts: Vec<crate::archive::segment_builder::BuiltSegment> = Vec::new();
        let result = core
            .compact_archive(
                &router,
                conv,
                "2026-04",
                &epoch_bytes,
                |_sid| Ok(epoch_bytes),
                |built| {
                    compacts.push(built.clone());
                    Ok(())
                },
            )
            .expect("noop");
        assert_eq!(result.buckets_inspected, 1);
        assert_eq!(result.buckets_compacted, 0);
        assert_eq!(result.segments_superseded, 0);
        assert_eq!(result.segments_emitted, 0);
        assert!(compacts.is_empty());
        // Source row remains at archive_verified.
        core.with_db(|db| {
            let state: String = db
                .connection()
                .query_row(
                    "SELECT state FROM archive_segment_map WHERE segment_id = ?1",
                    rusqlite::params![s1.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, "archive_verified");
        });
    }

    // ----------------------------------------------------------------
    // Phase 5, Task 2: upload_search_shards round-trip
    // ----------------------------------------------------------------

    #[test]
    fn upload_search_shards_round_trip_through_mock_transport() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::formats::search_shard::IndexType;
        use crate::search::cold_shard_source::{ShardKeyRegistry, TransportColdShardSource};
        use crate::search::query_engine::ColdShardSource;
        use crate::search::shard_builder::{FtsRow, FuzzyRow};
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";

        let fts_row = FtsRow {
            message_id: Uuid::now_v7().to_string(),
            conversation_id: conv_id.clone(),
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: "wendy lighthouse".into(),
        };
        let fuzzy_row = FuzzyRow {
            token: "wendy".into(),
            script: "Latn".into(),
            message_id: fts_row.message_id.clone(),
        };

        let transport = MockTransportClient::new();
        let receipt = core
            .upload_search_shards(
                &transport,
                &conv_id,
                bucket,
                vec![fts_row.clone()],
                vec![fuzzy_row.clone()],
                &k_text,
                &k_fuzzy,
                &conv_hash_key,
            )
            .expect("upload");
        assert!(receipt.text_shard.is_some());
        assert!(receipt.fuzzy_shard.is_some());
        assert_eq!(receipt.text_shard.as_ref().unwrap().doc_count, 1);
        assert_eq!(receipt.fuzzy_shard.as_ref().unwrap().doc_count, 1);

        let upload_calls = transport.upload_calls();
        assert_eq!(upload_calls.len(), 2);
        // Order: text first, then fuzzy.
        assert_eq!(upload_calls[0].2, "text");
        assert_eq!(upload_calls[1].2, "fuzzy");
        assert_eq!(upload_calls[0].0, receipt.conversation_hash);

        // Round-trip: TransportColdShardSource should retrieve and
        // decrypt the rows we just uploaded.
        let mut registry = ShardKeyRegistry::new();
        registry.insert(&conv_id, bucket, IndexType::Text, k_text.clone());
        registry.insert(&conv_id, bucket, IndexType::Fuzzy, k_fuzzy.clone());
        let adapter = TransportColdShardSource::new(
            &transport,
            vec![(conv_id.clone(), bucket.into())],
            &registry,
            &conv_hash_key,
        );
        let rows = adapter.fetch_text_rows(&conv_id, bucket).expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text_content, "wendy lighthouse");

        let fz = adapter.fetch_fuzzy_rows(&conv_id, bucket).expect("rows");
        assert_eq!(fz.len(), 1);
        assert_eq!(fz[0].token, "wendy");
    }

    #[test]
    fn upload_search_shards_skips_empty_buckets() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);
        let conv_id = Uuid::now_v7().to_string();

        let transport = MockTransportClient::new();
        let receipt = core
            .upload_search_shards(
                &transport,
                &conv_id,
                "2026-04",
                vec![],
                vec![],
                &k_text,
                &k_fuzzy,
                &conv_hash_key,
            )
            .expect("upload");
        assert!(receipt.text_shard.is_none());
        assert!(receipt.fuzzy_shard.is_none());
        assert!(transport.upload_calls().is_empty());
    }

    #[test]
    fn upload_search_shards_records_transport_failure_on_receipt() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::search::shard_builder::{keyed_conversation_id_hash, FtsRow};
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";

        let conv_hash = keyed_conversation_id_hash(&conv_id, &conv_hash_key);
        let conv_hash_b64 = base64_urlsafe_encode(&conv_hash);

        let transport = MockTransportClient::new();
        transport.fail_index_shard_upload_with(&conv_hash_b64, bucket, "text", "connection reset");

        let fts_row = FtsRow {
            message_id: Uuid::now_v7().to_string(),
            conversation_id: conv_id.clone(),
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: "wendy lighthouse".into(),
        };

        let receipt = core
            .upload_search_shards(
                &transport,
                &conv_id,
                bucket,
                vec![fts_row],
                vec![],
                &k_text,
                &k_fuzzy,
                &conv_hash_key,
            )
            .expect("upload should not error on transport failure — failure is on the receipt");
        assert!(
            receipt.text_shard.is_none(),
            "failed text shard should not be reported as success"
        );
        assert!(receipt.fuzzy_shard.is_none(), "fuzzy was empty");
        assert!(
            receipt.has_failures(),
            "receipt must report the transport failure"
        );
        let text_err = receipt.text_error.as_ref().expect("text_error populated");
        assert!(
            text_err.contains("connection reset") && text_err.contains("upload_search_shards"),
            "text_error preserves upstream message: {text_err}",
        );
        assert_eq!(receipt.first_error(), receipt.text_error.as_deref());

        // Retry with a fresh transport that doesn't fail.
        let healthy = MockTransportClient::new();
        let fts_row_2 = FtsRow {
            message_id: Uuid::now_v7().to_string(),
            conversation_id: conv_id.clone(),
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_001,
            text_content: "wendy lighthouse".into(),
        };
        let receipt = core
            .upload_search_shards(
                &healthy,
                &conv_id,
                bucket,
                vec![fts_row_2],
                vec![],
                &k_text,
                &k_fuzzy,
                &conv_hash_key,
            )
            .expect("retry upload");
        assert!(receipt.text_shard.is_some());
        assert!(!receipt.has_failures());
    }

    #[test]
    fn upload_search_shards_partial_success_text_uploaded_fuzzy_failed() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::search::shard_builder::{keyed_conversation_id_hash, FtsRow, FuzzyRow};
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";

        let conv_hash = keyed_conversation_id_hash(&conv_id, &conv_hash_key);
        let conv_hash_b64 = base64_urlsafe_encode(&conv_hash);

        let transport = MockTransportClient::new();
        transport.fail_index_shard_upload_with(
            &conv_hash_b64,
            bucket,
            "fuzzy",
            "fuzzy backend 503",
        );

        let fts_row = FtsRow {
            message_id: Uuid::now_v7().to_string(),
            conversation_id: conv_id.clone(),
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: "wendy lighthouse".into(),
        };
        let fuzzy_row = FuzzyRow {
            token: "wendy".into(),
            script: "Latn".into(),
            message_id: fts_row.message_id.clone(),
        };

        // Partial-upload contract: text succeeds, fuzzy fails. The
        // caller can detect this and retry only the fuzzy half
        // without re-uploading the text shard.
        let receipt = core
            .upload_search_shards(
                &transport,
                &conv_id,
                bucket,
                vec![fts_row],
                vec![fuzzy_row],
                &k_text,
                &k_fuzzy,
                &conv_hash_key,
            )
            .expect("upload");
        assert!(
            receipt.text_shard.is_some(),
            "text shard should be recorded as successfully uploaded",
        );
        assert!(
            receipt.fuzzy_shard.is_none(),
            "fuzzy shard upload failed, must not be reported as success",
        );
        assert!(receipt.text_error.is_none());
        let fuzzy_err = receipt.fuzzy_error.as_ref().expect("fuzzy_error populated");
        assert!(
            fuzzy_err.contains("fuzzy backend 503") && fuzzy_err.contains("upload_search_shards"),
            "fuzzy_error preserves upstream message: {fuzzy_err}",
        );
        assert!(receipt.has_failures());

        // The text shard was sent over the wire even though fuzzy
        // failed — exactly one upload call recorded.
        let calls = transport.upload_calls();
        assert_eq!(calls.iter().filter(|c| c.2 == "text").count(), 1);
        assert_eq!(calls.iter().filter(|c| c.2 == "fuzzy").count(), 1);
    }

    // ----------------------------------------------------------------
    // Phase 5, Task 1: run_incremental_backup_with_search_shards
    // ----------------------------------------------------------------

    /// Insert a `search_fts` + `search_fuzzy` row pair for a
    /// freshly-seeded message id. Mirrors what the message
    /// processor does when an inbound message lands.
    fn seed_search_rows(
        core: &CoreImpl,
        conv: Uuid,
        msg: Uuid,
        ts_ms: i64,
        text_content: &str,
        fuzzy_tokens: &[(&str, &str)],
    ) {
        core.with_db(|db| {
            db.connection()
                .execute(
                    "INSERT INTO search_fts(
                        message_id, conversation_id, sender_id,
                        created_at_ms, text_content
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        msg.to_string(),
                        conv.to_string(),
                        "user-1",
                        ts_ms,
                        text_content,
                    ],
                )
                .unwrap();
            for (token, script) in fuzzy_tokens {
                db.connection()
                    .execute(
                        "INSERT OR IGNORE INTO search_fuzzy(token, script, message_id)
                         VALUES (?1, ?2, ?3)",
                        rusqlite::params![token, script, msg.to_string()],
                    )
                    .unwrap();
            }
        });
    }

    #[test]
    fn run_incremental_backup_with_search_shards_uploads_affected_buckets() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Two messages, same conversation, same calendar bucket.
        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let ts1 = 1_777_000_000_000;
        let ts2 = 1_777_000_001_000;
        seed_backup_event(&core, conv, m1, ts1);
        seed_backup_event(&core, conv, m2, ts2);
        seed_search_rows(
            &core,
            conv,
            m1,
            ts1,
            "lighthouse keeper",
            &[("lighthouse", "Latn")],
        );
        seed_search_rows(
            &core,
            conv,
            m2,
            ts2,
            "lighthouse beam",
            &[("lighthouse", "Latn"), ("beam", "Latn")],
        );

        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);

        let transport = MockTransportClient::new();
        let bundle = core
            .run_incremental_backup_with_search_shards(
                &transport,
                "scheduled",
                &conv_hash_key,
                |_conv, _bucket| Ok((k_text.clone(), k_fuzzy.clone())),
            )
            .expect("incremental backup with shards");

        assert_eq!(bundle.backup.segments_built, 1);
        assert_eq!(bundle.backup.events_segmented, 2);
        assert_eq!(bundle.shards.len(), 1, "single (conv, bucket) pair");
        let receipt = &bundle.shards[0];
        assert!(
            receipt.text_shard.is_some(),
            "text shard uploaded for the affected bucket"
        );
        assert!(
            receipt.fuzzy_shard.is_some(),
            "fuzzy shard uploaded for the affected bucket"
        );
        assert_eq!(receipt.text_shard.as_ref().unwrap().doc_count, 2);
        assert_eq!(receipt.fuzzy_shard.as_ref().unwrap().doc_count, 3);
        assert_eq!(receipt.time_bucket.len(), 7); // YYYY-MM
        assert!(!bundle.has_shard_failures());
        assert_eq!(bundle.buckets_uploaded(), 1);

        // Two upload calls landed on the wire (one text + one
        // fuzzy) under the bucket the events fell into.
        let calls = transport.upload_calls();
        assert_eq!(calls.len(), 2);
        let text_call = calls.iter().find(|c| c.2 == "text").expect("text upload");
        let fuzzy_call = calls.iter().find(|c| c.2 == "fuzzy").expect("fuzzy upload");
        assert_eq!(text_call.0, receipt.conversation_hash);
        assert_eq!(fuzzy_call.0, receipt.conversation_hash);
        assert_eq!(text_call.1, receipt.time_bucket);
        assert_eq!(fuzzy_call.1, receipt.time_bucket);
    }

    #[test]
    fn run_incremental_backup_with_search_shards_is_noop_with_no_events() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let transport = MockTransportClient::new();
        let bundle = core
            .run_incremental_backup_with_search_shards(
                &transport,
                "scheduled",
                &conv_hash_key,
                |_conv, _bucket| panic!("must not derive keys for noop"),
            )
            .expect("noop");
        assert_eq!(bundle.backup, BackupResult::default());
        assert!(bundle.shards.is_empty());
        assert!(transport.upload_calls().is_empty());
    }

    #[test]
    fn run_incremental_backup_with_search_shards_groups_distinct_buckets() {
        use crate::archive::segment_builder::default_time_bucket_for_ms;
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv_a = Uuid::now_v7();
        let conv_b = Uuid::now_v7();
        seed_conversation(&core, &conv_a);
        seed_conversation(&core, &conv_b);

        // conv_a in 2026-04, conv_b in 2026-04, conv_b in 2026-12.
        let ts_apr = 1_777_000_000_000;
        let ts_apr_2 = 1_777_000_002_000;
        // ~ 8 months later.
        let ts_dec = ts_apr + 240 * 24 * 3_600 * 1_000;

        let m_a = Uuid::now_v7();
        let m_b1 = Uuid::now_v7();
        let m_b2 = Uuid::now_v7();
        seed_backup_event(&core, conv_a, m_a, ts_apr);
        seed_backup_event(&core, conv_b, m_b1, ts_apr_2);
        seed_backup_event(&core, conv_b, m_b2, ts_dec);
        seed_search_rows(&core, conv_a, m_a, ts_apr, "alpha", &[("alpha", "Latn")]);
        seed_search_rows(&core, conv_b, m_b1, ts_apr_2, "bravo", &[("bravo", "Latn")]);
        seed_search_rows(
            &core,
            conv_b,
            m_b2,
            ts_dec,
            "charlie",
            &[("charlie", "Latn")],
        );

        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);
        let transport = MockTransportClient::new();

        let bundle = core
            .run_incremental_backup_with_search_shards(
                &transport,
                "scheduled",
                &conv_hash_key,
                |_conv, _bucket| Ok((k_text.clone(), k_fuzzy.clone())),
            )
            .expect("incremental backup with shards");

        assert_eq!(bundle.backup.segments_built, 1);
        assert_eq!(bundle.shards.len(), 3, "3 distinct (conv,bucket) pairs");
        // Six upload calls: 3 buckets × (text + fuzzy).
        assert_eq!(transport.upload_calls().len(), 6);
        let buckets: Vec<_> = bundle
            .shards
            .iter()
            .map(|s| s.time_bucket.clone())
            .collect();
        assert!(buckets.contains(&default_time_bucket_for_ms(ts_apr)));
        assert!(buckets.contains(&default_time_bucket_for_ms(ts_dec)));
    }

    #[test]
    fn run_incremental_backup_with_search_shards_skips_buckets_with_no_search_rows() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Backup event but NO matching search_fts/search_fuzzy
        // rows — e.g. an event that does not produce indexable
        // text (a media-only message with no caption). The
        // upload sweep should silently skip the empty bucket.
        seed_backup_event(&core, conv, Uuid::now_v7(), 1_777_000_000_000);

        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);
        let transport = MockTransportClient::new();

        let bundle = core
            .run_incremental_backup_with_search_shards(
                &transport,
                "scheduled",
                &conv_hash_key,
                |_conv, _bucket| Ok((k_text.clone(), k_fuzzy.clone())),
            )
            .expect("incremental backup");
        assert_eq!(bundle.backup.segments_built, 1);
        assert!(bundle.shards.is_empty(), "no search rows → no shard upload",);
        assert!(transport.upload_calls().is_empty());
    }

    #[test]
    fn run_incremental_backup_with_search_shards_records_partial_failure_on_receipt() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::search::shard_builder::keyed_conversation_id_hash;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let m = Uuid::now_v7();
        let ts = 1_777_000_000_000;
        seed_backup_event(&core, conv, m, ts);
        seed_search_rows(&core, conv, m, ts, "wendy", &[("wendy", "Latn")]);

        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);

        // Pre-stage a fuzzy-shard upload failure for the bucket
        // the events will fall into.
        let conv_hash = keyed_conversation_id_hash(&conv.to_string(), &conv_hash_key);
        let conv_hash_b64 = base64_urlsafe_encode(&conv_hash);
        let bucket = crate::archive::segment_builder::default_time_bucket_for_ms(ts);
        let transport = MockTransportClient::new();
        transport.fail_index_shard_upload_with(
            &conv_hash_b64,
            &bucket,
            "fuzzy",
            "fuzzy backend 503",
        );

        let bundle = core
            .run_incremental_backup_with_search_shards(
                &transport,
                "scheduled",
                &conv_hash_key,
                |_conv, _bucket| Ok((k_text.clone(), k_fuzzy.clone())),
            )
            .expect("incremental backup");
        assert_eq!(bundle.backup.segments_built, 1);
        assert_eq!(bundle.shards.len(), 1);
        let receipt = &bundle.shards[0];
        assert!(receipt.text_shard.is_some());
        assert!(receipt.fuzzy_shard.is_none());
        assert!(bundle.has_shard_failures());
        assert!(receipt
            .fuzzy_error
            .as_deref()
            .unwrap()
            .contains("fuzzy backend 503"));
    }

    /// PR-#33 review regression: the Task-1 wrapper must build
    /// its `(conversation_id, time_bucket) → message_ids` map
    /// from the *exact* event set the inner pipeline sealed, not
    /// from an independent peek of `backup_event_journal`. The
    /// pre-fix wrapper called `read_unsegmented` itself before
    /// running the inner pipeline; a concurrent
    /// `BackupEventJournal::write_event` between the wrapper's
    /// peek (lock release) and the inner's re-read (lock
    /// re-acquire) would let the inner seal + cursor-advance
    /// past an event that the outer's `bucket_map` never saw,
    /// silently leaving its `search_fts` / `search_fuzzy` rows
    /// out of every shard upload — and the cursor advance meant
    /// no future call would re-peek those events either, so the
    /// loss was permanent. Post-fix the wrapper consumes
    /// `run_incremental_backup_inner`'s `sealed_events` summary
    /// directly so the two are derived from the same event
    /// list and cannot disagree.
    ///
    /// Test: spawn a writer thread that interleaves event +
    /// search-row writes with the main thread's wrapper calls.
    /// Drive the wrapper in a loop until both the writer is
    /// done and the journal is fully drained, then decode every
    /// `text` shard the mock transport recorded and union the
    /// `message_id`s. Assert the covered set equals the seeded
    /// set — every event must end up sealed in *some* bundle's
    /// shard upload, never sealed-and-orphaned. Also asserts
    /// the per-call invariant `Σ text_shard.doc_count ==
    /// backup.events_segmented`, which the post-fix wrapper
    /// guarantees.
    #[test]
    fn run_incremental_backup_with_search_shards_no_event_lost_under_concurrent_writer() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::formats::search_shard::SearchIndexShard;
        use crate::search::shard_builder::restore_text_search_shard;
        use crate::transport::MockTransportClient;
        use std::collections::BTreeSet;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const TOTAL_EVENTS: usize = 80;

        let core = Arc::new(fresh_core());
        install_test_backup_keys(&core);
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);

        // Pre-allocate the message_ids in the main thread so the
        // assertion can pin down the "seeded set".
        let mids: Vec<Uuid> = (0..TOTAL_EVENTS).map(|_| Uuid::now_v7()).collect();
        let expected: BTreeSet<String> = mids.iter().map(|u| u.to_string()).collect();

        let writer_done = Arc::new(AtomicBool::new(false));

        let writer_core = Arc::clone(&core);
        let writer_done_w = Arc::clone(&writer_done);
        let mids_w = mids.clone();
        let writer = std::thread::spawn(move || {
            // Spread across two `(conv, bucket)` pairs so the
            // wrapper's `bucket_map` has multiple entries each
            // call — a pre-fix peek-vs-seal split would be more
            // visible.
            for (i, mid) in mids_w.iter().enumerate() {
                let base = if i % 2 == 0 {
                    1_777_000_000_000 // 2026-04 bucket
                } else {
                    1_780_000_000_000 // 2026-05 bucket
                };
                let ts = base + i as i64;
                seed_backup_event(&writer_core, conv, *mid, ts);
                let body = format!("alpha-{i}");
                seed_search_rows(
                    &writer_core,
                    conv,
                    *mid,
                    ts,
                    &body,
                    &[(body.as_str(), "Latn")],
                );
                // Tiny pause so the main thread's wrapper has a
                // window to acquire the db mutex between writes
                // — exercises the lock-release / re-acquire seam
                // the original race lived in.
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
            writer_done_w.store(true, Ordering::Release);
        });

        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let k_text = KeyMaterial::from_bytes([0xA1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xA2; 32]);

        let transport = MockTransportClient::new();
        let mut total_segmented: u64 = 0;

        // Drive the wrapper until both the writer is done and
        // the inner reports zero events_segmented (i.e. the
        // journal is fully drained past the cursor).
        loop {
            let bundle = core
                .run_incremental_backup_with_search_shards(
                    &transport,
                    "scheduled",
                    &conv_hash_key,
                    |_conv, _bucket| Ok((k_text.clone(), k_fuzzy.clone())),
                )
                .expect("incremental backup with shards");

            total_segmented += bundle.backup.events_segmented;
            // Per-call invariant the post-fix code guarantees:
            // every event the inner sealed must have its
            // message_id covered by *this* bundle's text shards
            // (the bucket_map is built directly from
            // sealed_events).
            let bundle_doc_count: u64 = bundle
                .shards
                .iter()
                .map(|s| s.text_shard.as_ref().map(|t| t.doc_count).unwrap_or(0))
                .sum();
            assert_eq!(
                bundle_doc_count, bundle.backup.events_segmented,
                "per-call invariant: shards' text doc_count must \
                 equal events_segmented (pre-fix wrapper could \
                 miss events under concurrent writes)"
            );

            if writer_done.load(Ordering::Acquire) && bundle.backup.events_segmented == 0 {
                break;
            }
        }
        writer.join().expect("writer thread");

        // Every event ever written must have been sealed exactly
        // once across all wrapper calls.
        assert_eq!(
            total_segmented, TOTAL_EVENTS as u64,
            "every seeded event must be sealed exactly once"
        );

        // Decode every `text` upload the mock recorded and union
        // the message_ids — they must equal the seeded set. The
        // mock's `upload_calls()` returns
        // `(conv_hash, bucket, shard_type, ciphertext)`; the
        // ciphertext is `crate::cbor::to_vec(&SearchIndexShard)`
        // (see `CoreImpl::upload_search_shards`).
        let mut covered: BTreeSet<String> = BTreeSet::new();
        for (_conv_hash, _bucket, shard_type, bytes) in transport.upload_calls() {
            if shard_type != "text" {
                continue;
            }
            let shard: SearchIndexShard = crate::cbor::from_slice(&bytes).expect("decode shard");
            let rows = restore_text_search_shard(&shard, &k_text).expect("open text shard");
            for r in rows {
                covered.insert(r.message_id);
            }
        }
        assert_eq!(
            covered, expected,
            "every seeded message_id must appear in some text-shard upload"
        );
    }

    // ----------------------------------------------------------------
    // Phase 5, Task 2: fetch_and_restore_cold_shards
    // ----------------------------------------------------------------

    /// Stage one text + one fuzzy shard for `(conv, bucket)` on
    /// `transport` and return the per-shard keys plus the rows
    /// that should round-trip back through
    /// `fetch_and_restore_cold_shards`.
    fn stage_round_trip_shards(
        transport: &crate::transport::MockTransportClient,
        conv: &str,
        bucket: &str,
        conv_hash_key: &crate::crypto::key_hierarchy::KeyMaterial,
    ) -> (
        crate::crypto::key_hierarchy::KeyMaterial,
        crate::crypto::key_hierarchy::KeyMaterial,
        Vec<crate::search::shard_builder::FtsRow>,
        Vec<crate::search::shard_builder::FuzzyRow>,
    ) {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::search::shard_builder::{
            build_fuzzy_search_shard, build_text_search_shard, keyed_conversation_id_hash, FtsRow,
            FuzzyRow,
        };

        let k_text = KeyMaterial::from_bytes([0xC1; 32]);
        let k_fuzzy = KeyMaterial::from_bytes([0xC2; 32]);
        let m1 = Uuid::now_v7().to_string();
        let m2 = Uuid::now_v7().to_string();
        let fts_rows = vec![
            FtsRow {
                message_id: m1.clone(),
                conversation_id: conv.into(),
                sender_id: "user-1".into(),
                created_at_ms: 1_777_000_000_000,
                text_content: "lighthouse one".into(),
            },
            FtsRow {
                message_id: m2.clone(),
                conversation_id: conv.into(),
                sender_id: "user-1".into(),
                created_at_ms: 1_777_000_001_000,
                text_content: "lighthouse two".into(),
            },
        ];
        let fuzzy_rows = vec![
            FuzzyRow {
                token: "lighthouse".into(),
                script: "Latn".into(),
                message_id: m1.clone(),
            },
            FuzzyRow {
                token: "lighthouse".into(),
                script: "Latn".into(),
                message_id: m2.clone(),
            },
        ];

        let text_built = build_text_search_shard(
            fts_rows.clone(),
            conv,
            bucket.to_string(),
            &k_text,
            conv_hash_key,
        )
        .unwrap();
        let fuzzy_built = build_fuzzy_search_shard(
            fuzzy_rows.clone(),
            conv,
            bucket.to_string(),
            &k_fuzzy,
            conv_hash_key,
        )
        .unwrap();
        let conv_hash = keyed_conversation_id_hash(conv, conv_hash_key);
        let conv_hash_b64 = base64_urlsafe_encode(&conv_hash);
        transport.stage_index_shard(
            &conv_hash_b64,
            bucket,
            "text",
            crate::cbor::to_vec(&text_built.shard).unwrap(),
        );
        transport.stage_index_shard(
            &conv_hash_b64,
            bucket,
            "fuzzy",
            crate::cbor::to_vec(&fuzzy_built.shard).unwrap(),
        );
        (k_text, k_fuzzy, fts_rows, fuzzy_rows)
    }

    #[test]
    fn fetch_and_restore_cold_shards_round_trips_text_and_fuzzy() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::formats::search_shard::IndexType;
        use crate::search::cold_shard_source::ShardKeyRegistry;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";

        let transport = MockTransportClient::new();
        let (k_text, k_fuzzy, fts_rows, fuzzy_rows) =
            stage_round_trip_shards(&transport, &conv_id, bucket, &conv_hash_key);

        let mut registry = ShardKeyRegistry::new();
        registry.insert(&conv_id, bucket, IndexType::Text, k_text);
        registry.insert(&conv_id, bucket, IndexType::Fuzzy, k_fuzzy);

        let summary = core
            .fetch_and_restore_cold_shards(&transport, &conv_id, bucket, &conv_hash_key, &registry)
            .expect("restore");
        assert_eq!(summary.fetched_shards, 2);
        assert_eq!(summary.text_rows_inserted, fts_rows.len());
        assert_eq!(summary.fuzzy_rows_inserted, fuzzy_rows.len());
        assert!(!summary.is_empty());

        // Round-trip: every text + fuzzy row landed in the local
        // tables and is queryable.
        core.with_db(|db| {
            for r in &fts_rows {
                let n: i64 = db
                    .connection()
                    .query_row(
                        "SELECT count(*) FROM search_fts WHERE message_id = ?1",
                        rusqlite::params![r.message_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(n, 1, "fts row for {} present", r.message_id);
            }
            for r in &fuzzy_rows {
                let n: i64 = db
                    .connection()
                    .query_row(
                        "SELECT count(*) FROM search_fuzzy
                         WHERE token = ?1 AND script = ?2 AND message_id = ?3",
                        rusqlite::params![r.token, r.script, r.message_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(n, 1, "fuzzy row for {}/{} present", r.token, r.message_id);
            }
        });
    }

    #[test]
    fn fetch_and_restore_cold_shards_returns_zero_summary_for_empty_bucket() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::search::cold_shard_source::ShardKeyRegistry;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";
        let transport = MockTransportClient::new();
        // No staged shards — every fetch returns empty bytes.
        let registry = ShardKeyRegistry::new();
        let summary = core
            .fetch_and_restore_cold_shards(&transport, &conv_id, bucket, &conv_hash_key, &registry)
            .expect("restore");
        assert!(summary.is_empty());
        assert_eq!(summary.fetched_shards, 0);
        assert_eq!(summary.text_rows_inserted, 0);
        assert_eq!(summary.fuzzy_rows_inserted, 0);
    }

    #[test]
    fn fetch_and_restore_cold_shards_with_wrong_key_surfaces_aead_failure() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::formats::search_shard::IndexType;
        use crate::search::cold_shard_source::ShardKeyRegistry;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";

        let transport = MockTransportClient::new();
        let (_k_text, _k_fuzzy, _fts, _fz) =
            stage_round_trip_shards(&transport, &conv_id, bucket, &conv_hash_key);

        // Register WRONG keys for the registry. Decryption will
        // fail at AEAD-open time on the first shard.
        let mut registry = ShardKeyRegistry::new();
        registry.insert(
            &conv_id,
            bucket,
            IndexType::Text,
            KeyMaterial::from_bytes([0x11; 32]),
        );
        registry.insert(
            &conv_id,
            bucket,
            IndexType::Fuzzy,
            KeyMaterial::from_bytes([0x12; 32]),
        );

        let err = core
            .fetch_and_restore_cold_shards(&transport, &conv_id, bucket, &conv_hash_key, &registry)
            .expect_err("wrong key must surface as Err");
        let msg = err.to_string();
        assert!(
            msg.contains("aead") || msg.contains("AEAD") || msg.contains("decrypt"),
            "expected AEAD-style error, got {msg}"
        );

        // Local tables remain empty (the replay transaction
        // rolls back on the first failing shard).
        core.with_db(|db| {
            let n: i64 = db
                .connection()
                .query_row("SELECT count(*) FROM search_fts", [], |row| row.get(0))
                .unwrap();
            assert_eq!(n, 0);
            let n: i64 = db
                .connection()
                .query_row("SELECT count(*) FROM search_fuzzy", [], |row| row.get(0))
                .unwrap();
            assert_eq!(n, 0);
        });
    }

    #[test]
    fn fetch_and_restore_cold_shards_missing_registry_key_is_storage_error() {
        use crate::crypto::key_hierarchy::KeyMaterial;
        use crate::search::cold_shard_source::ShardKeyRegistry;
        use crate::transport::MockTransportClient;

        let core = fresh_core();
        let conv_hash_key = KeyMaterial::from_bytes([0x66; 32]);
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";
        let transport = MockTransportClient::new();
        let _ = stage_round_trip_shards(&transport, &conv_id, bucket, &conv_hash_key);

        // Empty registry — every lookup misses.
        let registry = ShardKeyRegistry::new();
        let err = core
            .fetch_and_restore_cold_shards(&transport, &conv_id, bucket, &conv_hash_key, &registry)
            .expect_err("missing registry entry must surface");
        assert!(err.to_string().contains("missing shard key"));
    }

    // ----------------------------------------------------------------
    // Phase 5, Task 3: hydrate_cold_search_results
    // ----------------------------------------------------------------

    /// Build a `MessageReceived` event whose payload carries a
    /// real text body via [`crate::archive::body_payload::encode`]
    /// — the production format the cold-hit hydration path
    /// decodes back via `try_decode_text`.
    fn body_event(
        conv: Uuid,
        message_id: Uuid,
        ms: i64,
        text: &str,
    ) -> crate::archive::event_journal::ArchiveEvent {
        crate::archive::event_journal::ArchiveEvent {
            event_type: crate::archive::event_journal::ArchiveEventType::MessageReceived,
            conversation_id: conv,
            message_id: Some(message_id),
            payload: crate::archive::body_payload::encode(Some(text)).unwrap(),
            created_at_ms: ms,
        }
    }

    /// Insert a `RemoteArchiveOnly` skeleton — same shape as
    /// what `rehydrate_timeline_skeletons` would have landed.
    fn seed_remote_only_skeleton(
        core: &CoreImpl,
        conv: Uuid,
        message_id: Uuid,
        created_at_ms: i64,
    ) {
        core.with_db(|db| {
            let stub = MessageSkeleton {
                message_id: message_id.to_string(),
                conversation_id: conv.to_string(),
                sender_id: "user-1".into(),
                created_at_ms,
                received_at_ms: created_at_ms,
                kind: MessageKind::Text,
                body_state: BodyState::RemoteArchiveOnly,
                media_state: None,
                archive_state: ArchiveState::ArchiveUploaded,
                backup_state: BackupState::NotBackedUp,
                reply_to: None,
                edited_at_ms: None,
                deleted_at_ms: None,
            };
            let _ = db.upsert_skeleton_from_archive(&stub).unwrap();
        });
    }

    fn cold_hit(
        message_id: Uuid,
        conversation_id: Uuid,
        created_at_ms: i64,
        snippet: &str,
    ) -> SearchResult {
        SearchResult {
            message_id,
            conversation_id,
            sender_id: "user-1".into(),
            created_at_ms,
            snippet: Some(snippet.into()),
            rank_score: 0.0,
            is_cold: true,
            semantic_score: None,
        }
    }

    #[test]
    fn hydrate_cold_search_results_writes_back_text_and_flips_body_state() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let m1 = Uuid::now_v7();
        let m2 = Uuid::now_v7();
        let ts = 1_777_000_000_000;
        let bucket = crate::archive::segment_builder::default_time_bucket_for_ms(ts);

        let transport = FixtureTransport::default();
        seal_and_seed_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            &bucket,
            vec![
                body_event(conv, m1, ts, "lighthouse one"),
                body_event(conv, m2, ts + 1_000, "lighthouse two"),
            ],
        );
        seed_remote_only_skeleton(&core, conv, m1, ts);
        seed_remote_only_skeleton(&core, conv, m2, ts + 1_000);

        let results = vec![
            cold_hit(m1, conv, ts, "lighthouse one"),
            cold_hit(m2, conv, ts + 1_000, "lighthouse two"),
        ];

        let hydrated = core
            .hydrate_cold_search_results(&transport, &results, |_segment_id| Ok(epoch_bytes))
            .expect("hydrate");
        assert_eq!(hydrated, 2);

        // Body rows landed and body_state flipped.
        core.with_db(|db| {
            for (mid, expected) in [(m1, "lighthouse one"), (m2, "lighthouse two")] {
                let skel = db.get_message_skeleton(&mid.to_string()).unwrap().unwrap();
                assert_eq!(skel.body_state, BodyState::LocalPlainAvailable);
                let body = db.get_message_body(&mid.to_string()).unwrap().unwrap();
                assert_eq!(body.text_content.as_deref(), Some(expected));
                let n: i64 = db
                    .connection()
                    .query_row(
                        "SELECT count(*) FROM search_fts WHERE message_id = ?1",
                        rusqlite::params![mid.to_string()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(n, 1, "FTS row landed for {mid}");
                let f: i64 = db
                    .connection()
                    .query_row(
                        "SELECT count(*) FROM search_fuzzy WHERE message_id = ?1",
                        rusqlite::params![mid.to_string()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(f > 0, "fuzzy tokens landed for {mid}");
            }
        });
    }

    #[test]
    fn hydrate_cold_search_results_makes_message_searchable_locally() {
        // The hydrated body should round-trip through the local
        // FTS5 search path.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let mid = Uuid::now_v7();
        let ts = 1_777_000_000_000;
        let bucket = crate::archive::segment_builder::default_time_bucket_for_ms(ts);
        let transport = FixtureTransport::default();
        seal_and_seed_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            &bucket,
            vec![body_event(conv, mid, ts, "hydrated needle in stack")],
        );
        seed_remote_only_skeleton(&core, conv, mid, ts);

        let results = vec![cold_hit(mid, conv, ts, "hydrated needle in stack")];
        let hydrated = core
            .hydrate_cold_search_results(&transport, &results, |_| Ok(epoch_bytes))
            .expect("hydrate");
        assert_eq!(hydrated, 1);

        // Local FTS now finds the hydrated body without going
        // through the cold path.
        let query = SearchQuery {
            query_string: "needle".into(),
            ..SearchQuery::default()
        };
        let (results, _) = core
            .search_and_prefetch_cold(query, SearchScope::LocalOnly)
            .expect("local search");
        assert!(
            results.iter().any(|r| r.message_id == mid && !r.is_cold),
            "hydrated message should be a local hit, got {results:?}"
        );
    }

    #[test]
    fn hydrate_cold_search_results_is_idempotent() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let mid = Uuid::now_v7();
        let ts = 1_777_000_000_000;
        let bucket = crate::archive::segment_builder::default_time_bucket_for_ms(ts);
        let transport = FixtureTransport::default();
        seal_and_seed_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            &bucket,
            vec![body_event(conv, mid, ts, "round trip")],
        );
        seed_remote_only_skeleton(&core, conv, mid, ts);
        let results = vec![cold_hit(mid, conv, ts, "round trip")];

        // First call hydrates the body.
        let n1 = core
            .hydrate_cold_search_results(&transport, &results, |_| Ok(epoch_bytes))
            .expect("first");
        assert_eq!(n1, 1);

        // Second call rehydrates the same body — must not error
        // and must converge to the same row counts.
        let n2 = core
            .hydrate_cold_search_results(&transport, &results, |_| Ok(epoch_bytes))
            .expect("second");
        assert_eq!(n2, 1);

        core.with_db(|db| {
            let n: i64 = db
                .connection()
                .query_row(
                    "SELECT count(*) FROM message_skeleton WHERE message_id = ?1",
                    rusqlite::params![mid.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "no duplicate skeleton row");
            let n: i64 = db
                .connection()
                .query_row(
                    "SELECT count(*) FROM search_fts WHERE message_id = ?1",
                    rusqlite::params![mid.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "FTS row deduplicated");
        });
    }

    #[test]
    fn hydrate_cold_search_results_skips_legacy_payload_events() {
        // Old-format archive events do not carry text bodies.
        // The hydration path must skip them gracefully without
        // surfacing an error or leaving partial state.
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let mid = Uuid::now_v7();
        let ts = 1_777_000_000_000;
        let bucket = crate::archive::segment_builder::default_time_bucket_for_ms(ts);
        let transport = FixtureTransport::default();
        // Use the legacy `make_event` helper which writes opaque
        // bytes (`[0xDE, 0xAD]`) as the payload — pre-Phase-5
        // shape.
        seal_and_seed_segment(
            &core,
            &transport,
            &epoch_bytes,
            conv,
            &bucket,
            vec![make_event(conv, mid, ts)],
        );
        seed_remote_only_skeleton(&core, conv, mid, ts);

        let results = vec![cold_hit(mid, conv, ts, "any")];
        let n = core
            .hydrate_cold_search_results(&transport, &results, |_| Ok(epoch_bytes))
            .expect("hydrate");
        assert_eq!(n, 0, "legacy payloads must be skipped");

        // Skeleton stays remote-only and no body row exists.
        core.with_db(|db| {
            let skel = db.get_message_skeleton(&mid.to_string()).unwrap().unwrap();
            assert_eq!(skel.body_state, BodyState::RemoteArchiveOnly);
            assert!(db.get_message_body(&mid.to_string()).unwrap().is_none());
        });
    }

    #[test]
    fn hydrate_cold_search_results_with_no_cold_results_is_noop() {
        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let transport = FixtureTransport::default();
        // All results are local hits.
        let results = vec![SearchResult {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "user-1".into(),
            created_at_ms: 1_777_000_000_000,
            snippet: None,
            rank_score: 0.0,
            is_cold: false,
            semantic_score: None,
        }];
        let n = core
            .hydrate_cold_search_results(&transport, &results, |_| {
                panic!("must not derive keys when there are no cold rows")
            })
            .expect("noop");
        assert_eq!(n, 0);
    }

    /// Phase-5 cold-hit hydration with mixed-backend segments
    /// (PR-#33 review feedback). The cold-hydration write-back
    /// path must route through
    /// [`crate::archive::prefetch::batch_prefetch_bucket_with_router`]
    /// so a bucket whose `archive_segment_map` rows carry
    /// `storage_backend = 'zk_object_fabric'` lands the body
    /// via the installed S3 client instead of erroring with
    /// `Error::Storage("ZKOF row encountered ...")` from the
    /// KChat-only `batch_prefetch_bucket` variant.
    #[test]
    fn hydrate_cold_search_results_routes_zkof_segments_through_s3_client() {
        use crate::archive::download::encode_archive_segment_blob;
        use crate::archive::segment_builder::{ArchiveSegmentBuilder, SegmentBuildRequest};

        // Build a core with the ZKOF archive backend so
        // `build_archive_router` returns a router wired to
        // S3 instead of the KChat-only fallback.
        let cfg = test_config().with_archive_backend(crate::config::ArchiveBackend::Zkof);
        let core = CoreImpl::new_in_memory(cfg, TEST_KEY).unwrap();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let root = fresh_archive_root();
        core.install_epoch_key_manager(&root, "2026-04").unwrap();
        let epoch_bytes = core.with_current_epoch_key(|k| *k).unwrap();

        let s3 = std::sync::Arc::new(InMemoryS3::default());
        let s3_dyn: std::sync::Arc<dyn crate::media::sinks::zk_fabric::S3Client> = s3.clone();
        let zkof_cfg = fresh_zkof_config();
        let zkof_bucket = zkof_cfg.bucket.clone();
        core.install_zkof_archive_backend(s3_dyn, zkof_cfg).unwrap();

        // Seal a ZKOF-backed segment carrying one body-bearing
        // event, push it into the in-memory S3 at the key the
        // router uses, and seed the segment-map row with
        // `storage_backend = 'zk_object_fabric'`.
        let mid = Uuid::now_v7();
        let ts = 1_777_000_000_000;
        let bucket = crate::archive::segment_builder::default_time_bucket_for_ms(ts);
        let built = ArchiveSegmentBuilder::new()
            .build_segment(
                SegmentBuildRequest {
                    conversation_id: conv,
                    time_bucket: bucket.clone(),
                    events: vec![body_event(conv, mid, ts, "north star body")],
                    segment_type: crate::formats::SegmentType::MessageDelta,
                },
                &epoch_bytes,
            )
            .unwrap();
        let blob = encode_archive_segment_blob(
            &built.segment_id,
            &built.merkle_root,
            &built.nonce,
            &built.ciphertext,
        );
        s3.objects.lock().unwrap().insert(
            (
                zkof_bucket.clone(),
                format!("archive/segments/{}", built.segment_id),
            ),
            blob,
        );
        core.with_db(|db| {
            db.connection()
                .execute(
                    "INSERT INTO archive_segment_map(
                        segment_id, conversation_id, time_bucket,
                        segment_type, blob_id, storage_backend,
                        merkle_root, state
                     ) VALUES (?1, ?2, ?3, 'message_delta', ?4,
                              'zk_object_fabric', ?5, 'archive_uploaded')",
                    rusqlite::params![
                        built.segment_id.to_string(),
                        conv.to_string(),
                        bucket,
                        format!("blob-{}", built.segment_id),
                        built.merkle_root.as_slice(),
                    ],
                )
                .unwrap();
        });
        seed_remote_only_skeleton(&core, conv, mid, ts);

        // The transport handed to `hydrate_cold_search_results`
        // is the KChat-side `FixtureTransport`. The bucket has
        // no `kchat_backend` rows, so it must never be touched
        // — every fetch must dispatch to the in-memory S3.
        let transport = FixtureTransport::default();
        let results = vec![cold_hit(mid, conv, ts, "north star body")];
        let hydrated = core
            .hydrate_cold_search_results(&transport, &results, |_segment_id| Ok(epoch_bytes))
            .expect("hydrate via ZKOF");
        assert_eq!(hydrated, 1);

        assert!(
            transport.calls().is_empty(),
            "ZKOF-only bucket must never hit the KChat transport: \
             {:?}",
            transport.calls(),
        );

        // Body row landed; body_state flipped; FTS row indexed.
        core.with_db(|db| {
            let skel = db.get_message_skeleton(&mid.to_string()).unwrap().unwrap();
            assert_eq!(skel.body_state, BodyState::LocalPlainAvailable);
            let body = db.get_message_body(&mid.to_string()).unwrap().unwrap();
            assert_eq!(body.text_content.as_deref(), Some("north star body"));
            let n: i64 = db
                .connection()
                .query_row(
                    "SELECT count(*) FROM search_fts WHERE message_id = ?1",
                    rusqlite::params![mid.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "FTS row landed");
        });
    }

    // ----- Phase 6, Tasks 2 + 9: ingest embedding wiring ------------

    #[test]
    fn ingest_messages_writes_text_embedding_when_embedder_installed() {
        use crate::message::processor::IngestedMessage;
        use crate::models::embeddings::{
            EmbeddingCache, LocalStoreEmbeddingCache, MockTextEmbedder, XLMR_MODEL_VERSION,
        };

        let core = fresh_core();
        core.install_text_embedder(Box::new(MockTextEmbedder::default()))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let now = now_ms_for_send_media();

        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "alice".into(),
            created_at_ms: now,
            text_content: Some("the quick brown fox".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };

        let res = core.ingest_messages(&[msg]).expect("ingest");
        assert_eq!(res.new_messages, 1);

        // Vector landed in the cross-pipeline cache.
        core.with_db(|db| {
            let cache = LocalStoreEmbeddingCache::new(db.connection());
            let stored = cache
                .get(&mid.to_string(), XLMR_MODEL_VERSION)
                .expect("cache get")
                .expect("vector present");
            assert!(!stored.is_empty(), "embedding non-empty");
        });
    }

    // -----------------------------------------------------------------
    // Phase 7 (2026-05-04 batch 10) — Task 5/6 desktop search wiring.
    // -----------------------------------------------------------------

    #[derive(Debug, Default)]
    struct CountingSpotlight {
        index_calls: std::sync::Mutex<Vec<crate::desktop_index::SpotlightItem>>,
    }
    impl crate::desktop_index::SpotlightAnchor for CountingSpotlight {
        fn index_items(
            &self,
            items: &[crate::desktop_index::SpotlightItem],
        ) -> std::result::Result<(), Error> {
            self.index_calls
                .lock()
                .unwrap()
                .extend(items.iter().cloned());
            Ok(())
        }
        fn remove_items(&self, _ids: &[String]) -> std::result::Result<(), Error> {
            Ok(())
        }
        fn remove_all(&self) -> std::result::Result<(), Error> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct CountingWindowsSearch {
        index_calls: std::sync::Mutex<Vec<crate::desktop_index::WindowsSearchItem>>,
    }
    impl crate::desktop_index::WindowsSearchAnchor for CountingWindowsSearch {
        fn index_items(
            &self,
            items: &[crate::desktop_index::WindowsSearchItem],
        ) -> std::result::Result<(), Error> {
            self.index_calls
                .lock()
                .unwrap()
                .extend(items.iter().cloned());
            Ok(())
        }
        fn remove_items(&self, _ids: &[String]) -> std::result::Result<(), Error> {
            Ok(())
        }
        fn remove_all(&self) -> std::result::Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn core_impl_ingest_updates_spotlight_when_installed() {
        use crate::message::processor::IngestedMessage;

        let core = fresh_core();
        let anchor = std::sync::Arc::new(CountingSpotlight::default());
        core.install_spotlight_anchor(anchor.clone()).unwrap();
        assert!(core.has_spotlight_anchor());

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "alice".into(),
            created_at_ms: now_ms_for_send_media(),
            text_content: Some("the quick brown fox".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };
        core.ingest_messages(&[msg]).unwrap();

        let calls = anchor.index_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].unique_id, mid.to_string());
        assert_eq!(calls[0].conversation_id, conv.to_string());
        assert!(!calls[0].content_description.is_empty());
    }

    #[test]
    fn core_impl_ingest_updates_windows_search_when_installed() {
        use crate::message::processor::IngestedMessage;

        let core = fresh_core();
        let anchor = std::sync::Arc::new(CountingWindowsSearch::default());
        core.install_windows_search_anchor(anchor.clone()).unwrap();
        assert!(core.has_windows_search_anchor());

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "bob".into(),
            created_at_ms: now_ms_for_send_media(),
            text_content: Some("hello windows".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };
        core.ingest_messages(&[msg]).unwrap();
        let calls = anchor.index_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].unique_id, mid.to_string());
    }

    #[test]
    fn core_impl_ingest_skips_spotlight_when_not_installed() {
        // No anchor installed -> ingest still succeeds and the
        // ingest path stays free of panics.
        use crate::message::processor::IngestedMessage;
        let core = fresh_core();
        assert!(!core.has_spotlight_anchor());
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "carol".into(),
            created_at_ms: now_ms_for_send_media(),
            text_content: Some("no anchor".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };
        let res = core.ingest_messages(&[msg]).unwrap();
        assert_eq!(res.new_messages, 1);
    }

    #[test]
    fn core_impl_ingest_skips_media_only_messages_in_spotlight() {
        use crate::formats::media_descriptor::MediaDescriptor;
        use crate::message::processor::IngestedMessage;
        let core = fresh_core();
        let anchor = std::sync::Arc::new(CountingSpotlight::default());
        core.install_spotlight_anchor(anchor.clone()).unwrap();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let desc = MediaDescriptor {
            asset_id: Uuid::now_v7(),
            mime_type: "image/jpeg".into(),
            bytes_total: 1_024,
            chunk_count: 1,
            merkle_root: [0u8; 32],
            blob_id: Uuid::now_v7(),
            wrapped_k_asset: vec![0u8; 40],
            storage_sink: None,
        };
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "dave".into(),
            created_at_ms: now_ms_for_send_media(),
            text_content: None,
            media_descriptors: vec![desc],
            reply_to: None,
        };
        core.ingest_messages(&[msg]).unwrap();
        // Media-only -> redacted preview policy says skip.
        assert_eq!(anchor.index_calls.lock().unwrap().len(), 0);
    }

    #[test]
    fn ingest_messages_skips_embedding_without_installed_embedder() {
        use crate::message::processor::IngestedMessage;
        use crate::models::embeddings::{
            EmbeddingCache, LocalStoreEmbeddingCache, XLMR_MODEL_VERSION,
        };

        let core = fresh_core();
        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let now = now_ms_for_send_media();
        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "bob".into(),
            created_at_ms: now,
            text_content: Some("no embedder installed".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };
        core.ingest_messages(&[msg]).expect("ingest");
        core.with_db(|db| {
            let cache = LocalStoreEmbeddingCache::new(db.connection());
            assert!(cache
                .get(&mid.to_string(), XLMR_MODEL_VERSION)
                .unwrap()
                .is_none());
        });
    }

    #[test]
    fn send_media_writes_image_embedding_when_embedder_installed() {
        use crate::models::clip::{MockImageEmbedder, MOBILECLIP_S2_MODEL_VERSION};
        use crate::models::embeddings::{EmbeddingCache, LocalStoreEmbeddingCache};

        let core = fresh_core();
        core.install_image_embedder(Box::new(MockImageEmbedder::default()))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        core.with_db(|db| {
            let cache = LocalStoreEmbeddingCache::new(db.connection());
            let stored = cache
                .get(&mid.to_string(), MOBILECLIP_S2_MODEL_VERSION)
                .expect("cache get")
                .expect("image vector present");
            assert!(!stored.is_empty());
        });
    }

    #[test]
    fn send_media_skips_image_embedding_for_non_image_mime() {
        use crate::models::clip::{MockImageEmbedder, MOBILECLIP_S2_MODEL_VERSION};
        use crate::models::embeddings::{EmbeddingCache, LocalStoreEmbeddingCache};

        let core = fresh_core();
        core.install_image_embedder(Box::new(MockImageEmbedder::default()))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        // Use a non-image MIME with a small payload; the
        // wiring guards on `mime_type.starts_with("image/")`.
        let res = core.send_media(
            conv,
            mid,
            b"PDF binary stand-in".to_vec(),
            "application/pdf",
            None,
        );
        // send_media accepts arbitrary MIME types; we only care
        // that no image embedding is written for non-images.
        assert!(res.is_ok() || res.is_err());

        core.with_db(|db| {
            let cache = LocalStoreEmbeddingCache::new(db.connection());
            assert!(cache
                .get(&mid.to_string(), MOBILECLIP_S2_MODEL_VERSION)
                .unwrap()
                .is_none());
        });
    }

    // ----------------------------------------------------------------
    // Phase 6, Tasks 1-3 (2026-05-04 batch) — send_media fan-out
    // tests for video keyframe sampling, audio transcription,
    // and document text extraction. The trait-level coverage of
    // each seam lives in `crate::models::{video,whisper,document}`;
    // these tests pin the integration contract that an
    // installed seam fans out into the cache and FTS / fuzzy
    // indexes during `send_media`.
    // ----------------------------------------------------------------

    #[test]
    fn send_media_extracts_keyframes_and_embeds_when_sampler_installed() {
        use crate::models::clip::{MockImageEmbedder, MOBILECLIP_S2_MODEL_VERSION};
        use crate::models::embeddings::{EmbeddingCache, LocalStoreEmbeddingCache};
        use crate::models::video::MockVideoKeyframeSampler;

        let core = fresh_core();
        core.install_image_embedder(Box::new(MockImageEmbedder::default()))
            .unwrap();
        core.install_video_keyframe_sampler(Box::new(MockVideoKeyframeSampler))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, b"video-bytes-x".to_vec(), "video/mp4", None)
            .expect("send_media");

        core.with_db(|db| {
            let cache = LocalStoreEmbeddingCache::new(db.connection());
            // The unsuffixed canonical key is mirrored from
            // frame 0 so existing duplicate-detection still
            // resolves.
            assert!(cache
                .get(&mid.to_string(), MOBILECLIP_S2_MODEL_VERSION)
                .unwrap()
                .is_some());
            // Per-frame rows land for at least frames 0..2.
            for frame_idx in 0..2u32 {
                let key = format!("{}_frame_{}", MOBILECLIP_S2_MODEL_VERSION, frame_idx);
                assert!(
                    cache.get(&mid.to_string(), &key).unwrap().is_some(),
                    "keyframe {frame_idx} embedding missing"
                );
            }
        });
    }

    #[test]
    fn send_media_skips_keyframe_extraction_for_non_video_mime() {
        use crate::models::clip::{MockImageEmbedder, MOBILECLIP_S2_MODEL_VERSION};
        use crate::models::embeddings::{EmbeddingCache, LocalStoreEmbeddingCache};
        use crate::models::video::MockVideoKeyframeSampler;

        let core = fresh_core();
        core.install_image_embedder(Box::new(MockImageEmbedder::default()))
            .unwrap();
        core.install_video_keyframe_sampler(Box::new(MockVideoKeyframeSampler))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        core.with_db(|db| {
            let cache = LocalStoreEmbeddingCache::new(db.connection());
            // No frame_0 row written for non-video media.
            let frame_key = format!("{}_frame_0", MOBILECLIP_S2_MODEL_VERSION);
            assert!(cache.get(&mid.to_string(), &frame_key).unwrap().is_none());
        });
    }

    #[test]
    fn send_media_skips_keyframe_extraction_when_no_sampler() {
        use crate::models::clip::{MockImageEmbedder, MOBILECLIP_S2_MODEL_VERSION};
        use crate::models::embeddings::{EmbeddingCache, LocalStoreEmbeddingCache};

        let core = fresh_core();
        core.install_image_embedder(Box::new(MockImageEmbedder::default()))
            .unwrap();
        // Note: no sampler installed.

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, b"video-bytes".to_vec(), "video/mp4", None)
            .expect("send_media");

        core.with_db(|db| {
            let cache = LocalStoreEmbeddingCache::new(db.connection());
            let frame_key = format!("{}_frame_0", MOBILECLIP_S2_MODEL_VERSION);
            assert!(cache.get(&mid.to_string(), &frame_key).unwrap().is_none());
        });
    }

    #[test]
    fn send_media_transcribes_voice_message_when_transcriber_installed() {
        use crate::models::whisper::MockWhisperTranscriber;

        let core = fresh_core();
        core.install_whisper_transcriber(Box::new(MockWhisperTranscriber))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        let res = core
            .send_media(conv, mid, b"voice-msg".to_vec(), "audio/wav", None)
            .expect("send_media");

        // Legacy media_search_index row is present.
        core.with_db(|db| {
            let rows: Vec<(String, String)> = db
                .connection()
                .prepare("SELECT kind, text FROM media_search_index WHERE asset_id = ?1")
                .unwrap()
                .query_map([res.asset_id.to_string()], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            assert!(rows.iter().any(|(k, _)| k == "transcript"));
        });
    }

    #[test]
    fn send_media_indexes_transcript_into_fts_and_fuzzy() {
        use crate::models::whisper::{MockWhisperTranscriber, WhisperTranscriber};
        use crate::search::fuzzy_search::FuzzySearchEngine;

        let core = fresh_core();
        core.install_whisper_transcriber(Box::new(MockWhisperTranscriber))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(conv, mid, b"voice-msg".to_vec(), "audio/wav", None)
            .expect("send_media");

        core.with_db(|db| {
            // FTS row keyed by the audio message_id is present.
            let fts_count: i64 = db
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM search_fts WHERE message_id = ?1",
                    [mid.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(fts_count >= 1, "transcript should land in search_fts");

            // Fuzzy index has at least one row keyed by message_id.
            let mock_text = MockWhisperTranscriber
                .transcribe(b"voice-msg", "audio/wav")
                .unwrap()
                .text;
            // Pull the first stem from the mock transcript so
            // we exercise the fuzzy lookup path with a real
            // token. Mock transcripts always start with
            // `"mock transcription"`.
            let probe = mock_text.split_whitespace().next().unwrap_or("mock");
            let fuzzy = FuzzySearchEngine::new(db);
            let hits = fuzzy.search_fuzzy(probe, 16).unwrap();
            assert!(
                hits.iter().any(|h| h.message_id == mid.to_string()),
                "transcript should land in search_fuzzy"
            );
        });
    }

    #[test]
    fn send_media_skips_transcription_for_non_audio_mime() {
        use crate::models::whisper::MockWhisperTranscriber;

        let core = fresh_core();
        core.install_whisper_transcriber(Box::new(MockWhisperTranscriber))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        let res = core
            .send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        core.with_db(|db| {
            let count: i64 = db
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM media_search_index
                     WHERE asset_id = ?1 AND kind = 'transcript'",
                    [res.asset_id.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "no transcript should be written for image media");
        });
    }

    #[test]
    fn send_media_skips_transcription_when_resource_gate_blocks() {
        use crate::models::resource_gate::{
            DeviceResources, NetworkType, ResourceProbe, ThermalState,
        };
        use crate::models::whisper::MockWhisperTranscriber;

        // A probe that reports critical thermal — every gate
        // refuses, including `should_run_transcription`.
        #[derive(Debug)]
        struct CriticalProbe;
        impl ResourceProbe for CriticalProbe {
            fn current_resources(&self) -> DeviceResources {
                DeviceResources {
                    battery_level: 1.0,
                    is_charging: true,
                    thermal_state: ThermalState::Critical,
                    network_type: NetworkType::WiFi,
                }
            }
        }

        let core = fresh_core();
        core.install_whisper_transcriber(Box::new(MockWhisperTranscriber))
            .unwrap();
        core.install_resource_probe(std::sync::Arc::new(CriticalProbe))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        let res = core
            .send_media(conv, mid, b"voice-msg".to_vec(), "audio/wav", None)
            .expect("send_media");

        core.with_db(|db| {
            let count: i64 = db
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM media_search_index
                     WHERE asset_id = ?1 AND kind = 'transcript'",
                    [res.asset_id.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "transcription should be gated off");
        });
    }

    #[test]
    fn send_media_extracts_document_text_when_extractor_installed() {
        use crate::models::document::MockDocumentExtractor;

        let core = fresh_core();
        core.install_document_extractor(Box::new(MockDocumentExtractor::default()))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        let res = core
            .send_media(
                conv,
                mid,
                b"%PDF-1.7 fake pdf bytes".to_vec(),
                "application/pdf",
                None,
            )
            .expect("send_media");

        core.with_db(|db| {
            let count: i64 = db
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM media_search_index
                     WHERE asset_id = ?1 AND kind = 'caption'",
                    [res.asset_id.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                count >= 1,
                "extractor should write at least one caption row"
            );
        });
    }

    #[test]
    fn send_media_indexes_document_pages_into_fts() {
        use crate::models::document::MockDocumentExtractor;

        let core = fresh_core();
        core.install_document_extractor(Box::new(MockDocumentExtractor::default()))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        core.send_media(
            conv,
            mid,
            b"%PDF-1.7 fake pdf bytes".to_vec(),
            "application/pdf",
            None,
        )
        .expect("send_media");

        core.with_db(|db| {
            // Each page lands as a synthetic
            // `{message_id}#page{N}` FTS row. Check at least
            // one `#page1` row exists.
            let count: i64 = db
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM search_fts
                     WHERE message_id LIKE ?1",
                    [format!("{}#page%", mid)],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(count >= 1, "page-level FTS rows missing");
        });
    }

    #[test]
    fn send_media_skips_extraction_for_non_document_mime() {
        use crate::models::document::MockDocumentExtractor;

        let core = fresh_core();
        core.install_document_extractor(Box::new(MockDocumentExtractor::default()))
            .unwrap();

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();

        let res = core
            .send_media(conv, mid, fake_image_bytes(), "image/png", None)
            .expect("send_media");

        core.with_db(|db| {
            let count: i64 = db
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM media_search_index
                     WHERE asset_id = ?1 AND kind = 'caption'",
                    [res.asset_id.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "no caption rows for image-only media");
        });
    }

    // ----------------------------------------------------------------
    // Phase 7, Task 8 (2026-05-04 batch) — perf-collector wiring
    // tests. The unit-level coverage of `PerfTrace` /
    // `InMemoryPerfCollector` lives in `crate::perf`. These two
    // tests pin the *integration* contract: an installed
    // collector sees the spans emitted by the `ingest_messages`
    // and `search` hot paths.
    // ----------------------------------------------------------------

    #[test]
    fn perf_collector_records_ingest_trace() {
        use crate::message::processor::IngestedMessage;
        use crate::perf::InMemoryPerfCollector;

        let core = fresh_core();
        let collector = std::sync::Arc::new(InMemoryPerfCollector::new());
        core.install_perf_collector(collector.clone())
            .expect("install perf collector");
        assert!(core.has_perf_collector());

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let now = now_ms_for_send_media();
        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "perf-alice".into(),
            created_at_ms: now,
            text_content: Some("perf trace ingest".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };
        core.ingest_messages(&[msg]).expect("ingest");

        let traces = core.collect_perf_stats();
        let ingest = traces
            .iter()
            .find(|t| t.operation == "ingest_messages")
            .expect("ingest_messages trace recorded");
        assert!(
            ingest.end_ns >= ingest.start_ns,
            "trace must close (start={}, end={})",
            ingest.start_ns,
            ingest.end_ns,
        );
        assert_eq!(
            ingest.metadata.get("messages_in").map(String::as_str),
            Some("1"),
            "metadata must record input batch size",
        );
        assert_eq!(
            ingest.metadata.get("new_messages").map(String::as_str),
            Some("1"),
            "metadata must record successful inserts",
        );
    }

    #[test]
    fn perf_collector_records_search_trace() {
        use crate::message::processor::IngestedMessage;
        use crate::perf::InMemoryPerfCollector;

        let core = fresh_core();
        let collector = std::sync::Arc::new(InMemoryPerfCollector::new());
        core.install_perf_collector(collector.clone())
            .expect("install perf collector");

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let now = now_ms_for_send_media();
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "perf-bob".into(),
            created_at_ms: now,
            text_content: Some("perf trace search".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };
        core.ingest_messages(&[msg]).expect("ingest");

        let q = SearchQuery {
            query_string: "perf trace".into(),
            ..Default::default()
        };
        let _hits = core.search(q, SearchScope::LocalOnly).expect("search");

        let traces = core.collect_perf_stats();
        let search = traces
            .iter()
            .find(|t| t.operation == "search")
            .expect("search trace recorded");
        assert!(
            search.end_ns >= search.start_ns,
            "search trace must close (start={}, end={})",
            search.start_ns,
            search.end_ns,
        );
        assert_eq!(
            search.metadata.get("scope").map(String::as_str),
            Some("local_only"),
            "scope metadata must be local_only",
        );
        assert!(
            search.metadata.contains_key("result_count"),
            "search trace must record result_count metadata",
        );
    }

    // ----------------------------------------------------------------
    // Phase 7 (2026-05-04 batch 10) — Task 7 perf-dashboard tests.
    // ----------------------------------------------------------------

    #[test]
    fn core_impl_hydrate_message_emits_perf_trace() {
        use crate::message::processor::IngestedMessage;
        use crate::perf::InMemoryPerfCollector;

        let core = fresh_core();
        let collector = std::sync::Arc::new(InMemoryPerfCollector::new());
        core.install_perf_collector(collector.clone())
            .expect("install perf collector");

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let mid = Uuid::now_v7();
        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: "perf-carol".into(),
            created_at_ms: now_ms_for_send_media(),
            text_content: Some("perf trace hydrate".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };
        core.ingest_messages(&[msg]).expect("ingest");
        let _ = core
            .hydrate_message(mid, "row_visible")
            .expect("hydrate ok");

        let traces = core.collect_perf_stats();
        let hydrate = traces
            .iter()
            .find(|t| t.operation == "hydrate_message")
            .expect("hydrate_message trace recorded");
        assert!(hydrate.end_ns >= hydrate.start_ns);
        assert_eq!(
            hydrate.metadata.get("reason").map(String::as_str),
            Some("row_visible")
        );
    }

    #[test]
    fn core_impl_backup_emits_perf_trace() {
        use crate::perf::InMemoryPerfCollector;

        let core = fresh_core();
        let collector = std::sync::Arc::new(InMemoryPerfCollector::new());
        core.install_perf_collector(collector.clone())
            .expect("install perf collector");

        let _ = core.run_incremental_backup("test-backup");

        let traces = core.collect_perf_stats();
        let backup = traces
            .iter()
            .find(|t| t.operation == "run_incremental_backup")
            .expect("run_incremental_backup trace recorded");
        assert!(backup.end_ns >= backup.start_ns);
        assert_eq!(
            backup.metadata.get("reason").map(String::as_str),
            Some("test-backup")
        );
    }

    #[test]
    fn core_impl_get_perf_summary_returns_data() {
        use crate::message::processor::IngestedMessage;
        use crate::perf::InMemoryPerfCollector;

        let core = fresh_core();
        let collector = std::sync::Arc::new(InMemoryPerfCollector::new());
        core.install_perf_collector(collector.clone())
            .expect("install perf collector");

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        for i in 0..3 {
            let msg = IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: format!("perf-bench-{i}"),
                created_at_ms: now_ms_for_send_media(),
                text_content: Some(format!("hello {i}")),
                media_descriptors: Vec::new(),
                reply_to: None,
            };
            core.ingest_messages(&[msg]).expect("ingest");
        }

        let summaries = core.get_perf_summary();
        assert!(!summaries.is_empty());
        let ingest = summaries
            .iter()
            .find(|s| s.operation == "ingest_messages")
            .expect("ingest summary present");
        assert!(ingest.count >= 3);
        assert!(ingest.p95_ns >= ingest.p50_ns);
        assert!(ingest.p99_ns >= ingest.p95_ns);
    }

    #[test]
    fn core_impl_check_perf_budgets_detects_violations() {
        use crate::message::processor::IngestedMessage;
        use crate::perf::{InMemoryPerfCollector, PerfBudget};

        let core = fresh_core();
        let collector = std::sync::Arc::new(InMemoryPerfCollector::new());
        core.install_perf_collector(collector.clone())
            .expect("install perf collector");

        let conv = Uuid::now_v7();
        seed_conversation(&core, &conv);
        let msg = IngestedMessage {
            message_id: Uuid::now_v7(),
            conversation_id: conv,
            sender_id: "perf-budget".into(),
            created_at_ms: now_ms_for_send_media(),
            text_content: Some("hello".into()),
            media_descriptors: Vec::new(),
            reply_to: None,
        };
        core.ingest_messages(&[msg]).expect("ingest");

        // 1ns budget — guaranteed violation. Whatever the
        // ingest path measured will exceed it.
        let budgets = vec![PerfBudget {
            operation: "ingest_messages".into(),
            p95_budget_ns: 1,
        }];
        let violations = core.check_perf_budgets(&budgets);
        assert!(!violations.is_empty());

        // Generous budget — no violation expected.
        let budgets = vec![PerfBudget {
            operation: "ingest_messages".into(),
            p95_budget_ns: u64::MAX,
        }];
        let violations = core.check_perf_budgets(&budgets);
        assert!(violations.is_empty());
    }

    // ----------------------------------------------------------------
    // Phase 7 (2026-05-04 batch 10) — Task 9 media-migration
    // scheduling tests.
    // ----------------------------------------------------------------

    #[test]
    fn schedule_media_migration_returns_false_for_empty_plan() {
        let core = fresh_core();
        let scheduler = Box::new(crate::scheduler::InProcessScheduler::new());
        core.install_scheduler(scheduler)
            .expect("install scheduler");

        let plan = crate::media::migration::MediaMigrationPlan {
            source_sink: "local".into(),
            target_sink: "user-cloud".into(),
            items: Vec::new(),
        };
        let scheduled = core
            .schedule_media_migration(
                &plan,
                crate::scheduler::TaskConstraints::wifi_and_charging(),
            )
            .expect("schedule");
        assert!(!scheduled);
    }

    #[test]
    fn schedule_media_migration_without_scheduler_errors() {
        let core = fresh_core();
        let plan = crate::media::migration::MediaMigrationPlan {
            source_sink: "local".into(),
            target_sink: "user-cloud".into(),
            items: vec![crate::media::migration::MediaMigrationItem {
                asset_id: "asset-1".into(),
                blob_id: "blob-1".into(),
                chunk_count: 1,
                merkle_root: [0u8; 32],
                sink_metadata: None,
            }],
        };
        let err = core
            .schedule_media_migration(
                &plan,
                crate::scheduler::TaskConstraints::wifi_and_charging(),
            )
            .expect_err("must error without scheduler");
        match err {
            Error::NotImplemented(tag) => assert_eq!(tag, "scheduler"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn schedule_media_migration_enqueues_into_in_process_scheduler() {
        use std::sync::Arc;

        let core = fresh_core();
        let scheduler = Arc::new(crate::scheduler::InProcessScheduler::new());

        // Wrap the Arc in a thin Box that delegates to the
        // shared instance so we can keep a side channel for
        // observing the queue.
        #[derive(Debug)]
        struct SharedScheduler(Arc<crate::scheduler::InProcessScheduler>);
        impl crate::scheduler::BackgroundScheduler for SharedScheduler {
            fn schedule_backup(&self, ms: u64) -> std::result::Result<(), Error> {
                self.0.schedule_backup(ms)
            }
            fn schedule_archive_compaction(&self, ms: u64) -> std::result::Result<(), Error> {
                self.0.schedule_archive_compaction(ms)
            }
            fn schedule_index_maintenance(&self, ms: u64) -> std::result::Result<(), Error> {
                self.0.schedule_index_maintenance(ms)
            }
            fn cancel_all(&self) -> std::result::Result<(), Error> {
                self.0.cancel_all()
            }
            fn is_task_pending(&self, id: &str) -> std::result::Result<bool, Error> {
                self.0.is_task_pending(id)
            }
            fn schedule_one_off_task(
                &self,
                task: crate::scheduler::OneOffTask,
                c: crate::scheduler::TaskConstraints,
            ) -> std::result::Result<(), Error> {
                self.0.schedule_one_off_task(task, c)
            }
        }

        let shared = SharedScheduler(scheduler.clone());
        core.install_scheduler(Box::new(shared))
            .expect("install scheduler");

        let plan = crate::media::migration::MediaMigrationPlan {
            source_sink: "local".into(),
            target_sink: "user-cloud".into(),
            items: vec![crate::media::migration::MediaMigrationItem {
                asset_id: "asset-1".into(),
                blob_id: "blob-1".into(),
                chunk_count: 1,
                merkle_root: [0u8; 32],
                sink_metadata: None,
            }],
        };
        let scheduled = core
            .schedule_media_migration(
                &plan,
                crate::scheduler::TaskConstraints::wifi_and_charging(),
            )
            .expect("schedule");
        assert!(scheduled);
        assert_eq!(scheduler.pending_one_off_count(), 1);
    }

    #[test]
    fn record_dedup_event_with_no_probe_is_noop() {
        let core = fresh_core();
        // No probe installed → record_dedup_event must not error.
        core.record_dedup_event(
            crate::transport::dedup_analytics::DedupEvent::ObjectUploaded {
                size_bytes: 10,
                was_deduped: false,
            },
        )
        .expect("noop without probe");
    }

    #[test]
    fn get_dedup_dashboard_aggregates_stats_and_events() {
        let core = fresh_core();
        let probe =
            std::sync::Arc::new(crate::transport::dedup_analytics::InProcessDedupAnalytics::new());
        core.install_dedup_analytics(probe).expect("install probe");

        for size in [100, 100, 100] {
            core.record_dedup_event(
                crate::transport::dedup_analytics::DedupEvent::ObjectUploaded {
                    size_bytes: size,
                    was_deduped: false,
                },
            )
            .unwrap();
        }
        core.record_dedup_event(
            crate::transport::dedup_analytics::DedupEvent::ObjectUploaded {
                size_bytes: 100,
                was_deduped: true,
            },
        )
        .unwrap();

        let dashboard = core.get_dedup_dashboard("tenant-test").unwrap();
        assert_eq!(dashboard.stats.total_objects, 4);
        assert_eq!(dashboard.stats.unique_objects, 3);
        assert_eq!(dashboard.savings.bytes_saved, 100);
        assert_eq!(dashboard.recent_events.len(), 4);
    }

    #[test]
    fn get_dedup_dashboard_without_probe_errors() {
        let core = fresh_core();
        let err = core.get_dedup_dashboard("tenant-test").unwrap_err();
        match err {
            Error::NotImplemented(tag) => assert_eq!(tag, "dedup_analytics"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn enforce_storage_budget_skips_migration_when_not_configured() {
        let core = fresh_core();
        let scheduler = Box::new(crate::scheduler::InProcessScheduler::new());
        core.install_scheduler(scheduler)
            .expect("install scheduler");

        let collector = std::sync::Arc::new(crate::perf::InMemoryPerfCollector::new());
        core.install_perf_collector(collector.clone())
            .expect("install perf collector");

        // No `auto_migrate_after_eviction` configured → eviction
        // path must not error and must not emit a
        // `migration_scheduled` perf-trace metadata key.
        let result = core.enforce_storage_budget("test");
        assert!(result.is_ok());
        let traces = core.collect_perf_stats();
        let evict = traces
            .iter()
            .find(|t| t.operation == "enforce_storage_budget")
            .expect("eviction trace");
        assert!(!evict.metadata.contains_key("migration_scheduled"));
    }
}
