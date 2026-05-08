# KChat Storage & Search — Rust Core

> A Rust core library with platform-specific bindings (iOS via UniFFI/Swift,
> Android via JNI/Kotlin, desktop via native Rust) providing E2EE local
> storage, personal archive, backup, offload, rehydration, and rich
> multilingual search for KChat.

**License**: Proprietary — All Rights Reserved. See [LICENSE](LICENSE).

> Status: **Phase 0 — `COMPLETE`.** **Phase 1 — Local Store + Text
> Search + MLS Integration — `In progress | ~96%`.** **Phase 2 —
> Media Encryption and Blob Service — `In progress | ~98%` (chunked
> media pipeline + thumbnailing landed; tiered media-storage routing
> wired through `MediaBlobSink`).**
> **Phase 3 — Personal Archive and Offload — `In progress | ~99%`
> (foundation: archive event journal wired into `MessagePersister`,
> archive segment builder, archive manifest chain builder, archive
> segment upload orchestration, archive state machine transitions,
> epoch-rotated archive keys with full lifecycle (`EpochKeyManager`),
> offload budget / scoring / eviction with pressure-tier filter +
> pinned-chat exclusion / hydration priority queue wired into
> `CoreImpl::hydrate_message` (timeline-skeleton rehydration without
> scroll-jump + lazy media rehydration on tap), batch-by-bucket
> prefetch with optional dummy request padding, archive backend
> routing (KChat backend / ZK Object Fabric), all three
> `MediaBlobSink` slots scaffolded (ZK Object Fabric S3-compatible
> sink, iCloud `CloudKit` bridge, Google Drive bridge), tiered
> eviction policy (cloud-offload first → full eviction),
> `CoreImpl::enforce_storage_budget`).**
> **Phase 4 — Backup and Restore — `In progress | ~90%`
> (full Rust backup + restore foundation: typed
> `BackupEventJournal`, CBOR + zstd + XChaCha20-Poly1305 segment
> builder under `K_backup_segment`, Ed25519-signed
> generation-chained manifest builder under `K_backup_manifest`
> with `device_id` AAD attribution, daily → weekly → monthly
> compaction policy with tombstone application, manifest chain
> verifier with structured failure modes, restore state machine
> persistence helpers, the skeleton-first restore pipeline
> wired through `CoreImpl::restore_from_backup` to terminal
> `FullRestoreComplete`, end-to-end
> `CoreImpl::run_incremental_backup` and
> `CoreImpl::compact_backup`, the `BackupSink` trait + ZK Object
> Fabric backup sink with Pattern C convergent encryption,
> encrypted search-index shard build/restore, archive
> compaction orchestration (`CoreImpl::compact_archive`), and
> the recovery-key + device-to-device transfer foundation in
> `restore::key_recovery`, the iCloud (`ICloudBackupSink`) and
> Android (`AndroidBackupSink`) backup sinks, the ZKOF
> archive-backend wiring (`ZkofArchiveAdapter` over
> `Arc<dyn S3Client>`), the search-index shard restore wired into
> `RestorePipeline::restore_search_index_shards_with_replay`, and
> passphrase-based key recovery in `restore::key_recovery`
> (Argon2id + AES-256-KW + serde envelope) including the
> `DeviceTransferEnvelope` zeroize fix).**
> **Phase 5 — Search (Fuzzy + Encrypted Shards) —
> `In progress | ~98%`** (cold-bucket fan-out: a
> `ColdShardSource` trait (`search::query_engine`) resolves cold
> `(conversation_id, time_bucket)` pairs and decrypts shards via
> `search::shard_builder::{restore_text_search_shard,
> restore_fuzzy_search_shard}`;
> `QueryEngine::execute_search_with_cold_source` merges cold +
> local hits, marks `is_cold = true`, and reranks under the
> shared formula. Concrete `TransportColdShardSource` adapter at
> `search::cold_shard_source` bridges `TransportClient` +
> `ShardKeyRegistry` into the trait, with a `GracefulCold`
> wrapper for transport-error degradation. Encrypted shard
> *upload* pipeline lives at `CoreImpl::upload_search_shards`
> (build → seal → CBOR → `TransportClient::upload_index_shard`
> → `UploadedSearchShards` receipt with per-shard
> `(shard_id, doc_count, ciphertext_sha256)`); the
> incremental-backup wrapper
> `CoreImpl::run_incremental_backup_with_search_shards` chains
> the upload onto every backup so shards stay in lock-step with
> the segments that produced them. The on-device fetch /
> decrypt / restore counterpart is
> `CoreImpl::fetch_and_restore_cold_shards` (calls
> `search::shard_prefetch::batch_prefetch_shards`, AEAD-opens
> each prefetched shard under the appropriate
> `K_search_root` per-shard key, and replays through
> `restore_text_search_shard` / `restore_fuzzy_search_shard`).
> The cold-result hydration write-back path is closed by
> `CoreImpl::hydrate_cold_search_results`: cold hits are
> resolved to their archive segments, AEAD-opened under the
> bucket's epoch key, and the body is written back via
> `LocalStoreDb::rehydrate_message_body` so `body_state`
> flips from `remote_archive_only` to `local_plain_available`
> and the message is re-indexed into both `search_fts` and
> `search_fuzzy`. Script-aware fuzzy matching with per-script
> overlap floors (`search::tokenizer::fuzzy_min_overlap`),
> mixed-language fan-out via `segment_by_script`, full ranking
> formula (`BM25_WEIGHT × FUZZY_WEIGHT × RECENCY_WEIGHT ×
> CONTENT_KIND_WEIGHTS` with a 30-day half-life recency decay),
> batch-by-bucket `search::shard_prefetch::batch_prefetch_shards`
> over all four `IndexType` variants in deterministic
> `[Text, Fuzzy, Vector, Media]` order, padding variant for
> `privacy_level = High`, criterion benchmarks at
> `crates/core/benches/phase5_benchmarks.rs` plus the CI p95
> latency gate at
> `tests/phase5_latency_smoke.rs::phase5_cold_shard_p95_latency_under_1_5s_budget`
> (asserts the end-to-end shard fetch + AEAD decrypt + FTS5 /
> fuzzy search across a 1 000-message multilingual one-month
> bucket stays under the **1.5 s** Phase-5 budget at p95). The
> on-device device-matrix p95 ≤ 1.5 s gate is queued for the
> Phase-5 device-matrix run.)
> **Phase 6 — Media and Semantic Search — `In progress | ~95%`**
> (ONNX Runtime session lifecycle in
> `crates/core/src/models/embeddings_onnx.rs`; XLM-R inference
> seam — `TextEmbedder` trait + `NoopTextEmbedder` /
> `MockTextEmbedder` in `crates/core/src/models/embeddings.rs`,
> wired into `CoreImpl::ingest_messages` via the best-effort
> `maybe_embed_text_message` that lands the vector in the shared
> `LocalStoreEmbeddingCache` keyed `(message_id, "xlmr@v1")`;
> MobileCLIP-S2 inference seam — `ImageEmbedder` /
> `NoopImageEmbedder` / `MockImageEmbedder` in
> `crates/core/src/models/clip.rs`, wired through
> `CoreImpl::send_media` and gated on
> `mime_type.starts_with("image/")` plus the cross-pipeline cache
> key `(message_id, "mobileclip_s2@v1")`; **Whisper transcription
> seam** — `WhisperTranscriber` / `NoopWhisperTranscriber` /
> `MockWhisperTranscriber` in
> `crates/core/src/models/whisper.rs`, wired into
> `CoreImpl::send_media` so audio MIME types land in
> `media_search_index` with `kind = "transcript"`;
> **document text extraction seam** — `DocumentExtractor` /
> `NoopDocumentExtractor` / `MockDocumentExtractor` in
> `crates/core/src/models/document.rs`, wired into
> `CoreImpl::send_media` so PDF / DOCX MIME types fan each page
> into `media_search_index` with `kind = "caption"`;
> **video keyframe sampling seam** — `VideoKeyframeSampler` /
> `NoopVideoKeyframeSampler` / `MockVideoKeyframeSampler` in
> `crates/core/src/models/video.rs`, wired into
> `CoreImpl::send_media` so video MIME types embed up to five
> sampled keyframes through MobileCLIP-S2 and write the first
> frame to `search_vector`; brute-force semantic search engine
> over the per-conversation `search_vector` corpus
> (`crates/core/src/search/semantic_search.rs`); **on-device
> reranker with raw `semantic_score`** —
> `SearchResult.semantic_score: Option<f64>` carries raw cosine
> similarity, `QueryEngine::rerank_with_semantic` re-sorts a
> result set under `SEMANTIC_WEIGHT = 1.5` (between BM25 / fuzzy
> contributions, merged in
> `QueryEngine::execute_search_with_semantic`); OCR bridge —
> `OcrBridge` trait + `NoopOcrBridge` in
> `crates/core/src/models/ocr.rs` plus
> `LocalStoreDb::insert_media_search_index` /
> `search_media_index` storage helpers; resource-gated background
> processing — `ResourceGate` / `ResourcePolicy` /
> `ResourceProbe` in `crates/core/src/models/resource_gate.rs`;
> model manager — `ModelManager` / `ModelDownloader` /
> `Quantization` in `crates/core/src/models/model_manager.rs`,
> with **INT4 quantization selection** (`select_quantization`
> returns `Int4` whenever `available_storage_bytes <
> TIGHT_STORAGE_THRESHOLD_BYTES = 512 MiB`),
> `ModelArtifactSpec` constants for the four expected artifacts
> (XLMR / MobileCLIP × INT8 / INT4), and INT4 ONNX session
> helpers behind `#[cfg(feature = "onnx-runtime")]`; encrypted
> vector and media shards through
> `crates/core/src/search/shard_builder.rs::{build,restore}_{vector,media}_search_shard`
> with new key-derivation helpers
> `crypto::key_hierarchy::derive_{vector,media}_index_shard`;
> cross-pipeline embedding cache — `EmbeddingCache` trait +
> `LocalStoreEmbeddingCache` plus the dedicated integration test
> at `crates/core/tests/phase6_embedding_cache.rs` that asserts
> put / get cosine fidelity > 0.999, version-mismatch → `None`,
> and two-instance same-connection cross-pipeline visibility.
> Items still open: real platform-bridge attach for Whisper /
> MobileCLIP / XLM-R sessions, desktop EP tuning, and the
> INT4-vs-INT8 multilingual relevance benchmark.)
> **Phase 7 — Desktop + Optimization — `In progress | ~85%`**
> (production-scale archive compaction via
> `CoreImpl::compact_archive` with cross-epoch decrypt
> coverage; **all 14 of 14** failure scenarios passing in
> `tests/failure_scenarios.rs` — chunk upload interrupted then
> resumed, SHA-256 fast-fail on tampered ciphertext, tampered
> descriptor `merkle_root`, wrong `K_backup_segment`, wrong
> manifest signing key, manifest chain break with expected /
> actual hashes (plus deepest-link variant), MLS-removed
> device, missing search shard graceful degrade, low-storage
> resumable error during restore, manifest upload interrupted
> mid-write retries without chain break. **Offline edge-case
> handling** — `OfflineDetector` trait,
> `NoopOfflineDetector`, `AlwaysOfflineDetector`,
> `ToggleOfflineDetector` in
> `crates/core/src/transport/offline.rs`; wired into `CoreImpl`
> via `install_offline_detector` / `is_online`.
> `run_incremental_backup` short-circuits with
> `BackupResult.deferred = true` while offline;
> `hydrate_message` returns `is_cold = true` + `offline = true`
> when the body is remote-archive-only and the device is
> offline. **Performance profiling scaffold** — `PerfTrace` +
> `PerfCollector` trait + `NoopPerfCollector` +
> `InMemoryPerfCollector` in `crates/core/src/perf.rs`; wired
> into `CoreImpl` via `install_perf_collector` /
> `has_perf_collector` / `collect_perf_stats`. Hot paths
> `ingest_messages`, `search`, and `enforce_storage_budget`
> emit traces with operation-specific metadata. **Large-scale
> integration scaffold** — `crates/core/tests/large_scale.rs`
> with three `#[ignore]` stress tests (10k multilingual ingest;
> 5k media-asset eviction at Critical pressure; 1k message
> backup → manifest-chain → restore round-trip; run with
> `cargo test --test large_scale -- --ignored`); a Phase-7
> 100 k multilingual stress test
> (`crates/core/tests/large_scale_test.rs`) covering 100+
> conversations, 11 scripts, 10k+ media messages, every
> storage-budget pressure level, full backup-restore manifest
> chain, and a p95-latency assertion against the Phase-1
> < 150 ms budget — also `#[ignore]`-marked, run with
> `cargo test --test large_scale_test -- --ignored`; and the
> first **macOS / Windows native integration scaffolds**
> (`crates/desktop/src/{macos,windows}.rs`) defining
> `SpotlightBridge` / `WindowsSearchBridge` (object-safe
> message indexers) + `MacOsSchedulerBridge` /
> `WindowsSchedulerBridge` (implementing the existing
> `BackgroundScheduler` trait for `NSBackgroundActivityScheduler`
> and Windows Task Scheduler) + `WindowsMlConfig` (CPU-only
> contract; DirectML EP best-effort, INT4 default for tight
> storage). **2026-05-04 batch-5**: the `crates/desktop/`
> trait scaffold (`SpotlightAnchor`, `WindowsSearchAnchor`,
> `DesktopScheduler`, `DesktopMlEpSelector`); cross-platform
> media migration (`crates/core/src/media/migration.rs`
> with `MediaMigrationPlan`, `plan_media_migration`,
> `execute_media_migration`, `MigrationProgress`); the
> 10 000-asset stress test
> (`crates/core/tests/media_sink_stress.rs`); the
> `ExecutionProviderSelector` ML-EP scaffold
> (`crates/core/src/models/ep_tuning.rs`); the
> `InProcessScheduler` Rust-native scheduler
> (`crates/core/src/scheduler/in_process.rs`); the
> read-only `DedupAnalytics` integration
> (`crates/core/src/transport/dedup_analytics.rs`); and four
> additional `#[ignore]` large-scale tests (100 k messages,
> 10 k media, 50 k archive compaction, concurrent
> writer / reader). Real platform-bridge attach (DirectML EP,
> Spotlight indexing, `NSBackgroundActivityScheduler` callback)
> remains.)
> **Phase 8 — Multi-Scope, Multi-Tenant Search — `In progress | ~98%`**
> (Phase 8 batch 6 lands ten tasks: bucket-level date pruning
> (`bucket_overlaps_date_range`), bloom-filter pre-check in the
> cold fan-out (`ColdShardSource::fetch_bloom_shard`), an
> on-device decrypted LRU shard cache
> (`crates/core/src/search/shard_cache.rs`, default 50 MB,
> mounted on `CoreImpl` via `install_shard_cache`), per-tenant
> B2B key derivation
> (`derive_b2b_tenant_root` / `derive_b2b_archive_epoch` /
> `derive_b2b_text_index_shard`), `TenantSearchPolicy` config +
> enforcement (`allow_global_search`,
> `allow_cross_tenant_results`,
> `max_cold_buckets_per_search`,
> `require_bloom_shards`), privacy-aware
> scope-proportional padding
> (`compute_scope_padding_multiplier`,
> `batch_prefetch_shards_with_padding_for_target`), background
> shard warming
> (`shard_cache::warm_shard_cache` +
> `ResourceGate::should_warm_shards` +
> `TaskType::ShardCacheWarming`), Android / iOS bridge surface
> (`KChatBridgeHandle::search_with_target` + UDL `SearchTarget`
> enum + optional `target` field), Phase 8 latency benchmarks
> (`crates/core/benches/phase8_benchmarks.rs`), and Phase 8
> integration tests
> (`crates/core/tests/phase8_multi_scope_search.rs`).
> **Parallel bucket fetch + streaming search** (this batch):
> `KChatCoreConfig::max_cold_fetch_concurrency` (default 4)
> plus `execute_search_with_cold_source_full_parallel` use
> `std::thread::scope` to fan cold-bucket fetches over a
> bounded thread pool with fail-open per-bucket error
> handling. `SearchEvent::{LocalResults,
> ColdBucketComplete, SearchComplete}` plus
> `execute_search_streaming` / `CoreImpl::search_streaming`
> emit events as each cold bucket completes, exposed
> through iOS / Android `SearchEventListener` callback
> interfaces.)
>
> (Phase 8 schema foundation: `conversation` table now carries
> `conversation_type` (`dm` / `group` / `channel`), `scope`
> (`b2c` / `b2b`), `tenant_id`, `community_id`, `domain_id`
> columns + matching `idx_conv_community` /
> `idx_conv_domain` / `idx_conv_tenant` / `idx_conv_scope`
> indexes; `archive_segment_map` carries `tenant_id` +
> `idx_asm_tenant_bucket(tenant_id, time_bucket)`. `SearchTarget`
> enum (`Conversation(Uuid)` / `Community(Uuid)` /
> `Domain(Uuid)` / `Tenant(String)` / `B2cAll` / `Global`) on
> `SearchQuery` with `effective_target()` mapping the legacy
> `conversation_filter` to `SearchTarget::Conversation`. Scope
> resolver `query_engine::resolve_target_to_conversation_set` +
> `push_target_filter` wired into both `execute_structured_only`
> and `allowed_skeleton_ids` — empty resolution emits a
> `1=0` SQL clause (fail-closed). **Bloom filter shard type**:
> `IndexType::Bloom` on the wire; `BloomFilter` /
> `build_bloom_shard` / `restore_bloom_shard` /
> `BloomShardPayload` in `crates/core/src/search/shard_builder.rs`,
> sealed under
> `crypto::key_hierarchy::derive_bloom_index_shard` (info
> string `kchat-bloom-index-shard-v1`). The deterministic
> shard prefetch order is now
> `[Bloom, Text, Fuzzy, Vector, Media]` so the bloom shard is
> fetched first and lets the prefetcher skip buckets whose
> filter rejects every query token before paying for the
> larger payloads. Items still open: bloom-filter pre-check in
> the cold fan-out path, on-device decrypted shard cache,
> parallel bucket fetch, per-tenant B2B key isolation, and
> `TenantSearchPolicy` enforcement.)
>
> Landed in Phase 0: Rust workspace scaffold, crypto module (BLAKE3,
> HKDF-SHA256 hierarchy, XChaCha20-Poly1305 / AES-256-GCM AEAD,
> Pattern C convergent encryption with bit-identical Go SDK interop,
> AES-256-KW key wrap), CBOR wire formats
> (`formats::{BackupSegmentFrame, ArchiveSegmentFrame,
> manifest::{BackupManifest, ArchiveManifest},
> media_descriptor::MediaDescriptor, search_shard::SearchIndexShard}`),
> Ed25519 manifest signing with a `previous_manifest_hash` chain,
> the multilingual tokenization spec
> (`search::tokenizer::{TokenizerConfig, FallbackMode, ScriptClass,
> FuzzyGranularity, fts5_tokenizer_config, detect_script,
> segment_by_script}`), and a CI pipeline.
>
> Landed in Phase 1 so far: typed local-store schema row structs +
> `SCHEMA_SQL` (`local_store::schema`), per-message state machines
> with `try_transition` (`local_store::state_machines`),
> SQLCipher-backed local store (`local_store::db::LocalStoreDb` with
> `PRAGMA key`, foreign-key enforcement, ICU/`unicode61` schema
> bring-up, conversation/skeleton/body CRUD plus
> `list_conversations` / `update_conversation_pin` /
> `update_conversation_mute`), the message processor
> with DB-backed `MessagePersister` (transactional skeleton + body +
> FTS row + journal entry, idempotent on `message_id`, plus
> `edit_message` / `delete_for_me` / `delete_for_everyone` with FTS
> **and fuzzy-index** maintenance — every persisted body is now
> dual-indexed into `search_fts` and `search_fuzzy`, and the
> persistence path also bumps `conversation.last_message_id` /
> `last_activity_ms` so `list_conversations` reflects the latest
> message without an extra call from the binding layer), the FTS5 text
> search engine (`search::text_search::TextSearchEngine` with
> BM25-ordered queries, snippet highlighting, prefix-search and
> phrase-quote handling), the unified query engine
> (`search::query_engine::QueryEngine` merging FTS5 + fuzzy hits by
> `message_id` with PROPOSAL.md §7.5 ranking weights
> `BM25_WEIGHT = 2.0` / `FUZZY_WEIGHT = 1.0` plus structured
> `sender` / `conversation` / `date_from` / `date_to` /
> `content_kind` filters), the script-aware **fuzzy token indexer**
> (`search::fuzzy_search::{FuzzyTokenizer, FuzzySearchEngine}`,
> trigrams for alphabetic scripts / bigrams for CJK), the
> concrete **`CoreImpl`** `KChatCore` implementation
> (`core_impl.rs`) wiring `send_text` / `edit_message` /
> `delete_for_me` / `delete_for_everyone` / `get_message` /
> `get_conversation_messages` / `ingest_messages` /
> `ingest_remote_messages` / `search` to the SQLCipher store, the
> public **`MessageView`** shape that pairs the skeleton with the
> optional decrypted body text so the timeline API never leaks
> internal schema types, the **transport trait abstraction**
> (`transport::DeliveryClient`,
> `transport::FetchResult { messages, next_cursor }`,
> `transport::RawDeliveryMessage`,
> `transport::TransportError { Network, Auth, Server }`) plus a
> test-only `MockDeliveryClient` so unit tests can stage
> per-cursor responses, the **transport-driven
> `ingest_remote_messages`** that pulls from a configured
> `Box<dyn DeliveryClient>` and reuses the existing batch-ingest
> pipeline (deduplication / FTS / fuzzy / journal writes
> unchanged) — `IngestResult.next_cursor` is now propagated
> end-to-end through the result so paginated drains can drive
> directly off the response without poking at the transport
> mock, the **conversation-management
> API** on `CoreImpl` (`create_conversation` /
> `list_conversations` / `get_conversation` /
> `update_conversation_pin` / `update_conversation_mute` /
> `delete_conversation` — the last one cascading through every
> dependent row inside a single `SAVEPOINT`), the
> **Phase-1 stub trait surface** for the rest of
> `docs/PROPOSAL.md §12` (`register_device`, `send_media`,
> `hydrate_message`, `run_incremental_backup`,
> `enforce_storage_budget`, `restore_from_backup`) returning
> `Err(Error::NotImplemented(<method>))`, the **bridge
> scaffolds** at `crates/ios-bridge/` (UniFFI 0.28 with
> `kchat.udl` mirroring the public `KChatCore` surface and a
> `build.rs` that calls `uniffi::generate_scaffolding`) and
> `crates/android-bridge/` (jni 0.21 with the
> `Java_com_kchat_core_KChatBridge_*` entry points wrapping a
> pure-Rust `KChatBridgeHandle` so unit tests exercise the
> bridge surface without a JNIEnv), the multilingual
> integration tests at `crates/core/tests/multilingual_search.rs`
> + `crates/core/tests/multilingual_fuzzy_search.rs` (combined
> FTS5 + fuzzy across Latin / Cyrillic / Arabic / Thai trigrams,
> CJK bigrams, mixed script, dedup, ranking, and structured
> filters), and the Phase-1 **criterion benchmark suite**
> (`crates/core/benches/phase1_benchmarks.rs`) validating the
> < 20 ms / < 150 ms p95 budgets.
>
> Outstanding for Phase 1: production UniFFI / JNI packaging
> (the bridge scaffolds at `crates/{ios,android}-bridge/` are
> in place but the generated Swift package and Kotlin façade
> are not yet wired into KChat.app / KChat-Android) and the
> platform-specific `K_local_db` wrap (Keychain / Keystore /
> DPAPI). The transport surface and the transport-driven
> `ingest_remote_messages` are now in place; what remains for
> Phase 1 is the production MLS delivery-client implementation
> of `DeliveryClient` (the trait itself, the
> `RawDeliveryMessage` / `FetchResult` / `TransportError`
> shapes, and the wiring through `CoreImpl::with_transport` /
> `set_delivery_client` / `ingest_remote_messages` are all
> landed). The broader transport surface for Phases 2–4
> also lives on the core today: `transport::TransportClient`
> defines the cursor-paginated message fetch, chunked blob
> upload (`init_blob_upload` / `upload_chunk` / `commit_blob`
> with whole-object Merkle-root verification),
> `fetch_blob_range` for ranged downloads, archive manifest +
> segment fetch, and encrypted index-shard fetch — backed by a
> `NoopTransportClient` that returns
> `Error::NotImplemented("transport")` from every method.
> `CoreImpl` also exposes the message-timeline page
> (`get_timeline`), single-message retrieval
> (`get_message_with_body`, `get_message_body`), and
> conversation-deletion cascade (`delete_conversation`) used
> by the rendering and storage-management paths in the
> bindings.
>
> Landed in Phase 2 so far: the chunked-media pipeline
> (`media::chunker`, `media::processor`, `media::upload`,
> `media::download`), the local media cache (`media::cache`),
> multilingual filename / caption handling (`media::caption`), the
> upload / download routing layer (`media::routing`), and the
> tiered-media routing surface (`media::sinks::MediaBlobSink`,
> `NoopMediaBlobSink`, `StorageSink` / `ArchiveBackend` enums on
> `KChatCoreConfig`, `storage_sink` field on `MediaDescriptor`,
> `storage_sink` column on `media_asset`). The `media_state`
> machine (`thumbnail_only` → `original_local` → `evicted` /
> `deleted`) is wired through `media::processor::transition_media_state`
> + `LocalStoreDb::update_media_state`.
> `media::chunker::chunk_and_encrypt` splits a plaintext blob into
> XChaCha20-Poly1305-sealed `SealedChunk`s under a per-chunk
> `KCHAT_BLOB_CHUNK_V1` AAD (PROPOSAL.md §8.3) bound to the
> whole-object BLAKE3 root, records per-chunk SHA-256 over the
> ciphertext for fast-fail integrity, and supports opt-in
> size-class padding via `pad_to_size_class` /
> `unpad_from_size_class` (PROPOSAL.md §8.2). The matching
> `verify_and_decrypt` rebuilds the AAD per chunk, AEAD-opens,
> and verifies the BLAKE3 root over the recovered plaintext.
> `media::processor::process_media` generates a fresh-random
> `K_asset` (zeroized on drop), runs the chunker, wraps `K_asset`
> under `K_local_db` / `K_archive_root` / `K_backup_root` with
> AES-256-KW, and assembles the `MediaDescriptor` the local store
> persists. `media::upload::upload_chunked_media` /
> `resume_upload` drive `TransportClient::init_blob_upload` →
> `upload_chunk` → `commit_blob` and verify the server-side
> BLAKE3 root on commit, with `UploadState::completed_chunks`
> bookkeeping so resumed uploads never duplicate completed
> chunks.
>
> The remaining higher-level engines
> (`archive`, `backup`, `offload`, `restore`) remain
> stubbed and land across Phases 3–7. See
> [docs/PROGRESS.md](docs/PROGRESS.md) for the full tracker.

---

## Project structure

The current shape of `crates/core/src/`. Bold modules carry real
implementation; the rest are still placeholders that fill in across
Phases 2–7.

```
chat-storage-search/
  Cargo.toml                                # workspace root
  README.md
  LICENSE
  docs/
    PROPOSAL.md
    ARCHITECTURE.md
    PHASES.md
    PROGRESS.md
  crates/
    core/                                   # platform-agnostic Rust core
      Cargo.toml
      src/
        lib.rs                              # Phase 1: KChatCore trait + public API types
        config.rs                           # KChatCoreConfig
        core_impl.rs                        # Phase 1: concrete CoreImpl implementing KChatCore
        crypto/                             # Phase 0: COMPLETE
          mod.rs
          aead.rs                           # XChaCha20-Poly1305 / AES-256-GCM
          content_hash.rs                   # BLAKE3 content hash
          convergent.rs                     # Pattern C convergent encryption (Go SDK interop)
          key_hierarchy.rs                  # HKDF-SHA256 derivation tree
          key_wrap.rs                       # AES-256-KW (RFC 3394)
        formats/                            # Phase 0: CBOR wire formats — COMPLETE
          mod.rs                            # BackupSegmentFrame / ArchiveSegmentFrame
          manifest.rs                       # BackupManifest / ArchiveManifest + Ed25519
          media_descriptor.rs               # MediaDescriptor
          search_shard.rs                   # SearchIndexShard (text/fuzzy/vector/media)
        local_store/                        # Phase 1: SQLCipher store + schema landed
          mod.rs
          db.rs                             # SQLCipher-backed LocalStoreDb + CRUD helpers
          schema.rs                         # SCHEMA_SQL + typed row structs
          state_machines.rs                 # body / media / archive / backup / restore
        message/                            # Phase 1: persister + edit / delete landed
          mod.rs
          processor.rs                      # IngestedMessage / OutboxEntry / MessagePersister (edit / delete)
        search/                             # Phase 1: FTS5 + structured + fuzzy search landed; Phase 4: encrypted search-index shard build / restore
          mod.rs
          tokenizer.rs                      # ICU + ScriptClass + FuzzyGranularity
          text_search.rs                    # FTS5 BM25 engine, ICU/unicode61 fallback
          query_engine.rs                   # FTS + sender/date/conv/kind structured filters; Phase 6: execute_search_with_semantic merges semantic hits using SEMANTIC_WEIGHT = 1.5
          fuzzy_search.rs                   # FuzzyTokenizer + FuzzySearchEngine (trigram / bigram)
          semantic_search.rs                # Phase 6: SemanticSearchEngine (brute-force cosine over `search_vector` rows, conversation-filterable)
          shard_builder.rs                  # build/restore_text_search_shard, build/restore_fuzzy_search_shard, build/restore_vector_search_shard, build/restore_media_search_shard (encrypted search shards for Phase 4 backup / restore + Phase 6 vector / media)
          shard_prefetch.rs                 # batch_prefetch_shards / batch_prefetch_shards_with_padding / batch_prefetch_shards_with_padding_for_target + compute_scope_padding_multiplier: scope-proportional cover traffic (Phase 8 batch 6)
          shard_cache.rs                    # Phase 8 batch 6: ShardCache (LRU, default 50 MB) + ShardCacheKey + CachedShard + warm_shard_cache (P5 idle background warmer)
          cold_shard_source.rs              # TransportColdShardSource (TransportClient + ShardKeyRegistry → ColdShardSource, with fetch_bloom_shard for the Phase 8 bloom precheck) + GracefulCold wrapper (Phase 5)
        archive/                            # Phase 3 foundation: event journal + segment builder + manifest builder + upload + download + prefetch + epoch keys + routing + privacy padding + compaction
          mod.rs
          event_journal.rs                  # ArchiveEventType / ArchiveEvent / ArchiveEventJournal (write_event / read_events_since / advance_cursor / read_unsegmented)
          segment_builder.rs                # SegmentBuildRequest / BuiltSegment / ArchiveSegmentBuilder (CBOR → zstd → XChaCha20-Poly1305)
          manifest_builder.rs               # ArchiveManifestBuilder: genesis → gen N chain, BLAKE3 manifest hash, Ed25519 signature, AEAD-seal under K_archive_manifest, wrapped_prior_epoch_keys carry-through
          upload.rs                         # upload_archive_segment over TransportClient + persist_segment_map_row
          download.rs                       # download_archive_segment / decrypt_archive_segment / decode_archive_segment_payload / fetch_and_decrypt_segment / ArchiveSegmentRouter (KChat backend ↔ ZK Object Fabric per-row routing)
          prefetch.rs                       # batch_prefetch_bucket / batch_prefetch_bucket_with_router / batch_prefetch_bucket_with_padding: one transport hop per (conversation_id, time_bucket)
          epoch_keys.rs                     # EpochKeyManager: current epoch in Zeroizing<[u8; 32]>, prior keys wrapped via AES-256-KW, rotate / unwrap_prior_epoch_key / delete_epoch_key
          routing.rs                        # route_archive_upload / route_archive_download / route_manifest_upload (KChat backend ↔ ZK Object Fabric)
          privacy.rs                        # should_pad / compute_padding_count / generate_dummy_segment_id (UUIDv4) / pad_with_dummy_requests (privacy_level = High)
          compaction.rs                     # apply_archive_tombstones + ArchiveCompactionResult (per-bucket merge of archive_verified segments → archive_compacted)
          body_payload.rs                   # KCHAT_ARCHIVE_BODY_PAYLOAD_V1 envelope: encode_body_payload / decode_body_payload (cold-result hydration write-back path)
        backup/                             # Phase 4 foundation: event journal + segment builder + manifest builder + compaction + sinks
          mod.rs
          event_journal.rs                  # BackupEventType / BackupEvent / BackupEventJournal (write_event / read_events_since / read_unsegmented / cursor)
          segment_builder.rs                # BackupSegmentBuildRequest / BuiltBackupSegment / BackupSegmentBuilder (CBOR → zstd → XChaCha20-Poly1305) + decrypt_backup_segment
          manifest_builder.rs               # BackupManifestBuildRequest / SealedBackupManifest / build_backup_manifest (genesis → gen N chain, Ed25519 signature, AEAD-sealed under K_backup_manifest with device_id AAD)
          compaction.rs                     # CompactionTier / CompactionPolicy / CompactionPlan + plan + apply_tombstones (daily → weekly → monthly)
          sinks/                            # BackupSink trait + backup-vault implementations
            mod.rs                          # BackupSink + NoopBackupSink (object-safe trait surface)
            zk_fabric.rs                    # ZkofBackupSink: backups/{manifest_id}, backups/segments/{segment_id}; Pattern C convergent encryption (bit-identical to Go SDK)
            icloud.rs                       # ICloudBackupSink: ICloudBackupBridge (upload_file / download_file / list_files / delete_file) → backups/{manifest_id} + backups/segments/{segment_id} record names; NoopICloudBackupBridge stub
            android.rs                      # AndroidBackupSink: AndroidBackupBridge (write_auto_backup / read_auto_backup / write_saf / read_saf / list_saf) — manifests via Auto Backup (≤ 25 MiB), segments via SAF; NoopAndroidBackupBridge stub
        media/                              # Phase 2: chunker + processor + upload + download + cache + routing + thumbnail
          mod.rs
          chunker.rs                        # chunk + AEAD-seal, size-class padding, verify_and_decrypt
          processor.rs                      # process_media: random K_asset + chunk + wrap + descriptor + state-machine helpers
          thumbnail.rs                      # ThumbnailGenerator: image decode → max_dimension scale → PNG re-encode
          upload.rs                         # upload_chunked_media + resume_upload over TransportClient
          download.rs                       # download_chunked_media + download_single_chunk
          cache.rs                          # MediaCache: LRU eviction with configurable byte budget
          caption.rs                        # NFC normalization, filename sanitization, multilingual captions
          routing.rs                        # route_media_upload / route_media_download (sink dispatch)
          sinks/                            # MediaBlobSink trait + sink implementations (PROPOSAL.md §5.7)
            mod.rs                          # MediaBlobSink + MediaBlobReference + NoopMediaBlobSink
            zk_fabric.rs                    # ZkObjectFabricSink: per-chunk S3 keys media/{asset_id}/chunk-{idx:08}, S3Client trait + NoopS3Client
            icloud.rs                       # ICloudBlobBridge trait + ICloudMediaBlobSink + NoopICloudBridge (storage_sink = "icloud")
            google_drive.rs                 # GoogleDriveBridge trait + GoogleDriveMediaBlobSink + NoopGoogleDriveBridge (storage_sink = "google_drive")
        models/                             # Phase 6: on-device ML seams
          mod.rs                            # re-exports
          embeddings.rs                     # TextEmbedder trait + NoopTextEmbedder + MockTextEmbedder + EmbeddingCache trait + LocalStoreEmbeddingCache + INT8 codec + XLMR_MODEL_VERSION / XLMR_EMBEDDING_DIM
          embeddings_onnx.rs                # ONNX Runtime session lifecycle (gated `#[cfg(feature = "onnx-runtime")]`); EP-selection state machine + Error::Model mapping + create_xlmr_session_int4 (INT4 MatMulNBits)
          clip.rs                           # ImageEmbedder trait + NoopImageEmbedder + MockImageEmbedder + MOBILECLIP_S2_MODEL_VERSION / MOBILECLIP_S2_EMBEDDING_DIM + create_mobileclip_session_int4
          whisper.rs                        # Phase 6: WhisperTranscriber trait + NoopWhisperTranscriber + MockWhisperTranscriber + TranscriptionResult / TranscriptionSegment + select_whisper_backend (Apple MLX vs ONNX) + WHISPER_BASE_MLX_MODEL_VERSION
          document.rs                       # Phase 6: DocumentExtractor trait + NoopDocumentExtractor + MockDocumentExtractor + DocumentPage (PDF / DOCX page-level extraction)
          video.rs                          # Phase 6: VideoKeyframeSampler trait + NoopVideoKeyframeSampler + MockVideoKeyframeSampler + Keyframe (timestamp_ms + image_data + mime_type)
          ocr.rs                            # OcrBridge trait (Send+Sync, object-safe) + NoopOcrBridge + OcrResult + BoundingBox
          model_manager.rs                  # ModelManager + ModelArtifact + ModelManagerConfig + Quantization (Int8 / Int4 / Float32) + ModelDownloader trait + NoopModelDownloader + select_quantization (Int4 when available_storage_bytes < TIGHT_STORAGE_THRESHOLD_BYTES = 512 MiB) + ModelArtifactSpec (XLMR / MobileCLIP × INT8 / INT4 filenames) + resolve_artifact
          resource_gate.rs                  # ResourceGate + ResourcePolicy + DeviceResources + ThermalState + NetworkType + ResourceProbe trait + NoopResourceProbe
        offload/                            # Phase 3 foundation: budget + scoring + eviction + hydration
          mod.rs
          budget.rs                         # StorageBudget / StorageUsage / BudgetAssessment / PressureLevel / StorageBudgetEnforcer
          scoring.rs                        # ContentKind weights + 30-day half-life recency decay + size bonus (PROPOSAL §5.4)
          eviction.rs                       # plan_eviction + plan_eviction_with_pressure + plan_tiered_eviction (cloud-offload first → full eviction) + execute_eviction (state-machine demotion)
          hydration.rs                      # HydrationQueue (P0..P5 priority + FIFO) + enqueue_prefetch_window
        restore/                            # Phase 4 foundation: state machine persistence + manifest verifier + skeleton-first pipeline + key recovery
          mod.rs
          state_machine.rs                  # restore_state row helpers (load / save / transition / reset) layered over local_store::state_machines::RestoreState
          manifest_verifier.rs              # verify_manifest_chain: walks gen 0..latest, Ed25519 + previous_manifest_hash check, returns EmptyChain / SignatureInvalid / ChainBreak / GapDetected / GenesisHashNotZero
          pipeline.rs                       # RestorePipeline: conversation list → skeletons → search shards → recent bodies → enable lazy media; persists every RestoreState transition
          key_recovery.rs                   # RecoveryKey (AES-256-KW wrap of K_user_master, hex display) + DeviceTransferPayload (XChaCha20-Poly1305 seal of K_user_master + 3 derived roots, transfer-code-derived AEAD key)
        scheduler/                          # Phase 5 / 7: BackgroundScheduler trait (Send+Sync, object-safe), TaskType (IncrementalBackup / ArchiveCompaction / IndexMaintenance / MediaCacheEviction / ModelWarmup), ScheduledTask, NoopScheduler, IosBgTaskBridge / AndroidWorkManagerBridge platform bridges + Noop stubs
        transport/                          # Phase 1: DeliveryClient + TransportClient + NoopTransportClient + MockDeliveryClient + Phase 7: offline.rs
          mod.rs
          offline.rs                        # Phase 7: OfflineDetector trait (Send+Sync+Debug, object-safe) + NoopOfflineDetector (always-online fail-open) + AlwaysOfflineDetector (test) + ToggleOfflineDetector (mid-test flip)
        perf.rs                             # Phase 7: PerfTrace + PerfCollector trait (Send+Sync+Debug, object-safe) + NoopPerfCollector + InMemoryPerfCollector — wired into CoreImpl via install_perf_collector / has_perf_collector / collect_perf_stats; ingest_messages / search / enforce_storage_budget hot paths emit start/end ns + free-form metadata
        desktop_index.rs                    # Phase 7: SpotlightAnchor / WindowsSearchAnchor object-safe traits — host-OS search-index bridges (macOS Spotlight via CSSearchableIndex, Windows Search via ISearchManager) so kchat metadata surfaces in the system search bar without breaking E2EE; CoreImpl carries a slot for each so platform bridges plug in without depending on the desktop crate
      benches/
        phase1_benchmarks.rs                # criterion: insert / search / batch / prefix / structured
        phase5_benchmarks.rs                # criterion: text_only_one_month / fuzzy_only_one_month / local_plus_one_cold_bucket — Phase 5 cold-shard latency budget
        phase6_int4_benchmarks.rs           # criterion: int8_encode_decode_round_trip / int4_encode_decode_round_trip / int8_vs_int4_cosine_fidelity (multilingual 100-vector corpus) / embedding_cache_throughput
        phase8_benchmarks.rs                # Phase 8 batch 6: bloom_precheck_one_month_bucket / shard_cache_hit_vs_miss / scope_resolver_community_100_conversations / date_pruning_100_buckets / global_search_with_bloom_10_buckets
      tests/
        manifest_signing.rs                 # generation chain end-to-end
        key_wrap_hierarchy.rs               # archive vs backup root wrap split
        epoch_key_derivation.rs             # Phase 3: K_archive_epoch determinism / rotation / wrap-unwrap / cross-epoch decrypt / info-string vectors
        archive_pipeline.rs                 # Phase 3 end-to-end: ingest → archive journal → group → segment build/decrypt → cursor advance, plus archive_pipeline_epoch_rotation_and_cross_epoch_compaction (2-epoch rotation + manifest carry-through) and archive_manifest_chain_carries_wrapped_keys_for_three_epoch_restore (3-epoch chain decode after a simulated fresh-device restore via EpochKeyManager::ingest_wrapped_prior_epoch_key)
        backup_pipeline.rs                  # Phase 4 end-to-end: build segment + 2-gen manifest chain → verify_manifest_chain → RestorePipeline::run → terminal FullRestoreComplete; chain-break catch test; search-shard restore round-trip
        backup_restore_multilingual.rs      # Phase 4 multilingual corpus: 8+ scripts (English / Russian / Chinese / Japanese / Arabic / Thai / Hindi / mixed Latin+CJK) round-trip through run_incremental_backup → manifest chain → verify_manifest_chain → RestorePipeline::run → FullRestoreComplete; soft-skips CJK / Thai FTS on non-ICU builds
        failure_scenarios.rs                # Phase 7 failure-test suite (14 of 14): chunk upload interrupted then resumed; SHA-256 fast-fail on tampered ciphertext; tampered descriptor merkle_root; wrong K_backup_segment / wrong manifest signing key; manifest chain break with expected/actual hashes (plus deepest-link variant); MLS-removed device surfaces SignatureInvalid; missing search shard graceful degrade with cold_unavailable flag; low-storage during restore surfaces resumable Error::Storage plus the end-to-end resume gate low_storage_during_restore_checkpoints_and_resumes_to_full_restore_complete; manifest upload interrupted mid-write retries without chain break; offline_during_backup_defers_upload_and_succeeds_on_reconnect (BackupResult.deferred = true while OfflineDetector reports offline, no segments built; reconnect produces a non-deferred run); offline_during_hydration_returns_cold_with_offline_flag (HydratedMessage { is_cold: true, offline: true, text_content: None } when body is RemoteArchiveOnly + offline)
        large_scale.rs                      # Phase 7 large-scale stress scaffold (#[ignore]): large_scale_ingest_and_search_10k_messages — 10k messages × 12 scripts (en / ru / zh / ja / ar / th / hi / ko / vi / de / fr / mixed-script), FTS5 + fuzzy + QueryEngine round-trip with rank-ordering check; large_scale_storage_budget_under_pressure — 5k media-asset rows totalling 500 MiB against 100 MiB budget at Critical pressure; large_scale_backup_restore_round_trip — 1k message backup → manifest-chain → RestorePipeline::run round-trip; run with `cargo test --test large_scale -- --ignored`
        large_scale_test.rs                 # Phase 7 production-scale stress test (#[ignore]): 100k+ messages × 100+ conversations × 11 scripts (Latin / Cyrillic / CJK / Arabic / Thai / Devanagari / Bengali / Tamil / Korean / Greek / Hebrew), 10k+ media messages, every storage-budget pressure level, full backup-restore manifest chain, p95 search latency asserted under the Phase-1 < 150 ms budget; run with `cargo test --test large_scale_test -- --ignored`
        cold_shard_search.rs                # Phase 5: encrypted shard fetch via ColdShardSource → on-device decrypt → FTS5 + fuzzy → merge with local hits → SearchScope::IncludeCold marks is_cold = true
        mixed_language_query.rs             # Phase 5: segment_by_script fan-out across Latin × CJK / Cyrillic × Latin / pure-CJK fuzzy fallback / mixed-script promotion / unrelated-row exclusion
        phase5_latency_smoke.rs             # Phase 5: cold-shard decrypt + search smoke test (debug-build smoke gate; plus the p95 latency gate phase5_cold_shard_p95_latency_under_1_5s_budget that drives 20 iterations on a 1 000-message multilingual one-month bucket and asserts the end-to-end shard fetch + AEAD decrypt + FTS5 / fuzzy search p95 stays under the 1.5 s Phase-5 budget; on-device device-matrix p95 ≤ 1.5 s gate runs in the device-matrix bench)
        media_pipeline.rs                   # process_media + chunker + cache + caption + routing + thumbnail end-to-end
        storage_budget_enforcement.rs       # Phase 3 end-to-end: pressure assessment → candidate collection → tiered eviction → executor (every PressureLevel × every EvictionTier)
        multilingual_search.rs              # Latin/Cyrillic/CJK/Arabic/Thai/Devanagari FTS5 round-trip
        multilingual_fuzzy_search.rs        # Combined FTS5 + fuzzy across scripts (typo recovery, dedup, rank, filters)
        phase6_embedding_cache.rs           # Phase 6: cross-pipeline EmbeddingCache integration test — put/get round-trip with INT8-codec cosine > 0.999, version-mismatch → None, two LocalStoreEmbeddingCache instances on the same SQLCipher connection see each other's writes
        phase8_multi_scope_search.rs        # Phase 8 batch 6: 10 end-to-end tests — community / domain / tenant / global scoping, bloom filter elimination, shard-cache refetch elimination, tenant-policy global block, date pruning, B2B per-tenant key isolation, and scope-proportional padding
        pattern_c_interop_vectors.rs        # Rust ↔ Go SDK bit-for-bit vectors
        pattern_c_interop_vectors.json
    ios-bridge/                             # UniFFI → Swift (Phase 1 scaffold: kchat.udl + build.rs + FFI wrappers)
    android-bridge/                         # JNI → Kotlin (Phase 1 scaffold: Java_com_kchat_core_KChatBridge_* entry points)
    desktop/                                # macOS + Windows (Phase 7)
      src/
        lib.rs                              # Phase 7: re-exports macos / windows scaffolds gated on #[cfg(target_os = ...)] + the platform-agnostic batch-5 trait scaffold; depends on kchat-core for BackgroundScheduler trait
        macos.rs                            # Phase 7 macOS scaffold (#[cfg(target_os = "macos")]): SpotlightBridge trait (object-safe) + NoopSpotlightBridge + index_message / remove_message / remove_conversation; MacOsSchedulerBridge implementing BackgroundScheduler via NSBackgroundActivityScheduler + NoopMacOsSchedulerBridge
        windows.rs                          # Phase 7 Windows scaffold (#[cfg(target_os = "windows")]): WindowsSearchBridge trait + NoopWindowsSearchBridge mirroring the macOS Spotlight surface; WindowsSchedulerBridge + NoopWindowsSchedulerBridge backed by the Task Scheduler; WindowsMlConfig (CPU-only ML contract: DirectML EP best-effort, INT4 default for tight storage)
        spotlight.rs                        # Phase 7 batch-5: SpotlightAnchor trait (object-safe, Send+Sync, Debug) + NoopSpotlightAnchor — platform-agnostic Spotlight indexing surface
        windows_search.rs                   # Phase 7 batch-5: WindowsSearchAnchor trait + NoopWindowsSearchAnchor — Windows Search protocol-handler surface
        background.rs                       # Phase 7 batch-5: DesktopScheduler trait + NoopDesktopScheduler implementing BackgroundScheduler from kchat-core
        ml_ep.rs                            # Phase 7 batch-5: DesktopMlEpSelector forwarding to kchat-core's ExecutionProviderSelector with CoreML / DirectML / CPU fallback
  tests/
    generate_vectors/
      main.go                               # Pattern C vector generator (calls Go SDK)
```

The full target shape (including the `archive/` / `backup/` /
`media/` / `models/` / `transport/` engines) lives in
[docs/ARCHITECTURE.md §2](docs/ARCHITECTURE.md) and the
"Target repo structure" section below.

---

## Quick start

```sh
# Build the workspace.
cargo build --workspace

# Run unit + cross-language interop tests.
cargo test --workspace

# Lint as CI does.
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

## How to run tests

```sh
cargo test --workspace --verbose
```

The Phase-7 large-scale stress tests at
[`crates/core/tests/large_scale.rs`](crates/core/tests/large_scale.rs)
are marked `#[ignore]` so they stay out of the default `cargo
test` matrix. Run them explicitly:

```sh
cargo test --test large_scale -- --ignored
```

Each test seeds either 10 000 multilingual messages (FTS5 +
fuzzy + QueryEngine round-trip), 5 000 media-asset rows
totalling 500 MiB against a 100 MiB budget at Critical
pressure, a 1 000-message backup → manifest-chain → restore
round-trip, or — added in the 2026-05-04 batch-5 — a
100 000-message multilingual ingest + search round-trip,
10 000 media-asset round-trip across 4 sinks, 50 000-message
ingest stress across 100 conversations, or a concurrent
writer / reader stress.

The Phase-7 media-blob sink stress test at
[`crates/core/tests/media_sink_stress.rs`](crates/core/tests/media_sink_stress.rs)
seeds 10 000 assets across `kchat_backend` / `icloud` /
`google_drive` / `zk_object_fabric`, asserts every
`media_asset.storage_sink` round-trips, samples chunk-fetch
round-trips, and exercises the migration executor at scale.
Run it explicitly:

```sh
cargo test --test media_sink_stress -- --ignored
```

The criterion benchmarks live under
[`crates/core/benches/`](crates/core/benches/) and run with
[criterion](https://docs.rs/criterion). The Phase-1 suite covers
local-store insert / search / structured-filter latency:

```sh
cargo bench -p kchat-core --bench phase1_benchmarks
```

The Phase-5 suite covers the cold-shard latency budget for
encrypted-shard fetch + on-device decrypt + search:

```sh
cargo bench -p kchat-core --bench phase5_benchmarks
```

`phase5_benchmarks` exposes three benches —
`text_only_one_month` (FTS5-only against a decrypted text shard
for a one-month bucket), `fuzzy_only_one_month` (fuzzy index
shard equivalent), and `local_plus_one_cold_bucket` (local search
+ one cold shard fetch through a delayed `ColdShardSource` that
simulates a network hop + decrypt + merge).

The Phase-8 suite covers the multi-scope search hot paths
(bloom precheck, shard cache hit vs miss, scope resolver,
date pruning, end-to-end global search with bloom precheck):

```sh
cargo bench -p kchat-core --bench phase8_benchmarks
```

`phase8_benchmarks` exposes five benches —
`bloom_precheck_one_month_bucket`, `shard_cache_hit_vs_miss`,
`scope_resolver_community_100_conversations`,
`date_pruning_100_buckets`, and
`global_search_with_bloom_10_buckets`. The matching CI smoke
test at
[`crates/core/tests/phase5_latency_smoke.rs`](crates/core/tests/phase5_latency_smoke.rs)
asserts the cold-shard decrypt+search path completes well under
5 s on debug builds; the on-device ≤ 1.5 s p95 gate runs in the
Phase-5 device-matrix bench.

HTML reports land under `target/criterion/`. Local p95 numbers on
the development VM measure ~100 µs / ~70 µs for single-insert /
1k-row FTS5 search, two orders of magnitude below the 20 ms /
150 ms targets in `docs/PROPOSAL.md §13`.

The Phase 0 + Phase 1 test surface covers:

* [`crypto`](crates/core/src/crypto/) — content hash, key
  hierarchy, AEAD, convergent encryption, key wrap.
* [`formats`](crates/core/src/formats/) — CBOR round-trip,
  manifest sign / verify / chain, media descriptor, search shard.
* [`search::tokenizer`](crates/core/src/search/tokenizer.rs) —
  script detection, mixed-script segmentation, fuzzy-granularity
  mapping, FTS5 config strings, `TokenizerConfig` serde.
* [`local_store::schema`](crates/core/src/local_store/schema.rs) —
  struct round-trip through serde, SQL schema validity (every
  documented table is present, parentheses balance, statements
  terminate cleanly).
* [`local_store::state_machines`](crates/core/src/local_store/state_machines.rs) —
  every legal transition succeeds, every illegal transition
  errors, `Display` / `FromStr` round-trip, serde round-trip.
* [`local_store::db`](crates/core/src/local_store/db.rs) —
  SQLCipher bring-up (`PRAGMA key`, foreign-key enforcement,
  ICU→`unicode61` schema fallback), `LocalStoreDb` CRUD round-trip
  for conversation / skeleton / body / `update_body_state` /
  `insert_backup_event`, FK-violation enforcement, the
  conversation-management helpers `list_conversations` (pinned
  first, then descending `last_activity_ms`),
  `update_conversation_pin`, `update_conversation_mute`, plus
  the message-timeline pagination (`get_timeline` newest-first
  with `before_ms` cursor, body-row drop surfaces as
  `text_content == None`) and the conversation-deletion
  cascade (`delete_conversation` removes
  `search_fuzzy` → `search_fts` → `message_body` →
  `message_skeleton` → `conversation` in a single
  `SAVEPOINT`, leaves sibling conversations untouched, and is
  a no-op for missing ids).
* [`message::processor`](crates/core/src/message/processor.rs) —
  `validate_ingest`, deduplication, outbox creation with monotonic
  UUID v7, plus the `MessagePersister` integration tests for
  transactional skeleton + body + FTS5 + journal writes,
  duplicate rejection, `mark_sent` event-journal entries, and the
  edit / delete operations (`edit_message`, `delete_for_me`,
  `delete_for_everyone`) with FTS5 **and fuzzy-index** maintenance
  (`search_fuzzy` rows are written / re-written / removed in
  lock-step with FTS), body-state transition validation, and
  `"message_edited"` / `"message_deleted"` journal entries.
* [`search::text_search`](crates/core/src/search/text_search.rs) —
  BM25 ordering, snippet highlighting, prefix queries, phrase
  quoting, special-character escaping in free-text input.
* [`search::query_engine`](crates/core/src/search/query_engine.rs)
  — sender / conversation / date / content-kind filters, FTS
  **merged with fuzzy** by `message_id` (PROPOSAL.md §7.5
  `BM25_WEIGHT = 2.0` / `FUZZY_WEIGHT = 1.0`), exact > fuzzy
  ranking, dedup on cross-engine hits, batch skeleton-hydration
  for fuzzy-only rows, structured filters narrowing the unioned
  candidates, and the `SearchScope::LocalOnly` invariant.
* [`search::fuzzy_search`](crates/core/src/search/fuzzy_search.rs)
  — script-aware n-gram tokenization (trigrams for alphabetic
  scripts, bigrams for CJK), index / remove / search round-trip
  against the `search_fuzzy` table, token-overlap scoring,
  case-insensitive matching, and word-boundary handling.
* [`core_impl`](crates/core/src/core_impl.rs) — concrete
  `KChatCore` round-trip tests: `send_text` → skeleton + body +
  FTS check, `ingest_messages` → search round-trip, duplicate
  rejection, `initialize` re-open at a new `data_dir`, the
  **edit / delete surface** on the trait (`edit_message`
  body-and-search update, `delete_for_me` removes from search
  while keeping the body, `delete_for_everyone` drops the body
  and tombstones the skeleton, missing-id error path), the
  **timeline retrieval surface** (trait-level `get_message`
  round-trip, `get_conversation_messages` newest-first
  ordering with `before_ms` pagination and `limit` handling,
  the inherent `get_timeline` `TimelineRow` page after
  `send_text` / `ingest_messages` plus multi-page cursor
  walks, and the inherent single-message helpers
  `get_message_with_body` / `get_message_body` covering
  missing-id `Ok(None)`, body-present after `send_text` /
  `ingest_messages`, and skeleton-with-`None`-body after
  `delete_for_everyone`), the
  **transport-driven `ingest_remote_messages`** (happy path
  with three messages indexed + searchable, no-transport
  `Error::Transport`, dedup on retry through the same mock
  cursor, and cursor pass-through verified by the mock's
  per-call assertion), `IngestResult.next_cursor`
  propagation (transport `Some(cursor)` flows through
  unchanged, `None` when the delivery store is drained, and
  the inherent `ingest_messages` entry point leaves it
  `None`), the
  conversation-management surface (`create_conversation` /
  `list_conversations` / `get_conversation` / pin / mute /
  trait-level `delete_conversation`, including
  `list_conversations_reflects_latest_message_activity`
  which pins the auto-bump of `last_message_id` /
  `last_activity_ms` from the persistence path, plus the
  cascade test that confirms messages and search hits are
  gone after `delete_conversation` and the missing-id
  `Error::Storage` path), and
  the Phase-1 `Error::NotImplemented` stubs for
  `register_device` / `send_media` / `hydrate_message` /
  `run_incremental_backup` / `enforce_storage_budget` /
  `restore_from_backup`.
* [`ios-bridge`](crates/ios-bridge/src/lib.rs) — UniFFI 0.28
  scaffold tests covering bridge construction, the
  wrong-key-length error path, the `Platform` round-trip,
  the `SearchQuery` / UUID parsing helpers, the
  `register_device` `NotImplemented` stub, and a full
  `send_text → get_message` round-trip through the FFI
  shape.
* [`android-bridge`](crates/android-bridge/src/lib.rs) — JNI
  0.21 scaffold tests against the pure-Rust
  `KChatBridgeHandle` (initialize / send-text round-trip,
  search, edit, `delete_for_me` / `delete_for_everyone`,
  `get_conversation_messages` pagination,
  `ingest_remote_messages` `next_cursor` propagation, plus
  the unknown-platform / wrong-key-length / invalid-UUID
  error paths and a compile-time signature-stability test
  for the `Java_com_kchat_core_KChatBridge_*` entry points).
* [`transport`](crates/core/src/transport/mod.rs) — unit tests
  for both transport surfaces: the narrower **`DeliveryClient`**
  used by `ingest_remote_messages` (`TransportError` `Display`
  strings, `FetchResult::default()` empty-page shape,
  object-safety pin via `Box<dyn DeliveryClient>`, and the
  `MockDeliveryClient` staged-response / cursor recording /
  panic-on-unexpected-cursor behaviour), and the broader
  **`TransportClient`** for Phases 2–4 (object safety,
  serde round-trips for `FetchMessagesResponse` /
  `BlobUploadHandle` / `ChunkReceipt` /
  `CommitBlobResponse` / `EncryptedManifest` / `BlobClass`,
  and `NoopTransportClient` returning
  `Error::NotImplemented("transport")` from every method —
  message fetch, blob upload init / chunk / commit / range
  fetch, archive manifest + segment fetch, and
  index-shard fetch).
* [`lib.rs`](crates/core/src/lib.rs) — public API type
  construction, default `SearchScope::IncludeCold`, P0–P5 ordering
  on `HydrationReason`, `Error` variant `Display` strings
  (including the new `Error::NotImplemented(&'static str)` so
  callers can pattern-match on missing capabilities), plus serde
  round-trip for the Phase-1 placeholder result types
  `HydratedMessage`, `BackupResult`, `OffloadResult`,
  `RestoreResult`, and the `BackupSource` input type.
* Integration tests under
  [`crates/core/tests/`](crates/core/tests/) — cross-language
  Pattern C vectors, manifest signing, key-wrap-by-hierarchy-root,
  the [multilingual FTS5 search
  round-trip](crates/core/tests/multilingual_search.rs) covering
  Latin / Cyrillic / Han / Hiragana-Katakana / Arabic / Thai /
  Devanagari / mixed-script messages, and the [combined FTS5 +
  fuzzy multilingual
  suite](crates/core/tests/multilingual_fuzzy_search.rs)
  exercising Latin / Cyrillic / Arabic / Thai trigram typo
  recovery, CJK bigram match, mixed-script same-row hits via two
  different queries, cross-engine deduplication, exact-vs-fuzzy
  ranking, and `conversation_filter` / `sender_filter` narrowing
  of fuzzy candidates. CJK and Thai word-level FTS searches
  require an ICU-linked SQLCipher build and soft-skip on the
  bundled `unicode61`-only configuration; the fuzzy half runs
  unconditionally because the n-gram tokenizer is pure Rust.

> SQLCipher is bundled by `rusqlite`'s
> `bundled-sqlcipher-vendored-openssl` feature, so `cargo test` does
> not need a system SQLCipher / OpenSSL install. The bundled build
> ships without ICU; the schema bring-up automatically falls back to
> `tokenize = 'unicode61 remove_diacritics 2'` and the multilingual
> integration test marks the CJK / Thai cases as soft-skipped
> instead of failing.

The workspace ships four crates: `kchat-core` (platform-agnostic
logic), and three thin bridges (`kchat-ios-bridge`,
`kchat-android-bridge`, `kchat-desktop`). The non-`crypto` /
non-`formats` / non-`search::tokenizer` / non-`local_store` /
non-`message::processor` modules in `kchat-core/src/` are stubbed
and filled in across Phases 2–7 (see
[docs/PHASES.md](docs/PHASES.md)).

### Cross-language interop

The Pattern C convergent-encryption path must produce **bit-identical**
ciphertext to the Go SDK at
`kennguy3n/zk-object-fabric/encryption/client_sdk/`. The contract is
locked by the test vectors in
`crates/core/tests/pattern_c_interop_vectors.json`, regenerated from
the Go SDK by `tests/generate_vectors/main.go`:

```sh
cd tests/generate_vectors
go run . > ../../crates/core/tests/pattern_c_interop_vectors.json
cd ../..
cargo test -p kchat-core --test pattern_c_interop_vectors
```

---

## What it is

This repository implements the storage, indexing, archive, backup,
offload, rehydration, and search engine that lives **inside** the
KChat client app on every supported platform. KChat itself owns the
MLS messaging layer; this library starts where MLS hands off
decrypted plaintext, and ends where the KChat UI reads timeline
rows and search results.

The implementation is a single Rust workspace. iOS gets a Swift
package generated by [UniFFI](https://mozilla.github.io/uniffi-rs/);
Android gets a Kotlin/Java binding via JNI; macOS and Windows
consume the same Rust crate natively. There is one source of truth
for crypto, schema, search, and state machines — written once in
Rust, exercised by cross-platform test vectors, and shipped to
every platform with a thin idiomatic wrapper.

## Privacy boundary

The KChat backend is treated as an **untrusted encrypted storage
and delivery service**. Everything the backend sees is ciphertext
or coarse server-safe routing metadata.

| The backend MAY store                            | The backend MUST NOT store                        |
| ------------------------------------------------ | ------------------------------------------------- |
| MLS ciphertext                                   | Plaintext messages                                |
| Encrypted media chunks                           | Search tokens, embeddings, OCR text               |
| Encrypted archive segments                       | Media keys (`K_asset`)                            |
| Encrypted search index shards                    | Backup keys (`K_backup_root` and derivatives)     |
| Encrypted backup manifests                       | Filenames, captions, alt text, transcripts        |
| Server-safe routing metadata (sizes, timestamps) | Plaintext content of any kind                     |

All encryption, decryption, indexing, search, archive segment
construction, backup construction, restore, and offload decisions
happen **on-device**. Any architectural change that would shift
plaintext or derived plaintext (tokens, embeddings, OCR text) onto
the backend is a privacy regression and is rejected.

To further reduce metadata leakage, the archive rehydration path
uses **batch-by-bucket prefetch**: when any segment in a
`(conversation_id, time_bucket)` is needed, all segments for that
pair are fetched, coarsening the access-pattern signal. An optional
**dummy request padding** mode (`privacy_level = "high"`) mixes
real fetches with decoy requests. Archive keys are
**epoch-rotated** (`K_archive_epoch`) so that a key compromise
limits the blast radius to the current epoch rather than the full
history. See [docs/PROPOSAL.md §2.1 and §5.6](docs/PROPOSAL.md).

## Four-store model

KChat persistence is split into four logically distinct stores. The
first three are interactive: the user reads from them in the normal
chat UI. The fourth is non-interactive: it exists only so a new or
wiped device can return to the steady state of the first three.

| Store              | Purpose                                                | Location                                                                | Interactive? |
| ------------------ | ------------------------------------------------------ | ----------------------------------------------------------------------- | ------------ |
| Local store        | Fast UX, search, timeline, thumbnails                  | Device (SQLCipher + encrypted files)                                    | Yes          |
| Delivery store     | MLS message fanout and short-term retention            | KChat backend (PostgreSQL)                                              | Yes          |
| Personal archive   | Scroll-back, lazy rehydration, storage offload         | KChat backend (PostgreSQL encrypted blobs) or ZK Object Fabric (S3 API)¹ | Yes          |
| Backup vault       | Disaster recovery / new-device restore                 | iCloud / Android backup / KChat encrypted backup (ZK Object Fabric)     | No           |

¹ Media originals may optionally route to user cloud storage
(iCloud / Google Drive / ZK Object Fabric) via the `MediaBlobSink`
trait to reduce backend storage costs. Thumbnails, archive
segments, and search index shards stay on the KChat backend or
ZKOF. See [docs/PROPOSAL.md §5.7](docs/PROPOSAL.md).

The four-store split is a hard architectural rule. Backup and
archive serve different purposes and have different shapes: an
archive must support per-conversation, per-time-bucket scroll-back
on a live device, while a backup only ever has to reproduce a
working steady state on a fresh device. Conflating them is one of
the standard ways multilingual chat clients end up with bad
scroll-back UX or oversized platform backups. See
[docs/PROPOSAL.md §5–§6](docs/PROPOSAL.md) and
[docs/ARCHITECTURE.md §3](docs/ARCHITECTURE.md) for the full
treatment.

## Multilingual

KChat is not English-only. Every text-processing path in this
library — tokenization, full-text search, fuzzy matching, OCR,
audio transcription, and embeddings — assumes mixed-language
content from day one.

| Concern                  | Approach                                                                                                                            |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| Tokenization (FTS5)      | SQLite FTS5 with **ICU tokenizer** (`tokenize = 'icu'`); falls back to `unicode61` only if ICU is unavailable on the platform.      |
| Fuzzy matching           | Trigrams for Latin / Cyrillic / Greek; bigrams for CJK (Chinese, Japanese, Korean); script-aware Levenshtein.                       |
| Text embeddings          | `XLM-R` (100+ languages, ~40–50 MB INT4 / ~80–100 MB INT8 ONNX) — same encoder used by `kennguy3n/slm-guardrail`, unifying the text encoder across the platform. INT4 default on tight-storage devices (low-end Android, Windows tablets); INT8 default on desktop and flagship. English-only MiniLM-L6 is **rejected**. |
| OCR                      | Apple Vision (18+ languages) on iOS / macOS; ML Kit Text Recognition v2 (50+ languages) on Android; multilingual fallback on desktop. |
| Audio transcription      | `Whisper-base` via Apple MLX on Apple Silicon (`mlx-community/whisper-base-mlx`, preferred — Neural Engine) or ~140 MB INT8 ONNX on other platforms; `Whisper-tiny` (~75 MB) on low-end Android. Gated on battery and thermal state. |
| Mixed-script messages    | A single message may interleave scripts (e.g. `Meeting at 3pm 会議室で`). ICU and the ML stack handle this natively per run.        |

## Tech stack

- **Rust** core, single workspace; one codebase for iOS, Android,
  macOS, and Windows.
- **UniFFI** for the iOS Swift package (and the iOS extension
  targets that ship the same binary).
- **JNI** for the Android Kotlin / Java binding.
- **Native Rust** on macOS and Windows (no FFI bridge needed).
- **SQLCipher** for the encrypted on-device database.
- **SQLite FTS5 + ICU tokenizer** for multilingual full-text search.
- **HNSW** (in-Rust, e.g. `instant-distance` or `hnsw_rs`) for
  approximate vector search.
- **ONNX Runtime** via the [`ort`](https://crates.io/crates/ort)
  crate for on-device ML inference: `XLM-R` text embeddings
  (~40–50 MB INT4 / ~80–100 MB INT8), `MobileCLIP-S2` image / video
  embeddings (~40 MB INT4 / ~80 MB INT8), `Whisper-base` (~140 MB)
  / `Whisper-tiny` (~75 MB) audio transcription. INT4 quantization
  uses ONNX Runtime's `MatMulNBits` and is supported on the
  embedding models only — Whisper stays at INT8. On Windows, ONNX
  Runtime uses the DirectML EP when a compatible GPU is available
  and falls back to the CPU EP otherwise (best-effort session
  creation; see `docs/ARCHITECTURE.md §11.4`).
- **BLAKE3** for content hashing (matches `kennguy3n/zk-object-fabric`'s
  Pattern C convergent dedup so backup interop is bit-identical).
- **XChaCha20-Poly1305** as the default AEAD; **AES-256-GCM** as
  the platform-accelerated alternative for hot paths where AES-NI
  / ARM Crypto Extensions are present.
- **CBOR** for wire formats (manifests, segments, descriptors); the
  format is documented and versioned, never an opaque
  language-specific blob.
- **zstd** for segment-level compression before encryption.

## Relationship to `kennguy3n/zk-object-fabric`

ZK Object Fabric is the optional encrypted backup storage backend
for this library. The relationship is intentionally narrow and
strictly client-side:

- KChat uses ZK Object Fabric's **S3-compatible API** as one of
  several backup sinks (alongside iCloud, Android Auto Backup,
  Android Large Backup, and Storage Access Framework).
- Backup-time deduplication uses **Pattern C** (client-side
  convergent encryption) from
  `kennguy3n/zk-object-fabric/docs/INTEGRATION.md` §5. The KChat
  client SDK derives a convergent DEK from the plaintext content
  and the tenant ID, encrypts with deterministic per-chunk
  nonces, and the gateway dedups on `BLAKE3(ciphertext)` without
  ever seeing plaintext. Same plaintext, same tenant ⇒ one stored
  copy. Different tenants ⇒ different DEKs ⇒ different ciphertext
  by construction.
- Cross-tenant deduplication is excluded by design (it would be a
  side channel). KChat inherits this rule unmodified.
- The Rust crypto module **must produce bit-identical ciphertext**
  to the Go reference at
  `kennguy3n/zk-object-fabric/encryption/client_sdk/` for any
  object stored under Pattern C. Cross-language test vectors enforce
  this — see Phase 0 in [docs/PHASES.md](docs/PHASES.md).

The exact binding points:

| Construct                                  | Rust must match Go's                                                                                          |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Convergent DEK                             | `HKDF-SHA256(secret = BLAKE3(plaintext), salt = tenant_id, info = "zkof-convergent-dek-v1")`                  |
| Convergent nonce                           | `HKDF-SHA256(secret = DEK, salt = nil, info = "zkof-nonce-v1" \|\| u64_be(chunk_index))[..24]`                |
| Chunk size (Pattern C)                     | 16 MiB (matches `client_sdk.DefaultChunkSize`)                                                                |
| Cipher                                     | XChaCha20-Poly1305 (24-byte nonce, 16-byte Poly1305 tag), AAD = empty                                         |
| Frame layout                               | `[24-byte nonce][4-byte BE ciphertext length][ciphertext+tag]`                                                |

ZK Object Fabric can also serve as the **personal archive backend**
(not just backup). When `archive_backend = "zkof"` is configured,
archive segment upload, download, and manifest storage route to the
S3 API instead of the KChat backend's blob service. This separates
archive ciphertext from the KChat operator, reducing legal-compulsion
and data-accumulation risks. The archive uses KChat's own per-chunk
AAD scheme (§8.3 of PROPOSAL.md), not Pattern C — the two paths
remain distinct.

ZKOF can additionally serve as a **media blob sink** through the
`MediaBlobSink` trait (see [docs/PROPOSAL.md §5.7](docs/PROPOSAL.md)
and §10.2). Setting `media_blob_sink = StorageSink::ZkObjectFabric { … }`
on `KChatCoreConfig` routes media originals to ZKOF independently
of the archive backend selection — ZKOF is then the platform-neutral
target for households that span iOS and Android (no iCloud / Drive
vendor lock-in). Backup, archive, and media sinks are three
independent ZKOF use cases; a deployment can use any subset.

For all other paths (KChat's own backend blob service, archive
segments, search index shards) KChat layers on a **per-chunk AAD**
binding the chunk to its blob and Merkle root — that scheme is
documented in [docs/PROPOSAL.md §8](docs/PROPOSAL.md) and is
deliberately distinct from the Pattern C wire format.

## Relationship to KChat

KChat is a downstream consumer, not a sibling. The library has no
opinion on UI, push notifications, contact discovery, or the wire
shape of MLS — those are all KChat's problem. The library only
guarantees that, given an MLS-decrypted message and its
descriptor, every subsequent persistence, indexing, archival,
backup, offload, rehydration, and search operation on that message
will preserve KChat's privacy boundary.

The Rust core defines the **public API surface** that the Swift,
Kotlin, and desktop apps embed. See
[docs/PROPOSAL.md §12](docs/PROPOSAL.md) for the API trait.

## Target repo structure

```
chat-storage-search/
  Cargo.toml                      # workspace root
  crates/
    core/                         # platform-agnostic Rust core
      src/
        lib.rs
        config.rs
        local_store/              # encrypted local DB, timeline, bodies, media cache, indexes
          mod.rs
          schema.rs               # SQLCipher schema (skeleton, body, media_asset, FTS, vector, media_index)
          message_skeleton.rs
          message_body.rs
          media_asset.rs
          search_index.rs         # FTS5 + fuzzy + vector index management
          backup_event_journal.rs
        message/                  # send/receive pipeline, outbox, idempotency
          mod.rs
          processor.rs
          outbox.rs
        media/                    # thumbnailing, chunk encryption, upload/download, media indexing
          mod.rs
          processor.rs
          chunker.rs
          thumbnail.rs
          sinks/                  # media-blob storage sinks (PROPOSAL.md §5.7)
            mod.rs                # MediaBlobSink trait + NoopMediaBlobSink
            icloud.rs             # iCloud (CloudKit file storage) — Phase 3
            google_drive.rs       # Google Drive (Drive API) — Phase 3
            zk_fabric.rs          # ZK Object Fabric (S3 PutObject/GetObject) — Phase 3
        search/                   # search engine — all local, no server search
          mod.rs
          text_search.rs          # FTS5 exact + prefix + BM25
          fuzzy_search.rs         # trigram / edit-distance fuzzy (multilingual)
          semantic_search.rs      # vector embedding search (HNSW)
          media_search.rs         # OCR, image/video/audio search
          query_engine.rs         # unified query parser + fan-out + merge + rerank
          ranking.rs              # ranking formula (exact + BM25 + fuzzy + semantic + recency)
          tokenizer.rs            # ICU-aware multilingual tokenizer
        archive/                  # personal encrypted archive (interactive cold store)
          mod.rs
          segment_builder.rs
          manifest.rs
          rehydration.rs
        backup/                   # backup vault (disaster recovery)
          mod.rs
          event_journal.rs
          segment_builder.rs
          manifest.rs
          sinks/
            mod.rs
            icloud.rs
            android_backup.rs     # Auto Backup + Large Backup + SAF
            zk_fabric.rs          # ZK Object Fabric S3 API (Pattern C)
        offload/                  # storage pressure, eviction, pinned chats, cache pruning
          mod.rs
          budget.rs
          eviction.rs
          scoring.rs              # eviction score formula
        restore/                  # manifest restore, key recovery, skeleton-first restore
          mod.rs
          state_machine.rs
          manifest_verifier.rs
        crypto/                   # encryption aligned with zk-object-fabric + KChat key hierarchy
          mod.rs
          key_hierarchy.rs        # K_user_master → K_archive_root, K_backup_root, K_search_root
          convergent.rs           # Pattern C convergent encryption (BLAKE3 + HKDF + XChaCha20-Poly1305)
          content_hash.rs         # BLAKE3 content hashing
          aead.rs                 # XChaCha20-Poly1305 / AES-256-GCM chunk sealing
          key_wrap.rs             # AES-256-KW (RFC 3394) for K_asset wrapping
        formats/                  # CBOR wire-format types (Phase 0 — see ARCHITECTURE.md §2)
          mod.rs                  # BackupSegmentFrame / ArchiveSegmentFrame / SegmentType
          manifest.rs             # BackupManifest / ArchiveManifest + Ed25519 sign / verify / chain
          media_descriptor.rs     # MediaDescriptor (asset_id, blob_id, Merkle root, wrapped K_asset)
          search_shard.rs         # SearchIndexShard (text / fuzzy / vector / media)
        models/                   # on-device ML model management
          mod.rs
          embeddings.rs           # multilingual text embedding (XLM-R via ONNX)
          clip.rs                 # MobileCLIP-S2 image/video embeddings (ONNX)
          whisper.rs              # Whisper-base / Whisper-tiny audio transcription. MLX (mlx-community/whisper-base-mlx) preferred on Apple Silicon; ONNX (multilingual) fallback on other platforms.
          ocr.rs                  # platform OCR bridge (Vision on iOS, ML Kit on Android)
          model_manager.rs        # model download, versioning, quantization
        transport/                # backend API client for blob/archive/delivery
          mod.rs
          blob_client.rs          # chunked encrypted blob upload/download
          archive_client.rs       # archive manifest/segment fetch
          delivery_client.rs      # MLS message fetch (cursor-based)
        scheduler/                # background job scheduling
          mod.rs                  # iOS BGTaskScheduler / Android WorkManager bridge
    ios-bridge/                   # UniFFI Swift bindings
    android-bridge/               # JNI Kotlin bindings
    desktop/                      # desktop (macOS, Windows) native layer
  docs/
    PROPOSAL.md
    ARCHITECTURE.md
    PHASES.md
    PROGRESS.md
```

## Documentation

- [docs/PROPOSAL.md](docs/PROPOSAL.md) — full technical design,
  scope, key hierarchy, state machines, search architecture,
  chunk and AEAD specs, performance targets, risk register.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system diagrams,
  crate dependency graph, four-store data flow, schema, search
  pipeline, crypto flows, backup/restore sequences.
- [docs/PHASES.md](docs/PHASES.md) — phased delivery plan
  (Phase 0 → Phase 8) with explicit decision gates.
- [docs/PROGRESS.md](docs/PROGRESS.md) — phase-gated tracker
  matching `kennguy3n/zk-object-fabric/docs/PROGRESS.md`.
- [docs/BLOG_PRIVACY_ARCHITECTURE.md](docs/BLOG_PRIVACY_ARCHITECTURE.md) — privacy architecture blog post.

## License

Proprietary — All Rights Reserved. See [LICENSE](LICENSE).
