# KChat Storage & Search — Phased Delivery Plan

**License**: Proprietary — All Rights Reserved. See [LICENSE](../LICENSE).

This document is a phase-gated delivery plan. Each phase has an
explicit goal, a checklist, and a decision gate. Do not skip to the
next phase until the current phase's gate has been met. Status is
tracked in [PROGRESS.md](PROGRESS.md).

> **Note:** Checklist items in this document are updated to reflect
> completion status. For detailed implementation notes and changelogs,
> see [PROGRESS.md](PROGRESS.md).

For the technical design, see [PROPOSAL.md](PROPOSAL.md). For the
system architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Phase 0: Protocol and Test Vectors

**Goal**: Lock the shared binary formats, crypto specs, and
cross-platform / cross-language test vectors **before** writing
application code. Phase 0 is what prevents quiet drift between
iOS, Android, desktop, and the ZK Object Fabric backup path.

Checklist:

- [x] Shared binary formats spec (CBOR for wire payloads; internal
      Rust structs ↔ CBOR mapping).
- [x] Crypto container spec (AEAD construction, AAD format, chunk
      layout) covering both KChat-internal AAD (PROPOSAL §8.3) and
      ZK Object Fabric Pattern C (empty AAD; PROPOSAL §8.4).
- [x] Manifest spec (backup manifest, archive manifest;
      `previous_manifest_hash` chain; Ed25519 signature).
- [x] Media descriptor spec (`asset_id`, `K_asset`, mime type,
      sizes, Merkle root, blob ID, chunk count).
- [x] Search index shard spec (text, fuzzy, vector, media index
      shard frames; encryption envelope; coarse-bucket addressing).
- [x] Multilingual tokenization spec (ICU configuration, script-
      specific rules, fallback behavior, fuzzy-index granularity
      per script).
- [x] iOS / Android / desktop / Rust cross-platform crypto test
      vectors: same plaintext + keys + nonce ⇒ identical ciphertext,
      tag, and Merkle root in every binding.
- [x] **ZK Object Fabric interop test vectors**: Rust output for
      Pattern C must match Go output from
      `kennguy3n/zk-object-fabric/encryption/client_sdk/` byte-for-byte
      across `DeriveConvergentDEK`, `deriveConvergentNonce`,
      chunk framing, and end-to-end `EncryptObject`.
- [x] Rust workspace scaffold (`crates/core`, `crates/ios-bridge`,
      `crates/android-bridge`, `crates/desktop`).
- [x] CI pipeline: Rust build + test, iOS build (UniFFI codegen
      sanity), Android build (JNI codegen sanity), desktop build,
      cross-language test-vector run.

> **Note (2026-05-03):** The epoch-rotated archive key derivation
> (`K_archive_epoch`) is an additive extension to the key hierarchy
> locked in this phase. It uses a new HKDF info string
> (`"kchat-archive-epoch-v1" || epoch_id`) and does not modify any
> existing derivation path or test vector. The spec, implementation,
> and test vectors for epoch keys land with Phase 3.

**Decision gate**: Crypto test vectors pass across Rust, Swift (via
UniFFI), Kotlin (via JNI), and Go (zk-object-fabric SDK). A
deviation in **any** binding blocks Phase 1.

---

## Phase 1: Local Store + Text Search + MLS Integration

**Goal**: Basic encrypted local storage with multilingual text
search and MLS-plaintext ingest. The library can be embedded in
the iOS and Android apps and round-trip text messages.

Checklist:

- [ ] SQLCipher integration for encrypted on-device storage; key
      `K_local_db` wrapped by Keychain / Keystore / DPAPI.
- [ ] Local schema (`conversation`, `message_skeleton`,
      `message_body`, `media_asset`, `backup_event_journal`,
      `archive_segment_map`, `restore_state`) — see
      [ARCHITECTURE.md §4](ARCHITECTURE.md).
- [ ] Message processor: ingest MLS-decrypted application messages,
      outbox, idempotency, dedup against client message ID.
- [ ] FTS5 with **ICU tokenizer** (`tokenize = 'icu'`) for
      multilingual full-text search; documented fallback to
      `unicode61 remove_diacritics 2`.
- [ ] Structured search (sender, date range, conversation, content
      kind).
- [ ] Body state machine (`local_plain_available`,
      `local_encrypted_available`, `delivery_store_only`,
      `deleted_for_me`, `deleted_for_everyone`, `unavailable`).
- [x] UniFFI bridge: generated Swift package consumable from
      KChat.app and any iOS extensions sharing the local store.
      _(Phase-1 scaffold at `crates/ios-bridge/`; production
      Swift packaging lands in Phase 2.)_
- [x] JNI bridge: idiomatic Kotlin façade over the generated JNI
      bindings. _(Phase-1 scaffold at `crates/android-bridge/`;
      production Kotlin packaging lands in Phase 2.)_
- [x] Core public API surface: `initialize`, `register_device`,
      `send_text`, `ingest_remote_messages`, `search`.
      _(`register_device` is a Phase-1 stub that returns
      `Error::NotImplemented`; the MLS layer wires in the real
      payload later in Phase 1 / Phase 2.)_
- [ ] Unit + integration test suite covering multilingual corpora
      (Latin, Cyrillic, CJK, Arabic, Hebrew, Thai, Devanagari, mixed-
      script messages).
- [ ] Performance validation: insert text < 20 ms p95; search recent
      < 150 ms p95.

**Decision gate**: Text messages can be stored, searched
(multilingual), and round-tripped through MLS ingest on both iOS
and Android with the targeted performance numbers.

---

## Phase 2: Media Encryption and Blob Service

**Goal**: Chunked encrypted media upload / download, thumbnailing,
and a local media cache that obeys the offload contract.

Checklist:

- [ ] Media processor: thumbnail generation, chunk encryption with
      a random `K_asset` per asset.
- [ ] Chunked encrypted blob upload / download in the transport
      client (`POST /v1/blobs/init`, `PUT chunks/{idx}`,
      `POST .../commit`, `GET ...?range=`).
- [ ] Media descriptor distribution through MLS (asset_id, K_asset,
      mime, sizes, Merkle root, blob_id, chunk_count).
- [ ] Local media cache with LRU eviction; encrypted on disk.
- [ ] Resume-upload (re-upload only missing chunks; idempotent
      commit on retry).
- [ ] Chunk integrity verification: per-chunk SHA-256, whole-object
      Merkle root (BLAKE3), AEAD tag.
- [ ] Media state machine (`thumbnail_only`, `original_local`,
      `remote_original`, `download_in_progress`, `evicted`,
      `deleted`).
- [ ] Size-class padding for metadata privacy (PROPOSAL §8.2).
- [ ] Per-chunk AEAD AAD construction (`KCHAT_BLOB_CHUNK_V1` …
      PROPOSAL §8.3).
- [ ] Multilingual filename / caption handling (UTF-8 canonicalization;
      no English-only assumptions).
- [ ] `StorageSink` enum and `ArchiveBackend` enum in config
      (`crates/core/src/config.rs`). See PROPOSAL.md §5.7.
- [ ] `storage_sink` field on `MediaDescriptor` (CBOR,
      `#[serde(default)]` for backward compat).
- [ ] `storage_sink` column on `media_asset` table (schema
      migration with `DEFAULT 'kchat_backend'`).
- [ ] `MediaBlobSink` trait: object-safe, `Send + Sync`, with
      `upload_media_chunks` / `fetch_media_chunk` /
      `delete_media_blob`. See PROPOSAL.md §5.7 and §10.2.
- [ ] `NoopMediaBlobSink` placeholder returning
      `Error::NotImplemented("media_blob_sink")` from every method.
- [ ] Media upload routing: thumbnails always go to the
      `TransportClient` (KChat backend); originals route to the
      configured `MediaBlobSink` (default: `TransportClient`
      fallback when `media_blob_sink = None`).
- [ ] Media rehydration routing: `media_asset.storage_sink`
      determines which `MediaBlobSink` implementation to fetch
      from on tap / scroll-back.

**Decision gate**: Media can be encrypted, chunked, uploaded,
downloaded, range-fetched, verified, and displayed (thumbnail +
original) on iOS, Android, macOS, and Windows. Resumed uploads
never duplicate completed chunks.

---

## Phase 3: Personal Archive and Offload

**Goal**: Interactive cold storage with scroll-back rehydration and
storage-pressure management.

> 2026-05-03: Foundation work has started. The archive event
> journal, archive segment builder, epoch-rotated archive key
> derivation, and the offload modules
> (`offload::{budget, scoring, eviction, hydration}`) all landed
> alongside `CoreImpl::hydrate_message` and
> `CoreImpl::enforce_storage_budget`. The remote archive fetch
> path (manifest reader / segment download / replay) and the
> archive segment uploader against `TransportClient` are queued
> for the next milestone. See `docs/PROGRESS.md` Phase 3 for the
> detailed checklist.
>
> 2026-05-03 (later in the day): Phase-2 finishing pass + Phase-3
> foundation: the archive event journal is wired into
> `MessagePersister` (so every persist / edit / delete /
> `send_media` writes an `ArchiveEvent` inside the existing
> SAVEPOINT), `offload::eviction::collect_eviction_candidates`
> is wired into `CoreImpl::enforce_storage_budget` (replaces the
> previous `Vec::new()` placeholder),
> `offload::scoring::compute_eviction_score` returns `f64::MIN`
> on pinned candidates, the archive manifest chain builder
> (`archive::manifest_builder`) and segment upload orchestrator
> (`archive::upload::upload_archive_segment`) landed, the archive
> state machine has a batched `update_archive_state` gated by
> `try_transition`, the hydration queue is wired into
> `CoreImpl` (`hydrate_message` enqueues every request mapped to
> P0–P5 by `parse_hydration_reason`;
> `CoreImpl::enqueue_prefetch_window` exposes the P3 viewport
> widener), and `archive::prefetch::batch_prefetch_bucket` is the
> first single-bucket transport hop per PROPOSAL §5.6. The
> end-to-end pipeline is exercised by the new
> `crates/core/tests/archive_pipeline.rs` integration test, plus
> `crates/core/tests/epoch_key_derivation.rs` for the per-epoch
> key vectors.

Checklist:

- [x] Archive event journal (every durable mutation writes an
      archive event). _(Wired into `MessagePersister`'s
      `persist_ingested_message`, `persist_outbox_entry`,
      `edit_message`, `delete_for_me`, `delete_for_everyone`, and
      into `CoreImpl::send_media` via `ArchiveEventType::MediaReceived`,
      all inside the existing SAVEPOINT alongside the
      `BackupEvent` write.)_
- [~] Archive segment builder: per-conversation, per-time-bucket
      segments for `message_delta`, `timeline_skeleton`,
      `media_key_delta`, `search_text_index`,
      `search_vector_index`, `media_index`, `checkpoint`.
      _(`archive::segment_builder::ArchiveSegmentBuilder::build_segment`
      builds `BuiltSegment` for `MessageDelta`; the other segment
      types are still queued on the same code path.)_
- [~] Archive manifest chain (generation N+1 referencing N via
      `previous_manifest_hash`; Ed25519 signature).
      _(`archive::manifest_builder::ArchiveManifestBuilder` builds
      genesis + chained manifests, signs with Ed25519, and
      AEAD-seals under `K_archive_manifest` derived from the
      active epoch key.)_
- [~] Encrypted segment upload to the KChat backend's blob service.
      _(`archive::upload::upload_archive_segment` drives
      `TransportClient::init_blob_upload → upload_chunk →
      commit_blob`; `persist_segment_map_row` records the result
      in `archive_segment_map` with `state = 'archive_uploaded'`.)_
- [~] Whole-object Merkle-root verification after upload commit.
      _(`upload_archive_segment` rejects mismatched
      `commit_blob.merkle_root` before any state-machine
      transition.)_
- [~] Archive state machine (`not_archived` → `archive_pending` →
      `archive_uploaded` → `archive_verified` → `archive_compacted`).
      _(`local_store::db::update_archive_state` validates every
      row's predecessor via `ArchiveState::try_transition` before
      issuing a batch UPDATE; rejects illegal jumps.)_
- [~] Storage budget enforcement (`enforceStorageBudget`).
      _(`CoreImpl::enforce_storage_budget` now harvests
      candidates via `collect_eviction_candidates` and runs them
      through `plan_eviction` / `execute_eviction`.)_
- [~] Eviction scoring formula (PROPOSAL §5.4). _(With pinned-row
      guard returning `f64::MIN` so the scoring path is also
      pin-safe even if a pinned row leaks past the SQL filter.)_
- [x] Eviction priority order: video → documents → images → voice →
      thumbnails (under severe pressure) → cold text bodies (under
      extreme pressure). _(Carried by `CONTENT_KIND_WEIGHTS` plus
      `plan_eviction_with_pressure`: originals are eligible at
      `Warning+`, thumbnails at `Critical+`, cold text bodies at
      `Extreme` only.)_
- [x] Pinned-chat / pinned-message exclusion. _(Three-deep:
      `collect_eviction_candidates` filters
      `conversation.pinned = 0`, `plan_eviction` skips pinned rows
      before scoring, and `compute_eviction_score` returns
      `f64::MIN` if a pinned candidate still reaches it.)_
- [x] Timeline-skeleton rehydration on scroll-back (no scroll-jump
      on update). _(`LocalStoreDb::rehydrate_message_body` does an
      `INSERT OR REPLACE` on `message_body` plus a `body_state`
      UPDATE in one SAVEPOINT without touching `created_at_ms` /
      `received_at_ms`, then re-indexes into `search_fts` and
      `search_fuzzy_words`. Wired into `CoreImpl::hydrate_message`.
      The bucket-level scroll-back rehydration sits on
      `CoreImpl::rehydrate_timeline_skeletons` —
      `batch_prefetch_bucket` → `archive::download::decrypt_archive_segment`
      → `LocalStoreDb::upsert_skeleton_from_archive` (`INSERT OR
      IGNORE` so existing local rows always win), landing
      archive-only stub skeletons at
      `BodyState::RemoteArchiveOnly`.)_
- [x] Lazy media rehydration on tap. _(`media::download::rehydrate_media_asset`
      reads `media_asset.{blob_id, storage_sink, chunk_count,
      merkle_root, wrapped_k_asset}`, unwraps `K_asset` via
      `K_local_db`, drives the chunked download through
      `TransportClient` or the configured `MediaBlobSink` based
      on `storage_sink`, verifies the BLAKE3 root, and flips
      `media_state` to `original_local`. The on-tap UI flow
      surfaces through `CoreImpl::rehydrate_media_for_message` —
      resolves the asset by `message_id` via
      `LocalStoreDb::get_media_asset_by_message`, and
      `hydrate_message` escalates the queued
      `HydrationReason` to `MediaFullScreen` whenever the
      attached asset is `MediaState::Evicted`.)_
- [~] Prefetch window management (viewport ± 100–150 messages).
      _(`HydrationQueue::enqueue_prefetch_window` plus
      `CoreImpl::enqueue_prefetch_window` widen a viewport into
      P3 prefetch enqueues.)_
- [x] Hydration priority queue (P0 → P5). _(Wired into
      `CoreImpl::hydrate_message`; reasons map through
      `parse_hydration_reason` (`search_result_tap` → P0 …
      `idle_fill` → P5; unknown reasons collapse to P5).)_
- [~] Epoch-rotated archive key derivation: `K_archive_root` →
      `K_archive_epoch(epoch_id)` → `K_archive_segment` /
      `K_archive_manifest`. HKDF info =
      `"kchat-archive-epoch-v1" || epoch_id`. Default epoch
      cadence: monthly (matching `time_bucket`).
- [x] Epoch key lifecycle: current epoch key in memory; prior
      epoch keys wrapped under `K_archive_root` and recorded in
      the archive manifest chain. Optional epoch-key deletion
      for forward secrecy. _(`archive::epoch_keys::EpochKeyManager`:
      current epoch in `Zeroizing<[u8; 32]>`, prior keys wrapped
      via AES-256-KW; `rotate(new_epoch_id)` /
      `unwrap_prior_epoch_key` / `delete_epoch_key(epoch_id)` cover
      the lifecycle including forward-secrecy deletion.)_
- [x] Epoch key derivation test vectors (Rust): deterministic
      derivation, epoch rotation, wrapped-key round-trip,
      cross-epoch segment decrypt after manifest-chain unwrap.
      _(`crates/core/tests/epoch_key_derivation.rs` —
      `deterministic_epoch_derivation`,
      `different_epochs_produce_different_keys`,
      `epoch_key_wrap_unwrap_round_trip`,
      `cross_epoch_segment_decrypt`,
      `epoch_key_info_string_matches_spec`.)_
- [ ] ZK Object Fabric as optional archive backend: S3-compatible
      transport adapter for archive segment upload / download /
      manifest storage. Configured via `archive_backend = "zkof"`
      + ZKOF tenant credentials.
- [x] Archive backend routing: transport client routes archive
      operations to KChat backend or ZKOF based on configuration.
      Manifest index stored as a well-known S3 key when using ZKOF.
      _(`archive::routing::route_archive_upload` /
      `route_archive_download` / `route_manifest_upload` dispatch
      to either `TransportClient` or a `ZkofArchiveAdapter` based
      on `KChatCoreConfig::archive_backend`. The ZKOF adapter is
      backed by an `S3Client` trait with a `NoopS3Client` stub and
      maps the manifest index to a well-known `manifests/index`
      key.)_
- [~] Batch-by-bucket prefetch: on any archive segment miss, fetch
      all segments for the `(conversation_id, time_bucket)` pair.
      Reduces per-segment access-pattern metadata to per-bucket
      granularity. _(`archive::prefetch::batch_prefetch_bucket`
      queries `archive_segment_map` and streams every matching
      segment through `TransportClient::fetch_archive_segment`.)_
- [x] Dummy request padding (optional, off by default): mix real
      rehydration fetches with dummy fetches to random segment IDs.
      Enabled via `privacy_level = "high"`.
      _(`archive::privacy::{should_pad, compute_padding_count,
      generate_dummy_segment_id, pad_with_dummy_requests}` mint
      UUIDv4 dummies and interleave them with real ids;
      `archive::prefetch::batch_prefetch_bucket_with_padding`
      issues one fetch per id in the padded order and silently
      drops dummy errors. Off by default; enable via
      `KChatCoreConfig::privacy_level = High`.)_
- [ ] iCloud `MediaBlobSink` implementation (CloudKit file
      storage). See PROPOSAL.md §10.2.
- [ ] Google Drive `MediaBlobSink` implementation (Drive API via
      the Android / desktop platform bridge). See PROPOSAL.md
      §10.2.
- [x] ZK Object Fabric `MediaBlobSink` implementation (S3
      `PutObject` / `GetObject`). See PROPOSAL.md §10.2.
      _(`media::sinks::zk_fabric::ZkObjectFabricSink`: maps
      `upload_media_chunks` / `fetch_media_chunk` /
      `delete_media_blob` to per-chunk S3 keys of the form
      `media/{asset_id}/chunk-{idx:08}` against a configured
      bucket. The S3 client itself is a small `S3Client` trait
      with `NoopS3Client` stub; the actual HTTP / SDK
      implementation lands later.)_
- [x] Tiered eviction policy: media originals offload to the
      configured user cloud sink before archive segments offload
      to the KChat backend.
      _(`offload::eviction::EvictionTier` classifies each
      `EvictionCandidate` by `storage_sink`: `kchat_backend` →
      `FullEviction`, everything else → `CloudOffload`.
      `plan_tiered_eviction` runs a two-pass planner — drains the
      cloud-offload pool first and only falls through to the
      full-eviction pool if the cloud pass underruns the byte
      budget. Wired into `CoreImpl::enforce_storage_budget` and
      exercised end-to-end by
      `crates/core/tests/storage_budget_enforcement.rs`.)_
- [ ] `storage_backend` column on `archive_segment_map` for
      tracking which backend each segment lives on (`kchat_backend`
      or `zk_object_fabric`).

**Decision gate**: Messages and media can be offloaded to the
archive, rehydrated transparently on scroll-back and search-result
tap, and the storage budget is enforced. The timeline renders
skeletons immediately with lazy body / media fill, and indexes
remain resident across all eviction strata. Epoch key rotation is
exercised end-to-end (build segments across two epochs, rotate,
verify both epochs decrypt). ZKOF archive backend passes the same
segment upload / download / rehydration tests as the KChat backend.
Batch-by-bucket prefetch is the default rehydration mode. Media
originals can be uploaded to and fetched from at least one
user-cloud sink (iCloud or ZKOF) in addition to the KChat backend,
with `media_asset.storage_sink` round-tripped correctly.

---

## Phase 4: Backup and Restore

**Goal**: Incremental backup to platform sinks and skeleton-first
restore. After Phase 4 a wiped or new device can come back to a
working state.

Checklist:

- [ ] Backup event journal.
- [ ] Incremental backup segment builder.
- [ ] Backup manifest chain with Ed25519 signature.
- [ ] iOS iCloud backup sink (iCloud container file storage).
- [ ] Android backup sink strategy: Auto Backup for small recovery
      envelopes / manifest pointers; Large Backup or SAF for full
      data.
- [ ] **ZK Object Fabric backup sink** (S3 API; Pattern C convergent
      encryption; bit-identical interop with the Go SDK at
      `kennguy3n/zk-object-fabric/encryption/client_sdk/`).
- [ ] Backup compaction: daily deltas → weekly checkpoint → monthly
      prune of superseded deltas.
- [ ] Manifest chain verification on restore (signature +
      `previous_manifest_hash` walk).
- [ ] Skeleton-first restore: conversation list → timeline
      skeletons → search index shards → recent bodies → lazy media.
- [ ] Restore state machine (`identity_restored` → `root_keys_unwrapped`
      → `manifest_verified` → `skeleton_restored` →
      `search_restored` → `recent_messages_restored` →
      `media_lazy_restore_enabled` → `full_restore_complete`).
- [ ] Key recovery (device-to-device transfer, recovery key,
      passphrase). Server escrow remains off by default.
- [ ] Search index backup and restore (encrypted text / fuzzy /
      vector / media shards).
- [ ] Multilingual restore validation: corpora across CJK / Arabic /
      Hebrew / Thai / Devanagari / Cyrillic / Latin survive a full
      backup-restore cycle with FTS, fuzzy, and structured search
      results unchanged.

**Decision gate**: Full backup / restore cycle works on every
target platform. A new device renders the conversation list and
returns search hits within seconds, recent bodies within minutes,
and pulls media lazily on demand thereafter. Pattern C dedup against
ZK Object Fabric is verified by re-uploading identical content from
two different test devices in the same tenant and observing a single
stored copy on the gateway side.

---

## Phase 5: Search — Fuzzy + Encrypted Shards

**Goal**: Fuzzy matching across scripts, plus encrypted search
shards on the backend so cold (offloaded) buckets remain
searchable.

Checklist:

- [ ] Fuzzy token index: trigrams for Latin / Cyrillic / Greek /
      Devanagari / Tamil / Bengali / Hangul; bigrams for logographic
      CJK runs.
- [ ] Script-aware fuzzy matching: per-token script tag drives
      lookup; script-appropriate edit distance.
- [ ] Encrypted search shard archive (text and fuzzy index shards
      sealed with `K_text_index_shard`).
- [ ] Search shard fetch from the backend
      (`GET /v1/archive/index-shards?conversation_hash=&bucket=&type=`).
- [ ] Cold-result hydration: search hit on offloaded content →
      fetch shard → decrypt locally → search → hydrate body / media
      on tap.
- [ ] Unified query engine: parse → fan-out → merge → rerank.
- [ ] Ranking formula implementation (PROPOSAL §7.5).
- [ ] Mixed-language query handling: a single query may interleave
      scripts; both sides of the query reach the appropriate fuzzy
      index.
- [ ] Latency budget: encrypted shard fetch + decrypt + local
      search ≤ 1.5 s p95 over Wi-Fi for a one-month bucket.
- [ ] Batch shard prefetch by time bucket: when fetching encrypted
      index shards, fetch all shard types for the target
      `(conversation_hash, bucket)` in one batch to coarsen the
      metadata signal on the shard-listing endpoint.

**Decision gate**: Fuzzy search returns relevant hits across all
target scripts, including mixed-script queries. Cold content
offloaded to the archive is searchable via encrypted-shard fetch
and on-device decrypt without ever leaking the query string to the
backend.

---

## Phase 6: Media and Semantic Search

**Goal**: On-device ML for OCR, image / video / audio search, and
semantic text search — all multilingual.

Checklist:

- [ ] ONNX Runtime integration via the
      [`ort`](https://crates.io/crates/ort) crate.
- [ ] Multilingual text embedding model (`XLM-R`, ~80–100 MB INT8
      ONNX) wired through the search pipeline. Same encoder as
      `kennguy3n/slm-guardrail`, unifying the text encoder across
      the platform. English-only MiniLM-L6 is **rejected**.
- [ ] HNSW vector index for semantic text search.
- [ ] `MobileCLIP-S2` integration for image search (multilingual
      text→image, ~80 MB INT8 ONNX).
- [ ] Video keyframe sampling and `MobileCLIP-S2` embeddings.
- [ ] Whisper multilingual integration for voice-message transcription:
      Apple MLX (`mlx-community/whisper-base-mlx`) on Apple Silicon
      (preferred — Neural Engine, lower latency / battery cost);
      ONNX Runtime (`whisper-base` ~140 MB INT8, INT4 not supported
      for audio transcription) on all other platforms (Intel macOS,
      Windows, Android, Linux); `whisper-tiny` (~75 MB) on low-end
      Android. See PROPOSAL §7.6 / §7.7.
- [ ] Platform OCR bridge: Vision (`VNRecognizeTextRequest`) on
      iOS / macOS; ML Kit Text Recognition v2 on Android;
      `Windows.Media.Ocr` / Tesseract on Windows.
- [ ] Document text extraction (PDF, DOCX) with multilingual
      handling and page-level indexing.
- [ ] Resource-gated background processing: battery level, thermal
      state, charging, network type.
- [ ] Model manager: lazy download on first semantic-search use
      (MobileCLIP-S2, Whisper) or eager pre-load (XLM-R),
      versioning, INT8/INT4 quantization, integrity-checked
      artifacts, warm-up strategy.
- [ ] Encrypted vector / media index shard archive.
- [ ] On-device reranking with semantic similarity scores.
- [ ] Desktop support: macOS (Core ML), Windows (DirectML EP
      preferred, CPU EP fallback).
- [ ] Cross-pipeline embedding cache: reuse `XLM-R` embeddings from
      `kennguy3n/slm-guardrail` in the search pipeline. Cache key
      `(message_id, model_version = 'xlmr@v1')`; backed by the
      `search_vector` table; version-mismatch invalidates. Trait:
      `crate::models::embeddings::EmbeddingCache`. See PROPOSAL §7.6.1.
- [ ] INT4 quantization for `XLM-R` and `MobileCLIP-S2` via ONNX
      Runtime `MatMulNBits`. Benchmark cosine-similarity correlation
      against the INT8 baseline using the multilingual relevance
      regression suite. INT4 ships as the default on devices with
      tight storage budgets (low-end Android, Windows tablets);
      INT8 remains the default on desktop and flagship mobile.

**Decision gate**: Semantic search returns relevant multilingual
results across text, images, video, and audio on iOS, Android,
macOS, and CPU-only Windows. Cross-platform parity is verified by
the Phase 0 test vectors plus a multilingual relevance regression
suite.

---

## Phase 7: Desktop + Optimization

**Goal**: Production-ready performance, full desktop integration,
and an explicit failure-test matrix.

Checklist:

- [ ] macOS native integration (Spotlight anchors for app-internal
      results; `NSBackgroundActivityScheduler` for background work).
- [ ] Windows native integration (Windows Search anchors; CPU-only
      ML; no GPU assumption).
- [ ] Performance profiling and optimization (memory residency,
      CPU per request, battery cost per backup, peak transfer
      throughput).
- [ ] Large-scale testing: 100K+ messages, 10K+ media files,
      multilingual corpus across 10+ scripts.
- [ ] Platform-specific ML execution-provider tuning (CoreML EP,
      NNAPI EP, optional DirectML EP on Windows when GPU is present).
- [ ] Dedup analytics integration with `kennguy3n/zk-object-fabric`'s
      ContentIndex metrics (read-only telemetry, no plaintext leaks).
- [ ] Edge-case handling: offline mode; interrupted backups;
      partial restores; corrupted chunks; missing manifests.
- [ ] Archive compaction at production scale (per account +
      conversation + bucket: collect old deltas → apply tombstones →
      rebuild compact segment → upload → new manifest → mark old
      expired).
- [ ] Cross-platform media migration: iOS → Android migrates
      iCloud-resident media blobs to Google Drive (or ZKOF as
      platform-neutral fallback) in the background, rewriting
      `media_asset.storage_sink` and the related `MediaDescriptor`
      field as it goes. See PROPOSAL.md §5.7.
- [ ] Media blob sink stress test: 10K+ media files across mixed
      sinks (KChat backend + iCloud + Google Drive + ZKOF in the
      same account); verify rehydration from each.
- [ ] **Failure test suite**, all passing:
  - chunk upload interrupted mid-stream
  - manifest upload interrupted mid-write
  - wrong backup key on restore
  - corrupted chunk (Merkle / SHA-256 mismatch)
  - device removed from MLS group between backup and restore
  - search shard missing from the backend
  - low-storage condition during restore
  - manifest chain break detected on restore

**Decision gate**: Production-ready performance on the target
device matrix (defined per platform during Phase 7). The full
failure test suite passes on every platform.
