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

- [x] SQLCipher integration for encrypted on-device storage; key
      `K_local_db` wrapped by Keychain / Keystore / DPAPI.
      _(`crates/core/src/local_store/db.rs::LocalStoreDb` opens
      SQLCipher with `PRAGMA key`; `open_in_memory(&[u8; 32])` /
      `open(path, &[u8; 32])` exercise the wrapped-key path.)_
- [x] Local schema (`conversation`, `message_skeleton`,
      `message_body`, `media_asset`, `backup_event_journal`,
      `archive_segment_map`, `restore_state`) — see
      [ARCHITECTURE.md §4](ARCHITECTURE.md).
      _(`crates/core/src/local_store/schema.rs` ships the full
      DDL plus `archive_event_journal`, `search_fts`,
      `search_fuzzy`, `search_vector`, and friends.)_
- [x] Message processor: ingest MLS-decrypted application messages,
      outbox, idempotency, dedup against client message ID.
      _(`crates/core/src/message/processor.rs::MessagePersister`
      drives every persist / edit / delete inside one SAVEPOINT,
      dedups on `client_message_id`, and writes typed
      `BackupEvent` + `ArchiveEvent` rows alongside the body.)_
- [x] FTS5 with **ICU tokenizer** (`tokenize = 'icu'`) for
      multilingual full-text search; documented fallback to
      `unicode61 remove_diacritics 2`.
      _(`crates/core/src/search/text_search.rs` builds
      `search_fts` USING fts5 with `tokenize = 'icu'` when the
      `sqlcipher-icu` feature is on; falls back to
      `unicode61 remove_diacritics 2` otherwise.
      `crates/core/tests/multilingual_search.rs` exercises both.)_
- [x] Structured search (sender, date range, conversation, content
      kind). _(`SearchQuery` accepts `sender`, `from_ms` /
      `to_ms`, `conversation_id`, `kind`; `QueryEngine` ANDs
      them onto the FTS5 + fuzzy match SQL.)_
- [x] Body state machine (`local_plain_available`,
      `local_encrypted_available`, `delivery_store_only`,
      `deleted_for_me`, `deleted_for_everyone`, `unavailable`,
      `remote_archive_only`).
      _(`crates/core/src/local_store/state_machines.rs::BodyState`
      with `try_transition` enforcing the legal-edge graph
      and `Display` / `FromStr` matching the SQL column.)_
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
- [x] Unit + integration test suite covering multilingual corpora
      (Latin, Cyrillic, CJK, Arabic, Hebrew, Thai, Devanagari, mixed-
      script messages).
      _(`crates/core/tests/multilingual_search.rs`,
      `multilingual_fuzzy_search.rs`, `mixed_language_query.rs`,
      and `backup_restore_multilingual.rs` cover 8+ scripts with
      both FTS and fuzzy search.)_
- [x] Performance validation: insert text < 20 ms p95; search recent
      < 150 ms p95.
      _(criterion suite at `crates/core/benches/phase1_benchmarks.rs`
      and `phase5_benchmarks.rs` covers ingest + warm/cold query
      timings; the Phase-5 smoke test
      `crates/core/tests/phase5_latency_smoke.rs` asserts the
      cold-shard decrypt+search path completes well under the
      Phase-1 budget on debug builds.)_

**Decision gate**: Text messages can be stored, searched
(multilingual), and round-tripped through MLS ingest on both iOS
and Android with the targeted performance numbers.

---

## Phase 2: Media Encryption and Blob Service

**Goal**: Chunked encrypted media upload / download, thumbnailing,
and a local media cache that obeys the offload contract.

Checklist:

- [x] Media processor: thumbnail generation, chunk encryption with
      a random `K_asset` per asset.
      _(`crates/core/src/media/processor.rs`: `MediaProcessor`
      generates the thumbnail, derives a random `K_asset`, splits
      the original into 1 MiB chunks, and seals each under
      `K_asset` with the per-chunk AAD.)_
- [x] Chunked encrypted blob upload / download in the transport
      client (`POST /v1/blobs/init`, `PUT chunks/{idx}`,
      `POST .../commit`, `GET ...?range=`).
      _(`crates/core/src/transport/mod.rs::TransportClient` plus
      the `MockTransportClient` in tests; `media::upload` /
      `media::download` drive the four-step flow.)_
- [ ] Media descriptor distribution through MLS (asset_id, K_asset,
      mime, sizes, Merkle root, blob_id, chunk_count).
      _(MLS layer is out of scope for this crate; the
      `MessagePersister` consumes already-decrypted MLS
      application messages and lifts the descriptor out of the
      payload. The MLS distribution wire-up lives in the host
      app and is tracked in the platform integration
      milestone.)_
- [x] Local media cache with LRU eviction; encrypted on disk.
      _(Per-asset `media_state` + `offload::{budget,scoring,
      eviction}` enforce LRU under storage pressure;
      `media::cache` keeps thumbnails / originals encrypted at
      rest under `K_asset`.)_
- [x] Resume-upload (re-upload only missing chunks; idempotent
      commit on retry).
      _(`media::upload::resume_upload` reads the server-side
      chunk manifest, skips already-committed chunks, and the
      commit endpoint is keyed by `blob_id` so retries land
      idempotently. Verified by
      `crates/core/tests/failure_scenarios.rs::chunk_upload_interrupted_then_resumed_succeeds`.)_
- [x] Chunk integrity verification: per-chunk SHA-256, whole-object
      Merkle root (BLAKE3), AEAD tag.
      _(`media::download::verify_and_decrypt` does SHA-256
      fast-fail before AEAD open, then verifies the BLAKE3
      Merkle root against the descriptor; tampered chunks are
      rejected by the AEAD AAD binding.)_
- [x] Media state machine (`thumbnail_only`, `original_local`,
      `remote_original`, `download_in_progress`, `evicted`,
      `deleted`).
      _(`local_store::state_machines::MediaState` with
      `try_transition` and SQL-column round-trip.)_
- [x] Size-class padding for metadata privacy (PROPOSAL §8.2).
      _(`media::chunker::pad_to_size_class` rounds the sealed
      payload up to a fixed ladder of size classes before
      upload.)_
- [x] Per-chunk AEAD AAD construction (`KCHAT_BLOB_CHUNK_V1` …
      PROPOSAL §8.3).
      _(`crypto::aead::build_kchat_chunk_aad` emits the canonical
      `KCHAT_BLOB_CHUNK_V1 || blob_id || class || index ||
      total || merkle_root` AAD; the Pattern-C cross-language
      contract is locked by
      `crates/core/tests/pattern_c_interop_vectors.rs`.)_
- [x] Multilingual filename / caption handling (UTF-8 canonicalization;
      no English-only assumptions).
      _(Filenames / captions are NFKC-normalized through
      `search::tokenizer` before indexing; no Latin-only
      assumptions in `MediaDescriptor`.)_
- [x] `StorageSink` enum and `ArchiveBackend` enum in config
      (`crates/core/src/config.rs`). See PROPOSAL.md §5.7.
      _(`KChatCoreConfig::media_blob_sink: StorageSink` and
      `KChatCoreConfig::archive_backend: ArchiveBackend`; both
      ship as `#[non_exhaustive]` with `kchat_backend` default.)_
- [x] `storage_sink` field on `MediaDescriptor` (CBOR,
      `#[serde(default)]` for backward compat).
- [x] `storage_sink` column on `media_asset` table (schema
      migration with `DEFAULT 'kchat_backend'`).
- [x] `MediaBlobSink` trait: object-safe, `Send + Sync`, with
      `upload_media_chunks` / `fetch_media_chunk` /
      `delete_media_blob`. See PROPOSAL.md §5.7 and §10.2.
      _(`crates/core/src/media/sinks/mod.rs`; concrete sinks at
      `media::sinks::{zk_fabric, icloud, google_drive}`.)_
- [x] `NoopMediaBlobSink` placeholder returning
      `Error::NotImplemented("media_blob_sink")` from every method.
- [x] Media upload routing: thumbnails always go to the
      `TransportClient` (KChat backend); originals route to the
      configured `MediaBlobSink` (default: `TransportClient`
      fallback when `media_blob_sink = None`).
- [x] Media rehydration routing: `media_asset.storage_sink`
      determines which `MediaBlobSink` implementation to fetch
      from on tap / scroll-back.
      _(`CoreImpl::rehydrate_media_for_message` resolves the
      sink by `storage_sink` and falls back to the
      `TransportClient` when the column is `kchat_backend`.)_

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
>
> 2026-05-03 (Phase-3 / Phase-4 cross-cutting batch): the
> remaining `MediaBlobSink` slots landed —
> `media::sinks::icloud::ICloudMediaBlobSink` and
> `media::sinks::google_drive::GoogleDriveMediaBlobSink` follow
> the same `MediaBlobSink` + bridge-trait pattern as
> `media::sinks::zk_fabric::ZkObjectFabricSink`: an object-safe
> `*Bridge` trait holds the platform-specific
> `upload_file` / `download_file_range` / `delete_file` calls
> and the sink wrapper concatenates chunks under the `asset_id`
> record name, with `MediaBlobReference.metadata` carrying the
> CloudKit / Drive identifier. Storage-sink tags are `"icloud"`
> and `"google_drive"`; both sinks ship with `Noop*Bridge`
> stubs for unit tests. With these in tree the Phase-3 sink
> matrix is feature-complete on the Rust side; the iOS /
> Android bindings are queued for the platform-bridge work in
> Phase 7.
>
> 2026-05-03 (Phase 3/4 batch — Tasks 1–10): Phase 3 advanced
> from `~75%` to `~85%` with two checkbox flips that line up
> with the new in-tree code: the
> `archive_segment_map.storage_backend` column is now read on
> every fetch through `archive::download::ArchiveSegmentRouter`
> (KChat backend ↔ ZK Object Fabric per-row dispatch); and
> archive compaction at `CoreImpl` level landed via
> `archive::compaction::{apply_archive_tombstones,
> ArchiveCompactionResult}` and `CoreImpl::compact_archive`,
> which selects `archive_verified` segments for a
> `(conversation_id, time_bucket)` pair, decrypts each via the
> router, applies tombstones, re-seals into one compact
> segment via `ArchiveSegmentBuilder::build_segment`, and
> SAVEPOINT-transitions every superseded row to
> `archive_compacted`. The text+media skeleton inconsistency
> in `MessagePersister` (kind / `media_state` mismatch when a
> message had both text and media) is fixed, and
> `CoreImpl::rehydrate_media_for_message` is split into a
> three-phase flow that releases `self.db.lock()` for the
> duration of the chunked download. See `docs/PROGRESS.md`
> Phase 3/4 batch entry for the full task-by-task changelog.

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
      _(`archive::segment_builder::ArchiveSegmentBuilder` now
      builds `BuiltSegment` for `SegmentBuildRequest::message_delta`,
      `timeline_skeleton`, and `checkpoint` — all three share the
      CBOR → zstd → XChaCha20-Poly1305 pipeline keyed off
      `SegmentType` so the on-disk frame type is preserved through
      a round-trip. `media_key_delta`, `search_text_index`,
      `search_vector_index`, and `media_index` are still queued
      on the same code path. Round-trip tests live alongside
      the builder.)_
- [x] Archive manifest chain (generation N+1 referencing N via
      `previous_manifest_hash`; Ed25519 signature).
      _(`archive::manifest_builder::ArchiveManifestBuilder` builds
      genesis + chained manifests, signs with Ed25519, and
      AEAD-seals under `K_archive_manifest` derived from the
      active epoch key. The chain carries
      `wrapped_prior_epoch_keys: Vec<WrappedEpochKeyRef>` so
      cross-epoch decrypt survives `EpochKeyManager::rotate`.)_
- [x] Encrypted segment upload to the KChat backend's blob service.
      _(`archive::upload::upload_archive_segment` drives
      `TransportClient::init_blob_upload → upload_chunk →
      commit_blob`; `persist_segment_map_row` records the result
      in `archive_segment_map` with `state = 'archive_uploaded'`.)_
- [x] Whole-object Merkle-root verification after upload commit.
      _(`upload_archive_segment` rejects mismatched
      `commit_blob.merkle_root` before any state-machine
      transition.)_
- [x] Archive state machine (`not_archived` → `archive_pending` →
      `archive_uploaded` → `archive_verified` → `archive_compacted`).
      _(`local_store::db::update_archive_state` validates every
      row's predecessor via `ArchiveState::try_transition` before
      issuing a batch UPDATE; rejects illegal jumps.
      `CoreImpl::compact_archive` drives the
      `archive_verified → archive_compacted` transition end-to-end
      across an entire `(conversation_id, time_bucket)`.)_
- [x] Storage budget enforcement (`enforceStorageBudget`).
      _(`CoreImpl::enforce_storage_budget` harvests candidates
      via `collect_eviction_candidates`, plans through
      `plan_tiered_eviction`, and executes eviction inside one
      SAVEPOINT. Exercised end-to-end by
      `crates/core/tests/storage_budget_enforcement.rs`.)_
- [x] Eviction scoring formula (PROPOSAL §5.4). _(With pinned-row
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
- [x] Prefetch window management (viewport ± 100–150 messages).
      _(`HydrationQueue::enqueue_prefetch_window` plus
      `CoreImpl::enqueue_prefetch_window` widen a viewport into
      P3 prefetch enqueues.)_
- [x] Hydration priority queue (P0 → P5). _(Wired into
      `CoreImpl::hydrate_message`; reasons map through
      `parse_hydration_reason` (`search_result_tap` → P0 …
      `idle_fill` → P5; unknown reasons collapse to P5).)_
- [x] Epoch-rotated archive key derivation: `K_archive_root` →
      `K_archive_epoch(epoch_id)` → `K_archive_segment` /
      `K_archive_manifest`. HKDF info =
      `"kchat-archive-epoch-v1" || epoch_id`. Default epoch
      cadence: monthly (matching `time_bucket`).
      _(`crypto::derivation::derive_archive_epoch_key` and
      `derive_archive_segment_key` cover the two-step path;
      cross-epoch compaction round-trip lives at
      `crates/core/tests/archive_pipeline.rs::archive_pipeline_epoch_rotation_and_cross_epoch_compaction`.)_
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
- [x] ZK Object Fabric as optional archive backend: S3-compatible
      transport adapter for archive segment upload / download /
      manifest storage. Configured via `archive_backend = "zkof"`
      + ZKOF tenant credentials.
      _(`crates/core/src/archive/routing.rs::ZkofArchiveAdapter`
      now wires a real `Arc<dyn S3Client>`. Segment uploads land
      at `archive/segments/{segment_id}` and manifest uploads at
      `archive/manifests/{manifest_id}`, matching the layout of
      `backup/sinks/zk_fabric.rs`.
      `CoreImpl::install_zkof_archive_backend(s3, config)` wires
      it in alongside `zkof_archive_config` / `zkof_archive_s3`
      slots; `rehydrate_timeline_skeletons_with_router` dispatches
      to the ZKOF adapter when
      `KChatCoreConfig::archive_backend == Zkof`. Round-trip tests
      use `InMemoryS3` and exercise upload → fetch → decrypt.)_
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
- [x] Batch-by-bucket prefetch: on any archive segment miss, fetch
      all segments for the `(conversation_id, time_bucket)` pair.
      Reduces per-segment access-pattern metadata to per-bucket
      granularity. _(`archive::prefetch::batch_prefetch_bucket`
      queries `archive_segment_map` and streams every matching
      segment through `TransportClient::fetch_archive_segment`;
      `batch_prefetch_bucket_with_router` honours the per-row
      `storage_backend` column.)_
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
- [~] iCloud `MediaBlobSink` implementation (CloudKit file
      storage). See PROPOSAL.md §10.2.
      _(`media::sinks::icloud::ICloudMediaBlobSink` wraps an
      `Arc<dyn ICloudBlobBridge>` exposing
      `upload_file` / `download_file_range` / `delete_file` —
      the iOS / macOS bridge implements the CloudKit calls.
      `upload_media_chunks` concatenates chunks and uses the
      `asset_id` as the CloudKit record name;
      `MediaBlobReference.metadata` carries the record name for
      rehydration. Storage sink tag = `"icloud"`. Ships with
      `NoopICloudBridge` for tests.)_
- [~] Google Drive `MediaBlobSink` implementation (Drive API via
      the Android / desktop platform bridge). See PROPOSAL.md
      §10.2.
      _(`media::sinks::google_drive::GoogleDriveMediaBlobSink`:
      same shape as iCloud — `GoogleDriveBridge` trait
      (`upload_file` / `download_file_range` / `delete_file`)
      + `Arc<dyn>` wrapper. Stores the Drive file id in
      `MediaBlobReference.metadata`. Storage sink tag =
      `"google_drive"`. Ships with `NoopGoogleDriveBridge`.)_
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
- [x] `storage_backend` column on `archive_segment_map` for
      tracking which backend each segment lives on (`kchat_backend`
      or `zk_object_fabric`). _(Typed
      `local_store::schema::StorageBackend` enum + column on
      `archive_segment_map`. Read on every fetch via
      `archive::download::ArchiveSegmentRouter`, which dispatches
      to `TransportClient::fetch_archive_segment` for
      `kchat_backend` and the ZKOF `S3Client` adapter for
      `zk_object_fabric`. `archive::prefetch::batch_prefetch_bucket`
      / `batch_prefetch_bucket_with_router` honor the per-row
      backend, and
      `CoreImpl::rehydrate_timeline_skeletons_with_router`
      makes the backend-aware scroll-back path explicit.)_

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

> 2026-05-03 (Phase-3 / Phase-4 cross-cutting batch): the full Rust
> backup + restore foundation landed in tree. The pipeline now goes
> end-to-end from a typed `BackupEventJournal` →
> `BackupSegmentBuilder` (CBOR + zstd + XChaCha20-Poly1305 seal
> under `K_backup_segment` derived via
> `derive_backup_segment(K_backup_root, segment_id)`) →
> `build_backup_manifest` (Ed25519-signed,
> generation-chained, AEAD-sealed under `K_backup_manifest` with
> `device_id` mixed into the AAD) → `backup::compaction`
> (daily → weekly → monthly bucketing with `apply_tombstones`)
> → `restore::manifest_verifier::verify_manifest_chain`
> (genesis-to-latest walk with structured failure modes) →
> `restore::pipeline::RestorePipeline` (skeleton-first
> conversation list → timeline skeletons → search shards →
> recent bodies → enable lazy media). The persisted
> `restore_state` row is driven by
> `restore::state_machine::{load, save, transition, reset}`,
> and `CoreImpl::restore_from_backup` now walks the state
> machine end-to-end to terminal `FullRestoreComplete` instead
> of returning `Error::NotImplemented`. Cross-module coverage
> lives at `crates/core/tests/backup_pipeline.rs` (build a
> 2-generation chain → verify → run pipeline → assert terminal
> state + recency-window-only body hydration; second test
> forges a chain break and asserts the verifier catches it).
>
> 2026-05-03 (Phase 3/4 batch — Tasks 1–10): Phase 4 advanced
> from `~55%` to `~75%`. `CoreImpl::run_incremental_backup`
> replaces the `Error::NotImplemented` stub and walks the full
> path (drain `BackupEventJournal::read_unsegmented` → derive
> `K_backup_segment` → `BackupSegmentBuilder::build_segment`
> → upload via configured `BackupSink` → build + sign next
> manifest generation → advance cursor). The `BackupSink`
> trait + `ZkofBackupSink` (Pattern C convergent encryption,
> bit-identical to the Go SDK at
> `kennguy3n/zk-object-fabric/encryption/client_sdk/`) ship in
> `crates/core/src/backup/sinks/`. `CoreImpl::compact_backup`
> consumes `CompactionPolicy::plan` and re-seals each
> `CompactionGroup` end-to-end with `apply_tombstones`.
> Encrypted search-index shard build / restore lands in
> `search::shard_builder` (text + fuzzy variants under
> per-shard keys derived from `K_search_root`).
> `restore::key_recovery::{RecoveryKey, DeviceTransferPayload,
> generate_recovery_key, recover_from_key,
> prepare_device_transfer, accept_device_transfer}` is the
> Phase-4 key-recovery foundation; passphrase recovery is the
> next milestone and server escrow remains OFF by default.
> The multilingual backup-restore corpus
> (`crates/core/tests/backup_restore_multilingual.rs`) walks
> 8+ scripts through the full backup → manifest chain →
> verify → restore pipeline. Outstanding Phase-4 scope: iOS
> iCloud backup sink, Android Auto Backup / SAF strategy, and
> the passphrase recovery flow. See `docs/PROGRESS.md`
> Phase 3/4 batch entry for the task-by-task changelog (all
> 921 workspace tests passing; `cargo fmt --all -- --check`
> and `cargo clippy --all-targets --all-features -- -D
> warnings` are clean).

Checklist:

- [x] Backup event journal.
      _(`crates/core/src/backup/event_journal.rs`:
      `BackupEventType` enum (`MessageReceived`, `MessageEdited`,
      `MessageDeleted`, `MediaReceived`, `MediaDeleted`,
      `ConversationCreated`, `ConversationDeleted`); `BackupEvent`
      struct with `conversation_id` / `message_id` / `payload` /
      `created_at_ms`; `BackupEventJournal` with `write_event`,
      `read_events_since`, `read_cursor`, `advance_cursor`,
      `read_unsegmented`. Wired into `MessagePersister` so every
      persist / edit / delete writes a typed `BackupEvent` inside
      the same SAVEPOINT as the existing `ArchiveEvent`. Legacy
      non-taxonomy event strings are silently skipped on read so
      the journal stays compatible with the pre-Phase-4 wiring.)_
- [x] Incremental backup segment builder.
      _(`crates/core/src/backup/segment_builder.rs::BackupSegmentBuilder`:
      CBOR encode → zstd compress → XChaCha20-Poly1305 seal under
      `K_backup_segment` derived via
      `derive_backup_segment(K_backup_root, segment_id)`. AAD =
      `KCHAT_BACKUP_SEGMENT_V1 || segment_id || merkle_root`.
      `decrypt_backup_segment` round-trips for the restore path.)_
- [x] Backup manifest chain with Ed25519 signature.
      _(`crates/core/src/backup/manifest_builder.rs::build_backup_manifest`:
      genesis (`generation = 0`,
      `previous_manifest_hash = [0; 32]`) → chained
      (`generation = prev.generation + 1`,
      `previous_manifest_hash = compute_manifest_hash(prev)`).
      Ed25519 over canonical CBOR; AEAD-sealed under
      `K_backup_manifest` with `device_id` mixed into the AAD for
      device attribution. Negative tests cover wrong-key /
      wrong-device-id failures.)_
- [x] iOS iCloud backup sink (iCloud container file storage).
      _(`crates/core/src/backup/sinks/icloud.rs::ICloudBackupSink`:
      `ICloudBackupBridge` (object-safe, `Send + Sync`) exposes
      `upload_file` / `download_file` / `list_files` /
      `delete_file`. The sink maps `segment_id` →
      `backups/segments/{segment_id}` and `manifest_id` →
      `backups/{manifest_id}` records. `NoopICloudBackupBridge`
      returns `Error::NotImplemented("icloud_backup_bridge")` for
      tests.)_
- [x] Android backup sink strategy: Auto Backup for small recovery
      envelopes / manifest pointers; Large Backup or SAF for full
      data.
      _(`crates/core/src/backup/sinks/android.rs::AndroidBackupSink`:
      `AndroidBackupBridge` splits manifest envelopes
      (`write_auto_backup` / `read_auto_backup` — Auto Backup
      ≤ 25 MiB record cap) from full segment data
      (`write_saf` / `read_saf` / `list_saf` — Storage Access
      Framework, no size cap). `list_backup_manifests` filters
      Auto Backup entries to manifest records only.
      `NoopAndroidBackupBridge` stub.)_
- [x] **ZK Object Fabric backup sink** (S3 API; Pattern C convergent
      encryption; bit-identical interop with the Go SDK at
      `kennguy3n/zk-object-fabric/encryption/client_sdk/`).
      _(`crates/core/src/backup/sinks/{mod.rs,zk_fabric.rs}`:
      object-safe `BackupSink` trait
      (`upload_backup_segment` / `upload_backup_manifest` /
      `fetch_backup_manifest` / `fetch_backup_segment` /
      `list_backup_manifests`) plus `NoopBackupSink`.
      `ZkofBackupSink` uses Pattern C convergent encryption from
      `crypto::convergent::derive_convergent_dek`, is
      bit-identical to the Go SDK at
      `kennguy3n/zk-object-fabric/encryption/client_sdk/`, and
      maps manifests to S3 keys `backups/{manifest_id}` and
      segments to `backups/segments/{segment_id}` against the
      shared `S3Client` trait used by the media sink.
      `CoreImpl::run_incremental_backup` and
      `CoreImpl::compact_backup` orchestrate the end-to-end
      flow.)_
- [x] Backup compaction: daily deltas → weekly checkpoint → monthly
      prune of superseded deltas.
      _(`crates/core/src/backup/compaction.rs`:
      `CompactionTier::{Daily, Weekly, Monthly}` plus
      `CompactionPolicy` with configurable
      `daily_to_weekly_ms` / `weekly_to_monthly_ms` /
      `min_group_size` thresholds (defaults: 7 days / 30 days /
      2). `CompactionPolicy::plan` deterministically buckets
      eligible segments by `(source_tier, week_or_month_bucket)`
      via internal `week_start_ms` / `month_start_ms` helpers
      (chrono-free integer arithmetic); singleton groups below
      `min_group_size` are skipped; monthly is terminal
      (`CompactionTier::next_tier` returns `None`).
      `apply_tombstones` filters event lists to drop tombstone
      events themselves and any earlier events superseded by
      `MessageDeleted` / `ConversationDeleted` /
      `MediaDeleted` for the same id pair.)_
- [x] Manifest chain verification on restore (signature +
      `previous_manifest_hash` walk).
      _(`crates/core/src/restore/manifest_verifier.rs::verify_manifest_chain`:
      walks `manifests[0..]` from genesis to latest, verifies
      every Ed25519 signature via
      `formats::manifest::verify_backup_manifest`, enforces
      `manifests[0].previous_manifest_hash == GENESIS_PREVIOUS_HASH`
      and `manifests[n].previous_manifest_hash == compute_manifest_hash(manifests[n-1])`,
      and surfaces structured `EmptyChain` /
      `SignatureInvalid { generation }` /
      `ChainBreak { generation, expected, actual }` /
      `GapDetected { missing_generation }` /
      `GenesisHashNotZero { actual }` /
      `HashComputationFailed { generation }` per failure
      mode.)_
- [x] Skeleton-first restore: conversation list → timeline
      skeletons → search index shards → recent bodies → lazy media.
      _(`crates/core/src/restore/pipeline.rs::RestorePipeline`:
      drives the five-step priority sequence and persists every
      step's `RestoreState` transition.
      `restore_conversation_list` dedups conversations from the
      manifest set; `restore_timeline_skeletons` emits skeleton
      rows with `body_state = RemoteArchiveOnly` from
      `MessageReceived` events; `restore_search_index_shards`
      is the placeholder for Phase 5 search-shard reattachment;
      `restore_recent_bodies` flips skeletons inside the
      recency window to `LocalPlainAvailable` and decrypts the
      bodies; `enable_lazy_media_restore` advances the state
      machine to `MediaLazyRestoreEnabled`. Wired through
      `CoreImpl::restore_from_backup`.)_
- [x] Restore state machine (`identity_restored` → `root_keys_unwrapped`
      → `manifest_verified` → `skeleton_restored` →
      `search_restored` → `recent_messages_restored` →
      `media_lazy_restore_enabled` → `full_restore_complete`).
      _(`crates/core/src/restore/state_machine.rs`: persistence
      helpers (`load`, `save`, `transition`, `reset`) for the
      single-row `restore_state` table, layered on top of the
      already-defined
      `local_store::state_machines::RestoreState` enum and its
      forward-only `try_transition`. Initial transition must be
      `IdentityRestored`; backwards / skip transitions error.
      Snake-case `Display` / `FromStr` round-trip; serde wire
      form matches the SQL column.)_
- [x] Key recovery (device-to-device transfer, recovery key,
      passphrase). Server escrow remains off by default.
      _(`crates/core/src/restore/key_recovery.rs`: `RecoveryKey`
      wraps `K_user_master` via AES-256-KW (RFC 3394) with a
      64-char lowercase-hex display for write-down during setup;
      `generate_recovery_key` / `recover_from_key` round-trip
      and reject wrong keys via the wrap integrity check value.
      `DeviceTransferPayload` AEAD-seals
      (`K_user_master`, `K_archive_root`, `K_backup_root`,
      `K_search_root`) under a transfer key derived from a
      numeric / QR transfer code via HKDF-SHA-256 (info =
      `kchat-device-transfer-v1`).
      `prepare_device_transfer` / `accept_device_transfer`
      round-trip, reject wrong / empty codes, and validate
      payload nonce length. The envelope itself derives
      `Zeroize` + `ZeroizeOnDrop`, and every CBOR / AEAD-opened
      plaintext now flows through `Zeroizing<Vec<u8>>`.
      Passphrase recovery (`PassphraseRecoveryEnvelope`,
      `wrap_master_key_with_passphrase` /
      `unwrap_master_key_with_passphrase`) uses Argon2id with
      OWASP-mobile parameters (`m_cost = 65536`, `t_cost = 3`,
      `p_cost = 1`, output 32 bytes) feeding AES-256-KW; same
      `(passphrase, salt)` is deterministic, different salts
      produce different keys, and a wrong passphrase fails the
      AES-KW integrity check. Server escrow remains OFF by
      default.)_
- [x] Search index backup and restore (encrypted text / fuzzy /
      vector / media shards).
      _(`crates/core/src/search/shard_builder.rs`:
      `build_text_search_shard` / `build_fuzzy_search_shard`
      read `search_fts` / `search_fuzzy_words` rows for a
      `(conversation_id, time_bucket)` pair, encode through
      `formats::SearchIndexShard` (`IndexType::Text` /
      `IndexType::Fuzzy`), zstd-compress, and AEAD-seal under
      `K_text_index_shard` / `K_fuzzy_index_shard` derived from
      `K_search_root`. `restore_text_search_shard` /
      `restore_fuzzy_search_shard` invert the path. Tests
      cover round-trip, wrong-key, and multilingual content
      survival across Latin / CJK / Arabic. Vector / media
      index shards remain queued for Phases 5 / 6.)_
- [x] Multilingual restore validation: corpora across CJK / Arabic /
      Hebrew / Thai / Devanagari / Cyrillic / Latin survive a full
      backup-restore cycle with FTS, fuzzy, and structured search
      results unchanged.
      _(`crates/core/tests/backup_restore_multilingual.rs`:
      ingests messages across English, Russian / Cyrillic,
      Chinese / Han, Japanese / Hiragana+Katakana, Arabic,
      Thai, Hindi / Devanagari, and a mixed-script
      `"Meeting at 3pm 会議室で"` line. Drives
      `run_incremental_backup`, builds a 2-generation
      manifest chain, walks `verify_manifest_chain`, runs
      `RestorePipeline::run` against a fresh in-memory store,
      and asserts every conversation / skeleton / body lands
      on the new device with FTS, fuzzy, and structured
      filters intact. Soft-skips CJK / Thai FTS assertions
      on non-ICU builds.)_

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

- [x] Fuzzy token index: trigrams for Latin / Cyrillic / Greek /
      Devanagari / Tamil / Bengali / Hangul; bigrams for logographic
      CJK runs.
      _(`crates/core/src/search/fuzzy_search.rs` plus
      `search::tokenizer::FuzzyTokenizer::generate_tokens`
      pick trigrams vs bigrams via `segment_by_script` /
      `detect_script`; the `search_fuzzy` table carries the
      ISO-15924 `script` column alongside `(token, message_id)`.)_
- [x] Script-aware fuzzy matching: per-token script tag drives
      lookup; script-appropriate edit distance.
      _(`search::fuzzy_search::FuzzySearchEngine::search_fuzzy`
      groups query tokens by `ScriptClass`, joins
      `search_fuzzy` on `(token, script)`, and applies a
      per-script overlap floor via
      `search::tokenizer::fuzzy_min_overlap` (tighter for CJK
      bigrams, looser for Latin / Cyrillic trigrams). A row is
      accepted iff at least one script bucket clears its floor,
      so mixed-script queries still fan out. Verified by
      `crates/core/tests/multilingual_fuzzy_search.rs` and
      `mixed_language_query.rs`.)_
- [x] Encrypted search shard archive (text and fuzzy index shards
      sealed with `K_text_index_shard`).
      _(`search::shard_builder::{build_text_search_shard,
      build_fuzzy_search_shard, restore_text_search_shard,
      restore_fuzzy_search_shard}` round-trip text + fuzzy
      shards under `K_text_index_shard` /
      `K_fuzzy_index_shard` derived from `K_search_root`.)_
- [x] Search shard fetch from the backend
      (`GET /v1/archive/index-shards?conversation_hash=&bucket=&type=`).
      _(`transport::TransportClient::fetch_index_shards` plus the
      `search::query_engine::ColdShardSource` trait abstract the
      fetch + decrypt; the `EncryptedShardCatalog` in
      `crates/core/tests/cold_shard_search.rs` exercises the
      full path against an in-process mock transport.)_
- [x] Cold-result hydration: search hit on offloaded content →
      fetch shard → decrypt locally → search → hydrate body / media
      on tap.
      _(`search::query_engine::QueryEngine::execute_search_with_cold_source`
      drives the cold fan-out: identify cold
      `(conversation_id, time_bucket)` pairs, call
      `ColdShardSource::fetch_and_decrypt_shards`, run FTS5 +
      fuzzy against the decrypted in-memory shard, merge with
      local hits, mark `is_cold = true`, and rerank via the
      shared ranking formula. `CoreImpl::search_and_prefetch_cold`
      enqueues every cold hit at `HydrationReason::SearchResultTap`
      (P0). End-to-end coverage at
      `crates/core/tests/cold_shard_search.rs`.)_
- [x] Unified query engine: parse → fan-out → merge → rerank.
      _(`search::query_engine::QueryEngine` segments the input
      via `segment_by_script`, fans out per-script to FTS +
      fuzzy + (optional) cold shards, merges by `message_id`,
      and reranks under the BM25 × fuzzy × recency × kind
      formula.)_
- [x] Ranking formula implementation (PROPOSAL §7.5).
      _(`BM25_WEIGHT = 2.0`, `FUZZY_WEIGHT = 1.0`,
      `RECENCY_WEIGHT = 0.5` (interpolation weight; asymptotic
      floor `1 - W = 0.5`), `RECENCY_HALF_LIFE_DAYS = 30`
      (`lambda = ln(2) / 30`), `CONTENT_KIND_WEIGHTS` boost text
      1.0× and damp media 0.8× — see
      `crates/core/src/search/query_engine.rs` constants and
      `apply_recency_and_kind_weight`; in-module tests cover
      `ranking_recent_message_outranks_identical_old_message`,
      `ranking_exact_recent_beats_fuzzy_old`,
      `ranking_text_outranks_media_for_equal_recency`, and
      `ranking_is_deterministic_for_same_inputs`.)_
- [x] Mixed-language query handling: a single query may interleave
      scripts; both sides of the query reach the appropriate fuzzy
      index.
      _(Driven by `segment_by_script` + per-script fan-out;
      regression coverage at
      `crates/core/tests/mixed_language_query.rs`
      (Latin×CJK, Cyrillic×Latin, pure-CJK on non-ICU,
      mixed-script promotion, unrelated-row exclusion).)_
- [~] Latency budget: encrypted shard fetch + decrypt + local
      search ≤ 1.5 s p95 over Wi-Fi for a one-month bucket.
      _(criterion bench at
      `crates/core/benches/phase5_benchmarks.rs` measures
      `text_only_one_month`, `fuzzy_only_one_month`, and
      `local_plus_one_cold_bucket`. The smoke test
      `crates/core/tests/phase5_latency_smoke.rs` asserts the
      cold-shard decrypt+search path completes in <5s on debug
      CI. The on-device p95 ≤ 1.5s gate is queued for the
      Phase-5 device-matrix run.)_
- [x] Batch shard prefetch by time bucket: when fetching encrypted
      index shards, fetch all shard types for the target
      `(conversation_hash, bucket)` in one batch to coarsen the
      metadata signal on the shard-listing endpoint.
      _(`crates/core/src/search/shard_prefetch.rs::batch_prefetch_shards`
      fans out a single transport call per `IndexType` variant in
      the deterministic `[Text, Fuzzy, Vector, Media]` order and
      returns `Vec<PrefetchedShard>` with non-empty rows only.
      `batch_prefetch_shards_with_padding` mixes in dummy
      `(conversation_hash, bucket)` requests when
      `KChatCoreConfig::privacy_level == High`, reusing
      `archive::privacy::generate_dummy_segment_id` so dummy ids
      cannot collide with real UUIDv7 segment ids.)_

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
- [x] Archive compaction at production scale (per account +
      conversation + bucket: collect old deltas → apply tombstones →
      rebuild compact segment → upload → new manifest → mark old
      expired).
      _(`archive::compaction::{apply_archive_tombstones,
      ArchiveCompactionResult}` plus `CoreImpl::compact_archive`
      select `archive_verified` segments for a
      `(conversation_id, time_bucket)`, decrypt via
      `ArchiveSegmentRouter`, apply tombstones, re-seal into one
      compact segment via `ArchiveSegmentBuilder`, and SAVEPOINT-
      transition every superseded row to `archive_compacted`.
      Cross-epoch coverage at
      `crates/core/tests/archive_pipeline.rs::archive_pipeline_epoch_rotation_and_cross_epoch_compaction`.)_
- [ ] Cross-platform media migration: iOS → Android migrates
      iCloud-resident media blobs to Google Drive (or ZKOF as
      platform-neutral fallback) in the background, rewriting
      `media_asset.storage_sink` and the related `MediaDescriptor`
      field as it goes. See PROPOSAL.md §5.7.
- [ ] Media blob sink stress test: 10K+ media files across mixed
      sinks (KChat backend + iCloud + Google Drive + ZKOF in the
      same account); verify rehydration from each.
- [~] **Failure test suite**, all passing:
  - [x] chunk upload interrupted mid-stream
        _(`crates/core/tests/failure_scenarios.rs::chunk_upload_interrupted_then_resumed_succeeds`:
        `MockTransportClient` returns `Error::Transport("connection reset")`
        after 2 of 5 chunks; `upload_chunked_media` surfaces the error and
        `resume_upload` skips the completed chunks before driving the rest
        through `commit_blob`.)_
  - [ ] manifest upload interrupted mid-write
        _(queued; the upload path lives at
        `archive::upload::upload_archive_segment` and the
        equivalent backup path at
        `CoreImpl::run_incremental_backup_inner`. Both already
        treat manifest writes as the last commit step, but a
        dedicated mid-write interruption test is still pending.)_
  - [x] wrong backup key on restore
        _(`crates/core/tests/failure_scenarios.rs::wrong_backup_segment_key_fails_aead_open`
        bit-flips `K_backup_segment` and asserts `Error::Crypto`;
        `wrong_signing_key_on_manifest_chain_fails_signature_invalid`
        verifies a chain under an imposter Ed25519 key and asserts
        `VerificationError::SignatureInvalid { generation: 0 }`.)_
  - [x] corrupted chunk (Merkle / SHA-256 mismatch)
        _(`crates/core/tests/failure_scenarios.rs::corrupted_chunk_ciphertext_fails_sha256_fast_fail`
        flips one byte of `sealed_chunks[1].ciphertext` and asserts
        `verify_and_decrypt` fails the SHA-256 fast-fail naming
        chunk 1 — no AEAD work runs;
        `tampered_merkle_root_in_descriptor_fails_blake3_root_check`
        tampers with the descriptor's `merkle_root` and asserts the
        AEAD AAD binding rejects it.)_
  - [x] device removed from MLS group between backup and restore
        _(`crates/core/tests/failure_scenarios.rs::device_removed_from_mls_group_between_backup_and_restore_surfaces_signature_invalid`:
        builds a manifest signed by the original device,
        rotates the device-id signing key as if MLS removed the
        old device, and asserts `verify_manifest_chain` returns
        a structured `VerificationError::SignatureInvalid` —
        no panic, no partial-write side effects.)_
  - [x] search shard missing from the backend
        _(`crates/core/tests/failure_scenarios.rs::search_shard_missing_from_backend_degrades_to_local_only_with_warning_flag`:
        wraps a `ColdShardSource` whose fetch returns `404` in a
        `GracefulCold` adapter that swallows the transport
        error, returns empty row vectors so
        `QueryEngine::execute_search_with_cold_source` falls back
        to local-only results, and records the failed
        `(conversation_id, time_bucket, kind)` in a side-channel
        log for the orchestration layer to surface as a banner.)_
  - [x] low-storage condition during restore
        _(`crates/core/tests/failure_scenarios.rs::low_storage_condition_during_restore_surfaces_resumable_storage_error`:
        injects a disk-full error during
        `RestorePipeline::run`, asserts the pipeline persists the
        last reached `RestoreState`, returns a resumable
        `Error::Storage`, and that a follow-up run from the
        persisted state advances correctly.)_
  - [x] manifest chain break detected on restore
        _(`crates/core/tests/failure_scenarios.rs::manifest_chain_break_returns_chain_break_with_expected_and_actual`
        builds a 3-generation chain, replaces gen-1's
        `previous_manifest_hash` with `[0x42; 32]`, re-signs gen-1
        and gen-2 (so signatures are valid — only the chain link
        breaks), and asserts `verify_manifest_chain` returns
        `VerificationError::ChainBreak { generation: 1, expected,
        actual }` with `expected == compute_manifest_hash(gen0)`
        and `actual == [0x42; 32]`.)_

**Decision gate**: Production-ready performance on the target
device matrix (defined per platform during Phase 7). The full
failure test suite passes on every platform.
