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
- [ ] iOS iCloud backup sink (iCloud container file storage).
- [ ] Android backup sink strategy: Auto Backup for small recovery
      envelopes / manifest pointers; Large Backup or SAF for full
      data.
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
- [~] Key recovery (device-to-device transfer, recovery key,
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
      payload nonce length. Server escrow remains OFF by
      default. Passphrase flow is the next milestone.)_
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
