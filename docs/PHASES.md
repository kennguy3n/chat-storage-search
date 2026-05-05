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
      `previous_manifest_hash` chain; hybrid Ed25519 + ML-DSA-65
      signature — see PQC hybrid signing note below).
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

> **Note (2026-05-05) — PQC hybrid manifest signing.** Manifest
> signing is upgraded from pure Ed25519 to **hybrid Ed25519 +
> ML-DSA-65** (FIPS 204) per NIST SP 800-227. The system is
> pre-launch, so this is a hard breaking change rather than a
> staged migration: `MANIFEST_VERSION` bumps from `1` to `2`, the
> magic strings become `KCHAT_BAK_MANIFEST_V2` /
> `KCHAT_ARC_MANIFEST_V2`, and both `BackupManifest` and
> `ArchiveManifest` gain a `pqc_signature: Vec<u8>` field
> alongside the existing `manifest_signature` (Ed25519). The
> canonical signing payload clears **both** signature fields to
> empty before CBOR-encoding, and verification requires **both**
> the Ed25519 and ML-DSA-65 legs to validate — either failing
> rejects the manifest. Device signing keys are now hybrid
> (`HybridSigningKey` / `HybridVerifyingKey` in
> `crates/core/src/crypto/signing.rs`); Ed25519 supplies classical
> security, ML-DSA-65 supplies post-quantum resilience against
> Shor's algorithm on a future cryptographically-relevant quantum
> computer.

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
- [x] Archive segment builder: per-conversation, per-time-bucket
      segments for `message_delta`, `timeline_skeleton`,
      `media_key_delta`, `search_text_index`,
      `search_vector_index`, `media_index`, `checkpoint`.
      _(`archive::segment_builder::ArchiveSegmentBuilder` now
      builds `BuiltSegment` for every Phase-3 segment type:
      `SegmentBuildRequest::message_delta`,
      `timeline_skeleton`, `checkpoint`, **2026-05-04 batch-5**:
      `media_key_delta`, `search_text_index`,
      `search_vector_index`, `media_index`. All seven share
      the CBOR → zstd → XChaCha20-Poly1305 pipeline keyed off
      `SegmentType` so the on-disk frame type is preserved
      through a round-trip. Non-archive segment types are
      rejected up-front with `Error::Storage`. Round-trip
      tests live alongside the builder and in
      `crates/core/tests/archive_pipeline.rs`.)_
- [x] Archive manifest chain (generation N+1 referencing N via
      `previous_manifest_hash`; hybrid Ed25519 + ML-DSA-65 signature).
      _(`archive::manifest_builder::ArchiveManifestBuilder` builds
      genesis + chained manifests, signs with hybrid Ed25519 +
      ML-DSA-65, and
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
> `build_backup_manifest` (hybrid Ed25519 + ML-DSA-65-signed,
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
- [x] Backup manifest chain with hybrid Ed25519 + ML-DSA-65
      signature.
      _(`crates/core/src/backup/manifest_builder.rs::build_backup_manifest`:
      genesis (`generation = 0`,
      `previous_manifest_hash = [0; 32]`) → chained
      (`generation = prev.generation + 1`,
      `previous_manifest_hash = compute_manifest_hash(prev)`).
      Hybrid Ed25519 + ML-DSA-65 over canonical CBOR (both signature
      fields cleared before encoding); AEAD-sealed under
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
      both the Ed25519 and ML-DSA-65 legs of every signature via
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
- [x] Latency budget: encrypted shard fetch + decrypt + local
      search ≤ 1.5 s p95 over Wi-Fi for a one-month bucket.
      _(criterion bench at
      `crates/core/benches/phase5_benchmarks.rs` measures
      `text_only_one_month`, `fuzzy_only_one_month`, and
      `local_plus_one_cold_bucket`. Smoke tests at
      `crates/core/tests/phase5_latency_smoke.rs` —
      `phase5_cold_shard_p95_latency_under_1_5s_budget`,
      `phase5_cold_shard_p95_multilingual_under_budget`,
      `phase5_cold_shard_p95_large_bucket_under_budget`,
      `phase5_cold_shard_p95_multiple_shards_under_budget` —
      assert p95 under budget across multilingual, large-bucket,
      and multi-shard scenarios. `DeviceMatrixConfig` in
      `crates/core/src/config.rs` defines per-platform p95
      budgets (iOS flagship 1.0 s, iOS older 1.5 s, Android
      flagship 1.2 s, Android mid-range 2.0 s, desktop 0.8 s)
      so the device-matrix run only has to look up the right
      entry.)_
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

- [x] ONNX Runtime integration via the
      [`ort`](https://crates.io/crates/ort) crate.
      _(Session lifecycle scaffold + EP-selection state machine in
      `crates/core/src/models/embeddings_onnx.rs`. ONNX-backed
      inference is gated behind `#[cfg(feature = "onnx-runtime")]`;
      without the feature an `Error::NotImplemented` stub keeps
      the public surface compilable. `Error::Model(String)` added
      to `kchat_core::Error` (`crates/core/src/lib.rs`) for
      `ort` -> core mapping. Tests:
      `models::embeddings_onnx::tests::*`.)_
- [x] Multilingual text embedding model (`XLM-R`, ~80–100 MB INT8
      ONNX) wired through the search pipeline. Same encoder as
      `kennguy3n/slm-guardrail`, unifying the text encoder across
      the platform. English-only MiniLM-L6 is **rejected**.
      _(`TextEmbedder` trait + `NoopTextEmbedder` /
      `MockTextEmbedder` in `crates/core/src/models/embeddings.rs`;
      wired into `CoreImpl` as
      `Mutex<Option<Box<dyn TextEmbedder>>>` via
      `install_text_embedder`. `CoreImpl::ingest_messages` runs a
      best-effort `maybe_embed_text_message` that writes the
      vector through `LocalStoreEmbeddingCache` keyed
      `(message_id, "xlmr@v1")`. Tests:
      `core_impl::tests::ingest_messages_writes_text_embedding_when_embedder_installed`,
      `models::embeddings::tests::*`.)_
- [x] HNSW vector index for semantic text search.
      _(Brute-force cosine over the bounded per-conversation
      `search_vector` corpus is the bring-up implementation
      and remains the fallback below
      `HNSW_FALLBACK_THRESHOLD = 1000` rows.
      **2026-05-04 batch-5**: `instant-distance` HNSW ANN
      graph builds lazily via `HnswIndex::build` and caches
      per `(conversation_id, model_version)` slot through
      `HnswIndexCache`. `SemanticSearchEngine::search_semantic_auto`
      auto-selects the path. Cache invalidation lives on
      `HnswIndexCache::invalidate`. Tests:
      `search::semantic_search::tests::*` (10 unit tests
      covering brute-force vs HNSW top-k overlap, cache
      invalidation, empty-corpus handling, threshold
      fallback).)_
- [x] `MobileCLIP-S2` integration for image search (multilingual
      text→image, ~80 MB INT8 ONNX).
      _(Inference seam: `ImageEmbedder` trait, `NoopImageEmbedder`,
      `MockImageEmbedder` in `crates/core/src/models/clip.rs`.
      Wired into `CoreImpl::send_media` via
      `maybe_embed_image_message`, gated on
      `mime_type.starts_with("image/")` and the cross-pipeline
      cache key `(message_id, "mobileclip_s2@v1")`. Actual ONNX
      session attach is the platform-bridge follow-up. Tests:
      `core_impl::tests::send_media_writes_image_embedding_when_embedder_installed`,
      `core_impl::tests::send_media_skips_image_embedding_for_non_image_mime`,
      `models::clip::tests::*`.)_
- [x] Video keyframe sampling and `MobileCLIP-S2` embeddings.
      _(`VideoKeyframeSampler` trait, `NoopVideoKeyframeSampler`,
      `MockVideoKeyframeSampler` in
      `crates/core/src/models/video.rs`. Wired into
      `CoreImpl::send_media`: video MIME types call
      `extract_keyframes(.., max_frames = 5)`; the first frame
      is embedded via the existing `ImageEmbedder` and the
      vector lands in `search_vector` keyed
      `(message_id, "mobileclip_s2@v1")`. Best-effort. Tests:
      `models::video::tests::*`,
      `core_impl::tests::send_media_embeds_video_keyframes_when_sampler_and_embedder_installed`,
      `core_impl::tests::send_media_skips_keyframes_for_non_video_mime`.)_
- [x] Whisper multilingual integration for voice-message transcription:
      Apple MLX (`mlx-community/whisper-base-mlx`) on Apple Silicon
      (preferred — Neural Engine, lower latency / battery cost);
      ONNX Runtime (`whisper-base` ~140 MB INT8, INT4 not supported
      for audio transcription) on all other platforms (Intel macOS,
      Windows, Android, Linux); `whisper-tiny` (~75 MB) on low-end
      Android. See PROPOSAL §7.6 / §7.7.
      _(Scaffold: `WhisperTranscriber` trait,
      `NoopWhisperTranscriber`, `MockWhisperTranscriber` +
      `select_whisper_backend` (Apple MLX vs ONNX) in
      `crates/core/src/models/whisper.rs`. Wired into
      `CoreImpl::send_media`: audio MIME types call
      `transcribe()`; the result lands in `media_search_index`
      with `kind = "transcript"` (text + language). Real
      MLX / ONNX inference attach is the platform-bridge
      follow-up. Tests: `models::whisper::tests::*`,
      `core_impl::tests::send_media_writes_transcript_when_transcriber_installed`,
      `core_impl::tests::send_media_skips_transcript_for_non_audio_mime`.)_
- [x] Platform OCR bridge: Vision (`VNRecognizeTextRequest`) on
      iOS / macOS; ML Kit Text Recognition v2 on Android;
      `Windows.Media.Ocr` / Tesseract on Windows.
      _(Trait + Noop in `crates/core/src/models/ocr.rs`; wired
      into `CoreImpl` as
      `Mutex<Option<Arc<dyn OcrBridge>>>` via
      `install_ocr_bridge`. Index storage:
      `LocalStoreDb::insert_media_search_index` and
      `LocalStoreDb::search_media_index` in
      `crates/core/src/local_store/db.rs`. Platform glue lives
      with the bridge crates and is delivered in Phase 7. Tests:
      `models::ocr::tests::*`,
      `local_store::db::tests::media_search_index_*`.)_
- [x] Document text extraction (PDF, DOCX) with multilingual
      handling and page-level indexing.
      _(`DocumentExtractor` trait, `NoopDocumentExtractor`,
      `MockDocumentExtractor` in
      `crates/core/src/models/document.rs`. Wired into
      `CoreImpl::send_media`: PDF / DOCX MIME types call
      `extract_text()` and each `DocumentPage` lands in
      `media_search_index` with `kind = "caption"` and
      `text = "[page {n}] {body}"`. Best-effort. Tests:
      `models::document::tests::*`,
      `core_impl::tests::send_media_writes_document_pages_when_extractor_installed`,
      `core_impl::tests::send_media_skips_extraction_for_non_document_mime`.)_
- [x] Resource-gated background processing: battery level, thermal
      state, charging, network type.
      _(`crates/core/src/models/resource_gate.rs` implements
      `DeviceResources`, `ThermalState`, `NetworkType`,
      `ResourcePolicy`, `ResourceGate` (separate gates for
      embedding / OCR / transcription / model-download), plus a
      `ResourceProbe` trait + `NoopResourceProbe`. Wired into
      `CoreImpl` via `install_resource_probe`. Tests:
      `models::resource_gate::tests::*`.)_
- [x] Model manager: lazy download on first semantic-search use
      (MobileCLIP-S2, Whisper) or eager pre-load (XLM-R),
      versioning, INT8/INT4 quantization, integrity-checked
      artifacts, warm-up strategy.
      _(`crates/core/src/models/model_manager.rs` defines
      `Quantization`, `ModelArtifact`, `ModelManagerConfig`, and
      `ModelManager` with `register / ensure / verify_integrity /
      list / delete / select_quantization`. The
      `ModelDownloader` trait is the `Send + Sync` HTTP seam
      (`NoopModelDownloader` returns `NotImplemented`); platform
      bridges supply the real downloader. Tests:
      `models::model_manager::tests::*`.)_
- [x] Encrypted vector / media index shard archive.
      _(Vector shard build/restore through `IndexType::Vector`
      and media shard build/restore through `IndexType::Media` in
      `crates/core/src/search/shard_builder.rs`; key derivation
      via `crypto::key_hierarchy::{derive_vector_index_shard,
      derive_media_index_shard}`. Tests:
      `search::shard_builder::tests::vector_shard_*` and
      `search::shard_builder::tests::media_shard_*` (including
      multilingual round-trip across en/ru/zh/ar plus the
      wrong-key and index-type-mismatch failure paths).)_
- [x] On-device reranking with semantic similarity scores.
      _(`SEMANTIC_WEIGHT = 1.5` between `BM25_WEIGHT = 2.0` and
      `FUZZY_WEIGHT = 1.0`, per PROPOSAL §7.5.
      `QueryEngine::execute_search_with_semantic` embeds the
      query, fans through
      `SemanticSearchEngine::search_semantic`, and merges hits
      into the FTS / fuzzy candidate set. Rows that hit both
      surfaces sum the contributions; semantic-only hits are
      materialized via `message_skeleton` lookup and reweighted
      by recency × content-kind. Falls back silently when no
      embedder is installed or the query is empty. Tests:
      `search::query_engine::tests::semantic_*`.)_
- [x] Desktop support: macOS (Core ML), Windows (DirectML EP
      preferred, CPU EP fallback).
      _(`crates/core/src/models/embeddings_onnx.rs` —
      `create_xlmr_session_with_ep` /
      `create_mobileclip_session_with_ep` accept an
      `ExecutionProvider` and configure
      `ort::CoreMLExecutionProvider` /
      `ort::DirectMLExecutionProvider` (CPU = no EP); EP
      initialization failures fall back to CPU.
      `crates/core/src/models/ep_tuning.rs::EpFallbackChain`
      returns the prioritized EP list per platform.
      `crates/desktop/src/ml_ep.rs::create_desktop_session` is
      the convenience entry point for desktop callers.)_
- [x] Cross-pipeline embedding cache: reuse `XLM-R` embeddings from
      `kennguy3n/slm-guardrail` in the search pipeline. Cache key
      `(message_id, model_version = 'xlmr@v1')`; backed by the
      `search_vector` table; version-mismatch invalidates. Trait:
      `crate::models::embeddings::EmbeddingCache`. See PROPOSAL §7.6.1.
      _(Trait `EmbeddingCache` + concrete
      `LocalStoreEmbeddingCache` in
      `crates/core/src/models/embeddings.rs`; wired into
      `CoreImpl::ingest_messages` (text path) and
      `CoreImpl::send_media` (image path) so a guardrail-pipeline
      vector short-circuits search-pipeline inference. Phase-6
      cross-pipeline test
      `crates/core/tests/phase6_embedding_cache.rs`:
      put/get round-trip with cosine > 0.999, version-mismatch →
      `None`, two-instance same-connection writes are mutually
      visible.)_
- [x] INT4 quantization for `XLM-R` and `MobileCLIP-S2` via ONNX
      Runtime `MatMulNBits`. Benchmark cosine-similarity correlation
      against the INT8 baseline using the multilingual relevance
      regression suite. INT4 ships as the default on devices with
      tight storage budgets (low-end Android, Windows tablets);
      INT8 remains the default on desktop and flagship mobile.
      _(Selection lives in
      `crates/core/src/models/model_manager.rs::select_quantization`:
      returns `Quantization::Int4` whenever
      `available_storage_bytes < TIGHT_STORAGE_THRESHOLD_BYTES`
      (512 MiB), else `Int8`. `ModelArtifactSpec` constants
      `XLMR_INT8_ARTIFACT` / `XLMR_INT4_ARTIFACT` /
      `MOBILECLIP_S2_INT8_ARTIFACT` /
      `MOBILECLIP_S2_INT4_ARTIFACT` pin the expected filenames;
      `ModelManager::resolve_artifact` selects the right one
      based on storage pressure. INT4 ONNX session helpers
      `create_xlmr_session_int4` / `create_mobileclip_session_int4`
      live behind `#[cfg(feature = "onnx-runtime")]` and return
      `NotImplemented` when the feature is off. The
      cosine-correlation benchmark vs INT8 is queued for the
      platform-bridge follow-up. Tests:
      `models::model_manager::tests::select_quantization_returns_int4_for_tight_storage`,
      `models::model_manager::tests::select_quantization_returns_int8_for_normal_storage`,
      `models::model_manager::tests::model_artifact_int4_variants_have_correct_names`,
      `models::model_manager::tests::resolve_artifact_selects_int4_when_storage_tight`.)_

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

- [x] macOS native integration (Spotlight anchors for app-internal
      results; `NSBackgroundActivityScheduler` for background work).
      _(Rust API surface complete:
      `crates/desktop/src/spotlight.rs::SpotlightAnchor` carries
      `index_items` / `remove_items` / `remove_all` with a
      `SpotlightItem` payload.
      `crates/desktop/src/background.rs::DesktopScheduler`
      carries `schedule_media_migration` and
      `schedule_shard_warming`.
      `crates/core/src/core_impl.rs::install_spotlight_anchor` /
      `update_spotlight_index` wire `ingest_messages` to
      forward new messages to the installed anchor. Native
      ObjC bridge attach (the actual `CSSearchableIndex` /
      `NSBackgroundActivityScheduler` calls) is the
      platform-bridge follow-up.)_
- [x] Windows native integration (Windows Search anchors; CPU-only
      ML; no GPU assumption).
      _(Rust API surface complete:
      `crates/desktop/src/windows_search.rs` adds
      `WindowsSearchItem` plus `index_items` / `remove_items` /
      `remove_all`.
      `crates/desktop/src/windows.rs::WindowsDesktopScheduler`
      models the Windows Task Scheduler semantics.
      `crates/desktop/src/ml_ep.rs::detect_gpu_available` lets
      `DesktopMlEpSelector::select` return `DirectMl` when a
      GPU is present and `Cpu` otherwise.
      `crates/core/src/core_impl.rs::install_windows_search_anchor`
      wires the same ingest-time forwarding as Spotlight.)_
- [x] Performance profiling and optimization (memory residency,
      CPU per request, battery cost per backup, peak transfer
      throughput).
      _(`crates/core/src/perf.rs` adds the p95 dashboard:
      `PerfSummary { count, p50_ns, p95_ns, p99_ns, max_ns,
      total_ns }`,
      `InMemoryPerfCollector::summarize` /
      `summarize_operation`, `PerfBudget` /
      `BudgetViolation` / `check_budgets` for budget
      enforcement. `CoreImpl::get_perf_summary` /
      `get_perf_summary_for` expose the dashboard. Perf trace
      coverage now spans `ingest_messages`, `search`,
      `enforce_storage_budget`, `hydrate_message`,
      `run_incremental_backup`, `compact_archive`, and
      `restore_from_backup`.)_
- [~] Large-scale testing: 100K+ messages, 10K+ media files,
      multilingual corpus across 10+ scripts.
      _(Scaffold lives in `crates/core/tests/large_scale.rs`
      behind `#[ignore]`: 10k multilingual ingest +
      FTS5 / fuzzy / QueryEngine round-trip across 12 scripts;
      5k media-asset eviction at Critical pressure;
      1k message backup → manifest-chain → restore round-trip;
      **2026-05-04 batch-5**: 100k message ingest + FTS5 /
      fuzzy / QueryEngine search; 10k media-asset round-trip
      across mixed MIME types and 4 sinks; 50k message ingest
      stress across 100 conversations; concurrent
      writer / reader / eviction stress.
      Run with `cargo test --test large_scale -- --ignored`.)_
- [x] Platform-specific ML execution-provider tuning (CoreML EP,
      NNAPI EP, optional DirectML EP on Windows when GPU is present).
      _(`crates/core/src/models/ep_tuning.rs` lands the full
      capture / cache / auto-selection pipeline:
      `EpBenchmarkRunner` trait + `NoopEpBenchmarkRunner` +
      `MockEpBenchmarkRunner`, `EpBenchmarkCache` with on-disk
      persistence and model-version invalidation,
      `select_best_ep` picking the lowest-p95 EP from the
      cache (falling back to `EpFallbackChain` when no
      benchmarks exist).
      `crates/core/src/models/model_manager.rs::benchmark_ep` /
      `select_optimal_ep` consult the cache before each
      session creation.
      `CoreImpl::install_ep_benchmark_runner` lets bridges
      register real runners.)_
- [x] Dedup analytics integration with `kennguy3n/zk-object-fabric`'s
      ContentIndex metrics (read-only telemetry, no plaintext leaks).
      _(`crates/core/src/transport/dedup_analytics.rs` adds
      `DedupEvent::{ObjectUploaded, ObjectDeleted}` +
      `DedupDashboard { stats, savings, recent_events }` +
      `InProcessDedupAnalytics` (Mutex + VecDeque ring buffer)
      for local capture +
      `ZkofDedupAnalytics` (S3-backed `metadata/content_index`
      reader with in-process fallback on transport failure).
      Backup and media sinks gain `with_dedup_analytics`
      builders so successful uploads / deletions record the
      right `DedupEvent`. `CoreImpl::record_dedup_event` /
      `get_dedup_dashboard` finish the pipeline. Privacy
      contract preserved: only opaque ciphertext-side
      metrics cross the boundary.)_
- [~] Edge-case handling: offline mode; interrupted backups;
      partial restores; corrupted chunks; missing manifests.
      _(Offline mode: `OfflineDetector` trait,
      `NoopOfflineDetector`, `AlwaysOfflineDetector`,
      `ToggleOfflineDetector` in
      `crates/core/src/transport/offline.rs`; wired into
      `CoreImpl` via `install_offline_detector` / `is_online`.
      `run_incremental_backup` defers (`BackupResult.deferred =
      true`) when offline; `hydrate_message` returns
      `is_cold = true` + `offline = true` when the body is
      remote-archive-only and the device is offline.
      Interrupted / partial / corrupted / missing variants
      already covered by the 8-of-8 failure suite below. Tests:
      `failure_scenarios::offline_during_backup_defers_upload_and_succeeds_on_reconnect`,
      `failure_scenarios::offline_during_hydration_returns_cold_with_offline_flag`.)_
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
- [x] Cross-platform media migration: iOS → Android migrates
      iCloud-resident media blobs to Google Drive (or ZKOF as
      platform-neutral fallback) in the background, rewriting
      `media_asset.storage_sink` and the related `MediaDescriptor`
      field as it goes. See PROPOSAL.md §5.7.
      _(In-tree pipeline + background-scheduling integration
      are now both done.
      `crates/core/src/media/migration.rs` provides the plan +
      executor with idempotent re-run + BLAKE3 transit-hash
      verification + optional source-blob delete.
      `crates/core/src/scheduler/mod.rs` adds
      `OneOffTask::MediaMigration { plan }` +
      `MediaMigrationPlanSnapshot` (CBOR-serialisable) +
      `TaskConstraints { require_wifi, require_charging,
      require_idle, max_retry_count }` +
      `BackgroundScheduler::schedule_one_off_task`.
      `crates/core/src/scheduler/in_process.rs::run_pending_tasks`
      drains the queue respecting Wi-Fi / charging / idle
      constraints via the `ResourceProbe`.
      `crates/core/src/core_impl.rs::schedule_media_migration` /
      `plan_and_schedule_media_migration` plus
      `KChatCoreConfig::auto_migrate_after_eviction` let
      `enforce_storage_budget` auto-queue a migration after
      successful eviction.)_
- [~] Media blob sink stress test: 10K+ media files across mixed
      sinks (KChat backend + iCloud + Google Drive + ZKOF in the
      same account); verify rehydration from each.
      _(2026-05-04 batch-5: `#[ignore]`-marked stress test in
      `crates/core/tests/media_sink_stress.rs` seeds 10 000
      assets split 40 / 20 / 20 / 20 across `kchat_backend`,
      `icloud`, `google_drive`, `zk_object_fabric`, asserts
      every `media_asset.storage_sink` round-trips, samples
      chunk-fetch round-trips per sink, and exercises the
      migration executor at scale by draining iCloud into
      Google Drive. Run with
      `cargo test --test media_sink_stress -- --ignored`.)_
- [x] **Failure test suite**, all passing:
  - [x] chunk upload interrupted mid-stream
        _(`crates/core/tests/failure_scenarios.rs::chunk_upload_interrupted_then_resumed_succeeds`:
        `MockTransportClient` returns `Error::Transport("connection reset")`
        after 2 of 5 chunks; `upload_chunked_media` surfaces the error and
        `resume_upload` skips the completed chunks before driving the rest
        through `commit_blob`.)_
  - [x] manifest upload interrupted mid-write
        _(`crates/core/tests/failure_scenarios.rs::manifest_upload_interrupted_mid_write_retries_without_chain_break`:
        a programmable `BackupSink` returns
        `Error::Transport("connection reset")` on the first
        `upload_backup_manifest` call. The test asserts the error
        variant, retries against a healthy sink, verifies the
        retry uploaded byte-for-byte identical bytes, and re-runs
        `verify_manifest_chain` to prove the gen 0 → gen 1 chain
        still validates after the retry — no duplicate
        generation, no chain break, no leftover sink state from
        the failed attempt.)_
  - [x] wrong backup key on restore
        _(`crates/core/tests/failure_scenarios.rs::wrong_backup_segment_key_fails_aead_open`
        bit-flips `K_backup_segment` and asserts `Error::Crypto`;
        `wrong_signing_key_on_manifest_chain_fails_signature_invalid`
        verifies a chain under an imposter hybrid Ed25519 + ML-DSA-65
        key and asserts
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
        builds a manifest signed by the original device's hybrid
        signing key, rotates the device-id signing key as if MLS
        removed the old device, and asserts `verify_manifest_chain`
        returns
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

---

## Phase 8: Multi-Scope, Multi-Tenant Search

**Goal**: Introduce conversation hierarchy (channels, communities, domains), multi-tenant B2B isolation, and search performance optimizations (bloom filters, shard cache, parallel fetch, progressive results) to support global, community, domain, and tenant-scoped search.

> This phase addresses the structural gaps in the search architecture
> when KChat introduces channels, communities (B2C), domains (B2B),
> and global search. The current codebase has a flat conversation
> model with no hierarchy and a single-conversation filter — both
> of which break down at community/domain/global scale.

Checklist:

- [x] **Schema: conversation hierarchy** — Add `conversation_type` (`dm` | `group` | `channel`), `scope` (`b2c` | `b2b`), `tenant_id`, `community_id`, `domain_id` columns to the `conversation` table. Add indexes: `idx_conv_community`, `idx_conv_domain`, `idx_conv_tenant`, `idx_conv_scope`. File: `crates/core/src/local_store/schema.rs`. _(Landed: `conversation` DDL in `schema.rs::SCHEMA_SQL` carries the five hierarchy columns and the four indexes; `Conversation` struct in the same module mirrors them with `#[serde(default)]` for backward compat.)_

- [x] **Schema: archive_segment_map tenant isolation** — Add `tenant_id TEXT NOT NULL DEFAULT ''` column and `idx_asm_tenant_bucket` index to `archive_segment_map`. File: `crates/core/src/local_store/schema.rs`. _(Landed: `archive_segment_map` in `schema.rs` carries `tenant_id TEXT NOT NULL DEFAULT ''` and `idx_asm_tenant_bucket(tenant_id, time_bucket)`; column-count regression test updated to 9.)_

- [x] **SearchTarget enum** — Replace `conversation_filter: Option<Uuid>` on `SearchQuery` with a `target: SearchTarget` field. `SearchTarget` variants: `Conversation(Uuid)`, `Community(Uuid)`, `Domain(Uuid)`, `Tenant(String)`, `B2cAll`, `Global` (default). File: `crates/core/src/lib.rs`. _(Landed: `SearchTarget` enum + `SearchQuery::target` (`#[serde(default)]`) + `effective_target()` mapping `conversation_filter` → `SearchTarget::Conversation` for backward compat.)_

- [x] **Scope resolver** — Implement `resolve_target_to_conversation_set(target: &SearchTarget, db: &LocalStoreDb) -> HashSet<String>` that maps each `SearchTarget` variant to a set of `conversation_id`s via SQL lookups on the new conversation columns. File: `crates/core/src/search/query_engine.rs`. _(Landed: `resolve_target_to_conversation_set` + `push_target_filter` wired into both `execute_structured_only` and `allowed_skeleton_ids`; `Global` returns `None` (no filter); empty resolution emits a `1=0` SQL clause for fail-closed behavior. Helper queries `list_conversations_by_{community, domain, tenant, scope}` live on `LocalStoreDb`.)_

- [x] **Bucket-level date pruning** — Before the `for (conv, bucket) in buckets` loop in `execute_search_with_cold_source`, parse each `time_bucket` string into a `(start_ms, end_ms)` range and skip buckets that fall entirely outside `[date_from, date_to]`. Implement `bucket_overlaps_date_range(bucket: &str, date_from: Option<i64>, date_to: Option<i64>) -> bool`. File: `crates/core/src/search/query_engine.rs`. _(Landed batch 6: `bucket_overlaps_date_range` + `parse_bucket_range_ms` filter the cold loop before any transport call. Tests: `bucket_overlaps_with_no_date_filters_returns_true`, `bucket_overlaps_rejects_bucket_before_date_from`, `bucket_overlaps_rejects_bucket_after_date_to`, `bucket_overlaps_accepts_overlapping_bucket`, `bucket_overlaps_handles_malformed_bucket_gracefully`. Integration: `cold_search_with_date_range_skips_irrelevant_buckets`.)_

- [x] **Bloom filter shard type** — Add `IndexType::Bloom` variant to the shard format enum. Implement `build_bloom_shard` / `restore_bloom_shard` in `crates/core/src/search/shard_builder.rs`. At shard build time, construct a bloom filter over the lowercased words in the bucket. Upload as a new shard type alongside `[Text, Fuzzy, Vector, Media]`. Add `fetch_bloom_filter()` to the `ColdShardSource` trait. Files: `crates/core/src/formats/search_shard.rs`, `crates/core/src/search/shard_builder.rs`, `crates/core/src/search/cold_shard_source.rs`. _(Landed: `IndexType::Bloom` variant; `BloomFilter` (3 BLAKE3 keyed-hash slots, 12 bits / element default), `BloomShardPayload`, `build_bloom_shard`, `restore_bloom_shard`; `cold_shard_source::shard_type_str` covers `IndexType::Bloom`; prefetch order is now `[Bloom, Text, Fuzzy, Vector, Media]`. Tests: round-trip, wrong-key rejection, FPR < 5%, multilingual word survival. Batch 6 finishes the `ColdShardSource` API: a default-`Ok(None)` `fetch_bloom_shard` method returns the decrypted `BloomShardPayload` so callers don't have to handle the wire envelope; `TransportColdShardSource` implements it via `IndexType::Bloom`.)_

- [x] **Bloom filter pre-check in cold fan-out** — Before fetching full text + fuzzy shards for a cold bucket, fetch the (tiny) bloom shard first. Check if query terms could exist in the bucket. Only download full shards for buckets where the bloom filter says "maybe match". File: `crates/core/src/search/query_engine.rs`. _(Landed batch 6: `bloom_might_contain_any` + bloom-shard probe inside the cold loop. Missing shards or transport errors fall through to the full fetch (graceful degradation). Tests: `bloom_precheck_skips_bucket_when_all_tokens_rejected`, `bloom_precheck_passes_bucket_when_any_token_matches`, `bloom_precheck_falls_through_when_bloom_shard_missing`, `bloom_precheck_falls_through_on_transport_error`. Integration: `bloom_filter_eliminates_irrelevant_cold_buckets` in `crates/core/tests/phase8_multi_scope_search.rs`.)_

- [x] **On-device decrypted shard cache (LRU)** — Implement `ShardCache` with LRU eviction keyed by `(conversation_id, time_bucket, IndexType)` → decrypted rows. Configurable memory budget (default 50 MB). Integrate into the cold fan-out path so subsequent searches reuse cached shards without network round-trips. File: `crates/core/src/search/cold_shard_source.rs` (new `ShardCache` struct). _(Landed batch 6 in a new `crates/core/src/search/shard_cache.rs` module — `ShardCache`, `ShardCacheKey`, `CachedShard`. Default budget `DEFAULT_SHARD_CACHE_BUDGET_BYTES = 50 * 1024 * 1024`. Mounted on `CoreImpl` via `install_shard_cache(max_bytes)` and consulted by `execute_search_with_cold_source_full`. Tests: `shard_cache_put_get_round_trip`, `shard_cache_evicts_lru_when_over_budget`, `shard_cache_hit_avoids_transport_fetch`, `shard_cache_clear_empties_all`, `shard_cache_respects_max_bytes`. Integration: `shard_cache_eliminates_refetch_on_repeated_search`.)_

- [x] **Parallel bucket fetch** — Replace the sequential `for (conv, bucket) in buckets` loop with bounded-concurrency parallel fetch (e.g., 4-8 concurrent fetches). The `ColdShardSource` trait may need a batch/async variant. Merge results after all fetches complete. File: `crates/core/src/search/query_engine.rs`. _(Landed: `KChatCoreConfig::max_cold_fetch_concurrency` (default 4) plus `execute_search_with_cold_source_full_parallel` use `std::thread::scope` to fan cold-bucket fetches over a bounded thread pool. Per-bucket errors are logged and skipped (fail-open per bucket). Tests: `parallel_fetch_returns_same_results_as_sequential`, `parallel_fetch_respects_concurrency_limit`, `parallel_fetch_survives_single_bucket_error`, `parallel_fetch_empty_buckets_returns_empty`. Integration: `parallel_fetch_global_search_10_buckets` in `crates/core/tests/phase8_multi_scope_search.rs`.)_

- [x] **Progressive/streaming search results** — Define `SearchEvent` enum (`LocalResults`, `ColdBucketComplete`, `SearchComplete`). Return local results immediately, then stream cold results as each bucket completes. File: `crates/core/src/search/query_engine.rs`, `crates/core/src/lib.rs`. _(Landed: `SearchEvent::{LocalResults, ColdBucketComplete, SearchComplete}` in `crates/core/src/lib.rs` + `execute_search_streaming` (callback-based) in `crates/core/src/search/query_engine.rs` + `CoreImpl::search_streaming` wrapper. iOS / Android bridges expose the streaming API via a `SearchEventListener` callback interface. Tests: `streaming_search_emits_local_results_first`, `streaming_search_emits_cold_bucket_complete_per_bucket`, `streaming_search_emits_search_complete_last`, `streaming_search_local_only_skips_cold_events`, `streaming_search_no_cold_buckets_emits_complete_immediately`.)_

- [x] **Background shard warming (P5 idle)** — During idle time (charging + Wi-Fi), pre-fetch and decrypt cold shards into the on-device shard cache. Aligns with the existing `OpportunisticFill` hydration priority (P5). File: `crates/core/src/search/cold_shard_source.rs`, `crates/core/src/offload/hydration.rs`. _(Landed batch 6: `warm_shard_cache(cache, cold_source, gate, resources, recent)` in `crates/core/src/search/shard_cache.rs` + `ResourceGate::should_warm_shards` in `crates/core/src/models/resource_gate.rs` + `TaskType::ShardCacheWarming` in `crates/core/src/scheduler/mod.rs`. Early-exits on gate failure / empty input / zero budget; otherwise populates Bloom, Text, and Fuzzy cache slots for each `(conv, bucket)` recent pair. Tests: `warm_shard_cache_populates_cache_for_recent_conversations`, `warm_shard_cache_respects_resource_gate`, `warm_shard_cache_noop_when_no_cold_buckets`, `warm_shard_cache_respects_cache_budget`.)_

- [x] **Per-tenant key isolation (B2B)** — Extend the key hierarchy with `K_b2b_tenant_root(tenant_id)` derived from `K_user_master`, and per-tenant `K_b2b_archive_epoch` / `K_b2b_text_index_shard` derivation paths. File: `crates/core/src/crypto/key_hierarchy.rs`. _(Landed batch 6: `derive_b2b_tenant_root`, `derive_b2b_archive_epoch`, `derive_b2b_text_index_shard` + `info::B2B_TENANT_ROOT` / `B2B_ARCHIVE_EPOCH` / `B2B_TEXT_INDEX_SHARD`. Tests: `derive_b2b_tenant_root_is_deterministic`, `different_tenant_ids_produce_different_roots`, `b2b_tenant_root_differs_from_b2c_archive_root`, `derive_b2b_archive_epoch_is_deterministic`, `derive_b2b_text_index_shard_is_deterministic`, `b2b_shard_key_differs_from_b2c_shard_key_for_same_shard_id`. Integration: `b2b_tenant_key_isolation`.)_

- [x] **TenantSearchPolicy** — Add `TenantSearchPolicy { allow_global_search, allow_cross_tenant_results, max_cold_buckets_per_search, require_bloom_shards }` to config. Apply tenant policies during cold fan-out to skip buckets from tenants that disallow global search. Files: `crates/core/src/config.rs`, `crates/core/src/search/query_engine.rs`. _(Landed batch 6: `TenantSearchPolicy` struct with the four documented fields and an idiomatic `impl Default`; `KChatCoreConfig::tenant_search_policies: HashMap<String, TenantSearchPolicy>` (`#[serde(default)]`). `execute_search_with_cold_source_full` short-circuits forbidden Global queries before `cold_buckets()`, caps the fan-out at `max_cold_buckets_per_search`, and skips buckets without bloom shards when `require_bloom_shards`. Tests: `tenant_policy_blocks_global_search_when_disabled`, `tenant_policy_caps_cold_bucket_count`, `tenant_policy_requires_bloom_when_configured`, `tenant_policy_default_allows_everything`, `tenant_policy_serde_round_trip`. Integration: `tenant_policy_blocks_global_search`.)_

- [x] **Privacy-aware scope-proportional padding** — Scale the dummy-request padding count proportionally to the search scope size. For global search, the padding ratio should be higher to obscure cross-tenant access patterns. File: `crates/core/src/search/shard_prefetch.rs`. _(Landed batch 6: `compute_scope_padding_multiplier(target)` + `batch_prefetch_shards_with_padding_for_target`. Multipliers — Conversation/Group/Channel/Starred/Unread = 1×, Community/Domain = 2×, Tenant/B2cAll = 3×, Global = 4×. Tests: `scope_padding_multiplier_conversation_is_1`, `scope_padding_multiplier_global_is_4`, `scope_padding_multiplier_climbs_monotonically_with_scope`, `batch_prefetch_with_global_scope_generates_more_dummies_than_conversation_scope`. Integration: `scope_proportional_padding_scales_with_target`.)_

- [x] **K_bloom_index_shard key derivation** — Add `derive_bloom_index_shard` to the key hierarchy under `K_search_root`. File: `crates/core/src/crypto/key_hierarchy.rs`. _(Landed: `derive_bloom_index_shard` + `info::BLOOM_INDEX_SHARD = b"kchat-bloom-index-shard-v1"`; covered by `derive_bloom_index_shard_is_deterministic` and `derive_bloom_index_shard_differs_from_text_and_vector`.)_

- [x] **Android/iOS bridge updates** — Update the bridge layers to accept `SearchTarget` instead of `conversation_filter`. Files: `crates/android-bridge/src/lib.rs`, `crates/ios-bridge/src/lib.rs`. _(Landed batch 6: Android `KChatBridgeHandle::search_with_target(query_json, target_json, scope)` plus a `SearchTarget` JSON shape mirroring `kchat_core::SearchTarget`; the legacy `search` keeps defaulting to `SearchTarget::Global`. iOS adds an FFI-shaped `SearchTarget` enum with `into_core` mapping to `kchat_core::SearchTarget` and an optional `target` field on `SearchQuery`; `crates/ios-bridge/src/kchat.udl` mirrors the enum and `SearchTarget? target;` field. Tests: `android_bridge_search_with_conversation_target`, `android_bridge_search_with_global_target_default`, `android_bridge_search_with_community_target`, `ios_bridge_search_target_round_trip`, `ios_bridge_search_defaults_to_global`.)_

- [x] **Latency budget: bloom + parallel fetch** — Benchmark the bloom-filter pre-check + parallel fetch path. Target: global search over 100 cold buckets completes bloom pre-check in < 2s, full shard fetch for matching buckets in < 5s total (parallel). File: `crates/core/benches/phase8_benchmarks.rs`. _(Landed batch 6: five criterion benches in `crates/core/benches/phase8_benchmarks.rs` — `bloom_precheck_one_month_bucket`, `shard_cache_hit_vs_miss`, `scope_resolver_community_100_conversations`, `date_pruning_100_buckets`, `global_search_with_bloom_10_buckets`. Wired into `crates/core/Cargo.toml` `[[bench]] name = "phase8_benchmarks" harness = false`. Run via `cargo bench -p kchat-core --bench phase8_benchmarks`. The parallel-fetch budget is gated on the still-deferred parallel-fetch implementation.)_

- [x] **Integration tests** — End-to-end tests for community-scoped search, domain-scoped search, tenant-scoped search, global search with bloom filter pruning, shard cache hit/miss, and tenant policy enforcement. File: `crates/core/tests/phase8_multi_scope_search.rs`. _(Landed batch 6: 10 end-to-end tests in `crates/core/tests/phase8_multi_scope_search.rs` — `community_scoped_search_returns_only_community_conversations`, `domain_scoped_search_returns_only_domain_conversations`, `tenant_scoped_search_returns_only_tenant_conversations`, `global_search_returns_all_conversations`, `bloom_filter_eliminates_irrelevant_cold_buckets`, `shard_cache_eliminates_refetch_on_repeated_search`, `tenant_policy_blocks_global_search`, `date_pruning_skips_old_buckets`, `b2b_tenant_key_isolation`, `scope_proportional_padding_scales_with_target`.)_

**Decision gate**: Community and domain-scoped search prunes cold buckets to the target scope. Bloom filter pre-check eliminates 80%+ of irrelevant buckets on a global search. Shard cache eliminates re-fetches on repeated searches. B2B tenant data is cryptographically isolated under per-tenant keys. Tenant search policies are enforced.

Priority order:
1. Schema + SearchTarget (foundation)
2. Bucket-level date pruning (trivial, high impact when dates are set)
3. Bloom filter shards (highest impact for community/domain/global search)
4. Shard cache (LRU) (eliminates re-fetches)
5. Parallel fetch (reduces wall-clock time)
6. Progressive streaming (UX improvement)
7. Per-tenant key isolation (B2B compliance)
8. Tenant search policy (B2B admin controls)
9. Background shard warming (best long-term)
