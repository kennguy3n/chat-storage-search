# KChat Storage & Search — Phased Delivery Plan

**License**: Proprietary — All Rights Reserved. See [LICENSE](../LICENSE).

This document is a phase-gated delivery plan. Each phase has an
explicit goal, a checklist, and a decision gate. Do not skip to the
next phase until the current phase's gate has been met. Status is
tracked in [PROGRESS.md](PROGRESS.md).

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

> **Note — Hybrid manifest signing.** Backup and archive manifests
> are signed with a hybrid Ed25519 + ML-DSA-65 (FIPS 204) scheme
> per NIST SP 800-227. Verification requires both legs to validate;
> either failing rejects the manifest. See PROPOSAL.md §2 and §6.3.

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
- [x] Local schema (`conversation`, `message_skeleton`,
      `message_body`, `media_asset`, `backup_event_journal`,
      `archive_segment_map`, `restore_state`) — see
      [ARCHITECTURE.md §4](ARCHITECTURE.md).
- [x] Message processor: ingest MLS-decrypted application messages,
      outbox, idempotency, dedup against client message ID.
- [x] FTS5 with **ICU tokenizer** (`tokenize = 'icu'`) for
      multilingual full-text search; documented fallback to
      `unicode61 remove_diacritics 2`.
- [x] Structured search (sender, date range, conversation, content
      kind).
- [x] Body state machine (`local_plain_available`,
      `local_encrypted_available`, `delivery_store_only`,
      `deleted_for_me`, `deleted_for_everyone`, `unavailable`,
      `remote_archive_only`).
- [x] UniFFI bridge: generated Swift package consumable from
      KChat.app and any iOS extensions sharing the local store.
- [x] JNI bridge: idiomatic Kotlin façade over the generated JNI
      bindings.
- [x] Core public API surface: `initialize`, `register_device`,
      `send_text`, `ingest_remote_messages`, `search`.
- [x] Unit + integration test suite covering multilingual corpora
      (Latin, Cyrillic, CJK, Arabic, Hebrew, Thai, Devanagari, mixed-
      script messages).
- [x] Performance validation: insert text < 20 ms p95; search recent
      < 150 ms p95.

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
- [x] Chunked encrypted blob upload / download in the transport
      client (`POST /v1/blobs/init`, `PUT chunks/{idx}`,
      `POST .../commit`, `GET ...?range=`).
- [ ] Media descriptor distribution through MLS (asset_id, K_asset,
      mime, sizes, Merkle root, blob_id, chunk_count).
- [x] Local media cache with LRU eviction; encrypted on disk.
- [x] Resume-upload (re-upload only missing chunks; idempotent
      commit on retry).
- [x] Chunk integrity verification: per-chunk SHA-256, whole-object
      Merkle root (BLAKE3), AEAD tag.
- [x] Media state machine (`thumbnail_only`, `original_local`,
      `remote_original`, `download_in_progress`, `evicted`,
      `deleted`).
- [x] Size-class padding for metadata privacy (PROPOSAL §8.2).
- [x] Per-chunk AEAD AAD construction (`KCHAT_BLOB_CHUNK_V1` …
      PROPOSAL §8.3).
- [x] Multilingual filename / caption handling (UTF-8 canonicalization;
      no English-only assumptions).
- [x] `StorageSink` enum and `ArchiveBackend` enum in config
      (`crates/core/src/config.rs`). See PROPOSAL.md §5.7.
- [x] `storage_sink` field on `MediaDescriptor` (CBOR,
      `#[serde(default)]` for backward compat).
- [x] `storage_sink` column on `media_asset` table (schema
      migration with `DEFAULT 'kchat_backend'`).
- [x] `MediaBlobSink` trait: object-safe, `Send + Sync`, with
      `upload_media_chunks` / `fetch_media_chunk` /
      `delete_media_blob`. See PROPOSAL.md §5.7 and §10.2.
- [x] `NoopMediaBlobSink` placeholder returning
      `Error::NotImplemented("media_blob_sink")` from every method.
- [x] Media upload routing: thumbnails always go to the
      `TransportClient` (KChat backend); originals route to the
      configured `MediaBlobSink` (default: `TransportClient`
      fallback when `media_blob_sink = None`).
- [x] Media rehydration routing: `media_asset.storage_sink`
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

Checklist:

- [x] Archive event journal (every durable mutation writes an
      archive event).
- [x] Archive segment builder: per-conversation, per-time-bucket
      segments for `message_delta`, `timeline_skeleton`,
      `media_key_delta`, `search_text_index`,
      `search_vector_index`, `media_index`, `checkpoint`.
- [x] Archive manifest chain (generation N+1 referencing N via
      `previous_manifest_hash`; hybrid Ed25519 + ML-DSA-65 signature).
- [x] Encrypted segment upload to the KChat backend's blob service.
- [x] Whole-object Merkle-root verification after upload commit.
- [x] Archive state machine (`not_archived` → `archive_pending` →
      `archive_uploaded` → `archive_verified` → `archive_compacted`).
- [x] Storage budget enforcement (`enforceStorageBudget`).
- [x] Eviction scoring formula (PROPOSAL §5.4).
- [x] Eviction priority order: video → documents → images → voice →
      thumbnails (under severe pressure) → cold text bodies (under
      extreme pressure).
- [x] Pinned-chat / pinned-message exclusion.
- [x] Timeline-skeleton rehydration on scroll-back (no scroll-jump
      on update).
- [x] Lazy media rehydration on tap.
- [x] Prefetch window management (viewport ± 100–150 messages).
- [x] Hydration priority queue (P0 → P5).
- [x] Epoch-rotated archive key derivation: `K_archive_root` →
      `K_archive_epoch(epoch_id)` → `K_archive_segment` /
      `K_archive_manifest`. HKDF info =
      `"kchat-archive-epoch-v1" || epoch_id`. Default epoch
      cadence: monthly (matching `time_bucket`).
- [x] Epoch key lifecycle: current epoch key in memory; prior
      epoch keys wrapped under `K_archive_root` and recorded in
      the archive manifest chain. Optional epoch-key deletion
      for forward secrecy.
- [x] Epoch key derivation test vectors (Rust): deterministic
      derivation, epoch rotation, wrapped-key round-trip,
      cross-epoch segment decrypt after manifest-chain unwrap.
- [x] ZK Object Fabric as optional archive backend: S3-compatible
      transport adapter for archive segment upload / download /
      manifest storage. Configured via `archive_backend = "zkof"`
      + ZKOF tenant credentials.
- [x] Archive backend routing: transport client routes archive
      operations to KChat backend or ZKOF based on configuration.
      Manifest index stored as a well-known S3 key when using ZKOF.
- [x] Batch-by-bucket prefetch: on any archive segment miss, fetch
      all segments for the `(conversation_id, time_bucket)` pair.
      Reduces per-segment access-pattern metadata to per-bucket
      granularity.
- [x] Dummy request padding (optional, off by default): mix real
      rehydration fetches with dummy fetches to random segment IDs.
      Enabled via `privacy_level = "high"`.
- [~] iCloud `MediaBlobSink` implementation (CloudKit file
      storage). See PROPOSAL.md §10.2.
- [~] Google Drive `MediaBlobSink` implementation (Drive API via
      the Android / desktop platform bridge). See PROPOSAL.md
      §10.2.
- [x] ZK Object Fabric `MediaBlobSink` implementation (S3
      `PutObject` / `GetObject`). See PROPOSAL.md §10.2.
- [x] Tiered eviction policy: media originals offload to the
      configured user cloud sink before archive segments offload
      to the KChat backend.
- [x] `storage_backend` column on `archive_segment_map` for
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

- [x] Backup event journal.
- [x] Incremental backup segment builder.
- [x] Backup manifest chain with hybrid Ed25519 + ML-DSA-65
      signature.
- [x] iOS iCloud backup sink (iCloud container file storage).
- [x] Android backup sink strategy: Auto Backup for small recovery
      envelopes / manifest pointers; Large Backup or SAF for full
      data.
- [x] **ZK Object Fabric backup sink** (S3 API; Pattern C convergent
      encryption; bit-identical interop with the Go SDK at
      `kennguy3n/zk-object-fabric/encryption/client_sdk/`).
- [x] Backup compaction: daily deltas → weekly checkpoint → monthly
      prune of superseded deltas.
- [x] Manifest chain verification on restore (signature +
      `previous_manifest_hash` walk).
- [x] Skeleton-first restore: conversation list → timeline
      skeletons → search index shards → recent bodies → lazy media.
- [x] Restore state machine (`identity_restored` → `root_keys_unwrapped`
      → `manifest_verified` → `skeleton_restored` →
      `search_restored` → `recent_messages_restored` →
      `media_lazy_restore_enabled` → `full_restore_complete`).
- [x] Key recovery (device-to-device transfer, recovery key,
      passphrase). Server escrow remains off by default.
- [x] Search index backup and restore (encrypted text / fuzzy /
      vector / media shards).
- [x] Multilingual restore validation: corpora across CJK / Arabic /
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

- [x] Fuzzy token index: trigrams for Latin / Cyrillic / Greek /
      Devanagari / Tamil / Bengali / Hangul; bigrams for logographic
      CJK runs.
- [x] Script-aware fuzzy matching: per-token script tag drives
      lookup; script-appropriate edit distance.
- [x] Encrypted search shard archive (text and fuzzy index shards
      sealed with `K_text_index_shard`).
- [x] Search shard fetch from the backend
      (`GET /v1/archive/index-shards?conversation_hash=&bucket=&type=`).
- [x] Cold-result hydration: search hit on offloaded content →
      fetch shard → decrypt locally → search → hydrate body / media
      on tap.
- [x] Unified query engine: parse → fan-out → merge → rerank.
- [x] Ranking formula implementation (PROPOSAL §7.5).
- [x] Mixed-language query handling: a single query may interleave
      scripts; both sides of the query reach the appropriate fuzzy
      index.
- [x] Latency budget: encrypted shard fetch + decrypt + local
      search ≤ 1.5 s p95 over Wi-Fi for a one-month bucket.
- [x] Batch shard prefetch by time bucket: when fetching encrypted
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

- [x] ONNX Runtime integration via the
      [`ort`](https://crates.io/crates/ort) crate.
- [x] Multilingual text embedding model (`XLM-R`, ~80–100 MB INT8
      ONNX) wired through the search pipeline. Same encoder as
      `kennguy3n/slm-guardrail`, unifying the text encoder across
      the platform. English-only MiniLM-L6 is **rejected**.
- [x] HNSW vector index for semantic text search.
- [x] `MobileCLIP-S2` integration for image search (multilingual
      text→image, ~80 MB INT8 ONNX).
- [x] Video keyframe sampling and `MobileCLIP-S2` embeddings.
- [x] Whisper multilingual integration for voice-message transcription:
      Apple MLX (`mlx-community/whisper-base-mlx`) on Apple Silicon
      (preferred — Neural Engine, lower latency / battery cost);
      ONNX Runtime (`whisper-base` ~140 MB INT8, INT4 not supported
      for audio transcription) on all other platforms (Intel macOS,
      Windows, Android, Linux); `whisper-tiny` (~75 MB) on low-end
      Android. See PROPOSAL §7.6 / §7.7.
- [x] Platform OCR bridge: Vision (`VNRecognizeTextRequest`) on
      iOS / macOS; ML Kit Text Recognition v2 on Android;
      `Windows.Media.Ocr` / Tesseract on Windows.
- [x] Document text extraction (PDF, DOCX) with multilingual
      handling and page-level indexing.
- [x] Resource-gated background processing: battery level, thermal
      state, charging, network type.
- [x] Model manager: lazy download on first semantic-search use
      (MobileCLIP-S2, Whisper) or eager pre-load (XLM-R),
      versioning, INT8/INT4 quantization, integrity-checked
      artifacts, warm-up strategy.
- [x] Encrypted vector / media index shard archive.
- [x] On-device reranking with semantic similarity scores.
- [x] Desktop support: macOS (Core ML), Windows (DirectML EP
      preferred, CPU EP fallback).
- [x] Cross-pipeline embedding cache: reuse `XLM-R` embeddings from
      `kennguy3n/slm-guardrail` in the search pipeline. Cache key
      `(message_id, model_version = 'xlmr@v1')`; backed by the
      `search_vector` table; version-mismatch invalidates. Trait:
      `crate::models::embeddings::EmbeddingCache`. See PROPOSAL §7.6.1.
- [x] INT4 quantization for `XLM-R` and `MobileCLIP-S2` via ONNX
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

- [x] macOS native integration (Spotlight anchors for app-internal
      results; `NSBackgroundActivityScheduler` for background work).
- [x] Windows native integration (Windows Search anchors; CPU-only
      ML; no GPU assumption).
- [x] Performance profiling and optimization (memory residency,
      CPU per request, battery cost per backup, peak transfer
      throughput).
- [~] Large-scale testing: 100K+ messages, 10K+ media files,
      multilingual corpus across 10+ scripts.
- [x] Platform-specific ML execution-provider tuning (CoreML EP,
      NNAPI EP, optional DirectML EP on Windows when GPU is present).
- [x] Dedup analytics integration with `kennguy3n/zk-object-fabric`'s
      ContentIndex metrics (read-only telemetry, no plaintext leaks).
- [~] Edge-case handling: offline mode; interrupted backups;
      partial restores; corrupted chunks; missing manifests.
- [x] Archive compaction at production scale (per account +
      conversation + bucket: collect old deltas → apply tombstones →
      rebuild compact segment → upload → new manifest → mark old
      expired).
- [x] Cross-platform media migration: iOS → Android migrates
      iCloud-resident media blobs to Google Drive (or ZKOF as
      platform-neutral fallback) in the background, rewriting
      `media_asset.storage_sink` and the related `MediaDescriptor`
      field as it goes. See PROPOSAL.md §5.7.
- [~] Media blob sink stress test: 10K+ media files across mixed
      sinks (KChat backend + iCloud + Google Drive + ZKOF in the
      same account); verify rehydration from each.
- [x] **Failure test suite**, all passing:
  - [x] chunk upload interrupted mid-stream
  - [x] manifest upload interrupted mid-write
  - [x] wrong backup key on restore
  - [x] corrupted chunk (Merkle / SHA-256 mismatch)
  - [x] device removed from MLS group between backup and restore
  - [x] search shard missing from the backend
  - [x] low-storage condition during restore
  - [x] manifest chain break detected on restore

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

- [x] **Schema: conversation hierarchy** — Add `conversation_type` (`dm` | `group` | `channel`), `scope` (`b2c` | `b2b`), `tenant_id`, `community_id`, `domain_id` columns to the `conversation` table. Add indexes: `idx_conv_community`, `idx_conv_domain`, `idx_conv_tenant`, `idx_conv_scope`.
- [x] **Schema: archive_segment_map tenant isolation** — Add `tenant_id TEXT NOT NULL DEFAULT ''` column and `idx_asm_tenant_bucket` index to `archive_segment_map`.
- [x] **SearchTarget enum** — Replace `conversation_filter: Option<Uuid>` on `SearchQuery` with a `target: SearchTarget` field. `SearchTarget` variants: `Conversation(Uuid)`, `Community(Uuid)`, `Domain(Uuid)`, `Tenant(String)`, `B2cAll`, `Global` (default).
- [x] **Scope resolver** — Implement `resolve_target_to_conversation_set(target: &SearchTarget, db: &LocalStoreDb) -> HashSet<String>` that maps each `SearchTarget` variant to a set of `conversation_id`s via SQL lookups on the new conversation columns.
- [x] **Bucket-level date pruning** — Before the `for (conv, bucket) in buckets` loop in `execute_search_with_cold_source`, parse each `time_bucket` string into a `(start_ms, end_ms)` range and skip buckets that fall entirely outside `[date_from, date_to]`. Implement `bucket_overlaps_date_range(bucket: &str, date_from: Option<i64>, date_to: Option<i64>) -> bool`.
- [x] **Bloom filter shard type** — Add `IndexType::Bloom` variant to the shard format enum. Implement `build_bloom_shard` / `restore_bloom_shard` in `crates/core/src/search/shard_builder.rs`. At shard build time, construct a bloom filter over the lowercased words in the bucket. Upload as a new shard type alongside `[Text, Fuzzy, Vector, Media]`. Add `fetch_bloom_filter()` to the `ColdShardSource` trait.
- [x] **Bloom filter pre-check in cold fan-out** — Before fetching full text + fuzzy shards for a cold bucket, fetch the (tiny) bloom shard first. Check if query terms could exist in the bucket. Only download full shards for buckets where the bloom filter says "maybe match".
- [x] **On-device decrypted shard cache (LRU)** — Implement `ShardCache` with LRU eviction keyed by `(conversation_id, time_bucket, IndexType)` → decrypted rows. Configurable memory budget (default 50 MB). Integrate into the cold fan-out path so subsequent searches reuse cached shards without network round-trips.
- [x] **Parallel bucket fetch** — Replace the sequential `for (conv, bucket) in buckets` loop with bounded-concurrency parallel fetch (e.g., 4-8 concurrent fetches). The `ColdShardSource` trait may need a batch/async variant. Merge results after all fetches complete.
- [x] **Progressive/streaming search results** — Define `SearchEvent` enum (`LocalResults`, `ColdBucketComplete`, `SearchComplete`). Return local results immediately, then stream cold results as each bucket completes.
- [x] **Background shard warming (P5 idle)** — During idle time (charging + Wi-Fi), pre-fetch and decrypt cold shards into the on-device shard cache. Aligns with the existing `OpportunisticFill` hydration priority (P5).
- [x] **Per-tenant key isolation (B2B)** — Extend the key hierarchy with `K_b2b_tenant_root(tenant_id)` derived from `K_user_master`, and per-tenant `K_b2b_archive_epoch` / `K_b2b_text_index_shard` derivation paths.
- [x] **TenantSearchPolicy** — Add `TenantSearchPolicy { allow_global_search, allow_cross_tenant_results, max_cold_buckets_per_search, require_bloom_shards }` to config. Apply tenant policies during cold fan-out to skip buckets from tenants that disallow global search.
- [x] **Privacy-aware scope-proportional padding** — Scale the dummy-request padding count proportionally to the search scope size. For global search, the padding ratio should be higher to obscure cross-tenant access patterns.
- [x] **K_bloom_index_shard key derivation** — Add `derive_bloom_index_shard` to the key hierarchy under `K_search_root`.
- [x] **Android/iOS bridge updates** — Update the bridge layers to accept `SearchTarget` instead of `conversation_filter`.
- [x] **Latency budget: bloom + parallel fetch** — Benchmark the bloom-filter pre-check + parallel fetch path. Target: global search over 100 cold buckets completes bloom pre-check in < 2s, full shard fetch for matching buckets in < 5s total (parallel).
- [x] **Integration tests** — End-to-end tests for community-scoped search, domain-scoped search, tenant-scoped search, global search with bloom filter pruning, shard cache hit/miss, and tenant policy enforcement.

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
