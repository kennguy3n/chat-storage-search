# KChat Storage & Search — Progress

**License**: Proprietary — All Rights Reserved. See [LICENSE](../LICENSE).

This document is the phase-gated tracker. Each phase lists the
status, the goal, the live checklist, and the decision gate that
must be met before moving on. For the design, see
[PROPOSAL.md](PROPOSAL.md). For the system architecture, see
[ARCHITECTURE.md](ARCHITECTURE.md). For the full phased delivery
plan, see [PHASES.md](PHASES.md).

## Phase summary

| Phase | Name                                | Status        | Completion |
| ----- | ----------------------------------- | ------------- | ---------: |
| 0     | Protocol and Test Vectors           | Complete      |     100 %  |
| 1     | Local Store + Text Search + MLS     | In progress   |      96 %  |
| 2     | Media Encryption and Blob Service   | In progress   |      98 %  |
| 3     | Personal Archive and Offload        | In progress   |      99 %  |
| 4     | Backup and Restore                  | In progress   |      90 %  |
| 5     | Search (Fuzzy + Encrypted Shards)   | In progress   |      98 %  |
| 6     | Media and Semantic Search           | In progress   |      95 %  |
| 7     | Desktop + Optimization              | In progress   |      85 %  |
| 8     | Multi-Scope, Multi-Tenant Search    | In progress   |      98 %  |

---

## Phase 0: Protocol and Test Vectors

**Status**: Complete.

**Goal**: Lock the shared binary formats, crypto specs, and
cross-platform / cross-language test vectors before writing
application code.

Checklist:

- [x] Shared binary formats spec (CBOR wire payloads).
- [x] Crypto container spec (AEAD, AAD format, chunk layout) for both
      KChat-internal AAD and ZK Object Fabric Pattern C.
- [x] Manifest spec (backup + archive; chained
      `previous_manifest_hash`; hybrid Ed25519 + ML-DSA-65 signature).
- [x] Media descriptor spec (`asset_id`, `K_asset`, sizes, Merkle
      root, `blob_id`, chunk count).
- [x] Search index shard spec (text, fuzzy, vector, media frames;
      encryption envelope; coarse-bucket addressing).
- [x] Multilingual tokenization spec (ICU, script-specific rules,
      fallback behavior, fuzzy-index granularity per script).
- [x] iOS / Android / desktop / Rust cross-platform crypto test
      vectors (byte-identical ciphertext, tag, Merkle root).
- [x] ZK Object Fabric interop test vectors bit-identical to the Go
      SDK across `DeriveConvergentDEK`, `deriveConvergentNonce`,
      chunk framing, and end-to-end `EncryptObject`.
- [x] Rust workspace scaffold and CI pipeline.

**Decision gate**: Crypto test vectors pass across Rust, Swift,
Kotlin, and Go (zk-object-fabric SDK).

---

## Phase 1: Local Store + Text Search + MLS Integration

**Status**: In progress (~96 %).

**Goal**: Encrypted local storage, multilingual text search, and
MLS-plaintext ingest. The library can be embedded in the iOS and
Android apps and round-trip text messages.

Checklist:

- [x] SQLCipher integration; `K_local_db` wrapped by Keychain /
      Keystore / DPAPI.
- [x] Local schema (`conversation`, `message_skeleton`,
      `message_body`, `media_asset`, `backup_event_journal`,
      `archive_segment_map`, `restore_state`).
- [x] Message processor: ingest MLS-decrypted application messages,
      outbox, idempotency, dedup on client message ID.
- [x] FTS5 with ICU tokenizer; `unicode61 remove_diacritics 2`
      fallback.
- [x] Structured search (sender, date range, conversation,
      content kind).
- [x] Body state machine (`local_plain_available`,
      `local_encrypted_available`, `delivery_store_only`,
      `deleted_for_me`, `deleted_for_everyone`, `unavailable`,
      `remote_archive_only`).
- [x] UniFFI bridge: generated Swift package.
- [x] JNI bridge: idiomatic Kotlin façade.
- [x] Core public API surface: `initialize`, `register_device`,
      `send_text`, `ingest_remote_messages`, `search`.
- [x] Unit + integration tests covering multilingual corpora
      (Latin, Cyrillic, CJK, Arabic, Hebrew, Thai, Devanagari, mixed).
- [x] Performance validation: insert text < 20 ms p95; search recent
      < 150 ms p95.

**Decision gate**: Text messages can be stored, searched, and
round-tripped through MLS ingest on both iOS and Android within
the performance budget.

---

## Phase 2: Media Encryption and Blob Service

**Status**: In progress (~98 %).

**Goal**: Chunked encrypted media upload / download, thumbnailing,
and a local media cache that obeys the offload contract.

Checklist:

- [x] Media processor: thumbnail generation, chunk encryption with a
      random `K_asset` per asset.
- [x] Chunked encrypted blob upload / download in the transport
      client.
- [ ] Media descriptor distribution through MLS.
- [x] Local media cache with LRU eviction; encrypted on disk.
- [x] Resume upload (re-upload only missing chunks; idempotent
      commit on retry).
- [x] Chunk integrity verification: per-chunk SHA-256, whole-object
      BLAKE3 Merkle root, AEAD tag.
- [x] Media state machine (`thumbnail_only`, `original_local`,
      `remote_original`, `download_in_progress`, `evicted`,
      `deleted`).
- [x] Size-class padding for metadata privacy.
- [x] Per-chunk AEAD AAD construction (`KCHAT_BLOB_CHUNK_V1`).
- [x] Multilingual filename / caption handling (UTF-8 canonical).
- [x] `MediaBlobSink` trait + iCloud / Google Drive / ZKOF sink
      wrappers for tiered media storage (PROPOSAL §5.7).
- [x] Production HTTP transport client (feature-gated
      `http-transport`) with retry, timeout, and auth-header
      coverage.

**Decision gate**: An encrypted image / video / document can
round-trip through upload, store, evict, redownload, decrypt, and
verify across iOS, Android, and desktop.

---

## Phase 3: Personal Archive and Offload

**Status**: In progress (~99 %).

**Goal**: Encrypted archive of older messages and media on the
KChat backend (or ZK Object Fabric), plus device-side offload and
on-demand rehydration.

Checklist:

- [x] Archive event journal and `archive_segment_map`.
- [x] Archive segment builder (CBOR + zstd + XChaCha20-Poly1305 seal
      under `K_archive_epoch`).
- [x] Archive manifest chain (genesis → chained; hybrid signed).
- [x] Epoch key rotation (`K_archive_epoch` derived per epoch from
      `K_archive_root`); historical epoch keys recoverable from the
      manifest chain.
- [x] Offload eviction algorithm based on storage budget,
      recency, pinned status, and content kind.
- [x] Rehydration: fetch encrypted segments, AEAD-open under the
      correct epoch key, restore `message_body` on tap or scroll.
- [x] Batch-by-bucket prefetch on the rehydration path.
- [x] Optional dummy-request padding for high privacy mode.
- [x] Archive backend routing: KChat backend (PostgreSQL) or ZK
      Object Fabric (S3 API).
- [x] Multilingual archive tests covering 8+ scripts.
- [x] iCloud / Google Drive bridge wrappers exposed through the
      iOS and Android bridges.

**Decision gate**: A device can offload a year of messages,
rehydrate on scroll-back, and verify every fetched segment without
ever decrypting on the server.

---

## Phase 4: Backup and Restore

**Status**: In progress (~90 %).

**Goal**: Incremental backup to platform sinks and skeleton-first
restore. A wiped or new device can return to a working state.

Checklist:

- [x] Backup event journal and segment builder.
- [x] Backup manifest chain (hybrid Ed25519 + ML-DSA-65 signed).
- [x] Incremental backup orchestration walking the event journal.
- [x] Backup compaction (daily → weekly → monthly bucketing with
      tombstone application).
- [x] `BackupSink` trait with `ZkofBackupSink` (Pattern C convergent
      encryption, bit-identical to the Go SDK).
- [x] Skeleton-first restore: conversation list → timeline
      skeletons → search shards → recent bodies → lazy media.
- [x] Restore state machine (`restore_state` row with `load`,
      `save`, `transition`, `reset`).
- [x] Manifest chain verifier walking genesis → latest with
      structured failure modes.
- [x] Recovery-key flow (`RecoveryKey`, `generate_recovery_key`,
      `recover_from_key`).
- [x] Device-to-device transfer (`prepare_device_transfer`,
      `accept_device_transfer`).
- [ ] iOS iCloud backup sink.
- [ ] Android Auto Backup / Storage Access Framework strategy.
- [ ] Passphrase recovery flow.

**Decision gate**: A fresh device can complete a skeleton-first
restore and reach a working steady state from each supported
backup sink.

---

## Phase 5: Search — Fuzzy + Encrypted Shards

**Status**: In progress (~98 %).

**Goal**: Script-aware fuzzy search and cold-shard search across
encrypted index shards stored on the backend. Hit the per-platform
search latency targets.

Checklist:

- [x] Script-aware fuzzy index (trigrams for alphabetic scripts;
      bigrams for CJK; ISO-15924 tagging).
- [x] Fuzzy lookup with script-aware Levenshtein.
- [x] Encrypted search index shard build (text + fuzzy variants).
- [x] Cold-shard fetch + decrypt + search via `ColdShardSource`.
- [x] Ranking formula merging FTS, fuzzy, and structured signals
      (PROPOSAL §7.5).
- [x] Cold-shard restore flow.
- [x] p95 latency gate across multilingual / large-bucket /
      multi-shard scenarios.
- [x] Per-platform `DeviceMatrixConfig` latency budgets.

**Decision gate**: Search latency targets met on iOS, Android,
macOS, and Windows for warm and cold queries.

---

## Phase 6: Media and Semantic Search

**Status**: In progress (~95 %).

**Goal**: On-device ML inference for text, image, video, audio,
and document search. Cross-modal retrieval against the local
encrypted index.

Checklist:

- [x] Text embedder seam (`TextEmbedder` trait) with XLM-R via ONNX.
- [x] Image embedder seam (`ImageEmbedder` trait) with MobileCLIP-S2.
- [x] OCR bridge (`OcrBridge` trait) — platform Vision / ML Kit on
      iOS / Android; multilingual fallback on desktop.
- [x] Audio transcription seam (`WhisperTranscriber` trait); Apple
      MLX backend on Apple Silicon, ONNX fallback elsewhere.
- [x] Document extractor seam for PDF / Word.
- [x] Video keyframe sampler seam.
- [x] On-device reranker producing raw `semantic_score`.
- [x] `ResourceGate` policy with battery, thermal, and connectivity
      gating.
- [x] `ModelManager` for download / versioning / quantization.
- [x] INT4 quantization selection on tight-storage devices; INT8 on
      desktop.
- [x] INT4 encode / decode codec for on-disk vector storage.
- [x] Criterion benchmark scaffold for ML inference latency.
- [x] Desktop ONNX EP wiring (`create_xlmr_session_with_ep`,
      `create_mobileclip_session_with_ep`, `EpFallbackChain`,
      `DesktopMlEpSelector`).
- [ ] Final mobile ML latency budget validation against
      `DeviceMatrixConfig`.

**Decision gate**: Semantic search produces results comparable to
keyword search latency on flagship devices and degrades cleanly
when resources are constrained.

---

## Phase 7: Desktop + Optimization

**Status**: In progress (~85 %).

**Goal**: macOS and Windows feature parity, performance dashboards,
failure scenarios, and production-scale stress coverage.

Checklist:

- [x] Failure suite (14 of 14 scenarios passing).
- [x] Offline detector.
- [x] Performance p95 dashboard (`PerfSummary`, `PerfBudget`).
- [x] Hot-path coverage (`hydrate_message`, `run_incremental_backup`,
      `compact_archive`, `restore_from_backup`).
- [x] Spotlight (macOS) and Windows Search Rust API surface.
- [x] Execution provider benchmark with capture, cache, and
      auto-selection.
- [x] Media migration auto-scheduled after eviction.
- [x] Dedup analytics wiring (`ZkofDedupAnalytics` with backup +
      media sinks recording `DedupEvent`s).
- [x] Large-scale stress tests (6 scenarios).
- [x] Edge-case scenarios (6 scenarios).
- [x] Media-sink stress tests with real iCloud / Google Drive
      bridges.
- [ ] Final device-matrix sign-off across iOS, Android, macOS, and
      Windows.

**Decision gate**: Production-ready performance on the target
device matrix; the full failure suite passes on every platform.

---

## Phase 8: Multi-Scope, Multi-Tenant Search

**Status**: In progress (~98 %).

**Goal**: Conversation hierarchy (channels, communities, domains),
B2B tenant isolation, and search performance optimizations (bloom
filters, shard cache, parallel fetch, progressive results) for
global, community, domain, and tenant-scoped search.

Checklist:

- [x] Schema: conversation hierarchy columns and indexes.
- [x] Schema: `archive_segment_map.tenant_id` and index.
- [x] `SearchTarget` enum on `SearchQuery`.
- [x] Scope resolver mapping `SearchTarget` to a conversation set.
- [x] Bucket-level date pruning in the cold fan-out.
- [x] Encrypted bloom-filter shard type (`IndexType::Bloom`).
- [x] Bloom-filter pre-check before fetching full shards.
- [x] On-device decrypted LRU shard cache (default 50 MB).
- [x] Parallel bucket fetch with bounded concurrency.
- [x] Progressive `SearchEvent` streaming results.
- [x] Background shard warming at P5 idle.
- [x] Per-tenant key isolation (`K_b2b_tenant_root`,
      `K_b2b_archive_epoch`, `K_b2b_text_index_shard`).
- [x] `TenantSearchPolicy` enforcement.
- [x] Scope-proportional cover-traffic padding.
- [x] `K_bloom_index_shard` derivation under `K_search_root`.
- [x] Android / iOS bridge surface for `SearchTarget` and progressive
      search events.
- [x] Phase 8 latency benchmarks and integration tests.

**Decision gate**: Multi-scope search hits the p95 latency budget
across community / domain / tenant / global scopes on the target
device matrix.

---

## Notable changes

- Hybrid manifest signing (Ed25519 + ML-DSA-65) adopted across
  backup and archive manifests per NIST SP 800-227.
- Epoch-rotated archive keys (`K_archive_epoch`) added on top of
  the Phase 0 key hierarchy to limit blast radius and enable
  forward secrecy.
- Tiered media storage (`MediaBlobSink` trait) added so media
  originals can route to user cloud storage (iCloud / Google
  Drive / ZKOF) while thumbnails and archive segments stay on the
  KChat backend.
- Phase 8 multi-scope search foundation: conversation hierarchy,
  `SearchTarget`, B2B tenant key isolation, bloom-filter shards,
  on-device shard cache, parallel bucket fetch, and progressive
  `SearchEvent` streaming.
