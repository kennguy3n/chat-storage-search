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

- [ ] Shared binary formats spec (CBOR for wire payloads; internal
      Rust structs ↔ CBOR mapping).
- [ ] Crypto container spec (AEAD construction, AAD format, chunk
      layout) covering both KChat-internal AAD (PROPOSAL §8.3) and
      ZK Object Fabric Pattern C (empty AAD; PROPOSAL §8.4).
- [ ] Manifest spec (backup manifest, archive manifest;
      `previous_manifest_hash` chain; Ed25519 signature).
- [ ] Media descriptor spec (`asset_id`, `K_asset`, mime type,
      sizes, Merkle root, blob ID, chunk count).
- [ ] Search index shard spec (text, fuzzy, vector, media index
      shard frames; encryption envelope; coarse-bucket addressing).
- [ ] Multilingual tokenization spec (ICU configuration, script-
      specific rules, fallback behavior, fuzzy-index granularity
      per script).
- [ ] iOS / Android / desktop / Rust cross-platform crypto test
      vectors: same plaintext + keys + nonce ⇒ identical ciphertext,
      tag, and Merkle root in every binding.
- [ ] **ZK Object Fabric interop test vectors**: Rust output for
      Pattern C must match Go output from
      `kennguy3n/zk-object-fabric/encryption/client_sdk/` byte-for-byte
      across `DeriveConvergentDEK`, `deriveConvergentNonce`,
      chunk framing, and end-to-end `EncryptObject`.
- [ ] Rust workspace scaffold (`crates/core`, `crates/ios-bridge`,
      `crates/android-bridge`, `crates/desktop`).
- [ ] CI pipeline: Rust build + test, iOS build (UniFFI codegen
      sanity), Android build (JNI codegen sanity), desktop build,
      cross-language test-vector run.

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
- [ ] UniFFI bridge: generated Swift package consumable from
      KChat.app and any iOS extensions sharing the local store.
- [ ] JNI bridge: idiomatic Kotlin façade over the generated JNI
      bindings.
- [ ] Core public API surface: `initialize`, `register_device`,
      `send_text`, `ingest_remote_messages`, `search`.
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

**Decision gate**: Media can be encrypted, chunked, uploaded,
downloaded, range-fetched, verified, and displayed (thumbnail +
original) on iOS, Android, macOS, and Windows. Resumed uploads
never duplicate completed chunks.

---

## Phase 3: Personal Archive and Offload

**Goal**: Interactive cold storage with scroll-back rehydration and
storage-pressure management.

Checklist:

- [ ] Archive event journal (every durable mutation writes an
      archive event).
- [ ] Archive segment builder: per-conversation, per-time-bucket
      segments for `message_delta`, `timeline_skeleton`,
      `media_key_delta`, `search_text_index`,
      `search_vector_index`, `media_index`, `checkpoint`.
- [ ] Archive manifest chain (generation N+1 referencing N via
      `previous_manifest_hash`; Ed25519 signature).
- [ ] Encrypted segment upload to the KChat backend's blob service.
- [ ] Whole-object Merkle-root verification after upload commit.
- [ ] Archive state machine (`not_archived` → `archive_pending` →
      `archive_uploaded` → `archive_verified` → `archive_compacted`).
- [ ] Storage budget enforcement (`enforceStorageBudget`).
- [ ] Eviction scoring formula (PROPOSAL §5.4).
- [ ] Eviction priority order: video → documents → images → voice →
      thumbnails (under severe pressure) → cold text bodies (under
      extreme pressure).
- [ ] Pinned-chat / pinned-message exclusion.
- [ ] Timeline-skeleton rehydration on scroll-back (no scroll-jump
      on update).
- [ ] Lazy media rehydration on tap.
- [ ] Prefetch window management (viewport ± 100–150 messages).
- [ ] Hydration priority queue (P0 → P5).

**Decision gate**: Messages and media can be offloaded to the
archive, rehydrated transparently on scroll-back and search-result
tap, and the storage budget is enforced. The timeline renders
skeletons immediately with lazy body / media fill, and indexes
remain resident across all eviction strata.

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
- [ ] Multilingual text embedding model (`multilingual-e5-small`,
      INT8 ONNX) wired through the search pipeline. English-only
      MiniLM-L6 is **rejected**.
- [ ] HNSW vector index for semantic text search.
- [ ] CLIP integration for image search (multilingual text→image).
- [ ] Video keyframe sampling and CLIP embeddings.
- [ ] Whisper multilingual integration for voice-message transcription
      (`whisper-small` default; `whisper-tiny` on low-end Android).
- [ ] Platform OCR bridge: Vision (`VNRecognizeTextRequest`) on
      iOS / macOS; ML Kit Text Recognition v2 on Android;
      `Windows.Media.Ocr` / Tesseract on Windows.
- [ ] Document text extraction (PDF, DOCX) with multilingual
      handling and page-level indexing.
- [ ] Resource-gated background processing: battery level, thermal
      state, charging, network type.
- [ ] Model manager: lazy download on first semantic-search use,
      versioning, INT8 quantization, integrity-checked artifacts.
- [ ] Encrypted vector / media index shard archive.
- [ ] On-device reranking with semantic similarity scores.
- [ ] Desktop support: macOS (Core ML), Windows (CPU-only ONNX
      Runtime).

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
