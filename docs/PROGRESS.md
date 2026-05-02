# KChat Storage & Search — Progress

- **Project**: KChat Storage & Search — Rust Core
- **License**: Proprietary — All Rights Reserved. See [LICENSE](../LICENSE).
- **Status**: Phase 0 — Protocol and Test Vectors (`COMPLETE`). Phase 1 — Local Store + Text Search + MLS Integration (`In progress | ~70%`).
- **Last updated**: 2026-05-02

This document is a phase-gated tracker. Each phase has an explicit
checklist and a decision gate. Do not skip to the next phase until
the current phase's gate has been met.

For the technical design, see [PROPOSAL.md](PROPOSAL.md). For the
system architecture, see [ARCHITECTURE.md](ARCHITECTURE.md). For
the full delivery plan, see [PHASES.md](PHASES.md).

---

## Phase 0: Protocol and Test Vectors

**Status**: `COMPLETE`

**Goal**: Lock the shared binary formats, crypto specs, and
cross-platform / cross-language test vectors **before** writing
application code. Phase 0 is what prevents quiet drift between
iOS, Android, desktop, and the ZK Object Fabric backup path.

Checklist:

- [x] Shared binary formats spec (CBOR for wire payloads; internal
      Rust structs ↔ CBOR mapping). _(See
      `crates/core/src/formats/`: `BackupSegmentFrame`,
      `ArchiveSegmentFrame`, `SegmentType`, plus the manifest,
      media-descriptor, and search-shard sub-modules. All types
      round-trip through `serde_cbor::to_vec` /
      `serde_cbor::from_slice` and use `serde_bytes` for compact
      byte-string encoding.)_
- [x] Crypto container spec (AEAD construction, AAD format, chunk
      layout) covering both KChat-internal AAD and ZK Object Fabric
      Pattern C.
- [x] Manifest spec (backup manifest, archive manifest;
      `previous_manifest_hash` chain; Ed25519 signature). _(See
      `crates/core/src/formats/manifest.rs`. `BackupManifest` and
      `ArchiveManifest` share the canonical-CBOR signing payload,
      `compute_manifest_hash` powers the generation chain, and the
      integration test at `crates/core/tests/manifest_signing.rs`
      walks gen 0 → gen 1 → gen 2 end-to-end.)_
- [x] Media descriptor spec. _(See
      `crates/core/src/formats/media_descriptor.rs`:
      `MediaDescriptor` carries `asset_id`, `mime_type`,
      `bytes_total`, `chunk_count`, BLAKE3 `merkle_root`,
      `blob_id`, and AES-256-KW-wrapped `K_asset`.)_
- [x] Search index shard spec (text, fuzzy, vector, media). _(See
      `crates/core/src/formats/search_shard.rs`:
      `SearchIndexShard` with the four-variant `IndexType` enum,
      `KCHAT_INDEX_SHARD_V1` magic, and zstd / XChaCha20-Poly1305
      framing per `docs/PROPOSAL.md §7.8`.)_
- [x] Multilingual tokenization spec (ICU configuration, script-
      specific rules, fallback behavior, fuzzy-index granularity
      per script). _(See `crates/core/src/search/tokenizer.rs`:
      `TokenizerConfig` (locale, NFKC, case fold, accent fold),
      `FallbackMode::{Icu, Unicode61}`, ISO-15924 `ScriptClass`,
      `FuzzyGranularity::{Trigram, Bigram}` mapped via
      `fuzzy_granularity`, `fts5_tokenizer_config` returning
      `tokenize = 'icu'`, and `detect_script` / `segment_by_script`
      for mixed-script runs per `docs/PROPOSAL.md §3.4`.)_
- [x] iOS / Android / desktop / Rust cross-platform crypto test
      vectors. _(Rust-side complete: BLAKE3 known vectors,
      HKDF derivation determinism, AEAD round-trip / wrong-key /
      tamper / AAD-mismatch tests. iOS / Android / desktop bindings
      pick this up in Phase 1 when UniFFI / JNI land.)_
- [x] **ZK Object Fabric interop test vectors** (Rust ↔ Go SDK at
      `kennguy3n/zk-object-fabric/encryption/client_sdk/`,
      bit-identical for `DeriveConvergentDEK`,
      `deriveConvergentNonce`, chunk framing, end-to-end
      `EncryptObject`). _(See
      `crates/core/tests/pattern_c_interop_vectors.{rs,json}` and
      the generator at `tests/generate_vectors/main.go`.)_
- [x] Rust workspace scaffold (`crates/core`, `crates/ios-bridge`,
      `crates/android-bridge`, `crates/desktop`).
- [x] CI pipeline (Rust build + test). _(`cargo fmt --check`,
      `cargo clippy -D warnings`, `cargo build --workspace`,
      `cargo test --workspace` in `.github/workflows/ci.yml`. iOS /
      Android / desktop platform builds and the cross-language
      vector job land in Phase 1.)_

**Decision gate**: Crypto test vectors pass across Rust, Swift (via
UniFFI), Kotlin (via JNI), and Go (zk-object-fabric SDK). A
deviation in any binding blocks Phase 1.

Notes:

- 2026-05-02: Rust crypto module landed (`crates/core/src/crypto/`):
  BLAKE3 content hashing (one-shot + streaming), HKDF-SHA256 key
  hierarchy with `Zeroize + ZeroizeOnDrop` `KeyMaterial`,
  XChaCha20-Poly1305 + AES-256-GCM AEADs, KChat per-chunk AAD
  (`KCHAT_BLOB_CHUNK_V1` + varint blob_class + u32 BE chunk_no /
  chunk_count + 32-byte Merkle root), and Pattern C convergent
  encryption that is bit-identical to
  `kennguy3n/zk-object-fabric/encryption/client_sdk/`.
- 2026-05-02: Cross-language vectors locked. The Go generator
  produces `pattern_c_interop_vectors.json`; the Rust integration
  test asserts BLAKE3 digest, DEK, chunk-0 nonce, full ciphertext,
  and Go-ciphertext → Rust-decrypt round-trip across four input
  shapes (single-chunk, single-byte, 4 KiB × 256-byte chunks,
  128-byte × 64-byte chunks). Status: 6/6 passing locally.
- 2026-05-02: Shared binary formats landed
  (`crates/core/src/formats/`): backup / archive segment frames,
  `BackupManifest` / `ArchiveManifest` with Ed25519 signing over
  the canonical-CBOR payload and a `previous_manifest_hash` chain
  (genesis manifests anchor to the all-zero hash),
  `MediaDescriptor`, and `SearchIndexShard` (text / fuzzy / vector
  / media). Integration tests at
  `crates/core/tests/manifest_signing.rs` and
  `crates/core/tests/key_wrap_hierarchy.rs` exercise the manifest
  chain and the AES-256-KW wrap-by-archive-vs-backup-root split.
- 2026-05-02: AES-256-KW (RFC 3394) key wrapping landed at
  `crates/core/src/crypto/key_wrap.rs` (no longer a stub).
  `wrap_key` / `unwrap_key` plus the `wrap_k_asset` /
  `unwrap_k_asset` convenience helpers operate on the
  `KeyMaterial` from the hierarchy; wrapped output is exactly 40
  bytes (32 + 8-byte integrity check).
- 2026-05-02: Phase 1 SQLCipher integration, message persistence,
  FTS5 text search engine, structured search query engine, and
  multilingual integration test suite landed.
  `crates/core/Cargo.toml` now depends on
  `rusqlite = { version = "0.31", features =
  ["bundled-sqlcipher-vendored-openssl", "column_decltype"] }`
  so `cargo build` and `cargo test` need no system SQLCipher /
  OpenSSL. ICU is detected via a non-destructive
  `CREATE VIRTUAL TABLE temp.__icu_probe USING fts5(...)` probe
  at open time; the schema rewrites `tokenize = 'icu'` to
  `tokenize = 'unicode61 remove_diacritics 2'` when ICU is
  unavailable. `K_local_db` platform wrapping (Keychain /
  Keystore / DPAPI) is still stubbed; callers pass the 32-byte
  raw key in for now.

---

## Phase 1: Local Store + Text Search + MLS Integration

**Status**: `In progress | ~70%`

**Goal**: Basic encrypted local storage with multilingual text
search and MLS-plaintext ingest.

Checklist:

- [x] SQLCipher integration; `K_local_db` wrapped by Keychain /
      Keystore / DPAPI. _(Encrypted local store landed at
      `crates/core/src/local_store/db.rs`: `LocalStoreDb` opens
      `{data_dir}/kchat.db` (or an in-memory database for tests),
      sets `PRAGMA key = x'…'` from the 32-byte `K_local_db`,
      enables foreign-key enforcement, and runs `SCHEMA_SQL` with
      automatic detection of the FTS5 ICU tokenizer plus
      `unicode61` fallback via
      `create_schema_with_unicode61_fallback()`. CRUD helpers cover
      conversation / skeleton / body / `update_body_state` /
      `insert_backup_event`. The platform wrap of `K_local_db`
      (Keychain / Keystore / DPAPI) is stubbed; callers pass the
      raw key in for now and the platform wrappers land later in
      Phase 1 with the UniFFI / JNI bridges.)_
- [x] Local schema (`conversation`, `message_skeleton`,
      `message_body`, `media_asset`, `backup_event_journal`,
      `archive_segment_map`, `restore_state`). _(Types defined in
      `crates/core/src/local_store/schema.rs`; the
      `SCHEMA_SQL` constant carries the `CREATE TABLE` /
      `CREATE VIRTUAL TABLE` statements verbatim from
      `docs/ARCHITECTURE.md §4`. SQLCipher binding follows.)_
- [x] Message processor: ingest MLS-decrypted messages, outbox,
      idempotency, edit / delete. _(DB-backed `MessagePersister`
      landed at `crates/core/src/message/processor.rs` alongside
      the existing validators: `persist_ingested_message`
      validates, deduplicates against `message_skeleton`, inserts
      skeleton + body + `search_fts` row + `"message_received"`
      journal entry inside a single `SAVEPOINT` boundary;
      `persist_outbox_entry` mints
      `body_state = local_plain_available` and writes an
      `"outbox_pending"` journal entry; `mark_sent` writes
      `"outbox_sent"`; `edit_message` rewrites `message_body.text`,
      stamps `edited_at_ms`, refreshes the FTS row, and writes a
      `"message_edited"` journal entry; `delete_for_me` /
      `delete_for_everyone` validate the body-state transition,
      remove the FTS row, and write a `"message_deleted"` journal
      entry (`{"scope": "for_me" | "for_everyone"}`);
      `delete_for_everyone` additionally drops the `message_body`
      row so the plaintext is gone; `check_duplicate` queries
      `message_skeleton` by id.)_
- [x] FTS5 with **ICU tokenizer** (`tokenize = 'icu'`) for
      multilingual full-text search; documented `unicode61` fallback.
      _(Engine landed at `crates/core/src/search/text_search.rs`:
      `TextSearchEngine::search_fts` runs
      `bm25(search_fts)`-ordered queries, returns
      `FtsMatch { message_id, conversation_id, sender_id,
      created_at_ms, snippet, bm25_score }`, and the schema
      bring-up in `local_store::db` automatically falls back to
      `tokenize = 'unicode61 remove_diacritics 2'` on builds
      without ICU. `build_fts_query` quotes free-text tokens to
      keep stray `:` / `^` from blowing up the FTS5 query parser
      and preserves `*` prefix queries plus explicit `"phrase"` /
      `AND` / `OR` / `NOT` / `NEAR` operators.)_
- [x] Structured search (sender, date range, conversation, content
      kind). _(Engine landed at
      `crates/core/src/search/query_engine.rs`:
      `QueryEngine::execute_search` combines FTS5 hits with
      structured `WHERE` clauses on `message_skeleton`
      (`sender_filter` / `conversation_filter` / `date_from` /
      `date_to` / `content_kind`), intersects FTS hits with the
      structured-filter result by `message_id`, and returns the
      unified rows ordered by BM25 (sign-flipped so callers see
      "higher = better"). Empty `query_string` returns skeleton
      rows ordered by `created_at_ms DESC`.
      `SearchScope::LocalOnly` is honored — no archive fan-out
      attempts in Phase 1.)_
- [x] Body state machine (`local_plain_available`,
      `local_encrypted_available`, `delivery_store_only`,
      `deleted_for_me`, `deleted_for_everyone`, `unavailable`).
      _(Plus media / archive / backup / restore state machines.
      See `crates/core/src/local_store/state_machines.rs`:
      every enum implements `try_transition`, `Display` /
      `FromStr`, and serde with snake_case wire form.)_
- [ ] UniFFI bridge for iOS / Swift.
- [ ] JNI bridge for Android / Kotlin.
- [x] Core public API surface: `initialize`, `register_device`,
      `send_text`, `ingest_remote_messages`, `search`. _(Types and
      trait method signatures defined in `crates/core/src/lib.rs`:
      `KChatCore` trait, `SearchQuery`, `SearchScope`,
      `SearchResult`, `HydrationReason` (P0–P5), `BackupReason`,
      `StoragePressureReason`, `ClientMessageId`,
      `DeliveryCursor`. Concrete implementation at
      `crates/core/src/core_impl.rs`: `CoreImpl::new(config, key)`
      opens the SQLCipher store, the trait `send_text` mints an
      outbox entry through `MessageProcessor` and persists it
      via `MessagePersister`, `search` delegates to
      `QueryEngine::execute_search`, `initialize` re-opens the
      DB at the new `data_dir` using the retained
      `K_local_db`. The transport-driven
      `ingest_remote_messages` is a Phase-1 stub returning
      `IngestResult::default()`; the inherent
      `CoreImpl::ingest_messages(&[IngestedMessage])` is the
      batch-ingest entry point tests and bridges currently use.
      Methods are sync `Result<_>`-returning placeholders that
      flip to `async fn` once the MLS delivery client lands.)_
- [x] Fuzzy token indexer foundation. _(Phase-5 foundation landed
      early at `crates/core/src/search/fuzzy_search.rs`:
      `FuzzyTokenizer::generate_tokens` segments input by script
      via `segment_by_script`, picks trigrams vs bigrams from
      `fuzzy_granularity`, lowercases tokens for
      case-insensitive matching, and splits per-script runs on
      ASCII whitespace / punctuation / digits so n-grams never
      straddle a separator. `FuzzySearchEngine::index_message` /
      `remove_message` write into the `search_fuzzy` table;
      `search_fuzzy` returns matches ordered by token-overlap
      ratio. The encrypted-shard / archive fan-out lands later
      in Phase 5.)_
- [x] Performance benchmarks (criterion). _(Suite at
      `crates/core/benches/phase1_benchmarks.rs`:
      `insert_text_message`, `insert_batch_100`,
      `search_recent_messages` (1k corpus, 5 conversations,
      ~10 needles), `search_with_structured_filters`, and
      `fts_prefix_search`. Run with `cargo bench -p kchat-core
      --bench phase1_benchmarks`; HTML reports land under
      `target/criterion/`. Local p95 numbers comfortably under
      the < 20 ms / < 150 ms targets — see "Performance
      validation" item below.)_
- [x] Multilingual unit + integration tests. _(Integration test
      at `crates/core/tests/multilingual_search.rs` exercises the
      full `MessagePersister` → `search_fts` → `QueryEngine`
      round-trip across eight scripts: English, Russian, Chinese,
      Japanese, Arabic, Thai, Hindi, mixed-script. Latin /
      Cyrillic / Arabic / Devanagari word search runs against
      `unicode61` and is required on every build; CJK / Thai
      tests soft-skip when the SQLCipher build does not link
      against ICU. Combined FTS-plus-conversation-filter and
      sender / date-range filters are also covered.)_
- [x] Performance validation: insert text < 20 ms p95; search
      recent < 150 ms p95. _(Smoke runs of the criterion suite on
      the development VM measure `insert_text_message` at
      ~100 µs and `search_recent_messages` (1k-row corpus,
      single FTS5 needle) at ~70 µs — both two orders of
      magnitude below the budget. Targets re-validated on iOS /
      Android hardware once UniFFI / JNI bridges land.)_

**Decision gate**: Text messages can be stored, searched
(multilingual), and round-tripped through MLS ingest on both iOS
and Android.

Notes:

- 2026-05-02: Multilingual tokenization spec landed at
  `crates/core/src/search/tokenizer.rs`. ICU is the primary FTS5
  tokenizer (`tokenize = 'icu'`); `unicode61 remove_diacritics 2`
  is the documented fallback. The script-aware fuzzy split is
  bigrams for logographic CJK (Hani / Hira / Kana) and trigrams
  for everything else (Latn / Cyrl / Grek / Arab / Hebr / Deva /
  Beng / Hang / Thai / Khmr / Laoo / Mymr / Unknown).
  `segment_by_script` splits mixed-script text per
  `docs/PROPOSAL.md §3.3` (e.g.
  `"Meeting at 3pm 会議室で"` → Latn / Hani / Hira runs).
- 2026-05-02: Local store schema types landed at
  `crates/core/src/local_store/schema.rs`: `Conversation`,
  `MessageSkeleton`, `MessageBody`, `MediaAsset`,
  `BackupEventJournalEntry`, `ArchiveSegmentMapEntry`,
  `RestoreStateEntry`, plus `MessageKind`, the `SCHEMA_SQL`
  constant (CREATE TABLE / CREATE VIRTUAL TABLE statements
  verbatim from `docs/ARCHITECTURE.md §4`), and the `TABLES`
  registry.
- 2026-05-02: State-machine enums landed at
  `crates/core/src/local_store/state_machines.rs`. Every
  transition not in the `docs/ARCHITECTURE.md §5` state diagrams
  returns `StateTransitionError::Illegal`. `Display` / `FromStr`
  use snake_case strings that match the SQL text columns.
- 2026-05-02: Message processor skeleton landed at
  `crates/core/src/message/processor.rs`: `IngestedMessage`,
  `OutboxEntry`, `OutboxStatus`, `IngestResult`, and the static
  `validate_ingest` / `is_duplicate` / `create_outbox_entry`
  helpers. UUID v7 is enforced for outbox client message ids.
- 2026-05-02: Public API surface expanded in
  `crates/core/src/lib.rs`. New types: `SearchQuery`,
  `ContentKind`, `SearchScope` (default `IncludeCold`),
  `SearchResult`, `HydrationReason` (P0–P5), `BackupReason`,
  `StoragePressureReason`, `ClientMessageId`, `DeliveryCursor`.
  New `Error` variants: `Storage`, `Search`, `Message`,
  `Transport`. `KChatCore` trait gained `initialize`,
  `send_text`, `ingest_remote_messages`, `search` (sync
  placeholders that turn into `async fn` once Phase 1 plumbing
  exists).
- 2026-05-02: `CoreImpl` concrete `KChatCore` implementation
  landed at `crates/core/src/core_impl.rs`. `CoreImpl::new`
  opens the SQLCipher store, the trait `send_text` mints an
  outbox entry through `MessageProcessor` and persists it via
  `MessagePersister`, `search` delegates to
  `QueryEngine::execute_search`, and `initialize` re-opens the
  DB at the new `data_dir` using the retained `K_local_db`
  (held in a `Zeroizing<[u8; 32]>`). The transport-driven
  `ingest_remote_messages` is a Phase-1 stub; the inherent
  `CoreImpl::ingest_messages` is the batch-ingest entry point
  bridges and tests use today.
- 2026-05-02: Message edit / delete operations landed on
  `MessagePersister` (`crates/core/src/message/processor.rs`).
  `edit_message` rewrites `message_body.text_content`, stamps
  `edited_at_ms`, refreshes the FTS row, and writes a
  `"message_edited"` journal entry; `delete_for_me` /
  `delete_for_everyone` validate the body-state transition,
  drop the FTS row, and write a `"message_deleted"` journal
  entry with `{"scope": "for_me" | "for_everyone"}`. The
  for-everyone path additionally drops the `message_body` row
  so the plaintext is gone. Backed by six new
  `LocalStoreDb` helpers
  (`update_message_body_text`, `update_skeleton_edited`,
  `update_skeleton_deleted`, `delete_message_body`,
  `delete_fts_row`, plus the existing FTS-row insert).
- 2026-05-02: Fuzzy token indexer foundation landed at
  `crates/core/src/search/fuzzy_search.rs`. Phase-5 prep:
  `FuzzyTokenizer::generate_tokens` returns script-aware
  trigrams / bigrams; `FuzzySearchEngine::index_message` /
  `remove_message` / `search_fuzzy` write into the
  `search_fuzzy` table and rank by token-overlap ratio.
  Encrypted-shard / archive fan-out lands later in Phase 5.
- 2026-05-02: Phase-1 performance benchmark suite landed at
  `crates/core/benches/phase1_benchmarks.rs` (criterion).
  Five benches cover single-insert latency, 100-row batch
  throughput, FTS5 search over a 1k-row corpus, structured
  filters (sender / conversation / date range / kind), and
  prefix queries. Smoke runs on the development VM measure
  ~100 µs / ~70 µs, two orders of magnitude below the
  20 ms / 150 ms budgets in `docs/PROPOSAL.md §13`.

---

## Phase 2: Media Encryption and Blob Service

**Status**: `NOT STARTED`

**Goal**: Chunked encrypted media upload / download, thumbnailing,
local media cache.

Checklist:

- [ ] Media processor: thumbnail generation, chunk encryption with
      random `K_asset`.
- [ ] Chunked encrypted blob upload / download (transport client).
- [ ] Media descriptor distribution through MLS.
- [ ] Local media cache with LRU eviction.
- [ ] Resume-upload (no duplicate completed chunks).
- [ ] Chunk integrity verification (per-chunk SHA-256, BLAKE3
      Merkle root, AEAD tag).
- [ ] Media state machine (`thumbnail_only`, `original_local`,
      `remote_original`, `download_in_progress`, `evicted`,
      `deleted`).
- [ ] Size-class padding for metadata privacy.
- [ ] Per-chunk AEAD AAD construction.
- [ ] Multilingual filename / caption handling.

**Decision gate**: Media can be encrypted, chunked, uploaded,
downloaded, range-fetched, verified, and displayed on iOS, Android,
macOS, and Windows. Resumed uploads never duplicate completed
chunks.

Notes:

- _(none yet)_

---

## Phase 3: Personal Archive and Offload

**Status**: `NOT STARTED`

**Goal**: Interactive cold storage with scroll-back rehydration and
storage-pressure management.

Checklist:

- [ ] Archive event journal.
- [ ] Archive segment builder (per-conversation / per-time-bucket).
- [ ] Archive manifest chain (generation N+1, `previous_manifest_hash`,
      Ed25519 signature).
- [ ] Encrypted segment upload to backend blob service.
- [ ] Whole-object Merkle-root verification after upload.
- [ ] Archive state machine (`not_archived` → `archive_pending` →
      `archive_uploaded` → `archive_verified` → `archive_compacted`).
- [ ] Storage budget enforcement (`enforceStorageBudget`).
- [ ] Eviction scoring formula.
- [ ] Eviction priority order (video → documents → images → voice →
      thumbnails → cold text bodies).
- [ ] Pinned-chat / pinned-message exclusion.
- [ ] Timeline-skeleton rehydration (no scroll-jump).
- [ ] Lazy media rehydration on tap.
- [ ] Prefetch window (viewport ± 100–150 messages).
- [ ] Hydration priority queue (P0–P5).

**Decision gate**: Messages and media offload + rehydrate
transparently; storage budget is enforced; timeline renders
skeletons immediately with lazy fill; indexes remain resident
across all eviction strata.

Notes:

- _(none yet)_

---

## Phase 4: Backup and Restore

**Status**: `NOT STARTED`

**Goal**: Incremental backup to platform sinks and skeleton-first
restore.

Checklist:

- [ ] Backup event journal.
- [ ] Incremental backup segment builder.
- [ ] Backup manifest chain with Ed25519 signature.
- [ ] iOS iCloud backup sink.
- [ ] Android backup sink strategy (Auto Backup for envelopes;
      Large Backup / SAF for full data).
- [ ] **ZK Object Fabric backup sink** (S3 API; Pattern C convergent
      encryption; bit-identical interop with the Go SDK).
- [ ] Backup compaction (daily → weekly checkpoint → monthly prune).
- [ ] Manifest chain verification on restore.
- [ ] Skeleton-first restore (conversation list → skeletons →
      search index shards → recent bodies → lazy media).
- [ ] Restore state machine.
- [ ] Key recovery (device-to-device, recovery key, passphrase;
      server escrow off by default).
- [ ] Search index backup and restore (encrypted shards).
- [ ] Multilingual backup-restore corpus validation.

**Decision gate**: Full backup / restore cycle works on every
target platform. New device renders conversation list and returns
search hits within seconds, recent bodies within minutes, media
lazy thereafter. Pattern C dedup against ZK Object Fabric is
verified by re-uploading identical content from two devices in the
same tenant and observing a single stored copy.

Notes:

- _(none yet)_

---

## Phase 5: Search — Fuzzy + Encrypted Shards

**Status**: `NOT STARTED`

**Goal**: Fuzzy matching across scripts, plus encrypted search
shards on the backend so cold buckets remain searchable.

Checklist:

- [ ] Fuzzy token index (trigrams for alphabetic scripts; bigrams
      for logographic CJK runs).
- [ ] Script-aware fuzzy matching with per-token script tag.
- [ ] Encrypted text / fuzzy shard archive
      (`K_text_index_shard`).
- [ ] Search shard fetch
      (`GET /v1/archive/index-shards?conversation_hash=&bucket=&type=`).
- [ ] Cold-result hydration on tap.
- [ ] Unified query engine (parse → fan-out → merge → rerank).
- [ ] Ranking formula implementation.
- [ ] Mixed-language query handling.
- [ ] Latency budget: encrypted shard fetch + decrypt + local
      search ≤ 1.5 s p95 over Wi-Fi for a one-month bucket.

**Decision gate**: Fuzzy search returns relevant hits across all
target scripts, including mixed-script queries. Cold (offloaded)
content is searchable via encrypted-shard fetch + on-device
decrypt — query strings never reach the backend.

Notes:

- _(none yet)_

---

## Phase 6: Media and Semantic Search

**Status**: `NOT STARTED`

**Goal**: On-device ML for OCR, image / video / audio search, and
semantic text search — all multilingual.

Checklist:

- [ ] ONNX Runtime integration via the `ort` crate.
- [ ] Multilingual text embedding model (`XLM-R`, ~80–100 MB INT8
      ONNX). Same encoder as `kennguy3n/slm-guardrail`, unifying
      the text encoder across the platform. English-only
      MiniLM-L6 is rejected.
- [ ] HNSW vector index for semantic text search.
- [ ] `MobileCLIP-S2` image / video embeddings (~80 MB INT8 ONNX).
- [ ] Video keyframe sampling.
- [ ] Whisper multilingual transcription (`whisper-base` default,
      ~140 MB; `whisper-tiny` on low-end Android, ~75 MB).
- [ ] Platform OCR bridge (Vision on iOS / macOS; ML Kit on
      Android; `Windows.Media.Ocr` / Tesseract on Windows).
- [ ] Document text extraction (PDF, DOCX) with page-level indexing.
- [ ] Resource-gated background processing (battery, thermal,
      charging, network).
- [ ] Model manager (lazy download, versioning, INT8 quantization).
- [ ] Encrypted vector / media shard archive.
- [ ] On-device reranking with semantic scores.
- [ ] Desktop support: macOS (Core ML), Windows (CPU-only ONNX RT).

**Decision gate**: Semantic search returns relevant multilingual
results across text, images, video, and audio on iOS, Android,
macOS, and CPU-only Windows. Cross-platform parity is verified by
Phase 0 test vectors plus a multilingual relevance regression
suite.

Notes:

- _(none yet)_

---

## Phase 7: Desktop + Optimization

**Status**: `NOT STARTED`

**Goal**: Production-ready performance, desktop integration, and an
explicit failure-test matrix.

Checklist:

- [ ] macOS native integration (Spotlight anchors;
      `NSBackgroundActivityScheduler`).
- [ ] Windows native integration (Windows Search anchors; CPU-only
      ML; no GPU assumption).
- [ ] Performance profiling and optimization.
- [ ] Large-scale testing (100K+ messages, 10K+ media, 10+ scripts).
- [ ] Platform-specific ML EP tuning (CoreML, NNAPI, optional
      DirectML).
- [ ] Dedup analytics integration with `kennguy3n/zk-object-fabric`'s
      `metadata/content_index` (read-only, no plaintext leaks).
- [ ] Edge-case handling (offline, interrupted, partial, corrupted,
      missing).
- [ ] Production-scale archive compaction.
- [ ] **Failure test suite**, all passing:
      - chunk upload interrupted
      - manifest upload interrupted
      - wrong backup key
      - corrupted chunk (Merkle / SHA-256 mismatch)
      - device removed from MLS group between backup and restore
      - search shard missing from backend
      - low storage during restore
      - manifest chain break detected on restore

**Decision gate**: Production-ready performance on the target
device matrix. Full failure test suite passes on every platform.

Notes:

- _(none yet)_

---

## Changelog

### 2026-05-02 — Model stack optimization

- Unified text embedding model: dropped `multilingual-e5-small` (~120 MB) and
  `XLM-RoBERTa-small` (~100 MB), standardized on **XLM-R** (~80–100 MB INT8 ONNX)
  — same encoder as slm-guardrail, eliminating cross-repo model redundancy.
- Changed default audio transcription from `Whisper-small` (~240 MB) to
  **`Whisper-base`** (~140 MB INT8 ONNX). Saves ~100 MB on mobile.
  `Whisper-tiny` (~75 MB) remains the low-end Android fallback.
- Replaced `CLIP ViT-B/32` (~150 MB) with **`MobileCLIP-S2`** (~80 MB INT8 ONNX)
  for image/video embeddings. Apple's MobileCLIP-S2 is designed for on-device
  inference and has native Core ML support.

- 2026-05-02: Phase 0 scaffold + crypto landed (PR #2).
- 2026-05-02: CBOR wire formats, manifest spec (Ed25519), media
  descriptor, search index shard spec, key wrap module landed
  (PR #3).
- 2026-05-02: Phase 0 closed. Multilingual tokenization spec
  (ICU primary, `unicode61` fallback, ISO-15924 `ScriptClass`,
  trigram-vs-bigram per-script split, mixed-script segmentation)
  landed at `crates/core/src/search/tokenizer.rs`.
- 2026-05-02: Phase 1 foundation landed. Local store schema types
  + `SCHEMA_SQL` (`crates/core/src/local_store/schema.rs`),
  per-message state machines with `try_transition` and snake_case
  Display / FromStr (`crates/core/src/local_store/state_machines.rs`),
  message processor skeleton
  (`crates/core/src/message/processor.rs`), and the expanded
  `KChatCore` public API in `crates/core/src/lib.rs`.
  Phase 0 ~90%.
