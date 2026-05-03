# KChat Storage & Search — Rust Core

> A Rust core library with platform-specific bindings (iOS via UniFFI/Swift,
> Android via JNI/Kotlin, desktop via native Rust) providing E2EE local
> storage, personal archive, backup, offload, rehydration, and rich
> multilingual search for KChat.

**License**: Proprietary — All Rights Reserved. See [LICENSE](LICENSE).

> Status: **Phase 0 — `COMPLETE`.** **Phase 1 — Local Store + Text
> Search + MLS Integration — `In progress | ~95%`.** **Phase 2 —
> Media Encryption and Blob Service — `In progress | ~95%` (chunked
> media pipeline + thumbnailing landed; tiered media-storage routing
> wired through `MediaBlobSink`).**
> **Phase 3 — Personal Archive and Offload — `In progress | ~60%`
> (foundation: archive event journal wired into `MessagePersister`,
> archive segment builder, archive manifest chain builder, archive
> segment upload orchestration, archive state machine transitions,
> epoch-rotated archive keys with full lifecycle (`EpochKeyManager`),
> offload budget / scoring / eviction with pressure-tier filter +
> pinned-chat exclusion / hydration priority queue wired into
> `CoreImpl::hydrate_message` (timeline-skeleton rehydration without
> scroll-jump + lazy media rehydration on tap), batch-by-bucket
> prefetch with optional dummy request padding, archive backend
> routing (KChat backend / ZK Object Fabric), ZK Object Fabric
> `MediaBlobSink`, tiered eviction policy (cloud-offload first → full
> eviction), `CoreImpl::enforce_storage_budget`).**
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
        search/                             # Phase 1: FTS5 + structured + fuzzy search landed
          mod.rs
          tokenizer.rs                      # ICU + ScriptClass + FuzzyGranularity
          text_search.rs                    # FTS5 BM25 engine, ICU/unicode61 fallback
          query_engine.rs                   # FTS + sender/date/conv/kind structured filters
          fuzzy_search.rs                   # FuzzyTokenizer + FuzzySearchEngine (trigram / bigram)
        archive/                            # Phase 3 foundation: event journal + segment builder + manifest builder + upload + prefetch + epoch keys + routing + privacy padding
          mod.rs
          event_journal.rs                  # ArchiveEventType / ArchiveEvent / ArchiveEventJournal (write_event / read_events_since / advance_cursor / read_unsegmented)
          segment_builder.rs                # SegmentBuildRequest / BuiltSegment / ArchiveSegmentBuilder (CBOR → zstd → XChaCha20-Poly1305)
          manifest_builder.rs               # ArchiveManifestBuilder: genesis → gen N chain, BLAKE3 manifest hash, Ed25519 signature, AEAD-seal under K_archive_manifest
          upload.rs                         # upload_archive_segment over TransportClient + persist_segment_map_row
          prefetch.rs                       # batch_prefetch_bucket / batch_prefetch_bucket_with_padding: one transport hop per (conversation_id, time_bucket)
          epoch_keys.rs                     # EpochKeyManager: current epoch in Zeroizing<[u8; 32]>, prior keys wrapped via AES-256-KW, rotate / unwrap_prior_epoch_key / delete_epoch_key
          routing.rs                        # route_archive_upload / route_archive_download / route_manifest_upload (KChat backend ↔ ZK Object Fabric)
          privacy.rs                        # should_pad / compute_padding_count / generate_dummy_segment_id (UUIDv4) / pad_with_dummy_requests (privacy_level = High)
        backup/                             # placeholder (Phase 4)
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
        models/                             # placeholder (Phase 6)
        offload/                            # Phase 3 foundation: budget + scoring + eviction + hydration
          mod.rs
          budget.rs                         # StorageBudget / StorageUsage / BudgetAssessment / PressureLevel / StorageBudgetEnforcer
          scoring.rs                        # ContentKind weights + 30-day half-life recency decay + size bonus (PROPOSAL §5.4)
          eviction.rs                       # plan_eviction + plan_eviction_with_pressure + plan_tiered_eviction (cloud-offload first → full eviction) + execute_eviction (state-machine demotion)
          hydration.rs                      # HydrationQueue (P0..P5 priority + FIFO) + enqueue_prefetch_window
        restore/                            # placeholder (Phase 4)
        scheduler/                          # placeholder (Phase 4 / 7)
        transport/                          # Phase 1: DeliveryClient + TransportClient + NoopTransportClient + MockDeliveryClient
      benches/
        phase1_benchmarks.rs                # criterion: insert / search / batch / prefix / structured
      tests/
        manifest_signing.rs                 # generation chain end-to-end
        key_wrap_hierarchy.rs               # archive vs backup root wrap split
        epoch_key_derivation.rs             # Phase 3: K_archive_epoch determinism / rotation / wrap-unwrap / cross-epoch decrypt / info-string vectors
        archive_pipeline.rs                 # Phase 3 end-to-end: ingest → archive journal → group → segment build/decrypt → cursor advance
        media_pipeline.rs                   # process_media + chunker + cache + caption + routing + thumbnail end-to-end
        storage_budget_enforcement.rs       # Phase 3 end-to-end: pressure assessment → candidate collection → tiered eviction → executor (every PressureLevel × every EvictionTier)
        multilingual_search.rs              # Latin/Cyrillic/CJK/Arabic/Thai/Devanagari FTS5 round-trip
        multilingual_fuzzy_search.rs        # Combined FTS5 + fuzzy across scripts (typo recovery, dedup, rank, filters)
        pattern_c_interop_vectors.rs        # Rust ↔ Go SDK bit-for-bit vectors
        pattern_c_interop_vectors.json
    ios-bridge/                             # UniFFI → Swift (Phase 1 scaffold: kchat.udl + build.rs + FFI wrappers)
    android-bridge/                         # JNI → Kotlin (Phase 1 scaffold: Java_com_kchat_core_KChatBridge_* entry points)
    desktop/                                # macOS + Windows (Phase 7)
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

The Phase-1 performance benchmarks live under
[`crates/core/benches/`](crates/core/benches/) and run with
[criterion](https://docs.rs/criterion). Run them with:

```sh
cargo bench -p kchat-core --bench phase1_benchmarks
```

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
  (Phase 0 → Phase 7) with explicit decision gates.
- [docs/PROGRESS.md](docs/PROGRESS.md) — phase-gated tracker
  matching `kennguy3n/zk-object-fabric/docs/PROGRESS.md`.

## License

Proprietary — All Rights Reserved. See [LICENSE](LICENSE).
