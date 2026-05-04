# KChat Storage & Search — Progress

- **Project**: KChat Storage & Search — Rust Core
- **License**: Proprietary — All Rights Reserved. See [LICENSE](../LICENSE).
- **Status**: Phase 0 — Protocol and Test Vectors (`COMPLETE`). Phase 1 — Local Store + Text Search + MLS Integration (`In progress | ~96%`). Phase 2 — Media Encryption and Blob Service (`In progress | ~95%`). Phase 3 — Personal Archive and Offload (`In progress | ~96%`). Phase 4 — Backup and Restore (`In progress | ~90%`). Phase 5 — Search (Fuzzy + Encrypted Shards) (`In progress | ~92%`, cold-shard transport adapter + upload pipeline landed). Phase 7 — Desktop + Optimization (`In progress | ~25%`, failure-test suite extended with `manifest_upload_interrupted_mid_write`).
- **Last updated**: 2026-05-04

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

**Status**: `In progress | ~95%`

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
- [x] Transport trait surface (types + `NoopTransportClient`).
      _(Phase-2/3/4 transport surface landed alongside the
      narrower Phase-1 `DeliveryClient`. See
      `crates/core/src/transport/mod.rs`:
      `TransportClient` defines `fetch_messages`,
      `init_blob_upload` / `upload_chunk` / `commit_blob` /
      `fetch_blob_range` (chunked blob I/O),
      `fetch_archive_manifests` / `fetch_archive_segment`
      (Personal Archive), and `fetch_index_shards` (encrypted
      search shards). Supporting types (`FetchMessagesResponse`,
      `BlobUploadHandle`, `ChunkReceipt`, `CommitBlobResponse`,
      `EncryptedManifest`, plus the serde-tagged `BlobClass`
      enum re-used from `crypto::aead`) round-trip through
      JSON. `NoopTransportClient` returns
      `Error::NotImplemented("transport")` from every method
      so `CoreImpl` can be constructed without a real HTTP /
      gRPC backend until Phase 2 lands.)_
- [x] Conversation metadata auto-update on message persist.
      _(`MessagePersister::persist_ingested_message` and
      `persist_outbox_entry` now call
      `LocalStoreDb::update_conversation_last_message` from
      inside the per-message `SAVEPOINT`, and the helper
      guards against out-of-order arrivals so an older
      timestamp can never pull `last_activity_ms` /
      `last_message_id` backwards. `list_conversations`
      ordering therefore reflects the latest message
      activity automatically — no extra call from the
      binding layer.)_
- [x] Message timeline pagination query.
      _(`LocalStoreDb::get_timeline(conversation_id, before_ms,
      limit)` joins `message_skeleton` against `message_body`
      (LEFT JOIN so a dropped body still surfaces with
      `text_content == None`), filters by `created_at_ms <
      before_ms` when supplied, orders newest-first, and
      caps the page with `LIMIT`. The flat
      `TimelineRow { message_id, conversation_id, sender_id,
      created_at_ms, kind, body_state, text_content,
      reply_to, edited_at_ms, deleted_at_ms }` shape lets a
      chat-list UI render the full timeline without an extra
      round-trip per message. Surfaced on `CoreImpl` as
      `get_timeline(uuid, before_ms, limit)` and re-exported
      from `crate::TimelineRow`.)_
- [x] Single-message retrieval on `CoreImpl`.
      _(`CoreImpl::get_message_with_body(message_id) ->
      Option<(MessageSkeleton, Option<MessageBody>)>` and
      `CoreImpl::get_message_body(message_id) ->
      Option<MessageBody>` wrap the existing
      `LocalStoreDb::get_message_with_body` /
      `get_message_body` helpers and convert `DbError` to
      `Error::Storage`. The pair lets bindings render a
      tombstone (skeleton + `None` body) after
      `delete_for_everyone` and lazily hydrate body text on
      tap.)_
- [x] Conversation deletion with cascade cleanup.
      _(`LocalStoreDb::delete_conversation(conversation_id)`
      drops every dependent row inside a single `SAVEPOINT`:
      `search_fuzzy` tokens for messages in the conversation,
      `search_fts` rows, `message_body` rows,
      `message_skeleton` rows, and finally the
      `conversation` row. Returns the count of conversation
      rows deleted; `CoreImpl::delete_conversation(uuid)`
      maps `0` to `Error::Storage` so callers can
      distinguish "not found" from "removed". Now exposed
      on the public `KChatCore` trait so bridge clients can
      drive the cascade without poking into `CoreImpl` directly.)_
- [x] `register_device` stub on the `KChatCore` trait.
      _(Phase-1 placeholder; returns
      `Err(Error::NotImplemented("register_device"))` so the
      bridge layers can pin the FFI shape today and the MLS
      credential / KeyPackage publication pipeline can fill it
      in later in Phase 1 / Phase 2 without breaking callers.)_
- [x] `next_cursor` propagated through `IngestResult`.
      _(`message::processor::IngestResult` now carries the
      `Option<String>` opaque transport cursor populated by
      `CoreImpl::ingest_remote_messages` from
      `transport::FetchResult::next_cursor`. The inherent
      `CoreImpl::ingest_messages` entry point — which has no
      transport context — leaves it as `None`, and the bridge
      layers expose it on their FFI mirrors so paginated drains
      do not have to read the transport mock directly.)_
- [x] UniFFI bridge for iOS / Swift. _(`crates/ios-bridge/`
      Phase-1 scaffold: UDL at `src/kchat.udl` mirrors the
      `KChatCore` surface, `build.rs` invokes
      `uniffi::generate_scaffolding`, and `src/lib.rs` wraps
      `CoreImpl` behind FFI-shaped types with UUID parsing and
      `Error → KChatError` mapping. Production Swift packaging,
      transport / archive / backup methods, and the bindgen-cli
      entry point land in Phase 2; the scaffold is verifiable
      today through the `kchat-ios-bridge` test suite.)_
- [x] JNI bridge for Android / Kotlin. _(`crates/android-bridge/`
      Phase-1 scaffold: `Java_com_kchat_core_KChatBridge_*`
      entry points (`initialize`, `destroy`, `sendText`,
      `search`, `editMessage`, `deleteForMe`,
      `deleteForEveryone`, `getMessage`,
      `getConversationMessages`) wrap a pure-Rust
      `KChatBridgeHandle` so unit tests exercise the same code
      paths without a JNIEnv. Errors throw
      `com.kchat.core.KChatException`; `MessageView` /
      `SearchResult` batches marshal as JSON for brevity at the
      JNI boundary.)_
- [x] Core public API surface: `initialize`, `register_device`,
      `send_text`, `edit_message`, `delete_for_me`,
      `delete_for_everyone`, `get_message`,
      `get_conversation_messages`, `ingest_remote_messages`,
      `search`, `send_media`, `hydrate_message`,
      `run_incremental_backup`, `enforce_storage_budget`,
      `restore_from_backup`. _(Types
      and trait method signatures defined in
      `crates/core/src/lib.rs`: `KChatCore` trait, `SearchQuery`,
      `SearchScope`, `SearchResult`, `HydrationReason` (P0–P5),
      `BackupReason`, `StoragePressureReason`, `ClientMessageId`,
      `DeliveryCursor`, plus the Phase-1 placeholder result
      types `HydratedMessage`, `BackupResult`, `OffloadResult`,
      `RestoreResult`, and the `BackupSource` input type — all
      `Default + Serialize + Deserialize` so the bridge layer
      can already round-trip them. A new
      `Error::NotImplemented(&'static str)` variant lets callers
      pattern-match on the missing capability without parsing
      free-form text.

      Concrete implementation at `crates/core/src/core_impl.rs`:
      `CoreImpl::new(config, key)` opens the SQLCipher store,
      the trait `send_text` mints an outbox entry through
      `MessageProcessor` and persists it via `MessagePersister`,
      `edit_message` / `delete_for_me` /
      `delete_for_everyone` lock the db mutex and delegate to
      `MessagePersister`, `get_message` /
      `get_conversation_messages` delegate to the matching
      `LocalStoreDb` helpers and re-shape the rows into the
      public `MessageView` (skeleton + optional body text),
      `search` delegates to `QueryEngine::execute_search`,
      `initialize` re-opens the DB at the new `data_dir` using
      the retained `K_local_db`. The transport-driven
      `ingest_remote_messages` now runs against an injected
      `Box<dyn DeliveryClient>`: `CoreImpl::with_transport` /
      `set_delivery_client` wire the transport, the trait
      method calls `fetch_messages(conversation_id,
      after_cursor)`, converts each `RawDeliveryMessage` to
      `IngestedMessage`, and forwards into the existing
      `ingest_messages` pipeline so deduplication and FTS
      indexing run unchanged. When no delivery client is
      configured the trait method returns
      `Err(Error::Transport("no delivery client configured"))`.
      The inherent `CoreImpl::ingest_messages(&[IngestedMessage])`
      remains the batch-ingest entry point bridges and tests use.
      The Phase-2/3/4 trait methods (`send_media`,
      `hydrate_message`, `run_incremental_backup`,
      `enforce_storage_budget`, `restore_from_backup`) return
      `Err(Error::NotImplemented(<method_name>))` — the surface
      is locked but the implementation lands with the relevant
      later phase. Methods are sync `Result<_>`-returning
      placeholders that flip to `async fn` once the MLS delivery
      client lands.)_
- [x] Conversation management API. _(Inherent methods on
      `CoreImpl` at `crates/core/src/core_impl.rs`:
      `create_conversation(uuid, title, last_activity_ms)`
      inserts a `conversation` row with the title stored
      verbatim in `title_cipher` (proper AEAD-sealed titles
      land in Phase 2); `list_conversations()` returns rows
      ordered pinned-first then by descending
      `last_activity_ms`; `get_conversation(uuid)` returns
      `Ok(None)` when the row is missing;
      `update_conversation_pin(uuid, pinned)` and
      `update_conversation_mute(uuid, muted)` toggle the
      respective flags and surface `Error::Storage` when the
      conversation does not exist. `LocalStoreDb` at
      `crates/core/src/local_store/db.rs` grew matching
      `list_conversations`, `update_conversation_pin`, and
      `update_conversation_mute` helpers backed by parameterized
      SQL, with six new unit tests covering ordering, missing
      rows, and pin / mute round-trips, plus six new
      `core_impl` tests covering the public surface.)_
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
- [x] Fuzzy token indexing wired into the message lifecycle.
      _(`MessagePersister` at `crates/core/src/message/processor.rs`
      now indexes every persisted body into `search_fuzzy`:
      `persist_ingested_message` and `persist_outbox_entry` call
      `FuzzySearchEngine::new(self.db).index_message(...)` after
      writing the FTS5 row, `edit_message` re-runs
      `remove_message` + `index_message` so old trigrams /
      bigrams are dropped before the new ones land, and
      `delete_for_me` / `delete_for_everyone` call
      `remove_message` so deleted bodies leave no fuzzy residue.
      Five processor unit tests pin the round-trip:
      `persist_ingested_message_indexes_fuzzy_tokens`,
      `persist_outbox_entry_indexes_fuzzy_tokens`,
      `edit_message_updates_fuzzy_tokens`,
      `delete_for_me_removes_fuzzy_tokens`, and
      `delete_for_everyone_removes_fuzzy_tokens`.)_
- [x] Unified FTS5 + fuzzy query engine.
      _(`QueryEngine::execute_search` at
      `crates/core/src/search/query_engine.rs` now fans out to
      both `TextSearchEngine::search_fts` and
      `FuzzySearchEngine::search_fuzzy`, deduplicates the union
      by `message_id`, and applies `BM25_WEIGHT = 2.0` /
      `FUZZY_WEIGHT = 1.0` per `docs/PROPOSAL.md §7.5` so exact
      hits always outrank fuzzy-only hits on the same query.
      Fuzzy-only rows are hydrated through a single
      `fetch_skeleton_basic_info()` batch query so the merged
      result list does not pay one round-trip per fuzzy hit.
      The same structured `WHERE` clause filters both engines
      via the unified `allowed_skeleton_ids()` helper.
      Five new unit tests pin the merge:
      `fuzzy_search_finds_typo_matches`,
      `combined_fts_and_fuzzy_deduplicates`,
      `fuzzy_results_have_lower_rank_than_exact`,
      `fuzzy_only_results_carry_skeleton_metadata`,
      `fuzzy_search_respects_structured_filters`.)_
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
      sender / date-range filters are also covered. A companion
      integration suite at
      `crates/core/tests/multilingual_fuzzy_search.rs` then
      drives the full **FTS5 + fuzzy** pipeline:
      Latin / Cyrillic / Arabic / Thai trigram typo recovery,
      CJK bigram match, mixed-script same-row hits via two
      different queries, cross-engine deduplication on exact
      matches, exact-vs-fuzzy ranking, and structured
      `conversation_filter` / `sender_filter` narrowing of
      fuzzy candidates. Eleven cases run unconditionally
      because the fuzzy half is pure Rust; the Thai FTS path
      soft-skips on non-ICU builds.)_
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
- 2026-05-02: Fuzzy index wired through the message lifecycle
  and merged into the unified search path. `MessagePersister`
  (`crates/core/src/message/processor.rs`) now indexes
  ingested + outbox bodies into `search_fuzzy` and removes /
  re-indexes on edit / delete; `QueryEngine`
  (`crates/core/src/search/query_engine.rs`) fans out to both
  `TextSearchEngine::search_fts` and
  `FuzzySearchEngine::search_fuzzy`, deduplicates by
  `message_id`, and weights the union per
  `docs/PROPOSAL.md §7.5` (`BM25_WEIGHT = 2.0`,
  `FUZZY_WEIGHT = 1.0`). Fuzzy-only rows are skeleton-hydrated
  through a single batch query (`fetch_skeleton_basic_info`).
  Ten new unit tests + an eleven-case integration suite at
  `crates/core/tests/multilingual_fuzzy_search.rs` pin
  Latin / Cyrillic / Arabic / Thai typo recovery, CJK bigram
  match, mixed-script hits, cross-engine dedup, ranking, and
  `conversation_filter` / `sender_filter` narrowing of fuzzy
  candidates.
- 2026-05-02: Public `KChatCore` surface caught up to
  `docs/PROPOSAL.md §12`. The trait now carries
  `send_media`, `hydrate_message`, `run_incremental_backup`,
  `enforce_storage_budget`, and `restore_from_backup` along
  with the matching placeholder result types
  (`HydratedMessage`, `BackupResult`, `OffloadResult`,
  `RestoreResult`) and the `BackupSource` input type — all
  `Default + Serialize + Deserialize`. A new
  `Error::NotImplemented(&'static str)` variant lets callers
  pattern-match on the missing capability; the matching
  `CoreImpl` stubs return
  `Err(Error::NotImplemented("<method>"))` until the
  Phase-2/3/4 implementations land. Every result type
  round-trips through serde and every stub asserts the
  expected error variant in unit tests.
- 2026-05-02: Conversation management API landed on
  `CoreImpl`. New inherent methods cover
  `create_conversation` / `list_conversations` /
  `get_conversation` / `update_conversation_pin` /
  `update_conversation_mute`, backed by matching SQL helpers
  on `LocalStoreDb`. Listing is pinned-first then by
  descending `last_activity_ms`; pin / mute updates surface
  `Error::Storage` when the conversation does not exist so
  the bridge layer can show the failure to the user.

---

## Phase 2: Media Encryption and Blob Service

**Status**: `In progress | ~95%`

**Goal**: Chunked encrypted media upload / download, thumbnailing,
local media cache.

Checklist:

- [x] Media processor: thumbnail generation, chunk encryption with
      random `K_asset`. (Chunk encryption + `K_asset` random gen +
      AES-256-KW wrap landed in `media::processor::process_media`;
      thumbnail generation lands in `media::thumbnail::ThumbnailGenerator`
      using the `image` crate to downscale and re-encode as PNG.)
- [~] Chunked encrypted blob upload / download (transport client).
      (`media::upload::upload_chunked_media` /
      `media::upload::resume_upload` drive `init → chunk(s) →
      commit` against `TransportClient`; the production HTTP /
      gRPC implementation of `TransportClient` itself is still
      stubbed by `NoopTransportClient`.)
- [ ] Media descriptor distribution through MLS.
- [x] Local media cache with LRU eviction.
- [x] Resume-upload (no duplicate completed chunks).
- [x] Chunk integrity verification (per-chunk SHA-256, BLAKE3
      Merkle root, AEAD tag).
- [x] Media state machine (`thumbnail_only`, `original_local`,
      `remote_original`, `download_in_progress`, `evicted`,
      `deleted`).
- [x] Size-class padding for metadata privacy.
- [x] Per-chunk AEAD AAD construction.
- [x] Multilingual filename / caption handling.
- [x] `StorageSink` enum and `ArchiveBackend` enum in config
      (`crates/core/src/config.rs`). See PROPOSAL.md §5.7.
- [x] `storage_sink` field on `MediaDescriptor` (CBOR,
      `#[serde(default)]` for backward compat).
- [x] `storage_sink` column on `media_asset` table (schema
      migration with `DEFAULT 'kchat_backend'`).
- [x] `MediaBlobSink` trait: object-safe, `Send + Sync`, with
      `upload_media_chunks` / `fetch_media_chunk` /
      `delete_media_blob`.
- [x] `NoopMediaBlobSink` placeholder.
- [x] Media upload routing: thumbnails always go to
      `TransportClient` (KChat backend); originals route to the
      configured `MediaBlobSink` (default: `TransportClient`
      fallback).
- [x] Media rehydration routing: `media_asset.storage_sink`
      determines which sink to fetch from.

**Decision gate**: Media can be encrypted, chunked, uploaded,
downloaded, range-fetched, verified, and displayed on iOS, Android,
macOS, and Windows. Resumed uploads never duplicate completed
chunks.

Notes:

- Tiered media storage spec and trait surface land here; sink
  implementations land in Phase 3. See PROPOSAL.md §5.7 and §10.2.
- Phase-2 chunked-media pipeline scaffolding landed at
  `crates/core/src/media/{chunker,processor,upload}.rs`. The
  chunker carries `chunk_and_encrypt` /
  `verify_and_decrypt` (per-chunk `KCHAT_BLOB_CHUNK_V1` AAD,
  XChaCha20-Poly1305, deterministic per-chunk nonces, SHA-256
  fast-fail before AEAD-open, BLAKE3 whole-object root) and the
  size-class padding (`pad_to_size_class` /
  `unpad_from_size_class`). The processor wires everything
  through random `K_asset` generation + AES-256-KW wrap +
  `MediaDescriptor` assembly. The upload pipeline drives
  `TransportClient` through `init → chunk(s) → commit` with
  server-side BLAKE3 verification, and `resume_upload` skips
  completed chunks for resumable transfers.
- The `K_asset` raw bytes returned by `process_media` live in a
  `Zeroizing<[u8; 32]>` so a panic mid-upload still scrubs the
  asset key before unwinding (matches the `core_impl::CoreImpl`
  pattern for `K_local_db`).

---

## Phase 3: Personal Archive and Offload

**Status**: `In progress | ~95%`

**Goal**: Interactive cold storage with scroll-back rehydration and
storage-pressure management.

Checklist:

- [x] Archive event journal. (`crates/core/src/archive/event_journal.rs`
      with `archive_event_journal` + `archive_event_cursor` tables;
      reader/writer API plus `read_unsegmented` to feed the segment
      builder. Wired into `MessagePersister` so every persist /
      edit / delete and `CoreImpl::send_media` writes a matching
      `ArchiveEvent` inside the same SAVEPOINT as the
      `backup_event_journal` row.)
- [~] Archive segment builder (per-conversation / per-time-bucket).
      (`crates/core/src/archive/segment_builder.rs`: CBOR encode →
      zstd compress → XChaCha20-Poly1305 seal under
      `K_archive_segment`, BLAKE3 plaintext root, default monthly
      `time_bucket` helper.)
- [~] Archive manifest chain (generation N+1, `previous_manifest_hash`,
      Ed25519 signature). (`crates/core/src/archive/manifest_builder.rs`:
      genesis → gen N chain, BLAKE3 over canonical-CBOR signing
      payload, Ed25519 signature, AEAD-seal under
      `K_archive_manifest` derived from the active epoch key.)
- [~] Encrypted segment upload to backend blob service.
      (`crates/core/src/archive/upload.rs::upload_archive_segment`:
      computes ciphertext-side BLAKE3 Merkle root, drives
      `TransportClient::init_blob_upload → upload_chunk →
      commit_blob`, asserts the commit response's Merkle root
      matches, and `persist_segment_map_row` records the
      result in `archive_segment_map` with `state =
      'archive_uploaded'`.)
- [~] Whole-object Merkle-root verification after upload.
      (`upload_archive_segment` rejects a mismatched
      `commit_blob` Merkle root before any state-machine
      transition.)
- [~] Archive state machine (`not_archived` → `archive_pending` →
      `archive_uploaded` → `archive_verified` → `archive_compacted`).
      (`local_store::db::update_archive_state`: validates every
      row's predecessor via `ArchiveState::try_transition` before
      issuing the batch UPDATE; rejects illegal jumps such as
      `not_archived → archive_verified`.)
- [~] Storage budget enforcement (`enforceStorageBudget`).
      (`crates/core/src/offload/budget.rs` with `StorageBudget`,
      `StorageUsage`, `BudgetAssessment`, `PressureLevel` and a
      stateless `StorageBudgetEnforcer::assess` driving the offload
      orchestration loop. `CoreImpl::enforce_storage_budget` wires
      this in.)
- [~] Eviction scoring formula.
      (`crates/core/src/offload/scoring.rs`:
      `compute_eviction_score` combines `ContentKind` weight,
      30-day half-life recency decay, and 16 MiB-normalised size
      bonus per PROPOSAL §5.4.)
- [x] Eviction priority order (video → documents → images → voice →
      thumbnails → cold text bodies). (`CONTENT_KIND_WEIGHTS` in
      `offload::scoring` plus `plan_eviction_with_pressure` in
      `offload::eviction` sort candidates accordingly and gate
      content kinds by [`PressureLevel`]: video / documents /
      images / voice are eligible at `Warning+`, thumbnails at
      `Critical+`, cold text bodies at `Extreme` only. The
      matching `collect_eviction_candidates` query joins
      `media_asset`, `message_skeleton`, and `conversation` and
      is wired into `CoreImpl::enforce_storage_budget` — it
      returns rows with `archive_state = archive_verified`,
      `pinned = 0`, `media_state = 'original_local'`, and
      `created_at_ms < now - min_offload_age_ms`.)
- [x] Pinned-chat / pinned-message exclusion.
      (`compute_eviction_score` returns `f64::MIN` for any
      candidate flagged `pinned = true` so a stray pinned row that
      slips past `collect_eviction_candidates` still cannot be
      evicted, and the SQL filter `conversation.pinned = 0` is the
      first guard.)
- [x] Timeline-skeleton rehydration (no scroll-jump).
      (`local_store::db::LocalStoreDb::rehydrate_message_body`
      runs an `INSERT OR REPLACE` on `message_body` and a
      `body_state` UPDATE on `message_skeleton` inside one
      SAVEPOINT without touching `created_at_ms` /
      `received_at_ms`, then re-indexes into `search_fts` and
      `search_fuzzy_words`. Wired through
      `CoreImpl::hydrate_message` so a cold message tapped from
      search results lands its body in place without
      jump-scrolling the viewport.)
- [x] Lazy media rehydration on tap.
      (`media::download::rehydrate_media_asset` reads
      `media_asset.{blob_id, storage_sink, chunk_count,
      merkle_root, wrapped_k_asset}`, unwraps `K_asset` via
      `K_local_db`, drives
      `download_chunked_media_via_transport` /
      `download_chunked_media_via_sink` based on
      `storage_sink`, verifies the BLAKE3 root, and calls
      `update_media_state` to flip `media_state` to
      `original_local`. Wired into `CoreImpl::hydrate_message`
      so an `evicted` / `remote_original` asset enqueues a
      hydration request at the appropriate priority.)
- [~] Prefetch window (viewport ± 100–150 messages).
      (`HydrationQueue::enqueue_prefetch_window` plus
      `CoreImpl::enqueue_prefetch_window` widen a viewport into
      P3 prefetch enqueues.)
- [x] Hydration priority queue (P0–P5).
      (`crates/core/src/offload/hydration.rs`: deduplicating priority
      queue keyed on `HydrationReason` with FIFO tiebreaker, plus
      `enqueue_prefetch_window` for viewport adjacency. Wired into
      `CoreImpl::hydrate_message` — every hydrate call enqueues a
      request mapped through `parse_hydration_reason`
      (`search_result_tap` → P0, `media_fullscreen` → P1,
      `visible_viewport` → P2, `prefetch` / `adjacent_prefetch` →
      P3, `background_restore` → P4, `idle_fill` /
      `opportunistic_fill` → P5; unknown reasons collapse to P5).)
- [~] Epoch-rotated archive key derivation: `K_archive_root` →
      `K_archive_epoch(epoch_id)` → `K_archive_segment` /
      `K_archive_manifest`. HKDF info =
      `"kchat-archive-epoch-v1" || epoch_id`. Default epoch
      cadence: monthly (matching `time_bucket`).
      (`crypto::key_hierarchy::{derive_archive_epoch_key,
      derive_archive_segment_key, derive_archive_manifest_key,
      wrap_epoch_key, unwrap_epoch_key}`.)
- [x] Epoch key lifecycle: current epoch key in memory; prior
      epoch keys wrapped under `K_archive_root` and recorded in
      the archive manifest chain. Optional epoch-key deletion
      for forward secrecy.
      (`crates/core/src/archive/epoch_keys.rs::EpochKeyManager`:
      current epoch key held in `Zeroizing<[u8; 32]>`, prior keys
      wrapped via AES-256-KW under `K_archive_root` and recorded
      in a `BTreeMap<String, Vec<u8>>` for cross-epoch segment
      decrypt. `rotate(new_epoch_id)` wraps the previous key
      before deriving the new one; `unwrap_prior_epoch_key`
      decrypts a stored wrapped key for cross-epoch segment
      reads; `delete_epoch_key(epoch_id)` drops the wrapped key
      for forward secrecy. Both rotation and deletion preserve
      the manifest-chain audit trail via the `epoch_id` /
      `derived_at_ms` metadata.)
- [x] Epoch key derivation test vectors (Rust): deterministic
      derivation, epoch rotation, wrapped-key round-trip,
      cross-epoch segment decrypt after manifest-chain unwrap.
      (`epoch_key_derivation_is_deterministic`,
      `different_epoch_ids_produce_different_keys`,
      `epoch_key_wrap_unwrap_round_trip`,
      `segment_key_from_epoch_is_deterministic`,
      `cross_epoch_segment_decrypt` in
      `crypto::key_hierarchy::tests`, plus the dedicated
      integration test surface at
      `crates/core/tests/epoch_key_derivation.rs`:
      `deterministic_epoch_derivation`,
      `different_epochs_produce_different_keys`,
      `epoch_key_wrap_unwrap_round_trip`,
      `cross_epoch_segment_decrypt`,
      `epoch_key_info_string_matches_spec`.)
- [x] ZK Object Fabric as optional archive backend: S3-compatible
      transport adapter for archive segment upload / download /
      manifest storage. Configured via `archive_backend = "zkof"`
      + ZKOF tenant credentials.
      (`crates/core/src/archive/routing.rs::ZkofArchiveAdapter`
      now wires a real `S3Client`-backed adapter — segment
      uploads land at `archive/segments/{segment_id}` and
      manifest uploads at `archive/manifests/{manifest_id}`,
      matching `backup/sinks/zk_fabric.rs`.
      `CoreImpl::install_zkof_archive_backend(s3, config)` wires
      it in alongside `zkof_archive_config` /
      `zkof_archive_s3` slots; `rehydrate_timeline_skeletons`
      dispatches via the ZKOF router when
      `archive_backend == Zkof`. Integration tests use
      `InMemoryS3` and round-trip a sealed segment through
      upload → fetch → decrypt.)
- [x] Archive backend routing: transport client routes archive
      operations to KChat backend or ZKOF based on configuration.
      Manifest index stored as a well-known S3 key when using ZKOF.
      (`crates/core/src/archive/routing.rs`: `route_archive_upload` /
      `route_archive_download` / `route_manifest_upload` dispatch
      to either `TransportClient` or a `ZkofArchiveAdapter` based
      on `KChatCoreConfig::archive_backend`. The ZKOF adapter
      uses an `S3Client`-shaped trait (`NoopS3Client` stub for
      now) and maps manifest objects to a well-known
      `manifests/index` key.)
- [~] Batch-by-bucket prefetch: on any archive segment miss, fetch
      all segments for the `(conversation_id, time_bucket)` pair.
      Reduces per-segment access-pattern metadata to per-bucket
      granularity. (`crates/core/src/archive/prefetch.rs::batch_prefetch_bucket`
      queries `archive_segment_map` for the pair and streams every
      matching segment through `TransportClient::fetch_archive_segment`,
      returning `PrefetchedSegment { segment_id, blob_id,
      storage_backend, ciphertext }` per row.)
- [x] Dummy request padding (optional, off by default): mix real
      rehydration fetches with dummy fetches to random segment IDs.
      Enabled via `privacy_level = "high"`.
      (`crates/core/src/archive/privacy.rs`: `should_pad`,
      `compute_padding_count`, `generate_dummy_segment_id` (UUIDv4
      to differentiate from real UUIDv7 segment ids), and
      `pad_with_dummy_requests` (deterministic interleave keyed
      on the real-id ordering hash).
      `archive::prefetch::batch_prefetch_bucket_with_padding` is
      the padding-aware variant of `batch_prefetch_bucket`:
      issues one fetch per id in the padded order, silently
      drops dummy errors. `KChatCoreConfig::privacy_level`
      defaults to `Standard` (off); set to `High` to enable.)
- [~] iCloud `MediaBlobSink` implementation (CloudKit file
      storage). See PROPOSAL.md §10.2.
      (`crates/core/src/media/sinks/icloud.rs::ICloudMediaBlobSink`:
      object-safe `ICloudBlobBridge` trait wraps the iOS/macOS
      bridge with `upload_file` / `download_file_range` /
      `delete_file`; `ICloudMediaBlobSink` concatenates chunks
      under the asset_id record name and stores the CloudKit
      record name in `MediaBlobReference.metadata`. Storage sink
      tag = `"icloud"`. Ships with `NoopICloudBridge` for tests.)
- [~] Google Drive `MediaBlobSink` implementation (Drive API via
      platform bridge).
      (`crates/core/src/media/sinks/google_drive.rs::GoogleDriveMediaBlobSink`:
      same pattern as iCloud — `GoogleDriveBridge` trait + `Arc<dyn>`
      sink wrapper. Stores the Drive file id in
      `MediaBlobReference.metadata`. Storage sink tag =
      `"google_drive"`. Ships with `NoopGoogleDriveBridge` for tests.)
- [x] ZK Object Fabric `MediaBlobSink` implementation (S3
      `PutObject` / `GetObject`).
      (`crates/core/src/media/sinks/zk_fabric.rs::ZkObjectFabricSink`:
      maps `upload_media_chunks` /
      `fetch_media_chunk` / `delete_media_blob` to per-chunk S3
      keys of the form `media/{asset_id}/chunk-{idx:08}` against
      a configured bucket. The S3 client itself is a small
      `S3Client` trait with `put_object` / `get_object` /
      `delete_objects_with_prefix` and a `NoopS3Client` stub for
      now — the actual HTTP / SDK implementation lands later.
      `MediaBlobReference::metadata` carries `[chunk_count:u32_be]
      [merkle_root:32b][asset_id:utf8]` so the rehydration path
      can re-derive every chunk key without a second DB
      round-trip.)
- [x] Tiered eviction policy: media originals offload to user
      cloud before archive segments offload to KChat backend.
      (`offload::eviction::EvictionTier` classifies each
      `EvictionCandidate` by its `storage_sink`:
      `kchat_backend` → `FullEviction`; everything else →
      `CloudOffload`. `plan_tiered_eviction` runs a two-pass
      planner that drains the cloud-offload pool first and only
      falls through to the full-eviction pool if the cloud pass
      underran the byte budget. Wired into
      `CoreImpl::enforce_storage_budget`, which now executes the
      cloud-offload plan and the full-eviction plan in order and
      reports the combined `freed_bytes` / `evicted_count`.)
- [x] `storage_backend` column on `archive_segment_map` for
      tracking where each segment lives.
      (`local_store::schema::StorageBackend` typed enum +
      column on `archive_segment_map`. The download path
      reads it via `archive::download::ArchiveSegmentRouter`,
      which dispatches to either `TransportClient` (for
      `kchat_backend`) or an `S3Client` (for
      `zk_object_fabric`). `archive::prefetch::batch_prefetch_bucket`
      / `_with_router` honor the per-row backend.
      `CoreImpl::rehydrate_timeline_skeletons_with_router`
      makes the backend-aware scroll-back path explicit.)

**Decision gate**: Messages and media offload + rehydrate
transparently; storage budget is enforced; timeline renders
skeletons immediately with lazy fill; indexes remain resident
across all eviction strata. Media originals can be uploaded to
and fetched from at least one user-cloud sink (iCloud or ZKOF) in
addition to the KChat backend.

Notes:

- 2026-05-03: Phase-3 foundation work landed — archive event
  journal, archive segment builder (CBOR + zstd + XChaCha20-
  Poly1305 seal), epoch-rotated archive key derivation,
  `offload::{budget, scoring, eviction, hydration}` modules, and
  the `CoreImpl::hydrate_message` + `enforce_storage_budget`
  wiring. The remote archive fetch path (manifest reader / segment
  download) is still queued; `hydrate_message` returns
  `is_cold = true` for `remote_archive_only` bodies and
  `enforce_storage_budget` is wired against the budget enforcer
  but does not yet harvest candidate rows from the local store
  (queued for the next milestone).
- 2026-05-03 (Phase-2 finishing pass + Phase-3 foundation): ten
  follow-on changes landed in the same day:
  1. **Archive event journal wired into `MessagePersister`**:
     every `persist_ingested_message` /
     `persist_outbox_entry` / `edit_message` /
     `delete_for_me` / `delete_for_everyone` /
     `CoreImpl::send_media` now writes a matching
     `ArchiveEvent` inside the existing SAVEPOINT alongside
     the `BackupEvent`.
  2. **Eviction candidate collection query**:
     `offload::eviction::collect_eviction_candidates` joins
     `media_asset` × `message_skeleton` × `conversation`,
     filters by `archive_state = archive_verified`,
     `pinned = 0`, `media_state = 'original_local'`, and
     min-offload-age, and is wired into
     `CoreImpl::enforce_storage_budget` (replaces the
     previous `Vec::new()` placeholder).
  3. **Pinned-chat exclusion guard in `compute_eviction_score`**:
     a `pinned` candidate scores `f64::MIN` so the scoring
     path is also pin-safe even if a pinned row leaks past the
     SQL filter.
  4. **Archive manifest chain builder**
     (`archive::manifest_builder`): genesis (gen 0,
     `previous_manifest_hash = [0; 32]`) → gen N chain,
     BLAKE3 over canonical-CBOR signing payload, Ed25519
     signature, AEAD-seal under `K_archive_manifest` derived
     from the epoch key, with negative tests for
     wrong-key-fails-open.
  5. **Archive segment upload orchestration**
     (`archive::upload::upload_archive_segment` +
     `persist_segment_map_row`): drives `init_blob_upload →
     upload_chunk → commit_blob` against the
     `TransportClient` trait, verifies the commit response's
     ciphertext-side BLAKE3 Merkle root, and inserts the
     resulting row into `archive_segment_map` with
     `state = 'archive_uploaded'`.
  6. **Archive state machine transitions**
     (`local_store::db::update_archive_state`): batch UPDATE
     gated by `ArchiveState::try_transition`; rejects illegal
     jumps such as `not_archived → archive_verified` and
     never partial-writes.
  7. **Epoch key derivation test vectors**
     (`crates/core/tests/epoch_key_derivation.rs`): the five
     PROPOSAL §2.1 vectors —
     `deterministic_epoch_derivation`,
     `different_epochs_produce_different_keys`,
     `epoch_key_wrap_unwrap_round_trip`,
     `cross_epoch_segment_decrypt`, and
     `epoch_key_info_string_matches_spec`.
  8. **Hydration priority queue wiring**
     (`CoreImpl::hydrate_message`,
     `CoreImpl::enqueue_prefetch_window`): `hydration_queue:
     Mutex<HydrationQueue>` field with `parse_hydration_reason`
     mapping reason strings to P0–P5; `hydrate_message`
     enqueues against the resolved priority while still
     serving local bodies inline.
  9. **Batch-by-bucket prefetch**
     (`archive::prefetch::batch_prefetch_bucket`): one
     transport hop per `(conversation_id, time_bucket)` so
     the storage backend's access log only sees per-bucket
     granularity per PROPOSAL §5.6.
  10. **End-to-end archive integration test**
      (`crates/core/tests/archive_pipeline.rs`): seed → ingest
      → archive journal → group by bucket → build segment →
      decrypt → re-derive key hierarchy → second-bucket
      segment → cursor advance, all in one
      `archive_pipeline_end_to_end` walk.

---

## Phase 4: Backup and Restore

**Status**: `In progress | ~85%`

**Goal**: Incremental backup to platform sinks and skeleton-first
restore.

Checklist:

- [x] Backup event journal.
      (`crates/core/src/backup/event_journal.rs`:
      `BackupEventType` enum (`MessageReceived`, `MessageEdited`,
      `MessageDeleted`, `MediaReceived`, `MediaDeleted`,
      `ConversationCreated`, `ConversationDeleted`); `BackupEvent`
      with `conversation_id` / `message_id` / `payload`;
      `BackupEventJournal` with `write_event`, `read_events_since`,
      `read_cursor`, `advance_cursor`, `read_unsegmented`. Wired
      into `MessagePersister` so every persist / edit / delete
      writes a typed `BackupEvent` inside the same SAVEPOINT as
      the `archive_event_journal` row. Legacy non-taxonomy event
      strings (e.g. `outbox_pending`) are silently skipped on
      read.)
- [x] Incremental backup segment builder.
      (`crates/core/src/backup/segment_builder.rs::BackupSegmentBuilder`:
      CBOR encode → zstd compress → XChaCha20-Poly1305 seal under
      `K_backup_segment` derived via
      `derive_backup_segment(K_backup_root, segment_id)`. AAD =
      `KCHAT_BACKUP_SEGMENT_V1 || segment_id || merkle_root`.
      `decrypt_backup_segment` powers the restore path.)
- [x] Backup manifest chain with Ed25519 signature.
      (`crates/core/src/backup/manifest_builder.rs::build_backup_manifest`:
      genesis (`generation = 0`,
      `previous_manifest_hash = [0; 32]`) → chained
      (`generation = prev.generation + 1`,
      `previous_manifest_hash = compute_manifest_hash(prev)`).
      Ed25519 over canonical CBOR, AEAD-sealed under
      `K_backup_manifest` with `device_id` mixed into the AAD for
      device attribution.)
- [x] iOS iCloud backup sink.
      (`crates/core/src/backup/sinks/icloud.rs::ICloudBackupSink`:
      `ICloudBackupBridge` trait (`upload_file` / `download_file`
      / `list_files` / `delete_file`) wraps the iOS / macOS side;
      `ICloudBackupSink` maps `segment_id` →
      `backups/segments/{segment_id}` and `manifest_id` →
      `backups/{manifest_id}` records and implements
      `BackupSink::{upload_backup_segment,
      upload_backup_manifest, fetch_backup_manifest,
      fetch_backup_segment, list_backup_manifests}`.
      `NoopICloudBackupBridge` returns
      `Error::NotImplemented("icloud_backup_bridge")`.)
- [x] Android backup sink strategy (Auto Backup for envelopes;
      Large Backup / SAF for full data).
      (`crates/core/src/backup/sinks/android.rs::AndroidBackupSink`:
      `AndroidBackupBridge` trait splits manifest envelopes
      (`write_auto_backup` / `read_auto_backup` — Auto Backup
      ≤ 25 MiB record cap) from full segment data
      (`write_saf` / `read_saf` / `list_saf` —
      Storage Access Framework, no size cap).
      `AndroidBackupSink::list_backup_manifests` filters Auto
      Backup entries to manifests-only.
      `NoopAndroidBackupBridge` stub for tests.)
- [x] **ZK Object Fabric backup sink** (S3 API; Pattern C convergent
      encryption; bit-identical interop with the Go SDK).
      (`crates/core/src/backup/sinks/zk_fabric.rs::ZkofBackupSink`:
      uploads sealed manifests to `backups/{manifest_id}` and
      sealed segments to `backups/segments/{segment_id}`
      against a configured S3 bucket; Pattern C convergent
      encryption is wired via
      `crypto::convergent::derive_convergent_dek` so identical
      tenant + plaintext produces a deterministic ciphertext —
      bit-identical to the Go SDK at
      `kennguy3n/zk-object-fabric/encryption/client_sdk/`.
      `BackupSink` trait + `NoopBackupSink` for tests.
      Tests cover round-trip, convergent determinism, and
      `Box<dyn BackupSink>` object safety.)
- [x] Backup compaction (daily → weekly checkpoint → monthly prune).
      (`crates/core/src/backup/compaction.rs`:
      `CompactionTier::{Daily, Weekly, Monthly}` +
      `CompactionPolicy` with configurable
      `daily_to_weekly_ms` / `weekly_to_monthly_ms` /
      `min_group_size` thresholds (defaults: 7d / 30d / 2);
      `plan` deterministically buckets eligible segments by
      `(source_tier, week_or_month_bucket)`; singleton groups
      below `min_group_size` are skipped;
      `apply_tombstones` drops tombstone events themselves and
      any earlier events superseded by `MessageDeleted` /
      `ConversationDeleted` / `MediaDeleted` for the same id
      pair. Monthly is terminal (`CompactionTier::next_tier`
      returns `None`).)
- [x] Manifest chain verification on restore.
      (`crates/core/src/restore/manifest_verifier.rs::verify_manifest_chain`:
      walks `manifests[0..]` from genesis to latest, verifies
      every Ed25519 signature via
      `formats::manifest::verify_backup_manifest`, enforces
      `manifests[0].previous_manifest_hash == GENESIS_PREVIOUS_HASH`
      and `manifests[n].previous_manifest_hash ==
      compute_manifest_hash(manifests[n-1])`, and surfaces
      structured `EmptyChain` /
      `SignatureInvalid { generation }` /
      `ChainBreak { generation, expected, actual }` /
      `GapDetected { missing_generation }` /
      `GenesisHashNotZero { actual }` /
      `HashComputationFailed { generation }` per failure
      mode.)
- [x] Skeleton-first restore (conversation list → skeletons →
      search index shards → recent bodies → lazy media).
      (`crates/core/src/restore/pipeline.rs::RestorePipeline`:
      drives the five-step priority sequence and persists every
      step's `RestoreState` transition. `restore_recent_bodies`
      flips skeletons inside the recency window from
      `RemoteArchiveOnly` to `LocalPlainAvailable`;
      `enable_lazy_media_restore` advances to
      `MediaLazyRestoreEnabled`; the run finishes at
      `FullRestoreComplete`. Wired through
      `CoreImpl::restore_from_backup`.)
- [x] Restore state machine.
      (`crates/core/src/restore/state_machine.rs`: persistence
      helpers (`load`, `save`, `transition`, `reset`) for the
      single-row `restore_state` table, layered on top of the
      already-defined
      `local_store::state_machines::RestoreState` enum and its
      forward-only `try_transition`. Snake-case `Display` /
      `FromStr` round-trip; serde wire form matches the SQL
      column.)
- [x] Key recovery (device-to-device, recovery key, passphrase;
      server escrow off by default).
      (`crates/core/src/restore/key_recovery.rs`: `RecoveryKey`
      wraps `K_user_master` via AES-256-KW (RFC 3394) with a
      hex display helper; `generate_recovery_key` /
      `recover_from_key` round-trip and reject wrong keys via
      the wrap integrity check value. `DeviceTransferPayload` +
      `prepare_device_transfer` / `accept_device_transfer`
      AEAD-seal `K_user_master` + the three derived roots
      (`K_archive_root`, `K_backup_root`, `K_search_root`)
      under a transfer key derived from a numeric / QR code via
      HKDF-SHA-256; the envelope itself now derives
      `Zeroize` + `ZeroizeOnDrop` and every CBOR /
      AEAD-opened plaintext flows through `Zeroizing<Vec<u8>>`.
      Passphrase recovery (`PassphraseRecoveryEnvelope`,
      `wrap_master_key_with_passphrase`,
      `unwrap_master_key_with_passphrase`) uses Argon2id with
      OWASP-mobile parameters (`m_cost = 65536`, `t_cost = 3`,
      `p_cost = 1`, output 32 bytes) feeding AES-256-KW;
      different salts produce different keys, the same
      (passphrase, salt) is deterministic, and a wrong
      passphrase fails the wrap integrity check value. Server
      escrow remains OFF by default per
      `docs/PHASES.md §Phase 4`.)
- [x] Search index backup and restore (encrypted shards).
      (`crates/core/src/search/shard_builder.rs`:
      `build_text_search_shard` / `build_fuzzy_search_shard`
      read `search_fts` / `search_fuzzy_words` rows for a
      `(conversation_id, time_bucket)` pair, encode through
      `formats::SearchIndexShard` (`IndexType::Text` /
      `IndexType::Fuzzy`), and AEAD-seal under
      `K_text_index_shard` / `K_fuzzy_index_shard` derived from
      `K_search_root`. `restore_text_search_shard` /
      `restore_fuzzy_search_shard` invert the path. Tests cover
      build / restore round-trip, wrong-key failure, and
      multilingual content survival across Latin / CJK /
      Arabic.)
- [x] Multilingual backup-restore corpus validation.
      (`crates/core/tests/backup_restore_multilingual.rs`:
      ingests 8+ scripts (English, Russian, Chinese, Japanese,
      Arabic, Thai, Hindi, mixed Latin+CJK), drives the segment
      builder + 2-generation manifest chain through
      `verify_manifest_chain`, runs `RestorePipeline::run`
      against a fresh in-memory store, and asserts every
      conversation / skeleton / body lands on the new device
      with the FTS / fuzzy / structured filters intact.
      Soft-skips CJK / Thai FTS assertions on non-ICU builds.)

**Decision gate**: Full backup / restore cycle works on every
target platform. New device renders conversation list and returns
search hits within seconds, recent bodies within minutes, media
lazy thereafter. Pattern C dedup against ZK Object Fabric is
verified by re-uploading identical content from two devices in the
same tenant and observing a single stored copy.

Notes:

- 2026-05-03: Phase-4 foundation landed. The backup pipeline now
  has a full end-to-end Rust path: `BackupEvent` typed taxonomy
  → `BackupEventJournal` cursor-drained reader → CBOR + zstd +
  XChaCha20-Poly1305 segment seal under `K_backup_segment` →
  Ed25519-signed, generation-chained manifest sealed under
  `K_backup_manifest` with `device_id` AAD attribution → a
  daily → weekly → monthly compaction policy with tombstone
  application → manifest chain verifier with structured failure
  modes → `RestorePipeline` skeleton-first orchestration that
  walks the `restore_state` machine to terminal
  `FullRestoreComplete`. iCloud / Google Drive / ZKOF
  `MediaBlobSink` scaffolds (Phase 3 sink slots) ship in the
  same change. Cross-module coverage lives at
  `crates/core/tests/backup_pipeline.rs`.
- 2026-05-03 (Phase 3/4 batch — Tasks 1–10): the ten tasks
  itemised in the Phase 3/4 plan all landed in tree, lifting
  Phase 3 from `~75%` to `~85%` and Phase 4 from `~55%` to
  `~75%`. All 921 tests in the workspace pass; clippy is clean
  with `-D warnings`; `cargo fmt --all -- --check` is clean.
  1. **Text+media skeleton consistency**
     (`crates/core/src/message/processor.rs`): when a message
     has BOTH `text_content` and `media_descriptors`, the
     skeleton now resolves `kind = MessageKind::Media` and
     `media_state = Some(MediaState::ThumbnailOnly)` so the
     `media_asset` rows the loop persists are no longer
     orphaned by a `media_state = NULL` skeleton header. Test:
     `persist_text_plus_media_message_sets_media_state_on_skeleton`.
  2. **`rehydrate_media_for_message` 3-phase refactor**
     (`crates/core/src/core_impl.rs` +
     `crates/core/src/media/download.rs`): the previous
     implementation held `self.db.lock()` across every
     sequential `transport.fetch_blob_range()` chunk, blocking
     `send_text` / `search` / `ingest` for the duration of a
     download. Now split into `prepare_rehydration` (read
     metadata under lock) → `execute_rehydration_download`
     (chunk download + BLAKE3 root verify, no DB reference) →
     `commit_rehydration` (SAVEPOINT-bounded
     `media_state` + `bytes_local` flip back under lock).
     A regression test spawns a parallel `search` while a mock
     transport sleeps inside `fetch_blob_range` and asserts
     the search returns immediately rather than blocking.
  3. **`CoreImpl::run_incremental_backup` end-to-end**
     (`crates/core/src/core_impl.rs`): replaces the
     `Error::NotImplemented("run_incremental_backup")` stub.
     Reads `BackupEventJournal::read_unsegmented`, derives
     `K_backup_segment` from `K_backup_root` via
     `crypto::key_hierarchy::derive_backup_segment`, builds a
     sealed segment via `BackupSegmentBuilder::build_segment`,
     uploads via the configured transport / `BackupSink`,
     builds + signs the next manifest generation via
     `build_backup_manifest`, advances the cursor, and returns
     a populated `BackupResult`. Tests:
     `run_incremental_backup_with_pending_events_produces_segment`,
     `run_incremental_backup_with_no_events_is_noop`,
     `run_incremental_backup_advances_cursor`,
     `run_incremental_backup_idempotent_on_retry`.
  4. **`BackupSink` trait + ZK Object Fabric backup sink**
     (`crates/core/src/backup/sinks/{mod.rs,zk_fabric.rs}`):
     mirrors `MediaBlobSink` for the backup vault.
     `BackupSink` is object-safe with
     `upload_backup_segment` / `upload_backup_manifest` /
     `fetch_backup_manifest` / `fetch_backup_segment` /
     `list_backup_manifests`. `ZkofBackupSink` uses Pattern C
     convergent encryption from `crypto::convergent` and is
     bit-identical to the Go SDK at
     `kennguy3n/zk-object-fabric/encryption/client_sdk/`. S3
     key layout is `backups/{manifest_id}` for manifests and
     `backups/segments/{segment_id}` for segments. A
     `NoopBackupSink` is provided for tests. Tests:
     `zkof_backup_sink_upload_and_fetch_round_trip`,
     `pattern_c_convergent_encryption_produces_deterministic_output`,
     `backup_sink_trait_is_object_safe`.
  5. **`CoreImpl::compact_backup` orchestration**
     (`crates/core/src/core_impl.rs`): consumes
     `CompactionPolicy::plan` (`crates/core/src/backup/compaction.rs`)
     against the current wall-clock and walks each
     `CompactionGroup`: decrypts every source segment via
     `decrypt_backup_segment`, concatenates events, runs
     `apply_tombstones`, re-seals via
     `BackupSegmentBuilder::build_segment`, uploads the new
     segment, and emits a fresh manifest superseding the
     compacted ones. Returns a `BackupCompactionResult` with
     groups compacted / segments superseded / bytes saved.
     Tests:
     `compact_backup_merges_aged_daily_segments_into_weekly`,
     `compact_backup_noop_when_no_eligible_segments`,
     `compact_backup_applies_tombstones`.
  6. **Encrypted search-index shard backup / restore**
     (`crates/core/src/search/shard_builder.rs`):
     `build_text_search_shard` / `build_fuzzy_search_shard`
     read `search_fts` / `search_fuzzy_words` rows for a
     `(conversation_id, time_bucket)` pair, encode through
     `formats::SearchIndexShard` (`IndexType::Text` /
     `IndexType::Fuzzy`), zstd-compress, and AEAD-seal under
     `K_text_index_shard` / `K_fuzzy_index_shard` derived
     from `K_search_root`.
     `restore_text_search_shard` /
     `restore_fuzzy_search_shard` invert the path. Tests:
     `text_shard_build_and_restore_round_trip`,
     `fuzzy_shard_build_and_restore_round_trip`,
     `wrong_key_fails_shard_decrypt`,
     `multilingual_content_survives_shard_round_trip`.
  7. **Multilingual backup-restore corpus**
     (`crates/core/tests/backup_restore_multilingual.rs`):
     end-to-end integration test that ingests messages across
     8+ scripts (English, Russian / Cyrillic, Chinese / Han,
     Japanese / Hiragana+Katakana, Arabic, Thai, Hindi /
     Devanagari, mixed-script `"Meeting at 3pm 会議室で"`),
     runs `run_incremental_backup`, builds a 2-generation
     manifest chain, verifies the chain via
     `verify_manifest_chain`, runs `RestorePipeline::run`
     against a fresh in-memory store, and asserts every
     conversation / skeleton / body lands on the new device,
     FTS / fuzzy / structured filters return hits per script,
     and `RestoreState` reaches `FullRestoreComplete`.
     Soft-skips CJK / Thai FTS assertions on non-ICU builds
     (same pattern as `multilingual_search.rs`).
  8. **`storage_backend` routing in archive download /
     prefetch / rehydration**
     (`crates/core/src/archive/{download.rs,prefetch.rs}` +
     `crates/core/src/core_impl.rs`):
     `archive::download::ArchiveSegmentRouter` reads each
     `archive_segment_map.storage_backend` row and dispatches
     to either `TransportClient::fetch_archive_segment` (for
     `kchat_backend`) or the ZKOF `S3Client` adapter (for
     `zk_object_fabric`).
     `archive::prefetch::batch_prefetch_bucket_with_router`
     honors the per-row backend, and
     `CoreImpl::rehydrate_timeline_skeletons_with_router`
     propagates the routing through the scroll-back path.
     Tests:
     `fetch_segment_routes_to_transport_for_kchat_backend`,
     `fetch_segment_routes_to_s3_for_zkof_backend`,
     `prefetch_bucket_reads_storage_backend_per_row`.
  9. **Archive compaction at `CoreImpl` level**
     (`crates/core/src/archive/compaction.rs` +
     `crates/core/src/core_impl.rs`):
     `apply_archive_tombstones` mirrors the backup compaction
     helper for `ArchiveEvent` (drops `MessageDeleted` /
     `ConversationDeleted` events themselves and any earlier
     events for tombstoned ids, including orphan
     `MediaReceived`). `ArchiveCompactionResult` carries
     per-bucket counters
     (`buckets_inspected` / `buckets_compacted` /
     `segments_superseded` / `segments_emitted` /
     `bytes_before` / `bytes_after`).
     `CoreImpl::compact_archive(conversation_id, time_bucket,
     ...)` runs the five-phase flow: (A) `SELECT`
     `archive_verified` segments and prefetch ciphertexts via
     `ArchiveSegmentRouter`, (B) decrypt each, concatenate,
     track superseded ids, (C)
     `apply_archive_tombstones` and rebuild via
     `ArchiveSegmentBuilder::build_segment`, (D) emit through
     a caller-provided `commit_compact` callback, (E)
     SAVEPOINT-bounded UPDATE of every superseded row to
     `archive_compacted`. Tests:
     `compact_archive_merges_segments_for_same_bucket`,
     `compact_archive_applies_tombstones`,
     `compact_archive_transitions_old_segments_to_compacted`,
     `compact_archive_noop_for_single_segment`.
  10. **Key recovery foundation (recovery key + device-to-device
      transfer)**
      (`crates/core/src/restore/key_recovery.rs`):
      `RecoveryKey` is a 256-bit secret that AES-256-KW-wraps
      `K_user_master` (RFC 3394) and exposes a 64-char
      lowercase hex display for write-down during setup.
      `generate_recovery_key` / `recover_from_key` round-trip
      and reject wrong keys via the wrap integrity check
      value. `DeviceTransferPayload` is an
      XChaCha20-Poly1305-sealed bundle of
      (`K_user_master`, `K_archive_root`, `K_backup_root`,
      `K_search_root`) under a transfer key derived from a
      numeric / QR transfer code via HKDF-SHA-256 (info =
      `kchat-device-transfer-v1`). Server escrow remains OFF
      by default per `docs/PHASES.md §Phase 4`. Tests:
      `recovery_key_generate_and_recover_round_trip`,
      `recovery_key_wrong_key_fails`,
      `recovery_key_display_round_trip`,
      `recovery_key_display_rejects_bad_input`,
      `recovery_key_is_deterministic_for_same_master_and_recovery_key`,
      `device_transfer_round_trip`,
      `device_transfer_wrong_code_fails`,
      `device_transfer_empty_code_rejected`,
      `device_transfer_payload_length_validates`.

---

## Phase 5: Search — Fuzzy + Encrypted Shards

**Status**: `In progress | ~85%`

**Goal**: Fuzzy matching across scripts, plus encrypted search
shards on the backend so cold buckets remain searchable.

Checklist:

- [x] Fuzzy token index (trigrams for alphabetic scripts; bigrams
      for logographic CJK runs).
      (`crates/core/src/search/fuzzy_search.rs::FuzzyTokenizer`
      plus `search::tokenizer::{segment_by_script,
      detect_script, fuzzy_granularity}` pick trigrams vs
      bigrams; the `search_fuzzy(token, script, message_id)`
      table carries the ISO-15924 `script` column for
      script-keyed lookup. Multilingual coverage at
      `crates/core/tests/multilingual_fuzzy_search.rs`.)
- [x] Script-aware fuzzy matching with per-token script tag.
      (`FuzzySearchEngine::search_fuzzy` groups query tokens
      by `ScriptClass`, joins on `(token, script)`, and applies
      a per-script overlap floor via
      `search::tokenizer::fuzzy_min_overlap` — tighter for CJK
      bigrams, looser for Latin / Cyrillic trigrams. A row is
      accepted iff at least one script bucket clears its
      floor, so a mixed query like `"meeting 会議"` still fans
      out to both indexes. New regression test
      `crates/core/tests/mixed_language_query.rs`.)
- [x] Encrypted text / fuzzy shard archive
      (`K_text_index_shard`).
      (`crates/core/src/search/shard_builder.rs::{build_text_search_shard,
      build_fuzzy_search_shard, restore_text_search_shard,
      restore_fuzzy_search_shard}` round-trip text and fuzzy
      shards under per-shard keys derived from `K_search_root`.)
- [x] Search shard fetch
      (`GET /v1/archive/index-shards?conversation_hash=&bucket=&type=`).
      (`transport::TransportClient::fetch_index_shards` plus
      the `search::query_engine::ColdShardSource` trait wrap
      the network fetch + on-device decrypt; the trait is
      what unit tests use to inject mocks without spinning up
      a real transport.)
- [x] Cold-result hydration on tap.
      (`QueryEngine::execute_search_with_cold_source` is the
      Phase 5, Task 1 entry point: cold
      `(conversation_id, time_bucket)` pairs are resolved by
      the source, encrypted shards are fetched + decrypted,
      FTS5 + fuzzy run against the in-memory shard, and cold
      hits are merged with local hits and reranked under the
      shared formula. `CoreImpl::search_and_prefetch_cold`
      enqueues every cold hit at
      `HydrationReason::SearchResultTap` (P0) so the body /
      media chase the search hit. End-to-end coverage at
      `crates/core/tests/cold_shard_search.rs`.)
- [x] Unified query engine (parse → fan-out → merge → rerank).
      (`QueryEngine` segments the input via
      `segment_by_script`, fans out per-script to FTS + fuzzy
      + (optional) cold shards, merges by `message_id`, and
      reranks under the BM25 × fuzzy × recency × kind formula
      from `apply_recency_and_kind_weight`.)
- [x] Ranking formula implementation (PROPOSAL §7.5).
      (`BM25_WEIGHT = 2.0`, `FUZZY_WEIGHT = 1.0`,
      `RECENCY_WEIGHT = 0.5` (interpolation weight; asymptotic
      floor `1 - W = 0.5`), `RECENCY_HALF_LIFE_DAYS = 30`
      (`lambda = ln(2) / 30`), `CONTENT_KIND_WEIGHTS` boost
      text 1.0× and damp media 0.8×. In-module tests cover
      `ranking_recent_message_outranks_identical_old_message`,
      `ranking_exact_recent_beats_fuzzy_old`,
      `ranking_text_outranks_media_for_equal_recency`, and
      `ranking_is_deterministic_for_same_inputs`.)
- [x] Mixed-language query handling.
      (`segment_by_script` decomposes a single query into
      per-script segments; each segment fans out to FTS5 and
      its script-specific fuzzy index. Regression coverage at
      `crates/core/tests/mixed_language_query.rs` exercises
      Latin × CJK, Cyrillic × Latin, pure-CJK on non-ICU
      builds via fuzzy fallback, mixed-script promotion, and
      unrelated-row exclusion.)
- [~] Latency budget: encrypted shard fetch + decrypt + local
      search ≤ 1.5 s p95 over Wi-Fi for a one-month bucket.
      (criterion bench at
      `crates/core/benches/phase5_benchmarks.rs` measures
      `text_only_one_month`, `fuzzy_only_one_month`, and
      `local_plus_one_cold_bucket` against a delayed
      `ColdShardSource` that simulates a network hop. The
      smoke test
      `crates/core/tests/phase5_latency_smoke.rs` asserts the
      cold-shard decrypt+search path completes well under
      5 s on debug-build CI. The on-device p95 ≤ 1.5 s gate
      lands with the Phase-5 device-matrix run.)
- [x] Batch shard prefetch by time bucket: when fetching encrypted
      index shards, fetch all shard types for the target
      `(conversation_hash, bucket)` in one batch to coarsen the
      metadata signal on the shard-listing endpoint.
      (`crates/core/src/search/shard_prefetch.rs::batch_prefetch_shards`
      fans out a single call per `IndexType` variant in
      deterministic `[Text, Fuzzy, Vector, Media]` order and
      returns `Vec<PrefetchedShard>` with non-empty rows only.
      `batch_prefetch_shards_with_padding` mixes in dummy
      `(conversation_hash, bucket)` requests when
      `KChatCoreConfig::privacy_level == High`, reusing the
      `archive::privacy` helpers so dummy ids do not collide
      with real UUIDv7 segments.)

**Decision gate**: Fuzzy search returns relevant hits across all
target scripts, including mixed-script queries. Cold (offloaded)
content is searchable via encrypted-shard fetch + on-device
decrypt — query strings never reach the backend.

Notes:

- 2026-05-03: Phase 5 advanced from `~15%` to `~85%`. Tasks 1–5
  of the 10-task batch landed end-to-end: encrypted-shard fetch
  via the `ColdShardSource` trait
  (`crates/core/src/search/query_engine.rs`), recency × kind
  ranking (`apply_recency_and_kind_weight`), per-script edit
  thresholds (`fuzzy_min_overlap`), mixed-language fan-out via
  `segment_by_script`, and the criterion benchmark suite at
  `crates/core/benches/phase5_benchmarks.rs` plus a CI smoke
  test at `crates/core/tests/phase5_latency_smoke.rs`. The only
  open item is the on-device ≤ 1.5 s p95 measurement, which
  belongs to the Phase-5 device-matrix run.

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
- [ ] Whisper multilingual transcription: Apple MLX
      (`mlx-community/whisper-base-mlx`) on Apple Silicon
      (preferred — Neural Engine, lower latency / battery cost);
      ONNX Runtime (`whisper-base` ~140 MB INT8) on all other
      platforms (Intel macOS, Windows, Android, Linux);
      `whisper-tiny` (~75 MB) on low-end Android. See PROPOSAL
      §7.6 / §7.7.
- [ ] Platform OCR bridge (Vision on iOS / macOS; ML Kit on
      Android; `Windows.Media.Ocr` / Tesseract on Windows).
- [ ] Document text extraction (PDF, DOCX) with page-level indexing.
- [ ] Resource-gated background processing (battery, thermal,
      charging, network).
- [ ] Model manager: lazy download on first semantic-search use
      (MobileCLIP-S2, Whisper) or eager pre-load (XLM-R),
      versioning, INT8/INT4 quantization, integrity-checked
      artifacts, warm-up strategy.
- [ ] Encrypted vector / media shard archive.
- [ ] On-device reranking with semantic scores.
- [ ] Desktop support: macOS (Core ML), Windows (DirectML EP
      preferred, CPU EP fallback).
- [ ] Cross-pipeline embedding cache: reuse `XLM-R` embeddings from
      `kennguy3n/slm-guardrail` in the search pipeline
      (`(message_id, model_version)` keyed `search_vector` row;
      version-mismatch invalidates). See PROPOSAL §7.6.1.
- [ ] INT4 quantization for `XLM-R` and `MobileCLIP-S2` via ONNX
      Runtime `MatMulNBits`; benchmark accuracy vs INT8 with the
      multilingual relevance regression suite.

**Decision gate**: Semantic search returns relevant multilingual
results across text, images, video, and audio on iOS, Android,
macOS, and CPU-only Windows. Cross-platform parity is verified by
Phase 0 test vectors plus a multilingual relevance regression
suite.

Notes:

- _(none yet)_

---

## Phase 7: Desktop + Optimization

**Status**: `In progress | ~20%`

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
- [x] Production-scale archive compaction.
      (`archive::compaction::{apply_archive_tombstones,
      ArchiveCompactionResult}` + `CoreImpl::compact_archive`:
      selects `archive_verified` segments for a
      `(conversation_id, time_bucket)`, decrypts via the
      `ArchiveSegmentRouter`, applies tombstones, re-seals into
      one compact segment via `ArchiveSegmentBuilder`, and
      SAVEPOINT-transitions every superseded row to
      `archive_compacted`. Cross-epoch coverage at
      `crates/core/tests/archive_pipeline.rs::archive_pipeline_epoch_rotation_and_cross_epoch_compaction`.)
- [ ] Cross-platform media migration: iOS → Android migrates
      iCloud media blobs to Google Drive (or ZKOF fallback) in the
      background.
- [ ] Media blob sink stress test: 10K+ media files across mixed
      sinks, verify rehydration from each.
- [~] **Failure test suite**, 7 of 8 passing
      (`crates/core/tests/failure_scenarios.rs`):
      - [x] chunk upload interrupted
            (`chunk_upload_interrupted_then_resumed_succeeds`)
      - [ ] manifest upload interrupted
            _(queued — the upload path lives at
            `archive::upload::upload_archive_segment` /
            `CoreImpl::run_incremental_backup_inner`, and a
            dedicated mid-write interruption test is still
            pending.)_
      - [x] wrong backup key
            (`wrong_backup_segment_key_fails_aead_open`,
            `wrong_signing_key_on_manifest_chain_fails_signature_invalid`)
      - [x] corrupted chunk (Merkle / SHA-256 mismatch)
            (`corrupted_chunk_ciphertext_fails_sha256_fast_fail`,
            `tampered_merkle_root_in_descriptor_fails_blake3_root_check`)
      - [x] device removed from MLS group between backup and
            restore
            (`device_removed_from_mls_group_between_backup_and_restore_surfaces_signature_invalid`)
      - [x] search shard missing from backend
            (`search_shard_missing_from_backend_degrades_to_local_only_with_warning_flag`)
      - [x] low storage during restore
            (`low_storage_condition_during_restore_surfaces_resumable_storage_error`)
      - [x] manifest chain break detected on restore
            (`manifest_chain_break_returns_chain_break_with_expected_and_actual`,
            plus the deepest-link variant
            `manifest_chain_break_at_deepest_generation_reports_correct_link`)

**Decision gate**: Production-ready performance on the target
device matrix. Full failure test suite passes on every platform.

Notes:

- 2026-05-03: Status moves from `NOT STARTED` to
  `In progress | ~20%`. Production-scale archive compaction
  and 7 of 8 failure scenarios are now in tree (Tasks 6–9 of
  the 10-task batch); the remaining failure scenario is
  `manifest upload interrupted mid-write`, and the rest of
  the phase (desktop integration, ML EP tuning, large-scale
  testing) is unchanged.

---

## Changelog

### 2026-05-04 — Phase 3 / 5 / 7 wrap-up batch (this PR)

Builds on PR #30 + #31 (the previous 10-task batches). Drives
Phase 5 from `~85%` to `~92%` by wiring a concrete
`TransportColdShardSource` adapter on top of the `ColdShardSource`
trait, exposing a `MockTransportClient` from the public transport
module, growing the `TransportClient` trait with a default-impl
`upload_index_shard(...)` method, and landing the encrypted
search-shard upload pipeline as `CoreImpl::upload_search_shards`.
Drives Phase 7 from `~20%` to `~25%` by adding the
`manifest_upload_interrupted_mid_write` failure scenario to
`tests/failure_scenarios.rs`. Drives Phase 3 from `~95%` to
`~96%` by adding round-trip tests for the
`SegmentType::TimelineSkeleton` + `SegmentType::Checkpoint`
variants of `ArchiveSegmentBuilder::build_segment`, plus a
regression test that the builder rejects backup-only segment
types up front. All changes ship with unit + integration tests;
`cargo test --workspace` passes, `cargo fmt --all -- --check` is
clean, and `cargo clippy --all-targets --all-features -- -D
warnings` is clean.

1. **Cold-result hydration adapter — `TransportColdShardSource`**
   (`crates/core/src/search/cold_shard_source.rs` *new*,
   `crates/core/src/search/mod.rs`,
   `crates/core/src/search/shard_builder.rs`):
   The orchestration layer can now wire a `TransportClient` and
   a `ShardKeyRegistry` directly into `QueryEngine` via the
   adapter, which translates a plaintext `conversation_id` into
   the keyed `conversation_id_hash`, calls
   `TransportClient::fetch_index_shards`, and decrypts the
   returned shard back into `Vec<FtsRow>` / `Vec<FuzzyRow>`. A
   `GracefulCold` wrapper swallows transport / storage errors so
   the engine can fall back to local results without a panic
   (Phase-7 graceful-degradation requirement). Five
   self-contained tests cover the round-trip, missing-shard, and
   missing-key paths.

2. **Encrypted shard upload pipeline — `CoreImpl::upload_search_shards`**
   (`crates/core/src/core_impl.rs`):
   New orchestration entry point that takes
   `(conversation_id, time_bucket, fts_rows, fuzzy_rows, k_text,
   k_fuzzy, conversation_hash_key)`, builds + seals each shard
   with the existing `build_text_search_shard` /
   `build_fuzzy_search_shard` helpers, CBOR-encodes the
   `SearchIndexShard` frame, and ferries it to the configured
   `TransportClient::upload_index_shard`. Returns an
   `UploadedSearchShards` receipt with per-shard
   `(shard_id, doc_count, ciphertext_len, ciphertext_sha256)` so
   callers can record the upload in their own `search_shard_map`
   ledger. Three tests cover the round-trip via
   `MockTransportClient`, the empty-bucket short-circuit, and
   transport-failure propagation + retry.

3. **`TransportClient` trait — `upload_index_shard` + public `MockTransportClient`**
   (`crates/core/src/transport/mod.rs`):
   New default-impl `upload_index_shard(conversation_hash,
   bucket, shard_type, ciphertext)` method returning
   `Error::NotImplemented("transport_upload_index_shard")` so
   existing implementations stay source-compatible. The
   `MockTransportClient` test double has graduated from
   `#[cfg(test)]` to a regular public type so integration tests
   in other crates can pre-stage / fail-inject shard responses
   without re-implementing the harness. Cross-wires successful
   uploads into the fetch path so round-trip tests can stay
   inside one transport instance.

4. **Phase-7 failure test — `manifest_upload_interrupted_mid_write`**
   (`crates/core/tests/failure_scenarios.rs`):
   New failure scenario covering the orchestration-layer mode
   where `BackupSink::upload_backup_manifest` fails with a
   transient `Error::Transport` part-way through the write. The
   test asserts the error variant, retries the upload against a
   healthy sink, verifies the retry uploaded byte-for-byte
   identical bytes, and re-runs `verify_manifest_chain` to prove
   the chain integrity is intact (no duplicate generation, no
   chain break).

5. **Phase-3 archive segment builder — `TimelineSkeleton` +
   `Checkpoint` round-trip + reject-backup-variant tests**
   (`crates/core/src/archive/segment_builder.rs`):
   Three new tests exercising
   `SegmentBuildRequest { segment_type:
   SegmentType::TimelineSkeleton, .. }` /
   `Checkpoint` round-trips through
   `decrypt_segment`, asserting that `BuiltSegment::segment_type`
   echoes the request rather than silently falling back to
   `MessageDelta` (regression for the doc-comment fix in PR #31),
   and a regression test that `build_segment(...)` rejects
   `SegmentType::Events` (backup-only variant) up front via the
   `is_archive_segment()` guard.

### 2026-05-03 — Phase 3 / 5 / 7 batch of 10 (this PR)

Builds on PR #30 (the previous 10-task batch). Drives Phase 5 from
`~15%` to `~85%` (cold-shard fan-out via `ColdShardSource`,
recency + content-kind ranking, script-aware fuzzy matching with
per-script overlap floors, mixed-language fan-out, criterion
benchmarks for the cold-shard latency budget), adds the remaining
4 of 8 Phase-7 failure scenarios, extends the archive segment
builder with `TimelineSkeleton` + `Checkpoint` variants, lands an
end-to-end passphrase-recovery integration test, wires a
cross-epoch archive-compaction integration test, and reconciles
the documentation against the actual source so PHASES.md and
PROGRESS.md no longer carry stale `[ ]` items. All ten tasks ship
with unit + integration tests; `cargo test --workspace` passes
(1 023 tests total), `cargo fmt --all -- --check` is clean, and
`cargo clippy --all-targets --all-features -- -D warnings` is
clean.

1. **Cold-bucket shard fetch wired into `QueryEngine`**
   (`crates/core/src/search/query_engine.rs`,
   `crates/core/src/core_impl.rs`, new
   `crates/core/tests/cold_shard_search.rs`):
   `QueryEngine::execute_search_with_cold_source` accepts a
   `ColdShardSource` trait object that returns the cold
   `(conversation_id, time_bucket)` pairs and decrypts the
   encrypted shards in-process. Cold hits are merged with the
   local hits, marked `is_cold = true`, and reranked under the
   shared formula. Three integration tests cover the
   round-trip, `SearchScope::LocalOnly` skipping the fan-out,
   and per-conversation scoping. `CoreImpl::search_and_prefetch_cold`
   wires the trait through to the live transport while keeping
   the unit-test path mockable.

2. **Script-aware fuzzy matching**
   (`crates/core/src/search/fuzzy_search.rs`,
   `crates/core/src/search/tokenizer.rs`):
   `FuzzySearchEngine::search_fuzzy` groups query tokens by
   `ScriptClass`, joins on the existing
   `search_fuzzy(token, script, message_id)` table, and
   applies a per-script overlap floor via
   `search::tokenizer::fuzzy_min_overlap` (tighter for CJK
   bigrams, looser for Latin / Cyrillic trigrams). A row is
   accepted iff at least one script bucket clears its floor,
   so a mixed query like `"meeting 会議"` still fans out to
   both indexes. Existing `multilingual_fuzzy_search.rs` tests
   keep passing; new coverage at
   `crates/core/tests/mixed_language_query.rs`.

3. **Full ranking formula (recency decay × content-kind
   weight)** (`crates/core/src/search/query_engine.rs`):
   adds `RECENCY_WEIGHT = 0.5` (linear-interpolation weight;
   asymptotic floor `1 - W = 0.5`),
   `RECENCY_HALF_LIFE_DAYS = 30` (`lambda = ln(2) / 30`),
   and `CONTENT_KIND_WEIGHTS` (text 1.0×, media 0.8×) on top
   of the existing `BM25_WEIGHT = 2.0` / `FUZZY_WEIGHT = 1.0`.
   The decay computes
   `recency_factor = (1 - W) + W × exp(-λ × age_days)`, so a
   message authored today scores 1.0, a 30-day-old message
   0.75, and any sufficiently-old message asymptotically
   approaches the 0.5 floor.
   `apply_recency_and_kind_weight` applies the multiplicative
   combination so a recent text hit always outranks an
   identical older one and an exact + recent hit always
   outranks a fuzzy + old hit. Four new ranking tests
   (`ranking_recent_message_outranks_identical_old_message`,
   `ranking_exact_recent_beats_fuzzy_old`,
   `ranking_text_outranks_media_for_equal_recency`,
   `ranking_is_deterministic_for_same_inputs`) cover the
   formula; `apply_cold_recency_weight` reuses the same decay
   for the cold-merge path.

4. **Mixed-language query fan-out**
   (`crates/core/src/search/query_engine.rs`,
   `crates/core/src/search/tokenizer.rs`, new
   `crates/core/tests/mixed_language_query.rs`):
   `QueryEngine` segments the input via `segment_by_script`
   and fans out per-script to FTS5 + the script-specific
   fuzzy index; results from every segment are merged by
   `message_id` and reranked. New regression coverage:
   Latin × CJK (`"meeting 会議室"` finds
   `"Meeting at 3pm 会議室で"`), Cyrillic × Latin
   (`"встреча meeting"` finds rows in either language),
   pure-CJK on non-ICU builds via fuzzy fallback,
   mixed-script promotion (a dual-script row outranks
   single-script rows), and unrelated-row exclusion.

5. **Phase 5 latency benchmarks + smoke test**
   (`crates/core/Cargo.toml`, new
   `crates/core/benches/phase5_benchmarks.rs`,
   `crates/core/tests/phase5_latency_smoke.rs`):
   adds three criterion benchmarks —
   `text_only_one_month`, `fuzzy_only_one_month`, and
   `local_plus_one_cold_bucket` (the last one drives a
   `DelayedCatalog` `ColdShardSource` that simulates a
   network hop) — plus a CI-friendly `#[test]` that asserts
   the cold-shard decrypt+search path completes in under
   5 s on debug builds. Run with
   `cargo bench -p kchat-core --bench phase5_benchmarks`.
   The on-device p95 ≤ 1.5 s gate moves to the Phase-5
   device-matrix run.

6. **Archive segment builder — `TimelineSkeleton` +
   `Checkpoint` variants**
   (`crates/core/src/archive/segment_builder.rs`,
   `crates/core/src/formats/mod.rs`):
   `SegmentBuildRequest` gains `timeline_skeleton(...)` and
   `checkpoint(...)` constructors alongside the existing
   `message_delta(...)`. All three share the CBOR → zstd →
   XChaCha20-Poly1305 pipeline keyed off `SegmentType` so
   the on-disk frame type is preserved through a round-trip.
   Round-trip tests live alongside the builder; a new
   integration test in `crates/core/tests/archive_pipeline.rs`
   exercises a `TimelineSkeleton` segment build.

7. **Phase-7 failure suite — remaining 4 of 8 scenarios**
   (`crates/core/tests/failure_scenarios.rs`): adds
   `device_removed_from_mls_group_between_backup_and_restore_surfaces_signature_invalid`
   (manifest signed by an MLS-removed device, asserts
   `VerificationError::SignatureInvalid` rather than a
   panic),
   `search_shard_missing_from_backend_degrades_to_local_only_with_warning_flag`
   (wraps a `ColdShardSource` whose fetch returns 404 in a
   `GracefulCold` adapter, asserts the query engine falls back
   to local-only results, and records the failed bucket in a
   side-channel log for the orchestration layer to surface as a
   banner),
   `low_storage_condition_during_restore_surfaces_resumable_storage_error`
   (injects a disk-full error during `RestorePipeline::run`,
   asserts the pipeline persists the last
   `RestoreState` and returns a resumable
   `Error::Storage`), and a deepest-link variant
   `manifest_chain_break_at_deepest_generation_reports_correct_link`.
   The full failure suite is now 7 of 8 green; the
   outstanding scenario is `manifest upload interrupted
   mid-write`.

8. **End-to-end passphrase recovery integration test**
   (`crates/core/tests/backup_pipeline.rs`):
   `passphrase_recovery_end_to_end_round_trip_across_three_scripts`
   walks `K_user_master` →
   `wrap_master_key_with_passphrase` → 3-script ingest
   (Latin, CJK, Arabic) → `run_incremental_backup` →
   2-generation manifest chain → search-shard build →
   fresh in-memory destination device →
   `unwrap_master_key_with_passphrase` →
   `verify_manifest_chain` → `RestorePipeline::run` →
   FTS + fuzzy search hit assertions per script. Negative
   coverage for wrong passphrase (`Error::Crypto`) and the
   PR #30 trim regression (whitespace-padded passphrase
   still unwraps).

9. **Epoch key rotation + cross-epoch archive compaction
   integration test** (`crates/core/tests/archive_pipeline.rs`):
   `archive_pipeline_epoch_rotation_and_cross_epoch_compaction`
   creates an `EpochKeyManager` at `"2026-01"`, builds an
   archive segment, rotates to `"2026-02"`, builds a second
   segment, runs `CoreImpl::compact_archive` over a bucket
   that spans both epochs, and asserts: (a) the compacted
   segment decrypts under the current epoch key,
   (b) `wrapped_prior_epoch_keys_for_manifest()` carries the
   prior epoch's wrapped key in the manifest chain,
   (c) `unwrap_prior_epoch_key("2026-01", K_archive_root)`
   plus a fresh segment-key derivation re-decrypts the
   pre-rotation segment, and (d) `delete_epoch_key("2026-01")`
   makes the prior segment undecryptable
   (`Error::Storage` on the unwrap attempt). This is the
   cross-epoch decision-gate test for Phase 3.

10. **Documentation reconciliation** (this PR only — no
    runtime code change):
    PHASES.md, PROGRESS.md, README.md, and ARCHITECTURE.md
    were audited against the actual source / tests / benches
    rather than the existing checkbox state. Stale `[ ]`
    items in Phases 1, 2, and 3 (SQLCipher, ICU FTS5,
    multilingual test corpus, body / archive / media state
    machines, MediaBlobSink trait, archive manifest chain,
    Merkle-root verification, archive state machine, storage
    budget enforcement, eviction scoring, batch-by-bucket
    prefetch, epoch-rotated archive key derivation) are now
    `[x]` with line-anchored notes; Phase 5 is checked off
    everywhere except the on-device latency gate; Phase 7
    archive compaction at production scale + 7 of 8 failure
    scenarios are checked off. The README banner and tree
    move to the new state and the `cargo bench` quick-start
    references the Phase-5 bench file.

### 2026-05-03 — Phase 3 / 4 / 5 / 7 batch of 10 (PR #30)

Lands the previous 10-task batch on top of PR #29 (`ba706825`).
Closes the remaining Phase-3 ZKOF archive plumbing, finishes the
Phase-4 backup sinks (iCloud, Android), introduces passphrase-based
key recovery, wires the Phase-4 search-index shard restore path,
and opens Phase 5 (cold-result hydration, batch shard prefetch)
plus the Phase-5/7 scheduler foundation and the first 4 of the 8
Phase-7 failure scenarios. All ten tasks ship with unit +
integration tests; `cargo test --workspace` passed (981 tests
total), `cargo fmt --all -- --check` was clean, and
`cargo clippy --all-targets --all-features -- -D warnings` was
clean.

1. **DeviceTransferEnvelope zeroize fix**
   (`crates/core/src/restore/key_recovery.rs`):
   `DeviceTransferEnvelope` now derives
   `#[derive(Zeroize, ZeroizeOnDrop)]`. `prepare_device_transfer`
   wraps the CBOR plaintext in `Zeroizing::new(...)` and
   `accept_device_transfer` wraps the AEAD-opened plaintext in
   `Zeroizing::new(aead_open(...)?)`. New compile-time test
   `device_transfer_envelope_implements_zeroize_on_drop` asserts
   the trait bound. Closes the Devin Review finding on PR #29.

2. **ZKOF S3 archive transport adapter**
   (`crates/core/src/archive/routing.rs`,
   `crates/core/src/core_impl.rs`): the `ZkofArchiveAdapter`
   stops returning `NotImplemented` and instead drives a real
   `Arc<dyn S3Client>`. Segment uploads land at
   `archive/segments/{segment_id}` and manifest uploads at
   `archive/manifests/{manifest_id}`, matching the layout of
   `backup/sinks/zk_fabric.rs`. `CoreImpl` carries
   `zkof_archive_config` / `zkof_archive_s3` slots and exposes
   `install_zkof_archive_backend(s3, config)`;
   `rehydrate_timeline_skeletons_with_router` dispatches on
   `KChatCoreConfig::archive_backend == Zkof`. New integration
   tests upload → fetch → decrypt round-trip a sealed segment
   through `InMemoryS3`.

3. **iCloud backup sink**
   (`crates/core/src/backup/sinks/icloud.rs`): mirrors
   `media::sinks::icloud`. `ICloudBackupBridge` (object-safe,
   `Send + Sync`) exposes `upload_file` / `download_file` /
   `list_files` / `delete_file`. `ICloudBackupSink` maps
   `segment_id` → `backups/segments/{segment_id}` and
   `manifest_id` → `backups/{manifest_id}` records and
   implements `BackupSink::{upload_backup_segment,
   upload_backup_manifest, fetch_backup_manifest,
   fetch_backup_segment, list_backup_manifests}`.
   `NoopICloudBackupBridge` returns
   `Error::NotImplemented("icloud_backup_bridge")`. 5 unit tests
   (object safety, round-trip, list filtering, error
   propagation, delete idempotency).

4. **Android backup sink**
   (`crates/core/src/backup/sinks/android.rs`):
   `AndroidBackupBridge` splits manifest envelopes
   (`write_auto_backup` / `read_auto_backup` — Auto Backup
   ≤ 25 MiB record cap) from full segment data
   (`write_saf` / `read_saf` / `list_saf` — Storage Access
   Framework, no size cap). `AndroidBackupSink::list_backup_manifests`
   filters Auto Backup entries to manifests-only.
   `NoopAndroidBackupBridge` stub. 5 unit tests matching the
   iCloud sink coverage.

5. **Passphrase-based key recovery**
   (`crates/core/src/restore/key_recovery.rs`,
   `crates/core/Cargo.toml`): adds the `argon2 = "0.5"`
   dependency with the `alloc` feature. New
   `derive_passphrase_key(passphrase, salt)` runs Argon2id with
   OWASP mobile parameters (`m_cost = 65536`, `t_cost = 3`,
   `p_cost = 1`, output 32 bytes). `wrap_master_key_with_passphrase`
   generates a 16-byte salt, derives the wrapping key, and
   AES-256-KW wraps `K_user_master` into a
   `PassphraseRecoveryEnvelope { salt, wrapped_key,
   argon2_params }` (serde + zeroize aware).
   `unwrap_master_key_with_passphrase` returns
   `Zeroizing<[u8; 32]>` and surfaces wrong-passphrase /
   tampered-envelope failures via the AES-KW integrity check.
   6 tests cover round-trip, wrong-passphrase, deterministic
   derivation for the same `(passphrase, salt)`, different
   salts → different keys, empty-passphrase rejection, and
   serde round-trip of the envelope.

6. **Search shard restore wired into RestorePipeline**
   (`crates/core/src/restore/pipeline.rs`,
   `crates/core/tests/backup_pipeline.rs`):
   `restore_search_index_shards_with_replay` accepts
   `SealedSearchShardEntry<'_>` (sealed shard ⊕ per-shard key)
   and dispatches to `restore_text_search_shard` /
   `restore_fuzzy_search_shard` based on the shard's
   `IndexType`, replaying every entry into local `search_fts`
   and `search_fuzzy` while the state machine advances through
   `RestoreState::SearchIndexShardsRestored`. Returns
   `RestoredShardSummary { shards, fts_rows, fuzzy_rows }` for
   progress reporting. New integration test
   `search_shards_round_trip_through_pipeline` builds text +
   fuzzy shards, replays them, and asserts FTS / fuzzy queries
   return the restored content.

7. **Cold-result hydration in search query engine**
   (`crates/core/src/search/query_engine.rs`,
   `crates/core/src/core_impl.rs`): when the caller passes
   `SearchScope::IncludeCold`, `mark_cold_results` joins
   `message_skeleton.body_state` and flips `is_cold = true` on
   any hit whose body lives in the archive
   (`body_state = 'remote_archive_only'`). `CoreImpl::search`
   enqueues every cold result into the `HydrationQueue` at
   `HydrationReason::SearchResultTap` (P0) priority, and a new
   `CoreImpl::search_and_prefetch_cold` returns
   `(results, cold_count)` so the platform layer can render a
   "hydrating…" badge. 3 query-engine tests cover the offloaded
   → cold marking, `LocalOnly` never marks cold, and structured
   filters ⊕ cold marking.

8. **Batch shard prefetch by time bucket**
   (`crates/core/src/search/shard_prefetch.rs`,
   `crates/core/src/search/mod.rs`):
   `batch_prefetch_shards(transport, conversation_hash,
   bucket)` fans out a single transport call per `IndexType`
   variant in the deterministic
   `[Text, Fuzzy, Vector, Media]` order and returns
   `Vec<PrefetchedShard>` with non-empty rows only.
   `batch_prefetch_shards_with_padding` mixes in dummy
   `(conversation_hash, bucket)` requests when
   `KChatCoreConfig::privacy_level == High`, reusing
   `archive::privacy::generate_dummy_segment_id` so dummy
   conversation hashes never collide with real ones. 6 unit
   tests with a `RecordingTransport` mock cover seeded shards,
   skipped empty responses, empty buckets, padding-disabled
   call ordering, padding-enabled dummy interleave, and dummy
   call distinctness.

9. **Scheduler module foundation**
   (`crates/core/src/scheduler/mod.rs`,
   `crates/core/src/core_impl.rs`): replaces the 4-line
   placeholder with a full Phase-5/7 scheduler surface.
   `BackgroundScheduler` (object-safe, `Send + Sync`) declares
   `schedule_backup` / `schedule_archive_compaction` /
   `schedule_index_maintenance` / `cancel_all` /
   `is_task_pending`. `ScheduledTask { task_id, task_type,
   interval_ms, last_run_ms, next_run_ms }` describes one
   task; `TaskType` enumerates `IncrementalBackup`,
   `ArchiveCompaction`, `IndexMaintenance`,
   `MediaCacheEviction`, `ModelWarmup` (snake-case serde).
   `NoopScheduler` returns `Error::NotImplemented("scheduler")`
   for every method. Platform bridges
   (`IosBgTaskBridge` for `BGTaskScheduler`,
   `AndroidWorkManagerBridge` for `WorkManager`) and matching
   `Noop*` stubs sit alongside.
   `CoreImpl::install_scheduler` / `has_scheduler` install /
   probe the bridge. 10 unit tests cover trait object safety,
   `Noop*` returns, `TaskType` and `ScheduledTask` serde
   round-trip, default `task_id` namespace, and
   `next_run_ms = now + interval`.

10. **Phase-7 failure-scenario suite (4 of 8)**
    (`crates/core/tests/failure_scenarios.rs`): each test is
    self-contained, uses an in-memory store / mock transport,
    and asserts a specific error variant.
    • `chunk_upload_interrupted_then_resumed_succeeds` drives a
      `MockTransportClient` that returns
      `Error::Transport("connection reset")` after 2 of 5
      chunks, asserts `upload_chunked_media` surfaces the
      transport error, then resumes via `resume_upload` with a
      seeded `UploadState` and asserts only chunks 2/3/4 are
      pushed and the post-commit BLAKE3 root matches.
    • `corrupted_chunk_ciphertext_fails_sha256_fast_fail` flips
      one byte of `sealed_chunks[1].ciphertext`, asserts
      `verify_and_decrypt` fails with the SHA-256 fast-fail
      message naming chunk 1 (no AEAD work runs);
      `tampered_merkle_root_in_descriptor_fails_blake3_root_check`
      tampers with the descriptor's `merkle_root` and asserts
      the AEAD AAD binding rejects it.
    • `wrong_backup_segment_key_fails_aead_open` builds a
      sealed segment, decrypts with the right key (sanity), and
      asserts a bit-flipped `K_backup_segment` produces
      `Error::Crypto`. `wrong_signing_key_on_manifest_chain_fails_signature_invalid`
      verifies a chain under an imposter Ed25519 key and asserts
      `VerificationError::SignatureInvalid { generation: 0 }`.
    • `manifest_chain_break_returns_chain_break_with_expected_and_actual`
      builds a 3-generation chain, replaces gen-1's
      `previous_manifest_hash` with garbage, re-signs gen-1 and
      gen-2 (so signatures are valid — only the chain link
      breaks), and asserts `verify_manifest_chain` returns
      `VerificationError::ChainBreak { generation: 1, expected,
      actual }` with `expected == compute_manifest_hash(gen0)`
      and `actual == [0x42; 32]`.

Status moves: Phase 3 → `In progress | ~95%`; Phase 4 →
`In progress | ~85%`; Phase 5 → `In progress | ~15%` (was
`NOT STARTED`).

### 2026-05-03 — Phase-3 / Phase-4 batch of 10 (PR #29)

Lands the next batch on top of PRs #27 and #28. Closes the Phase-3
`storage_backend` plumbing, finishes the Phase-4 backup pipeline
(incremental backup, ZK Object Fabric sink, compaction), and lays
down the Phase-4 restore-side machinery (search shards,
multilingual corpus, key recovery, archive compaction). All ten
tasks ship with unit + integration tests and a clean
`cargo test --workspace` (921 tests passing) +
`cargo fmt --check` + `cargo clippy --all-targets --all-features
-- -D warnings`.

1. **Text+media skeleton `media_state` consistency**
   (`message::processor`): when an `IngestedMessage` carries both
   `text_content` and `media_descriptors`, the skeleton now
   resolves `kind = MessageKind::Media` and
   `media_state = Some(ThumbnailOnly)` so the row matches the
   `media_asset` writes. New regression test
   `persist_text_plus_media_message_sets_media_state_on_skeleton`.
2. **Three-phase media rehydration** (`core_impl::rehydrate_media_for_message`):
   the db mutex is now released between (Phase 1) reading the
   `media_asset` row + planning, (Phase 2) downloading +
   verifying the BLAKE3 root, and (Phase 3) committing
   `media_state = original_local`. `media::download` exposes
   `prepare_rehydration` / `execute_rehydration_download` /
   `commit_rehydration` for the new shape; existing single-call
   tests still pass.
3. **`CoreImpl::run_incremental_backup` end-to-end**: replaces
   the `Error::NotImplemented` stub. Reads
   `BackupEventJournal::read_unsegmented` → derives
   `K_backup_segment` via `derive_backup_segment` → builds via
   `BackupSegmentBuilder::build_segment` → builds + signs the
   manifest via `build_backup_manifest` → advances the cursor.
   Returns a populated `BackupResult` and is idempotent on a
   second call without new events.
4. **ZK Object Fabric backup sink with Pattern C**
   (`backup::sinks::zk_fabric`): `BackupSink` trait
   (`upload_backup_segment`, `upload_backup_manifest`,
   `fetch_backup_manifest`, `fetch_backup_segment`,
   `list_backup_manifests`); `ZkofBackupSink` implementation
   wires Pattern C convergent encryption from
   `crypto::convergent::derive_convergent_dek` so the Rust
   ciphertext matches the Go SDK at
   `kennguy3n/zk-object-fabric/encryption/client_sdk/`.
   `NoopBackupSink` for tests; `Box<dyn BackupSink>` is object
   safe.
5. **`CoreImpl::compact_backup`**: drives `CompactionPolicy::plan`
   over the local backup-segment ledger, decrypts each source
   segment, concatenates events, runs `apply_tombstones`,
   re-seals via `BackupSegmentBuilder::build_segment`, and
   returns a `BackupCompactionResult` summarising groups
   compacted / segments superseded / bytes saved. New
   integration tests cover the daily → weekly merge and the
   tombstone application.
6. **Encrypted search-index shard build/restore**
   (`search::shard_builder`): `build_text_search_shard` /
   `build_fuzzy_search_shard` read `search_fts` /
   `search_fuzzy_words` for `(conversation_id, time_bucket)`,
   encode via `formats::SearchIndexShard`, and AEAD-seal under
   per-(account, conversation, bucket, kind)-derived shard
   keys. `restore_text_search_shard` /
   `restore_fuzzy_search_shard` invert. Tests cover round-trip,
   wrong-key, and multilingual content (Latin / CJK / Arabic).
7. **Multilingual backup-restore corpus integration test**
   (`crates/core/tests/backup_restore_multilingual.rs`):
   end-to-end test that ingests 8+ scripts (English, Russian,
   Chinese, Japanese, Arabic, Thai, Hindi, mixed Latin+CJK),
   drives `run_incremental_backup` to produce sealed segments,
   builds a 2-generation manifest chain, runs
   `verify_manifest_chain` and `RestorePipeline::run` against
   a fresh in-memory store, and asserts every conversation /
   skeleton / body lands with FTS / fuzzy / structured filters
   intact. Soft-skips CJK / Thai FTS assertions on non-ICU
   builds.
8. **Storage-backend routing in archive download / prefetch /
   rehydration** (`archive::download::ArchiveSegmentRouter`,
   `archive::prefetch::batch_prefetch_bucket_with_router`,
   `CoreImpl::rehydrate_timeline_skeletons_with_router`): the
   `archive_segment_map.storage_backend` column finally drives
   per-row routing — `kchat_backend` → `TransportClient`,
   `zk_object_fabric` → `S3Client` adapter. Tests cover
   `fetch_segment_routes_to_transport_for_kchat_backend`,
   `fetch_segment_routes_to_s3_for_zkof_backend`, and
   `prefetch_bucket_reads_storage_backend_per_row`.
9. **Archive compaction orchestration**
   (`archive::compaction` + `CoreImpl::compact_archive`):
   per `(conversation_id, time_bucket)`, collects
   `archive_state = archive_verified` segments, decrypts each
   via the `ArchiveSegmentRouter`, applies
   `apply_archive_tombstones` (drops `MessageDeleted` /
   `ConversationDeleted` events themselves and any earlier
   events for tombstoned ids), re-seals via
   `ArchiveSegmentBuilder::build_segment`, and atomically
   transitions superseded rows to `archive_compacted` inside a
   SAVEPOINT. Tests cover the merge, the tombstone semantics,
   the state-machine transitions, and the no-op-for-singleton
   case.
10. **Key recovery foundation** (`restore::key_recovery`):
    `RecoveryKey` is a 256-bit human-readable secret (64-char
    lowercase hex) that AES-256-KW-wraps `K_user_master`;
    `generate_recovery_key` / `recover_from_key` round-trip and
    fail-fast on wrong keys via the RFC 3394 integrity check
    value. `DeviceTransferPayload` AEAD-seals
    `(K_user_master, K_archive_root, K_backup_root,
    K_search_root)` under a transfer key derived from a numeric
    code via HKDF-SHA-256. Server escrow remains OFF by default
    per `docs/PHASES.md §Phase 4`.

Status moves: Phase 3 → `In progress | ~85%`; Phase 4 →
`In progress | ~75%`.

### 2026-05-03 — Phase-3 / Phase-4 cross-cutting batch of 10

Lands the next cross-cutting batch on top of PR #27. Phase 3
sink slots get the remaining iCloud / Google Drive / ZK Object
Fabric `MediaBlobSink` scaffolds; Phase 4 picks up its full Rust
foundation: backup event journal, segment builder, manifest
chain, compaction, manifest verification, restore state machine,
and skeleton-first restore pipeline.

**Phase 3 — `MediaBlobSink` slots:**

1. **ZK Object Fabric `MediaBlobSink`**
   (`crates/core/src/media/sinks/zk_fabric.rs`): per-chunk S3
   keys of the form `media/{asset_id}/chunk-{idx:08}` against a
   configured bucket. The S3 client is a small `S3Client` trait
   (`put_object` / `get_object` / `delete_objects_with_prefix`)
   with a `NoopS3Client` stub for tests.
2. **iCloud `MediaBlobSink`**
   (`crates/core/src/media/sinks/icloud.rs`): platform-bridge
   scaffold — `ICloudBlobBridge` trait (`upload_file`,
   `download_file_range`, `delete_file`) wraps the iOS / macOS
   side; `ICloudMediaBlobSink` concatenates chunks under the
   asset_id record name. Storage sink tag = `"icloud"`.
3. **Google Drive `MediaBlobSink`**
   (`crates/core/src/media/sinks/google_drive.rs`): same shape
   as iCloud — `GoogleDriveBridge` trait + `Arc<dyn>` sink
   wrapper, Drive file id stored in
   `MediaBlobReference.metadata`. Storage sink tag =
   `"google_drive"`.

**Phase 4 — backup foundation:**

4. **Backup event journal**
   (`crates/core/src/backup/event_journal.rs`): typed taxonomy
   (`BackupEventType` 7-variant enum), `BackupEvent` row with
   `conversation_id` / `message_id` / `payload`, and
   `BackupEventJournal` with `write_event`,
   `read_events_since`, `read_cursor`, `advance_cursor`,
   `read_unsegmented`. Wired into `MessagePersister` so every
   persist / edit / delete writes a typed `BackupEvent` inside
   the same SAVEPOINT as the existing `ArchiveEvent`. Legacy
   non-taxonomy event strings are silently skipped on read so
   the journal stays compatible with the pre-Phase-4 wiring.
5. **Backup segment builder**
   (`crates/core/src/backup/segment_builder.rs`): CBOR encode →
   zstd compress → XChaCha20-Poly1305 seal under
   `K_backup_segment` derived via
   `derive_backup_segment(K_backup_root, segment_id)`. AAD =
   `KCHAT_BACKUP_SEGMENT_V1 || segment_id || merkle_root`.
   `decrypt_backup_segment` round-trips for the restore path.
6. **Backup manifest builder**
   (`crates/core/src/backup/manifest_builder.rs`): genesis
   (`generation = 0`, `previous_manifest_hash = [0; 32]`) →
   chained (`generation = prev.generation + 1`,
   `previous_manifest_hash = compute_manifest_hash(prev)`).
   Ed25519 over canonical CBOR; AEAD-sealed under
   `K_backup_manifest` with `device_id` mixed into the AAD for
   device attribution. Negative tests cover wrong-key /
   wrong-device-id failures.
7. **Backup compaction**
   (`crates/core/src/backup/compaction.rs`):
   `CompactionPolicy` with configurable
   `daily_to_weekly_ms` / `weekly_to_monthly_ms` /
   `min_group_size` thresholds (defaults: 7d / 30d / 2);
   deterministic `plan` buckets eligible segments by
   `(source_tier, week_or_month_bucket)`; `apply_tombstones`
   drops events superseded by `MessageDeleted` /
   `ConversationDeleted` / `MediaDeleted`. Monthly is terminal.

**Phase 4 — restore foundation:**

8. **Restore state machine persistence**
   (`crates/core/src/restore/state_machine.rs`): SQL helpers
   (`load`, `save`, `transition`, `reset`) for the single-row
   `restore_state` table, layered on top of the already-defined
   `local_store::state_machines::RestoreState` enum and its
   forward-only `try_transition`. Initial transition must be
   `IdentityRestored`; backwards / skip transitions error.
9. **Manifest chain verifier**
   (`crates/core/src/restore/manifest_verifier.rs`): walks the
   manifest chain from genesis to the latest, verifying every
   Ed25519 signature and the
   `previous_manifest_hash == compute_manifest_hash(prev)`
   invariant. Returns structured `EmptyChain` /
   `SignatureInvalid { generation }` /
   `ChainBreak { generation, expected, actual }` /
   `GapDetected { missing_generation }` /
   `GenesisHashNotZero { actual }` /
   `HashComputationFailed { generation }` per failure mode.
10. **Skeleton-first restore pipeline**
    (`crates/core/src/restore/pipeline.rs::RestorePipeline`):
    drives the priority sequence — conversation list → timeline
    skeletons → search index shards (placeholder) → recent
    bodies (recency-window flip from `RemoteArchiveOnly` →
    `LocalPlainAvailable`) → enable lazy media restore — with a
    persisted `RestoreState` transition between every step.
    `CoreImpl::restore_from_backup` now walks the state machine
    end-to-end to terminal `FullRestoreComplete`; the
    placeholder `Error::NotImplemented` return is gone.

**Cross-module integration test:** `crates/core/tests/backup_pipeline.rs`
covers the round-trip — build a 2-generation manifest chain →
`verify_manifest_chain` → run `RestorePipeline::run` against
the sealed segment → assert terminal state +
`recent_bodies` hydrated only inside the recency window. A
second test forges a chain break and asserts the verifier
catches it.

Status moves: Phase 3 → `In progress | ~75%`; Phase 4 →
`In progress | ~55%`.

### 2026-05-03 — Phase-2 / Phase-3 cross-cutting batch of 10 (this PR)

Lands the remaining Phase-2 / Phase-3 task surface as a single
cross-cutting batch. Highlights:

**Phase 2 / Phase 3:**

1. **`storage_backend` plumbing on `archive_segment_map`** —
   `local_store::state_machines::StorageBackend` is the typed
   enum (`KchatBackend`, `ZkObjectFabric`) wired through
   `LocalStoreDb::{get,update}_segment_storage_backend`. Round-trip
   insert / read / update unit tests guard the column.
2. **Archive segment download + decrypt pipeline** —
   `archive::download::{download_archive_segment,
   decrypt_archive_segment, decode_archive_segment_payload,
   fetch_and_decrypt_segment}` mirrors the inverse of
   `segment_builder` (XChaCha20-Poly1305 open + zstd decompress +
   CBOR decode). 10 unit tests cover round-trip, wrong-key,
   tampered ciphertext, and transport-error paths.
3. **Epoch key lifecycle wired into `CoreImpl`** —
   `archive::epoch_keys::EpochKeyManager` is now installed at the
   `CoreImpl` layer via `with_current_epoch_key` /
   `rotate_archive_epoch` / `unwrap_prior_epoch_key` /
   `delete_epoch_key`. `ArchiveManifestBuilder` carries a
   `wrapped_prior_epoch_keys: Vec<WrappedEpochKeyRef>` slot in
   the signed manifest, with integration tests covering rotation
   + wrap-unwrap round-trip + zeroize-on-delete.
4. **Timeline-skeleton rehydration on scroll-back** —
   `CoreImpl::rehydrate_timeline_skeletons` calls
   `batch_prefetch_bucket`, decrypts each segment via the new
   `archive::download` pipeline, and lands archive-only stub
   skeletons (`BodyState::RemoteArchiveOnly`) through
   `LocalStoreDb::upsert_skeleton_from_archive` (`INSERT OR
   IGNORE` so existing local rows always win). Integration tests
   cover happy-path landing, INSERT OR IGNORE preservation,
   empty-bucket no-op, and wrong-key error propagation.
5. **Lazy media rehydration on tap** —
   `LocalStoreDb::get_media_asset_by_message` resolves an asset
   row from a `message_id`, and `CoreImpl::rehydrate_media_for_message`
   wraps `media::download::rehydrate_media_asset` so the on-tap
   UI flow can resolve the right asset by message-key. The
   `hydrate_message` worker enqueue now escalates to
   `HydrationReason::MediaFullScreen` whenever the message has an
   evicted media asset, ensuring tap latency beats opportunistic
   prefetch.
6. **`MediaDescriptor` propagation through MLS ingest** —
   `MessagePersister::persist_ingested_message` now writes a
   `media_asset` row (state = `ThumbnailOnly`) for every attached
   `MediaDescriptor`, defaults `storage_sink` to `kchat_backend`
   when the sender did not set one, and rolls back atomically
   under the existing `SAVEPOINT persist_ingest`. 4 new unit
   tests cover writes, no-op without descriptor, sink override,
   and SAVEPOINT-backed idempotency.

Already-landed in earlier PRs and re-verified: tiered eviction
policy (`PressureLevel`-gated), dummy request padding
(`PrivacyLevel::High`), ZK Object Fabric `MediaBlobSink`, and
archive backend routing (KChat / ZKOF dispatch). All tests in
those modules continue to pass.

Test surface lands at 691 unit tests + integration suites, all
green: `cargo test --workspace` passes end-to-end.

### 2026-05-03 — Phase-2 / Phase-3 follow-on batch of 10

Closes the remaining Phase-2 thumbnail item and pushes Phase-3 from
~35% to ~60% in a single PR. Highlights:

**Phase 2:**

1. **Thumbnail generation in `media::processor`** —
   `generate_thumbnail` (using the `image` crate) downscales image
   plaintext to a configurable max dimension and re-encodes as PNG;
   wired into `process_media` so `MediaProcessResult` now carries
   `thumbnail_bytes: Option<Vec<u8>>`. Non-image MIME types and
   empty input cleanly return `None`.

**Phase 3:**

2. **Eviction priority order** — `offload::scoring::PressureLevel`
   gates content-kind eligibility (originals at `Warning+`,
   thumbnails at `Critical+`, cold text at `Extreme` only).
   `plan_eviction_with_pressure` is the pressure-aware variant of
   `plan_eviction`.
3. **Timeline-skeleton rehydration (no scroll-jump)** —
   `LocalStoreDb::rehydrate_message_body` runs an
   `INSERT OR REPLACE` on `message_body` plus a `body_state`
   UPDATE inside one SAVEPOINT without touching `created_at_ms` /
   `received_at_ms`, then re-indexes into `search_fts` /
   `search_fuzzy_words`. `CoreImpl::hydrate_message` consumes it
   on cold-message taps so the viewport never scroll-jumps.
4. **Lazy media rehydration on tap** —
   `media::download::rehydrate_media_asset` reads
   `media_asset.{blob_id, storage_sink, chunk_count, merkle_root,
   wrapped_k_asset}`, unwraps `K_asset` via `K_local_db`, drives
   the chunked download through `TransportClient` or the
   configured `MediaBlobSink` based on `storage_sink`, verifies
   the BLAKE3 root, and flips `media_state` to `original_local`.
5. **Epoch key lifecycle** —
   `archive::epoch_keys::EpochKeyManager` keeps the current epoch
   key in `Zeroizing<[u8; 32]>`, wraps prior keys via AES-256-KW
   under `K_archive_root` for cross-epoch segment decrypt, and
   exposes `rotate(new_epoch_id)` / `unwrap_prior_epoch_key` /
   `delete_epoch_key(epoch_id)` for forward secrecy.
6. **Archive backend routing** — `archive::routing::route_*`
   dispatches `route_archive_upload` / `route_archive_download` /
   `route_manifest_upload` to either `TransportClient` (KChat
   backend) or a `ZkofArchiveAdapter` based on
   `KChatCoreConfig::archive_backend`. The ZKOF adapter sits on a
   small `S3Client` trait with `NoopS3Client` stub for now and
   maps the manifest index to a well-known
   `manifests/index` key.
7. **Dummy request padding (privacy: high)** —
   `archive::privacy::{should_pad, compute_padding_count,
   generate_dummy_segment_id, pad_with_dummy_requests}` mints
   UUIDv4 dummies (UUIDv7 is the real-id format) and interleaves
   them with real ids.
   `archive::prefetch::batch_prefetch_bucket_with_padding`
   issues one fetch per id in the padded order and silently
   drops dummy errors. `KChatCoreConfig::privacy_level` defaults
   to `Standard` (off); set to `High` to enable.
8. **ZK Object Fabric `MediaBlobSink`** —
   `media::sinks::zk_fabric::ZkObjectFabricSink` maps
   `upload_media_chunks` / `fetch_media_chunk` /
   `delete_media_blob` to per-chunk S3 keys of the form
   `media/{asset_id}/chunk-{idx:08}` against a configured bucket.
   `MediaBlobReference::metadata` carries
   `[chunk_count:u32_be][merkle_root:32b][asset_id:utf8]` so the
   rehydration path can re-derive every chunk key without a
   second DB round-trip.
9. **Tiered eviction policy** — `offload::eviction::EvictionTier`
   classifies each `EvictionCandidate` by its `storage_sink`:
   `kchat_backend` → `FullEviction`; everything else →
   `CloudOffload`. `plan_tiered_eviction` is a two-pass planner
   that drains the cloud-offload pool first and only falls
   through to the full-eviction pool if the cloud pass underran
   the budget. Wired into `CoreImpl::enforce_storage_budget`.
10. **End-to-end storage budget enforcement integration test** —
    `crates/core/tests/storage_budget_enforcement.rs`
    seeds a fully-shaped `LocalStoreDb` with multiple
    conversations / mime types / archive states / storage sinks
    and walks the budget enforcer → candidate collector → tiered
    planner → executor pipeline at every pressure level (`None`,
    `Warning`, `Critical`, `Extreme`). Each pressure tier and
    eviction-tier branch has a dedicated test.

Test surface bumps from 649 → ~712 with all pre-existing tests
green: `cargo test --workspace` passes end-to-end. Documentation
updates land alongside the code: PROGRESS.md (this entry plus the
Phase 2 / Phase 3 checklists below), README.md (status banner +
project tree), ARCHITECTURE.md (archive sub-modules, tiered
eviction note), and PHASES.md (Phase 3 checklist).

### 2026-05-03 — Phase-2 finishing pass + Phase-3 foundation (10-task batch)

Closes the open Phase-2 thumbnail / `send_media` items and lays
the Phase-3 archive + offload foundation in a single PR:

**Phase 2:**

- `media::thumbnail::ThumbnailGenerator` — decode PNG/JPEG, scale
  to `DEFAULT_MAX_DIMENSION = 256`, re-encode as PNG; unit tests
  cover valid input, max-dimension, unsupported MIME, and empty
  input.
- `CoreImpl::send_media` is wired end-to-end against the chunked
  media pipeline: random `K_asset`, `MediaDescriptor` assembly,
  optional thumbnail, `media_asset` row + skeleton + caption body
  rows, all behind a `SAVEPOINT` so partial failures roll back.
  Returns the new `SendMediaResult { client_message_id, asset_id,
  descriptor }`.
- `crates/core/tests/media_pipeline.rs` end-to-end integration
  tests: `process_media` round-trip, padding, multi-chunk inputs,
  `MediaCache` insert / touch / evict, multilingual
  `normalize_caption` + `sanitize_filename`, `route_media_upload`
  /`route_media_download` dispatch logic, and a
  `ThumbnailGenerator` smoke test.

**Phase 3 foundation:**

- `archive::event_journal` — append-only `archive_event_journal`
  table, `archive_event_cursor` table, and an
  `ArchiveEventJournal` API (`write_event`, `read_events_since`,
  `read_cursor`, `advance_cursor`, `read_unsegmented`).
- `archive::segment_builder` — `SegmentBuildRequest`,
  `BuiltSegment`, and `ArchiveSegmentBuilder::{group_events_by_bucket,
  build_segment}`. Pipeline: CBOR encode → zstd compress →
  XChaCha20-Poly1305 seal under `K_archive_segment(segment_id)`;
  AAD ties `segment_id` and BLAKE3 plaintext root to the
  ciphertext, blocking ciphertext-swap attacks.
- `crypto::key_hierarchy` — epoch-rotated archive keys:
  `derive_archive_epoch_key`, `derive_archive_segment_key`,
  `derive_archive_manifest_key`, plus AES-256-KW `wrap_epoch_key`
  / `unwrap_epoch_key` so the orchestration layer can persist
  prior-epoch keys in the manifest chain.
- `offload::budget` — `StorageBudget`, `StorageUsage`,
  `BudgetAssessment`, `PressureLevel`, and
  `StorageBudgetEnforcer::assess` (DB probe + headroom + pressure
  level mapping).
- `offload::scoring` — `ContentKind` weights matching PROPOSAL
  §5.4 (video → text), 30-day half-life recency decay, 16 MiB
  size-bonus normalisation, with pinned candidates
  short-circuited to `f64::NEG_INFINITY`.
- `offload::eviction` — `plan_eviction` (filter pinned /
  not-archived → score → sort → accumulate to target_bytes) +
  `execute_eviction` (state-machine demotion of `media_asset`
  rows).
- `offload::hydration` — `HydrationQueue` (deduplicating priority
  queue, P0..P5 ordering by `HydrationReason`, FIFO tiebreaker,
  `enqueue_prefetch_window` for viewport adjacency).
- `CoreImpl::hydrate_message` — local-hit path returns the body;
  cold (`remote_archive_only`) returns the skeleton with
  `is_cold = true`; `deleted_for_everyone` returns
  `Error::Message`.
- `CoreImpl::enforce_storage_budget` — assesses pressure via the
  budget enforcer and short-circuits to a zero result when no
  pressure exists. The candidate-collection query that drives a
  non-trivial plan is queued for the next milestone.

Test count: workspace test count grew from ~538 to ~600+ across
unit tests and the new `media_pipeline` integration suite.

### 2026-05-03 — Post-optimization benchmark rerun (Phase-1 baseline + cross-repo summary)

Re-ran `cargo test --workspace` and
`cargo bench -p kchat-core` after the cross-repo improvements
A–H (unified `llama-server`, Apple MLX SLM + Whisper,
embedding cache, INT4 quantization, DirectML EP for Windows,
model warm-up, Whisper MLX) landed across the four KChat
repos. The `chat-storage-search` Phase-1 hot paths are
unchanged on this Linux x86 VM — improvements A–H introduce
alternative code paths (Apple MLX, Windows DirectML, server
warm-up) that this repo's Phase-1 surface doesn't exercise.

- `cargo test --workspace`: 538 passed, 0 failed, 0 ignored
  across 13 test targets (kchat-core unit + 5 integration,
  kchat-android-bridge, kchat-desktop, kchat-ios-bridge, +
  doctests). Verified via `grep -rE '#\[ignore' crates/` that
  no tests are silently skipped — particularly important for
  the multilingual / FTS5 / fuzzy search integration tests.
- `cargo bench -p kchat-core`
  (`crates/core/benches/phase1_benchmarks.rs`): all five
  benchmarks land three orders of magnitude under their
  PROPOSAL §13 latency budgets:
  - `insert_text_message`: median 144 µs (target < 20 ms p95).
  - `insert_batch_100/100_text_messages`: median 10.04 ms
    (target < 2 s for the batch).
  - `search_recent_messages`: median 110 µs (target < 150 ms p95).
  - `search_with_structured_filters`: median 147 µs (same target).
  - `fts_prefix_search`: median 102 µs (same target).
- Phase 6 ML benchmarks (XLM-R / MobileCLIP-S2 / Whisper) are
  explicitly listed as "not yet runnable" in the new
  `docs/benchmarks/phase1-benchmark-results.md` — Phase 6
  has not started in this repo (only the Apple MLX Whisper
  backend scaffold has landed, see entry below), and the
  on-Apple-Silicon MLX runtime path cannot be measured on
  this Linux x86 VM.

Files added:
- `docs/benchmarks/phase1-benchmark-results.md` — Phase-1
  test + criterion results, environment, target comparison,
  Phase-6 deferral note, cross-platform skips, reproduction
  command.
- `docs/benchmarks/cross-repo-summary.md` — consolidated
  performance + verification table across all four KChat
  repos (slm-guardrail, cv-guard, slm-chat-demo,
  chat-storage-search) with no-mock verification checklist.

### 2026-05-03 — Phase 6 scaffold: Apple MLX Whisper backend (Apple Silicon) → ONNX Runtime fallback

- Added `crates/core/src/models/whisper.rs`: pure
  `select_whisper_backend(&AppleSiliconProbe)` state machine
  that returns `WhisperBackend::Mlx` on Apple Silicon
  (`aarch64` `macOS` / `iOS`) when the probe reports MLX
  available, and `WhisperBackend::Onnx` everywhere else.
  Mirrors the DirectML → CPU pattern in
  `crates/core/src/models/embeddings_onnx.rs` /
  `crates/core/src/models/clip.rs` but pivots on
  `cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))`
  instead of `cfg(target_os = "windows")`.
- Canonical artifact identifiers exposed for the model
  manager: `WHISPER_BASE_MLX_MODEL_REPO =
  "mlx-community/whisper-base-mlx"` and
  `WHISPER_BASE_ONNX_ARTIFACT = "whisper-base.int8.onnx"`.
  `WHISPER_BASE_MLX_MODEL_VERSION` / `WHISPER_BASE_ONNX_MODEL_VERSION`
  are versioned independently so transcripts cannot leak
  across decoder families.
- Documentation alignment: PROPOSAL §7.6 model table gains
  an "Apple MLX" column; PROPOSAL §7.7 platform table marks
  iOS / macOS as `MLX (preferred for Whisper) or Core ML or
  ONNX Runtime CoreML EP`. README, ARCHITECTURE §11.1 / §11.3,
  PHASES Phase 6, and PROGRESS Phase 6 follow the same split.
  Whisper joins the same MLX-on-Apple-Silicon track already
  established in
  [`kennguy3n/slm-chat-demo`](https://github.com/kennguy3n/slm-chat-demo)
  and [`kennguy3n/cv-guard`](https://github.com/kennguy3n/cv-guard)
  for the SLM stack.

### 2026-05-03 — Phase 2 media download + cache + state machine + caption + routing

- Media download pipeline landed at `crates/core/src/media/download.rs`:
  `download_chunked_media` and `download_single_chunk` fetch encrypted
  chunks via `TransportClient::fetch_blob_range`, verify per-chunk
  SHA-256, AEAD-open with per-chunk AAD, and verify the whole-object
  BLAKE3 root.
- Local media cache with LRU eviction landed at
  `crates/core/src/media/cache.rs`: `MediaCache` tracks local media
  assets with configurable byte budget and LRU eviction.
- Media state machine integration: `MediaState` transitions wired
  into the media processor and local store via
  `LocalStoreDb::update_media_state`.
- Multilingual filename/caption handling landed at
  `crates/core/src/media/caption.rs`: NFC normalization, filename
  sanitization, caption validation with full multilingual support.
- Media upload/download routing landed at
  `crates/core/src/media/routing.rs`: thumbnails always route to
  `TransportClient`; originals route to the configured
  `MediaBlobSink` when present, falling back to `TransportClient`.

### 2026-05-03 — Phase 2 chunked-media pipeline (chunker / processor / upload)

- Media chunker landed at `crates/core/src/media/chunker.rs`:
  `DEFAULT_CHUNK_SIZE = 16 MiB` (matches Pattern C), the
  `SealedChunk { ciphertext, chunk_sha256 }` /
  `ChunkedMedia { sealed_chunks, merkle_root, chunk_count }`
  pair, and `chunk_and_encrypt(plaintext, k_asset, blob_id,
  blob_class, chunk_size, pad)` driving XChaCha20-Poly1305 over
  every `chunk_size`-byte slice with a per-chunk
  `KCHAT_BLOB_CHUNK_V1` AAD (PROPOSAL.md §8.3) and a
  deterministic 24-byte nonce derived from the chunk index.
  Per-chunk SHA-256 is recorded over the **ciphertext** so the
  rehydration path can fast-fail on torn / re-ordered uploads
  before doing any AEAD work. The whole-object BLAKE3 root is
  computed over the (padded) plaintext and bound into every
  per-chunk AAD. Empty plaintext still produces one zero-length
  chunk so `chunk_count >= 1` holds.
- Size-class padding (PROPOSAL.md §8.2) landed in the same
  module: `pad_to_size_class(plaintext)` rounds
  `plaintext.len() + 8` up to the next class from
  `[1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB,
  16 MiB, 64 MiB, 256 MiB, 1 GiB]` (extending the §8.2 ladder
  by 1 KiB at the low end and 1 GiB at the high end so sub-4 KiB
  voice notes and long-form video both have a class) and writes
  an 8-byte big-endian length prefix so
  `unpad_from_size_class(padded)` can recover the original slice.
  Inputs larger than 1 GiB round up to the next power of two.
  `chunk_and_encrypt` wires it through an opt-in `pad: bool`
  parameter; the merkle root is computed *after* padding so the
  rehydration path doesn't have to re-run padding logic.
- Chunk-integrity verifier (`media::chunker::verify_and_decrypt`)
  closes the rehydration loop: SHA-256 fast-fail across every
  chunk, then per-chunk AEAD-open with the same §8.3 AAD, then
  whole-object BLAKE3 verification against the descriptor's
  `merkle_root`. Error messages distinguish each stage so the UI
  layer can surface a useful diagnostic.
- Media processor landed at `crates/core/src/media/processor.rs`:
  `process_media(plaintext, mime_type, wrapping_key, blob_class,
  pad)` generates a fresh-random 256-bit `K_asset` (held in a
  `Zeroizing<[u8; 32]>` for panic-safe scrubbing), runs the
  chunker, AES-256-KW-wraps `K_asset` under the caller's
  wrapping key (`K_local_db` / `K_archive_root` /
  `K_backup_root`), and assembles a CBOR-ready
  `MediaDescriptor` (`asset_id` / `blob_id` from `Uuid::now_v7`,
  `bytes_total`, `chunk_count`, `merkle_root`,
  `wrapped_k_asset`, `storage_sink: None`).
  `MediaProcessResult { descriptor, sealed_chunks, k_asset_raw }`
  bundles everything the local store and the upload pipeline
  need.
- Chunked-blob upload pipeline landed at
  `crates/core/src/media/upload.rs`:
  `upload_chunked_media(transport, sealed_chunks, merkle_root,
  blob_class)` drives `TransportClient::init_blob_upload` →
  `upload_chunk` (echoing per-chunk SHA-256 in the receipt) →
  `commit_blob`, then verifies
  `commit_response.merkle_root == merkle_root`.
  `resume_upload(transport, state, sealed_chunks, blob_class)`
  consumes an `UploadState { blob_id, completed_chunks,
  merkle_root }`, skips chunks already marked completed, pushes
  the remainder, and re-runs commit. Both functions return an
  `UploadResult { blob_id, merkle_root, server_merkle_root }`
  for observability of any client/server disagreement on
  whole-object integrity.
- Test coverage: the lib test count is up by **24** to **395**
  total. The new tests cover the prompt's full matrix —
  `single_chunk_round_trip`, `multi_chunk_splits_correctly`,
  `empty_plaintext`, `chunk_sha256_is_over_ciphertext`,
  `different_k_asset_produces_different_ciphertext`,
  `aad_mismatch_prevents_decrypt`, `pad_round_trip`,
  `padding_reaches_next_class`, `unpad_rejects_corrupted_length`,
  `zero_length_input_pads_correctly`,
  `padding_in_chunk_and_encrypt_round_trips_through_verify`,
  `verify_and_decrypt_round_trip`,
  `tampered_ciphertext_fails_sha256`,
  `tampered_chunk_order_fails`, `wrong_merkle_root_fails`,
  `wrong_key_fails`, `empty_sealed_chunks_rejected`,
  `process_media_round_trip`, `process_media_descriptor_fields`,
  `process_media_with_padding`,
  `different_calls_produce_different_k_asset`,
  `upload_all_chunks_happy_path`,
  `resume_skips_completed_chunks`,
  `merkle_root_mismatch_on_commit_fails`,
  `empty_chunks_list_errors`,
  `resume_with_all_chunks_complete_only_commits`, and
  `resume_length_mismatch_errors` (the upload tests use a
  test-only `MockTransportClient` modeled on the existing
  `MockDeliveryClient` pattern).
- Phase 2 status flipped from `NOT STARTED` to
  `In progress | ~30%`. The PR #14 items it inherits
  (`StorageSink` / `ArchiveBackend` enums, `storage_sink` on
  `MediaDescriptor` and `media_asset`, `MediaBlobSink` trait,
  `NoopMediaBlobSink` placeholder) are now ticked alongside the
  new per-chunk AAD, size-class padding, and chunk-integrity
  verification items.

### 2026-05-02 — Phase 1 bridges + trait surface cleanup

- UniFFI bridge scaffold for iOS landed at `crates/ios-bridge/`.
  Adds `uniffi = "0.28"` (regular + build dependencies),
  `src/kchat.udl` mirroring the public `KChatCore` surface,
  `build.rs` that calls `uniffi::generate_scaffolding`, and
  `src/lib.rs` with FFI-shaped wrappers (`KChatCoreConfig`,
  `Platform`, `SearchQuery`, `SearchResult`, `SearchScope`,
  `ContentKind`, `MessageView`, `ClientMessageId`,
  `DeliveryCursor`, `IngestResult`, `DeviceRegistration`) plus a
  `KChatCore` UDL `interface` whose Rust implementation wraps
  `kchat_core::CoreImpl`. UUIDs cross the FFI as canonical
  strings; argument validation throws
  `KChatError::InvalidArgument`. Seven unit tests round-trip
  `send_text` → `get_message`, exercise the wrong-key-length
  error path, and pin the `Platform` / `SearchQuery`
  conversions.
- JNI bridge scaffold for Android landed at
  `crates/android-bridge/`. Adds `jni = "0.21"` and exposes a
  pure-Rust `KChatBridgeHandle` plus the
  `Java_com_kchat_core_KChatBridge_*` entry points
  (`initialize`, `destroy`, `sendText`, `search`,
  `editMessage`, `deleteForMe`, `deleteForEveryone`,
  `getMessage`, `getConversationMessages`). Errors throw
  `com.kchat.core.KChatException`; `MessageView` /
  `SearchResult` batches marshal as JSON for brevity. Eleven
  unit tests exercise the bridge surface without a JNIEnv
  (round-trip send / search / edit / delete / pagination,
  invalid UUID / wrong key length / unknown platform error
  paths, plus a compile-only delegate-signatures test).
- `KChatCore` trait surface tightened. `delete_conversation`
  is now a trait method (was inherent on `CoreImpl`),
  `register_device(&str) -> Result<DeviceRegistration>` was
  added as a Phase-1 stub returning
  `Error::NotImplemented("register_device")`, and a new
  `DeviceRegistration` placeholder type lives next to the
  other Phase-1 placeholders in `crates/core/src/lib.rs`.
- `IngestResult.next_cursor: Option<String>` propagated
  through `CoreImpl::ingest_remote_messages` from
  `transport::FetchResult::next_cursor`. The TODO that
  punted this to Phase 2 is gone; the inherent
  `CoreImpl::ingest_messages` entry point continues to leave
  `next_cursor` as `None` because it has no transport
  context.

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
- 2026-05-02: Phase 1 caught up to ~90%. The KChatCore trait
  now exposes the full Phase-1 message lifecycle and the
  transport surface is no longer a stub.
  - `edit_message`, `delete_for_me`, and `delete_for_everyone`
    on the trait delegate to `MessagePersister` so callers can
    drive the local lifecycle without reaching into
    `core::message`. Four new `core_impl` tests pin the
    body / skeleton / FTS / fuzzy state at every transition
    plus the missing-id error path.
  - Timeline retrieval landed: `LocalStoreDb` grew
    `get_conversation_messages(conversation_id, before_ms,
    limit)` and `get_message_with_body(message_id)`; the
    trait surfaces them as `get_message` and
    `get_conversation_messages` returning the new `MessageView`
    (skeleton fields plus optional body text) so the public API
    never leaks the internal schema. Six new tests cover
    newest-first ordering, `before_ms` pagination, `limit`
    handling (including `limit == 0`), the joined skeleton +
    body shape, the missing-body fallback, and the round-trip
    through `CoreImpl`.
  - Transport trait abstraction landed at
    `crates/core/src/transport/mod.rs`: `DeliveryClient`
    (object-safe, `Send + Sync`),
    `FetchResult { messages, next_cursor }`,
    `RawDeliveryMessage` (the wire-shape ingest payload), and
    `TransportError { Network, Auth, Server }` (with
    `thiserror`-derived `Display`). A test-only
    `MockDeliveryClient` lets unit tests stage responses keyed
    on the expected `after_cursor` and asserts the cursor
    pass-through inside `fetch_messages`. The trait's
    object-safety is pinned by an `assert_object_safe` test
    that constructs a `Box<dyn DeliveryClient>`.
  - `CoreImpl::ingest_remote_messages` is wired to the
    transport: the new `delivery_client:
    Mutex<Option<Box<dyn DeliveryClient>>>` field defaults to
    `None` (so existing call sites still work), and
    `with_transport(config, key, client)` /
    `set_delivery_client(client)` install one. On call the
    trait method fetches with the caller's cursor, converts
    each `RawDeliveryMessage` to `IngestedMessage`, and runs
    the result through the existing batch-ingest pipeline so
    deduplication / FTS / fuzzy / journal writes are unchanged.
    Four new tests pin the happy path (3 messages persisted +
    searchable), the no-transport error
    (`Error::Transport("no delivery client configured")`),
    the dedup behavior on retry, and the cursor pass-through.
  - Conversation metadata auto-update landed in the persistence
    pipeline. `LocalStoreDb::update_conversation_last_message`
    bumps `conversation.last_message_id` and
    `last_activity_ms` in a single statement, and both
    `MessagePersister::persist_ingested_message` and
    `persist_outbox_entry` invoke it from inside the existing
    `SAVEPOINT` so the conversation row stays in lock-step with
    the message timeline. `list_conversations` therefore
    reflects the latest activity automatically — no extra call
    is required from the binding layer. Four new tests cover
    the SQL helper (sets fields, returns 0 for missing id),
    the ingested + outbox persistence paths, and the public
    `list_conversations` re-ordering.
- 2026-05-02: Phase 1 caught up to ~80%. Fuzzy index is wired
  through `MessagePersister` (ingest / outbox / edit / delete)
  and merged into `QueryEngine::execute_search` with
  PROPOSAL.md §7.5 weights. The `KChatCore` trait grew the
  remaining `send_media` / `hydrate_message` /
  `run_incremental_backup` / `enforce_storage_budget` /
  `restore_from_backup` surface, all stubbed via
  `Error::NotImplemented`. Conversation management
  (create / list / get / pin / mute) landed on `CoreImpl`
  and `LocalStoreDb`. New combined FTS5 + fuzzy multilingual
  integration suite at
  `crates/core/tests/multilingual_fuzzy_search.rs`.
- 2026-05-02: Phase 1 closed in to ~95% with five sibling
  tasks. (1) Transport trait surface: `transport::mod`
  expanded with `TransportClient` (fetch_messages,
  init_blob_upload, upload_chunk, commit_blob,
  fetch_blob_range, fetch_archive_manifests,
  fetch_archive_segment, fetch_index_shards), supporting
  types (`FetchMessagesResponse`, `BlobUploadHandle`,
  `ChunkReceipt`, `CommitBlobResponse`,
  `EncryptedManifest`), and `NoopTransportClient` that
  returns `Error::NotImplemented("transport")` from every
  method. `BlobClass` in `crypto::aead` picked up
  `Serialize / Deserialize` so the wire-level AAD tag and
  the transport-level upload argument can never disagree.
  (2) Conversation metadata auto-update is now hardened
  against out-of-order arrivals: `update_conversation_last_message`
  does not regress `last_activity_ms`. (3) Message timeline
  pagination: `LocalStoreDb::get_timeline` and
  `CoreImpl::get_timeline` return a newest-first
  `TimelineRow` page (skeleton + optional body text) cursored
  on `before_ms`. (4) Single-message retrieval:
  `CoreImpl::get_message_with_body` and
  `CoreImpl::get_message_body` wrap the existing DB helpers
  for the binding layer's hydration display path. (5)
  Conversation deletion: `LocalStoreDb::delete_conversation`
  cascades through `search_fuzzy` → `search_fts` →
  `message_body` → `message_skeleton` → `conversation` in a
  single `SAVEPOINT`; `CoreImpl::delete_conversation` maps
  the missing-row case to `Error::Storage`. The five sibling
  tasks ship with 18 new unit tests across
  `local_store::db` and `core_impl` plus 12 transport-trait
  tests (object safety, serde round-trips, every
  `NoopTransportClient` method).
