# KChat Storage & Search — Architecture

**License**: Proprietary — All Rights Reserved. See [LICENSE](../LICENSE).

This document is the system-architecture companion to
[PROPOSAL.md](PROPOSAL.md). It contains the diagrams, schema, state
machines, and sequence flows that define how the Rust core and its
platform bridges fit together. Where the proposal is "what and why",
this document is "how the pieces connect".

All mermaid diagrams use double-quoted labels and no colors so they
render identically in every viewer.

---

## 1. System Overview

The library is a layered Rust core embedded in the KChat client
app. Platform bridges (UniFFI on iOS, JNI on Android, native crate
on desktop) project the core's public API into idiomatic Swift /
Kotlin / Rust call sites. The core itself is platform-agnostic.

```mermaid
flowchart TD
    subgraph Apps["KChat App (Swift / Kotlin / Rust)"]
        UI["UI Layer"]
    end

    subgraph FFI["FFI Bridges"]
        Swift["UniFFI &rarr; Swift"]
        Kotlin["JNI &rarr; Kotlin"]
        Native["Native Rust"]
    end

    subgraph Core["Rust Core (crates/core)"]
        LocalStore["Local Store<br/>(SQLCipher)"]
        Search["Search Engine<br/>(FTS5 + Fuzzy + HNSW + ML)"]
        Archive["Archive Engine"]
        Backup["Backup Engine"]
        Offload["Offload Engine"]
        Restore["Restore Engine"]
        Crypto["Crypto Module"]
        Transport["Transport Client"]
    end

    subgraph External["External Services"]
        BE["KChat Backend<br/>(PostgreSQL, MLS distribution)"]
        ZKOF["ZK Object Fabric<br/>(S3 API, optional backup)"]
        Platform["Platform Services<br/>(Keychain / Keystore,<br/>BGTaskScheduler / WorkManager,<br/>Vision / ML Kit, iCloud,<br/>Auto Backup / SAF)"]
    end

    UI --> Swift
    UI --> Kotlin
    UI --> Native

    Swift --> LocalStore
    Kotlin --> LocalStore
    Native --> LocalStore

    LocalStore --> Search
    LocalStore --> Archive
    LocalStore --> Backup
    LocalStore --> Offload
    LocalStore --> Restore

    Archive --> Crypto
    Backup --> Crypto
    Search --> Crypto
    Restore --> Crypto

    Archive --> Transport
    Backup --> Transport
    Restore --> Transport
    Search --> Transport

    Transport --> BE
    Transport --> ZKOF
    Crypto --> Platform
    Backup --> Platform
    Restore --> Platform
```

The core never talks to the UI directly. Every cross-boundary call
goes through the FFI bridge for the host platform.

---

## 2. Crate Structure

The workspace ships four crates: a core that knows nothing about
platforms, and three thin bridges.

```mermaid
flowchart LR
    Core["crates/core<br/>(platform-agnostic)"]
    iOS["crates/ios-bridge<br/>(UniFFI &rarr; Swift)"]
    Android["crates/android-bridge<br/>(JNI &rarr; Kotlin)"]
    Desktop["crates/desktop<br/>(macOS + Windows)"]

    iOS --> Core
    Android --> Core
    Desktop --> Core
```

Inside `crates/core` the modules layer downward; higher-level
modules depend on lower-level ones, never vice versa.

```mermaid
flowchart TD
    Public["lib.rs<br/>(public API trait)"]
    Message["message"]
    Media["media"]
    Search["search"]
    Archive["archive"]
    Backup["backup"]
    Offload["offload"]
    Restore["restore"]
    LocalStore["local_store"]
    Models["models"]
    Transport["transport"]
    Scheduler["scheduler"]
    Crypto["crypto"]

    Public --> Message
    Public --> Media
    Public --> Search
    Public --> Archive
    Public --> Backup
    Public --> Offload
    Public --> Restore

    Message --> LocalStore
    Media --> LocalStore
    Media --> Models
    Search --> LocalStore
    Search --> Models
    Archive --> LocalStore
    Backup --> LocalStore
    Offload --> LocalStore
    Restore --> LocalStore

    Archive --> Transport
    Backup --> Transport
    Restore --> Transport
    Search --> Transport
    Media --> Transport
    Message --> Transport

    LocalStore --> Crypto
    Archive --> Crypto
    Backup --> Crypto
    Search --> Crypto
    Restore --> Crypto
    Media --> Crypto

    Backup --> Scheduler
    Archive --> Scheduler
    Search --> Scheduler
    Models --> Scheduler
```

`crypto` is a leaf module: every other module that touches
ciphertext routes through it, and `crypto` itself depends only on
the standard library and chosen primitives.

---

## 3. Four-Store Data Flow

Four logically distinct stores; three interactive on the device,
one non-interactive for disaster recovery. Direction of arrows is
data flow, not request flow.

```mermaid
flowchart LR
    Local["Local Store<br/>(device, SQLCipher)"]
    Delivery["Delivery Store<br/>(KChat backend, MLS fanout)"]
    Archive["Personal Archive<br/>(KChat backend, encrypted segments)"]
    Backup["Backup Vault<br/>(iCloud / Android backup / ZK Object Fabric)"]

    Delivery -->|"ingest plaintext (post-MLS-decrypt)"| Local
    Local -->|"send (pre-MLS-encrypt)"| Delivery
    Local -->|"offload"| Archive
    Archive -->|"rehydrate on scroll-back / search hit"| Local
    Local -->|"incremental backup"| Backup
    Backup -->|"restore"| Local
```

Backup never feeds the archive directly, and the archive never
feeds the backup directly. They are independent pipelines reading
from their own event journals on the local store.

---

## 4. Local Store Schema

The schema lives in `crates/core/src/local_store/schema.rs`. The
multilingual FTS5 configuration is the headline element:

```sql
-- Conversations
CREATE TABLE conversation (
    conversation_id   TEXT PRIMARY KEY,
    title_cipher      BLOB,                 -- encrypted with K_local_db
    pinned            INTEGER NOT NULL DEFAULT 0,
    muted             INTEGER NOT NULL DEFAULT 0,
    last_message_id   TEXT,
    last_activity_ms  INTEGER NOT NULL
);

-- Skeletons render the timeline before any body / media is loaded
CREATE TABLE message_skeleton (
    message_id        TEXT PRIMARY KEY,
    conversation_id   TEXT NOT NULL REFERENCES conversation(conversation_id),
    sender_id         TEXT NOT NULL,
    created_at_ms     INTEGER NOT NULL,
    received_at_ms    INTEGER NOT NULL,
    kind              TEXT NOT NULL,
    body_state        TEXT NOT NULL,
    media_state       TEXT,
    archive_state     TEXT NOT NULL DEFAULT 'not_archived',
    backup_state      TEXT NOT NULL DEFAULT 'not_backed_up',
    reply_to          TEXT,
    edited_at_ms      INTEGER,
    deleted_at_ms     INTEGER
);

CREATE TABLE message_body (
    message_id        TEXT PRIMARY KEY REFERENCES message_skeleton(message_id),
    text_content      TEXT,                 -- UTF-8, may mix scripts
    detected_language TEXT,                 -- BCP-47, optional
    rich_meta         BLOB                  -- mentions, link previews (CBOR)
);

CREATE TABLE media_asset (
    asset_id          TEXT PRIMARY KEY,
    message_id        TEXT NOT NULL REFERENCES message_skeleton(message_id),
    mime_type         TEXT NOT NULL,
    bytes_total       INTEGER NOT NULL,
    bytes_local       INTEGER NOT NULL,
    media_state       TEXT NOT NULL,
    wrapped_k_asset   BLOB NOT NULL,
    chunk_count       INTEGER NOT NULL,
    merkle_root       BLOB NOT NULL,
    blob_id           TEXT NOT NULL
);

-- Multilingual full-text search
CREATE VIRTUAL TABLE search_fts USING fts5(
    message_id        UNINDEXED,
    conversation_id   UNINDEXED,
    sender_id         UNINDEXED,
    created_at_ms     UNINDEXED,
    text_content,
    tokenize = 'icu'                       -- primary multilingual tokenizer
);

CREATE TABLE search_fuzzy (
    token       TEXT NOT NULL,
    script      TEXT NOT NULL,             -- ISO-15924
    message_id  TEXT NOT NULL,
    PRIMARY KEY (token, script, message_id)
);

CREATE TABLE search_vector (
    message_id    TEXT NOT NULL,
    embedding     BLOB NOT NULL,            -- INT8-quantized
    model_version TEXT NOT NULL,
    PRIMARY KEY (message_id, model_version)
);

CREATE TABLE media_search_index (
    asset_id      TEXT NOT NULL REFERENCES media_asset(asset_id),
    kind          TEXT NOT NULL,            -- 'ocr' | 'caption' | 'transcript' | 'tag'
    text          TEXT NOT NULL,
    language      TEXT,                     -- BCP-47 if detected
    confidence    REAL,
    PRIMARY KEY (asset_id, kind, text)
);

-- Backup pipeline
CREATE TABLE backup_event_journal (
    event_seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type    TEXT NOT NULL,
    payload       BLOB NOT NULL,            -- CBOR
    created_at_ms INTEGER NOT NULL
);

-- Archive pipeline
CREATE TABLE archive_segment_map (
    segment_id           TEXT PRIMARY KEY,
    conversation_id      TEXT NOT NULL,
    time_bucket          TEXT NOT NULL,     -- e.g. '2026-04'
    segment_type         TEXT NOT NULL,
    blob_id              TEXT NOT NULL,
    merkle_root          BLOB NOT NULL,
    state                TEXT NOT NULL      -- not_archived..archive_compacted
);

-- Restore state machine
CREATE TABLE restore_state (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    state  TEXT NOT NULL,                  -- identity_restored..full_restore_complete
    notes  TEXT
);
```

The whole database is a SQLCipher database keyed by `K_local_db`,
itself wrapped by the platform Keychain / Keystore.

---

## 5. Message State Machine

```mermaid
stateDiagram-v2
    direction LR
    [*] --> local_plain_available
    local_plain_available --> local_encrypted_available : "lock screen / app suspend"
    local_encrypted_available --> local_plain_available : "unlock / app foreground"
    local_plain_available --> remote_archive_only : "enforceStorageBudget"
    remote_archive_only --> local_plain_available : "rehydrate"
    local_plain_available --> deleted_for_me : "user deletes locally"
    local_plain_available --> deleted_for_everyone : "for-everyone delete"
    delivery_store_only --> local_plain_available : "ingest"
    [*] --> delivery_store_only : "MLS message arrived,<br/>not yet ingested"
    remote_archive_only --> unavailable : "backend lost, no local copy"
```

```mermaid
stateDiagram-v2
    direction LR
    [*] --> thumbnail_only
    thumbnail_only --> original_local : "user taps to download"
    original_local --> evicted : "enforceStorageBudget"
    evicted --> download_in_progress : "user taps"
    download_in_progress --> original_local : "verified + decrypted"
    original_local --> deleted : "delete for everyone / for me"
    thumbnail_only --> remote_original : "ingested but not yet downloaded"
    remote_original --> download_in_progress : "user taps / prefetch"
```

```mermaid
stateDiagram-v2
    direction LR
    [*] --> not_archived
    not_archived --> archive_pending : "scheduler picks up"
    archive_pending --> archive_uploaded : "segment + manifest uploaded"
    archive_uploaded --> archive_verified : "Merkle root re-checked"
    archive_verified --> archive_compacted : "checkpoint subsumes deltas"
```

```mermaid
stateDiagram-v2
    direction LR
    [*] --> not_backed_up
    not_backed_up --> backup_pending : "event journaled"
    backup_pending --> backup_uploaded : "segment uploaded to sink"
    backup_uploaded --> backup_manifest_committed : "manifest signed + uploaded"
    backup_manifest_committed --> backup_expired : "compacted into checkpoint"
```

---

## 6. Search Engine Architecture

The search pipeline runs fully on-device. Cold buckets either
arrive as locally cached encrypted shards or are fetched on demand
by coarse bucket; the query string itself never crosses the FFI
boundary as a server request.

```mermaid
flowchart TD
    Q["User query"]
    LD["Language detection<br/>(optional, tokenizer hint)"]
    NORM["ICU normalize<br/>(NFKC + case fold + script-aware)"]
    TOK["ICU tokenize"]

    subgraph Local["Local fan-out"]
        FTS["FTS5<br/>(exact + prefix + BM25,<br/>tokenize = 'icu')"]
        FZ["Fuzzy index<br/>(trigram for Latn / Cyrl,<br/>bigram for CJK)"]
        STRUCT["Structured index<br/>(sender, date, conversation)"]
        EMB["Multilingual embedding<br/>(multilingual-e5-small)"]
        HNSW["HNSW vector index"]
    end

    Cold["Cold bucket?<br/>fetch encrypted shard<br/>by coarse bucket"]
    Decrypt["Decrypt shard locally"]
    Merge["Merge candidates"]
    Rerank["Rerank<br/>(see PROPOSAL.md §7.5)"]
    Out["Skeleton results<br/>(hydrate on tap)"]

    Q --> LD --> NORM --> TOK
    TOK --> FTS
    TOK --> FZ
    Q --> STRUCT
    Q --> EMB --> HNSW
    FTS -->|"index missing locally"| Cold
    FZ -->|"index missing locally"| Cold
    HNSW -->|"index missing locally"| Cold
    Cold --> Decrypt
    Decrypt --> Merge
    FTS --> Merge
    FZ --> Merge
    STRUCT --> Merge
    HNSW --> Merge
    Merge --> Rerank --> Out
```

---

## 7. Crypto Architecture

Every key derives from `K_user_master` via labelled HKDF-SHA256.
The crypto module knows nothing about messages, media, or search;
it serves AEAD-sealed bytes against typed key handles.

```mermaid
flowchart TD
    UM["K_user_master"]
    AR["K_archive_root"]
    BR["K_backup_root"]
    SR["K_search_root"]
    PR["K_profile_private_data"]

    AS["K_archive_segment(segment_id)"]
    AM["K_archive_manifest(manifest_id)"]
    BS["K_backup_segment(segment_id)"]
    BM["K_backup_manifest(manifest_id)"]
    TS["K_text_index_shard(shard_id)"]
    VS["K_vector_index_shard(shard_id)"]
    MS["K_media_index_shard(shard_id)"]

    UM --> AR
    UM --> BR
    UM --> SR
    UM --> PR
    AR --> AS
    AR --> AM
    BR --> BS
    BR --> BM
    SR --> TS
    SR --> VS
    SR --> MS

    LDB["K_local_db<br/>(SQLCipher key)"]
    DSK["Device signing key<br/>(Ed25519)"]
    UM_W["wrapped K_user_master<br/>(Keychain / Keystore)"]

    LDB -.- DSK -.- UM_W
```

Per-media-object encryption is a separate path with its own
random key:

```mermaid
flowchart LR
    Plain["Media plaintext"]
    KAsset["K_asset = random 256-bit"]
    Wrapped_local["wrapped by K_local_db"]
    Wrapped_archive["wrapped by K_archive_root"]
    Wrapped_backup["wrapped by K_backup_root"]
    MLS["MLS application message<br/>(K_asset + descriptor)"]
    Local["Local cache (chunked AEAD)"]
    Archive["Archive segment (chunked AEAD)"]
    Backup["Backup segment (chunked AEAD)"]

    Plain --> Local
    KAsset --> Local
    KAsset --> MLS
    KAsset --> Wrapped_local
    KAsset --> Wrapped_archive
    KAsset --> Wrapped_backup
    Wrapped_archive --> Archive
    Wrapped_backup --> Backup
```

ZK Object Fabric backups use Pattern C, derived deterministically
from the plaintext + tenant ID. The Rust path must produce
bit-identical output to the Go SDK at
`kennguy3n/zk-object-fabric/encryption/client_sdk/`:

```mermaid
flowchart LR
    PT["Plaintext"]
    H["BLAKE3(plaintext)"]
    DEK["HKDF-SHA256<br/>secret = BLAKE3,<br/>salt = tenant_id,<br/>info = zkof-convergent-dek-v1"]
    NC["HKDF-SHA256<br/>secret = DEK,<br/>info = zkof-nonce-v1 || u64_BE(idx)"]
    AEAD["XChaCha20-Poly1305<br/>(AAD = empty,<br/>16 MiB chunks)"]
    Frame["[24B nonce][4B BE len][ciphertext+tag]"]
    CT["Ciphertext"]

    PT --> H --> DEK
    DEK --> NC
    DEK --> AEAD
    NC --> AEAD
    PT --> AEAD
    AEAD --> Frame --> CT
```

---

## 8. Archive and Offload Architecture

### 8.1 Archive segment build and upload

```mermaid
sequenceDiagram
    participant Core as "Rust core (archive engine)"
    participant Cr as "crypto"
    participant Tr as "transport"
    participant BE as "KChat backend"

    Core->>Core: "read archive event journal since cursor"
    Core->>Core: "group by (conversation_id, time_bucket)"
    Core->>Core: "build CBOR payload, zstd compress"
    Core->>Cr: "AEAD seal with K_archive_segment"
    Cr-->>Core: "ciphertext + Merkle root"
    Core->>Tr: "blob init (chunked upload)"
    Tr->>BE: "POST /v1/blobs/init"
    BE-->>Tr: "blob_id"
    Core->>Tr: "upload chunks"
    Tr->>BE: "PUT /v1/blobs/{blob_id}/chunks/{idx}"
    Core->>Tr: "commit blob"
    Tr->>BE: "POST /v1/blobs/{blob_id}/commit"
    BE-->>Tr: "merkle_root"
    Core->>Core: "verify backend Merkle root == local"
    Core->>Cr: "build & seal manifest gen N+1"
    Cr-->>Core: "manifest ciphertext"
    Core->>Tr: "upload manifest"
    Core->>Core: "mark archive_state = archive_verified;<br/>advance cursor"
```

### 8.2 Offload / eviction

```mermaid
sequenceDiagram
    participant Sys as "OS / scheduler"
    participant Off as "offload engine"
    participant DB as "local_store"

    Sys->>Off: "enforceStorageBudget(reason)"
    Off->>DB: "compute storage usage + headroom"
    Off->>DB: "build candidate set<br/>(verified archives, not pinned, not active)"
    Off->>DB: "score each candidate<br/>(see PROPOSAL.md §5.4)"
    loop "until headroom reclaimed"
        Off->>DB: "evict next candidate per priority order"
    end
    Off-->>Sys: "OffloadResult { freed_bytes, evicted_count }"
```

### 8.3 Rehydration

```mermaid
sequenceDiagram
    participant UI as "UI"
    participant Core as "Rust core"
    participant DB as "local_store"
    participant Tr as "transport"
    participant BE as "KChat backend"

    UI->>Core: "scrolled to / tapped message_id"
    Core->>DB: "read skeleton + body_state"
    alt "body local"
        Core-->>UI: "render plaintext"
    else "body cold"
        Core->>Tr: "fetch archive segment by segment_id"
        Tr->>BE: "GET /v1/archive/segments/{segment_id}"
        BE-->>Tr: "encrypted segment chunks"
        Core->>Core: "verify per-chunk SHA-256 + Merkle root"
        Core->>Core: "AEAD decrypt with K_archive_segment"
        Core->>DB: "update body in place"
        Core-->>UI: "render plaintext (no scroll jump)"
    end
```

### 8.4 Prefetch window

```mermaid
flowchart LR
    Vis["Visible viewport<br/>(rows currently on screen)"]
    Win["Prefetch window<br/>(viewport &plusmn; 100&ndash;150 messages)"]
    Q["Hydration queue<br/>P0 tap &gt; P1 media open &gt; P2 visible &gt;<br/>P3 prefetch &gt; P4 background restore &gt; P5 idle fill"]

    Vis --> Q
    Win --> Q
    Q --> NetIO["chunk fetch + decrypt"]
```

---

## 9. Backup and Restore Architecture

### 9.1 Incremental backup

```mermaid
sequenceDiagram
    participant Sched as "scheduler"
    participant Bk as "backup engine"
    participant Cr as "crypto"
    participant Sink as "sink (iCloud / Auto Backup /<br/>SAF / ZK Object Fabric)"

    Sched->>Bk: "run_incremental_backup(reason)"
    Bk->>Bk: "load last manifest cursor"
    Bk->>Bk: "read backup_event_journal since cursor"
    Bk->>Bk: "group into per-type, per-bucket segments"
    loop "per segment"
        Bk->>Bk: "zstd compress"
        Bk->>Cr: "AEAD seal with K_backup_segment"
        Cr-->>Bk: "ciphertext"
        Bk->>Sink: "upload (resume from prior chunk receipt if any)"
    end
    Bk->>Cr: "build, sign, seal manifest gen N+1"
    Cr-->>Bk: "manifest ciphertext + Ed25519 signature"
    Bk->>Sink: "upload manifest (last)"
    Bk-->>Sched: "BackupResult"
```

### 9.2 Skeleton-first restore

```mermaid
sequenceDiagram
    participant App as "KChat app"
    participant Core as "Rust core (restore engine)"
    participant Sink as "backup sink"
    participant BE as "KChat backend"
    participant UI as "UI"

    App->>Core: "restore_from_backup(source)"
    Core->>BE: "register device"
    Core->>Core: "recover K_user_master<br/>(D2D / recovery key / passphrase)"
    Core->>Sink: "fetch latest manifest"
    Core->>Core: "verify signature + previous_manifest_hash chain"
    Core->>Sink: "fetch conversation list segment"
    Core-->>UI: "skeleton_restored &mdash; render conversation list"
    Core->>Sink: "fetch timeline_skeleton segments"
    Core-->>UI: "skeletons render in each conversation"
    Core->>Sink: "fetch search_index_shard segments"
    Core-->>UI: "search_restored &mdash; search returns hits"
    Core->>Sink: "fetch recent message_body segments"
    Core-->>UI: "recent_messages_restored"
    Core->>Sink: "lazy media (on tap, on prefetch)"
```

### 9.3 Restore state machine

```mermaid
stateDiagram-v2
    direction LR
    [*] --> identity_restored
    identity_restored --> root_keys_unwrapped
    root_keys_unwrapped --> manifest_verified
    manifest_verified --> skeleton_restored
    skeleton_restored --> search_restored
    search_restored --> recent_messages_restored
    recent_messages_restored --> media_lazy_restore_enabled
    media_lazy_restore_enabled --> full_restore_complete
```

### 9.4 Manifest chain verification

```mermaid
flowchart LR
    GenN["manifest gen N<br/>signature OK,<br/>previous_manifest_hash &rarr; gen N-1"]
    GenN1["manifest gen N-1"]
    GenN2["manifest gen N-2"]
    Genesis["genesis hash<br/>(device-attested)"]

    GenN -->|"prev"| GenN1 -->|"prev"| GenN2 -->|"prev"| Genesis
    GenN -->|"break in chain &rArr; alert"| GenN1
```

A break in the chain (a `previous_manifest_hash` mismatch or
signature failure) halts restore and surfaces a recoverable error
to the UI; restore never silently re-roots.

---

## 10. Transport Layer

The transport client is a thin async HTTP client that speaks the
KChat backend API. It does not hold any plaintext; every payload
it sends or receives is already AEAD-sealed by the crypto module.

### 10.1 Chunked encrypted blob upload

```mermaid
sequenceDiagram
    participant Core as "core"
    participant Tr as "transport"
    participant BE as "backend"

    Core->>Tr: "init blob (size, blob_class, expected_merkle_root)"
    Tr->>BE: "POST /v1/blobs/init"
    BE-->>Tr: "blob_id, upload_token"
    loop "per chunk"
        Core->>Tr: "upload chunk(idx, ciphertext, sha256)"
        Tr->>BE: "PUT /v1/blobs/{blob_id}/chunks/{idx}"
        BE-->>Tr: "chunk_receipt"
    end
    Core->>Tr: "commit"
    Tr->>BE: "POST /v1/blobs/{blob_id}/commit"
    BE-->>Tr: "computed merkle_root"
    Core->>Core: "verify merkle_root == local"
```

### 10.2 Range download

```mermaid
sequenceDiagram
    participant Core as "core"
    participant Tr as "transport"
    participant BE as "backend"

    Core->>Tr: "fetch blob {blob_id} range [from..to]"
    Tr->>BE: "GET /v1/blobs/{blob_id}?range=from-to"
    BE-->>Tr: "ciphertext bytes"
    Core->>Core: "verify per-chunk AEAD tag + SHA-256"
    Core->>Core: "decrypt with K_archive_segment / K_asset / etc."
```

### 10.3 Archive manifest fetch and segment download

```mermaid
sequenceDiagram
    participant Core as "core"
    participant Tr as "transport"
    participant BE as "backend"

    Core->>Tr: "list archive manifests after_generation = N"
    Tr->>BE: "GET /v1/archive/manifests?after_generation=N"
    BE-->>Tr: "manifest list (encrypted)"
    Core->>Core: "decrypt manifests, walk previous_manifest_hash"
    loop "per needed segment"
        Core->>Tr: "fetch segment {segment_id}"
        Tr->>BE: "GET /v1/archive/segments/{segment_id}"
        BE-->>Tr: "ciphertext"
        Core->>Core: "AEAD decrypt with K_archive_segment"
    end
```

### 10.4 Delivery message fetch (cursor-based)

```mermaid
sequenceDiagram
    participant Core as "core"
    participant Tr as "transport"
    participant BE as "backend"

    Core->>Tr: "ingest_remote_messages(conversation_id, after_cursor)"
    Tr->>BE: "GET /v1/mls/messages?conversation_id=&amp;after_cursor="
    BE-->>Tr: "MLS application messages + new cursor"
    Core->>Core: "MLS-decrypt (KChat MLS layer)"
    Core->>Core: "persist message_skeleton, message_body, media_asset"
    Core->>Core: "write backup + archive events"
    Core->>Core: "update FTS / fuzzy / vector / media indexes"
```

---

## 11. Platform Integration

### 11.1 iOS

| Concern                    | API / Mechanism                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| FFI binding                | UniFFI &rarr; generated Swift package consumed by KChat.app and any iOS extensions sharing the local store   |
| Keys                       | Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`); biometric-protected key for higher-tier ops   |
| Background work            | `BGTaskScheduler` (`BGProcessingTask` for backup / archive / index maintenance)                              |
| OCR                        | `VNRecognizeTextRequest` (multilingual; 18+ languages supported in current iOS)                              |
| ML inference               | Core ML (preferred) or ONNX Runtime CoreML EP                                                                |
| iCloud backup              | App's iCloud container file storage for encrypted backup files                                               |
| Audio session              | Foreground for live recording; background-friendly transcription via Whisper-tiny / Whisper-small            |

### 11.2 Android

| Concern                    | API / Mechanism                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| FFI binding                | JNI &rarr; idiomatic Kotlin façade in `crates/android-bridge`                                                |
| Keys                       | Android Keystore (StrongBox if available); biometric gate via `BiometricPrompt` when configured              |
| Background work            | `WorkManager` (constraints: charging, unmetered network, thermal-headroom)                                   |
| OCR                        | ML Kit Text Recognition v2 (multilingual; 50+ languages including CJK)                                       |
| ML inference               | ONNX Runtime NNAPI EP, fallback to CPU EP                                                                    |
| Auto Backup                | `BackupAgent` storing recovery envelopes + manifest pointers under the 25 MB cap                             |
| Large Backup               | Large Backups API where available                                                                            |
| Storage Access Framework   | User-selected cloud / document provider for large encrypted backup files                                     |

### 11.3 macOS

| Concern                    | API / Mechanism                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| FFI binding                | Native Rust (no FFI bridge needed)                                                                           |
| Keys                       | Keychain                                                                                                     |
| Background work            | `NSBackgroundActivityScheduler` + cooperative scheduler                                                      |
| OCR                        | `VNRecognizeTextRequest` (Vision)                                                                            |
| ML inference               | Core ML or ONNX Runtime CoreML EP                                                                            |
| Search integration         | Optional Spotlight integration for app-internal search anchors                                               |

### 11.4 Windows

| Concern                    | API / Mechanism                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| FFI binding                | Native Rust                                                                                                  |
| Keys                       | DPAPI (`CryptProtectData`) bound to the user profile; TPM-backed via `NCryptCreatePersistedKey` if available |
| Background work            | Background Tasks / Task Scheduler integration                                                                |
| OCR                        | `Windows.Media.Ocr` (multilingual where the Language Pack is installed); Tesseract fallback                  |
| ML inference               | ONNX Runtime CPU EP; **no GPU assumption**; INT8 quantized models essential                                  |
| Search integration         | Optional Windows Search integration for app-internal anchors                                                 |

---

## 12. Data Flow Diagrams

### 12.1 Message receive

```mermaid
flowchart LR
    MLS["MLS<br/>application message"]
    Decrypt["KChat MLS layer<br/>decrypt"]
    Persist["local_store:<br/>insert skeleton, body, media_asset"]
    Index["search:<br/>FTS / fuzzy / vector / media index"]
    ArchEvt["archive:<br/>write archive event"]
    BkEvt["backup:<br/>write backup event"]

    MLS --> Decrypt --> Persist
    Persist --> Index
    Persist --> ArchEvt
    Persist --> BkEvt
```

### 12.2 Message send

```mermaid
flowchart LR
    Compose["UI compose"]
    Outbox["message:<br/>persist to outbox<br/>(local_plain_available)"]
    Index["search:<br/>index outgoing message"]
    MLS["KChat MLS layer<br/>encrypt"]
    Send["transport:<br/>POST /v1/mls/messages"]
    Confirm["delivery confirm"]
    ArchEvt["archive event"]
    BkEvt["backup event"]

    Compose --> Outbox --> Index
    Outbox --> MLS --> Send --> Confirm
    Confirm --> ArchEvt
    Confirm --> BkEvt
```

### 12.3 Media receive

```mermaid
flowchart LR
    Msg["MLS message<br/>(K_asset + descriptor)"]
    Thumb["fetch thumbnail blob"]
    Decrypt["AEAD decrypt with K_asset"]
    Persist["local_store:<br/>media_asset (thumbnail_only),<br/>wrapped K_asset"]
    BG["background:<br/>OCR + image embedding +<br/>(if video) keyframe + Whisper transcript"]
    MIndex["media_search_index +<br/>search_vector"]

    Msg --> Thumb --> Decrypt --> Persist --> BG --> MIndex
```

### 12.4 Search

```mermaid
flowchart LR
    Q["query"]
    Local["local fan-out<br/>(FTS5 + fuzzy + HNSW + structured)"]
    Cold["cold buckets?<br/>fetch encrypted index shard"]
    Decrypt["decrypt shard locally"]
    Merge["merge + rerank"]
    Tap["user taps result"]
    Hyd["hydrate body / media if cold"]

    Q --> Local
    Local --> Cold --> Decrypt --> Merge
    Local --> Merge
    Merge --> Tap --> Hyd
```

### 12.5 Backup

```mermaid
flowchart LR
    Sched["scheduler trigger<br/>(BGTask / WorkManager / app launch)"]
    Journal["read backup_event_journal"]
    Build["build per-segment CBOR payload"]
    Compress["zstd compress"]
    Seal["AEAD seal with K_backup_segment"]
    Upload["upload to selected sink"]
    Manifest["build, sign, seal manifest gen N+1"]
    Commit["mark events included; advance cursor"]

    Sched --> Journal --> Build --> Compress --> Seal --> Upload --> Manifest --> Commit
```

### 12.6 Restore

```mermaid
flowchart LR
    Auth["authenticate account"]
    Reg["register new device"]
    Keys["recover K_user_master"]
    Man["fetch + verify manifest chain"]
    Conv["restore conversation list"]
    Skel["restore timeline skeletons"]
    Idx["restore search index shards"]
    Recent["restore recent bodies"]
    Lazy["lazy media on demand"]

    Auth --> Reg --> Keys --> Man --> Conv --> Skel --> Idx --> Recent --> Lazy
```
