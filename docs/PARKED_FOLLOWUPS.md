# KChat Storage & Search — Parked Follow-Ups

**License**: Proprietary — All Rights Reserved. See [LICENSE](../LICENSE).

This document tracks technical follow-ups identified during code
review of merged PRs that were deliberately deferred rather than
addressed inline. Each entry records the originating finding, the
trade-off that justified parking it, and the conditions under
which it should be picked up. The companion documents
[DESIGN.md](DESIGN.md) and [ARCHITECTURE.md](ARCHITECTURE.md)
describe the system the follow-ups relate to.

Items here are NOT bugs in the merged code — each is a known
limitation, defense-in-depth opportunity, performance improvement,
or future-API placeholder with an explicit "do not address in
isolation" rationale.

---

## 1. ONNX Runtime EP plumbing: `_with_ep` parameter is a no-op

**Origin**: PR #68 — `models: extract shared create_onnx_session
helper (DirectML/CPU fallback dedupe)`. Devin Review finding on
`crates/core/src/models/clip.rs:129`.

**Surface**: `create_mobileclip_session_with_ep`
(`crates/core/src/models/clip.rs`),
`create_xlmr_session_with_ep`
(`crates/core/src/models/embeddings_onnx.rs`), and
`create_whisper_session_with_ep`
(`crates/core/src/models/whisper_onnx.rs`) all accept an
`OnnxExecutionProvider` argument and discard it with `let _ =
ep;`, delegating to the generic session creator that re-runs
`select_provider` internally.

**Caller**: `crates/desktop/src/ml_ep.rs:169`
(`create_desktop_session`) walks `host_fallback_chain()` to
choose an EP and passes it through, only for it to be ignored.

**Trade-off**: Today the fallback chain only contains DirectML
and CPU, both of which the generic `select_provider` already
handles via the `OrtDirectMlProbe`. The plumbing parity is
defensive — the parameter exists on the seam so future EPs
(CoreML / NNAPI / OpenVINO) can be wired through without
touching every call site. Wiring the parameter today before
those EPs land would either (a) re-run the same DirectML/CPU
state machine twice, or (b) require introducing a no-op
"caller-requested EP" branch that has no behavioral effect.

**Unblock condition**: any of CoreML / NNAPI / OpenVINO support
landing in `crates/core/src/models/`. When that lands, the
helper should honor the caller-supplied EP first and fall back
to `select_provider` if the requested EP refuses to register.

**Optional intermediate step**: emit a debug log when the
caller-supplied `ep` differs from what `select_provider` chose,
so the no-op is visible in production traces.

---

## 2. PR-7 residual: `onig_sys` cross-compile validation + tokenizer telemetry

**Origin**: PR #7 (XLM-R tokenizer integration) review residuals
that did not block the merge.

**Surface**:

- `onig_sys` (the Onigmo regex backend pulled in transitively
  via `tokenizers` for some SentencePiece configurations) has
  not been validated against the full mobile-bridge cross-compile
  matrix (iOS arm64-sim, iOS device, Android arm64-v8a,
  Android armeabi-v7a, Windows MSVC). Today's CI only covers
  the four targets the desktop crate ships against
  (`android-aarch64`, `macos-aarch64`, `linux-x86_64`,
  `windows-x86_64`). The bridge crates compile on-host as
  libraries but their full target matrix is gated behind the
  mobile-bridge CI job that has not yet landed.

- `OnnxTextEmbedder::embed` (`crates/core/src/models/embeddings_onnx.rs`)
  silently absorbs `tokenizer.decode` failures via `.ok()`,
  losing diagnostic granularity when a tokenizer mis-trains
  against a corpus. Should chain `.inspect_err(|e| tracing::warn!(...))`
  once the mobile-bridge target matrix has been validated to
  surface these in production logs.

**Trade-off**: Adding cross-compile validation without the CI
matrix to run it produces test code that nobody runs — pure
review noise. Adding tracing telemetry without first verifying
the tokenizer doesn't have a systemic failure mode on a mobile
target risks flooding production logs.

**Unblock condition**: mobile-bridge cross-compile CI matrix
landing (iOS sim + device, Android arm64-v8a + armeabi-v7a,
Windows MSVC), at which point `onig_sys` builds get exercised
nightly and any `tokenizer.decode` failure rate becomes a
measurable signal worth instrumenting.

---

## 3. `send_media` synchronous-in-lock ML migration onto compute/commit split

**Origin**: PR #66 — `core: wire OcrBridge through media-ingest
pipeline`. Devin Review finding #3 on `crates/core/src/core_impl.rs:4838`:
"OCR runs synchronously inside the db_writer mutex + SAVEPOINT".

**Surface**: `send_media` (`crates/core/src/core_impl.rs`)
holds the `db_writer` mutex across calls to
`maybe_run_ocr_on_image_message`, `maybe_embed_image_message`,
`maybe_transcribe_audio_message`, `maybe_extract_document_pages`,
and `maybe_embed_video_keyframes`. ML inference inside the lock
can take hundreds of milliseconds (OCR) to tens of seconds
(Whisper transcription), blocking concurrent `send_text` /
`search` / `ingest` writes for the duration.

**Why this is now actionable**: PR #69 introduced the
`compute_post_rehydration_*` / `commit_post_rehydration_ml`
split for the rehydration path, which already runs the same
five pipelines outside the writer lock. The send path can
migrate onto the same compute/commit split:

1. Restructure `send_media` to call the compute helpers BEFORE
   acquiring the writer mutex, against the in-memory plaintext
   it already has.
2. Acquire the writer mutex, run the existing SAVEPOINT,
   commit the message body / asset rows, then call
   `commit_post_rehydration_ml` (or a sibling
   `commit_send_media_ml`) to fan structured ML outputs into
   the search indexes.

**Trade-off (why this is parked)**: The five `maybe_*` helpers
have at least 28 existing tests directly asserting the
synchronous semantics (e.g., "after `send_media` returns, the
OCR row must be in `media_search_index`"). Migrating
`send_media` onto the compute/commit split requires either:

- Re-touching all 28 tests to await ML commit (architecturally
  the wrong direction — sent media should be queryable
  immediately when the sender pulls up their own conversation), or
- Preserving send-side synchronous semantics by gating the
  compute/commit split behind a `mode: SendOrRehydrate` enum
  that runs compute INSIDE the lock for send and OUTSIDE for
  rehydration — which collapses back to the current pathology
  on the send side.

Neither resolves Devin Review's concern; both add complexity.
The actual fix is a deeper architectural change: introduce a
`ResourceGate`-aware deferred-ML queue that runs even sent-media
ML asynchronously, with the user's UI showing a transient
"indexing…" state until commit. That is an out-of-scope product
decision, not a refactor.

**Unblock condition**: product decision on whether sent-media
ML is allowed to be deferred (UI shows "indexing…" briefly), or
whether send-side ML must remain synchronous and we accept the
lock-hold cost as the price of immediate consistency.

---

## 4. Centralized `insert_search_fts_row` helper with idempotency guard

**Origin**: PR #69 — `core: post-rehydration ML fan-out runs
OCR/whisper/extraction outside writer lock`. Devin Review
finding #5 on `crates/core/src/core_impl.rs:3689`:
"FTS INSERT can produce duplicate rows on repeated rehydration".

**Surface**: Both `commit_post_rehydration_ml` (the new path)
and `maybe_run_ocr_on_image_message` / `maybe_transcribe_audio_message`
/ `maybe_extract_document_pages` (the existing send path) use
plain `INSERT INTO search_fts(...)` without `ON CONFLICT` /
`OR IGNORE` guards. Repeated invocation (e.g., rehydration
retry after a phase-4b lock failure) silently accumulates
duplicate FTS rows for the same `(message_id, text_content)`
tuple.

**Trade-off**: Today's behavior is harmless — the search engine
treats `search_fts` as content-addressed by `(message_id,
text_content)` and de-duplicates results at query time. The
duplicates only matter when:

1. FTS query plans regress on duplicate rows (would require a
   benchmark to demonstrate), or
2. A future maintenance / compaction pass tries to count rows
   per message and sees inflated counts.

The asymmetry (embedding cache has a `cache.get`-then-`put`
guard for idempotency; FTS does not) is mildly inconsistent but
the comment at `crates/core/src/core_impl.rs:3200-3205`
explicitly documents the convention.

**Unblock condition**: introduce a centralized
`insert_search_fts_row(db, message_id, conversation_id,
sender_id, created_at_ms, text_content)` helper that performs
`INSERT OR IGNORE` (or its `ON CONFLICT DO NOTHING` equivalent),
migrate all 8 current call sites to it, and remove the
"duplicates harmless" comment block. Single PR, ~80 lines of
diff, no behavior change in the steady state.

**Optional bonus**: same PR could introduce
`insert_search_fuzzy_row` for symmetric treatment of the fuzzy
index (which has similar duplicate-on-retry behavior, just less
visible).

---

## 5. Re-index-media API for backfilling phase-4b best-effort skips

**Origin**: PR #69 — `core: post-rehydration ML fan-out runs
OCR/whisper/extraction outside writer lock`. Devin Review
finding #1 on `crates/core/src/core_impl.rs:2704`:
"Best-effort Phase 4b means search indexes can be permanently
missing for rehydrated media".

**Surface**: `rehydrate_media_for_message` (`crates/core/src/core_impl.rs`)
runs phase 4b's ML commit step inside `if let Ok(db) = ...`,
intentionally absorbing a poisoned mutex so a panic in another
writer thread during the long-running phase 4a ML inference
window cannot cause the freshly-decrypted plaintext to be lost.
The trade-off is that ML-derived search indexes (OCR text,
transcription, document extraction, video keyframe embeddings,
XLM-R embeddings) can be permanently missing for an asset once
phase 3 has committed the `Evicted → OriginalLocal` transition
— subsequent `rehydrate_media_for_message` calls hit
`prepare_rehydration`'s "already original_local" rejection.

**Trade-off (why this is parked)**: A public re-index-media API
is a non-trivial design decision:

- **Surface**: a new public method on `CoreImpl` (e.g.,
  `reindex_media_search(message_id) -> Result<()>`) that
  re-runs the compute/commit pipelines against the
  already-local plaintext.
- **Permissions**: who can call it? UI-driven user action?
  Background-job sweep that detects assets in `OriginalLocal`
  state with empty `media_search_index` rows? Both?
- **Lock semantics**: re-using the existing compute/commit
  split is straightforward; the question is whether phase 4b's
  best-effort contract should be tightened on the re-index path
  (caller explicitly opted in, so `?` propagation is acceptable).
- **Resource-gating**: should re-index respect the
  `ResourceGate` (defer when battery < 20% / on cellular)?
  Probably yes, but UX-driven re-index requests may want a
  "user is actively waiting" override.

**Unblock condition**: a product / UX decision on (a) whether
re-index is exposed as an explicit user action vs. a
background sweep, and (b) whether the user-initiated path
bypasses resource gating. Once that decision is made, the
implementation is a ~150-line PR: new public method, new
`commit_reindex_ml` variant with stricter error propagation,
new test covering the phase-4b-failed → re-index-recovers cycle.

---

## 6. Per-pipeline cache pre-checks in compute methods

**Origin**: PR #69 — `core: post-rehydration ML fan-out runs
OCR/whisper/extraction outside writer lock`. Devin Review
finding #6 on `crates/core/src/core_impl.rs:3534`:
"Wasted ML inference on already-cached embeddings during
rehydration".

**Surface**: `compute_post_rehydration_image_embed`,
`compute_post_rehydration_ocr`,
`compute_post_rehydration_transcribe`, and
`compute_post_rehydration_document` (all in
`crates/core/src/core_impl.rs`) run full ML inference even when
the embedding / FTS / `media_search_index` row already exists
in the database for that `message_id`. The commit step's
`cache.get`-then-`put` guards prevent duplicate writes, but the
inference cost is paid regardless.

**Trade-off**: The compute methods deliberately hold no
`&LocalStoreDb` reference — that's what allows them to run
outside the writer mutex during phase 4a. Pre-checking the
cache from inside the compute methods requires either:

- Passing a read-only DB snapshot (a `&LocalStoreReader` from
  the existing read-pool) through the compute helpers, OR
- Performing the cache pre-check before entering phase 4a in
  `rehydrate_media_for_message` and short-circuiting the
  compute call entirely when the cache is warm.

The second approach is cleaner — the rehydration caller
already holds a writer-lock guard in phase 1, so it can issue
the cache lookups while it's reading the skeleton metadata,
without adding a new DB-access surface to the compute helpers.

**When this matters**: rehydration of an asset that was
previously rehydrated and then evicted back to remote storage
(an eviction-cycle loop). Today's behavior pays the
full ML inference cost on every cycle even though the cached
rows are already present. Per-asset cost is bounded (one
inference per rehydration event), but cumulative cost on a
chatty channel with frequent evictions could add up on a
resource-constrained device.

**Unblock condition**: implement the pre-check inside phase 1
of `rehydrate_media_for_message`, alongside the existing
skeleton-metadata snapshot. ~50 lines of diff, no public API
change, no test churn — the existing
`commit_post_rehydration_ml_is_idempotent_for_xlmr_cache` test
already covers the steady-state behavior.

This is the smallest of the six items and the lowest-risk
candidate for a quick-win PR once any of items 3 / 4 / 5
is being touched (so the compute/commit pipeline gets a
second pair of eyes anyway).

---

## Conventions

- An item leaves this document only when its unblock condition
  fires AND a PR landing the fix has merged to main.
- New parked items append a new section; do not renumber
  existing items, since the numbers appear in code comments and
  Devin Review thread replies that reference this document.
- Each section MUST record: (1) origin PR + finding, (2)
  surface (file paths), (3) trade-off explaining the park, (4)
  unblock condition.
