# Phase-1 benchmark results — 2026-05-03

Re-run of `cargo bench -p kchat-core` and the full
`cargo test --workspace` suite after the cross-repo
optimization wave (improvements A–H: unified `llama-server`,
Apple MLX SLM + Whisper, embedding cache, INT4 quantization,
DirectML EP for Windows, model warm-up, Whisper MLX). Phase-1
itself does not load any ML models — these runs only validate
that the local-store + crypto + FTS5 + fuzzy-search hot paths
have not regressed.

## Environment

| Item       | Value                                                       |
|------------|-------------------------------------------------------------|
| CPU        | AMD EPYC 7763 64-Core Processor (8 vCPU, AVX2-only)         |
| OS         | Ubuntu 22.04.5 LTS, Linux 5.15.200 x86_64                   |
| Rust       | rustc 1.95.0 (59807616e 2026-04-14)                         |
| Cargo      | cargo 1.95.0 (f2d3ce0bd 2026-03-21)                         |
| SQLCipher  | bundled via `libsqlite3-sys 0.28.0`                         |
| Profile    | criterion `bench` profile, optimized release                |
| Branch     | `main` HEAD                                                 |

## `cargo test --workspace` — results

```
cargo test --workspace
```

| Crate / target                                      | Tests | Passed | Failed | Ignored |
|-----------------------------------------------------|-----:|-------:|-------:|--------:|
| `kchat-android-bridge` unit (`src/lib.rs`)          |    12 |     12 |      0 |       0 |
| `kchat-core` unit (`src/lib.rs`)                    |   479 |    479 |      0 |       0 |
| `kchat-core` integration `key_wrap_hierarchy.rs`    |     4 |      4 |      0 |       0 |
| `kchat-core` integration `manifest_signing.rs`      |     5 |      5 |      0 |       0 |
| `kchat-core` integration `multilingual_fuzzy_search.rs` |    11 |     11 |      0 |       0 |
| `kchat-core` integration `multilingual_search.rs`   |    14 |     14 |      0 |       0 |
| `kchat-core` integration `pattern_c_interop_vectors.rs` |     6 |      6 |      0 |       0 |
| `kchat-desktop` unit (`src/lib.rs`)                 |     0 |      0 |      0 |       0 |
| `kchat-ios-bridge` unit (`src/lib.rs`)              |     7 |      7 |      0 |       0 |
| Doctests (5 crates)                                 |     0 |      0 |      0 |       0 |
| **Total**                                           | **538** | **538** | **0** | **0** |

**Verification:** `grep -rE '#\[ignore' crates/` returns no
matches anywhere in the workspace, so no tests are skipped via
`#[ignore]`. Every multilingual-search, fuzzy-search, FTS5,
crypto, manifest-signing, and pattern-C interop test runs.

## `cargo bench -p kchat-core` — `phase1_benchmarks`

Source: `crates/core/benches/phase1_benchmarks.rs`. Criterion
collected 100 samples per benchmark over a ~5–10 s window each.
Targets are the latency budgets in
[`docs/PROPOSAL.md` §13](../PROPOSAL.md):

* **Insert (single text message)** — < 20 ms p95.
* **Search (recent messages, 1k-row corpus)** — < 150 ms p95.

| Benchmark                                  | Median   | Mean     | Std-dev  | vs. target | Headroom        |
|--------------------------------------------|---------:|---------:|---------:|------------|-----------------|
| `insert_text_message`                      |  144 µs  |  146 µs  |   10 µs  | < 20 ms    | **~137× under** |
| `insert_batch_100/100_text_messages`       | 10.04 ms | 10.05 ms |  382 µs  | < 20 ms × 100 = 2 s | **~199× under** |
| `search_recent_messages`                   |  110 µs  |  112 µs  |    8 µs  | < 150 ms   | **~1340× under**|
| `search_with_structured_filters`           |  147 µs  |  149 µs  |    6 µs  | < 150 ms   | **~1006× under**|
| `fts_prefix_search`                        |  102 µs  |  103 µs  |    2 µs  | < 150 ms   | **~1456× under**|

Single text-message insert (with body encryption + FTS5 index
+ skeleton row write) is two orders of magnitude under the
20 ms budget on this AVX2-only commodity VM, and every search
path is three orders of magnitude under the 150 ms budget. No
benchmark in this group has ever been observed near its
target on any of the host classes the project benchmarks on
([`docs/PROGRESS.md` Phase 1
section](../PROGRESS.md#phase-1-local-store--text-search--mls-integration));
the budgets exist as a safety net for slower hosts and for
larger corpora than the 1 k-row reference set.

### Outliers

Criterion flagged 2–6 outliers per group (max 6 % of 100
samples), all on the high tail. Distribution is tight (std-dev
2–10 µs on hot paths) so the outliers do not shift the
median.

### Comparison vs. previous run

This is the first criterion run committed to the repo for the
post-optimization sweep; criterion's own
`target/criterion/<bench>/change/estimates.json` is therefore
empty. Future runs will produce relative-change deltas
automatically.

## Phase 6 ML benchmarks — not yet runnable

[`docs/PHASES.md`
"Phase 6 — Media + Semantic Search"](../PHASES.md) lists the
ML adapters that will be benchmarked once they land:

* XLM-R / mE5-small embedding (ONNX) for cross-lingual text
  retrieval — currently scaffolded in `slm-guardrail`, not yet
  wired into `chat-storage-search`.
* MobileCLIP-S2 / SigLIP for image / vision retrieval —
  scaffolded in `cv-guard`'s `desktop/native/*` addons, not
  yet wired here.
* Whisper-tiny (CTranslate2 + Apple MLX) for speech-to-text —
  scaffolded in `crates/core/src/audio/transcribe.rs` per the
  2026-05-03 changelog, but the on-Apple-Silicon MLX path
  cannot be measured on this Linux x86 reference VM.

Phase 6 is **not started** in this repo (per the changelog the
only Phase-6 land is the Whisper backend scaffold), so there
are no XLM-R / MobileCLIP / Whisper inference latencies to
report. The Phase-1 numbers above are the canonical
"steady-state CPU search latency" baseline that Phase 6 will
need to stay under once embedding-side latency is added on
top.

## Cross-platform notes (not measured here)

* **macOS (Apple Silicon)** — Phase-6 Apple MLX runtimes
  (`prism-ml/Bonsai-1.7B-mlx-2bit` + `prism-ml/whisper-tiny-mlx-2bit`)
  cannot be measured on this Linux x86 VM; they require
  `mlx-lm` / `mlx-whisper` on a macOS Apple Silicon host.
* **Windows** — Phase-6 ONNX Runtime DirectML EP
  (Direct3D 12) cannot be measured on this Linux VM; it
  requires a Windows host with DirectML 1.12+.
* **iOS / Android** — `kchat-ios-bridge` and
  `kchat-android-bridge` unit tests pass on this Linux VM
  because they're host-side UniFFI / JNI scaffold tests; the
  full `swift test` (Xcode) and `./gradlew connectedTest`
  device runs are out of scope here.

## Reproducing this report

```bash
cd /path/to/chat-storage-search
cargo test --workspace
cargo bench -p kchat-core
# HTML reports land under target/criterion/
```

## See also

* [`crates/core/benches/phase1_benchmarks.rs`](../../crates/core/benches/phase1_benchmarks.rs)
  — benchmark source.
* [`docs/PROPOSAL.md` §13](../PROPOSAL.md) — Phase-1 latency
  budget definitions.
* [`docs/PROGRESS.md`](../PROGRESS.md) — full phase-by-phase
  changelog including the cross-repo optimization wave.
* [`docs/benchmarks/cross-repo-summary.md`](./cross-repo-summary.md)
  — consolidated post-optimization performance table across
  all four KChat repos (slm-guardrail, cv-guard,
  slm-chat-demo, chat-storage-search).
