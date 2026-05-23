# Local-store and text-search benchmark results

**License**: Proprietary — All Rights Reserved. See [LICENSE](../../LICENSE).

Baseline run of `cargo bench -p kchat-core` and
`cargo test --workspace` for the local-store + crypto + FTS5 +
fuzzy-search hot paths. No ML models are loaded; these benches
validate that the SQLCipher-backed local store and the
multilingual text-search pipeline meet the
[DESIGN.md §13](../DESIGN.md) latency budgets.

## Environment

| Item       | Value                                                       |
|------------|-------------------------------------------------------------|
| CPU        | AMD EPYC 7763 64-Core Processor (8 vCPU, AVX2-only)         |
| OS         | Ubuntu 22.04.5 LTS, Linux 5.15 x86_64                       |
| Rust       | rustc 1.95.0                                                |
| Cargo      | cargo 1.95.0                                                |
| SQLCipher  | bundled via `libsqlite3-sys 0.28.0`                         |
| Profile    | criterion `bench` profile (optimized release)               |
| Branch     | `main`                                                      |

## `cargo test --workspace` — results

```sh
cargo test --workspace
```

| Crate / target                                          | Tests | Passed | Failed | Ignored |
|---------------------------------------------------------|------:|-------:|-------:|--------:|
| `kchat-android-bridge` unit                             |    12 |     12 |      0 |       0 |
| `kchat-core` unit                                       |   479 |    479 |      0 |       0 |
| `kchat-core` integration `key_wrap_hierarchy.rs`        |     4 |      4 |      0 |       0 |
| `kchat-core` integration `manifest_signing.rs`          |     5 |      5 |      0 |       0 |
| `kchat-core` integration `multilingual_fuzzy_search.rs` |    11 |     11 |      0 |       0 |
| `kchat-core` integration `multilingual_search.rs`       |    14 |     14 |      0 |       0 |
| `kchat-core` integration `pattern_c_interop_vectors.rs` |     6 |      6 |      0 |       0 |
| `kchat-desktop` unit                                    |     0 |      0 |      0 |       0 |
| `kchat-ios-bridge` unit                                 |     7 |      7 |      0 |       0 |
| Doctests (5 crates)                                     |     0 |      0 |      0 |       0 |
| **Total**                                               | **538** | **538** | **0** | **0** |

`grep -rE '#\[ignore' crates/` returns no matches anywhere in
the workspace, so no tests are skipped via `#[ignore]`. Every
multilingual-search, fuzzy-search, FTS5, crypto,
manifest-signing, and pattern-C interop test runs.

## `cargo bench -p kchat-core` — `phase1_benchmarks`

Source: `crates/core/benches/phase1_benchmarks.rs`. Criterion
collected 100 samples per benchmark over a ~5–10 s window each.
Targets are the latency budgets in
[DESIGN.md §13](../DESIGN.md):

* **Insert (single text message)** — < 20 ms p95.
* **Search (recent messages, 1k-row corpus)** — < 150 ms p95.

| Benchmark                                  | Median   | Mean     | Std-dev  | vs. target | Headroom        |
|--------------------------------------------|---------:|---------:|---------:|------------|-----------------|
| `insert_text_message`                      |  144 µs  |  146 µs  |   10 µs  | < 20 ms    | **~137× under** |
| `insert_batch_100/100_text_messages`       | 10.04 ms | 10.05 ms |  382 µs  | < 20 ms × 100 = 2 s | **~199× under** |
| `search_recent_messages`                   |  110 µs  |  112 µs  |    8 µs  | < 150 ms   | **~1340× under**|
| `search_with_structured_filters`           |  147 µs  |  149 µs  |    6 µs  | < 150 ms   | **~1006× under**|
| `fts_prefix_search`                        |  102 µs  |  103 µs  |    2 µs  | < 150 ms   | **~1456× under**|

Single text-message insert (with body encryption + FTS5 index +
skeleton row write) is two orders of magnitude under the 20 ms
budget on this AVX2-only commodity VM, and every search path is
three orders of magnitude under the 150 ms budget. The budgets
exist as a safety net for slower hosts and for larger corpora
than the 1k-row reference set.

### Outliers

Criterion flagged 2–6 outliers per group (max 6 % of 100
samples), all on the high tail. Distribution is tight (std-dev
2–10 µs on hot paths) so the outliers do not shift the median.

### Comparison vs. previous run

This is the baseline run; future runs will generate relative
deltas automatically via criterion's
`target/criterion/<bench>/change/estimates.json`.

## Cross-platform notes

Cross-platform benchmarks (macOS / Apple Silicon, Windows
DirectML, iOS, Android) are tracked separately on their target
hardware; they cannot be measured on this Linux x86 reference
VM.

## Reproducing this report

```sh
cd /path/to/chat-storage-search
cargo test --workspace
cargo bench -p kchat-core
# HTML reports land under target/criterion/
```

## See also

* [`crates/core/benches/phase1_benchmarks.rs`](../../crates/core/benches/phase1_benchmarks.rs)
  — benchmark source.
* [DESIGN.md §13](../DESIGN.md) — latency budget definitions.
* [cross-repo-summary.md](./cross-repo-summary.md) — consolidated
  performance table across all four KChat repos.
