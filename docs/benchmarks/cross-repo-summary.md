# Cross-Repo Benchmark Summary

**License**: Proprietary — All Rights Reserved. See [LICENSE](../../LICENSE).

This document is a standalone benchmark report covering the four
repositories that make up the KChat client-side stack:
multilingual content classification (`slm-guardrail`),
on-device vision (`cv-guard`), the chat UI / SLM demo
(`slm-chat-demo`), and chat storage + search
(`chat-storage-search`).

All runs use the **real** model weights — no mock encoders, no
deterministic fakes, no fallbacks. Each run is repeated on a
common reference VM so the numbers can be compared directly.

## Reference environment

| Item       | Value                                                       |
|------------|-------------------------------------------------------------|
| CPU        | AMD EPYC 7763 64-Core Processor (8 vCPU, AVX2-only Zen 3)   |
| ISA flags  | AVX, AVX2, F16C, FMA, BMI2 (no AVX-512)                     |
| RAM        | 31 GB total                                                 |
| OS         | Ubuntu 22.04.5 LTS, Linux 5.15 x86_64                       |
| Python     | 3.12.8 (CPython)                                            |
| ONNX RT    | 1.25.1 (CPU EP)                                             |
| Node       | v22.12.0                                                    |
| Rust       | rustc 1.95.0                                                |
| llama.cpp  | `prism` branch, built locally with `GGML_NATIVE=ON GGML_OPENMP=ON GGML_AVX2=ON GGML_FMA=ON LLAMA_BUILD_SERVER=ON LLAMA_CURL=OFF CMAKE_BUILD_TYPE=Release` |
| Bonsai-1.7B model | `Bonsai-1.7B.gguf` (Q1_0_g128, 237 MB)               |
| XLM-R model | `models/xlmr.onnx` (107 MB INT8) + `models/xlmr.spm`      |

## Performance summary

| Repo                   | Component                          | Metric                  | Value          | Target       | Status |
|------------------------|------------------------------------|-------------------------|----------------|--------------|--------|
| `slm-guardrail`        | XLM-R pipeline                     | p50 latency             | 2.483 ms       | ≤ 250 ms     | PASS   |
| `slm-guardrail`        | XLM-R pipeline                     | p95 latency             | 2.975 ms       | ≤ 250 ms     | PASS   |
| `slm-guardrail`        | XLM-R pipeline                     | p99 latency             | 3.048 ms       | —            | PASS   |
| `slm-guardrail`        | XLM-R pipeline                     | mean latency            | 2.421 ms       | —            | PASS   |
| `slm-guardrail`        | XLM-R adapter                      | cold-start (first call) | 781.79 ms      | —            | PASS   |
| `slm-guardrail`        | XLM-R pipeline                     | classification accuracy | 27 / 27        | 100 %        | PASS   |
| `cv-guard`             | Bonsai-1.7B SLM (server mode)      | P50 inference           | 2669 ms        | ≤ 100 ms (AVX-512) | N/A on AVX2 host |
| `cv-guard`             | Bonsai-1.7B SLM (server mode)      | P95 inference           | 4679 ms        | —            | —     |
| `cv-guard`             | Bonsai-1.7B SLM (server mode)      | mean inference          | 3006 ms        | —            | —     |
| `cv-guard`             | Bonsai-1.7B SLM (server mode)      | peak RSS                | 85.5 MB        | ≤ 1024 MB    | PASS   |
| `cv-guard`             | Bonsai-1.7B SLM (server mode)      | scenarios using SLM     | 6 / 6          | 6 / 6        | PASS   |
| `cv-guard`             | demo:verify pipeline               | matrix conformance      | 16 / 16        | 16 / 16      | PASS   |
| `slm-chat-demo`        | Translate (single)                 | TTFT                    | 4637 ms        | —            | flat  |
| `slm-chat-demo`        | Smart reply                        | TTFT                    | 2996 ms        | —            | flat  |
| `slm-chat-demo`        | All 10 surfaces                    | tok/s (range)           | 31.95–35.17    | ≥ 5 (short) / ≥ 20 (classifier) | PASS  |
| `slm-chat-demo`        | All 10 surfaces                    | `[MOCK]` outputs        | 0 / 10         | 0 / 10       | PASS   |
| `chat-storage-search`  | `insert_text_message`              | median latency          | 144 µs         | < 20 ms p95  | PASS (~137× under) |
| `chat-storage-search`  | `insert_batch_100`                 | median latency          | 10.04 ms       | < 2 s        | PASS (~199× under) |
| `chat-storage-search`  | `search_recent_messages`           | median latency          | 110 µs         | < 150 ms p95 | PASS (~1340× under) |
| `chat-storage-search`  | `search_with_structured_filters`   | median latency          | 147 µs         | < 150 ms p95 | PASS (~1006× under) |
| `chat-storage-search`  | `fts_prefix_search`                | median latency          | 102 µs         | < 150 ms p95 | PASS (~1456× under) |

## Verification checklist (no mocks)

Every benchmark run is verified against the on-disk JSON to
confirm that the **real** model was used, not a mock or
fallback.

- [x] **`slm-guardrail`** — the XLM-R results JSON has
      `"adapter": "XLMRAdapter"` (not `"MockEncoderAdapter"`)
      and `"model_path": "models/xlmr.onnx"` pointing at a real
      ONNX file. The SentencePiece model
      (`models/xlmr.spm`) is also present.
- [x] **`cv-guard`** — every Bonsai-1.7B run records
      `"used_slm": true` and `"adapter": "ServerLlamaAdapter"`
      against the `prism` llama.cpp server. No scenario reports
      `"fallback_to_safe_default": true` at the scenario level.
- [x] **`slm-chat-demo`** — every surface JSON records
      `"adapter": "LlamaServerAdapter"` and zero `[MOCK]`
      strings across the 10 surfaces. The Ollama fallback is
      not used.
- [x] **`chat-storage-search`** — the criterion benches link
      against the production SQLCipher build with the ICU
      tokenizer enabled. ML-dependent benches that exercise
      embedding and OCR/transcription bridges are tracked
      separately from the local-store and text-search baseline
      in [`phase1-benchmark-results.md`](phase1-benchmark-results.md).

## Per-repo highlights

### `slm-guardrail`

XLM-R adapter cold-start is 782 ms (first call after process
boot, including ONNX session and SPM loader initialization).
Steady-state pipeline overhead (normalize → detectors →
classifier → thresholds) is 2.4 ms mean and 3.0 ms p95, two
orders of magnitude under the 250 ms budget. All 27 sample
cases produce the expected category + severity; confidence
values are stable to ±0.001 across runs.

### `cv-guard`

The SLM server-mode path is the default runtime. On this
AVX2-only Linux VM the P50 inference latency is at the AVX2
floor (~2.7 s P50, ~85 MB peak RSS). The legacy
per-call-subprocess mode is fully retired in favour of the
shared llama.cpp server. The full vision + SLM verification
matrix passes 16 / 16.

### `slm-chat-demo`

TTFT and tok/s are within run-to-run variance of the previous
baseline. Every surface clears the latency floors with a wide
margin (≥ 6× short-assistant, ≥ 1.6× classifier). The unified
llama.cpp sidecar is the primary runtime; Ollama is strictly a
fallback.

### `chat-storage-search`

All 538 workspace tests pass with no `#[ignore]` markers in the
codebase. The multilingual / FTS5 / fuzzy search integration
tests run end-to-end against the bundled SQLCipher build.
Criterion search-latency benches are 100–149 µs, three orders
of magnitude under the §13 budgets in
[DESIGN.md](../DESIGN.md).

## Cross-platform paths not measured here

| Path                                                       | Reason for skip                                           |
|------------------------------------------------------------|-----------------------------------------------------------|
| Apple MLX SLM                                              | Requires macOS + Apple Silicon + `mlx-lm`                 |
| Apple MLX Whisper                                          | Requires macOS + Apple Silicon + `mlx-whisper`            |
| iOS Swift tests                                            | Requires Xcode toolchain (macOS only)                     |
| Windows DirectML EP for ONNX Runtime                       | Requires Windows + DirectML 1.12+                         |
| Android device tests                                       | Requires Android device / emulator                        |

These platform-specific paths are tracked in their respective
per-repo benchmark reports and re-measured on the target
hardware.

## Methodology

Each run uses the production build (`--release` for Rust,
`production` flag for Node, `Release` cmake build for
llama.cpp), the real model weights, and the production
configuration. Test fixtures and mock adapters are explicitly
disabled. Latency numbers are computed by criterion / pytest's
own statistics module from at least 30 samples per metric;
single-sample VM variance is called out in the per-repo
sections.
