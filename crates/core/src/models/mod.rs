//! `models` module — on-device ML model management.
//!
//! `docs/PROPOSAL.md §7.6` lays out the on-device ML model set:
//! `XLM-R` for multilingual text embeddings, `MobileCLIP-S2` for
//! image / video embeddings, and `Whisper-base` / `Whisper-tiny`
//! for audio transcription. Phase 6 wires these models to ONNX
//! Runtime via the [`ort`](https://crates.io/crates/ort) crate and
//! lands the model manager (lazy download, versioning, INT8 / INT4
//! quantization, integrity-checked artifacts).
//!
//! The submodules below land incrementally:
//!
//! * [`embeddings`] — XLM-R text-embedding seam **and** the
//!   cross-pipeline [`embeddings::EmbeddingCache`] trait
//!   (`docs/PROPOSAL.md §7.6.1`). The trait surface and the default
//!   `search_vector`-backed implementation land now so the
//!   guardrail (`kennguy3n/slm-guardrail`) and search pipelines
//!   can start sharing one XLM-R inference per message ahead of
//!   the Phase 6 ONNX integration.
//! * [`embeddings_onnx`] — Phase 6 scaffold: the XLM-R
//!   `ort::Session` creator with the best-effort DirectML → CPU
//!   execution-provider state machine for Windows
//!   (`docs/ARCHITECTURE.md §11.4`). The EP-selection function is
//!   pure Rust so it is unit-tested on any host; the actual
//!   `ort::Session` glue is gated behind the `onnx-runtime` cargo
//!   feature.
//! * [`clip`] — Phase 6 scaffold: the MobileCLIP-S2
//!   `ort::Session` creator. Re-uses the EP-selection state
//!   machine from [`embeddings_onnx`] for the same DirectML → CPU
//!   pattern.
//! * [`whisper`] — Phase 6 scaffold: the Apple-MLX-preferred
//!   Whisper backend selector. On Apple Silicon (`macOS` / `iOS`
//!   `aarch64`) `Whisper-base` runs through MLX
//!   ([`mlx-community/whisper-base-mlx`](https://huggingface.co/mlx-community/whisper-base-mlx)),
//!   which routes to the Neural Engine; everywhere else the
//!   pipeline falls back to ONNX Runtime CPU EP. The backend
//!   selection mirrors the DirectML → CPU pattern in
//!   [`embeddings_onnx`] / [`clip`] but pivots on
//!   `cfg(target_arch = "aarch64", target_os = "macos" | "ios")`
//!   instead of `cfg(target_os = "windows")`.
//!
//! See `docs/PHASES.md` Phase 6 for the schedule.

pub mod clip;
pub mod embeddings;
pub mod embeddings_onnx;
pub mod whisper;
