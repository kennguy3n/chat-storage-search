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
//!
//! See `docs/PHASES.md` Phase 6 for the schedule.

pub mod embeddings;
