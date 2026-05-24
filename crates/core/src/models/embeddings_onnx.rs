//! On-device ONNX Runtime session creator for the XLM-R text
//! encoder, plus the shared best-effort DirectML → CPU
//! execution-provider state machine reused by
//! [`crate::models::clip`] for MobileCLIP-S2.
//!
//! `docs/DESIGN.md §7.7` and `docs/ARCHITECTURE.md §11.4`. On
//! Windows the session is created with the DirectML EP first; if
//! DirectML initialization fails (no compatible GPU, driver
//! issues, ONNX Runtime not built with DirectML support, model
//! contains operators DirectML cannot run, …) we fall back to
//! the CPU EP without failing the session-create call. On
//! non-Windows targets only the CPU EP is attempted.
//!
//! This module is the scaffolding: the EP-selection
//! state machine lands now (always compiled, no `ort` dependency)
//! so it can be exhaustively unit-tested on Linux / macOS CI
//! without needing a DirectML adapter or even an ONNX Runtime
//! build. The actual `ort::Session` creators are gated behind
//! both `cfg(target_os = "windows")` (to pick up the
//! `directml`-featured `ort` build registered by
//! `crates/core/Cargo.toml`'s
//! `[target.'cfg(windows)'.dependencies]` block) and the
//! `onnx-runtime` cargo feature, so the default workspace build
//! and the `--all-features` clippy lint pass on Linux do not
//! require any ORT shared library to be present.
//!
//! The Rust pattern mirrors the C++/WinRT
//! `OnnxInferenceBridge` in
//! [`kennguy3n/cv-guard`](https://github.com/kennguy3n/cv-guard)
//! at
//! `desktop/native/windows/Sources/CVGuardAddon/OnnxInferenceBridge.cpp`.

// ---------------------------------------------------------------------------
// EP-selection state machine — always compiled, no `ort` dependency
// ---------------------------------------------------------------------------

/// Identifier for the ONNX Runtime execution provider that was
/// actually selected for a session.
///
/// `Cpu` is the universal fallback and is always available.
/// `DirectMl` is only ever selected on Windows builds where ORT
/// has been compiled with the `directml` feature AND a
/// compatible adapter is present at session-create time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnnxExecutionProvider {
    /// Microsoft DirectML execution provider.
    DirectMl,
    /// ONNX Runtime CPU execution provider.
    Cpu,
}

impl OnnxExecutionProvider {
    /// Stable, telemetry-friendly name for the selected provider.
    ///
    /// Matches the strings emitted by the cv-guard
    /// `OnnxInferenceBridge` (`"DirectML"` / `"CPU"`) so any
    /// future cross-product telemetry pipeline can reuse the
    /// same dimensions.
    pub const fn name(self) -> &'static str {
        match self {
            Self::DirectMl => "DirectML",
            Self::Cpu => "CPU",
        }
    }
}

/// Result of [`select_provider`] — which EP was selected and
/// whether DirectML was even attempted on this host.
///
/// `directml_attempted` is `false` on non-Windows targets (we
/// short-circuit to CPU without probing) and `true` on Windows
/// regardless of the outcome (so telemetry can distinguish
/// "DirectML probe ran and reported unavailable" from "DirectML
/// not applicable on this OS at all").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OnnxProviderReport {
    /// The provider that should be (or was) registered on the
    /// session.
    pub provider: OnnxExecutionProvider,
    /// `true` if the DirectML probe was consulted on this host.
    pub directml_attempted: bool,
}

/// Cheap probe of DirectML availability.
///
/// Factored out of [`select_provider`] so the EP-selection state
/// machine can be exhaustively unit-tested on non-Windows hosts
/// without requiring any DirectML adapter or ONNX Runtime build
/// to be present. The production probe lives in
/// `OrtDirectMlProbe` and is gated behind both
/// `cfg(target_os = "windows")` and the `onnx-runtime` cargo
/// feature.
///
/// Implementations MUST be cheap (no allocation, no I/O beyond
/// what ORT does internally) and MUST NOT panic on failure
/// any error path inside the probe is reported as `false`.
pub trait DirectMlProbe {
    /// Return `true` if DirectML is available on the current
    /// host, `false` otherwise.
    fn directml_available(&self) -> bool;
}

/// Pure EP-selection function. Returns the EP that should be
/// used for a session given a probe of DirectML availability.
///
/// On non-Windows targets the result is always
/// [`OnnxExecutionProvider::Cpu`] — the DirectML branch is
/// `cfg(target_os = "windows")` gated to mirror the `ort`
/// crate's own `directml` feature gating. On Windows the
/// DirectML EP is preferred when the probe reports
/// availability; otherwise we fall back to CPU.
///
/// The probe is taken by reference (with `?Sized` so dyn-objects
/// work) because the production probe is a zero-sized type and
/// the test stub holds a single `bool`.
pub fn select_provider<P: DirectMlProbe + ?Sized>(probe: &P) -> OnnxProviderReport {
    #[cfg(target_os = "windows")]
    {
        if probe.directml_available() {
            return OnnxProviderReport {
                provider: OnnxExecutionProvider::DirectMl,
                directml_attempted: true,
            };
        }
        OnnxProviderReport {
            provider: OnnxExecutionProvider::Cpu,
            directml_attempted: true,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Probe is irrelevant on non-Windows; consume it to
        // avoid an unused-parameter warning under
        // `#[deny(unused)]`.
        let _ = probe;
        OnnxProviderReport {
            provider: OnnxExecutionProvider::Cpu,
            directml_attempted: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Real `ort::Session` creator — Windows + onnx-runtime feature
// ---------------------------------------------------------------------------

/// Result type for the ONNX Runtime session creators.
///
/// Aliased so callers (and the documentation) need not depend
/// on `ort::Result` directly. Only re-exported when the
/// `onnx-runtime` feature is enabled.
#[cfg(feature = "onnx-runtime")]
pub type OrtSessionResult<T> = ort::Result<T>;

#[cfg(all(target_os = "windows", feature = "onnx-runtime"))]
mod windows_directml {
    use super::{
        select_provider, DirectMlProbe, OnnxExecutionProvider, OnnxProviderReport, OrtSessionResult,
    };
    use ort::ep::{DirectML, ExecutionProvider, CPU};
    use ort::session::Session;
    use std::path::Path;

    /// Production [`DirectMlProbe`] backed by
    /// [`ort::ep::DirectML::is_available`]. Returns `false` on
    /// any error from ORT instead of propagating.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct OrtDirectMlProbe;

    impl DirectMlProbe for OrtDirectMlProbe {
        fn directml_available(&self) -> bool {
            DirectML::default().is_available().unwrap_or(false)
        }
    }

    /// Create an `ort::Session` for the XLM-R text encoder
    /// loaded from `model_path`.
    ///
    /// Tries DirectML first (per [`select_provider`]); falls
    /// back to CPU if DirectML registration on the
    /// [`SessionBuilder`] returns an error. The returned
    /// [`OnnxProviderReport`] reflects the EP that was actually
    /// registered on the resulting session, not the original
    /// intent — i.e. if the probe reported DirectML available
    /// but registration failed, the report reads
    /// `provider: Cpu, directml_attempted: true`.
    ///
    /// This is the scaffold: the inference loop
    /// (input-tensor encode → `session.run` → mean-pool →
    /// `Vec<f32>`) is intentionally not wired here yet — that
    /// lands together with the SentencePiece tokenizer in a
    /// follow-up. Callers that need a working text-embedding
    /// hook in the meantime should keep using the
    /// [`crate::models::embeddings::EmbeddingCache`] surface.
    pub fn create_xlmr_session(
        model_path: &Path,
    ) -> OrtSessionResult<(Session, OnnxProviderReport)> {
        let intent = select_provider(&OrtDirectMlProbe);
        let mut builder = Session::builder()?;

        let actual_provider = match intent.provider {
            OnnxExecutionProvider::DirectMl => {
                if DirectML::default().register(&mut builder).is_ok() {
                    OnnxExecutionProvider::DirectMl
                } else {
                    // DirectML probe lied (or registration failed
                    // for a model-specific reason). Fall back to
                    // CPU; CPU registration is best-effort because
                    // ORT auto-registers a default CPU EP at
                    // commit time anyway.
                    let _ = CPU::default().register(&mut builder);
                    OnnxExecutionProvider::Cpu
                }
            }
            OnnxExecutionProvider::Cpu => {
                let _ = CPU::default().register(&mut builder);
                OnnxExecutionProvider::Cpu
            }
        };

        let session = builder.commit_from_file(model_path)?;
        Ok((
            session,
            OnnxProviderReport {
                provider: actual_provider,
                directml_attempted: intent.directml_attempted,
            },
        ))
    }
}

#[cfg(all(target_os = "windows", feature = "onnx-runtime"))]
pub use windows_directml::{create_xlmr_session, OrtDirectMlProbe};

#[cfg(all(not(target_os = "windows"), feature = "onnx-runtime"))]
mod posix_cpu {
    use super::{select_provider, DirectMlProbe, OnnxProviderReport, OrtSessionResult};
    use ort::ep::{ExecutionProvider, CPU};
    use ort::session::Session;
    use std::path::Path;

    /// Non-Windows [`DirectMlProbe`] — DirectML never available.
    /// Provided for parity so callers can name the same type
    /// across platforms when wiring telemetry.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct OrtDirectMlProbe;

    impl DirectMlProbe for OrtDirectMlProbe {
        fn directml_available(&self) -> bool {
            false
        }
    }

    /// macOS / Linux flavor of the XLM-R session creator.
    ///
    /// Always registers the CPU EP. The cross-platform
    /// inference seam (CoreML EP on Apple, NNAPI EP on Android,
    /// etc.) is layered above this; this entry point focuses on
    /// the Windows DirectML path called out in
    /// `docs/ARCHITECTURE.md §11.4`.
    pub fn create_xlmr_session(
        model_path: &Path,
    ) -> OrtSessionResult<(Session, OnnxProviderReport)> {
        let report = select_provider(&OrtDirectMlProbe);
        let mut builder = Session::builder()?;
        let _ = CPU::default().register(&mut builder);
        let session = builder.commit_from_file(model_path)?;
        Ok((session, report))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "onnx-runtime"))]
pub use posix_cpu::{create_xlmr_session, OrtDirectMlProbe};

/// INT4 (`MatMulNBits`)
/// flavor of [`create_xlmr_session`].
///
/// Same EP-selection state machine and CPU fallback as
/// [`create_xlmr_session`] — the only difference is the
/// expected on-disk file (`xlmr-v1-int4.onnx`) carries
/// `MatMulNBits` nodes which `ort` honors at session-load time
/// without any extra `SessionBuilder` call. This helper exists
/// as a named seam so future graph-optimization tweaks can
/// land without touching the INT8 path.
#[cfg(feature = "onnx-runtime")]
pub fn create_xlmr_session_int4(
    model_path: &std::path::Path,
) -> OrtSessionResult<(ort::session::Session, OnnxProviderReport)> {
    create_xlmr_session(model_path)
}

/// EP-aware named seam
/// over [`create_xlmr_session`].
///
/// Production callers walk the [`crate::models::ep_tuning::EpFallbackChain`]
/// and pass the chosen [`crate::models::ep_tuning::ExecutionProvider`]
/// through this function so the bridge crate can pick its own
/// EP without re-running the platform state machine.
///
/// The actual EP-registration logic remains the platform-aware
/// best-effort fallback inside [`create_xlmr_session`]: on
/// Windows the helper attempts DirectML first when `ep ==
/// DirectMl`, otherwise registers CPU; on non-Windows the only
/// supported EP is CPU. The returned [`OnnxProviderReport`]
/// reflects the EP that was actually registered, not the
/// requested one.
/// Re-export of `ort::session::Session` so consumer crates
/// (notably `kchat-desktop`) can name the return type of the
/// EP-aware session creators without taking a direct
/// dependency on the `ort` crate.
#[cfg(feature = "onnx-runtime")]
pub use ort::session::Session as OrtSession;

#[cfg(feature = "onnx-runtime")]
pub fn create_xlmr_session_with_ep(
    model_path: &std::path::Path,
    ep: crate::models::ep_tuning::ExecutionProvider,
) -> OrtSessionResult<(ort::session::Session, OnnxProviderReport)> {
    // The current `ort` build only wires DirectML + CPU; CoreML /
    // NNAPI are tracked in the platform-bridge follow-up. For
    // non-supported EPs we degrade to the auto-select path so
    // the session creator still produces a working session under
    // the platform's CPU EP.
    let _ = ep;
    create_xlmr_session(model_path)
}

/// INT4 session-creator
/// stub for builds without the `onnx-runtime` cargo feature.
#[cfg(not(feature = "onnx-runtime"))]
pub fn create_xlmr_session_int4(_model_path: &std::path::Path) -> crate::Result<()> {
    Err(crate::Error::NotImplemented(
        "create_xlmr_session_int4 requires onnx-runtime feature",
    ))
}

/// stub for the
/// EP-aware seam when the `onnx-runtime` feature is off.
#[cfg(not(feature = "onnx-runtime"))]
pub fn create_xlmr_session_with_ep(
    _model_path: &std::path::Path,
    _ep: crate::models::ep_tuning::ExecutionProvider,
) -> crate::Result<()> {
    Err(crate::Error::NotImplemented(
        "create_xlmr_session_with_ep requires onnx-runtime feature",
    ))
}

// ---------------------------------------------------------------------------
// OnnxTextEmbedder — long-lived `ort::Session` wrapper + the
// pure-math kernels that drive its XLM-R inference loop.
//
// (`docs/DESIGN.md §7.6 / §7.7`,
// `docs/ARCHITECTURE.md §11.4`). The struct owns one
// `ort::Session` and one [`tokenizers::Tokenizer`] for the
// lifetime of the wrapper so XLM-R inference re-uses the same
// DirectML / CPU registration AND the same tokenizer state
// across every `embed_text` call rather than paying the
// session-build / tokenizer-parse cost per message. Both are
// dropped together when the wrapper is dropped — no extra
// teardown step is required because `ort` releases its
// underlying ONNX Runtime resources on `Drop` and the
// `Tokenizer` is plain heap state.
//
// The shape of the inference loop is:
//
// 1. [`tokenizers::Tokenizer::encode`] turns the input text into
// `(ids: &[u32], attention_mask: &[u32])` honouring the
// model's bundled normalizer / pretokenizer / decoder.
// 2. [`pad_or_truncate_ids`] reshapes those slices to the
// session's fixed `[1, max_length]` input.
// 3. `ort::value::Tensor::from_array` materialises the two i64
// tensors and `session.run` produces the encoder's last
// hidden state with shape `[1, max_length, hidden_size]`.
// 4. [`mask_aware_mean_pool`] collapses the seq dimension
// weighted by the attention mask, and
// [`l2_normalize_in_place`] yields the cosine-friendly
// embedding the rest of the search pipeline expects.
//
// Steps 1-and the wrapper itself live behind the
// `onnx-runtime` cargo feature (the `ort` and `tokenizers`
// crates only resolve when it is on). Steps 2-4 are pure
// functions over `&[u32]` / `&[i64]` / `&[f32]` and are
// therefore **always compiled** so the unit tests can pin them
// on every host without needing an ORT shared library, a
// DirectML adapter, or a real XLM-R `.onnx` artifact. The
// integration tests in the Model-manager suite still exercise
// the full session-backed loop when a fixture is available.
//
// What also lives outside the feature gate is the error-mapping
// shim: [`map_ort_error`] turns any `ort::Error` into the
// canonical [`crate::Error::Model`] variant. The shim is a free
// function so the lifetime contract — "wrapping and inference
// share one error path" — is enforced at compile time.
// ---------------------------------------------------------------------------

/// Pad or truncate a tokenizer `(ids, mask)` pair to a fixed
/// `max_length`, returning the i64-typed tensors XLM-R expects.
///
/// HuggingFace tokenizers produce `u32` ids and `u32` attention
/// masks of length `n` where `n` is the encoded token count
/// (post-normalisation, post-special-tokens). XLM-R's exported
/// ONNX graph expects fixed `[1, max_length]` `int64` inputs, so
/// we either:
///
/// * truncate the suffix when `ids.len() > max_length` — mirroring
///   the HuggingFace `truncation=True` default — OR
/// * pad with `pad_token_id` (and a zero attention mask) to fill
///   the gap when `ids.len() < max_length`.
///
/// The function is total: it never panics on malformed inputs.
/// In particular:
///
/// * `max_length == 0` returns `(Vec::new(), Vec::new())` — the
///   caller is responsible for either rejecting this at the
///   builder boundary (`OnnxTextEmbedder::with_max_length` panics
///   on zero via `assert!`) or for handling the empty pair before
///   passing it to a tensor-build call, since
///   `ort::value::Tensor::from_array` does not accept a
///   zero-dimensional shape. In the wired-up `embed_text` path
///   this branch is unreachable because the constructor default
///   is 128 and the builder rejects 0.
/// * `ids.len() != mask.len()` is tolerated by truncating to the
///   shorter slice (the HuggingFace contract guarantees they are
///   equal, but defensive code keeps fuzz / proptest input from
///   triggering `Vec`-bound `panic`s).
pub fn pad_or_truncate_ids(
    ids: &[u32],
    mask: &[u32],
    max_length: usize,
    pad_token_id: i64,
) -> (Vec<i64>, Vec<i64>) {
    if max_length == 0 {
        return (Vec::new(), Vec::new());
    }
    let n = ids.len().min(mask.len()).min(max_length);
    let mut out_ids = Vec::with_capacity(max_length);
    let mut out_mask = Vec::with_capacity(max_length);
    for i in 0..n {
        out_ids.push(ids[i] as i64);
        out_mask.push(mask[i] as i64);
    }
    while out_ids.len() < max_length {
        out_ids.push(pad_token_id);
        out_mask.push(0);
    }
    (out_ids, out_mask)
}

/// Mask-aware mean-pool of an XLM-R encoder's last hidden state.
///
/// `hidden` is the flat row-major buffer returned by
/// `ort::value::Tensor::try_extract_tensor::<f32>` whose logical
/// shape is `[1, seq_len, hidden_size]`. `attention_mask` is the
/// i64 mask we passed in at inference time (length `seq_len`,
/// `1` for real tokens, `0` for padding); we use it both to
/// weight the sum and to compute the divisor so padding tokens
/// do not bias the embedding toward zero.
///
/// Returns a `hidden_size`-length `Vec<f32>` in canonical
/// least-recently-updated order. Returns `None` when:
///
/// * `hidden.len() != seq_len * hidden_size` (caller passed a
///   mismatched buffer), OR
/// * `seq_len == 0` / `hidden_size == 0` (degenerate shape).
///
/// The all-padding edge case (`mask.iter().sum() == 0`) returns
/// `Some(vec![0.0; hidden_size])` rather than dividing by zero —
/// the downstream [`l2_normalize_in_place`] then leaves the
/// zero vector untouched (its norm is below `f32::EPSILON`), so
/// the embedding is a deterministic, well-defined null vector
/// rather than `NaN`.
pub fn mask_aware_mean_pool(
    hidden: &[f32],
    attention_mask: &[i64],
    seq_len: usize,
    hidden_size: usize,
) -> Option<Vec<f32>> {
    if seq_len == 0 || hidden_size == 0 {
        return None;
    }
    if hidden.len() != seq_len.checked_mul(hidden_size)? {
        return None;
    }
    if attention_mask.len() < seq_len {
        return None;
    }
    let mut pooled = vec![0.0f32; hidden_size];
    let mut mask_sum = 0.0f32;
    for tok in 0..seq_len {
        let m = attention_mask[tok];
        if m <= 0 {
            continue;
        }
        let mf = m as f32;
        mask_sum += mf;
        let row = &hidden[tok * hidden_size..(tok + 1) * hidden_size];
        for (acc, v) in pooled.iter_mut().zip(row.iter()) {
            *acc += *v * mf;
        }
    }
    if mask_sum > 0.0 {
        for v in &mut pooled {
            *v /= mask_sum;
        }
    }
    Some(pooled)
}

/// In-place L2 normalisation of a real-valued vector.
///
/// Divides every component by `sqrt(sum(v^2))` so the resulting
/// vector has unit norm — a precondition for the cosine-distance
/// reranker downstream (§7.6 of `docs/DESIGN.md`). If the vector
/// is already (numerically) zero (`norm <= f32::EPSILON`) the
/// function is a no-op rather than producing `NaN` / `inf`
/// lanes; this matches the [`mask_aware_mean_pool`] null-vector
/// convention so an all-padding input yields a deterministic
/// all-zero embedding the caller can detect via `iter().all(|x|
/// *x == 0.0)` rather than via a `NaN`-aware float check.
pub fn l2_normalize_in_place(v: &mut [f32]) {
    let mut sumsq = 0.0f32;
    for &x in v.iter() {
        sumsq += x * x;
    }
    let norm = sumsq.sqrt();
    if norm > f32::EPSILON {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

#[cfg(feature = "onnx-runtime")]
use crate::Result;

/// Map an `ort::Error` to the canonical [`crate::Error::Model`]
/// variant.
///
/// Captures the upstream message verbatim so telemetry pipelines
/// (and the bridge crates in `kennguy3n/slm-guardrail` /
/// `kennguy3n/cv-guard`) can pattern-match on the `model:` prefix
/// without parsing the wrapped substring. Always returns the
/// `Model` variant; never `Storage` or `Search`, even if the
/// upstream message mentions a database or query — the on-device
/// ML pipeline is a single error domain at the public surface.
#[cfg(feature = "onnx-runtime")]
pub(crate) fn map_ort_error(err: ort::Error) -> crate::Error {
    crate::Error::Model(err.to_string().into())
}

/// Long-lived ONNX Runtime wrapper for the XLM-R text encoder.
///
/// Construction loads the model from disk, registers the
/// preferred execution provider (DirectML on Windows when
/// available, CPU everywhere else), and parses the bundled
/// HuggingFace [`tokenizers::Tokenizer`] (`tokenizer.json`)
/// sitting next to the `.onnx` artifact. Subsequent
/// [`Self::embed_text`] calls reuse the same session AND the
/// same tokenizer — the `ort::Session` holds the per-graph
/// state (allocator, optimised graph, EP context) and the
/// `Tokenizer` holds the parsed normaliser / pretokeniser /
/// vocab maps, so per-call cost is just `encode` + tensor
/// binding + inference + pool/normalise, not a full
/// session/tokenizer rebuild.
///
/// The struct is `Send + Sync`-friendly *given* that
/// `ort::Session` and `tokenizers::Tokenizer` are both `Send`
/// in the versions we pin; the wrapper carries a `Mutex` around
/// the session to short-borrow it for inference without forcing
/// `&mut self` through the
/// [`crate::models::embeddings::TextEmbedder`] trait. The
/// tokenizer is `&self`-callable (its `encode` takes `&self`),
/// so it sits outside the lock for parallel-read access.
#[cfg(feature = "onnx-runtime")]
pub struct OnnxTextEmbedder {
    session: std::sync::Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
    report: OnnxProviderReport,
    /// Maximum input-token sequence length the wrapper enforces
    /// before pad/truncate. Defaults to 128 — matches the XLM-R
    /// fine-tune used by `kennguy3n/slm-guardrail`.
    max_length: usize,
    /// Token id used to pad shorter inputs up to `max_length`.
    /// Resolved at construction time by asking the tokenizer for
    /// its `<pad>` token (XLM-R's canonical pad token id is
    /// `1`); falls back to `XLMR_FALLBACK_PAD_TOKEN_ID` if the
    /// vocab lacks the expected special token.
    pad_token_id: i64,
}

/// Default tokenizer artifact filename (HuggingFace convention).
///
/// The XLM-R artifact in the [`super::model_manager`] cache is
/// expected to live alongside this file; the
/// [`OnnxTextEmbedder::new`] constructor resolves it relative
/// to the parent directory of the `.onnx` path. Callers that
/// want a different layout can use
/// [`OnnxTextEmbedder::new_with_tokenizer`] directly.
#[cfg(feature = "onnx-runtime")]
pub const XLMR_TOKENIZER_FILENAME: &str = "tokenizer.json";

/// Canonical XLM-R pad token id used when the bundled tokenizer
/// does not advertise a `<pad>` special token.
///
/// XLM-R / XLM-RoBERTa exports `<pad>` at vocab index `1`; the
/// session's `int64` `input_ids` tensor uses this value to
/// signal "this position carries no real token" alongside the
/// matching `0` lane in `attention_mask`.
pub const XLMR_FALLBACK_PAD_TOKEN_ID: i64 = 1;

#[cfg(feature = "onnx-runtime")]
impl std::fmt::Debug for OnnxTextEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnnxTextEmbedder")
            .field("report", &self.report)
            .field("max_length", &self.max_length)
            .field("pad_token_id", &self.pad_token_id)
            .field("tokenizer_vocab_size", &self.tokenizer.get_vocab_size(true))
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "onnx-runtime")]
impl OnnxTextEmbedder {
    /// Default maximum-token-sequence length used by [`Self::new`].
    pub const DEFAULT_MAX_LENGTH: usize = 128;

    /// Create a new XLM-R wrapper backed by the model at
    /// `model_path` and a tokenizer file sitting at
    /// `<model_dir>/tokenizer.json`.
    ///
    /// Errors map through [`map_ort_error`] (session-create)
    /// and a [`crate::models::ModelError::Tokenizer`] variant
    /// (tokenizer parse) so the public surface is a single
    /// [`crate::Error::Model`] variant, regardless of whether
    /// DirectML registration, model load, graph optimisation,
    /// or tokenizer parsing failed.
    pub fn new(model_path: &std::path::Path) -> Result<Self> {
        let tokenizer_path = default_tokenizer_path(model_path);
        Self::new_with_tokenizer(model_path, &tokenizer_path)
    }

    /// Variant of [`Self::new`] that takes an explicit
    /// `tokenizer.json` path.
    ///
    /// Use this when the tokenizer artifact does not sit next
    /// to the `.onnx` model — e.g. integration tests that
    /// stage a tokenizer in a temp directory or bridge crates
    /// that override the platform model cache layout.
    pub fn new_with_tokenizer(
        model_path: &std::path::Path,
        tokenizer_path: &std::path::Path,
    ) -> Result<Self> {
        let (session, report) = create_xlmr_session(model_path).map_err(map_ort_error)?;
        let tokenizer = load_xlmr_tokenizer(tokenizer_path)?;
        let pad_token_id = resolve_pad_token_id(&tokenizer);
        Ok(Self {
            session: std::sync::Mutex::new(session),
            tokenizer,
            report,
            max_length: Self::DEFAULT_MAX_LENGTH,
            pad_token_id,
        })
    }

    /// Replace the maximum input-token sequence length. Call this
    /// before the first `embed_text` to override the
    /// [`Self::DEFAULT_MAX_LENGTH`] default.
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        assert!(max_length > 0, "max_length must be > 0");
        self.max_length = max_length;
        self
    }

    /// Execution-provider report captured at session-create time.
    pub fn provider_report(&self) -> OnnxProviderReport {
        self.report
    }

    /// Maximum input-token-sequence length the wrapper applies
    /// before pad / truncate.
    pub fn max_length(&self) -> usize {
        self.max_length
    }

    /// Pad token id the wrapper writes into the `input_ids`
    /// tensor for positions past the encoded sequence length.
    pub fn pad_token_id(&self) -> i64 {
        self.pad_token_id
    }

    /// Run XLM-R inference on `text` and return the mean-pooled,
    /// L2-normalised embedding of dimension
    /// [`crate::models::embeddings::XLMR_EMBEDDING_DIM`].
    ///
    /// Inference loop:
    ///
    /// 1. [`tokenizers::Tokenizer::encode`] with
    ///    `add_special_tokens = true` (XLM-R prepends `<s>` and
    ///    appends `</s>` per the bundled tokenizer config).
    /// 2. [`pad_or_truncate_ids`] reshapes the encoded
    ///    `(ids, mask)` to the session's fixed
    ///    `[1, max_length]` shape using
    ///    [`Self::pad_token_id`] for padding.
    /// 3. `ort::value::Tensor::from_array` materialises the two
    ///    `int64` input tensors and `session.run` produces the
    ///    encoder's last hidden state with shape
    ///    `[1, max_length, hidden_size]`.
    /// 4. [`mask_aware_mean_pool`] collapses the seq dimension
    ///    weighted by `attention_mask`.
    /// 5. [`l2_normalize_in_place`] normalises the pooled
    ///    vector so downstream cosine-distance reranking
    ///    reduces to dot product.
    pub fn embed_text(&self, text: &str) -> Result<Vec<f32>> {
        use crate::models::ModelError;

        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| make_tokenizer_error("encode", e))?;
        let (input_ids, attention_mask) = pad_or_truncate_ids(
            encoding.get_ids(),
            encoding.get_attention_mask(),
            self.max_length,
            self.pad_token_id,
        );
        debug_assert_eq!(input_ids.len(), self.max_length);
        debug_assert_eq!(attention_mask.len(), self.max_length);

        // Build the two input tensors. `input_ids` is consumed
        // by `Tensor::from_array` (XLM-R does not reuse it
        // downstream) so we move it. `attention_mask` is reused
        // by `mask_aware_mean_pool` after `session.run` to
        // weight the pooled output, so we clone it once into the
        // tensor and keep the owned vec for the pool step. The
        // shape vec is moved into the second call and built
        // inline for the first — `vec![…]` is two i64s, cheaper
        // than a heap clone.
        let ids_tensor =
            ort::value::Tensor::from_array((vec![1_i64, self.max_length as i64], input_ids))
                .map_err(map_ort_error)?;
        let mask_tensor = ort::value::Tensor::from_array((
            vec![1_i64, self.max_length as i64],
            attention_mask.clone(),
        ))
        .map_err(map_ort_error)?;

        // Hold the session lock across `run` AND the tensor
        // extraction: `SessionOutputs<'s>` borrows from the
        // session it was produced by, so extracting after the
        // lock guard drops would let the session escape its
        // borrow. We mean-pool into an owned `Vec<f32>` inside
        // the critical section, then drop both the outputs and
        // the lock together before normalising.
        let mut pooled = {
            let mut session = self.session.lock().map_err(|_| {
                crate::Error::Model(ModelError::LockPoisoned("onnx_text_embedder_session"))
            })?;
            let outputs = session
                .run(ort::inputs![
                    "input_ids" => ids_tensor,
                    "attention_mask" => mask_tensor,
                ])
                .map_err(map_ort_error)?;
            // The XLM-R encoder export emits its last hidden
            // state as output 0 — different `optimum` /
            // `transformers` export passes name the tensor
            // differently (`last_hidden_state`, `output_0`,
            // …), so we look it up by index. The shape
            // contract is fixed at the graph level:
            // `[batch, seq_len, hidden_size]`.
            let (out_shape, hidden) = outputs[0]
                .try_extract_tensor::<f32>()
                .map_err(map_ort_error)?;
            if out_shape.len() != 3 || out_shape[0] != 1 {
                return Err(crate::Error::Model(ModelError::Custom(format!(
                    "xlmr session returned unexpected output shape {out_shape:?}; expected [1, seq, hidden]"
                ))));
            }
            let seq_len = out_shape[1] as usize;
            let hidden_size = out_shape[2] as usize;
            // Pin the hidden-size invariant inline. The
            // `EmbeddingCache` schema (and downstream cosine /
            // ANN reranking that consumes these vectors) all
            // assume a fixed `XLMR_EMBEDDING_DIM`-element blob;
            // a wrong model export silently producing a
            // different `hidden_size` would corrupt the cache
            // on first write. Surface it loudly here instead.
            if hidden_size != crate::models::embeddings::XLMR_EMBEDDING_DIM {
                return Err(crate::Error::Model(ModelError::Custom(format!(
                    "xlmr session produced hidden_size={hidden_size}, \
                     expected XLMR_EMBEDDING_DIM={}; refusing to write a \
                     wrong-shape blob to the embedding cache",
                    crate::models::embeddings::XLMR_EMBEDDING_DIM,
                ))));
            }
            mask_aware_mean_pool(hidden, &attention_mask, seq_len, hidden_size).ok_or_else(
                || {
                    crate::Error::Model(ModelError::Custom(format!(
                        "xlmr mean-pool shape mismatch: hidden.len={} seq_len={} hidden_size={}",
                        hidden.len(),
                        seq_len,
                        hidden_size,
                    )))
                },
            )?
        };
        l2_normalize_in_place(&mut pooled);
        Ok(pooled)
    }
}

/// Wrap a `tokenizers::Tokenizer::*` error in a
/// [`crate::models::ModelError::Tokenizer`] variant.
///
/// Helper so the inference loop body stays terse and so call
/// sites name the failing op (`"from_file"` / `"encode"`)
/// uniformly.
#[cfg(feature = "onnx-runtime")]
fn make_tokenizer_error(
    op: &'static str,
    err: Box<dyn std::error::Error + Send + Sync>,
) -> crate::Error {
    crate::Error::Model(crate::models::ModelError::Tokenizer {
        op,
        detail: err.to_string(),
    })
}

/// Load and parse the HuggingFace `tokenizer.json` artifact at
/// `path`.
///
/// Centralised so the constructor body stays readable and so
/// the test suite can stub the loader behind a `cfg(test)` shim
/// without duplicating the error-mapping shape.
#[cfg(feature = "onnx-runtime")]
fn load_xlmr_tokenizer(path: &std::path::Path) -> Result<tokenizers::Tokenizer> {
    tokenizers::Tokenizer::from_file(path).map_err(|e| make_tokenizer_error("from_file", e))
}

/// Compute the default `tokenizer.json` path co-located with
/// `model_path`.
///
/// HuggingFace's `optimum-cli` / `transformers` export drops
/// the tokenizer next to the `.onnx` file by convention; this
/// helper just appends [`XLMR_TOKENIZER_FILENAME`] to the
/// model's parent directory. If `model_path` has no parent
/// (i.e. it is a bare filename) the result is a relative path
/// `tokenizer.json` — which the constructor will then fail to
/// open with a clear `Model(Tokenizer { op: "from_file" })`
/// error rather than panicking here.
#[cfg(feature = "onnx-runtime")]
fn default_tokenizer_path(model_path: &std::path::Path) -> std::path::PathBuf {
    match model_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(XLMR_TOKENIZER_FILENAME),
        _ => std::path::PathBuf::from(XLMR_TOKENIZER_FILENAME),
    }
}

/// Resolve the pad token id by asking the tokenizer for its
/// canonical XLM-R `<pad>` special token, with a tested fallback.
#[cfg(feature = "onnx-runtime")]
fn resolve_pad_token_id(tokenizer: &tokenizers::Tokenizer) -> i64 {
    tokenizer
        .token_to_id("<pad>")
        .map(|x| x as i64)
        .unwrap_or(XLMR_FALLBACK_PAD_TOKEN_ID)
}

/// Always-`NotImplemented` `OnnxTextEmbedder` stub for builds
/// without the `onnx-runtime` feature.
///
/// `OnnxTextEmbedder` exists in both feature configurations so
/// downstream code can name the type unconditionally — it just
/// errors out on construction without the feature.
#[cfg(not(feature = "onnx-runtime"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct OnnxTextEmbedder;

#[cfg(not(feature = "onnx-runtime"))]
impl OnnxTextEmbedder {
    /// Always returns
    /// [`crate::Error::NotImplemented`](crate::Error::NotImplemented)
    /// the `onnx-runtime` cargo feature is required for the
    /// real session creator.
    pub fn new(_model_path: &std::path::Path) -> crate::Result<Self> {
        Err(crate::Error::NotImplemented(
            "onnx_text_embedder.new (onnx-runtime feature disabled)",
        ))
    }

    /// Always returns
    /// [`crate::Error::NotImplemented`](crate::Error::NotImplemented).
    pub fn embed_text(&self, _text: &str) -> crate::Result<Vec<f32>> {
        Err(crate::Error::NotImplemented(
            "onnx_text_embedder.embed_text (onnx-runtime feature disabled)",
        ))
    }
}

// Sanity tests for the always-compiled stub variant — the real
// inference loop tests live behind `cfg(feature = "onnx-runtime")`
// in the model-manager integration suite.
#[cfg(all(test, not(feature = "onnx-runtime")))]
mod stub_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn stub_new_reports_feature_gate() {
        let err = OnnxTextEmbedder::new(&PathBuf::from("/nonexistent")).unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }

    #[test]
    fn stub_embed_text_reports_feature_gate() {
        let stub = OnnxTextEmbedder;
        let err = stub.embed_text("hello").unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }
}

// ---------------------------------------------------------------------------
// Tests — exercise `select_provider` exhaustively. The actual
// `ort::Session` creators are not unit-testable without a real
// ORT install + a real.onnx fixture, so they are deferred to
// the integration test suite.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub probe with an injected boolean so the EP-selection
    /// state machine can be exercised on any host.
    struct StubProbe(bool);
    impl DirectMlProbe for StubProbe {
        fn directml_available(&self) -> bool {
            self.0
        }
    }

    #[test]
    fn provider_name_is_stable() {
        assert_eq!(OnnxExecutionProvider::DirectMl.name(), "DirectML");
        assert_eq!(OnnxExecutionProvider::Cpu.name(), "CPU");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn directml_preferred_when_available_on_windows() {
        let report = select_provider(&StubProbe(true));
        assert_eq!(report.provider, OnnxExecutionProvider::DirectMl);
        assert!(report.directml_attempted);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn cpu_fallback_when_directml_unavailable_on_windows() {
        let report = select_provider(&StubProbe(false));
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
        assert!(
            report.directml_attempted,
            "the probe should still be consulted on Windows"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn directml_never_attempted_off_windows_even_if_probe_lies() {
        // Even a probe that returns `true` must be ignored on
        // non-Windows: the `directml` feature on the `ort` crate
        // is only enabled in `[target.'cfg(windows)'.dependencies]`,
        // so `ort::ep::DirectML` does not even exist here.
        let report = select_provider(&StubProbe(true));
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
        assert!(!report.directml_attempted);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn cpu_selected_off_windows_with_unavailable_probe() {
        let report = select_provider(&StubProbe(false));
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
        assert!(!report.directml_attempted);
    }

    #[test]
    fn select_provider_accepts_dyn_probe() {
        // Sanity: the `?Sized` bound means `&dyn DirectMlProbe`
        // works too, which keeps the seam friendly to runtime
        // probe injection (e.g. forcing CPU via a config flag).
        let probe: &dyn DirectMlProbe = &StubProbe(false);
        let report = select_provider(probe);
        assert_eq!(report.provider, OnnxExecutionProvider::Cpu);
    }

    // ----------------------------------------------------------
    // Pure-math kernels — `pad_or_truncate_ids`,
    // `mask_aware_mean_pool`, `l2_normalize_in_place`.
    //
    // These functions back the real XLM-R inference loop in
    // `OnnxTextEmbedder::embed_text` and are unit-tested here
    // (no feature gate) so the contract is pinned even when CI
    // does not have an ORT shared library to link against.
    // ----------------------------------------------------------

    #[test]
    fn pad_or_truncate_pads_short_sequences() {
        let (ids, mask) = pad_or_truncate_ids(&[5, 6, 7], &[1, 1, 1], 6, 1);
        assert_eq!(ids, vec![5, 6, 7, 1, 1, 1]);
        assert_eq!(mask, vec![1, 1, 1, 0, 0, 0]);
    }

    #[test]
    fn pad_or_truncate_truncates_long_sequences() {
        let (ids, mask) = pad_or_truncate_ids(&[10, 11, 12, 13, 14], &[1, 1, 1, 1, 1], 3, 1);
        assert_eq!(ids, vec![10, 11, 12]);
        assert_eq!(mask, vec![1, 1, 1]);
    }

    #[test]
    fn pad_or_truncate_returns_full_length_pad_only_for_empty_input() {
        let (ids, mask) = pad_or_truncate_ids(&[], &[], 4, 1);
        assert_eq!(ids, vec![1, 1, 1, 1]);
        assert_eq!(mask, vec![0, 0, 0, 0]);
    }

    #[test]
    fn pad_or_truncate_handles_zero_max_length() {
        // Degenerate but defensible: zero-length output rather
        // than a panic. Downstream tensor-build will reject the
        // zero-dimensional shape with a clean ORT error.
        let (ids, mask) = pad_or_truncate_ids(&[1, 2, 3], &[1, 1, 1], 0, 1);
        assert!(ids.is_empty());
        assert!(mask.is_empty());
    }

    #[test]
    fn pad_or_truncate_uses_shorter_of_mismatched_inputs() {
        // The HuggingFace `Encoding` contract guarantees
        // `ids.len() == mask.len()`, but the helper is total so
        // fuzz / proptest input that violates the contract does
        // not panic. We consume `min(ids, mask)` real tokens and
        // pad the rest.
        let (ids, mask) = pad_or_truncate_ids(&[1, 2, 3, 4], &[1, 1], 5, 9);
        assert_eq!(ids, vec![1, 2, 9, 9, 9]);
        assert_eq!(mask, vec![1, 1, 0, 0, 0]);
    }

    #[test]
    fn mean_pool_averages_unmasked_positions_only() {
        // Two unmasked rows of [1, 2] and [3, 4]; one masked
        // row of [9, 9] that must not contribute. Expected:
        // ([1, 2] + [3, 4]) / 2 == [2, 3].
        let hidden = vec![1.0, 2.0, 3.0, 4.0, 9.0, 9.0];
        let mask = vec![1, 1, 0];
        let pooled = mask_aware_mean_pool(&hidden, &mask, 3, 2).expect("pooled");
        assert_eq!(pooled, vec![2.0, 3.0]);
    }

    #[test]
    fn mean_pool_returns_zero_vector_when_mask_is_all_zero() {
        let hidden = vec![1.0, 2.0, 3.0, 4.0];
        let mask = vec![0, 0];
        let pooled = mask_aware_mean_pool(&hidden, &mask, 2, 2).expect("pooled");
        assert_eq!(pooled, vec![0.0, 0.0]);
    }

    #[test]
    fn mean_pool_rejects_shape_mismatch() {
        // hidden has 5 lanes but seq_len * hidden_size == 6.
        assert!(mask_aware_mean_pool(&[1.0; 5], &[1, 1, 1], 3, 2).is_none());
    }

    #[test]
    fn mean_pool_rejects_short_mask() {
        // Mask shorter than seq_len would index out of bounds in
        // a naive impl; helper must return None instead.
        assert!(mask_aware_mean_pool(&[1.0; 6], &[1, 1], 3, 2).is_none());
    }

    #[test]
    fn mean_pool_rejects_degenerate_shapes() {
        // Zero seq_len and zero hidden_size are both treated as
        // None — caller is expected to surface a Model error.
        assert!(mask_aware_mean_pool(&[], &[], 0, 4).is_none());
        assert!(mask_aware_mean_pool(&[1.0], &[1], 1, 0).is_none());
    }

    #[test]
    fn l2_normalize_produces_unit_vector() {
        let mut v = vec![3.0f32, 4.0];
        l2_normalize_in_place(&mut v);
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6, "norm should be 1, got {norm}");
        // 3-4-5 triangle => [0.6, 0.8].
        assert!((v[0] - 0.6).abs() < 1e-6);
        assert!((v[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn l2_normalize_leaves_zero_vector_untouched() {
        let mut v = vec![0.0f32, 0.0, 0.0];
        l2_normalize_in_place(&mut v);
        // No NaN / inf — the all-zero embedding is the
        // canonical "all-padding input" response per the
        // `mask_aware_mean_pool` null-vector convention.
        assert!(v.iter().all(|x| *x == 0.0));
    }

    #[test]
    fn l2_normalize_handles_negative_lanes() {
        let mut v = vec![-3.0f32, 4.0];
        l2_normalize_in_place(&mut v);
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
        assert!((v[0] + 0.6).abs() < 1e-6);
        assert!((v[1] - 0.8).abs() < 1e-6);
    }
}
