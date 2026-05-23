//! Model lifecycle manager.
//!
//! `docs/DESIGN.md §7.6` describes lazy / eager model
//! distribution: XLM-R is eagerly pre-loaded (~80 MB), while
//! MobileCLIP-S2 (~80 MB) and Whisper (~75–140 MB) are lazily
//! downloaded on first use. Quantization is INT8 by default with
//! INT4 (`MatMulNBits`) on tight-storage devices.
//!
//! This module owns the in-process registry: it does NOT speak
//! HTTP itself — the platform glue implements the
//! [`ModelDownloader`] trait and the manager calls into it. The
//! manager handles caching, versioning, and SHA-256 integrity
//! checks. The on-disk path of each artifact is opaque to the
//! manager: callers pass the absolute path of the downloaded
//! file in [`ModelArtifact`].
//!
//! ## Threading
//!
//! [`ModelManager`] wraps the registry in `RwLock` so multiple
//! background workers can call `ensure_model` / `list_models`
//! concurrently without serializing through a single mutex.
//! Mutating calls (`register_model`, `delete_model`) take the
//! write lock briefly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::Result;

/// Quantization tier for an [`ModelArtifact`].
///
/// - `Float32`: full-precision; used during research only.
/// - `Int8`: default tier shipped to devices.
/// - `Int4`: tight-storage tier (`docs/DESIGN.md §7.6`
///   ONNX `MatMulNBits`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Quantization {
    /// Full f32 precision. ~4× the size of `Int8`.
    Float32,
    /// 8-bit integer quantization. Default tier.
    Int8,
    /// 4-bit integer quantization. Tight-storage tier.
    Int4,
}

/// One on-disk model artifact in the local cache.
///
/// `model_id` is the encoder family (`"xlmr"`, `"mobileclip_s2"`,
/// `"whisper-base"`, …); `model_version` is the
/// `<encoder>@v<rev>` tag the cache uses for invalidation (see
/// the [`crate::models::embeddings::XLMR_MODEL_VERSION`] /
/// [`crate::models::clip::MOBILECLIP_S2_MODEL_VERSION`]
/// constants).
#[derive(Debug, Clone)]
pub struct ModelArtifact {
    /// Encoder family (`"xlmr"`, `"mobileclip_s2"`, …).
    pub model_id: String,
    /// Cache-invalidation tag (`"xlmr@v1"`, …).
    pub model_version: String,
    /// Absolute path of the on-disk artifact.
    pub file_path: PathBuf,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Quantization tier.
    pub quantization: Quantization,
    /// Expected SHA-256 of the on-disk artifact (32 bytes).
    pub sha256: [u8; 32],
}

/// Configuration knobs for [`ModelManager`].
///
/// `models_dir` is informational — the manager does not enforce
/// that registered artifacts live under it (callers may keep
/// MobileCLIP-S2 in a Documents subfolder, Whisper in Caches,
/// etc.). It is used as the *default* download destination by
/// [`ModelManager::resolve_destination`].
#[derive(Debug, Clone)]
pub struct ModelManagerConfig {
    /// Default destination directory for downloaded artifacts.
    pub models_dir: PathBuf,
    /// Prefer INT4 over INT8 even when storage is plentiful.
    pub prefer_int4: bool,
    /// Soft cap on the on-disk cache (in bytes). Currently used
    /// only by [`ModelManager::is_cache_under_limit`] for
    /// telemetry; eviction is the platform layer's job.
    pub max_cache_bytes: u64,
}

impl Default for ModelManagerConfig {
    fn default() -> Self {
        Self {
            models_dir: PathBuf::from(""),
            prefer_int4: false,
            // 1 GiB — comfortably exceeds the XLM-R + MobileCLIP-S2
            // + Whisper-base footprint at INT8.
            max_cache_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Storage threshold below which [`ModelManager::select_quantization`]
/// downgrades the default tier from `Int8` to `Int4`.
///
/// 512 MiB matches the documented "tight-storage" cutoff in
/// `docs/DESIGN.md §7.6`.
pub const TIGHT_STORAGE_THRESHOLD_BYTES: u64 = 512 * 1024 * 1024;

/// Static descriptor for a model artifact.
///
/// Unlike [`ModelArtifact`] (which carries dynamic on-disk state
/// file path, size, sha256), this is a compile-time constant
/// describing the *expected* shape of the artifact:
/// `(model_id, model_version, filename, quantization)`. The
/// platform downloader bridge resolves the spec to a concrete
/// [`ModelArtifact`] by downloading `filename` to a per-device
/// path and computing the sha256.
///
/// The four `XLMR_INT4_ARTIFACT` / `XLMR_INT8_ARTIFACT` /
/// `MOBILECLIP_S2_INT4_ARTIFACT` / `MOBILECLIP_S2_INT8_ARTIFACT`
/// constants below are the source of truth for what each
/// encoder ships at each quantization tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelArtifactSpec {
    /// Encoder family (`"xlmr"`, `"mobileclip_s2"`).
    pub model_id: &'static str,
    /// Cache-invalidation tag (`"xlmr@v1"`, `"mobileclip_s2@v1"`).
    pub model_version: &'static str,
    /// Canonical on-disk filename (`"xlmr-v1-int8.onnx"`, …).
    pub filename: &'static str,
    /// Quantization tier this spec describes.
    pub quantization: Quantization,
}

/// XLM-R INT8 artifact descriptor — the default tier shipped to
/// devices with normal storage headroom.
pub const XLMR_INT8_ARTIFACT: ModelArtifactSpec = ModelArtifactSpec {
    model_id: "xlmr",
    model_version: crate::models::embeddings::XLMR_MODEL_VERSION,
    filename: crate::models::embeddings::XLMR_INT8_FILENAME,
    quantization: Quantization::Int8,
};

/// XLM-R INT4 artifact descriptor — the tight-storage tier
/// (`docs/DESIGN.md §7.6`, ONNX `MatMulNBits`).
pub const XLMR_INT4_ARTIFACT: ModelArtifactSpec = ModelArtifactSpec {
    model_id: "xlmr",
    model_version: crate::models::embeddings::XLMR_MODEL_VERSION,
    filename: crate::models::embeddings::XLMR_INT4_FILENAME,
    quantization: Quantization::Int4,
};

/// MobileCLIP-S2 INT8 artifact descriptor — the default tier
/// shipped to devices with normal storage headroom.
pub const MOBILECLIP_S2_INT8_ARTIFACT: ModelArtifactSpec = ModelArtifactSpec {
    model_id: "mobileclip_s2",
    model_version: crate::models::clip::MOBILECLIP_S2_MODEL_VERSION,
    filename: crate::models::clip::MOBILECLIP_S2_INT8_FILENAME,
    quantization: Quantization::Int8,
};

/// MobileCLIP-S2 INT4 artifact descriptor — the tight-storage
/// tier (`docs/DESIGN.md §7.6`).
pub const MOBILECLIP_S2_INT4_ARTIFACT: ModelArtifactSpec = ModelArtifactSpec {
    model_id: "mobileclip_s2",
    model_version: crate::models::clip::MOBILECLIP_S2_MODEL_VERSION,
    filename: crate::models::clip::MOBILECLIP_S2_INT4_FILENAME,
    quantization: Quantization::Int4,
};

/// Object-safe seam for the platform downloader bridge.
///
/// The Rust core never speaks HTTP itself — the iOS / Android /
/// desktop runtimes implement `download_model` against their
/// native networking stack and hand the result back. The
/// downloader is responsible for landing the bytes at `dest`,
/// computing the SHA-256, and returning a fully-populated
/// [`ModelArtifact`]; the [`ModelManager`] re-runs the SHA-256
/// check via [`ModelManager::verify_integrity`] before declaring
/// the artifact available.
pub trait ModelDownloader: std::fmt::Debug + Send + Sync {
    /// Download `(model_id, model_version)` to `dest`. The
    /// returned [`ModelArtifact`] MUST be self-consistent
    /// (`sha256` matches the bytes at `file_path`, etc.).
    fn download_model(
        &self,
        model_id: &str,
        model_version: &str,
        dest: &Path,
    ) -> Result<ModelArtifact>;
}

/// Always-`NotImplemented` `ModelDownloader` used in tests and
/// during early bring-up.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopModelDownloader;

impl ModelDownloader for NoopModelDownloader {
    fn download_model(
        &self,
        _model_id: &str,
        _model_version: &str,
        _dest: &Path,
    ) -> Result<ModelArtifact> {
        Err(crate::Error::NotImplemented("model_downloader"))
    }
}

/// In-process model-cache registry.
///
/// `(model_id, model_version)` is the registry key. The manager
/// is intentionally a thin index — it does not own files on
/// disk, only their metadata + integrity contracts.
#[derive(Debug)]
pub struct ModelManager {
    config: ModelManagerConfig,
    artifacts: RwLock<HashMap<(String, String), ModelArtifact>>,
}

impl ModelManager {
    /// Build a fresh manager with the supplied config.
    pub fn new(config: ModelManagerConfig) -> Self {
        Self {
            config,
            artifacts: RwLock::new(HashMap::new()),
        }
    }

    /// Borrow the active config.
    pub fn config(&self) -> &ModelManagerConfig {
        &self.config
    }

    /// Lookup a registered artifact for `(model_id,
    /// model_version)`. Returns the registered artifact if
    /// present, else [`crate::Error::NotImplemented("model_not_cached")`].
    ///
    /// The "not cached" branch surfaces as `NotImplemented`
    /// (rather than a freshly-defined error) so callers can
    /// distinguish "you never installed a downloader" from "the
    /// downloader returned an actual transport error".
    pub fn ensure_model(&self, model_id: &str, model_version: &str) -> Result<ModelArtifact> {
        let guard = self.artifacts.read().map_err(|_| {
            crate::Error::Model(crate::models::ModelError::LockPoisoned(
                "model_manager_registry",
            ))
        })?;
        guard
            .get(&(model_id.to_string(), model_version.to_string()))
            .cloned()
            .ok_or(crate::Error::NotImplemented("model_not_cached"))
    }

    /// Register a downloaded artifact in the cache.
    ///
    /// Re-registering the same `(model_id, model_version)` pair
    /// replaces the previous metadata. Callers should call
    /// [`Self::verify_integrity`] before registering.
    pub fn register_model(&self, artifact: ModelArtifact) -> Result<()> {
        let mut guard = self.artifacts.write().map_err(|_| {
            crate::Error::Model(crate::models::ModelError::LockPoisoned(
                "model_manager_registry",
            ))
        })?;
        let key = (artifact.model_id.clone(), artifact.model_version.clone());
        guard.insert(key, artifact);
        Ok(())
    }

    /// Verify the on-disk SHA-256 of `artifact.file_path`
    /// matches `artifact.sha256`.
    ///
    /// Returns `Ok(true)` on a match, `Ok(false)` on a hash
    /// mismatch, and `Err(crate::Error::Storage)` when the file
    /// cannot be read (missing, permission-denied, …).
    pub fn verify_integrity(&self, artifact: &ModelArtifact) -> Result<bool> {
        // We intentionally use SHA-256 (not BLAKE3) to match the
        // upstream artifact-distribution channel; BLAKE3 here
        // would force every artifact provider to publish two
        // hashes.
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(&artifact.file_path)
            .map_err(|e| crate::Error::Storage(format!("model read: {e}").into()))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let got = hasher.finalize();
        Ok(got.as_slice() == artifact.sha256)
    }

    /// List every registered artifact in unspecified order.
    pub fn list_models(&self) -> Vec<ModelArtifact> {
        match self.artifacts.read() {
            Ok(guard) => guard.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Remove the artifact for `(model_id, model_version)`.
    /// Returns `Ok(())` whether or not the row existed —
    /// idempotent.
    pub fn delete_model(&self, model_id: &str, model_version: &str) -> Result<()> {
        let mut guard = self.artifacts.write().map_err(|_| {
            crate::Error::Model(crate::models::ModelError::LockPoisoned(
                "model_manager_registry",
            ))
        })?;
        guard.remove(&(model_id.to_string(), model_version.to_string()));
        Ok(())
    }

    /// Pick a quantization tier for `model_id` given the
    /// reported free `available_storage` in bytes.
    ///
    /// - If [`ModelManagerConfig::prefer_int4`] is set, always
    ///   returns `Int4`.
    /// - Otherwise, returns `Int4` when free storage is below
    ///   [`TIGHT_STORAGE_THRESHOLD_BYTES`], `Int8` otherwise.
    ///
    /// `model_id` is currently unused — the same policy applies
    /// to every encoder. Reserved for per-model overrides in a
    /// follow-up.
    pub fn select_quantization(&self, _model_id: &str, available_storage: u64) -> Quantization {
        if self.config.prefer_int4 {
            return Quantization::Int4;
        }
        if available_storage < TIGHT_STORAGE_THRESHOLD_BYTES {
            Quantization::Int4
        } else {
            Quantization::Int8
        }
    }

    /// Sum of `size_bytes` across every registered artifact.
    /// Cheap to call — purely an in-memory operation.
    pub fn total_cache_bytes(&self) -> u64 {
        match self.artifacts.read() {
            Ok(guard) => guard.values().map(|a| a.size_bytes).sum(),
            Err(_) => 0,
        }
    }

    /// Whether the registry is below the configured soft cap.
    pub fn is_cache_under_limit(&self) -> bool {
        self.total_cache_bytes() <= self.config.max_cache_bytes
    }

    /// Pick the correct [`ModelArtifactSpec`] for `model_id`
    /// given the device's free `available_storage`.
    ///
    /// Defers the storage-tier decision to
    /// [`Self::select_quantization`] and looks up the matching
    /// pre-canned spec
    /// ([`XLMR_INT4_ARTIFACT`] / [`XLMR_INT8_ARTIFACT`] /
    /// [`MOBILECLIP_S2_INT4_ARTIFACT`] /
    /// [`MOBILECLIP_S2_INT8_ARTIFACT`]).
    ///
    /// Returns `None` when `model_id` is not one of the known
    /// encoders.
    pub fn resolve_artifact(
        &self,
        model_id: &str,
        available_storage: u64,
    ) -> Option<ModelArtifactSpec> {
        let q = self.select_quantization(model_id, available_storage);
        match (model_id, q) {
            ("xlmr", Quantization::Int4) => Some(XLMR_INT4_ARTIFACT),
            ("xlmr", Quantization::Int8) => Some(XLMR_INT8_ARTIFACT),
            ("xlmr", Quantization::Float32) => Some(XLMR_INT8_ARTIFACT),
            ("mobileclip_s2", Quantization::Int4) => Some(MOBILECLIP_S2_INT4_ARTIFACT),
            ("mobileclip_s2", Quantization::Int8) => Some(MOBILECLIP_S2_INT8_ARTIFACT),
            ("mobileclip_s2", Quantization::Float32) => Some(MOBILECLIP_S2_INT8_ARTIFACT),
            _ => None,
        }
    }

    /// Default destination filename for `(model_id,
    /// model_version)` under the configured `models_dir`.
    pub fn resolve_destination(&self, model_id: &str, model_version: &str) -> PathBuf {
        // `<models_dir>/<model_id>-<sanitized_version>.onnx`. We
        // sanitize `@` because it confuses some Windows tooling
        // even though NTFS itself permits it.
        let safe_version = model_version.replace('@', "_");
        let filename = format!("{model_id}-{safe_version}.onnx");
        self.config.models_dir.join(filename)
    }

    // -------------------------------------------------------------
    // EP benchmark capture
    // and auto-selection.
    // -------------------------------------------------------------

    /// Run an EP benchmark for `(model_id, ep)` via the supplied
    /// runner. Returns the resulting [`crate::models::ep_tuning::EpBenchmark`]
    /// without persisting it — callers feed the benchmark into
    /// an [`crate::models::ep_tuning::EpBenchmarkCache`] if they
    /// want it to survive process restarts.
    pub fn benchmark_ep(
        &self,
        model_id: &str,
        ep: crate::models::ep_tuning::ExecutionProvider,
        runner: &dyn crate::models::ep_tuning::EpBenchmarkRunner,
    ) -> Result<crate::models::ep_tuning::EpBenchmark> {
        // We benchmark against the *first* registered version of
        // this model_id. Production callers typically register a
        // single version per model_id, but if multiple are
        // present any one is acceptable for the benchmark
        // (latency depends on the EP, not the artifact version).
        let guard = self.artifacts.read().map_err(|_| {
            crate::Error::Model(crate::models::ModelError::LockPoisoned(
                "model_manager_registry",
            ))
        })?;
        let artifact = guard
            .iter()
            .find(|((id, _), _)| id == model_id)
            .map(|(_, a)| a.clone())
            .ok_or_else(|| {
                crate::Error::Model(crate::models::ModelError::Custom(format!(
                    "benchmark_ep: model_id {model_id} not registered"
                )))
            })?;
        drop(guard);
        runner.run_benchmark(ep, &artifact)
    }

    /// Pick the EP with the lowest measured latency for
    /// `model_id` from the supplied cache, falling back to the
    /// supplied `fallback_chain` when no benchmark is recorded.
    /// See [`crate::models::ep_tuning::select_best_ep`].
    pub fn select_optimal_ep(
        &self,
        model_id: &str,
        cache: &crate::models::ep_tuning::EpBenchmarkCache,
        fallback_chain: &[crate::models::ep_tuning::ExecutionProvider],
    ) -> crate::models::ep_tuning::ExecutionProvider {
        let benchmarks = cache.benchmarks_for_model(model_id);
        crate::models::ep_tuning::select_best_ep(&benchmarks, fallback_chain)
    }
}

impl Default for ModelManager {
    fn default() -> Self {
        Self::new(ModelManagerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    fn artifact_at(dir: &Path, model_id: &str, model_version: &str, bytes: &[u8]) -> ModelArtifact {
        let path = dir.join(format!("{model_id}-{model_version}.bin"));
        std::fs::write(&path, bytes).expect("write fixture");
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let mut sha = [0u8; 32];
        sha.copy_from_slice(hasher.finalize().as_slice());
        ModelArtifact {
            model_id: model_id.into(),
            model_version: model_version.into(),
            file_path: path,
            size_bytes: bytes.len() as u64,
            quantization: Quantization::Int8,
            sha256: sha,
        }
    }

    #[test]
    fn register_and_ensure_round_trip() {
        let tmp = TempDir::new().unwrap();
        let mgr = ModelManager::default();
        let art = artifact_at(tmp.path(), "xlmr", "v1", b"hello");
        mgr.register_model(art.clone()).unwrap();
        let got = mgr.ensure_model("xlmr", "v1").unwrap();
        assert_eq!(got.file_path, art.file_path);
        assert_eq!(got.size_bytes, 5);
    }

    #[test]
    fn ensure_missing_returns_not_implemented() {
        let mgr = ModelManager::default();
        let err = mgr.ensure_model("xlmr", "v1").unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }

    #[test]
    fn verify_integrity_passes_for_correct_hash() {
        let tmp = TempDir::new().unwrap();
        let mgr = ModelManager::default();
        let art = artifact_at(tmp.path(), "xlmr", "v1", b"correct");
        assert!(mgr.verify_integrity(&art).unwrap());
    }

    #[test]
    fn verify_integrity_fails_for_wrong_hash() {
        let tmp = TempDir::new().unwrap();
        let mgr = ModelManager::default();
        let mut art = artifact_at(tmp.path(), "xlmr", "v1", b"correct");
        art.sha256[0] ^= 0xFF;
        assert!(!mgr.verify_integrity(&art).unwrap());
    }

    #[test]
    fn verify_integrity_io_error_when_file_missing() {
        let mgr = ModelManager::default();
        let art = ModelArtifact {
            model_id: "xlmr".into(),
            model_version: "v1".into(),
            file_path: PathBuf::from("/definitely/does/not/exist.bin"),
            size_bytes: 0,
            quantization: Quantization::Int8,
            sha256: [0u8; 32],
        };
        let err = mgr.verify_integrity(&art).unwrap_err();
        assert!(matches!(err, crate::Error::Storage(_)));
    }

    #[test]
    fn list_models_returns_every_registration() {
        let tmp = TempDir::new().unwrap();
        let mgr = ModelManager::default();
        mgr.register_model(artifact_at(tmp.path(), "xlmr", "v1", b"a"))
            .unwrap();
        mgr.register_model(artifact_at(tmp.path(), "mobileclip_s2", "v1", b"bb"))
            .unwrap();
        let mut listed: Vec<_> = mgr.list_models().into_iter().map(|a| a.model_id).collect();
        listed.sort();
        assert_eq!(listed, vec!["mobileclip_s2", "xlmr"]);
    }

    #[test]
    fn delete_removes_from_cache_and_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let mgr = ModelManager::default();
        mgr.register_model(artifact_at(tmp.path(), "xlmr", "v1", b"x"))
            .unwrap();
        mgr.delete_model("xlmr", "v1").unwrap();
        let err = mgr.ensure_model("xlmr", "v1").unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
        // Second delete is a no-op, not an error.
        mgr.delete_model("xlmr", "v1").unwrap();
    }

    #[test]
    fn select_quantization_picks_int4_for_tight_storage() {
        let mgr = ModelManager::default();
        // 100 MiB free → tight.
        assert_eq!(
            mgr.select_quantization("xlmr", 100 * 1024 * 1024),
            Quantization::Int4
        );
        // 4 GiB free → comfortable.
        assert_eq!(
            mgr.select_quantization("xlmr", 4u64 * 1024 * 1024 * 1024),
            Quantization::Int8
        );
    }

    #[test]
    fn select_quantization_respects_prefer_int4() {
        let mgr = ModelManager::new(ModelManagerConfig {
            prefer_int4: true,
            ..Default::default()
        });
        assert_eq!(
            mgr.select_quantization("xlmr", 4u64 * 1024 * 1024 * 1024),
            Quantization::Int4
        );
    }

    #[test]
    fn total_cache_bytes_sums_registrations() {
        let tmp = TempDir::new().unwrap();
        let mgr = ModelManager::default();
        mgr.register_model(artifact_at(tmp.path(), "xlmr", "v1", b"AA"))
            .unwrap();
        mgr.register_model(artifact_at(tmp.path(), "mobileclip_s2", "v1", b"BBB"))
            .unwrap();
        assert_eq!(mgr.total_cache_bytes(), 5);
    }

    #[test]
    fn noop_downloader_returns_not_implemented() {
        let dl = NoopModelDownloader;
        let tmp = TempDir::new().unwrap();
        let err = dl
            .download_model("xlmr", "v1", &tmp.path().join("x.bin"))
            .unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented(_)));
    }

    #[test]
    fn resolve_destination_sanitizes_at_sign() {
        let mgr = ModelManager::new(ModelManagerConfig {
            models_dir: PathBuf::from("/tmp/models"),
            ..Default::default()
        });
        let p = mgr.resolve_destination("xlmr", "xlmr@v1");
        assert!(p.to_string_lossy().contains("xlmr_v1"));
        assert!(!p.to_string_lossy().contains('@'));
    }

    // -----------------------------------------------------------
    // INT4 selection +
    // ModelArtifactSpec coverage.
    // -----------------------------------------------------------

    #[test]
    fn select_quantization_returns_int4_for_tight_storage() {
        let mgr = ModelManager::default();
        // 1 MiB free is well below the 512 MiB threshold.
        assert_eq!(
            mgr.select_quantization("xlmr", 1024 * 1024),
            Quantization::Int4
        );
        // Right at the threshold (still less than) returns Int4.
        assert_eq!(
            mgr.select_quantization("xlmr", TIGHT_STORAGE_THRESHOLD_BYTES - 1),
            Quantization::Int4
        );
    }

    #[test]
    fn select_quantization_returns_int8_for_normal_storage() {
        let mgr = ModelManager::default();
        // Exactly at the threshold falls into the comfortable
        // bucket because the comparison is `<` (strict).
        assert_eq!(
            mgr.select_quantization("xlmr", TIGHT_STORAGE_THRESHOLD_BYTES),
            Quantization::Int8
        );
        assert_eq!(
            mgr.select_quantization("xlmr", 8u64 * 1024 * 1024 * 1024),
            Quantization::Int8
        );
    }

    #[test]
    fn model_artifact_int4_variants_have_correct_names() {
        assert_eq!(XLMR_INT4_ARTIFACT.model_id, "xlmr");
        assert_eq!(
            XLMR_INT4_ARTIFACT.filename,
            crate::models::embeddings::XLMR_INT4_FILENAME
        );
        assert_eq!(XLMR_INT4_ARTIFACT.quantization, Quantization::Int4);
        assert!(XLMR_INT4_ARTIFACT.filename.contains("int4"));

        assert_eq!(MOBILECLIP_S2_INT4_ARTIFACT.model_id, "mobileclip_s2");
        assert_eq!(
            MOBILECLIP_S2_INT4_ARTIFACT.filename,
            crate::models::clip::MOBILECLIP_S2_INT4_FILENAME
        );
        assert_eq!(MOBILECLIP_S2_INT4_ARTIFACT.quantization, Quantization::Int4);
        assert!(MOBILECLIP_S2_INT4_ARTIFACT.filename.contains("int4"));

        // INT8 / INT4 specs differ on quantization + filename.
        assert_ne!(XLMR_INT4_ARTIFACT.filename, XLMR_INT8_ARTIFACT.filename);
        assert_ne!(
            XLMR_INT4_ARTIFACT.quantization,
            XLMR_INT8_ARTIFACT.quantization
        );
    }

    #[test]
    fn resolve_artifact_selects_int4_when_storage_tight() {
        let mgr = ModelManager::default();

        let xlmr_tight = mgr
            .resolve_artifact("xlmr", 100 * 1024 * 1024)
            .expect("xlmr resolves");
        assert_eq!(xlmr_tight, XLMR_INT4_ARTIFACT);

        let clip_tight = mgr
            .resolve_artifact("mobileclip_s2", 100 * 1024 * 1024)
            .expect("clip resolves");
        assert_eq!(clip_tight, MOBILECLIP_S2_INT4_ARTIFACT);

        // Comfortable storage gets the INT8 spec.
        let xlmr_normal = mgr
            .resolve_artifact("xlmr", 4u64 * 1024 * 1024 * 1024)
            .expect("xlmr resolves");
        assert_eq!(xlmr_normal, XLMR_INT8_ARTIFACT);
        let clip_normal = mgr
            .resolve_artifact("mobileclip_s2", 4u64 * 1024 * 1024 * 1024)
            .expect("clip resolves");
        assert_eq!(clip_normal, MOBILECLIP_S2_INT8_ARTIFACT);

        // Unknown encoders → None.
        assert!(mgr
            .resolve_artifact("unknown", 1024 * 1024 * 1024)
            .is_none());
    }
}
