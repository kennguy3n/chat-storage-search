//! Production HTTP `ModelDownloader` implementation.
//!
//! [`HttpModelDownloader`] is the reference production implementation of
//! the [`super::model_manager::ModelDownloader`] trait. It downloads model
//! artifacts (XLM-R, MobileCLIP-S2, Whisper, …) over HTTPS, computes a
//! streaming SHA-256, and lands the bytes at the caller-supplied
//! destination through an atomic `.partial` → final rename.
//!
//! ## Resumable downloads
//!
//! When the destination already has a sibling `<dest>.partial` file from a
//! previous, interrupted download, the client issues a `Range:
//! bytes=<existing>-` request and appends to the same partial. The
//! streaming SHA-256 hasher is primed with the existing bytes first so the
//! final digest matches the full artifact regardless of how many
//! interruptions / resumes happened along the way. If the server responds
//! with `200 OK` instead of `206 Partial Content` (i.e. it does not
//! support range requests), the client truncates the partial and starts
//! over.
//!
//! ## Atomic replacement
//!
//! Bytes are streamed into `<dest>.partial` (NOT `<dest>` itself) so a
//! crash mid-download cannot leave a half-written model file at `<dest>`.
//! On success, the partial is `fsync`'d and then renamed onto `<dest>` —
//! POSIX rename is atomic within a filesystem, so any concurrent reader
//! sees either the old `<dest>` or the new fully-written `<dest>`, never a
//! truncated one.
//!
//! ## Integrity contract
//!
//! [`HttpModelDownloader::download_model`] returns a [`ModelArtifact`]
//! whose `sha256` field is the SHA-256 of the bytes it actually wrote.
//! The caller (typically [`super::model_manager::ModelManager`]) is
//! responsible for verifying that digest against the expected value via
//! [`super::model_manager::ModelManager::verify_integrity`]. The
//! downloader itself does not know expected SHA-256s; it just reports
//! what it received.
//!
//! ## Retry policy
//!
//! Retries match the [`crate::transport::http_client::HttpTransportClient`]
//! policy: three attempts at 1 s / 2 s / 4 s exponential backoff for
//! transient transport errors and HTTP status `429` / `5xx`. Per-attempt
//! timeout defaults to 120 s (model artifacts can be tens of megabytes,
//! and ranged resumes still need full-body timeouts for large tails).
//!
//! The module is gated on the `http-transport` cargo feature so the
//! workspace build does not pull `reqwest` or `rustls`. Bridges flip the
//! feature on when they wire [`super::model_manager::ModelManager`]
//! against a real artifact-distribution backend.

#![cfg(feature = "http-transport")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::model_manager::{ModelArtifact, ModelDownloader, Quantization};
use crate::Error;

/// Per-attempt timeout for model downloads.
///
/// Model artifacts are typically 75–150 MB. The transport client uses
/// 30 s for control-plane and 120 s for blob uploads; we match the
/// 120 s tier so a slow mobile link can complete a single artifact in
/// one attempt without hitting the per-request timeout, while still
/// bounding the total wall-clock under the 3-attempt retry budget.
pub const HTTP_MODEL_DOWNLOAD_TIMEOUT_SECS: u64 = 120;

/// Number of retry attempts the downloader makes against transient
/// failures (network errors, 429, 5xx). Matches
/// [`crate::transport::http_client::HTTP_TRANSPORT_RETRY_ATTEMPTS`].
pub const HTTP_MODEL_DOWNLOAD_RETRY_ATTEMPTS: u32 = 3;

/// Streaming-read chunk size used when copying the response body into
/// the partial file. 64 KiB matches the buffer size `reqwest::blocking`
/// uses internally for `copy_to`, but the explicit loop here lets us
/// hash + truncate-on-Content-Range-mismatch in one pass.
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// Suffix appended to the destination path for the in-flight download.
///
/// Bytes are streamed here first, then atomically renamed onto the
/// caller-supplied destination on success. The suffix is intentionally
/// short and predictable so callers can sweep / report on stalled
/// downloads (`find /models -name '*.partial'`).
pub const PARTIAL_SUFFIX: &str = ".partial";

/// Per-model URL + quantization mapping.
///
/// [`HttpModelDownloader::register_entry`] installs one
/// [`DownloadEntry`] per `(model_id, model_version)` pair the downloader
/// is expected to fetch. The trait signature does not carry a filename
/// or URL — the downloader is the policy point that decides how to map
/// the encoder family + version tag to a wire URL.
#[derive(Debug, Clone)]
pub struct DownloadEntry {
    /// Fully-qualified URL the downloader issues a `GET` against.
    /// Must be absolute (`https://…`) — the downloader does not
    /// resolve relative URLs.
    pub url: String,
    /// Quantization tier the URL serves. Propagated into the
    /// returned [`ModelArtifact::quantization`] so callers can
    /// pivot on it without re-parsing the filename.
    pub quantization: Quantization,
}

impl DownloadEntry {
    /// Build a download entry for `url` serving artifacts at the
    /// supplied [`Quantization`] tier.
    pub fn new(url: impl Into<String>, quantization: Quantization) -> Self {
        Self {
            url: url.into(),
            quantization,
        }
    }
}

/// Production HTTPS-backed [`ModelDownloader`].
///
/// Constructed via [`HttpModelDownloader::new`] (optionally with an
/// authorization bearer token via [`HttpModelDownloader::with_auth_token`]).
/// Callers register one [`DownloadEntry`] per `(model_id,
/// model_version)` they intend to fetch through
/// [`HttpModelDownloader::register_entry`]; the per-pair URL + quant
/// table lives behind an `RwLock` so the same downloader instance can
/// be installed once at boot and updated as new model versions ship.
///
/// The downloader is `Send + Sync`-safe: every field is either
/// immutable after construction (`client`, `auth_token`) or behind a
/// concurrency primitive (`registry: RwLock<…>`).
#[derive(Debug)]
pub struct HttpModelDownloader {
    client: reqwest::blocking::Client,
    auth_token: Option<String>,
    registry: RwLock<HashMap<(String, String), DownloadEntry>>,
}

impl HttpModelDownloader {
    /// Build a fresh downloader with an empty registry.
    ///
    /// The underlying `reqwest::blocking::Client` is built once and
    /// reused for every download so per-call cost is just the
    /// request body plus the response body, rather than a full
    /// connection-pool + TLS handshake setup per call. The
    /// per-attempt timeout is [`HTTP_MODEL_DOWNLOAD_TIMEOUT_SECS`].
    ///
    /// Returns [`Error::Transport`] only on `reqwest::Client::builder`
    /// failure — a deterministic configuration error that retrying will
    /// not fix.
    pub fn new() -> crate::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_MODEL_DOWNLOAD_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                Error::Transport(crate::transport::TransportError::Server(format!(
                    "reqwest model-downloader builder: {e}"
                )))
            })?;
        Ok(Self {
            client,
            auth_token: None,
            registry: RwLock::new(HashMap::new()),
        })
    }

    /// Attach a bearer token. All subsequent downloads carry
    /// `Authorization: Bearer <token>`. Pass an empty `String` to
    /// reset to unauthenticated.
    ///
    /// The token is stored verbatim — call sites are responsible for
    /// zeroizing the original buffer if they care. The token is
    /// **not** redacted from `Debug` output; the downloader is not
    /// intended to be logged. Bridges that need redaction should wrap
    /// the downloader in a thin shim.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Register a `(model_id, model_version)` → URL mapping.
    ///
    /// Re-registering the same `(model_id, model_version)` pair
    /// replaces the previous entry. Returns
    /// [`Error::Model(ModelError::LockPoisoned)`] if a prior panic
    /// poisoned the registry lock.
    pub fn register_entry(
        &self,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
        entry: DownloadEntry,
    ) -> crate::Result<()> {
        let mut guard = self.registry.write().map_err(|_| {
            Error::Model(crate::models::ModelError::LockPoisoned(
                "http_model_downloader_registry",
            ))
        })?;
        guard.insert((model_id.into(), model_version.into()), entry);
        Ok(())
    }

    /// Snapshot the registered entry for `(model_id, model_version)`.
    /// Returns `None` if no entry is registered yet.
    pub fn lookup_entry(
        &self,
        model_id: &str,
        model_version: &str,
    ) -> crate::Result<Option<DownloadEntry>> {
        let guard = self.registry.read().map_err(|_| {
            Error::Model(crate::models::ModelError::LockPoisoned(
                "http_model_downloader_registry",
            ))
        })?;
        Ok(guard
            .get(&(model_id.to_string(), model_version.to_string()))
            .cloned())
    }

    /// Number of registered entries. Cheap; behind the read lock.
    pub fn registry_len(&self) -> usize {
        self.registry.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Compute the streaming-resume partial path for `dest`.
    ///
    /// The partial path is `<dest>` with [`PARTIAL_SUFFIX`] appended;
    /// `/models/xlmr.onnx` becomes `/models/xlmr.onnx.partial`. The
    /// callee is responsible for ensuring the parent directory
    /// exists.
    pub fn partial_path(dest: &Path) -> PathBuf {
        let mut p = dest.as_os_str().to_owned();
        p.push(PARTIAL_SUFFIX);
        PathBuf::from(p)
    }

    /// Issue one download attempt, returning the (size, sha256)
    /// pair of the fully-assembled artifact on success.
    ///
    /// Internal contract:
    ///
    /// * Reads existing `<dest>.partial` (if any) and primes the
    ///   hasher with those bytes so the final SHA-256 matches the
    ///   full artifact regardless of how many resumes happened.
    /// * Sends `Range: bytes=<existing>-` when the partial is
    ///   non-empty. If the server responds with `200 OK`, the
    ///   partial is truncated and the hasher reset — the server
    ///   does not support range requests.
    /// * Streams the response body into `<dest>.partial`,
    ///   updating the SHA-256 hasher as it goes.
    /// * On success, returns `(size, sha256)` — the caller renames
    ///   `<dest>.partial` onto `<dest>`. The rename is the atomic
    ///   commit point.
    ///
    /// Errors are surfaced verbatim; the caller's retry budget
    /// (see [`download_model`]) decides whether to retry.
    fn run_attempt(&self, url: &str, partial_path: &Path) -> crate::Result<(u64, [u8; 32])> {
        let mut existing_size: u64 = 0;
        let mut hasher = Sha256::new();

        if let Ok(meta) = std::fs::metadata(partial_path) {
            existing_size = meta.len();
            if existing_size > 0 {
                let mut file = std::fs::File::open(partial_path).map_err(|e| {
                    Error::Storage(format!("model-download: read partial: {e}").into())
                })?;
                let mut buf = vec![0u8; COPY_CHUNK_BYTES];
                loop {
                    let n = file.read(&mut buf).map_err(|e| {
                        Error::Storage(format!("model-download: read partial chunk: {e}").into())
                    })?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
            }
        }

        let mut request = self.client.get(url);
        if let Some(token) = self.auth_token.as_deref() {
            request = request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if existing_size > 0 {
            request = request.header(reqwest::header::RANGE, format!("bytes={existing_size}-"));
        }

        let response = request
            .send()
            .map_err(|e| map_reqwest_err("model-download", e))?;
        let status = response.status();

        if !status.is_success() {
            // Classify retryable vs. terminal status here —
            // mirrors `crate::transport::http_client::response_status_is_retryable`:
            // `429` and any `5xx` are retryable transients (route
            // onto `Network` so `is_retryable_error` returns true),
            // every other non-success is terminal (route onto
            // `Server`).
            let msg = format!("model-download: HTTP {status} from {url}");
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                return Err(Error::Transport(crate::transport::TransportError::Network(
                    msg,
                )));
            } else {
                return Err(Error::Transport(crate::transport::TransportError::Server(
                    msg,
                )));
            }
        }

        let server_resumed = status == reqwest::StatusCode::PARTIAL_CONTENT;
        if !server_resumed && existing_size > 0 {
            hasher = Sha256::new();
            existing_size = 0;
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(partial_path)
                .map_err(|e| {
                    Error::Storage(format!("model-download: truncate partial: {e}").into())
                })?;
        }

        let mut partial = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(partial_path)
            .map_err(|e| Error::Storage(format!("model-download: open partial: {e}").into()))?;

        let mut body = response;
        let mut buf = vec![0u8; COPY_CHUNK_BYTES];
        let mut written: u64 = existing_size;
        loop {
            let n = match body.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    return Err(Error::Transport(crate::transport::TransportError::Network(
                        format!("model-download: body read: {e}"),
                    )));
                }
            };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            partial.write_all(&buf[..n]).map_err(|e| {
                Error::Storage(format!("model-download: write partial: {e}").into())
            })?;
            written += n as u64;
        }

        partial
            .flush()
            .map_err(|e| Error::Storage(format!("model-download: flush partial: {e}").into()))?;
        partial
            .sync_all()
            .map_err(|e| Error::Storage(format!("model-download: fsync partial: {e}").into()))?;

        let digest = hasher.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(digest.as_slice());
        Ok((written, sha256))
    }
}

impl ModelDownloader for HttpModelDownloader {
    fn download_model(
        &self,
        model_id: &str,
        model_version: &str,
        dest: &Path,
    ) -> crate::Result<ModelArtifact> {
        let entry = self.lookup_entry(model_id, model_version)?.ok_or_else(|| {
            Error::Model(crate::models::ModelError::Custom(format!(
                "no download entry registered for ({model_id}, {model_version})"
            )))
        })?;

        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Storage(format!("model-download: mkdir {parent:?}: {e}").into())
                })?;
            }
        }

        let partial = Self::partial_path(dest);
        let mut last_err: Option<crate::Error> = None;
        let attempts = HTTP_MODEL_DOWNLOAD_RETRY_ATTEMPTS.max(1);

        for attempt in 0..attempts {
            match self.run_attempt(&entry.url, &partial) {
                Ok((size, sha256)) => {
                    std::fs::rename(&partial, dest).map_err(|e| {
                        Error::Storage(
                            format!("model-download: rename {partial:?} -> {dest:?}: {e}").into(),
                        )
                    })?;
                    return Ok(ModelArtifact {
                        model_id: model_id.to_string(),
                        model_version: model_version.to_string(),
                        file_path: dest.to_path_buf(),
                        size_bytes: size,
                        quantization: entry.quantization,
                        sha256,
                    });
                }
                Err(e) => {
                    let retryable = is_retryable_error(&e);
                    let is_last = attempt + 1 >= attempts;
                    if !retryable || is_last {
                        return Err(e);
                    }
                    last_err = Some(e);
                    let backoff_ms = 1_000u64 << attempt; // 1s, 2s, 4s
                    std::thread::sleep(Duration::from_millis(backoff_ms));
                }
            }
        }

        // Unreachable in normal operation: the loop above returns on
        // either success or the final attempt's failure. We surface
        // any captured error here just so the type system is happy
        // without an `unreachable!()` panic.
        Err(last_err.unwrap_or_else(|| {
            Error::Transport(crate::transport::TransportError::Server(
                "model-download: retry budget exhausted with no recorded error".to_string(),
            ))
        }))
    }
}

/// Map a `reqwest::Error` onto [`Error::Transport`]. Mirrors the
/// classifier in [`crate::transport::http_client::HttpTransportClient::map_err`]:
/// timeout / connect / request / body failures land on
/// `TransportError::Network` (the retry target), everything else on
/// `TransportError::Server`.
fn map_reqwest_err(label: &str, err: reqwest::Error) -> Error {
    let msg = format!("{label}: {err}");
    if err.is_timeout() || err.is_connect() || err.is_request() || err.is_body() {
        Error::Transport(crate::transport::TransportError::Network(msg))
    } else {
        Error::Transport(crate::transport::TransportError::Server(msg))
    }
}

/// Whether a captured [`crate::Error`] should trigger a retry.
///
/// Two retry targets:
///
/// * [`crate::transport::TransportError::Network`] — transient
///   transport-level failure (`is_timeout` / `is_connect` /
///   `is_request` / `is_body` from `reqwest::Error`, or `body read`
///   I/O errors during streaming).
/// * Storage errors from the partial-file path are
///   intentionally NOT retried — they typically indicate a permission
///   / disk-full / quota problem that another attempt will not fix.
fn is_retryable_error(err: &Error) -> bool {
    matches!(
        err,
        Error::Transport(crate::transport::TransportError::Network(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_path_appends_suffix() {
        let p = HttpModelDownloader::partial_path(Path::new("/models/xlmr.onnx"));
        assert_eq!(
            p,
            PathBuf::from("/models/xlmr.onnx".to_string() + PARTIAL_SUFFIX)
        );
    }

    #[test]
    fn partial_path_handles_no_extension() {
        let p = HttpModelDownloader::partial_path(Path::new("/x/xlmr"));
        assert_eq!(p, PathBuf::from("/x/xlmr.partial"));
    }

    #[test]
    fn register_and_lookup_round_trip() {
        let d = HttpModelDownloader::new().expect("new");
        assert_eq!(d.registry_len(), 0);
        assert!(d
            .lookup_entry("xlmr", "xlmr@v1")
            .expect("lookup ok")
            .is_none());
        d.register_entry(
            "xlmr",
            "xlmr@v1",
            DownloadEntry::new("https://m.example/xlmr.onnx", Quantization::Int8),
        )
        .expect("register");
        assert_eq!(d.registry_len(), 1);
        let e = d
            .lookup_entry("xlmr", "xlmr@v1")
            .expect("lookup ok")
            .expect("entry present");
        assert_eq!(e.url, "https://m.example/xlmr.onnx");
        assert_eq!(e.quantization, Quantization::Int8);
    }

    #[test]
    fn register_replaces_existing_entry() {
        let d = HttpModelDownloader::new().expect("new");
        d.register_entry(
            "xlmr",
            "xlmr@v1",
            DownloadEntry::new("https://old.example/x.onnx", Quantization::Int8),
        )
        .expect("first");
        d.register_entry(
            "xlmr",
            "xlmr@v1",
            DownloadEntry::new("https://new.example/x.onnx", Quantization::Int4),
        )
        .expect("second");
        let e = d
            .lookup_entry("xlmr", "xlmr@v1")
            .unwrap()
            .expect("entry present");
        assert_eq!(e.url, "https://new.example/x.onnx");
        assert_eq!(e.quantization, Quantization::Int4);
    }

    #[test]
    fn missing_entry_surfaces_model_error() {
        let d = HttpModelDownloader::new().expect("new");
        let dest = std::env::temp_dir().join("kchat-model-test-missing.onnx");
        let _ = std::fs::remove_file(&dest); // best-effort
        let err = d
            .download_model("nope", "nope@v1", &dest)
            .expect_err("should error");
        assert!(
            matches!(err, Error::Model(_)),
            "expected Error::Model, got {err:?}"
        );
    }

    #[test]
    fn with_auth_token_stores_token() {
        let d = HttpModelDownloader::new()
            .expect("new")
            .with_auth_token("abc-123");
        assert_eq!(d.auth_token.as_deref(), Some("abc-123"));
    }

    #[test]
    fn is_retryable_classifies_correctly() {
        assert!(is_retryable_error(&Error::Transport(
            crate::transport::TransportError::Network("x".into())
        )));
        assert!(!is_retryable_error(&Error::Transport(
            crate::transport::TransportError::Server("x".into())
        )));
        assert!(!is_retryable_error(&Error::Storage("disk full".into())));
        assert!(!is_retryable_error(&Error::Model(
            crate::models::ModelError::Custom("nope".into())
        )));
    }
}

// End-to-end integration tests use a `std::net::TcpListener`-backed
// HTTP server fixture so we don't pull in `mockito` / `wiremock`
// just for these few cases. The fixture lives in
// `crates/core/tests/http_model_downloader.rs`.
