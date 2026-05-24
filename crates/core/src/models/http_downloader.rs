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
//! policy: up to three attempts with exponential backoff between them.
//! The backoff sleeps are 1 s after attempt #1 and 2 s after attempt #2;
//! a third attempt is issued immediately at t = 3 s and a failure on
//! attempt #3 is returned without further sleeping (the 4 s slot from
//! `1 << 2` would be a sleep-then-return, so we skip it). Transient
//! transport errors (network) and HTTP `429` / `5xx` are retryable; every
//! other non-success status (including `416 Range Not Satisfiable`
//! against a stale partial — see [`HttpModelDownloader::run_attempt`])
//! is reclassified inline by `run_attempt`. Per-attempt timeout defaults
//! to 120 s (model artifacts can be tens of megabytes, and ranged
//! resumes still need full-body timeouts for large tails).
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

/// Default base for the exponential-backoff sleep between attempts.
/// The Nth retry (0-indexed) sleeps `base << N` milliseconds, so with
/// the default 1 000 ms the sleeps are 1 s after attempt #1 and 2 s
/// after attempt #2. Tests override this via
/// [`HttpModelDownloader::with_retry_backoff_base_millis`] to compress
/// the wall-clock cost without losing coverage of the retry path.
pub const HTTP_MODEL_DOWNLOAD_BACKOFF_BASE_MILLIS: u64 = 1_000;

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
///
/// `Debug` is implemented manually so the bearer token (if any) is
/// redacted from formatted output — matches the posture of
/// [`crate::transport::http_client::HttpTransportClient`] (see the
/// `http_client_debug_redacts_auth_token` test).
pub struct HttpModelDownloader {
    client: reqwest::blocking::Client,
    auth_token: Option<String>,
    registry: RwLock<HashMap<(String, String), DownloadEntry>>,
    /// Base sleep (milliseconds) for the exponential backoff between
    /// retry attempts. Production callers leave this at the default
    /// [`HTTP_MODEL_DOWNLOAD_BACKOFF_BASE_MILLIS`]; tests override it
    /// via [`HttpModelDownloader::with_retry_backoff_base_millis`] so
    /// the retry path is still exercised without the 1–2 s real-time
    /// sleeps. `0` disables the sleeps entirely.
    retry_backoff_base_millis: u64,
}

impl std::fmt::Debug for HttpModelDownloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpModelDownloader")
            .field("client", &self.client)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            .field("registry_len", &self.registry_len())
            .field("retry_backoff_base_millis", &self.retry_backoff_base_millis)
            .finish()
    }
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
            retry_backoff_base_millis: HTTP_MODEL_DOWNLOAD_BACKOFF_BASE_MILLIS,
        })
    }

    /// Override the base sleep (milliseconds) between retry attempts.
    ///
    /// Used exclusively by integration tests to compress the 1–2 s
    /// real-time sleeps from the default policy so the retry path is
    /// still exercised end-to-end without dominating the test suite
    /// wall-clock. Production callers should leave this at the default
    /// (see [`HTTP_MODEL_DOWNLOAD_BACKOFF_BASE_MILLIS`]). `0` disables
    /// the sleeps entirely; the loop still runs all
    /// [`HTTP_MODEL_DOWNLOAD_RETRY_ATTEMPTS`] attempts but transitions
    /// between them with no wait.
    pub fn with_retry_backoff_base_millis(mut self, base_ms: u64) -> Self {
        self.retry_backoff_base_millis = base_ms;
        self
    }

    /// Attach a bearer token. All subsequent downloads carry
    /// `Authorization: Bearer <token>`. Pass an empty `String` to
    /// reset to unauthenticated — the empty case is filtered into
    /// `None` rather than sending a broken `Authorization: Bearer `
    /// header that servers would reject as `401`.
    ///
    /// The token is stored verbatim — call sites are responsible for
    /// zeroizing the original buffer if they care. The token is
    /// redacted from `Debug` output (see the manual `Debug` impl on
    /// [`HttpModelDownloader`]).
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.auth_token = if token.is_empty() { None } else { Some(token) };
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
            //
            // Special-case `416 Range Not Satisfiable` when we sent
            // a `Range: bytes=<existing>-` header. This means the
            // partial file on disk is larger than the artifact the
            // server is willing to serve (disk corruption, an
            // external tool that tampered with the partial, or a
            // server-side artifact replacement). Delete the partial
            // so the next attempt restarts from byte 0, and surface
            // the error as a retryable `Network` so the outer loop
            // re-runs `run_attempt` without the stale partial.
            if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE && existing_size > 0 {
                let _ = std::fs::remove_file(partial_path);
                return Err(Error::Transport(crate::transport::TransportError::Network(
                    format!(
                        "model-download: HTTP 416 from {url} \
                         (partial size {existing_size} exceeds artifact); \
                         deleted partial, will restart from byte 0"
                    ),
                )));
            }
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

        // Defense-in-depth: when the server returns 206, validate the
        // `Content-Range` start byte matches the `existing_size` we sent
        // in the request's `Range` header. Without this check, a
        // misbehaving or compromised server could send arbitrary bytes
        // appended to our partial; the SHA-256 mismatch would only be
        // caught downstream by `ModelManager::verify_integrity` after a
        // wasted full-body download (potentially 75-150 MB). Catching
        // it here aborts the attempt immediately so the retry budget
        // can attempt recovery (currently as a terminal `Server`
        // error -- a misbehaving server is unlikely to self-heal on
        // retry against the same URL).
        if server_resumed {
            let content_range = response
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            match content_range
                .as_deref()
                .and_then(parse_content_range_first_byte)
            {
                Some(start) if start == existing_size => {
                    // Server-claimed start matches our partial size; OK.
                }
                Some(start) => {
                    return Err(Error::Transport(crate::transport::TransportError::Server(
                        format!(
                            "model-download: 206 Content-Range start {start} \
                             does not match partial size {existing_size} for {url}"
                        ),
                    )));
                }
                None => {
                    return Err(Error::Transport(crate::transport::TransportError::Server(
                        format!(
                            "model-download: 206 response missing parseable \
                             Content-Range header from {url} \
                             (header={content_range:?})"
                        ),
                    )));
                }
            }
        }

        // Open the partial write handle. Two cases:
        //
        // * Server ignored our `Range` and is sending the full body
        //   (200 OK with `existing_size > 0`) — reset the hasher and
        //   open the partial in a single `create + write + truncate`
        //   syscall sequence so there is no handle-less window
        //   between truncation and re-open.
        // * Otherwise (206 resume, or no prior partial) — open with
        //   `create + append` so the body stream extends whatever is
        //   already on disk in place.
        let mut partial = if !server_resumed && existing_size > 0 {
            hasher = Sha256::new();
            existing_size = 0;
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(partial_path)
                .map_err(|e| {
                    Error::Storage(format!("model-download: open/truncate partial: {e}").into())
                })?
        } else {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(partial_path)
                .map_err(|e| Error::Storage(format!("model-download: open partial: {e}").into()))?
        };

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
                    // Exponential backoff between attempts. With the
                    // default `HTTP_MODEL_DOWNLOAD_RETRY_ATTEMPTS = 3`,
                    // the loop reaches this point on `attempt` 0 and
                    // 1 only — attempt 2 short-circuits via `is_last`
                    // above, so the `base << 2` slot is never used.
                    //
                    // Defensive bounds: `checked_shl` on a u64 panics
                    // in debug / wraps to `0` in release when the
                    // shift count is >= 64. If a future change ever
                    // bumps `HTTP_MODEL_DOWNLOAD_RETRY_ATTEMPTS` past
                    // 64 (or some caller increments `attempt` by
                    // hand) the shift would either kill the worker
                    // or silently degrade the backoff to "no sleep".
                    // Cap the shift via `checked_shl`; on overflow,
                    // fall back to `u64::MAX` so the sleep saturates
                    // at the 584-million-year mark — i.e. the
                    // function never gets back to retry, but
                    // crucially does *not* panic and does *not*
                    // silently disable the backoff.
                    if self.retry_backoff_base_millis > 0 {
                        let backoff_ms = self
                            .retry_backoff_base_millis
                            .checked_shl(attempt)
                            .unwrap_or(u64::MAX);
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                    }
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

/// Parse the first byte of an HTTP `Content-Range` header value.
///
/// Accepts the RFC 7233 §4.2 byte-range form:
///
/// * `bytes <start>-<end>/<total>` (regular case),
/// * `bytes <start>-<end>/*` (unknown total),
/// * `bytes */<total>` (unsatisfied range — rejected here because
///   the call site only invokes this on `206 Partial Content`).
///
/// RFC 7233 §4.2 ABNF requires a single SP (`" "`) between the
/// `bytes` unit and the range-spec. We require at least one ASCII
/// whitespace character there — a header like `bytes1024-2047/2048`
/// is non-conformant and is rejected even though a permissive parser
/// could extract `1024` from it. Returns `None` for any header value
/// that does not match the expected prefix or whose start byte does
/// not parse as a `u64`.
fn parse_content_range_first_byte(header: &str) -> Option<u64> {
    let trimmed = header.trim();
    let after_unit = trimmed.strip_prefix("bytes")?;
    // RFC 7233 §4.2 ABNF: `byte-content-range = bytes-unit SP
    // byte-range-resp`. The SP separator is mandatory; reject any
    // header that runs the unit and range together so a malformed
    // server response is observed and aborted here rather than
    // silently parsing into a plausible-looking start byte.
    let first = after_unit.chars().next()?;
    if !first.is_ascii_whitespace() {
        return None;
    }
    let rest = after_unit.trim_start();
    if rest.starts_with('*') {
        // `bytes */<total>` — server is signalling an unsatisfied
        // range; we should not reach this on `206 Partial Content`.
        return None;
    }
    let dash = rest.find('-')?;
    let start = &rest[..dash];
    start.trim().parse::<u64>().ok()
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
    fn with_auth_token_empty_string_resets_to_none() {
        // The builder consumes `self`, so the only way to "reset" is to
        // pass an empty string. Confirm that path doesn't leave us with
        // a `Some("")` that would later send `Authorization: Bearer `
        // (which servers reject as 401).
        let d = HttpModelDownloader::new()
            .expect("new")
            .with_auth_token("abc")
            .with_auth_token("");
        assert!(
            d.auth_token.is_none(),
            "empty token should reset auth to None, got {:?}",
            d.auth_token
        );
    }

    #[test]
    fn debug_redacts_auth_token() {
        // Matches the posture of
        // `crate::transport::http_client::HttpTransportClient` which
        // also redacts its bearer token from `Debug`. Operationally
        // important: log lines that include the downloader should
        // never leak the artifact-distribution credential.
        let d = HttpModelDownloader::new()
            .expect("new")
            .with_auth_token("super-secret-key-do-not-leak");
        let dbg = format!("{d:?}");
        assert!(
            !dbg.contains("super-secret-key-do-not-leak"),
            "Debug output must redact auth token, got: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Debug output should mark the token as redacted, got: {dbg}"
        );
    }

    #[test]
    fn content_range_parser_extracts_first_byte() {
        // Regular case (RFC 7233 §4.2 byte-range with known total).
        assert_eq!(
            parse_content_range_first_byte("bytes 1024-2047/2048"),
            Some(1024)
        );
        // Unknown total — `bytes <start>-<end>/*`.
        assert_eq!(
            parse_content_range_first_byte("bytes 4096-8191/*"),
            Some(4096)
        );
        // Zero start byte.
        assert_eq!(parse_content_range_first_byte("bytes 0-1023/1024"), Some(0));
        // Whitespace tolerance — some servers add extra space after `bytes`.
        assert_eq!(
            parse_content_range_first_byte("bytes   512-1023/1024"),
            Some(512)
        );
        // Leading/trailing whitespace on the header value itself.
        assert_eq!(
            parse_content_range_first_byte("  bytes 100-200/300  "),
            Some(100)
        );
    }

    #[test]
    fn content_range_parser_rejects_malformed_headers() {
        // `bytes */<total>` is RFC's "unsatisfied range" form; not
        // expected on a 206 response. Reject it so the call site
        // surfaces a Server error instead of trusting the body.
        assert_eq!(parse_content_range_first_byte("bytes */1024"), None);
        // Missing the `bytes` unit prefix.
        assert_eq!(parse_content_range_first_byte("0-1023/1024"), None);
        // Non-numeric start byte.
        assert_eq!(parse_content_range_first_byte("bytes abc-1023/1024"), None);
        // No dash in the range.
        assert_eq!(parse_content_range_first_byte("bytes 1024/2048"), None);
        // Empty input.
        assert_eq!(parse_content_range_first_byte(""), None);
        // Wrong unit (e.g. items, pages — non-standard).
        assert_eq!(parse_content_range_first_byte("items 0-9/100"), None);
    }

    #[test]
    fn content_range_parser_requires_space_after_unit() {
        // RFC 7233 §4.2 ABNF mandates SP between `bytes` and the
        // range-spec. A non-conformant header that runs them together
        // must be rejected — otherwise a permissive parser would
        // extract a plausible-looking start byte from a malformed
        // response and silently accept corrupt data.
        assert_eq!(
            parse_content_range_first_byte("bytes1024-2047/2048"),
            None,
            "no space after `bytes` must be rejected"
        );
        assert_eq!(
            parse_content_range_first_byte("bytes-1024/2048"),
            None,
            "dash directly after `bytes` (no SP) must be rejected"
        );
        // Tabs are valid ASCII whitespace per the ABNF (LWSP-char
        // tolerance in legacy HTTP), so we accept them.
        assert_eq!(
            parse_content_range_first_byte("bytes\t512-1023/1024"),
            Some(512),
            "tab separator must be accepted"
        );
    }

    #[test]
    fn with_retry_backoff_base_millis_overrides_default() {
        let d = HttpModelDownloader::new()
            .expect("new")
            .with_retry_backoff_base_millis(7);
        assert_eq!(d.retry_backoff_base_millis, 7);
    }

    #[test]
    fn new_uses_default_backoff_base_millis() {
        let d = HttpModelDownloader::new().expect("new");
        assert_eq!(
            d.retry_backoff_base_millis,
            HTTP_MODEL_DOWNLOAD_BACKOFF_BASE_MILLIS
        );
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
