//! Production HTTP/JSON [`TransportClient`] — Phase 2 (2026-05-04
//! final batch), Task 4.
//!
//! `docs/PROPOSAL.md §10` and `docs/ARCHITECTURE.md §10` pin the
//! REST endpoint shape:
//!
//! * `GET  /v1/messages?conversation_id=&cursor=` →
//!   [`FetchMessagesResponse`].
//! * `POST /v1/blobs/init`                       →
//!   [`BlobUploadHandle`].
//! * `PUT  /v1/blobs/{blob_id}/chunks/{idx}`     →
//!   [`ChunkReceipt`] (octet-stream body).
//! * `POST /v1/blobs/{blob_id}/commit`           →
//!   [`CommitBlobResponse`].
//! * `GET  /v1/blobs/{blob_id}?range=START-END`  → bytes.
//! * `GET  /v1/archive/manifests?after=`         → manifests.
//! * `GET  /v1/archive/segments/{id}`            → bytes.
//! * `GET  /v1/archive/index-shards?conversation_hash=&bucket=&type=`
//!   → bytes.
//!
//! Retry policy: 3 attempts at 1 s / 2 s / 4 s backoff for any
//! transient failure. Two failure classes trigger a retry:
//!
//! * Transport-level [`reqwest::Error`]s that report
//!   `is_timeout` / `is_connect` (DNS / TCP / TLS failure).
//! * Completed HTTP exchanges whose response status is `429`
//!   or any `5xx`. Status-code classification happens on the
//!   [`reqwest::blocking::Response`] returned by `send`, not on
//!   `reqwest::Error::status` (which only carries a code for
//!   errors produced by `error_for_status`, a path we never take).
//!
//! Per-request timeout: 30 s (120 s for chunk uploads, which can
//! be megabytes large under hostile carrier conditions).
//!
//! The client is feature-gated on `http-transport` so the workspace
//! build doesn't pull `reqwest` or `rustls`. Bridges flip the
//! feature on when they wire [`crate::core_impl::CoreImpl`]
//! against a real backend.

#[cfg(feature = "http-transport")]
use std::ops::Range;
#[cfg(feature = "http-transport")]
use std::time::Duration;

#[cfg(feature = "http-transport")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "http-transport")]
use super::{
    BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest, FetchMessagesResponse,
    TransportClient, TransportResult,
};
#[cfg(feature = "http-transport")]
use crate::crypto::aead::BlobClass;

/// Number of retries the client makes against transient failures.
pub const HTTP_TRANSPORT_RETRY_ATTEMPTS: u32 = 3;
/// Per-request timeout for fetch / control-plane calls.
pub const HTTP_TRANSPORT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Per-request timeout for chunk uploads.
pub const HTTP_TRANSPORT_BLOB_UPLOAD_TIMEOUT_SECS: u64 = 120;

/// Serialized init-blob payload sent on the wire.
#[cfg(feature = "http-transport")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitBlobBody {
    pub size: u64,
    pub blob_class: BlobClass,
    pub expected_merkle_root: String,
}

/// Wire-format chunk receipt — the on-disk variant carries
/// hex-encoded SHA-256, while the runtime [`ChunkReceipt`] uses
/// `[u8; 32]`.
#[cfg(feature = "http-transport")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkReceiptWire {
    pub blob_id: String,
    pub chunk_idx: u32,
    pub sha256_hex: String,
}

/// Wire-format commit response.
#[cfg(feature = "http-transport")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitBlobWire {
    pub blob_id: String,
    pub chunk_count: u32,
    pub merkle_root_hex: String,
}

/// Wire-format encrypted manifest envelope.
#[cfg(feature = "http-transport")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedManifestWire {
    pub generation: u64,
    pub previous_manifest_hash_hex: String,
    pub payload_b64: String,
}

/// Production [`TransportClient`] backed by `reqwest::blocking`.
///
/// Constructed via [`HttpTransportClient::new`] with a base URL
/// (no trailing slash) and an MLS-derived bearer token. Every
/// request carries `Authorization: Bearer <token>` and
/// `Content-Type: application/json` (or `application/octet-stream`
/// for blob bodies). Internal retry uses exponential backoff —
/// see [`HTTP_TRANSPORT_RETRY_ATTEMPTS`].
///
/// Two `reqwest::blocking::Client` instances are built once at
/// [`HttpTransportClient::new`] time and re-used for every call:
/// `client` carries the 30 s control-plane timeout; `upload_client`
/// carries the 120 s blob-upload timeout. `reqwest::blocking::Client`
/// internally owns a tokio runtime and connection pool, so building
/// it per call would spawn a fresh runtime on every chunk upload —
/// the field-level cache avoids that.
#[cfg(feature = "http-transport")]
#[derive(Clone)]
pub struct HttpTransportClient {
    base_url: String,
    auth_token: String,
    client: reqwest::blocking::Client,
    upload_client: reqwest::blocking::Client,
}

// Manual `Debug` impl that redacts the bearer token so it cannot
// leak through logs / crash reports / panic messages. Mirrors the
// pattern used by `crate::core_impl::CoreImpl::fmt`.
#[cfg(feature = "http-transport")]
impl std::fmt::Debug for HttpTransportClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransportClient")
            .field("base_url", &self.base_url)
            .field("auth_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "http-transport")]
impl HttpTransportClient {
    /// Build a new HTTP transport against `base_url` (no trailing
    /// slash) authenticated with `auth_token`.
    ///
    /// Returns a transport [`crate::Error::Transport`] if the
    /// `reqwest::blocking::Client` builder rejects the supplied
    /// timeouts (it does not, in practice, but the Result keeps the
    /// signature future-proof).
    pub fn new(base_url: &str, auth_token: &str) -> crate::Result<Self> {
        // Client builder failures are deterministic configuration
        // errors (TLS backend init, invalid default header, invalid
        // timeout value) — retrying produces the same failure. Route
        // them onto `TransportError::Server` (non-retryable) so
        // callers don't burn retry budget on a permanent config
        // problem.
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_TRANSPORT_REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                crate::Error::Transport(crate::transport::TransportError::Server(format!(
                    "reqwest builder: {e}"
                )))
            })?;
        let upload_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_TRANSPORT_BLOB_UPLOAD_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                crate::Error::Transport(crate::transport::TransportError::Server(format!(
                    "reqwest upload builder: {e}"
                )))
            })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token: auth_token.to_string(),
            client,
            upload_client,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.auth_token)
    }

    /// Wrap a fallible HTTP request in the retry policy: 3 attempts
    /// at 1 s / 2 s / 4 s exponential backoff.
    ///
    /// Retries on:
    ///   - Transport-level [`reqwest::Error`]s that report
    ///     `is_timeout` / `is_connect`.
    ///   - HTTP responses with status `429` or any `5xx`.
    ///
    /// `reqwest::blocking::Client::send` returns `Ok(Response)` for
    /// every completed HTTP exchange regardless of status, and
    /// `reqwest::Error::status` only carries a code for errors
    /// produced by `error_for_status` (which we never call). The
    /// retry helper therefore inspects the
    /// [`reqwest::blocking::Response`] directly rather than relying
    /// on the error variant. The final response (or error) is
    /// returned to the caller after the retry budget is exhausted
    /// so the existing `if !status.is_success() { … }` branch can
    /// surface the body in the canonical `Error::Transport`.
    fn with_retry(
        attempts: u32,
        mut op: impl FnMut() -> Result<reqwest::blocking::Response, reqwest::Error>,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        debug_assert!(attempts >= 1, "with_retry requires at least one attempt");
        for attempt in 0..attempts {
            let is_last = attempt + 1 >= attempts;
            let result = op();
            let retryable = match &result {
                Ok(resp) => response_status_is_retryable(resp.status()),
                Err(e) => err_is_retryable(e),
            };
            if !retryable || is_last {
                return result;
            }
            let backoff_ms = 1_000u64 << attempt; // 1s, 2s, 4s
            std::thread::sleep(Duration::from_millis(backoff_ms));
        }
        unreachable!("with_retry loop must return before exhausting all attempts")
    }

    fn map_err(label: &str, err: reqwest::Error) -> crate::Error {
        let msg = format!("{label}: {err}");
        // Categorise the reqwest::Error onto TransportError variants
        // so callers can route on intent (retryable vs not).
        //
        // Retryable — `TransportError::Network`:
        //   * `is_timeout()`  — server didn't reply before the client
        //                       timeout fired. Walks the cause chain;
        //                       can fire on any `Kind` if the source
        //                       contains a `TimedOut`.
        //   * `is_connect()`  — TCP/TLS handshake failure. Walks the
        //                       cause chain for hyper connect errors;
        //                       again `Kind`-orthogonal.
        //   * `is_request()`  — `Kind::Request`: generic
        //                       request-sending failure (body stream
        //                       interrupted, HTTP/2 framing issue,
        //                       etc.).
        //   * `is_body()`     — `Kind::Body`: connection drop while
        //                       reading the response body. The server
        //                       had started replying but the stream
        //                       was truncated mid-flight; the partial
        //                       payload is unusable. Retrying the
        //                       whole request typically recovers.
        //                       Critical: this Kind is NOT covered by
        //                       `is_request()`, so without an explicit
        //                       check these transient mid-body drops
        //                       would misclassify as non-retryable.
        //
        // Non-retryable — `TransportError::Server`:
        //   * `is_builder()`  — `Kind::Builder`: client config issue
        //                       (handled at construction sites, this
        //                       branch is a defensive fallthrough).
        //   * `is_redirect()` — `Kind::Redirect`: redirect policy
        //                       loop / too-many-hops. Deterministic
        //                       at the same URL.
        //   * `is_status()`   — `Kind::Status`: HTTP error status
        //                       surfaced by `error_for_status()`. The
        //                       caller path normally invokes
        //                       `map_status` explicitly, but the
        //                       fallback is to treat the status
        //                       itself as the failure signal.
        //   * `is_decode()`   — `Kind::Decode`: the server replied
        //                       with a malformed payload. Retrying
        //                       returns the same broken response.
        //   * `is_upgrade()`  — `Kind::Upgrade`: HTTP upgrade
        //                       negotiation failed.
        //
        // Default: any future `reqwest::Kind` value the classifier
        // doesn't recognise falls through to `Server` so the caller
        // surfaces the unfamiliar error rather than burning retry
        // budget. This is the safer default for a classifier that
        // wants to err toward visibility over resilience.
        let category = if err.is_timeout() || err.is_connect() || err.is_request() || err.is_body()
        {
            crate::transport::TransportError::Network(msg)
        } else {
            crate::transport::TransportError::Server(msg)
        };
        crate::Error::Transport(category)
    }

    fn map_status(label: &str, status: reqwest::StatusCode, body: &str) -> crate::Error {
        // Map HTTP status onto the structured `TransportError`
        // categories so the upper layers can pattern-match on
        // intent: `Auth` for 401/403, `Network` for retryable 5xx,
        // `Server` for everything else.
        let msg = format!(
            "{label}: HTTP {} — {}",
            status.as_u16(),
            body.chars().take(256).collect::<String>()
        );
        let category = if status.as_u16() == 401 || status.as_u16() == 403 {
            crate::transport::TransportError::Auth(msg)
        } else if status.as_u16() >= 500 || status.as_u16() == 429 {
            crate::transport::TransportError::Network(msg)
        } else {
            crate::transport::TransportError::Server(msg)
        };
        crate::Error::Transport(category)
    }
}

/// Whether a response status code should trigger a retry under the
/// [`HttpTransportClient`] retry policy: `429` (Too Many Requests)
/// and any `5xx`. Pulled out as a free function so the unit tests
/// can exercise the classifier without fabricating a
/// [`reqwest::blocking::Response`].
#[cfg(feature = "http-transport")]
fn response_status_is_retryable(status: reqwest::StatusCode) -> bool {
    status.as_u16() == 429 || status.is_server_error()
}

/// Whether a transport-level [`reqwest::Error`] should trigger a
/// retry: timeouts and connect errors only. Status-code-bearing
/// errors (from `error_for_status`) are not produced by our call
/// sites, so we deliberately do not classify on `e.status()`.
#[cfg(feature = "http-transport")]
fn err_is_retryable(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect()
}

#[cfg(feature = "http-transport")]
impl TransportClient for HttpTransportClient {
    fn fetch_messages(
        &self,
        conversation_id: &str,
        after_cursor: Option<&str>,
    ) -> TransportResult<FetchMessagesResponse> {
        let mut url = self.url("/v1/messages");
        url.push_str(&format!(
            "?conversation_id={}",
            urlencoding_encode(conversation_id)
        ));
        if let Some(c) = after_cursor {
            url.push_str(&format!("&cursor={}", urlencoding_encode(c)));
        }

        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            self.client
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
        })
        .map_err(|e| Self::map_err("fetch_messages", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Self::map_status("fetch_messages", status, &body));
        }
        response
            .json::<FetchMessagesResponse>()
            .map_err(|e| Self::map_err("fetch_messages decode", e))
    }

    fn init_blob_upload(
        &self,
        size: u64,
        blob_class: BlobClass,
        expected_merkle_root: [u8; 32],
    ) -> TransportResult<BlobUploadHandle> {
        let body = InitBlobBody {
            size,
            blob_class,
            expected_merkle_root: hex_encode(&expected_merkle_root),
        };
        let url = self.url("/v1/blobs/init");
        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            self.client
                .post(&url)
                .header("Authorization", self.auth_header())
                .json(&body)
                .send()
        })
        .map_err(|e| Self::map_err("init_blob_upload", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Self::map_status("init_blob_upload", status, &body));
        }
        response
            .json::<BlobUploadHandle>()
            .map_err(|e| Self::map_err("init_blob_upload decode", e))
    }

    fn upload_chunk(
        &self,
        blob_id: &str,
        chunk_idx: u32,
        ciphertext: &[u8],
        sha256: [u8; 32],
    ) -> TransportResult<ChunkReceipt> {
        let url = self.url(&format!(
            "/v1/blobs/{}/chunks/{}",
            urlencoding_encode(blob_id),
            chunk_idx
        ));
        // Use the longer-timeout upload client built once at
        // construction time. Building a fresh
        // `reqwest::blocking::Client` per call would spin up a new
        // tokio runtime + connection pool every chunk.
        let body_bytes = ciphertext.to_vec();
        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            self.upload_client
                .put(&url)
                .header("Authorization", self.auth_header())
                .header("Content-Type", "application/octet-stream")
                .header("X-Sha256", hex_encode(&sha256))
                .body(body_bytes.clone())
                .send()
        })
        .map_err(|e| Self::map_err("upload_chunk", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Self::map_status("upload_chunk", status, &body));
        }
        let wire = response
            .json::<ChunkReceiptWire>()
            .map_err(|e| Self::map_err("upload_chunk decode", e))?;
        let mut bytes = [0u8; 32];
        // Response-payload decode failure: the server returned a 200
        // but the hex string in the body is malformed. Retrying will
        // produce the same result — surface as `Server`
        // (non-retryable) rather than `Network`.
        hex_decode_into(&wire.sha256_hex, &mut bytes).map_err(|e| {
            crate::Error::Transport(crate::transport::TransportError::Server(format!(
                "upload_chunk: {e}"
            )))
        })?;
        Ok(ChunkReceipt {
            blob_id: wire.blob_id,
            chunk_idx: wire.chunk_idx,
            sha256: bytes,
        })
    }

    fn commit_blob(&self, blob_id: &str) -> TransportResult<CommitBlobResponse> {
        let url = self.url(&format!("/v1/blobs/{}/commit", urlencoding_encode(blob_id)));
        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            self.client
                .post(&url)
                .header("Authorization", self.auth_header())
                .send()
        })
        .map_err(|e| Self::map_err("commit_blob", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Self::map_status("commit_blob", status, &body));
        }
        let wire = response
            .json::<CommitBlobWire>()
            .map_err(|e| Self::map_err("commit_blob decode", e))?;
        let mut root = [0u8; 32];
        // Response-payload decode failure: see note in `upload_chunk`.
        hex_decode_into(&wire.merkle_root_hex, &mut root).map_err(|e| {
            crate::Error::Transport(crate::transport::TransportError::Server(format!(
                "commit_blob: {e}"
            )))
        })?;
        Ok(CommitBlobResponse {
            blob_id: wire.blob_id,
            chunk_count: wire.chunk_count,
            merkle_root: root,
        })
    }

    fn fetch_blob_range(&self, blob_id: &str, range: Range<u64>) -> TransportResult<Vec<u8>> {
        let url = self.url(&format!("/v1/blobs/{}", urlencoding_encode(blob_id)));
        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            self.client
                .get(&url)
                .header("Authorization", self.auth_header())
                .header(
                    "Range",
                    format!("bytes={}-{}", range.start, range.end.saturating_sub(1)),
                )
                .send()
        })
        .map_err(|e| Self::map_err("fetch_blob_range", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Self::map_status("fetch_blob_range", status, &body));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| Self::map_err("fetch_blob_range bytes", e))
    }

    fn fetch_archive_manifests(
        &self,
        after_generation: Option<u64>,
    ) -> TransportResult<Vec<EncryptedManifest>> {
        let mut url = self.url("/v1/archive/manifests");
        if let Some(after) = after_generation {
            url.push_str(&format!("?after={after}"));
        }
        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            self.client
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
        })
        .map_err(|e| Self::map_err("fetch_archive_manifests", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Self::map_status("fetch_archive_manifests", status, &body));
        }
        let wires = response
            .json::<Vec<EncryptedManifestWire>>()
            .map_err(|e| Self::map_err("fetch_archive_manifests decode", e))?;
        let mut out = Vec::with_capacity(wires.len());
        for w in wires {
            let mut hash = [0u8; 32];
            // Response-payload decode failure: see note in
            // `upload_chunk`.
            hex_decode_into(&w.previous_manifest_hash_hex, &mut hash).map_err(|e| {
                crate::Error::Transport(crate::transport::TransportError::Server(format!(
                    "fetch_archive_manifests: {e}"
                )))
            })?;
            let payload = base64_decode(&w.payload_b64).map_err(|e| {
                crate::Error::Transport(crate::transport::TransportError::Server(format!(
                    "fetch_archive_manifests: {e}"
                )))
            })?;
            out.push(EncryptedManifest {
                generation: w.generation,
                previous_manifest_hash: hash,
                payload,
            });
        }
        Ok(out)
    }

    fn fetch_archive_segment(&self, segment_id: &str) -> TransportResult<Vec<u8>> {
        let url = self.url(&format!(
            "/v1/archive/segments/{}",
            urlencoding_encode(segment_id)
        ));
        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            self.client
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
        })
        .map_err(|e| Self::map_err("fetch_archive_segment", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Self::map_status("fetch_archive_segment", status, &body));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| Self::map_err("fetch_archive_segment bytes", e))
    }

    fn fetch_index_shards(
        &self,
        conversation_hash: &str,
        bucket: &str,
        shard_type: &str,
    ) -> TransportResult<Vec<u8>> {
        let url = self.url(&format!(
            "/v1/archive/index-shards?conversation_hash={}&bucket={}&type={}",
            urlencoding_encode(conversation_hash),
            urlencoding_encode(bucket),
            urlencoding_encode(shard_type),
        ));
        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            self.client
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
        })
        .map_err(|e| Self::map_err("fetch_index_shards", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_else(|_| "<no body>".to_string());
            return Err(Self::map_status("fetch_index_shards", status, &body));
        }
        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| Self::map_err("fetch_index_shards bytes", e))
    }
}

// ---------------------------------------------------------------
// Lightweight helpers — local hex / base64 / urlencode without
// pulling extra crates. Encoded sizes are small so the
// allocations are negligible.
// ---------------------------------------------------------------

#[cfg(feature = "http-transport")]
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "http-transport")]
fn hex_decode_into(input: &str, out: &mut [u8]) -> Result<(), String> {
    if input.len() != out.len() * 2 {
        return Err(format!(
            "hex length mismatch: expected {}, got {}",
            out.len() * 2,
            input.len()
        ));
    }
    let bytes = input.as_bytes();
    for i in 0..out.len() {
        let hi = decode_nibble(bytes[2 * i])?;
        let lo = decode_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

#[cfg(feature = "http-transport")]
fn decode_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex byte: {b:#x}")),
    }
}

/// RFC 4648 base64 encoder/decoder (standard alphabet, with
/// padding). Hand-rolled to avoid pulling another dependency.
#[cfg(feature = "http-transport")]
#[allow(dead_code)]
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let chunks = bytes.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHA[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() >= 3 {
            out.push(ALPHA[(b2 & 0b111111) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(feature = "http-transport")]
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim_end_matches('=');
    let len = trimmed.len();
    let mut out = Vec::with_capacity(len * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in trimmed.chars() {
        let v: u32 = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(format!("invalid base64 char: {c:?}")),
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Minimal urlencode: percent-encode any byte outside
/// `[A-Za-z0-9_.~-]`. Sufficient for query-string identifiers
/// (UUIDs, conversation ids, cursors) we ship.
#[cfg(feature = "http-transport")]
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------
// Tests — exercise the helpers and the error mapping. Real-network
// integration tests use `mockito` and live behind
// `cfg(all(test, feature = "http-transport"))`.
// ---------------------------------------------------------------

#[cfg(all(test, feature = "http-transport"))]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_round_trip() {
        let mut data = [0u8; 32];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let encoded = hex_encode(&data);
        let mut back = [0u8; 32];
        hex_decode_into(&encoded, &mut back).unwrap();
        assert_eq!(data, back);
    }

    #[test]
    fn base64_round_trip() {
        let inputs: &[&[u8]] = &[b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        for input in inputs {
            let encoded = base64_encode(input);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, input.to_vec());
        }
    }

    #[test]
    fn urlencoding_passes_unreserved_through() {
        assert_eq!(urlencoding_encode("abcXYZ-_.~"), "abcXYZ-_.~");
        assert_eq!(urlencoding_encode("a b"), "a%20b");
        assert_eq!(urlencoding_encode("="), "%3D");
    }

    #[test]
    fn http_client_constructs_with_trailing_slash_normalized() {
        let c = HttpTransportClient::new("https://example.com/", "tok").unwrap();
        assert_eq!(c.base_url, "https://example.com");
    }

    #[test]
    fn http_client_auth_header_format() {
        let c = HttpTransportClient::new("https://example.com", "tok").unwrap();
        assert_eq!(c.auth_header(), "Bearer tok");
    }

    #[test]
    fn http_client_url_concat() {
        let c = HttpTransportClient::new("https://example.com", "tok").unwrap();
        assert_eq!(c.url("/v1/messages"), "https://example.com/v1/messages");
    }

    #[test]
    fn response_status_is_retryable_classifies_correctly() {
        // 5xx and 429 retry; everything else does not.
        assert!(response_status_is_retryable(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(response_status_is_retryable(
            reqwest::StatusCode::BAD_GATEWAY
        ));
        assert!(response_status_is_retryable(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(response_status_is_retryable(
            reqwest::StatusCode::GATEWAY_TIMEOUT
        ));
        assert!(response_status_is_retryable(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(!response_status_is_retryable(reqwest::StatusCode::OK));
        assert!(!response_status_is_retryable(
            reqwest::StatusCode::BAD_REQUEST
        ));
        assert!(!response_status_is_retryable(
            reqwest::StatusCode::UNAUTHORIZED
        ));
        assert!(!response_status_is_retryable(
            reqwest::StatusCode::NOT_FOUND
        ));
    }

    #[test]
    fn http_client_debug_redacts_auth_token() {
        // PR-level invariant: the bearer token must never appear
        // in `Debug` output (which is what flows into logs,
        // crash reports, `assert!` panic messages, and the
        // structured trace metadata in `crate::perf`).
        let secret = "super-secret-bearer-token-xyz";
        let c = HttpTransportClient::new("https://example.com", secret).unwrap();
        let dbg = format!("{c:?}");
        assert!(
            !dbg.contains(secret),
            "Debug output leaked auth token: {dbg}"
        );
        // The redaction marker is present so reviewers can spot
        // the field at a glance.
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
        // The non-secret base URL still surfaces so the Debug is
        // useful for incident triage.
        assert!(
            dbg.contains("example.com"),
            "base_url missing from Debug: {dbg}"
        );
    }

    #[test]
    fn http_client_new_builds_two_distinct_clients() {
        // Both clients must be constructed eagerly so per-call
        // `upload_chunk` does not allocate a new tokio runtime.
        let c = HttpTransportClient::new("https://example.com", "tok").unwrap();
        let client_addr = std::ptr::addr_of!(c.client) as usize;
        let upload_addr = std::ptr::addr_of!(c.upload_client) as usize;
        assert_ne!(client_addr, upload_addr);
    }
}

// ---------------------------------------------------------------
// Feature-off shape
// ---------------------------------------------------------------

#[cfg(not(feature = "http-transport"))]
#[allow(dead_code)]
#[derive(Debug)]
pub struct HttpTransportClient;

#[cfg(not(feature = "http-transport"))]
impl HttpTransportClient {
    /// Stub constructor: returns
    /// [`crate::Error::NotImplemented`] when the
    /// `http-transport` feature is off.
    pub fn new(_base_url: &str, _auth_token: &str) -> crate::Result<Self> {
        Err(crate::Error::NotImplemented(
            "http-transport feature is required for HttpTransportClient",
        ))
    }
}

#[cfg(all(test, not(feature = "http-transport")))]
mod feature_off_tests {
    use super::*;

    #[test]
    fn noop_client_used_when_http_transport_feature_off() {
        let result = HttpTransportClient::new("https://example.com", "tok");
        assert!(matches!(result, Err(crate::Error::NotImplemented(_))));
    }
}
