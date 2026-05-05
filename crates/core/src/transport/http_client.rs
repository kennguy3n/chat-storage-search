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
//! transient transport error (connection reset, 5xx, 429).
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
#[cfg(feature = "http-transport")]
#[derive(Debug, Clone)]
pub struct HttpTransportClient {
    base_url: String,
    auth_token: String,
    client: reqwest::blocking::Client,
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
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_TRANSPORT_REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| crate::Error::Transport(format!("reqwest builder: {e}")))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token: auth_token.to_string(),
            client,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.auth_token)
    }

    /// Wrap a fallible request in the retry policy: 3 attempts at
    /// 1 s / 2 s / 4 s backoff, retrying only on `reqwest::Error`s
    /// that report `is_timeout`/`is_connect` or 5xx / 429.
    fn with_retry<T>(
        attempts: u32,
        mut op: impl FnMut() -> Result<T, reqwest::Error>,
    ) -> Result<T, reqwest::Error> {
        let mut last_err: Option<reqwest::Error> = None;
        for attempt in 0..attempts {
            match op() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let retryable = e.is_timeout()
                        || e.is_connect()
                        || matches!(e.status().map(|s| s.as_u16()), Some(429) | Some(500..=599));
                    last_err = Some(e);
                    if !retryable || attempt + 1 >= attempts {
                        break;
                    }
                    let backoff_ms = 1_000u64 << attempt; // 1s, 2s, 4s
                    std::thread::sleep(Duration::from_millis(backoff_ms));
                }
            }
        }
        Err(last_err.expect("at least one attempt was made"))
    }

    fn map_err(label: &str, err: reqwest::Error) -> crate::Error {
        crate::Error::Transport(format!("{label}: {err}"))
    }

    fn map_status(label: &str, status: reqwest::StatusCode, body: &str) -> crate::Error {
        crate::Error::Transport(format!(
            "{label}: HTTP {} — {}",
            status.as_u16(),
            body.chars().take(256).collect::<String>()
        ))
    }
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
        // Use the longer upload timeout for blob bodies.
        let upload_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_TRANSPORT_BLOB_UPLOAD_TIMEOUT_SECS))
            .build()
            .map_err(|e| crate::Error::Transport(format!("reqwest builder: {e}")))?;

        let body_bytes = ciphertext.to_vec();
        let response = Self::with_retry(HTTP_TRANSPORT_RETRY_ATTEMPTS, || {
            upload_client
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
        hex_decode_into(&wire.sha256_hex, &mut bytes)
            .map_err(|e| crate::Error::Transport(format!("upload_chunk: {e}")))?;
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
        hex_decode_into(&wire.merkle_root_hex, &mut root)
            .map_err(|e| crate::Error::Transport(format!("commit_blob: {e}")))?;
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
            hex_decode_into(&w.previous_manifest_hash_hex, &mut hash)
                .map_err(|e| crate::Error::Transport(format!("fetch_archive_manifests: {e}")))?;
            let payload = base64_decode(&w.payload_b64)
                .map_err(|e| crate::Error::Transport(format!("fetch_archive_manifests: {e}")))?;
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
    fn with_retry_returns_first_success() {
        let calls = std::sync::Mutex::new(0u32);
        // Manually-constructed dummy that always succeeds — we
        // can't easily fabricate a `reqwest::Error`, so we test
        // the success path here.
        let r: Result<u32, reqwest::Error> = HttpTransportClient::with_retry(3, || {
            *calls.lock().unwrap() += 1;
            Ok(42)
        });
        assert_eq!(r.unwrap(), 42);
        assert_eq!(*calls.lock().unwrap(), 1);
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
