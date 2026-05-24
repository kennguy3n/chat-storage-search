//! Integration tests for [`HttpModelDownloader`].
//!
//! Exercise the full download path against a `std::net::TcpListener`-backed
//! HTTP/1.1 server fixture rather than a real network endpoint, so the
//! tests are hermetic, offline, and resilient to CI sandbox isolation. The
//! fixture is intentionally minimal — just enough to verify the wire
//! contract:
//!
//! 1. Full-body `GET` → 200 OK with `Content-Length` and body.
//! 2. Range `GET` (`Range: bytes=N-`) → 206 Partial Content with the
//!    tail bytes after byte N.
//! 3. Range `GET` against a server that doesn't support resume → 200 OK
//!    with the full body (client truncates the partial and restarts).
//! 4. Transient `5xx` → retry; persistent `5xx` → surface error.
//! 5. `404` → non-retryable error.
//! 6. Bearer token propagation.
//!
//! The integration suite is gated on the `http-transport` cargo feature,
//! same as the production module itself.

#![cfg(feature = "http-transport")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

use sha2::{Digest, Sha256};

use kchat_core::models::http_downloader::{
    DownloadEntry, HttpModelDownloader, HTTP_MODEL_DOWNLOAD_RETRY_ATTEMPTS, PARTIAL_SUFFIX,
};
use kchat_core::models::model_manager::{ModelDownloader, Quantization};
use kchat_core::Error;

/// Spawn a tiny HTTP/1.1 server on `127.0.0.1:<ephemeral-port>` that
/// dispatches every accepted connection to `handler`.
///
/// The listener thread is detached (we never join it). When the
/// test process exits, the OS reclaims it. This is intentional —
/// `TcpListener` has no portable `close()` API, and joining a
/// blocking-accept thread is impossible without out-of-band
/// signalling. The threads are cheap and short-lived.
fn spawn_server<F>(handler: F) -> ServerHandle
where
    F: Fn(TcpStream, u32) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let n = counter_clone.fetch_add(1, Ordering::SeqCst) + 1;
                    let handler = handler.clone();
                    thread::spawn(move || handler(s, n));
                }
                Err(_) => break,
            }
        }
    });
    ServerHandle {
        addr: format!("http://{}", addr),
        counter,
    }
}

struct ServerHandle {
    addr: String,
    counter: Arc<AtomicU32>,
}

impl ServerHandle {
    fn url(&self) -> &str {
        &self.addr
    }
    fn requests_seen(&self) -> u32 {
        self.counter.load(Ordering::SeqCst)
    }
}

/// Parse a single HTTP/1.1 request from `stream` into
/// `(method, path, headers)`. Bodies are not parsed — these tests are
/// `GET`-only.
fn read_request(stream: &mut TcpStream) -> (String, String, Vec<(String, String)>) {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .expect("read request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read header");
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some(colon) = trimmed.find(':') {
            let (k, v) = trimmed.split_at(colon);
            headers.push((k.to_lowercase(), v[1..].trim().to_string()));
        }
    }
    (method, path, headers)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    extra_headers: &[(&str, String)],
) {
    let phrase = match status {
        200 => "OK",
        206 => "Partial Content",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let _ = stream.flush();
}

fn random_payload(seed: u64, len: usize) -> Vec<u8> {
    // Linear-congruential PRNG so the payload is deterministic per seed
    // but distinct from previous tests. No `rand` crate needed.
    let mut s = seed.wrapping_mul(0x9E37_79B1_7F4A_7C15);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1442695040888963407);
        out.push((s >> 33) as u8);
    }
    out
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_slice());
    out
}

fn temp_dest(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "kchat-http-model-downloader-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(HttpModelDownloader::partial_path(&p));
    p
}

#[test]
fn full_body_download_200() {
    let body = random_payload(1, 8192);
    let expected_sha = sha256_of(&body);
    let body_arc = Arc::new(body.clone());
    let server = spawn_server(move |mut s, _n| {
        let (method, _path, _headers) = read_request(&mut s);
        assert_eq!(method, "GET");
        write_response(&mut s, 200, &body_arc, &[]);
    });

    let d = HttpModelDownloader::new().expect("new");
    d.register_entry(
        "xlmr",
        "xlmr@v1",
        DownloadEntry::new(format!("{}/xlmr.onnx", server.url()), Quantization::Int8),
    )
    .expect("register");

    let dest = temp_dest("full");
    let artifact = d
        .download_model("xlmr", "xlmr@v1", &dest)
        .expect("download");
    assert_eq!(artifact.file_path, dest);
    assert_eq!(artifact.size_bytes as usize, body.len());
    assert_eq!(artifact.sha256, expected_sha);
    assert_eq!(artifact.quantization, Quantization::Int8);
    // Partial file must be gone after the atomic rename.
    let partial = HttpModelDownloader::partial_path(&dest);
    assert!(
        !partial.exists(),
        "partial should be renamed onto dest, not left behind"
    );
    // Final file content must match the body exactly.
    let on_disk = std::fs::read(&dest).expect("read final");
    assert_eq!(on_disk, body);
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn resumable_range_download_206() {
    // Seed the partial with the first half of the artifact, simulate a
    // crash, and verify the second half is fetched + appended with a
    // SHA-256 that matches the full file.
    let full = random_payload(2, 16384);
    let expected_sha = sha256_of(&full);
    let mid = full.len() / 2;
    let prefix = full[..mid].to_vec();
    let tail = full[mid..].to_vec();
    let tail_arc = Arc::new(tail.clone());
    let full_len = full.len() as u64;

    let server = spawn_server(move |mut s, _n| {
        let (method, _path, headers) = read_request(&mut s);
        assert_eq!(method, "GET");
        let range = headers
            .iter()
            .find(|(k, _)| k == "range")
            .map(|(_, v)| v.clone());
        // The client should request bytes=<mid>- on resume.
        let range = range.expect("client must send Range header on resume");
        let prefix_len = full_len / 2;
        let expected = format!("bytes={prefix_len}-");
        assert_eq!(
            range, expected,
            "client must request the unsent tail, got: {range}"
        );
        let last = full_len - 1;
        write_response(
            &mut s,
            206,
            &tail_arc,
            &[(
                "Content-Range",
                format!("bytes {prefix_len}-{last}/{full_len}"),
            )],
        );
    });

    let d = HttpModelDownloader::new().expect("new");
    d.register_entry(
        "xlmr",
        "xlmr@v1",
        DownloadEntry::new(format!("{}/xlmr.onnx", server.url()), Quantization::Int8),
    )
    .expect("register");

    let dest = temp_dest("resume");
    // Pre-seed the partial file with the prefix bytes (the
    // "interrupted prior attempt" simulation).
    let partial = HttpModelDownloader::partial_path(&dest);
    std::fs::write(&partial, &prefix).expect("seed partial");

    let artifact = d
        .download_model("xlmr", "xlmr@v1", &dest)
        .expect("resume download");
    assert_eq!(artifact.size_bytes, full_len);
    assert_eq!(artifact.sha256, expected_sha);
    let on_disk = std::fs::read(&dest).expect("read final");
    assert_eq!(on_disk, full);
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn server_ignoring_range_returns_200_restart() {
    // Server ignores the Range header and returns the full body with a
    // 200 — client must truncate the partial, reset the hasher, and
    // accept the body. Final SHA-256 still matches.
    let full = random_payload(3, 10000);
    let expected_sha = sha256_of(&full);
    let prefix = random_payload(4, 4000); // garbage prefix
    let full_arc = Arc::new(full.clone());

    let server = spawn_server(move |mut s, _n| {
        let (method, _path, _headers) = read_request(&mut s);
        assert_eq!(method, "GET");
        write_response(&mut s, 200, &full_arc, &[]);
    });

    let d = HttpModelDownloader::new().expect("new");
    d.register_entry(
        "xlmr",
        "xlmr@v1",
        DownloadEntry::new(format!("{}/xlmr.onnx", server.url()), Quantization::Int8),
    )
    .expect("register");

    let dest = temp_dest("restart");
    let partial = HttpModelDownloader::partial_path(&dest);
    std::fs::write(&partial, &prefix).expect("seed garbage partial");

    let artifact = d
        .download_model("xlmr", "xlmr@v1", &dest)
        .expect("download");
    assert_eq!(artifact.size_bytes as usize, full.len());
    assert_eq!(artifact.sha256, expected_sha);
    let on_disk = std::fs::read(&dest).expect("read final");
    assert_eq!(on_disk, full);
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn transient_5xx_then_200_succeeds_via_retry() {
    // First two attempts: 503; third attempt: 200. The client should
    // exhaust its retry budget (3 attempts at 1s/2s/4s backoff) and
    // succeed on the third.
    let full = random_payload(5, 4096);
    let expected_sha = sha256_of(&full);
    let full_arc = Arc::new(full.clone());

    let server = spawn_server(move |mut s, n| {
        let (_method, _path, _headers) = read_request(&mut s);
        if n < 3 {
            write_response(&mut s, 503, b"oops", &[]);
        } else {
            write_response(&mut s, 200, &full_arc, &[]);
        }
    });

    let d = HttpModelDownloader::new().expect("new");
    d.register_entry(
        "xlmr",
        "xlmr@v1",
        DownloadEntry::new(format!("{}/xlmr.onnx", server.url()), Quantization::Int8),
    )
    .expect("register");

    let dest = temp_dest("retry");
    // Note: the downloader sleeps 1s + 2s = 3s of backoff between
    // attempts 1→2 and 2→3. This test takes ~3s to run.
    let artifact = d
        .download_model("xlmr", "xlmr@v1", &dest)
        .expect("download");
    assert_eq!(artifact.size_bytes as usize, full.len());
    assert_eq!(artifact.sha256, expected_sha);
    assert_eq!(
        server.requests_seen(),
        HTTP_MODEL_DOWNLOAD_RETRY_ATTEMPTS,
        "should have used full retry budget"
    );
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn persistent_5xx_exhausts_retries_and_errors() {
    let server = spawn_server(move |mut s, _n| {
        let (_method, _path, _headers) = read_request(&mut s);
        write_response(&mut s, 500, b"boom", &[]);
    });

    let d = HttpModelDownloader::new().expect("new");
    d.register_entry(
        "xlmr",
        "xlmr@v1",
        DownloadEntry::new(format!("{}/xlmr.onnx", server.url()), Quantization::Int8),
    )
    .expect("register");

    let dest = temp_dest("persistent5xx");
    // Note: 1s + 2s = 3s of backoff between attempts.
    let err = d
        .download_model("xlmr", "xlmr@v1", &dest)
        .expect_err("should fail");
    assert!(
        matches!(err, Error::Transport(_)),
        "expected Error::Transport, got {err:?}"
    );
    // dest should not exist; the partial should still hold whatever
    // was written (which is nothing — 500 is detected before the
    // body-stream loop touches the partial).
    assert!(!dest.exists(), "dest must not exist on failure");
    let _ = std::fs::remove_file(HttpModelDownloader::partial_path(&dest));
}

#[test]
fn http_404_surfaces_non_retryable_error() {
    let server = spawn_server(move |mut s, _n| {
        let (_method, _path, _headers) = read_request(&mut s);
        write_response(&mut s, 404, b"missing", &[]);
    });

    let d = HttpModelDownloader::new().expect("new");
    d.register_entry(
        "xlmr",
        "xlmr@v1",
        DownloadEntry::new(format!("{}/xlmr.onnx", server.url()), Quantization::Int8),
    )
    .expect("register");

    let dest = temp_dest("404");
    let err = d
        .download_model("xlmr", "xlmr@v1", &dest)
        .expect_err("should fail");
    assert!(
        matches!(err, Error::Transport(_)),
        "expected Error::Transport, got {err:?}"
    );
    // The downloader must NOT retry a 404 — it's a non-retryable
    // error. So we should see exactly one request.
    assert_eq!(
        server.requests_seen(),
        1,
        "404 must not be retried — request count: {}",
        server.requests_seen()
    );
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn bearer_token_propagates_to_request() {
    let body = random_payload(7, 2048);
    let body_arc = Arc::new(body.clone());
    let seen_token: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let seen_token_clone = seen_token.clone();

    let server = spawn_server(move |mut s, _n| {
        let (_method, _path, headers) = read_request(&mut s);
        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone());
        *seen_token_clone.lock().unwrap() = auth;
        write_response(&mut s, 200, &body_arc, &[]);
    });

    let d = HttpModelDownloader::new()
        .expect("new")
        .with_auth_token("secret-token-xyz");
    d.register_entry(
        "xlmr",
        "xlmr@v1",
        DownloadEntry::new(format!("{}/xlmr.onnx", server.url()), Quantization::Int8),
    )
    .expect("register");

    let dest = temp_dest("auth");
    let _ = d
        .download_model("xlmr", "xlmr@v1", &dest)
        .expect("download");
    let token = seen_token.lock().unwrap().clone();
    assert_eq!(token.as_deref(), Some("Bearer secret-token-xyz"));
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn oversized_partial_416_recovers_via_partial_delete_and_restart() {
    // Robustness against a corrupted / externally-tampered partial
    // file: the partial on disk is *larger* than the artifact the
    // server is willing to serve, so the `Range: bytes=<too_large>-`
    // request elicits `416 Range Not Satisfiable`. The downloader
    // must:
    //   1) detect the 416 and delete the stale partial,
    //   2) classify the failure as retryable (network class), and
    //   3) restart from byte 0 on the next attempt so the download
    //      ultimately succeeds with the correct SHA-256.
    //
    // Without this handling the partial would block every future
    // attempt until manually removed.
    let full = random_payload(11, 7000);
    let expected_sha = sha256_of(&full);
    let full_arc = Arc::new(full.clone());
    // The on-disk partial is bigger than the server's artifact so the
    // server has nothing to serve from byte `len(partial)` onwards.
    let bogus_partial = random_payload(12, full.len() + 4096);

    let server = spawn_server(move |mut s, n| {
        let (method, _path, headers) = read_request(&mut s);
        assert_eq!(method, "GET");
        let range = headers
            .iter()
            .find(|(k, _)| k == "range")
            .map(|(_, v)| v.clone());
        if n == 1 {
            // First attempt: client sends a Range header derived from
            // the bogus oversized partial. Server replies 416.
            assert!(range.is_some(), "first attempt must carry a Range header");
            write_response(&mut s, 416, b"out of range", &[]);
        } else {
            // Subsequent attempts: partial has been deleted, so the
            // client issues a plain GET (no Range). Serve the full
            // body so the retry succeeds.
            assert!(
                range.is_none(),
                "after 416 the client must restart without a Range \
                 header (got range={:?} on attempt {n})",
                range
            );
            write_response(&mut s, 200, &full_arc, &[]);
        }
    });

    let d = HttpModelDownloader::new().expect("new");
    d.register_entry(
        "xlmr",
        "xlmr@v1",
        DownloadEntry::new(format!("{}/xlmr.onnx", server.url()), Quantization::Int8),
    )
    .expect("register");

    let dest = temp_dest("416-recovery");
    let partial = HttpModelDownloader::partial_path(&dest);
    std::fs::write(&partial, &bogus_partial).expect("seed oversized partial");

    // Note: the downloader sleeps 1 s of backoff between attempt 1 (416)
    // and attempt 2 (200), so this test takes ~1 s.
    let artifact = d
        .download_model("xlmr", "xlmr@v1", &dest)
        .expect("download must succeed after 416-driven partial reset");
    assert_eq!(artifact.size_bytes as usize, full.len());
    assert_eq!(
        artifact.sha256, expected_sha,
        "SHA-256 must match the full artifact after restart"
    );
    let on_disk = std::fs::read(&dest).expect("read final");
    assert_eq!(on_disk, full);
    assert!(
        !partial.exists(),
        "partial must be cleaned up after successful restart"
    );
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn partial_suffix_matches_constant() {
    // PR-level invariant: callers that sweep on the `.partial`
    // extension (`find /models -name '*.partial'`) rely on this exact
    // string. Pinned here so a refactor cannot silently change it.
    assert_eq!(PARTIAL_SUFFIX, ".partial");
}
