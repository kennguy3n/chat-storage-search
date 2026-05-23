//! XLM-R text-embedding interface and cross-pipeline cache.
//!
//! `docs/PROPOSAL.md §7.6` (on-device ML models) and §7.6.1
//! (cross-pipeline embedding cache). Two responsibilities live here:
//!
//! 1. The on-device XLM-R ONNX inference seam that semantic search
//!    uses to embed queries and messages. Phase 6 fills this in.
//! 2. The [`EmbeddingCache`] trait — the cross-pipeline cache that
//!    lets the guardrail (`kennguy3n/slm-guardrail`) and the search
//!    pipeline share one XLM-R inference per message.
//!
//! Phase 6 lands the actual ONNX session glue. The cache trait
//! surface and the default `search_vector`-backed implementation
//! land here as forward-compatible scaffolding so the persistence
//! layer (`crate::message::processor::MessagePersister` and the
//! semantic-search engine) can hit the cache as soon as either
//! pipeline writes embeddings — no flag day required when the ONNX
//! wiring lands.

use rusqlite::{params, Connection, OptionalExtension};

use crate::Result;

// ---------------------------------------------------------------------------
// Canonical XLM-R version tag
// ---------------------------------------------------------------------------

/// Canonical `model_version` tag for the XLM-R encoder shared
/// across the chat-storage-search and `kennguy3n/slm-guardrail`
/// pipelines.
///
/// `docs/PROPOSAL.md §7.6.1`. Embeddings written under this tag
/// are readable across both pipelines. A future encoder upgrade
/// (e.g. `xlmr@v2`) MUST bump this constant; the
/// version-mismatch invariant on [`EmbeddingCache::get`] then
/// invalidates stale rows automatically.
pub const XLMR_MODEL_VERSION: &str = "xlmr@v1";

/// Output dimensionality of the XLM-R encoder shipped to devices.
///
/// `docs/PROPOSAL.md §7.6.1`. Matches the shared encoder
/// configuration in `kennguy3n/slm-guardrail`. The cache itself
/// does not enforce this dimension — it only requires the
/// dequantized blob length to match what was written — but
/// callers SHOULD assert against this constant before consuming
/// a cached vector to catch dimension drift across encoder
/// upgrades.
pub const XLMR_EMBEDDING_DIM: usize = 384;

/// Canonical on-disk filename for the INT8 XLM-R artifact.
/// Phase 6, Task 5 (2026-05-04 batch).
pub const XLMR_INT8_FILENAME: &str = "xlmr-v1-int8.onnx";

/// Canonical on-disk filename for the INT4 (`MatMulNBits`)
/// XLM-R artifact shipped to tight-storage devices. Phase 6,
/// Task 5 (2026-05-04 batch).
pub const XLMR_INT4_FILENAME: &str = "xlmr-v1-int4.onnx";

// ---------------------------------------------------------------------------
// EmbeddingCache trait
// ---------------------------------------------------------------------------

/// Cross-pipeline cache for XLM-R (and other) text embeddings.
///
/// `docs/PROPOSAL.md §7.6.1`. A message's embedding is computed at
/// most once: whichever pipeline (guardrail or search) first
/// observes the message writes the vector through [`put`], and the
/// other pipeline reads it back through [`get`] instead of running
/// its own ONNX inference.
///
/// Implementations MUST enforce the version-mismatch invariant: a
/// `get(message_id, model_version)` MUST return `None` if the
/// stored row was written under a different `model_version`. This
/// is what lets either pipeline upgrade encoders without poisoning
/// the other.
///
/// The trait is deliberately small and synchronous. Per-message
/// lookups happen on the message-ingest hot path, so blocking I/O
/// is acceptable; the implementation is expected to dispatch onto
/// the same SQLCipher connection the rest of the local store uses.
///
/// [`put`]: EmbeddingCache::put
/// [`get`]: EmbeddingCache::get
pub trait EmbeddingCache: std::fmt::Debug {
    /// Look up a cached embedding for `(message_id, model_version)`.
    ///
    /// Returns `Ok(None)` if no row exists for that pair —
    /// including when a row exists for the same `message_id` under
    /// a different `model_version` (the version-mismatch
    /// invariant). Returns `Ok(Some(v))` if the row is present;
    /// `v.len()` matches the encoder's output dimensionality.
    fn get(&self, message_id: &str, model_version: &str) -> Result<Option<Vec<f32>>>;

    /// Insert or replace the cached embedding for
    /// `(message_id, model_version)`.
    ///
    /// Replacing an existing row is by design: a re-embed under
    /// the same `model_version` (e.g. retry after a transient
    /// NPU/GPU error) MUST NOT be treated as a duplicate-key
    /// failure. Different `model_version` values for the same
    /// `message_id` may coexist if the implementation chooses; the
    /// default `search_vector`-backed implementation does so
    /// because the table's primary key is `(message_id,
    /// model_version)`.
    fn put(&self, message_id: &str, model_version: &str, embedding: &[f32]) -> Result<()>;
}

// ---------------------------------------------------------------------------
// NoopEmbeddingCache
// ---------------------------------------------------------------------------

/// `EmbeddingCache` placeholder for early bring-up before the
/// local store is open (e.g. Phase 0 / Phase 1 fixtures, or a
/// caller that does not have a SQLCipher connection in hand).
///
/// [`get`](EmbeddingCache::get) always returns `Ok(None)` so
/// callers fall through to the inference path. [`put`] returns
/// [`crate::Error::NotImplemented`] so a misconfigured caller
/// learns about the missing backing store loudly instead of
/// silently dropping cache writes.
///
/// [`put`]: EmbeddingCache::put
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEmbeddingCache;

impl EmbeddingCache for NoopEmbeddingCache {
    fn get(&self, _message_id: &str, _model_version: &str) -> Result<Option<Vec<f32>>> {
        Ok(None)
    }

    fn put(&self, _message_id: &str, _model_version: &str, _embedding: &[f32]) -> Result<()> {
        Err(crate::Error::NotImplemented("embedding_cache.put"))
    }
}

// ---------------------------------------------------------------------------
// LocalStoreEmbeddingCache (default implementation)
// ---------------------------------------------------------------------------

/// Default `EmbeddingCache` implementation backed by the
/// `search_vector` table on the local SQLCipher store.
///
/// The wire format on disk is INT8-quantized, matching the inline
/// comment on the `search_vector.embedding` column in
/// [`crate::local_store::schema::SCHEMA_SQL`]:
///
/// ```text
/// [scale: f32 little-endian, 4 bytes][q: i8, dim bytes]
/// ```
///
/// `scale` is the per-row symmetric-quantization scale (max
/// absolute value divided by 127). [`put`](EmbeddingCache::put)
/// computes `scale = max(|x|).max(EPS) / 127`, encodes each lane
/// as `round(x[i] / scale).clamp(-127, 127) as i8`, and prepends
/// the `f32` scale. [`get`](EmbeddingCache::get) reverses the
/// codec by reading the 4-byte prefix and multiplying each `i8`
/// lane by `scale`.
///
/// The codec is lossy at the i8 boundary; round-trip error is
/// bounded by `scale`, which is small relative to the L2 norm of
/// the normalized XLM-R embeddings the encoder produces.
/// Acceptable for a cache layer whose only consumer is HNSW
/// approximate vector search — the dequantized vector is closer
/// to the original than the ANN search radius.
pub struct LocalStoreEmbeddingCache<'a> {
    conn: &'a Connection,
}

impl std::fmt::Debug for LocalStoreEmbeddingCache<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStoreEmbeddingCache")
            .finish_non_exhaustive()
    }
}

impl<'a> LocalStoreEmbeddingCache<'a> {
    /// Wrap an existing SQLCipher [`Connection`] (the one held by
    /// [`crate::local_store::db::LocalStoreDb`]) as an
    /// [`EmbeddingCache`].
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }
}

impl EmbeddingCache for LocalStoreEmbeddingCache<'_> {
    fn get(&self, message_id: &str, model_version: &str) -> Result<Option<Vec<f32>>> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT embedding FROM search_vector
                 WHERE message_id = ?1 AND model_version = ?2",
                params![message_id, model_version],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|e| crate::Error::Storage(format!("search_vector lookup: {e}").into()))?;
        Ok(blob.map(|b| dequantize_int8(&b)))
    }

    fn put(&self, message_id: &str, model_version: &str, embedding: &[f32]) -> Result<()> {
        let blob = quantize_int8(embedding);
        self.conn
            .execute(
                "INSERT INTO search_vector(message_id, embedding, model_version)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(message_id, model_version)
                 DO UPDATE SET embedding = excluded.embedding",
                params![message_id, blob, model_version],
            )
            .map_err(|e| crate::Error::Storage(format!("search_vector upsert: {e}").into()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Symmetric INT8 quantization codec
// ---------------------------------------------------------------------------

/// Smallest scale allowed before falling back to a constant.
/// Avoids divide-by-zero on an all-zero embedding (which a poorly
/// initialized encoder might produce in edge cases).
const QUANT_EPS: f32 = 1e-12;

fn quantize_int8(embedding: &[f32]) -> Vec<u8> {
    let max_abs = embedding.iter().fold(0.0_f32, |acc, &x| acc.max(x.abs()));
    let scale = (max_abs / 127.0).max(QUANT_EPS);
    let mut out = Vec::with_capacity(4 + embedding.len());
    out.extend_from_slice(&scale.to_le_bytes());
    for &x in embedding {
        let q = (x / scale).round().clamp(-127.0, 127.0) as i8;
        out.push(q as u8);
    }
    out
}

fn dequantize_int8(blob: &[u8]) -> Vec<f32> {
    if blob.len() < 4 {
        return Vec::new();
    }
    let scale = f32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    blob[4..]
        .iter()
        .map(|&b| (b as i8) as f32 * scale)
        .collect()
}

/// Crate-private accessor for [`dequantize_int8`].
///
/// Phase 6, Task 3: the brute-force semantic-search engine in
/// [`crate::search::semantic_search`] needs to dequantize raw
/// `search_vector.embedding` blobs without going through the
/// [`EmbeddingCache::get`] entry point (the engine fetches all
/// rows in one statement and dequantizes per-row in memory).
/// Lives here so the codec stays a single source of truth.
pub(crate) fn dequantize_int8_for_search(blob: &[u8]) -> Vec<f32> {
    dequantize_int8(blob)
}

// ---------------------------------------------------------------------------
// INT4 codec — Phase 6, Task 4 (2026-05-04 batch)
// ---------------------------------------------------------------------------
//
// Linear, symmetric INT4 quantization. Each f32 value is mapped
// into the range `[-7, 7]` with a per-vector `scale = max_abs / 7`
// and packed two values per byte (low nibble = even index, high
// nibble = odd index). On-disk layout:
//
//   bytes  0..4   : little-endian f32 `scale`
//   bytes  4..6   : little-endian u16 `len`   (number of f32 values)
//   bytes  6..    : ceil(len / 2) packed bytes
//
// `len` is stored explicitly so an odd-length vector
// (`len = 2 * packed_bytes - 1`) round-trips losslessly back to
// the same number of f32 values. The chosen format is intentionally
// distinct from [`quantize_int8`] / [`dequantize_int8`] so the two
// codecs cannot accidentally alias on the same byte buffer.
//
// References: `docs/PROPOSAL.md §7.6` (per-tier model packaging),
// `docs/PHASES.md` Phase 6 (storage-budget aware quantization).

const INT4_HEADER_LEN: usize = 6;

/// Encode an `f32` embedding as an INT4-quantized blob.
///
/// Two values per byte. Returns the prefix described above.
/// Empty inputs return `[0; 6]` so the round-trip is well-defined.
pub fn encode_int4(embedding: &[f32]) -> Vec<u8> {
    let max_abs = embedding.iter().fold(0.0_f32, |acc, &x| acc.max(x.abs()));
    let scale = (max_abs / 7.0).max(QUANT_EPS);
    let len = embedding.len() as u16;

    let packed_len = embedding.len().div_ceil(2);
    let mut out = Vec::with_capacity(INT4_HEADER_LEN + packed_len);
    out.extend_from_slice(&scale.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());

    let mut byte = 0u8;
    for (i, &x) in embedding.iter().enumerate() {
        // Symmetric clamp into the signed-4-bit range
        // `[-7, 7]`. We avoid the `-8` end of the two's
        // complement range so the codec is symmetric and
        // negation is an involution.
        let q = (x / scale).round().clamp(-7.0, 7.0) as i8;
        // Map signed nibble to its 4-bit two's-complement
        // representation by masking with `0x0F`.
        let nibble = (q as u8) & 0x0F;
        if i % 2 == 0 {
            byte = nibble;
            if i == embedding.len() - 1 {
                out.push(byte);
            }
        } else {
            byte |= nibble << 4;
            out.push(byte);
            byte = 0;
        }
    }
    out
}

/// Decode an INT4-quantized blob produced by [`encode_int4`].
///
/// Returns an empty vector when the blob is too short or
/// inconsistent (e.g. the declared `len` exceeds the available
/// packed bytes).
pub fn decode_int4(blob: &[u8]) -> Vec<f32> {
    if blob.len() < INT4_HEADER_LEN {
        return Vec::new();
    }
    let scale = f32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let len = u16::from_le_bytes([blob[4], blob[5]]) as usize;
    let need_packed = len.div_ceil(2);
    if blob.len() < INT4_HEADER_LEN + need_packed {
        return Vec::new();
    }
    let packed = &blob[INT4_HEADER_LEN..INT4_HEADER_LEN + need_packed];

    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let byte = packed[i / 2];
        let nibble = if i % 2 == 0 {
            byte & 0x0F
        } else {
            (byte >> 4) & 0x0F
        };
        // Sign-extend 4 bits to i8.
        let signed = if nibble & 0x08 != 0 {
            (nibble | 0xF0) as i8
        } else {
            nibble as i8
        };
        out.push(signed as f32 * scale);
    }
    out
}

/// Compute the cosine similarity between two equal-length
/// vectors. Returns `0.0` for any pair containing a zero
/// magnitude vector — that matches the semantics used by
/// [`crate::search::semantic_search`] when reranking.
///
/// Lives here so the INT4 / INT8 fidelity benches and tests share
/// a single implementation.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0_f32;
    let mut na = 0.0_f32;
    let mut nb = 0.0_f32;
    for (&x, &y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na <= QUANT_EPS || nb <= QUANT_EPS {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

// ---------------------------------------------------------------------------
// TextEmbedder trait — Phase 6, Task 2
// ---------------------------------------------------------------------------

/// On-device text-embedding seam used by the semantic-search and
/// message-ingest pipelines.
///
/// `docs/PROPOSAL.md §7.6 / §7.6.1` and Phase 6, Task 2. The trait
/// is intentionally tiny so any encoder (XLM-R, a future
/// multilingual replacement, a deterministic mock, …) can plug in.
/// Implementations MUST return an L2-normalized vector of length
/// [`XLMR_EMBEDDING_DIM`] for the canonical encoder; consumers
/// SHOULD assert on length before mixing the vector into the
/// cosine-similarity reranker (see
/// [`crate::search::semantic_search::SemanticSearchEngine`]).
///
/// Object-safety + `Send + Sync`: `CoreImpl` stores the embedder
/// inside a `Mutex<Option<Box<dyn TextEmbedder>>>`, mirroring the
/// pattern used for [`crate::transport::DeliveryClient`].
pub trait TextEmbedder: std::fmt::Debug + Send + Sync {
    /// Run the encoder over `text` and return the embedding.
    ///
    /// Implementations are expected to be deterministic for a
    /// fixed input (modulo numerical noise from quantization /
    /// EP selection); the cross-pipeline embedding cache in
    /// [`EmbeddingCache`] relies on this so the guardrail and
    /// search pipelines share one inference per message.
    fn embed(&self, text: &str) -> Result<Vec<f32>>;
}

/// `TextEmbedder` placeholder for builds without a real encoder.
///
/// `embed` always returns
/// [`crate::Error::NotImplemented("text_embedder")`](crate::Error::NotImplemented)
/// so a misconfigured `CoreImpl` (one that called
/// [`crate::core_impl::CoreImpl::install_text_embedder`] with the
/// noop) learns about the missing inference loop loudly instead
/// of silently writing zero vectors into the embedding cache.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTextEmbedder;

impl TextEmbedder for NoopTextEmbedder {
    fn embed(&self, _text: &str) -> Result<Vec<f32>> {
        Err(crate::Error::NotImplemented("text_embedder"))
    }
}

/// Deterministic test [`TextEmbedder`] that hashes `text` into a
/// reproducible, L2-normalized vector.
///
/// Used by the Phase 6 unit tests and integration tests to stand
/// in for an actual ONNX-backed XLM-R encoder. The output is
/// stable across runs and across processes for a given input —
/// that is what lets the semantic-search tests assert "the same
/// query returns the same nearest neighbor".
///
/// Implementation: BLAKE3 over the UTF-8 bytes of `text` seeds an
/// LCG; each LCG step produces one f32 lane in `[-1, 1]`; the
/// resulting `dim`-length vector is L2-normalized so cosine
/// similarity matches dot product downstream.
#[derive(Debug, Clone, Copy)]
pub struct MockTextEmbedder {
    dim: usize,
}

impl Default for MockTextEmbedder {
    fn default() -> Self {
        Self {
            dim: XLMR_EMBEDDING_DIM,
        }
    }
}

impl MockTextEmbedder {
    /// Build a [`MockTextEmbedder`] that emits `dim`-length
    /// vectors. The default constructor uses
    /// [`XLMR_EMBEDDING_DIM`].
    pub fn with_dim(dim: usize) -> Self {
        assert!(dim > 0, "MockTextEmbedder dim must be > 0");
        Self { dim }
    }

    /// Embedding dimensionality the mock emits.
    pub fn dim(&self) -> usize {
        self.dim
    }
}

impl TextEmbedder for MockTextEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        // Seed an LCG from BLAKE3(text). Using the first four
        // bytes of the hash as a u32 seed gives us a fully
        // deterministic, well-spread starting point — different
        // inputs that happen to share a short prefix still seed
        // disjoint LCG paths because BLAKE3 is collision-resistant.
        let hash = blake3::hash(text.as_bytes());
        let seed_bytes = &hash.as_bytes()[..4];
        let mut x =
            u32::from_le_bytes([seed_bytes[0], seed_bytes[1], seed_bytes[2], seed_bytes[3]]);
        // Avoid the all-zero seed → all-zero embedding edge case
        // (e.g. an LCG that lands on x = 0 + multiplier 0 stays
        // at 0). Numerical-Recipes constants give a full-period
        // 2^32 cycle so we walk every state regardless of seed.
        if x == 0 {
            x = 1;
        }
        let mut raw: Vec<f32> = Vec::with_capacity(self.dim);
        for _ in 0..self.dim {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            raw.push((x as i32) as f32 / i32::MAX as f32);
        }
        // L2-normalize so cosine similarity reduces to dot
        // product downstream — matches what a real XLM-R encoder
        // outputs after the model's built-in normalization layer.
        let norm: f32 = raw.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > QUANT_EPS {
            for v in &mut raw {
                *v /= norm;
            }
        }
        Ok(raw)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Spin up an in-memory SQLite connection with just enough of
    /// the local-store schema to back the cache. We deliberately
    /// don't pull in the full SQLCipher `LocalStoreDb` here — the
    /// cache only depends on the `search_vector` table, and
    /// touching it directly keeps the unit test fast and free of
    /// SQLCipher-init noise.
    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("open_in_memory");
        conn.execute_batch(
            "CREATE TABLE search_vector (
                message_id    TEXT NOT NULL,
                embedding     BLOB NOT NULL,
                model_version TEXT NOT NULL,
                PRIMARY KEY (message_id, model_version)
            );",
        )
        .expect("create search_vector");
        conn
    }

    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        dot / (na * nb)
    }

    fn fixture_embedding(seed: u32) -> Vec<f32> {
        // Deterministic LCG; values in roughly [-1, 1].
        let mut x = seed.wrapping_mul(2_654_435_761);
        (0..XLMR_EMBEDDING_DIM)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x as i32) as f32 / i32::MAX as f32
            })
            .collect()
    }

    #[test]
    fn quantize_dequantize_round_trip_within_int8_tolerance() {
        let v = fixture_embedding(42);
        let blob = quantize_int8(&v);
        // 4-byte scale prefix + one i8 lane per dimension.
        assert_eq!(blob.len(), 4 + XLMR_EMBEDDING_DIM);
        let back = dequantize_int8(&blob);
        assert_eq!(back.len(), XLMR_EMBEDDING_DIM);
        // Cosine similarity stays close to 1 across symmetric
        // INT8 quantization for typical embedding magnitudes.
        let sim = cosine(&v, &back);
        assert!(
            sim > 0.999,
            "cosine similarity after INT8 round-trip should exceed 0.999, got {sim}"
        );
    }

    #[test]
    fn dequantize_handles_short_blob_gracefully() {
        assert!(dequantize_int8(&[]).is_empty());
        assert!(dequantize_int8(&[0u8, 1u8]).is_empty());
    }

    #[test]
    fn local_store_cache_round_trips_an_embedding() {
        let conn = fresh_conn();
        let cache = LocalStoreEmbeddingCache::new(&conn);
        let v = fixture_embedding(7);
        cache
            .put("m-1", XLMR_MODEL_VERSION, &v)
            .expect("put succeeds");
        let got = cache
            .get("m-1", XLMR_MODEL_VERSION)
            .expect("get succeeds")
            .expect("hit");
        let sim = cosine(&v, &got);
        assert!(sim > 0.999, "cache round-trip cosine sim {sim}");
    }

    #[test]
    fn local_store_cache_misses_for_unknown_message() {
        let conn = fresh_conn();
        let cache = LocalStoreEmbeddingCache::new(&conn);
        let got = cache
            .get("never-written", XLMR_MODEL_VERSION)
            .expect("get succeeds");
        assert!(got.is_none(), "unknown message must miss");
    }

    #[test]
    fn local_store_cache_misses_on_version_mismatch() {
        // The version-mismatch invariant on EmbeddingCache::get:
        // a row stored under model_version A must not satisfy a
        // lookup for model_version B.
        let conn = fresh_conn();
        let cache = LocalStoreEmbeddingCache::new(&conn);
        let v = fixture_embedding(99);
        cache.put("m-2", "xlmr@v1", &v).expect("put v1");

        let got_v2 = cache.get("m-2", "xlmr@v2").expect("get succeeds");
        assert!(
            got_v2.is_none(),
            "different model_version must not satisfy the lookup"
        );

        let got_v1 = cache.get("m-2", "xlmr@v1").expect("get succeeds");
        assert!(got_v1.is_some(), "matching model_version must hit");
    }

    #[test]
    fn local_store_cache_put_overwrites_same_key() {
        // Re-embed under the same (message_id, model_version) is
        // an upsert, not an error — see EmbeddingCache::put.
        let conn = fresh_conn();
        let cache = LocalStoreEmbeddingCache::new(&conn);
        let v1 = fixture_embedding(1);
        let v2 = fixture_embedding(2);
        cache.put("m-3", XLMR_MODEL_VERSION, &v1).expect("put 1");
        cache.put("m-3", XLMR_MODEL_VERSION, &v2).expect("put 2");
        let got = cache
            .get("m-3", XLMR_MODEL_VERSION)
            .expect("get succeeds")
            .expect("hit");
        // The second put should have overwritten the first; the
        // returned vector is closer to v2 than to v1.
        let sim2 = cosine(&v2, &got);
        let sim1 = cosine(&v1, &got);
        assert!(
            sim2 > sim1,
            "second put must overwrite first (sim2 = {sim2}, sim1 = {sim1})"
        );
    }

    #[test]
    fn local_store_cache_coexists_across_versions_for_same_message() {
        // Same message may have rows under different model_version
        // tags simultaneously (PK is (message_id, model_version)).
        // Useful during a rolling encoder upgrade.
        let conn = fresh_conn();
        let cache = LocalStoreEmbeddingCache::new(&conn);
        let v1 = fixture_embedding(10);
        let v2 = fixture_embedding(20);
        cache.put("m-4", "xlmr@v1", &v1).expect("put v1");
        cache.put("m-4", "xlmr@v2", &v2).expect("put v2");

        let got_v1 = cache.get("m-4", "xlmr@v1").expect("get").expect("hit v1");
        let got_v2 = cache.get("m-4", "xlmr@v2").expect("get").expect("hit v2");
        assert!(cosine(&v1, &got_v1) > 0.999);
        assert!(cosine(&v2, &got_v2) > 0.999);
    }

    #[test]
    fn noop_cache_misses_on_get_and_errors_on_put() {
        let cache = NoopEmbeddingCache;
        let v = fixture_embedding(0);
        assert!(cache.get("m", XLMR_MODEL_VERSION).expect("ok").is_none());
        let err = cache.put("m", XLMR_MODEL_VERSION, &v).unwrap_err();
        assert!(matches!(
            err,
            crate::Error::NotImplemented("embedding_cache.put")
        ));
    }

    // ----- Phase 6, Task 2: TextEmbedder trait coverage --------------

    #[test]
    fn noop_text_embedder_returns_not_implemented() {
        let emb = NoopTextEmbedder;
        let err = emb.embed("hello").unwrap_err();
        assert!(matches!(err, crate::Error::NotImplemented("text_embedder")));
    }

    #[test]
    fn mock_text_embedder_is_deterministic_for_same_input() {
        let emb = MockTextEmbedder::default();
        let a = emb.embed("hello world").expect("embed a");
        let b = emb.embed("hello world").expect("embed b");
        assert_eq!(a, b, "MockTextEmbedder must be deterministic");
        assert_eq!(a.len(), XLMR_EMBEDDING_DIM);
    }

    #[test]
    fn mock_text_embedder_different_inputs_diverge() {
        let emb = MockTextEmbedder::default();
        let a = emb.embed("hello world").expect("embed a");
        let b = emb.embed("привет мир").expect("embed b");
        // Two distinct inputs should yield distinct embeddings —
        // exact equality would mean the hash seeded the same
        // LCG which would be a real bug.
        assert_ne!(a, b);
        // Both still L2-normalized.
        let na: f32 = a.iter().map(|v| v * v).sum::<f32>().sqrt();
        let nb: f32 = b.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((na - 1.0).abs() < 1e-3, "left vector not normalized: {na}");
        assert!((nb - 1.0).abs() < 1e-3, "right vector not normalized: {nb}");
    }

    #[test]
    fn mock_text_embedder_respects_custom_dim() {
        let emb = MockTextEmbedder::with_dim(64);
        let v = emb.embed("dim test").expect("embed");
        assert_eq!(v.len(), 64);
        assert_eq!(emb.dim(), 64);
    }

    #[test]
    fn text_embedder_trait_is_object_safe() {
        // Compile-time check: a `dyn TextEmbedder` reference can
        // be constructed and called. CoreImpl wires the trait
        // through `Box<dyn TextEmbedder>`, so this test would
        // fail to compile if the trait drifted out of object-
        // safe shape.
        let mock = MockTextEmbedder::default();
        let dynref: &dyn TextEmbedder = &mock;
        let v = dynref.embed("trait dispatch").expect("dyn embed");
        assert_eq!(v.len(), XLMR_EMBEDDING_DIM);
    }

    // ----- Phase 6, Task 4 (2026-05-04 batch): INT4 codec ----------------

    #[test]
    fn int4_encode_decode_round_trip_preserves_cosine_above_threshold() {
        // For typical embeddings, INT4 quantization should still
        // preserve cosine similarity above 0.95.
        let v = fixture_embedding(7);
        let blob = encode_int4(&v);
        // 6-byte header + ceil(N/2) packed bytes.
        assert_eq!(
            blob.len(),
            INT4_HEADER_LEN + v.len().div_ceil(2),
            "INT4 packed-blob size matches the documented layout"
        );
        let back = decode_int4(&blob);
        assert_eq!(back.len(), v.len());
        let sim = cosine_similarity(&v, &back);
        assert!(
            sim > 0.95,
            "INT4 round-trip cosine should be > 0.95, got {sim}"
        );
    }

    #[test]
    fn int4_codec_handles_zero_vector() {
        let v = vec![0.0_f32; 16];
        let blob = encode_int4(&v);
        let back = decode_int4(&blob);
        assert_eq!(back.len(), v.len());
        assert!(back.iter().all(|x| x.abs() < 1e-3));
    }

    #[test]
    fn int4_codec_handles_uniform_vector() {
        // All-equal-positive: scale = max / 7, every nibble lands
        // on +7 → decoded values match the original to within
        // half a quantization step.
        let v = vec![0.42_f32; 12];
        let blob = encode_int4(&v);
        let back = decode_int4(&blob);
        assert_eq!(back.len(), v.len());
        for (orig, dec) in v.iter().zip(back.iter()) {
            assert!((orig - dec).abs() < 0.42 / 7.0 + 1e-3);
        }

        // All-equal-negative: same property, opposite sign.
        let v = vec![-0.42_f32; 12];
        let blob = encode_int4(&v);
        let back = decode_int4(&blob);
        for (orig, dec) in v.iter().zip(back.iter()) {
            assert!((orig - dec).abs() < 0.42 / 7.0 + 1e-3);
        }
    }

    #[test]
    fn int4_codec_handles_odd_length_vector() {
        // Odd-length vectors exercise the trailing-half-byte
        // path in `encode_int4` / `decode_int4`.
        let v = vec![0.1_f32, -0.1, 0.5, -0.5, 0.9];
        let blob = encode_int4(&v);
        let back = decode_int4(&blob);
        assert_eq!(back.len(), v.len());
        let sim = cosine_similarity(&v, &back);
        assert!(sim > 0.95, "odd-length INT4 cosine {sim}");
    }

    #[test]
    fn int4_decode_handles_short_blob_gracefully() {
        assert!(decode_int4(&[]).is_empty());
        assert!(decode_int4(&[0u8, 1, 2]).is_empty());
    }

    #[test]
    fn int4_blob_is_smaller_than_int8_blob() {
        // A correctness guard for the storage-budget claim in
        // `docs/PROPOSAL.md §7.6`: INT4 packs ~2x denser than
        // INT8 for the same input vector.
        let v = fixture_embedding(1);
        let i8_blob = quantize_int8(&v);
        let i4_blob = encode_int4(&v);
        assert!(
            i4_blob.len() < i8_blob.len(),
            "INT4 ({} bytes) should be smaller than INT8 ({} bytes)",
            i4_blob.len(),
            i8_blob.len()
        );
    }

    #[test]
    fn select_quantization_picks_int4_for_low_storage_budget() {
        use crate::models::model_manager::{ModelManager, Quantization};

        let mgr = ModelManager::default();
        // 100 MiB available → tight-storage tier → INT4.
        let q = mgr.select_quantization("xlmr", 100 * 1024 * 1024);
        assert_eq!(q, Quantization::Int4);
    }
}
