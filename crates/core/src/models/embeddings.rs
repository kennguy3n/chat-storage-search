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
            .map_err(|e| crate::Error::Storage(format!("search_vector lookup: {e}")))?;
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
            .map_err(|e| crate::Error::Storage(format!("search_vector upsert: {e}")))?;
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
}
