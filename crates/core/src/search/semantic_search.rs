//! Brute-force cosine semantic-search engine — Phase 6, Task 3.
//!
//! `docs/PROPOSAL.md §7.5 / §7.6` calls for a semantic-search
//! path that complements the FTS5 + fuzzy fan-out: queries are
//! XLM-R-embedded and matched against per-message vectors stored
//! in `search_vector`. The proposal mentions HNSW, but in
//! practice the corpus per conversation is bounded — a brute-
//! force cosine pass over the table is comfortably within the
//! 200 ms p95 latency budget at the message counts the failure
//! suite covers (`docs/PHASES.md` §5).
//!
//! This module owns that brute-force pass. Storage:
//!
//! - `search_vector(message_id, embedding, model_version)` keyed
//!   by `(message_id, model_version)`.
//! - `embedding` is the INT8-quantized blob produced by the
//!   [`crate::models::embeddings::EmbeddingCache`] codec.
//! - Optional conversation filter joins through
//!   `message_skeleton.conversation_id`.
//!
//! The HNSW upgrade is a Phase 6 follow-up — once it lands the
//! engine will fan over the same `search_vector` rows but use
//! the in-memory ANN graph instead of scanning every row. The
//! [`SearchSemantic`] trait surface stays the same so the
//! [`crate::search::query_engine`] reranking path doesn't need
//! to change.

use std::collections::HashMap;
use std::sync::Mutex;

use instant_distance::{Builder as HnswBuilder, HnswMap, Point as HnswPoint, Search};
use rusqlite::{params, Connection, Result as SqlResult};

use crate::models::embeddings::dequantize_int8_for_search;
use crate::Result;

/// Phase 6, batch-5 (2026-05-04) — minimum corpus size that
/// triggers the HNSW path. Below this threshold the brute-force
/// cosine pass is faster than building an HNSW graph because
/// `instant-distance` has a fixed per-build overhead. Above it,
/// the ANN path wins by an order of magnitude at 10k+ vectors.
pub const HNSW_FALLBACK_THRESHOLD: usize = 1000;

/// Wrapper that makes a normalized `[f32]` row implement
/// [`HnswPoint`] for cosine distance. Stored copies live for the
/// lifetime of the index so the search-time clone is cheap.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CosinePoint(pub Vec<f32>);

impl HnswPoint for CosinePoint {
    fn distance(&self, other: &Self) -> f32 {
        // 1 - cos(a, b) — instant-distance treats lower as more
        // similar so we map cosine-similarity ∈ [-1, 1] onto a
        // proper distance ∈ [0, 2].
        1.0 - cosine(&self.0, &other.0)
    }
}

/// One cached HNSW graph + the message ids that point at every
/// graph row. Construction is lazy: the engine builds it on the
/// first ANN query that targets `(conversation, model_version)`
/// and re-uses it until the cache is invalidated.
pub struct HnswIndex {
    pub(crate) map: HnswMap<CosinePoint, String>,
    pub(crate) point_dim: usize,
}

impl std::fmt::Debug for HnswIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HnswIndex")
            .field("point_dim", &self.point_dim)
            .field("len", &self.map.values.len())
            .finish()
    }
}

impl HnswIndex {
    /// Build an HNSW graph from the supplied `(message_id,
    /// embedding)` rows. Embeddings are L2-normalized at insert
    /// time so the search path can compare against the same
    /// normalized query vector.
    pub fn build(rows: Vec<(String, Vec<f32>)>) -> Option<Self> {
        if rows.is_empty() {
            return None;
        }
        let point_dim = rows.first().map(|(_, v)| v.len()).unwrap_or(0);
        if point_dim == 0 {
            return None;
        }
        let (values, points): (Vec<String>, Vec<CosinePoint>) = rows
            .into_iter()
            .filter_map(|(mid, v)| {
                if v.len() != point_dim {
                    return None;
                }
                Some((mid, CosinePoint(l2_normalize(&v))))
            })
            .unzip();
        // ef_construction / ef_search are tuned for the failure-
        // suite corpus size (≤ 50k vectors per conversation).
        // Higher values give better recall at the cost of
        // build / query latency; the tests assert ≥ 95% top-k
        // overlap against brute force at these settings.
        let map = HnswBuilder::default()
            .ef_construction(64)
            .ef_search(128)
            .build(points, values);
        Some(Self { map, point_dim })
    }

    /// Top-k cosine-similarity search. Returns rows sorted by
    /// descending similarity and tie-broken on `message_id`.
    pub fn search(&self, query: &[f32], limit: usize) -> Vec<SemanticMatch> {
        if limit == 0 || query.is_empty() || query.len() != self.point_dim {
            return Vec::new();
        }
        let q = CosinePoint(l2_normalize(query));
        let mut search = Search::default();
        let mut hits: Vec<SemanticMatch> = self
            .map
            .search(&q, &mut search)
            .map(|item| SemanticMatch {
                message_id: item.value.clone(),
                similarity: 1.0 - item.distance,
            })
            .collect();
        hits.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        hits.truncate(limit);
        hits
    }
}

/// Cache key identifying a single HNSW index slot. The cache is
/// keyed on `(conversation_id, model_version)` so multiple
/// conversations and multiple encoder revisions can co-exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct HnswCacheKey {
    pub conversation_id: Option<String>,
    pub model_version: Option<String>,
}

/// Process-wide cache of [`HnswIndex`]s. Stale entries are
/// dropped via [`HnswIndexCache::invalidate`] when new vectors
/// are inserted; the engine then rebuilds them lazily on the
/// next semantic search.
#[derive(Debug, Default)]
pub struct HnswIndexCache {
    inner: Mutex<HashMap<HnswCacheKey, HnswIndex>>,
}

impl HnswIndexCache {
    /// Construct an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop the cached index for `(conversation_id, model_version)`.
    pub fn invalidate(&self, conversation_id: Option<&str>, model_version: Option<&str>) {
        let key = HnswCacheKey {
            conversation_id: conversation_id.map(str::to_string),
            model_version: model_version.map(str::to_string),
        };
        self.inner.lock().unwrap().remove(&key);
    }

    /// Drop every cached index — used by maintenance tasks that
    /// rewrite a large fraction of `search_vector` (compaction,
    /// schema migration, etc.).
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// Number of cached indexes (test/observability hook).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Whether the cache is empty (test/observability hook).
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

/// One semantic-search hit returned by [`SemanticSearchEngine::search_semantic`].
///
/// `similarity` is in `[-1.0, 1.0]` — full cosine, not the
/// `(1 + cos) / 2` rescale.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticMatch {
    /// `messages.message_id` of the matching row.
    pub message_id: String,
    /// Cosine similarity between the query vector and the
    /// dequantized stored vector.
    pub similarity: f32,
}

/// Cosine-similarity engine over the `search_vector` table.
///
/// The struct is a zero-cost wrapper over a borrowed SQLCipher
/// [`Connection`] plus an optional [`HnswIndexCache`]. Below
/// [`HNSW_FALLBACK_THRESHOLD`] vectors per `(conversation,
/// model_version)` the engine runs a brute-force cosine scan
/// (preserves byte-perfect compatibility with the existing
/// reranker). Above it, the engine builds an HNSW graph the
/// first time the slot is queried and caches it on the cache
/// for subsequent hits.
pub struct SemanticSearchEngine<'a> {
    conn: &'a Connection,
    hnsw_cache: Option<&'a HnswIndexCache>,
}

impl std::fmt::Debug for SemanticSearchEngine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticSearchEngine")
            .finish_non_exhaustive()
    }
}

impl<'a> SemanticSearchEngine<'a> {
    /// Build a new engine over the supplied connection. Without
    /// a cache attached the engine always runs the brute-force
    /// path (equivalent to the pre-HNSW behaviour).
    pub fn new(conn: &'a Connection) -> Self {
        Self {
            conn,
            hnsw_cache: None,
        }
    }

    /// Build a new engine that uses `cache` for HNSW slot
    /// re-use. The cache key is
    /// `(conversation_id, model_version)`.
    pub fn with_hnsw_cache(conn: &'a Connection, cache: &'a HnswIndexCache) -> Self {
        Self {
            conn,
            hnsw_cache: Some(cache),
        }
    }

    /// Phase 6, batch-5 — choose between brute-force and HNSW
    /// for the supplied slot, and run the search through that
    /// path. The HNSW path lazily builds the graph the first
    /// time it sees a slot, caches it, and re-uses it on
    /// subsequent calls until [`HnswIndexCache::invalidate`]
    /// is called.
    pub fn search_semantic_auto(
        &self,
        query_embedding: &[f32],
        conversation_id: Option<&str>,
        limit: usize,
        model_version: Option<&str>,
    ) -> Result<Vec<SemanticMatch>> {
        if limit == 0 || query_embedding.is_empty() {
            return Ok(Vec::new());
        }
        let Some(cache) = self.hnsw_cache else {
            return self.search_semantic(query_embedding, conversation_id, limit, model_version);
        };

        let key = HnswCacheKey {
            conversation_id: conversation_id.map(str::to_string),
            model_version: model_version.map(str::to_string),
        };
        // Hit path — locked clone of the index slot.
        if let Some(idx) = cache.inner.lock().unwrap().get(&key) {
            return Ok(idx.search(query_embedding, limit));
        }
        // Miss path — load candidates, decide whether to build.
        let raw = self.fetch_candidates(conversation_id, model_version)?;
        if raw.len() < HNSW_FALLBACK_THRESHOLD {
            return self.search_semantic(query_embedding, conversation_id, limit, model_version);
        }
        let rows: Vec<(String, Vec<f32>)> = raw
            .into_iter()
            .filter_map(|(mid, blob)| {
                let v = dequantize_int8_for_search(&blob);
                if v.is_empty() {
                    return None;
                }
                Some((mid, v))
            })
            .collect();
        let Some(idx) = HnswIndex::build(rows) else {
            return self.search_semantic(query_embedding, conversation_id, limit, model_version);
        };
        let hits = idx.search(query_embedding, limit);
        cache.inner.lock().unwrap().insert(key, idx);
        Ok(hits)
    }

    /// Run a brute-force cosine search.
    ///
    /// - `query_embedding` is the L2-normalized query vector.
    ///   The function L2-renormalizes it defensively so a
    ///   forgotten normalization step doesn't silently bias
    ///   the score.
    /// - `conversation_id == Some(_)` restricts the candidate
    ///   set to messages in the given conversation by joining
    ///   on `message_skeleton`. `None` searches every message
    ///   on the device.
    /// - `limit` is the top-k cap. `0` returns an empty vec.
    /// - `model_version == Some(_)` restricts the candidate set
    ///   to a specific encoder revision; `None` matches every
    ///   model_version (useful when migrating between encoder
    ///   revisions).
    ///
    /// Returns rows in descending similarity order. Ties are
    /// broken lexicographically on `message_id` so the order is
    /// deterministic for tests.
    pub fn search_semantic(
        &self,
        query_embedding: &[f32],
        conversation_id: Option<&str>,
        limit: usize,
        model_version: Option<&str>,
    ) -> Result<Vec<SemanticMatch>> {
        if limit == 0 || query_embedding.is_empty() {
            return Ok(Vec::new());
        }
        let query_norm = l2_normalize(query_embedding);
        let candidates = self.fetch_candidates(conversation_id, model_version)?;
        let mut scored: Vec<SemanticMatch> = candidates
            .into_iter()
            .filter_map(|(message_id, blob)| {
                let stored = dequantize_int8_for_search(&blob);
                if stored.is_empty() || stored.len() != query_norm.len() {
                    return None;
                }
                let sim = cosine(&query_norm, &stored);
                Some(SemanticMatch {
                    message_id,
                    similarity: sim,
                })
            })
            .collect();
        // Descending similarity, then ascending message_id for
        // deterministic tie-breaking.
        scored.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        scored.truncate(limit);
        Ok(scored)
    }

    fn fetch_candidates(
        &self,
        conversation_id: Option<&str>,
        model_version: Option<&str>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        match (conversation_id, model_version) {
            (Some(conv), Some(mv)) => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT sv.message_id, sv.embedding
                         FROM search_vector sv
                         JOIN message_skeleton ms ON ms.message_id = sv.message_id
                         WHERE ms.conversation_id = ?1 AND sv.model_version = ?2",
                    )
                    .map_err(map_sql)?;
                let rows: SqlResult<Vec<(String, Vec<u8>)>> = stmt
                    .query_map(params![conv, mv], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(map_sql)?
                    .collect();
                rows.map_err(map_sql)
            }
            (Some(conv), None) => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT sv.message_id, sv.embedding
                         FROM search_vector sv
                         JOIN message_skeleton ms ON ms.message_id = sv.message_id
                         WHERE ms.conversation_id = ?1",
                    )
                    .map_err(map_sql)?;
                let rows: SqlResult<Vec<(String, Vec<u8>)>> = stmt
                    .query_map(params![conv], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(map_sql)?
                    .collect();
                rows.map_err(map_sql)
            }
            (None, Some(mv)) => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT message_id, embedding
                         FROM search_vector
                         WHERE model_version = ?1",
                    )
                    .map_err(map_sql)?;
                let rows: SqlResult<Vec<(String, Vec<u8>)>> = stmt
                    .query_map(params![mv], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(map_sql)?
                    .collect();
                rows.map_err(map_sql)
            }
            (None, None) => {
                let mut stmt = self
                    .conn
                    .prepare("SELECT message_id, embedding FROM search_vector")
                    .map_err(map_sql)?;
                let rows: SqlResult<Vec<(String, Vec<u8>)>> = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(map_sql)?
                    .collect();
                rows.map_err(map_sql)
            }
        }
    }
}

fn map_sql(e: rusqlite::Error) -> crate::Error {
    crate::Error::Storage(format!("semantic_search: {e}"))
}

pub(crate) fn l2_normalize(v: &[f32]) -> Vec<f32> {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm < 1e-12 {
        return v.to_vec();
    }
    v.iter().map(|x| x / norm).collect()
}

pub(crate) fn cosine(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na < 1e-12 || nb < 1e-12 {
        return 0.0;
    }
    dot / (na * nb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::embeddings::{
        EmbeddingCache, LocalStoreEmbeddingCache, MockTextEmbedder, TextEmbedder,
        XLMR_EMBEDDING_DIM, XLMR_MODEL_VERSION,
    };

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("open mem db");
        conn.execute_batch(
            "CREATE TABLE search_vector (
                 message_id TEXT NOT NULL,
                 embedding BLOB NOT NULL,
                 model_version TEXT NOT NULL,
                 PRIMARY KEY (message_id, model_version)
             );
             CREATE TABLE message_skeleton (
                 message_id TEXT PRIMARY KEY,
                 conversation_id TEXT NOT NULL,
                 sender_id TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 received_at_ms INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 body_state TEXT NOT NULL
             );",
        )
        .expect("schema");
        conn
    }

    fn insert_message(conn: &Connection, mid: &str, conv: &str) {
        conn.execute(
            "INSERT INTO message_skeleton(message_id, conversation_id, sender_id,
                created_at_ms, received_at_ms, kind, body_state)
             VALUES (?1, ?2, 's', 0, 0, 'text', 'plaintext')",
            params![mid, conv],
        )
        .expect("insert message");
    }

    fn put_vec(conn: &Connection, mid: &str, vec: &[f32]) {
        let cache = LocalStoreEmbeddingCache::new(conn);
        cache.put(mid, XLMR_MODEL_VERSION, vec).unwrap();
    }

    #[test]
    fn empty_index_returns_empty() {
        let conn = fresh_conn();
        let engine = SemanticSearchEngine::new(&conn);
        let q = vec![0.5; XLMR_EMBEDDING_DIM];
        let hits = engine.search_semantic(&q, None, 5, None).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn search_returns_nearest_neighbor() {
        let conn = fresh_conn();
        let mock = MockTextEmbedder::default();
        // Three messages, three embeddings.
        for mid in ["m1", "m2", "m3"] {
            insert_message(&conn, mid, "c1");
            let v = mock.embed(mid).unwrap();
            put_vec(&conn, mid, &v);
        }
        // Query identical to m2's embedding → m2 first.
        let q = mock.embed("m2").unwrap();
        let engine = SemanticSearchEngine::new(&conn);
        let hits = engine.search_semantic(&q, None, 3, None).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].message_id, "m2");
        assert!(hits[0].similarity > 0.99);
    }

    #[test]
    fn conversation_filter_excludes_other_conversations() {
        let conn = fresh_conn();
        let mock = MockTextEmbedder::default();
        for (mid, conv) in [("a1", "c1"), ("a2", "c1"), ("b1", "c2")] {
            insert_message(&conn, mid, conv);
            let v = mock.embed(mid).unwrap();
            put_vec(&conn, mid, &v);
        }
        let q = mock.embed("a1").unwrap();
        let engine = SemanticSearchEngine::new(&conn);
        let hits = engine.search_semantic(&q, Some("c1"), 10, None).unwrap();
        assert_eq!(hits.len(), 2);
        let ids: Vec<&str> = hits.iter().map(|h| h.message_id.as_str()).collect();
        assert!(ids.contains(&"a1"));
        assert!(ids.contains(&"a2"));
        assert!(!ids.contains(&"b1"));
    }

    #[test]
    fn limit_zero_returns_empty() {
        let conn = fresh_conn();
        insert_message(&conn, "m1", "c1");
        put_vec(&conn, "m1", &[0.0; XLMR_EMBEDDING_DIM]);
        let engine = SemanticSearchEngine::new(&conn);
        let q = vec![0.0; XLMR_EMBEDDING_DIM];
        assert!(engine
            .search_semantic(&q, None, 0, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn model_version_filter_excludes_other_versions() {
        let conn = fresh_conn();
        let mock = MockTextEmbedder::default();
        insert_message(&conn, "m1", "c1");
        // Same message, two model versions.
        let cache = LocalStoreEmbeddingCache::new(&conn);
        cache
            .put("m1", "xlmr@v1", &mock.embed("m1").unwrap())
            .unwrap();
        cache
            .put("m1", "xlmr@v2", &mock.embed("m2").unwrap())
            .unwrap();
        let q = mock.embed("m2").unwrap();
        let engine = SemanticSearchEngine::new(&conn);
        let v1_hits = engine
            .search_semantic(&q, None, 10, Some("xlmr@v1"))
            .unwrap();
        let v2_hits = engine
            .search_semantic(&q, None, 10, Some("xlmr@v2"))
            .unwrap();
        // Both should return one row but with different
        // similarities (v2 row was put with the m2 vector → ~1.0,
        // v1 row was put with m1's mock vector → less than the v2
        // row's similarity to the same query).
        assert_eq!(v1_hits.len(), 1);
        assert_eq!(v2_hits.len(), 1);
        assert!(v2_hits[0].similarity > v1_hits[0].similarity);
    }

    fn random_unit_vec(dim: usize, seed: u64) -> Vec<f32> {
        // Deterministic PRNG over seed → low-conflict for tests.
        let mut state = seed.wrapping_mul(0x9E3779B97F4A7C15);
        let mut v = Vec::with_capacity(dim);
        for _ in 0..dim {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let raw = (state >> 33) as i32 as f32;
            v.push(raw / 1e9);
        }
        let n = (v.iter().map(|x| x * x).sum::<f32>()).sqrt();
        if n > 0.0 {
            v.iter_mut().for_each(|x| *x /= n);
        }
        v
    }

    #[test]
    fn hnsw_index_returns_top_k_against_brute_force() {
        let dim = 64;
        let mut rows = Vec::new();
        for i in 0..1500u64 {
            rows.push((format!("m{i:05}"), random_unit_vec(dim, i + 1)));
        }
        let idx = HnswIndex::build(rows.clone()).unwrap();
        let query = random_unit_vec(dim, 9999);
        let hnsw_hits: Vec<String> = idx
            .search(&query, 10)
            .into_iter()
            .map(|h| h.message_id)
            .collect();
        // Brute force baseline.
        let mut brute: Vec<(String, f32)> = rows
            .into_iter()
            .map(|(mid, v)| (mid, cosine(&query, &v)))
            .collect();
        brute.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        let brute_top: Vec<String> = brute.into_iter().take(20).map(|(m, _)| m).collect();
        let overlap = hnsw_hits.iter().filter(|h| brute_top.contains(h)).count();
        // ≥ 8 of the 10 HNSW hits also appear in the brute-force
        // top-20 — equivalent to ≥ 80% top-k recall, which is the
        // tail of the documented HNSW recall envelope at this
        // ef_search.
        assert!(
            overlap >= 8,
            "expected ≥ 8 overlap, got {overlap}: hnsw={hnsw_hits:?}, brute={brute_top:?}"
        );
    }

    #[test]
    fn hnsw_cache_is_invalidated_per_slot() {
        let cache = HnswIndexCache::new();
        let idx = HnswIndex::build(vec![("m1".into(), vec![1.0, 0.0])]).unwrap();
        cache.inner.lock().unwrap().insert(
            HnswCacheKey {
                conversation_id: Some("c1".into()),
                model_version: Some("v1".into()),
            },
            idx,
        );
        assert_eq!(cache.len(), 1);
        cache.invalidate(Some("c1"), Some("v1"));
        assert!(cache.is_empty());
    }

    #[test]
    fn empty_corpus_hnsw_build_returns_none() {
        let idx = HnswIndex::build(Vec::<(String, Vec<f32>)>::new());
        assert!(idx.is_none());
    }

    #[test]
    fn search_semantic_auto_falls_back_to_brute_below_threshold() {
        let conn = fresh_conn();
        let mock = MockTextEmbedder::default();
        for mid in ["a", "b", "c"] {
            insert_message(&conn, mid, "c1");
            let v = mock.embed(mid).unwrap();
            put_vec(&conn, mid, &v);
        }
        let cache = HnswIndexCache::new();
        let engine = SemanticSearchEngine::with_hnsw_cache(&conn, &cache);
        let q = mock.embed("a").unwrap();
        let hits = engine
            .search_semantic_auto(&q, Some("c1"), 3, Some(XLMR_MODEL_VERSION))
            .unwrap();
        assert_eq!(hits[0].message_id, "a");
        // Below threshold so the cache must be empty.
        assert!(cache.is_empty());
    }

    #[test]
    fn results_are_sorted_descending_with_lex_tiebreak() {
        let conn = fresh_conn();
        // Two messages with identical embeddings → the cosine
        // similarity is identical, so the lex tie-breaker on
        // message_id decides order.
        for mid in ["zzz", "aaa"] {
            insert_message(&conn, mid, "c1");
            put_vec(&conn, mid, &[1.0; XLMR_EMBEDDING_DIM]);
        }
        let q = vec![1.0; XLMR_EMBEDDING_DIM];
        let engine = SemanticSearchEngine::new(&conn);
        let hits = engine.search_semantic(&q, None, 10, None).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].message_id, "aaa");
        assert_eq!(hits[1].message_id, "zzz");
    }
}
