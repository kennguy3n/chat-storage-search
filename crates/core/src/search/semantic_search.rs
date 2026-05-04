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

use rusqlite::{params, Connection, Result as SqlResult};

use crate::models::embeddings::dequantize_int8_for_search;
use crate::Result;

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
/// [`Connection`]; create one per query batch, drop it when
/// done. No internal state is cached so concurrent reads are
/// safe through SQLite's `RwLock`-equivalent.
pub struct SemanticSearchEngine<'a> {
    conn: &'a Connection,
}

impl std::fmt::Debug for SemanticSearchEngine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticSearchEngine")
            .finish_non_exhaustive()
    }
}

impl<'a> SemanticSearchEngine<'a> {
    /// Build a new engine over the supplied connection.
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
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
