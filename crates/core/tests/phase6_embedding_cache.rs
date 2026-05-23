//! cross-pipeline embedding cache integration
//! test (`docs/DESIGN.md §7.6.1`).
//!
//! [`EmbeddingCache`] is the on-disk seam shared between the
//! search pipeline (xlm-r text embeddings) and the guardrail
//! pipeline (Llama / Gemma sidecar). Two cache instances on the
//! same SQLCipher connection MUST observe each other's writes,
//! and a (`message_id`, `model_version`) pair that doesn't match
//! the row's stored version MUST surface as "miss" rather than
//! returning a row that was actually written for a different
//! model.

use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::models::embeddings::{
    EmbeddingCache, LocalStoreEmbeddingCache, XLMR_EMBEDDING_DIM, XLMR_MODEL_VERSION,
};

/// Ten-byte fixture key — every + integration test uses
/// the same `0xCD..` shape so failed CI logs are easy to grep.
const FIXTURE_KEY: [u8; 32] = [0xCD; 32];

fn fresh_db() -> LocalStoreDb {
    LocalStoreDb::open_in_memory(&FIXTURE_KEY).expect("open in-memory db")
}

fn deterministic_embedding(seed: u32, dim: usize) -> Vec<f32> {
    let mut x = seed.max(1);
    let mut raw: Vec<f32> = Vec::with_capacity(dim);
    for _ in 0..dim {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        raw.push((x as i32) as f32 / i32::MAX as f32);
    }
    let norm: f32 = raw.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 1e-12 {
        for v in &mut raw {
            *v /= norm;
        }
    }
    raw
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len(), "vector dim mismatch");
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na: f32 = a
        .iter()
        .map(|x| x * x)
        .sum::<f32>()
        .sqrt()
        .max(f32::EPSILON);
    let nb: f32 = b
        .iter()
        .map(|x| x * x)
        .sum::<f32>()
        .sqrt()
        .max(f32::EPSILON);
    dot / (na * nb)
}

#[test]
fn put_then_get_round_trips_with_high_fidelity() {
    let db = fresh_db();
    let cache = LocalStoreEmbeddingCache::new(db.connection());

    let mid = "00000000-0000-0000-0000-000000000001";
    let original = deterministic_embedding(0xABCD, XLMR_EMBEDDING_DIM);
    cache.put(mid, XLMR_MODEL_VERSION, &original).expect("put");
    let read_back = cache
        .get(mid, XLMR_MODEL_VERSION)
        .expect("get")
        .expect("vector present");

    assert_eq!(read_back.len(), original.len());
    let sim = cosine_similarity(&original, &read_back);
    assert!(
        sim > 0.999,
        "INT8 round-trip cosine should be >0.999 (got {sim})",
    );
}

#[test]
fn version_mismatch_returns_none() {
    let db = fresh_db();
    let cache = LocalStoreEmbeddingCache::new(db.connection());

    let mid = "00000000-0000-0000-0000-000000000002";
    let v = deterministic_embedding(0xBEEF, XLMR_EMBEDDING_DIM);
    cache.put(mid, XLMR_MODEL_VERSION, &v).expect("put");

    // Same message, different model_version — must miss.
    let other = cache
        .get(mid, "xlmr@v999")
        .expect("get under wrong version");
    assert!(
        other.is_none(),
        "version-mismatched lookup must return None",
    );
}

#[test]
fn shared_connection_two_cache_instances_see_each_others_writes() {
    let db = fresh_db();

    // The "search-pipeline" cache writes a row.
    let search_pipeline = LocalStoreEmbeddingCache::new(db.connection());
    let mid = "00000000-0000-0000-0000-000000000003";
    let written = deterministic_embedding(0xC0FFEE, XLMR_EMBEDDING_DIM);
    search_pipeline
        .put(mid, XLMR_MODEL_VERSION, &written)
        .expect("search-pipeline put");

    // The "guardrail-pipeline" cache reads it back through a
    // different `LocalStoreEmbeddingCache` instance bound to the
    // same connection.
    let guardrail_pipeline = LocalStoreEmbeddingCache::new(db.connection());
    let read = guardrail_pipeline
        .get(mid, XLMR_MODEL_VERSION)
        .expect("guardrail-pipeline get")
        .expect("vector visible cross-pipeline");
    let sim = cosine_similarity(&written, &read);
    assert!(
        sim > 0.999,
        "cross-pipeline read must round-trip with cosine >0.999 (got {sim})",
    );

    // And vice-versa: a write from the guardrail side is visible
    // to the search side.
    let mid2 = "00000000-0000-0000-0000-000000000004";
    let written2 = deterministic_embedding(0xFACE, XLMR_EMBEDDING_DIM);
    guardrail_pipeline
        .put(mid2, XLMR_MODEL_VERSION, &written2)
        .expect("guardrail-pipeline put");

    let read2 = search_pipeline
        .get(mid2, XLMR_MODEL_VERSION)
        .expect("search-pipeline get")
        .expect("vector visible reverse direction");
    assert!(cosine_similarity(&written2, &read2) > 0.999);
}

#[test]
fn empty_cache_get_returns_none() {
    let db = fresh_db();
    let cache = LocalStoreEmbeddingCache::new(db.connection());
    let res = cache
        .get("00000000-0000-0000-0000-000000000005", XLMR_MODEL_VERSION)
        .expect("get on empty cache");
    assert!(res.is_none());
}
