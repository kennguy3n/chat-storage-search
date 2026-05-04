//! Phase-5 smoke test for cold-shard search latency.
//!
//! `docs/PHASES.md §Phase 5` decision gate is "≤ 1.5 s p95 over
//! Wi-Fi for a one-month bucket". The criterion benches in
//! `phase5_benchmarks.rs` exercise the histogram; this test acts
//! as a coarse, CI-friendly upper bound: the decrypt + search
//! path for a one-month bucket must finish in well under 5 s on
//! even the slowest CI runner. Anything slower indicates a
//! regression at the order-of-magnitude level.

use std::collections::HashMap;
use std::time::Instant;

use uuid::Uuid;

use kchat_core::crypto::key_hierarchy::{derive_search_root, derive_text_index_shard, KeyMaterial};
use kchat_core::formats::search_shard::SearchIndexShard;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::search::fuzzy_search::FuzzyTokenizer;
use kchat_core::search::query_engine::{ColdShardSource, QueryEngine};
use kchat_core::search::shard_builder::{
    build_fuzzy_search_shard, build_text_search_shard, restore_fuzzy_search_shard,
    restore_text_search_shard, FtsRow, FuzzyRow,
};
use kchat_core::{Error, SearchQuery, SearchScope};

const SHARD_ROWS: usize = 1_000;
const BUCKET: &str = "2026-04";
const NEEDLE: &str = "lighthouse";

struct InMemoryCatalog {
    text_blobs: HashMap<(String, String), (SearchIndexShard, KeyMaterial)>,
    fuzzy_blobs: HashMap<(String, String), (SearchIndexShard, KeyMaterial)>,
}

impl ColdShardSource for InMemoryCatalog {
    fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
        let mut keys: Vec<(String, String)> = self.text_blobs.keys().cloned().collect();
        for k in self.fuzzy_blobs.keys() {
            if !keys.contains(k) {
                keys.push(k.clone());
            }
        }
        Ok(keys)
    }
    fn fetch_text_rows(
        &self,
        conversation_id: &str,
        time_bucket: &str,
    ) -> Result<Vec<FtsRow>, Error> {
        let key = (conversation_id.to_string(), time_bucket.to_string());
        let Some((shard, k)) = self.text_blobs.get(&key) else {
            return Ok(Vec::new());
        };
        restore_text_search_shard(shard, k)
    }
    fn fetch_fuzzy_rows(
        &self,
        conversation_id: &str,
        time_bucket: &str,
    ) -> Result<Vec<FuzzyRow>, Error> {
        let key = (conversation_id.to_string(), time_bucket.to_string());
        let Some((shard, k)) = self.fuzzy_blobs.get(&key) else {
            return Ok(Vec::new());
        };
        restore_fuzzy_search_shard(shard, k)
    }
}

#[test]
fn phase5_cold_shard_decrypt_and_search_finishes_under_smoke_budget() {
    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_id = Uuid::now_v7().to_string();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);
    let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();
    let k_fuzzy = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();

    let mut fts_rows: Vec<FtsRow> = Vec::with_capacity(SHARD_ROWS);
    let mut fuzzy_rows: Vec<FuzzyRow> = Vec::new();
    for i in 0..SHARD_ROWS {
        let mid = Uuid::now_v7().to_string();
        let text = if i % (SHARD_ROWS / 10) == 0 {
            format!("{NEEDLE} keepers gathered at dusk near the harbor (#{i})")
        } else {
            format!("standard chatter about coffee, work, and weekends (#{i})")
        };
        fts_rows.push(FtsRow {
            message_id: mid.clone(),
            conversation_id: conv_id.clone(),
            sender_id: format!("user-{}", i % 5),
            created_at_ms: 1_700_000_000_000 + i as i64,
            text_content: text.clone(),
        });
        for tok in FuzzyTokenizer::generate_tokens(&text) {
            fuzzy_rows.push(FuzzyRow {
                token: tok.token,
                script: tok.script.to_iso_15924().to_string(),
                message_id: mid.clone(),
            });
        }
    }
    let text_built =
        build_text_search_shard(fts_rows, &conv_id, BUCKET, &k_text, &conv_hash_key).unwrap();
    let fuzzy_built =
        build_fuzzy_search_shard(fuzzy_rows, &conv_id, BUCKET, &k_fuzzy, &conv_hash_key).unwrap();

    let mut text_blobs = HashMap::new();
    text_blobs.insert(
        (conv_id.clone(), BUCKET.to_string()),
        (text_built.shard, text_built.k_shard),
    );
    let mut fuzzy_blobs = HashMap::new();
    fuzzy_blobs.insert(
        (conv_id.clone(), BUCKET.to_string()),
        (fuzzy_built.shard, fuzzy_built.k_shard),
    );
    let catalog = InMemoryCatalog {
        text_blobs,
        fuzzy_blobs,
    };

    let db = LocalStoreDb::open_in_memory(&[0x55; 32]).unwrap();
    let engine = QueryEngine::new(&db);

    let q = SearchQuery {
        query_string: NEEDLE.into(),
        ..Default::default()
    };

    let start = Instant::now();
    let hits = engine
        .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
        .unwrap();
    let elapsed = start.elapsed();

    assert!(!hits.is_empty(), "cold path should surface needle rows");
    // 5-second smoke budget — not the p95 gate, just an
    // order-of-magnitude regression detector.
    assert!(
        elapsed.as_secs_f64() < 5.0,
        "cold-shard decrypt + search took {elapsed:?}, exceeds 5 s smoke budget",
    );
}
