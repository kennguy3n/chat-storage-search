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
    let engine = QueryEngine::new(db.connection(), db.icu_available());

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

/// p95 budget gate: end-to-end shard fetch (in-memory mock) +
/// AEAD decrypt + local FTS5 / fuzzy search across a one-month
/// bucket of ~1 000 multilingual messages must stay under
/// **1.5 s** at the 95th percentile (`docs/PHASES.md §Phase 5`).
///
/// This complements the criterion benches in
/// `crates/core/benches/phase5_benchmarks.rs` (which produce the
/// publishable histogram) with a CI-friendly assert: it runs in
/// every `cargo test --workspace` pass and fails the build if
/// the p95 ever exceeds the documented budget.
///
/// The corpus interleaves four scripts (Latin, Cyrillic, Greek,
/// CJK) so the script-aware fuzzy tokenizer is exercised on the
/// fetch path. The needle term is repeated in ~1 % of rows so
/// every iteration surfaces hits from the cold path.
#[test]
fn phase5_cold_shard_p95_latency_under_1_5s_budget() {
    use std::time::Duration;

    const ITERATIONS: usize = 20;
    const P95_BUDGET: Duration = Duration::from_millis(1_500);

    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_id = Uuid::now_v7().to_string();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);
    let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();
    let k_fuzzy = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();

    // Multilingual one-month corpus. Every 100th row carries the
    // needle in Latin so the FTS path lights up; the remaining
    // rows interleave four scripts so the fuzzy tokenizer runs
    // each per-script branch.
    let scripts: [&str; 4] = [
        "lighthouse keepers gathered at dusk",
        "смотритель маяка собрал сети на закате",
        "οι φύλακες του φάρου μάζεψαν δίχτυα",
        "灯塔守护者在黄昏时分聚集",
    ];

    let mut fts_rows: Vec<FtsRow> = Vec::with_capacity(SHARD_ROWS);
    let mut fuzzy_rows: Vec<FuzzyRow> = Vec::new();
    for i in 0..SHARD_ROWS {
        let mid = Uuid::now_v7().to_string();
        let text = if i % (SHARD_ROWS / 10) == 0 {
            format!("{NEEDLE} keepers gathered at dusk near the harbor (#{i})")
        } else {
            format!("{} (#{i})", scripts[i % scripts.len()])
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

    // Warm criterion-style: discard a single warm-up sample to
    // amortise allocator + page-cache costs before measuring.
    {
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: NEEDLE.into(),
            ..Default::default()
        };
        let _ = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
            .unwrap();
    }

    let mut samples: Vec<Duration> = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: NEEDLE.into(),
            ..Default::default()
        };
        let start = Instant::now();
        let hits = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
            .unwrap();
        samples.push(start.elapsed());
        assert!(!hits.is_empty(), "cold path must surface needle rows");
    }
    samples.sort();

    // p95 = ceil(0.95 * N) - 1 (zero-indexed) gives a stable
    // pick across small sample counts. With ITERATIONS = 20 this
    // is samples[18], i.e. the second-slowest run.
    let p95_idx = ((samples.len() as f64) * 0.95).ceil() as usize - 1;
    let p95 = samples[p95_idx];
    assert!(
        p95 <= P95_BUDGET,
        "phase 5 p95 latency {p95:?} exceeds {P95_BUDGET:?} (samples: {samples:?})",
    );
}

/// Helper: build a multilingual `(text_blobs, fuzzy_blobs)` pair
/// for a corpus of `rows` messages where ~1% match `needle`.
/// Used by the new Phase-5 batch-10 latency smoke tests below.
#[allow(clippy::type_complexity)]
fn build_multilingual_corpus(
    rows: usize,
    needle: &str,
    bucket: &str,
) -> (
    HashMap<(String, String), (SearchIndexShard, KeyMaterial)>,
    HashMap<(String, String), (SearchIndexShard, KeyMaterial)>,
    String,
) {
    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_id = Uuid::now_v7().to_string();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);
    let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();
    let k_fuzzy = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();

    let scripts: [&str; 4] = [
        "lighthouse keepers gathered at dusk",
        "смотритель маяка собрал сети на закате",
        "οι φύλακες του φάρου μάζεψαν δίχτυα",
        "灯塔守护者在黄昏时分聚集",
    ];

    let mut fts_rows: Vec<FtsRow> = Vec::with_capacity(rows);
    let mut fuzzy_rows: Vec<FuzzyRow> = Vec::new();
    let needle_step = (rows / 100).max(1);
    for i in 0..rows {
        let mid = Uuid::now_v7().to_string();
        let text = if i % needle_step == 0 {
            format!("{needle} keepers gathered at dusk near the harbor (#{i})")
        } else {
            format!("{} (#{i})", scripts[i % scripts.len()])
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
        build_text_search_shard(fts_rows, &conv_id, bucket, &k_text, &conv_hash_key).unwrap();
    let fuzzy_built =
        build_fuzzy_search_shard(fuzzy_rows, &conv_id, bucket, &k_fuzzy, &conv_hash_key).unwrap();

    let mut text_blobs = HashMap::new();
    text_blobs.insert(
        (conv_id.clone(), bucket.to_string()),
        (text_built.shard, text_built.k_shard),
    );
    let mut fuzzy_blobs = HashMap::new();
    fuzzy_blobs.insert(
        (conv_id.clone(), bucket.to_string()),
        (fuzzy_built.shard, fuzzy_built.k_shard),
    );
    (text_blobs, fuzzy_blobs, conv_id)
}

/// Helper: drive the cold-shard search path through `iterations`
/// runs against an [`InMemoryCatalog`] and assert the p95 stays
/// under `budget`. Phase 5 batch 10 — Task 4.
fn assert_p95_under_budget(
    catalog: &InMemoryCatalog,
    iterations: usize,
    budget: std::time::Duration,
) {
    let db = LocalStoreDb::open_in_memory(&[0x55; 32]).unwrap();
    // Warm-up — discard the first sample so allocator / page-cache
    // costs don't bias the histogram.
    {
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: NEEDLE.into(),
            ..Default::default()
        };
        let _ = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, catalog)
            .unwrap();
    }
    let mut samples: Vec<std::time::Duration> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let engine = QueryEngine::new(db.connection(), db.icu_available());
        let q = SearchQuery {
            query_string: NEEDLE.into(),
            ..Default::default()
        };
        let start = Instant::now();
        let _ = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, catalog)
            .unwrap();
        samples.push(start.elapsed());
    }
    samples.sort();
    let p95_idx = ((samples.len() as f64) * 0.95).ceil() as usize - 1;
    let p95 = samples[p95_idx];
    assert!(
        p95 <= budget,
        "phase 5 p95 latency {p95:?} exceeds {budget:?} (samples: {samples:?})",
    );
}

/// Phase 5, batch 10 — Task 4: multilingual p95 gate.
///
/// Same shape as the existing one-bucket gate but explicitly
/// stresses the script-aware fuzzy path with a larger corpus
/// (4 scripts interleaved). Must stay under the PROPOSAL §7.5
/// 1.5 s headline budget.
#[test]
fn phase5_cold_shard_p95_multilingual_under_budget() {
    use std::time::Duration;
    const ITERATIONS: usize = 20;
    const P95_BUDGET: Duration = Duration::from_millis(1_500);

    let (text_blobs, fuzzy_blobs, _) = build_multilingual_corpus(SHARD_ROWS, NEEDLE, BUCKET);
    let catalog = InMemoryCatalog {
        text_blobs,
        fuzzy_blobs,
    };
    assert_p95_under_budget(&catalog, ITERATIONS, P95_BUDGET);
}

/// Phase 5, batch 10 — Task 4: large-bucket stress test.
///
/// 5 000-row bucket — five times the headline corpus. The p95
/// budget grows linearly with corpus size so a 5x bucket gets
/// the headline 1.5 s × 5 = 7.5 s gate. Anything slower than
/// that is a regression in the cold-fetch / decrypt / merge
/// pipeline.
#[test]
fn phase5_cold_shard_p95_large_bucket_under_budget() {
    use std::time::Duration;
    const ITERATIONS: usize = 10;
    const ROWS: usize = 5_000;
    const P95_BUDGET: Duration = Duration::from_millis(7_500);

    let (text_blobs, fuzzy_blobs, _) = build_multilingual_corpus(ROWS, NEEDLE, BUCKET);
    let catalog = InMemoryCatalog {
        text_blobs,
        fuzzy_blobs,
    };
    assert_p95_under_budget(&catalog, ITERATIONS, P95_BUDGET);
}

/// Phase 5, batch 10 — Task 4: multi-shard p95 gate.
///
/// Splits the corpus across 3 buckets so the cold fan-out
/// fetches 3 text + 3 fuzzy shards per search. The p95 must
/// stay under 3.0 s — the headline budget × 2 with 3 shards is
/// generous enough to hide CI noise without masking a real
/// regression.
#[test]
fn phase5_cold_shard_p95_multiple_shards_under_budget() {
    use std::time::Duration;
    const ITERATIONS: usize = 15;
    const ROWS_PER_SHARD: usize = 400;
    const P95_BUDGET: Duration = Duration::from_millis(3_000);

    let (mut text_blobs, mut fuzzy_blobs, _) =
        build_multilingual_corpus(ROWS_PER_SHARD, NEEDLE, "2026-04");
    for bucket in ["2026-05", "2026-06"] {
        let (more_text, more_fuzzy, _) = build_multilingual_corpus(ROWS_PER_SHARD, NEEDLE, bucket);
        text_blobs.extend(more_text);
        fuzzy_blobs.extend(more_fuzzy);
    }
    let catalog = InMemoryCatalog {
        text_blobs,
        fuzzy_blobs,
    };
    assert_p95_under_budget(&catalog, ITERATIONS, P95_BUDGET);
}
