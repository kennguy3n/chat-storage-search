//! Phase 8 (2026-05-04 batch 6) — multi-scope search latency
//! benchmarks.
//!
//! `docs/PHASES.md §Phase 8` calls for the new search surface to
//! stay under the §12 latency budget even when the query
//! exercises bloom pre-checks, the on-device shard cache, and
//! the multi-scope target resolver. This bench suite wires up
//! criterion so the histograms can be diffed against the
//! Phase-5 baseline.
//!
//! Sub-benches:
//!
//! * `bloom_precheck_one_month_bucket` — build a bloom shard
//!   for a 1 000-word bucket and check 10 query terms against
//!   it. Target: `< 1 ms` per check (i.e. the criterion mean).
//! * `shard_cache_hit_vs_miss` — measure the latency gap
//!   between a [`ShardCache::get`] hit and the equivalent cold
//!   fetch + decrypt path.
//! * `scope_resolver_community_100_conversations` — resolve a
//!   `SearchTarget::Community` over a synthetic 100-conversation
//!   community using the structured-only SQL filter.
//! * `date_pruning_100_buckets` — prune 100 candidate buckets
//!   with a date range, exercising
//!   [`bucket_overlaps_date_range`].
//! * `global_search_with_bloom_10_buckets` — end-to-end
//!   global search across 10 cold buckets with the bloom
//!   pre-check active; only 1 bucket actually contains the
//!   query token.
//!
//! Run with:
//! ```sh
//! cargo bench -p kchat-core --features test-support --bench phase8_benchmarks
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use uuid::Uuid;

use kchat_core::crypto::key_hierarchy::{
    derive_bloom_index_shard, derive_search_root, derive_text_index_shard, KeyMaterial,
};
use kchat_core::formats::search_shard::IndexType;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::search::query_engine::{bucket_overlaps_date_range, ColdShardSource, QueryEngine};
use kchat_core::search::shard_builder::{
    build_bloom_shard, restore_bloom_shard, BloomFilter, FtsRow, FuzzyRow,
};
use kchat_core::search::shard_cache::{CachedShard, ShardCache, ShardCacheKey};
use kchat_core::{Error, SearchQuery, SearchScope, SearchTarget};

// ---------------------------------------------------------------------------
// helpers shared across the sub-benches
// ---------------------------------------------------------------------------

fn fresh_keys() -> (KeyMaterial, KeyMaterial) {
    // Pretend we are the orchestration layer: derive a search
    // root from a 32-byte master. The exact values do not
    // matter for benches.
    let master = KeyMaterial::from_bytes([0xA1; 32]);
    let search_root = derive_search_root(&master).expect("search root");
    // Touch derive_text_index_shard so the import isn't dead in
    // case the bench grows a text-shard sub-bench later.
    let _shard_key =
        derive_text_index_shard(&search_root, b"phase8-bench-shard").expect("text shard key");
    let conv_key = KeyMaterial::from_bytes([0xB2; 32]);
    (search_root, conv_key)
}

fn synth_words(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("word{i:06}")).collect()
}

fn synth_text_rows(conv: &str, n: usize) -> Vec<FtsRow> {
    (0..n)
        .map(|i| FtsRow {
            message_id: format!("msg-{i:08}"),
            conversation_id: conv.to_string(),
            sender_id: "alice".into(),
            created_at_ms: 1_700_000_000_000 + i as i64,
            // Each row carries a unique high-entropy term that
            // the bench query can target deterministically.
            text_content: format!("lighthouse needle{i:06} beacon"),
        })
        .collect()
}

#[derive(Default)]
struct BenchColdSource {
    text: HashMap<(String, String), Vec<FtsRow>>,
    fuzzy: HashMap<(String, String), Vec<FuzzyRow>>,
    bloom: HashMap<(String, String), BloomFilter>,
}

impl BenchColdSource {
    fn with_text(mut self, conv: &str, bucket: &str, rows: Vec<FtsRow>) -> Self {
        self.text.insert((conv.into(), bucket.into()), rows);
        self
    }
    fn with_bloom(mut self, conv: &str, bucket: &str, filter: BloomFilter) -> Self {
        self.bloom.insert((conv.into(), bucket.into()), filter);
        self
    }
}

impl ColdShardSource for BenchColdSource {
    fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
        Ok(self.text.keys().cloned().collect())
    }
    fn fetch_text_rows(&self, c: &str, b: &str) -> Result<Vec<FtsRow>, Error> {
        Ok(self
            .text
            .get(&(c.to_string(), b.to_string()))
            .cloned()
            .unwrap_or_default())
    }
    fn fetch_fuzzy_rows(&self, c: &str, b: &str) -> Result<Vec<FuzzyRow>, Error> {
        Ok(self
            .fuzzy
            .get(&(c.to_string(), b.to_string()))
            .cloned()
            .unwrap_or_default())
    }
    fn fetch_bloom_shard(&self, c: &str, b: &str) -> Result<Option<BloomFilter>, Error> {
        Ok(self.bloom.get(&(c.to_string(), b.to_string())).cloned())
    }
}

fn local_db() -> LocalStoreDb {
    LocalStoreDb::open_in_memory(&[0xCC; 32]).unwrap()
}

fn seed_conversations(db: &LocalStoreDb, n: usize, community: &str) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let id = Uuid::now_v7();
        db.insert_conversation(&Conversation {
            conversation_id: id.to_string(),
            community_id: community.into(),
            domain_id: String::new(),
            tenant_id: String::new(),
            scope: "b2c".into(),
            ..Default::default()
        })
        .unwrap();
        out.push(id);
    }
    out
}

// ---------------------------------------------------------------------------
// 1. bloom_precheck_one_month_bucket
// ---------------------------------------------------------------------------

fn bench_bloom_precheck_one_month_bucket(c: &mut Criterion) {
    // Build a bloom filter sized for ~1000 distinct words —
    // representative of a one-month bucket per Phase 5.
    let words = synth_words(1_000);
    let filter = BloomFilter::from_words(&words, words.len());
    let queries: Vec<String> = (0..10).map(|i| format!("queryterm{i:04}")).collect();
    c.bench_function("bloom_precheck_one_month_bucket", |b| {
        b.iter(|| {
            let mut hits = 0u32;
            for q in &queries {
                if black_box(filter.maybe_contains(q)) {
                    hits += 1;
                }
            }
            black_box(hits);
        });
    });
}

// ---------------------------------------------------------------------------
// 2. shard_cache_hit_vs_miss
// ---------------------------------------------------------------------------

fn bench_shard_cache_hit_vs_miss(c: &mut Criterion) {
    let conv = Uuid::now_v7().to_string();
    let bucket = "2026-04";
    let rows = synth_text_rows(&conv, 200);
    let key = ShardCacheKey::new(&conv, bucket, IndexType::Text);

    let mut cache = ShardCache::new(8 * 1024 * 1024);
    cache.put(key.clone(), CachedShard::Text(rows.clone()));
    let cache = Mutex::new(cache);

    let mut group = c.benchmark_group("shard_cache_hit_vs_miss");
    group.bench_function("hit", |b| {
        b.iter(|| {
            let mut g = cache.lock().unwrap();
            let _ = black_box(g.get(&key));
        });
    });
    group.bench_function("miss_via_clone", |b| {
        // The "miss" path's dominating cost in production is
        // decryption + Vec<FtsRow> reconstruction. We
        // approximate that here with a fresh row vector clone,
        // which is cheap relative to a real decrypt but still
        // noticeably above the cache-hit latency.
        b.iter_batched(
            || rows.clone(),
            |fresh_rows| {
                let _ = black_box(fresh_rows.len());
                black_box(fresh_rows);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// 3. scope_resolver_community_100_conversations
// ---------------------------------------------------------------------------

fn bench_scope_resolver_community_100_conversations(c: &mut Criterion) {
    let db = local_db();
    let community = Uuid::now_v7();
    let _convs = seed_conversations(&db, 100, &community.to_string());
    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let q = SearchQuery {
        query_string: String::new(),
        target: SearchTarget::Community(community),
        ..Default::default()
    };
    c.bench_function("scope_resolver_community_100_conversations", |b| {
        b.iter(|| {
            let r = engine
                .execute_search(&q, &SearchScope::LocalOnly)
                .expect("search");
            black_box(r.len());
        });
    });
}

// ---------------------------------------------------------------------------
// 4. date_pruning_100_buckets
// ---------------------------------------------------------------------------

fn bench_date_pruning_100_buckets(c: &mut Criterion) {
    // 100 monthly buckets spanning ~8 years.
    let mut buckets = Vec::with_capacity(100);
    for i in 0..100 {
        let year = 2018 + (i / 12);
        let month = (i % 12) + 1;
        buckets.push(format!("{year}-{month:02}"));
    }
    // Window covers exactly 12 months in the middle — so half
    // the buckets pass and half are pruned.
    let from_ms = days_from_civil(2022, 1, 1) * 86_400_000;
    let to_ms = days_from_civil(2022, 12, 31) * 86_400_000;
    c.bench_function("date_pruning_100_buckets", |b| {
        b.iter(|| {
            let mut kept = 0u32;
            for bucket in &buckets {
                if black_box(bucket_overlaps_date_range(
                    bucket,
                    Some(from_ms),
                    Some(to_ms),
                )) {
                    kept += 1;
                }
            }
            black_box(kept);
        });
    });
}

// Shared with `bucket_overlaps_date_range`'s implementation —
// avoids a chrono dependency in benches.
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u32;
    let m = m as i32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = ((153 * mp + 2) as u32) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146_097 + doe as i64 - 719_468
}

// ---------------------------------------------------------------------------
// 5. global_search_with_bloom_10_buckets
// ---------------------------------------------------------------------------

fn bench_global_search_with_bloom_10_buckets(c: &mut Criterion) {
    let (_search_root, conv_key) = fresh_keys();
    let conv = Uuid::now_v7().to_string();
    let mut source = BenchColdSource::default();

    let search_root =
        derive_search_root(&KeyMaterial::from_bytes([0xA1; 32])).expect("search root");

    // 10 cold buckets, only one of which contains the needle.
    let needle_bucket = "2026-04";
    for i in 1..=10 {
        let bucket = format!("2026-{i:02}");
        let shard_id = format!("bench-bloom-{bucket}");
        let bloom_key =
            derive_bloom_index_shard(&search_root, shard_id.as_bytes()).expect("bloom key");
        if bucket == needle_bucket {
            source = source.with_text(&conv, &bucket, synth_text_rows(&conv, 200));
            // Bloom filter advertises the needle word.
            let words: Vec<String> = synth_words(64)
                .into_iter()
                .chain(["lighthouse".to_string()])
                .collect();
            let built = build_bloom_shard(words, 128, &conv, bucket.clone(), &bloom_key, &conv_key)
                .expect("build bloom");
            let restored = restore_bloom_shard(&built.shard, &built.k_shard).expect("restore");
            source = source.with_bloom(&conv, &bucket, restored);
        } else {
            // Other buckets carry rows that don't mention
            // "lighthouse" but expose a bloom filter that
            // doesn't include it either — bloom precheck will
            // skip them.
            source = source.with_text(&conv, &bucket, synth_text_rows(&conv, 32));
            let words = synth_words(64);
            let built = build_bloom_shard(words, 128, &conv, bucket.clone(), &bloom_key, &conv_key)
                .expect("build bloom");
            let restored = restore_bloom_shard(&built.shard, &built.k_shard).expect("restore");
            source = source.with_bloom(&conv, &bucket, restored);
        }
    }

    let db = local_db();
    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let q = SearchQuery {
        query_string: "lighthouse".into(),
        target: SearchTarget::Global,
        ..Default::default()
    };

    c.bench_function("global_search_with_bloom_10_buckets", |b| {
        b.iter(|| {
            let r = engine
                .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &source)
                .expect("search");
            black_box(r.len());
        });
    });
}

criterion_group!(
    benches,
    bench_bloom_precheck_one_month_bucket,
    bench_shard_cache_hit_vs_miss,
    bench_scope_resolver_community_100_conversations,
    bench_date_pruning_100_buckets,
    bench_global_search_with_bloom_10_buckets,
);
criterion_main!(benches);
