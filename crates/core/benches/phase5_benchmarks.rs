//! cold-shard latency benchmarks.
//!
//! The decision gate: "Search across
//! offloaded shards within ≤ 1.5 s p95 over Wi-Fi for a one-month
//! bucket". This bench suite exercises the production seal /
//! open / search path end-to-end so the criterion histograms can
//! be diffed against the budget.
//!
//! What the benches measure:
//!
//! * `shard_decrypt_and_search` — given a pre-built encrypted
//!   text shard for a one-month bucket (~1 000 messages), measure
//!   the time to decrypt the shard, hand the rows to the cold
//!   path, and run a single FTS-style word query.
//! * `fuzzy_shard_decrypt_and_search` — same shape but for the
//!   fuzzy n-gram shard (script-aware bigram / trigram index).
//! * `combined_local_plus_cold_search` — local FTS + 1 cold
//!   shard fetch (with a small simulated transport delay) +
//!   decrypt + merge through
//!   [`QueryEngine::execute_search_with_cold_source`].
//!
//! Run with:
//! ```sh
//! cargo bench -p kchat-core --features test-support --bench phase5_benchmarks
//! ```
//!
//! Criterion HTML reports land under `target/criterion/`.

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use uuid::Uuid;

use kchat_core::crypto::key_hierarchy::{derive_search_root, derive_text_index_shard, KeyMaterial};
use kchat_core::formats::search_shard::SearchIndexShard;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::search::fuzzy_search::FuzzyTokenizer;
use kchat_core::search::query_engine::{ColdShardSource, QueryEngine};
use kchat_core::search::shard_builder::{
    build_fuzzy_search_shard, build_text_search_shard, restore_fuzzy_search_shard,
    restore_text_search_shard, FtsRow, FuzzyRow,
};
use kchat_core::{Error, SearchQuery, SearchScope};

const BENCH_KEY: [u8; 32] = [0x55; 32];
const BUCKET: &str = "2026-04";
const NEEDLE: &str = "lighthouse";
/// One month's worth of messages — matches the budget
/// "one-month bucket" quoted in ``.
const SHARD_ROWS: usize = 1_000;
/// Simulated round-trip transport latency for the
/// "combined local + cold" path. Treat as p50 Wi-Fi.
const SIMULATED_TRANSPORT_MS: u64 = 50;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn fresh_db() -> LocalStoreDb {
    LocalStoreDb::open_in_memory(&BENCH_KEY).expect("open in-memory db")
}

fn seed_conversation(db: &LocalStoreDb, conv_id: Uuid) {
    db.insert_conversation(&Conversation {
        conversation_id: conv_id.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms: 1,
        ..Default::default()
    })
    .unwrap();
}

fn make_message(conv: Uuid, idx: usize, text: &str) -> IngestedMessage {
    IngestedMessage {
        message_id: Uuid::now_v7(),
        conversation_id: conv,
        sender_id: format!("user-{}", idx % 5),
        created_at_ms: 1_700_000_000_000 + idx as i64,
        text_content: Some(text.into()),
        media_descriptors: vec![],
        reply_to: None,
    }
}

/// One-month corpus reused across the benches. Roughly ~1 % of
/// rows contain the needle term so the FTS / fuzzy engines have
/// something to surface.
fn one_month_corpus() -> Vec<(String, String, i64, String)> {
    (0..SHARD_ROWS)
        .map(|i| {
            let mid = Uuid::now_v7().to_string();
            let sender = format!("user-{}", i % 5);
            let ts = 1_700_000_000_000 + i as i64;
            let text = if i % (SHARD_ROWS / 10) == 0 {
                format!("{NEEDLE} keepers gathered at dusk near the harbor (#{i})")
            } else {
                format!("standard chatter about coffee, work, and weekends (#{i})")
            };
            (mid, sender, ts, text)
        })
        .collect()
}

fn build_text_shard(
    rows: &[(String, String, i64, String)],
    conv_id: &str,
    k_shard: &KeyMaterial,
    conv_hash_key: &KeyMaterial,
) -> SearchIndexShard {
    let fts_rows: Vec<FtsRow> = rows
        .iter()
        .map(|(mid, sender, ts, text)| FtsRow {
            message_id: mid.clone(),
            conversation_id: conv_id.to_string(),
            sender_id: sender.clone(),
            created_at_ms: *ts,
            text_content: text.clone(),
        })
        .collect();
    build_text_search_shard(fts_rows, conv_id, BUCKET, k_shard, conv_hash_key)
        .unwrap()
        .shard
}

fn build_fuzzy_shard(
    rows: &[(String, String, i64, String)],
    conv_id: &str,
    k_shard: &KeyMaterial,
    conv_hash_key: &KeyMaterial,
) -> SearchIndexShard {
    let mut fuzzy_rows: Vec<FuzzyRow> = Vec::new();
    for (mid, _sender, _ts, text) in rows {
        for tok in FuzzyTokenizer::generate_tokens(text) {
            fuzzy_rows.push(FuzzyRow {
                token: tok.token,
                script: tok.script.to_iso_15924().to_string(),
                message_id: mid.clone(),
            });
        }
    }
    build_fuzzy_search_shard(fuzzy_rows, conv_id, BUCKET, k_shard, conv_hash_key)
        .unwrap()
        .shard
}

/// Cold-shard catalog with a configurable per-fetch delay so the
/// "combined" bench can model real transport latency.
struct DelayedCatalog {
    text_blobs: HashMap<(String, String), (SearchIndexShard, KeyMaterial)>,
    fuzzy_blobs: HashMap<(String, String), (SearchIndexShard, KeyMaterial)>,
    delay: Duration,
}

impl DelayedCatalog {
    fn new(delay: Duration) -> Self {
        Self {
            text_blobs: HashMap::new(),
            fuzzy_blobs: HashMap::new(),
            delay,
        }
    }
}

impl ColdShardSource for DelayedCatalog {
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
        if self.delay > Duration::ZERO {
            thread::sleep(self.delay);
        }
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
        if self.delay > Duration::ZERO {
            thread::sleep(self.delay);
        }
        let key = (conversation_id.to_string(), time_bucket.to_string());
        let Some((shard, k)) = self.fuzzy_blobs.get(&key) else {
            return Ok(Vec::new());
        };
        restore_fuzzy_search_shard(shard, k)
    }
}

// ---------------------------------------------------------------------------
// shard_decrypt_and_search — text only
// ---------------------------------------------------------------------------

fn bench_shard_decrypt_and_search(c: &mut Criterion) {
    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_id = Uuid::now_v7().to_string();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);
    let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();

    let corpus = one_month_corpus();
    let text_shard = build_text_shard(&corpus, &conv_id, &k_text, &conv_hash_key);

    let mut catalog = DelayedCatalog::new(Duration::ZERO);
    catalog
        .text_blobs
        .insert((conv_id.clone(), BUCKET.to_string()), (text_shard, k_text));

    let db = fresh_db();

    let mut group = c.benchmark_group("phase5_shard_decrypt_and_search");
    group.sample_size(20);
    group.bench_function("text_only_one_month", |b| {
        b.iter(|| {
            let engine = QueryEngine::new(db.connection(), db.icu_available());
            let q = SearchQuery {
                query_string: NEEDLE.into(),
                ..Default::default()
            };
            let hits = engine
                .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
                .unwrap();
            black_box(hits);
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// fuzzy_shard_decrypt_and_search — fuzzy only
// ---------------------------------------------------------------------------

fn bench_fuzzy_shard_decrypt_and_search(c: &mut Criterion) {
    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_id = Uuid::now_v7().to_string();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);
    let k_fuzzy = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();

    let corpus = one_month_corpus();
    let fuzzy_shard = build_fuzzy_shard(&corpus, &conv_id, &k_fuzzy, &conv_hash_key);

    let mut catalog = DelayedCatalog::new(Duration::ZERO);
    catalog.fuzzy_blobs.insert(
        (conv_id.clone(), BUCKET.to_string()),
        (fuzzy_shard, k_fuzzy),
    );

    let db = fresh_db();

    let mut group = c.benchmark_group("phase5_fuzzy_shard_decrypt_and_search");
    group.sample_size(20);
    group.bench_function("fuzzy_only_one_month", |b| {
        b.iter(|| {
            let engine = QueryEngine::new(db.connection(), db.icu_available());
            // Use a typo to exercise the fuzzy path explicitly.
            let q = SearchQuery {
                query_string: "lighthose".into(),
                ..Default::default()
            };
            let hits = engine
                .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
                .unwrap();
            black_box(hits);
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// combined_local_plus_cold_search — local FTS + simulated cold fetch
// ---------------------------------------------------------------------------

fn bench_combined_local_plus_cold_search(c: &mut Criterion) {
    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_id = Uuid::now_v7();
    let conv_id_str = conv_id.to_string();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);
    let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();
    let k_fuzzy = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();

    let corpus = one_month_corpus();
    let text_shard = build_text_shard(&corpus, &conv_id_str, &k_text, &conv_hash_key);
    let fuzzy_shard = build_fuzzy_shard(&corpus, &conv_id_str, &k_fuzzy, &conv_hash_key);

    let mut catalog = DelayedCatalog::new(Duration::from_millis(SIMULATED_TRANSPORT_MS));
    catalog.text_blobs.insert(
        (conv_id_str.clone(), BUCKET.to_string()),
        (text_shard, k_text),
    );
    catalog.fuzzy_blobs.insert(
        (conv_id_str.clone(), BUCKET.to_string()),
        (fuzzy_shard, k_fuzzy),
    );

    // Local hot rows: fresh DB with 200 messages, ~10 % needles.
    let local_db = fresh_db();
    seed_conversation(&local_db, conv_id);
    let persister = MessagePersister::new(&local_db);
    for i in 0..200 {
        let text = if i % 10 == 0 {
            format!("{NEEDLE} on the local side (#{i})")
        } else {
            format!("local chatter (#{i})")
        };
        persister
            .persist_ingested_message(&make_message(conv_id, i, &text))
            .unwrap();
    }

    let mut group = c.benchmark_group("phase5_combined_local_plus_cold_search");
    group.sample_size(10);
    group.bench_function("local_plus_one_cold_bucket", |b| {
        b.iter_batched(
            || (),
            |_| {
                let engine = QueryEngine::new(local_db.connection(), local_db.icu_available());
                let q = SearchQuery {
                    query_string: NEEDLE.into(),
                    ..Default::default()
                };
                let hits = engine
                    .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
                    .unwrap();
                black_box(hits);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// phase5_p95_multilingual — text shard across CJK / Arabic /
// Cyrillic / Latin corpora.
//
// device-matrix p95
// gate. The bench is sized so each subgroup (`bench_function`)
// produces an independent histogram, which lets a per-script p95
// regression be diffed against the
// [`kchat_core::config::DeviceMatrixConfig`] budget without
// rebuilding the corpus across iterations.
// ---------------------------------------------------------------------------
fn phase5_p95_multilingual(c: &mut Criterion) {
    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);

    let scripts: [(&str, &[&str]); 4] = [
        ("latin", &["coffee shop near the lighthouse harbor"]),
        ("cjk", &["上海港口的灯塔附近的咖啡店"]),
        ("arabic", &["مقهى بالقرب من ميناء المنارة"]),
        ("cyrillic", &["Кофейня рядом с маяком в гавани"]),
    ];

    let mut group = c.benchmark_group("phase5_p95_multilingual");
    group.sample_size(20);

    for (label, sentences) in scripts.iter() {
        let conv_id = Uuid::now_v7().to_string();
        let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();

        // Build a 1k-row corpus using the script-specific sentence.
        let corpus: Vec<(String, String, i64, String)> = (0..SHARD_ROWS)
            .map(|i| {
                let mid = Uuid::now_v7().to_string();
                let sender = format!("user-{}", i % 5);
                let ts = 1_700_000_000_000 + i as i64;
                let s = sentences[i % sentences.len()];
                let text = format!("{s} (#{i})");
                (mid, sender, ts, text)
            })
            .collect();

        let text_shard = build_text_shard(&corpus, &conv_id, &k_text, &conv_hash_key);
        let mut catalog = DelayedCatalog::new(Duration::ZERO);
        catalog
            .text_blobs
            .insert((conv_id.clone(), BUCKET.to_string()), (text_shard, k_text));

        // Pull a query token from the seed sentence so the
        // FTS5 path actually finds rows.
        let needle: String = sentences[0]
            .split_whitespace()
            .next()
            .unwrap_or(NEEDLE)
            .to_string();

        let db = fresh_db();
        group.bench_function(*label, |b| {
            b.iter(|| {
                let engine = QueryEngine::new(db.connection(), db.icu_available());
                let q = SearchQuery {
                    query_string: needle.clone(),
                    ..Default::default()
                };
                let hits = engine
                    .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
                    .unwrap();
                black_box(hits);
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// phase5_p95_large_bucket — 5000-message bucket stress.
// ---------------------------------------------------------------------------
fn phase5_p95_large_bucket(c: &mut Criterion) {
    const LARGE_ROWS: usize = 5_000;
    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_id = Uuid::now_v7().to_string();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);
    let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();

    // 5k row corpus, ~1% rows carry the needle.
    let corpus: Vec<(String, String, i64, String)> = (0..LARGE_ROWS)
        .map(|i| {
            let mid = Uuid::now_v7().to_string();
            let sender = format!("user-{}", i % 5);
            let ts = 1_700_000_000_000 + i as i64;
            let text = if i % (LARGE_ROWS / 10) == 0 {
                format!("{NEEDLE} keepers gathered at dusk near the harbor (#{i})")
            } else {
                format!("standard chatter about coffee, work, and weekends (#{i})")
            };
            (mid, sender, ts, text)
        })
        .collect();
    let text_shard = build_text_shard(&corpus, &conv_id, &k_text, &conv_hash_key);
    let mut catalog = DelayedCatalog::new(Duration::ZERO);
    catalog
        .text_blobs
        .insert((conv_id.clone(), BUCKET.to_string()), (text_shard, k_text));

    let db = fresh_db();
    let mut group = c.benchmark_group("phase5_p95_large_bucket");
    group.sample_size(10);
    group.bench_function("text_only_5k", |b| {
        b.iter(|| {
            let engine = QueryEngine::new(db.connection(), db.icu_available());
            let q = SearchQuery {
                query_string: NEEDLE.into(),
                ..Default::default()
            };
            let hits = engine
                .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
                .unwrap();
            black_box(hits);
        });
    });
    group.finish();
}

criterion_group!(
    name = phase5_benches;
    config = Criterion::default();
    targets =
        bench_shard_decrypt_and_search,
        bench_fuzzy_shard_decrypt_and_search,
        bench_combined_local_plus_cold_search,
        phase5_p95_multilingual,
        phase5_p95_large_bucket,
);
criterion_main!(phase5_benches);
