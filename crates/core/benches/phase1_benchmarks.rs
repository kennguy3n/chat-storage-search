//! Phase-1 performance benchmarks for the local store + search.
//!
//! `docs/PROPOSAL.md §13` lists the latency budgets for the Phase-1
//! local-store hot paths. The targets relevant to this benchmark
//! suite are:
//!
//! * **Insert (single text message)** — < 20 ms p95.
//! * **Search (recent messages, 1k-row corpus)** — < 150 ms p95.
//!
//! Run with:
//! ```sh
//! cargo bench -p kchat-core --features test-support --bench phase1_benchmarks
//! ```
//!
//! Criterion's HTML reports land under `target/criterion/`.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use uuid::Uuid;

use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::search::query_engine::QueryEngine;
use kchat_core::{ContentKind, SearchQuery, SearchScope};

const BENCH_KEY: [u8; 32] = [0x42; 32];

fn fresh_db() -> LocalStoreDb {
    LocalStoreDb::open_in_memory(&BENCH_KEY).expect("open in-memory db")
}

fn seed_conversation(db: &LocalStoreDb, conv_id: &Uuid) {
    let conv = Conversation {
        conversation_id: conv_id.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms: 1,
        ..Default::default()
    };
    db.insert_conversation(&conv).unwrap();
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

// ---------------------------------------------------------------------------
// insert_text_message — single insert latency
// ---------------------------------------------------------------------------

fn bench_insert_text_message(c: &mut Criterion) {
    c.bench_function("insert_text_message", |b| {
        b.iter_batched(
            || {
                let db = fresh_db();
                let conv = Uuid::now_v7();
                seed_conversation(&db, &conv);
                (db, conv)
            },
            |(db, conv)| {
                let persister = MessagePersister::new(&db);
                let msg = make_message(conv, 0, "hello world from the benchmark suite");
                persister.persist_ingested_message(&msg).unwrap();
                black_box(());
            },
            BatchSize::SmallInput,
        );
    });
}

// ---------------------------------------------------------------------------
// insert_batch_100 — throughput of 100 sequential inserts
// ---------------------------------------------------------------------------

fn bench_insert_batch_100(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert_batch_100");
    group.sample_size(20);
    group.bench_function("100_text_messages", |b| {
        b.iter_batched(
            || {
                let db = fresh_db();
                let conv = Uuid::now_v7();
                seed_conversation(&db, &conv);
                (db, conv)
            },
            |(db, conv)| {
                let persister = MessagePersister::new(&db);
                for i in 0..100 {
                    let msg = make_message(conv, i, "the quick brown fox jumps over the lazy dog");
                    persister.persist_ingested_message(&msg).unwrap();
                }
                black_box(());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Shared "1k corpus, 5 conversations, ~10 needles" fixture
// ---------------------------------------------------------------------------

const CORPUS_SIZE: usize = 1000;
const NEEDLE_COUNT: usize = 10;
const NEEDLE_TERM: &str = "lighthouse";

fn build_corpus() -> (LocalStoreDb, Vec<Uuid>) {
    let db = fresh_db();
    let conv_ids: Vec<Uuid> = (0..5).map(|_| Uuid::now_v7()).collect();
    for cid in &conv_ids {
        seed_conversation(&db, cid);
    }
    let persister = MessagePersister::new(&db);
    for i in 0..CORPUS_SIZE {
        let conv = conv_ids[i % conv_ids.len()];
        let text = if i % (CORPUS_SIZE / NEEDLE_COUNT) == 0 {
            // ~10 messages contain the needle term.
            format!("{NEEDLE_TERM} keepers gathered at dusk near the harbor (#{i})")
        } else {
            format!("standard chatter about coffee, work, and weekends (#{i})")
        };
        let msg = make_message(conv, i, &text);
        persister.persist_ingested_message(&msg).unwrap();
    }
    (db, conv_ids)
}

// ---------------------------------------------------------------------------
// search_recent_messages — FTS5 search over a 1k-row corpus
// ---------------------------------------------------------------------------

fn bench_search_recent_messages(c: &mut Criterion) {
    let (db, _conv_ids) = build_corpus();
    c.bench_function("search_recent_messages", |b| {
        b.iter(|| {
            let engine = QueryEngine::new(&db);
            let q = SearchQuery {
                query_string: NEEDLE_TERM.to_string(),
                ..SearchQuery::default()
            };
            let hits = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
            black_box(hits);
        });
    });
}

// ---------------------------------------------------------------------------
// search_with_structured_filters — sender + date-range narrowing
// ---------------------------------------------------------------------------

fn bench_search_with_structured_filters(c: &mut Criterion) {
    let (db, conv_ids) = build_corpus();
    c.bench_function("search_with_structured_filters", |b| {
        b.iter(|| {
            let engine = QueryEngine::new(&db);
            let q = SearchQuery {
                query_string: NEEDLE_TERM.to_string(),
                sender_filter: Some("user-0".to_string()),
                conversation_filter: Some(conv_ids[0]),
                date_from: Some(1_700_000_000_000),
                date_to: Some(1_700_000_002_000),
                content_kind: Some(ContentKind::Text),
                target: Default::default(),
            };
            let hits = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
            black_box(hits);
        });
    });
}

// ---------------------------------------------------------------------------
// fts_prefix_search — trailing-`*` prefix queries
// ---------------------------------------------------------------------------

fn bench_fts_prefix_search(c: &mut Criterion) {
    let (db, _) = build_corpus();
    c.bench_function("fts_prefix_search", |b| {
        b.iter(|| {
            let engine = QueryEngine::new(&db);
            // "light*" matches "lighthouse" and any other term that
            // starts with "light"; FTS5 handles the prefix expansion
            // natively via the trailing `*`.
            let q = SearchQuery {
                query_string: "light*".to_string(),
                ..SearchQuery::default()
            };
            let hits = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
            black_box(hits);
        });
    });
}

criterion_group!(
    name = phase1_benches;
    config = Criterion::default();
    targets =
        bench_insert_text_message,
        bench_insert_batch_100,
        bench_search_recent_messages,
        bench_search_with_structured_filters,
        bench_fts_prefix_search,
);
criterion_main!(phase1_benches);
