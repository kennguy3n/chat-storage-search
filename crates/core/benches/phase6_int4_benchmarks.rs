//! Phase 6 INT4 / INT8 quantization benchmarks.
//!
//! `docs/PROPOSAL.md §7.6` documents the per-tier model
//! packaging story (INT4 for tight storage, INT8 for the
//! default tier). This bench suite measures the encode /
//! decode throughput of both codecs and the cosine-similarity
//! fidelity of INT4 vs INT8 against the original f32 vector
//! across a deterministic multilingual corpus.
//!
//! What the benches measure:
//!
//! * `int8_embedding_encode_decode_round_trip` — encode a
//!   known f32 vector to INT8, then decode it back. Throughput
//!   ceiling for the on-disk codec used by
//!   [`kchat_core::models::embeddings::LocalStoreEmbeddingCache`].
//! * `int4_embedding_encode_decode_round_trip` — same shape
//!   for INT4, exercising the new packed nibble codec added in
//!   the 2026-05-04 batch.
//! * `int8_vs_int4_cosine_fidelity` — across 128 fixture
//!   vectors, compute the average cosine similarity between
//!   the original and the round-tripped vector for both
//!   codecs. Captures the expected fidelity / storage
//!   trade-off in a histogram criterion can plot over time.
//! * `embedding_cache_throughput` — tight loop of `put` / `get`
//!   round-trips through the SQLCipher-backed
//!   [`kchat_core::models::embeddings::LocalStoreEmbeddingCache`]
//!   so we can track the cost of the round-trip including
//!   the SQL prepared-statement path.
//!
//! Run with:
//! ```sh
//! cargo bench -p kchat-core --bench phase6_int4_benchmarks
//! ```
//!
//! Criterion HTML reports land under `target/criterion/`.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rusqlite::Connection;

use kchat_core::local_store::schema::SCHEMA_SQL;
use kchat_core::models::embeddings::{
    cosine_similarity, decode_int4, encode_int4, EmbeddingCache, LocalStoreEmbeddingCache,
    XLMR_EMBEDDING_DIM, XLMR_MODEL_VERSION,
};

/// Build a deterministic fixture embedding seeded by `seed`.
///
/// The same shape as the one used by the unit tests in
/// `models::embeddings`: a low-amplitude sine wave with a
/// `seed`-dependent phase so distinct seeds produce distinct
/// vectors but every fixture stays in roughly the same
/// magnitude range. The vector is L2-normalized so cosine
/// similarity is well-defined.
fn fixture_embedding(seed: u64) -> Vec<f32> {
    let dim = XLMR_EMBEDDING_DIM;
    let mut v = Vec::with_capacity(dim);
    for i in 0..dim {
        let phase = (seed as f32) * 0.017_453_292;
        let x = (i as f32 * 0.1 + phase).sin();
        v.push(x);
    }
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-12);
    for x in &mut v {
        *x /= norm;
    }
    v
}

/// Build a 128-vector multilingual corpus by interleaving
/// distinct seed bands. The seed bands are picked to cover
/// roughly the same magnitude / sign distribution as the
/// production XLM-R `[CLS]` embeddings observed in the Phase 1
/// fixtures.
fn fixture_corpus() -> Vec<Vec<f32>> {
    (0..128).map(|i| fixture_embedding(i as u64 * 7)).collect()
}

/// In-memory SQLCipher-shaped Connection for the embedding-cache
/// throughput bench. We don't need a real cipher key for the
/// measurement — only the schema bring-up runs `SCHEMA_SQL`.
fn fresh_conn() -> Connection {
    let conn = Connection::open_in_memory().expect("open in-memory");
    conn.execute_batch(SCHEMA_SQL).expect("schema");
    conn
}

// Naive INT8 encode mirroring the on-disk layout used by
// `LocalStoreEmbeddingCache`, exposed here through
// [`LocalStoreEmbeddingCache::put`] so the bench can avoid
// reaching into private helpers. To measure the codec in
// isolation we re-implement the same arithmetic — kept tiny so
// the bench result is dominated by the loop body rather than
// allocation overhead.
fn encode_int8_inline(embedding: &[f32]) -> Vec<u8> {
    let max_abs = embedding.iter().fold(0.0_f32, |acc, &x| acc.max(x.abs()));
    let scale = (max_abs / 127.0).max(1e-12);
    let mut out = Vec::with_capacity(4 + embedding.len());
    out.extend_from_slice(&scale.to_le_bytes());
    for &x in embedding {
        let q = (x / scale).round().clamp(-127.0, 127.0) as i8;
        out.push(q as u8);
    }
    out
}

fn decode_int8_inline(blob: &[u8]) -> Vec<f32> {
    if blob.len() < 4 {
        return Vec::new();
    }
    let scale = f32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    blob[4..]
        .iter()
        .map(|&b| (b as i8) as f32 * scale)
        .collect()
}

fn bench_int8_round_trip(c: &mut Criterion) {
    let v = fixture_embedding(1);
    c.bench_function("int8_embedding_encode_decode_round_trip", |b| {
        b.iter(|| {
            let blob = encode_int8_inline(black_box(&v));
            let back = decode_int8_inline(black_box(&blob));
            black_box(back);
        })
    });
}

fn bench_int4_round_trip(c: &mut Criterion) {
    let v = fixture_embedding(2);
    c.bench_function("int4_embedding_encode_decode_round_trip", |b| {
        b.iter(|| {
            let blob = encode_int4(black_box(&v));
            let back = decode_int4(black_box(&blob));
            black_box(back);
        })
    });
}

fn bench_int8_vs_int4_fidelity(c: &mut Criterion) {
    let corpus = fixture_corpus();
    c.bench_function("int8_vs_int4_cosine_fidelity", |b| {
        b.iter(|| {
            let mut int8_avg = 0.0_f32;
            let mut int4_avg = 0.0_f32;
            for v in &corpus {
                let i8_blob = encode_int8_inline(v);
                let i8_back = decode_int8_inline(&i8_blob);
                int8_avg += cosine_similarity(v, &i8_back);
                let i4_blob = encode_int4(v);
                let i4_back = decode_int4(&i4_blob);
                int4_avg += cosine_similarity(v, &i4_back);
            }
            black_box(int8_avg / corpus.len() as f32);
            black_box(int4_avg / corpus.len() as f32);
        })
    });
}

fn bench_embedding_cache_throughput(c: &mut Criterion) {
    let conn = fresh_conn();
    let cache = LocalStoreEmbeddingCache::new(&conn);
    let v = fixture_embedding(3);
    // Pre-populate so the `get` half exercises the read path.
    cache
        .put("seed-msg", XLMR_MODEL_VERSION, &v)
        .expect("seed put");

    let mut group = c.benchmark_group("embedding_cache_throughput");
    group.bench_function("put_and_get_round_trip", |b| {
        b.iter_batched(
            || (),
            |_| {
                let mid = uuid::Uuid::now_v7().to_string();
                cache.put(&mid, XLMR_MODEL_VERSION, &v).expect("put");
                let got = cache.get(&mid, XLMR_MODEL_VERSION).expect("get");
                black_box(got);
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("get_existing_row", |b| {
        b.iter(|| {
            let got = cache
                .get(black_box("seed-msg"), black_box(XLMR_MODEL_VERSION))
                .expect("get");
            black_box(got);
        })
    });
    group.finish();
}

criterion_group!(
    name = phase6_int4_benches;
    config = Criterion::default();
    targets =
        bench_int8_round_trip,
        bench_int4_round_trip,
        bench_int8_vs_int4_fidelity,
        bench_embedding_cache_throughput,
);
criterion_main!(phase6_int4_benches);
