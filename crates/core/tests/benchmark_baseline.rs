//! Benchmark baseline for the KChat storage / search / archive /
//! backup / restore pipeline.
//!
//! This is the committed baseline that pairs with [`e2e_demo`]:
//! it runs a focused micro-benchmark sweep over the same dataset
//! shape used by the demo and writes the results to
//! `tests/benchmark_results.json` so future PRs can diff against
//! a known-good snapshot.
//!
//! The criterion suites under `crates/core/benches/` are the
//! authoritative perf gate; this file is a *baseline* run that
//! lives next to the integration tests so it can:
//!
//! * be pinned to the same dataset shape the [`e2e_demo`] uses;
//! * commit a checked-in JSON snapshot future PRs can diff
//!   against without standing up a full criterion run;
//! * surface per-step latencies in `cargo test --ignored
//!   --nocapture` output for hand inspection.
//!
//! The test is gated behind `#[ignore]` because each captured
//! metric runs at least 10 iterations and the FTS / fuzzy probes
//! inflate that to a thousand. Run with:
//!
//! ```text
//! cargo test --test benchmark_baseline -- --ignored --nocapture
//! ```
//!
//! Set `E2E_BENCHMARK_OUTPUT=/path/to/file.json` to write the
//! captured metrics to a custom path (defaults to
//! `crates/core/tests/benchmark_results.json`).
//!
//! Captured metrics:
//!
//! * `insert_text_message_us` — single-message persist latency
//!   (1 000 iterations).
//! * `fts_search_1k_us` — FTS5 search latency over a 1 000-row
//!   corpus (1 000 iterations).
//! * `fuzzy_search_1k_us` — fuzzy search latency over the same
//!   corpus (1 000 iterations).
//! * `backup_segment_build_us` — `BackupSegmentBuilder` build +
//!   seal latency over a 1 000-event payload (10 iterations).
//! * `archive_round_trip_us` — `ArchiveSegmentBuilder` build +
//!   `decrypt_segment` round-trip over a 1 000-event payload
//!   (10 iterations).
//! * `restore_pipeline_us` — `RestorePipeline::run` end-to-end
//!   latency from `ManifestVerified` to `FullRestoreComplete`
//!   over a 1 000-event payload (10 iterations).
//!
//! Each metric is reported as `{ p50, p95, p99, samples }` so a
//! single panicked outlier does not poison the snapshot.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use uuid::Uuid;

use kchat_core::archive::event_journal::{ArchiveEvent, ArchiveEventType};
use kchat_core::archive::segment_builder::{
    decrypt_segment, default_time_bucket_for_ms, ArchiveSegmentBuilder, SegmentBuildRequest,
};
use kchat_core::backup::event_journal::{BackupEvent, BackupEventType};
use kchat_core::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
use kchat_core::backup::segment_builder::{BackupSegmentBuildRequest, BackupSegmentBuilder};
use kchat_core::crypto::key_hierarchy::{
    derive_archive_root, derive_archive_segment, derive_backup_manifest, derive_backup_root,
    derive_backup_segment, KeyMaterial,
};
use kchat_core::crypto::signing::HybridSigningKey;
use kchat_core::formats::SegmentType;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::state_machines::RestoreState;
use kchat_core::message::processor::MessagePersister;
use kchat_core::restore::pipeline::RestorePipeline;
use kchat_core::restore::state_machine;
use kchat_core::search::fuzzy_search::FuzzySearchEngine;
use kchat_core::search::text_search::TextSearchEngine;

#[path = "e2e_demo_dataset.rs"]
mod dataset;

use dataset::{generate_demo_conversations, generate_demo_messages};

/// Sample size for the latency-sensitive insert / search probes.
/// 1 000 samples lets us report p99 with a healthy safety margin.
const SEARCH_ITERATIONS: usize = 1_000;
/// Sample size for the heavier pipeline probes (segment seal,
/// archive round-trip, restore). The build-and-seal call already
/// dominates the run and 10 samples is enough to compute a
/// stable p99 without inflating the test runtime past the rest
/// of the workspace.
const PIPELINE_ITERATIONS: usize = 10;
/// Corpus shape for the FTS / fuzzy probes — 1 000 messages
/// across 5 conversations matches the bench shape the criterion
/// suites use.
const CORPUS_MESSAGE_COUNT: usize = 1_000;
const CORPUS_CONVERSATION_COUNT: usize = 5;

#[test]
#[ignore = "slow: 1 000-iteration latency sweep + 10-iteration pipeline sweep. Run with --ignored."]
fn benchmark_baseline() {
    let started = Instant::now();
    let mut report = BenchmarkReport::new();

    // ---- Setup: seed a 1 000-row corpus shared by every probe.
    let db = LocalStoreDb::open_in_memory(&[0xBA; 32]).expect("open in-memory db");
    let conversations = generate_demo_conversations(CORPUS_CONVERSATION_COUNT);
    let conv_ids: Vec<Uuid> = conversations
        .iter()
        .map(|c| Uuid::parse_str(&c.conversation_id).expect("uuid"))
        .collect();
    for c in &conversations {
        db.insert_conversation(c).expect("seed conversation");
    }
    let corpus = generate_demo_messages(&conv_ids, CORPUS_MESSAGE_COUNT);
    let persister = MessagePersister::new(&db);
    for msg in &corpus {
        persister
            .persist_ingested_message(msg)
            .expect("persist corpus message");
    }

    // ---- Probe 1: single-message insert latency (1 000 iterations).
    {
        // Use a *fresh* DB so the journal cursor and
        // FTS5 segment growth do not skew successive samples.
        let probe_db = LocalStoreDb::open_in_memory(&[0xBB; 32]).expect("open insert probe db");
        for c in &conversations {
            probe_db.insert_conversation(c).expect("seed insert probe");
        }
        let probe_persister = MessagePersister::new(&probe_db);
        let mut samples = Vec::with_capacity(SEARCH_ITERATIONS);
        let probe_msgs = generate_demo_messages(&conv_ids, SEARCH_ITERATIONS);
        for msg in &probe_msgs {
            let t = Instant::now();
            probe_persister
                .persist_ingested_message(msg)
                .expect("insert probe");
            samples.push(t.elapsed());
        }
        report.add("insert_text_message_us", samples);
    }

    // ---- Probe 2: FTS search latency over 1 k corpus.
    {
        let engine = TextSearchEngine::new(db.connection(), db.icu_available());
        let mut samples = Vec::with_capacity(SEARCH_ITERATIONS);
        for _ in 0..SEARCH_ITERATIONS {
            let t = Instant::now();
            let _ = engine.search_fts("lighthouse", 50).expect("fts probe");
            samples.push(t.elapsed());
        }
        report.add("fts_search_1k_us", samples);
    }

    // ---- Probe 3: fuzzy search latency over 1 k corpus.
    {
        let engine = FuzzySearchEngine::new(db.connection());
        let mut samples = Vec::with_capacity(SEARCH_ITERATIONS);
        for _ in 0..SEARCH_ITERATIONS {
            let t = Instant::now();
            let _ = engine.search_fuzzy("lighthose", 50).expect("fuzzy probe");
            samples.push(t.elapsed());
        }
        report.add("fuzzy_search_1k_us", samples);
    }

    // ---- Probe 4: backup-segment build + seal.
    let identity = KeyMaterial::from_bytes([0xB1; 32]);
    let backup_root = derive_backup_root(&identity).expect("backup root");
    let k_seg =
        derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).expect("k_backup_seg");
    let backup_events: Vec<BackupEvent> = corpus
        .iter()
        .map(|m| BackupEvent {
            event_type: BackupEventType::MessageReceived,
            conversation_id: Some(m.conversation_id),
            message_id: Some(m.message_id),
            payload: m.text_content.clone().unwrap_or_default().into_bytes(),
            created_at_ms: m.created_at_ms,
        })
        .collect();
    {
        let mut samples = Vec::with_capacity(PIPELINE_ITERATIONS);
        for _ in 0..PIPELINE_ITERATIONS {
            let t = Instant::now();
            let _ = BackupSegmentBuilder::new()
                .build_segment(
                    BackupSegmentBuildRequest {
                        events: backup_events.clone(),
                        segment_type: SegmentType::Events,
                    },
                    &k_seg,
                )
                .expect("backup segment build probe");
            samples.push(t.elapsed());
        }
        report.add("backup_segment_build_us", samples);
    }

    // ---- Probe 5: archive segment build + decrypt round-trip.
    let archive_root = derive_archive_root(&identity).expect("archive root");
    let archive_events = synthetic_archive_events(&conv_ids, CORPUS_MESSAGE_COUNT);
    {
        let mut samples = Vec::with_capacity(PIPELINE_ITERATIONS);
        for _ in 0..PIPELINE_ITERATIONS {
            let t = Instant::now();
            let k_arc = derive_archive_segment(&archive_root, &Uuid::now_v7().into_bytes())
                .expect("k_archive_seg");
            let built = ArchiveSegmentBuilder::new()
                .build_segment(
                    SegmentBuildRequest::message_delta(
                        archive_events[0].conversation_id,
                        default_time_bucket_for_ms(archive_events[0].created_at_ms),
                        archive_events.clone(),
                    ),
                    k_arc.as_bytes(),
                )
                .expect("archive build probe");
            let _ = decrypt_segment(&built, k_arc.as_bytes()).expect("archive decrypt probe");
            samples.push(t.elapsed());
        }
        report.add("archive_round_trip_us", samples);
    }

    // ---- Probe 6: restore pipeline end-to-end.
    {
        let mut rng = OsRng;
        let signing = HybridSigningKey::generate(&mut rng);
        let k_man = derive_backup_manifest(&backup_root, b"benchmark-baseline").expect("k_man");
        let segment = BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: backup_events.clone(),
                    segment_type: SegmentType::Events,
                },
                &k_seg,
            )
            .expect("restore probe build");
        let manifest = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: std::slice::from_ref(&segment),
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-bench".into(),
                manifest_id: None,
            },
            &signing,
            &k_man,
        )
        .expect("restore probe manifest");
        let now_ms = backup_events
            .iter()
            .map(|e| e.created_at_ms)
            .max()
            .unwrap_or_default();
        let chain = vec![manifest.manifest.clone()];

        let mut samples = Vec::with_capacity(PIPELINE_ITERATIONS);
        for _ in 0..PIPELINE_ITERATIONS {
            // Each probe needs its own DB — `RestorePipeline::run`
            // mutates the persisted restore-state row.
            let probe_db =
                LocalStoreDb::open_in_memory(&[0x77; 32]).expect("open restore probe db");
            for st in [
                RestoreState::IdentityRestored,
                RestoreState::RootKeysUnwrapped,
                RestoreState::ManifestVerified,
            ] {
                state_machine::transition(probe_db.connection(), st, None).expect("walk states");
            }
            let t = Instant::now();
            let _ = RestorePipeline::new()
                .run(
                    probe_db.connection(),
                    &chain,
                    std::slice::from_ref(&segment),
                    &k_seg,
                    now_ms,
                    100 * 86_400 * 1_000,
                )
                .expect("restore probe");
            samples.push(t.elapsed());
        }
        report.add("restore_pipeline_us", samples);
    }

    // ---- Emit JSON.
    let json = report.to_json();
    println!("\n=== Benchmark Baseline ===\n{json}\n");
    let output_path = match std::env::var("E2E_BENCHMARK_OUTPUT") {
        Ok(p) => PathBuf::from(p),
        Err(_) => default_output_path(),
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("create benchmark output dir");
    }
    fs::write(&output_path, &json).expect("write benchmark output");
    println!(
        "Wrote benchmark baseline to {} (total runtime: {} ms)",
        output_path.display(),
        started.elapsed().as_millis(),
    );
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

fn synthetic_archive_events(conversations: &[Uuid], count: usize) -> Vec<ArchiveEvent> {
    (0..count)
        .map(|i| ArchiveEvent {
            event_type: ArchiveEventType::MessageReceived,
            conversation_id: conversations[i % conversations.len()],
            message_id: Some(Uuid::now_v7()),
            payload: format!("benchmark-event-{i}").into_bytes(),
            created_at_ms: 1_777_000_000_000 + i as i64 * 1_000,
        })
        .collect()
}

fn default_output_path() -> PathBuf {
    // crates/core/tests/benchmark_results.json — committed to the
    // repo as the durable baseline snapshot.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("benchmark_results.json")
}

fn percentile(samples: &mut [Duration], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort();
    let idx = ((samples.len() as f64) * p).clamp(0.0, samples.len() as f64 - 1.0) as usize;
    samples[idx].as_micros() as u64
}

#[derive(Debug, Default)]
struct MetricStats {
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    samples: usize,
}

#[derive(Debug, Default)]
struct BenchmarkReport {
    entries: Vec<(&'static str, MetricStats)>,
}

impl BenchmarkReport {
    fn new() -> Self {
        Self::default()
    }

    fn add(&mut self, label: &'static str, mut samples: Vec<Duration>) {
        let stats = MetricStats {
            p50_us: percentile(&mut samples, 0.50),
            p95_us: percentile(&mut samples, 0.95),
            p99_us: percentile(&mut samples, 0.99),
            samples: samples.len(),
        };
        println!(
            "  {label:<26} p50={:>6} µs  p95={:>6} µs  p99={:>6} µs  samples={}",
            stats.p50_us, stats.p95_us, stats.p99_us, stats.samples,
        );
        self.entries.push((label, stats));
    }

    fn to_json(&self) -> String {
        // Hand-rolled JSON keeps the test free of an extra
        // serde_json dev-dep and the output stable across
        // rust toolchains.
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!("  \"generated_at\": \"{}\",\n", today_iso_date(),));
        s.push_str("  \"platform\": \"development-vm\",\n");
        s.push_str("  \"results\": {\n");
        for (i, (label, stats)) in self.entries.iter().enumerate() {
            let trailing = if i + 1 == self.entries.len() { "" } else { "," };
            s.push_str(&format!(
                "    \"{label}\": {{ \"p50_us\": {}, \"p95_us\": {}, \"p99_us\": {}, \"samples\": {} }}{trailing}\n",
                stats.p50_us, stats.p95_us, stats.p99_us, stats.samples,
            ));
        }
        s.push_str("  }\n}\n");
        s
    }
}

/// `chrono` is not a dev-dep on this crate. The committed
/// snapshot only needs a calendar date, so we derive one from
/// `SystemTime::now` arithmetic — accurate to the day, which is
/// the only resolution the JSON snapshot records.
fn today_iso_date() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let days = secs / 86_400;
    civil_from_days(days)
}

fn civil_from_days(days: i64) -> String {
    // Howard Hinnant's "civil_from_days" algorithm — the
    // canonical Gregorian-calendar conversion. Produces an
    // ISO-8601 date string. See
    // https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!("{y:04}-{m:02}-{d:02}")
}
