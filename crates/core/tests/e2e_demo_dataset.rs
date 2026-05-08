//! Shared dataset generator for the comprehensive end-to-end demo
//! (`crates/core/tests/e2e_demo.rs`) and the focused benchmark
//! sweep (`crates/core/tests/benchmark_baseline.rs`).
//!
//! The dataset shape mirrors the "comprehensive sample" called out
//! in `docs/PROPOSAL.md §12` — five conversations spanning a
//! personal chat, a group chat, a work channel, a multilingual
//! group, and a media-heavy thread; messages drawn from twelve
//! scripts (English, Russian, Chinese, Japanese, Arabic, Thai,
//! Hindi, Korean, Vietnamese, German, French, mixed-script); and
//! a handful of varied-MIME-type media descriptors.
//!
//! The module is `#[path]`-included from the demo and benchmark
//! tests so they share a single corpus shape; the in-file
//! `#[test]` only sanity-checks the generators (counts, language
//! coverage, MIME-type variety) so a default `cargo test` run
//! still exercises them.
//!
//! `#[allow(dead_code)]` is necessary at module scope because
//! Rust treats the `#[path]`-included module as a fresh
//! compilation unit per consumer — items only used by one of
//! the two test binaries (e.g. [`SCRIPT_TOKENS`] is only used
//! by `e2e_demo.rs`) would otherwise produce a `dead_code`
//! warning when compiled into `benchmark_baseline.rs`.
#![allow(dead_code)]

use kchat_core::formats::media_descriptor::MediaDescriptor;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::IngestedMessage;
use uuid::Uuid;

/// Twelve corpora — same shape as
/// [`crate::tests::large_scale`]'s `CORPORA`. Order matters: the
/// dataset generators round-robin through the slice so the first
/// `CORPORA.len()` messages cover every script before any one
/// language repeats.
pub const CORPORA: &[(&str, &str)] = &[
    (
        "en",
        "Meeting at 3pm in the conference room near the lighthouse",
    ),
    ("ru", "Встреча в 15:00 в конференц-зале около маяка"),
    ("zh", "下午三点在会议室开会，灯塔旁边"),
    ("ja", "会議は午後3時に会議室で行います、灯台の近く"),
    ("ar", "الاجتماع في الساعة 3 مساءً قرب المنارة"),
    ("th", "ประชุมเวลาบ่าย 3 โมงใกล้ประภาคาร"),
    ("hi", "बैठक दोपहर 3 बजे लाइटहाउस के पास"),
    ("ko", "오후 3시에 등대 옆 회의실에서 만나요"),
    (
        "vi",
        "Cuộc họp lúc 3 giờ chiều tại phòng họp gần ngọn hải đăng",
    ),
    ("de", "Besprechung um 15 Uhr im Konferenzraum am Leuchtturm"),
    (
        "fr",
        "Réunion à 15 heures dans la salle de conférence près du phare",
    ),
    (
        "mixed",
        "Meeting at 3pm 会議室で — Встреча — réunion — 회의실에서 — lighthouse",
    ),
];

/// One distinguishing token per corpus that the FTS / fuzzy /
/// structured search assertions can fan out over.
///
/// Every entry is present in the corresponding `CORPORA` row (so a
/// well-formed FTS5 ICU tokenizer must return ≥ 1 hit) and is
/// distinct enough that the ranker does not accidentally cross
/// scripts.
pub const SCRIPT_TOKENS: &[(&str, &str)] = &[
    ("en", "lighthouse"),
    ("ru", "маяка"),
    ("zh", "灯塔"),
    ("ja", "灯台"),
    ("ar", "المنارة"),
    ("th", "ประภาคาร"),
    ("hi", "लाइटहाउस"),
    ("ko", "등대"),
    ("vi", "ngọn hải đăng"),
    ("de", "Leuchtturm"),
    ("fr", "phare"),
    ("mixed", "lighthouse"),
];

/// Fixed senders so structured-search assertions can filter
/// deterministically. Round-robin assignment matches
/// `large_scale.rs` (`alice` even, `bob` odd) but with two more
/// names so each conversation's roster is plausibly multi-party.
pub const SENDERS: &[&str] = &["alice", "bob", "carol", "dave"];

/// Five MIME types so the structured-search and budget-eviction
/// assertions can mix media kinds. Sizes are realistic-ish so
/// `bytes_total` × `chunk_count` math stays sane.
pub const MIME_TYPES: &[(&str, u64, u32)] = &[
    ("image/jpeg", 256 * 1024, 1),
    ("image/png", 512 * 1024, 1),
    ("video/mp4", 8 * 1024 * 1024, 8),
    ("application/pdf", 1024 * 1024, 2),
    ("audio/mpeg", 2 * 1024 * 1024, 2),
];

/// Default conversation count for the standard dataset. The five
/// conversations cover a personal chat, a group chat, a work
/// channel, a multilingual group, and a media-heavy thread.
pub const DEFAULT_CONVERSATION_COUNT: usize = 5;
/// Default message count for the standard dataset.
pub const DEFAULT_MESSAGE_COUNT: usize = 200;
/// Default media-asset count for the standard dataset.
pub const DEFAULT_MEDIA_COUNT: usize = 20;

/// Anchor timestamp for the dataset (`2026-04-01 00:00:00 UTC`).
/// Three-month span lands message timestamps in `2026-04`,
/// `2026-05`, and `2026-06` so the archive partitioner produces
/// at least three buckets.
///
/// `20_544` is the Unix day count of `2026-04-01 00:00:00 UTC`
/// (verified against `chrono::DateTime::from_timestamp`).
pub const DATASET_START_MS: i64 = 20_544 * 86_400 * 1_000;
/// Three months in milliseconds — 90 days × 86_400 s × 1_000 ms.
pub const DATASET_SPAN_MS: i64 = 90 * 86_400 * 1_000;

/// Generate `count` conversations with deterministic activity
/// timestamps. The first five entries correspond to:
///
/// 1. a personal one-to-one chat,
/// 2. a small group chat,
/// 3. a work channel,
/// 4. a multilingual group, and
/// 5. a media-heavy thread.
///
/// Larger counts repeat the personal-chat shape — the demo's
/// large-scale `#[ignore]` variant uses this to stress-test
/// 10 000-message ingest with hundreds of conversations.
pub fn generate_demo_conversations(count: usize) -> Vec<Conversation> {
    let span = DATASET_SPAN_MS.max(1);
    (0..count)
        .map(|i| {
            let conv_id = Uuid::now_v7();
            let last_activity_ms = DATASET_START_MS + ((i as i64 + 1) * span) / count.max(1) as i64;
            Conversation {
                conversation_id: conv_id.to_string(),
                title_cipher: None,
                pinned: i == 0, // pin the personal chat
                muted: false,
                last_message_id: None,
                last_activity_ms,
                ..Default::default()
            }
        })
        .collect()
}

/// Round-robin `count` messages across the supplied `conversations`
/// and the [`CORPORA`] table, with timestamps spaced so they cover
/// the [`DATASET_SPAN_MS`] window.
///
/// The returned messages are ready to feed into
/// [`kchat_core::message::processor::MessagePersister::persist_ingested_message`].
pub fn generate_demo_messages(conversations: &[Uuid], count: usize) -> Vec<IngestedMessage> {
    assert!(
        !conversations.is_empty(),
        "generate_demo_messages requires at least one conversation",
    );
    let span = DATASET_SPAN_MS.max(1);
    (0..count)
        .map(|i| {
            let conv = conversations[i % conversations.len()];
            let (_, text) = CORPORA[i % CORPORA.len()];
            let sender = SENDERS[i % SENDERS.len()];
            // Spread timestamps evenly so the archive partitioner
            // produces multiple `(conversation_id, time_bucket)`
            // groups even when `count` is small.
            let created_at_ms = DATASET_START_MS + ((i as i64 + 1) * span) / count.max(1) as i64;
            IngestedMessage {
                message_id: Uuid::now_v7(),
                conversation_id: conv,
                sender_id: sender.to_string(),
                created_at_ms,
                text_content: Some((*text).to_string()),
                media_descriptors: vec![],
                reply_to: None,
            }
        })
        .collect()
}

/// Generate `count` media-asset descriptors round-robined over
/// [`MIME_TYPES`] and the supplied `conversations`. Returned as
/// `(conversation_id, descriptor)` pairs so callers can decide
/// whether to attach them to a fresh ingested message or to seed
/// the `media_asset` table directly.
pub fn generate_demo_media_assets(
    conversations: &[Uuid],
    count: usize,
) -> Vec<(Uuid, MediaDescriptor)> {
    assert!(
        !conversations.is_empty(),
        "generate_demo_media_assets requires at least one conversation",
    );
    (0..count)
        .map(|i| {
            let (mime, bytes_total, chunk_count) = MIME_TYPES[i % MIME_TYPES.len()];
            let conv = conversations[i % conversations.len()];
            let merkle_root = {
                let mut m = [0u8; 32];
                m.iter_mut()
                    .enumerate()
                    .for_each(|(j, b)| *b = ((i ^ j) & 0xFF) as u8);
                m
            };
            let descriptor = MediaDescriptor {
                asset_id: Uuid::now_v7(),
                mime_type: mime.to_string(),
                bytes_total,
                chunk_count,
                merkle_root,
                blob_id: Uuid::now_v7(),
                wrapped_k_asset: vec![((i + 1) & 0xFF) as u8; 40],
                storage_sink: None,
            };
            (conv, descriptor)
        })
        .collect()
}

#[test]
fn dataset_generators_cover_every_script() {
    let convs = generate_demo_conversations(DEFAULT_CONVERSATION_COUNT);
    assert_eq!(convs.len(), DEFAULT_CONVERSATION_COUNT);
    let conv_ids: Vec<Uuid> = convs
        .iter()
        .map(|c| Uuid::parse_str(&c.conversation_id).expect("uuid"))
        .collect();
    let messages = generate_demo_messages(&conv_ids, DEFAULT_MESSAGE_COUNT);
    assert_eq!(messages.len(), DEFAULT_MESSAGE_COUNT);

    // Every script must appear at least once. With 200 messages
    // round-robined over 12 corpora that is guaranteed, but the
    // assertion guards regressions in `CORPORA` shape.
    let mut langs: std::collections::BTreeSet<&'static str> = Default::default();
    for (i, _msg) in messages.iter().enumerate() {
        langs.insert(CORPORA[i % CORPORA.len()].0);
    }
    assert_eq!(
        langs.len(),
        CORPORA.len(),
        "round-robin schedule must cover every corpus",
    );

    // Every conversation must receive at least one message.
    let touched: std::collections::BTreeSet<Uuid> =
        messages.iter().map(|m| m.conversation_id).collect();
    assert_eq!(
        touched.len(),
        conv_ids.len(),
        "every conversation must be touched by the message round-robin",
    );

    let media = generate_demo_media_assets(&conv_ids, DEFAULT_MEDIA_COUNT);
    assert_eq!(media.len(), DEFAULT_MEDIA_COUNT);
    let mime_set: std::collections::BTreeSet<String> =
        media.iter().map(|(_, d)| d.mime_type.clone()).collect();
    assert_eq!(
        mime_set.len(),
        MIME_TYPES.len(),
        "media generator must cover every MIME type in the round-robin",
    );
}

#[test]
fn dataset_timestamps_span_three_months() {
    let convs = generate_demo_conversations(DEFAULT_CONVERSATION_COUNT);
    let conv_ids: Vec<Uuid> = convs
        .iter()
        .map(|c| Uuid::parse_str(&c.conversation_id).expect("uuid"))
        .collect();
    let messages = generate_demo_messages(&conv_ids, DEFAULT_MESSAGE_COUNT);
    let min = messages.iter().map(|m| m.created_at_ms).min().unwrap();
    let max = messages.iter().map(|m| m.created_at_ms).max().unwrap();
    // Allow some slack at the edges (the round-robin never
    // touches `DATASET_START_MS` itself), but the spread must
    // exceed two months.
    assert!(
        max - min > 60 * 86_400 * 1_000,
        "demo dataset must span > 60 days; got {min}..{max}",
    );
    assert!(
        max - min <= DATASET_SPAN_MS,
        "demo dataset must stay within the 90-day window; got {min}..{max}",
    );
}
