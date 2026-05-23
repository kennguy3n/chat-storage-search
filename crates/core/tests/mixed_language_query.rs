//! mixed-language query fan-out integration tests.
//!
//! `docs/DESIGN.md §3 / §7` requires search to handle queries
//! that interleave multiple scripts in a single string. The
//! tokenizer's [`segment_by_script`] (already used for indexing)
//! drives the fuzzy half; FTS5 with the ICU tokenizer handles the
//! word half when available, and the fuzzy fallback covers the
//! non-ICU build.
//!
//! These tests pin the public-seam behavior:
//!
//! 1. `meeting 会議室` matches a row containing both halves.
//! 2. `встреча meeting` (Cyrillic + Latin) matches rows in either
//!    language.
//! 3. Pure-CJK queries still work on non-ICU builds via the fuzzy
//!    fallback.
//! 4. Mixed-script ranking promotes rows that cover both halves
//!    over rows that cover only one.
//!
//! ICU-dependent assertions are gated on
//! [`LocalStoreDb::icu_available`] so the suite passes on
//! SQLCipher builds without the ICU tokenizer.

use std::collections::HashMap;

use uuid::Uuid;

use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::search::query_engine::QueryEngine;
use kchat_core::{SearchQuery, SearchScope};

const DB_KEY: [u8; 32] = [0x4C; 32];

struct Fixture {
    db: LocalStoreDb,
    ids: HashMap<&'static str, Uuid>,
}

fn seed_conv(db: &LocalStoreDb, id: Uuid) {
    db.insert_conversation(&Conversation {
        conversation_id: id.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms: 1,
        ..Default::default()
    })
    .unwrap();
}

fn build_fixture() -> Fixture {
    let db = LocalStoreDb::open_in_memory(&DB_KEY).unwrap();
    let conv = Uuid::now_v7();
    seed_conv(&db, conv);

    let p = MessagePersister::new(&db);
    let mut ids = HashMap::new();

    // Reuse a stable timestamp scaffold so the recency-decay
    // ordering is dominated by the FTS / fuzzy contribution
    // instead of timestamp drift.
    let base_ts = 1_700_000_000_000_i64;

    let corpus: &[(&str, &str, &str, i64)] = &[
        (
            "latin_only",
            "Meeting agenda for next quarter",
            "alice",
            base_ts + 1,
        ),
        ("cjk_only", "会議室の予約をお願いします", "bob", base_ts + 2),
        (
            "mixed_meeting_cjk",
            "Meeting at 3pm 会議室で",
            "carol",
            base_ts + 3,
        ),
        ("cyrillic_only", "Встреча в три часа", "dmitri", base_ts + 4),
        (
            "mixed_cyrillic_latin",
            "встреча meeting confirmed",
            "eve",
            base_ts + 5,
        ),
        (
            "unrelated",
            "Coffee break later today",
            "frank",
            base_ts + 6,
        ),
        ("cjk_dual", "会議は新しい議題について", "gina", base_ts + 7),
    ];

    for (tag, text, sender, ts) in corpus {
        let mid = Uuid::now_v7();
        p.persist_ingested_message(&IngestedMessage {
            message_id: mid,
            conversation_id: conv,
            sender_id: sender.to_string(),
            created_at_ms: *ts,
            text_content: Some(text.to_string()),
            media_descriptors: vec![],
            reply_to: None,
        })
        .unwrap();
        ids.insert(*tag, mid);
    }

    Fixture { db, ids }
}

fn search(db: &LocalStoreDb, q: &str) -> Vec<kchat_core::SearchResult> {
    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let query = SearchQuery {
        query_string: q.to_string(),
        ..Default::default()
    };
    engine
        .execute_search(&query, &SearchScope::LocalOnly)
        .unwrap()
}

fn ids_in_order(results: &[kchat_core::SearchResult]) -> Vec<String> {
    results.iter().map(|r| r.message_id.to_string()).collect()
}

#[test]
fn mixed_latin_cjk_query_finds_dual_script_message() {
    let fx = build_fixture();
    let results = search(&fx.db, "meeting 会議室");
    let ids = ids_in_order(&results);
    let mixed_id = fx.ids["mixed_meeting_cjk"].to_string();
    assert!(
        ids.contains(&mixed_id),
        "dual-script row must surface for mixed query: {ids:?}",
    );
}

#[test]
fn mixed_cyrillic_latin_query_finds_messages_in_both_languages() {
    let fx = build_fixture();
    let results = search(&fx.db, "встреча meeting");
    let ids = ids_in_order(&results);
    assert!(
        ids.contains(&fx.ids["mixed_cyrillic_latin"].to_string()),
        "row covering both Cyrillic + Latin halves must surface: {ids:?}",
    );
    // The Latin-only and Cyrillic-only rows should both surface
    // through fuzzy fallback or FTS hit.
    let latin = fx.ids["latin_only"].to_string();
    let cyrillic = fx.ids["cyrillic_only"].to_string();
    assert!(
        ids.contains(&latin) || ids.contains(&cyrillic),
        "at least one single-script row must surface from fan-out: {ids:?}",
    );
}

#[test]
fn pure_cjk_query_works_on_non_icu_build_via_fuzzy_fallback() {
    let fx = build_fixture();
    // Even when FTS5 is configured without ICU, the fuzzy bigram
    // index covers the CJK script class and surfaces rows
    // containing the bigrams in the query.
    let results = search(&fx.db, "会議");
    let ids = ids_in_order(&results);
    assert!(
        ids.contains(&fx.ids["cjk_only"].to_string())
            || ids.contains(&fx.ids["mixed_meeting_cjk"].to_string())
            || ids.contains(&fx.ids["cjk_dual"].to_string()),
        "pure-CJK query must surface at least one CJK row: {ids:?}",
    );
}

#[test]
fn mixed_script_query_promotes_dual_script_match_over_single_script() {
    let fx = build_fixture();
    let results = search(&fx.db, "meeting 会議");
    let ids = ids_in_order(&results);

    // The dual-script row covers both halves of the query and
    // should rank above pure single-script rows when both surface
    // (the two halves combine through BM25 + fuzzy).
    let pos_dual = ids
        .iter()
        .position(|i| *i == fx.ids["mixed_meeting_cjk"].to_string())
        .expect("dual-script row must surface");
    if let Some(pos_latin) = ids
        .iter()
        .position(|i| *i == fx.ids["latin_only"].to_string())
    {
        assert!(
            pos_dual <= pos_latin,
            "dual-script row must outrank Latin-only row: \
             dual at {pos_dual}, latin at {pos_latin}, ids = {ids:?}",
        );
    }
}

#[test]
fn unrelated_row_is_not_surfaced_by_mixed_script_query() {
    let fx = build_fixture();
    let results = search(&fx.db, "meeting 会議室");
    let ids = ids_in_order(&results);
    assert!(
        !ids.contains(&fx.ids["unrelated"].to_string()),
        "unrelated row must not surface: {ids:?}",
    );
}
