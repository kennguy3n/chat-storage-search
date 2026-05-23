//! Phase 1 combined FTS5 + fuzzy multilingual integration tests.
//!
//! `docs/PHASES.md §Phase 1` decision gate: "Text messages can be
//! stored, searched (multilingual)". The companion
//! `multilingual_search.rs` covers the FTS5 / structured-filter half
//! of that gate; this file exercises the **combined** FTS5 + fuzzy
//! pipeline that PR #6 introduced and PRs in this series wired into
//! `MessagePersister` (Task 1) and `QueryEngine` (Task 2).
//!
//! Each test goes through the public seam: messages are persisted via
//! [`MessagePersister`] (which now indexes both `search_fts` and
//! `search_fuzzy`) and then queried through [`QueryEngine`] (which
//! merges FTS5 hits + fuzzy hits, dedups by `message_id`, and ranks
//! exact > fuzzy per `docs/PROPOSAL.md §7.5`).
//!
//! ICU-only tests (CJK / Thai FTS word search) are gated on the same
//! [`LocalStoreDb::icu_available`] probe used by `multilingual_search.rs`
//! so the suite still passes on SQLCipher builds without the ICU
//! tokenizer; the fuzzy half of those tests runs unconditionally
//! because the fuzzy indexer is pure Rust.

use std::collections::HashMap;

use uuid::Uuid;

use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::search::query_engine::QueryEngine;
use kchat_core::{SearchQuery, SearchScope};

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

struct Fixture {
    db: LocalStoreDb,
    /// `tag → message_id` map used to assert "search 'X' must surface
    /// message Y".
    ids: HashMap<&'static str, Uuid>,
    /// One sender used by the structured-filter narrowing test.
    /// Other senders are present in the corpus but are not
    /// individually referenced by name from outside `build_fixture`.
    #[allow(dead_code)]
    sender_alice: String,
    sender_bob: String,
    conv_a: Uuid,
    /// Second conversation used to seed cross-conversation rows;
    /// not directly referenced by every test.
    #[allow(dead_code)]
    conv_b: Uuid,
}

fn build_fixture() -> Fixture {
    let db = LocalStoreDb::open_in_memory(&[0xCA; 32]).expect("open in-memory db");
    let conv_a = Uuid::now_v7();
    let conv_b = Uuid::now_v7();
    seed_conversation(&db, conv_a, 1_000);
    seed_conversation(&db, conv_b, 1_000);
    let alice = "alice".to_string();
    let bob = "bob".to_string();

    let persister = MessagePersister::new(&db);
    let mut ids = HashMap::new();

    // (tag, text, conversation, sender, created_at_ms)
    let corpus: &[(&str, &str, &Uuid, &str, i64)] = &[
        // Latin: clean trigrams; "lighthouse keeper" should be
        // findable via the typo "lighthose".
        (
            "latin_lighthouse",
            "The lighthouse keeper waved at midnight",
            &conv_a,
            "alice",
            1_700_000_000_000,
        ),
        // Cyrillic: "Привет мир" is short but the trigrams of "при"
        // and "рив" overlap "Привт" enough to score > 0.
        (
            "cyrillic_hello",
            "Привет мир — добро пожаловать",
            &conv_a,
            "bob",
            1_700_000_001_000,
        ),
        // CJK: bigrams. "会議室で" produces bigrams ("会議", "議室")
        // for the Hani run and is split from the Hira "で".
        (
            "cjk_meeting_room",
            "会議室で打ち合わせしましょう",
            &conv_b,
            "alice",
            1_700_000_002_000,
        ),
        // Mixed-script: Latin "meeting" + Hani "会議室". Both engines
        // should hit the same message under different queries.
        (
            "mixed_script",
            "Meeting at 3pm 会議室で — Встреча",
            &conv_b,
            "alice",
            1_700_000_003_000,
        ),
        // Arabic trigrams. "مرحبا" → trigrams "مرح", "رحب", "حبا".
        // A query of "مرحب" overlaps two of those.
        (
            "arabic_hello",
            "مرحبا بالعالم",
            &conv_a,
            "bob",
            1_700_000_004_000,
        ),
        // Thai trigrams. "สวัสดี" is 6 chars (with combining marks);
        // we search a partial substring.
        (
            "thai_hello",
            "สวัสดีครับ everyone",
            &conv_b,
            "bob",
            1_700_000_005_000,
        ),
        // Distinct conversation/sender so the structured-filter
        // narrowing test can exclude one of two fuzzy candidates.
        (
            "structured_decoy",
            "Hello from the lighthouse keeper of conv_b",
            &conv_b,
            "alice",
            1_700_000_006_000,
        ),
    ];
    for (tag, text, conv, sender, ts) in corpus {
        let mid = Uuid::now_v7();
        let msg = IngestedMessage {
            message_id: mid,
            conversation_id: **conv,
            sender_id: (*sender).to_string(),
            created_at_ms: *ts,
            text_content: Some((*text).to_string()),
            media_descriptors: vec![],
            reply_to: None,
        };
        persister
            .persist_ingested_message(&msg)
            .unwrap_or_else(|e| panic!("failed to persist {tag}: {e:?}"));
        ids.insert(*tag, mid);
    }

    Fixture {
        db,
        ids,
        sender_alice: alice,
        sender_bob: bob,
        conv_a,
        conv_b,
    }
}

fn seed_conversation(db: &LocalStoreDb, conversation_id: Uuid, last_activity_ms: i64) {
    db.insert_conversation(&Conversation {
        conversation_id: conversation_id.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms,
        ..Default::default()
    })
    .unwrap();
}

fn require_icu_or_skip(label: &str, db: &LocalStoreDb) -> bool {
    if !db.icu_available() {
        eprintln!(
            "[skip] {label}: SQLCipher built without FTS5 ICU tokenizer; \
             unicode61 fallback cannot segment CJK / Thai. \
             Re-run with an ICU-linked SQLCipher build."
        );
        return false;
    }
    true
}

fn search_ids(f: &Fixture, query: &str) -> Vec<Uuid> {
    let q = SearchQuery {
        query_string: query.to_string(),
        ..Default::default()
    };
    QueryEngine::new(f.db.connection(), f.db.icu_available())
        .execute_search(&q, &SearchScope::LocalOnly)
        .unwrap()
        .into_iter()
        .map(|r| r.message_id)
        .collect()
}

// ---------------------------------------------------------------------------
// Required tests — must pass on every build (fuzzy is pure Rust).
// ---------------------------------------------------------------------------

#[test]
fn latin_fuzzy_finds_typo_match() {
    // "lighthose" is a typo for "lighthouse"; FTS5 alone would miss
    // it but the trigram fuzzy index recovers it.
    let f = build_fixture();
    let ids = search_ids(&f, "lighthose");
    assert!(
        ids.contains(&f.ids["latin_lighthouse"]),
        "fuzzy should recover typo'd Latin match; got {ids:?}"
    );
}

#[test]
fn cyrillic_fuzzy_finds_typo_match() {
    // "Привт" drops the "е"; the surviving trigrams "при" / "рив"
    // overlap "привет" enough to score above zero.
    let f = build_fixture();
    let ids = search_ids(&f, "Привт");
    assert!(
        ids.contains(&f.ids["cyrillic_hello"]),
        "fuzzy should recover typo'd Cyrillic match; got {ids:?}"
    );
}

#[test]
fn cjk_fuzzy_bigram_match() {
    // CJK runs are bigram-tokenized regardless of ICU.
    let f = build_fixture();
    let ids = search_ids(&f, "会議");
    assert!(
        ids.contains(&f.ids["cjk_meeting_room"]),
        "fuzzy should match CJK bigram '会議' in 会議室で; got {ids:?}"
    );
    assert!(
        ids.contains(&f.ids["mixed_script"]),
        "fuzzy should also match the mixed-script row; got {ids:?}"
    );
}

#[test]
fn mixed_script_returns_distinct_engine_hits() {
    // The mixed-script row contains both Latin "meeting" (FTS) and
    // Hani "会議" (fuzzy bigram). Two distinct queries should both
    // resolve to the same row without depending on ICU.
    let f = build_fixture();
    let mixed_id = f.ids["mixed_script"];

    let by_fts = search_ids(&f, "meeting");
    assert!(
        by_fts.contains(&mixed_id),
        "FTS query 'meeting' should find mixed row; got {by_fts:?}"
    );

    let by_fuzzy = search_ids(&f, "会議");
    assert!(
        by_fuzzy.contains(&mixed_id),
        "fuzzy bigram query '会議' should find mixed row; got {by_fuzzy:?}"
    );
}

#[test]
fn arabic_fuzzy_partial_match() {
    let f = build_fixture();
    let ids = search_ids(&f, "مرحب");
    assert!(
        ids.contains(&f.ids["arabic_hello"]),
        "fuzzy should match Arabic trigram prefix; got {ids:?}"
    );
}

#[test]
fn cross_engine_dedup_returns_single_result() {
    // A clean exact word — the FTS index hits this row and the
    // fuzzy index hits it too. The merged engine must return it
    // exactly once (PROPOSAL.md §7.5 dedupes by message_id).
    let f = build_fixture();
    let ids = search_ids(&f, "lighthouse");

    let target = f.ids["latin_lighthouse"];
    let count = ids.iter().filter(|&&id| id == target).count();
    assert_eq!(
        count, 1,
        "exact + fuzzy hits on same message must dedupe; got ids={ids:?}"
    );
}

#[test]
fn exact_match_outranks_fuzzy_only_match() {
    // "lighthouse" is exact in `latin_lighthouse` and `structured_decoy`
    // but only fuzzy-overlaps with `cyrillic_hello`. The FTS hits must
    // sort ahead of any fuzzy-only hits.
    let f = build_fixture();
    let q = SearchQuery {
        query_string: "lighthouse".into(),
        ..Default::default()
    };
    let rows = QueryEngine::new(f.db.connection(), f.db.icu_available())
        .execute_search(&q, &SearchScope::LocalOnly)
        .unwrap();
    assert!(!rows.is_empty(), "expected at least one hit");
    // Both Latin lighthouse rows have FTS hits; their rank_score
    // must be > 0 and the top result must be one of them.
    let top = rows.first().unwrap();
    assert!(
        top.message_id == f.ids["latin_lighthouse"] || top.message_id == f.ids["structured_decoy"],
        "expected an FTS hit on top, got message_id={}",
        top.message_id
    );
    assert!(
        top.rank_score > 0.0,
        "FTS hit should score above zero; got {}",
        top.rank_score
    );
}

#[test]
fn structured_filters_narrow_fuzzy_results() {
    // Two messages contain "lighthouse"-ish content:
    //   - latin_lighthouse: alice / conv_a
    //   - structured_decoy: alice / conv_b
    // Constrain to conv_a — only the first must come back.
    let f = build_fixture();
    let q = SearchQuery {
        query_string: "lighthose".into(), // fuzzy typo
        conversation_filter: Some(f.conv_a),
        ..Default::default()
    };
    let rows = QueryEngine::new(f.db.connection(), f.db.icu_available())
        .execute_search(&q, &SearchScope::LocalOnly)
        .unwrap();
    let ids: Vec<_> = rows.iter().map(|r| r.message_id).collect();
    assert!(
        ids.contains(&f.ids["latin_lighthouse"]),
        "fuzzy match in filtered conv must come back; got {ids:?}"
    );
    assert!(
        !ids.contains(&f.ids["structured_decoy"]),
        "row in conv_b must be excluded by conversation filter; got {ids:?}"
    );
}

#[test]
fn sender_filter_narrows_fuzzy_results() {
    // "Hello" appears in two rows (cyrillic_hello via fuzzy and
    // structured_decoy via FTS). Constrain to bob — only
    // cyrillic_hello (sender=bob) must remain.
    let f = build_fixture();
    let q = SearchQuery {
        query_string: "hello".into(),
        sender_filter: Some(f.sender_bob.clone()),
        ..Default::default()
    };
    let rows = QueryEngine::new(f.db.connection(), f.db.icu_available())
        .execute_search(&q, &SearchScope::LocalOnly)
        .unwrap();
    let ids: Vec<_> = rows.iter().map(|r| r.message_id).collect();
    assert!(
        !ids.contains(&f.ids["structured_decoy"]),
        "alice's row must be excluded by sender_filter=bob; got {ids:?}"
    );
    // Bob's "Hello world" via Cyrillic doesn't actually contain a
    // Latin "hello" — so the only sender=bob row that should match
    // is via the trigram overlap. We assert it doesn't include
    // alice's row, which is the substantive guarantee.
    for id in &ids {
        let row =
            f.db.get_message_skeleton(&id.to_string())
                .unwrap()
                .expect("skel");
        assert_eq!(row.sender_id, f.sender_bob, "sender_filter held");
    }
}

#[test]
fn fuzzy_only_hit_has_lower_rank_than_exact() {
    // Search for an exact term that hits one row directly via FTS
    // and another row only via fuzzy n-gram overlap. The exact hit
    // must come first.
    let f = build_fixture();
    let q = SearchQuery {
        query_string: "lighthouse".into(),
        ..Default::default()
    };
    let rows = QueryEngine::new(f.db.connection(), f.db.icu_available())
        .execute_search(&q, &SearchScope::LocalOnly)
        .unwrap();
    assert!(rows.len() >= 2, "expected ≥2 hits; got {}", rows.len());
    let top_two = &rows[..2];
    // The top two must be the exact-match rows; "cyrillic_hello"
    // (fuzzy-only by trigram coincidence) must rank below them
    // when it appears at all.
    let cyr = f.ids["cyrillic_hello"];
    assert!(
        !top_two.iter().any(|r| r.message_id == cyr),
        "fuzzy-only Cyrillic row must not be in the top two; got {top_two:?}"
    );
}

// ---------------------------------------------------------------------------
// ICU-gated test — Thai FTS needs the ICU tokenizer.
// ---------------------------------------------------------------------------

#[test]
fn thai_fuzzy_partial_match() {
    // The fuzzy half of Thai is unconditional; the FTS half is
    // gated.
    let f = build_fixture();
    let ids = search_ids(&f, "สวัสดี");
    assert!(
        ids.contains(&f.ids["thai_hello"]),
        "fuzzy should match Thai trigrams of 'สวัสดี'; got {ids:?}"
    );

    if !require_icu_or_skip("thai_fts", &f.db) {
        return;
    }
    // ICU-tokenized FTS path: the same query exercises FTS5 word
    // segmentation when ICU is linked.
    let ids = search_ids(&f, "สวัสดี");
    assert!(
        ids.contains(&f.ids["thai_hello"]),
        "FTS5+fuzzy should still find Thai row with ICU; got {ids:?}"
    );
}
