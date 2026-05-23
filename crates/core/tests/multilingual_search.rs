//! Phase 1 multilingual search integration tests.
//!
//! `docs/PHASES.md §Phase 1` decision gate: "Text messages can be
//! stored, searched (multilingual)". This test exercises the full
//! [`MessagePersister`] → `search_fts` → [`QueryEngine`] round-trip
//! across eight scripts (Latin, Cyrillic, Han / CJK, mixed
//! Hira-Kata-Han, Arabic, Thai, Devanagari, mixed-script).
//!
//! ICU-only behavior (CJK / Thai / Khmer / Lao / Myanmar word
//! segmentation) is gated behind a runtime probe: when the SQLCipher
//! build does not link against ICU, those tests log the situation
//! and return early instead of failing. Latin / Cyrillic / Arabic /
//! Devanagari word search runs against `unicode61` and is required
//! to pass on every build.

use rusqlite::params;
use uuid::Uuid;

use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::search::query_engine::QueryEngine;
use kchat_core::search::text_search::TextSearchEngine;
use kchat_core::search::tokenizer::FallbackMode;
use kchat_core::{ContentKind, SearchQuery, SearchScope};

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

struct Fixture {
    db: LocalStoreDb,
    /// `language tag → message_id` map used to assert "search 'X'
    /// must surface message Y".
    ids: std::collections::HashMap<&'static str, Uuid>,
    /// Two distinct senders so the structured-filter test has
    /// something to disambiguate.
    sender_alice: String,
    sender_bob: String,
    /// Three conversations so the conversation-filter test has
    /// something to disambiguate.
    conv_a: Uuid,
    conv_b: Uuid,
    conv_c: Uuid,
}

fn build_fixture() -> Fixture {
    let db = LocalStoreDb::open_in_memory(&[0xCA; 32]).expect("open in-memory db");
    let conv_a = Uuid::now_v7();
    let conv_b = Uuid::now_v7();
    let conv_c = Uuid::now_v7();
    seed_conversation(&db, conv_a, 1_000);
    seed_conversation(&db, conv_b, 1_000);
    seed_conversation(&db, conv_c, 1_000);
    let alice = "alice".to_string();
    let bob = "bob".to_string();

    let persister = MessagePersister::new(&db);
    let mut ids = std::collections::HashMap::new();

    let corpus: &[(&str, &str, &Uuid, &str, i64)] = &[
        (
            "en",
            "Meeting at 3pm in the conference room",
            &conv_a,
            "alice",
            1_700_000_000_000,
        ),
        (
            "ru",
            "Встреча в 15:00 в конференц-зале",
            &conv_a,
            "bob",
            1_700_000_001_000,
        ),
        (
            "zh",
            "下午三点在会议室开会",
            &conv_b,
            "alice",
            1_700_000_002_000,
        ),
        (
            "ja",
            "会議は午後3時に会議室で行います",
            &conv_b,
            "bob",
            1_700_000_003_000,
        ),
        (
            "ar",
            "الاجتماع في الساعة 3 مساءً",
            &conv_a,
            "alice",
            1_700_000_004_000,
        ),
        (
            "th",
            "ประชุมเวลาบ่าย 3 โมง",
            &conv_b,
            "bob",
            1_700_000_005_000,
        ),
        ("hi", "बैठक दोपहर 3 बजे", &conv_a, "alice", 1_700_000_006_000),
        (
            "mixed",
            "Meeting at 3pm 会議室で — Встреча",
            &conv_c,
            "alice",
            1_700_000_007_000,
        ),
    ];
    for (lang, text, conv, sender, ts) in corpus {
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
            .unwrap_or_else(|e| {
                panic!("failed to persist {lang}: {e:?}");
            });
        ids.insert(*lang, mid);
    }

    Fixture {
        db,
        ids,
        sender_alice: alice,
        sender_bob: bob,
        conv_a,
        conv_b,
        conv_c,
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

fn icu_available(db: &LocalStoreDb) -> bool {
    db.icu_available()
}

fn require_icu_or_skip(label: &str, db: &LocalStoreDb) -> bool {
    if !icu_available(db) {
        eprintln!(
            "[skip] {label}: SQLCipher built without FTS5 ICU tokenizer; \
             unicode61 fallback cannot segment CJK / Thai. \
             Re-run with an ICU-linked SQLCipher build."
        );
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Required tests — must pass on every build
// ---------------------------------------------------------------------------

#[test]
fn fts_finds_english_meeting() {
    let f = build_fixture();
    let engine = TextSearchEngine::new(f.db.connection(), f.db.icu_available());
    let hits = engine.search_fts("meeting", 50).unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
    let en_id = f.ids["en"].to_string();
    let mixed_id = f.ids["mixed"].to_string();
    assert!(ids.contains(&en_id), "missing en hit; got {ids:?}");
    assert!(ids.contains(&mixed_id), "missing mixed hit; got {ids:?}");
}

#[test]
fn fts_finds_cyrillic_vstrecha() {
    let f = build_fixture();
    let engine = TextSearchEngine::new(f.db.connection(), f.db.icu_available());
    let hits = engine.search_fts("Встреча", 50).unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
    let ru_id = f.ids["ru"].to_string();
    let mixed_id = f.ids["mixed"].to_string();
    assert!(ids.contains(&ru_id), "missing ru hit; got {ids:?}");
    assert!(ids.contains(&mixed_id), "missing mixed hit; got {ids:?}");
}

#[test]
fn fts_finds_arabic_meeting_word() {
    let f = build_fixture();
    let engine = TextSearchEngine::new(f.db.connection(), f.db.icu_available());
    let hits = engine.search_fts("الاجتماع", 50).unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
    let ar_id = f.ids["ar"].to_string();
    assert!(ids.contains(&ar_id), "missing ar hit; got {ids:?}");
}

#[test]
fn fts_finds_devanagari_baithak() {
    let f = build_fixture();
    let engine = TextSearchEngine::new(f.db.connection(), f.db.icu_available());
    let hits = engine.search_fts("बैठक", 50).unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
    let hi_id = f.ids["hi"].to_string();
    assert!(ids.contains(&hi_id), "missing hi hit; got {ids:?}");
}

#[test]
fn structured_filter_by_sender_returns_per_sender_rows() {
    let f = build_fixture();
    let engine = QueryEngine::new(f.db.connection(), f.db.icu_available());
    let q_alice = SearchQuery {
        sender_filter: Some(f.sender_alice.clone()),
        ..Default::default()
    };
    let alice_rows = engine
        .execute_search(&q_alice, &SearchScope::LocalOnly)
        .unwrap();
    let alice_ids: Vec<_> = alice_rows.iter().map(|r| r.message_id).collect();
    for tag in ["en", "zh", "ar", "hi", "mixed"] {
        let id = f.ids[tag];
        assert!(
            alice_ids.contains(&id),
            "alice should own {tag} (id={id}); got {alice_ids:?}"
        );
    }

    let q_bob = SearchQuery {
        sender_filter: Some(f.sender_bob.clone()),
        ..Default::default()
    };
    let bob_rows = engine
        .execute_search(&q_bob, &SearchScope::LocalOnly)
        .unwrap();
    let bob_ids: Vec<_> = bob_rows.iter().map(|r| r.message_id).collect();
    for tag in ["ru", "ja", "th"] {
        let id = f.ids[tag];
        assert!(
            bob_ids.contains(&id),
            "bob should own {tag} (id={id}); got {bob_ids:?}"
        );
    }
}

#[test]
fn structured_filter_by_date_range_is_inclusive() {
    let f = build_fixture();
    let engine = QueryEngine::new(f.db.connection(), f.db.icu_available());
    let q = SearchQuery {
        date_from: Some(1_700_000_002_000),
        date_to: Some(1_700_000_004_000),
        ..Default::default()
    };
    let rows = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
    let ids: Vec<_> = rows.iter().map(|r| r.message_id).collect();
    for tag in ["zh", "ja", "ar"] {
        assert!(ids.contains(&f.ids[tag]), "missing {tag}; got {ids:?}");
    }
    for tag in ["en", "ru", "th", "hi", "mixed"] {
        assert!(
            !ids.contains(&f.ids[tag]),
            "should not include {tag}; got {ids:?}"
        );
    }
}

#[test]
fn combined_fts_meeting_plus_conversation_filter() {
    let f = build_fixture();
    let engine = QueryEngine::new(f.db.connection(), f.db.icu_available());
    let q = SearchQuery {
        query_string: "meeting".into(),
        conversation_filter: Some(f.conv_c),
        ..Default::default()
    };
    let rows = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
    // conv_c has only the mixed-script row.
    assert_eq!(
        rows.len(),
        1,
        "expected exactly the mixed row; got {rows:?}"
    );
    assert_eq!(rows[0].message_id, f.ids["mixed"]);
}

#[test]
fn combined_fts_meeting_plus_conversation_a_excludes_other_convs() {
    let f = build_fixture();
    let engine = QueryEngine::new(f.db.connection(), f.db.icu_available());
    let q = SearchQuery {
        query_string: "meeting".into(),
        conversation_filter: Some(f.conv_a),
        ..Default::default()
    };
    let rows = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
    let ids: Vec<_> = rows.iter().map(|r| r.message_id).collect();
    // English row is on conv_a; mixed is on conv_c.
    assert!(ids.contains(&f.ids["en"]));
    assert!(!ids.contains(&f.ids["mixed"]));
}

#[test]
fn empty_query_returns_every_inserted_row() {
    let f = build_fixture();
    let engine = QueryEngine::new(f.db.connection(), f.db.icu_available());
    let rows = engine
        .execute_search(&SearchQuery::default(), &SearchScope::LocalOnly)
        .unwrap();
    assert_eq!(rows.len(), 8);
}

#[test]
fn structured_filter_text_kind_keeps_text_messages() {
    let f = build_fixture();
    let engine = QueryEngine::new(f.db.connection(), f.db.icu_available());
    let q = SearchQuery {
        content_kind: Some(ContentKind::Text),
        ..Default::default()
    };
    let rows = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
    assert_eq!(rows.len(), 8, "all messages in fixture are text");
    // The conversation pre-seeding above does not insert any media
    // skeletons, so a Text filter is equivalent to "any" here. Now
    // add one media skeleton manually and re-assert.
    let media_mid = Uuid::now_v7();
    f.db.connection()
        .execute(
            "INSERT INTO message_skeleton (
                message_id, conversation_id, sender_id, created_at_ms,
                received_at_ms, kind, body_state
             ) VALUES (?1, ?2, ?3, ?4, ?4, 'media', 'local_plain_available')",
            params![
                media_mid.to_string(),
                f.conv_b.to_string(),
                "alice",
                1_700_000_010_000_i64,
            ],
        )
        .unwrap();
    let rows = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
    assert_eq!(rows.len(), 8, "text filter must skip the media row");
}

// ---------------------------------------------------------------------------
// ICU-only tests — soft-skip when the build lacks ICU
// ---------------------------------------------------------------------------

#[test]
fn fts_finds_chinese_huiyi_with_icu() {
    let f = build_fixture();
    if !require_icu_or_skip("zh hui-yi", &f.db) {
        return;
    }
    let engine = TextSearchEngine::new(f.db.connection(), f.db.icu_available());
    let hits = engine.search_fts("会议", 50).unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
    // Chinese fixture uses the simplified form 会议. The Japanese
    // fixture uses the traditional form 会議; we don't assume the
    // build's ICU collation folds the two.
    let zh_id = f.ids["zh"].to_string();
    assert!(ids.contains(&zh_id), "missing zh hit; got {ids:?}");
}

#[test]
fn fts_finds_japanese_kaigi_with_icu() {
    let f = build_fixture();
    if !require_icu_or_skip("ja kai-gi", &f.db) {
        return;
    }
    let engine = TextSearchEngine::new(f.db.connection(), f.db.icu_available());
    let hits = engine.search_fts("会議", 50).unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
    let ja_id = f.ids["ja"].to_string();
    let mixed_id = f.ids["mixed"].to_string();
    assert!(ids.contains(&ja_id), "missing ja hit; got {ids:?}");
    assert!(ids.contains(&mixed_id), "missing mixed hit; got {ids:?}");
}

#[test]
fn fts_finds_thai_prachum_with_icu() {
    let f = build_fixture();
    if !require_icu_or_skip("th prachum", &f.db) {
        return;
    }
    let engine = TextSearchEngine::new(f.db.connection(), f.db.icu_available());
    let hits = engine.search_fts("ประชุม", 50).unwrap();
    let ids: Vec<_> = hits.iter().map(|h| h.message_id.clone()).collect();
    let th_id = f.ids["th"].to_string();
    assert!(ids.contains(&th_id), "missing th hit; got {ids:?}");
}

// ---------------------------------------------------------------------------
// Sanity test — tokenizer mode is consistent
// ---------------------------------------------------------------------------

#[test]
fn tokenizer_mode_matches_db_state() {
    let f = build_fixture();
    let engine = TextSearchEngine::new(f.db.connection(), f.db.icu_available());
    let mode = engine.tokenizer_mode();
    let expected = if f.db.icu_available() {
        FallbackMode::Icu
    } else {
        FallbackMode::Unicode61
    };
    assert_eq!(mode, expected);
}
