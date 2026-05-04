//! Integration tests for the Phase 8, batch-5
//! multi-scope-search foundation.
//!
//! Exercises the new [`SearchTarget`] variants
//! (`ConversationGroup`, `Channel`, `Starred`, `Unread`) and
//! the [`crate::search::search_target::ConversationGroupResolver`]
//! trait wired through
//! [`crate::core_impl::CoreImpl::search_with_target`] and
//! [`crate::search::query_engine::QueryEngine::execute_search_with_target`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::search::query_engine::QueryEngine;
use kchat_core::search::search_target::{
    ConversationGroupResolver, NoopConversationGroupResolver, StaticConversationGroupResolver,
};
use kchat_core::{SearchQuery, SearchScope, SearchTarget};
use uuid::Uuid;

const TEST_DB_KEY: [u8; 32] = [0x22; 32];

fn open_db() -> LocalStoreDb {
    LocalStoreDb::open_in_memory(&TEST_DB_KEY).expect("open in-memory db")
}

fn insert_conv(db: &LocalStoreDb, conv: Uuid) {
    db.insert_conversation(&Conversation {
        conversation_id: conv.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms: 0,
        ..Default::default()
    })
    .unwrap();
}

fn seed_message(db: &LocalStoreDb, conv: Uuid, body: &str, ts_ms: i64) {
    let persister = MessagePersister::new(db);
    let msg = IngestedMessage {
        message_id: Uuid::now_v7(),
        conversation_id: conv,
        sender_id: "user-1".into(),
        created_at_ms: ts_ms,
        text_content: Some(body.into()),
        media_descriptors: Vec::new(),
        reply_to: None,
    };
    persister.persist_ingested_message(&msg).unwrap();
}

fn query_for(s: &str) -> SearchQuery {
    SearchQuery {
        query_string: s.into(),
        ..Default::default()
    }
}

#[test]
fn search_target_global_returns_every_conversation() {
    let db = open_db();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_conv(&db, a);
    insert_conv(&db, b);
    seed_message(&db, a, "hello world from alpha", 1_000);
    seed_message(&db, b, "hello world from beta", 2_000);

    let engine = QueryEngine::new(&db);
    let resolver = NoopConversationGroupResolver::new();
    let hits = engine
        .execute_search_with_target(
            &query_for("hello"),
            &SearchScope::LocalOnly,
            &SearchTarget::Global,
            &resolver,
            200,
        )
        .unwrap();
    let convs: HashSet<_> = hits.iter().map(|h| h.conversation_id).collect();
    assert!(convs.contains(&a) && convs.contains(&b));
}

#[test]
fn search_target_conversation_filters_to_one_conversation() {
    let db = open_db();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_conv(&db, a);
    insert_conv(&db, b);
    seed_message(&db, a, "hello world", 1_000);
    seed_message(&db, b, "hello world", 2_000);

    let engine = QueryEngine::new(&db);
    let resolver = NoopConversationGroupResolver::new();
    let hits = engine
        .execute_search_with_target(
            &query_for("hello"),
            &SearchScope::LocalOnly,
            &SearchTarget::Conversation(a),
            &resolver,
            200,
        )
        .unwrap();
    assert!(!hits.is_empty(), "expected at least one hit");
    for h in &hits {
        assert_eq!(h.conversation_id, a, "non-target conversation leaked");
    }
}

#[test]
fn search_target_conversation_group_scopes_to_explicit_id_set() {
    let db = open_db();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let c = Uuid::now_v7();
    insert_conv(&db, a);
    insert_conv(&db, b);
    insert_conv(&db, c);
    seed_message(&db, a, "match-this-alpha", 1_000);
    seed_message(&db, b, "match-this-beta", 2_000);
    seed_message(&db, c, "match-this-gamma", 3_000);

    let engine = QueryEngine::new(&db);
    let resolver = NoopConversationGroupResolver::new();
    let hits = engine
        .execute_search_with_target(
            &query_for("match-this"),
            &SearchScope::LocalOnly,
            &SearchTarget::ConversationGroup(vec![a, b]),
            &resolver,
            200,
        )
        .unwrap();
    let convs: HashSet<_> = hits.iter().map(|h| h.conversation_id).collect();
    assert!(convs.contains(&a));
    assert!(convs.contains(&b));
    assert!(!convs.contains(&c), "c was outside the target group");
}

#[test]
fn search_target_starred_uses_resolver_set() {
    let db = open_db();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_conv(&db, a);
    insert_conv(&db, b);
    seed_message(&db, a, "starred-needle", 1_000);
    seed_message(&db, b, "starred-needle", 2_000);

    let mut starred = HashSet::new();
    starred.insert(a.to_string());
    let resolver = StaticConversationGroupResolver::new(HashMap::new(), starred, HashSet::new());

    let engine = QueryEngine::new(&db);
    let hits = engine
        .execute_search_with_target(
            &query_for("starred-needle"),
            &SearchScope::LocalOnly,
            &SearchTarget::Starred,
            &resolver,
            200,
        )
        .unwrap();
    assert!(!hits.is_empty(), "expected at least one starred hit");
    for h in &hits {
        assert_eq!(h.conversation_id, a, "non-starred conversation leaked");
    }
}

#[test]
fn search_target_unread_uses_resolver_set() {
    let db = open_db();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_conv(&db, a);
    insert_conv(&db, b);
    seed_message(&db, a, "unread-needle", 1_000);
    seed_message(&db, b, "unread-needle", 2_000);

    let mut unread = HashSet::new();
    unread.insert(b.to_string());
    let resolver = StaticConversationGroupResolver::new(HashMap::new(), HashSet::new(), unread);

    let engine = QueryEngine::new(&db);
    let hits = engine
        .execute_search_with_target(
            &query_for("unread-needle"),
            &SearchScope::LocalOnly,
            &SearchTarget::Unread,
            &resolver,
            200,
        )
        .unwrap();
    assert!(!hits.is_empty(), "expected at least one unread hit");
    for h in &hits {
        assert_eq!(h.conversation_id, b);
    }
}

#[test]
fn search_target_starred_with_empty_resolver_returns_no_results() {
    let db = open_db();
    let a = Uuid::now_v7();
    insert_conv(&db, a);
    seed_message(&db, a, "no-star-here", 1_000);
    let engine = QueryEngine::new(&db);
    let resolver = NoopConversationGroupResolver::new();
    let hits = engine
        .execute_search_with_target(
            &query_for("no-star-here"),
            &SearchScope::LocalOnly,
            &SearchTarget::Starred,
            &resolver,
            200,
        )
        .unwrap();
    assert!(hits.is_empty(), "empty starred set must yield no hits");
}

#[test]
fn search_target_channel_resolves_via_resolver() {
    let db = open_db();
    let conv_a = Uuid::now_v7();
    let conv_b = Uuid::now_v7();
    insert_conv(&db, conv_a);
    insert_conv(&db, conv_b);
    seed_message(&db, conv_a, "channel-one-msg", 1_000);
    seed_message(&db, conv_b, "channel-two-msg", 2_000);

    let channel_id = Uuid::now_v7();
    let mut channels = HashMap::new();
    let mut set = HashSet::new();
    set.insert(conv_a.to_string());
    channels.insert(channel_id, set);
    let resolver = StaticConversationGroupResolver::new(channels, HashSet::new(), HashSet::new());

    let engine = QueryEngine::new(&db);
    let hits = engine
        .execute_search_with_target(
            &query_for("channel-one-msg"),
            &SearchScope::LocalOnly,
            &SearchTarget::Channel(channel_id),
            &resolver,
            200,
        )
        .unwrap();
    assert!(!hits.is_empty());
    for h in &hits {
        assert_eq!(h.conversation_id, conv_a);
    }
}

#[test]
fn search_query_target_field_is_threaded_through_default_execute_search() {
    let db = open_db();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    insert_conv(&db, a);
    insert_conv(&db, b);
    seed_message(&db, a, "thread-target", 1_000);
    seed_message(&db, b, "thread-target", 2_000);

    let mut q = query_for("thread-target");
    q.target = SearchTarget::Conversation(a);

    let engine = QueryEngine::new(&db);
    let hits = engine.execute_search(&q, &SearchScope::LocalOnly).unwrap();
    assert!(!hits.is_empty());
    for h in &hits {
        assert_eq!(h.conversation_id, a);
    }
}

#[test]
fn conversation_group_resolver_is_object_safe() {
    let r: Arc<dyn ConversationGroupResolver> = Arc::new(NoopConversationGroupResolver::new());
    let cid = Uuid::now_v7();
    let ch = r.resolve_channel(&cid).unwrap();
    assert!(ch.contains(&cid.to_string()));
}

#[test]
fn all_conversations_alias_equals_global() {
    assert_eq!(SearchTarget::all_conversations(), SearchTarget::Global);
}
