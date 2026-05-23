//! end-to-end integration tests.
//!
//! Covers the new multi-scope search machinery introduced
//! across batch 6:
//!
//! 1. community-scoped target,
//! 2. domain-scoped target,
//! 3. tenant-scoped target,
//! 4. `Global` target,
//! 5. bloom-filter pre-check eliminating irrelevant cold buckets,
//! 6. shard cache eliminating refetch on repeated search,
//! 7. tenant policy blocking `Global`,
//! 8. date pruning skipping out-of-range buckets,
//! 9. B2B per-tenant key isolation,
//! 10. scope-proportional padding scaling with target.
//!
//! These tests build directly on the public `kchat_core` API
//! they intentionally avoid `CoreImpl` so the assertions stay
//! focused on the search engine, the cold-source contract, and
//! the cache / policy enforcement points.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use uuid::Uuid;

use kchat_core::config::{PrivacyLevel, TenantSearchPolicy};
use kchat_core::crypto::key_hierarchy::{
    derive_b2b_text_index_shard, derive_search_root, derive_text_index_shard, KeyMaterial,
};
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::search::query_engine::{bucket_overlaps_date_range, ColdShardSource, QueryEngine};
use kchat_core::search::search_target::NoopConversationGroupResolver;
use kchat_core::search::shard_builder::{
    build_bloom_shard, build_text_search_shard, restore_bloom_shard, restore_text_search_shard,
    BloomFilter, BuiltShard, FtsRow, FuzzyRow,
};
use kchat_core::search::shard_cache::{CachedShard, ShardCache, ShardCacheKey};
use kchat_core::search::shard_prefetch::compute_scope_padding_multiplier;
use kchat_core::{Error, SearchQuery, SearchScope, SearchTarget};

const DB_KEY: [u8; 32] = [0x33; 32];

fn open_db() -> LocalStoreDb {
    LocalStoreDb::open_in_memory(&DB_KEY).expect("open in-memory db")
}

fn insert_conv_with_scope(
    db: &LocalStoreDb,
    conv: Uuid,
    community: Option<Uuid>,
    domain: Option<Uuid>,
    tenant: Option<&str>,
    scope: &str,
) {
    db.insert_conversation(&Conversation {
        conversation_id: conv.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms: 0,
        conversation_type: "group".into(),
        scope: scope.into(),
        tenant_id: tenant.map(str::to_string).unwrap_or_default(),
        community_id: community.map(|c| c.to_string()).unwrap_or_default(),
        domain_id: domain.map(|d| d.to_string()).unwrap_or_default(),
    })
    .unwrap();
}

fn seed(db: &LocalStoreDb, conv: Uuid, body: &str, ts_ms: i64) {
    let p = MessagePersister::new(db);
    p.persist_ingested_message(&IngestedMessage {
        message_id: Uuid::now_v7(),
        conversation_id: conv,
        sender_id: "u".into(),
        created_at_ms: ts_ms,
        text_content: Some(body.into()),
        media_descriptors: Vec::new(),
        reply_to: None,
    })
    .unwrap();
}

fn q(s: &str, target: SearchTarget) -> SearchQuery {
    SearchQuery {
        query_string: s.into(),
        target,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// 1. community_scoped_search_returns_only_community_conversations
// ---------------------------------------------------------------------------

#[test]
fn community_scoped_search_returns_only_community_conversations() {
    let db = open_db();
    let community_a = Uuid::now_v7();
    let community_b = Uuid::now_v7();
    let conv_a = Uuid::now_v7();
    let conv_b = Uuid::now_v7();
    insert_conv_with_scope(&db, conv_a, Some(community_a), None, None, "b2c");
    insert_conv_with_scope(&db, conv_b, Some(community_b), None, None, "b2c");
    seed(&db, conv_a, "needle in community a", 1);
    seed(&db, conv_b, "needle in community b", 2);

    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let resolver = NoopConversationGroupResolver::new();
    let hits = engine
        .execute_search_with_target(
            &q("needle", SearchTarget::Community(community_a)),
            &SearchScope::LocalOnly,
            &SearchTarget::Community(community_a),
            &resolver,
            200,
        )
        .unwrap();
    assert!(!hits.is_empty(), "community a must have at least one hit");
    for h in &hits {
        assert_eq!(h.conversation_id, conv_a, "non-community-a leaked");
    }
}

// ---------------------------------------------------------------------------
// 2. domain_scoped_search_returns_only_domain_conversations
// ---------------------------------------------------------------------------

#[test]
fn domain_scoped_search_returns_only_domain_conversations() {
    let db = open_db();
    let domain_a = Uuid::now_v7();
    let domain_b = Uuid::now_v7();
    let conv_a = Uuid::now_v7();
    let conv_b = Uuid::now_v7();
    insert_conv_with_scope(&db, conv_a, None, Some(domain_a), None, "b2c");
    insert_conv_with_scope(&db, conv_b, None, Some(domain_b), None, "b2c");
    seed(&db, conv_a, "needle in domain a", 1);
    seed(&db, conv_b, "needle in domain b", 2);

    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let resolver = NoopConversationGroupResolver::new();
    let hits = engine
        .execute_search_with_target(
            &q("needle", SearchTarget::Domain(domain_a)),
            &SearchScope::LocalOnly,
            &SearchTarget::Domain(domain_a),
            &resolver,
            200,
        )
        .unwrap();
    assert!(!hits.is_empty());
    for h in &hits {
        assert_eq!(h.conversation_id, conv_a, "non-domain-a leaked");
    }
}

// ---------------------------------------------------------------------------
// 3. tenant_scoped_search_returns_only_tenant_conversations
// ---------------------------------------------------------------------------

#[test]
fn tenant_scoped_search_returns_only_tenant_conversations() {
    let db = open_db();
    let conv_a = Uuid::now_v7();
    let conv_b = Uuid::now_v7();
    insert_conv_with_scope(&db, conv_a, None, None, Some("tenant-acme"), "b2b");
    insert_conv_with_scope(&db, conv_b, None, None, Some("tenant-globex"), "b2b");
    seed(&db, conv_a, "needle in acme", 1);
    seed(&db, conv_b, "needle in globex", 2);

    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let resolver = NoopConversationGroupResolver::new();
    let hits = engine
        .execute_search_with_target(
            &q("needle", SearchTarget::Tenant("tenant-acme".into())),
            &SearchScope::LocalOnly,
            &SearchTarget::Tenant("tenant-acme".into()),
            &resolver,
            200,
        )
        .unwrap();
    assert!(!hits.is_empty());
    for h in &hits {
        assert_eq!(h.conversation_id, conv_a, "non-acme leaked");
    }
}

// ---------------------------------------------------------------------------
// 4. global_search_returns_all_conversations
// ---------------------------------------------------------------------------

#[test]
fn global_search_returns_all_conversations() {
    let db = open_db();
    let conv_a = Uuid::now_v7();
    let conv_b = Uuid::now_v7();
    insert_conv_with_scope(&db, conv_a, None, None, None, "b2c");
    insert_conv_with_scope(&db, conv_b, None, None, None, "b2c");
    seed(&db, conv_a, "shared needle alpha", 1);
    seed(&db, conv_b, "shared needle beta", 2);

    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let resolver = NoopConversationGroupResolver::new();
    let hits = engine
        .execute_search_with_target(
            &q("needle", SearchTarget::Global),
            &SearchScope::LocalOnly,
            &SearchTarget::Global,
            &resolver,
            200,
        )
        .unwrap();
    let convs: std::collections::HashSet<_> = hits.iter().map(|h| h.conversation_id).collect();
    assert!(convs.contains(&conv_a) && convs.contains(&conv_b));
}

// ---------------------------------------------------------------------------
// 5. bloom_filter_eliminates_irrelevant_cold_buckets
// ---------------------------------------------------------------------------

/// Counts every transport-shaped fetch the engine asks for.
/// The cold path consults bloom shards first; only the
/// bucket(s) whose bloom advertises the query word should pay
/// the text/fuzzy cost.
#[derive(Default)]
struct CountingBloomCatalog {
    text: HashMap<(String, String), Vec<FtsRow>>,
    fuzzy: HashMap<(String, String), Vec<FuzzyRow>>,
    bloom: HashMap<(String, String), BloomFilter>,
    text_calls: AtomicUsize,
    fuzzy_calls: AtomicUsize,
    bloom_calls: AtomicUsize,
}

impl ColdShardSource for CountingBloomCatalog {
    fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
        let mut keys: Vec<_> = self.text.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }
    fn fetch_text_rows(&self, c: &str, b: &str) -> Result<Vec<FtsRow>, Error> {
        self.text_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .text
            .get(&(c.into(), b.into()))
            .cloned()
            .unwrap_or_default())
    }
    fn fetch_fuzzy_rows(&self, c: &str, b: &str) -> Result<Vec<FuzzyRow>, Error> {
        self.fuzzy_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .fuzzy
            .get(&(c.into(), b.into()))
            .cloned()
            .unwrap_or_default())
    }
    fn fetch_bloom_shard(&self, c: &str, b: &str) -> Result<Option<BloomFilter>, Error> {
        self.bloom_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.bloom.get(&(c.into(), b.into())).cloned())
    }
}

fn build_bloom_for_words(conv: &str, bucket: &str, words: &[&str]) -> BloomFilter {
    let master = KeyMaterial::from_bytes([0x55; 32]);
    let search_root = derive_search_root(&master).unwrap();
    let key = derive_text_index_shard(&search_root, bucket.as_bytes()).unwrap();
    let conv_key = KeyMaterial::from_bytes([0x66; 32]);
    let built = build_bloom_shard(
        words.iter().map(|s| (*s).to_string()).collect(),
        128,
        conv,
        bucket.to_string(),
        &key,
        &conv_key,
    )
    .unwrap();
    restore_bloom_shard(&built.shard, &built.k_shard).unwrap()
}

#[test]
fn bloom_filter_eliminates_irrelevant_cold_buckets() {
    let db = open_db();
    let conv = Uuid::now_v7();
    insert_conv_with_scope(&db, conv, None, None, None, "b2c");

    let mut cat = CountingBloomCatalog::default();
    let conv_str = conv.to_string();
    // 5 buckets — only "2026-03" advertises "needle".
    for m in 1..=5u32 {
        let bucket = format!("2026-{m:02}");
        let words = if bucket == "2026-03" {
            vec!["needle", "alpha", "beta"]
        } else {
            vec!["alpha", "beta", "gamma"]
        };
        let rows = vec![FtsRow {
            message_id: format!("msg-{m}"),
            conversation_id: conv_str.clone(),
            sender_id: "u".into(),
            created_at_ms: 0,
            text_content: words.join(" "),
        }];
        cat.text.insert((conv_str.clone(), bucket.clone()), rows);
        cat.bloom.insert(
            (conv_str.clone(), bucket.clone()),
            build_bloom_for_words(&conv_str, &bucket, &words),
        );
    }

    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let q = q("needle", SearchTarget::Global);
    let _ = engine
        .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &cat)
        .unwrap();

    // 5 bloom probes (one per bucket), but only 1 text fetch
    // (the bucket whose bloom advertised "needle").
    assert_eq!(cat.bloom_calls.load(Ordering::Relaxed), 5);
    assert_eq!(
        cat.text_calls.load(Ordering::Relaxed),
        1,
        "bloom must have eliminated 4/5 buckets"
    );
}

// ---------------------------------------------------------------------------
// 6. shard_cache_eliminates_refetch_on_repeated_search
// ---------------------------------------------------------------------------

#[test]
fn shard_cache_eliminates_refetch_on_repeated_search() {
    let db = open_db();
    let conv = Uuid::now_v7();
    insert_conv_with_scope(&db, conv, None, None, None, "b2c");

    let mut cat = CountingBloomCatalog::default();
    let conv_str = conv.to_string();
    let bucket = "2026-04";
    let words = vec!["needle", "alpha"];
    cat.text.insert(
        (conv_str.clone(), bucket.into()),
        vec![FtsRow {
            message_id: "msg-1".into(),
            conversation_id: conv_str.clone(),
            sender_id: "u".into(),
            created_at_ms: 0,
            text_content: words.join(" "),
        }],
    );
    cat.bloom.insert(
        (conv_str.clone(), bucket.into()),
        build_bloom_for_words(&conv_str, bucket, &words),
    );

    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let cache = Mutex::new(ShardCache::new(8 * 1024 * 1024));
    let policy = TenantSearchPolicy::default();
    let q = q("needle", SearchTarget::Global);

    // First search: 1 text + 1 bloom fetch.
    let _ = engine
        .execute_search_with_cold_source_full(
            &q,
            &SearchScope::IncludeCold,
            &cat,
            &policy,
            Some(&cache),
            200,
        )
        .unwrap();
    let after_first_text = cat.text_calls.load(Ordering::Relaxed);
    let after_first_bloom = cat.bloom_calls.load(Ordering::Relaxed);

    // Second search: cache must absorb both fetches.
    let _ = engine
        .execute_search_with_cold_source_full(
            &q,
            &SearchScope::IncludeCold,
            &cat,
            &policy,
            Some(&cache),
            200,
        )
        .unwrap();
    assert_eq!(
        cat.text_calls.load(Ordering::Relaxed),
        after_first_text,
        "second search must hit the text-row cache"
    );
    assert_eq!(
        cat.bloom_calls.load(Ordering::Relaxed),
        after_first_bloom,
        "second search must hit the bloom cache"
    );
}

// ---------------------------------------------------------------------------
// 7. tenant_policy_blocks_global_search
// ---------------------------------------------------------------------------

#[test]
fn tenant_policy_blocks_global_search() {
    let db = open_db();
    let conv = Uuid::now_v7();
    insert_conv_with_scope(&db, conv, None, None, None, "b2c");

    let mut cat = CountingBloomCatalog::default();
    let conv_str = conv.to_string();
    cat.text.insert(
        (conv_str.clone(), "2026-04".into()),
        vec![FtsRow {
            message_id: "m".into(),
            conversation_id: conv_str.clone(),
            sender_id: "u".into(),
            created_at_ms: 0,
            text_content: "needle".into(),
        }],
    );

    let engine = QueryEngine::new(db.connection(), db.icu_available());
    let policy = TenantSearchPolicy {
        allow_global_search: false,
        ..TenantSearchPolicy::default()
    };
    let q = q("needle", SearchTarget::Global);
    let hits = engine
        .execute_search_with_cold_source_full(
            &q,
            &SearchScope::IncludeCold,
            &cat,
            &policy,
            None,
            200,
        )
        .unwrap();

    assert!(
        hits.iter().all(|h| !h.is_cold),
        "policy must reject cold fan-out for Global"
    );
    assert_eq!(
        cat.text_calls.load(Ordering::Relaxed),
        0,
        "no cold text fetch when Global is blocked"
    );
}

// ---------------------------------------------------------------------------
// 8. date_pruning_skips_old_buckets
// ---------------------------------------------------------------------------

#[test]
fn date_pruning_skips_old_buckets() {
    // Direct exercise of `bucket_overlaps_date_range` — the
    // pruning predicate the engine uses to drop irrelevant
    // buckets before any transport call.
    let buckets = (1..=12).map(|m| format!("2024-{m:02}")).collect::<Vec<_>>();
    // Window: March-April 2024 only.
    let from_ms = days_from_civil(2024, 3, 1) * 86_400_000;
    let to_ms = days_from_civil(2024, 4, 30) * 86_400_000;
    let kept: Vec<_> = buckets
        .iter()
        .filter(|b| bucket_overlaps_date_range(b, Some(from_ms), Some(to_ms)))
        .collect();
    assert_eq!(
        kept,
        vec![&"2024-03".to_string(), &"2024-04".to_string()],
        "only March-April should pass the date filter"
    );
}

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
// 9. b2b_tenant_key_isolation
// ---------------------------------------------------------------------------

#[test]
fn b2b_tenant_key_isolation() {
    // Build a B2B text shard sealed under tenant A's key, then
    // assert tenant B's key cannot decrypt it.
    let master = KeyMaterial::from_bytes([0x77; 32]);
    let search_root = derive_search_root(&master).unwrap();
    let shard_id = "shard-shared-id";
    let key_a = derive_b2b_text_index_shard(&search_root, "tenant-a", shard_id).unwrap();
    let key_b = derive_b2b_text_index_shard(&search_root, "tenant-b", shard_id).unwrap();
    assert_ne!(
        key_a.as_bytes(),
        key_b.as_bytes(),
        "per-tenant keys must not collide"
    );

    let conv = Uuid::now_v7().to_string();
    let conv_key = KeyMaterial::from_bytes([0x88; 32]);
    let rows = vec![FtsRow {
        message_id: "m1".into(),
        conversation_id: conv.clone(),
        sender_id: "alice".into(),
        created_at_ms: 0,
        text_content: "tenant-a confidential".into(),
    }];
    let BuiltShard { shard, .. } =
        build_text_search_shard(rows.clone(), &conv, "2026-04", &key_a, &conv_key).unwrap();

    let restored_a = restore_text_search_shard(&shard, &key_a).expect("tenant a opens own shard");
    assert_eq!(restored_a.len(), 1);

    let err = restore_text_search_shard(&shard, &key_b);
    assert!(
        err.is_err(),
        "tenant b must NOT be able to decrypt tenant a's shard"
    );
}

// ---------------------------------------------------------------------------
// 10. scope_proportional_padding_scales_with_target
// ---------------------------------------------------------------------------

#[test]
fn scope_proportional_padding_scales_with_target() {
    // dummy padding scales with the
    // scope's privacy surface. Conversation = 1×, Global = 4×.
    // The unit-level test in `shard_prefetch::tests` exercises
    // the transport-recording path; here we lock the policy
    // contract at the integration boundary.
    let conv_target = SearchTarget::Conversation(Uuid::now_v7());
    let global_target = SearchTarget::Global;

    assert_eq!(compute_scope_padding_multiplier(&conv_target), 1);
    assert_eq!(compute_scope_padding_multiplier(&global_target), 4);
    assert!(
        compute_scope_padding_multiplier(&global_target)
            > compute_scope_padding_multiplier(&conv_target),
        "Global must out-pad Conversation so cover-traffic \
         hides the wider access pattern (PrivacyLevel = {:?})",
        PrivacyLevel::High,
    );
}

// ---------------------------------------------------------------------------
// helper: keep the unused-import lint happy when individual tests
// are stripped via cargo test --test
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn _link_cache(key: ShardCacheKey) -> ShardCacheKey {
    let _ = CachedShard::Text(Vec::<FtsRow>::new());
    key
}
