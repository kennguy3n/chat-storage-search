//! Integration test for the Phase 5, Task 1 cold-bucket search
//! fan-out.
//!
//! End-to-end exercise of [`QueryEngine::execute_search_with_cold_source`]
//! on top of real encrypted-shard build / restore primitives. We
//!
//! 1. Open an in-memory `LocalStoreDb` (ICU may or may not be
//!    available — the tests stay on terms FTS5 will accept either
//!    way).
//! 2. Build an FTS shard and a fuzzy shard for a single
//!    `(conversation_id, time_bucket)` using
//!    [`build_text_search_shard`] / [`build_fuzzy_search_shard`].
//! 3. Stand up an in-process [`ColdShardSource`] that calls
//!    [`restore_text_search_shard`] /
//!    [`restore_fuzzy_search_shard`] on the encrypted blobs (so the
//!    decrypt path is the actual production code, not a mock).
//! 4. Run the unified search via
//!    [`QueryEngine::execute_search_with_cold_source`] and verify
//!    that:
//!    * `IncludeCold` returns the shard rows with `is_cold = true`.
//!    * `LocalOnly` skips the cold source entirely.
//!    * Conversation-filter scoping reaches into the cold path.

use std::collections::HashMap;

use kchat_core::crypto::key_hierarchy::{derive_search_root, derive_text_index_shard, KeyMaterial};
use kchat_core::formats::search_shard::SearchIndexShard;
use kchat_core::local_store::db::LocalStoreDb;
use kchat_core::local_store::schema::Conversation;
use kchat_core::message::processor::{IngestedMessage, MessagePersister};
use kchat_core::search::query_engine::{ColdShardSource, QueryEngine};
use kchat_core::search::shard_builder::{
    build_fuzzy_search_shard, build_text_search_shard, restore_fuzzy_search_shard,
    restore_text_search_shard, FtsRow, FuzzyRow,
};
use kchat_core::{ContentKind, Error, SearchQuery, SearchScope};
use uuid::Uuid;

const DB_KEY: [u8; 32] = [0x77; 32];

/// In-test [`ColdShardSource`] that decrypts encrypted shards on
/// demand. Mirrors what `core_impl::CoreImpl` does: the shard
/// blob lives "remote" (in a HashMap) and the key lives in a
/// per-shard map.
struct EncryptedShardCatalog {
    text_blobs: HashMap<(String, String), (SearchIndexShard, KeyMaterial)>,
    fuzzy_blobs: HashMap<(String, String), (SearchIndexShard, KeyMaterial)>,
}

impl EncryptedShardCatalog {
    fn new() -> Self {
        Self {
            text_blobs: HashMap::new(),
            fuzzy_blobs: HashMap::new(),
        }
    }
    fn insert_text(
        &mut self,
        conversation_id: &str,
        time_bucket: &str,
        shard: SearchIndexShard,
        k: KeyMaterial,
    ) {
        self.text_blobs.insert(
            (conversation_id.to_string(), time_bucket.to_string()),
            (shard, k),
        );
    }
    fn insert_fuzzy(
        &mut self,
        conversation_id: &str,
        time_bucket: &str,
        shard: SearchIndexShard,
        k: KeyMaterial,
    ) {
        self.fuzzy_blobs.insert(
            (conversation_id.to_string(), time_bucket.to_string()),
            (shard, k),
        );
    }
}

impl ColdShardSource for EncryptedShardCatalog {
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
        let key = (conversation_id.to_string(), time_bucket.to_string());
        let Some((shard, k)) = self.fuzzy_blobs.get(&key) else {
            return Ok(Vec::new());
        };
        restore_fuzzy_search_shard(shard, k)
    }
}

#[test]
fn cold_shard_round_trip_returns_decrypted_results() {
    let identity = KeyMaterial::from_bytes([0xAB; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_hash_key = KeyMaterial::from_bytes([0xCD; 32]);

    let conv_id = Uuid::now_v7().to_string();
    let bucket = "2026-04";
    let cold_mid = Uuid::now_v7();

    // Build the text shard.
    let text_shard_id = Uuid::now_v7();
    let k_text = derive_text_index_shard(&search_root, text_shard_id.as_bytes()).unwrap();
    let fts_rows = vec![FtsRow {
        message_id: cold_mid.to_string(),
        conversation_id: conv_id.clone(),
        sender_id: "alice".into(),
        created_at_ms: 1_700_000_000_000,
        text_content: "lighthouse beacon shines bright".into(),
    }];
    let text_built =
        build_text_search_shard(fts_rows, &conv_id, bucket, &k_text, &conv_hash_key).unwrap();

    // Build the fuzzy shard with hand-rolled n-grams matching the
    // text payload.
    let fuzzy_shard_id = Uuid::now_v7();
    let k_fuzzy = derive_text_index_shard(&search_root, fuzzy_shard_id.as_bytes()).unwrap();
    let fuzzy_rows = vec![
        FuzzyRow {
            token: "lig".into(),
            script: "Latn".into(),
            message_id: cold_mid.to_string(),
        },
        FuzzyRow {
            token: "igh".into(),
            script: "Latn".into(),
            message_id: cold_mid.to_string(),
        },
        FuzzyRow {
            token: "ght".into(),
            script: "Latn".into(),
            message_id: cold_mid.to_string(),
        },
    ];
    let fuzzy_built =
        build_fuzzy_search_shard(fuzzy_rows, &conv_id, bucket, &k_fuzzy, &conv_hash_key).unwrap();

    let mut catalog = EncryptedShardCatalog::new();
    catalog.insert_text(&conv_id, bucket, text_built.shard, text_built.k_shard);
    catalog.insert_fuzzy(&conv_id, bucket, fuzzy_built.shard, fuzzy_built.k_shard);

    // Fresh local store with no rows — every hit must come from
    // the cold path.
    let db = LocalStoreDb::open_in_memory(&DB_KEY).unwrap();
    let engine = QueryEngine::new(&db);

    let q = SearchQuery {
        query_string: "lighthouse".into(),
        ..Default::default()
    };
    let results = engine
        .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
        .expect("cold fan-out must succeed");

    assert_eq!(
        results.len(),
        1,
        "exactly one cold row should match `lighthouse`",
    );
    let row = &results[0];
    assert_eq!(row.message_id, cold_mid);
    assert_eq!(row.conversation_id.to_string(), conv_id);
    assert!(row.is_cold);
    assert_eq!(row.sender_id, "alice");
    assert_eq!(row.created_at_ms, 1_700_000_000_000);
    assert!(
        row.rank_score > 0.0,
        "merged rank must be strictly positive"
    );
}

#[test]
fn cold_shard_local_only_skips_decryption() {
    // LocalOnly is the offline-only contract. Even when the
    // catalog has the row, we must not call into the decrypt
    // path.
    struct PoisonedCatalog;
    impl ColdShardSource for PoisonedCatalog {
        fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
            panic!("cold_buckets called under LocalOnly");
        }
        fn fetch_text_rows(
            &self,
            _conversation_id: &str,
            _time_bucket: &str,
        ) -> Result<Vec<FtsRow>, Error> {
            panic!("fetch_text_rows called under LocalOnly");
        }
        fn fetch_fuzzy_rows(
            &self,
            _conversation_id: &str,
            _time_bucket: &str,
        ) -> Result<Vec<FuzzyRow>, Error> {
            panic!("fetch_fuzzy_rows called under LocalOnly");
        }
    }

    let db = LocalStoreDb::open_in_memory(&DB_KEY).unwrap();
    let engine = QueryEngine::new(&db);

    let q = SearchQuery {
        query_string: "lighthouse".into(),
        ..Default::default()
    };
    // Must not panic — the LocalOnly branch must short-circuit
    // before any cold source method is called.
    let results = engine
        .execute_search_with_cold_source(&q, &SearchScope::LocalOnly, &PoisonedCatalog)
        .unwrap();
    assert!(results.is_empty());
}

#[test]
fn cold_shard_conversation_filter_scopes_fan_out() {
    let identity = KeyMaterial::from_bytes([0xCC; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_hash_key = KeyMaterial::from_bytes([0xDD; 32]);

    let conv_a = Uuid::now_v7();
    let conv_b = Uuid::now_v7();
    let mid_a = Uuid::now_v7();
    let mid_b = Uuid::now_v7();
    let bucket = "2026-04";

    let mut catalog = EncryptedShardCatalog::new();

    for (conv, mid, sender) in [(conv_a, mid_a, "alice"), (conv_b, mid_b, "bob")] {
        let shard_id = Uuid::now_v7();
        let k = derive_text_index_shard(&search_root, shard_id.as_bytes()).unwrap();
        let rows = vec![FtsRow {
            message_id: mid.to_string(),
            conversation_id: conv.to_string(),
            sender_id: sender.into(),
            created_at_ms: 1,
            text_content: "lighthouse".into(),
        }];
        let built =
            build_text_search_shard(rows, &conv.to_string(), bucket, &k, &conv_hash_key).unwrap();
        catalog.insert_text(&conv.to_string(), bucket, built.shard, built.k_shard);
    }

    let db = LocalStoreDb::open_in_memory(&DB_KEY).unwrap();
    let engine = QueryEngine::new(&db);

    let q = SearchQuery {
        query_string: "lighthouse".into(),
        conversation_filter: Some(conv_a),
        ..Default::default()
    };
    let results = engine
        .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
        .unwrap();
    assert_eq!(results.len(), 1, "filter must scope cold buckets");
    assert_eq!(results[0].message_id, mid_a);
}

/// Phase 5, Task 1 regression: a message that exists in **both**
/// the local FTS / fuzzy result set and a cold shard for the same
/// `(conversation_id, time_bucket)` must
///
/// 1. Stay marked `is_cold = false` (its body is local — the
///    hydration queue must not enqueue work for it).
/// 2. Have its rank score *increase* relative to the local-only
///    pass (the cold contribution should accumulate).
/// 3. **Not** have the Task-3 recency × kind weighting applied a
///    second time on top of the local pass.
///
/// The pre-fix code paths (`merge_cold_hit` flipped `is_cold`
/// unconditionally; `apply_cold_recency_weight` keyed off
/// `is_cold`) caused condition 1 and 3 to fail. This test pins
/// the corrected contract end-to-end.
#[test]
fn cold_shard_merge_does_not_double_weight_local_rows() {
    let identity = KeyMaterial::from_bytes([0xEF; 32]);
    let search_root = derive_search_root(&identity).unwrap();
    let conv_hash_key = KeyMaterial::from_bytes([0xBA; 32]);

    let conv_id = Uuid::now_v7();
    let bucket = "2026-04";
    // Pin the timestamp so the recency component is deterministic
    // across invocations.
    let created_at_ms = 1_700_000_000_000_i64;
    let text = "lighthouse beacon shines bright";

    // Seed the local store with a single ingested message via
    // the production MessagePersister path so FTS + fuzzy rows
    // are populated under the local pipeline.
    let db = LocalStoreDb::open_in_memory(&DB_KEY).unwrap();
    db.insert_conversation(&Conversation {
        conversation_id: conv_id.to_string(),
        title_cipher: None,
        pinned: false,
        muted: false,
        last_message_id: None,
        last_activity_ms: created_at_ms,
        ..Default::default()
    })
    .unwrap();
    let persister = MessagePersister::new(&db);
    let mid = Uuid::now_v7();
    persister
        .persist_ingested_message(&IngestedMessage {
            message_id: mid,
            conversation_id: conv_id,
            sender_id: "alice".into(),
            created_at_ms,
            text_content: Some(text.into()),
            media_descriptors: vec![],
            reply_to: None,
        })
        .unwrap();

    // Build a cold shard for the *same* (conversation, bucket,
    // message_id, content) so the cold fan-out hits the row that
    // is also in the local result set.
    let text_shard_id = Uuid::now_v7();
    let k_text = derive_text_index_shard(&search_root, text_shard_id.as_bytes()).unwrap();
    let fts_rows = vec![FtsRow {
        message_id: mid.to_string(),
        conversation_id: conv_id.to_string(),
        sender_id: "alice".into(),
        created_at_ms,
        text_content: text.into(),
    }];
    let text_built = build_text_search_shard(
        fts_rows,
        &conv_id.to_string(),
        bucket,
        &k_text,
        &conv_hash_key,
    )
    .unwrap();

    let mut catalog = EncryptedShardCatalog::new();
    catalog.insert_text(
        &conv_id.to_string(),
        bucket,
        text_built.shard,
        text_built.k_shard,
    );

    let engine = QueryEngine::new(&db);
    let q = SearchQuery {
        query_string: "lighthouse".into(),
        ..Default::default()
    };

    // Baseline: local-only pass — already includes Task 3 recency
    // × kind weighting from `apply_recency_and_kind_weight`.
    let local_only = engine
        .execute_search(&q, &SearchScope::LocalOnly)
        .expect("local-only search must succeed");
    assert_eq!(local_only.len(), 1);
    let local_only_score = local_only[0].rank_score;
    assert!(
        local_only_score > 0.0,
        "local-only rank must be strictly positive"
    );
    assert!(
        !local_only[0].is_cold,
        "body is local — local-only result must not be flagged cold"
    );

    // Merged path: same row also surfaces from the cold shard.
    let merged = engine
        .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &catalog)
        .expect("cold fan-out must succeed");

    assert_eq!(merged.len(), 1, "deduplicated to one row by message_id");
    let row = &merged[0];
    assert_eq!(row.message_id, mid);

    // Contract 1: body is local → row must NOT be flagged cold.
    // Pre-fix this assertion failed because `merge_cold_hit`
    // flipped `is_cold` for every row that surfaced from a cold
    // shard, regardless of local availability.
    assert!(
        !row.is_cold,
        "row's body is local — merge_cold_hit must not flip is_cold to true \
         (would cause spurious P0 hydration enqueue)",
    );

    // Contract 2: cold contribution accumulated on top of local
    // contribution → merged rank > local-only rank.
    assert!(
        row.rank_score > local_only_score,
        "merged rank ({:.4}) must exceed local-only rank ({:.4}) — cold \
         contribution should accumulate",
        row.rank_score,
        local_only_score
    );

    // Contract 3: recency × kind must NOT have been applied a
    // second time. Pre-fix: `apply_cold_recency_weight` keyed off
    // `is_cold` (set by `merge_cold_hit`), re-multiplying the
    // already-weighted local contribution. Since the recency ×
    // kind factor is strictly < 1 for any non-zero age × text
    // kind, the buggy result would be:
    //
    //     merged_buggy = (local_only_score + raw_cold) * recency * kind
    //                  < local_only_score + raw_cold
    //
    // and could even fall below `local_only_score`. The fix path
    // sums raw cold contribution onto local without re-weighting
    // local, so the merged score is bounded above by
    // `local_only_score + (BM25_WEIGHT × matched_words)`. The
    // upper bound below is loose — `BM25_WEIGHT = 2.0` and
    // exactly one word ("lighthouse") matches in the cold shard,
    // so the raw cold contribution is `2.0`. We assert merged is
    // close to `local_only_score + 2.0` and not blown up by a
    // second-application factor.
    let raw_cold_contribution = 2.0_f64; // BM25_WEIGHT × 1 matched word
    let upper_bound = local_only_score + raw_cold_contribution + 1e-6;
    assert!(
        row.rank_score <= upper_bound,
        "merged rank ({:.4}) must not exceed local-only rank ({:.4}) plus \
         raw cold contribution ({:.4}); a higher value indicates the cold \
         path applied a multiplicative factor it should not have",
        row.rank_score,
        local_only_score,
        raw_cold_contribution
    );
    let lower_bound = local_only_score + raw_cold_contribution - 1e-6;
    assert!(
        row.rank_score >= lower_bound,
        "merged rank ({:.4}) must be at least local-only rank ({:.4}) plus \
         raw cold contribution ({:.4}); a lower value indicates the cold \
         path re-weighted (shrank) the local contribution",
        row.rank_score,
        local_only_score,
        raw_cold_contribution
    );
}

/// Phase 5, Task 1 contract: when the caller has narrowed the
/// search to a non-text content kind, the cold fan-out must
/// short-circuit before consulting `ColdShardSource`. Phase 5
/// only ships text + fuzzy cold shards, so any cold fetch on a
/// media-only query would (a) be wasted I/O and (b) leak text
/// hits through the kind filter that the local pass enforced via
/// `allowed_skeleton_ids`.
///
/// This test stands up a [`PoisonedCatalog`] that panics on every
/// trait method, runs the search with `content_kind =
/// ContentKind::Image`, and asserts the call returns `Ok` without
/// any cold method being invoked.
#[test]
fn cold_shard_skips_fan_out_for_non_text_kind() {
    /// Mock cold source that fails the test if any of its methods
    /// are called. Used to prove the cold path was never reached.
    struct PoisonedCatalog;
    impl ColdShardSource for PoisonedCatalog {
        fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
            panic!(
                "cold_buckets must not be called when content_kind is non-text \
                 (Phase 5 ships text + fuzzy cold shards only)"
            );
        }
        fn fetch_text_rows(
            &self,
            _conversation_id: &str,
            _time_bucket: &str,
        ) -> Result<Vec<FtsRow>, Error> {
            panic!("fetch_text_rows must not be called for non-text content_kind");
        }
        fn fetch_fuzzy_rows(
            &self,
            _conversation_id: &str,
            _time_bucket: &str,
        ) -> Result<Vec<FuzzyRow>, Error> {
            panic!("fetch_fuzzy_rows must not be called for non-text content_kind");
        }
    }

    let db = LocalStoreDb::open_in_memory(&DB_KEY).unwrap();
    let engine = QueryEngine::new(&db);

    // Image / Video / Audio / Document all map to the `media`
    // skeleton kind in Phase 1, and none of them have a cold
    // shard variant in Phase 5. Each must skip the cold fan-out.
    for kind in [
        ContentKind::Image,
        ContentKind::Video,
        ContentKind::Audio,
        ContentKind::Document,
    ] {
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            content_kind: Some(kind),
            ..Default::default()
        };
        // Must not panic — the early return must fire before any
        // ColdShardSource method is invoked.
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &PoisonedCatalog)
            .unwrap_or_else(|e| panic!("cold path must not error for kind {kind:?}: {e:?}"));
        assert!(
            results.is_empty(),
            "no local rows in this DB; cold fan-out short-circuited \
             for kind {kind:?} → result set must be empty"
        );
    }

    // Sanity: when content_kind is Text or Any, the cold path is
    // *expected* to run. Wire up a non-poisoned catalog and prove
    // the call still works (no early return for these kinds).
    struct EmptyCatalog;
    impl ColdShardSource for EmptyCatalog {
        fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
            Ok(Vec::new())
        }
        fn fetch_text_rows(
            &self,
            _conversation_id: &str,
            _time_bucket: &str,
        ) -> Result<Vec<FtsRow>, Error> {
            Ok(Vec::new())
        }
        fn fetch_fuzzy_rows(
            &self,
            _conversation_id: &str,
            _time_bucket: &str,
        ) -> Result<Vec<FuzzyRow>, Error> {
            Ok(Vec::new())
        }
    }
    for kind in [ContentKind::Text, ContentKind::Any] {
        let q = SearchQuery {
            query_string: "lighthouse".into(),
            content_kind: Some(kind),
            ..Default::default()
        };
        let results = engine
            .execute_search_with_cold_source(&q, &SearchScope::IncludeCold, &EmptyCatalog)
            .unwrap();
        assert!(results.is_empty());
    }
}
