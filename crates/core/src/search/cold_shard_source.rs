//! Transport-driven [`ColdShardSource`] adapter (Phase 5, Task 1).
//!
//! `docs/PHASES.md §Phase 5` calls for cold-result hydration to
//! "fetch the encrypted shard, decrypt with the right
//! `K_*_index_shard(shard_id)`, and replay into the in-process
//! merge". The query engine already accepts a [`ColdShardSource`]
//! abstraction; this module lands the adapter that bridges that
//! trait to the concrete
//! [`crate::transport::TransportClient::fetch_index_shards`] →
//! [`crate::search::shard_builder::restore_text_search_shard`] /
//! [`crate::search::shard_builder::restore_fuzzy_search_shard`]
//! pipeline so callers that already hold a `TransportClient` and a
//! per-shard key registry can wire the cold path in two function
//! calls instead of writing their own `ColdShardSource` impl.
//!
//! `TransportColdShardSource` keeps responsibilities narrow:
//!
//! * **It does not own keys.** Callers supply a
//!   [`ShardKeyRegistry`] mapping
//!   `(conversation_id, time_bucket, IndexType)` →
//!   [`KeyMaterial`] so the adapter never has to know about the
//!   `K_archive_root → K_search_root → K_text_index_shard(shard_id)`
//!   derivation tree.
//! * **It does not own the cold-bucket inventory.** The caller
//!   passes the list of `(conversation_id, time_bucket)` cold
//!   pairs up front — typically by querying
//!   `archive_segment_map` for rows whose local body is offloaded
//!   but whose search shard has been uploaded.
//! * **It decrypts on the fetch path.** Each
//!   [`ColdShardSource::fetch_text_rows`] /
//!   [`ColdShardSource::fetch_fuzzy_rows`] call hits
//!   `TransportClient::fetch_index_shards`, deserialises the
//!   returned bytes as [`SearchIndexShard`] CBOR, and runs the
//!   restore pipeline to recover the original FTS / fuzzy rows.
//! * **It treats "no shard on backend" as "no rows".** An empty
//!   transport response surfaces as `Ok(Vec::new())` per the
//!   contract on
//!   [`ColdShardSource::fetch_text_rows`].
//!
//! When the orchestration layer needs graceful degradation
//! (`docs/PHASES.md §Phase 7` failure suite — "search shard
//! missing from backend"), wrap this adapter in
//! [`GracefulCold`]. That wrapper swallows transient
//! `Error::Transport` / `Error::Storage` failures, logs them via
//! a callback the caller supplies, and returns
//! `Ok(Vec::new())` so the merge step still completes with
//! whatever local rows are available.

use std::collections::HashMap;

use crate::crypto::key_hierarchy::KeyMaterial;
use crate::formats::search_shard::{IndexType, SearchIndexShard};
use crate::search::query_engine::ColdShardSource;
use crate::search::shard_builder::{
    restore_fuzzy_search_shard, restore_text_search_shard, FtsRow, FuzzyRow,
};
use crate::transport::TransportClient;
use crate::Error;

/// Wire identifier the transport uses for a given shard type.
/// Mirrors the same mapping in
/// [`crate::search::shard_prefetch`] so the upload + fetch
/// addressing schemes agree.
fn shard_type_str(it: IndexType) -> &'static str {
    match it {
        IndexType::Text => "text",
        IndexType::Fuzzy => "fuzzy",
        IndexType::Vector => "vector",
        IndexType::Media => "media",
    }
}

/// Lookup table for `K_*_index_shard(shard_id)` keyed by
/// `(conversation_id, time_bucket, IndexType)`.
///
/// The orchestration layer is responsible for populating this
/// registry — typically by querying a `search_shard_map` table
/// keyed on the same triple. The adapter only ever reads from it;
/// missing entries surface as `Error::Storage` so callers detect
/// "we forgot to record the key" rather than silently returning
/// empty rows.
#[derive(Debug, Default, Clone)]
pub struct ShardKeyRegistry {
    keys: HashMap<(String, String, IndexType), KeyMaterial>,
}

impl ShardKeyRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one `(conversation_id, time_bucket, index_type) →
    /// k_shard` mapping.
    pub fn insert(
        &mut self,
        conversation_id: impl Into<String>,
        time_bucket: impl Into<String>,
        index_type: IndexType,
        k_shard: KeyMaterial,
    ) {
        self.keys.insert(
            (conversation_id.into(), time_bucket.into(), index_type),
            k_shard,
        );
    }

    /// Look up the per-shard key for the supplied triple.
    pub fn get(
        &self,
        conversation_id: &str,
        time_bucket: &str,
        index_type: IndexType,
    ) -> Option<&KeyMaterial> {
        self.keys
            .get(&(conversation_id.into(), time_bucket.into(), index_type))
    }
}

/// Transport-backed [`ColdShardSource`] implementation.
///
/// Instances borrow the transport, the key registry, and a
/// pre-computed list of cold buckets so the adapter is cheap to
/// construct per-query.
#[allow(missing_debug_implementations)] // dyn TransportClient is not Debug
pub struct TransportColdShardSource<'a> {
    /// Underlying transport for `fetch_index_shards`.
    transport: &'a dyn TransportClient,
    /// `(conversation_id, time_bucket)` pairs that should be
    /// fanned out for this query. The query engine deduplicates
    /// internally so duplicates here are harmless.
    cold_buckets: Vec<(String, String)>,
    /// Lookup for `K_*_index_shard(shard_id)`.
    key_registry: &'a ShardKeyRegistry,
    /// Per-account `K_conv_hash_key` used by
    /// [`crate::search::shard_builder::keyed_conversation_id_hash`]
    /// to map plaintext `conversation_id` → opaque
    /// `conversation_id_hash` the backend stores shards under.
    conversation_hash_key: &'a KeyMaterial,
}

impl<'a> TransportColdShardSource<'a> {
    /// Construct a new adapter.
    pub fn new(
        transport: &'a dyn TransportClient,
        cold_buckets: Vec<(String, String)>,
        key_registry: &'a ShardKeyRegistry,
        conversation_hash_key: &'a KeyMaterial,
    ) -> Self {
        Self {
            transport,
            cold_buckets,
            key_registry,
            conversation_hash_key,
        }
    }

    /// Fetch + decode a [`SearchIndexShard`] for the requested
    /// `(conversation_id, time_bucket, index_type)` triple.
    /// Returns `Ok(None)` when the backend has no bytes for the
    /// triple — the caller treats this as "no rows".
    fn fetch_shard(
        &self,
        conversation_id: &str,
        time_bucket: &str,
        index_type: IndexType,
    ) -> Result<Option<SearchIndexShard>, Error> {
        let conv_hash = crate::search::shard_builder::keyed_conversation_id_hash(
            conversation_id,
            self.conversation_hash_key,
        );
        let conv_hash_b64 = base64_encode_urlsafe(&conv_hash);
        let bytes = self.transport.fetch_index_shards(
            &conv_hash_b64,
            time_bucket,
            shard_type_str(index_type),
        )?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let shard: SearchIndexShard = serde_cbor::from_slice(&bytes).map_err(|e| {
            Error::Storage(format!(
                "TransportColdShardSource: shard cbor decode failed for ({conversation_id}, {time_bucket}, {index_type:?}): {e}"
            ))
        })?;
        Ok(Some(shard))
    }
}

impl ColdShardSource for TransportColdShardSource<'_> {
    fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
        Ok(self.cold_buckets.clone())
    }

    fn fetch_text_rows(
        &self,
        conversation_id: &str,
        time_bucket: &str,
    ) -> Result<Vec<FtsRow>, Error> {
        let Some(shard) = self.fetch_shard(conversation_id, time_bucket, IndexType::Text)? else {
            return Ok(Vec::new());
        };
        let k_shard = self
            .key_registry
            .get(conversation_id, time_bucket, IndexType::Text)
            .ok_or_else(|| {
                Error::Storage(format!(
                    "TransportColdShardSource: missing K_text_index_shard for ({conversation_id}, {time_bucket})"
                ))
            })?;
        restore_text_search_shard(&shard, k_shard)
    }

    fn fetch_fuzzy_rows(
        &self,
        conversation_id: &str,
        time_bucket: &str,
    ) -> Result<Vec<FuzzyRow>, Error> {
        let Some(shard) = self.fetch_shard(conversation_id, time_bucket, IndexType::Fuzzy)? else {
            return Ok(Vec::new());
        };
        let k_shard = self
            .key_registry
            .get(conversation_id, time_bucket, IndexType::Fuzzy)
            .ok_or_else(|| {
                Error::Storage(format!(
                    "TransportColdShardSource: missing K_fuzzy_index_shard for ({conversation_id}, {time_bucket})"
                ))
            })?;
        restore_fuzzy_search_shard(&shard, k_shard)
    }
}

/// URL-safe base64 (no padding) encoding of a byte slice.
///
/// Replicates the same alphabet the transport surface expects in
/// the `conversation_hash` parameter — RFC 4648 §5 with `=`
/// padding stripped, matching the wire shape used by the existing
/// search-shard fetch tests.
fn base64_encode_urlsafe(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let chunks = bytes.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let n = chunk.len();
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if n >= 2 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if n >= 3 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

#[allow(missing_debug_implementations)] // F is FnMut, not Debug
/// `ColdShardSource` wrapper that swallows transient transport /
/// storage failures and records them on a callback.
///
/// Used by the Phase-7 "search shard missing from backend"
/// scenario: the merge step still needs to return *something*
/// (the local rows), so the wrapper short-circuits the failed
/// fetch into `Ok(Vec::new())` instead of bubbling the error up.
///
/// The `on_failure` callback receives the
/// `(conversation_id, time_bucket, error)` triple so the
/// orchestration layer can attach a "results may be incomplete"
/// flag to the [`crate::SearchResult`] stream it returns to the
/// UI.
pub struct GracefulCold<'a, F: FnMut(&str, &str, &Error)> {
    inner: TransportColdShardSource<'a>,
    on_failure: std::cell::RefCell<F>,
}

impl<'a, F: FnMut(&str, &str, &Error)> GracefulCold<'a, F> {
    /// Wrap a [`TransportColdShardSource`] with graceful failure
    /// handling.
    pub fn new(inner: TransportColdShardSource<'a>, on_failure: F) -> Self {
        Self {
            inner,
            on_failure: std::cell::RefCell::new(on_failure),
        }
    }

    /// Inner adapter, exposed for tests that want to inspect the
    /// wrapped transport / registry.
    pub fn inner(&self) -> &TransportColdShardSource<'a> {
        &self.inner
    }
}

impl<F: FnMut(&str, &str, &Error)> ColdShardSource for GracefulCold<'_, F> {
    fn cold_buckets(&self) -> Result<Vec<(String, String)>, Error> {
        self.inner.cold_buckets()
    }

    fn fetch_text_rows(
        &self,
        conversation_id: &str,
        time_bucket: &str,
    ) -> Result<Vec<FtsRow>, Error> {
        match self.inner.fetch_text_rows(conversation_id, time_bucket) {
            Ok(rows) => Ok(rows),
            Err(ref e @ Error::Transport(_)) | Err(ref e @ Error::Storage(_)) => {
                // Forward the original error verbatim so the
                // orchestration layer's `on_failure` callback can
                // log the actual underlying message (e.g. the
                // upstream `"connection reset"`, `"404"`,
                // `"timeout"`) rather than a synthesized stub.
                (self.on_failure.borrow_mut())(conversation_id, time_bucket, e);
                Ok(Vec::new())
            }
            Err(other) => Err(other),
        }
    }

    fn fetch_fuzzy_rows(
        &self,
        conversation_id: &str,
        time_bucket: &str,
    ) -> Result<Vec<FuzzyRow>, Error> {
        match self.inner.fetch_fuzzy_rows(conversation_id, time_bucket) {
            Ok(rows) => Ok(rows),
            Err(ref e @ Error::Transport(_)) | Err(ref e @ Error::Storage(_)) => {
                (self.on_failure.borrow_mut())(conversation_id, time_bucket, e);
                Ok(Vec::new())
            }
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_hierarchy::{derive_search_root, derive_text_index_shard, KeyMaterial};
    use crate::search::shard_builder::{
        build_fuzzy_search_shard, build_text_search_shard, FtsRow, FuzzyRow,
    };
    use crate::transport::MockTransportClient;
    use uuid::Uuid;

    fn make_text_shard(
        conv_id: &str,
        bucket: &str,
        k_shard: &KeyMaterial,
        conv_hash_key: &KeyMaterial,
        text: &str,
    ) -> SearchIndexShard {
        let mid = Uuid::now_v7().to_string();
        let row = FtsRow {
            message_id: mid.clone(),
            conversation_id: conv_id.into(),
            sender_id: "user-1".into(),
            created_at_ms: 1_700_000_000_000,
            text_content: text.into(),
        };
        build_text_search_shard(vec![row], conv_id, bucket, k_shard, conv_hash_key)
            .expect("build text shard")
            .shard
    }

    fn make_fuzzy_shard(
        conv_id: &str,
        bucket: &str,
        k_shard: &KeyMaterial,
        conv_hash_key: &KeyMaterial,
    ) -> SearchIndexShard {
        let row = FuzzyRow {
            token: "abc".into(),
            script: "Latn".into(),
            message_id: Uuid::now_v7().to_string(),
        };
        build_fuzzy_search_shard(vec![row], conv_id, bucket, k_shard, conv_hash_key)
            .expect("build fuzzy shard")
            .shard
    }

    fn stage_shard_on_transport(
        transport: &MockTransportClient,
        conv_id: &str,
        bucket: &str,
        shard_type: IndexType,
        shard: &SearchIndexShard,
        conv_hash_key: &KeyMaterial,
    ) {
        let conv_hash =
            crate::search::shard_builder::keyed_conversation_id_hash(conv_id, conv_hash_key);
        let conv_hash_b64 = base64_encode_urlsafe(&conv_hash);
        let bytes = serde_cbor::to_vec(shard).expect("encode shard");
        transport.stage_index_shard(&conv_hash_b64, bucket, shard_type_str(shard_type), bytes);
    }

    #[test]
    fn transport_adapter_fetches_and_decrypts_text_shard() {
        let identity = KeyMaterial::from_bytes([0x77; 32]);
        let search_root = derive_search_root(&identity).unwrap();
        let conv_hash_key = KeyMaterial::from_bytes([0x88; 32]);
        let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";

        let shard = make_text_shard(
            &conv_id,
            bucket,
            &k_text,
            &conv_hash_key,
            "wendy lighthouse",
        );

        let transport = MockTransportClient::new();
        stage_shard_on_transport(
            &transport,
            &conv_id,
            bucket,
            IndexType::Text,
            &shard,
            &conv_hash_key,
        );

        let mut registry = ShardKeyRegistry::new();
        registry.insert(&conv_id, bucket, IndexType::Text, k_text);
        let adapter = TransportColdShardSource::new(
            &transport,
            vec![(conv_id.clone(), bucket.into())],
            &registry,
            &conv_hash_key,
        );
        let rows = adapter.fetch_text_rows(&conv_id, bucket).expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text_content, "wendy lighthouse");
        assert_eq!(rows[0].conversation_id, conv_id);
    }

    #[test]
    fn transport_adapter_returns_empty_when_backend_has_no_shard() {
        let conv_hash_key = KeyMaterial::from_bytes([0x88; 32]);
        let transport = MockTransportClient::new();
        let registry = ShardKeyRegistry::new();
        let adapter = TransportColdShardSource::new(
            &transport,
            vec![("conv-x".into(), "2026-04".into())],
            &registry,
            &conv_hash_key,
        );
        let rows = adapter.fetch_text_rows("conv-x", "2026-04").expect("rows");
        assert!(rows.is_empty());
    }

    #[test]
    fn transport_adapter_surfaces_missing_key_as_storage_error() {
        let identity = KeyMaterial::from_bytes([0x77; 32]);
        let search_root = derive_search_root(&identity).unwrap();
        let conv_hash_key = KeyMaterial::from_bytes([0x88; 32]);
        let k_text = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";

        let shard = make_text_shard(&conv_id, bucket, &k_text, &conv_hash_key, "missing-key");

        let transport = MockTransportClient::new();
        stage_shard_on_transport(
            &transport,
            &conv_id,
            bucket,
            IndexType::Text,
            &shard,
            &conv_hash_key,
        );

        // Empty registry — no key for this triple.
        let registry = ShardKeyRegistry::new();
        let adapter = TransportColdShardSource::new(
            &transport,
            vec![(conv_id.clone(), bucket.into())],
            &registry,
            &conv_hash_key,
        );
        let err = adapter.fetch_text_rows(&conv_id, bucket).unwrap_err();
        match err {
            Error::Storage(msg) => {
                assert!(msg.contains("K_text_index_shard"), "got: {msg}");
            }
            other => panic!("expected Error::Storage, got {other:?}"),
        }
    }

    #[test]
    fn graceful_wrapper_swallows_transport_errors() {
        let conv_hash_key = KeyMaterial::from_bytes([0x88; 32]);
        let conv_id = "conv-y";
        let bucket = "2026-04";

        let transport = MockTransportClient::new();
        // Programme a failure on the matching triple.
        let conv_hash =
            crate::search::shard_builder::keyed_conversation_id_hash(conv_id, &conv_hash_key);
        let conv_hash_b64 = base64_encode_urlsafe(&conv_hash);
        transport.fail_index_shard_fetch_with(
            &conv_hash_b64,
            bucket,
            shard_type_str(IndexType::Text),
            "connection reset",
        );

        let registry = ShardKeyRegistry::new();
        let inner = TransportColdShardSource::new(
            &transport,
            vec![(conv_id.into(), bucket.into())],
            &registry,
            &conv_hash_key,
        );
        let mut log: Vec<(String, String)> = Vec::new();
        // Use an Rc<RefCell<...>> to share the log buffer with the
        // closure, which the wrapper takes ownership of.
        let log_ref = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let log_for_closure = log_ref.clone();
        let graceful = GracefulCold::new(inner, move |c, b, _e| {
            log_for_closure.borrow_mut().push((c.into(), b.into()));
        });
        let rows = graceful.fetch_text_rows(conv_id, bucket).expect("rows");
        assert!(rows.is_empty(), "graceful should swallow the failure");

        log.extend(log_ref.borrow().iter().cloned());
        assert_eq!(log, vec![(conv_id.into(), bucket.into())]);
    }

    #[test]
    fn fuzzy_round_trip_through_adapter() {
        let identity = KeyMaterial::from_bytes([0xAA; 32]);
        let search_root = derive_search_root(&identity).unwrap();
        let conv_hash_key = KeyMaterial::from_bytes([0xBB; 32]);
        let k_fuzzy = derive_text_index_shard(&search_root, Uuid::now_v7().as_bytes()).unwrap();
        let conv_id = Uuid::now_v7().to_string();
        let bucket = "2026-04";

        let shard = make_fuzzy_shard(&conv_id, bucket, &k_fuzzy, &conv_hash_key);

        let transport = MockTransportClient::new();
        stage_shard_on_transport(
            &transport,
            &conv_id,
            bucket,
            IndexType::Fuzzy,
            &shard,
            &conv_hash_key,
        );
        let mut registry = ShardKeyRegistry::new();
        registry.insert(&conv_id, bucket, IndexType::Fuzzy, k_fuzzy);
        let adapter = TransportColdShardSource::new(
            &transport,
            vec![(conv_id.clone(), bucket.into())],
            &registry,
            &conv_hash_key,
        );
        let rows = adapter.fetch_fuzzy_rows(&conv_id, bucket).expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token, "abc");
    }
}
