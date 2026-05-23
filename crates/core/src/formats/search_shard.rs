//! Encrypted search index shard wire format.
//!
//! Mirrors the JSON sketch in `docs/DESIGN.md §7.8` but written as
//! CBOR for on-disk / on-wire use. Conversion to / from the §7.8 JSON
//! shape is straightforward: the byte fields (`conversation_id_hash`,
//! `nonce`, `aad_hash`, `ciphertext`, `ciphertext_sha256`) are
//! base64-encoded strings in JSON and raw byte strings in CBOR.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::serde_bytes_array;

/// Magic string for [`SearchIndexShard`]. Stored as a UTF-8 string in
/// CBOR (rather than a fixed-size byte array) because the §7.8 JSON
/// sketch stores it as a string.
pub const SHARD_MAGIC: &str = "KCHAT_INDEX_SHARD_V1";

/// On-wire `version` field for [`SearchIndexShard`].
pub const SHARD_VERSION: u32 = 1;

/// Compression scheme applied inside the AEAD (`zstd`).
pub const SHARD_COMPRESSION: &str = "zstd";

/// AEAD construction used to seal the shard payload
/// (`xchacha20-poly1305`).
pub const SHARD_ENCRYPTION: &str = "xchacha20-poly1305";

/// Discriminant for the kinds of search index a shard can carry.
///
/// Adds [`IndexType::Bloom`]: a
/// per-`(conversation_id, time_bucket)` bloom filter built from
/// the lowercase word set of every `search_fts` row. Bloom shards
/// are fetched first by the prefetcher (see
/// [`crate::search::shard_prefetch`]) so that fan-out can skip
/// buckets whose filter rejects every query token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexType {
    /// Per-bucket bloom filter over `search_fts` words.
    /// fetched first so the prefetcher can skip buckets
    /// that cannot contain any query token.
    Bloom,
    /// FTS5 (or fallback `unicode61`) full-text index.
    Text,
    /// Trigram / bigram fuzzy index.
    Fuzzy,
    /// HNSW vector index (multilingual embeddings).
    Vector,
    /// Media OCR / transcript / caption index.
    Media,
}

impl IndexType {
    /// Iterate over every defined variant, in stable declaration
    /// order. Useful for property-style "every variant round-trips"
    /// tests.
    pub fn all() -> &'static [IndexType] {
        &[
            IndexType::Bloom,
            IndexType::Text,
            IndexType::Fuzzy,
            IndexType::Vector,
            IndexType::Media,
        ]
    }
}

/// Encrypted search index shard frame.
///
/// `conversation_id_hash` is the BLAKE3-keyed-hash of the conversation
/// id (per `docs/DESIGN.md §7.8`); the field is `Vec<u8>` (rather
/// than a fixed-size array) because the keyed hash output length is a
/// configuration knob the search layer owns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchIndexShard {
    /// Always [`SHARD_MAGIC`].
    pub magic: String,

    /// Always [`SHARD_VERSION`].
    pub version: u32,

    /// UUID v7 identifying this shard.
    pub shard_id: Uuid,

    /// Which kind of index this shard contains.
    pub index_type: IndexType,

    /// BLAKE3-keyed-hash of the conversation id under a per-account
    /// key. Raw bytes in CBOR; base64 in the JSON projection.
    #[serde(with = "serde_bytes")]
    pub conversation_id_hash: Vec<u8>,

    /// Coarse time bucket (e.g. `"2026-04"`).
    pub time_bucket: String,

    /// Number of plaintext docs covered by this shard.
    pub doc_count: u64,

    /// Compression algorithm — always [`SHARD_COMPRESSION`] in v1.
    pub compression: String,

    /// AEAD construction — always [`SHARD_ENCRYPTION`] in v1.
    pub encryption: String,

    /// 24-byte XChaCha20-Poly1305 nonce.
    #[serde(with = "serde_bytes_array")]
    pub nonce: [u8; 24],

    /// 32-byte BLAKE3 of the canonical AAD.
    #[serde(with = "serde_bytes_array")]
    pub aad_hash: [u8; 32],

    /// AEAD ciphertext sealed with the appropriate
    /// `K_*_index_shard(shard_id)` from
    /// [`crate::crypto::key_hierarchy`].
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,

    /// SHA-256 over `ciphertext`.
    #[serde(with = "serde_bytes_array")]
    pub ciphertext_sha256: [u8; 32],
}

impl SearchIndexShard {
    /// Whether the magic string and version match this build.
    pub fn has_valid_header(&self) -> bool {
        self.magic == SHARD_MAGIC
            && self.version == SHARD_VERSION
            && self.compression == SHARD_COMPRESSION
            && self.encryption == SHARD_ENCRYPTION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_shard(index_type: IndexType) -> SearchIndexShard {
        let seed = match index_type {
            IndexType::Bloom => 0x05,
            IndexType::Text => 0x10,
            IndexType::Fuzzy => 0x20,
            IndexType::Vector => 0x30,
            IndexType::Media => 0x40,
        };
        SearchIndexShard {
            magic: SHARD_MAGIC.to_string(),
            version: SHARD_VERSION,
            shard_id: Uuid::now_v7(),
            index_type,
            conversation_id_hash: vec![seed ^ 0xA5; 32],
            time_bucket: "2026-04".to_string(),
            doc_count: 12_000,
            compression: SHARD_COMPRESSION.to_string(),
            encryption: SHARD_ENCRYPTION.to_string(),
            nonce: [seed; 24],
            aad_hash: [seed.wrapping_add(1); 32],
            ciphertext: vec![seed.wrapping_add(2); 256],
            ciphertext_sha256: [seed.wrapping_add(3); 32],
        }
    }

    #[test]
    fn shard_round_trips_for_every_index_type() {
        for &it in IndexType::all() {
            let shard = sample_shard(it);
            let bytes = crate::cbor::to_vec(&shard).expect("encode");
            let decoded: SearchIndexShard = crate::cbor::from_slice(&bytes).expect("decode");
            assert_eq!(decoded, shard, "round-trip failed for {it:?}");
        }
    }

    #[test]
    fn shard_magic_and_version_are_v1() {
        let shard = sample_shard(IndexType::Text);
        assert_eq!(shard.magic, "KCHAT_INDEX_SHARD_V1");
        assert_eq!(shard.version, 1);
        assert!(shard.has_valid_header());
    }

    #[test]
    fn shard_rejects_wrong_magic() {
        let mut shard = sample_shard(IndexType::Vector);
        shard.magic = "NOT_KCHAT".to_string();
        assert!(!shard.has_valid_header());
    }

    #[test]
    fn shard_rejects_wrong_compression() {
        let mut shard = sample_shard(IndexType::Vector);
        shard.compression = "gzip".to_string();
        assert!(!shard.has_valid_header());
    }

    #[test]
    fn distinct_index_types_produce_distinct_cbor() {
        let bloom = crate::cbor::to_vec(&sample_shard(IndexType::Bloom)).unwrap();
        let text = crate::cbor::to_vec(&sample_shard(IndexType::Text)).unwrap();
        let fuzzy = crate::cbor::to_vec(&sample_shard(IndexType::Fuzzy)).unwrap();
        let vector = crate::cbor::to_vec(&sample_shard(IndexType::Vector)).unwrap();
        let media = crate::cbor::to_vec(&sample_shard(IndexType::Media)).unwrap();
        // No two encodings should match — the discriminant alone is
        // enough to disambiguate, and the seed-derived bytes
        // reinforce the split.
        let all = [&bloom, &text, &fuzzy, &vector, &media];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "shards {i} and {j} encode to the same CBOR");
            }
        }
    }

    #[test]
    fn index_type_round_trips_via_lowercase_string() {
        for &it in IndexType::all() {
            let bytes = crate::cbor::to_vec(&it).expect("encode");
            let decoded: IndexType = crate::cbor::from_slice(&bytes).expect("decode");
            assert_eq!(decoded, it);
        }
    }
}
