//! Encrypted search-index shard build / restore (Phase 4, Task 6).
//!
//! `docs/PROPOSAL.md §7.8` describes the encrypted shard layer
//! that the cloud-backup / archive pipelines use to seal FTS and
//! fuzzy index rows. This module is the **runtime** counterpart
//! to [`crate::formats::search_shard::SearchIndexShard`] (the
//! wire format): it knows how to drain `search_fts` and
//! `search_fuzzy` rows for a `(conversation_id, time_bucket)`,
//! seal them into an [`SearchIndexShard`], and walk the inverse
//! path during restore.
//!
//! Sealing pipeline:
//!
//! 1. Read rows for the bucket from the local store.
//! 2. CBOR-encode the rows into an [`FtsShardPayload`] /
//!    [`FuzzyShardPayload`].
//! 3. zstd-compress the CBOR.
//! 4. AEAD-seal the compressed bytes with the appropriate
//!    `K_text_index_shard(shard_id)` /
//!    `K_fuzzy_index_shard(shard_id)` (Phase 4 reuses the
//!    text-index hierarchy for fuzzy shards until the per-fuzzy
//!    derivation lands in Phase 5).
//! 5. Wrap the ciphertext into a [`SearchIndexShard`] so the
//!    backup manifest can carry it.
//!
//! Restoration is the inverse: `K_*_index_shard(shard_id)` →
//! AEAD open → zstd decode → CBOR decode → row vector.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::aead::xchacha20_poly1305::{open, seal, KEY_LEN, NONCE_LEN};
use crate::crypto::content_hash::content_hash;
use crate::crypto::key_hierarchy::KeyMaterial;
use crate::formats::search_shard::{
    IndexType, SearchIndexShard, SHARD_COMPRESSION, SHARD_ENCRYPTION, SHARD_MAGIC, SHARD_VERSION,
};
use crate::Error;

/// zstd compression level used for the FTS and fuzzy shard
/// payloads. Mirrors
/// [`crate::backup::segment_builder::ZSTD_COMPRESSION_LEVEL`].
const SHARD_ZSTD_LEVEL: i32 = 3;

/// AAD magic prefix for FTS / fuzzy shard seals. Domain-separated
/// from the backup-segment AAD magic so a malicious sealer cannot
/// retag a backup segment as a search shard.
pub const SEARCH_SHARD_AAD_MAGIC: &[u8] = b"KCHAT_SEARCH_SHARD_AAD_V1";

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// One row of `search_fts` ready to seal into a text shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FtsRow {
    /// Message identifier (string form of the UUID v7).
    pub message_id: String,
    /// Conversation identifier (string form of the UUID v7).
    pub conversation_id: String,
    /// Sender identifier — same shape as
    /// [`crate::local_store::schema::MessageSkeleton::sender_id`].
    pub sender_id: String,
    /// Wall-clock timestamp the message was created (ms epoch).
    pub created_at_ms: i64,
    /// Plaintext text body.
    pub text_content: String,
}

/// One row of `search_fuzzy` ready to seal into a fuzzy shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyRow {
    /// N-gram token (already lowercased — see
    /// [`crate::search::fuzzy_search::FuzzyTokenizer`]).
    pub token: String,
    /// ISO-15924 script tag (text projection of
    /// [`crate::search::tokenizer::ScriptClass`]).
    pub script: String,
    /// Message identifier the token row belongs to.
    pub message_id: String,
}

/// One row of `search_vector` ready to seal into a vector
/// shard. Phase 6, Task 7.
///
/// `embedding` is the raw INT8-quantized blob — *not* the
/// dequantized `Vec<f32>`. Keeping the wire format identical to
/// the on-device cache layout means restore is a straight
/// byte-for-byte INSERT into `search_vector`; the dequantize +
/// re-quantize round trip would amplify the i8 boundary error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorRow {
    /// Message identifier this embedding belongs to.
    pub message_id: String,
    /// INT8-quantized embedding blob (`[scale: f32 LE, 4
    /// bytes][q: i8, dim bytes]` — see
    /// [`crate::models::embeddings::LocalStoreEmbeddingCache`]
    /// for the codec).
    #[serde(with = "serde_bytes")]
    pub embedding: Vec<u8>,
    /// Encoder revision tag (`"xlmr@v1"`,
    /// `"mobileclip_s2@v1"`, …). Carried verbatim so the
    /// restore path can preserve the cross-pipeline cache
    /// version-mismatch invariant.
    pub model_version: String,
}

/// One row of `media_search_index` ready to seal into a media
/// shard. Phase 6, Task 7.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaIndexRow {
    /// `media_asset.asset_id` for the row.
    pub asset_id: String,
    /// `'ocr' | 'caption' | 'transcript' | 'tag'`.
    pub kind: String,
    /// Recognized text.
    pub text: String,
    /// BCP-47 language tag, when the recognizer reported one.
    pub language: Option<String>,
    /// Per-row confidence, when the recognizer reported one.
    pub confidence: Option<f32>,
}

// ---------------------------------------------------------------------------
// Payload shapes (CBOR-sealed inside the shard ciphertext)
// ---------------------------------------------------------------------------

/// Domain-separation magic for [`FtsShardPayload`].
pub const TEXT_SHARD_PAYLOAD_MAGIC: &[u8] = b"KCHAT_TEXT_SHARD_PAYLOAD_V1";

/// Domain-separation magic for [`FuzzyShardPayload`].
pub const FUZZY_SHARD_PAYLOAD_MAGIC: &[u8] = b"KCHAT_FUZZY_SHARD_PAYLOAD_V1";

/// Domain-separation magic for [`VectorShardPayload`].
///
/// Phase 6, Task 7. Distinct from the text / fuzzy magics so a
/// malicious sealer cannot retag a vector shard as text (and
/// vice-versa) — the restore path checks the magic against the
/// expected discriminator before deserializing.
pub const VECTOR_SHARD_PAYLOAD_MAGIC: &[u8] = b"KCHAT_VECTOR_SHARD_PAYLOAD_V1";

/// Domain-separation magic for [`MediaShardPayload`].
pub const MEDIA_SHARD_PAYLOAD_MAGIC: &[u8] = b"KCHAT_MEDIA_SHARD_PAYLOAD_V1";

/// Domain-separation magic for [`BloomShardPayload`].
/// Phase 8 (2026-05-04 batch).
pub const BLOOM_SHARD_PAYLOAD_MAGIC: &[u8] = b"KCHAT_BLOOM_SHARD_PAYLOAD_V1";

/// CBOR-sealed plaintext of a text [`SearchIndexShard`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FtsShardPayload {
    /// Always [`TEXT_SHARD_PAYLOAD_MAGIC`].
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// FTS rows packed in this shard.
    pub rows: Vec<FtsRow>,
}

/// CBOR-sealed plaintext of a fuzzy [`SearchIndexShard`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyShardPayload {
    /// Always [`FUZZY_SHARD_PAYLOAD_MAGIC`].
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// Fuzzy n-gram rows packed in this shard.
    pub rows: Vec<FuzzyRow>,
}

/// CBOR-sealed plaintext of a vector [`SearchIndexShard`]
/// (Phase 6, Task 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorShardPayload {
    /// Always [`VECTOR_SHARD_PAYLOAD_MAGIC`].
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// `search_vector` rows packed in this shard.
    pub rows: Vec<VectorRow>,
}

/// CBOR-sealed plaintext of a media [`SearchIndexShard`]
/// (Phase 6, Task 7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaShardPayload {
    /// Always [`MEDIA_SHARD_PAYLOAD_MAGIC`].
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// `media_search_index` rows packed in this shard.
    pub rows: Vec<MediaIndexRow>,
}

/// CBOR-sealed plaintext of a bloom-filter [`SearchIndexShard`]
/// (Phase 8 — 2026-05-04 batch). The payload encodes the
/// in-memory [`BloomFilter`] as `(bit_count, hash_count, bits)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BloomShardPayload {
    /// Always [`BLOOM_SHARD_PAYLOAD_MAGIC`].
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// Number of bits in the filter (always a multiple of 8).
    pub bit_count: u64,
    /// Number of independent hash positions per inserted word.
    pub hash_count: u32,
    /// Packed bit array (`(bit_count + 7) / 8` bytes).
    #[serde(with = "serde_bytes")]
    pub bits: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Build / restore
// ---------------------------------------------------------------------------

/// Output of [`build_text_search_shard`] /
/// [`build_fuzzy_search_shard`].
#[derive(Debug, Clone)]
pub struct BuiltShard {
    /// Wire-format shard ready to attach to a backup manifest.
    pub shard: SearchIndexShard,
    /// `K_*_index_shard(shard_id)` the orchestrator just sealed
    /// the shard under. Phase 5 will move this into a
    /// `wrapped_k_shard` field on the manifest entry — until
    /// then the orchestrator keeps it in memory the same way the
    /// backup pipeline keeps `K_backup_segment` next to
    /// `BuiltBackupSegment` (Task 5).
    pub k_shard: KeyMaterial,
}

/// Compute the canonical AAD for a shard seal:
/// `SEARCH_SHARD_AAD_MAGIC || index_type_byte || shard_id(16) ||
/// conversation_id_hash || time_bucket`.
fn build_shard_aad(
    shard_id: &Uuid,
    index_type: IndexType,
    conversation_id_hash: &[u8],
    time_bucket: &str,
) -> Vec<u8> {
    let it_byte: u8 = match index_type {
        IndexType::Text => 1,
        IndexType::Fuzzy => 2,
        IndexType::Vector => 3,
        IndexType::Media => 4,
        IndexType::Bloom => 5,
    };
    let mut aad = Vec::with_capacity(
        SEARCH_SHARD_AAD_MAGIC.len() + 1 + 16 + conversation_id_hash.len() + time_bucket.len(),
    );
    aad.extend_from_slice(SEARCH_SHARD_AAD_MAGIC);
    aad.push(it_byte);
    aad.extend_from_slice(shard_id.as_bytes());
    aad.extend_from_slice(conversation_id_hash);
    aad.extend_from_slice(time_bucket.as_bytes());
    aad
}

/// BLAKE3-keyed-hash of a conversation id under
/// `conversation_hash_key`.
///
/// Stable across runs given the same inputs — the cold-shard
/// transport pipeline uses this to translate a plaintext
/// `conversation_id` into the opaque
/// `conversation_id_hash` the backend stores its shards under
/// (`docs/PROPOSAL.md §7.8`).
pub fn keyed_conversation_id_hash(
    conversation_id: &str,
    conversation_hash_key: &KeyMaterial,
) -> Vec<u8> {
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(conversation_hash_key.as_bytes());
    blake3::keyed_hash(&key, conversation_id.as_bytes())
        .as_bytes()
        .to_vec()
}

fn random_nonce() -> [u8; NONCE_LEN] {
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Seal `payload_cbor` into a [`SearchIndexShard`] under the
/// derived per-shard key.
fn seal_shard(
    rows_cbor: Vec<u8>,
    index_type: IndexType,
    conversation_id_hash: Vec<u8>,
    time_bucket: String,
    doc_count: u64,
    k_shard: &KeyMaterial,
) -> Result<SearchIndexShard, Error> {
    let compressed = zstd::stream::encode_all(&rows_cbor[..], SHARD_ZSTD_LEVEL).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::Zstd {
            context: "search shard encode",
            source: e,
        })
    })?;
    let shard_id = Uuid::now_v7();
    let nonce = random_nonce();
    let aad = build_shard_aad(&shard_id, index_type, &conversation_id_hash, &time_bucket);
    let aad_hash = content_hash(&aad);

    let ciphertext = seal(k_shard.as_bytes(), &nonce, &compressed, &aad).map_err(Error::Crypto)?;
    let ciphertext_sha256 = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&ciphertext);
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    };

    Ok(SearchIndexShard {
        magic: SHARD_MAGIC.to_string(),
        version: SHARD_VERSION,
        shard_id,
        index_type,
        conversation_id_hash,
        time_bucket,
        doc_count,
        compression: SHARD_COMPRESSION.to_string(),
        encryption: SHARD_ENCRYPTION.to_string(),
        nonce,
        aad_hash,
        ciphertext,
        ciphertext_sha256,
    })
}

/// Build an encrypted FTS shard from the supplied rows.
///
/// `k_text_index_shard` is the per-shard AEAD key — typically
/// `K_text_index_shard(shard_id)` from
/// [`crate::crypto::key_hierarchy::derive_text_index_shard`].
/// Because the shard generates its own `shard_id` internally
/// (mirroring [`crate::backup::segment_builder::BackupSegmentBuilder::build_segment`]),
/// the orchestrator stores `k_shard` alongside the shard so it
/// can re-open the seal without having to re-derive.
pub fn build_text_search_shard(
    rows: Vec<FtsRow>,
    conversation_id: &str,
    time_bucket: impl Into<String>,
    k_text_index_shard: &KeyMaterial,
    conversation_hash_key: &KeyMaterial,
) -> Result<BuiltShard, Error> {
    let payload = FtsShardPayload {
        magic: TEXT_SHARD_PAYLOAD_MAGIC.to_vec(),
        rows: rows.clone(),
    };
    let cbor = crate::cbor::to_vec(&payload).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborEncode {
            context: "text shard",
            source: e,
        })
    })?;
    let conversation_id_hash = keyed_conversation_id_hash(conversation_id, conversation_hash_key);
    let shard = seal_shard(
        cbor,
        IndexType::Text,
        conversation_id_hash,
        time_bucket.into(),
        rows.len() as u64,
        k_text_index_shard,
    )?;
    Ok(BuiltShard {
        shard,
        k_shard: k_text_index_shard.clone(),
    })
}

/// Build an encrypted fuzzy-token shard from the supplied rows.
pub fn build_fuzzy_search_shard(
    rows: Vec<FuzzyRow>,
    conversation_id: &str,
    time_bucket: impl Into<String>,
    k_fuzzy_index_shard: &KeyMaterial,
    conversation_hash_key: &KeyMaterial,
) -> Result<BuiltShard, Error> {
    let payload = FuzzyShardPayload {
        magic: FUZZY_SHARD_PAYLOAD_MAGIC.to_vec(),
        rows: rows.clone(),
    };
    let cbor = crate::cbor::to_vec(&payload).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborEncode {
            context: "fuzzy shard",
            source: e,
        })
    })?;
    let conversation_id_hash = keyed_conversation_id_hash(conversation_id, conversation_hash_key);
    let shard = seal_shard(
        cbor,
        IndexType::Fuzzy,
        conversation_id_hash,
        time_bucket.into(),
        rows.len() as u64,
        k_fuzzy_index_shard,
    )?;
    Ok(BuiltShard {
        shard,
        k_shard: k_fuzzy_index_shard.clone(),
    })
}

/// Decrypt + decompress + decode a text [`SearchIndexShard`]
/// previously built by [`build_text_search_shard`].
pub fn restore_text_search_shard(
    shard: &SearchIndexShard,
    k_text_index_shard: &KeyMaterial,
) -> Result<Vec<FtsRow>, Error> {
    if shard.index_type != IndexType::Text {
        return Err(Error::Storage(
            format!(
                "restore_text_search_shard: index_type {:?} != Text",
                shard.index_type
            )
            .into(),
        ));
    }
    let cbor = open_shard(shard, k_text_index_shard)?;
    let payload: FtsShardPayload = crate::cbor::from_slice(&cbor).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborDecode {
            context: "text shard",
            source: e,
        })
    })?;
    if payload.magic != TEXT_SHARD_PAYLOAD_MAGIC {
        return Err(Error::Storage("text shard payload magic mismatch".into()));
    }
    Ok(payload.rows)
}

/// Decrypt + decompress + decode a fuzzy [`SearchIndexShard`]
/// previously built by [`build_fuzzy_search_shard`].
pub fn restore_fuzzy_search_shard(
    shard: &SearchIndexShard,
    k_fuzzy_index_shard: &KeyMaterial,
) -> Result<Vec<FuzzyRow>, Error> {
    if shard.index_type != IndexType::Fuzzy {
        return Err(Error::Storage(
            format!(
                "restore_fuzzy_search_shard: index_type {:?} != Fuzzy",
                shard.index_type
            )
            .into(),
        ));
    }
    let cbor = open_shard(shard, k_fuzzy_index_shard)?;
    let payload: FuzzyShardPayload = crate::cbor::from_slice(&cbor).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborDecode {
            context: "fuzzy shard",
            source: e,
        })
    })?;
    if payload.magic != FUZZY_SHARD_PAYLOAD_MAGIC {
        return Err(Error::Storage("fuzzy shard payload magic mismatch".into()));
    }
    Ok(payload.rows)
}

/// Build an encrypted vector shard from the supplied rows.
/// Phase 6, Task 7.
///
/// `k_vector_index_shard` is the per-shard AEAD key, typically
/// `K_vector_index_shard(shard_id)` from
/// [`crate::crypto::key_hierarchy::derive_vector_index_shard`].
/// As with the text / fuzzy shard builders, the orchestrator
/// stores the returned `k_shard` next to the [`SearchIndexShard`]
/// so it can re-open the seal without re-deriving.
pub fn build_vector_search_shard(
    rows: Vec<VectorRow>,
    conversation_id: &str,
    time_bucket: impl Into<String>,
    k_vector_index_shard: &KeyMaterial,
    conversation_hash_key: &KeyMaterial,
) -> Result<BuiltShard, Error> {
    let payload = VectorShardPayload {
        magic: VECTOR_SHARD_PAYLOAD_MAGIC.to_vec(),
        rows: rows.clone(),
    };
    let cbor = crate::cbor::to_vec(&payload).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborEncode {
            context: "vector shard",
            source: e,
        })
    })?;
    let conversation_id_hash = keyed_conversation_id_hash(conversation_id, conversation_hash_key);
    let shard = seal_shard(
        cbor,
        IndexType::Vector,
        conversation_id_hash,
        time_bucket.into(),
        rows.len() as u64,
        k_vector_index_shard,
    )?;
    Ok(BuiltShard {
        shard,
        k_shard: k_vector_index_shard.clone(),
    })
}

/// Decrypt + decompress + decode a vector [`SearchIndexShard`]
/// previously built by [`build_vector_search_shard`].
pub fn restore_vector_search_shard(
    shard: &SearchIndexShard,
    k_vector_index_shard: &KeyMaterial,
) -> Result<Vec<VectorRow>, Error> {
    if shard.index_type != IndexType::Vector {
        return Err(Error::Storage(
            format!(
                "restore_vector_search_shard: index_type {:?} != Vector",
                shard.index_type
            )
            .into(),
        ));
    }
    let cbor = open_shard(shard, k_vector_index_shard)?;
    let payload: VectorShardPayload = crate::cbor::from_slice(&cbor).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborDecode {
            context: "vector shard",
            source: e,
        })
    })?;
    if payload.magic != VECTOR_SHARD_PAYLOAD_MAGIC {
        return Err(Error::Storage("vector shard payload magic mismatch".into()));
    }
    Ok(payload.rows)
}

/// Build an encrypted media shard from the supplied rows.
/// Phase 6, Task 7.
pub fn build_media_search_shard(
    rows: Vec<MediaIndexRow>,
    conversation_id: &str,
    time_bucket: impl Into<String>,
    k_media_index_shard: &KeyMaterial,
    conversation_hash_key: &KeyMaterial,
) -> Result<BuiltShard, Error> {
    let payload = MediaShardPayload {
        magic: MEDIA_SHARD_PAYLOAD_MAGIC.to_vec(),
        rows: rows.clone(),
    };
    let cbor = crate::cbor::to_vec(&payload).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborEncode {
            context: "media shard",
            source: e,
        })
    })?;
    let conversation_id_hash = keyed_conversation_id_hash(conversation_id, conversation_hash_key);
    let shard = seal_shard(
        cbor,
        IndexType::Media,
        conversation_id_hash,
        time_bucket.into(),
        rows.len() as u64,
        k_media_index_shard,
    )?;
    Ok(BuiltShard {
        shard,
        k_shard: k_media_index_shard.clone(),
    })
}

/// Decrypt + decompress + decode a media [`SearchIndexShard`]
/// previously built by [`build_media_search_shard`].
pub fn restore_media_search_shard(
    shard: &SearchIndexShard,
    k_media_index_shard: &KeyMaterial,
) -> Result<Vec<MediaIndexRow>, Error> {
    if shard.index_type != IndexType::Media {
        return Err(Error::Storage(
            format!(
                "restore_media_search_shard: index_type {:?} != Media",
                shard.index_type
            )
            .into(),
        ));
    }
    let cbor = open_shard(shard, k_media_index_shard)?;
    let payload: MediaShardPayload = crate::cbor::from_slice(&cbor).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborDecode {
            context: "media shard",
            source: e,
        })
    })?;
    if payload.magic != MEDIA_SHARD_PAYLOAD_MAGIC {
        return Err(Error::Storage("media shard payload magic mismatch".into()));
    }
    Ok(payload.rows)
}

// ---------------------------------------------------------------------------
// Phase 8 — Bloom filter shards
// ---------------------------------------------------------------------------

/// Default number of hash positions per word.
pub const BLOOM_HASH_COUNT: u32 = 3;

/// Lower bound on the bit array size, used when callers ask for
/// a filter sized for a tiny or empty word set.
const BLOOM_MIN_BITS: u64 = 64;

/// Approximate target false-positive rate for
/// [`BloomFilter::for_expected_count`]. Picked so that a
/// 10× over-fill of the expected_count still keeps the false
/// positive rate below ~1%.
const BLOOM_BITS_PER_ELEMENT: u64 = 12;

/// Per-bucket bloom filter. Uses three independent BLAKE3 keyed
/// hashes — one per `BLOOM_HASH_COUNT` slot — over the lowercase
/// word bytes. Hash positions are taken mod the bit-array
/// length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    bit_count: u64,
    hash_count: u32,
    bits: Vec<u8>,
}

impl BloomFilter {
    /// Build a filter sized for `expected_count` entries with
    /// `hash_count` independent hash positions each.
    pub fn for_expected_count(expected_count: usize, hash_count: u32) -> Self {
        let bits_needed = (expected_count as u64).saturating_mul(BLOOM_BITS_PER_ELEMENT);
        let bit_count = bits_needed.max(BLOOM_MIN_BITS).div_ceil(8) * 8;
        Self {
            bit_count,
            hash_count: hash_count.max(1),
            bits: vec![0u8; (bit_count / 8) as usize],
        }
    }

    /// Build a filter from the supplied lowercase word set.
    pub fn from_words(words: &[String], expected_count: usize) -> Self {
        let mut f = Self::for_expected_count(expected_count.max(words.len()), BLOOM_HASH_COUNT);
        for w in words {
            f.insert_word(w);
        }
        f
    }

    /// Insert a single word into the filter. The caller is
    /// responsible for case-folding before insertion — this
    /// matches the behaviour of [`Self::maybe_contains`].
    pub fn insert_word(&mut self, word: &str) {
        for slot in 0..self.hash_count {
            let pos = self.position(word, slot);
            self.set_bit(pos);
        }
    }

    /// Check whether `word` is *possibly* in the filter. False
    /// positives are bounded by the configured fill ratio;
    /// false negatives never occur for words that were inserted
    /// without modification.
    pub fn maybe_contains(&self, word: &str) -> bool {
        for slot in 0..self.hash_count {
            let pos = self.position(word, slot);
            if !self.get_bit(pos) {
                return false;
            }
        }
        true
    }

    fn position(&self, word: &str, slot: u32) -> u64 {
        // Domain-separated keys per slot using a 32-byte BLAKE3
        // keyed hash. The slot index is encoded into the key so
        // each slot uses an independent function.
        let mut key = [0u8; 32];
        let prefix = b"kchat-bloom-shard-slot-";
        key[..prefix.len()].copy_from_slice(prefix);
        key[prefix.len()..prefix.len() + 4].copy_from_slice(&slot.to_le_bytes());
        let h = blake3::keyed_hash(&key, word.as_bytes());
        let bytes = h.as_bytes();
        let v = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
        if self.bit_count == 0 {
            return 0;
        }
        v % self.bit_count
    }

    fn set_bit(&mut self, pos: u64) {
        let byte = (pos / 8) as usize;
        let bit = (pos % 8) as u8;
        if byte < self.bits.len() {
            self.bits[byte] |= 1u8 << bit;
        }
    }

    fn get_bit(&self, pos: u64) -> bool {
        let byte = (pos / 8) as usize;
        let bit = (pos % 8) as u8;
        if byte >= self.bits.len() {
            return false;
        }
        (self.bits[byte] >> bit) & 1 == 1
    }

    /// Number of bits in the bit array (multiple of 8).
    pub fn bit_count(&self) -> u64 {
        self.bit_count
    }

    /// Number of hash positions per inserted word.
    pub fn hash_count(&self) -> u32 {
        self.hash_count
    }
}

/// Build an encrypted bloom shard sealing the supplied
/// `words` into a [`BloomFilter`] plus a
/// [`BloomShardPayload`].
///
/// `k_bloom_index_shard` is the per-shard AEAD key — typically
/// `K_bloom_index_shard(shard_id)` from
/// [`crate::crypto::key_hierarchy::derive_bloom_index_shard`].
pub fn build_bloom_shard(
    words: Vec<String>,
    expected_count: usize,
    conversation_id: &str,
    time_bucket: impl Into<String>,
    k_bloom_index_shard: &KeyMaterial,
    conversation_hash_key: &KeyMaterial,
) -> Result<BuiltShard, Error> {
    let filter = BloomFilter::from_words(&words, expected_count);
    let payload = BloomShardPayload {
        magic: BLOOM_SHARD_PAYLOAD_MAGIC.to_vec(),
        bit_count: filter.bit_count,
        hash_count: filter.hash_count,
        bits: filter.bits.clone(),
    };
    let cbor = crate::cbor::to_vec(&payload).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborEncode {
            context: "bloom shard",
            source: e,
        })
    })?;
    let conversation_id_hash = keyed_conversation_id_hash(conversation_id, conversation_hash_key);
    let shard = seal_shard(
        cbor,
        IndexType::Bloom,
        conversation_id_hash,
        time_bucket.into(),
        words.len() as u64,
        k_bloom_index_shard,
    )?;
    Ok(BuiltShard {
        shard,
        k_shard: k_bloom_index_shard.clone(),
    })
}

/// Decrypt + decompress + decode a bloom [`SearchIndexShard`]
/// previously built by [`build_bloom_shard`].
pub fn restore_bloom_shard(
    shard: &SearchIndexShard,
    k_bloom_index_shard: &KeyMaterial,
) -> Result<BloomFilter, Error> {
    if shard.index_type != IndexType::Bloom {
        return Err(Error::Storage(
            format!(
                "restore_bloom_shard: index_type {:?} != Bloom",
                shard.index_type
            )
            .into(),
        ));
    }
    let cbor = open_shard(shard, k_bloom_index_shard)?;
    let payload: BloomShardPayload = crate::cbor::from_slice(&cbor).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborDecode {
            context: "bloom shard",
            source: e,
        })
    })?;
    if payload.magic != BLOOM_SHARD_PAYLOAD_MAGIC {
        return Err(Error::Storage("bloom shard payload magic mismatch".into()));
    }
    Ok(BloomFilter {
        bit_count: payload.bit_count,
        hash_count: payload.hash_count,
        bits: payload.bits,
    })
}

fn open_shard(shard: &SearchIndexShard, k: &KeyMaterial) -> Result<Vec<u8>, Error> {
    if !shard.has_valid_header() {
        return Err(Error::Storage(
            "search shard header / version mismatch".into(),
        ));
    }
    let aad = build_shard_aad(
        &shard.shard_id,
        shard.index_type,
        &shard.conversation_id_hash,
        &shard.time_bucket,
    );
    let actual_aad_hash = content_hash(&aad);
    if actual_aad_hash != shard.aad_hash {
        return Err(Error::Storage("search shard aad_hash mismatch".into()));
    }
    let compressed =
        open(k.as_bytes(), &shard.nonce, &shard.ciphertext, &aad).map_err(Error::Crypto)?;
    let cbor = zstd::stream::decode_all(&compressed[..]).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::Zstd {
            context: "search shard decode",
            source: e,
        })
    })?;
    Ok(cbor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_hierarchy::{derive_search_root, derive_text_index_shard};

    fn fresh_shard_key() -> KeyMaterial {
        let identity = KeyMaterial::from_bytes([0xAB; 32]);
        let search_root = derive_search_root(&identity).expect("derive search root");
        derive_text_index_shard(&search_root, &Uuid::now_v7().into_bytes())
            .expect("derive shard key")
    }

    fn fresh_conv_hash_key() -> KeyMaterial {
        KeyMaterial::from_bytes([0x77; 32])
    }

    fn sample_text_rows(n: usize) -> Vec<FtsRow> {
        (0..n)
            .map(|i| FtsRow {
                message_id: format!("msg-{i}"),
                conversation_id: "conv-A".to_string(),
                sender_id: format!("sender-{}", i % 3),
                created_at_ms: 1_777_000_000_000 + (i as i64) * 1_000,
                text_content: format!("hello world #{i} the quick brown fox"),
            })
            .collect()
    }

    fn sample_fuzzy_rows(n: usize) -> Vec<FuzzyRow> {
        (0..n)
            .map(|i| FuzzyRow {
                token: format!("tok{i:03}"),
                script: "Latn".to_string(),
                message_id: format!("msg-{i}"),
            })
            .collect()
    }

    #[test]
    fn text_shard_build_and_restore_round_trip() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(8);
        let built = build_text_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        assert!(built.shard.has_valid_header());
        assert_eq!(built.shard.index_type, IndexType::Text);
        assert_eq!(built.shard.doc_count, 8);
        let restored = restore_text_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn fuzzy_shard_build_and_restore_round_trip() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_fuzzy_rows(12);
        let built = build_fuzzy_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        assert!(built.shard.has_valid_header());
        assert_eq!(built.shard.index_type, IndexType::Fuzzy);
        let restored = restore_fuzzy_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn wrong_key_fails_text_shard_decrypt() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(4);
        let built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let bogus = KeyMaterial::from_bytes([0xFF; 32]);
        let err = restore_text_search_shard(&built.shard, &bogus).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn wrong_key_fails_fuzzy_shard_decrypt() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_fuzzy_rows(4);
        let built =
            build_fuzzy_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let bogus = KeyMaterial::from_bytes([0xFF; 32]);
        let err = restore_fuzzy_search_shard(&built.shard, &bogus).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn restore_with_wrong_index_type_fails() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(2);
        let built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        // Pass to fuzzy restorer.
        let err = restore_fuzzy_search_shard(&built.shard, &built.k_shard).unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.to_string().contains("Fuzzy")),
            "got {err:?}"
        );
    }

    #[test]
    fn multilingual_content_survives_text_shard_round_trip() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        // Latin + Cyrillic + CJK + Arabic + Devanagari + mixed.
        let rows = vec![
            FtsRow {
                message_id: "m1".into(),
                conversation_id: "conv-A".into(),
                sender_id: "alice".into(),
                created_at_ms: 1_777_000_000_000,
                text_content: "hello world".into(),
            },
            FtsRow {
                message_id: "m2".into(),
                conversation_id: "conv-A".into(),
                sender_id: "bob".into(),
                created_at_ms: 1_777_000_001_000,
                text_content: "Привет, мир".into(),
            },
            FtsRow {
                message_id: "m3".into(),
                conversation_id: "conv-A".into(),
                sender_id: "carol".into(),
                created_at_ms: 1_777_000_002_000,
                text_content: "你好世界".into(),
            },
            FtsRow {
                message_id: "m4".into(),
                conversation_id: "conv-A".into(),
                sender_id: "dave".into(),
                created_at_ms: 1_777_000_003_000,
                text_content: "مرحبا بالعالم".into(),
            },
            FtsRow {
                message_id: "m5".into(),
                conversation_id: "conv-A".into(),
                sender_id: "eve".into(),
                created_at_ms: 1_777_000_004_000,
                text_content: "नमस्ते दुनिया".into(),
            },
            FtsRow {
                message_id: "m6".into(),
                conversation_id: "conv-A".into(),
                sender_id: "frank".into(),
                created_at_ms: 1_777_000_005_000,
                text_content: "Meeting at 3pm 会議室で".into(),
            },
        ];
        let built = build_text_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        let restored = restore_text_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn tampered_aad_hash_fails_open() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(2);
        let mut built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        built.shard.aad_hash[0] ^= 0xFF;
        let err = restore_text_search_shard(&built.shard, &built.k_shard).unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.to_string().contains("aad_hash")),
            "got {err:?}"
        );
    }

    // ----- Phase 6, Task 7: vector + media shards --------------

    use crate::crypto::key_hierarchy::{derive_media_index_shard, derive_vector_index_shard};

    fn fresh_vector_shard_key() -> KeyMaterial {
        let identity = KeyMaterial::from_bytes([0xAB; 32]);
        let search_root = derive_search_root(&identity).expect("derive search root");
        derive_vector_index_shard(&search_root, &Uuid::now_v7().into_bytes())
            .expect("derive vector shard key")
    }

    fn fresh_media_shard_key() -> KeyMaterial {
        let identity = KeyMaterial::from_bytes([0xAB; 32]);
        let search_root = derive_search_root(&identity).expect("derive search root");
        derive_media_index_shard(&search_root, &Uuid::now_v7().into_bytes())
            .expect("derive media shard key")
    }

    fn sample_vector_rows(n: usize) -> Vec<VectorRow> {
        (0..n)
            .map(|i| VectorRow {
                message_id: format!("msg-v-{i}"),
                embedding: vec![(i as u8).wrapping_mul(7); 4 + 384],
                model_version: "xlmr@v1".into(),
            })
            .collect()
    }

    fn sample_media_rows(n: usize) -> Vec<MediaIndexRow> {
        (0..n)
            .map(|i| MediaIndexRow {
                asset_id: format!("asset-{i}"),
                kind: if i % 2 == 0 {
                    "ocr".into()
                } else {
                    "caption".into()
                },
                text: format!("recognized text {i}"),
                language: Some("en".into()),
                confidence: Some(0.5 + (i as f32 * 0.01)),
            })
            .collect()
    }

    #[test]
    fn vector_shard_build_and_restore_round_trip() {
        let key = fresh_vector_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_vector_rows(6);
        let built = build_vector_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        assert!(built.shard.has_valid_header());
        assert_eq!(built.shard.index_type, IndexType::Vector);
        assert_eq!(built.shard.doc_count, 6);
        let restored = restore_vector_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn vector_shard_wrong_key_fails() {
        let key = fresh_vector_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_vector_rows(3);
        let built =
            build_vector_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let bogus = KeyMaterial::from_bytes([0xFF; 32]);
        let err = restore_vector_search_shard(&built.shard, &bogus).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn empty_vector_shard_round_trips() {
        let key = fresh_vector_shard_key();
        let conv_key = fresh_conv_hash_key();
        let built = build_vector_search_shard(Vec::new(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        assert_eq!(built.shard.doc_count, 0);
        let restored = restore_vector_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert!(restored.is_empty());
    }

    #[test]
    fn vector_shard_index_type_mismatch_rejected() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(2);
        let built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let err = restore_vector_search_shard(&built.shard, &built.k_shard).unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.to_string().contains("Vector")),
            "got {err:?}"
        );
    }

    #[test]
    fn media_shard_build_and_restore_round_trip() {
        let key = fresh_media_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_media_rows(5);
        let built = build_media_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        assert_eq!(built.shard.index_type, IndexType::Media);
        assert_eq!(built.shard.doc_count, 5);
        let restored = restore_media_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn media_shard_wrong_key_fails() {
        let key = fresh_media_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_media_rows(3);
        let built =
            build_media_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let bogus = KeyMaterial::from_bytes([0xFF; 32]);
        let err = restore_media_search_shard(&built.shard, &bogus).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn media_shard_multilingual_round_trip() {
        let key = fresh_media_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = vec![
            MediaIndexRow {
                asset_id: "a-en".into(),
                kind: "ocr".into(),
                text: "hello world".into(),
                language: Some("en".into()),
                confidence: Some(0.95),
            },
            MediaIndexRow {
                asset_id: "a-ru".into(),
                kind: "ocr".into(),
                text: "Привет, мир".into(),
                language: Some("ru".into()),
                confidence: Some(0.88),
            },
            MediaIndexRow {
                asset_id: "a-zh".into(),
                kind: "caption".into(),
                text: "你好世界".into(),
                language: Some("zh".into()),
                confidence: None,
            },
            MediaIndexRow {
                asset_id: "a-ar".into(),
                kind: "transcript".into(),
                text: "مرحبا بالعالم".into(),
                language: Some("ar".into()),
                confidence: Some(0.71),
            },
        ];
        let built = build_media_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        let restored = restore_media_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn media_shard_index_type_mismatch_rejected() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(2);
        let built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let err = restore_media_search_shard(&built.shard, &built.k_shard).unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.to_string().contains("Media")),
            "got {err:?}"
        );
    }

    // -------------------------------------------------------------
    // Phase 8 — Bloom shard tests
    // -------------------------------------------------------------

    fn fresh_bloom_shard_key() -> KeyMaterial {
        use crate::crypto::key_hierarchy::derive_bloom_index_shard;
        let identity = KeyMaterial::from_bytes([0xAB; 32]);
        let search_root = derive_search_root(&identity).expect("derive search root");
        derive_bloom_index_shard(&search_root, &Uuid::now_v7().into_bytes())
            .expect("derive bloom shard key")
    }

    #[test]
    fn bloom_filter_maybe_contains_returns_true_for_inserted_words() {
        let words = vec!["alpha".into(), "beta".into(), "gamma".into()];
        let f = BloomFilter::from_words(&words, 16);
        for w in &words {
            assert!(f.maybe_contains(w), "{w} must be present");
        }
    }

    #[test]
    fn bloom_filter_maybe_contains_returns_false_for_absent_words() {
        let words: Vec<String> = (0..32).map(|i| format!("inserted-{i}")).collect();
        let f = BloomFilter::from_words(&words, 32);
        let absent: Vec<String> = (0..1000).map(|i| format!("absent-token-{i}")).collect();
        let false_positives = absent.iter().filter(|w| f.maybe_contains(w)).count();
        // Allow some false positives (it's a probabilistic
        // structure) but most absent words should be rejected.
        assert!(
            false_positives < absent.len() / 4,
            "too many false positives: {} / {}",
            false_positives,
            absent.len()
        );
    }

    #[test]
    fn bloom_filter_false_positive_rate_under_5_percent() {
        // Build a filter sized for 1000 entries, fill it, and
        // probe it with 10 000 *un*inserted words. With the
        // BLOOM_BITS_PER_ELEMENT setting (12 bits/elem, 3 hash
        // functions) the FPR should sit well under 5%.
        let inserted: Vec<String> = (0..1000).map(|i| format!("inserted-{i}")).collect();
        let f = BloomFilter::from_words(&inserted, 1000);
        let absent: Vec<String> = (1000..11000).map(|i| format!("absent-{i}")).collect();
        let fp = absent.iter().filter(|w| f.maybe_contains(w)).count();
        let rate = (fp as f64) / (absent.len() as f64);
        assert!(
            rate < 0.05,
            "false positive rate {rate} too high (fp = {fp})"
        );
    }

    #[test]
    fn bloom_filter_build_and_restore_round_trip() {
        let key = fresh_bloom_shard_key();
        let conv_key = fresh_conv_hash_key();
        let words: Vec<String> = vec![
            "hello".into(),
            "world".into(),
            "lighthouse".into(),
            "keeper".into(),
        ];
        let built = build_bloom_shard(words.clone(), 32, "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        let restored = restore_bloom_shard(&built.shard, &built.k_shard).expect("restore");
        for w in &words {
            assert!(
                restored.maybe_contains(w),
                "round-tripped filter must still contain {w}"
            );
        }
    }

    #[test]
    fn bloom_shard_wrong_key_fails_decrypt() {
        let key_a = fresh_bloom_shard_key();
        let key_b = fresh_bloom_shard_key();
        let conv_key = fresh_conv_hash_key();
        let words: Vec<String> = vec!["alpha".into(), "beta".into()];
        let built =
            build_bloom_shard(words, 8, "conv-A", "2026-04", &key_a, &conv_key).expect("build");
        let err = restore_bloom_shard(&built.shard, &key_b).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn bloom_shard_multilingual_words_round_trip() {
        let key = fresh_bloom_shard_key();
        let conv_key = fresh_conv_hash_key();
        let words: Vec<String> = vec![
            "lighthouse".into(), // Latin
            "Встреча".into(),    // Cyrillic
            "会議室".into(),     // CJK
            "مرحبا".into(),      // Arabic
            "안녕".into(),       // Hangul
            "नमस्ते".into(),       // Devanagari
        ];
        let built = build_bloom_shard(words.clone(), 16, "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        let restored = restore_bloom_shard(&built.shard, &built.k_shard).expect("restore");
        for w in &words {
            assert!(
                restored.maybe_contains(w),
                "multilingual word {w} must survive round-trip"
            );
        }
    }

    #[test]
    fn bloom_shard_index_type_mismatch_rejected() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(2);
        let built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let err = restore_bloom_shard(&built.shard, &built.k_shard).unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.to_string().contains("Bloom")),
            "got {err:?}"
        );
    }
}
