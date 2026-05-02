//! Crypto primitives for the KChat core.
//!
//! Phase 0 implements:
//! * [`content_hash`] — BLAKE3 content hashing (one-shot + streaming).
//! * [`key_hierarchy`] — HKDF-SHA256 key derivation tree rooted at
//!   `K_user_master`.
//! * [`aead`] — XChaCha20-Poly1305 (default) and AES-256-GCM AEADs,
//!   plus the KChat per-chunk AAD construction from
//!   `docs/PROPOSAL.md §8.3`.
//! * [`convergent`] — ZK Object Fabric Pattern C convergent
//!   encryption, byte-identical to the Go SDK at
//!   `kennguy3n/zk-object-fabric/encryption/client_sdk`.
//!
//! [`key_wrap`] is a stub for now; Phase 1 fills it in alongside
//! `K_local_db` and platform keychain wrappers.

pub mod aead;
pub mod content_hash;
pub mod convergent;
pub mod key_hierarchy;
pub mod key_wrap;

/// Crypto module error type.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// AEAD seal or open failed (wrong key, tampered ciphertext,
    /// AAD mismatch, malformed frame).
    #[error("aead: {0}")]
    Aead(&'static str),

    /// HKDF key derivation failed (typically: requested output too
    /// large or rejected input).
    #[error("kdf: {0}")]
    Kdf(&'static str),

    /// A required input was empty or otherwise invalid.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    /// A frame in a Pattern C ciphertext stream was malformed.
    #[error("frame: {0}")]
    Frame(String),
}

/// Crypto module result alias.
pub type CryptoResult<T> = Result<T, CryptoError>;
