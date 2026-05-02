//! kchat-core — platform-agnostic core for the KChat storage and
//! search engine.
//!
//! Phase 0 establishes the on-disk and on-wire crypto contract:
//! BLAKE3 content hashing, the [`crypto::key_hierarchy`] HKDF-SHA256
//! derivation tree, the AEAD constructions in [`crypto::aead`], the
//! Pattern C convergent encryption in [`crypto::convergent`]
//! (bit-identical to the Go SDK at
//! `kennguy3n/zk-object-fabric/encryption/client_sdk`), and the
//! AES-256-KW key wrapping in [`crypto::key_wrap`].
//!
//! [`formats`] holds the CBOR wire-format types — backup / archive
//! segment frames, manifest frames (with Ed25519 signatures and the
//! `previous_manifest_hash` chain), the media descriptor, and the
//! search index shard — that travel between the device and the
//! KChat backend / ZK Object Fabric backup sink.
//!
//! Higher-level modules (`message`, `media`, `search`, `archive`,
//! `backup`, `offload`, `restore`, `local_store`, `models`,
//! `transport`, `scheduler`) are stubbed in Phase 0 and filled in
//! as later phases land. See `docs/PHASES.md` for the schedule.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod archive;
pub mod backup;
pub mod config;
pub mod crypto;
pub mod formats;
pub mod local_store;
pub mod media;
pub mod message;
pub mod models;
pub mod offload;
pub mod restore;
pub mod scheduler;
pub mod search;
pub mod transport;

pub use config::KChatCoreConfig;

/// Top-level error type for the core library. Phase 0 carries crypto
/// and configuration errors only; later phases extend the variants
/// without changing the existing ones.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A crypto primitive (key derivation, AEAD seal/open, hashing)
    /// failed.
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
}

/// Crate-wide [`Result`] alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Phase 0 stub of the public core trait. The full surface is
/// defined in `docs/PROPOSAL.md §12` and lands progressively across
/// Phases 1 – 6. Keeping the trait declared here lets bridge crates
/// already type-check against the placeholder shape.
pub trait KChatCore: Send + Sync {
    /// Returns the configuration this core was initialized with.
    fn config(&self) -> &KChatCoreConfig;
}
