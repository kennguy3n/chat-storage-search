//! Configuration for [`crate::KChatCore`].
//!
//! Phase 0 captures only the platform identifier and the on-disk
//! root directory; later phases extend the struct (network policy,
//! ML model directory, search budget, etc.) without breaking the
//! existing fields.

use std::path::PathBuf;

/// Logical platform the core is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Ios,
    Android,
    MacOs,
    Windows,
}

/// Configuration for a [`crate::KChatCore`] instance.
#[derive(Debug, Clone)]
pub struct KChatCoreConfig {
    /// Root directory for the encrypted local store and chunk cache.
    pub data_dir: PathBuf,
    /// Platform the core is running on. Drives platform-specific
    /// keychain bindings and ML execution-provider selection.
    pub platform: Platform,
    /// Tenant identifier used for ZK Object Fabric Pattern C derivation.
    pub tenant_id: String,
}

impl KChatCoreConfig {
    /// Construct a new configuration with the required fields.
    pub fn new(data_dir: PathBuf, platform: Platform, tenant_id: impl Into<String>) -> Self {
        Self {
            data_dir,
            platform,
            tenant_id: tenant_id.into(),
        }
    }
}
