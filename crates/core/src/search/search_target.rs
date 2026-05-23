//! `ConversationGroupResolver` trait
//!
//!
//! `docs/DESIGN.md §12` calls for
//! a multi-scope search: a single search query may apply to
//! every conversation, one conversation, an explicit group, a
//! channel, every starred conversation, or every conversation
//! with unread messages.
//!
//! For variants that map onto a schema column on the
//! `conversation` table (`Community`, `Domain`, `Tenant`,
//! `B2cAll`) the resolution is purely SQL — the
//! [`crate::search::query_engine`] module handles them inline.
//! For the new variants — `ConversationGroup`, `Channel`,
//! `Starred`, `Unread` — the resolution depends on application-
//! state the local store does not own (channel → conversation
//! mapping, user-curated starred set, unread state machine).
//! That state lives in the orchestration layer; this trait is
//! how the orchestration layer hands resolution back into the
//! query engine.
//!
//! Implementations MUST be `Send + Sync + Debug` so the trait
//! object can be parked on the [`crate::core_impl::CoreImpl`]
//! and shared across worker threads.

use std::collections::HashSet;

use crate::Error;

/// Trait the orchestration layer fills in to resolve the
/// non-schema-backed [`crate::SearchTarget`] variants
/// (`ConversationGroup`, `Channel`, `Starred`, `Unread`) into
/// concrete `conversation_id` strings the query engine can use.
pub trait ConversationGroupResolver: Send + Sync + std::fmt::Debug {
    /// Resolve [`crate::SearchTarget::Channel`] to its
    /// conversation set. The default implementation returns the
    /// channel id as a single-element set so callers that store
    /// channel-conversations under matching ids "just work".
    fn resolve_channel(&self, channel_id: &uuid::Uuid) -> Result<HashSet<String>, Error> {
        let mut s = HashSet::new();
        s.insert(channel_id.to_string());
        Ok(s)
    }

    /// Resolve [`crate::SearchTarget::Starred`] to its
    /// conversation set. Default = empty set so a search with
    /// no starred conversations cleanly returns no results
    /// rather than fanning out globally.
    fn resolve_starred(&self) -> Result<HashSet<String>, Error> {
        Ok(HashSet::new())
    }

    /// Resolve [`crate::SearchTarget::Unread`] to its
    /// conversation set. Default = empty set.
    fn resolve_unread(&self) -> Result<HashSet<String>, Error> {
        Ok(HashSet::new())
    }
}

/// Default resolver that uses the trait-level defaults — used
/// by the query engine when no resolver has been installed on
/// `CoreImpl`. Channel resolves to the singleton set
/// `{channel_id}`; Starred and Unread resolve to the empty set.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopConversationGroupResolver;

impl NoopConversationGroupResolver {
    /// `const fn` constructor.
    pub const fn new() -> Self {
        Self
    }
}

impl ConversationGroupResolver for NoopConversationGroupResolver {}

/// Test-only resolver wired from a triple of static sets.
/// Saves test code from defining a one-off impl per assertion.
#[derive(Debug, Clone)]
pub struct StaticConversationGroupResolver {
    channels: std::collections::HashMap<uuid::Uuid, HashSet<String>>,
    starred: HashSet<String>,
    unread: HashSet<String>,
}

impl StaticConversationGroupResolver {
    /// Construct a resolver with the supplied snapshots.
    pub fn new(
        channels: std::collections::HashMap<uuid::Uuid, HashSet<String>>,
        starred: HashSet<String>,
        unread: HashSet<String>,
    ) -> Self {
        Self {
            channels,
            starred,
            unread,
        }
    }
}

impl ConversationGroupResolver for StaticConversationGroupResolver {
    fn resolve_channel(&self, channel_id: &uuid::Uuid) -> Result<HashSet<String>, Error> {
        Ok(self.channels.get(channel_id).cloned().unwrap_or_default())
    }
    fn resolve_starred(&self) -> Result<HashSet<String>, Error> {
        Ok(self.starred.clone())
    }
    fn resolve_unread(&self) -> Result<HashSet<String>, Error> {
        Ok(self.unread.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use uuid::Uuid;

    #[test]
    fn conversation_group_resolver_is_object_safe_through_arc_dyn() {
        let r: Arc<dyn ConversationGroupResolver> = Arc::new(NoopConversationGroupResolver::new());
        let cid = Uuid::new_v4();
        let ch = r.resolve_channel(&cid).unwrap();
        assert!(ch.contains(&cid.to_string()));
        assert!(r.resolve_starred().unwrap().is_empty());
        assert!(r.resolve_unread().unwrap().is_empty());
    }

    #[test]
    fn static_resolver_returns_seeded_sets() {
        let cid = Uuid::new_v4();
        let other = Uuid::new_v4().to_string();
        let mut channels = std::collections::HashMap::new();
        let mut ch_set = HashSet::new();
        ch_set.insert(other.clone());
        channels.insert(cid, ch_set);
        let mut starred = HashSet::new();
        starred.insert(Uuid::new_v4().to_string());
        let mut unread = HashSet::new();
        unread.insert(Uuid::new_v4().to_string());
        let r = StaticConversationGroupResolver::new(channels, starred.clone(), unread.clone());
        assert!(r.resolve_channel(&cid).unwrap().contains(&other));
        assert_eq!(r.resolve_starred().unwrap(), starred);
        assert_eq!(r.resolve_unread().unwrap(), unread);
        // Unknown channel resolves to empty.
        assert!(r.resolve_channel(&Uuid::new_v4()).unwrap().is_empty());
    }
}
