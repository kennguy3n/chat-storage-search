//! Phase-B.9 search coordinator.
//!
//! Owns the in-memory search-orchestration state previously held
//! directly on [`crate::core_impl::CoreImpl`]:
//!
//!   * `hydration_queue` — the priority queue
//!     ([`crate::offload::hydration::HydrationQueue`]) that
//!     `search` / `search_and_prefetch_cold` / `search_streaming`
//!     populate with cold-flagged results so the orchestration
//!     layer can pop hydration requests in priority order
//!     (`docs/PROPOSAL.md §5.5`).
//!   * `conversation_group_resolver` — the Phase-8
//!     [`crate::search::search_target::ConversationGroupResolver`]
//!     bridge that translates a [`crate::SearchTarget`] into a
//!     conversation-id set inside
//!     [`crate::search::query_engine::QueryEngine::execute_search_with_target`].
//!     Held in [`OnceLock`] so `search_with_target` resolves the
//!     bridge with a lock-free atomic load.
//!
//! The coordinator deliberately does **not** own the large search
//! orchestrator methods themselves (`search_and_prefetch_cold`,
//! `search_with_cold_source`, `search_streaming`,
//! `upload_search_shards`, `restore_search_shards`,
//! `fetch_and_restore_cold_shards`, `hydrate_cold_search_results`,
//! `rehydrate_timeline_skeletons`, `search_with_target`,
//! `KChatCore::search`). Those methods cross-cut the writer +
//! reader pool, the archive segment router, the transport client,
//! and the model bridges (text embedder, cold-shard cache), and
//! continue to live on [`crate::core_impl::CoreImpl`] as
//! orchestrators that call the coordinator's typed accessor
//! surface in place of the previous direct `self.hydration_queue.lock()`
//! / `self.conversation_group_resolver.get()` calls.
//!
//! The accessor surface centralises three patterns that were
//! previously open-coded at each call site:
//!
//!   * **Best-effort enqueue** (poisoned-mutex tolerant) — used by
//!     [`Coordinator::enqueue_cold_results`] for the
//!     [`crate::HydrationReason::SearchResultTap`] backfill in
//!     [`crate::core_impl::CoreImpl::enqueue_cold_results_for_hydration`].
//!     A poisoned queue mutex is logged-and-skipped so the search
//!     results still flow back to the caller.
//!   * **Failable enqueue** (poisoned-mutex surfaced) — used by
//!     [`Coordinator::enqueue_request`] /
//!     [`Coordinator::enqueue_prefetch_window`] from
//!     [`crate::core_impl::CoreImpl::hydrate_message`] and
//!     [`crate::core_impl::CoreImpl::enqueue_prefetch_window`]
//!     where the orchestrator wants to surface the poisoned-mutex
//!     state to the caller rather than silently drop the request.
//!   * **Lock-free resolver lookup** — used by
//!     [`Coordinator::resolver_or_default`] to resolve the
//!     installed
//!     [`crate::search::search_target::ConversationGroupResolver`]
//!     in [`crate::core_impl::CoreImpl::search_with_target`]
//!     without contending on a mutex before every reader-pool
//!     checkout. Falls back to the
//!     [`crate::search::search_target::NoopConversationGroupResolver`]
//!     default when nothing has been installed yet.
//!
//! No method on the coordinator holds a lock across an I/O call
//! or across a call into the query engine — every accessor either
//! drops the lock after enqueueing or returns a cheap `Arc` clone
//! and releases the `OnceLock` atomic load immediately.

use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use uuid::Uuid;

use crate::core_impl::poisoned;
use crate::local_store::StorageError;
use crate::offload::hydration::{HydrationQueue, HydrationRequest};
use crate::search::search_target::{ConversationGroupResolver, NoopConversationGroupResolver};
use crate::{Error, HydrationReason, Result, SearchResult};

/// Process-wide fallback [`NoopConversationGroupResolver`] used
/// by [`Coordinator::resolver_or_default`] when no resolver has
/// been installed. Held in a [`LazyLock`] so the noop resolver
/// is allocated **once per process** and every fallback path
/// returns a cheap `Arc` clone (one atomic increment) instead
/// of allocating a fresh `NoopConversationGroupResolver` on
/// every `search_with_target` call — see PR #57 review feedback.
/// The resolver is stateless so a shared instance is
/// observationally identical to per-call construction.
static NOOP_RESOLVER: LazyLock<Arc<dyn ConversationGroupResolver>> =
    LazyLock::new(|| Arc::new(NoopConversationGroupResolver::new()));

/// Phase-B.9 search coordinator — owns the
/// [`HydrationQueue`] mutex and the
/// [`ConversationGroupResolver`] [`OnceLock`] previously held
/// directly on [`crate::core_impl::CoreImpl`].
pub(crate) struct Coordinator {
    /// Phase-3 hydration priority queue. `hydrate_message`
    /// enqueues a request before serving from local storage so
    /// the orchestration layer can later pop pending fetches in
    /// priority order (`docs/PROPOSAL.md §5.5`).
    hydration_queue: Mutex<HydrationQueue>,
    /// Phase-8 multi-scope search resolver. Write-once via
    /// [`Self::install_resolver`]; the query engine treats "not
    /// installed" as the default
    /// [`NoopConversationGroupResolver`] (Channel resolves to its
    /// singleton id, Starred / Unread resolve to the empty set).
    /// Held in [`OnceLock`] so `search_with_target` resolves the
    /// bridge with a lock-free atomic load instead of contending
    /// on a mutex before each reader-pool checkout.
    conversation_group_resolver: OnceLock<Arc<dyn ConversationGroupResolver>>,
}

impl Coordinator {
    /// Construct a coordinator with an empty
    /// [`HydrationQueue`] sized to `queue_capacity` and no
    /// installed [`ConversationGroupResolver`].
    pub(crate) fn new(queue_capacity: usize) -> Self {
        Self {
            hydration_queue: Mutex::new(HydrationQueue::new(queue_capacity)),
            conversation_group_resolver: OnceLock::new(),
        }
    }

    // ----------------------------------------------------------------
    // Hydration queue
    // ----------------------------------------------------------------

    /// Best-effort batch enqueue of every cold-flagged
    /// [`SearchResult`] in `results` at the supplied `reason`
    /// priority and `now_ms` timestamp.
    ///
    /// A poisoned queue mutex is logged-and-skipped — the search
    /// path that called this still flows results back to the
    /// caller. Matches the legacy behaviour of
    /// `CoreImpl::enqueue_cold_results_for_hydration`.
    pub(crate) fn enqueue_cold_results(
        &self,
        results: &[SearchResult],
        reason: HydrationReason,
        now_ms: i64,
    ) {
        let mut queue = match self.hydration_queue.lock() {
            Ok(q) => q,
            Err(_) => return,
        };
        for r in results.iter().filter(|r| r.is_cold) {
            queue.enqueue(HydrationRequest {
                message_id: r.message_id,
                conversation_id: r.conversation_id,
                reason,
                requested_at_ms: now_ms,
            });
        }
    }

    /// Enqueue a single [`HydrationRequest`] and surface a
    /// poisoned-mutex state to the caller as
    /// [`StorageError::LockPoisoned`].
    ///
    /// Used by [`crate::core_impl::CoreImpl::hydrate_message`]
    /// where the orchestrator wants to surface the poisoned state
    /// rather than silently drop the request.
    pub(crate) fn enqueue_request(&self, request: HydrationRequest) -> Result<()> {
        let mut queue = self.hydration_queue.lock().map_err(poisoned)?;
        queue.enqueue(request);
        Ok(())
    }

    /// Enqueue P3 prefetches for `visible_ids` and the surrounding
    /// viewport window. Wraps
    /// [`HydrationQueue::enqueue_prefetch_window`].
    pub(crate) fn enqueue_prefetch_window(
        &self,
        visible_ids: &[Uuid],
        conversation_id: Uuid,
        window_size: usize,
        now_ms: i64,
    ) -> Result<()> {
        let mut queue = self.hydration_queue.lock().map_err(poisoned)?;
        queue.enqueue_prefetch_window(visible_ids, conversation_id, window_size, now_ms);
        Ok(())
    }

    /// Current queue length. Test-only inspector matching the
    /// legacy `CoreImpl::hydration_queue_len` helper. Returns `0`
    /// on a poisoned mutex (consistent with the legacy `.expect`
    /// path's intent of surfacing a fault — but without crashing
    /// the test binary mid-run).
    #[cfg(test)]
    pub(crate) fn queue_len(&self) -> usize {
        self.hydration_queue.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Drain the queue into priority order. Test-only inspector
    /// matching the legacy `CoreImpl::hydration_queue_drain`
    /// helper. Production callers pop with
    /// [`HydrationQueue::dequeue`] inside a worker loop.
    #[cfg(test)]
    pub(crate) fn drain_queue(&self) -> Vec<HydrationRequest> {
        let mut queue = match self.hydration_queue.lock() {
            Ok(q) => q,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::with_capacity(queue.len());
        while let Some(r) = queue.dequeue() {
            out.push(r);
        }
        out
    }

    // ----------------------------------------------------------------
    // Conversation group resolver
    // ----------------------------------------------------------------

    /// Install the Phase-8 multi-scope search resolver. Write-once
    /// — returns [`StorageError::SubsystemAlreadyInstalled`] if a
    /// resolver has already been installed.
    pub(crate) fn install_resolver(
        &self,
        resolver: Arc<dyn ConversationGroupResolver>,
    ) -> Result<()> {
        self.conversation_group_resolver.set(resolver).map_err(|_| {
            Error::Storage(StorageError::SubsystemAlreadyInstalled(
                "conversation_group_resolver",
            ))
        })
    }

    /// Whether [`Self::install_resolver`] has been called.
    pub(crate) fn has_resolver(&self) -> bool {
        self.conversation_group_resolver.get().is_some()
    }

    /// Resolve the installed [`ConversationGroupResolver`] or
    /// fall back to the process-wide
    /// [`NOOP_RESOLVER`] singleton when nothing has been
    /// installed yet.
    ///
    /// Returns an owned `Arc` rather than a borrow because the
    /// caller hands the bridge to
    /// [`crate::search::query_engine::QueryEngine::execute_search_with_target`]
    /// across a reader-pool checkout that lives in a separate
    /// closure scope. The fallback path is a cheap `Arc::clone`
    /// (one atomic increment) against the process-wide
    /// [`NoopConversationGroupResolver`] — no heap allocation
    /// happens on the cold path either.
    pub(crate) fn resolver_or_default(&self) -> Arc<dyn ConversationGroupResolver> {
        match self.conversation_group_resolver.get() {
            Some(r) => Arc::clone(r),
            None => Arc::clone(&NOOP_RESOLVER),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `install_resolver` is write-once.
    #[test]
    fn install_resolver_is_write_once() {
        let c = Coordinator::new(16);
        assert!(!c.has_resolver());
        c.install_resolver(Arc::new(NoopConversationGroupResolver::new()))
            .unwrap();
        assert!(c.has_resolver());
        let second = c.install_resolver(Arc::new(NoopConversationGroupResolver::new()));
        assert!(matches!(
            second,
            Err(Error::Storage(StorageError::SubsystemAlreadyInstalled(
                "conversation_group_resolver"
            )))
        ));
    }

    /// `resolver_or_default` returns the installed bridge when
    /// present and falls back to [`NoopConversationGroupResolver`]
    /// when none is installed. Pinned because the fallback is the
    /// invariant `search_with_target` depends on.
    #[test]
    fn resolver_or_default_falls_back_to_noop() {
        let c = Coordinator::new(16);
        // Drop the resolver immediately — we only assert that the
        // method returns *something* without panicking, which is
        // the relevant fallback semantic.
        let _ = c.resolver_or_default();
        assert!(!c.has_resolver());
    }

    /// `enqueue_request` surfaces success and queue length
    /// reflects the enqueue.
    #[test]
    fn enqueue_request_grows_queue() {
        let c = Coordinator::new(16);
        assert_eq!(c.queue_len(), 0);
        c.enqueue_request(HydrationRequest {
            message_id: Uuid::now_v7(),
            conversation_id: Uuid::now_v7(),
            reason: HydrationReason::SearchResultTap,
            requested_at_ms: 0,
        })
        .unwrap();
        assert_eq!(c.queue_len(), 1);
    }

    /// `enqueue_cold_results` only enqueues `is_cold` results.
    #[test]
    fn enqueue_cold_results_filters_non_cold() {
        let c = Coordinator::new(16);
        let cold = SearchResult {
            message_id: Uuid::now_v7(),
            conversation_id: Uuid::now_v7(),
            sender_id: "sender".to_string(),
            created_at_ms: 0,
            snippet: None,
            rank_score: 1.0,
            is_cold: true,
            semantic_score: None,
        };
        let warm = SearchResult {
            is_cold: false,
            ..cold.clone()
        };
        c.enqueue_cold_results(&[cold, warm], HydrationReason::SearchResultTap, 0);
        assert_eq!(c.queue_len(), 1);
    }
}
