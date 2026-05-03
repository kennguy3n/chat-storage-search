//! Phase-3 hydration priority queue.
//!
//! `docs/PROPOSAL.md §5.5` defines the P0..P5 hydration ladder
//! used by the rehydration pipeline. This module turns that
//! ladder into an in-memory queue ordered by [`HydrationReason`]
//! (priority) and FIFO insertion order within a priority.
//!
//! The queue is **deduplicating**: re-enqueueing the same
//! `message_id` upgrades its priority if the new priority is
//! higher, so a search-result tap on a message that's already
//! queued for an adjacent prefetch immediately jumps to P0.
//!
//! `HydrationReason`'s enum-declaration order is the priority
//! order — `P0` first, `P5` last — and the `PartialOrd`/`Ord`
//! derives mirror that. The queue uses `<=` comparisons against
//! that ordering, so adding a new reason in the future is a wire
//! change but not a queue change.

use std::collections::HashMap;

use uuid::Uuid;

use crate::HydrationReason;

/// One enqueued hydration request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrationRequest {
    /// Message to hydrate.
    pub message_id: Uuid,
    /// Owning conversation.
    pub conversation_id: Uuid,
    /// Why the rehydration is happening.
    pub reason: HydrationReason,
    /// Wall-clock millisecond timestamp the request was queued
    /// — used as the FIFO tiebreaker within a single priority
    /// bucket.
    pub requested_at_ms: i64,
}

/// Priority queue used by the rehydration pipeline.
///
/// Backed by a `Vec<HydrationRequest>` kept sorted on every
/// insertion. The expected queue size is small (low hundreds at
/// most — the orchestration layer drains it as workers become
/// available), so the per-insert `O(n log n)` sort is the right
/// tradeoff against a `BinaryHeap`'s lookup-by-id problem.
#[derive(Debug, Default)]
pub struct HydrationQueue {
    items: Vec<HydrationRequest>,
    capacity: usize,
    by_id: HashMap<Uuid, usize>,
}

impl HydrationQueue {
    /// Build a queue with the given capacity hint. The queue does
    /// not enforce a hard upper bound — `capacity` only sizes the
    /// internal `Vec`.
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            capacity,
            by_id: HashMap::with_capacity(capacity),
        }
    }

    /// Number of queued requests.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether `message_id` is currently queued.
    pub fn contains(&self, message_id: &Uuid) -> bool {
        self.by_id.contains_key(message_id)
    }

    /// Peek at the highest-priority request without removing it.
    pub fn peek(&self) -> Option<&HydrationRequest> {
        self.items.first()
    }

    /// Enqueue `request`. Deduplicates by `message_id`: if the
    /// queue already contains the same message at a *lower*
    /// priority, the request is upgraded; if the existing entry is
    /// already at an equal-or-higher priority, the call is a no-op.
    pub fn enqueue(&mut self, request: HydrationRequest) {
        if let Some(&idx) = self.by_id.get(&request.message_id) {
            // Already queued — upgrade priority if higher.
            if request.reason < self.items[idx].reason {
                self.items[idx] = request;
                self.resort();
            }
            return;
        }
        self.items.push(request.clone());
        self.by_id.insert(request.message_id, self.items.len() - 1);
        self.resort();
    }

    /// Pop the highest-priority request.
    pub fn dequeue(&mut self) -> Option<HydrationRequest> {
        if self.items.is_empty() {
            return None;
        }
        let request = self.items.remove(0);
        self.by_id.remove(&request.message_id);
        // After `remove(0)` every other entry shifted; rebuild the
        // index map. We could update it in place, but the queue
        // is small and the rebuild is O(n).
        self.rebuild_index();
        Some(request)
    }

    /// Remove `message_id` from the queue. Returns `true` if a
    /// request was removed.
    pub fn remove(&mut self, message_id: &Uuid) -> bool {
        if let Some(idx) = self.by_id.remove(message_id) {
            self.items.remove(idx);
            self.rebuild_index();
            return true;
        }
        false
    }

    /// Enqueue P3 prefetches for every id in `visible_ids` and
    /// the surrounding viewport window. The orchestration layer
    /// supplies the window size — typical values are 5..50.
    pub fn enqueue_prefetch_window(
        &mut self,
        visible_ids: &[Uuid],
        conversation_id: Uuid,
        window_size: usize,
        now_ms: i64,
    ) {
        let _ = window_size; // The window size is the slice the
                             // caller already widened — it shapes
                             // `visible_ids`, not our internal
                             // logic. Kept in the signature so the
                             // orchestration layer can pass a
                             // window-shape hint without
                             // restructuring.
        for id in visible_ids {
            self.enqueue(HydrationRequest {
                message_id: *id,
                conversation_id,
                reason: HydrationReason::AdjacentPrefetch,
                requested_at_ms: now_ms,
            });
        }
    }

    /// Capacity hint passed at construction.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn resort(&mut self) {
        // Sort by reason ascending (P0 < P5) then by FIFO order
        // (lower requested_at_ms first).
        self.items.sort_by(|a, b| {
            a.reason
                .cmp(&b.reason)
                .then_with(|| a.requested_at_ms.cmp(&b.requested_at_ms))
        });
        self.rebuild_index();
    }

    fn rebuild_index(&mut self) {
        self.by_id.clear();
        for (idx, item) in self.items.iter().enumerate() {
            self.by_id.insert(item.message_id, idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(reason: HydrationReason, ms: i64) -> HydrationRequest {
        HydrationRequest {
            message_id: Uuid::now_v7(),
            conversation_id: Uuid::now_v7(),
            reason,
            requested_at_ms: ms,
        }
    }

    #[test]
    fn p0_dequeues_before_p5() {
        let mut q = HydrationQueue::new(8);
        q.enqueue(req(HydrationReason::OpportunisticFill, 0));
        q.enqueue(req(HydrationReason::SearchResultTap, 1));
        let first = q.dequeue().unwrap();
        assert_eq!(first.reason, HydrationReason::SearchResultTap);
    }

    #[test]
    fn same_priority_fifo_order() {
        let mut q = HydrationQueue::new(8);
        let a = req(HydrationReason::AdjacentPrefetch, 1);
        let b = req(HydrationReason::AdjacentPrefetch, 2);
        let c = req(HydrationReason::AdjacentPrefetch, 3);
        q.enqueue(b.clone());
        q.enqueue(a.clone());
        q.enqueue(c.clone());
        // Lower requested_at_ms wins the FIFO tie.
        assert_eq!(q.dequeue().unwrap().requested_at_ms, 1);
        assert_eq!(q.dequeue().unwrap().requested_at_ms, 2);
        assert_eq!(q.dequeue().unwrap().requested_at_ms, 3);
    }

    #[test]
    fn duplicate_message_id_upgrades_priority() {
        let mut q = HydrationQueue::new(8);
        let mid = Uuid::now_v7();
        let conv = Uuid::now_v7();
        q.enqueue(HydrationRequest {
            message_id: mid,
            conversation_id: conv,
            reason: HydrationReason::AdjacentPrefetch,
            requested_at_ms: 1,
        });
        q.enqueue(HydrationRequest {
            message_id: mid,
            conversation_id: conv,
            reason: HydrationReason::SearchResultTap,
            requested_at_ms: 2,
        });
        assert_eq!(q.len(), 1);
        let popped = q.dequeue().unwrap();
        assert_eq!(popped.reason, HydrationReason::SearchResultTap);
    }

    #[test]
    fn duplicate_at_lower_priority_is_noop() {
        let mut q = HydrationQueue::new(8);
        let mid = Uuid::now_v7();
        q.enqueue(HydrationRequest {
            message_id: mid,
            conversation_id: Uuid::now_v7(),
            reason: HydrationReason::SearchResultTap,
            requested_at_ms: 1,
        });
        q.enqueue(HydrationRequest {
            message_id: mid,
            conversation_id: Uuid::now_v7(),
            reason: HydrationReason::OpportunisticFill,
            requested_at_ms: 2,
        });
        assert_eq!(q.len(), 1);
        assert_eq!(q.peek().unwrap().reason, HydrationReason::SearchResultTap);
    }

    #[test]
    fn dequeue_returns_none_when_empty() {
        let mut q = HydrationQueue::new(8);
        assert!(q.dequeue().is_none());
        assert!(q.peek().is_none());
        assert!(q.is_empty());
    }

    #[test]
    fn remove_works() {
        let mut q = HydrationQueue::new(8);
        let r1 = req(HydrationReason::AdjacentPrefetch, 1);
        let r2 = req(HydrationReason::AdjacentPrefetch, 2);
        q.enqueue(r1.clone());
        q.enqueue(r2.clone());
        assert!(q.remove(&r1.message_id));
        assert!(!q.contains(&r1.message_id));
        assert_eq!(q.len(), 1);
        // Removing a non-existent id returns false.
        assert!(!q.remove(&Uuid::now_v7()));
    }

    #[test]
    fn prefetch_window_enqueues_p3_requests() {
        let mut q = HydrationQueue::new(8);
        let conv = Uuid::now_v7();
        let ids: Vec<Uuid> = (0..5).map(|_| Uuid::now_v7()).collect();
        q.enqueue_prefetch_window(&ids, conv, 5, 0);
        assert_eq!(q.len(), 5);
        for r in &q.items {
            assert_eq!(r.reason, HydrationReason::AdjacentPrefetch);
            assert_eq!(r.conversation_id, conv);
        }
    }

    #[test]
    fn capacity_is_remembered() {
        let q = HydrationQueue::new(64);
        assert_eq!(q.capacity(), 64);
    }
}
