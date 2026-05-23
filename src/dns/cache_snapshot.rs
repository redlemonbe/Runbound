// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// XDP DNS cache snapshot — issue #60 (upgraded for wire-format keys in #64).
//
// Double-buffer design:
//   Writer (DNS server, tokio task): DashMap — concurrent lock-free inserts
//   Reader (XDP workers, OS threads): ArcSwap<HashMap> — zero-lock snapshot reads
//
// A background publish_loop clones the mutable map every 10 ms, evicts expired
// entries, and atomically replaces the shared snapshot.  XDP workers call
// load_full() once per received batch and look up from the frozen copy.
//
// #64 upgrade: QuestionKey now uses wire-format DNS name bytes (SmallVec) +
// qclass field; CacheEntry uses bytes::Bytes for zero-copy payload access.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use arc_swap::ArcSwap;
use bytes::Bytes;
use smallvec::SmallVec;

/// Key for cache lookup: wire-format lowercase DNS name + query type + class.
///
/// Wire format: length-prefixed labels, e.g. `\x07example\x03com\x00`.
/// Lowercase is guaranteed by the caller (LowerName or equivalent).
/// 64 bytes is enough for names up to ~60 chars without heap allocation.
#[derive(Hash, Eq, PartialEq, Clone)]
pub struct QuestionKey {
    /// Wire-format DNS name, lowercased (matches QNAME bytes from the client).
    pub name:   SmallVec<[u8; 64]>,
    /// Wire-format numeric query type (1 = A, 28 = AAAA, …).
    pub qtype:  u16,
    /// Wire-format query class (1 = IN).
    pub qclass: u16,
}

pub struct CacheEntry {
    /// Full DNS response datagram in wire format with QID zeroed (bytes [0..2]).
    /// The XDP worker patches bytes [0..2] with the actual QID before sending.
    /// Using `Bytes` enables O(1) clones during the snapshot publish — Arc<[u8]> internally.
    pub wire_payload: Bytes,
    pub expires_at:   Instant,
}

impl Clone for CacheEntry {
    fn clone(&self) -> Self {
        Self {
            wire_payload: self.wire_payload.clone(), // O(1) — just increments the Arc refcount
            expires_at:   self.expires_at,
        }
    }
}

pub type CacheSnapshot       = HashMap<QuestionKey, CacheEntry>;
pub type SharedCacheSnapshot = Arc<ArcSwap<CacheSnapshot>>;
pub type MutableCacheMap     = Arc<DashMap<QuestionKey, CacheEntry>>;

/// Global counter of DNS responses served from the XDP cache snapshot.
/// Read by the Prometheus metrics handler and GET /api/system.
pub static XDP_CACHE_SNAPSHOT_HITS:    AtomicU64 = AtomicU64::new(0);
pub static XDP_CACHE_SNAPSHOT_MISSES:  AtomicU64 = AtomicU64::new(0);
/// Live entry count, updated by publish_loop after each snapshot swap.
pub static XDP_CACHE_SNAPSHOT_ENTRIES: AtomicU64 = AtomicU64::new(0);

// ── Per-worker packet distribution (#67) ─────────────────────────────────────
// 64 slots (one per NIC queue / worker thread). Incremented by xdp_worker
// threads and read by GET /api/system. Kept in this always-compiled module so
// the API handler can reference it without the "xdp" feature gate.
#[allow(clippy::declare_interior_mutable_const)]
pub static XDP_WORKER_PKTS: [AtomicU64; 64] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 64]
};

/// Insert a cache entry, respecting the max-entries cap.
///
/// If the map is full and the incoming key is new, we evict the first expired
/// entry found.  If no expired entry exists we skip the insert (backpressure)
/// rather than evicting live entries — better to let the entry be served by
/// hickory than to purge a still-valid cached response.
pub fn cache_insert(
    mutable:     &MutableCacheMap,
    key:         QuestionKey,
    entry:       CacheEntry,
    max_entries: usize,
) {
    if mutable.len() >= max_entries && !mutable.contains_key(&key) {
        let now = Instant::now();
        let to_remove = mutable.iter()
            .find(|kv| kv.value().expires_at <= now)
            .map(|kv| kv.key().clone());
        match to_remove {
            Some(k) => { mutable.remove(&k); }
            None    => return, // all entries still live — skip this insert
        }
    }
    mutable.insert(key, entry);
}

/// Background task: every 10 ms, clone the mutable map (evicting expired
/// entries), then atomically publish it as the new read-only snapshot.
pub async fn publish_loop(snapshot: SharedCacheSnapshot, mutable: MutableCacheMap) {
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let now = Instant::now();
        let new_snap: CacheSnapshot = mutable.iter()
            .filter(|kv| kv.value().expires_at > now)
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect();
        XDP_CACHE_SNAPSHOT_ENTRIES.store(new_snap.len() as u64, Ordering::Relaxed);
        snapshot.store(Arc::new(new_snap));
    }
}
