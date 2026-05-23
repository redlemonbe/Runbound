// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// XDP DNS cache snapshot — issue #60.
//
// Double-buffer design:
//   Writer (DNS server, tokio task): Mutex<HashMap> — low-contention inserts
//   Reader (XDP workers, OS threads): ArcSwap<HashMap> — zero-lock snapshot reads
//
// A background publish_loop clones the mutable map every 100 ms, evicts expired
// entries, and atomically replaces the shared snapshot.  XDP workers call
// load_full() once per received batch and look up from the frozen copy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

/// Key for cache lookup: lowercase FQDN with trailing dot + wire-format query type.
#[derive(Hash, Eq, PartialEq, Clone)]
pub struct QuestionKey {
    /// Lowercase FQDN with trailing dot (e.g. "example.com.").
    pub name:  String,
    /// Wire-format numeric query type (1 = A, 28 = AAAA, …).
    pub qtype: u16,
}

pub struct CacheEntry {
    /// DNS response in wire format with QID zeroed. The XDP worker patches
    /// bytes [0..2] with the actual QID before sending.
    pub wire_response: Arc<Vec<u8>>,
    pub expires_at:    Instant,
}

impl Clone for CacheEntry {
    fn clone(&self) -> Self {
        Self {
            wire_response: Arc::clone(&self.wire_response),
            expires_at:    self.expires_at,
        }
    }
}

pub type CacheSnapshot     = HashMap<QuestionKey, CacheEntry>;
pub type SharedCacheSnapshot = Arc<ArcSwap<CacheSnapshot>>;
pub type MutableCacheMap   = Arc<Mutex<CacheSnapshot>>;

/// Global counter of DNS responses served from the XDP cache snapshot.
/// Read by the Prometheus metrics handler.
pub static XDP_CACHE_SNAPSHOT_HITS: AtomicU64 = AtomicU64::new(0);

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
    let mut map = mutable.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() >= max_entries && !map.contains_key(&key) {
        let now = Instant::now();
        let to_remove = map.iter()
            .find(|(_, v)| v.expires_at <= now)
            .map(|(k, _)| k.clone());
        match to_remove {
            Some(k) => { map.remove(&k); }
            None    => return, // all entries still live — skip this insert
        }
    }
    map.insert(key, entry);
}

/// Background task: every 100 ms, clone the mutable map (evicting expired
/// entries), then atomically publish it as the new read-only snapshot.
pub async fn publish_loop(snapshot: SharedCacheSnapshot, mutable: MutableCacheMap) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let new_snap: CacheSnapshot = {
            let map = mutable.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            map.iter()
                .filter(|(_, v)| v.expires_at > now)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        snapshot.store(Arc::new(new_snap));
    }
}
