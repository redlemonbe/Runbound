// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Per-domain query counter — feeds GET /api/stats/top-domains (#5).
//
// Uses DashMap so DNS worker threads can increment without contending on a
// global lock. Capped at MAX_TRACKED domains to bound worst-case heap usage.
// Counters are cumulative since process start; no windowing in this version.

use std::cell::{Cell, RefCell};
use std::collections::HashMap as StdHashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;

const MAX_TRACKED: usize = 10_000;
/// Flush the thread-local accumulator into the global DashMap every N increments.
/// Reduces atomic contention on hot domains by up to FLUSH_INTERVAL× (PERF-4 / #136).
const FLUSH_INTERVAL: u64 = 512;

thread_local! {
    static TL_DS_BUF: RefCell<StdHashMap<Box<str>, u64>> =
        RefCell::new(StdHashMap::new());
    static TL_DS_CALLS: Cell<u64> = const { Cell::new(0) };
}

pub struct DomainStats {
    map: DashMap<Box<str>, AtomicU64, ahash::RandomState>,
}

impl DomainStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            map: DashMap::with_hasher(ahash::RandomState::default()),
        })
    }

    /// Increment the query counter for `domain`.
    ///
    /// Writes to a thread-local accumulator and flushes to the shared DashMap
    /// every FLUSH_INTERVAL calls (PERF-4 / #136).  Counts within the unflushed
    /// window may be temporarily invisible to GET /api/stats/top-domains —
    /// acceptable for a monitoring dashboard.
    pub fn inc(&self, domain: &str) {
        TL_DS_BUF.with(|buf| {
            *buf.borrow_mut().entry(domain.into()).or_insert(0) += 1;
        });
        let calls = TL_DS_CALLS.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            v
        });
        if calls % FLUSH_INTERVAL == 0 {
            self.flush_tl();
        }
    }

    /// Drain the calling thread's accumulator into the shared DashMap.
    pub fn flush_tl(&self) {
        TL_DS_BUF.with(|buf| {
            let mut map = buf.borrow_mut();
            for (k, n) in map.drain() {
                if let Some(v) = self.map.get(k.as_ref()) {
                    v.fetch_add(n, Ordering::Relaxed);
                } else if self.map.len() < MAX_TRACKED {
                    self.map
                        .entry(k)
                        .or_insert_with(|| AtomicU64::new(0))
                        .fetch_add(n, Ordering::Relaxed);
                }
            }
        });
    }

    /// Return the top `limit` domains by query count, sorted descending.
    /// Each tuple is (domain, count).
    /// Flushes the calling thread's TL buffer first so counts are up-to-date.
    pub fn top(&self, limit: usize) -> Vec<(String, u64)> {
        self.flush_tl();
        let mut v: Vec<(String, u64)> = self
            .map
            .iter()
            .map(|e| (e.key().to_string(), e.value().load(Ordering::Relaxed)))
            .collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(limit);
        v
    }

    /// Total number of tracked domains.
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inc_and_top() {
        let ds = DomainStats::new();
        for _ in 0..5 {
            ds.inc("popular.com");
        }
        ds.inc("rare.com");
        let top = ds.top(10);
        assert_eq!(top[0], ("popular.com".to_string(), 5));
        assert_eq!(top[1], ("rare.com".to_string(), 1));
    }

    #[test]
    fn top_respects_limit() {
        let ds = DomainStats::new();
        ds.inc("a.com");
        ds.inc("b.com");
        ds.inc("c.com");
        assert_eq!(ds.top(2).len(), 2);
    }

    #[test]
    fn idempotent_on_cap() {
        let ds = DomainStats::new();
        // Fill to cap using a deterministic set of domains.
        for i in 0..MAX_TRACKED {
            ds.inc(&format!("domain{i}.test"));
        }
        ds.flush_tl(); // drain TL batch buffer before checking len
        assert_eq!(ds.len(), MAX_TRACKED);
        // A new domain should be silently ignored.
        ds.inc("overflow.test");
        ds.flush_tl();
        assert_eq!(ds.len(), MAX_TRACKED);
        // An existing domain should still increment.
        ds.inc("domain0.test");
        let top = ds.top(1);
        assert_eq!(top[0].1, 2);
    }
}
