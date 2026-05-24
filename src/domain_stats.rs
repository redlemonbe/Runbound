// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Per-domain query counter — feeds GET /api/stats/top-domains (#5).
//
// Uses DashMap so DNS worker threads can increment without contending on a
// global lock. Capped at MAX_TRACKED domains to bound worst-case heap usage.
// Counters are cumulative since process start; no windowing in this version.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;

const MAX_TRACKED: usize = 10_000;

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
    /// Silently ignored when MAX_TRACKED is reached.
    pub fn inc(&self, domain: &str) {
        if let Some(v) = self.map.get(domain) {
            v.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.map.len() >= MAX_TRACKED {
            return;
        }
        self.map
            .entry(domain.into())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Return the top `limit` domains by query count, sorted descending.
    /// Each tuple is (domain, count).
    pub fn top(&self, limit: usize) -> Vec<(String, u64)> {
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
        assert_eq!(ds.len(), MAX_TRACKED);
        // A new domain should be silently ignored.
        ds.inc("overflow.test");
        assert_eq!(ds.len(), MAX_TRACKED);
        // An existing domain should still increment.
        ds.inc("domain0.test");
        let top = ds.top(1);
        assert_eq!(top[0].1, 2);
    }
}
