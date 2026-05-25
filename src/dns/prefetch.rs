// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// DNS prefetch tracker — counts forwarded queries per domain per window.
// When a domain exceeds the threshold the background task re-resolves it
// proactively before the cached answer expires (opt-in, prefetch: yes).
//
// Uses DashMap<String, AtomicU32> instead of Mutex<HashMap> so that DNS
// worker threads can increment counters without contending on a global lock.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dashmap::DashMap;

pub struct PrefetchTracker {
    inner: DashMap<String, AtomicU32, ahash::RandomState>,
}

impl PrefetchTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: DashMap::with_hasher(ahash::RandomState::default()),
        })
    }

    /// Increment the request counter for `domain` — lock-free on the fast path.
    pub fn increment(&self, domain: &str) {
        if let Some(v) = self.inner.get(domain) {
            v.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner
                .entry(domain.to_owned())
                .or_insert_with(|| AtomicU32::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Return all domains with count >= threshold and reset all counters to zero.
    pub fn take_hot(&self, threshold: u32) -> Vec<String> {
        let hot: Vec<String> = self
            .inner
            .iter()
            .filter(|e| e.value().load(Ordering::Relaxed) >= threshold)
            .map(|e| e.key().clone())
            .collect();
        self.inner.clear();
        hot
    }

    #[cfg(test)]
    pub fn count_for(&self, domain: &str) -> u32 {
        self.inner
            .get(domain)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_and_count() {
        let t = PrefetchTracker::new();
        t.increment("example.com");
        t.increment("example.com");
        t.increment("other.net");
        assert_eq!(t.count_for("example.com"), 2);
        assert_eq!(t.count_for("other.net"), 1);
    }

    #[test]
    fn take_hot_filters_by_threshold() {
        let t = PrefetchTracker::new();
        for _ in 0..5 {
            t.increment("hot.com");
        }
        t.increment("cold.com");
        let hot = t.take_hot(5);
        assert_eq!(hot, vec!["hot.com"]);
        // counters reset
        assert_eq!(t.count_for("hot.com"), 0);
        assert_eq!(t.count_for("cold.com"), 0);
    }

    #[test]
    fn take_hot_resets_all_counters() {
        let t = PrefetchTracker::new();
        t.increment("a.com");
        t.increment("b.com");
        let _ = t.take_hot(1);
        assert_eq!(t.len(), 0);
    }
}
