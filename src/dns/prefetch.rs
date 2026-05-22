// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// DNS prefetch tracker — counts forwarded queries per domain per window.
// When a domain exceeds the threshold the background task re-resolves it
// proactively before the cached answer expires (opt-in, prefetch: yes).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct PrefetchTracker {
    inner: Mutex<HashMap<String, u32>>,
}

impl PrefetchTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(HashMap::new()) })
    }

    /// Increment the request counter for `domain`.
    pub fn increment(&self, domain: &str) {
        let mut map = self.inner.lock()
            .unwrap_or_else(|e| panic!("prefetch: Mutex poisoned in increment: {e}"));
        *map.entry(domain.to_string()).or_insert(0) += 1;
    }

    /// Return all domains with count >= threshold and reset all counters to zero.
    pub fn take_hot(&self, threshold: u32) -> Vec<String> {
        let mut map = self.inner.lock()
            .unwrap_or_else(|e| panic!("prefetch: Mutex poisoned in take_hot: {e}"));
        let hot: Vec<String> = map.iter()
            .filter(|(_, &count)| count >= threshold)
            .map(|(k, _)| k.clone())
            .collect();
        map.clear();
        hot
    }

    #[cfg(test)]
    pub fn count_for(&self, domain: &str) -> u32 {
        let map = self.inner.lock()
            .unwrap_or_else(|e| e.into_inner());
        *map.get(domain).unwrap_or(&0)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
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
        for _ in 0..5 { t.increment("hot.com"); }
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
