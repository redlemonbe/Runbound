// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// DNS prefetch (FEAT #16) — background cache-scan refresher state.
//
// Keeps popular cache entries warm by re-resolving them shortly before they expire.
// This is entirely OFF the hot path: the executor (in `server::build_and_launch`)
// runs on a background task, and the per-key refresh budget below is never read or
// written by the serving fast path — so prefetch adds zero cost to serving.
//
// The budget bounds wasted upstream traffic: an entry may be prefetch-refreshed at
// most `PREFETCH_BUDGET` times before it is left to expire, unless a global reset
// (fired periodically by the executor) restores budgets so still-popular names can
// be refreshed again. Opt-in via `prefetch: yes`.

use std::sync::Arc;

use dashmap::DashMap;

/// Max prefetch refreshes for one cache key before it is left to expire (until the
/// next periodic global reset). Bounds the traffic spent on a name nobody asks for.
pub const PREFETCH_BUDGET: u8 = 8;

/// Per-cache-key refresh budget. Background-only state.
pub struct PrefetchTracker {
    budget: DashMap<u64, u8, ahash::RandomState>,
}

impl PrefetchTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            budget: DashMap::with_hasher(ahash::RandomState::default()),
        })
    }

    /// Refresh budget remaining for `key` (full budget if never seen).
    pub fn budget(&self, key: u64) -> u8 {
        self.budget.get(&key).map(|v| *v).unwrap_or(PREFETCH_BUDGET)
    }

    /// Spend one refresh for `key` (saturating at 0).
    pub fn spend(&self, key: u64) {
        let left = self.budget(key).saturating_sub(1);
        self.budget.insert(key, left);
    }

    /// Clear all budgets — a periodic global reset so still-popular names can be
    /// refreshed again after their budget was spent.
    pub fn reset_all(&self) {
        self.budget.clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.budget.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_spend_and_reset() {
        let t = PrefetchTracker::new();
        // Unseen key starts at full budget.
        assert_eq!(t.budget(42), PREFETCH_BUDGET);
        t.spend(42);
        assert_eq!(t.budget(42), PREFETCH_BUDGET - 1);
        // Spending past zero saturates.
        for _ in 0..PREFETCH_BUDGET {
            t.spend(42);
        }
        assert_eq!(t.budget(42), 0);
        // Global reset restores full budget.
        t.reset_all();
        assert_eq!(t.budget(42), PREFETCH_BUDGET);
        assert_eq!(t.len(), 0);
    }
}
