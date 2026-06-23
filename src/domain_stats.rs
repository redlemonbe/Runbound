// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Per-domain query counter — feeds GET /api/stats/top-domains (#5).
//
// Uses DashMap so DNS worker threads can increment without contending on a
// global lock. Capped at MAX_TRACKED domains to bound worst-case heap usage.
// Counters are cumulative since process start; no windowing in this version.

use std::cell::{Cell, RefCell};
use std::collections::HashMap as StdHashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;

const MAX_TRACKED: usize = 10_000;
/// Flush the thread-local accumulator into the global DashMap every N increments.
/// Reduces atomic contention on hot domains by up to FLUSH_INTERVAL× (PERF-4 / #136).
const FLUSH_INTERVAL: u64 = 512;

/// Sampling rate for the XDP cache-hit hot path (inc_wire). The path can run at >10 M/s;
/// touching the shared top-domains map every hit contends and crushes throughput at high
/// domain cardinality (v0.22.1 regression). We process 1 in INC_WIRE_SAMPLE hits and weight
/// the count by INC_WIRE_SAMPLE so the top-N estimate stays statistically unbiased. Must be
/// a power of two for the cheap `& mask` test.
const INC_WIRE_SAMPLE: u64 = 32;

thread_local! {
    static TL_DS_BUF: RefCell<StdHashMap<Box<str>, u64>> =
        RefCell::new(StdHashMap::new());
    static TL_DS_CALLS: Cell<u64> = const { Cell::new(0) };
    // Per-thread sampling counter for the XDP hot path (inc_wire).
    static TL_DS_SAMPLE: Cell<u64> = const { Cell::new(0) };
    // Reused scratch for wire→dotted QNAME conversion on the XDP hot path (inc_wire),
    // so cache-hit attribution allocates nothing in steady state.
    static TL_NAME_BUF: RefCell<String> = RefCell::new(String::with_capacity(256));
}

pub struct DomainStats {
    map: DashMap<Box<str>, AtomicU64, ahash::RandomState>,
    /// Approximate live entry count, maintained on insert. Used by `flush_tl` instead of
    /// `DashMap::len()` (which read-locks EVERY shard): at high domain cardinality the map
    /// stays full at MAX_TRACKED, so every untracked key hit the all-shard `len()` lock —
    /// with N workers that collapsed XDP throughput ~2× (the dual-NIC 100K regression, #209).
    entries: AtomicUsize,
}

impl DomainStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            map: DashMap::with_hasher(ahash::RandomState::default()),
            entries: AtomicUsize::new(0),
        })
    }

    /// Increment the query counter for `domain`.
    ///
    /// Writes to a thread-local accumulator and flushes to the shared DashMap
    /// every FLUSH_INTERVAL calls (PERF-4 / #136).  Counts within the unflushed
    /// window may be temporarily invisible to GET /api/stats/top-domains —
    /// acceptable for a monitoring dashboard.
    pub fn inc(&self, domain: &str) {
        // Check-then-insert: a repeat domain (the common case) only bumps a u64 and never
        // allocates; a Box<str> key is built only the first time a domain appears in this
        // thread's window. (Previously `entry(domain.into())` allocated on every call.)
        TL_DS_BUF.with(|buf| {
            let mut b = buf.borrow_mut();
            if let Some(v) = b.get_mut(domain) {
                *v += 1;
            } else {
                b.insert(domain.into(), 1);
            }
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

    /// Increment from a wire-format QNAME (length-prefixed labels, NUL-terminated) —
    /// the form the XDP cache-hit hot path holds. Converts into a reused thread-local
    /// String (zero per-hit heap allocation in steady state), producing the same dotted,
    /// trailing-dot, lowercase key as the slow path so the two datapaths merge into one
    /// count. Contention-free: writes a thread-local accumulator, flushed periodically.
    pub fn inc_wire(&self, wire_qname: &[u8]) {
        // Sample 1/INC_WIRE_SAMPLE hits: on the other (SAMPLE-1)/SAMPLE the hot path pays
        // only a thread-local counter bump and returns, keeping XDP throughput at line rate
        // even with a huge working set. The sampled hit is weighted by INC_WIRE_SAMPLE so the
        // top-N estimate stays statistically unbiased.
        let n = TL_DS_SAMPLE.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            v
        });
        if n & (INC_WIRE_SAMPLE - 1) != 0 {
            return;
        }
        self.inc_wire_one(wire_qname, INC_WIRE_SAMPLE);
    }

    /// Decode a wire QNAME into the reused thread-local String and add `weight` to its
    /// count (allocation-free in steady state). Returns silently on a malformed QNAME.
    /// `inc_wire` wraps this with sampling; tests call it directly for deterministic decode.
    fn inc_wire_one(&self, wire_qname: &[u8], weight: u64) {
        let counted = TL_NAME_BUF.with(|nb| {
            let mut name = nb.borrow_mut();
            name.clear();
            let mut i = 0usize;
            while i < wire_qname.len() {
                let len = wire_qname[i] as usize;
                if len == 0 {
                    break; // root label → end of name
                }
                if len > 63 || i + 1 + len > wire_qname.len() {
                    return false; // malformed wire → skip, count nothing
                }
                i += 1;
                // Wire QNAME bytes are ASCII (already lowercased by the caller).
                for &b in &wire_qname[i..i + len] {
                    name.push(b as char);
                }
                name.push('.');
                i += len;
            }
            if name.is_empty() {
                return false;
            }
            TL_DS_BUF.with(|buf| {
                let mut b = buf.borrow_mut();
                if let Some(v) = b.get_mut(name.as_str()) {
                    *v += weight;
                } else {
                    b.insert(name.as_str().into(), weight);
                }
            });
            true
        });
        if !counted {
            return;
        }
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
                } else if self.entries.load(Ordering::Relaxed) < MAX_TRACKED {
                    // Cheap atomic load instead of DashMap::len() (all-shard read lock).
                    // Use the Entry API so we only bump `entries` when WE create the key;
                    // a small over-count under a race is fine (MAX_TRACKED is a soft cap).
                    use dashmap::mapref::entry::Entry;
                    match self.map.entry(k) {
                        Entry::Occupied(e) => {
                            e.get().fetch_add(n, Ordering::Relaxed);
                        }
                        Entry::Vacant(e) => {
                            e.insert(AtomicU64::new(n));
                            self.entries.fetch_add(1, Ordering::Relaxed);
                        }
                    }
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
    fn inc_wire_one_decodes_and_merges_with_inc() {
        let ds = DomainStats::new();
        // Wire QNAME for "health.curseforge.com." : length-prefixed labels + root NUL.
        // health=6, curseforge=10 (0x0a), com=3.
        let wire = b"\x06health\x0acurseforge\x03com\x00";
        for _ in 0..3 {
            ds.inc_wire_one(wire, 1);
        }
        // The slow-path string API must produce the SAME dotted key and merge into one count.
        ds.inc("health.curseforge.com.");
        let top = ds.top(10);
        assert_eq!(
            top[0],
            ("health.curseforge.com.".to_string(), 4),
            "inc_wire decode must produce the same dotted, trailing-dot key as inc() and sum"
        );
    }

    #[test]
    fn inc_wire_one_rejects_malformed() {
        let ds = DomainStats::new();
        ds.inc_wire_one(b"\x40toolong", 1); // label length 64 > 63 max → skip
        ds.inc_wire_one(b"\x06ab", 1); // claims 6 bytes, only 2 present → skip
        ds.inc_wire_one(b"\x02ok\x00", 1); // well-formed "ok."
        assert_eq!(
            ds.top(10),
            vec![("ok.".to_string(), 1)],
            "malformed wire QNAMEs must be skipped, not counted"
        );
    }

    #[test]
    fn inc_wire_sampling_is_weighted_and_unbiased() {
        let ds = DomainStats::new();
        let wire = b"\x03ex1\x03com\x00";
        // Any window of INC_WIRE_SAMPLE consecutive calls crosses exactly one sample boundary
        // (multiples of the power-of-two rate are INC_WIRE_SAMPLE apart), so the weighted
        // estimate equals the real count regardless of the thread-local counter's start value.
        for _ in 0..INC_WIRE_SAMPLE {
            ds.inc_wire(wire);
        }
        let top = ds.top(10);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, "ex1.com.");
        assert_eq!(
            top[0].1, INC_WIRE_SAMPLE,
            "1 sampled hit weighted by INC_WIRE_SAMPLE estimates INC_WIRE_SAMPLE real hits"
        );
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
