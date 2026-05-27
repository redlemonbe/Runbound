// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Query statistics — shared between DNS hot path and REST API.
//
// All counters are AtomicU64: DNS increments and API reads never contend.
// Latency histogram uses fixed buckets — zero allocation per query.
// QPS ring buffer: 300 one-second slots (5-minute window), updated by a
// dedicated background task that reads the total counter each second.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde_json::Value as JsonValue;

/// Shared, lock-free snapshot cache.
/// Updated every second by `qps_update_loop`; API handlers read it
/// instead of calling `snapshot()` on every request (avoids ~360 atomic
/// loads per API call under monitoring load).
pub type SharedSnapshot = Arc<ArcSwap<StatsSnapshot>>;

pub fn new_snapshot_cache(stats: &Stats) -> SharedSnapshot {
    Arc::new(ArcSwap::from_pointee(stats.snapshot()))
}

// ── Latency histogram ──────────────────────────────────────────────────────
//
// 12 upper-bound thresholds in microseconds define 13 buckets:
//   [0]  ≤ 0.1 ms   [1]  ≤ 0.5 ms   [2]  ≤ 1 ms    [3]  ≤ 2 ms
//   [4]  ≤ 5 ms     [5]  ≤ 10 ms    [6]  ≤ 50 ms   [7]  ≤ 100 ms
//   [8]  ≤ 250 ms   [9]  ≤ 500 ms  [10]  ≤ 1 s     [11]  ≤ 3 s
//   [12] > 3 s     (overflow — reported as lower bound, not a fake midpoint)
pub const HIST_BOUNDS_US: [u64; 12] = [
    100, 500, 1_000, 2_000, 5_000, 10_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 3_000_000,
];
pub const HIST_BUCKETS: usize = 13;

// ── QPS ring buffer ────────────────────────────────────────────────────────
// 300 slots × 1 second each = 5-minute sliding window.
pub const QPS_RING_SIZE: usize = 300;

// ── Hickory resolver cache size ────────────────────────────────────────────
// Configured in build_resolver(); used to cap the cache_entries approximation.
const HICKORY_CACHE_SIZE: u64 = 8_192;

// ── Cache hit threshold ────────────────────────────────────────────────────
// Forward lookups completing in < 2 ms are almost certainly served from
// hickory's in-process cache (real upstream RTT is typically 5–200 ms).
pub const CACHE_HIT_THRESHOLD_US: u64 = 2_000;

// ── Cache-line padding (#70) ───────────────────────────────────────────────
// Wraps a value so it occupies its own 64-byte cache line.
// Used for fields that are written by different CPU cores (qps_head / qps_peak
// written by qps_update_loop vs. the per-query counters written by DNS handlers)
// to prevent false sharing — a read-for-ownership on one core invalidating the
// cache line of another core that modified an unrelated field in the same line.
#[repr(align(64))]
pub struct CachePadded<T>(pub T);

impl<T> std::ops::Deref for CachePadded<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T> std::ops::DerefMut for CachePadded<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

pub struct Stats {
    // Core query counters
    pub total: AtomicU64,
    pub blocked: AtomicU64,
    pub forwarded: AtomicU64,
    pub nxdomain: AtomicU64,
    pub refused: AtomicU64,
    pub stale_served: AtomicU64,
    pub servfail: AtomicU64,
    pub started_at: Instant,

    // Latency histogram — fixed 10 buckets, zero alloc per query
    pub lat_hist: Vec<AtomicU64>,

    // QPS ring buffer — 300 one-second slots
    pub qps_ring: Vec<AtomicU64>,
    // #70: each field lives on its own 64-byte cache line — qps_update_loop writes
    // these from a background task while DNS handlers write total/blocked/… on other
    // cores.  Without padding both would share a line causing false-sharing evictions.
    pub qps_head: CachePadded<AtomicU64>, // next write slot index
    pub qps_peak: CachePadded<AtomicU64>, // all-time peak (queries in any one second)

    // Cache / local resolution metrics
    // cache_hits: forwarded lookups < CACHE_HIT_THRESHOLD_US (likely in-process cache)
    // cache_misses: forwarded lookups ≥ threshold (network round-trip)
    // cache_entries: approximate count of distinct cached domains (0..HICKORY_CACHE_SIZE)
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_entries: AtomicU64,
    // local_hits: queries answered from local zone data (config + API dns_entries)
    pub local_hits: AtomicU64,

    // DNSSEC counters — only incremented when dnssec-validation is enabled.
    // secure:   resolved with valid DNSSEC signature chain (RRSIG present)
    // bogus:    DNSSEC validation failed (ProtoErrorKind::RrsigsNotPresent)
    // insecure: resolved OK but unsigned (no RRSIG — delegation proven unsigned by parent)
    pub dnssec_secure: AtomicU64,
    pub dnssec_bogus: AtomicU64,
    pub dnssec_insecure: AtomicU64,
    /// #34: upstream DNSSEC stripping events detected.

    // DoT reconnect metrics (#77 fix) — updated by keepalive, level-2 reconnect, and API endpoint.
    pub dot_reconnects_total: AtomicU64,
    /// ISO-8601 timestamp of the last successful resolver rebuild; None until first rebuild.
    pub last_reconnect_at: std::sync::Mutex<Option<String>>,
    /// Per-DNS-record-type query counters. Index = type code 0–255.
    pub qtype_counts: Vec<AtomicU64>,
    /// Accumulates queries with record type > 255 (e.g. CAA=257).
    pub qtype_high: AtomicU64,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            nxdomain: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            stale_served: AtomicU64::new(0),
            servfail: AtomicU64::new(0),
            started_at: Instant::now(),
            lat_hist: (0..HIST_BUCKETS).map(|_| AtomicU64::new(0)).collect(),
            qps_ring: (0..QPS_RING_SIZE).map(|_| AtomicU64::new(0)).collect(),
            qps_head: CachePadded(AtomicU64::new(0)),
            qps_peak: CachePadded(AtomicU64::new(0)),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_entries: AtomicU64::new(0),
            local_hits: AtomicU64::new(0),
            dnssec_secure: AtomicU64::new(0),
            dnssec_bogus: AtomicU64::new(0),
            dnssec_insecure: AtomicU64::new(0),
            dot_reconnects_total: AtomicU64::new(0),
            last_reconnect_at: std::sync::Mutex::new(None),
            qtype_counts: (0..256).map(|_| AtomicU64::new(0)).collect(),
            qtype_high: AtomicU64::new(0),
        })
    }

    /// Record a DoT resolver rebuild: increment counter and update timestamp.
    pub fn record_dot_reconnect(&self) {
        self.dot_reconnects_total.fetch_add(1, Ordering::Relaxed);
        let ts = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            crate::logbuffer::format_ts(secs)
        };
        if let Ok(mut g) = self.last_reconnect_at.lock() {
            *g = Some(ts);
        }
    }

    /// Increment the per-query-type counter for the given DNS type code.
    #[inline]
    pub fn inc_qtype_raw(&self, type_code: u16) {
        if (type_code as usize) < self.qtype_counts.len() {
            self.qtype_counts[type_code as usize].fetch_add(1, Ordering::Relaxed);
        } else {
            self.qtype_high.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn inc_total(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_blocked(&self) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_forwarded(&self) {
        self.forwarded.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_nxdomain(&self) {
        self.nxdomain.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_stale_served(&self) { self.stale_served.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_servfail(&self) {
        self.servfail.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_local_hits(&self) {
        self.local_hits.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_dnssec_secure(&self) {
        self.dnssec_secure.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_dnssec_bogus(&self) {
        self.dnssec_bogus.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn inc_dnssec_insecure(&self) {
        self.dnssec_insecure.fetch_add(1, Ordering::Relaxed);
    }

    /// Record query latency — zero allocation, single atomic increment.
    /// Finds the histogram bucket via binary search on the 9 thresholds.
    #[inline]
    pub fn record_latency_us(&self, us: u64) {
        // partition_point returns the first index i where HIST_BOUNDS_US[i] >= us,
        // i.e. the first bucket whose upper bound is ≥ the measured latency.
        let bucket = HIST_BOUNDS_US.partition_point(|&b| us > b);
        self.lat_hist[bucket].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a completed forwarded lookup and update cache metrics.
    /// elapsed_us < 2 ms → cache hit (hickory served from its in-process DNS cache).
    /// elapsed_us ≥ 2 ms → cache miss (round-trip to upstream resolver).
    #[inline]
    pub fn record_forward(&self, elapsed_us: u64) {
        if elapsed_us < CACHE_HIT_THRESHOLD_US {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
            // Approximate cache fill: increment up to hickory's cache size.
            // Saturates at HICKORY_CACHE_SIZE (matching hickory's eviction behaviour).
            self.cache_entries
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    if n < HICKORY_CACHE_SIZE {
                        Some(n + 1)
                    } else {
                        None
                    }
                })
                .ok();
        }
    }

    /// Reset cache counters after a resolver cache flush (called by memory_guard_loop).
    pub fn reset_cache(&self) {
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.cache_entries.store(0, Ordering::Relaxed);
    }

    /// Compute a percentile (0–100) from the current latency histogram.
    /// Returns the result in milliseconds.
    pub fn percentile_ms(&self, pct: f64) -> f64 {
        let counts: [u64; HIST_BUCKETS] =
            std::array::from_fn(|i| self.lat_hist[i].load(Ordering::Relaxed));
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return 0.0;
        }
        let target = ((total as f64 * pct / 100.0) as u64).max(1);
        let mut cum = 0u64;
        for (i, &c) in counts.iter().enumerate() {
            cum += c;
            if cum >= target {
                // Midpoint of bucket in µs → convert to ms.
                // Overflow bucket (no upper bound): report lower bound to avoid
                // returning a fake midpoint artifact.
                let mid_us: u64 = if i == 0 {
                    50 // midpoint of [0, 100µs]
                } else {
                    let lo = HIST_BOUNDS_US[i - 1];
                    match HIST_BOUNDS_US.get(i) {
                        Some(&hi) => (lo + hi) / 2,
                        None => lo,
                    }
                };
                return (mid_us as f64 / 1000.0 * 10.0).round() / 10.0;
            }
        }
        1000.0
    }

    /// Compute QPS statistics from the ring buffer.
    /// Returns (qps_1m, qps_5m, qps_peak).
    pub fn qps_stats(&self) -> (f64, f64, u64) {
        let head = self.qps_head.load(Ordering::Relaxed) as usize;
        let mut sum_1m: u64 = 0;
        let mut sum_5m: u64 = 0;
        for i in 0..QPS_RING_SIZE {
            // Walk backwards from the last written slot
            let slot = (head + QPS_RING_SIZE - 1 - i) % QPS_RING_SIZE;
            let v = self.qps_ring[slot].load(Ordering::Relaxed);
            if i < 60 {
                sum_1m += v;
            }
            sum_5m += v;
        }
        let qps_peak = self.qps_peak.load(Ordering::Relaxed);
        (
            (sum_1m as f64 / 60.0 * 10.0).round() / 10.0,
            (sum_5m as f64 / 300.0 * 10.0).round() / 10.0,
            qps_peak,
        )
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let total = self.total.load(Ordering::Relaxed);
        let blocked = self.blocked.load(Ordering::Relaxed);
        let nxdomain = self.nxdomain.load(Ordering::Relaxed);
        let ch = self.cache_hits.load(Ordering::Relaxed);
        let cm = self.cache_misses.load(Ordering::Relaxed);
        let cache_hit_rate = if ch + cm > 0 {
            (ch as f64 / (ch + cm) as f64 * 1000.0).round() / 10.0
        } else {
            0.0
        };
        let (qps_1m, qps_5m, qps_peak) = self.qps_stats();
        let qtype_stats = Self::build_qtype_stats(&self.qtype_counts, self.qtype_high.load(Ordering::Relaxed));
        StatsSnapshot {
            total,
            blocked,
            forwarded: self.forwarded.load(Ordering::Relaxed),
            nxdomain,
            refused: self.refused.load(Ordering::Relaxed),
            stale_served: self.stale_served.load(Ordering::Relaxed),
            servfail: self.servfail.load(Ordering::Relaxed),
            uptime_secs: self.started_at.elapsed().as_secs(),
            qps_1m,
            qps_5m,
            qps_peak,
            latency_p50_ms: self.percentile_ms(50.0),
            latency_p95_ms: self.percentile_ms(95.0),
            latency_p99_ms: self.percentile_ms(99.0),
            cache_hit_rate,
            cache_entries: self.cache_entries.load(Ordering::Relaxed),
            local_hits: self.local_hits.load(Ordering::Relaxed),
            dnssec_secure: self.dnssec_secure.load(Ordering::Relaxed),
            dnssec_bogus: self.dnssec_bogus.load(Ordering::Relaxed),
            dnssec_insecure: self.dnssec_insecure.load(Ordering::Relaxed),
            qtype_stats,
        }
    }

    fn build_qtype_stats(counts: &[AtomicU64], high: u64) -> Vec<(String, u64)> {
        const NAMED: &[(usize, &str)] = &[
            (1, "A"), (2, "NS"), (5, "CNAME"), (6, "SOA"), (12, "PTR"),
            (15, "MX"), (16, "TXT"), (28, "AAAA"), (33, "SRV"), (43, "DS"),
            (46, "RRSIG"), (47, "NSEC"), (48, "DNSKEY"), (52, "TLSA"), (255, "ANY"),
        ];
        let known: std::collections::HashSet<usize> = NAMED.iter().map(|&(i, _)| i).collect();
        let mut result: Vec<(String, u64)> = NAMED.iter().filter_map(|&(idx, name)| {
            let n = counts.get(idx).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0);
            if n > 0 { Some((name.to_owned(), n)) } else { None }
        }).collect();
        let other: u64 = counts.iter().enumerate()
            .filter(|(i, _)| !known.contains(i))
            .map(|(_, c)| c.load(Ordering::Relaxed))
            .sum::<u64>()
            .saturating_add(high);
        if other > 0 { result.push(("OTHER".to_owned(), other)); }
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }
}

pub struct StatsSnapshot {
    pub total: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub nxdomain: u64,
    pub refused: u64,
    pub stale_served: u64,
    pub servfail: u64,
    pub uptime_secs: u64,
    pub qps_1m: f64,
    pub qps_5m: f64,
    pub qps_peak: u64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub cache_hit_rate: f64,
    pub cache_entries: u64,
    pub local_hits: u64,
    pub dnssec_secure: u64,
    pub dnssec_bogus: u64,
    pub dnssec_insecure: u64,
    /// Per-record-type query distribution, sorted descending by count.
    pub qtype_stats: Vec<(String, u64)>,
}

pub fn snapshot_to_json(snap: &StatsSnapshot) -> JsonValue {
    let pct_blocked = if snap.total > 0 {
        (snap.blocked as f64 / snap.total as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };
    serde_json::json!({
        "total":            snap.total,
        "blocked":          snap.blocked,
        "forwarded":        snap.forwarded,
        "nxdomain":         snap.nxdomain,
        "stale_served":      snap.stale_served,
        "refused":          snap.refused,
        "servfail":         snap.servfail,
        "local_hits":       snap.local_hits,
        "blocked_percent":  pct_blocked,
        "uptime_secs":      snap.uptime_secs,
        "qps_1m":           snap.qps_1m,
        "qps_5m":           snap.qps_5m,
        "qps_peak":         snap.qps_peak,
        "latency_p50_ms":   snap.latency_p50_ms,
        "latency_p95_ms":   snap.latency_p95_ms,
        "latency_p99_ms":   snap.latency_p99_ms,
        "cache_hit_rate":   snap.cache_hit_rate,
        "cache_entries":    snap.cache_entries,
        "dnssec": {
            "secure":   snap.dnssec_secure,
            "bogus":    snap.dnssec_bogus,
            "insecure": snap.dnssec_insecure,
        },
        "qtype_stats": snap.qtype_stats.iter()
            .map(|(k, v)| serde_json::json!({"type": k, "count": v}))
            .collect::<Vec<_>>(),
    })
}

// ── QPS + snapshot background task ────────────────────────────────────────
//
// Runs every second:
//   1. Updates the QPS ring buffer and all-time peak.
//   2. Atomically swaps the SharedSnapshot so API handlers read pre-computed
//      values (avoids ~360 atomic loads per API call under monitoring load).
pub async fn qps_update_loop(stats: Arc<Stats>, snapshot_cache: SharedSnapshot) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prev_total: u64 = 0;

    loop {
        interval.tick().await;
        let total = stats.total.load(Ordering::Relaxed);
        let qps = total.saturating_sub(prev_total);
        prev_total = total;

        // Write to ring slot and advance head atomically.
        let slot = (stats.qps_head.fetch_add(1, Ordering::Relaxed) as usize) % QPS_RING_SIZE;
        stats.qps_ring[slot].store(qps, Ordering::Relaxed);

        // Update peak (lock-free max).
        stats.qps_peak.fetch_max(qps, Ordering::Relaxed);

        // Refresh the shared snapshot cache used by API handlers.
        snapshot_cache.store(Arc::new(stats.snapshot()));
    }
}
