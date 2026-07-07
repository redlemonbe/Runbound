// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Per-IP token-bucket rate limiter shared between the normal DNS path
// (server.rs) and the XDP fast-path (xdp/worker.rs).

use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

const RATE_LIMIT_WINDOW_MS: u64 = 1_000;
const MAX_RATE_LIMIT_BUCKETS: usize = 65_536;

/// Mask a source IP to the configured prefix before DashMap lookup.
/// IPv4: zero host bits beyond `prefix_v4` (e.g. /24 → x.x.x.0).
/// IPv6: zero host bits beyond `prefix_v6` (e.g. /48 → keep first 6 bytes).
/// Grouping flood traffic to a subnet bucket reduces shard-lock contention at
/// high QPS and prevents bucket-exhaustion attacks from many distinct IPs in
/// the same routed block.
fn normalize_ip(ip: IpAddr, prefix_v4: u8, prefix_v6: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix_v4 == 0 {
                0 // /0 buckets every source together; avoids the shift-by-32 UB
            } else if prefix_v4 >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix_v4)
            };
            IpAddr::V4((bits & mask).into())
        }
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            let keep_bytes = (prefix_v6 as usize) / 8;
            let keep_bits = (prefix_v6 as usize) % 8;
            if keep_bytes < 16 {
                if keep_bits > 0 {
                    octets[keep_bytes] &= 0xFF_u8 << (8 - keep_bits);
                    for b in &mut octets[keep_bytes + 1..] {
                        *b = 0;
                    }
                } else {
                    for b in &mut octets[keep_bytes..] {
                        *b = 0;
                    }
                }
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

struct IpBucket {
    tokens: u64,
    last_refill: Instant,
}

pub struct RateLimiter {
    buckets: DashMap<IpAddr, IpBucket, ahash::RandomState>,
    start: Instant,        // base for nanosecond GC clock
    next_gc_ns: AtomicU64, // nanos since `start` at which to next run retain()
    rps: u64,
    burst: u64,
    prefix_v4: u8,
    prefix_v6: u8,
}

impl RateLimiter {
    pub fn new(rps: u64, burst: Option<u64>, prefix_v4: u8, prefix_v6: u8) -> Arc<Self> {
        Arc::new(Self {
            buckets: DashMap::with_hasher(ahash::RandomState::default()),
            start: Instant::now(),
            next_gc_ns: AtomicU64::new(10_000_000_000), // first GC at 10 s
            rps,
            burst: burst.unwrap_or_else(|| rps.saturating_mul(2)),
            prefix_v4,
            prefix_v6,
        })
    }

    /// Cheap disabled-check (rps==0) so hot paths can skip the gate entirely.
    #[inline]
    pub fn enabled(&self) -> bool { self.rps != 0 }

    #[inline]
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.rps == 0 {
            return true;
        }
        // Never rate-limit loopback (local health checks / dig @127.0.0.1) — mirrors the
        // ban systems' loopback exemption. Remote clients always arrive via the real IP.
        if ip.is_loopback() {
            return true;
        }

        let ip = normalize_ip(ip, self.prefix_v4, self.prefix_v6);
        let now = Instant::now();

        // Time-based GC: hot path is a single load (no write, no cache-line contention).
        // One thread per 10-second window runs retain() via a CAS.
        let now_ns = now.duration_since(self.start).as_nanos() as u64;
        let gc_at = self.next_gc_ns.load(Ordering::Relaxed);
        if now_ns >= gc_at
            && self
                .next_gc_ns
                .compare_exchange(
                    gc_at,
                    gc_at.saturating_add(10_000_000_000),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            self.buckets
                .retain(|_, b| now.duration_since(b.last_refill).as_secs() < 60);
        }

        if self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS && !self.buckets.contains_key(&ip) {
            // Bucket table full — aggressively evict idle entries (>10 s) before
            // silently dropping the new IP. This prevents a bucket-exhaustion attack
            // where an attacker floods from N distinct IPs to fill the table and
            // cause all subsequent IPs (including legitimate clients) to be refused.
            self.buckets
                .retain(|_, b| now.duration_since(b.last_refill).as_secs() < 10);
            if self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
                // Still full after eviction — table is under active flood; drop.
                return false;
            }
        }

        let mut bucket = self.buckets.entry(ip).or_insert_with(|| IpBucket {
            tokens: self.burst,
            last_refill: now,
        });

        let elapsed_ms = now.duration_since(bucket.last_refill).as_millis() as u64;
        if elapsed_ms >= RATE_LIMIT_WINDOW_MS {
            bucket.tokens = self.burst;
            bucket.last_refill = now;
        } else {
            // u128 math + saturating add: a huge configured rps must never overflow.
            let new_tokens =
                ((self.rps as u128 * elapsed_ms as u128) / RATE_LIMIT_WINDOW_MS as u128) as u64;
            if new_tokens > 0 {
                bucket.tokens = bucket.tokens.saturating_add(new_tokens).min(self.burst);
                bucket.last_refill = now;
            }
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }

    pub fn clear(&self) -> usize {
        let count = self.buckets.len();
        self.buckets.clear();
        count
    }
}
