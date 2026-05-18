// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Per-IP token-bucket rate limiter shared between the normal DNS path
// (server.rs) and the XDP fast-path (xdp/worker.rs).

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;

const RATE_LIMIT_WINDOW_MS:   u64 = 1_000;
const MAX_RATE_LIMIT_BUCKETS: usize = 65_536;

struct IpBucket {
    tokens:      u64,
    last_refill: Instant,
}

pub struct RateLimiter {
    buckets:         DashMap<IpAddr, IpBucket, ahash::RandomState>,
    cleanup_counter: AtomicU64,
    rps:             u64,
    burst:           u64,
}

impl RateLimiter {
    pub fn new(rps: u64) -> Arc<Self> {
        Arc::new(Self {
            buckets: DashMap::with_hasher(ahash::RandomState::default()),
            cleanup_counter: AtomicU64::new(0),
            rps,
            burst: rps.saturating_mul(2),
        })
    }

    #[inline]
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.rps == 0 {
            return true;
        }

        let now = Instant::now();

        let count = self.cleanup_counter.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(10_000) {
            self.buckets.retain(|_, b| now.duration_since(b.last_refill).as_secs() < 60);
        }

        if !self.buckets.contains_key(&ip) && self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
            // Bucket table full — aggressively evict idle entries (>10 s) before
            // silently dropping the new IP. This prevents a bucket-exhaustion attack
            // where an attacker floods from N distinct IPs to fill the table and
            // cause all subsequent IPs (including legitimate clients) to be refused.
            self.buckets.retain(|_, b| now.duration_since(b.last_refill).as_secs() < 10);
            if self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
                // Still full after eviction — table is under active flood; drop.
                return false;
            }
        }

        let mut bucket = self.buckets.entry(ip).or_insert(IpBucket {
            tokens:      self.burst,
            last_refill: now,
        });

        let elapsed_ms = now.duration_since(bucket.last_refill).as_millis() as u64;
        if elapsed_ms >= RATE_LIMIT_WINDOW_MS {
            bucket.tokens = self.burst;
            bucket.last_refill = now;
        } else {
            let new_tokens = (self.rps * elapsed_ms) / RATE_LIMIT_WINDOW_MS;
            if new_tokens > 0 {
                bucket.tokens = (bucket.tokens + new_tokens).min(self.burst);
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
