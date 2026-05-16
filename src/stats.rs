// Query statistics counters — shared between DNS handler and REST API.
// All fields are AtomicU64 so reads from /stats and increments from the
// hot DNS path never contend with each other.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub struct Stats {
    pub total:     AtomicU64,
    pub blocked:   AtomicU64,
    pub forwarded: AtomicU64,
    pub nxdomain:  AtomicU64,
    pub refused:   AtomicU64,
    pub servfail:  AtomicU64,
    pub started_at: Instant,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total:      AtomicU64::new(0),
            blocked:    AtomicU64::new(0),
            forwarded:  AtomicU64::new(0),
            nxdomain:   AtomicU64::new(0),
            refused:    AtomicU64::new(0),
            servfail:   AtomicU64::new(0),
            started_at: Instant::now(),
        })
    }

    pub fn inc_total(&self)     { self.total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_blocked(&self)   { self.blocked.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_forwarded(&self) { self.forwarded.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_nxdomain(&self)  { self.nxdomain.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_refused(&self)   { self.refused.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_servfail(&self)  { self.servfail.fetch_add(1, Ordering::Relaxed); }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total:        self.total.load(Ordering::Relaxed),
            blocked:      self.blocked.load(Ordering::Relaxed),
            forwarded:    self.forwarded.load(Ordering::Relaxed),
            nxdomain:     self.nxdomain.load(Ordering::Relaxed),
            refused:      self.refused.load(Ordering::Relaxed),
            servfail:     self.servfail.load(Ordering::Relaxed),
            uptime_secs:  self.started_at.elapsed().as_secs(),
        }
    }
}

pub struct StatsSnapshot {
    pub total:       u64,
    pub blocked:     u64,
    pub forwarded:   u64,
    pub nxdomain:    u64,
    pub refused:     u64,
    pub servfail:    u64,
    pub uptime_secs: u64,
}
