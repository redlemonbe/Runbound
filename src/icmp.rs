// SPDX-License-Identifier: AGPL-3.0-or-later
// ICMP echo responder — config types, stats, and BPF map accessors (#89).

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

/// In-memory config mirroring the BPF `icmp_cfg_entry` map entry.
#[derive(Clone, Debug)]
pub struct IcmpConfig {
    pub enabled: bool,
    pub rate_pps: u32,
    pub burst: u32,
}

impl Default for IcmpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rate_pps: 10,
            burst: 5,
        }
    }
}

/// Rust-side counters populated by polling the BPF per-CPU array.
/// Held in AppState; the poll task increments these from the BPF map.
#[derive(Default)]
pub struct IcmpStats {
    pub handled: AtomicU64,
    pub replied: AtomicU64,
    pub dropped: AtomicU64,
    pub rate_limited: AtomicU64,
}

impl IcmpStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}
