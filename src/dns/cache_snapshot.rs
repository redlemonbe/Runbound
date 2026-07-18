// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// XDP DNS cache snapshot — issue #60 (upgraded for wire-format keys in #64).
//
// Double-buffer design:
//   Writer (DNS server, tokio task): DashMap — concurrent lock-free inserts
//   Reader (XDP workers, OS threads): ArcSwap<HashMap> — zero-lock snapshot reads
//
// A background publish_loop clones the mutable map every 10 ms, evicts expired
// entries, and atomically replaces the shared snapshot.  XDP workers call
// load_full() once per received batch and look up from the frozen copy.
//
// #64 upgrade: QuestionKey now uses wire-format DNS name bytes (SmallVec) +
// qclass field; CacheEntry uses bytes::Bytes for zero-copy payload access.
//
// #29: rkyv zero-copy persistence. save_xdp_cache / load_xdp_cache write and
// read the mutable DashMap to/from disk using rkyv's binary format, prefixed
// with a 4-byte magic header b"RBv1" for format detection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use arc_swap::ArcSwap;
use bytes::Bytes;
use smallvec::SmallVec;
use crate::dns::hasher::IdentityHasherBuilder;

/// Key for cache lookup: wire-format lowercase DNS name + query type + class.
///
/// Wire format: length-prefixed labels, e.g. `\x07example\x03com\x00`.
/// Lowercase is guaranteed by the caller (LowerName or equivalent).
/// 64 bytes is enough for names up to ~60 chars without heap allocation.
#[derive(Hash, Eq, Clone)]
#[allow(dead_code, clippy::derived_hash_with_manual_eq)]
pub struct QuestionKey {
    /// Wire-format DNS name, lowercased (matches QNAME bytes from the client).
    pub name: SmallVec<[u8; 64]>,
    /// Wire-format numeric query type (1 = A, 28 = AAAA, …).
    pub qtype: u16,
    /// Wire-format query class (1 = IN).
    pub qclass: u16,
}

impl PartialEq for QuestionKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.qtype == other.qtype
            && self.qclass == other.qclass
            && crate::dns::simd::bytes_eq(&self.name, &other.name)
    }
}


pub struct CacheEntry {
    /// Full DNS response datagram in wire format with QID zeroed (bytes [0..2]).
    /// The XDP worker patches bytes [0..2] with the actual QID before sending.
    /// Using `Bytes` enables O(1) clones during the snapshot publish — Arc<[u8]> internally.
    pub wire_payload: Bytes,
    pub expires_at: Instant,
    /// Wire-format lowercase QNAME bytes — used for anti-collision after CRC32c lookup.
    /// Empty for entries inserted via the legacy QuestionKey path (kernel_loop compat).
    pub wire_qname: Bytes,
}

impl Clone for CacheEntry {
    fn clone(&self) -> Self {
        Self {
            wire_payload: self.wire_payload.clone(), // O(1) — just increments the Arc refcount
            expires_at: self.expires_at,
            wire_qname: self.wire_qname.clone(),     // O(1) — Arc<[u8]>
        }
    }
}

// #perf: CRC32c (SSE4.2) key pre-hashed to u64 + IdentityHasher (0 re-hash cycles).
// Same routine as answer_dns_wire — a single ASM lookup path for local-zone AND cache.
// wire_qname in CacheEntry guards against the (astronomically rare) CRC32c collision.
pub type CacheSnapshot = HashMap<u64, CacheEntry, IdentityHasherBuilder>;
pub type SharedCacheSnapshot = Arc<ArcSwap<CacheSnapshot>>;

/// Per-view (split-horizon) snapshots (#187). Each entry maps a set of source
/// CIDR blocks to a `CacheSnapshot` built from that view's local-data. The XDP
/// worker matches the client IP to the first view whose CIDRs contain it and
/// serves from that view's snapshot BEFORE the global one, so split-horizon is
/// correct on the fast path with no cross-view leak. Empty = no split-horizon
/// configured = zero per-packet cost.
pub type ViewSnapshots = Vec<(Vec<crate::dns::acl::CidrBlock>, CacheSnapshot)>;
pub type SharedViewSnapshots = Arc<ArcSwap<ViewSnapshots>>;

/// Process-wide live handle to the per-view snapshots, (re)published by the
/// server whenever the split-horizon table is compiled. `None` until first set.
pub static SPLIT_HORIZON_SNAPSHOTS: std::sync::OnceLock<SharedViewSnapshots> =
    std::sync::OnceLock::new();

/// Build a `CacheSnapshot` from one split-horizon view's local zone set (#187).
/// Reuses the exact wire-serialisation of the global preload via
/// `local_zone_entries`, so a view answers byte-identically to a global zone.
pub fn build_view_snapshot(zones: &crate::dns::local::LocalZoneSet) -> CacheSnapshot {
    let mut snap = CacheSnapshot::default();
    for (key, entry) in crate::dns::local::local_zone_entries(zones) {
        snap.insert(key, entry);
    }
    snap
}
pub type MutableCacheMap = Arc<DashMap<u64, CacheEntry, IdentityHasherBuilder>>;

/// Global counter of DNS responses served from the XDP cache snapshot.
/// Read by the Prometheus metrics handler and GET /api/system.
pub static XDP_CACHE_SNAPSHOT_HITS: AtomicU64 = AtomicU64::new(0);
pub static XDP_CACHE_SNAPSHOT_MISSES: AtomicU64 = AtomicU64::new(0);
/// Live entry count, updated by publish_loop after each snapshot swap.
pub static XDP_CACHE_SNAPSHOT_ENTRIES: AtomicU64 = AtomicU64::new(0);
/// Monotonic write-generation counter — incremented by cache_insert on every new entry.
/// publish_loop compares against its last-seen value to skip the O(n) DashMap clone
/// when no new entries have been inserted since the previous snapshot (PERF-1 / #135).
pub static CACHE_WRITE_GEN: AtomicU64 = AtomicU64::new(0);

/// #186: process-wide handle to the shared mutable XDP cache, published once at
/// startup. API write handlers use it to evict stale forwarded entries on
/// local-zone writes so edits take effect live on the fast path. Unset when the
/// XDP cache is disabled. Read-only after the single startup `set`.
pub static XDP_CACHE_FOR_API: std::sync::OnceLock<MutableCacheMap> = std::sync::OnceLock::new();

// ── Per-worker packet distribution (#67) ─────────────────────────────────────
// 64 slots (one per NIC queue / worker thread). Incremented by xdp_worker
// threads and read by GET /api/system. Kept in this always-compiled module so
// the API handler can reference it without the "xdp" feature gate.
#[allow(clippy::declare_interior_mutable_const)]
pub static XDP_WORKER_PKTS: [AtomicU64; 64] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 64]
};

// Per-worker XDP cache MISS counter (packet not served by the fast path -> fallback).
// Paired with XDP_WORKER_PKTS (served = hits) to compute the XDP cache-hit rate in
// Rust, off the hot path. The hit path is unchanged (it already bumps XDP_WORKER_PKTS);
// this only adds one increment on the already-slow miss/fallback branch.
#[allow(clippy::declare_interior_mutable_const)]
pub static XDP_WORKER_MISS: [AtomicU64; 64] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 64]
};

/// Insert a cache entry, respecting the max-entries cap.
///
/// If the map is full and the incoming key is new, we evict the first expired
/// entry found.  If no expired entry exists we skip the insert (backpressure)
/// rather than evicting live entries — better to let the entry be served by
/// hickory than to purge a still-valid cached response.

/// Sentinel `expires_at` for local-data entries that must NEVER expire or be
/// evicted.  Local-data is static (loaded at startup); only a full zone reload
/// replaces it.  Value = 100 years from process start (Instant cannot be const).
#[allow(dead_code)]
pub fn sentinel_expires() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(100 * 365 * 24 * 3600)
}

/// Returns true if this entry was inserted as local-data (never expires).
/// Used by cache_insert to skip eviction of sentinel entries.
#[inline]
pub fn is_sentinel(entry: &CacheEntry) -> bool {
    // Entries inserted more than 50 years in the future are sentinels.
    entry.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(50 * 365 * 24 * 3600)
}

pub fn cache_insert(
    mutable: &MutableCacheMap,
    key: u64,
    entry: CacheEntry,
    max_entries: usize,
) {
    if mutable.len() >= max_entries && !mutable.contains_key(&key) {
        let now = Instant::now();
        let to_remove = mutable
            .iter()
            .find(|kv| kv.value().expires_at <= now && !is_sentinel(kv.value()))
            .map(|kv| kv.key().clone());
        match to_remove {
            Some(k) => {
                mutable.remove(&k);
            }
            None => return, // all entries still live — skip this insert
        }
    }
    mutable.insert(key, entry);
    CACHE_WRITE_GEN.fetch_add(1, Ordering::Relaxed);
}


/// Insert a local-data (preloaded) entry into the cache.
/// Uses a sentinel `expires_at` so the entry is never evicted by TTL logic.
/// Sentinel entries survive every snapshot rebuild because `is_sentinel()` guards eviction.
pub fn cache_insert_local(
    mutable: &MutableCacheMap,
    key: u64,
    entry: CacheEntry,
) {
    // Local-data entries always win — overwrite if key already exists.
    mutable.insert(key, entry);
    CACHE_WRITE_GEN.fetch_add(1, Ordering::Relaxed);
}

/// Evict live, non-sentinel entries oldest-first until at most `target_len`
/// remain. "Oldest" = soonest-to-expire (`expires_at`) — `CacheEntry` carries
/// no separate insertion timestamp, and reusing the TTL field costs nothing
/// extra per entry while still favouring the least-useful-going-forward
/// entries for removal, which is what a resolver cache actually wants evicted
/// under pressure (a fresh 300s-TTL answer survives over one with 2s left).
///
/// Used exclusively by the background memory-pressure watchdog
/// (`memory_guard_loop`) — never called from the hot query path, so its cost
/// never touches DNS latency regardless of cache size.
///
/// Cost: one O(n) pass to collect non-sentinel `(key, expires_at)` pairs, one
/// O(n) average-case partial selection (`select_nth_unstable_by_key` — no
/// full O(n log n) sort) to find the eviction cutoff, then O(k) removals.
///
/// Returns the number of entries actually removed. Bumps `CACHE_WRITE_GEN` on
/// any removal so the next `publish_loop` tick (≤10 ms) republishes the
/// shrunk snapshot to the XDP read side.
pub fn evict_oldest(mutable: &MutableCacheMap, target_len: usize) -> usize {
    let current = mutable.len();
    if current <= target_len {
        return 0;
    }
    let want_removed = current - target_len;

    let mut candidates: Vec<(u64, Instant)> = mutable
        .iter()
        .filter(|kv| !is_sentinel(kv.value()))
        .map(|kv| (*kv.key(), kv.value().expires_at))
        .collect();

    if candidates.is_empty() {
        return 0;
    }

    let n = want_removed.min(candidates.len());
    if n < candidates.len() {
        // Partition so the n soonest-to-expire entries land in [..n] —
        // avoids paying for a full sort of entries we're going to keep.
        candidates.select_nth_unstable_by_key(n - 1, |&(_, expires_at)| expires_at);
    }

    let mut evicted = 0usize;
    for (key, _) in candidates.into_iter().take(n) {
        if mutable.remove(&key).is_some() {
            evicted += 1;
        }
    }
    if evicted > 0 {
        CACHE_WRITE_GEN.fetch_add(1, Ordering::Relaxed);
    }
    evicted
}

/// Construct a new empty MutableCacheMap with the correct IdentityHasherBuilder.
pub fn new_mutable_cache() -> MutableCacheMap {
    Arc::new(DashMap::with_hasher(IdentityHasherBuilder))
}

// ── #29: rkyv-based cache persistence ────────────────────────────────────────
//
// Separate "persist" types are used because:
//   - Instant is not serializable → replaced by u64 UNIX timestamp
//   - bytes::Bytes is not rkyv-serializable → Vec<u8>
//   - SmallVec inline storage size must match exactly for rkyv → Vec<u8>
//
// Magic header guards against loading old/corrupt files: if the first 4 bytes
// are not b"RBv1" the file is silently ignored and the server starts cold.

const CACHE_MAGIC: &[u8; 4] = b"RBv1";

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
pub struct PersistKey {
    pub name: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
pub struct PersistEntry {
    pub wire_payload: Vec<u8>,
    /// Absolute UNIX timestamp (seconds) when this entry expires.
    pub expires_secs: u64,
}

/// Serialize the live DashMap to disk at `path`.
/// The file is written atomically via a temp file + rename.
/// Returns the number of entries written, or an error string.
pub fn save_xdp_cache(cache: &MutableCacheMap, path: &std::path::Path) -> Result<usize, String> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let instant_now = Instant::now();

    let snapshot: Vec<(PersistKey, PersistEntry)> = cache
        .iter()
        .filter(|kv| kv.value().expires_at > instant_now)
        .map(|kv| {
            let remaining = kv
                .value()
                .expires_at
                .saturating_duration_since(instant_now)
                .as_secs();
            (
                PersistKey {
                    // u64 key stored as little-endian bytes; name/qtype/qclass fields
                    // kept for format compatibility — key bytes contain the CRC32c hash.
                    name: kv.key().to_le_bytes().to_vec(),
                    qtype: 0u16,
                    qclass: 0u16,
                },
                PersistEntry {
                    wire_payload: kv.value().wire_payload.to_vec(),
                    // Store wire_qname for anti-collision restore.
                    expires_secs: now_unix + remaining,
                },
            )
        })
        .collect();

    let count = snapshot.len();

    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&snapshot)
        .map_err(|e| format!("rkyv serialize: {e}"))?;

    // Write magic + rkyv bytes to a temp file, then atomically rename.
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f =
            std::fs::File::create(&tmp).map_err(|e| format!("create tmp cache file: {e}"))?;
        f.write_all(CACHE_MAGIC)
            .map_err(|e| format!("write magic: {e}"))?;
        f.write_all(&bytes)
            .map_err(|e| format!("write rkyv bytes: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("rename cache file: {e}"))?;

    Ok(count)
}

/// Load the on-disk cache into `cache`.
/// Silently returns 0 if the file is absent or has an invalid magic header.
/// Logs a warning on corruption.
pub fn load_xdp_cache(
    cache: &MutableCacheMap,
    path: &std::path::Path,
    max_entries: usize,
) -> usize {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return 0,
    };

    if data.len() < 4 || &data[..4] != CACHE_MAGIC {
        tracing::warn!(
            path = %path.display(),
            "XDP cache: missing or invalid magic header — ignored (stale format?)"
        );
        return 0;
    }

    let snapshot: Vec<(PersistKey, PersistEntry)> = match rkyv::from_bytes::<
        Vec<(PersistKey, PersistEntry)>,
        rkyv::rancor::Error,
    >(&data[4..])
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(err = %e, path = %path.display(), "XDP cache: rkyv validation failed — ignored");
            return 0;
        }
    };

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let instant_now = Instant::now();
    let mut loaded = 0usize;

    for (pk, pe) in snapshot {
        if pe.expires_secs <= now_unix {
            continue;
        } // already expired
        let remaining = Duration::from_secs(pe.expires_secs - now_unix);
        // Restore u64 key from little-endian bytes stored in pk.name.
        let key: u64 = if pk.name.len() >= 8 {
            u64::from_le_bytes([pk.name[0],pk.name[1],pk.name[2],pk.name[3],
                                 pk.name[4],pk.name[5],pk.name[6],pk.name[7]])
        } else {
            continue; // corrupt entry — skip
        };
        // A corrupt/crafted persisted entry can carry an absurd expiry; a checked add
        // avoids an Instant-overflow panic at startup — skip such an entry instead.
        let Some(expires_at) = instant_now.checked_add(remaining) else {
            continue; // corrupt entry — skip
        };
        let entry = CacheEntry {
            wire_payload: Bytes::from(pe.wire_payload),
            expires_at,
            wire_qname: Bytes::new(), // anti-collision disabled for persisted entries
        };
        cache_insert(cache, key, entry, max_entries);
        loaded += 1;
    }
    loaded
}

/// Background task: publish the XDP read-only snapshot from the mutable DashMap.
///
/// PERF-1 (#135): skip the O(n) DashMap clone when no new entries were inserted
/// since the previous tick — `CACHE_WRITE_GEN` is bumped by `cache_insert`.
/// A forced eviction pass runs every 256 ticks (~2.5 s) to drop TTL-expired
/// entries even in steady-state (warm cache, no new inserts).
pub async fn publish_loop(snapshot: SharedCacheSnapshot, mutable: MutableCacheMap) {
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_gen: u64 = 0;
    let mut evict_tick: u8 = 0;
    loop {
        interval.tick().await;
        let cur_gen = CACHE_WRITE_GEN.load(Ordering::Relaxed);
        evict_tick = evict_tick.wrapping_add(1);
        let force_evict = evict_tick == 0; // every 256 × 10ms ≈ 2.56 s
        if cur_gen == last_gen && !force_evict {
            continue; // nothing changed — skip the clone entirely
        }
        last_gen = cur_gen;
        let now = Instant::now();
        // PERF (#165): on the periodic forced-eviction pass, drop expired entries from the
        // MUTABLE map too — not just filter them out of the snapshot. This keeps the mutable
        // below capacity so cache_insert almost never has to O(n)-scan for a victim under a
        // cache-miss flood. Background task, never the hot path; sentinels are preserved.
        if force_evict {
            mutable.retain(|_, v| v.expires_at > now || is_sentinel(v));
        }
        let new_snap: CacheSnapshot = mutable
            .iter()
            .filter(|kv| kv.value().expires_at > now)
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect();
        XDP_CACHE_SNAPSHOT_ENTRIES.store(new_snap.len() as u64, Ordering::Relaxed);
        snapshot.store(Arc::new(new_snap));
    }
}

#[cfg(test)]
mod evict_oldest_tests {
    use super::*;

    fn entry(ttl_secs: u64) -> CacheEntry {
        CacheEntry {
            wire_payload: Bytes::new(),
            expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            wire_qname: Bytes::new(),
        }
    }

    #[test]
    fn no_op_when_already_under_target() {
        let m = new_mutable_cache();
        m.insert(1, entry(60));
        m.insert(2, entry(120));
        assert_eq!(evict_oldest(&m, 10), 0);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn evicts_soonest_to_expire_first() {
        let m = new_mutable_cache();
        // Key N has an N*10s TTL — key 1 is the "oldest" (least remaining life).
        for i in 1u64..=10 {
            m.insert(i, entry(i * 10));
        }
        let evicted = evict_oldest(&m, 4);
        assert_eq!(evicted, 6);
        assert_eq!(m.len(), 4);
        // Survivors must be the 4 entries with the longest remaining TTL: keys 7..=10.
        let mut remaining: Vec<u64> = m.iter().map(|kv| *kv.key()).collect();
        remaining.sort_unstable();
        assert_eq!(remaining, vec![7, 8, 9, 10]);
    }

    #[test]
    fn never_evicts_sentinel_entries() {
        let m = new_mutable_cache();
        m.insert(1, entry(5)); // short TTL — would normally go first
        let sentinel = CacheEntry {
            wire_payload: Bytes::new(),
            expires_at: sentinel_expires(),
            wire_qname: Bytes::new(),
        };
        m.insert(2, sentinel);
        // Ask to shrink to 0 — only the non-sentinel entry may be removed.
        let evicted = evict_oldest(&m, 0);
        assert_eq!(evicted, 1);
        assert_eq!(m.len(), 1);
        assert!(m.contains_key(&2));
    }

    #[test]
    fn returns_zero_on_all_sentinel_cache() {
        let m = new_mutable_cache();
        m.insert(1, CacheEntry {
            wire_payload: Bytes::new(),
            expires_at: sentinel_expires(),
            wire_qname: Bytes::new(),
        });
        assert_eq!(evict_oldest(&m, 0), 0);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn bumps_write_gen_only_on_actual_eviction() {
        let m = new_mutable_cache();
        m.insert(1, entry(60));
        let before = CACHE_WRITE_GEN.load(Ordering::Relaxed);
        assert_eq!(evict_oldest(&m, 10), 0); // no-op: already under target
        assert_eq!(CACHE_WRITE_GEN.load(Ordering::Relaxed), before);
        assert_eq!(evict_oldest(&m, 0), 1); // real eviction
        assert_eq!(CACHE_WRITE_GEN.load(Ordering::Relaxed), before + 1);
    }
}
