// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// #230 — infrastructure cache for the in-house iterative validating recursor.
//
// Before this, a cache miss re-walked from the root on EVERY query: it re-fetched
// the zone-cut NS sets and the whole DNSSEC chain (root/TLD DNSKEY+DS) each time,
// so ~70% of miss traffic hit the root servers (incl. a TCP fetch of the root
// DNSKEY per miss) and each miss cost 325 ms–1.3 s. This adds two TTL-honouring,
// bounded caches consulted during a descent:
//
//   - ZONE-CUT cache: zone -> resolved NS addresses learned from referrals, so a
//     descent starts at the DEEPEST cached enclosing cut instead of the root.
//   - VALIDATED-DNSKEY cache: zone -> DNSSEC-validated DNSKEY rdatas, so the chain
//     walk reuses cuts it already validated (incl. the root DNSKEY, ~once / 48 h).
//
// Safety — this NEVER weakens validation:
//   - DNSKEYs are inserted ONLY after the chain to that zone validated Secure; a
//     cached entry is ignored once its TTL expires (fail-closed re-validation).
//   - The zone-cut cache only selects WHICH servers to ask — every answer is still
//     DNSSEC-validated on the way out, and a stale/dead cached cut falls back to a
//     fresh root descent (see `zone_cut_forget`).
// Entries are keyed case-insensitively, TTL-clamped, bounded, and evicted on
// expiry then LRU.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dns::wire::Name;

/// Cap on cached zone-cut entries (NS address sets).
const MAX_CUTS: usize = 16_384;
/// Cap on cached validated-DNSKEY entries (one per zone in the chains we serve).
const MAX_KEYS: usize = 8_192;
/// Never trust a cached infra entry longer than this, whatever the record TTL
/// says (bound on staleness / absurd TTLs; the root DNSKEY's 48 h TTL sits at it).
const TTL_CAP: u32 = 172_800; // 48 h
/// Never cache for less than this (avoid thrashing on tiny TTLs).
const TTL_FLOOR: u32 = 60;

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn key_of(name: &Name) -> String {
    name.to_ascii().to_ascii_lowercase()
}

fn clamp_ttl(ttl: u32) -> u32 {
    ttl.clamp(TTL_FLOOR, TTL_CAP)
}

/// One cached value with its absolute expiry (unix secs) and an LRU tick.
struct Entry<V> {
    expiry: u32,
    used: u64,
    val: V,
}

/// A bounded, TTL-expiring, LRU-approx map keyed by a lowercased name string.
struct Bounded<V> {
    map: HashMap<String, Entry<V>>,
    cap: usize,
    tick: u64,
}

impl<V: Clone> Bounded<V> {
    fn new(cap: usize) -> Self {
        Self { map: HashMap::new(), cap, tick: 0 }
    }

    /// Fresh value for `key`, or `None` if absent or expired (expired → removed).
    fn get(&mut self, key: &str, now: u32) -> Option<V> {
        self.tick += 1;
        let t = self.tick;
        match self.map.get_mut(key) {
            Some(e) if e.expiry > now => {
                e.used = t;
                Some(e.val.clone())
            }
            Some(_) => {
                self.map.remove(key);
                None
            }
            None => None,
        }
    }

    fn insert(&mut self, key: String, val: V, expiry: u32, now: u32) {
        self.tick += 1;
        let t = self.tick;
        if self.map.len() >= self.cap && !self.map.contains_key(&key) {
            self.evict_one(now);
        }
        self.map.insert(key, Entry { expiry, used: t, val });
    }

    fn remove(&mut self, key: &str) {
        self.map.remove(key);
    }

    /// Evict one entry: an expired one if any, else the least-recently-used.
    fn evict_one(&mut self, now: u32) {
        if let Some(k) = self
            .map
            .iter()
            .find(|(_, e)| e.expiry <= now)
            .map(|(k, _)| k.clone())
        {
            self.map.remove(&k);
            return;
        }
        if let Some(k) = self.map.iter().min_by_key(|(_, e)| e.used).map(|(k, _)| k.clone()) {
            self.map.remove(&k);
        }
    }
}

struct InfraCache {
    cuts: Mutex<Bounded<Vec<IpAddr>>>,
    keys: Mutex<Bounded<Vec<Vec<u8>>>>,
}

static CACHE: LazyLock<InfraCache> = LazyLock::new(|| InfraCache {
    cuts: Mutex::new(Bounded::new(MAX_CUTS)),
    keys: Mutex::new(Bounded::new(MAX_KEYS)),
});

// ── Zone-cut / NS-address cache ───────────────────────────────────────────────

/// Learn a zone cut: `zone` is served by `ns_ips`, valid for `ttl` seconds.
/// The root is never cached (it is the static bootstrap), nor is an empty set.
pub fn zone_cut_learn(zone: &Name, ns_ips: &[IpAddr], ttl: u32) {
    if ns_ips.is_empty() || zone.is_root() {
        return;
    }
    let now = unix_now();
    let expiry = now.saturating_add(clamp_ttl(ttl));
    let mut g = CACHE.cuts.lock().unwrap_or_else(|e| e.into_inner());
    g.insert(key_of(zone), ns_ips.to_vec(), expiry, now);
}

/// Deepest cached, non-expired zone cut enclosing `qname`, with its NS addresses.
/// A descent should start here instead of the root. `None` → start at the root.
pub fn zone_cut_start(qname: &Name) -> Option<(Name, Vec<IpAddr>)> {
    let now = unix_now();
    let mut g = CACHE.cuts.lock().unwrap_or_else(|e| e.into_inner());
    let mut cur = qname.clone();
    while !cur.is_root() {
        if let Some(ips) = g.get(&key_of(&cur), now) {
            return Some((cur, ips));
        }
        cur = cur.parent()?;
    }
    None
}

/// Drop a cached cut whose NS turned out to be stale/dead (→ fall back to root).
pub fn zone_cut_forget(zone: &Name) {
    let mut g = CACHE.cuts.lock().unwrap_or_else(|e| e.into_inner());
    g.remove(&key_of(zone));
}

// ── Validated-DNSKEY cache ────────────────────────────────────────────────────

/// Cache the DNSSEC-validated DNSKEY rdatas for `zone`. Call ONLY after the chain
/// down to `zone` validated Secure. `ttl` is the DNSKEY RRset TTL.
pub fn dnskey_learn(zone: &Name, keys: &[Vec<u8>], ttl: u32) {
    if keys.is_empty() {
        return;
    }
    let now = unix_now();
    let expiry = now.saturating_add(clamp_ttl(ttl));
    let mut g = CACHE.keys.lock().unwrap_or_else(|e| e.into_inner());
    g.insert(key_of(zone), keys.to_vec(), expiry, now);
}

/// Fresh validated DNSKEY set for exactly `zone`, if cached and unexpired.
pub fn dnskey_get(zone: &Name) -> Option<Vec<Vec<u8>>> {
    let now = unix_now();
    let mut g = CACHE.keys.lock().unwrap_or_else(|e| e.into_inner());
    g.get(&key_of(zone), now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_honours_expiry() {
        let mut b: Bounded<u32> = Bounded::new(8);
        b.insert("a".into(), 1, /*expiry*/ 100, /*now*/ 10);
        assert_eq!(b.get("a", 99), Some(1)); // before expiry
        assert_eq!(b.get("a", 100), None); // at expiry → gone (expiry is exclusive)
        assert_eq!(b.get("a", 101), None); // and stays gone (removed on the expired read)
    }

    #[test]
    fn bounded_evicts_expired_first_then_lru() {
        let mut b: Bounded<u32> = Bounded::new(2);
        b.insert("old".into(), 1, 50, 10); // will be expired at now=60
        b.insert("keep".into(), 2, 1000, 10);
        // Inserting a 3rd at capacity with `old` expired → `old` is evicted, not `keep`.
        b.insert("new".into(), 3, 1000, 60);
        assert_eq!(b.get("old", 60), None);
        assert_eq!(b.get("keep", 60), Some(2));
        assert_eq!(b.get("new", 60), Some(3));
    }

    #[test]
    fn bounded_evicts_lru_when_all_fresh() {
        let mut b: Bounded<u32> = Bounded::new(2);
        b.insert("a".into(), 1, 1000, 10);
        b.insert("b".into(), 2, 1000, 10);
        let _ = b.get("a", 11); // touch a → b is now LRU
        b.insert("c".into(), 3, 1000, 11); // at cap, none expired → evict b
        assert_eq!(b.get("b", 12), None);
        assert_eq!(b.get("a", 12), Some(1));
        assert_eq!(b.get("c", 12), Some(3));
    }

    #[test]
    fn clamp_ttl_bounds() {
        assert_eq!(clamp_ttl(1), TTL_FLOOR);
        assert_eq!(clamp_ttl(300), 300);
        assert_eq!(clamp_ttl(10_000_000), TTL_CAP);
    }

    #[test]
    fn zone_cut_start_prefers_deepest_and_expires() {
        // Uses the process-global cache; use unique labels to avoid cross-test bleed.
        let com = Name::from_ascii("uniqtest-com.").unwrap();
        let sub = Name::from_ascii("clubic.uniqtest-com.").unwrap();
        let q = Name::from_ascii("zz1b6427.clubic.uniqtest-com.").unwrap();
        zone_cut_learn(&com, &["9.9.9.9".parse().unwrap()], 3600);
        zone_cut_learn(&sub, &["1.1.1.1".parse().unwrap()], 3600);
        let (z, ips) = zone_cut_start(&q).expect("a cut should be cached");
        assert!(z.eq_ignore_ascii_case(&sub), "must pick the deepest enclosing cut");
        assert_eq!(ips, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        // After forgetting the deep cut, it falls back to the shallower one.
        zone_cut_forget(&sub);
        let (z2, _) = zone_cut_start(&q).expect("shallower cut remains");
        assert!(z2.eq_ignore_ascii_case(&com));
    }

    #[test]
    fn dnskey_roundtrip() {
        let z = Name::from_ascii("uniqtest-keys.").unwrap();
        assert!(dnskey_get(&z).is_none());
        dnskey_learn(&z, &[vec![1, 2, 3]], 3600);
        assert_eq!(dnskey_get(&z), Some(vec![vec![1, 2, 3]]));
    }
}
