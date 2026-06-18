// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Local zone authority — in-memory, instant updates, O(1) lookup.

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};

use crate::dns::hasher::{hash_wire_qname, DnsHasherBuilder, IdentityHasherBuilder};
use crate::dns::simd;
use smallvec::SmallVec;
use std::str::FromStr;

/// #201: set once at startup from `local-zone-dnssec`. When true, local zones are **not**
/// preloaded into the fast-path snapshot — they are served (and DNSSEC-signed) on the slow path,
/// which is the only place we can vary the answer by the client's DO bit (RFC 4035 §3.2.1).
pub static LOCAL_ZONE_DNSSEC: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

use hickory_proto::rr::{
    rdata::{self, CNAME},
    LowerName, Name, RData, Record, RecordType,
};

use crate::config::parser::{LocalData, LocalZone};

#[derive(Debug, Clone, PartialEq)]
pub enum ZoneAction {
    Refuse,
    NxDomain,
    Static,
    // Mirrors Unbound's "redirect" zone type — reserved for future CNAME-based redirect support
    #[allow(dead_code)]
    Redirect,
    /// Return block page IP instead of NXDOMAIN.
    BlockPage,
}

impl From<&str> for ZoneAction {
    fn from(s: &str) -> Self {
        match s {
            "refuse" | "inform_deny" => ZoneAction::Refuse,
            "always_nxdomain" | "nxdomain" => ZoneAction::NxDomain,
            "static" | "redirect" => ZoneAction::Static,
            "block_page" | "block-page" => ZoneAction::BlockPage,
            _ => ZoneAction::Refuse,
        }
    }
}

/// In-memory local zone set.
/// zones:   HashMap for O(1) exact lookup + parent-walking for subdomain coverage.
/// records: HashMap<Name, Vec<Record>> for O(1) name lookup.
///          Clone happens only on API writes (rare), never on DNS reads (ArcSwap).
#[derive(Debug, Default, Clone)]
pub struct LocalZoneSet {
    pub zones: HashMap<Name, ZoneAction, DnsHasherBuilder>,
    pub records: HashMap<Name, Vec<Record>, DnsHasherBuilder>,
    /// SEC-AGV-01: names that were statically configured at startup.
    /// DDNS DELETE operations on these names are rejected.
    pub static_names: HashSet<Name>,
    /// Fast-path wire-key A/AAAA index (#156 item 3).
    /// Exact-match only; parent-walk / wildcard / other types fall through
    /// to the hickory slow path via answer_dns().
    pub wire_records: WireRecordIndex,
}


// ── Wire-record index types (#156 item 3) ────────────────────────────────────
// Pre-serialised A/AAAA rdata built once at load time.
// Hot path reads these directly — zero hickory::RData access at query time.

/// A single wire-format resource-record datum, pre-serialised at zone load.
/// `rdata` holds the raw bytes: 4 bytes for A, 16 bytes for AAAA.
/// `SmallVec<[u8;16]>` stays on the stack for both types.
#[derive(Debug, Clone)]
pub struct WireRdata {
    pub ttl:   u32,
    pub rdata: SmallVec<[u8; 16]>,
}

/// All A and AAAA records for one exact DNS name, indexed by wire-qname hash.
/// `wire_qname` is stored for anti-collision check via `simd::bytes_eq`.
#[derive(Debug, Clone)]
pub struct WireRecordEntry {
    pub wire_qname:   SmallVec<[u8; 64]>,
    pub a_records:    SmallVec<[WireRdata; 4]>,
    pub aaaa_records: SmallVec<[WireRdata; 2]>,
}

/// Fast-path exact-match index for A/AAAA records.
/// Key = `hash_wire_qname(name_to_wire_qname(name))` (CRC32c Fibonacci-spread).
/// Uses `IdentityHasherBuilder` — the key is already a high-quality hash,
/// re-hashing it would waste ~3 cycles/lookup.
#[derive(Debug, Clone, Default)]
pub struct WireRecordIndex {
    pub map: HashMap<u64, WireRecordEntry, IdentityHasherBuilder>,
}

impl WireRecordIndex {
    pub fn new() -> Self {
        Self { map: HashMap::with_hasher(IdentityHasherBuilder) }
    }
}

/// Convert a hickory `Name` to a lowercase, uncompressed wire-format QNAME.
///
/// Output format: `[len][label_bytes]...0x00`  (RFC 1035 §3.1)
/// Exactly matches what `simd::copy_lowercase_label` produces from a raw
/// DNS query wire buffer — guaranteed by the round-trip test in hasher.rs.
///
/// # Correctness note
/// Uses `simd::copy_lowercase_label` for the per-label lowercase step,
/// the SAME function used in the hot path on the raw query wire bytes.
/// One function = one normalisation = no silent divergence.
pub(crate) fn name_to_wire_qname(name: &Name) -> SmallVec<[u8; 64]> {
    let mut buf: SmallVec<[u8; 64]> = SmallVec::new();
    for label in name.iter() {
        if label.is_empty() {
            // Root label — emitted as 0x00 below; skip empty labels from iter().
            continue;
        }
        buf.push(label.len() as u8);
        // Use the SAME simd::copy_lowercase_label as the hot path so both sides
        // of the index are byte-identical after normalisation.
        // copy_lowercase_label(dst, src) appends src lowercased into dst.
        // Same function as the hot path — one normalisation path, no divergence.
        simd::copy_lowercase_label(&mut buf, label);
    }
    buf.push(0u8); // root label
    buf
}

impl LocalZoneSet {
    pub fn from_config(zones: &[LocalZone], data: &[LocalData]) -> Self {
        let mut map = HashMap::with_capacity_and_hasher(zones.len(), DnsHasherBuilder::new());
        for z in zones {
            let name_str = if z.name.ends_with('.') {
                z.name.clone()
            } else {
                format!("{}.", z.name)
            };
            if let Ok(n) = Name::from_str(&name_str) {
                map.insert(n, ZoneAction::from(z.zone_type.as_str()));
            }
        }
        // Build record map: O(1) name lookup replaces O(n) Vec scan on every query.
        // Also sets implicit static zone for each local-data name (Unbound behaviour).
        let mut record_map: HashMap<Name, Vec<Record>, DnsHasherBuilder> = HashMap::with_hasher(DnsHasherBuilder::new());
        for d in data {
            if let Some(rec) = parse_local_data(&d.rr) {
                let name = rec.name.clone();
                map.entry(name.clone()).or_insert(ZoneAction::Static);
                record_map.entry(name).or_default().push(rec);
            }
        }

        // ── Build wire-record index (#156 item 3) ──────────────────────────────
        // Pre-serialise A/AAAA rdata into WireRdata (stack SmallVec) keyed by
        // hash_wire_qname(name_to_wire_qname(name)).  Built once at load; the hot
        // path answer_dns_wire() uses this index to avoid Name::read per packet.
        let mut wire_idx = WireRecordIndex::new();
        for (name, recs) in &record_map {
            let wq = name_to_wire_qname(name);
            let key = hash_wire_qname(&wq);
            let entry = wire_idx.map.entry(key).or_insert_with(|| WireRecordEntry {
                wire_qname:   wq.clone(),
                a_records:    SmallVec::new(),
                aaaa_records: SmallVec::new(),
            });
            // Anti-collision: if two names hash to the same key, we keep the
            // first one in the index and skip the rest.  The collision rate for
            // CRC32c Fibonacci-spread over ≤10k zone names is negligible, but
            // correctness is preserved — colliding names fall back to hickory.
            if entry.wire_qname != wq {
                tracing::warn!(
                    name = %name,
                    "WireRecordIndex: CRC32c hash collision — name falls back to hickory slow path"
                );
                continue;
            }
            for rec in recs {
                let ttl = rec.ttl;
                match rec.data {
                    RData::A(ref a) => {
                        entry.a_records.push(WireRdata {
                            ttl,
                            rdata: SmallVec::from_slice(&a.octets()),
                        });
                    }
                    RData::AAAA(ref aaaa) => {
                        entry.aaaa_records.push(WireRdata {
                            ttl,
                            rdata: SmallVec::from_slice(&aaaa.octets()),
                        });
                    }
                    _ => {} // CNAME/MX/TXT etc. → slow path only
                }
            }
        }

        // SEC-AGV-01: track all statically configured names so DDNS cannot delete them.
        let static_names: HashSet<Name> = zones.iter()
            .filter_map(|z| {
                let n = if z.name.ends_with('.') { z.name.clone() } else { format!("{}.", z.name) };
                Name::from_str(&n).ok()
            })
            .chain(data.iter().filter_map(|d| parse_local_data(&d.rr).map(|r| r.name)))
            .collect();

        Self {
            zones: map,
            records: record_map,
            static_names,
            wire_records: wire_idx,
        }
    }

    /// Override any existing zone action for `name`.
    /// Unlike `add_zone` (which uses `or_insert` and ignores an existing entry),
    /// this always replaces — ensuring blacklist entries shadow static zones.
    #[inline]
    pub fn override_zone(&mut self, name: &str, action: ZoneAction) {
        let name_str = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{}.", name)
        };
        if let Ok(n) = Name::from_str(&name_str) {
            self.zones.insert(n, action);
        }
    }

    #[inline]
    pub fn remove_zone(&mut self, name: &str) {
        let name_str = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{}.", name)
        };
        if let Ok(n) = Name::from_str(&name_str) {
            self.zones.remove(&n);
        }
    }

    /// Find matching zone for a query name.
    /// Walks up the name hierarchy: "www.evil.com." → "evil.com." → "com." → "."
    /// Returns the most-specific match (exact domain wins over parent zone).
    ///
    /// Accepts `&LowerName` directly — avoids the `Name::from(lower.clone())`
    /// allocation that callers previously had to perform before each lookup.
    /// `LowerName: Deref<Target=Name>`, so `&**query` gives a `&Name` for the
    /// HashMap without any heap allocation on the exact-match fast path.
    #[inline]
    pub fn find(&self, query: &LowerName) -> Option<ZoneAction> {
        // Fast path: exact match — LowerName: Borrow<Name>, zero allocation.
        if let Some(action) = self.zones.get(query.borrow() as &Name) {
            return Some(action.clone());
        }
        if query.is_root() {
            return None;
        }
        // Slow path: walk up the label hierarchy via LowerName::base_name().
        // One LowerName allocation per label trimmed — same cost as before.
        let mut name = query.base_name();
        loop {
            if let Some(action) = self.zones.get(name.borrow() as &Name) {
                return Some(action.clone());
            }
            if name.is_root() {
                break;
            }
            name = name.base_name();
        }
        None
    }

    /// Exact local-data records for a query. O(1) name lookup + O(m) type filter
    /// where m is the number of records for that name (typically 1–5).
    #[inline(always)]
    pub fn local_records(&self, query_name: &LowerName, rtype: RecordType) -> Vec<&Record> {
        self.records
            .get(query_name.borrow() as &Name)
            .map(|recs| recs.iter().filter(|r| r.record_type() == rtype).collect())
            .unwrap_or_default()
    }

    /// True if the name has at least one record of any type. O(1) HashMap lookup.
    /// Used to distinguish NODATA (name exists, wrong type → NOERROR empty)
    /// from NXDOMAIN (name itself does not exist) — RFC 1035 §3.7.
    #[inline(always)]
    pub fn name_has_records(&self, name: &LowerName) -> bool {
        self.records.contains_key(name.borrow() as &Name)
    }
}


/// Preload all explicit A/AAAA local-data entries from `zones.wire_records`
/// into `cache`.  Each entry is stored with a sentinel `expires_at` so it
/// survives every snapshot rebuild and is never evicted by TTL logic.
///
/// Called once at XDP startup (after zones are loaded).  Local-data entries
/// are static; a zone reload replaces the whole LocalZoneSet and re-calls
/// this function.
///
/// Only exact A/AAAA records are preloaded.  Wildcards, CNAME, MX, TXT,
/// BlockPage and other special zones are NOT preloaded — they remain handled
/// by `answer_dns()` (hickory slow path).
/// Build (cache_key, CacheEntry) pairs for every A/AAAA name in a zone set.
/// Shared by `preload_into_cache` (global XDP snapshot seed) and the per-view
/// split-horizon snapshots (#187) so both paths serialise records identically.
pub(crate) fn local_zone_entries(
    zones: &LocalZoneSet,
) -> Vec<(u64, crate::dns::cache_snapshot::CacheEntry)> {
    use crate::dns::cache_snapshot::{sentinel_expires, CacheEntry};
    use crate::dns::wire_builder::{build_answer_a_aaaa_wire, WireQuery};
    use bytes::Bytes;

    let sentinel = sentinel_expires();
    let mut out: Vec<(u64, CacheEntry)> = Vec::new();

    for (key_raw, entry) in &zones.wire_records.map {
        for qtype in [1u16, 28u16] {
            let recs: Vec<crate::dns::local::WireRdata> = if qtype == 1 {
                entry.a_records.iter().cloned().collect()
            } else {
                entry.aaaa_records.iter().cloned().collect()
            };
            if recs.is_empty() {
                continue;
            }
            let fake_qname = &entry.wire_qname;
            let wq = WireQuery {
                id: 0,
                qname_wire: fake_qname.as_slice(),
                qtype,
                qclass: 1,
                edns: None,
            };
            let mut buf = [0u8; 512];
            let len = match build_answer_a_aaaa_wire(&wq, &mut buf, recs.as_slice(), None) {
                Some(n) => n,
                None => continue,
            };
            let cache_key: u64 = *key_raw ^ ((qtype as u64) << 48);
            out.push((
                cache_key,
                CacheEntry {
                    wire_payload: Bytes::copy_from_slice(&buf[..len]),
                    expires_at: sentinel,
                    wire_qname: Bytes::copy_from_slice(fake_qname.as_slice()),
                },
            ));
        }
    }
    out
}

pub(crate) fn preload_into_cache(
    zones: &LocalZoneSet,
    cache: &crate::dns::cache_snapshot::MutableCacheMap,
) {
    // #201: when local zones are DNSSEC-signed, they must be served on the slow path (so the
    // RRSIG can be added and the DO bit honoured), not from the unsigned fast-path snapshot.
    if LOCAL_ZONE_DNSSEC.load(std::sync::atomic::Ordering::Relaxed) {
        tracing::info!(
            "local-zone-dnssec: local zones served signed on the slow path (skipping fast-path preload)"
        );
        return;
    }
    use crate::dns::cache_snapshot::cache_insert_local;
    let entries = local_zone_entries(zones);
    let preloaded = entries.len();
    for (key, entry) in entries {
        cache_insert_local(cache, key, entry);
    }
    tracing::info!(preloaded, "XDP cache: preloaded local-data A/AAAA entries");
}

/// Parse a `local-data` RR string into a hickory Record.
/// Supports: A, AAAA, CNAME, TXT, PTR, NS, MX, SRV, CAA, NAPTR, SSHFP, TLSA
/// Format:  name [ttl] TYPE rdata...
pub fn parse_local_data(rr: &str) -> Option<Record> {
    let parts: Vec<&str> = rr.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // Parse: name [ttl] [class] TYPE rdata
    // Both TTL and class (IN/CH/HS) are optional and can appear in any order.
    let mut idx = 1usize;
    let mut ttl = 300u32;
    // Consume optional TTL (numeric)
    if parts[idx].parse::<u32>().is_ok() {
        ttl = parts[idx].parse().ok()?;
        idx += 1;
    }
    // Consume optional DNS class (IN / CH / HS / ANY)
    if idx < parts.len() {
        let up = parts[idx].to_uppercase();
        if up == "IN" || up == "CH" || up == "HS" || up == "ANY" {
            idx += 1;
        }
    }
    if idx >= parts.len() {
        return None;
    }
    let name_str = parts[0];
    let type_str = parts[idx];
    let rest = &parts[idx + 1..];

    if rest.is_empty() {
        return None;
    }

    // Always produce an FQDN Name (with trailing dot) so it round-trips with
    // the names that hickory_proto parses from the wire (which are always FQDN).
    // Names without a trailing dot hash differently → HashMap lookup miss.
    let name_fqdn = if name_str.ends_with('.') {
        name_str.to_string()
    } else {
        format!("{}.", name_str)
    };
    let name = Name::from_str(&name_fqdn).ok()?;
    let joined = rest.join(" ");

    let rdata: RData = match type_str.to_uppercase().as_str() {
        "A" => RData::A(rest[0].parse().ok()?),
        "AAAA" => RData::AAAA(rest[0].parse().ok()?),
        "CNAME" => RData::CNAME(CNAME(Name::from_str(rest[0]).ok()?)),
        "PTR" => RData::PTR(rdata::PTR(Name::from_str(rest[0]).ok()?)),
        "NS" => RData::NS(rdata::NS(Name::from_str(rest[0]).ok()?)),
        "TXT" => {
            let txt = joined.trim_matches('"').to_string();
            RData::TXT(rdata::TXT::new(vec![txt]))
        }
        // MX: priority exchange
        "MX" => {
            let pref: u16 = rest[0].parse().ok()?;
            let exch = Name::from_str(rest[1]).ok()?;
            RData::MX(rdata::MX::new(pref, exch))
        }
        // SRV: priority weight port target
        "SRV" => {
            let priority: u16 = rest[0].parse().ok()?;
            let weight: u16 = rest[1].parse().ok()?;
            let port: u16 = rest[2].parse().ok()?;
            let target = Name::from_str(rest[3]).ok()?;
            RData::SRV(rdata::SRV::new(priority, weight, port, target))
        }
        // CAA: flags tag value
        "CAA" => {
            let flags: u8 = rest[0].parse().ok()?;
            let tag_str = rest[1];
            let val = rest[2..].join(" ").trim_matches('"').to_string();
            let issuer_crit = flags & 0x80 != 0;
            match tag_str {
                "issue" => RData::CAA(rdata::CAA::new_issue(
                    issuer_crit,
                    Name::from_str(&val).ok(),
                    vec![],
                )),
                "issuewild" => RData::CAA(rdata::CAA::new_issuewild(
                    issuer_crit,
                    Name::from_str(&val).ok(),
                    vec![],
                )),
                _ => return None,
            }
        }
        // SSHFP: algorithm fp_type hex_fingerprint
        "SSHFP" => {
            use hickory_proto::rr::rdata::sshfp::{Algorithm, FingerprintType, SSHFP};
            let algo: u8 = rest[0].parse().ok()?;
            let fpt: u8 = rest[1].parse().ok()?;
            let fp_hex = rest[2];
            let fp_bytes = hex::decode(fp_hex).ok()?;
            let algorithm = Algorithm::from(algo);
            let fp_type = FingerprintType::from(fpt);
            RData::SSHFP(SSHFP::new(algorithm, fp_type, fp_bytes))
        }
        // TLSA: cert_usage selector matching_type cert_data_hex
        "TLSA" => {
            use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector, TLSA};
            let cu: u8 = rest[0].parse().ok()?;
            let sel: u8 = rest[1].parse().ok()?;
            let mt: u8 = rest[2].parse().ok()?;
            let data = hex::decode(rest[3]).ok()?;
            RData::TLSA(TLSA::new(
                CertUsage::from(cu),
                Selector::from(sel),
                Matching::from(mt),
                data,
            ))
        }
        // NAPTR: order preference "flags" "services" "regexp" replacement
        // RFC 2915 — used for ENUM, SIP, URI resolution
        "NAPTR" => {
            use hickory_proto::rr::rdata::NAPTR;
            let order: u16 = rest[0].parse().ok()?;
            let preference: u16 = rest[1].parse().ok()?;
            let flags_raw = rest[2].trim_matches('"');
            let services_raw = rest[3].trim_matches('"');
            let regexp_raw = rest[4].trim_matches('"');
            let replacement = Name::from_str(rest[5]).ok()?;
            RData::NAPTR(NAPTR::new(
                order,
                preference,
                flags_raw.as_bytes().to_vec().into_boxed_slice(),
                services_raw.as_bytes().to_vec().into_boxed_slice(),
                regexp_raw.as_bytes().to_vec().into_boxed_slice(),
                replacement,
            ))
        }
        _ => return None,
    };

    Some(Record::from_rdata(name, ttl, rdata))
}
