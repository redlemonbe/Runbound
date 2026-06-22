// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// #201 — DNSSEC authoritative signing for local zones — hickory-free.
//
// Per-zone KSK + ZSK (ECDSAP256SHA256 / alg 13, RFC 6605), generated on demand and stored as
// PKCS#8 DER under `<config_dir>/dnssec/<zone>/{ksk,zsk}.key` (mode 0600 from creation). Keys and
// all signing run on the in-house `dns::dnssec_sign` crypto (ring); every record this module
// produces is one of our own `wire::Record`s. No hickory types here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::dns::dnssec_sign::{self, SigningKey};
use crate::dns::wire::consts::{class, rtype};
use crate::dns::wire::{Decoder, Name, Rdata, Record};

/// Signature validity backdate (SEC-L5): inception is now − 1h so a validator whose clock runs
/// slightly ahead does not reject a freshly minted signature.
const INCEPTION_BACKDATE_SECS: u64 = 3600;

/// RFC 9276 NSEC3 parameters: SHA-1, 0 iterations, empty salt.
const NSEC3_ITERATIONS: u16 = 0;
const NSEC3_SALT: &[u8] = &[];

// ── wire::Name navigation helpers (kept local; the wire codec stays minimal) ──────────────────

/// Strip the leftmost label, yielding the parent name. `None` at the root.
fn base_name(n: &Name) -> Option<Name> {
    let w = n.wire();
    if w.len() <= 1 {
        return None; // root
    }
    let skip = 1 + w[0] as usize;
    if skip >= w.len() {
        return None;
    }
    let mut d = Decoder::new(&w[skip..]);
    Name::parse(&mut d).ok()
}

/// True if `apex` is equal to, or a suffix of, `name` (i.e. `name` is in the zone).
fn zone_of(apex: &Name, name: &Name) -> bool {
    let a = apex.wire();
    let mut cur: &[u8] = name.wire();
    loop {
        if cur.eq_ignore_ascii_case_bytes(a) {
            return true;
        }
        if cur.len() <= 1 {
            return false;
        }
        let skip = 1 + cur[0] as usize;
        if skip >= cur.len() {
            return false;
        }
        cur = &cur[skip..];
    }
}

/// Prepend a single presentation label to `name` (used for NSEC3 owners and the wildcard).
fn prepend_label(label: &str, name: &Name) -> Option<Name> {
    let base = name.to_ascii();
    let full = if base == "." {
        format!("{label}.")
    } else {
        format!("{label}.{base}")
    };
    Name::from_ascii(&full).ok()
}

/// Case-insensitive byte comparison over two wire names.
trait EqIgnoreCaseBytes {
    fn eq_ignore_ascii_case_bytes(&self, other: &[u8]) -> bool;
}
impl EqIgnoreCaseBytes for [u8] {
    fn eq_ignore_ascii_case_bytes(&self, other: &[u8]) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .zip(other)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Key file management (unchanged on-disk format: PKCS#8 DER, mode 0600) ──────────────────────

/// Directory holding a zone's keys: `<config_dir>/dnssec/<zone>/`.
fn zone_key_dir(config_dir: &Path, zone: &Name) -> PathBuf {
    let label = zone.to_ascii();
    let label = label.trim_end_matches('.');
    let label = if label.is_empty() { "root" } else { label };
    config_dir.join("dnssec").join(label)
}

/// Load the zone's KSK + ZSK, generating and persisting them (mode 0600) on first use.
pub fn load_or_generate(config_dir: &Path, zone: &Name) -> Result<(SigningKey, SigningKey), String> {
    let dir = zone_key_dir(config_dir, zone);
    let ksk = load_or_generate_one(&dir, "ksk.key", true)?;
    let zsk = load_or_generate_one(&dir, "zsk.key", false)?;
    Ok((ksk, zsk))
}

fn load_or_generate_one(dir: &Path, file: &str, is_ksk: bool) -> Result<SigningKey, String> {
    let path = dir.join(file);
    if let Ok(bytes) = std::fs::read(&path) {
        return SigningKey::from_pkcs8(bytes, is_ksk);
    }
    let key = SigningKey::generate(is_ksk)?;
    write_key_0600(&path, key.pkcs8())?;
    Ok(key)
}

/// Remove a zone's key material (called on zone deletion — no orphaned keys, #201 lifecycle).
#[allow(dead_code)]
pub fn remove_zone_keys(config_dir: &Path, zone: &Name) -> Result<(), String> {
    let dir = zone_key_dir(config_dir, zone);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove zone keys {dir:?}: {e}")),
    }
}

/// Write a private-key file atomically with mode 0600 from creation (never world-readable).
fn write_key_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("open {path:?}: {e}"))?;
        f.write_all(bytes).map_err(|e| format!("write {path:?}: {e}"))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes).map_err(|e| format!("write {path:?}: {e}"))?;
    Ok(())
}

/// Read a zone's stored KSK + ZSK (PKCS#8 DER), base64-encoded for relay transport.
pub fn export_keys(config_dir: &Path, apex: &Name) -> Option<(String, String, String)> {
    let dir = zone_key_dir(config_dir, apex);
    let ksk = std::fs::read(dir.join("ksk.key")).ok()?;
    let zsk = std::fs::read(dir.join("zsk.key")).ok()?;
    Some((
        apex.to_ascii(),
        data_encoding::BASE64.encode(&ksk),
        data_encoding::BASE64.encode(&zsk),
    ))
}

/// Write a base64-encoded PKCS#8 key (mode 0600) only when it differs. Used on the slave to adopt
/// the master's replicated keys. SEC-L11: only the two known filenames are ever written.
pub fn import_key(config_dir: &Path, zone: &str, file: &str, b64: &str) -> Result<bool, String> {
    if file != "ksk.key" && file != "zsk.key" {
        return Err(format!("invalid key filename: {file}"));
    }
    let bytes = data_encoding::BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("base64 decode: {e}"))?;
    let zone_name = Name::from_ascii(zone).map_err(|e| format!("invalid zone '{zone}': {e:?}"))?;
    let path = zone_key_dir(config_dir, &zone_name).join(file);
    if std::fs::read(&path).map(|c| c == bytes).unwrap_or(false) {
        return Ok(false);
    }
    write_key_0600(&path, &bytes)?;
    Ok(true)
}

// ── Online signer ─────────────────────────────────────────────────────────────────────────────

/// One signed zone's key bundle.
struct ZoneKeys {
    apex: Name,
    ksk: SigningKey,
    zsk: SigningKey,
}

/// Online DNSSEC signer for the configured local zones (#201). Holds each zone's KSK+ZSK and
/// produces signed `wire::Record`s on the serving path.
pub struct ZoneSigner {
    zones: HashMap<Box<[u8]>, ZoneKeys>, // keyed by lowercased wire apex name
    sig_validity: Duration,
}

pub type SharedZoneSigner = std::sync::Arc<arc_swap::ArcSwap<Option<std::sync::Arc<ZoneSigner>>>>;

pub static SHARED_SIGNER: std::sync::OnceLock<SharedZoneSigner> = std::sync::OnceLock::new();

/// Lowercased wire-name key.
fn wire_key(n: &Name) -> Box<[u8]> {
    let mut out = Vec::with_capacity(n.wire().len());
    for &b in n.wire() {
        out.push(b.to_ascii_lowercase());
    }
    out.into_boxed_slice()
}

/// Rebuild the signer for `apexes` and hot-swap it into the shared handle (slave key adoption).
pub fn rebuild_shared(config_dir: &Path, apexes: &[String], sig_validity: Duration) -> Result<usize, String> {
    let signer = ZoneSigner::new(config_dir, apexes, sig_validity)?;
    let n = signer.zones.len();
    if let Some(shared) = SHARED_SIGNER.get() {
        shared.store(std::sync::Arc::new(Some(std::sync::Arc::new(signer))));
    }
    Ok(n)
}

impl ZoneSigner {
    /// Load (or generate on first use) the KSK+ZSK for each configured local-zone apex.
    pub fn new(config_dir: &Path, apexes: &[String], sig_validity: Duration) -> Result<Self, String> {
        let mut zones = HashMap::new();
        for a in apexes {
            let apex = Name::from_ascii(a).map_err(|e| format!("invalid zone '{a}': {e:?}"))?;
            let (ksk, zsk) = load_or_generate(config_dir, &apex)?;
            zones.insert(wire_key(&apex), ZoneKeys { apex, ksk, zsk });
        }
        Ok(Self { zones, sig_validity })
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// Longest-suffix match: the signed zone whose apex is a suffix of (or equal to) `name`.
    fn zone_for(&self, name: &Name) -> Option<&ZoneKeys> {
        let mut cur: &[u8] = name.wire();
        loop {
            let key: Vec<u8> = cur.iter().map(|b| b.to_ascii_lowercase()).collect();
            if let Some(z) = self.zones.get(&key[..]) {
                return Some(z);
            }
            if cur.len() <= 1 {
                return None;
            }
            let skip = 1 + cur[0] as usize;
            if skip >= cur.len() {
                return None;
            }
            cur = &cur[skip..];
        }
    }

    /// True if `name` is exactly a signed-zone apex.
    pub fn is_apex(&self, name: &Name) -> bool {
        self.zones.contains_key(&wire_key(name)[..])
    }

    /// The apex of the signed zone containing `name`, if any.
    pub fn apex_for(&self, name: &Name) -> Option<Name> {
        self.zone_for(name).map(|z| z.apex.clone())
    }

    fn validity_window(&self) -> (u32, u32) {
        let now = now_secs();
        let inception = now.saturating_sub(INCEPTION_BACKDATE_SECS) as u32;
        let expiration = (now + self.sig_validity.as_secs()) as u32;
        (inception, expiration)
    }

    /// Build an RRSIG `wire::Record` over `rdatas` (all sharing `owner`/`type_covered`/`ttl`),
    /// signed with `key` whose DNSKEY publishes at `apex`.
    fn rrsig_record(
        &self,
        key: &SigningKey,
        apex: &Name,
        owner: &Name,
        type_covered: u16,
        ttl: u32,
        rdatas: &[&Rdata],
    ) -> Option<Record> {
        let (inception, expiration) = self.validity_window();
        let p = dnssec_sign::RrsigParams {
            type_covered,
            key_tag: key.key_tag(),
            signer_name: apex.clone(),
            original_ttl: ttl,
            inception,
            expiration,
        };
        let rdata = dnssec_sign::sign_rrset(key, &p, owner, class::IN, rdatas).ok()?;
        Some(Record {
            name: owner.clone(),
            rtype: rtype::RRSIG,
            rclass: class::IN,
            ttl,
            rdata: Rdata::Unknown { rtype: rtype::RRSIG, data: rdata },
        })
    }

    /// Sign a positive answer RRset, returning the RRSIG record to append. `None` if the name is
    /// not within a signed zone.
    pub fn sign_answer(&self, qtype: u16, records: &[Record]) -> Option<Record> {
        let first = records.first()?;
        let z = self.zone_for(&first.name)?;
        let rdatas: Vec<&Rdata> = records.iter().map(|r| &r.rdata).collect();
        self.rrsig_record(&z.zsk, &z.apex, &first.name, qtype, first.ttl, &rdatas)
    }

    /// Sign every RRset in a record chain (e.g. a CNAME chain + terminal RRset). Groups by
    /// (owner, type); returns the RRSIG records to append.
    pub fn sign_chain(&self, records: &[Record]) -> Vec<Record> {
        let mut groups: Vec<(Name, u16, Vec<&Record>)> = Vec::new();
        for r in records {
            if let Some(g) = groups
                .iter_mut()
                .find(|(gn, gt, _)| gn.eq_ignore_ascii_case(&r.name) && *gt == r.rtype)
            {
                g.2.push(r);
            } else {
                groups.push((r.name.clone(), r.rtype, vec![r]));
            }
        }
        let mut out = Vec::new();
        for (owner, ty, recs) in &groups {
            if let Some(z) = self.zone_for(owner) {
                let rdatas: Vec<&Rdata> = recs.iter().map(|r| &r.rdata).collect();
                if let Some(sig) =
                    self.rrsig_record(&z.zsk, &z.apex, owner, *ty, recs[0].ttl, &rdatas)
                {
                    out.push(sig);
                }
            }
        }
        out
    }

    /// The apex DNSKEY RRset (KSK + ZSK) plus its RRSIG (signed by the KSK), for a DNSKEY query.
    pub fn apex_dnskey(&self, apex: &Name) -> Option<Vec<Record>> {
        let z = self.zones.get(&wire_key(apex)[..])?;
        let ttl = 3600;
        let ksk_rd = Rdata::Unknown { rtype: rtype::DNSKEY, data: z.ksk.dnskey_rdata() };
        let zsk_rd = Rdata::Unknown { rtype: rtype::DNSKEY, data: z.zsk.dnskey_rdata() };
        let mk = |rd: &Rdata| Record {
            name: z.apex.clone(),
            rtype: rtype::DNSKEY,
            rclass: class::IN,
            ttl,
            rdata: rd.clone(),
        };
        let mut out = vec![mk(&ksk_rd), mk(&zsk_rd)];
        let rdatas = [&ksk_rd, &zsk_rd];
        let sig = self.rrsig_record(&z.ksk, &z.apex, &z.apex, rtype::DNSKEY, ttl, &rdatas)?;
        out.push(sig);
        Some(out)
    }

    /// Synthesize the apex SOA RDATA (Runbound local zones carry none).
    fn synth_soa_rdata(apex: &Name) -> Rdata {
        let serial = (now_secs() / 60) as u32;
        let rname = prepend_label("hostmaster", apex).unwrap_or_else(|| apex.clone());
        Rdata::Soa {
            mname: apex.clone(),
            rname,
            serial,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 300,
        }
    }

    /// The signed apex SOA RRset (SOA queries, and the authority of negative responses).
    pub fn signed_soa(&self, apex: &Name) -> Option<Vec<Record>> {
        let z = self.zones.get(&wire_key(apex)[..])?;
        let ttl = 300;
        let rd = Self::synth_soa_rdata(&z.apex);
        let soa = Record {
            name: z.apex.clone(),
            rtype: rtype::SOA,
            rclass: class::IN,
            ttl,
            rdata: rd.clone(),
        };
        let sig = self.rrsig_record(&z.zsk, &z.apex, &z.apex, rtype::SOA, ttl, &[&rd])?;
        Some(vec![soa, sig])
    }

    /// Authority section for a signed negative response: SOA + RRSIG, then the NSEC3 denial.
    pub fn signed_negative(
        &self,
        is_nxdomain: bool,
        qname: &Name,
        owners: &[(Name, Vec<u16>)],
    ) -> Option<Vec<Record>> {
        let z = self.zone_for(qname)?;
        let mut authority = self.signed_soa(&z.apex)?;
        let denial = if is_nxdomain {
            self.nsec3_nxdomain(z, qname, owners)?
        } else {
            self.nsec3_nodata(z, qname, owners)?
        };
        authority.extend(denial);
        Some(authority)
    }

    /// DS RDATA (SHA-256) for every signed zone — surfaced to the operator to publish at the parent.
    /// Returns `(zone-presentation, key_tag, ds_rdata_bytes)`.
    pub fn ds_records(&self) -> Vec<(String, u16, Vec<u8>)> {
        let mut out = Vec::new();
        for z in self.zones.values() {
            let ds = z.ksk.ds_rdata(&z.apex);
            let key_tag = u16::from_be_bytes([ds[0], ds[1]]);
            out.push((z.apex.to_ascii(), key_tag, ds));
        }
        out
    }

    // ── NSEC3 authenticated denial (RFC 5155, params per RFC 9276) ─────────────────────────────

    /// Build + sign one NSEC3 RR for `hash` with `next_hash` and `types`: `[NSEC3, RRSIG]`.
    fn signed_nsec3(
        &self,
        z: &ZoneKeys,
        hash: &[u8],
        next_hash: &[u8],
        types: &[u16],
    ) -> Option<Vec<Record>> {
        let owner = prepend_label(&dnssec_sign::nsec3_owner_label(hash), &z.apex)?;
        let ttl = 300;
        let nsec3_rd = dnssec_sign::nsec3_rdata(0, NSEC3_ITERATIONS, NSEC3_SALT, next_hash, types);
        let rd = Rdata::Unknown { rtype: rtype::NSEC3, data: nsec3_rd };
        let rec = Record {
            name: owner.clone(),
            rtype: rtype::NSEC3,
            rclass: class::IN,
            ttl,
            rdata: rd.clone(),
        };
        let sig = self.rrsig_record(&z.zsk, &z.apex, &owner, rtype::NSEC3, ttl, &[&rd])?;
        Some(vec![rec, sig])
    }

    /// NSEC3 NODATA proof: the signed NSEC3 matching `qname` (exists, lacks the qtype).
    fn nsec3_nodata(&self, z: &ZoneKeys, qname: &Name, owners: &[(Name, Vec<u16>)]) -> Option<Vec<Record>> {
        let nodes = build_nsec3_chain(owners)?;
        let qhash = nsec3_hash_name(qname);
        let i = nodes.iter().position(|n| n.hash == qhash)?;
        self.signed_nsec3(z, &nodes[i].hash, &next_hash(&nodes, i), &nodes[i].types)
    }

    /// NSEC3 NXDOMAIN proof (RFC 5155 §7.2.2): match the closest encloser, cover the next-closer
    /// name, cover the wildcard at the closest encloser.
    fn nsec3_nxdomain(&self, z: &ZoneKeys, qname: &Name, owners: &[(Name, Vec<u16>)]) -> Option<Vec<Record>> {
        let nodes = build_nsec3_chain(owners)?;
        let existing: std::collections::HashSet<[u8; 20]> =
            owners.iter().map(|(n, _)| nsec3_hash_name(n)).collect();

        // Closest encloser: longest existing ancestor of qname. Next closer: one label longer.
        let mut child = qname.clone();
        let (ce, next_closer) = loop {
            let parent = base_name(&child)?;
            if existing.contains(&nsec3_hash_name(&parent)) {
                break (parent, child);
            }
            child = parent;
        };

        let ce_hash = nsec3_hash_name(&ce);
        let nc_hash = nsec3_hash_name(&next_closer);
        let wc_hash = nsec3_hash_name(&prepend_label("*", &ce)?);

        let ce_i = nodes.iter().position(|n| n.hash == ce_hash)?;
        let nc_i = (0..nodes.len()).find(|&i| covers(&nodes, i, &nc_hash));
        let wc_i = (0..nodes.len()).find(|&i| covers(&nodes, i, &wc_hash));

        let mut out: Vec<Record> = Vec::new();
        let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for i in [Some(ce_i), nc_i, wc_i].into_iter().flatten() {
            if seen.insert(i) {
                out.extend(self.signed_nsec3(z, &nodes[i].hash, &next_hash(&nodes, i), &nodes[i].types)?);
            }
        }
        Some(out)
    }
}

/// Compute the zone's owner set for NSEC3: every name at/under `apex` with its present RR types,
/// the apex augmented with SOA + DNSKEY + NSEC3PARAM, plus the empty non-terminals between names
/// and the apex. `entries` yields each existing owner name with its present types.
pub fn zone_owners(
    entries: impl Iterator<Item = (Name, Vec<u16>)>,
    apex: &Name,
) -> Vec<(Name, Vec<u16>)> {
    use std::collections::{HashMap, HashSet};
    let mut map: HashMap<Box<[u8]>, (Name, HashSet<u16>)> = HashMap::new();
    let apex_entry = map
        .entry(wire_key(apex))
        .or_insert_with(|| (apex.clone(), HashSet::new()));
    apex_entry.1.insert(rtype::SOA);
    apex_entry.1.insert(rtype::DNSKEY);
    apex_entry.1.insert(rtype::NSEC3PARAM);
    for (name, types) in entries {
        if !zone_of(apex, &name) {
            continue;
        }
        // Empty non-terminals: every ancestor between `name` and the apex must exist.
        let mut cur = name.clone();
        while cur.label_count() > apex.label_count() {
            let Some(parent) = base_name(&cur) else { break };
            map.entry(wire_key(&cur))
                .or_insert_with(|| (cur.clone(), HashSet::new()));
            cur = parent;
        }
        let e = map
            .entry(wire_key(&name))
            .or_insert_with(|| (name.clone(), HashSet::new()));
        for t in types {
            e.1.insert(t);
        }
    }
    map.into_values()
        .map(|(n, ts)| (n, ts.into_iter().collect()))
        .collect()
}

/// One node of the sorted NSEC3 hash ring.
struct Nsec3Node {
    hash: [u8; 20],
    types: Vec<u16>,
}

fn nsec3_hash_name(name: &Name) -> [u8; 20] {
    let canon = dnssec_sign::canonical_name_wire(name);
    dnssec_sign::nsec3_hash(&canon, NSEC3_SALT, NSEC3_ITERATIONS)
}

/// Build the NSEC3 chain over the zone's owner names, sorted ascending by hash (deduped).
fn build_nsec3_chain(owners: &[(Name, Vec<u16>)]) -> Option<Vec<Nsec3Node>> {
    let mut nodes: Vec<Nsec3Node> = Vec::with_capacity(owners.len());
    for (name, types) in owners {
        let hash = nsec3_hash_name(name);
        let mut t = types.clone();
        t.push(rtype::RRSIG);
        nodes.push(Nsec3Node { hash, types: t });
    }
    nodes.sort_by(|a, b| a.hash.cmp(&b.hash));
    nodes.dedup_by(|a, b| a.hash == b.hash);
    (!nodes.is_empty()).then_some(nodes)
}

fn next_hash(nodes: &[Nsec3Node], i: usize) -> [u8; 20] {
    nodes[(i + 1) % nodes.len()].hash
}

/// True if node `i` covers `target` (owner < target < next, with ring wraparound).
fn covers(nodes: &[Nsec3Node], i: usize, target: &[u8; 20]) -> bool {
    let owner = &nodes[i].hash;
    let next = &nodes[(i + 1) % nodes.len()].hash;
    if owner < next {
        owner < target && target < next
    } else {
        target > owner || target < next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dnskey_and_ds() {
        let ksk = SigningKey::generate(true).unwrap();
        let zone = Name::from_ascii("example.com.").unwrap();
        let ds = ksk.ds_rdata(&zone);
        let tag = u16::from_be_bytes([ds[0], ds[1]]);
        assert_eq!(tag, ksk.key_tag(), "DS references the DNSKEY key tag");
        assert_eq!(ds.len(), 36);
    }

    #[test]
    fn load_or_generate_persists_and_reloads() {
        let tmp = std::env::temp_dir().join(format!("rb201wtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let zone = Name::from_ascii("test.example.").unwrap();
        let (k1, z1) = load_or_generate(&tmp, &zone).unwrap();
        let (k2, z2) = load_or_generate(&tmp, &zone).unwrap();
        assert_eq!(k1.key_tag(), k2.key_tag());
        assert_eq!(z1.key_tag(), z2.key_tag());
        assert!(k1.is_ksk() && !z1.is_ksk());
        remove_zone_keys(&tmp, &zone).unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn signer_for(apex: &str) -> (ZoneSigner, Name) {
        let tmp = std::env::temp_dir().join(format!("rb201sig-{}-{}", std::process::id(), apex));
        let _ = std::fs::remove_dir_all(&tmp);
        let s = ZoneSigner::new(&tmp, &[apex.to_string()], Duration::from_secs(86_400)).unwrap();
        (s, Name::from_ascii(apex).unwrap())
    }

    #[test]
    fn apex_dnskey_has_two_keys_and_rrsig() {
        let (s, apex) = signer_for("signed.test.");
        let recs = s.apex_dnskey(&apex).unwrap();
        assert_eq!(recs.iter().filter(|r| r.rtype == rtype::DNSKEY).count(), 2);
        assert_eq!(recs.iter().filter(|r| r.rtype == rtype::RRSIG).count(), 1);
    }

    #[test]
    fn signed_soa_and_positive_answer_have_rrsig() {
        let (s, apex) = signer_for("signed.test.");
        let soa = s.signed_soa(&apex).unwrap();
        assert!(soa.iter().any(|r| r.rtype == rtype::SOA));
        assert!(soa.iter().any(|r| r.rtype == rtype::RRSIG));

        let a = Record {
            name: Name::from_ascii("www.signed.test.").unwrap(),
            rtype: rtype::A,
            rclass: class::IN,
            ttl: 300,
            rdata: Rdata::A("192.0.2.1".parse().unwrap()),
        };
        let sig = s.sign_answer(rtype::A, &[a]).unwrap();
        assert_eq!(sig.rtype, rtype::RRSIG);
    }

    #[test]
    fn nsec3_nxdomain_produces_covering_records() {
        let (s, apex) = signer_for("signed.test.");
        let owners = zone_owners(
            [(Name::from_ascii("www.signed.test.").unwrap(), vec![rtype::A])].into_iter(),
            &apex,
        );
        let proof = s
            .signed_negative(true, &Name::from_ascii("absent.signed.test.").unwrap(), &owners)
            .unwrap();
        // SOA + its RRSIG, plus at least one NSEC3 + RRSIG pair.
        assert!(proof.iter().any(|r| r.rtype == rtype::SOA));
        assert!(proof.iter().filter(|r| r.rtype == rtype::NSEC3).count() >= 1);
        assert!(proof.iter().filter(|r| r.rtype == rtype::RRSIG).count() >= 2);
    }
}
