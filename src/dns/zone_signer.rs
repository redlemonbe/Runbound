// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// #201 — DNSSEC authoritative signing for local zones: key-management foundation.
//
// Per-zone KSK + ZSK (ECDSAP256SHA256 / alg 13, RFC 6605), generated on demand and stored as
// PKCS#8 DER under `<config_dir>/dnssec/<zone>/{ksk,zsk}.key` (mode 0600 from creation). This
// module owns the key lifecycle and the published DNSKEY / DS records. Online RRset signing
// (RRSIG / NSEC3) and the serving path land in later increments.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::dnssec::crypto::{signing_key_from_der, EcdsaSigningKey};
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, NSEC3, RRSIG};
use hickory_proto::dnssec::{Algorithm, DigestType, DnssecSigner, Nsec3HashAlgorithm, SigningKey};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

/// The single algorithm used for local-zone signing: ECDSA P-256 / SHA-256 (RFC 6605, alg 13).
const ZONE_ALGORITHM: Algorithm = Algorithm::ECDSAP256SHA256;

/// One zone-signing keypair (KSK or ZSK): the PKCS#8 DER (for storage) + the loaded signer.
pub struct ZoneKey {
    pkcs8: Vec<u8>,
    is_ksk: bool,
    signer: Box<dyn SigningKey>,
}

impl ZoneKey {
    /// Generate a fresh ECDSAP256SHA256 key (KSK if `is_ksk`, else ZSK).
    pub fn generate(is_ksk: bool) -> Result<Self, String> {
        let der = EcdsaSigningKey::generate_pkcs8(ZONE_ALGORITHM)
            .map_err(|e| format!("dnssec key generation failed: {e}"))?;
        Self::from_pkcs8(der.secret_pkcs8_der().to_vec(), is_ksk)
    }

    /// Load a key from its stored PKCS#8 DER bytes.
    pub fn from_pkcs8(pkcs8: Vec<u8>, is_ksk: bool) -> Result<Self, String> {
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.clone()));
        let signer = signing_key_from_der(&der, ZONE_ALGORITHM)
            .map_err(|e| format!("dnssec key load failed: {e}"))?;
        Ok(Self {
            pkcs8,
            is_ksk,
            signer,
        })
    }

    #[allow(dead_code)] // used by tests and later increments
    pub fn is_ksk(&self) -> bool {
        self.is_ksk
    }

    #[allow(dead_code)] // direct signer access reserved for future increments
    pub fn signer(&self) -> &dyn SigningKey {
        self.signer.as_ref()
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The DNSKEY RR data: zone key, with the Secure Entry Point bit set for the KSK.
    pub fn dnskey(&self) -> Result<DNSKEY, String> {
        let public = self
            .signer
            .to_public_key()
            .map_err(|e| format!("dnssec public key: {e}"))?;
        Ok(DNSKEY::new(true, self.is_ksk, false, public))
    }

    /// The key tag (RFC 4034 §5.3) for this key's DNSKEY.
    #[allow(dead_code)] // used by tests and the DS/rollover paths in later increments
    pub fn key_tag(&self) -> Result<u16, String> {
        self.dnskey()?
            .calculate_key_tag()
            .map_err(|e| format!("dnssec key tag: {e}"))
    }

    /// The DS RR (SHA-256) to publish at the parent for `zone`.
    pub fn ds(&self, zone: &Name) -> Result<DS, String> {
        let dnskey = self.dnskey()?;
        let key_tag = dnskey
            .calculate_key_tag()
            .map_err(|e| format!("dnssec key tag: {e}"))?;
        let digest = dnskey
            .to_digest(zone, DigestType::SHA256)
            .map_err(|e| format!("dnssec DS digest: {e}"))?;
        Ok(DS::new(
            key_tag,
            ZONE_ALGORITHM,
            DigestType::SHA256,
            digest.as_ref().to_vec(),
        ))
    }

    /// Build a `DnssecSigner` bound to `zone` for producing RRSIGs. The signing key is
    /// reconstructed from the stored PKCS#8 so the `ZoneKey` itself stays usable afterwards.
    pub fn dnssec_signer(&self, zone: &Name, sig_validity: Duration) -> Result<DnssecSigner, String> {
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.clone()));
        let key = signing_key_from_der(&der, ZONE_ALGORITHM)
            .map_err(|e| format!("dnssec signer key: {e}"))?;
        let dnskey = self.dnskey()?;
        Ok(DnssecSigner::new(dnskey, key, zone.clone(), sig_validity))
    }
}

/// Sign an RRset with `signer`, returning the RRSIG as a ready-to-serve `Record` (RFC 4034).
/// Inception is "now"; expiration is `now + signer.sig_duration()`.
pub fn sign_rrset(rrset: &RecordSet, signer: &DnssecSigner) -> Result<Record, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock before epoch: {e}"))?
        .as_secs() as i64;
    // SEC-L5: backdate inception by 1h so a validator whose clock runs slightly ahead does
    // not reject a freshly-minted signature (now < inception). Expiration shifts with it; the
    // validity window length is unchanged.
    let inception = OffsetDateTime::from_unix_timestamp(now - 3600)
        .map_err(|e| format!("inception time: {e}"))?;
    let rrsig = RRSIG::from_rrset(rrset, DNSClass::IN, inception, signer)
        .map_err(|e| format!("sign rrset: {e}"))?;
    Ok(Record::from_rdata(
        rrset.name().clone(),
        rrset.ttl(),
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
    ))
}

/// Directory holding a zone's keys: `<config_dir>/dnssec/<zone>/`.
fn zone_key_dir(config_dir: &Path, zone: &Name) -> PathBuf {
    let label = zone.to_string();
    let label = label.trim_end_matches('.');
    let label = if label.is_empty() { "root" } else { label };
    config_dir.join("dnssec").join(label)
}

/// Load the zone's KSK + ZSK, generating and persisting them (mode 0600) on first use.
/// Returns `(ksk, zsk)`.
pub fn load_or_generate(config_dir: &Path, zone: &Name) -> Result<(ZoneKey, ZoneKey), String> {
    let dir = zone_key_dir(config_dir, zone);
    let ksk = load_or_generate_one(&dir, "ksk.key", true)?;
    let zsk = load_or_generate_one(&dir, "zsk.key", false)?;
    Ok((ksk, zsk))
}

fn load_or_generate_one(dir: &Path, file: &str, is_ksk: bool) -> Result<ZoneKey, String> {
    let path = dir.join(file);
    if let Ok(bytes) = std::fs::read(&path) {
        return ZoneKey::from_pkcs8(bytes, is_ksk);
    }
    let key = ZoneKey::generate(is_ksk)?;
    write_key_0600(&path, key.pkcs8())?;
    Ok(key)
}

/// Remove a zone's key material (called on zone deletion — no orphaned keys, #201 lifecycle).
#[allow(dead_code)] // wired into zone deletion in #201 increment 7 (lifecycle)
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
        f.write_all(bytes)
            .map_err(|e| format!("write {path:?}: {e}"))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes).map_err(|e| format!("write {path:?}: {e}"))?;
    Ok(())
}

/// One signed zone's key bundle.
struct ZoneKeys {
    apex: Name,
    ksk: ZoneKey,
    zsk: ZoneKey,
    // SEC-L1: per-zone signers built ONCE at load (not reconstructed from PKCS#8 per RRset per
    // query). Reused for every RRSIG; sign_rrset still stamps a fresh inception each call.
    zsk_signer: DnssecSigner,
    ksk_signer: DnssecSigner,
}

/// Online DNSSEC signer for the configured local zones (#201). Holds each zone's KSK+ZSK and
/// signs answers / the apex DNSKEY on the slow path. `None` in the handler when the feature is off.
pub struct ZoneSigner {
    sig_validity: Duration,
    zones: HashMap<LowerName, ZoneKeys>,
}

/// Hot-swappable handle to the zone signer, so a slave can adopt the master's replicated keys at
/// runtime. `None` inner = signing off (or not yet keyed).
pub type SharedZoneSigner =
    std::sync::Arc<arc_swap::ArcSwap<Option<std::sync::Arc<ZoneSigner>>>>;

/// Process-global handle to the live signer, shared by the DNS handler (run_dns_server) and the
/// relay key-replication path (sync.rs) without threading it through every constructor.
pub static SHARED_SIGNER: std::sync::OnceLock<SharedZoneSigner> = std::sync::OnceLock::new();

/// Rebuild the signer for `apexes` under `config_dir` and hot-swap it into the shared handle.
/// Called on the slave after the master replicates fresh keys to disk. Returns the zone count.
pub fn rebuild_shared(config_dir: &Path, apexes: &[String], sig_validity: Duration) -> Result<usize, String> {
    let signer = ZoneSigner::new(config_dir, apexes, sig_validity)?;
    let n = signer.zones.len();
    if let Some(shared) = SHARED_SIGNER.get() {
        shared.store(std::sync::Arc::new(Some(std::sync::Arc::new(signer))));
    }
    Ok(n)
}

/// Read a zone's stored KSK + ZSK (PKCS#8 DER) from disk, base64-encoded for relay transport.
/// `(zone-presentation, ksk_b64, zsk_b64)`; `None` if either key file is missing.
pub fn export_keys(config_dir: &Path, apex: &Name) -> Option<(String, String, String)> {
    let dir = zone_key_dir(config_dir, apex);
    let ksk = std::fs::read(dir.join("ksk.key")).ok()?;
    let zsk = std::fs::read(dir.join("zsk.key")).ok()?;
    Some((
        apex.to_string(),
        data_encoding::BASE64.encode(&ksk),
        data_encoding::BASE64.encode(&zsk),
    ))
}

/// Write a base64-encoded PKCS#8 key to `<config_dir>/dnssec/<zone>/<file>` (mode 0600), only when
/// it differs from what is already there. Returns `true` if the file changed. Used on the slave to
/// adopt the master's replicated keys.
pub fn import_key(config_dir: &Path, zone: &str, file: &str, b64: &str) -> Result<bool, String> {
    // SEC-L11 (defence-in-depth): only ever write the two known key filenames. The slave passes
    // these as hard-coded literals today, but validate here so no future caller can turn the
    // relayed `file` into a path-traversal write. (Cross-model Gemini finding, disputed-down:
    // not currently reachable since `file` is not attacker-controlled, but cheap to fence off.)
    if file != "ksk.key" && file != "zsk.key" {
        return Err(format!("invalid key filename: {file}"));
    }
    let bytes = data_encoding::BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("base64 decode: {e}"))?;
    let zone_name = Name::from_str(zone).map_err(|e| format!("invalid zone '{zone}': {e}"))?;
    let path = zone_key_dir(config_dir, &zone_name).join(file);
    if std::fs::read(&path).map(|c| c == bytes).unwrap_or(false) {
        return Ok(false);
    }
    write_key_0600(&path, &bytes)?;
    Ok(true)
}

impl ZoneSigner {
    /// Load (or generate on first use) the KSK+ZSK for each configured local-zone apex.
    pub fn new(config_dir: &Path, apexes: &[String], sig_validity: Duration) -> Result<Self, String> {
        let mut zones = HashMap::new();
        for a in apexes {
            let apex = Name::from_str(a).map_err(|e| format!("invalid zone '{a}': {e}"))?;
            let (ksk, zsk) = load_or_generate(config_dir, &apex)?;
            let zsk_signer = zsk.dnssec_signer(&apex, sig_validity)?;
            let ksk_signer = ksk.dnssec_signer(&apex, sig_validity)?;
            zones.insert(
                LowerName::from(apex.clone()),
                ZoneKeys { apex, ksk, zsk, zsk_signer, ksk_signer },
            );
        }
        Ok(Self {
            sig_validity,
            zones,
        })
    }

    #[allow(dead_code)] // used by startup diagnostics / API in later #201 increments
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// Longest-suffix match: the signed zone whose apex is a suffix of (or equal to) `name`.
    fn zone_for(&self, name: &LowerName) -> Option<&ZoneKeys> {
        let mut cur = name.clone();
        loop {
            if let Some(z) = self.zones.get(&cur) {
                return Some(z);
            }
            if cur.is_root() {
                return None;
            }
            cur = cur.base_name();
        }
    }

    /// True if `name` is exactly a signed-zone apex (where the DNSKEY RRset lives).
    pub fn is_apex(&self, name: &LowerName) -> bool {
        self.zones.contains_key(name)
    }

    /// The apex of the signed zone containing `name`, if any.
    pub fn apex_for(&self, name: &LowerName) -> Option<Name> {
        self.zone_for(name).map(|z| z.apex.clone())
    }

    /// Sign a positive answer RRset, returning the RRSIG record to append to the answer section.
    /// `None` if the name is not within a signed zone.
    pub fn sign_answer(&self, qtype: RecordType, records: &[&Record]) -> Option<Record> {
        let first = *records.first()?;
        let z = self.zone_for(&LowerName::from(first.name.clone()))?;
        let mut rrset = RecordSet::new(first.name.clone(), qtype, 0);
        rrset.set_ttl(first.ttl);
        for r in records {
            rrset.insert((*r).clone(), 0);
        }
        sign_rrset(&rrset, &z.zsk_signer).ok()
    }

    /// SEC-L7: sign every RRset in a record chain (e.g. a CNAME chain + its terminal RRset).
    /// Groups by (owner, type) and signs each group with the zone ZSK; returns the RRSIG records
    /// to append. Records outside any signed zone are skipped (sign_answer returns None).
    pub fn sign_chain(&self, records: &[Record]) -> Vec<Record> {
        let mut groups: Vec<(Name, RecordType, Vec<&Record>)> = Vec::new();
        for r in records {
            let n = r.name.clone();
            let ty = r.record_type();
            if let Some(g) = groups.iter_mut().find(|(gn, gt, _)| *gn == n && *gt == ty) {
                g.2.push(r);
            } else {
                groups.push((n, ty, vec![r]));
            }
        }
        let mut out = Vec::new();
        for (_, ty, recs) in &groups {
            if let Some(rrsig) = self.sign_answer(*ty, recs) {
                out.push(rrsig);
            }
        }
        out
    }

    /// The apex DNSKEY RRset (KSK + ZSK) plus its RRSIG (signed by the KSK), for a DNSKEY query.
    pub fn apex_dnskey(&self, apex: &LowerName) -> Option<Vec<Record>> {
        let z = self.zones.get(apex)?;
        let mut rrset = RecordSet::new(z.apex.clone(), RecordType::DNSKEY, 0);
        rrset.set_ttl(3600);
        rrset.add_rdata(RData::DNSSEC(DNSSECRData::DNSKEY(z.ksk.dnskey().ok()?)));
        rrset.add_rdata(RData::DNSSEC(DNSSECRData::DNSKEY(z.zsk.dnskey().ok()?)));
        let rrsig = sign_rrset(&rrset, &z.ksk_signer).ok()?;
        let mut out: Vec<Record> = rrset.records_without_rrsigs().cloned().collect();
        out.push(rrsig);
        Some(out)
    }

    /// DS records (SHA-256) for every signed zone — surfaced to the operator to publish at the parent.
    pub fn ds_records(&self) -> Vec<(String, DS)> {
        let mut out = Vec::new();
        for z in self.zones.values() {
            if let Ok(ds) = z.ksk.ds(&z.apex) {
                out.push((z.apex.to_string(), ds));
            }
        }
        out
    }

    /// Synthesize the apex SOA for a signed zone (Runbound local zones carry none). Minute-resolution
    /// serial so it advances monotonically across restarts; conservative timers.
    fn synth_soa(apex: &Name) -> SOA {
        let serial = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            / 60) as u32;
        let rname = apex.prepend_label("hostmaster").unwrap_or_else(|_| apex.clone());
        SOA::new(apex.clone(), rname, serial, 3600, 900, 604_800, 300)
    }

    /// The signed apex SOA RRset (for SOA queries and the authority of negative responses).
    pub fn signed_soa(&self, apex: &LowerName) -> Option<Vec<Record>> {
        let z = self.zones.get(apex)?;
        let mut rrset = RecordSet::new(z.apex.clone(), RecordType::SOA, 0);
        rrset.set_ttl(300);
        rrset.add_rdata(RData::SOA(Self::synth_soa(&z.apex)));
        let rrsig = sign_rrset(&rrset, &z.zsk_signer).ok()?;
        let mut out: Vec<Record> = rrset.records_without_rrsigs().cloned().collect();
        out.push(rrsig);
        Some(out)
    }

    /// Authority section for a signed negative response: SOA + RRSIG, then the NSEC3 denial
    /// (closest-encloser for NXDOMAIN, matching for NODATA). `owners` = the zone owner set.
    pub fn signed_negative(
        &self,
        is_nxdomain: bool,
        qname: &Name,
        owners: &[(Name, Vec<RecordType>)],
    ) -> Option<Vec<Record>> {
        let z = self.zone_for(&LowerName::from(qname.clone()))?;
        let apex = LowerName::from(z.apex.clone());
        let mut authority = self.signed_soa(&apex)?;
        let denial = if is_nxdomain {
            self.nsec3_nxdomain(qname, owners)?
        } else {
            self.nsec3_nodata(qname, owners)?
        };
        authority.extend(denial);
        Some(authority)
    }
}

/// Compute the zone's owner set for NSEC3: every name at/under `apex` with its present RR types,
/// the apex augmented with SOA + DNSKEY + NSEC3PARAM, and the empty non-terminals between names
/// and the apex. `entries` yields each existing owner name with its present types.
pub fn zone_owners(
    entries: impl Iterator<Item = (Name, Vec<RecordType>)>,
    apex: &Name,
) -> Vec<(Name, Vec<RecordType>)> {
    use std::collections::{HashMap, HashSet};
    let mut map: HashMap<Name, HashSet<RecordType>> = HashMap::new();
    // Apex always exists with these meta types.
    let apex_entry = map.entry(apex.clone()).or_default();
    apex_entry.insert(RecordType::SOA);
    apex_entry.insert(RecordType::DNSKEY);
    apex_entry.insert(RecordType::NSEC3PARAM);
    for (name, types) in entries {
        if !apex.zone_of(&name) {
            continue; // outside this zone
        }
        // Empty non-terminals: every ancestor between `name` and the apex must exist.
        let mut cur = name.clone();
        while cur.num_labels() > apex.num_labels() {
            map.entry(cur.clone()).or_default();
            cur = cur.base_name();
        }
        let e = map.entry(name).or_default();
        for t in types {
            e.insert(t);
        }
    }
    map.into_iter()
        .map(|(n, ts)| (n, ts.into_iter().collect()))
        .collect()
}

// ── #201: NSEC3 authenticated denial of existence (RFC 5155, params per RFC 9276) ───────────
// Generation is complete + unit-tested here; it is wired into the negative serve path (with the
// zone owner-set + SOA) in the following increment, hence the module-scoped dead-code allowance.
mod nsec3_gen {
    #![allow(dead_code)]
    use super::*;

// RFC 9276: SHA-1, 0 iterations, empty salt.
const NSEC3_ITERATIONS: u16 = 0;

/// Raw 20-byte NSEC3 SHA-1 hash of `name`.
fn nsec3_hash(name: &Name, salt: &[u8]) -> Option<Vec<u8>> {
    Nsec3HashAlgorithm::SHA1
        .hash(salt, name, NSEC3_ITERATIONS)
        .ok()
        .map(|d| d.as_ref().to_vec())
}

/// NSEC3 owner name: `<base32hex(hash)>.<apex>`.
fn nsec3_owner(apex: &Name, hash: &[u8]) -> Option<Name> {
    apex.prepend_label(data_encoding::BASE32_DNSSEC.encode(hash).as_str())
        .ok()
}

/// One node of the sorted NSEC3 hash ring.
struct Nsec3Node {
    hash: Vec<u8>,
    types: Vec<RecordType>,
}

/// Build the NSEC3 chain over the zone's owner names, sorted ascending by hash (deduped).
fn build_nsec3_chain(owners: &[(Name, Vec<RecordType>)], salt: &[u8]) -> Option<Vec<Nsec3Node>> {
    let mut nodes: Vec<Nsec3Node> = Vec::with_capacity(owners.len());
    for (name, types) in owners {
        let hash = nsec3_hash(name, salt)?;
        let mut t = types.clone();
        t.push(RecordType::RRSIG);
        nodes.push(Nsec3Node { hash, types: t });
    }
    nodes.sort_by(|a, b| a.hash.cmp(&b.hash));
    nodes.dedup_by(|a, b| a.hash == b.hash);
    (!nodes.is_empty()).then_some(nodes)
}

/// The `next hashed owner name` for node `i` (wraps to node 0).
fn next_hash(nodes: &[Nsec3Node], i: usize) -> Vec<u8> {
    nodes[(i + 1) % nodes.len()].hash.clone()
}

/// True if node `i` *covers* `target` (owner < target < next, with ring wraparound).
fn covers(nodes: &[Nsec3Node], i: usize, target: &[u8]) -> bool {
    let owner = nodes[i].hash.as_slice();
    let next = nodes[(i + 1) % nodes.len()].hash.as_slice();
    if owner < next {
        owner < target && target < next
    } else {
        target > owner || target < next // last node wraps the ring
    }
}

impl ZoneSigner {
    /// Build + sign one NSEC3 RR (node `i`): returns `[NSEC3 record, RRSIG]`.
    fn signed_nsec3(
        &self,
        z: &ZoneKeys,
        nodes: &[Nsec3Node],
        i: usize,
        salt: &[u8],
    ) -> Option<Vec<Record>> {
        let owner = nsec3_owner(&z.apex, &nodes[i].hash)?;
        let nsec3 = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            NSEC3_ITERATIONS,
            salt.to_vec(),
            next_hash(nodes, i),
            nodes[i].types.iter().copied(),
        );
        let rec = Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC3(nsec3)));
        let mut rrset = RecordSet::new(owner, RecordType::NSEC3, 0);
        rrset.set_ttl(300);
        rrset.insert(rec.clone(), 0);
        let rrsig = sign_rrset(&rrset, &z.zsk_signer).ok()?;
        Some(vec![rec, rrsig])
    }

    /// NSEC3 NODATA proof: the signed NSEC3 matching `qname` (which exists, but lacks the qtype).
    pub fn nsec3_nodata(
        &self,
        qname: &Name,
        owners: &[(Name, Vec<RecordType>)],
    ) -> Option<Vec<Record>> {
        let z = self.zone_for(&LowerName::from(qname.clone()))?;
        let salt: &[u8] = &[];
        let nodes = build_nsec3_chain(owners, salt)?;
        let qhash = nsec3_hash(qname, salt)?;
        let i = nodes.iter().position(|n| n.hash == qhash)?;
        self.signed_nsec3(z, &nodes, i, salt)
    }

    /// NSEC3 NXDOMAIN proof (RFC 5155 §7.2.2): match the closest encloser, cover the next-closer
    /// name, cover the wildcard at the closest encloser. `owners` must include empty non-terminals.
    pub fn nsec3_nxdomain(
        &self,
        qname: &Name,
        owners: &[(Name, Vec<RecordType>)],
    ) -> Option<Vec<Record>> {
        let z = self.zone_for(&LowerName::from(qname.clone()))?;
        let salt: &[u8] = &[];
        let nodes = build_nsec3_chain(owners, salt)?;
        let existing: std::collections::HashSet<Vec<u8>> =
            owners.iter().filter_map(|(n, _)| nsec3_hash(n, salt)).collect();

        // Closest encloser: the longest existing ancestor of qname. Next closer: one label longer.
        let mut child = qname.clone();
        let (ce, next_closer) = loop {
            if child.is_root() {
                return None;
            }
            let parent = child.base_name();
            if existing.contains(&nsec3_hash(&parent, salt)?) {
                break (parent, child);
            }
            child = parent;
        };

        let ce_hash = nsec3_hash(&ce, salt)?;
        let nc_hash = nsec3_hash(&next_closer, salt)?;
        let wc_hash = nsec3_hash(&ce.prepend_label("*").ok()?, salt)?;

        let ce_i = nodes.iter().position(|n| n.hash == ce_hash)?;
        let nc_i = (0..nodes.len()).find(|&i| covers(&nodes, i, &nc_hash));
        let wc_i = (0..nodes.len()).find(|&i| covers(&nodes, i, &wc_hash));

        let mut out: Vec<Record> = Vec::new();
        let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for i in [Some(ce_i), nc_i, wc_i].into_iter().flatten() {
            if seen.insert(i) {
                out.extend(self.signed_nsec3(z, &nodes, i, salt)?);
            }
        }
        Some(out)
    }
}
} // mod nsec3_gen

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn generate_dnskey_and_ds() {
        let ksk = ZoneKey::generate(true).unwrap();
        let zone = Name::from_str("example.com.").unwrap();
        // DNSKEY + key tag are computable and the DS references the same key tag.
        let tag = ksk.key_tag().unwrap();
        let ds = ksk.ds(&zone).unwrap();
        assert_eq!(ds.key_tag(), tag);
        assert!(!ds.digest().is_empty(), "DS digest must not be empty");
    }

    #[test]
    fn pkcs8_load_roundtrip_stable_key_tag() {
        let k1 = ZoneKey::generate(false).unwrap();
        let der = k1.pkcs8().to_vec();
        let k2 = ZoneKey::from_pkcs8(der, false).unwrap();
        assert_eq!(k1.key_tag().unwrap(), k2.key_tag().unwrap());
    }

    #[test]
    fn load_or_generate_persists_and_reloads() {
        let tmp = std::env::temp_dir().join(format!("rb201test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let zone = Name::from_str("test.example.").unwrap();
        let (k1, z1) = load_or_generate(&tmp, &zone).unwrap();
        let (k2, z2) = load_or_generate(&tmp, &zone).unwrap(); // second call reloads from disk
        assert_eq!(k1.key_tag().unwrap(), k2.key_tag().unwrap());
        assert_eq!(z1.key_tag().unwrap(), z2.key_tag().unwrap());
        assert!(k1.is_ksk() && !z1.is_ksk());
        remove_zone_keys(&tmp, &zone).unwrap();
        assert!(!tmp.join("dnssec").join("test.example").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sign_rrset_produces_valid_rrsig() {
        use hickory_proto::dnssec::{PublicKey, TBS};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::RecordType;
        let zsk = ZoneKey::generate(false).unwrap();
        let zone = Name::from_str("example.com.").unwrap();
        let mut rrset = RecordSet::new(zone.clone(), RecordType::A, 0);
        rrset.add_rdata(RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))));
        let signer = zsk
            .dnssec_signer(&zone, Duration::from_secs(86_400))
            .unwrap();
        let rec = sign_rrset(&rrset, &signer).unwrap();
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &rec.data else {
            panic!("expected an RRSIG record");
        };
        // The RRSIG must validate against the ZSK public key over the canonical RRset.
        let tbs = TBS::from_input(
            rrset.name(),
            DNSClass::IN,
            rrsig.input(),
            rrset.records_without_rrsigs(),
        )
        .unwrap();
        let pubkey = signer.key().to_public_key().unwrap();
        assert!(
            pubkey.verify(tbs.as_ref(), rrsig.sig()).is_ok(),
            "RRSIG must validate against the ZSK public key"
        );
    }

    #[test]
    fn nsec3_nodata_and_nxdomain_proofs() {
        let tmp = std::env::temp_dir().join(format!("rb201n3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let signer =
            ZoneSigner::new(&tmp, &["example.com.".to_string()], Duration::from_secs(86_400))
                .unwrap();
        // Owner set: apex (SOA/DNSKEY) + www (A).
        let owners = vec![
            (
                Name::from_str("example.com.").unwrap(),
                vec![RecordType::SOA, RecordType::DNSKEY, RecordType::NSEC3PARAM],
            ),
            (Name::from_str("www.example.com.").unwrap(), vec![RecordType::A]),
        ];
        // NODATA: www exists but has no MX -> matching NSEC3 for www.
        let nodata = signer
            .nsec3_nodata(&Name::from_str("www.example.com.").unwrap(), &owners)
            .expect("NODATA proof");
        assert!(nodata
            .iter()
            .any(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::NSEC3(_)))));
        assert!(nodata
            .iter()
            .any(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(_)))));
        // NXDOMAIN: nope.example.com -> closest-encloser proof (CE=apex, cover next-closer + wildcard).
        let nx = signer
            .nsec3_nxdomain(&Name::from_str("nope.example.com.").unwrap(), &owners)
            .expect("NXDOMAIN proof");
        let n3 = nx
            .iter()
            .filter(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::NSEC3(_))))
            .count();
        assert!((1..=3).contains(&n3), "expected 1..3 NSEC3 RRs, got {n3}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn signed_negative_has_soa_nsec3_and_owners_have_ents() {
        let tmp = std::env::temp_dir().join(format!("rb201neg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let apex = Name::from_str("example.com.").unwrap();
        let signer =
            ZoneSigner::new(&tmp, &["example.com.".to_string()], Duration::from_secs(86_400))
                .unwrap();
        // A record under a deep name forces an empty non-terminal (b.example.com).
        let owners = zone_owners(
            vec![(
                Name::from_str("a.b.example.com.").unwrap(),
                vec![RecordType::A],
            )]
            .into_iter(),
            &apex,
        );
        assert!(owners
            .iter()
            .any(|(n, ts)| *n == apex && ts.contains(&RecordType::SOA)));
        assert!(owners
            .iter()
            .any(|(n, _)| *n == Name::from_str("b.example.com.").unwrap()));
        let neg = signer
            .signed_negative(true, &Name::from_str("nope.example.com.").unwrap(), &owners)
            .expect("signed negative");
        assert!(neg.iter().any(|r| matches!(&r.data, RData::SOA(_))));
        assert!(neg
            .iter()
            .any(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::NSEC3(_)))));
        assert!(
            neg.iter()
                .filter(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(_))))
                .count()
                >= 2
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn zone_signer_signs_answer_and_apex_dnskey() {
        use hickory_proto::rr::rdata::A;
        let tmp = std::env::temp_dir().join(format!("rb201zs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let signer =
            ZoneSigner::new(&tmp, &["example.com.".to_string()], Duration::from_secs(86_400))
                .unwrap();
        assert!(!signer.is_empty());

        // Apex DNSKEY RRset: 2 DNSKEY (KSK+ZSK) + 1 RRSIG.
        let apex = LowerName::from(Name::from_str("example.com.").unwrap());
        assert!(signer.is_apex(&apex));
        let dnskey = signer.apex_dnskey(&apex).unwrap();
        assert_eq!(dnskey.len(), 3, "DNSKEY RRset must be KSK + ZSK + RRSIG");

        // Sign a positive answer for a name inside the zone.
        let rec = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        );
        let rrsig = signer.sign_answer(RecordType::A, &[&rec]).unwrap();
        assert!(matches!(&rrsig.data, RData::DNSSEC(DNSSECRData::RRSIG(_))));

        // A name outside any signed zone yields no signature.
        let foreign = Record::from_rdata(
            Name::from_str("www.other.net.").unwrap(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 2))),
        );
        assert!(signer.sign_answer(RecordType::A, &[&foreign]).is_none());

        assert!(!signer.ds_records().is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
