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
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_proto::dnssec::{Algorithm, DigestType, DnssecSigner, SigningKey};
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
    #[allow(dead_code)] // surfaced via the API in #201 increment 5 (DS publication)
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
    let inception =
        OffsetDateTime::from_unix_timestamp(now).map_err(|e| format!("inception time: {e}"))?;
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
}

/// Online DNSSEC signer for the configured local zones (#201). Holds each zone's KSK+ZSK and
/// signs answers / the apex DNSKEY on the slow path. `None` in the handler when the feature is off.
pub struct ZoneSigner {
    sig_validity: Duration,
    zones: HashMap<LowerName, ZoneKeys>,
}

impl ZoneSigner {
    /// Load (or generate on first use) the KSK+ZSK for each configured local-zone apex.
    pub fn new(config_dir: &Path, apexes: &[String], sig_validity: Duration) -> Result<Self, String> {
        let mut zones = HashMap::new();
        for a in apexes {
            let apex = Name::from_str(a).map_err(|e| format!("invalid zone '{a}': {e}"))?;
            let (ksk, zsk) = load_or_generate(config_dir, &apex)?;
            zones.insert(LowerName::from(apex.clone()), ZoneKeys { apex, ksk, zsk });
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
        let signer = z.zsk.dnssec_signer(&z.apex, self.sig_validity).ok()?;
        sign_rrset(&rrset, &signer).ok()
    }

    /// The apex DNSKEY RRset (KSK + ZSK) plus its RRSIG (signed by the KSK), for a DNSKEY query.
    pub fn apex_dnskey(&self, apex: &LowerName) -> Option<Vec<Record>> {
        let z = self.zones.get(apex)?;
        let mut rrset = RecordSet::new(z.apex.clone(), RecordType::DNSKEY, 0);
        rrset.set_ttl(3600);
        rrset.add_rdata(RData::DNSSEC(DNSSECRData::DNSKEY(z.ksk.dnskey().ok()?)));
        rrset.add_rdata(RData::DNSSEC(DNSSECRData::DNSKEY(z.zsk.dnskey().ok()?)));
        let signer = z.ksk.dnssec_signer(&z.apex, self.sig_validity).ok()?;
        let rrsig = sign_rrset(&rrset, &signer).ok()?;
        let mut out: Vec<Record> = rrset.records_without_rrsigs().cloned().collect();
        out.push(rrsig);
        Some(out)
    }

    /// DS records (SHA-256) for every signed zone — surfaced to the operator to publish at the parent.
    #[allow(dead_code)] // exposed via GET /api/dnssec/ds in #201 increment 5
    pub fn ds_records(&self) -> Vec<(String, DS)> {
        let mut out = Vec::new();
        for z in self.zones.values() {
            if let Ok(ds) = z.ksk.ds(&z.apex) {
                out.push((z.apex.to_string(), ds));
            }
        }
        out
    }
}

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
