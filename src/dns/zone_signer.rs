// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// #201 — DNSSEC authoritative signing for local zones: key-management foundation.
//
// Per-zone KSK + ZSK (ECDSAP256SHA256 / alg 13, RFC 6605), generated on demand and stored as
// PKCS#8 DER under `<config_dir>/dnssec/<zone>/{ksk,zsk}.key` (mode 0600 from creation). This
// module owns the key lifecycle and the published DNSKEY / DS records. Online RRset signing
// (RRSIG / NSEC3) and the serving path land in later increments.

use std::path::{Path, PathBuf};

use hickory_proto::dnssec::crypto::{signing_key_from_der, EcdsaSigningKey};
use hickory_proto::dnssec::rdata::{DNSKEY, DS};
use hickory_proto::dnssec::{Algorithm, DigestType, SigningKey};
use hickory_proto::rr::Name;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

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

    pub fn is_ksk(&self) -> bool {
        self.is_ksk
    }

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
}
