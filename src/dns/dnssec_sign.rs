// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Hickory-free DNSSEC signing crypto (ECDSA P-256 / SHA-256, RFC 6605, alg 13).
//!
//! De-hickory increment 1: the key foundation. ECDSA signing runs on `ring`'s
//! vetted FIXED-format primitive (`ECDSA_P256_SHA256_FIXED_SIGNING`), which
//! emits the raw `r || s` 64-byte signature DNSSEC mandates (RFC 6605 §4) — no
//! ASN.1 re-encoding. The wire-format pieces (DNSKEY / DS RDATA, key tag) are
//! built here against our own `wire` codec, so no hickory type crosses this
//! boundary. RRSIG (increment 2) and NSEC3 (increment 3) layer on top.
//!
//! Correctness is held to the same bar as the wire codec: a differential test
//! (kept while hickory remains a dev-dependency) proves our DNSKEY RDATA, key
//! tag, and DS digest match hickory's for the same key material.

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::dns::wire::Name;

/// DNSSEC algorithm number for ECDSA P-256 / SHA-256 (RFC 6605 §1, alg 13).
pub const ALG_ECDSAP256SHA256: u8 = 13;
/// DS digest type SHA-256 (RFC 4509, digest type 2).
pub const DIGEST_SHA256: u8 = 2;
/// DNSKEY protocol octet — always 3 (RFC 4034 §2.1.2).
const DNSKEY_PROTOCOL: u8 = 3;
/// DNSKEY flags: ZONE bit (bit 7, value 0x0100). Present on every zone key.
const DNSKEY_FLAG_ZONE: u16 = 0x0100;
/// DNSKEY flags: Secure Entry Point (bit 15, value 0x0001). Set on the KSK.
const DNSKEY_FLAG_SEP: u16 = 0x0001;

/// One zone-signing keypair (KSK or ZSK): its PKCS#8 DER (for storage) and the
/// loaded `ring` ECDSA key. The DER is retained so the key can be persisted and
/// relayed without re-deriving it.
pub struct SigningKey {
    pkcs8: Vec<u8>,
    is_ksk: bool,
    key: EcdsaKeyPair,
}

impl SigningKey {
    /// Generate a fresh ECDSAP256SHA256 key (KSK if `is_ksk`, else ZSK).
    pub fn generate(is_ksk: bool) -> Result<Self, String> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| format!("dnssec key generation failed: {e}"))?;
        Self::from_pkcs8(pkcs8.as_ref().to_vec(), is_ksk)
    }

    /// Load a key from its stored PKCS#8 DER bytes.
    pub fn from_pkcs8(pkcs8: Vec<u8>, is_ksk: bool) -> Result<Self, String> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|e| format!("dnssec key load failed: {e}"))?;
        Ok(Self { pkcs8, is_ksk, key })
    }

    /// Only consumed by the zone-signer test oracle (KSK/ZSK split assertion).
    #[cfg(test)]
    pub fn is_ksk(&self) -> bool {
        self.is_ksk
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The raw 64-byte public key (`X || Y`, P-256 affine coordinates) as it
    /// appears in DNSKEY RDATA (RFC 6605 §4). `ring` hands back the SEC1
    /// uncompressed point `0x04 || X || Y`; DNSSEC drops the `0x04` prefix.
    pub fn public_key_raw(&self) -> Vec<u8> {
        let p = self.key.public_key().as_ref();
        // Uncompressed SEC1 point: 0x04 || X(32) || Y(32) = 65 bytes.
        debug_assert_eq!(p.len(), 65, "P-256 uncompressed point is 65 bytes");
        p[1..].to_vec()
    }

    /// Sign `message` with raw ECDSA P-256 (RFC 6605 §4: fixed `r || s`, 64 bytes).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let rng = SystemRandom::new();
        self.key
            .sign(&rng, message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|e| format!("dnssec sign failed: {e}"))
    }

    /// The DNSKEY RDATA bytes for this key (RFC 4034 §2.1):
    /// `flags(u16) | protocol(u8=3) | algorithm(u8=13) | public_key`.
    /// ZONE bit always set; SEP bit set on the KSK.
    pub fn dnskey_rdata(&self) -> Vec<u8> {
        let mut flags = DNSKEY_FLAG_ZONE;
        if self.is_ksk {
            flags |= DNSKEY_FLAG_SEP;
        }
        let pubkey = self.public_key_raw();
        let mut out = Vec::with_capacity(4 + pubkey.len());
        out.extend_from_slice(&flags.to_be_bytes());
        out.push(DNSKEY_PROTOCOL);
        out.push(ALG_ECDSAP256SHA256);
        out.extend_from_slice(&pubkey);
        out
    }

    /// The DNSKEY key tag (RFC 4034 Appendix B, general algorithm — alg 13 is
    /// not the alg-1 special case). Computed over this key's DNSKEY RDATA.
    pub fn key_tag(&self) -> u16 {
        key_tag(&self.dnskey_rdata())
    }

    /// The DS RDATA (SHA-256, RFC 4034 §5.1.4 / RFC 4509) to publish at the
    /// parent for owner `zone`:
    /// `key_tag(u16) | algorithm(u8) | digest_type(u8=2) | SHA256(owner || DNSKEY_RDATA)`.
    /// `owner` is the canonical (lowercased, uncompressed) wire name.
    pub fn ds_rdata(&self, zone: &Name) -> Vec<u8> {
        let dnskey = self.dnskey_rdata();
        let tag = key_tag(&dnskey);
        let mut digest_input = canonical_name_wire(zone);
        digest_input.extend_from_slice(&dnskey);
        let digest = ring::digest::digest(&ring::digest::SHA256, &digest_input);
        let mut out = Vec::with_capacity(4 + digest.as_ref().len());
        out.extend_from_slice(&tag.to_be_bytes());
        out.push(ALG_ECDSAP256SHA256);
        out.push(DIGEST_SHA256);
        out.extend_from_slice(digest.as_ref());
        out
    }
}

/// RFC 4034 Appendix B key-tag checksum over DNSKEY RDATA (for algorithms other
/// than 1): treat the RDATA as a sequence of big-endian 16-bit words, sum them
/// (a trailing odd byte counts as its high half), fold the carry, take the low
/// 16 bits.
pub fn key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        if i & 1 == 0 {
            ac += (b as u32) << 8;
        } else {
            ac += b as u32;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

/// The canonical DNSSEC wire form of a name (RFC 4034 §6.2): the uncompressed
/// wire encoding with every label ASCII-lowercased. Length octets are 0–63,
/// all below `A`, so a blanket lowercase never disturbs them.
pub fn canonical_name_wire(name: &Name) -> Vec<u8> {
    name.wire().iter().map(|b| b.to_ascii_lowercase()).collect()
}

// ── DNSSEC increment 2: RRSIG generation (RFC 4034 §3.1, canonical RRset §6) ──

use crate::dns::wire::{Encoder, Rdata};

/// RRSIG metadata for one signing operation (RFC 4034 §3.1). The signature,
/// labels, and the covered RRset's wire bytes are derived; these are the inputs.
pub struct RrsigParams {
    /// The RR type the signature covers (RFC 4034 §3.1.1).
    pub type_covered: u16,
    /// Key tag of the signing DNSKEY (RFC 4034 §3.1.6).
    pub key_tag: u16,
    /// The signer's name = the zone apex owning the key (RFC 4034 §3.1.7).
    pub signer_name: Name,
    /// Original TTL of the covered RRset (RFC 4034 §3.1.4).
    pub original_ttl: u32,
    /// Signature inception, unix seconds (RFC 4034 §3.1.5).
    pub inception: u32,
    /// Signature expiration, unix seconds (RFC 4034 §3.1.5).
    pub expiration: u32,
}

/// Canonical RDATA bytes for one record's data (RFC 4034 §6.2: names lowercased).
fn canonical_rdata(rd: &Rdata) -> Vec<u8> {
    let mut e = Encoder::uncompressed();
    rd.emit_canonical(&mut e);
    e.into_vec()
}

/// The RRSIG `labels` field (RFC 4034 §3.1.3): owner label count, excluding the
/// root and a leading `*` wildcard label.
fn rrsig_labels(owner: &Name) -> u8 {
    let mut n = owner.label_count();
    let w = owner.wire();
    if w.len() >= 2 && w[0] == 1 && w[1] == b'*' {
        n = n.saturating_sub(1); // leading wildcard is not counted
    }
    n as u8
}

/// The RRSIG RDATA *prefix*: every field except the trailing signature
/// (RFC 4034 §3.1). This is also the leading bytes of the signed data.
fn rrsig_prefix(p: &RrsigParams, labels: u8) -> Vec<u8> {
    let signer = canonical_name_wire(&p.signer_name);
    let mut o = Vec::with_capacity(18 + signer.len());
    o.extend_from_slice(&p.type_covered.to_be_bytes());
    o.push(ALG_ECDSAP256SHA256);
    o.push(labels);
    o.extend_from_slice(&p.original_ttl.to_be_bytes());
    o.extend_from_slice(&p.expiration.to_be_bytes());
    o.extend_from_slice(&p.inception.to_be_bytes());
    o.extend_from_slice(&p.key_tag.to_be_bytes());
    o.extend_from_slice(&signer);
    o
}

/// Build the RRSIG to-be-signed byte stream (RFC 4034 §3.1.8.1):
/// `RRSIG_RDATA_prefix || sorted( owner | type | class | OrigTTL | rdlen | RDATA )`.
/// RRs are sorted by canonical RDATA (RFC 4034 §6.3). `owner` is the RRset owner;
/// `rclass` is its class.
pub fn rrsig_tbs(p: &RrsigParams, owner: &Name, rclass: u16, rdatas: &[&Rdata]) -> Vec<u8> {
    let labels = rrsig_labels(owner);
    let mut tbs = rrsig_prefix(p, labels);

    // Canonical RDATA for each record, sorted as left-justified octet sequences.
    let mut canon: Vec<Vec<u8>> = rdatas.iter().map(|rd| canonical_rdata(rd)).collect();
    canon.sort();

    let owner_wire = canonical_name_wire(owner);
    for rd in &canon {
        tbs.extend_from_slice(&owner_wire);
        tbs.extend_from_slice(&p.type_covered.to_be_bytes());
        tbs.extend_from_slice(&rclass.to_be_bytes());
        tbs.extend_from_slice(&p.original_ttl.to_be_bytes());
        tbs.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        tbs.extend_from_slice(rd);
    }
    tbs
}

/// Sign an RRset, returning the full RRSIG RDATA (`prefix || signature`,
/// RFC 4034 §3.1), ready to wrap in a `wire::Record`.
pub fn sign_rrset(
    key: &SigningKey,
    p: &RrsigParams,
    owner: &Name,
    rclass: u16,
    rdatas: &[&Rdata],
) -> Result<Vec<u8>, String> {
    let tbs = rrsig_tbs(p, owner, rclass, rdatas);
    let sig = key.sign(&tbs)?;
    let labels = rrsig_labels(owner);
    let mut rdata = rrsig_prefix(p, labels);
    rdata.extend_from_slice(&sig);
    Ok(rdata)
}


// ── DNSSEC increment 3: NSEC3 hashing + RDATA (RFC 5155, params per RFC 9276) ──

/// NSEC3 hash algorithm SHA-1 (RFC 5155 §11, the only registered algorithm).
pub const NSEC3_HASH_SHA1: u8 = 1;

/// Iterated NSEC3 hash (RFC 5155 §5): `IH(salt, x, 0) = SHA1(x || salt)`, then
/// `IH(salt, x, k) = SHA1(IH(salt, x, k-1) || salt)`. `name` is the canonical
/// (lowercased, uncompressed) owner wire form. Returns the 20-byte digest.
pub fn nsec3_hash(name_canonical_wire: &[u8], salt: &[u8], iterations: u16) -> [u8; 20] {
    use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1};
    let mut buf = Vec::with_capacity(name_canonical_wire.len() + salt.len());
    buf.extend_from_slice(name_canonical_wire);
    buf.extend_from_slice(salt);
    let mut h = digest(&SHA1, &buf);
    for _ in 0..iterations {
        let mut inp = Vec::with_capacity(20 + salt.len());
        inp.extend_from_slice(h.as_ref());
        inp.extend_from_slice(salt);
        h = digest(&SHA1, &inp);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(h.as_ref());
    out
}

/// Encode an NSEC/NSEC3 type-bitmap (RFC 4034 §4.1.2): per 256-type window, a
/// `window | length | bitmap` block, windows ascending, types set MSB-first.
pub fn type_bitmap(types: &[u16]) -> Vec<u8> {
    use std::collections::BTreeMap;
    let mut windows: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
    for &t in types {
        let win = (t >> 8) as u8;
        let bit = (t & 0xFF) as usize;
        let bm = windows.entry(win).or_insert([0u8; 32]);
        bm[bit / 8] |= 0x80 >> (bit % 8);
    }
    let mut out = Vec::new();
    for (win, bm) in windows {
        let len = bm.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
        if len == 0 {
            continue;
        }
        out.push(win);
        out.push(len as u8);
        out.extend_from_slice(&bm[..len]);
    }
    out
}

/// Build NSEC3 RDATA (RFC 5155 §3.2):
/// `hash_alg(u8=1) | flags(u8) | iterations(u16) | salt_len(u8) | salt |
///  hash_len(u8) | next_hashed_owner | type_bitmaps`.
/// `flags` bit 0 is opt-out; `next_hash` is the raw (un-base32'd) next owner hash.
pub fn nsec3_rdata(flags: u8, iterations: u16, salt: &[u8], next_hash: &[u8], types: &[u16]) -> Vec<u8> {
    let mut o = Vec::with_capacity(6 + salt.len() + next_hash.len() + 8);
    o.push(NSEC3_HASH_SHA1);
    o.push(flags);
    o.extend_from_slice(&iterations.to_be_bytes());
    o.push(salt.len() as u8);
    o.extend_from_slice(salt);
    o.push(next_hash.len() as u8);
    o.extend_from_slice(next_hash);
    o.extend_from_slice(&type_bitmap(types));
    o
}

/// The NSEC3 owner label: base32hex (RFC 4648 §7, lowercase, no padding) of the
/// hash, prepended to the zone apex. Returns the leading label only.
pub fn nsec3_owner_label(hash: &[u8]) -> String {
    data_encoding::BASE32_DNSSEC.encode(hash)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_load_roundtrip_stable_key_tag() {
        let k1 = SigningKey::generate(false).unwrap();
        let der = k1.pkcs8().to_vec();
        let k2 = SigningKey::from_pkcs8(der, false).unwrap();
        // Same key material → same DNSKEY RDATA → same key tag.
        assert_eq!(k1.dnskey_rdata(), k2.dnskey_rdata());
        assert_eq!(k1.key_tag(), k2.key_tag());
        assert_eq!(k1.public_key_raw().len(), 64, "P-256 pubkey is X||Y = 64 bytes");
    }

    #[test]
    fn sign_is_64_byte_fixed() {
        let k = SigningKey::generate(false).unwrap();
        let sig = k.sign(b"hello dnssec").unwrap();
        assert_eq!(sig.len(), 64, "ECDSA P-256 fixed signature is r||s = 64 bytes");
    }

    #[test]
    fn ksk_sets_sep_bit_zsk_does_not() {
        let ksk = SigningKey::generate(true).unwrap();
        let zsk = SigningKey::generate(false).unwrap();
        let ksk_flags = u16::from_be_bytes([ksk.dnskey_rdata()[0], ksk.dnskey_rdata()[1]]);
        let zsk_flags = u16::from_be_bytes([zsk.dnskey_rdata()[0], zsk.dnskey_rdata()[1]]);
        assert_eq!(ksk_flags, 0x0101, "KSK = ZONE|SEP");
        assert_eq!(zsk_flags, 0x0100, "ZSK = ZONE only");
    }

    #[test]
    fn ds_rdata_layout() {
        let ksk = SigningKey::generate(true).unwrap();
        let zone = Name::from_ascii("example.com.").unwrap();
        let ds = ksk.ds_rdata(&zone);
        // key_tag(2) + alg(1) + digest_type(1) + SHA256(32) = 36 bytes.
        assert_eq!(ds.len(), 36);
        assert_eq!(ds[2], ALG_ECDSAP256SHA256);
        assert_eq!(ds[3], DIGEST_SHA256);
        let tag = u16::from_be_bytes([ds[0], ds[1]]);
        assert_eq!(tag, ksk.key_tag(), "DS references this DNSKEY's key tag");
    }

    /// Differential oracle: our DNSKEY RDATA, key tag, and DS digest must match
    /// hickory's for the same PKCS#8 key. Retired with the hickory dev-dep.
    #[test]
    fn matches_hickory_oracle() {
        use hickory_proto::dnssec::crypto::{signing_key_from_der, EcdsaSigningKey};
        use hickory_proto::dnssec::rdata::DNSKEY;
        use hickory_proto::dnssec::{Algorithm, DigestType, SigningKey as HSigningKey};
        use hickory_proto::rr::Name as HName;
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        // Generate with hickory, load the same DER into ours.
        let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let pkcs8 = der.secret_pkcs8_der().to_vec();
        let ours = SigningKey::from_pkcs8(pkcs8.clone(), true).unwrap();

        let hkey = signing_key_from_der(
            &PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)),
            Algorithm::ECDSAP256SHA256,
        )
        .unwrap();
        // KSK DNSKEY: zone_key=true, secure_entry_point=true, revoke=false.
        let public = hkey.to_public_key().unwrap();
        let hdnskey = DNSKEY::new(true, true, false, public);

        // DNSKEY RDATA bytes: hickory emits flags|proto|alg|pubkey too.
        let mut hbytes = Vec::new();
        hdnskey.emit(&mut BinEncoder::new(&mut hbytes)).unwrap();
        assert_eq!(ours.dnskey_rdata(), hbytes, "DNSKEY RDATA must match hickory");

        // Key tag.
        assert_eq!(ours.key_tag(), hdnskey.calculate_key_tag().unwrap());

        // DS digest (SHA-256) over the same owner.
        let zone = "example.com.";
        let hname = HName::from_ascii(zone).unwrap();
        let hds = hdnskey.to_digest(&hname, DigestType::SHA256).unwrap();
        let ours_ds = ours.ds_rdata(&Name::from_ascii(zone).unwrap());
        assert_eq!(&ours_ds[4..], hds.as_ref(), "DS digest must match hickory");
    }

    #[test]
    fn rrsig_tbs_matches_hickory_and_self_verifies() {
        use crate::dns::wire::consts::{class, rtype};
        use crate::dns::wire::Rdata;
        use hickory_proto::dnssec::rdata::sig::SigInput;
        use hickory_proto::dnssec::{Algorithm, TBS};
        use hickory_proto::rr::rdata::A as HA;
        use hickory_proto::rr::{DNSClass, Name as HName, RData, Record as HRecord, RecordType as HRecordType, SerialNumber};
        use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
        use std::net::Ipv4Addr;

        let zsk = SigningKey::generate(false).unwrap();
        let owner = Name::from_ascii("www.example.com.").unwrap();
        let apex = Name::from_ascii("example.com.").unwrap();
        let ttl = 300u32;
        let inception = 1_700_000_000u32;
        let expiration = 1_700_086_400u32;

        // Two A records (unsorted on input) — sorting is part of canonical form.
        let rdatas = [
            Rdata::A(Ipv4Addr::new(192, 0, 2, 2)),
            Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
        ];
        let refs: Vec<&Rdata> = rdatas.iter().collect();
        let params = RrsigParams {
            type_covered: rtype::A,
            key_tag: zsk.key_tag(),
            signer_name: apex.clone(),
            original_ttl: ttl,
            inception,
            expiration,
        };

        let tbs = rrsig_tbs(&params, &owner, class::IN, &refs);
        let rrsig_rdata = sign_rrset(&zsk, &params, &owner, class::IN, &refs).unwrap();

        // (a) Our signature validates over our TBS (ring verifier).
        let sig = &rrsig_rdata[rrsig_rdata.len() - 64..];
        let mut sec1 = vec![0x04u8];
        sec1.extend_from_slice(&zsk.public_key_raw());
        let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &sec1);
        pk.verify(&tbs, sig)
            .expect("our RRSIG must verify against our own public key");

        // (b) Our canonical TBS is byte-identical to hickory's. Build hickory's
        //     SigInput with the same metadata and its TBS over the same RRset.
        let hinput = SigInput {
            type_covered: HRecordType::A,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: 3, // www.example.com.
            original_ttl: ttl,
            sig_expiration: SerialNumber::new(expiration),
            sig_inception: SerialNumber::new(inception),
            key_tag: zsk.key_tag(),
            signer_name: HName::from_ascii("example.com.").unwrap(),
        };
        let howner = HName::from_ascii("www.example.com.").unwrap();
        let hrecords: Vec<HRecord> = [Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(192, 0, 2, 1)]
            .iter()
            .map(|ip| HRecord::from_rdata(howner.clone(), ttl, RData::A(HA(*ip))))
            .collect();
        let htbs = TBS::from_input(&howner, DNSClass::IN, &hinput, hrecords.iter()).unwrap();
        assert_eq!(
            tbs,
            htbs.as_ref(),
            "our RRSIG canonical TBS must match hickory's"
        );
    }

    #[test]
    fn nsec3_hash_and_rdata_match_hickory() {
        use crate::dns::wire::consts::rtype;
        use hickory_proto::dnssec::rdata::NSEC3;
        use hickory_proto::dnssec::Nsec3HashAlgorithm;
        use hickory_proto::rr::{Name as HName, RecordType as HRecordType};
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

        let name = Name::from_ascii("www.example.com.").unwrap();
        let salt: &[u8] = &[]; // RFC 9276: empty salt, 0 iterations.
        let iters = 0u16;

        // (a) Our iterated SHA-1 hash == hickory's.
        let ours = nsec3_hash(&canonical_name_wire(&name), salt, iters);
        let hname = HName::from_ascii("www.example.com.").unwrap();
        let hhash = Nsec3HashAlgorithm::SHA1.hash(salt, &hname, iters).unwrap();
        assert_eq!(&ours[..], hhash.as_ref(), "NSEC3 hash must match hickory");

        // (b) Our NSEC3 RDATA bytes == hickory's NSEC3 RDATA, same fields.
        let next_hash = nsec3_hash(&canonical_name_wire(&Name::from_ascii("a.example.com.").unwrap()), salt, iters);
        let types = [rtype::A, rtype::RRSIG];
        let ours_rdata = nsec3_rdata(0, iters, salt, &next_hash, &types);

        let hnsec3 = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false, // opt-out off
            iters,
            salt.to_vec(),
            next_hash.to_vec(),
            [HRecordType::A, HRecordType::RRSIG].into_iter(),
        );
        let mut hbytes = Vec::new();
        hnsec3.emit(&mut BinEncoder::new(&mut hbytes)).unwrap();
        assert_eq!(ours_rdata, hbytes, "NSEC3 RDATA must match hickory");
    }

    #[test]
    fn type_bitmap_encodes_windows() {
        use crate::dns::wire::consts::rtype;
        // A(1), AAAA(28), RRSIG(46) all in window 0 → one block.
        let bm = type_bitmap(&[rtype::A, rtype::AAAA, rtype::RRSIG]);
        assert_eq!(bm[0], 0, "window 0");
        // length = ceil((46+1)/8) = 6 bytes.
        assert_eq!(bm[1], 6, "bitmap length");
        // bit for A (type 1) = byte 0, mask 0x40.
        assert_eq!(bm[2] & 0x40, 0x40, "A bit set");
    }
}
