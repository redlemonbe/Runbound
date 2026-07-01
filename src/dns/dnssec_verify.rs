// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// Hickory-free DNSSEC validation — Phase 2, increment 1: RRSIG verification.
//
// Verifies one RRSIG over an RRset against a candidate DNSKEY, on `ring`'s vetted
// primitives. Fail-closed: anything unparsed, unsupported, out-of-window or
// cryptographically invalid returns `false` — never a soft pass.
//
// The to-be-signed stream (RFC 4034 §3.1.8.1) reuses the exact canonical form the
// in-house signer produces (proven byte-identical to hickory by the differential
// oracle): the received RRSIG RDATA prefix (everything before the signature) plus
// the owner|type|class|origTTL|rdlen|RDATA records, each RDATA canonicalised
// (RFC 4034 §6.2) and the set sorted by canonical RDATA (§6.3).
//
// NOT YET wired in: the chain of trust (DS↔DNSKEY from the root anchor) and the
// NSEC/NSEC3 denial proofs are later increments; this primitive alone does not
// make an answer "Secure".

// Increment 1: verified and tested, but not yet dispatched to (the validating
// recursor is wired only once the full chain + denial proofs land).
#![allow(dead_code)]

use ring::signature;

use crate::dns::wire::{consts, Decoder, Encoder, Name, Rdata};

// DNSSEC algorithm numbers (IANA DNSSEC Algorithm Numbers registry).
const ALG_RSASHA256: u8 = 8;
const ALG_RSASHA512: u8 = 10;
const ALG_ECDSAP256SHA256: u8 = 13;
const ALG_ECDSAP384SHA384: u8 = 14;
const ALG_ED25519: u8 = 15;

/// Fields parsed out of an RRSIG RDATA (RFC 4034 §3.1).
struct Rrsig<'a> {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    #[allow(dead_code)]
    key_tag: u16,
    /// Signer name (uncompressed; RFC 4034 §3.1.7).
    signer: Name,
    /// RRSIG RDATA bytes before the signature — the leading bytes of signed data.
    prefix: &'a [u8],
    /// The signature octets.
    signature: &'a [u8],
}

fn parse_rrsig(rdata: &[u8]) -> Option<Rrsig<'_>> {
    if rdata.len() < 18 {
        return None;
    }
    let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = rdata[2];
    let labels = rdata[3];
    let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
    let expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
    let inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
    let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);
    // Signer name is uncompressed in RRSIG RDATA.
    let signer = Name::parse(&mut Decoder::new(&rdata[18..])).ok()?;
    let prefix_len = 18 + signer.len();
    if prefix_len > rdata.len() {
        return None;
    }
    Some(Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer,
        prefix: &rdata[..prefix_len],
        signature: &rdata[prefix_len..],
    })
}

/// Build the canonical to-be-signed stream for `rrset` under `sig` (RFC 4034
/// §3.1.8.1): the received RRSIG prefix, then the sorted canonical records.
fn signed_data(sig: &Rrsig, owner: &Name, rclass: u16, rdatas: &[&Rdata]) -> Vec<u8> {
    let mut tbs = sig.prefix.to_vec();

    // Canonical RDATA (names lowercased) for each record, sorted as octet strings.
    let mut canon: Vec<Vec<u8>> = rdatas
        .iter()
        .map(|rd| {
            let mut e = Encoder::uncompressed();
            rd.emit_canonical(&mut e);
            e.into_vec()
        })
        .collect();
    canon.sort();
    canon.dedup();

    let owner_wire = crate::dns::dnssec_sign::canonical_name_wire(owner);
    for rd in &canon {
        tbs.extend_from_slice(&owner_wire);
        tbs.extend_from_slice(&sig.type_covered.to_be_bytes());
        tbs.extend_from_slice(&rclass.to_be_bytes());
        tbs.extend_from_slice(&sig.original_ttl.to_be_bytes());
        tbs.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        tbs.extend_from_slice(rd);
    }
    tbs
}

/// Extract `(n, e)` from an RSA DNSKEY public key (RFC 3110 §2).
fn rsa_components(pubkey: &[u8]) -> Option<(&[u8], &[u8])> {
    if pubkey.is_empty() {
        return None;
    }
    let (exp_len, rest) = if pubkey[0] != 0 {
        (pubkey[0] as usize, &pubkey[1..])
    } else {
        if pubkey.len() < 3 {
            return None;
        }
        (u16::from_be_bytes([pubkey[1], pubkey[2]]) as usize, &pubkey[3..])
    };
    if exp_len == 0 || rest.len() <= exp_len {
        return None;
    }
    let (e, n) = rest.split_at(exp_len);
    Some((n, e))
}

/// RRSIG validity window check (RFC 4034 §3.1.5), using serial-number arithmetic
/// (RFC 1982) so values straddling the 2^32 wrap are compared correctly.
fn within_validity(inception: u32, expiration: u32, now: u32) -> bool {
    // now >= inception  AND  now <= expiration, in serial space.
    let after_inception = now.wrapping_sub(inception) < 0x8000_0000;
    let before_expiration = expiration.wrapping_sub(now) < 0x8000_0000;
    after_inception && before_expiration
}

/// Verify the cryptographic signature with `ring`, dispatching on algorithm.
/// SHA-1 algorithms and anything unknown are rejected (fail-closed).
fn verify_signature(algorithm: u8, dnskey_pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match algorithm {
        ALG_RSASHA256 | ALG_RSASHA512 => {
            let Some((n, e)) = rsa_components(dnskey_pubkey) else {
                return false;
            };
            // Accept 1024-bit RSA: many production DNSSEC zones (Verisign, IANA,
            // ISC, …) still publish 1024-bit ZSKs/KSKs, and a validator that
            // refused them would SERVFAIL those zones. The key length is the zone
            // operator's choice; like unbound/bind we verify what they publish.
            let params = if algorithm == ALG_RSASHA256 {
                &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
            } else {
                &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
            };
            signature::RsaPublicKeyComponents { n, e }
                .verify(params, msg, sig)
                .is_ok()
        }
        ALG_ECDSAP256SHA256 | ALG_ECDSAP384SHA384 => {
            // DNSKEY carries the raw X||Y point; ring wants uncompressed SEC1 (0x04||X||Y).
            let expected = if algorithm == ALG_ECDSAP256SHA256 { 64 } else { 96 };
            if dnskey_pubkey.len() != expected {
                return false;
            }
            let mut point = Vec::with_capacity(expected + 1);
            point.push(0x04);
            point.extend_from_slice(dnskey_pubkey);
            let alg = if algorithm == ALG_ECDSAP256SHA256 {
                &signature::ECDSA_P256_SHA256_FIXED
            } else {
                &signature::ECDSA_P384_SHA384_FIXED
            };
            signature::UnparsedPublicKey::new(alg, &point)
                .verify(msg, sig)
                .is_ok()
        }
        ALG_ED25519 => {
            if dnskey_pubkey.len() != 32 {
                return false;
            }
            signature::UnparsedPublicKey::new(&signature::ED25519, dnskey_pubkey)
                .verify(msg, sig)
                .is_ok()
        }
        _ => false, // SHA-1 (5/7), unknown, private — fail-closed.
    }
}

/// Canonical TBS owner for an RRSIG with `labels` (RFC 4034 §3.1.3, RFC 4035
/// §5.3.2). When `labels` equals the owner's label count the owner is used as-is;
/// when it is smaller the RRset was synthesised from a wildcard and the signed
/// owner is `*.` followed by the `labels` rightmost labels of the queried owner.
/// `labels` greater than the owner's label count is malformed → `None` (reject).
fn rrsig_owner_name(owner: &Name, labels: u8) -> Option<Name> {
    let total = owner.label_count();
    let n = labels as usize;
    if n > total {
        return None;
    }
    if n == total {
        return Some(owner.clone());
    }
    // Wildcard expansion: `*.<n rightmost labels>`. Build the owner from the WIRE
    // bytes (not a presentation round-trip) so labels containing `.`/`\`/non-print
    // octets reconstruct byte-exactly. Walk past the first (total - n) labels, then
    // prepend a single `*` label to the surviving suffix (which keeps its NUL root).
    let w = owner.wire();
    let mut i = 0usize;
    for _ in 0..(total - n) {
        i += 1 + w[i] as usize;
    }
    let mut wire = Vec::with_capacity(2 + (w.len() - i));
    wire.push(1); // label length
    wire.push(b'*');
    wire.extend_from_slice(&w[i..]);
    Name::parse(&mut Decoder::new(&wire)).ok()
}

/// Verify one RRSIG (`rrsig_rdata`) over the RRset (`owner`/`rclass`/`rdatas`)
/// using the candidate DNSKEY (`dnskey_rdata`), at unix time `now`.
///
/// Returns `true` only when: the RRSIG parses, its algorithm matches the key,
/// `now` is inside the validity window, the RRSIG covers the RRset's type, the
/// signer is at or above the owner, and the signature verifies. Fail-closed.
pub fn verify_rrsig(
    owner: &Name,
    rclass: u16,
    rrset_type: u16,
    rdatas: &[&Rdata],
    rrsig_rdata: &[u8],
    dnskey_rdata: &[u8],
    now: u32,
) -> bool {
    let Some(sig) = parse_rrsig(rrsig_rdata) else {
        return false;
    };
    if sig.type_covered != rrset_type {
        return false;
    }
    if !within_validity(sig.inception, sig.expiration, now) {
        return false;
    }
    // The signer (key owner / zone apex) must be at or above the RRset owner.
    if !owner.is_in_zone(&sig.signer) {
        return false;
    }
    // DNSKEY RDATA: flags(2) | protocol(1) | algorithm(1) | public key.
    if dnskey_rdata.len() < 4 || dnskey_rdata[3] != sig.algorithm {
        return false;
    }
    let dnskey_pubkey = &dnskey_rdata[4..];
    // RFC 4035 §5.3.2: a wildcard-expanded RRset (RRSIG.labels < owner labels) was
    // signed under `*.<suffix>`, not the queried name — reconstruct the TBS owner
    // accordingly. `labels` exceeding the owner's label count is malformed → reject.
    let Some(tbs_owner) = rrsig_owner_name(owner, sig.labels) else {
        return false;
    };
    let msg = signed_data(&sig, &tbs_owner, rclass, rdatas);
    verify_signature(sig.algorithm, dnskey_pubkey, &msg, &sig.signature)
}

// ── Phase 2, increment 2: DS ↔ DNSKEY chain of trust ─────────────────────────

/// DS digest types we accept. SHA-256 (RFC 4509) and SHA-384 (RFC 6605); the
/// deprecated SHA-1 (type 1) is rejected — an attacker must not be able to
/// downgrade a delegation to a forgeable digest.
const DS_DIGEST_SHA256: u8 = 2;
const DS_DIGEST_SHA384: u8 = 4;

/// A delegation-signer commitment: the parent's hash of a child DNSKEY
/// (RFC 4034 §5.1). Borrows its digest so both the hardcoded root anchor
/// (`'static`) and DS parsed from the wire share one type.
#[derive(Clone, Copy)]
pub struct Ds<'a> {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: &'a [u8],
}

/// The IANA root trust anchors (DS of the root KSKs) — the one piece of state
/// that MUST come out of band, never from the network. Published in
/// <https://data.iana.org/root-anchors/root-anchors.xml>.
///   - KSK-2017: key tag 20326 (cross-checkable against the well-known digest).
///   - KSK-2024: key tag 38696 (current KSK).
/// Both are algorithm 8 (RSA/SHA-256), digest type 2 (SHA-256).
const ROOT_KSK_2017: [u8; 32] =
    hex32("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D");
const ROOT_KSK_2024: [u8; 32] =
    hex32("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16");

pub const ROOT_ANCHORS: &[Ds<'static>] = &[
    Ds { key_tag: 20326, algorithm: 8, digest_type: DS_DIGEST_SHA256, digest: &ROOT_KSK_2017 },
    Ds { key_tag: 38696, algorithm: 8, digest_type: DS_DIGEST_SHA256, digest: &ROOT_KSK_2024 },
];

/// Decode a 64-char hex string to 32 bytes at compile time, so the anchors read
/// as the published hex without a runtime hex-decode dependency.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "trust anchor digest must be 64 hex chars");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(b[2 * i]) << 4) | hex_nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex digit in trust anchor"),
    }
}

/// Compute the DS digest of a DNSKEY (RFC 4034 §5.1.4): `digest(owner_canonical
/// || DNSKEY_RDATA)`. Returns `None` for unsupported (e.g. SHA-1) digest types.
fn compute_ds_digest(owner: &Name, dnskey_rdata: &[u8], digest_type: u8) -> Option<Vec<u8>> {
    let alg = match digest_type {
        DS_DIGEST_SHA256 => &ring::digest::SHA256,
        DS_DIGEST_SHA384 => &ring::digest::SHA384,
        _ => return None,
    };
    let mut input = crate::dns::dnssec_sign::canonical_name_wire(owner);
    input.extend_from_slice(dnskey_rdata);
    Some(ring::digest::digest(alg, &input).as_ref().to_vec())
}

/// Does this DNSKEY match the DS commitment (key tag + algorithm + digest)?
fn dnskey_matches_ds(owner: &Name, dnskey_rdata: &[u8], ds: &Ds) -> bool {
    if dnskey_rdata.len() < 4 || dnskey_rdata[3] != ds.algorithm {
        return false;
    }
    if crate::dns::dnssec_sign::key_tag(dnskey_rdata) != ds.key_tag {
        return false;
    }
    // The DS digest is public data (published in the parent zone), so a plain
    // comparison is fine — there is no secret whose timing could leak.
    match compute_ds_digest(owner, dnskey_rdata, ds.digest_type) {
        Some(d) => d.as_slice() == ds.digest,
        None => false,
    }
}

/// Validate a zone's DNSKEY RRset against a set of trusted DS records (the
/// secure entry point): a DNSKEY must match one DS, and an RRSIG over the whole
/// DNSKEY RRset must verify under that DS-matched key. On success the full
/// DNSKEY RRset is returned as the zone's now-trusted keys (KSK + ZSKs).
///
/// Fail-closed: no DS match, or no self-signature under the matched key → `None`.
pub fn validate_dnskey_rrset<'k>(
    owner: &Name,
    dnskeys: &[&'k [u8]],
    rrsigs: &[&[u8]],
    trusted_ds: &[Ds],
    now: u32,
) -> Option<Vec<&'k [u8]>> {
    let rdatas: Vec<Rdata> = dnskeys
        .iter()
        .map(|d| Rdata::Unknown { rtype: consts::rtype::DNSKEY, data: d.to_vec() })
        .collect();
    let refs: Vec<&Rdata> = rdatas.iter().collect();

    for &key in dnskeys {
        // 1. Is this key anchored by a trusted DS?
        if !trusted_ds.iter().any(|ds| dnskey_matches_ds(owner, key, ds)) {
            continue;
        }
        // 2. Does an RRSIG over the DNSKEY RRset verify under this key?
        for &sig in rrsigs {
            if verify_rrsig(owner, consts::class::IN, consts::rtype::DNSKEY, &refs, sig, key, now) {
                return Some(dnskeys.to_vec());
            }
        }
    }
    None
}

/// The signer name (zone apex, RFC 4034 §3.1.7) carried by an RRSIG RDATA — used
/// to determine which zone's keys must validate the RRset it covers.
pub fn rrsig_signer(rdata: &[u8]) -> Option<Name> {
    parse_rrsig(rdata).map(|s| s.signer)
}

/// The type covered by an RRSIG RDATA (RFC 4034 §3.1.1).
pub fn rrsig_type_covered(rdata: &[u8]) -> Option<u16> {
    (rdata.len() >= 2).then(|| u16::from_be_bytes([rdata[0], rdata[1]]))
}

/// The `labels` field of an RRSIG RDATA (RFC 4034 §3.1.3) — the number of labels
/// in the original (pre-wildcard-expansion) owner name.
pub fn rrsig_labels(rdata: &[u8]) -> Option<u8> {
    (rdata.len() >= 4).then(|| rdata[3])
}

/// Parse a DS RDATA (RFC 4034 §5.1): key tag | algorithm | digest type | digest.
pub fn parse_ds(rdata: &[u8]) -> Option<Ds<'_>> {
    if rdata.len() < 5 {
        return None;
    }
    Some(Ds {
        key_tag: u16::from_be_bytes([rdata[0], rdata[1]]),
        algorithm: rdata[2],
        digest_type: rdata[3],
        digest: &rdata[4..],
    })
}

/// Verify an RRset under a set of already-trusted DNSKEYs: at least one RRSIG
/// over the RRset must verify under at least one trusted key. Fail-closed.
pub fn validate_rrset(
    owner: &Name,
    rclass: u16,
    rtype: u16,
    rdatas: &[&Rdata],
    rrsigs: &[&[u8]],
    trusted_keys: &[&[u8]],
    now: u32,
) -> bool {
    validate_rrset_wc(owner, rclass, rtype, rdatas, rrsigs, trusted_keys, now).is_some()
}

/// Like [`validate_rrset`], but also reports whether the signature that validated
/// was a wildcard expansion (RRSIG.labels < the owner's label count). `None` = no
/// valid signature; `Some(false)` = ordinary validation; `Some(true)` = validated
/// via a wildcard — the caller MUST then require a no-exact-match denial proof
/// (RFC 4035 §5.3.4), else a wildcard RRSIG could be replayed onto an existing name.
pub fn validate_rrset_wc(
    owner: &Name,
    rclass: u16,
    rtype: u16,
    rdatas: &[&Rdata],
    rrsigs: &[&[u8]],
    trusted_keys: &[&[u8]],
    now: u32,
) -> Option<bool> {
    for sig in rrsigs {
        for key in trusted_keys {
            if verify_rrsig(owner, rclass, rtype, rdatas, sig, key, now) {
                let wildcard = rrsig_labels(sig)
                    .map(|l| (l as usize) < owner.label_count())
                    .unwrap_or(false);
                return Some(wildcard);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::dnssec_sign::{key_tag, sign_rrset, RrsigParams, SigningKey};
    use std::net::Ipv4Addr;

    // DV-04: RRSIG.labels drives the canonical TBS owner (RFC 4035 §5.3.2).
    #[test]
    fn rrsig_owner_name_reconstructs_wildcard() {
        let owner = Name::from_ascii("foo.example.com.").unwrap();
        // labels == owner labels → owner verbatim.
        assert_eq!(rrsig_owner_name(&owner, 3).unwrap().to_ascii(), "foo.example.com.");
        // labels < owner labels → wildcard at the closest encloser.
        assert_eq!(rrsig_owner_name(&owner, 2).unwrap().to_ascii(), "*.example.com.");
        let deep = Name::from_ascii("a.b.example.com.").unwrap();
        assert_eq!(rrsig_owner_name(&deep, 2).unwrap().to_ascii(), "*.example.com.");
        // labels > owner labels → malformed → reject (fail-closed).
        assert!(rrsig_owner_name(&owner, 4).is_none());
    }

    // Round-trip: sign an A RRset with our ECDSA P-256 signer (oracle-proven vs
    // hickory), then verify it here. Proves the canonical TBS + ECDSA path.
    #[test]
    fn ecdsa_roundtrip_verifies() {
        let key = SigningKey::generate(false).unwrap();
        let owner = Name::from_ascii("host.example.com.").unwrap();
        let rdatas = [
            Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
            Rdata::A(Ipv4Addr::new(192, 0, 2, 2)),
        ];
        let refs: Vec<&Rdata> = rdatas.iter().collect();
        let params = RrsigParams {
            type_covered: consts::rtype::A,
            key_tag: key_tag(&key.dnskey_rdata()),
            signer_name: Name::from_ascii("example.com.").unwrap(),
            original_ttl: 3600,
            inception: 1_000_000,
            expiration: 3_000_000,
        };
        let rrsig_rdata = sign_rrset(&key, &params, &owner, consts::class::IN, &refs).unwrap();
        let dnskey = key.dnskey_rdata();

        // Valid: in-window, correct key.
        assert!(verify_rrsig(
            &owner, consts::class::IN, consts::rtype::A, &refs, &rrsig_rdata, &dnskey, 2_000_000
        ));
        // Fail-closed: tampered RDATA.
        let tampered = [Rdata::A(Ipv4Addr::new(192, 0, 2, 99)), Rdata::A(Ipv4Addr::new(192, 0, 2, 2))];
        let trefs: Vec<&Rdata> = tampered.iter().collect();
        assert!(!verify_rrsig(
            &owner, consts::class::IN, consts::rtype::A, &trefs, &rrsig_rdata, &dnskey, 2_000_000
        ));
        // Fail-closed: outside the validity window (before inception).
        assert!(!verify_rrsig(
            &owner, consts::class::IN, consts::rtype::A, &refs, &rrsig_rdata, &dnskey, 999
        ));
        // Fail-closed: wrong type_covered claim.
        assert!(!verify_rrsig(
            &owner, consts::class::IN, consts::rtype::AAAA, &refs, &rrsig_rdata, &dnskey, 2_000_000
        ));
    }

    #[test]
    fn rsa_components_parses_short_and_long_exponent() {
        // 1-byte exponent length form.
        let mut k = vec![3, 1, 0, 1]; // explen=3, e=010001, n=...
        k.extend_from_slice(&[0xAA; 256]);
        let (n, e) = rsa_components(&k).unwrap();
        assert_eq!(e, &[1, 0, 1]);
        assert_eq!(n.len(), 256);
        // 3-byte exponent length form (leading 0).
        let mut k2 = vec![0, 0, 3, 1, 0, 1];
        k2.extend_from_slice(&[0xBB; 256]);
        let (n2, e2) = rsa_components(&k2).unwrap();
        assert_eq!(e2, &[1, 0, 1]);
        assert_eq!(n2.len(), 256);
    }

    // Live: fetch the root DNSKEY RRset (DO=1) from a root server and verify the
    // KSK self-signature — a real RSA/SHA-256 (alg 8) signature over real data,
    // i.e. the actual DNSSEC trust anchor. Run with:
    //   cargo test -- --ignored verify_root_ksk_rsa
    #[tokio::test]
    #[ignore]
    async fn verify_root_ksk_rsa() {
        use crate::dns::wire;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Build a DO=1 query for `. DNSKEY` (header RD=0, one question, one OPT RR).
        let mut idb = [0u8; 2];
        let _ = getrandom::fill(&mut idb);
        let mut enc = wire::Encoder::uncompressed();
        wire::Header {
            id: u16::from_be_bytes(idb),
            flags: 0,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 1,
        }
        .emit(&mut enc);
        wire::Question::new(Name::root(), consts::rtype::DNSKEY).emit(&mut enc);
        // OPT pseudo-RR: name=root, type=OPT, class=UDP payload, ttl=DO flag, rdlen=0.
        enc.u8(0);
        enc.u16(consts::rtype::OPT);
        enc.u16(1232);
        enc.u32(0x0000_8000); // DO bit set
        enc.u16(0);
        let q = enc.into_vec();

        // TCP to a.root-servers.net for a complete (untruncated) DNSKEY RRset.
        let mut stream = tokio::net::TcpStream::connect("198.41.0.4:53").await.unwrap();
        let len = (q.len() as u16).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(&q).await.unwrap();
        let mut lb = [0u8; 2];
        stream.read_exact(&mut lb).await.unwrap();
        let mut resp = vec![0u8; u16::from_be_bytes(lb) as usize];
        stream.read_exact(&mut resp).await.unwrap();

        let msg = wire::Message::parse(&resp).expect("parse root DNSKEY response");
        let dnskeys: Vec<&Rdata> = msg
            .answers
            .iter()
            .filter(|r| r.rtype == consts::rtype::DNSKEY)
            .map(|r| &r.rdata)
            .collect();
        let rrsigs: Vec<&[u8]> = msg
            .answers
            .iter()
            .filter(|r| r.rtype == consts::rtype::RRSIG)
            .filter_map(|r| match &r.rdata {
                Rdata::Unknown { data, .. } => Some(data.as_slice()),
                _ => None,
            })
            .collect();
        assert!(!dnskeys.is_empty(), "no DNSKEY in root answer");
        assert!(!rrsigs.is_empty(), "no RRSIG in root answer");

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

        // At least one RRSIG must validate over the DNSKEY RRset under some key
        // (the KSK self-signs the RRset; the KSK is RSA/SHA-256).
        let mut verified = false;
        for sig in &rrsigs {
            for key in &dnskeys {
                let Rdata::Unknown { data: key_rdata, .. } = key else { continue };
                if verify_rrsig(
                    &Name::root(),
                    consts::class::IN,
                    consts::rtype::DNSKEY,
                    &dnskeys,
                    sig,
                    key_rdata,
                    now,
                ) {
                    verified = true;
                }
            }
        }
        assert!(verified, "root DNSKEY RRset did not validate under any key (RSA path)");
        eprintln!(
            "LIVE root DNSKEY: {} keys, {} RRSIGs — self-signature VALIDATED (RSA)",
            dnskeys.len(),
            rrsigs.len()
        );
    }

    // Fetch the root DNSKEY RRset (DNSKEY rdatas, RRSIG rdatas) over TCP/DO=1.
    async fn fetch_root_dnskey() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        use crate::dns::wire;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut idb = [0u8; 2];
        let _ = getrandom::fill(&mut idb);
        let mut enc = wire::Encoder::uncompressed();
        wire::Header { id: u16::from_be_bytes(idb), flags: 0, qdcount: 1, ancount: 0, nscount: 0, arcount: 1 }
            .emit(&mut enc);
        wire::Question::new(Name::root(), consts::rtype::DNSKEY).emit(&mut enc);
        enc.u8(0);
        enc.u16(consts::rtype::OPT);
        enc.u16(1232);
        enc.u32(0x0000_8000);
        enc.u16(0);
        let q = enc.into_vec();
        let mut s = tokio::net::TcpStream::connect("198.41.0.4:53").await.unwrap();
        s.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        s.write_all(&q).await.unwrap();
        let mut lb = [0u8; 2];
        s.read_exact(&mut lb).await.unwrap();
        let mut resp = vec![0u8; u16::from_be_bytes(lb) as usize];
        s.read_exact(&mut resp).await.unwrap();
        let msg = wire::Message::parse(&resp).expect("parse root DNSKEY");
        let keys = msg.answers.iter().filter(|r| r.rtype == consts::rtype::DNSKEY)
            .filter_map(|r| match &r.rdata { Rdata::Unknown { data, .. } => Some(data.clone()), _ => None }).collect();
        let sigs = msg.answers.iter().filter(|r| r.rtype == consts::rtype::RRSIG)
            .filter_map(|r| match &r.rdata { Rdata::Unknown { data, .. } => Some(data.clone()), _ => None }).collect();
        (keys, sigs)
    }

    // Live: validate the real root DNSKEY RRset against the HARDCODED anchor.
    // This exercises increment 2 end to end (DS digest match + RRSIG over the
    // DNSKEY set under the DS-matched key) and cross-checks the anchor digests.
    //   cargo test -- --ignored validate_root_dnskey_against_anchor
    #[tokio::test]
    #[ignore]
    async fn validate_root_dnskey_against_anchor() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let (keys, sigs) = fetch_root_dnskey().await;
        for k in &keys {
            // SEP (KSK) bit is the LSB of the 16-bit flags field.
            if k.len() >= 2 && (u16::from_be_bytes([k[0], k[1]]) & 0x0001) != 0 {
                let tag = key_tag(k);
                let ds = compute_ds_digest(&Name::root(), k, DS_DIGEST_SHA256).unwrap();
                let hexd: String = ds.iter().map(|b| format!("{b:02X}")).collect();
                eprintln!("ROOT KSK tag={tag} DS-SHA256={hexd}");
            }
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let kr: Vec<&[u8]> = keys.iter().map(|v| v.as_slice()).collect();
        let sr: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
        let validated = validate_dnskey_rrset(&Name::root(), &kr, &sr, ROOT_ANCHORS, now);
        assert!(validated.is_some(), "root DNSKEY did NOT validate against the hardcoded anchor");
        eprintln!("ROOT DNSKEY validated against hardcoded anchor: {} trusted keys", validated.unwrap().len());
    }

    // Fetch (name, qtype) with DO=1 from a validating-aware resolver over TCP,
    // returning the parsed message. Used only to feed real records to the chain
    // validator under test — the production resolver fetches via its own descent.
    async fn fetch_do(qname: &Name, qtype: u16) -> crate::dns::wire::Message {
        use crate::dns::wire;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut idb = [0u8; 2];
        let _ = getrandom::fill(&mut idb);
        let mut enc = wire::Encoder::uncompressed();
        // RD + CD: CD (checking disabled) makes the resolver hand back the raw
        // records — including deliberately-bogus ones — so WE do the validation.
        wire::Header { id: u16::from_be_bytes(idb), flags: 0x0110, qdcount: 1, ancount: 0, nscount: 0, arcount: 1 }
            .emit(&mut enc);
        wire::Question::new(qname.clone(), qtype).emit(&mut enc);
        enc.u8(0);
        enc.u16(consts::rtype::OPT);
        enc.u16(1232);
        enc.u32(0x0000_8000);
        enc.u16(0);
        let q = enc.into_vec();
        let mut s = tokio::net::TcpStream::connect("8.8.8.8:53").await.unwrap();
        s.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        s.write_all(&q).await.unwrap();
        let mut lb = [0u8; 2];
        s.read_exact(&mut lb).await.unwrap();
        let mut resp = vec![0u8; u16::from_be_bytes(lb) as usize];
        s.read_exact(&mut resp).await.unwrap();
        wire::Message::parse(&resp).expect("parse DO response")
    }

    // Owned RDATA of `rtype` in the answer, plus the RRSIG rdatas covering it.
    fn records_and_sigs(msg: &crate::dns::wire::Message, rtype: u16) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let rdatas = msg.answers.iter().filter(|r| r.rtype == rtype)
            .map(|r| { let mut e = crate::dns::wire::Encoder::uncompressed(); r.rdata.emit(&mut e); e.into_vec() })
            .collect();
        let sigs = msg.answers.iter()
            .filter(|r| r.rtype == consts::rtype::RRSIG)
            .filter_map(|r| match &r.rdata { Rdata::Unknown { data, .. } => Some(data.clone()), _ => None })
            .filter(|d| d.len() >= 2 && u16::from_be_bytes([d[0], d[1]]) == rtype)
            .collect();
        (rdatas, sigs)
    }

    fn as_unknown(rdatas: &[Vec<u8>], rtype: u16) -> Vec<Rdata> {
        rdatas.iter().map(|d| Rdata::Unknown { rtype, data: d.clone() }).collect()
    }

    // Live: validate the full chain of trust root -> com -> cloudflare.com and a
    // signed A RRset, from the hardcoded anchor. Proves Secure end to end.
    //   cargo test -- --ignored validate_chain_root_to_cloudflare
    #[tokio::test]
    #[ignore]
    async fn validate_chain_root_to_cloudflare() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let root = Name::root();
        let com = Name::from_ascii("com.").unwrap();
        let cf = Name::from_ascii("cloudflare.com.").unwrap();

        // 1. Root DNSKEY validated against the hardcoded anchor.
        let m = fetch_do(&root, consts::rtype::DNSKEY).await;
        let (rk, rs) = records_and_sigs(&m, consts::rtype::DNSKEY);
        let rk_refs: Vec<&[u8]> = rk.iter().map(|v| v.as_slice()).collect();
        let rs_refs: Vec<&[u8]> = rs.iter().map(|v| v.as_slice()).collect();
        let root_keys = validate_dnskey_rrset(&root, &rk_refs, &rs_refs, ROOT_ANCHORS, now)
            .expect("root DNSKEY vs anchor");

        // helper closure: validate child DNSKEY given parent's trusted keys.
        async fn descend(child: &Name, parent: &Name, parent_keys: &[&[u8]], now: u32) -> Vec<Vec<u8>> {
            // DS of child lives in the parent zone, signed by the parent.
            let dm = fetch_do(child, consts::rtype::DS).await;
            let (ds_rd, ds_sig) = records_and_sigs(&dm, consts::rtype::DS);
            let ds_un = as_unknown(&ds_rd, consts::rtype::DS);
            let ds_refs: Vec<&Rdata> = ds_un.iter().collect();
            let dssig_refs: Vec<&[u8]> = ds_sig.iter().map(|v| v.as_slice()).collect();
            assert!(
                validate_rrset(child, consts::class::IN, consts::rtype::DS, &ds_refs, &dssig_refs, parent_keys, now),
                "DS of {} not signed by {}", child.to_ascii(), parent.to_ascii()
            );
            let ds_list: Vec<Ds> = ds_rd.iter().filter_map(|r| parse_ds(r)).collect();
            // Child DNSKEY validated against the (now trusted) DS.
            let km = fetch_do(child, consts::rtype::DNSKEY).await;
            let (ck, cs) = records_and_sigs(&km, consts::rtype::DNSKEY);
            let ck_refs: Vec<&[u8]> = ck.iter().map(|v| v.as_slice()).collect();
            let cs_refs: Vec<&[u8]> = cs.iter().map(|v| v.as_slice()).collect();
            validate_dnskey_rrset(child, &ck_refs, &cs_refs, &ds_list, now)
                .unwrap_or_else(|| panic!("DNSKEY of {} vs DS", child.to_ascii()))
                .iter().map(|s| s.to_vec()).collect()
        }

        let root_refs: Vec<&[u8]> = root_keys.to_vec();
        let com_keys = descend(&com, &root, &root_refs, now).await;
        let com_refs: Vec<&[u8]> = com_keys.iter().map(|v| v.as_slice()).collect();
        let cf_keys = descend(&cf, &com, &com_refs, now).await;
        let cf_refs: Vec<&[u8]> = cf_keys.iter().map(|v| v.as_slice()).collect();

        // Final: a signed A RRset for cloudflare.com under its validated keys.
        let am = fetch_do(&cf, consts::rtype::A).await;
        let a_rdatas: Vec<&Rdata> = am.answers.iter().filter(|r| r.rtype == consts::rtype::A).map(|r| &r.rdata).collect();
        let (_a, a_sigs) = records_and_sigs(&am, consts::rtype::A);
        let asig_refs: Vec<&[u8]> = a_sigs.iter().map(|v| v.as_slice()).collect();
        assert!(!a_rdatas.is_empty(), "no A records for cloudflare.com");
        assert!(
            validate_rrset(&cf, consts::class::IN, consts::rtype::A, &a_rdatas, &asig_refs, &cf_refs, now),
            "cloudflare.com A RRset did not validate under its keys"
        );
        eprintln!("CHAIN root->com->cloudflare.com + A RRset: SECURE ({} cf keys)", cf_keys.len());
    }

    // Live fail-closed: dnssec-failed.org is deliberately misconfigured (its keys
    // do not match the DS in .org / its RRSIGs are bad). The validator MUST refuse
    // to call it Secure — anything else is the exact vulnerability we are avoiding.
    //   cargo test -- --ignored bogus_zone_fails_closed
    #[tokio::test]
    #[ignore]
    async fn bogus_zone_fails_closed() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let bad = Name::from_ascii("dnssec-failed.org.").unwrap();

        // The bad zone's DS (in .org) and its DNSKEY.
        let dm = fetch_do(&bad, consts::rtype::DS).await;
        let (ds_rd, _ds_sig) = records_and_sigs(&dm, consts::rtype::DS);
        let ds_list: Vec<Ds> = ds_rd.iter().filter_map(|r| parse_ds(r)).collect();
        let km = fetch_do(&bad, consts::rtype::DNSKEY).await;
        let (ck, cs) = records_and_sigs(&km, consts::rtype::DNSKEY);
        let ck_refs: Vec<&[u8]> = ck.iter().map(|v| v.as_slice()).collect();
        let cs_refs: Vec<&[u8]> = cs.iter().map(|v| v.as_slice()).collect();

        // Whole positive chain to a validated A must NOT succeed.
        let a_secure = match validate_dnskey_rrset(&bad, &ck_refs, &cs_refs, &ds_list, now) {
            None => false, // DNSKEY does not chain to the DS — already Bogus.
            Some(keys) => {
                let am = fetch_do(&bad, consts::rtype::A).await;
                let a_rdatas: Vec<&Rdata> =
                    am.answers.iter().filter(|r| r.rtype == consts::rtype::A).map(|r| &r.rdata).collect();
                let (_a, a_sigs) = records_and_sigs(&am, consts::rtype::A);
                let asig: Vec<&[u8]> = a_sigs.iter().map(|v| v.as_slice()).collect();
                let kr: Vec<&[u8]> = keys.to_vec();
                validate_rrset(&bad, consts::class::IN, consts::rtype::A, &a_rdatas, &asig, &kr, now)
            }
        };
        assert!(!a_secure, "BOGUS zone validated as SECURE — DNSSEC validation is broken");
        eprintln!("BOGUS dnssec-failed.org correctly REJECTED (fail-closed)");
    }

    #[test]
    fn hex32_decodes_known_anchor() {
        // Cross-check the const decoder against the well-known KSK-2017 digest.
        assert_eq!(
            ROOT_KSK_2017[..4],
            [0xE0, 0x6D, 0x44, 0xB8]
        );
        assert_eq!(ROOT_KSK_2017.len(), 32);
    }

    #[test]
    fn validity_window_serial_arithmetic() {
        assert!(within_validity(100, 200, 150));
        assert!(!within_validity(100, 200, 50));
        assert!(!within_validity(100, 200, 250));
        // Wrap-around window (inception near 2^32, expiration just after wrap).
        assert!(within_validity(0xFFFF_FF00, 0x0000_0100, 0xFFFF_FFF0));
        assert!(within_validity(0xFFFF_FF00, 0x0000_0100, 0x0000_0050));
    }
}
