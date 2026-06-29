// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// Hickory-free DNSSEC denial of existence — Phase 2, increment 3a: NSEC.
//
// Given NSEC records that have ALREADY been RRSIG-validated under the zone's
// trusted DNSKEYs (incr. 1 + 2), these primitives decide what they prove:
//   - NODATA: the name exists but the queried type does not;
//   - name non-existence: the name is not covered by any owner→next interval.
// The closest-encloser / wildcard NXDOMAIN composition and NSEC3 are the next
// sub-increments. Everything here is pure logic — fail-closed by returning false.

#![allow(dead_code)]

use crate::dns::wire::{consts, Decoder, Name};

/// Is `rtype` present in an NSEC/NSEC3 type bitmap (RFC 4034 §4.1.2)? The bitmap
/// is a sequence of `window(1) | length(1) | bits(length)` blocks.
pub fn type_in_bitmap(mut bm: &[u8], rtype: u16) -> bool {
    let window = (rtype >> 8) as u8;
    let offset = (rtype & 0xff) as usize;
    while bm.len() >= 2 {
        let w = bm[0];
        let len = bm[1] as usize;
        if bm.len() < 2 + len {
            return false; // malformed → fail-closed
        }
        if w == window {
            let byte = offset / 8;
            return byte < len && (bm[2 + byte] & (0x80 >> (offset % 8))) != 0;
        }
        bm = &bm[2 + len..];
    }
    false
}

/// Split NSEC RDATA into its next owner name and the type bitmap (RFC 4034 §4.1).
/// The next name is uncompressed.
pub fn parse_nsec(rdata: &[u8]) -> Option<(Name, &[u8])> {
    let next = Name::parse(&mut Decoder::new(rdata)).ok()?;
    let nlen = next.len();
    if nlen > rdata.len() {
        return None;
    }
    Some((next, &rdata[nlen..]))
}

/// Does the NSEC interval `(owner, next]`'s open range `owner < name < next`
/// cover `name` (RFC 4034 §6.1 canonical order)? Handles the apex wrap, where
/// `next <= owner` and the NSEC covers everything after `owner` or before `next`.
pub fn nsec_covers(owner: &Name, next: &Name, name: &Name) -> bool {
    use std::cmp::Ordering::Less;
    if owner.canonical_cmp(next) == Less {
        owner.canonical_cmp(name) == Less && name.canonical_cmp(next) == Less
    } else {
        // Last NSEC of the zone wraps around the apex.
        owner.canonical_cmp(name) == Less || name.canonical_cmp(next) == Less
    }
}

/// Does an NSEC at `owner` with `bitmap` prove NODATA for `qname`/`qtype`?
/// (RFC 4035 §5.4): the owner is exactly `qname`, the type is absent, and — so the
/// answer is genuinely empty rather than a CNAME — CNAME is absent too (unless the
/// query itself was for CNAME).
pub fn nsec_proves_nodata(owner: &Name, bitmap: &[u8], qname: &Name, qtype: u16) -> bool {
    owner.eq_ignore_ascii_case(qname)
        && !type_in_bitmap(bitmap, qtype)
        && (qtype == consts::rtype::CNAME || !type_in_bitmap(bitmap, consts::rtype::CNAME))
}

/// One validated NSEC record (owner + parsed RDATA), for the proof helpers.
pub struct Nsec<'a> {
    pub owner: Name,
    pub next: Name,
    pub bitmap: &'a [u8],
}

impl<'a> Nsec<'a> {
    pub fn parse(owner: Name, rdata: &'a [u8]) -> Option<Self> {
        let (next, bitmap) = parse_nsec(rdata)?;
        Some(Nsec { owner, next, bitmap })
    }
}

/// Do these NSECs prove `qname` does not exist (some interval covers it)?
/// This is the name-non-existence half of an NXDOMAIN proof; the wildcard half
/// is composed by the caller (next sub-increment).
pub fn nsec_proves_nonexistence(nsecs: &[Nsec], qname: &Name) -> bool {
    nsecs
        .iter()
        .any(|n| nsec_covers(&n.owner, &n.next, qname))
}

// ── NSEC3 (RFC 5155): hashed denial of existence ─────────────────────────────

/// Decode a base32hex label (RFC 4648 §7, no padding, case-insensitive) — the
/// form an NSEC3 owner's first label takes. Returns `None` on a non-base32hex byte.
pub fn base32hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for &c in input {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'V' => c - b'A' + 10,
            b'a'..=b'v' => c - b'a' + 10,
            _ => return None,
        } as u64;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Encode bytes as a base32hex label (uppercase, no padding).
pub fn base32hex_encode(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = Vec::with_capacity(input.len() * 8 / 5 + 1);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for &b in input {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1f) as usize]);
    }
    out
}

/// A parsed NSEC3 record (RFC 5155 §3): its params, owner hash (from the owner
/// name's first label), next hash, and type bitmap.
pub struct Nsec3<'a> {
    pub hash_alg: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: &'a [u8],
    pub owner_hash: Vec<u8>,
    pub next_hash: &'a [u8],
    pub bitmap: &'a [u8],
}

impl<'a> Nsec3<'a> {
    pub fn parse(owner: &Name, rdata: &'a [u8]) -> Option<Self> {
        if rdata.len() < 5 {
            return None;
        }
        let hash_alg = rdata[0];
        let flags = rdata[1];
        let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
        let salt_len = rdata[4] as usize;
        let mut p = 5usize;
        if rdata.len() < p + salt_len + 1 {
            return None;
        }
        let salt = &rdata[p..p + salt_len];
        p += salt_len;
        let hash_len = rdata[p] as usize;
        p += 1;
        if rdata.len() < p + hash_len {
            return None;
        }
        let next_hash = &rdata[p..p + hash_len];
        p += hash_len;
        let bitmap = &rdata[p..];
        // Owner hash = base32hex-decode of the owner's first label.
        let first = owner.labels_lower().into_iter().next()?;
        let owner_hash = base32hex_decode(&first)?;
        Some(Nsec3 { hash_alg, flags, iterations, salt, owner_hash, next_hash, bitmap })
    }

    /// Opt-out (RFC 5155 §6): an unsigned delegation may be omitted in this span.
    pub fn opt_out(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Hash `name` under this NSEC3's params (only SHA-1, hash alg 1, is defined).
    fn hash(&self, name: &Name) -> Option<[u8; 20]> {
        if self.hash_alg != 1 {
            return None;
        }
        let canon = crate::dns::dnssec_sign::canonical_name_wire(name);
        Some(crate::dns::dnssec_sign::nsec3_hash(&canon, self.salt, self.iterations))
    }

    /// MATCH: this NSEC3's owner hash equals hash(name) — the name's hash exists.
    pub fn matches(&self, name: &Name) -> bool {
        matches!(self.hash(name), Some(h) if self.owner_hash == h)
    }

    /// COVER: hash(name) falls in the open interval (owner_hash, next_hash),
    /// with the zone-apex wrap — the name's hash does not exist.
    pub fn covers(&self, name: &Name) -> bool {
        let Some(h) = self.hash(name) else { return false };
        cover_hash(&self.owner_hash, self.next_hash, &h)
    }
}

/// Hash-space interval test (octet order), handling the last-NSEC3 wrap.
fn cover_hash(owner: &[u8], next: &[u8], h: &[u8]) -> bool {
    if owner < next {
        owner < h && h < next
    } else {
        owner < h || h < next
    }
}

/// Does a matching NSEC3 prove NODATA for `qname`/`qtype`? (RFC 5155 §8.5):
/// an NSEC3 matches the qname and the type — and CNAME — are absent.
pub fn nsec3_proves_nodata(nsec3s: &[Nsec3], qname: &Name, qtype: u16) -> bool {
    nsec3s.iter().any(|n3| {
        n3.matches(qname)
            && !type_in_bitmap(n3.bitmap, qtype)
            && (qtype == consts::rtype::CNAME || !type_in_bitmap(n3.bitmap, consts::rtype::CNAME))
    })
}

/// `*.name` — the wildcard at `name` (prepend a `*` label).
fn wildcard_of(name: &Name) -> Option<Name> {
    Name::from_ascii(&format!("*.{}", name.to_ascii())).ok()
}

/// NSEC3 NXDOMAIN proof (RFC 5155 §8.4): there is a closest encloser CE (a proper
/// ancestor of `qname` with a MATCHING NSEC3), the next-closer name (one label
/// longer than CE, toward `qname`) is COVERED, and the wildcard `*.CE` is COVERED.
/// All three NSEC3s must share the zone's hash params — guaranteed here because
/// each is hashed with its own record's params during match/cover.
pub fn nsec3_proves_nxdomain(nsec3s: &[Nsec3], qname: &Name, zone: &Name) -> bool {
    // Ancestor chain: qname, parent, …, up to and including the zone apex.
    let mut chain = vec![qname.clone()];
    let mut cur = qname.clone();
    while !cur.eq_ignore_ascii_case(zone) {
        match cur.parent() {
            Some(p) => {
                cur = p.clone();
                chain.push(p);
            }
            None => return false, // qname is not under zone
        }
    }
    // Closest encloser = the longest PROPER ancestor (chain[1..]) matching an NSEC3.
    for i in 1..chain.len() {
        let ce = &chain[i];
        if !nsec3s.iter().any(|n3| n3.matches(ce)) {
            continue;
        }
        let next_closer = &chain[i - 1];
        let nc_covered = nsec3s.iter().any(|n3| n3.covers(next_closer));
        let Some(wc) = wildcard_of(ce) else { return false };
        let wc_covered = nsec3s.iter().any(|n3| n3.covers(&wc));
        return nc_covered && wc_covered;
    }
    false
}

/// NSEC NXDOMAIN proof (RFC 4035 §5.4): an NSEC covers `qname` (it does not
/// exist) and an NSEC covers the wildcard `*.CE`, where CE is the closest
/// encloser — the owner of the NSEC that covers `qname` shares CE as a suffix,
/// so we try the wildcard at each ancestor of `qname` down to `zone`.
pub fn nsec_proves_nxdomain(nsecs: &[Nsec], qname: &Name, zone: &Name) -> bool {
    if !nsec_proves_nonexistence(nsecs, qname) {
        return false;
    }
    // The wildcard sits at the closest encloser, an ancestor of qname within zone.
    let mut cur = qname.clone();
    while let Some(parent) = cur.parent() {
        if parent.is_in_zone(zone) {
            if let Some(wc) = wildcard_of(&parent) {
                if nsecs.iter().any(|nz| nsec_covers(&nz.owner, &nz.next, &wc)) {
                    return true;
                }
            }
        }
        if parent.eq_ignore_ascii_case(zone) {
            break;
        }
        cur = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    // Type bitmap with a single window 0 holding A (1), NS (2), SOA (6), RRSIG (46).
    // Window 0, length covering byte 5 (bit 46): A=bit1, NS=bit2, SOA=bit6, RRSIG=bit46.
    fn bitmap_a_ns_soa_rrsig() -> Vec<u8> {
        // bytes: bit i set at byte i/8, mask 0x80>>(i%8)
        let mut bits = [0u8; 6]; // covers types 0..=47
        for t in [1u16, 2, 6, 46] {
            let o = (t & 0xff) as usize;
            bits[o / 8] |= 0x80 >> (o % 8);
        }
        let mut bm = vec![0u8, bits.len() as u8];
        bm.extend_from_slice(&bits);
        bm
    }

    #[test]
    fn type_bitmap_membership() {
        let bm = bitmap_a_ns_soa_rrsig();
        assert!(type_in_bitmap(&bm, consts::rtype::A));
        assert!(type_in_bitmap(&bm, consts::rtype::NS));
        assert!(type_in_bitmap(&bm, consts::rtype::SOA));
        assert!(type_in_bitmap(&bm, consts::rtype::RRSIG));
        assert!(!type_in_bitmap(&bm, consts::rtype::AAAA)); // 28
        assert!(!type_in_bitmap(&bm, consts::rtype::MX)); // 15
        assert!(!type_in_bitmap(&bm, consts::rtype::CNAME)); // 5
    }

    #[test]
    fn covering_interval_and_apex_wrap() {
        let owner = n("a.example.com.");
        let next = n("c.example.com.");
        assert!(nsec_covers(&owner, &next, &n("b.example.com.")));
        assert!(!nsec_covers(&owner, &next, &n("a.example.com."))); // owner excluded
        assert!(!nsec_covers(&owner, &next, &n("c.example.com."))); // next excluded
        assert!(!nsec_covers(&owner, &next, &n("d.example.com.")));
        // Apex wrap: last NSEC owner=z..., next=apex.
        let owner2 = n("z.example.com.");
        let apex = n("example.com.");
        assert!(nsec_covers(&owner2, &apex, &n("zz.example.com."))); // after owner
        // a.example.com sorts before z.example.com, so the wrap NSEC does NOT cover it.
        assert!(!nsec_covers(&owner2, &apex, &n("a.example.com.")));
    }

    #[test]
    fn nodata_proof() {
        let owner = n("host.example.com.");
        let bm = bitmap_a_ns_soa_rrsig();
        // host has A; querying AAAA → NODATA proven (AAAA absent, no CNAME).
        assert!(nsec_proves_nodata(&owner, &bm, &n("host.example.com."), consts::rtype::AAAA));
        // Querying A → NOT NODATA (A is present).
        assert!(!nsec_proves_nodata(&owner, &bm, &n("host.example.com."), consts::rtype::A));
        // Different owner → not a NODATA proof for this name.
        assert!(!nsec_proves_nodata(&owner, &bm, &n("other.example.com."), consts::rtype::AAAA));
    }

    #[test]
    fn nonexistence_proof() {
        let nsecs = [Nsec { owner: n("a.example.com."), next: n("c.example.com."), bitmap: &[] }];
        assert!(nsec_proves_nonexistence(&nsecs, &n("b.example.com.")));
        assert!(!nsec_proves_nonexistence(&nsecs, &n("d.example.com.")));
    }

    #[test]
    fn base32hex_roundtrip() {
        for data in [&b"hello"[..], &[0u8; 20][..], &[0xFFu8; 20][..], &[0x12, 0x34, 0x56][..]] {
            let enc = base32hex_encode(data);
            assert_eq!(base32hex_decode(&enc).unwrap(), data);
        }
    }

    // Build an NSEC3 owner from a real hash and confirm match / non-match.
    #[test]
    fn nsec3_matches_real_hash() {
        let salt = [0xAAu8, 0xBB];
        let iters = 5u16;
        let name = n("host.example.com.");
        let canon = crate::dns::dnssec_sign::canonical_name_wire(&name);
        let h = crate::dns::dnssec_sign::nsec3_hash(&canon, &salt, iters);
        let label = String::from_utf8(base32hex_encode(&h)).unwrap();
        let owner = n(&format!("{label}.example.com."));
        let mut next = h.to_vec();
        next[19] = next[19].wrapping_add(1);
        let mut rdata = vec![1u8, 0, (iters >> 8) as u8, (iters & 0xff) as u8, salt.len() as u8];
        rdata.extend_from_slice(&salt);
        rdata.push(20);
        rdata.extend_from_slice(&next);
        let n3 = Nsec3::parse(&owner, &rdata).unwrap();
        assert!(n3.matches(&name));
        assert!(!n3.matches(&n("other.example.com.")));
    }

    // An NSEC3 spanning the whole hash space covers any name's hash but matches none.
    #[test]
    fn nsec3_covers_interval() {
        let owner_hash = [0u8; 20];
        let next_hash = [0xFFu8; 20];
        let label = String::from_utf8(base32hex_encode(&owner_hash)).unwrap();
        let owner = n(&format!("{label}.example.com."));
        let mut rdata = vec![1u8, 0, 0, 1, 0]; // alg1, flags0, iter1, saltlen0
        rdata.push(20);
        rdata.extend_from_slice(&next_hash);
        let n3 = Nsec3::parse(&owner, &rdata).unwrap();
        let target = n("xyz.example.com.");
        assert!(n3.covers(&target));
        assert!(!n3.matches(&target));
        assert!(!n3.opt_out());
    }

    fn mk_nsec3(owner_hash: &[u8], next_hash: &[u8]) -> (Name, Vec<u8>) {
        let label = String::from_utf8(base32hex_encode(owner_hash)).unwrap();
        let owner = n(&format!("{label}.example.com."));
        let mut rdata = vec![1u8, 0, 0, 0, 0]; // alg1, flags0, iter0, saltlen0
        rdata.push(next_hash.len() as u8);
        rdata.extend_from_slice(next_hash);
        (owner, rdata)
    }

    #[test]
    fn nsec3_nxdomain_closest_encloser() {
        let h = |name: &Name| {
            crate::dns::dnssec_sign::nsec3_hash(
                &crate::dns::dnssec_sign::canonical_name_wire(name),
                &[],
                0,
            )
        };
        // Matching NSEC3 for the closest encloser (example.com), plus an NSEC3
        // spanning the whole hash space to cover the next-closer and the wildcard.
        let ce_hash = h(&n("example.com."));
        let mut ce_next = ce_hash.to_vec();
        ce_next[19] = ce_next[19].wrapping_add(1);
        let (ce_owner, ce_rdata) = mk_nsec3(&ce_hash, &ce_next);
        let (wide_owner, wide_rdata) = mk_nsec3(&[0u8; 20], &[0xFFu8; 20]);

        let proven = [
            Nsec3::parse(&ce_owner, &ce_rdata).unwrap(),
            Nsec3::parse(&wide_owner, &wide_rdata).unwrap(),
        ];
        assert!(nsec3_proves_nxdomain(&proven, &n("nx.example.com."), &n("example.com.")));

        // Without the closest-encloser match, the proof must fail.
        let only_wide = [Nsec3::parse(&wide_owner, &wide_rdata).unwrap()];
        assert!(!nsec3_proves_nxdomain(&only_wide, &n("nx.example.com."), &n("example.com.")));
    }
}
