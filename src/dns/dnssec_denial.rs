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
        let nsecs = vec![
            Nsec { owner: n("a.example.com."), next: n("c.example.com."), bitmap: &[] },
        ];
        assert!(nsec_proves_nonexistence(&nsecs, &n("b.example.com.")));
        assert!(!nsec_proves_nonexistence(&nsecs, &n("d.example.com.")));
    }
}
