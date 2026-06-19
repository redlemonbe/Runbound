// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Differential tests: our codec against `hickory-proto` as the oracle.
//!
//! hickory stays a normal dependency throughout the de-hickory work *precisely*
//! so it can serve as a reference. Each case builds a message with hickory and
//! serializes it (hickory compresses names aggressively, exercising our
//! decompressor), parses it with our codec, and re-encodes with our codec. Our
//! output must be *semantically* identical to hickory's, which we check by
//! canonicalizing both byte strings through hickory (parse + re-encode): two
//! messages with the same meaning collapse to the same canonical bytes, so a
//! mismatch is a real divergence and not just a compression-layout difference.
//!
//! `#[cfg(test)]` only — never in the shipped binary.

#![cfg(test)]

use hickory_proto::op::{Message as HMessage, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name as HName, RData, Record as HRecord, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dns::wire;

fn hname(s: &str) -> HName {
    HName::from_ascii(s).unwrap()
}

/// Two wire encodings mean the same thing iff they canonicalize (parse +
/// re-encode through hickory) to identical bytes.
fn assert_semantic_eq(a: &[u8], b: &[u8]) {
    let ca = HMessage::from_vec(a)
        .expect("hickory parses lhs")
        .to_vec()
        .expect("hickory re-encodes lhs");
    let cb = HMessage::from_vec(b)
        .expect("hickory parses rhs")
        .to_vec()
        .expect("hickory re-encodes rhs");
    assert_eq!(ca, cb, "semantic divergence after our codec round-trip");
}

/// hickory builds and encodes `m`; our codec must parse it and re-emit
/// something hickory agrees is the same message.
fn assert_oracle(m: HMessage) {
    let wire = m.to_vec().expect("hickory encodes");
    let mine = wire::Message::parse(&wire).expect("our codec parses hickory output");
    let wire2 = mine.encode();
    assert_semantic_eq(&wire, &wire2);
}

fn resp() -> HMessage {
    let mut m = HMessage::response(0xBEEF, OpCode::Query);
    m.add_query(Query::query(hname("www.example.com."), RecordType::A));
    m
}

fn answer(name: &str, ttl: u32, rdata: RData) -> HRecord {
    HRecord::from_rdata(hname(name), ttl, rdata)
}

#[test]
fn oracle_a_with_compression() {
    let mut m = resp();
    m.add_answer(answer(
        "www.example.com.",
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    m.add_answer(answer(
        "www.example.com.",
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
    ));
    assert_oracle(m);
}

#[test]
fn oracle_aaaa() {
    let mut m = resp();
    m.add_answer(answer(
        "www.example.com.",
        60,
        RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
    ));
    assert_oracle(m);
}

#[test]
fn oracle_cname_chain() {
    let mut m = resp();
    m.add_answer(answer(
        "www.example.com.",
        300,
        RData::CNAME(CNAME(hname("cdn.example.net."))),
    ));
    m.add_answer(answer(
        "cdn.example.net.",
        300,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
    ));
    assert_oracle(m);
}

#[test]
fn oracle_ns_mx_ptr() {
    let mut m = resp();
    m.add_authority(answer(
        "example.com.",
        172800,
        RData::NS(NS(hname("ns1.example.com."))),
    ));
    m.add_authority(answer(
        "example.com.",
        172800,
        RData::NS(NS(hname("ns2.example.com."))),
    ));
    m.add_answer(answer(
        "example.com.",
        3600,
        RData::MX(MX::new(10, hname("mail.example.com."))),
    ));
    m.add_answer(answer(
        "1.2.0.192.in-addr.arpa.",
        3600,
        RData::PTR(PTR(hname("host.example.com."))),
    ));
    assert_oracle(m);
}

#[test]
fn oracle_soa_authority() {
    let mut m = resp();
    m.add_authority(answer(
        "example.com.",
        3600,
        RData::SOA(SOA::new(
            hname("ns1.example.com."),
            hname("hostmaster.example.com."),
            2026_06_20,
            7200,
            3600,
            1_209_600,
            300,
        )),
    ));
    assert_oracle(m);
}

#[test]
fn oracle_txt_and_srv() {
    let mut m = resp();
    m.add_answer(answer(
        "example.com.",
        300,
        RData::TXT(TXT::new(vec![
            "v=spf1 include:_spf.example.com -all".to_string()
        ])),
    ));
    m.add_answer(answer(
        "_sip._tcp.example.com.",
        300,
        RData::SRV(SRV::new(10, 60, 5060, hname("sipserver.example.com."))),
    ));
    assert_oracle(m);
}

#[test]
fn oracle_edns_opt() {
    use hickory_proto::op::Edns as HEdns;
    let mut m = resp();
    m.add_answer(answer(
        "www.example.com.",
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    let mut edns = HEdns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(true);
    m.set_edns(edns);
    assert_oracle(m);
}

/// Phase-2 readiness: the zone store and cache are keyed today on hickory's
/// `LowerName`. Migrating them to `wire::Name` is only safe if our name, parsed
/// from a wire QNAME, denotes exactly what hickory's `LowerName` does for the
/// same bytes — case-insensitively. Prove it across a spread of names so the
/// re-keying in phase 2 rests on evidence, not hope.
#[test]
fn wire_name_is_a_valid_lookup_key() {
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
    // The zone-store/cache key is the case-folded wire form of the name — *not*
    // its presentation (hickory decodes IDN punycode like `xn--p1ai` to `рф`
    // for display; on the wire and as a key it is the ASCII label). So prove
    // the keys match at the byte level: parsing hickory's exact wire name must
    // yield byte-identical wire bytes, for every name including an IDN and root.
    for s in [
        "www.example.com.",
        "EXAMPLE.COM.",
        "a.b.c.d.e.f.",
        "xn--p1ai.",
        "1.0.0.127.in-addr.arpa.",
        "_sip._tcp.example.com.",
        ".",
    ] {
        let hick = hname(s);
        let mut qname = Vec::new();
        hick.emit(&mut BinEncoder::new(&mut qname)).unwrap();

        let mine = wire::Name::parse(&mut wire::Decoder::new(&qname)).unwrap();
        assert_eq!(
            mine.wire(),
            &qname[..],
            "our parse must preserve hickory's exact wire key for {s}"
        );

        // And case-folding (the actual lookup normalization) is order-free:
        // folding then comparing matches regardless of the original case.
        let fold = |b: &[u8]| b.iter().map(|c| c.to_ascii_lowercase()).collect::<Vec<_>>();
        assert_eq!(fold(mine.wire()), fold(&qname));
    }
}

/// Phase-2 increment: our hickory-free presentation parser
/// (`wire::present::parse_rr_line`) must produce records byte-identical to the
/// existing hickory parser (`dns::local::parse_local_data`) for every modelled
/// type — same type, TTL, owner name, and RDATA wire bytes. This is what lets
/// the zone store be built from our own types instead of hickory's.
#[test]
fn parse_rr_line_matches_hickory_parse_local_data() {
    use crate::dns::local::{name_to_wire_qname, parse_local_data};
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

    let fold = |b: &[u8]| b.iter().map(|c| c.to_ascii_lowercase()).collect::<Vec<_>>();
    let lines = [
        "host.example.com. 300 A 192.0.2.1",
        "host.example.com. AAAA 2001:db8::1",
        "example.com. 3600 IN NS ns1.example.com.",
        "www.example.com. CNAME cdn.example.net.",
        "4.3.2.1.in-addr.arpa. 600 PTR host.example.com.",
        "example.com. 3600 MX 10 mail.example.com.",
        "example.com. TXT \"v=spf1 -all\"",
        "_sip._tcp.example.com. SRV 10 60 5060 sip.example.com.",
    ];
    for line in lines {
        let hick = parse_local_data(line).unwrap_or_else(|| panic!("hickory parses {line}"));
        let mine = wire::present::parse_rr_line(line).unwrap_or_else(|| panic!("ours parses {line}"));

        assert_eq!(mine.rtype, u16::from(hick.record_type()), "{line}: type");
        assert_eq!(mine.ttl, hick.ttl, "{line}: ttl");
        assert_eq!(
            fold(mine.name.wire()),
            name_to_wire_qname(&hick.name).to_vec(),
            "{line}: owner name"
        );

        let mut my_rd = wire::Encoder::uncompressed();
        mine.rdata.emit(&mut my_rd);
        let mut hk_rd = Vec::new();
        hick.data.emit(&mut BinEncoder::new(&mut hk_rd)).unwrap();
        assert_eq!(fold(my_rd.as_slice()), fold(&hk_rd), "{line}: rdata wire");
    }
}

/// Beyond the fixed cases: hundreds of randomly-shaped messages (mixed types,
/// names, TTLs, section sizes) built and compressed by hickory, round-tripped
/// through our codec, and canonically compared. This is where odd compression
/// layouts and section combinations get exercised.
#[test]
fn oracle_randomized_messages() {
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    let mut rng = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let names = [
        "a.com.",
        "www.a.com.",
        "b.example.org.",
        "deep.x.y.z.example.",
        "ns1.a.com.",
        "mail.b.example.org.",
        "_sip._tcp.a.com.",
    ];
    let pick = |v: u64| names[(v as usize) % names.len()];

    for _ in 0..400 {
        let mut m = HMessage::response(rng() as u16, OpCode::Query);
        m.add_query(Query::query(hname(pick(rng())), RecordType::A));
        let n_ans = rng() % 6;
        for _ in 0..n_ans {
            let name = pick(rng());
            let ttl = (rng() % 7200) as u32;
            let rd = match rng() % 7 {
                0 => RData::A(A(Ipv4Addr::new(
                    rng() as u8,
                    rng() as u8,
                    rng() as u8,
                    rng() as u8,
                ))),
                1 => RData::AAAA(AAAA(Ipv6Addr::new(
                    rng() as u16,
                    rng() as u16,
                    0,
                    0,
                    0,
                    0,
                    0,
                    rng() as u16,
                ))),
                2 => RData::CNAME(CNAME(hname(pick(rng())))),
                3 => RData::NS(NS(hname(pick(rng())))),
                4 => RData::MX(MX::new(rng() as u16, hname(pick(rng())))),
                5 => RData::TXT(TXT::new(vec![format!("txt-{}", rng() % 100000)])),
                _ => RData::SRV(SRV::new(
                    rng() as u16,
                    rng() as u16,
                    rng() as u16,
                    hname(pick(rng())),
                )),
            };
            m.add_answer(answer(name, ttl, rd));
        }
        assert_oracle(m);
    }
}

/// The parser must survive arbitrary bytes — no panic, no hang — and any
/// message it accepts must re-encode to something it accepts again.
#[test]
fn fuzz_no_panic_and_reparse() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..50_000 {
        let len = (next() % 300) as usize;
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            *b = (next() & 0xFF) as u8;
        }
        if let Ok(m) = wire::Message::parse(&buf) {
            let re = m.encode();
            let m2 = wire::Message::parse(&re).expect("re-encode must re-parse");
            assert_eq!(m.questions, m2.questions);
        }
    }
}
