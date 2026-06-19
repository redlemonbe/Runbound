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
