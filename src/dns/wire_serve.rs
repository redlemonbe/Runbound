// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Hickory-free local-zone serving core.
//!
//! [`answer_local`] takes a parsed query and a [`LocalZoneSet`] and produces the
//! authoritative response for a locally-served name — entirely with our own
//! wire types. It mirrors the semantics of the hickory slow path in
//! `server.rs` (`handle_zone_set`): zone-action dispatch (Refuse / NxDomain /
//! BlockPage / Static), exact records, RFC 1034 §3.6.2 CNAME chaining, and the
//! RFC 2308 NODATA-vs-NXDOMAIN distinction, with EDNS echoed back.
//!
//! It returns `None` when the name is **not** locally authoritative, which is
//! the signal for the caller to forward upstream. DNSSEC online-signing of the
//! answer is done wire-native by `zone_signer` on the serving path (serve_wire);
//! this core builds the unsigned authoritative answer.

use smallvec::SmallVec;

use crate::dns::local::{LocalZoneSet, ZoneAction};
use crate::dns::wire::consts::{class, rcode, rtype};
use crate::dns::wire::{Edns, Message, Name, Rdata, Record};

/// Lowercased wire key for a name already in wire form — on the stack.
///
/// Two fast-path properties: (1) the case-fold is the hand-written SIMD/asm
/// `copy_lowercase_label` (`byte OR (mask AND 0x20)`), the same one the hot path
/// uses; (2) the result lives inline in a `SmallVec<[u8; 64]>`, so a normal name
/// never heap-allocates and the `HashMap` lookups borrow it directly. Length
/// octets are 0–63, all below `A`, so the case bit never touches them.
fn lower_key(wire_name: &[u8]) -> SmallVec<[u8; 64]> {
    let mut out: SmallVec<[u8; 64]> = SmallVec::new();
    crate::dns::simd::copy_lowercase_label(&mut out, wire_name);
    out
}

/// Build the authoritative local answer for `query`, or `None` if the queried
/// name is not locally authoritative (caller should forward upstream).
pub fn answer_local(query: &Message, zones: &LocalZoneSet) -> Option<Message> {
    let question = query.first_question()?.clone();
    let qtype = question.qtype;
    let key = lower_key(question.name.wire());

    let action = zones.find_wire(&key)?; // None ⇒ not authoritative ⇒ forward

    let mut resp = Message {
        header: query.header,
        ..Default::default()
    };
    resp.header.set_qr(true);
    resp.header.set_aa(false);
    // RA=1: Runbound is a recursive/forwarding resolver, so every response must
    // advertise recursion-available — consistent with the forward path and the XDP
    // fast-path builders (FLAGS_*_NXDOMAIN/REFUSED). Serving a blacklist/local-zone
    // block without RA made dig warn "recursion not available" and could nudge a
    // client to retry the name on a secondary resolver, bypassing the block.
    resp.header.set_ra(true);
    resp.header.set_tc(false);
    // We do not validate DNSSEC here, so never claim Authentic Data (RFC 6840
    // §5.8) even if the client set AD in the query.
    resp.header.set_ad(false);
    resp.questions.push(question);

    let mut rc = rcode::NOERROR;
    match action {
        ZoneAction::Refuse => {
            rc = rcode::REFUSED;
        }
        ZoneAction::NxDomain => {
            resp.header.set_aa(true);
            rc = rcode::NXDOMAIN;
        }
        ZoneAction::BlockPage => {
            // Authoritative either way: serve the pre-inserted block record if
            // present, otherwise an authoritative NXDOMAIN (matches the XDP path).
            resp.header.set_aa(true);
            let recs = zones.local_records_wire(&key, qtype);
            if recs.is_empty() {
                rc = rcode::NXDOMAIN;
            } else {
                resp.answers = recs.into_iter().cloned().collect();
            }
        }
        ZoneAction::Static | ZoneAction::Redirect => {
            let recs = zones.local_records_wire(&key, qtype);
            if !recs.is_empty() {
                resp.header.set_aa(true);
                resp.answers = recs.into_iter().cloned().collect();
            } else {
                let chain = if qtype != rtype::CNAME {
                    follow_cname(zones, &key, qtype)
                } else {
                    Vec::new()
                };
                if !chain.is_empty() {
                    resp.header.set_aa(true);
                    resp.answers = chain;
                } else if zones.name_has_records_wire(&key) {
                    // NODATA: the name exists, just not this type (RFC 2308).
                    resp.header.set_aa(true);
                } else {
                    resp.header.set_aa(true);
                    rc = rcode::NXDOMAIN;
                }
            }
        }
    }
    resp.header.set_rcode_low(rc);

    // Echo EDNS (RFC 6891 §7): if the client sent an OPT, answer with one sized
    // to the smaller of our default and the client's advertised payload, and
    // reflect the DO bit (mirrors the XDP slow path's OPT echo).
    if let Ok(Some(client)) = query.edns() {
        let mut server = Edns::default();
        server.udp_payload = client.udp_payload.clamp(512, server.udp_payload);
        server.set_dnssec_ok(client.dnssec_ok());
        resp.additional.push(server.to_record());
    }

    Some(resp)
}

/// Datagram-level local serving: parse a query, serve it locally, and return
/// the response bytes — or `None` if the datagram is malformed or the name is
/// not locally authoritative (the caller forwards). This is the per-packet seam
/// the future own UDP/TCP listener calls.
pub fn serve_datagram(query: &[u8], zones: &LocalZoneSet) -> Option<Vec<u8>> {
    let msg = Message::parse(query).ok()?;
    let resp = answer_local(&msg, zones)?;
    Some(resp.encode())
}

/// CNAME chain following (RFC 1034 §3.6.2), wire-typed twin of
/// `follow_local_cname`. Returns the CNAME(s) plus the resolved target records,
/// or empty if the chain does not resolve within the local zones.
pub(crate) fn follow_cname(zones: &LocalZoneSet, start: &[u8], qtype: u16) -> Vec<Record> {
    let mut chain: Vec<Record> = Vec::with_capacity(8);
    let mut current: SmallVec<[u8; 64]> = SmallVec::from_slice(start);

    for _ in 0..8 {
        let cnames = zones.local_records_wire(&current, rtype::CNAME);
        let Some(cname_rec) = cnames.first().map(|r| (*r).clone()) else {
            break;
        };
        let next = match &cname_rec.rdata {
            Rdata::Cname(n) => lower_key(n.wire()),
            _ => break,
        };
        chain.push(cname_rec);
        let resolved: Vec<Record> = zones
            .local_records_wire(&next, qtype)
            .into_iter()
            .cloned()
            .collect();
        if !resolved.is_empty() {
            chain.extend(resolved);
            return chain;
        }
        current = next;
    }
    Vec::new()
}

/// True if wire name `name` is equal to, or a descendant of, `zone` — both in
/// lowercased length-prefixed wire form. Walks `name`'s parents by stripping its
/// leftmost label until it equals `zone` (or runs out). The twin of the parent
/// walk in [`LocalZoneSet::find_wire`].
fn wire_name_in_zone(mut name: &[u8], zone: &[u8]) -> bool {
    loop {
        if name == zone {
            return true;
        }
        if name.len() <= 1 {
            return false; // reached the root without matching
        }
        let skip = 1 + name[0] as usize;
        if skip >= name.len() {
            return false;
        }
        name = &name[skip..];
    }
}

/// Synthesise a zone SOA when the zone data carries none — mirrors the values
/// the previous hickory AXFR used so secondaries see stable apex metadata.
fn synthetic_soa(zone: &Name, serial: u32) -> Record {
    let mname = Name::from_ascii("ns1.runbound.local.").unwrap_or_else(|_| zone.clone());
    let rname = Name::from_ascii("hostmaster.runbound.local.").unwrap_or_else(|_| zone.clone());
    Record {
        name: zone.clone(),
        rtype: rtype::SOA,
        rclass: class::IN,
        ttl: 3600,
        rdata: Rdata::Soa {
            mname,
            rname,
            serial,
            refresh: 3600,
            retry: 900,
            expire: 86400,
            minimum: 300,
        },
    }
}

/// Build a wire-native AXFR/IXFR response for the zone named by `query`'s
/// question — a single message carrying `SOA … records … SOA` (RFC 5936 §2.2),
/// entirely with our own wire types. IXFR is served as a full AXFR (matching the
/// prior behaviour). Returns `None` when the zone holds no local records, so the
/// caller can answer NXDOMAIN. Access control (axfr-allow) is the caller's job.
///
/// Single-message transfer: large zones that would exceed 64 KiB are not split
/// across messages here — the same limitation the previous hickory path had; the
/// local zones Runbound serves are well within one message.
pub fn axfr_response(query: &Message, zones: &LocalZoneSet) -> Option<Vec<u8>> {
    let question = query.first_question()?.clone();
    let zone_key = lower_key(question.name.wire());

    // Every local record whose owner name falls within the requested zone.
    let mut records: Vec<Record> = Vec::new();
    for (name_key, recs) in &zones.records_wire {
        if wire_name_in_zone(name_key, &zone_key) {
            for r in recs {
                let mut r = r.clone();
                r.rclass = class::IN;
                records.push(r);
            }
        }
    }
    if records.is_empty() {
        return None;
    }

    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 60) as u32)
        .unwrap_or(1);
    let soa = records
        .iter()
        .find(|r| r.rtype == rtype::SOA)
        .cloned()
        .unwrap_or_else(|| synthetic_soa(&question.name, serial));

    let mut answers: Vec<Record> = Vec::with_capacity(records.len() + 2);
    answers.push(soa.clone());
    for r in records.into_iter() {
        if r.rtype != rtype::SOA {
            answers.push(r);
        }
    }
    answers.push(soa);

    let mut resp = Message {
        header: query.header,
        ..Default::default()
    };
    resp.header.set_qr(true);
    resp.header.set_aa(true);
    resp.header.set_ra(false);
    resp.header.set_tc(false);
    resp.header.set_ad(false);
    resp.header.set_rcode_low(rcode::NOERROR);
    resp.questions.push(question);
    resp.answers = answers;
    Some(resp.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::{LocalData, LocalZone};
    use crate::dns::wire::{consts, Name, Question};

    fn zoneset() -> LocalZoneSet {
        let zones = vec![
            LocalZone {
                name: "local.".into(),
                zone_type: "static".into(),
            },
            LocalZone {
                name: "refuse.test.".into(),
                zone_type: "refuse".into(),
            },
            LocalZone {
                name: "gone.test.".into(),
                zone_type: "always_nxdomain".into(),
            },
        ];
        let data = vec![
            LocalData {
                rr: "host.local. 300 A 10.0.0.1".into(),
            },
            LocalData {
                rr: "host.local. 300 A 10.0.0.2".into(),
            },
            LocalData {
                rr: "host.local. 300 AAAA 2001:db8::1".into(),
            },
            LocalData {
                rr: "alias.local. 300 CNAME host.local.".into(),
            },
        ];
        LocalZoneSet::from_config(&zones, &data)
    }

    fn query(name: &str, qtype: u16, with_edns: bool) -> Message {
        let mut m = Message::default();
        m.header.id = 0x4242;
        m.header.set_rd(true);
        m.questions
            .push(Question::new(Name::from_ascii(name).unwrap(), qtype));
        if with_edns {
            m.additional.push(Edns::default().to_record());
        }
        m
    }

    /// Every answer this core builds must be parseable by hickory (well-formed).
    fn assert_wellformed(resp: &Message) {
        let bytes = resp.encode();
        hickory_proto::op::Message::from_vec(&bytes).expect("hickory parses our response");
    }

    #[test]
    fn positive_answer() {
        let z = zoneset();
        let r = answer_local(&query("host.local.", consts::rtype::A, false), &z).unwrap();
        assert!(r.header.qr() && r.header.aa());
        assert_eq!(r.header.rcode_low(), rcode::NOERROR);
        assert_eq!(r.answers.len(), 2);
        assert_eq!(r.header.id, 0x4242);
        assert!(r.header.rd(), "RD echoed");
        assert_wellformed(&r);
    }

    #[test]
    fn nodata_when_type_absent() {
        let z = zoneset();
        let r = answer_local(&query("host.local.", consts::rtype::MX, false), &z).unwrap();
        assert_eq!(r.header.rcode_low(), rcode::NOERROR);
        assert!(r.header.aa());
        assert!(r.answers.is_empty());
        assert_wellformed(&r);
    }

    #[test]
    fn nxdomain_when_name_absent() {
        let z = zoneset();
        let r = answer_local(&query("absent.local.", consts::rtype::A, false), &z).unwrap();
        assert_eq!(r.header.rcode_low(), rcode::NXDOMAIN);
        assert!(r.header.aa());
        assert_wellformed(&r);
    }

    #[test]
    fn refuse_zone() {
        let z = zoneset();
        let r = answer_local(&query("x.refuse.test.", consts::rtype::A, false), &z).unwrap();
        assert_eq!(r.header.rcode_low(), rcode::REFUSED);
        // v0.22.1: blocked/local responses must advertise recursion-available (RA),
        // consistent with the forward + XDP paths.
        assert!(r.header.ra(), "REFUSED block must set RA");
        assert_wellformed(&r);
    }

    #[test]
    fn nxdomain_zone() {
        let z = zoneset();
        let r = answer_local(&query("anything.gone.test.", consts::rtype::A, false), &z).unwrap();
        assert_eq!(r.header.rcode_low(), rcode::NXDOMAIN);
        assert!(r.header.ra(), "NXDOMAIN block must set RA");
        assert_wellformed(&r);
    }

    #[test]
    fn cname_chain_resolved() {
        let z = zoneset();
        let r = answer_local(&query("alias.local.", consts::rtype::A, false), &z).unwrap();
        assert_eq!(r.header.rcode_low(), rcode::NOERROR);
        assert!(r.header.aa());
        // CNAME + the two A records of the target
        assert_eq!(r.answers.len(), 3);
        assert_eq!(r.answers[0].rtype, consts::rtype::CNAME);
        assert_wellformed(&r);
    }

    #[test]
    fn not_authoritative_returns_none() {
        let z = zoneset();
        assert!(answer_local(&query("example.org.", consts::rtype::A, false), &z).is_none());
    }

    #[test]
    fn edns_echoed() {
        let z = zoneset();
        let r = answer_local(&query("host.local.", consts::rtype::A, true), &z).unwrap();
        assert!(r.edns().unwrap().is_some());
        assert_wellformed(&r);
    }

    /// Full stack over a real socket: client query bytes → our parse → our
    /// serving core → our encode → back over UDP → hickory validates the wire,
    /// and our parser reads the content. No hickory in the serving path.
    #[test]
    fn udp_roundtrip_serves_local_zone() {
        use std::net::UdpSocket;
        let z = zoneset();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let q = query("host.local.", consts::rtype::A, true).encode();
        client.send_to(&q, addr).unwrap();

        let mut buf = [0u8; 1232];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        let resp = serve_datagram(&buf[..n], &z).expect("name is locally authoritative");
        server.send_to(&resp, from).unwrap();

        let (n2, _) = client.recv_from(&mut buf).unwrap();
        // hickory must accept what actually went over the wire,
        hickory_proto::op::Message::from_vec(&buf[..n2]).expect("hickory parses the response");
        // and our own parser reads the expected content back.
        let parsed = Message::parse(&buf[..n2]).unwrap();
        assert!(parsed.header.qr() && parsed.header.aa());
        assert_eq!(parsed.header.rcode_low(), rcode::NOERROR);
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.header.id, 0x4242);
    }

    #[test]
    fn axfr_brackets_records_with_soa() {
        let z = zoneset();
        let req = query("local.", consts::rtype::AXFR, false);
        let bytes = axfr_response(&req, &z).expect("local. has records");
        // Must be valid on the wire and self-parseable.
        hickory_proto::op::Message::from_vec(&bytes).expect("hickory parses AXFR");
        let parsed = Message::parse(&bytes).unwrap();
        assert!(parsed.header.qr() && parsed.header.aa());
        assert_eq!(parsed.header.rcode_low(), rcode::NOERROR);
        // SOA … records … SOA: at least 3 answers, first and last are SOA.
        assert!(parsed.answers.len() >= 3, "got {}", parsed.answers.len());
        assert_eq!(parsed.answers.first().unwrap().rtype, consts::rtype::SOA);
        assert_eq!(parsed.answers.last().unwrap().rtype, consts::rtype::SOA);
        // The host.local. A/AAAA and alias.local. CNAME records are inside.
        let inner = &parsed.answers[1..parsed.answers.len() - 1];
        assert!(inner.iter().any(|r| r.rtype == consts::rtype::A));
        assert!(inner.iter().any(|r| r.rtype == consts::rtype::CNAME));
        assert!(inner.iter().all(|r| r.rtype != consts::rtype::SOA));
    }

    #[test]
    fn axfr_unknown_zone_returns_none() {
        let z = zoneset();
        let req = query("nonexistent.example.", consts::rtype::AXFR, false);
        assert!(axfr_response(&req, &z).is_none());
    }

    #[test]
    fn axfr_serves_configured_soa_not_synthetic() {
        // A zone whose local-data carries an explicit SOA: AXFR must serve that
        // SOA (configured serial), not a synthesised one.
        let zones = vec![LocalZone {
            name: "example.test.".into(),
            zone_type: "static".into(),
        }];
        let data = vec![
            LocalData {
                rr: "example.test. 3600 IN SOA ns1.example.test. admin.example.test. 2026010101 3600 900 604800 300".into(),
            },
            LocalData {
                rr: "www.example.test. 300 A 192.0.2.10".into(),
            },
        ];
        let z = LocalZoneSet::from_config(&zones, &data);
        let req = query("example.test.", consts::rtype::AXFR, false);
        let bytes = axfr_response(&req, &z).expect("zone has records");
        let parsed = Message::parse(&bytes).unwrap();
        let soa = parsed.answers.first().unwrap();
        assert_eq!(soa.rtype, consts::rtype::SOA);
        match &soa.rdata {
            Rdata::Soa { serial, .. } => assert_eq!(*serial, 2026010101, "configured serial"),
            other => panic!("expected SOA, got {other:?}"),
        }
    }
}
