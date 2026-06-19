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
//! answer stays in the hickory signer for now and is layered on at integration;
//! this core builds the unsigned authoritative answer.

use crate::dns::local::{LocalZoneSet, ZoneAction};
use crate::dns::wire::consts::{rcode, rtype};
use crate::dns::wire::{Edns, Message, Rdata, Record};

/// Lowercased wire key for a name already in wire form.
fn lower_key(wire_name: &[u8]) -> Vec<u8> {
    wire_name.iter().map(|b| b.to_ascii_lowercase()).collect()
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
    resp.header.set_ra(false);
    resp.header.set_tc(false);
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
            let recs = zones.local_records_wire(&key, qtype);
            if recs.is_empty() {
                rc = rcode::NXDOMAIN;
            } else {
                resp.header.set_aa(true);
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

    // Echo EDNS: if the client sent an OPT, answer with one sized to the
    // smaller of our default and the client's advertised payload.
    if let Ok(Some(client)) = query.edns() {
        let mut server = Edns::default();
        server.udp_payload = client.udp_payload.clamp(512, server.udp_payload);
        resp.additional.push(server.to_record());
    }

    Some(resp)
}

/// CNAME chain following (RFC 1034 §3.6.2), wire-typed twin of
/// `follow_local_cname`. Returns the CNAME(s) plus the resolved target records,
/// or empty if the chain does not resolve within the local zones.
fn follow_cname(zones: &LocalZoneSet, start: &[u8], qtype: u16) -> Vec<Record> {
    let mut chain: Vec<Record> = Vec::with_capacity(8);
    let mut current = start.to_vec();

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
        assert_wellformed(&r);
    }

    #[test]
    fn nxdomain_zone() {
        let z = zoneset();
        let r = answer_local(&query("anything.gone.test.", consts::rtype::A, false), &z).unwrap();
        assert_eq!(r.header.rcode_low(), rcode::NXDOMAIN);
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
}
