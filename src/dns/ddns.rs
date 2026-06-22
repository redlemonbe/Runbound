// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//! RFC 2136 Dynamic DNS UPDATE handler (#14) — hickory-free.
//!
//! The request is authenticated with TSIG (RFC 8945) via [`crate::dns::tsig`]
//! and applied to the live [`LocalZoneSet`] with copy-on-write on the wire
//! record store (`records_wire` / `zones_wire`), which the wire serving core
//! reads. No hickory types cross into this path.

use std::{
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

use crate::dns::local::{wire_name_key, LocalZoneSet, ZoneAction};
use crate::dns::tsig::{self, TsigAlg, TsigError};
use crate::dns::wire::consts::{class, rcode, rtype};
use crate::dns::wire::Message;

/// Accepted TSIG clock skew, matching the prior handler.
const TSIG_WINDOW_SECS: u64 = 300;

/// Verify a TSIG-authenticated DNS UPDATE (RFC 2136) and apply it to `zones`.
/// Returns `(rcode, Some(verified))` on a successful TSIG check so the caller can
/// sign the response (RFC 8945 §5.4.1); `(rcode, None)` when the request is
/// rejected before/at TSIG verification. `raw` is the verbatim request wire
/// (needed for the MAC); `msg` is its parse.
pub fn handle_update_wire(
    raw: &[u8],
    msg: &Message,
    zones: &Arc<ArcSwap<LocalZoneSet>>,
    tsig_keys: &[(String, TsigAlg, Vec<u8>)],
    client_ip: IpAddr,
) -> (u16, Option<tsig::Verified>) {
    // ── TSIG is mandatory for UPDATE ────────────────────────────────────
    if tsig_keys.is_empty() {
        warn!(%client_ip, "DNS UPDATE refused — no TSIG keys configured");
        return (rcode::REFUSED, None);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let verified = match tsig::verify_request(raw, tsig_keys, now, TSIG_WINDOW_SECS) {
        Ok(v) => v,
        Err(e) => {
            warn!(%client_ip, ?e, "DNS UPDATE refused — TSIG verification failed");
            return (
                match e {
                    TsigError::FormErr => rcode::FORMERR,
                    _ => rcode::REFUSED,
                },
                None,
            );
        }
    };
    let key_name = verified.key_name.clone();

    // ── Update section = the authority records (RFC 2136 §2.1, UPCOUNT) ──
    let updates = &msg.authority;
    if updates.is_empty() {
        debug!(%client_ip, key = %key_name, "DNS UPDATE with empty update section");
        return (rcode::NOERROR, Some(verified));
    }

    let current = zones.load_full();

    // SEC-AGV-01: a UPDATE must not delete a statically configured name. Class
    // ANY/NONE on a static name is rejected before any mutation.
    for rr in updates {
        if rr.rclass == class::ANY || rr.rclass == class::NONE {
            let key = wire_name_key(&rr.name);
            if current.static_names_wire.contains(&key[..]) {
                warn!(%client_ip, key = %key_name, name = %rr.name.to_ascii(),
                    "DNS UPDATE refused — delete of static zone rejected");
                return (rcode::REFUSED, Some(verified));
            }
        }
    }

    let mut new_zones = (*current).clone();
    let mut added = 0usize;
    let mut deleted = 0usize;

    for rr in updates {
        let key = wire_name_key(&rr.name);
        match (rr.rtype, rr.rclass) {
            // Delete all RRsets at a name: class ANY, type ANY (RFC 2136 §2.5.3).
            (rtype::ANY, class::ANY) => {
                if new_zones.records_wire.remove(&key[..]).is_some() {
                    deleted += 1;
                }
            }
            // Delete an RRset: class ANY, specific type (§2.5.2).
            (rt, class::ANY) => {
                if let Some(recs) = new_zones.records_wire.get_mut(&key[..]) {
                    let before = recs.len();
                    recs.retain(|r| r.rtype != rt);
                    deleted += before - recs.len();
                }
            }
            // Delete a specific RR: class NONE — match on type + RDATA (§2.5.4).
            (rt, class::NONE) => {
                if let Some(recs) = new_zones.records_wire.get_mut(&key[..]) {
                    let before = recs.len();
                    recs.retain(|r| !(r.rtype == rt && r.rdata == rr.rdata));
                    deleted += before - recs.len();
                }
            }
            // Add an RR: class IN, supported types (§2.5.1).
            (rt, class::IN) if is_supported_add(rt) => {
                new_zones
                    .zones_wire
                    .entry(key.clone())
                    .or_insert(ZoneAction::Static);
                let entry = new_zones.records_wire.entry(key).or_default();
                // Adding an already-present identical RR is a no-op (§2.5.1).
                let mut rec = rr.clone();
                rec.rclass = class::IN;
                if !entry.iter().any(|r| r.rtype == rec.rtype && r.rdata == rec.rdata) {
                    entry.push(rec);
                    added += 1;
                }
            }
            _ => {
                debug!(name = %rr.name.to_ascii(), rtype = rr.rtype, class = rr.rclass,
                    "DNS UPDATE: skipping unsupported RR type/class");
            }
        }
    }

    zones.store(Arc::new(new_zones));
    info!(%client_ip, key = %key_name, added, deleted, "DNS UPDATE applied");
    (rcode::NOERROR, Some(verified))
}

/// Record types Runbound accepts as DDNS additions (mirrors the prior handler).
fn is_supported_add(rt: u16) -> bool {
    matches!(
        rt,
        rtype::A
            | rtype::AAAA
            | rtype::CNAME
            | rtype::TXT
            | rtype::MX
            | rtype::SRV
            | rtype::NS
            | rtype::PTR
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::{LocalData, LocalZone};
    use crate::dns::wire::consts::opcode;
    use crate::dns::wire::{Header, Message, Name, Question, Rdata, Record};

    fn keys() -> Vec<(String, TsigAlg, Vec<u8>)> {
        vec![("ddns-key".into(), TsigAlg::Sha256, b"secret-key-material-xyz".to_vec())]
    }

    fn base_zoneset() -> Arc<ArcSwap<LocalZoneSet>> {
        let zones = vec![LocalZone {
            name: "dyn.test.".into(),
            zone_type: "static".into(),
        }];
        let data = vec![LocalData {
            rr: "fixed.dyn.test. 300 A 10.0.0.1".into(),
        }];
        Arc::new(ArcSwap::from_pointee(LocalZoneSet::from_config(&zones, &data)))
    }

    /// Build a TSIG-signed UPDATE adding/deleting `updates` (authority section).
    fn signed_update(updates: Vec<Record>, time: u64) -> Vec<u8> {
        let mut h = Header::default();
        h.id = 0x55aa;
        h.set_opcode(opcode::UPDATE);
        let mut m = Message {
            header: h,
            ..Default::default()
        };
        m.questions
            .push(Question::new(Name::from_ascii("dyn.test.").unwrap(), rtype::SOA));
        m.authority = updates;
        let unsigned = m.encode();
        // Reuse the tsig module's signing test helper via its public verify by
        // constructing the MAC the same way: sign with ring over TBS.
        crate::dns::tsig::test_support::sign(
            &unsigned,
            "ddns-key.",
            TsigAlg::Sha256,
            b"secret-key-material-xyz",
            time,
        )
    }

    fn add_rr(name: &str, rt: u16, rdata: Rdata) -> Record {
        Record {
            name: Name::from_ascii(name).unwrap(),
            rtype: rt,
            rclass: class::IN,
            ttl: 300,
            rdata,
        }
    }

    #[test]
    fn add_then_present_in_records_wire() {
        let zones = base_zoneset();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let rr = add_rr("host.dyn.test.", rtype::A, Rdata::A("10.0.0.9".parse().unwrap()));
        let raw = signed_update(vec![rr], now);
        let msg = Message::parse(&raw).unwrap();
        let (rc, _) = handle_update_wire(&raw, &msg, &zones, &keys(), "127.0.0.1".parse().unwrap());
        assert_eq!(rc, rcode::NOERROR);
        let z = zones.load();
        let key = wire_name_key(&Name::from_ascii("host.dyn.test.").unwrap());
        assert_eq!(z.records_wire.get(&key[..]).map(|v| v.len()), Some(1));
    }

    #[test]
    fn delete_rrset_removes_records() {
        let zones = base_zoneset();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // First add, then delete the RRset.
        let rr = add_rr("gone.dyn.test.", rtype::A, Rdata::A("10.0.0.5".parse().unwrap()));
        let raw = signed_update(vec![rr], now);
        let msg = Message::parse(&raw).unwrap();
        handle_update_wire(&raw, &msg, &zones, &keys(), "127.0.0.1".parse().unwrap());

        let mut del = add_rr("gone.dyn.test.", rtype::A, Rdata::Unknown { rtype: rtype::A, data: vec![] });
        del.rclass = class::ANY;
        del.ttl = 0;
        let raw2 = signed_update(vec![del], now);
        let msg2 = Message::parse(&raw2).unwrap();
        let (rc, _) = handle_update_wire(&raw2, &msg2, &zones, &keys(), "127.0.0.1".parse().unwrap());
        assert_eq!(rc, rcode::NOERROR);
        let z = zones.load();
        let key = wire_name_key(&Name::from_ascii("gone.dyn.test.").unwrap());
        assert!(z.records_wire.get(&key[..]).map(|v| v.is_empty()).unwrap_or(true));
    }

    #[test]
    fn delete_of_static_name_is_refused() {
        let zones = base_zoneset();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Attempt to delete the statically configured fixed.dyn.test.
        let mut del = add_rr("fixed.dyn.test.", rtype::ANY, Rdata::Unknown { rtype: rtype::ANY, data: vec![] });
        del.rclass = class::ANY;
        del.ttl = 0;
        let raw = signed_update(vec![del], now);
        let msg = Message::parse(&raw).unwrap();
        let (rc, _) = handle_update_wire(&raw, &msg, &zones, &keys(), "127.0.0.1".parse().unwrap());
        assert_eq!(rc, rcode::REFUSED);
        // The static record survives.
        let z = zones.load();
        let key = wire_name_key(&Name::from_ascii("fixed.dyn.test.").unwrap());
        assert_eq!(z.records_wire.get(&key[..]).map(|v| v.len()), Some(1));
    }

    #[test]
    fn unsigned_update_is_refused() {
        let zones = base_zoneset();
        let mut h = Header::default();
        h.set_opcode(opcode::UPDATE);
        let mut m = Message { header: h, ..Default::default() };
        m.authority.push(add_rr("x.dyn.test.", rtype::A, Rdata::A("10.0.0.2".parse().unwrap())));
        let raw = m.encode();
        let (rc, _) = handle_update_wire(&raw, &m, &zones, &keys(), "127.0.0.1".parse().unwrap());
        assert_eq!(rc, rcode::REFUSED);
    }
}
