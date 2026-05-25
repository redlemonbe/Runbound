// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Issue #22 — AXFR/IXFR zone transfer (RFC 5936/1995).
// Runbound acts as primary; secondaries pull full zone data via AXFR over TCP.

use std::net::IpAddr;
use std::str::FromStr;

use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tracing::{info, warn};

use crate::dns::local::LocalZoneSet;

pub fn is_transfer_allowed(ip: IpAddr, allow_cidrs: &[String]) -> bool {
    if allow_cidrs.is_empty() {
        return false;
    }
    allow_cidrs.iter().any(|cidr| cidr_matches(cidr, ip))
}

fn cidr_matches(cidr: &str, ip: IpAddr) -> bool {
    if let Some((addr_str, prefix_str)) = cidr.split_once('/') {
        let Ok(prefix) = prefix_str.parse::<u8>() else { return false; };
        match (ip, IpAddr::from_str(addr_str).ok()) {
            (IpAddr::V4(client), Some(IpAddr::V4(net))) => {
                let mask = if prefix >= 32 { u32::MAX } else { !((1u32 << (32 - prefix)) - 1) };
                (u32::from(client) & mask) == (u32::from(net) & mask)
            }
            (IpAddr::V6(client), Some(IpAddr::V6(net))) => {
                let cb = client.octets();
                let nb = net.octets();
                let full_bytes = (prefix / 8) as usize;
                if cb[..full_bytes.min(16)] != nb[..full_bytes.min(16)] {
                    return false;
                }
                let rem = prefix % 8;
                if rem > 0 && full_bytes < 16 {
                    let mask = 0xFF_u8 << (8 - rem);
                    (cb[full_bytes] & mask) == (nb[full_bytes] & mask)
                } else {
                    true
                }
            }
            _ => false,
        }
    } else {
        IpAddr::from_str(cidr).map(|n| n == ip).unwrap_or(false)
    }
}

fn synthetic_soa(zone: &Name, serial: u32) -> Record {
    let mname = Name::from_str("ns1.runbound.local.").unwrap_or_else(|_| zone.clone());
    let rname = Name::from_str("hostmaster.runbound.local.").unwrap_or_else(|_| zone.clone());
    let soa = RData::SOA(SOA::new(mname, rname, serial, 3600, 900, 86400, 300));
    Record::from_rdata(zone.clone(), 3600, soa)
}

fn error_info(request: &Request, code: ResponseCode) -> ResponseInfo {
    let mut meta = Metadata::response_from_request(&request.metadata);
    meta.response_code = code;
    ResponseInfo::from(hickory_proto::op::Header {
        metadata: meta,
        counts: Default::default(),
    })
}

pub async fn handle_axfr<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    zones: &LocalZoneSet,
    client_ip: IpAddr,
    qname_str: &str,
    allow_cidrs: &[String],
) -> ResponseInfo {
    if !is_transfer_allowed(client_ip, allow_cidrs) {
        warn!(ip = %client_ip, zone = %qname_str, "AXFR refused — not in axfr-allow");
        return error_info(request, ResponseCode::Refused);
    }

    let Ok(zone_name) = Name::from_str(qname_str) else {
        return error_info(request, ResponseCode::FormErr);
    };

    let mut zone_records: Vec<Record> = Vec::new();
    for (name, recs) in &zones.records {
        if name == &zone_name || name.zone_of(&zone_name) {
            zone_records.extend(recs.iter().cloned());
        }
    }

    if zone_records.is_empty() {
        warn!(ip = %client_ip, zone = %qname_str, "AXFR: no records for zone");
        return error_info(request, ResponseCode::NXDomain);
    }

    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 60) as u32)
        .unwrap_or(1);

    let soa_record = zone_records.iter()
        .find(|r| r.record_type() == RecordType::SOA)
        .cloned()
        .unwrap_or_else(|| synthetic_soa(&zone_name, serial));

    // AXFR wire format: SOA, all records (non-SOA), SOA.
    let mut answers: Vec<Record> = Vec::with_capacity(zone_records.len() + 2);
    answers.push(soa_record.clone());
    for r in &zone_records {
        if r.record_type() != RecordType::SOA {
            answers.push(r.clone());
        }
    }
    answers.push(soa_record);

    info!(ip = %client_ip, zone = %qname_str, records = zone_records.len(), "AXFR served");

    let mut meta = Metadata::response_from_request(&request.metadata);
    meta.authoritative = true;
    meta.response_code = ResponseCode::NoError;

    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.build(meta, answers.iter(), [], [], []);
    response_handle.send_response(response).await.unwrap_or_else(|e| {
        tracing::error!("AXFR send_response error: {e}");
        error_info(request, ResponseCode::ServFail)
    })
}
