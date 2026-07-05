// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Presentation-format (master-file style) parsing of a single resource record
//! into a [`Record`], hickory-free.
//!
//! This is the codec side of `local-data` configuration: a line of the form
//!
//! ```text
//! name [ttl] [class] TYPE rdata...
//! ```
//!
//! becomes a wire [`Record`]. It mirrors `dns::local::parse_local_data` (which
//! builds a hickory `Record`) and is proven byte-for-byte equivalent to it by
//! the differential oracle, so phase 2 can build the zone store from our own
//! types instead of hickory's.
//!
//! Common types are modelled structurally; rarer ones (SSHFP/TLSA/NAPTR/…) are
//! not handled here yet and return `None`, exactly where the caller still falls
//! back to the hickory parser during the migration.

use super::consts::{class, rtype};
use super::name::Name;
use super::rdata::Rdata;
use super::record::Record;

fn fqdn(s: &str) -> String {
    if s.ends_with('.') {
        s.to_string()
    } else {
        format!("{s}.")
    }
}

/// Parse one presentation-format RR line into a [`Record`], or `None` if the
/// line is malformed or its type is not yet modelled here.
pub fn parse_rr_line(rr: &str) -> Option<Record> {
    let parts: Vec<&str> = rr.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // name [ttl] [class] TYPE rdata...  — ttl and class are optional, in order.
    let mut idx = 1usize;
    let mut ttl = 300u32;
    if let Ok(t) = parts[idx].parse::<u32>() {
        ttl = t;
        idx += 1;
    }
    if idx < parts.len() {
        let up = parts[idx].to_ascii_uppercase();
        if up == "IN" || up == "CH" || up == "HS" || up == "ANY" {
            idx += 1;
        }
    }
    if idx >= parts.len() {
        return None;
    }

    let name = Name::from_ascii(&fqdn(parts[0])).ok()?;
    let type_str = parts[idx].to_ascii_uppercase();
    let rest = &parts[idx + 1..];
    if rest.is_empty() {
        return None;
    }

    let rdata = match type_str.as_str() {
        "A" => Rdata::A(rest[0].parse().ok()?),
        "AAAA" => Rdata::Aaaa(rest[0].parse().ok()?),
        "NS" => Rdata::Ns(Name::from_ascii(rest[0]).ok()?),
        "CNAME" => Rdata::Cname(Name::from_ascii(rest[0]).ok()?),
        // SOA: mname rname serial refresh retry expire minimum (RFC 1035 §3.3.13).
        // Needed so AXFR can serve the zone's configured apex SOA rather than a
        // synthesised one.
        "SOA" => {
            let mname = Name::from_ascii(rest.first()?).ok()?;
            let rname = Name::from_ascii(rest.get(1)?).ok()?;
            let serial: u32 = rest.get(2)?.parse().ok()?;
            let refresh: u32 = rest.get(3)?.parse().ok()?;
            let retry: u32 = rest.get(4)?.parse().ok()?;
            let expire: u32 = rest.get(5)?.parse().ok()?;
            let minimum: u32 = rest.get(6)?.parse().ok()?;
            Rdata::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }
        }
        "PTR" => Rdata::Ptr(Name::from_ascii(rest[0]).ok()?),
        "MX" => {
            let preference: u16 = rest[0].parse().ok()?;
            let exchange = Name::from_ascii(rest.get(1)?).ok()?;
            Rdata::Mx {
                preference,
                exchange,
            }
        }
        "TXT" => {
            // One character-string, quotes stripped (matches parse_local_data).
            let txt = rest.join(" ");
            let txt = txt.trim_matches('"');
            Rdata::Txt(vec![txt.as_bytes().to_vec()])
        }
        "SRV" => {
            let priority: u16 = rest[0].parse().ok()?;
            let weight: u16 = rest.get(1)?.parse().ok()?;
            let port: u16 = rest.get(2)?.parse().ok()?;
            let target = Name::from_ascii(rest.get(3)?).ok()?;
            Rdata::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        // CAA: flags tag value. hickory only re-encodes the critical bit of the
        // flags (new_issue/new_issuewild), so mask to 0x80 to stay byte-equal;
        // the value is the issuer domain with no trailing root dot.
        "CAA" => {
            let flags = rest[0].parse::<u8>().ok()? & 0x80;
            let tag = rest.get(1)?;
            if *tag != "issue" && *tag != "issuewild" {
                return None;
            }
            let value = rest[2..].join(" ");
            let value = value.trim_matches('"').trim_end_matches('.');
            Rdata::Caa {
                flags,
                tag: tag.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            }
        }
        // SSHFP: algorithm fp_type hex_fingerprint → opaque wire RDATA.
        "SSHFP" => {
            let algo: u8 = rest[0].parse().ok()?;
            let fp_type: u8 = rest.get(1)?.parse().ok()?;
            let fp = hex::decode(rest.get(2)?).ok()?;
            let mut data = vec![algo, fp_type];
            data.extend_from_slice(&fp);
            Rdata::Unknown {
                rtype: rtype::SSHFP,
                data,
            }
        }
        // TLSA: cert_usage selector matching_type hex_cert_data → opaque RDATA.
        "TLSA" => {
            let cert_usage: u8 = rest[0].parse().ok()?;
            let selector: u8 = rest.get(1)?.parse().ok()?;
            let matching: u8 = rest.get(2)?.parse().ok()?;
            let cert = hex::decode(rest.get(3)?).ok()?;
            let mut data = vec![cert_usage, selector, matching];
            data.extend_from_slice(&cert);
            Rdata::Unknown {
                rtype: rtype::TLSA,
                data,
            }
        }
        // NAPTR: order preference "flags" "services" "regexp" replacement.
        // Char-strings then an uncompressed replacement name (RFC 3403).
        "NAPTR" => {
            let order: u16 = rest[0].parse().ok()?;
            let preference: u16 = rest.get(1)?.parse().ok()?;
            let mut data = Vec::new();
            data.extend_from_slice(&order.to_be_bytes());
            data.extend_from_slice(&preference.to_be_bytes());
            for i in 2..=4 {
                let s = rest.get(i)?.trim_matches('"');
                if s.len() > 255 {
                    return None;
                }
                data.push(s.len() as u8);
                data.extend_from_slice(s.as_bytes());
            }
            let replacement = Name::from_ascii(rest.get(5)?).ok()?;
            data.extend_from_slice(replacement.wire());
            Rdata::Unknown {
                rtype: rtype::NAPTR,
                data,
            }
        }
        _ => return None,
    };

    Some(Record {
        name,
        rtype: rdata.rtype(),
        rclass: class::IN,
        ttl,
        rdata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_types() {
        assert!(parse_rr_line("host.example.com. 300 A 192.0.2.1").is_some());
        assert!(parse_rr_line("host.example.com. AAAA 2001:db8::1").is_some());
        assert!(parse_rr_line("example.com. 3600 IN MX 10 mail.example.com.").is_some());
        assert!(parse_rr_line("www.example.com. CNAME cdn.example.net.").is_some());
    }

    #[test]
    fn ttl_and_class_optional_in_order() {
        let r = parse_rr_line("a.example. 600 IN A 10.0.0.1").unwrap();
        assert_eq!(r.ttl, 600);
        assert_eq!(r.rtype, rtype::A);
        let r2 = parse_rr_line("a.example. A 10.0.0.1").unwrap();
        assert_eq!(r2.ttl, 300); // default
    }

    #[test]
    fn unmodelled_type_is_none() {
        // DNSKEY is not a local-data type either parser models.
        assert!(parse_rr_line("x.example. 300 DNSKEY 256 3 8 AwEAAa==").is_none());
    }

    #[test]
    fn appends_root_to_owner() {
        let r = parse_rr_line("bare A 10.0.0.1").unwrap();
        assert_eq!(r.name.to_ascii(), "bare.");
    }

    #[test]
    fn parses_soa() {
        let r = parse_rr_line(
            "example.test. 3600 IN SOA ns1.example.test. admin.example.test. 2026010101 3600 900 604800 300",
        )
        .unwrap();
        assert_eq!(r.rtype, rtype::SOA);
        match r.rdata {
            Rdata::Soa { serial, refresh, retry, expire, minimum, .. } => {
                assert_eq!(serial, 2026010101);
                assert_eq!(refresh, 3600);
                assert_eq!(retry, 900);
                assert_eq!(expire, 604800);
                assert_eq!(minimum, 300);
            }
            other => panic!("expected SOA, got {other:?}"),
        }
    }
    // Note: our SOA RDATA wire encoding is held byte-identical to hickory by the
    // `oracle_soa_authority` differential test in `wire::oracle`.
}
