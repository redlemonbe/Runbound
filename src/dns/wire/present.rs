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
        _ => return None,
    };

    let rtype_num = match type_str.as_str() {
        "A" => rtype::A,
        "AAAA" => rtype::AAAA,
        "NS" => rtype::NS,
        "CNAME" => rtype::CNAME,
        "PTR" => rtype::PTR,
        "MX" => rtype::MX,
        "TXT" => rtype::TXT,
        "SRV" => rtype::SRV,
        _ => return None,
    };

    Some(Record {
        name,
        rtype: rtype_num,
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
        assert!(parse_rr_line("x.example. 300 TLSA 3 0 1 abcdef").is_none());
    }

    #[test]
    fn appends_root_to_owner() {
        let r = parse_rr_line("bare A 10.0.0.1").unwrap();
        assert_eq!(r.name.to_ascii(), "bare.");
    }
}
