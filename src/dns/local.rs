// Local zone authority — in-memory, instant updates, O(1) lookup.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::str::FromStr;

use hickory_proto::rr::{
    rdata::{self, CNAME},
    LowerName, Name, RData, Record, RecordType,
};

use crate::config::parser::{LocalData, LocalZone};

#[derive(Debug, Clone, PartialEq)]
pub enum ZoneAction {
    Refuse,
    NxDomain,
    Static,
    // Mirrors Unbound's "redirect" zone type — reserved for future CNAME-based redirect support
    #[allow(dead_code)]
    Redirect,
}

impl From<&str> for ZoneAction {
    fn from(s: &str) -> Self {
        match s {
            "refuse" | "inform_deny" => ZoneAction::Refuse,
            "always_nxdomain" | "nxdomain" => ZoneAction::NxDomain,
            "static" | "redirect" => ZoneAction::Static,
            _ => ZoneAction::Refuse,
        }
    }
}

/// In-memory local zone set.
/// zones:   HashMap for O(1) exact lookup + parent-walking for subdomain coverage.
/// records: HashMap<Name, Vec<Record>> for O(1) name lookup.
///          Clone happens only on API writes (rare), never on DNS reads (ArcSwap).
#[derive(Debug, Default, Clone)]
pub struct LocalZoneSet {
    pub zones:   HashMap<Name, ZoneAction>,
    pub records: HashMap<Name, Vec<Record>>,
}

impl LocalZoneSet {
    pub fn from_config(zones: &[LocalZone], data: &[LocalData]) -> Self {
        let mut map = HashMap::with_capacity(zones.len());
        for z in zones {
            let name_str = if z.name.ends_with('.') {
                z.name.clone()
            } else {
                format!("{}.", z.name)
            };
            if let Ok(n) = Name::from_str(&name_str) {
                map.insert(n, ZoneAction::from(z.zone_type.as_str()));
            }
        }
        // Build record map: O(1) name lookup replaces O(n) Vec scan on every query.
        // Also sets implicit static zone for each local-data name (Unbound behaviour).
        let mut record_map: HashMap<Name, Vec<Record>> = HashMap::new();
        for d in data {
            if let Some(rec) = parse_local_data(&d.rr) {
                let name = rec.name().clone();
                map.entry(name.clone()).or_insert(ZoneAction::Static);
                record_map.entry(name).or_default().push(rec);
            }
        }

        Self { zones: map, records: record_map }
    }

    /// Override any existing zone action for `name`.
    /// Unlike `add_zone` (which uses `or_insert` and ignores an existing entry),
    /// this always replaces — ensuring blacklist entries shadow static zones.
    #[inline]
    pub fn override_zone(&mut self, name: &str, action: ZoneAction) {
        let name_str = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{}.", name)
        };
        if let Ok(n) = Name::from_str(&name_str) {
            self.zones.insert(n, action);
        }
    }

    #[inline]
    pub fn remove_zone(&mut self, name: &str) {
        let name_str = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{}.", name)
        };
        if let Ok(n) = Name::from_str(&name_str) {
            self.zones.remove(&n);
        }
    }

    /// Find matching zone for a query name.
    /// Walks up the name hierarchy: "www.evil.com." → "evil.com." → "com." → "."
    /// Returns the most-specific match (exact domain wins over parent zone).
    ///
    /// Accepts `&LowerName` directly — avoids the `Name::from(lower.clone())`
    /// allocation that callers previously had to perform before each lookup.
    /// `LowerName: Deref<Target=Name>`, so `&**query` gives a `&Name` for the
    /// HashMap without any heap allocation on the exact-match fast path.
    #[inline]
    pub fn find(&self, query: &LowerName) -> Option<ZoneAction> {
        // Fast path: exact match — LowerName: Borrow<Name>, zero allocation.
        if let Some(action) = self.zones.get(query.borrow() as &Name) {
            return Some(action.clone());
        }
        if query.is_root() {
            return None;
        }
        // Slow path: walk up the label hierarchy via LowerName::base_name().
        // One LowerName allocation per label trimmed — same cost as before.
        let mut name = query.base_name();
        loop {
            if let Some(action) = self.zones.get(name.borrow() as &Name) {
                return Some(action.clone());
            }
            if name.is_root() {
                break;
            }
            name = name.base_name();
        }
        None
    }

    /// Exact local-data records for a query. O(1) name lookup + O(m) type filter
    /// where m is the number of records for that name (typically 1–5).
    #[inline(always)]
    pub fn local_records(&self, query_name: &LowerName, rtype: RecordType) -> Vec<&Record> {
        self.records.get(query_name.borrow() as &Name)
            .map(|recs| recs.iter().filter(|r| r.record_type() == rtype).collect())
            .unwrap_or_default()
    }

    /// True if the name has at least one record of any type. O(1) HashMap lookup.
    /// Used to distinguish NODATA (name exists, wrong type → NOERROR empty)
    /// from NXDOMAIN (name itself does not exist) — RFC 1035 §3.7.
    #[inline(always)]
    pub fn name_has_records(&self, name: &LowerName) -> bool {
        self.records.contains_key(name.borrow() as &Name)
    }
}

/// Parse a `local-data` RR string into a hickory Record.
/// Supports: A, AAAA, CNAME, TXT, PTR, NS, MX, SRV, CAA, NAPTR, SSHFP, TLSA
/// Format:  name [ttl] TYPE rdata...
pub fn parse_local_data(rr: &str) -> Option<Record> {
    let parts: Vec<&str> = rr.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // Parse: name [ttl] [class] TYPE rdata
    // Both TTL and class (IN/CH/HS) are optional and can appear in any order.
    let mut idx = 1usize;
    let mut ttl = 300u32;
    // Consume optional TTL (numeric)
    if parts[idx].parse::<u32>().is_ok() {
        ttl = parts[idx].parse().ok()?;
        idx += 1;
    }
    // Consume optional DNS class (IN / CH / HS / ANY)
    if idx < parts.len() {
        let up = parts[idx].to_uppercase();
        if up == "IN" || up == "CH" || up == "HS" || up == "ANY" {
            idx += 1;
        }
    }
    if idx >= parts.len() { return None; }
    let name_str  = parts[0];
    let type_str  = parts[idx];
    let rest      = &parts[idx + 1..];

    if rest.is_empty() { return None; }

    // Always produce an FQDN Name (with trailing dot) so it round-trips with
    // the names that hickory_proto parses from the wire (which are always FQDN).
    // Names without a trailing dot hash differently → HashMap lookup miss.
    let name_fqdn = if name_str.ends_with('.') {
        name_str.to_string()
    } else {
        format!("{}.", name_str)
    };
    let name = Name::from_str(&name_fqdn).ok()?;
    let joined = rest.join(" ");

    let rdata: RData = match type_str.to_uppercase().as_str() {
        "A"     => RData::A(rest[0].parse().ok()?),
        "AAAA"  => RData::AAAA(rest[0].parse().ok()?),
        "CNAME" => RData::CNAME(CNAME(Name::from_str(rest[0]).ok()?)),
        "PTR"   => RData::PTR(rdata::PTR(Name::from_str(rest[0]).ok()?)),
        "NS"    => RData::NS(rdata::NS(Name::from_str(rest[0]).ok()?)),
        "TXT"   => {
            let txt = joined.trim_matches('"').to_string();
            RData::TXT(rdata::TXT::new(vec![txt]))
        }
        // MX: priority exchange
        "MX"    => {
            let pref: u16 = rest[0].parse().ok()?;
            let exch = Name::from_str(rest[1]).ok()?;
            RData::MX(rdata::MX::new(pref, exch))
        }
        // SRV: priority weight port target
        "SRV"   => {
            let priority: u16 = rest[0].parse().ok()?;
            let weight:   u16 = rest[1].parse().ok()?;
            let port:     u16 = rest[2].parse().ok()?;
            let target        = Name::from_str(rest[3]).ok()?;
            RData::SRV(rdata::SRV::new(priority, weight, port, target))
        }
        // CAA: flags tag value
        "CAA"   => {
            let flags: u8 = rest[0].parse().ok()?;
            let tag_str    = rest[1];
            let val        = rest[2..].join(" ").trim_matches('"').to_string();
            let issuer_crit = flags & 0x80 != 0;
            match tag_str {
                "issue"     => RData::CAA(rdata::CAA::new_issue(issuer_crit,
                    Name::from_str(&val).ok(), vec![])),
                "issuewild" => RData::CAA(rdata::CAA::new_issuewild(issuer_crit,
                    Name::from_str(&val).ok(), vec![])),
                _           => return None,
            }
        }
        // SSHFP: algorithm fp_type hex_fingerprint
        "SSHFP" => {
            use hickory_proto::rr::rdata::sshfp::{Algorithm, FingerprintType, SSHFP};
            let algo: u8   = rest[0].parse().ok()?;
            let fpt:  u8   = rest[1].parse().ok()?;
            let fp_hex     = rest[2];
            let fp_bytes   = hex::decode(fp_hex).ok()?;
            let algorithm  = Algorithm::from(algo);
            let fp_type    = FingerprintType::from(fpt);
            RData::SSHFP(SSHFP::new(algorithm, fp_type, fp_bytes))
        }
        // TLSA: cert_usage selector matching_type cert_data_hex
        "TLSA"  => {
            use hickory_proto::rr::rdata::tlsa::{CertUsage, Selector, Matching, TLSA};
            let cu: u8  = rest[0].parse().ok()?;
            let sel: u8 = rest[1].parse().ok()?;
            let mt: u8  = rest[2].parse().ok()?;
            let data    = hex::decode(rest[3]).ok()?;
            RData::TLSA(TLSA::new(
                CertUsage::from(cu), Selector::from(sel), Matching::from(mt), data))
        }
        // NAPTR: order preference "flags" "services" "regexp" replacement
        // RFC 2915 — used for ENUM, SIP, URI resolution
        "NAPTR" => {
            use hickory_proto::rr::rdata::NAPTR;
            let order:      u16  = rest[0].parse().ok()?;
            let preference: u16  = rest[1].parse().ok()?;
            let flags_raw        = rest[2].trim_matches('"');
            let services_raw     = rest[3].trim_matches('"');
            let regexp_raw       = rest[4].trim_matches('"');
            let replacement      = Name::from_str(rest[5]).ok()?;
            RData::NAPTR(NAPTR::new(
                order,
                preference,
                flags_raw.as_bytes().to_vec().into_boxed_slice(),
                services_raw.as_bytes().to_vec().into_boxed_slice(),
                regexp_raw.as_bytes().to_vec().into_boxed_slice(),
                replacement,
            ))
        }
        _ => return None,
    };

    let mut record = Record::new();
    record
        .set_name(name)
        .set_rr_type(rdata.record_type())
        .set_data(Some(rdata))
        .set_ttl(ttl);
    Some(record)
}
