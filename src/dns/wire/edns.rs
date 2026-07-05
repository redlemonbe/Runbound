// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! EDNS(0) — the OPT pseudo-record (RFC 6891).
//!
//! OPT is carried as an ordinary record of type 41 in the additional section,
//! but its fields are overloaded: the owner name is root, CLASS is the
//! requestor's UDP payload size, and TTL packs the extended RCODE, EDNS
//! version, and flags (the DO bit lives in the high bit). This module presents
//! that overloaded record as a typed [`Edns`] without the codec having to know
//! anything special — it just reads/writes a type-41 record.

use super::consts::rtype;
use super::error::{WireError, WireResult};
use super::name::Name;
use super::rdata::Rdata;
use super::record::Record;

/// The DO (DNSSEC OK) bit within the EDNS flag word.
pub const DO_BIT: u16 = 0x8000;

/// A decoded EDNS(0) OPT record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edns {
    /// Requestor's/responder's UDP payload size (OPT CLASS).
    pub udp_payload: u16,
    /// Upper 8 bits of the 12-bit extended RCODE.
    pub ext_rcode: u8,
    /// EDNS version (0).
    pub version: u8,
    /// Flag word; DO is [`DO_BIT`].
    pub flags: u16,
    /// (option-code, option-data) pairs, in order.
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Default for Edns {
    fn default() -> Self {
        Edns {
            udp_payload: 1232, // the DNS-flag-day-2020 recommended default
            ext_rcode: 0,
            version: 0,
            flags: 0,
            options: Vec::new(),
        }
    }
}

impl Edns {
    /// Whether the DO bit is set (client is DNSSEC-aware).
    #[inline]
    pub fn dnssec_ok(&self) -> bool {
        self.flags & DO_BIT != 0
    }

    #[inline]
    pub fn set_dnssec_ok(&mut self, on: bool) {
        if on {
            self.flags |= DO_BIT;
        } else {
            self.flags &= !DO_BIT;
        }
    }

    /// Interpret a type-41 record as EDNS. Returns `None` if `rec` is not OPT.
    pub fn from_record(rec: &Record) -> WireResult<Option<Edns>> {
        if rec.rtype != rtype::OPT {
            return Ok(None);
        }
        let ttl = rec.ttl;
        let ext_rcode = (ttl >> 24) as u8;
        let version = (ttl >> 16) as u8;
        let flags = ttl as u16;

        let mut options = Vec::new();
        if let Rdata::Unknown { data, .. } = &rec.rdata {
            let mut i = 0;
            while i + 4 <= data.len() {
                let code = u16::from_be_bytes([data[i], data[i + 1]]);
                let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                i += 4;
                if i + len > data.len() {
                    return Err(WireError::BadOpt);
                }
                options.push((code, data[i..i + len].to_vec()));
                i += len;
            }
            if i != data.len() {
                return Err(WireError::BadOpt);
            }
        }

        Ok(Some(Edns {
            udp_payload: rec.rclass,
            ext_rcode,
            version,
            flags,
            options,
        }))
    }

    /// Build the type-41 record carrying this EDNS state.
    pub fn to_record(&self) -> Record {
        let mut data = Vec::new();
        for (code, val) in &self.options {
            data.extend_from_slice(&code.to_be_bytes());
            data.extend_from_slice(&(val.len() as u16).to_be_bytes());
            data.extend_from_slice(val);
        }
        let ttl = ((self.ext_rcode as u32) << 24)
            | ((self.version as u32) << 16)
            | (self.flags as u32);
        Record {
            name: Name::root(),
            rtype: rtype::OPT,
            rclass: self.udp_payload.max(512),
            ttl,
            rdata: Rdata::Unknown {
                rtype: rtype::OPT,
                data,
            },
        }
    }
}

/// Convenience: is this record an OPT pseudo-record?
#[inline]
pub fn is_opt(rec: &Record) -> bool {
    rec.rtype == rtype::OPT
}

#[cfg(test)]
mod tests {
    use super::super::consts::class;
    use super::*;

    #[test]
    fn edns_record_roundtrip() {
        let mut ed = Edns {
            udp_payload: 1232,
            ext_rcode: 0,
            version: 0,
            flags: 0,
            options: vec![(10, vec![1, 2, 3, 4, 5, 6, 7, 8])], // COOKIE
        };
        ed.set_dnssec_ok(true);
        let rec = ed.to_record();
        let back = Edns::from_record(&rec).unwrap().unwrap();
        assert_eq!(back, ed);
        assert!(back.dnssec_ok());
    }

    #[test]
    fn non_opt_is_none() {
        let rec = Record {
            name: Name::root(),
            rtype: rtype::A,
            rclass: class::IN,
            ttl: 0,
            rdata: Rdata::A(std::net::Ipv4Addr::UNSPECIFIED),
        };
        assert_eq!(Edns::from_record(&rec).unwrap(), None);
    }

    #[test]
    fn rejects_truncated_option() {
        let rec = Record {
            name: Name::root(),
            rtype: rtype::OPT,
            rclass: 1232,
            ttl: 0,
            rdata: Rdata::Unknown {
                rtype: rtype::OPT,
                data: vec![0, 10, 0, 8, 1, 2], // claims 8 bytes, gives 2
            },
        };
        assert_eq!(Edns::from_record(&rec), Err(WireError::BadOpt));
    }
}
