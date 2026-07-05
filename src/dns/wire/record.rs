// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! A resource record (RFC 1035 §4.1.3): owner name, type, class, TTL, RDATA.

use super::decoder::Decoder;
use super::encoder::Encoder;
use super::error::WireResult;
use super::name::Name;
use super::rdata::Rdata;

/// A single resource record from any section.
///
/// `rtype` and `rclass` are stored raw rather than derived from `rdata`, so an
/// OPT pseudo-record (whose class is a UDP payload size and whose TTL packs the
/// extended RCODE/version/flags) survives a round trip untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Rdata,
}

impl Record {
    pub fn parse(d: &mut Decoder) -> WireResult<Record> {
        let name = Name::parse(d)?;
        let rtype = d.u16()?;
        let rclass = d.u16()?;
        let ttl = d.u32()?;
        let rdlength = d.u16()?;
        let rdata = Rdata::parse(d, rtype, rdlength)?;
        Ok(Record {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        })
    }

    pub fn emit(&self, e: &mut Encoder) {
        self.name.emit(e); // owner names may be compressed
        e.u16(self.rtype);
        e.u16(self.rclass);
        e.u32(self.ttl);
        let at = e.reserve_u16();
        self.rdata.emit(e);
        e.patch_u16_len(at);
    }
}

#[cfg(test)]
mod tests {
    use super::super::consts::{class, rtype};
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn record_roundtrip() {
        let r = Record {
            name: Name::from_ascii("www.example.com.").unwrap(),
            rtype: rtype::A,
            rclass: class::IN,
            ttl: 300,
            rdata: Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let mut e = Encoder::new();
        r.emit(&mut e);
        let buf = e.into_vec();
        let mut d = Decoder::new(&buf);
        assert_eq!(Record::parse(&mut d).unwrap(), r);
        assert_eq!(d.remaining(), 0);
    }
}
