// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Record data: structured for the types Runbound inspects, opaque for the
//! rest.
//!
//! A forwarder/cache must round-trip *every* record type faithfully, including
//! ones it has never heard of, so anything not modelled here is preserved as
//! [`Rdata::Unknown`] — its number plus its raw RDATA bytes (RFC 3597). This
//! is safe because compression inside RDATA is only ever used by the original
//! RFC 1035 types (NS/CNAME/SOA/PTR/MX), all of which *are* modelled and thus
//! decompressed on parse and re-emitted canonically. Modern types never
//! compress names in their RDATA, so their raw bytes are self-contained.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::consts::rtype;
use super::decoder::Decoder;
use super::encoder::Encoder;
use super::error::{WireError, WireResult};
use super::name::Name;

/// Parsed record data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(Name),
    Cname(Name),
    Ptr(Name),
    Soa {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Mx {
        preference: u16,
        exchange: Name,
    },
    /// One or more character-strings (RFC 1035 §3.3.14), each ≤ 255 octets.
    Txt(Vec<Vec<u8>>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Caa {
        flags: u8,
        tag: Vec<u8>,
        value: Vec<u8>,
    },
    /// Any type not modelled above: its numeric type and opaque RDATA.
    Unknown {
        rtype: u16,
        data: Vec<u8>,
    },
}

impl Rdata {
    /// The record type number this RDATA represents.
    pub fn rtype(&self) -> u16 {
        match self {
            Rdata::A(_) => rtype::A,
            Rdata::Aaaa(_) => rtype::AAAA,
            Rdata::Ns(_) => rtype::NS,
            Rdata::Cname(_) => rtype::CNAME,
            Rdata::Ptr(_) => rtype::PTR,
            Rdata::Soa { .. } => rtype::SOA,
            Rdata::Mx { .. } => rtype::MX,
            Rdata::Txt(_) => rtype::TXT,
            Rdata::Srv { .. } => rtype::SRV,
            Rdata::Caa { .. } => rtype::CAA,
            Rdata::Unknown { rtype, .. } => *rtype,
        }
    }

    /// Parse RDATA of the given type and on-wire length. The decoder starts at
    /// the first RDATA octet. On success the decoder has advanced by exactly
    /// the on-wire RDATA size; a structured field that disagrees with
    /// `rdlength` is rejected as malformed.
    pub fn parse(d: &mut Decoder, rtype_num: u16, rdlength: u16) -> WireResult<Rdata> {
        let start = d.pos();
        let end = start
            .checked_add(rdlength as usize)
            .ok_or(WireError::BadRdataLength)?;
        if end > d.buffer().len() {
            return Err(WireError::BadRdataLength);
        }

        // A zero-length RDATA appears in RFC 2136 UPDATE delete records (class
        // ANY/NONE, "delete an RRset" / "delete all"): no typed parser can read
        // an empty body, so represent it as empty opaque RDATA regardless of the
        // record type. (For normal answers a typed RR always carries its fields.)
        if rdlength == 0 {
            return Ok(Rdata::Unknown {
                rtype: rtype_num,
                data: Vec::new(),
            });
        }

        let rd = match rtype_num {
            rtype::A => {
                let s = d.slice(4)?;
                Rdata::A(Ipv4Addr::new(s[0], s[1], s[2], s[3]))
            }
            rtype::AAAA => {
                let s = d.slice(16)?;
                let mut o = [0u8; 16];
                o.copy_from_slice(s);
                Rdata::Aaaa(Ipv6Addr::from(o))
            }
            rtype::NS => Rdata::Ns(Name::parse(d)?),
            rtype::CNAME => Rdata::Cname(Name::parse(d)?),
            rtype::PTR => Rdata::Ptr(Name::parse(d)?),
            rtype::SOA => Rdata::Soa {
                mname: Name::parse(d)?,
                rname: Name::parse(d)?,
                serial: d.u32()?,
                refresh: d.u32()?,
                retry: d.u32()?,
                expire: d.u32()?,
                minimum: d.u32()?,
            },
            rtype::MX => Rdata::Mx {
                preference: d.u16()?,
                exchange: Name::parse(d)?,
            },
            rtype::TXT => {
                let mut strings = Vec::new();
                while d.pos() < end {
                    let len = d.u8()? as usize;
                    if d.pos() + len > end {
                        return Err(WireError::BadCharString);
                    }
                    strings.push(d.slice(len)?.to_vec());
                }
                Rdata::Txt(strings)
            }
            rtype::SRV => Rdata::Srv {
                priority: d.u16()?,
                weight: d.u16()?,
                port: d.u16()?,
                target: Name::parse(d)?,
            },
            rtype::CAA => {
                let flags = d.u8()?;
                let taglen = d.u8()? as usize;
                if d.pos() + taglen > end {
                    return Err(WireError::BadRdataLength);
                }
                let tag = d.slice(taglen)?.to_vec();
                let value = d.slice(end - d.pos())?.to_vec();
                Rdata::Caa { flags, tag, value }
            }
            _ => {
                let data = d.slice(rdlength as usize)?.to_vec();
                Rdata::Unknown {
                    rtype: rtype_num,
                    data,
                }
            }
        };

        // The structured parsers must consume exactly the advertised RDATA.
        // A mismatch means the length and the contents disagree → malformed.
        if d.pos() != end {
            return Err(WireError::BadRdataLength);
        }
        Ok(rd)
    }

    /// Emit RDATA contents (the surrounding RDLENGTH is written by
    /// [`super::record::Record::emit`]). Names embedded here are emitted
    /// uncompressed.
    pub fn emit(&self, e: &mut Encoder) {
        match self {
            Rdata::A(ip) => e.bytes(&ip.octets()),
            Rdata::Aaaa(ip) => e.bytes(&ip.octets()),
            Rdata::Ns(n) | Rdata::Cname(n) | Rdata::Ptr(n) => n.emit_raw(e),
            Rdata::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                mname.emit_raw(e);
                rname.emit_raw(e);
                e.u32(*serial);
                e.u32(*refresh);
                e.u32(*retry);
                e.u32(*expire);
                e.u32(*minimum);
            }
            Rdata::Mx {
                preference,
                exchange,
            } => {
                e.u16(*preference);
                exchange.emit_raw(e);
            }
            Rdata::Txt(strings) => {
                for s in strings {
                    debug_assert!(s.len() <= 255, "character-string exceeds 255");
                    e.u8(s.len() as u8);
                    e.bytes(s);
                }
            }
            Rdata::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                e.u16(*priority);
                e.u16(*weight);
                e.u16(*port);
                target.emit_raw(e);
            }
            Rdata::Caa { flags, tag, value } => {
                e.u8(*flags);
                e.u8(tag.len() as u8);
                e.bytes(tag);
                e.bytes(value);
            }
            Rdata::Unknown { data, .. } => e.bytes(data),
        }
    }

    /// Emit RDATA in DNSSEC canonical form (RFC 4034 §6.2): identical to
    /// [`Rdata::emit`] except every embedded domain name is lowercased. Every
    /// name-bearing type modelled here (NS/CNAME/PTR/SOA/MX/SRV) is on the §6.2
    /// downcase list, so the rule is simply "downcase every name".
    pub fn emit_canonical(&self, e: &mut Encoder) {
        match self {
            Rdata::A(ip) => e.bytes(&ip.octets()),
            Rdata::Aaaa(ip) => e.bytes(&ip.octets()),
            Rdata::Ns(n) | Rdata::Cname(n) | Rdata::Ptr(n) => n.emit_canonical(e),
            Rdata::Soa {
                mname, rname, serial, refresh, retry, expire, minimum,
            } => {
                mname.emit_canonical(e);
                rname.emit_canonical(e);
                e.u32(*serial);
                e.u32(*refresh);
                e.u32(*retry);
                e.u32(*expire);
                e.u32(*minimum);
            }
            Rdata::Mx { preference, exchange } => {
                e.u16(*preference);
                exchange.emit_canonical(e);
            }
            Rdata::Txt(strings) => {
                for s in strings {
                    e.u8(s.len() as u8);
                    e.bytes(s);
                }
            }
            Rdata::Srv { priority, weight, port, target } => {
                e.u16(*priority);
                e.u16(*weight);
                e.u16(*port);
                target.emit_canonical(e);
            }
            Rdata::Caa { flags, tag, value } => {
                e.u8(*flags);
                e.u8(tag.len() as u8);
                e.bytes(tag);
                e.bytes(value);
            }
            Rdata::Unknown { data, .. } => e.bytes(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(rd: Rdata) {
        let rtype_num = rd.rtype();
        let mut e = Encoder::new();
        let at = e.reserve_u16();
        rd.emit(&mut e);
        e.patch_u16_len(at);
        let buf = e.into_vec();
        let mut d = Decoder::new(&buf);
        let rdlength = d.u16().unwrap();
        let got = Rdata::parse(&mut d, rtype_num, rdlength).unwrap();
        assert_eq!(got, rd);
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn a_aaaa() {
        roundtrip(Rdata::A(Ipv4Addr::new(192, 0, 2, 1)));
        roundtrip(Rdata::Aaaa("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn zero_length_rdata_is_empty_unknown() {
        // RFC 2136 "delete an RRset" carries a typed record with RDLENGTH 0.
        // It must parse (as empty opaque RDATA) rather than failing as a
        // truncated A/AAAA/etc.
        let buf: [u8; 0] = [];
        let mut d = Decoder::new(&buf);
        let got = Rdata::parse(&mut d, rtype::A, 0).unwrap();
        assert_eq!(got, Rdata::Unknown { rtype: rtype::A, data: Vec::new() });
    }

    #[test]
    fn names() {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        roundtrip(Rdata::Ns(n("ns1.example.com.")));
        roundtrip(Rdata::Cname(n("alias.example.com.")));
        roundtrip(Rdata::Ptr(n("host.example.com.")));
        roundtrip(Rdata::Mx {
            preference: 10,
            exchange: n("mail.example.com."),
        });
        roundtrip(Rdata::Srv {
            priority: 1,
            weight: 5,
            port: 443,
            target: n("svc.example.com."),
        });
    }

    #[test]
    fn soa() {
        roundtrip(Rdata::Soa {
            mname: Name::from_ascii("ns.example.com.").unwrap(),
            rname: Name::from_ascii("hostmaster.example.com.").unwrap(),
            serial: 2026_06_20,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 300,
        });
    }

    #[test]
    fn txt_and_caa() {
        roundtrip(Rdata::Txt(vec![b"v=spf1 -all".to_vec(), b"second".to_vec()]));
        roundtrip(Rdata::Caa {
            flags: 0,
            tag: b"issue".to_vec(),
            value: b"letsencrypt.org".to_vec(),
        });
    }

    #[test]
    fn unknown_passthrough() {
        roundtrip(Rdata::Unknown {
            rtype: 99,
            data: vec![1, 2, 3, 4, 5, 6, 7],
        });
    }

    #[test]
    fn rejects_rdlength_underrun() {
        // Claim an A record but give 3 bytes.
        let buf = [192, 0, 2];
        let mut d = Decoder::new(&buf);
        assert!(Rdata::parse(&mut d, rtype::A, 3).is_err());
    }
}
