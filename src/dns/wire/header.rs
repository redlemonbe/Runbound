// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! The 12-octet DNS message header (RFC 1035 §4.1.1).
//!
//! The flag word is kept raw with typed accessors. This loses nothing and
//! avoids re-encoding bugs: bits we do not interpret are preserved verbatim on
//! the way through, which is what a forwarder wants.

use super::decoder::Decoder;
use super::encoder::Encoder;
use super::error::WireResult;

/// Fixed 12-byte message header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    /// Raw flag word (QR/Opcode/AA/TC/RD/RA/Z/AD/CD/RCODE). Use the accessors.
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

// Flag bit masks within the 16-bit flag word.
const QR: u16 = 0x8000;
const OPCODE_MASK: u16 = 0x7800;
const OPCODE_SHIFT: u16 = 11;
const AA: u16 = 0x0400;
const TC: u16 = 0x0200;
const RD: u16 = 0x0100;
const RA: u16 = 0x0080;
const AD: u16 = 0x0020;
const CD: u16 = 0x0010;
const RCODE_MASK: u16 = 0x000F;

macro_rules! flag_accessors {
    ($get:ident, $set:ident, $mask:expr) => {
        #[inline]
        pub fn $get(&self) -> bool {
            self.flags & $mask != 0
        }
        #[inline]
        pub fn $set(&mut self, v: bool) {
            if v {
                self.flags |= $mask;
            } else {
                self.flags &= !$mask;
            }
        }
    };
}

impl Header {
    flag_accessors!(qr, set_qr, QR);
    flag_accessors!(aa, set_aa, AA);
    flag_accessors!(tc, set_tc, TC);
    flag_accessors!(rd, set_rd, RD);
    flag_accessors!(ra, set_ra, RA);
    flag_accessors!(ad, set_ad, AD);
    flag_accessors!(cd, set_cd, CD);

    /// 4-bit opcode (bits 11–14).
    #[inline]
    pub fn opcode(&self) -> u8 {
        ((self.flags & OPCODE_MASK) >> OPCODE_SHIFT) as u8
    }
    #[inline]
    pub fn set_opcode(&mut self, op: u8) {
        self.flags = (self.flags & !OPCODE_MASK) | (((op as u16) << OPCODE_SHIFT) & OPCODE_MASK);
    }

    /// Low 4 bits of the response code (EDNS supplies the upper 8 separately).
    #[inline]
    pub fn rcode_low(&self) -> u16 {
        self.flags & RCODE_MASK
    }
    #[inline]
    pub fn set_rcode_low(&mut self, rc: u16) {
        self.flags = (self.flags & !RCODE_MASK) | (rc & RCODE_MASK);
    }

    /// Parse the 12-byte header.
    pub fn parse(d: &mut Decoder) -> WireResult<Header> {
        Ok(Header {
            id: d.u16()?,
            flags: d.u16()?,
            qdcount: d.u16()?,
            ancount: d.u16()?,
            nscount: d.u16()?,
            arcount: d.u16()?,
        })
    }

    /// Emit the 12-byte header.
    pub fn emit(&self, e: &mut Encoder) {
        e.u16(self.id);
        e.u16(self.flags);
        e.u16(self.qdcount);
        e.u16(self.ancount);
        e.u16(self.nscount);
        e.u16(self.arcount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_roundtrip() {
        let mut h = Header::default();
        h.set_qr(true);
        h.set_rd(true);
        h.set_opcode(super::super::consts::opcode::QUERY);
        h.set_rcode_low(super::super::consts::rcode::NXDOMAIN);
        assert!(h.qr() && h.rd() && !h.aa());
        assert_eq!(h.rcode_low(), 3);

        let mut e = Encoder::new();
        h.emit(&mut e);
        let mut d = Decoder::new(e.as_slice());
        let h2 = Header::parse(&mut d).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn opcode_does_not_bleed() {
        let mut h = Header::default();
        h.set_opcode(5); // UPDATE
        h.set_rcode_low(0xF);
        assert_eq!(h.opcode(), 5);
        assert_eq!(h.rcode_low(), 0xF);
        h.set_opcode(0);
        assert_eq!(h.rcode_low(), 0xF, "rcode survived opcode change");
    }
}
