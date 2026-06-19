// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Numeric DNS constants: record types, classes, opcodes, response codes.
//!
//! These are kept as bare `u16`/`u8` with named constants rather than `enum`s.
//! A forwarder and cache must pass through record types it does not understand
//! (RFC 3597), so the codec never rejects an unknown type — it preserves the
//! number and treats the RDATA opaquely. Named constants exist only for the
//! types the slow path inspects.

/// DNS record types (RFC 1035 and successors).
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const HINFO: u16 = 13;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const NAPTR: u16 = 35;
    pub const OPT: u16 = 41;
    pub const DS: u16 = 43;
    pub const SSHFP: u16 = 44;
    pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47;
    pub const DNSKEY: u16 = 48;
    pub const NSEC3: u16 = 50;
    pub const NSEC3PARAM: u16 = 51;
    pub const TLSA: u16 = 52;
    pub const SVCB: u16 = 64;
    pub const HTTPS: u16 = 65;
    pub const CAA: u16 = 257;
    pub const ANY: u16 = 255;
    pub const AXFR: u16 = 252;
    pub const IXFR: u16 = 251;
}

/// DNS classes. Only IN is used in practice; the rest exist for completeness.
pub mod class {
    pub const IN: u16 = 1;
    pub const CH: u16 = 3;
    pub const HS: u16 = 4;
    pub const NONE: u16 = 254;
    pub const ANY: u16 = 255;
}

/// Opcodes (header bits 11–14).
pub mod opcode {
    pub const QUERY: u8 = 0;
    pub const IQUERY: u8 = 1;
    pub const STATUS: u8 = 2;
    pub const NOTIFY: u8 = 4;
    pub const UPDATE: u8 = 5;
}

/// Response codes (the low 4 header bits; EDNS extends to 12 bits).
pub mod rcode {
    pub const NOERROR: u16 = 0;
    pub const FORMERR: u16 = 1;
    pub const SERVFAIL: u16 = 2;
    pub const NXDOMAIN: u16 = 3;
    pub const NOTIMP: u16 = 4;
    pub const REFUSED: u16 = 5;
    pub const BADVERS: u16 = 16; // also BADSIG; EDNS extended
    pub const BADCOOKIE: u16 = 23;
}

/// Render a record type as its mnemonic, or `TYPE<n>` for unknown types
/// (RFC 3597 §5 presentation).
pub fn rtype_name(t: u16) -> String {
    use rtype::*;
    let s = match t {
        A => "A",
        NS => "NS",
        CNAME => "CNAME",
        SOA => "SOA",
        PTR => "PTR",
        HINFO => "HINFO",
        MX => "MX",
        TXT => "TXT",
        AAAA => "AAAA",
        SRV => "SRV",
        NAPTR => "NAPTR",
        OPT => "OPT",
        DS => "DS",
        SSHFP => "SSHFP",
        RRSIG => "RRSIG",
        NSEC => "NSEC",
        DNSKEY => "DNSKEY",
        NSEC3 => "NSEC3",
        NSEC3PARAM => "NSEC3PARAM",
        TLSA => "TLSA",
        SVCB => "SVCB",
        HTTPS => "HTTPS",
        CAA => "CAA",
        ANY => "ANY",
        AXFR => "AXFR",
        IXFR => "IXFR",
        _ => return format!("TYPE{t}"),
    };
    s.to_string()
}
