// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Bridge between our `wire::Record` and hickory's `Record`.
//!
//! The zone store is keyed on `wire::Record`. hickory is no longer a runtime
//! dependency (it is a `[dev-dependencies]`-only differential oracle); this
//! bridge converts between `wire::Record` and hickory's `Record` for the
//! remaining hickory-typed code paths (tests/oracles and not-yet-migrated
//! mutation inputs). The DNSSEC signer (`zone_signer`) is fully in-house.
//!
//! Both directions go through the wire: a record is serialized by one side and
//! parsed by the other. That is exactly the path the differential oracle proves
//! correct, so the bridge inherits that correctness. It is intended to be
//! deleted once hickory is gone from the default build.

// Ahead-of-use: called by tests now, and by the mutation
// sites / DNSSEC signer as they are wired in. Removed with the module.
#![allow(dead_code)]

use hickory_proto::rr::Record as HRecord;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

use crate::dns::wire;

/// `wire::Record` → hickory `Record`: emit ours, parse with hickory.
///
/// Returns `None` only if the record cannot be represented on the wire, which
/// for a well-formed record never happens.
pub fn to_hickory(r: &wire::Record) -> Option<HRecord> {
    let mut enc = wire::Encoder::uncompressed();
    r.emit(&mut enc);
    let bytes = enc.into_vec();
    let mut dec = BinDecoder::new(&bytes);
    HRecord::read(&mut dec).ok()
}

/// hickory `Record` → `wire::Record`: emit hickory, parse with ours.
pub fn from_hickory(r: &HRecord) -> Option<wire::Record> {
    let mut bytes = Vec::new();
    {
        let mut enc = BinEncoder::new(&mut bytes);
        r.emit(&mut enc).ok()?;
    }
    wire::Record::parse(&mut wire::Decoder::new(&bytes)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{consts, Name, Rdata};
    use std::net::Ipv4Addr;

    fn sample() -> wire::Record {
        wire::Record {
            name: Name::from_ascii("www.example.com.").unwrap(),
            rtype: consts::rtype::A,
            rclass: consts::class::IN,
            ttl: 300,
            rdata: Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    #[test]
    fn wire_to_hickory_and_back() {
        let r = sample();
        let h = to_hickory(&r).expect("to hickory");
        let back = from_hickory(&h).expect("back to wire");
        assert_eq!(back, r);
    }

    #[test]
    fn hickory_to_wire_and_back() {
        use hickory_proto::rr::rdata::{CNAME, MX};
        use hickory_proto::rr::{Name as HName, RData, Record as HRec};
        for h in [
            HRec::from_rdata(
                HName::from_ascii("a.example.com.").unwrap(),
                60,
                RData::CNAME(CNAME(HName::from_ascii("b.example.net.").unwrap())),
            ),
            HRec::from_rdata(
                HName::from_ascii("example.com.").unwrap(),
                3600,
                RData::MX(MX::new(10, HName::from_ascii("mail.example.com.").unwrap())),
            ),
        ] {
            let w = from_hickory(&h).expect("to wire");
            let back = to_hickory(&w).expect("back to hickory");
            // Compare via wire bytes: hickory Display/eq can differ on IDN etc.
            let mut a = Vec::new();
            h.emit(&mut BinEncoder::new(&mut a)).unwrap();
            let mut b = Vec::new();
            back.emit(&mut BinEncoder::new(&mut b)).unwrap();
            assert_eq!(a, b);
        }
    }
}
