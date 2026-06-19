// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! The question section entry (RFC 1035 §4.1.2): a name, a 16-bit type, and a
//! 16-bit class. Type and class are kept raw so unknown values pass through.

use super::consts;
use super::decoder::Decoder;
use super::encoder::Encoder;
use super::error::WireResult;
use super::name::Name;

/// One entry of the question section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    /// A standard IN-class query for `name`/`qtype`.
    pub fn new(name: Name, qtype: u16) -> Self {
        Question {
            name,
            qtype,
            qclass: consts::class::IN,
        }
    }

    pub fn parse(d: &mut Decoder) -> WireResult<Question> {
        let name = Name::parse(d)?;
        let qtype = d.u16()?;
        let qclass = d.u16()?;
        Ok(Question {
            name,
            qtype,
            qclass,
        })
    }

    pub fn emit(&self, e: &mut Encoder) {
        self.name.emit(e);
        e.u16(self.qtype);
        e.u16(self.qclass);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let q = Question::new(Name::from_ascii("example.com.").unwrap(), consts::rtype::A);
        let mut e = Encoder::new();
        q.emit(&mut e);
        let mut d = Decoder::new(e.as_slice());
        assert_eq!(Question::parse(&mut d).unwrap(), q);
        assert_eq!(d.remaining(), 0);
    }
}
