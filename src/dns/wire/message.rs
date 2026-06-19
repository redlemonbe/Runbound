// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! A whole DNS message: header plus the four sections.
//!
//! [`Message::parse`] is the single entry point for untrusted input. It never
//! panics and never loops unboundedly: section counts are honoured but every
//! record read is bounds-checked, so an inflated count simply runs into an
//! `UnexpectedEof`. Trailing bytes after the last record are ignored (some
//! middleboxes pad), which matches what permissive resolvers do.

use super::decoder::Decoder;
use super::edns::Edns;
use super::encoder::Encoder;
use super::error::WireResult;
use super::header::Header;
use super::question::Question;
use super::record::Record;

/// A parsed (or to-be-built) DNS message.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

/// Initial capacity cap so a hostile header count cannot make us pre-allocate
/// a huge vector before any bytes are validated.
const PREALLOC_CAP: usize = 16;

fn parse_records(d: &mut Decoder, count: u16) -> WireResult<Vec<Record>> {
    let mut v = Vec::with_capacity((count as usize).min(PREALLOC_CAP));
    for _ in 0..count {
        v.push(Record::parse(d)?);
    }
    Ok(v)
}

impl Message {
    /// Parse a complete message from a datagram or TCP payload.
    pub fn parse(buf: &[u8]) -> WireResult<Message> {
        let mut d = Decoder::new(buf);
        let header = Header::parse(&mut d)?;

        let mut questions = Vec::with_capacity((header.qdcount as usize).min(PREALLOC_CAP));
        for _ in 0..header.qdcount {
            questions.push(Question::parse(&mut d)?);
        }
        let answers = parse_records(&mut d, header.ancount)?;
        let authority = parse_records(&mut d, header.nscount)?;
        let additional = parse_records(&mut d, header.arcount)?;

        Ok(Message {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// Serialize to wire form. The section counts in the emitted header are
    /// derived from the actual sections, so callers cannot desynchronize them.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_with(true)
    }

    /// Serialize without name compression (canonical, pointer-free output).
    pub fn encode_uncompressed(&self) -> Vec<u8> {
        self.encode_with(false)
    }

    fn encode_with(&self, compress: bool) -> Vec<u8> {
        let mut e = if compress {
            Encoder::new()
        } else {
            Encoder::uncompressed()
        };
        let mut h = self.header;
        h.qdcount = self.questions.len() as u16;
        h.ancount = self.answers.len() as u16;
        h.nscount = self.authority.len() as u16;
        h.arcount = self.additional.len() as u16;
        h.emit(&mut e);
        for q in &self.questions {
            q.emit(&mut e);
        }
        for r in &self.answers {
            r.emit(&mut e);
        }
        for r in &self.authority {
            r.emit(&mut e);
        }
        for r in &self.additional {
            r.emit(&mut e);
        }
        e.into_vec()
    }

    /// The first (and conventionally only) question, if any.
    pub fn first_question(&self) -> Option<&Question> {
        self.questions.first()
    }

    /// Decode the EDNS OPT record from the additional section, if present.
    pub fn edns(&self) -> WireResult<Option<Edns>> {
        for rec in &self.additional {
            if let Some(ed) = Edns::from_record(rec)? {
                return Ok(Some(ed));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::super::consts::{class, rtype};
    use super::super::name::Name;
    use super::super::rdata::Rdata;
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_query() -> Message {
        let mut h = Header {
            id: 0x1234,
            ..Default::default()
        };
        h.set_rd(true);
        Message {
            header: h,
            questions: vec![Question::new(
                Name::from_ascii("www.example.com.").unwrap(),
                rtype::A,
            )],
            ..Default::default()
        }
    }

    #[test]
    fn query_roundtrip() {
        let m = sample_query();
        let wire = m.encode();
        let back = Message::parse(&wire).unwrap();
        assert_eq!(back.header.id, 0x1234);
        assert!(back.header.rd());
        assert_eq!(back.questions, m.questions);
    }

    #[test]
    fn response_with_answers_roundtrips() {
        let mut m = sample_query();
        m.header.set_qr(true);
        m.answers.push(Record {
            name: Name::from_ascii("www.example.com.").unwrap(),
            rtype: rtype::A,
            rclass: class::IN,
            ttl: 300,
            rdata: Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
        });
        m.answers.push(Record {
            name: Name::from_ascii("www.example.com.").unwrap(),
            rtype: rtype::CNAME,
            rclass: class::IN,
            ttl: 300,
            rdata: Rdata::Cname(Name::from_ascii("cdn.example.net.").unwrap()),
        });
        let wire = m.encode();
        let back = Message::parse(&wire).unwrap();
        assert_eq!(back, normalize_counts(m));
    }

    // After encode/parse the header counts equal the section lengths; reflect
    // that in the expected value.
    fn normalize_counts(mut m: Message) -> Message {
        m.header.qdcount = m.questions.len() as u16;
        m.header.ancount = m.answers.len() as u16;
        m.header.nscount = m.authority.len() as u16;
        m.header.arcount = m.additional.len() as u16;
        m
    }

    #[test]
    fn inflated_count_is_eof_not_panic() {
        let m = sample_query();
        let mut wire = m.encode();
        // Claim 100 answers that are not there.
        wire[6] = 0;
        wire[7] = 100;
        assert!(Message::parse(&wire).is_err());
    }

    #[test]
    fn edns_extracted_from_additional() {
        let mut m = sample_query();
        let ed = Edns::default();
        m.additional.push(ed.to_record());
        let wire = m.encode();
        let back = Message::parse(&wire).unwrap();
        assert!(back.edns().unwrap().is_some());
    }
}
