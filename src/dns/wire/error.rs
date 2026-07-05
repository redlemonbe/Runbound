// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Error type for the hand-rolled DNS wire codec.
//!
//! Every fallible decode/encode path returns [`WireError`]. The variants are
//! deliberately fine-grained so that fuzzing and the differential oracle can
//! assert *why* a malformed packet was rejected, and so that the slow path can
//! map specific failures onto the right RCODE (FORMERR vs NOTIMP, etc.).

use std::fmt;

/// A DNS wire-format decode or encode failure.
///
/// All variants are non-panicking: the codec never indexes out of bounds and
/// never loops unboundedly. A malformed or hostile packet always resolves to
/// one of these, never to a crash or hang.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Ran off the end of the buffer while reading a fixed-size field or slice.
    UnexpectedEof,
    /// A label length octet exceeded 63 (the 6-bit label limit, RFC 1035 §3.1).
    LabelTooLong(u8),
    /// The total wire length of a name exceeded 255 octets (RFC 1035 §3.1).
    NameTooLong,
    /// A compression pointer did not point strictly backwards, i.e. it could
    /// form a loop. We reject rather than follow (anti-DoS, RFC 1035 §4.1.4).
    BadPointer,
    /// Too many compression pointers were chased for a single name. Belt-and
    /// -suspenders cap on top of the strictly-backwards rule.
    TooManyPointers,
    /// The top two bits of a length octet were `0b01`/`0b10` — reserved and
    /// undefined for use (RFC 1035 §4.1.4, RFC 6891 has not reassigned them).
    ReservedLabelType,
    /// An RDLENGTH did not match the bytes actually consumed by the RDATA, or
    /// pointed past the end of the message.
    BadRdataLength,
    /// A character-string length octet ran past the RDATA boundary (RFC 1035 §3.3).
    BadCharString,
    /// EDNS OPT pseudo-record was malformed (bad option length, duplicate, …).
    BadOpt,
    /// The header claimed more records than the message actually contained.
    TruncatedSection,
    /// A presentation-format name failed to parse (used by `Name::from_ascii`).
    BadName,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::UnexpectedEof => write!(f, "unexpected end of buffer"),
            WireError::LabelTooLong(n) => write!(f, "label length {n} exceeds 63"),
            WireError::NameTooLong => write!(f, "name exceeds 255 octets"),
            WireError::BadPointer => write!(f, "compression pointer is not strictly backward"),
            WireError::TooManyPointers => write!(f, "too many compression pointers in one name"),
            WireError::ReservedLabelType => write!(f, "reserved label type (0b01/0b10)"),
            WireError::BadRdataLength => write!(f, "RDLENGTH does not match RDATA"),
            WireError::BadCharString => write!(f, "character-string runs past RDATA"),
            WireError::BadOpt => write!(f, "malformed EDNS OPT record"),
            WireError::TruncatedSection => write!(f, "message shorter than header counts claim"),
            WireError::BadName => write!(f, "invalid presentation-format name"),
        }
    }
}

impl std::error::Error for WireError {}

/// Convenience alias for codec results.
pub type WireResult<T> = Result<T, WireError>;
