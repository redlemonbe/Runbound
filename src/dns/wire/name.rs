// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Domain names: parsing (with decompression), emitting (with compression),
//! presentation format, and case-insensitive comparison.
//!
//! # Security
//!
//! Name decompression is the classic DNS denial-of-service surface (pointer
//! loops, compression bombs). [`Name::parse`] is bounded three independent
//! ways, so a hostile packet can neither loop nor blow up memory:
//!
//! 1. **Backward pointers only** — a compression pointer must target an offset
//!    strictly *before* the pointer itself; forward and self pointers are
//!    rejected outright.
//! 2. **Pointer-chase cap** — at most [`MAX_POINTERS`] indirections per name.
//! 3. **Length budget** — the decompressed wire form may never exceed
//!    [`MAX_NAME_WIRE`] (255) octets; a label may never exceed 63.
//!
//! Any two of these alone already force termination; together they leave no
//! room for abuse, and every failure is a clean [`WireError`], never a panic.

use smallvec::SmallVec;
use std::hash::{Hash, Hasher};

use super::decoder::Decoder;
use super::encoder::Encoder;
use super::error::{WireError, WireResult};

/// Maximum total wire length of a name including length octets and the root
/// terminator (RFC 1035 §3.1).
pub const MAX_NAME_WIRE: usize = 255;
/// Maximum length of a single label (the 6 usable bits of the length octet).
pub const MAX_LABEL: usize = 63;
/// Hard cap on compression-pointer indirections while decoding one name.
pub const MAX_POINTERS: usize = 127;

const PTR_BITS: u8 = 0xC0;

/// A DNS domain name, stored decompressed in canonical wire layout
/// `<len><label> … <len><label> 0`, always terminated by the root octet.
///
/// Names compare and hash case-insensitively (ASCII), as DNS requires.
/// Original label case is preserved for output (0x20 mixed-case echo, AXFR,
/// authoritative answers).
#[derive(Clone)]
pub struct Name {
    /// Decompressed wire form, always ending in a single `0` octet.
    wire: SmallVec<[u8; 24]>,
}

impl Name {
    /// The root name (`.`).
    #[inline]
    pub fn root() -> Self {
        let mut wire = SmallVec::new();
        wire.push(0);
        Name { wire }
    }

    /// Whether this is the root name.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /// The decompressed wire bytes (including the trailing root octet).
    #[inline]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Wire length in octets.
    #[inline]
    pub fn len(&self) -> usize {
        self.wire.len()
    }

    /// Always false (the root name is one octet); present to satisfy clippy.
    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Number of labels, excluding the root (root name → 0).
    pub fn label_count(&self) -> usize {
        let mut i = 0;
        let mut n = 0;
        while self.wire[i] != 0 {
            n += 1;
            i += 1 + self.wire[i] as usize;
        }
        n
    }

    /// The parent name (this name with its leftmost label removed), or `None`
    /// for the root. Used by the iterative resolver to walk the delegation chain.
    pub fn parent(&self) -> Option<Name> {
        if self.is_root() {
            return None;
        }
        let skip = 1 + self.wire[0] as usize;
        let mut wire: SmallVec<[u8; 24]> = SmallVec::new();
        wire.extend_from_slice(&self.wire[skip..]);
        Some(Name { wire })
    }

    /// True if `self` is `zone` or a subdomain of it (case-insensitive). Walks the
    /// label hierarchy, so the suffix match is always label-aligned.
    pub fn is_in_zone(&self, zone: &Name) -> bool {
        let mut cur = self.clone();
        loop {
            if cur.eq_ignore_ascii_case(zone) {
                return true;
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => return false,
            }
        }
    }

    /// Lowercased copy of the wire form (length octets untouched, label data
    /// ASCII-lowercased). This is both the comparison key and the compression
    /// table key.
    fn lower_wire(&self) -> SmallVec<[u8; 24]> {
        let mut out: SmallVec<[u8; 24]> = SmallVec::with_capacity(self.wire.len());
        let mut i = 0;
        while i < self.wire.len() {
            let ll = self.wire[i] as usize;
            out.push(self.wire[i]);
            if ll == 0 {
                break;
            }
            for &b in &self.wire[i + 1..i + 1 + ll] {
                out.push(b.to_ascii_lowercase());
            }
            i += 1 + ll;
        }
        out
    }

    /// Parse a (possibly compressed) name from the cursor. On success the
    /// decoder is positioned just past the name in the *primary* stream — i.e.
    /// past the first compression pointer if one was used, otherwise past the
    /// root octet. See the module docs for the safety argument.
    pub fn parse(d: &mut Decoder) -> WireResult<Name> {
        let buf = d.buffer();
        let mut wire: SmallVec<[u8; 24]> = SmallVec::new();
        let mut pos = d.pos();
        let mut resume: Option<usize> = None;
        let mut pointers = 0usize;

        loop {
            let len = *buf.get(pos).ok_or(WireError::UnexpectedEof)?;
            match len & PTR_BITS {
                0x00 => {
                    if len == 0 {
                        wire.push(0);
                        pos += 1;
                        if resume.is_none() {
                            resume = Some(pos);
                        }
                        break;
                    }
                    // len is 1..=63 (top two bits are clear).
                    let ll = len as usize;
                    let start = pos + 1;
                    let end = start.checked_add(ll).ok_or(WireError::UnexpectedEof)?;
                    if end > buf.len() {
                        return Err(WireError::UnexpectedEof);
                    }
                    // Budget: current + this label + the root terminator.
                    if wire.len() + 1 + ll + 1 > MAX_NAME_WIRE {
                        return Err(WireError::NameTooLong);
                    }
                    wire.push(len);
                    wire.extend_from_slice(&buf[start..end]);
                    pos = end;
                }
                0xC0 => {
                    let b2 = *buf.get(pos + 1).ok_or(WireError::UnexpectedEof)?;
                    let target = (((len & 0x3F) as usize) << 8) | b2 as usize;
                    if resume.is_none() {
                        resume = Some(pos + 2);
                    }
                    pointers += 1;
                    if pointers > MAX_POINTERS {
                        return Err(WireError::TooManyPointers);
                    }
                    // Strictly backward: never forward, never to self.
                    if target >= pos {
                        return Err(WireError::BadPointer);
                    }
                    pos = target;
                }
                // 0x40 and 0x80 are reserved label types (RFC 6891 did not
                // reassign them); reject rather than guess.
                _ => return Err(WireError::ReservedLabelType),
            }
        }

        d.seek(resume.expect("resume set before break"))?;
        Ok(Name { wire })
    }

    /// Emit the name, using the encoder's compression table when enabled.
    /// Standard suffix compression: the longest already-seen suffix becomes a
    /// pointer; preceding labels are written and registered for later reuse.
    pub fn emit(&self, e: &mut Encoder) {
        let lower = self.lower_wire();
        let mut i = 0usize;
        loop {
            if self.wire[i] == 0 {
                e.u8(0);
                return;
            }
            if let Some(off) = e.lookup_name(&lower[i..]) {
                e.u16(0xC000 | off);
                return;
            }
            e.remember_name(&lower[i..], e.len());
            let ll = self.wire[i] as usize;
            e.u8(self.wire[i]);
            e.bytes(&self.wire[i + 1..i + 1 + ll]);
            i += 1 + ll;
        }
    }

    /// Emit the name uncompressed and without touching the encoder's
    /// compression table. Used for names embedded in RDATA, where compression
    /// is either forbidden (RFC 3597 modern types, RFC 2782 SRV) or simply not
    /// worth the cross-record pointer hazard. The stored wire form is already
    /// the canonical uncompressed encoding, so this is a single copy.
    #[inline]
    pub fn emit_raw(&self, e: &mut Encoder) {
        e.bytes(&self.wire);
    }

    /// Emit the name in DNSSEC canonical form (RFC 4034 §6.2): uncompressed and
    /// fully lowercased. Length octets (0–63) are below `A`, so a blanket
    /// ASCII-lowercase leaves them untouched.
    #[inline]
    pub fn emit_canonical(&self, e: &mut Encoder) {
        for &b in &self.wire {
            e.u8(b.to_ascii_lowercase());
        }
    }

    /// Render in presentation format (`example.com.`) with RFC 1035 §5.1
    /// escaping of `.`, `\`, and non-printable octets.
    pub fn to_ascii(&self) -> String {
        if self.is_root() {
            return ".".to_string();
        }
        let mut s = String::new();
        let mut i = 0;
        while self.wire[i] != 0 {
            let ll = self.wire[i] as usize;
            for &b in &self.wire[i + 1..i + 1 + ll] {
                match b {
                    b'.' | b'\\' => {
                        s.push('\\');
                        s.push(b as char);
                    }
                    0x21..=0x7E => s.push(b as char),
                    _ => {
                        s.push('\\');
                        s.push_str(&format!("{b:03}"));
                    }
                }
            }
            s.push('.');
            i += 1 + ll;
        }
        s
    }

    /// Parse a presentation-format name. Accepts an optional trailing dot;
    /// the empty string and `"."` are both the root. Supports `\.`, `\\`, and
    /// `\DDD` escapes.
    pub fn from_ascii(s: &str) -> WireResult<Name> {
        if s.is_empty() || s == "." {
            return Ok(Name::root());
        }
        let bytes = s.as_bytes();
        let mut wire: SmallVec<[u8; 24]> = SmallVec::new();
        let mut label: SmallVec<[u8; 64]> = SmallVec::new();
        let mut i = 0;

        let flush = |label: &mut SmallVec<[u8; 64]>,
                     wire: &mut SmallVec<[u8; 24]>|
         -> WireResult<()> {
            if label.is_empty() {
                // empty label only legal as the trailing root dot
                return Ok(());
            }
            if label.len() > MAX_LABEL {
                return Err(WireError::LabelTooLong(label.len() as u8));
            }
            if wire.len() + 1 + label.len() + 1 > MAX_NAME_WIRE {
                return Err(WireError::NameTooLong);
            }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label);
            label.clear();
            Ok(())
        };

        while i < bytes.len() {
            let c = bytes[i];
            match c {
                b'.' => {
                    flush(&mut label, &mut wire)?;
                    i += 1;
                }
                b'\\' => {
                    if i + 1 >= bytes.len() {
                        return Err(WireError::BadName);
                    }
                    let n = bytes[i + 1];
                    if n.is_ascii_digit() {
                        if i + 3 >= bytes.len()
                            || !bytes[i + 2].is_ascii_digit()
                            || !bytes[i + 3].is_ascii_digit()
                        {
                            return Err(WireError::BadName);
                        }
                        let v = (n - b'0') as u16 * 100
                            + (bytes[i + 2] - b'0') as u16 * 10
                            + (bytes[i + 3] - b'0') as u16;
                        if v > 255 {
                            return Err(WireError::BadName);
                        }
                        label.push(v as u8);
                        i += 4;
                    } else {
                        label.push(n);
                        i += 2;
                    }
                }
                _ => {
                    label.push(c);
                    i += 1;
                }
            }
        }
        flush(&mut label, &mut wire)?;
        wire.push(0);
        Ok(Name { wire })
    }

    /// Case-insensitive equality on the wire form.
    #[inline]
    pub fn eq_ignore_ascii_case(&self, other: &Name) -> bool {
        self.wire.len() == other.wire.len()
            && self
                .wire
                .iter()
                .zip(other.wire.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl PartialEq for Name {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}
impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the lowercased form so equal names hash equally.
        for &b in self.wire.iter() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Name({})", self.to_ascii())
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_ascii())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_at(buf: &[u8], start: usize) -> WireResult<Name> {
        let mut d = Decoder::new(buf);
        d.seek(start).unwrap();
        Name::parse(&mut d)
    }

    #[test]
    fn root_roundtrip() {
        let n = Name::root();
        assert!(n.is_root());
        assert_eq!(n.to_ascii(), ".");
        assert_eq!(n.wire(), &[0]);
    }

    #[test]
    fn simple_name() {
        // 3www 7example 3com 0
        let buf = b"\x03www\x07example\x03com\x00";
        let n = parse_at(buf, 0).unwrap();
        assert_eq!(n.to_ascii(), "www.example.com.");
        assert_eq!(n.label_count(), 3);
    }

    #[test]
    fn presentation_roundtrip() {
        for s in ["example.com.", "a.b.c.d.", "xn--p1ai.", "."] {
            let n = Name::from_ascii(s).unwrap();
            assert_eq!(n.to_ascii(), s);
        }
    }

    #[test]
    fn case_insensitive_eq_and_hash() {
        use std::collections::hash_map::DefaultHasher;
        let a = Name::from_ascii("Example.COM.").unwrap();
        let b = Name::from_ascii("example.com.").unwrap();
        assert_eq!(a, b);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
        // case is preserved on output, though
        assert_eq!(a.to_ascii(), "Example.COM.");
    }

    #[test]
    fn compression_pointer_followed() {
        // "example.com" at offset 0, then "www" + pointer to 0 at the end.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\x07example\x03com\x00"); // offset 0
        let www_at = buf.len();
        buf.extend_from_slice(b"\x03www\xC0\x00"); // www + ptr->0
        let n = parse_at(&buf, www_at).unwrap();
        assert_eq!(n.to_ascii(), "www.example.com.");
    }

    #[test]
    fn rejects_forward_pointer() {
        // pointer at 0 -> 2, which is not strictly backward.
        let buf = [0xC0, 0x02, 0x00];
        assert_eq!(parse_at(&buf, 0), Err(WireError::BadPointer));
    }

    #[test]
    fn rejects_self_pointer() {
        let buf = [0xC0, 0x00]; // ptr at 0 -> 0
        assert_eq!(parse_at(&buf, 0), Err(WireError::BadPointer));
    }

    #[test]
    fn pointer_loop_terminates() {
        // Two labels that point back at each other's region; must error, not hang.
        // offset0: 1 'a' ptr->4 ; offset4: 1 'b' ptr->0
        let buf = [0x01, b'a', 0xC0, 0x04, 0x01, b'b', 0xC0, 0x00];
        // starting at 4: b -> ptr 0 -> a -> ptr 4 (>= pos? 4>=2 no... ) eventually
        // bounded by NameTooLong / MAX_POINTERS — just assert it returns an Err.
        let r = parse_at(&buf, 4);
        assert!(r.is_err(), "expected bounded error, got {r:?}");
    }

    #[test]
    fn rejects_oversize_name() {
        // Build a name longer than 255 octets without any pointer.
        let mut buf = Vec::new();
        for _ in 0..6 {
            buf.push(63);
            buf.extend_from_slice(&[b'a'; 63]);
        }
        buf.push(0);
        assert_eq!(parse_at(&buf, 0), Err(WireError::NameTooLong));
    }

    #[test]
    fn rejects_reserved_label_type() {
        let buf = [0x80, 0x00];
        assert_eq!(parse_at(&buf, 0), Err(WireError::ReservedLabelType));
    }

    #[test]
    fn emit_compresses_shared_suffix() {
        let mut e = Encoder::new();
        Name::from_ascii("www.example.com.").unwrap().emit(&mut e);
        let p1 = e.len();
        Name::from_ascii("mail.example.com.").unwrap().emit(&mut e);
        // second name: 4mail + pointer to the "example.com" suffix → 7 bytes.
        assert_eq!(e.len() - p1, 4 + 1 + 2);
    }

    #[test]
    fn emit_uncompressed_has_no_pointers() {
        let mut e = Encoder::uncompressed();
        Name::from_ascii("www.example.com.").unwrap().emit(&mut e);
        Name::from_ascii("mail.example.com.").unwrap().emit(&mut e);
        assert!(e.as_slice().iter().all(|&b| b & 0xC0 != 0xC0 || b == 0));
    }
}
