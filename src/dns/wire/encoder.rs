// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Append-only DNS message builder with optional name compression.
//!
//! The encoder owns a growing `Vec<u8>` and, when compression is enabled, a
//! table mapping the lowercased wire form of every name already written to the
//! offset where it was written. Names are compressed against that table per
//! RFC 1035 §4.1.4. Pointers are only ever emitted to offsets `< 0x3FFF`, the
//! 14-bit limit; names that would be written past that point are emitted
//! uncompressed, which is always legal.

use std::collections::HashMap;

/// The 14-bit ceiling above which a name offset can no longer be referenced by
/// a compression pointer. Anything beyond is written without compression.
pub(crate) const MAX_COMPRESS_OFFSET: usize = 0x3FFF;

/// A growable DNS wire-format writer.
pub struct Encoder {
    buf: Vec<u8>,
    /// lowercased wire-name → offset, only populated when `compress` is true.
    names: HashMap<Box<[u8]>, u16>,
    compress: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// A compressing encoder (the normal case for responses).
    pub fn new() -> Self {
        Encoder {
            buf: Vec::with_capacity(512),
            names: HashMap::new(),
            compress: true,
        }
    }

    /// An encoder that never compresses. Used where the wire form must be
    /// canonical and pointer-free — e.g. building the byte stream that gets
    /// hashed for DNSSEC, or RDATA of modern record types (RFC 3597).
    pub fn uncompressed() -> Self {
        Encoder {
            buf: Vec::with_capacity(512),
            names: HashMap::new(),
            compress: false,
        }
    }

    /// Number of bytes written so far (also the offset of the next byte).
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written yet.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether compression is active.
    #[inline]
    pub(crate) fn compression_enabled(&self) -> bool {
        self.compress
    }

    #[inline]
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    #[inline]
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    #[inline]
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    #[inline]
    pub fn bytes(&mut self, s: &[u8]) {
        self.buf.extend_from_slice(s);
    }

    /// Look up a previously written name's offset for compression. Returns
    /// `None` when compression is off or the name has not been seen.
    #[inline]
    pub(crate) fn lookup_name(&self, lower_wire: &[u8]) -> Option<u16> {
        if !self.compress {
            return None;
        }
        self.names.get(lower_wire).copied()
    }

    /// Remember that the (lowercased) name was written at `offset`, so later
    /// occurrences can point back to it. Offsets beyond the 14-bit pointer
    /// range are not recorded — they can never be the target of a pointer.
    #[inline]
    pub(crate) fn remember_name(&mut self, lower_wire: &[u8], offset: usize) {
        if self.compress && offset <= MAX_COMPRESS_OFFSET {
            self.names
                .entry(lower_wire.to_vec().into_boxed_slice())
                .or_insert(offset as u16);
        }
    }

    /// Reserve a two-byte big-endian length placeholder (e.g. RDLENGTH) and
    /// return its offset. Pair with [`Encoder::patch_u16_len`].
    #[inline]
    pub fn reserve_u16(&mut self) -> usize {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        at
    }

    /// Backfill a placeholder reserved with [`Encoder::reserve_u16`] with the
    /// number of bytes written after it.
    #[inline]
    pub fn patch_u16_len(&mut self, at: usize) {
        let n = (self.buf.len() - at - 2) as u16;
        let b = n.to_be_bytes();
        self.buf[at] = b[0];
        self.buf[at + 1] = b[1];
    }

    /// Overwrite a previously written big-endian u16 (e.g. patch a header
    /// count after the fact). Caller guarantees `at + 2 <= len`.
    #[inline]
    pub fn patch_u16(&mut self, at: usize, v: u16) {
        let b = v.to_be_bytes();
        self.buf[at] = b[0];
        self.buf[at + 1] = b[1];
    }

    /// Borrow the bytes written so far.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the encoder and yield the finished message.
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_are_big_endian() {
        let mut e = Encoder::new();
        e.u8(0xAB);
        e.u16(0x1234);
        e.u32(0xDEAD_BEEF);
        assert_eq!(e.as_slice(), &[0xAB, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn reserve_and_patch_len() {
        let mut e = Encoder::new();
        e.u16(0xAAAA);
        let at = e.reserve_u16();
        e.bytes(&[1, 2, 3, 4, 5]);
        e.patch_u16_len(at);
        // 0xAAAA, len=5, payload
        assert_eq!(e.as_slice(), &[0xAA, 0xAA, 0x00, 0x05, 1, 2, 3, 4, 5]);
    }
}
