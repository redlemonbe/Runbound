// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Bounds-checked, big-endian cursor over a DNS message buffer.
//!
//! Every read is length-checked: there is no path that indexes the backing
//! slice without first proving the bytes are present. This is the single choke
//! point through which all untrusted input flows, so it is kept tiny and
//! audited. Name decompression needs to seek to arbitrary earlier offsets, so
//! the decoder also exposes the full backing buffer and a checked `seek`.

use super::error::{WireError, WireResult};

/// A forward cursor over a borrowed message buffer.
///
/// Cheap to copy (two words). Cloning a `Decoder` is the idiomatic way to take
/// a save-point, e.g. when a name parser needs to remember where to resume
/// after following a compression pointer.
#[derive(Clone, Copy, Debug)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Wrap a buffer with the cursor at offset 0.
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Decoder { buf, pos: 0 }
    }

    /// Current read offset.
    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// The full backing buffer (needed by name decompression to read at an
    /// earlier offset without losing the resume position).
    #[inline]
    pub fn buffer(&self) -> &'a [u8] {
        self.buf
    }

    /// Bytes between the cursor and the end of the buffer.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether the cursor is at or past the end.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Move the cursor to an absolute offset. Used to resume after a name that
    /// ended in a compression pointer. The target may equal `buf.len()` (the
    /// just-past-the-end position) but never beyond it.
    #[inline]
    pub fn seek(&mut self, pos: usize) -> WireResult<()> {
        if pos > self.buf.len() {
            return Err(WireError::UnexpectedEof);
        }
        self.pos = pos;
        Ok(())
    }

    /// Read one octet and advance.
    #[inline]
    pub fn u8(&mut self) -> WireResult<u8> {
        let b = *self.buf.get(self.pos).ok_or(WireError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    /// Peek one octet without advancing.
    #[inline]
    pub fn peek_u8(&self) -> WireResult<u8> {
        self.buf.get(self.pos).copied().ok_or(WireError::UnexpectedEof)
    }

    /// Read a big-endian u16 and advance.
    #[inline]
    pub fn u16(&mut self) -> WireResult<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }

    /// Read a big-endian u32 and advance.
    #[inline]
    pub fn u32(&mut self) -> WireResult<u32> {
        let a = self.u16()? as u32;
        let b = self.u16()? as u32;
        Ok((a << 16) | b)
    }

    /// Borrow `n` bytes and advance past them.
    #[inline]
    pub fn slice(&mut self, n: usize) -> WireResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(WireError::UnexpectedEof)?;
        let s = self.buf.get(self.pos..end).ok_or(WireError::UnexpectedEof)?;
        self.pos = end;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian() {
        let mut d = Decoder::new(&[0x12, 0x34, 0x56, 0x78, 0xAB]);
        assert_eq!(d.u16().unwrap(), 0x1234);
        assert_eq!(d.u16().unwrap(), 0x5678);
        assert_eq!(d.u8().unwrap(), 0xAB);
        assert_eq!(d.u8(), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn u32_and_slice() {
        let mut d = Decoder::new(&[0, 0, 1, 0, 9, 9]);
        assert_eq!(d.u32().unwrap(), 0x0000_0100);
        assert_eq!(d.slice(2).unwrap(), &[9, 9]);
        assert_eq!(d.slice(1), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn slice_overflow_is_eof_not_panic() {
        let mut d = Decoder::new(&[1, 2, 3]);
        assert_eq!(d.slice(usize::MAX), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn seek_is_bounds_checked() {
        let mut d = Decoder::new(&[1, 2, 3]);
        assert!(d.seek(3).is_ok()); // just-past-end allowed
        assert_eq!(d.seek(4), Err(WireError::UnexpectedEof));
    }
}
