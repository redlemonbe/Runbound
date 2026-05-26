// SPDX-License-Identifier: AGPL-3.0-or-later
// SIMD label lowercasing and byte-equality for the DNS wire-format hot path.
//
// DNS label content is ASCII case-insensitive (RFC 1034).
// Dispatch at runtime via crate::cpu::simd_level():
//   AVX2   → 32 bytes/iteration (Haswell+ / Xeon E5 v3+)
//   SSE2   → 16 bytes/iteration (x86_64 baseline, Xeon E5 v2 included)
//   scalar → fallback (non-x86_64 only)
//
// Uppercase detection (avoids unsigned compare — SSE/AVX only has signed pcmpgtb):
//   biased   = byte XOR 0x80        (shift range into signed domain)
//   lo_pass  = biased > 0xC0 signed → byte >= 'A' (0x41)
//   hi_pass  = 0xDB > biased signed → byte <= 'Z' (0x5A)
//   mask     = lo_pass AND hi_pass  → 0xFF where byte in [A-Z]
//   result   = byte OR (mask AND 0x20)

use smallvec::SmallVec;

/// Copy ASCII-lowercased bytes from `src` into `dst`.
/// Runtime dispatch: AVX2 → SSE2 → scalar.
#[inline]
pub fn copy_lowercase_label(dst: &mut SmallVec<[u8; 64]>, src: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::cpu::SimdLevel;
        match crate::cpu::simd_level() {
            SimdLevel::Avx2 | SimdLevel::Avx512 => {
                return unsafe { copy_lowercase_avx2(dst, src) };
            }
            _ => {
                return unsafe { copy_lowercase_sse2(dst, src) };
            }
        }
    }
    #[allow(unreachable_code)]
    for &b in src {
        dst.push(if b >= b'A' && b <= b'Z' { b | 0x20 } else { b });
    }
}

/// SSE2 path: 16 bytes/iteration. Xeon E5 v2 (Ivy Bridge) baseline.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn copy_lowercase_sse2(dst: &mut SmallVec<[u8; 64]>, src: &[u8]) {
    use std::arch::x86_64::_mm_set1_epi8;

    let len = src.len();
    dst.reserve(len);
    let base = dst.len();
    let out_base = dst.as_mut_ptr().add(base);

    let xmm_bias = _mm_set1_epi8(0x80u8 as i8);
    let xmm_lo   = _mm_set1_epi8(0xC0u8 as i8);
    let xmm_hi   = _mm_set1_epi8(0xDBu8 as i8);
    let xmm_c20  = _mm_set1_epi8(0x20i8);

    let mut si = src.as_ptr();
    let mut di = out_base;
    let mut remaining = len;

    while remaining >= 16 {
        core::arch::asm!(
            "movdqu {inp}, [{si}]",
            "movdqa {bsd}, {inp}",
            "pxor   {bsd}, {bias}",
            "movdqa {lop}, {bsd}",
            "pcmpgtb {lop}, {lo}",
            "movdqa {hip}, {hi}",
            "pcmpgtb {hip}, {bsd}",
            "pand {lop}, {hip}",
            "pand {lop}, {c20}",
            "por  {inp}, {lop}",
            "movdqu [{di}], {inp}",
            si   = in(reg)      si,
            di   = in(reg)      di,
            bias = in(xmm_reg)  xmm_bias,
            lo   = in(xmm_reg)  xmm_lo,
            hi   = in(xmm_reg)  xmm_hi,
            c20  = in(xmm_reg)  xmm_c20,
            inp  = out(xmm_reg) _,
            bsd  = out(xmm_reg) _,
            lop  = out(xmm_reg) _,
            hip  = out(xmm_reg) _,
            options(nostack),
        );
        si = si.add(16);
        di = di.add(16);
        remaining -= 16;
    }

    for i in 0..remaining {
        let b = *si.add(i);
        *di.add(i) = if b >= b'A' && b <= b'Z' { b | 0x20 } else { b };
    }

    dst.set_len(base + len);
}

/// AVX2 path: 32 bytes/iteration. Haswell / Xeon E5 v3+ only.
/// Falls back to SSE2 16-byte chunk + scalar for the tail.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn copy_lowercase_avx2(dst: &mut SmallVec<[u8; 64]>, src: &[u8]) {
    use std::arch::x86_64::{_mm256_set1_epi8, _mm_set1_epi8};

    let len = src.len();
    dst.reserve(len);
    let base = dst.len();
    let out_base = dst.as_mut_ptr().add(base);

    let ymm_bias = _mm256_set1_epi8(0x80u8 as i8);
    let ymm_lo   = _mm256_set1_epi8(0xC0u8 as i8);
    let ymm_hi   = _mm256_set1_epi8(0xDBu8 as i8);
    let ymm_c20  = _mm256_set1_epi8(0x20i8);

    let mut si = src.as_ptr();
    let mut di = out_base;
    let mut remaining = len;

    while remaining >= 32 {
        core::arch::asm!(
            "vmovdqu {inp}, [{si}]",
            "vpxor   {bsd}, {inp}, {bias}",
            "vpcmpgtb {lop}, {bsd}, {lo}",
            "vpcmpgtb {hip}, {hi}, {bsd}",
            "vpand   {lop}, {lop}, {hip}",
            "vpand   {lop}, {lop}, {c20}",
            "vpor    {inp}, {inp}, {lop}",
            "vmovdqu [{di}], {inp}",
            si   = in(reg)       si,
            di   = in(reg)       di,
            bias = in(ymm_reg)   ymm_bias,
            lo   = in(ymm_reg)   ymm_lo,
            hi   = in(ymm_reg)   ymm_hi,
            c20  = in(ymm_reg)   ymm_c20,
            inp  = out(ymm_reg)  _,
            bsd  = out(ymm_reg)  _,
            lop  = out(ymm_reg)  _,
            hip  = out(ymm_reg)  _,
            options(nostack),
        );
        si = si.add(32);
        di = di.add(32);
        remaining -= 32;
    }

    // 16-byte tail — VEX-encoded to avoid AVX→SSE transition penalty
    if remaining >= 16 {
        let xmm_bias = _mm_set1_epi8(0x80u8 as i8);
        let xmm_lo   = _mm_set1_epi8(0xC0u8 as i8);
        let xmm_hi   = _mm_set1_epi8(0xDBu8 as i8);
        let xmm_c20  = _mm_set1_epi8(0x20i8);
        core::arch::asm!(
            "vmovdqu {inp}, xmmword ptr [{si}]",
            "vpxor   {bsd}, {inp}, {bias}",
            "vpcmpgtb {lop}, {bsd}, {lo}",
            "vpcmpgtb {hip}, {hi}, {bsd}",
            "vpand   {lop}, {lop}, {hip}",
            "vpand   {lop}, {lop}, {c20}",
            "vpor    {inp}, {inp}, {lop}",
            "vmovdqu xmmword ptr [{di}], {inp}",
            si   = in(reg)       si,
            di   = in(reg)       di,
            bias = in(xmm_reg)   xmm_bias,
            lo   = in(xmm_reg)   xmm_lo,
            hi   = in(xmm_reg)   xmm_hi,
            c20  = in(xmm_reg)   xmm_c20,
            inp  = out(xmm_reg)  _,
            bsd  = out(xmm_reg)  _,
            lop  = out(xmm_reg)  _,
            hip  = out(xmm_reg)  _,
            options(nostack),
        );
        si = si.add(16);
        di = di.add(16);
        remaining -= 16;
    }

    // scalar tail <16 bytes
    for i in 0..remaining {
        let b = *si.add(i);
        *di.add(i) = if b >= b'A' && b <= b'Z' { b | 0x20 } else { b };
    }

    dst.set_len(base + len);
}


/// Test byte-slice equality using SIMD (early exit on first chunk mismatch).
/// Runtime dispatch: AVX2 (32 bytes/iter) → SSE2 (16 bytes/iter) → scalar.
#[inline]
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        use crate::cpu::SimdLevel;
        match crate::cpu::simd_level() {
            SimdLevel::Avx2 | SimdLevel::Avx512 => {
                return unsafe { bytes_eq_avx2(a, b) };
            }
            _ => {
                return unsafe { bytes_eq_sse2(a, b) };
            }
        }
    }
    a == b  // scalar fallback — unreachable on x86_64
}

/// SSE2: pcmpeqb + pmovmskb, 16 bytes/iteration.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn bytes_eq_sse2(a: &[u8], b: &[u8]) -> bool {
    let mut pa = a.as_ptr();
    let mut pb = b.as_ptr();
    let mut remaining = a.len();

    while remaining >= 16 {
        let mask: u32;
        core::arch::asm!(
            "movdqu {va}, [{pa}]",
            "movdqu {vb}, [{pb}]",
            "pcmpeqb {va}, {vb}",
            "pmovmskb {mask:e}, {va}",
            pa   = in(reg)      pa,
            pb   = in(reg)      pb,
            va   = out(xmm_reg) _,
            vb   = out(xmm_reg) _,
            mask = out(reg)     mask,
            options(nostack),
        );
        if mask != 0xFFFF {
            return false;
        }
        pa = pa.add(16);
        pb = pb.add(16);
        remaining -= 16;
    }

    for i in 0..remaining {
        if *pa.add(i) != *pb.add(i) {
            return false;
        }
    }
    true
}

/// AVX2: vpcmpeqb + vpmovmskb, 32 bytes/iteration.
/// SSE2 tail for remaining 16-31 bytes (VEX-encoded to avoid transition penalty).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn bytes_eq_avx2(a: &[u8], b: &[u8]) -> bool {
    let mut pa = a.as_ptr();
    let mut pb = b.as_ptr();
    let mut remaining = a.len();

    while remaining >= 32 {
        let mask: u32;
        core::arch::asm!(
            "vmovdqu {va}, [{pa}]",
            "vmovdqu {vb}, [{pb}]",
            "vpcmpeqb {va}, {va}, {vb}",
            "vpmovmskb {mask:e}, {va}",
            pa   = in(reg)       pa,
            pb   = in(reg)       pb,
            va   = out(ymm_reg)  _,
            vb   = out(ymm_reg)  _,
            mask = out(reg)      mask,
            options(nostack),
        );
        if mask != 0xFFFF_FFFF {
            return false;
        }
        pa = pa.add(32);
        pb = pb.add(32);
        remaining -= 32;
    }

    // 16-byte tail — VEX-encoded to avoid AVX→SSE transition penalty
    if remaining >= 16 {
        let mask: u32;
        core::arch::asm!(
            "vmovdqu {va}, xmmword ptr [{pa}]",
            "vmovdqu {vb}, xmmword ptr [{pb}]",
            "vpcmpeqb {va}, {va}, {vb}",
            "vpmovmskb {mask:e}, {va}",
            pa   = in(reg)      pa,
            pb   = in(reg)      pb,
            va   = out(xmm_reg) _,
            vb   = out(xmm_reg) _,
            mask = out(reg)     mask,
            options(nostack),
        );
        if mask != 0xFFFF {
            return false;
        }
        pa = pa.add(16);
        pb = pb.add(16);
        remaining -= 16;
    }

    // scalar tail <16 bytes
    for i in 0..remaining {
        if *pa.add(i) != *pb.add(i) {
            return false;
        }
    }
    true
}


/// Find the position of the first 0x00 byte in `bytes` (up to 255 bytes).
/// Returns `None` if no zero is found within that range.
/// Used by the XDP QNAME parser to determine wire length before bulk lowercasing.
#[inline]
pub fn find_zero(bytes: &[u8]) -> Option<usize> {
    let limit = bytes.len().min(255);
    #[cfg(target_arch = "x86_64")]
    {
        return unsafe { find_zero_sse2(bytes, limit) };
    }
    #[allow(unreachable_code)]
    bytes[..limit].iter().position(|&b| b == 0)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn find_zero_sse2(bytes: &[u8], limit: usize) -> Option<usize> {
    use std::arch::x86_64::_mm_setzero_si128;

    let zero16 = _mm_setzero_si128();
    let mut pos = 0usize;

    while pos + 16 <= limit {
        let mask: u32;
        core::arch::asm!(
            "movdqu {v}, [{ptr}]",
            "pcmpeqb {v}, {zero}",
            "pmovmskb {mask:e}, {v}",
            ptr  = in(reg)      bytes.as_ptr().add(pos),
            zero = in(xmm_reg)  zero16,
            v    = out(xmm_reg) _,
            mask = out(reg)     mask,
            options(nostack, nomem),
        );
        if mask != 0 {
            return Some(pos + mask.trailing_zeros() as usize);
        }
        pos += 16;
    }

    while pos < limit {
        if *bytes.as_ptr().add(pos) == 0 {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

#[cfg(test)]
mod find_zero_tests {
    use super::*;

    #[test]
    fn find_zero_empty() {
        assert_eq!(find_zero(b""), None);
    }

    #[test]
    fn find_zero_not_found() {
        let v: Vec<u8> = (1u8..=32).collect();
        assert_eq!(find_zero(&v), None);
    }

    #[test]
    fn find_zero_at_each_position() {
        for pos in 0..64usize {
            let mut v: Vec<u8> = (1u8..=100).take(64).collect();
            v[pos] = 0;
            assert_eq!(find_zero(&v), Some(pos), "failed at pos={pos}");
        }
    }

    #[test]
    fn find_zero_qname_example() {
        // wire: \x07example\x03com\x00
        let wire = b"\x07example\x03com\x00";
        assert_eq!(find_zero(wire), Some(12)); // \x00 is at index 12
    }

    #[test]
    fn find_zero_first_wins() {
        let wire = b"\x03abc\x00\x00extra";
        assert_eq!(find_zero(wire), Some(4)); // first \x00
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::SmallVec;

    fn lower(s: &[u8]) -> Vec<u8> {
        let mut v: SmallVec<[u8; 64]> = SmallVec::new();
        copy_lowercase_label(&mut v, s);
        v.to_vec()
    }

    #[test]
    fn basic_uppercase()    { assert_eq!(lower(b"EXAMPLE"), b"example"); }

    #[test]
    fn mixed_case()         { assert_eq!(lower(b"ExAmPlE"), b"example"); }

    #[test]
    fn digits_unchanged()   { assert_eq!(lower(b"test123"), b"test123"); }

    #[test]
    fn hyphen_unchanged()   { assert_eq!(lower(b"my-host"), b"my-host"); }

    #[test]
    fn high_bytes_unchanged() {
        let input: Vec<u8> = (0x80u8..=0xFFu8).collect();
        assert_eq!(lower(&input), input);
    }

    #[test]
    fn all_lengths_0_to_80() {
        for len in 0..=80usize {
            let input: Vec<u8> = (0u8..).take(len).map(|i| b'A' + (i % 26) as u8).collect();
            let expected: Vec<u8> = input.iter().map(|&b| b | 0x20).collect();
            assert_eq!(lower(&input), expected, "failed at len={len}");
        }
    }

    #[test]
    fn realistic_dns_label() {
        assert_eq!(lower(b"RunBound"), b"runbound");
        assert_eq!(lower(b"www"), b"www");
        assert_eq!(lower(b"API-v2"), b"api-v2");
    }

    // Force SSE2 path explicitly (for machines where AVX2 dispatches instead)
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sse2_explicit_all_lengths() {
        for len in 0..=80usize {
            let input: Vec<u8> = (0u8..).take(len).map(|i| b'A' + (i % 26) as u8).collect();
            let expected: Vec<u8> = input.iter().map(|&b| b | 0x20).collect();
            let mut out: SmallVec<[u8; 64]> = SmallVec::new();
            unsafe { super::copy_lowercase_sse2(&mut out, &input) };
            assert_eq!(out.as_slice(), expected.as_slice(), "sse2 failed at len={len}");
        }
    }

    // Force AVX2 path explicitly (only compiled/run on AVX2 machines)
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn avx2_explicit_all_lengths() {
        if !std::is_x86_feature_detected!("avx2") {
            return; // skip on Xeon v2 / SSE4.2-only
        }
        for len in 0..=80usize {
            let input: Vec<u8> = (0u8..).take(len).map(|i| b'A' + (i % 26) as u8).collect();
            let expected: Vec<u8> = input.iter().map(|&b| b | 0x20).collect();
            let mut out: SmallVec<[u8; 64]> = SmallVec::new();
            unsafe { super::copy_lowercase_avx2(&mut out, &input) };
            assert_eq!(out.as_slice(), expected.as_slice(), "avx2 failed at len={len}");
        }
    }

    #[test]
    fn bytes_eq_identical() {
        assert!(bytes_eq(b"example.com.", b"example.com."));
    }

    #[test]
    fn bytes_eq_different() {
        assert!(!bytes_eq(b"example.com.", b"example.net."));
    }

    #[test]
    fn bytes_eq_different_len() {
        assert!(!bytes_eq(b"example.com.", b"example.com"));
    }

    #[test]
    fn bytes_eq_empty() {
        assert!(bytes_eq(b"", b""));
    }

    #[test]
    fn bytes_eq_all_lengths_0_to_80() {
        for len in 0..=80usize {
            let a: Vec<u8> = (0u8..).take(len).collect();
            let mut b = a.clone();
            assert!(bytes_eq(&a, &b), "should be equal at len={len}");
            if !b.is_empty() {
                let last = b.len() - 1;
                b[last] ^= 0xFF;
                assert!(!bytes_eq(&a, &b), "should differ at len={len}");
            }
        }
    }

    #[test]
    fn bytes_eq_mismatch_at_each_position() {
        let base: Vec<u8> = (0u8..64).collect();
        for pos in 0..64usize {
            let mut other = base.clone();
            other[pos] ^= 0xFF;
            assert!(!bytes_eq(&base, &other), "should differ at pos={pos}");
        }
    }

    // Force AVX2 equality path explicitly
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn avx2_bytes_eq_explicit() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        let base: Vec<u8> = (0u8..64).collect();
        for pos in 0..64usize {
            let mut other = base.clone();
            other[pos] ^= 0xFF;
            assert!(!unsafe { super::bytes_eq_avx2(&base, &other) }, "avx2 differ at pos={pos}");
        }
        assert!(unsafe { super::bytes_eq_avx2(&base, &base) });
    }
}
