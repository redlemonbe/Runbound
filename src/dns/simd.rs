// SPDX-License-Identifier: AGPL-3.0-or-later
// SIMD label lowercasing for the DNS wire-format hot path.
//
// DNS label content is ASCII case-insensitive (RFC 1034).
// The XDP cache lookup path copies each label byte with `| 0x20` (scalar).
// This module replaces that loop with an SSE2 SIMD pass: 16 bytes/iteration.
//
// Uppercase detection (avoids unsigned compare — SSE2 only has signed pcmpgtb):
//   biased   = byte XOR 0x80        (shift range into signed domain)
//   lo_pass  = biased > 0xC0 signed → byte >= 'A' (0x41)
//   hi_pass  = 0xDB > biased signed → byte <= 'Z' (0x5A)
//   mask     = lo_pass AND hi_pass  → 0xFF where byte in [A-Z]
//   result   = byte OR (mask AND 0x20)

use smallvec::SmallVec;

/// Copy ASCII-lowercased bytes from `src` into `dst`.
#[inline]
pub fn copy_lowercase_label(dst: &mut SmallVec<[u8; 64]>, src: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        return unsafe { copy_lowercase_sse2(dst, src) };
    }
    #[allow(unreachable_code)]
    for &b in src {
        dst.push(if b >= b'A' && b <= b'Z' { b | 0x20 } else { b });
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn copy_lowercase_sse2(dst: &mut SmallVec<[u8; 64]>, src: &[u8]) {
    use std::arch::x86_64::_mm_set1_epi8;

    let len = src.len();
    dst.reserve(len);
    let base = dst.len();
    let out_base = dst.as_mut_ptr().add(base);

    // Constants loaded via intrinsics (single movdqa each), consumed by asm! loop.
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
}
