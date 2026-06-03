// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// CRC32c hardware hasher for DNS domain name lookups.
//
// Uses SSE4.2 (x86_64) or CRC extension (aarch64) when available;
// falls back to FNV-1a 64-bit on unsupported hardware.
// Call `init()` once at startup before building any `LocalZoneSet`.

use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};

static HAS_HW_CRC32C: AtomicBool = AtomicBool::new(false);

/// Probe CPU features and activate hardware CRC32c if available.
/// Logs the selected backend via tracing. Must be called after the tracing
/// subscriber is initialised and before any `LocalZoneSet` is built.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("sse4.2") {
        HAS_HW_CRC32C.store(true, Ordering::Relaxed);
        tracing::info!("[DNS] domain hasher: CRC32c SSE4.2 (hardware)");
        return;
    }

    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("crc") {
        HAS_HW_CRC32C.store(true, Ordering::Relaxed);
        tracing::info!("[DNS] domain hasher: CRC32c ARM-CRC (hardware)");
        return;
    }

    tracing::info!("[DNS] domain hasher: FNV-1a (software — no hardware CRC32c detected)");
}

// ── x86_64 SSE4.2 ────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_sse42(crc: u32, bytes: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let mut crc64 = crc as u64;
    // SAFETY: align_to::<u64> is safe for u64 (any bit pattern is valid).
    let (prefix, aligned, suffix) = bytes.align_to::<u64>();
    for &b in prefix {
        crc64 = _mm_crc32_u8(crc64 as u32, b) as u64;
    }
    for &word in aligned {
        crc64 = _mm_crc32_u64(crc64, word);
    }
    let mut crc = crc64 as u32;
    for &b in suffix {
        crc = _mm_crc32_u8(crc, b);
    }
    crc
}


// ── x86_64 SSE4.2 — raw asm! (no align_to overhead, unaligned reads) ────────
//
// Eliminates align_to::<u64>() overhead for short DNS names (8-64 bytes).
// Adds a 4-byte stage between the 8-byte loop and the byte tail.
// options(pure, nomem, nostack) lets the compiler schedule freely around calls.
//
// CRC32Q latency: 3 cycles. Throughput: 1/cycle. Sequential dependency chain
// is the bottleneck for short inputs; 3-stream parallel variant is a TODO.

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_sse42_asm(mut crc: u32, bytes: &[u8]) -> u32 {
    let mut ptr = bytes.as_ptr();
    let mut remaining = bytes.len();

    while remaining >= 8 {
        let word = ptr.cast::<u64>().read_unaligned();
        let mut crc64 = crc as u64;
        core::arch::asm!(
            "crc32 {acc}, {word}",
            acc = inout(reg) crc64,
            word = in(reg) word,
            options(nostack, nomem, pure),
        );
        crc = crc64 as u32;
        ptr = ptr.add(8);
        remaining -= 8;
    }

    if remaining >= 4 {
        let dword = ptr.cast::<u32>().read_unaligned();
        core::arch::asm!(
            "crc32 {acc:e}, {dword:e}",
            acc = inout(reg) crc,
            dword = in(reg) dword,
            options(nostack, nomem, pure),
        );
        ptr = ptr.add(4);
        remaining -= 4;
    }

    while remaining > 0 {
        let byte = ptr.read();
        core::arch::asm!(
            "crc32 {acc:e}, {byte}",
            acc = inout(reg) crc,
            byte = in(reg_byte) byte,
            options(nostack, nomem, pure),
        );
        ptr = ptr.add(1);
        remaining -= 1;
    }

    crc
}
// ── aarch64 CRC32 ────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn crc32c_arm(crc: u32, bytes: &[u8]) -> u32 {
    use std::arch::aarch64::{__crc32cb, __crc32cd};
    // SAFETY: align_to::<u64> is safe for u64 (any bit pattern is valid).
    let (prefix, aligned, suffix) = bytes.align_to::<u64>();
    let mut crc = crc;
    for &b in prefix {
        crc = __crc32cb(crc, b);
    }
    for &word in aligned {
        crc = __crc32cd(crc, word);
    }
    for &b in suffix {
        crc = __crc32cb(crc, b);
    }
    crc
}

// ── Runtime dispatch ──────────────────────────────────────────────────────

#[inline]
fn crc32c_hw(crc: u32, bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: only called when HAS_HW_CRC32C is true; init() confirmed SSE4.2.
        return unsafe { crc32c_sse42_asm(crc, bytes) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: only called when HAS_HW_CRC32C is true; init() confirmed ARM CRC.
        return unsafe { crc32c_arm(crc, bytes) };
    }
    // HAS_HW_CRC32C is never set on unsupported architectures.
    #[allow(unreachable_code)]
    crc
}

// ── FNV-1a 64-bit software fallback ───────────────────────────────────────

#[inline]
fn fnv1a_update(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

// ── Hasher ────────────────────────────────────────────────────────────────

pub struct DnsHasher {
    crc: u32,
    fnv: u64,
    hw: bool,
}

impl Hasher for DnsHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if self.hw {
            self.crc = crc32c_hw(self.crc, bytes);
        } else {
            self.fnv = fnv1a_update(self.fnv, bytes);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        if self.hw {
            // Spread 32-bit CRC to 64 bits via Fibonacci hashing to reduce
            // hash-table slot collisions in the lower bits.
            let c = self.crc as u64;
            c ^ c.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        } else {
            self.fnv
        }
    }
}

// ── BuildHasher ───────────────────────────────────────────────────────────

/// Drop-in `BuildHasher` for `HashMap`/`HashSet` over DNS names.
/// Hardware CRC32c is selected at construction time based on what `init()` detected.
#[derive(Clone)]
pub struct DnsHasherBuilder {
    hw: bool,
}

impl Default for DnsHasherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsHasherBuilder {
    pub fn new() -> Self {
        Self {
            hw: HAS_HW_CRC32C.load(Ordering::Relaxed),
        }
    }
}

impl BuildHasher for DnsHasherBuilder {
    type Hasher = DnsHasher;
    fn build_hasher(&self) -> DnsHasher {
        DnsHasher {
            crc: 0,
            fnv: 0xcbf2_9ce4_8422_2325,
            hw: self.hw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::hash::BuildHasher;

    fn make_builder() -> DnsHasherBuilder {
        // Force hardware path if available, else software.
        // init() may not have been called in unit tests, so we call it here.
        HAS_HW_CRC32C.store(false, Ordering::Relaxed);
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("sse4.2") {
            HAS_HW_CRC32C.store(true, Ordering::Relaxed);
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("crc") {
            HAS_HW_CRC32C.store(true, Ordering::Relaxed);
        }
        DnsHasherBuilder::new()
    }

    fn hash_bytes(b: &[u8]) -> u64 {
        let builder = make_builder();
        let mut h = builder.build_hasher();
        h.write(b);
        h.finish()
    }

    #[test]
    fn same_input_same_output() {
        let a = hash_bytes(b"example.com.");
        let b = hash_bytes(b"example.com.");
        assert_eq!(a, b, "same input must produce same hash");
    }

    #[test]
    fn different_inputs_different_hashes() {
        let a = hash_bytes(b"example.com.");
        let b = hash_bytes(b"evil.com.");
        assert_ne!(a, b, "different domains must not collide");
    }

    #[test]
    fn empty_input() {
        let h = hash_bytes(b"");
        // Just must not panic and finish() must be callable.
        let _ = h;
    }

    #[test]
    fn long_domain() {
        // 63-char label (DNS max) repeated — exercises 8-byte chunking.
        let long = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com.";
        let a = hash_bytes(long);
        let b = hash_bytes(long);
        assert_eq!(a, b);
    }

    #[test]
    fn hw_and_sw_consistent() {
        // Hash via hardware path.
        HAS_HW_CRC32C.store(false, Ordering::Relaxed);
        #[cfg(target_arch = "x86_64")]
        let hw_available = std::is_x86_feature_detected!("sse4.2");
        #[cfg(target_arch = "aarch64")]
        let hw_available = std::arch::is_aarch64_feature_detected!("crc");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let hw_available = false;

        if !hw_available {
            return; // nothing to test
        }

        // Software hash
        let sw_hash = hash_bytes(b"test.runbound.local.");

        // Hardware hash
        HAS_HW_CRC32C.store(true, Ordering::Relaxed);
        let hw_hash = hash_bytes(b"test.runbound.local.");

        // SW and HW use different algorithms intentionally, so hashes differ.
        // What we verify: both are stable (same input → same output on same path).
        HAS_HW_CRC32C.store(false, Ordering::Relaxed);
        assert_eq!(sw_hash, hash_bytes(b"test.runbound.local."));
        HAS_HW_CRC32C.store(true, Ordering::Relaxed);
        assert_eq!(hw_hash, hash_bytes(b"test.runbound.local."));
    }

    #[test]
    fn works_as_hashmap_hasher() {
        let builder = make_builder();
        let mut map: HashMap<String, u32, DnsHasherBuilder> =
            HashMap::with_hasher(builder);
        map.insert("example.com.".to_string(), 42);
        map.insert("evil.com.".to_string(), 1337);
        assert_eq!(map.get("example.com."), Some(&42));
        assert_eq!(map.get("evil.com."), Some(&1337));
        assert_eq!(map.get("missing.com."), None);
    }

    #[test]
    fn asm_matches_intrinsic() {
        // Verify crc32c_sse42_asm produces identical output to crc32c_sse42
        // for all interesting input lengths (0..=80 covers all DNS label sizes).
        #[cfg(target_arch = "x86_64")]
        if !std::is_x86_feature_detected!("sse4.2") {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        {
            let data: Vec<u8> = (0u8..=79).collect();
            for len in 0..=80usize {
                let input = &data[..len];
                let intrinsic = unsafe { crc32c_sse42(0, input) };
                let asm_out   = unsafe { crc32c_sse42_asm(0, input) };
                assert_eq!(
                    intrinsic, asm_out,
                    "asm/intrinsic mismatch at len={len}: {intrinsic:#010x} vs {asm_out:#010x}"
                );
            }
        }
    }

    #[test]
    fn asm_stable_across_starts() {
        // Same content, different starting CRC — ensures asm version handles
        // the crc accumulator correctly across all 3 input-size stages.
        #[cfg(target_arch = "x86_64")]
        {
            let data = b"example.com.";
            let a = unsafe { crc32c_sse42_asm(0xFFFF_FFFFu32, data) };
            let b = unsafe { crc32c_sse42_asm(0xFFFF_FFFFu32, data) };
            assert_eq!(a, b);
            // Also check it differs from zero-init (basic sanity)
            let z = unsafe { crc32c_sse42_asm(0, data) };
            assert_ne!(a, z);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // hash_wire_qname + IdentityHasher tests (Livraison A, #156)
    // ─────────────────────────────────────────────────────────────────────────

    /// Hot-path normalisation: raw wire buffer → lowercase via SIMD.
    fn build_wire_qname_hot(name: &str) -> Vec<u8> {
        use crate::dns::simd;
        use smallvec::SmallVec;
        let mut buf = Vec::new();
        let n = name.trim_end_matches('.');
        for label in n.split('.') {
            buf.push(label.len() as u8);
            let mut lc: SmallVec<[u8; 64]> = SmallVec::new();
            simd::copy_lowercase_label(&mut lc, label.as_bytes());
            buf.extend_from_slice(&lc);
        }
        buf.push(0u8);
        buf
    }

    /// Load-time normalisation: hickory Name iteration → lowercase via SIMD.
    /// This is the path used when building WireRecordIndex from LocalZoneSet.
    fn build_wire_qname_load(name_str: &str) -> Vec<u8> {
        use crate::dns::simd;
        use hickory_proto::rr::Name;
        use smallvec::SmallVec;
        use std::str::FromStr;
        let name = Name::from_str(name_str).expect("valid name");
        let mut buf = Vec::new();
        for label in name.iter() {
            buf.push(label.len() as u8);
            let mut lc: SmallVec<[u8; 64]> = SmallVec::new();
            simd::copy_lowercase_label(&mut lc, label);
            buf.extend_from_slice(&lc);
        }
        buf.push(0u8);
        buf
    }

    /// THE mandatory round-trip test.
    ///
    /// Verifies that the load-time path (hickory Name iteration + SIMD lowercase)
    /// and the hot-path (raw wire buffer + SIMD lowercase) produce IDENTICAL wire
    /// bytes AND identical `hash_wire_qname` keys for all test cases.
    ///
    /// If this test fails, WireRecordIndex lookups will NEVER hit → silent no-op.
    #[test]
    fn wire_qname_roundtrip() {
        let cases = [
            ("a.bench.test.",  "FQDN lowercase"),
            ("A.BENCH.TEST.",  "FQDN mixed-case"),
            ("bench.test",     "no trailing dot"),
            ("x.example.com.", "multi-label"),
        ];
        for (name, label) in &cases {
            let load_wire = build_wire_qname_load(name);
            let hot_wire  = build_wire_qname_hot(name);
            assert_eq!(
                load_wire, hot_wire,
                "[{}] wire bytes differ: load={:?} hot={:?}",
                label, load_wire, hot_wire
            );
            let k_load = super::hash_wire_qname(&load_wire);
            let k_hot  = super::hash_wire_qname(&hot_wire);
            assert_eq!(
                k_load, k_hot,
                "[{}] hash mismatch: k_load={:#018x} k_hot={:#018x}",
                label, k_load, k_hot
            );
        }
    }

    #[test]
    fn hash_wire_qname_deterministic() {
        let w = build_wire_qname_hot("a.bench.test.");
        assert_eq!(super::hash_wire_qname(&w), super::hash_wire_qname(&w));
    }

    #[test]
    fn hash_wire_qname_distinct() {
        let a = build_wire_qname_hot("a.bench.test.");
        let b = build_wire_qname_hot("b.bench.test.");
        assert_ne!(super::hash_wire_qname(&a), super::hash_wire_qname(&b));
    }

    #[test]
    fn hash_wire_qname_case_invariant() {
        let lo = build_wire_qname_hot("a.bench.test.");
        let up = build_wire_qname_hot("A.BENCH.TEST.");
        assert_eq!(
            super::hash_wire_qname(&lo),
            super::hash_wire_qname(&up),
            "mixed-case must hash identically to lowercase"
        );
    }

    #[test]
    fn len_bytes_not_mangled_by_lowercase() {
        // DNS label length bytes are 0x01-0x3F (labels 1-63 bytes).
        // 0x41 = b'A' — first byte copy_lowercase_label would alter.
        // This proves length bytes survive normalisation unchanged.
        let w = build_wire_qname_load("a.bench.test.");
        let mut pos = 0usize;
        while pos < w.len() {
            let len = w[pos] as usize;
            if len == 0 { break; }
            assert!(len < 0x41,
                "length byte 0x{:02x} at pos {} >= 0x41, would be corrupted", len, pos);
            pos += 1 + len;
        }
    }

    #[test]
    fn identity_hasher_passthrough() {
        use std::hash::{BuildHasher, Hasher};
        let bh = super::IdentityHasherBuilder;
        let mut h = bh.build_hasher();
        h.write_u64(0xDEAD_BEEF_CAFE_1234u64);
        assert_eq!(h.finish(), 0xDEAD_BEEF_CAFE_1234u64);
    }

    #[test]
    fn identity_hasher_in_hashmap() {
        use std::collections::HashMap;
        let w = build_wire_qname_hot("a.bench.test.");
        let key = super::hash_wire_qname(&w);
        let mut map: HashMap<u64, &str, super::IdentityHasherBuilder> =
            HashMap::with_hasher(super::IdentityHasherBuilder);
        map.insert(key, "hit");
        assert_eq!(map.get(&key), Some(&"hit"));
        let other = super::hash_wire_qname(&build_wire_qname_hot("other.test."));
        assert!(map.get(&other).is_none());
    }

}

// ── Wire-QNAME fast hash (for WireRecordIndex) ────────────────────────────

/// Hash a DNS wire-format QNAME (lowercase, uncompressed, labels length-prefixed,
/// root \0 terminal) for use in `WireRecordIndex`.
///
/// Uses the same CRC32c SSE4.2 + Fibonacci-spread as `DnsHasher` — identical
/// quality and hardware path, callable directly on `&[u8]` without Hasher trait
/// overhead (~1 virtual dispatch saved per hot-path lookup).
///
/// # Normalisation contract
/// Caller MUST pass a lowercase wire-QNAME produced by `simd::copy_lowercase_label`.
/// `tests::wire_qname_roundtrip` enforces byte-for-byte equivalence between the
/// load-time (hickory Name) and hot-path (raw wire) normalisation paths.
#[inline]
pub fn hash_wire_qname(wire_qname: &[u8]) -> u64 {
    let mut h = DnsHasherBuilder::new().build_hasher();
    h.write(wire_qname);
    h.finish()
}

// ── Identity BuildHasher (for HashMap<u64, _, IdentityHasherBuilder>) ────

/// `BuildHasher` that passes a `u64` key through as its own hash (identity).
///
/// Used for `WireRecordIndex::map: HashMap<u64, _, IdentityHasherBuilder>` where
/// keys are already high-quality 64-bit hashes from `hash_wire_qname`.
/// Re-hashing a CRC32c Fibonacci-spread u64 wastes ~3 cycles/lookup; this removes
/// that overhead.
///
/// # Safety
/// Only correct when keys have uniform 64-bit entropy (`hash_wire_qname` guarantees
/// this).  Do NOT use with low-entropy or sequential keys.
#[derive(Clone, Default)]
pub struct IdentityHasherBuilder;

pub struct IdentityHasher(u64);

impl std::hash::Hasher for IdentityHasher {
    /// Non-u64 write fallback (FNV-1a mix) — not called on the hot path.
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        let mut h = self.0;
        for &b in bytes { h ^= b as u64; h = h.wrapping_mul(0x0000_0100_0000_01B3); }
        self.0 = h;
    }
    #[inline(always)]
    fn write_u64(&mut self, k: u64) { self.0 = k; }
    #[inline(always)]
    fn finish(&self) -> u64 { self.0 }
}

impl std::hash::BuildHasher for IdentityHasherBuilder {
    type Hasher = IdentityHasher;
    #[inline(always)]
    fn build_hasher(&self) -> IdentityHasher { IdentityHasher(0) }
}
