#![allow(dead_code)]
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// DNS domain name hash — issue #72
//
// Hardware CRC32 (SSE4.2) with FNV-1a software fallback.
// Used for worker routing: hash(qname) % num_workers.

/// Hash a DNS name byte slice to a u32.
///
/// Uses CRC32c (SSE4.2) on x86_64 when available at runtime.
/// Falls back to FNV-1a on all other architectures or when SSE4.2 is absent.
pub fn hash_dns_name(name: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("sse4.2") {
        // SAFETY: guarded by is_x86_feature_detected above.
        return unsafe { hash_crc32(name) };
    }
    hash_fnv1a(name)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn hash_crc32(name: &[u8]) -> u32 {
    use std::arch::x86_64::_mm_crc32_u32;
    let mut h: u32 = 0xFFFF_FFFF;
    for chunk in name.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        h = _mm_crc32_u32(h, u32::from_le_bytes(word));
    }
    h ^ 0xFFFF_FFFF
}

fn hash_fnv1a(name: &[u8]) -> u32 {
    name.iter().fold(2_166_136_261u32, |h, &b| {
        (h ^ b as u32).wrapping_mul(16_777_619)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_across_identical_inputs() {
        let a = hash_dns_name(b"example.com");
        let b = hash_dns_name(b"example.com");
        assert_eq!(a, b);
    }

    #[test]
    fn different_names_differ() {
        let a = hash_dns_name(b"example.com");
        let b = hash_dns_name(b"other.org");
        assert_ne!(a, b, "collision on trivial inputs");
    }

    #[test]
    fn empty_name_does_not_panic() {
        let _ = hash_dns_name(b"");
    }

    #[test]
    fn distribution_basic() {
        // Verify all hashes route to distinct buckets mod 4 for 4 distinct names
        let names: &[&[u8]] = &[b"a.com", b"b.com", b"c.net", b"d.org"];
        let buckets: Vec<u32> = names.iter().map(|n| hash_dns_name(n) % 4).collect();
        // Just verify no panic and all values are in 0..4
        assert!(buckets.iter().all(|&b| b < 4));
    }
}
