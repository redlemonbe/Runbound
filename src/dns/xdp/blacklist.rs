// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe
// XDP blacklist userspace helpers for issue #153.
// Converts dotted domain names to DNS wire-format QNAME keys for the
// dns_blacklist BPF_MAP_TYPE_HASH map.

/// Key size for the dns_blacklist BPF map (must match C char[256]).
pub const BLACKLIST_KEY_LEN: usize = 256;

/// Maximum domains the BPF map accepts (matches map max_entries in dns_xdp.c).
pub const BLACKLIST_MAX: usize = 500_000;

/// Convert a dotted ASCII domain name (e.g. "example.com") to a 256-byte
/// DNS wire-format QNAME key (e.g. \x07example\x03com\x00 + zeros).
///
/// Returns None if the domain contains an empty label, a label > 63 bytes,
/// or if the resulting wire form would exceed 255 bytes (RFC 1035 limit).
pub fn domain_to_key(domain: &str) -> Option<[u8; BLACKLIST_KEY_LEN]> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    let mut buf = [0u8; BLACKLIST_KEY_LEN];
    let mut pos = 0usize;
    for label in domain.split('.') {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > 63 {
            return None;
        }
        // Need 1 (length) + lb.len() + 1 (null terminator) remaining
        if pos + 1 + lb.len() + 1 > BLACKLIST_KEY_LEN {
            return None;
        }
        buf[pos] = lb.len() as u8;
        pos += 1;
        buf[pos..pos + lb.len()].copy_from_slice(lb);
        pos += lb.len();
    }
    // pos points to the null terminator byte (already 0 from zero-init)
    if pos >= BLACKLIST_KEY_LEN {
        return None;
    }
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_simple() {
        let key = domain_to_key("example.com").unwrap();
        assert_eq!(&key[..13], b"\x07example\x03com\x00");
        assert!(key[13..].iter().all(|&b| b == 0));
    }

    #[test]
    fn wire_format_subdomain() {
        let key = domain_to_key("www.example.com").unwrap();
        assert_eq!(&key[..17], b"\x03www\x07example\x03com\x00");
    }

    #[test]
    fn wire_format_trailing_dot() {
        let a = domain_to_key("example.com").unwrap();
        let b = domain_to_key("example.com.").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_label_rejected() {
        assert!(domain_to_key("foo..com").is_none());
        assert!(domain_to_key("").is_none());
    }

    #[test]
    fn label_too_long_rejected() {
        let long = "a".repeat(64);
        assert!(domain_to_key(&format!("{}.com", long)).is_none());
    }
}
