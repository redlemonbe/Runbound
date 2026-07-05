// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Issue #22 — AXFR/IXFR zone transfer (RFC 5936/1995).
// Runbound acts as primary; secondaries pull full zone data via AXFR over TCP.
//
// The transfer itself is built in the hickory-free wire serving core
// (`wire_serve::axfr_response`); this module owns only the `axfr-allow` access
// control, which is pure IP/CIDR matching with no DNS-library dependency.

use std::net::IpAddr;
use std::str::FromStr;

/// Whether `ip` is permitted to pull a zone transfer, per the `axfr-allow`
/// CIDR/host list. Empty list ⇒ deny all (fail-closed).
pub fn is_transfer_allowed(ip: IpAddr, allow_cidrs: &[String]) -> bool {
    if allow_cidrs.is_empty() {
        return false;
    }
    allow_cidrs.iter().any(|cidr| cidr_matches(cidr, ip))
}

fn cidr_matches(cidr: &str, ip: IpAddr) -> bool {
    if let Some((addr_str, prefix_str)) = cidr.split_once('/') {
        let Ok(prefix) = prefix_str.parse::<u8>() else { return false; };
        match (ip, IpAddr::from_str(addr_str).ok()) {
            (IpAddr::V4(client), Some(IpAddr::V4(net))) => {
                // SEC-G1: prefix 0 = match-all (mask 0); avoids `1u32 << 32` (debug panic / release fail-closed).
                let mask = if prefix == 0 { 0 } else if prefix >= 32 { u32::MAX } else { !((1u32 << (32 - prefix)) - 1) };
                (u32::from(client) & mask) == (u32::from(net) & mask)
            }
            (IpAddr::V6(client), Some(IpAddr::V6(net))) => {
                let cb = client.octets();
                let nb = net.octets();
                let full_bytes = (prefix / 8) as usize;
                if cb[..full_bytes.min(16)] != nb[..full_bytes.min(16)] {
                    return false;
                }
                let rem = prefix % 8;
                if rem > 0 && full_bytes < 16 {
                    let mask = 0xFF_u8 << (8 - rem);
                    (cb[full_bytes] & mask) == (nb[full_bytes] & mask)
                } else {
                    true
                }
            }
            _ => false,
        }
    } else {
        IpAddr::from_str(cidr).map(|n| n == ip).unwrap_or(false)
    }
}

#[cfg(test)]
mod axfr_tests {
    use super::cidr_matches;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn cidr_zero_matches_all_v4() {
        // SEC-G1: /0 must match any IPv4 (previously matched nothing / debug-panicked).
        assert!(cidr_matches("0.0.0.0/0", IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(cidr_matches("0.0.0.0/0", IpAddr::from_str("192.168.1.1").unwrap()));
    }
    #[test]
    fn cidr_normal_v4() {
        assert!(cidr_matches("192.168.0.0/16", IpAddr::from_str("192.168.5.5").unwrap()));
        assert!(!cidr_matches("192.168.0.0/16", IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(cidr_matches("10.1.2.3/32", IpAddr::from_str("10.1.2.3").unwrap()));
        assert!(!cidr_matches("10.1.2.3/32", IpAddr::from_str("10.1.2.4").unwrap()));
    }
    #[test]
    fn cidr_malformed_fails_closed() {
        assert!(!cidr_matches("not-a-cidr", IpAddr::from_str("1.2.3.4").unwrap()));
        assert!(!cidr_matches("1.2.3.4/abc", IpAddr::from_str("1.2.3.4").unwrap()));
    }
}
