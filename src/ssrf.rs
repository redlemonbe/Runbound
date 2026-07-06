// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// SSRF address filter and connection-time DNS guard — the single source of truth
// shared by the recursor (nameserver-IP filtering), the feed fetcher and the
// webhook client. Kept in its own std/tokio/reqwest-only module (no main-only
// deps) so it is reachable from the `fuzz` library build.

use std::net::IpAddr;

/// Reject addresses that must never be connected to / queried (anti-SSRF).
/// Mirrors the spirit of hickory's RECOMMENDED_SERVER_FILTERS: no loopback,
/// private, link-local, CGNAT, documentation, benchmarking, multicast or
/// unspecified. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is re-checked as IPv4 so it
/// cannot bypass the guard on a dual-stack host.
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.is_multicast()
                || o[0] == 0                       // 0.0.0.0/8
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xfe) == 18)    // 198.18.0.0/15 benchmark
                || o[0] >= 240) // 240.0.0.0/4 reserved
        }
        IpAddr::V6(a) => {
            // An IPv4-mapped address (::ffff:a.b.c.d) is routed by the kernel to the
            // embedded IPv4 on a dual-stack host — re-run the (thorough) v4 checks so
            // ::ffff:10.0.0.1 / ::ffff:127.0.0.1 can't bypass the SSRF guard.
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00                 // fc00::/7 ULA
                || (s[0] & 0xffc0) == 0xfe80                 // fe80::/10 link-local
                || (s[0] == 0x64 && s[1] == 0xff9b)          // 64:ff9b::/96 NAT64 → v4
                || (s[0] == 0x2001 && s[1] == 0x0db8)        // 2001:db8::/32 documentation
                || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0)) // ::/96 (incl. IPv4-compatible)
        }
    }
}

/// Inverse of [`is_public_ip`]: true for any private / special-use / internal
/// address a fetcher or webhook must not connect to.
pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    !is_public_ip(*ip)
}

/// A `reqwest` DNS resolver that filters private/internal IPs at the TCP
/// connection layer (defense-in-depth against DNS rebinding): even if a hostname
/// resolves to a public IP at validation time and an internal one at connect
/// time, the internal address is dropped here. Every hostname-to-address
/// resolution made by the SSRF-safe reqwest clients passes through this.
pub(crate) struct SsrfSafeDnsResolver;

impl reqwest::dns::Resolve for SsrfSafeDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            type DynErr = Box<dyn std::error::Error + Send + Sync>;

            let addrs = tokio::net::lookup_host(format!("{host}:0"))
                .await
                .map_err(|e| Box::new(e) as DynErr)?;

            let safe: Vec<std::net::SocketAddr> =
                addrs.filter(|a| !is_private_ip(&a.ip())).collect();

            if safe.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("all IPs for '{host}' are private/internal — SSRF blocked"),
                )) as DynErr);
            }
            Ok(Box::new(safe.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
