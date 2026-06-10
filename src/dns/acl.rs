// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Access-control list — shared between the normal DNS path (server.rs)
// and the XDP fast-path (xdp/worker.rs).
//
// Mirrors Unbound's access-control directive:
//   access-control: <network/prefix> allow|deny|refuse
//
// Evaluation rules:
//   - First matching rule wins (same as Unbound).
//   - IPv4-mapped IPv6 (::ffff:a.b.c.d) is normalised to plain IPv4 before
//     matching so that IPv4 rules apply correctly on dual-stack sockets.
//     Without this, a client connecting on [::ffff:127.0.0.1] would not match
//     the rule `127.0.0.0/8 allow`, silently falling through to the
//     secure-default Refuse.
//   - If no rules are configured, all clients are allowed (backward compat
//     with stock Unbound which defaults to allow-all when unconfigured).
//   - If rules exist but the client IP matches none, the default is Refuse
//     (fail-secure — unrecognised clients cannot use the resolver).

use std::net::IpAddr;
use tracing::warn;

#[derive(Debug, Clone, PartialEq)]
pub enum AclAction {
    Allow,
    /// Silently drop the packet — no DNS response sent.
    Deny,
    /// Send a REFUSED response (RFC 2182 §2.1).
    Refuse,
}

#[derive(Clone)]
pub(crate) struct CidrBlock {
    prefix: IpAddr,
    prefix_len: u8,
}

impl CidrBlock {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let (ip_str, prefix_len) = if let Some(pos) = s.find('/') {
            let len: u8 = s[pos + 1..].parse().ok()?;
            (&s[..pos], len)
        } else {
            let ip: IpAddr = s.parse().ok()?;
            let len = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            (s, len)
        };
        let prefix: IpAddr = ip_str.parse().ok()?;
        Some(CidrBlock { prefix, prefix_len })
    }

    #[inline]
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.prefix, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 32u8.saturating_sub(self.prefix_len);
                let mask = !0u32 << shift;
                u32::from(net) & mask == u32::from(addr) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 128u8.saturating_sub(self.prefix_len);
                let mask = !0u128 << shift;
                u128::from(net) & mask == u128::from(addr) & mask
            }
            _ => false,
        }
    }
}

/// Set of CIDR ranges that must never appear in resolver responses.
/// Mirrors Unbound's `private-address` directive — blocks DNS rebinding attacks
/// where a malicious domain resolves to a private/loopback IP.
pub struct PrivateAddressSet(Vec<CidrBlock>);

impl PrivateAddressSet {
    pub fn from_config(cidrs: &[String]) -> Self {
        let parsed = cidrs
            .iter()
            .filter_map(|s| {
                CidrBlock::parse(s.trim()).or_else(|| {
                    warn!(cidr=%s, "private-address: parse error — ignored");
                    None
                })
            })
            .collect();
        Self(parsed)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|b| b.contains(ip))
    }
}

struct AclEntry {
    cidr: CidrBlock,
    action: AclAction,
}

impl AclEntry {
    fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split_whitespace();
        let net_str = parts.next()?;
        let action_str = parts.next()?;
        let action = match action_str {
            "allow" | "allow_snoop" | "allow_setrd" => AclAction::Allow,
            "deny" | "deny_non_local" => AclAction::Deny,
            "refuse" | "refuse_non_local" => AclAction::Refuse,
            _ => return None,
        };
        let cidr = CidrBlock::parse(net_str)?;
        Some(AclEntry { cidr, action })
    }

    #[inline]
    fn matches(&self, ip: IpAddr) -> bool {
        self.cidr.contains(ip)
    }
}

/// Compiled access-control list.  Build once from config, share via `Arc`.
pub struct Acl(Vec<AclEntry>);

impl Acl {
    pub fn from_config(entries: &[String]) -> Self {
        let parsed = entries
            .iter()
            .filter_map(|s| {
                AclEntry::parse(s).or_else(|| {
                    warn!(entry=%s, "access-control: parse error — ignored");
                    None
                })
            })
            .collect();
        Self(parsed)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Evaluate the ACL for `ip`.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are normalised to their
    /// plain IPv4 equivalent before matching, ensuring that rules configured
    /// as IPv4 CIDRs match correctly even when the OS delivers the connection
    /// as an IPv6 address on a dual-stack socket.
    #[inline]
    pub fn check(&self, ip: IpAddr) -> AclAction {
        if self.0.is_empty() {
            return AclAction::Allow;
        }
        // Normalise IPv4-mapped and deprecated IPv4-compatible IPv6 → plain IPv4.
        // to_ipv4() covers both ::ffff:x.x.x.x and ::x.x.x.x forms (SEC-2026-05-24-05).
        // Guard: preserve ::1 because to_ipv4() maps it to 0.0.0.1 (not loopback).
        let ip = match ip {
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    IpAddr::V6(v6)
                } else {
                    #[allow(deprecated)]
                    v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
                }
            }
            _ => ip,
        };
        for entry in &self.0 {
            if entry.matches(ip) {
                return entry.action.clone();
            }
        }
        AclAction::Refuse // no rule matched → fail-secure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_acl(entry: &str) -> Acl {
        Acl::from_config(&[entry.to_string()])
    }

    // SEC-2026-05-24-05: ::127.0.0.1 must match a 127.0.0.0/8 deny rule.
    #[test]
    fn acl_ipv4_compatible_loopback_matches_ipv4_rule() {
        let acl = make_acl("127.0.0.0/8 deny");
        let ip: IpAddr = "::127.0.0.1".parse().unwrap();
        assert_eq!(
            acl.check(ip),
            AclAction::Deny,
            "::127.0.0.1 must match 127.0.0.0/8 deny rule after normalisation"
        );
    }

    #[test]
    fn acl_ipv6_loopback_preserved() {
        let acl = make_acl("::1/128 deny");
        let ip: IpAddr = "::1".parse().unwrap();
        assert_eq!(
            acl.check(ip),
            AclAction::Deny,
            "::1 must match ::1/128 deny rule"
        );
    }

    #[test]
    fn acl_ipv4_mapped_matches_ipv4_rule() {
        let acl = make_acl("127.0.0.0/8 deny");
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(
            acl.check(ip),
            AclAction::Deny,
            "::ffff:127.0.0.1 must match 127.0.0.0/8 deny rule"
        );
    }

    #[test]
    fn acl_empty_allows_all() {
        let acl = Acl::from_config(&[]);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(acl.check(ip), AclAction::Allow);
    }
}
