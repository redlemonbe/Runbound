// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// #202 — sovereign full-recursion backend.
//
// Wraps the *stable* recursor that ships inside hickory-resolver 0.26.1 (feature
// `recursor`): iterative resolution from the root servers (no third-party forwarder),
// QNAME minimisation and DNSSEC validation, with secure defaults:
//   - `deny_server` defaults to hickory's RECOMMENDED_SERVER_FILTERS (22 nets incl. RFC1918,
//     loopback, link-local) → a NS pointing at an internal address is never queried (anti-SSRF).
//   - `recursion_limit` / `ns_recursion_limit` bound the delegation walk (anti-DoS budget).
//   - case randomisation (0x20) is enabled here (off by default) for off-path poisoning resistance.
//
// EXPERIMENTAL / opt-in: only used when `resolution: full-recursion`. Default stays `forward`.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use hickory_proto::op::{Message, Query};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions};

/// IANA root servers (IPv4) — the public, stable recursion bootstrap ("hints").
/// <https://www.iana.org/domains/root/servers>
const ROOT_HINTS_V4: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),     // a.root-servers.net
    Ipv4Addr::new(170, 247, 170, 2),  // b
    Ipv4Addr::new(192, 33, 4, 12),    // c
    Ipv4Addr::new(199, 7, 91, 13),    // d
    Ipv4Addr::new(192, 203, 230, 10), // e
    Ipv4Addr::new(192, 5, 5, 241),    // f
    Ipv4Addr::new(192, 112, 36, 4),   // g
    Ipv4Addr::new(198, 97, 190, 53),  // h
    Ipv4Addr::new(192, 36, 148, 17),  // i
    Ipv4Addr::new(192, 58, 128, 30),  // j
    Ipv4Addr::new(193, 0, 14, 129),   // k
    Ipv4Addr::new(199, 7, 83, 42),    // l
    Ipv4Addr::new(202, 12, 27, 33),   // m
];

/// The concrete recursor type used by the server (Tokio runtime).
pub type SovereignRecursor = Recursor<TokioRuntimeProvider>;

/// Build the full-recursion backend with secure defaults.
///
/// `dnssec` mirrors the `dnssec-validation` config flag: when true, the recursor validates
/// from the built-in IANA root trust anchor; when false, validation is disabled (still
/// recurses from root, just without RRSIG checking).
pub fn build_recursor(dnssec: bool) -> Result<SovereignRecursor, String> {
    let roots: Vec<IpAddr> = ROOT_HINTS_V4.iter().copied().map(IpAddr::V4).collect();

    // Keep hickory's secure defaults (deny_server = 22 recommended filters = anti-SSRF,
    // recursion_limit = 24 = budget); only turn on 0x20 case randomisation.
    let options = RecursorOptions {
        case_randomization: true,
        ..Default::default()
    };

    let policy = if dnssec {
        // DnssecConfig is #[non_exhaustive]; its defaults are exactly what we want
        // (trust_anchor: None → built-in IANA root KSK, sane NSEC3 iteration limits).
        DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default())
    } else {
        DnssecPolicy::ValidationDisabled
    };

    Recursor::new(
        &roots,
        policy,
        None, // no pre-seeded encrypted-transport state
        options,
        TokioRuntimeProvider::default(),
    )
    .map_err(|e| format!("failed to build sovereign recursor: {e}"))
}

/// Resolve a single query iteratively from the root.
pub async fn recursor_resolve(
    recursor: &SovereignRecursor,
    query: Query,
    dnssec_ok: bool,
) -> Result<Message, String> {
    recursor
        .resolve(query, Instant::now(), dnssec_ok)
        .await
        .map_err(|e| format!("recursor resolve error: {e}"))
}
