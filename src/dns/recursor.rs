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
// Opt-in: only used when `resolution: full-recursion`. Default stays `forward`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, Query};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::recursor::{
    DnssecConfig, DnssecPolicy, Recursor, RecursorError, RecursorOptions,
};

use crate::config::parser::ResolutionMode;

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

/// Resolve a single query iteratively from the root. The `RecursorError` is propagated as-is so
/// the caller can distinguish NXDOMAIN / NODATA (which carry the zone SOA) from real failures.
pub async fn recursor_resolve(
    recursor: &SovereignRecursor,
    query: Query,
    dnssec_ok: bool,
) -> Result<Message, RecursorError> {
    recursor.resolve(query, Instant::now(), dnssec_ok).await
}

/// Hot-swappable handle to the sovereign recursor. `None` = forward mode (or build failed →
/// the dispatch falls back to forwarding). Shared by the DNS data path and the API toggle.
pub type SharedRecursor = Arc<ArcSwap<Option<Arc<SovereignRecursor>>>>;

/// AtomicU8 mirror of `ResolutionMode` (1 = full-recursion, 0 = forward) read on the hot path.
pub fn mode_atomic(mode: ResolutionMode) -> Arc<AtomicU8> {
    Arc::new(AtomicU8::new(u8::from(mode == ResolutionMode::FullRecursion)))
}

/// Build the shared recursor handle for `mode`. The recursor is built only in full-recursion
/// mode; on build failure we log and return an empty handle so the caller forwards instead.
pub fn shared_recursor(mode: ResolutionMode, dnssec: bool) -> SharedRecursor {
    let inner = build_inner(mode, dnssec);
    Arc::new(ArcSwap::from_pointee(inner))
}

/// Rebuild an existing shared handle in place (live toggle). Returns the error string if
/// full-recursion was requested but the recursor failed to build (handle is left as `None`).
pub fn rebuild_shared(handle: &SharedRecursor, mode: ResolutionMode, dnssec: bool) -> Result<(), String> {
    if mode == ResolutionMode::FullRecursion {
        match build_recursor(dnssec) {
            Ok(r) => {
                handle.store(Arc::new(Some(Arc::new(r))));
                Ok(())
            }
            Err(e) => {
                handle.store(Arc::new(None));
                Err(e)
            }
        }
    } else {
        handle.store(Arc::new(None));
        Ok(())
    }
}

fn build_inner(mode: ResolutionMode, dnssec: bool) -> Option<Arc<SovereignRecursor>> {
    if mode != ResolutionMode::FullRecursion {
        return None;
    }
    match build_recursor(dnssec) {
        Ok(r) => {
            tracing::info!(dnssec, "resolution=full-recursion: sovereign recursor built");
            Some(Arc::new(r))
        }
        Err(e) => {
            tracing::error!("resolution=full-recursion requested but recursor build failed: {e} — forwarding");
            None
        }
    }
}
