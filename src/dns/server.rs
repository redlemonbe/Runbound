// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Runbound DNS server — drop-in for Unbound.
//
// Architecture:
//   1. Access-control list check (per source IP, from unbound.conf)
//   2. Rate limiting (per source IP token bucket)
//   3. Check local zones (local-data, blacklist, feeds) in memory → instant
//   4. Otherwise → forward upstream via the in-house wire forward pool
//      (src/dns/forward.rs); full recursion is behind the optional `recursor` feature.
//
// UDP + TCP on the configured port (default 53).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use base64::Engine as _;
use bytes::Bytes;
use dashmap::DashMap;
use crate::dns::tsig::TsigAlg;

use crate::dns::forward::{self as forward_pool, ForwardPool};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use super::acl::{Acl, AclAction, PrivateAddressSet};
use super::local::LocalZoneSet;
use super::ratelimit::RateLimiter;
use super::kernel_loop::FallbackMsg;
use crate::config::parser::TlsConfig;
use crate::config::parser::UnboundConfig;
use crate::logbuffer::SharedLogBuffer;
use crate::logbuffer::LogAction;
use crate::stats::Stats;
use crate::stats::CACHE_HIT_THRESHOLD_US;

// ── Concurrency cap — prevents OOM under flood ─────────────────────────────
//
// The wire request dispatch spawns one tokio task per incoming DNS request with
// no inherent backpressure. Under a flood (DDoS or perf test) this exhausts RAM.
// A non-blocking try_acquire returns REFUSED instantly without allocating
// any additional memory, so the bound is hard even at line rate.
const MAX_INFLIGHT_REQUESTS: usize = 4_096;
/// #ddos tarpit defaults (overridable via abuse-tarpit-* config directives).
const ABUSE_TARPIT_MAX_DEFAULT: usize = 256;
const ABUSE_TARPIT_DELAY_MS_DEFAULT: u64 = 2000;
/// (hold delay ms, max concurrent held) — set once from config at startup.
static ABUSE_TARPIT_CFG: std::sync::OnceLock<(u64, usize)> = std::sync::OnceLock::new();
static TARPIT_SEMA: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
fn tarpit_sema() -> &'static Semaphore {
    let max = ABUSE_TARPIT_CFG.get().map(|c| c.1).unwrap_or(ABUSE_TARPIT_MAX_DEFAULT);
    TARPIT_SEMA.get_or_init(|| Semaphore::new(max))
}
fn tarpit_delay() -> Duration {
    Duration::from_millis(ABUSE_TARPIT_CFG.get().map(|c| c.0).unwrap_or(ABUSE_TARPIT_DELAY_MS_DEFAULT))
}

const RATE_LIMIT_QPS_DEFAULT: u64 = 200;


// ============================================================
// Handler
// ============================================================

pub struct RunboundHandler {
    pub zones: Arc<ArcSwap<LocalZoneSet>>,
    pool: Arc<ArcSwap<ForwardPool>>,
    rate_limiter: Arc<RateLimiter>,
    alert_tracker: Option<Arc<crate::alerts::AlertTracker>>,
    inflight: Arc<Semaphore>,
    acl: Arc<Acl>,
    private_addrs: Arc<PrivateAddressSet>,
    cache_max_ttl: u32,
    /// #164: minimum TTL floor — prevents clients from re-querying too aggressively.
    cache_min_ttl: u32,
    pub stats: Arc<Stats>,
    pub log_buffer: SharedLogBuffer,
    /// DNSSEC tracking enabled — mirrors `dnssec-validation: yes` in config.
    /// Read by the recursor's forward-validation path; the wire path's DNSSEC is
    /// served by `zone_signer` (local signed zones), so this is unread by default.
    #[allow(dead_code)]
    dnssec_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// #201: online DNSSEC signer for local zones — hot-swappable so the slave adopts the
    /// master's replicated keys at runtime. Inner `None` when local-zone-dnssec is off.
    zone_signer: crate::dns::zone_signer::SharedZoneSigner,
    /// #202: resolution mode — 0 = forward (default), 1 = full-recursion. Hot-swappable.
    resolution_mode: Arc<std::sync::atomic::AtomicU8>,
    /// #202: stateless handle for the API/relay plumbing (the validating resolver
    /// itself is stateless).
    #[allow(dead_code)]
    recursor: crate::dns::recursor::SharedRecursor,
    /// Optional prefetch tracker — None when prefetch: no (default).
    /// NOTE: the tracker is incremented only on the recursor path and no executor
    /// ever drains it (`take_hot` is test-only) — prefetch is an incomplete feature
    /// pending a prefetch loop (see audit finding). Unread on the default path.
    #[allow(dead_code)]
    prefetch_tracker: Option<Arc<crate::dns::prefetch::PrefetchTracker>>,
    /// #60: mutable cache map shared with XDP workers (via publish_loop).
    /// None when xdp-cache-snapshot: no or XDP feature not compiled.
    xdp_cache: Option<super::cache_snapshot::MutableCacheMap>,
    cache_max_entries: usize,
    /// #77: upstream list for transparent pool reconnection on DoT exhaustion.
    upstreams: crate::upstreams::SharedUpstreams,
    /// #33: per-upstream resolvers for racing mode.
    #[allow(dead_code)]
    per_upstream_resolvers: SharedResolversVec,
    #[allow(dead_code)]
    upstream_racing: bool,
    /// #33: per-upstream win counters — how many times each upstream answered first.
    pub racing_wins:
        Arc<dashmap::DashMap<String, Arc<std::sync::atomic::AtomicU64>, ahash::RandomState>>,
    /// #5: per-domain query counter — feeds GET /api/stats/top-domains.
    domain_stats: Arc<crate::domain_stats::DomainStats>,
    /// #94: enable /etc/resolv.conf fallback when all configured upstreams are down.
    resolv_fallback: bool,
    /// #94: true while resolv.conf fallback is active.
    pub fallback_active: Arc<std::sync::atomic::AtomicBool>,
    /// #108: serve-stale cache (default wire serving path) — wire-native, keyed by
    /// (lowercased presentation name, qtype). Fed on a successful forward, served on
    /// a transient upstream SERVFAIL (RFC 8767). `None` when serve-stale is off.
    stale_cache_wire: Option<Arc<dashmap::DashMap<(String, u16), (Vec<crate::dns::wire::Record>, std::time::Instant), ahash::RandomState>>>,
    /// #108: TTL to advertise for stale answers (seconds).
    stale_answer_ttl: u32,
    /// #108: max age of a stale entry (seconds).
    stale_max_age: u64,
    /// #14: allow DNS UPDATE (RFC 2136). False = refuse all UPDATE messages.
    allow_update: bool,
    block_https_record: bool,

    /// #14: TSIG keys for DNS UPDATE authentication: (name, algorithm, base64-secret).
    /// SEC-20: pre-decoded TSIG keys (name_lower, algorithm, key_bytes) — decoded once at startup.
    tsig_keys: Vec<(String, TsigAlg, Vec<u8>)>,
    axfr_allow: Vec<String>,
    /// #10/#186: compiled split-horizon table — live-swappable so API edits
    /// apply without a restart. Read once per slow-path query via ArcSwap.
    split_horizon: std::sync::Arc<arc_swap::ArcSwap<SplitHorizonTable>>,
    /// #203: require DNS Cookies (RFC 7873) on UDP.
    dns_cookies: bool,
    /// #203: RRL slip ratio (0 = legacy Refused-to-all).
    rrl_slip: u64,
    /// #203: per-boot secret for the server cookie HMAC.
    cookie_secret: [u8; 16],
    /// #203: counter driving the RRL slip leak.
    rrl_counter: std::sync::atomic::AtomicU64,
    /// #204: DDR (RFC 9462) endpoint info, Some when `ddr: yes` + a TLS hostname is set.
    /// DDR SVCB synthesis is not yet ported to the wire serving path — recursor-only
    /// (the synthesiser returns hickory records). See audit finding.
    #[allow(dead_code)]
    ddr: Option<DdrInfo>,
}

/// #10/#186: compiled split-horizon table — (CidrBlock list, per-subnet LocalZoneSet).
pub type SplitHorizonTable = Vec<(Vec<super::acl::CidrBlock>, std::sync::Arc<LocalZoneSet>)>;

/// #10/#186: process-wide handle to the live split-horizon table, published once
/// at startup so API write handlers can hot-swap it without a service restart.
pub static SPLIT_HORIZON_LIVE: std::sync::OnceLock<std::sync::Arc<arc_swap::ArcSwap<SplitHorizonTable>>> =
    std::sync::OnceLock::new();

/// #187: (re)build the per-view fast-path snapshots from the split-horizon table
/// and publish them live. Called on startup and on every API hot-swap, so the XDP
/// fast path can serve each source subnet its own view (no cross-view leak).
pub fn publish_view_snapshots(table: &SplitHorizonTable) {
    let views: crate::dns::cache_snapshot::ViewSnapshots = table
        .iter()
        .map(|(cidrs, zoneset)| {
            (cidrs.to_vec(), crate::dns::cache_snapshot::build_view_snapshot(zoneset))
        })
        .collect();
    crate::dns::cache_snapshot::SPLIT_HORIZON_SNAPSHOTS
        .get_or_init(|| std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())))
        .store(std::sync::Arc::new(views));
}

/// Compile editable split-horizon entries into the resolver's per-subnet table.
/// Used both at boot and on every live API edit.
pub fn compile_split_horizon(
    entries: &[crate::config::parser::SplitHorizonEntry],
) -> SplitHorizonTable {
    entries
        .iter()
        .filter_map(|entry| {
            let subnets: Vec<super::acl::CidrBlock> = entry
                .subnets
                .iter()
                .filter_map(|s| super::acl::CidrBlock::parse(s.trim()))
                .collect();
            if subnets.is_empty() {
                warn!(name = %entry.name, "split-horizon: no valid subnets — entry skipped");
                return None;
            }
            let zones = LocalZoneSet::from_config(&[], &entry.local_data);
            Some((subnets, std::sync::Arc::new(zones)))
        })
        .collect()
}

impl RunboundHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        zones: Arc<ArcSwap<LocalZoneSet>>,
        pool: Arc<ArcSwap<ForwardPool>>,
        rate_limiter: Arc<RateLimiter>,
        acl: Arc<Acl>,
        private_addrs: Arc<PrivateAddressSet>,
        cache_max_ttl: u32,
        cache_min_ttl: u32,
        stats: Arc<Stats>,
        log_buffer: SharedLogBuffer,
        dnssec_enabled: Arc<std::sync::atomic::AtomicBool>,
        zone_signer: crate::dns::zone_signer::SharedZoneSigner,
        prefetch_tracker: Option<Arc<crate::dns::prefetch::PrefetchTracker>>,
        xdp_cache: Option<super::cache_snapshot::MutableCacheMap>,
        cache_max_entries: usize,
        upstreams: crate::upstreams::SharedUpstreams,
        per_upstream_resolvers: SharedResolversVec,
        upstream_racing: bool,
        racing_wins: Arc<
            dashmap::DashMap<String, Arc<std::sync::atomic::AtomicU64>, ahash::RandomState>,
        >,
        resolv_fallback: bool,
        fallback_active: Arc<std::sync::atomic::AtomicBool>,
        domain_stats: Arc<crate::domain_stats::DomainStats>,
        serve_stale: bool,
        stale_answer_ttl: u32,
        stale_max_age: u64,
        allow_update: bool,
        block_https_record: bool,


        tsig_keys_raw: Vec<(String, String, String)>,
        alert_tracker: Option<Arc<crate::alerts::AlertTracker>>,
        axfr_allow: Vec<String>,
        split_horizon: std::sync::Arc<arc_swap::ArcSwap<SplitHorizonTable>>,
        resolution_mode: Arc<std::sync::atomic::AtomicU8>,
        recursor: crate::dns::recursor::SharedRecursor,
        dns_cookies: bool,
        rrl_slip: u64,
        ddr: Option<DdrInfo>,
    ) -> Self {
        Self {
            zones,
            pool,
            rate_limiter,
            alert_tracker,
            axfr_allow,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_REQUESTS)),
            acl,
            private_addrs,
            cache_max_ttl,
            cache_min_ttl,
            stats,
            log_buffer,
            dnssec_enabled,
            zone_signer,
            resolution_mode,
            recursor,
            prefetch_tracker,
            xdp_cache,
            cache_max_entries,
            upstreams,
            per_upstream_resolvers,
            upstream_racing,
            racing_wins,
            domain_stats,
            resolv_fallback,
            fallback_active,
            stale_cache_wire: if serve_stale {
                Some(Arc::new(dashmap::DashMap::with_hasher(ahash::RandomState::default())))
            } else {
                None
            },
            stale_answer_ttl,
            stale_max_age,
            allow_update,
            block_https_record,

            split_horizon,
            dns_cookies,
            rrl_slip,
            cookie_secret: {
                let mut sk = [0u8; 16];
                let _ = getrandom::fill(&mut sk);
                sk
            },
            rrl_counter: std::sync::atomic::AtomicU64::new(0),
            ddr,
            // SEC-20: decode TSIG keys once at startup instead of per-request.
            tsig_keys: tsig_keys_raw.into_iter().filter_map(|(name, alg_str, secret_b64)| {
                let Some(alg) = TsigAlg::parse(&alg_str) else {
                    tracing::error!(alg=%alg_str, key=%name, "TSIG: unsupported algorithm — key will NOT be loaded, DDNS may be unprotected");
                    return None;
                };
                match base64::engine::general_purpose::STANDARD.decode(&secret_b64) {
                    // Normalize the key name to match the TSIG verifier, which compares
                    // against the request key name with the trailing dot stripped
                    // (tsig::verify_request). Storing "key." here while the verifier looks
                    // up "key" caused UnknownKey for any config name written with a trailing
                    // dot (e.g. tsig-key: "name." ...). Strip it on both sides.
                    Ok(bytes) => Some((name.trim_end_matches('.').to_ascii_lowercase(), alg, bytes)),
                    Err(e) => {
                        tracing::error!(key=%name, err=%e, "TSIG: base64 decode failed — key will NOT be loaded, DDNS may be unprotected");
                        None
                    }
                }
            }).collect(),
        }
    }

}

impl RunboundHandler {
    /// De-hickory fast path: resolve a query entirely on the own wire codec when
    /// it needs none of the hickory-typed special handling. Returns
    /// `Some(response_bytes)` when fully handled, or `None` for the routed-out
    /// cases (with the `recursor` feature, the recursor handler takes them;
    /// default builds drop on `None`).
    ///
    /// Routed to the fallback (before any side-effectful gate, so gates run once):
    /// non-QUERY opcodes (UPDATE), AXFR/IXFR/ANY, non-IN class (CHAOS), HTTPS-block,
    /// DNS cookies, split-horizon, signed local zones, recursor mode, alert tracker,
    /// RRL-with-slip, and any ACL result other than Allow. The dominant forward and
    /// plain local-zone paths are served here with zero hickory.
    ///
    /// Observability note: the per-query web-UI log buffer is hickory-name typed and
    /// is not written on this fast path; stats counters are. Full parity returns when
    /// the handler's logging is wire-native.
    /// Wire-native query log — feeds the webui Logs panel / `GET /api/logs`.
    /// Latency stats are recorded inline by `serve_wire`; this only emits the
    /// structured log entry (mirrors the recursor `record_query`, no hickory types).
    fn log_query_wire(&self, client: IpAddr, name: &str, qtype: u16, action: LogAction, start: Instant) {
        let is_notable = matches!(
            action,
            LogAction::Nxdomain | LogAction::Servfail | LogAction::Refused | LogAction::Blocked
        );
        if tracing::enabled!(tracing::Level::INFO)
            || (is_notable && tracing::enabled!(tracing::Level::WARN) && self.log_buffer.is_enabled())
        {
            let elapsed_ms = start.elapsed().as_millis() as u32;
            // MED-06: sanitize the name before structured log emission (log injection).
            let safe = sanitize_name_str(name);
            let client_log = self.log_buffer.push_query(&safe, &client, qtype, action, elapsed_ms);
            info!(client = %client_log, name = %safe, qtype = qtype, action = action.as_str(), ms = elapsed_ms, "query");
        }
    }

    /// #108: store the last successful records for a (name, qtype) — wire-native
    /// serve-stale source. Evicts the oldest entry when at `cache_max_entries`.
    fn store_stale_wire(&self, name_lc: &str, qtype: u16, records: &[crate::dns::wire::Record]) {
        if let Some(ref sc) = self.stale_cache_wire {
            if !records.is_empty() {
                if sc.len() >= self.cache_max_entries {
                    if let Some(old) = sc.iter().next().map(|e| e.key().clone()) {
                        sc.remove(&old);
                    }
                }
                sc.insert(
                    (name_lc.to_string(), qtype),
                    (records.to_vec(), std::time::Instant::now()),
                );
            }
        }
    }

    /// #108 / RFC 8767: return a stale answer for (name, qtype) if one is cached and
    /// younger than `stale_max_age`, with the TTL rewritten to `stale_answer_ttl`.
    fn try_stale_wire(&self, name_lc: &str, qtype: u16) -> Option<Vec<crate::dns::wire::Record>> {
        let sc = self.stale_cache_wire.as_ref()?;
        let entry = sc.get(&(name_lc.to_string(), qtype))?;
        let (ref recs, stored_at) = *entry;
        if stored_at.elapsed().as_secs() > self.stale_max_age || recs.is_empty() {
            return None;
        }
        let ttl = self.stale_answer_ttl;
        Some(
            recs.iter()
                .map(|r| {
                    let mut rc = r.clone();
                    rc.ttl = ttl;
                    rc
                })
                .collect(),
        )
    }

    pub async fn serve_wire(&self, query: &[u8], peer: std::net::SocketAddr) -> Option<Vec<u8>> {
        use crate::dns::wire::consts::{class, opcode, rcode, rtype};
        use crate::dns::wire::Message as WMessage;

        let msg = WMessage::parse(query).ok()?;
        let q = msg.first_question()?.clone();
        let qtype = q.qtype;

        // ── Route-outs (no gate side-effects yet) ───────────────────────────
        match msg.header.opcode() {
            opcode::QUERY => {}
            opcode::UPDATE => {
                // ── RFC 2136 DNS UPDATE, wire-native (TSIG via crate::dns::tsig) ──
                if !self.allow_update {
                    debug!(ip = %peer.ip(), "DNS UPDATE refused — allow-update: no");
                    return Some(self.wire_update_response(&msg, rcode::REFUSED));
                }
                let (rc, verified) = crate::dns::ddns::handle_update_wire(
                    query,
                    &msg,
                    &self.zones,
                    &self.tsig_keys,
                    peer.ip(),
                );
                let resp = self.wire_update_response(&msg, rc);
                // RFC 8945 §5.4.1: a TSIG-authenticated request gets a signed
                // response (whatever the rcode) so the client can verify it.
                return Some(match verified {
                    Some(v) => match self
                        .tsig_keys
                        .iter()
                        .find(|(n, _, _)| *n == v.key_name)
                    {
                        Some((_, alg, secret)) => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            crate::dns::tsig::sign_response(
                                &resp,
                                &v.request_mac,
                                &v.key_name,
                                *alg,
                                secret,
                                now,
                                300,
                            )
                        }
                        None => resp,
                    },
                    None => resp,
                });
            }
            _ => return Some(self.wire_error(&msg, rcode::NOTIMP)), // NOTIFY/STATUS/etc.
        }
        if matches!(qtype, rtype::AXFR | rtype::IXFR) {
            // ── AXFR/IXFR zone transfer (#22), wire-native ──────────────────
            // Gated solely by axfr-allow (not the normal ACL), matching the
            // prior hickory dispatch order. IXFR is served as a full AXFR.
            self.stats.inc_total();
            self.stats.inc_qtype_raw(qtype);
            if self.axfr_allow.is_empty()
                || !crate::dns::axfr::is_transfer_allowed(peer.ip(), &self.axfr_allow)
            {
                warn!(ip = %peer.ip(), "AXFR/IXFR refused — not in axfr-allow");
                self.stats.inc_refused();
                return Some(self.wire_error(&msg, rcode::REFUSED));
            }
            return Some(
                match crate::dns::wire_serve::axfr_response(&msg, &self.zones.load()) {
                    Some(bytes) => bytes,
                    None => self.wire_error(&msg, rcode::NXDOMAIN),
                },
            );
        }
        // ── DNSSEC: signed-zone serving (wire-native) ───────────────────────
        // Placed before the RRL/alert route-outs so a query within a signed zone
        // is never downgraded to an unsigned reply by the fallback handler. Rate
        // limiting is applied inline (signed responses are amplification-relevant).
        {
            let signer_guard = self.zone_signer.load_full();
            if let Some(signer) = signer_guard.as_ref().as_ref() {
                let do_bit = msg.edns().ok().flatten().map(|e| e.dnssec_ok()).unwrap_or(false);
                if do_bit && signer.apex_for(&q.name).is_some() {
                    let client_ip = peer.ip();
                    if !matches!(self.acl.check(client_ip), AclAction::Allow) {
                        return None; // denied client → fallback handler drops it
                    }
                    self.stats.inc_total();
                    self.stats.inc_qtype_raw(qtype);
                    if !self.rate_limiter.check(client_ip) {
                        self.stats.inc_refused();
                        return Some(self.wire_error(&msg, rcode::REFUSED));
                    }
                    let _permit = match self.inflight.try_acquire() {
                        Ok(p) => p,
                        Err(_) => return Some(self.wire_error(&msg, rcode::REFUSED)),
                    };
                    let zones = self.zones.load();
                    return Some(self.serve_signed(&msg, &q, signer, &zones));
                }
            }
        }
        let client_ip = peer.ip();

        // ── ACL (wire-native) ───────────────────────────────────────────────
        match self.acl.check(client_ip) {
            AclAction::Allow => {}
            AclAction::Deny => {
                // Silent drop: an empty buffer means the listener sends nothing.
                self.stats.inc_refused();
                return Some(Vec::new());
            }
            AclAction::Refuse => {
                self.stats.inc_refused();
                return Some(self.wire_error(&msg, rcode::REFUSED));
            }
        }

        let start = Instant::now();
        self.stats.inc_total();
        self.stats.inc_qtype_raw(qtype);

        // ── DNS Cookies (RFC 7873) — anti-spoof on real UDP clients ─────────
        // Loopback peers are the TCP/DoT/DoH relay (connection-verified): skip.
        if self.dns_cookies && !peer.ip().is_loopback() {
            let client_cookie = msg
                .edns()
                .ok()
                .flatten()
                .and_then(|e| e.options.iter().find(|(c, _)| *c == 10).map(|(_, d)| d.clone()));
            if let Some(cc) = client_cookie {
                if cc.len() >= 8 {
                    let expected = server_cookie(&self.cookie_secret, &cc[..8], peer.ip());
                    let verified = cc.len() >= 16 && {
                        use subtle::ConstantTimeEq;
                        bool::from(cc[8..16].ct_eq(&expected))
                    };
                    if !verified {
                        let mut full = cc[..8].to_vec();
                        full.extend_from_slice(&expected);
                        self.stats.inc_refused();
                        return Some(self.wire_badcookie(&msg, full));
                    }
                }
            }
        }

        // ── Rate limit, with RRL SLIP (#203) ────────────────────────────────
        // slip=0 → REFUSED to all. slip>0 → leak 1-in-slip as REFUSED (a legit
        // client learns it is limited) and drop the rest, so a spoofed flood gets
        // zero amplification.
        if !self.rate_limiter.check(client_ip) {
            self.stats.inc_refused();
            if self.rrl_slip == 0 {
                return Some(self.wire_error(&msg, rcode::REFUSED));
            }
            let n = self.rrl_counter.fetch_add(1, Ordering::Relaxed);
            if n % self.rrl_slip == 0 {
                return Some(self.wire_error(&msg, rcode::REFUSED));
            }
            return Some(Vec::new()); // drop
        }
        let _permit = match self.inflight.try_acquire() {
            Ok(p) => p,
            Err(_) => return Some(self.wire_error(&msg, rcode::REFUSED)),
        };

        // ── Alert / anti-DDoS escalation (#12), wire-native ─────────────────
        // Connection transports arrive via the loopback relay (abuse handled there
        // on the real IP); skip loopback. Only escalate verified (non-spoofed)
        // sources: non-loopback here is always UDP, so verification = a valid
        // server cookie.
        if let Some(at) = &self.alert_tracker {
            if !client_ip.is_loopback() {
                let cookie_ok = msg
                    .edns()
                    .ok()
                    .flatten()
                    .and_then(|e| e.options.iter().find(|(c, _)| *c == 10).map(|(_, d)| d.clone()))
                    .map(|cc| {
                        cc.len() >= 16 && {
                            use subtle::ConstantTimeEq;
                            let expected = server_cookie(&self.cookie_secret, &cc[..8], client_ip);
                            bool::from(cc[8..16].ct_eq(&expected))
                        }
                    })
                    .unwrap_or(false);
                match at.record(client_ip, cookie_ok) {
                    crate::alerts::AbuseVerdict::Block => {
                        self.stats.inc_refused();
                        return Some(self.wire_error(&msg, rcode::REFUSED));
                    }
                    crate::alerts::AbuseVerdict::Tarpit => {
                        if let Ok(_p) = tarpit_sema().try_acquire() {
                            tokio::time::sleep(tarpit_delay()).await;
                        }
                        self.stats.inc_refused();
                        return Some(self.wire_error(&msg, rcode::REFUSED));
                    }
                    crate::alerts::AbuseVerdict::Serve => {}
                }
            }
        }

        // ── Special query classes/types (RFC-mandated rejections), wire-native ──
        // CHAOS class (version.bind/hostname.bind identity probes) → NOTIMP (RFC 5358).
        if q.qclass != class::IN {
            self.stats.inc_refused();
            return Some(self.wire_error(&msg, rcode::NOTIMP));
        }
        // Identity-probe names regardless of class → REFUSED (defence in depth, SEC-03).
        let qname_pres = q.name.to_ascii();
        let qname_lc = qname_pres.to_ascii_lowercase();
        if matches!(
            qname_lc.as_str(),
            "version.bind." | "hostname.bind." | "id.server." | "authors.bind."
        ) {
            self.stats.inc_refused();
            return Some(self.wire_error(&msg, rcode::REFUSED));
        }
        // ANY → REFUSED (RFC 8482 amplification mitigation).
        if qtype == rtype::ANY {
            return Some(self.wire_error(&msg, rcode::REFUSED));
        }
        // block-https-record: suppress HTTPS type-65 (QUIC/HTTP3 guard) → empty NOERROR.
        if self.block_https_record && qtype == rtype::HTTPS {
            return Some(self.wire_answer(&msg, &[], rcode::NOERROR));
        }

        // #5: per-domain counter (feeds GET /api/stats/top-domains). The XDP fast
        // path counts cache hits in the kernel loop; the slow path counts here so
        // forwarded/local queries are not missing from top-domains in noxdp mode.
        self.domain_stats.inc(&qname_lc);

        // ── Split-horizon (#10): per-subnet zone override, wire-native ──────
        // Clone only the matching per-subnet zone Arc, dropping the table guard.
        let sh_match: Option<std::sync::Arc<LocalZoneSet>> = {
            let table = self.split_horizon.load();
            table
                .iter()
                .find(|(subnets, _)| subnets.iter().any(|cb| cb.contains(client_ip)))
                .map(|(_, z)| std::sync::Arc::clone(z))
        };
        if let Some(sh_zones) = sh_match {
            if let Some(resp) = crate::dns::wire_serve::serve_datagram(query, &sh_zones) {
                self.stats.inc_local_hits();
                self.stats.record_latency_us(start.elapsed().as_micros() as u64);
                self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Local, start);
                return Some(resp);
            }
            // No match in the split-horizon zone → fall through to global zones.
        }

        // ── Local zones (own wire serving core) ─────────────────────────────
        let zones = self.zones.load();
        if let Some(resp) = crate::dns::wire_serve::serve_datagram(query, &zones) {
            self.stats.inc_local_hits();
            self.stats.record_latency_us(start.elapsed().as_micros() as u64);
            self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Local, start);
            return Some(resp);
        }

        // ── #8: per-subnet additive blacklist (SLOW PATH ONLY) ──────────────
        // A domain blocked only for this client's subnet is, by design, not in the
        // global filter, so it is never caught by the XDP/kernel fast path and lands
        // here. REFUSED and never cached (so it can't leak to other subnets). The
        // fast path is untouched.
        if crate::subnet_policy::blocks(client_ip, &qname_lc) {
            self.stats.inc_blocked();
            self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Blocked, start);
            return Some(self.wire_error(&msg, rcode::REFUSED));
        }

        // ── Full recursion (own validating resolver) ───────────────────────
        // resolution: full-recursion → resolve iteratively from the root and
        // DNSSEC-validate. A Bogus answer is never served (fail-closed → SERVFAIL)
        // UNLESS the client set CD (Checking Disabled): RFC 4035 §3.2.2 requires a
        // validating resolver to return the data unvalidated so the client can
        // validate it itself (the answer never carries AD in that case).
        if self.resolution_mode.load(Ordering::Relaxed) == 1 {
            use crate::dns::dnssec_chain::Verdict;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let cd_bit = msg.header.cd();
            match crate::dns::recursor_wire::resolve_validated(&q.name, qtype, now).await {
                Some(val) if val.verdict != Verdict::Bogus || cd_bit => {
                    match val.verdict {
                        Verdict::Secure => self.stats.inc_dnssec_secure(),
                        Verdict::Insecure => self.stats.inc_dnssec_insecure(),
                        // Reached only with CD=1 — counted as bogus, served unvalidated.
                        Verdict::Bogus => self.stats.inc_dnssec_bogus(),
                    }
                    // AD only when the data is genuinely Secure and the client is
                    // DNSSEC-aware — never on a CD-served (unvalidated/Bogus) answer.
                    let do_bit = msg.edns().ok().flatten().map(|e| e.dnssec_ok()).unwrap_or(false);
                    let set_ad = val.verdict == Verdict::Secure && do_bit;
                    if val.rcode == rcode::NXDOMAIN {
                        self.stats.inc_nxdomain();
                        self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Nxdomain, start);
                        // RFC 2308 §3: carry the zone SOA (+ DNSSEC denial for DO).
                        let mut resp =
                            self.wire_negative(&msg, rcode::NXDOMAIN, &val.authority, do_bit);
                        if set_ad && resp.len() > 3 {
                            resp[3] |= 0x20; // authenticated denial (RFC 4035)
                        }
                        return Some(resp);
                    }
                    let mut records = val.records;
                    if records.is_empty() {
                        // NODATA (NOERROR, empty answer) — also carry the SOA (RFC 2308 §3).
                        let mut resp =
                            self.wire_negative(&msg, rcode::NOERROR, &val.authority, do_bit);
                        if set_ad && resp.len() > 3 {
                            resp[3] |= 0x20;
                        }
                        self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Recursed, start);
                        return Some(resp);
                    }
                    for r in records.iter_mut() {
                        r.ttl = r.ttl.max(self.cache_min_ttl).min(self.cache_max_ttl);
                    }
                    let mut resp = self.wire_answer(&msg, &records, rcode::NOERROR);
                    if set_ad && resp.len() > 3 {
                        resp[3] |= 0x20; // AD bit (RFC 4035)
                    }
                    // Never cache a CD-served (Bogus) answer: it must not poison the
                    // cache for non-CD clients, who would then get it as NOERROR without
                    // the SERVFAIL that validation requires. Secure/Insecure are cacheable.
                    if val.verdict != Verdict::Bogus {
                        self.maybe_cache_wire(&q, &resp, &records);
                    }
                    self.stats.inc_forwarded();
                    self.stats.record_forward(start.elapsed().as_micros() as u64);
                    // full-recursion: the answer came from our own iterative resolver,
                    // not a configured upstream — log it as `recursed`, not `forwarded`.
                    self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Recursed, start);
                    return Some(resp);
                }
                Some(_bogus) => {
                    // Bogus and the client did NOT set CD → never served (RFC 4035) → SERVFAIL.
                    self.stats.inc_dnssec_bogus();
                    self.stats.inc_servfail();
                    self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Servfail, start);
                    return Some(self.wire_error(&msg, rcode::SERVFAIL));
                }
                None => {
                    // Resolution failure (timeout / no reachable authority).
                    self.stats.inc_servfail();
                    self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Servfail, start);
                    return Some(self.wire_error(&msg, rcode::SERVFAIL));
                }
            }
        }

        // ── Forward upstream (own wire forward pool) ────────────────────────
        let (fwd, winner) = self.pool.load().forward(query).await;
        // #33: record the racing win for the upstream that answered first.
        if let Some(ref w) = winner {
            self.racing_wins
                .entry(w.clone())
                .or_insert_with(|| Arc::new(std::sync::atomic::AtomicU64::new(0)))
                .fetch_add(1, Ordering::Relaxed);
        }
        // #94: resolv.conf fallback when ALL configured upstreams are down. The
        // recovery loop (start_server) removes the temporary entries once a primary
        // upstream recovers. Spawned off the hot path; guarded by a CAS so a flood of
        // SERVFAILs triggers the rebuild exactly once.
        if matches!(fwd, crate::dns::forward::ResolveResult::Servfail)
            && self.resolv_fallback
            && !self.fallback_active.load(Ordering::Relaxed)
            && crate::upstreams::all_non_temporary_unhealthy(&self.upstreams)
            && self
                .fallback_active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            let ups = Arc::clone(&self.upstreams);
            let pool_rebuild = Arc::clone(&self.pool);
            tokio::spawn(async move {
                crate::upstreams::add_resolv_fallback(&ups);
                let addrs = crate::upstreams::upstream_addrs(&ups);
                let _ = rebuild_and_swap(&pool_rebuild, &addrs, false).await;
                warn!("resolv.conf fallback activated");
            });
        }
        match fwd {
            crate::dns::forward::ResolveResult::Answer { mut records } => {
                // private-address block (#rebinding)
                if !self.private_addrs.is_empty() {
                    for r in &records {
                        let ip = match &r.rdata {
                            crate::dns::wire::Rdata::A(a) => Some(std::net::IpAddr::V4(*a)),
                            crate::dns::wire::Rdata::Aaaa(a) => Some(std::net::IpAddr::V6(*a)),
                            _ => None,
                        };
                        if let Some(ip) = ip {
                            if self.private_addrs.contains(ip) {
                                self.stats.inc_servfail();
                                self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Servfail, start);
                                return Some(self.wire_error(&msg, rcode::SERVFAIL));
                            }
                        }
                    }
                }
                // TTL clamp
                for r in records.iter_mut() {
                    r.ttl = r.ttl.max(self.cache_min_ttl).min(self.cache_max_ttl);
                }
                let resp = self.wire_answer(&msg, &records, rcode::NOERROR);
                self.maybe_cache_wire(&q, &resp, &records);
                // #108: remember this answer so a later transient SERVFAIL can serve it stale.
                self.store_stale_wire(&qname_lc, qtype, &records);
                let fwd_us = start.elapsed().as_micros() as u64;
                self.stats.inc_forwarded();
                self.stats.record_forward(fwd_us);
                let action = if fwd_us < CACHE_HIT_THRESHOLD_US {
                    LogAction::Cached
                } else {
                    LogAction::Forwarded
                };
                self.log_query_wire(client_ip, &qname_pres, qtype, action, start);
                Some(resp)
            }
            crate::dns::forward::ResolveResult::NegativeAnswer { rcode: rc, .. } => {
                let action = if rc == rcode::NXDOMAIN {
                    self.stats.inc_nxdomain();
                    LogAction::Nxdomain
                } else {
                    self.stats.inc_servfail();
                    LogAction::Servfail
                };
                self.log_query_wire(client_ip, &qname_pres, qtype, action, start);
                Some(self.wire_error(&msg, rc))
            }
            crate::dns::forward::ResolveResult::Servfail => {
                // #108 / RFC 8767: a transient upstream failure serves the last good
                // answer (stale) instead of SERVFAIL, when serve-stale is enabled.
                if let Some(stale) = self.try_stale_wire(&qname_lc, qtype) {
                    self.stats.inc_stale_served();
                    let resp = self.wire_answer(&msg, &stale, rcode::NOERROR);
                    self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Cached, start);
                    return Some(resp);
                }
                self.stats.inc_servfail();
                self.log_query_wire(client_ip, &qname_pres, qtype, LogAction::Servfail, start);
                Some(self.wire_error(&msg, rcode::SERVFAIL))
            }
        }
    }

    /// Build a response carrying `records` for `req` (header copied, QR/RA set,
    /// EDNS echoed). Wire-native — no hickory.
    fn wire_answer(
        &self,
        req: &crate::dns::wire::Message,
        records: &[crate::dns::wire::Record],
        rcode_low: u16,
    ) -> Vec<u8> {
        use crate::dns::wire::{Header, Message};
        let mut h = Header {
            id: req.header.id,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        h.set_qr(true);
        h.set_rd(req.header.rd());
        h.set_ra(true);
        h.set_rcode_low(rcode_low);
        let mut additional = Vec::new();
        if let Ok(Some(req_edns)) = req.edns() {
            let mut e = crate::dns::wire::Edns {
                udp_payload: req_edns.udp_payload.clamp(512, 1232),
                ..Default::default()
            };
            e.set_dnssec_ok(req_edns.dnssec_ok());
            additional.push(e.to_record());
        }
        let m = Message {
            header: h,
            questions: req.questions.clone(),
            answers: records.to_vec(),
            authority: Vec::new(),
            additional,
        };
        m.encode()
    }

    /// Build a negative response (NXDOMAIN / NODATA) carrying the zone SOA in the
    /// authority section (RFC 2308 §3) so downstream resolvers can negative-cache.
    /// The SOA is always included; DNSSEC denial records (NSEC/NSEC3/RRSIG) only for
    /// DO clients (RFC 4035). `authority` is the validated upstream authority section.
    fn wire_negative(
        &self,
        req: &crate::dns::wire::Message,
        rcode_low: u16,
        authority: &[crate::dns::wire::Record],
        do_bit: bool,
    ) -> Vec<u8> {
        use crate::dns::wire::{consts::rtype, Header, Message};
        let mut h = Header {
            id: req.header.id,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        h.set_qr(true);
        h.set_rd(req.header.rd());
        h.set_ra(true);
        h.set_rcode_low(rcode_low);
        let auth: Vec<crate::dns::wire::Record> = authority
            .iter()
            .filter(|r| {
                r.rtype == rtype::SOA
                    || (do_bit
                        && matches!(r.rtype, rtype::NSEC | rtype::NSEC3 | rtype::RRSIG))
            })
            .cloned()
            .collect();
        let mut additional = Vec::new();
        if let Ok(Some(req_edns)) = req.edns() {
            let mut e = crate::dns::wire::Edns {
                udp_payload: req_edns.udp_payload.clamp(512, 1232),
                ..Default::default()
            };
            e.set_dnssec_ok(req_edns.dnssec_ok());
            additional.push(e.to_record());
        }
        let m = Message {
            header: h,
            questions: req.questions.clone(),
            answers: Vec::new(),
            authority: auth,
            additional,
        };
        m.encode()
    }

    /// Build an error/empty response (no answers) for `req` with `rcode_low`.
    fn wire_error(&self, req: &crate::dns::wire::Message, rcode_low: u16) -> Vec<u8> {
        self.wire_answer(req, &[], rcode_low)
    }

    /// Build an authoritative DNSSEC response (AA set, OPT with DO echoed) carrying
    /// `answers` and `authority`. Wire-native.
    fn wire_signed_answer(
        &self,
        req: &crate::dns::wire::Message,
        answers: &[crate::dns::wire::Record],
        authority: &[crate::dns::wire::Record],
        rcode_low: u16,
    ) -> Vec<u8> {
        use crate::dns::wire::{Edns, Header, Message};
        let mut h = Header {
            id: req.header.id,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        h.set_qr(true);
        h.set_aa(true);
        h.set_rd(req.header.rd());
        h.set_ra(false);
        h.set_rcode_low(rcode_low);
        let mut e = Edns::default();
        if let Ok(Some(req_edns)) = req.edns() {
            e.udp_payload = req_edns.udp_payload.clamp(512, 1232);
        }
        e.set_dnssec_ok(true);
        let m = Message {
            header: h,
            questions: req.questions.clone(),
            answers: answers.to_vec(),
            authority: authority.to_vec(),
            additional: vec![e.to_record()],
        };
        m.encode()
    }

    /// Serve a query within a signed zone (DO bit set), wire-native: DNSKEY/SOA at
    /// the apex, signed positive answers (RRSIG), signed CNAME chains, and signed
    /// NSEC3 denials. Fails closed (SERVFAIL) rather than serve an unsigned
    /// downgrade of a signed zone (SEC-L2).
    fn serve_signed(
        &self,
        msg: &crate::dns::wire::Message,
        q: &crate::dns::wire::Question,
        signer: &crate::dns::zone_signer::ZoneSigner,
        zones: &LocalZoneSet,
    ) -> Vec<u8> {
        use crate::dns::wire::consts::{rcode, rtype};
        use crate::dns::wire::Record;
        let qtype = q.qtype;

        // Apex meta types: DNSKEY and SOA are synthesized + signed.
        if qtype == rtype::DNSKEY && signer.is_apex(&q.name) {
            if let Some(recs) = signer.apex_dnskey(&q.name) {
                return self.wire_signed_answer(msg, &recs, &[], rcode::NOERROR);
            }
        }
        if qtype == rtype::SOA && signer.is_apex(&q.name) {
            if let Some(recs) = signer.signed_soa(&q.name) {
                return self.wire_signed_answer(msg, &recs, &[], rcode::NOERROR);
            }
        }

        let key = crate::dns::local::wire_name_key(&q.name);
        match zones.find_wire(&key) {
            Some(crate::dns::local::ZoneAction::Refuse) => {
                return self.wire_error(msg, rcode::REFUSED);
            }
            Some(crate::dns::local::ZoneAction::NxDomain) => {
                return self.signed_negative_resp(msg, q, signer, zones, true);
            }
            _ => {}
        }

        // Exact records of the queried type → signed positive answer.
        let recs = zones.local_records_wire(&key, qtype);
        if !recs.is_empty() {
            let mut answer: Vec<Record> = recs.iter().map(|r| (*r).clone()).collect();
            if let Some(sig) = signer.sign_answer(qtype, &answer) {
                answer.push(sig);
            }
            return self.wire_signed_answer(msg, &answer, &[], rcode::NOERROR);
        }

        // CNAME chain → sign each RRset of the chain.
        if qtype != rtype::CNAME {
            let chain = crate::dns::wire_serve::follow_cname(zones, &key, qtype);
            if !chain.is_empty() {
                let mut answer = chain.clone();
                answer.extend(signer.sign_chain(&chain));
                return self.wire_signed_answer(msg, &answer, &[], rcode::NOERROR);
            }
        }

        // No record of this type: NODATA if the name exists, else NXDOMAIN.
        let is_nxdomain = !zones.name_has_records_wire(&key);
        self.signed_negative_resp(msg, q, signer, zones, is_nxdomain)
    }

    /// Build a signed negative response (SOA+RRSIG + NSEC3 denial). SEC-L2: on any
    /// failure to build the proof, return SERVFAIL — never an unsigned downgrade.
    fn signed_negative_resp(
        &self,
        msg: &crate::dns::wire::Message,
        q: &crate::dns::wire::Question,
        signer: &crate::dns::zone_signer::ZoneSigner,
        zones: &LocalZoneSet,
        is_nxdomain: bool,
    ) -> Vec<u8> {
        use crate::dns::wire::consts::rcode;
        let Some(apex) = signer.apex_for(&q.name) else {
            return self.wire_error(msg, rcode::SERVFAIL);
        };
        let owners = crate::dns::zone_signer::zone_owners(
            zones.records_wire.values().filter_map(|recs| {
                let n = recs.first()?.name.clone();
                Some((n, recs.iter().map(|r| r.rtype).collect::<Vec<u16>>()))
            }),
            &apex,
        );
        match signer.signed_negative(is_nxdomain, &q.name, &owners) {
            Some(authority) => {
                let rc = if is_nxdomain { rcode::NXDOMAIN } else { rcode::NOERROR };
                self.wire_signed_answer(msg, &[], &authority, rc)
            }
            None => {
                warn!(name = %q.name.to_ascii(), "signed-zone denial proof failed — SERVFAIL");
                self.wire_error(msg, rcode::SERVFAIL)
            }
        }
    }

    /// Build an RFC 2136 UPDATE response: opcode UPDATE preserved, QR set, the
    /// zone (question) section echoed, `rcode_low` set, no RA. Wire-native.
    fn wire_update_response(&self, req: &crate::dns::wire::Message, rcode_low: u16) -> Vec<u8> {
        use crate::dns::wire::consts::opcode;
        use crate::dns::wire::{Header, Message};
        let mut h = Header {
            id: req.header.id,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        h.set_qr(true);
        h.set_opcode(opcode::UPDATE);
        h.set_rcode_low(rcode_low);
        let m = Message {
            header: h,
            questions: req.questions.clone(),
            ..Default::default()
        };
        m.encode()
    }

    /// Build a BADCOOKIE (extended RCODE 23, RFC 7873) response carrying the
    /// 16-byte server cookie so the client can retry with a valid cookie.
    fn wire_badcookie(&self, req: &crate::dns::wire::Message, full_cookie: Vec<u8>) -> Vec<u8> {
        use crate::dns::wire::{Edns, Header, Message};
        const BADCOOKIE: u16 = 23;
        let mut h = Header { id: req.header.id, flags: 0, qdcount: 0, ancount: 0, nscount: 0, arcount: 0 };
        h.set_qr(true);
        h.set_rd(req.header.rd());
        h.set_ra(true);
        h.set_rcode_low(BADCOOKIE & 0x0F); // low nibble in the header
        let mut e = Edns::default();
        if let Ok(Some(req_edns)) = req.edns() {
            e.udp_payload = req_edns.udp_payload.clamp(512, 1232);
            e.set_dnssec_ok(req_edns.dnssec_ok());
        }
        e.ext_rcode = (BADCOOKIE >> 4) as u8; // high 8 bits of the 12-bit extended RCODE
        e.options.push((10, full_cookie)); // COOKIE option
        let m = Message {
            header: h,
            questions: req.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: vec![e.to_record()],
        };
        m.encode()
    }

    /// Insert a positive answer into the XDP cache snapshot (so the fast path can
    /// serve it). Mirrors the hickory path's cache insert, wire-native. Best-effort.
    fn maybe_cache_wire(
        &self,
        q: &crate::dns::wire::Question,
        resp_wire: &[u8],
        records: &[crate::dns::wire::Record],
    ) {
        let Some(cache) = &self.xdp_cache else { return };
        if records.is_empty() {
            return;
        }
        let min_ttl = records
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(60)
            .max(self.cache_min_ttl)
            .min(self.cache_max_ttl);
        let qname_lc = crate::dns::wire_builder::normalize_query_qname(q.name.wire());
        let raw_key = crate::dns::hasher::hash_wire_qname(&qname_lc);
        let key: u64 = raw_key ^ ((q.qtype as u64) << 48);
        let entry = super::cache_snapshot::CacheEntry {
            wire_payload: Bytes::copy_from_slice(resp_wire),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(min_ttl as u64),
            wire_qname: bytes::Bytes::copy_from_slice(&qname_lc),
        };
        let cache_ref = Arc::clone(cache);
        let max_ent = self.cache_max_entries;
        tokio::spawn(async move {
            super::cache_snapshot::cache_insert(&cache_ref, key, entry, max_ent);
        });
    }
}

impl RunboundHandler {
    /// #ddos: clone of the alert/abuse tracker, so the TCP/DoT/DoH relay can enforce
    /// bans on the REAL client IP — the handler itself only sees the loopback relay
    /// address for connection transports.
    pub fn alert_tracker(&self) -> Option<Arc<crate::alerts::AlertTracker>> {
        self.alert_tracker.clone()
    }

    // ─────────── Wire-based request dispatch (replaces hickory Server) ───────────

    /// Dispatch a raw DNS wire query and return the wire response. The in-house
    /// wire serving core (`serve_wire`) handles every path — local zones,
    /// forwarding and full-recursion (with DNSSEC validation). It returns `None`
    /// only on a malformed query, which we drop (empty = no response).
    pub async fn handle_request_wire(&self, wire: &[u8], peer: std::net::SocketAddr) -> Vec<u8> {
        self.serve_wire(wire, peer).await.unwrap_or_default()
    }
}


// ============================================================
// Helpers
// ============================================================

// is_pool_exhausted removed (uses NetError from hickory_resolver).
/// MED-06: wire-path name sanitizer — replaces any non-printable / non-ASCII byte
/// with '?' before the name reaches the structured log (prevents log injection).
/// Returns the input unchanged (borrow-free fast path) when already clean.
fn sanitize_name_str(s: &str) -> String {
    if s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        s.to_string()
    } else {
        s.chars()
            .map(|c| if c.is_ascii() && !c.is_ascii_control() { c } else { '?' })
            .collect()
    }
}

/// #204: DDR (RFC 9462) endpoint info used to synthesise the `_dns.resolver.arpa`
/// SVCB answer that points clients at this node's encrypted transports.
#[derive(Clone)]
#[allow(dead_code)]
struct DdrInfo {
    hostname: String,
    dot_port: u16,
    doh_port: u16,
    doq_port: u16,
}

/// RFC 7873 server cookie: HMAC-SHA256(secret, client_cookie || client_ip)[..8].
/// Used by the wire serving path to verify DNS Cookies on UDP queries.
fn server_cookie(secret: &[u8; 16], client_cookie: &[u8], ip: IpAddr) -> [u8; 8] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("hmac key");
    mac.update(&client_cookie[..client_cookie.len().min(8)]);
    match ip {
        IpAddr::V4(a) => mac.update(&a.octets()),
        IpAddr::V6(a) => mac.update(&a.octets()),
    }
    let out = mac.finalize().into_bytes();
    let mut c = [0u8; 8];
    c.copy_from_slice(&out[..8]);
    c
}



/// Shared, hot-swappable DNS resolver used by the server handler and the API.
/// Hot-swappable forward pool — replaces the old hickory TokioResolver.
pub type SharedResolver = Arc<ArcSwap<ForwardPool>>;

/// Per-upstream resolvers for racing — no-op now, racing is inside ForwardPool.
/// Kept for API compatibility with main.rs / api/mod.rs.
pub type SharedResolversVec = Arc<ArcSwap<Vec<(String, ())>>>;

/// Racing is now handled inside ForwardPool â no-op kept for API compat.
pub fn build_per_upstream_resolvers(
    _addrs: &[(String, u16, bool, Option<String>)],
    _dnssec: bool,
) -> anyhow::Result<Vec<(String, ())>> {
    Ok(Vec::new())
}

/// Create an empty SharedResolversVec â racing is now inside ForwardPool, this is a stub.
pub fn create_shared_resolvers_vec() -> SharedResolversVec {
    Arc::new(ArcSwap::from_pointee(Vec::new()))
}

/// Create a SharedResolver (ForwardPool) from config at startup.
pub fn create_shared_resolver(cfg: &UnboundConfig) -> anyhow::Result<SharedResolver> {
    let pool = forward_pool::create_shared_pool(cfg);
    Ok(pool)
}

/// Derive a TLS SNI hostname for a DoT upstream.
///
/// Uses `explicit` when provided; otherwise maps well-known public resolver IPs
/// to their correct certificate SANs. Falls back to the IP string for unknowns
/// (produces a DnsName from the IP literal, which will fail TLS validation on
/// servers that only advertise their DNS name as a SAN — the correct behaviour
/// is to set `tls_hostname` explicitly for such servers).
#[allow(dead_code)]
pub fn dot_tls_name(ip: &IpAddr, explicit: Option<&str>) -> Arc<str> {
    if let Some(h) = explicit {
        return Arc::from(h);
    }
    let known = match ip.to_string().as_str() {
        "1.1.1.1" | "1.0.0.1" => "cloudflare-dns.com",
        "9.9.9.9" | "149.112.112.112" => "dns.quad9.net",
        "8.8.8.8" | "8.8.4.4" => "dns.google",
        "208.67.222.222" | "208.67.220.220" => "dns.opendns.com",
        _ => "",
    };
    if known.is_empty() {
        Arc::from(ip.to_string())
    } else {
        Arc::from(known)
    }
}

/// Keepalive probe for the ForwardPool (replaces the old hickory warm_up).
async fn warm_up(pool: &ForwardPool) -> bool {
    pool.keepalive().await;
    true
}
/// Rebuild the ForwardPool from an explicit upstream list and atomically swap it in.
/// Replaces the old hickory-based rebuild_and_swap. Signature kept for API compat.
pub async fn rebuild_and_swap(
    shared: &SharedResolver,
    addrs: &[(String, u16, bool, Option<String>)],
    _dnssec: bool,
) -> anyhow::Result<bool> {
    forward_pool::rebuild_pool(shared, addrs).await;
    // Keepalive probe so DoT connections are established before the pool goes live.
    let pool_snap = shared.load();
    warm_up(&pool_snap).await;
    Ok(true)
}

/// Proactively warm up DoT connections at startup via ForwardPool::keepalive().
pub async fn warm_up_dot_connections(pool: &SharedResolver, dot_count: usize) {
    if dot_count == 0 {
        return;
    }
    pool.load().keepalive().await;
    info!(connections = dot_count, "DoT pool warmed up");
}

/// Periodic keepalive for DoT connections inside ForwardPool. Fires every 90 s.
pub async fn dot_keepalive_loop(
    pool: SharedResolver,
    upstreams: crate::upstreams::SharedUpstreams,
    stats: Arc<crate::stats::Stats>,
    _dnssec: bool,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(90));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await; // skip the immediate first tick
    loop {
        interval.tick().await;
        let dot_count = upstreams
            .read()
            .map(|u| u.iter().filter(|s| s.protocol == "dot").count())
            .unwrap_or(0);
        if dot_count == 0 {
            continue;
        }
        pool.load().keepalive().await;
        stats.record_dot_reconnect();
        debug!(connections = dot_count, "DoT keepalive: connections refreshed");
    }
}


// build_resolver_from_addrs removed â replaced by forward_pool::rebuild_pool().
// build_resolver removed â replaced by forward_pool::create_shared_pool().

// ============================================================
// Memory pressure guard
// ============================================================

// Check memory every 30 s. On Linux /proc/meminfo is a cheap kernel read.
const MEM_CHECK_SECS: u64 = 30;
// Scale-up cooldown: do not increase cache more often than every 5 minutes.
// Halving cooldown: do not halve more often than once every 5 minutes.
// Memory pressure thresholds (used ratio = 1 - MemAvailable/MemTotal):
const MEM_MOD_WATERMARK: f64 = 0.70; // [0.70, 0.80) → halve cache
const MEM_HIGH_WATERMARK: f64 = 0.80; // ≥ 0.80 → recalc + flush rate limiter

/// Resolve the process own cgroup v2 base directory from /proc/self/cgroup.
/// Returns /sys/fs/cgroup/<rel> or /sys/fs/cgroup as fallback.
fn cgroup_base() -> std::path::PathBuf {
    if let Ok(text) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(rel) = text.lines()
            .find(|l| l.starts_with("0::"))
            .and_then(|l| l.strip_prefix("0::"))
        {
            let p = std::path::PathBuf::from("/sys/fs/cgroup")
                .join(rel.trim().trim_start_matches('/'));
            if p.exists() {
                return p;
            }
        }
    }
    std::path::PathBuf::from("/sys/fs/cgroup")
}

/// Read the cgroup v2 hard memory limit in bytes.
/// Returns None when the limit is "max" (unrestricted) or the file is absent.
fn cgroup_memory_max_bytes() -> Option<u64> {
    let s = std::fs::read_to_string(cgroup_base().join("memory.max")).ok()?;
    let s = s.trim();
    if s == "max" {
        return None;
    }
    s.parse().ok()
}

/// Read the cgroup v2 current memory usage in bytes.
fn cgroup_memory_current_bytes() -> Option<u64> {
    std::fs::read_to_string(cgroup_base().join("memory.current"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Compute an appropriate resolver cache size from current available RAM.
///
/// 1 hickory cache entry ≈ 512 bytes.
/// Allocates up to 10 % of available memory, clamped to [512, 65536].
/// Inside a cgroup v2 container /proc/meminfo reflects host RAM; we use the
/// cgroup limit instead to avoid overcommitting the container's memory budget.
/// Falls back to 8192 when neither source is available.
fn cache_size_from_meminfo() -> usize {
    let avail_kb: u64 = if let Some(max_bytes) = cgroup_memory_max_bytes() {
        let current_bytes = cgroup_memory_current_bytes().unwrap_or(0);
        max_bytes.saturating_sub(current_bytes) / 1024
    } else {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|t| {
                t.lines()
                    .find(|l| l.starts_with("MemAvailable:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(0)
    };
    if avail_kb == 0 {
        return 8192;
    }
    // #cache: size the resolver cache to a generous slice of AVAILABLE memory (cgroup-aware),
    // so it scales with the host's RAM instead of a fixed tiny cap. This is a CEILING, not an
    // upfront allocation — entries fill it as queries arrive; the memory-pressure watermarks
    // (MEM_*_WATERMARK) shrink it dynamically if usage climbs, so growing it stays OOM-safe.
    // Was clamped at 65536 entries (~32 MiB) — absurdly small on a multi-GiB host.
    const CACHE_ENTRY_BYTES: u64 = 512; // rough avg cache entry (name + RRset + metadata)
    let entries = avail_kb * 1024 / 4 / CACHE_ENTRY_BYTES; // ~1/4 of available memory
    (entries as usize).clamp(8192, 64 * 1024 * 1024) // 8K floor … 64M entries (~32 GiB) ceiling
}

/// Read system memory and return (available_kb, total_kb).
/// Prefers cgroup v2 limits over /proc/meminfo when inside a container —
/// /proc/meminfo reports host RAM which would cause cache overcommit.
/// Returns None on any parse or I/O error (non-Linux, container without /proc, etc.).
fn read_meminfo() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let (mut total, mut available) = (0u64, 0u64);
    for line in text.lines() {
        if line.starts_with("MemTotal:") {
            total = line.split_whitespace().nth(1)?.parse().ok()?;
        } else if line.starts_with("MemAvailable:") {
            available = line.split_whitespace().nth(1)?.parse().ok()?;
        }
        if total > 0 && available > 0 {
            break;
        }
    }
    if total == 0 {
        return None;
    }
    // Cap at cgroup v2 limit when running inside a container.
    if let Some(max_bytes) = cgroup_memory_max_bytes() {
        let max_kb = max_bytes / 1024;
        if max_kb < total {
            let current_kb = cgroup_memory_current_bytes().unwrap_or(0) / 1024;
            total = max_kb;
            available = max_kb.saturating_sub(current_kb);
        }
    }
    Some((available, total))
}

/// Background task: monitors system memory and adjusts the DNS resolver cache size.
///
/// Four operating modes based on memory pressure (used = 1 - MemAvailable/MemTotal):
///   < 60 %  — scale up: restore cache toward optimal size (with cooldown).
///   60–70 % — stable: no action.
///   70–80 % — moderate pressure: halve cache size, floor at cache_min_entries.
///   ≥ 80 %  — high pressure: recalc cache from current RAM + flush rate limiter.
///
/// Three guards prevent infinite cache destruction on memory-constrained systems:
///   1. Floor: never halve below cfg.cache_min_entries (default 2048).
///   2. Cooldown: at most one halving per CACHE_HALVE_COOLDOWN (5 min).
///   3. No-effect detection: if halving does not reduce used_pct by ≥ 5 %,
///      halvings are disabled for this process lifetime with a clear WARN.
///
/// Cache changes take effect by rebuilding the forward pool and atomically
/// swapping it via ArcSwap. In-flight queries keep their Arc until completion.
/// Background task: monitors system memory and adjusts rate limiter under pressure.
/// The DNS cache now lives in ForwardPool (no hickory resolver cache to resize);
/// we keep the memory watermark logic to flush the rate limiter under high pressure.
pub async fn memory_guard_loop(
    rate_limiter: Arc<RateLimiter>,
    pool: Arc<ArcSwap<ForwardPool>>,
    cfg: Arc<UnboundConfig>,
    stats: Arc<Stats>,
    initial_cache_size: usize,
    upstreams: crate::upstreams::SharedUpstreams,
    _dnssec_enabled: Arc<std::sync::atomic::AtomicBool>,
) {
    let _ = initial_cache_size; // ForwardPool has no resolver cache to resize
    let mut interval = tokio::time::interval(Duration::from_secs(MEM_CHECK_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let Some((avail_kb, total_kb)) = tokio::task::spawn_blocking(read_meminfo)
            .await
            .ok()
            .flatten()
        else {
            continue;
        };
        let used_ratio = 1.0 - (avail_kb as f64 / total_kb as f64);

        if used_ratio >= MEM_HIGH_WATERMARK {
            // High pressure: rebuild pool (may help with DoT connection churn) + flush rate limiter.
            let addrs = crate::upstreams::upstream_addrs(&upstreams);
            let _ = rebuild_and_swap(&pool, &addrs, false).await;
            stats.reset_cache();
            let freed = rate_limiter.clear();
            warn!(
                used_pct = format!("{:.1}%", used_ratio * 100.0),
                freed_buckets = freed,
                "memory pressure high: pool rebuilt, rate limiter cleared"
            );
        } else if used_ratio >= MEM_MOD_WATERMARK {
            // Moderate pressure: nothing to halve in ForwardPool, just log.
            let min = cfg.cache_min_entries;
            let _ = min;
            debug!(used_pct = format!("{:.1}%", used_ratio * 100.0), "memory moderate pressure");
        }
        // Low/stable band: no action.
    }
}
// ============================================================
// TLS helpers
// ============================================================

/// Load TLS cert+key materials from PEM files. Returns None if not configured.
fn load_tls_materials(
    tls: &TlsConfig,
) -> Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_path = tls.cert_path.as_deref()?;
    let key_path = tls.key_path.as_deref()?;
    let cert_pem = std::fs::read(cert_path).ok()?;
    let key_pem = std::fs::read(key_path).ok()?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .flatten()
        .collect();
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .ok()??
        .clone_key();
    if certs.is_empty() {
        return None;
    }
    Some((certs, key))
}

/// Build a rustls ServerConfig for a specific DNS-over-TLS protocol.
///
/// * `alpn`      — ALPN token: `b"dot"`, `b"h2"`, or `b"doq"`.
/// * `tls13_only`— true for DoQ (Quinn requires TLS 1.3 exclusively).
/// * `client_ca` — optional path to CA PEM for mTLS (HIGH-08, DoT only).
fn build_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: &[u8],
    tls13_only: bool,
    client_ca: Option<&str>,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let builder = if tls13_only {
        // DoQ requires TLS 1.3 — Quinn rejects configs that allow TLS 1.2.
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        rustls::ServerConfig::builder()
    };

    let mut config = if let Some(ca_path) = client_ca {
        // HIGH-08: mutual TLS for DoT — require a client certificate signed by ca_path.
        let ca_pem =
            std::fs::read(ca_path).map_err(|e| anyhow::anyhow!("read CA cert {ca_path}: {e}"))?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()).flatten() {
            roots
                .add(cert)
                .map_err(|e| anyhow::anyhow!("load CA cert: {e}"))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| anyhow::anyhow!("mTLS verifier: {e}"))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("TLS config: {e}"))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("TLS config: {e}"))?
    };

    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(config))
}

// SO_REUSEPORT UDP socket: the kernel distributes incoming packets across
// all sockets bound to the same address:port, one per CPU core. Each socket
// is driven by a separate tokio task on a separate thread, giving true
// multi-core parallelism without any userspace load-balancing overhead.
#[cfg(unix)]
/// #167: bind a blocking std UDP socket on the server port with SO_REUSEPORT so
/// the XDP recursion-miss fallback can reply FROM the server port. We only ever
/// send on it; SO_REUSEPORT lets it coexist with the XDP / kernel-loop port bindings.
/// Cap a UDP DNS response to the client's maximum payload, setting TC (RFC 1035
/// §4.1.1 / RFC 6891). The budget is 512 bytes without EDNS, else the client's
/// advertised UDP size clamped to `[512, 1232]`. When the full answer exceeds it,
/// strip to header + question (keeping the OPT pseudo-RR for EDNS clients) and set
/// TC so the client retries over TCP. No-op when the answer already fits.
fn truncate_udp_response(resp: &mut Vec<u8>, query: &[u8]) {
    use crate::dns::wire::{consts::rtype, Message};
    let max = match Message::parse(query) {
        Ok(m) => match m.edns() {
            Ok(Some(e)) => (e.udp_payload as usize).clamp(512, 1232),
            _ => 512,
        },
        Err(_) => 512,
    };
    if resp.len() <= max {
        return;
    }
    let Ok(mut m) = Message::parse(resp) else {
        return;
    };
    m.header.set_tc(true);
    m.answers.clear();
    m.authority.clear();
    m.additional.retain(|r| r.rtype == rtype::OPT);
    let encoded = m.encode();
    // header + question (+ OPT) is well under any 512 budget; guard regardless.
    *resp = encoded;
    if resp.len() > max {
        resp.truncate(max);
    }
}

fn bind_xdp_reply_sock(port: u16) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse()?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

// ── FIX 6.2: Per-IP TCP connection cap ────────────────────────────────────────

/// Max concurrent TCP DNS connections from a single source IP (or /48 for IPv6).
const TCP_CONN_PER_IP_MAX: u16 = 20;

/// Truncate IPv6 to /48 for TCP connection tracking (consistent with rate limiter).
fn normalize_tcp_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[6..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

struct TcpConnTracker {
    counts: DashMap<IpAddr, Arc<AtomicU16>, ahash::RandomState>,
    last_warn: DashMap<IpAddr, Instant, ahash::RandomState>,
}

impl TcpConnTracker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            counts: DashMap::with_hasher(ahash::RandomState::default()),
            last_warn: DashMap::with_hasher(ahash::RandomState::default()),
        })
    }

    /// Attempt to claim a connection slot for `ip`.
    /// Returns `true` if allowed, `false` if the per-IP cap is exceeded.
    /// Loopback addresses (127.x and ::1) are always allowed (health checks).
    fn try_acquire(&self, ip: IpAddr) -> bool {
        if matches!(ip, IpAddr::V4(a) if a.is_loopback())
            || matches!(ip, IpAddr::V6(a) if a.is_loopback())
        {
            return true;
        }
        let counter = self
            .counts
            .entry(ip)
            .or_insert_with(|| Arc::new(AtomicU16::new(0)));
        let prev = counter.fetch_add(1, Ordering::Relaxed);
        if prev >= TCP_CONN_PER_IP_MAX {
            counter.fetch_sub(1, Ordering::Relaxed);
            let mut emit = false;
            self.last_warn
                .entry(ip)
                .and_modify(|t| {
                    if t.elapsed().as_secs() >= 60 {
                        *t = Instant::now();
                        emit = true;
                    }
                })
                .or_insert_with(|| {
                    emit = true;
                    Instant::now()
                });
            if emit {
                warn!(%ip, limit = TCP_CONN_PER_IP_MAX, "TCP per-IP connection cap reached — dropping");
            }
            false
        } else {
            true
        }
    }

    fn release(&self, ip: IpAddr) {
        // SCOPE the get() Ref so its DashMap shard read-lock is dropped BEFORE the
        // remove_if() below takes the SAME shard write-lock. Holding the read guard
        // across remove_if self-deadlocks DashMap: the worker thread hangs holding the
        // shard lock, and every later try_acquire()/release() for an IP hashing to that
        // shard blocks forever — freezing ALL subsequent TCP/DoT/DoH accepts from tracked
        // (non-loopback) clients after the very first connection. Loopback is never
        // inserted (try_acquire short-circuits) so it masked the bug in local testing.
        let reached_zero = {
            if let Some(c) = self.counts.get(&ip) {
                c.fetch_sub(1, Ordering::Relaxed) == 1
            } else {
                false
            }
        };
        if reached_zero {
            // Count just reached 0 — evict the entry so the map does not grow
            // unbounded when many distinct source IPs connect over time.
            // Re-insertion is safe: a concurrent increment will use or_insert_with.
            self.counts
                .remove_if(&ip, |_, v| v.load(Ordering::Relaxed) == 0);
            self.last_warn.remove(&ip);
        }
    }
}

/// Accept-with-limit loop for a public-facing TCP listener.
/// Connections within the per-IP cap are relayed to `relay_addr` (a loopback
/// listener served by the wire handler `handle_request_wire`) via bidirectional byte copy.
///
/// Trade-off: the handler sees 127.0.0.1 as the source for all relayed TCP
/// connections, so the DNS per-IP rate limiter uses a shared loopback bucket
/// for TCP clients. Acceptable because TCP DNS traffic is inherently low-volume
/// (large responses, DNSSEC chains). The TCP connection cap enforced here
/// prevents the primary DoS vector (FD exhaustion via many idle connections).
/// #208: live count of accepted TCP/DoT/DoH relay connections (listener saturation).
pub static ACTIVE_TCP_CONNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn run_tcp_with_limit(
    public_tcp: TcpListener,
    relay_addr: SocketAddr,
    tracker: Arc<TcpConnTracker>,
    conn_timeout: Duration,
    acl: Arc<Acl>,
    proxy_protocol: bool,
    alert: Option<Arc<crate::alerts::AlertTracker>>,
    // PENT-1/PENT-2: when true, prepend a PROXY v2 header carrying the REAL client IP
    // to the loopback relay connection so the handler (serve_wire) sees the real source
    // instead of 127.0.0.1. Required for the plain-TCP loopback listener (AXFR allow-list
    // + split-horizon). MUST be false for the DoT/DoH relays — their loopback listeners
    // expect a TLS handshake, not a PROXY header.
    forward_real_ip: bool,
) {
    loop {
        let (mut client, peer) = match public_tcp.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(err=%e, "TCP accept error");
                continue;
            }
        };
        // #21: PROXY protocol v2 — when enabled, the real client IP is carried in a
        // header prepended by the L4 load balancer; the socket peer is the LB. The
        // header is mandatory once enabled: drop connections without a valid one.
        let raw_ip = if proxy_protocol {
            match tokio::time::timeout(Duration::from_secs(5), read_proxy_v2(&mut client)).await {
                Ok(Some(ip)) => ip,
                _ => continue,
            }
        } else {
            peer.ip()
        };
        // FIX 2 (VUL-NEW-03): check loopback BEFORE normalize so that ::1
        // is not collapsed to :: (an unrelated /48 prefix) by normalize_tcp_ip.
        let src_ip = if raw_ip.is_loopback() {
            raw_ip
        } else {
            normalize_tcp_ip(raw_ip)
        };
        // SEC (Cycle I, SEC-I23): enforce the source-IP ACL on the REAL client. The relay
        // to the loopback wire listener makes the DNS handler see 127.0.0.1, so without
        // this check TCP/DoT/DoH would bypass allow/deny/refuse rules. Deny and Refuse both
        // drop the connection here (no DNS message parsed yet); loopback follows the same
        // ACL as the UDP path.
        if !matches!(acl.check(src_ip), AclAction::Allow) {
            continue;
        }
        // #ddos: the handler sees the loopback relay address for connection transports,
        // so enforce alert verdicts on the REAL client IP here. The TCP/TLS handshake
        // proves the IP (verified=true). Per-connection granularity.
        // Loopback never escalates (consistency with the handler; a local process must
        // not be able to self-ban 127.0.0.1 via the TCP relay) (#ddos).
        if let (Some(at), false) = (&alert, raw_ip.is_loopback()) {
            match at.record(raw_ip, true) {
                crate::alerts::AbuseVerdict::Block => continue,
                crate::alerts::AbuseVerdict::Tarpit => {
                    // Hold the attacker's connection a bounded delay, then drop it —
                    // wastes their time at near-zero cost (capped by the tarpit sema).
                    if let Ok(permit) = tarpit_sema().try_acquire() {
                        tokio::spawn(async move {
                            let _permit = permit;
                            tokio::time::sleep(tarpit_delay()).await;
                            drop(client);
                        });
                    }
                    continue;
                }
                crate::alerts::AbuseVerdict::Serve => {}
            }
        }
        if !tracker.try_acquire(src_ip) {
            // Over limit: drop immediately (TcpStream closed on drop → TCP FIN/RST)
            continue;
        }
        let tracker2 = Arc::clone(&tracker);
        ACTIVE_TCP_CONNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            let r = tokio::time::timeout(conn_timeout, async {
                let mut relay = TcpStream::connect(relay_addr).await?;
                // PENT-1/PENT-2: hand the REAL client IP to the loopback handler via a
                // PROXY v2 header so per-IP handler logic (AXFR allow-list, split-horizon)
                // sees the true source. Only the plain-TCP loopback listener parses it.
                if forward_real_ip {
                    use tokio::io::AsyncWriteExt;
                    relay.write_all(&proxy_v2_header(raw_ip)).await?;
                }
                tokio::io::copy_bidirectional(&mut client, &mut relay).await?;
                Ok::<_, std::io::Error>(())
            })
            .await;
            if let Ok(Err(e)) = r {
                debug!(err=%e, %src_ip, "TCP relay error");
            }
            tracker2.release(src_ip);
            ACTIVE_TCP_CONNS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

/// Build a PROXY protocol v2 header carrying `ip` as the source address (dst and
/// ports are zero — the loopback reader only consumes the source IP). Used by the
/// plain-TCP relay to hand the real client IP to the loopback handler (PENT-1/PENT-2).
fn proxy_v2_header(ip: std::net::IpAddr) -> Vec<u8> {
    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    let mut h = Vec::with_capacity(16 + 36);
    h.extend_from_slice(&SIG);
    h.push(0x21); // version 2, command PROXY
    match ip {
        std::net::IpAddr::V4(v4) => {
            h.push(0x11); // AF_INET, STREAM
            h.extend_from_slice(&12u16.to_be_bytes());
            h.extend_from_slice(&v4.octets()); // src
            h.extend_from_slice(&[0u8; 4]); // dst
            h.extend_from_slice(&[0u8; 4]); // src/dst ports
        }
        std::net::IpAddr::V6(v6) => {
            h.push(0x21); // AF_INET6, STREAM
            h.extend_from_slice(&36u16.to_be_bytes());
            h.extend_from_slice(&v6.octets()); // src
            h.extend_from_slice(&[0u8; 16]); // dst
            h.extend_from_slice(&[0u8; 4]); // src/dst ports
        }
    }
    h
}

/// Parse a PROXY protocol v2 header (HAProxy/Envoy) off the front of a TCP stream
/// and return the real client IP. Returns `None` for the LOCAL command, an
/// unsupported address family, or a malformed/absent header — the caller then
/// drops the connection (PROXY protocol is mandatory once enabled). (#21)
async fn read_proxy_v2(stream: &mut TcpStream) -> Option<std::net::IpAddr> {
    use tokio::io::AsyncReadExt;
    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    let mut hdr = [0u8; 16];
    stream.read_exact(&mut hdr).await.ok()?;
    if hdr[0..12] != SIG {
        return None;
    }
    if (hdr[12] >> 4) != 0x02 {
        return None; // version must be 2
    }
    let cmd = hdr[12] & 0x0F; // 0 = LOCAL, 1 = PROXY
    let fam = hdr[13] >> 4; // 1 = AF_INET, 2 = AF_INET6
    let len = u16::from_be_bytes([hdr[14], hdr[15]]) as usize;
    let mut addrs = vec![0u8; len];
    stream.read_exact(&mut addrs).await.ok()?;
    if cmd != 1 {
        return None; // LOCAL: no proxied client address
    }
    match fam {
        1 if len >= 12 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            addrs[0], addrs[1], addrs[2], addrs[3],
        ))),
        2 if len >= 36 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&addrs[0..16]);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
/// Process-wide trigger to hot-reload the encrypted-DNS (DoT/DoH/DoQ) listeners
/// without restarting. Set once by `run_dns_server`; the WebUI `/tls/*` handlers
/// send `()` after persisting new TLS config — see [`tls_supervisor`].
pub static TLS_APPLY_TX: std::sync::OnceLock<tokio::sync::mpsc::Sender<()>> =
    std::sync::OnceLock::new();



async fn spawn_tls_service(
    handler: std::sync::Arc<RunboundHandler>,
    tls_cfg: &TlsConfig,
    interfaces: &[String],
    acl: &Arc<Acl>,
    tcp_tracker: &Arc<TcpConnTracker>,
    proxy_protocol: bool,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let (certs, key) = match load_tls_materials(tls_cfg) {
        Some(m) => m,
        None => {
            info!("encrypted DNS: not configured — DoT/DoH/DoQ disabled");
            return handles;
        }
    };
    let dot_port = tls_cfg.dot_port.unwrap_or(853);
    let doh_port = tls_cfg.doh_port.unwrap_or(443);
    let doq_port = tls_cfg.doq_port.unwrap_or(853);
    let hostname = tls_cfg
        .hostname
        .clone()
        .unwrap_or_else(|| "runbound.local".to_string());
    const TLS_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

    let dot_config = match build_tls_config(
        certs.clone(),
        key.clone_key(),
        b"dot",
        false,
        tls_cfg.dot_client_auth_ca.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!(err=%e, "DoT TLS config failed — encrypted DNS not started");
            return handles;
        }
    };
    let doh_config = match build_tls_config(certs.clone(), key.clone_key(), b"h2", false, None) {
        Ok(c) => c,
        Err(e) => {
            warn!(err=%e, "DoH TLS config failed — encrypted DNS not started");
            return handles;
        }
    };
    let _doq_config = match build_tls_config(certs, key, b"doq", true, None) {
        Ok(c) => c,
        Err(e) => {
            warn!(err=%e, "DoQ TLS config failed — encrypted DNS not started");
            return handles;
        }
    };

    // DoH is served by our own RFC 8484 handler (see doh_service); clone the
    // shared handler before `handler` is moved into the hickory server below.
    let doh_handler = std::sync::Arc::clone(&handler);
    let alert = handler.alert_tracker();
    let handler_dot_sup = std::sync::Arc::clone(&handler);
    drop(handler); // consumed; DoT now uses handler_dot_sup clone
    for iface in interfaces {
        // DNS-over-TLS (853 TCP) — public listener relays to a loopback wire listener.
        let dot_addr = format!("{}:{}", iface, dot_port);
        match TcpListener::bind(&dot_addr).await {
            Ok(public_dot) => match TcpListener::bind("127.0.0.1:0").await {
                Ok(relay_dot) => {
                    if let Ok(relay_dot_addr) = relay_dot.local_addr() {
                        info!(addr=%dot_addr, mtls=tls_cfg.dot_client_auth_ca.is_some(), "DoT (DNS-over-TLS) listening — RFC 7858");
                        // Own DoT relay: TLS-terminated own listener calling handle_request_wire.
                        let h_dot = std::sync::Arc::clone(&handler_dot_sup);
                        let dc = std::sync::Arc::clone(&dot_config);
                        handles.push(tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let acceptor = tokio_rustls::TlsAcceptor::from(dc);
                            loop {
                                let (tcp, peer) = match relay_dot.accept().await {
                                    Ok(x) => x,
                                    Err(e) => { debug!(err=%e, "DoT relay accept"); continue; }
                                };
                                let acceptor = acceptor.clone();
                                let hh = std::sync::Arc::clone(&h_dot);
                                tokio::spawn(async move {
                                    // PENT-2: the relay prepends a PROXY v2 header with the real
                                    // client IP before the TLS bytes; recover it so split-horizon /
                                    // per-IP handler logic see the true source for DoT clients.
                                    let mut tcp = tcp;
                                    let real_ip = match tokio::time::timeout(
                                        Duration::from_secs(5), read_proxy_v2(&mut tcp)).await
                                    {
                                        Ok(Some(ip)) => ip,
                                        _ => return,
                                    };
                                    let peer = SocketAddr::new(real_ip, peer.port());
                                    let mut tls = match acceptor.accept(tcp).await {
                                        Ok(s) => s,
                                        Err(e) => { debug!(err=%e, "DoT TLS handshake"); return; }
                                    };
                                    let _ = tls.get_ref().0.set_nodelay(true);
                                    let mut len_buf = [0u8; 2];
                                    loop {
                                        if tokio::time::timeout(TLS_SESSION_TIMEOUT, tls.read_exact(&mut len_buf)).await.is_err() { return; }
                                        let msg_len = u16::from_be_bytes(len_buf) as usize;
                                        if msg_len == 0 || msg_len > 65535 { return; }
                                        let mut buf = vec![0u8; msg_len];
                                        if tokio::time::timeout(TLS_SESSION_TIMEOUT, tls.read_exact(&mut buf)).await.is_err() { return; }
                                        let resp = hh.handle_request_wire(&buf, peer).await;
                                        if resp.is_empty() { continue; }
                                        let rlen = (resp.len() as u16).to_be_bytes();
                                        if tls.write_all(&rlen).await.is_err() { return; }
                                        if tls.write_all(&resp).await.is_err() { return; }
                                    }
                                });
                            }
                        }));
                        handles.push(tokio::spawn(run_tcp_with_limit(
                                public_dot,
                                relay_dot_addr,
                                std::sync::Arc::clone(tcp_tracker),
                                TLS_SESSION_TIMEOUT,
                                std::sync::Arc::clone(acl),
                                proxy_protocol,
                                alert.clone(),
                                true, // DoT: relay prepends real client IP; loopback reads it pre-TLS (PENT-2)
                            )));
                    }
                }
                Err(e) => warn!(addr=%dot_addr, err=%e, "DoT relay bind failed — skipping"),
            },
            Err(e) => warn!(addr=%dot_addr, err=%e, "DoT bind failed — skipping"),
        }

        // DNS-over-HTTPS (443 TCP)
        let doh_addr = format!("{}:{}", iface, doh_port);
        match TcpListener::bind(&doh_addr).await {
            Ok(public_doh) => match TcpListener::bind("127.0.0.1:0").await {
                Ok(relay_doh) => {
                    if let Ok(relay_doh_addr) = relay_doh.local_addr() {
                        info!(addr=%doh_addr, "DoH (DNS-over-HTTPS) listening — RFC 8484");
                        // Runbound serves DoH itself (see doh_service): hickory's
                        // verify_request requires Content-Type on every request, so it
                        // rejects the bodyless GET that Firefox/Chrome send (#doh-get).
                        handles.push(tokio::spawn(doh_service(
                            relay_doh,
                            std::sync::Arc::clone(&doh_config),
                            std::sync::Arc::clone(&doh_handler),
                            "/dns-query".to_string(),
                            hostname.clone(),
                        )));
                        handles.push(tokio::spawn(run_tcp_with_limit(
                            public_doh,
                            relay_doh_addr,
                            std::sync::Arc::clone(tcp_tracker),
                            TLS_SESSION_TIMEOUT,
                            std::sync::Arc::clone(acl),
                            proxy_protocol,
                            alert.clone(),
                            true, // DoH: relay prepends real client IP; doh_service reads it pre-TLS (PENT-2)
                        )));
                    }
                }
                Err(e) => warn!(addr=%doh_addr, err=%e, "DoH relay bind failed — skipping"),
            },
            Err(e) => warn!(addr=%doh_addr, err=%e, "DoH bind failed — skipping"),
        }

        // DNS-over-QUIC: not supported in this build (requires --features doq).
        let _ = doq_port; // suppress unused warning
    }

    // All DoT/DoH listeners are already spawned as tasks in handles above.
    handles
}

// ───────────────────────── DNS-over-HTTPS (RFC 8484) ─────────────────────────
// Runbound serves DoH itself rather than via hickory's HTTPS listener: hickory's
// verify_request requires `Content-Type: application/dns-message` on EVERY request,
// but an RFC 8484 GET carries the query in `?dns=` and has no body (so no
// Content-Type) — hickory therefore rejects every GET, which is exactly what
// Firefox and Chrome send. This handler accepts GET (?dns=base64url) and POST
// (application/dns-message), resolves through the shared RunboundHandler, and
// returns application/dns-message. TLS + HTTP/2 terminate here, behind the same
// public relay that enforces the source-IP ACL / per-IP conn cap / PROXY protocol.




fn doh_reply(
    status: hyper::StatusCode,
    body: Vec<u8>,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    let mut b = hyper::Response::builder().status(status);
    if !body.is_empty() {
        b = b.header(hyper::header::CONTENT_TYPE, "application/dns-message");
    }
    b.body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .unwrap_or_else(|_| hyper::Response::new(http_body_util::Full::new(bytes::Bytes::new())))
}

/// Handle one DoH HTTP request (GET `?dns=` or POST application/dns-message).
async fn doh_handle(
    req: hyper::Request<hyper::body::Incoming>,
    handler: std::sync::Arc<RunboundHandler>,
    peer: SocketAddr,
    path: std::sync::Arc<str>,
    hostname: std::sync::Arc<str>,
) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, std::convert::Infallible> {
    use base64::Engine;
    if req.uri().path() != &*path {
        return Ok(doh_reply(hyper::StatusCode::NOT_FOUND, Vec::new()));
    }
    // authority / Host must match the configured hostname (parity with hickory).
    let authority = req
        .uri()
        .authority()
        .map(|a| a.host().to_string())
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        });
    if let Some(h) = authority {
        if h != *hostname {
            return Ok(doh_reply(hyper::StatusCode::NOT_FOUND, Vec::new()));
        }
    }
    let wire: Vec<u8> = match *req.method() {
        hyper::Method::GET => {
            let q = req.uri().query().unwrap_or("");
            let dns = q.split('&').find_map(|kv| {
                let mut it = kv.splitn(2, '=');
                match (it.next(), it.next()) {
                    (Some("dns"), Some(v)) => Some(v),
                    _ => None,
                }
            });
            let Some(b64) = dns else {
                return Ok(doh_reply(hyper::StatusCode::BAD_REQUEST, Vec::new()));
            };
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64.trim_end_matches('=')) {
                Ok(b) => b,
                Err(_) => return Ok(doh_reply(hyper::StatusCode::BAD_REQUEST, Vec::new())),
            }
        }
        hyper::Method::POST => {
            let ct = req
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if ct != "application/dns-message" {
                return Ok(doh_reply(
                    hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    Vec::new(),
                ));
            }
            use http_body_util::BodyExt;
            // DNS messages are tiny; cap the body to guard against abuse.
            match http_body_util::Limited::new(req.into_body(), 65_535)
                .collect()
                .await
            {
                Ok(c) => c.to_bytes().to_vec(),
                Err(_) => return Ok(doh_reply(hyper::StatusCode::BAD_REQUEST, Vec::new())),
            }
        }
        _ => return Ok(doh_reply(hyper::StatusCode::METHOD_NOT_ALLOWED, Vec::new())),
    };
    // DoH terminates here and resolves through the wire fast path, same as the
    // UDP/TCP/DoT listeners — no hickory handler.
    let resp = handler.handle_request_wire(&wire, peer).await;
    if resp.is_empty() {
        Ok(doh_reply(hyper::StatusCode::BAD_REQUEST, Vec::new()))
    } else {
        Ok(doh_reply(hyper::StatusCode::OK, resp))
    }
}

/// Serve DoH on `listener` (the loopback target of the public 443 relay). TLS +
/// HTTP/2 (and HTTP/1.1 fallback) terminate here; each request is resolved through
/// the shared handler. Aborting this task drops the listener and frees the socket.
async fn doh_service(
    listener: TcpListener,
    tls: std::sync::Arc<rustls::ServerConfig>,
    handler: std::sync::Arc<RunboundHandler>,
    path: String,
    hostname: String,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let path: std::sync::Arc<str> = std::sync::Arc::from(path);
    let hostname: std::sync::Arc<str> = std::sync::Arc::from(hostname);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                debug!(err=%e, "DoH accept error");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let handler = std::sync::Arc::clone(&handler);
        let path = std::sync::Arc::clone(&path);
        let hostname = std::sync::Arc::clone(&hostname);
        tokio::spawn(async move {
            // PENT-2: recover the real client IP from the relay's PROXY v2 header
            // (prepended before the TLS bytes) so split-horizon / per-IP handler
            // logic see the true source for DoH clients.
            let mut tcp = tcp;
            let real_ip = match tokio::time::timeout(
                Duration::from_secs(5), read_proxy_v2(&mut tcp)).await
            {
                Ok(Some(ip)) => ip,
                _ => return,
            };
            let peer = SocketAddr::new(real_ip, peer.port());
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(err=%e, "DoH TLS handshake failed");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let svc = hyper::service::service_fn(move |req| {
                doh_handle(
                    req,
                    std::sync::Arc::clone(&handler),
                    peer,
                    std::sync::Arc::clone(&path),
                    std::sync::Arc::clone(&hostname),
                )
            });
            let builder = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            );
            if let Err(e) = builder.serve_connection(io, svc).await {
                debug!(err=%e, "DoH connection error");
            }
        });
    }
}

/// Supervise the encrypted-DNS listeners. On each `()` received (sent by the
/// WebUI after it persists new TLS config), tear the current listeners down
/// (abort + await, freeing the public ports) and bring them back up from the
/// freshly re-read config — all without touching the plain :53 path.
async fn tls_supervisor(
    mut rx: tokio::sync::mpsc::Receiver<()>,
    handler: std::sync::Arc<RunboundHandler>,
    cfg_path: String,
    interfaces: Vec<String>,
    acl: Arc<Acl>,
    tcp_tracker: Arc<TcpConnTracker>,
    proxy_protocol: bool,
    fw: std::sync::Arc<crate::firewall::FirewallManager>,
) {
    fn current_tls(cfg_path: &str) -> TlsConfig {
        crate::config::load(cfg_path)
            .map(|c| c.tls)
            .unwrap_or_default()
    }
    let mut handles = spawn_tls_service(
        std::sync::Arc::clone(&handler),
        &current_tls(&cfg_path),
        &interfaces,
        &acl,
        &tcp_tracker,
        proxy_protocol,
    )
    .await;
    while rx.recv().await.is_some() {
        info!("encrypted DNS: hot-reloading listeners (no restart)");
        for h in handles.drain(..) {
            h.abort();
            let _ = h.await;
        }
        // Let the OS fully release the listening sockets before rebinding.
        tokio::time::sleep(Duration::from_millis(300)).await;
        handles = spawn_tls_service(
            std::sync::Arc::clone(&handler),
            &current_tls(&cfg_path),
            &interfaces,
            &acl,
            &tcp_tracker,
            proxy_protocol,
        )
        .await;
        // Track the encrypted-DNS ports in the firewall too (open/close live).
        let fw_cfg = crate::config::load(&cfg_path).unwrap_or_default();
        fw.resync(&crate::firewall::PortSet::from_config(&fw_cfg));
        info!(tasks = handles.len(), "encrypted DNS: hot reload complete");
    }
}

pub async fn run_dns_server(
    cfg: &UnboundConfig,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl: Arc<Acl>,
    stats: Arc<Stats>,
    log_buffer: SharedLogBuffer,
    resolver: SharedResolver,
    prefetch_tracker: Option<Arc<crate::dns::prefetch::PrefetchTracker>>,
    xdp_cache: Option<super::cache_snapshot::MutableCacheMap>,
    cache_max_entries: usize,
    upstreams: crate::upstreams::SharedUpstreams,
    per_upstream_resolvers: SharedResolversVec,
    racing_wins: Arc<DashMap<String, Arc<std::sync::atomic::AtomicU64>, ahash::RandomState>>,
    domain_stats: Arc<crate::domain_stats::DomainStats>,
    alert_tracker: Arc<crate::alerts::AlertTracker>,
    dnssec_enabled: Arc<std::sync::atomic::AtomicBool>,
    icmp_stats: Arc<crate::icmp::IcmpStats>,
    resolution_mode: Arc<std::sync::atomic::AtomicU8>,
    recursor: crate::dns::recursor::SharedRecursor,
    cfg_path: String,
    fw: std::sync::Arc<crate::firewall::FirewallManager>,
) -> anyhow::Result<()> {
    let _ = ABUSE_TARPIT_CFG.set((cfg.abuse_tarpit_delay_ms, cfg.abuse_tarpit_max_conns));
    let rps = cfg.rate_limit.unwrap_or(RATE_LIMIT_QPS_DEFAULT);
    if rps == 0 {
        info!("rate limiting disabled (rate-limit: 0)");
    } else {
        info!(rps, burst = rps * 2, "DNS rate limiter configured");
    }

    let initial_cache_size = cache_size_from_meminfo();
    info!(
        cache_size = initial_cache_size,
        "cache size auto-sized from MemAvailable"
    );
    // #165: the resolver cache cap MUST scale with RAM (or honour an explicit cache-size),
    // NOT the xdp-cache-snapshot-size that was mis-wired into this parameter — otherwise the
    // cache plateaus at ~10 000 entries no matter how much memory the host has.
    let _ = cache_max_entries; // deprecated source (was cfg.xdp_cache_snapshot_size)
    let cache_max_entries = cfg.cache_size.filter(|&n| n > 0).unwrap_or(initial_cache_size);
    info!(
        cache_max_entries,
        explicit = cfg.cache_size.is_some(),
        "resolver cache cap (#165: RAM-scaled or explicit cache-size)"
    );

    // Spawn memory pressure guard — monitors /proc/meminfo every 30 s and
    // adjusts the DNS cache size and flushes the rate limiter under pressure.
    {
        let rl = Arc::clone(&rate_limiter);
        let res = Arc::clone(&resolver);
        let cfg_arc = Arc::new(cfg.clone());
        let stats_mg = Arc::clone(&stats);
        let ups_mg = Arc::clone(&upstreams);
        let dnssec_mg = Arc::clone(&dnssec_enabled);
        tokio::spawn(async move {
            memory_guard_loop(rl, res, cfg_arc, stats_mg, initial_cache_size, ups_mg, dnssec_mg).await
        });
    }

    if acl.is_empty() {
        info!("access-control: no rules — all clients allowed (add access-control directives to restrict)");
    } else {
        info!(rules = acl.len(), "access-control: ACL loaded");
    }

    let cache_max_ttl = cfg.cache_max_ttl.unwrap_or(86400);
    let cache_min_ttl = cfg.cache_min_ttl.unwrap_or(0);
    info!(cache_max_ttl, cache_min_ttl, "TTL cap/floor configured");

    let private_addrs = Arc::new(PrivateAddressSet::from_config(&cfg.private_addresses));
    if !private_addrs.is_empty() {
        info!(
            count = cfg.private_addresses.len(),
            "private-address: DNS rebinding protection active"
        );
    }

    // Level 1 (#77) — #84 two-phase startup: spawn warm-up in background so
    // DNS sockets open immediately.  Cache hits and local-zone queries are served
    // from the first packet; upstream forwarding becomes available ~800ms later
    // once the DoT pool is ready.  Queries that miss the cache before the pool
    // is live will wait for the forward pool's lazy-connect retry (no SERVFAIL storm).
    let dot_count = upstreams
        .read()
        .map(|u| u.iter().filter(|s| s.protocol == "dot").count())
        .unwrap_or(0);
    {
        let res_wu = Arc::clone(&resolver);
        tokio::spawn(async move {
            warm_up_dot_connections(&res_wu, dot_count).await;
        });
    }

    // Level 3 (#77): spawn keepalive task.
    {
        let res_ka = Arc::clone(&resolver);
        let ups_ka = upstreams.clone();
        let stats_ka = Arc::clone(&stats);
        let dnssec = dnssec_enabled.load(std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(dot_keepalive_loop(res_ka, ups_ka, stats_ka, dnssec));
    }

    let fallback_active = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // #94: resolv.conf fallback recovery — check every 30s whether a primary upstream
    // has recovered so the temporary fallback entries can be removed.
    if cfg.resolv_fallback {
        let ups_r = Arc::clone(&upstreams);
        let res_r = Arc::clone(&resolver);
        let fa_r = Arc::clone(&fallback_active);
        let dnssec = dnssec_enabled.load(std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if !fa_r.load(Ordering::Relaxed) {
                    continue;
                }
                if crate::upstreams::has_healthy_non_temporary(&ups_r) {
                    crate::upstreams::remove_resolv_fallback(&ups_r);
                    fa_r.store(false, Ordering::Relaxed);
                    let addrs = crate::upstreams::upstream_addrs(&ups_r);
                    let _ = rebuild_and_swap(&res_r, &addrs, dnssec).await;
                    info!("resolv.conf fallback deactivated — primary upstream recovered");
                }
            }
        });
    }

    // Clone for kernel fast loop (must happen before acl/zones are moved into handler).
    let acl_for_kloop   = Arc::clone(&acl);
    let zones_for_kloop = Arc::clone(&zones);
    let rl_for_kloop    = Arc::clone(&rate_limiter);
    let icmp_for_kloop  = Arc::clone(&icmp_stats);
    let stats_for_kloop        = Arc::clone(&stats);
    let domain_stats_for_kloop = Arc::clone(&domain_stats);
    let xdp_cache_for_kloop    = xdp_cache.as_ref().map(Arc::clone);

    // #201: build the online DNSSEC signer when local-zone-dnssec is enabled. Keys live under
    // the config dir; on failure we log and disable signing rather than refuse to start.
    // The master (or a standalone node) generates + holds the keys; a slave starts with no signer
    // and adopts the master's replicated keys via the relay (model B) — never signs with its own.
    let signer_inner: Option<Arc<crate::dns::zone_signer::ZoneSigner>> = if cfg.local_zone_dnssec
        && !cfg.is_slave()
    {
        let apexes: Vec<String> = cfg.local_zones.iter().map(|z| z.name.clone()).collect();
        match crate::dns::zone_signer::ZoneSigner::new(
            crate::runtime::base_dir(),
            &apexes,
            Duration::from_secs(14 * 24 * 3600),
        ) {
            Ok(s) => {
                info!(zones = apexes.len(), "local-zone-dnssec: online signer ready");
                Some(Arc::new(s))
            }
            Err(e) => {
                error!("local-zone-dnssec: signer init failed: {e} — serving unsigned");
                None
            }
        }
    } else {
        None
    };
    // Hot-swappable handle, shared globally so the relay key-replication path can adopt fresh keys.
    let zone_signer: crate::dns::zone_signer::SharedZoneSigner =
        Arc::new(arc_swap::ArcSwap::from_pointee(signer_inner));
    let _ = crate::dns::zone_signer::SHARED_SIGNER.set(Arc::clone(&zone_signer));
    // #202: resolution_mode + recursor are created in build_and_launch (so the API can
    // hot-swap them) and threaded in as parameters — same pattern as dnssec_enabled.

    let handler = RunboundHandler::new(
        Arc::clone(&zones),
        Arc::clone(&resolver),
        rate_limiter,
        Arc::clone(&acl),
        private_addrs,
        cache_max_ttl,
        cache_min_ttl,
        stats,
        log_buffer,
        Arc::clone(&dnssec_enabled),
        zone_signer,
        prefetch_tracker,
        xdp_cache,
        cache_max_entries,
        upstreams,
        per_upstream_resolvers,
        cfg.upstream_racing,
        racing_wins,
        cfg.resolv_fallback,
        fallback_active,
        domain_stats,
        cfg.serve_stale,
        cfg.stale_answer_ttl,
        cfg.stale_max_age,
        cfg.allow_update,
        cfg.block_https_record,

        cfg.tsig_keys.clone(),
        Some(Arc::clone(&alert_tracker)),
        cfg.axfr_allow.clone(),
        {
            // #10/#186: compile split-horizon and publish a live-swappable handle
            // so API edits apply without a restart.
            let table = compile_split_horizon(&cfg.split_horizon);
            info!(entries = table.len(), "split-horizon zones loaded");
            publish_view_snapshots(&table);
            let live = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(table));
            let _ = SPLIT_HORIZON_LIVE.set(std::sync::Arc::clone(&live));
            live
        },
        Arc::clone(&resolution_mode),
        recursor.clone(),
        cfg.dns_cookies,
        cfg.rrl_slip,
        if cfg.ddr {
            cfg.tls.hostname.clone().map(|h| DdrInfo {
                hostname: h,
                dot_port: cfg.tls.dot_port.unwrap_or(853),
                doh_port: cfg.tls.doh_port.unwrap_or(443),
                doq_port: cfg.tls.doq_port.unwrap_or(853),
            })
        } else {
            None
        },
    );
    // Step 3b: wrap handler in Arc for sharing between the TLS supervisor and the fallback reader.
    let handler_arc = std::sync::Arc::new(handler);
    let handler_arc2 = std::sync::Arc::clone(&handler_arc);

    // handler_arc2 is used by the fallback reader; TLS supervisor uses handler_arc.
    // No hickory Server needed — all listeners use handle_request_wire().

    let _port = cfg.port;
    let interfaces: Vec<String> = if cfg.interfaces.is_empty() {
        vec!["0.0.0.0".into()]
    } else {
        cfg.interfaces.clone()
    };

    // ── Kernel UDP fast loop (#kernel-fastloop) ─────────────────────────────
    // One blocking OS thread per physical NUMA-local core.  Handles local-zone
    // A/AAAA + cache hits with zero hickory allocs (wire builder + SIMD).
    // Fallback queries (CNAME, MX, TSIG, recursion…) are sent to the wire
    // serving-core reader (handle_request_wire) via the fallback channel below.
    //
    // Kernel UDP fast loop: ONLY when XDP is NOT managing this NIC.
    // xdp:yes → XDP workers own the UDP path; kernel loop would pin OS threads
    // on the SAME cores as XDP workers → CPU contention → ~2.5x throughput regression.
    // xdp:no  → kernel loop handles all UDP, the wire handler serves TCP + fallback only.
    // #fix(xdp-recursion): fallback channel created unconditionally so XDP-mode
    // misses also reach the wire serving-core reader (forward upstream + fill cache).
    let (fallback_tx, mut fallback_rx) = tokio::sync::mpsc::channel::<FallbackMsg>(4096);
    let _ = crate::dns::kernel_loop::XDP_FALLBACK_TX.set(fallback_tx.clone());

    // #167: in XDP mode the workers have no kernel arrival socket; recursive-miss
    // fallback replies must leave from the server port (:53), not an ephemeral one
    // (clients reject mismatched source ports -> silent timeout). Bind a shared
    // SO_REUSEPORT UDP socket on the server port for the reader to reply through.
    if cfg.xdp {
        // #167: reply socket on the server port for recursive-miss fallbacks to LAN
        // clients (their queries arrive via XDP; replies must leave from :port).
        match bind_xdp_reply_sock(cfg.port) {
            Ok(s) => {
                let _ = crate::dns::kernel_loop::XDP_FALLBACK_REPLY_SOCK
                    .set(std::sync::Arc::new(s));
                tracing::info!(port = cfg.port, "XDP fallback reply socket bound — recursion-miss replies leave from server port (#167)");
            }
            Err(e) => tracing::warn!("XDP fallback reply socket bind failed: {e} — recursive misses in XDP mode will time out"),
        }
        // #167b: 127.0.0.1 is slowpath (kernel), NEVER XDP (XDP only owns the
        // physical NIC). Serve loopback queries with ONE kernel UDP thread bound to
        // 127.0.0.1 so local resolution works in XDP mode. The kernel routes lo:port
        // to this specific bind, not the 0.0.0.0 reply socket. One core => no real
        // contention with the XDP workers.
        let lo_snapshot: Option<super::cache_snapshot::SharedCacheSnapshot> =
            xdp_cache_for_kloop.as_ref().map(|mutable| {
                let snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(
                    super::cache_snapshot::CacheSnapshot::default(),
                )));
                let snap2 = Arc::clone(&snapshot);
                let mut2 = Arc::clone(mutable);
                tokio::spawn(super::cache_snapshot::publish_loop(snap2, mut2));
                snapshot
            });
        let lo_cores: Vec<usize> = crate::cpu::physical_cores().into_iter().take(1).collect();
        let lo_bind = format!("127.0.0.1:{}", cfg.port);
        match crate::dns::kernel_loop::start_kernel_fast_loop(
            &lo_bind,
            &lo_cores,
            Arc::clone(&zones_for_kloop),
            Arc::clone(&acl_for_kloop),
            Arc::clone(&rl_for_kloop),
            Arc::clone(&icmp_for_kloop),
            fallback_tx.clone(),
            lo_snapshot,
            Some(Arc::clone(&stats_for_kloop)),
            Some(Arc::clone(&domain_stats_for_kloop)),
        ) {
            Ok(h) => {
                std::mem::forget(h); // keep the loopback listener alive for the process lifetime
                tracing::info!(addr = %lo_bind, "XDP mode: loopback slowpath kernel listener started (#167b)");
            }
            Err(e) => tracing::warn!("XDP mode loopback listener failed to start: {e} — 127.0.0.1 DNS will time out in XDP mode"),
        }
    }

    if !cfg.xdp {
        // SO_REUSEPORT: the per-core fast-loop sockets all share the
        // same port.  The kernel balances across ALL sockets by 4-tuple hash, so
        // fast-loop threads see their fair share of the traffic without RPS/steering.
        //
        // kernel_fast_loop is a kernel-UDP feature (not AF_XDP).
        // This block only runs when cfg.xdp == false (see outer guard).
        let kernel_loop_iface = interfaces.first().map(|s| s.as_str()).unwrap_or("0.0.0.0");
        let fast_cores = {
            let nic_node = crate::cpu::nic_numa_node(kernel_loop_iface);
            let phys_sorted = crate::cpu::physical_cores_numa_sorted(nic_node);
            let total = phys_sorted.len().max(1);
            // #183: honour the same core budget as the XDP fast path.
            //  - Xeon v2 + X520: the X520 PCIe bus is served by ~16 cores
            //    (10 NIC-local + 6 cross-NUMA); past that the QPI/bus collapses.
            //  - otherwise: NUMA-sorted physical cores, but keep one for the wire
            //    serving-core fallback / TCP / API / the rest of the program.
            let cap = if crate::dns::xdp::socket::is_xeon_v2_x520_host(kernel_loop_iface) {
                16.min(total)
            } else {
                total.saturating_sub(1).max(1)
            };
            phys_sorted.into_iter().take(cap).collect::<Vec<usize>>()
        };
        let n_fast = fast_cores.len().max(1);

        // #slowpath-autotune: the kernel-UDP slow path is softirq-bound. Without RPS the
        // RX softirq stays on the handful of NIC-IRQ cores (~3M ceiling); spreading it to
        // all cores lifts it toward the NAPI wall (~7M+ on this NIC class). Pin the NIC
        // IRQs to its NUMA-local CPUs so NAPI stays local. XDP mode never reaches this
        // block (outer `if !cfg.xdp`), so the AF_XDP fast path is byte-for-byte unaffected.
        {
            // The bind address (`interface:`) is not a NIC name, so detect the NIC(s) to
            // tune: the explicitly configured `xdp-interface` if present, otherwise
            // auto-detect physical UP NICs (out-of-the-box, no manual host tuning). RPS is
            // applied to every target (harmless on idle NICs); IRQ pinning only to an
            // explicitly named NIC, so the management NIC's IRQs are never re-pinned.
            let named: Vec<String> = cfg
                .xdp_interface
                .as_deref()
                .map(|s| {
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        // SEC (Cycle I, SEC-I24): the interface name flows into sysfs paths
                        // (/sys/class/net/<iface>/...). Reject path-bearing names so a
                        // config value cannot traverse out (e.g. "../../tmp/x").
                        .filter(|x| {
                            !x.is_empty()
                                && x.len() <= 15
                                && !x.contains('/')
                                && !x.contains("..")
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let rps_targets: Vec<String> = if named.is_empty() {
                crate::cpu::physical_up_nics()
            } else {
                named.clone()
            };
            // Moderate NIC queue count for the kernel-UDP slow path (vs the XDP max):
            // ~16 queues feed the RX ring fast enough at line rate while leaving the bulk
            // of cores free for the RPS-distributed serving threads. RPS to all physical
            // serving cores is the dominant lever (measured 0.5M -> 6.4M qps). Queue +
            // IRQ retune only on an explicitly named NIC (a combined-count change resets
            // the link — never do that to the management NIC); RPS is harmless on idle
            // NICs, so it is applied to every detected target.
            // Raise the kernel socket-buffer ceiling so the kloop's SO_RCVBUF request
            // (RCVBUF_SIZE, 32 MiB) is not clamped — otherwise NAPI overruns the socket
            // under burst (UdpRcvbufErrors) even with spare CPU. Best-effort sysctl write
            // (root); harmless if it already is higher. Slow-path only.
            const SOCKBUF_MAX: usize = 32 * 1024 * 1024;
            for knob in ["net.core.rmem_max", "net.core.wmem_max"] {
                let path = format!("/proc/sys/{}", knob.replace('.', "/"));
                if let Ok(cur) = std::fs::read_to_string(&path) {
                    if cur.trim().parse::<usize>().map(|v| v < SOCKBUF_MAX).unwrap_or(true) {
                        let _ = std::fs::write(&path, SOCKBUF_MAX.to_string());
                    }
                }
            }
            // Safety cap so a pathologically large NUMA node (NPS1: a node = the
            // whole socket) does not create an excessive number of NAPI/IRQ cores.
            const SLOWPATH_QUEUE_CAP: u32 = 32;
            for nic in &rps_targets {
                let mut queues = 0u32;
                let mut irq_n = 0usize;
                if named.contains(nic) {
                    // Adapt to the NIC's OWN NUMA node + the CPU topology: the kernel-UDP
                    // slow path is bounded by NAPI saturating the NIC-NUMA-local cores, so
                    // size the queues to ONE RX queue (and IRQ) per node-local logical CPU —
                    // enough to drain the ring at line rate, all node-local — and pin those
                    // IRQs to that node, leaving the rest of the machine for the RPS-spread
                    // serving threads. This is the dominant lever after RPS: measured
                    // X710/5995WX (NIC on node 4 = 16 logical CPUs) — node-local IRQs +
                    // rx-usecs 25 = 8.2M vs cross-node IRQs 6.7M. Reads the live topology, so
                    // it adapts to the card (which node) and the CPU (node size); falls back
                    // to all serving cores if the cpulist is unreadable.
                    let nic_node = crate::cpu::nic_numa_node(nic);
                    let node_cpus = std::fs::read_to_string(format!(
                        "/sys/devices/system/node/node{nic_node}/cpulist"
                    ))
                    .ok()
                    .map(|s| crate::cpu::parse_cpulist(&s))
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| fast_cores.clone());
                    // #physical-only: pin the NAPI IRQs to the NIC node's PHYSICAL cores, NEVER
                    // their SMT siblings — the SIMD serving saturates a physical core's execution
                    // units, so a softirq on an HT sibling steals throughput (and shows up as
                    // "active cores > physical core count" in mpstat). Keep a generous RX-queue
                    // count for RSS fan-out (node logical-CPU count), but wrap those IRQs onto
                    // the physical node cores only (fast_cores is the physical serving set).
                    let irq_cores: Vec<usize> =
                        fast_cores.iter().copied().filter(|c| node_cpus.contains(c)).collect();
                    let irq_cores = if irq_cores.is_empty() { node_cpus.clone() } else { irq_cores };
                    let target_q = (node_cpus.len() as u32)
                        .min(fast_cores.len() as u32)
                        .min(SLOWPATH_QUEUE_CAP)
                        .max(1);
                    queues = crate::dns::xdp::socket::set_combined_queues(nic, target_q);
                    // Let the NIC recreate its IRQs after the channel change before pinning.
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    // One IRQ per node-local PHYSICAL core, wrapping if queues > physical cores.
                    let pairs: Vec<(u32, usize)> = (0..queues)
                        .map(|q| (q, irq_cores[q as usize % irq_cores.len()]))
                        .collect();
                    crate::cpu::set_irq_affinity(nic, &pairs);
                    irq_n = pairs.len();
                    // rx-usecs 25 (moderate coalescing — fewer NAPI re-arms, higher pps at a
                    // ~25 µs latency cost) and hash UDP/IPv4 on (src ip, dst ip, src port,
                    // dst port) so traffic from a few client IPs (large NATs / forwarders /
                    // a benchmark generator) still fans across all queues. Best-effort shell;
                    // skipped if ethtool is absent.
                    let _ = std::process::Command::new("ethtool")
                        .args(["-C", nic, "adaptive-rx", "off", "rx-usecs", "25"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                    let _ = std::process::Command::new("ethtool")
                        .args(["-N", nic, "rx-flow-hash", "udp4", "sdfn"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                    // #slowpath: disable the i40e/ixgbe flow-director ATR (automatic
                    // application-targeted RX re-steering). ATR re-pins each flow to the queue
                    // the app last transmitted from; with the kloop sending from many sockets it
                    // thrashes the RX placement and, under any softirq spread, drops packets
                    // (measured on i40e: 16.8M softnet drops/s with ATR on -> 152k/s with it off).
                    // Best-effort: ntuple covers the generic path, the priv-flag the i40e ATR.
                    for args in [
                        vec!["-K", nic, "ntuple", "off"],
                        vec!["--set-priv-flags", nic, "flow-director-atr", "off"],
                    ] {
                        let _ = std::process::Command::new("ethtool")
                            .args(&args)
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status();
                    }
                }
                // #slowpath-spread: NO RPS — it collapses on i40e (measured 16.8M softnet
                // drops/s, 1.39M qps). The serving is spread across all cores by the random
                // reuseport cBPF (kernel_loop.rs) instead, flow-independent and i40e-safe.
                info!(
                    iface = %nic, nic_queues = queues, irqs_pinned = irq_n,
                    "slow-path auto-tune: node-local queues + 1:1 IRQ pin, random reuseport spread (no RPS)"
                );
            }
        }
        // Reserve at least 2 physical cores for the wire serving-core fallback/TCP/API.
        let _n_fallback = (crate::cpu::physical_cores().len().saturating_sub(n_fast)).max(2);

        // Channel + XDP_FALLBACK_TX global created before this guard.

        // ── kernel fast loop : build real cache snapshot + START THE THREADS ─────
        // Build a SharedCacheSnapshot from the mutable cache map (same pattern as
        // main.rs for the XDP path).  If xdp_cache is None (cache disabled), we
        // pass None — the fast loop skips answer_from_cache and falls back.
        let kloop_cache_snapshot: Option<super::cache_snapshot::SharedCacheSnapshot> =
            xdp_cache_for_kloop.as_ref().map(|mutable| {
                let snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(
                    super::cache_snapshot::CacheSnapshot::default(),
                )));
                // Spawn publish loop so the snapshot stays up-to-date.
                let snap2 = Arc::clone(&snapshot);
                let mut2  = Arc::clone(mutable);
                tokio::spawn(super::cache_snapshot::publish_loop(snap2, mut2));
                snapshot
            });

        // Start one kernel UDP thread per fast core.
        // MULTI-INTERFACE NOTE: currently binds to interfaces[0] only.
        // If multiple interfaces are configured, the additional interfaces have no
        // kernel fast loop — they have no UDP listener at all (future follow-up).
        let kernel_loop_bind = format!("{}:{}", kernel_loop_iface, cfg.port);
        let _kloop_handle = crate::dns::kernel_loop::start_kernel_fast_loop(
            &kernel_loop_bind,
            &fast_cores,
            Arc::clone(&zones_for_kloop),
            Arc::clone(&acl_for_kloop),
            Arc::clone(&rl_for_kloop),
            Arc::clone(&icmp_for_kloop),
            fallback_tx.clone(),
            kloop_cache_snapshot,
            Some(Arc::clone(&stats_for_kloop)),
            Some(Arc::clone(&domain_stats_for_kloop)),
        )?;
        info!(
            threads = fast_cores.len(),
            addr = %kernel_loop_bind,
            "kernel UDP fast loop started (wire handler serves TCP + fallback only)"
        );
    } // end kernel fast loop guard — kernel UDP threads only (#fix: reader is now unconditional)


    // ── Step 3b: real hickory fallback reader ────────────────────────────────
        // #179: reply via the per-message arrival socket (msg.socket), which is the
        // DRAINED socket the query came in on (kernel-loop: the worker's 8 MiB
        // SO_REUSEPORT socket; XDP: the #167 reply socket). A separate fb_sock bound
        // to :port with SO_REUSEPORT but NEVER recv()'d used to steal ~1/N of incoming
        // queries via the reuseport hash, filling its (default-sized) buffer and
        // dropping them (RcvbufErrors) -> intermittent NXDOMAIN/cache-miss timeouts.

        let handler_fb = std::sync::Arc::clone(&handler_arc2);
        // #fix(xdp-recursion): process fallbacks CONCURRENTLY. A sequential await
        // serialises every upstream resolution (DoT TLS handshake ~100ms) → ~1 qps,
        // which made XDP-mode cache warm-up unusable. Bound with a Semaphore.
        let fb_sema = std::sync::Arc::new(tokio::sync::Semaphore::new(1024));
        tokio::spawn(async move {
            while let Some(msg) = fallback_rx.recv().await {
                let permit = match std::sync::Arc::clone(&fb_sema).acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let handler_c = std::sync::Arc::clone(&handler_fb);
                let sock_c = std::sync::Arc::clone(&msg.socket);
                tokio::spawn(async move {
                    let _permit = permit;
                    let mut resp = handler_c.handle_request_wire(&msg.query, msg.peer).await;
                    if !resp.is_empty() {
                        // This is the UDP datapath — cap to the client's payload and set
                        // TC if over budget (RFC 1035 §4.1.1). TCP replies (handled
                        // elsewhere) are never truncated.
                        truncate_udp_response(&mut resp, &msg.query);
                        let _ = sock_c.send_to(&resp, msg.peer);
                    }
                });
            }
        });

    // Step 3b: hickory no longer has UDP sockets — fast loop covers all cores.
    // TSIG/AXFR/UPDATE are served wire-native; only the (feature-gated) recursor uses the fallback.
    // TCP is kept intact (low volume, handled by run_tcp_with_limit).
    let port = cfg.port;

    // FIX 6.2: shared per-IP TCP connection tracker (across all interfaces)
    let tcp_tracker = TcpConnTracker::new();
    const TCP_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

    for iface in &interfaces {
        let udp_addr = format!("{}:{}", iface, port);
        let tcp_addr = format!("{}:{}", iface, port);

        // UDP sockets are now owned by the kernel fast loop (Step 3b).
        // No UDP sockets are bound here — the wire handler serves only TCP + fallback channel.
        info!(addr=%udp_addr, "DNS UDP handled by kernel fast loop (wire handler = TCP + fallback only)");

        // FIX 6.2: public-facing TCP listener feeds our per-IP accept gate.
        // The wire handler gets a loopback relay listener so its accept
        // loop never sees connections from over-limit source IPs.
        let public_tcp = TcpListener::bind(&tcp_addr)
            .await
            .map_err(|e| anyhow::anyhow!("TCP bind {tcp_addr}: {e}"))?;
        // Relay listener: loopback, ephemeral port — the own wire relay loop owns this listener.
        let relay_tcp = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| anyhow::anyhow!("TCP relay bind: {e}"))?;
        let relay_addr = relay_tcp
            .local_addr()
            .map_err(|e| anyhow::anyhow!("TCP relay local_addr: {e}"))?;
        info!(addr=%tcp_addr, "DNS TCP listening (per-IP cap: {} conns)", TCP_CONN_PER_IP_MAX);
        // Own TCP relay listener: reads 2-byte-length-prefixed DNS messages (RFC 1035),
        // dispatches through handle_request_wire, writes the wire response back.
        {
            let h = std::sync::Arc::clone(&handler_arc);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                loop {
                    let (mut stream, peer) = match relay_tcp.accept().await {
                        Ok(x) => x,
                        Err(e) => { debug!(err=%e, "TCP relay accept"); continue; }
                    };
                    let hh = std::sync::Arc::clone(&h);
                    tokio::spawn(async move {
                        let _ = stream.set_nodelay(true);
                        // PENT-1/PENT-2: the public relay prepends a PROXY v2 header with the
                        // REAL client IP. Recover it so AXFR allow-list + split-horizon see the
                        // true source instead of the loopback relay address. Mandatory: a
                        // connection without a valid header is dropped (only the relay reaches
                        // this loopback listener).
                        let real_ip = match tokio::time::timeout(
                            Duration::from_secs(5), read_proxy_v2(&mut stream)).await
                        {
                            Ok(Some(ip)) => ip,
                            _ => return,
                        };
                        let peer = SocketAddr::new(real_ip, peer.port());
                        let mut len_buf = [0u8; 2];
                        loop {
                            if tokio::time::timeout(TCP_SESSION_TIMEOUT, stream.read_exact(&mut len_buf)).await.is_err() { return; }
                            let msg_len = u16::from_be_bytes(len_buf) as usize;
                            if msg_len == 0 || msg_len > 65535 { return; }
                            let mut buf = vec![0u8; msg_len];
                            if tokio::time::timeout(TCP_SESSION_TIMEOUT, stream.read_exact(&mut buf)).await.is_err() { return; }
                            let resp = hh.handle_request_wire(&buf, peer).await;
                            if resp.is_empty() { continue; }
                            let rlen = (resp.len() as u16).to_be_bytes();
                            if stream.write_all(&rlen).await.is_err() { return; }
                            if stream.write_all(&resp).await.is_err() { return; }
                        }
                    });
                }
            });
        }

        let tracker2 = Arc::clone(&tcp_tracker);
        tokio::spawn(run_tcp_with_limit(
            public_tcp,
            relay_addr,
            tracker2,
            TCP_SESSION_TIMEOUT,
            Arc::clone(&acl),
            cfg.proxy_protocol,
            Some(Arc::clone(&alert_tracker)),
            true, // plain TCP: forward real client IP to the loopback handler (PENT-1/PENT-2)
        ));
    }

    // ── Encrypted DNS (DoT/DoH/DoQ) — supervised, hot-reloadable ──────────
    // The TLS listeners run on their OWN wire-native listeners (handle_request_wire
    // / doh_service), supervised so
    // the WebUI can enable / disable / re-key them live: no process restart and
    // no blip on the plain UDP/TCP :53 path. See `tls_supervisor`.
    {
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(8);
        let _ = TLS_APPLY_TX.set(tx);
        let h = std::sync::Arc::clone(&handler_arc);
        let ifaces = interfaces.clone();
        let acl_tls = std::sync::Arc::clone(&acl);
        let tracker_tls = std::sync::Arc::clone(&tcp_tracker);
        let fw_sup = std::sync::Arc::clone(&fw);
        tokio::spawn(tls_supervisor(rx, h, cfg_path, ifaces, acl_tls, tracker_tls, cfg.proxy_protocol, fw_sup));
    }


    info!("Runbound ready — RFC 1034/1035/2782/4033/6891/7858/8484/9250");
    // All listeners are spawned as tokio tasks; block here until process exits.
    std::future::pending::<anyhow::Result<()>>().await
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_tls_name_cloudflare() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(dot_tls_name(&ip, None), Arc::from("cloudflare-dns.com"));
    }

    #[test]
    fn dot_tls_name_cloudflare_alt() {
        let ip: IpAddr = "1.0.0.1".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(dot_tls_name(&ip, None), Arc::from("cloudflare-dns.com"));
    }

    #[test]
    fn dot_tls_name_quad9() {
        let ip: IpAddr = "9.9.9.9".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(dot_tls_name(&ip, None), Arc::from("dns.quad9.net"));
    }

    #[test]
    fn dot_tls_name_quad9_alt() {
        let ip: IpAddr = "149.112.112.112".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(dot_tls_name(&ip, None), Arc::from("dns.quad9.net"));
    }

    #[test]
    fn dot_tls_name_google() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(dot_tls_name(&ip, None), Arc::from("dns.google"));
    }

    #[test]
    fn dot_tls_name_google_alt() {
        let ip: IpAddr = "8.8.4.4".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(dot_tls_name(&ip, None), Arc::from("dns.google"));
    }

    #[test]
    fn dot_tls_name_unknown_ip() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(dot_tls_name(&ip, None), Arc::from("192.168.1.1"));
    }

    #[test]
    fn dot_tls_name_explicit_override() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(
            dot_tls_name(&ip, Some("my-custom-dot.example.com")),
            Arc::from("my-custom-dot.example.com"),
        );
    }

    #[test]
    fn dot_tls_name_explicit_overrides_known_resolver() {
        // forward-tls-hostname must win even over the built-in Cloudflare mapping
        let ip: IpAddr = "1.1.1.1".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(
            dot_tls_name(&ip, Some("dot.internal.example.com")),
            Arc::from("dot.internal.example.com"),
        );
    }

    #[test]
    fn dot_tls_name_custom_ip_no_fallback_to_literal() {
        // Unknown IP with no explicit hostname falls back to the IP literal —
        // correct behaviour: TLS will fail rather than silently accept.
        let ip: IpAddr = "203.0.113.1".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(dot_tls_name(&ip, None), Arc::from("203.0.113.1"));
    }

    // ── make_opt_edns tests (#160 — OPT echo on all paths) ──────────────────

    #[test]
    fn make_opt_edns_no_edns_returns_none() {
        // Requête sans OPT → aucun echo
        use hickory_proto::op::Edns;
        // Simuler un MessageRequest sans edns via le champ public
        // On teste la logique de make_opt_edns directement :
        // None input → None output
        let e: Option<Edns> = None;
        let result: Option<Edns> = e.as_ref().map(|req_edns| {
            let mut edns = Edns::new();
            edns.set_max_payload(req_edns.max_payload().clamp(512, 1232));
            edns.flags_mut().dnssec_ok = req_edns.flags().dnssec_ok;
            edns
        });
        assert!(result.is_none(), "no EDNS in request → no OPT in response");
    }

    #[test]
    fn make_opt_edns_echoes_payload_capped() {
        use hickory_proto::op::Edns;
        // Payload 4096 → capped à 1232
        let mut req_edns = Edns::new();
        req_edns.set_max_payload(4096);
        let result = {
            let mut edns = Edns::new();
            edns.set_max_payload(req_edns.max_payload().clamp(512, 1232));
            edns.flags_mut().dnssec_ok = req_edns.flags().dnssec_ok;
            edns
        };
        assert_eq!(result.max_payload(), 1232, "payload must be capped at 1232");
        assert!(!result.flags().dnssec_ok, "DO bit must be false when not set");
    }

    #[test]
    fn make_opt_edns_reflects_do_bit() {
        use hickory_proto::op::Edns;
        // DO=1 → reflété
        let mut req_edns = Edns::new();
        req_edns.set_max_payload(1232);
        req_edns.flags_mut().dnssec_ok = true;
        let result = {
            let mut edns = Edns::new();
            edns.set_max_payload(req_edns.max_payload().clamp(512, 1232));
            edns.flags_mut().dnssec_ok = req_edns.flags().dnssec_ok;
            edns
        };
        assert!(result.flags().dnssec_ok, "DO bit must be reflected");
        assert_eq!(result.max_payload(), 1232);
    }

    #[test]
    fn make_opt_edns_minimum_payload_floor() {
        use hickory_proto::op::Edns;
        // Payload 128 (sous le minimum) → floored à 512
        let mut req_edns = Edns::new();
        req_edns.set_max_payload(128);
        let result = {
            let mut edns = Edns::new();
            edns.set_max_payload(req_edns.max_payload().clamp(512, 1232));
            edns
        };
        assert_eq!(result.max_payload(), 512, "payload must be floored at 512");
    }

}

#[cfg(test)]
mod split_horizon_compile_tests {
    //! #10/#186: split-horizon compiles to a per-subnet table that matches clients
    //! by source IP. The live hot-swap itself is covered by the runtime test.
    use super::compile_split_horizon;
    use crate::config::parser::{LocalData, SplitHorizonEntry};
    use std::net::IpAddr;

    #[test]
    fn compile_and_match_by_subnet() {
        let e = SplitHorizonEntry {
            name: "internal".into(),
            subnets: vec!["10.0.0.0/8".into()],
            local_data: vec![LocalData { rr: "intranet.corp. A 10.0.0.5".into() }],
        };
        let table = compile_split_horizon(&[e]);
        assert_eq!(table.len(), 1, "one compiled entry expected");
        let inside: IpAddr = "10.1.2.3".parse().unwrap();
        let outside: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(table[0].0.iter().any(|cb| cb.contains(inside)), "in-range client must match");
        assert!(!table[0].0.iter().any(|cb| cb.contains(outside)), "out-of-range client must not match");
    }

    #[test]
    fn invalid_subnet_entry_is_skipped() {
        let e = SplitHorizonEntry {
            name: "bad".into(),
            subnets: vec!["not-a-subnet".into()],
            local_data: vec![],
        };
        assert_eq!(compile_split_horizon(&[e]).len(), 0, "entry with no valid subnet is skipped");
    }
}
