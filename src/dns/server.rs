// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Runbound DNS server — drop-in for Unbound.
//
// Architecture:
//   1. Access-control list check (per source IP, from unbound.conf)
//   2. Rate limiting (per source IP token bucket)
//   3. Check local zones (local-data, blacklist, feeds) in memory → instant
//   4. Otherwise → recursive resolver (hickory-resolver)
//
// UDP + TCP on the configured port (default 53).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::future::select_ok;
use hickory_proto::op::Query as DnsQuery;
use hickory_proto::op::{Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_resolver::{
    config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    lookup::Lookup,
    net::runtime::TokioRuntimeProvider,
    net::{DnsError, NetError, NoRecords},
    TokioResolver,
};
use hickory_server::{
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
    Server,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use smallvec::SmallVec;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use super::acl::{Acl, AclAction, PrivateAddressSet};
use super::local::{LocalZoneSet, ZoneAction};
use super::ratelimit::RateLimiter;
use crate::config::parser::TlsConfig;
use crate::config::parser::UnboundConfig;
use crate::logbuffer::{LogAction, SharedLogBuffer};
use crate::stats::{Stats, CACHE_HIT_THRESHOLD_US};

// ── Concurrency cap — prevents OOM under flood ─────────────────────────────
//
// hickory-server spawns one tokio task per incoming DNS request with no
// backpressure. Under a flood (DDoS or perf test) this exhausts RAM.
// A non-blocking try_acquire returns REFUSED instantly without allocating
// any additional memory, so the bound is hard even at line rate.
const MAX_INFLIGHT_REQUESTS: usize = 4_096;

const RATE_LIMIT_QPS_DEFAULT: u64 = 200;

// ── Resolver lookup hard timeout (#83) ─────────────────────────────────────
//
// hickory-resolver's internal timeout is opts.timeout × opts.attempts = 3 s × 2 = 6 s.
// Under sustained pool exhaustion (upstream unreachable or pool not yet established),
// N concurrent queries each block a Tokio worker for up to 6 s.  When N ≥ num_cpus
// all workers are occupied, preventing the background reconnect task from running —
// the runtime deadlocks completely (even loopback stops responding).
//
// RESOLVER_LOOKUP_TIMEOUT is a hard outer fuse applied by Runbound independently of
// hickory's internal retry/timeout mechanism.  The tokio::time::timeout future is
// cancelled when it fires, immediately freeing the worker regardless of hickory's
// internal state.  2500 ms keeps latency low while remaining above 1 RTT for any
// realistic upstream.
const RESOLVER_LOOKUP_TIMEOUT: Duration = Duration::from_millis(2500);

/// Wrap a resolver lookup with a hard external timeout.
/// Returns `Err(NetError::Timeout)` if hickory does not respond within
/// `RESOLVER_LOOKUP_TIMEOUT`, cancelling the hickory future and freeing the
/// Tokio worker immediately.
async fn timed_lookup(
    resolver: &TokioResolver,
    name: Name,
    qtype: RecordType,
) -> Result<Lookup, NetError> {
    match tokio::time::timeout(RESOLVER_LOOKUP_TIMEOUT, resolver.lookup(name, qtype)).await {
        Ok(r) => r,
        Err(_) => Err(NetError::Timeout),
    }
}

// ── DoT rebuild rate-limiter ────────────────────────────────────────────────
// At most one resolver rebuild every 2 s. Under sustained DoT pool exhaustion
// every failed query would otherwise trigger its own rebuild, creating a
// positive-feedback loop that saturates the Tokio runtime with rebuild tasks.
// DOT_REBUILD_LAST_LOG_SECS throttles the log to at most one message per 10 s.
static DOT_REBUILD_LAST_SECS: AtomicU64 = AtomicU64::new(0);
static DOT_REBUILD_LAST_LOG_SECS: AtomicU64 = AtomicU64::new(0);

// ── Identity-probe name set (zero-alloc hot path) ──────────────────────────
// Initialised once on first DNS query; compared directly as LowerName.
// Avoids a String allocation per request for the CHAOS identity-probe check.
static IDENTITY_PROBE_NAMES: OnceLock<[LowerName; 4]> = OnceLock::new();

fn identity_probe_names() -> &'static [LowerName; 4] {
    IDENTITY_PROBE_NAMES.get_or_init(|| {
        [
            LowerName::from(
                Name::from_str("version.bind.")
                    .unwrap_or_else(|e| panic!("bad static DNS name: {e}")),
            ),
            LowerName::from(
                Name::from_str("hostname.bind.")
                    .unwrap_or_else(|e| panic!("bad static DNS name: {e}")),
            ),
            LowerName::from(
                Name::from_str("id.server.").unwrap_or_else(|e| panic!("bad static DNS name: {e}")),
            ),
            LowerName::from(
                Name::from_str("version.server.")
                    .unwrap_or_else(|e| panic!("bad static DNS name: {e}")),
            ),
        ]
    })
}

// ============================================================
// Handler
// ============================================================

pub struct RunboundHandler {
    pub zones: Arc<ArcSwap<LocalZoneSet>>,
    resolver: Arc<ArcSwap<TokioResolver>>,
    rate_limiter: Arc<RateLimiter>,
    inflight: Arc<Semaphore>,
    acl: Arc<Acl>,
    private_addrs: Arc<PrivateAddressSet>,
    cache_max_ttl: u32,
    pub stats: Arc<Stats>,
    pub log_buffer: SharedLogBuffer,
    /// DNSSEC tracking enabled — mirrors `dnssec-validation: yes` in config.
    dnssec_enabled: bool,
    dnssec_log_bogus: bool,
    /// Optional prefetch tracker — None when prefetch: no (default).
    prefetch_tracker: Option<Arc<crate::dns::prefetch::PrefetchTracker>>,
    /// #60: mutable cache map shared with XDP workers (via publish_loop).
    /// None when xdp-cache-snapshot: no or XDP feature not compiled.
    xdp_cache: Option<super::cache_snapshot::MutableCacheMap>,
    cache_max_entries: usize,
    /// #77: upstream list for transparent pool reconnection on DoT exhaustion.
    upstreams: crate::upstreams::SharedUpstreams,
    /// #33: per-upstream resolvers for racing mode.
    per_upstream_resolvers: SharedResolversVec,
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
    /// #108: serve-stale cache — stores last successful records per (name, qtype).
    stale_cache: Option<Arc<dashmap::DashMap<(hickory_proto::rr::LowerName, hickory_proto::rr::RecordType), (Vec<hickory_proto::rr::Record>, std::time::Instant), ahash::RandomState>>>,
    /// #108: TTL to advertise for stale answers (seconds).
    stale_answer_ttl: u32,
    /// #108: max age of a stale entry (seconds).
    stale_max_age: u64,
}

impl RunboundHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        zones: Arc<ArcSwap<LocalZoneSet>>,
        resolver: Arc<ArcSwap<TokioResolver>>,
        rate_limiter: Arc<RateLimiter>,
        acl: Arc<Acl>,
        private_addrs: Arc<PrivateAddressSet>,
        cache_max_ttl: u32,
        stats: Arc<Stats>,
        log_buffer: SharedLogBuffer,
        dnssec_enabled: bool,
        dnssec_log_bogus: bool,
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
    ) -> Self {
        Self {
            zones,
            resolver,
            rate_limiter,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_REQUESTS)),
            acl,
            private_addrs,
            cache_max_ttl,
            stats,
            log_buffer,
            dnssec_enabled,
            dnssec_log_bogus,
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
            stale_cache: if serve_stale {
                Some(Arc::new(dashmap::DashMap::with_hasher(ahash::RandomState::default())))
            } else {
                None
            },
            stale_answer_ttl,
            stale_max_age,
        }
    }

    /// Record a completed query: latency histogram, log buffer push, tracing log.
    /// Cache metrics (record_forward) and domain counters are updated at call sites.
    #[inline]
    fn record_query(
        &self,
        client: IpAddr,
        qname: &hickory_proto::rr::LowerName,
        qtype: RecordType,
        rcode: ResponseCode,
        action: LogAction,
        start: Instant,
    ) {
        let elapsed = start.elapsed();
        let elapsed_us = elapsed.as_micros() as u64;
        let elapsed_ms = elapsed.as_millis() as u32;

        self.stats.record_latency_us(elapsed_us);
        if action == LogAction::Local {
            self.stats.inc_local_hits();
        }

        // MED-06: sanitize the DNS name before structured log emission to prevent
        // log injection via control characters embedded in query names.
        //
        // Notable = any non-NoError response or explicitly blocked action.
        // Rate-limited queries arrive here as ResponseCode::Refused + LogAction::Refused,
        // so they are covered by the rcode check.
        //
        // Guard levels:
        //   verbosity:0 (ERROR) — WARN disabled → outer check false → zero alloc, zero mutex.
        //   verbosity:1 (WARN)  — notable queries only: log buffer push + warn!, NOERROR skipped.
        //   verbosity:2 (INFO)  — all queries: log buffer push + info!.
        let is_notable = rcode != ResponseCode::NoError || matches!(action, LogAction::Blocked);

        if tracing::enabled!(tracing::Level::INFO)
            || (is_notable
                && tracing::enabled!(tracing::Level::WARN)
                && self.log_buffer.is_enabled())
        {
            let safe_name = sanitize_dns_name(qname);
            let safe_name_str = safe_name.to_string();
            let client_log = self.log_buffer.push_query(
                &safe_name_str,
                &client,
                u16::from(qtype),
                action,
                elapsed_ms,
            );
            info!(
                client = %client_log,
                name   = %safe_name,
                qtype  = %qtype,
                rcode  = %rcode,
                action = action.as_str(),
                ms     = elapsed_ms,
                "query"
            );
        }
    }
}

impl RunboundHandler {
    /// Attempt to answer from local zones (blacklist, static data, CNAME chains).
    /// Returns `Ok(info)` when a response was sent; `Err(rh)` when no local match
    /// was found and the query should fall through to recursive resolution.
    async fn handle_local_zone<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        qname: &LowerName,
        qtype: RecordType,
        client_ip: IpAddr,
        start: Instant,
    ) -> Result<ResponseInfo, R> {
        let zones_snap = self.zones.load();
        let zone_action = zones_snap.find(qname);

        match zone_action {
            Some(ZoneAction::Refuse) => {
                debug!(name=%sanitize_dns_name(qname), "local-zone REFUSED");
                self.stats.inc_blocked();
                self.stats.inc_refused();
                self.record_query(
                    client_ip,
                    qname,
                    qtype,
                    ResponseCode::Refused,
                    LogAction::Blocked,
                    start,
                );
                return Ok(send_error(request, response_handle, ResponseCode::Refused).await);
            }
            Some(ZoneAction::NxDomain) => {
                debug!(name=%sanitize_dns_name(qname), "local-zone NXDOMAIN");
                self.stats.inc_blocked();
                self.stats.inc_nxdomain();
                self.record_query(
                    client_ip,
                    qname,
                    qtype,
                    ResponseCode::NXDomain,
                    LogAction::Blocked,
                    start,
                );
                return Ok(send_error(request, response_handle, ResponseCode::NXDomain).await);
            }
            Some(ZoneAction::Static) | Some(ZoneAction::Redirect) => {
                let records = zones_snap.local_records(qname, qtype);

                if !records.is_empty() {
                    debug!(name=%sanitize_dns_name(qname), count = records.len(), "local-data answer");
                    let mut metadata = Metadata::response_from_request(&request.metadata);
                    metadata.authoritative = true;
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.build(
                        metadata,
                        records,
                        std::iter::empty(),
                        std::iter::empty(),
                        std::iter::empty(),
                    );
                    self.record_query(
                        client_ip,
                        qname,
                        qtype,
                        ResponseCode::NoError,
                        LogAction::Local,
                        start,
                    );
                    return Ok(response_handle
                        .send_response(response)
                        .await
                        .unwrap_or_else(|e| {
                            error!("send: {e}");
                            servfail_info(request)
                        }));
                }

                // CNAME chain following (RFC 1034 §3.6.2)
                if qtype != RecordType::CNAME {
                    let chain = follow_local_cname(&zones_snap, qname, qtype);
                    if !chain.is_empty() {
                        let mut metadata = Metadata::response_from_request(&request.metadata);
                        metadata.authoritative = true;
                        let builder = MessageResponseBuilder::from_message_request(request);
                        let response = builder.build(
                            metadata,
                            chain.iter(),
                            std::iter::empty(),
                            std::iter::empty(),
                            std::iter::empty(),
                        );
                        self.record_query(
                            client_ip,
                            qname,
                            qtype,
                            ResponseCode::NoError,
                            LogAction::Local,
                            start,
                        );
                        return Ok(response_handle
                            .send_response(response)
                            .await
                            .unwrap_or_else(|e| {
                                error!("send: {e}");
                                servfail_info(request)
                            }));
                    }
                }

                // RFC 1035 §3.7 / RFC 2308: NODATA vs NXDOMAIN
                if zones_snap.name_has_records(qname) {
                    debug!(name=%sanitize_dns_name(qname), %qtype, "local-zone NODATA");
                    let mut metadata = Metadata::response_from_request(&request.metadata);
                    metadata.authoritative = true;
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.build(
                        metadata,
                        std::iter::empty::<&Record>(),
                        std::iter::empty(),
                        std::iter::empty(),
                        std::iter::empty(),
                    );
                    self.record_query(
                        client_ip,
                        qname,
                        qtype,
                        ResponseCode::NoError,
                        LogAction::Local,
                        start,
                    );
                    return Ok(response_handle
                        .send_response(response)
                        .await
                        .unwrap_or_else(|e| {
                            error!("send: {e}");
                            servfail_info(request)
                        }));
                }
                debug!(name=%sanitize_dns_name(qname), "local-zone NXDOMAIN (name not found)");
                self.record_query(
                    client_ip,
                    qname,
                    qtype,
                    ResponseCode::NXDomain,
                    LogAction::Nxdomain,
                    start,
                );
                return Ok(send_error(request, response_handle, ResponseCode::NXDomain).await);
            }
            None => {}
        }
        // Reached only via the None arm — response_handle was not consumed.
        Err(response_handle)
    }

    /// Recursive upstream resolution with DNSSEC validation and rebinding protection.
    async fn resolve_upstream<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        qname: &LowerName,
        qtype: RecordType,
        client_ip: IpAddr,
        start: Instant,
    ) -> ResponseInfo {
        // #33: racing mode — send to all upstreams simultaneously, first wins.
        // All lookup calls go through timed_lookup (#83) to cap worker occupancy.
        let result = if self.upstream_racing {
            let resolvers = self.per_upstream_resolvers.load();
            if resolvers.len() >= 2 {
                let name = Name::from(qname);
                let futs: Vec<_> = resolvers
                    .iter()
                    .map(|(addr, r)| {
                        let r = Arc::clone(r);
                        let n = name.clone();
                        let addr = addr.clone();
                        Box::pin(async move { timed_lookup(&r, n, qtype).await.map(|l| (l, addr)) })
                    })
                    .collect();
                match select_ok(futs).await {
                    Ok(((lookup, winner), _rest)) => {
                        // Record win for the upstream that answered first.
                        self.racing_wins
                            .entry(winner)
                            .or_insert_with(|| Arc::new(std::sync::atomic::AtomicU64::new(0)))
                            .fetch_add(1, Ordering::Relaxed);
                        Ok(lookup)
                    }
                    Err(e) => Err(e),
                }
            } else {
                timed_lookup(&self.resolver.load(), Name::from(qname), qtype).await
            }
        } else {
            timed_lookup(&self.resolver.load(), Name::from(qname), qtype).await
        };

        // Level 2: transparent reconnection on DoT pool exhaustion (#77 + #83).
        // Rate-limited to one rebuild every 2 s: under sustained pool exhaustion,
        // every failed query would otherwise spawn its own rebuild task, creating
        // a positive-feedback loop that saturates the Tokio scheduler.
        // Queries that lose the CAS race return SERVFAIL immediately — no rebuild.
        //
        // #83: the rebuild is spawned as a background task instead of being awaited
        // in the query handler.  Awaiting rebuild_and_swap() (which calls warm_up()
        // internally) could block the current worker for up to 3 s, compounding the
        // worker-exhaustion problem.  The next query will use the rebuilt resolver.
        if let Err(ref e) = result {
            if is_pool_exhausted(e) {
                let now_s = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let last = DOT_REBUILD_LAST_SECS.load(Ordering::Relaxed);
                if now_s.saturating_sub(last) >= 2
                    && DOT_REBUILD_LAST_SECS
                        .compare_exchange(last, now_s, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                {
                    // At most one log line per 10 s so the event is visible without spam.
                    let last_log = DOT_REBUILD_LAST_LOG_SECS.load(Ordering::Relaxed);
                    if now_s.saturating_sub(last_log) >= 10 {
                        DOT_REBUILD_LAST_LOG_SECS.store(now_s, Ordering::Relaxed);
                        info!(name=%sanitize_dns_name(qname), "DoT pool exhausted — rebuilding resolver");
                    }
                    let addrs = crate::upstreams::upstream_addrs(&self.upstreams);
                    let resolver_rebuild = Arc::clone(&self.resolver);
                    let stats_rebuild = Arc::clone(&self.stats);
                    let dnssec = self.dnssec_enabled;
                    tokio::spawn(async move {
                        if rebuild_and_swap(&resolver_rebuild, &addrs, dnssec)
                            .await
                            .is_ok()
                        {
                            stats_rebuild.record_dot_reconnect();
                        }
                    });
                    // This query returns SERVFAIL; the next query will find the rebuilt resolver.
                }
            }

            // #94: resolv.conf fallback — activate when all real upstreams are unhealthy.
            if self.resolv_fallback
                && !self.fallback_active.load(Ordering::Relaxed)
                && crate::upstreams::all_non_temporary_unhealthy(&self.upstreams)
                && self
                    .fallback_active
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                let ups = Arc::clone(&self.upstreams);
                let res = Arc::clone(&self.resolver);
                let dnssec = self.dnssec_enabled;
                tokio::spawn(async move {
                    crate::upstreams::add_resolv_fallback(&ups);
                    let addrs = crate::upstreams::upstream_addrs(&ups);
                    let _ = rebuild_and_swap(&res, &addrs, dnssec).await;
                    warn!("resolv.conf fallback activated — all configured upstreams are down");
                });
            }
        }

        match result {
            Ok(lookup) => {
                // DNS rebinding protection: SERVFAIL if any A/AAAA record falls
                // within a configured private-address range (Unbound compatible).
                if !self.private_addrs.is_empty() {
                    for rec in lookup.answers() {
                        let private_ip = match &rec.data {
                            RData::A(a) => Some(IpAddr::V4(a.0)),
                            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                            _ => None,
                        };
                        if let Some(ip) = private_ip {
                            if self.private_addrs.contains(ip) {
                                warn!(name=%sanitize_dns_name(qname), %ip, "private-address block → SERVFAIL");
                                self.record_query(
                                    client_ip,
                                    qname,
                                    qtype,
                                    ResponseCode::ServFail,
                                    LogAction::Servfail,
                                    start,
                                );
                                return send_error(
                                    request,
                                    response_handle,
                                    ResponseCode::ServFail,
                                )
                                .await;
                            }
                        }
                    }
                }

                let ttl_cap = self.cache_max_ttl;
                let needs_cap = lookup.answers().iter().any(|r| r.ttl > ttl_cap);
                let capped: Vec<Record>;
                let records: &[Record] = if needs_cap {
                    capped = lookup
                        .answers()
                        .iter()
                        .map(|r| {
                            if r.ttl > ttl_cap {
                                let mut rc = r.clone();
                                rc.ttl = ttl_cap;
                                rc
                            } else {
                                r.clone()
                            }
                        })
                        .collect();
                    &capped
                } else {
                    lookup.answers()
                };

                // DNSSEC: check for bogus proof on individual records in success path.
                if self.dnssec_enabled {
                    let has_bogus = records.iter().any(|r| r.proof.is_bogus());
                    if has_bogus {
                        self.stats.inc_dnssec_bogus();
                        if self.dnssec_log_bogus {
                            warn!(name=%sanitize_dns_name(qname), "DNSSEC bogus — SERVFAIL");
                        }
                        self.record_query(
                            client_ip,
                            qname,
                            qtype,
                            ResponseCode::ServFail,
                            LogAction::Servfail,
                            start,
                        );
                        return send_error(request, response_handle, ResponseCode::ServFail).await;
                    }
                    let has_rrsig = records.iter().any(|r| r.record_type() == RecordType::RRSIG);
                    if has_rrsig {
                        self.stats.inc_dnssec_secure();
                    } else {
                        self.stats.inc_dnssec_insecure();
                    }
                }

                debug!(name=%sanitize_dns_name(qname), %qtype, count = records.len(), "resolved");

                // #60 / #64: populate the XDP cache snapshot with wire-format response.
                // Key uses wire-format DNS name bytes + qclass for fast XDP lookup.
                // Stored with QID=0; XDP workers patch bytes [0..2] before sending.
                // Insert is spawned to avoid blocking the response path.
                if let Some(ref cache) = self.xdp_cache {
                    if !records.is_empty() {
                        let min_ttl = records
                            .iter()
                            .map(|r| r.ttl)
                            .min()
                            .unwrap_or(60)
                            .min(self.cache_max_ttl);
                        // Build wire-format name key
                        let mut name_tmp: Vec<u8> = Vec::with_capacity(64);
                        let mut name_enc = BinEncoder::new(&mut name_tmp);
                        if Name::from(qname).emit(&mut name_enc).is_ok() {
                            let wire_name: SmallVec<[u8; 64]> = SmallVec::from_slice(&name_tmp);
                            let key = super::cache_snapshot::QuestionKey {
                                name: wire_name,
                                qtype: u16::from(qtype),
                                qclass: 1u16, // IN class
                            };
                            let mut wire: Vec<u8> = Vec::with_capacity(512);
                            let mut cache_msg =
                                Message::new(0, MessageType::Response, OpCode::Query);
                            cache_msg.metadata.recursion_available = true;
                            cache_msg.metadata.response_code = ResponseCode::NoError;
                            cache_msg.add_query(DnsQuery::query(Name::from(qname), qtype));
                            for r in records {
                                cache_msg.add_answer((*r).clone());
                            }
                            let mut enc = BinEncoder::new(&mut wire);
                            if cache_msg.emit(&mut enc).is_ok() {
                                let expires_at = std::time::Instant::now()
                                    + std::time::Duration::from_secs(min_ttl as u64);
                                let entry = super::cache_snapshot::CacheEntry {
                                    wire_payload: Bytes::from(wire),
                                    expires_at,
                                };
                                let cache_ref = Arc::clone(cache);
                                let max_ent = self.cache_max_entries;
                                tokio::spawn(async move {
                                    super::cache_snapshot::cache_insert(
                                        &cache_ref, key, entry, max_ent,
                                    );
                                });
                            }
                        }
                    }
                }

                // #108: Update stale cache with fresh records.
                if let Some(ref sc) = self.stale_cache {
                    if !records.is_empty() {
                        let stale_key = (qname.clone(), qtype);
                        sc.insert(stale_key, (records.to_vec(), std::time::Instant::now()));
                    }
                }

                // Prefetch: count forwarded queries so hot domains can be refreshed before expiry.
                if let Some(ref tracker) = self.prefetch_tracker {
                    tracker.increment(&qname.to_string());
                }
                let mut metadata = Metadata::response_from_request(&request.metadata);
                metadata.recursion_available = true;
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.build(
                    metadata,
                    records.iter(),
                    std::iter::empty(),
                    std::iter::empty(),
                    std::iter::empty(),
                );
                self.stats.inc_forwarded();
                let fwd_us = start.elapsed().as_micros() as u64;
                self.stats.record_forward(fwd_us);
                let fwd_action = if fwd_us < CACHE_HIT_THRESHOLD_US {
                    LogAction::Cached
                } else {
                    LogAction::Forwarded
                };
                self.record_query(
                    client_ip,
                    qname,
                    qtype,
                    ResponseCode::NoError,
                    fwd_action,
                    start,
                );
                response_handle
                    .send_response(response)
                    .await
                    .unwrap_or_else(|e| {
                        error!("send: {e}");
                        servfail_info(request)
                    })
            }
            Err(e) => {
                // DNSSEC bogus via NSEC denial: validated proof the record does not exist.
                let is_dnssec_bogus = self.dnssec_enabled
                    && matches!(&e, NetError::Dns(DnsError::Nsec { proof, .. }) if proof.is_bogus());

                if is_dnssec_bogus {
                    self.stats.inc_dnssec_bogus();
                    if self.dnssec_log_bogus {
                        warn!(name=%sanitize_dns_name(qname), "DNSSEC bogus — SERVFAIL (NSEC denial)");
                    }
                }

                let rcode = match &e {
                    NetError::Dns(DnsError::NoRecordsFound(NoRecords {
                        response_code, ..
                    })) => {
                        debug!(name=%sanitize_dns_name(qname), ?response_code, "no records from resolver");
                        *response_code
                    }
                    _ => {
                        if !is_dnssec_bogus {
                            warn!(name=%sanitize_dns_name(qname), err=%e, "resolver error → SERVFAIL");
                        }
                        ResponseCode::ServFail
                    }
                };
                let err_action = match rcode {
                    ResponseCode::NXDomain => {
                        self.stats.inc_nxdomain();
                        LogAction::Nxdomain
                    }
                    ResponseCode::ServFail => {
                        self.stats.inc_servfail();
                        LogAction::Servfail
                    }
                    ResponseCode::Refused => {
                        self.stats.inc_refused();
                        LogAction::Refused
                    }
                    _ => LogAction::Servfail,
                };
                // #108: serve-stale — if SERVFAIL and we have a cached entry, serve it.
                if rcode == ResponseCode::ServFail {
                    if let Some(ref sc) = self.stale_cache {
                        let stale_key = (qname.clone(), qtype);
                        if let Some(entry) = sc.get(&stale_key) {
                            let (ref stale_records, stored_at) = *entry;
                            let age = stored_at.elapsed().as_secs();
                            if age <= self.stale_max_age && !stale_records.is_empty() {
                                let stale_ttl = self.stale_answer_ttl;
                                let capped: Vec<hickory_proto::rr::Record> = stale_records
                                    .iter()
                                    .map(|r| { let mut rc = r.clone(); rc.ttl = stale_ttl; rc })
                                    .collect();
                                drop(entry);
                                info!(name=%sanitize_dns_name(qname), age_secs=age, ttl=stale_ttl, "serve-stale");
                                self.stats.inc_stale_served();
                                self.record_query(client_ip, qname, qtype, ResponseCode::NoError, LogAction::Cached, start);
                                let mut metadata = Metadata::response_from_request(&request.metadata);
                                metadata.recursion_available = true;
                                let builder = MessageResponseBuilder::from_message_request(request);
                                let response = builder.build(metadata, capped.iter(), std::iter::empty(), std::iter::empty(), std::iter::empty());
                                return response_handle.send_response(response).await.unwrap_or_else(|e| { error!("send: {e}"); servfail_info(request) });
                            }
                        }
                    }
                }

                self.record_query(client_ip, qname, qtype, rcode, err_action, start);
                send_error(request, response_handle, rcode).await
            }
        }
    }
}

#[async_trait]
impl RequestHandler for RunboundHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let start = Instant::now();

        // Require exactly one query — RFC 1035 §4.1.2.
        let Ok(info) = request.request_info() else {
            self.stats.inc_total();
            return servfail_info(request);
        };
        let qname = info.query.name();
        let qtype = info.query.query_type();
        let client_ip = info.src.ip();

        self.stats.inc_total();
        self.domain_stats.inc(&qname.to_string());

        // ── 0. Access-control list ──────────────────────────────────────
        match self.acl.check(client_ip) {
            AclAction::Allow => {}
            AclAction::Deny => {
                // Silently drop — no response sent, just track the event.
                debug!(%client_ip, name=%sanitize_dns_name(qname), "ACL deny (silent drop)");
                self.record_query(
                    client_ip,
                    qname,
                    qtype,
                    ResponseCode::Refused,
                    LogAction::Refused,
                    start,
                );
                let mut meta = Metadata::response_from_request(&request.metadata);
                meta.response_code = ResponseCode::Refused;
                return ResponseInfo::from(hickory_proto::op::Header {
                    metadata: meta,
                    counts: hickory_proto::op::HeaderCounts::default(),
                });
            }
            AclAction::Refuse => {
                debug!(%client_ip, name=%sanitize_dns_name(qname), "ACL refuse");
                self.record_query(
                    client_ip,
                    qname,
                    qtype,
                    ResponseCode::Refused,
                    LogAction::Refused,
                    start,
                );
                return send_error(request, response_handle, ResponseCode::Refused).await;
            }
        }

        // ── 1. Rate limiting (per source IP) ───────────────────────────
        if !self.rate_limiter.check(client_ip) {
            warn!(%client_ip, "rate limited");
            self.record_query(
                client_ip,
                qname,
                qtype,
                ResponseCode::Refused,
                LogAction::Refused,
                start,
            );
            return send_error(request, response_handle, ResponseCode::Refused).await;
        }

        // ── 2. Concurrency cap (anti-OOM) ──────────────────────────────
        let _permit = match self.inflight.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                warn!(%client_ip, inflight = MAX_INFLIGHT_REQUESTS, "inflight cap reached — REFUSED");
                self.record_query(
                    client_ip,
                    qname,
                    qtype,
                    ResponseCode::Refused,
                    LogAction::Refused,
                    start,
                );
                return send_error(request, response_handle, ResponseCode::Refused).await;
            }
        };

        // ── 3a. Block CHAOS class queries (version.bind, hostname.bind) ───
        // CHAOS class (numeric 3) exposes server identity. Compare by wire value
        // to avoid any hickory Unknown(3) vs CH variant mismatch.
        // RFC 5358 §4: responders that do not implement CHAOS SHOULD return NOTIMP.
        if u16::from(info.query.query_class()) == 3 {
            debug!(%client_ip, name=%sanitize_dns_name(qname), "CHAOS class query → NOTIMP");
            self.stats.inc_refused();
            self.record_query(
                client_ip,
                qname,
                qtype,
                ResponseCode::NotImp,
                LogAction::Refused,
                start,
            );
            return send_error(request, response_handle, ResponseCode::NotImp).await;
        }

        // ── 3b. SEC-03: defense-in-depth — block identity-probe names ───────
        // Block well-known identity-probe names by name regardless of query
        // class. hickory may normalise the CHAOS class (numeric 3) to IN
        // before invoking our handler, which bypasses the class check above
        // (observed: version.bind → NOERROR, hostname.bind → NXDOMAIN).
        // Zero allocation: qname is already a LowerName; compared against a
        // static set initialised once on first request.
        if identity_probe_names().iter().any(|n| n == qname) {
            debug!(%client_ip, name=%sanitize_dns_name(qname), "identity probe → REFUSED");
            self.stats.inc_refused();
            self.record_query(
                client_ip,
                qname,
                qtype,
                ResponseCode::Refused,
                LogAction::Refused,
                start,
            );
            return send_error(request, response_handle, ResponseCode::Refused).await;
        }

        // ── 3c. Block ANY queries (RFC 8482 — amplification vector) ────
        if qtype == RecordType::ANY {
            debug!(%client_ip, "ANY query blocked (RFC 8482)");
            self.record_query(
                client_ip,
                qname,
                qtype,
                ResponseCode::NotImp,
                LogAction::Refused,
                start,
            );
            return send_error(request, response_handle, ResponseCode::NotImp).await;
        }

        debug!(%client_ip, name=%sanitize_dns_name(qname), type=%qtype, "DNS query");

        // ── 4. Local zones ──────────────────────────────────────────────
        let response_handle = match self
            .handle_local_zone(request, response_handle, qname, qtype, client_ip, start)
            .await
        {
            Ok(info) => return info,
            Err(rh) => rh,
        };

        // ── 5. Recursive resolution ─────────────────────────────────────
        self.resolve_upstream(request, response_handle, qname, qtype, client_ip, start)
            .await
    }
}

// ============================================================
// Helpers
// ============================================================

/// Returns true when the hickory error indicates the DoT connection pool is exhausted
/// or all underlying TCP connections were reset by the peer (#77).
fn is_pool_exhausted(e: &NetError) -> bool {
    matches!(e, NetError::NoConnections)
        || matches!(e, NetError::Io(io) if matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
        ))
}

/// MED-06: Strip control characters from DNS names before structured log emission.
/// Prevents log injection via carefully crafted query names containing \n, \r, etc.
///
/// Returns a lazy Display wrapper so the formatting (and the String allocation)
/// only happens when the log level is actually enabled, saving one alloc per query
/// on disabled levels (e.g. debug! in production).
struct SanitizedDnsName<'a>(&'a LowerName);

impl std::fmt::Display for SanitizedDnsName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        let s = self.0.to_string();
        if s.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
            for c in s.chars() {
                f.write_char(if c.is_ascii() && !c.is_ascii_control() {
                    c
                } else {
                    '?'
                })?;
            }
        } else {
            f.write_str(&s)?;
        }
        Ok(())
    }
}

fn sanitize_dns_name(name: &LowerName) -> SanitizedDnsName<'_> {
    SanitizedDnsName(name)
}

/// Follow CNAME records within local zones, up to 8 hops (prevents loops).
/// Returns a Vec<Record> containing the CNAME chain + final target records,
/// or an empty Vec if there is no CNAME or the chain leads outside local zones.
fn follow_local_cname(
    zones: &super::local::LocalZoneSet,
    start: &LowerName,
    qtype: RecordType,
) -> Vec<Record> {
    let mut chain: Vec<Record> = Vec::with_capacity(8);
    let mut current = start.clone();

    for _ in 0..8 {
        let cnames = zones.local_records(&current, RecordType::CNAME);
        if cnames.is_empty() {
            break;
        }
        let cname_rec = (*cnames[0]).clone();
        let next = match &cname_rec.data {
            RData::CNAME(c) => LowerName::from(c.0.clone()),
            _ => break,
        };
        chain.push(cname_rec);
        let resolved: Vec<Record> = zones
            .local_records(&next, qtype)
            .into_iter()
            .map(|r| (*r).clone())
            .collect();
        if !resolved.is_empty() {
            chain.extend(resolved);
            return chain;
        }
        current = next;
    }
    // Chain incomplete (target not in local zones) — return nothing;
    // the caller will fall through to NODATA / NXDOMAIN as appropriate.
    Vec::new()
}

/// Construct a ResponseInfo carrying a SERVFAIL code without sending.
/// Used as the send-failure fallback when the socket is already broken.
#[inline]
fn servfail_info(request: &Request) -> ResponseInfo {
    let mut meta = Metadata::response_from_request(&request.metadata);
    meta.response_code = ResponseCode::ServFail;
    ResponseInfo::from(hickory_proto::op::Header {
        metadata: meta,
        counts: hickory_proto::op::HeaderCounts::default(),
    })
}

/// Send an error response, mirroring the request's EDNS0 OPT record if present.
/// RFC 6891 §7: "If a query included an OPT record, the response MUST include one."
#[inline(always)]
async fn send_error<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    rcode: ResponseCode,
) -> ResponseInfo {
    // `error_msg` mirrors the request's EDNS0 OPT record, satisfying RFC 6891 §7.
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.error_msg(&request.metadata, rcode);
    response_handle
        .send_response(response)
        .await
        .unwrap_or_else(|e| {
            error!("send: {e}");
            servfail_info(request)
        })
}

/// Shared, hot-swappable DNS resolver used by the server handler and the API.
pub type SharedResolver = Arc<ArcSwap<TokioResolver>>;

/// One resolver per upstream, used for DNS racing (#33).
/// Each entry is `(upstream_addr, resolver)`.
pub type SharedResolversVec = Arc<ArcSwap<Vec<(String, Arc<TokioResolver>)>>>;

/// Build one TokioResolver per upstream for racing mode.
pub fn build_per_upstream_resolvers(
    addrs: &[(String, u16, bool, Option<String>)],
    dnssec: bool,
) -> anyhow::Result<Vec<(String, Arc<TokioResolver>)>> {
    let mut result = Vec::with_capacity(addrs.len());
    for (addr_str, port, use_tls, tls_hostname) in addrs {
        let single = build_resolver_from_addrs(
            &[(addr_str.clone(), *port, *use_tls, tls_hostname.clone())],
            0, // no hickory-cache needed for racing path
            dnssec,
        )?;
        result.push((addr_str.clone(), Arc::new(single)));
    }
    Ok(result)
}

/// Create an empty SharedResolversVec — populated when upstream-racing is enabled.
pub fn create_shared_resolvers_vec() -> SharedResolversVec {
    Arc::new(ArcSwap::new(Arc::new(Vec::new())))
}

/// Create a SharedResolver from config at startup. Call once in build_and_launch.
pub fn create_shared_resolver(cfg: &UnboundConfig) -> anyhow::Result<SharedResolver> {
    let size = cache_size_from_meminfo();
    let resolver = build_resolver(cfg, size)?;
    Ok(Arc::new(ArcSwap::new(Arc::new(resolver))))
}

/// Derive a TLS SNI hostname for a DoT upstream.
///
/// Uses `explicit` when provided; otherwise maps well-known public resolver IPs
/// to their correct certificate SANs. Falls back to the IP string for unknowns
/// (produces a DnsName from the IP literal, which will fail TLS validation on
/// servers that only advertise their DNS name as a SAN — the correct behaviour
/// is to set `tls_hostname` explicitly for such servers).
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

/// Try to establish at least one live TCP/TLS connection in `resolver`.
/// Hickory opens connections lazily, so we must probe BEFORE making the
/// resolver visible via ArcSwap — otherwise the first real query races
/// against connection setup and gets `NetError::NoConnections`.
///
/// Retries up to 3 times with 250 ms delay on `NoConnections`; treats
/// every other outcome (including DNS errors) as "connection established".
/// Returns `true` when the pool is confirmed live, `false` after 3 failures.
async fn warm_up(resolver: &TokioResolver) -> bool {
    let probe = Name::from_str("example.com.").unwrap_or_else(|_| unreachable!("static DNS name"));
    for _ in 0..3u8 {
        match resolver.lookup(probe.clone(), RecordType::A).await {
            Ok(_) => return true,
            Err(ref e) if matches!(e, NetError::NoConnections) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(_) => return true, // connected but query failed (NXDOMAIN etc.) — pool is live
        }
    }
    false
}

/// Rebuild the resolver from an explicit list of (addr_string, port, use_tls, tls_hostname) tuples
/// and atomically swap it in. Used by POST /api/cache/flush and upstreams CRUD.
///
/// Calls `warm_up()` on the new resolver **before** the ArcSwap::store so that
/// TCP/TLS connections are established before any query can reach it (#77).
/// Returns `Ok(true)` when warm-up succeeded, `Ok(false)` when it timed out
/// (3 × 250 ms with no response) — the resolver is still stored in both cases.
pub async fn rebuild_and_swap(
    shared: &SharedResolver,
    addrs: &[(String, u16, bool, Option<String>)],
    dnssec: bool,
) -> anyhow::Result<bool> {
    let size = cache_size_from_meminfo();
    let new_res = build_resolver_from_addrs(addrs, size, dnssec)?;
    let warmed = warm_up(&new_res).await;
    shared.store(Arc::new(new_res));
    Ok(warmed)
}

/// Level 1 (#77): proactively warm up DoT TCP connections at startup.
/// Sends `dot_count` parallel probe queries so the pool has live connections
/// before the first real query arrives.
pub async fn warm_up_dot_connections(resolver: &SharedResolver, dot_count: usize) {
    if dot_count == 0 {
        return;
    }
    let probe = Name::from_str("example.com.").unwrap_or_else(|_| unreachable!("static DNS name"));
    let mut joins = Vec::with_capacity(dot_count);
    for _ in 0..dot_count {
        let res = Arc::clone(resolver);
        let name = probe.clone();
        joins.push(tokio::spawn(async move {
            let _ = res.load().lookup(name, RecordType::A).await;
        }));
    }
    for j in joins {
        let _ = j.await;
    }
    info!(connections = dot_count, "DoT pool warmed up");
}

/// Level 3 (#77): periodic keepalive to prevent idle DoT TCP connections from being
/// closed by the peer.  Fires every 90 s; sends one probe query per DoT upstream.
/// Rebuilds the resolver transparently if the pool is exhausted.
pub async fn dot_keepalive_loop(
    resolver: SharedResolver,
    upstreams: crate::upstreams::SharedUpstreams,
    stats: Arc<crate::stats::Stats>,
    dnssec: bool,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(90));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await; // skip the immediate first tick
    let probe = Name::from_str("example.com.").unwrap_or_else(|_| unreachable!("static DNS name"));
    loop {
        interval.tick().await;
        let dot_count = upstreams
            .read()
            .map(|u| u.iter().filter(|s| s.protocol == "dot").count())
            .unwrap_or(0);
        if dot_count == 0 {
            continue;
        }
        let mut joins = Vec::with_capacity(dot_count);
        for _ in 0..dot_count {
            let res = Arc::clone(&resolver);
            let name = probe.clone();
            joins.push(tokio::spawn(async move {
                res.load().lookup(name, RecordType::A).await
            }));
        }
        let mut any_exhausted = false;
        for j in joins {
            if let Ok(Err(ref e)) = j.await {
                if is_pool_exhausted(e) {
                    any_exhausted = true;
                }
            }
        }
        if any_exhausted {
            let addrs = crate::upstreams::upstream_addrs(&upstreams);
            match rebuild_and_swap(&resolver, &addrs, dnssec).await {
                Ok(warmed) => {
                    stats.record_dot_reconnect();
                    info!(warmed, "DoT keepalive: pool rebuilt after connection loss");
                }
                Err(e) => warn!(err=%e, "DoT keepalive: resolver rebuild failed"),
            }
        } else {
            debug!(
                connections = dot_count,
                "DoT keepalive: connections refreshed"
            );
        }
    }
}

/// Build resolver from an explicit (addr, port, use_tls, tls_hostname) list — used for runtime rebuilds.
pub fn build_resolver_from_addrs(
    addrs: &[(String, u16, bool, Option<String>)],
    cache_size: usize,
    dnssec: bool,
) -> anyhow::Result<TokioResolver> {
    let mut resolver_cfg = ResolverConfig::from_parts(None, vec![], vec![]);

    for (addr_str, port, use_tls, tls_hostname) in addrs {
        if let Ok(ip) = addr_str.parse::<IpAddr>() {
            if *use_tls {
                let tls_name = dot_tls_name(&ip, tls_hostname.as_deref());
                let mut cc = ConnectionConfig::tls(tls_name);
                cc.port = *port;
                resolver_cfg.add_name_server(NameServerConfig::new(ip, true, vec![cc]));
            } else {
                let mut cc_udp = ConnectionConfig::udp();
                cc_udp.port = *port;
                let mut cc_tcp = ConnectionConfig::tcp();
                cc_tcp.port = *port;
                resolver_cfg.add_name_server(NameServerConfig::new(ip, true, vec![cc_udp, cc_tcp]));
            }
        }
    }

    if resolver_cfg.name_servers().is_empty() {
        for ip_str in ["1.1.1.1", "1.0.0.1"] {
            let ip: IpAddr = ip_str
                .parse()
                .unwrap_or_else(|_| unreachable!("hardcoded Cloudflare IP is valid"));
            resolver_cfg.add_name_server(NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            ));
        }
    }

    let mut opts = ResolverOpts::default();
    opts.recursion_desired = true;
    opts.cache_size = cache_size as u64;
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 2;
    opts.validate = dnssec;
    opts.use_hosts_file = ResolveHosts::Never;

    TokioResolver::builder_with_config(resolver_cfg, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| anyhow::anyhow!("resolver build: {e}"))
}

/// Build resolver from forward-zones in unbound.conf, fallback to system resolvers.
fn build_resolver(cfg: &UnboundConfig, cache_size: usize) -> anyhow::Result<TokioResolver> {
    let mut resolver_cfg = ResolverConfig::from_parts(None, vec![], vec![]);

    for fwd in &cfg.forward_zones {
        for addr_str in &fwd.addrs {
            // Supports Unbound addr@port syntax: "1.1.1.1@853"
            let default_port = if fwd.tls { 853u16 } else { 53u16 };
            let (ip_str, port) = if let Some(at) = addr_str.find('@') {
                let p: u16 = addr_str[at + 1..].parse().unwrap_or(default_port);
                (&addr_str[..at], p)
            } else {
                (addr_str.as_str(), default_port)
            };
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if fwd.tls {
                    // DNS-over-TLS: encrypted channel, single TCP connection per server.
                    // dot_tls_name derives the correct SNI hostname for well-known resolvers.
                    let tls_name = dot_tls_name(&ip, None);
                    let mut cc = ConnectionConfig::tls(tls_name);
                    cc.port = port;
                    resolver_cfg.add_name_server(NameServerConfig::new(ip, true, vec![cc]));
                } else {
                    // UDP for normal queries (fast path)
                    let mut cc_udp = ConnectionConfig::udp();
                    cc_udp.port = port;
                    // TCP mandatory for DNSSEC: DNSKEY RRsets exceed UDP MTU and
                    // arrive truncated (TC=1). Without TCP, the DNSSEC chain cannot
                    // be completed and every signed domain returns SERVFAIL.
                    let mut cc_tcp = ConnectionConfig::tcp();
                    cc_tcp.port = port;
                    resolver_cfg.add_name_server(NameServerConfig::new(
                        ip,
                        true,
                        vec![cc_udp, cc_tcp],
                    ));
                }
            }
        }
    }

    // No forward-zone configured — fall back to Cloudflare.
    // WARNING: This sends all DNS queries to a third-party cloud resolver.
    // For sensitive or nation-state deployments, configure explicit forward-zone
    // blocks with trusted upstream resolvers. This fallback should never trigger
    // in production; it exists only to make Runbound usable out of the box.
    if resolver_cfg.name_servers().is_empty() {
        warn!(
            "No forward-zone configured — falling back to Cloudflare (1.1.1.1). \
             All DNS queries will be sent to a third-party resolver. \
             Add forward-zone blocks to runbound.conf to suppress this warning."
        );
        for ip_str in ["1.1.1.1", "1.0.0.1"] {
            let ip: IpAddr = ip_str
                .parse()
                .unwrap_or_else(|_| unreachable!("hardcoded Cloudflare IP is valid"));
            resolver_cfg.add_name_server(NameServerConfig::new(
                ip,
                true,
                vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            ));
        }
    }

    let mut opts = ResolverOpts::default();
    opts.recursion_desired = true;
    opts.cache_size = cache_size as u64;
    opts.timeout = Duration::from_secs(3); // hard timeout per upstream query
    opts.attempts = 2; // retry once before SERVFAIL
                       // DNSSEC: controlled by `dnssec-validation` directive (default: off for forwarders).
                       // Enable only when operating as a full recursive resolver with complete RRSIG chains.
                       // Forwarders must leave this off: upstreams strip RRSIGs before forwarding,
                       // causing spurious SERVFAIL for every signed domain (gmail.com, google.com…).
    opts.validate = cfg.dnssec_validation;
    opts.use_hosts_file = ResolveHosts::Never; // don't leak host file data

    TokioResolver::builder_with_config(resolver_cfg, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| anyhow::anyhow!("resolver build: {e}"))
}

// ============================================================
// Memory pressure guard
// ============================================================

// Check memory every 30 s. On Linux /proc/meminfo is a cheap kernel read.
const MEM_CHECK_SECS: u64 = 30;
// Scale-up cooldown: do not increase cache more often than every 5 minutes.
const MEM_SCALEUP_COOLDOWN: u64 = 300;
// Halving cooldown: do not halve more often than once every 5 minutes.
const CACHE_HALVE_COOLDOWN: Duration = Duration::from_secs(300);
// Memory pressure thresholds (used ratio = 1 - MemAvailable/MemTotal):
const MEM_LOW_WATERMARK: f64 = 0.60; // below → scale up if cache was reduced
const MEM_MOD_WATERMARK: f64 = 0.70; // [0.70, 0.80) → halve cache
const MEM_HIGH_WATERMARK: f64 = 0.80; // ≥ 0.80 → recalc + flush rate limiter

/// Read the cgroup v2 hard memory limit in bytes.
/// Returns None when the limit is "max" (unrestricted) or the file is absent.
fn cgroup_memory_max_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    let s = s.trim();
    if s == "max" {
        return None;
    }
    s.parse().ok()
}

/// Read the cgroup v2 current memory usage in bytes.
fn cgroup_memory_current_bytes() -> Option<u64> {
    std::fs::read_to_string("/sys/fs/cgroup/memory.current")
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
    ((avail_kb * 1024 / 10 / 512) as usize).clamp(512, 65536)
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
/// Cache changes take effect by rebuilding the hickory resolver and atomically
/// swapping it via ArcSwap. In-flight queries keep their Arc until completion.
pub async fn memory_guard_loop(
    rate_limiter: Arc<RateLimiter>,
    resolver: Arc<ArcSwap<TokioResolver>>,
    cfg: Arc<UnboundConfig>,
    stats: Arc<Stats>,
    initial_cache_size: usize,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(MEM_CHECK_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut current_cache_size = initial_cache_size;
    let mut last_scale_up = Instant::now()
        .checked_sub(Duration::from_secs(MEM_SCALEUP_COOLDOWN))
        .unwrap_or_else(Instant::now);

    // Halving guards
    let mut last_halved: Instant = Instant::now()
        .checked_sub(CACHE_HALVE_COOLDOWN)
        .unwrap_or_else(Instant::now);
    // used_ratio captured just before the last halving; cleared after one check cycle.
    let mut pct_before_last_halve: Option<f64> = None;
    // Set permanently when halving is proven to have no measurable effect on RSS.
    let mut halving_disabled = false;

    loop {
        interval.tick().await;

        // spawn_blocking: read_meminfo calls std::fs::read_to_string("/proc/meminfo")
        // which is blocking I/O — must not run on the async thread pool.
        let Some((avail_kb, total_kb)) = tokio::task::spawn_blocking(read_meminfo)
            .await
            .ok()
            .flatten()
        else {
            continue;
        };
        let used_ratio = 1.0 - (avail_kb as f64 / total_kb as f64);

        // No-effect detection: check whether the previous halving reduced pressure.
        if let Some(pct_before) = pct_before_last_halve.take() {
            if used_ratio >= pct_before - 0.05 {
                halving_disabled = true;
                warn!(
                    pct_before = format!("{:.1}%", pct_before * 100.0),
                    pct_after = format!("{:.1}%", used_ratio * 100.0),
                    "cache halving has no effect on memory pressure \
                     (pct before={:.1}% after={:.1}%) — cache floor reached, \
                     consider increasing MemoryMax in the service file or reducing other workloads",
                    pct_before * 100.0,
                    used_ratio * 100.0,
                );
            }
        }

        if used_ratio >= MEM_HIGH_WATERMARK {
            // High pressure — recalc from current RAM state, flush rate limiter.
            let new_size = cache_size_from_meminfo();
            match build_resolver(&cfg, new_size) {
                Ok(new_res) => {
                    resolver.store(Arc::new(new_res));
                    stats.reset_cache();
                    let freed = rate_limiter.clear();
                    warn!(
                        used_pct = format!("{:.1}%", used_ratio * 100.0),
                        cache_from = current_cache_size,
                        cache_to = new_size,
                        freed_buckets = freed,
                        "memory pressure high — cache flushed, resized, rate limiter cleared"
                    );
                    current_cache_size = new_size;
                }
                Err(e) => warn!(%e, "memory guard: resolver rebuild failed (high pressure)"),
            }
        } else if used_ratio >= MEM_MOD_WATERMARK {
            // Moderate pressure — halve cache, floor at cache_min_entries.
            let min = cfg.cache_min_entries;
            if halving_disabled {
                // no-op: halving proven ineffective, avoid log spam
            } else if current_cache_size <= min {
                warn!(
                    cache_size = current_cache_size,
                    cache_min = min,
                    used_pct = format!("{:.1}%", used_ratio * 100.0),
                    "cache at minimum size ({}) — memory pressure ignored",
                    min,
                );
            } else if last_halved.elapsed() < CACHE_HALVE_COOLDOWN {
                // cooldown active — skip this cycle silently
            } else {
                let new_size = (current_cache_size / 2).max(min);
                match build_resolver(&cfg, new_size) {
                    Ok(new_res) => {
                        resolver.store(Arc::new(new_res));
                        stats.reset_cache();
                        warn!(
                            used_pct = format!("{:.1}%", used_ratio * 100.0),
                            cache_from = current_cache_size,
                            cache_to = new_size,
                            "memory pressure — cache halved"
                        );
                        current_cache_size = new_size;
                        last_halved = Instant::now();
                        pct_before_last_halve = Some(used_ratio);
                    }
                    Err(e) => {
                        warn!(%e, "memory guard: resolver rebuild failed (moderate pressure)")
                    }
                }
            }
        } else if used_ratio < MEM_LOW_WATERMARK {
            // Memory freed — scale up toward optimal if cooldown elapsed.
            let optimal = cache_size_from_meminfo();
            let elapsed = last_scale_up.elapsed();
            if optimal > current_cache_size && elapsed >= Duration::from_secs(MEM_SCALEUP_COOLDOWN)
            {
                match build_resolver(&cfg, optimal) {
                    Ok(new_res) => {
                        resolver.store(Arc::new(new_res));
                        stats.reset_cache();
                        info!(
                            used_pct = format!("{:.1}%", used_ratio * 100.0),
                            cache_from = current_cache_size,
                            cache_to = optimal,
                            "memory pressure resolved — cache scaled up"
                        );
                        current_cache_size = optimal;
                        last_scale_up = Instant::now();
                    }
                    Err(e) => warn!(%e, "memory guard: resolver rebuild failed (scale up)"),
                }
            }
        }
        // 60–70 %: stable band — no action.
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
fn bind_reuseport_udp(addr: &str) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("parse addr {addr}: {e}"))?;
    let domain = if sock_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| anyhow::anyhow!("socket new: {e}"))?;
    socket
        .set_reuse_port(true)
        .map_err(|e| anyhow::anyhow!("SO_REUSEPORT: {e}"))?;
    socket
        .bind(&sock_addr.into())
        .map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("nonblocking: {e}"))?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(|e| anyhow::anyhow!("tokio from_std: {e}"))
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
        if let Some(c) = self.counts.get(&ip) {
            let prev = c.fetch_sub(1, Ordering::Relaxed);
            if prev == 1 {
                // Count just reached 0 — evict the entry so the map does not
                // grow unbounded when many distinct source IPs connect over time.
                // Re-insertion is safe: a concurrent increment will use or_insert_with.
                self.counts
                    .remove_if(&ip, |_, v| v.load(Ordering::Relaxed) == 0);
                self.last_warn.remove(&ip);
            }
        }
    }
}

/// Accept-with-limit loop for a public-facing TCP listener.
/// Connections within the per-IP cap are relayed to `relay_addr` (a loopback
/// listener owned by hickory-server) via bidirectional byte copy.
///
/// Trade-off: hickory sees 127.0.0.1 as the source for all relayed TCP
/// connections, so the DNS per-IP rate limiter uses a shared loopback bucket
/// for TCP clients. Acceptable because TCP DNS traffic is inherently low-volume
/// (large responses, DNSSEC chains). The TCP connection cap enforced here
/// prevents the primary DoS vector (FD exhaustion via many idle connections).
async fn run_tcp_with_limit(
    public_tcp: TcpListener,
    relay_addr: SocketAddr,
    tracker: Arc<TcpConnTracker>,
    conn_timeout: Duration,
) {
    loop {
        let (mut client, peer) = match public_tcp.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(err=%e, "TCP accept error");
                continue;
            }
        };
        // FIX 2 (VUL-NEW-03): check loopback BEFORE normalize so that ::1
        // is not collapsed to :: (an unrelated /48 prefix) by normalize_tcp_ip.
        let src_ip = if peer.ip().is_loopback() {
            peer.ip()
        } else {
            normalize_tcp_ip(peer.ip())
        };
        if !tracker.try_acquire(src_ip) {
            // Over limit: drop immediately (TcpStream closed on drop → TCP FIN/RST)
            continue;
        }
        let tracker2 = Arc::clone(&tracker);
        tokio::spawn(async move {
            let r = tokio::time::timeout(conn_timeout, async {
                let mut relay = TcpStream::connect(relay_addr).await?;
                tokio::io::copy_bidirectional(&mut client, &mut relay).await?;
                Ok::<_, std::io::Error>(())
            })
            .await;
            if let Ok(Err(e)) = r {
                debug!(err=%e, %src_ip, "TCP relay error");
            }
            tracker2.release(src_ip);
        });
    }
}

#[allow(clippy::too_many_arguments)]
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
) -> anyhow::Result<()> {
    let tls_cfg = &cfg.tls;
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

    // Spawn memory pressure guard — monitors /proc/meminfo every 30 s and
    // adjusts the DNS cache size and flushes the rate limiter under pressure.
    {
        let rl = Arc::clone(&rate_limiter);
        let res = Arc::clone(&resolver);
        let cfg_arc = Arc::new(cfg.clone());
        let stats_mg = Arc::clone(&stats);
        tokio::spawn(async move {
            memory_guard_loop(rl, res, cfg_arc, stats_mg, initial_cache_size).await
        });
    }

    if acl.is_empty() {
        info!("access-control: no rules — all clients allowed (add access-control directives to restrict)");
    } else {
        info!(rules = acl.len(), "access-control: ACL loaded");
    }

    let cache_max_ttl = cfg.cache_max_ttl.unwrap_or(86400);
    info!(cache_max_ttl, "TTL cap configured");

    let private_addrs = Arc::new(PrivateAddressSet::from_config(&cfg.private_addresses));
    if !private_addrs.is_empty() {
        info!(
            count = cfg.private_addresses.len(),
            "private-address: DNS rebinding protection active"
        );
    }

    // Level 1 (#77): warm up DoT connections before accepting queries.
    let dot_count = upstreams
        .read()
        .map(|u| u.iter().filter(|s| s.protocol == "dot").count())
        .unwrap_or(0);
    warm_up_dot_connections(&resolver, dot_count).await;

    // Level 3 (#77): spawn keepalive task.
    {
        let res_ka = Arc::clone(&resolver);
        let ups_ka = upstreams.clone();
        let stats_ka = Arc::clone(&stats);
        let dnssec = cfg.dnssec_validation;
        tokio::spawn(dot_keepalive_loop(res_ka, ups_ka, stats_ka, dnssec));
    }

    let fallback_active = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // #94: resolv.conf fallback recovery — check every 30s whether a primary upstream
    // has recovered so the temporary fallback entries can be removed.
    if cfg.resolv_fallback {
        let ups_r = Arc::clone(&upstreams);
        let res_r = Arc::clone(&resolver);
        let fa_r = Arc::clone(&fallback_active);
        let dnssec = cfg.dnssec_validation;
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

    let handler = RunboundHandler::new(
        Arc::clone(&zones),
        Arc::clone(&resolver),
        rate_limiter,
        acl,
        private_addrs,
        cache_max_ttl,
        stats,
        log_buffer,
        cfg.dnssec_validation,
        cfg.dnssec_log_bogus,
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
    );
    let mut server = Server::new(handler);

    let ncpus = crate::cpu::physical_cores().len().max(1);

    let port = cfg.port;
    let interfaces: Vec<String> = if cfg.interfaces.is_empty() {
        vec!["0.0.0.0".into()]
    } else {
        cfg.interfaces.clone()
    };

    // FIX 6.2: shared per-IP TCP connection tracker (across all interfaces)
    let tcp_tracker = TcpConnTracker::new();
    const TCP_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

    for iface in &interfaces {
        let udp_addr = format!("{}:{}", iface, port);
        let tcp_addr = format!("{}:{}", iface, port);

        // Bind one UDP socket per CPU with SO_REUSEPORT.
        // The kernel distributes packets across sockets via a flow hash,
        // giving near-linear QPS scaling with core count.
        #[cfg(unix)]
        for i in 0..ncpus {
            let udp = bind_reuseport_udp(&udp_addr)
                .map_err(|e| anyhow::anyhow!("UDP SO_REUSEPORT socket {i}: {e}"))?;
            server.register_socket(udp);
        }
        #[cfg(not(unix))]
        {
            let udp = UdpSocket::bind(&udp_addr)
                .await
                .map_err(|e| anyhow::anyhow!("UDP bind {udp_addr}: {e}"))?;
            server.register_socket(udp);
        }
        info!(addr=%udp_addr, sockets=ncpus, "DNS UDP listening (SO_REUSEPORT)");

        // FIX 6.2: public-facing TCP listener feeds our per-IP accept gate.
        // hickory-server gets a loopback relay listener so its internal accept
        // loop never sees connections from over-limit source IPs.
        let public_tcp = TcpListener::bind(&tcp_addr)
            .await
            .map_err(|e| anyhow::anyhow!("TCP bind {tcp_addr}: {e}"))?;
        // Relay listener: loopback, ephemeral port — hickory owns this listener.
        let relay_tcp = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| anyhow::anyhow!("TCP relay bind: {e}"))?;
        let relay_addr = relay_tcp
            .local_addr()
            .map_err(|e| anyhow::anyhow!("TCP relay local_addr: {e}"))?;
        info!(addr=%tcp_addr, "DNS TCP listening (per-IP cap: {} conns)", TCP_CONN_PER_IP_MAX);
        // 30s idle timeout — enough for slow DNSSEC responses while limiting FD exhaustion.
        // 4096-byte response buffer fits any DNS response (max UDP payload is 65535 bytes but
        // typical responses are well under 4 KiB; EDNS0 handles larger).
        server.register_listener(relay_tcp, TCP_SESSION_TIMEOUT, 4096);

        let tracker2 = Arc::clone(&tcp_tracker);
        tokio::spawn(run_tcp_with_limit(
            public_tcp,
            relay_addr,
            tracker2,
            TCP_SESSION_TIMEOUT,
        ));
    }

    // ── DoT / DoH / DoQ (RFC 7858 / 8484 / 9250) ───────────────────────────
    if let Some((certs, key)) = load_tls_materials(tls_cfg) {
        let dot_port = tls_cfg.dot_port.unwrap_or(853);
        let doh_port = tls_cfg.doh_port.unwrap_or(443);
        let doq_port = tls_cfg.doq_port.unwrap_or(853);
        let hostname = tls_cfg
            .hostname
            .clone()
            .unwrap_or_else(|| "runbound.local".to_string());

        // Build one ServerConfig per protocol (each needs its own ALPN token).
        // PrivateKeyDer does not implement Clone; use clone_key() for each copy.
        let dot_config = build_tls_config(
            certs.clone(),
            key.clone_key(),
            b"dot",
            false,
            tls_cfg.dot_client_auth_ca.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!("DoT TLS config: {e}"))?;

        let doh_config = build_tls_config(certs.clone(), key.clone_key(), b"h2", false, None)
            .map_err(|e| anyhow::anyhow!("DoH TLS config: {e}"))?;

        // DoQ requires TLS 1.3 exclusively (Quinn constraint).
        let doq_config = build_tls_config(certs, key, b"doq", true, None)
            .map_err(|e| anyhow::anyhow!("DoQ TLS config: {e}"))?;

        for iface in &interfaces {
            // DNS-over-TLS (port 853 TCP)
            // FIX 1 (VUL-NEW-01): public listener → run_tcp_with_limit → loopback relay → hickory.
            // Same TcpConnTracker as DNS/TCP; DoT now shares the per-IP cap of 20 connections.
            let dot_addr = format!("{}:{}", iface, dot_port);
            match TcpListener::bind(&dot_addr).await {
                Ok(public_dot) => {
                    let relay_dot = TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| anyhow::anyhow!("DoT relay bind: {e}"))?;
                    let relay_dot_addr = relay_dot
                        .local_addr()
                        .map_err(|e| anyhow::anyhow!("DoT relay local_addr: {e}"))?;
                    info!(addr=%dot_addr, mtls=tls_cfg.dot_client_auth_ca.is_some(), "DoT (DNS-over-TLS) listening — RFC 7858");
                    server
                        .register_tls_listener_with_tls_config(
                            relay_dot,
                            Duration::from_secs(30),
                            Arc::clone(&dot_config),
                        )
                        .map_err(|e| anyhow::anyhow!("DoT register: {e}"))?;
                    let tracker_dot = Arc::clone(&tcp_tracker);
                    tokio::spawn(run_tcp_with_limit(
                        public_dot,
                        relay_dot_addr,
                        tracker_dot,
                        TCP_SESSION_TIMEOUT,
                    ));
                }
                Err(e) => warn!(addr=%dot_addr, err=%e, "DoT bind failed — skipping"),
            }

            // DNS-over-HTTPS (port 443 TCP)
            // FIX 1 (VUL-NEW-01): same relay pattern as DoT above.
            let doh_addr = format!("{}:{}", iface, doh_port);
            match TcpListener::bind(&doh_addr).await {
                Ok(public_doh) => {
                    let relay_doh = TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| anyhow::anyhow!("DoH relay bind: {e}"))?;
                    let relay_doh_addr = relay_doh
                        .local_addr()
                        .map_err(|e| anyhow::anyhow!("DoH relay local_addr: {e}"))?;
                    info!(addr=%doh_addr, "DoH (DNS-over-HTTPS) listening — RFC 8484");
                    server
                        .register_https_listener_with_tls_config(
                            relay_doh,
                            Duration::from_secs(30),
                            Arc::clone(&doh_config),
                            Some(hostname.clone()),
                            "/dns-query".to_string(),
                        )
                        .map_err(|e| anyhow::anyhow!("DoH register: {e}"))?;
                    let tracker_doh = Arc::clone(&tcp_tracker);
                    tokio::spawn(run_tcp_with_limit(
                        public_doh,
                        relay_doh_addr,
                        tracker_doh,
                        TCP_SESSION_TIMEOUT,
                    ));
                }
                Err(e) => warn!(addr=%doh_addr, err=%e, "DoH bind failed — skipping"),
            }

            // DNS-over-QUIC (port 853 UDP)
            let doq_addr = format!("{}:{}", iface, doq_port);
            match UdpSocket::bind(&doq_addr).await {
                Ok(udp) => {
                    info!(addr=%doq_addr, "DoQ (DNS-over-QUIC) listening — RFC 9250");
                    server
                        .register_quic_listener_and_tls_config(
                            udp,
                            Duration::from_secs(30),
                            Arc::clone(&doq_config),
                        )
                        .map_err(|e| anyhow::anyhow!("DoQ register: {e}"))?;
                }
                Err(e) => warn!(addr=%doq_addr, err=%e, "DoQ bind failed — skipping"),
            }
        }
    } else {
        info!("TLS not configured — DoT/DoH/DoQ disabled (add tls-service-pem + tls-service-key to enable)");
    }

    info!("Runbound ready — RFC 1034/1035/2782/4033/6891/7858/8484/9250");
    server
        .block_until_done()
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))
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
}
