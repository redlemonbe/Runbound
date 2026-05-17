// Runbound DNS server — drop-in for Unbound.
//
// Architecture:
//   1. Access-control list check (per source IP, from unbound.conf)
//   2. Rate limiting (per source IP token bucket)
//   3. Check local zones (local-data, blacklist, feeds) in memory → instant
//   4. Otherwise → recursive resolver (hickory-resolver)
//
// UDP + TCP on the configured port (default 53).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use hickory_proto::error::ProtoErrorKind;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    TokioAsyncResolver,
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture},
};
use arc_swap::ArcSwap;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::parser::TlsConfig;

use crate::config::parser::UnboundConfig;
use crate::logbuffer::{LogAction, LogEntry, SharedLogBuffer};
use crate::stats::{Stats, CACHE_HIT_THRESHOLD_US};
use super::acl::{Acl, AclAction, PrivateAddressSet};
use super::local::{LocalZoneSet, ZoneAction};
use super::ratelimit::RateLimiter;

// ── Concurrency cap — prevents OOM under flood ─────────────────────────────
//
// hickory-server spawns one tokio task per incoming DNS request with no
// backpressure. Under a flood (DDoS or perf test) this exhausts RAM.
// A non-blocking try_acquire returns REFUSED instantly without allocating
// any additional memory, so the bound is hard even at line rate.
const MAX_INFLIGHT_REQUESTS: usize = 4_096;

const RATE_LIMIT_QPS_DEFAULT: u64 = 200;

// ============================================================
// Handler
// ============================================================

pub struct RunboundHandler {
    pub zones:        Arc<ArcSwap<LocalZoneSet>>,
    resolver:         Arc<ArcSwap<TokioAsyncResolver>>,
    rate_limiter:     Arc<RateLimiter>,
    inflight:         Arc<Semaphore>,
    acl:              Arc<Acl>,
    private_addrs:    Arc<PrivateAddressSet>,
    cache_max_ttl:    u32,
    pub stats:        Arc<Stats>,
    pub log_buffer:   SharedLogBuffer,
    /// DNSSEC tracking enabled — mirrors `dnssec-validation: yes` in config.
    dnssec_enabled:   bool,
    dnssec_log_bogus: bool,
}

impl RunboundHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        zones:            Arc<ArcSwap<LocalZoneSet>>,
        resolver:         Arc<ArcSwap<TokioAsyncResolver>>,
        rate_limiter:     Arc<RateLimiter>,
        acl:              Arc<Acl>,
        private_addrs:    Arc<PrivateAddressSet>,
        cache_max_ttl:    u32,
        stats:            Arc<Stats>,
        log_buffer:       SharedLogBuffer,
        dnssec_enabled:   bool,
        dnssec_log_bogus: bool,
    ) -> Self {
        Self {
            zones, resolver, rate_limiter,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_REQUESTS)),
            acl, private_addrs, cache_max_ttl, stats, log_buffer,
            dnssec_enabled, dnssec_log_bogus,
        }
    }

    /// Record a completed query: latency histogram, log buffer push, tracing log.
    /// Cache metrics (record_forward) and domain counters are updated at call sites.
    #[inline]
    fn record_query(
        &self,
        client: IpAddr,
        qname:  &hickory_proto::rr::LowerName,
        qtype:  RecordType,
        rcode:  ResponseCode,
        action: LogAction,
        start:  Instant,
    ) {
        let elapsed    = start.elapsed();
        let elapsed_us = elapsed.as_micros() as u64;
        let elapsed_ms = elapsed.as_millis() as u32;

        self.stats.record_latency_us(elapsed_us);
        if action == LogAction::Local {
            self.stats.inc_local_hits();
        }

        if let Ok(mut buf) = self.log_buffer.lock() {
            buf.push(LogEntry::new(
                &qname.to_string(), &client, u16::from(qtype), action, elapsed_ms,
            ));
        }

        info!(
            client = %client,
            name   = %qname,
            qtype  = %qtype,
            rcode  = %rcode,
            action = action.as_str(),
            ms     = elapsed_ms,
            "query"
        );
    }
}

#[async_trait]
impl RequestHandler for RunboundHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let start     = Instant::now();
        let qname     = request.query().name();
        let qtype     = request.query().query_type();
        let client_ip = request.src().ip();

        self.stats.inc_total();

        // ── 0. Access-control list ──────────────────────────────────────
        match self.acl.check(client_ip) {
            AclAction::Allow  => {}
            AclAction::Deny   => {
                // Silently drop — no response sent
                debug!(%client_ip, %qname, "ACL deny (silent drop)");
                let mut h = Header::response_from_request(request.header());
                h.set_response_code(ResponseCode::Refused);
                let info: ResponseInfo = h.into();
                self.record_query(client_ip, qname, qtype, ResponseCode::Refused, LogAction::Refused, start);
                return info;
            }
            AclAction::Refuse => {
                debug!(%client_ip, %qname, "ACL refuse");
                self.record_query(client_ip, qname, qtype, ResponseCode::Refused, LogAction::Refused, start);
                return send_error(request, response_handle, ResponseCode::Refused).await;
            }
        }

        // ── 1. Rate limiting (per source IP) ───────────────────────────
        if !self.rate_limiter.check(client_ip) {
            warn!(%client_ip, "rate limited");
            self.record_query(client_ip, qname, qtype, ResponseCode::Refused, LogAction::Refused, start);
            return send_error(request, response_handle, ResponseCode::Refused).await;
        }

        // ── 2. Concurrency cap (anti-OOM) ──────────────────────────────
        let _permit = match self.inflight.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                warn!(%client_ip, inflight = MAX_INFLIGHT_REQUESTS, "inflight cap reached — REFUSED");
                self.record_query(client_ip, qname, qtype, ResponseCode::Refused, LogAction::Refused, start);
                return send_error(request, response_handle, ResponseCode::Refused).await;
            }
        };

        // ── 3a. Block CHAOS class queries (version.bind, hostname.bind) ───
        // CHAOS class exposes DNS server identity even when hide-identity/
        // hide-version are set in unbound.conf. Return REFUSED for all CH queries.
        if request.query().query_class() == DNSClass::CH {
            debug!(%client_ip, %qname, "CHAOS class query blocked");
            self.stats.inc_refused();
            self.record_query(client_ip, qname, qtype, ResponseCode::Refused, LogAction::Refused, start);
            return send_error(request, response_handle, ResponseCode::Refused).await;
        }

        // ── 3b. Block ANY queries (RFC 8482 — amplification vector) ────
        if qtype == RecordType::ANY {
            debug!(%client_ip, "ANY query blocked (RFC 8482)");
            self.record_query(client_ip, qname, qtype, ResponseCode::NotImp, LogAction::Refused, start);
            return send_error(request, response_handle, ResponseCode::NotImp).await;
        }

        debug!(%client_ip, name=%qname, type=%qtype, "DNS query");

        // ── 4. Local zones ──────────────────────────────────────────────
        let zones_snap = self.zones.load();
        let zone_action = zones_snap.find(qname);

        match zone_action {
            Some(ZoneAction::Refuse) => {
                debug!(%qname, "local-zone REFUSED");
                self.stats.inc_blocked(); self.stats.inc_refused();
                self.record_query(client_ip, qname, qtype, ResponseCode::Refused, LogAction::Blocked, start);
                return send_error(request, response_handle, ResponseCode::Refused).await;
            }
            Some(ZoneAction::NxDomain) => {
                debug!(%qname, "local-zone NXDOMAIN");
                self.stats.inc_blocked(); self.stats.inc_nxdomain();
                self.record_query(client_ip, qname, qtype, ResponseCode::NXDomain, LogAction::Blocked, start);
                return send_error(request, response_handle, ResponseCode::NXDomain).await;
            }
            Some(ZoneAction::Static) | Some(ZoneAction::Redirect) => {
                let records = zones_snap.local_records(qname, qtype);

                if !records.is_empty() {
                    debug!(%qname, count = records.len(), "local-data answer");
                    let mut header = Header::response_from_request(request.header());
                    header.set_authoritative(true);
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.build(
                        header,
                        records,
                        std::iter::empty(),
                        std::iter::empty(),
                        std::iter::empty(),
                    );
                    self.record_query(client_ip, qname, qtype, ResponseCode::NoError, LogAction::Local, start);
                    return response_handle.send_response(response).await
                        .unwrap_or_else(|e| { error!("send: {e}"); header.into() });
                }

                // CNAME chain following (RFC 1034 §3.6.2):
                // If the name exists but has no records of the requested type,
                // check for a CNAME and follow the chain within local zones.
                // A query for alias.local A → CNAME tardis.local → A 192.168.1.1
                // should return both the CNAME and the A record in one answer.
                if qtype != RecordType::CNAME {
                    let chain = follow_local_cname(&zones_snap, qname, qtype);
                    if !chain.is_empty() {
                        let mut header = Header::response_from_request(request.header());
                        header.set_authoritative(true);
                        let builder = MessageResponseBuilder::from_message_request(request);
                        let response = builder.build(
                            header,
                            chain.iter(),
                            std::iter::empty(),
                            std::iter::empty(),
                            std::iter::empty(),
                        );
                        self.record_query(client_ip, qname, qtype, ResponseCode::NoError, LogAction::Local, start);
                        return response_handle.send_response(response).await
                            .unwrap_or_else(|e| { error!("send: {e}"); header.into() });
                    }
                }

                // RFC 1035 §3.7 / RFC 2308: NODATA vs NXDOMAIN
                if zones_snap.name_has_records(qname) {
                    debug!(%qname, %qtype, "local-zone NODATA");
                    let mut header = Header::response_from_request(request.header());
                    header.set_authoritative(true);
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.build(
                        header,
                        std::iter::empty(),
                        std::iter::empty(),
                        std::iter::empty(),
                        std::iter::empty(),
                    );
                    self.record_query(client_ip, qname, qtype, ResponseCode::NoError, LogAction::Local, start);
                    return response_handle.send_response(response).await
                        .unwrap_or_else(|e| { error!("send: {e}"); header.into() });
                }
                debug!(%qname, "local-zone NXDOMAIN (name not found)");
                self.record_query(client_ip, qname, qtype, ResponseCode::NXDomain, LogAction::Nxdomain, start);
                return send_error(request, response_handle, ResponseCode::NXDomain).await;
            }
            None => {}
        }
        drop(zones_snap);

        // ── 5. Recursive resolution ─────────────────────────────────────
        match self.resolver.load_full().lookup(Name::from(qname), qtype).await {
            Ok(lookup) => {
                // DNS rebinding protection: SERVFAIL if any A/AAAA record falls
                // within a configured private-address range (Unbound compatible).
                if !self.private_addrs.is_empty() {
                    for rec in lookup.records() {
                        let private_ip = match rec.data() {
                            Some(RData::A(a))    => Some(IpAddr::V4((*a).into())),
                            Some(RData::AAAA(a)) => Some(IpAddr::V6((*a).into())),
                            _ => None,
                        };
                        if let Some(ip) = private_ip {
                            if self.private_addrs.contains(ip) {
                                warn!(%qname, %ip, "private-address block → SERVFAIL");
                                self.record_query(client_ip, qname, qtype, ResponseCode::ServFail, LogAction::Servfail, start);
                                return send_error(request, response_handle, ResponseCode::ServFail).await;
                            }
                        }
                    }
                }
                debug!(%qname, %qtype, count = lookup.records().len(), "resolved");
                let mut header = Header::response_from_request(request.header());
                header.set_recursion_available(true);
                let builder = MessageResponseBuilder::from_message_request(request);
                let ttl_cap = self.cache_max_ttl;
                let records: Vec<_> = lookup.records().iter().map(|r| {
                    let mut r = r.clone();
                    if r.ttl() > ttl_cap { r.set_ttl(ttl_cap); }
                    r
                }).collect();
                let response = builder.build(
                    header,
                    records.iter(),
                    std::iter::empty(),
                    std::iter::empty(),
                    std::iter::empty(),
                );
                self.stats.inc_forwarded();
                let fwd_us = start.elapsed().as_micros() as u64;
                self.stats.record_forward(fwd_us);
                // DNSSEC: classify Secure vs Insecure when validation is enabled.
                // RRSIG records in the answer indicate the response is signed (Secure).
                // No RRSIG = delegation proved unsigned by parent NSEC/NSEC3 (Insecure).
                if self.dnssec_enabled {
                    let has_rrsig = records.iter()
                        .any(|r| r.record_type() == RecordType::RRSIG);
                    if has_rrsig {
                        self.stats.inc_dnssec_secure();
                    } else {
                        self.stats.inc_dnssec_insecure();
                    }
                }
                let fwd_action = if fwd_us < CACHE_HIT_THRESHOLD_US {
                    LogAction::Cached
                } else {
                    LogAction::Forwarded
                };
                self.record_query(client_ip, qname, qtype, ResponseCode::NoError, fwd_action, start);
                response_handle.send_response(response).await
                    .unwrap_or_else(|e| { error!("send: {e}"); header.into() })
            }
            Err(e) => {
                // Detect DNSSEC bogus: ProtoErrorKind::RrsigsNotPresent means hickory
                // found no RRSIG for a domain it expected to be signed → bogus signature chain.
                let is_dnssec_bogus = self.dnssec_enabled
                    && matches!(e.kind(), ResolveErrorKind::Proto(pe)
                        if matches!(pe.kind(), ProtoErrorKind::RrsigsNotPresent { .. }));

                if is_dnssec_bogus {
                    self.stats.inc_dnssec_bogus();
                    if self.dnssec_log_bogus {
                        warn!(%qname, "DNSSEC bogus — SERVFAIL (missing/invalid RRSIG)");
                    }
                }

                let rcode = match e.kind() {
                    ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                        debug!(%qname, ?response_code, "no records from resolver");
                        *response_code
                    }
                    _ => {
                        if !is_dnssec_bogus {
                            warn!(%qname, err=%e, "resolver error → SERVFAIL");
                        }
                        ResponseCode::ServFail
                    }
                };
                let err_action = match rcode {
                    ResponseCode::NXDomain => { self.stats.inc_nxdomain(); LogAction::Nxdomain }
                    ResponseCode::ServFail => { self.stats.inc_servfail(); LogAction::Servfail }
                    ResponseCode::Refused  => { self.stats.inc_refused();  LogAction::Refused  }
                    _                      => LogAction::Servfail,
                };
                self.record_query(client_ip, qname, qtype, rcode, err_action, start);
                send_error(request, response_handle, rcode).await
            }
        }
    }
}

// ============================================================
// Helpers
// ============================================================

/// Follow CNAME records within local zones, up to 8 hops (prevents loops).
/// Returns a Vec<Record> containing the CNAME chain + final target records,
/// or an empty Vec if there is no CNAME or the chain leads outside local zones.
fn follow_local_cname(
    zones: &super::local::LocalZoneSet,
    start: &LowerName,
    qtype: RecordType,
) -> Vec<Record> {
    let mut chain: Vec<Record> = Vec::new();
    let mut current = start.clone();

    for _ in 0..8 {
        let cnames = zones.local_records(&current, RecordType::CNAME);
        if cnames.is_empty() { break; }
        let cname_rec = (*cnames[0]).clone();
        let next = match cname_rec.data() {
            Some(RData::CNAME(c)) => LowerName::from(c.0.clone()),
            _ => break,
        };
        chain.push(cname_rec);
        let resolved: Vec<Record> = zones.local_records(&next, qtype)
            .into_iter().map(|r| (*r).clone()).collect();
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

/// Send an error response, mirroring the request's EDNS0 OPT record if present.
/// RFC 6891 §7: "If a query included an OPT record, the response MUST include one."
#[inline(always)]
async fn send_error<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    rcode: ResponseCode,
) -> ResponseInfo {
    let mut header = Header::response_from_request(request.header());
    header.set_response_code(rcode);
    let builder  = MessageResponseBuilder::from_message_request(request);
    // `build()` mirrors the request's EDNS0 OPT record into the response,
    // satisfying RFC 6891 §7.  `error_msg()` does NOT include the OPT record.
    let response = builder.build(
        header,
        std::iter::empty::<&hickory_proto::rr::Record>(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );
    response_handle.send_response(response).await
        .unwrap_or_else(|e| {
            error!("send: {e}");
            header.into()
        })
}

/// Build resolver from forward-zones in unbound.conf, fallback to system resolvers.
fn build_resolver(cfg: &UnboundConfig) -> anyhow::Result<TokioAsyncResolver> {
    let mut resolver_cfg = ResolverConfig::new();

    for fwd in &cfg.forward_zones {
        for addr_str in &fwd.addrs {
            // Supports Unbound addr@port syntax: "1.1.1.1@853"
            let (ip_str, port) = if let Some(at) = addr_str.find('@') {
                let p: u16 = addr_str[at + 1..].parse().unwrap_or(if fwd.tls { 853 } else { 53 });
                (&addr_str[..at], p)
            } else {
                (addr_str.as_str(), if fwd.tls { 853 } else { 53 })
            };
            if let Ok(ip) = ip_str.parse() {
                let addr = std::net::SocketAddr::new(ip, port);
                if fwd.tls {
                    // DNS-over-TLS: encrypted channel, single TCP connection per server.
                    resolver_cfg.add_name_server(NameServerConfig::new(addr, Protocol::Tls));
                } else {
                    // UDP for normal queries (fast path)
                    resolver_cfg.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
                    // TCP mandatory for DNSSEC: DNSKEY RRsets exceed UDP MTU and
                    // arrive truncated (TC=1). Without TCP, the DNSSEC chain cannot
                    // be completed and every signed domain returns SERVFAIL.
                    resolver_cfg.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
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
        resolver_cfg = ResolverConfig::cloudflare();
    }

    let mut opts = ResolverOpts::default();
    opts.recursion_desired = true;
    opts.cache_size = 8192; // doubled from 4096 — better hit rate under load
    opts.timeout = Duration::from_secs(3);      // hard timeout per upstream query
    opts.attempts = 2;                           // retry once before SERVFAIL
    // DNSSEC: controlled by `dnssec-validation` directive (default: off for forwarders).
    // Enable only when operating as a full recursive resolver with complete RRSIG chains.
    // Forwarders must leave this off: upstreams strip RRSIGs before forwarding,
    // causing spurious SERVFAIL for every signed domain (gmail.com, google.com…).
    opts.validate = cfg.dnssec_validation;
    opts.use_hosts_file = false;                 // don't leak host file data

    Ok(TokioAsyncResolver::tokio(resolver_cfg, opts))
}

// ============================================================
// Memory pressure guard
// ============================================================

// Check memory every 30 s. On Linux /proc/meminfo is a cheap kernel read.
const MEM_CHECK_SECS: u64 = 30;
// Trigger purge when system memory usage ≥ 80 %.
// Using 80 % rather than 90 % gives a safe margin before the OOM killer fires.
const MEM_PRESSURE_THRESHOLD: f64 = 0.80;
// After purge, log whether we landed below 50 % (target) or are still high.
const MEM_TARGET_THRESHOLD: f64 = 0.50;

/// Read /proc/meminfo and return (available_kb, total_kb).
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
        if total > 0 && available > 0 { break; }
    }
    if total > 0 { Some((available, total)) } else { None }
}

/// Background task: monitors system memory and purges DNS caches when needed.
///
/// Two caches are flushed:
///   1. Rate-limiter DashMap — freed O(n_unique_IPs) memory, rebuilds naturally.
///   2. hickory-resolver internal cache — flushed by rebuilding the resolver and
///      atomically swapping it via ArcSwap. In-flight queries keep the old Arc
///      until they finish; new queries use the fresh resolver with empty cache.
pub async fn memory_guard_loop(
    rate_limiter: Arc<RateLimiter>,
    resolver:     Arc<ArcSwap<TokioAsyncResolver>>,
    cfg:          Arc<UnboundConfig>,
    stats:        Arc<Stats>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(MEM_CHECK_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let Some((avail_kb, total_kb)) = read_meminfo() else { continue };
        let used_ratio = 1.0 - (avail_kb as f64 / total_kb as f64);

        if used_ratio < MEM_PRESSURE_THRESHOLD { continue; }

        warn!(
            used_pct  = format!("{:.1}%", used_ratio * 100.0),
            avail_mb  = avail_kb / 1024,
            total_mb  = total_kb / 1024,
            "Memory pressure — purging DNS caches"
        );

        // 1. Clear rate-limiter (all token buckets — they rebuild on next query)
        let freed_buckets = rate_limiter.clear();

        // 2. Rebuild resolver — this discards hickory's entire in-memory DNS cache.
        //    Queries in flight hold their own Arc<TokioAsyncResolver> and finish
        //    normally; new queries get the fresh empty-cache resolver.
        match build_resolver(&cfg) {
            Ok(new_res) => {
                resolver.store(Arc::new(new_res));
                stats.reset_cache();
                warn!(freed_buckets, "DNS resolver cache flushed and rate limiter cleared");
            }
            Err(e) => {
                warn!(%e, freed_buckets, "Resolver rebuild failed — rate limiter still cleared");
            }
        }

        if let Some((new_avail, _)) = read_meminfo() {
            let new_ratio = 1.0 - (new_avail as f64 / total_kb as f64);
            let status = if new_ratio < MEM_TARGET_THRESHOLD { "below 50% target" } else { "still elevated" };
            warn!(used_pct = format!("{:.1}%", new_ratio * 100.0), status, "Memory after purge");
        }
    }
}

// ============================================================
// Server entry point
// ============================================================

/// Load TLS cert+key from PEM files. Returns None if not configured.
fn load_tls(tls: &TlsConfig) -> Option<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    let cert_path = tls.cert_path.as_deref()?;
    let key_path  = tls.key_path.as_deref()?;

    let cert_pem = std::fs::read(cert_path).ok()?;
    let key_pem  = std::fs::read(key_path).ok()?;

    let certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .ok()?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    // Try PKCS8 first, then RSA
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_slice())
        .ok()
        .and_then(|k| k.into_iter().next().map(rustls::PrivateKey))
        .or_else(|| {
            rustls_pemfile::rsa_private_keys(&mut key_pem.as_slice())
                .ok()
                .and_then(|k| k.into_iter().next().map(rustls::PrivateKey))
        })?;

    if certs.is_empty() { return None; }
    Some((certs, key))
}

// SO_REUSEPORT UDP socket: the kernel distributes incoming packets across
// all sockets bound to the same address:port, one per CPU core. Each socket
// is driven by a separate tokio task on a separate thread, giving true
// multi-core parallelism without any userspace load-balancing overhead.
#[cfg(unix)]
fn bind_reuseport_udp(addr: &str) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock_addr: std::net::SocketAddr = addr.parse()
        .map_err(|e| anyhow::anyhow!("parse addr {addr}: {e}"))?;
    let domain = if sock_addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| anyhow::anyhow!("socket new: {e}"))?;
    socket.set_reuse_port(true)
        .map_err(|e| anyhow::anyhow!("SO_REUSEPORT: {e}"))?;
    socket.bind(&sock_addr.into())
        .map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    socket.set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("nonblocking: {e}"))?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
        .map_err(|e| anyhow::anyhow!("tokio from_std: {e}"))
}

pub async fn run_dns_server(
    cfg:          &UnboundConfig,
    zones:        Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl:          Arc<Acl>,
    stats:        Arc<Stats>,
    log_buffer:   SharedLogBuffer,
) -> anyhow::Result<()> {
    let tls_cfg = &cfg.tls;
    let rps = cfg.rate_limit.unwrap_or(RATE_LIMIT_QPS_DEFAULT);
    info!(rps, burst = rps * 2, "DNS rate limiter configured");

    let resolver = Arc::new(ArcSwap::new(Arc::new(build_resolver(cfg)?)));

    // Spawn memory pressure guard — monitors /proc/meminfo every 30 s and
    // flushes DNS caches (rate limiter + resolver) when usage exceeds 80 %.
    {
        let rl       = Arc::clone(&rate_limiter);
        let res      = Arc::clone(&resolver);
        let cfg_arc  = Arc::new(cfg.clone());
        let stats_mg = Arc::clone(&stats);
        tokio::spawn(async move { memory_guard_loop(rl, res, cfg_arc, stats_mg).await });
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
        info!(count = cfg.private_addresses.len(), "private-address: DNS rebinding protection active");
    }

    let handler = RunboundHandler::new(
        Arc::clone(&zones), resolver, rate_limiter, acl, private_addrs, cache_max_ttl, stats, log_buffer,
        cfg.dnssec_validation, cfg.dnssec_log_bogus,
    );
    let mut server = ServerFuture::new(handler);

    let ncpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);

    let port = cfg.port;
    let interfaces: Vec<String> = if cfg.interfaces.is_empty() {
        vec!["0.0.0.0".into()]
    } else {
        cfg.interfaces.clone()
    };

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
            let udp = UdpSocket::bind(&udp_addr).await
                .map_err(|e| anyhow::anyhow!("UDP bind {udp_addr}: {e}"))?;
            server.register_socket(udp);
        }
        info!(addr=%udp_addr, sockets=ncpus, "DNS UDP listening (SO_REUSEPORT)");

        let tcp = TcpListener::bind(&tcp_addr).await
            .map_err(|e| anyhow::anyhow!("TCP bind {tcp_addr}: {e}"))?;
        info!(addr=%tcp_addr, "DNS TCP listening");
        // 30s idle timeout — enough for slow DNSSEC responses while limiting FD exhaustion
        server.register_listener(tcp, Duration::from_secs(30));
    }

    // ── DoT / DoH / DoQ (RFC 7858 / 8484 / 9250) ───────────────────────────
    if let Some(tls) = load_tls(tls_cfg) {
        let dot_port = tls_cfg.dot_port.unwrap_or(853);
        let doh_port = tls_cfg.doh_port.unwrap_or(443);
        let doq_port = tls_cfg.doq_port.unwrap_or(853);
        let hostname = tls_cfg.hostname.clone()
            .unwrap_or_else(|| "runbound.local".to_string());

        for iface in &interfaces {
            // DNS-over-TLS (port 853 TCP)
            let dot_addr = format!("{}:{}", iface, dot_port);
            match TcpListener::bind(&dot_addr).await {
                Ok(tcp) => {
                    info!(addr=%dot_addr, "DoT (DNS-over-TLS) listening — RFC 7858");
                    server.register_tls_listener(tcp, Duration::from_secs(30), tls.clone())
                        .map_err(|e| anyhow::anyhow!("DoT register: {e}"))?;
                }
                Err(e) => warn!(addr=%dot_addr, err=%e, "DoT bind failed — skipping"),
            }

            // DNS-over-HTTPS (port 443 TCP)
            let doh_addr = format!("{}:{}", iface, doh_port);
            match TcpListener::bind(&doh_addr).await {
                Ok(tcp) => {
                    info!(addr=%doh_addr, "DoH (DNS-over-HTTPS) listening — RFC 8484");
                    server.register_https_listener(tcp, Duration::from_secs(30), tls.clone(), Some(hostname.clone()))
                        .map_err(|e| anyhow::anyhow!("DoH register: {e}"))?;
                }
                Err(e) => warn!(addr=%doh_addr, err=%e, "DoH bind failed — skipping"),
            }

            // DNS-over-QUIC (port 853 UDP)
            let doq_addr = format!("{}:{}", iface, doq_port);
            match UdpSocket::bind(&doq_addr).await {
                Ok(udp) => {
                    info!(addr=%doq_addr, "DoQ (DNS-over-QUIC) listening — RFC 9250");
                    server.register_quic_listener(udp, Duration::from_secs(30), tls.clone(), Some(hostname.clone()))
                        .map_err(|e| anyhow::anyhow!("DoQ register: {e}"))?;
                }
                Err(e) => warn!(addr=%doq_addr, err=%e, "DoQ bind failed — skipping"),
            }
        }
    } else {
        info!("TLS not configured — DoT/DoH/DoQ disabled (add tls-service-pem + tls-service-key to enable)");
    }

    info!("Runbound ready — RFC 1034/1035/2782/4033/6891/7858/8484/9250");
    server.block_until_done().await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))
}
