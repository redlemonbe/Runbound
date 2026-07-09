//! Own DNS upstream forwarder — replaces hickory-resolver's TokioResolver.
//!
//! `ForwardPool` provides:
//! - Per-upstream persistent DoT connections (RFC 7858 TCP framing), pooled
//! - UDP upstream forwarding
//! - Parallel racing: all upstreams queried simultaneously, first definitive wins
//! - Automatic reconnection on failure
//! - Keepalive probes for DoT connections

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::sync::atomic::{AtomicU16, Ordering};
use dashmap::DashMap;
use std::time::{Duration, Instant};
use arc_swap::ArcSwap;
use futures_util::StreamExt;
use crate::dns::wire;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

// ─────────────────────── Timeouts ────────────────────────────────────────────

const DOT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DOT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// TCP fallback query (RFC 1035 §4.2.2) — only used to recover a full RRset after
/// a truncated UDP answer, so it is off the common forward path.
const TCP_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Max idle connections held per DoT upstream
const POOL_CONNS: usize = 4;
/// Discard pooled connections idle longer than this
const POOL_IDLE_TTL: Duration = Duration::from_secs(90);

// ─────────────────────── Public result type ───────────────────────────────────

/// Result of a forward query. Non-`Servfail` variants are "definitive" — in
/// racing mode a definitive result ends the race immediately.
#[derive(Debug)]
pub enum ResolveResult {
    /// NOERROR with one or more answer records
    Answer {
        records: Vec<wire::Record>,
        /// upstream set AD AND arrived over an authenticated (DoT) channel; a
        /// forwarder may then relay AD to a client that asked for it (RFC 6840 §5.7).
        /// False on any cleartext (UDP/TCP) upstream — plaintext AD is spoofable.
        authenticated: bool,
    },
    /// Authoritative negative: NXDOMAIN or NOERROR+empty ANSWER (NODATA).
    /// `neg_ttl` is RFC 2308 §5 min(SOA MINIMUM, SOA record TTL), or 0 if no SOA
    /// was present (do-not-cache sentinel). No negative-answer cache exists yet
    /// anywhere in the codebase (neither this slow path nor the XDP fast path —
    /// see #210), so `neg_ttl` is computed but currently unread.
    NegativeAnswer {
        rcode: u16,
        /// RFC 2308 §5 negative TTL: `min(SOA.minimum, SOA.ttl)`, or 0 = do-not-cache.
        neg_ttl: u32,
        /// RFC 2308 §3: the zone SOA record(s) from the upstream authority section, so the
        /// forward path serves and caches negatives with the SOA (like the recursion path).
        soa: Vec<wire::Record>,
    },
    /// Transient error: timeout, connection failure, SERVFAIL, REFUSED
    Servfail,
}

impl ResolveResult {
    /// True if this is a definitive result (positive or authoritative negative).
    pub fn is_definitive(&self) -> bool {
        !matches!(self, Self::Servfail)
    }

}

// ─────────────────────── Upstream spec ───────────────────────────────────────

/// Config for a single upstream (built from UnboundConfig forward-zones or API).
#[derive(Clone, Debug)]
pub struct UpstreamSpec {
    /// Display label, e.g. "1.1.1.1@853"
    pub label: String,
    pub addr: SocketAddr,
    pub kind: UpstreamKind,
}

#[derive(Clone, Debug)]
pub enum UpstreamKind {
    Udp,
    Dot {
        sni: Arc<str>,
        tls: Arc<rustls::ClientConfig>,
    },
}

// ─────────────────────── Connection pool internals ───────────────────────────

struct DotConn {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    last_used: Instant,
}

struct DotUpstream {
    addr: SocketAddr,
    sni: Arc<str>,
    tls: Arc<rustls::ClientConfig>,
    pool: Mutex<Vec<Option<DotConn>>>,
}

impl DotUpstream {
    fn new(addr: SocketAddr, sni: Arc<str>, tls: Arc<rustls::ClientConfig>) -> Self {
        Self {
            addr,
            sni,
            tls,
            pool: Mutex::new((0..POOL_CONNS).map(|_| None).collect()),
        }
    }

    async fn take_conn(&self) -> Option<DotConn> {
        let mut slots = self.pool.lock().await;
        for slot in slots.iter_mut() {
            if let Some(c) = slot.take() {
                if c.last_used.elapsed() < POOL_IDLE_TTL {
                    return Some(c);
                }
                // Too old — drop it
            }
        }
        None
    }

    async fn return_conn(&self, mut c: DotConn) {
        c.last_used = Instant::now();
        let mut slots = self.pool.lock().await;
        for slot in slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(c);
                return;
            }
        }
        // Pool full — drop
    }

    async fn new_conn(&self) -> anyhow::Result<DotConn> {
        let tcp = timeout(DOT_CONNECT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .map_err(|_| anyhow::anyhow!("DoT TCP timeout to {}", self.addr))?
            .map_err(|e| anyhow::anyhow!("DoT TCP to {}: {e}", self.addr))?;
        let _ = tcp.set_nodelay(true);
        let connector = TlsConnector::from(Arc::clone(&self.tls));
        let sni = rustls::pki_types::ServerName::try_from(self.sni.as_ref().to_owned())
            .map_err(|_| anyhow::anyhow!("invalid DoT SNI: {}", self.sni))?;
        let stream = timeout(DOT_CONNECT_TIMEOUT, connector.connect(sni, tcp))
            .await
            .map_err(|_| anyhow::anyhow!("DoT TLS timeout to {}", self.addr))?
            .map_err(|e| anyhow::anyhow!("DoT TLS to {}: {e}", self.addr))?;
        Ok(DotConn { stream, last_used: Instant::now() })
    }

    /// Send/recv over an existing connection. RFC 7858: 2-byte length prefix.
    async fn send_recv(conn: &mut DotConn, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let len = u16::try_from(wire.len())
            .map_err(|_| anyhow::anyhow!("DNS query too large for DoT framing"))?;
        conn.stream.write_all(&len.to_be_bytes()).await?;
        conn.stream.write_all(wire).await?;
        conn.stream.flush().await?;
        let mut len_buf = [0u8; 2];
        conn.stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 {
            anyhow::bail!("DoT zero-length response");
        }
        let mut buf = vec![0u8; resp_len];
        conn.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn query(&self, wire: &[u8]) -> ResolveResult {
        match timeout(DOT_QUERY_TIMEOUT, self.do_query(wire)).await {
            Ok(r) => r,
            Err(_) => {
                debug!(addr=%self.addr, "DoT upstream timeout");
                ResolveResult::Servfail
            }
        }
    }

    async fn do_query(&self, wire: &[u8]) -> ResolveResult {
        // Try a pooled connection first.
        if let Some(mut c) = self.take_conn().await {
            match Self::send_recv(&mut c, wire).await {
                Ok(resp) => {
                    self.return_conn(c).await;
                    return parse_response(&resp, true);
                }
                Err(e) => {
                    debug!(addr=%self.addr, err=%e, "DoT pooled conn broken, reconnecting");
                    // c is dropped (TLS session closed)
                }
            }
        }
        // Fresh connection.
        match self.new_conn().await {
            Ok(mut c) => match Self::send_recv(&mut c, wire).await {
                Ok(resp) => {
                    self.return_conn(c).await;
                    parse_response(&resp, true)
                }
                Err(e) => {
                    debug!(addr=%self.addr, err=%e, "DoT fresh conn query failed");
                    ResolveResult::Servfail
                }
            },
            Err(e) => {
                debug!(addr=%self.addr, err=%e, "DoT connect failed");
                ResolveResult::Servfail
            }
        }
    }
}

struct UdpUpstream {
    addr: SocketAddr,
}

impl UdpUpstream {
    async fn query(&self, wire: &[u8]) -> ResolveResult {
        match timeout(UDP_QUERY_TIMEOUT, self.do_query(wire)).await {
            Ok(r) => r,
            Err(_) => {
                debug!(addr=%self.addr, "UDP upstream timeout");
                ResolveResult::Servfail
            }
        }
    }

    async fn do_query(&self, wire: &[u8]) -> ResolveResult {
        let bind = if self.addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = match UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(e) => {
                warn!(err=%e, "UDP forward: bind failed");
                return ResolveResult::Servfail;
            }
        };
        if let Err(e) = sock.connect(self.addr).await {
            debug!(addr=%self.addr, err=%e, "UDP connect failed");
            return ResolveResult::Servfail;
        }
        if let Err(e) = sock.send(wire).await {
            debug!(addr=%self.addr, err=%e, "UDP send failed");
            return ResolveResult::Servfail;
        }
        // SEC-O1: capture the query transaction ID and question so the response can
        // be validated. Over plain UDP the connected socket only filters the source
        // address; without an ID/question check a spoofed datagram from the upstream
        // address would be accepted verbatim → cache poisoning. (DoT is authenticated
        // by TLS and does not need this.)
        let qid = u16::from_be_bytes([wire[0], wire[1]]);
        let qquestion = wire::Message::parse(wire)
            .ok()
            .and_then(|m| m.first_question().cloned());
        let mut buf = vec![0u8; 4096];
        // Keep reading until a datagram matching the query arrives; a single spoofed
        // / stale non-matching datagram no longer aborts resolution. The outer
        // UDP_QUERY_TIMEOUT (in `query()`) bounds the total wait.
        loop {
            match sock.recv(&mut buf).await {
                Ok(n) => {
                    if response_matches(&buf[..n], qid, qquestion.as_ref()) {
                        // RFC 1035 §4.2.1: a truncated (TC=1) UDP answer is
                        // incomplete — the upstream capped at 512 and dropped the
                        // RRset (large DNSKEY/TXT come back empty). Retry the same
                        // query over TCP to pull the full answer. response_matches
                        // already parsed the header, so buf[2] (flags hi byte) is
                        // in bounds. Only oversized answers reach here → TCP cold.
                        if buf[2] & 0x02 != 0 {
                            if let Some(full) = tcp_query(self.addr, wire).await {
                                // Re-apply SEC-O1: the TCP answer must match the
                                // query ID + question before it is trusted.
                                if response_matches(&full, qid, qquestion.as_ref()) {
                                    return parse_response(&full, false);
                                }
                            }
                            // TCP failed / mismatched → fall through to the
                            // truncated UDP parse (a TC-flagged partial beats a
                            // dropped query).
                        }
                        return parse_response(&buf[..n], false);
                    }
                    debug!(addr=%self.addr, "UDP forward: response did not match query (id/question) — ignored");
                    // loop and wait for the genuine reply (bounded by the outer timeout)
                }
                Err(e) => {
                    debug!(addr=%self.addr, err=%e, "UDP recv failed");
                    return ResolveResult::Servfail;
                }
            }
        }
    }
}

/// RFC 1035 §4.2.2: query an upstream over plain TCP (2-byte length prefix),
/// used to recover a full RRset after a truncated UDP answer. Returns the raw
/// response bytes, or `None` on any I/O failure (the caller then falls back to
/// the truncated UDP answer rather than dropping the query). The caller still
/// re-applies SEC-O1 ID/question matching to the returned bytes.
async fn tcp_query(addr: SocketAddr, wire: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(wire.len()).ok()?;
    let mut tcp = timeout(TCP_QUERY_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let _ = tcp.set_nodelay(true);
    let io = async {
        tcp.write_all(&len.to_be_bytes()).await.ok()?;
        tcp.write_all(wire).await.ok()?;
        tcp.flush().await.ok()?;
        let mut len_buf = [0u8; 2];
        tcp.read_exact(&mut len_buf).await.ok()?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 {
            return None;
        }
        let mut buf = vec![0u8; resp_len];
        tcp.read_exact(&mut buf).await.ok()?;
        Some(buf)
    };
    timeout(TCP_QUERY_TIMEOUT, io).await.ok()?
}

/// SEC-O1: a plain-UDP upstream response is only accepted when its transaction ID
/// and its question (name case-insensitive + type + class) match the query.
fn response_matches(resp: &[u8], qid: u16, qq: Option<&wire::Question>) -> bool {
    if resp.len() < 4 || u16::from_be_bytes([resp[0], resp[1]]) != qid {
        return false;
    }
    let Ok(msg) = wire::Message::parse(resp) else { return false };
    match (msg.first_question(), qq) {
        (Some(rq), Some(qq)) => {
            rq.qtype == qq.qtype && rq.qclass == qq.qclass && rq.name.eq_ignore_ascii_case(&qq.name)
        }
        (None, None) => true,
        _ => false,
    }
}

enum Upstream {
    Udp(UdpUpstream),
    Dot(DotUpstream),
}

impl Upstream {
    async fn query(&self, wire: &[u8]) -> ResolveResult {
        match self {
            Self::Udp(u) => u.query(wire).await,
            Self::Dot(d) => d.query(wire).await,
        }
    }

    fn is_dot(&self) -> bool {
        matches!(self, Self::Dot(_))
    }
}

// ─────────────────────── ForwardPool (public) ─────────────────────────────────

/// The forward pool. Held behind `Arc<ArcSwap<ForwardPool>>` so it can be
/// hot-swapped when upstreams change (API edits, resolv.conf fallback).
pub struct ForwardPool {
    entries: Vec<(String, Arc<Upstream>)>,
}

impl ForwardPool {
    /// Build a pool from a slice of upstream specs.
    pub fn build(specs: &[UpstreamSpec]) -> Arc<Self> {
        let entries = specs
            .iter()
            .map(|spec| {
                let up = match &spec.kind {
                    UpstreamKind::Udp => Upstream::Udp(UdpUpstream { addr: spec.addr }),
                    UpstreamKind::Dot { sni, tls } => {
                        Upstream::Dot(DotUpstream::new(spec.addr, Arc::clone(sni), Arc::clone(tls)))
                    }
                };
                (spec.label.clone(), Arc::new(up))
            })
            .collect();
        Arc::new(Self { entries })
    }

    /// Forward a raw DNS wire query to all upstreams in parallel.
    /// Returns `(result, winning_upstream_label)`. The winning label is `None`
    /// when all upstreams returned `Servfail`.
    pub async fn forward(&self, query_wire: &[u8]) -> (ResolveResult, Option<String>) {
        if self.entries.is_empty() {
            return (ResolveResult::Servfail, None);
        }
        if self.entries.len() == 1 {
            let (label, up) = &self.entries[0];
            let result = up.query(query_wire).await;
            let winner = result.is_definitive().then(|| label.clone());
            return (result, winner);
        }
        // Race all upstreams — first definitive result wins.
        let wire: Arc<[u8]> = Arc::from(query_wire);
        let mut futs: futures_util::stream::FuturesUnordered<_> = self
            .entries
            .iter()
            .map(|(label, up)| {
                let label = label.clone();
                let up = Arc::clone(up);
                let wire = Arc::clone(&wire);
                Box::pin(async move {
                    let result = up.query(&wire).await;
                    (result, label)
                })
            })
            .collect();

        while let Some((result, label)) = futs.next().await {
            if result.is_definitive() {
                return (result, Some(label));
            }
        }
        (ResolveResult::Servfail, None)
    }

    /// Send a SOA keepalive probe to each DoT upstream to keep TLS sessions alive.
    pub async fn keepalive(&self) {
        let probe = keepalive_wire();
        for (label, up) in &self.entries {
            if up.is_dot() {
                match timeout(DOT_QUERY_TIMEOUT, up.query(&probe)).await {
                    Ok(r) if r.is_definitive() => {
                        debug!(upstream=%label, "DoT keepalive OK");
                    }
                    Ok(_) => debug!(upstream=%label, "DoT keepalive SERVFAIL"),
                    Err(_) => debug!(upstream=%label, "DoT keepalive timeout"),
                }
            }
        }
    }

}

// ─────────────────────── Spec builders from config ───────────────────────────

/// Build upstream specs from config `forward-zone` blocks.
pub fn specs_from_config(cfg: &crate::config::parser::UnboundConfig) -> Vec<UpstreamSpec> {
    let root_store = build_root_store();
    let mut out = Vec::new();
    for fz in &cfg.forward_zones {
        let use_tls = fz.tls;
        let default_port = if use_tls { 853u16 } else { 53u16 };
        for addr_str in &fz.addrs {
            let (ip_str, port) = split_addr_port(addr_str, default_port);
            let Ok(ip) = ip_str.parse::<IpAddr>() else { continue };
            let addr = SocketAddr::new(ip, port);
            if use_tls {
                let sni = fz.tls_hostname.as_deref()
                    .map(Arc::from)
                    .unwrap_or_else(|| dot_tls_name(&ip, None));
                let tls = dot_client_config(Arc::clone(&root_store));
                out.push(UpstreamSpec {
                    label: format!("{ip_str}@{port}"),
                    addr,
                    kind: UpstreamKind::Dot { sni, tls },
                });
            } else {
                out.push(UpstreamSpec {
                    label: format!("{ip_str}@{port}"),
                    addr,
                    kind: UpstreamKind::Udp,
                });
            }
        }
    }
    // Fallback: Cloudflare DoT (same behaviour as old build_resolver)
    if out.is_empty() {
        warn!(
            "No forward-zone configured — falling back to Cloudflare DoT (1.1.1.1@853). \
             Add forward-zone blocks to runbound.conf to suppress this warning."
        );
        let tls = dot_client_config(Arc::clone(&root_store));
        for (ip_str, sni_str) in [("1.1.1.1", "cloudflare-dns.com"), ("1.0.0.1", "cloudflare-dns.com")] {
            let ip: IpAddr = ip_str.parse().unwrap();
            out.push(UpstreamSpec {
                label: format!("{ip_str}@853"),
                addr: SocketAddr::new(ip, 853),
                kind: UpstreamKind::Dot {
                    sni: Arc::from(sni_str),
                    tls: Arc::clone(&tls),
                },
            });
        }
    }
    out
}

/// Build upstream specs from the live upstream list `(addr, port, use_tls, tls_hostname_override)`.
/// Used when upstreams change via the API.
pub fn specs_from_addrs(addrs: &[(String, u16, bool, Option<String>)]) -> Vec<UpstreamSpec> {
    let root_store = build_root_store();
    let mut out = Vec::new();
    for (addr_str, port, use_tls, tls_hostname) in addrs {
        let Ok(ip) = addr_str.parse::<IpAddr>() else { continue };
        let addr = SocketAddr::new(ip, *port);
        if *use_tls {
            let sni = tls_hostname.as_deref()
                .map(Arc::from)
                .unwrap_or_else(|| dot_tls_name(&ip, None));
            let tls = dot_client_config(Arc::clone(&root_store));
            out.push(UpstreamSpec {
                label: format!("{addr_str}@{port}"),
                addr,
                kind: UpstreamKind::Dot { sni, tls },
            });
        } else {
            out.push(UpstreamSpec {
                label: format!("{addr_str}@{port}"),
                addr,
                kind: UpstreamKind::Udp,
            });
        }
    }
    out
}

// ─────────────────────── Shared resolver type ────────────────────────────────

/// Hot-swappable forward pool, shared across the server.
pub type SharedPool = Arc<ArcSwap<ForwardPool>>;

/// Create the initial SharedPool from config.
pub fn create_shared_pool(cfg: &crate::config::parser::UnboundConfig) -> SharedPool {
    let specs = specs_from_config(cfg);
    let pool = ForwardPool::build(&specs);
    Arc::new(ArcSwap::from(pool))
}

/// Replace the current pool with a freshly built one (called on upstream changes
/// and after resolv.conf fallback recovery).
pub async fn rebuild_pool(shared: &SharedPool, addrs: &[(String, u16, bool, Option<String>)]) {
    let specs = specs_from_addrs(addrs);
    let pool = ForwardPool::build(&specs);
    shared.store(pool);
}

// ─────────────────────── TLS helpers ─────────────────────────────────────────

fn build_root_store() -> Arc<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    // Prefer system CA bundle; fall back to the bundled webpki roots.
    let native = rustls_native_certs::load_native_certs();
    let mut loaded = 0usize;
    for cert in native.certs {
        if store.add(cert).is_ok() {
            loaded += 1;
        }
    }
    if loaded == 0 {
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Arc::new(store)
}

fn dot_client_config(roots: Arc<rustls::RootCertStore>) -> Arc<rustls::ClientConfig> {
    // Pin the ring provider before building any TLS config: with both ring and
    // aws-lc-rs in the dependency graph, rustls cannot auto-select a default, so
    // ClientConfig::builder() would panic. main() installs it for the live binary;
    // doing it here too covers any path (e.g. tests) that builds a client config
    // first. Idempotent — .ok() ignores an already-installed provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"dot".to_vec()];
    Arc::new(cfg)
}

/// Return the canonical DoT SNI hostname for well-known resolvers.
/// Matches the logic in server.rs `dot_tls_name`.
pub(crate) fn dot_tls_name(ip: &IpAddr, override_: Option<&str>) -> Arc<str> {
    if let Some(h) = override_ {
        return Arc::from(h);
    }
    match ip.to_string().as_str() {
        "1.1.1.1" | "1.0.0.1" => Arc::from("cloudflare-dns.com"),
        "8.8.8.8" | "8.8.4.4" => Arc::from("dns.google"),
        "9.9.9.9" | "149.112.112.112" => Arc::from("dns.quad9.net"),
        other => Arc::from(other),
    }
}

// ─────────────────────── Wire helpers ────────────────────────────────────────

/// Parse a DNS wire response into a `ResolveResult`.
fn parse_response(wire_bytes: &[u8], authed_channel: bool) -> ResolveResult {
    use crate::dns::wire::consts::rcode;
    let msg = match wire::Message::parse(wire_bytes) {
        Ok(m) => m,
        Err(e) => {
            debug!(err = ?e, "failed to parse upstream DNS response");
            return ResolveResult::Servfail;
        }
    };
    let rc = msg.header.rcode_low();
    match rc {
        rcode::NOERROR => {
            if msg.answers.is_empty() {
                // NODATA — authoritative empty answer
                // neg_ttl 0 = no usable SOA → consumer must not negative-cache (#210).
                ResolveResult::NegativeAnswer {
                    rcode: rcode::NOERROR,
                    neg_ttl: soa_min_ttl(&msg).unwrap_or(0),
                    soa: zone_soas(&msg),
                }
            } else {
                ResolveResult::Answer {
                    authenticated: msg.header.ad() && authed_channel,
                    records: msg.answers,
                }
            }
        }
        rcode::NXDOMAIN => ResolveResult::NegativeAnswer {
            rcode: rcode::NXDOMAIN,
            neg_ttl: soa_min_ttl(&msg).unwrap_or(0),
            soa: zone_soas(&msg),
        },
        other => {
            debug!(rcode = other, "upstream returned error rcode");
            ResolveResult::Servfail
        }
    }
}

/// Negative-cache TTL from the authority SOA (RFC 2308 §5): the LESSER of the SOA
/// MINIMUM field and the SOA record's own TTL (the record TTL was previously
/// ignored — #210). `None` when the authority carries no SOA: RFC 2308 negative
/// caching is predicated on the SOA, so a no-SOA negative must not be pinned on an
/// invented TTL — the consumer treats `None`/0 as "do not negative-cache". The
/// configured-window clamp is the consumer's job, not done here.
fn soa_min_ttl(msg: &wire::Message) -> Option<u32> {
    let qname = response_qname(msg)?;
    msg.authority.iter().find_map(|r| match &r.rdata {
        wire::Rdata::Soa { minimum, .. } if qname.is_in_zone(&r.name) => Some((*minimum).min(r.ttl)),
        _ => None,
    })
}

/// The query name from the response's own question section. `response_matches`
/// (SEC-O1) has already bound this question to the query we sent, so it is a
/// trustworthy anchor for the bailiwick check below.
fn response_qname(msg: &wire::Message) -> Option<&wire::Name> {
    msg.questions.first().map(|q| &q.name)
}

/// Authority-section SOA records that actually enclose the qname (RFC 2308 §3: a
/// negative answer's SOA must come from a zone authoritative for the name). A
/// laterally out-of-bailiwick SOA — e.g. an `other.tld` SOA stuffed into a reply
/// for `www.victim.tld` — is dropped so it cannot drive the negative-cache TTL.
/// Mirrors the recursor's in-bailiwick guarantee (minus the DNSSEC proof: forward
/// mode trusts the configured upstream, but not an unrelated zone's SOA).
fn zone_soas(msg: &wire::Message) -> Vec<wire::Record> {
    let Some(qname) = response_qname(msg) else {
        return Vec::new();
    };
    msg.authority
        .iter()
        .filter(|r| matches!(r.rdata, wire::Rdata::Soa { .. }) && qname.is_in_zone(&r.name))
        .cloned()
        .collect()
}

/// Build a keepalive SOA query for "." in DNS wire format.
fn keepalive_wire() -> Vec<u8> {
    static KA_ID: AtomicU16 = AtomicU16::new(0xCA11);
    let id = KA_ID.fetch_add(1, Ordering::Relaxed);
    use crate::dns::wire::consts::{opcode, rtype};
    let mut h = wire::Header { id, flags: 0, qdcount: 0, ancount: 0, nscount: 0, arcount: 0 };
    h.set_opcode(opcode::QUERY);
    h.set_rd(true);
    let msg = wire::Message {
        header: h,
        questions: vec![wire::Question::new(wire::Name::root(), rtype::SOA)],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    msg.encode()
}

/// Split "addr@port" into (addr_str, port), defaulting port when absent.
fn split_addr_port(s: &str, default_port: u16) -> (&str, u16) {
    if let Some(at) = s.find('@') {
        let port = s[at + 1..].parse().unwrap_or(default_port);
        (&s[..at], port)
    } else {
        (s, default_port)
    }
}

// ─────────────────── Forward DO=1 answer cache (#dnssec-forward-cache) ────────
//
// In forward mode a DO=1 (DNSSEC-aware) client query is re-forwarded to the
// upstream on every repeat: the XDP/UDP fast-path cache only holds the AD-less
// DO=0 datagram, so a validating client keeps paying the upstream round-trip.
// This cache holds the forwarded answer *including* the covering RRSIGs the
// upstream returned (the client's DO=1 query is forwarded verbatim, so the
// upstream answer section carries them), keyed by (qname, qtype); repeat DO=1
// queries are then served locally. The DO=0 fast path is entirely untouched.
//
// Security invariants (fail-closed — mirrors recursor_wire::VALIDATED_CACHE):
//   * Only DO=1 answers are ever inserted or served (they carry the RRSIGs the
//     client needs to validate; a DO=0 answer has none and never reaches here).
//   * An entry's lifetime is bounded by BOTH the smallest record TTL AND the
//     nearest RRSIG expiration (serial arithmetic, RFC 4034 §3.1.5), capped at
//     24 h. A served record's TTL is additionally clamped to the remaining entry
//     lifetime, so a hit can never advertise a TTL past a signature's expiration.
//   * TTLs decay: a hit returns TTL_original - elapsed (then clamped); if any
//     record TTL would reach 0 the entry is a miss and is dropped.
//   * An answer carrying NO RRSIG is refused (nothing bounds it by signature
//     expiry — fail-closed): we only validate-cache signed answers.

/// Hard ceiling on how long any forward DO=1 answer may be cached (defence
/// against absurd upstream TTLs): 24 h. Matches VALIDATED_CACHE_TTL_CAP.
const FORWARD_DO_CACHE_TTL_CAP: u32 = 86_400;
/// Naive size bound: once full we stop inserting NEW keys (existing entries keep
/// expiring / being refreshed in place). No LRU — the cheapest bound that never
/// serves stale data; churn drains it as TTLs / RRSIG windows elapse.
const FORWARD_DO_CACHE_MAX: usize = 100_000;

/// A forward-mode DO=1 answer held in memory. `records` keep their ORIGINAL TTLs
/// (INCLUDING the covering RRSIGs); the elapsed time since `inserted_at` is
/// subtracted, and the result clamped to the remaining lifetime, on every read.
struct CachedForward {
    records: Vec<wire::Record>,
    /// Upstream set AD AND the answer arrived over an authenticated (DoT) channel;
    /// stored verbatim so the caller can re-apply the same AD relay gate as the
    /// live forward path (RFC 6840 §5.7). False for any cleartext upstream.
    authenticated: bool,
    inserted_at: Instant,
    expires_at: Instant,
}

/// Global cache of forward-mode DO=1 answers, keyed by (qname, qtype). `Name`
/// hashes/compares case-insensitively, so mixed-case queries share one entry.
static FORWARD_DO_CACHE: LazyLock<DashMap<(wire::Name, u16), CachedForward>> =
    LazyLock::new(DashMap::new);

/// Seconds until the nearest RRSIG expiration among `records`, using serial-number
/// arithmetic against `now` (RFC 4034 §3.1.5 — wrap-safe, the same comparison as
/// `recursor_wire::nearest_rrsig_secs`). The expiration is octets 8..12 of the
/// RRSIG rdata (RFC 4034 §3.1), carried opaquely as `Rdata::Unknown` (RFC 3597).
/// Returns:
///   * `None` — no RRSIG present to bound the entry (caller must not cache);
///   * `Some(0)` — at least one RRSIG is already expired (fail-closed: do not cache);
///   * `Some(min_left)` — smallest seconds-until-expiration across all RRSIGs.
fn forward_nearest_rrsig_secs(records: &[wire::Record], now: u32) -> Option<u32> {
    let mut min_left: Option<u32> = None;
    for r in records {
        if r.rtype != wire::consts::rtype::RRSIG {
            continue;
        }
        let wire::Rdata::Unknown { data, .. } = &r.rdata else {
            continue;
        };
        let secs = if data.len() >= 12 {
            let exp = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            // Serial-space distance now -> expiration; >= 2^31 means `now` is at or
            // past expiration (RFC 4034 §3.1.5) -> already expired.
            let left = exp.wrapping_sub(now);
            if left >= 0x8000_0000 { 0 } else { left }
        } else {
            0 // unparseable RRSIG -> fail-closed (treat as expired)
        };
        min_left = Some(min_left.map_or(secs, |m| m.min(secs)));
    }
    min_left
}

/// Look up a cached forward DO=1 answer. On a live hit returns the records with
/// every TTL decremented by the elapsed time AND clamped to the entry's remaining
/// lifetime (so no served TTL ever outlives the nearest RRSIG expiry), plus the
/// stored `authenticated` flag. Returns `None` (and drops the entry) if it is
/// expired, or if any record TTL would reach 0 (the RRset expired since insertion
/// -> the hit is a miss). Never mutates a live entry.
pub fn forward_do_cache_get(qname: &wire::Name, qtype: u16) -> Option<(Vec<wire::Record>, bool)> {
    let key = (qname.clone(), qtype);
    let hit = FORWARD_DO_CACHE.get(&key)?;
    let now_i = Instant::now();
    let served = if hit.expires_at > now_i {
        let elapsed =
            now_i.duration_since(hit.inserted_at).as_secs().min(u64::from(u32::MAX)) as u32;
        // Remaining entry lifetime (bounded at put-time by the nearest RRSIG
        // expiry): every served record TTL is clamped to this so a hit never
        // advertises a TTL past a signature's expiration.
        let remaining =
            hit.expires_at.saturating_duration_since(now_i).as_secs().min(u64::from(u32::MAX)) as u32;
        let mut out = Vec::with_capacity(hit.records.len());
        let mut ok = true;
        for r in &hit.records {
            // Decay by elapsed (miss if it reaches 0), then clamp to `remaining`.
            match r.ttl.checked_sub(elapsed).filter(|&t| t > 0) {
                Some(ttl) => {
                    let served_ttl = ttl.min(remaining);
                    if served_ttl == 0 {
                        ok = false;
                        break;
                    }
                    let mut c = r.clone();
                    c.ttl = served_ttl;
                    out.push(c);
                }
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok { Some((out, hit.authenticated)) } else { None }
    } else {
        None
    };
    drop(hit); // release the DashMap shard lock before any remove()
    if served.is_none() {
        FORWARD_DO_CACHE.remove(&key);
    }
    served
}

/// Insert a forward-mode DO=1 answer under `(qname, qtype)`. Cache TTL is
/// `min(smallest record TTL, seconds to the nearest RRSIG expiration, 24 h cap)`.
/// `now` is epoch-seconds (for the RRSIG serial comparison); the entry's monotonic
/// deadline uses `Instant`. Refuses to cache when: `records` carries no RRSIG (a
/// DO=1 answer we can't bound by a signature — fail-closed), any RRSIG is already
/// expired, the bounded TTL is 0, or the cache is full and this is a NEW key.
pub fn forward_do_cache_put(
    qname: &wire::Name,
    qtype: u16,
    records: &[wire::Record],
    authenticated: bool,
    now: u32,
) {
    // Signed answers are bounded by their nearest RRSIG expiration; an unsigned
    // (Insecure) DO=1 answer carries no RRSIG and is bounded by its record TTL alone
    // — safe, since there is no signature that could outlive the entry. Only an
    // ALREADY-EXPIRED signature is fail-closed (never cached).
    let rrsig_left = match forward_nearest_rrsig_secs(records, now) {
        Some(0) => return, // a covering signature is already expired -> fail-closed
        Some(s) => s,      // signed: bound by the nearest RRSIG expiration
        None => u32::MAX,  // unsigned (Insecure): record-TTL bound only
    };
    let mut ttl_cache = u32::MAX;
    for r in records {
        ttl_cache = ttl_cache.min(r.ttl);
    }
    ttl_cache = ttl_cache.min(rrsig_left);
    // Degenerate: no record supplied a TTL -> fall back to the cap (never unbounded).
    if ttl_cache == u32::MAX {
        ttl_cache = FORWARD_DO_CACHE_TTL_CAP;
    }
    ttl_cache = ttl_cache.min(FORWARD_DO_CACHE_TTL_CAP);
    if ttl_cache == 0 {
        return; // already-expired signature or zero TTL -> fail-closed
    }
    let key = (qname.clone(), qtype);
    // Naive size bound: reject NEW keys once full; refreshing an existing key is
    // always allowed so a stale entry can be replaced.
    if FORWARD_DO_CACHE.len() >= FORWARD_DO_CACHE_MAX && !FORWARD_DO_CACHE.contains_key(&key) {
        return;
    }
    let now_i = Instant::now();
    FORWARD_DO_CACHE.insert(
        key,
        CachedForward {
            records: records.to_vec(),
            authenticated,
            inserted_at: now_i,
            expires_at: now_i + Duration::from_secs(u64::from(ttl_cache)),
        },
    );
}

/// Drop every entry in the forward DO=1 answer cache. Called by the API
/// `POST /api/cache/flush` handler alongside the resolver + validated + XDP cache
/// clears so a flush truly forgets all forwarded validated names.
pub fn flush_forward_do_cache() {
    FORWARD_DO_CACHE.clear();
}

#[cfg(test)]
mod forward_do_cache_tests {
    use super::*;
    use crate::dns::wire::consts::rtype;

    /// Build an RRSIG record whose signature-expiration field (RFC 4034 §3.1,
    /// octets 8..12 of the rdata) is `expiration` epoch-seconds. The other rdata
    /// fields are irrelevant to the cache's lifetime bound, so they stay zero.
    fn rrsig(name: &str, ttl: u32, expiration: u32) -> wire::Record {
        let mut data = vec![0u8; 18];
        data[0] = 0x00;
        data[1] = 0x01; // type-covered = A (not read by the bound; only octets 8..12 matter)
        data[8..12].copy_from_slice(&expiration.to_be_bytes());
        wire::Record {
            name: wire::Name::from_ascii(name).unwrap(),
            rtype: rtype::RRSIG,
            rclass: 1,
            ttl,
            rdata: wire::Rdata::Unknown { rtype: rtype::RRSIG, data },
        }
    }
    fn a_record(name: &str, ttl: u32) -> wire::Record {
        wire::Record {
            name: wire::Name::from_ascii(name).unwrap(),
            rtype: rtype::A,
            rclass: 1,
            ttl,
            rdata: wire::Rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    #[test]
    fn ttl_bounded_by_rrsig_expiration() {
        flush_forward_do_cache();
        let now: u32 = 1_000_000;
        let name = wire::Name::from_ascii("secure.example.").unwrap();
        // A record TTL 100000s but the RRSIG expires in 50s -> the entry, and every
        // served record TTL, must be bounded to ~50s (never the raw 100000s).
        let records =
            vec![a_record("secure.example.", 100_000), rrsig("secure.example.", 100_000, now + 50)];
        forward_do_cache_put(&name, rtype::A, &records, true, now);
        let (got, authed) = forward_do_cache_get(&name, rtype::A).expect("DO=1 answer must cache");
        assert!(authed, "authenticated flag must round-trip");
        let a_ttl = got.iter().find(|r| r.rtype == rtype::A).unwrap().ttl;
        assert!(
            (45..=50).contains(&a_ttl),
            "served A TTL must be bounded to the ~50s RRSIG window, got {a_ttl}"
        );
        flush_forward_do_cache();
    }

    #[test]
    fn expired_rrsig_not_cached() {
        flush_forward_do_cache();
        let now: u32 = 1_000_000;
        let name = wire::Name::from_ascii("expired.example.").unwrap();
        // RRSIG already expired (10s in the past) -> fail-closed, never cached.
        let records =
            vec![a_record("expired.example.", 3600), rrsig("expired.example.", 3600, now - 10)];
        forward_do_cache_put(&name, rtype::A, &records, true, now);
        assert!(
            forward_do_cache_get(&name, rtype::A).is_none(),
            "an already-expired RRSIG must not be cached"
        );
        flush_forward_do_cache();
    }

    #[test]
    fn unsigned_answer_cached_bounded_by_ttl() {
        flush_forward_do_cache();
        let now: u32 = 1_000_000;
        let name = wire::Name::from_ascii("nosig.example.").unwrap();
        // An unsigned (Insecure) DO=1 answer carries no RRSIG: cache it bounded by its
        // record TTL alone (there is no signature that could outlive the entry).
        // `authenticated` is false for an unsigned answer.
        let records = vec![a_record("nosig.example.", 300)];
        forward_do_cache_put(&name, rtype::A, &records, false, now);
        let (got, authed) = forward_do_cache_get(&name, rtype::A)
            .expect("an unsigned DO=1 answer must be TTL-cached");
        assert!(!authed, "an unsigned answer is never authenticated");
        let a_ttl = got.iter().find(|r| r.rtype == rtype::A).map(|r| r.ttl).unwrap();
        assert!(a_ttl > 0 && a_ttl <= 300, "served A TTL must be within the record TTL, got {a_ttl}");
        flush_forward_do_cache();
    }
}

#[cfg(test)]
mod sec_o1_tests {
    use super::*;
    use crate::dns::wire::consts::{opcode, rtype};
    use crate::dns::wire::{Header, Message, Name, Question};

    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut h = Header { id, flags: 0, qdcount: 0, ancount: 0, nscount: 0, arcount: 0 };
        h.set_opcode(opcode::QUERY);
        h.set_rd(true);
        Message {
            header: h,
            questions: vec![Question::new(Name::from_ascii(name).unwrap(), qtype)],
            answers: vec![], authority: vec![], additional: vec![],
        }
        .encode()
    }
    fn response(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut h = Header { id, flags: 0, qdcount: 0, ancount: 0, nscount: 0, arcount: 0 };
        h.set_opcode(opcode::QUERY);
        h.set_qr(true);
        Message {
            header: h,
            questions: vec![Question::new(Name::from_ascii(name).unwrap(), qtype)],
            answers: vec![], authority: vec![], additional: vec![],
        }
        .encode()
    }

    #[test]
    fn accepts_matching_response() {
        let q = query(0x1234, "example.com.", rtype::A);
        let qq = Message::parse(&q).unwrap().first_question().cloned();
        let r = response(0x1234, "EXAMPLE.com.", rtype::A); // case-insensitive name
        assert!(response_matches(&r, 0x1234, qq.as_ref()));
    }

    #[test]
    fn rejects_wrong_txid() {
        let q = query(0x1234, "example.com.", rtype::A);
        let qq = Message::parse(&q).unwrap().first_question().cloned();
        let spoof = response(0x9999, "example.com.", rtype::A);
        assert!(!response_matches(&spoof, 0x1234, qq.as_ref()));
    }

    #[test]
    fn rejects_wrong_question() {
        let q = query(0x1234, "example.com.", rtype::A);
        let qq = Message::parse(&q).unwrap().first_question().cloned();
        // right id, wrong name and wrong type — must be rejected (cache-poison guard)
        assert!(!response_matches(&response(0x1234, "evil.com.", rtype::A), 0x1234, qq.as_ref()));
        assert!(!response_matches(&response(0x1234, "example.com.", rtype::AAAA), 0x1234, qq.as_ref()));
    }

    #[test]
    fn rejects_truncated() {
        assert!(!response_matches(&[0x12, 0x34], 0x1234, None));
    }

    /// NOERROR response carrying a single A record, with the AD flag controllable.
    fn answer_response(ad: bool) -> Vec<u8> {
        let mut h = Header { id: 0x1234, flags: 0, qdcount: 0, ancount: 0, nscount: 0, arcount: 0 };
        h.set_opcode(opcode::QUERY);
        h.set_qr(true);
        h.set_ad(ad);
        Message {
            header: h,
            questions: vec![Question::new(Name::from_ascii("example.com.").unwrap(), rtype::A)],
            answers: vec![wire::Record {
                name: Name::from_ascii("example.com.").unwrap(),
                rtype: rtype::A,
                rclass: 1, // IN
                ttl: 300,
                rdata: wire::Rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            }],
            authority: vec![],
            additional: vec![],
        }
        .encode()
    }

    #[test]
    fn ad_propagates_only_over_authenticated_channel() {
        // Upstream set AD=1 but the answer came over cleartext UDP/TCP: AD is spoofable
        // there, so a forwarder must never propagate it.
        let wire_ad = answer_response(true);
        match parse_response(&wire_ad, false) {
            ResolveResult::Answer { authenticated, .. } => assert!(!authenticated),
            other => panic!("expected Answer, got {other:?}"),
        }
        // Same AD=1 answer over an authenticated (DoT) channel: propagation allowed.
        match parse_response(&wire_ad, true) {
            ResolveResult::Answer { authenticated, .. } => assert!(authenticated),
            other => panic!("expected Answer, got {other:?}"),
        }
        // Upstream AD=0 on an authenticated channel: never fabricate AD out of nothing.
        let wire_noad = answer_response(false);
        match parse_response(&wire_noad, true) {
            ResolveResult::Answer { authenticated, .. } => assert!(!authenticated),
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn negative_soa_out_of_bailiwick_is_dropped() {
        let soa = |owner: &str, minimum: u32, ttl: u32| wire::Record {
            name: wire::Name::from_ascii(owner).unwrap(),
            rtype: rtype::SOA,
            rclass: 1, // IN
            ttl,
            rdata: wire::Rdata::Soa {
                mname: wire::Name::from_ascii("ns.example.com.").unwrap(),
                rname: wire::Name::from_ascii("hostmaster.example.com.").unwrap(),
                serial: 1, refresh: 3600, retry: 600, expire: 86400, minimum,
            },
        };
        let msg = |auth: Vec<wire::Record>| wire::Message {
            header: wire::Header { id: 1, flags: 0, qdcount: 1, ancount: 0, nscount: 0, arcount: 0 },
            questions: vec![wire::Question::new(wire::Name::from_ascii("www.victim.tld.").unwrap(), rtype::A)],
            answers: vec![],
            authority: auth,
            additional: vec![],
        };
        // In-bailiwick SOA (the enclosing zone) is kept and drives the neg-TTL
        // (min(SOA.minimum, record.ttl) = min(300, 900)).
        let good = msg(vec![soa("victim.tld.", 300, 900)]);
        assert_eq!(zone_soas(&good).len(), 1);
        assert_eq!(soa_min_ttl(&good), Some(300));
        // A laterally out-of-bailiwick SOA (unrelated zone) is dropped: an on-path /
        // malicious upstream cannot pin a forged negative-cache TTL on www.victim.tld.
        let forged = msg(vec![soa("attacker.example.org.", 900, 900)]);
        assert!(zone_soas(&forged).is_empty());
        assert_eq!(soa_min_ttl(&forged), None);
    }
}
