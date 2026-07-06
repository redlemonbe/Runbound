//! Own DNS upstream forwarder — replaces hickory-resolver's TokioResolver.
//!
//! `ForwardPool` provides:
//! - Per-upstream persistent DoT connections (RFC 7858 TCP framing), pooled
//! - UDP upstream forwarding
//! - Parallel racing: all upstreams queried simultaneously, first definitive wins
//! - Automatic reconnection on failure
//! - Keepalive probes for DoT connections

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
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
    Answer { records: Vec<wire::Record> },
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
                    return parse_response(&resp);
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
                    parse_response(&resp)
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
                                    return parse_response(&full);
                                }
                            }
                            // TCP failed / mismatched → fall through to the
                            // truncated UDP parse (a TC-flagged partial beats a
                            // dropped query).
                        }
                        return parse_response(&buf[..n]);
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
fn parse_response(wire_bytes: &[u8]) -> ResolveResult {
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
                    soa: msg.authority.iter().filter(|r| matches!(r.rdata, wire::Rdata::Soa { .. })).cloned().collect(),
                }
            } else {
                ResolveResult::Answer { records: msg.answers }
            }
        }
        rcode::NXDOMAIN => ResolveResult::NegativeAnswer {
            rcode: rcode::NXDOMAIN,
            neg_ttl: soa_min_ttl(&msg).unwrap_or(0),
            soa: msg.authority.iter().filter(|r| matches!(r.rdata, wire::Rdata::Soa { .. })).cloned().collect(),
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
    msg.authority.iter().find_map(|r| {
        if let wire::Rdata::Soa { minimum, .. } = &r.rdata {
            Some((*minimum).min(r.ttl))
        } else {
            None
        }
    })
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
}
