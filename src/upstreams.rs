// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Upstream DNS health monitoring.
//
// UDP upstreams: probed with a minimal UDP DNS query (`. IN A`).
// DoT upstreams: probed with a TCP+TLS connect+handshake (no DNS query needed).
//
// Backoff: a failing upstream is retried with exponential backoff (30s → 60s →
// 120s → 300s cap) so that a permanently unreachable server does not spam logs.
// On recovery, the backoff resets and an INFO message is emitted.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::time;
use tracing::{info, warn};

use crate::config::parser::UnboundConfig;

// ── Probe interval / timeout ───────────────────────────────────────────────
const PROBE_INTERVAL_SECS: u64 = 30;
const PROBE_TIMEOUT_MS:    u64 = 2_000;

const BIND_V4: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
const BIND_V6: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0);

// RFC 1035 DNS query with EDNS0 OPT RR (RFC 6891) and DO bit (RFC 3225).
// Sent as primary UDP probe: response confirms the upstream is up AND lets
// us detect DNSSEC validation support (AD bit in the reply header).
//
// Header (12) + Question (5: root IN A) + OPT RR (11) = 28 bytes
//   OPT: name=0x00, type=0x0029, class=0x1000 (4096 UDP payload),
//        TTL=0x00008000 (DO=1, version=0, ext-rcode=0), rdlen=0x0000
const DNS_PROBE_PACKET: [u8; 28] = [
    0x00, 0x01, // ID
    0x01, 0x00, // flags: RD=1
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x00, // ANCOUNT = 0
    0x00, 0x00, // NSCOUNT = 0
    0x00, 0x01, // ARCOUNT = 1 (OPT RR)
    0x00,       // root label (empty name = ".")
    0x00, 0x01, // QTYPE = A
    0x00, 0x01, // QCLASS = IN
    // OPT RR
    0x00,             // Name = root
    0x00, 0x29,       // Type = OPT (41)
    0x10, 0x00,       // Class = 4096 (UDP payload size)
    0x00, 0x00, 0x80, 0x00, // TTL: ext-rcode=0, version=0, DO=1, Z=0
    0x00, 0x00,       // RDLENGTH = 0
];

// ── Status per upstream ────────────────────────────────────────────────────
#[derive(Serialize, Deserialize, Clone)]
pub struct UpstreamStatus {
    pub id:         String,
    pub addr:       String,
    /// Explicit DNS port — defaults to 53 (UDP) or 853 (DoT).
    pub port:       u16,
    pub name:       Option<String>,
    pub protocol:   String,   // "udp" or "dot"
    pub healthy:    bool,
    pub latency_ms: Option<u64>,
    pub last_check: String,
    pub zone:       String,
    /// #48: whether the upstream validates DNSSEC (AD bit in probe response).
    /// None = not yet probed or upstream is unhealthy.
    /// Omitted from JSON when None; not persisted (runtime only).
    #[serde(skip_serializing_if = "Option::is_none", skip_deserializing, default)]
    pub dnssec_supported: Option<bool>,
    /// #49: rolling buffer of the last 5 latency measurements (ms).
    /// Not persisted; serialised as a JSON array.
    #[serde(serialize_with = "serialize_latency_history", skip_deserializing, default)]
    pub latency_history: VecDeque<u64>,
    /// #53: last error message from a failed health probe.
    /// Cleared on successful probe. Not persisted (runtime only).
    #[serde(skip_serializing_if = "Option::is_none", skip_deserializing, default)]
    pub last_error: Option<String>,
    /// #56: TLS server name used for SNI. Required for DoT — if None,
    /// derived automatically from well-known IPs.
    /// Persisted; None for UDP upstreams.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tls_hostname: Option<String>,
    // Internal backoff state — not serialised in API responses.
    #[serde(skip, default)]
    pub consecutive_failures: u32,
    #[serde(skip, default = "Instant::now")]
    pub next_check_at: Instant,
}

fn serialize_latency_history<S>(v: &VecDeque<u64>, s: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    let vec: Vec<u64> = v.iter().copied().collect();
    serde::Serialize::serialize(&vec, s)
}

/// #49: push a new latency sample, capping the history at 5 entries.
pub fn push_latency(history: &mut VecDeque<u64>, latency_ms: u64) {
    if history.len() >= 5 {
        history.pop_front();
    }
    history.push_back(latency_ms);
}

/// #48: extract the AD (Authenticated Data) bit from a DNS response.
/// AD = bit 5 of flags byte 3 (byte[3] & 0x20).
pub fn parse_ad_bit(response: &[u8]) -> bool {
    response.get(3).map(|&b| b & 0x20 != 0).unwrap_or(false)
}

pub type SharedUpstreams = Arc<RwLock<Vec<UpstreamStatus>>>;

// ── Persistence format ─────────────────────────────────────────────────────
// Only durable fields are saved; runtime health state is not persisted.
#[derive(Serialize, Deserialize)]
struct PersistedUpstream {
    id:           String,
    addr:         String,
    port:         u16,
    protocol:     String,
    name:         Option<String>,
    zone:         String,
    #[serde(default)]
    tls_hostname: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct UpstreamsFile {
    upstreams: Vec<PersistedUpstream>,
}

/// Persist all upstreams to `base_dir/upstreams.json` + optional .mac sidecar.
pub fn save_upstreams(upstreams: &SharedUpstreams, base_dir: &Path) {
    let list = upstreams.read()
        .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in save_upstreams: {e}"));
    let file = UpstreamsFile {
        upstreams: list.iter().map(|u| PersistedUpstream {
            id:           u.id.clone(),
            addr:         u.addr.clone(),
            port:         u.port,
            protocol:     u.protocol.clone(),
            name:         u.name.clone(),
            zone:         u.zone.clone(),
            tls_hostname: u.tls_hostname.clone(),
        }).collect(),
    };
    drop(list);

    let path = base_dir.join("upstreams.json");
    let json = match serde_json::to_string_pretty(&file) {
        Ok(s) => s,
        Err(e) => { warn!(%e, "upstreams: serialisation failed"); return; }
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, &json) {
        warn!(%e, path = %path.display(), "upstreams: write failed");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        warn!(%e, path = %path.display(), "upstreams: rename failed");
        return;
    }
    let key = crate::integrity::store_key();
    if let Err(e) = crate::integrity::write_mac(&path, json.as_bytes(), key.as_deref()) {
        warn!(%e, "upstreams: .mac write failed");
    }
}

/// Load persisted upstreams from `base_dir/upstreams.json`.
/// Returns an empty Vec (no error) if the file is absent.
/// Refuses load on HMAC mismatch.
pub fn load_upstreams(base_dir: &Path) -> Vec<UpstreamStatus> {
    let path = base_dir.join("upstreams.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return vec![],
        Err(e) => {
            warn!(%e, path = %path.display(), "upstreams: read failed");
            return vec![];
        }
    };
    let key = crate::integrity::store_key();
    if let Err(e) = crate::integrity::verify_mac(&path, content.as_bytes(), key.as_deref()) {
        warn!(%e, "upstreams: HMAC mismatch — refusing to load persisted upstreams");
        return vec![];
    }
    let file: UpstreamsFile = match serde_json::from_str(&content) {
        Ok(f) => f,
        Err(e) => {
            warn!(%e, path = %path.display(), "upstreams: JSON parse failed");
            return vec![];
        }
    };
    file.upstreams.into_iter().map(|p| UpstreamStatus {
        id:                   p.id,
        addr:                 p.addr,
        port:                 p.port,
        name:                 p.name,
        protocol:             p.protocol,
        zone:                 p.zone,
        tls_hostname:         p.tls_hostname,
        healthy:              false,
        latency_ms:           None,
        last_check:           String::new(),
        dnssec_supported:     None,
        latency_history:      VecDeque::new(),
        last_error:           None,
        consecutive_failures: 0,
        next_check_at:        Instant::now(),
    }).collect()
}

// ── Backoff schedule ───────────────────────────────────────────────────────
// 1st failure → retry in 30s, 2nd → 60s, 3rd → 120s, 4th+ → 300s cap.
fn backoff_secs(consecutive_failures: u32) -> u64 {
    match consecutive_failures {
        0 | 1 => PROBE_INTERVAL_SECS,
        2     => 60,
        3     => 120,
        _     => 300,
    }
}

// ── Parse port from "ip@port" addr string ─────────────────────────────────
fn parse_addr_port(addr: &str, default_port: u16) -> (String, u16) {
    if let Some(at) = addr.find('@') {
        let port = addr[at + 1..].parse().unwrap_or(default_port);
        (addr[..at].to_string(), port)
    } else {
        (addr.to_string(), default_port)
    }
}

// ── Initialise from config ─────────────────────────────────────────────────
pub fn init_upstreams(cfg: &UnboundConfig) -> SharedUpstreams {
    let mut statuses = Vec::new();
    for fz in &cfg.forward_zones {
        let default_port: u16 = if fz.tls { 853 } else { 53 };
        for addr in &fz.addrs {
            let (clean, port) = parse_addr_port(addr, default_port);
            statuses.push(UpstreamStatus {
                id:                  uuid::Uuid::new_v4().to_string(),
                addr:                clean,
                port,
                name:                None,
                protocol:            if fz.tls { "dot".into() } else { "udp".into() },
                zone:                fz.name.clone(),
                tls_hostname:        None,
                healthy:             false,
                latency_ms:          None,
                last_check:          String::new(),
                dnssec_supported:    None,
                latency_history:     VecDeque::new(),
                last_error:          None,
                consecutive_failures: 0,
                next_check_at:       Instant::now(),
            });
        }
    }
    Arc::new(RwLock::new(statuses))
}

/// Merge persisted API upstreams into the config-file baseline.
/// When (addr, protocol) duplicates exist, the persisted entry wins.
pub fn merge_persisted(shared: &SharedUpstreams, persisted: Vec<UpstreamStatus>) {
    if persisted.is_empty() { return; }
    let mut list = shared.write()
        .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in merge_persisted: {e}"));
    for p in persisted {
        list.retain(|u| !(u.addr == p.addr && u.protocol == p.protocol));
        list.push(p);
    }
}

/// Add a runtime upstream (POST /api/upstreams). Returns the new entry.
pub fn add_upstream(
    upstreams:    &SharedUpstreams,
    addr:         String,
    port:         u16,
    protocol:     String,
    name:         Option<String>,
    tls_hostname: Option<String>,
) -> UpstreamStatus {
    let entry = UpstreamStatus {
        id:                  uuid::Uuid::new_v4().to_string(),
        addr,
        port,
        name,
        protocol,
        tls_hostname,
        healthy:             false,
        latency_ms:          None,
        last_check:          String::new(),
        dnssec_supported:    None,
        latency_history:     VecDeque::new(),
        last_error:          None,
        zone:                ".".into(),
        consecutive_failures: 0,
        next_check_at:       Instant::now(),
    };
    upstreams.write()
        .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in add_upstream: {e}"))
        .push(entry.clone());
    entry
}

/// Remove a runtime upstream by id (DELETE /api/upstreams/:id).
/// Returns the removed entry if found.
pub fn remove_upstream(upstreams: &SharedUpstreams, id: &str) -> Option<UpstreamStatus> {
    let mut list = upstreams.write()
        .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in remove_upstream: {e}"));
    list.iter().position(|u| u.id == id).map(|pos| list.remove(pos))
}

/// #50: Rename an upstream in-place. Used in unit tests; production code
/// patches fields directly in the handler to handle multiple fields atomically.
#[allow(dead_code)]
pub fn patch_upstream_name(
    upstreams: &SharedUpstreams,
    id: &str,
    name: Option<String>,
) -> Option<UpstreamStatus> {
    let mut list = upstreams.write()
        .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in patch_upstream_name: {e}"));
    if let Some(u) = list.iter_mut().find(|u| u.id == id) {
        u.name = name;
        Some(u.clone())
    } else {
        None
    }
}

/// Snapshot of (addr, port, use_tls, tls_hostname) for resolver rebuilds.
pub fn upstream_addrs(upstreams: &SharedUpstreams) -> Vec<(String, u16, bool, Option<String>)> {
    upstreams.read()
        .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in upstream_addrs: {e}"))
        .iter()
        .map(|u| (u.addr.clone(), u.port, u.protocol == "dot", u.tls_hostname.clone()))
        .collect()
}

// ── Background health loop ─────────────────────────────────────────────────
pub async fn upstream_health_loop(upstreams: SharedUpstreams) {
    let mut interval = time::interval(Duration::from_secs(PROBE_INTERVAL_SECS));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let now = Instant::now();

        // Collect (id, addr, port, protocol) for upstreams that are due for a probe.
        // Use UUID (not index) to avoid TOCTOU: the Vec may be reordered between
        // the snapshot and the write-back if an upstream is added/removed via API.
        let to_probe: Vec<(String, String, u16, String)> = {
            upstreams
                .read()
                .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in health task: {e}"))
                .iter()
                .filter(|s| now >= s.next_check_at)
                .map(|s| (s.id.clone(), s.addr.clone(), s.port, s.protocol.clone()))
                .collect()
        };

        // Probe each due upstream in parallel using spawn_blocking (blocking I/O).
        // join_all runs all probes concurrently instead of serially, so N × timeout
        // does not stall the runtime on unhealthy upstreams.
        let handles: Vec<_> = to_probe
            .into_iter()
            .map(|(id, addr, port, protocol)| {
                tokio::task::spawn_blocking(move || {
                    let (healthy, latency, dnssec, last_error) = probe_upstream(&addr, port, &protocol);
                    (id, healthy, latency, dnssec, last_error)
                })
            })
            .collect();
        let results: Vec<ProbeResultWithId> =
            futures_util::future::join_all(handles)
                .await
                .into_iter()
                .filter_map(|r| r.ok())
                .collect();

        // Write results back, matching by UUID to avoid index aliasing.
        let mut statuses = upstreams.write()
            .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in health task: {e}"));
        let now_str = crate::logbuffer::format_ts(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        for (id, healthy, latency_ms, dnssec_supported, last_error) in results {
            let Some(s) = statuses.iter_mut().find(|u| u.id == id) else { continue };
            if healthy {
                if s.consecutive_failures > 0 {
                    info!(
                        upstream = %s.addr,
                        failures = s.consecutive_failures,
                        "upstream recovered after {} failure(s)", s.consecutive_failures,
                    );
                }
                s.consecutive_failures = 0;
                s.next_check_at = Instant::now() + Duration::from_secs(PROBE_INTERVAL_SECS);
                // #49: push latency sample (only on successful probes)
                if let Some(lat) = latency_ms {
                    push_latency(&mut s.latency_history, lat);
                }
                // #48: update DNSSEC detection result
                s.dnssec_supported = dnssec_supported;
                // #53: clear last_error on success
                s.last_error = None;
            } else {
                s.consecutive_failures += 1;
                let wait = backoff_secs(s.consecutive_failures);
                warn!(
                    upstream        = %s.addr,
                    attempt         = s.consecutive_failures,
                    next_check_secs = wait,
                    "Upstream DNS health check failed (attempt {}) — next check in {}s",
                    s.consecutive_failures, wait,
                );
                s.next_check_at = Instant::now() + Duration::from_secs(wait);
                // #48: unhealthy → dnssec_supported = None
                s.dnssec_supported = None;
                // #49: do NOT push to history on failure
                // #53: record last_error
                s.last_error = last_error;
            }
            s.healthy    = healthy;
            s.latency_ms = latency_ms;
            s.last_check = now_str.clone();
        }
    }
}

// ── Probe result type ─────────────────────────────────────────────────────
/// Return type of `probe_upstream` and its variants:
/// `(healthy, latency_ms, dnssec_supported, last_error)`.
type ProbeResult = (bool, Option<u64>, Option<bool>, Option<String>);

/// Health-loop result tuple enriched with the upstream UUID:
/// `(id, healthy, latency_ms, dnssec_supported, last_error)`.
type ProbeResultWithId = (String, bool, Option<u64>, Option<bool>, Option<String>);

// ── Probe dispatcher ──────────────────────────────────────────────────────
// Returns (healthy, latency_ms, dnssec_supported, last_error).
pub fn probe_upstream(addr: &str, port: u16, protocol: &str) -> ProbeResult {
    if protocol == "dot" {
        probe_dot(addr, port)
    } else {
        probe_udp(addr, port)
    }
}

// ── UDP probe — sends EDNS0+DO query, checks AD bit (#48) ─────────────────
fn probe_udp(addr: &str, port: u16) -> ProbeResult {
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return (false, None, None, Some("bind failed".into())),
    };
    let target = SocketAddr::new(ip, port);
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => BIND_V4,
        IpAddr::V6(_) => BIND_V6,
    };

    let sock = match UdpSocket::bind(bind) {
        Ok(s)  => s,
        Err(_) => return (false, None, None, Some("bind failed".into())),
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(PROBE_TIMEOUT_MS)));

    let t0 = Instant::now();
    if sock.send_to(&DNS_PROBE_PACKET, target).is_err() {
        return (false, None, None, Some("send failed".into()));
    }

    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) if n >= 12 => {
            if buf[0] == DNS_PROBE_PACKET[0] && buf[1] == DNS_PROBE_PACKET[1] {
                let latency = Some(t0.elapsed().as_millis() as u64);
                // #48: AD bit = bit 5 of flags byte 3
                let dnssec = Some(parse_ad_bit(&buf[..n]));
                (true, latency, dnssec, None)
            } else {
                (false, None, None, Some("id mismatch".into()))
            }
        }
        Ok((n, _)) if n < 12 => (false, None, None, Some("short response".into())),
        _ => (false, None, None, Some("timeout".into())),
    }
}

// ── DoT probe (TCP + TLS + DNS round-trip, RFC 7858) ─────────────────────
// Sends DNS_PROBE_PACKET over an established TLS session with the 2-byte TCP
// length prefix required by RFC 7858. A matching response ID confirms the
// upstream is both reachable and answering DNS. The AD bit is checked so
// DNSSEC detection works identically for DoT and UDP upstreams.
fn probe_dot(addr: &str, port: u16) -> ProbeResult {
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return (false, None, None, Some("TCP connect failed".into())),
    };
    let target  = SocketAddr::new(ip, port);
    let timeout = Duration::from_millis(PROBE_TIMEOUT_MS);

    let t0 = Instant::now();

    // Step 1: TCP connect
    let tcp = match TcpStream::connect_timeout(&target, timeout) {
        Ok(s)  => s,
        Err(_) => return (false, None, None, Some("TCP connect failed".into())),
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    // Step 2: TLS handshake
    let server_name = match rustls::pki_types::ServerName::try_from(addr.to_owned()) {
        Ok(n)  => n,
        Err(_) => return (false, None, None, Some("TLS handshake failed".into())),
    };
    let config = Arc::new(
        rustls::ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("TLS protocol versions: {e}"))
        .with_root_certificates(build_tls_roots())
        .with_no_client_auth(),
    );
    let conn = match rustls::ClientConnection::new(config, server_name) {
        Ok(c)  => c,
        Err(_) => return (false, None, None, Some("TLS handshake failed".into())),
    };
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    // Step 3: send DNS query with 2-byte TCP length prefix (RFC 7858 §3.3)
    let len_prefix = (DNS_PROBE_PACKET.len() as u16).to_be_bytes();
    if tls.write_all(&len_prefix).is_err() || tls.write_all(&DNS_PROBE_PACKET).is_err() {
        return (false, None, None, Some("DNS send failed".into()));
    }

    // Step 4: read response length
    let mut resp_len_buf = [0u8; 2];
    if tls.read_exact(&mut resp_len_buf).is_err() {
        return (false, None, None, Some("DNS response timeout".into()));
    }
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    if resp_len < 12 {
        return (false, None, None, Some("short response".into()));
    }

    // Step 5: read response body
    let mut buf = vec![0u8; resp_len];
    if tls.read_exact(&mut buf).is_err() {
        return (false, None, None, Some("DNS response timeout".into()));
    }

    // Step 6: verify ID match and extract AD bit
    if buf[0] == DNS_PROBE_PACKET[0] && buf[1] == DNS_PROBE_PACKET[1] {
        let latency = Some(t0.elapsed().as_millis() as u64);
        let dnssec  = Some(parse_ad_bit(&buf));
        (true, latency, dnssec, None)
    } else {
        (false, None, None, Some("id mismatch".into()))
    }
}

// ── TLS root-CA store ─────────────────────────────────────────────────────
// Attempts to load system native CAs; falls back to bundled WebPKI roots.
fn build_tls_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    for cert in result.certs {
        roots.add(cert).ok();
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    roots
}

// ── Tests ─────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── Network probes (ignored by default) ──────────────────────────────

    #[test]
    #[ignore = "requires network access to 1.1.1.1:853"]
    fn probe_dot_cloudflare_healthy() {
        let (healthy, latency, _dnssec, last_error) = probe_upstream("1.1.1.1", 853, "dot");
        assert!(healthy, "Cloudflare DoT 1.1.1.1:853 should be healthy");
        assert!(latency.is_some());
        assert!(last_error.is_none());
    }

    #[test]
    #[ignore = "requires network access to 1.1.1.1:53"]
    fn probe_udp_cloudflare_healthy() {
        let (healthy, latency, dnssec, last_error) = probe_upstream("1.1.1.1", 53, "udp");
        assert!(healthy, "Cloudflare UDP 1.1.1.1:53 should be healthy");
        assert!(latency.is_some());
        // Cloudflare validates DNSSEC — AD bit expected
        assert_eq!(dnssec, Some(true), "Cloudflare should set AD bit");
        assert!(last_error.is_none());
    }

    #[test]
    fn probe_dot_unreachable_returns_false() {
        // 192.0.2.0/24 is TEST-NET-1 — guaranteed unreachable (RFC 5737)
        let (healthy, latency, dnssec, last_error) = probe_upstream("192.0.2.1", 853, "dot");
        assert!(!healthy, "unreachable host must not be reported healthy");
        assert!(latency.is_none());
        assert!(dnssec.is_none());
        // #53: TCP connect to TEST-NET must produce a connect error
        assert_eq!(last_error.as_deref(), Some("TCP connect failed"));
    }

    // ── #48: parse_ad_bit ─────────────────────────────────────────────────

    #[test]
    fn parse_ad_bit_set() {
        // byte[3] = 0x20 → AD bit set (QR=0, AA=0, TC=0, RD=0, RA=0, Z=0, AD=1)
        let mut buf = [0u8; 12];
        buf[3] = 0x20;
        assert!(parse_ad_bit(&buf), "AD bit should be detected when byte[3] & 0x20");
    }

    #[test]
    fn parse_ad_bit_not_set() {
        let buf = [0u8; 12];
        assert!(!parse_ad_bit(&buf), "AD bit should be false when byte[3] = 0");
    }

    #[test]
    fn parse_ad_bit_other_flags_ignored() {
        // byte[3] = 0xDF = all bits except AD (0x20)
        let mut buf = [0u8; 12];
        buf[3] = 0xdf;
        assert!(!parse_ad_bit(&buf), "AD bit should be false when bit5 is 0");
    }

    #[test]
    fn parse_ad_bit_short_response_returns_false() {
        let buf = [0xffu8; 3]; // only 3 bytes — byte[3] absent
        assert!(!parse_ad_bit(&buf));
    }

    // ── #49: latency history ──────────────────────────────────────────────

    #[test]
    fn latency_history_fills_to_three() {
        let mut history = VecDeque::new();
        for i in 1..=3 { push_latency(&mut history, i * 10); }
        assert_eq!(history.len(), 3);
        assert_eq!(history[2], 30);
    }

    #[test]
    fn latency_history_caps_at_five() {
        let mut history = VecDeque::new();
        for i in 1..=7 { push_latency(&mut history, i * 10); }
        assert_eq!(history.len(), 5, "history must be capped at 5");
        // First two (10, 20) dropped; remaining [30,40,50,60,70]
        assert_eq!(history[0], 30, "oldest retained entry should be 30ms");
        assert_eq!(history[4], 70, "newest entry should be 70ms");
    }

    #[test]
    fn latency_history_failed_probe_unchanged() {
        let mut history = VecDeque::new();
        push_latency(&mut history, 10);
        push_latency(&mut history, 20);
        push_latency(&mut history, 30);
        let snapshot: Vec<u64> = history.iter().copied().collect();
        // Simulate a failed probe: do NOT call push_latency
        let after: Vec<u64> = history.iter().copied().collect();
        assert_eq!(snapshot, after, "history must be unchanged after a failed probe");
    }

    // ── #48: upstream unhealthy → dnssec_supported = None ────────────────

    #[test]
    fn probe_unreachable_udp_dnssec_none() {
        // 192.0.2.0/24 is TEST-NET-1 — guaranteed unreachable (RFC 5737)
        let (healthy, _lat, dnssec, last_error) = probe_upstream("192.0.2.1", 53, "udp");
        assert!(!healthy);
        assert!(dnssec.is_none(), "unhealthy upstream must have dnssec_supported = None");
        // #53: UDP timeout to TEST-NET must produce a timeout error
        assert_eq!(last_error.as_deref(), Some("timeout"));
    }

    // ── #53: last_error cleared on successful probe ───────────────────────

    #[test]
    fn parse_last_error_cleared_on_healthy() {
        let upstreams = init_upstreams(&crate::config::parser::UnboundConfig::default());
        let entry = add_upstream(&upstreams, "1.1.1.1".into(), 53, "udp".into(), None, None);
        // Simulate a previous failure
        {
            let mut list = upstreams.write().unwrap_or_else(|e| e.into_inner());
            let s = list.iter_mut().find(|u| u.id == entry.id).unwrap_or_else(|| panic!("entry not found"));
            s.last_error = Some("timeout".into());
            s.healthy = false;
        }
        // Simulate a successful write-back (healthy=true → clear last_error)
        {
            let mut list = upstreams.write().unwrap_or_else(|e| e.into_inner());
            let s = list.iter_mut().find(|u| u.id == entry.id).unwrap_or_else(|| panic!("entry not found"));
            s.healthy    = true;
            s.last_error = None;
        }
        let list = upstreams.read().unwrap_or_else(|e| e.into_inner());
        let s = list.iter().find(|u| u.id == entry.id).unwrap_or_else(|| panic!("entry not found"));
        assert!(s.last_error.is_none(), "last_error must be None after a successful probe");
        assert!(s.healthy);
    }

    // ── #50: patch_upstream_name ──────────────────────────────────────────

    #[test]
    fn patch_upstream_name_updates_name() {
        let upstreams = init_upstreams(&crate::config::parser::UnboundConfig::default());
        let entry = add_upstream(&upstreams, "1.1.1.1".into(), 53, "udp".into(), None, None);
        let updated = patch_upstream_name(&upstreams, &entry.id, Some("Test".into()));
        assert!(updated.is_some());
        assert_eq!(updated.unwrap().name.as_deref(), Some("Test"));
    }

    #[test]
    fn patch_upstream_name_unknown_id_returns_none() {
        let upstreams = init_upstreams(&crate::config::parser::UnboundConfig::default());
        let result = patch_upstream_name(&upstreams, "nonexistent-id", Some("x".into()));
        assert!(result.is_none());
    }

    #[test]
    fn patch_upstream_name_none_clears_name() {
        let upstreams = init_upstreams(&crate::config::parser::UnboundConfig::default());
        let entry = add_upstream(&upstreams, "1.1.1.1".into(), 53, "udp".into(), Some("Old".into()), None);
        let updated = patch_upstream_name(&upstreams, &entry.id, None);
        assert!(updated.unwrap().name.is_none());
    }
}
