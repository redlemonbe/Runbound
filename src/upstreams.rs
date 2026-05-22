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

use std::io::Write;
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

// Minimal RFC 1035 DNS query: id=0x0001, RD=1, QDCOUNT=1, `. IN A`
// 17 bytes total (header 12 + root label 1 + qtype 2 + qclass 2)
const DNS_PROBE_PACKET: [u8; 17] = [
    0x00, 0x01, // ID
    0x01, 0x00, // flags: RD=1
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x00, // ANCOUNT = 0
    0x00, 0x00, // NSCOUNT = 0
    0x00, 0x00, // ARCOUNT = 0
    0x00,       // root label (empty name = ".")
    0x00, 0x01, // QTYPE = A
    0x00, 0x01, // QCLASS = IN
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
    // Internal backoff state — not serialised in API responses.
    #[serde(skip, default)]
    pub consecutive_failures: u32,
    #[serde(skip, default = "Instant::now")]
    pub next_check_at: Instant,
}

pub type SharedUpstreams = Arc<RwLock<Vec<UpstreamStatus>>>;

// ── Persistence format ─────────────────────────────────────────────────────
// Only durable fields are saved; runtime health state is not persisted.
#[derive(Serialize, Deserialize)]
struct PersistedUpstream {
    id:       String,
    addr:     String,
    port:     u16,
    protocol: String,
    name:     Option<String>,
    zone:     String,
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
            id:       u.id.clone(),
            addr:     u.addr.clone(),
            port:     u.port,
            protocol: u.protocol.clone(),
            name:     u.name.clone(),
            zone:     u.zone.clone(),
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
        healthy:              false,
        latency_ms:           None,
        last_check:           String::new(),
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
                healthy:             false,
                latency_ms:          None,
                last_check:          String::new(),
                zone:                fz.name.clone(),
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
    upstreams: &SharedUpstreams,
    addr:      String,
    port:      u16,
    protocol:  String,
    name:      Option<String>,
) -> UpstreamStatus {
    let entry = UpstreamStatus {
        id:                  uuid::Uuid::new_v4().to_string(),
        addr,
        port,
        name,
        protocol,
        healthy:             false,
        latency_ms:          None,
        last_check:          String::new(),
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

/// Snapshot of (addr, port, use_tls) for resolver rebuilds.
pub fn upstream_addrs(upstreams: &SharedUpstreams) -> Vec<(String, u16, bool)> {
    upstreams.read()
        .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in upstream_addrs: {e}"))
        .iter()
        .map(|u| (u.addr.clone(), u.port, u.protocol == "dot"))
        .collect()
}

// ── Background health loop ─────────────────────────────────────────────────
pub async fn upstream_health_loop(upstreams: SharedUpstreams) {
    let mut interval = time::interval(Duration::from_secs(PROBE_INTERVAL_SECS));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let now = Instant::now();

        // Collect (index, addr, port, protocol) for upstreams that are due for a probe.
        let to_probe: Vec<(usize, String, u16, String)> = {
            upstreams
                .read()
                .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in health task: {e}"))
                .iter()
                .enumerate()
                .filter(|(_, s)| now >= s.next_check_at)
                .map(|(i, s)| (i, s.addr.clone(), s.port, s.protocol.clone()))
                .collect()
        };

        // Probe each due upstream (blocking I/O — UDP for plain, TCP+TLS for DoT).
        let results: Vec<(usize, bool, Option<u64>)> = to_probe
            .iter()
            .map(|(i, addr, port, protocol)| {
                let (healthy, latency) = probe_upstream(addr, *port, protocol);
                (*i, healthy, latency)
            })
            .collect();

        // Write results back, updating backoff state.
        let mut statuses = upstreams.write()
            .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in health task: {e}"));
        let now_str = crate::logbuffer::format_ts(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        for (idx, healthy, latency_ms) in results {
            let Some(s) = statuses.get_mut(idx) else { continue };
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
            }
            s.healthy    = healthy;
            s.latency_ms = latency_ms;
            s.last_check = now_str.clone();
        }
    }
}

// ── Probe dispatcher ──────────────────────────────────────────────────────
fn probe_upstream(addr: &str, port: u16, protocol: &str) -> (bool, Option<u64>) {
    if protocol == "dot" {
        probe_dot(addr, port)
    } else {
        probe_udp(addr, port)
    }
}

// ── UDP probe ─────────────────────────────────────────────────────────────
fn probe_udp(addr: &str, port: u16) -> (bool, Option<u64>) {
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return (false, None),
    };
    let target = SocketAddr::new(ip, port);
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => BIND_V4,
        IpAddr::V6(_) => BIND_V6,
    };

    let sock = match UdpSocket::bind(bind) {
        Ok(s)  => s,
        Err(_) => return (false, None),
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(PROBE_TIMEOUT_MS)));

    let t0 = Instant::now();
    if sock.send_to(&DNS_PROBE_PACKET, target).is_err() {
        return (false, None);
    }

    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) if n >= 2 => {
            if buf[0] == DNS_PROBE_PACKET[0] && buf[1] == DNS_PROBE_PACKET[1] {
                (true, Some(t0.elapsed().as_millis() as u64))
            } else {
                (false, None)
            }
        }
        _ => (false, None),
    }
}

// ── DoT probe (TCP + TLS handshake) ───────────────────────────────────────
// A successful TLS handshake is sufficient proof that the server is up and
// speaking TLS on the expected port. No DNS query is sent.
fn probe_dot(addr: &str, port: u16) -> (bool, Option<u64>) {
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return (false, None),
    };
    let target   = SocketAddr::new(ip, port);
    let timeout  = Duration::from_millis(PROBE_TIMEOUT_MS);

    let t0 = Instant::now();

    // Step 1: TCP connect
    let tcp = match TcpStream::connect_timeout(&target, timeout) {
        Ok(s)  => s,
        Err(_) => return (false, None),
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    // Step 2: TLS handshake — server name derived from the IP address
    let server_name = match rustls::pki_types::ServerName::try_from(addr.to_owned()) {
        Ok(n)  => n,
        Err(_) => return (false, None),
    };
    // Use the ring provider explicitly — avoids relying on a process-level
    // install_default() that may not have run outside of the main binary.
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
        Err(_) => return (false, None),
    };
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    // flush() → complete_io() → blocks until TLS handshake is done or fails
    match tls.flush() {
        Ok(()) => (true, Some(t0.elapsed().as_millis() as u64)),
        Err(_) => (false, None),
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

    #[test]
    #[ignore = "requires network access to 1.1.1.1:853"]
    fn probe_dot_cloudflare_healthy() {
        let (healthy, latency) = probe_upstream("1.1.1.1", 853, "dot");
        assert!(healthy, "Cloudflare DoT 1.1.1.1:853 should be healthy");
        assert!(latency.is_some());
    }

    #[test]
    #[ignore = "requires network access to 1.1.1.1:53"]
    fn probe_udp_cloudflare_healthy() {
        let (healthy, latency) = probe_upstream("1.1.1.1", 53, "udp");
        assert!(healthy, "Cloudflare UDP 1.1.1.1:53 should be healthy");
        assert!(latency.is_some());
    }

    #[test]
    fn probe_dot_unreachable_returns_false() {
        // 192.0.2.0/24 is TEST-NET-1 — guaranteed unreachable (RFC 5737)
        let (healthy, latency) = probe_upstream("192.0.2.1", 853, "dot");
        assert!(!healthy, "unreachable host must not be reported healthy");
        assert!(latency.is_none());
    }
}
