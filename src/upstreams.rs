// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Upstream DNS health monitoring.
//
// Probes each configured forward-addr with a minimal UDP DNS query (`. IN A`).
// Reports latency and reachability. Never mutates resolver configuration —
// read-only diagnostic view.
//
// Backoff: a failing upstream is retried with exponential backoff (30s → 60s →
// 120s → 300s cap) so that a permanently unreachable server does not spam logs.
// On recovery, the backoff resets and an INFO message is emitted.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
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
#[derive(Serialize, Clone)]
pub struct UpstreamStatus {
    pub id:         String,
    pub addr:       String,
    pub name:       Option<String>,
    pub protocol:   String,   // "udp" or "dot"
    pub healthy:    bool,
    pub latency_ms: Option<u64>,
    pub last_check: String,
    pub zone:       String,
    // Internal backoff state — not serialised in API responses.
    #[serde(skip)]
    pub consecutive_failures: u32,
    #[serde(skip)]
    pub next_check_at: Instant,
}

pub type SharedUpstreams = Arc<RwLock<Vec<UpstreamStatus>>>;

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

// ── Initialise from config ─────────────────────────────────────────────────
pub fn init_upstreams(cfg: &UnboundConfig) -> SharedUpstreams {
    let mut statuses = Vec::new();
    for fz in &cfg.forward_zones {
        for addr in &fz.addrs {
            let clean = addr.split('@').next().unwrap_or(addr).to_string();
            statuses.push(UpstreamStatus {
                id:                  uuid::Uuid::new_v4().to_string(),
                addr:                clean,
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

/// Add a runtime upstream (POST /api/upstreams). Returns the new entry.
pub fn add_upstream(
    upstreams: &SharedUpstreams,
    addr:      String,
    protocol:  String,
    name:      Option<String>,
) -> UpstreamStatus {
    let entry = UpstreamStatus {
        id:                  uuid::Uuid::new_v4().to_string(),
        addr,
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
        .expect("upstreams: RwLock poisoned in add_upstream")
        .push(entry.clone());
    entry
}

/// Remove a runtime upstream by id (DELETE /api/upstreams/:id).
/// Returns the removed entry if found.
pub fn remove_upstream(upstreams: &SharedUpstreams, id: &str) -> Option<UpstreamStatus> {
    let mut list = upstreams.write().expect("upstreams: RwLock poisoned in remove_upstream");
    if let Some(pos) = list.iter().position(|u| u.id == id) {
        Some(list.remove(pos))
    } else {
        None
    }
}

/// Snapshot of (addr, use_tls) for resolver rebuilds.
pub fn upstream_addrs(upstreams: &SharedUpstreams) -> Vec<(String, bool)> {
    upstreams.read()
        .expect("upstreams: RwLock poisoned in upstream_addrs")
        .iter()
        .map(|u| (u.addr.clone(), u.protocol == "dot"))
        .collect()
}

// ── Background health loop ─────────────────────────────────────────────────
pub async fn upstream_health_loop(upstreams: SharedUpstreams) {
    let mut interval = time::interval(Duration::from_secs(PROBE_INTERVAL_SECS));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let now = Instant::now();

        // Collect (index, addr) for upstreams that are due for a probe.
        let to_probe: Vec<(usize, String)> = {
            upstreams
                .read()
                .expect("upstreams: RwLock poisoned in health task")
                .iter()
                .enumerate()
                .filter(|(_, s)| now >= s.next_check_at)
                .map(|(i, s)| (i, s.addr.clone()))
                .collect()
        };

        // Probe each due upstream (blocking UDP, no async needed).
        let results: Vec<(usize, bool, Option<u64>)> = to_probe
            .iter()
            .map(|(i, addr)| {
                let (healthy, latency) = probe_upstream(addr);
                (*i, healthy, latency)
            })
            .collect();

        // Write results back, updating backoff state.
        let mut statuses = upstreams.write().expect("upstreams: RwLock poisoned in health task");
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

// ── UDP probe — blocking, run via spawn_blocking ───────────────────────────
fn probe_upstream(addr: &str) -> (bool, Option<u64>) {
    // Parse address — default to port 53 if not specified
    let target: SocketAddr = {
        let with_port = if addr.contains(':') && !addr.starts_with('[') {
            // Bare IPv6 without brackets — treat as IP only
            format!("[{}]:53", addr)
        } else if addr.contains('@') {
            // Hickory-style "ip@port"
            let parts: Vec<&str> = addr.splitn(2, '@').collect();
            format!("{}:{}", parts[0], parts.get(1).copied().unwrap_or("53"))
        } else if addr.contains("]:") || (addr.contains('.') && addr.contains(':')) {
            // Already has port ("1.2.3.4:853" or "[::1]:853")
            addr.to_string()
        } else {
            format!("{}:53", addr)
        };
        match with_port.parse() {
            Ok(a)  => a,
            Err(_) => return (false, None),
        }
    };

    let bind: SocketAddr = match target.ip() {
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
            // Verify the response ID matches (bytes 0-1)
            if buf[0] == DNS_PROBE_PACKET[0] && buf[1] == DNS_PROBE_PACKET[1] {
                (true, Some(t0.elapsed().as_millis() as u64))
            } else {
                (false, None)
            }
        }
        _ => (false, None),
    }
}
