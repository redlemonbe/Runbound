// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Upstream DNS health monitoring.
//
// Probes each configured forward-addr every 30 seconds with a minimal UDP DNS
// query (`. IN A`). Reports latency and reachability. Never mutates resolver
// configuration — read-only diagnostic view.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::time;
use tracing::warn;

use crate::config::parser::UnboundConfig;

// ── Probe interval / timeout ───────────────────────────────────────────────
const PROBE_INTERVAL_SECS: u64 = 30;
const PROBE_TIMEOUT_MS:    u64 = 2_000;

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
    pub addr:       String,
    pub healthy:    bool,
    pub latency_ms: Option<u64>,
    pub last_check: String,
    pub zone:       String,
}

pub type SharedUpstreams = Arc<RwLock<Vec<UpstreamStatus>>>;

// ── Initialise from config ─────────────────────────────────────────────────
pub fn init_upstreams(cfg: &UnboundConfig) -> SharedUpstreams {
    let mut statuses = Vec::new();
    for fz in &cfg.forward_zones {
        for addr in &fz.addrs {
            // Strip port if present (e.g. "1.1.1.1@853")
            let clean = addr.split('@').next().unwrap_or(addr).to_string();
            statuses.push(UpstreamStatus {
                addr:       clean,
                healthy:    false,
                latency_ms: None,
                last_check: String::new(),
                zone:       fz.name.clone(),
            });
        }
    }
    Arc::new(RwLock::new(statuses))
}

// ── Background health loop ─────────────────────────────────────────────────
pub async fn upstream_health_loop(upstreams: SharedUpstreams) {
    let mut interval = time::interval(Duration::from_secs(PROBE_INTERVAL_SECS));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        // Collect addresses to probe (read-only snapshot)
        let addrs: Vec<String> = {
            upstreams.read().unwrap().iter().map(|s| s.addr.clone()).collect()
        };

        let mut results: Vec<(bool, Option<u64>)> = Vec::with_capacity(addrs.len());
        for addr in &addrs {
            results.push(probe_upstream(addr));
        }

        // Write results back
        let mut statuses = upstreams.write().unwrap();
        let now = crate::logbuffer::format_ts(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        for (i, (healthy, latency_ms)) in results.into_iter().enumerate() {
            if let Some(s) = statuses.get_mut(i) {
                if !healthy {
                    warn!(upstream = %s.addr, "Upstream DNS health check failed");
                }
                s.healthy    = healthy;
                s.latency_ms = latency_ms;
                s.last_check = now.clone();
            }
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
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
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
