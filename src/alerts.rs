// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Issue #12 — Per-client alert thresholds: count, block, notify via webhook.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::Serialize;

use crate::config::parser::AlertRule;
use crate::icmp::IcmpBanCmd;

const MAX_CLIENT_BUCKETS: usize = 100_000;
const RECENT_ALERTS_CAP: usize = 200;
/// Hard cap on blocked IPs — prevents memory exhaustion under IP-rotation flood attacks.
const MAX_BLOCKED_ENTRIES: usize = 50_000;

#[derive(Debug, Clone, Serialize)]
pub struct AlertEvent {
    pub ts: u64,           // unix seconds
    pub rule: String,
    pub client_ip: String,
    pub count: u64,
    pub action: String,
}

struct ClientBucket {
    count: u64,
    window_start: Instant,
}

struct BlockEntry {
    expires: Option<Instant>, // None = permanent
    rule: String,
}

/// Verdict for a recorded query (#ddos): Serve = let through; Tarpit = delayed
/// REFUSED to waste a verified abuser's time on connection transports; Block = drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseVerdict {
    Serve,
    Tarpit,
    Block,
}

pub struct AlertTracker {
    rules: std::sync::RwLock<Vec<AlertRule>>,
    client_counts: DashMap<IpAddr, ClientBucket, ahash::RandomState>,
    blocked: DashMap<IpAddr, BlockEntry, ahash::RandomState>,
    tarpitted: DashMap<IpAddr, BlockEntry, ahash::RandomState>,
    recent: Mutex<VecDeque<AlertEvent>>,
    notify_tx: tokio::sync::mpsc::UnboundedSender<(String, AlertEvent)>,
    base_dir: Option<Arc<PathBuf>>,
    /// #ddos: XDP ban channel — wired only when XDP is attached (set_ban_tx).
    ban_tx: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<IcmpBanCmd>>,
}

impl AlertTracker {
    pub fn new(rules: Vec<AlertRule>, base_dir: Option<PathBuf>) -> std::sync::Arc<Self> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(String, AlertEvent)>();
        tokio::spawn(webhook_sender(rx));
        let base_dir_arc = base_dir.map(Arc::new);
        let tracker = std::sync::Arc::new(Self {
            rules: std::sync::RwLock::new(rules),
            client_counts: DashMap::with_hasher(ahash::RandomState::default()),
            blocked: DashMap::with_hasher(ahash::RandomState::default()),
            tarpitted: DashMap::with_hasher(ahash::RandomState::default()),
            recent: Mutex::new(VecDeque::new()),
            notify_tx: tx,
            base_dir: base_dir_arc,
            ban_tx: std::sync::OnceLock::new(),
        });
        tracker.load_blocks();
        tracker
    }

    fn blocks_path(&self) -> Option<PathBuf> {
        self.base_dir.as_ref().map(|d| d.join("alert-blocks.json"))
    }

    // SEC-B7: persist current block set to disk so bans survive restarts.
    fn persist_blocks(&self) {
        let Some(path) = self.blocks_path() else { return };
        let now = Instant::now();
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let entries: Vec<serde_json::Value> = self.blocked.iter()
            .filter_map(|e| {
                let ip = e.key();
                let entry = e.value();
                let expires_epoch = match entry.expires {
                    None => serde_json::Value::Null,
                    Some(exp) => {
                        let remaining = exp.saturating_duration_since(now).as_secs();
                        serde_json::json!(now_epoch + remaining)
                    }
                };
                Some(serde_json::json!({
                    "ip": ip.to_string(),
                    "rule": &entry.rule,
                    "expires_epoch": expires_epoch,
                }))
            })
            .collect();
        if let Ok(data) = serde_json::to_vec(&entries) {
            let _ = std::fs::write(&path, data);
        }
    }

    // SEC-B7: load block set from disk on startup.
    fn load_blocks(&self) {
        let Some(path) = self.blocks_path() else { return };
        let Ok(data) = std::fs::read_to_string(&path) else { return };
        let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&data) else { return };
        let now = Instant::now();
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut count = 0usize;
        for entry in entries {
            let ip_str = entry["ip"].as_str().unwrap_or("");
            let Ok(ip) = ip_str.parse::<IpAddr>() else { continue };
            let rule = entry["rule"].as_str().unwrap_or("unknown").to_string();
            let expires = match entry["expires_epoch"].as_u64() {
                None => None, // permanent
                Some(epoch) => {
                    if epoch <= now_epoch { continue } // already expired
                    Some(now + Duration::from_secs(epoch - now_epoch))
                }
            };
            self.blocked.insert(ip, BlockEntry { expires, rule });
            count += 1;
        }
        if count > 0 {
            tracing::info!(count, "Alert blocks loaded from disk");
        }
    }

    /// Returns true if this IP is currently blocked by an alert rule.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if let Some(entry) = self.blocked.get(&ip) {
            match entry.expires {
                None => return true,
                Some(exp) if Instant::now() < exp => return true,
                Some(_) => {
                    drop(entry);
                    self.blocked.remove(&ip);
                    self.xdp_push(ip, false);
                }
            }
        }
        false
    }

    /// #208: live (non-expired) counts of blocked + tarpitted IPs (for metrics).
    pub fn metrics(&self) -> (usize, usize) {
        let now = Instant::now();
        let live = |m: &DashMap<IpAddr, BlockEntry, ahash::RandomState>| {
            m.iter().filter(|e| e.value().expires.is_none_or(|x| now < x)).count()
        };
        (live(&self.blocked), live(&self.tarpitted))
    }

    /// Returns true if this IP is currently tarpitted (delayed responses).
    pub fn is_tarpitted(&self, ip: IpAddr) -> bool {
        if let Some(entry) = self.tarpitted.get(&ip) {
            match entry.expires {
                None => return true,
                Some(exp) if Instant::now() < exp => return true,
                Some(_) => {
                    drop(entry);
                    self.tarpitted.remove(&ip);
                }
            }
        }
        false
    }

    /// Record a query from `ip`. Returns true if the query should be blocked.
    ///
    /// `verified` is true only when the source IP is proven not spoofed: TCP / DoT /
    /// DoH / DoQ (connection), or a UDP query carrying a VALID server cookie. The
    /// per-IP counters and any escalation (block / notify) fire ONLY for verified
    /// sources — blocking on a spoofable UDP source would let an attacker spoof a
    /// victim's IP and get the victim banned (anti-spoof gate, #ddos). Unverified
    /// UDP floods are handled by the rate limiter + DNS cookies, not by banning.
    pub fn record(&self, ip: IpAddr, verified: bool) -> AbuseVerdict {
        // Honour an existing block regardless of rules: manual/API bans and bans
        // restored from disk must be enforced even when no alert rule is configured.
        // (A ban set while a source was verified still drops later, possibly spoofed,
        // packets claiming that IP — no new harm.)
        if self.is_blocked(ip) {
            return AbuseVerdict::Block;
        }

        if self.rules.read().unwrap().is_empty() {
            return AbuseVerdict::Serve;
        }

        // Anti-spoof: never count or escalate an unverified source.
        if !verified {
            return AbuseVerdict::Serve;
        }

        let now = Instant::now();

        // GC client_counts when table is full.
        if self.client_counts.len() >= MAX_CLIENT_BUCKETS {
            let max_window = self.rules.read().unwrap().iter().map(|r| r.window_s).max().unwrap_or(60);
            self.client_counts.retain(|_, b| {
                now.duration_since(b.window_start).as_secs() < max_window * 2
            });
        }

        let mut bucket = self.client_counts.entry(ip).or_insert_with(|| ClientBucket {
            count: 0,
            window_start: now,
        });

        // Check per-rule, smallest window first.
        {
            let rules = self.rules.read().unwrap();
            for rule in rules.iter() {
                if rule.metric != "client-qps" {
                    continue;
                }
                let elapsed = now.duration_since(bucket.window_start).as_secs();
                if elapsed >= rule.window_s {
                    bucket.count = 0;
                    bucket.window_start = now;
                }
            }
        }
        bucket.count += 1;
        let count = bucket.count;
        drop(bucket);

        let rules_snapshot: Vec<_> = self.rules.read().unwrap().clone();
        for rule in &rules_snapshot {
            if rule.metric != "client-qps" {
                continue;
            }
            if count == rule.threshold + 1 {
                // Crossed threshold — fire once per window
                self.trigger(ip, rule, count, now);
            }
        }

        if self.is_blocked(ip) {
            AbuseVerdict::Block
        } else if self.is_tarpitted(ip) {
            AbuseVerdict::Tarpit
        } else {
            AbuseVerdict::Serve
        }
    }

    fn trigger(&self, ip: IpAddr, rule: &AlertRule, count: u64, now: Instant) {
        let event = AlertEvent {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            rule: rule.name.clone(),
            client_ip: ip.to_string(),
            count,
            action: rule.action.clone(),
        };

        tracing::warn!(
            rule = %rule.name,
            ip = %ip,
            count = count,
            window_s = rule.window_s,
            action = %rule.action,
            "Alert threshold crossed"
        );

        match rule.action.as_str() {
            "block" if Self::is_ban_exempt(ip) => {
                tracing::warn!(ip = %ip, rule = %rule.name, "ban skipped: protected IP (loopback/unspecified)");
            }
            "block" => {
                if !self.blocked.contains_key(&ip) && self.blocked.len() >= MAX_BLOCKED_ENTRIES {
                    tracing::warn!(ip = %ip, "blocked map full -- ban dropped");
                } else {
                    let expires = if rule.block_duration_s == 0 {
                        None
                    } else {
                        Some(now + std::time::Duration::from_secs(rule.block_duration_s))
                    };
                    self.blocked.insert(ip, BlockEntry { expires, rule: rule.name.clone() });
                    self.persist_blocks();
                    self.xdp_push(ip, true);
                }
            }
            "tarpit" => {
                if !self.tarpitted.contains_key(&ip) && self.tarpitted.len() >= MAX_BLOCKED_ENTRIES {
                    tracing::warn!(ip = %ip, "tarpit map full -- entry dropped");
                } else {
                    let expires = if rule.block_duration_s == 0 {
                        None
                    } else {
                        Some(now + std::time::Duration::from_secs(rule.block_duration_s))
                    };
                    self.tarpitted.insert(ip, BlockEntry { expires, rule: rule.name.clone() });
                }
            }
            "notify" => {
                if let Some(url) = &rule.notify_url {
                    let _ = self.notify_tx.send((url.clone(), event.clone()));
                }
            }
            _ => {} // "log" — already logged above
        }

        if let Ok(mut q) = self.recent.lock() {
            if q.len() >= RECENT_ALERTS_CAP {
                q.pop_front();
            }
            q.push_back(event);
        }
    }

    /// API: snapshot of recent alerts, blocked clients, and rule list.
    pub fn api_snapshot(&self) -> serde_json::Value {
        let recent = self.recent.lock()
            .map(|q| q.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        let blocked: Vec<serde_json::Value> = self.blocked.iter()
            .filter_map(|e| {
                let ip = e.key();
                let entry = e.value();
                match entry.expires {
                    Some(exp) if Instant::now() >= exp => None,
                    expires_opt => Some(serde_json::json!({
                        "ip": ip.to_string(),
                        "rule": entry.rule,
                        "permanent": expires_opt.is_none(),
                        "expires_in_s": expires_opt.map(|exp| {
                            let rem = exp.saturating_duration_since(Instant::now());
                            rem.as_secs()
                        })
                    }))
                }
            })
            .collect();

        let rules: Vec<serde_json::Value> = self.rules.read().unwrap().iter().map(|r| serde_json::json!({
            "name": r.name,
            "metric": r.metric,
            "window_s": r.window_s,
            "threshold": r.threshold,
            "action": r.action,
            "block_duration_s": r.block_duration_s,
        })).collect();

        serde_json::json!({
            "rules": rules,
            "blocked_clients": blocked,
            "recent_alerts": recent,
        })
    }

    /// Unblock an IP (API: DELETE /api/alerts/blocked/{ip}).
    pub fn unblock(&self, ip: IpAddr) -> bool {
        let removed = self.blocked.remove(&ip).is_some();
        if removed {
            self.persist_blocks();
            self.xdp_push(ip, false);
        }
        removed
    }

    /// M-1: protected-IP allowlist. An operator misconfiguration (or a spoofed
    /// source that survives the verified-source gate) must never be able to push
    /// loopback or the unspecified address into the kernel ban map — that would
    /// drop the node's own traffic. The allowlist is intentionally conservative:
    /// loopback (127.0.0.0/8, ::1) and unspecified (0.0.0.0, ::). Upstream-resolver
    /// addresses are not reachable from this struct, so they are not covered here.
    fn is_ban_exempt(ip: IpAddr) -> bool {
        ip.is_loopback() || ip.is_unspecified()
    }

    /// #ddos: push a block/unblock to the XDP ban map (line-rate XDP_DROP) when an
    /// XDP ban channel is wired. IPv4 only (the BPF map is v4); IPv6 blocks stay
    /// enforced in userspace via is_blocked().
    fn xdp_push(&self, ip: IpAddr, ban: bool) {
        if let Some(tx) = self.ban_tx.get() {
            if let IpAddr::V4(v4) = ip {
                let _ = tx.send(if ban { IcmpBanCmd::Ban(v4) } else { IcmpBanCmd::Unban(v4) });
            }
        }
    }

    /// Wire the XDP ban channel — call ONCE, only when XDP is attached (otherwise
    /// nothing drains the channel and sends accumulate). Re-syncs already-loaded
    /// blocks (e.g. restored from disk) into the BPF map.
    pub fn set_ban_tx(&self, tx: tokio::sync::mpsc::UnboundedSender<IcmpBanCmd>) {
        if self.ban_tx.set(tx).is_err() {
            return;
        }
        for e in self.blocked.iter() {
            if let IpAddr::V4(v4) = *e.key() {
                self.xdp_push(IpAddr::V4(v4), true);
            }
        }
    }

    /// Hot-reload: replace the active alert rules without restarting (#149).
    pub fn update_rules(&self, new_rules: Vec<AlertRule>) {
        let count = new_rules.len();
        *self.rules.write().unwrap() = new_rules;
        tracing::info!(count, "alert rules updated via hot-reload");
    }

    /// Immediately block an IP without going through a rule threshold.
    /// Used by ICMP flood detector and relay propagation.
    pub fn block_manual(&self, ip: IpAddr, rule: String) {
        if Self::is_ban_exempt(ip) {
            tracing::warn!(ip = %ip, "manual ban skipped: protected IP (loopback/unspecified)");
            return;
        }
        if self.is_blocked(ip) {
            return;
        }
        if self.blocked.len() >= MAX_BLOCKED_ENTRIES {
            tracing::warn!(ip = %ip, "blocked map full -- manual ban dropped");
            return;
        }
        self.blocked.insert(ip, BlockEntry { expires: None, rule: rule.clone() });
        self.persist_blocks();
        self.xdp_push(ip, true);
        let event = AlertEvent {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            rule,
            client_ip: ip.to_string(),
            count: 0,
            action: "block".to_string(),
        };
        tracing::warn!(ip = %ip, "IP manually blocked");
        if let Ok(mut q) = self.recent.lock() {
            if q.len() >= RECENT_ALERTS_CAP {
                q.pop_front();
            }
            q.push_back(event);
        }
    }

    /// Block an IP for a fixed duration (used by bot defense). Emits an AlertEvent.
    pub fn block_bot(&self, ip: std::net::IpAddr, rule: &str, duration_secs: u64) {
        if Self::is_ban_exempt(ip) {
            tracing::warn!(ip = %ip, rule = rule, "bot ban skipped: protected IP (loopback/unspecified)");
            return;
        }
        if !self.blocked.contains_key(&ip) && self.blocked.len() >= MAX_BLOCKED_ENTRIES {
            tracing::warn!(ip = %ip, rule = rule, "blocked map full -- bot ban dropped");
            return;
        }
        let expires = if duration_secs == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(duration_secs))
        };
        self.blocked.insert(ip, BlockEntry { expires, rule: rule.to_string() });
        self.persist_blocks();
        let event = AlertEvent {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            rule: rule.to_string(),
            client_ip: ip.to_string(),
            count: 1,
            action: "block".to_string(),
        };
        // Note: block_bot does not dispatch to notify_tx (no URL context available here).
        // The event is recorded in recent_alerts; callers should use trigger() for webhook delivery.
        if let Ok(mut q) = self.recent.lock() {
            if q.len() >= RECENT_ALERTS_CAP { q.pop_front(); }
            q.push_back(event);
        }
        tracing::warn!(ip = %ip, rule = rule, "bot defense: IP banned via block_bot");
    }

    /// Remove all expired blocks from the tracker. Returns the list of evicted IPs.
    pub fn evict_expired(&self) -> Vec<std::net::IpAddr> {
        let now = Instant::now();
        let expired: Vec<std::net::IpAddr> = self.blocked
            .iter()
            .filter_map(|e| match e.value().expires {
                Some(exp) if now >= exp => Some(*e.key()),
                _ => None,
            })
            .collect();
        for ip in &expired {
            self.blocked.remove(ip);
        }
        if !expired.is_empty() {
            self.persist_blocks();
        }
        expired
    }
}

/// True if `ip` falls into a range a webhook must never be allowed to reach:
/// loopback, unspecified, RFC-1918 private, link-local (incl. 169.254.0.0/16
/// metadata) and IPv6 loopback/unique-local/link-local.
fn webhook_ip_blocked(ip: std::net::IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            // unique-local fc00::/7 and link-local fe80::/10 — not yet stable as
            // std helpers, so test the leading bits directly.
            let seg = v6.segments()[0];
            (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80
        }
    }
}

/// Returns true if the URL is safe to POST to (scheme is http/https, not a private address).
fn is_safe_webhook_url(url: &str) -> bool {
    // Reject non-HTTP/HTTPS schemes (file://, ftp://, etc.)
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }
    // Parse to extract hostname and reject RFC-1918 / loopback / link-local.
    let Ok(parsed) = url::Url::parse(url) else { return false };
    let host = parsed.host_str().unwrap_or("");
    if host.is_empty() {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if webhook_ip_blocked(ip) {
            return false;
        }
    }
    // Reject common localhost/metadata aliases
    let host_lc = host.to_ascii_lowercase();
    if host_lc == "localhost"
        || host_lc.ends_with(".local")
        || host_lc == "metadata.google.internal"
        || host_lc == "169.254.169.254"
    {
        return false;
    }
    // I-2: when the host is a hostname (not a literal IP), resolve it and re-check
    // every resolved address. Without this, a DNS name that resolves into a
    // private/metadata range (DNS-rebinding-style SSRF) would slip past the
    // literal-IP guard above.
    if host.parse::<std::net::IpAddr>().is_err() {
        let port = parsed.port_or_known_default().unwrap_or(80);
        use std::net::ToSocketAddrs;
        match (host, port).to_socket_addrs() {
            Ok(addrs) => {
                let mut saw_one = false;
                for sa in addrs {
                    saw_one = true;
                    if webhook_ip_blocked(sa.ip()) {
                        return false;
                    }
                }
                // Unresolvable hostname → fail closed.
                if !saw_one {
                    return false;
                }
            }
            // Resolution failure → fail closed rather than deliver blind.
            Err(_) => return false,
        }
    }
    true
}

async fn webhook_sender(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<(String, AlertEvent)>,
) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    while let Some((url, event)) = rx.recv().await {
        if !is_safe_webhook_url(&url) {
            tracing::warn!(url = %url, "Alert webhook: URL rejected (private/loopback/invalid scheme)");
            continue;
        }
        let body = serde_json::json!({
            "source": "runbound",
            "event": "alert_threshold",
            "data": event,
        });
        if let Err(e) = client.post(&url).json(&body).send().await {
            tracing::warn!(url = %url, err = %e, "Alert webhook delivery failed");
        }
    }
}


#[cfg(test)]
mod ddos_tests {
    use super::*;
    use crate::config::parser::AlertRule;

    fn block_rule(threshold: u64) -> AlertRule {
        AlertRule {
            name: "t".to_string(),
            metric: "client-qps".to_string(),
            window_s: 60,
            threshold,
            action: "block".to_string(),
            notify_url: None,
            block_duration_s: 60,
        }
    }

    // A verified source crossing the threshold is blocked AND pushed to the XDP ban
    // channel; an unverified (spoofable) source is never counted or banned (#ddos).
    #[tokio::test]
    async fn verified_block_pushes_xdp_ban_unverified_does_not() {
        let t = AlertTracker::new(vec![block_rule(3)], None);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        t.set_ban_tx(tx);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        // Unverified: never escalates, never bans.
        for _ in 0..10 {
            assert_eq!(t.record(ip, false), AbuseVerdict::Serve);
        }
        assert!(rx.try_recv().is_err(), "unverified source must never be banned");

        // Verified: crosses threshold (3) -> Block + XDP Ban pushed.
        let mut v = AbuseVerdict::Serve;
        for _ in 0..5 {
            v = t.record(ip, true);
        }
        assert_eq!(v, AbuseVerdict::Block);
        assert!(
            matches!(rx.try_recv(), Ok(IcmpBanCmd::Ban(_))),
            "verified block must push an XDP Ban"
        );
    }

    // M-1: protected IPs (loopback / unspecified) must never enter the ban set,
    // regardless of which ban path is used.
    #[test]
    fn ban_exempt_covers_loopback_and_unspecified() {
        assert!(AlertTracker::is_ban_exempt("127.0.0.1".parse().unwrap()));
        assert!(AlertTracker::is_ban_exempt("::1".parse().unwrap()));
        assert!(AlertTracker::is_ban_exempt("0.0.0.0".parse().unwrap()));
        assert!(AlertTracker::is_ban_exempt("::".parse().unwrap()));
        assert!(!AlertTracker::is_ban_exempt("203.0.113.7".parse().unwrap()));
    }

    #[tokio::test]
    async fn block_manual_and_block_bot_skip_protected_ips() {
        let t = AlertTracker::new(vec![], None);
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let any: IpAddr = "0.0.0.0".parse().unwrap();
        t.block_manual(lo, "test".to_string());
        t.block_bot(any, "test", 60);
        assert!(!t.is_blocked(lo), "loopback must never be banned");
        assert!(!t.is_blocked(any), "unspecified must never be banned");
        // A normal public IP still bans through both paths.
        let pub_ip: IpAddr = "203.0.113.9".parse().unwrap();
        t.block_manual(pub_ip, "test".to_string());
        assert!(t.is_blocked(pub_ip), "public IP must still be bannable");
    }

    // I-2: the per-IP webhook blocklist must reject private/loopback/link-local
    // ranges — this is what every resolved hostname address is re-checked against.
    #[test]
    fn webhook_ip_blocked_ranges() {
        assert!(webhook_ip_blocked("127.0.0.1".parse().unwrap()));
        assert!(webhook_ip_blocked("10.0.0.1".parse().unwrap()));
        assert!(webhook_ip_blocked("192.168.1.1".parse().unwrap()));
        assert!(webhook_ip_blocked("169.254.169.254".parse().unwrap())); // cloud metadata
        assert!(webhook_ip_blocked("::1".parse().unwrap()));
        assert!(webhook_ip_blocked("fd00::1".parse().unwrap())); // IPv6 unique-local
        assert!(webhook_ip_blocked("fe80::1".parse().unwrap())); // IPv6 link-local
        assert!(!webhook_ip_blocked("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn webhook_url_rejects_literal_and_alias_targets() {
        assert!(!is_safe_webhook_url("http://127.0.0.1/hook"));
        assert!(!is_safe_webhook_url("http://10.0.0.5/hook"));
        assert!(!is_safe_webhook_url("http://169.254.169.254/latest/meta-data"));
        assert!(!is_safe_webhook_url("http://localhost/hook"));
        assert!(!is_safe_webhook_url("https://foo.local/hook"));
        assert!(!is_safe_webhook_url("ftp://example.com/hook")); // non-http scheme
        assert!(!is_safe_webhook_url("http://[::1]/hook"));
    }
}
