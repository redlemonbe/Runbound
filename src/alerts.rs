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

const MAX_CLIENT_BUCKETS: usize = 100_000;
const RECENT_ALERTS_CAP: usize = 200;

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

pub struct AlertTracker {
    rules: std::sync::RwLock<Vec<AlertRule>>,
    client_counts: DashMap<IpAddr, ClientBucket, ahash::RandomState>,
    blocked: DashMap<IpAddr, BlockEntry, ahash::RandomState>,
    recent: Mutex<VecDeque<AlertEvent>>,
    notify_tx: tokio::sync::mpsc::UnboundedSender<(String, AlertEvent)>,
    base_dir: Option<Arc<PathBuf>>,
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
            recent: Mutex::new(VecDeque::new()),
            notify_tx: tx,
            base_dir: base_dir_arc,
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
                }
            }
        }
        false
    }

    /// Record a query from `ip`. Returns true if the query should be blocked.
    pub fn record(&self, ip: IpAddr) -> bool {
        if self.rules.read().unwrap().is_empty() {
            return false;
        }

        // Already blocked?
        if self.is_blocked(ip) {
            return true;
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

        self.is_blocked(ip)
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
            "block" => {
                let expires = if rule.block_duration_s == 0 {
                    None
                } else {
                    Some(now + std::time::Duration::from_secs(rule.block_duration_s))
                };
                self.blocked.insert(ip, BlockEntry { expires, rule: rule.name.clone() });
                self.persist_blocks();
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
        if removed { self.persist_blocks(); }
        removed
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
        if self.is_blocked(ip) {
            return;
        }
        self.blocked.insert(ip, BlockEntry { expires: None, rule: rule.clone() });
        self.persist_blocks();
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
        let _ = self.notify_tx.send(("bot_ban".to_string(), event.clone()));
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

async fn webhook_sender(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<(String, AlertEvent)>,
) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    while let Some((url, event)) = rx.recv().await {
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
