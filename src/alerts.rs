// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Issue #12 — Per-client alert thresholds: count, block, notify via webhook.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

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
    expires: Option<Instant>, // None = permanent until restart
    rule: String,
}

pub struct AlertTracker {
    rules: Vec<AlertRule>,
    client_counts: DashMap<IpAddr, ClientBucket, ahash::RandomState>,
    blocked: DashMap<IpAddr, BlockEntry, ahash::RandomState>,
    recent: Mutex<VecDeque<AlertEvent>>,
    notify_tx: tokio::sync::mpsc::UnboundedSender<(String, AlertEvent)>,
}

impl AlertTracker {
    pub fn new(rules: Vec<AlertRule>) -> std::sync::Arc<Self> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(String, AlertEvent)>();
        tokio::spawn(webhook_sender(rx));
        std::sync::Arc::new(Self {
            rules,
            client_counts: DashMap::with_hasher(ahash::RandomState::default()),
            blocked: DashMap::with_hasher(ahash::RandomState::default()),
            recent: Mutex::new(VecDeque::new()),
            notify_tx: tx,
        })
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
        if self.rules.is_empty() {
            return false;
        }

        // Already blocked?
        if self.is_blocked(ip) {
            return true;
        }

        let now = Instant::now();

        // GC client_counts when table is full.
        if self.client_counts.len() >= MAX_CLIENT_BUCKETS {
            self.client_counts.retain(|_, b| {
                now.duration_since(b.window_start).as_secs()
                    < self.rules.iter().map(|r| r.window_s).max().unwrap_or(60) * 2
            });
        }

        let mut bucket = self.client_counts.entry(ip).or_insert_with(|| ClientBucket {
            count: 0,
            window_start: now,
        });

        // Check per-rule, smallest window first.
        for rule in &self.rules {
            if rule.metric != "client-qps" {
                continue;
            }
            let elapsed = now.duration_since(bucket.window_start).as_secs();
            if elapsed >= rule.window_s {
                bucket.count = 0;
                bucket.window_start = now;
            }
        }
        bucket.count += 1;
        let count = bucket.count;
        drop(bucket);

        for rule in &self.rules {
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

        let rules: Vec<serde_json::Value> = self.rules.iter().map(|r| serde_json::json!({
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
        self.blocked.remove(&ip).is_some()
    }

    /// Immediately block an IP without going through a rule threshold.
    /// Used by ICMP flood detector and relay propagation.
    pub fn block_manual(&self, ip: IpAddr, rule: String) {
        if self.is_blocked(ip) {
            return;
        }
        self.blocked.insert(ip, BlockEntry { expires: None, rule: rule.clone() });
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
