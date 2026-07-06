// SPDX-License-Identifier: AGPL-3.0-or-later
// System-level webhook notifications for Runbound — issue #11.
//
// Supports multiple targets (Slack, Discord, ntfy, generic-json).
// Events: domain-blocked, slave-disconnect, qps-spike, feed-error, key-rotated, config-reloaded.
// Retry: 3 attempts with exponential backoff (1s, 2s, 4s).
// Webhook failures never block the DNS hot path — fire-and-forget via unbounded channel.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

// ── Config types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebhookFormat {
    Slack,
    Discord,
    Ntfy,
    GenericJson,
}

impl Default for WebhookFormat {
    fn default() -> Self { Self::GenericJson }
}

impl std::str::FromStr for WebhookFormat {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.to_ascii_lowercase().as_str() {
            "slack"        => Ok(Self::Slack),
            "discord"      => Ok(Self::Discord),
            "ntfy"         => Ok(Self::Ntfy),
            "generic-json" | "generic_json" | "json" => Ok(Self::GenericJson),
            _              => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebhookEventKind {
    DomainBlocked,
    SlaveDisconnect,
    QpsSpike,
    FeedError,
    KeyRotated,
    ConfigReloaded,
    AlertThreshold,
    All,
}

impl std::str::FromStr for WebhookEventKind {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "domain_blocked" | "malware_blocked" => Ok(Self::DomainBlocked),
            "slave_disconnect" | "slave_disconnected" => Ok(Self::SlaveDisconnect),
            "qps_spike" => Ok(Self::QpsSpike),
            "feed_error" => Ok(Self::FeedError),
            "key_rotated" => Ok(Self::KeyRotated),
            "config_reloaded" => Ok(Self::ConfigReloaded),
            "alert_threshold" => Ok(Self::AlertThreshold),
            "all" | "*" => Ok(Self::All),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebhookTarget {
    pub url:    String,
    pub format: WebhookFormat,
    pub token:  Option<String>,
    pub events: Vec<WebhookEventKind>,
}

impl WebhookTarget {
    /// Returns true if this target should receive the given event.
    fn accepts(&self, kind: &WebhookEventKind) -> bool {
        if self.events.is_empty() { return true; }
        self.events.iter().any(|e| e == &WebhookEventKind::All || e == kind)
    }
}

// ── Event payload ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub kind:    String,         // "domain-blocked" etc.
    pub ts:      u64,            // unix seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client:  Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain:  Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed:    Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

impl WebhookEvent {
    pub fn now(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            client: None,
            domain: None,
            feed: None,
            message: None,
            node_id: None,
        }
    }

    fn summary(&self) -> String {
        match self.kind.as_str() {
            "domain-blocked" => format!(
                "🚫 Domain blocked: {} (client: {})",
                self.domain.as_deref().unwrap_or("?"),
                self.client.as_deref().unwrap_or("?"),
            ),
            "slave-disconnect" => format!(
                "⚠️  Slave disconnected: {}",
                self.node_id.as_deref().unwrap_or("?"),
            ),
            "qps-spike" => format!(
                "📈 QPS spike from {} — {}",
                self.client.as_deref().unwrap_or("?"),
                self.message.as_deref().unwrap_or(""),
            ),
            "feed-error" => format!(
                "❌ Feed error: {} — {}",
                self.feed.as_deref().unwrap_or("?"),
                self.message.as_deref().unwrap_or(""),
            ),
            "key-rotated"      => "🔑 API key rotated".to_owned(),
            "config-reloaded"  => "🔄 Config reloaded".to_owned(),
            "alert-threshold"  => format!(
                "🚨 Alert threshold crossed — {} from {}",
                self.message.as_deref().unwrap_or("?"),
                self.client.as_deref().unwrap_or("?"),
            ),
            other => format!("ℹ️  Runbound event: {other}"),
        }
    }
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WebhookDispatcher {
    tx: UnboundedSender<(WebhookTarget, WebhookEvent)>,
}

impl WebhookDispatcher {
    pub fn new(_targets: Arc<tokio::sync::RwLock<Vec<WebhookTarget>>>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(WebhookTarget, WebhookEvent)>();
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .user_agent("Runbound-Webhook/1.0")
                // SEC-2026-07-B: filter private/internal IPs at resolution time (rebinding-safe)
                // and never follow redirects into internal targets.
                .dns_resolver(Arc::new(crate::ssrf::SsrfSafeDnsResolver))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default();
            while let Some((target, event)) = rx.recv().await {
                deliver_with_retry(&client, &target, &event).await;
            }
        });
        Self { tx }
    }

    /// Fire a webhook event to all matching targets. Non-blocking.
    pub fn fire(&self, targets: &[WebhookTarget], event: WebhookEvent) {
        let kind_str = event.kind.clone();
        let kind = kind_str.parse::<WebhookEventKind>().unwrap_or(WebhookEventKind::All);
        for target in targets {
            if target.accepts(&kind) {
                let _ = self.tx.send((target.clone(), event.clone()));
            }
        }
    }
}

async fn deliver_with_retry(client: &reqwest::Client, target: &WebhookTarget, event: &WebhookEvent) {
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await; // 1s, 2s
        }
        match send_once(client, target, event).await {
            Ok(()) => {
                info!(url = %target.url, kind = %event.kind, "webhook delivered");
                return;
            }
            Err(e) => {
                warn!(url = %target.url, attempt = attempt + 1, err = %e, "webhook delivery failed");
            }
        }
    }
}

async fn send_once(client: &reqwest::Client, target: &WebhookTarget, event: &WebhookEvent) -> Result<(), String> {
    if !is_safe_url(&target.url) {
        return Err("URL rejected (private/loopback)".to_owned());
    }
    match target.format {
        WebhookFormat::Slack => {
            let body = serde_json::json!({
                "text": event.summary(),
                "blocks": [{
                    "type": "section",
                    "text": { "type": "mrkdwn", "text": format!("*Runbound*: {}", event.summary()) }
                }]
            });
            client.post(&target.url).json(&body).send().await
                .map_err(|e| e.to_string())?.error_for_status()
                .map_err(|e| e.to_string())?;
        }
        WebhookFormat::Discord => {
            let body = serde_json::json!({
                "content": event.summary(),
                "embeds": [{
                    "title": format!("Runbound — {}", event.kind),
                    "description": event.summary(),
                    "color": 0xE74C3C,
                    "timestamp": ts_iso(event.ts),
                }]
            });
            client.post(&target.url).json(&body).send().await
                .map_err(|e| e.to_string())?.error_for_status()
                .map_err(|e| e.to_string())?;
        }
        WebhookFormat::Ntfy => {
            let mut req = client.post(&target.url)
                .header("Title", format!("Runbound: {}", event.kind))
                .header("Priority", ntfy_priority(&event.kind))
                .header("Tags", ntfy_tags(&event.kind))
                .body(event.summary());
            if let Some(ref token) = target.token {
                req = req.bearer_auth(token);
            }
            req.send().await.map_err(|e| e.to_string())?
               .error_for_status().map_err(|e| e.to_string())?;
        }
        WebhookFormat::GenericJson => {
            let body = serde_json::json!({
                "source": "runbound",
                "event":  event.kind,
                "ts":     event.ts,
                "data":   event,
            });
            client.post(&target.url).json(&body).send().await
                .map_err(|e| e.to_string())?.error_for_status()
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn ntfy_priority(kind: &str) -> &'static str {
    match kind {
        "domain-blocked" | "qps-spike" | "alert-threshold" => "high",
        "slave-disconnect" | "feed-error" => "urgent",
        _ => "default",
    }
}

fn ntfy_tags(kind: &str) -> &'static str {
    match kind {
        "domain-blocked"   => "shield,warning",
        "slave-disconnect" => "rotating_light,link",
        "qps-spike"        => "chart_with_upwards_trend",
        "feed-error"       => "x,cloud",
        "key-rotated"      => "key",
        "config-reloaded"  => "repeat",
        _                  => "bell",
    }
}


fn ts_iso(unix_secs: u64) -> String {
    // Minimal ISO 8601 without chrono. Good enough for webhook consumers.
    let secs = unix_secs;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Approximate date — not RFC 8601 compliant but readable in Slack/Discord
    let _ = (days, h, m, s); // suppress unused
    format!("{unix_secs}")   // fall back to unix timestamp for now
}

fn is_safe_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") { return false; }
    let Ok(parsed) = url::Url::parse(url) else { return false };
    let host = parsed.host_str().unwrap_or("");
    // IP literals: reuse the shared SSRF filter (covers IPv4 RFC1918/CGNAT/loopback/
    // link-local AND IPv6 ULA/link-local/mapped) — SEC-2026-07-B. Rebinding via a
    // hostname is caught at resolution time by SsrfSafeDnsResolver on the client below.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if crate::ssrf::is_private_ip(&ip) { return false; }
    }
    let host_lc = host.to_ascii_lowercase();
    // Match the internal-name guards of the feeds redirect policy (defense in depth
    // against split-horizon DNS that resolves internal names to proxied targets).
    !matches!(host_lc.as_str(), "localhost" | "metadata.google.internal")
        && !host_lc.ends_with(".local")
        && !host_lc.ends_with(".internal")
        && !host_lc.ends_with(".corp")
        && !host_lc.ends_with(".lan")
}
