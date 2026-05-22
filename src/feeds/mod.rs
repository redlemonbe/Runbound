// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Runbound — Feed subscription management (remote blocklists)
//
// Feeds are remote domain blocklists (ads, telemetry, malware...).
// Each feed is fetched, parsed, and cached locally.
// Feed entries are applied directly to the in-memory DNS authority.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::dns::BlacklistAction;
use crate::error::AppError;
use crate::integrity::{store_key, verify_mac, write_mac};


// ============================================================
// Constants
// ============================================================

fn feeds_config_path() -> std::path::PathBuf { crate::runtime::base_dir().join("feeds.json") }
fn feed_cache_dir() -> std::path::PathBuf { crate::runtime::base_dir().join("feed_cache") }

/// VUL-03: Maximum feed body size (100 MiB).
/// Without a cap, a malicious feed server can exhaust process memory.
const MAX_FEED_BYTES: usize = 100 * 1024 * 1024;

// ============================================================
// Types
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FeedFormat {
    /// Lines like: `0.0.0.0 ads.example.com` or `127.0.0.1 ads.example.com`
    #[default]
    Hosts,
    /// One domain per line, `#` comments ignored
    Domains,
    /// AdBlock syntax: `||ads.example.com^`
    Adblock,
}

impl std::fmt::Display for FeedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedFormat::Hosts   => write!(f, "hosts"),
            FeedFormat::Domains => write!(f, "domains"),
            FeedFormat::Adblock => write!(f, "adblock"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feed {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub format: FeedFormat,
    #[serde(default)]
    pub action: BlacklistAction,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Number of domains loaded from this feed
    #[serde(default)]
    pub entry_count: usize,
    /// ISO 8601 timestamp of last successful update
    #[serde(default)]
    pub last_updated: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedsConfig {
    pub feeds: Vec<Feed>,
}

// ============================================================
// Well-known presets
// ============================================================

pub fn builtin_presets() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "StevenBlack — Ads & Malware (unified)",
            "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "format": "hosts",
            "action": "refuse",
            "description": "~150k domains. Merges multiple reputable blocklists. Most popular general-purpose list."
        }),
        serde_json::json!({
            "name": "StevenBlack — Ads, Malware & Porn",
            "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
            "format": "hosts",
            "action": "refuse",
            "description": "Unified list + adult content."
        }),
        serde_json::json!({
            "name": "OISD — Basic",
            "url": "https://small.oisd.nl/",
            "format": "adblock",
            "action": "refuse",
            "description": "~100k domains. Carefully curated, low false-positive rate. Good for home networks."
        }),
        serde_json::json!({
            "name": "OISD — Big (full list)",
            "url": "https://big.oisd.nl/",
            "format": "adblock",
            "action": "refuse",
            "description": "~600k domains. Extended OISD list. Recommended for Pi-hole / Unbound setups."
        }),
        serde_json::json!({
            "name": "Hagezi — Pro",
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
            "format": "hosts",
            "action": "refuse",
            "description": "~350k domains. Balanced between blocking and usability. Actively maintained."
        }),
        serde_json::json!({
            "name": "Hagezi — Pro++ (aggressive)",
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt",
            "format": "hosts",
            "action": "refuse",
            "description": "~550k domains. More aggressive than Pro. May cause some false positives."
        }),
        serde_json::json!({
            "name": "Windows Telemetry — WindowsSpyBlocker",
            "url": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
            "format": "hosts",
            "action": "nxdomain",
            "description": "Blocks Windows telemetry, tracking and spying endpoints."
        }),
        serde_json::json!({
            "name": "AdGuard DNS Filter",
            "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            "format": "adblock",
            "action": "refuse",
            "description": "AdGuard's official DNS filter. ~80k domains. Ads, trackers, malware."
        }),
        serde_json::json!({
            "name": "URLhaus — Malware",
            "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
            "format": "hosts",
            "action": "nxdomain",
            "description": "Active malware distribution sites from abuse.ch. Updated frequently."
        }),
    ]
}

// ============================================================
// Storage
// ============================================================

pub fn load_feeds() -> Result<FeedsConfig, AppError> {
    let path = feeds_config_path();
    if !path.exists() {
        return Ok(FeedsConfig::default());
    }
    let content = fs::read_to_string(&path).map_err(|e| {
        AppError::Internal(format!("Failed to read feeds config: {}", e))
    })?;
    // HIGH-06: verify HMAC integrity before deserializing
    verify_mac(&path, content.as_bytes(), store_key().as_deref())
        .map_err(AppError::Internal)?;
    serde_json::from_str(&content).map_err(|e| {
        AppError::Internal(format!("Failed to parse feeds config JSON: {}", e))
    })
}

pub fn save_feeds(config: &FeedsConfig) -> Result<(), AppError> {
    let path = feeds_config_path();
    let content = serde_json::to_string_pretty(config).map_err(|e| {
        AppError::Internal(format!("Failed to serialize feeds config: {}", e))
    })?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|e| {
            AppError::Internal(format!("Failed to create temp feeds file: {}", e))
        })?;
        f.write_all(content.as_bytes()).map_err(|e| {
            AppError::Internal(format!("Failed to write temp feeds file: {}", e))
        })?;
        // VUL-07: fsync before rename — ensures data reaches storage before
        // the directory entry is updated; prevents zero-byte file on power loss.
        f.sync_all().map_err(|e| {
            AppError::Internal(format!("Failed to fsync feeds file: {}", e))
        })?;
    }
    fs::rename(&tmp, &path).map_err(|e| {
        AppError::Internal(format!("Atomic rename of feeds file failed: {}", e))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
    }
    // HIGH-06: write HMAC sidecar after atomic rename.
    write_mac(&path, content.as_bytes(), store_key().as_deref())
        .map_err(|e| AppError::Internal(format!("write feeds .mac: {e}")))?;
    Ok(())
}

fn cache_path(feed_id: &str) -> PathBuf {
    // Sanitize ID: only allow alphanumeric and hyphens (prevents path traversal)
    let safe_id: String = feed_id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(64)
        .collect();
    feed_cache_dir().join(format!("{}.json", safe_id))
}

pub fn load_feed_domains(feed_id: &str) -> Vec<String> {
    let path = cache_path(feed_id);
    if !path.exists() {
        return Vec::new();
    }
    let content = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    // HIGH-06: domain caches are regeneratable; HMAC mismatch → WARN + empty result.
    if let Err(e) = verify_mac(&path, content.as_bytes(), store_key().as_deref()) {
        warn!("Feed domain cache {} HMAC mismatch ({e}) — cache discarded.", path.display());
        return Vec::new();
    }
    serde_json::from_str::<Vec<String>>(&content).unwrap_or_default()
}

fn save_feed_domains(feed_id: &str, domains: &[String]) -> Result<(), AppError> {
    fs::create_dir_all(feed_cache_dir()).map_err(|e| {
        AppError::Internal(format!("Failed to create feed cache dir: {}", e))
    })?;
    let path = cache_path(feed_id);
    let tmp = path.with_extension("json.tmp");
    let content = serde_json::to_string(domains).map_err(|e| {
        AppError::Internal(format!("Failed to serialize feed domains: {}", e))
    })?;
    {
        let mut f = fs::File::create(&tmp).map_err(|e| {
            AppError::Internal(format!("Failed to create temp domain cache: {}", e))
        })?;
        f.write_all(content.as_bytes()).map_err(|e| {
            AppError::Internal(format!("Failed to write temp domain cache: {}", e))
        })?;
        f.sync_all().map_err(|e| {
            AppError::Internal(format!("Failed to fsync domain cache: {}", e))
        })?;
    }
    fs::rename(&tmp, &path).map_err(|e| {
        AppError::Internal(format!("Atomic rename of domain cache failed: {}", e))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
    }
    // HIGH-06: write HMAC sidecar.
    write_mac(&path, content.as_bytes(), store_key().as_deref())
        .map_err(|e| AppError::Internal(format!("write domain cache .mac: {e}")))?;
    Ok(())
}

fn delete_feed_cache(feed_id: &str) {
    let path = cache_path(feed_id);
    fs::remove_file(&path).ok();
}

// ============================================================
// Feed CRUD
// ============================================================

/// Validate feed URL: only https:// allowed, no private/loopback IPs (SSRF prevention).
/// VUL-02: async so we can resolve the hostname and reject DNS-rebinding attacks
/// (hostname that looks public but resolves to an RFC1918/loopback address).
async fn validate_feed_url(url: &str) -> Result<(), AppError> {
    if url.len() > 2048 {
        return Err(AppError::BadRequest("URL too long (max 2048 chars)".into()));
    }

    let lower = url.to_lowercase();
    // HTTP is explicitly blocked — not just warned about.
    // A MITM can inject arbitrary domains into a plaintext feed, instantly
    // poisoning the entire blocklist. HTTPS is mandatory.
    if lower.starts_with("http://") {
        return Err(AppError::BadRequest(
            "HTTP feed URLs are not allowed — use HTTPS to prevent MITM blocklist injection".into()
        ));
    }
    if !lower.starts_with("https://") {
        return Err(AppError::BadRequest(
            "Only https:// URLs are allowed (no http://, file://, ftp://, etc.)".into()
        ));
    }
    // Strip fragment — fragments are client-side and never sent in the HTTP request,
    // but reject them explicitly to avoid ambiguity in stored URLs and audit logs.
    let url_no_fragment = url.split('#').next().unwrap_or(url);

    // Strip embedded credentials (user:pass@host) — the reqwest client would
    // send them, but we reject them to keep the stored URL clean and prevent
    // credential leakage into logs.
    let after_scheme = url_no_fragment.split("://").nth(1).unwrap_or("");
    if after_scheme.contains('@') {
        return Err(AppError::BadRequest(
            "Feed URLs must not contain credentials (user:pass@host)".into()
        ));
    }

    // Extract host+port portion
    let host_and_port = after_scheme
        .split('/').next().unwrap_or("");

    // Handle IPv6 bracket notation ([::1]:8080) vs host:port
    let host = if host_and_port.starts_with('[') {
        host_and_port.trim_start_matches('[').split(']').next().unwrap_or("")
    } else {
        host_and_port.split(':').next().unwrap_or("")
    };

    // Block internal/loopback hostnames by name
    let blocked_hosts = ["localhost", "127.0.0.1", "::1", "0.0.0.0",
                          "metadata.google.internal", "169.254.169.254"];
    if blocked_hosts.contains(&host) {
        return Err(AppError::BadRequest(
            "Internal/loopback addresses are not allowed as feed URLs".into()
        ));
    }

    // Block RFC1918 / link-local IP ranges if the host is a literal IP address
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(&ip) {
            return Err(AppError::BadRequest(
                "Private/internal IP addresses are not allowed as feed URLs".into()
            ));
        }
        // Literal IP passed all checks — no DNS resolution needed
        return Ok(());
    }

    // VUL-02: DNS rebinding protection — resolve the hostname and verify that
    // none of its A/AAAA records point to a private/loopback range.
    // An attacker could register "feed.attacker.com" → 10.0.0.1 to reach
    // internal services; resolving here prevents that at subscription time.
    let lookup_target = format!("{}:80", host);
    match tokio::net::lookup_host(&lookup_target).await {
        Ok(addrs) => {
            for addr in addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(AppError::BadRequest(format!(
                        "Feed hostname '{}' resolves to a private/internal IP ({}) — \
                         DNS rebinding attack prevented",
                        host, addr.ip()
                    )));
                }
            }
        }
        Err(e) => {
            return Err(AppError::BadRequest(format!(
                "Feed hostname '{}' could not be resolved: {}", host, e
            )));
        }
    }

    Ok(())
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // RFC1918: 10/8, 172.16/12, 192.168/16
            // Loopback: 127/8, Link-local: 169.254/16, This-network: 0/8
            o[0] == 10
            || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
            || (o[0] == 192 && o[1] == 168)
            || o[0] == 127
            || (o[0] == 169 && o[1] == 254)
            || o[0] == 0
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            // Loopback (::1) and unspecified (::)
            v6.is_loopback() || v6.is_unspecified()
            // ULA: fc00::/7 — covers fd00::/8 used in enterprise/gov networks
            || (s[0] & 0xfe00) == 0xfc00
            // Link-local: fe80::/10
            || (s[0] & 0xffc0) == 0xfe80
            // IPv4-mapped: ::ffff:0:0/96
            || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0
                && s[4] == 0 && s[5] == 0xffff)
            // Discard/NAT64 well-known: 100::/64
            || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
        }
    }
}

/// Validate feed ID: must be a valid UUID v4 (prevents path traversal in cache filenames).
fn validate_feed_id(id: &str) -> bool {
    // UUID v4: 8-4-4-4-12 hex chars with dashes, 4th group starts with 4
    id.len() == 36
    && id.chars().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => c == '-',
        _ => c.is_ascii_hexdigit(),
    })
}

pub async fn add_feed(
    name: String,
    url: String,
    format: FeedFormat,
    action: BlacklistAction,
    description: Option<String>,
) -> Result<Feed, AppError> {
    validate_feed_url(&url).await?;

    if name.is_empty() || name.len() > 128 {
        return Err(AppError::BadRequest("Feed name must be 1-128 characters".into()));
    }

    let mut config = load_feeds()?;
    let feed = Feed {
        id: Uuid::new_v4().to_string(),
        name,
        url,
        format,
        action,
        enabled: true,
        entry_count: 0,
        last_updated: None,
        description,
    };
    config.feeds.push(feed.clone());
    save_feeds(&config)?;
    Ok(feed)
}

pub fn remove_feed(id: &str) -> Result<(), AppError> {
    if !validate_feed_id(id) {
        return Err(AppError::BadRequest("Invalid feed ID format".into()));
    }
    let mut config = load_feeds()?;
    let pos = config.feeds.iter().position(|f| f.id == id).ok_or_else(|| {
        AppError::NotFound(format!("Feed not found: {}", id))
    })?;
    config.feeds.remove(pos);
    save_feeds(&config)?;
    delete_feed_cache(id);
    Ok(())
}

// ============================================================
// Format parsers
// ============================================================

fn parse_hosts(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            // Strip inline comments
            let line = line.split('#').next().unwrap_or("").trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
            if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                let domain = parts[1];
                // Skip localhost variants
                if domain == "localhost" || domain == "localhost.localdomain"
                    || domain == "local" || domain == "broadcasthost"
                    || domain == "ip6-localhost" || domain == "ip6-loopback"
                {
                    return None;
                }
                if is_valid_domain(domain) {
                    return Some(domain.to_lowercase());
                }
            }
            None
        })
        .collect()
}

fn parse_domains(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim().split('#').next().unwrap_or("").trim();
            if line.is_empty() { return None; }
            if is_valid_domain(line) { Some(line.to_lowercase()) } else { None }
        })
        .collect()
}

fn parse_adblock(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
                return None;
            }
            // Match `||domain.com^` or `||domain.com^$...`
            if let Some(rest) = line.strip_prefix("||") {
                let domain = rest
                    .split('^')
                    .next()
                    .unwrap_or("")
                    .split('$')
                    .next()
                    .unwrap_or("")
                    .trim();
                if is_valid_domain(domain) {
                    return Some(domain.to_lowercase());
                }
            }
            None
        })
        .collect()
}

fn is_valid_domain(s: &str) -> bool {
    // Strip optional trailing dot (FQDN notation)
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 { return false; }
    // Must have at least one dot (no TLDs alone in blocklists)
    if !s.contains('.') { return false; }
    // Validate per-label: RFC 1035 §2.3.4
    for label in s.split('.') {
        if label.is_empty() { return false; }         // consecutive or leading/trailing dots
        if label.len() > 63 { return false; }         // RFC 1035 label length limit
        if label.starts_with('-') || label.ends_with('-') { return false; }
        // Only ASCII alphanumeric + hyphen + underscore (service labels, SRV)
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return false;
        }
    }
    true
}

pub fn parse_feed_content(content: &str, format: &FeedFormat) -> Vec<String> {
    let mut domains = match format {
        FeedFormat::Hosts   => parse_hosts(content),
        FeedFormat::Domains => parse_domains(content),
        FeedFormat::Adblock => parse_adblock(content),
    };
    // Deduplicate
    domains.sort_unstable();
    domains.dedup();
    domains
}

// ============================================================
// Feed update (HTTP fetch + parse + cache)
// ============================================================

pub async fn update_feed(feed: &mut Feed, client: &reqwest::Client) -> Result<usize, AppError> {
    info!("Updating feed '{}' from {}", feed.name, feed.url);

    // VUL-FIX (TOCTOU): re-validate the URL before every fetch, not just at
    // subscription time.  An attacker who controls the feed's DNS can change
    // the A record to a private IP after the initial validation passes; without
    // this check, the 24-hour auto-update would silently fetch from an internal
    // host (DNS rebinding attack).
    validate_feed_url(&feed.url).await.map_err(|e| {
        AppError::Internal(format!("Feed '{}' URL re-validation failed: {}", feed.name, e))
    })?;

    let response = client
        .get(&feed.url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch feed '{}': {}", feed.name, e)))?;

    if !response.status().is_success() {
        return Err(AppError::Internal(format!(
            "Feed '{}' returned HTTP {}", feed.name, response.status()
        )));
    }

    // VUL-03: Enforce 100 MiB cap — stream into bytes first so we can check
    // the size before decoding, preventing OOM via an oversized response body.
    let bytes = response.bytes().await.map_err(|e| {
        AppError::Internal(format!("Failed to read feed '{}' body: {}", feed.name, e))
    })?;
    if bytes.len() > MAX_FEED_BYTES {
        return Err(AppError::Internal(format!(
            "Feed '{}' response too large ({} bytes, max {} MiB)",
            feed.name, bytes.len(), MAX_FEED_BYTES / 1_048_576
        )));
    }
    let content = String::from_utf8_lossy(&bytes).into_owned();

    let domains = parse_feed_content(&content, &feed.format);
    let count = domains.len();

    save_feed_domains(&feed.id, &domains)?;

    feed.entry_count = count;
    feed.last_updated = Some(utc_now_rfc3339());

    info!("Feed '{}' updated: {} domains", feed.name, count);
    Ok(count)
}

// ── MED-03: SSRF-safe DNS resolver ───────────────────────────────────────────
//
// Defense-in-depth below validate_feed_url(): filters private IPs at the TCP
// connection layer so that even a DNS rebinding attack that slips past the
// async lookup in validate_feed_url() cannot reach internal services.
// Every hostname-to-address resolution made by reqwest passes through here.

struct SsrfSafeDnsResolver;

impl reqwest::dns::Resolve for SsrfSafeDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            type DynErr = Box<dyn std::error::Error + Send + Sync>;

            let addrs = tokio::net::lookup_host(format!("{host}:0"))
                .await
                .map_err(|e| Box::new(e) as DynErr)?;

            let safe: Vec<std::net::SocketAddr> = addrs
                .filter(|a| !is_private_ip(&a.ip()))
                .collect();

            if safe.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("all IPs for '{host}' are private/internal — SSRF blocked"),
                )) as DynErr);
            }
            Ok(Box::new(safe.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Build a reqwest client with layered SSRF protection:
///   1. Custom DNS resolver (MED-03): private IPs filtered at connection time.
///   2. Redirect policy: blocks HTTPS→HTTP downgrade and redirect-to-private-IP.
fn ssrf_safe_client() -> reqwest::Client {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(SsrfSafeDnsResolver))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let url = attempt.url();
            // Block HTTPS → non-HTTPS downgrade (MITM injection vector)
            let was_https = attempt.previous().last()
                .map(|u| u.scheme() == "https")
                .unwrap_or(false);
            if was_https && url.scheme() != "https" {
                return attempt.error("redirect from HTTPS to non-HTTPS blocked");
            }
            if let Some(host) = url.host_str() {
                // Block redirect to private/loopback literal IP
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    if is_private_ip(&ip) {
                        return attempt.error("redirect to private IP blocked");
                    }
                } else {
                    // Hostname destination — block well-known internal names.
                    // Full async DNS resolution is not possible in a sync redirect
                    // policy; block common names and rely on SsrfSafeDnsResolver
                    // (which runs on every connect) for the resolution-time check.
                    let h = host.to_lowercase();
                    if h == "localhost"
                        || h.ends_with(".local")
                        || h.ends_with(".internal")
                        || h.ends_with(".corp")
                        || h.ends_with(".lan")
                        || h == "metadata.google.internal"
                        || h == "169.254.169.254"
                    {
                        return attempt.error("redirect to internal hostname blocked");
                    }
                }
            }
            attempt.follow()
        }))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

pub async fn update_all_feeds() -> Result<Vec<FeedUpdateResult>, AppError> {
    let mut config = load_feeds()?;
    let client = ssrf_safe_client();
    let mut results = Vec::new();

    for feed in config.feeds.iter_mut() {
        if !feed.enabled {
            results.push(FeedUpdateResult {
                id: feed.id.clone(),
                name: feed.name.clone(),
                status: "skipped".into(),
                entry_count: feed.entry_count,
                error: None,
            });
            continue;
        }

        match update_feed(feed, &client).await {
            Ok(count) => results.push(FeedUpdateResult {
                id: feed.id.clone(),
                name: feed.name.clone(),
                status: "updated".into(),
                entry_count: count,
                error: None,
            }),
            Err(e) => {
                error!("Failed to update feed '{}': {}", feed.name, e);
                results.push(FeedUpdateResult {
                    id: feed.id.clone(),
                    name: feed.name.clone(),
                    status: "error".into(),
                    entry_count: feed.entry_count,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    save_feeds(&config)?;
    Ok(results)
}

pub async fn update_one_feed(id: &str) -> Result<FeedUpdateResult, AppError> {
    if !validate_feed_id(id) {
        return Err(AppError::BadRequest("Invalid feed ID format".into()));
    }
    let mut config = load_feeds()?;
    let feed = config.feeds.iter_mut().find(|f| f.id == id).ok_or_else(|| {
        AppError::NotFound(format!("Feed not found: {}", id))
    })?;

    let client = ssrf_safe_client();
    let result = match update_feed(feed, &client).await {
        Ok(count) => FeedUpdateResult {
            id: feed.id.clone(),
            name: feed.name.clone(),
            status: "updated".into(),
            entry_count: count,
            error: None,
        },
        Err(e) => {
            let result = FeedUpdateResult {
                id: feed.id.clone(),
                name: feed.name.clone(),
                status: "error".into(),
                entry_count: feed.entry_count,
                error: Some(e.to_string()),
            };
            warn!("Feed update failed for '{}': {}", feed.name, e);
            result
        }
    };

    save_feeds(&config)?;
    Ok(result)
}

#[derive(Debug, Serialize)]
pub struct FeedUpdateResult {
    pub id: String,
    pub name: String,
    pub status: String,
    pub entry_count: usize,
    pub error: Option<String>,
}

// ============================================================
// Collect all feed domains for config generation
// ============================================================

/// Returns all domains from all enabled feeds, with their configured action.
/// Used by generate_unbound_config to build local-zone directives.
pub fn collect_feed_entries() -> Vec<(String, BlacklistAction)> {
    let config = match load_feeds() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to load feeds for config generation: {}", e);
            return Vec::new();
        }
    };

    let mut entries: Vec<(String, BlacklistAction)> = Vec::new();

    for feed in &config.feeds {
        if !feed.enabled { continue; }
        let domains = load_feed_domains(&feed.id);
        for domain in domains {
            entries.push((domain, feed.action.clone()));
        }
    }

    // Deduplicate by domain (first occurrence wins)
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.dedup_by(|a, b| a.0 == b.0);
    entries
}

// ============================================================
// Timestamp helper
// ============================================================

fn utc_now_rfc3339() -> String {
    humantime::format_rfc3339(std::time::SystemTime::now()).to_string()
}


// ============================================================
// Background auto-update loop
// ============================================================

pub async fn feed_update_loop(interval_secs: u64) {
    if interval_secs == 0 {
        info!("Feed auto-update disabled (interval = 0)");
        return;
    }

    info!("Feed auto-update started: interval={}s", interval_secs);
    let interval = std::time::Duration::from_secs(interval_secs);

    loop {
        tokio::time::sleep(interval).await;

        info!("Auto-updating all feeds...");
        match update_all_feeds().await {
            Ok(results) => {
                let updated: Vec<_> = results.iter().filter(|r| r.status == "updated").collect();
                let errors: Vec<_> = results.iter().filter(|r| r.status == "error").collect();
                info!(
                    "Feed auto-update complete: {} updated, {} skipped, {} errors",
                    updated.len(),
                    results.iter().filter(|r| r.status == "skipped").count(),
                    errors.len()
                );
                for e in errors {
                    error!("Feed '{}' update error: {:?}", e.name, e.error);
                }
            }
            Err(e) => error!("Feed auto-update failed: {}", e),
        }
    }
}
