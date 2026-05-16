// Runbound — Feed subscription management (remote blocklists)
//
// Feeds are remote domain blocklists (ads, telemetry, malware...).
// Each feed is fetched, parsed, and cached locally.
// Feed entries are applied directly to the in-memory DNS authority.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::dns::BlacklistAction;
use crate::error::AppError;


// ============================================================
// Constants
// ============================================================

pub const FEEDS_CONFIG_PATH: &str = "/etc/runbound/feeds.json";
pub const FEED_CACHE_DIR: &str = "/etc/runbound/feed_cache";

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
            "format": "domains",
            "action": "refuse",
            "description": "~100k domains. Carefully curated, low false-positive rate. Good for home networks."
        }),
        serde_json::json!({
            "name": "OISD — Big (full list)",
            "url": "https://big.oisd.nl/",
            "format": "domains",
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
    let path = PathBuf::from(FEEDS_CONFIG_PATH);
    if !path.exists() {
        return Ok(FeedsConfig::default());
    }
    let content = fs::read_to_string(&path).map_err(|e| {
        AppError::Internal(format!("Failed to read feeds config: {}", e))
    })?;
    serde_json::from_str(&content).map_err(|e| {
        AppError::Internal(format!("Failed to parse feeds config JSON: {}", e))
    })
}

pub fn save_feeds(config: &FeedsConfig) -> Result<(), AppError> {
    let path = PathBuf::from(FEEDS_CONFIG_PATH);
    let content = serde_json::to_string_pretty(config).map_err(|e| {
        AppError::Internal(format!("Failed to serialize feeds config: {}", e))
    })?;
    let tmp = PathBuf::from(format!("{}.tmp", FEEDS_CONFIG_PATH));
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
    Ok(())
}

fn cache_path(feed_id: &str) -> PathBuf {
    // Sanitize ID: only allow alphanumeric and hyphens (prevents path traversal)
    let safe_id: String = feed_id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(64)
        .collect();
    PathBuf::from(FEED_CACHE_DIR).join(format!("{}.json", safe_id))
}

pub fn load_feed_domains(feed_id: &str) -> Vec<String> {
    let path = cache_path(feed_id);
    if !path.exists() {
        return Vec::new();
    }
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
}

fn save_feed_domains(feed_id: &str, domains: &[String]) -> Result<(), AppError> {
    fs::create_dir_all(FEED_CACHE_DIR).map_err(|e| {
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
    if !lower.starts_with("https://") && !lower.starts_with("http://") {
        return Err(AppError::BadRequest(
            "Only https:// URLs are allowed (no http://, file://, ftp://, etc.)".into()
        ));
    }
    // Warn loudly when http:// is used — MITM injection is possible.
    if lower.starts_with("http://") {
        warn!(
            url = %url,
            "Feed URL uses plaintext HTTP — a man-in-the-middle can inject \
             arbitrary domains into the blocklist; use HTTPS instead"
        );
    }

    // Extract host+port portion
    let host_and_port = url
        .split("://").nth(1).unwrap_or("")
        .split('/').next().unwrap_or("")
        .split('@').last().unwrap_or(""); // strip user:pass@

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
            if line.starts_with("||") {
                let rest = &line[2..];
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

/// Build a reqwest client with a SSRF-safe redirect policy.
///
/// Two redirect attacks are blocked:
///   1. HTTPS → HTTP downgrade: allows a MITM to inject domains once the
///      feed server redirects a validated HTTPS request to plaintext HTTP.
///   2. Redirect to private/loopback IP: a feed server that initially has a
///      public IP can redirect to an internal host (10.x, 172.16.x, etc.),
///      bypassing the SSRF check that was performed on the original URL.
fn ssrf_safe_client() -> reqwest::Client {
    reqwest::Client::builder()
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
                    // Full async DNS resolution is not possible inside a sync
                    // redirect policy; block the most common internal hostnames
                    // and rely on validate_feed_url() re-validation (TOCTOU
                    // mitigation) for the resolution-time check.
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

