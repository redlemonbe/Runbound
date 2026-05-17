// Runbound REST API — full DNS management + feeds + DoT/DoH status

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use std::net::IpAddr;

use dashmap::DashMap;

use std::convert::Infallible;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    response::sse::{Event, KeepAlive, Sse},
    Json as JsonExtract,
    Router,
    routing::{delete, get, post},
};
use arc_swap::ArcSwap;
use futures_util::stream;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::dns::{BlacklistAction, ZoneAction, local::{LocalZoneSet, parse_local_data}};
use crate::feeds::{self, FeedFormat, add_feed, builtin_presets, remove_feed, update_all_feeds, update_one_feed};
use crate::logbuffer::{LogAction, LogQuery, SharedLogBuffer};
use crate::store::{self, DnsEntry, DnsType, BlacklistEntry};
use crate::config::parser::{TlsConfig, UnboundConfig};
use crate::stats::Stats;
use crate::sync::{SyncJournal, SyncOp};
use crate::upstreams::SharedUpstreams;

/// Max TTL for API-created DNS entries (86400 s = 24 h).
/// Prevents TTL-based cache persistence attacks and operator mistakes.
const MAX_API_TTL: u32 = 86_400;

// ── API security constants ─────────────────────────────────────────────────

/// API key — read from RUNBOUND_API_KEY env at startup, or generated if absent.
static API_KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Global authentication failure counter (reset on every successful auth).
/// Used to detect and slow brute-force attempts without per-IP state.
static AUTH_FAILURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Max JSON body size (64 KiB) — prevents OOM via huge payloads.
const MAX_BODY_BYTES: usize = 65_536;

/// API rate limit: max requests per IP per second.
const API_RATE_LIMIT_RPS: u64 = 30;
const API_RATE_BURST: u64 = 60;

/// Hard cap on persisted DNS entries — prevents authenticated DoS / OOM.
const MAX_DNS_ENTRIES: usize = 10_000;
/// Hard cap on blacklist entries (feeds can add millions; the API is manual).
const MAX_BLACKLIST_ENTRIES: usize = 100_000;
/// Hard cap on feed subscriptions. Each feed can download up to 100 MiB;
/// without this limit an authenticated client could trigger unbounded I/O.
const MAX_FEEDS: usize = 100;

/// Priority: RUNBOUND_API_KEY env var > api-key in unbound.conf > auto-generate.
/// Auto-generated keys are 256-bit CSPRNG (2× UUID v4, backed by getrandom).
pub fn init_api_key(config_key: Option<String>) -> String {
    let key = std::env::var("RUNBOUND_API_KEY")
        .ok()
        .or(config_key)
        .unwrap_or_else(|| {
            // 256 bits from OS CSPRNG — two UUID v4s = 64 hex chars.
            // Previous implementation used PID+timestamp (deterministic → weak).
            format!("{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple())
        });
    API_KEY.get_or_init(|| key.clone());
    key
}

pub fn get_api_key() -> &'static str {
    API_KEY.get().map(|s| s.as_str()).unwrap_or("")
}

// ── API rate limiter ───────────────────────────────────────────────────────

struct ApiBucket { tokens: u64, last: Instant }

// DashMap: each shard has its own RwLock — no global lock, parallel IPs don't
// contend. check() is sync (no .await), keeping the hot middleware path lean.
// AHash: faster than SipHash for IpAddr keys (same HashDoS resistance, v0.8+).
#[derive(Clone)]
pub struct ApiRateLimiter(Arc<DashMap<IpAddr, ApiBucket, ahash::RandomState>>);

impl ApiRateLimiter {
    fn new() -> Self {
        Self(Arc::new(DashMap::with_hasher(ahash::RandomState::default())))
    }
    pub fn new_public() -> Self { Self::new() }
    #[inline]
    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut b = self.0.entry(ip).or_insert(ApiBucket { tokens: API_RATE_BURST, last: now });
        let elapsed_ms = now.duration_since(b.last).as_millis() as u64;
        if elapsed_ms >= 1000 {
            b.tokens = API_RATE_BURST; b.last = now;
        } else {
            let new = (API_RATE_LIMIT_RPS * elapsed_ms) / 1000;
            if new > 0 { b.tokens = (b.tokens + new).min(API_RATE_BURST); b.last = now; }
        }
        if b.tokens > 0 { b.tokens -= 1; true } else { false }
    }
}

// ── Shared state ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub zones:        Arc<ArcSwap<LocalZoneSet>>,
    // Serialises concurrent API writes: load-clone-modify-store is not atomic,
    // so two simultaneous POST /dns would race without this guard.
    // DNS reads (every query) never touch this mutex — zero read overhead.
    pub zones_mutex:  Arc<Mutex<()>>,
    pub tls_cfg:      Arc<TlsConfig>,
    pub rate_limiter: ApiRateLimiter,
    pub stats:        Arc<Stats>,
    pub cfg:          Arc<UnboundConfig>,
    pub cfg_path:     String,
    pub log_buffer:   SharedLogBuffer,
    pub upstreams:    SharedUpstreams,
    /// Master: Some(journal) to record write events for slave replication.
    /// Slave / standalone: None.
    pub sync_journal: Option<Arc<SyncJournal>>,
    /// True when running as slave — all write operations are blocked (503).
    pub slave_mode:   bool,
    /// Directory where runtime files (api.key, dns_entries.json, …) are stored.
    /// Exposed for handlers in future features; suppress dead_code lint.
    #[allow(dead_code)]
    pub base_dir:     Arc<PathBuf>,
}

// ── Request types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AddDnsRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: DnsType,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    // simple types
    pub value: Option<String>,
    // MX / SRV priority
    pub priority: Option<u16>,
    // SRV
    pub weight: Option<u16>,
    pub port: Option<u16>,
    // CAA
    pub flags: Option<u8>,
    pub tag: Option<String>,
    // NAPTR
    pub order: Option<u16>,
    pub preference_naptr: Option<u16>,
    pub flags_naptr: Option<String>,
    pub services: Option<String>,
    pub regexp: Option<String>,
    pub replacement: Option<String>,
    // SSHFP
    pub algorithm: Option<u8>,
    pub fp_type: Option<u8>,
    pub fingerprint: Option<String>,
    // TLSA
    pub cert_usage: Option<u8>,
    pub selector: Option<u8>,
    pub matching_type: Option<u8>,
    pub cert_data: Option<String>,
    pub description: Option<String>,
}

fn default_ttl() -> u32 { 3600 }

#[derive(Debug, Deserialize)]
pub struct AddFeedRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub format: FeedFormat,
    #[serde(default)]
    pub action: BlacklistAction,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddBlacklistRequest {
    pub domain: String,
    #[serde(default)]
    pub action: BlacklistAction,
    pub description: Option<String>,
}

// ── Security middleware ────────────────────────────────────────────────────

async fn security_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // ── 1. Rate limiting ──────────────────────────────────────────────
    // VUL-04: Never trust X-Forwarded-For. The API is bound exclusively to
    // 127.0.0.1 so the real peer is always localhost. Accepting XFF would let
    // any caller spoof an arbitrary IP to bypass per-IP rate limiting.
    let client_ip: IpAddr = IpAddr::from([127, 0, 0, 1]);

    if !state.rate_limiter.check(client_ip) {
        warn!(%client_ip, "API rate limited");
        return (StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "1")],
            "Rate limit exceeded").into_response();
    }

    // ── 2. API key authentication (Bearer token) ──────────────────────
    // ALL endpoints require authentication — including /help.
    // Exposing version, endpoint list, or RFCs without auth enables
    // fingerprinting and targeted exploitation (AUDIT-HIGH-02).
    let path = req.uri().path();
    {
        let auth = req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let expected = format!("Bearer {}", get_api_key());
        if !constant_time_eq(auth.as_bytes(), expected.as_bytes()) {
            // Increment global auth-failure counter (localhost-only API,
            // so per-IP tracking adds nothing; we track globally).
            let failures = AUTH_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if failures.is_multiple_of(10) {
                warn!(failures, %path, "Repeated API authentication failures — check RUNBOUND_API_KEY");
            }
            // Threshold 50 is reachable within one rate-limiter burst window (burst=60).
            // At 100 the rate limiter would pre-empt most rapid attacks before the
            // counter could accumulate, making the lockout unobservable.
            if failures >= 50 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            return (StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, "Bearer realm=\"runbound\"")],
                "Unauthorized").into_response();
        }
        // Successful auth resets the failure counter.
        AUTH_FAILURES.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    // ── 3. Security response headers ──────────────────────────────────
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options",    HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options",           HeaderValue::from_static("DENY"));
    headers.insert("x-xss-protection",          HeaderValue::from_static("1; mode=block"));
    headers.insert("referrer-policy",           HeaderValue::from_static("no-referrer"));
    headers.insert("content-security-policy",   HeaderValue::from_static("default-src 'none'"));
    headers.insert("cache-control",             HeaderValue::from_static("no-store"));
    // Disable nginx response buffering so SSE events reach the client immediately.
    headers.insert("x-accel-buffering",         HeaderValue::from_static("no"));
    response
}

/// Constant-time byte-slice comparison.
/// VUL-01 fix: the previous implementation had an early-exit on length mismatch,
/// leaking whether the submitted token had the correct length (timing oracle).
/// This version encodes the length mismatch as a byte difference and always
/// iterates b.len() bytes — timing depends only on key length, never on content.
#[inline(always)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    // Fold length mismatch into the accumulator as a non-zero seed.
    // Then XOR every byte of b against the corresponding byte of a
    // (using 0x00 padding when a is shorter). No early exit anywhere.
    let len_mismatch = u8::from(a.len() != b.len());
    let diff: u8 = b.iter().enumerate()
        .fold(len_mismatch, |acc, (i, &bi)| {
            acc | (a.get(i).copied().unwrap_or(0) ^ bi)
        });
    diff.ct_eq(&0u8).into()
}

// ── Slave write guard ──────────────────────────────────────────────────────

async fn slave_guard_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if state.slave_mode && req.method() != axum::http::Method::GET {
        return (StatusCode::SERVICE_UNAVAILABLE, JsonExtract(serde_json::json!({
            "error":   "READ_ONLY",
            "details": "This node is a slave replica — write operations are disabled",
        }))).into_response();
    }
    next.run(req).await
}

// ── Router ─────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        // Info
        .route("/help",              get(help_handler))
        // Operations
        .route("/health",            get(health_handler))
        .route("/stats",             get(stats_handler))
        .route("/stats/stream",      get(stats_stream_handler))
        .route("/config",            get(config_handler))
        .route("/reload",            post(reload_handler))
        // DNS CRUD
        .route("/dns",               get(list_dns_handler).post(add_dns_handler))
        .route("/dns/:id",           delete(delete_dns_handler))
        // Blacklist
        .route("/blacklist",         get(list_blacklist_handler).post(add_blacklist_handler))
        .route("/blacklist/:id",     delete(delete_blacklist_handler))
        // Feeds
        .route("/feeds",             get(get_feeds_handler).post(add_feed_handler))
        .route("/feeds/presets",     get(feed_presets_handler))
        .route("/feeds/update",      post(update_feeds_handler))
        .route("/feeds/:id",         delete(delete_feed_handler))
        .route("/feeds/:id/update",  post(update_one_feed_handler))
        // TLS / Protocol status
        .route("/tls",               get(tls_status_handler))
        // Monitoring
        .route("/upstreams",         get(upstreams_handler))
        .route("/logs",              get(logs_handler))
        .layer(middleware::from_fn_with_state(state.clone(), slave_guard_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), security_middleware))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .with_state(state)
}

// ── GET /help ──────────────────────────────────────────────────────────────

async fn help_handler() -> impl IntoResponse {
    JsonExtract(serde_json::json!({
        "service": "Runbound DNS",
        "version": env!("CARGO_PKG_VERSION"),
        "protocols": ["DNS/UDP:53","DNS/TCP:53","DoT:853","DoH:443","DoQ:853/UDP"],
        "rfcs": ["RFC1034","RFC1035","RFC2782","RFC4033","RFC4034","RFC4035","RFC6698","RFC6891","RFC7858","RFC8484","RFC9250"],
        "endpoints": [
            {"method":"GET",    "path":"/help",             "description":"API documentation"},
            {"method":"GET",    "path":"/health",           "description":"Liveness check"},
            {"method":"GET",    "path":"/stats",            "description":"Query statistics snapshot"},
            {"method":"GET",    "path":"/stats/stream",     "description":"Live stats as Server-Sent Events (1-second interval)"},
            {"method":"GET",    "path":"/config",           "description":"Running configuration"},
            {"method":"POST",   "path":"/reload",           "description":"Hot-reload zones and blacklist from disk"},
            {"method":"GET",    "path":"/dns",              "description":"List all local DNS entries"},
            {"method":"POST",   "path":"/dns",              "description":"Add a local DNS entry (A/AAAA/CNAME/TXT/MX/SRV/CAA/PTR/NAPTR/SSHFP/TLSA/NS)"},
            {"method":"DELETE", "path":"/dns/:id",          "description":"Remove a DNS entry by UUID"},
            {"method":"GET",    "path":"/blacklist",        "description":"List blacklist entries"},
            {"method":"POST",   "path":"/blacklist",        "description":"Add a domain to the blacklist (refuse/nxdomain)"},
            {"method":"DELETE", "path":"/blacklist/:id",    "description":"Remove a blacklist entry"},
            {"method":"GET",    "path":"/feeds",            "description":"List feed subscriptions"},
            {"method":"POST",   "path":"/feeds",            "description":"Subscribe to a remote blocklist"},
            {"method":"DELETE", "path":"/feeds/:id",        "description":"Remove a feed subscription"},
            {"method":"POST",   "path":"/feeds/update",     "description":"Refresh all feeds"},
            {"method":"POST",   "path":"/feeds/:id/update", "description":"Refresh one feed"},
            {"method":"GET",    "path":"/feeds/presets",    "description":"List pre-configured blocklists"},
            {"method":"GET",    "path":"/tls",              "description":"DoT/DoH/DoQ TLS status"},
            {"method":"GET",    "path":"/upstreams",        "description":"Upstream DNS resolver health"},
            {"method":"GET",    "path":"/logs",             "description":"Recent query log (newest first) — ?limit=100&page=0&action=blocked&client=1.2.3.4&since=<unix>"},
        ]
    }))
}

// ── GET /health ────────────────────────────────────────────────────────────

async fn health_handler(State(s): State<AppState>) -> impl IntoResponse {
    let snap = s.stats.snapshot();
    JsonExtract(serde_json::json!({
        "status":      "ok",
        "uptime_secs": snap.uptime_secs,
        "queries":     snap.total,
    }))
}

// ── GET /stats ─────────────────────────────────────────────────────────────

async fn stats_handler(State(s): State<AppState>) -> impl IntoResponse {
    JsonExtract(stats_json(&s.stats.snapshot()))
}

fn stats_json(snap: &crate::stats::StatsSnapshot) -> serde_json::Value {
    let pct_blocked = if snap.total > 0 {
        (snap.blocked as f64 / snap.total as f64 * 1000.0).round() / 10.0
    } else { 0.0 };
    serde_json::json!({
        "total":            snap.total,
        "blocked":          snap.blocked,
        "forwarded":        snap.forwarded,
        "nxdomain":         snap.nxdomain,
        "refused":          snap.refused,
        "servfail":         snap.servfail,
        "local_hits":       snap.local_hits,
        "blocked_percent":  pct_blocked,
        "uptime_secs":      snap.uptime_secs,
        "qps_1m":           snap.qps_1m,
        "qps_5m":           snap.qps_5m,
        "qps_peak":         snap.qps_peak,
        "latency_p50_ms":   snap.latency_p50_ms,
        "latency_p95_ms":   snap.latency_p95_ms,
        "latency_p99_ms":   snap.latency_p99_ms,
        "cache_hit_rate":   snap.cache_hit_rate,
        "cache_entries":    snap.cache_entries,
    })
}

// ── GET /stats/stream ──────────────────────────────────────────────────────

async fn stats_stream_handler(
    State(s): State<AppState>,
) -> Sse<impl stream::Stream<Item = Result<Event, Infallible>>> {
    let sse_stream = stream::unfold(s.stats, |stats| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let data = stats_json(&stats.snapshot()).to_string();
        let event = Event::default().data(data);
        Some((Ok::<Event, Infallible>(event), stats))
    });
    Sse::new(sse_stream).keep_alive(KeepAlive::default())
}

// ── GET /config ────────────────────────────────────────────────────────────

async fn config_handler(State(s): State<AppState>) -> impl IntoResponse {
    let cfg = s.cfg.as_ref();
    // Live counts include both config-file entries and API-managed entries.
    let api_dns   = store::load().map(|st| st.entries.len()).unwrap_or(0);
    let api_bl    = store::load_blacklist().map(|bl| bl.entries.len()).unwrap_or(0);
    let api_feeds = crate::feeds::load_feeds().map(|f| f.feeds.len()).unwrap_or(0);
    JsonExtract(serde_json::json!({
        "port":              cfg.port,
        "interfaces":        cfg.interfaces,
        "forward_zones":     cfg.forward_zones.iter().map(|fz| serde_json::json!({
            "name":  fz.name,
            "addrs": fz.addrs,
            "tls":   fz.tls,
        })).collect::<Vec<_>>(),
        // file_* = entries from runbound.conf; api_* = entries added via REST API
        "file_local_zones":  cfg.local_zones.len(),
        "file_local_data":   cfg.local_data.len(),
        "api_dns_entries":   api_dns,
        "api_blacklist":     api_bl,
        "api_feeds":         api_feeds,
        "access_control":    cfg.access_control,
        "private_addresses": cfg.private_addresses,
        "rate_limit":        cfg.rate_limit,
        "cache_max_ttl":     cfg.cache_max_ttl,
        "dnssec_validation": cfg.dnssec_validation,
        "api_port":          cfg.api_port,
        // api_key intentionally omitted — secret
        "logfile":           cfg.logfile,
    }))
}

// ── POST /reload ────────────────────────────────────────────────────────────

async fn reload_handler(State(s): State<AppState>) -> impl IntoResponse {
    match crate::config::load(&s.cfg_path) {
        Ok(new_cfg) => {
            let new_zones = crate::build_zone_set(&new_cfg);
            s.zones.store(std::sync::Arc::new(new_zones));
            info!(cfg_path = %s.cfg_path, "API hot-reload complete");
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "status":      "ok",
                "cfg_path":    s.cfg_path,
                "local_zones": new_cfg.local_zones.len(),
                "local_data":  new_cfg.local_data.len(),
            })))
        }
        Err(e) => {
            warn!(err = %e, "API reload failed — keeping current zones");
            (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error":   "RELOAD_FAILED",
                "details": e.to_string(),
            })))
        }
    }
}

// ── DNS CRUD ───────────────────────────────────────────────────────────────

async fn list_dns_handler(State(_s): State<AppState>) -> impl IntoResponse {
    match store::load() {
        Ok(st) => (StatusCode::OK, JsonExtract(serde_json::json!({
            "entries": st.entries,
            "total": st.entries.len()
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
            "error": e.to_string()
        }))),
    }
}

async fn add_dns_handler(
    State(s): State<AppState>,
    JsonExtract(req): JsonExtract<AddDnsRequest>,
) -> impl IntoResponse {
    // VUL-05: Reject malformed or dangerous names before any parsing.
    if let Err(e) = validate_dns_name(&req.name) {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_NAME", "details": e
        })));
    }
    // Reject control characters in free-text fields (CRLF injection prevention).
    for (field, val) in [
        ("value",       req.value.as_deref().unwrap_or("")),
        ("tag",         req.tag.as_deref().unwrap_or("")),
        ("description", req.description.as_deref().unwrap_or("")),
        ("fingerprint", req.fingerprint.as_deref().unwrap_or("")),
        ("cert_data",   req.cert_data.as_deref().unwrap_or("")),
        ("services",    req.services.as_deref().unwrap_or("")),
        ("regexp",      req.regexp.as_deref().unwrap_or("")),
        ("replacement", req.replacement.as_deref().unwrap_or("")),
        ("flags_naptr", req.flags_naptr.as_deref().unwrap_or("")),
    ] {
        if let Err(e) = validate_no_control_chars(val, field) {
            return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                "error": "INVALID_FIELD", "details": e
            })));
        }
    }
    // RFC 2181 §8: TTL is a signed 32-bit integer; values >= 2^31 are treated
    // as 0 by compliant resolvers — reject them to prevent silent data loss.
    const RFC2181_MAX_TTL: u32 = 2_147_483_647;
    if req.ttl > RFC2181_MAX_TTL {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_TTL",
            "details": format!("TTL {} exceeds RFC 2181 maximum of 2147483647", req.ttl)
        })));
    }
    let entry = DnsEntry {
        id:               DnsEntry::new_id(),
        name:             ensure_dot(&req.name),
        entry_type:       req.entry_type,
        ttl:              req.ttl.min(MAX_API_TTL),
        value:            req.value,
        priority:         req.priority,
        weight:           req.weight,
        port:             req.port,
        flags:            req.flags,
        tag:              req.tag,
        order:            req.order,
        preference_naptr: req.preference_naptr,
        flags_naptr:      req.flags_naptr,
        services:         req.services,
        regexp:           req.regexp,
        replacement:      req.replacement,
        algorithm:        req.algorithm,
        fp_type:          req.fp_type,
        fingerprint:      req.fingerprint,
        cert_usage:       req.cert_usage,
        selector:         req.selector,
        matching_type:    req.matching_type,
        cert_data:        req.cert_data,
        description:      req.description,
    };

    // Validate by converting to RR string and parsing
    let rr = match entry.to_rr_string() {
        Some(r) => r,
        None => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_ENTRY",
            "details": "Missing required fields for this record type"
        }))),
    };

    let record = match parse_local_data(&rr) {
        Some(r) => r,
        None => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "PARSE_FAILED",
            "details": format!("Could not parse RR: {rr}")
        }))),
    };

    // Persist + inject atomically under zones_mutex.
    // VUL-FIX: store load/save MUST be inside the mutex.  Without this,
    // two concurrent POST /dns both load the same snapshot, each append
    // their entry, and the last writer wins — the other entry is silently
    // lost from the on-disk store (in-memory zones get both, but a restart
    // would only restore one).
    {
        let _guard = s.zones_mutex.lock().await;

        let mut st = store::load().unwrap_or_default();
        if st.entries.len() >= MAX_DNS_ENTRIES {
            return (StatusCode::UNPROCESSABLE_ENTITY, JsonExtract(serde_json::json!({
                "error": "LIMIT_EXCEEDED",
                "details": format!("Maximum {} DNS entries reached", MAX_DNS_ENTRIES)
            })));
        }
        st.entries.push(entry.clone());
        if let Err(e) = store::save(&st) {
            return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error": e.to_string()
            })));
        }

        let current = s.zones.load_full();
        let mut new_zones = (*current).clone();
        let name = record.name().clone();
        new_zones.zones.entry(name.clone()).or_insert(ZoneAction::Static);
        new_zones.records.entry(name).or_default().push(record);
        s.zones.store(Arc::new(new_zones));
    }

    info!(id=%entry.id, name=%entry.name, r#type=?entry.entry_type, "DNS entry added");
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::AddDns { entry: entry.clone() });
    }
    (StatusCode::CREATED, JsonExtract(serde_json::json!({
        "status": "ok",
        "entry": entry,
        "rr": rr
    })))
}

async fn delete_dns_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _guard = s.zones_mutex.lock().await;

    let mut st = match store::load() {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error": e.to_string()}))),
    };

    let pos = st.entries.iter().position(|e| e.id == id);
    let Some(pos) = pos else {
        return (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":"NOT_FOUND","id":id})));
    };

    let entry = st.entries.remove(pos);
    if let Err(e) = store::save(&st) {
        return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error": e.to_string()})));
    }

    // Remove from live zone set — ArcSwap write
    if let Some(rr) = entry.to_rr_string() {
        if let Some(record) = parse_local_data(&rr) {
            let current = s.zones.load_full();
            let mut new_zones = (*current).clone();
            let name = record.name().clone();
            if let Some(recs) = new_zones.records.get_mut(&name) {
                // VUL-08: match on the full Record (name + type + rdata + TTL),
                // not just the type. The old code removed ALL records of the
                // same type for the given name — e.g. deleting one A record
                // would silently wipe every A record for that name.
                let mut removed = false;
                recs.retain(|r| {
                    if !removed && r == &record {
                        removed = true;
                        false
                    } else {
                        true
                    }
                });
                if recs.is_empty() {
                    new_zones.records.remove(&name);
                    new_zones.zones.remove(&name);
                }
            }
            s.zones.store(Arc::new(new_zones));
        }
    }

    info!(id=%id, "DNS entry deleted");
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::DeleteDns { id: id.clone() });
    }
    (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok","deleted_id":id})))
}

// ── Blacklist ──────────────────────────────────────────────────────────────

async fn list_blacklist_handler(State(_s): State<AppState>) -> impl IntoResponse {
    match store::load_blacklist() {
        Ok(bl) => (StatusCode::OK, JsonExtract(serde_json::json!({
            "blacklist": bl.entries,
            "total": bl.entries.len()
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
            "error": e.to_string()
        }))),
    }
}

async fn add_blacklist_handler(
    State(s): State<AppState>,
    JsonExtract(req): JsonExtract<AddBlacklistRequest>,
) -> impl IntoResponse {
    // VUL-05: Reject invalid domain names (empty, root zone, Unicode, etc.)
    if let Err(e) = validate_dns_name(&req.domain) {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_NAME", "details": e
        })));
    }
    if let Some(ref desc) = req.description {
        if let Err(e) = validate_no_control_chars(desc, "description") {
            return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                "error": "INVALID_FIELD", "details": e
            })));
        }
    }
    // Persist + inject atomically under zones_mutex (same race-fix as add_dns).
    let entry = {
        let _guard = s.zones_mutex.lock().await;

        let mut bl = store::load_blacklist().unwrap_or_default();
        if bl.entries.len() >= MAX_BLACKLIST_ENTRIES {
            return (StatusCode::UNPROCESSABLE_ENTITY, JsonExtract(serde_json::json!({
                "error": "LIMIT_EXCEEDED",
                "details": format!("Maximum {} blacklist entries reached", MAX_BLACKLIST_ENTRIES)
            })));
        }
        let entry = BlacklistEntry {
            id:          uuid::Uuid::new_v4().to_string(),
            domain:      req.domain.clone(),
            action:      req.action.clone(),
            description: req.description.clone(),
        };
        bl.entries.push(entry.clone());
        if let Err(e) = store::save_blacklist(&bl) {
            return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error": e.to_string()
            })));
        }

        let current = s.zones.load_full();
        let mut new_zones = (*current).clone();
        // VUL-09: override_zone so the blacklist entry always takes precedence
        // over any static zone with the same name defined in unbound.conf.
        new_zones.override_zone(&req.domain, ZoneAction::from(&req.action));
        s.zones.store(Arc::new(new_zones));

        entry
    };

    info!(domain=%req.domain, action=?req.action, "Blacklist entry added");
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::AddBlacklist { entry: entry.clone() });
    }
    (StatusCode::CREATED, JsonExtract(serde_json::json!({
        "status": "ok",
        "entry": entry
    })))
}

async fn delete_blacklist_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _guard = s.zones_mutex.lock().await;

    let mut bl = match store::load_blacklist() {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error": e.to_string()}))),
    };
    let pos = bl.entries.iter().position(|e| e.id == id);
    let Some(pos) = pos else {
        return (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":"NOT_FOUND","id":id})));
    };
    let removed = bl.entries.remove(pos);
    if let Err(e) = store::save_blacklist(&bl) {
        return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error": e.to_string()})));
    }

    let current = s.zones.load_full();
    let mut new_zones = (*current).clone();
    new_zones.remove_zone(&removed.domain);
    s.zones.store(Arc::new(new_zones));

    info!(id=%id, domain=%removed.domain, "Blacklist entry deleted");
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::DeleteBlacklist { id: id.clone() });
    }
    (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok","deleted_id":id,"domain":removed.domain})))
}

// ── Feeds ──────────────────────────────────────────────────────────────────

async fn get_feeds_handler(State(_s): State<AppState>) -> impl IntoResponse {
    let config = feeds::load_feeds().unwrap_or_default();
    (StatusCode::OK, JsonExtract(serde_json::json!({"feeds": config.feeds, "total": config.feeds.len()})))
}

async fn add_feed_handler(
    State(s): State<AppState>,
    JsonExtract(p): JsonExtract<AddFeedRequest>,
) -> impl IntoResponse {
    // Enforce subscription cap before attempting download/validation.
    let current = feeds::load_feeds().unwrap_or_default();
    if current.feeds.len() >= MAX_FEEDS {
        return (StatusCode::UNPROCESSABLE_ENTITY, JsonExtract(serde_json::json!({
            "error": "LIMIT_EXCEEDED",
            "details": format!("Maximum {} feed subscriptions reached", MAX_FEEDS)
        })));
    }
    match add_feed(p.name, p.url, p.format, p.action, p.description).await {
        Ok(feed) => {
            info!("Feed added: {} ({})", feed.name, feed.url);
            if let Some(ref j) = s.sync_journal {
                j.push(SyncOp::AddFeed { feed: feed.clone() });
            }
            (StatusCode::CREATED, JsonExtract(serde_json::json!({
                "status": "ok", "feed": feed,
                "message": "Run POST /feeds/:id/update to fetch domains."
            })))
        }
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, JsonExtract(serde_json::json!({
                "error": "FEED_ERROR", "details": e.to_string()
            })))
        }
    }
}

async fn delete_feed_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match remove_feed(&id) {
        Ok(()) => {
            if let Some(ref j) = s.sync_journal {
                j.push(SyncOp::DeleteFeed { id: id.clone() });
            }
            (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok","deleted_id":id})))
        }
        Err(crate::error::AppError::BadRequest(msg)) => (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"BAD_REQUEST","details":msg}))),
        Err(e) => (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":"FEED_NOT_FOUND","details":e.to_string()}))),
    }
}

async fn update_feeds_handler(State(s): State<AppState>) -> impl IntoResponse {
    match update_all_feeds().await {
        Ok(results) => {
            let updated = results.iter().filter(|r| r.status == "updated").count();
            let errors  = results.iter().filter(|r| r.status == "error").count();
            // Rebuild zone set so newly downloaded feed domains are immediately active.
            let new_zones = crate::build_zone_set(&s.cfg);
            s.zones.store(std::sync::Arc::new(new_zones));
            info!(updated, errors, "Feed update complete — zones rebuilt");
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "status": "ok", "results": results,
                "summary": {"updated": updated, "errors": errors}
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error":e.to_string()}))),
    }
}

async fn update_one_feed_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Look up URL before updating (for journal event)
    let feed_url = feeds::load_feeds()
        .ok()
        .and_then(|cfg| cfg.feeds.into_iter().find(|f| f.id == id))
        .map(|f| f.url);

    match update_one_feed(&id).await {
        Ok(result) => {
            // Rebuild zone set immediately so the refreshed feed is active without a reload.
            let new_zones = crate::build_zone_set(&s.cfg);
            s.zones.store(std::sync::Arc::new(new_zones));
            if result.error.is_none() {
                if let (Some(j), Some(url)) = (s.sync_journal.as_ref(), feed_url) {
                    j.push(SyncOp::UpdateFeed { id: id.clone(), url });
                }
            }
            let code = if result.error.is_some() { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::OK };
            (code, JsonExtract(serde_json::json!({"result": result})))
        }
        Err(crate::error::AppError::BadRequest(msg)) => (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"BAD_REQUEST","details":msg}))),
        Err(e) => (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":e.to_string()}))),
    }
}

async fn feed_presets_handler() -> impl IntoResponse {
    let presets = builtin_presets();
    JsonExtract(serde_json::json!({"presets": presets, "total": presets.len()}))
}

// ── GET /upstreams ─────────────────────────────────────────────────────────

async fn upstreams_handler(State(s): State<AppState>) -> impl IntoResponse {
    let statuses = s.upstreams.read().unwrap().clone();
    let total = statuses.len();
    let healthy = statuses.iter().filter(|u| u.healthy).count();
    JsonExtract(serde_json::json!({
        "upstreams": statuses,
        "total":     total,
        "healthy":   healthy,
    }))
}

// ── GET /logs ──────────────────────────────────────────────────────────────

const LOG_LIMIT_MAX: usize = 1_000;
const LOG_LIMIT_DEFAULT: usize = 100;

#[derive(Deserialize)]
struct LogsParams {
    #[serde(default = "default_log_limit")]
    limit:  usize,
    #[serde(default)]
    page:   usize,
    action: Option<String>,
    client: Option<String>,
    since:  Option<u64>,
}

fn default_log_limit() -> usize { LOG_LIMIT_DEFAULT }

async fn logs_handler(
    State(s):          State<AppState>,
    Query(params):     Query<LogsParams>,
) -> Response {
    if params.limit > LOG_LIMIT_MAX {
        return (StatusCode::UNPROCESSABLE_ENTITY, JsonExtract(serde_json::json!({
            "error":   "INVALID_PARAM",
            "details": format!("limit must be ≤ {}", LOG_LIMIT_MAX),
        }))).into_response();
    }

    let action = match params.action.as_deref() {
        Some(s) => match LogAction::from_str(s) {
            Some(a) => Some(a),
            None => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                "error":   "INVALID_PARAM",
                "details": format!("action '{}' is not valid — expected one of: forwarded, cached, local, blocked, nxdomain, refused, servfail", s),
            }))).into_response(),
        },
        None => None,
    };

    let client = match params.client.as_deref() {
        Some(s) => match s.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                "error":   "INVALID_PARAM",
                "details": format!("client '{}' is not a valid IP address", s),
            }))).into_response(),
        },
        None => None,
    };

    let q = LogQuery {
        limit:      params.limit,
        page:       params.page,
        action,
        client,
        since_secs: params.since,
    };

    let (entries, total) = s.log_buffer.lock().unwrap().query(&q);
    JsonExtract(serde_json::json!({
        "entries": entries,
        "total":   total,
        "page":    params.page,
        "limit":   params.limit,
    })).into_response()
}

// ── TLS status ─────────────────────────────────────────────────────────────

async fn tls_status_handler(State(s): State<AppState>) -> impl IntoResponse {
    let tls = s.tls_cfg.as_ref();
    JsonExtract(serde_json::json!({
        "dot": {
            "enabled": tls.cert_path.is_some() && tls.key_path.is_some(),
            "port": tls.dot_port.unwrap_or(853),
            "rfc": "RFC 7858"
        },
        "doh": {
            "enabled": tls.cert_path.is_some() && tls.key_path.is_some(),
            "port": tls.doh_port.unwrap_or(443),
            "rfc": "RFC 8484"
        },
        "doq": {
            "enabled": tls.cert_path.is_some() && tls.key_path.is_some(),
            "port": tls.doq_port.unwrap_or(853),
            "rfc": "RFC 9250"
        },
        "cert": tls.cert_path.as_deref().unwrap_or("not configured"),
        "hostname": tls.hostname.as_deref().unwrap_or("runbound.local")
    }))
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn ensure_dot(name: &str) -> String {
    if name.ends_with('.') { name.to_string() } else { format!("{}.", name) }
}

/// Reject any string that contains ASCII control characters (0x00–0x1f, 0x7f).
/// Applied to all user-supplied text fields (value, description) to prevent
/// CRLF injection into logs, stored JSON, or HTTP response bodies.
fn validate_no_control_chars(s: &str, field: &'static str) -> Result<(), String> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("Field '{}' must not contain control characters (\\r, \\n, etc.)", field));
    }
    Ok(())
}

/// VUL-05: Validate a DNS name before accepting it from the API.
/// Rejects: empty names, root zone ("."), labels > 63 chars, name > 253 chars,
/// non-ASCII / Unicode (including homoglyph attacks), invalid label characters.
/// Underscores are allowed for service labels (_dmarc, _tcp, etc. — RFC 2782/6763).
fn validate_dns_name(name: &str) -> Result<(), &'static str> {
    let n = name.trim_end_matches('.');
    if n.is_empty() {
        return Err("Domain name cannot be empty or the root zone");
    }
    if n.len() > 253 {
        return Err("Domain name exceeds 253 characters");
    }
    for label in n.split('.') {
        if label.is_empty() {
            return Err("Domain label cannot be empty (no consecutive or leading dots)");
        }
        if label.len() > 63 {
            return Err("Domain label exceeds 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Domain label cannot start or end with a hyphen");
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err("Domain label contains invalid characters \
                        (ASCII alphanumeric, hyphens, underscores only)");
        }
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt; // oneshot

    const TEST_KEY: &str = "test-api-key-for-unit-tests";

    fn make_test_app() -> Router {
        // Initialise API key (OnceLock — safe to call multiple times with same value)
        init_api_key(Some(TEST_KEY.to_string()));
        // Initialise BASE_DIR for store/feeds path resolution (OnceLock — idempotent).
        let _ = crate::runtime::BASE_DIR.set(std::path::PathBuf::from("/tmp/runbound-test"));

        let zones = Arc::new(ArcSwap::new(Arc::new(
            crate::dns::local::LocalZoneSet::default()
        )));
        let cfg_arc = Arc::new(crate::config::parser::UnboundConfig::default());
        let log_buffer = crate::logbuffer::new_shared();
        let upstreams = crate::upstreams::init_upstreams(&cfg_arc);

        let state = AppState {
            zones:       Arc::clone(&zones),
            zones_mutex: Arc::new(tokio::sync::Mutex::new(())),
            tls_cfg:     Arc::new(crate::config::parser::TlsConfig::default()),
            rate_limiter: ApiRateLimiter::new_public(),
            stats:       crate::stats::Stats::new(),
            cfg:         Arc::clone(&cfg_arc),
            cfg_path:    "/dev/null".to_string(),
            log_buffer,
            upstreams,
            sync_journal: None,
            slave_mode:   false,
            base_dir:     Arc::new(std::path::PathBuf::from("/tmp/runbound-test")),
        };
        router(state)
    }

    async fn body_json(body: axum::body::Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn auth_header() -> (&'static str, String) {
        ("Authorization", format!("Bearer {}", TEST_KEY))
    }

    // ── /stats ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn stats_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/stats").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stats_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/stats").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        for field in &["total", "blocked", "forwarded", "qps_1m", "qps_5m",
                       "latency_p50_ms", "cache_hit_rate", "local_hits"] {
            assert!(json.get(field).is_some(), "missing field: {field}");
        }
    }

    // ── /stats/stream ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn stats_stream_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/stats/stream").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stats_stream_content_type() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/stats/stream").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(ct.contains("text/event-stream"), "unexpected Content-Type: {ct}");
    }

    // ── /upstreams ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn upstreams_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/upstreams").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upstreams_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/upstreams").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json.get("upstreams").is_some());
        assert!(json.get("total").is_some());
        assert!(json.get("healthy").is_some());
    }

    // ── /logs ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn logs_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/logs").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logs_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/logs").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json.get("entries").is_some());
        assert!(json.get("total").is_some());
    }

    #[tokio::test]
    async fn logs_limit_too_large() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/logs?limit=2000").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn logs_invalid_action() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/logs?action=invalid").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn logs_invalid_client_ip() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/logs?client=notanip").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
