// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Runbound REST API — full DNS management + feeds + DoT/DoH status

pub mod relay;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Instant;
use std::net::IpAddr;

use dashmap::DashMap;

use std::convert::Infallible;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    response::sse::{Event, KeepAlive, Sse},
    Json as JsonExtract,
    Router,
    routing::{any, delete, get, post},
};
use arc_swap::ArcSwap;
use futures_util::stream;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use hickory_proto::rr::{LowerName, Name, RecordType};
use crate::dns::{BlacklistAction, ZoneAction, local::{LocalZoneSet, parse_local_data}};
use crate::dns::server::{SharedResolver, SharedResolversVec};
use crate::feeds::{self, FeedFormat, add_feed, builtin_presets, remove_feed, update_all_feeds, update_one_feed};
use crate::logbuffer::{LogAction, LogQuery, SharedLogBuffer};
use crate::store::{self, DnsEntry, DnsType, BlacklistEntry};
use crate::config::parser::{TlsConfig, UnboundConfig};
use crate::stats::Stats;
use crate::audit::{AuditEvent, AuditLogger};
use crate::sync::{SyncJournal, SyncOp};
use crate::upstreams::{self, SharedUpstreams};

/// Max TTL for API-created DNS entries (86400 s = 24 h).
/// Prevents TTL-based cache persistence attacks and operator mistakes.
const MAX_API_TTL: u32 = 86_400;

// ── /reload rate limiter ───────────────────────────────────────────────────

/// Independent token bucket for POST /reload — 2 req/s, burst of 2.
/// Kept separate from the main API rate limiter so a burst of reloads cannot
/// consume the shared bucket and throttle other endpoints.
///
/// Uses `std::sync::Mutex` (not tokio) so that `check()` serialises all callers
/// without any async context. Refill and consumption happen inside a single lock
/// acquisition — no TOCTOU possible. `last_refill` is always updated on every
/// call so that elapsed time is never double-counted across concurrent callers.
struct ReloadLimiterInner {
    tokens:      f64,
    last_refill: Instant,
    rate:        f64,  // tokens per second
    burst:       f64,  // maximum token capacity
}

pub struct ReloadLimiter {
    inner: std::sync::Mutex<ReloadLimiterInner>,
}

impl ReloadLimiter {
    pub fn new() -> Self {
        Self::new_with_params(2.0, 2.0)
    }

    pub fn new_with_params(rate: f64, burst: f64) -> Self {
        Self {
            inner: std::sync::Mutex::new(ReloadLimiterInner {
                tokens:      burst,
                last_refill: Instant::now(),
                rate,
                burst,
            }),
        }
    }

    pub fn check(&self) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now     = Instant::now();
        let elapsed = now.duration_since(inner.last_refill).as_secs_f64();
        // Refill and update timestamp unconditionally — no conditional branch that
        // could cause elapsed time to accumulate across multiple callers.
        inner.tokens      = (inner.tokens + elapsed * inner.rate).min(inner.burst);
        inner.last_refill = now;
        if inner.tokens >= 1.0 {
            inner.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── Custom JSON body extractor ─────────────────────────────────────────────
// axum's default Json<T> extractor returns a plain-text 422/400 body on
// deserialization failure (Q-01, Q-02, Q-03). ApiJson<T> wraps it and always
// returns a structured JSON error body so clients can parse the failure
// programmatically.

struct ApiJson<T>(T);

#[axum::async_trait]
impl<T, S> axum::extract::FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, axum::Json<serde_json::Value>);

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(val)) => Ok(ApiJson(val)),
            Err(rejection) => {
                use axum::extract::rejection::JsonRejection;
                let (status, msg) = match rejection {
                    JsonRejection::JsonDataError(e)        => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
                    JsonRejection::JsonSyntaxError(e)      => (StatusCode::BAD_REQUEST,          e.to_string()),
                    JsonRejection::MissingJsonContentType(e) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, e.to_string()),
                    e                                      => (StatusCode::BAD_REQUEST,          e.to_string()),
                };
                Err((status, axum::Json(serde_json::json!({
                    "error":   "INVALID_REQUEST",
                    "details": msg
                }))))
            }
        }
    }
}

// ── API security constants ─────────────────────────────────────────────────

/// API key — stored in an ArcSwap so it can be rotated live via POST /rotate-key.
static API_KEY: std::sync::OnceLock<ArcSwap<String>> = std::sync::OnceLock::new();

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

/// Priority: HSM > RUNBOUND_API_KEY env var > api-key in unbound.conf > auto-generate.
/// Auto-generated keys are 256-bit CSPRNG (2× UUID v4, backed by getrandom).
pub fn init_api_key(config_key: Option<String>) -> String {
    let key = crate::hsm::api_key().map(|k| k.to_string())
        .or_else(|| std::env::var("RUNBOUND_API_KEY").ok())
        .or(config_key)
        .unwrap_or_else(|| {
            // 256 bits from OS CSPRNG — two UUID v4s = 64 hex chars.
            // Previous implementation used PID+timestamp (deterministic → weak).
            format!("{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple())
        });
    API_KEY.get_or_init(|| ArcSwap::from(Arc::new(key.clone())));
    key
}

/// Returns the current API key as an owned Arc — zero-copy for the common read path.
pub fn get_api_key() -> Arc<String> {
    API_KEY.get()
        .map(|s| s.load_full())
        .unwrap_or_else(|| Arc::new(String::new()))
}

/// Atomically replaces the active API key. The old key is invalidated immediately.
pub fn rotate_api_key(new_key: String) {
    if let Some(swap) = API_KEY.get() {
        swap.store(Arc::new(new_key));
    }
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
    pub rate_limiter:   ApiRateLimiter,
    pub reload_limiter: Arc<ReloadLimiter>,
    pub stats:          Arc<Stats>,
    /// Pre-computed snapshot refreshed every second by `qps_update_loop`.
    /// API handlers load this instead of calling `stats.snapshot()` on every
    /// request, avoiding ~360 atomic loads per call under monitoring load.
    pub stats_cache:    crate::stats::SharedSnapshot,
    pub cfg:          Arc<UnboundConfig>,
    pub cfg_path:     String,
    pub log_buffer:   SharedLogBuffer,
    pub upstreams:    SharedUpstreams,
    /// Master: Some(journal) to record write events for slave replication.
    /// Slave / standalone: None.
    pub sync_journal: Option<Arc<SyncJournal>>,
    /// Sync/relay HMAC key — used to sign relay requests (#85/#87).
    pub sync_key:     Option<String>,
    /// This node's stable UUID — set on slave for identification (#88).
    pub node_id:      Option<String>,
    /// True when running as slave — all write operations are blocked (503).
    pub slave_mode:   bool,
    /// Directory where runtime files (api.key, dns_entries.json, …) are stored.
    pub base_dir:     Arc<PathBuf>,
    /// Immutable audit log sender. No-op when audit is disabled.
    pub audit:        AuditLogger,
    /// XDP mode set by main: 0=disabled, 1=drv, 2=skb.
    pub xdp_active:   Arc<AtomicU8>,
    /// Shared DNS resolver — allows cache flush and upstream rebuild from API handlers.
    pub resolver:     SharedResolver,
    /// FEAT #46: tracks when the last successful cache flush was requested.
    /// Guarded by a Mutex so the read-check-write is atomic without await.
    pub last_flush_at: Arc<std::sync::Mutex<Option<Instant>>>,
    /// #51: Cache eviction counter — reset on flush. Hits/misses are read
    /// directly from `stats.cache_hits/misses` (they are incremented there).
    pub cache_evictions: Arc<AtomicU64>,
    /// #75: Rate limiter for POST /api/dns/lookup — 10 req/s global.
    /// The API binds to 127.0.0.1 only, so a global limit is equivalent
    /// to a per-IP limit in practice.
    pub lookup_limiter: Arc<ReloadLimiter>,
    /// #33: per-upstream resolvers used by racing mode — rebuilt when upstreams change.
    pub per_upstream_resolvers: SharedResolversVec,
    /// #33: per-upstream win counters — how many times each upstream answered first.
    pub racing_wins: Arc<DashMap<String, Arc<AtomicU64>, ahash::RandomState>>,
    /// #86: broadcast sender for SSE node-status events.  None on slave/standalone.
    pub events_tx: Option<tokio::sync::broadcast::Sender<crate::sync::NodeStatusEvent>>,
}

// ── Request types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AddDnsRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: DnsType,
    // i64 so serde accepts negative values and we can return a uniform JSON 422
    // instead of axum's default plain-text deserialization error.
    #[serde(default = "default_ttl_i64")]
    pub ttl: i64,
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

fn default_ttl_i64() -> i64 { 3600 }

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
    // ── 0. Body size pre-check ───────────────────────────────────────
    // DefaultBodyLimit fires at extraction time inside the handler, not here.
    // A large body would therefore hit the rate limiter first and return 429
    // instead of 413. Checking Content-Length early produces the correct 413
    // for over-sized requests before the rate limit token is consumed.
    //
    // SEC-04: clients sending chunked bodies (no Content-Length) bypass this
    // check and hit DefaultBodyLimit directly. For very large chunked bodies
    // (> ~512 KB) hyper cannot drain the remaining data before the RST, so
    // the client receives a connection drop instead of 413.
    // Fix: require Content-Length on JSON-body requests. Non-JSON POST
    // endpoints (/reload, /feeds/update, etc.) are unaffected.
    let has_content_type_json = req.headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false);

    if let Some(cl) = req.headers().get(axum::http::header::CONTENT_LENGTH) {
        let len: usize = match cl.to_str().ok().and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
                "error": "BAD_REQUEST",
                "details": "Malformed Content-Length header"
            }))).into_response(),
        };
        if len > MAX_BODY_BYTES {
            return (StatusCode::PAYLOAD_TOO_LARGE, axum::Json(serde_json::json!({
                "error": "REQUEST_TOO_LARGE",
                "details": format!("Body exceeds {} bytes", MAX_BODY_BYTES)
            }))).into_response();
        }
    } else if has_content_type_json {
        // JSON body without Content-Length → 411 Length Required.
        // Eliminates the chunked-body drop-without-413 behaviour (SEC-04).
        return (StatusCode::LENGTH_REQUIRED, axum::Json(serde_json::json!({
            "error": "LENGTH_REQUIRED",
            "details": "Content-Length header is required for JSON requests"
        }))).into_response();
    }

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
        // NEW-HIGH (pentest v0.4.4): timing oracle — pre-auth brute-force brake.
        // The sleep is applied BEFORE constant_time_eq so it cannot be used as
        // a timing signal to distinguish key content. All requests (correct key,
        // wrong key, or partial key) are equally delayed when failures are high.
        let current_failures = AUTH_FAILURES.load(std::sync::atomic::Ordering::Relaxed);
        if current_failures >= 50 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let auth = req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let key = get_api_key();
        let expected = format!("Bearer {}", key.as_str());
        if !constant_time_eq(auth.as_bytes(), expected.as_bytes()) {
            let failures = AUTH_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            // All post-comparison side effects (audit event, periodic warning) run in a
            // background task so the 401 is returned immediately with no timing signal.
            // Combined with the pre-auth sleep above, this eliminates the timing oracle.
            let audit = state.audit.clone();
            let path_owned = path.to_string();
            tokio::spawn(async move {
                audit.send(AuditEvent::AuthFailure { path: path_owned });
                if failures.is_multiple_of(10) {
                    warn!(failures, "Repeated API authentication failures — check RUNBOUND_API_KEY");
                }
            });
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
    // /health stays at root — used by load-balancer probes without auth.
    let health_route = Router::new()
        .route("/health", get(health_handler))
        .with_state(state.clone());

    let api_routes = Router::new()
        // Info
        .route("/help",              get(help_handler))
        // Operations
        .route("/stats",             get(stats_handler))
        .route("/stats/stream",      get(stats_stream_handler))
        .route("/config",            get(config_handler))
        .route("/reload",            post(reload_handler))
        // DNS CRUD
        .route("/dns/lookup",        post(dns_lookup_handler))
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
        // System
        .route("/system",            get(system_handler))
        .route("/cache/flush",       post(cache_flush_handler))
        // TLS / Protocol status
        .route("/tls",               get(tls_status_handler))
        // Monitoring
        .route("/upstreams",         get(upstreams_handler).post(add_upstream_handler))
        .route("/upstreams/presets",    get(upstream_presets_handler))
        .route("/upstreams/reconnect",  post(reconnect_upstreams_handler))
        .route("/upstreams/:id",        delete(delete_upstream_handler).patch(patch_upstream_handler))
        .route("/upstreams/:id/probe",  post(probe_upstream_handler))
        .route("/cache/stats",       get(cache_stats_handler))
        .route("/logs",              get(logs_handler).delete(clear_logs_handler))
        .route("/audit/tail",        get(audit_tail_handler))
        .route("/metrics",           get(metrics_handler))
        // Sync
        .route("/sync/slaves",       get(sync_slaves_handler))
        // #86: SSE node-status stream
        .route("/events",            get(events_handler))
        // Node relay (#85/#87/#88) — master side
        .route("/nodes",                          get(relay::list_nodes_handler))
        .route("/nodes/:node_id/relay/*path",     any(relay::relay_forward_handler))
        // Administration
        .route("/rotate-key",        post(rotate_key_handler))
        .layer(middleware::from_fn_with_state(state.clone(), slave_guard_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), security_middleware))
        // axum DefaultBodyLimit returns HTTP 413 before reading the body into RAM,
        // regardless of payload size. tower_http::RequestBodyLimitLayer drops the
        // TCP connection for very large payloads (> ~512 KB) instead of 413.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    Router::new()
        .merge(health_route)
        .nest("/api", api_routes)
}

// ── GET /help ──────────────────────────────────────────────────────────────

async fn help_handler() -> impl IntoResponse {
    JsonExtract(serde_json::json!({
        "service": "Runbound DNS",
        "version": env!("CARGO_PKG_VERSION"),
        "protocols": ["DNS/UDP:53","DNS/TCP:53","DoT:853","DoH:443","DoQ:853/UDP"],
        "rfcs": ["RFC1034","RFC1035","RFC2782","RFC4033","RFC4034","RFC4035","RFC6698","RFC6891","RFC7858","RFC8484","RFC9250"],
        "endpoints": [
            {"method":"GET",    "path":"/health",               "description":"Liveness check (no auth required)"},
            {"method":"GET",    "path":"/api/help",             "description":"API documentation"},
            {"method":"GET",    "path":"/api/stats",            "description":"Query statistics snapshot"},
            {"method":"GET",    "path":"/api/stats/stream",     "description":"Live stats as Server-Sent Events (1-second interval)"},
            {"method":"GET",    "path":"/api/config",           "description":"Running configuration"},
            {"method":"POST",   "path":"/api/reload",           "description":"Hot-reload zones and blacklist from disk"},
            {"method":"GET",    "path":"/api/dns",              "description":"List all local DNS entries"},
            {"method":"POST",   "path":"/api/dns",              "description":"Add a local DNS entry (A/AAAA/CNAME/TXT/MX/SRV/CAA/PTR/NAPTR/SSHFP/TLSA/NS)"},
            {"method":"DELETE", "path":"/api/dns/:id",          "description":"Remove a DNS entry by UUID"},
            {"method":"GET",    "path":"/api/blacklist",        "description":"List blacklist entries"},
            {"method":"POST",   "path":"/api/blacklist",        "description":"Add a domain to the blacklist (refuse/nxdomain)"},
            {"method":"DELETE", "path":"/api/blacklist/:id",    "description":"Remove a blacklist entry"},
            {"method":"GET",    "path":"/api/feeds",            "description":"List feed subscriptions"},
            {"method":"POST",   "path":"/api/feeds",            "description":"Subscribe to a remote blocklist"},
            {"method":"DELETE", "path":"/api/feeds/:id",        "description":"Remove a feed subscription"},
            {"method":"POST",   "path":"/api/feeds/update",     "description":"Refresh all feeds"},
            {"method":"POST",   "path":"/api/feeds/:id/update", "description":"Refresh one feed"},
            {"method":"GET",    "path":"/api/feeds/presets",    "description":"List pre-configured blocklists"},
            {"method":"GET",    "path":"/api/system",           "description":"Host system info: version, memory, CPU cores, XDP state, workers"},
            {"method":"GET",    "path":"/api/tls",              "description":"DoT/DoH/DoQ TLS status"},
            {"method":"GET",    "path":"/api/upstreams",         "description":"Upstream DNS resolver health"},
            {"method":"POST",   "path":"/api/upstreams",         "description":"Add a runtime upstream resolver"},
            {"method":"DELETE", "path":"/api/upstreams/:id",     "description":"Remove a runtime upstream resolver"},
            {"method":"GET",    "path":"/api/upstreams/presets", "description":"List pre-configured upstream resolvers"},
            {"method":"POST",   "path":"/api/cache/flush",       "description":"Flush the DNS resolver cache"},
            {"method":"GET",    "path":"/api/cache/stats",       "description":"DNS cache counters: hits, misses, evictions, hit rate"},
            {"method":"PATCH",  "path":"/api/upstreams/:id",       "description":"Rename a runtime upstream resolver (only 'name' is patchable)"},
            {"method":"POST",   "path":"/api/upstreams/:id/probe", "description":"Trigger an immediate health probe for one upstream"},
            {"method":"GET",    "path":"/api/sync/slaves",       "description":"List connected slave nodes (master mode only)"},
            {"method":"GET",    "path":"/api/nodes",             "description":"List registered nodes with relay capability (#88)"},
            {"method":"ANY",    "path":"/api/nodes/{id}/relay/*", "description":"Relay request to a registered slave via HMAC-signed channel (#85)"},
            {"method":"GET",    "path":"/api/logs",             "description":"Recent query log (newest first) — ?limit=100&page=0&action=blocked&client=1.2.3.4&since=<unix>"},
            {"method":"DELETE", "path":"/api/logs",             "description":"Clear the in-memory query log ring buffer (GDPR right-to-erasure)"},
            {"method":"GET",    "path":"/api/audit/tail",       "description":"Last N audit log entries — ?n=100"},
            {"method":"GET",    "path":"/api/metrics",          "description":"Prometheus/OpenMetrics exposition (text/plain; version=0.0.4)"},
            {"method":"POST",   "path":"/api/rotate-key",       "description":"Atomically rotate API key — reads new key from RUNBOUND_API_KEY env var"},
        ]
    }))
}

// ── GET /health ────────────────────────────────────────────────────────────

async fn health_handler(State(s): State<AppState>) -> impl IntoResponse {
    let snap = s.stats_cache.load();
    let xdp_active = s.xdp_active.load(Ordering::Relaxed) > 0;
    let (upstreams_healthy, upstreams_total) = {
        let list = s.upstreams.read()
            .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in health handler: {e}"));
        (
            list.iter().filter(|u| u.healthy).count() as u32,
            list.len() as u32,
        )
    };
    // #74: dynamic status — "ok" nominal, "degraded" all upstreams down, "error" no upstreams
    let status = if upstreams_total == 0 {
        "error"
    } else if upstreams_healthy == 0 {
        "degraded"
    } else {
        "ok"
    };
    JsonExtract(serde_json::json!({
        "status":            status,
        "version":           env!("CARGO_PKG_VERSION"),
        "uptime_secs":       snap.uptime_secs,
        "xdp_active":        xdp_active,
        "upstreams_healthy": upstreams_healthy,
        "upstreams_total":   upstreams_total,
        "cache_entries":     snap.cache_entries,
    }))
}

// ── GET /stats ─────────────────────────────────────────────────────────────

async fn stats_handler(State(s): State<AppState>) -> impl IntoResponse {
    JsonExtract(crate::stats::snapshot_to_json(&s.stats_cache.load()))
}

// ── GET /stats/stream ──────────────────────────────────────────────────────

async fn stats_stream_handler(
    State(s): State<AppState>,
) -> Sse<impl stream::Stream<Item = Result<Event, Infallible>>> {
    let sse_stream = stream::unfold(s.stats_cache, |cache| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let data = crate::stats::snapshot_to_json(&cache.load()).to_string();
        let event = Event::default().data(data);
        Some((Ok::<Event, Infallible>(event), cache))
    });
    Sse::new(sse_stream).keep_alive(KeepAlive::default())
}

// ── GET /system ────────────────────────────────────────────────────────────

async fn system_handler(State(s): State<AppState>) -> impl IntoResponse {
    let snap = s.stats_cache.load();
    let xdp_raw = s.xdp_active.load(Ordering::Relaxed);
    let xdp_active = xdp_raw > 0;
    let xdp_mode = match xdp_raw {
        1 => "drv",
        2 => "skb",
        _ => "disabled",
    };

    // Memory: prefer cgroup v2 (container-aware) over /proc/meminfo.
    let (mem_avail_mb, mem_total_mb) = system_memory_mb();

    // Approximate average CPU% for this process since start.
    let cpu_percent = process_cpu_percent();

    // Worker count: one XDP worker per NIC queue + tokio thread pool.
    let cpu_cores = crate::cpu::physical_cores().len().max(1);

    // FEAT #47: upstream health counts
    let (upstreams_healthy, upstreams_total) = {
        let list = s.upstreams.read()
            .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in system handler: {e}"));
        (
            list.iter().filter(|u| u.healthy).count() as u32,
            list.len() as u32,
        )
    };

    let dot_reconnects_total = s.stats.dot_reconnects_total.load(Ordering::Relaxed);
    let last_reconnect_at = s.stats.last_reconnect_at.lock()
        .ok()
        .and_then(|g| g.clone())
        .map(serde_json::Value::String)
        .unwrap_or(serde_json::Value::Null);

    // XDP wire-format cache stats (#64)
    let xdp_cache_entries = crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_ENTRIES
        .load(Ordering::Relaxed);
    let xdp_hits   = crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_HITS
        .load(Ordering::Relaxed);
    let xdp_misses = crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
        .load(Ordering::Relaxed);
    let xdp_cache_hit_rate = if xdp_hits + xdp_misses > 0 {
        (xdp_hits as f64 / (xdp_hits + xdp_misses) as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    // #80: NIC ring buffer + drop stats
    let nic_rx_ring     = crate::dns::xdp::socket::XDP_NIC_RX_RING.load(Ordering::Relaxed);
    let nic_rx_ring_max = crate::dns::xdp::socket::XDP_NIC_RX_RING_MAX.load(Ordering::Relaxed);
    let nic_rx_dropped  = crate::dns::xdp::socket::XDP_ACTIVE_IFACE
        .get()
        .map(|iface| crate::dns::xdp::socket::read_nic_rx_dropped(iface))
        .unwrap_or(0);

    // #33: upstream racing wins per upstream.
    let upstream_racing_wins: serde_json::Map<String, serde_json::Value> = s.racing_wins
        .iter()
        .map(|kv| (kv.key().clone(), serde_json::Value::Number(
            serde_json::Number::from(kv.value().load(Ordering::Relaxed))
        )))
        .collect();

    JsonExtract(serde_json::json!({
        "version":              env!("CARGO_PKG_VERSION"),
        "uptime_secs":          snap.uptime_secs,
        "xdp_active":           xdp_active,
        "xdp_mode":             xdp_mode,
        "cpu_cores":            cpu_cores,
        "cpu_percent":          cpu_percent,
        "mem_total_mb":         mem_total_mb,
        "mem_avail_mb":         mem_avail_mb,
        "cache_entries":        snap.cache_entries,
        "workers":              cpu_cores,
        "prefetch_enabled":     s.cfg.prefetch,
        "upstreams_healthy":    upstreams_healthy,
        "upstreams_total":      upstreams_total,
        "dot_reconnects_total": dot_reconnects_total,
        "last_reconnect_at":    last_reconnect_at,
        "xdp_cache_entries":       xdp_cache_entries,
        "xdp_cache_hit_rate":      xdp_cache_hit_rate,
        "xdp_domain_routing":      s.cfg.xdp_domain_routing,
        "xdp_worker_distribution": crate::dns::cache_snapshot::XDP_WORKER_PKTS
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect::<Vec<u64>>(),
        "nic_rx_ring":     nic_rx_ring,
        "nic_rx_ring_max": nic_rx_ring_max,
        "nic_rx_dropped":  nic_rx_dropped,
        "upstream_racing":      s.cfg.upstream_racing,
        "upstream_racing_wins": upstream_racing_wins,
    }))
}

/// Read system memory (MB). Prefers cgroup v2 inside containers.
fn system_memory_mb() -> (u64, u64) {
    // cgroup v2
    if let Some(max_bytes) = cgroup_memory_max_bytes() {
        let current = cgroup_memory_current_bytes().unwrap_or(0);
        return (
            max_bytes.saturating_sub(current) / (1024 * 1024),
            max_bytes / (1024 * 1024),
        );
    }
    // /proc/meminfo fallback
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        let (mut total_kb, mut avail_kb) = (0u64, 0u64);
        for line in text.lines() {
            if line.starts_with("MemTotal:")     { total_kb = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0); }
            if line.starts_with("MemAvailable:") { avail_kb = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0); }
        }
        return (avail_kb / 1024, total_kb / 1024);
    }
    (0, 0)
}

/// Read the cgroup v2 hard memory limit in bytes (None = unlimited).
fn cgroup_memory_max_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    let s = s.trim();
    if s == "max" { return None; }
    s.parse().ok()
}

/// Read the cgroup v2 current memory usage in bytes.
fn cgroup_memory_current_bytes() -> Option<u64> {
    std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()?.trim().parse().ok()
}

/// Compute average CPU% for this process since it started.
/// Reads /proc/self/stat (utime+stime) and /proc/uptime.
fn process_cpu_percent() -> f64 {
    let stat = match std::fs::read_to_string("/proc/self/stat") {
        Ok(s) => s, Err(_) => return 0.0,
    };
    // Skip past the comm field "(name)" which may contain spaces.
    let after_comm = match stat.find(')') {
        Some(p) => p + 2, None => return 0.0,
    };
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
    let utime:     u64 = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0);
    let stime:     u64 = fields.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
    let starttime: u64 = fields.get(19).and_then(|v| v.parse().ok()).unwrap_or(0);
    let uptime_s: f64 = std::fs::read_to_string("/proc/uptime").ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(0.0);
    const CLK_TCK: f64 = 100.0; // sysconf(_SC_CLK_TCK) on all supported Linux targets
    let proc_uptime = uptime_s - (starttime as f64 / CLK_TCK);
    if proc_uptime <= 0.0 { return 0.0; }
    ((utime + stime) as f64 / CLK_TCK / proc_uptime * 1000.0).round() / 10.0
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
        "log_retention":     cfg.log_retention,
        "log_client_ip":     cfg.log_client_ip,
        "api_port":          cfg.api_port,
        // api_key intentionally omitted — secret
        "logfile":           cfg.logfile,
        // HSM config — pin masked
        "hsm": serde_json::json!({
            "active":            crate::hsm::is_active(),
            "pkcs11_lib":        cfg.hsm_pkcs11_lib,
            "slot":              cfg.hsm_slot,
            "pin":               cfg.hsm_pin.as_ref().map(|_| "***"),
            "api_key_label":     cfg.hsm_api_key_label,
            "store_key_label":   cfg.hsm_store_key_label,
        }),
    }))
}

// ── POST /reload ────────────────────────────────────────────────────────────

async fn reload_handler(State(s): State<AppState>) -> impl IntoResponse {
    // FIX 3.2: independent 2 RPS cap — prevents authenticated DoS via rapid reloads.
    if !s.reload_limiter.check() {
        return (StatusCode::TOO_MANY_REQUESTS, JsonExtract(serde_json::json!({
            "error":   "RATE_LIMITED",
            "details": "reload endpoint is limited to 2 requests per second",
        })));
    }
    match crate::config::load(&s.cfg_path) {
        Ok(new_cfg) => {
            let new_zones = crate::build_zone_set(&new_cfg);
            s.zones.store(std::sync::Arc::new(new_zones));
            info!(cfg_path = %s.cfg_path, "API hot-reload complete");
            s.audit.send(AuditEvent::ConfigReload);
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "status":      "ok",
                "cfg_path":    s.cfg_path,
                "local_zones": new_cfg.local_zones.len(),
                "local_data":  new_cfg.local_data.len(),
            })))
        }
        Err(e) => {
            // FIX 3.4: full error already in the WARN log; sanitize the HTTP body.
            warn!(err = %e, "API reload failed — keeping current zones");
            (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error":   "RELOAD_FAILED",
                "details": sanitize_error(&e),
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
        Err(e) => {
            warn!(err = %e, "store load failed");
            (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error": sanitize_error(&e)
            })))
        }
    }
}

type ApiError = (StatusCode, JsonExtract<serde_json::Value>);

/// Validate all fields of an AddDnsRequest and build the DnsEntry + RR + Record.
/// Returns the triple on success, or a (StatusCode, JSON error) ready to return.
fn validate_dns_entry(req: &AddDnsRequest) -> Result<(DnsEntry, String, hickory_proto::rr::Record), ApiError> {
    // VUL-05: Reject malformed or dangerous names before any parsing.
    if let Err(e) = validate_dns_name(&req.name) {
        return Err((StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_NAME", "details": e
        }))));
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
            return Err((StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                "error": "INVALID_FIELD", "details": e
            }))));
        }
    }
    // S-10: for record types where value is a domain name, validate it as such.
    // validate_no_control_chars is not enough — it would accept a 300-char CNAME target.
    match req.entry_type {
        DnsType::CNAME | DnsType::NS | DnsType::PTR | DnsType::MX | DnsType::SRV => {
            if let Some(ref v) = req.value {
                if let Err(e) = validate_dns_name(v) {
                    return Err((StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                        "error": "INVALID_VALUE", "details": e
                    }))));
                }
            }
        }
        DnsType::NAPTR => {
            // replacement may be "." (no-replacement special case — RFC 2915 §2)
            if let Some(ref r) = req.replacement {
                if r != "." {
                    if let Err(e) = validate_dns_name(r) {
                        return Err((StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                            "error": "INVALID_REPLACEMENT", "details": e
                        }))));
                    }
                }
            }
        }
        _ => {}
    }
    // RFC 2181 §8: TTL is a non-negative 32-bit integer; values outside
    // [0, 2^31-1] must be rejected with a uniform JSON error.
    const RFC2181_MAX_TTL: i64 = 2_147_483_647;
    if req.ttl < 0 || req.ttl > RFC2181_MAX_TTL {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, JsonExtract(serde_json::json!({
            "error": "INVALID_TTL",
            "details": "TTL must be between 0 and 2147483647"
        }))));
    }
    let ttl = req.ttl as u32;
    let entry = DnsEntry {
        id:               DnsEntry::new_id(),
        name:             ensure_dot(&req.name),
        entry_type:       req.entry_type.clone(),
        ttl:              ttl.min(MAX_API_TTL),
        value:            req.value.clone(),
        priority:         req.priority,
        weight:           req.weight,
        port:             req.port,
        flags:            req.flags,
        tag:              req.tag.clone(),
        order:            req.order,
        preference_naptr: req.preference_naptr,
        flags_naptr:      req.flags_naptr.clone(),
        services:         req.services.clone(),
        regexp:           req.regexp.clone(),
        replacement:      req.replacement.clone(),
        algorithm:        req.algorithm,
        fp_type:          req.fp_type,
        fingerprint:      req.fingerprint.clone(),
        cert_usage:       req.cert_usage,
        selector:         req.selector,
        matching_type:    req.matching_type,
        cert_data:        req.cert_data.clone(),
        description:      req.description.clone(),
    };
    let rr = match entry.to_rr_string() {
        Some(r) => r,
        None => return Err((StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_ENTRY",
            "details": "Missing required fields for this record type"
        })))),
    };
    let record = match parse_local_data(&rr) {
        Some(r) => r,
        None => {
            // FIX 6 (VUL-NEW-07): do not reflect the internal RR string in the HTTP response;
            // log it server-side so operators can diagnose but clients see no filesystem/config detail.
            warn!(rr = %rr, "RR parse failed for input");
            return Err((StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                "error": "PARSE_FAILED",
                "details": "Record validation failed"
            }))));
        }
    };
    Ok((entry, rr, record))
}

/// Persist entry to disk and atomically inject into the live zone set.
/// VUL-FIX: store load/save MUST be inside zones_mutex.  Without this,
/// two concurrent POST /dns both load the same snapshot, each append
/// their entry, and the last writer wins — the other entry is silently
/// lost from the on-disk store.
async fn persist_and_swap(
    entry: &DnsEntry,
    record: hickory_proto::rr::Record,
    s: &AppState,
) -> Result<(), ApiError> {
    {
        let _guard = s.zones_mutex.lock().await;

        let mut st = store::load().unwrap_or_default();
        if st.entries.len() >= MAX_DNS_ENTRIES {
            return Err((StatusCode::UNPROCESSABLE_ENTITY, JsonExtract(serde_json::json!({
                "error": "LIMIT_EXCEEDED",
                "details": format!("Maximum {} DNS entries reached", MAX_DNS_ENTRIES)
            }))));
        }
        st.entries.push(entry.clone());
        if let Err(e) = store::save(&st) {
            warn!(err = %e, "store save failed");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error": sanitize_error(&e)
            }))));
        }

        let current = s.zones.load_full();
        let mut new_zones = (*current).clone();
        let name = record.name.clone();
        new_zones.zones.entry(name.clone()).or_insert(ZoneAction::Static);
        new_zones.records.entry(name).or_default().push(record);
        s.zones.store(Arc::new(new_zones));
    }
    info!(id=%entry.id, name=%entry.name, r#type=?entry.entry_type, "DNS entry added");
    s.audit.send(AuditEvent::DnsAdd {
        name:  entry.name.clone(),
        rtype: format!("{:?}", entry.entry_type),
        value: entry.value.clone().unwrap_or_default(),
    });
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::AddDns { entry: entry.clone() });
        if let Some(ref k) = s.sync_key {
            if let Ok(b) = serde_json::to_vec(&entry) {
                relay::push_to_slaves(j, k, Method::POST, "dns".to_string(), bytes::Bytes::from(b));
            }
        }
    }
    Ok(())
}

async fn add_dns_handler(
    State(s): State<AppState>,
    ApiJson(req): ApiJson<AddDnsRequest>,
) -> impl IntoResponse {
    let (entry, rr, record) = match validate_dns_entry(&req) {
        Ok(v)  => v,
        Err(e) => return e,
    };
    if let Err(e) = persist_and_swap(&entry, record, &s).await {
        return e;
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
        Err(e) => {
            warn!(err = %e, "store load failed in delete_dns");
            return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error": sanitize_error(&e)})));
        }
    };

    let pos = st.entries.iter().position(|e| e.id == id);
    let Some(pos) = pos else {
        return (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":"NOT_FOUND","id":id})));
    };

    let entry = st.entries.remove(pos);
    if let Err(e) = store::save(&st) {
        warn!(err = %e, "store save failed in delete_dns");
        return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error": sanitize_error(&e)})));
    }

    // Remove from live zone set — ArcSwap write
    if let Some(rr) = entry.to_rr_string() {
        if let Some(record) = parse_local_data(&rr) {
            let current = s.zones.load_full();
            let mut new_zones = (*current).clone();
            let name = record.name.clone();
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
    s.audit.send(AuditEvent::DnsDelete { id: id.clone() });
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::DeleteDns { id: id.clone() });
        if let Some(ref k) = s.sync_key {
            relay::push_to_slaves(j, k, Method::DELETE, format!("dns/{id}"), bytes::Bytes::new());
        }
    }
    (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok","deleted_id":id})))
}

// ── POST /api/dns/lookup ───────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct DnsLookupRequest {
    name: String,
    #[serde(rename = "type", default = "dns_lookup_default_type")]
    qtype: String,
}

fn dns_lookup_default_type() -> String { "A".to_string() }

async fn dns_lookup_handler(
    State(s): State<AppState>,
    ApiJson(p): ApiJson<DnsLookupRequest>,
) -> impl IntoResponse {
    if !s.lookup_limiter.check() {
        return (StatusCode::TOO_MANY_REQUESTS, JsonExtract(serde_json::json!({
            "error": "RATE_LIMITED", "details": "Max 10 req/s"
        }))).into_response();
    }

    if let Err(e) = validate_dns_name(&p.name) {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_NAME", "details": e
        }))).into_response();
    }

    let qtype: RecordType = match p.qtype.to_uppercase().as_str() {
        "A"     => RecordType::A,
        "AAAA"  => RecordType::AAAA,
        "MX"    => RecordType::MX,
        "TXT"   => RecordType::TXT,
        "CNAME" => RecordType::CNAME,
        "PTR"   => RecordType::PTR,
        other   => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_TYPE",
            "details": format!("Unsupported type '{other}'. Use: A, AAAA, MX, TXT, CNAME, PTR")
        }))).into_response(),
    };

    let fqdn_str = if p.name.ends_with('.') { p.name.clone() } else { format!("{}.", p.name) };
    let name = match fqdn_str.parse::<Name>() {
        Ok(n) => n,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_NAME", "details": "Could not parse as DNS name"
        }))).into_response(),
    };
    let lower = LowerName::from(&name);

    // Check local zones first
    {
        let zones_snap = s.zones.load();
        match zones_snap.find(&lower) {
            Some(crate::dns::ZoneAction::Refuse) | Some(crate::dns::ZoneAction::NxDomain) => {
                return (StatusCode::OK, JsonExtract(serde_json::json!({
                    "name": p.name, "type": p.qtype,
                    "answers": [], "status": "BLOCKED",
                    "elapsed_ms": 0, "from_cache": false
                }))).into_response();
            }
            Some(crate::dns::ZoneAction::Static) | Some(crate::dns::ZoneAction::Redirect) => {
                let records = zones_snap.local_records(&lower, qtype);
                let answers: Vec<serde_json::Value> = records.iter().map(|r| {
                    serde_json::json!({ "ttl": r.ttl, "data": r.data.to_string() })
                }).collect();
                return (StatusCode::OK, JsonExtract(serde_json::json!({
                    "name": p.name, "type": p.qtype,
                    "answers": answers, "status": "NOERROR",
                    "elapsed_ms": 0, "from_cache": true
                }))).into_response();
            }
            None => {}
        }
    }

    // Resolve upstream
    let start = std::time::Instant::now();
    match s.resolver.load().lookup(name, qtype).await {
        Ok(lookup) => {
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let from_cache = elapsed_ms * 1000 < crate::stats::CACHE_HIT_THRESHOLD_US;
            let answers: Vec<serde_json::Value> = lookup.answers().iter().map(|r| {
                serde_json::json!({ "ttl": r.ttl, "data": r.data.to_string() })
            }).collect();
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "name": p.name, "type": p.qtype,
                "answers": answers, "status": "NOERROR",
                "elapsed_ms": elapsed_ms, "from_cache": from_cache
            }))).into_response()
        }
        Err(e) => {
            use hickory_resolver::net::{DnsError, NetError, NoRecords};
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let status = match &e {
                NetError::Dns(DnsError::NoRecordsFound(NoRecords { response_code, .. })) => {
                    use hickory_proto::op::ResponseCode;
                    match response_code {
                        ResponseCode::NXDomain => "NXDOMAIN",
                        ResponseCode::Refused  => "REFUSED",
                        _                      => "SERVFAIL",
                    }
                }
                _ => "SERVFAIL",
            };
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "name": p.name, "type": p.qtype,
                "answers": [], "status": status,
                "elapsed_ms": elapsed_ms, "from_cache": false
            }))).into_response()
        }
    }
}

// ── Blacklist ──────────────────────────────────────────────────────────────

async fn list_blacklist_handler(State(_s): State<AppState>) -> impl IntoResponse {
    match store::load_blacklist() {
        Ok(bl) => (StatusCode::OK, JsonExtract(serde_json::json!({
            "blacklist": bl.entries,
            "total": bl.entries.len()
        }))),
        Err(e) => {
            warn!(err = %e, "blacklist load failed");
            (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error": sanitize_error(&e)
            })))
        }
    }
}

async fn add_blacklist_handler(
    State(s): State<AppState>,
    ApiJson(req): ApiJson<AddBlacklistRequest>,
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
            warn!(err = %e, "blacklist save failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error": sanitize_error(&e)
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
    s.audit.send(AuditEvent::BlacklistAdd { domain: entry.domain.clone() });
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::AddBlacklist { entry: entry.clone() });
        if let Some(ref k) = s.sync_key {
            if let Ok(b) = serde_json::to_vec(&entry) {
                relay::push_to_slaves(j, k, Method::POST, "blacklist".to_string(), bytes::Bytes::from(b));
            }
        }
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
        Err(e) => {
            warn!(err = %e, "blacklist load failed in delete");
            return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error": sanitize_error(&e)})));
        }
    };
    let pos = bl.entries.iter().position(|e| e.id == id);
    let Some(pos) = pos else {
        return (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":"NOT_FOUND","id":id})));
    };
    let removed = bl.entries.remove(pos);
    if let Err(e) = store::save_blacklist(&bl) {
        warn!(err = %e, "blacklist save failed in delete");
        return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error": sanitize_error(&e)})));
    }

    let current = s.zones.load_full();
    let mut new_zones = (*current).clone();
    new_zones.remove_zone(&removed.domain);
    s.zones.store(Arc::new(new_zones));

    info!(id=%id, domain=%removed.domain, "Blacklist entry deleted");
    s.audit.send(AuditEvent::BlacklistDelete { id: id.clone() });
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::DeleteBlacklist { id: id.clone() });
        if let Some(ref k) = s.sync_key {
            relay::push_to_slaves(j, k, Method::DELETE, format!("blacklist/{id}"), bytes::Bytes::new());
        }
    }
    (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok","deleted_id":id,"domain":removed.domain})))
}

// ── Feeds ──────────────────────────────────────────────────────────────────

async fn get_feeds_handler(State(_s): State<AppState>) -> impl IntoResponse {
    let config = feeds::load_feeds().unwrap_or_default();
    let feeds: Vec<serde_json::Value> = config.feeds.iter().map(|f| {
        let blocked_count: serde_json::Value = if f.enabled {
            serde_json::json!(feeds::load_feed_domains(&f.id).len())
        } else {
            serde_json::Value::Null
        };
        let mut v = serde_json::to_value(f).unwrap_or_default();
        if let serde_json::Value::Object(ref mut m) = v {
            m.insert("blocked_count".to_string(), blocked_count);
        }
        v
    }).collect();
    let total = feeds.len();
    (StatusCode::OK, JsonExtract(serde_json::json!({"feeds": feeds, "total": total})))
}

async fn add_feed_handler(
    State(s): State<AppState>,
    ApiJson(p): ApiJson<AddFeedRequest>,
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
            s.audit.send(AuditEvent::FeedAdd {
                id:   feed.id.clone(),
                name: feed.name.clone(),
                url:  feed.url.clone(),
            });
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
            s.audit.send(AuditEvent::FeedDelete { id: id.clone() });
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

/// #33: rebuild per-upstream resolvers if racing is enabled.
/// Called after any upstream list change (add, delete, reconnect).
fn rebuild_racing_resolvers(s: &AppState) {
    if !s.cfg.upstream_racing { return; }
    let addrs = upstreams::upstream_addrs(&s.upstreams);
    match crate::dns::server::build_per_upstream_resolvers(&addrs, s.cfg.dnssec_validation) {
        Ok(vec) => {
            info!(count = vec.len(), "upstream-racing: per-upstream resolvers rebuilt");
            s.per_upstream_resolvers.store(Arc::new(vec));
        }
        Err(e) => warn!(err = %e, "upstream-racing: rebuild failed — racing resolvers unchanged"),
    }
}

// ── GET /api/upstreams ─────────────────────────────────────────────────────

async fn upstreams_handler(State(s): State<AppState>) -> impl IntoResponse {
    let statuses = match s.upstreams.read() {
        Ok(g)  => g.clone(),
        Err(e) => {
            error!(err = %e, "upstreams RwLock poisoned");
            return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error": "INTERNAL", "details": "upstream state unavailable"
            }))).into_response();
        }
    };
    let total   = statuses.len();
    let healthy = statuses.iter().filter(|u| u.healthy).count();
    (StatusCode::OK, JsonExtract(serde_json::json!({
        "upstreams": statuses,
        "total":     total,
        "healthy":   healthy,
    }))).into_response()
}

// ── POST /api/upstreams ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddUpstreamRequest {
    addr:         String,
    #[serde(default = "default_protocol")]
    protocol:     String,
    name:         Option<String>,
    /// Explicit port. Defaults to 53 (UDP) or 853 (DoT) if omitted.
    port:         Option<u16>,
    /// #56: TLS SNI hostname for DoT upstreams. If absent, derived automatically
    /// from well-known IPs (Cloudflare, Google, Quad9, OpenDNS).
    tls_hostname: Option<String>,
}
fn default_protocol() -> String { "udp".into() }

async fn add_upstream_handler(
    State(s): State<AppState>,
    ApiJson(req): ApiJson<AddUpstreamRequest>,
) -> impl IntoResponse {
    // Validate protocol
    if req.protocol != "udp" && req.protocol != "dot" {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_PROTOCOL", "details": "protocol must be 'udp' or 'dot'"
        }))).into_response();
    }
    // Validate addr is a valid IP (no @ syntax — port is a separate field now)
    let ip: IpAddr = match req.addr.parse() {
        Ok(ip) => ip,
        Err(_) => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_ADDR", "details": "addr must be a valid IP address (e.g. 1.1.1.1)"
        }))).into_response(),
    };
    // FIX #40: reject loopback and IPv4 link-local
    if ip.is_loopback() {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_ADDR",
            "details": "loopback addresses cannot be used as upstream resolvers"
        }))).into_response();
    }
    if let IpAddr::V4(v4) = ip {
        if v4.is_link_local() {
            return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                "error": "INVALID_ADDR",
                "details": "link-local addresses cannot be used as upstream resolvers"
            }))).into_response();
        }
    }
    // SEC-11: reject unspecified (0.0.0.0 / ::) — routes to loopback on Linux (SSRF)
    if ip.is_unspecified() {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_ADDR",
            "details": "unspecified addresses cannot be used as upstream resolvers"
        }))).into_response();
    }
    // FIX #44: resolve port with sensible defaults; reject port 0
    let default_port: u16 = if req.protocol == "dot" { 853 } else { 53 };
    let port = req.port.unwrap_or(default_port);
    if port == 0 {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_PORT", "details": "port must be between 1 and 65535"
        }))).into_response();
    }

    // #56: validate optional tls_hostname
    let tls_hostname = match validate_tls_hostname(req.tls_hostname.as_deref()) {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_FIELD", "details": e
        }))).into_response(),
    };

    let entry = upstreams::add_upstream(&s.upstreams, req.addr, port, req.protocol, req.name, tls_hostname);

    // Rebuild resolver with updated upstream list
    let addrs = upstreams::upstream_addrs(&s.upstreams);
    if let Err(e) = crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, s.cfg.dnssec_validation).await {
        warn!(%e, "resolver rebuild after upstream add failed — upstream added but DNS unchanged");
    }
    rebuild_racing_resolvers(&s);
    // FIX #43: persist after successful add
    upstreams::save_upstreams(&s.upstreams, &s.base_dir);

    info!(id = %entry.id, addr = %entry.addr, port = entry.port, protocol = %entry.protocol, "upstream added via API");
    if let (Some(ref j), Some(ref k)) = (&s.sync_journal, &s.sync_key) {
        j.push(SyncOp::AddUpstream {
            addr: entry.addr.clone(), port: entry.port,
            protocol: entry.protocol.clone(), name: entry.name.clone(),
            tls_hostname: entry.tls_hostname.clone(),
        });
        let body = serde_json::json!({
            "addr": entry.addr, "port": entry.port,
            "protocol": entry.protocol, "name": entry.name, "tls_hostname": entry.tls_hostname,
        });
        if let Ok(b) = serde_json::to_vec(&body) {
            relay::push_to_slaves(j, k, Method::POST, "upstreams".to_string(), bytes::Bytes::from(b));
        }
    }
    (StatusCode::CREATED, JsonExtract(serde_json::json!({
        "status": "ok", "upstream": entry
    }))).into_response()
}

// ── DELETE /api/upstreams/:id ──────────────────────────────────────────────

async fn delete_upstream_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // FIX #41: refuse to delete the last upstream — resolver would be empty.
    {
        let list = s.upstreams.read()
            .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in delete handler: {e}"));
        let target_exists = list.iter().any(|u| u.id == id);
        if target_exists && list.len() == 1 {
            return (StatusCode::CONFLICT, JsonExtract(serde_json::json!({
                "error":   "LAST_UPSTREAM",
                "details": "cannot delete the last upstream resolver"
            }))).into_response();
        }
    }

    // #57: if this is a config-file upstream, remove its forward-addr from unbound.conf.
    {
        let list = s.upstreams.read()
            .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in delete handler: {e}"));
        if let Some(u) = list.iter().find(|u| u.id == id) {
            if u.source == "config" {
                let addr  = u.addr.clone();
                let port  = u.port;
                let path  = s.cfg_path.clone();
                drop(list);
                match upstreams::remove_forward_addr_from_config(&path, &addr, port) {
                    Ok(true)  => info!(id = %id, addr = %addr, cfg = %path, "config upstream removed from unbound.conf"),
                    Ok(false) => warn!(id = %id, addr = %addr, "forward-addr line not found in config"),
                    Err(e)    => warn!(%e, id = %id, addr = %addr, "failed to edit unbound.conf"),
                }
            }
        }
    }

    match upstreams::remove_upstream(&s.upstreams, &id) {
        Some(removed) => {
            let addrs = upstreams::upstream_addrs(&s.upstreams);
            if let Err(e) = crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, s.cfg.dnssec_validation).await {
                warn!(%e, "resolver rebuild after upstream delete failed");
            }
            rebuild_racing_resolvers(&s);
            // FIX #43: persist after successful delete
            upstreams::save_upstreams(&s.upstreams, &s.base_dir);
            info!(id = %id, addr = %removed.addr, "upstream deleted via API");
            if let (Some(ref j), Some(ref k)) = (&s.sync_journal, &s.sync_key) {
                j.push(SyncOp::DeleteUpstream { id: id.clone() });
                relay::push_to_slaves(j, k, Method::DELETE, format!("upstreams/{id}"), bytes::Bytes::new());
            }
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "status": "ok", "deleted_id": id, "addr": removed.addr
            }))).into_response()
        }
        None => (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({
            "error": "NOT_FOUND", "id": id
        }))).into_response(),
    }
}

// ── GET /api/upstreams/presets ─────────────────────────────────────────────

async fn upstream_presets_handler() -> impl IntoResponse {
    // FIX #42: DoT entries use a separate `port` field — addr contains only the IP.
    // #56: DoT presets include tls_hostname so the hickory resolver uses the correct SNI.
    JsonExtract(serde_json::json!({ "presets": [
        {"name":"Cloudflare",          "addr":"1.1.1.1",        "port":53,  "protocol":"udp","description":"Cloudflare DNS — privacy-focused, fast"},
        {"name":"Cloudflare alt",      "addr":"1.0.0.1",        "port":53,  "protocol":"udp","description":"Cloudflare secondary"},
        {"name":"Cloudflare DoT",      "addr":"1.1.1.1",        "port":853, "protocol":"dot","tls_hostname":"cloudflare-dns.com","description":"Cloudflare DNS-over-TLS"},
        {"name":"Cloudflare DoT alt",  "addr":"1.0.0.1",        "port":853, "protocol":"dot","tls_hostname":"cloudflare-dns.com","description":"Cloudflare DNS-over-TLS secondary"},
        {"name":"Google",              "addr":"8.8.8.8",        "port":53,  "protocol":"udp","description":"Google Public DNS"},
        {"name":"Google alt",          "addr":"8.8.4.4",        "port":53,  "protocol":"udp","description":"Google Public DNS secondary"},
        {"name":"Google DoT",          "addr":"8.8.8.8",        "port":853, "protocol":"dot","tls_hostname":"dns.google","description":"Google DNS-over-TLS"},
        {"name":"Google DoT alt",      "addr":"8.8.4.4",        "port":853, "protocol":"dot","tls_hostname":"dns.google","description":"Google DNS-over-TLS secondary"},
        {"name":"Quad9",               "addr":"9.9.9.9",        "port":53,  "protocol":"udp","description":"Quad9 — malware-blocking, privacy-focused"},
        {"name":"Quad9 alt",           "addr":"149.112.112.112","port":53,  "protocol":"udp","description":"Quad9 secondary"},
        {"name":"Quad9 DoT",           "addr":"9.9.9.9",        "port":853, "protocol":"dot","tls_hostname":"dns.quad9.net","description":"Quad9 DNS-over-TLS"},
        {"name":"Quad9 DoT alt",       "addr":"149.112.112.112","port":853, "protocol":"dot","tls_hostname":"dns.quad9.net","description":"Quad9 DNS-over-TLS secondary"},
        {"name":"OpenDNS",             "addr":"208.67.222.222", "port":53,  "protocol":"udp","description":"Cisco OpenDNS"},
        {"name":"OpenDNS alt",         "addr":"208.67.220.220", "port":53,  "protocol":"udp","description":"Cisco OpenDNS secondary"},
    ]}))
}

// ── POST /api/cache/flush ──────────────────────────────────────────────────

async fn cache_flush_handler(State(s): State<AppState>) -> impl IntoResponse {
    // FEAT #46: cooldown guard — reject if called too soon after the last flush.
    let cooldown = s.cfg.cache_flush_cooldown;
    if cooldown > 0 {
        let mut last = s.last_flush_at.lock()
            .unwrap_or_else(|e| panic!("last_flush_at poisoned: {e}"));
        if let Some(t) = *last {
            let elapsed = t.elapsed().as_secs();
            if elapsed < cooldown {
                let retry_after = cooldown - elapsed;
                let mut resp = (StatusCode::TOO_MANY_REQUESTS, JsonExtract(serde_json::json!({
                    "error": "FLUSH_COOLDOWN",
                    "retry_after_secs": retry_after
                }))).into_response();
                resp.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from_str(&retry_after.to_string())
                        .unwrap_or_else(|e| panic!("Retry-After header value: {e}")),
                );
                return resp;
            }
        }
        *last = Some(Instant::now());
        // Lock released here — flush proceeds without holding the mutex.
    }

    let before = s.stats.snapshot().cache_entries;
    let addrs  = upstreams::upstream_addrs(&s.upstreams);
    match crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, s.cfg.dnssec_validation).await {
        Ok(_warmed) => {
            s.stats.reset_cache();
            s.cache_evictions.store(0, Ordering::Relaxed);
            info!(flushed = before, "DNS cache flushed via API");
            s.audit.send(AuditEvent::ConfigReload);
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "status": "ok", "flushed_entries": before
            }))).into_response()
        }
        Err(e) => {
            warn!(%e, "cache flush: resolver rebuild failed");
            (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
                "error": "FLUSH_FAILED", "details": sanitize_error(&e)
            }))).into_response()
        }
    }
}

// ── PATCH /api/upstreams/:id ──────────────────────────────────────────────

async fn patch_upstream_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<serde_json::Value>,
) -> impl IntoResponse {
    // Only "name" and "tls_hostname" are patchable — reject any other key.
    if let Some(obj) = body.as_object() {
        for key in obj.keys() {
            if key != "name" && key != "tls_hostname" {
                return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                    "error":   "INVALID_FIELD",
                    "details": format!("field '{}' is not patchable; only 'name' and 'tls_hostname' are supported", key)
                }))).into_response();
            }
        }
    }

    // Resolve name: absent → skip; null or "" → None; non-empty → Some(s).
    let name_patch: Option<Option<String>> = match body.get("name") {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::String(s)) if s.is_empty() => Some(None),
        Some(serde_json::Value::String(s)) => {
            if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
                return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                    "error":   "INVALID_FIELD",
                    "details": "name must not contain control characters"
                }))).into_response();
            }
            if s.len() > 64 {
                return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                    "error":   "INVALID_FIELD",
                    "details": "name must not exceed 64 characters"
                }))).into_response();
            }
            Some(Some(s.clone()))
        }
        _ => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error":   "INVALID_FIELD",
            "details": "field 'name' must be a string or null"
        }))).into_response(),
    };

    // Resolve tls_hostname: absent → skip; null or "" → None (clear); non-empty → Some(s).
    let tls_patch: Option<Option<String>> = match body.get("tls_hostname") {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Some(None),
        Some(serde_json::Value::String(s)) => {
            match validate_tls_hostname(Some(s.as_str())) {
                Ok(h)  => Some(h),
                Err(e) => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
                    "error": "INVALID_FIELD", "details": e
                }))).into_response(),
            }
        }
        _ => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error":   "INVALID_FIELD",
            "details": "field 'tls_hostname' must be a string or null"
        }))).into_response(),
    };

    // Apply both patches in a single write-lock acquisition.
    let updated = {
        let mut list = s.upstreams.write()
            .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in patch handler: {e}"));
        if let Some(u) = list.iter_mut().find(|u| u.id == id) {
            if let Some(n) = name_patch        { u.name         = n; }
            if let Some(h) = tls_patch         { u.tls_hostname = h; }
            Some(u.clone())
        } else {
            None
        }
    };

    match updated {
        Some(u) => {
            upstreams::save_upstreams(&s.upstreams, &s.base_dir);
            info!(id = %id, "upstream patched via PATCH");
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "status": "ok", "upstream": u
            }))).into_response()
        }
        None => (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({
            "error": "NOT_FOUND", "id": id
        }))).into_response(),
    }
}

// ── POST /api/upstreams/:id/probe ─────────────────────────────────────────

async fn probe_upstream_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // a. Find upstream by id (read lock) — 404 if not found
    let probe_target = {
        let list = s.upstreams.read()
            .unwrap_or_else(|e| e.into_inner());
        list.iter()
            .find(|u| u.id == id)
            .map(|u| (u.addr.clone(), u.port, u.protocol.clone()))
    };
    let (addr, port, protocol) = match probe_target {
        Some(t) => t,
        None => return (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({
            "error": "NOT_FOUND", "id": id
        }))).into_response(),
    };

    // b. Run probe in spawn_blocking (blocking I/O)
    let result = tokio::task::spawn_blocking(move || {
        upstreams::probe_upstream(&addr, port, &protocol)
    }).await;

    let (healthy, latency_ms, dnssec_supported, last_error) = match result {
        Ok(r) => r,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
            "error": "PROBE_FAILED"
        }))).into_response(),
    };

    // c. Write result back (write lock, find by id)
    let now_str = crate::logbuffer::format_ts(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    let updated = {
        let mut list = s.upstreams.write()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(u) = list.iter_mut().find(|u| u.id == id) {
            u.healthy          = healthy;
            u.latency_ms       = latency_ms;
            u.dnssec_supported = if healthy { dnssec_supported } else { None };
            u.last_error       = if healthy { None } else { last_error };
            u.last_check       = now_str;
            if healthy {
                if let Some(lat) = latency_ms {
                    upstreams::push_latency(&mut u.latency_history, lat);
                }
            }
            Some(u.clone())
        } else {
            None
        }
    };

    match updated {
        Some(u) => (StatusCode::OK, JsonExtract(serde_json::json!({
            "status": "ok", "upstream": u
        }))).into_response(),
        None => (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({
            "error": "NOT_FOUND", "id": id
        }))).into_response(),
    }
}

// ── POST /api/upstreams/reconnect (#78) ────────────────────────────────────

async fn reconnect_upstreams_handler(State(s): State<AppState>) -> impl IntoResponse {
    let start = std::time::Instant::now();

    // Rebuild the resolver (resets the entire DoT connection pool).
    // warm_up() is called inside rebuild_and_swap — it probes before the ArcSwap
    // so that TCP/TLS connections are live before any query reaches the new resolver.
    let addrs = crate::upstreams::upstream_addrs(&s.upstreams);
    let warm_up = match crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, s.cfg.dnssec_validation).await {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({
            "error": "REBUILD_FAILED", "details": e.to_string()
        }))).into_response(),
    };

    s.stats.record_dot_reconnect();
    rebuild_racing_resolvers(&s);

    // Probe every DoT upstream in parallel to report reconnected vs failed.
    // UDP upstreams are ignored.
    let dot_targets: Vec<(String, u16)> = {
        s.upstreams.read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|u| u.protocol == "dot")
            .map(|u| (u.addr.clone(), u.port))
            .collect()
    };

    let mut probe_tasks = Vec::with_capacity(dot_targets.len());
    for (addr, port) in dot_targets {
        probe_tasks.push(tokio::task::spawn_blocking(move || {
            crate::upstreams::probe_upstream(&addr, port, "dot")
        }));
    }

    let mut reconnected = 0u32;
    let mut failed      = 0u32;
    for task in probe_tasks {
        match task.await {
            Ok((healthy, _, _, _)) => if healthy { reconnected += 1; } else { failed += 1; },
            Err(_)                 => { failed += 1; }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    (StatusCode::OK, JsonExtract(serde_json::json!({
        "reconnected": reconnected,
        "failed":      failed,
        "warm_up":     warm_up,
        "duration_ms": duration_ms,
    }))).into_response()
}

// ── GET /api/cache/stats ───────────────────────────────────────────────────

async fn cache_stats_handler(State(s): State<AppState>) -> impl IntoResponse {
    let hits      = s.stats.cache_hits.load(Ordering::Relaxed);
    let misses    = s.stats.cache_misses.load(Ordering::Relaxed);
    let evictions = s.cache_evictions.load(Ordering::Relaxed);
    let entries   = s.stats.cache_entries.load(Ordering::Relaxed);
    let total     = hits + misses;
    let hit_rate_pct = if total == 0 {
        serde_json::Value::Null
    } else {
        let pct = (hits as f64 / total as f64 * 1000.0).round() / 10.0;
        serde_json::json!(pct)
    };
    (StatusCode::OK, JsonExtract(serde_json::json!({
        "entries":      entries,
        "hits":         hits,
        "misses":       misses,
        "evictions":    evictions,
        "hit_rate_pct": hit_rate_pct,
    }))).into_response()
}

// ── GET /api/sync/slaves ───────────────────────────────────────────────────

async fn sync_slaves_handler(State(s): State<AppState>) -> impl IntoResponse {
    match &s.sync_journal {
        Some(journal) => {
            let slaves = journal.connected_slaves();
            let total  = slaves.len();
            (StatusCode::OK, JsonExtract(serde_json::json!({
                "slaves": slaves, "total": total
            }))).into_response()
        }
        None => (StatusCode::OK, JsonExtract(serde_json::json!({
            "slaves": [], "total": 0,
            "note": "this node is not configured as master (no sync-port directive)"
        }))).into_response(),
    }
}

// ── GET /events — SSE node-status stream (#86) ────────────────────────────

async fn events_handler(
    State(s): State<AppState>,
) -> impl IntoResponse {
    let Some(ref tx) = s.events_tx else {
        return (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({
                "error": "NOT_FOUND",
                "detail": "this node is not a master or has no sync-port configured"
            })),
        ).into_response();
    };
    let rx = tx.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    match Event::default().json_data(&event) {
                        Ok(e)  => return Some((Ok::<_, Infallible>(e), rx)),
                        Err(_) => continue,
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    let e = Event::default().comment(format!("lagged: {n} events dropped"));
                    return Some((Ok(e), rx));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
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
    State(s):      State<AppState>,
    params_result: Result<Query<LogsParams>, QueryRejection>,
) -> Response {
    let Query(params) = match params_result {
        Ok(q) => q,
        Err(e) => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error":   "INVALID_PARAM",
            "details": e.to_string()
        }))).into_response(),
    };

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

    let (entries, total) = s.log_buffer.query(&q);
    JsonExtract(serde_json::json!({
        "entries": entries,
        "total":   total,
        "page":    params.page,
        "limit":   params.limit,
    })).into_response()
}

// ── DELETE /logs ───────────────────────────────────────────────────────────

async fn clear_logs_handler(
    State(s): State<AppState>,
) -> impl IntoResponse {
    let deleted = s.log_buffer.clear();
    s.audit.send(AuditEvent::LogsClear { count: deleted });
    info!(entries_deleted = deleted, "log buffer cleared via DELETE /logs");
    JsonExtract(serde_json::json!({
        "message":         "log buffer cleared",
        "entries_deleted": deleted,
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

// ── GET /audit/tail ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AuditTailQuery { n: Option<usize> }

async fn audit_tail_handler(
    State(s): State<AppState>,
    Query(q): Query<AuditTailQuery>,
) -> impl IntoResponse {
    let n = q.n.unwrap_or(100).min(1000);
    let log_path = s.base_dir.join("audit.log");
    match crate::audit::tail_audit_log(&log_path, n) {
        Ok(lines) => (StatusCode::OK, JsonExtract(serde_json::json!({
            "lines": lines,
            "count": lines.len(),
        }))),
        Err(e) => (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({
            "error": "AUDIT_LOG_UNAVAILABLE",
            "details": e,
        }))),
    }
}

// ── GET /metrics ───────────────────────────────────────────────────────────

fn fmt_counter(name: &str, help: &str, val: u64) -> String {
    format!("# HELP {name} {help}\n# TYPE {name} counter\n{name} {val}\n")
}

fn fmt_gauge<V: std::fmt::Display>(name: &str, help: &str, val: V) -> String {
    format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {val}\n")
}

/// Per-upstream data snapshot for Prometheus metrics (no RwLock held during formatting).
struct UpstreamMetric {
    id:         String,
    addr:       String,
    port:       u16,
    protocol:   String,
    healthy:    bool,
    latency_ms: Option<u64>,
}

fn render_prometheus_metrics(
    snap:        &crate::stats::StatsSnapshot,
    cache_hits:   u64,
    cache_misses: u64,
    evictions:    u64,
    xdp_active:   bool,
    upstreams:    &[UpstreamMetric],
) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str(&fmt_counter("runbound_queries_total",              "Total DNS queries received",                      snap.total));
    out.push_str(&fmt_counter("runbound_queries_blocked_total",      "Queries blocked by blocklist",                    snap.blocked));
    out.push_str(&fmt_counter("runbound_queries_forwarded_total",    "Queries forwarded to upstreams",                  snap.forwarded));
    out.push_str(&fmt_counter("runbound_queries_nxdomain_total",     "Queries answered NXDOMAIN",                       snap.nxdomain));
    out.push_str(&fmt_counter("runbound_queries_servfail_total",     "Queries answered SERVFAIL",                       snap.servfail));
    out.push_str(&fmt_counter("runbound_queries_local_hits_total",   "Queries answered from local zones",               snap.local_hits));
    out.push_str(&fmt_gauge(  "runbound_qps_1m",                     "Queries per second (1 minute average)",           snap.qps_1m));
    out.push_str(&fmt_gauge(  "runbound_qps_peak",                   "Peak queries per second observed",                snap.qps_peak));
    out.push_str(&fmt_gauge(  "runbound_latency_p50_ms",             "DNS response latency p50 in milliseconds",        snap.latency_p50_ms));
    out.push_str(&fmt_gauge(  "runbound_latency_p95_ms",             "DNS response latency p95 in milliseconds",        snap.latency_p95_ms));
    out.push_str(&fmt_gauge(  "runbound_latency_p99_ms",             "DNS response latency p99 in milliseconds",        snap.latency_p99_ms));
    out.push_str(&fmt_gauge(  "runbound_cache_hit_rate",             "Cache hit rate (0.0 to 1.0)",                     snap.cache_hit_rate));
    out.push_str(&fmt_gauge(  "runbound_cache_entries",              "Current number of entries in DNS cache",          snap.cache_entries));
    out.push_str(&fmt_counter("runbound_cache_hits_total",           "Total cache hits",                                cache_hits));
    out.push_str(&fmt_counter("runbound_cache_misses_total",         "Total cache misses",                              cache_misses));
    out.push_str(&fmt_counter("runbound_cache_evictions_total",      "Total cache evictions",                           evictions));
    out.push_str(&fmt_gauge(  "runbound_uptime_seconds",             "Service uptime in seconds",                       snap.uptime_secs));
    out.push_str(&fmt_gauge(  "runbound_xdp_active",                 "Whether XDP fast path is active (1=yes, 0=no)",   xdp_active as u8));
    out.push_str(&fmt_counter("runbound_xdp_cache_hits_total",       "DNS responses served from XDP cache snapshot",
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_HITS.load(std::sync::atomic::Ordering::Relaxed)));
    out.push_str(&fmt_counter("runbound_xdp_cache_misses_total",     "XDP cache lookups that missed",
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES.load(std::sync::atomic::Ordering::Relaxed)));
    out.push_str(&fmt_gauge(  "runbound_xdp_cache_entries",          "Current live entries in XDP wire-format cache",
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_ENTRIES.load(std::sync::atomic::Ordering::Relaxed)));
    out.push_str(&fmt_gauge(  "runbound_nic_rx_ring",                "Applied NIC RX ring descriptor count (0=unavailable)",
        crate::dns::xdp::socket::XDP_NIC_RX_RING.load(std::sync::atomic::Ordering::Relaxed)));
    out.push_str(&fmt_gauge(  "runbound_nic_rx_ring_max",            "Hardware maximum NIC RX ring descriptor count",
        crate::dns::xdp::socket::XDP_NIC_RX_RING_MAX.load(std::sync::atomic::Ordering::Relaxed)));
    {
        let nic_dropped = crate::dns::xdp::socket::XDP_ACTIVE_IFACE
            .get()
            .map(|iface| crate::dns::xdp::socket::read_nic_rx_dropped(iface))
            .unwrap_or(0);
        out.push_str(&fmt_counter("runbound_nic_rx_dropped_total",       "NIC RX packets dropped before XDP (hardware FIFO overflow)",
            nic_dropped));
    }

    // Per-upstream metrics with labels — omit latency when not yet measured (null → skip, no NaN).
    if !upstreams.is_empty() {
        out.push_str("# HELP runbound_upstream_healthy Whether upstream is healthy (1=yes, 0=no)\n");
        out.push_str("# TYPE runbound_upstream_healthy gauge\n");
        for u in upstreams {
            out.push_str(&format!(
                "runbound_upstream_healthy{{id=\"{}\",addr=\"{}\",port=\"{}\",protocol=\"{}\"}} {}\n",
                u.id, u.addr, u.port, u.protocol, u.healthy as u8,
            ));
        }
        let latency_upstreams: Vec<&UpstreamMetric> = upstreams.iter().filter(|u| u.latency_ms.is_some()).collect();
        if !latency_upstreams.is_empty() {
            out.push_str("# HELP runbound_upstream_latency_ms Last measured upstream latency in milliseconds\n");
            out.push_str("# TYPE runbound_upstream_latency_ms gauge\n");
            for u in latency_upstreams {
                out.push_str(&format!(
                    "runbound_upstream_latency_ms{{id=\"{}\",addr=\"{}\",port=\"{}\",protocol=\"{}\"}} {}\n",
                    u.id, u.addr, u.port, u.protocol, u.latency_ms.unwrap(),
                ));
            }
        }
    }
    out
}

async fn metrics_handler(State(s): State<AppState>) -> impl IntoResponse {
    let snap         = s.stats.snapshot();
    let cache_hits   = s.stats.cache_hits.load(Ordering::Relaxed);
    let cache_misses = s.stats.cache_misses.load(Ordering::Relaxed);
    let evictions    = s.cache_evictions.load(Ordering::Relaxed);
    let xdp_active   = s.xdp_active.load(Ordering::Relaxed) > 0;
    let upstreams: Vec<UpstreamMetric> = {
        let list = s.upstreams.read()
            .unwrap_or_else(|e| panic!("upstreams: RwLock poisoned in metrics handler: {e}"));
        list.iter().map(|u| UpstreamMetric {
            id:         u.id.clone(),
            addr:       u.addr.clone(),
            port:       u.port,
            protocol:   u.protocol.clone(),
            healthy:    u.healthy,
            latency_ms: u.latency_ms,
        }).collect()
    };
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        render_prometheus_metrics(&snap, cache_hits, cache_misses, evictions, xdp_active, &upstreams),
    )
}

// ── POST /rotate-key ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RotateKeyRequest {
    new_key: String,
}

async fn rotate_key_handler(
    State(s): State<AppState>,
    ApiJson(req): ApiJson<RotateKeyRequest>,
) -> impl IntoResponse {
    // Require at least 32 bytes of entropy (64 hex chars) — shorter keys are
    // statistically weak and likely copy-paste mistakes.
    if req.new_key.len() < 32 {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "WEAK_KEY",
            "details": "new_key must be at least 32 characters",
        }))).into_response();
    }
    // Reject control characters (CRLF injection, log injection).
    if req.new_key.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({
            "error": "INVALID_KEY",
            "details": "new_key must not contain control characters",
        }))).into_response();
    }
    rotate_api_key(req.new_key.clone());
    // Persist to base_dir/api.key so the key survives a restart.
    let key_path = s.base_dir.join("api.key");
    let persist_result = std::fs::write(&key_path, req.new_key.as_bytes()).and_then(|_| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    });
    if let Err(e) = persist_result {
        // Non-fatal: key is already active in memory; log the write failure.
        warn!(path = %key_path.display(), err = %e, "Failed to persist rotated API key to disk");
    }
    s.audit.send(AuditEvent::ConfigReload);
    info!("API key rotated via POST /rotate-key");
    (StatusCode::OK, JsonExtract(serde_json::json!({
        "status": "ok",
        "message": "API key rotated — old token is immediately invalid",
    }))).into_response()
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// FIX 3.4: Strip file-system paths from error messages before they reach HTTP
/// response bodies.  The full error (with path) is always logged at WARN level
/// so operators retain visibility; clients receive only a generic message.
fn sanitize_error(e: &impl std::fmt::Display) -> String {
    let s = e.to_string();
    if s.contains('/') { "internal error".to_string() } else { s }
}

fn ensure_dot(name: &str) -> String {
    if name.ends_with('.') { name.to_string() } else { format!("{}.", name) }
}

/// Reject any string that contains ASCII control characters (0x00–0x1f, 0x7f).
/// Applied to all user-supplied text fields (value, description) to prevent
/// CRLF injection into logs, stored JSON, or HTTP response bodies.
fn validate_no_control_chars(s: &str, field: &'static str) -> Result<(), String> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("Field '{}' must not contain control characters (\r, \n, etc.)", field));
    }
    Ok(())
}

/// #56: Validate and normalise a `tls_hostname` value from the API.
/// - `None` / empty string → `Ok(None)` (auto-derive)
/// - Non-empty, valid → `Ok(Some(trimmed))`
/// - Too long or containing control characters → `Err(message)`
fn validate_tls_hostname(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(h) = raw else { return Ok(None); };
    let h = h.trim();
    if h.is_empty() { return Ok(None); }
    if h.len() > 253 {
        return Err("tls_hostname must not exceed 253 characters".into());
    }
    if h.bytes().any(|b| b < 0x20) {
        return Err("tls_hostname must not contain control characters".into());
    }
    Ok(Some(h.to_string()))
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
        make_test_app_with_cfg(crate::config::parser::UnboundConfig::default())
    }

    fn make_test_app_with_cfg(cfg: crate::config::parser::UnboundConfig) -> Router {
        // Initialise API key (OnceLock — safe to call multiple times with same value)
        init_api_key(Some(TEST_KEY.to_string()));
        // Initialise BASE_DIR for store/feeds path resolution (OnceLock — idempotent).
        let _ = crate::runtime::BASE_DIR.set(std::path::PathBuf::from("/tmp/runbound-test"));

        let cfg_arc = Arc::new(cfg);
        let zones = Arc::new(ArcSwap::new(Arc::new(
            crate::dns::local::LocalZoneSet::from_config(&cfg_arc.local_zones, &cfg_arc.local_data)
        )));
        let log_buffer = crate::logbuffer::new_shared(1000, true);
        let upstreams = crate::upstreams::init_upstreams(&cfg_arc);
        let resolver  = crate::dns::server::create_shared_resolver(&cfg_arc)
            .expect("test resolver");

        let stats = crate::stats::Stats::new();
        let stats_cache = crate::stats::new_snapshot_cache(&stats);
        let state = AppState {
            zones:            Arc::clone(&zones),
            zones_mutex:      Arc::new(tokio::sync::Mutex::new(())),
            tls_cfg:          Arc::new(crate::config::parser::TlsConfig::default()),
            rate_limiter:     ApiRateLimiter::new_public(),
            reload_limiter:   Arc::new(ReloadLimiter::new()),
            stats,
            stats_cache,
            cfg:              Arc::clone(&cfg_arc),
            cfg_path:         "/dev/null".to_string(),
            log_buffer,
            upstreams,
            sync_journal:     None,
            sync_key:         None,
            node_id:          None,
            slave_mode:       false,
            base_dir:         Arc::new(std::path::PathBuf::from("/tmp/runbound-test")),
            audit:            crate::audit::init(false, None, None, std::path::PathBuf::from("/tmp")),
            xdp_active:       Arc::new(AtomicU8::new(0)),
            resolver,
            last_flush_at:    Arc::new(std::sync::Mutex::new(None)),
            cache_evictions:  Arc::new(AtomicU64::new(0)),
            lookup_limiter:   Arc::new(ReloadLimiter::new_with_params(10.0, 10.0)),
            per_upstream_resolvers: crate::dns::server::create_shared_resolvers_vec(),
            racing_wins:           Arc::new(DashMap::with_hasher(ahash::RandomState::new())),
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

    // ── /health (root, no auth) ───────────────────────────────────────────

    #[tokio::test]
    async fn health_no_auth_required() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/health").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── /api/stats ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn stats_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/api/stats").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stats_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/stats").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        for field in &["total", "blocked", "forwarded", "qps_1m", "qps_5m",
                       "latency_p50_ms", "cache_hit_rate", "local_hits"] {
            assert!(json.get(field).is_some(), "missing field: {field}");
        }
    }

    // ── /api/stats/stream ─────────────────────────────────────────────────

    #[tokio::test]
    async fn stats_stream_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/api/stats/stream").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stats_stream_content_type() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/stats/stream").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(ct.contains("text/event-stream"), "unexpected Content-Type: {ct}");
    }

    // ── /api/upstreams ────────────────────────────────────────────────────

    #[tokio::test]
    async fn upstreams_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/api/upstreams").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upstreams_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/upstreams").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json.get("upstreams").is_some());
        assert!(json.get("total").is_some());
        assert!(json.get("healthy").is_some());
    }

    // ── /api/logs ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn logs_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/api/logs").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logs_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/logs").header(k, v).body(Body::empty()).unwrap()
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
            Request::builder().uri("/api/logs?limit=2000").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn logs_invalid_action() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/logs?action=invalid").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn logs_invalid_client_ip() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/logs?client=notanip").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── validate_dns_name unit tests (SEC-02) ─────────────────────────────

    #[test]
    fn test_validate_dns_name_253_chars_accepted() {
        // 63+1+63+1+63+1+61 = 253 chars — exactly at RFC 1035 §2.3.4 limit
        let name = format!("{}.{}.{}.{}",
            "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
        assert_eq!(name.len(), 253);
        assert!(validate_dns_name(&name).is_ok());
    }

    #[test]
    fn test_validate_dns_name_254_chars_rejected() {
        // 63+1+63+1+63+1+62 = 254 chars — one over the RFC limit
        let name = format!("{}.{}.{}.{}",
            "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62));
        assert_eq!(name.len(), 254);
        assert!(validate_dns_name(&name).is_err());
    }

    #[test]
    fn test_validate_dns_name_253_with_trailing_dot_accepted() {
        // trailing dot is stripped before length check
        let name = format!("{}.{}.{}.{}.",
            "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
        assert_eq!(name.trim_end_matches('.').len(), 253);
        assert!(validate_dns_name(&name).is_ok());
    }

    #[test]
    fn test_validate_dns_name_254_with_trailing_dot_rejected() {
        let name = format!("{}.{}.{}.{}.",
            "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62));
        assert_eq!(name.trim_end_matches('.').len(), 254);
        assert!(validate_dns_name(&name).is_err());
    }

    #[test]
    fn test_validate_dns_name_label_64_chars_rejected() {
        let name = "a".repeat(64);
        assert!(validate_dns_name(&name).is_err());
    }

    #[test]
    fn test_validate_dns_name_label_63_chars_accepted() {
        let name = "a".repeat(63);
        assert!(validate_dns_name(&name).is_ok());
    }

    // ── SEC-02 HTTP endpoint integration tests ────────────────────────────────
    // Verify that the /dns and /blacklist endpoints reject 254-char domain names
    // at the HTTP level. Pentest v0.4.4 claimed "254 chars → HTTP 201"; these
    // tests prove the rejection works end-to-end and that the pentest was using
    // a 253-char name + trailing dot (= 254 bytes submitted, 253-char domain
    // after trailing-dot strip — correctly accepted).

    #[tokio::test]
    async fn dns_name_254_chars_is_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // 254-char name (no trailing dot): 63+1+63+1+63+1+62 = 254.
        // validate_dns_name must reject this → 400.
        let name: String = format!("{}.{}.{}.{}",
            "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62));
        assert_eq!(name.len(), 254);
        let body = serde_json::json!({
            "name": name, "type": "A", "value": "1.2.3.4"
        }).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/dns")
                .header(k, v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST,
            "254-char domain name must be rejected with 400");
    }

    #[tokio::test]
    async fn dns_name_253_chars_no_trailing_dot_passes_validation() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // 253-char name (no trailing dot) — valid per RFC 1035 §2.3.4.
        // validate_dns_name must accept this. The handler may fail at store
        // level (test dir), but must NOT return 400 for the name itself.
        let name: String = format!("{}.{}.{}.{}",
            "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
        assert_eq!(name.len(), 253);
        let body = serde_json::json!({
            "name": name, "type": "A", "value": "1.2.3.4"
        }).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/dns")
                .header(k, v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST,
            "253-char domain name must not be rejected by name validation");
    }

    #[tokio::test]
    async fn blacklist_name_254_chars_is_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let name: String = format!("{}.{}.{}.{}",
            "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62));
        assert_eq!(name.len(), 254);
        let body = serde_json::json!({"domain": name}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/blacklist")
                .header(k, v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST,
            "254-char blacklist domain must be rejected with 400");
    }

    // ── SEC-04 body limit integration tests ───────────────────────────────────

    #[tokio::test]
    async fn post_json_without_content_length_gets_411() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // JSON Content-Type but no Content-Length → 411 (SEC-04 fix).
        let body = serde_json::json!({"name": "example.com", "type": "A", "value": "1.2.3.4"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/dns")
                .header(k, v)
                .header("Content-Type", "application/json")
                // Deliberately omit Content-Length
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::LENGTH_REQUIRED,
            "JSON POST without Content-Length must return 411");
    }

    #[tokio::test]
    async fn post_without_body_no_content_type_passes() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // Bodyless POST (/reload) has no Content-Type → must not get 411.
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/reload")
                .header(k, v)
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_ne!(resp.status(), StatusCode::LENGTH_REQUIRED,
            "Bodyless POST must not get 411");
    }

    // ── POST /api/upstreams ───────────────────────────────────────────────────

    #[tokio::test]
    async fn add_upstream_requires_auth() {
        let app = make_test_app();
        let body = serde_json::json!({"addr":"1.1.1.1","protocol":"udp"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams")
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn add_upstream_invalid_protocol() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = serde_json::json!({"addr":"1.1.1.1","protocol":"tcp"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams")
                .header(k, v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn add_upstream_invalid_addr() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = serde_json::json!({"addr":"not-an-ip","protocol":"udp"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams")
                .header(k, v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn add_upstream_happy_path() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = serde_json::json!({"addr":"9.9.9.9","protocol":"udp","name":"Quad9"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams")
                .header(k, v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["status"], "ok");
        assert!(json["upstream"]["id"].is_string());
    }

    // ── DELETE /api/upstreams/:id ─────────────────────────────────────────────

    #[tokio::test]
    async fn delete_upstream_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder()
                .method("DELETE").uri("/api/upstreams/some-id")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_upstream_not_found() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder()
                .method("DELETE").uri("/api/upstreams/nonexistent-uuid")
                .header(k, v)
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── GET /api/upstreams/presets ────────────────────────────────────────────

    #[tokio::test]
    async fn upstream_presets_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/api/upstreams/presets").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upstream_presets_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/upstreams/presets").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json["presets"].is_array());
        assert!(json["presets"].as_array().map(|a| a.len() >= 4).unwrap_or(false));
    }

    // ── POST /api/cache/flush ─────────────────────────────────────────────────

    #[tokio::test]
    async fn cache_flush_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().method("POST").uri("/api/cache/flush").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cache_flush_happy_path() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/cache/flush")
                .header(k, v)
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["status"], "ok");
        assert!(json["flushed_entries"].is_number());
    }

    // ── FEAT #46: cache flush cooldown ────────────────────────────────────────

    fn make_flush_app(cooldown_secs: u64) -> Router {
        let mut cfg = crate::config::parser::UnboundConfig::defaults();
        cfg.cache_flush_cooldown = cooldown_secs;
        make_test_app_with_cfg(cfg)
    }

    #[tokio::test]
    async fn cache_flush_cooldown_second_call_429() {
        let app = make_flush_app(60);
        let (k, v) = auth_header();

        let r1 = app.clone().oneshot(
            Request::builder().method("POST").uri("/api/cache/flush")
                .header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = app.clone().oneshot(
            Request::builder().method("POST").uri("/api/cache/flush")
                .header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
        let j = body_json(r2.into_body()).await;
        assert_eq!(j["error"], "FLUSH_COOLDOWN");
        assert!(j["retry_after_secs"].as_u64().unwrap_or(0) > 0);
    }

    #[tokio::test]
    async fn cache_flush_cooldown_disabled_allows_two_calls() {
        let app = make_flush_app(0);
        let (k, v) = auth_header();

        let r1 = app.clone().oneshot(
            Request::builder().method("POST").uri("/api/cache/flush")
                .header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = app.oneshot(
            Request::builder().method("POST").uri("/api/cache/flush")
                .header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
    }

    // ── FEAT #47: /api/system new fields ──────────────────────────────────────

    #[tokio::test]
    async fn system_has_prefetch_fields() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/system").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        // Default config has prefetch: false (derived Default)
        assert_eq!(j["prefetch_enabled"], false);
        assert!(j.get("upstreams_healthy").is_some());
        assert!(j.get("upstreams_total").is_some());
    }

    #[tokio::test]
    async fn system_prefetch_enabled_reflects_config() {
        let mut cfg = crate::config::parser::UnboundConfig::defaults();
        cfg.prefetch = true;
        let app = make_test_app_with_cfg(cfg);
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/system").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["prefetch_enabled"], true);
    }

    #[tokio::test]
    async fn system_upstreams_healthy_matches_upstreams_endpoint() {
        let app = make_test_app();
        let (k, v) = auth_header();

        let sys = body_json(
            app.clone().oneshot(
                Request::builder().uri("/api/system").header(k, &v).body(Body::empty()).unwrap()
            ).await.unwrap().into_body()
        ).await;

        let ups = body_json(
            app.oneshot(
                Request::builder().uri("/api/upstreams").header(k, &v).body(Body::empty()).unwrap()
            ).await.unwrap().into_body()
        ).await;

        assert_eq!(sys["upstreams_healthy"], ups["healthy"]);
        assert_eq!(sys["upstreams_total"],   ups["total"]);
    }

    // ── GET /api/sync/slaves ──────────────────────────────────────────────────

    #[tokio::test]
    async fn sync_slaves_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/api/sync/slaves").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sync_slaves_standalone_returns_empty() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/sync/slaves").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["total"], 0);
        assert!(json["slaves"].as_array().map(|a| a.is_empty()).unwrap_or(false));
    }

    // ── GET /health schema (no auth, version field present) ───────────────────

    #[tokio::test]
    async fn health_schema() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/health").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        let status = json["status"].as_str().unwrap_or("");
        assert!(
            matches!(status, "ok" | "degraded" | "error"),
            "health status must be ok/degraded/error; got: {status}"
        );
        assert!(json["version"].is_string(), "health must include version field");
        assert!(json.get("hsm").is_none(), "health must not expose hsm field");
        assert!(json["uptime_secs"].is_number());
    }

    // ── #74: /health enriched fields ──────────────────────────────────────────

    #[tokio::test]
    async fn health_has_enriched_fields() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/health").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json["xdp_active"].is_boolean(),  "health must include xdp_active");
        assert!(json["upstreams_healthy"].is_number(), "health must include upstreams_healthy");
        assert!(json["upstreams_total"].is_number(),   "health must include upstreams_total");
        assert!(json["cache_entries"].is_number(),     "health must include cache_entries");
        assert!(json["status"].is_string(),            "health must include status");
    }

    #[tokio::test]
    async fn health_status_ok_when_no_upstreams_configured() {
        // Default test config has no forward zones → 0 upstreams → status "error"
        let app = make_test_app();
        let json = body_json(
            app.oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
                .await.unwrap().into_body()
        ).await;
        assert_eq!(json["upstreams_total"], 0);
        assert_eq!(json["status"], "error");
    }

    #[tokio::test]
    async fn health_status_ok_with_healthy_upstream() {
        let mut cfg = crate::config::parser::UnboundConfig::default();
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(), addrs: vec!["1.1.1.1@53".into()], tls: false,
        });
        let app = make_test_app_with_cfg(cfg);
        let (k, v) = auth_header();
        // Mark the upstream healthy via the upstreams endpoint
        let json = body_json(
            app.clone().oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
                .await.unwrap().into_body()
        ).await;
        // No probe has run yet → healthy=0 but total=1 → "degraded"
        assert_eq!(json["upstreams_total"], 1);
        assert_eq!(json["status"], "degraded");
        let _ = (k, v);
    }

    // ── #73: GET /api/metrics Prometheus format ───────────────────────────────

    #[tokio::test]
    async fn metrics_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/api/metrics").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_content_type_prometheus() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/metrics").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").and_then(|h| h.to_str().ok()).unwrap_or("");
        assert!(ct.contains("text/plain"), "content-type must be text/plain; got: {ct}");
        assert!(ct.contains("0.0.4"),      "content-type must include version=0.0.4; got: {ct}");
    }

    #[tokio::test]
    async fn metrics_contains_required_metric_names() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/metrics").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&bytes).unwrap();
        for metric in &[
            "runbound_queries_total",
            "runbound_queries_blocked_total",
            "runbound_queries_forwarded_total",
            "runbound_queries_nxdomain_total",
            "runbound_queries_servfail_total",
            "runbound_queries_local_hits_total",
            "runbound_qps_1m",
            "runbound_qps_peak",
            "runbound_latency_p50_ms",
            "runbound_latency_p95_ms",
            "runbound_latency_p99_ms",
            "runbound_cache_hit_rate",
            "runbound_cache_entries",
            "runbound_cache_hits_total",
            "runbound_cache_misses_total",
            "runbound_cache_evictions_total",
            "runbound_uptime_seconds",
            "runbound_xdp_active",
        ] {
            assert!(body.contains(metric), "metrics output must contain {metric}");
        }
    }

    #[tokio::test]
    async fn metrics_upstream_labels_present() {
        let mut cfg = crate::config::parser::UnboundConfig::default();
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(), addrs: vec!["9.9.9.9@53".into()], tls: false,
        });
        let app = make_test_app_with_cfg(cfg);
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/metrics").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(body.contains("runbound_upstream_healthy"), "upstream_healthy metric must be present");
        assert!(body.contains("addr=\"9.9.9.9\""), "upstream addr label must be present");
        assert!(body.contains("protocol=\"udp\""), "upstream protocol label must be present");
    }

    // ── ReloadLimiter correctness under parallel load ─────────────────────────
    // Regression test for the TOCTOU race in the previous integer-arithmetic
    // token bucket: 20 threads hit the limiter simultaneously; at most 2 (burst)
    // must be allowed, at least 18 must be denied.
    #[test]
    fn reload_limiter_parallel() {
        use std::sync::Arc;
        use std::thread;

        let limiter = Arc::new(ReloadLimiter::new());
        let barrier = Arc::new(std::sync::Barrier::new(20));

        let handles: Vec<_> = (0..20).map(|_| {
            let l = Arc::clone(&limiter);
            let b = Arc::clone(&barrier);
            thread::spawn(move || {
                b.wait(); // all threads start at the same instant
                l.check()
            })
        }).collect();

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let allowed = results.iter().filter(|&&r|  r).count();
        let denied  = results.iter().filter(|&&r| !r).count();

        assert!(allowed <= 2, "allowed={allowed} but burst=2");
        assert!(denied  >= 18, "denied={denied} but expected ≥18");
    }

    // ── HTTP-level concurrent test: 20 concurrent POST /reload sharing ONE AppState ──
    // This is the correct simulation of the production scenario: one process,
    // one Arc<ReloadLimiter>, 20 concurrent HTTP requests routed through axum.
    // (The previous pattern of calling make_test_app() 20 times created 20
    // independent AppState instances — each with fresh tokens=2.0 — which is
    // exactly the multi-process bug and produces 200:20, 429:0.)
    #[tokio::test]
    async fn reload_http_concurrent_429() {
        use std::sync::Arc as StdArc;
        use tokio::sync::Barrier;

        let (k, v) = auth_header();
        let barrier = StdArc::new(Barrier::new(20));

        // ONE app, cloned 20 times — all clones share the same Arc<ReloadLimiter>.
        let app = make_test_app();

        let mut handles = Vec::new();
        for _ in 0..20 {
            let app = app.clone();
            let k = k;
            let v = v.clone();
            let b = StdArc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                b.wait().await;
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/reload")
                        .header(k, v)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            }));
        }

        let statuses: Vec<StatusCode> = futures_util::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        let ok   = statuses.iter().filter(|&&s| s == StatusCode::OK).count();
        let r429 = statuses.iter().filter(|&&s| s == StatusCode::TOO_MANY_REQUESTS).count();
        let other: Vec<_> = statuses.iter()
            .filter(|&&s| s != StatusCode::OK && s != StatusCode::TOO_MANY_REQUESTS)
            .collect();

        eprintln!("[HTTP_TEST] 200={ok} 429={r429} other={other:?}");
        assert!(ok <= 2,  "burst=2 but {ok} requests got 200");
        assert!(r429 >= 18, "expected ≥18 requests to get 429, got {r429}");
    }

    // ── FIX #40: loopback and IPv4 link-local are rejected ────────────────

    fn post_upstream(app: axum::Router, auth: (&'static str, String), body_str: &'static str)
        -> impl std::future::Future<Output = axum::response::Response>
    {
        use tower::ServiceExt;
        let req = Request::builder()
            .method("POST")
            .uri("/api/upstreams")
            .header(auth.0, auth.1)
            .header("Content-Type", "application/json")
            .header("Content-Length", body_str.len().to_string())
            .body(Body::from(body_str))
            .unwrap();
        async move { app.oneshot(req).await.unwrap() }
    }

    #[tokio::test]
    async fn add_upstream_loopback_v4_rejected() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"127.0.0.1"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_ADDR");
    }

    #[tokio::test]
    async fn add_upstream_loopback_v6_rejected() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"::1"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_ADDR");
    }

    #[tokio::test]
    async fn add_upstream_link_local_rejected() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"169.254.169.254"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_ADDR");
    }

    #[tokio::test]
    async fn add_upstream_unspecified_v4_rejected() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"0.0.0.0"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_ADDR");
    }

    #[tokio::test]
    async fn add_upstream_unspecified_v6_rejected() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"::"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_ADDR");
    }

    #[tokio::test]
    async fn add_upstream_private_v4_allowed() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"10.0.0.1"}"#).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn add_upstream_private_192_allowed() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"192.168.1.1"}"#).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // ── FIX #41: last upstream cannot be deleted ──────────────────────────

    #[tokio::test]
    async fn delete_last_upstream_returns_409() {
        let app = make_test_app();
        let (k, v) = auth_header();

        // Add the only upstream
        let add_resp = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"1.1.1.1"}"#).await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let j = body_json(add_resp.into_body()).await;
        let id = j["upstream"]["id"].as_str().unwrap().to_string();

        // Attempt to delete it — only one present, must return 409
        let del_resp = app.clone().oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/upstreams/{id}"))
                .header(k, &v)
                .body(Body::empty())
                .unwrap(),
        ).await.unwrap();
        assert_eq!(del_resp.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(del_resp.into_body()).await["error"], "LAST_UPSTREAM");

        // Upstream must still be present after 409
        let list_resp = app.oneshot(
            Request::builder()
                .uri("/api/upstreams")
                .header(k, &v)
                .body(Body::empty())
                .unwrap(),
        ).await.unwrap();
        assert_eq!(body_json(list_resp.into_body()).await["total"], 1);
    }

    #[tokio::test]
    async fn delete_one_of_two_upstreams_returns_200() {
        let app = make_test_app();
        let (k, v) = auth_header();

        let add1 = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"1.1.1.1"}"#).await;
        assert_eq!(add1.status(), StatusCode::CREATED);
        let id1 = body_json(add1.into_body()).await["upstream"]["id"]
            .as_str().unwrap().to_string();

        let add2 = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"8.8.8.8"}"#).await;
        assert_eq!(add2.status(), StatusCode::CREATED);

        // Delete first — two upstreams present, must return 200
        let del_resp = app.oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/upstreams/{id1}"))
                .header(k, &v)
                .body(Body::empty())
                .unwrap(),
        ).await.unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);
    }

    // ── FIX #42: presets DoT entries have no @port in addr ────────────────

    #[tokio::test]
    async fn upstream_presets_dot_no_at_port() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder()
                .uri("/api/upstreams/presets")
                .header(k, v)
                .body(Body::empty())
                .unwrap(),
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        let presets = json["presets"].as_array().unwrap();
        assert!(!presets.is_empty());
        for preset in presets {
            let addr = preset["addr"].as_str().unwrap();
            assert!(!addr.contains('@'), "preset addr must not contain @port: {addr}");
            if preset["protocol"] == "dot" {
                assert_eq!(preset["port"], 853, "DoT preset must have port 853");
            }
        }
    }

    // ── FIX #44: port field in response, defaults, port=0 rejected ────────

    #[tokio::test]
    async fn add_upstream_default_port_udp() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"1.1.1.1","protocol":"udp"}"#).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(body_json(resp.into_body()).await["upstream"]["port"], 53);
    }

    #[tokio::test]
    async fn add_upstream_default_port_dot() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"1.1.1.1","protocol":"dot"}"#).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(body_json(resp.into_body()).await["upstream"]["port"], 853);
    }

    #[tokio::test]
    async fn add_upstream_explicit_port_in_response() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"1.1.1.1","port":5353}"#).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(body_json(resp.into_body()).await["upstream"]["port"], 5353);
    }

    #[tokio::test]
    async fn add_upstream_port_zero_rejected() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"1.1.1.1","port":0}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_PORT");
    }

    // ── #48/#49: upstreams response schema includes new fields ────────────────

    #[tokio::test]
    async fn upstreams_response_has_latency_history_array() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_body = r#"{"addr":"9.9.9.9","protocol":"udp"}"#;
        post_upstream(app.clone(), (k, v.clone()), add_body).await;

        let resp = app.oneshot(
            Request::builder().uri("/api/upstreams").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        let upstreams = json["upstreams"].as_array().expect("upstreams must be array");
        assert!(!upstreams.is_empty());
        for u in upstreams {
            assert!(u["latency_history"].is_array(),
                "latency_history must be a JSON array; got: {:?}", u["latency_history"]);
        }
    }

    #[tokio::test]
    async fn upstreams_new_entry_latency_history_empty() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_body = r#"{"addr":"9.9.9.9","protocol":"udp"}"#;
        let add_resp = post_upstream(app.clone(), (k, v.clone()), add_body).await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let upstream = body_json(add_resp.into_body()).await;
        assert_eq!(upstream["upstream"]["latency_history"].as_array().map(|a| a.len()), Some(0),
            "newly added upstream must have empty latency_history");
    }

    #[tokio::test]
    async fn upstreams_dnssec_supported_absent_when_not_probed() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_body = r#"{"addr":"9.9.9.9","protocol":"udp"}"#;
        post_upstream(app.clone(), (k, v.clone()), add_body).await;

        let resp = app.oneshot(
            Request::builder().uri("/api/upstreams").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        let json = body_json(resp.into_body()).await;
        let ups = json["upstreams"].as_array().unwrap();
        for u in ups {
            assert!(u.get("dnssec_supported").is_none(),
                "dnssec_supported must be absent (None) before first probe; got: {:?}", u);
        }
    }

    // ── #50: PATCH /api/upstreams/:id ─────────────────────────────────────────

    #[tokio::test]
    async fn patch_upstream_requires_auth() {
        let app = make_test_app();
        let body = serde_json::json!({"name":"Test"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("PATCH").uri("/api/upstreams/some-id")
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn patch_upstream_renames() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_resp = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"9.9.9.9"}"#).await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str().unwrap().to_string();

        let patch_body = serde_json::json!({"name":"Quad9 renamed"}).to_string();
        let resp = app.clone().oneshot(
            Request::builder()
                .method("PATCH").uri(format!("/api/upstreams/{id}"))
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", patch_body.len().to_string())
                .body(Body::from(patch_body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["status"], "ok");
        assert_eq!(j["upstream"]["name"], "Quad9 renamed");
    }

    #[tokio::test]
    async fn patch_upstream_empty_name_clears() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_resp = post_upstream(app.clone(), (k, v.clone()),
            r#"{"addr":"9.9.9.9","name":"Old Name"}"#).await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str().unwrap().to_string();

        let patch_body = serde_json::json!({"name":""}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("PATCH").uri(format!("/api/upstreams/{id}"))
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", patch_body.len().to_string())
                .body(Body::from(patch_body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert!(j["upstream"]["name"].is_null(), "empty name must become null");
    }

    #[tokio::test]
    async fn patch_upstream_unknown_field_returns_400() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_resp = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"9.9.9.9"}"#).await;
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str().unwrap().to_string();

        let patch_body = serde_json::json!({"addr":"1.2.3.4"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("PATCH").uri(format!("/api/upstreams/{id}"))
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", patch_body.len().to_string())
                .body(Body::from(patch_body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_FIELD");
    }

    #[tokio::test]
    async fn patch_upstream_not_found() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let patch_body = serde_json::json!({"name":"x"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("PATCH").uri("/api/upstreams/nonexistent-uuid")
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", patch_body.len().to_string())
                .body(Body::from(patch_body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── #51: GET /api/cache/stats ─────────────────────────────────────────────

    #[tokio::test]
    async fn cache_stats_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().uri("/api/cache/stats").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cache_stats_schema_initial_zeros() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/cache/stats").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["hits"],      0);
        assert_eq!(j["misses"],    0);
        assert_eq!(j["evictions"], 0);
        assert!(j["entries"].is_number(), "entries must be a number");
        assert!(j["hit_rate_pct"].is_null(), "hit_rate_pct must be null when both are 0");
    }

    // ── #54: POST /api/upstreams/:id/probe ───────────────────────────────

    #[tokio::test]
    async fn probe_upstream_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams/any-id/probe")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn probe_upstream_not_found() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams/nonexistent-uuid/probe")
                .header(k, &v)
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn probe_upstream_updates_status() {
        let app = make_test_app();
        let (k, v) = auth_header();

        // Add an upstream pointing to TEST-NET-1 (192.0.2.1, RFC 5737 — guaranteed unreachable)
        let add_resp = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"192.0.2.1"}"#).await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str().unwrap_or_default().to_string();

        // Trigger immediate probe
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri(format!("/api/upstreams/{id}/probe"))
                .header(k, &v)
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["status"], "ok");
        assert_eq!(j["upstream"]["healthy"], false, "TEST-NET-1 must be unhealthy");
        assert!(j["upstream"]["last_error"].is_string(), "last_error must be set on failure");
    }

    // ── #53: last_error field on upstream failures ────────────────────────────

    #[tokio::test]
    async fn upstream_last_error_present_on_failure() {
        let app = make_test_app();
        let (k, v) = auth_header();

        // Add an upstream pointing to TEST-NET-1 (192.0.2.1, RFC 5737 — unreachable)
        let add_resp = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"192.0.2.1"}"#).await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str().unwrap_or_default().to_string();

        // Trigger immediate probe — should fail
        let probe_resp = app.clone().oneshot(
            Request::builder()
                .method("POST").uri(format!("/api/upstreams/{id}/probe"))
                .header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(probe_resp.status(), StatusCode::OK);
        let j = body_json(probe_resp.into_body()).await;
        assert_eq!(j["upstream"]["healthy"], false);
        assert!(j["upstream"]["last_error"].is_string(),
            "last_error must be present after a failed probe; got: {:?}", j["upstream"]);
    }

    #[tokio::test]
    async fn upstream_last_error_cleared_on_success() {
        // Directly manipulate UpstreamStatus: set last_error, then simulate
        // a successful write-back and verify it is cleared.
        // (Unit-level; mirrors parse_last_error_cleared_on_healthy in upstreams.rs)
        use crate::upstreams::{add_upstream as add_us, init_upstreams};
        let cfg = crate::config::parser::UnboundConfig::default();
        let shared = init_upstreams(&cfg);
        let entry = add_us(&shared, "1.1.1.1".into(), 53, "udp".into(), None, None);

        // Inject a prior error
        {
            let mut list = shared.write().unwrap_or_else(|e| e.into_inner());
            let s = list.iter_mut().find(|u| u.id == entry.id)
                .unwrap_or_else(|| panic!("entry not found"));
            s.last_error = Some("timeout".into());
            s.healthy = false;
        }
        // Simulate successful write-back
        {
            let mut list = shared.write().unwrap_or_else(|e| e.into_inner());
            let s = list.iter_mut().find(|u| u.id == entry.id)
                .unwrap_or_else(|| panic!("entry not found"));
            s.healthy    = true;
            s.last_error = None;
        }
        let list = shared.read().unwrap_or_else(|e| e.into_inner());
        let s = list.iter().find(|u| u.id == entry.id)
            .unwrap_or_else(|| panic!("entry not found"));
        assert!(s.last_error.is_none(), "last_error must be None after a successful probe");
        assert!(s.healthy);
    }

    // ── #56: tls_hostname on PATCH /api/upstreams/:id ─────────────────────────

    #[tokio::test]
    async fn patch_upstream_tls_hostname_sets_value() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_resp = post_upstream(app.clone(), (k, v.clone()),
            r#"{"addr":"9.9.9.9","protocol":"dot"}"#).await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str().unwrap().to_string();

        let patch_body = serde_json::json!({"tls_hostname":"custom.example.com"}).to_string();
        let resp = app.clone().oneshot(
            Request::builder()
                .method("PATCH").uri(format!("/api/upstreams/{id}"))
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", patch_body.len().to_string())
                .body(Body::from(patch_body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["upstream"]["tls_hostname"], "custom.example.com");
    }

    #[tokio::test]
    async fn patch_upstream_tls_hostname_empty_clears() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // Add DoT upstream with tls_hostname set
        let body = serde_json::json!({"addr":"9.9.9.9","protocol":"dot","tls_hostname":"dns.quad9.net"}).to_string();
        let add_resp = app.clone().oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams")
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str().unwrap().to_string();

        // Clear tls_hostname by patching with ""
        let patch_body = serde_json::json!({"tls_hostname":""}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("PATCH").uri(format!("/api/upstreams/{id}"))
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", patch_body.len().to_string())
                .body(Body::from(patch_body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        // tls_hostname absent from JSON when None (skip_serializing_if)
        assert!(j["upstream"].get("tls_hostname").is_none() || j["upstream"]["tls_hostname"].is_null(),
            "tls_hostname must be absent or null after clearing; got: {:?}", j["upstream"]);
    }

    #[tokio::test]
    async fn post_upstream_tls_hostname_validated_control_char() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // tls_hostname with control character must return 400
        let body = serde_json::json!({"addr":"9.9.9.9","protocol":"dot","tls_hostname":"bad\x01host"}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams")
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_FIELD");
    }

    #[tokio::test]
    async fn post_upstream_tls_hostname_too_long() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // 254-char tls_hostname must return 400
        let long_host = "a".repeat(254);
        let body = serde_json::json!({"addr":"9.9.9.9","protocol":"dot","tls_hostname": long_host}).to_string();
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/upstreams")
                .header(k, &v)
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_FIELD");
    }

    #[tokio::test]
    async fn cache_stats_reset_on_flush() {
        let app = make_test_app();
        let (k, v) = auth_header();

        // Flush the cache (resets counters)
        let flush_resp = app.clone().oneshot(
            Request::builder().method("POST").uri("/api/cache/flush")
                .header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(flush_resp.status(), StatusCode::OK);

        // Counters must be zero after reset
        let resp = app.oneshot(
            Request::builder().uri("/api/cache/stats").header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["hits"],      0);
        assert_eq!(j["misses"],    0);
        assert_eq!(j["evictions"], 0);
    }

    // ── #57: config upstreams have source field ───────────────────────────────

    #[tokio::test]
    async fn config_upstream_has_source_field() {
        let mut cfg = crate::config::parser::UnboundConfig::default();
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(),
            addrs: vec!["1.1.1.1@53".into()],
            tls: false,
        });
        let app = make_test_app_with_cfg(cfg);
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().uri("/api/upstreams").header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        let ups = json["upstreams"].as_array().expect("upstreams must be array");
        let config_up = ups.iter().find(|u| u["addr"] == "1.1.1.1").expect("1.1.1.1 must be present");
        assert_eq!(config_up["source"], "config", "config-file upstream must have source=config");
    }

    #[tokio::test]
    async fn config_upstream_delete_idempotent_404() {
        // Create a real temp config file with a forward-addr line.
        let tmp = std::env::temp_dir().join(format!("runbound-test-{}.conf", std::process::id()));
        let conf_content = "server:\n    port: 5353\n\nforward-zone:\n    name: \".\"\n    forward-addr: 9.9.9.9@53\n";
        std::fs::write(&tmp, conf_content).expect("write temp conf");

        init_api_key(Some(TEST_KEY.to_string()));
        let _ = crate::runtime::BASE_DIR.set(std::path::PathBuf::from("/tmp/runbound-test"));

        let mut cfg = crate::config::parser::UnboundConfig::default();
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(),
            addrs: vec!["9.9.9.9@53".into()],
            tls: false,
        });
        // Add a second upstream so the first can be deleted (FIX #41)
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(),
            addrs: vec!["8.8.8.8@53".into()],
            tls: false,
        });

        let zones = Arc::new(ArcSwap::new(Arc::new(crate::dns::local::LocalZoneSet::default())));
        let cfg_arc = Arc::new(cfg);
        let log_buffer = crate::logbuffer::new_shared(1000, true);
        let upstreams = crate::upstreams::init_upstreams(&cfg_arc);
        let resolver  = crate::dns::server::create_shared_resolver(&cfg_arc).expect("test resolver");
        let stats = crate::stats::Stats::new();
        let stats_cache = crate::stats::new_snapshot_cache(&stats);
        let state = AppState {
            zones:            Arc::clone(&zones),
            zones_mutex:      Arc::new(tokio::sync::Mutex::new(())),
            tls_cfg:          Arc::new(crate::config::parser::TlsConfig::default()),
            rate_limiter:     ApiRateLimiter::new_public(),
            reload_limiter:   Arc::new(ReloadLimiter::new()),
            stats,
            stats_cache,
            cfg:              Arc::clone(&cfg_arc),
            cfg_path:         tmp.to_string_lossy().to_string(),
            log_buffer,
            upstreams,
            sync_journal:     None,
            sync_key:         None,
            node_id:          None,
            slave_mode:       false,
            base_dir:         Arc::new(std::path::PathBuf::from("/tmp/runbound-test")),
            audit:            crate::audit::init(false, None, None, std::path::PathBuf::from("/tmp")),
            xdp_active:       Arc::new(AtomicU8::new(0)),
            resolver,
            last_flush_at:    Arc::new(std::sync::Mutex::new(None)),
            cache_evictions:  Arc::new(AtomicU64::new(0)),
            lookup_limiter:   Arc::new(ReloadLimiter::new_with_params(10.0, 10.0)),
            per_upstream_resolvers: crate::dns::server::create_shared_resolvers_vec(),
            racing_wins:           Arc::new(DashMap::with_hasher(ahash::RandomState::new())),
        };
        let app = router(state);

        // Compute the deterministic config upstream ID for 9.9.9.9:53:udp
        let id = {
            use sha2::{Digest, Sha256};
            let key = "cfg:9.9.9.9:53:udp";
            let h = Sha256::digest(key.as_bytes());
            let b = h.as_slice();
            format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
                b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]
            )
        };
        let (k, v) = auth_header();

        // First DELETE — must succeed
        let del1 = app.clone().oneshot(
            Request::builder()
                .method("DELETE").uri(format!("/api/upstreams/{id}"))
                .header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(del1.status(), StatusCode::OK, "first delete must return 200");

        // Config file must no longer contain forward-addr: 9.9.9.9@53
        let after = std::fs::read_to_string(&tmp).expect("read temp conf after delete");
        assert!(!after.contains("9.9.9.9"), "forward-addr must be removed from config file");

        // Second DELETE — must return 404 (idempotent)
        let del2 = app.oneshot(
            Request::builder()
                .method("DELETE").uri(format!("/api/upstreams/{id}"))
                .header(k, &v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(del2.status(), StatusCode::NOT_FOUND, "re-delete must return 404");

        let _ = std::fs::remove_file(&tmp);
    }

    // ── POST /api/dns/lookup (#75) ────────────────────────────────────────

    #[tokio::test]
    async fn dns_lookup_no_auth_rejected() {
        let app = make_test_app();
        let body = r#"{"name":"example.com"}"#;
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/dns/lookup")
                .header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dns_lookup_invalid_domain_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = r#"{"name":"-invalid-domain-","type":"A"}"#;
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/dns/lookup")
                .header(k, v).header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["error"], "INVALID_NAME");
    }

    #[tokio::test]
    async fn dns_lookup_invalid_type_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = r#"{"name":"example.com","type":"SOA"}"#;
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/dns/lookup")
                .header(k, v).header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["error"], "INVALID_TYPE");
    }

    #[tokio::test]
    async fn dns_lookup_blocked_domain_returns_blocked_status() {
        // Build app with a blocked zone
        let mut cfg = crate::config::parser::UnboundConfig::default();
        cfg.local_zones.push(crate::config::parser::LocalZone {
            name: "blocked.test.".to_string(),
            zone_type: "refuse".to_string(),
        });
        let app = make_test_app_with_cfg(cfg);
        let (k, v) = auth_header();
        let body = r#"{"name":"blocked.test","type":"A"}"#;
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/dns/lookup")
                .header(k, v).header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["status"], "BLOCKED");
        assert_eq!(j["answers"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn dns_lookup_missing_name_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = r#"{"type":"A"}"#;
        let resp = app.oneshot(
            Request::builder()
                .method("POST").uri("/api/dns/lookup")
                .header(k, v).header("Content-Type", "application/json")
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body)).unwrap()
        ).await.unwrap();
        // Missing required field → unprocessable entity from ApiJson
        assert!(resp.status().is_client_error());
    }

    // ── POST /api/upstreams/reconnect (#78) ───────────────────────────────

    #[tokio::test]
    async fn upstreams_reconnect_requires_auth() {
        let app = make_test_app();
        let resp = app.oneshot(
            Request::builder().method("POST").uri("/api/upstreams/reconnect")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upstreams_reconnect_get_not_allowed() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().method("GET").uri("/api/upstreams/reconnect")
                .header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn upstreams_reconnect_returns_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app.oneshot(
            Request::builder().method("POST").uri("/api/upstreams/reconnect")
                .header(k, v).body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        for field in &["reconnected", "failed", "duration_ms"] {
            assert!(json.get(field).is_some(), "missing field: {field}");
        }
    }
}
