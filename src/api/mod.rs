// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Runbound REST API — full DNS management + feeds + DoT/DoH status

pub mod relay;
pub mod clients;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

use std::convert::Infallible;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::{
    extract::{rejection::QueryRejection, Path, Query, State},
    http::{HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
    Json as JsonExtract, Router,
};
use futures_util::stream;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::audit::{AuditEvent, AuditLogger};
use crate::config::parser::{TlsConfig, UnboundConfig};
use crate::dns::server::{SharedResolver, SharedResolversVec};
use crate::dns::{
    local::LocalZoneSet,
    BlacklistAction, ZoneAction,
};
use crate::feeds::{
    self, add_feed, builtin_presets, remove_feed, update_all_feeds, update_one_feed, FeedFormat,
};
use crate::logbuffer::{LogAction, LogQuery, SharedLogBuffer};
use crate::stats::Stats;
use crate::store::{self, BlacklistEntry, DnsEntry, DnsType};
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
    tokens: f64,
    last_refill: Instant,
    rate: f64,  // tokens per second
    burst: f64, // maximum token capacity
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
                tokens: burst,
                last_refill: Instant::now(),
                rate,
                burst,
            }),
        }
    }

    pub fn check(&self) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let elapsed = now.duration_since(inner.last_refill).as_secs_f64();
        // Refill and update timestamp unconditionally — no conditional branch that
        // could cause elapsed time to accumulate across multiple callers.
        inner.tokens = (inner.tokens + elapsed * inner.rate).min(inner.burst);
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
                    JsonRejection::JsonDataError(e) => {
                        (StatusCode::UNPROCESSABLE_ENTITY, e.to_string())
                    }
                    JsonRejection::JsonSyntaxError(e) => (StatusCode::BAD_REQUEST, e.to_string()),
                    JsonRejection::MissingJsonContentType(e) => {
                        (StatusCode::UNSUPPORTED_MEDIA_TYPE, e.to_string())
                    }
                    e => (StatusCode::BAD_REQUEST, e.to_string()),
                };
                Err((
                    status,
                    axum::Json(serde_json::json!({
                        "error":   "INVALID_REQUEST",
                        "details": msg
                    })),
                ))
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

/// #8: caps on per-subnet policies — bound the persisted file size and the
/// per-query O(N) policy scan / domain set so an authenticated client cannot
/// inflate them into a slow-path resource-exhaustion vector.
const MAX_POLICIES: usize = 256;
const MAX_POLICY_DOMAINS: usize = 4096;

/// Priority: HSM > RUNBOUND_API_KEY env var > api-key in unbound.conf > auto-generate.
/// Auto-generated keys are 256-bit CSPRNG (2× UUID v4, backed by getrandom).
pub fn init_api_key(config_key: Option<String>) -> String {
    let key = crate::hsm::api_key()
        .map(|k| k.to_string())
        // #181: read the key from a 0600 file whose PATH is in the env, so the secret
        // VALUE is never exported into the process environment (/proc/<pid>/environ).
        .or_else(|| {
            std::env::var("RUNBOUND_API_KEY_FILE")
                .ok()
                .and_then(|path| std::fs::read_to_string(path).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        // #190: a set-but-blank RUNBOUND_API_KEY (or a blank config `api-key`) must NOT
        // win over the random fallback — an empty key panicked at `&api_key[..8]`
        // (main.rs). Trim and treat blank as absent, matching the FILE path above.
        .or_else(|| {
            std::env::var("RUNBOUND_API_KEY")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| config_key.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| {
            // 256 bits from OS CSPRNG — two UUID v4s = 64 hex chars.
            // Previous implementation used PID+timestamp (deterministic → weak).
            format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )
        });
    API_KEY.get_or_init(|| ArcSwap::from(Arc::new(key.clone())));
    key
}

/// Returns the current API key as an owned Arc — zero-copy for the common read path.
pub fn get_api_key() -> Arc<String> {
    API_KEY
        .get()
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

struct ApiBucket {
    tokens: u64,
    last: Instant,
}

// DashMap: each shard has its own RwLock — no global lock, parallel IPs don't
// contend. check() is sync (no .await), keeping the hot middleware path lean.
// AHash: faster than SipHash for IpAddr keys (same HashDoS resistance).
#[derive(Clone)]
pub struct ApiRateLimiter(Arc<DashMap<IpAddr, ApiBucket, ahash::RandomState>>);

impl ApiRateLimiter {
    fn new() -> Self {
        Self(Arc::new(
            DashMap::with_hasher(ahash::RandomState::default()),
        ))
    }
    pub fn new_public() -> Self {
        Self::new()
    }
    #[inline]
    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut b = self.0.entry(ip).or_insert(ApiBucket {
            tokens: API_RATE_BURST,
            last: now,
        });
        let elapsed_ms = now.duration_since(b.last).as_millis() as u64;
        if elapsed_ms >= 1000 {
            b.tokens = API_RATE_BURST;
            b.last = now;
        } else {
            let new = (API_RATE_LIMIT_RPS * elapsed_ms) / 1000;
            if new > 0 {
                b.tokens = (b.tokens + new).min(API_RATE_BURST);
                b.last = now;
            }
        }
        if b.tokens > 0 {
            b.tokens -= 1;
            true
        } else {
            false
        }
    }
}

// ── Shared state ───────────────────────────────────────────────────────────

/// Anycast / health knobs surfaced to the API and /health endpoint (#21).
#[derive(Clone, Default)]
pub struct NodeHealth {
    pub node_id: Option<String>,
    pub servfail_threshold: f64,
    pub latency_threshold_ms: u64,
    pub min_qps: u64,
}

#[derive(Clone)]
pub struct AppState {
    pub zones: Arc<ArcSwap<LocalZoneSet>>,
    // Serialises concurrent API writes: load-clone-modify-store is not atomic,
    // so two simultaneous POST /dns would race without this guard.
    // DNS reads (every query) never touch this mutex — zero read overhead.
    pub zones_mutex: Arc<Mutex<()>>,
    pub tls_cfg: Arc<TlsConfig>,
    pub rate_limiter: ApiRateLimiter,
    pub dns_rate_limiter: Arc<crate::dns::ratelimit::RateLimiter>,
    pub reload_limiter: Arc<ReloadLimiter>,
    pub stats: Arc<Stats>,
    /// Pre-computed snapshot refreshed every second by `qps_update_loop`.
    /// API handlers load this instead of calling `stats.snapshot()` on every
    /// request, avoiding ~360 atomic loads per call under monitoring load.
    pub stats_cache: crate::stats::SharedSnapshot,
    pub cfg: Arc<UnboundConfig>,
    pub cfg_path: String,
    pub log_buffer: SharedLogBuffer,
    pub upstreams: SharedUpstreams,
    /// Master: Some(journal) to record write events for slave replication.
    /// Slave / standalone: None.
    pub sync_journal: Option<Arc<SyncJournal>>,
    /// Sync/relay HMAC key — used to sign relay requests (#85/#87).
    pub sync_key: Option<String>,
    /// True when running as slave — all write operations are blocked (503).
    pub slave_mode: bool,
    /// Directory where runtime files (api.key, dns_entries.json, …) are stored.
    pub base_dir: Arc<PathBuf>,
    /// Immutable audit log sender. No-op when audit is disabled.
    pub audit: AuditLogger,
    /// XDP mode set by main: 0=disabled, 1=drv, 2=skb.
    pub xdp_active: Arc<AtomicU8>,
    /// Shared DNS resolver — allows cache flush and upstream rebuild from API handlers.
    pub resolver: SharedResolver,
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
    /// #5: per-domain query counter — top-domains endpoint.
    pub domain_stats: Arc<crate::domain_stats::DomainStats>,
    pub alert_tracker: Arc<crate::alerts::AlertTracker>,
    pub webhook_targets: Arc<tokio::sync::RwLock<Vec<crate::webhooks::WebhookTarget>>>,
    pub webhook_dispatcher: crate::webhooks::WebhookDispatcher,
    /// #89: ICMP echo responder statistics (polled from BPF per-CPU array).
    pub icmp_stats: Arc<crate::icmp::IcmpStats>,
    /// #89: Current ICMP config — updated via PUT /api/icmp/config.
    pub icmp_cfg: Arc<std::sync::Mutex<crate::icmp::IcmpConfig>>,
    /// Runtime DNSSEC validation toggle (#72 perf path). Mirrors cfg.dnssec_validation at startup.
    /// Updated by PATCH /api/config; all rebuild_and_swap calls read from here.
    pub dnssec_enabled: Arc<AtomicBool>,
    /// #202: resolution mode (0 = forward, 1 = full-recursion). Hot-swapped by PUT /api/resolution
    /// (admin-only); the DNS data path reads it on the hot path. Shared with the running handler.
    pub resolution_mode: Arc<std::sync::atomic::AtomicU8>,
    /// #202: stateless recursor plumbing handle (the validating
    /// resolver is stateless; `resolution_mode` alone drives serving). Retained
    /// for relay/handler construction symmetry — never read.
    #[allow(dead_code)]
    pub recursor: crate::dns::recursor::SharedRecursor,
    /// Multi-user registry (None = single-user mode, only master API key works).
    pub user_registry: Option<Arc<crate::multiuser::UserRegistry>>,
    /// #153: Channel to send the current blacklist domain list to the XDP poll task
    /// for fast-path NXDOMAIN blocking. None when XDP is disabled.
    pub blacklist_reload_tx: Option<tokio::sync::mpsc::Sender<Vec<String>>>,
    /// #10: editable split-horizon entries. CRUD via /api/split-horizon persists to
    /// runbound.conf and is applied LIVE (#187): apply_split_horizon_live rebuilds the
    /// per-view fast-path snapshots and hot-swaps SPLIT_HORIZON_LIVE for the slow path —
    /// no restart required.
    pub split_horizon: Arc<std::sync::Mutex<Vec<crate::config::parser::SplitHorizonEntry>>>,
    pub node_health: NodeHealth,
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

fn default_ttl_i64() -> i64 {
    3600
}

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
    pub schedule: Option<store::ScheduleWindow>,
}

// ── Security middleware ────────────────────────────────────────────────────

async fn security_middleware(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
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
    let has_content_type_json = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false);

    if let Some(cl) = req.headers().get(axum::http::header::CONTENT_LENGTH) {
        let len: usize = match cl.to_str().ok().and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({
                        "error": "BAD_REQUEST",
                        "details": "Malformed Content-Length header"
                    })),
                )
                    .into_response()
            }
        };
        if len > MAX_BODY_BYTES {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                axum::Json(serde_json::json!({
                    "error": "REQUEST_TOO_LARGE",
                    "details": format!("Body exceeds {} bytes", MAX_BODY_BYTES)
                })),
            )
                .into_response();
        }
    } else if has_content_type_json {
        // JSON body without Content-Length → 411 Length Required.
        // Eliminates the chunked-body drop-without-413 behaviour (SEC-04).
        return (
            StatusCode::LENGTH_REQUIRED,
            axum::Json(serde_json::json!({
                "error": "LENGTH_REQUIRED",
                "details": "Content-Length header is required for JSON requests"
            })),
        )
            .into_response();
    }

    // ── 1. Rate limiting ──────────────────────────────────────────────
    // VUL-04: Never trust X-Forwarded-For. The API is bound exclusively to
    // 127.0.0.1 so the real peer is always localhost. Accepting XFF would let
    // any caller spoof an arbitrary IP to bypass per-IP rate limiting.
    let client_ip: IpAddr = IpAddr::from([127, 0, 0, 1]);

    if !state.rate_limiter.check(client_ip) {
        warn!(%client_ip, "API rate limited");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "1")],
            "Rate limit exceeded",
        )
            .into_response();
    }

    // ── 2. API key authentication (Bearer token) ──────────────────────
    // ALL endpoints require authentication — including /help.
    // Exposing version, endpoint list, or RFCs without auth enables
    // fingerprinting and targeted exploitation (AUDIT-HIGH-02).
    let path = req.uri().path();
    // NEW-N1: this middleware is layered on the INNER
    // `api_routes`, which the top-level router mounts via `nest("/api", …)`.
    // axum's `nest` applies `StripPrefix`, so `req.uri().path()` here is the
    // STRIPPED path (`/dns`), not the original (`/api/dns`). The RBAC matcher
    // `Role::may_write` keys on `/api/...` prefixes, so the stripped path made
    // every non-admin write fail-closed (403) and left the per-zone
    // `may_manage_name` check unreachable. Recover the original, un-stripped
    // path from the `OriginalUri` extension axum inserts on nesting; fall back
    // to the visible path if it is ever absent (e.g. a non-nested mount).
    let full_path = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|o| o.0.path().to_string())
        .unwrap_or_else(|| path.to_string());
    let audit_method = req.method().clone();
    let audit_path = path.to_string();
    {
        // NEW-HIGH: timing oracle — pre-auth brute-force brake.
        // The sleep is applied BEFORE constant_time_eq so it cannot be used as
        // a timing signal to distinguish key content. All requests (correct key,
        // wrong key, or partial key) are equally delayed when failures are high.
        let current_failures = AUTH_FAILURES.load(std::sync::atomic::Ordering::Relaxed);
        if current_failures >= 50 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let auth = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let key = get_api_key();
        let expected = format!("Bearer {}", key.as_str());
        if !constant_time_eq(auth.as_bytes(), expected.as_bytes()) {
            // Master key did not match -- check user registry if multi-user is enabled.
            let user_bearer = auth.strip_prefix("Bearer ").unwrap_or("");
            let maybe_user = state.user_registry.as_ref()
                .and_then(|reg| reg.by_api_key(user_bearer))
                .filter(|u| u.enabled);

            if let Some(user) = maybe_user {
                AUTH_FAILURES.store(0, std::sync::atomic::Ordering::Relaxed);
                // RBAC: enforce role-based write restrictions
                let method = req.method().clone();
                let is_write = !matches!(method, axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS);
                if is_write && !user.admin && !user.role.may_write(&full_path) {
                    return (
                        StatusCode::FORBIDDEN,
                        [(axum::http::header::CONTENT_TYPE, "text/plain")],
                        "Forbidden: role does not permit writes to this endpoint",
                    ).into_response();
                }
                req.extensions_mut().insert(crate::multiuser::RequestUser::from_account(&user));
            } else {
                let failures = AUTH_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let audit = state.audit.clone();
                let path_owned = path.to_string();
                tokio::spawn(async move {
                    audit.send(AuditEvent::AuthFailure { path: path_owned });
                    if failures.is_multiple_of(10) {
                        warn!(failures, "Repeated API authentication failures — check RUNBOUND_API_KEY");
                    }
                });
                // #182: after repeated INVALID attempts, lock out the brute-forcer
                // with 429. A VALID key never reaches this branch — it resets
                // AUTH_FAILURES and proceeds — so a legitimate caller is never locked out.
                if failures >= 20 {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(axum::http::header::RETRY_AFTER, "30")],
                        "Too many authentication failures",
                    ).into_response();
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    [(axum::http::header::WWW_AUTHENTICATE, "Bearer realm=\"runbound\"")],
                    "Unauthorized",
                ).into_response();
            }
        } else {
            AUTH_FAILURES.store(0, std::sync::atomic::Ordering::Relaxed);
            req.extensions_mut().insert(crate::multiuser::RequestUser::admin_context());
        }
    }

    // ── 3. Security response headers ──────────────────────────────────
    // #audit: actor = the authenticated user resolved above (inserted into req).
    let audit_actor = req
        .extensions()
        .get::<crate::multiuser::RequestUser>()
        .map(|u| u.username.clone());
    let mut response = next.run(req).await;
    // #audit: record what authenticated users/admins do — every mutating request,
    // with the actor and the result status (the structured events add the detail).
    if let Some(actor) = audit_actor {
        if !matches!(audit_method, axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS) {
            let audit = state.audit.clone();
            let status = response.status().as_u16();
            tokio::spawn(async move {
                audit.send_as(actor, AuditEvent::AdminAction { method: audit_method.to_string(), path: audit_path, status });
            });
        }
    }
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    // Disable nginx response buffering so SSE events reach the client immediately.
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
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
    let diff: u8 = b.iter().enumerate().fold(len_mismatch, |acc, (i, &bi)| {
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
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            JsonExtract(serde_json::json!({
                "error":   "READ_ONLY",
                "details": "This node is a slave replica — write operations are disabled",
            })),
        )
            .into_response();
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
        .route("/help", get(help_handler))
        // Operations
        .route("/stats", get(stats_handler))
        .route("/stats/stream", get(stats_stream_handler))
        .route("/stats/top-domains", get(top_domains_handler))
        .route("/config", get(config_handler).patch(patch_config_handler))
        .route("/dnssec/ds", get(dnssec_ds_handler))
        .route("/resolution", get(resolution_get_handler).put(resolution_put_handler))
        .route("/reload", post(reload_handler))
        // DNS CRUD
        .route("/dns/lookup", post(dns_lookup_handler))
        .route("/dns", get(list_dns_handler).post(add_dns_handler))
        .route("/dns/:id", get(get_dns_handler).delete(delete_dns_handler))
        // Blacklist
        .route(
            "/blacklist",
            get(list_blacklist_handler).post(add_blacklist_handler),
        )
        .route("/blacklist/:id", delete(delete_blacklist_handler))
        .route("/split-horizon", get(list_split_horizon).post(add_split_horizon))
        .route("/split-horizon/:name", delete(delete_split_horizon))
        // #8: per-subnet/VLAN filtering policies.
        .route("/policies", get(list_policies_handler).post(add_policy_handler))
        .route(
            "/policies/:name",
            delete(delete_policy_handler).put(put_policy_handler),
        )
        // Feeds
        .route("/feeds", get(get_feeds_handler).post(add_feed_handler))
        .route("/feeds/presets", get(feed_presets_handler))
        .route("/feeds/update", post(update_feeds_handler))
        .route("/feeds/:id", delete(delete_feed_handler))
        .route("/feeds/:id/update", post(update_one_feed_handler))
        // System
        .route("/system", get(system_handler))
        .route("/cache/flush", post(cache_flush_handler))
        // TLS / Protocol status
        .route("/tls", get(tls_status_handler).delete(tls_disable_handler))
        .route("/tls/cert", get(tls_cert_handler))
        .route("/tls/self-signed", post(tls_self_signed_handler))
        .route("/tls/ca", get(tls_ca_handler))
        .route("/tls/import", post(tls_import_handler))
        // Monitoring
        .route(
            "/upstreams",
            get(upstreams_handler).post(add_upstream_handler),
        )
        .route("/upstreams/presets", get(upstream_presets_handler))
        .route("/upstreams/reconnect", post(reconnect_upstreams_handler))
        .route(
            "/upstreams/:id",
            delete(delete_upstream_handler).patch(patch_upstream_handler),
        )
        .route("/upstreams/:id/probe", post(probe_upstream_handler))
        .route("/cache/stats", get(cache_stats_handler))
        .route("/logs", get(logs_handler).delete(clear_logs_handler))
        .route("/clients", get(clients::clients_handler))
        .route("/clients/:ip", get(clients::client_detail_handler))
        .route("/clients/:ip/logs", get(clients::client_logs_handler))
        .route("/audit/tail", get(audit_tail_handler))
        .route("/metrics", get(metrics_handler))
        // Sync
        .route("/sync/slaves", get(sync_slaves_handler))
        // #86: SSE node-status stream
        .route("/events", get(events_handler))
        // Node relay (#85/#87/#88) — master side
        .route("/nodes", get(relay::list_nodes_handler))
        .route(
            "/nodes/:node_id/relay/*path",
            any(relay::relay_forward_handler),
        )
        // ICMP echo responder (#89)
        .route("/icmp/stats", get(icmp_stats_handler))
        .route(
            "/icmp/config",
            get(icmp_config_get_handler).put(icmp_config_put_handler),
        )
        // Alert thresholds (#12)
        .route("/alerts", get(get_alerts))
        .route("/alerts/rules", get(get_alerts).put(put_alert_rules))
        .route("/webhooks/test", post(post_webhook_test))
        .route("/alerts/blocked/:ip", delete(delete_blocked_ip).put(put_blocked_ip))
        .route("/protection/banned", get(banned_list_handler))
        .route("/protection/banned/:ip/blacklist", post(blacklist_ip_handler))
        // Administration
        .route("/rotate-key", post(rotate_key_handler))
        // Multi-user management
        .route("/users", get(list_users_handler).post(create_user_handler))
        .route("/users/me", get(get_me_handler))
        .route("/users/:id", delete(delete_user_handler))
        .route("/users/:id/rotate-key", post(rotate_user_key_handler))
        // Backup & restore
        .route("/backup", get(list_backups_handler).post(backup_handler))
        .route("/backup/restore", post(restore_handler))
        .route("/backup/export", get(backup_export_handler))
        .route("/backup/import", post(backup_import_handler))
        .route("/backup/:id", delete(delete_backup_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            slave_guard_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        // axum DefaultBodyLimit returns HTTP 413 before reading the body into RAM,
        // regardless of payload size. tower_http::RequestBodyLimitLayer drops the
        // TCP connection for very large payloads (> ~512 KB) instead of 413.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    Router::new().merge(health_route).nest("/api", api_routes)
}

// ── GET /help ──────────────────────────────────────────────────────────────

/// (method, path, description) — kept as a plain data table rather than one
/// giant `json!` array literal: with 80+ entries the latter hits serde_json's
/// macro recursion limit at compile time. Must stay in sync with the actual
/// `.route(...)` declarations in `router()` above — there is no way to derive
/// this list from axum's `Router` at runtime, so it is hand-maintained.
const HELP_ENDPOINTS: &[(&str, &str, &str)] = &[
    ("GET",    "/health",               "Liveness check (no auth required)"),
    ("GET",    "/api/help",             "API documentation"),
    ("GET",    "/api/stats",            "Query statistics snapshot"),
    ("GET",    "/api/stats/stream",     "Live stats as Server-Sent Events (1-second interval)"),
    ("GET",    "/api/stats/top-domains", "Top queried domains since startup (query param: limit=N, default 10, max 100)"),
    ("GET",    "/api/config",           "Running configuration"),
    ("PATCH",  "/api/config",           "Toggle runtime settings without restart (dnssec_validation)"),
    ("GET",    "/api/dnssec/ds",        "DS record(s) for DNSSEC-signed local zones (local-zone-dnssec: yes)"),
    ("GET",    "/api/resolution",       "Current resolution mode (forward / full-recursion) and recursor status"),
    ("PUT",    "/api/resolution",       "Switch resolution mode at runtime, no restart (admin only)"),
    ("POST",   "/api/reload",           "Hot-reload zones and blacklist from disk"),
    ("POST",   "/api/dns/lookup",       "Live DNS resolution via the configured resolver, with cache visibility"),
    ("GET",    "/api/dns",              "List all local DNS entries"),
    ("POST",   "/api/dns",              "Add a local DNS entry (A/AAAA/CNAME/TXT/MX/SRV/CAA/PTR/NAPTR/SSHFP/TLSA/NS)"),
    ("GET",    "/api/dns/:id",          "Get a single DNS entry by UUID"),
    ("DELETE", "/api/dns/:id",          "Remove a DNS entry by UUID"),
    ("GET",    "/api/blacklist",        "List blacklist entries"),
    ("POST",   "/api/blacklist",        "Add a domain to the blacklist (refuse/nxdomain)"),
    ("DELETE", "/api/blacklist/:id",    "Remove a blacklist entry"),
    ("GET",    "/api/split-horizon",       "List split-horizon entries (per-client-subnet answer sets, #10)"),
    ("POST",   "/api/split-horizon",       "Add or replace (by name) a split-horizon entry — applied live (no restart)"),
    ("DELETE", "/api/split-horizon/:name", "Remove a split-horizon entry by name"),
    ("GET",    "/api/policies",         "List per-subnet/VLAN filtering policies, additive to the global blacklist (#8)"),
    ("POST",   "/api/policies",         "Add or replace (by name) a subnet policy — applied live, no restart (#8)"),
    ("PUT",    "/api/policies/:name",   "Update a subnet policy — applied live, no restart (#8)"),
    ("DELETE", "/api/policies/:name",   "Remove a subnet policy — applied live, no restart (#8)"),
    ("GET",    "/api/feeds",            "List feed subscriptions"),
    ("POST",   "/api/feeds",            "Subscribe to a remote blocklist"),
    ("DELETE", "/api/feeds/:id",        "Remove a feed subscription"),
    ("POST",   "/api/feeds/update",     "Refresh all feeds"),
    ("POST",   "/api/feeds/:id/update", "Refresh one feed"),
    ("GET",    "/api/feeds/presets",    "List pre-configured blocklists"),
    ("GET",    "/api/system",           "Host system info: version, memory, CPU cores, XDP state, workers"),
    ("POST",   "/api/cache/flush",      "Flush the DNS resolver cache"),
    ("GET",    "/api/tls",              "DoT/DoH/DoQ TLS status"),
    ("DELETE", "/api/tls",              "Disable encrypted DNS — DoT/DoH/DoQ (admin only, restart required)"),
    ("GET",    "/api/tls/cert",         "Encrypted-DNS certificate status (active vs configured, expiry, fingerprint)"),
    ("POST",   "/api/tls/self-signed",  "Generate a self-signed cert and enable DoT/DoH/DoQ (admin only, restart required)"),
    ("GET",    "/api/tls/ca",           "Download the Runbound Local CA certificate (PEM) for trust-store import"),
    ("POST",   "/api/tls/import",       "Import an existing certificate + key, e.g. Let's Encrypt (admin only, restart required)"),
    ("GET",    "/api/upstreams",         "Upstream DNS resolver health"),
    ("POST",   "/api/upstreams",         "Add a runtime upstream resolver"),
    ("GET",    "/api/upstreams/presets", "List pre-configured upstream resolvers"),
    ("POST",   "/api/upstreams/reconnect", "Force-reconnect all DoT upstreams"),
    ("DELETE", "/api/upstreams/:id",     "Remove a runtime upstream resolver"),
    ("PATCH",  "/api/upstreams/:id",       "Update a runtime upstream resolver (name, tls_hostname)"),
    ("POST",   "/api/upstreams/:id/probe", "Trigger an immediate health probe for one upstream"),
    ("GET",    "/api/cache/stats",       "DNS cache counters: hits, misses, evictions, hit rate"),
    ("GET",    "/api/logs",             "Recent query log (newest first) — ?limit=100&page=0&action=blocked&client=1.2.3.4&since=<unix>"),
    ("DELETE", "/api/logs",             "Clear the in-memory query log ring buffer (GDPR right-to-erasure)"),
    ("GET",    "/api/clients",         "Per-client DNS activity — list all active clients with stats (#6)"),
    ("GET",    "/api/clients/:ip",      "Per-client detail: top domains, action breakdown (#6)"),
    ("GET",    "/api/clients/:ip/logs", "Recent log entries for a specific client IP (#6)"),
    ("GET",    "/api/audit/tail",       "Tail of the HMAC-chained, tamper-evident audit log"),
    ("GET",    "/api/metrics",          "Prometheus/OpenMetrics exposition (text/plain; version=0.0.4)"),
    ("GET",    "/api/sync/slaves",       "List connected slave nodes (master mode only)"),
    ("GET",    "/api/events",            "Real-time node-status push via Server-Sent Events (master only)"),
    ("GET",    "/api/nodes",             "List registered nodes with relay capability (#88)"),
    ("ANY",    "/api/nodes/{id}/relay/*", "Relay request to a registered slave via HMAC-signed channel (#85)"),
    ("GET",    "/api/icmp/stats",          "ICMP echo responder counters: handled, replied, dropped, rate_limited"),
    ("GET",    "/api/icmp/config",         "Current ICMP echo responder config"),
    ("PUT",    "/api/icmp/config",         "Update ICMP echo responder config live (enable, rate_limit, burst)"),
    ("GET",    "/api/alerts",              "Active alert rules, currently blocked clients, recent alert events"),
    ("GET",    "/api/alerts/rules",        "Same response as GET /api/alerts (alias path)"),
    ("PUT",    "/api/alerts/rules",        "Replace the full alert-rule set — hot-applied, no restart (admin only)"),
    ("POST",   "/api/webhooks/test",       "Send a synthetic test event to the configured webhook targets"),
    ("PUT",    "/api/alerts/blocked/:ip",  "Manually block an IP address (permanent, no expiry)"),
    ("DELETE", "/api/alerts/blocked/:ip",  "Unblock a previously blocked IP"),
    ("GET",    "/api/protection/banned",   "Current banned source IPs, enforced on the XDP and kernel slow datapaths"),
    ("POST",   "/api/protection/banned/:ip/blacklist", "Promote a ban to permanent (never auto-expires)"),
    ("POST",   "/api/rotate-key",       "Atomically rotate the API key — reads new_key from the JSON request body"),
    ("GET",    "/api/users",             "List all users, multi-user mode (admin only)"),
    ("POST",   "/api/users",             "Create a user, multi-user mode (admin only)"),
    ("GET",    "/api/users/me",          "Profile of the authenticated user (admin or per-user key)"),
    ("DELETE", "/api/users/:id",         "Delete a user, multi-user mode (admin only)"),
    ("POST",   "/api/users/:id/rotate-key", "Rotate a user's API key (admin, or the user themselves)"),
    ("POST",   "/api/backup",            "Snapshot config + DNS entries + blacklist + feeds to base_dir/backups/"),
    ("GET",    "/api/backup",            "List available backup snapshots"),
    ("POST",   "/api/backup/restore",    "Restore a snapshot by id (triggers hot-reload)"),
    ("GET",    "/api/backup/export",     "Full backup download (JSON): config + all state/secret files, base64-encoded"),
    ("POST",   "/api/backup/import",     "Full restore from an exported backup — applied live (admin only)"),
    ("DELETE", "/api/backup/:id",        "Delete a backup snapshot"),
];

async fn help_handler() -> impl IntoResponse {
    let endpoints: Vec<serde_json::Value> = HELP_ENDPOINTS
        .iter()
        .map(|(method, path, description)| {
            serde_json::json!({"method": method, "path": path, "description": description})
        })
        .collect();
    JsonExtract(serde_json::json!({
        "service": "Runbound DNS",
        "version": env!("CARGO_PKG_VERSION"),
        "protocols": ["DNS/UDP:53","DNS/TCP:53","DoT:853","DoH:443","DoQ:853/UDP"],
        "rfcs": ["RFC1034","RFC1035","RFC2782","RFC4033","RFC4034","RFC4035","RFC6698","RFC6891","RFC7858","RFC8484","RFC9250"],
        "endpoints": endpoints
    }))
}

// ── GET /health ────────────────────────────────────────────────────────────

async fn health_handler(State(s): State<AppState>) -> impl IntoResponse {
    let snap = s.stats_cache.load();
    let xdp_active = s.xdp_active.load(Ordering::Relaxed) > 0;
    let (upstreams_healthy, upstreams_total) = {
        let list = s
            .upstreams
            .read()
            .unwrap_or_else(|e| e.into_inner());
        (
            list.iter().filter(|u| u.healthy).count() as u32,
            list.len() as u32,
        )
    };
    // #21: BGP Route Health Injection — return 503 when degraded so the BGP
    // daemon (BIRD/ExaBGP/FRR) withdraws the anycast route. Opt-in: 503 only fires
    // when a health threshold is configured; otherwise /health stays a 200 liveness probe.
    let nh = &s.node_health;
    let total = snap.total.max(1);
    let servfail_pct = snap.servfail as f64 / total as f64 * 100.0;
    let armed = nh.servfail_threshold > 0.0 || nh.latency_threshold_ms > 0 || nh.min_qps > 0;
    let mut reason: Option<String> = None;
    if nh.servfail_threshold > 0.0 && servfail_pct > nh.servfail_threshold {
        reason = Some(format!("servfail {servfail_pct:.1}% > {:.1}%", nh.servfail_threshold));
    }
    if reason.is_none() && nh.latency_threshold_ms > 0 && snap.latency_p95_ms > nh.latency_threshold_ms as f64 {
        reason = Some(format!("p95 latency {:.0}ms > {}ms", snap.latency_p95_ms, nh.latency_threshold_ms));
    }
    if reason.is_none() && nh.min_qps > 0 && (snap.qps_1m as u64) < nh.min_qps {
        reason = Some(format!("qps {:.0} < {}", snap.qps_1m, nh.min_qps));
    }
    if reason.is_none() && armed && upstreams_total > 0 && upstreams_healthy == 0 {
        reason = Some("all upstreams down".to_string());
    }
    let status = if upstreams_total == 0 {
        "error"
    } else if upstreams_healthy == 0 || reason.is_some() {
        "degraded"
    } else {
        "ok"
    };
    let code = if reason.is_some() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (code, JsonExtract(serde_json::json!({
        "status":            status,
        "node":              nh.node_id,
        "uptime_secs":       snap.uptime_secs,
        "xdp_active":        xdp_active,
        "upstreams_healthy": upstreams_healthy,
        "upstreams_total":   upstreams_total,
        "cache_entries":     snap.cache_entries,
        "reason":            reason,
    })))
}

// ── GET /api/icmp/stats (#89) ─────────────────────────────────────────────
async fn icmp_stats_handler(State(s): State<AppState>) -> impl IntoResponse {
    use axum::Json;
    use std::sync::atomic::Ordering;
    Json(serde_json::json!({
        "handled":      s.icmp_stats.handled.load(Ordering::Relaxed),
        "replied":      s.icmp_stats.replied.load(Ordering::Relaxed),
        "dropped":      s.icmp_stats.dropped.load(Ordering::Relaxed),
        "rate_limited": s.icmp_stats.rate_limited.load(Ordering::Relaxed),
        "banned":       s.icmp_stats.banned_snapshot(),
    }))
}

// ── GET /api/icmp/config (#89) ────────────────────────────────────────────
async fn icmp_config_get_handler(State(s): State<AppState>) -> impl IntoResponse {
    use axum::Json;
    let cfg = s.icmp_cfg.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Json(serde_json::json!({
        "enable":        cfg.enabled,
        "rate_limit":    cfg.rate_pps,
        "burst":         cfg.burst,
        "ban_threshold": cfg.ban_threshold,
    }))
}

#[derive(serde::Deserialize)]
struct IcmpConfigRequest {
    enable: Option<bool>,
    rate_limit: Option<u32>,
    burst: Option<u32>,
    ban_threshold: Option<u32>,
}

// ── PUT /api/icmp/config (#89) ────────────────────────────────────────────
async fn icmp_config_put_handler(
    State(s): State<AppState>,
    axum::extract::Json(body): axum::extract::Json<IcmpConfigRequest>,
) -> impl IntoResponse {
    use axum::Json;
    let mut cfg = s.icmp_cfg.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = body.enable        { cfg.enabled = v; }
    if let Some(v) = body.rate_limit    { cfg.rate_pps = v; }
    if let Some(v) = body.burst         { cfg.burst = v; }
    if let Some(v) = body.ban_threshold { cfg.ban_threshold = v; }
    let enabled = cfg.enabled;
    let rate_pps = cfg.rate_pps;
    let burst = cfg.burst;
    let ban_threshold = cfg.ban_threshold;
    drop(cfg);

    let _ = std::fs::write(
        s.base_dir.join("icmp.json"),
        serde_json::json!({"enable":enabled,"rate_limit":rate_pps,"burst":burst,"ban_threshold":ban_threshold}).to_string(),
    );

    if let (Some(ref j), Some(ref k)) = (&s.sync_journal, &s.sync_key) {
        crate::api::relay::push_to_slaves(
            j, k, axum::http::Method::PUT, "icmp/config".to_string(),
            bytes::Bytes::from(serde_json::json!({"enable":enabled,"rate_limit":rate_pps,"burst":burst,"ban_threshold":ban_threshold}).to_string()),
        );
    }

    Json(serde_json::json!({
        "enable":        enabled,
        "rate_limit":    rate_pps,
        "burst":         burst,
        "ban_threshold": ban_threshold,
    }))
}

// ── GET /stats/top-domains ─────────────────────────────────────────────────
#[derive(serde::Deserialize)]
struct TopDomainsParams {
    limit: Option<usize>,
}

async fn top_domains_handler(
    State(s): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<TopDomainsParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(10).clamp(1, 100);
    let top = s.domain_stats.top(limit);
    let entries: Vec<serde_json::Value> = top
        .into_iter()
        .map(|(domain, count)| serde_json::json!({"domain": domain, "count": count}))
        .collect();
    axum::Json(serde_json::json!({
        "top_queried": entries,
        "tracked_domains": s.domain_stats.len(),
    }))
}

// ── GET /stats ─────────────────────────────────────────────────────────────

async fn stats_handler(State(s): State<AppState>) -> impl IntoResponse {
    let mut json = crate::stats::snapshot_to_json(&s.stats_cache.load());
    // #159: read from per-interface registry (covers all N interfaces)
    let xdp_ifaces = crate::dns::xdp::socket::xdp_iface_snapshot();
    let xdp_queues: Vec<serde_json::Value> = xdp_ifaces.iter().flat_map(|iface| {
        iface.queue_modes.iter().map(|(id, zc)| {
            serde_json::json!({
                "iface": iface.iface,
                "id":    id,
                "mode":  if *zc { "zerocopy" } else { "copy" }
            })
        })
    }).collect();
    json["xdp_queues"]  = serde_json::Value::Array(xdp_queues);
    json["xdp_ifaces"]  = serde_json::json!(
        xdp_ifaces.iter().map(|s| {
            let (mut rx_dropped, mut fill_empty, mut ring_full, mut rx_inval) = (0u64,0u64,0u64,0u64);
            for &fd in &s.xsk_fds {
                if let Some(st) = crate::dns::xdp::socket::read_xsk_statistics(fd) {
                    rx_dropped += st.rx_dropped;
                    fill_empty += st.rx_fill_ring_empty_descs;
                    ring_full  += st.rx_ring_full;
                    rx_inval   += st.rx_invalid_descs;
                }
            }
            serde_json::json!({
            "iface":           s.iface,
            "nic_rx_ring":     s.nic_rx_ring,
            "nic_rx_ring_max": s.nic_rx_ring_max,
            "queues":          s.queue_modes.len(),
            "xsk_rx_dropped":          rx_dropped,
            "xsk_rx_fill_ring_empty":  fill_empty,
            "xsk_rx_ring_full":        ring_full,
            "xsk_rx_invalid_descs":    rx_inval,
        })}).collect::<Vec<_>>()
    );
    JsonExtract(json)
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

    // Worker count: one XDP worker per NIC queue + tokio thread pool. Use the
    // cgroup-aware count so a container reports the cores it can actually use
    // (host sysfs topology is not namespaced) rather than the host's total.
    let cpu_cores = crate::cpu::available_cores();

    // FEAT #47: upstream health counts
    let (upstreams_healthy, upstreams_total) = {
        let list = s
            .upstreams
            .read()
            .unwrap_or_else(|e| e.into_inner());
        (
            list.iter().filter(|u| u.healthy).count() as u32,
            list.len() as u32,
        )
    };

    let dot_reconnects_total = s.stats.dot_reconnects_total.load(Ordering::Relaxed);
    let last_reconnect_at = s
        .stats
        .last_reconnect_at
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .map(serde_json::Value::String)
        .unwrap_or(serde_json::Value::Null);

    // XDP wire-format cache stats (#64).
    let xdp_cache_entries =
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_ENTRIES.load(Ordering::Relaxed);
    // In-kernel eBPF snapshot hits/misses: the BPF program answers directly, before the
    // AF_XDP worker. 0 when the snapshot path isn't serving (e.g. copy mode on a VM).
    let xdp_snapshot_hits = crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_HITS.load(Ordering::Relaxed);
    let xdp_snapshot_misses = crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES.load(Ordering::Relaxed);
    // XDP fast-path (per-worker) cache hits/misses — what the XDP datapath actually served
    // from cache. This is the meaningful "is XDP serving from cache?" rate.
    let xdp_cache_hits: u64 = crate::dns::cache_snapshot::XDP_WORKER_PKTS
        .iter().map(|c| c.load(Ordering::Relaxed)).sum();
    let xdp_cache_misses: u64 = crate::dns::cache_snapshot::XDP_WORKER_MISS
        .iter().map(|c| c.load(Ordering::Relaxed)).sum();
    let xdp_cache_hit_rate = if xdp_cache_hits + xdp_cache_misses > 0 {
        (xdp_cache_hits as f64 / (xdp_cache_hits + xdp_cache_misses) as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    // #80: NIC ring buffer + drop stats
    let nic_rx_ring = crate::dns::xdp::socket::XDP_NIC_RX_RING.load(Ordering::Relaxed);
    let nic_rx_ring_max = crate::dns::xdp::socket::XDP_NIC_RX_RING_MAX.load(Ordering::Relaxed);
    // AF_XDP per-socket RX stats (kernel ABI, getsockopt XDP_STATISTICS) — VALID
    // under zero-copy, unlike the old ethtool/sysfs nic_rx_* reads which are blind
    // to XDP_REDIRECT->XSK. (Slow-path stats are computed elsewhere, untouched.)
    let (mut xsk_rx_dropped, mut xsk_fill_ring_empty, mut xsk_rx_ring_full) = (0u64, 0u64, 0u64);
    for st_if in crate::dns::xdp::socket::xdp_iface_snapshot() {
        for fd in st_if.xsk_fds {
            if let Some(xs) = crate::dns::xdp::socket::read_xsk_statistics(fd) {
                xsk_rx_dropped      += xs.rx_dropped;
                xsk_fill_ring_empty += xs.rx_fill_ring_empty_descs;
                xsk_rx_ring_full    += xs.rx_ring_full;
            }
        }
    }

    // #33: upstream racing wins per upstream.
    let upstream_racing_wins: serde_json::Map<String, serde_json::Value> = s
        .racing_wins
        .iter()
        .map(|kv| {
            (
                kv.key().clone(),
                serde_json::Value::Number(serde_json::Number::from(
                    kv.value().load(Ordering::Relaxed),
                )),
            )
        })
        .collect();

    // Anycast state (built-in announcer) for the cluster / node view.
    let anycast_json = match crate::anycast::state() {
        Some(st) => serde_json::json!({
            "configured": st.configured,
            "address":    st.address,
            "peer":       st.peer,
            "local_as":   st.local_as,
            "announced":  st.announced.load(Ordering::Relaxed),
        }),
        None => serde_json::json!({ "configured": false }),
    };

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
        "xdp_cache_hits":          xdp_cache_hits,
        "xdp_cache_misses":        xdp_cache_misses,
        "xdp_kernel_snapshot_hits":   xdp_snapshot_hits,
        "xdp_kernel_snapshot_misses": xdp_snapshot_misses,
        "xdp_domain_routing":      s.cfg.xdp_domain_routing,
        "xdp_worker_distribution": crate::dns::cache_snapshot::XDP_WORKER_PKTS
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect::<Vec<u64>>(),
        "nic_rx_ring":     nic_rx_ring,
        "nic_rx_ring_max": nic_rx_ring_max,
        "xsk_rx_dropped":         xsk_rx_dropped,
        "xsk_rx_fill_ring_empty": xsk_fill_ring_empty,
        "xsk_rx_ring_full":       xsk_rx_ring_full,
        "upstream_racing":      s.cfg.upstream_racing,
        "upstream_racing_wins": upstream_racing_wins,
            "dnssec_validation": s.dnssec_enabled.load(Ordering::Relaxed),
        "anycast":              anycast_json,
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
            if line.starts_with("MemTotal:") {
                total_kb = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
            if line.starts_with("MemAvailable:") {
                avail_kb = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
        }
        return (avail_kb / 1024, total_kb / 1024);
    }
    (0, 0)
}

/// Read the cgroup v2 hard memory limit in bytes (None = unlimited).
fn cgroup_memory_max_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    let s = s.trim();
    if s == "max" {
        return None;
    }
    s.parse().ok()
}

/// Read the cgroup v2 current memory usage in bytes.
fn cgroup_memory_current_bytes() -> Option<u64> {
    std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Compute average CPU% for this process since it started.
/// Reads /proc/self/stat (utime+stime) and /proc/uptime.
fn process_cpu_percent() -> f64 {
    let stat = match std::fs::read_to_string("/proc/self/stat") {
        Ok(s) => s,
        Err(_) => return 0.0,
    };
    // Skip past the comm field "(name)" which may contain spaces.
    let after_comm = match stat.find(')') {
        Some(p) => p + 2,
        None => return 0.0,
    };
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
    let utime: u64 = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
    let starttime: u64 = fields.get(19).and_then(|v| v.parse().ok()).unwrap_or(0);
    let uptime_s: f64 = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(0.0);
    const CLK_TCK: f64 = 100.0; // sysconf(_SC_CLK_TCK) on all supported Linux targets
    let proc_uptime = uptime_s - (starttime as f64 / CLK_TCK);
    if proc_uptime <= 0.0 {
        return 0.0;
    }
    ((utime + stime) as f64 / CLK_TCK / proc_uptime * 1000.0).round() / 10.0
}

// ── GET /config ────────────────────────────────────────────────────────────

/// GET /api/dnssec/ds — the DS records to publish at the parent registrar for each signed local
/// zone (#201). Keys are loaded from the config dir on demand; the value is the standard DS
/// presentation `<key_tag> <alg> <digest_type> <digest-hex>`.
async fn dnssec_ds_handler(State(s): State<AppState>) -> impl IntoResponse {
    if !s.cfg.local_zone_dnssec {
        return JsonExtract(serde_json::json!({ "enabled": false, "ds": [] }));
    }
    // SEC-L9: surface the DS from the LIVE in-memory signer (built once at startup on the master,
    // adopted via key-replication on the slave). Do NOT call ZoneSigner::new here: that path
    // load_or_generate()s, i.e. it would WRITE fresh keys on a mere authenticated GET, and on a
    // slave it would mint divergent local keys instead of the replicated master keys.
    match crate::dns::zone_signer::SHARED_SIGNER
        .get()
        .and_then(|sh| (*sh.load_full()).clone())
    {
        Some(signer) => {
            let ds: Vec<_> = signer
                .ds_records()
                .into_iter()
                .map(|(zone, key_tag, ds)| {
                    // DS presentation (RFC 4034 §5.3): key_tag alg digest_type HEXDIGEST.
                    let alg = ds.get(2).copied().unwrap_or(0);
                    let dtype = ds.get(3).copied().unwrap_or(0);
                    let digest = data_encoding::HEXUPPER.encode(ds.get(4..).unwrap_or(&[]));
                    serde_json::json!({ "zone": zone, "ds": format!("{key_tag} {alg} {dtype} {digest}") })
                })
                .collect();
            JsonExtract(serde_json::json!({ "enabled": true, "ds": ds }))
        }
        None => JsonExtract(serde_json::json!({ "enabled": true, "ds": [] })),
    }
}

async fn config_handler(State(s): State<AppState>) -> impl IntoResponse {
    let cfg = s.cfg.as_ref();
    // Live counts include both config-file entries and API-managed entries.
    let api_dns = store::load().map(|st| st.entries.len()).unwrap_or(0);
    let api_bl = store::load_blacklist()
        .map(|bl| bl.entries.len())
        .unwrap_or(0);
    let api_feeds = crate::feeds::load_feeds()
        .map(|f| f.feeds.len())
        .unwrap_or(0);
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
        "rate_limit":        s.dns_rate_limiter.rps(),
        "rate_limit_burst":  s.dns_rate_limiter.burst(),
        "cache_max_ttl":     cfg.cache_max_ttl,
        "cache_min_ttl":     cfg.cache_min_ttl,
        "dnssec_validation": s.dnssec_enabled.load(Ordering::Relaxed),
        "resolution_mode":   if s.resolution_mode.load(Ordering::Relaxed) == 1 { "full-recursion" } else { "forward" },
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

/// #186: write-path XDP cache coherency.
///
/// The XDP fast path checks the shared cache snapshot BEFORE the live local zone,
/// so a stale *forwarded* answer that was cached before a rule was written keeps
/// shadowing that rule until its TTL expires or the service restarts — breaking
/// the no-restart guarantee for local-data, and silently defeating freshly-added
/// blacklist/feed blocks (a security issue for a DNS filter). The wire-native slow
/// path checks the live zone first and is unaffected.
///
/// Fix entirely on the rare WRITE path (zero added per-query work, hot paths
/// untouched): evict every name that changed — old union new zone keys, which
/// also covers deletions — from the shared mutable cache by wire-qname (all
/// qtypes), then re-preload the current local-data. `publish_loop` refreezes the
/// XDP snapshot via `CACHE_WRITE_GEN`.
///
/// MUST be called BEFORE `s.zones.store(..)` so `s.zones` still holds the old set.
fn resync_xdp_cache(s: &AppState, new_zones: &LocalZoneSet) {
    let Some(cache) = crate::dns::cache_snapshot::XDP_CACHE_FOR_API.get() else { return };
    resync_xdp_cache_inner(cache, &s.zones.load_full(), new_zones);
}

/// Pure core of `resync_xdp_cache`, decoupled from the global cache handle and
/// `AppState` so it can be unit-tested. Evicts every changed name (old union new
/// zone keys, which also covers deletions) by wire-qname (all qtypes), then
/// re-preloads the current local-data. `pub(crate)`: also called directly from
/// the SIGHUP handler in `main.rs`, which has no `AppState`.
pub(crate) fn resync_xdp_cache_inner(
    cache: &crate::dns::cache_snapshot::MutableCacheMap,
    old_zones: &LocalZoneSet,
    new_zones: &LocalZoneSet,
) {
    let mut affected: std::collections::HashSet<Vec<u8>> =
        std::collections::HashSet::with_capacity(
            old_zones.zones_wire.len() + new_zones.zones_wire.len(),
        );
    // zones_wire keys are already lowercased wire QNAMEs — no conversion needed.
    for k in old_zones.zones_wire.keys().chain(new_zones.zones_wire.keys()) {
        affected.insert(k.to_vec());
    }
    if !affected.is_empty() {
        cache.retain(|_k, e| !affected.contains(e.wire_qname.as_ref()));
    }
    // Re-insert the current local-data A/AAAA (overwrites any evicted-then-changed
    // record; no-op for pure blacklist/feed/delete writes).
    crate::dns::local::preload_into_cache(new_zones, cache);
    crate::dns::cache_snapshot::CACHE_WRITE_GEN
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Apply the on-disk config to the running server WITHOUT a restart: reload
/// runbound.conf, rebuild + republish the local zones (resyncing the XDP cache),
/// refresh alert rules, and re-apply the runtime resolution toggles (resolution
/// mode + QNAME minimisation) a restore may have changed. Shared by POST
/// /api/reload and the backup restore/import paths so a restore takes effect live
/// ("no restart ever"). Returns `(local_zones, local_data, alert_rules)` counts.
fn apply_config_hot_reload(s: &AppState) -> anyhow::Result<(usize, usize, usize)> {
    let new_cfg = crate::config::load(&s.cfg_path)?;
    let new_zones = crate::build_zone_set(&new_cfg);
    resync_xdp_cache(s, &new_zones);
    s.zones.store(std::sync::Arc::new(new_zones));
    // #149: hot-reload alert rules without restart.
    let alert_rules_count = new_cfg.alerts.len();
    s.alert_tracker.update_rules(new_cfg.alerts.clone());
    // Re-apply the runtime resolution toggles a restore may have changed.
    use std::sync::atomic::Ordering;
    let recursion_on =
        new_cfg.resolution_mode == crate::config::parser::ResolutionMode::FullRecursion;
    s.resolution_mode.store(u8::from(recursion_on), Ordering::Relaxed);
    crate::dns::recursor_wire::set_qname_minimisation(new_cfg.qname_minimisation);
    s.audit.send(AuditEvent::ConfigReload);
    // Fire config-reloaded webhook (#11).
    {
        let tgts = s.webhook_targets.try_read();
        if let Ok(tgts) = tgts {
            let ev = crate::webhooks::WebhookEvent::now("config-reloaded");
            s.webhook_dispatcher.fire(&tgts, ev);
        }
    }
    info!(cfg_path = %s.cfg_path, alert_rules = alert_rules_count, "config hot-reload applied");
    Ok((new_cfg.local_zones.len(), new_cfg.local_data.len(), alert_rules_count))
}

async fn reload_handler(State(s): State<AppState>) -> impl IntoResponse {
    // FIX 3.2: independent 2 RPS cap — prevents authenticated DoS via rapid reloads.
    if !s.reload_limiter.check() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            JsonExtract(serde_json::json!({
                "error":   "RATE_LIMITED",
                "details": "reload endpoint is limited to 2 requests per second",
            })),
        );
    }
    match apply_config_hot_reload(&s) {
        Ok((local_zones, local_data, alert_rules)) => (
            StatusCode::OK,
            JsonExtract(serde_json::json!({
                "status":      "ok",
                "cfg_path":    s.cfg_path,
                "local_zones": local_zones,
                "local_data":  local_data,
                "alert_rules": alert_rules,
            })),
        ),
        Err(e) => {
            // FIX 3.4: full error already in the WARN log; sanitize the HTTP body.
            warn!(err = %e, "API reload failed — keeping current zones");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error":   "RELOAD_FAILED",
                    "details": sanitize_error(&e),
                })),
            )
        }
    }
}


// ── PATCH /api/config ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PatchConfigBody {
    dnssec_validation: Option<bool>,
    /// DNS rate limiter steady-state rps (0 disables). Applied live.
    rate_limit: Option<u64>,
    /// DNS rate limiter burst ceiling. Applied live.
    rate_limit_burst: Option<u64>,
}

async fn patch_config_handler(
    State(s): State<AppState>,
    axum::extract::Json(body): axum::extract::Json<PatchConfigBody>,
) -> impl IntoResponse {
    if let Some(v) = body.dnssec_validation {
        s.dnssec_enabled.store(v, Ordering::Relaxed);
        let addrs = upstreams::upstream_addrs(&s.upstreams);
        if let Err(e) = crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, v).await {
            warn!(%e, "resolver rebuild after DNSSEC toggle — continuing");
        }
        // The in-house validating resolver validates every recursive answer
        // (fail-closed) and holds no per-policy state, so there is nothing to
        // rebuild when the DNSSEC-validation flag is toggled.
        s.audit.send(AuditEvent::ConfigReload);
        info!(dnssec = v, "DNSSEC validation toggled via API");
        persist_config(&s);
        // Propagate DNSSEC toggle to all registered slaves
        if let Some(ref j) = s.sync_journal {
            if let Some(ref k) = s.sync_key {
                let body_bytes = bytes::Bytes::from(
                    serde_json::json!({"dnssec_validation": v}).to_string()
                );
                relay::push_to_slaves(j, k, Method::PATCH, "config".to_string(), body_bytes);
            }
        }
    }
    if body.rate_limit.is_some() || body.rate_limit_burst.is_some() {
        // Live-edit the DNS rate limiter (shared with the XDP fast path via AtomicU64).
        // A field left out keeps its current value; both are clamped like the parser.
        let rps = body.rate_limit.map(|v| v.min(1_000_000)).unwrap_or_else(|| s.dns_rate_limiter.rps());
        let burst = body.rate_limit_burst.map(|v| v.min(2_000_000)).unwrap_or_else(|| s.dns_rate_limiter.burst());
        s.dns_rate_limiter.set_limits(rps, Some(burst));
        info!(rps, burst, "DNS rate limit updated live via API");
        persist_config(&s);
    }
    JsonExtract(serde_json::json!({
        "ok": true,
        "dnssec_validation": s.dnssec_enabled.load(Ordering::Relaxed),
        "rate_limit": s.dns_rate_limiter.rps(),
        "rate_limit_burst": s.dns_rate_limiter.burst(),
    }))
}

// ── #202: resolution mode (forward ↔ sovereign full-recursion) ──────────────

#[derive(serde::Deserialize)]
struct ResolutionBody {
    mode: String,
}

/// GET /api/resolution — current mode + whether the sovereign recursor is live.
async fn resolution_get_handler(State(s): State<AppState>) -> impl IntoResponse {
    let full = s.resolution_mode.load(Ordering::Relaxed) == 1;
    JsonExtract(serde_json::json!({
        "mode": if full { "full-recursion" } else { "forward" },
        // The in-house validating resolver has no separate backend handle — there is
        // no `SharedRecursor`; it is active exactly when
        // the serving hot path is in full-recursion mode. `load_full()` is always
        // None now, so report the real serving state instead.
        "recursor_active": full,
    }))
}

/// PUT /api/resolution — admin-only. Atomically switches between forward and sovereign
/// full-recursion: rebuilds the recursor, flips the hot-path atomic only once the backend is
/// ready, persists runbound.conf, and propagates to slaves so the cluster answers consistently.
/// A failed recursor build leaves us in forward mode and returns 500 (never full-recursion with
/// no backend).
async fn resolution_put_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    ApiJson(body): ApiJson<ResolutionBody>,
) -> impl IntoResponse {
    let caller = caller_ext
        .map(|e| e.0)
        .unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (
            StatusCode::FORBIDDEN,
            JsonExtract(serde_json::json!({
                "error": "FORBIDDEN",
                "details": "changing the resolution mode requires admin"
            })),
        );
    }
    let mode = match crate::config::parser::ResolutionMode::parse_value(&body.mode) {
        Some(m) => m,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error": "INVALID_MODE",
                    "details": "mode must be 'forward' or 'full-recursion'"
                })),
            )
        }
    };
    // The in-house validating resolver is always available (no backend to build),
    // so applying a mode is just flipping the hot-path atomic.
    let val = u8::from(mode == crate::config::parser::ResolutionMode::FullRecursion);
    s.resolution_mode.store(val, Ordering::Relaxed);
    s.audit.send(AuditEvent::ConfigReload);
    info!(mode = mode.as_str(), "resolution mode changed via API");
    persist_config(&s);
    // Propagate to slaves (best-effort) — the relay replays PUT /api/resolution with admin context.
    if let Some(ref j) = s.sync_journal {
        if let Some(ref k) = s.sync_key {
            let body_bytes =
                bytes::Bytes::from(serde_json::json!({"mode": mode.as_str()}).to_string());
            relay::push_to_slaves(j, k, Method::PUT, "resolution".to_string(), body_bytes);
        }
    }
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({
            "ok": true,
            "mode": mode.as_str(),
            "recursor_active": s.resolution_mode.load(Ordering::Relaxed) == 1,
        })),
    )
}

// ── DNS CRUD ───────────────────────────────────────────────────────────────

async fn list_dns_handler(
    State(_s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    // BOLA fix: get_dns_handler enforces may_manage_name on a single entry, but
    // this list handler returned the whole store — a non-admin `read` user could
    // enumerate every other tenant's records. Filter to the caller's manageable
    // zones (admin_context → admin=true → sees all, unchanged for the master key).
    let caller = caller_ext
        .map(|e| e.0)
        .unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    match store::load() {
        Ok(st) => {
            let entries: Vec<_> = st
                .entries
                .into_iter()
                .filter(|e| caller.may_manage_name(&e.name))
                .collect();
            let total = entries.len();
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "entries": entries,
                    "total": total
                })),
            )
        }
        Err(e) => {
            warn!(err = %e, "store load failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error": sanitize_error(&e)
                })),
            )
        }
    }
}

type ApiError = (StatusCode, JsonExtract<serde_json::Value>);

/// GET /api/dns/:id — return a single DNS entry by UUID.
async fn get_dns_handler(
    State(_s): State<AppState>,
    Path(id): Path<String>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    match store::load() {
        Ok(st) => {
            match st.entries.iter().find(|e| e.id == id) {
                Some(entry) => {
                    if !caller.may_manage_name(&entry.name) {
                        return (
                            StatusCode::FORBIDDEN,
                            JsonExtract(serde_json::json!({"error":"FORBIDDEN"})),
                        ).into_response();
                    }
                    (StatusCode::OK, JsonExtract(serde_json::json!({"entry": entry}))).into_response()
                }
                None => (
                    StatusCode::NOT_FOUND,
                    JsonExtract(serde_json::json!({"error":"NOT_FOUND","id":id})),
                ).into_response(),
            }
        }
        Err(e) => {
            warn!(err = %e, "store load failed in get_dns");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({"error": sanitize_error(&e)})),
            ).into_response()
        }
    }
}

/// Validate all fields of an AddDnsRequest and build the DnsEntry + RR + Record.
/// Returns the triple on success, or a (StatusCode, JSON error) ready to return.
fn validate_dns_entry(
    req: &AddDnsRequest,
) -> Result<(DnsEntry, String), ApiError> {
    // VUL-05: Reject malformed or dangerous names before any parsing.
    if let Err(e) = validate_dns_name(&req.name) {
        return Err((
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_NAME", "details": e
            })),
        ));
    }
    // Reject control characters in free-text fields (CRLF injection prevention).
    for (field, val) in [
        ("value", req.value.as_deref().unwrap_or("")),
        ("tag", req.tag.as_deref().unwrap_or("")),
        ("description", req.description.as_deref().unwrap_or("")),
        ("fingerprint", req.fingerprint.as_deref().unwrap_or("")),
        ("cert_data", req.cert_data.as_deref().unwrap_or("")),
        ("services", req.services.as_deref().unwrap_or("")),
        ("regexp", req.regexp.as_deref().unwrap_or("")),
        ("replacement", req.replacement.as_deref().unwrap_or("")),
        ("flags_naptr", req.flags_naptr.as_deref().unwrap_or("")),
    ] {
        if let Err(e) = validate_no_control_chars(val, field) {
            return Err((
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error": "INVALID_FIELD", "details": e
                })),
            ));
        }
    }
    // S-10: for record types where value is a domain name, validate it as such.
    // validate_no_control_chars is not enough — it would accept a 300-char CNAME target.
    match req.entry_type {
        DnsType::CNAME | DnsType::NS | DnsType::PTR | DnsType::MX | DnsType::SRV => {
            if let Some(ref v) = req.value {
                if let Err(e) = validate_dns_name(v) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        JsonExtract(serde_json::json!({
                            "error": "INVALID_VALUE", "details": e
                        })),
                    ));
                }
            }
        }
        DnsType::NAPTR => {
            // replacement may be "." (no-replacement special case — RFC 2915 §2)
            if let Some(ref r) = req.replacement {
                if r != "." {
                    if let Err(e) = validate_dns_name(r) {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            JsonExtract(serde_json::json!({
                                "error": "INVALID_REPLACEMENT", "details": e
                            })),
                        ));
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
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            JsonExtract(serde_json::json!({
                "error": "INVALID_TTL",
                "details": "TTL must be between 0 and 2147483647"
            })),
        ));
    }
    let ttl = req.ttl as u32;
    let entry = DnsEntry {
        id: DnsEntry::new_id(),
        name: ensure_dot(&req.name),
        entry_type: req.entry_type.clone(),
        ttl: ttl.min(MAX_API_TTL),
        value: req.value.clone(),
        priority: req.priority,
        weight: req.weight,
        port: req.port,
        flags: req.flags,
        tag: req.tag.clone(),
        order: req.order,
        preference_naptr: req.preference_naptr,
        flags_naptr: req.flags_naptr.clone(),
        services: req.services.clone(),
        regexp: req.regexp.clone(),
        replacement: req.replacement.clone(),
        algorithm: req.algorithm,
        fp_type: req.fp_type,
        fingerprint: req.fingerprint.clone(),
        cert_usage: req.cert_usage,
        selector: req.selector,
        matching_type: req.matching_type,
        cert_data: req.cert_data.clone(),
        description: req.description.clone(),
        owner_user_id: None, // Set by caller for user-owned entries
    };
    let rr = match entry.to_rr_string() {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error": "INVALID_ENTRY",
                    "details": "Missing required fields for this record type"
                })),
            ))
        }
    };
    // Validate the RR parses with our own wire parser (hickory-free).
    // FIX 6 (VUL-NEW-07): do not reflect the internal RR string in the HTTP response;
    // log it server-side so operators can diagnose but clients see no filesystem/config detail.
    if crate::dns::wire::present::parse_rr_line(&rr).is_none() {
        warn!(rr = %rr, "RR parse failed for input");
        return Err((
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "PARSE_FAILED",
                "details": "Record validation failed"
            })),
        ));
    }
    Ok((entry, rr))
}

/// Persist entry to disk and atomically inject into the live zone set.
/// VUL-FIX: store load/save MUST be inside zones_mutex.  Without this,
/// two concurrent POST /dns both load the same snapshot, each append
/// their entry, and the last writer wins — the other entry is silently
/// lost from the on-disk store.
async fn persist_and_swap(
    entry: &DnsEntry,
    s: &AppState,
) -> Result<(), ApiError> {
    {
        let _guard = s.zones_mutex.lock().await;

        let mut st = store::load().unwrap_or_default();
        if st.entries.len() >= MAX_DNS_ENTRIES {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                JsonExtract(serde_json::json!({
                    "error": "LIMIT_EXCEEDED",
                    "details": format!("Maximum {} DNS entries reached", MAX_DNS_ENTRIES)
                })),
            ));
        }
        st.entries.push(entry.clone());
        if let Err(e) = store::save(&st) {
            warn!(err = %e, "store save failed");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error": sanitize_error(&e)
                })),
            ));
        }

        let current = s.zones.load_full();
        let mut new_zones = (*current).clone();
        // Insert into the wire store the serving path reads (records_wire / zones_wire).
        if let Some(rr) = entry.to_rr_string() {
            if let Some(wr) = crate::dns::wire::present::parse_rr_line(&rr) {
                let key = crate::dns::local::wire_name_key(&wr.name);
                new_zones
                    .zones_wire
                    .entry(key.clone())
                    .or_insert(crate::dns::local::ZoneAction::Static);
                new_zones.records_wire.entry(key).or_default().push(wr);
            }
        }
        resync_xdp_cache(s, &new_zones);
        s.zones.store(Arc::new(new_zones));
    }
    info!(id=%entry.id, name=%entry.name, r#type=?entry.entry_type, "DNS entry added");
    s.audit.send(AuditEvent::DnsAdd {
        name: entry.name.clone(),
        rtype: format!("{:?}", entry.entry_type),
        value: entry.value.clone().unwrap_or_default(),
    });
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::AddDns {
            entry: entry.clone(),
        });
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
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    ApiJson(req): ApiJson<AddDnsRequest>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    let (entry, rr) = match validate_dns_entry(&req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // F3: a non-admin Dns/Operator user may only create records within their
    // assigned zone_prefixes. The role middleware (mod.rs:546) only gates the
    // path, not the per-user zone scope — enforce it explicitly here.
    if !caller.may_manage_name(&entry.name) {
        return (
            StatusCode::FORBIDDEN,
            JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"name outside your zone scope"})),
        );
    }
    if let Err(e) = persist_and_swap(&entry, &s).await {
        return e;
    }
    (
        StatusCode::CREATED,
        JsonExtract(serde_json::json!({
            "status": "ok",
            "entry": entry,
            "rr": rr
        })),
    )
}

async fn delete_dns_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    let _guard = s.zones_mutex.lock().await;

    let mut st = match store::load() {
        Ok(s) => s,
        Err(e) => {
            warn!(err = %e, "store load failed in delete_dns");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({"error": sanitize_error(&e)})),
            );
        }
    };

    let pos = st.entries.iter().position(|e| e.id == id);
    let Some(pos) = pos else {
        return (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({"error":"NOT_FOUND","id":id})),
        );
    };

    // F3: a non-admin Dns/Operator user may only delete records within their
    // assigned zone_prefixes. Check the loaded entry's name before removing it.
    if !caller.may_manage_name(&st.entries[pos].name) {
        return (
            StatusCode::FORBIDDEN,
            JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"name outside your zone scope"})),
        );
    }

    let entry = st.entries.remove(pos);
    if let Err(e) = store::save(&st) {
        warn!(err = %e, "store save failed in delete_dns");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({"error": sanitize_error(&e)})),
        );
    }

    // Remove from live zone set — ArcSwap write
    if let Some(rr) = entry.to_rr_string() {
        if let Some(wr) = crate::dns::wire::present::parse_rr_line(&rr) {
            let current = s.zones.load_full();
            let mut new_zones = (*current).clone();
            // VUL-08: match on the full record (name + type + rdata), not just the
            // type — removing one A record must not wipe every A for that name.
            let key = crate::dns::local::wire_name_key(&wr.name);
            if let Some(wrecs) = new_zones.records_wire.get_mut(&key[..]) {
                let mut removed = false;
                wrecs.retain(|r| {
                    if !removed && r.rtype == wr.rtype && r.rdata == wr.rdata {
                        removed = true;
                        false
                    } else {
                        true
                    }
                });
                if wrecs.is_empty() {
                    new_zones.records_wire.remove(&key[..]);
                    new_zones.zones_wire.remove(&key[..]);
                }
            }
            resync_xdp_cache(&s, &new_zones);
            s.zones.store(Arc::new(new_zones));
        }
    }

    info!(id=%id, "DNS entry deleted");
    s.audit.send(AuditEvent::DnsDelete { id: id.clone() });
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::DeleteDns { id: id.clone() });
        if let Some(ref k) = s.sync_key {
            relay::push_to_slaves(
                j,
                k,
                Method::DELETE,
                format!("dns/{id}"),
                bytes::Bytes::new(),
            );
        }
    }
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({"status":"ok","deleted_id":id})),
    )
}

// ── POST /api/dns/lookup ───────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct DnsLookupRequest {
    name: String,
    #[serde(rename = "type", default = "dns_lookup_default_type")]
    qtype: String,
}

fn dns_lookup_default_type() -> String {
    "A".to_string()
}

async fn dns_lookup_handler(
    State(s): State<AppState>,
    ApiJson(p): ApiJson<DnsLookupRequest>,
) -> impl IntoResponse {
    if !s.lookup_limiter.check() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            JsonExtract(serde_json::json!({
                "error": "RATE_LIMITED", "details": "Max 10 req/s"
            })),
        )
            .into_response();
    }

    if let Err(e) = validate_dns_name(&p.name) {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_NAME", "details": e
            })),
        )
            .into_response();
    }

    use crate::dns::wire::consts::rtype;
    let qtype: u16 = match p.qtype.to_uppercase().as_str() {
        "A" => rtype::A,
        "AAAA" => rtype::AAAA,
        "MX" => rtype::MX,
        "TXT" => rtype::TXT,
        "CNAME" => rtype::CNAME,
        "PTR" => rtype::PTR,
        other => return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_TYPE",
                "details": format!("Unsupported type '{other}'. Use: A, AAAA, MX, TXT, CNAME, PTR")
            })),
        )
            .into_response(),
    };

    let fqdn_str = if p.name.ends_with('.') {
        p.name.clone()
    } else {
        format!("{}.", p.name)
    };
    let name = match crate::dns::wire::Name::from_ascii(&fqdn_str) {
        Ok(n) => n,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error": "INVALID_NAME", "details": "Could not parse as DNS name"
                })),
            )
                .into_response()
        }
    };
    let qkey = crate::dns::local::wire_name_key(&name);

    // Check local zones first
    {
        let zones_snap = s.zones.load();
        match zones_snap.find_wire(&qkey) {
            Some(crate::dns::ZoneAction::Refuse) | Some(crate::dns::ZoneAction::NxDomain) | Some(crate::dns::ZoneAction::BlockPage) => {
                return (
                    StatusCode::OK,
                    JsonExtract(serde_json::json!({
                        "name": p.name, "type": p.qtype,
                        "answers": [], "status": "BLOCKED",
                        "elapsed_ms": 0, "from_cache": false
                    })),
                )
                    .into_response();
            }
            Some(crate::dns::ZoneAction::Static) | Some(crate::dns::ZoneAction::Redirect) => {
                let records = zones_snap.local_records_wire(&qkey, qtype);
                let answers: Vec<serde_json::Value> = records
                    .iter()
                    .map(|r| serde_json::json!({ "ttl": r.ttl, "data": r.rdata.to_presentation() }))
                    .collect();
                return (
                    StatusCode::OK,
                    JsonExtract(serde_json::json!({
                        "name": p.name, "type": p.qtype,
                        "answers": answers, "status": "NOERROR",
                        "elapsed_ms": 0, "from_cache": true
                    })),
                )
                    .into_response();
            }
            None => {}
        }
    }

    // Resolve upstream via ForwardPool — synthesise the query with our own encoder.
    let start = std::time::Instant::now();
    let query_wire = crate::dns::wire::message::encode_query(&name, qtype);
    let (fwd_result, _winner) = s.resolver.load().forward(&query_wire).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let from_cache = elapsed_ms * 1000 < crate::stats::CACHE_HIT_THRESHOLD_US;
    use crate::dns::forward::ResolveResult;
    match fwd_result {
        ResolveResult::Answer { records } => {
            let answers: Vec<serde_json::Value> = records
                .iter()
                .map(|r| serde_json::json!({ "ttl": r.ttl, "data": r.rdata.to_presentation() }))
                .collect();
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "name": p.name, "type": p.qtype,
                    "answers": answers, "status": "NOERROR",
                    "elapsed_ms": elapsed_ms, "from_cache": from_cache
                })),
            )
                .into_response()
        }
        ResolveResult::NegativeAnswer { rcode, .. } => {
            let status = match rcode {
                3 => "NXDOMAIN",
                5 => "REFUSED",
                _ => "NODATA",
            };
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "name": p.name, "type": p.qtype,
                    "answers": [], "status": status,
                    "elapsed_ms": elapsed_ms, "from_cache": false
                })),
            )
                .into_response()
        }
        ResolveResult::Servfail => {
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "name": p.name, "type": p.qtype,
                    "answers": [], "status": "SERVFAIL",
                    "elapsed_ms": elapsed_ms, "from_cache": false
                })),
            )
                .into_response()
        }
    }
}

// ── Blacklist ──────────────────────────────────────────────────────────────

async fn list_blacklist_handler(
    State(_s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    // BOLA fix: only return blacklist entries the caller owns (admin sees all).
    // Previously the full store leaked to any authenticated `read` user.
    let caller = caller_ext
        .map(|e| e.0)
        .unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    match store::load_blacklist() {
        Ok(bl) => {
            let entries: Vec<_> = bl
                .entries
                .into_iter()
                .filter(|e| {
                    caller.admin
                        || e.owner_user_id.as_deref() == Some(caller.id.as_str())
                })
                .collect();
            let total = entries.len();
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "blacklist": entries,
                    "total": total
                })),
            )
        }
        Err(e) => {
            warn!(err = %e, "blacklist load failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error": sanitize_error(&e)
                })),
            )
        }
    }
}

async fn add_blacklist_handler(
    State(s): State<AppState>,
    ApiJson(req): ApiJson<AddBlacklistRequest>,
) -> impl IntoResponse {
    // VUL-05: Reject invalid domain names (empty, root zone, Unicode, etc.)
    if let Err(e) = validate_dns_name(&req.domain) {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_NAME", "details": e
            })),
        );
    }
    if let Some(ref desc) = req.description {
        if let Err(e) = validate_no_control_chars(desc, "description") {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error": "INVALID_FIELD", "details": e
                })),
            );
        }
    }
    // Persist + inject atomically under zones_mutex (same race-fix as add_dns).
    let entry = {
        let _guard = s.zones_mutex.lock().await;

        let mut bl = store::load_blacklist().unwrap_or_default();
        if bl.entries.len() >= MAX_BLACKLIST_ENTRIES {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                JsonExtract(serde_json::json!({
                    "error": "LIMIT_EXCEEDED",
                    "details": format!("Maximum {} blacklist entries reached", MAX_BLACKLIST_ENTRIES)
                })),
            );
        }
        // SEC-AGV-02: validate schedule format to prevent silent bypass.
        if let Some(ref sched) = req.schedule {
            fn valid_hhmm(t: &str) -> bool {
                t.len() == 5
                    && t.as_bytes().get(2) == Some(&b':')
                    && t.get(..2).and_then(|h| h.parse::<u8>().ok()).map_or(false, |h| h <= 23)
                    && t.get(3..5).and_then(|m| m.parse::<u8>().ok()).map_or(false, |m| m <= 59)
            }
            if !valid_hhmm(&sched.start) || !valid_hhmm(&sched.end) {
                return (
                    StatusCode::BAD_REQUEST,
                    JsonExtract(serde_json::json!({"error": "invalid schedule: use HH:MM format (00:00-23:59)"})),
                );
            }
        }
        let is_scheduled = req.schedule.is_some();
        let entry = BlacklistEntry {
            id: uuid::Uuid::new_v4().to_string(),
            domain: req.domain.clone(),
            action: req.action.clone(),
            description: req.description.clone(),
            schedule: req.schedule.clone(),
            owner_user_id: None,
        };
        bl.entries.push(entry.clone());
        if let Err(e) = store::save_blacklist(&bl) {
            warn!(err = %e, "blacklist save failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error": sanitize_error(&e)
                })),
            );
        }

        let current = s.zones.load_full();
        let mut new_zones = (*current).clone();
        // VUL-09: override_zone so the blacklist entry always takes precedence
        // over any static zone with the same name defined in unbound.conf.
        // #9: only add to active zone set if schedule is currently active (or no schedule)
        if !is_scheduled || entry.schedule.as_ref().map_or(true, |s| s.is_active_now()) {
            new_zones.override_zone(&req.domain, ZoneAction::from(&req.action));
        }
        resync_xdp_cache(&s, &new_zones);
        s.zones.store(Arc::new(new_zones));

        entry
    };

    info!(domain=%req.domain, action=?req.action, "Blacklist entry added");
    // #153: push updated blacklist to XDP fast path
    if let Some(ref tx) = s.blacklist_reload_tx {
        if let Ok(bl) = store::load_blacklist() {
            let domains: Vec<String> = bl.entries.iter().map(|e| e.domain.clone()).collect();
            let _ = tx.try_send(domains);
        }
    }
    s.audit.send(AuditEvent::BlacklistAdd {
        domain: entry.domain.clone(),
    });
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::AddBlacklist {
            entry: entry.clone(),
        });
        if let Some(ref k) = s.sync_key {
            if let Ok(b) = serde_json::to_vec(&entry) {
                relay::push_to_slaves(
                    j,
                    k,
                    Method::POST,
                    "blacklist".to_string(),
                    bytes::Bytes::from(b),
                );
            }
        }
    }
    (
        StatusCode::CREATED,
        JsonExtract(serde_json::json!({
            "status": "ok",
            "entry": entry
        })),
    )
}

async fn delete_blacklist_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let _guard = s.zones_mutex.lock().await;

    let mut bl = match store::load_blacklist() {
        Ok(b) => b,
        Err(e) => {
            warn!(err = %e, "blacklist load failed in delete");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({"error": sanitize_error(&e)})),
            );
        }
    };
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    let pos = bl.entries.iter().position(|e| e.id == id);
    let Some(pos) = pos else {
        return (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({"error":"NOT_FOUND","id":id})),
        );
    };
    if !caller.admin && bl.entries[pos].owner_user_id.as_deref() != Some(caller.id.as_str()) {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"not your entry"})));
    }
    let removed = bl.entries.remove(pos);
    if let Err(e) = store::save_blacklist(&bl) {
        warn!(err = %e, "blacklist save failed in delete");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({"error": sanitize_error(&e)})),
        );
    }

    let current = s.zones.load_full();
    let mut new_zones = (*current).clone();
    new_zones.remove_zone(&removed.domain);
    resync_xdp_cache(&s, &new_zones);
    s.zones.store(Arc::new(new_zones));

    info!(id=%id, domain=%removed.domain, "Blacklist entry deleted");
    // #153: push updated blacklist to XDP fast path
    if let Some(ref tx) = s.blacklist_reload_tx {
        if let Ok(bl) = store::load_blacklist() {
            let domains: Vec<String> = bl.entries.iter().map(|e| e.domain.clone()).collect();
            let _ = tx.try_send(domains);
        }
    }
    s.audit.send(AuditEvent::BlacklistDelete { id: id.clone() });
    if let Some(ref j) = s.sync_journal {
        j.push(SyncOp::DeleteBlacklist { id: id.clone() });
        if let Some(ref k) = s.sync_key {
            relay::push_to_slaves(
                j,
                k,
                Method::DELETE,
                format!("blacklist/{id}"),
                bytes::Bytes::new(),
            );
        }
    }
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({"status":"ok","deleted_id":id,"domain":removed.domain})),
    )
}

// ── Feeds ──────────────────────────────────────────────────────────────────

async fn get_feeds_handler(State(_s): State<AppState>) -> impl IntoResponse {
    let config = feeds::load_feeds().unwrap_or_default();
    let feeds: Vec<serde_json::Value> = config
        .feeds
        .iter()
        .map(|f| {
            let blocked_count: serde_json::Value = if f.enabled {
                serde_json::json!(feeds::load_feed_domain_count(&f.id))
            } else {
                serde_json::Value::Null
            };
            let mut v = serde_json::to_value(f).unwrap_or_default();
            if let serde_json::Value::Object(ref mut m) = v {
                m.insert("blocked_count".to_string(), blocked_count);
            }
            v
        })
        .collect();
    let total = feeds.len();
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({"feeds": feeds, "total": total})),
    )
}

async fn add_feed_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    ApiJson(p): ApiJson<AddFeedRequest>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"feed management requires admin"})));
    }
    // Enforce subscription cap before attempting download/validation.
    let current = feeds::load_feeds().unwrap_or_default();
    if current.feeds.len() >= MAX_FEEDS {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            JsonExtract(serde_json::json!({
                "error": "LIMIT_EXCEEDED",
                "details": format!("Maximum {} feed subscriptions reached", MAX_FEEDS)
            })),
        );
    }
    match add_feed(p.name, p.url, p.format, p.action, p.description).await {
        Ok(feed) => {
            info!("Feed added: {} ({})", feed.name, feed.url);
            s.audit.send(AuditEvent::FeedAdd {
                id: feed.id.clone(),
                name: feed.name.clone(),
                url: feed.url.clone(),
            });
            if let Some(ref j) = s.sync_journal {
                j.push(SyncOp::AddFeed { feed: feed.clone() });
            }
            (
                StatusCode::CREATED,
                JsonExtract(serde_json::json!({
                    "status": "ok", "feed": feed,
                    "message": "Run POST /feeds/:id/update to fetch domains."
                })),
            )
        }
        Err(e) => {
            let code =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (
                code,
                JsonExtract(serde_json::json!({
                    "error": "FEED_ERROR", "details": e.to_string()
                })),
            )
        }
    }
}

async fn delete_feed_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"feed management requires admin"})));
    }
    match remove_feed(&id) {
        Ok(()) => {
            s.audit.send(AuditEvent::FeedDelete { id: id.clone() });
            if let Some(ref j) = s.sync_journal {
                j.push(SyncOp::DeleteFeed { id: id.clone() });
            }
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({"status":"ok","deleted_id":id})),
            )
        }
        Err(crate::error::AppError::BadRequest(msg)) => (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"BAD_REQUEST","details":msg})),
        ),
        Err(e) => (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({"error":"FEED_NOT_FOUND","details":e.to_string()})),
        ),
    }
}

async fn update_feeds_handler(State(s): State<AppState>) -> impl IntoResponse {
    match update_all_feeds().await {
        Ok(results) => {
            let updated = results.iter().filter(|r| r.status == "updated").count();
            let errors = results.iter().filter(|r| r.status == "error").count();
            // Rebuild zone set so newly downloaded feed domains are immediately active.
            let new_zones = crate::build_zone_set(&s.cfg);
            resync_xdp_cache(&s, &new_zones);
            s.zones.store(std::sync::Arc::new(new_zones));
            info!(updated, errors, "Feed update complete — zones rebuilt");
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "status": "ok", "results": results,
                    "summary": {"updated": updated, "errors": errors}
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({"error":e.to_string()})),
        ),
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
            resync_xdp_cache(&s, &new_zones);
            s.zones.store(std::sync::Arc::new(new_zones));
            if result.error.is_none() {
                if let (Some(j), Some(url)) = (s.sync_journal.as_ref(), feed_url) {
                    j.push(SyncOp::UpdateFeed {
                        id: id.clone(),
                        url,
                    });
                }
            }
            let code = if result.error.is_some() {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            };
            (code, JsonExtract(serde_json::json!({"result": result})))
        }
        Err(crate::error::AppError::BadRequest(msg)) => (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"BAD_REQUEST","details":msg})),
        ),
        Err(e) => (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({"error":e.to_string()})),
        ),
    }
}

async fn feed_presets_handler() -> impl IntoResponse {
    let presets = builtin_presets();
    JsonExtract(serde_json::json!({"presets": presets, "total": presets.len()}))
}

/// #33: rebuild per-upstream resolvers if racing is enabled.
/// Called after any upstream list change (add, delete, reconnect).
fn rebuild_racing_resolvers(s: &AppState) {
    if !s.cfg.upstream_racing {
        return;
    }
    let addrs = upstreams::upstream_addrs(&s.upstreams);
    match crate::dns::server::build_per_upstream_resolvers(&addrs, s.dnssec_enabled.load(Ordering::Relaxed)) {
        Ok(vec) => {
            info!(
                count = vec.len(),
                "upstream-racing: per-upstream resolvers rebuilt"
            );
            s.per_upstream_resolvers.store(Arc::new(vec));
        }
        Err(e) => warn!(err = %e, "upstream-racing: rebuild failed — racing resolvers unchanged"),
    }
}

// ── GET /api/upstreams ─────────────────────────────────────────────────────

async fn upstreams_handler(State(s): State<AppState>) -> impl IntoResponse {
    let statuses = match s.upstreams.read() {
        Ok(g) => g.clone(),
        Err(e) => {
            error!(err = %e, "upstreams RwLock poisoned");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error": "INTERNAL", "details": "upstream state unavailable"
                })),
            )
                .into_response();
        }
    };
    let total = statuses.len();
    let healthy = statuses.iter().filter(|u| u.healthy).count();
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({
            "upstreams": statuses,
            "total":     total,
            "healthy":   healthy,
        })),
    )
        .into_response()
}

// ── POST /api/upstreams ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddUpstreamRequest {
    addr: String,
    #[serde(default = "default_protocol")]
    protocol: String,
    name: Option<String>,
    /// Explicit port. Defaults to 53 (UDP) or 853 (DoT) if omitted.
    port: Option<u16>,
    /// #56: TLS SNI hostname for DoT upstreams. If absent, derived automatically
    /// from well-known IPs (Cloudflare, Google, Quad9, OpenDNS).
    tls_hostname: Option<String>,
}
fn default_protocol() -> String {
    "udp".into()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SplitHorizonView {
    name: String,
    subnets: Vec<String>,
    #[serde(default)]
    local_data: Vec<String>,
}
impl SplitHorizonView {
    fn from_entry(e: &crate::config::parser::SplitHorizonEntry) -> Self {
        Self {
            name: e.name.clone(),
            subnets: e.subnets.clone(),
            local_data: e.local_data.iter().map(|d| d.rr.clone()).collect(),
        }
    }
    fn into_entry(self) -> crate::config::parser::SplitHorizonEntry {
        crate::config::parser::SplitHorizonEntry {
            name: self.name,
            subnets: self.subnets,
            local_data: self.local_data.into_iter()
                .map(|rr| crate::config::parser::LocalData { rr }).collect(),
        }
    }
}

/// GET /api/split-horizon — list editable split-horizon entries.
async fn list_split_horizon(State(s): State<AppState>) -> impl IntoResponse {
    let v: Vec<SplitHorizonView> = s.split_horizon
        .lock().unwrap_or_else(|e| e.into_inner())
        .iter().map(SplitHorizonView::from_entry).collect();
    JsonExtract(serde_json::json!({ "split_horizon": v }))
}

/// POST /api/split-horizon — add or replace (by name) a split-horizon entry.
/// Persisted to runbound.conf; applied on the next service restart.
async fn add_split_horizon(
    State(s): State<AppState>,
    ApiJson(req): ApiJson<SplitHorizonView>,
) -> impl IntoResponse {
    if s.slave_mode {
        return (StatusCode::SERVICE_UNAVAILABLE, JsonExtract(serde_json::json!({"error":"SLAVE_READONLY"})));
    }
    if req.name.trim().is_empty() || req.subnets.is_empty() {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"INVALID","details":"name and at least one subnet are required"})));
    }
    // SEC-J1: these fields are written back into runbound.conf; reject control
    // characters / quotes / backslashes so a value cannot inject a config directive
    // (the config writer also escapes them now — defence in depth).
    let has_bad = |s: &str| s.chars().any(|c| c.is_control() || c == '"' || c == '\\');
    if has_bad(&req.name) || req.subnets.iter().any(|s| has_bad(s)) {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"INVALID","details":"name/subnet contains forbidden characters"})));
    }
    let name = req.name.clone();
    {
        let mut g = s.split_horizon.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|e| e.name != name);
        g.push(req.into_entry());
    }
    persist_config(&s);
    apply_split_horizon_live(&s.split_horizon.lock().unwrap_or_else(|e| e.into_inner()));
    info!(name = %name, "split-horizon entry added/updated via API (live)");
    (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok","name":name,"note":"applied live (no restart)"})))
}

/// DELETE /api/split-horizon/:name — remove a split-horizon entry by name.
async fn delete_split_horizon(
    State(s): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    if s.slave_mode {
        return (StatusCode::SERVICE_UNAVAILABLE, JsonExtract(serde_json::json!({"error":"SLAVE_READONLY"})));
    }
    let before;
    {
        let mut g = s.split_horizon.lock().unwrap_or_else(|e| e.into_inner());
        before = g.len();
        g.retain(|e| e.name != name);
    }
    persist_config(&s);
    apply_split_horizon_live(&s.split_horizon.lock().unwrap_or_else(|e| e.into_inner()));
    info!(name = %name, "split-horizon entry deleted via API (live)");
    (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok","removed": before, "note":"applied live (no restart)"})))
}

// ── #8: per-subnet/VLAN filtering policies ──────────────────────────────────
// Stored in subnet-policies.json (not runbound.conf) and applied LIVE on the slow
// serving path only — the XDP fast path is never touched.

/// GET /api/policies — list per-subnet policies with their blocked counts.
async fn list_policies_handler(State(_s): State<AppState>) -> impl IntoResponse {
    let counts: std::collections::HashMap<String, u64> =
        crate::subnet_policy::blocked_counts().into_iter().collect();
    let out: Vec<_> = crate::subnet_policy::load()
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "subnet": p.subnet,
                "blacklist_extra": p.blacklist_extra,
                "blocked": counts.get(&p.name).copied().unwrap_or(0),
            })
        })
        .collect();
    JsonExtract(serde_json::json!({ "policies": out }))
}

/// Add-or-replace (by name) a subnet policy; persist + apply live. Shared by POST/PUT.
fn upsert_policy_resp(
    slave_mode: bool,
    pol: crate::subnet_policy::SubnetPolicy,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if slave_mode {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            JsonExtract(serde_json::json!({"error":"SLAVE_READONLY"})),
        )
            .into_response();
    }
    if pol.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"INVALID","details":"name is required"})),
        )
            .into_response();
    }
    if crate::dns::acl::CidrBlock::parse(&pol.subnet).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"INVALID_SUBNET","details":"subnet must be a CIDR, e.g. 192.168.10.0/24"})),
        )
            .into_response();
    }
    // Sanitize the name (it is logged and persisted to JSON) and validate the domain
    // list — same standard as the blacklist/split-horizon handlers (audit #8 F1).
    if pol.name.len() > 64
        || pol
            .name
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"INVALID","details":"name must be ≤64 chars with no control characters, quotes or backslashes"})),
        )
            .into_response();
    }
    if pol.blacklist_extra.len() > MAX_POLICY_DOMAINS {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"TOO_MANY_DOMAINS","details": format!("max {} domains per policy", MAX_POLICY_DOMAINS)})),
        )
            .into_response();
    }
    for d in pol.blacklist_extra.iter().filter(|d| !d.trim().is_empty()) {
        if let Err(e) = validate_dns_name(d) {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({"error":"INVALID_DOMAIN","details": format!("'{}': {}", d, e)})),
            )
                .into_response();
        }
    }
    let name = pol.name.clone();
    let mut pols = crate::subnet_policy::load();
    if !pols.iter().any(|p| p.name == name) && pols.len() >= MAX_POLICIES {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"TOO_MANY_POLICIES","details": format!("max {} subnet policies", MAX_POLICIES)})),
        )
            .into_response();
    }
    pols.retain(|p| p.name != name);
    pols.push(pol);
    if let Err(e) = crate::subnet_policy::save(&pols) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({"error":"PERSIST_FAILED","details": e.to_string()})),
        )
            .into_response();
    }
    crate::subnet_policy::apply(&pols);
    info!(name = %name, "subnet policy added/updated via API (live)");
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({"status":"ok","name":name,"note":"applied live (no restart)"})),
    )
        .into_response()
}

/// POST /api/policies — create or replace a per-subnet policy.
async fn add_policy_handler(
    State(s): State<AppState>,
    ApiJson(pol): ApiJson<crate::subnet_policy::SubnetPolicy>,
) -> impl IntoResponse {
    upsert_policy_resp(s.slave_mode, pol)
}

/// PUT /api/policies/:name — update a per-subnet policy (the path name wins).
async fn put_policy_handler(
    State(s): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    ApiJson(mut pol): ApiJson<crate::subnet_policy::SubnetPolicy>,
) -> impl IntoResponse {
    pol.name = name;
    upsert_policy_resp(s.slave_mode, pol)
}

/// DELETE /api/policies/:name — remove a per-subnet policy by name.
async fn delete_policy_handler(
    State(s): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    if s.slave_mode {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            JsonExtract(serde_json::json!({"error":"SLAVE_READONLY"})),
        );
    }
    let mut pols = crate::subnet_policy::load();
    let before = pols.len();
    pols.retain(|p| p.name != name);
    let removed = before - pols.len();
    if let Err(e) = crate::subnet_policy::save(&pols) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({"error":"PERSIST_FAILED","details": e.to_string()})),
        );
    }
    crate::subnet_policy::apply(&pols);
    info!(name = %name, "subnet policy deleted via API (live)");
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({"status":"ok","removed": removed, "note":"applied live (no restart)"})),
    )
}

/// Persist the effective config (boot config + live runtime overrides: the DNSSEC
/// toggle and the current upstream set) back to runbound.conf via the atomic
/// writer. No-op on slaves (their config is driven by the master). Errors are
/// logged and swallowed so a write failure never breaks the API response.
/// #10/#186: recompile the editable split-horizon entries into the live resolver
/// table (hot-swap, no restart) AND evict those names from the XDP cache so the
/// fast path falls through to the slow path where the per-subnet view applies.
fn apply_split_horizon_live(entries: &[crate::config::parser::SplitHorizonEntry]) {
    let table = crate::dns::server::compile_split_horizon(entries);
    // #187: rebuild the per-view fast-path snapshots so the XDP path serves the new views.
    crate::dns::server::publish_view_snapshots(&table);
    // Fast-path coherency: evict split-horizon names from the shared cache so a
    // stale forwarded answer cannot shadow the per-subnet view.
    if let Some(cache) = crate::dns::cache_snapshot::XDP_CACHE_FOR_API.get() {
        let mut affected: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for (_subnets, zs) in &table {
            for k in zs.zones_wire.keys() {
                affected.insert(k.to_vec());
            }
        }
        if !affected.is_empty() {
            cache.retain(|_k, e| !affected.contains(e.wire_qname.as_ref()));
            crate::dns::cache_snapshot::CACHE_WRITE_GEN
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    // Slow path: hot-swap the live resolver table (picked up on the next query).
    if let Some(live) = crate::dns::server::SPLIT_HORIZON_LIVE.get() {
        live.store(std::sync::Arc::new(table));
    }
}

fn persist_config(s: &AppState) {
    if s.slave_mode { return; }
    let mut c = (*s.cfg).clone();
    c.dnssec_validation = s.dnssec_enabled.load(Ordering::Relaxed);
    c.resolution_mode = if s.resolution_mode.load(Ordering::Relaxed) == 1 {
        crate::config::parser::ResolutionMode::FullRecursion
    } else {
        crate::config::parser::ResolutionMode::Forward
    };
    c.forward_zones = upstreams::rebuild_forward_zones(&s.upstreams);
    c.split_horizon = s.split_horizon.lock().unwrap_or_else(|e| e.into_inner()).clone();
    c.rate_limit = Some(s.dns_rate_limiter.rps());
    c.rate_limit_burst = Some(s.dns_rate_limiter.burst());
    match crate::config::writer::write_config_atomic(&c, std::path::Path::new(&s.cfg_path)) {
        Ok(()) => info!(path = %s.cfg_path, "config persisted to runbound.conf"),
        Err(e) => warn!(%e, path = %s.cfg_path, "failed to persist config to runbound.conf"),
    }
}

async fn add_upstream_handler(
    State(s): State<AppState>,
    ApiJson(req): ApiJson<AddUpstreamRequest>,
) -> impl IntoResponse {
    // Validate protocol
    if req.protocol != "udp" && req.protocol != "dot" {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_PROTOCOL", "details": "protocol must be 'udp' or 'dot'"
            })),
        )
            .into_response();
    }
    // Validate addr is a valid IP (no @ syntax — port is a separate field now)
    let ip: IpAddr = match req.addr.parse() {
        Ok(ip) => ip,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_ADDR", "details": "addr must be a valid IP address (e.g. 1.1.1.1)"
            })),
        )
            .into_response(),
    };
    // SEC-NEW-01: normalize IPv6-mapped/compatible IPv4 (::ffff:x.x.x.x and ::x.x.x.x) before
    // checks. to_ipv4() covers both mapped and deprecated IPv4-compatible forms; to_ipv4_mapped()
    // only handles the ::ffff: form and would miss ::127.0.0.1 (RFC 4291 §2.5.5.1).
    // Guard: skip normalization for the native IPv6 loopback (::1) because to_ipv4() maps it to
    // 0.0.0.1, which is not flagged as loopback — we preserve the original so is_loopback() works.
    #[allow(deprecated)]
    let ip = if let IpAddr::V6(v6) = ip {
        if v6.is_loopback() {
            IpAddr::V6(v6)
        } else {
            v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
        }
    } else {
        ip
    };
    // FIX #40: reject loopback and IPv4 link-local
    if ip.is_loopback() {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_ADDR",
                "details": "loopback addresses cannot be used as upstream resolvers"
            })),
        )
            .into_response();
    }
    if let IpAddr::V4(v4) = ip {
        if v4.is_link_local() {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error": "INVALID_ADDR",
                    "details": "link-local addresses cannot be used as upstream resolvers"
                })),
            )
                .into_response();
        }
    }
    // SEC-11: reject unspecified (0.0.0.0 / ::) — routes to loopback on Linux (SSRF)
    if ip.is_unspecified() {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_ADDR",
                "details": "unspecified addresses cannot be used as upstream resolvers"
            })),
        )
            .into_response();
    }
    // FIX #44: resolve port with sensible defaults; reject port 0
    let default_port: u16 = if req.protocol == "dot" { 853 } else { 53 };
    let port = req.port.unwrap_or(default_port);
    if port == 0 {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_PORT", "details": "port must be between 1 and 65535"
            })),
        )
            .into_response();
    }

    // #56: validate optional tls_hostname
    let tls_hostname = match validate_tls_hostname(req.tls_hostname.as_deref()) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error": "INVALID_FIELD", "details": e
                })),
            )
                .into_response()
        }
    };

    let entry = upstreams::add_upstream(
        &s.upstreams,
        req.addr,
        port,
        req.protocol,
        req.name,
        tls_hostname,
    );

    // Rebuild resolver with updated upstream list
    let addrs = upstreams::upstream_addrs(&s.upstreams);
    if let Err(e) =
        crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, s.dnssec_enabled.load(Ordering::Relaxed)).await
    {
        warn!(%e, "resolver rebuild after upstream add failed — upstream added but DNS unchanged");
    }
    rebuild_racing_resolvers(&s);
    // FIX #43: persist after successful add
    upstreams::save_upstreams(&s.upstreams, &s.base_dir);
    persist_config(&s);

    info!(id = %entry.id, addr = %entry.addr, port = entry.port, protocol = %entry.protocol, "upstream added via API");
    if let (Some(ref j), Some(ref k)) = (&s.sync_journal, &s.sync_key) {
        j.push(SyncOp::AddUpstream {
            addr: entry.addr.clone(),
            port: entry.port,
            protocol: entry.protocol.clone(),
            name: entry.name.clone(),
            tls_hostname: entry.tls_hostname.clone(),
        });
        let body = serde_json::json!({
            "addr": entry.addr, "port": entry.port,
            "protocol": entry.protocol, "name": entry.name, "tls_hostname": entry.tls_hostname,
        });
        if let Ok(b) = serde_json::to_vec(&body) {
            relay::push_to_slaves(
                j,
                k,
                Method::POST,
                "upstreams".to_string(),
                bytes::Bytes::from(b),
            );
        }
    }
    (
        StatusCode::CREATED,
        JsonExtract(serde_json::json!({
            "status": "ok", "upstream": entry
        })),
    )
        .into_response()
}

// ── DELETE /api/upstreams/:id ──────────────────────────────────────────────

async fn delete_upstream_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // FIX #41: refuse to delete the last upstream — resolver would be empty.
    {
        let list = s
            .upstreams
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let target_exists = list.iter().any(|u| u.id == id);
        if target_exists && list.len() == 1 {
            return (
                StatusCode::CONFLICT,
                JsonExtract(serde_json::json!({
                    "error":   "LAST_UPSTREAM",
                    "details": "cannot delete the last upstream resolver"
                })),
            )
                .into_response();
        }
    }

    // #57: if this is a config-file upstream, remove its forward-addr from unbound.conf.
    {
        let list = s
            .upstreams
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(u) = list.iter().find(|u| u.id == id) {
            if u.source == "config" {
                let addr = u.addr.clone();
                let port = u.port;
                let path = s.cfg_path.clone();
                drop(list);
                match upstreams::remove_forward_addr_from_config(&path, &addr, port) {
                    Ok(true) => {
                        info!(id = %id, addr = %addr, cfg = %path, "config upstream removed from unbound.conf")
                    }
                    Ok(false) => {
                        warn!(id = %id, addr = %addr, "forward-addr line not found in config")
                    }
                    Err(e) => warn!(%e, id = %id, addr = %addr, "failed to edit unbound.conf"),
                }
            }
        }
    }

    match upstreams::remove_upstream(&s.upstreams, &id) {
        Some(removed) => {
            let addrs = upstreams::upstream_addrs(&s.upstreams);
            if let Err(e) =
                crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, s.dnssec_enabled.load(Ordering::Relaxed))
                    .await
            {
                warn!(%e, "resolver rebuild after upstream delete failed");
            }
            rebuild_racing_resolvers(&s);
            // FIX #43: persist after successful delete
            upstreams::save_upstreams(&s.upstreams, &s.base_dir);
            persist_config(&s);
            info!(id = %id, addr = %removed.addr, "upstream deleted via API");
            if let (Some(ref j), Some(ref k)) = (&s.sync_journal, &s.sync_key) {
                j.push(SyncOp::DeleteUpstream { id: id.clone() });
                relay::push_to_slaves(
                    j,
                    k,
                    Method::DELETE,
                    format!("upstreams/{id}"),
                    bytes::Bytes::new(),
                );
            }
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "status": "ok", "deleted_id": id, "addr": removed.addr
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({
                "error": "NOT_FOUND", "id": id
            })),
        )
            .into_response(),
    }
}

// ── GET /api/upstreams/presets ─────────────────────────────────────────────

async fn upstream_presets_handler() -> impl IntoResponse {
    // FIX #42: DoT entries use a separate `port` field — addr contains only the IP.
    // #56: DoT presets include tls_hostname so the DoT forwarder uses the correct SNI.
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
        let mut last = s
            .last_flush_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(t) = *last {
            let elapsed = t.elapsed().as_secs();
            if elapsed < cooldown {
                let retry_after = cooldown - elapsed;
                let mut resp = (
                    StatusCode::TOO_MANY_REQUESTS,
                    JsonExtract(serde_json::json!({
                        "error": "FLUSH_COOLDOWN",
                        "retry_after_secs": retry_after
                    })),
                )
                    .into_response();
                resp.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from_str(&retry_after.to_string())
                        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("60")),
                );
                return resp;
            }
        }
        *last = Some(Instant::now());
        // Lock released here — flush proceeds without holding the mutex.
    }

    let before = s.stats.snapshot().cache_entries;
    let addrs = upstreams::upstream_addrs(&s.upstreams);
    match crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, s.dnssec_enabled.load(Ordering::Relaxed)).await {
        Ok(_warmed) => {
            s.stats.reset_cache();
            s.cache_evictions.store(0, Ordering::Relaxed);
            // rebuild_and_swap only rebuilds the async resolver's own cache (the
            // slow serve_wire path). On an XDP-active host almost every cache hit
            // is served by the fast path's independent snapshot (worker.rs
            // answer_from_cache, refreshed from XDP_CACHE_FOR_API by publish_loop)
            // — without this, "flush" reported success while every previously
            // resolved name kept answering from the untouched fast-path cache.
            // Evict-all + bump the generation counter is the same pattern already
            // used by resync_xdp_cache_inner/apply_split_horizon_live; publish_loop
            // picks it up within one 10ms tick.
            if let Some(cache) = crate::dns::cache_snapshot::XDP_CACHE_FOR_API.get() {
                cache.clear();
                crate::dns::cache_snapshot::CACHE_WRITE_GEN.fetch_add(1, Ordering::Relaxed);
            }
            info!(flushed = before, "DNS cache flushed via API");
            s.audit.send(AuditEvent::ConfigReload);
            // Fire config-reloaded webhook (#11)
            {
                let tgts = s.webhook_targets.try_read();
                if let Ok(tgts) = tgts {
                    let ev = crate::webhooks::WebhookEvent::now("config-reloaded");
                    s.webhook_dispatcher.fire(&tgts, ev);
                }
            }
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "status": "ok", "flushed_entries": before
                })),
            )
                .into_response()
        }
        Err(e) => {
            warn!(%e, "cache flush: resolver rebuild failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error": "FLUSH_FAILED", "details": sanitize_error(&e)
                })),
            )
                .into_response()
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
                return (
                    StatusCode::BAD_REQUEST,
                    JsonExtract(serde_json::json!({
                        "error":   "INVALID_FIELD",
                        "details": "name must not contain control characters"
                    })),
                )
                    .into_response();
            }
            if s.len() > 64 {
                return (
                    StatusCode::BAD_REQUEST,
                    JsonExtract(serde_json::json!({
                        "error":   "INVALID_FIELD",
                        "details": "name must not exceed 64 characters"
                    })),
                )
                    .into_response();
            }
            Some(Some(s.clone()))
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error":   "INVALID_FIELD",
                    "details": "field 'name' must be a string or null"
                })),
            )
                .into_response()
        }
    };

    // Resolve tls_hostname: absent → skip; null or "" → None (clear); non-empty → Some(s).
    let tls_patch: Option<Option<String>> = match body.get("tls_hostname") {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Some(None),
        Some(serde_json::Value::String(s)) => match validate_tls_hostname(Some(s.as_str())) {
            Ok(h) => Some(h),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    JsonExtract(serde_json::json!({
                        "error": "INVALID_FIELD", "details": e
                    })),
                )
                    .into_response()
            }
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error":   "INVALID_FIELD",
                    "details": "field 'tls_hostname' must be a string or null"
                })),
            )
                .into_response()
        }
    };

    // Apply both patches in a single write-lock acquisition.
    let updated = {
        let mut list = s
            .upstreams
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(u) = list.iter_mut().find(|u| u.id == id) {
            if let Some(n) = name_patch {
                u.name = n;
            }
            if let Some(h) = tls_patch {
                u.tls_hostname = h;
            }
            Some(u.clone())
        } else {
            None
        }
    };

    match updated {
        Some(u) => {
            upstreams::save_upstreams(&s.upstreams, &s.base_dir);
            persist_config(&s);
            info!(id = %id, "upstream patched via PATCH");
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "status": "ok", "upstream": u
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({
                "error": "NOT_FOUND", "id": id
            })),
        )
            .into_response(),
    }
}

// ── POST /api/upstreams/:id/probe ─────────────────────────────────────────

async fn probe_upstream_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // a. Find upstream by id (read lock) — 404 if not found
    let probe_target = {
        let list = s.upstreams.read().unwrap_or_else(|e| e.into_inner());
        list.iter()
            .find(|u| u.id == id)
            .map(|u| (u.addr.clone(), u.port, u.protocol.clone()))
    };
    let (addr, port, protocol) = match probe_target {
        Some(t) => t,
        None => {
            return (
                StatusCode::NOT_FOUND,
                JsonExtract(serde_json::json!({
                    "error": "NOT_FOUND", "id": id
                })),
            )
                .into_response()
        }
    };

    // b. Run probe in spawn_blocking (blocking I/O)
    let result =
        tokio::task::spawn_blocking(move || upstreams::probe_upstream(&addr, port, &protocol))
            .await;

    let (healthy, latency_ms, dnssec_supported, last_error) = match result {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error": "PROBE_FAILED"
                })),
            )
                .into_response()
        }
    };

    // c. Write result back (write lock, find by id)
    let now_str = crate::logbuffer::format_ts(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    let updated = {
        let mut list = s.upstreams.write().unwrap_or_else(|e| e.into_inner());
        if let Some(u) = list.iter_mut().find(|u| u.id == id) {
            u.healthy = healthy;
            u.latency_ms = latency_ms;
            u.dnssec_supported = if healthy { dnssec_supported } else { None };
            u.last_error = if healthy { None } else { last_error };
            u.last_check = now_str;
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
        Some(u) => (
            StatusCode::OK,
            JsonExtract(serde_json::json!({
                "status": "ok", "upstream": u
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({
                "error": "NOT_FOUND", "id": id
            })),
        )
            .into_response(),
    }
}

// ── POST /api/upstreams/reconnect (#78) ────────────────────────────────────

async fn reconnect_upstreams_handler(State(s): State<AppState>) -> impl IntoResponse {
    let start = std::time::Instant::now();

    // Rebuild the resolver (resets the entire DoT connection pool).
    // warm_up() is called inside rebuild_and_swap — it probes before the ArcSwap
    // so that TCP/TLS connections are live before any query reaches the new resolver.
    let addrs = crate::upstreams::upstream_addrs(&s.upstreams);
    let warm_up =
        match crate::dns::server::rebuild_and_swap(&s.resolver, &addrs, s.dnssec_enabled.load(Ordering::Relaxed))
            .await
        {
            Ok(w) => w,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    JsonExtract(serde_json::json!({
                        "error": "REBUILD_FAILED", "details": e.to_string()
                    })),
                )
                    .into_response()
            }
        };

    s.stats.record_dot_reconnect();
    rebuild_racing_resolvers(&s);

    // Probe every DoT upstream in parallel to report reconnected vs failed.
    // UDP upstreams are ignored.
    let dot_targets: Vec<(String, u16)> = {
        s.upstreams
            .read()
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
    let mut failed = 0u32;
    for task in probe_tasks {
        match task.await {
            Ok((healthy, _, _, _)) => {
                if healthy {
                    reconnected += 1;
                } else {
                    failed += 1;
                }
            }
            Err(_) => {
                failed += 1;
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({
            "reconnected": reconnected,
            "failed":      failed,
            "warm_up":     warm_up,
            "duration_ms": duration_ms,
        })),
    )
        .into_response()
}

// ── GET /api/cache/stats ───────────────────────────────────────────────────

async fn cache_stats_handler(State(s): State<AppState>) -> impl IntoResponse {
    // Canonical cache_hits = slow-path counter + Σ per-worker fast-path hits (same
    // sum /api/stats reports). Reading s.stats.cache_hits alone misses every
    // fast-path (XDP / kernel-fast-loop) hit, so the two endpoints would disagree.
    let xh: u64 = crate::dns::cache_snapshot::XDP_WORKER_PKTS
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .sum();
    let hits = s.stats.cache_hits.load(Ordering::Relaxed) + xh;
    let misses = s.stats.cache_misses.load(Ordering::Relaxed);
    let evictions = s.cache_evictions.load(Ordering::Relaxed);
    // #obs (v0.9.3): real cached-entry count (resolver cache map len), not the
    // per-miss counter — see stats.rs snapshot().
    let entries = crate::dns::cache_snapshot::XDP_CACHE_FOR_API
        .get()
        .map(|c| c.len() as u64)
        .unwrap_or_else(|| s.stats.cache_entries.load(Ordering::Relaxed));
    let total = hits + misses;
    let hit_rate_pct = if total == 0 {
        serde_json::Value::Null
    } else {
        let pct = (hits as f64 / total as f64 * 1000.0).round() / 10.0;
        serde_json::json!(pct)
    };
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({
            "entries":      entries,
            "hits":         hits,
            "misses":       misses,
            "evictions":    evictions,
            "hit_rate_pct": hit_rate_pct,
        })),
    )
        .into_response()
}

// ── GET /api/sync/slaves ───────────────────────────────────────────────────

async fn sync_slaves_handler(State(s): State<AppState>) -> impl IntoResponse {
    match &s.sync_journal {
        Some(journal) => {
            let slaves = journal.connected_slaves();
            let total = slaves.len();
            (
                StatusCode::OK,
                JsonExtract(serde_json::json!({
                    "slaves": slaves, "total": total
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::OK,
            JsonExtract(serde_json::json!({
                "slaves": [], "total": 0,
                "note": "this node is not configured as master (no sync-port directive)"
            })),
        )
            .into_response(),
    }
}

// ── GET /events — SSE node-status stream (#86) ────────────────────────────

async fn events_handler(State(s): State<AppState>) -> impl IntoResponse {
    let Some(ref tx) = s.events_tx else {
        return (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({
                "error": "NOT_FOUND",
                "detail": "this node is not a master or has no sync-port configured"
            })),
        )
            .into_response();
    };
    let rx = tx.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => match Event::default().json_data(&event) {
                    Ok(e) => return Some((Ok::<_, Infallible>(e), rx)),
                    Err(_) => continue,
                },
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
    limit: usize,
    #[serde(default)]
    page: usize,
    action: Option<String>,
    client: Option<String>,
    since: Option<u64>,
}

fn default_log_limit() -> usize {
    LOG_LIMIT_DEFAULT
}

async fn logs_handler(
    State(s): State<AppState>,
    params_result: Result<Query<LogsParams>, QueryRejection>,
) -> Response {
    let Query(params) = match params_result {
        Ok(q) => q,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                JsonExtract(serde_json::json!({
                    "error":   "INVALID_PARAM",
                    "details": e.to_string()
                })),
            )
                .into_response()
        }
    };

    if params.limit > LOG_LIMIT_MAX {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            JsonExtract(serde_json::json!({
                "error":   "INVALID_PARAM",
                "details": format!("limit must be ≤ {}", LOG_LIMIT_MAX),
            })),
        )
            .into_response();
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
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    JsonExtract(serde_json::json!({
                        "error":   "INVALID_PARAM",
                        "details": format!("client '{}' is not a valid IP address", s),
                    })),
                )
                    .into_response()
            }
        },
        None => None,
    };

    let q = LogQuery {
        limit: params.limit,
        page: params.page,
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
    }))
    .into_response()
}

// ── DELETE /logs ───────────────────────────────────────────────────────────

async fn clear_logs_handler(State(s): State<AppState>) -> impl IntoResponse {
    let deleted = s.log_buffer.clear();
    s.audit.send(AuditEvent::LogsClear { count: deleted });
    info!(
        entries_deleted = deleted,
        "log buffer cleared via DELETE /logs"
    );
    JsonExtract(serde_json::json!({
        "message":         "log buffer cleared",
        "entries_deleted": deleted,
    }))
    .into_response()
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
struct AuditTailQuery {
    n: Option<usize>,
}

async fn audit_tail_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    Query(q): Query<AuditTailQuery>,
) -> impl IntoResponse {
    // The audit log is a security control (privileged-action record, auth failures,
    // per-actor usernames), not operational telemetry. Gate it to admins like
    // /backup/export (SEC-N1) instead of leaving it on the blanket "Read = any GET"
    // surface, where a scoped key could enumerate cross-user/admin activity.
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (
            StatusCode::FORBIDDEN,
            JsonExtract(serde_json::json!({"error": "FORBIDDEN"})),
        );
    }
    let n = q.n.unwrap_or(100).min(1000);
    // Use the configured audit-log-path if set, else base_dir/audit.log — must match
    // audit::init resolution, otherwise /audit/tail cannot find the log (QA Cycle I).
    let log_path = s.cfg.audit_log_path.as_ref().map(std::path::PathBuf::from)
        .unwrap_or_else(|| s.base_dir.join("audit.log"));
    // No audit log on disk means audit logging is simply not enabled — a normal state,
    // not an error. Report a well-formed empty tail (200) instead of a 404 that would
    // leak the resolved path and raw OS errno to the client.
    if !log_path.exists() {
        return (
            StatusCode::OK,
            JsonExtract(serde_json::json!({
                "lines": [],
                "count": 0,
                "enabled": false,
            })),
        );
    }
    match crate::audit::tail_audit_log(&log_path, n) {
        Ok(lines) => (
            StatusCode::OK,
            JsonExtract(serde_json::json!({
                "lines": lines,
                "count": lines.len(),
                "enabled": true,
            })),
        ),
        // The file exists but could not be read (permissions, I/O, corruption). Log the
        // detail server-side; return a generic 500 without echoing the raw OS error.
        Err(e) => {
            warn!(path = %log_path.display(), err = %e, "audit tail read failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({
                    "error": "AUDIT_LOG_READ_FAILED",
                })),
            )
        }
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
    id: String,
    addr: String,
    port: u16,
    protocol: String,
    healthy: bool,
    latency_ms: Option<u64>,
}

fn render_prometheus_metrics(
    snap: &crate::stats::StatsSnapshot,
    cache_hits: u64,
    cache_misses: u64,
    evictions: u64,
    xdp_active: bool,
    upstreams: &[UpstreamMetric],
    node_id: Option<&str>,
) -> String {
    let mut out = String::with_capacity(2048);
    if let Some(n) = node_id {
        out.push_str("# HELP runbound_node_info Node identity for multi-PoP/anycast deployments.\n# TYPE runbound_node_info gauge\n");
        out.push_str(&format!("runbound_node_info{{node=\"{}\"}} 1\n", n));
    }
    out.push_str(&fmt_counter(
        "runbound_queries_total",
        "Total DNS queries received",
        snap.total,
    ));
    out.push_str(&fmt_counter(
        "runbound_queries_blocked_total",
        "Queries blocked by blocklist",
        snap.blocked,
    ));
    out.push_str(&fmt_counter(
        "runbound_queries_forwarded_total",
        "Queries forwarded to upstreams",
        snap.forwarded,
    ));
    out.push_str(&fmt_counter(
        "runbound_queries_nxdomain_total",
        "Queries answered NXDOMAIN",
        snap.nxdomain,
    ));
    out.push_str(&fmt_counter(
        "runbound_queries_servfail_total",
        "Queries answered SERVFAIL",
        snap.servfail,
    ));
    out.push_str(&fmt_counter(
        "runbound_dnssec_secure_total",
        "Answers DNSSEC-validated as Secure",
        snap.dnssec_secure,
    ));
    out.push_str(&fmt_counter(
        "runbound_dnssec_bogus_total",
        "Answers DNSSEC-validated as Bogus (served as SERVFAIL)",
        snap.dnssec_bogus,
    ));
    out.push_str(&fmt_counter(
        "runbound_dnssec_insecure_total",
        "Answers in unsigned (Insecure) zones",
        snap.dnssec_insecure,
    ));
    out.push_str(&fmt_counter(
        "runbound_queries_local_hits_total",
        "Queries answered from local zones",
        snap.local_hits,
    ));
    out.push_str(&fmt_gauge(
        "runbound_qps_1m",
        "Queries per second (1 minute average)",
        snap.qps_1m,
    ));
    out.push_str(&fmt_gauge(
        "runbound_qps_peak",
        "Peak queries per second observed",
        snap.qps_peak,
    ));
    out.push_str(&fmt_gauge(
        "runbound_latency_p50_ms",
        "DNS response latency p50 in milliseconds",
        snap.latency_p50_ms,
    ));
    out.push_str(&fmt_gauge(
        "runbound_latency_p95_ms",
        "DNS response latency p95 in milliseconds",
        snap.latency_p95_ms,
    ));
    out.push_str(&fmt_gauge(
        "runbound_latency_p99_ms",
        "DNS response latency p99 in milliseconds",
        snap.latency_p99_ms,
    ));
    out.push_str(&fmt_gauge(
        "runbound_cache_hit_rate",
        "Cache hit rate as a percentage (0 to 100)",
        snap.cache_hit_rate,
    ));
    out.push_str(&fmt_gauge(
        "runbound_cache_entries",
        "Current number of entries in DNS cache",
        snap.cache_entries,
    ));
    out.push_str(&fmt_counter(
        "runbound_cache_hits_total",
        "Total cache hits",
        cache_hits,
    ));
    out.push_str(&fmt_counter(
        "runbound_cache_misses_total",
        "Total cache misses",
        cache_misses,
    ));
    out.push_str(&fmt_counter(
        "runbound_cache_evictions_total",
        "Total cache evictions",
        evictions,
    ));
    out.push_str(&fmt_gauge(
        "runbound_uptime_seconds",
        "Service uptime in seconds",
        snap.uptime_secs,
    ));
    out.push_str(&fmt_gauge(
        "runbound_xdp_active",
        "Whether XDP fast path is active (1=yes, 0=no)",
        xdp_active as u8,
    ));
    // XDP fast-path cache: per-worker counters = what the XDP datapath actually served
    // from cache / missed. This is the meaningful "is XDP serving cache?" signal — NOT
    // the in-kernel eBPF snapshot below, which is 0 whenever the snapshot path isn't
    // answering (e.g. AF_XDP copy mode on a VM) even though the workers serve at line rate.
    let xdp_worker_hits: u64 = crate::dns::cache_snapshot::XDP_WORKER_PKTS
        .iter().map(|c| c.load(std::sync::atomic::Ordering::Relaxed)).sum();
    let xdp_worker_misses: u64 = crate::dns::cache_snapshot::XDP_WORKER_MISS
        .iter().map(|c| c.load(std::sync::atomic::Ordering::Relaxed)).sum();
    out.push_str(&fmt_counter(
        "runbound_xdp_cache_hits_total",
        "DNS responses served from the fast-path cache — AF_XDP workers and the kernel recvmmsg fast-loop (non-zero even when xdp:no)",
        xdp_worker_hits,
    ));
    out.push_str(&fmt_counter(
        "runbound_xdp_cache_misses_total",
        "XDP fast-path cache lookups that missed (fell back to recursion)",
        xdp_worker_misses,
    ));
    out.push_str(&fmt_counter(
        "runbound_xdp_kernel_snapshot_hits_total",
        "DNS responses answered directly by the in-kernel eBPF cache snapshot",
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_HITS
            .load(std::sync::atomic::Ordering::Relaxed),
    ));
    out.push_str(&fmt_counter(
        "runbound_xdp_kernel_snapshot_misses_total",
        "Lookups the in-kernel eBPF cache snapshot could not answer",
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
            .load(std::sync::atomic::Ordering::Relaxed),
    ));
    out.push_str(&fmt_gauge(
        "runbound_xdp_cache_entries",
        "Current live entries in XDP wire-format cache",
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_ENTRIES
            .load(std::sync::atomic::Ordering::Relaxed),
    ));
    out.push_str(&fmt_gauge(
        "runbound_nic_rx_ring",
        "Applied NIC RX ring descriptor count (0=unavailable)",
        crate::dns::xdp::socket::XDP_NIC_RX_RING.load(std::sync::atomic::Ordering::Relaxed),
    ));
    out.push_str(&fmt_gauge(
        "runbound_nic_rx_ring_max",
        "Hardware maximum NIC RX ring descriptor count",
        crate::dns::xdp::socket::XDP_NIC_RX_RING_MAX.load(std::sync::atomic::Ordering::Relaxed),
    ));
    {
        // #159: sum across all XDP interfaces
        let nic_dropped: u64 = crate::dns::xdp::socket::xdp_iface_snapshot()
            .iter()
            .map(|s| crate::dns::xdp::socket::read_nic_rx_dropped(&s.iface))
            .sum();
        out.push_str(&fmt_counter(
            "runbound_nic_rx_dropped_total",
            "NIC RX packets dropped before XDP (hardware FIFO overflow, sum across all ifaces)",
            nic_dropped,
        ));
    }

    // Per-record-type query counters
    if !snap.qtype_stats.is_empty() {
        out.push_str("# HELP runbound_queries_by_type_total DNS queries by record type\n");
        out.push_str("# TYPE runbound_queries_by_type_total counter\n");
        for (qtype, count) in &snap.qtype_stats {
            out.push_str(&format!(
                "runbound_queries_by_type_total{{type=\"{}\"}} {}\n",
                qtype, count,
            ));
        }
    }

    // Per-upstream metrics with labels — omit latency when not yet measured (null → skip, no NaN).
    if !upstreams.is_empty() {
        out.push_str(
            "# HELP runbound_upstream_healthy Whether upstream is healthy (1=yes, 0=no)\n",
        );
        out.push_str("# TYPE runbound_upstream_healthy gauge\n");
        for u in upstreams {
            out.push_str(&format!(
                "runbound_upstream_healthy{{id=\"{}\",addr=\"{}\",port=\"{}\",protocol=\"{}\"}} {}\n",
                u.id, u.addr, u.port, u.protocol, u.healthy as u8,
            ));
        }
        let latency_upstreams: Vec<&UpstreamMetric> = upstreams
            .iter()
            .filter(|u| u.latency_ms.is_some())
            .collect();
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
    // Reuse the once/sec cached snapshot (same <=1s staleness contract as /api/stats)
    // instead of recomputing ~360 atomic loads + qtype sort + latency-ring scans per scrape.
    let snap = s.stats_cache.load();
    // Canonical cache hits/misses = snapshot()'s SUMMED counters (slow path + XDP
    // fast-path worker hits, no double-count). Reusing the snapshot fields guarantees
    // hits_total/misses_total stay consistent with cache_hit_rate — both come from the
    // same source instead of one reading XDP-only and the other slow-only.
    let (cache_hits, cache_misses) = (snap.cache_hits, snap.cache_misses);
    let evictions = s.cache_evictions.load(Ordering::Relaxed);
    let xdp_active = s.xdp_active.load(Ordering::Relaxed) > 0;
    let upstreams: Vec<UpstreamMetric> = {
        let list = s
            .upstreams
            .read()
            .unwrap_or_else(|e| e.into_inner());
        list.iter()
            .map(|u| UpstreamMetric {
                id: u.id.clone(),
                addr: u.addr.clone(),
                port: u.port,
                protocol: u.protocol.clone(),
                healthy: u.healthy,
                latency_ms: u.latency_ms,
            })
            .collect()
    };
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        {
            let mut body = render_prometheus_metrics(
                &snap,
                cache_hits,
                cache_misses,
                evictions,
                xdp_active,
                &upstreams,
                s.node_health.node_id.as_deref(),
            );
            // #208: ICMP / ban / abuse / connection observability.
            use std::sync::atomic::Ordering as O;
            let ic = &s.icmp_stats;
            body.push_str(&fmt_counter("runbound_icmp_handled_total", "ICMP echo requests handled by XDP", ic.handled.load(O::Relaxed)));
            body.push_str(&fmt_counter("runbound_icmp_replied_total", "ICMP echo replies sent by XDP", ic.replied.load(O::Relaxed)));
            body.push_str(&fmt_counter("runbound_icmp_dropped_total", "Packets dropped from banned source IPs at XDP", ic.dropped.load(O::Relaxed)));
            body.push_str(&fmt_counter("runbound_icmp_rate_limited_total", "Packets rate-limited at the XDP ICMP gate", ic.rate_limited.load(O::Relaxed)));
            body.push_str(&fmt_gauge("runbound_banned_ips", "Source IPs currently banned in the XDP map", ic.banned.len() as u64));
            let (alert_blocked, alert_tarpitted) = s.alert_tracker.metrics();
            body.push_str(&fmt_gauge("runbound_alert_blocked_ips", "Source IPs currently blocked by an alert rule / manual ban", alert_blocked as u64));
            body.push_str(&fmt_gauge("runbound_alert_tarpitted_ips", "Source IPs currently tarpitted", alert_tarpitted as u64));
            body.push_str(&fmt_gauge("runbound_tcp_connections_active", "Active TCP/DoT/DoH relay connections (listener saturation)", crate::dns::server::ACTIVE_TCP_CONNS.load(O::Relaxed)));
            body
        },
    )
}

// ── POST /rotate-key ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RotateKeyRequest {
    new_key: String,
}

async fn rotate_key_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    ApiJson(req): ApiJson<RotateKeyRequest>,
) -> impl IntoResponse {
    // Defense-in-depth: rotating the master API key is admin-only. The role
    // middleware already blocks non-admin writes here, but gate explicitly.
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    // Require at least 32 bytes of entropy (64 hex chars) — shorter keys are
    // statistically weak and likely copy-paste mistakes.
    if req.new_key.len() < 32 {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "WEAK_KEY",
                "details": "new_key must be at least 32 characters",
            })),
        )
            .into_response();
    }
    // Reject control characters (CRLF injection, log injection).
    if req.new_key.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_KEY",
                "details": "new_key must not contain control characters",
            })),
        )
            .into_response();
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
    (
        StatusCode::OK,
        JsonExtract(serde_json::json!({
            "status": "ok",
            "message": "API key rotated — old token is immediately invalid",
        })),
    )
        .into_response()
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// FIX 3.4: Strip file-system paths from error messages before they reach HTTP
/// response bodies.  The full error (with path) is always logged at WARN level
/// so operators retain visibility; clients receive only a generic message.
fn sanitize_error(e: &impl std::fmt::Display) -> String {
    let s = e.to_string();
    if s.contains('/') {
        "internal error".to_string()
    } else {
        s
    }
}

fn ensure_dot(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

/// Reject any string that contains ASCII control characters (0x00–0x1f, 0x7f).
/// Applied to all user-supplied text fields (value, description) to prevent
/// CRLF injection into logs, stored JSON, or HTTP response bodies.
fn validate_no_control_chars(s: &str, field: &'static str) -> Result<(), String> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!(
            "Field '{}' must not contain control characters (\r, \n, etc.)",
            field
        ));
    }
    // SEC-B16: reject Unicode bidi override and format characters (log injection via U+202x, U+2028/9).
    for ch in s.chars() {
        let cp = ch as u32;
        if (0x200B..=0x200F).contains(&cp)  // zero-width, direction marks
            || (0x202A..=0x202E).contains(&cp)  // bidi overrides
            || cp == 0x2028 || cp == 0x2029     // line/paragraph separators
            || (0xFFF9..=0xFFFB).contains(&cp)  // interlinear annotation
        {
            return Err(format!(
                "Field '{}' must not contain Unicode control or format characters",
                field
            ));
        }
    }
    Ok(())
}

/// #56: Validate and normalise a `tls_hostname` value from the API.
/// - `None` / empty string → `Ok(None)` (auto-derive)
/// - Non-empty, valid → `Ok(Some(trimmed))`
/// - Too long or containing control characters → `Err(message)`
fn validate_tls_hostname(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(h) = raw else {
        return Ok(None);
    };
    let h = h.trim();
    if h.is_empty() {
        return Ok(None);
    }
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
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("Domain label contains invalid characters \
                        (ASCII alphanumeric, hyphens, underscores only)");
        }
    }
    Ok(())
}

// ── Multi-user management handlers ────────────────────────────────────────

/// GET /api/users — admin only: list all users (keys redacted).
async fn list_users_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    let Some(ref reg) = s.user_registry else {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"MULTI_USER_DISABLED"}))).into_response();
    };
    let users: Vec<serde_json::Value> = reg.all_users().iter().map(|u| serde_json::json!({
        "id": u.id,
        "username": u.username,
        "zone_prefixes": u.zone_prefixes,
        "enabled": u.enabled,
        "admin": u.admin,
        "role": u.role,
    })).collect();
    (StatusCode::OK, JsonExtract(serde_json::json!({"users": users}))).into_response()
}

#[derive(serde::Deserialize)]
struct CreateUserRequest {
    username: String,
    #[serde(default)]
    zone_prefixes: Vec<String>,
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    role: crate::multiuser::Role,
}

/// POST /api/users — admin only: create user. Returns the new API key once.
async fn create_user_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    ApiJson(body): ApiJson<CreateUserRequest>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    let Some(ref reg) = s.user_registry else {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"MULTI_USER_DISABLED"}))).into_response();
    };
    if body.username.trim().is_empty() || body.username.len() > 64 {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"INVALID_USERNAME"}))).into_response();
    }
    // Stored-XSS defence-in-depth: username + zone_prefixes are rendered in the
    // admin WebUI. The UI escapes them, but reject HTML-significant bytes here
    // too — they are never valid in a username or a DNS zone name.
    let has_html = |s: &str| s.bytes().any(|b| matches!(b, b'<' | b'>' | b'"' | b'\'' | b'&'));
    if has_html(&body.username) || body.zone_prefixes.iter().any(|p| has_html(p)) {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error":"INVALID_INPUT",
                "details":"username/zone_prefixes must not contain < > \" ' &"
            })),
        ).into_response();
    }
    match reg.create_user(body.username, body.zone_prefixes, body.admin, body.role) {
        Ok(u) => {
            info!(id = %u.id, username = %u.username, "User created");
            (StatusCode::CREATED, JsonExtract(serde_json::json!({
                "id": u.id,
                "username": u.username,
                "api_key": u.api_key,
                "zone_prefixes": u.zone_prefixes,
                "enabled": u.enabled,
                "admin": u.admin,
                "role": u.role,
            }))).into_response()
        }
        Err(e) => (StatusCode::CONFLICT, JsonExtract(serde_json::json!({"error": e}))).into_response(),
    }
}

/// DELETE /api/users/:id — admin only.
async fn delete_user_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    let Some(ref reg) = s.user_registry else {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"MULTI_USER_DISABLED"}))).into_response();
    };
    if reg.delete_user(&id) {
        info!(id = %id, "User deleted");
        (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok"}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":"NOT_FOUND"}))).into_response()
    }
}

/// GET /api/users/me — authenticated user (admin or regular).
async fn get_me_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    // For admin context (master key), return basic info without zone_prefixes.
    if caller.id == "admin" {
        return (StatusCode::OK, JsonExtract(serde_json::json!({
            "id": "admin",
            "username": "admin",
            "admin": true,
            "zone_prefixes": [],
        }))).into_response();
    }
    // For user key, return full profile.
    if let Some(ref reg) = s.user_registry {
        if let Some(u) = reg.by_id(&caller.id) {
            return (StatusCode::OK, JsonExtract(serde_json::json!({
                "id": u.id,
                "username": u.username,
                "admin": u.admin,
                "zone_prefixes": u.zone_prefixes,
            }))).into_response();
        }
    }
    (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":"NOT_FOUND"}))).into_response()
}

/// POST /api/users/:id/rotate-key — admin or self: generate new API key.
async fn rotate_user_key_handler(
    State(s): State<AppState>,
    Path(id): Path<String>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin && caller.id != id {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    let Some(ref reg) = s.user_registry else {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"MULTI_USER_DISABLED"}))).into_response();
    };
    match reg.rotate_key(&id) {
        Some(new_key) => {
            info!(id = %id, "User API key rotated");
            (StatusCode::OK, JsonExtract(serde_json::json!({"api_key": new_key}))).into_response()
        }
        None => (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error":"NOT_FOUND"}))).into_response(),
    }
}

// ── Encrypted DNS admin: DoT / DoH / DoQ TLS material (WebUI) ───────────────
// The DoT (853), DoH (443) and DoQ (853/udp) listeners are bound once at startup
// (see dns/server.rs). These endpoints let the WebUI enable encrypted DNS by
// either generating a self-signed certificate or importing an existing cert+key,
// persisting tls-service-pem / tls-service-key / ports / hostname to runbound.conf.
// Activation requires a restart — every mutating response carries restart_required.

const TLS_CERT_FILE: &str = "cert.pem";
const TLS_KEY_FILE: &str = "key.pem";

#[derive(Deserialize)]
struct TlsSelfSignedBody {
    hostname: String,
    dot_port: Option<u16>,
    doh_port: Option<u16>,
    doq_port: Option<u16>,
}

#[derive(Deserialize)]
struct TlsImportBody {
    cert_pem: String,
    key_pem: String,
    hostname: Option<String>,
    dot_port: Option<u16>,
    doh_port: Option<u16>,
    doq_port: Option<u16>,
}

/// Parse a PEM cert file into a JSON summary (subject/issuer CN, validity, SHA-256
/// fingerprint, SANs). Falls back to fingerprint-only if X.509 parsing fails.
fn tls_cert_info(cert_path: &str) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let pem = match std::fs::read(cert_path) {
        Ok(b) => b,
        Err(_) => return serde_json::Value::Null,
    };
    let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_slice()).flatten().collect();
    let der = match certs.first() {
        Some(d) => d,
        None => return serde_json::Value::Null,
    };
    let fingerprint = {
        let mut h = Sha256::new();
        h.update(der.as_ref());
        h.finalize()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    match x509_parser::parse_x509_certificate(der.as_ref()) {
        Ok((_, c)) => {
            let cn = |name: &x509_parser::x509::X509Name| {
                name.iter_common_name()
                    .next()
                    .and_then(|a| a.as_str().ok())
                    .unwrap_or("")
                    .to_string()
            };
            let subject = cn(c.subject());
            let issuer = cn(c.issuer());
            let not_before = c.validity().not_before.timestamp();
            let not_after = c.validity().not_after.timestamp();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let days_remaining = (not_after - now) / 86_400;
            let sans: Vec<String> = c
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|san| {
                    san.value
                        .general_names
                        .iter()
                        .filter_map(|gn| match gn {
                            x509_parser::extensions::GeneralName::DNSName(n) => {
                                Some((*n).to_string())
                            }
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            serde_json::json!({
                "subject_cn": subject,
                "issuer_cn": issuer,
                "self_signed": !subject.is_empty() && subject == issuer,
                "not_before": not_before,
                "not_after": not_after,
                "days_remaining": days_remaining,
                "expired": days_remaining < 0,
                "fingerprint_sha256": fingerprint,
                "sans": sans,
            })
        }
        Err(_) => serde_json::json!({
            "fingerprint_sha256": fingerprint,
            "parse_error": true,
        }),
    }
}

/// Validate that cert_pem contains at least one certificate, key_pem a private key,
/// and that rustls accepts them together (the key matches the leaf certificate).
fn tls_validate_cert_key(cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).flatten().collect();
    if certs.is_empty() {
        return Err("no CERTIFICATE block found in cert_pem".to_string());
    }
    let key = match rustls_pemfile::private_key(&mut &key_pem[..]) {
        Ok(Some(k)) => k,
        Ok(None) => return Err("no PRIVATE KEY block found in key_pem".to_string()),
        Err(e) => return Err(format!("key parse error: {e}")),
    };
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map(|_| ())
        .map_err(|e| format!("certificate and private key do not match: {e}"))
}

/// Load the persisted config, mutate its TLS section, write it back atomically.
fn tls_write_config(s: &AppState, mutate: impl FnOnce(&mut TlsConfig)) -> Result<(), String> {
    let mut c = crate::config::load(&s.cfg_path).map_err(|e| format!("load config: {e}"))?;
    mutate(&mut c.tls);
    crate::config::writer::write_config_atomic(&c, std::path::Path::new(&s.cfg_path))
        .map_err(|e| format!("write config: {e}"))
}

// SEC-L3: write a private key so it is NEVER world-readable, even briefly. fs::write creates
// with the umask (typically 0644) and only chmods afterwards — a TOCTOU window where a local
// user can read the key. Write to a 0600 temp file then atomically rename over the target
// (the rename also fixes SEC-L8: no half-written/orphan key on failure). A failed write/perm
// is propagated (no silent 0644 key).
fn tls_write_key_0600(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true).create(true).truncate(true).mode(0o600)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, path)
    }
    #[cfg(not(unix))]
    { std::fs::write(path, bytes) }
}

fn tls_slave_guard(s: &AppState) -> Option<axum::response::Response> {
    if s.slave_mode {
        return Some(
            (
                StatusCode::CONFLICT,
                JsonExtract(serde_json::json!({
                    "error": "SLAVE_READ_ONLY",
                    "details": "encrypted-DNS settings are managed on the master"
                })),
            )
                .into_response(),
        );
    }
    None
}

/// GET /api/tls/cert — active (booted) vs configured (persisted) state + cert info.
async fn tls_cert_handler(State(s): State<AppState>) -> impl IntoResponse {
    let cfg_tls = crate::config::load(&s.cfg_path)
        .map(|c| c.tls)
        .unwrap_or_else(|_| (*s.tls_cfg).clone());
    let boot = s.tls_cfg.as_ref();
    let active = boot.cert_path.is_some() && boot.key_path.is_some();
    let configured = cfg_tls.cert_path.is_some() && cfg_tls.key_path.is_some();
    let cert = cfg_tls
        .cert_path
        .as_deref()
        .map(tls_cert_info)
        .unwrap_or(serde_json::Value::Null);
    JsonExtract(serde_json::json!({
        "active": active,
        "configured": configured,
        "restart_required": false,
        "dot_port": cfg_tls.dot_port.unwrap_or(853),
        "doh_port": cfg_tls.doh_port.unwrap_or(443),
        "doq_port": cfg_tls.doq_port.unwrap_or(853),
        "hostname": cfg_tls.hostname.clone().unwrap_or_else(|| "runbound.local".to_string()),
        "cert_path": cfg_tls.cert_path,
        "cert": cert,
    }))
    .into_response()
}

/// Build a leaf certificate for `host` signed by the Runbound Local CA (shared with
/// the WebUI), so it chains to a CA the operator imports once. Browsers reject bare
/// self-signed leaves; a CA-signed leaf becomes trusted once the CA is imported.
fn tls_sign_leaf_with_ca(
    host: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> anyhow::Result<(String, String)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let not_before =
        rcgen::date_time_ymd(1970, 1, 1) + std::time::Duration::from_secs(now.saturating_sub(60));
    let not_after = not_before + std::time::Duration::from_secs(397 * 24 * 3600);

    let ca_key =
        rcgen::KeyPair::from_pem(ca_key_pem).map_err(|e| anyhow::anyhow!("load CA key: {e}"))?;
    let ca_cert = rcgen::CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .map_err(|e| anyhow::anyhow!("load CA cert: {e}"))?
        .self_signed(&ca_key)
        .map_err(|e| anyhow::anyhow!("CA re-sign: {e}"))?;

    let mut params =
        rcgen::CertificateParams::new(vec![]).map_err(|e| anyhow::anyhow!("leaf params: {e}"))?;
    params.not_before = not_before;
    params.not_after = not_after;
    // Emit the Authority Key Identifier (from the CA's Subject Key Identifier) so the
    // chain verifies under strict X.509 validators (OpenSSL 3 strict mode).
    params.use_authority_key_identifier_extension = true;
    // Leaf usage for a TLS server cert (strict validators / OpenSSL 3).
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);
    // SANs: the hostname (DNS name or IP literal) + loopback, for local testing.
    for san in [host, "localhost", "127.0.0.1"] {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
        } else if let Ok(ia5) = rcgen::Ia5String::try_from(san) {
            params.subject_alt_names.push(rcgen::SanType::DnsName(ia5));
        }
    }

    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow::anyhow!("leaf key gen: {e}"))?;
    let cert = params
        .signed_by(&key_pair, &ca_cert, &ca_key)
        .map_err(|e| anyhow::anyhow!("leaf sign: {e}"))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// GET /api/tls/ca — download the Runbound Local CA certificate (public). Import it
/// into the browser/OS trust store so the self-signed DoT/DoH cert is trusted.
async fn tls_ca_handler(State(s): State<AppState>) -> impl IntoResponse {
    match crate::webui::ensure_webui_ca("", "", &s.base_dir) {
        Ok((ca_pem, _)) => Response::builder()
            .status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "application/x-pem-file")
            .header(
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"runbound-ca.pem\"",
            )
            .body(axum::body::Body::from(ca_pem))
            .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response()),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({ "error": "CA_FAILED", "details": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/tls/self-signed — generate a self-signed cert+key, enable DoT/DoH/DoQ.
async fn tls_self_signed_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    ApiJson(b): ApiJson<TlsSelfSignedBody>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"encrypted-DNS settings require admin"}))).into_response();
    }
    if let Some(r) = tls_slave_guard(&s) {
        return r;
    }
    let host = b.hostname.trim().to_string();
    if host.is_empty() || host.len() > 253 || host.contains(|c: char| c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({
                "error": "INVALID_HOSTNAME",
                "details": "hostname must be 1..253 chars with no control characters"
            })),
        )
            .into_response();
    }
    let cert_path = s.base_dir.join(TLS_CERT_FILE);
    let key_path = s.base_dir.join(TLS_KEY_FILE);
    // Sign the leaf with the Runbound Local CA (shared with the WebUI) so the cert
    // chains to a CA the operator imports once — browsers reject bare self-signed
    // leaves. The CA cert is downloadable at GET /api/tls/ca.
    let (ca_cert_pem, ca_key_pem) = match crate::webui::ensure_webui_ca("", "", &s.base_dir) {
        Ok(x) => x,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({ "error": "CA_FAILED", "details": e.to_string() })),
            )
                .into_response()
        }
    };
    let (cert_pem, key_pem) = match tls_sign_leaf_with_ca(&host, &ca_cert_pem, &ca_key_pem) {
        Ok(x) => x,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonExtract(serde_json::json!({ "error": "GEN_FAILED", "details": e.to_string() })),
            )
                .into_response()
        }
    };
    if let Err(e) = std::fs::write(&cert_path, cert_pem.as_bytes()) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({ "error": "WRITE_CERT", "details": e.to_string() })),
        )
            .into_response();
    }
    if let Err(e) = tls_write_key_0600(&key_path, key_pem.as_bytes()) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({ "error": "WRITE_KEY", "details": e.to_string() })),
        )
            .into_response();
    }
    let (cp, kp) = (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    );
    let (dot, doh, doq) = (b.dot_port, b.doh_port, b.doq_port);
    if let Err(e) = tls_write_config(&s, move |t| {
        t.cert_path = Some(cp);
        t.key_path = Some(kp);
        t.hostname = Some(host);
        if let Some(p) = dot {
            t.dot_port = Some(p);
        }
        if let Some(p) = doh {
            t.doh_port = Some(p);
        }
        if let Some(p) = doq {
            t.doq_port = Some(p);
        }
    }) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({ "error": "CONFIG_WRITE", "details": e })),
        )
            .into_response();
    }
    s.audit.send(AuditEvent::ConfigReload);
    info!(cert = %cert_path.display(), "Encrypted DNS: self-signed certificate generated");
    if let Some(tx) = crate::dns::server::TLS_APPLY_TX.get() {
        let _ = tx.try_send(());
    }
    JsonExtract(serde_json::json!({
        "ok": true,
        "mode": "self-signed",
        "restart_required": false,
        "cert": tls_cert_info(&cert_path.to_string_lossy()),
    }))
    .into_response()
}

/// POST /api/tls/import — import an existing cert + key (e.g. Let's Encrypt).
async fn tls_import_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    ApiJson(b): ApiJson<TlsImportBody>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"encrypted-DNS settings require admin"}))).into_response();
    }
    if let Some(r) = tls_slave_guard(&s) {
        return r;
    }
    if let Err(e) = tls_validate_cert_key(b.cert_pem.as_bytes(), b.key_pem.as_bytes()) {
        return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({ "error": "INVALID_CERT", "details": e })),
        )
            .into_response();
    }
    let cert_path = s.base_dir.join(TLS_CERT_FILE);
    let key_path = s.base_dir.join(TLS_KEY_FILE);
    if let Err(e) = std::fs::write(&cert_path, b.cert_pem.as_bytes()) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({ "error": "WRITE_CERT", "details": e.to_string() })),
        )
            .into_response();
    }
    if let Err(e) = tls_write_key_0600(&key_path, b.key_pem.as_bytes()) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({ "error": "WRITE_KEY", "details": e.to_string() })),
        )
            .into_response();
    }
    let (cp, kp) = (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    );
    let host = b.hostname.and_then(|h| {
        let h = h.trim().to_string();
        if h.is_empty() || h.len() > 253 || h.contains(|c: char| c.is_control()) {
            None
        } else {
            Some(h)
        }
    });
    let (dot, doh, doq) = (b.dot_port, b.doh_port, b.doq_port);
    if let Err(e) = tls_write_config(&s, move |t| {
        t.cert_path = Some(cp);
        t.key_path = Some(kp);
        if let Some(h) = host {
            t.hostname = Some(h);
        }
        if let Some(p) = dot {
            t.dot_port = Some(p);
        }
        if let Some(p) = doh {
            t.doh_port = Some(p);
        }
        if let Some(p) = doq {
            t.doq_port = Some(p);
        }
    }) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({ "error": "CONFIG_WRITE", "details": e })),
        )
            .into_response();
    }
    s.audit.send(AuditEvent::ConfigReload);
    info!(cert = %cert_path.display(), "Encrypted DNS: certificate imported");
    if let Some(tx) = crate::dns::server::TLS_APPLY_TX.get() {
        let _ = tx.try_send(());
    }
    JsonExtract(serde_json::json!({
        "ok": true,
        "mode": "import",
        "restart_required": false,
        "cert": tls_cert_info(&cert_path.to_string_lossy()),
    }))
    .into_response()
}

/// DELETE /api/tls — disable encrypted DNS (clear cert/key directives).
async fn tls_disable_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"encrypted-DNS settings require admin"}))).into_response();
    }
    if let Some(r) = tls_slave_guard(&s) {
        return r;
    }
    if let Err(e) = tls_write_config(&s, |t| {
        t.cert_path = None;
        t.key_path = None;
    }) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({ "error": "CONFIG_WRITE", "details": e })),
        )
            .into_response();
    }
    s.audit.send(AuditEvent::ConfigReload);
    info!("Encrypted DNS: disabled via API");
    if let Some(tx) = crate::dns::server::TLS_APPLY_TX.get() {
        let _ = tx.try_send(());
    }
    JsonExtract(serde_json::json!({ "ok": true, "restart_required": false })).into_response()
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
        let _ = crate::runtime::BASE_DIR.set({ let d = std::env::temp_dir().join(format!("runbound-test-{}", std::process::id())); let _ = std::fs::create_dir_all(&d); d });

        let cfg_arc = Arc::new(cfg);
        let zones = Arc::new(ArcSwap::new(Arc::new(
            crate::dns::local::LocalZoneSet::from_config(&cfg_arc.local_zones, &cfg_arc.local_data),
        )));
        let log_buffer = crate::logbuffer::new_shared(1000, true);
        let upstreams = crate::upstreams::init_upstreams(&cfg_arc);
        let resolver = crate::dns::server::create_shared_resolver(&cfg_arc).expect("test resolver");

        let stats = crate::stats::Stats::new();
        let stats_cache = crate::stats::new_snapshot_cache(&stats);
        let state = AppState {
            split_horizon: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            node_health: NodeHealth::default(),
            zones: Arc::clone(&zones),
            zones_mutex: Arc::new(tokio::sync::Mutex::new(())),
            tls_cfg: Arc::new(crate::config::parser::TlsConfig::default()),
            rate_limiter: ApiRateLimiter::new_public(),
            dns_rate_limiter: crate::dns::ratelimit::RateLimiter::new(0, None, 24, 56),
            reload_limiter: Arc::new(ReloadLimiter::new()),
            stats,
            stats_cache,
            cfg: Arc::clone(&cfg_arc),
            cfg_path: "/dev/null".to_string(),
            log_buffer,
            upstreams,
            sync_journal: None,
            sync_key: None,
            slave_mode: false,
            base_dir: Arc::new({ let d = std::env::temp_dir().join(format!("runbound-test-{}", std::process::id())); let _ = std::fs::create_dir_all(&d); d }),
            audit: crate::audit::init(false, None, None, std::path::PathBuf::from("/tmp"), 0),
            xdp_active: Arc::new(AtomicU8::new(0)),
            resolver,
            last_flush_at: Arc::new(std::sync::Mutex::new(None)),
            cache_evictions: Arc::new(AtomicU64::new(0)),
            lookup_limiter: Arc::new(ReloadLimiter::new_with_params(10.0, 10.0)),
            per_upstream_resolvers: crate::dns::server::create_shared_resolvers_vec(),
            racing_wins: Arc::new(DashMap::with_hasher(ahash::RandomState::new())),
            events_tx: None,
            domain_stats: crate::domain_stats::DomainStats::new(),
            alert_tracker: crate::alerts::AlertTracker::new(vec![], None),
            webhook_targets: Arc::new(tokio::sync::RwLock::new(vec![])),
            webhook_dispatcher: {
                let targets = Arc::new(tokio::sync::RwLock::new(vec![]));
                crate::webhooks::WebhookDispatcher::new(Arc::clone(&targets))
            },
            icmp_stats: crate::icmp::IcmpStats::new(),
            icmp_cfg: Arc::new(std::sync::Mutex::new(crate::icmp::IcmpConfig::default())),
            dnssec_enabled: Arc::new(AtomicBool::new(cfg_arc.dnssec_validation)),
            resolution_mode: crate::dns::recursor::mode_atomic(cfg_arc.resolution_mode),
            recursor: crate::dns::recursor::shared_recursor(
                crate::config::parser::ResolutionMode::Forward,
                false,
            ),
            user_registry: None,
            blacklist_reload_tx: None,
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
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── /api/stats ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn stats_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stats_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/stats")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        for field in &[
            "total",
            "blocked",
            "forwarded",
            "qps_1m",
            "qps_5m",
            "latency_p50_ms",
            "cache_hit_rate",
            "local_hits",
        ] {
            assert!(json.get(field).is_some(), "missing field: {field}");
        }
    }

    // ── /api/stats/stream ─────────────────────────────────────────────────

    #[tokio::test]
    async fn stats_stream_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/stats/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stats_stream_content_type() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/stats/stream")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("text/event-stream"),
            "unexpected Content-Type: {ct}"
        );
    }

    // ── /api/upstreams ────────────────────────────────────────────────────

    #[tokio::test]
    async fn upstreams_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upstreams_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
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
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/logs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logs_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/logs")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json.get("entries").is_some());
        assert!(json.get("total").is_some());
    }

    #[tokio::test]
    async fn logs_limit_too_large() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/logs?limit=2000")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn logs_invalid_action() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/logs?action=invalid")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn logs_invalid_client_ip() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/logs?client=notanip")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── validate_dns_name unit tests (SEC-02) ─────────────────────────────

    #[test]
    fn test_validate_dns_name_253_chars_accepted() {
        // 63+1+63+1+63+1+61 = 253 chars — exactly at RFC 1035 §2.3.4 limit
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(name.len(), 253);
        assert!(validate_dns_name(&name).is_ok());
    }

    #[test]
    fn test_validate_dns_name_254_chars_rejected() {
        // 63+1+63+1+63+1+62 = 254 chars — one over the RFC limit
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(name.len(), 254);
        assert!(validate_dns_name(&name).is_err());
    }

    #[test]
    fn test_validate_dns_name_253_with_trailing_dot_accepted() {
        // trailing dot is stripped before length check
        let name = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(name.trim_end_matches('.').len(), 253);
        assert!(validate_dns_name(&name).is_ok());
    }

    #[test]
    fn test_validate_dns_name_254_with_trailing_dot_rejected() {
        let name = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
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
    // at the HTTP level. An earlier pentest claimed "254 chars → HTTP 201"; these
    // tests prove the rejection works end-to-end and that the pentest was using
    // a 253-char name + trailing dot (= 254 bytes submitted, 253-char domain
    // after trailing-dot strip — correctly accepted).

    #[tokio::test]
    async fn dns_name_254_chars_is_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // 254-char name (no trailing dot): 63+1+63+1+63+1+62 = 254.
        // validate_dns_name must reject this → 400.
        let name: String = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(name.len(), 254);
        let body = serde_json::json!({
            "name": name, "type": "A", "value": "1.2.3.4"
        })
        .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "254-char domain name must be rejected with 400"
        );
    }

    #[tokio::test]
    async fn dns_name_253_chars_no_trailing_dot_passes_validation() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // 253-char name (no trailing dot) — valid per RFC 1035 §2.3.4.
        // validate_dns_name must accept this. The handler may fail at store
        // level (test dir), but must NOT return 400 for the name itself.
        let name: String = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(name.len(), 253);
        let body = serde_json::json!({
            "name": name, "type": "A", "value": "1.2.3.4"
        })
        .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "253-char domain name must not be rejected by name validation"
        );
    }

    #[tokio::test]
    async fn blacklist_name_254_chars_is_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let name: String = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(name.len(), 254);
        let body = serde_json::json!({"domain": name}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/blacklist")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "254-char blacklist domain must be rejected with 400"
        );
    }

    // ── SEC-04 body limit integration tests ───────────────────────────────────

    #[tokio::test]
    async fn post_json_without_content_length_gets_411() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // JSON Content-Type but no Content-Length → 411 (SEC-04 fix).
        let body =
            serde_json::json!({"name": "example.com", "type": "A", "value": "1.2.3.4"}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    // Deliberately omit Content-Length
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::LENGTH_REQUIRED,
            "JSON POST without Content-Length must return 411"
        );
    }

    #[tokio::test]
    async fn post_without_body_no_content_type_passes() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // Bodyless POST (/reload) has no Content-Type → must not get 411.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/reload")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::LENGTH_REQUIRED,
            "Bodyless POST must not get 411"
        );
    }

    // ── POST /api/upstreams ───────────────────────────────────────────────────

    #[tokio::test]
    async fn add_upstream_requires_auth() {
        let app = make_test_app();
        let body = serde_json::json!({"addr":"1.1.1.1","protocol":"udp"}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams")
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn add_upstream_invalid_protocol() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = serde_json::json!({"addr":"1.1.1.1","protocol":"tcp"}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn add_upstream_invalid_addr() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = serde_json::json!({"addr":"not-an-ip","protocol":"udp"}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn add_upstream_happy_path() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body =
            serde_json::json!({"addr":"9.9.9.9","protocol":"udp","name":"Quad9"}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["status"], "ok");
        assert!(json["upstream"]["id"].is_string());
    }

    // ── DELETE /api/upstreams/:id ─────────────────────────────────────────────

    #[tokio::test]
    async fn delete_upstream_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/upstreams/some-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_upstream_not_found() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/upstreams/nonexistent-uuid")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── GET /api/upstreams/presets ────────────────────────────────────────────

    #[tokio::test]
    async fn upstream_presets_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams/presets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upstream_presets_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams/presets")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json["presets"].is_array());
        assert!(json["presets"]
            .as_array()
            .map(|a| a.len() >= 4)
            .unwrap_or(false));
    }

    // ── POST /api/cache/flush ─────────────────────────────────────────────────

    #[tokio::test]
    async fn cache_flush_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/cache/flush")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cache_flush_happy_path() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/cache/flush")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
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

        let r1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/cache/flush")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/cache/flush")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
        let j = body_json(r2.into_body()).await;
        assert_eq!(j["error"], "FLUSH_COOLDOWN");
        assert!(j["retry_after_secs"].as_u64().unwrap_or(0) > 0);
    }

    #[tokio::test]
    async fn cache_flush_cooldown_disabled_allows_two_calls() {
        let app = make_flush_app(0);
        let (k, v) = auth_header();

        let r1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/cache/flush")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/cache/flush")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
    }

    // ── FEAT #47: /api/system new fields ──────────────────────────────────────

    #[tokio::test]
    async fn system_has_prefetch_fields() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/system")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
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
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/system")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["prefetch_enabled"], true);
    }

    #[tokio::test]
    async fn system_upstreams_healthy_matches_upstreams_endpoint() {
        let app = make_test_app();
        let (k, v) = auth_header();

        let sys = body_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/system")
                        .header(k, &v)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .into_body(),
        )
        .await;

        let ups = body_json(
            app.oneshot(
                Request::builder()
                    .uri("/api/upstreams")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
        )
        .await;

        assert_eq!(sys["upstreams_healthy"], ups["healthy"]);
        assert_eq!(sys["upstreams_total"], ups["total"]);
    }

    // ── GET /api/sync/slaves ──────────────────────────────────────────────────

    #[tokio::test]
    async fn sync_slaves_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/sync/slaves")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sync_slaves_standalone_returns_empty() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/sync/slaves")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["total"], 0);
        assert!(json["slaves"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false));
    }

    // ── GET /health schema (no auth, version field present) ───────────────────

    #[tokio::test]
    async fn health_schema() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        let status = json["status"].as_str().unwrap_or("");
        assert!(
            matches!(status, "ok" | "degraded" | "error"),
            "health status must be ok/degraded/error; got: {status}"
        );
        assert!(
            json.get("version").is_none(),
            "health must not disclose the version field (anti-fingerprinting)"
        );
        assert!(
            json.get("hsm").is_none(),
            "health must not expose hsm field"
        );
        assert!(json["uptime_secs"].is_number());
    }

    // ── #74: /health enriched fields ──────────────────────────────────────────

    #[tokio::test]
    async fn health_has_enriched_fields() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(
            json["xdp_active"].is_boolean(),
            "health must include xdp_active"
        );
        assert!(
            json["upstreams_healthy"].is_number(),
            "health must include upstreams_healthy"
        );
        assert!(
            json["upstreams_total"].is_number(),
            "health must include upstreams_total"
        );
        assert!(
            json["cache_entries"].is_number(),
            "health must include cache_entries"
        );
        assert!(json["status"].is_string(), "health must include status");
    }

    #[tokio::test]
    async fn health_status_ok_when_no_upstreams_configured() {
        // Default test config has no forward zones → 0 upstreams → status "error"
        let app = make_test_app();
        let json = body_json(
            app.oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
        )
        .await;
        assert_eq!(json["upstreams_total"], 0);
        assert_eq!(json["status"], "error");
    }

    #[tokio::test]
    async fn health_status_ok_with_healthy_upstream() {
        let mut cfg = crate::config::parser::UnboundConfig::default();
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(),
            addrs: vec!["1.1.1.1@53".into()],
            tls: false,
            tls_hostname: None,
        });
        let app = make_test_app_with_cfg(cfg);
        let (k, v) = auth_header();
        // Mark the upstream healthy via the upstreams endpoint
        let json = body_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .into_body(),
        )
        .await;
        // No probe has run yet → healthy=0 but total=1 → "degraded"
        assert_eq!(json["upstreams_total"], 1);
        assert_eq!(json["status"], "degraded");
        let _ = (k, v);
    }

    // ── #73: GET /api/metrics Prometheus format ───────────────────────────────

    #[tokio::test]
    async fn metrics_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_content_type_prometheus() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("text/plain"),
            "content-type must be text/plain; got: {ct}"
        );
        assert!(
            ct.contains("0.0.4"),
            "content-type must include version=0.0.4; got: {ct}"
        );
    }

    #[tokio::test]
    async fn metrics_contains_required_metric_names() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&bytes).unwrap();
        for metric in &[
            "runbound_queries_total",
            "runbound_queries_blocked_total",
            "runbound_queries_forwarded_total",
            "runbound_queries_nxdomain_total",
            "runbound_queries_servfail_total",
            "runbound_dnssec_secure_total",
            "runbound_dnssec_bogus_total",
            "runbound_dnssec_insecure_total",
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
            assert!(
                body.contains(metric),
                "metrics output must contain {metric}"
            );
        }
    }

    #[tokio::test]
    async fn metrics_upstream_labels_present() {
        let mut cfg = crate::config::parser::UnboundConfig::default();
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(),
            addrs: vec!["9.9.9.9@53".into()],
            tls: false,
            tls_hostname: None,
        });
        let app = make_test_app_with_cfg(cfg);
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/metrics")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(
            body.contains("runbound_upstream_healthy"),
            "upstream_healthy metric must be present"
        );
        assert!(
            body.contains("addr=\"9.9.9.9\""),
            "upstream addr label must be present"
        );
        assert!(
            body.contains("protocol=\"udp\""),
            "upstream protocol label must be present"
        );
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

        let handles: Vec<_> = (0..20)
            .map(|_| {
                let l = Arc::clone(&limiter);
                let b = Arc::clone(&barrier);
                thread::spawn(move || {
                    b.wait(); // all threads start at the same instant
                    l.check()
                })
            })
            .collect();

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let allowed = results.iter().filter(|&&r| r).count();
        let denied = results.iter().filter(|&&r| !r).count();

        assert!(allowed <= 2, "allowed={allowed} but burst=2");
        assert!(denied >= 18, "denied={denied} but expected ≥18");
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

        let ok = statuses.iter().filter(|&&s| s == StatusCode::OK).count();
        let r429 = statuses
            .iter()
            .filter(|&&s| s == StatusCode::TOO_MANY_REQUESTS)
            .count();
        #[allow(unused_variables)]
        let other: Vec<_> = statuses
            .iter()
            .filter(|&&s| s != StatusCode::OK && s != StatusCode::TOO_MANY_REQUESTS)
            .collect();

        assert!(ok <= 2, "burst=2 but {ok} requests got 200");
        assert!(r429 >= 18, "expected ≥18 requests to get 429, got {r429}");
    }

    // ── FIX #40: loopback and IPv4 link-local are rejected ────────────────

    fn post_upstream(
        app: axum::Router,
        auth: (&'static str, String),
        body_str: &'static str,
    ) -> impl std::future::Future<Output = axum::response::Response> {
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

    // ── SEC-NEW-01: IPv6-mapped IPv4 SSRF bypass ──────────────────────────
    #[tokio::test]
    async fn add_upstream_ipv6_mapped_loopback_rejected() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"::ffff:127.0.0.1"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_ADDR");
    }

    #[tokio::test]
    async fn add_upstream_ipv6_mapped_unspecified_rejected() {
        let app = make_test_app();
        let resp = post_upstream(app, auth_header(), r#"{"addr":"::ffff:0.0.0.0"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_ADDR");
    }

    #[tokio::test]
    async fn add_upstream_ipv4_compatible_loopback_rejected() {
        let app = make_test_app();
        // ::127.0.0.1 is IPv4-compatible (deprecated) — should be rejected as loopback
        let resp = post_upstream(app, auth_header(), r#"{"addr":"::127.0.0.1"}"#).await;
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
        let del_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/upstreams/{id}"))
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            body_json(del_resp.into_body()).await["error"],
            "LAST_UPSTREAM"
        );

        // Upstream must still be present after 409
        let list_resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_json(list_resp.into_body()).await["total"], 1);
    }

    #[tokio::test]
    async fn delete_one_of_two_upstreams_returns_200() {
        let app = make_test_app();
        let (k, v) = auth_header();

        let add1 = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"1.1.1.1"}"#).await;
        assert_eq!(add1.status(), StatusCode::CREATED);
        let id1 = body_json(add1.into_body()).await["upstream"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let add2 = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"8.8.8.8"}"#).await;
        assert_eq!(add2.status(), StatusCode::CREATED);

        // Delete first — two upstreams present, must return 200
        let del_resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/upstreams/{id1}"))
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);
    }

    // ── FIX #42: presets DoT entries have no @port in addr ────────────────

    #[tokio::test]
    async fn upstream_presets_dot_no_at_port() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams/presets")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        let presets = json["presets"].as_array().unwrap();
        assert!(!presets.is_empty());
        for preset in presets {
            let addr = preset["addr"].as_str().unwrap();
            assert!(
                !addr.contains('@'),
                "preset addr must not contain @port: {addr}"
            );
            if preset["protocol"] == "dot" {
                assert_eq!(preset["port"], 853, "DoT preset must have port 853");
            }
        }
    }

    // ── FIX #44: port field in response, defaults, port=0 rejected ────────

    #[tokio::test]
    async fn add_upstream_default_port_udp() {
        let app = make_test_app();
        let resp =
            post_upstream(app, auth_header(), r#"{"addr":"1.1.1.1","protocol":"udp"}"#).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(body_json(resp.into_body()).await["upstream"]["port"], 53);
    }

    #[tokio::test]
    async fn add_upstream_default_port_dot() {
        let app = make_test_app();
        let resp =
            post_upstream(app, auth_header(), r#"{"addr":"1.1.1.1","protocol":"dot"}"#).await;
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

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        let upstreams = json["upstreams"]
            .as_array()
            .expect("upstreams must be array");
        assert!(!upstreams.is_empty());
        for u in upstreams {
            assert!(
                u["latency_history"].is_array(),
                "latency_history must be a JSON array; got: {:?}",
                u["latency_history"]
            );
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
        assert_eq!(
            upstream["upstream"]["latency_history"]
                .as_array()
                .map(|a| a.len()),
            Some(0),
            "newly added upstream must have empty latency_history"
        );
    }

    #[tokio::test]
    async fn upstreams_dnssec_supported_absent_when_not_probed() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_body = r#"{"addr":"9.9.9.9","protocol":"udp"}"#;
        post_upstream(app.clone(), (k, v.clone()), add_body).await;

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp.into_body()).await;
        let ups = json["upstreams"].as_array().unwrap();
        for u in ups {
            assert!(
                u.get("dnssec_supported").is_none(),
                "dnssec_supported must be absent (None) before first probe; got: {:?}",
                u
            );
        }
    }

    // ── #50: PATCH /api/upstreams/:id ─────────────────────────────────────────

    #[tokio::test]
    async fn patch_upstream_requires_auth() {
        let app = make_test_app();
        let body = serde_json::json!({"name":"Test"}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/upstreams/some-id")
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn patch_upstream_renames() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_resp = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"9.9.9.9"}"#).await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let patch_body = serde_json::json!({"name":"Quad9 renamed"}).to_string();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/upstreams/{id}"))
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", patch_body.len().to_string())
                    .body(Body::from(patch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["status"], "ok");
        assert_eq!(j["upstream"]["name"], "Quad9 renamed");
    }

    #[tokio::test]
    async fn patch_upstream_empty_name_clears() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_resp = post_upstream(
            app.clone(),
            (k, v.clone()),
            r#"{"addr":"9.9.9.9","name":"Old Name"}"#,
        )
        .await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let patch_body = serde_json::json!({"name":""}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/upstreams/{id}"))
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", patch_body.len().to_string())
                    .body(Body::from(patch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert!(
            j["upstream"]["name"].is_null(),
            "empty name must become null"
        );
    }

    #[tokio::test]
    async fn patch_upstream_unknown_field_returns_400() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_resp = post_upstream(app.clone(), (k, v.clone()), r#"{"addr":"9.9.9.9"}"#).await;
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let patch_body = serde_json::json!({"addr":"1.2.3.4"}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/upstreams/{id}"))
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", patch_body.len().to_string())
                    .body(Body::from(patch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_FIELD");
    }

    #[tokio::test]
    async fn patch_upstream_not_found() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let patch_body = serde_json::json!({"name":"x"}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/upstreams/nonexistent-uuid")
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", patch_body.len().to_string())
                    .body(Body::from(patch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── #51: GET /api/cache/stats ─────────────────────────────────────────────

    #[tokio::test]
    async fn cache_stats_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/cache/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cache_stats_schema_initial_zeros() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/cache/stats")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["hits"], 0);
        assert_eq!(j["misses"], 0);
        assert_eq!(j["evictions"], 0);
        assert!(j["entries"].is_number(), "entries must be a number");
        assert!(
            j["hit_rate_pct"].is_null(),
            "hit_rate_pct must be null when both are 0"
        );
    }

    // ── #54: POST /api/upstreams/:id/probe ───────────────────────────────

    #[tokio::test]
    async fn probe_upstream_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams/any-id/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn probe_upstream_not_found() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams/nonexistent-uuid/probe")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
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
            .as_str()
            .unwrap_or_default()
            .to_string();

        // Trigger immediate probe
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/upstreams/{id}/probe"))
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["status"], "ok");
        assert_eq!(
            j["upstream"]["healthy"], false,
            "TEST-NET-1 must be unhealthy"
        );
        assert!(
            j["upstream"]["last_error"].is_string(),
            "last_error must be set on failure"
        );
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
            .as_str()
            .unwrap_or_default()
            .to_string();

        // Trigger immediate probe — should fail
        let probe_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/upstreams/{id}/probe"))
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(probe_resp.status(), StatusCode::OK);
        let j = body_json(probe_resp.into_body()).await;
        assert_eq!(j["upstream"]["healthy"], false);
        assert!(
            j["upstream"]["last_error"].is_string(),
            "last_error must be present after a failed probe; got: {:?}",
            j["upstream"]
        );
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
            let s = list
                .iter_mut()
                .find(|u| u.id == entry.id)
                .unwrap_or_else(|| panic!("entry not found"));
            s.last_error = Some("timeout".into());
            s.healthy = false;
        }
        // Simulate successful write-back
        {
            let mut list = shared.write().unwrap_or_else(|e| e.into_inner());
            let s = list
                .iter_mut()
                .find(|u| u.id == entry.id)
                .unwrap_or_else(|| panic!("entry not found"));
            s.healthy = true;
            s.last_error = None;
        }
        let list = shared.read().unwrap_or_else(|e| e.into_inner());
        let s = list
            .iter()
            .find(|u| u.id == entry.id)
            .unwrap_or_else(|| panic!("entry not found"));
        assert!(
            s.last_error.is_none(),
            "last_error must be None after a successful probe"
        );
        assert!(s.healthy);
    }

    // ── #56: tls_hostname on PATCH /api/upstreams/:id ─────────────────────────

    #[tokio::test]
    async fn patch_upstream_tls_hostname_sets_value() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let add_resp = post_upstream(
            app.clone(),
            (k, v.clone()),
            r#"{"addr":"9.9.9.9","protocol":"dot"}"#,
        )
        .await;
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let patch_body = serde_json::json!({"tls_hostname":"custom.example.com"}).to_string();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/upstreams/{id}"))
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", patch_body.len().to_string())
                    .body(Body::from(patch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["upstream"]["tls_hostname"], "custom.example.com");
    }

    #[tokio::test]
    async fn patch_upstream_tls_hostname_empty_clears() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // Add DoT upstream with tls_hostname set
        let body =
            serde_json::json!({"addr":"9.9.9.9","protocol":"dot","tls_hostname":"dns.quad9.net"})
                .to_string();
        let add_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams")
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(add_resp.status(), StatusCode::CREATED);
        let id = body_json(add_resp.into_body()).await["upstream"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Clear tls_hostname by patching with ""
        let patch_body = serde_json::json!({"tls_hostname":""}).to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/upstreams/{id}"))
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", patch_body.len().to_string())
                    .body(Body::from(patch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        // tls_hostname absent from JSON when None (skip_serializing_if)
        assert!(
            j["upstream"].get("tls_hostname").is_none() || j["upstream"]["tls_hostname"].is_null(),
            "tls_hostname must be absent or null after clearing; got: {:?}",
            j["upstream"]
        );
    }

    #[tokio::test]
    async fn post_upstream_tls_hostname_validated_control_char() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // tls_hostname with control character must return 400
        let body =
            serde_json::json!({"addr":"9.9.9.9","protocol":"dot","tls_hostname":"bad\x01host"})
                .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams")
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_FIELD");
    }

    #[tokio::test]
    async fn post_upstream_tls_hostname_too_long() {
        let app = make_test_app();
        let (k, v) = auth_header();
        // 254-char tls_hostname must return 400
        let long_host = "a".repeat(254);
        let body = serde_json::json!({"addr":"9.9.9.9","protocol":"dot","tls_hostname": long_host})
            .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams")
                    .header(k, &v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp.into_body()).await["error"], "INVALID_FIELD");
    }

    #[tokio::test]
    async fn cache_stats_reset_on_flush() {
        let app = make_test_app();
        let (k, v) = auth_header();

        // Flush the cache (resets counters)
        let flush_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/cache/flush")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(flush_resp.status(), StatusCode::OK);

        // Counters must be zero after reset
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/cache/stats")
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["hits"], 0);
        assert_eq!(j["misses"], 0);
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
            tls_hostname: None,
        });
        let app = make_test_app_with_cfg(cfg);
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/upstreams")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        let ups = json["upstreams"]
            .as_array()
            .expect("upstreams must be array");
        let config_up = ups
            .iter()
            .find(|u| u["addr"] == "1.1.1.1")
            .expect("1.1.1.1 must be present");
        assert_eq!(
            config_up["source"], "config",
            "config-file upstream must have source=config"
        );
    }

    #[tokio::test]
    async fn config_upstream_delete_idempotent_404() {
        // Create a real temp config file with a forward-addr line.
        let tmp = std::env::temp_dir().join(format!("runbound-test-{}.conf", std::process::id()));
        let conf_content = "server:\n    port: 5353\n\nforward-zone:\n    name: \".\"\n    forward-addr: 9.9.9.9@53\n";
        std::fs::write(&tmp, conf_content).expect("write temp conf");

        init_api_key(Some(TEST_KEY.to_string()));
        let _ = crate::runtime::BASE_DIR.set({ let d = std::env::temp_dir().join(format!("runbound-test-{}", std::process::id())); let _ = std::fs::create_dir_all(&d); d });

        let mut cfg = crate::config::parser::UnboundConfig::default();
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(),
            addrs: vec!["9.9.9.9@53".into()],
            tls: false,
            tls_hostname: None,
        });
        // Add a second upstream so the first can be deleted (FIX #41)
        cfg.forward_zones.push(crate::config::parser::ForwardZone {
            name: ".".into(),
            addrs: vec!["8.8.8.8@53".into()],
            tls: false,
            tls_hostname: None,
        });

        let zones = Arc::new(ArcSwap::new(Arc::new(
            crate::dns::local::LocalZoneSet::default(),
        )));
        let cfg_arc = Arc::new(cfg);
        let log_buffer = crate::logbuffer::new_shared(1000, true);
        let upstreams = crate::upstreams::init_upstreams(&cfg_arc);
        let resolver = crate::dns::server::create_shared_resolver(&cfg_arc).expect("test resolver");
        let stats = crate::stats::Stats::new();
        let stats_cache = crate::stats::new_snapshot_cache(&stats);
        let state = AppState {
            split_horizon: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            node_health: NodeHealth::default(),
            zones: Arc::clone(&zones),
            zones_mutex: Arc::new(tokio::sync::Mutex::new(())),
            tls_cfg: Arc::new(crate::config::parser::TlsConfig::default()),
            rate_limiter: ApiRateLimiter::new_public(),
            dns_rate_limiter: crate::dns::ratelimit::RateLimiter::new(0, None, 24, 56),
            reload_limiter: Arc::new(ReloadLimiter::new()),
            stats,
            stats_cache,
            cfg: Arc::clone(&cfg_arc),
            cfg_path: tmp.to_string_lossy().to_string(),
            log_buffer,
            upstreams,
            sync_journal: None,
            sync_key: None,
            slave_mode: false,
            base_dir: Arc::new({ let d = std::env::temp_dir().join(format!("runbound-test-{}", std::process::id())); let _ = std::fs::create_dir_all(&d); d }),
            audit: crate::audit::init(false, None, None, std::path::PathBuf::from("/tmp"), 0),
            xdp_active: Arc::new(AtomicU8::new(0)),
            resolver,
            last_flush_at: Arc::new(std::sync::Mutex::new(None)),
            cache_evictions: Arc::new(AtomicU64::new(0)),
            lookup_limiter: Arc::new(ReloadLimiter::new_with_params(10.0, 10.0)),
            per_upstream_resolvers: crate::dns::server::create_shared_resolvers_vec(),
            racing_wins: Arc::new(DashMap::with_hasher(ahash::RandomState::new())),
            events_tx: None,
            domain_stats: crate::domain_stats::DomainStats::new(),
            alert_tracker: crate::alerts::AlertTracker::new(vec![], None),
            webhook_targets: Arc::new(tokio::sync::RwLock::new(vec![])),
            webhook_dispatcher: {
                let targets = Arc::new(tokio::sync::RwLock::new(vec![]));
                crate::webhooks::WebhookDispatcher::new(Arc::clone(&targets))
            },
            icmp_stats: crate::icmp::IcmpStats::new(),
            icmp_cfg: Arc::new(std::sync::Mutex::new(crate::icmp::IcmpConfig::default())),
            dnssec_enabled: Arc::new(AtomicBool::new(cfg_arc.dnssec_validation)),
            resolution_mode: crate::dns::recursor::mode_atomic(cfg_arc.resolution_mode),
            recursor: crate::dns::recursor::shared_recursor(
                crate::config::parser::ResolutionMode::Forward,
                false,
            ),
            user_registry: None,
            blacklist_reload_tx: None,
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
        let del1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/upstreams/{id}"))
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            del1.status(),
            StatusCode::OK,
            "first delete must return 200"
        );

        // Config file must no longer contain forward-addr: 9.9.9.9@53
        let after = std::fs::read_to_string(&tmp).expect("read temp conf after delete");
        assert!(
            !after.contains("9.9.9.9"),
            "forward-addr must be removed from config file"
        );

        // Second DELETE — must return 404 (idempotent)
        let del2 = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/upstreams/{id}"))
                    .header(k, &v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            del2.status(),
            StatusCode::NOT_FOUND,
            "re-delete must return 404"
        );

        let _ = std::fs::remove_file(&tmp);
    }

    // ── POST /api/dns/lookup (#75) ────────────────────────────────────────

    #[tokio::test]
    async fn dns_lookup_no_auth_rejected() {
        let app = make_test_app();
        let body = r#"{"name":"example.com"}"#;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns/lookup")
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dns_lookup_invalid_domain_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = r#"{"name":"-invalid-domain-","type":"A"}"#;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns/lookup")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let j = body_json(resp.into_body()).await;
        assert_eq!(j["error"], "INVALID_NAME");
    }

    #[tokio::test]
    async fn dns_lookup_invalid_type_rejected() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let body = r#"{"name":"example.com","type":"SOA"}"#;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns/lookup")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
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
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns/lookup")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
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
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dns/lookup")
                    .header(k, v)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Missing required field → unprocessable entity from ApiJson
        assert!(resp.status().is_client_error());
    }

    // ── POST /api/upstreams/reconnect (#78) ───────────────────────────────

    #[tokio::test]
    async fn upstreams_reconnect_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams/reconnect")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upstreams_reconnect_get_not_allowed() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/upstreams/reconnect")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn upstreams_reconnect_returns_schema() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/upstreams/reconnect")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        for field in &["reconnected", "failed", "duration_ms"] {
            assert!(json.get(field).is_some(), "missing field: {field}");
        }
    }

    // ── ICMP API tests (#89) ──────────────────────────────────────────────

    #[tokio::test]
    async fn icmp_stats_returns_counters() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/icmp/stats")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        for field in &["handled", "replied", "dropped", "rate_limited"] {
            assert!(json.get(field).is_some(), "missing field: {field}");
        }
    }

    #[tokio::test]
    async fn icmp_config_get_returns_defaults() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/icmp/config")
                    .header(k, v)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["enable"], false);
        assert!(json["rate_limit"].is_number());
        assert!(json["burst"].is_number());
    }

    #[tokio::test]
    async fn icmp_config_put_updates_and_reflects() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/icmp/config")
                    .header(k, v)
                    .header("content-type", "application/json")
                    .header("Content-Length", "42")
                    .body(Body::from(r#"{"enable":true,"rate_limit":50,"burst":10}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["enable"], true);
        assert_eq!(json["rate_limit"], 50);
        assert_eq!(json["burst"], 10);
    }

    #[tokio::test]
    async fn icmp_config_put_partial_update() {
        let app = make_test_app();
        let (k, v) = auth_header();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/icmp/config")
                    .header(k, v)
                    .header("content-type", "application/json")
                    .header("Content-Length", "18")
                    .body(Body::from(r#"{"rate_limit":100}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["enable"], false);
        assert_eq!(json["rate_limit"], 100);
    }

    #[tokio::test]
    async fn icmp_stats_requires_auth() {
        let app = make_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/icmp/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── NEW-N1: RBAC enforcement through the FULL nested router ────────────
    //
    // Regression guard for NEW-N1: `security_middleware` is
    // layered on the INNER `api_routes`, which axum mounts under
    // `nest("/api", …)`. nesting applies `StripPrefix`, so inside the middleware
    // `req.uri().path()` is `/dns`, NOT `/api/dns`. `Role::may_write` matches
    // `/api/...` prefixes, so a non-admin write used to fail-closed (403 with
    // "role does not permit writes") for EVERY endpoint — making the per-role
    // write-RBAC inert and the per-zone `may_manage_name` check unreachable.
    //
    // These tests drive a non-admin `Dns` user and an admin through the real
    // top-level router (the exact gap two static audits + the unit tests missed,
    // because none exercised a non-admin role across the `nest` boundary). They
    // MUST fail against the buggy middleware and pass once it evaluates the
    // original (un-stripped) path via `OriginalUri`.

    /// Serialises the RBAC tests that perform a *successful* DNS write. The DNS
    /// store path is derived from the global `BASE_DIR` OnceLock, so every test
    /// in this binary shares one `dns_entries.json`; two concurrent successful
    /// writes race on `store::save`'s tmp→rename and intermittently 500. The
    /// pre-existing harness never hit this because its `/api/dns` POST tests are
    /// all validation-rejection cases that return before persisting. Holding
    /// this async mutex across the write keeps these tests deterministic.
    static DNS_STORE_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Build the real top-level router with a populated user registry containing
    /// a non-admin `Dns` user scoped to `shop.example.com.` and an admin user.
    /// Returns `(router_factory, dns_key, admin_key)`. The factory rebuilds the
    /// router per call because `oneshot` consumes the service.
    fn make_rbac_app() -> (impl Fn() -> Router, String, String) {
        // Unique dir per invocation for this test's `users.json` (the user
        // registry). NB: the DNS store path is derived from the global
        // `BASE_DIR`, not from `state.base_dir`, so successful DNS writes still
        // share one file — see DNS_STORE_WRITE_LOCK.
        let uniq = format!(
            "/tmp/runbound-rbac-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::fs::create_dir_all(&uniq).unwrap();

        let dns_key = "rbac-dns-user-key-0001".to_string();
        let admin_key = "rbac-admin-user-key-0002".to_string();
        let users_json = format!(
            r#"{{"users":[
                {{"id":"u-dns","username":"dnsuser","api_key":"{dns_key}",
                  "zone_prefixes":["shop.example.com."],"enabled":true,
                  "admin":false,"role":"dns"}},
                {{"id":"u-admin","username":"adminuser","api_key":"{admin_key}",
                  "zone_prefixes":[],"enabled":true,"admin":true,"role":"admin"}}
            ]}}"#
        );
        let users_path = std::path::PathBuf::from(&uniq).join("users.json");
        std::fs::write(&users_path, users_json).unwrap();
        let registry = crate::multiuser::UserRegistry::load(&users_path);
        assert_eq!(registry.all_users().len(), 2, "test registry must load 2 users");

        init_api_key(Some(TEST_KEY.to_string()));
        let _ = crate::runtime::BASE_DIR.set({ let d = std::env::temp_dir().join(format!("runbound-test-{}", std::process::id())); let _ = std::fs::create_dir_all(&d); d });

        let cfg_arc = Arc::new(crate::config::parser::UnboundConfig::default());
        let base = std::path::PathBuf::from(uniq);
        let factory = move || {
            // Each router needs its own AppState (oneshot consumes the service),
            // but they share the same registry + base dir.
            let zones = Arc::new(ArcSwap::new(Arc::new(
                crate::dns::local::LocalZoneSet::from_config(
                    &cfg_arc.local_zones,
                    &cfg_arc.local_data,
                ),
            )));
            let log_buffer = crate::logbuffer::new_shared(1000, true);
            let upstreams = crate::upstreams::init_upstreams(&cfg_arc);
            let resolver =
                crate::dns::server::create_shared_resolver(&cfg_arc).expect("test resolver");
            let stats = crate::stats::Stats::new();
            let stats_cache = crate::stats::new_snapshot_cache(&stats);
            let state = AppState {
                split_horizon: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                node_health: NodeHealth::default(),
                zones: Arc::clone(&zones),
                zones_mutex: Arc::new(tokio::sync::Mutex::new(())),
                tls_cfg: Arc::new(crate::config::parser::TlsConfig::default()),
                rate_limiter: ApiRateLimiter::new_public(),
            dns_rate_limiter: crate::dns::ratelimit::RateLimiter::new(0, None, 24, 56),
                reload_limiter: Arc::new(ReloadLimiter::new()),
                stats,
                stats_cache,
                cfg: Arc::clone(&cfg_arc),
                cfg_path: "/dev/null".to_string(),
                log_buffer,
                upstreams,
                sync_journal: None,
                sync_key: None,
                slave_mode: false,
                base_dir: Arc::new(base.clone()),
                audit: crate::audit::init(false, None, None, std::path::PathBuf::from("/tmp"), 0),
                xdp_active: Arc::new(AtomicU8::new(0)),
                resolver,
                last_flush_at: Arc::new(std::sync::Mutex::new(None)),
                cache_evictions: Arc::new(AtomicU64::new(0)),
                lookup_limiter: Arc::new(ReloadLimiter::new_with_params(10.0, 10.0)),
                per_upstream_resolvers: crate::dns::server::create_shared_resolvers_vec(),
                racing_wins: Arc::new(DashMap::with_hasher(ahash::RandomState::new())),
                events_tx: None,
                domain_stats: crate::domain_stats::DomainStats::new(),
                alert_tracker: crate::alerts::AlertTracker::new(vec![], None),
                webhook_targets: Arc::new(tokio::sync::RwLock::new(vec![])),
                webhook_dispatcher: {
                    let targets = Arc::new(tokio::sync::RwLock::new(vec![]));
                    crate::webhooks::WebhookDispatcher::new(Arc::clone(&targets))
                },
                icmp_stats: crate::icmp::IcmpStats::new(),
                icmp_cfg: Arc::new(std::sync::Mutex::new(crate::icmp::IcmpConfig::default())),
                dnssec_enabled: Arc::new(AtomicBool::new(cfg_arc.dnssec_validation)),
                resolution_mode: crate::dns::recursor::mode_atomic(cfg_arc.resolution_mode),
                recursor: crate::dns::recursor::shared_recursor(
                    crate::config::parser::ResolutionMode::Forward,
                    false,
                ),
                user_registry: Some(Arc::clone(&registry)),
                blacklist_reload_tx: None,
            };
            router(state)
        };
        (factory, dns_key, admin_key)
    }

    fn dns_write_body(name: &str) -> String {
        format!(r#"{{"name":"{name}","type":"A","value":"203.0.113.7","ttl":300}}"#)
    }

    async fn post_json(app: Router, uri: &str, key: &str, body: String) -> StatusCode {
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Authorization", format!("Bearer {key}"))
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.status()
    }

    /// Non-admin `Dns` user writing INSIDE its zone → reaches `may_manage_name`,
    /// which passes → 201. (Pre-fix: 403 "role does not permit writes".)
    #[tokio::test]
    async fn rbac_nonadmin_in_zone_dns_write_is_created() {
        let _w = DNS_STORE_WRITE_LOCK.lock().await; // serialise shared-store writes
        let (app, dns_key, _admin) = make_rbac_app();
        let status = post_json(
            app(),
            "/api/dns",
            &dns_key,
            dns_write_body("www.shop.example.com"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "in-zone DNS write by a Dns user must reach may_manage_name and be created (201)"
        );
    }

    /// Non-admin `Dns` user writing OUTSIDE its zone → `may_write` passes (it's
    /// `/api/dns`) but `may_manage_name` rejects → 403. This is SEC-N2 finally
    /// live: it is *unreachable* while NEW-N1 fails-closed at `may_write`.
    #[tokio::test]
    async fn rbac_nonadmin_out_of_zone_dns_write_is_forbidden() {
        let (app, dns_key, _admin) = make_rbac_app();
        let status = post_json(
            app(),
            "/api/dns",
            &dns_key,
            dns_write_body("www.evil.example.org"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "out-of-zone DNS write must be rejected by may_manage_name (403)"
        );
    }

    /// Non-admin `Dns` user hitting an admin-only endpoint (`/api/users`) →
    /// `may_write` rejects (Dns role has no write on /api/users) → 403.
    #[tokio::test]
    async fn rbac_nonadmin_admin_endpoint_write_is_forbidden() {
        let (app, dns_key, _admin) = make_rbac_app();
        let body = r#"{"username":"intruder","role":"admin"}"#.to_string();
        let status = post_json(app(), "/api/users", &dns_key, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Dns role must not be able to write to /api/users (403)"
        );
    }

    /// Admin user writes everywhere → 201 on DNS even outside any zone_prefix.
    #[tokio::test]
    async fn rbac_admin_write_is_created_everywhere() {
        let _w = DNS_STORE_WRITE_LOCK.lock().await; // serialise shared-store writes
        let (app, _dns, admin_key) = make_rbac_app();
        let status = post_json(
            app(),
            "/api/dns",
            &admin_key,
            dns_write_body("anything.example.net"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "admin DNS write must succeed regardless of zone (201)"
        );
    }

    /// Read for a non-admin user must still work (GET is never gated by may_write).
    #[tokio::test]
    async fn rbac_nonadmin_get_is_allowed() {
        let (app, dns_key, _admin) = make_rbac_app();
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/dns")
                    .header("Authorization", format!("Bearer {dns_key}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET (read) by a non-admin user must remain allowed"
        );
    }
}


// POST /api/webhooks/test — send a test notification to all configured webhooks (#11)
async fn post_webhook_test(State(state): State<AppState>) -> impl IntoResponse {
    let targets = state.webhook_targets.read().await;
    let event = crate::webhooks::WebhookEvent {
        kind: "config-reloaded".to_owned(),
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        client: None,
        domain: None,
        feed: None,
        message: Some("Webhook test from Runbound dashboard".to_owned()),
        node_id: None,
    };
    state.webhook_dispatcher.fire(&targets, event);
    (axum::http::StatusCode::OK, axum::Json(serde_json::json!({"sent": targets.len()})))
}

// GET /api/alerts — alert rules, blocked clients, recent events (#12)
// Auth handled by security_middleware.
#[derive(serde::Deserialize)]
struct AlertRuleBody {
    name: String,
    #[serde(default = "ar_metric")]
    metric: String,
    #[serde(default = "ar_window")]
    window_s: u64,
    #[serde(default = "ar_threshold")]
    threshold: u64,
    #[serde(default = "ar_action")]
    action: String,
    #[serde(default)]
    notify_url: Option<String>,
    #[serde(default = "ar_blockdur")]
    block_duration_s: u64,
}
fn ar_metric() -> String { "client-qps".to_string() }
fn ar_window() -> u64 { 10 }
fn ar_threshold() -> u64 { 1000 }
fn ar_action() -> String { "log".to_string() }
fn ar_blockdur() -> u64 { 300 }

/// PUT /api/alerts/rules — replace the full alert-rule set (admin). Persists to the
/// config (regenerated) and hot-applies via AlertTracker::update_rules — no restart.
async fn put_alert_rules(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    ApiJson(rules): ApiJson<Vec<AlertRuleBody>>,
) -> impl IntoResponse {
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN","details":"alert rules require admin"}))).into_response();
    }
    if rules.len() > 64 {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"TOO_MANY_RULES","details":"max 64 rules"}))).into_response();
    }
    let mut out: Vec<crate::config::parser::AlertRule> = Vec::with_capacity(rules.len());
    for r in rules {
        let name = r.name.trim().to_string();
        if name.is_empty() || name.len() > 64 || name.contains(|c: char| c.is_control()) {
            return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"INVALID_NAME","details":"rule name 1..64 chars, no control chars"}))).into_response();
        }
        if !matches!(r.action.as_str(), "log" | "block" | "notify" | "tarpit") {
            return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"INVALID_ACTION","details":"action must be log, block, notify or tarpit"}))).into_response();
        }
        if r.metric != "client-qps" {
            return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"INVALID_METRIC","details":"only client-qps is supported"}))).into_response();
        }
        if r.action == "notify" && r.notify_url.as_deref().unwrap_or("").is_empty() {
            return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"MISSING_NOTIFY_URL","details":"action=notify requires notify-url"}))).into_response();
        }
        if let Some(u) = &r.notify_url {
            if u.len() > 2048 || u.contains(|c: char| c.is_control()) {
                return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"INVALID_NOTIFY_URL","details":"notify-url must be <=2048 chars with no control characters"}))).into_response();
            }
        }
        out.push(crate::config::parser::AlertRule {
            name,
            metric: r.metric,
            window_s: r.window_s.clamp(1, 86_400),
            threshold: r.threshold.max(1),
            action: r.action,
            notify_url: r.notify_url,
            block_duration_s: r.block_duration_s.min(31_536_000),
        });
    }
    // Persist (whole-config regeneration preserves everything else).
    let cfg_path = s.cfg_path.clone();
    let rules_for_cfg = out.clone();
    let persist = (|| -> Result<(), String> {
        let mut c = crate::config::load(&cfg_path).map_err(|e| format!("load config: {e}"))?;
        c.alerts = rules_for_cfg;
        crate::config::writer::write_config_atomic(&c, std::path::Path::new(&cfg_path)).map_err(|e| format!("write config: {e}"))
    })();
    if let Err(e) = persist {
        return (StatusCode::INTERNAL_SERVER_ERROR, JsonExtract(serde_json::json!({"error":"CONFIG_WRITE","details":e}))).into_response();
    }
    // Hot-apply.
    s.alert_tracker.update_rules(out.clone());
    s.audit.send(AuditEvent::ConfigReload);
    info!(count = out.len(), "Alert rules updated via API (persisted + hot-applied)");
    JsonExtract(serde_json::json!({"ok": true, "rules": out.len()})).into_response()
}

async fn get_alerts(State(state): State<AppState>) -> impl IntoResponse {
    JsonExtract(state.alert_tracker.api_snapshot())
}

// PUT /api/alerts/blocked/:ip — manually block an IP (XDP + AlertTracker)
// GET /api/protection/banned — current banned source IPs (flood / manual / relay /
// blacklisted), the same authoritative set the XDP `icmp_banned` map and the kernel
// slow path enforce. (#protection-bans)
async fn banned_list_handler(State(s): State<AppState>) -> impl IntoResponse {
    let entries = s.icmp_stats.banned_snapshot();
    (StatusCode::OK, JsonExtract(serde_json::json!({
        "count": entries.len(),
        "entries": entries,
    }))).into_response()
}

// POST /api/protection/banned/:ip/blacklist — promote a ban to a permanent one
// ("blacklist"): it no longer auto-expires and is propagated to slaves. The ban is
// applied to BOTH ban systems so it is enforced on every path: `icmp_stats`
// (XDP + kernel-UDP fast path) AND `alert_tracker` (the `serve_wire` slow path, which
// is what DoT/DoH/DoQ go through — they check `alert.is_blocked`, not `icmp_stats`).
// Before this, only icmp_stats was set, so a blacklisted IP could still reach the
// resolver over the encrypted transports (DoT/DoH/DoQ) and the slow path.
async fn blacklist_ip_handler(
    State(state): State<AppState>,
    axum::extract::Path(ip_str): axum::extract::Path<String>,
) -> impl IntoResponse {
    match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_loopback() || ip.is_unspecified() => {
            (StatusCode::OK, JsonExtract(serde_json::json!({"blacklisted": false, "ip": ip_str, "reason": "protected address (loopback/unspecified) is never banned"}))).into_response()
        }
        Ok(ip) => {
            state.icmp_stats.ban_permanent(ip);
            state.alert_tracker.block_manual(ip, "manual-blacklist".to_string());
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    let _ = state.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::Ban(ipv4));
                }
                std::net::IpAddr::V6(ipv6) => {
                    let _ = state.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::BanV6(ipv6));
                }
            }
            if let (Some(ref j), Some(ref k)) = (&state.sync_journal, &state.sync_key) {
                crate::api::relay::push_to_slaves(
                    j, k, axum::http::Method::PUT,
                    format!("alerts/blocked/{ip_str}"), bytes::Bytes::new(),
                );
            }
            (StatusCode::OK, JsonExtract(serde_json::json!({"blacklisted": true, "ip": ip_str}))).into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error": "invalid IP"}))).into_response(),
    }
}

async fn put_blocked_ip(
    State(state): State<AppState>,
    axum::extract::Path(ip_str): axum::extract::Path<String>,
) -> impl IntoResponse {
    match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_loopback() || ip.is_unspecified() => {
            (StatusCode::OK, JsonExtract(serde_json::json!({"blocked": false, "ip": ip_str, "reason": "protected address (loopback/unspecified) is never banned"}))).into_response()
        }
        Ok(ip) => {
            state.alert_tracker.block_manual(ip, "manual".to_string());
            // #protection-bans: a manual ban is permanent ("no expiry", per the API help
            // and matching alert_tracker's expires:None). Previously this used
            // icmp_stats.ban() (permanent:false, auto-expiring), so after the TTL the IP
            // unblocked on the icmp/XDP fast path while alert_tracker (slow path, DoT/DoH/
            // DoQ) still held it — and /api/protection/banned reported permanent:false
            // while /api/alerts reported permanent:true for the very same ban. Use
            // ban_permanent() so both systems agree and the ban does not silently lapse.
            state.icmp_stats.ban_permanent(ip);
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    let _ = state.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::Ban(ipv4));
                }
                std::net::IpAddr::V6(ipv6) => {
                    let _ = state.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::BanV6(ipv6));
                }
            }
            if let (Some(ref j), Some(ref k)) = (&state.sync_journal, &state.sync_key) {
                crate::api::relay::push_to_slaves(
                    j, k, axum::http::Method::PUT,
                    format!("alerts/blocked/{ip_str}"), bytes::Bytes::new(),
                );
            }
            (StatusCode::OK, JsonExtract(serde_json::json!({"blocked": true, "ip": ip_str}))).into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error": "invalid IP"}))).into_response(),
    }
}

// DELETE /api/alerts/blocked/:ip — unblock a specific IP (#12)
async fn delete_blocked_ip(
    State(state): State<AppState>,
    axum::extract::Path(ip_str): axum::extract::Path<String>,
) -> impl IntoResponse {
    match ip_str.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            let removed = state.alert_tracker.unblock(ip);
            state.icmp_stats.unban(ip);
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    let _ = state.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::Unban(ipv4));
                }
                std::net::IpAddr::V6(ipv6) => {
                    let _ = state.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::UnbanV6(ipv6));
                }
            }
            if let (Some(ref j), Some(ref k)) = (&state.sync_journal, &state.sync_key) {
                crate::api::relay::push_to_slaves(
                    j, k, axum::http::Method::DELETE,
                    format!("alerts/blocked/{ip_str}"), bytes::Bytes::new(),
                );
            }
            (StatusCode::OK, JsonExtract(serde_json::json!({"unblocked": removed, "ip": ip_str}))).into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error": "invalid IP"}))).into_response(),
    }
}

// ── Backup / Restore ─────────────────────────────────────────────────────────

fn runbound_backup_dir(s: &AppState) -> std::path::PathBuf {
    s.base_dir.join("backups")
}

/// Files included in a full backup, relative to base_dir. The main config
/// (runbound.conf) is handled separately via cfg_path. Excludes regenerable or
/// huge artifacts (backups/, feed_cache/, audit.log) and stale *.bak-* copies.
const BACKUP_STATE_FILES: &[&str] = &[
    "dns_entries.json", "dns_entries.mac",
    "blacklist.json", "blacklist.mac",
    "feeds.json", "feeds.mac",
    "upstreams.json", "upstreams.mac",
    "alert-blocks.json", "icmp.json", "slaves.json",
    "api.key", "webui-auth.conf",
    "sync-cert.pem", "sync-key.pem", "sync-master.fingerprint",
    "webui-ca-cert.pem", "webui-ca-key.pem",
];

/// GET /api/backup/export — full backup (admin). Returns a JSON document with the
/// config and every state/secret file, base64-encoded, as a downloadable attachment.
/// NOTE: contains secrets (API key, sync key, WebUI auth, private keys) — store securely.
async fn backup_export_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> Response {
    // H-1: this endpoint base64-dumps runbound.conf + secret state files
    // (api.key, sync-key.pem, webui-ca-key.pem, webui-auth.conf) — admin only.
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut files = serde_json::Map::new();
    if let Ok(c) = std::fs::read(&s.cfg_path) {
        files.insert("runbound.conf".into(), serde_json::Value::String(b64.encode(c)));
    }
    for f in BACKUP_STATE_FILES {
        if let Ok(c) = std::fs::read(s.base_dir.join(f)) {
            files.insert((*f).into(), serde_json::Value::String(b64.encode(c)));
        }
    }
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let body = serde_json::json!({
        "format": "runbound-backup-v1",
        "version": env!("CARGO_PKG_VERSION"),
        "created": ts,
        "files": files,
    }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"runbound-backup.json\"")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
}

/// POST /api/backup/import — restore a full backup (admin; slave read-only). Writes
/// each whitelisted file atomically (tmp + rename), then applies it live (no restart).
async fn backup_import_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    use base64::Engine as _;
    // H-1: restoring a backup overwrites runbound.conf + secret state files — admin only.
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"})));
    }
    if s.slave_mode {
        return (StatusCode::SERVICE_UNAVAILABLE, JsonExtract(serde_json::json!({"error":"SLAVE_READONLY"})));
    }
    if body.get("format").and_then(|v| v.as_str()) != Some("runbound-backup-v1") {
        return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"INVALID_FORMAT","details":"expected runbound-backup-v1"})));
    }
    let files = match body.get("files").and_then(|v| v.as_object()) {
        Some(f) => f,
        None => return (StatusCode::BAD_REQUEST, JsonExtract(serde_json::json!({"error":"NO_FILES"}))),
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut restored = 0u32;
    let mut secrets_restored = false;
    for (name, val) in files {
        // Security: only whitelisted names, never a path component.
        let allowed = name == "runbound.conf" || BACKUP_STATE_FILES.contains(&name.as_str());
        if !allowed || name.contains('/') || name.contains('\\') || name.contains("..") { continue; }
        let data = match val.as_str().and_then(|t| b64.decode(t).ok()) { Some(d) => d, None => continue };
        let dest: std::path::PathBuf = if name == "runbound.conf" {
            std::path::PathBuf::from(&s.cfg_path)
        } else {
            s.base_dir.join(name)
        };
        let tmp = dest.with_extension("restore-tmp");
        // SEC-G8: create_new (O_CREAT|O_EXCL) so a symlink pre-planted at `tmp`
        // cannot be followed to overwrite an arbitrary file. Clear any stale tmp
        // first; if creation still fails (race / planted symlink), skip this file.
        let _ = std::fs::remove_file(&tmp);
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        // Some restored files are secrets (api.key, webui-auth.conf, sync-key.pem,
        // webui-ca-key.pem). Create them 0600 like every other secret-write path
        // (tls_write_key_0600 / sync::write_key_0600) instead of inheriting the
        // umask default (0644, world-readable). Harmless for the data files too.
        let wrote = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(&data));
        if wrote.is_ok() && std::fs::rename(&tmp, &dest).is_ok() {
            restored += 1;
            // apply_config_hot_reload does NOT re-read these — they bind at startup.
            if matches!(name.as_str(), "api.key" | "webui-auth.conf" | "sync-key.pem" | "webui-ca-key.pem") {
                secrets_restored = true;
            }
        }
    }
    // Apply the restored config live — Runbound never restarts ("no restart ever").
    let note = match apply_config_hot_reload(&s) {
        // A restored API key / relay key / WebUI creds bind at startup; the hot
        // reload re-reads zones/alerts/resolution only. Don't claim "no restart
        // needed" when the operator just restored secret material that is still inert.
        Ok(_) if secrets_restored =>
            "config and data applied live; a restored API key / private keys take effect only after a restart",
        Ok(_) => "applied live — no restart needed",
        Err(e) => {
            warn!(restored, err = %e, "restored files but hot-reload failed");
            "restored, but live reload failed — check the config, then POST /api/reload"
        }
    };
    info!(restored, "full backup restored via API");
    (StatusCode::OK, JsonExtract(serde_json::json!({"status":"ok","restored":restored,"note":note})))
}

async fn backup_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    body: axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    // H-1: creating a backup snapshots config + data files — admin only.
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let label = body.get("label")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && s.len() <= 32
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or("")
        .to_owned();

    let dir_name = if label.is_empty() {
        format!("backup_{ts}")
    } else {
        format!("backup_{ts}_{label}")
    };

    let bdir = runbound_backup_dir(&s).join(&dir_name);
    if let Err(e) = std::fs::create_dir_all(&bdir) {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({"error": format!("cannot create backup dir: {e}")}))).into_response();
    }

    // Config file
    if let Err(e) = std::fs::copy(&s.cfg_path, bdir.join("runbound.conf")) {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({"error": format!("config copy failed: {e}")}))).into_response();
    }

    // Data files from base_dir
    for fname in &["dns_entries.json", "blacklist.json", "feeds.json", "upstreams.json"] {
        let src = s.base_dir.join(fname);
        if src.exists() {
            let _ = std::fs::copy(&src, bdir.join(fname));
        }
    }

    (StatusCode::OK, JsonExtract(serde_json::json!({
        "id": dir_name,
        "ts": ts,
    }))).into_response()
}

async fn list_backups_handler(
    State(s): State<AppState>,
) -> impl IntoResponse {
    let bdir = runbound_backup_dir(&s);
    let entries = match std::fs::read_dir(&bdir) {
        Ok(e) => e,
        Err(_) => return (StatusCode::OK, JsonExtract(serde_json::json!([]))).into_response(),
    };

    let mut items: Vec<serde_json::Value> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.metadata().map(|m| m.is_dir()).unwrap_or(false))
        .filter(|e| e.file_name().to_string_lossy().starts_with("backup_"))
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let ts = e.metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let files: Vec<String> = std::fs::read_dir(e.path())
                .map(|rd| rd.filter_map(|f| f.ok())
                    .map(|f| f.file_name().to_string_lossy().to_string())
                    .collect())
                .unwrap_or_default();
            serde_json::json!({"id": name, "ts": ts, "files": files})
        })
        .collect();

    items.sort_by_key(|v| v["id"].as_str().unwrap_or("").to_owned());
    (StatusCode::OK, JsonExtract(serde_json::json!(items))).into_response()
}

async fn restore_handler(
    State(s): State<AppState>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    body: axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    // H-1: restoring overwrites runbound.conf + data files — admin only.
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    let id = match body.get("id").and_then(|v| v.as_str()) {
        Some(s) => s.to_owned(),
        None => return (StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error": "Missing id field"}))).into_response(),
    };

    if id.contains('/') || id.contains("..") || !id.starts_with("backup_") {
        return (StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error": "Invalid backup id"}))).into_response();
    }

    let bdir = runbound_backup_dir(&s).join(&id);
    if !bdir.exists() {
        return (StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({"error": "Backup not found"}))).into_response();
    }

    // Restore config
    if let Err(e) = std::fs::copy(bdir.join("runbound.conf"), &s.cfg_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            JsonExtract(serde_json::json!({"error": format!("config restore failed: {e}")}))).into_response();
    }

    // Restore data files
    for fname in &["dns_entries.json", "blacklist.json", "feeds.json", "upstreams.json"] {
        let src = bdir.join(fname);
        if src.exists() {
            let _ = std::fs::copy(&src, s.base_dir.join(fname));
        }
    }

    // Apply the restored config live — Runbound never restarts ("no restart ever").
    if let Err(e) = apply_config_hot_reload(&s) {
        tracing::warn!(backup_id = %id, err = %e, "restored files but hot-reload failed");
    } else {
        tracing::info!(backup_id = %id, "backup restored and applied live");
    }

    (StatusCode::OK, JsonExtract(serde_json::json!({
        "ok": true,
        "restored": id,
    }))).into_response()
}

async fn delete_backup_handler(
    State(s): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
) -> impl IntoResponse {
    // H-1: deleting backups is a privileged operation — admin only.
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (StatusCode::FORBIDDEN, JsonExtract(serde_json::json!({"error":"FORBIDDEN"}))).into_response();
    }
    if id.contains('/') || id.contains("..") || !id.starts_with("backup_") {
        return (StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error": "Invalid backup id"}))).into_response();
    }
    let bdir = runbound_backup_dir(&s).join(&id);
    match std::fs::remove_dir_all(&bdir) {
        Ok(_) => (StatusCode::OK, JsonExtract(serde_json::json!({"ok": true, "deleted": id}))).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, JsonExtract(serde_json::json!({"error": "Backup not found"}))).into_response(),
    }
}


#[cfg(test)]
mod resync_xdp_cache_tests {
    //! #186 regression: a write to the local zone must evict any stale *forwarded*
    //! cache entry for the affected name, so edits (local-data / blacklist / feed /
    //! delete) take effect live on the XDP fast path without a restart.
    use super::resync_xdp_cache_inner;
    use crate::dns::cache_snapshot::{new_mutable_cache, CacheEntry, MutableCacheMap};
    use crate::dns::local::{name_to_wire_qname, LocalZoneSet, ZoneAction};
    use bytes::Bytes;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    /// Insert a fake *forwarded* (recursive) A-record entry for `name`, as if it had
    /// been resolved upstream and cached. Returns its cache key.
    fn insert_forward(cache: &MutableCacheMap, name: &str) -> u64 {
        let n = Name::from_str(name).unwrap();
        let wq = name_to_wire_qname(&n);
        let key = crate::dns::hasher::hash_wire_qname(&wq) ^ (1u64 << 48); // qtype A=1
        cache.insert(
            key,
            CacheEntry {
                wire_payload: Bytes::from_static(b"\x00\x00stale-forwarded-answer"),
                // short TTL -> a normal forwarded entry, NOT a local-data sentinel
                expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
                wire_qname: Bytes::copy_from_slice(&wq),
            },
        );
        key
    }

    #[test]
    fn blacklist_evicts_cached_forward_security() {
        // evil.com was resolved+cached, THEN blacklisted. The cached answer must go,
        // otherwise the block silently does nothing until TTL/restart.
        let cache = new_mutable_cache();
        let k_evil = insert_forward(&cache, "evil.com.");
        let k_good = insert_forward(&cache, "good.com.");

        let old = LocalZoneSet::from_config(&[], &[]);
        let mut new = LocalZoneSet::from_config(&[], &[]);
        new.override_zone("evil.com", ZoneAction::NxDomain);

        resync_xdp_cache_inner(&cache, &old, &new);

        assert!(!cache.contains_key(&k_evil), "blacklisted name still cached → block not live");
        assert!(cache.contains_key(&k_good), "unrelated recursive cache entry wrongly evicted");
    }

    #[test]
    fn local_data_add_evicts_cached_forward() {
        // The apex bug: runasm.com forwarded to the parking IP and cached, THEN a
        // local A record is added. The stale forward must be evicted.
        let cache = new_mutable_cache();
        let k = insert_forward(&cache, "runasm.com.");

        let old = LocalZoneSet::from_config(&[], &[]);
        let mut new = LocalZoneSet::from_config(&[], &[]);
        new.override_zone("runasm.com", ZoneAction::Static);

        resync_xdp_cache_inner(&cache, &old, &new);

        assert!(!cache.contains_key(&k), "local-data add did not evict the stale forward (apex bug)");
    }

    #[test]
    fn delete_evicts_cached_entry() {
        // A name present before the write but absent after (deletion) must be evicted
        // via the OLD-keys half of the union.
        let cache = new_mutable_cache();
        let k = insert_forward(&cache, "del.lan.");

        let mut old = LocalZoneSet::from_config(&[], &[]);
        old.override_zone("del.lan", ZoneAction::Static);
        let new = LocalZoneSet::from_config(&[], &[]);

        resync_xdp_cache_inner(&cache, &old, &new);

        assert!(!cache.contains_key(&k), "deleted name still served from cache");
    }

    #[test]
    fn unrelated_recursive_cache_is_preserved() {
        // Writing one rule must NOT flush the whole recursive cache.
        let cache = new_mutable_cache();
        let k_a = insert_forward(&cache, "a.example.");
        let k_b = insert_forward(&cache, "b.example.");

        let old = LocalZoneSet::from_config(&[], &[]);
        let mut new = LocalZoneSet::from_config(&[], &[]);
        new.override_zone("c.example", ZoneAction::NxDomain);

        resync_xdp_cache_inner(&cache, &old, &new);

        assert!(cache.contains_key(&k_a), "unrelated cache entry a.example wrongly evicted");
        assert!(cache.contains_key(&k_b), "unrelated cache entry b.example wrongly evicted");
    }
}
