//! Per-client DNS activity dashboard (#6).
//!
//! GET /api/clients           — list all active client IPs with aggregate stats
//! GET /api/clients/:ip       — detail for one IP: top domains + action breakdown
//! GET /api/clients/:ip/logs  — paginated log entries for one IP

use std::collections::HashMap;
use std::net::IpAddr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::logbuffer::{LogQuery, LOG_CAP};

use super::{AppState, JsonExtract};

const CLIENT_LIST_MAX: usize = 500;

// ── Serialisable output types ──────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct ClientSummary {
    ip:          String,
    total:       u64,
    blocked:     u64,
    blocked_pct: f64,
    last_seen:   String,
    top_domain:  String,
}

#[derive(Serialize)]
struct ClientDetail {
    ip:          String,
    total:       u64,
    blocked:     u64,
    blocked_pct: f64,
    last_seen:   String,
    top_domains: Vec<DomainCount>,
    actions:     ActionBreakdown,
}

#[derive(Serialize)]
struct DomainCount {
    domain: String,
    count:  u64,
}

#[derive(Serialize, Default)]
struct ActionBreakdown {
    forwarded: u64,
    cached:    u64,
    local:     u64,
    blocked:   u64,
    nxdomain:  u64,
    refused:   u64,
    servfail:  u64,
}

// ── Query params ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ClientsParams {
    #[serde(default = "default_50")]
    limit: usize,
    #[serde(default)]
    page: usize,
}
fn default_50() -> usize { 50 }

#[derive(Deserialize)]
pub struct ClientLogsParams {
    #[serde(default = "default_100")]
    limit: usize,
    #[serde(default)]
    page: usize,
}
fn default_100() -> usize { 100 }

// ── Internal aggregation helper ────────────────────────────────────────────

struct IpAgg {
    total:       u64,
    blocked:     u64,
    last_seen:   String,   // ISO 8601 UTC — lexicographic max = most recent
    domain_freq: HashMap<String, u64>,
    actions:     ActionBreakdown,
}

impl IpAgg {
    fn new() -> Self {
        Self {
            total: 0,
            blocked: 0,
            last_seen: String::new(),
            domain_freq: HashMap::new(),
            actions: ActionBreakdown::default(),
        }
    }

    fn record(&mut self, action: &str, name: &str, ts: &str) {
        self.total += 1;
        // entries arrive newest-first; keep the max ts string
        if ts > self.last_seen.as_str() {
            self.last_seen = ts.to_owned();
        }
        // Cap unique domains tracked per IP: a flood of random subdomains (remote,
        // pre-auth) followed by an admin viewing this IP must not grow an unbounded map.
        if self.domain_freq.len() < 50_000 || self.domain_freq.contains_key(name) {
            *self.domain_freq.entry(name.to_owned()).or_insert(0) += 1;
        }
        match action {
            "forwarded" => self.actions.forwarded += 1,
            "cached"    => self.actions.cached    += 1,
            "local"     => self.actions.local     += 1,
            "blocked"   => { self.actions.blocked += 1; self.blocked += 1; }
            "nxdomain"  => self.actions.nxdomain  += 1,
            "refused"   => self.actions.refused   += 1,
            "servfail"  => self.actions.servfail  += 1,
            _ => {}
        }
    }

    fn top_domain(&self) -> String {
        self.domain_freq.iter()
            .max_by_key(|(_, &c)| c)
            .map(|(d, _)| d.clone())
            .unwrap_or_default()
    }

    fn blocked_pct(&self) -> f64 {
        if self.total == 0 { 0.0 } else { (self.blocked as f64 / self.total as f64) * 100.0 }
    }

    fn top_domains(&self, n: usize) -> Vec<DomainCount> {
        let mut v: Vec<DomainCount> = self.domain_freq.iter()
            .map(|(d, &c)| DomainCount { domain: d.clone(), count: c })
            .collect();
        v.sort_unstable_by(|a, b| b.count.cmp(&a.count));
        v.truncate(n);
        v
    }
}

fn build_agg(s: &AppState) -> HashMap<String, IpAgg> {
    let q = LogQuery { limit: LOG_CAP, page: 0, action: None, client: None, since_secs: None };
    let (entries, _) = s.log_buffer.query(&q);
    let mut map: HashMap<String, IpAgg> = HashMap::new();
    for e in &entries {
        if e.client == "[redacted]" || e.client.is_empty() { continue; }
        map.entry(e.client.clone()).or_insert_with(IpAgg::new)
            .record(&e.action, &e.name, &e.ts);
    }
    map
}

// ── GET /api/clients ───────────────────────────────────────────────────────

static CLIENTS_CACHE: std::sync::OnceLock<std::sync::Mutex<Option<(std::time::Instant, Vec<ClientSummary>)>>> =
    std::sync::OnceLock::new();

pub async fn clients_handler(
    State(s): State<AppState>,
    params_result: Result<Query<ClientsParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(p) = match params_result {
        Ok(q) => q,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"INVALID_PARAM","details":e.to_string()})),
        ).into_response(),
    };
    if p.limit > CLIENT_LIST_MAX {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            JsonExtract(serde_json::json!({"error":"INVALID_PARAM","details":format!("limit must be <= {}", CLIENT_LIST_MAX)})),
        ).into_response();
    }

    // OPEN-I17: the full log-buffer scan + aggregation is bounded but expensive; memoize
    // the sorted result for a short window so repeated authenticated requests cannot spin
    // the CPU re-scanning on every call.
    let mut summaries: Vec<ClientSummary> = {
        let cache = CLIENTS_CACHE.get_or_init(|| std::sync::Mutex::new(None));
        let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some((t, v)) if t.elapsed() < std::time::Duration::from_secs(2) => v.clone(),
            _ => {
                let agg = build_agg(&s);
                let mut v: Vec<ClientSummary> = agg.into_iter().map(|(ip, a)| ClientSummary {
                    ip,
                    total:       a.total,
                    blocked:     a.blocked,
                    blocked_pct: a.blocked_pct(),
                    last_seen:   a.last_seen.clone(),
                    top_domain:  a.top_domain(),
                }).collect();
                v.sort_unstable_by(|x, y| y.total.cmp(&x.total).then(x.ip.cmp(&y.ip)));
                *guard = Some((std::time::Instant::now(), v.clone()));
                v
            }
        }
    };

    let total = summaries.len();
    let start = p.page.saturating_mul(p.limit).min(total); // no overflow on huge page
    let end   = (start + p.limit).min(total);
    let page  = summaries.drain(start..end).collect::<Vec<_>>();

    JsonExtract(serde_json::json!({"clients":page,"total":total,"page":p.page,"limit":p.limit})).into_response()
}

// ── GET /api/clients/:ip ───────────────────────────────────────────────────

pub async fn client_detail_handler(
    State(s): State<AppState>,
    Path(ip_str): Path<String>,
) -> Response {
    let ip: IpAddr = match ip_str.parse() {
        Ok(i) => i,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"INVALID_PARAM","details":"not a valid IP address"})),
        ).into_response(),
    };

    let q = LogQuery { limit: LOG_CAP, page: 0, action: None, client: Some(ip), since_secs: None };
    let (entries, total) = s.log_buffer.query(&q);
    if total == 0 {
        return (
            StatusCode::NOT_FOUND,
            JsonExtract(serde_json::json!({"error":"NOT_FOUND","details":format!("no log entries for {}", ip_str)})),
        ).into_response();
    }

    let mut agg = IpAgg::new();
    for e in &entries {
        agg.record(&e.action, &e.name, &e.ts);
    }

    let detail = ClientDetail {
        ip:          ip_str,
        total:       agg.total,
        blocked:     agg.blocked,
        blocked_pct: agg.blocked_pct(),
        last_seen:   agg.last_seen.clone(),
        top_domains: agg.top_domains(20),
        actions:     agg.actions,
    };

    JsonExtract(serde_json::json!(detail)).into_response()
}

// ── GET /api/clients/:ip/logs ──────────────────────────────────────────────

pub async fn client_logs_handler(
    State(s): State<AppState>,
    Path(ip_str): Path<String>,
    params_result: Result<Query<ClientLogsParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let ip: IpAddr = match ip_str.parse() {
        Ok(i) => i,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"INVALID_PARAM","details":"not a valid IP address"})),
        ).into_response(),
    };

    let Query(p) = match params_result {
        Ok(q) => q,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            JsonExtract(serde_json::json!({"error":"INVALID_PARAM","details":e.to_string()})),
        ).into_response(),
    };
    let limit = p.limit.min(1000);

    let q = LogQuery { limit, page: p.page, action: None, client: Some(ip), since_secs: None };
    let (entries, total) = s.log_buffer.query(&q);

    JsonExtract(serde_json::json!({
        "entries": entries,
        "total":   total,
        "page":    p.page,
        "limit":   limit,
        "client":  ip_str,
    })).into_response()
}
