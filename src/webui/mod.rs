use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use axum::{
    body::Body,
    extract::{ConnectInfo, Form, State},
    http::{header, HeaderMap, Request, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post},
    Router,
};
use dashmap::DashMap;
use futures_util::StreamExt as _;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;
use crate::alerts::AlertTracker;
use crate::icmp::IcmpBanCmd;
use crate::sync::{SyncJournal, SyncOp};

static INDEX_HTML: &str = include_str!("index.html");
static INDEX_HTML_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/index.html.gz"));
static SECURITY_AUDIT_MD: &str = include_str!("../../docs/security-audit/SECURITY-AUDIT.md");

#[derive(Clone, serde::Serialize)]
struct AuthEvent {
    ts: u64,
    event: &'static str,
    user: String,
    ip: String,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
const CRED_FILE: &str = "webui-auth.conf";

#[derive(Clone)]
pub struct WebUiState {
    api_port: u16,
    api_key:  String,
    client:   reqwest::Client,
    /// Sessions: session_token → (expiry, csrf_token). SEC-19: csrf stored per session.
    sessions: Arc<DashMap<String, (Instant, String)>>,
    creds:    Arc<std::sync::Mutex<WebUiCred>>,
    auth_path: PathBuf,
    auth_events: Arc<std::sync::Mutex<std::collections::VecDeque<AuthEvent>>>,
    /// SEC-A1: per-IP login failure tracker — (failure_count, window_start).
    login_rl: Arc<DashMap<std::net::IpAddr, (u32, Instant)>>,
    /// Local CA cert PEM served at /webui/ca.crt. Empty when TLS disabled.
    ca_cert_pem: Arc<String>,
    // ── Bot defense ──────────────────────────────────────────────────────────
    pub alert_tracker: Arc<AlertTracker>,
    pub ban_cmd_tx: tokio::sync::mpsc::UnboundedSender<IcmpBanCmd>,
    pub sync_journal: Option<Arc<SyncJournal>>,
    pub bot_ban_duration_secs: u64,
    pub bot_honeypot_enabled: bool,
    /// Per-IP bad-request burst tracker: (count, window_start).
    burst_tracker: Arc<DashMap<IpAddr, (u64, Instant), ahash::RandomState>>,
    /// True when the WebUI is serving TLS directly (not behind a reverse proxy).
    tls_enabled: bool,
}

struct WebUiCred {
    username: String,
    hash:     String, // argon2id encoded string
}

pub fn router(
    api_port: u16,
    api_key: String,
    base_dir: PathBuf,
    ca_cert_pem: String,
    alert_tracker: Arc<AlertTracker>,
    ban_cmd_tx: tokio::sync::mpsc::UnboundedSender<IcmpBanCmd>,
    sync_journal: Option<Arc<SyncJournal>>,
    bot_ban_duration_secs: u64,
    bot_honeypot_enabled: bool,
    tls_enabled: bool,
) -> Router {
    let auth_path = base_dir.join(CRED_FILE);
    let creds = load_or_default_creds(&auth_path);
    let state = Arc::new(WebUiState {
        api_port,
        api_key,
        client: reqwest::Client::builder()
            .pool_max_idle_per_host(8)
            .build()
            .expect("reqwest client"),
        sessions: Arc::new(DashMap::new()),
        creds: Arc::new(std::sync::Mutex::new(creds)),
        auth_path,
        auth_events: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::with_capacity(100))),
        login_rl: Arc::new(DashMap::new()),
        ca_cert_pem: Arc::new(ca_cert_pem),
        alert_tracker,
        ban_cmd_tx,
        sync_journal,
        bot_ban_duration_secs,
        bot_honeypot_enabled,
        burst_tracker: Arc::new(DashMap::with_hasher(ahash::RandomState::default())),
        tls_enabled,
    });
    // SEC-B10: periodic cleanup of expired sessions (every 5 minutes).
    {
        let sessions = Arc::clone(&state.sessions);
        let login_rl = Arc::clone(&state.login_rl);
        let burst_tracker_ref = Arc::clone(&state.burst_tracker);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                sessions.retain(|_, (exp, _)| std::time::Instant::now() < *exp);
                login_rl.retain(|_, (_, since)| since.elapsed().as_secs() < 120);
                // Evict burst tracker entries older than 60 s (window is 5 s; these are long stale).
                let burst_cutoff = Instant::now() - Duration::from_secs(60);
                burst_tracker_ref.retain(|_, (_, ts)| *ts > burst_cutoff);
            }
        });
    }
    Router::new()
        .route("/", get(serve_dashboard))
        .route("/login",  get(serve_login).post(handle_login))
        .route("/logout", get(handle_logout).post(handle_logout))
        .route("/api/webui/password", post(change_password))
        .route("/favicon.ico", get(serve_favicon))
        .route("/webui/auth-events", get(auth_events_handler))
        .route("/api/webui/auth-events", get(auth_events_handler))
        .route("/webui/ca.crt", get(serve_ca_cert))
        .route("/webui/security-audit", get(serve_security_audit))
        .route("/api",       any(proxy_api))
        .route("/api/*path", any(proxy_api))
        // Bot defense: scanner trap routes
        .route("/wp-admin",  any(bot_trap_handler))
        .route("/wp-admin/*path",  any(bot_trap_handler))
        .route("/.env",  any(bot_trap_handler))
        .route("/.git/config",  any(bot_trap_handler))
        .route("/.git/*path",  any(bot_trap_handler))
        .route("/phpmyadmin",  any(bot_trap_handler))
        .route("/phpmyadmin/*path",  any(bot_trap_handler))
        .route("/xmlrpc.php",  any(bot_trap_handler))
        .route("/admin",  any(bot_trap_handler))
        .route("/administrator",  any(bot_trap_handler))
        .route("/config.php",  any(bot_trap_handler))
        .route("/wp-login.php",  any(bot_trap_handler))
        .route("/cgi-bin/*path",  any(bot_trap_handler))
        .route("/shell",  any(bot_trap_handler))
        .route("/cmd",  any(bot_trap_handler))
        .route("/.aws/credentials",  any(bot_trap_handler))
        .route("/actuator/*path",  any(bot_trap_handler))
        .route("/console",  any(bot_trap_handler))
        .route("/manager/*path",  any(bot_trap_handler))
        .with_state(state)
}

fn load_or_default_creds(path: &PathBuf) -> WebUiCred {
    if let Ok(content) = std::fs::read_to_string(path) {
        #[derive(Deserialize)]
        struct CredsFile { username: String, hash: String }
        if let Ok(c) = serde_json::from_str::<CredsFile>(&content) {
            if !c.hash.is_empty() {
                return WebUiCred { username: c.username, hash: c.hash };
            }
        }
    }
    // Default: admin/admin
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(b"admin", &salt)
        .expect("argon2 hash")
        .to_string();
    WebUiCred { username: "admin".to_string(), hash }
}

/// SEC-19: Extract CSRF token for a validated session.
fn session_csrf(state: &WebUiState, headers: &HeaderMap) -> Option<String> {
    let token = session_token(headers)?;
    let entry = state.sessions.get(&token)?;
    let (exp, csrf) = entry.value();
    if Instant::now() < *exp { Some(csrf.clone()) } else { None }
}

/// SEC-19: Verify X-CSRF-Token header matches the session's stored CSRF token.
fn verify_csrf(state: &WebUiState, headers: &HeaderMap) -> bool {
    let expected = match session_csrf(state, headers) {
        Some(t) => t,
        None => return false,
    };
    headers.get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map_or(false, |actual| expected == actual)
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("cookie")?.to_str().ok()?;
    v.split(';').find_map(|s| s.trim().strip_prefix("rb_session=").map(|t| t.to_string()))
}

fn is_authenticated(state: &WebUiState, headers: &HeaderMap) -> bool {
    let token = match session_token(headers) { Some(t) => t, None => return false };
    if let Some(entry) = state.sessions.get(&token) {
        let (exp, _csrf) = &*entry;
        if Instant::now() < *exp { return true; }
        drop(entry);
        state.sessions.remove(&token);
    }
    false
}

async fn serve_dashboard(State(state): State<Arc<WebUiState>>, req: Request<Body>) -> Response {
    if !is_authenticated(&state, req.headers()) {
        return Redirect::to("/login").into_response();
    }
    let accepts_gzip = req.headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("gzip"))
        .unwrap_or(false);
    if accepts_gzip {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
            .body(Body::from(INDEX_HTML_GZ))
            .unwrap_or_else(|_| Html(INDEX_HTML).into_response())
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
            .body(Body::from(INDEX_HTML))
            .unwrap_or_else(|_| Html(INDEX_HTML).into_response())
    }
}


const LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Runbound — Sign in</title>
  <link rel="icon" href="/favicon.ico"/>
  <style>
    @keyframes glow-pulse{{0%,100%{{opacity:.6}}50%{{opacity:1}}}}
    @keyframes fade-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
    @keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:0}}}}
    body{color:#e2e8f0;font-family:'SF Mono','Fira Code','Consolas',monospace;background-color:#060b14;background-image:radial-gradient(circle at 1px 1px,rgba(34,211,238,.055) 1px,transparent 0);background-size:30px 30px;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;overflow:hidden;position:relative}
    body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 150% 65% at 50% -20%,rgba(14,102,128,.28) 0%,transparent 62%);pointer-events:none;animation:glow-pulse 6s ease-in-out infinite}
    body::after{content:'';position:fixed;bottom:-20%;left:50%;transform:translateX(-50%);width:60%;height:40%;background:radial-gradient(ellipse at center,rgba(14,102,128,.08) 0%,transparent 70%);pointer-events:none;animation:glow-pulse 8s ease-in-out infinite reverse}
    .card{position:relative;z-index:1;background:rgba(6,11,20,.94);backdrop-filter:blur(14px);border:1px solid rgba(34,211,238,.1);border-top:1px solid rgba(34,211,238,.28);border-radius:12px;padding:38px;width:100%;max-width:380px;box-sizing:border-box;margin:0 16px;box-shadow:0 32px 64px rgba(0,0,0,.65),0 0 0 1px rgba(34,211,238,.03);animation:fade-in .35s ease-out}
    .logo{color:#22d3ee;font-size:20px;font-weight:700;letter-spacing:.14em;display:inline-block}
    .cursor{display:inline-block;color:#22d3ee;animation:blink 1.1s step-end infinite;margin-left:1px}
    label{display:block;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.12em;margin-bottom:7px}
    input{display:block;width:100%;background:#0f172a;border:1px solid #1e293b;border-radius:6px;padding:9px 13px;font-size:13px;outline:none;box-sizing:border-box;color:#e2e8f0;font-family:inherit;margin:0;transition:border-color .15s,box-shadow .15s}
    input:focus{border-color:#0e7490;box-shadow:0 0 0 2px rgba(8,145,178,.15)}
    input:-webkit-autofill,input:-webkit-autofill:hover,input:-webkit-autofill:focus,input:-webkit-autofill:active{-webkit-text-fill-color:#e2e8f0 !important;-webkit-box-shadow:0 0 0px 1000px #0f172a inset !important;transition:background-color 5000s ease-in-out 0s;caret-color:#e2e8f0}
    button{display:block;width:100%;background:#0e4f63;color:#e2e8f0;border:1px solid #0e6680;border-radius:6px;padding:10px 14px;cursor:pointer;font-size:13px;font-family:inherit;font-weight:600;transition:background .15s;margin-top:8px}
    button:hover{background:#0f6b89}
  </style>
</head>
<body>
  <div class="card">
    <div style="text-align:center;margin-bottom:34px">
      <div><span class="logo">RUNBOUND</span><span class="cursor">_</span></div>
      <div style="color:#152a38;font-size:10px;margin-top:7px;letter-spacing:.18em">MANAGEMENT CONSOLE</div>
    </div>
    <form method="POST" action="/login">
      <input type="text" name="username" value="" autocomplete="off" tabindex="-1" aria-hidden="true" style="display:none;position:absolute;left:-9999px;opacity:0;height:0;width:0;" />
      <input type="password" name="password" value="" autocomplete="off" tabindex="-1" aria-hidden="true" style="display:none;position:absolute;left:-9999px;opacity:0;height:0;width:0;" />
      <div style="margin-bottom:16px">
        <label for="u">Username</label>
        <input id="u" name="rb_user" type="text" autocomplete="username" autofocus class="input w-full"/>
      </div>
      <div style="margin-bottom:26px">
        <label for="p">Password</label>
        <input id="p" name="rb_pass" type="password" autocomplete="current-password" class="input w-full"/>
      </div>
      <button type="submit" class="btn-primary w-full mt-2">Sign in →</button>
    </form>
    <div id="err" style="color:#f87171;font-size:12px;text-align:center;margin-top:16px;min-height:16px"></div>
    <div style="color:#0c1a24;font-size:10px;text-align:center;margin-top:26px">Delete webui-auth.conf to reset credentials</div>
  </div>
  <script>
    const e=new URLSearchParams(location.search).get('err');
    if(e)document.getElementById('err').textContent=decodeURIComponent(e);
    document.getElementById('u').focus();
  </script>
</body>
</html>"#;

async fn serve_favicon() -> impl axum::response::IntoResponse {
    static FAVICON: &[u8] = include_bytes!("favicon.ico");
    ([(axum::http::header::CONTENT_TYPE, "image/x-icon")], FAVICON)
}

async fn serve_ca_cert(State(state): State<Arc<WebUiState>>) -> Response {
    if state.ca_cert_pem.is_empty() {
        return (StatusCode::NOT_FOUND, "TLS not enabled").into_response();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-pem-file")
        .header(header::CONTENT_DISPOSITION, r#"attachment; filename="runbound-ca.pem""#)
        .body(Body::from(state.ca_cert_pem.as_ref().clone()))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
}

async fn serve_security_audit() -> impl IntoResponse {
    let md = SECURITY_AUDIT_MD;
    let html = format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Runbound — Security Audit</title>
  <style>
    :root{{--bg:#050d18;--bg2:#0e1e2e;--accent:#67e8f9;--text:#d1d5db;--muted:#6b7280;--border:#1e3a5f;--green:#4ade80;--red:#f87171;--yellow:#fbbf24}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.7;padding:2rem 1rem}}
    .wrap{{max-width:900px;margin:0 auto}}
    h1{{color:var(--accent);font-size:1.6rem;margin-bottom:.3rem;letter-spacing:.04em}}
    h2{{color:var(--accent);font-size:1.15rem;margin:2rem 0 .7rem;border-bottom:1px solid var(--border);padding-bottom:.3rem}}
    h3{{color:#93c5fd;font-size:1rem;margin:1.2rem 0 .4rem}}
    h4{{color:#c084fc;font-size:.9rem;margin:1rem 0 .3rem}}
    p{{margin:.4rem 0}}
    a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
    code{{background:var(--bg2);border:1px solid var(--border);border-radius:3px;padding:1px 5px;font-family:'Courier New',monospace;font-size:.85em;color:#e2e8f0}}
    pre{{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:1rem;overflow-x:auto;margin:.6rem 0}}
    pre code{{background:none;border:none;padding:0;font-size:.82em}}
    table{{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.85em}}
    th{{background:var(--bg2);color:var(--accent);border:1px solid var(--border);padding:.35rem .7rem;text-align:left}}
    td{{border:1px solid var(--border);padding:.3rem .7rem;vertical-align:top}}
    tr:nth-child(even) td{{background:#08121e}}
    ul,ol{{margin:.3rem 0 .3rem 1.5rem}}
    li{{margin:.15rem 0}}
    hr{{border:none;border-top:1px solid var(--border);margin:1.5rem 0}}
    blockquote{{border-left:3px solid var(--border);padding:.3rem 1rem;color:var(--muted);margin:.4rem 0}}
    .badge-fixed{{color:var(--green);font-weight:600}}
    .badge-open{{color:var(--yellow);font-weight:600}}
    .badge-accepted{{color:var(--muted);font-weight:600}}
    .badge-disputed{{color:#a78bfa;font-weight:600}}
    .header-bar{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:1rem 1.2rem;margin-bottom:1.5rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem}}
    .back{{font-size:.8rem;color:var(--muted);border:1px solid var(--border);border-radius:4px;padding:.3rem .8rem;cursor:pointer;background:transparent;color:var(--accent)}}
    .back:hover{{background:var(--bg2)}}
  </style>
</head>
<body>
<div class="wrap">
  <div class="header-bar">
    <div>
      <div style="color:var(--accent);font-weight:700;font-size:1rem;letter-spacing:.06em">RUNBOUND — Security Audit</div>
      <div style="color:var(--muted);font-size:.75rem;margin-top:.2rem">Consolidated findings — all cycles</div>
    </div>
    <button class="back" onclick="history.back()">← Back to dashboard</button>
  </div>
  <div id="content"></div>
</div>
<script>
const raw = {md_json};

function esc(s){{return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}
function badge(s){{
  if(/✅/.test(s)) return s.replace(/✅/g,'<span class="badge-fixed">✅</span>');
  if(/⏳/.test(s)) return s.replace(/⏳/g,'<span class="badge-open">⏳</span>');
  if(/⚠️/.test(s)) return s.replace(/⚠️/g,'<span class="badge-accepted">⚠️</span>');
  if(/🔄/.test(s)) return s.replace(/🔄/g,'<span class="badge-disputed">🔄</span>');
  return s;
}}
function md(text){{
  let lines = text.split('\n');
  let out = '';
  let inPre = false;
  let inTable = false;
  let tableHeader = false;
  for(let i=0;i<lines.length;i++){{
    let l = lines[i];
    if(l.startsWith('```')){{
      if(inPre){{out+='</code></pre>\n';inPre=false;}}
      else{{
        let lang=l.slice(3).trim();
        out+=`<pre><code class="lang-${{lang}}">`; inPre=true;
      }}
      continue;
    }}
    if(inPre){{out+=esc(l)+'\n';continue;}}
    // Table detection
    if(/^\|/.test(l)){{
      if(!inTable){{out+='<table>\n<thead>\n<tr>'; inTable=true; tableHeader=true;}}
      else if(/^\|[-:| ]+\|/.test(l)){{out+='</tr>\n</thead>\n<tbody>\n';tableHeader=false;continue;}}
      else{{out+='<tr>';}}
      let cells=l.split('|').slice(1,-1);
      let tag=tableHeader?'th':'td';
      cells.forEach(c=>{{out+=`<${{tag}}>${{inlinemd(badge(c.trim()))}}</${{tag}}>`;}});
      out+='</tr>\n'; continue;
    }}else if(inTable){{out+='</tbody></table>\n';inTable=false;}}
    if(/^#{{1,4}} /.test(l)){{
      let m=l.match(/^(#+) (.*)/);
      let lvl=m[1].length;
      out+=`<h${{lvl}}>${{inlinemd(badge(m[2]))}}</h${{lvl}}>
`;
    }} else if(/^---+$/.test(l)){{
      out+='<hr>\n';
    }} else if(/^> /.test(l)){{
      out+=`<blockquote>${{inlinemd(l.slice(2))}}</blockquote>
`;
    }} else if(/^[\*\-] /.test(l)){{
      out+=`<li>${{inlinemd(l.slice(2))}}</li>
`;
    }} else if(/^\d+\. /.test(l)){{
      out+=`<li>${{inlinemd(l.replace(/^\d+\. /,''))}}</li>
`;
    }} else if(l.trim()===''){{
      out+='\n';
    }} else {{
      out+=`<p>${{inlinemd(badge(l))}}</p>
`;
    }}
  }}
  if(inTable) out+='</tbody></table>\n';
  if(inPre) out+='</code></pre>\n';
  return out;
}}
function inlinemd(s){{
  s=badge(s);
  s=s.replace(/`([^`]+)`/g,'<code>$1</code>');
  s=s.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
  s=s.replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2">$1</a>');
  return s;
}}
document.getElementById('content').innerHTML = md(raw);
</script>
</body>
</html>"##,
        md_json = serde_json::to_string(md).unwrap_or_default()
    );
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}


async fn serve_login() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

#[derive(Deserialize)]
struct LoginForm {
    rb_user: String,
    rb_pass: String,
    // Honeypot fields — must be empty (bots fill these)
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

async fn handle_login(
    State(state): State<Arc<WebUiState>>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let client_ip_addr = connect_info
        .map(|ConnectInfo(a)| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let client_ip = client_ip_addr.to_string();
    // SEC-A1/SEC-B5: atomic rate-limit — pre-increment inside the shard lock to prevent
    // concurrent-request bypass. On success, entry is removed (reset). On failure, count stays.
    {
        let now = Instant::now();
        let mut entry = state.login_rl.entry(client_ip_addr).or_insert((0u32, now));
        let (count, since) = &mut *entry;
        if since.elapsed().as_secs() >= 60 { *count = 0; *since = now; }
        if *count >= 5 {
            tracing::warn!(ip = %client_ip, "WebUI login rate-limited");
            return (StatusCode::TOO_MANY_REQUESTS, Html("<h1>Too many attempts. Try again in a minute.</h1>")).into_response();
        }
        *count += 1; // Pre-increment atomically — prevents concurrent bypass
    }
    // Bot defense: honeypot check
    if state.bot_honeypot_enabled && (!form.username.is_empty() || !form.password.is_empty()) {
        ban_bot(&state, client_ip_addr, "bot-honeypot").await;
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    let ok = {
        let creds = state.creds.lock().unwrap_or_else(|e| e.into_inner());
        if creds.username != form.rb_user { false }
        else {
            match PasswordHash::new(&creds.hash) {
                Ok(h) => Argon2::default().verify_password(form.rb_pass.as_bytes(), &h).is_ok(),
                Err(_) => false,
            }
        }
    };
    if !ok {
        tracing::warn!(user = %form.rb_user, ip = %client_ip, "WebUI login FAILED — invalid credentials");
        push_auth_event(&state, "login_fail", &form.rb_user, &client_ip);
        if track_bad_request(&state, client_ip_addr) {
            ban_bot(&state, client_ip_addr, "bot-burst").await;
        }
        return Redirect::to("/login?err=Invalid%20credentials").into_response();
    }
    // Success — reset rate limit
    state.login_rl.remove(&client_ip_addr);
    // Purge expired sessions before adding a new one
    state.sessions.retain(|_, (exp, _)| Instant::now() < *exp);
    let token = uuid::Uuid::new_v4().to_string();
    // SEC-19: generate CSRF token, stored alongside session expiry.
    let csrf_token = uuid::Uuid::new_v4().to_string().replace('-', "");
    state.sessions.insert(token.clone(), (Instant::now() + SESSION_TTL, csrf_token.clone()));
    tracing::info!(user = %form.rb_user, ip = %client_ip, "WebUI login successful");
    push_auth_event(&state, "login_ok", &form.rb_user, &client_ip);
    // SEC-A2: add Secure flag when TLS is active (direct or via reverse proxy).
    let forwarded_https = headers.get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false);
    let secure = state.tls_enabled || forwarded_https;
    let secure_attr = if secure { "; Secure" } else { "" };
    let cookie_session = format!(
        "rb_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{secure_attr}",
        SESSION_TTL.as_secs()
    );
    // rb_csrf is NOT HttpOnly — JS reads it to add X-CSRF-Token header (SEC-19 double-submit).
    let cookie_csrf = format!(
        "rb_csrf={csrf_token}; Path=/; SameSite=Lax; Max-Age={}{secure_attr}",
        SESSION_TTL.as_secs()
    );
    Response::builder()
        .status(303)
        .header(header::LOCATION, "/")
        .header(header::SET_COOKIE, cookie_session)
        .header(header::SET_COOKIE, cookie_csrf)
        .body(Body::empty())
        .unwrap()
}

async fn handle_logout(
    State(state): State<Arc<WebUiState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
) -> Response {
    let client_ip = addr.ip().to_string();
    if let Some(token) = session_token(req.headers()) {
        state.sessions.remove(&token);
        tracing::info!(ip = %client_ip, "WebUI logout");
        push_auth_event(&state, "logout", "", &client_ip);
    }
    (
        [(header::SET_COOKIE, "rb_session=; Path=/; HttpOnly; Max-Age=0")],
        Redirect::to("/login"),
    ).into_response()
}

// POST /api/webui/password — change WebUI credentials (authenticated)
#[derive(Deserialize)]
struct ChangePasswordPayload { username: String, password: String }

async fn change_password(
    State(state): State<Arc<WebUiState>>,
    headers: HeaderMap,
    axum::extract::Json(payload): axum::extract::Json<ChangePasswordPayload>,
) -> Response {
    if !is_authenticated(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    }
    // SEC-19: verify CSRF token on password change.
    if !verify_csrf(&state, &headers) {
        return (StatusCode::FORBIDDEN, "CSRF token invalid or missing").into_response();
    }
    if payload.username.trim().is_empty() || payload.password.len() < 12 {
        return (StatusCode::BAD_REQUEST, "username required; password min 12 chars").into_response();
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = match Argon2::default().hash_password(payload.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "hash error").into_response(),
    };
    let body = serde_json::json!({ "username": payload.username, "hash": hash }).to_string();
    if let Err(e) = std::fs::write(&state.auth_path, &body) {
        warn!(err=%e, "failed to write webui-auth.conf");
        return (StatusCode::INTERNAL_SERVER_ERROR, "write failed").into_response();
    }
    *state.creds.lock().unwrap_or_else(|e| e.into_inner()) = WebUiCred {
        username: payload.username, hash,
    };
    // SEC-25: invalidate all sessions on password change
    state.sessions.clear();
    (StatusCode::OK, "{}").into_response()
}

fn push_auth_event(state: &WebUiState, event: &'static str, user: &str, ip: &str) {
    let mut q = state.auth_events.lock().unwrap_or_else(|e| e.into_inner());
    if q.len() >= 100 { q.pop_front(); }
    q.push_back(AuthEvent { ts: now_unix(), event, user: user.to_string(), ip: ip.to_string() });
}

async fn auth_events_handler(State(state): State<Arc<WebUiState>>, req: Request<Body>) -> Response {
    if !is_authenticated(&state, req.headers()) {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    }
    let q = state.auth_events.lock().unwrap_or_else(|e| e.into_inner());
    let events: Vec<&AuthEvent> = q.iter().collect();
    axum::Json(serde_json::json!({"events": events})).into_response()
}

async fn proxy_api(State(state): State<Arc<WebUiState>>, req: Request<Body>) -> Response {
    if !is_authenticated(&state, req.headers()) {
        return (StatusCode::UNAUTHORIZED, r#"{"error":"not authenticated"}"#).into_response();
    }
    let method  = req.method().clone();
    // SEC-B14: require CSRF token for all state-changing methods forwarded to the API.
    if matches!(method, axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::DELETE | axum::http::Method::PATCH) {
        if !verify_csrf(&state, req.headers()) {
            return (StatusCode::FORBIDDEN, r#"{"error":"invalid CSRF token"}"#).into_response();
        }
    }
    let uri     = req.uri().clone();
    let headers = req.headers().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), 65_536).await {
        Ok(b)  => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "request too large").into_response(),
    };
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let target = format!("http://127.0.0.1:{}{}", state.api_port, path_and_query);
    let rmethod = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return (StatusCode::METHOD_NOT_ALLOWED, "bad method").into_response(),
    };
    let mut builder = state.client.request(rmethod, &target);
    // Inject API key; always strip any browser-sent Authorization
    builder = builder.header("Authorization", format!("Bearer {}", state.api_key));
    for (name, value) in &headers {
        let n = name.as_str();
        if matches!(n, "host" | "transfer-encoding" | "content-length" | "authorization") {
            continue;
        }
        builder = builder.header(n, value.as_bytes());
    }
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.to_vec());
    }
    match builder.send().await {
        Err(e) => {
            warn!(err=%e, "webui proxy error");
            (StatusCode::BAD_GATEWAY, format!("proxy: {e}")).into_response()
        }
        Ok(upstream) => {
            let status = StatusCode::from_u16(upstream.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut rb = axum::http::Response::builder().status(status);
            for (name, value) in upstream.headers() {
                if name.as_str() == "transfer-encoding" { continue; }
                rb = rb.header(name.as_str(), value.as_bytes());
            }
            let stream = upstream.bytes_stream()
                .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())));
            rb.body(Body::from_stream(stream))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
        }
    }
}


// ── Bot defense helpers ───────────────────────────────────────────────────────

/// Ban an IP via the alert tracker + XDP BPF map + sync journal.
async fn ban_bot(state: &WebUiState, ip: std::net::IpAddr, rule: &str) {
    // Never ban loopback or RFC-1918 addresses â would lock out the server itself.
    let skip = match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || {
            let s = v6.segments();
            // fc00::/7 â unique local
            (s[0] & 0xfe00) == 0xfc00
        },
    };
    if skip {
        tracing::debug!(ip = %ip, rule = rule, "bot defense: skipping ban for loopback/private IP");
        return;
    }
    if state.alert_tracker.is_blocked(ip) {
        return; // already banned
    }
    state.alert_tracker.block_bot(ip, rule, state.bot_ban_duration_secs);
    if let std::net::IpAddr::V4(ipv4) = ip {
        let _ = state.ban_cmd_tx.send(IcmpBanCmd::Ban(ipv4));
    }
    if let Some(journal) = &state.sync_journal {
        journal.push(SyncOp::AddGlobalBan {
            ip: ip.to_string(),
            rule: rule.to_string(),
            expires_secs: Some(state.bot_ban_duration_secs),
        });
    }
    tracing::warn!(ip = %ip, rule = rule, "bot defense: IP banned");
}

/// Track a bad request (failed login / scanner hit) for a given IP.
/// Returns true if the burst threshold (10 in 5s) has been reached.
fn track_bad_request(state: &WebUiState, ip: std::net::IpAddr) -> bool {
    let now = Instant::now();
    let threshold = 10u64;
    let window = Duration::from_secs(5);

    let mut entry = state.burst_tracker.entry(ip).or_insert((0u64, now));
    if now.duration_since(entry.1) > window {
        *entry = (1, now);
        false
    } else {
        entry.0 += 1;
        entry.0 >= threshold
    }
}

/// Catch-all handler for known scanner/bot paths (wp-admin, .env, .git, etc.).
async fn bot_trap_handler(
    State(state): State<Arc<WebUiState>>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
) -> impl IntoResponse {
    let ip = connect_info
        .map(|ConnectInfo(a)| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    ban_bot(&state, ip, "bot-scanner").await;
    (StatusCode::NOT_FOUND, "Not Found")
}

// ── WebUI TLS cert management ────────────────────────────────────────────────

/// Generate or load the local CA certificate.
/// The CA is NEVER auto-renewed — regenerating it would invalidate all client trust stores.
/// Returns (ca_cert_pem, ca_key_pem).
pub fn ensure_webui_ca(
    ca_cert_path: &str,
    ca_key_path: &str,
    base_dir: &std::path::Path,
) -> anyhow::Result<(String, String)> {
    let cert_file = if !ca_cert_path.is_empty() {
        std::path::PathBuf::from(ca_cert_path)
    } else {
        base_dir.join("webui-ca.pem")
    };
    let key_file = if !ca_key_path.is_empty() {
        std::path::PathBuf::from(ca_key_path)
    } else {
        base_dir.join("webui-ca-key.pem")
    };
    if cert_file.exists() && key_file.exists() {
        if let (Ok(cert), Ok(key)) = (
            std::fs::read_to_string(&cert_file),
            std::fs::read_to_string(&key_file),
        ) {
            tracing::info!(path=%cert_file.display(), "WebUI CA: loaded from disk");
            return Ok((cert, key));
        }
    }
    gen_webui_ca(&cert_file, &key_file)
}

fn gen_webui_ca(
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
) -> anyhow::Result<(String, String)> {
    tracing::info!("WebUI CA: generating local CA certificate (10 years)");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let not_before = rcgen::date_time_ymd(1970, 1, 1)
        + std::time::Duration::from_secs(now.saturating_sub(60));
    let not_after = not_before + std::time::Duration::from_secs(10 * 365 * 24 * 3600);

    let mut params = rcgen::CertificateParams::new(vec![])
        .map_err(|e| anyhow::anyhow!("CA params: {e}"))?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = not_before;
    params.not_after  = not_after;
    params.distinguished_name.push(rcgen::DnType::CommonName, "Runbound Local CA");
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "Runbound");

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| anyhow::anyhow!("CA key gen: {e}"))?;
    let cert = params.self_signed(&key_pair)
        .map_err(|e| anyhow::anyhow!("CA self-sign: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem  = key_pair.serialize_pem();

    let _ = std::fs::create_dir_all(
        cert_file.parent().unwrap_or_else(|| std::path::Path::new("/etc/runbound"))
    );
    std::fs::write(cert_file, &cert_pem)
        .map_err(|e| anyhow::anyhow!("save CA cert: {e}"))?;
    std::fs::write(key_file, &key_pem)
        .map_err(|e| anyhow::anyhow!("save CA key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(key_file, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(cert=%cert_file.display(), "WebUI CA certificate saved (install once per client)");
    Ok((cert_pem, key_pem))
}

/// Load server cert+key, or auto-generate one signed by the local CA.
/// Returns (cert_pem, key_pem, expires_at).
pub fn ensure_webui_cert(
    cert_path: &str,
    key_path: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    base_dir: &std::path::Path,
    extra_sans: &[String],
) -> anyhow::Result<(String, String, std::time::SystemTime)> {
    if !cert_path.is_empty() && !key_path.is_empty() {
        if let (Ok(cert), Ok(key)) = (
            std::fs::read_to_string(cert_path),
            std::fs::read_to_string(key_path),
        ) {
            let expires = std::time::SystemTime::now()
                + std::time::Duration::from_secs(90 * 24 * 3600);
            tracing::info!(cert=%cert_path, "WebUI TLS: loaded cert from file");
            return Ok((cert, key, expires));
        }
    }
    gen_webui_cert(cert_path, key_path, ca_cert_pem, ca_key_pem, base_dir, extra_sans)
}

fn gen_webui_cert(
    cert_path: &str,
    key_path: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    base_dir: &std::path::Path,
    extra_sans: &[String],
) -> anyhow::Result<(String, String, std::time::SystemTime)> {
    tracing::info!("WebUI TLS: generating certificate signed by local CA (366 days)");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let not_before = rcgen::date_time_ymd(1970, 1, 1)
        + std::time::Duration::from_secs(now.saturating_sub(60));
    let not_after  = not_before + std::time::Duration::from_secs(366 * 24 * 3600);

    // Load CA for signing
    let ca_key = rcgen::KeyPair::from_pem(ca_key_pem)
        .map_err(|e| anyhow::anyhow!("load CA key: {e}"))?;
    let ca_params = rcgen::CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .map_err(|e| anyhow::anyhow!("load CA cert params: {e}"))?;
    let ca_cert = ca_params.self_signed(&ca_key)
        .map_err(|e| anyhow::anyhow!("CA re-sign: {e}"))?;

    // Generate server cert with IP SANs for LAN access
    tracing::info!(sans = ?extra_sans, "WebUI TLS: adding IP/DNS SANs to certificate");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| anyhow::anyhow!("server cert params: {e}"))?;
    params.not_before = not_before;
    params.not_after  = not_after;
    params.distinguished_name.push(rcgen::DnType::CommonName, "Runbound WebUI");

    // Always include loopback IP SANs (#150)
    params.subject_alt_names.push(rcgen::SanType::IpAddress(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    ));
    params.subject_alt_names.push(rcgen::SanType::IpAddress(
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    ));

    // Add any extra SANs from config (ui-tls-san directives)
    for san in extra_sans {
        let s = san.trim();
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
        } else if !s.is_empty() {
            if let Ok(ia5) = rcgen::Ia5String::try_from(s) {
                params.subject_alt_names.push(rcgen::SanType::DnsName(ia5));
            } else {
                tracing::warn!(san = s, "WebUI TLS: invalid DNS SAN — skipped");
            }
        }
    }

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| anyhow::anyhow!("server key gen: {e}"))?;
    let cert = params.signed_by(&key_pair, &ca_cert, &ca_key)
        .map_err(|e| anyhow::anyhow!("server cert sign: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem  = key_pair.serialize_pem();

    let save_cert = if !cert_path.is_empty() {
        std::path::PathBuf::from(cert_path)
    } else {
        base_dir.join("webui-cert.pem")
    };
    let save_key = if !key_path.is_empty() {
        std::path::PathBuf::from(key_path)
    } else {
        base_dir.join("webui-key.pem")
    };
    let _ = std::fs::create_dir_all(base_dir);
    if let Err(e) = std::fs::write(&save_cert, &cert_pem) {
        tracing::warn!(path=%save_cert.display(), err=%e, "Could not save WebUI cert");
    }
    if let Err(e) = std::fs::write(&save_key, &key_pem) {
        tracing::warn!(path=%save_key.display(), err=%e, "Could not save WebUI key");
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&save_key, std::fs::Permissions::from_mode(0o600));
        }
    }
    let expires = std::time::SystemTime::now() + std::time::Duration::from_secs(365 * 24 * 3600);
    tracing::info!(
        cert=%save_cert.display(),
        key=%save_key.display(),
        "WebUI TLS certificate saved (CA-signed)"
    );
    Ok((cert_pem, key_pem, expires))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt as _;

    fn app() -> Router {
        use crate::alerts::AlertTracker;
        use crate::icmp::IcmpStats;
        let tracker = AlertTracker::new(vec![], None);
        let icmp = IcmpStats::new();
        router(
            19999,
            "test-key".to_string(),
            std::path::PathBuf::from("/tmp"),
            String::new(),
            tracker,
            icmp.ban_cmd_tx.clone(),
            None,
            86400,
            false,
            false, // tls_enabled: tests use HTTP
        )
    }

    async fn body_str(b: Body) -> String {
        String::from_utf8_lossy(&axum::body::to_bytes(b, usize::MAX).await.unwrap()).into_owned()
    }

    #[tokio::test]
    async fn unauthenticated_root_redirects_login() {
        let resp = app().oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }


    #[tokio::test]
    async fn login_page_ok() {
        let resp = app().oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_str(resp.into_body()).await;
        assert!(body.contains("<form"), "login form missing");
    }

    #[tokio::test]
    async fn unauthenticated_api_401() {
        let resp = app().oneshot(Request::builder().uri("/api/stats").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bad_login_redirects_with_err() {
        use axum::http::Method;
        let resp = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("rb_user=admin&rb_pass=wrongpassword"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.contains("/login") && loc.contains("err="), "expected redirect to /login?err=...");
    }
}
