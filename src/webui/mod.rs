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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

static INDEX_HTML: &str = include_str!("index.html");
static INDEX_HTML_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/index.html.gz"));

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
}

struct WebUiCred {
    username: String,
    hash:     String, // argon2id encoded string
}

pub fn router(api_port: u16, api_key: String, base_dir: PathBuf, ca_cert_pem: String) -> Router {
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
    });
    // SEC-B10: periodic cleanup of expired sessions (every 5 minutes).
    {
        let sessions = Arc::clone(&state.sessions);
        let login_rl = Arc::clone(&state.login_rl);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                sessions.retain(|_, (exp, _)| std::time::Instant::now() < *exp);
                login_rl.retain(|_, (_, since)| since.elapsed().as_secs() < 120);
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
        .route("/api",       any(proxy_api))
        .route("/api/*path", any(proxy_api))
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
    @keyframes glow-pulse{0%,100%{opacity:.6}50%{opacity:1}}
    @keyframes fade-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
    @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
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
      <div style="margin-bottom:16px">
        <label for="u">Username</label>
        <input id="u" name="username" type="text" autocomplete="username" class="input w-full"/>
      </div>
      <div style="margin-bottom:26px">
        <label for="p">Password</label>
        <input id="p" name="password" type="password" autocomplete="current-password" class="input w-full"/>
      </div>
      <button type="submit" class="btn-primary w-full mt-2">Sign in →</button>
    </form>
    <div id="err" style="color:#f87171;font-size:12px;text-align:center;margin-top:16px;min-height:16px"></div>
    <div style="color:#0c1a24;font-size:10px;text-align:center;margin-top:26px">Delete webui-auth.conf to reset credentials</div>
  </div>
  <script>
    const e=new URLSearchParams(location.search).get('err');
    if(e)document.getElementById('err').textContent=decodeURIComponent(e);
    document.getElementById('p').focus();
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

async fn serve_login() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

#[derive(Deserialize)]
struct LoginForm { username: String, password: String }

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
    let ok = {
        let creds = state.creds.lock().unwrap_or_else(|e| e.into_inner());
        if creds.username != form.username { false }
        else {
            match PasswordHash::new(&creds.hash) {
                Ok(h) => Argon2::default().verify_password(form.password.as_bytes(), &h).is_ok(),
                Err(_) => false,
            }
        }
    };
    if !ok {
        tracing::warn!(user = %form.username, ip = %client_ip, "WebUI login FAILED — invalid credentials");
        push_auth_event(&state, "login_fail", &form.username, &client_ip);
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
    tracing::info!(user = %form.username, ip = %client_ip, "WebUI login successful");
    push_auth_event(&state, "login_ok", &form.username, &client_ip);
    // SEC-A2: add Secure flag when behind an HTTPS reverse proxy.
    let secure = headers.get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false);
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
    gen_webui_cert(cert_path, key_path, ca_cert_pem, ca_key_pem, base_dir)
}

fn gen_webui_cert(
    cert_path: &str,
    key_path: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    base_dir: &std::path::Path,
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
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| anyhow::anyhow!("server cert params: {e}"))?;
    params.not_before = not_before;
    params.not_after  = not_after;
    params.distinguished_name.push(rcgen::DnType::CommonName, "Runbound WebUI");

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

    fn app() -> Router { router(19999, "test-key".to_string(), std::path::PathBuf::from("/tmp"), String::new()) }

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
                    .body(Body::from("username=admin&password=wrongpassword"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.contains("/login") && loc.contains("err="), "expected redirect to /login?err=...");
    }
}
