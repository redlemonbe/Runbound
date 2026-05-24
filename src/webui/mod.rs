use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use axum::{
    body::Body,
    extract::{Form, State},
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

static INDEX_HTML: &str = include_str!("../../examples/web-ui/index.html");
static TAILWIND_JS: &[u8] = include_bytes!("../../examples/web-ui/tailwind.min.js");

const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
const CRED_FILE: &str = "webui-auth.conf";

#[derive(Clone)]
pub struct WebUiState {
    api_port: u16,
    api_key:  String,
    client:   reqwest::Client,
    sessions: Arc<DashMap<String, Instant>>,
    creds:    Arc<std::sync::Mutex<WebUiCred>>,
    auth_path: PathBuf,
}

struct WebUiCred {
    username: String,
    hash:     String, // argon2id encoded string
}

pub fn router(api_port: u16, api_key: String, base_dir: PathBuf) -> Router {
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
    });
    Router::new()
        .route("/", get(serve_dashboard))
        .route("/tailwind.js", get(serve_tailwind))
        .route("/login",  get(serve_login).post(handle_login))
        .route("/logout", get(handle_logout))
        .route("/api/webui/password", post(change_password))
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

fn session_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("cookie")?.to_str().ok()?;
    v.split(';').find_map(|s| s.trim().strip_prefix("rb_session=").map(|t| t.to_string()))
}

fn is_authenticated(state: &WebUiState, headers: &HeaderMap) -> bool {
    let token = match session_token(headers) { Some(t) => t, None => return false };
    if let Some(exp) = state.sessions.get(&token) {
        if Instant::now() < *exp { return true; }
        drop(exp);
        state.sessions.remove(&token);
    }
    false
}

async fn serve_dashboard(State(state): State<Arc<WebUiState>>, req: Request<Body>) -> Response {
    if !is_authenticated(&state, req.headers()) {
        return Redirect::to("/login").into_response();
    }
    Html(INDEX_HTML).into_response()
}

async fn serve_tailwind() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/javascript")], TAILWIND_JS)
}

const LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Runbound — Sign in</title>
  <script src="/tailwind.js"></script>
  <style>
    body{font-family:'SF Mono','Fira Code','Consolas',monospace;background:#0a0a0a;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .card{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:32px;width:100%;max-width:360px;box-sizing:border-box;margin:0 16px}
    input{display:block;width:100%;background:#0a0a0a;border:1px solid #334155;color:#e2e8f0;border-radius:6px;padding:8px 12px;font-size:13px;outline:none;box-sizing:border-box;font-family:inherit;margin:0}
    input:focus{border-color:#22d3ee}
    button{display:block;width:100%;background:#0e6680;color:white;border:none;border-radius:6px;padding:9px;cursor:pointer;font-size:13px;font-family:inherit;transition:background .15s;margin-top:4px}
    button:hover{background:#0891b2}
    label{display:block;color:#94a3b8;font-size:11px;margin-bottom:6px}
  </style>
</head>
<body>
  <div class="card">
    <div style="text-align:center;margin-bottom:28px">
      <div style="color:#22d3ee;font-size:18px;font-weight:700;letter-spacing:.08em">RUNBOUND</div>
      <div style="color:#475569;font-size:11px;margin-top:4px">Management Console</div>
    </div>
    <form method="POST" action="/login">
      <div style="margin-bottom:14px">
        <label for="u">Username</label>
        <input id="u" name="username" type="text" value="admin" autocomplete="username"/>
      </div>
      <div style="margin-bottom:20px">
        <label for="p">Password</label>
        <input id="p" name="password" type="password" autocomplete="current-password" placeholder="Enter password"/>
      </div>
      <button type="submit">Sign in</button>
    </form>
    <div id="err" style="color:#f87171;font-size:12px;text-align:center;margin-top:14px;min-height:16px"></div>
    <div style="color:#1e293b;font-size:10px;text-align:center;margin-top:20px">Delete webui-auth.conf to reset credentials</div>
  </div>
  <script>
    const e=new URLSearchParams(location.search).get('err');
    if(e)document.getElementById('err').textContent=decodeURIComponent(e);
    document.getElementById('p').focus();
  </script>
</body>
</html>"#;

async fn serve_login() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

#[derive(Deserialize)]
struct LoginForm { username: String, password: String }

async fn handle_login(State(state): State<Arc<WebUiState>>, Form(form): Form<LoginForm>) -> Response {
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
        return Redirect::to("/login?err=Invalid%20credentials").into_response();
    }
    // Purge expired sessions before adding a new one
    state.sessions.retain(|_, exp| Instant::now() < *exp);
    let token = uuid::Uuid::new_v4().to_string();
    state.sessions.insert(token.clone(), Instant::now() + SESSION_TTL);
    let cookie = format!(
        "rb_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    ([( header::SET_COOKIE, cookie )], Redirect::to("/")).into_response()
}

async fn handle_logout(State(state): State<Arc<WebUiState>>, req: Request<Body>) -> Response {
    if let Some(token) = session_token(req.headers()) {
        state.sessions.remove(&token);
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
    if payload.username.trim().is_empty() || payload.password.len() < 4 {
        return (StatusCode::BAD_REQUEST, "username required; password min 4 chars").into_response();
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

async fn proxy_api(State(state): State<Arc<WebUiState>>, req: Request<Body>) -> Response {
    if !is_authenticated(&state, req.headers()) {
        return (StatusCode::UNAUTHORIZED, r#"{"error":"not authenticated"}"#).into_response();
    }
    let method  = req.method().clone();
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt as _;

    fn app() -> Router { router(19999, "test-key".to_string(), std::path::PathBuf::from("/tmp")) }

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
    async fn tailwind_js_served() {
        let resp = app().oneshot(Request::builder().uri("/tailwind.js").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("content-type").unwrap().to_str().unwrap().contains("javascript"));
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
