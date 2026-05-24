use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{any, get},
    Router,
};
use futures_util::StreamExt as _;
use std::sync::Arc;
use tracing::warn;

static INDEX_HTML: &str = include_str!("../../examples/web-ui/index.html");

#[derive(Clone)]
pub struct WebUiState {
    api_port: u16,
    client: reqwest::Client,
}

pub fn router(api_port: u16) -> Router {
    let state = Arc::new(WebUiState {
        api_port,
        client: reqwest::Client::builder()
            .pool_max_idle_per_host(8)
            .build()
            .expect("reqwest client"),
    });
    Router::new()
        .route("/", get(serve_index))
        .route("/api", any(proxy_api))
        .route("/api/*path", any(proxy_api))
        .with_state(state)
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

// Transparent reverse-proxy: forwards any /api/* request to the local API listener.
// The browser sees same-origin responses; the API stays on 127.0.0.1 only.
async fn proxy_api(State(state): State<Arc<WebUiState>>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "request too large").into_response(),
    };

    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let target = format!("http://127.0.0.1:{}{}", state.api_port, path_and_query);

    let rmethod = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return (StatusCode::METHOD_NOT_ALLOWED, "bad method").into_response(),
    };

    let mut builder = state.client.request(rmethod, &target);
    for (name, value) in &headers {
        let n = name.as_str();
        if n == "host" || n == "transfer-encoding" || n == "content-length" {
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
                let n = name.as_str();
                if n == "transfer-encoding" {
                    continue;
                }
                rb = rb.header(n, value.as_bytes());
            }

            // Stream the body — works for both regular JSON and SSE event streams.
            let stream = upstream
                .bytes_stream()
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

    async fn body_bytes(body: Body) -> bytes::Bytes {
        axum::body::to_bytes(body, usize::MAX).await.unwrap()
    }

    #[tokio::test]
    async fn index_returns_html() {
        let app = router(19999); // no backend needed for this test
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/html"), "expected text/html, got {ct}");
        let body = body_bytes(resp.into_body()).await;
        assert!(!body.is_empty(), "HTML body must not be empty");
    }

    #[tokio::test]
    async fn index_content_matches_embedded_html() {
        let app = router(19999);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = body_bytes(resp.into_body()).await;
        assert_eq!(body.as_ref(), INDEX_HTML.as_bytes());
    }

    #[tokio::test]
    async fn proxy_no_backend_returns_502() {
        // Port 19998 should not be listening — proxy must return 502 Bad Gateway.
        let app = router(19998);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/system")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn proxy_wildcard_no_backend_returns_502() {
        let app = router(19998);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/stats/top-domains")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
