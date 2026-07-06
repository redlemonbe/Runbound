// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// src/api/relay.rs — HMAC-SHA256 relay: master ↔ slave command forwarding
// Issues #85 (relay chiffré), #87 (config push), #88 (node registration)

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{Method, StatusCode},
    response::IntoResponse,
    Json,
};
use bytes::Bytes;
use tracing::{info, warn};

use crate::api::AppState;
use crate::sync::{hmac_sign, hmac_unix_now, SyncJournal};

// ── TLS client for relay (TLS encryption, HMAC provides auth) ─────────────────

fn relay_tls_config() -> Arc<rustls::ClientConfig> {
    // TLS with no cert verification: HMAC-SHA256 provides authentication.
    // The TLS layer still encrypts the connection — only cert validation is skipped.
    Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Relay request (signed HTTPS, hyper + tokio-rustls) ────────────────────────

/// Make a signed relay request to a slave's node server.
/// Returns (status_code, response_body).
async fn relay_request(
    relay_host: &str, // "ip:port"
    tls_config: Arc<rustls::ClientConfig>,
    method: &str,
    path: &str, // e.g. "/relay/dns"
    sync_key: &str,
    body: Bytes,
) -> anyhow::Result<(u16, Bytes)> {
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;

    let ts = hmac_unix_now();
    let sig = hmac_sign(sync_key, method, path, ts, &body);

    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(relay_host),
    )
    .await
    .map_err(|_| anyhow::anyhow!("relay TCP connect timeout to {relay_host}"))?
    .map_err(|e| anyhow::anyhow!("relay TCP connect {relay_host}: {e}"))?;

    let sni_host = relay_host.rsplit_once(':').map(|(h, _)| h).unwrap_or(relay_host);
    let server_name = if let Ok(ip) = sni_host.parse::<std::net::IpAddr>() {
        rustls::pki_types::ServerName::IpAddress(ip.into())
    } else {
        rustls::pki_types::ServerName::try_from(sni_host.to_owned())
            .map_err(|e| anyhow::anyhow!("SNI: {e}"))?
    };
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow::anyhow!("relay TLS handshake timeout"))?
        .map_err(|e| anyhow::anyhow!("relay TLS: {e}"))?;

    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
        .map_err(|e| anyhow::anyhow!("HTTP handshake: {e}"))?;
    let conn_handle = tokio::spawn(async move { conn.await });

    let content_length = body.len().to_string();
    let req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", relay_host)
        .header("connection", "close")
        .header("content-type", "application/json")
        .header("content-length", &content_length)
        .header("x-runbound-ts", ts.to_string())
        .header("x-runbound-sig", &sig)
        .body(Full::new(body))
        .map_err(|e| anyhow::anyhow!("build relay request: {e}"))?;

    let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
        .await
        .map_err(|_| anyhow::anyhow!("relay send timeout"))?
        .map_err(|e| anyhow::anyhow!("relay send: {e}"))?;

    let status = resp.status().as_u16();
    let bytes = resp
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("relay collect: {e}"))?
        .to_bytes();
    drop(sender);
    let _ = tokio::time::timeout(Duration::from_millis(500), conn_handle).await;
    Ok((status, bytes))
}

// ── GET|POST|PUT|DELETE /api/nodes/{node_id}/relay/*path ──────────────────────
//
// Master-side relay forward: look up slave by node_id, sign and forward.

pub async fn relay_forward_handler(
    State(s): State<AppState>,
    Path(params): Path<std::collections::HashMap<String, String>>,
    caller_ext: Option<axum::Extension<crate::multiuser::RequestUser>>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    // Defense-in-depth: forwarding an arbitrary request to a slave is admin-only.
    // The role middleware already blocks non-admin writes here, but gate explicitly.
    let caller = caller_ext.map(|e| e.0).unwrap_or_else(crate::multiuser::RequestUser::admin_context);
    if !caller.admin {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"FORBIDDEN"})),
        )
            .into_response();
    }
    let node_id = params.get("node_id").cloned().unwrap_or_default();
    let relay_path = params.get("path").cloned().unwrap_or_default();
    let (sync_key, journal) = match (&s.sync_key, &s.sync_journal) {
        (Some(k), Some(j)) => (k.clone(), Arc::clone(j)),
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "RELAY_DISABLED",
                    "details": "sync-key or sync-port not configured on this master"
                })),
            )
                .into_response()
        }
    };

    let slave = match journal.get_node(&node_id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "NODE_NOT_FOUND",
                    "details": format!("No registered node with id {node_id}")
                })),
            )
                .into_response()
        }
    };

    let relay_host = match slave.relay_host {
        Some(h) => h,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "NODE_NO_RELAY",
                    "details": "Node registered without relay_host"
                })),
            )
                .into_response()
        }
    };

    // Build relay path: /relay/{relay_path}
    let path = format!("/relay/{}", relay_path.trim_start_matches('/'));

    // SEC: reject path traversal — a relayed path with `..` could be normalised by the
    // slave to reach an endpoint outside the intended /relay/ surface.
    if relay_path.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "RELAY_PATH",
                "details": "path traversal is not allowed"
            })),
        )
            .into_response();
    }

    // Anti-recursion: never relay to /relay/* itself.
    if path.starts_with("/relay/relay") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "RELAY_RECURSION",
                "details": "Relay to /relay/* is forbidden"
            })),
        )
            .into_response();
    }

    let method_str = req.method().as_str().to_string();
    let body = match axum::body::to_bytes(req.into_body(), 65_536).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "BODY_READ_ERROR", "details": e.to_string()
                })),
            )
                .into_response()
        }
    };

    // SEC-B1: use cert pinning when fingerprint is known (TOFU established at registration).
    let tls = if let Some(fp) = &slave.cert_fingerprint {
        Arc::new(crate::sync::pinned_client_config(fp))
    } else {
        relay_tls_config()
    };
    match relay_request(&relay_host, tls, &method_str, &path, &sync_key, body).await {
        Ok((status, resp_bytes)) => {
            let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            let body_str = String::from_utf8_lossy(&resp_bytes).to_string();
            (
                status_code,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body_str,
            )
                .into_response()
        }
        Err(e) => {
            warn!(node_id, relay_host, err = %e, "Relay forward failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "RELAY_ERROR", "details": "relay to slave failed"
                })),
            )
                .into_response()
        }
    }
}

// ── GET /api/nodes ────────────────────────────────────────────────────────────

pub async fn list_nodes_handler(State(s): State<AppState>) -> impl IntoResponse {
    match &s.sync_journal {
        Some(j) => {
            let nodes = j.registered_slaves();
            let total = nodes.len();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "nodes": nodes, "total": total })),
            )
                .into_response()
        }
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "nodes": [], "total": 0,
                "note": "this node is not configured as master"
            })),
        )
            .into_response(),
    }
}

// ── Config push to all registered slaves (#87) ────────────────────────────────
//
// Fire-and-forget: called after master write operations.
// Non-blocking: spawns a task per slave; does not fail the master operation.

pub fn push_to_slaves(
    journal: &Arc<SyncJournal>,
    sync_key: &str,
    method: Method,
    relay_path: String, // e.g. "dns" or "dns/{id}"
    body: Bytes,
) {
    let slaves = journal.registered_slaves();
    let key = sync_key.to_string();
    let method_s = method.as_str().to_string();

    let path = format!("/relay/{}", relay_path.trim_start_matches('/')); // loop-invariant
    for slave in slaves {
        let Some(relay_host) = slave.relay_host else {
            continue;
        };
        let path = path.clone();
        let body = body.clone();
        let key = key.clone();
        let method_s = method_s.clone();
        let node_id = slave.node_id.unwrap_or_default();
        let cert_fp = slave.cert_fingerprint.clone();
        tokio::spawn(async move {
            let tls = if let Some(ref fp) = cert_fp {
                Arc::new(crate::sync::pinned_client_config(fp))
            } else {
                relay_tls_config()
            };
            match relay_request(&relay_host, tls, &method_s, &path, &key, body).await {
                Ok((status, _)) if status < 300 => {
                    info!(node_id, relay_host, path, "Config push OK");
                }
                Ok((status, body)) => {
                    warn!(node_id, relay_host, path, status, body = %String::from_utf8_lossy(&body), "Config push non-2xx");
                }
                Err(e) => {
                    warn!(node_id, relay_host, path, err = %e, "Config push failed");
                }
            }
        });
    }
}

// ── Slave auto-registration (#88) ─────────────────────────────────────────────
//
// Called at slave startup: generates/loads node_id, registers with master.

/// Returns true on success (HTTP 200), false otherwise.
pub async fn register_with_master(
    master_sync_addr: String, // "ip:port"
    sync_key: String,
    node_id: String,
    relay_host: String, // "{slave_ip}:{slave_sync_port}"
    cert_fingerprint: String,
    version: String,
) -> bool {
    use http_body_util::Full;
    use hyper_util::rt::TokioIo;

    let body = match serde_json::to_vec(&serde_json::json!({
        "node_id":          node_id,
        "relay_host":       relay_host,
        "cert_fingerprint": cert_fingerprint,
        "version":          version,
    })) {
        Ok(b) => Bytes::from(b),
        Err(e) => {
            warn!("register: serialize failed: {e}");
            return false;
        }
    };

    let ts = hmac_unix_now();
    let sig = hmac_sign(&sync_key, "POST", "/nodes/register", ts, &body);

    let tls_config = relay_tls_config();
    let sni_host = master_sync_addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(&master_sync_addr);
    let server_name = if let Ok(ip) = sni_host.parse::<std::net::IpAddr>() {
        rustls::pki_types::ServerName::IpAddress(ip.into())
    } else {
        match rustls::pki_types::ServerName::try_from(sni_host.to_owned()) {
            Ok(n) => n,
            Err(e) => {
                warn!("register: SNI error: {e}");
                return false;
            }
        }
    };

    let result: anyhow::Result<u16> = async {
        let tcp = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(&master_sync_addr),
        )
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timeout"))?
        .map_err(|e| anyhow::anyhow!("TCP: {e}"))?;

        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
            .await
            .map_err(|_| anyhow::anyhow!("TLS timeout"))?
            .map_err(|e| anyhow::anyhow!("TLS: {e}"))?;

        let io = TokioIo::new(tls);
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(io)
            .await
            .map_err(|e| anyhow::anyhow!("HTTP handshake: {e}"))?;
        let conn_handle = tokio::spawn(async move { conn.await });

        let len = body.len().to_string();
        let req = hyper::Request::builder()
            .method("POST")
            .uri("/nodes/register")
            .header("host", &master_sync_addr)
            .header("connection", "close")
            .header("content-type", "application/json")
            .header("content-length", &len)
            .header("x-runbound-ts", ts.to_string())
            .header("x-runbound-sig", &sig)
            .body(Full::new(body))
            .map_err(|e| anyhow::anyhow!("build: {e}"))?;

        let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
            .await
            .map_err(|_| anyhow::anyhow!("send timeout"))?
            .map_err(|e| anyhow::anyhow!("send: {e}"))?;

        let status = resp.status().as_u16();
        drop(sender);
        let _ = tokio::time::timeout(Duration::from_millis(500), conn_handle).await;
        Ok(status)
    }
    .await;

    match result {
        Ok(200) => {
            warn!(master = %master_sync_addr, "Registered with master");
            true
        }
        Ok(s) => {
            warn!(master = %master_sync_addr, status = s, "Registration returned non-200");
            false
        }
        Err(e) => {
            warn!(master = %master_sync_addr, err = %e, "Registration failed");
            false
        }
    }
}
