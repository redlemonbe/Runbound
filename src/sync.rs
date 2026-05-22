// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// src/sync.rs — slave/master synchronisation (delta journal + TOFU TLS)

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use arc_swap::ArcSwap;

use crate::config::parser::UnboundConfig;
use crate::dns::local::{LocalZoneSet, parse_local_data};
use crate::dns::ZoneAction;
use crate::feeds::{load_feeds, save_feeds, update_one_feed, Feed, FeedsConfig};
use crate::store::{
    load, load_blacklist, save, save_blacklist, BlacklistEntry, BlacklistStore, DnsEntry, DnsStore,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const JOURNAL_CAPACITY: usize = 1_000;
fn fingerprint_path() -> std::path::PathBuf { crate::runtime::base_dir().join("sync-master.fingerprint") }
fn sync_cert_path() -> std::path::PathBuf { crate::runtime::base_dir().join("sync-cert.pem") }
fn sync_key_path() -> std::path::PathBuf { crate::runtime::base_dir().join("sync-key.pem") }

// ── SyncJournal ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum SyncOp {
    AddDns          { entry: DnsEntry },
    DeleteDns       { id: String },
    AddBlacklist    { entry: BlacklistEntry },
    DeleteBlacklist { id: String },
    AddFeed         { feed: Feed },
    DeleteFeed      { id: String },
    UpdateFeed      { id: String, url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEvent {
    pub seq: u64,
    pub ts:  u64,
    pub op:  SyncOp,
}

/// Lightweight record of a connected slave, updated on each /sync/delta call.
#[derive(Debug, Clone, Serialize)]
pub struct SlaveInfo {
    pub addr:          String,
    pub last_seen_secs: u64,
    pub last_seq:      u64,
}

// Max calls to /sync/cert per peer IP per 60-second window (TOFU bootstrap guard).
const CERT_RL_MAX: u32 = 10;

pub struct SyncJournal {
    events:            Mutex<VecDeque<SyncEvent>>,
    seq:               AtomicU64,
    connected_slaves:  Mutex<HashMap<String, SlaveInfo>>,
    /// Per-peer rate-limit for the public /sync/cert endpoint:
    /// maps peer-addr → (request_count_in_window, window_start).
    cert_rl:           dashmap::DashMap<String, (u32, Instant), ahash::RandomState>,
}

impl SyncJournal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events:           Mutex::new(VecDeque::with_capacity(JOURNAL_CAPACITY)),
            seq:              AtomicU64::new(0),
            connected_slaves: Mutex::new(HashMap::new()),
            cert_rl:          dashmap::DashMap::with_hasher(ahash::RandomState::default()),
        })
    }

    /// Record or refresh a slave connection (called from /sync/state and /sync/delta).
    pub fn record_slave(&self, addr: String, seq: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut map = self.connected_slaves.lock().unwrap_or_else(|e| panic!("sync: slaves mutex poisoned: {e}"));
        map.insert(addr.clone(), SlaveInfo { addr, last_seen_secs: now, last_seq: seq });
    }

    /// Return a snapshot of recently-seen slaves (last-seen ≤ 5 min ago).
    pub fn connected_slaves(&self) -> Vec<SlaveInfo> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let map = self.connected_slaves.lock().unwrap_or_else(|e| panic!("sync: slaves mutex poisoned: {e}"));
        map.values()
            .filter(|s| now.saturating_sub(s.last_seen_secs) < 300)
            .cloned()
            .collect()
    }

    /// Push an operation, returns the assigned sequence number.
    pub fn push(&self, op: SyncOp) -> u64 {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut q = self.events.lock().unwrap_or_else(|e| panic!("sync: events mutex poisoned: {e}"));
        if q.len() >= JOURNAL_CAPACITY {
            q.pop_front();
        }
        q.push_back(SyncEvent { seq, ts, op });
        seq
    }

    /// Returns events with seq >= since.
    /// Returns None when `since` predates the ring buffer — slave must do a full sync.
    pub fn delta(&self, since: u64) -> Option<Vec<SyncEvent>> {
        let q = self.events.lock().unwrap_or_else(|e| panic!("sync: events mutex poisoned: {e}"));
        if let Some(oldest) = q.front() {
            if since < oldest.seq {
                return None; // 410 Gone — too far behind
            }
        }
        Some(q.iter().filter(|e| e.seq >= since).cloned().collect())
    }

    pub fn current_seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }
}

// ── TLS certificate management ────────────────────────────────────────────────

/// Load existing sync cert or generate a new self-signed one. Returns (cert_pem, key_pem).
pub fn ensure_sync_cert() -> anyhow::Result<(String, String)> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let cert_path = sync_cert_path();
    let key_path  = sync_key_path();
    if let (Ok(cert), Ok(key)) = (
        fs::read_to_string(&cert_path),
        fs::read_to_string(&key_path),
    ) {
        return Ok((cert, key));
    }

    info!("Generating self-signed sync certificate");
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["runbound-sync".to_string()])
            .map_err(|e| anyhow::anyhow!("sync cert generation failed: {e}"))?;

    fs::create_dir_all(crate::runtime::base_dir())
        .map_err(|e| anyhow::anyhow!("create base_dir: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    fs::write(&cert_path, &cert_pem)
        .map_err(|e| anyhow::anyhow!("write sync-cert.pem: {e}"))?;
    fs::write(&key_path, &key_pem)
        .map_err(|e| anyhow::anyhow!("write sync-key.pem: {e}"))?;
    #[cfg(unix)]
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow::anyhow!("chmod sync-key.pem: {e}"))?;

    Ok((cert_pem, key_pem))
}

/// SHA-256 hex fingerprint of the first DER certificate in a PEM string.
pub fn cert_sha256_hex(cert_pem: &str) -> anyhow::Result<String> {
    let der = pem_cert_to_der(cert_pem)?;
    Ok(hex::encode(Sha256::digest(&der)))
}

fn pem_cert_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_bytes()))
        .flatten()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| anyhow::anyhow!("no certificate in PEM"))
}

/// Build a rustls 0.23 ServerConfig from cert+key PEM.
pub fn server_tls_config(cert_pem: &str, key_pem: &str) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
            .flatten()
            .collect();

    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))
            .map_err(|e| anyhow::anyhow!("parse key PEM: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS server config: {e}"))
}

// ── Pinned cert verifier (slave → master) ─────────────────────────────────────

// ── Custom rustls verifiers (shared helpers) ───────────────────────────────

/// Delegate TLS signature verification to the ring crypto provider.
macro_rules! impl_tls_signature_verification {
    ($t:ty) => {
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message, cert, dss,
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
                message, cert, dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    };
}

#[derive(Debug)]
struct PinnedCertVerifier {
    fingerprint: String,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let got = hex::encode(Sha256::digest(end_entity));
        if got == self.fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert fingerprint mismatch: got {got}, expected {}", self.fingerprint
            )))
        }
    }

    impl_tls_signature_verification!(PinnedCertVerifier);
}

/// Capture-on-first-use verifier for TOFU handshake.
#[derive(Debug)]
struct TofuVerifier {
    captured: Mutex<Option<String>>,
}

impl TofuVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self { captured: Mutex::new(None) })
    }
    fn take_fingerprint(&self) -> Option<String> {
        self.captured.lock().unwrap_or_else(|e| panic!("sync: TOFU captured mutex poisoned: {e}")).clone()
    }
}

impl rustls::client::danger::ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = hex::encode(Sha256::digest(end_entity));
        *self.captured.lock().unwrap_or_else(|e| panic!("sync: TOFU captured mutex poisoned: {e}")) = Some(fp);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    impl_tls_signature_verification!(TofuVerifier);
}

fn pinned_client_config(fingerprint: &str) -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier {
            fingerprint: fingerprint.to_string(),
        }))
        .with_no_client_auth()
}

// ── Sync HTTP client (hyper + tokio-rustls, rustls 0.21) ─────────────────────

/// Make a single HTTPS GET request. Returns (status_code, body_bytes).
async fn sync_get(
    host_port: &str,
    tls_config: Arc<rustls::ClientConfig>,
    path: &str,
    auth: Option<&str>,
) -> anyhow::Result<(u16, Bytes)> {
    let tcp = tokio::net::TcpStream::connect(host_port).await
        .map_err(|e| anyhow::anyhow!("TCP connect {host_port}: {e}"))?;

    let server_name = rustls::pki_types::ServerName::try_from("runbound-sync")
        .map_err(|e| anyhow::anyhow!("invalid SNI: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let tls = connector.connect(server_name, tcp).await
        .map_err(|e| anyhow::anyhow!("TLS handshake: {e}"))?;

    let io = TokioIo::new(tls);
    let (mut sender, conn) =
        hyper::client::conn::http1::Builder::new().handshake(io).await
            .map_err(|e| anyhow::anyhow!("HTTP handshake: {e}"))?;
    tokio::spawn(async move { conn.await.ok(); });

    let mut builder = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host_port);
    if let Some(a) = auth {
        builder = builder.header("authorization", a);
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| anyhow::anyhow!("build request: {e}"))?;

    let resp = sender.send_request(req).await
        .map_err(|e| anyhow::anyhow!("send request: {e}"))?;
    let status = resp.status().as_u16();
    let bytes = resp.collect().await
        .map_err(|e| anyhow::anyhow!("collect body: {e}"))?.to_bytes();

    Ok((status, bytes))
}

// ── Master sync HTTPS server ──────────────────────────────────────────────────

pub async fn start_master_sync_server(
    port: u16,
    journal: Arc<SyncJournal>,
    sync_key: String,
    cert_fingerprint: String,
    cert_pem: String,
    key_pem: String,
) -> anyhow::Result<()> {
    let tls_config = Arc::new(server_tls_config(&cert_pem, &key_pem)?);
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await
        .map_err(|e| anyhow::anyhow!("bind sync port {port}: {e}"))?;
    info!(port, "Sync HTTPS server listening");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => { warn!("sync accept: {e}"); continue; }
        };
        let acceptor       = acceptor.clone();
        let journal        = Arc::clone(&journal);
        let sync_key       = sync_key.clone();
        let cert_fp        = cert_fingerprint.clone();

        let peer_str = peer.to_string();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => { warn!(%peer, "sync TLS: {e}"); return; }
            };
            let io = TokioIo::new(tls);
            let peer_str2 = peer_str.clone();
            let svc = service_fn(move |req| {
                handle_sync_request(req, Arc::clone(&journal), sync_key.clone(), cert_fp.clone(), peer_str2.clone())
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                warn!(%peer, "sync conn: {e}");
            }
        });
    }
}

async fn handle_sync_request(
    req: hyper::Request<hyper::body::Incoming>,
    journal: Arc<SyncJournal>,
    sync_key: String,
    cert_fingerprint: String,
    peer_addr: String,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let path  = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    // /sync/cert — returns fingerprint, no auth (TOFU bootstrap).
    // Rate-limited per peer IP: max 10 requests per 60-second window to prevent
    // enumeration of certificate rotations by unauthenticated callers.
    if path == "/sync/cert" {
        let now = Instant::now();
        let allowed = {
            let mut entry = journal.cert_rl
                .entry(peer_addr.clone())
                .or_insert((0u32, now));
            if entry.1.elapsed().as_secs() >= 60 {
                *entry = (1, now);
                true
            } else {
                entry.0 += 1;
                entry.0 <= CERT_RL_MAX
            }
        };
        if !allowed {
            return Ok(json_resp(429, serde_json::json!({ "error": "RATE_LIMITED" })));
        }
        return Ok(json_ok(serde_json::json!({ "fingerprint": cert_fingerprint })));
    }

    // All other endpoints require Bearer auth — constant-time to prevent
    // timing oracles on the sync key length and content.
    let auth     = req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {sync_key}");
    let authed: bool = {
        use subtle::ConstantTimeEq as _;
        auth.as_bytes().ct_eq(expected.as_bytes()).into()
    };
    if !authed {
        return Ok(json_resp(401, serde_json::json!({ "error": "UNAUTHORIZED" })));
    }

    match path.as_str() {
        "/sync/state" => {
            let seq = journal.current_seq();
            journal.record_slave(peer_addr, seq);
            Ok(json_ok(serde_json::json!({ "seq": seq })))
        }
        "/sync/config" => {
            let seq       = journal.current_seq();
            let dns       = load().unwrap_or_default().entries;
            let blacklist = load_blacklist().unwrap_or_default().entries;
            let feeds     = load_feeds().unwrap_or_default().feeds;
            Ok(json_ok(serde_json::json!({
                "dns": dns, "blacklist": blacklist, "feeds": feeds, "seq": seq,
            })))
        }
        "/sync/delta" => {
            let since: u64 = query
                .split('&')
                .find_map(|p| p.strip_prefix("since="))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let seq = journal.current_seq();
            journal.record_slave(peer_addr, seq);
            match journal.delta(since) {
                Some(events) => Ok(json_ok(serde_json::json!({
                    "events": events, "seq": seq,
                }))),
                None => Ok(json_resp(410, serde_json::json!({ "error": "TOO_FAR_BEHIND" }))),
            }
        }
        _ => Ok(json_resp(404, serde_json::json!({ "error": "NOT_FOUND" }))),
    }
}

fn json_ok(body: serde_json::Value) -> hyper::Response<Full<Bytes>> {
    json_resp(200, body)
}

fn json_resp(status: u16, body: serde_json::Value) -> hyper::Response<Full<Bytes>> {
    // Builder with hardcoded valid status + header: infallible.
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_else(|e| panic!("response builder: {e}"))
}

// ── SlaveClient ───────────────────────────────────────────────────────────────

pub struct SlaveClient {
    host_port:   String,
    sync_key:    String,
    interval:    u64,
    zones:       Arc<ArcSwap<LocalZoneSet>>,
    zones_mutex: Arc<tokio::sync::Mutex<()>>,
    cfg:         Arc<UnboundConfig>,
}

impl SlaveClient {
    pub fn new(
        master:      &str,
        sync_key:    &str,
        interval:    u64,
        zones:       Arc<ArcSwap<LocalZoneSet>>,
        zones_mutex: Arc<tokio::sync::Mutex<()>>,
        cfg:         Arc<UnboundConfig>,
    ) -> Self {
        Self {
            host_port: master.to_string(),
            sync_key:  sync_key.to_string(),
            interval,
            zones,
            zones_mutex,
            cfg,
        }
    }

    pub async fn run(self) {
        let fingerprint = match self.tofu_handshake().await {
            Ok(fp) => fp,
            Err(e) => { error!("Slave sync TOFU failed: {e}"); return; }
        };

        let tls_config = Arc::new(pinned_client_config(&fingerprint));

        let mut last_seq = match self.full_sync(&tls_config).await {
            Ok(seq) => { info!("Slave sync: initial full sync complete (seq={seq})"); seq }
            Err(e)  => { warn!("Slave sync: initial full sync failed: {e}"); 0 }
        };

        let mut backoff_secs: u64 = 5;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(self.interval)).await;

            match self.sync_tick(&tls_config, last_seq).await {
                Ok(new_seq) => {
                    if new_seq > last_seq {
                        info!("Slave sync: applied delta seq {last_seq}→{new_seq}");
                        last_seq = new_seq;
                    }
                    backoff_secs = 5;
                }
                Err(SyncError::TooFarBehind) => {
                    warn!("Slave sync: 410 too far behind — performing full sync");
                    match self.full_sync(&tls_config).await {
                        Ok(seq) => { last_seq = seq; info!("Slave sync: recovery full sync (seq={seq})"); }
                        Err(e)  => { warn!("Slave sync: full sync failed: {e}"); self.sleep_backoff(&mut backoff_secs).await; }
                    }
                }
                Err(e) => {
                    warn!("Slave sync error: {e}");
                    self.sleep_backoff(&mut backoff_secs).await;
                }
            }
        }
    }

    async fn sleep_backoff(&self, secs: &mut u64) {
        tokio::time::sleep(std::time::Duration::from_secs(*secs)).await;
        *secs = (*secs * 2).min(300);
    }

    // TOFU: load saved fingerprint or discover it from master on first connect.
    async fn tofu_handshake(&self) -> anyhow::Result<String> {
        if let Ok(fp) = std::fs::read_to_string(fingerprint_path()) {
            let fp = fp.trim().to_string();
            if !fp.is_empty() {
                return Ok(fp);
            }
        }

        warn!(
            "Slave sync: no pinned fingerprint — TOFU connect to {}. \
             Verify sync-master.fingerprint in config base_dir manually.",
            self.host_port
        );

        // Connect with capture verifier to record the cert fingerprint.
        let verifier = TofuVerifier::new();
        let verifier_dyn: Arc<dyn rustls::client::danger::ServerCertVerifier> = verifier.clone();
        let tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier_dyn)
                .with_no_client_auth()
        );

        let (status, body) = sync_get(&self.host_port, tls_config, "/sync/cert", None).await?;
        if status != 200 {
            return Err(anyhow::anyhow!("TOFU /sync/cert returned {status}"));
        }

        let fp = verifier.take_fingerprint()
            .ok_or_else(|| anyhow::anyhow!("TOFU: no cert captured during handshake"))?;

        #[derive(Deserialize)]
        struct CertResp { fingerprint: String }
        let resp: CertResp = serde_json::from_slice(&body)?;

        if resp.fingerprint != fp {
            return Err(anyhow::anyhow!(
                "TOFU: cert fingerprint from TLS ({fp}) differs from /sync/cert body ({}) — possible MITM",
                resp.fingerprint
            ));
        }

        let fp_path = fingerprint_path();
        warn!("Slave sync: pinning master SHA-256={fp} → {}", fp_path.display());
        std::fs::create_dir_all(crate::runtime::base_dir())
            .map_err(|e| anyhow::anyhow!("create base_dir: {e}"))?;
        std::fs::write(&fp_path, &fp)
            .map_err(|e| anyhow::anyhow!("write fingerprint: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&fp_path, std::fs::Permissions::from_mode(0o640));
        }

        Ok(fp)
    }

    async fn full_sync(&self, tls_config: &Arc<rustls::ClientConfig>) -> anyhow::Result<u64> {
        let auth = format!("Bearer {}", self.sync_key);
        let (status, body) = sync_get(&self.host_port, Arc::clone(tls_config), "/sync/config", Some(&auth)).await?;
        if status != 200 {
            return Err(anyhow::anyhow!("full sync returned {status}"));
        }

        #[derive(Deserialize)]
        struct FullSyncResp {
            dns:       Vec<DnsEntry>,
            blacklist: Vec<BlacklistEntry>,
            feeds:     Vec<Feed>,
            seq:       u64,
        }
        let resp: FullSyncResp = serde_json::from_slice(&body)
            .map_err(|e| anyhow::anyhow!("parse full sync: {e}"))?;

        {
            let _guard = self.zones_mutex.lock().await;
            save(&DnsStore { entries: resp.dns })
                .map_err(|e| anyhow::anyhow!("save DNS: {e}"))?;
            save_blacklist(&BlacklistStore { entries: resp.blacklist })
                .map_err(|e| anyhow::anyhow!("save blacklist: {e}"))?;
            save_feeds(&FeedsConfig { feeds: resp.feeds })
                .map_err(|e| anyhow::anyhow!("save feeds: {e}"))?;
            // Rebuild zone handler from the freshly written stores.
            let new_zones = crate::build_zone_set(&self.cfg);
            self.zones.store(Arc::new(new_zones));
        }

        Ok(resp.seq)
    }

    async fn sync_tick(
        &self,
        tls_config: &Arc<rustls::ClientConfig>,
        last_seq: u64,
    ) -> Result<u64, SyncError> {
        let auth = format!("Bearer {}", self.sync_key);

        // Check master seq first to avoid unnecessary delta downloads
        let (status, body) = sync_get(&self.host_port, Arc::clone(tls_config), "/sync/state", Some(&auth))
            .await.map_err(|e| SyncError::Request(e.to_string()))?;
        if status != 200 {
            return Err(SyncError::Request(format!("/sync/state returned {status}")));
        }
        #[derive(Deserialize)]
        struct StateResp { seq: u64 }
        let state: StateResp = serde_json::from_slice(&body)
            .map_err(|e| SyncError::Request(format!("parse state: {e}")))?;
        if state.seq <= last_seq {
            return Ok(last_seq);
        }

        // Pull delta
        let path = format!("/sync/delta?since={last_seq}");
        let (status, body) = sync_get(&self.host_port, Arc::clone(tls_config), &path, Some(&auth))
            .await.map_err(|e| SyncError::Request(e.to_string()))?;
        if status == 410 {
            return Err(SyncError::TooFarBehind);
        }
        if status != 200 {
            return Err(SyncError::Request(format!("/sync/delta returned {status}")));
        }

        #[derive(Deserialize)]
        struct DeltaResp { events: Vec<SyncEvent>, seq: u64 }
        let delta: DeltaResp = serde_json::from_slice(&body)
            .map_err(|e| SyncError::Request(format!("parse delta: {e}")))?;

        for event in delta.events {
            if let Err(e) = self.apply_event(event).await {
                warn!("Slave sync: apply event failed: {e}");
            }
        }

        Ok(delta.seq)
    }

    async fn apply_event(&self, event: SyncEvent) -> anyhow::Result<()> {
        match event.op {
            SyncOp::AddDns { entry } => {
                let _guard = self.zones_mutex.lock().await;
                let mut st = load().unwrap_or_default();
                if !st.entries.iter().any(|e| e.id == entry.id) {
                    st.entries.push(entry.clone());
                    save(&st).map_err(|e| anyhow::anyhow!("{e}"))?;
                    // Mirror the same zone injection the API handler does.
                    if let Some(rr) = entry.to_rr_string() {
                        if let Some(record) = parse_local_data(&rr) {
                            let current = self.zones.load_full();
                            let mut new_zones = (*current).clone();
                            let name = record.name.clone();
                            new_zones.zones.entry(name.clone()).or_insert(ZoneAction::Static);
                            new_zones.records.entry(name).or_default().push(record);
                            self.zones.store(Arc::new(new_zones));
                        }
                    }
                }
            }
            SyncOp::DeleteDns { id } => {
                let _guard = self.zones_mutex.lock().await;
                let mut st = load().unwrap_or_default();
                st.entries.retain(|e| e.id != id);
                save(&st).map_err(|e| anyhow::anyhow!("{e}"))?;
                // Deletion requires a full rebuild — no partial removal on the zone trie.
                let new_zones = crate::build_zone_set(&self.cfg);
                self.zones.store(Arc::new(new_zones));
            }
            SyncOp::AddBlacklist { entry } => {
                let _guard = self.zones_mutex.lock().await;
                let mut bl = load_blacklist().unwrap_or_default();
                if !bl.entries.iter().any(|e| e.id == entry.id) {
                    let action = ZoneAction::from(&entry.action);
                    bl.entries.push(entry.clone());
                    save_blacklist(&bl).map_err(|e| anyhow::anyhow!("{e}"))?;
                    let current = self.zones.load_full();
                    let mut new_zones = (*current).clone();
                    new_zones.override_zone(&entry.domain, action);
                    self.zones.store(Arc::new(new_zones));
                }
            }
            SyncOp::DeleteBlacklist { id } => {
                let _guard = self.zones_mutex.lock().await;
                let mut bl = load_blacklist().unwrap_or_default();
                bl.entries.retain(|e| e.id != id);
                save_blacklist(&bl).map_err(|e| anyhow::anyhow!("{e}"))?;
                let new_zones = crate::build_zone_set(&self.cfg);
                self.zones.store(Arc::new(new_zones));
            }
            SyncOp::AddFeed { feed } => {
                let mut cfg = load_feeds().unwrap_or_default();
                if !cfg.feeds.iter().any(|f| f.id == feed.id) {
                    cfg.feeds.push(feed);
                    save_feeds(&cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
                }
            }
            SyncOp::DeleteFeed { id } => {
                let mut cfg = load_feeds().unwrap_or_default();
                cfg.feeds.retain(|f| f.id != id);
                save_feeds(&cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            SyncOp::UpdateFeed { id, .. } => {
                if let Err(e) = update_one_feed(&id).await {
                    warn!("Slave sync: UpdateFeed {id} failed: {e}");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
enum SyncError {
    TooFarBehind,
    Request(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::TooFarBehind => write!(f, "too far behind (410 Gone)"),
            SyncError::Request(s)   => write!(f, "request error: {s}"),
        }
    }
}
