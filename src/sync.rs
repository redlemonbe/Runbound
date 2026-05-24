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
use crate::upstreams::{SharedUpstreams, add_upstream, remove_upstream};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the IP from a peer address string (strips the ephemeral port).
/// Handles IPv4 ("1.2.3.4:port"), IPv6 ("[::1]:port"), and bare IPs.
fn slave_ip(addr: &str) -> String {
    // IPv6 bracketed: [::1]:54321
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(pos) = rest.rfind(']') {
            return rest[..pos].to_string();
        }
    }
    // IPv4: 1.2.3.4:54321
    if let Some(pos) = addr.rfind(':') {
        // Ensure the part after ':' looks like a port, not an IPv6 segment
        if addr[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            return addr[..pos].to_string();
        }
    }
    addr.to_string()
}

// ── Constants ─────────────────────────────────────────────────────────────────

const JOURNAL_CAPACITY: usize = 1_000;
fn fingerprint_path()  -> std::path::PathBuf { crate::runtime::base_dir().join("sync-master.fingerprint") }
fn sync_cert_path()    -> std::path::PathBuf { crate::runtime::base_dir().join("sync-cert.pem") }
fn sync_key_path()     -> std::path::PathBuf { crate::runtime::base_dir().join("sync-key.pem") }
fn slaves_json_path()  -> std::path::PathBuf { crate::runtime::base_dir().join("slaves.json") }
fn node_id_path()      -> std::path::PathBuf { crate::runtime::base_dir().join("node-id") }
fn relay_cert_path()   -> std::path::PathBuf { crate::runtime::base_dir().join("relay-cert.pem") }
fn relay_key_path()    -> std::path::PathBuf { crate::runtime::base_dir().join("relay-key.pem") }

// ── HMAC-SHA256 relay authentication (#85) ────────────────────────────────────
//
// Message = METHOD + "\n" + path + "\n" + unix_timestamp_decimal
// Signature = HMAC-SHA256(sync_key_bytes, message_bytes) — hex-encoded
// Headers: X-Runbound-TS (unix secs)  +  X-Runbound-Sig (hex)

pub fn hmac_unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn hmac_sign(key: &str, method: &str, path: &str, ts: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let msg = format!("{method}\n{path}\n{ts}");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time HMAC verification. Returns true iff the signature is valid
/// AND the timestamp is within ±30 s of the current server clock.
pub fn hmac_verify_with_ts(key: &str, method: &str, path: &str, ts: u64, sig: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let now = hmac_unix_now();
    let diff = if now >= ts { now - ts } else { ts - now };
    if diff > 30 {
        return false;
    }
    let expected = hmac_sign(key, method, path, ts);
    // Length mismatch also returns false.
    // Fold both length check and byte comparison into a single constant-time accumulator.
    let len_ok: u8 = if expected.len() == sig.len() { 1 } else { 0 };
    let byte_diff: u8 = sig.bytes().zip(expected.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    // Both checks must pass: len_ok == 1 AND byte_diff == 0.
    let combined = byte_diff | (1u8.wrapping_sub(len_ok)); // non-zero if either fails
    combined.ct_eq(&0u8).into()
}

/// Generate or load the relay TLS cert (separate from sync cert — each node has its own).
pub fn ensure_relay_cert() -> anyhow::Result<(String, String)> {
    use std::fs;
    #[cfg(unix)] use std::os::unix::fs::PermissionsExt;

    let cert_path = relay_cert_path();
    let key_path  = relay_key_path();
    if let (Ok(cert), Ok(key)) = (
        fs::read_to_string(&cert_path),
        fs::read_to_string(&key_path),
    ) {
        return Ok((cert, key));
    }
    info!("Generating self-signed relay certificate");
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["runbound-relay".to_string()])
            .map_err(|e| anyhow::anyhow!("relay cert generation failed: {e}"))?;
    fs::create_dir_all(crate::runtime::base_dir())
        .map_err(|e| anyhow::anyhow!("create base_dir: {e}"))?;
    let cert_pem = cert.pem();
    let key_pem  = key_pair.serialize_pem();
    fs::write(&cert_path, &cert_pem)
        .map_err(|e| anyhow::anyhow!("write relay-cert.pem: {e}"))?;
    fs::write(&key_path, &key_pem)
        .map_err(|e| anyhow::anyhow!("write relay-key.pem: {e}"))?;
    #[cfg(unix)]
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow::anyhow!("chmod relay-key.pem: {e}"))?;
    Ok((cert_pem, key_pem))
}

/// Load or generate the stable node UUID (persisted in node-id file).
pub fn ensure_node_id() -> anyhow::Result<String> {
    let path = node_id_path();
    if let Ok(id) = std::fs::read_to_string(&path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    std::fs::create_dir_all(crate::runtime::base_dir())
        .map_err(|e| anyhow::anyhow!("create base_dir: {e}"))?;
    std::fs::write(&path, &id)
        .map_err(|e| anyhow::anyhow!("write node-id: {e}"))?;
    info!(%id, "Generated new node UUID");
    Ok(id)
}

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
    // #87 — upstream replication
    AddUpstream    { addr: String, port: u16, protocol: String, name: Option<String>, tls_hostname: Option<String> },
    DeleteUpstream { id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEvent {
    pub seq: u64,
    pub ts:  u64,
    pub op:  SyncOp,
}

/// Snapshot of a connected slave returned by GET /api/sync/slaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaveInfo {
    /// Stable UUID identifying this node (set at registration, #88).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id:          Option<String>,
    /// Slave IP address (deduplicated — ephemeral port stripped).
    pub addr:             String,
    /// "{ip}:{sync_port}" used by master to reach slave for relay (#85).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_host:       Option<String>,
    /// SHA-256 hex of slave's TLS cert — pinned for relay connections (#85).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_fingerprint: Option<String>,
    /// Unix timestamp of the last contact.
    pub last_seen_at:     u64,
    /// Seconds elapsed since last contact (computed at query time).
    #[serde(default)]
    pub last_seen_secs:   u64,
    /// "connected" (seen ≤30s ago) or "disconnected".
    #[serde(default)]
    pub status:           String,
    pub last_seq:         u64,
    /// Number of zones synchronised (0 = not tracked yet).
    pub zones_synced:     u32,
    /// Slave binary version (null = not reported yet).
    pub version:          Option<String>,
}

// Max calls to /sync/cert per peer IP per 60-second window (TOFU bootstrap guard).
const CERT_RL_MAX: u32 = 10;

pub struct SyncJournal {
    events:            Mutex<VecDeque<SyncEvent>>,
    seq:               AtomicU64,
    connected_slaves:  Mutex<HashMap<String, SlaveInfo>>,
    /// Registered nodes (node_id → SlaveInfo). Persisted to slaves.json (#88).
    registered_nodes:  Mutex<HashMap<String, SlaveInfo>>,
    /// Per-peer rate-limit for the public /sync/cert endpoint:
    /// maps peer-addr → (request_count_in_window, window_start).
    cert_rl:           dashmap::DashMap<String, (u32, Instant), ahash::RandomState>,
}

impl SyncJournal {
    pub fn new() -> Arc<Self> {
        let j = Arc::new(Self {
            events:           Mutex::new(VecDeque::with_capacity(JOURNAL_CAPACITY)),
            seq:              AtomicU64::new(0),
            connected_slaves: Mutex::new(HashMap::new()),
            registered_nodes: Mutex::new(HashMap::new()),
            cert_rl:          dashmap::DashMap::with_hasher(ahash::RandomState::default()),
        });
        j.load_nodes();
        j
    }

    /// Record or refresh a slave connection (called from /sync/state and /sync/delta).
    /// Deduplicates by IP — the ephemeral port is stripped so reconnects from the
    /// same slave don't create duplicate entries.
    pub fn record_slave(&self, addr: String, seq: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ip = slave_ip(&addr);
        let mut map = self.connected_slaves.lock().unwrap_or_else(|e| panic!("sync: slaves mutex poisoned: {e}"));
        map.insert(ip.clone(), SlaveInfo {
            node_id:          None,
            addr:             ip,
            relay_host:       None,
            cert_fingerprint: None,
            last_seen_at:     now,
            last_seen_secs:   0,
            status:           String::new(),
            last_seq:         seq,
            zones_synced:     0,
            version:          None,
        });
    }

    /// Return a snapshot of recently-seen slaves (last-seen ≤ 5 min ago).
    /// Delegates to all_slaves_snapshot for a merged view of legacy + registered.
    pub fn connected_slaves(&self) -> Vec<SlaveInfo> {
        self.all_slaves_snapshot()
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

    // ── Node registration (#88) ───────────────────────────────────────────

    pub fn register_node(
        &self,
        node_id:          String,
        addr:             String,
        relay_host:       String,
        cert_fingerprint: String,
        version:          Option<String>,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let info = SlaveInfo {
            node_id:          Some(node_id.clone()),
            addr,
            relay_host:       Some(relay_host),
            cert_fingerprint: Some(cert_fingerprint),
            last_seen_at:     now,
            last_seen_secs:   0,
            status:           String::new(),
            last_seq:         0,
            zones_synced:     0,
            version,
        };
        self.registered_nodes.lock()
            .unwrap_or_else(|e| panic!("sync: registered_nodes mutex poisoned: {e}"))
            .insert(node_id, info);
        self.save_nodes();
    }

    /// Refresh last_seen for a registered node (called on relay contact).
    pub fn touch_node(&self, node_id: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Ok(mut map) = self.registered_nodes.lock() {
            if let Some(s) = map.get_mut(node_id) {
                s.last_seen_at = now;
            }
        }
    }

    /// Return all registered nodes with relay_host set (for config push).
    pub fn registered_slaves(&self) -> Vec<SlaveInfo> {
        self.registered_nodes.lock()
            .unwrap_or_else(|e| panic!("sync: registered_nodes mutex poisoned: {e}"))
            .values()
            .filter(|s| s.relay_host.is_some())
            .cloned()
            .collect()
    }

    /// Return a slave by node_id (for relay forward).
    pub fn get_node(&self, node_id: &str) -> Option<SlaveInfo> {
        self.registered_nodes.lock()
            .unwrap_or_else(|e| panic!("sync: registered_nodes mutex poisoned: {e}"))
            .get(node_id)
            .cloned()
    }

    /// Merged list for GET /api/sync/slaves (legacy connected + registered).
    pub fn all_slaves_snapshot(&self) -> Vec<SlaveInfo> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut out: Vec<SlaveInfo> = Vec::new();

        // Legacy sync-connected (IP keyed, no node_id)
        if let Ok(map) = self.connected_slaves.lock() {
            for s in map.values().filter(|s| now.saturating_sub(s.last_seen_at) < 300) {
                let secs = now.saturating_sub(s.last_seen_at);
                out.push(SlaveInfo {
                    node_id:          s.node_id.clone(),
                    addr:             s.addr.clone(),
                    relay_host:       s.relay_host.clone(),
                    cert_fingerprint: None,
                    last_seen_at:     s.last_seen_at,
                    last_seen_secs:   secs,
                    status:           if secs < 30 { "connected".into() } else { "disconnected".into() },
                    last_seq:         s.last_seq,
                    zones_synced:     s.zones_synced,
                    version:          s.version.clone(),
                });
            }
        }

        // Registered nodes
        if let Ok(map) = self.registered_nodes.lock() {
            for s in map.values() {
                // Skip if already present as legacy (by IP)
                if out.iter().any(|x| x.addr == s.addr && x.node_id.is_none()) {
                    continue;
                }
                let secs = now.saturating_sub(s.last_seen_at);
                out.push(SlaveInfo {
                    node_id:          s.node_id.clone(),
                    addr:             s.addr.clone(),
                    relay_host:       s.relay_host.clone(),
                    cert_fingerprint: None, // never expose fingerprint in API
                    last_seen_at:     s.last_seen_at,
                    last_seen_secs:   secs,
                    status:           if secs < 30 { "connected".into() } else { "disconnected".into() },
                    last_seq:         s.last_seq,
                    zones_synced:     s.zones_synced,
                    version:          s.version.clone(),
                });
            }
        }
        out
    }

    fn save_nodes(&self) {
        if let Ok(map) = self.registered_nodes.lock() {
            let path = slaves_json_path();
            match serde_json::to_string_pretty(map.values().collect::<Vec<_>>().as_slice()) {
                Ok(json) => { let _ = std::fs::write(&path, &json); }
                Err(e) => warn!("save_nodes: serialize failed: {e}"),
            }
        }
    }

    fn load_nodes(&self) {
        let path = slaves_json_path();
        if let Ok(data) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Vec<SlaveInfo>>(&data) {
                Ok(nodes) => {
                    let mut map = self.registered_nodes.lock()
                        .unwrap_or_else(|e| panic!("sync: registered_nodes mutex poisoned: {e}"));
                    for node in nodes {
                        if let Some(ref id) = node.node_id.clone() {
                            map.insert(id.clone(), node);
                        }
                    }
                    info!(count = map.len(), "Loaded registered nodes from slaves.json");
                }
                Err(e) => warn!("load_nodes: parse slaves.json failed: {e}"),
            }
        }
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
                Err(e) => {
                    // InvalidContentType = plain-HTTP client connected to TLS port.
                    let hint = if e.to_string().contains("InvalidContentType")
                        || e.to_string().contains("corrupt message")
                    {
                        " — plain-HTTP client? use HTTPS (TLS) on this port"
                    } else {
                        ""
                    };
                    warn!(%peer, "sync TLS: {e}{hint}");
                    return;
                }
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
    let method = req.method().to_string();
    let path   = req.uri().path().to_string();
    let query  = req.uri().query().unwrap_or("").to_string();

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

    // /nodes/register — HMAC-SHA256 auth (slave→master, #88).
    // Uses X-Runbound-TS + X-Runbound-Sig headers instead of Bearer token.
    if path == "/nodes/register" && method == "POST" {
        let ts_str = req.headers()
            .get("x-runbound-ts").and_then(|v| v.to_str().ok()).unwrap_or("");
        let sig = req.headers()
            .get("x-runbound-sig").and_then(|v| v.to_str().ok()).unwrap_or("");
        let ts: u64 = ts_str.parse().unwrap_or(0);
        if !hmac_verify_with_ts(&sync_key, "POST", "/nodes/register", ts, sig) {
            return Ok(json_resp(401, serde_json::json!({ "error": "UNAUTHORIZED" })));
        }
        let body_bytes = match req.collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => return Ok(json_resp(400, serde_json::json!({ "error": format!("body read: {e}") }))),
        };
        if body_bytes.len() > 4096 {
            return Ok(json_resp(413, serde_json::json!({ "error": "REQUEST_TOO_LARGE" })));
        }
        #[derive(serde::Deserialize)]
        struct RegisterReq {
            node_id:          String,
            relay_host:       String,  // "{slave_ip}:{slave_sync_port}"
            cert_fingerprint: String,
            version:          Option<String>,
        }
        let reg: RegisterReq = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(e) => return Ok(json_resp(400, serde_json::json!({ "error": format!("parse: {e}") }))),
        };
        // Validate node_id is a non-empty string (no UUID format enforcement — flexible)
        if reg.node_id.is_empty() || reg.relay_host.is_empty() || reg.cert_fingerprint.is_empty() {
            return Ok(json_resp(400, serde_json::json!({ "error": "MISSING_FIELDS" })));
        }
        let peer_ip = slave_ip(&peer_addr);
        info!(node_id = %reg.node_id, relay_host = %reg.relay_host, peer = %peer_ip, "Node registered");
        journal.register_node(
            reg.node_id.clone(),
            peer_ip,
            reg.relay_host,
            reg.cert_fingerprint,
            reg.version,
        );
        return Ok(json_ok(serde_json::json!({ "ok": true, "node_id": reg.node_id })));
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
    upstreams:   SharedUpstreams,
}

impl SlaveClient {
    pub fn new(
        master:      &str,
        sync_key:    &str,
        interval:    u64,
        zones:       Arc<ArcSwap<LocalZoneSet>>,
        zones_mutex: Arc<tokio::sync::Mutex<()>>,
        cfg:         Arc<UnboundConfig>,
        upstreams:   SharedUpstreams,
    ) -> Self {
        Self {
            host_port: master.to_string(),
            sync_key:  sync_key.to_string(),
            interval,
            zones,
            zones_mutex,
            cfg,
            upstreams,
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
            Err(e) => {
                let s = e.to_string();
                // TLS errors here almost always mean a stale pinned fingerprint —
                // master cert was replaced. Guide the admin to the exact fix.
                if s.contains("TLS") || s.contains("handshake") || s.contains("reset")
                    || s.contains("fingerprint") || s.contains("InvalidCertificate")
                {
                    error!(
                        "Slave sync: TLS failure on initial sync: {e}\n\
                         The master certificate may have changed since TOFU was performed.\n\
                         To re-pin: delete {} and restart the slave.",
                        fingerprint_path().display()
                    );
                } else {
                    warn!("Slave sync: initial full sync failed: {e}");
                }
                0
            }
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
            SyncOp::AddUpstream { addr, port, protocol, name, tls_hostname } => {
                add_upstream(&self.upstreams, addr, port, protocol, name, tls_hostname);
            }
            SyncOp::DeleteUpstream { id } => {
                remove_upstream(&self.upstreams, &id);
            }
        }
        Ok(())
    }
}

// ── Node relay server (slave side, #85) ───────────────────────────────────────

/// State passed to the slave relay server for executing relayed operations.
pub struct NodeRelay {
    pub zones:        Arc<ArcSwap<LocalZoneSet>>,
    pub zones_mutex:  Arc<tokio::sync::Mutex<()>>,
    pub cfg:          Arc<UnboundConfig>,
    pub upstreams:    SharedUpstreams,
    pub stats_cache:  crate::stats::SharedSnapshot,
}

/// Slave relay TLS server — listens on sync_port, handles /relay/* paths.
/// Only HMAC-authenticated requests from master are accepted.
pub async fn start_node_server(
    port:     u16,
    sync_key: String,
    cert_pem: String,
    key_pem:  String,
    relay:    Arc<NodeRelay>,
) -> anyhow::Result<()> {
    let tls_config = Arc::new(server_tls_config(&cert_pem, &key_pem)?);
    let acceptor   = TlsAcceptor::from(tls_config);
    let listener   = TcpListener::bind(format!("0.0.0.0:{port}")).await
        .map_err(|e| anyhow::anyhow!("bind node relay port {port}: {e}"))?;
    info!(port, "Node relay server listening");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x)  => x,
            Err(e) => { warn!("relay accept: {e}"); continue; }
        };
        let acceptor  = acceptor.clone();
        let sync_key  = sync_key.clone();
        let relay     = Arc::clone(&relay);
        let peer_str  = peer.to_string();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s)  => s,
                Err(e) => { warn!(peer = %peer_str, "relay TLS: {e}"); return; }
            };
            let io = TokioIo::new(tls);
            let svc = service_fn(move |req| {
                handle_relay_request(req, sync_key.clone(), Arc::clone(&relay))
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                warn!(peer = %peer_str, "relay conn: {e}");
            }
        });
    }
}

async fn handle_relay_request(
    req:      hyper::Request<hyper::body::Incoming>,
    sync_key: String,
    relay:    Arc<NodeRelay>,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let path   = req.uri().path().to_string();

    // Only /relay/* is served here.
    if !path.starts_with("/relay/") && path != "/relay" {
        return Ok(json_resp(404, serde_json::json!({ "error": "NOT_FOUND" })));
    }

    // Validate HMAC + timestamp (replay protection ±30s).
    let ts_str = req.headers()
        .get("x-runbound-ts").and_then(|v| v.to_str().ok()).unwrap_or("");
    let sig = req.headers()
        .get("x-runbound-sig").and_then(|v| v.to_str().ok()).unwrap_or("");
    let ts: u64 = ts_str.parse().unwrap_or(0);
    if !hmac_verify_with_ts(&sync_key, &method, &path, ts, sig) {
        return Ok(json_resp(401, serde_json::json!({ "error": "UNAUTHORIZED" })));
    }

    // Strip /relay/ prefix to get the operation path.
    let op = path.strip_prefix("/relay/").unwrap_or("").trim_matches('/');

    // Read body (max 64 KiB).
    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return Ok(json_resp(400, serde_json::json!({ "error": format!("body read: {e}") }))),
    };
    if body_bytes.len() > 65_536 {
        return Ok(json_resp(413, serde_json::json!({ "error": "REQUEST_TOO_LARGE" })));
    }

    match (method.as_str(), op) {
        // ── DNS ──────────────────────────────────────────────────────────────
        ("POST", "dns") => {
            let entry: DnsEntry = match serde_json::from_slice(&body_bytes) {
                Ok(e) => e,
                Err(e) => return Ok(json_resp(400, serde_json::json!({ "error": format!("parse: {e}") }))),
            };
            let _guard = relay.zones_mutex.lock().await;
            let mut st = load().unwrap_or_default();
            if !st.entries.iter().any(|e| e.id == entry.id) {
                if let Some(rr) = entry.to_rr_string() {
                    if let Some(record) = parse_local_data(&rr) {
                        let current = relay.zones.load_full();
                        let mut new_zones = (*current).clone();
                        let name = record.name.clone();
                        new_zones.zones.entry(name.clone()).or_insert(ZoneAction::Static);
                        new_zones.records.entry(name).or_default().push(record);
                        relay.zones.store(Arc::new(new_zones));
                    }
                }
                st.entries.push(entry.clone());
                if let Err(e) = save(&st) {
                    return Ok(json_resp(500, serde_json::json!({ "error": format!("save: {e}") })));
                }
            }
            Ok(json_ok(serde_json::json!({ "ok": true, "id": entry.id })))
        }
        ("DELETE", op) if op.starts_with("dns/") => {
            let id = op.trim_start_matches("dns/");
            let _guard = relay.zones_mutex.lock().await;
            let mut st = load().unwrap_or_default();
            st.entries.retain(|e| e.id != id);
            if let Err(e) = save(&st) {
                return Ok(json_resp(500, serde_json::json!({ "error": format!("save: {e}") })));
            }
            let new_zones = crate::build_zone_set(&relay.cfg);
            relay.zones.store(Arc::new(new_zones));
            Ok(json_ok(serde_json::json!({ "ok": true })))
        }
        // ── Blacklist ────────────────────────────────────────────────────────
        ("POST", "blacklist") => {
            let entry: BlacklistEntry = match serde_json::from_slice(&body_bytes) {
                Ok(e) => e,
                Err(e) => return Ok(json_resp(400, serde_json::json!({ "error": format!("parse: {e}") }))),
            };
            let _guard = relay.zones_mutex.lock().await;
            let mut bl = load_blacklist().unwrap_or_default();
            if !bl.entries.iter().any(|e| e.id == entry.id) {
                let action = ZoneAction::from(&entry.action);
                bl.entries.push(entry.clone());
                if let Err(e) = save_blacklist(&bl) {
                    return Ok(json_resp(500, serde_json::json!({ "error": format!("save: {e}") })));
                }
                let current = relay.zones.load_full();
                let mut new_zones = (*current).clone();
                new_zones.override_zone(&entry.domain, action);
                relay.zones.store(Arc::new(new_zones));
            }
            Ok(json_ok(serde_json::json!({ "ok": true, "id": entry.id })))
        }
        ("DELETE", op) if op.starts_with("blacklist/") => {
            let id = op.trim_start_matches("blacklist/");
            let _guard = relay.zones_mutex.lock().await;
            let mut bl = load_blacklist().unwrap_or_default();
            bl.entries.retain(|e| e.id != id);
            if let Err(e) = save_blacklist(&bl) {
                return Ok(json_resp(500, serde_json::json!({ "error": format!("save: {e}") })));
            }
            let new_zones = crate::build_zone_set(&relay.cfg);
            relay.zones.store(Arc::new(new_zones));
            Ok(json_ok(serde_json::json!({ "ok": true })))
        }
        // ── Upstreams ────────────────────────────────────────────────────────
        ("POST", "upstreams") => {
            #[derive(serde::Deserialize)]
            struct RelayUpstream {
                addr: String, port: u16, protocol: String,
                name: Option<String>, tls_hostname: Option<String>,
            }
            let u: RelayUpstream = match serde_json::from_slice(&body_bytes) {
                Ok(u) => u,
                Err(e) => return Ok(json_resp(400, serde_json::json!({ "error": format!("parse: {e}") }))),
            };
            let entry = add_upstream(&relay.upstreams, u.addr, u.port, u.protocol, u.name, u.tls_hostname);
            Ok(json_ok(serde_json::json!({ "ok": true, "id": entry.id })))
        }
        ("DELETE", op) if op.starts_with("upstreams/") => {
            let id = op.trim_start_matches("upstreams/");
            remove_upstream(&relay.upstreams, id);
            Ok(json_ok(serde_json::json!({ "ok": true })))
        }
        // ── Snapshot (#87) ───────────────────────────────────────────────────
        ("GET", "snapshot") => {
            let dns       = load().unwrap_or_default().entries;
            let blacklist = load_blacklist().unwrap_or_default().entries;
            let feeds     = load_feeds().unwrap_or_default().feeds;
            Ok(json_ok(serde_json::json!({
                "dns": dns, "blacklist": blacklist, "feeds": feeds,
            })))
        }
        // ── Read-only queries forwarded from master ───────────────────────────
        ("GET", "stats") => {
            let snap = relay.stats_cache.load();
            Ok(json_ok(crate::stats::snapshot_to_json(&snap)))
        }
        ("GET", "upstreams") => {
            let statuses = relay.upstreams.read().map(|g| g.clone()).unwrap_or_default();
            let total   = statuses.len();
            let healthy = statuses.iter().filter(|u| u.healthy).count();
            Ok(json_ok(serde_json::json!({
                "upstreams": statuses,
                "total":     total,
                "healthy":   healthy,
            })))
        }
        _ => Ok(json_resp(404, serde_json::json!({ "error": "NOT_FOUND" }))),
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
