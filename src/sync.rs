// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// src/sync.rs — slave/master synchronisation (delta journal + TOFU TLS)

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
use crate::dns::local::{parse_local_data, LocalZoneSet};
use crate::dns::ZoneAction;
use crate::feeds::{load_feeds, save_feeds, update_one_feed, Feed, FeedsConfig};
use crate::store::{
    load, load_blacklist, save, save_blacklist, BlacklistEntry, BlacklistStore, DnsEntry, DnsStore,
};
use crate::upstreams::{add_upstream, remove_upstream, SharedUpstreams};

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
fn fingerprint_path() -> std::path::PathBuf {
    crate::runtime::base_dir().join("sync-master.fingerprint")
}
fn sync_cert_path() -> std::path::PathBuf {
    crate::runtime::base_dir().join("sync-cert.pem")
}
fn sync_key_path() -> std::path::PathBuf {
    crate::runtime::base_dir().join("sync-key.pem")
}
fn slaves_json_path() -> std::path::PathBuf {
    crate::runtime::base_dir().join("slaves.json")
}
fn node_id_path() -> std::path::PathBuf {
    crate::runtime::base_dir().join("node-id")
}
fn relay_cert_path() -> std::path::PathBuf {
    crate::runtime::base_dir().join("relay-cert.pem")
}
fn relay_key_path() -> std::path::PathBuf {
    crate::runtime::base_dir().join("relay-key.pem")
}

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

pub fn hmac_sign(key: &str, method: &str, path: &str, ts: u64, body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    // SEC-I14: the request body is part of the signed message (after the header line).
    let msg = format!("{method}\n{path}\n{ts}\n");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(msg.as_bytes());
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time HMAC verification. Returns true iff the signature is valid
/// AND the timestamp is within ±30 s of the current server clock.
pub fn hmac_verify_with_ts(
    key: &str,
    method: &str,
    path: &str,
    ts: u64,
    body: &[u8],
    sig: &str,
) -> bool {
    let now = hmac_unix_now();
    let diff = if now >= ts { now - ts } else { ts - now };
    if diff > 30 {
        return false;
    }
    // SEC-J5 (v0.18.x): only the body-covering signature is accepted. The pre-v0.17.1
    // header-only fallback (which left the request body unauthenticated) was removed now
    // that the fleet is >= v0.17.1. The relay channel is TLS-pinned; this is defence in depth.
    ct_eq_hex(&hmac_sign(key, method, path, ts, body), sig)
}

/// Constant-time comparison of two equal-purpose hex strings (length mismatch also fails).
fn ct_eq_hex(expected: &str, sig: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let len_ok: u8 = if expected.len() == sig.len() { 1 } else { 0 };
    let byte_diff: u8 = sig
        .bytes()
        .zip(expected.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    let combined = byte_diff | (1u8.wrapping_sub(len_ok));
    combined.ct_eq(&0u8).into()
}

/// SEC-J7: write a private-key file atomically with mode 0600 from creation, so the key
/// is never briefly world-readable in the window between `write` and a later `chmod`.
fn write_key_0600(path: &std::path::Path, pem: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(path)
            .map_err(|e| anyhow::anyhow!("create key {path:?}: {e}"))?;
        f.write_all(pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("write key {path:?}: {e}"))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, pem).map_err(|e| anyhow::anyhow!("write key {path:?}: {e}"))?;
    Ok(())
}

/// Generate or load the relay TLS cert (separate from sync cert — each node has its own).
pub fn ensure_relay_cert() -> anyhow::Result<(String, String)> {
    use std::fs;

    let cert_path = relay_cert_path();
    let key_path = relay_key_path();
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
    let key_pem = key_pair.serialize_pem();
    fs::write(&cert_path, &cert_pem).map_err(|e| anyhow::anyhow!("write relay-cert.pem: {e}"))?;
    write_key_0600(&key_path, &key_pem)?;
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
    std::fs::write(&path, &id).map_err(|e| anyhow::anyhow!("write node-id: {e}"))?;
    info!(%id, "Generated new node UUID");
    Ok(id)
}

// ── SyncJournal ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum SyncOp {
    AddDns {
        entry: DnsEntry,
    },
    DeleteDns {
        id: String,
    },
    AddBlacklist {
        entry: BlacklistEntry,
    },
    DeleteBlacklist {
        id: String,
    },
    AddFeed {
        feed: Feed,
    },
    DeleteFeed {
        id: String,
    },
    UpdateFeed {
        id: String,
        url: String,
    },
    // #87 — upstream replication
    AddUpstream {
        addr: String,
        port: u16,
        protocol: String,
        name: Option<String>,
        tls_hostname: Option<String>,
    },
    DeleteUpstream {
        id: String,
    },
    // Bot defense cross-cluster ban propagation
    AddGlobalBan {
        ip: String,
        rule: String,
        expires_secs: Option<u64>,
    },
    DeleteGlobalBan {
        ip: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEvent {
    pub seq: u64,
    pub ts: u64,
    pub op: SyncOp,
}

/// #86: SSE event pushed to GET /api/events subscribers when a slave's health
/// status changes.  Status thresholds: ok (<15s), warn (15-60s), error (>60s).
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatusEvent {
    pub node_id: String,
    pub addr: String,
    /// "ok" | "warn" | "error"
    pub status: String,
    pub reason: String,
    /// Unix timestamp (seconds) when the event was generated.
    pub ts: u64,
}

/// Snapshot of a connected slave returned by GET /api/sync/slaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaveInfo {
    /// Stable UUID identifying this node (set at registration, #88).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Slave IP address (deduplicated — ephemeral port stripped).
    pub addr: String,
    /// "{ip}:{sync_port}" used by master to reach slave for relay (#85).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_host: Option<String>,
    /// SHA-256 hex of slave's TLS cert — pinned for relay connections (#85).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_fingerprint: Option<String>,
    /// Unix timestamp of the last contact.
    pub last_seen_at: u64,
    /// Seconds elapsed since last contact (computed at query time).
    #[serde(default)]
    pub last_seen_secs: u64,
    /// "connected" (seen ≤30s ago) or "disconnected".
    #[serde(default)]
    pub status: String,
    pub last_seq: u64,
    /// Number of zones synchronised (0 = not tracked yet).
    pub zones_synced: u32,
    /// Slave binary version (null = not reported yet).
    pub version: Option<String>,
}

// Max calls to /sync/cert per peer IP per 60-second window (TOFU bootstrap guard).
const CERT_RL_MAX: u32 = 10;

pub struct SyncJournal {
    events: Mutex<VecDeque<SyncEvent>>,
    seq: AtomicU64,
    connected_slaves: Mutex<HashMap<String, SlaveInfo>>,
    /// Registered nodes (node_id → SlaveInfo). Persisted to slaves.json (#88).
    registered_nodes: Mutex<HashMap<String, SlaveInfo>>,
    /// Per-peer rate-limit for the public /sync/cert endpoint:
    /// maps peer-addr → (request_count_in_window, window_start).
    cert_rl: dashmap::DashMap<String, (u32, Instant), ahash::RandomState>,
    /// #86: broadcast channel for SSE node-status events.
    pub events_tx: tokio::sync::broadcast::Sender<NodeStatusEvent>,
}

impl SyncJournal {
    pub fn new() -> Arc<Self> {
        let (events_tx, _) = tokio::sync::broadcast::channel::<NodeStatusEvent>(64);
        let j = Arc::new(Self {
            events: Mutex::new(VecDeque::with_capacity(JOURNAL_CAPACITY)),
            seq: AtomicU64::new(0),
            connected_slaves: Mutex::new(HashMap::new()),
            registered_nodes: Mutex::new(HashMap::new()),
            cert_rl: dashmap::DashMap::with_hasher(ahash::RandomState::default()),
            events_tx,
        });
        j.load_nodes();
        // #86: spawn slave-status watcher
        let weak = Arc::downgrade(&j);
        let tx = j.events_tx.clone();
        tokio::spawn(slave_status_watcher(weak, tx));
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
        let mut map = self
            .connected_slaves
            .lock()
            .unwrap_or_else(|e| panic!("sync: slaves mutex poisoned: {e}"));
        map.insert(
            ip.clone(),
            SlaveInfo {
                node_id: None,
                addr: ip,
                relay_host: None,
                cert_fingerprint: None,
                last_seen_at: now,
                last_seen_secs: 0,
                status: String::new(),
                last_seq: seq,
                zones_synced: 0,
                version: None,
            },
        );
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
        let mut q = self
            .events
            .lock()
            .unwrap_or_else(|e| panic!("sync: events mutex poisoned: {e}"));
        if q.len() >= JOURNAL_CAPACITY {
            q.pop_front();
        }
        q.push_back(SyncEvent { seq, ts, op });
        seq
    }

    /// Returns events with seq >= since.
    /// Returns None when `since` predates the ring buffer — slave must do a full sync.
    pub fn delta(&self, since: u64) -> Option<Vec<SyncEvent>> {
        let q = self
            .events
            .lock()
            .unwrap_or_else(|e| panic!("sync: events mutex poisoned: {e}"));
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
        node_id: String,
        addr: String,
        relay_host: String,
        cert_fingerprint: String,
        version: Option<String>,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let info = SlaveInfo {
            node_id: Some(node_id.clone()),
            addr,
            relay_host: Some(relay_host),
            cert_fingerprint: Some(cert_fingerprint),
            last_seen_at: now,
            last_seen_secs: 0,
            status: String::new(),
            last_seq: 0,
            zones_synced: 0,
            version,
        };
        self.registered_nodes
            .lock()
            .unwrap_or_else(|e| panic!("sync: registered_nodes mutex poisoned: {e}"))
            .insert(node_id, info);
        self.save_nodes();
    }


    /// Return all registered nodes with relay_host set (for config push).
    pub fn registered_slaves(&self) -> Vec<SlaveInfo> {
        self.registered_nodes
            .lock()
            .unwrap_or_else(|e| panic!("sync: registered_nodes mutex poisoned: {e}"))
            .values()
            .filter(|s| s.relay_host.is_some())
            .cloned()
            .collect()
    }

    /// Return a slave by node_id (for relay forward).
    pub fn get_node(&self, node_id: &str) -> Option<SlaveInfo> {
        self.registered_nodes
            .lock()
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
            for s in map
                .values()
                .filter(|s| now.saturating_sub(s.last_seen_at) < 300)
            {
                let secs = now.saturating_sub(s.last_seen_at);
                out.push(SlaveInfo {
                    node_id: s.node_id.clone(),
                    addr: s.addr.clone(),
                    relay_host: s.relay_host.clone(),
                    cert_fingerprint: None,
                    last_seen_at: s.last_seen_at,
                    last_seen_secs: secs,
                    status: if secs < 30 {
                        "connected".into()
                    } else {
                        "disconnected".into()
                    },
                    last_seq: s.last_seq,
                    zones_synced: s.zones_synced,
                    version: s.version.clone(),
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
                    node_id: s.node_id.clone(),
                    addr: s.addr.clone(),
                    relay_host: s.relay_host.clone(),
                    cert_fingerprint: None, // never expose fingerprint in API
                    last_seen_at: s.last_seen_at,
                    last_seen_secs: secs,
                    status: if secs < 30 {
                        "connected".into()
                    } else {
                        "disconnected".into()
                    },
                    last_seq: s.last_seq,
                    zones_synced: s.zones_synced,
                    version: s.version.clone(),
                });
            }
        }
        out
    }

    fn save_nodes(&self) {
        if let Ok(map) = self.registered_nodes.lock() {
            let path = slaves_json_path();
            match serde_json::to_string_pretty(map.values().collect::<Vec<_>>().as_slice()) {
                Ok(json) => {
                    let _ = std::fs::write(&path, &json);
                }
                Err(e) => warn!("save_nodes: serialize failed: {e}"),
            }
        }
    }

    fn load_nodes(&self) {
        let path = slaves_json_path();
        if let Ok(data) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Vec<SlaveInfo>>(&data) {
                Ok(nodes) => {
                    let mut map = self
                        .registered_nodes
                        .lock()
                        .unwrap_or_else(|e| panic!("sync: registered_nodes mutex poisoned: {e}"));
                    for node in nodes {
                        if let Some(ref id) = node.node_id.clone() {
                            map.insert(id.clone(), node);
                        }
                    }
                    info!(
                        count = map.len(),
                        "Loaded registered nodes from slaves.json"
                    );
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

    let cert_path = sync_cert_path();
    let key_path = sync_key_path();
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
    fs::write(&cert_path, &cert_pem).map_err(|e| anyhow::anyhow!("write sync-cert.pem: {e}"))?;
    write_key_0600(&key_path, &key_pem)?;

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
                "cert fingerprint mismatch: got {got}, expected {}",
                self.fingerprint
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
        Arc::new(Self {
            captured: Mutex::new(None),
        })
    }
    fn take_fingerprint(&self) -> Option<String> {
        self.captured
            .lock()
            .unwrap_or_else(|e| panic!("sync: TOFU captured mutex poisoned: {e}"))
            .clone()
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
        *self
            .captured
            .lock()
            .unwrap_or_else(|e| panic!("sync: TOFU captured mutex poisoned: {e}")) = Some(fp);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    impl_tls_signature_verification!(TofuVerifier);
}

pub fn pinned_client_config(fingerprint: &str) -> rustls::ClientConfig {
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
    let tcp = tokio::net::TcpStream::connect(host_port)
        .await
        .map_err(|e| anyhow::anyhow!("TCP connect {host_port}: {e}"))?;

    let sni_host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    let server_name = if let Ok(ip) = sni_host.parse::<std::net::IpAddr>() {
        rustls::pki_types::ServerName::IpAddress(ip.into())
    } else {
        rustls::pki_types::ServerName::try_from(sni_host.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid SNI: {e}"))?
    };
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("TLS handshake: {e}"))?;

    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
        .map_err(|e| anyhow::anyhow!("HTTP handshake: {e}"))?;
    tokio::spawn(async move {
        conn.await.ok();
    });

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

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| anyhow::anyhow!("send request: {e}"))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("collect body: {e}"))?
        .to_bytes();

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
    allow_private_relay: bool,
) -> anyhow::Result<()> {
    let tls_config = Arc::new(server_tls_config(&cert_pem, &key_pem)?);
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .map_err(|e| anyhow::anyhow!("bind sync port {port}: {e}"))?;
    info!(port, "Sync HTTPS server listening");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("sync accept: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let journal = Arc::clone(&journal);
        let sync_key = sync_key.clone();
        let cert_fp = cert_fingerprint.clone();
        let allow_priv = allow_private_relay;

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
                handle_sync_request(
                    req,
                    Arc::clone(&journal),
                    sync_key.clone(),
                    cert_fp.clone(),
                    peer_str2.clone(),
                    allow_priv,
                )
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
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
    allow_private_relay: bool,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    // /sync/cert — returns fingerprint, no auth (TOFU bootstrap).
    // Rate-limited per peer IP: max 10 requests per 60-second window to prevent
    // enumeration of certificate rotations by unauthenticated callers.
    if path == "/sync/cert" {
        let now = Instant::now();
        let allowed = {
            // Key by IP (not IP:port) so rate limit applies per host, not per connection.
            let cert_rl_key = slave_ip(&peer_addr);
            let mut entry = journal.cert_rl.entry(cert_rl_key).or_insert((0u32, now));
            if entry.1.elapsed().as_secs() >= 60 {
                *entry = (1, now);
                true
            } else {
                entry.0 += 1;
                entry.0 <= CERT_RL_MAX
            }
        };
        if !allowed {
            return Ok(json_resp(
                429,
                serde_json::json!({ "error": "RATE_LIMITED" }),
            ));
        }
        return Ok(json_ok(
            serde_json::json!({ "fingerprint": cert_fingerprint }),
        ));
    }

    // /nodes/register — HMAC-SHA256 auth (slave→master, #88).
    // Uses X-Runbound-TS + X-Runbound-Sig headers instead of Bearer token.
    if path == "/nodes/register" && method == "POST" {
        let ts_str = req
            .headers()
            .get("x-runbound-ts")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let sig = req
            .headers()
            .get("x-runbound-sig")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let ts: u64 = ts_str.parse().unwrap_or(0);
        // SEC-I14: read the body BEFORE verifying so the HMAC can cover it.
        let body_bytes = match req.collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                return Ok(json_resp(
                    400,
                    serde_json::json!({ "error": format!("body read: {e}") }),
                ))
            }
        };
        if !hmac_verify_with_ts(&sync_key, "POST", "/nodes/register", ts, &body_bytes, &sig) {
            return Ok(json_resp(
                401,
                serde_json::json!({ "error": "UNAUTHORIZED" }),
            ));
        }
        if body_bytes.len() > 4096 {
            return Ok(json_resp(
                413,
                serde_json::json!({ "error": "REQUEST_TOO_LARGE" }),
            ));
        }
        #[derive(serde::Deserialize)]
        struct RegisterReq {
            node_id: String,
            relay_host: String, // "{slave_ip}:{slave_sync_port}"
            cert_fingerprint: String,
            version: Option<String>,
        }
        let reg: RegisterReq = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(e) => {
                return Ok(json_resp(
                    400,
                    serde_json::json!({ "error": format!("parse: {e}") }),
                ))
            }
        };
        // Validate node_id is a non-empty string (no UUID format enforcement — flexible)
        if reg.node_id.is_empty() || reg.relay_host.is_empty() || reg.cert_fingerprint.is_empty() {
            return Ok(json_resp(
                400,
                serde_json::json!({ "error": "MISSING_FIELDS" }),
            ));
        }
        // SEC-2026-05-24-06: validate relay_host is a valid IP:port, reject loopback/
        // unspecified/link-local to prevent SSRF via relay forward from master.
        if reg.relay_host.len() > 64 {
            return Ok(json_resp(
                400,
                serde_json::json!({
                    "error": "INVALID_RELAY_HOST", "details": "relay_host too long"
                }),
            ));
        }
        let relay_ip_str = if reg.relay_host.starts_with('[') {
            reg.relay_host
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or("")
        } else {
            reg.relay_host.rsplitn(2, ':').nth(1).unwrap_or("")
        };
        match relay_ip_str.parse::<std::net::IpAddr>() {
            Err(_) => {
                return Ok(json_resp(
                    400,
                    serde_json::json!({
                        "error": "INVALID_RELAY_HOST",
                        "details": "relay_host must be a valid IP:port (e.g. 192.168.1.2:8082)"
                    }),
                ))
            }
            Ok(ip) => {
                if ip.is_loopback() || ip.is_unspecified() {
                    return Ok(json_resp(
                        400,
                        serde_json::json!({
                            "error": "INVALID_RELAY_HOST",
                            "details": "loopback/unspecified not allowed as relay_host"
                        }),
                    ));
                }
                match ip {
                    std::net::IpAddr::V4(v4) if v4.is_link_local() => {
                        return Ok(json_resp(400, serde_json::json!({
                            "error": "INVALID_RELAY_HOST",
                            "details": "link-local not allowed as relay_host"
                        })));
                    }
                    // SEC-A5: also reject IPv6 link-local (fe80::/10)
                    std::net::IpAddr::V6(v6) => {
                        let s = v6.segments();
                        if (s[0] & 0xffc0) == 0xfe80 {
                            return Ok(json_resp(400, serde_json::json!({
                                "error": "INVALID_RELAY_HOST",
                                "details": "link-local not allowed as relay_host"
                            })));
                        }
                        // SEC-B2: reject ULA fc00::/7
                        if (s[0] & 0xfe00) == 0xfc00 {
                            return Ok(json_resp(400, serde_json::json!({
                                "error": "INVALID_RELAY_HOST",
                                "details": "unique-local (ULA) not allowed as relay_host"
                            })));
                        }
                    }
                    // SEC-B2: reject RFC 1918 private ranges unless explicitly allowed
                    // (sync-allow-private-relay: yes in config — for LAN deployments).
                    std::net::IpAddr::V4(v4) if !allow_private_relay => {
                        let o = v4.octets();
                        let is_private = o[0] == 10
                            || (o[0] == 172 && (o[1] & 0xf0) == 16)
                            || (o[0] == 192 && o[1] == 168);
                        if is_private {
                            return Ok(json_resp(400, serde_json::json!({
                                "error": "INVALID_RELAY_HOST",
                                "details": "private RFC 1918 not allowed (set sync-allow-private-relay: yes for LAN)"
                            })));
                        }
                    }
                    std::net::IpAddr::V4(_) => {}
                }
            }
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
        return Ok(json_ok(
            serde_json::json!({ "ok": true, "node_id": reg.node_id }),
        ));
    }

    // All other endpoints require Bearer auth — constant-time to prevent
    // timing oracles on the sync key length and content.
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {sync_key}");
    let authed: bool = {
        use subtle::ConstantTimeEq as _;
        auth.as_bytes().ct_eq(expected.as_bytes()).into()
    };
    if !authed {
        return Ok(json_resp(
            401,
            serde_json::json!({ "error": "UNAUTHORIZED" }),
        ));
    }

    match path.as_str() {
        "/sync/state" => {
            let seq = journal.current_seq();
            journal.record_slave(peer_addr, seq);
            Ok(json_ok(serde_json::json!({ "seq": seq })))
        }
        "/sync/config" => {
            let seq = journal.current_seq();
            let dns = load().unwrap_or_default().entries;
            let blacklist = load_blacklist().unwrap_or_default().entries;
            let feeds = load_feeds().unwrap_or_default().feeds;
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
                None => Ok(json_resp(
                    410,
                    serde_json::json!({ "error": "TOO_FAR_BEHIND" }),
                )),
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
    host_port: String,
    sync_key: String,
    interval: u64,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    zones_mutex: Arc<tokio::sync::Mutex<()>>,
    cfg: Arc<UnboundConfig>,
    upstreams: SharedUpstreams,
    alert_tracker: std::sync::Arc<crate::alerts::AlertTracker>,
    icmp_stats: std::sync::Arc<crate::icmp::IcmpStats>,
}

impl SlaveClient {
    pub fn new(
        master: &str,
        sync_key: &str,
        interval: u64,
        zones: Arc<ArcSwap<LocalZoneSet>>,
        zones_mutex: Arc<tokio::sync::Mutex<()>>,
        cfg: Arc<UnboundConfig>,
        upstreams: SharedUpstreams,
        alert_tracker: std::sync::Arc<crate::alerts::AlertTracker>,
        icmp_stats: std::sync::Arc<crate::icmp::IcmpStats>,
    ) -> Self {
        Self {
            host_port: master.to_string(),
            sync_key: sync_key.to_string(),
            interval,
            zones,
            zones_mutex,
            cfg,
            upstreams,
            alert_tracker,
            icmp_stats,
        }
    }

    pub async fn run(self) {
        let fingerprint = match self.tofu_handshake().await {
            Ok(fp) => fp,
            Err(e) => {
                error!("Slave sync TOFU failed: {e}");
                return;
            }
        };

        let tls_config = Arc::new(pinned_client_config(&fingerprint));

        let mut last_seq = match self.full_sync(&tls_config).await {
            Ok(seq) => {
                info!("Slave sync: initial full sync complete (seq={seq})");
                seq
            }
            Err(e) => {
                let s = e.to_string();
                // TLS errors here almost always mean a stale pinned fingerprint —
                // master cert was replaced. Guide the admin to the exact fix.
                if s.contains("TLS")
                    || s.contains("handshake")
                    || s.contains("reset")
                    || s.contains("fingerprint")
                    || s.contains("InvalidCertificate")
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
                        Ok(seq) => {
                            last_seq = seq;
                            info!("Slave sync: recovery full sync (seq={seq})");
                        }
                        Err(e) => {
                            warn!("Slave sync: full sync failed: {e}");
                            self.sleep_backoff(&mut backoff_secs).await;
                        }
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
                .with_no_client_auth(),
        );

        let (status, body) = sync_get(&self.host_port, tls_config, "/sync/cert", None).await?;
        if status != 200 {
            return Err(anyhow::anyhow!("TOFU /sync/cert returned {status}"));
        }

        let fp = verifier
            .take_fingerprint()
            .ok_or_else(|| anyhow::anyhow!("TOFU: no cert captured during handshake"))?;

        #[derive(Deserialize)]
        struct CertResp {
            fingerprint: String,
        }
        let resp: CertResp = serde_json::from_slice(&body)?;

        if resp.fingerprint != fp {
            return Err(anyhow::anyhow!(
                "TOFU: cert fingerprint from TLS ({fp}) differs from /sync/cert body ({}) — possible MITM",
                resp.fingerprint
            ));
        }

        let fp_path = fingerprint_path();
        warn!(
            "Slave sync: pinning master SHA-256={fp} → {}",
            fp_path.display()
        );
        std::fs::create_dir_all(crate::runtime::base_dir())
            .map_err(|e| anyhow::anyhow!("create base_dir: {e}"))?;
        std::fs::write(&fp_path, &fp).map_err(|e| anyhow::anyhow!("write fingerprint: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&fp_path, std::fs::Permissions::from_mode(0o640));
        }

        Ok(fp)
    }

    async fn full_sync(&self, tls_config: &Arc<rustls::ClientConfig>) -> anyhow::Result<u64> {
        let auth = format!("Bearer {}", self.sync_key);
        let (status, body) = sync_get(
            &self.host_port,
            Arc::clone(tls_config),
            "/sync/config",
            Some(&auth),
        )
        .await?;
        if status != 200 {
            return Err(anyhow::anyhow!("full sync returned {status}"));
        }

        #[derive(Deserialize)]
        struct FullSyncResp {
            dns: Vec<DnsEntry>,
            blacklist: Vec<BlacklistEntry>,
            feeds: Vec<Feed>,
            seq: u64,
        }
        let resp: FullSyncResp =
            serde_json::from_slice(&body).map_err(|e| anyhow::anyhow!("parse full sync: {e}"))?;

        {
            let _guard = self.zones_mutex.lock().await;
            save(&DnsStore { entries: resp.dns }).map_err(|e| anyhow::anyhow!("save DNS: {e}"))?;
            save_blacklist(&BlacklistStore {
                entries: resp.blacklist,
            })
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
        let (status, body) = sync_get(
            &self.host_port,
            Arc::clone(tls_config),
            "/sync/state",
            Some(&auth),
        )
        .await
        .map_err(|e| SyncError::Request(e.to_string()))?;
        if status != 200 {
            return Err(SyncError::Request(format!("/sync/state returned {status}")));
        }
        #[derive(Deserialize)]
        struct StateResp {
            seq: u64,
        }
        let state: StateResp = serde_json::from_slice(&body)
            .map_err(|e| SyncError::Request(format!("parse state: {e}")))?;
        if state.seq <= last_seq {
            return Ok(last_seq);
        }

        // Pull delta
        let path = format!("/sync/delta?since={last_seq}");
        let (status, body) = sync_get(&self.host_port, Arc::clone(tls_config), &path, Some(&auth))
            .await
            .map_err(|e| SyncError::Request(e.to_string()))?;
        if status == 410 {
            return Err(SyncError::TooFarBehind);
        }
        if status != 200 {
            return Err(SyncError::Request(format!("/sync/delta returned {status}")));
        }

        #[derive(Deserialize)]
        struct DeltaResp {
            events: Vec<SyncEvent>,
            seq: u64,
        }
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
                            new_zones
                                .zones
                                .entry(name.clone())
                                .or_insert(ZoneAction::Static);
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
            SyncOp::AddUpstream {
                addr,
                port,
                protocol,
                name,
                tls_hostname,
            } => {
                add_upstream(&self.upstreams, addr, port, protocol, name, tls_hostname);
            }
            SyncOp::DeleteUpstream { id } => {
                remove_upstream(&self.upstreams, &id);
            }
            SyncOp::AddGlobalBan { ip, rule, expires_secs } => {
                if let Ok(parsed_ip) = ip.parse::<std::net::IpAddr>() {
                    let dur = expires_secs.unwrap_or(86400);
                    self.alert_tracker.block_bot(parsed_ip, &rule, dur);
                    if let std::net::IpAddr::V4(ipv4) = parsed_ip {
                        let _ = self.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::Ban(ipv4));
                    }
                }
            }
            SyncOp::DeleteGlobalBan { ip } => {
                if let Ok(parsed_ip) = ip.parse::<std::net::IpAddr>() {
                    self.alert_tracker.unblock(parsed_ip);
                    if let std::net::IpAddr::V4(ipv4) = parsed_ip {
                        let _ = self.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::Unban(ipv4));
                    }
                }
            }
        }
        Ok(())
    }
}

// ── Node relay server (slave side, #85) ───────────────────────────────────────

/// State passed to the slave relay server for executing relayed operations.
pub struct NodeRelay {
    pub zones: Arc<ArcSwap<LocalZoneSet>>,
    pub zones_mutex: Arc<tokio::sync::Mutex<()>>,
    pub cfg: Arc<UnboundConfig>,
    pub upstreams: SharedUpstreams,
    pub stats_cache: crate::stats::SharedSnapshot,
    pub domain_stats: Arc<crate::domain_stats::DomainStats>,
    pub dnssec_enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub resolver: crate::dns::server::SharedResolver,
    pub icmp_stats: std::sync::Arc<crate::icmp::IcmpStats>,
    pub icmp_cfg: std::sync::Arc<std::sync::Mutex<crate::icmp::IcmpConfig>>,
    pub base_dir: std::sync::Arc<std::path::PathBuf>,
    pub alert_tracker: std::sync::Arc<crate::alerts::AlertTracker>,
}

/// Slave relay TLS server — listens on sync_port, handles /relay/* paths.
/// Only HMAC-authenticated requests from master are accepted.
pub async fn start_node_server(
    port: u16,
    sync_key: String,
    cert_pem: String,
    key_pem: String,
    relay: Arc<NodeRelay>,
) -> anyhow::Result<()> {
    let tls_config = Arc::new(server_tls_config(&cert_pem, &key_pem)?);
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .map_err(|e| anyhow::anyhow!("bind node relay port {port}: {e}"))?;
    info!(port, "Node relay server listening");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("relay accept: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let sync_key = sync_key.clone();
        let relay = Arc::clone(&relay);
        let peer_str = peer.to_string();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %peer_str, "relay TLS: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls);
            let svc = service_fn(move |req| {
                handle_relay_request(req, sync_key.clone(), Arc::clone(&relay))
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, svc)
                .await
            {
                warn!(peer = %peer_str, "relay conn: {e}");
            }
        });
    }
}

async fn handle_relay_request(
    req: hyper::Request<hyper::body::Incoming>,
    sync_key: String,
    relay: Arc<NodeRelay>,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // Only /relay/* is served here.
    if !path.starts_with("/relay/") && path != "/relay" {
        return Ok(json_resp(404, serde_json::json!({ "error": "NOT_FOUND" })));
    }

    // Validate HMAC + timestamp (replay protection ±30s).
    let ts_str = req
        .headers()
        .get("x-runbound-ts")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let sig = req
        .headers()
        .get("x-runbound-sig")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ts: u64 = ts_str.parse().unwrap_or(0);

    // Strip /relay/ prefix to get the operation path.
    let op = path.strip_prefix("/relay/").unwrap_or("").trim_matches('/');

    // SEC-I14: read the body BEFORE verifying so the HMAC can cover it (max 64 KiB).
    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return Ok(json_resp(
                400,
                serde_json::json!({ "error": format!("body read: {e}") }),
            ))
        }
    };
    if !hmac_verify_with_ts(&sync_key, &method, &path, ts, &body_bytes, &sig) {
        return Ok(json_resp(
            401,
            serde_json::json!({ "error": "UNAUTHORIZED" }),
        ));
    }
    if body_bytes.len() > 65_536 {
        return Ok(json_resp(
            413,
            serde_json::json!({ "error": "REQUEST_TOO_LARGE" }),
        ));
    }

    match (method.as_str(), op) {
        // ── DNS ──────────────────────────────────────────────────────────────
        ("POST", "dns") => {
            let entry: DnsEntry = match serde_json::from_slice(&body_bytes) {
                Ok(e) => e,
                Err(e) => {
                    return Ok(json_resp(
                        400,
                        serde_json::json!({ "error": format!("parse: {e}") }),
                    ))
                }
            };
            let _guard = relay.zones_mutex.lock().await;
            let mut st = load().unwrap_or_default();
            if !st.entries.iter().any(|e| e.id == entry.id) {
                if let Some(rr) = entry.to_rr_string() {
                    if let Some(record) = parse_local_data(&rr) {
                        let current = relay.zones.load_full();
                        let mut new_zones = (*current).clone();
                        let name = record.name.clone();
                        new_zones
                            .zones
                            .entry(name.clone())
                            .or_insert(ZoneAction::Static);
                        new_zones.records.entry(name).or_default().push(record);
                        relay.zones.store(Arc::new(new_zones));
                    }
                }
                st.entries.push(entry.clone());
                if let Err(e) = save(&st) {
                    return Ok(json_resp(
                        500,
                        serde_json::json!({ "error": format!("save: {e}") }),
                    ));
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
                return Ok(json_resp(
                    500,
                    serde_json::json!({ "error": format!("save: {e}") }),
                ));
            }
            let new_zones = crate::build_zone_set(&relay.cfg);
            relay.zones.store(Arc::new(new_zones));
            Ok(json_ok(serde_json::json!({ "ok": true })))
        }
        // ── Blacklist ────────────────────────────────────────────────────────
        ("POST", "blacklist") => {
            let entry: BlacklistEntry = match serde_json::from_slice(&body_bytes) {
                Ok(e) => e,
                Err(e) => {
                    return Ok(json_resp(
                        400,
                        serde_json::json!({ "error": format!("parse: {e}") }),
                    ))
                }
            };
            let _guard = relay.zones_mutex.lock().await;
            let mut bl = load_blacklist().unwrap_or_default();
            if !bl.entries.iter().any(|e| e.id == entry.id) {
                let action = ZoneAction::from(&entry.action);
                bl.entries.push(entry.clone());
                if let Err(e) = save_blacklist(&bl) {
                    return Ok(json_resp(
                        500,
                        serde_json::json!({ "error": format!("save: {e}") }),
                    ));
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
                return Ok(json_resp(
                    500,
                    serde_json::json!({ "error": format!("save: {e}") }),
                ));
            }
            let new_zones = crate::build_zone_set(&relay.cfg);
            relay.zones.store(Arc::new(new_zones));
            Ok(json_ok(serde_json::json!({ "ok": true })))
        }
        // ── Upstreams ────────────────────────────────────────────────────────
        ("POST", "upstreams") => {
            #[derive(serde::Deserialize)]
            struct RelayUpstream {
                addr: String,
                port: u16,
                protocol: String,
                name: Option<String>,
                tls_hostname: Option<String>,
            }
            let u: RelayUpstream = match serde_json::from_slice(&body_bytes) {
                Ok(u) => u,
                Err(e) => {
                    return Ok(json_resp(
                        400,
                        serde_json::json!({ "error": format!("parse: {e}") }),
                    ))
                }
            };
            let entry = add_upstream(
                &relay.upstreams,
                u.addr,
                u.port,
                u.protocol,
                u.name,
                u.tls_hostname,
            );
            Ok(json_ok(serde_json::json!({ "ok": true, "id": entry.id })))
        }
        ("DELETE", op) if op.starts_with("upstreams/") => {
            let id = op.trim_start_matches("upstreams/");
            remove_upstream(&relay.upstreams, id);
            Ok(json_ok(serde_json::json!({ "ok": true })))
        }
        // ── Snapshot (#87) ───────────────────────────────────────────────────
        ("GET", "snapshot") => {
            let dns = load().unwrap_or_default().entries;
            let blacklist = load_blacklist().unwrap_or_default().entries;
            let feeds = load_feeds().unwrap_or_default().feeds;
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
            let statuses = relay
                .upstreams
                .read()
                .map(|g| g.clone())
                .unwrap_or_default();
            let total = statuses.len();
            let healthy = statuses.iter().filter(|u| u.healthy).count();
            Ok(json_ok(serde_json::json!({
                "upstreams": statuses,
                "total":     total,
                "healthy":   healthy,
            })))
        }
        ("GET", op) if op.starts_with("stats/top-domains") => {
            let limit: usize = op.split('=').last()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10)
                .min(100);
            let top = relay.domain_stats.top(limit);
            let tracked = relay.domain_stats.len();
            let entries: Vec<_> = top.into_iter()
                .map(|(d, c)| serde_json::json!({"domain": d, "count": c}))
                .collect();
            Ok(json_ok(serde_json::json!({ "top_queried": entries, "tracked_domains": tracked })))
        }
        // ── System info (for WebUI node overview) ───────────────────────────
        ("GET", "system") => {
            let snap = relay.stats_cache.load();
            let cpu_cores = crate::cpu::physical_cores().len().max(1);

            // Memory: cgroup v2 if available, else /proc/meminfo
            let (mem_avail_mb, mem_total_mb): (u64, u64) = {
                let cg_max = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()
                    .and_then(|s| if s.trim() == "max" { None } else { s.trim().parse::<u64>().ok() });
                if let Some(max_b) = cg_max {
                    let cur = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
                        .ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
                    (max_b.saturating_sub(cur) / (1024 * 1024), max_b / (1024 * 1024))
                } else if let Ok(txt) = std::fs::read_to_string("/proc/meminfo") {
                    let (mut tot, mut avail) = (0u64, 0u64);
                    for l in txt.lines() {
                        if l.starts_with("MemTotal:")     { tot   = l.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0); }
                        if l.starts_with("MemAvailable:") { avail = l.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0); }
                    }
                    (avail / 1024, tot / 1024)
                } else { (0, 0) }
            };

            // CPU%: (utime + stime) / proc_uptime since process start
            let cpu_percent: f64 = (|| -> Option<f64> {
                let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
                let ac = stat.find(')')? + 2;
                let f: Vec<&str> = stat[ac..].split_whitespace().collect();
                let ut: u64 = f.get(11).and_then(|v| v.parse().ok())?;
                let st: u64 = f.get(12).and_then(|v| v.parse().ok())?;
                let ss: u64 = f.get(19).and_then(|v| v.parse().ok())?;
                let up: f64 = std::fs::read_to_string("/proc/uptime").ok()
                    .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))?;
                let pu = up - (ss as f64 / 100.0);
                if pu <= 0.0 { return Some(0.0); }
                Some(((ut + st) as f64 / 100.0 / pu * 1000.0).round() / 10.0)
            })().unwrap_or(0.0);

            Ok(json_ok(serde_json::json!({
                "version":           env!("CARGO_PKG_VERSION"),
                "uptime_secs":       snap.uptime_secs,
                "xdp_active":        false,
                "xdp_mode":          "disabled",
                "cpu_cores":         cpu_cores,
                "cpu_percent":       cpu_percent,
                "mem_total_mb":      mem_total_mb,
                "mem_avail_mb":      mem_avail_mb,
                "workers":           cpu_cores,
                "prefetch_enabled":  relay.cfg.prefetch,
                "dnssec_validation": relay.dnssec_enabled.load(std::sync::atomic::Ordering::Relaxed),
                "anycast":           match crate::anycast::state() {
                    Some(st) => serde_json::json!({
                        "configured": st.configured,
                        "address":    st.address,
                        "peer":       st.peer,
                        "local_as":   st.local_as,
                        "announced":  st.announced.load(std::sync::atomic::Ordering::Relaxed),
                    }),
                    None => serde_json::json!({ "configured": false }),
                },
            })))
        }
        ("GET", op) if op.starts_with("cache") => {
            Ok(json_ok(serde_json::json!({ "entries": 0, "hit_rate": 0.0 })))
        }
        // ── DNSSEC toggle propagation ────────────────────────────────────────
        ("GET", "icmp/stats") => {
            use std::sync::atomic::Ordering::Relaxed;
            Ok(json_ok(serde_json::json!({
                "handled":      relay.icmp_stats.handled.load(Relaxed),
                "replied":      relay.icmp_stats.replied.load(Relaxed),
                "dropped":      relay.icmp_stats.dropped.load(Relaxed),
                "rate_limited": relay.icmp_stats.rate_limited.load(Relaxed),
            })))
        }
        ("GET", "icmp/config") => {
            let cfg = relay.icmp_cfg.lock().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(json_ok(serde_json::json!({
                "enable":     cfg.enabled,
                "rate_limit": cfg.rate_pps,
                "burst":      cfg.burst,
            })))
        }
        ("PUT", "icmp/config") => {
            #[derive(serde::Deserialize)]
            struct IcmpPut { enable: Option<bool>, rate_limit: Option<u32>, burst: Option<u32>, ban_threshold: Option<u32> }
            let p: IcmpPut = match serde_json::from_slice(&body_bytes) {
                Ok(v) => v,
                Err(e) => return Ok(json_resp(400, serde_json::json!({ "error": format!("parse: {e}") }))),
            };
            let (enabled, rate_pps, burst_v, ban_thr) = {
                let mut cfg = relay.icmp_cfg.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(v) = p.enable         { cfg.enabled = v; }
                if let Some(v) = p.rate_limit     { cfg.rate_pps = v; }
                if let Some(v) = p.burst          { cfg.burst = v; }
                if let Some(v) = p.ban_threshold  { cfg.ban_threshold = v; }
                (cfg.enabled, cfg.rate_pps, cfg.burst, cfg.ban_threshold)
            };
            let _ = std::fs::write(
                relay.base_dir.join("icmp.json"),
                serde_json::json!({"enable":enabled,"rate_limit":rate_pps,"burst":burst_v,"ban_threshold":ban_thr}).to_string(),
            );
            Ok(json_ok(serde_json::json!({ "enable": enabled, "rate_limit": rate_pps, "burst": burst_v, "ban_threshold": ban_thr })))
        }
        // Ban propagation from master flood detector
        ("PUT", op) if op.starts_with("alerts/blocked/") => {
            let ip_str = op.trim_start_matches("alerts/blocked/");
            match ip_str.parse::<std::net::IpAddr>() {
                Err(_) => Ok(json_resp(400, serde_json::json!({ "error": "invalid IP" }))),
                Ok(ip) => {
                    relay.alert_tracker.block_manual(ip, "icmp-flood-relay".to_string());
                    relay.icmp_stats.ban(ip, crate::icmp::BanSource::Relay);
                    if let std::net::IpAddr::V4(ipv4) = ip {
                        let _ = relay.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::Ban(ipv4));
                    }
                    Ok(json_ok(serde_json::json!({ "ok": true, "ip": ip_str })))
                }
            }
        }
        ("DELETE", op) if op.starts_with("alerts/blocked/") => {
            let ip_str = op.trim_start_matches("alerts/blocked/");
            match ip_str.parse::<std::net::IpAddr>() {
                Err(_) => Ok(json_resp(400, serde_json::json!({ "error": "invalid IP" }))),
                Ok(ip) => {
                    relay.alert_tracker.unblock(ip);
                    relay.icmp_stats.unban(ip);
                    if let std::net::IpAddr::V4(ipv4) = ip {
                        let _ = relay.icmp_stats.ban_cmd_tx.send(crate::icmp::IcmpBanCmd::Unban(ipv4));
                    }
                    Ok(json_ok(serde_json::json!({ "ok": true, "ip": ip_str })))
                }
            }
        }
                ("PATCH", "config") => {
            #[derive(serde::Deserialize)]
            struct ConfigPatch { dnssec_validation: Option<bool> }
            let p: ConfigPatch = match serde_json::from_slice(&body_bytes) {
                Ok(v) => v,
                Err(e) => return Ok(json_resp(400, serde_json::json!({ "error": format!("parse: {e}") }))),
            };
            if let Some(v) = p.dnssec_validation {
                relay.dnssec_enabled.store(v, std::sync::atomic::Ordering::Relaxed);
                let addrs = crate::upstreams::upstream_addrs(&relay.upstreams);
                if let Err(e) = crate::dns::server::rebuild_and_swap(&relay.resolver, &addrs, v).await {
                    tracing::warn!(%e, "relay: resolver rebuild after DNSSEC toggle");
                }
                tracing::info!(dnssec = v, "DNSSEC toggle applied on slave via relay");
            }
            Ok(json_ok(serde_json::json!({ "ok": true })))
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
            SyncError::Request(s) => write!(f, "request error: {s}"),
        }
    }
}

// ── #86: slave-status watcher ──────────────────────────────────────────────
//
// Polls all_slaves_snapshot() every 5 s and emits a NodeStatusEvent on the
// broadcast channel whenever a node's health category changes.
//
// Status thresholds (last_seen_secs):
//   ok    < 15 s  — node is actively syncing
//   warn  < 60 s  — missed one sync cycle, may be transient
//   error ≥ 60 s  — node appears unreachable
async fn slave_status_watcher(
    journal: std::sync::Weak<SyncJournal>,
    tx: tokio::sync::broadcast::Sender<NodeStatusEvent>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prev: HashMap<String, String> = HashMap::new();

    loop {
        interval.tick().await;
        let Some(journal) = journal.upgrade() else {
            break;
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let slaves = journal.all_slaves_snapshot();
        let mut current_keys: Vec<String> = Vec::with_capacity(slaves.len());

        for slave in &slaves {
            let secs = slave.last_seen_secs;
            let new_status = if secs < 15 {
                "ok"
            } else if secs < 60 {
                "warn"
            } else {
                "error"
            };
            let key = slave.node_id.as_deref().unwrap_or(&slave.addr).to_string();
            current_keys.push(key.clone());

            let changed = prev.get(&key).map_or(true, |s| s != new_status);
            if changed {
                let reason = if secs < 15 {
                    "connected".to_string()
                } else {
                    format!("last seen {}s ago", secs)
                };
                let event = NodeStatusEvent {
                    node_id: slave.node_id.clone().unwrap_or_else(|| slave.addr.clone()),
                    addr: slave.addr.clone(),
                    status: new_status.to_string(),
                    reason,
                    ts: now,
                };
                let _ = tx.send(event);
                prev.insert(key, new_status.to_string());
            }
        }

        // Remove stale keys (nodes that left the snapshot).
        prev.retain(|k, _| current_keys.contains(k));
    }
}


#[cfg(test)]
mod sec_i14_hmac_body {
    use super::{hmac_sign, hmac_unix_now, hmac_verify_with_ts};

    #[test]
    fn body_is_covered_legacy_rejected() {
        let key = "k";
        let body = br#"{"node_id":"x"}"#;
        let ts = hmac_unix_now();
        let sig = hmac_sign(key, "POST", "/relay/dns", ts, body);
        // valid body-covering signature verifies
        assert!(hmac_verify_with_ts(key, "POST", "/relay/dns", ts, body, &sig));
        // a tampered body is rejected
        assert!(!hmac_verify_with_ts(key, "POST", "/relay/dns", ts, b"tampered", &sig));
        // SEC-J5: a signature that does not cover this body (e.g. computed over an empty
        // body, as the removed legacy header-only path did) no longer verifies
        let header_only = hmac_sign(key, "POST", "/relay/dns", ts, b"");
        assert!(!hmac_verify_with_ts(key, "POST", "/relay/dns", ts, body, &header_only));
        // wrong key is rejected
        assert!(!hmac_verify_with_ts("other", "POST", "/relay/dns", ts, body, &sig));
    }
}
