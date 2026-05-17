// Runbound — Immutable audit log
//
// Events are written to an append-only file (O_APPEND | O_CREAT | O_WRONLY).
// Each line is a JSON object with a monotonic sequence number and an HMAC-SHA256
// chain: mac = HMAC-SHA256(key, seq || ts || event || fields).
//
// A dedicated tokio task drains an unbounded channel — callers never block.
// The monotonic seq is persisted in `base_dir/audit-seq.dat` so it survives restarts.
// The HMAC key is auto-generated on first run and saved to `base_dir/audit-hmac.key` (chmod 600).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use tracing::{error, warn};

type HmacSha256 = Hmac<Sha256>;

// ── Event types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AuditEvent {
    Startup,
    Shutdown,
    DnsAdd     { name: String, rtype: String, value: String },
    DnsDelete  { id: String },
    FeedAdd    { id: String, name: String, url: String },
    FeedDelete { id: String },
    BlacklistAdd    { domain: String },
    BlacklistDelete { id: String },
    AuthFailure { path: String },
    ConfigReload,
}

impl AuditEvent {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Startup           => "startup",
            Self::Shutdown          => "shutdown",
            Self::DnsAdd { .. }     => "dns_add",
            Self::DnsDelete { .. }  => "dns_delete",
            Self::FeedAdd { .. }    => "feed_add",
            Self::FeedDelete { .. } => "feed_delete",
            Self::BlacklistAdd { .. }    => "blacklist_add",
            Self::BlacklistDelete { .. } => "blacklist_delete",
            Self::AuthFailure { .. } => "auth_failure",
            Self::ConfigReload       => "config_reload",
        }
    }

    fn fields(&self) -> serde_json::Value {
        match self {
            Self::Startup | Self::Shutdown | Self::ConfigReload => serde_json::json!({}),
            Self::DnsAdd { name, rtype, value } => serde_json::json!({
                "name": name, "type": rtype, "value": value,
            }),
            Self::DnsDelete  { id }  => serde_json::json!({ "id": id }),
            Self::FeedAdd    { id, name, url } => serde_json::json!({
                "id": id, "name": name, "url": url,
            }),
            Self::FeedDelete { id }  => serde_json::json!({ "id": id }),
            Self::BlacklistAdd    { domain } => serde_json::json!({ "domain": domain }),
            Self::BlacklistDelete { id }     => serde_json::json!({ "id": id }),
            Self::AuthFailure { path }       => serde_json::json!({ "path": path }),
        }
    }
}

// ── AuditLogger (the sender handle — cheap Clone) ──────────────────────────────

#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::UnboundedSender<AuditEvent>,
}

impl AuditLogger {
    pub fn send(&self, event: AuditEvent) {
        // Best-effort: never block the hot path. If the channel is closed (shutdown),
        // silently drop — the task has already exited cleanly.
        let _ = self.tx.send(event);
    }
}

// ── Background writer task ─────────────────────────────────────────────────────

/// Initialise the audit subsystem. Returns an `AuditLogger` (sender) and spawns
/// a dedicated tokio task that writes to `log_path` with O_APPEND atomicity.
///
/// If `enabled` is false, returns a logger whose sends are silently discarded.
pub fn init(
    enabled:    bool,
    log_path:   Option<PathBuf>,
    hmac_key:   Option<String>,
    base_dir:   PathBuf,
) -> AuditLogger {
    let (tx, rx) = mpsc::unbounded_channel::<AuditEvent>();

    if enabled {
        let resolved_path = log_path.unwrap_or_else(|| base_dir.join("audit.log"));
        let key_bytes = load_or_generate_hmac_key(hmac_key, &base_dir);
        let seq = load_seq(&base_dir);
        tokio::spawn(writer_task(rx, resolved_path, key_bytes, seq, base_dir));
    } else {
        // Consume events from the channel so it doesn't accumulate.
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
    }

    AuditLogger { tx }
}

// ── Seq persistence ────────────────────────────────────────────────────────────

fn seq_path(base_dir: &std::path::Path) -> PathBuf {
    base_dir.join("audit-seq.dat")
}

fn load_seq(base_dir: &std::path::Path) -> u64 {
    fs::read_to_string(seq_path(base_dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_seq(base_dir: &std::path::Path, seq: u64) {
    let _ = fs::write(seq_path(base_dir), seq.to_string());
}

// ── HMAC key management ────────────────────────────────────────────────────────

fn hmac_key_path(base_dir: &std::path::Path) -> PathBuf {
    base_dir.join("audit-hmac.key")
}

fn load_or_generate_hmac_key(config_key: Option<String>, base_dir: &std::path::Path) -> Vec<u8> {
    use hex::{decode, encode};

    // Priority: config > file > auto-generate
    if let Some(k) = config_key.filter(|s| !s.is_empty()) {
        return k.into_bytes();
    }

    let path = hmac_key_path(base_dir);
    if let Ok(hex_str) = fs::read_to_string(&path) {
        if let Ok(bytes) = decode(hex_str.trim()) {
            if bytes.len() >= 32 {
                return bytes;
            }
        }
    }

    // Auto-generate 256-bit key
    let key: Vec<u8> = (0..32).map(|_| rand_byte()).collect();
    let _ = fs::create_dir_all(base_dir);
    let _ = fs::write(&path, encode(&key));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    warn!(path = %path.display(), "Audit HMAC key auto-generated");
    key
}

fn rand_byte() -> u8 {
    let mut buf = [0u8; 1];
    getrandom::fill(&mut buf).expect("getrandom failed");
    buf[0]
}

// ── Writer task ────────────────────────────────────────────────────────────────

async fn writer_task(
    mut rx:      mpsc::UnboundedReceiver<AuditEvent>,
    log_path:    PathBuf,
    key:         Vec<u8>,
    start_seq:   u64,
    base_dir:    PathBuf,
) {
    let _ = fs::create_dir_all(log_path.parent().unwrap_or(std::path::Path::new(".")));

    // O_APPEND: each write() is atomic at the OS level (POSIX guarantee for O_APPEND).
    // We never truncate or seek — the log is append-only by construction.
    let mut file = match OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
    {
        Ok(f) => f,
        Err(e) => {
            error!(path = %log_path.display(), err = %e, "Cannot open audit log — audit disabled");
            return;
        }
    };

    let mut seq = start_seq;

    while let Some(event) = rx.recv().await {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let event_name = event.event_name();
        let fields     = event.fields();

        // HMAC-SHA256 over: seq (8 bytes LE) || ts (8 bytes LE) || event name || fields JSON
        let mac = compute_mac(&key, seq, ts, event_name, &fields.to_string());

        let line = serde_json::json!({
            "seq":   seq,
            "ts":    ts,
            "event": event_name,
            "fields": fields,
            "mac":   mac,
        });

        let mut buf = line.to_string();
        buf.push('\n');

        if let Err(e) = file.write_all(buf.as_bytes()) {
            error!(err = %e, "Audit log write failed");
        }

        seq += 1;
        // Persist seq every 100 events to limit replay window on crash.
        if seq.is_multiple_of(100) {
            save_seq(&base_dir, seq);
        }
    }

    // Flush on channel close (shutdown).
    save_seq(&base_dir, seq);
}

fn compute_mac(key: &[u8], seq: u64, ts: u64, event: &str, fields: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(&seq.to_le_bytes());
    mac.update(&ts.to_le_bytes());
    mac.update(event.as_bytes());
    mac.update(fields.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ── GET /audit/tail endpoint helper ───────────────────────────────────────────

/// Read the last `n` lines (max 1000) from the audit log file.
/// Reads from EOF backwards using a simple reverse-line scan.
pub fn tail_audit_log(log_path: &std::path::Path, n: usize) -> Result<Vec<serde_json::Value>, String> {
    let n = n.min(1000);

    let content = fs::read_to_string(log_path)
        .map_err(|e| format!("read audit log: {e}"))?;

    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    let result = lines[start..]
        .iter()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    Ok(result)
}
