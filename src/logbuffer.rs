// Query log ring buffer — fixed capacity, zero allocation after startup.
//
// LogEntry is a fixed-size struct (no heap pointers). The ring buffer
// pre-allocates exactly LOG_CAP slots at startup; every push() overwrites
// the oldest slot in O(1) under a short Mutex critical section.
//
// query() produces LogEntryView values (serde::Serialize) on the read path
// only — allocations there are fine (REST API, not DNS hot path).

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

// ── Capacity ───────────────────────────────────────────────────────────────
pub const LOG_CAP: usize = 10_000;

// DNS name max length per RFC 1035 is 253 characters.
// Store it as a fixed-size byte array + length to avoid heap allocation.
const NAME_CAP: usize = 253;

// IPv6 text representation fits in 39 bytes; we store 45 to be safe.
const CLIENT_CAP: usize = 45;

// ── Action enum ───────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LogAction {
    Forwarded = 0,
    Cached    = 1,
    Local     = 2,
    Blocked   = 3,
    Nxdomain  = 4,
    Refused   = 5,
    Servfail  = 6,
}

impl LogAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Cached    => "cached",
            Self::Local     => "local",
            Self::Blocked   => "blocked",
            Self::Nxdomain  => "nxdomain",
            Self::Refused   => "refused",
            Self::Servfail  => "servfail",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "forwarded" => Some(Self::Forwarded),
            "cached"    => Some(Self::Cached),
            "local"     => Some(Self::Local),
            "blocked"   => Some(Self::Blocked),
            "nxdomain"  => Some(Self::Nxdomain),
            "refused"   => Some(Self::Refused),
            "servfail"  => Some(Self::Servfail),
            _           => None,
        }
    }
}

// ── Fixed-size log entry — zero heap allocation ────────────────────────────
pub struct LogEntry {
    // Unix timestamp in seconds (enough precision for log browsing)
    pub ts_secs:    u64,
    // DNS name, UTF-8 bytes, length in name_len, zero-padded
    pub name_buf:   [u8; NAME_CAP],
    pub name_len:   u8,  // 253 fits in u8
    // Client IP as text (no port), length in client_len
    pub client_buf: [u8; CLIENT_CAP],
    pub client_len: u8,
    // DNS record type (qtype), e.g. 1=A, 28=AAAA, 15=MX
    pub qtype:      u16,
    // Resolution action
    pub action:     LogAction,
    // Round-trip in milliseconds (capped at u32::MAX ≈ 49 days)
    pub elapsed_ms: u32,
}

impl LogEntry {
    pub fn new(
        name:       &str,
        client:     &IpAddr,
        qtype:      u16,
        action:     LogAction,
        elapsed_ms: u32,
    ) -> Self {
        let ts_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut name_buf = [0u8; NAME_CAP];
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(NAME_CAP) as u8;
        name_buf[..name_len as usize].copy_from_slice(&name_bytes[..name_len as usize]);

        let client_str = client.to_string();
        let mut client_buf = [0u8; CLIENT_CAP];
        let client_bytes = client_str.as_bytes();
        let client_len = client_bytes.len().min(CLIENT_CAP) as u8;
        client_buf[..client_len as usize].copy_from_slice(&client_bytes[..client_len as usize]);

        Self { ts_secs, name_buf, name_len, client_buf, client_len, qtype, action, elapsed_ms }
    }

    pub fn name(&self) -> &str {
        std::str::from_utf8(&self.name_buf[..self.name_len as usize]).unwrap_or("")
    }

    pub fn client(&self) -> &str {
        std::str::from_utf8(&self.client_buf[..self.client_len as usize]).unwrap_or("")
    }
}

// ── Serializable view — produced only on read path ─────────────────────────
#[derive(Serialize)]
pub struct LogEntryView {
    pub ts:         String,
    pub name:       String,
    pub client:     String,
    pub qtype:      u16,
    pub action:     &'static str,
    pub elapsed_ms: u32,
}

// ── Query filters ─────────────────────────────────────────────────────────
pub struct LogQuery {
    pub limit:      usize,      // max entries to return (default 100, max 1000)
    pub page:       usize,      // 0-based page number
    pub action:     Option<LogAction>,
    pub client:     Option<IpAddr>,
    pub since_secs: Option<u64>,
}

// ── Ring buffer ───────────────────────────────────────────────────────────
pub struct LogBuffer {
    slots: Vec<Option<LogEntry>>,
    head:  usize,   // next write position
    count: usize,   // total entries written (saturates at LOG_CAP)
}

impl LogBuffer {
    fn new() -> Self {
        let mut slots = Vec::with_capacity(LOG_CAP);
        for _ in 0..LOG_CAP { slots.push(None); }
        Self { slots, head: 0, count: 0 }
    }

    /// Push a log entry — O(1), overwrites oldest when full.
    pub fn push(&mut self, entry: LogEntry) {
        self.slots[self.head] = Some(entry);
        self.head = (self.head + 1) % LOG_CAP;
        if self.count < LOG_CAP { self.count += 1; }
    }

    /// Query entries — newest first, with optional filters and pagination.
    /// Allocates only on the read path.
    pub fn query(&self, q: &LogQuery) -> (Vec<LogEntryView>, usize) {
        let filled = self.count.min(LOG_CAP);
        if filled == 0 { return (vec![], 0); }

        // Collect matching entries newest-first
        let mut matched: Vec<LogEntryView> = Vec::new();
        for i in 0..filled {
            let idx = (self.head + LOG_CAP - 1 - i) % LOG_CAP;
            let entry = match &self.slots[idx] {
                Some(e) => e,
                None    => continue,
            };

            if let Some(a) = q.action {
                if entry.action != a { continue; }
            }
            if let Some(ref c) = q.client {
                if entry.client() != c.to_string() { continue; }
            }
            if let Some(since) = q.since_secs {
                if entry.ts_secs < since { continue; }
            }

            matched.push(LogEntryView {
                ts:         format_ts(entry.ts_secs),
                name:       entry.name().to_owned(),
                client:     entry.client().to_owned(),
                qtype:      entry.qtype,
                action:     entry.action.as_str(),
                elapsed_ms: entry.elapsed_ms,
            });
        }

        let total = matched.len();
        let start = (q.page * q.limit).min(total);
        let end   = (start + q.limit).min(total);
        (matched.drain(start..end).collect(), total)
    }
}

// ── Shared handle ─────────────────────────────────────────────────────────
pub type SharedLogBuffer = Arc<Mutex<LogBuffer>>;

pub fn new_shared() -> SharedLogBuffer {
    Arc::new(Mutex::new(LogBuffer::new()))
}

// ── Timestamp formatter ────────────────────────────────────────────────────
// Formats Unix seconds as RFC 3339 / ISO 8601 UTC without external crates.
pub fn format_ts(secs: u64) -> String {
    // Days since Unix epoch → Gregorian date via Rata Die algorithm.
    let s     = secs % 86400;
    let days  = secs / 86400;
    let hh    = s / 3600;
    let mm    = (s % 3600) / 60;
    let ss    = s % 60;

    // Civil date from epoch days (algorithm from Howard Hinnant)
    let z     = days as i64 + 719468;
    let era   = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe   = z - era * 146097;
    let yoe   = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y     = yoe + era * 400;
    let doy   = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp    = (5 * doy + 2) / 153;
    let d     = doy - (153 * mp + 2) / 5 + 1;
    let m     = if mp < 10 { mp + 3 } else { mp - 9 };
    let y     = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}
