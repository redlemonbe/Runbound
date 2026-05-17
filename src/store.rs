// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Persistent DNS entry store.
// Survives restarts — JSON file under base_dir (derived from config path at startup).
// The in-memory LocalZoneSet is always the source of truth for queries;
// this file is loaded at boot and written on every mutation.

use std::fs;
use std::io::Write;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::integrity::{store_key, verify_mac, write_mac};

fn store_path() -> std::path::PathBuf { crate::runtime::base_dir().join("dns_entries.json") }
fn blacklist_path() -> std::path::PathBuf { crate::runtime::base_dir().join("blacklist.json") }

// ── Record types supported by the API ──────────────────────────────────────

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsType {
    A, AAAA, CNAME, TXT,
    MX, SRV, CAA, PTR,
    NAPTR, SSHFP, TLSA, NS,
}

impl std::fmt::Display for DnsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEntry {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: DnsType,
    pub ttl: u32,
    // ── Simple types (A, AAAA, CNAME, TXT, PTR, NS) ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    // ── MX ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    // ── SRV ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    // ── CAA ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,  // "issue", "issuewild", "iodef"
    // ── NAPTR ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preference_naptr: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags_naptr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regexp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    // ── SSHFP ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<u8>,    // 1=RSA 2=DSA 3=ECDSA 4=Ed25519
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp_type: Option<u8>,      // 1=SHA-1 2=SHA-256
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,  // hex
    // ── TLSA ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_usage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matching_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_data: Option<String>,  // hex
    // ── Metadata ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl DnsEntry {
    pub fn new_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// Convert to unbound-style local-data RR string for LocalZoneSet.
    pub fn to_rr_string(&self) -> Option<String> {
        let name = &self.name;
        let ttl  = self.ttl;
        match self.entry_type {
            DnsType::A     => Some(format!("{name} {ttl} A {}", self.value.as_deref()?)),
            DnsType::AAAA  => Some(format!("{name} {ttl} AAAA {}", self.value.as_deref()?)),
            DnsType::CNAME => Some(format!("{name} {ttl} CNAME {}", self.value.as_deref()?)),
            DnsType::TXT   => Some(format!("{name} {ttl} TXT {}", self.value.as_deref()?)),
            DnsType::PTR   => Some(format!("{name} {ttl} PTR {}", self.value.as_deref()?)),
            DnsType::NS    => Some(format!("{name} {ttl} NS {}", self.value.as_deref()?)),
            DnsType::MX    => Some(format!("{name} {ttl} MX {} {}", self.priority?, self.value.as_deref()?)),
            DnsType::SRV   => Some(format!("{name} {ttl} SRV {} {} {} {}", self.priority?, self.weight?, self.port?, self.value.as_deref()?)),
            DnsType::CAA   => Some(format!("{name} {ttl} CAA {} {} \"{}\"", self.flags.unwrap_or(0), self.tag.as_deref()?, self.value.as_deref()?)),
            DnsType::NAPTR => Some(format!("{name} {ttl} NAPTR {} {} \"{}\" \"{}\" \"{}\" {}",
                self.order?, self.preference_naptr?,
                self.flags_naptr.as_deref().unwrap_or(""),
                self.services.as_deref().unwrap_or(""),
                self.regexp.as_deref().unwrap_or(""),
                self.replacement.as_deref().unwrap_or("."))),
            DnsType::SSHFP => Some(format!("{name} {ttl} SSHFP {} {} {}", self.algorithm?, self.fp_type?, self.fingerprint.as_deref()?)),
            DnsType::TLSA  => Some(format!("{name} {ttl} TLSA {} {} {} {}", self.cert_usage?, self.selector?, self.matching_type?, self.cert_data.as_deref()?)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsStore {
    pub entries: Vec<DnsEntry>,
}

pub fn load() -> Result<DnsStore, AppError> {
    let path = store_path();
    if !path.exists() {
        return Ok(DnsStore::default());
    }
    let content = fs::read_to_string(&path)
        .map_err(|e| AppError::Internal(format!("read store: {e}")))?;
    verify_mac(&path, content.as_bytes(), store_key().as_deref())
        .map_err(AppError::Internal)?;
    serde_json::from_str(&content)
        .map_err(|e| AppError::Internal(format!("parse store: {e}")))
}

pub fn save(store: &DnsStore) -> Result<(), AppError> {
    let path = store_path();
    let dir  = path.parent().ok_or_else(|| AppError::Internal("store path has no parent".into()))?;
    fs::create_dir_all(dir)
        .map_err(|e| AppError::Internal(format!("create store dir: {e}")))?;

    let content = serde_json::to_string_pretty(store)
        .map_err(|e| AppError::Internal(format!("serialize store: {e}")))?;

    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| AppError::Internal(format!("create tmp: {e}")))?;
        f.write_all(content.as_bytes())
            .map_err(|e| AppError::Internal(format!("write tmp: {e}")))?;
        // VUL-07: fsync before rename — guarantees data survives a power cut.
        // Without this, the rename can land but the file content is still in
        // the page cache; a crash between rename and writeback yields a zero-byte file.
        f.sync_all()
            .map_err(|e| AppError::Internal(format!("fsync tmp: {e}")))?;
    }
    fs::rename(&tmp, &path)
        .map_err(|e| AppError::Internal(format!("rename store: {e}")))?;
    // VUL-06: 640 — root:root rw-r----- ; world has no access to DNS entries.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
    }
    // HIGH-06: write HMAC sidecar after atomic rename.
    write_mac(&path, content.as_bytes(), store_key().as_deref())
        .map_err(|e| AppError::Internal(format!("write store .mac: {e}")))?;
    Ok(())
}

// ── Blacklist store ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub id: String,
    pub domain: String,
    pub action: crate::dns::BlacklistAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlacklistStore {
    pub entries: Vec<BlacklistEntry>,
}

pub fn load_blacklist() -> Result<BlacklistStore, AppError> {
    let path = blacklist_path();
    if !path.exists() {
        return Ok(BlacklistStore::default());
    }
    let content = fs::read_to_string(&path)
        .map_err(|e| AppError::Internal(format!("read blacklist: {e}")))?;
    verify_mac(&path, content.as_bytes(), store_key().as_deref())
        .map_err(AppError::Internal)?;
    serde_json::from_str(&content)
        .map_err(|e| AppError::Internal(format!("parse blacklist: {e}")))
}

pub fn save_blacklist(store: &BlacklistStore) -> Result<(), AppError> {
    let path = blacklist_path();
    let dir  = path.parent().ok_or_else(|| AppError::Internal("blacklist path has no parent".into()))?;
    fs::create_dir_all(dir)
        .map_err(|e| AppError::Internal(format!("create blacklist dir: {e}")))?;

    let content = serde_json::to_string_pretty(store)
        .map_err(|e| AppError::Internal(format!("serialize blacklist: {e}")))?;

    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| AppError::Internal(format!("create blacklist tmp: {e}")))?;
        f.write_all(content.as_bytes())
            .map_err(|e| AppError::Internal(format!("write blacklist tmp: {e}")))?;
        f.sync_all()
            .map_err(|e| AppError::Internal(format!("fsync blacklist tmp: {e}")))?;
    }
    fs::rename(&tmp, &path)
        .map_err(|e| AppError::Internal(format!("rename blacklist store: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
    }
    // HIGH-06: write HMAC sidecar after atomic rename.
    write_mac(&path, content.as_bytes(), store_key().as_deref())
        .map_err(|e| AppError::Internal(format!("write blacklist .mac: {e}")))?;
    Ok(())
}
