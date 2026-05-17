// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// HIGH-06: HMAC-SHA256 integrity guard for JSON stores.
//
// When RUNBOUND_STORE_KEY is set, every JSON write gets a sidecar .mac file
// containing HMAC-SHA256(content, key) in lowercase hex.
// On load:
//   - .mac missing, key set     → WARN (backwards compat, load proceeds)
//   - .mac present, key set     → verify; mismatch → ERROR, load refused
//   - .mac present, key missing → WARN (cannot verify)
//   - .mac missing, key missing → OK   (integrity not configured)

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{error, warn};

type HmacSha256 = Hmac<Sha256>;

/// Return the HMAC key from `RUNBOUND_STORE_KEY`.
/// Accepts: 64+ lowercase hex chars (decoded to bytes), or raw UTF-8.
/// Returns `None` if the variable is unset or empty.
pub fn store_key() -> Option<Vec<u8>> {
    let raw = std::env::var("RUNBOUND_STORE_KEY").ok()?;
    let raw = raw.trim();
    if raw.is_empty() { return None; }
    if raw.len() >= 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(raw).ok()
    } else {
        Some(raw.as_bytes().to_vec())
    }
}

/// HMAC-SHA256(content, key) → lowercase hex (64 chars).
pub fn compute_mac(content: &[u8], key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(content);
    hex::encode(mac.finalize().into_bytes())
}

/// Write a .mac sidecar for `path` atomically (tmp → rename).
/// No-op when `key` is `None`.
pub fn write_mac(path: &std::path::Path, content: &[u8], key: Option<&[u8]>) -> std::io::Result<()> {
    let Some(k) = key else { return Ok(()); };
    let mac_str = compute_mac(content, k);
    let mac_path = path.with_extension("mac");
    let tmp = mac_path.with_extension("mac.tmp");
    std::fs::write(&tmp, mac_str.as_bytes())?;
    std::fs::rename(&tmp, &mac_path)
}

/// Verify `path`'s .mac sidecar against `content`.
///
/// Returns:
/// - `Ok(())` — verified, or no key configured
/// - `Err(msg)` — .mac present and HMAC mismatch (caller must refuse load)
pub fn verify_mac(path: &std::path::Path, content: &[u8], key: Option<&[u8]>) -> Result<(), String> {
    let mac_path = path.with_extension("mac");
    let mac_exists = mac_path.exists();

    match (key, mac_exists) {
        (None, false)  => Ok(()),
        (None, true)   => {
            warn!(
                path = %path.display(),
                "Store .mac file found but RUNBOUND_STORE_KEY is not set — integrity cannot be verified."
            );
            Ok(())
        }
        (Some(_), false) => {
            warn!(
                path = %path.display(),
                "RUNBOUND_STORE_KEY is set but no .mac sidecar found — \
                 file was saved without integrity protection."
            );
            Ok(())
        }
        (Some(k), true) => {
            let stored = std::fs::read_to_string(&mac_path)
                .map_err(|e| format!("read .mac for {}: {e}", path.display()))?;
            let stored = stored.trim();
            let expected = compute_mac(content, k);
            if stored.as_bytes().ct_eq(expected.as_bytes()).into() {
                Ok(())
            } else {
                error!(
                    path = %path.display(),
                    "HMAC mismatch — store file may have been tampered with. Load refused."
                );
                Err(format!("HMAC mismatch: {}", path.display()))
            }
        }
    }
}
