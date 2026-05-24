// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// HSM (Hardware Security Module) key loading via PKCS#11.
//
// Keys are loaded once at startup, stored in process memory with Zeroizing
// wrappers (zeroed on drop), and accessed through module-level OnceLock cells.
//
// Priority chain for each key:
//   HSM (this module) > RUNBOUND_API_KEY / RUNBOUND_STORE_KEY env vars > config file
//
// When hsm-pkcs11-lib is configured and key loading fails, the process exits
// immediately — there is no silent fallback to avoid running without HSM protection
// after the operator explicitly opted in.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tracing::info;
use zeroize::Zeroizing;

use crate::config::parser::UnboundConfig;

// ── Process-global key storage ────────────────────────────────────────────────
// Populated once at startup by load_and_store(). Never updated after that.

static HSM_API_KEY: OnceLock<Zeroizing<String>> = OnceLock::new();
static HSM_STORE_KEY: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();
static HSM_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Returns true if keys were successfully loaded from an HSM at startup.
pub fn is_active() -> bool {
    HSM_ACTIVE.load(Ordering::Relaxed)
}

/// Returns the HSM-loaded API key, if any.
/// Checked by `init_api_key()` before env vars and config file.
pub fn api_key() -> Option<&'static str> {
    HSM_API_KEY.get().map(|k| k.as_str())
}

/// Returns the HSM-loaded store HMAC key bytes, if any.
/// Checked by `integrity::store_key()` before `RUNBOUND_STORE_KEY`.
pub fn store_key() -> Option<&'static [u8]> {
    HSM_STORE_KEY.get().map(|k| k.as_slice())
}

// ── Configuration ─────────────────────────────────────────────────────────────

pub struct HsmConfig {
    pub pkcs11_lib: String,
    pub slot: u64,
    pub pin: Zeroizing<String>,
    pub api_key_label: Option<String>,
    pub store_key_label: Option<String>,
}

impl HsmConfig {
    /// Build from `UnboundConfig`.
    /// PIN priority: `HSM_PIN` env var → `hsm-pin` config directive.
    /// Returns `None` when `hsm-pkcs11-lib` is not set (HSM disabled).
    pub fn from_config(cfg: &UnboundConfig) -> Option<Self> {
        let lib = cfg.hsm_pkcs11_lib.as_ref()?.clone();
        let pin = std::env::var("HSM_PIN")
            .ok()
            .or_else(|| cfg.hsm_pin.clone())
            .unwrap_or_default();
        Some(Self {
            pkcs11_lib: lib,
            slot: cfg.hsm_slot,
            pin: Zeroizing::new(pin),
            api_key_label: cfg.hsm_api_key_label.clone(),
            store_key_label: cfg.hsm_store_key_label.clone(),
        })
    }
}

// ── Key loading ───────────────────────────────────────────────────────────────

/// Open a PKCS#11 session, extract the configured key objects, store them in
/// the process-global OnceLocks, and close the session.
///
/// On any failure this returns `Err`. The caller (`main.rs`) must treat this
/// as fatal and exit — no silent fallback when HSM is explicitly configured.
pub fn load_and_store(config: &HsmConfig) -> Result<()> {
    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;

    info!(lib = %config.pkcs11_lib, slot = config.slot, "Opening PKCS#11 HSM session");

    let pkcs11 = Pkcs11::new(&config.pkcs11_lib)
        .with_context(|| format!("Cannot load PKCS#11 library '{}'", config.pkcs11_lib))?;
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .context("PKCS#11 C_Initialize failed")?;

    let slots = pkcs11
        .get_slots_with_initialized_token()
        .context("PKCS#11 C_GetSlotList failed")?;
    let &slot = slots.get(config.slot as usize).ok_or_else(|| {
        anyhow::anyhow!(
            "HSM slot {} not found ({} slots with initialised tokens visible)",
            config.slot,
            slots.len()
        )
    })?;

    let session = pkcs11
        .open_rw_session(slot)
        .context("PKCS#11 C_OpenSession failed")?;

    let pin = AuthPin::new(config.pin.as_str().to_string());
    session
        .login(UserType::User, Some(&pin))
        .context("PKCS#11 C_Login failed — check HSM_PIN / hsm-pin and slot number")?;

    if let Some(ref label) = config.api_key_label {
        let bytes = extract_key(&session, label)
            .with_context(|| format!("API key extraction failed (label '{label}')"))?;
        let s = String::from_utf8(bytes)
            .with_context(|| format!("API key for label '{label}' is not valid UTF-8"))?;
        let _ = HSM_API_KEY.set(Zeroizing::new(s));
        info!(label, "HSM: API key loaded");
    }

    if let Some(ref label) = config.store_key_label {
        let bytes = extract_key(&session, label)
            .with_context(|| format!("Store key extraction failed (label '{label}')"))?;
        let _ = HSM_STORE_KEY.set(Zeroizing::new(bytes));
        info!(label, "HSM: store HMAC key loaded");
    }

    session.logout().ok();
    drop(session);
    // pkcs11 drops here → C_Finalize. Safe: all key bytes are now in the OnceLocks.

    HSM_ACTIVE.store(true, Ordering::Relaxed);
    info!(
        slot = config.slot,
        "HSM session closed — keys held in process memory"
    );
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn extract_key(session: &cryptoki::session::Session, label: &str) -> Result<Vec<u8>> {
    use cryptoki::object::{Attribute, AttributeType, ObjectClass};
    let template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let handles = session
        .find_objects(&template)
        .with_context(|| format!("C_FindObjects failed (label '{label}')"))?;
    let handle = *handles.first().ok_or_else(|| {
        anyhow::anyhow!("Key '{label}' not found in HSM — check label and CKA_EXTRACTABLE=true")
    })?;

    let attrs = session
        .get_attributes(handle, &[AttributeType::Value])
        .with_context(|| format!("C_GetAttributeValue failed for '{label}'"))?;
    for attr in attrs {
        if let Attribute::Value(v) = attr {
            return Ok(v);
        }
    }
    anyhow::bail!(
        "CKA_VALUE attribute missing for '{label}' — set CKA_EXTRACTABLE=true on the key object"
    )
}
