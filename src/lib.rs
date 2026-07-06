// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// Library entry point — only compiled when the "fuzz" feature is active.
// The normal runbound binary uses main.rs exclusively; this lib.rs exists
// solely to expose internal parsing functions for cargo-fuzz targets.
//
// NOTE: Modules that reference crate-root functions defined in main.rs
// (build_zone_set, etc.) are intentionally NOT included here; only the
// modules needed by the four fuzz targets are exposed.

// ── Modules exposed for fuzzing ───────────────────────────────────────────────

#[cfg(feature = "fuzz")]
pub mod config {
    pub mod parser;
    // parser calls writer::is_managed_directive during parsing.
    pub mod writer;
}

// hsm is required by api — re-exported to allow api to compile via lib.
// src/hsm.rs is NOT modified (absolute constraint respected).
#[cfg(feature = "fuzz")]
pub mod hsm;

// config::parser (and config::writer) reference these crate-root modules via
// the Config struct fields and directive handling. They form a self-contained
// closure that does not touch main.rs-only items, so re-exposing them here lets
// the parser compile in the library crate without dragging in the binary.
#[cfg(feature = "fuzz")]
pub mod webhooks;
// webhooks delegates its SSRF filter to the standalone `ssrf` module (std/tokio/
// reqwest only), so it must be exposed alongside webhooks in the fuzz lib.
#[cfg(feature = "fuzz")]
pub mod ssrf;
#[cfg(feature = "fuzz")]
pub mod multiuser;
#[cfg(feature = "fuzz")]
pub mod upstreams;
#[cfg(feature = "fuzz")]
pub mod integrity;
#[cfg(feature = "fuzz")]
pub mod logbuffer;

// Runbound's own zero-copy wire parser — the only inbound parse path
// (hickory is a [dev-dependencies]-only oracle for differential tests, never a
// runtime dependency). It is self-contained: its only cross-module references
// live in the `oracle` submodule, which is #[cfg(test)] and therefore excluded
// from the fuzz build.
#[cfg(feature = "fuzz")]
pub mod dns {
    pub mod wire;
}

// ── Fuzz helpers ─────────────────────────────────────────────────────────────

/// Parse raw DNS wire bytes through Runbound's own zero-copy wire parser
/// (`dns::wire::Message::parse`) — the default inbound parse path, so this fuzzes
/// the code Runbound owns rather than a third-party dependency.
/// Returns Some(()) on success, None on parse failure.
/// Used by the fuzz_dns_query target.
#[cfg(feature = "fuzz")]
pub fn parse_dns_bytes(data: &[u8]) -> Option<()> {
    crate::dns::wire::Message::parse(data).ok().map(|_| ())
}

/// Parse a string as an Unbound-format config.
/// Returns Some(()) on success, None on parse failure.
/// Used by the fuzz_config target.
#[cfg(feature = "fuzz")]
pub fn parse_config_str(s: &str) -> Option<()> {
    crate::config::parser::parse_str(s).ok().map(|_| ())
}

/// Validate a DNS name string using the same logic as the REST API.
/// Returns true if valid, false otherwise.
/// Used by the fuzz_dns_name target.
#[cfg(any(test, feature = "fuzz"))]
pub fn fuzz_validate_dns_name(name: &str) -> bool {
    let n = name.trim_end_matches('.');
    if n.is_empty() || n.len() > 253 {
        return false;
    }
    for label in n.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
    }
    true
}

// ── Minimal API request structs for fuzz_api_json ────────────────────────────
// These are standalone re-implementations of the serde shapes used by the REST
// API, so the fuzz target can deserialise inputs without pulling in the full
// axum/tokio stack.

#[cfg(feature = "fuzz")]
pub mod api_fuzz {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct AddDnsRequest {
        pub name: String,
        #[serde(rename = "type")]
        pub entry_type: Option<String>,
        #[serde(default = "default_ttl")]
        pub ttl: i64,
        pub value: Option<String>,
        pub priority: Option<u16>,
        pub weight: Option<u16>,
        pub port: Option<u16>,
        pub flags: Option<u8>,
        pub tag: Option<String>,
        pub order: Option<u16>,
        pub preference_naptr: Option<u16>,
        pub flags_naptr: Option<String>,
        pub services: Option<String>,
        pub regexp: Option<String>,
        pub replacement: Option<String>,
        pub algorithm: Option<u8>,
        pub fp_type: Option<u8>,
        pub fingerprint: Option<String>,
        pub cert_usage: Option<u8>,
        pub selector: Option<u8>,
        pub matching_type: Option<u8>,
        pub cert_data: Option<String>,
        pub description: Option<String>,
    }

    fn default_ttl() -> i64 {
        3600
    }

    #[derive(Debug, Deserialize)]
    pub struct AddFeedRequest {
        pub name: String,
        pub url: String,
        pub format: Option<String>,
        pub action: Option<String>,
        pub description: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct AddBlacklistRequest {
        pub domain: String,
        pub action: Option<String>,
        pub description: Option<String>,
    }
}
