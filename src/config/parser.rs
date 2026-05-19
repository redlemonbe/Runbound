// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
use anyhow::{Context, Result};
use tracing::warn;

#[derive(Debug, Clone)]
pub struct LocalZone {
    pub name: String,
    pub zone_type: String, // "refuse", "always_nxdomain", "static", etc.
}

#[derive(Debug, Clone)]
pub struct LocalData {
    pub rr: String, // raw RR string, e.g. "host.local. A 192.168.1.1"
}

#[derive(Debug, Clone)]
pub struct ForwardZone {
    pub name: String,
    pub addrs: Vec<String>,
    /// Send queries over DNS-over-TLS (port 853) instead of plain UDP/TCP.
    pub tls: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    /// DNS-over-TLS port (RFC 7858) — default 853
    pub dot_port: Option<u16>,
    /// DNS-over-HTTPS port (RFC 8484) — default 443
    pub doh_port: Option<u16>,
    /// DNS-over-QUIC port (RFC 9250) — default 853 UDP
    pub doq_port: Option<u16>,
    /// Hostname sent in TLS SNI / DoH path
    pub hostname: Option<String>,
    /// Path to CA cert PEM for DoT mutual TLS client authentication (HIGH-08).
    /// When set, DoT clients must present a certificate signed by this CA.
    /// DoH and DoQ are unaffected (they authenticate via the application layer).
    pub dot_client_auth_ca: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UnboundConfig {
    pub interfaces: Vec<String>,
    pub port: u16,
    pub access_control: Vec<String>,
    pub local_zones: Vec<LocalZone>,
    pub local_data: Vec<LocalData>,
    pub forward_zones: Vec<ForwardZone>,
    pub verbosity: u8,
    pub logfile: Option<String>,
    pub pidfile: Option<String>,
    pub do_ipv4: bool,
    pub do_ipv6: bool,
    pub do_udp: bool,
    pub do_tcp: bool,
    pub tls: TlsConfig,
    /// DNS rate limit in queries/second per source IP.
    /// Overrides the compiled default (200). Set to 5000+ for shared resolvers.
    pub rate_limit: Option<u64>,
    /// REST API key. Overridden by RUNBOUND_API_KEY env var if both are set.
    pub api_key: Option<String>,
    /// REST API port. Default: 8081.
    pub api_port: Option<u16>,
    /// Maximum TTL cap for cached records (seconds). Default: 86400 (24 h).
    pub cache_max_ttl: Option<u32>,
    /// CIDR ranges that must never appear in resolver responses (DNS rebinding guard).
    pub private_addresses: Vec<String>,
    /// Enable DNSSEC validation. Default: false (forwarder mode — trust upstream AD bit).
    /// Set to `yes` for recursive/authoritative deployments with full RRSIG chains.
    pub dnssec_validation: bool,
    /// Log WARN for every DNSSEC-bogus query when dnssec-validation is enabled.
    pub dnssec_log_bogus: bool,

    // ── GDPR / privacy controls ────────────────────────────────────────────
    /// Max entries in the in-RAM query log ring buffer. Default: 1000. 0 = disabled.
    /// Reduce or set to 0 if your data-retention policy requires it.
    pub log_retention: usize,
    /// Include client IPs in /logs and logfile. Default: true.
    /// Set to `no` to replace IPs with "[redacted]" (does not apply to audit log).
    pub log_client_ip: bool,

    // ── Audit log ─────────────────────────────────────────────────────────────
    /// Enable immutable HMAC-chained audit log. Default: false.
    pub audit_log: bool,
    /// Path to audit log file. Default: base_dir/audit.log.
    pub audit_log_path: Option<String>,
    /// HMAC-SHA256 key (hex or raw). Auto-generated if empty.
    pub audit_log_hmac_key: Option<String>,

    // ── Slave/master sync (Runbound extensions) ────────────────────────────
    /// Node role: "master" (default) or "slave".
    pub mode: String,
    /// Master only: port for the HTTPS sync server (e.g. 8082). Disabled if absent.
    pub sync_port: Option<u16>,
    /// Slave only: master IP:port (e.g. "192.168.1.10:8082").
    pub sync_master: Option<String>,
    /// Slave only: Bearer token for authenticating to the master sync API.
    pub sync_key: Option<String>,
    /// Slave only: sync interval in seconds. Default: 30.
    pub sync_interval: u64,

    // ── ACME (Let's Encrypt) ───────────────────────────────────────────────
    /// Contact email for Let's Encrypt account.
    pub acme_email: Option<String>,
    /// Domain names to include in the cert (can appear multiple times).
    pub acme_domains: Vec<String>,
    /// Directory to store ACME account credentials and temp files.
    pub acme_cache_dir: Option<String>,
    /// Use Let's Encrypt Staging API (for testing). Default: false.
    pub acme_staging: bool,
    /// Port for the HTTP-01 challenge server. Default: 80.
    pub acme_challenge_port: Option<u16>,

    // ── HSM (Hardware Security Module) via PKCS#11 ────────────────────────
    /// Path to the PKCS#11 shared library (.so). HSM is disabled when absent.
    /// Example: /usr/lib/softhsm/libsofthsm2.so
    pub hsm_pkcs11_lib: Option<String>,
    /// PKCS#11 slot index (0-based). Default: 0.
    pub hsm_slot: u64,
    /// PKCS#11 PIN. Prefer the HSM_PIN environment variable (chmod 640).
    pub hsm_pin: Option<String>,
    /// Label of the CKO_SECRET_KEY object used as the REST API Bearer token.
    pub hsm_api_key_label: Option<String>,
    /// Label of the CKO_SECRET_KEY object used as the JSON store HMAC key.
    pub hsm_store_key_label: Option<String>,

    // ── Performance ───────────────────────────────────────────────────────────
    /// Pin each tokio worker thread to a distinct physical core (HT excluded).
    /// Default: true. Set to `no` to disable (e.g. in containers without CAP_SYS_NICE).
    pub cpu_affinity: bool,
    /// Enable AF/XDP kernel-bypass fast path. Default: true (when compiled with xdp feature).
    /// Set to `no` in unbound.conf, or pass `--no-xdp` on the command line, to disable.
    pub xdp: bool,
}

impl UnboundConfig {
    fn defaults() -> Self {
        Self {
            interfaces:    vec![],   // empty = bind 0.0.0.0 in server.rs
            port:          53,
            do_ipv4:       true,
            do_ipv6:       true,
            do_udp:        true,
            do_tcp:        true,
            mode:          "master".to_string(),
            sync_interval: 30,
            log_retention: 1000,
            log_client_ip: true,
            cpu_affinity:  true,
            xdp:           true,
            ..Default::default()
        }
    }

    pub fn is_slave(&self) -> bool { self.mode == "slave" }
    pub fn is_master(&self) -> bool { !self.is_slave() }
}

pub fn parse_file(path: &str) -> Result<UnboundConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read unbound config: {}", path))?;
    parse_str(&content)
}

pub fn parse_str(content: &str) -> Result<UnboundConfig> {
    let mut cfg = UnboundConfig::defaults();
    let mut current_forward: Option<ForwardZone> = None;
    let mut current_section = String::new();

    for (lineno, raw) in content.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        // Section header
        if line.ends_with(':') && !line.contains(' ') {
            if let Some(fwd) = current_forward.take() {
                cfg.forward_zones.push(fwd);
            }
            current_section = line.trim_end_matches(':').to_string();
            continue;
        }

        let Some((key, val)) = line.split_once(':') else {
            warn!("Line {}: cannot parse '{}' — ignored", lineno + 1, line);
            continue;
        };
        let key = key.trim();
        // Do NOT strip quotes globally — directives like local-zone have complex quoted values.
        // Each handler strips its own quotes where needed.
        let val = val.trim();

        match current_section.as_str() {
            "server" => parse_server_directive(&mut cfg, key, val, lineno + 1),
            "forward-zone" => {
                let fwd = current_forward.get_or_insert_with(|| ForwardZone {
                    name: String::new(),
                    addrs: Vec::new(),
                    tls: false,
                });
                match key {
                    "name"           => fwd.name = val.trim_matches('"').to_string(),
                    "forward-addr"   => fwd.addrs.push(val.trim_matches('"').to_string()),
                    "forward-tls-upstream" => fwd.tls = val.trim() == "yes",
                    other => warn!("Line {}: unknown forward-zone directive '{}' — ignored", lineno + 1, other),
                }
            }
            other => {
                warn!("Line {}: unknown section '{}' — ignored", lineno + 1, other);
            }
        }
    }

    if let Some(fwd) = current_forward {
        cfg.forward_zones.push(fwd);
    }

    Ok(cfg)
}

/// LOW-03: cap on local-zone / local-data to prevent DoS via pathological configs.
const MAX_LOCAL_ZONES: usize = 1_000_000;
const MAX_LOCAL_DATA:  usize = 1_000_000;

fn parse_server_directive(cfg: &mut UnboundConfig, key: &str, val: &str, lineno: usize) {
    // Mapping intentionnel 1:1 avec la syntaxe unbound.conf.
    // Volumineux par design — chaque directive Unbound correspond
    // à une assignation. Ne pas refactorer en table générique
    // pour conserver la lisibilité directive par directive.
    match key {
        "interface"      => cfg.interfaces.push(val.to_string()),
        "port"           => cfg.port = val.parse().unwrap_or(53),
        "access-control" => cfg.access_control.push(val.to_string()),
        "local-zone"     => {
            if cfg.local_zones.len() >= MAX_LOCAL_ZONES {
                warn!("Line {}: local-zone limit ({MAX_LOCAL_ZONES}) reached — entry ignored", lineno);
                return;
            }
            // Format: "name." type  OR  name. type  (with or without quotes)
            // Strip optional leading quote, then split name from type
            let raw = val.trim_start_matches('"');
            if let Some(pos) = raw.find("\" ").or_else(|| raw.find(' ')) {
                let (name, rest) = raw.split_at(pos);
                let name = name.trim_matches('"').trim();
                let zone_type = rest.trim_matches('"').trim();
                if !name.is_empty() && !zone_type.is_empty() {
                    cfg.local_zones.push(LocalZone {
                        name: name.to_string(),
                        zone_type: zone_type.to_string(),
                    });
                }
            }
        }
        "local-data"     => {
            if cfg.local_data.len() >= MAX_LOCAL_DATA {
                warn!("Line {}: local-data limit ({MAX_LOCAL_DATA}) reached — entry ignored", lineno);
                return;
            }
            // Format: "name. TYPE value"  (entire RR is quoted)
            let rr = val.trim_matches('"').trim().to_string();
            if !rr.is_empty() {
                cfg.local_data.push(LocalData { rr });
            }
        }
        "verbosity"      => cfg.verbosity = val.parse().unwrap_or(1),
        "logfile"        => cfg.logfile = Some(val.to_string()),
        "pidfile"        => cfg.pidfile = Some(val.to_string()),
        "do-ip4"         => cfg.do_ipv4 = val == "yes",
        "do-ip6"         => cfg.do_ipv6 = val == "yes",
        "do-udp"         => cfg.do_udp  = val == "yes",
        "do-tcp"         => cfg.do_tcp  = val == "yes",
        // TLS — DoT / DoH / DoQ (Runbound extensions, ignored by real Unbound)
        "tls-service-pem" | "tls-cert-bundle" => cfg.tls.cert_path = Some(val.trim_matches('"').to_string()),
        "tls-service-key"                      => cfg.tls.key_path  = Some(val.trim_matches('"').to_string()),
        "tls-port"   => cfg.tls.dot_port  = val.parse().ok(),
        "https-port" => cfg.tls.doh_port  = val.parse().ok(),
        "quic-port"  => cfg.tls.doq_port  = val.parse().ok(),
        "tls-cert-hostname" | "server-hostname" => cfg.tls.hostname = Some(val.trim_matches('"').to_string()),
        "dot-client-auth-ca" => cfg.tls.dot_client_auth_ca = Some(val.trim_matches('"').to_string()),
        // Runbound-specific extensions (not in stock Unbound)
        "rate-limit"    => cfg.rate_limit = val.parse::<u64>().ok()
                               .map(|v| v.min(1_000_000)), // cap at 1M rps — u64::MAX silently disables
        "api-key"       => {
            warn!(
                "api-key is set in the config file (plaintext). \
                 Prefer the RUNBOUND_API_KEY environment variable — \
                 set it in /etc/runbound/env (chmod 640) to keep the key \
                 out of config files and version control."
            );
            cfg.api_key = Some(val.trim_matches('"').to_string());
        }
        "api-port"      => cfg.api_port      = val.parse().ok(),
        "cache-max-ttl" => cfg.cache_max_ttl = val.parse().ok(),
        "private-address" => {
            let cidr = val.trim_matches('"').trim().to_string();
            if !cidr.is_empty() { cfg.private_addresses.push(cidr); }
        }
        "dnssec-validation" => cfg.dnssec_validation = val.trim_matches('"') == "yes",
        "dnssec-log-bogus"  => cfg.dnssec_log_bogus  = val.trim_matches('"') == "yes",
        "log-retention"     => cfg.log_retention      = val.parse().unwrap_or(1000),
        "log-client-ip"     => cfg.log_client_ip      = val.trim_matches('"') != "no",
        "audit-log"          => cfg.audit_log          = val.trim_matches('"') == "yes",
        "audit-log-path"     => cfg.audit_log_path     = Some(val.trim_matches('"').to_string()),
        "audit-log-hmac-key" => cfg.audit_log_hmac_key = Some(val.trim_matches('"').to_string()),
        // Slave/master sync directives
        "mode"          => cfg.mode          = val.trim_matches('"').to_string(),
        "sync-port"     => cfg.sync_port     = val.parse().ok(),
        "sync-master"   => cfg.sync_master   = Some(val.trim_matches('"').to_string()),
        "sync-key"      => cfg.sync_key      = Some(val.trim_matches('"').to_string()),
        "sync-interval" => cfg.sync_interval = val.parse().unwrap_or(30),
        // ACME / Let's Encrypt
        "acme-email"          => cfg.acme_email          = Some(val.trim_matches('"').to_string()),
        "acme-domain"         => cfg.acme_domains.push(val.trim_matches('"').to_string()),
        "acme-cache-dir"      => cfg.acme_cache_dir      = Some(val.trim_matches('"').to_string()),
        "acme-staging"        => cfg.acme_staging        = val.trim_matches('"') == "yes",
        "acme-challenge-port" => cfg.acme_challenge_port = val.parse().ok(),
        // HSM / PKCS#11
        "hsm-pkcs11-lib"      => cfg.hsm_pkcs11_lib  = Some(val.trim_matches('"').to_string()),
        "hsm-slot"            => cfg.hsm_slot         = val.parse().unwrap_or(0),
        "hsm-pin"             => {
            warn!(
                "hsm-pin is set in the config file (plaintext). \
                 Prefer the HSM_PIN environment variable — \
                 set it in /etc/runbound/env (chmod 640) to keep the PIN \
                 out of config files and version control."
            );
            cfg.hsm_pin = Some(val.trim_matches('"').to_string());
        }
        "hsm-api-key-label"   => cfg.hsm_api_key_label   = Some(val.trim_matches('"').to_string()),
        "hsm-store-key-label" => cfg.hsm_store_key_label = Some(val.trim_matches('"').to_string()),
        "cpu-affinity"        => cfg.cpu_affinity        = val.trim_matches('"') != "no",
        "xdp"                 => cfg.xdp                 = val.trim_matches('"') != "no",
        // Accepted but unused — common Unbound tuning directives
        "num-threads" | "cache-size" | "msg-cache-size" | "rrset-cache-size"
        | "so-rcvbuf" | "so-sndbuf" | "outgoing-range" | "num-queries-per-thread"
        | "infra-cache-slabs" | "key-cache-slabs" | "msg-cache-slabs"
        | "rrset-cache-slabs" | "prefetch" | "prefetch-key"
        | "use-syslog" | "log-queries" | "log-replies"
        | "hide-identity" | "hide-version" | "identity" | "version"
        | "username" | "chroot" | "directory"
        | "auto-trust-anchor-file" | "val-log-level"
        | "harden-glue" | "harden-dnssec-stripped"
        | "unwanted-reply-threshold" | "private-domain"
        => {} // silently accepted
        other => warn!("Line {}: unknown server directive '{}' — ignored", lineno, other),
    }
}
