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

fn parse_server_directive(cfg: &mut UnboundConfig, key: &str, val: &str, lineno: usize) {
    match key {
        "interface"      => cfg.interfaces.push(val.to_string()),
        "port"           => cfg.port = val.parse().unwrap_or(53),
        "access-control" => cfg.access_control.push(val.to_string()),
        "local-zone"     => {
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
        // Runbound-specific extensions (not in stock Unbound)
        "rate-limit"    => cfg.rate_limit    = val.parse().ok(),
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
        "audit-log"          => cfg.audit_log          = val.trim_matches('"') == "yes",
        "audit-log-path"     => cfg.audit_log_path     = Some(val.trim_matches('"').to_string()),
        "audit-log-hmac-key" => cfg.audit_log_hmac_key = Some(val.trim_matches('"').to_string()),
        // Slave/master sync directives
        "mode"          => cfg.mode          = val.trim_matches('"').to_string(),
        "sync-port"     => cfg.sync_port     = val.parse().ok(),
        "sync-master"   => cfg.sync_master   = Some(val.trim_matches('"').to_string()),
        "sync-key"      => cfg.sync_key      = Some(val.trim_matches('"').to_string()),
        "sync-interval" => cfg.sync_interval = val.parse().unwrap_or(30),
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
