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
    /// Explicit TLS SNI hostname for DoT upstreams (`forward-tls-hostname`).
    /// Overrides the built-in IP→hostname map in `dot_tls_name`.
    pub tls_hostname: Option<String>,
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

// ── Alert thresholds (#12) ────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct AlertRule {
    pub name: String,
    /// "client-qps" — queries per window per source IP.
    pub metric: String,
    /// Sliding window length in seconds.
    pub window_s: u64,
    /// Query count that triggers the alert (inclusive).
    pub threshold: u64,
    /// "log" (default), "block", "notify".
    pub action: String,
    /// Webhook URL for action="notify".
    pub notify_url: Option<String>,
    /// Seconds to block the IP for action="block". 0 = permanent until restart.
    pub block_duration_s: u64,
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
    /// IPv4 prefix length for rate-limit subnet bucketing. Default: 24 (/24).
    pub rate_limit_prefix_v4: u8,
    /// IPv6 prefix length for rate-limit subnet bucketing. Default: 48 (/48).
    pub rate_limit_prefix_v6: u8,
    /// REST API key. Overridden by RUNBOUND_API_KEY env var if both are set.
    pub api_key: Option<String>,
    /// Static scoped API keys from api-key-extra blocks (#13).
    pub extra_api_keys: Vec<ExtraApiKey>,
    /// Per-subnet DNS override zones for split-horizon DNS (#10).
    pub split_horizon: Vec<SplitHorizonEntry>,
    /// REST API port. Default: 8081.
    pub api_port: Option<u16>,
    /// Maximum TTL cap for cached records (seconds). Default: 86400 (24 h).
    pub cache_max_ttl: Option<u32>,
    /// #164: minimum TTL to advertise for cached answers (floor enforcement).
    pub cache_min_ttl: Option<u32>,
    /// Minimum number of cache entries during memory pressure halvings. Default: 2048.
    /// The cache halving mechanism will never reduce the cache below this value.
    pub cache_min_entries: usize,
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
    /// Write a checkpoint every N audit entries for fast crash recovery (#28). Default: 10000. 0 = disabled.
    pub audit_checkpoint_every: u64,

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
    /// Master only: allow RFC 1918/ULA slave relay_host (local network deployments).
    pub sync_allow_private_relay: bool,

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
    /// XDP network interface configuration.
    /// - `None`              = auto-detect single interface from listen address (default, backward-compatible)
    /// - `Some("none")`      = disable XDP via interface override (useful when `xdp: yes` is shared)
    /// - `Some("eth1")`      = bind XDP to eth1 only (single explicit interface, backward-compatible)
    /// - `Some("nic2,nic3")` = bind XDP on nic2 AND nic3 simultaneously (multi-NIC, comma-separated)
    /// - `Some("auto")`      = enumerate and bind ALL eligible interfaces (UP, physical, non-bonded)
    ///
    /// Multi-NIC mode: each interface gets its own XskSocket set + worker threads, fully independent.
    /// AF_XDP is incompatible with bonding — bonded interfaces are skipped with a WARN in auto mode.
    pub xdp_interface: Option<String>,
    /// Set scaling governor to 'performance' on XDP worker cores. Default: false.
    /// Eliminates frequency-scaling ramp-up jitter on DNS burst traffic.
    /// Silent no-op when /sys/devices/system/cpu/cpuN/cpufreq/ is absent (containers, VMs).
    pub xdp_cpu_governor: bool,
    /// Pin NIC queue IRQs to their corresponding XDP worker cores. Default: false.
    /// Silent no-op when /proc/interrupts is unavailable or IRQs not found (VMs, containers).
    pub xdp_irq_affinity: bool,
    /// Attempt to allocate UMEM using 2 MiB huge pages. Default: true.
    /// Falls back silently to standard 4 KiB pages when huge pages are unavailable.
    pub xdp_hugepages: bool,
    /// Enable the XDP DNS cache snapshot (ArcSwap-backed, zero-lock reads). Default: true.
    pub xdp_cache_snapshot: bool,
    /// Maximum entries in the XDP cache snapshot. Default: 10 000.
    pub xdp_cache_snapshot_size: usize,
    /// Route DNS queries by question name hash to a dedicated CPU via CPUMAP (#67).
    /// Improves XDP cache locality for repeated lookups of the same domain.
    /// Default: false. Falls back silently to RSS if CPUMAP is unavailable.
    pub xdp_domain_routing: bool,
    /// Drain RX ring before sleeping (busy-drain loop + NAPI busy-poll hints).
    /// Eliminates rx_missed_errors under flood by processing all queued descriptors
    /// before calling poll(). Default: true.
    pub xdp_busy_poll: bool,
    /// NIC ring buffer size for AF_XDP (#80).
    /// `None` = "auto" — maximize to hardware max via SIOCETHTOOL (default).
    /// `Some(n)` = set ring to exactly n descriptors (capped at hardware max).
    pub xdp_ring_size: Option<u32>,

    // ── DNS prefetching ───────────────────────────────────────────────────────
    /// Pre-resolve popular domains before their cache entry expires. Default: false.
    pub prefetch: bool,
    /// Minimum forwarded-query count per window to qualify for prefetch. Default: 5.
    pub prefetch_threshold: u32,

    // ── API safety ────────────────────────────────────────────────────────────
    /// Minimum seconds between two consecutive POST /api/cache/flush calls.
    /// 0 disables the cooldown entirely. Default: 60.
    pub cache_flush_cooldown: u64,

    // ── Upstream racing (#33) ─────────────────────────────────────────────────
    /// Send the same query to ALL configured upstreams simultaneously and return
    /// the first valid response.  Remaining in-flight queries are cancelled.
    /// Reduces p99 latency to the fastest upstream when 2+ are configured.
    /// Default: false (backward-compatible round-robin/failover via hickory).
    pub upstream_racing: bool,

    // ── resolv.conf fallback (#94) ────────────────────────────────────────────
    /// Fall back to /etc/resolv.conf nameservers when all configured upstreams
    /// are unhealthy.  Entries appear with source="resolv.conf" and temporary=true
    /// in GET /api/upstreams.  Removed automatically when a primary upstream
    /// recovers.  Default: true.
    pub resolv_fallback: bool,

    // ── Serve-stale RFC 8767 (#108) ──────────────────────────────────────────────
    /// Return stale (expired) cached data when all upstreams return SERVFAIL.
    /// Default: true. Set to `no` to disable.
    pub serve_stale: bool,
    /// TTL (seconds) to advertise for stale answers. Default: 30.
    pub stale_answer_ttl: u32,
    /// Maximum age (seconds) of a stale entry that can still be served. Default: 86400.
    pub stale_max_age: u64,

    // ── AF_XDP ring sizes (#96) ───────────────────────────────────────────────
    /// AF_XDP fill ring size (power of 2, 64–65536). Default: 4096.
    pub xdp_fill_ring_size: u32,
    /// AF_XDP completion ring size (power of 2, 64–65536). Default: 4096.
    pub xdp_comp_ring_size: u32,
    /// AF_XDP RX ring size (power of 2, 64–65536). Default: 4096.
    pub xdp_rx_ring_size: u32,
    /// AF_XDP TX ring size (power of 2, 64–65536). Default: 4096.
    pub xdp_tx_ring_size: u32,

    // ── Firewall management (#90) ─────────────────────────────────────────────
    /// Auto-manage firewall rules at startup/shutdown. Default: false.
    pub firewall_manage: bool,
    /// Firewall backend override: auto | ufw | nftables | iptables | none.
    pub firewall_backend: Option<String>,
    /// Tag added to every rule opened by Runbound. Default: "runbound".
    pub firewall_tag: String,

    // ── Dynamic DNS RFC 2136 (#14) ───────────────────────────────────────────────
    /// Enable DNS UPDATE (RFC 2136). Default: false.
    pub allow_update: bool,
    /// Return empty NOERROR for HTTPS record queries (type 65) — prevents browsers
    /// from using HTTP/3 when QUIC is blocked on the network. Default: false.
    pub block_https_record: bool,
    pub block_page: bool,
    pub block_page_port: u16,
    pub block_page_title: String,
    pub block_page_org: String,
    pub block_page_redirect_ip: Option<String>,
    pub block_page_allow_bypass: bool,
    pub block_page_bypass_pin: String,
    /// TSIG keys for authorizing DNS UPDATEs: Vec of (name, algorithm, base64-secret).
    /// Algorithm: hmac-sha256 (recommended), hmac-sha512, hmac-sha1.
    /// Example config: tsig-key: "ddns-key" hmac-sha256 "base64secret=="
    pub tsig_keys: Vec<(String, String, String)>,

    // ── Embedded web UI (#4/#91) ──────────────────────────────────────────────
    /// Serve the built-in web UI. Default: false.
    pub ui_enabled: bool,
    /// Port for the web UI listener. Default: 8090.
    pub ui_port: u16,
    /// Bind address for the web UI listener. Default: 0.0.0.0.
    pub ui_bind: String,
    /// Enable TLS on the web UI listener. Default: true.
    pub ui_tls: bool,
    /// Path to TLS certificate PEM for the web UI. Empty = auto-generated (signed by local CA).
    pub ui_cert: String,
    /// Path to TLS private key PEM for the web UI. Empty = auto-generated.
    pub ui_key: String,
    /// Path to the local CA certificate PEM. Empty = auto-generated in base_dir.
    pub ui_ca_cert: String,
    /// Path to the local CA private key PEM. Empty = auto-generated in base_dir.
    pub ui_ca_key: String,

    // ── WebUI TLS — Option B: ACME / Let's Encrypt ──────────────────────────
    /// Set ui-tls to "acme" to use DNS-01 Let's Encrypt instead of local CA.
    pub ui_tls_acme: bool,
    /// Domain to obtain a Let's Encrypt certificate for (e.g. runbound.example.com).
    pub ui_acme_domain: String,
    /// Contact email for the Let's Encrypt account.
    pub ui_acme_email: String,
    /// DNS provider for DNS-01 challenge: "cloudflare" or "hook".
    pub ui_acme_dns: String,
    /// Cloudflare API token with Zone:DNS:Edit permission (when ui-acme-dns: cloudflare).
    pub ui_acme_cf_token: String,
    /// Path to hook script called as: script add|del NAME VALUE (when ui-acme-dns: hook).
    pub ui_acme_hook: String,

    // ── UDP socket options (#20) ─────────────────────────────────────────────
    /// Enable SO_BUSY_POLL + SO_PREFER_BUSY_POLL on UDP sockets. Default: false.
    /// Spins in kernel context instead of sleeping between packets.
    /// Reduces scheduler wake-up latency (p99) on dedicated servers.
    /// Wastes CPU on shared/virtualized hosts — leave off unless benchmarked.
    pub udp_busy_poll: bool,

    // ── ICMP echo responder (#89) ──────────────────────────────────────────
    pub icmp_enabled: bool,
    pub icmp_rate_pps: u32,
    pub icmp_burst: u32,
    // ── AXFR/IXFR zone transfer (#22) ────────────────────────────────────────
    /// Enable AXFR zone transfer serving. Default: false.
    /// Enable io_uring for async I/O operations. Requires Linux 5.1+. Default: false.
    /// When enabled, detected at startup and logged. Falls back silently if unavailable.
    pub io_uring: bool,
    pub axfr_enabled: bool,
    /// CIDR ranges allowed to pull zone transfers. Required when axfr-enabled.
    pub axfr_allow: Vec<String>,

    // ── Alert thresholds (#12) ────────────────────────────────────────────────
    pub alerts: Vec<AlertRule>,

    // ── Bot defense (#bot-defense) ──────────────────────────────────────────
    /// Duration in seconds for automatic bot bans. Default: 86400 (24h). 0 = permanent.
    pub bot_ban_duration_secs: u64,
    /// Enable honeypot fields in the WebUI login form. Default: false.
    pub bot_honeypot_enabled: bool,

    // ── WebUI TLS SANs (#150) ─────────────────────────────────────────────────
    /// Extra IP addresses or hostnames to add as Subject Alternative Names to the
    /// auto-generated WebUI TLS certificate. Repeat the directive for multiple SANs.
    pub ui_tls_san: Vec<String>,

    // ── White-label branding (#25) ─────────────────────────────────────────────
    /// Custom product name displayed in the web UI (default: "Runbound"). 
    pub ui_brand_name: String,
    /// URL of a custom logo image displayed in the header (default: empty = built-in SVG globe).
    pub ui_brand_logo_url: String,
    /// Hex accent color for the UI (default: #22d3ee = cyan-400).
    pub ui_accent_color: String,
    /// Custom favicon URL (default: empty = built-in).
    pub ui_favicon_url: String,

    // ── Webhooks (#11) ────────────────────────────────────────────────────────
    /// List of webhook targets for system event notifications.
    pub webhooks: Vec<crate::webhooks::WebhookTarget>,
}


/// Statically-provisioned scoped API key from api-key-extra: config block (#13).
#[derive(Debug, Clone, Default)]
pub struct ExtraApiKey {
    pub label: String,
    pub key: String,
    pub role: crate::multiuser::Role,
}

/// Per-subnet DNS override zone for split-horizon DNS (#10).
#[derive(Debug, Clone, Default)]
pub struct SplitHorizonEntry {
    pub name: String,
    pub subnets: Vec<String>,
    pub local_data: Vec<LocalData>,
}

impl UnboundConfig {
    pub fn defaults() -> Self {
        Self {
            interfaces: vec![], // empty = bind 0.0.0.0 in server.rs
            port: 53,
            verbosity: 1, // WARN — per-query logs off by default
            do_ipv4: true,
            do_ipv6: true,
            do_udp: true,
            do_tcp: true,
            mode: "master".to_string(),
            sync_interval: 30,
            log_retention: 1000,
            log_client_ip: false,
            cpu_affinity: false, // #163: floating scheduler outperforms naive pinning (measured: 874k vs 630k qps on Xeon v2)
            xdp: true,
            xdp_hugepages: true,
            xdp_busy_poll: true,
            xdp_cache_snapshot: true,
            xdp_cache_snapshot_size: 10_000,
            cache_min_entries: 2048,
            prefetch: false,
            prefetch_threshold: 5,
            cache_flush_cooldown: 60,
            resolv_fallback: true,
            rate_limit_prefix_v4: 24,
            rate_limit_prefix_v6: 48,
            xdp_fill_ring_size: 4096,
            xdp_comp_ring_size: 4096,
            xdp_rx_ring_size: 4096,
            xdp_tx_ring_size: 4096,
            serve_stale: true,
            stale_answer_ttl: 30,
            stale_max_age: 86400,
            ui_enabled: false,
            ui_port: 8090,
            ui_bind: "0.0.0.0".to_owned(),
            ui_tls: true,
            ui_cert: String::new(),
            ui_key: String::new(),
            ui_ca_cert: String::new(),
            ui_ca_key: String::new(),
            ui_tls_acme: false,
            ui_acme_domain: String::new(),
            ui_acme_email: String::new(),
            ui_acme_dns: String::new(),
            ui_acme_cf_token: String::new(),
            ui_acme_hook: String::new(),
            icmp_enabled: false,
            icmp_rate_pps: 10,
            icmp_burst: 5,
            audit_checkpoint_every: 10000,
            io_uring: false,
            axfr_enabled: false,
            axfr_allow: vec![],
            alerts: vec![],
            bot_ban_duration_secs: 86400,
            bot_honeypot_enabled: false,
            udp_busy_poll: false,
            ui_tls_san: vec![],
            ui_brand_name: "Runbound".to_string(),
            ui_brand_logo_url: String::new(),
            ui_accent_color: "#22d3ee".to_string(),
            ui_favicon_url: String::new(),
            webhooks: vec![],
            ..Default::default()
        }
    }

    pub fn is_slave(&self) -> bool {
        self.mode == "slave"
    }
    pub fn is_master(&self) -> bool {
        !self.is_slave()
    }
}

pub fn parse_file(path: &str) -> Result<UnboundConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read unbound config: {}", path))?;
    parse_str(&content)
}

pub fn parse_str(content: &str) -> Result<UnboundConfig> {
    let mut cfg = UnboundConfig::defaults();
    let mut current_forward: Option<ForwardZone> = None;
    let mut current_extra_key: Option<ExtraApiKey> = None;
    let mut current_split: Option<SplitHorizonEntry> = None;
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
            if let Some(ek) = current_extra_key.take() {
                if !ek.label.is_empty() && !ek.key.is_empty() {
                    cfg.extra_api_keys.push(ek);
                }
            }
            if let Some(se) = current_split.take() {
                if !se.subnets.is_empty() {
                    cfg.split_horizon.push(se);
                }
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
            "server" => parse_server_directive(&mut cfg, key, val, lineno + 1)?,
            "forward-zone" => {
                let fwd = current_forward.get_or_insert_with(|| ForwardZone {
                    name: String::new(),
                    addrs: Vec::new(),
                    tls: false,
                    tls_hostname: None,
                });
                match key {
                    "name" => fwd.name = val.trim_matches('"').to_string(),
                    "forward-addr" => fwd.addrs.push(val.trim_matches('"').to_string()),
                    "forward-tls-upstream" => fwd.tls = val.trim() == "yes",
                    "forward-tls-hostname" => fwd.tls_hostname = Some(val.trim_matches('"').to_string()),
                    other => warn!(
                        "Line {}: unknown forward-zone directive '{}' — ignored",
                        lineno + 1,
                        other
                    ),
                }
            }
            "icmp" => match key {
                "enable" => cfg.icmp_enabled = val.trim_matches('"') == "yes",
                "rate-limit" => {
                    cfg.icmp_rate_pps = val.trim_matches('"').parse().unwrap_or(10);
                }
                "rate-limit-burst" => {
                    cfg.icmp_burst = val.trim_matches('"').parse().unwrap_or(5);
                }
                other => warn!(
                    "Line {}: unknown icmp directive '{}' — ignored",
                    lineno + 1,
                    other
                ),
            },
            "api-key-extra" => {
                let ek = current_extra_key.get_or_insert_with(ExtraApiKey::default);
                match key {
                    "label" => ek.label = val.trim_matches('"').to_string(),
                    "key" => {
                        let raw = val.trim_matches('"');
                        ek.key = if let Some(env_var) = raw.strip_prefix("env:") {
                            std::env::var(env_var).unwrap_or_default()
                        } else {
                            raw.to_string()
                        };
                    }
                    "role" => {
                        ek.role = match val.trim_matches('"').to_lowercase().as_str() {
                            "read"     => crate::multiuser::Role::Read,
                            "dns"      => crate::multiuser::Role::Dns,
                            "operator" => crate::multiuser::Role::Operator,
                            "admin"    => crate::multiuser::Role::Admin,
                            other => {
                                warn!("Line {}: unknown role '{}' — defaulting to read", lineno + 1, other);
                                crate::multiuser::Role::Read
                            }
                        };
                    }
                    other => warn!("Line {}: unknown api-key-extra directive '{}' — ignored", lineno + 1, other),
                }
            },
            "split-horizon" => {
                let se = current_split.get_or_insert_with(SplitHorizonEntry::default);
                match key {
                    "name" => se.name = val.trim_matches('"').to_string(),
                    "subnet" => se.subnets.push(val.trim_matches('"').to_string()),
                    "local-data" => {
                        let rr = val.trim_matches('"').trim().to_string();
                        if !rr.is_empty() {
                            se.local_data.push(LocalData { rr });
                        }
                    }
                    other => warn!("Line {}: unknown split-horizon directive '{}' — ignored", lineno + 1, other),
                }
            },
            "io-uring" => {
                match key {
                    "enable" => cfg.io_uring = val.trim_matches('"') == "yes",
                    other => warn!("Line {}: unknown io-uring directive '{}' — ignored", lineno + 1, other),
                }
            }
            "axfr" => {
                match key {
                    "enable" => cfg.axfr_enabled = val.trim_matches('"') == "yes",
                    "allow" => cfg.axfr_allow.push(val.trim_matches('"').to_string()),
                    other => warn!("Line {}: unknown axfr directive '{}' — ignored", lineno + 1, other),
                }
            }
            "alert" => {
                // #148: helper — ensure a rule exists before writing sub-directives.
                // If name: was not the first directive, emit a warning and auto-insert a
                // placeholder rule so the remaining directives are not silently dropped.
                let ensure_rule = |alerts: &mut Vec<AlertRule>, k: &str, ln: usize| {
                    if alerts.is_empty() {
                        warn!(
                            "Line {}: alert directive '{}' before 'name:' — inserting unnamed rule.                              Add 'name: <label>' as the first directive in your alert block.",
                            ln, k
                        );
                        alerts.push(AlertRule {
                            name: format!("alert-{}", ln),
                            metric: "client-qps".to_string(),
                            window_s: 10,
                            threshold: 1000,
                            action: "log".to_string(),
                            notify_url: None,
                            block_duration_s: 300,
                        });
                    }
                };
                match key {
                    "name" => {
                        cfg.alerts.push(AlertRule {
                            name: val.trim_matches('"'  ).to_string(),
                            metric: "client-qps".to_string(),
                            window_s: 10,
                            threshold: 1000,
                            action: "log".to_string(),
                            notify_url: None,
                            block_duration_s: 300,
                        });
                    }
                    "metric" => {
                        ensure_rule(&mut cfg.alerts, key, lineno + 1);
                        cfg.alerts.last_mut().unwrap().metric = val.trim_matches('"').to_string();
                    }
                    "window-s" => {
                        ensure_rule(&mut cfg.alerts, key, lineno + 1);
                        cfg.alerts.last_mut().unwrap().window_s = val.trim_matches('"').parse().unwrap_or(10);
                    }
                    "threshold" => {
                        ensure_rule(&mut cfg.alerts, key, lineno + 1);
                        cfg.alerts.last_mut().unwrap().threshold = val.trim_matches('"').parse().unwrap_or(1000);
                    }
                    "action" => {
                        ensure_rule(&mut cfg.alerts, key, lineno + 1);
                        cfg.alerts.last_mut().unwrap().action = val.trim_matches('"').to_string();
                    }
                    "notify-url" => {
                        ensure_rule(&mut cfg.alerts, key, lineno + 1);
                        cfg.alerts.last_mut().unwrap().notify_url = Some(val.trim_matches('"').to_string());
                    }
                    "block-duration-s" => {
                        ensure_rule(&mut cfg.alerts, key, lineno + 1);
                        cfg.alerts.last_mut().unwrap().block_duration_s = val.trim_matches('"').parse().unwrap_or(300);
                    }
                    other => warn!("Line {}: unknown alert directive '{}' — ignored", lineno + 1, other),
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
    if let Some(ek) = current_extra_key {
        if !ek.label.is_empty() && !ek.key.is_empty() {
            cfg.extra_api_keys.push(ek);
        }
    }
    if let Some(se) = current_split {
        if !se.subnets.is_empty() {
            cfg.split_horizon.push(se);
        }
    }

    Ok(cfg)
}

/// LOW-03: cap on local-zone / local-data to prevent DoS via pathological configs.
const MAX_LOCAL_ZONES: usize = 1_000_000;
const MAX_LOCAL_DATA: usize = 1_000_000;

/// Parse and validate an AF_XDP ring-size directive (#96).
/// Accepts a u32 that is a power of 2 in [64, 65536]; returns a config error otherwise.
fn parse_xdp_ring_size(val: &str, key: &str, lineno: usize) -> anyhow::Result<u32> {
    let v = val
        .trim_matches('"')
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("Line {lineno}: {key} must be a positive integer"))?;
    if !(64..=65536).contains(&v) || !v.is_power_of_two() {
        anyhow::bail!(
            "Line {lineno}: {key} = {v} is invalid (must be a power of 2 between 64 and 65536)"
        );
    }
    Ok(v)
}

fn parse_server_directive(
    cfg: &mut UnboundConfig,
    key: &str,
    val: &str,
    lineno: usize,
) -> anyhow::Result<()> {
    // Mapping intentionnel 1:1 avec la syntaxe unbound.conf.
    // Volumineux par design — chaque directive Unbound correspond
    // à une assignation. Ne pas refactorer en table générique
    // pour conserver la lisibilité directive par directive.
    match key {
        "interface" => cfg.interfaces.push(val.to_string()),
        "port" => cfg.port = val.parse().unwrap_or(53),
        "access-control" => cfg.access_control.push(val.to_string()),
        "local-zone" => {
            if cfg.local_zones.len() >= MAX_LOCAL_ZONES {
                warn!(
                    "Line {}: local-zone limit ({MAX_LOCAL_ZONES}) reached — entry ignored",
                    lineno
                );
                return Ok(());
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
        "local-data" => {
            if cfg.local_data.len() >= MAX_LOCAL_DATA {
                warn!(
                    "Line {}: local-data limit ({MAX_LOCAL_DATA}) reached — entry ignored",
                    lineno
                );
                return Ok(());
            }
            // Format: "name. TYPE value"  (entire RR is quoted)
            let rr = val.trim_matches('"').trim().to_string();
            if !rr.is_empty() {
                cfg.local_data.push(LocalData { rr });
            }
        }
        "verbosity" => cfg.verbosity = val.parse().unwrap_or(1),
        "logfile" => cfg.logfile = Some(val.to_string()),
        "pidfile" => cfg.pidfile = Some(val.to_string()),
        "do-ip4" => cfg.do_ipv4 = val == "yes",
        "do-ip6" => cfg.do_ipv6 = val == "yes",
        "do-udp" => cfg.do_udp = val == "yes",
        "do-tcp" => cfg.do_tcp = val == "yes",
        // TLS — DoT / DoH / DoQ (Runbound extensions, ignored by real Unbound)
        "tls-service-pem" | "tls-cert-bundle" => {
            cfg.tls.cert_path = Some(val.trim_matches('"').to_string())
        }
        "tls-service-key" => cfg.tls.key_path = Some(val.trim_matches('"').to_string()),
        "tls-port" => cfg.tls.dot_port = val.parse().ok(),
        "https-port" => cfg.tls.doh_port = val.parse().ok(),
        "quic-port" => cfg.tls.doq_port = val.parse().ok(),
        "tls-cert-hostname" | "server-hostname" => {
            cfg.tls.hostname = Some(val.trim_matches('"').to_string())
        }
        "dot-client-auth-ca" => {
            cfg.tls.dot_client_auth_ca = Some(val.trim_matches('"').to_string())
        }
        // Runbound-specific extensions (not in stock Unbound)
        "rate-limit" => cfg.rate_limit = val.parse::<u64>().ok().map(|v| v.min(1_000_000)), // cap at 1M rps — u64::MAX silently disables
        "rate-limit-prefix-v4" => {
            cfg.rate_limit_prefix_v4 = val.parse::<u8>().unwrap_or(24).min(32)
        }
        "rate-limit-prefix-v6" => {
            cfg.rate_limit_prefix_v6 = val.parse::<u8>().unwrap_or(48).min(128)
        }
        "api-key" => {
            warn!(
                "api-key is set in the config file (plaintext). \
                 Prefer the RUNBOUND_API_KEY environment variable — \
                 set it in /etc/runbound/env (chmod 640) to keep the key \
                 out of config files and version control."
            );
            cfg.api_key = Some(val.trim_matches('"').to_string());
        }
        "api-port" => cfg.api_port = val.parse().ok(),
        "cache-max-ttl" => cfg.cache_max_ttl = val.parse().ok(),
        "cache-min-ttl" => cfg.cache_min_ttl = val.parse().ok(),
        "cache-min-entries" => cfg.cache_min_entries = val.parse::<usize>().unwrap_or(2048).max(1),
        "private-address" => {
            let cidr = val.trim_matches('"').trim().to_string();
            if !cidr.is_empty() {
                cfg.private_addresses.push(cidr);
            }
        }
        "dnssec-validation" => cfg.dnssec_validation = val.trim_matches('"') == "yes",
        "dnssec-log-bogus" => cfg.dnssec_log_bogus = val.trim_matches('"') == "yes",
        "log-retention" => cfg.log_retention = val.parse().unwrap_or(1000),
        "log-client-ip" => cfg.log_client_ip = val.trim_matches('"') != "no",
        "audit-log" => cfg.audit_log = val.trim_matches('"') == "yes",
        "audit-log-path" => cfg.audit_log_path = Some(val.trim_matches('"').to_string()),
        "audit-log-hmac-key" => cfg.audit_log_hmac_key = Some(val.trim_matches('"').to_string()),
        "audit-checkpoint-every" => cfg.audit_checkpoint_every = val.parse().unwrap_or(10000),
        // Slave/master sync directives
        "mode" => cfg.mode = val.trim_matches('"').to_string(),
        "sync-port" => cfg.sync_port = val.parse().ok(),
        "sync-master" => cfg.sync_master = Some(val.trim_matches('"').to_string()),
        "sync-key" => cfg.sync_key = Some(val.trim_matches('"').to_string()),
        "sync-interval" => cfg.sync_interval = val.parse().unwrap_or(30),
        "sync-allow-private-relay" => cfg.sync_allow_private_relay = matches!(val.trim(), "yes" | "true" | "1"),
        // ACME / Let's Encrypt
        "acme-email" => cfg.acme_email = Some(val.trim_matches('"').to_string()),
        "acme-domain" => cfg.acme_domains.push(val.trim_matches('"').to_string()),
        "acme-cache-dir" => cfg.acme_cache_dir = Some(val.trim_matches('"').to_string()),
        "acme-staging" => cfg.acme_staging = val.trim_matches('"') == "yes",
        "acme-challenge-port" => cfg.acme_challenge_port = val.parse().ok(),
        // HSM / PKCS#11
        "hsm-pkcs11-lib" => cfg.hsm_pkcs11_lib = Some(val.trim_matches('"').to_string()),
        "hsm-slot" => cfg.hsm_slot = val.parse().unwrap_or(0),
        "hsm-pin" => {
            warn!(
                "hsm-pin is set in the config file (plaintext). \
                 Prefer the HSM_PIN environment variable — \
                 set it in /etc/runbound/env (chmod 640) to keep the PIN \
                 out of config files and version control."
            );
            cfg.hsm_pin = Some(val.trim_matches('"').to_string());
        }
        "hsm-api-key-label" => cfg.hsm_api_key_label = Some(val.trim_matches('"').to_string()),
        "hsm-store-key-label" => cfg.hsm_store_key_label = Some(val.trim_matches('"').to_string()),
        "udp-busy-poll" => cfg.udp_busy_poll = val.trim_matches('"') == "yes",
        "cpu-affinity" => cfg.cpu_affinity = val.trim_matches('"') != "no",
        "xdp" => cfg.xdp = val.trim_matches('"') != "no",
        "xdp-interface" => cfg.xdp_interface = Some(val.trim_matches('"').to_string()),
        "xdp-cpu-governor" => {
            // Accept "performance" (documented value) and "yes" (legacy);
            // anything else (none / no / absent) leaves the feature disabled.
            cfg.xdp_cpu_governor = matches!(val.trim_matches('"'), "performance" | "yes");
        }
        "xdp-irq-affinity" => cfg.xdp_irq_affinity = val.trim_matches('"') == "yes",
        "xdp-hugepages" => cfg.xdp_hugepages = val.trim_matches('"') != "no",
        "xdp-cache-snapshot" => cfg.xdp_cache_snapshot = val.trim_matches('"') != "no",
        "xdp-cache-snapshot-size" => cfg.xdp_cache_snapshot_size = val.parse().unwrap_or(10_000),
        "xdp-domain-routing" => cfg.xdp_domain_routing = val.trim_matches('"') == "yes",
        "xdp-busy-poll" => cfg.xdp_busy_poll = val.trim_matches('"') != "no",
        "xdp-ring-size" => {
            let v = val.trim_matches('"').trim();
            cfg.xdp_ring_size = if v == "auto" {
                None
            } else {
                v.parse::<u32>().ok()
            };
        }
        "prefetch" => cfg.prefetch = val.trim_matches('"') == "yes",
        "prefetch-threshold" => cfg.prefetch_threshold = val.parse().unwrap_or(5),
        "cache-flush-cooldown" => cfg.cache_flush_cooldown = val.parse().unwrap_or(60),
        "upstream-racing" => cfg.upstream_racing = val.trim_matches('"') == "yes",
        "resolv-fallback" => cfg.resolv_fallback = val.trim_matches('"') != "no",
        "serve-stale" => cfg.serve_stale = val.trim_matches('"') != "no",
        "allow-update" => cfg.allow_update = val.trim_matches('"') != "no",
        "block-https-record" => cfg.block_https_record = val.trim_matches('"') == "yes",
        "block-page" => cfg.block_page = val.trim_matches('"') == "yes",
        "block-page-port" => cfg.block_page_port = val.trim_matches('"').parse().unwrap_or(8083),
        "block-page-title" => cfg.block_page_title = val.trim_matches('"').to_string(),
        "block-page-org" => cfg.block_page_org = val.trim_matches('"').to_string(),
        "block-page-redirect-ip" => cfg.block_page_redirect_ip = Some(val.trim_matches('"').to_string()),
        "block-page-allow-bypass" => cfg.block_page_allow_bypass = val.trim_matches('"') == "yes",
        "block-page-bypass-pin" => cfg.block_page_bypass_pin = val.trim_matches('"').to_string(),
        "tsig-key" => {
            // Format: "keyname" algorithm "base64secret"
            let parts: Vec<&str> = val.splitn(3, ' ').collect();
            if parts.len() == 3 {
                let name = parts[0].trim_matches('"').to_string();
                let alg  = parts[1].to_string();
                let sec  = parts[2].trim_matches('"').to_string();
                cfg.tsig_keys.push((name, alg, sec));
            }
        }
        "stale-answer-ttl" => cfg.stale_answer_ttl = val.parse().unwrap_or(30),
        "stale-max-age" => cfg.stale_max_age = val.parse().unwrap_or(86400),
        "firewall-manage" => cfg.firewall_manage = val.trim_matches('"') == "yes",
        "firewall-backend" => cfg.firewall_backend = Some(val.trim_matches('"').to_owned()),
        "firewall-tag" => cfg.firewall_tag = val.trim_matches('"').to_owned(),
        "ui-enabled" => cfg.ui_enabled = val.trim_matches('"') == "yes",
        "ui-port" => cfg.ui_port = val.parse().unwrap_or(8090),
        "ui-bind" => cfg.ui_bind = val.trim_matches('"').to_owned(),
        "ui-tls"  => match val.trim().trim_matches('"') {
            "acme" => { cfg.ui_tls = true;  cfg.ui_tls_acme = true; }
            "no" | "false" | "0" => cfg.ui_tls = false,
            _ => { cfg.ui_tls = true; cfg.ui_tls_acme = false; } // yes/true/1/ca
        },
        "ui-cert"    => cfg.ui_cert    = val.trim().trim_matches('"').to_owned(),
        "ui-key"     => cfg.ui_key     = val.trim().trim_matches('"').to_owned(),
        "ui-ca-cert"      => cfg.ui_ca_cert      = val.trim().trim_matches('"').to_owned(),
        "ui-ca-key"       => cfg.ui_ca_key       = val.trim().trim_matches('"').to_owned(),
        "ui-acme-domain"  => cfg.ui_acme_domain  = val.trim().trim_matches('"').to_owned(),
        "ui-acme-email"   => cfg.ui_acme_email   = val.trim().trim_matches('"').to_owned(),
        "ui-acme-dns"     => cfg.ui_acme_dns     = val.trim().trim_matches('"').to_owned(),
        "ui-acme-cf-token"=> cfg.ui_acme_cf_token= val.trim().trim_matches('"').to_owned(),
        "ui-acme-hook"    => cfg.ui_acme_hook    = val.trim().trim_matches('"').to_owned(),
        "ui-brand-name"    => cfg.ui_brand_name    = val.trim().trim_matches('"').to_owned(),
        "ui-brand-logo-url" => cfg.ui_brand_logo_url = val.trim().trim_matches('"').to_owned(),
        "ui-accent-color"  => cfg.ui_accent_color  = val.trim().trim_matches('"').to_owned(),
        "ui-favicon-url"   => cfg.ui_favicon_url   = val.trim().trim_matches('"').to_owned(),
        "xdp-rx-ring-size" => {
            cfg.xdp_rx_ring_size = parse_xdp_ring_size(val, "xdp-rx-ring-size", lineno)?
        }
        "xdp-tx-ring-size" => {
            cfg.xdp_tx_ring_size = parse_xdp_ring_size(val, "xdp-tx-ring-size", lineno)?
        }
        "xdp-fill-ring-size" => {
            cfg.xdp_fill_ring_size = parse_xdp_ring_size(val, "xdp-fill-ring-size", lineno)?
        }
        "xdp-comp-ring-size" => {
            cfg.xdp_comp_ring_size = parse_xdp_ring_size(val, "xdp-comp-ring-size", lineno)?
        }
        "bot-ban-duration-secs" => {
            cfg.bot_ban_duration_secs = val.trim_matches('"').parse().unwrap_or(86400);
        }
        "bot-honeypot-enabled" => {
            cfg.bot_honeypot_enabled = val.trim_matches('"') == "yes";
        }
        "webhook" | "webhook-url" => {
            // webhook "https://hooks.slack.com/..." (followed by format/token/events directives)
            cfg.webhooks.push(crate::webhooks::WebhookTarget {
                url:    val.trim_matches('"').to_owned(),
                format: crate::webhooks::WebhookFormat::GenericJson,
                token:  None,
                events: vec![],
            });
        }
        "webhook-format" => {
            if let Ok(f) = val.trim_matches('"').parse::<crate::webhooks::WebhookFormat>() {
                if let Some(last) = cfg.webhooks.last_mut() { last.format = f; }
            }
        }
        "webhook-token" => {
            if let Some(last) = cfg.webhooks.last_mut() {
                last.token = Some(val.trim_matches('"').to_owned());
            }
        }
        "webhook-events" => {
            if let Some(last) = cfg.webhooks.last_mut() {
                for ev in val.split_whitespace() {
                    if let Ok(kind) = ev.trim_matches('"').parse() {
                        last.events.push(kind);
                    }
                }
            }
        }
        "ui-tls-san" => {
            cfg.ui_tls_san.push(val.trim_matches('"').to_string());
        }
        // Accepted but unused — common Unbound tuning directives
        "num-threads"
        | "cache-size"
        | "msg-cache-size"
        | "rrset-cache-size"
        | "so-rcvbuf"
        | "so-sndbuf"
        | "outgoing-range"
        | "num-queries-per-thread"
        | "infra-cache-slabs"
        | "key-cache-slabs"
        | "msg-cache-slabs"
        | "rrset-cache-slabs"
        | "prefetch-key"
        | "use-syslog"
        | "log-queries"
        | "log-replies"
        | "hide-identity"
        | "hide-version"
        | "identity"
        | "version"
        | "username"
        | "chroot"
        | "directory"
        | "auto-trust-anchor-file"
        | "val-log-level"
        | "harden-glue"
        | "harden-dnssec-stripped"
        | "unwanted-reply-threshold"
        | "private-domain" => {} // silently accepted
        other => warn!(
            "Line {}: unknown server directive '{}' — ignored",
            lineno, other
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FEAT #16: prefetch config parsing ─────────────────────────────────

    #[test]
    fn prefetch_defaults_to_false() {
        let cfg = parse_str("server:\n").unwrap();
        assert!(!cfg.prefetch);
        assert_eq!(cfg.prefetch_threshold, 5);
    }

    #[test]
    fn prefetch_yes_enables_prefetch() {
        let cfg = parse_str("server:\n  prefetch: yes\n").unwrap();
        assert!(cfg.prefetch);
    }

    #[test]
    fn prefetch_no_disables_prefetch() {
        let cfg = parse_str("server:\n  prefetch: no\n").unwrap();
        assert!(!cfg.prefetch);
    }

    #[test]
    fn prefetch_threshold_parsed() {
        let cfg = parse_str("server:\n  prefetch-threshold: 10\n").unwrap();
        assert_eq!(cfg.prefetch_threshold, 10);
    }

    #[test]
    fn prefetch_threshold_invalid_falls_back_to_default() {
        let cfg = parse_str("server:\n  prefetch-threshold: notanumber\n").unwrap();
        assert_eq!(cfg.prefetch_threshold, 5);
    }

    // ── FEAT #96: AF_XDP ring size config parsing ─────────────────────────

    #[test]
    fn xdp_ring_sizes_default_to_4096() {
        let cfg = parse_str("server:\n").unwrap();
        assert_eq!(cfg.xdp_rx_ring_size, 4096);
        assert_eq!(cfg.xdp_tx_ring_size, 4096);
        assert_eq!(cfg.xdp_fill_ring_size, 4096);
        assert_eq!(cfg.xdp_comp_ring_size, 4096);
    }

    #[test]
    fn xdp_ring_sizes_valid_power_of_two() {
        let cfg = parse_str(
            "server:\n  xdp-rx-ring-size: 512\n  xdp-tx-ring-size: 1024\n  \
             xdp-fill-ring-size: 2048\n  xdp-comp-ring-size: 8192\n",
        )
        .unwrap();
        assert_eq!(cfg.xdp_rx_ring_size, 512);
        assert_eq!(cfg.xdp_tx_ring_size, 1024);
        assert_eq!(cfg.xdp_fill_ring_size, 2048);
        assert_eq!(cfg.xdp_comp_ring_size, 8192);
    }

    #[test]
    fn xdp_ring_size_not_power_of_two_is_error() {
        assert!(parse_str("server:\n  xdp-rx-ring-size: 1000\n").is_err());
    }

    #[test]
    fn xdp_ring_size_below_min_is_error() {
        assert!(parse_str("server:\n  xdp-rx-ring-size: 32\n").is_err());
    }

    #[test]
    fn xdp_ring_size_above_max_is_error() {
        assert!(parse_str("server:\n  xdp-rx-ring-size: 131072\n").is_err());
    }

    #[test]
    fn xdp_ring_size_boundary_64_is_valid() {
        let cfg = parse_str("server:\n  xdp-rx-ring-size: 64\n").unwrap();
        assert_eq!(cfg.xdp_rx_ring_size, 64);
    }

    #[test]
    fn xdp_ring_size_boundary_65536_is_valid() {
        let cfg = parse_str("server:\n  xdp-rx-ring-size: 65536\n").unwrap();
        assert_eq!(cfg.xdp_rx_ring_size, 65536);
    }

    // --- #158 xdp-cpu-governor parser coverage ---

    #[test]
    fn xdp_cpu_governor_performance_enables_feature() {
        let cfg = parse_str("server:\n  xdp-cpu-governor: performance\n").unwrap();
        assert!(cfg.xdp_cpu_governor,
            "xdp-cpu-governor: performance must set xdp_cpu_governor = true");
    }

    #[test]
    fn xdp_cpu_governor_yes_enables_feature() {
        let cfg = parse_str("server:\n  xdp-cpu-governor: yes\n").unwrap();
        assert!(cfg.xdp_cpu_governor,
            "xdp-cpu-governor: yes must set xdp_cpu_governor = true (legacy compat)");
    }

    #[test]
    fn xdp_cpu_governor_none_disables_feature() {
        let cfg = parse_str("server:\n  xdp-cpu-governor: none\n").unwrap();
        assert!(!cfg.xdp_cpu_governor,
            "xdp-cpu-governor: none must leave xdp_cpu_governor = false");
    }

    #[test]
    fn xdp_cpu_governor_absent_defaults_false() {
        let cfg = parse_str("server:\n  xdp: yes\n").unwrap();
        assert!(!cfg.xdp_cpu_governor,
            "absent xdp-cpu-governor must default to false");
    }

    #[test]
    fn xdp_busy_poll_yes_enables_feature() {
        let cfg = parse_str("server:\n  xdp-busy-poll: yes\n").unwrap();
        assert!(cfg.xdp_busy_poll, "xdp-busy-poll: yes must be true");
    }

    #[test]
    fn xdp_busy_poll_no_disables_feature() {
        let cfg = parse_str("server:\n  xdp-busy-poll: no\n").unwrap();
        assert!(!cfg.xdp_busy_poll, "xdp-busy-poll: no must be false");
    }

    #[test]
    fn xdp_busy_poll_absent_defaults_true() {
        let cfg = parse_str("server:\n  xdp: yes\n").unwrap();
        assert!(cfg.xdp_busy_poll, "absent xdp-busy-poll must default to true");
    }


    // ── #feat/xdp-multi-interface: xdp-interface parsing tests ───────────────

    #[test]
    fn xdp_interface_single() {
        let cfg = parse_str("server:\n  xdp-interface: nic3\n").unwrap();
        assert_eq!(cfg.xdp_interface.as_deref(), Some("nic3"));
    }

    #[test]
    fn xdp_interface_multi_csv() {
        let cfg = parse_str("server:\n  xdp-interface: nic2,nic3\n").unwrap();
        let val = cfg.xdp_interface.as_deref().unwrap();
        assert!(val.contains(','), "multi-interface must contain comma");
        let parts: Vec<_> = val.split(',').collect();
        assert_eq!(parts, vec!["nic2", "nic3"]);
    }

    #[test]
    fn xdp_interface_auto() {
        let cfg = parse_str("server:\n  xdp-interface: auto\n").unwrap();
        assert_eq!(cfg.xdp_interface.as_deref(), Some("auto"));
    }

    #[test]
    fn xdp_interface_absent_is_none() {
        let cfg = parse_str("server:\n  xdp: yes\n").unwrap();
        assert!(cfg.xdp_interface.is_none(), "absent xdp-interface must be None");
    }

    #[test]
    fn xdp_interface_none_disables() {
        let cfg = parse_str("server:\n  xdp-interface: none\n").unwrap();
        assert_eq!(cfg.xdp_interface.as_deref(), Some("none"));
    }

    #[test]
    fn xdp_no_disables_fast_path() {
        let cfg = parse_str("server:\n  xdp: no\n").unwrap();
        assert!(!cfg.xdp, "xdp: no must disable fast path");
    }

}
