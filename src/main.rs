// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
mod acme;
mod audit;
mod config;
mod cpu;
mod dns;
mod api;
mod feeds;
mod error;
mod hsm;
mod integrity;
mod logbuffer;
mod runtime;
mod store;
mod stats;
mod sync;
mod upstreams;

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use anyhow::Result;
use arc_swap::ArcSwap;
use tracing::{error, info};

use config::parser::UnboundConfig;
use dns::local::LocalZoneSet;
use dns::{Acl, RateLimiter};
use api::{AppState, init_api_key};
use stats::Stats;

const API_BIND: &str = "127.0.0.1"; // API must not be exposed externally

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if handle_cli_flags(&args)? {
        return Ok(());
    }

    let (cfg, base_dir, cfg_path) = init_runtime(&args)?;

    // ── Tokio runtime with optional CPU affinity ──────────────────────────
    // init_runtime() has already installed the tracing subscriber, so info!()
    // works here without a running async runtime.
    let cores = cpu::physical_cores();
    let core_count = cores.len();

    let runtime = if cfg.cpu_affinity && !cores.is_empty() {
        info!(cores = core_count, "CPU affinity enabled — physical cores (HT excluded)");
        let cores_arc = Arc::new(cores);
        let thread_index = Arc::new(AtomicUsize::new(0));
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(core_count)
            .on_thread_start(move || {
                let idx = thread_index.fetch_add(1, Ordering::Relaxed) % core_count;
                cpu::pin_to_cpu(cores_arc[idx]);
            })
            .enable_all()
            .build()?
    } else {
        if cfg.cpu_affinity {
            info!("CPU affinity disabled (fallback: /sys unavailable)");
        } else {
            info!("CPU affinity disabled (cpu-affinity: no)");
        }
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
    };

    runtime.block_on(async_main(cfg, base_dir, cfg_path))
}

async fn async_main(cfg: UnboundConfig, base_dir: std::path::PathBuf, cfg_path: String) -> Result<()> {
    let (zones, rate_limiter, acl, global_stats, log_buffer, audit) =
        build_and_launch(&cfg, base_dir, cfg_path).await?;

    // ── XDP fast path (optional, feature-gated) ───────────────────────────
    // The handle must stay alive for the entire process lifetime; dropping it
    // would detach the XDP program and destroy the XSKMAP.
    #[cfg(feature = "xdp")]
    let _xdp_handle = {
        let iface = cfg.interfaces.first()
            .and_then(|s| {
                let s = s.trim();
                if s == "0.0.0.0" || s == "::" || s.is_empty() { return None; }
                if s.parse::<std::net::IpAddr>().is_ok() {
                    return dns::xdp::socket::iface_for_ip(s);
                }
                Some(s.to_string())
            })
            .or_else(|| dns::xdp::socket::default_interface());
        match iface {
            Some(ref iface_name) => {
                match dns::xdp::start_xdp(iface_name, Arc::clone(&zones), Arc::clone(&rate_limiter), Arc::clone(&acl)) {
                    Ok(h)  => { info!(iface = %iface_name, "XDP kernel-bypass fast path active"); Some(h) }
                    Err(e) => { tracing::warn!("XDP not available (continuing without): {e}"); None }
                }
            }
            None => { tracing::warn!("XDP: could not determine network interface; fast path disabled"); None }
        }
    };

    let result = dns::run_dns_server(&cfg, zones, rate_limiter, acl, global_stats, log_buffer).await;
    audit.send(audit::AuditEvent::Shutdown);
    result
}

/// Handle `--help`, `--version`, `--gen-cert` flags. Returns `true` if the process should exit.
fn handle_cli_flags(args: &[String]) -> Result<bool> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(true);
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("runbound {}", env!("CARGO_PKG_VERSION"));
        return Ok(true);
    }
    // --gen-cert [hostname] — generate a self-signed TLS certificate for DoT/DoH/DoQ
    if let Some(pos) = args.iter().position(|a| a == "--gen-cert") {
        let hostname = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("runbound.local");
        gen_self_signed_cert(hostname)?;
        return Ok(true);
    }
    Ok(false)
}

/// Install rustls crypto provider, init tracing, load and validate config, init HSM.
fn init_runtime(args: &[String]) -> Result<(UnboundConfig, std::path::PathBuf, String)> {
    // rustls 0.23: when multiple crypto backends are compiled in (ring + aws-lc-rs),
    // ServerConfig::builder() panics unless a default provider is installed first.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok() = no-op if already installed

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cfg_path = args.get(1)
        .cloned()
        .unwrap_or_else(|| "/etc/unbound/unbound.conf".to_string());

    // Derive runtime base_dir from config file's parent directory.
    // All runtime files (api.key, dns_entries.json, …) are stored there.
    let cfg_canonical = std::fs::canonicalize(&cfg_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&cfg_path));
    let base_dir = cfg_canonical
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Reject / and /tmp — running from there would scatter files in unexpected places.
    match base_dir.to_str() {
        Some("/") | Some("/tmp") => {
            anyhow::bail!(
                "Config base directory '{}' is not allowed. \
                 Move your config file to a dedicated directory (e.g. /etc/runbound/).",
                base_dir.display()
            );
        }
        _ => {}
    }

    runtime::BASE_DIR.set(base_dir.clone())
        .expect("BASE_DIR set twice — this is a bug");
    info!(base_dir = %base_dir.display(), "Runtime base_dir");

    info!(path = %cfg_path, "Loading config");
    let unbound_cfg = config::load(&cfg_path)?;

    // ── HSM: load key material from PKCS#11 device (if configured) ───────────
    // Must run before init_api_key() and integrity::store_key() so the HSM
    // keys are in the OnceLocks before any code reads them.
    // On failure: log + exit(1). Never silently fall back to env vars —
    // the operator explicitly opted into HSM protection.
    if let Some(hsm_cfg) = hsm::HsmConfig::from_config(&unbound_cfg) {
        if let Err(e) = hsm::load_and_store(&hsm_cfg) {
            error!(err = %e, "HSM key loading failed — exiting");
            std::process::exit(1);
        }
    }

    info!(
        port          = unbound_cfg.port,
        interfaces    = ?unbound_cfg.interfaces,
        local_zones   = unbound_cfg.local_zones.len(),
        local_data    = unbound_cfg.local_data.len(),
        forward_zones = unbound_cfg.forward_zones.len(),
        "Config loaded"
    );

    Ok((unbound_cfg, base_dir, cfg_path))
}

/// Init audit, ACME, zone set, background tasks, REST API, sync. Returns DNS server inputs.
async fn build_and_launch(
    cfg:      &UnboundConfig,
    base_dir: std::path::PathBuf,
    cfg_path: String,
) -> Result<(
    Arc<ArcSwap<LocalZoneSet>>,
    Arc<RateLimiter>,
    Arc<Acl>,
    Arc<Stats>,
    logbuffer::SharedLogBuffer,
    audit::AuditLogger,
)> {
    // ── Audit log ─────────────────────────────────────────────────────────
    let audit_log_path = cfg.audit_log_path.as_deref().map(std::path::PathBuf::from);
    let audit = audit::init(cfg.audit_log, audit_log_path, cfg.audit_log_hmac_key.clone(), base_dir.clone());
    audit.send(audit::AuditEvent::Startup);

    // ── ACME: auto-provision TLS cert if needed ────────────────────────────
    if let Some(ref email) = cfg.acme_email {
        if cfg.acme_domains.is_empty() {
            tracing::warn!("acme-email set but no acme-domain directives — ACME disabled");
        } else {
            let cert_path = cfg.tls.cert_path.as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| base_dir.join("cert.pem"));
            let key_path = cfg.tls.key_path.as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| base_dir.join("key.pem"));
            let cache_dir = cfg.acme_cache_dir.as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| base_dir.join("acme"));
            let acme_cfg = acme::AcmeConfig {
                email:          email.clone(),
                domains:        cfg.acme_domains.clone(),
                cert_path:      cert_path.clone(),
                key_path:       key_path.clone(),
                cache_dir,
                staging:        cfg.acme_staging,
                challenge_port: cfg.acme_challenge_port.unwrap_or(80),
            };
            if acme::needs_renewal(&cert_path) {
                info!("ACME: cert missing or due for renewal — contacting Let's Encrypt");
                if let Err(e) = acme::ensure_certificate(&acme_cfg).await {
                    tracing::warn!(err = %e, "ACME cert provisioning failed — continuing");
                }
            } else {
                info!("ACME: cert is current (>30 days remaining)");
            }
            tokio::spawn(acme::renewal_loop(acme_cfg));
        }
    }

    // ── Build in-memory zone set ───────────────────────────────────────────
    // ArcSwap: reads are a single atomic pointer load — zero lock contention
    // on the hot DNS query path regardless of core count.
    let zones   = Arc::new(ArcSwap::new(Arc::new(build_zone_set(cfg))));
    let tls_cfg = Arc::new(cfg.tls.clone());

    // ── SIGHUP: hot-reload zones from config without dropping connections ──
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let zones_hup    = Arc::clone(&zones);
        let cfg_path_hup = cfg_path.clone();
        tokio::spawn(async move {
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => { tracing::warn!("Cannot install SIGHUP handler: {e}"); return; }
            };
            loop {
                hup.recv().await;
                info!("SIGHUP — reloading zones from config");
                match config::load(&cfg_path_hup) {
                    Ok(new_cfg) => {
                        let new_zones = build_zone_set(&new_cfg);
                        zones_hup.store(Arc::new(new_zones));
                        info!(
                            local_zones = new_cfg.local_zones.len(),
                            local_data  = new_cfg.local_data.len(),
                            "Hot-reload complete"
                        );
                    }
                    Err(e) => tracing::warn!("SIGHUP reload failed (keeping current zones): {e}"),
                }
            }
        });
    }

    // ── Background: feed auto-update ───────────────────────────────────────
    tokio::spawn(async move { feeds::feed_update_loop(86400).await });

    // ── REST API (localhost only, port from api-port directive, default 8081) ──
    let api_port = cfg.api_port.unwrap_or(8081);
    let api_key  = init_api_key(cfg.api_key.clone());
    info!(
        addr = %format!("{API_BIND}:{api_port}"),
        "REST API key: {}...{}",
        &api_key[..8], &api_key[api_key.len()-4..]
    );
    let key_path = runtime::base_dir().join("api.key");
    info!(path = %key_path.display(), "Full API key stored (chmod 600)");
    if let Ok(()) = std::fs::create_dir_all(runtime::base_dir()) {
        let _ = std::fs::write(&key_path, &api_key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
    }

    let global_stats = Stats::new();
    tokio::spawn(stats::qps_update_loop(Arc::clone(&global_stats)));
    let log_buffer = logbuffer::new_shared(cfg.log_retention, cfg.log_client_ip);

    // ── Upstream health monitor ────────────────────────────────────────────
    let upstreams = upstreams::init_upstreams(cfg);
    {
        let ups = Arc::clone(&upstreams);
        tokio::spawn(async move { upstreams::upstream_health_loop(ups).await });
    }

    let cfg_arc = Arc::new(cfg.clone());

    // ── Slave/master sync ──────────────────────────────────────────────────
    let sync_journal = if let (true, Some(port)) = (cfg.is_master(), cfg.sync_port) {
        let journal = sync::SyncJournal::new();
        match sync::ensure_sync_cert() {
            Ok((cert_pem, key_pem)) => {
                match sync::cert_sha256_hex(&cert_pem) {
                    Ok(fingerprint) => {
                        info!(port, sha256 = %fingerprint, "Sync HTTPS server starting");
                        let j        = Arc::clone(&journal);
                        let cert_fp  = fingerprint.clone();
                        let sync_key = cfg.sync_key.clone()
                            .unwrap_or_else(|| {
                                let k = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
                                info!("No sync-key in config — generated: {}...{}", &k[..8], &k[k.len()-4..]);
                                info!("Add  sync-key: {k}  to both master and slave configs.");
                                k
                            });
                        tokio::spawn(async move {
                            if let Err(e) = sync::start_master_sync_server(
                                port, j, sync_key, cert_fp, cert_pem, key_pem,
                            ).await {
                                error!("Sync server exited: {e}");
                            }
                        });
                        Some(journal)
                    }
                    Err(e) => { tracing::warn!("Sync cert fingerprint error: {e}"); None }
                }
            }
            Err(e) => { tracing::warn!("Sync cert error: {e}"); None }
        }
    } else {
        None
    };

    // Hoisted so both SlaveClient and AppState share the same mutex instance.
    let zones_mutex = Arc::new(tokio::sync::Mutex::new(()));

    if cfg.is_slave() {
        match (&cfg.sync_master, &cfg.sync_key) {
            (Some(master), Some(key)) => {
                let client = sync::SlaveClient::new(
                    master, key, cfg.sync_interval,
                    Arc::clone(&zones),
                    Arc::clone(&zones_mutex),
                    Arc::clone(&cfg_arc),
                );
                tokio::spawn(async move { client.run().await });
                info!("Slave sync started → master {master}");
            }
            _ => tracing::warn!("Slave mode enabled but sync-master or sync-key not set — sync disabled"),
        }
    }

    let state = AppState {
        zones:        Arc::clone(&zones),
        tls_cfg:      Arc::clone(&tls_cfg),
        rate_limiter: api::ApiRateLimiter::new_public(),
        zones_mutex:  Arc::clone(&zones_mutex),
        stats:        Arc::clone(&global_stats),
        cfg:          Arc::clone(&cfg_arc),
        cfg_path,
        log_buffer:   Arc::clone(&log_buffer),
        upstreams:    Arc::clone(&upstreams),
        sync_journal,
        slave_mode:   cfg.is_slave(),
        base_dir:     Arc::new(base_dir),
        audit:        audit.clone(),
    };
    let app      = api::router(state);
    let api_addr = format!("{API_BIND}:{api_port}");
    let listener = tokio::net::TcpListener::bind(&api_addr).await
        .map_err(|e| anyhow::anyhow!("API bind {api_addr}: {e}"))?;
    info!(addr=%api_addr, "REST API listening (localhost only)");
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });

    // ── Shared rate limiter and ACL (XDP fast-path + normal DNS path) ─────
    let rate_limiter = RateLimiter::new(cfg.rate_limit.unwrap_or(200));
    let acl          = Arc::new(Acl::from_config(&cfg.access_control));

    Ok((zones, rate_limiter, acl, global_stats, log_buffer, audit))
}

fn print_help() {
    println!(concat!(
        "runbound ", env!("CARGO_PKG_VERSION"), " — high-performance DNS server (Unbound drop-in)
",
        "
",
        "USAGE:
",
        "    runbound [OPTIONS] [CONFIG]
",
        "
",
        "ARGUMENTS:
",
        "    CONFIG    Path to unbound.conf  [default: /etc/unbound/unbound.conf]
",
        "
",
        "OPTIONS:
",
        "    -h, --help             Print this help message and exit
",
        "    -V, --version          Print version and exit
",
        "        --gen-cert [HOST]  Generate a self-signed TLS certificate for DoT/DoH/DoQ
",
        "                           Writes /etc/runbound/cert.pem and key.pem
",
        "                           HOST defaults to 'runbound.local'
",
        "
",
        "ENVIRONMENT:
",
        "    RUNBOUND_API_KEY    REST API key. Priority: env var > api-key in unbound.conf
",
        "                        > auto-generated (256-bit CSPRNG, saved to api.key)
",
        "    RUST_LOG            Log level filter  [default: info]
",
        "                        Examples: RUST_LOG=debug  RUST_LOG=runbound=trace
",
        "
",
        "CONFIG FILE EXTENSIONS (Runbound-specific, ignored by stock Unbound):
",
        "    rate-limit: 200     DNS queries/second per source IP
",
        "                        Default: 200 (residential). Use 5000+ for shared resolvers.
",
        "    api-key: <secret>   REST API key (overridden by RUNBOUND_API_KEY env var)
",
        "    tls-service-pem: /etc/runbound/cert.pem   TLS certificate for DoT/DoH/DoQ
",
        "    tls-service-key: /etc/runbound/key.pem    TLS private key
",
        "
",
        "TLS QUICK START (DoT / DoH / DoQ):
",
        "    # 1. Generate self-signed certificate
",
        "    runbound --gen-cert dns.example.com
",
        "    # 2. Add to unbound.conf:
",
        "    #    tls-service-pem: /etc/runbound/cert.pem
",
        "    #    tls-service-key: /etc/runbound/key.pem
",
        "    # 3. For production: replace with a Let's Encrypt certificate
",
        "    #    certbot certonly --standalone -d dns.example.com
",
        "    #    tls-service-pem: /etc/letsencrypt/live/dns.example.com/fullchain.pem
",
        "    #    tls-service-key: /etc/letsencrypt/live/dns.example.com/privkey.pem
",
        "
",
        "PORTS:
",
        "    53    DNS/UDP + DNS/TCP      (configured via unbound.conf)
",
        "    853   DoT (RFC 7858)         (requires tls-service-pem + tls-service-key)
",
        "    443   DoH (RFC 8484)         (requires tls-service-pem + tls-service-key)
",
        "    8081  REST API (localhost)   Authorization: Bearer <key>
",
        "
",
        "REST API ENDPOINTS (all require Authorization: Bearer <key>):
",
        "    GET    /help               API documentation (public)
",
        "    GET    /dns                List local DNS entries
",
        "    POST   /dns                Add a DNS entry (A/AAAA/CNAME/TXT/MX/SRV/…)
",
        "    DELETE /dns/:id            Remove a DNS entry
",
        "    GET    /blacklist          List blacklist entries
",
        "    POST   /blacklist          Block a domain (refuse/nxdomain)
",
        "    DELETE /blacklist/:id      Remove a blacklist entry
",
        "    GET    /feeds              List feed subscriptions
",
        "    POST   /feeds              Subscribe to a remote blocklist
",
        "    DELETE /feeds/:id          Remove a feed subscription
",
        "    POST   /feeds/update       Refresh all feeds
",
        "    POST   /feeds/:id/update   Refresh one feed
",
        "    GET    /feeds/presets       List pre-configured blocklists
",
        "    GET    /tls                DoT/DoH/DoQ TLS status
",
        "
",
        "FILES:
",
        "    /etc/unbound/unbound.conf        Default config (Unbound-compatible)
",
        "    /etc/runbound/api.key            REST API key (chmod 600)
",
        "    /etc/runbound/cert.pem           TLS certificate (--gen-cert or Let's Encrypt)
",
        "    /etc/runbound/key.pem            TLS private key (chmod 600)
",
        "    /etc/runbound/dns_entries.json   Persisted DNS entries
",
        "    /etc/runbound/blacklist.json     Persisted blacklist
",
        "    /etc/runbound/feeds.json          Feed subscriptions
",
        "
",
        "MEMORY SAFETY:
",
        "    System memory is checked every 30 s. If usage exceeds 80 %, the DNS
",
        "    resolver cache and rate-limiter buckets are purged automatically to
",
        "    bring usage below 50 %. The server keeps running throughout.
",
        "
",
        "EXAMPLES:
",
        "    runbound                                      # use default config
",
        "    runbound /etc/runbound/unbound.conf           # custom config
",
        "    runbound --gen-cert dns.myserver.com          # generate TLS cert
",
        "    RUST_LOG=debug runbound                       # verbose logging
",
        "    RUNBOUND_API_KEY=mysecret runbound            # fixed API key via env
",
    ));
}

/// Generate a self-signed TLS certificate for DoT / DoH / DoQ.
/// Writes cert.pem and key.pem to /etc/runbound/ (chmod 600 for the key).
fn gen_self_signed_cert(hostname: &str) -> anyhow::Result<()> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let cert_path = "/etc/runbound/cert.pem";
    let key_path  = "/etc/runbound/key.pem";

    println!("Generating self-signed certificate for: {hostname}");

    let subject_alt_names = vec![
        hostname.to_string(),
        // Also include localhost so the cert works for local testing
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(subject_alt_names)
            .map_err(|e| anyhow::anyhow!("cert generation failed: {e}"))?;

    fs::create_dir_all("/etc/runbound")
        .map_err(|e| anyhow::anyhow!("create /etc/runbound: {e}"))?;

    fs::write(cert_path, cert.pem())
        .map_err(|e| anyhow::anyhow!("write {cert_path}: {e}"))?;

    let key_pem = key_pair.serialize_pem();
    fs::write(key_path, &key_pem)
        .map_err(|e| anyhow::anyhow!("write {key_path}: {e}"))?;

    // Protect the private key: readable by owner only
    #[cfg(unix)]
    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow::anyhow!("chmod {key_path}: {e}"))?;

    println!("Certificate : {cert_path}");
    println!("Private key : {key_path}  (chmod 600)");
    println!();
    println!("Add to your unbound.conf server section:");
    println!("    tls-service-pem: {cert_path}");
    println!("    tls-service-key: {key_path}");
    println!();
    println!("WARNING: Self-signed certificate — clients will show a TLS warning.");
    println!("For production use Let's Encrypt:");
    println!("    certbot certonly --standalone -d {hostname}");
    println!("    tls-service-pem: /etc/letsencrypt/live/{hostname}/fullchain.pem");
    println!("    tls-service-key: /etc/letsencrypt/live/{hostname}/privkey.pem");

    Ok(())
}

/// Build the in-memory zone set from config + persisted store + blacklist + feeds.
/// Called at startup, on SIGHUP hot-reload, and by POST /reload.
pub fn build_zone_set(cfg: &UnboundConfig) -> LocalZoneSet {
    let mut zone_set = LocalZoneSet::from_config(&cfg.local_zones, &cfg.local_data);

    // Persisted DNS entries (from REST API POST /dns)
    if let Ok(st) = store::load() {
        for entry in &st.entries {
            if let Some(rr) = entry.to_rr_string() {
                if let Some(record) = dns::local::parse_local_data(&rr) {
                    let name = record.name.clone();
                    zone_set.zones.entry(name.clone()).or_insert(dns::ZoneAction::Static);
                    zone_set.records.entry(name).or_default().push(record);
                }
            }
        }
        if !st.entries.is_empty() {
            tracing::info!(count = st.entries.len(), "Loaded persisted DNS entries");
        }
    }

    // Persisted blacklist (override_zone so blacklist always shadows static zones)
    if let Ok(bl) = store::load_blacklist() {
        for entry in &bl.entries {
            zone_set.override_zone(&entry.domain, dns::ZoneAction::from(&entry.action));
        }
        if !bl.entries.is_empty() {
            tracing::info!(count = bl.entries.len(), "Loaded persisted blacklist entries");
        }
    }

    // Feed block-list entries (also override static zones)
    for (domain, action) in feeds::collect_feed_entries() {
        zone_set.override_zone(&domain, dns::ZoneAction::from(&action));
    }

    zone_set
}
