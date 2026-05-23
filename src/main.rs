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
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
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
    let (zones, rate_limiter, acl, global_stats, log_buffer, audit, xdp_mode, resolver, prefetch_tracker, upstreams, per_upstream_resolvers, racing_wins) =
        build_and_launch(&cfg, base_dir, cfg_path).await?;

    // #60: XDP cache snapshot — create only when XDP is enabled and configured.
    let mut xdp_cache_snapshot: Option<dns::cache_snapshot::SharedCacheSnapshot> = None;
    let mut xdp_cache_mutable:  Option<dns::cache_snapshot::MutableCacheMap>     = None;
    #[cfg(feature = "xdp")]
    if cfg.xdp && cfg.xdp_cache_snapshot {
        let mutable  = Arc::new(dashmap::DashMap::new());
        let snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(dns::cache_snapshot::CacheSnapshot::default())));
        tokio::spawn(dns::cache_snapshot::publish_loop(Arc::clone(&snapshot), Arc::clone(&mutable)));
        xdp_cache_snapshot = Some(snapshot);
        xdp_cache_mutable  = Some(mutable);
    }

    // #29: load XDP cache from disk on startup.
    #[cfg(feature = "xdp")]
    if let Some(ref cache) = xdp_cache_mutable {
        let cache_file = runtime::base_dir().join("xdp_cache.rkyv");
        let loaded = dns::cache_snapshot::load_xdp_cache(cache, &cache_file, cfg.xdp_cache_snapshot_size);
        if loaded > 0 {
            info!(entries = loaded, path = %cache_file.display(), "XDP cache loaded from disk");
        }
    }

    // #29: SIGUSR2 — save XDP cache to disk.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let cache_for_usr2 = xdp_cache_mutable.clone();
        tokio::spawn(async move {
            let mut usr2 = match signal(SignalKind::user_defined2()) {
                Ok(s) => s,
                Err(e) => { tracing::warn!("Cannot install SIGUSR2 handler: {e}"); return; }
            };
            let cache_file = runtime::base_dir().join("xdp_cache.rkyv");
            loop {
                usr2.recv().await;
                match &cache_for_usr2 {
                    Some(cache) => match dns::cache_snapshot::save_xdp_cache(cache, &cache_file) {
                        Ok(n)  => info!(entries = n, path = %cache_file.display(), "SIGUSR2 — XDP cache saved"),
                        Err(e) => tracing::warn!(err = %e, "SIGUSR2 — XDP cache save failed"),
                    },
                    None => tracing::debug!("SIGUSR2 — XDP cache not active, nothing to save"),
                }
            }
        });
    }

    // ── XDP fast path (optional, feature-gated) ───────────────────────────
    // The handle must stay alive for the entire process lifetime; dropping it
    // would detach the XDP program and destroy the XSKMAP.
    #[cfg(feature = "xdp")]
    let _xdp_handle = if !cfg.xdp {
        info!("XDP fast path disabled (xdp: no / --no-xdp)");
        None
    } else if cfg.xdp_interface.as_deref() == Some("none") {
        // #79: xdp-interface: none disables XDP without touching the xdp: directive.
        info!("XDP fast path disabled (xdp-interface: none)");
        None
    } else {
        // #79: explicit interface wins; otherwise auto-detect from listen address / default route.
        let iface = if let Some(ref explicit) = cfg.xdp_interface {
            info!(iface = %explicit, "XDP interface: explicit config (xdp-interface)");
            Some(explicit.clone())
        } else {
            let detected = cfg.interfaces.first()
                .and_then(|s| {
                    let s = s.trim();
                    if s == "0.0.0.0" || s == "::" || s.is_empty() { return None; }
                    if s.parse::<std::net::IpAddr>().is_ok() {
                        return dns::xdp::socket::iface_for_ip(s);
                    }
                    Some(s.to_string())
                })
                .or_else(dns::xdp::socket::default_interface);
            if let Some(ref name) = detected {
                info!(iface = %name, "XDP auto-selected interface (use xdp-interface: to override)");
            }
            detected
        };
        match iface {
            Some(ref iface_name) => {
                match dns::xdp::start_xdp(iface_name, Arc::clone(&zones), Arc::clone(&rate_limiter), Arc::clone(&acl), cfg.xdp_cpu_governor, cfg.xdp_irq_affinity, cfg.xdp_hugepages, xdp_cache_snapshot.clone(), cfg.xdp_domain_routing, cfg.xdp_ring_size) {
                    Ok(Some(h)) => { info!(iface = %iface_name, "XDP kernel-bypass fast path active"); xdp_mode.store(match h.mode { dns::xdp::XdpMode::Drv => 1, dns::xdp::XdpMode::Skb => 2 }, Ordering::Relaxed); Some(h) }
                    Ok(None)    => None, // virtual interface or self-test — already warned
                    Err(e) => {
                        let reason = if e.contains("BPF_PROG_LOAD") {
                            "eBPF program rejected by kernel verifier"
                        } else if e.contains("Operation not permitted") || e.contains("EPERM") {
                            "missing CAP_NET_ADMIN/CAP_BPF (add to systemd service)"
                        } else if e.contains("AF_XDP") {
                            "AF_XDP not allowed (add AF_XDP to RestrictAddressFamilies in service)"
                        } else {
                            "NIC or kernel does not support AF_XDP"
                        };
                        tracing::warn!("XDP disabled: {} — error: {}", reason, e);
                        None
                    }
                }
            }
            None => { tracing::warn!("XDP: could not determine network interface; fast path disabled"); None }
        }
    };

    let result = dns::run_dns_server(&cfg, zones, rate_limiter, acl, global_stats, log_buffer, resolver, prefetch_tracker, xdp_cache_mutable, cfg.xdp_cache_snapshot_size, upstreams, per_upstream_resolvers, racing_wins).await;
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
    // --check-config [path] — validate config and systemd security parameters, then exit
    if let Some(pos) = args.iter().position(|a| a == "--check-config") {
        let path = args.get(pos + 1).map(|s| s.as_str())
            .unwrap_or("/etc/unbound/unbound.conf");
        let code = run_check_config(path);
        std::process::exit(code);
    }
    Ok(false)
}

fn verbosity_to_filter(v: u8) -> &'static str {
    match v {
        0 => "error",
        1 => "error,runbound=warn",
        2 => "warn,runbound=info",
        _ => "debug",
    }
}

/// Install rustls crypto provider, load config, init tracing, validate config, init HSM.
///
/// Tracing is initialized AFTER config load so `verbosity:` takes effect.
/// Priority: RUST_LOG env var > verbosity: directive > default WARN.
fn init_runtime(args: &[String]) -> Result<(UnboundConfig, std::path::PathBuf, String)> {
    // rustls 0.23: when multiple crypto backends are compiled in (ring + aws-lc-rs),
    // ServerConfig::builder() panics unless a default provider is installed first.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok() = no-op if already installed

    let cfg_path = args.iter().skip(1)
        .find(|a| !a.starts_with('-'))
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

    // Load config before tracing so verbosity: takes effect.
    // Unknown-directive warnings from the parser are silently dropped here;
    // they will reappear on reload if the operator adds an unknown key.
    let mut unbound_cfg = config::load(&cfg_path)?;

    // Init tracing: RUST_LOG env var > verbosity: directive > WARN.
    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_env("RUST_LOG"))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                verbosity_to_filter(unbound_cfg.verbosity)
            ))
            .init();
    }

    runtime::BASE_DIR.set(base_dir.clone())
        .unwrap_or_else(|_| panic!("BASE_DIR set twice — this is a bug"));
    info!(base_dir = %base_dir.display(), "Runtime base_dir");

    info!(
        path = %cfg_path,
        verbosity = unbound_cfg.verbosity,
        "Config loaded"
    );

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
        "Server config"
    );

    if args.iter().any(|a| a == "--no-xdp") {
        unbound_cfg.xdp = false;
    }

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
    Arc<AtomicU8>,
    dns::server::SharedResolver,
    Option<Arc<dns::prefetch::PrefetchTracker>>,
    upstreams::SharedUpstreams,
    dns::server::SharedResolversVec,
    Arc<dashmap::DashMap<String, Arc<std::sync::atomic::AtomicU64>, ahash::RandomState>>,
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
    let api_port = cfg.api_port.unwrap_or(8080);
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

    let global_stats   = Stats::new();
    let snapshot_cache = stats::new_snapshot_cache(&global_stats);
    tokio::spawn(stats::qps_update_loop(Arc::clone(&global_stats), Arc::clone(&snapshot_cache)));
    let log_buffer = logbuffer::new_shared(cfg.log_retention, cfg.log_client_ip);

    // ── SIGUSR1: stats dump (SIGUSR2 is wired in async_main after cache init) ──
    // The default OS action for SIGUSR1/SIGUSR2 is to terminate the process.
    // A production DNS server must never die from a monitoring tool or logrotate
    // script sending these signals.  SIGUSR1 dumps a live stats snapshot to the
    // log; SIGUSR2 triggers XDP cache persistence (#29).
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let stats_usr1 = Arc::clone(&global_stats);
        tokio::spawn(async move {
            let mut usr1 = match signal(SignalKind::user_defined1()) {
                Ok(s) => s,
                Err(e) => { tracing::warn!("Cannot install SIGUSR1 handler: {e}"); return; }
            };
            loop {
                usr1.recv().await;
                let snap = stats_usr1.snapshot();
                info!(
                    total     = snap.total,
                    forwarded = snap.forwarded,
                    blocked   = snap.blocked,
                    servfail  = snap.servfail,
                    uptime_s  = snap.uptime_secs,
                    qps_1m    = snap.qps_1m,
                    hit_rate  = snap.cache_hit_rate,
                    "SIGUSR1 — live stats dump"
                );
            }
        });
    }

    // ── Upstream health monitor ────────────────────────────────────────────
    let upstreams = upstreams::init_upstreams(cfg);
    // FIX #43: merge any upstreams persisted via the API (API entry wins on duplicate)
    {
        let saved = upstreams::load_upstreams(&base_dir);
        upstreams::merge_persisted(&upstreams, saved);
    }
    {
        let ups = Arc::clone(&upstreams);
        tokio::spawn(async move { upstreams::upstream_health_loop(ups).await });
    }

    let cfg_arc = Arc::new(cfg.clone());

    // ── Shared DNS resolver (hot-swappable via ArcSwap) ───────────────────
    let resolver = dns::server::create_shared_resolver(cfg)
        .map_err(|e| anyhow::anyhow!("DNS resolver init: {e}"))?;

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

    let xdp_mode = Arc::new(AtomicU8::new(0)); // 0=disabled, 1=drv, 2=skb

    // ── DNS prefetch tracker (FEAT #16, opt-in via prefetch: yes) ─────────
    let prefetch_tracker: Option<Arc<dns::prefetch::PrefetchTracker>> = if cfg.prefetch {
        let tracker = dns::prefetch::PrefetchTracker::new();
        let t = Arc::clone(&tracker);
        let res = Arc::clone(&resolver);
        let threshold = cfg.prefetch_threshold;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let hot = t.take_hot(threshold);
                if hot.is_empty() { continue; }
                tracing::debug!(count = hot.len(), "prefetch: queuing {} domain(s)", hot.len());
                for name in hot {
                    let r = Arc::clone(&res);
                    tokio::spawn(async move {
                        use hickory_proto::rr::RecordType;
                        use hickory_proto::rr::Name;
                        if let Ok(n) = name.parse::<Name>() {
                            let _ = r.load().lookup(n, RecordType::A).await;
                        }
                    });
                }
            }
        });
        Some(tracker)
    } else {
        None
    };

    // #33: per-upstream resolvers for racing mode.
    let per_upstream_resolvers = dns::server::create_shared_resolvers_vec();
    if cfg.upstream_racing {
        let addrs = upstreams::upstream_addrs(&upstreams);
        match dns::server::build_per_upstream_resolvers(&addrs, cfg.dnssec_validation) {
            Ok(vec) => {
                info!(count = vec.len(), "upstream-racing: per-upstream resolvers built");
                per_upstream_resolvers.store(Arc::new(vec));
            }
            Err(e) => tracing::warn!(err = %e, "upstream-racing: failed to build per-upstream resolvers — racing disabled"),
        }
    }
    let racing_wins: Arc<dashmap::DashMap<String, Arc<std::sync::atomic::AtomicU64>, ahash::RandomState>> =
        Arc::new(dashmap::DashMap::with_hasher(ahash::RandomState::new()));

    let state = AppState {
        zones:            Arc::clone(&zones),
        tls_cfg:          Arc::clone(&tls_cfg),
        rate_limiter:     api::ApiRateLimiter::new_public(),
        reload_limiter:   Arc::new(api::ReloadLimiter::new()),
        zones_mutex:      Arc::clone(&zones_mutex),
        stats:            Arc::clone(&global_stats),
        stats_cache:      Arc::clone(&snapshot_cache),
        cfg:              Arc::clone(&cfg_arc),
        cfg_path,
        log_buffer:       Arc::clone(&log_buffer),
        upstreams:        Arc::clone(&upstreams),
        sync_journal,
        slave_mode:       cfg.is_slave(),
        base_dir:         Arc::new(base_dir),
        audit:            audit.clone(),
        xdp_active:       Arc::clone(&xdp_mode),
        resolver:         Arc::clone(&resolver),
        last_flush_at:    Arc::new(std::sync::Mutex::new(None)),
        cache_evictions:  Arc::new(std::sync::atomic::AtomicU64::new(0)),
        lookup_limiter:   Arc::new(api::ReloadLimiter::new_with_params(10.0, 10.0)),
        per_upstream_resolvers: Arc::clone(&per_upstream_resolvers),
        racing_wins:            Arc::clone(&racing_wins),
    };
    let app      = api::router(state);
    let api_addr = format!("{API_BIND}:{api_port}");
    // Bind with std so the fd is runtime-agnostic; convert inside the API runtime.
    let std_listener = std::net::TcpListener::bind(&api_addr)
        .map_err(|e| anyhow::anyhow!("API bind {api_addr}: {e}"))?;
    std_listener.set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("API set_nonblocking: {e}"))?;
    info!(addr=%api_addr, "REST API listening (localhost only)");

    // Dedicated 2-thread runtime isolated from the DNS runtime.
    // Under DoT rebuild storms the DNS runtime can be flooded with hundreds of
    // tasks/second, which starves axum task slots and freezes the API entirely.
    // A separate runtime gives the HTTP server its own scheduler queue.
    // Box::leak is intentional: the runtime must stay alive for the whole process.
    let api_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("runbound-api")
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("API runtime: {e}"))?;
    api_rt.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("TcpListener::from_std failed");
        axum::serve(listener, app).await.ok()
    });
    Box::leak(Box::new(api_rt));

    // ── Shared rate limiter and ACL (XDP fast-path + normal DNS path) ─────
    let rate_limiter = RateLimiter::new(cfg.rate_limit.unwrap_or(200));
    let acl          = Arc::new(Acl::from_config(&cfg.access_control));

    Ok((zones, rate_limiter, acl, global_stats, log_buffer, audit, xdp_mode, resolver, prefetch_tracker, upstreams, per_upstream_resolvers, racing_wins))
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
        "    -h, --help                   Print this help message and exit
",
        "    -V, --version                Print version and exit
",
        "        --gen-cert [HOST]        Generate a self-signed TLS certificate for DoT/DoH/DoQ
",
        "                                 Writes /etc/runbound/cert.pem and key.pem
",
        "                                 HOST defaults to 'runbound.local'
",
        "        --check-config [CONFIG]  Validate config + systemd security parameters
",
        "                                 Checks: parse, rate-limit, data dir, port 53,
",
        "                                 capabilities (CAP_NET_RAW/ADMIN/BPF), RLIMIT_MEMLOCK
",
        "                                 Exit codes: 0=clean  1=error  2=warnings only
",
        "        --no-xdp                 Disable AF/XDP kernel-bypass fast path at runtime
",
        "                                 Equivalent to 'xdp: no' in unbound.conf
",
        "                                 Useful for troubleshooting or environments without
",
        "                                 CAP_NET_ADMIN/CAP_BPF/AF_XDP (containers, VMs)
",
        "
",
        "ENVIRONMENT:
",
        "    RUNBOUND_API_KEY    REST API key. Priority: env var > api-key in unbound.conf
",
        "                        > auto-generated (256-bit CSPRNG, saved to api.key)
",
        "    RUST_LOG            Log level filter. Overrides verbosity: in unbound.conf.
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
        "    xdp: no             Disable AF/XDP kernel-bypass fast path (default: yes)
",
        "                        Equivalent to --no-xdp on the command line
",
        "    xdp-interface: eth1 Explicit NIC for XDP (default: auto-detected)
",
        "                        Use in dual-NIC setups to pin XDP to the DNS-facing NIC.
",
        "                        Set to 'none' to disable XDP without changing xdp: directive.
",
        "    cpu-affinity: no    Disable CPU pinning (default: yes)
",
        "                        Use in containers that lack CAP_SYS_NICE
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
        "    runbound                                           # use default config
",
        "    runbound /etc/runbound/unbound.conf                # custom config
",
        "    runbound --gen-cert dns.myserver.com               # generate TLS cert
",
        "    runbound --check-config /etc/runbound/unbound.conf # validate before start
",
        "    RUST_LOG=debug runbound                            # verbose logging
",
        "    RUNBOUND_API_KEY=mysecret runbound                 # fixed API key via env
",
    ));
}

// ── --check-config implementation ─────────────────────────────────────────

/// Validate config + systemd security parameters without starting the server.
/// Returns 0 (clean), 1 (critical error), 2 (warnings only).
fn run_check_config(path: &str) -> i32 {
    rustls::crypto::ring::default_provider().install_default().ok();

    let mut warnings = 0u32;
    let mut errors   = 0u32;

    // ── 1. Config parse ────────────────────────────────────────────────────
    let cfg = match config::load(path) {
        Ok(c) => {
            println!("[OK]   Config parsed: port={} interfaces={:?}", c.port, c.interfaces);
            c
        }
        Err(e) => {
            println!("[ERR]  Config parse failed: {e}");
            return 1;
        }
    };

    // ── 2. verbosity ───────────────────────────────────────────────────────
    {
        let level_name = match cfg.verbosity {
            0 => "error",
            1 => "warn",
            2 => "info",
            _ => "debug",
        };
        println!("[OK]   verbosity: {} ({})", cfg.verbosity, level_name);
        if cfg.verbosity > 1 && cfg.port == 53
            && cfg.rate_limit.map(|r| r > 0).unwrap_or(true)
        {
            println!(
                "[WARN] verbosity: {} ({}) logs every query — expect significant CPU \
                 overhead above 10k QPS. Use verbosity: 1 for production.",
                cfg.verbosity, level_name
            );
            warnings += 1;
        }
    }

    // ── 3. rate-limit ──────────────────────────────────────────────────────
    match cfg.rate_limit {
        None | Some(0) => println!("[OK]   Rate limit: disabled (unlimited)"),
        Some(n)        => println!("[OK]   Rate limit: {n} QPS per source IP"),
    }

    // ── 4. Data directory writable ─────────────────────────────────────────
    let base_dir = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let probe = base_dir.join(".runbound_check_write");
    match std::fs::write(&probe, b"") {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            println!("[OK]   Data directory writable: {}", base_dir.display());
        }
        Err(e) => {
            println!("[ERR]  Data directory not writable: {} — {e}", base_dir.display());
            errors += 1;
        }
    }

    // ── 5. Port availability ───────────────────────────────────────────────
    check_cfg_port(cfg.port, &mut errors);

    // ── 6. Capabilities (Linux only) ───────────────────────────────────────
    #[cfg(target_os = "linux")]
    check_cfg_capabilities(&mut warnings);

    // ── 7. RLIMIT_MEMLOCK (Linux only) ─────────────────────────────────────
    #[cfg(target_os = "linux")]
    check_cfg_rlimit_memlock(&mut warnings);

    // ── 8. XDP interface type (Linux only) ─────────────────────────────────
    #[cfg(target_os = "linux")]
    check_cfg_xdp_interface(&cfg, &mut warnings);

    // ── Summary ────────────────────────────────────────────────────────────
    if errors > 0 {
        println!("Config check failed ({errors} error(s), {warnings} warning(s))");
        1
    } else if warnings > 0 {
        println!("Config check passed ({warnings} warning(s))");
        2
    } else {
        println!("Config check passed");
        0
    }
}

fn check_cfg_port(port: u16, errors: &mut u32) {
    use std::net::UdpSocket;
    match UdpSocket::bind(format!("0.0.0.0:{port}")) {
        Ok(_)  => println!("[OK]   Port {port} available"),
        Err(e) => {
            println!("[ERR]  Port {port} already in use — {e}");
            *errors += 1;
        }
    }
}

#[cfg(target_os = "linux")]
fn check_cfg_capabilities(warnings: &mut u32) {
    // CAP_NET_RAW=13  CAP_NET_ADMIN=12  CAP_BPF=39
    // Read effective capability mask from /proc/self/status CapEff field.
    const CAP_NET_ADMIN: u64 = 1 << 12;
    const CAP_NET_RAW:   u64 = 1 << 13;
    const CAP_BPF:       u64 = 1 << 39;

    let cap_eff: Option<u64> = std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("CapEff:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| u64::from_str_radix(v, 16).ok())
        });

    let Some(cap) = cap_eff else {
        println!("[WARN] Could not read /proc/self/status — capability check skipped");
        *warnings += 1;
        return;
    };

    for (name, bit) in [
        ("CAP_NET_ADMIN", CAP_NET_ADMIN),
        ("CAP_NET_RAW",   CAP_NET_RAW),
        ("CAP_BPF",       CAP_BPF),
    ] {
        if cap & bit == 0 {
            println!("[WARN] {name} not available — XDP will be disabled");
            println!("       Fix: sudo setcap cap_net_raw,cap_net_admin,cap_bpf+eip $(which runbound)");
            println!("       Or add AmbientCapabilities={name} to the systemd service");
            *warnings += 1;
        } else {
            println!("[OK]   {name} present");
        }
    }
}

#[cfg(target_os = "linux")]
fn check_cfg_rlimit_memlock(warnings: &mut u32) {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl); }
    if rl.rlim_cur == libc::RLIM_INFINITY {
        println!("[OK]   RLIMIT_MEMLOCK: unlimited");
        return;
    }
    let under_systemd = std::env::var("INVOCATION_ID").is_ok()
        || std::fs::read_to_string("/proc/1/comm")
            .map(|s| s.trim().contains("systemd"))
            .unwrap_or(false);
    let mb = rl.rlim_cur / (1024 * 1024);
    if under_systemd {
        println!("[WARN] RLIMIT_MEMLOCK is limited ({}MB) — XDP UMEM allocation will fail", mb);
        println!("       Fix: add LimitMEMLOCK=infinity to the systemd service file");
        *warnings += 1;
    } else {
        println!("[INFO] RLIMIT_MEMLOCK = {}MB — running outside systemd.", mb);
        println!("       At runtime LimitMEMLOCK=infinity from the service file will apply.");
        println!("       Run 'runbound --check-config' via systemd-run to test under real");
        println!("       runtime conditions.");
    }
}

#[cfg(target_os = "linux")]
fn check_cfg_xdp_interface(cfg: &config::parser::UnboundConfig, warnings: &mut u32) {
    use dns::xdp::socket::{default_interface, iface_for_ip, is_virtual_interface};
    if !cfg.xdp {
        println!("[OK]   XDP disabled in config — interface check skipped");
        return;
    }
    if cfg.xdp_interface.as_deref() == Some("none") {
        println!("[OK]   XDP disabled via xdp-interface: none");
        return;
    }
    let iface = if let Some(ref explicit) = cfg.xdp_interface {
        Some(explicit.clone())
    } else {
        cfg.interfaces.first()
            .and_then(|s| {
                let s = s.trim();
                if s == "0.0.0.0" || s == "::" || s.is_empty() { return None; }
                if s.parse::<std::net::IpAddr>().is_ok() { return iface_for_ip(s); }
                Some(s.to_string())
            })
            .or_else(default_interface)
    };
    let iface_name = match iface {
        Some(ref i) => i.as_str(),
        None => {
            println!("[WARN] Could not determine network interface — XDP interface check skipped");
            *warnings += 1;
            return;
        }
    };
    if is_virtual_interface(iface_name) {
        println!("[WARN] '{}' is a virtual interface (ipvlan / macvlan / bridge / veth) \
                  — AF/XDP requires a physical NIC or a direct VLAN sub-interface \
                  (e.g. bond0.10).", iface_name);
        println!("       XDP will be disabled at runtime; DNS will fall back to UDP.");
        println!("       Suggestion: bind Runbound directly to the physical interface");
        println!("       or VLAN sub-interface instead.");
        *warnings += 1;
    } else {
        println!("[OK]   Interface '{}' is physical — XDP compatible", iface_name);
    }
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
