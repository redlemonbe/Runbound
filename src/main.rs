mod config;
mod dns;
mod api;
mod feeds;
mod error;
mod logbuffer;
mod store;
mod stats;
mod sync;
mod upstreams;

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;
use anyhow::Result;
use arc_swap::ArcSwap;
use tracing::{error, info};

use config::parser::UnboundConfig;
use dns::local::LocalZoneSet;
use dns::{Acl, RateLimiter};
use api::{AppState, init_api_key};
use stats::Stats;

const API_BIND: &str = "127.0.0.1"; // API must not be exposed externally

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("runbound {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    // --gen-cert [hostname] — generate a self-signed TLS certificate for DoT/DoH/DoQ
    if let Some(pos) = args.iter().position(|a| a == "--gen-cert") {
        let hostname = args.get(pos + 1)
            .map(|s| s.as_str())
            .unwrap_or("runbound.local");
        gen_self_signed_cert(hostname)?;
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cfg_path = args.get(1)
        .cloned()
        .unwrap_or_else(|| "/etc/unbound/unbound.conf".to_string());

    info!(path = %cfg_path, "Loading config");
    let unbound_cfg = config::load(&cfg_path)?;

    info!(
        port = unbound_cfg.port,
        interfaces = ?unbound_cfg.interfaces,
        local_zones = unbound_cfg.local_zones.len(),
        local_data  = unbound_cfg.local_data.len(),
        forward_zones = unbound_cfg.forward_zones.len(),
        "Config loaded"
    );

    // ── Build in-memory zone set ───────────────────────────────────────────
    let zone_set = build_zone_set(&unbound_cfg);

    // ArcSwap: reads are a single atomic pointer load — zero lock contention
    // on the hot DNS query path regardless of core count.
    let zones   = Arc::new(ArcSwap::new(Arc::new(zone_set)));
    let tls_cfg = Arc::new(unbound_cfg.tls.clone());

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
    tokio::spawn(async move {
        feeds::feed_update_loop(86400).await;
    });

    // ── REST API (localhost only, port from api-port directive, default 8081) ──
    let api_port = unbound_cfg.api_port.unwrap_or(8081);
    let api_key = init_api_key(unbound_cfg.api_key.clone());
    info!(
        addr = %format!("{API_BIND}:{api_port}"),
        "REST API key: {}...{}",
        &api_key[..8], &api_key[api_key.len()-4..]
    );
    info!("Full API key stored in /etc/runbound/api.key (chmod 600)");
    // Write key to file for operators
    let key_path = "/etc/runbound/api.key";
    if let Ok(()) = std::fs::create_dir_all("/etc/runbound") {
        let _ = std::fs::write(key_path, &api_key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        }
    }

    let global_stats = Stats::new();

    // ── QPS ring buffer background task ───────────────────────────────────
    tokio::spawn(stats::qps_update_loop(Arc::clone(&global_stats)));

    // ── Log ring buffer (pre-allocated, zero alloc after startup) ─────────
    let log_buffer = logbuffer::new_shared();

    // ── Upstream health monitor ────────────────────────────────────────────
    let upstreams = upstreams::init_upstreams(&unbound_cfg);
    {
        let ups = Arc::clone(&upstreams);
        tokio::spawn(async move { upstreams::upstream_health_loop(ups).await });
    }

    let cfg_arc = Arc::new(unbound_cfg.clone());

    // ── Slave/master sync ──────────────────────────────────────────────────
    let sync_journal = if unbound_cfg.is_master() && unbound_cfg.sync_port.is_some() {
        let journal = sync::SyncJournal::new();
        let port = unbound_cfg.sync_port.unwrap();

        match sync::ensure_sync_cert() {
            Ok((cert_pem, key_pem)) => {
                match sync::cert_sha256_hex(&cert_pem) {
                    Ok(fingerprint) => {
                        info!(port, sha256 = %fingerprint, "Sync HTTPS server starting");
                        let j        = Arc::clone(&journal);
                        let cert_fp  = fingerprint.clone();
                        let sync_key = unbound_cfg.sync_key.clone()
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

    if unbound_cfg.is_slave() {
        match (&unbound_cfg.sync_master, &unbound_cfg.sync_key) {
            (Some(master), Some(key)) => {
                let client = sync::SlaveClient::new(master, key, unbound_cfg.sync_interval);
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
        zones_mutex:  Arc::new(tokio::sync::Mutex::new(())),
        stats:        Arc::clone(&global_stats),
        cfg:          Arc::clone(&cfg_arc),
        cfg_path:     cfg_path.clone(),
        log_buffer:   Arc::clone(&log_buffer),
        upstreams:    Arc::clone(&upstreams),
        sync_journal,
        slave_mode:   unbound_cfg.is_slave(),
    };
    let app = api::router(state);
    let api_addr = format!("{API_BIND}:{api_port}");
    let listener = tokio::net::TcpListener::bind(&api_addr).await
        .map_err(|e| anyhow::anyhow!("API bind {api_addr}: {e}"))?;
    info!(addr=%api_addr, "REST API listening (localhost only)");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // ── Shared rate limiter (XDP fast-path + normal DNS path share one budget)
    let rps          = unbound_cfg.rate_limit.unwrap_or(200);
    let rate_limiter = RateLimiter::new(rps);

    // ── Shared ACL (XDP fast-path + normal DNS path enforce the same rules)
    let acl = Arc::new(Acl::from_config(&unbound_cfg.access_control));

    // ── XDP fast path (optional, feature-gated) ───────────────────────────
    // The handle must stay alive for the entire process lifetime; dropping it
    // would detach the XDP program and destroy the XSKMAP.
    #[cfg(feature = "xdp")]
    let _xdp_handle = {
        let iface = unbound_cfg.interfaces.first()
            .and_then(|s| {
                let s = s.trim();
                if s == "0.0.0.0" || s == "::" || s.is_empty() {
                    return None;
                }
                if s.parse::<std::net::IpAddr>().is_ok() {
                    return dns::xdp::socket::iface_for_ip(s);
                }
                Some(s.to_string())
            })
            .or_else(|| dns::xdp::socket::default_interface());

        match iface {
            Some(ref iface_name) => {
                match dns::xdp::start_xdp(iface_name, Arc::clone(&zones), Arc::clone(&rate_limiter), Arc::clone(&acl)) {
                    Ok(h) => {
                        info!(iface = %iface_name, "XDP kernel-bypass fast path active");
                        Some(h)
                    }
                    Err(e) => {
                        tracing::warn!("XDP not available (continuing without): {e}");
                        None
                    }
                }
            }
            None => {
                tracing::warn!("XDP: could not determine network interface; fast path disabled");
                None
            }
        }
    };

    // ── DNS server (blocks until shutdown) ────────────────────────────────
    dns::run_dns_server(&unbound_cfg, zones, rate_limiter, acl, global_stats, log_buffer).await
}

fn print_help() {
    println!(concat!(
        "runbound ", env!("CARGO_PKG_VERSION"), " — high-performance DNS server (Unbound drop-in)\n",
        "\n",
        "USAGE:\n",
        "    runbound [OPTIONS] [CONFIG]\n",
        "\n",
        "ARGUMENTS:\n",
        "    CONFIG    Path to unbound.conf  [default: /etc/unbound/unbound.conf]\n",
        "\n",
        "OPTIONS:\n",
        "    -h, --help             Print this help message and exit\n",
        "    -V, --version          Print version and exit\n",
        "        --gen-cert [HOST]  Generate a self-signed TLS certificate for DoT/DoH/DoQ\n",
        "                           Writes /etc/runbound/cert.pem and key.pem\n",
        "                           HOST defaults to 'runbound.local'\n",
        "\n",
        "ENVIRONMENT:\n",
        "    RUNBOUND_API_KEY    REST API key. Priority: env var > api-key in unbound.conf\n",
        "                        > auto-generated (256-bit CSPRNG, saved to api.key)\n",
        "    RUST_LOG            Log level filter  [default: info]\n",
        "                        Examples: RUST_LOG=debug  RUST_LOG=runbound=trace\n",
        "\n",
        "CONFIG FILE EXTENSIONS (Runbound-specific, ignored by stock Unbound):\n",
        "    rate-limit: 200     DNS queries/second per source IP\n",
        "                        Default: 200 (residential). Use 5000+ for shared resolvers.\n",
        "    api-key: <secret>   REST API key (overridden by RUNBOUND_API_KEY env var)\n",
        "    tls-service-pem: /etc/runbound/cert.pem   TLS certificate for DoT/DoH/DoQ\n",
        "    tls-service-key: /etc/runbound/key.pem    TLS private key\n",
        "\n",
        "TLS QUICK START (DoT / DoH / DoQ):\n",
        "    # 1. Generate self-signed certificate\n",
        "    runbound --gen-cert dns.example.com\n",
        "    # 2. Add to unbound.conf:\n",
        "    #    tls-service-pem: /etc/runbound/cert.pem\n",
        "    #    tls-service-key: /etc/runbound/key.pem\n",
        "    # 3. For production: replace with a Let's Encrypt certificate\n",
        "    #    certbot certonly --standalone -d dns.example.com\n",
        "    #    tls-service-pem: /etc/letsencrypt/live/dns.example.com/fullchain.pem\n",
        "    #    tls-service-key: /etc/letsencrypt/live/dns.example.com/privkey.pem\n",
        "\n",
        "PORTS:\n",
        "    53    DNS/UDP + DNS/TCP      (configured via unbound.conf)\n",
        "    853   DoT (RFC 7858)         (requires tls-service-pem + tls-service-key)\n",
        "    443   DoH (RFC 8484)         (requires tls-service-pem + tls-service-key)\n",
        "    8081  REST API (localhost)   Authorization: Bearer <key>\n",
        "\n",
        "REST API ENDPOINTS (all require Authorization: Bearer <key>):\n",
        "    GET    /help               API documentation (public)\n",
        "    GET    /dns                List local DNS entries\n",
        "    POST   /dns                Add a DNS entry (A/AAAA/CNAME/TXT/MX/SRV/…)\n",
        "    DELETE /dns/:id            Remove a DNS entry\n",
        "    GET    /blacklist          List blacklist entries\n",
        "    POST   /blacklist          Block a domain (refuse/nxdomain)\n",
        "    DELETE /blacklist/:id      Remove a blacklist entry\n",
        "    GET    /feeds              List feed subscriptions\n",
        "    POST   /feeds              Subscribe to a remote blocklist\n",
        "    DELETE /feeds/:id          Remove a feed subscription\n",
        "    POST   /feeds/update       Refresh all feeds\n",
        "    POST   /feeds/:id/update   Refresh one feed\n",
        "    GET    /feeds/presets       List pre-configured blocklists\n",
        "    GET    /tls                DoT/DoH/DoQ TLS status\n",
        "\n",
        "FILES:\n",
        "    /etc/unbound/unbound.conf        Default config (Unbound-compatible)\n",
        "    /etc/runbound/api.key            REST API key (chmod 600)\n",
        "    /etc/runbound/cert.pem           TLS certificate (--gen-cert or Let's Encrypt)\n",
        "    /etc/runbound/key.pem            TLS private key (chmod 600)\n",
        "    /etc/runbound/dns_entries.json   Persisted DNS entries\n",
        "    /etc/runbound/blacklist.json     Persisted blacklist\n",
        "    /etc/runbound/feeds.json          Feed subscriptions\n",
        "\n",
        "MEMORY SAFETY:\n",
        "    System memory is checked every 30 s. If usage exceeds 80 %, the DNS\n",
        "    resolver cache and rate-limiter buckets are purged automatically to\n",
        "    bring usage below 50 %. The server keeps running throughout.\n",
        "\n",
        "EXAMPLES:\n",
        "    runbound                                      # use default config\n",
        "    runbound /etc/runbound/unbound.conf           # custom config\n",
        "    runbound --gen-cert dns.myserver.com          # generate TLS cert\n",
        "    RUST_LOG=debug runbound                       # verbose logging\n",
        "    RUNBOUND_API_KEY=mysecret runbound            # fixed API key via env\n",
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
                    let name = record.name().clone();
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

