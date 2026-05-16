mod config;
mod dns;
mod api;
mod feeds;
mod error;
mod store;

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;
use anyhow::Result;
use arc_swap::ArcSwap;
use tracing::info;

use dns::local::LocalZoneSet;
use dns::{Acl, RateLimiter};
use api::{AppState, init_api_key};

const API_PORT: u16 = 8081;  // 8080 used by GuestDNS in dev; production uses 8080
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
    let mut zone_set = LocalZoneSet::from_config(
        &unbound_cfg.local_zones,
        &unbound_cfg.local_data,
    );

    // Load persisted DNS entries from store
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
        info!(count = st.entries.len(), "Loaded persisted DNS entries");
    }

    // Load persisted blacklist entries
    // VUL-09: override_zone so blacklist always shadows any static zone with
    // the same name defined in unbound.conf (add_zone's or_insert would silently
    // keep the static zone, letting blocked domains resolve normally).
    if let Ok(bl) = store::load_blacklist() {
        for entry in &bl.entries {
            zone_set.override_zone(&entry.domain, dns::ZoneAction::from(&entry.action));
        }
        if !bl.entries.is_empty() {
            info!(count = bl.entries.len(), "Loaded persisted blacklist entries");
        }
    }

    // Inject feed/blocklist entries (feeds also override static zones)
    for (domain, action) in feeds::collect_feed_entries() {
        zone_set.override_zone(&domain, dns::ZoneAction::from(&action));
    }

    // ArcSwap: reads are a single atomic pointer load — zero lock contention
    // on the hot DNS query path regardless of core count.
    let zones   = Arc::new(ArcSwap::new(Arc::new(zone_set)));
    let tls_cfg = Arc::new(unbound_cfg.tls.clone());

    // ── Background: feed auto-update ───────────────────────────────────────
    tokio::spawn(async move {
        feeds::feed_update_loop(86400).await;
    });

    // ── REST API on port 8081 (localhost only) ────────────────────────────
    let api_key = init_api_key(unbound_cfg.api_key.clone());
    info!(
        addr = %format!("{API_BIND}:{API_PORT}"),
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

    let state = AppState {
        zones:       Arc::clone(&zones),
        tls_cfg:     Arc::clone(&tls_cfg),
        rate_limiter: api::ApiRateLimiter::new_public(),
        zones_mutex: Arc::new(tokio::sync::Mutex::new(())),
    };
    let app = api::router(state);
    let api_addr = format!("{API_BIND}:{API_PORT}");
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
    dns::run_dns_server(&unbound_cfg, zones, rate_limiter, acl).await
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
        "    /etc/guestdns/feeds.json         Feed subscriptions\n",
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

