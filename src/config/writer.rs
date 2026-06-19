// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// Config writer — regenerate runbound.conf from the in-memory UnboundConfig.
//
// Model (chosen by the maintainer): FULL regeneration from internal state.
// - Scalars are emitted ONLY when they differ from `UnboundConfig::default()`.
//   This keeps the file small AND avoids round-trip drift from parser clamping
//   (e.g. cache-min-entries reparses through `.max(1)`, so emitting an absent 0
//   would come back as 1). Absent == default == not emitted == reparses to default.
// - Directives the writer does NOT regenerate (Unbound tuning knobs accepted but
//   unused, and unknown/exotic lines) are captured verbatim at parse time into
//   `cfg.raw_passthrough` and re-emitted here, so NOTHING is silently dropped.
// - `is_managed_directive()` is the single source of truth shared with the parser:
//   the parser sends to passthrough exactly what the writer does NOT regenerate.
//
// Safety: `write_config_atomic()` renders to a temp file, re-parses it as a
// validation gate, and only then renames over the live config.

use crate::config::parser::{parse_str, UnboundConfig};
use std::io::Write as _;
use std::path::Path;

/// Directives the writer regenerates from struct fields (per section).
/// Everything NOT listed here is captured verbatim into `raw_passthrough`
/// by the parser and re-emitted unchanged — guaranteeing zero loss.
pub fn is_managed_directive(section: &str, key: &str) -> bool {
    match section {
        "server" => matches!(
            key,
            "interface" | "port" | "access-control" | "local-zone" | "local-data"
                | "verbosity" | "logfile" | "pidfile" | "log-format"
                | "do-ip4" | "do-ip6" | "do-udp" | "do-tcp"
                | "tls-service-pem" | "tls-cert-bundle" | "tls-service-key"
                | "tls-port" | "https-port" | "quic-port"
                | "tls-cert-hostname" | "server-hostname" | "dot-client-auth-ca"
                | "rate-limit" | "rate-limit-prefix-v4" | "rate-limit-prefix-v6"
                | "api-key" | "api-port" | "api-socket"
                | "cache-max-ttl" | "cache-min-ttl" | "cache-min-entries"
                | "private-address"
                | "dnssec-validation" | "dnssec-log-bogus" | "local-zone-dnssec" | "resolution"
                | "log-retention" | "log-client-ip"
                | "audit-log" | "audit-log-path" | "audit-log-hmac-key" | "audit-checkpoint-every"
                | "mode" | "sync-port" | "sync-master" | "sync-key" | "sync-interval"
                | "sync-allow-private-relay"
                | "acme-email" | "acme-domain" | "acme-cache-dir" | "acme-staging" | "acme-challenge-port"
                | "hsm-pkcs11-lib" | "hsm-slot" | "hsm-pin" | "hsm-api-key-label" | "hsm-store-key-label"
                | "udp-busy-poll"
                | "xdp" | "xdp-interface" | "xdp-cpu-governor" | "xdp-irq-affinity"
                | "xdp-hugepages" | "xdp-cache-snapshot" | "xdp-cache-snapshot-size"
                | "xdp-domain-routing" | "xdp-busy-poll" | "xdp-ring-size"
                | "xdp-rx-ring-size" | "xdp-tx-ring-size" | "xdp-fill-ring-size" | "xdp-comp-ring-size"
                | "prefetch" | "prefetch-threshold" | "cache-flush-cooldown"
                | "upstream-racing" | "resolv-fallback" | "serve-stale"
                | "stale-answer-ttl" | "stale-max-age"
                | "allow-update" | "block-https-record"
                | "block-page" | "block-page-port" | "block-page-title" | "block-page-org"
                | "block-page-redirect-ip" | "block-page-allow-bypass" | "block-page-bypass-pin"
                | "tsig-key"
                | "firewall-manage" | "firewall-backend" | "firewall-tag"
                | "ui-enabled" | "ui-port" | "ui-bind" | "ui-tls"
                | "ui-cert" | "ui-key" | "ui-ca-cert" | "ui-ca-key"
                | "ui-acme-domain" | "ui-acme-email" | "ui-acme-dns" | "ui-acme-cf-token" | "ui-acme-hook"
                | "ui-brand-name" | "ui-brand-logo-url" | "ui-accent-color" | "ui-favicon-url"
                | "branding"
                | "node-id" | "drain-timeout" | "health-servfail-threshold"
                | "health-latency-threshold" | "health-min-qps" | "proxy-protocol"
                | "ui-tls-san"
                | "bot-ban-duration-secs" | "bot-honeypot-enabled"
                | "webhook" | "webhook-url" | "webhook-format" | "webhook-token" | "webhook-events"
        ),
        "forward-zone" => matches!(
            key,
            "name" | "forward-addr" | "forward-tls-upstream" | "forward-tls-hostname"
        ),
        "icmp" => matches!(key, "enable" | "rate-limit" | "rate-limit-burst"),
        "api-key-extra" => matches!(key, "label" | "key" | "role"),
        "split-horizon" => matches!(key, "name" | "subnet" | "local-data"),
        "io-uring" => matches!(key, "enable"),
        "axfr" => matches!(key, "enable" | "allow"),
        "alert" => matches!(
            key,
            "name" | "metric" | "window-s" | "threshold" | "action" | "notify-url" | "block-duration-s"
        ),
        "anycast" => matches!(
            key,
            "address" | "local-as" | "peer" | "peer-as" | "local-address" | "router-id" | "exabgp-path"
        ),
        _ => false,
    }
}

fn b(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

/// Render a complete runbound.conf from `cfg`. Round-trip stable:
/// `parse(render(parse(f)))` equals `parse(f)`.
/// SEC: escape a value before embedding it inside a double-quoted config token so it
/// cannot break out of its quotes or inject a new directive line. Defense-in-depth — the
/// primary mitigation is input-layer control-char rejection (validate_no_control_chars).
fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], " ")
}

pub fn render_config(cfg: &UnboundConfig) -> String {
    let d = parse_str("server:\n").unwrap_or_default();
    let mut o = String::with_capacity(4096);
    o.push_str("# Runbound configuration — regenerated by runbound (webui/API).\n");
    o.push_str("# Manual edits to directive VALUES are preserved; comments and layout are not.\n\n");

    o.push_str("server:\n");
    // Vec scalars (emit each element; empty == default == nothing)
    for x in &cfg.interfaces { o.push_str(&format!("    interface: {x}\n")); }
    for x in &cfg.access_control { o.push_str(&format!("    access-control: {x}\n")); }
    if cfg.port != d.port { o.push_str(&format!("    port: {}\n", cfg.port)); }
    if cfg.verbosity != d.verbosity { o.push_str(&format!("    verbosity: {}\n", cfg.verbosity)); }
    if cfg.log_format != d.log_format { o.push_str(&format!("    log-format: {}\n", cfg.log_format)); }
    if let Some(v) = &cfg.logfile { o.push_str(&format!("    logfile: \"{}\"\n", escape_str(v))); }
    if let Some(v) = &cfg.pidfile { o.push_str(&format!("    pidfile: \"{}\"\n", escape_str(v))); }
    if cfg.do_ipv4 != d.do_ipv4 { o.push_str(&format!("    do-ip4: {}\n", b(cfg.do_ipv4))); }
    if cfg.do_ipv6 != d.do_ipv6 { o.push_str(&format!("    do-ip6: {}\n", b(cfg.do_ipv6))); }
    if cfg.do_udp != d.do_udp { o.push_str(&format!("    do-udp: {}\n", b(cfg.do_udp))); }
    if cfg.do_tcp != d.do_tcp { o.push_str(&format!("    do-tcp: {}\n", b(cfg.do_tcp))); }
    // local-zone / local-data
    for z in &cfg.local_zones { o.push_str(&format!("    local-zone: \"{}\" {}\n", escape_str(&z.name), z.zone_type)); }
    for r in &cfg.local_data { o.push_str(&format!("    local-data: \"{}\"\n", escape_str(&r.rr))); }
    // TLS
    if let Some(v) = &cfg.tls.cert_path { o.push_str(&format!("    tls-service-pem: \"{}\"\n", escape_str(v))); }
    if let Some(v) = &cfg.tls.key_path { o.push_str(&format!("    tls-service-key: \"{}\"\n", escape_str(v))); }
    if let Some(v) = cfg.tls.dot_port { o.push_str(&format!("    tls-port: {v}\n")); }
    if let Some(v) = cfg.tls.doh_port { o.push_str(&format!("    https-port: {v}\n")); }
    if let Some(v) = cfg.tls.doq_port { o.push_str(&format!("    quic-port: {v}\n")); }
    if let Some(v) = &cfg.tls.hostname { o.push_str(&format!("    tls-cert-hostname: \"{}\"\n", escape_str(v))); }
    if let Some(v) = &cfg.tls.dot_client_auth_ca { o.push_str(&format!("    dot-client-auth-ca: \"{}\"\n", escape_str(v))); }
    // rate limit
    if let Some(v) = cfg.rate_limit { o.push_str(&format!("    rate-limit: {v}\n")); }
    if cfg.rate_limit_prefix_v4 != d.rate_limit_prefix_v4 { o.push_str(&format!("    rate-limit-prefix-v4: {}\n", cfg.rate_limit_prefix_v4)); }
    if cfg.rate_limit_prefix_v6 != d.rate_limit_prefix_v6 { o.push_str(&format!("    rate-limit-prefix-v6: {}\n", cfg.rate_limit_prefix_v6)); }
    if let Some(v) = &cfg.api_key { o.push_str(&format!("    api-key: \"{}\"\n", escape_str(v))); }
    if let Some(v) = cfg.api_port { o.push_str(&format!("    api-port: {v}\n")); }
    if let Some(v) = &cfg.api_socket { o.push_str(&format!("    api-socket: \"{}\"\n", escape_str(v))); }
    if let Some(v) = cfg.cache_max_ttl { o.push_str(&format!("    cache-max-ttl: {v}\n")); }
    if let Some(v) = cfg.cache_min_ttl { o.push_str(&format!("    cache-min-ttl: {v}\n")); }
    if cfg.cache_min_entries != d.cache_min_entries { o.push_str(&format!("    cache-min-entries: {}\n", cfg.cache_min_entries)); }
    for x in &cfg.private_addresses { o.push_str(&format!("    private-address: {x}\n")); }
    if cfg.dnssec_validation != d.dnssec_validation { o.push_str(&format!("    dnssec-validation: {}\n", b(cfg.dnssec_validation))); }
    if cfg.dnssec_log_bogus != d.dnssec_log_bogus { o.push_str(&format!("    dnssec-log-bogus: {}\n", b(cfg.dnssec_log_bogus))); }
    if cfg.local_zone_dnssec != d.local_zone_dnssec { o.push_str(&format!("    local-zone-dnssec: {}\n", b(cfg.local_zone_dnssec))); }
    if cfg.resolution_mode != d.resolution_mode { o.push_str(&format!("    resolution: {}\n", cfg.resolution_mode.as_str())); }
    if cfg.log_retention != d.log_retention { o.push_str(&format!("    log-retention: {}\n", cfg.log_retention)); }
    if cfg.log_client_ip != d.log_client_ip { o.push_str(&format!("    log-client-ip: {}\n", b(cfg.log_client_ip))); }
    if cfg.audit_log != d.audit_log { o.push_str(&format!("    audit-log: {}\n", b(cfg.audit_log))); }
    if let Some(v) = &cfg.audit_log_path { o.push_str(&format!("    audit-log-path: \"{}\"\n", escape_str(v))); }
    if let Some(v) = &cfg.audit_log_hmac_key { o.push_str(&format!("    audit-log-hmac-key: \"{}\"\n", escape_str(v))); }
    if cfg.audit_checkpoint_every != d.audit_checkpoint_every { o.push_str(&format!("    audit-checkpoint-every: {}\n", cfg.audit_checkpoint_every)); }
    if cfg.mode != d.mode { o.push_str(&format!("    mode: \"{}\"\n", cfg.mode)); }
    if let Some(v) = cfg.sync_port { o.push_str(&format!("    sync-port: {v}\n")); }
    if let Some(v) = &cfg.sync_master { o.push_str(&format!("    sync-master: \"{}\"\n", escape_str(v))); }
    if let Some(v) = &cfg.sync_key { o.push_str(&format!("    sync-key: \"{}\"\n", escape_str(v))); }
    if cfg.sync_interval != d.sync_interval { o.push_str(&format!("    sync-interval: {}\n", cfg.sync_interval)); }
    if cfg.sync_allow_private_relay != d.sync_allow_private_relay { o.push_str(&format!("    sync-allow-private-relay: {}\n", b(cfg.sync_allow_private_relay))); }
    if let Some(v) = &cfg.acme_email { o.push_str(&format!("    acme-email: \"{}\"\n", escape_str(v))); }
    for x in &cfg.acme_domains { o.push_str(&format!("    acme-domain: \"{}\"\n", escape_str(x))); }
    if let Some(v) = &cfg.acme_cache_dir { o.push_str(&format!("    acme-cache-dir: \"{}\"\n", escape_str(v))); }
    if cfg.acme_staging != d.acme_staging { o.push_str(&format!("    acme-staging: {}\n", b(cfg.acme_staging))); }
    if let Some(v) = cfg.acme_challenge_port { o.push_str(&format!("    acme-challenge-port: {v}\n")); }
    if let Some(v) = &cfg.hsm_pkcs11_lib { o.push_str(&format!("    hsm-pkcs11-lib: \"{}\"\n", escape_str(v))); }
    if cfg.hsm_slot != d.hsm_slot { o.push_str(&format!("    hsm-slot: {}\n", cfg.hsm_slot)); }
    if let Some(v) = &cfg.hsm_pin { o.push_str(&format!("    hsm-pin: \"{}\"\n", escape_str(v))); }
    if let Some(v) = &cfg.hsm_api_key_label { o.push_str(&format!("    hsm-api-key-label: \"{}\"\n", escape_str(v))); }
    if let Some(v) = &cfg.hsm_store_key_label { o.push_str(&format!("    hsm-store-key-label: \"{}\"\n", escape_str(v))); }
    if cfg.udp_busy_poll != d.udp_busy_poll { o.push_str(&format!("    udp-busy-poll: {}\n", b(cfg.udp_busy_poll))); }
    if cfg.xdp != d.xdp { o.push_str(&format!("    xdp: {}\n", b(cfg.xdp))); }
    if let Some(v) = &cfg.xdp_interface { o.push_str(&format!("    xdp-interface: \"{}\"\n", escape_str(v))); }
    if cfg.xdp_cpu_governor != d.xdp_cpu_governor { o.push_str(&format!("    xdp-cpu-governor: {}\n", if cfg.xdp_cpu_governor { "performance" } else { "no" })); }
    if cfg.xdp_irq_affinity != d.xdp_irq_affinity { o.push_str(&format!("    xdp-irq-affinity: {}\n", b(cfg.xdp_irq_affinity))); }
    if cfg.xdp_hugepages != d.xdp_hugepages { o.push_str(&format!("    xdp-hugepages: {}\n", b(cfg.xdp_hugepages))); }
    if cfg.xdp_cache_snapshot != d.xdp_cache_snapshot { o.push_str(&format!("    xdp-cache-snapshot: {}\n", b(cfg.xdp_cache_snapshot))); }
    if cfg.xdp_cache_snapshot_size != d.xdp_cache_snapshot_size { o.push_str(&format!("    xdp-cache-snapshot-size: {}\n", cfg.xdp_cache_snapshot_size)); }
    if cfg.xdp_domain_routing != d.xdp_domain_routing { o.push_str(&format!("    xdp-domain-routing: {}\n", b(cfg.xdp_domain_routing))); }
    if cfg.xdp_busy_poll != d.xdp_busy_poll { o.push_str(&format!("    xdp-busy-poll: {}\n", b(cfg.xdp_busy_poll))); }
    if let Some(v) = cfg.xdp_ring_size { o.push_str(&format!("    xdp-ring-size: {v}\n")); }
    if cfg.xdp_rx_ring_size != d.xdp_rx_ring_size { o.push_str(&format!("    xdp-rx-ring-size: {}\n", cfg.xdp_rx_ring_size)); }
    if cfg.xdp_tx_ring_size != d.xdp_tx_ring_size { o.push_str(&format!("    xdp-tx-ring-size: {}\n", cfg.xdp_tx_ring_size)); }
    if cfg.xdp_fill_ring_size != d.xdp_fill_ring_size { o.push_str(&format!("    xdp-fill-ring-size: {}\n", cfg.xdp_fill_ring_size)); }
    if cfg.xdp_comp_ring_size != d.xdp_comp_ring_size { o.push_str(&format!("    xdp-comp-ring-size: {}\n", cfg.xdp_comp_ring_size)); }
    if cfg.prefetch != d.prefetch { o.push_str(&format!("    prefetch: {}\n", b(cfg.prefetch))); }
    if cfg.prefetch_threshold != d.prefetch_threshold { o.push_str(&format!("    prefetch-threshold: {}\n", cfg.prefetch_threshold)); }
    if cfg.cache_flush_cooldown != d.cache_flush_cooldown { o.push_str(&format!("    cache-flush-cooldown: {}\n", cfg.cache_flush_cooldown)); }
    if cfg.upstream_racing != d.upstream_racing { o.push_str(&format!("    upstream-racing: {}\n", b(cfg.upstream_racing))); }
    if cfg.resolv_fallback != d.resolv_fallback { o.push_str(&format!("    resolv-fallback: {}\n", b(cfg.resolv_fallback))); }
    if cfg.serve_stale != d.serve_stale { o.push_str(&format!("    serve-stale: {}\n", b(cfg.serve_stale))); }
    if cfg.stale_answer_ttl != d.stale_answer_ttl { o.push_str(&format!("    stale-answer-ttl: {}\n", cfg.stale_answer_ttl)); }
    if cfg.stale_max_age != d.stale_max_age { o.push_str(&format!("    stale-max-age: {}\n", cfg.stale_max_age)); }
    if cfg.allow_update != d.allow_update { o.push_str(&format!("    allow-update: {}\n", b(cfg.allow_update))); }
    if cfg.block_https_record != d.block_https_record { o.push_str(&format!("    block-https-record: {}\n", b(cfg.block_https_record))); }
    if cfg.block_page != d.block_page { o.push_str(&format!("    block-page: {}\n", b(cfg.block_page))); }
    if cfg.block_page_port != d.block_page_port { o.push_str(&format!("    block-page-port: {}\n", cfg.block_page_port)); }
    if cfg.block_page_title != d.block_page_title { o.push_str(&format!("    block-page-title: \"{}\"\n", escape_str(&cfg.block_page_title))); }
    if cfg.block_page_org != d.block_page_org { o.push_str(&format!("    block-page-org: \"{}\"\n", escape_str(&cfg.block_page_org))); }
    if let Some(v) = &cfg.block_page_redirect_ip { o.push_str(&format!("    block-page-redirect-ip: \"{}\"\n", escape_str(v))); }
    if cfg.block_page_allow_bypass != d.block_page_allow_bypass { o.push_str(&format!("    block-page-allow-bypass: {}\n", b(cfg.block_page_allow_bypass))); }
    if cfg.block_page_bypass_pin != d.block_page_bypass_pin { o.push_str(&format!("    block-page-bypass-pin: \"{}\"\n", cfg.block_page_bypass_pin)); }
    for (name, alg, sec) in &cfg.tsig_keys { o.push_str(&format!("    tsig-key: \"{}\" {alg} \"{}\"\n", escape_str(name), escape_str(sec))); }
    if cfg.firewall_manage != d.firewall_manage { o.push_str(&format!("    firewall-manage: {}\n", b(cfg.firewall_manage))); }
    if let Some(v) = &cfg.firewall_backend { o.push_str(&format!("    firewall-backend: \"{}\"\n", escape_str(v))); }
    if cfg.firewall_tag != d.firewall_tag { o.push_str(&format!("    firewall-tag: \"{}\"\n", cfg.firewall_tag)); }
    if cfg.ui_enabled != d.ui_enabled { o.push_str(&format!("    ui-enabled: {}\n", b(cfg.ui_enabled))); }
    if cfg.ui_port != d.ui_port { o.push_str(&format!("    ui-port: {}\n", cfg.ui_port)); }
    if cfg.ui_bind != d.ui_bind { o.push_str(&format!("    ui-bind: \"{}\"\n", cfg.ui_bind)); }
    if cfg.ui_tls != d.ui_tls || cfg.ui_tls_acme != d.ui_tls_acme {
        o.push_str(&format!("    ui-tls: {}\n", if cfg.ui_tls_acme { "acme" } else if cfg.ui_tls { "yes" } else { "no" }));
    }
    if cfg.ui_cert != d.ui_cert { o.push_str(&format!("    ui-cert: \"{}\"\n", cfg.ui_cert)); }
    if cfg.ui_key != d.ui_key { o.push_str(&format!("    ui-key: \"{}\"\n", cfg.ui_key)); }
    if cfg.ui_ca_cert != d.ui_ca_cert { o.push_str(&format!("    ui-ca-cert: \"{}\"\n", cfg.ui_ca_cert)); }
    if cfg.ui_ca_key != d.ui_ca_key { o.push_str(&format!("    ui-ca-key: \"{}\"\n", cfg.ui_ca_key)); }
    if cfg.ui_acme_domain != d.ui_acme_domain { o.push_str(&format!("    ui-acme-domain: \"{}\"\n", cfg.ui_acme_domain)); }
    if cfg.ui_acme_email != d.ui_acme_email { o.push_str(&format!("    ui-acme-email: \"{}\"\n", cfg.ui_acme_email)); }
    if cfg.ui_acme_dns != d.ui_acme_dns { o.push_str(&format!("    ui-acme-dns: \"{}\"\n", cfg.ui_acme_dns)); }
    if cfg.ui_acme_cf_token != d.ui_acme_cf_token { o.push_str(&format!("    ui-acme-cf-token: \"{}\"\n", cfg.ui_acme_cf_token)); }
    if cfg.ui_acme_hook != d.ui_acme_hook { o.push_str(&format!("    ui-acme-hook: \"{}\"\n", cfg.ui_acme_hook)); }
    if cfg.ui_brand_name != d.ui_brand_name { o.push_str(&format!("    ui-brand-name: \"{}\"\n", escape_str(&cfg.ui_brand_name))); }
    if cfg.ui_brand_logo_url != d.ui_brand_logo_url { o.push_str(&format!("    ui-brand-logo-url: \"{}\"\n", escape_str(&cfg.ui_brand_logo_url))); }
    if cfg.ui_accent_color != d.ui_accent_color { o.push_str(&format!("    ui-accent-color: \"{}\"\n", escape_str(&cfg.ui_accent_color))); }
    if cfg.ui_favicon_url != d.ui_favicon_url { o.push_str(&format!("    ui-favicon-url: \"{}\"\n", escape_str(&cfg.ui_favicon_url))); }
    for x in &cfg.ui_tls_san { o.push_str(&format!("    ui-tls-san: \"{}\"\n", escape_str(x))); }
    if cfg.bot_ban_duration_secs != d.bot_ban_duration_secs { o.push_str(&format!("    bot-ban-duration-secs: {}\n", cfg.bot_ban_duration_secs)); }
    if cfg.bot_honeypot_enabled != d.bot_honeypot_enabled { o.push_str(&format!("    bot-honeypot-enabled: {}\n", b(cfg.bot_honeypot_enabled))); }
    // webhooks (one block per target)
    for w in &cfg.webhooks {
        o.push_str(&format!("    webhook: \"{}\"\n", escape_str(&w.url)));
        o.push_str(&format!("    webhook-format: \"{}\"\n", fmt_str(&w.format)));
        if let Some(t) = &w.token { o.push_str(&format!("    webhook-token: \"{}\"\n", escape_str(t))); }
        if !w.events.is_empty() {
            let evs: Vec<&str> = w.events.iter().map(evt_str).collect();
            o.push_str(&format!("    webhook-events: \"{}\"\n", evs.join(" ")));
        }
    }

    // ── forward-zone blocks ──────────────────────────────────────────────
    for fz in &cfg.forward_zones {
        o.push_str("\nforward-zone:\n");
        o.push_str(&format!("    name: \"{}\"\n", escape_str(&fz.name)));
        for a in &fz.addrs { o.push_str(&format!("    forward-addr: {a}\n")); }
        if fz.tls { o.push_str("    forward-tls-upstream: yes\n"); }
        if let Some(h) = &fz.tls_hostname { o.push_str(&format!("    forward-tls-hostname: \"{h}\"\n")); }
    }

    // ── anycast ──────────────────────────────────────────────────────────
    if let Some(ac) = &cfg.anycast {
        o.push_str("\nanycast:\n");
        o.push_str(&format!("    address: {}\n", ac.address));
        o.push_str(&format!("    local-as: {}\n", ac.local_as));
        o.push_str(&format!("    peer: {}\n", ac.peer));
        o.push_str(&format!("    peer-as: {}\n", ac.peer_as));
        if let Some(la) = &ac.local_address { o.push_str(&format!("    local-address: {la}\n")); }
        if let Some(ri) = &ac.router_id { o.push_str(&format!("    router-id: {ri}\n")); }
        if let Some(ep) = &ac.exabgp_path { o.push_str(&format!("    exabgp-path: {ep}\n")); }
    }

    // ── icmp ─────────────────────────────────────────────────────────────
    if cfg.icmp_enabled != d.icmp_enabled || cfg.icmp_rate_pps != d.icmp_rate_pps || cfg.icmp_burst != d.icmp_burst {
        o.push_str("\nicmp:\n");
        o.push_str(&format!("    enable: {}\n", b(cfg.icmp_enabled)));
        if cfg.icmp_rate_pps != d.icmp_rate_pps { o.push_str(&format!("    rate-limit: {}\n", cfg.icmp_rate_pps)); }
        if cfg.icmp_burst != d.icmp_burst { o.push_str(&format!("    rate-limit-burst: {}\n", cfg.icmp_burst)); }
    }

    // ── io-uring ─────────────────────────────────────────────────────────
    if cfg.io_uring != d.io_uring {
        o.push_str("\nio-uring:\n");
        o.push_str(&format!("    enable: {}\n", b(cfg.io_uring)));
    }

    // ── axfr ─────────────────────────────────────────────────────────────
    if cfg.axfr_enabled != d.axfr_enabled || !cfg.axfr_allow.is_empty() {
        o.push_str("\naxfr:\n");
        o.push_str(&format!("    enable: {}\n", b(cfg.axfr_enabled)));
        for a in &cfg.axfr_allow { o.push_str(&format!("    allow: \"{a}\"\n")); }
    }

    // ── api-key-extra blocks ─────────────────────────────────────────────
    for ek in &cfg.extra_api_keys {
        o.push_str("\napi-key-extra:\n");
        o.push_str(&format!("    label: \"{}\"\n", ek.label));
        o.push_str(&format!("    key: \"{}\"\n", ek.key));
        o.push_str(&format!("    role: {}\n", role_str(&ek.role)));
    }

    // ── split-horizon blocks ─────────────────────────────────────────────
    for se in &cfg.split_horizon {
        o.push_str("\nsplit-horizon:\n");
        o.push_str(&format!("    name: \"{}\"\n", escape_str(&se.name)));
        for s in &se.subnets { o.push_str(&format!("    subnet: \"{}\"\n", escape_str(s))); }
        for ld in &se.local_data { o.push_str(&format!("    local-data: \"{}\"\n", escape_str(&ld.rr))); }
    }

    // ── alert blocks ─────────────────────────────────────────────────────
    for al in &cfg.alerts {
        o.push_str("\nalert:\n");
        o.push_str(&format!("    name: \"{}\"\n", al.name));
        o.push_str(&format!("    metric: \"{}\"\n", al.metric));
        o.push_str(&format!("    window-s: {}\n", al.window_s));
        o.push_str(&format!("    threshold: {}\n", al.threshold));
        o.push_str(&format!("    action: \"{}\"\n", al.action));
        if let Some(u) = &al.notify_url { o.push_str(&format!("    notify-url: \"{u}\"\n")); }
        o.push_str(&format!("    block-duration-s: {}\n", al.block_duration_s));
    }

    // ── raw passthrough (unmanaged / unknown lines), grouped by section ───
    let mut sections: Vec<&String> = cfg.raw_passthrough.iter().map(|(s, _)| s).collect();
    sections.dedup();
    let mut seen: Vec<String> = Vec::new();
    for (sec, _) in &cfg.raw_passthrough {
        if seen.contains(sec) { continue; }
        seen.push(sec.clone());
        if sec.is_empty() {
            // top-level lines with no section — should not normally happen
            for (s2, line) in &cfg.raw_passthrough { if s2 == sec { o.push_str(&format!("{line}\n")); } }
        } else {
            o.push_str(&format!("\n{sec}:\n"));
            for (s2, line) in &cfg.raw_passthrough {
                if s2 == sec { o.push_str(&format!("    {line}\n")); }
            }
        }
    }

    o
}

fn fmt_str(f: &crate::webhooks::WebhookFormat) -> &'static str {
    use crate::webhooks::WebhookFormat::*;
    match f {
        Slack => "slack",
        Discord => "discord",
        Ntfy => "ntfy",
        GenericJson => "generic-json",
    }
}

fn evt_str(e: &crate::webhooks::WebhookEventKind) -> &'static str {
    use crate::webhooks::WebhookEventKind::*;
    match e {
        DomainBlocked => "domain_blocked",
        SlaveDisconnect => "slave_disconnect",
        QpsSpike => "qps_spike",
        FeedError => "feed_error",
        KeyRotated => "key_rotated",
        ConfigReloaded => "config_reloaded",
        AlertThreshold => "alert_threshold",
        All => "all",
    }
}

fn role_str(r: &crate::multiuser::Role) -> &'static str {
    match r {
        crate::multiuser::Role::Read => "read",
        crate::multiuser::Role::Dns => "dns",
        crate::multiuser::Role::Operator => "operator",
        crate::multiuser::Role::Admin => "admin",
    }
}

/// Render `cfg`, write to a temp file, re-parse it as a validation gate,
/// then atomically rename over `path`. Returns an error WITHOUT touching the
/// live file if rendering produces an unparseable config.
pub fn write_config_atomic(cfg: &UnboundConfig, path: &Path) -> std::io::Result<()> {
    let rendered = render_config(cfg);
    // Validation gate: the rendered text must parse.
    if let Err(e) = parse_str(&rendered) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("refusing to write config: rendered output does not re-parse: {e}"),
        ));
    }
    // SEC-I16: unpredictable temp name + O_EXCL (create_new) so a symlink pre-placed in
    // the config dir cannot redirect the write (open fails on an existing path).
    let tmp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(rendered.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}



#[cfg(test)]
mod roundtrip_tests {
    use crate::config::parser::parse_str;
    use crate::config::writer::render_config;

    /// The anycast block parses and survives a write→re-parse round-trip.
    #[test]
    fn anycast_block_roundtrip() {
        let src = "server:\n  do-udp: yes\nanycast:\n  address: 198.51.100.53/32\n  local-as: 65001\n  peer: 192.168.1.1\n  peer-as: 65000\n  local-address: 192.168.1.10\n";
        let cfg = parse_str(src).unwrap();
        let ac = cfg.anycast.as_ref().expect("anycast block parsed");
        assert_eq!(ac.address, "198.51.100.53/32");
        assert_eq!(ac.local_as, 65001);
        assert_eq!(ac.peer, "192.168.1.1");
        assert_eq!(ac.peer_as, 65000);
        assert_eq!(ac.local_address.as_deref(), Some("192.168.1.10"));
        // write → re-parse must preserve it (not silently dropped)
        let cfg2 = parse_str(&render_config(&cfg)).unwrap();
        let ac2 = cfg2.anycast.as_ref().expect("anycast survives round-trip");
        assert_eq!(ac2.local_as, 65001);
        assert_eq!(ac2.peer_as, 65000);
        assert_eq!(ac2.address, "198.51.100.53/32");
    }

    /// parse(render(parse(f))) must equal parse(f) for every shipped example config.
    /// Guards against the writer silently dropping or altering any directive.
    #[test]
    fn roundtrip_example_configs() {
        let mut failures = Vec::new();
        for entry in std::fs::read_dir("examples").expect("examples dir") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("conf") { continue; }
            // branding.conf is a dedicated WebUI branding file (#25), not a main config.
            if path.file_name().and_then(|n| n.to_str()) == Some("branding.conf") { continue; }
            let content = std::fs::read_to_string(&path).unwrap();
            let cfg1 = parse_str(&content).expect("parse original");
            let rendered = render_config(&cfg1);
            let cfg2 = parse_str(&rendered).expect("rendered config must re-parse");
            if format!("{:#?}", cfg1) != format!("{:#?}", cfg2) {
                failures.push(format!("{:?}", path));
            }
        }
        assert!(failures.is_empty(), "config round-trip mismatch: {:?}", failures);
    }
    /// Upstreams must survive the persistence round-trip: rebuild_forward_zones
    /// (used by persist_config) must invert init_upstreams. Guards bug #2 — that
    /// writing upstreams to the config file does not deform them.
    #[test]
    fn upstreams_persistence_roundtrip() {
        use crate::upstreams::{init_upstreams, rebuild_forward_zones};
        let cfg = parse_str("server:\n    do-udp: yes\nforward-zone:\n    name: \".\"\n    forward-addr: 1.1.1.1@853\n    forward-addr: 9.9.9.9@853\n    forward-tls-upstream: yes\n").unwrap();
        let ups1 = init_upstreams(&cfg);
        let fz = rebuild_forward_zones(&ups1);
        let mut cfg2 = parse_str("server:\n").unwrap();
        cfg2.forward_zones = fz;
        let ups2 = init_upstreams(&cfg2);
        let key = |u: &crate::upstreams::SharedUpstreams| {
            let mut v: Vec<(String, u16, String, String)> = u.read().unwrap().iter()
                .map(|x| (x.addr.clone(), x.port, x.protocol.clone(), x.zone.clone())).collect();
            v.sort();
            v
        };
        assert_eq!(key(&ups1), key(&ups2), "upstreams deformed by forward-zone rebuild");
    }
    /// Unused Unbound tuning knobs and unknown directives must survive verbatim
    /// (raw_passthrough), and the config must round-trip. Guards #177.
    #[test]
    fn roundtrip_preserves_passthrough_and_unused() {
        let cfg = "server:\n    interface: 0.0.0.0\n    num-threads: 4\n    cache-size: 256m\n    x-unknown-directive: hello world\n    dnssec-validation: yes\n";
        let c1 = parse_str(cfg).unwrap();
        let rendered = render_config(&c1);
        assert!(rendered.contains("num-threads: 4"), "num-threads dropped:\n{rendered}");
        assert!(rendered.contains("cache-size: 256m"), "cache-size dropped:\n{rendered}");
        assert!(rendered.contains("x-unknown-directive: hello world"), "unknown directive dropped:\n{rendered}");
        let c2 = parse_str(&rendered).unwrap();
        assert_eq!(format!("{:#?}", c1), format!("{:#?}", c2), "passthrough round-trip mismatch:\n{rendered}");
    }

    /// Exercise a wide spread of directives and every section in one config.
    /// Guards #177 against writer gaps not covered by the example files.
    #[test]
    fn roundtrip_kitchen_sink() {
        let cfg = concat!(
            "server:\n",
            "    interface: 0.0.0.0\n",
            "    port: 5353\n",
            "    do-ip6: no\n",
            "    dnssec-validation: yes\n",
            "    serve-stale: no\n",
            "    cache-min-ttl: 60\n",
            "    rate-limit: 5000\n",
            "    rate-limit-prefix-v4: 28\n",
            "    block-page: yes\n",
            "    block-page-port: 8083\n",
            "    block-page-title: \"Blocked\"\n",
            "    udp-busy-poll: yes\n",
            "    serve-stale: no\n",
            "    stale-answer-ttl: 15\n",
            "    ui-enabled: yes\n",
            "    ui-acme-domain: dns.example.com\n",
            "    ui-brand-name: ACME\n",
            "    ui-accent-color: \"#ff8800\"\n",
            "    webhook: \"https://hooks.example.com/x\"\n",
            "    webhook-format: slack\n",
            "    webhook-events: \"domain_blocked qps_spike\"\n",
            "    tsig-key: \"k1\" hmac-sha256 \"c2VjcmV0\"\n",
            "    num-threads: 8\n",
            "    local-zone: \"corp.\" static\n",
            "    local-data: \"a.corp. A 10.0.0.9\"\n",
            "forward-zone:\n",
            "    name: \".\"\n",
            "    forward-addr: 1.1.1.1@853\n",
            "    forward-tls-upstream: yes\n",
            "api-key-extra:\n",
            "    label: \"ro\"\n",
            "    key: \"abcdef0123\"\n",
            "    role: read\n",
            "split-horizon:\n",
            "    name: \"office\"\n",
            "    subnet: \"10.0.0.0/8\"\n",
            "    local-data: \"intra. A 10.0.0.5\"\n",
            "alert:\n",
            "    name: \"qps\"\n",
            "    metric: \"client-qps\"\n",
            "    threshold: 1000\n",
        );
        let c1 = parse_str(cfg).unwrap();
        let rendered = render_config(&c1);
        let c2 = parse_str(&rendered).unwrap();
        assert_eq!(format!("{:#?}", c1), format!("{:#?}", c2), "kitchen-sink round-trip mismatch. rendered:\n{rendered}");
    }
}
