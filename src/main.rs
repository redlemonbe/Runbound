// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

// Clippy style/lint preferences, neutralised crate-wide (chore/clippy-clean).
// Annotations only — NO executable code is changed, so the compiled binary is
// identical to the benchmarked one (no perf/behaviour impact). Per-lint refactors
// (e.g. splitting too-many-arg signatures) can be done later, one lint at a time.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::unnecessary_sort_by)]
#![allow(clippy::unnecessary_filter_map)]
#![allow(clippy::unnecessary_get_then_check)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::redundant_locals)]
#![allow(clippy::redundant_async_block)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::double_ended_iterator_last)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::manual_abs_diff)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::manual_split_once)]
#![allow(clippy::items_after_test_module)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::empty_line_after_doc_comments)]

mod acme;
mod anycast;
mod blockpage;
mod api;
mod audit;
mod caps_drop;
mod config;
mod cpu;
mod dns;
mod domain_stats;
mod alerts;
mod webhooks;
mod error;
mod feeds;
mod firewall;
mod hsm;
mod icmp;
mod integrity;
mod logbuffer;
mod runtime;
mod ssrf;
mod stats;
mod store;
mod subnet_policy;
mod sync;
mod upstreams;
mod webui;
mod multiuser;

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::Result;
use arc_swap::ArcSwap;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

use api::{init_api_key, AppState};
use config::parser::UnboundConfig;
use dns::local::LocalZoneSet;
use dns::{Acl, RateLimiter};
use domain_stats::DomainStats;
use icmp::{IcmpConfig, IcmpStats};
use stats::Stats;

const API_BIND: &str = "127.0.0.1"; // API must not be exposed externally

#[cfg(target_os = "linux")]
fn raise_nofile_to_hard() {
    // SAFETY: get/setrlimit over a stack rlimit; no aliasing, no invalid memory.
    unsafe {
        // Target a generous FD budget; root (CAP_SYS_RESOURCE) may raise the hard
        // cap too, so set both. Never lower an already-higher limit.
        const TARGET: libc::rlim_t = 1_048_576;
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            let new_max = rl.rlim_max.max(TARGET);
            let new_cur = new_max; // soft = hard
            if new_cur > rl.rlim_cur {
                let prev = rl.rlim_cur;
                rl.rlim_cur = new_cur;
                rl.rlim_max = new_max;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) == 0 {
                    info!(from = prev, to = new_cur, "RLIMIT_NOFILE raised");
                } else {
                    // Fall back to raising the soft limit up to the existing hard cap.
                    rl.rlim_max = libc::rlimit { rlim_cur: 0, rlim_max: 0 }.rlim_max;
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 && rl.rlim_cur < rl.rlim_max {
                        let cap = rl.rlim_max; rl.rlim_cur = cap;
                        let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
                        info!(soft = cap, "RLIMIT_NOFILE raised to hard cap (could not raise hard)");
                    } else {
                        tracing::warn!("RLIMIT_NOFILE: could not raise — staying at the soft limit");
                    }
                }
            }
        }
    }
}

fn main() -> Result<()> {
    // FIRST thing, before any fork/daemonization or socket setup: a DNS forwarder
    // must not depend on the launcher for its FD budget. A MAX_INFLIGHT forward
    // burst opens one UDP socket per in-flight query, so a default soft
    // RLIMIT_NOFILE (1024) yields EMFILE under load outside the systemd unit's
    // LimitNOFILE. Raise it eagerly.
    #[cfg(target_os = "linux")]
    raise_nofile_to_hard();

    let args: Vec<String> = std::env::args().collect();

    if handle_cli_flags(&args)? {
        return Ok(());
    }

    let (cfg, base_dir, cfg_path) = init_runtime(&args)?;

    // ── Tokio runtime with optional CPU affinity ──────────────────────────
    // init_runtime() has already installed the tracing subscriber, so info!()
    // works here without a running async runtime.
    cpu::log_cpu_info();
    let cores = cpu::physical_cores();
    let core_count = cores.len();

    // #163: CPU placement is fully automatic.
    // Kernel slow path: OS scheduler floats on all cores (+39% vs naive pin, Xeon v2+X520).
    // XDP fast path: workers auto-pinned to NUMA-local physical cores in start_xdp_on_iface().
    info!(cores = core_count, "CPU placement: automatic (OS scheduler + XDP NUMA-local pin)");
    // #physical-only: pin every tokio thread (control plane + wire serving-core fallback + API) to a
    // PHYSICAL core, never an SMT sibling. The cache-hit hot path is the kloop / AF_XDP worker
    // (already physical-only); a tokio async thread floating onto the HT sibling of a busy SIMD
    // core steals that core's execution units (HT only helps code that leaves units idle —
    // saturated ASM/SIMD has none to spare). Default num_cpus (= all logical incl. HT) is what
    // put async work on the SMT siblings. Worker count = physical cores so fallback bursts still
    // scale; the threads park when idle, so sharing physical cores with the kloop is free.
    let phys_cores = crate::cpu::physical_cores();
    let n_phys = phys_cores.len().max(1);
    // #physical-only (non-negotiable): confine the WHOLE process to PHYSICAL cores up-front, so
    // EVERY thread Runbound ever spawns — tokio workers, the API/UI runtimes, std::threads, the
    // kloop and the XDP workers — inherits a physical-cores-only affinity mask and can NEVER be
    // scheduled onto an SMT sibling. A thread on the HT sibling of a saturated SIMD core steals
    // its execution units (HT only helps code that leaves units idle — Runbound's ASM/SIMD hot
    // path has none to spare). Threads that need one specific core (kloop / XDP) narrow this
    // mask further to a single physical core; that is always a subset, so it stays HT-free.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: zeroed cpu_set_t, CPU_SET each physical core id (< CPU_SETSIZE), then
        // sched_setaffinity on self (pid 0). All standard, no aliasing.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            for &c in &phys_cores {
                if c < libc::CPU_SETSIZE as usize {
                    libc::CPU_SET(c, &mut set);
                }
            }
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        }
    }
    let pin_cursor = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(n_phys)
        .max_blocking_threads(n_phys)
        .on_thread_start({
            let phys = phys_cores.clone();
            let cursor = pin_cursor.clone();
            move || {
                #[cfg(target_os = "linux")]
                {
                    let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let core = phys[i % phys.len()];
                    if core < libc::CPU_SETSIZE as usize {
                        // SAFETY: zeroed cpu_set_t + CPU_SET(core) with core < CPU_SETSIZE;
                        // sched_setaffinity on self (pid 0) is a standard pin.
                        unsafe {
                            let mut set: libc::cpu_set_t = std::mem::zeroed();
                            libc::CPU_SET(core, &mut set);
                            libc::sched_setaffinity(
                                0,
                                std::mem::size_of::<libc::cpu_set_t>(),
                                &set,
                            );
                        }
                    }
                }
            }
        })
        .build()?;

    runtime.block_on(async_main(cfg, base_dir, cfg_path))
}

async fn async_main(
    cfg: UnboundConfig,
    base_dir: std::path::PathBuf,
    cfg_path: String,
) -> Result<()> {
    let (
        zones,
        rate_limiter,
        acl,
        global_stats,
        log_buffer,
        audit,
        xdp_mode,
        resolver,
        prefetch_tracker,
        upstreams,
        per_upstream_resolvers,
        racing_wins,
        domain_stats,
        alert_tracker,
        icmp_stats,
        icmp_cfg,
        dnssec_enabled,
        resolution_mode,
        recursor,
        blacklist_reload_rx,
    ) = build_and_launch(&cfg, base_dir, cfg_path.clone()).await?;

    // #201: latch the local-zone signing flag before any fast-path preload runs, so signed
    // local zones are kept out of the snapshot and served on the slow path.
    dns::local::LOCAL_ZONE_DNSSEC
        .store(cfg.local_zone_dnssec, std::sync::atomic::Ordering::Relaxed);

    // #60: XDP cache snapshot — create only when XDP is enabled and configured.
    let mut xdp_cache_snapshot: Option<dns::cache_snapshot::SharedCacheSnapshot> = None;
    let mut xdp_cache_mutable: Option<dns::cache_snapshot::MutableCacheMap> = None;
    // #183: build the cache snapshot whenever xdp-cache-snapshot is on — it feeds
    // BOTH the XDP fast path (xdp: yes) AND the kernel fast loop (xdp: no). Gating it
    // on cfg.xdp left the kernel fast loop with no snapshot -> every slow-path query
    // fell back to the serving-core slow path instead of the shared ASM answer_from_cache path.
    #[cfg(feature = "xdp")]
    if cfg.xdp_cache_snapshot {
        let mutable = dns::cache_snapshot::new_mutable_cache();
        let snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(
            dns::cache_snapshot::CacheSnapshot::default(),
        )));
        tokio::spawn(dns::cache_snapshot::publish_loop(
            Arc::clone(&snapshot),
            Arc::clone(&mutable),
        ));
        xdp_cache_snapshot = Some(snapshot);
        // #186: publish the shared cache so API write handlers can evict stale
        // forwarded entries on local-zone writes (keeps edits live on the fast path).
        let _ = dns::cache_snapshot::XDP_CACHE_FOR_API.set(Arc::clone(&mutable));
        xdp_cache_mutable = Some(mutable);
    }

    // #29: load XDP cache from disk on startup.
    #[cfg(feature = "xdp")]
    if let Some(ref cache) = xdp_cache_mutable {
        let cache_file = runtime::base_dir().join("xdp_cache.rkyv");
        let loaded =
            dns::cache_snapshot::load_xdp_cache(cache, &cache_file, cfg.xdp_cache_snapshot_size);
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
                Err(e) => {
                    tracing::warn!("Cannot install SIGUSR2 handler: {e}");
                    return;
                }
            };
            let cache_file = runtime::base_dir().join("xdp_cache.rkyv");
            loop {
                usr2.recv().await;
                match &cache_for_usr2 {
                    Some(cache) => match dns::cache_snapshot::save_xdp_cache(cache, &cache_file) {
                        Ok(n) => {
                            info!(entries = n, path = %cache_file.display(), "SIGUSR2 — XDP cache saved")
                        }
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
    // ── XDP multi-interface init (#feat/xdp-multi-interface) ─────────────────
    // xdp-interface supports three modes:
    //   <name>       — single interface (backward-compatible)
    //   <a>,<b>,...  — explicit list, bind each independently
    //   auto         — enumerate all eligible interfaces via list_eligible_interfaces()
    //   none         — disable XDP via interface override
    //   absent       — auto-detect single interface from listen IP / default route (legacy default)
    #[cfg(feature = "xdp")]
    let mut _xdp_handles: Vec<dns::xdp::XdpHandle> = if !cfg.xdp {
        info!("XDP fast path disabled (xdp: no / --no-xdp)");
        vec![]
    } else if cfg.xdp_interface.as_deref() == Some("none") {
        // #79: xdp-interface: none disables XDP without touching the xdp: directive.
        info!("XDP fast path disabled (xdp-interface: none)");
        vec![]
    } else {
        let xdp_ring_sizes = dns::xdp::XdpRingSizes {
            rx: cfg.xdp_rx_ring_size,
            tx: cfg.xdp_tx_ring_size,
            fill: cfg.xdp_fill_ring_size,
            comp: cfg.xdp_comp_ring_size,
        };

        // Resolve the interface list from config
        let iface_list: Vec<String> = match cfg.xdp_interface.as_deref() {
            Some("auto") => {
                // Enumerate all eligible interfaces (UP, physical, non-bonded)
                let found = dns::xdp::socket::list_eligible_interfaces();
                if found.is_empty() {
                    tracing::warn!("XDP auto: no eligible interface found — fast path disabled");
                }
                found
            }
            Some(explicit) if explicit.contains(',') => {
                // Comma-separated explicit list: "nic2,nic3"
                explicit.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            Some(explicit) => {
                // Single explicit interface name
                vec![explicit.to_string()]
            }
            None => {
                // Legacy: auto-detect single interface from listen address / default route
                let detected = cfg
                    .interfaces
                    .first()
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
                    .or_else(dns::xdp::socket::default_interface);
                if let Some(ref name) = detected {
                    info!(iface = %name, "XDP auto-selected interface (use xdp-interface: to override)");
                } else {
                    tracing::warn!("XDP: could not determine network interface; fast path disabled");
                }
                detected.into_iter().collect()
            }
        };

        if iface_list.is_empty() {
            vec![]
        } else {
            let iface_refs: Vec<&str> = iface_list.iter().map(|s| s.as_str()).collect();
            let handles = dns::xdp::start_xdp_multi(
                &iface_refs,
                Arc::clone(&zones),
                Arc::clone(&rate_limiter),
                Arc::clone(&acl),
                cfg.xdp_cpu_governor,
                cfg.xdp_irq_affinity,
                cfg.xdp_hugepages,
                xdp_cache_snapshot.clone(),
                cfg.xdp_domain_routing,
                cfg.xdp_busy_poll,
                cfg.xdp_ring_size,
                xdp_ring_sizes,
                Arc::clone(&global_stats),
                Arc::clone(&domain_stats),
            );
            // Update xdp_mode from the first handle (representative)
            if let Some(h) = handles.first() {
                let m: u8 = match h.mode {
                    dns::xdp::XdpMode::Drv => 1,
                    dns::xdp::XdpMode::Skb => 2,
                };
                xdp_mode.store(m, Ordering::Relaxed);
                // Mirror into the global single-source-of-truth so consumers without
                // AppState (the slave relay /system handler) report the real mode too.
                dns::xdp::socket::XDP_MODE.store(m, Ordering::Relaxed);
            }
            handles
        }
    };
    // Preload local-data A/AAAA into the XDP cache for the single-lookup fast path.
    // Must run after start_xdp_multi (handles live) and after zones + cache are ready.
    // Sentinel expires_at ensures local-data survives every snapshot rebuild.
    #[cfg(feature = "xdp")]
    if let Some(ref cache) = xdp_cache_mutable {
        let zones_snap = zones.load();
        dns::local::preload_into_cache(&zones_snap, cache);
    }

    // ── ICMP BPF init + stats poll task (#89) ──────────────────────────────
    // Multi-iface: ICMP BPF ops target the primary handle (index 0).
    #[cfg(feature = "xdp")]
    if let Some(h) = _xdp_handles.first_mut() {
        // Push initial config to BPF map
        if let Err(e) = h.icmp_update_config(cfg.icmp_enabled, cfg.icmp_rate_pps, cfg.icmp_burst) {
            tracing::warn!(err=%e, "ICMP BPF config init failed");
        } else if cfg.icmp_enabled {
            info!(
                "XDP ICMP echo responder active (rate={}/s)",
                cfg.icmp_rate_pps
            );
        }
    }

    // Pentest hardening: CAP_BPF/CAP_PERFMON were only needed for the XDP
    // load/attach + one-time BPF map init above (blacklist/CPUMAP/XSKMAP/ICMP
    // config, all done by this point). Every later BPF map operation (ban,
    // blacklist reload, domain-routing toggle) updates a map through an fd
    // this process already holds and does not need the capability again — see
    // caps_drop.rs. Unconditional and feature-independent: a no-op when the
    // capabilities were never granted (xdp: no, or the `xdp` feature is not
    // compiled in). Runs once, at boot, before the server starts answering
    // queries — not on any query/packet path.
    caps_drop::drop_bpf_load_time_capabilities();
    // ── #158: extract GovernorGuard BEFORE handle is moved into poll task ──────
    // XdpHandle is moved into a detached tokio::spawn below — its Drop is never
    // reached on SIGTERM (OS kills the process before unwind).  We extract the
    // guard here so it can be stored in an Arc<Mutex> and explicitly dropped in
    // a SIGTERM handler.
    // #158 + multi-iface: extract all GovernorGuards before handles move into poll task.
    // Each handle may have pinned different cores; we collect all guards.
    #[cfg(feature = "xdp")]
    let _xdp_governor_guards: Vec<dns::xdp::governor::GovernorGuard> = {
        _xdp_handles.iter_mut().filter_map(|h| h.take_governor_guard()).collect()
    };
    #[cfg(not(feature = "xdp"))]
    let _xdp_governor_guards: Vec<()> = vec![];

    // Wrap in Arc<Mutex<Vec>> for sharing with SIGTERM handler.
    let governor_arc = std::sync::Arc::new(std::sync::Mutex::new(_xdp_governor_guards));

    // Spawn BPF stats poll task — runs every second, updates Rust atomics.
    // Also detects ICMP floods, applies XDP bans, and pushes config changes to BPF.
    #[cfg(feature = "xdp")]
    let _icmp_poll_task = {
        use std::sync::atomic::Ordering;
        let icmp_stats_poll = Arc::clone(&icmp_stats);
        let icmp_cfg_poll = Arc::clone(&icmp_cfg);
        let alert_tracker_poll = Arc::clone(&alert_tracker);
        // #ddos: route AlertTracker rule blocks to the XDP ban map (line-rate drop),
        // but ONLY when XDP is actually attached — otherwise nothing drains
        // ban_cmd_rx and the sends would accumulate unbounded.
        if !_xdp_handles.is_empty() {
            alert_tracker.set_ban_tx(icmp_stats.ban_cmd_tx.clone());
        }
        // Take the receiver from IcmpStats (created in new(), consumed once here).
        let mut ban_cmd_rx = icmp_stats
            .ban_cmd_rx
            .lock()
            .unwrap()
            .take()
            .expect("IcmpStats ban_cmd_rx already consumed");
        // All XDP handles (primary + additional) are kept alive inside the
        // tokio::spawn closure below.  The primary (index 0) is used for ICMP
        // BPF ops; the rest are held passively so their eBPF programs remain
        // attached for the entire process lifetime.
        //
        // CRITICAL: do NOT split the Vec (remove(0) + _rest outside closure).
        // Variables not referenced inside `async move` are NOT captured — they
        // are dropped when this outer block closes (~line 432), which calls
        // XdpHandle::Drop → XDP prog detached → rx_drained=0 on iface1+.
        let mut xdp_handles_all = _xdp_handles; // entire Vec moved into closure
        // Local set of IPs currently banned in BPF — used to detect delta changes.
        let mut bpf_banned: std::collections::HashSet<u32> = std::collections::HashSet::new();
        // #228: v6 twin of `bpf_banned` (16-byte address, network byte order).
        let mut bpf_banned_v6: std::collections::HashSet<[u8; 16]> =
            std::collections::HashSet::new();
        // #ddos: mirror of the BPF bans_active gate (set only on empty<->non-empty).
        let mut bans_gate = false;
        let mut blacklist_reload_rx = blacklist_reload_rx;
        tokio::spawn(async move {
            let mut last_rate = 0u32;
            let mut last_enabled = false;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                // Primary handle (index 0) used for ICMP BPF ops.
                // xdp_handles_all is moved into this closure — all handles
                // remain alive, keeping ALL XDP programs attached.
                // NEVER break here: it would drop the closure → drop all handles
                // → XDP progs detached → iface1+ gets rx_drained=0.
                let h = match xdp_handles_all.first_mut() {
                    Some(h) => h,
                    None => {
                        // No XDP handles (xdp:no): the BPF ban map doesn't exist, but drain
                        // the channel so queued ban/unban commands don't accumulate unbounded
                        // (icmp_stats.banned is the source of truth on the kernel-UDP path).
                        while ban_cmd_rx.try_recv().is_ok() {}
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };

                // Process ban/unban commands from API and relay handlers
                while let Ok(cmd) = ban_cmd_rx.try_recv() {
                    use crate::icmp::IcmpBanCmd;
                    match cmd {
                        IcmpBanCmd::Ban(ipv4) => {
                            let be32 = u32::from(ipv4).to_be();
                            if bpf_banned.insert(be32) {
                                let _ = h.icmp_ban_ip(be32);
                            }
                        }
                        IcmpBanCmd::Unban(ipv4) => {
                            let be32 = u32::from(ipv4).to_be();
                            if bpf_banned.remove(&be32) {
                                let _ = h.icmp_unban_ip(be32);
                            }
                        }
                        IcmpBanCmd::BanV6(ip6) => {
                            let key = ip6.octets();
                            if bpf_banned_v6.insert(key) {
                                let _ = h.icmp_ban_ip_v6(key);
                            }
                        }
                        IcmpBanCmd::UnbanV6(ip6) => {
                            let key = ip6.octets();
                            if bpf_banned_v6.remove(&key) {
                                let _ = h.icmp_unban_ip_v6(key);
                            }
                        }
                    }
                }

                // #ddos: keep the BPF DNS-path ban gate in sync with the ban set, so
                // the hot path skips the per-IP lookup whenever no IP is banned.
                // #228: the gate covers both the v4 and v6 ban maps.
                let want_gate = !bpf_banned.is_empty() || !bpf_banned_v6.is_empty();
                if want_gate != bans_gate {
                    let _ = h.set_bans_active(want_gate);
                    bans_gate = want_gate;
                }

                // #153: Apply pending blacklist reload commands
                while let Ok(domains) = blacklist_reload_rx.try_recv() {
                    match h.blacklist_reload(&domains) {
                        Ok(n) => tracing::debug!(count = n, "XDP blacklist reloaded"),
                        Err(e) => tracing::warn!(err = %e, "XDP blacklist reload failed"),
                    }
                }

                // Read stats from BPF per-CPU array
                if let Ok(vals) = h.icmp_read_stats() {
                    icmp_stats_poll.handled.store(vals[0], Ordering::Relaxed);
                    icmp_stats_poll.replied.store(vals[1], Ordering::Relaxed);
                    icmp_stats_poll.dropped.store(vals[2], Ordering::Relaxed);
                    icmp_stats_poll.rate_limited.store(vals[3], Ordering::Relaxed);
                }

                // Flood detection: read per-IP rate-limited counts, ban exceeding IPs
                let ban_threshold = {
                    let c = icmp_cfg_poll.lock().unwrap_or_else(|e| e.into_inner());
                    c.ban_threshold
                };
                if let Ok(rl_hits) = h.icmp_read_and_reset_rl() {
                    for (ip_be32, count) in rl_hits {
                        if count < ban_threshold as u64 {
                            continue;
                        }
                        // Convert BE32 to Ipv4Addr (ip_be32 is network byte order)
                        let ipv4 = std::net::Ipv4Addr::from(u32::from_be(ip_be32));
                        let ip_addr = std::net::IpAddr::V4(ipv4);
                        if icmp_stats_poll.banned.contains_key(&ip_addr) {
                            continue; // already banned
                        }
                        tracing::warn!(
                            ip = %ipv4,
                            rl_count = count,
                            "ICMP flood detected — IP banned at XDP layer"
                        );
                        // Update in-memory ban list + AlertTracker
                        icmp_stats_poll.ban(ip_addr, crate::icmp::BanSource::IcmpFlood);
                        alert_tracker_poll.block_manual(
                            ip_addr,
                            "icmp-flood".to_string(),
                        );
                        // Apply XDP ban
                        if bpf_banned.insert(ip_be32) {
                            let _ = h.icmp_ban_ip(ip_be32);
                        }
                        // Propagate to slaves via relay
                        if let Some(tx) = icmp_stats_poll.ban_propagate_tx.get() {
                            let _ = tx.send(ip_addr);
                        }
                    }
                }

                // Push config changes to BPF map
                let (enabled, rate_pps, burst) = {
                    let c = icmp_cfg_poll.lock().unwrap_or_else(|e| e.into_inner());
                    (c.enabled, c.rate_pps, c.burst)
                };
                if (enabled != last_enabled || rate_pps != last_rate)
                    && h.icmp_update_config(enabled, rate_pps, burst).is_ok()
                {
                    last_enabled = enabled;
                    last_rate = rate_pps;
                }
            }
        })
    };
    // When xdp feature is off: keep icmp_stats/icmp_cfg alive for API use
    #[cfg(not(feature = "xdp"))]
    let (_icmp_stats_keep, _icmp_cfg_keep) = (Arc::clone(&icmp_stats), Arc::clone(&icmp_cfg));
    #[cfg(not(feature = "xdp"))]
    drop(blacklist_reload_rx);

    // ── #158: SIGTERM / SIGINT — graceful shutdown with governor restore ────────
    // Before this fix, SIGTERM used the OS default (kill) — no unwind, no Drop.
    // Now: restore the CPU frequency governor explicitly, THEN exit.
    // exit(0) has the same visible effect as the old kill, but with cleanup.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let gg = std::sync::Arc::clone(&governor_arc);
        let drain_secs = cfg.drain_timeout_secs;
        tokio::spawn(async move {
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Cannot install SIGTERM handler: {e}");
                    return;
                }
            };
            let mut intr = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Cannot install SIGINT handler: {e}");
                    return;
                }
            };
            tokio::select! {
                _ = term.recv() => { info!("SIGTERM received — graceful shutdown"); }
                _ = intr.recv() => { info!("SIGINT received — graceful shutdown"); }
            }
            // #21: drain — keep serving briefly so BGP withdraws the anycast route
            // and in-flight queries finish before the process exits.
            if drain_secs > 0 {
                info!(secs = drain_secs, "draining before exit (anycast: lets BGP converge)");
                tokio::time::sleep(std::time::Duration::from_secs(drain_secs)).await;
            }
            // Drop all GovernorGuards: restores CPU governor on every XDP core (#158).
            // Multi-interface: one guard per interface; each core returns to its original governor.
            #[cfg(feature = "xdp")]
            if let Ok(mut guards) = gg.lock() {
                let count = guards.len();
                guards.drain(..).for_each(drop);
                if count > 0 {
                    info!(cores = count, "CPU governor restored on all XDP interfaces");
                }
            }
            std::process::exit(0);
        });
    }

    // ── io_uring availability detection (#65) ─────────────────────────────────
    if cfg.io_uring {
        let available = std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled")
            .map(|s| s.trim() == "0")
            .unwrap_or(true);
        if available {
            info!("io_uring: enabled and available — async I/O upgrade active");
            // tokio io_uring backend is active when compiled with tokio_unstable + io-uring feature.
            // The slow-path resolver uses tokio tasks which transparently benefit from io_uring.
        } else {
            tracing::warn!("io_uring: enabled in config but disabled by kernel (io_uring_disabled != 0) — falling back to epoll");
        }
    }

    // #93: TTY-only startup banner — not printed under systemd (no TTY on stderr).
    if std::io::stderr().is_terminal() {
        let xdp_str = match xdp_mode.load(Ordering::Relaxed) {
            1 => "\x1b[32menabled (DRV)\x1b[0m",
            2 => "\x1b[32menabled (SKB)\x1b[0m",
            _ => "disabled",
        };
        eprintln!(
            "\x1b[36mRunbound v{ver}\x1b[0m  —  DNS :{dns}  |  API :{api}  |  XDP: {xdp}",
            ver = env!("CARGO_PKG_VERSION"),
            dns = cfg.port,
            api = cfg.api_port.unwrap_or(8080),
            xdp = xdp_str,
        );
    }

    let fw_ports = firewall::PortSet::from_config(&cfg);
    let fw_manager = std::sync::Arc::new(firewall::FirewallManager::new(
        cfg.firewall_manage,
        cfg.firewall_backend.as_deref(),
        &cfg.firewall_tag,
    ));
    fw_manager.open(&fw_ports);
    let fw_cleanup = Arc::clone(&fw_manager);

    // ── anycast: announce the VIP over BGP while the server runs ───────────────────
    // Held for the lifetime of the server; dropped on shutdown → exabgp stops → route
    // withdrawn (graceful drain). The VIP must already be on a dummy/lo iface (docs/anycast.md).
    let _anycast_announcer = cfg.anycast.as_ref().and_then(|ac| {
        match anycast::AnycastAnnouncer::prepare(ac) {
            Ok(mut a) => match a.announce() {
                Ok(()) => Some(a),
                Err(e) => {
                    tracing::error!("anycast: announce failed — running without it: {e:#}");
                    None
                }
            },
            Err(e) => {
                tracing::error!("anycast: invalid config — running without it: {e:#}");
                None
            }
        }
    });

    let result = dns::run_dns_server(
        &cfg,
        zones,
        rate_limiter,
        acl,
        global_stats,
        log_buffer,
        resolver,
        prefetch_tracker,
        xdp_cache_mutable,
        cfg.xdp_cache_snapshot_size,
        upstreams,
        per_upstream_resolvers,
        racing_wins,
        domain_stats,
        Arc::clone(&alert_tracker),
        Arc::clone(&dnssec_enabled),
        icmp_stats,
        resolution_mode,
        recursor,
        cfg_path,
        std::sync::Arc::clone(&fw_manager),
    )
    .await;
    fw_cleanup.close();
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
        let hostname = args
            .get(pos + 1)
            .map(|s| s.as_str())
            .unwrap_or("runbound.local");
        gen_self_signed_cert(hostname)?;
        return Ok(true);
    }
    // --check-config [path] — validate config and systemd security parameters, then exit
    if let Some(pos) = args.iter().position(|a| a == "--check-config") {
        let path = args
            .get(pos + 1)
            .map(|s| s.as_str())
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

    let cfg_path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| "/etc/unbound/unbound.conf".to_string());

    // Derive runtime base_dir from config file's parent directory.
    // All runtime files (api.key, dns_entries.json, …) are stored there.
    let cfg_canonical =
        std::fs::canonicalize(&cfg_path).unwrap_or_else(|_| std::path::PathBuf::from(&cfg_path));
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

    // Fail fast — and with an actionable message — if the base directory is not
    // writable. Runbound persists its runtime state there (api.key, node-id,
    // sync-master.fingerprint, relay-cert.pem, xdp_cache.rkyv…). A read-only base_dir
    // otherwise surfaces much later as a cascade of I/O errors during slave-sync /
    // relay init and, because the API/UI runtimes are already live in the async
    // context by then, a confusing tokio "cannot drop a runtime in a context where
    // blocking is not allowed" panic instead of a clear cause.
    {
        let probe = base_dir.join(".runbound-write-test");
        match std::fs::write(&probe, b"") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
            }
            Err(e) => {
                anyhow::bail!(
                    "Config base directory '{}' is not writable ({}). Runbound stores its runtime state there — fix its ownership/permissions so the runbound user can write it, or, under a systemd sandbox, add it to ReadWritePaths=.",
                    base_dir.display(),
                    e
                );
            }
        }
    }

    // Load config before tracing so verbosity: takes effect.
    // Unknown-directive warnings from the parser are silently dropped here;
    // they will reappear on reload if the operator adds an unknown key.
    let mut unbound_cfg = config::load(&cfg_path)?;

    // Init tracing: RUST_LOG env var > verbosity: directive > WARN.
    // log-format: json emits structured (SIEM-ready) logs; default is text.
    let log_filter = if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::EnvFilter::from_env("RUST_LOG")
    } else {
        tracing_subscriber::EnvFilter::new(verbosity_to_filter(unbound_cfg.verbosity))
    };
    // #knob: logfile — if set, write logs to that file (create its dir first) instead
    // of stdout. A non-rotating appender; falls back to stdout if the path is unusable.
    let json = unbound_cfg.log_format == "json";
    let file_writer = unbound_cfg.logfile.as_deref().and_then(|p| {
        let path = std::path::Path::new(p);
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or_else(|| std::path::Path::new("."));
        let _ = std::fs::create_dir_all(dir);
        let name = path.file_name()?;
        // Verify we can actually write before committing to the file appender; otherwise
        // fall back to stdout instead of silently losing every log line to a stderr error.
        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(_) => Some(tracing_appender::rolling::never(dir, name)),
            Err(e) => {
                eprintln!("logfile {p} is not writable ({e}) — logging to stdout instead");
                None
            }
        }
    });
    match (file_writer, json) {
        (Some(w), true) => tracing_subscriber::fmt().json().with_env_filter(log_filter).with_writer(w).init(),
        (Some(w), false) => tracing_subscriber::fmt().with_env_filter(log_filter).with_writer(w).init(),
        (None, true) => tracing_subscriber::fmt().json().with_env_filter(log_filter).init(),
        (None, false) => tracing_subscriber::fmt().with_env_filter(log_filter).init(),
    }
    // #knob: pidfile — write our PID so classic init/monitoring can find us (best-effort).
    if let Some(pidfile) = unbound_cfg.pidfile.as_deref() {
        if let Err(e) = std::fs::write(pidfile, format!("{}\n", std::process::id())) {
            tracing::warn!(pidfile, err = %e, "could not write pidfile");
        }
    }
    // #knob guards: warn on transport configs that answer nothing / are silently ignored.
    if !unbound_cfg.do_udp && !unbound_cfg.do_tcp {
        tracing::warn!("both do-udp and do-tcp are disabled — no DNS transport will be served");
    }
    if unbound_cfg.xdp && !unbound_cfg.do_udp {
        tracing::warn!("do-udp: no has no effect with xdp: yes — AF_XDP owns UDP:53");
    }

    runtime::BASE_DIR
        .set(base_dir.clone())
        .unwrap_or_else(|_| panic!("BASE_DIR set twice — this is a bug"));
    info!(base_dir = %base_dir.display(), "Runtime base_dir");

    dns::hasher::init();

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
    cfg: &UnboundConfig,
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
    Arc<DomainStats>,
    Arc<crate::alerts::AlertTracker>,
    Arc<crate::icmp::IcmpStats>,
    Arc<std::sync::Mutex<crate::icmp::IcmpConfig>>,
    Arc<std::sync::atomic::AtomicBool>,
    Arc<std::sync::atomic::AtomicU8>,
    dns::recursor::SharedRecursor,
    tokio::sync::mpsc::Receiver<Vec<String>>,
)> {
    // ── Audit log ─────────────────────────────────────────────────────────
    let audit_log_path = cfg.audit_log_path.as_deref().map(std::path::PathBuf::from);
    let audit = audit::init(
        cfg.audit_log,
        audit_log_path,
        cfg.audit_log_hmac_key.clone(),
        base_dir.clone(),
        cfg.audit_checkpoint_every,
    );
    audit.send(audit::AuditEvent::Startup);

    // ── ACME: auto-provision TLS cert if needed ────────────────────────────
    if let Some(ref email) = cfg.acme_email {
        if cfg.acme_domains.is_empty() {
            tracing::warn!("acme-email set but no acme-domain directives — ACME disabled");
        } else {
            let cert_path = cfg
                .tls
                .cert_path
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| base_dir.join("cert.pem"));
            let key_path = cfg
                .tls
                .key_path
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| base_dir.join("key.pem"));
            let cache_dir = cfg
                .acme_cache_dir
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| base_dir.join("acme"));
            let acme_cfg = acme::AcmeConfig {
                email: email.clone(),
                domains: cfg.acme_domains.clone(),
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
                cache_dir,
                staging: cfg.acme_staging,
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
    let zones = Arc::new(ArcSwap::new(Arc::new(build_zone_set(cfg))));
    let tls_cfg = Arc::new(cfg.tls.clone());

    // ── SIGHUP: hot-reload zones from config without dropping connections ──
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let zones_hup = Arc::clone(&zones);
        let cfg_path_hup = cfg_path.clone();
        tokio::spawn(async move {
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Cannot install SIGHUP handler: {e}");
                    return;
                }
            };
            loop {
                hup.recv().await;
                info!("SIGHUP — reloading zones from config");
                match config::load(&cfg_path_hup) {
                    Ok(new_cfg) => {
                        let new_zones = build_zone_set(&new_cfg);
                        // Evict/re-preload the XDP cache BEFORE swapping zones_hup, same
                        // ordering as the API reload path — otherwise a stale forwarded
                        // answer cached before a blacklist/feed/local-zone change keeps
                        // shadowing it from the XDP fast path until TTL expiry.
                        if let Some(cache) = dns::cache_snapshot::XDP_CACHE_FOR_API.get() {
                            api::resync_xdp_cache_inner(cache, &zones_hup.load_full(), &new_zones);
                        }
                        zones_hup.store(Arc::new(new_zones));
                        info!(
                            local_zones = new_cfg.local_zones.len(),
                            local_data = new_cfg.local_data.len(),
                            "Hot-reload complete"
                        );
                    }
                    Err(e) => tracing::warn!("SIGHUP reload failed (keeping current zones): {e}"),
                }
            }
        });
    }

    // ── Hickory-free plain DNS server ──────────────────────────────────
    // Opt in with RUNBOUND_PLAIN_SERVER_PORT=<port>: own listeners (no
    // hickory-server) that serve local zones with our wire codec and forward the
    // rest to the first configured upstream — over DoT when the upstream is TLS
    // with a hostname, otherwise plain UDP. Additive and off by default; the
    // production wire-native listeners (run_dns_server) are left untouched.
    if let Some(port) = std::env::var("RUNBOUND_PLAIN_SERVER_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
    {
        let upstream = cfg.forward_zones.iter().find_map(|fz| {
            let raw = fz.addrs.first()?;
            let ip: std::net::IpAddr = raw.split('@').next().unwrap_or(raw).parse().ok()?;
            if fz.tls {
                // DoT needs an SNI hostname; skip TLS upstreams without one.
                let sni = fz.tls_hostname.clone()?;
                Some(dns::plain_server::Upstream::Dot {
                    ip,
                    sni,
                    config: dns::plain_server::dot_client_config(),
                })
            } else {
                Some(dns::plain_server::Upstream::Udp(std::net::SocketAddr::new(ip, 53)))
            }
        });
        match upstream {
            Some(up) => {
                let up = Arc::new(up);
                let bind = format!("0.0.0.0:{port}");
                let z_udp = Arc::clone(&zones);
                let up_udp = Arc::clone(&up);
                let b_udp = bind.clone();
                tokio::spawn(async move {
                    match tokio::net::UdpSocket::bind(&b_udp).await {
                        Ok(s) => {
                            let _ = dns::plain_server::run(Arc::new(s), z_udp, up_udp).await;
                        }
                        Err(e) => tracing::error!("plain-server UDP bind {b_udp} failed: {e}"),
                    }
                });
                let z_tcp = Arc::clone(&zones);
                let up_tcp = Arc::clone(&up);
                tokio::spawn(async move {
                    match tokio::net::TcpListener::bind(&bind).await {
                        Ok(l) => {
                            let _ = dns::plain_server::run_tcp(l, z_tcp, up_tcp).await;
                        }
                        Err(e) => tracing::error!("plain-server TCP bind {bind} failed: {e}"),
                    }
                });
                info!(port, "hickory-free plain DNS server on UDP+TCP");
            }
            None => tracing::warn!(
                "RUNBOUND_PLAIN_SERVER_PORT set but no usable forward upstream — not started"
            ),
        }
    }

    // ── Background: feed auto-update ───────────────────────────────────────
    tokio::spawn(async move { feeds::feed_update_loop(86400).await });

    // ── Block page server ────────────────────────────────────────────────────────
    if cfg.block_page {
        let bp_cfg = std::sync::Arc::new(blockpage::BlockPageConfig {
            redirect_ip: cfg.block_page_redirect_ip.as_deref().and_then(|s| s.parse().ok()),
            port: if cfg.block_page_port == 0 { 8083 } else { cfg.block_page_port },
            title: if cfg.block_page_title.is_empty() { "Access Blocked".to_string() } else { cfg.block_page_title.clone() },
            org: if cfg.block_page_org.is_empty() { "Runbound DNS Filter".to_string() } else { cfg.block_page_org.clone() },
            allow_bypass: cfg.block_page_allow_bypass,
            bypass_pin: cfg.block_page_bypass_pin.clone(),
        });
        blockpage::start(bp_cfg).await;
    }

    // ── REST API (localhost only, port from api-port directive, default 8081) ──
    let api_port = cfg.api_port.unwrap_or(8080);
    let api_key = init_api_key(cfg.api_key.clone());
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
    let snapshot_cache = stats::new_snapshot_cache(&global_stats);
    tokio::spawn(stats::qps_update_loop(
        Arc::clone(&global_stats),
        Arc::clone(&snapshot_cache),
    ));
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
                Err(e) => {
                    tracing::warn!("Cannot install SIGUSR1 handler: {e}");
                    return;
                }
            };
            loop {
                usr1.recv().await;
                let snap = stats_usr1.snapshot();
                info!(
                    total = snap.total,
                    forwarded = snap.forwarded,
                    blocked = snap.blocked,
                    servfail = snap.servfail,
                    uptime_s = snap.uptime_secs,
                    qps_1m = snap.qps_1m,
                    hit_rate = snap.cache_hit_rate,
                    "SIGUSR1 — live stats dump"
                );
            }
        });
    }

    // ── Upstream health monitor ────────────────────────────────────────────
    let upstreams = upstreams::init_upstreams(cfg);
    // #webui: runbound.conf is now the single source of truth for upstreams.
    // One-shot migration: if a legacy upstreams.json (API-added upstreams) exists,
    // merge it into the live set, regenerate the config so those upstreams survive,
    // then archive the store. Afterwards the file is authoritative and manual edits
    // to the forward-zone take effect on restart.
    {
        let store = base_dir.join("upstreams.json");
        if store.exists() {
            let saved = upstreams::load_upstreams(&base_dir);
            upstreams::merge_persisted(&upstreams, saved);
            let mut c = cfg.clone();
            c.forward_zones = upstreams::rebuild_forward_zones(&upstreams);
            if crate::config::writer::write_config_atomic(&c, std::path::Path::new(&cfg_path)).is_ok() {
                let _ = std::fs::rename(&store, base_dir.join("upstreams.json.migrated"));
                tracing::info!(path = %cfg_path, "migrated upstreams.json into the config — file is now the source of truth");
            }
        }
    }
    {
        let ups = Arc::clone(&upstreams);
        tokio::spawn(async move { upstreams::upstream_health_loop(ups).await });
    }

    let cfg_arc = Arc::new(cfg.clone());
    let dnssec_enabled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(cfg.dnssec_validation));

    // ── #202: sovereign full-recursion (resolution mode + recursor) ───────
    // Created once here so the DNS data path (run_dns_server) and the API (AppState,
    // hot-swap on toggle) share the same handles — same pattern as dnssec_enabled.
    let resolution_mode = dns::recursor::mode_atomic(cfg.resolution_mode);
    let recursor = dns::recursor::shared_recursor(cfg.resolution_mode, cfg.dnssec_validation);
    // #231: apply QNAME minimisation (RFC 9156) to the iterative resolver at startup.
    dns::recursor_wire::set_qname_minimisation(cfg.qname_minimisation);

    // ── Shared DNS resolver (hot-swappable via ArcSwap) ───────────────────
    let resolver = dns::server::create_shared_resolver(cfg)
        .map_err(|e| anyhow::anyhow!("DNS resolver init: {e}"))?;

    // ── Slave/master sync ──────────────────────────────────────────────────
    // Hoist sync_key: master may auto-generate it; both master and slave need it for relay.
    let sync_key_resolved: Option<String> = cfg.sync_key.clone().or_else(|| {
        if cfg.is_master() && cfg.sync_port.is_some() {
            let k = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            info!(
                "No sync-key in config — generated: {}...{}",
                &k[..8],
                &k[k.len() - 4..]
            );
            info!("Add  sync-key: {k}  to both master and slave configs.");
            Some(k)
        } else {
            None
        }
    });

    let sync_journal = if let (true, Some(port)) = (cfg.is_master(), cfg.sync_port) {
        let journal = sync::SyncJournal::new();
        match sync::ensure_sync_cert() {
            Ok((cert_pem, key_pem)) => match sync::cert_sha256_hex(&cert_pem) {
                Ok(fingerprint) => {
                    info!(port, sha256 = %fingerprint, "Sync HTTPS server starting");
                    let j = Arc::clone(&journal);
                    let cert_fp = fingerprint.clone();
                    let sync_key = sync_key_resolved.clone().unwrap_or_default();
                    let allow_priv = cfg.sync_allow_private_relay;
                    tokio::spawn(async move {
                        if let Err(e) = sync::start_master_sync_server(
                            port, j, sync_key, cert_fp, cert_pem, key_pem, allow_priv,
                        )
                        .await
                        {
                            error!("Sync server exited: {e}");
                        }
                    });
                    Some(journal)
                }
                Err(e) => {
                    tracing::warn!("Sync cert fingerprint error: {e}");
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Sync cert error: {e}");
                None
            }
        }
    } else {
        None
    };

    // Hoisted so both SlaveClient and AppState share the same mutex instance.
    let zones_mutex = Arc::new(tokio::sync::Mutex::new(()));
    // Hoisted so both NodeRelay (slave relay) and DNS handler share the same instance.
    let domain_stats = DomainStats::new();
    let alert_tracker = crate::alerts::AlertTracker::new(cfg.alerts.clone(), Some(base_dir.clone()));

    // icmp state hoisted here so NodeRelay (slave relay) can reference it
    let icmp_stats = IcmpStats::new();
    icmp_stats.load_blacklist();
    // #ddos: let alert-rule `block` escalations also hit the kernel-UDP fast-path ban set.
    alert_tracker.set_icmp_stats(Arc::clone(&icmp_stats));

    // #8: load per-subnet filtering policies from disk into the live (slow-path) set.
    subnet_policy::init();

    // SEC-C3: periodic cleanup of expired ICMP ban entries (24h TTL, runs hourly).
    {
        let icmp_cleanup = Arc::clone(&icmp_stats);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                icmp_cleanup.cleanup_expired_bans(86_400);
            }
        });
    }
    let (icmp_en, icmp_rate, icmp_burst_val, icmp_ban_thr) = {
        let p = base_dir.join("icmp.json");
        std::fs::read_to_string(&p).ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .map(|v| (
                v["enable"].as_bool().unwrap_or(cfg.icmp_enabled),
                v["rate_limit"].as_u64().map(|x| x as u32).unwrap_or(cfg.icmp_rate_pps),
                v["burst"].as_u64().map(|x| x as u32).unwrap_or(cfg.icmp_burst),
                v["ban_threshold"].as_u64().map(|x| x as u32).unwrap_or(100),
            ))
            .unwrap_or((cfg.icmp_enabled, cfg.icmp_rate_pps, cfg.icmp_burst, 100))
    };
    let icmp_cfg = Arc::new(std::sync::Mutex::new(IcmpConfig {
        enabled: icmp_en,
        rate_pps: icmp_rate,
        burst: icmp_burst_val,
        ban_threshold: icmp_ban_thr,
    }));

    // Slave node UUID — generated once, persisted to disk (#88).
    let node_id: Option<String> = if cfg.is_slave() {
        match sync::ensure_node_id() {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!("node-id generation failed: {e}");
                None
            }
        }
    } else {
        None
    };

    if cfg.is_slave() {
        match (&cfg.sync_master, &sync_key_resolved) {
            (Some(master), Some(key)) => {
                let client = sync::SlaveClient::new(
                    master,
                    key,
                    cfg.sync_interval,
                    Arc::clone(&zones),
                    Arc::clone(&zones_mutex),
                    Arc::clone(&cfg_arc),
                    Arc::clone(&upstreams),
                    Arc::clone(&alert_tracker),
                    Arc::clone(&icmp_stats),
                );
                tokio::spawn(async move { client.run().await });
                info!("Slave sync started → master {master}");

                // ── Relay server + auto-registration (#85, #88) ──────────────────────
                match cfg.sync_port {
                    None => {
                        warn!("Slave relay disabled — add sync-port to slave config to enable config push and relay forwarding");
                    }
                    Some(port) => {
                        match sync::ensure_relay_cert() {
                            Err(e) => error!("Relay cert generation failed — relay disabled: {e}"),
                            Ok((cert_pem, key_pem)) => {
                                // Start relay TLS server.
                                let relay_state = std::sync::Arc::new(sync::NodeRelay {
                                    zones: Arc::clone(&zones),
                                    zones_mutex: Arc::clone(&zones_mutex),
                                    cfg: Arc::clone(&cfg_arc),
                                    upstreams: Arc::clone(&upstreams),
                                    stats_cache: Arc::clone(&snapshot_cache),
                                    domain_stats: Arc::clone(&domain_stats),
                                    dnssec_enabled: Arc::clone(&dnssec_enabled),
                                    resolver: Arc::clone(&resolver),
                                    resolution_mode: Arc::clone(&resolution_mode),
                                    recursor: recursor.clone(),
                                    icmp_stats: Arc::clone(&icmp_stats),
                                    icmp_cfg: Arc::clone(&icmp_cfg),
                                    base_dir: Arc::new(base_dir.clone()),
                                    alert_tracker: Arc::clone(&alert_tracker),
                                });
                                let sk = key.clone();
                                let cp = cert_pem.clone();
                                let kp = key_pem.clone();
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        sync::start_node_server(port, sk, cp, kp, relay_state).await
                                    {
                                        error!("Node relay server exited: {e}");
                                    }
                                });

                                // Auto-register with master.
                                if let Some(ref nid) = node_id {
                                    match sync::cert_sha256_hex(&cert_pem) {
                                        Err(e) => error!("Relay cert fingerprint error: {e}"),
                                        Ok(fp) => {
                                            // Derive the actual outbound IP toward the master via the
                                            // routing table. cfg.interfaces contains bind addresses
                                            // (e.g. 0.0.0.0) which are not routable from the master.
                                            let master_host = if master.starts_with('[') {
                                                master
                                                    .trim_start_matches('[')
                                                    .split(']')
                                                    .next()
                                                    .unwrap_or("127.0.0.1")
                                                    .to_string()
                                            } else {
                                                master
                                                    .split(':')
                                                    .next()
                                                    .unwrap_or("127.0.0.1")
                                                    .to_string()
                                            };
                                            let slave_ip = std::net::UdpSocket::bind("0.0.0.0:0")
                                                .and_then(|s| {
                                                    s.connect((master_host.as_str(), 1u16))?;
                                                    s.local_addr()
                                                })
                                                .map(|a| a.ip().to_string())
                                                .unwrap_or_else(|_| {
                                                    cfg.interfaces
                                                        .iter()
                                                        .find(|ip| *ip != "0.0.0.0" && *ip != "::")
                                                        .cloned()
                                                        .unwrap_or_else(|| "127.0.0.1".to_string())
                                                });
                                            let relay_host = format!("{slave_ip}:{port}");
                                            let master_addr = master.clone();
                                            let key2 = key.clone();
                                            let nid2 = nid.clone();
                                            let ver = env!("CARGO_PKG_VERSION").to_string();
                                            tokio::spawn(async move {
                                                // Brief delay — let relay server bind before registering.
                                                tokio::time::sleep(std::time::Duration::from_secs(
                                                    2,
                                                ))
                                                .await;
                                                // Retry with exponential backoff until success or shutdown.
                                                let mut delay = 2u64;
                                                loop {
                                                    if api::relay::register_with_master(
                                                        master_addr.clone(),
                                                        key2.clone(),
                                                        nid2.clone(),
                                                        relay_host.clone(),
                                                        fp.clone(),
                                                        ver.clone(),
                                                    )
                                                    .await
                                                    {
                                                        break;
                                                    }
                                                    tokio::time::sleep(
                                                        std::time::Duration::from_secs(delay),
                                                    )
                                                    .await;
                                                    delay = (delay * 2).min(300);
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => tracing::warn!(
                "Slave mode enabled but sync-master or sync-key not set — sync disabled"
            ),
        }
    }

    let xdp_mode = Arc::new(AtomicU8::new(0)); // 0=disabled, 1=drv, 2=skb

    // ── DNS prefetch (FEAT #16, opt-in via prefetch: yes) ─────────────────
    // The background cache-scan refresher lives in `server::build_and_launch` (it
    // needs the handler + XDP cache). Here we only allocate the per-key refresh
    // budget map; `None` disables prefetch. `prefetch-threshold` is retained for
    // config compatibility but unused by the cache-scan design.
    let _ = cfg.prefetch_threshold;
    let prefetch_tracker: Option<Arc<dns::prefetch::PrefetchTracker>> = if cfg.prefetch {
        Some(dns::prefetch::PrefetchTracker::new())
    } else {
        None
    };

    // #33: per-upstream resolvers for racing mode.
    let per_upstream_resolvers = dns::server::create_shared_resolvers_vec();
    if cfg.upstream_racing {
        let addrs = upstreams::upstream_addrs(&upstreams);
        match dns::server::build_per_upstream_resolvers(&addrs, cfg.dnssec_validation) {
            Ok(vec) => {
                info!(
                    count = vec.len(),
                    "upstream-racing: per-upstream resolvers built"
                );
                per_upstream_resolvers.store(Arc::new(vec));
            }
            Err(e) => {
                tracing::warn!(err = %e, "upstream-racing: failed to build per-upstream resolvers — racing disabled")
            }
        }
    }
    let racing_wins: Arc<
        dashmap::DashMap<String, Arc<std::sync::atomic::AtomicU64>, ahash::RandomState>,
    > = Arc::new(dashmap::DashMap::with_hasher(ahash::RandomState::new()));

    let events_tx = sync_journal.as_ref().map(|j| j.events_tx.clone());

    // Set up ICMP ban propagation: relay new bans to slaves.
    // The poll task sends IpAddr values here; we push a PUT /alerts/blocked/{ip} to slaves.
    if let (Some(ref j), Some(ref k)) = (&sync_journal, &sync_key_resolved) {
        let (ban_tx, mut ban_rx) = tokio::sync::mpsc::unbounded_channel::<std::net::IpAddr>();
        let _ = icmp_stats.ban_propagate_tx.set(ban_tx);
        let j_arc = Arc::clone(j);
        let k_str = k.clone();
        tokio::spawn(async move {
            while let Some(ip) = ban_rx.recv().await {
                crate::api::relay::push_to_slaves(
                    &j_arc,
                    &k_str,
                    axum::http::Method::PUT,
                    format!("alerts/blocked/{ip}"),
                    bytes::Bytes::new(),
                );
            }
        });

        // #201: replicate zone DNSSEC keys to slaves every 30 s (model B). Idempotent — the slave
        // only rewrites + rebuilds when a key actually changes. Covers slaves that register later.
        if cfg.local_zone_dnssec {
            let j2 = Arc::clone(j);
            let k2 = k.clone();
            let apexes: Vec<String> = cfg.local_zones.iter().map(|z| z.name.clone()).collect();
            tokio::spawn(async move {
                let base = crate::runtime::base_dir();
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let mut zones = Vec::new();
                    for a in &apexes {
                        if let Ok(name) = crate::dns::wire::Name::from_ascii(a)
                        {
                            if let Some((zone, ksk, zsk)) =
                                crate::dns::zone_signer::export_keys(base, &name)
                            {
                                zones.push(
                                    serde_json::json!({ "zone": zone, "ksk": ksk, "zsk": zsk }),
                                );
                            }
                        }
                    }
                    if !zones.is_empty() {
                        let body = bytes::Bytes::from(
                            serde_json::json!({ "zones": zones }).to_string(),
                        );
                        crate::api::relay::push_to_slaves(
                            &j2,
                            &k2,
                            axum::http::Method::PUT,
                            "dnssec-keys".to_string(),
                            body,
                        );
                    }
                }
            });
        }
    }

    // Multi-user registry — always enabled; users.json created on first POST /api/users.
    let users_json_path = base_dir.join("users.json");
    if users_json_path.exists() {
        tracing::info!(path = %users_json_path.display(), "Loading multi-user registry");
    }
    let user_registry: Option<Arc<crate::multiuser::UserRegistry>> =
        Some(crate::multiuser::UserRegistry::load(&users_json_path));
    // Inject api-key-extra static keys from config (#13).
    if let Some(ref reg) = user_registry {
        for ek in &cfg.extra_api_keys {
            if !ek.key.is_empty() {
                tracing::info!(label = %ek.label, role = ?ek.role, "Injecting static API key");
                reg.inject_static_key(ek.label.clone(), ek.key.clone(), ek.role);
            }
        }
    }

    // #153: XDP blacklist reload channel — sender stored in AppState for API handlers,
    // receiver returned to async_main() for use in the ICMP/XDP poll task.
    let (blacklist_reload_tx, blacklist_reload_rx) = tokio::sync::mpsc::channel::<Vec<String>>(8);

    // Shared DNS rate limiter (XDP fast path + kernel slow path). Created here so AppState
    // holds it for live edits (PATCH /api/config) and the SAME Arc is returned for the data
    // path — one limiter, edited in one place, read everywhere.
    let rate_limiter = RateLimiter::new(
        cfg.rate_limit.unwrap_or(200),
        cfg.rate_limit_burst,
        cfg.rate_limit_prefix_v4,
        cfg.rate_limit_prefix_v6,
    );
    let state = AppState {
        split_horizon: std::sync::Arc::new(std::sync::Mutex::new(cfg.split_horizon.clone())),
        node_health: crate::api::NodeHealth {
            node_id: cfg.node_id.clone(),
            servfail_threshold: cfg.health_servfail_threshold,
            latency_threshold_ms: cfg.health_latency_threshold_ms,
            min_qps: cfg.health_min_qps,
        },
        zones: Arc::clone(&zones),
        tls_cfg: Arc::clone(&tls_cfg),
        rate_limiter: api::ApiRateLimiter::new_public(),
        dns_rate_limiter: Arc::clone(&rate_limiter),
        reload_limiter: Arc::new(api::ReloadLimiter::new()),
        zones_mutex: Arc::clone(&zones_mutex),
        stats: Arc::clone(&global_stats),
        stats_cache: Arc::clone(&snapshot_cache),
        cfg: Arc::clone(&cfg_arc),
        cfg_path,
        log_buffer: Arc::clone(&log_buffer),
        upstreams: Arc::clone(&upstreams),
        sync_journal: sync_journal.clone(),
        sync_key: sync_key_resolved,
        slave_mode: cfg.is_slave(),
        base_dir: Arc::new(base_dir.clone()),
        audit: audit.clone(),
        xdp_active: Arc::clone(&xdp_mode),
        resolver: Arc::clone(&resolver),
        last_flush_at: Arc::new(std::sync::Mutex::new(None)),
        cache_evictions: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        lookup_limiter: Arc::new(api::ReloadLimiter::new_with_params(10.0, 10.0)),
        per_upstream_resolvers: Arc::clone(&per_upstream_resolvers),
        racing_wins: Arc::clone(&racing_wins),
        events_tx,
        domain_stats: Arc::clone(&domain_stats),
        alert_tracker: Arc::clone(&alert_tracker),
        webhook_targets: Arc::new(tokio::sync::RwLock::new(cfg_arc.webhooks.clone())),
        webhook_dispatcher: {
            let targets = Arc::new(tokio::sync::RwLock::new(cfg_arc.webhooks.clone()));
            crate::webhooks::WebhookDispatcher::new(Arc::clone(&targets))
        },
        icmp_stats: Arc::clone(&icmp_stats),
        icmp_cfg: Arc::clone(&icmp_cfg),
        dnssec_enabled: Arc::clone(&dnssec_enabled),
        resolution_mode: Arc::clone(&resolution_mode),
        recursor: recursor.clone(),
        user_registry,
        blacklist_reload_tx: Some(blacklist_reload_tx),
    };
    let app = api::router(state);

    let api_addr = format!("{API_BIND}:{api_port}");
    // Bind with std so the fd is runtime-agnostic; convert inside the API runtime.
    let std_listener = std::net::TcpListener::bind(&api_addr)
        .map_err(|e| anyhow::anyhow!("API bind {api_addr}: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("API set_nonblocking: {e}"))?;
    info!(addr=%api_addr, "REST API listening (localhost only)");

    // Dedicated 2-thread runtime isolated from the DNS runtime.
    // Under DoT rebuild storms the DNS runtime can be flooded with hundreds of
    // tasks/second, which starves axum task slots and freezes the API entirely.
    // A separate runtime gives the HTTP server its own scheduler queue.
    // Box::leak is intentional: the runtime must stay alive for the whole process.
    // Leak the runtime at creation: it lives for the whole process anyway, and leaking
    // it up-front (rather than after the setup below) guarantees no later `?`/unwind can
    // drop a Runtime from within this async context — which panics with
    // "Cannot drop a runtime in a context where blocking is not allowed".
    let api_rt: &'static tokio::runtime::Runtime = Box::leak(Box::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("runbound-api")
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("API runtime: {e}"))?,
    ));
    // #174: optional Unix-domain socket (mode 0600), in addition to localhost TCP.
    // axum 0.7 serve() is TCP-only, so the socket is served via a small hyper-util loop.
    if let Some(sock_path) = cfg.api_socket.clone() {
        let app_unix = app.clone();
        // SEC-J13: only unlink a pre-existing *socket* — never follow a symlink or delete a
        // regular file an attacker may have planted at this path (TOCTOU hardening).
        {
            use std::os::unix::fs::FileTypeExt;
            match std::fs::symlink_metadata(&sock_path) {
                Ok(md) if md.file_type().is_socket() => { let _ = std::fs::remove_file(&sock_path); }
                Ok(_) => { error!(socket = %sock_path, "api-socket path exists and is not a socket — refusing to unlink"); }
                Err(_) => {}
            }
        }
        match tokio::net::UnixListener::bind(&sock_path) {
            Ok(listener) => {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));
                info!(socket = %sock_path, "REST API also listening on Unix socket (mode 0600)");
                api_rt.spawn(async move {
                    loop {
                        let (stream, _) = match listener.accept().await {
                            Ok(s) => s,
                            Err(e) => { tracing::warn!(%e, "API unix accept failed"); break; }
                        };
                        let app_conn = app_unix.clone();
                        tokio::spawn(async move {
                            let io = hyper_util::rt::TokioIo::new(stream);
                            let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                                let mut app_req = app_conn.clone();
                                async move {
                                    let req = req.map(axum::body::Body::new);
                                    tower::Service::call(&mut app_req, req).await
                                }
                            });
                            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                                .serve_connection(io, svc)
                                .await;
                        });
                    }
                });
            }
            Err(e) => tracing::warn!(%e, path = %sock_path, "API Unix socket bind failed"),
        }
    }
    api_rt.spawn(async move {
        let listener =
            tokio::net::TcpListener::from_std(std_listener).expect("TcpListener::from_std failed");
        axum::serve(listener, app).await.ok()
    });

    // ── Embedded web UI server (#4/#91) ───────────────────────────────────────
    if cfg.ui_enabled {
        let ui_addr = format!("{}:{}", cfg.ui_bind, cfg.ui_port);
        match std::net::TcpListener::bind(&ui_addr) {
            Err(e) => {
                error!(addr=%ui_addr, err=%e, "Web UI bind failed — continuing without UI");
            }
            Ok(ui_std_listener) => {
                ui_std_listener.set_nonblocking(true).ok();
                let api_port = cfg.api_port.unwrap_or(8080);
                // Leak at creation — same rationale as api_rt above: the WebUI TLS/cert
                // setup below can `?` (e.g. base_dir not writable), and dropping this
                // Runtime during that unwind would panic in the async context.
                let ui_rt: &'static tokio::runtime::Runtime = Box::leak(Box::new(
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(1)
                        .thread_name("runbound-ui")
                        .enable_all()
                        .build()
                        .map_err(|e| anyhow::anyhow!("Web UI runtime: {e}"))?,
                ));
                if cfg.ui_tls && cfg.ui_tls_acme {
                    // ── ACME DNS-01 path ──────────────────────────────────────
                    if cfg.ui_acme_domain.is_empty() || cfg.ui_acme_email.is_empty() {
                        error!("ui-tls: acme requires ui-acme-domain and ui-acme-email");
                        return Err(anyhow::anyhow!("ACME config incomplete"));
                    }
                    let provider = match cfg.ui_acme_dns.as_str() {
                        "cloudflare" => {
                            if cfg.ui_acme_cf_token.is_empty() {
                                return Err(anyhow::anyhow!("ui-acme-dns: cloudflare requires ui-acme-cf-token"));
                            }
                            acme::DnsProvider::Cloudflare { api_token: cfg.ui_acme_cf_token.clone() }
                        }
                        "hook" => {
                            if cfg.ui_acme_hook.is_empty() {
                                return Err(anyhow::anyhow!("ui-acme-dns: hook requires ui-acme-hook"));
                            }
                            acme::DnsProvider::Hook { script: cfg.ui_acme_hook.clone() }
                        }
                        other => return Err(anyhow::anyhow!("Unknown ui-acme-dns provider: {other} (use cloudflare or hook)")),
                    };
                    let acme_cache = base_dir.join("acme-webui");
                    let acme_cert = if cfg.ui_cert.is_empty() { base_dir.join("webui-acme-cert.pem") }
                                   else { std::path::PathBuf::from(&cfg.ui_cert) };
                    let acme_key  = if cfg.ui_key.is_empty()  { base_dir.join("webui-acme-key.pem")  }
                                   else { std::path::PathBuf::from(&cfg.ui_key)  };
                    let acme_cfg = acme::AcmeDns01Config {
                        email:     cfg.ui_acme_email.clone(),
                        domain:    cfg.ui_acme_domain.clone(),
                        cert_path: acme_cert.clone(),
                        key_path:  acme_key.clone(),
                        cache_dir: acme_cache,
                        provider,
                    };
                    // Provision cert on startup if missing or expiring
                    if acme::needs_renewal(&acme_cert) {
                        info!(domain=%cfg.ui_acme_domain, "ACME DNS-01: provisioning WebUI certificate");
                        acme::ensure_certificate_dns01(&acme_cfg).await
                            .map_err(|e| anyhow::anyhow!("ACME DNS-01 failed: {e}"))?;
                    }
                    let cert_pem = std::fs::read_to_string(&acme_cert)?;
                    let key_pem  = std::fs::read_to_string(&acme_key)?;
                    // No local CA — domain cert is trusted everywhere
                    let ui_app = webui::router(
                        api_port, api_key.clone(), base_dir.clone(), String::new(),
                        Arc::clone(&alert_tracker),
                        Arc::clone(&icmp_stats),
                        sync_journal.as_ref().map(Arc::clone),
                        cfg.bot_ban_duration_secs,
                        cfg.bot_honeypot_enabled,
                        true, // tls_enabled: ACME TLS
                    
        cfg.ui_brand_name.clone(),
        cfg.ui_brand_logo_url.clone(),
        cfg.ui_accent_color.clone(),
        cfg.ui_favicon_url.clone(),
        cfg.about_org.clone(),
        cfg.about_text.clone(),
        cfg.about_support_url.clone(),
    );
                    let initial_cfg = Arc::new(crate::sync::server_tls_config(&cert_pem, &key_pem)?);
                    let tls_state: Arc<tokio::sync::RwLock<Arc<rustls::ServerConfig>>> =
                        Arc::new(tokio::sync::RwLock::new(initial_cfg));
                    // Renewal loop with hot-swap
                    ui_rt.spawn(acme::renewal_loop_dns01(acme_cfg, Arc::clone(&tls_state)));
                    // TLS accept loop (same as CA path — reused below)
                    let ui_port_tls = cfg.ui_port;
                    ui_rt.spawn(async move {
                        use hyper_util::rt::{TokioExecutor, TokioIo};
                        use hyper_util::server::conn::auto::Builder as HyperBuilder;
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        use tower::Service as _;
                        let listener = tokio::net::TcpListener::from_std(ui_std_listener)
                            .expect("ui TcpListener::from_std");
                        let make_svc = ui_app
                            .into_make_service_with_connect_info::<std::net::SocketAddr>();
                        loop {
                            let (tcp, addr) = match listener.accept().await {
                                Ok(x) => x,
                                Err(e) => { warn!("WebUI accept: {e}"); continue; }
                            };
                            let server_cfg = Arc::clone(&*tls_state.read().await);
                            let acceptor   = tokio_rustls::TlsAcceptor::from(server_cfg);
                            let mut ms     = make_svc.clone();
                            tokio::spawn(async move {
                                let mut tcp = tcp;
                                let mut peek = [0u8; 1];
                                if tcp.peek(&mut peek).await.unwrap_or(0) == 1 && peek[0].is_ascii_uppercase() {
                                    let mut buf = vec![0u8; 4096];
                                    let n = tcp.read(&mut buf).await.unwrap_or(0);
                                    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                                    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/").to_owned();
                                    let host_hdr = req.lines().find(|l| l.to_ascii_lowercase().starts_with("host:")).and_then(|l| l.splitn(2, ':').nth(1)).map(|h| h.trim().to_owned());
                                    let location = match host_hdr {
                                        Some(h) if h.contains(':') => format!("https://{h}{path}"),
                                        Some(h) => format!("https://{h}:{ui_port_tls}{path}"),
                                        None => format!("https://{}:{ui_port_tls}{path}", addr.ip()),
                                    };
                                    let body = format!("<a href=\"{location}\">HTTPS required</a>");
                                    let resp = format!("HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                                    tcp.write_all(resp.as_bytes()).await.ok();
                                    return;
                                }
                                let svc = match ms.call(addr).await { Ok(s) => s, Err(_) => return };
                                let svc = hyper_util::service::TowerToHyperService::new(svc);
                                match acceptor.accept(tcp).await {
                                    Ok(tls) => { HyperBuilder::new(TokioExecutor::new()).serve_connection_with_upgrades(TokioIo::new(tls), svc).await.ok(); }
                                    Err(e) => { tracing::debug!(peer=%addr, "WebUI TLS: {e}"); }
                                }
                            });
                        }
                    });
                    info!(addr=%ui_addr, domain=%cfg.ui_acme_domain, "Web UI listening (HTTPS/ACME)");
                } else if cfg.ui_tls {
                    // ── Local CA path ─────────────────────────────────────────
                    let (ca_cert_pem, ca_key_pem) =
                        webui::ensure_webui_ca(&cfg.ui_ca_cert, &cfg.ui_ca_key, &base_dir)?;
                    let ui_app = webui::router(
                        api_port, api_key.clone(), base_dir.clone(), ca_cert_pem.clone(),
                        Arc::clone(&alert_tracker),
                        Arc::clone(&icmp_stats),
                        sync_journal.as_ref().map(Arc::clone),
                        cfg.bot_ban_duration_secs,
                        cfg.bot_honeypot_enabled,
                        true, // tls_enabled: local CA TLS
                    
        cfg.ui_brand_name.clone(),
        cfg.ui_brand_logo_url.clone(),
        cfg.ui_accent_color.clone(),
        cfg.ui_favicon_url.clone(),
        cfg.about_org.clone(),
        cfg.about_text.clone(),
        cfg.about_support_url.clone(),
    );
                    let (cert_pem, key_pem, cert_expires) =
                        webui::ensure_webui_cert(&cfg.ui_cert, &cfg.ui_key, &ca_cert_pem, &ca_key_pem, &base_dir, &cfg.ui_tls_san)?;
                    let initial_cfg = Arc::new(crate::sync::server_tls_config(&cert_pem, &key_pem)?);
                    let tls_state: Arc<tokio::sync::RwLock<Arc<rustls::ServerConfig>>> =
                        Arc::new(tokio::sync::RwLock::new(initial_cfg));

                    // Cert renewal background task (checks every 6 h)
                    {
                        let tls_state2    = Arc::clone(&tls_state);
                        let cert_path_r   = cfg.ui_cert.clone();
                        let key_path_r    = cfg.ui_key.clone();
                        let ca_cert_pem_r = ca_cert_pem.clone();
                        let ca_key_pem_r  = ca_key_pem.clone();
                        let base_dir_r    = base_dir.clone();
                        let tls_san_r     = cfg.ui_tls_san.clone();
                        ui_rt.spawn(async move {
                            let mut interval = tokio::time::interval(
                                std::time::Duration::from_secs(6 * 3600)
                            );
                            interval.tick().await; // skip first tick
                            let mut expires   = cert_expires;
                            let mut last_mtime: Option<std::time::SystemTime> = None;
                            loop {
                                interval.tick().await;
                                let need = if cert_path_r.is_empty() {
                                    // Auto-gen: renew 30 days before expiry
                                    expires
                                        .duration_since(std::time::SystemTime::now())
                                        .map(|d| d.as_secs() < 30 * 24 * 3600)
                                        .unwrap_or(true)
                                } else {
                                    // File mode: reload when cert file changes
                                    let mtime = std::fs::metadata(&cert_path_r)
                                        .and_then(|m| m.modified())
                                        .ok();
                                    let changed = mtime != last_mtime;
                                    if changed { last_mtime = mtime; }
                                    changed
                                };
                                if !need { continue; }
                                match webui::ensure_webui_cert(&cert_path_r, &key_path_r, &ca_cert_pem_r, &ca_key_pem_r, &base_dir_r, &tls_san_r) {
                                    Ok((c, k, new_exp)) => {
                                        match crate::sync::server_tls_config(&c, &k) {
                                            Ok(cfg2) => {
                                                *tls_state2.write().await = Arc::new(cfg2);
                                                expires = new_exp;
                                                info!("WebUI TLS certificate renewed");
                                            }
                                            Err(e) => warn!("WebUI TLS rebuild: {e}"),
                                        }
                                    }
                                    Err(e) => warn!("WebUI cert renewal: {e}"),
                                }
                            }
                        });
                    }

                    // TLS accept loop — with HTTP-to-HTTPS redirect detection
                    let ui_port_tls = cfg.ui_port;
                    ui_rt.spawn(async move {
                        use hyper_util::rt::{TokioExecutor, TokioIo};
                        use hyper_util::server::conn::auto::Builder as HyperBuilder;
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        use tower::Service as _;
                        let listener = tokio::net::TcpListener::from_std(ui_std_listener)
                            .expect("ui TcpListener::from_std");
                        let make_svc = ui_app
                            .into_make_service_with_connect_info::<std::net::SocketAddr>();
                        loop {
                            let (tcp, addr) = match listener.accept().await {
                                Ok(x) => x,
                                Err(e) => { warn!("WebUI accept: {e}"); continue; }
                            };
                            let server_cfg = Arc::clone(&*tls_state.read().await);
                            let acceptor   = tokio_rustls::TlsAcceptor::from(server_cfg);
                            let mut ms     = make_svc.clone();
                            tokio::spawn(async move {
                                let mut tcp = tcp;
                                // Peek at first byte: HTTP methods start with uppercase ASCII.
                                // TLS ClientHello starts with 0x16 (22). If plain HTTP, redirect.
                                let mut peek = [0u8; 1];
                                if tcp.peek(&mut peek).await.unwrap_or(0) == 1
                                    && peek[0].is_ascii_uppercase()
                                {
                                    // Plain HTTP — read request to extract Host + path
                                    let mut buf = vec![0u8; 4096];
                                    let n = tcp.read(&mut buf).await.unwrap_or(0);
                                    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                                    let path = req.lines().next()
                                        .and_then(|l| l.split_whitespace().nth(1))
                                        .unwrap_or("/")
                                        .to_owned();
                                    let host_hdr = req.lines()
                                        .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                                        .and_then(|l| l.splitn(2, ':').nth(1))
                                        .map(|h| h.trim().to_owned());
                                    let location = match host_hdr {
                                        // Host already includes port (e.g. "192.168.8.12:8090")
                                        Some(h) if h.contains(':') => {
                                            format!("https://{h}{path}")
                                        }
                                        // Host without port — append server port
                                        Some(h) => format!("https://{h}:{ui_port_tls}{path}"),
                                        None => format!("https://{}:{ui_port_tls}{path}", addr.ip()),
                                    };
                                    let body = format!("<a href=\"{location}\">HTTPS required</a>");
                                    let resp = format!(
                                        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                        body.len()
                                    );
                                    tcp.write_all(resp.as_bytes()).await.ok();
                                    return;
                                }
                                let svc = match ms.call(addr).await {
                                    Ok(s) => s,
                                    Err(_) => return,
                                };
                                let svc = hyper_util::service::TowerToHyperService::new(svc);
                                match acceptor.accept(tcp).await {
                                    Ok(tls) => {
                                        HyperBuilder::new(TokioExecutor::new())
                                            .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                                            .await
                                            .ok();
                                    }
                                    Err(e) => {
                                        tracing::debug!(peer=%addr, "WebUI TLS: {e}");
                                    }
                                }
                            });
                        }
                    });
                    info!(addr=%ui_addr, "Web UI listening (HTTPS)");
                } else {
                    // Plain HTTP
                    let ui_app = webui::router(
                        api_port, api_key.clone(), base_dir.clone(), String::new(),
                        Arc::clone(&alert_tracker),
                        Arc::clone(&icmp_stats),
                        sync_journal.as_ref().map(Arc::clone),
                        cfg.bot_ban_duration_secs,
                        cfg.bot_honeypot_enabled,
                        false, // tls_enabled: plain HTTP
                    
        cfg.ui_brand_name.clone(),
        cfg.ui_brand_logo_url.clone(),
        cfg.ui_accent_color.clone(),
        cfg.ui_favicon_url.clone(),
        cfg.about_org.clone(),
        cfg.about_text.clone(),
        cfg.about_support_url.clone(),
    );
                    ui_rt.spawn(async move {
                        let listener = tokio::net::TcpListener::from_std(ui_std_listener)
                            .expect("ui TcpListener::from_std failed");
                        axum::serve(listener, ui_app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.ok()
                    });
                    info!(addr=%ui_addr, "Web UI listening (HTTP)");
                }
            }
        }
    }


    // ── Bot defense: background ban eviction task ────────────────────────────
    {
        let eviction_tracker = Arc::clone(&alert_tracker);
        let eviction_ban_tx = icmp_stats.ban_cmd_tx.clone();
        let eviction_journal = if cfg.is_master() { sync_journal.as_ref().map(Arc::clone) } else { None };
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let expired = eviction_tracker.evict_expired();
                for ip in expired {
                    match ip {
                        std::net::IpAddr::V4(ipv4) => {
                            let _ = eviction_ban_tx.send(crate::icmp::IcmpBanCmd::Unban(ipv4));
                        }
                        std::net::IpAddr::V6(ipv6) => {
                            let _ = eviction_ban_tx.send(crate::icmp::IcmpBanCmd::UnbanV6(ipv6));
                        }
                    }
                    if let Some(journal) = &eviction_journal {
                        journal.push(crate::sync::SyncOp::DeleteGlobalBan { ip: ip.to_string() });
                    }
                    tracing::info!(ip = %ip, "bot defense: ban expired, IP unblocked");
                }
            }
        });
    }

    let acl = Arc::new(Acl::from_config(&cfg.access_control));

    Ok((
        zones,
        rate_limiter,
        acl,
        global_stats,
        log_buffer,
        audit,
        xdp_mode,
        resolver,
        prefetch_tracker,
        upstreams,
        per_upstream_resolvers,
        racing_wins,
        domain_stats,
        alert_tracker,
        icmp_stats,
        icmp_cfg,
        dnssec_enabled,
        resolution_mode,
        recursor,
        blacklist_reload_rx,
    ))
}

fn print_help() {
    println!(concat!(
        "runbound ",
        env!("CARGO_PKG_VERSION"),
        " — high-performance DNS server (Unbound drop-in)
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mut warnings = 0u32;
    let mut errors = 0u32;

    // ── 1. Config parse ────────────────────────────────────────────────────
    let cfg = match config::load(path) {
        Ok(c) => {
            println!(
                "[OK]   Config parsed: port={} interfaces={:?}",
                c.port, c.interfaces
            );
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
        if cfg.verbosity > 1 && cfg.port == 53 && cfg.rate_limit.map(|r| r > 0).unwrap_or(true) {
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
        Some(n) => println!("[OK]   Rate limit: {n} QPS per source IP"),
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
            println!(
                "[ERR]  Data directory not writable: {} — {e}",
                base_dir.display()
            );
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
        Ok(_) => println!("[OK]   Port {port} available"),
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
    const CAP_NET_RAW: u64 = 1 << 13;
    const CAP_BPF: u64 = 1 << 39;

    let cap_eff: Option<u64> = std::fs::read_to_string("/proc/self/status")
        .ok()
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
        ("CAP_NET_RAW", CAP_NET_RAW),
        ("CAP_BPF", CAP_BPF),
    ] {
        if cap & bit == 0 {
            println!("[WARN] {name} not available — XDP will be disabled");
            println!(
                "       Fix: sudo setcap cap_net_raw,cap_net_admin,cap_bpf+eip $(which runbound)"
            );
            println!("       Or add AmbientCapabilities={name} to the systemd service");
            *warnings += 1;
        } else {
            println!("[OK]   {name} present");
        }
    }
}

#[cfg(target_os = "linux")]
fn check_cfg_rlimit_memlock(warnings: &mut u32) {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl);
    }
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
        println!(
            "[WARN] RLIMIT_MEMLOCK is limited ({}MB) — XDP UMEM allocation will fail",
            mb
        );
        println!("       Fix: add LimitMEMLOCK=infinity to the systemd service file");
        *warnings += 1;
    } else {
        println!(
            "[INFO] RLIMIT_MEMLOCK = {}MB — running outside systemd.",
            mb
        );
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
        cfg.interfaces
            .first()
            .and_then(|s| {
                let s = s.trim();
                if s == "0.0.0.0" || s == "::" || s.is_empty() {
                    return None;
                }
                if s.parse::<std::net::IpAddr>().is_ok() {
                    return iface_for_ip(s);
                }
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
        println!(
            "[WARN] '{}' is a virtual interface (ipvlan / macvlan / bridge / veth) \
                  — AF/XDP requires a physical NIC or a direct VLAN sub-interface \
                  (e.g. bond0.10).",
            iface_name
        );
        println!("       XDP will be disabled at runtime; DNS will fall back to UDP.");
        println!("       Suggestion: bind Runbound directly to the physical interface");
        println!("       or VLAN sub-interface instead.");
        *warnings += 1;
    } else {
        println!(
            "[OK]   Interface '{}' is physical — XDP compatible",
            iface_name
        );
    }
}

/// Generate a self-signed TLS certificate for DoT / DoH / DoQ.
/// Writes cert.pem and key.pem to /etc/runbound/ (chmod 600 for the key).
fn gen_self_signed_cert(hostname: &str) -> anyhow::Result<()> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let cert_path = "/etc/runbound/cert.pem";
    let key_path = "/etc/runbound/key.pem";

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

    fs::write(cert_path, cert.pem()).map_err(|e| anyhow::anyhow!("write {cert_path}: {e}"))?;

    let key_pem = key_pair.serialize_pem();
    fs::write(key_path, &key_pem).map_err(|e| anyhow::anyhow!("write {key_path}: {e}"))?;

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
/// #9: Background loop that re-evaluates scheduled blocking rules every 60 seconds.
/// When a scheduled entry crosses its time boundary, rebuild the zone set to
/// activate or deactivate the block.
pub async fn schedule_enforce_loop(
    zones: Arc<arc_swap::ArcSwap<dns::local::LocalZoneSet>>,
    cfg_path: String,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let bl = match store::load_blacklist() {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Only do work if any scheduled entries exist
        if bl.entries.iter().all(|e| e.schedule.is_none()) {
            continue;
        }
        let new_cfg = match crate::config::load(&cfg_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let new_zones = build_zone_set(&new_cfg);
        zones.store(Arc::new(new_zones));
        tracing::debug!("schedule_enforce: zone set rebuilt");
    }
}

pub fn build_zone_set(cfg: &UnboundConfig) -> LocalZoneSet {
    // Persisted DNS entries (REST API POST /dns) are folded into the local-data set
    // BEFORE building the zone set, so from_config populates BOTH the wire stores
    // (records_wire/zones_wire/static_names_wire, read by serve_wire) and the
    // hickory maps. Appending only to the hickory maps afterwards left API records
    // invisible to the wire serving path.
    let mut local_data = cfg.local_data.clone();
    if let Ok(st) = store::load() {
        let mut added = 0usize;
        for entry in &st.entries {
            if let Some(rr) = entry.to_rr_string() {
                local_data.push(crate::config::parser::LocalData { rr });
                added += 1;
            }
        }
        if added > 0 {
            tracing::info!(count = added, "Loaded persisted DNS entries");
        }
    }
    let mut zone_set = LocalZoneSet::from_config(&cfg.local_zones, &local_data);

    // Persisted blacklist (override_zone so blacklist always shadows static zones)
    // #9: only apply entries whose schedule is currently active (or have no schedule)
    if let Ok(bl) = store::load_blacklist() {
        let active: Vec<_> = bl.entries.iter()
            .filter(|e| e.schedule.as_ref().map_or(true, |s| s.is_active_now()))
            .collect();
        for entry in &active {
            zone_set.override_zone(&entry.domain, dns::ZoneAction::from(&entry.action));
        }
        if !bl.entries.is_empty() {
            tracing::info!(
                total = bl.entries.len(),
                active = active.len(),
                "Loaded persisted blacklist entries"
            );
        }
    }

    // Feed block-list entries (also override static zones)
    for (domain, action) in feeds::collect_feed_entries() {
        zone_set.override_zone(&domain, dns::ZoneAction::from(&action));
    }

    // For BlockPage zones: insert A record pointing to block page server IP
    if let Some(ref ip_str) = cfg.block_page_redirect_ip {
        if let Ok(bp_ip) = ip_str.parse::<std::net::Ipv4Addr>() {
            // Insert the block-page A record for every BlockPage zone straight into
            // the wire store the serving path reads (records_wire / zones_wire).
            let bp_keys: Vec<Box<[u8]>> = zone_set.zones_wire.iter()
                .filter(|(_, v)| **v == dns::ZoneAction::BlockPage)
                .map(|(k, _)| k.clone())
                .collect();
            for key in bp_keys {
                // Reconstruct the wire Name from its stored (lowercased) wire QNAME.
                if let Ok(wn) = dns::wire::Name::parse(&mut dns::wire::Decoder::new(&key)) {
                    zone_set.records_wire.entry(key).or_default().push(dns::wire::Record {
                        name: wn,
                        rtype: dns::wire::consts::rtype::A,
                        rclass: dns::wire::consts::class::IN,
                        ttl: 10,
                        rdata: dns::wire::Rdata::A(bp_ip),
                    });
                }
            }
        }
    }

    zone_set
}
