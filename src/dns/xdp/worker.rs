// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// XDP worker: poll loop that reads raw Ethernet frames from the AF_XDP RX
// ring, processes local-zone DNS queries entirely in user space, and writes
// DNS responses back to the TX ring.
//
// Each worker owns one XskSocket (one NIC queue).  Workers run on dedicated
// OS threads so the hot path never contends with the Tokio executor.
//
// Fast path (local query answered here):
//   poll() → consume_rx() → parse eth/ip/udp/dns → LocalZoneSet lookup →
//   build response → craft reply frame → enqueue_tx() → kick if needed →
//   return frames to fill ring
//
// Slow path (recursive / unknown name):
//   The XDP program was configured with XDP_PASS fallback, so these packets
//   never reached the AF_XDP socket — hickory-server handles them normally.
//   Within the worker, a query whose name isn't found locally returns None
//   from process_packet(); the frame is recycled without a TX response.

#![deny(unsafe_op_in_unsafe_fn)]

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::LowerName,
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};
use smallvec::SmallVec;

use super::loader::XdpHandle;
/// Return type for `answer_dns_wire()` — three-way dispatch replacing `Option<usize>`.
///
/// Using an explicit enum instead of the footgun `Some(0)` sentinel (#155 review):
///   - `Answered(len)` : response written into `out[0..len]`, send it.
///   - `Fallback`      : case not handled by wire builder → try hickory answer_dns().
///   - `Drop`          : ACL Deny or unrecoverable error → silent drop, no TX, no fallback.
#[derive(Debug)]
pub(crate) enum WireResult {
    Answered(usize),
    Fallback,
    Drop,
}

use crate::dns::wire_builder::{
    build_refused, parse_query, EdnsInfo,
};
use super::socket::{
    create_xsk_socket, get_rx_queue_count, iface_index, is_virtual_interface,
    parent_interface, sanitize_iface_name, XskSocket,
};
use super::umem::{XdpDesc, XdpRingSizes, FRAME_SIZE};
use crate::dns::acl::{Acl, AclAction};
use crate::dns::local::{LocalZoneSet, ZoneAction};
use crate::dns::RateLimiter;

const ETH_HDR: usize = 14;
const IPV4_HDR_MIN: usize = 20;
const IPV6_HDR: usize = 40;
const UDP_HDR: usize = 8;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const PROTO_UDP: u8 = 17;

/// Load the XDP program onto `iface`, open one AF_XDP socket per RX queue,
/// and spawn a dedicated OS thread for each.  Returns `Ok(Some(handle))` when
/// the fast path is active, `Ok(None)` when XDP is cleanly disabled (virtual
/// interface with no detectable parent, self-test failure, or
/// `RUNBOUND_DISABLE_XDP` is set), or `Err` for unexpected errors.
///
/// If `iface` is a virtual interface (bridge, veth, ipvlan, macvlan), the
/// function automatically retries on the physical parent before giving up.
///
/// Emergency escape hatch: set `RUNBOUND_DISABLE_XDP=1` in the environment
/// to skip XDP entirely without editing the config file. Useful when the host
/// is unreachable after XDP bricks the network and rescue-mode boot is needed.
#[allow(clippy::too_many_arguments)]

// ── debug/xdp-tx-multi : per-interface TX instrumentation ─────────────────────
#[cfg(feature = "xdp-debug-counters")]
use std::sync::atomic::{AtomicU64, Ordering as AOrdering};

/// Counters shared across all workers of ONE interface.
/// Logged 1×/sec by a dedicated logger thread; reset after each log.
#[cfg(feature = "xdp-debug-counters")]
pub(crate) struct XdpIfaceCounters {
    pub iface:           String,
    pub rx_drained:      AtomicU64,
    pub answers_built:   AtomicU64,
    pub tx_enqueued:     AtomicU64,
    pub tx_kicks:        AtomicU64,
    pub tx_completed:    AtomicU64,
    pub tx_free_empty:   AtomicU64,
}
#[cfg(feature = "xdp-debug-counters")]
impl XdpIfaceCounters {
    pub fn new(iface: &str) -> Arc<Self> {
        Arc::new(Self {
            iface:         iface.to_owned(),
            rx_drained:    AtomicU64::new(0),
            answers_built: AtomicU64::new(0),
            tx_enqueued:   AtomicU64::new(0),
            tx_kicks:      AtomicU64::new(0),
            tx_completed:  AtomicU64::new(0),
            tx_free_empty: AtomicU64::new(0),
        })
    }
}
// ─────────────────────────────────────────────────────────────────────────────

pub fn start_xdp(
    iface: &str,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl: Arc<Acl>,
    cpu_governor: bool,
    irq_affinity: bool,
    hugepages: bool,
    cache_snapshot: Option<crate::dns::cache_snapshot::SharedCacheSnapshot>,
    domain_routing: bool,
    busy_poll: bool,
    ring_size: Option<u32>,
    xdp_ring_sizes: XdpRingSizes,
    stats: Arc<crate::stats::Stats>,
    domain_stats: Arc<crate::domain_stats::DomainStats>,
) -> Result<Option<XdpHandle>, String> {
    if std::env::var("RUNBOUND_DISABLE_XDP").is_ok() {
        tracing::info!("XDP disabled via RUNBOUND_DISABLE_XDP environment variable");
        return Ok(None);
    }
    if is_virtual_interface(iface) {
        match parent_interface(iface) {
            Some(ref parent) => {
                tracing::warn!(
                    virt = %iface, parent = %parent,
                    "XDP: virtual interface detected — retrying on parent"
                );
                let result = start_xdp_on_iface(
                    parent,
                    zones,
                    rate_limiter,
                    acl,
                    cpu_governor,
                    irq_affinity,
                    hugepages,
                    cache_snapshot,
                    domain_routing,
                    busy_poll,
                    0,   // core_base=0 for virtual parent fallback (mono-iface)
                    ring_size,
                    xdp_ring_sizes,
                    stats,
                    domain_stats,
                );
                if result.as_ref().map(|r| r.is_some()).unwrap_or(false) {
                    tracing::info!(parent = %parent, "XDP active on parent interface");
                }
                return result;
            }
            None => {
                tracing::warn!(
                    iface = %iface,
                    "XDP: virtual interface with no detectable parent — \
                     disabling XDP, falling back to UDP"
                );
                return Ok(None);
            }
        }
    }
    let mut handle = start_xdp_on_iface(
        iface,
        zones,
        rate_limiter,
        acl,
        cpu_governor,
        irq_affinity,
        hugepages,
        cache_snapshot,
        domain_routing,
        busy_poll,
        0,          // core_base — mono-interface: always starts at core 0
        ring_size,
        xdp_ring_sizes,
        stats,
        domain_stats,
    )?;
    // Mono-interface governor: pin on the handle's own cores.
    if cpu_governor {
        if let Some(ref mut h) = handle {
            let cores = crate::cpu::physical_cores();
            let q = get_rx_queue_count(iface).max(1) as usize;
            let n = q.min(cores.len());
            let xdp_cores: Vec<usize> = (0..n).map(|i| cores[i]).collect();
            h.governor_guard = Some(super::governor::pin_performance(&xdp_cores));
        }
    }
    Ok(handle)
}

/// Start XDP fast path on multiple interfaces simultaneously.
///
/// Each interface gets its own set of XskSockets + worker threads, fully
/// independent — mirroring a single-interface start but ×N.
/// Returns a Vec of XdpHandles (one per successfully bound interface).
/// Interfaces that fail to attach log WARN and are skipped (non-fatal).
#[allow(clippy::too_many_arguments)]
pub fn start_xdp_multi(
    ifaces: &[&str],
    zones: Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl: Arc<Acl>,
    cpu_governor: bool,
    irq_affinity: bool,
    hugepages: bool,
    cache_snapshot: Option<crate::dns::cache_snapshot::SharedCacheSnapshot>,
    domain_routing: bool,
    busy_poll: bool,
    ring_size: Option<u32>,
    xdp_ring_sizes: XdpRingSizes,
    stats: Arc<crate::stats::Stats>,
    domain_stats: Arc<crate::domain_stats::DomainStats>,
) -> Vec<XdpHandle> {
    // #162/#163: NUMA-local core selection + Xeon-v2-only cap of 16.
    // Use the NUMA node of the FIRST interface as representative (multi-iface
    // on the same NUMA node is the common case; mixed-NUMA = separate start_xdp_multi calls).
    let nic_numa_node = ifaces.first()
        .map(|iface| crate::cpu::nic_numa_node(iface))
        .unwrap_or(0);
    let numa_sorted_cores = crate::cpu::physical_cores_numa_sorted(nic_numa_node);
    let local_count = numa_sorted_cores.iter().filter(|&&cpu_id| {
        std::path::Path::new(&format!(
            "/sys/devices/system/cpu/cpu{cpu_id}/node{nic_numa_node}"
        )).exists()
    }).count();

    // Cap at 16 ONLY on Xeon v2 + X520 (PCIe bus ceiling ~16 cores, auto-detected).
    // On AMD / Xeon v3+: allow the full sorted pool so queue_count <= cores avoids
    // modulo wrap (e.g. 16 queues, NPS-8 node of 8 local cores → take 16 = 8 local +
    // 8 from neighbour node, 1 queue/core, no wrap, negligible cross-NUMA UMEM cost).
    let is_xeon_v2 = ifaces.first()
        .map(|iface| super::socket::is_xeon_v2_x520_host(iface))
        .unwrap_or(false);
    let core_cap: usize = if is_xeon_v2 {
        16 // X520 PCIe bus ceiling — inchangé
    } else {
        numa_sorted_cores.len() // full pool, local-first; no wrap while queues <= cores
    };
    let physical_cores: Vec<usize> = numa_sorted_cores.iter().copied().take(core_cap).collect();
    let remote_count = core_cap.saturating_sub(local_count);
    let total_phys = physical_cores.len().max(1);

    if is_xeon_v2 {
        tracing::info!(
            numa_node    = nic_numa_node,
            cores        = physical_cores.len(),
            local_cores  = local_count,
            remote_cores = remote_count,
            cap          = "16 (Xeon v2 + X520 PCIe bus ceiling)",
            "XDP: worker core pool selected"
        );
    } else {
        tracing::info!(
            numa_node    = nic_numa_node,
            cores        = physical_cores.len(),
            local_cores  = local_count,
            remote_cores = remote_count,
            cap          = "none (full NUMA-sorted pool)",
            "XDP: worker core pool selected"
        );
    }

    // fix/xdp-multi-iface-affinity: assign each interface a contiguous block
    // of physical cores starting at core_base, accumulated across interfaces.
    // iface0 → [0..n0), iface1 → [n0..n0+n1), ...
    // If total_queues > physical_cores.len(), wraps via modulo (WARN below).
    let mut core_base: usize = 0;
    let mut handles = Vec::new();

    // Collect all XDP worker cores across all interfaces for GovernorGuard union.
    let mut all_xdp_cores: Vec<usize> = Vec::new();

    for &iface in ifaces {
        let queue_count = get_rx_queue_count(iface).max(1) as usize;
        // Warn if we are about to wrap (collision via modulo)
        if core_base + queue_count > total_phys {
            tracing::warn!(
                iface = %iface,
                core_base,
                queue_count,
                physical_cores = total_phys,
                "XDP multi-iface: total queues exceed physical cores —                  wrapping core assignment via modulo. Consider reducing queue count                  or using a machine with more physical cores."
            );
        }
        // Collect the cores this interface will use (before potential wrap)
        for q in 0..queue_count {
            let core_id = physical_cores[(core_base + q) % total_phys];
            if !all_xdp_cores.contains(&core_id) {
                all_xdp_cores.push(core_id);
            }
        }

        match start_xdp_on_iface(
            iface,
            Arc::clone(&zones),
            Arc::clone(&rate_limiter),
            Arc::clone(&acl),
            cpu_governor,
            irq_affinity,
            hugepages,
            cache_snapshot.clone(),
            domain_routing,
            busy_poll,
            core_base,
            ring_size,
            xdp_ring_sizes,
            Arc::clone(&stats),
            Arc::clone(&domain_stats),
        ) {
            Ok(Some(h)) => {
                tracing::info!(
                    iface       = %iface,
                    mode        = ?h.mode,
                    core_base,
                    queue_count,
                    cores       = ?physical_cores.iter()
                                    .skip(core_base % total_phys)
                                    .take(queue_count)
                                    .collect::<Vec<_>>(),
                    "XDP fast path active (core block assigned)"
                );
                handles.push(h);
                core_base += queue_count;
            }
            Ok(None) => {
                tracing::warn!(iface = %iface, "XDP: skipped (virtual / self-test)");
                // Still advance core_base to keep blocks consistent for subsequent ifaces
                core_base += queue_count;
            }
            Err(e) => {
                tracing::warn!(iface = %iface, err = %e, "XDP attach failed — skipping interface");
                core_base += queue_count;
            }
        }
    }

    // fix/xdp-multi-iface-affinity: pin governor on the UNION of all interface
    // core blocks (not just the first 0-15).  One GovernorGuard on the first handle.
    if cpu_governor && !handles.is_empty() && !all_xdp_cores.is_empty() {
        handles[0].governor_guard = Some(
            super::governor::pin_performance(&all_xdp_cores)
        );
        tracing::info!(
            cores = ?all_xdp_cores,
            "xdp-cpu-governor: performance pinned on union of all XDP interface cores"
        );
    }

    if handles.is_empty() {
        tracing::warn!("XDP: no interface could be bound — fast path disabled");
    } else {
        tracing::info!(
            count = handles.len(),
            interfaces = ?ifaces,
            "XDP active on {} interface(s)",
            handles.len()
        );
    }
    handles
}


#[allow(clippy::too_many_arguments)]
fn start_xdp_on_iface(
    iface: &str,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl: Arc<Acl>,
    _cpu_governor: bool,  // governor managed centrally in start_xdp/start_xdp_multi
    irq_affinity: bool,
    hugepages: bool,
    cache_snapshot: Option<crate::dns::cache_snapshot::SharedCacheSnapshot>,
    domain_routing: bool,
    busy_poll: bool,
    core_base: usize,
    ring_size: Option<u32>,
    xdp_ring_sizes: XdpRingSizes,
    stats: Arc<crate::stats::Stats>,
    domain_stats: Arc<crate::domain_stats::DomainStats>,
) -> Result<Option<XdpHandle>, String> {
    let ifidx = iface_index(iface).ok_or_else(|| format!("interface {iface} not found"))?;

    // #80: maximize NIC ring buffers before attaching XDP to prevent hardware
    // FIFO overflow at ≥10M QPS. Silent fallback on EOPNOTSUPP / EPERM.
    // XDP_ACTIVE_IFACE + maximize_nic_ring are now set via register_xdp_iface()
    // after socket bind (post-bind state is authoritative). (#159)

    // Bug B: check MTU before attach — virtio-net refuses DRV mode when MTU > 3506.
    // Falling back to SKB mode is acceptable but must be visible to the operator.
    if let Some(iface_safe) = sanitize_iface_name(iface) {
        if let Ok(s) = std::fs::read_to_string(format!("/sys/class/net/{iface_safe}/mtu")) {
            if let Ok(mtu) = s.trim().parse::<u32>() {
                if mtu > 3506 {
                    tracing::warn!(
                        iface = %iface, mtu, limit = 3506,
                        "MTU exceeds virtio-net single-buffer XDP limit — \
                         DRV mode unavailable, falling back to SKB mode (higher latency). \
                         Reduce MTU to ≤3506 or accept SKB-mode operation."
                    );
                }
            }
        }
    }

    let queue_count = get_rx_queue_count(iface).max(1);
    let mut handle = XdpHandle::load(iface, queue_count, domain_routing)?;
    let num_cpus = crate::cpu::physical_cores().len().max(1);
    tracing::info!(iface = %iface, queues = queue_count, "Starting XDP workers");

    // Bug D: virtio-net often reports a single queue; XDP will use locked TX mode.
    if queue_count == 1 && num_cpus > 1 {
        tracing::warn!(
            iface = %iface, cpus = num_cpus,
            "virtio-net single-queue detected — XDP workers share queue 0 in locked TX \
             mode. For multi-queue performance set queues=<N> in the VM NIC config."
        );
    }

    let cores = crate::cpu::physical_cores();

    // Create all sockets before spawning threads so we can run the self-test.
    let mut sockets: Vec<(u32, XskSocket)> = Vec::with_capacity(queue_count as usize);
    for q in 0..queue_count {
        // S1: XSKMAP is created with max_entries=64; a queue_id ≥ 64 would write
        // outside the map bounds inside the kernel.
        if q >= 64 {
            return Err(format!(
                "queue_id {q} exceeds XSKMAP capacity (64) — \
                 reduce NIC queue count or use SO_REUSEPORT path"
            ));
        }
        // SAFETY: `ifidx` is a valid ifindex returned by `iface_index`. `q` is
        //         in [0, min(queue_count, 64)), which is the valid range of NIC RX
        //         queues. On zero-copy failure we fall back to copy mode.
        let sock = unsafe { create_xsk_socket(ifidx, q, true, hugepages, &xdp_ring_sizes) }
            .or_else(|_| unsafe { create_xsk_socket(ifidx, q, false, hugepages, &xdp_ring_sizes) })
            .map_err(|e| format!("AF_XDP socket creation failed: {e}"))?;
        tracing::info!(
            queue_id = q,
            mode = if sock.zerocopy { "zerocopy" } else { "copy" },
            rx_frames = xdp_ring_sizes.rx,
            tx_frames = xdp_ring_sizes.tx,
            "XDP queue bound"
        );
        handle.register_socket(q, sock.fd)?;
        sockets.push((q, sock));
    }

    let queue_modes: Vec<(u32, bool)> = sockets.iter().map(|(q, s)| (*q, s.zerocopy)).collect();
    // #159: register per-interface state in the Vec registry (works for N interfaces).
    // Also feed compat singleton (first iface wins, subsequent skipped silently).
    let (nic_rx_ring, nic_rx_ring_max) = super::socket::maximize_nic_ring(iface, None);
    super::socket::register_xdp_iface(super::socket::XdpIfaceState {
        iface:           iface.to_owned(),
        queue_modes:     queue_modes.clone(),
        nic_rx_ring,
        nic_rx_ring_max,
    });
    // #164 — Xeon v2 + X520 bus-ceiling hint (one-time at bind).
    super::socket::maybe_warn_xeon_v2_x520(iface);

    // Compat shims — first iface only (existing API callers unchanged).
    super::socket::XDP_QUEUE_MODES.set(queue_modes).ok();
    let _ = super::socket::XDP_ACTIVE_IFACE.set(iface.to_owned());
    super::socket::XDP_NIC_RX_RING.store(nic_rx_ring, std::sync::atomic::Ordering::Relaxed);
    super::socket::XDP_NIC_RX_RING_MAX.store(nic_rx_ring_max, std::sync::atomic::Ordering::Relaxed);

    // #155 — Gate domain-routing OFF when any socket is in true zerocopy mode.
    //
    // This is the hard enforcement (Commit 4): sock.zerocopy is the ground truth
    // (confirmed after AF_XDP bind succeeds with XDP_ZEROCOPY flag), unlike the
    // XdpMode::Drv proxy used for the early WARN in loader.rs.
    //
    // If domain_routing was requested by the user AND any queue is in ZC mode,
    // disable_domain_routing() writes 0 to domain_routing_cfg[0].enabled so the
    // eBPF takes the XSKMAP path on the next packet (ZC fast path).  domain-routing
    // remains active in pure SKB/copy
    // mode where CPUMAP redirect costs nothing extra and cache-locality is useful.
    let any_zerocopy = sockets.iter().any(|(_, s)| s.zerocopy);
    if domain_routing && any_zerocopy {
        tracing::warn!(
            iface         = %iface,
            zerocopy      = true,
            "xdp-domain-routing: yes IGNORÉ — interface is in zerocopy mode. \
             CPUMAP redirect would exit the ZC ring and cause ×40 throughput \
             regression (4.77 M → 120 k qps, #155). \
             Forcing domain-routing OFF; zerocopy fast path preserved. \
             To use domain-routing, switch to SKB/copy mode (no xdp-hugepages)."
        );
        if let Err(e) = handle.disable_domain_routing() {
            tracing::warn!(
                err = %e,
                "domain_routing_cfg gate-off failed — ZC may be compromised;                  check BPF map access (#155)"
            );
        }
    }

    // Self-test on the first socket before committing threads.
    if let Some((_, first_sock)) = sockets.first_mut() {
        if let Err(msg) = xdp_fill_ring_self_test(iface, first_sock) {
            tracing::warn!("{msg}");
            return Ok(None);
        }
    }

    // debug/xdp-tx-multi: per-interface instrumentation counters (feature-gated).
    // Enabled with --features xdp-debug-counters; zero cost in production.
    #[cfg(feature = "xdp-debug-counters")]
    let iface_ctr = XdpIfaceCounters::new(iface);

    // #68: build queue→core map for IRQ affinity pinning after thread spawn.
    let mut queue_to_core: Vec<(u32, usize)> = Vec::with_capacity(sockets.len());
    for (q, sock) in sockets {
        let z = Arc::clone(&zones);
        let rl = Arc::clone(&rate_limiter);
        let acl = Arc::clone(&acl);
        let cs = cache_snapshot.clone();
        // fix/xdp-multi-iface-affinity: offset by core_base so each interface
        // gets a distinct physical-core block (no collision between iface N workers).
        // Wraps via modulo when total_queues > physical_cores (WARN emitted below).
        let core_id = if cores.is_empty() {
            0
        } else {
            cores[(core_base + q as usize) % cores.len()]
        };
        queue_to_core.push((q, core_id));
        let q_idx = q as usize;
        let st = Arc::clone(&stats);
        let ds = Arc::clone(&domain_stats);
        std::thread::Builder::new()
            .name(format!("xdp-{iface}-q{q}"))
            .spawn({
                #[cfg(feature = "xdp-debug-counters")]
                let ctr = Arc::clone(&iface_ctr);
                move || xdp_worker(
                    sock, z, rl, acl, core_id, cs, q_idx, st, ds, busy_poll,
                    #[cfg(feature = "xdp-debug-counters")] ctr,
                )
            })
            .map_err(|e| format!("thread spawn: {e}"))?;
    }
    tracing::info!(
        iface   = %iface,
        workers = queue_to_core.len(),
        "XDP workers spawned — confirm count is queue_count (#fix/xdp-multi-iface-tx)"
    );

    // #68: pin NIC queue IRQs to their XDP worker cores to avoid cross-core cache misses.
    if irq_affinity {
        crate::cpu::set_irq_affinity(iface, &queue_to_core);
    }

    // fix/xdp-multi-iface-affinity: governor is now pinned centrally in
    // start_xdp_multi (or start_xdp for mono-iface) to cover the UNION of
    // all interface core blocks.  Return queue_to_core to the caller instead.

    // #164 — Health monitor thread: log rx_missed_errors + rx_no_dma every 60s.
    // Always compiled (prod observability — NOT behind xdp-debug-counters).
    // Distinguishes NIC/bus-bound (high rx_missed, low CPU) from CPU-bound.
    {
        let iface_health = iface.to_owned();
        std::thread::Builder::new()
            .name(format!("xdp-health-{iface}"))
            .spawn(move || {
                let mut last_missed: u64 = 0;
                let mut last_no_dma: u64 = 0;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                    let missed  = super::socket::read_nic_rx_missed(&iface_health);
                    let no_dma  = super::socket::read_nic_rx_no_dma(&iface_health);
                    let d_missed = missed.saturating_sub(last_missed);
                    let d_no_dma = no_dma.saturating_sub(last_no_dma);
                    last_missed = missed;
                    last_no_dma = no_dma;
                    if d_missed > 0 || d_no_dma > 0 {
                        tracing::warn!(
                            iface = %iface_health, rx_missed = d_missed, rx_no_dma = d_no_dma,
                            "[XDP-HEALTH] NIC dropping: rx_missed={d_missed}/60s rx_no_dma={d_no_dma}/60s. Bottleneck=NIC/PCIe bus, not CPU. (#164)"
                        );
                    } else {
                        tracing::debug!(
                            iface     = %iface_health,
                            rx_missed = d_missed,
                            rx_no_dma = d_no_dma,
                            "[XDP-HEALTH] no NIC drops in last 60s"
                        );
                    }
                }
            })
            .ok();
    }

    // Logger thread: only compiled when xdp-debug-counters feature is active.
    // Zero cost (no atomics, no thread) in production builds.
    #[cfg(feature = "xdp-debug-counters")]
    {
        let ctr = Arc::clone(&iface_ctr);
        std::thread::Builder::new()
            .name(format!("xdp-log-{iface}"))
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let rx  = ctr.rx_drained.swap(0, AOrdering::Relaxed);
                let ans = ctr.answers_built.swap(0, AOrdering::Relaxed);
                let enq = ctr.tx_enqueued.swap(0, AOrdering::Relaxed);
                let kck = ctr.tx_kicks.swap(0, AOrdering::Relaxed);
                let cmp = ctr.tx_completed.swap(0, AOrdering::Relaxed);
                let emp = ctr.tx_free_empty.swap(0, AOrdering::Relaxed);
                tracing::info!(
                    iface = %ctr.iface,
                    rx_drained    = rx,
                    answers_built = ans,
                    tx_enqueued   = enq,
                    tx_kicks      = kck,
                    tx_completed  = cmp,
                    tx_free_empty = emp,
                    "[DBG-TX] per-interface counters"
                );
            })
            .ok();
    }
    Ok(Some(handle))
}

/// Verify the UMEM fill ring was seeded, then inject 3 synthetic DNS frames and
/// poll the RX ring for up to 200 ms.  Returns `Ok(())` if any RX frames arrive,
/// if the TX pool was empty (can't inject — skip loopback check), or if the
/// 200 ms deadline expires without loopback (expected in SKB mode / VM envs).
/// Returns `Err` only if the fill ring was never seeded (UMEM misconfiguration).
fn xdp_fill_ring_self_test(iface: &str, sock: &mut XskSocket) -> Result<(), String> {
    use libc::{poll, pollfd, POLLIN};

    // Emergency bypass for validation/debugging environments where XDP traffic
    // cannot loop back (isolated VMs, CI, Proxmox virtio-net). Set
    // RUNBOUND_SKIP_XDP_SELFTEST=1 to skip the loopback check.
    if std::env::var("RUNBOUND_SKIP_XDP_SELFTEST").is_ok() {
        tracing::warn!(iface = %iface, "XDP self-test bypassed via RUNBOUND_SKIP_XDP_SELFTEST");
        return Ok(());
    }

    // Hard check: fill ring must have been seeded by Umem::new().
    if sock.umem.fill.producer_count() == 0 {
        return Err(format!(
            "XDP self-test failed: fill ring empty or UMEM misconfigured on '{iface}' \
             — disabling XDP, falling back to kernel UDP path"
        ));
    }

    // S5: use the interface's own unicast MAC as dst to avoid ARP storms.
    // Fall back to broadcast only if the address cannot be read.
    let dst_mac =
        super::socket::read_iface_mac(iface).unwrap_or([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    // Inject up to 3 synthetic DNS frames into the TX ring.
    let mut injected = 0u32;
    for _ in 0..3 {
        if let Some(tx_addr) = sock.umem.tx_free.pop_front() {
            // SAFETY: `tx_addr` is a frame offset in the TX pool
            //         (range [RX_FRAME_COUNT*FRAME_SIZE, (RX_FRAME_COUNT+TX_FRAME_COUNT)*FRAME_SIZE)).
            //         FRAME_SIZE fits within `area_len`; `frame_mut` performs the
            //         bounds check and returns None on failure.
            if let Some(frame) = unsafe { sock.umem.frame_mut(tx_addr, FRAME_SIZE as usize) } {
                let len = build_test_frame(frame, dst_mac);
                if len > 0 {
                    sock.tx.enqueue_tx(&[XdpDesc {
                        addr: tx_addr,
                        len: len as u32,
                        options: 0,
                    }]);
                    injected += 1;
                } else {
                    sock.umem.tx_free.push_back(tx_addr);
                }
            } else {
                sock.umem.tx_free.push_back(tx_addr);
            }
        }
    }
    // Kick the driver if needed.
    if sock.tx.needs_wakeup() {
        // SAFETY: `sock.fd` is a valid AF_XDP socket fd owned by `XskSocket`.
        //         Passing null pointers with length 0 and MSG_DONTWAIT is the
        //         documented way to kick the TX driver without sending data.
        unsafe {
            libc::sendto(
                sock.fd,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            );
        }
    }
    // If TX pool was exhausted we can't inject — skip loopback check.
    if injected == 0 {
        return Ok(());
    }

    // Poll RX ring for up to 200 ms — any incoming frame confirms the socket works.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
    let mut rx_descs: Vec<XdpDesc> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let mut pfd = pollfd {
            fd: sock.fd,
            events: POLLIN,
            revents: 0,
        };
        let timeout_ms = (remaining.as_millis() as i32).clamp(1, 20);
        // SAFETY: `&mut pfd` is a valid pointer to a single `pollfd` struct.
        //         nfds=1 matches the array length. `timeout_ms` is a valid
        //         non-negative timeout in milliseconds.
        let ret = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if ret > 0 && (pfd.revents & POLLIN) != 0 {
            sock.rx.consume_rx_into(&mut rx_descs);
            if !rx_descs.is_empty() {
                let addrs: Vec<u64> = rx_descs.iter().map(|d| d.addr).collect();
                sock.umem.fill.enqueue_batch(&addrs);
                tracing::info!(iface = %iface, rx_frames = rx_descs.len(), "XDP self-test passed");
                return Ok(());
            }
        }
        if ret < 0 {
            break;
        }
    }
    // No loopback frames received in 200 ms.
    // In SKB mode (virtio-net, KVM/Proxmox with MTU > 3506), AF_XDP TX frames
    // go through the kernel SKB path and do NOT re-enter the XDP ingress path,
    // so the loopback round-trip never completes.  The fill ring IS seeded, the
    // socket IS bound, and the BPF program IS attached — real ingress DNS traffic
    // will be delivered correctly to the AF_XDP socket.
    tracing::warn!(
        iface = %iface,
        "XDP self-test: no loopback frames in 200 ms \
         (expected in SKB mode / VM environment — XDP remains active)"
    );
    Ok(())
}

/// Build a minimal Ethernet/IPv4/UDP/DNS query frame for the self-test.
/// Destination: 192.0.2.2 (TEST-NET-1, RFC 5737 — not routable).
/// Returns the total frame length, or 0 if `buf` is too small.
fn build_test_frame(buf: &mut [u8], dst_mac: [u8; 6]) -> usize {
    // DNS query: A record for "xdp.test." (ID=0xDEAD)
    const DNS: &[u8] = &[
        0xDE, 0xAD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'x', b'd',
        b'p', 4, b't', b'e', b's', b't', 0, 0x00, 0x01, 0x00, 0x01,
    ];
    const ETH: usize = 14;
    const IP: usize = 20;
    const UDP: usize = 8;
    let total = ETH + IP + UDP + DNS.len();
    if buf.len() < total {
        return 0;
    }

    // Ethernet: unicast dst (interface's own MAC), fake src, EtherType=IPv4
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4: src=192.0.2.1, dst=192.0.2.2, proto=UDP
    let ip_total = (IP + UDP + DNS.len()) as u16;
    buf[ETH] = 0x45; // version=4, IHL=5
    buf[ETH + 1] = 0;
    buf[ETH + 2..ETH + 4].copy_from_slice(&ip_total.to_be_bytes());
    buf[ETH + 4..ETH + 6].copy_from_slice(&[0xDE, 0xAD]); // ID
    buf[ETH + 6..ETH + 8].copy_from_slice(&[0x40, 0x00]); // DF
    buf[ETH + 8] = 64; // TTL
    buf[ETH + 9] = 17; // UDP
    buf[ETH + 10..ETH + 12].fill(0); // checksum placeholder
    buf[ETH + 12..ETH + 16].copy_from_slice(&[192, 0, 2, 1]); // src
    buf[ETH + 16..ETH + 20].copy_from_slice(&[192, 0, 2, 2]); // dst
    let cksum = ipv4_checksum(&buf[ETH..ETH + IP]);
    buf[ETH + 10..ETH + 12].copy_from_slice(&cksum.to_be_bytes());

    // UDP: src_port=12345, dst_port=53
    let udp_len = (UDP + DNS.len()) as u16;
    buf[ETH + IP..ETH + IP + 2].copy_from_slice(&12345u16.to_be_bytes());
    buf[ETH + IP + 2..ETH + IP + 4].copy_from_slice(&53u16.to_be_bytes());
    buf[ETH + IP + 4..ETH + IP + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[ETH + IP + 6..ETH + IP + 8].fill(0); // no UDP checksum

    // DNS payload
    buf[ETH + IP + UDP..total].copy_from_slice(DNS);
    total
}

/// Poll loop for one NIC queue. Runs until the socket fd is closed.
#[allow(clippy::too_many_arguments)]
fn xdp_worker(
    mut sock: XskSocket,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl: Arc<Acl>,
    core_id: usize,
    cache_snapshot: Option<crate::dns::cache_snapshot::SharedCacheSnapshot>,
    worker_id: usize,
    stats: Arc<crate::stats::Stats>,
    domain_stats: Arc<crate::domain_stats::DomainStats>,
    busy_poll: bool,
    #[cfg(feature = "xdp-debug-counters")] counters: Arc<XdpIfaceCounters>,
) {
    use libc::{poll, pollfd, POLLIN};

    crate::cpu::pin_to_cpu(core_id);
    // Migrate UMEM pages to the local NUMA node now that the thread is pinned.
    #[cfg(target_os = "linux")]
    super::umem::rebind_to_local_numa(sock.umem.area, sock.umem.area_len);
    // Pre-allocate scratch buffers outside the hot loop to avoid per-batch
    // heap allocations.  Each Vec retains its capacity across iterations;
    // clear() resets length without releasing memory.
    let mut rxds: Vec<XdpDesc> = Vec::with_capacity(sock.rx.size as usize);
    let mut tx_descs: Vec<XdpDesc> = Vec::with_capacity(sock.rx.size as usize);
    let mut rx_addrs: Vec<u64> = Vec::with_capacity(sock.rx.size as usize);
    let mut dns_scratch: Vec<u8> = Vec::with_capacity(512);

    // perf: busy-drain loop — drain first, sleep only when ring is durably empty.
    // Under flood (ring never empty) this eliminates poll() from the hot path entirely.
    // At idle, after MAX_EMPTY_SPINS consecutive empty drains we call poll(1 ms) to
    // release the CPU; empty_spins resets to 0 after each sleep so we never spin ∞.
    let mut empty_spins: u32 = 0;
    // busy_poll=false → max_empty_spins=0 → poll immédiat (comportement legacy)
    let max_empty_spins: u32 = if busy_poll { 1024 } else { 0 };

    loop {
        let tx_free_before = sock.umem.tx_free.len() as u64;
        sock.umem.reclaim_tx();
        let tx_free_after = sock.umem.tx_free.len() as u64;
        if tx_free_after > tx_free_before {
            #[cfg(feature = "xdp-debug-counters")]
            counters.tx_completed.fetch_add(tx_free_after - tx_free_before, AOrdering::Relaxed);
        }
        if sock.umem.tx_free.is_empty() {
            #[cfg(feature = "xdp-debug-counters")]
            counters.tx_free_empty.fetch_add(1, AOrdering::Relaxed);
        }

        rxds.clear();
        sock.rx.consume_rx_into(&mut rxds);

        if rxds.is_empty() {
            empty_spins += 1;
            if empty_spins >= max_empty_spins {
                // Ring durably empty — sleep to avoid 100% CPU at idle.
                let mut pfd = pollfd { fd: sock.fd, events: POLLIN, revents: 0 };
                // SAFETY: `&mut pfd` is a valid pointer to a single `pollfd`.
                //         nfds=1 matches the array length. timeout=1 ms is valid.
                let ret = unsafe { poll(&mut pfd, 1, 1 /* ms */) };
                if ret < 0 {
                    // poll() error: log and keep running instead of silently
                    // killing the worker — a dead worker leaves rx_drained=0
                    // and is indistinguishable from "no traffic" (#fix/xdp-multi-iface-tx).
                    tracing::warn!(
                        worker = worker_id,
                        err    = %std::io::Error::last_os_error(),
                        "xdp_worker: poll() error — sleeping 1 ms then retrying"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                empty_spins = 0;
            }
            continue;
        }
        // Ring had data — reset spin counter and process the batch.
        empty_spins = 0;
        #[cfg(feature = "xdp-debug-counters")]
        counters.rx_drained.fetch_add(rxds.len() as u64, AOrdering::Relaxed);

        let snapshot = zones.load();
        // #60: load the frozen cache snapshot once per batch — zero-lock read.
        let cache_arc: Option<std::sync::Arc<crate::dns::cache_snapshot::CacheSnapshot>> =
            cache_snapshot.as_ref().map(|s| s.load_full());
        tx_descs.clear();
        rx_addrs.clear();

        // `i` is used only inside #[cfg(target_arch = "x86_64")] for the prefetch hint.
        // Suppress unused_variables on other arches with cfg_attr rather than the _i prefix
        // (which would trigger clippy::unused_enumerate_index instead).
        #[cfg_attr(not(target_arch = "x86_64"), allow(unused_variables))]
        for (i, desc) in rxds.iter().enumerate() {
            // #71: prefetch the next packet's payload into L1 cache while processing
            // this one. _mm_prefetch is a non-faulting hint — safe even for out-of-range
            // addresses; the processor simply ignores an invalid prefetch target.
            #[cfg(target_arch = "x86_64")]
            if let Some(next_desc) = rxds.get(i + 1) {
                // SAFETY: `sock.umem.area` is the base of the mmap'd UMEM region. Adding
                //         next_desc.addr stays within the mapped region for valid kernel-
                //         supplied descriptors; _mm_prefetch never faults on bad addresses.
                unsafe {
                    let next_ptr = sock.umem.area.add(next_desc.addr as usize);
                    std::arch::x86_64::_mm_prefetch(
                        next_ptr as *const i8,
                        std::arch::x86_64::_MM_HINT_T0,
                    );
                }
            }

            rx_addrs.push(desc.addr);

            if let Some(tx_addr) = sock.umem.tx_free.pop_front() {
                // S3: bounds check on kernel-controlled descriptor fields.
                // desc.addr and desc.len come from the XDP RX ring; use checked_add
                // to avoid wrapping on 32-bit and verify desc.len ≤ FRAME_SIZE.
                // Silently skip — never panic, never access memory outside UMEM.
                let end = (desc.addr as usize).checked_add(desc.len as usize);
                if desc.len as usize > FRAME_SIZE as usize
                    || end.map(|e| e > sock.umem.area_len).unwrap_or(true)
                {
                    sock.umem.tx_free.push_back(tx_addr);
                    continue;
                }
                let (rx_frame, tx_frame) = unsafe {
                    // SAFETY: `desc.addr + desc.len <= area_len` is verified by the
                    //         bounds check above. `sock.umem.area` is the base of the
                    //         mmap'd UMEM region (PROT_READ|PROT_WRITE, size=area_len).
                    //         u8 has alignment 1; the resulting slice is valid for the
                    //         duration of this loop iteration only (no aliasing with tx).
                    let rx = std::slice::from_raw_parts(
                        sock.umem.area.add(desc.addr as usize),
                        desc.len as usize,
                    );
                    // SAFETY: `tx_addr` is a frame offset from the TX free pool
                    //         (range [RX_FRAME_COUNT*FRAME_SIZE, …)), disjoint from the
                    //         RX frame above. FRAME_SIZE fits within `area_len`.
                    //         u8 has alignment 1; no other reference to this frame exists
                    //         while `tx_frame` is live.
                    let tx = std::slice::from_raw_parts_mut(
                        sock.umem.area.add(tx_addr as usize),
                        FRAME_SIZE as usize,
                    );
                    (rx, tx)
                };

                // Rate-limit check before processing: extract source IP from
                // the raw frame and consume a token from the shared bucket.
                // Dropped frames are silently recycled — no REFUSED response
                // is crafted in the XDP path (matches `deny` ACL semantics).
                // S4: unwrap_or(true) — frames with no parseable source IP are
                // dropped. Non-IP frames should never reach port 53 via XDP_PASS,
                // but deny-by-default is the correct posture if they do.
                let src_ip = extract_src_ip(rx_frame);

                // PERF-5 (#137): thread-local shadow rate-limit cache.
                // Cache hit skips the DashMap shard lock for 99%+ of known-IP traffic.
                // Allowed TTL = 10ms (token depletion visible within one refill window);
                // denied TTL = 100ms (flood IPs never reach the DashMap).
                thread_local! {
                    static TL_RL: std::cell::RefCell<
                        std::collections::HashMap<std::net::IpAddr, (bool, std::time::Instant)>
                    > = std::cell::RefCell::new(
                        std::collections::HashMap::with_capacity(1024)
                    );
                }
                if src_ip.map(|ip| {
                    let now = std::time::Instant::now();
                    let cached = TL_RL.with(|c| {
                        c.borrow()
                            .get(&ip)
                            .and_then(|&(ok, until)| (now < until).then_some(!ok))
                    });
                    if let Some(drop_pkt) = cached {
                        drop_pkt
                    } else {
                        let ok = rate_limiter.check(ip);
                        TL_RL.with(|c| {
                            let mut cache = c.borrow_mut();
                            if cache.len() >= 1024 { cache.clear(); }
                            let ttl = if ok {
                                std::time::Duration::from_millis(10)
                            } else {
                                std::time::Duration::from_millis(100)
                            };
                            cache.insert(ip, (ok, now + ttl));
                        });
                        !ok
                    }
                }).unwrap_or(true) {
                    sock.umem.tx_free.push_back(tx_addr);
                    continue;
                }

                dns_scratch.clear();
                match process_packet(
                    rx_frame,
                    tx_frame,
                    &snapshot,
                    &acl,
                    src_ip,
                    &mut dns_scratch,
                    cache_arc.as_deref(),
                    &stats,
                    &domain_stats,
                ) {
                    Some(tx_len) => {
                        // Track per-worker packet distribution (#67)
                        if worker_id < crate::dns::cache_snapshot::XDP_WORKER_PKTS.len() {
                            crate::dns::cache_snapshot::XDP_WORKER_PKTS[worker_id]
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        #[cfg(feature = "xdp-debug-counters")]
                        counters.answers_built.fetch_add(1, AOrdering::Relaxed);
                        tx_descs.push(XdpDesc {
                            addr: tx_addr,
                            len: tx_len as u32,
                            options: 0,
                        });
                    }
                    None => {
                        sock.umem.tx_free.push_back(tx_addr);
                    }
                }
            }
        }

        // Return consumed RX frames to the kernel fill ring.
        sock.umem.fill.enqueue_batch(&rx_addrs);

        if !tx_descs.is_empty() {
            #[cfg(feature = "xdp-debug-counters")]
            counters.tx_enqueued.fetch_add(tx_descs.len() as u64, AOrdering::Relaxed);
            sock.tx.enqueue_tx(&tx_descs);

            // Kick the driver.
            //
            // Primary path: XDP_USE_NEED_WAKEUP — kernel sets the flag when it
            // needs userspace to wake it up.  Under moderate load this avoids the
            // sendto() syscall when the driver is already draining the TX ring.
            //
            // Secondary path (fix/xdp-multi-iface-tx): unconditional kick when
            // the TX free pool is empty.  This breaks the deadlock that stalls one
            // interface under flood:
            //
            //   tx_free exhausted → 0 frames enqueued → tx_descs.is_empty() → no
            //   sendto() → kernel never drains TX ring → CQ never updated →
            //   reclaim_tx() returns nothing → tx_free stays empty → ∞ stall.
            //
            // At bas-débit the pool never exhausts so the deadlock never triggers
            // (explains the "works at low QPS, stalls under flood" symptom).
            // The unconditional kick here is a sendto(MSG_DONTWAIT) — cheap
            // (~150 ns) and only emitted when tx_free was actually exhausted this
            // batch, so it is not on the hot path under normal load.
            let need_kick = sock.tx.needs_wakeup() || sock.umem.tx_free.is_empty();
            if need_kick {
                #[cfg(feature = "xdp-debug-counters")]
                counters.tx_kicks.fetch_add(1, AOrdering::Relaxed);
                // SAFETY: `sock.fd` is a valid AF_XDP socket fd owned by `XskSocket`.
                //         Passing null pointers with length 0 and MSG_DONTWAIT is the
                //         documented way to kick the TX driver without sending data.
                unsafe {
                    libc::sendto(
                        sock.fd,
                        std::ptr::null(),
                        0,
                        libc::MSG_DONTWAIT,
                        std::ptr::null(),
                        0,
                    );
                }
            }
        } else if sock.umem.tx_free.is_empty() {
            // No new TX this batch but tx_free is exhausted — the kernel is
            // holding frames in the TX ring that it hasn't completed yet.
            // Kick unconditionally to unblock the completion queue.
            #[cfg(feature = "xdp-debug-counters")]
            counters.tx_kicks.fetch_add(1, AOrdering::Relaxed);
            // SAFETY: same as above.
            unsafe {
                libc::sendto(
                    sock.fd,
                    std::ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null(),
                    0,
                );
            }
        }
    }
}

/// Extract the source IP address from a raw Ethernet frame (IPv4 or IPv6).
/// Returns None for non-IP frames or frames that are too short.
#[inline]
fn extract_src_ip(rx: &[u8]) -> Option<IpAddr> {
    if rx.len() < ETH_HDR {
        return None;
    }
    let ethertype = u16::from_be_bytes([rx[12], rx[13]]);
    match ethertype {
        ETH_P_IP => {
            if rx.len() < ETH_HDR + 20 {
                return None;
            }
            let src: [u8; 4] = rx[ETH_HDR + 12..ETH_HDR + 16].try_into().ok()?;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(src)))
        }
        ETH_P_IPV6 => {
            if rx.len() < ETH_HDR + 40 {
                return None;
            }
            let src: [u8; 16] = rx[ETH_HDR + 8..ETH_HDR + 24].try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(src)))
        }
        _ => None,
    }
}

/// Parse a raw Ethernet frame, answer the DNS query from `zones`, and write
/// the response frame into `tx`.  Returns the number of bytes written on
/// success, or `None` if this frame should not receive an XDP reply.
///
/// `dns_scratch` is a caller-supplied buffer (cleared before each call) used
/// for DNS response serialisation.  Passing a pre-allocated Vec avoids a heap
/// allocation on every packet.
/// `FallbackMsg.socket` is unused by the fallback reader (it replies via its own
/// bound socket); XDP workers have no arrival socket, so we hand it a shared dummy.
fn xdp_fallback_dummy_sock() -> std::sync::Arc<std::net::UdpSocket> {
    static D: std::sync::OnceLock<std::sync::Arc<std::net::UdpSocket>> =
        std::sync::OnceLock::new();
    std::sync::Arc::clone(D.get_or_init(|| {
        std::sync::Arc::new(
            std::net::UdpSocket::bind("0.0.0.0:0").expect("xdp fallback dummy socket"),
        )
    }))
}

fn process_packet(
    rx: &[u8],
    tx: &mut [u8],
    zones: &LocalZoneSet,
    acl: &Acl,
    src_ip: Option<IpAddr>,
    dns_scratch: &mut Vec<u8>,
    cache_snap: Option<&crate::dns::cache_snapshot::CacheSnapshot>,
    stats: &Arc<crate::stats::Stats>,
    domain_stats: &Arc<crate::domain_stats::DomainStats>,
) -> Option<usize> {
    // ── Ethernet ─────────────────────────────────────────────────────────────
    if rx.len() < ETH_HDR {
        return None;
    }
    let ethertype = u16::from_be_bytes([rx[12], rx[13]]);

    let (ip_off, is_v6) = match ethertype {
        ETH_P_IP => (ETH_HDR, false),
        ETH_P_IPV6 => (ETH_HDR, true),
        _ => return None,
    };

    // ── IP ───────────────────────────────────────────────────────────────────
    let (udp_off, ip_hdr_len, src_ip_off, dst_ip_off, ip_len_off) = if !is_v6 {
        if rx.len() < ip_off + IPV4_HDR_MIN {
            return None;
        }
        if rx[ip_off + 9] != PROTO_UDP {
            return None;
        }
        let ihl = (rx[ip_off] & 0x0F) as usize * 4;
        if !(20..=60).contains(&ihl) {
            return None;
        }
        (ip_off + ihl, ihl, ip_off + 12, ip_off + 16, ip_off + 2)
    } else {
        if rx.len() < ip_off + IPV6_HDR {
            return None;
        }
        if rx[ip_off + 6] != PROTO_UDP {
            return None;
        }
        (
            ip_off + IPV6_HDR,
            IPV6_HDR,
            ip_off + 8,
            ip_off + 24,
            ip_off + 4,
        )
    };

    // ── UDP ──────────────────────────────────────────────────────────────────
    if rx.len() < udp_off + UDP_HDR {
        return None;
    }
    let src_port = u16::from_be_bytes([rx[udp_off], rx[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([rx[udp_off + 2], rx[udp_off + 3]]);
    if dst_port != 53 {
        return None;
    }

    let dns_off = udp_off + UDP_HDR;
    if rx.len() <= dns_off {
        return None;
    }
    let dns_in = &rx[dns_off..];

    // ── DNS ──────────────────────────────────────────────────────────────────
    // Fast path 1: local zone (refuse/nxdomain/static).
    // Fast path 2 (#60/#64): XDP cache snapshot — check after local zone miss.
    //
    // DNS payload is written into tx BEFORE checksum computation so that the
    // UDP checksum covers the actual response bytes (fixing a latent bug where
    // the checksum was computed over uninitialised tx bytes).
    // ── DNS fast path ────────────────────────────────────────────────────────
    // Priority: wire fast path > cache snapshot > hickory local zone > drop.
    //
    // answer_dns_wire() (#156): hand-rolled wire builder — zero hickory allocs
    // for A/AAAA/NXDOMAIN/NODATA/REFUSED on static/redirect zones.
    //
    // Fallback to hickory (answer_dns) for: EDNS (has_edns=true), CNAME, MX,
    // TXT, BlockPage, Redirect-complex, ANY, parse fail — correctness preserved.
    //
    // Drop semantics:
    //   WireDrop   = ACL Deny or malformed → no TX, no fallback.
    //   WirePass   = None from wire builder (unsupported case) → try next path.
    //   WireAnswer = Some(len) → response written directly into tx[dns_off..].
    let dns_len = match answer_dns_wire(dns_in, &mut tx[dns_off..], zones, acl, src_ip) {
        // ── ACL Deny or unrecoverable error → silent drop, no TX ─────────
        WireResult::Drop => return None,
        // ── Wire fast path: response already in tx[dns_off..dns_off+len] ─
        WireResult::Answered(len) => len,
        // ── Fallback: case not handled by wire builder → try other paths ─
        WireResult::Fallback => {
            if answer_dns(dns_in, zones, acl, src_ip, dns_scratch) {
                // Hickory local zone (EDNS, CNAME, complex cases).
                let len = dns_scratch.len();
                if dns_off + len > tx.len() {
                    return None;
                }
                tx[dns_off..dns_off + len].copy_from_slice(dns_scratch);
                len
            } else {
                // Not answerable locally. Try the XDP cache; on a MISS, recurse via
                // the hickory fallback channel (#fix(xdp-recursion): forward upstream
                // + fill the cache; the fallback reader replies from its own bound
                // socket). Both the cache-enabled miss AND the cache-disabled case
                // reach here — previously both dropped silently, so XDP-mode
                // recursion never worked.
                let cached = cache_snap.and_then(|snap| {
                    answer_from_cache(dns_in, snap, acl, src_ip, &mut tx[dns_off..], Some(stats), Some(domain_stats))
                });
                match cached {
                    Some(len) => len,
                    None => {
                        if let (Some(tx_ch), Some(ip)) =
                            (crate::dns::kernel_loop::XDP_FALLBACK_TX.get(), src_ip)
                        {
                            let _ = tx_ch.try_send(crate::dns::kernel_loop::FallbackMsg {
                                query: dns_in.to_vec(),
                                peer: std::net::SocketAddr::new(ip, src_port),
                                socket: xdp_fallback_dummy_sock(),
                            });
                        }
                        return None;
                    }
                }
            }
        }
    };

    // ── Build reply frame ────────────────────────────────────────────────────
    let reply_len = dns_off + dns_len;
    if reply_len > tx.len() {
        return None;
    }

    // Ethernet: swap src ↔ dst MAC
    tx[0..6].copy_from_slice(&rx[6..12]);
    tx[6..12].copy_from_slice(&rx[0..6]);
    tx[12..14].copy_from_slice(&rx[12..14]);

    if !is_v6 {
        // IPv4: copy then fix length, swap src/dst, recompute checksum
        tx[ip_off..ip_off + ip_hdr_len].copy_from_slice(&rx[ip_off..ip_off + ip_hdr_len]);
        let new_tot = (ip_hdr_len + UDP_HDR + dns_len) as u16;
        tx[ip_len_off..ip_len_off + 2].copy_from_slice(&new_tot.to_be_bytes());

        let src: [u8; 4] = rx[src_ip_off..src_ip_off + 4].try_into().ok()?;
        let dst: [u8; 4] = rx[dst_ip_off..dst_ip_off + 4].try_into().ok()?;
        tx[ip_off + 12..ip_off + 16].copy_from_slice(&dst);
        tx[ip_off + 16..ip_off + 20].copy_from_slice(&src);

        // RFC 1624 incremental checksum update: only total_length changed.
        // HC' = ~(~HC + ~m + m')  (one's-complement 16-bit arithmetic)
        // src<->dst swap is neutral (same words, same sum). Read from rx
        // (header intact); tx already has new_tot written at ip_len_off.
        let old_cksum = u16::from_be_bytes([rx[ip_off + 10], rx[ip_off + 11]]);
        let old_tot   = u16::from_be_bytes([rx[ip_len_off], rx[ip_len_off + 1]]);
        let cksum = ip_checksum_update(old_cksum, old_tot, new_tot);
        tx[ip_off + 10..ip_off + 12].copy_from_slice(&cksum.to_be_bytes());
    } else {
        // IPv6: copy, set payload length, swap src/dst
        tx[ip_off..ip_off + IPV6_HDR].copy_from_slice(&rx[ip_off..ip_off + IPV6_HDR]);
        let payload_len = (UDP_HDR + dns_len) as u16;
        tx[ip_len_off..ip_len_off + 2].copy_from_slice(&payload_len.to_be_bytes());

        let src: [u8; 16] = rx[src_ip_off..src_ip_off + 16].try_into().ok()?;
        let dst: [u8; 16] = rx[dst_ip_off..dst_ip_off + 16].try_into().ok()?;
        tx[ip_off + 8..ip_off + 24].copy_from_slice(&dst);
        tx[ip_off + 24..ip_off + 40].copy_from_slice(&src);
    }

    // UDP: swap ports, set length
    let udp_len = (UDP_HDR + dns_len) as u16;
    tx[udp_off..udp_off + 2].copy_from_slice(&dst_port.to_be_bytes()); // src = 53
    tx[udp_off + 2..udp_off + 4].copy_from_slice(&src_port.to_be_bytes());
    tx[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());

    // Compute UDP checksum — DNS payload is now in tx (correct!).
    tx[udp_off + 6..udp_off + 8].fill(0);
    let cksum = if !is_v6 {
        let si: [u8; 4] = tx[ip_off + 12..ip_off + 16].try_into().ok()?;
        let di: [u8; 4] = tx[ip_off + 16..ip_off + 20].try_into().ok()?;
        udp_checksum_v4(&si, &di, &tx[udp_off..udp_off + UDP_HDR + dns_len])
    } else {
        let si: [u8; 16] = tx[ip_off + 8..ip_off + 24].try_into().ok()?;
        let di: [u8; 16] = tx[ip_off + 24..ip_off + 40].try_into().ok()?;
        udp_checksum_v6(&si, &di, &tx[udp_off..udp_off + UDP_HDR + dns_len])
    };
    tx[udp_off + 6..udp_off + 8].copy_from_slice(&cksum.to_be_bytes());

    // DNS payload is already in tx — no final copy needed.
    Some(reply_len)
}

fn wire_qname_to_str(wire: &[u8]) -> String {
    let mut s = String::with_capacity(wire.len());
    let mut pos = 0;
    let mut first = true;
    while pos < wire.len() {
        let len = wire[pos] as usize;
        pos += 1;
        if len == 0 { break; }
        if !first { s.push('.'); }
        first = false;
        if pos + len <= wire.len() {
            s.push_str(std::str::from_utf8(&wire[pos..pos + len]).unwrap_or("?"));
        }
        pos += len;
    }
    s
}

/// Look up `query_bytes` in the frozen XDP cache snapshot.
/// On a hit, writes the wire response directly into `tx_dns` (a slice of the TX
/// UMEM frame starting at the DNS payload offset) and returns `Some(len)`.
/// Returns `None` on a miss, ACL deny/refuse, or if `tx_dns` is too small.
///
/// #64: Zero-copy path — no intermediate Vec allocation.  Parses the DNS
/// query header and QNAME directly from raw bytes without calling hickory.
/// Writing directly into the TX frame eliminates one memcpy per cache hit.
///
/// ACL semantics mirror `answer_dns`:
///   Allow  → proceed with cache lookup.
///   Deny   → silent drop (return None, no TX frame crafted).
///   Refuse → return None (let hickory send a proper REFUSED response).

/// Public (crate-visible) wrapper for `answer_dns_wire` — used by `kernel_loop.rs`.
/// Maps internal `WireResult` to `WireResultPub` (identical enum, re-exported).
pub(crate) use WireResult as WireResultPub;

#[inline(always)]
pub(crate) fn answer_dns_wire_pub(
    query_bytes: &[u8],
    out: &mut [u8],
    zones: &LocalZoneSet,
    acl: &Acl,
    src_ip: Option<IpAddr>,
) -> WireResult {
    answer_dns_wire(query_bytes, out, zones, acl, src_ip)
}

/// Public (crate-visible) wrapper for `answer_from_cache` — used by `kernel_loop.rs`.
#[inline(always)]
pub(crate) fn answer_from_cache_pub(
    query_bytes: &[u8],
    cache_snap: &crate::dns::cache_snapshot::CacheSnapshot,
    acl: &Acl,
    src_ip: Option<IpAddr>,
    tx_dns: &mut [u8],
    stats: Option<&Arc<crate::stats::Stats>>,
    domain_stats: Option<&Arc<crate::domain_stats::DomainStats>>,
) -> Option<usize> {
    answer_from_cache(query_bytes, cache_snap, acl, src_ip, tx_dns, stats, domain_stats)
}

fn answer_from_cache(
    query_bytes: &[u8],
    cache_snap: &crate::dns::cache_snapshot::CacheSnapshot,
    acl: &Acl,
    src_ip: Option<IpAddr>,
    tx_dns: &mut [u8],
    stats: Option<&Arc<crate::stats::Stats>>,
    domain_stats: Option<&Arc<crate::domain_stats::DomainStats>>,
) -> Option<usize> {
    // ACL check first — denied clients must not receive cached data.
    if let Some(ip) = src_ip {
        match acl.check(ip) {
            AclAction::Allow => {}
            AclAction::Deny | AclAction::Refuse => return None,
        }
    }

    // ── Zero-copy DNS header parse ────────────────────────────────────────
    // Header layout: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
    // Minimum useful message: 12-byte header + 1-byte QNAME start.
    if query_bytes.len() < 13 {
        return None;
    }

    // QR bit (bit 15): 0 = query, 1 = response.
    // OPCODE (bits 14–11): 0 = standard query.
    let flags = u16::from_be_bytes([query_bytes[2], query_bytes[3]]);
    if flags & 0x8000 != 0 {
        return None;
    } // response — skip
    if flags & 0x7800 != 0 {
        return None;
    } // non-standard opcode

    // Exactly one question section entry expected.
    let qdcount = u16::from_be_bytes([query_bytes[4], query_bytes[5]]);
    if qdcount != 1 {
        return None;
    }

    let qid = [query_bytes[0], query_bytes[1]];

    // ── Parse QNAME — bulk SIMD pass (#152) ─────────────────────────────────
    // Key insight: label length bytes are always 0x00–0x3F, which is below 'A'
    // (0x41). The SIMD lowercase operation only modifies bytes in [0x41, 0x5A].
    // Therefore we can lowercase the ENTIRE QNAME wire encoding in one SIMD
    // call — length bytes and the root \x00 are untouched — then validate
    // compression pointers on the result (already in L1 cache).
    //
    // Old approach: N copy_lowercase_label calls (one per label) + N bounds checks.
    // New approach: 1 find_zero (SIMD \0 scan) + 1 copy_lowercase_label + 1 local walk.
    let qname_region = &query_bytes[12..];
    let zero_pos = match crate::dns::simd::find_zero(qname_region) {
        Some(p) => p,
        None => {
            crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
    };
    // qname_wire_len includes the terminating \x00 byte.
    let qname_wire_len = zero_pos + 1;
    // Packet must contain QTYPE(2) + QCLASS(2) after the QNAME.
    if 12 + qname_wire_len + 4 > query_bytes.len() {
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return None;
    }

    // Bulk lowercase: one SIMD call covering all labels + length bytes + root.
    let mut name_buf: SmallVec<[u8; 64]> = SmallVec::new();
    crate::dns::simd::copy_lowercase_label(&mut name_buf, &qname_region[..qname_wire_len]);

    // Validate label structure on local (L1-cached) name_buf: no compression
    // pointers (0xC0+), labels within bounds, proper termination.
    let mut vpos = 0usize;
    loop {
        if vpos >= name_buf.len() {
            crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        let lb = name_buf[vpos];
        if lb & 0xC0 == 0xC0 {
            crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        if lb == 0 {
            break;
        }
        vpos += 1 + lb as usize;
        if vpos >= name_buf.len() {
            crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
    }
    let pos = 12 + qname_wire_len;

    // QTYPE(2) + QCLASS(2) follow the QNAME.
    if query_bytes.len() < pos + 4 {
        crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    let qtype = u16::from_be_bytes([query_bytes[pos], query_bytes[pos + 1]]);
    let qclass = u16::from_be_bytes([query_bytes[pos + 2], query_bytes[pos + 3]]);

    // ANY queries are not cached (hickory returns NOTIMP per RFC 8482).
    const QTYPE_ANY: u16 = 255;
    if qtype == QTYPE_ANY {
        return None;
    }

    let key = crate::dns::cache_snapshot::QuestionKey {
        name: name_buf,
        qtype,
        qclass,
    };

    let now = std::time::Instant::now();
    if let Some(entry) = cache_snap.get(&key) {
        if entry.expires_at > now && entry.wire_payload.len() >= 2 {
            let wire = &entry.wire_payload;
            // Bail out if the TX frame slice is too small to hold the response.
            if tx_dns.len() < wire.len() {
                crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return None;
            }
            // Write directly into the TX UMEM frame — no intermediate Vec.
            tx_dns[..wire.len()].copy_from_slice(wire);
            // Patch QID (bytes [0..2]) with the client's actual transaction ID.
            tx_dns[0] = qid[0];
            tx_dns[1] = qid[1];
            // #perf: these per-packet stats (a String alloc in domain_stats + a
            // GLOBAL atomic hammered by all 16 workers) were a ~50x throughput
            // regression on the cache hot path — added v0.9.9 (169092b), they made
            // the CACHE slower than the zero-alloc local-zone path (answer_dns_wire).
            // Sample 1/N per-thread (contention-free) and scale the exact counters by
            // N so totals stay accurate; qtype/domain distributions stay proportional.
            const STAT_N: u64 = 64;
            thread_local! { static HIT_SAMPLE: std::cell::Cell<u64> = std::cell::Cell::new(0); }
            let sampled = HIT_SAMPLE.with(|c| { let n = c.get().wrapping_add(1); c.set(n); n % STAT_N == 0 });
            if sampled {
                use std::sync::atomic::Ordering::Relaxed;
                crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_HITS.fetch_add(STAT_N, Relaxed);
                if let Some(s) = stats {
                    s.total.fetch_add(STAT_N, Relaxed);
                    let tc = qtype as usize;
                    if tc < s.qtype_counts.len() { s.qtype_counts[tc].fetch_add(STAT_N, Relaxed); }
                    else { s.qtype_high.fetch_add(STAT_N, Relaxed); }
                }
                if let Some(ds) = domain_stats { ds.inc(&wire_qname_to_str(&key.name)); }
            }
            return Some(wire.len());
        }
    }
    crate::dns::cache_snapshot::XDP_CACHE_SNAPSHOT_MISSES
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    None
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use crate::dns::cache_snapshot::{CacheEntry, CacheSnapshot, QuestionKey};
    use bytes::Bytes;
    use std::time::{Duration, Instant};

    fn make_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        // Build minimal DNS query wire bytes.
        let mut pkt = vec![
            (id >> 8) as u8,
            id as u8, // ID
            0x01,
            0x00, // flags: RD=1, QR=0
            0x00,
            0x01, // QDCOUNT=1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00, // AN/NS/AR = 0
        ];
        // Encode name as wire-format labels
        for label in name.trim_end_matches('.').split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // root label
        pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        pkt
    }

    fn make_cache_key(name: &str, qtype: u16) -> QuestionKey {
        let mut name_buf: SmallVec<[u8; 64]> = SmallVec::new();
        for label in name.trim_end_matches('.').split('.') {
            name_buf.push(label.len() as u8);
            name_buf.extend_from_slice(label.to_ascii_lowercase().as_bytes());
        }
        name_buf.push(0); // root
        QuestionKey {
            name: name_buf,
            qtype,
            qclass: 1,
        }
    }

    fn make_wire_response(id: u16) -> Vec<u8> {
        // Minimal DNS response: id + flags=QR|AA + QDCOUNT=1 + ANCOUNT=1
        vec![
            (id >> 8) as u8,
            id as u8,
            0x84,
            0x00, // QR=1 AA=1 NOERROR
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            // minimal payload to pass length check
        ]
    }

    fn make_snap_with_entry(
        key: QuestionKey,
        payload: Vec<u8>,
        expires_at: Instant,
    ) -> CacheSnapshot {
        let mut snap = CacheSnapshot::default();
        snap.insert(
            key,
            CacheEntry {
                wire_payload: Bytes::from(payload),
                expires_at,
            },
        );
        snap
    }

    #[test]
    fn cache_hit_patches_qid() {
        let key = make_cache_key("example.com", 1);
        // Store with QID=0
        let mut stored = make_wire_response(0);
        stored.extend_from_slice(&[0u8; 4]); // padding so len > 2
        let snap = make_snap_with_entry(key, stored, Instant::now() + Duration::from_secs(300));
        let acl = crate::dns::acl::Acl::from_config(&[]);
        let query = make_query(0xBEEF, "example.com", 1);
        let mut tx_dns = vec![0u8; 512];
        let result = answer_from_cache(&query, &snap, &acl, None, &mut tx_dns, None, None);
        assert!(result.is_some(), "expected cache hit");
        assert_eq!(tx_dns[0], 0xBE, "QID byte 0 patched");
        assert_eq!(tx_dns[1], 0xEF, "QID byte 1 patched");
    }

    #[test]
    fn cache_hit_case_insensitive() {
        let key = make_cache_key("example.com", 1); // lowercase key
        let snap = make_snap_with_entry(
            key,
            make_wire_response(0),
            Instant::now() + Duration::from_secs(300),
        );
        let acl = crate::dns::acl::Acl::from_config(&[]);
        // Query with mixed case — should still hit because we lowercase
        let query = make_query(1, "EXAMPLE.COM", 1);
        let mut tx_dns = vec![0u8; 512];
        let result = answer_from_cache(&query, &snap, &acl, None, &mut tx_dns, None, None);
        assert!(result.is_some(), "cache should hit with uppercase query");
    }

    #[test]
    fn cache_miss_on_expired_entry() {
        let key = make_cache_key("old.example.com", 1);
        let snap = make_snap_with_entry(
            key,
            make_wire_response(0),
            Instant::now() - Duration::from_secs(1), // already expired
        );
        let acl = crate::dns::acl::Acl::from_config(&[]);
        let query = make_query(1, "old.example.com", 1);
        let mut tx_dns = vec![0u8; 512];
        let result = answer_from_cache(&query, &snap, &acl, None, &mut tx_dns, None, None);
        assert!(result.is_none(), "expired entry must not be served");
    }

    #[test]
    fn any_query_not_cached() {
        let key = make_cache_key("example.com", 255);
        let snap = make_snap_with_entry(
            key,
            make_wire_response(0),
            Instant::now() + Duration::from_secs(300),
        );
        let acl = crate::dns::acl::Acl::from_config(&[]);
        let query = make_query(1, "example.com", 255); // QTYPE=ANY
        let mut tx_dns = vec![0u8; 512];
        let result = answer_from_cache(&query, &snap, &acl, None, &mut tx_dns, None, None);
        assert!(
            result.is_none(),
            "ANY queries must not be served from cache"
        );
    }
}

// ── Wire fast path (#156) ─────────────────────────────────────���──────────────
//
// answer_dns_wire() replaces the hickory hot path for the common case:
// A/AAAA/NXDOMAIN/NODATA/REFUSED on static/redirect zones.
//
// Return semantics (THREE distinct outcomes — caller must honour all three):
//
//   Some(len)  → response written into out[0..len], send it.
//   None       → unsupported case (EDNS, CNAME, MX, complex…) → fallback to
//                answer_dns() hickory.  DO NOT DROP.
//
// Drop (ACL Deny, malformed parse) is signalled by returning Some(0) — a
// zero-length DNS payload that process_packet() turns into a drop because
// the upstream reply_len check filters it out.  This keeps None strictly
// meaning "try next path".
//
// NOTE ON EDNS (#156 must-fix):
//   If wq.has_edns == true, we return None → hickory handles it correctly.
//   Sending arcount=0 to an EDNS client breaks EDNS negotiation (clients
//   retry with smaller UDP sizes, performance regression for real traffic).
//   EDNS echo in the fast path is a follow-up once this code is stable.
fn answer_dns_wire(
    query_bytes: &[u8],
    out: &mut [u8],
    zones: &LocalZoneSet,
    acl: &Acl,
    src_ip: Option<IpAddr>,
) -> WireResult {
    // ── Parse ────────────────────────────────────────────────────────────────
    // parse_query() is zero-alloc: reads id, qname via SIMD find_zero,
    // qtype, qclass, and has_edns (arcount scan).  Returns None on malformed.
    let wq = match parse_query(query_bytes) {
        Some(q) => q,
        None => return WireResult::Fallback, // malformed → hickory fallback
    };

    // EDNS gate (#156): DO=1 (DNSSEC) → hickory; otherwise handle with OPT echo.
    // RFC 6891 §7: "If a query included an OPT record, the response MUST include one."
    // The wire path echoes a minimal OPT RR (DO=0, rdlen=0) for non-DNSSEC queries.
    // DO=1 → fallback hickory (DNSSEC validation required, wire path cannot handle).
    let edns_info: Option<EdnsInfo> = wq.edns;
    if let Some(ref e) = edns_info {
        if e.do_bit {
            return WireResult::Fallback; // DNSSEC → hickory
        }
        // else: non-DNSSEC EDNS — continue, wire path will echo OPT in response
    }

    // ANY queries: RFC 8482 HINFO response — let hickory handle it.
    const QTYPE_ANY: u16 = 255;
    if wq.qtype == QTYPE_ANY {
        return WireResult::Fallback;
    }

    // ── ACL check ────────────────────────────────────────────────────────────
    // Mirrors answer_dns() exactly: Deny = silent drop, Refuse = REFUSED wire.
    if let Some(ip) = src_ip {
        match acl.check(ip) {
            AclAction::Allow => {}
            AclAction::Deny => return WireResult::Drop, // drop — no response, no fallback
            AclAction::Refuse => {
                // REFUSED wire: QR=1 AA=0 RCODE=5, echo question.
                return match build_refused(&wq, out, edns_info.as_ref()) {
                Some(l) => WireResult::Answered(l),
                None    => WireResult::Fallback,
            };
            }
        }
    }

    // ── Wire-record fast path (#156 item 3 — Livraison C) ─────────────────────
    //
    // Replaces: wire_qname_to_lower_name (Name::read alloc) + zones.find (parent-walk)
    //           + zones.local_records (Vec<&Record> alloc) + hickory RData dispatch.
    //
    // Hot path for bench/prod (local-data A/AAAA exact-match):
    //   1. normalize_query_qname: copy_lowercase_label on raw wire bytes (SIMD, stack)
    //   2. hash_wire_qname: CRC32c SSE4.2 + Fibonacci spread -> u64
    //   3. wire_records.map.get(key): identity-hasher HashMap, 0 re-hash cycles
    //   4. simd::bytes_eq: anti-collision exact match of wire QNAME
    //   5. build_answer_a_aaaa_wire: writes RR from pre-serialised WireRdata (no hickory)
    //
    // All other cases (NXDOMAIN zone, Refuse zone, BlockPage, wildcard, parent-walk,
    // CNAME, MX, TXT, non-exact-match) -> Fallback -> answer_dns() hickory handles them.
    // Correctness is preserved: the wire path is strictly additive over hickory.
    const QTYPE_A:    u16 = 1;
    const QTYPE_AAAA: u16 = 28;

    if wq.qtype == QTYPE_A || wq.qtype == QTYPE_AAAA {
        // Normalise wire QNAME to lowercase (shared helper = same bytes as load-time index).
        let qname_lc = crate::dns::wire_builder::normalize_query_qname(wq.qname_wire);

        // CRC32c hash (SSE4.2 + Fibonacci spread).
        let key = crate::dns::hasher::hash_wire_qname(&qname_lc);

        // Identity-hashed lookup: 0 re-hash cycles (key IS already a quality hash).
        if let Some(entry) = zones.wire_records.map.get(&key) {
            // Anti-collision: verify full wire QNAME bytes match (guards CRC32c collisions).
            if crate::dns::simd::bytes_eq(&entry.wire_qname, &qname_lc) {
                let recs = if wq.qtype == QTYPE_A {
                    entry.a_records.as_slice()
                } else {
                    entry.aaaa_records.as_slice()
                };

                if !recs.is_empty() {
                    // Build response from pre-serialised WireRdata: zero hickory, zero alloc.
                    if let Some(len) = crate::dns::wire_builder::build_answer_a_aaaa_wire(
                        &wq, out, recs, edns_info.as_ref(),
                    ) {
                        return WireResult::Answered(len);
                    }
                    // Buffer too small (extremely unlikely for A/AAAA) -> hickory.
                }
                // Exact name match but no A/AAAA records for this qtype
                // (e.g. AAAA query on an A-only zone) -> Fallback -> hickory NODATA.
            }
            // CRC32c collision (astronomically rare) -> Fallback -> hickory.
        }
        // No exact wire-record hit -> Fallback -> hickory handles:
        //   - NxDomain zones, Refuse zones, BlockPage zones
        //   - parent-walk (local-zone bench.test. without explicit local-data)
        //   - wildcard zones (*.example.)
        //   - CNAME, MX, TXT and any non-A/AAAA record type
    }
    // Non-A/AAAA qtype (MX, TXT, SRV, NS...) -> hickory unconditionally.

    WireResult::Fallback
}

/// Parse `query_bytes` as a DNS query, look it up in `zones`, write the
/// serialised response into `out`.  Returns false if the query should be
/// forwarded to the kernel (non-local name, not a standard query, ACL deny, etc.).
///
/// ACL enforcement in the XDP path:
///   Allow  → proceed normally.
///   Deny   → silent drop (return false, no TX frame crafted).
///   Refuse → craft a REFUSED response and return true so the TX path sends it.
fn answer_dns(
    query_bytes: &[u8],
    zones: &LocalZoneSet,
    acl: &Acl,
    src_ip: Option<IpAddr>,
    out: &mut Vec<u8>,
) -> bool {
    let msg = match Message::from_bytes(query_bytes) {
        Ok(m) => m,
        Err(_) => return false,
    };
    // #160 RFC 6891 §7: must echo OPT RR in response if query carries one.
    let req_edns: Option<Edns> = msg.edns.clone();
    if msg.message_type != MessageType::Query {
        return false;
    }
    if msg.op_code != OpCode::Query {
        return false;
    }

    let q = match msg.queries.first() {
        Some(q) => q,
        None => return false,
    };

    // ── ACL check ─────────────────────────────────────────────────────────
    // Applied before zone lookup so that Deny/Refuse clients cannot probe
    // local zone membership even in the XDP fast path.
    if let Some(ip) = src_ip {
        match acl.check(ip) {
            AclAction::Allow => {}
            AclAction::Deny => return false, // silent drop — no response
            AclAction::Refuse => {
                // Craft a minimal REFUSED response and send it.
                let mut refused = Message::new(msg.id, MessageType::Response, OpCode::Query);
                refused.metadata.response_code = ResponseCode::Refused;
                refused.metadata.recursion_desired = msg.recursion_desired;
                refused.add_query(q.clone());
                let mut enc = BinEncoder::new(out);
                return refused.emit(&mut enc).is_ok();
            }
        }
    }

    let name = LowerName::from(q.name());
    let rtype = q.query_type();

    // ANY queries go to the normal server (which returns NOTIMP per RFC 8482)
    if rtype == hickory_proto::rr::RecordType::ANY {
        return false;
    }

    let mut resp = Message::new(msg.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = msg.recursion_desired;
    resp.metadata.recursion_available = false;
    resp.add_query(q.clone());

    let zone_action = zones.find(&name); match zone_action {
        Some(ZoneAction::Refuse) => {
            resp.metadata.response_code = ResponseCode::Refused;
            resp.metadata.authoritative = false;
        }
        Some(ZoneAction::NxDomain) | Some(ZoneAction::BlockPage) => {
            // BlockPage: if pre-inserted A record exists, return it; otherwise NxDomain
            let bp_records = zones.local_records(&name, rtype);
            if matches!(zone_action, Some(ZoneAction::BlockPage)) && !bp_records.is_empty() {
                resp.metadata.response_code = ResponseCode::NoError;
                resp.metadata.authoritative = true;
                for r in bp_records { resp.add_answer(r.clone()); }
            } else {
                resp.metadata.response_code = ResponseCode::NXDomain;
                resp.metadata.authoritative = true;
            }
        }
        Some(ZoneAction::Static) | Some(ZoneAction::Redirect) => {
            resp.metadata.authoritative = true;
            let records = zones.local_records(&name, rtype);
            if !records.is_empty() {
                resp.metadata.response_code = ResponseCode::NoError;
                for r in records {
                    resp.add_answer(r.clone());
                }
            } else if zones.name_has_records(&name) {
                // NODATA — name exists, wrong type (RFC 2308)
                resp.metadata.response_code = ResponseCode::NoError;
            } else {
                resp.metadata.response_code = ResponseCode::NXDomain;
            }
        }
        // Name not in any local zone — forward to kernel / hickory-server
        None => return false,
    }

    // #160 RFC 6891 §7: echo OPT RR — client payload capped to 1232, DO bit reflected.
    if let Some(req_opt) = req_edns {
        let mut resp_edns = Edns::new();
        resp_edns.set_max_payload(req_opt.max_payload().min(1232).max(512));
        resp_edns.flags_mut().dnssec_ok = req_opt.flags().dnssec_ok;
        resp.set_edns(resp_edns);
    }
    let mut enc = BinEncoder::new(out);
    resp.emit(&mut enc).is_ok()
}

// ── Checksum helpers ──────────────────────────────────────────────────────────

// Process 8 bytes per loop iteration (4 sixteen-bit words) into a u64 accumulator.
// u64 can hold up to 2^48 words without overflow — far beyond any DNS packet —
// so we fold only once at the end rather than after every addition.
#[inline]
fn ones_complement_sum(data: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    let mut chunks = data.chunks_exact(8);
    for chunk in chunks.by_ref() {
        acc += u16::from_be_bytes([chunk[0], chunk[1]]) as u64
            + u16::from_be_bytes([chunk[2], chunk[3]]) as u64
            + u16::from_be_bytes([chunk[4], chunk[5]]) as u64
            + u16::from_be_bytes([chunk[6], chunk[7]]) as u64;
    }
    let rem = chunks.remainder();
    let mut i = 0;
    while i + 1 < rem.len() {
        acc += u16::from_be_bytes([rem[i], rem[i + 1]]) as u64;
        i += 2;
    }
    if rem.len() % 2 == 1 {
        acc += (rem[rem.len() - 1] as u64) << 8;
    }
    acc
}

fn fold_checksum(mut s: u64) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    let r = !(s as u16);
    if r == 0 {
        0xFFFF
    } else {
        r
    } // RFC 768: 0 is transmitted as all-ones
}

/// RFC 1624 §3 incremental IPv4 checksum update for a single changed 16-bit word.
///
/// HC  = old (valid) header checksum
/// m   = old value of the changed word  (old total_length)
/// m'  = new value of the changed word  (new total_length)
/// HC' = ~(~HC + ~m + m')  — computed in 32-bit, folded to 16-bit.
///
/// Convention: matches fold_checksum() — maps 0x0000 → 0xFFFF (RFC 768).
#[inline]
fn ip_checksum_update(old_cksum: u16, old_word: u16, new_word: u16) -> u16 {
    let mut sum = (!old_cksum) as u32 + (!old_word) as u32 + new_word as u32;
    // Fold carries: at most two passes (sum <= 3 * 0xFFFF = 0x2FFFD).
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    let r = !(sum as u16);
    if r == 0 { 0xFFFF } else { r }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    fold_checksum(ones_complement_sum(header))
}

fn udp_checksum_v4(src: &[u8; 4], dst: &[u8; 4], udp: &[u8]) -> u16 {
    let udp_len = udp.len() as u64;
    let s = ones_complement_sum(src)
        + ones_complement_sum(dst)
        + PROTO_UDP as u64
        + udp_len
        + ones_complement_sum(udp);
    fold_checksum(s)
}

fn udp_checksum_v6(src: &[u8; 16], dst: &[u8; 16], udp: &[u8]) -> u16 {
    // IPv6 pseudo-header: src(16) + dst(16) + UDP length(4) + zeros(3) + next-header(1)
    let udp_len = udp.len() as u32;
    let udp_len_bytes = udp_len.to_be_bytes();
    let s = ones_complement_sum(src)
        + ones_complement_sum(dst)
        + ones_complement_sum(&udp_len_bytes)
        + PROTO_UDP as u64
        + ones_complement_sum(udp);
    fold_checksum(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify the u64 8-byte accumulator produces the same sum as the naive
    // 2-byte u32 reference, across different payload lengths and alignments.
    #[test]
    fn checksum_u64_matches_reference() {
        fn reference_sum(data: &[u8]) -> u64 {
            let mut s: u64 = 0;
            let mut i = 0;
            while i + 1 < data.len() {
                s += u16::from_be_bytes([data[i], data[i + 1]]) as u64;
                i += 2;
            }
            if data.len() % 2 == 1 {
                s += (data[data.len() - 1] as u64) << 8;
            }
            s
        }

        // 64-byte payload (8 full chunks, no remainder)
        let data64: Vec<u8> = (0u8..64).collect();
        assert_eq!(
            ones_complement_sum(&data64),
            reference_sum(&data64),
            "64-byte payload"
        );

        // 65-byte payload (8 full chunks + 1 odd byte)
        let data65: Vec<u8> = (0u8..65).collect();
        assert_eq!(
            ones_complement_sum(&data65),
            reference_sum(&data65),
            "65-byte payload"
        );

        // 6-byte payload (no full 8-byte chunk, pure remainder path)
        let data6 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(
            ones_complement_sum(&data6),
            reference_sum(&data6),
            "6-byte payload"
        );

        // 1-byte payload (odd byte only)
        let data1 = [0x42u8];
        assert_eq!(
            ones_complement_sum(&data1),
            reference_sum(&data1),
            "1-byte payload"
        );

        // Empty payload
        assert_eq!(
            ones_complement_sum(&[]),
            reference_sum(&[]),
            "empty payload"
        );
    }

    /// Correctness guard: ip_checksum_update must be byte-identical to
    /// a full ipv4_checksum recompute on the modified header.
    ///
    /// Method: build a valid IPv4 header with old_tot, compute its checksum
    /// via ipv4_checksum, then assert incremental == full recompute with new_tot.
    #[test]
    fn incremental_checksum_matches_full_recompute() {
        // Build a minimal 20-byte IPv4 header with a given total_length.
        // IHL=5, DSCP=0, TTL=64, proto=17 (UDP), src=12.34.56.78, dst=192.168.1.1
        fn make_ipv4_hdr(tot_len: u16) -> [u8; 20] {
            let mut h = [0u8; 20];
            h[0] = 0x45;                               // Version=4, IHL=5
            h[1] = 0x00;                               // DSCP/ECN
            h[2..4].copy_from_slice(&tot_len.to_be_bytes()); // total length
            h[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
            h[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF, frag=0
            h[8] = 64;                                 // TTL
            h[9] = 17;                                 // proto = UDP
            // h[10..12] = checksum — set below
            h[12..16].copy_from_slice(&[12, 34, 56, 78]);  // src
            h[16..20].copy_from_slice(&[192, 168, 1, 1]);  // dst
            h
        }

        fn full_cksum_with_new_tot(old_hdr: &[u8; 20], new_tot: u16) -> u16 {
            let mut h = *old_hdr;
            h[2..4].copy_from_slice(&new_tot.to_be_bytes());
            h[10..12].fill(0);
            ipv4_checksum(&h)
        }

        let cases: &[(u16, u16)] = &[
            // (old_tot, new_tot) — realistic DNS query→response size change
            (60,  120),    // small query, larger response
            (100, 80),     // response shorter than query
            (20,  1480),   // minimum header → near-MTU
            (0xFFE0, 0xFFF0), // near-overflow: fold carry exercised
            (0xFFFF, 20),  // max → small (carry path)
            (28,  28),     // unchanged: incremental must equal full recompute
            // Zero-sum edge: force a result that would be 0x0000 before convention
            // (hard to construct deterministically; covered by carry-fold cases above)
        ];

        for &(old_tot, new_tot) in cases {
            let hdr = make_ipv4_hdr(old_tot);
            // Compute valid checksum for the query header (old_tot)
            let mut hdr_for_cksum = hdr;
            hdr_for_cksum[10..12].fill(0);
            let old_cksum = ipv4_checksum(&hdr_for_cksum);

            let incremental = ip_checksum_update(old_cksum, old_tot, new_tot);
            let full        = full_cksum_with_new_tot(&hdr, new_tot);

            assert_eq!(
                incremental, full,
                "incremental != full for old_tot={old_tot} new_tot={new_tot}: \
                 got {incremental:#06x}, expected {full:#06x}"
            );
        }
    }

    /// Convention guard: ip_checksum_update never returns 0x0000 (maps to 0xFFFF).
    #[test]
    fn incremental_checksum_zero_convention() {
        // To get 0xFFFF from fold_checksum, the pre-NOT sum must be 0x0000,
        // meaning NOT(result) == 0xFFFF → result == 0x0000 before convention.
        // We verify our function also returns 0xFFFF, not 0x0000, in that case
        // by exhaustive check on a small range of inputs — and by construction
        // via the equivalence test above (if incremental == full and full never
        // returns 0 from ipv4_checksum on a valid header, we're covered).
        // Spot-check: a header whose incremental result would naively be 0.
        // Use brute force on 4-byte toy headers to find such a case.
        let mut found_zero_candidate = false;
        'outer: for a in 0u16..=0xFF {
            for b in 0u16..=0xFF {
                // Minimal 4-byte "header" so ipv4_checksum/fold_checksum can
                // return 0xFFFF (all-ones input → sum=0xFFFF → NOT=0 → 0xFFFF).
                let hdr = [(a >> 8) as u8, (a & 0xFF) as u8,
                           (b >> 8) as u8, (b & 0xFF) as u8];
                let ck = ipv4_checksum(&hdr);
                // Try updating word 0 from a→a: should be idempotent
                let upd = ip_checksum_update(ck, a, a);
                assert_ne!(upd, 0x0000,
                    "ip_checksum_update returned 0x0000 for a={a:#06x} b={b:#06x}");
                if ck == 0xFFFF {
                    found_zero_candidate = true;
                    break 'outer;
                }
            }
        }
        // Ensure we actually exercised the 0xFFFF case
        assert!(found_zero_candidate, "no 0xFFFF checksum found in sweep — test may be incomplete");
    }


    // ─── fix/xdp-multi-iface-affinity tests ─────────────────────────────────

    /// Simulate the core assignment logic for 2 interfaces × N queues.
    /// Verifies zero collision between interface core blocks.
    #[test]
    fn multi_iface_core_assignment_no_collision() {
        // Simulate physical_cores() returning [0..31] (32 physical cores)
        let physical_cores: Vec<usize> = (0..32).collect();
        let total_phys = physical_cores.len();

        let iface0_queues: usize = 16;
        let iface1_queues: usize = 16;

        let core_base_iface0: usize = 0;
        let core_base_iface1: usize = core_base_iface0 + iface0_queues;

        let mut cores_iface0 = Vec::new();
        let mut cores_iface1 = Vec::new();

        for q in 0..iface0_queues {
            cores_iface0.push(physical_cores[(core_base_iface0 + q) % total_phys]);
        }
        for q in 0..iface1_queues {
            cores_iface1.push(physical_cores[(core_base_iface1 + q) % total_phys]);
        }

        // Zero collision: no core appears in both sets
        for c in &cores_iface0 {
            assert!(
                !cores_iface1.contains(c),
                "collision: core {c} appears in both iface0 and iface1 blocks"
            );
        }

        // iface0 gets cores 0-15, iface1 gets cores 16-31
        assert_eq!(cores_iface0, (0usize..16).collect::<Vec<_>>());
        assert_eq!(cores_iface1, (16usize..32).collect::<Vec<_>>());
    }

    /// Verify wrap-on-overflow: when total_queues > physical_cores, indices wrap
    /// via modulo — no panic, no OOB.
    #[test]
    fn multi_iface_core_wrap_no_panic() {
        let physical_cores: Vec<usize> = (0..4).collect(); // only 4 physical cores
        let total_phys = physical_cores.len();

        // 2 ifaces × 4 queues = 8 workers on 4 cores → wrap
        let iface0_queues: usize = 4;
        let iface1_queues: usize = 4;
        let core_base_iface1 = iface0_queues; // = 4

        // Must not panic
        for q in 0..iface1_queues {
            let core_id = physical_cores[(core_base_iface1 + q) % total_phys];
            // Core IDs should wrap: (4+0)%4=0, (4+1)%4=1, ... same as iface0 (collision via wrap)
            assert!(core_id < total_phys, "core_id {core_id} out of range");
        }
    }

    /// Governor union covers all interfaces: for 2 ifaces × 2 queues on 4 cores,
    /// the union set has exactly 4 distinct core IDs, not just the first 2.
    #[test]
    fn multi_iface_governor_covers_union() {
        let physical_cores: Vec<usize> = (0..8).collect();
        let total_phys = physical_cores.len();

        let iface0_queues = 2usize;
        let iface1_queues = 2usize;

        let mut all_xdp_cores: Vec<usize> = Vec::new();

        let core_base_iface0 = 0;
        for q in 0..iface0_queues {
            let c = physical_cores[(core_base_iface0 + q) % total_phys];
            if !all_xdp_cores.contains(&c) { all_xdp_cores.push(c); }
        }
        let core_base_iface1 = iface0_queues;
        for q in 0..iface1_queues {
            let c = physical_cores[(core_base_iface1 + q) % total_phys];
            if !all_xdp_cores.contains(&c) { all_xdp_cores.push(c); }
        }

        // Union = 4 distinct cores (0,1 from iface0 + 2,3 from iface1)
        assert_eq!(all_xdp_cores.len(), 4,
            "governor union should cover all 4 distinct XDP cores, got {:?}", all_xdp_cores);
        assert_eq!(all_xdp_cores, vec![0usize, 1, 2, 3]);
    }

}

#[cfg(test)]
mod tests_edns_160 {
    //! #160 — OPT echo in answer_dns() slow path (RFC 6891 §7).

    use hickory_proto::{
        op::{Edns, Message, MessageType, OpCode},
        rr::RecordType,
        serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
    };
    use crate::config::parser::{LocalData, LocalZone};
    use crate::dns::local::LocalZoneSet;
    use crate::dns::acl::Acl;

    fn build_query(name: &str, rtype: RecordType, udp_payload: Option<u16>) -> Vec<u8> {
        use hickory_proto::{op::Query, rr::Name};
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_utf8(name).unwrap(), rtype));
        if let Some(payload) = udp_payload {
            let mut edns = Edns::new();
            edns.set_max_payload(payload);
            msg.set_edns(edns);
        }
        let mut buf = Vec::new();
        let mut enc = BinEncoder::new(&mut buf);
        msg.emit(&mut enc).unwrap();
        buf
    }

    fn parse_opt_payload(wire: &[u8]) -> Option<u16> {
        let msg = Message::from_bytes(wire).ok()?;
        msg.edns.map(|e| e.max_payload())
    }

    fn make_zones() -> LocalZoneSet {
        let zones = vec![LocalZone { name: "bench.test.".to_string(), zone_type: "static".to_string() }];
        let data  = vec![LocalData { rr: "a.bench.test. 60 IN A 203.0.113.1".to_string() }];
        LocalZoneSet::from_config(&zones, &data)
    }

    fn make_acl() -> Acl {
        Acl::from_config(&[])
    }

    #[test]
    fn edns_query_gets_opt_echoed() {
        let (zones, acl) = (make_zones(), make_acl());
        let q = build_query("a.bench.test.", RecordType::A, Some(1232));
        let mut out = Vec::new();
        assert!(super::answer_dns(&q, &zones, &acl, None, &mut out));
        let payload = parse_opt_payload(&out);
        assert_eq!(payload, Some(1232), "OPT must be echoed with client payload");
    }

    #[test]
    fn non_edns_query_gets_no_opt() {
        let (zones, acl) = (make_zones(), make_acl());
        let q = build_query("a.bench.test.", RecordType::A, None);
        let mut out = Vec::new();
        assert!(super::answer_dns(&q, &zones, &acl, None, &mut out));
        let payload = parse_opt_payload(&out);
        assert_eq!(payload, None, "no OPT expected for non-EDNS query");
    }

    #[test]
    fn edns_payload_capped_at_1232() {
        let (zones, acl) = (make_zones(), make_acl());
        let q = build_query("a.bench.test.", RecordType::A, Some(4096)); // oversized
        let mut out = Vec::new();
        assert!(super::answer_dns(&q, &zones, &acl, None, &mut out));
        let payload = parse_opt_payload(&out);
        assert_eq!(payload, Some(1232), "payload must be capped to 1232");
    }
}
