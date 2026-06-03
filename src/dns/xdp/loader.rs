// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Load the compiled XDP eBPF program, attach it to a NIC, and manage the
// XSKMAP that maps queue_id → AF_XDP socket fd.
//
// The dns_xdp.o object is embedded at compile time — no files to deploy.
// Aya (pure Rust) handles ELF parsing, BPF syscalls, and map creation.

use std::os::fd::RawFd;

use aya::programs::xdp::XdpLinkId;
use aya::{
    maps::{Array, CpuMap, HashMap, PerCpuArray, PerCpuHashMap, XskMap},
    programs::{Xdp, XdpFlags},
    Ebpf, EbpfLoader,
};

/// Full XDP binary — includes BPF_MAP_TYPE_CPUMAP for domain-affinity routing.
/// `include_bytes!` aligns to 1 byte, but aya's ELF64 parser (via the `object`
/// crate) requires 8-byte alignment for the ELF header read. We copy to a
/// heap-allocated Vec<u64> inside `load_ebpf_bytes()` before calling `Ebpf::load()`.
static XDP_PROG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dns_xdp.o"));

/// Minimal XDP binary — compiled with -DNO_CPUMAP.
/// Used as fallback when BPF_MAP_TYPE_CPUMAP creation fails on the target host
/// (slave VM, restricted CAP_BPF, or kernel < 4.15 without CPUMAP support).
/// Domain routing is disabled when this binary is active; XSKMAP (RSS) is used.
static XDP_PROG_MINIMAL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dns_xdp_minimal.o"));

/// BPF map entry mirroring `struct icmp_cfg_entry` in dns_xdp.c.
/// Must match the C struct layout exactly (repr(C), same padding).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct IcmpCfgEntry {
    pub enabled: u8,
    pub _pad: [u8; 3],
    pub rate_pps: u32,
    pub burst: u32,
}

// SAFETY: IcmpCfgEntry is a plain C struct with no pointers.
unsafe impl aya::Pod for IcmpCfgEntry {}

/// #155 — BPF map entry mirroring `struct domain_routing_cfg_entry` in dns_xdp.c.
/// Replaces `volatile const DOMAIN_ROUTING_ENABLED` (frozen .rodata) with a
/// runtime-writable Array map so the gate-off can happen AFTER zerocopy bind.
/// Must match the C struct layout exactly (repr(C), same padding).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct DomainRoutingCfgEntry {
    /// 1 = CPUMAP domain routing active; 0 = XSKMAP RSS/ZC fast path.
    pub enabled: u8,
    pub _pad: [u8; 3],
}

// SAFETY: DomainRoutingCfgEntry is a plain C struct with no pointers.
unsafe impl aya::Pod for DomainRoutingCfgEntry {}

/// XDP attachment mode — reported by GET /api/system as `xdp_mode`.
#[derive(Clone, Copy, Debug)]
pub enum XdpMode {
    Drv,
    Skb,
}

/// RAII handle for the loaded XDP program.
///
/// Dropping this struct detaches the XDP program from the NIC and destroys
/// all BPF maps. Without explicit detach the program would remain attached
/// after process exit (prevents NIC hot-unplug and re-attach on restart).
pub struct XdpHandle {
    bpf: Ebpf,
    link_id: Option<XdpLinkId>,
    pub mode: XdpMode,
    /// #158: GovernorGuard holds original governors for XDP worker cores.
    /// Restores them on Drop so the OS scheduler is left in its original state.
    pub(crate) governor_guard: Option<super::governor::GovernorGuard>,
    /// #155: true iff CPUMAP-based domain routing is actually active at runtime.
    /// Starts as `actual_routing` from load(); can be forced to false by
    /// `disable_domain_routing()` when zerocopy is confirmed on a socket.
    pub(crate) domain_routing_active: bool,
}

impl Drop for XdpHandle {
    fn drop(&mut self) {
        if let Some(id) = self.link_id.take() {
            if let Some(prog) = self.bpf.program_mut("dns_xdp") {
                if let Ok(xdp) = <&mut Xdp>::try_from(prog) {
                    let _ = xdp.detach(id);
                }
            }
        }
        // GovernorGuard::drop() restores the original governors automatically.
        drop(self.governor_guard.take());
    }
}

impl XdpHandle {
    /// Load and attach the DNS XDP filter to `iface`.
    ///
    /// - `nb_workers`: number of XDP worker threads (injected into the eBPF global
    ///   `NB_WORKERS`); used for CPUMAP domain-affinity routing.
    /// - `domain_routing`: if true, enable CPUMAP-based per-domain CPU affinity (#67).
    ///
    /// Tries the full binary (with CPUMAP) first.  If BPF_MAP_TYPE_CPUMAP
    /// creation fails (missing CAP_BPF, slave VM, old kernel), retries with the
    /// minimal binary (-DNO_CPUMAP) and disables domain routing automatically.
    ///
    /// Tries native (DRV) mode first for lowest latency; falls back to
    /// generic (SKB) mode if the driver does not support native XDP.
    pub fn load(iface: &str, nb_workers: u32, domain_routing: bool) -> Result<Self, String> {
        let routing_flag: u32 = if domain_routing { 1 } else { 0 };

        // #155: cap NB_WORKERS to physical-core count.
        // The eBPF global NB_WORKERS is the modulus for the per-domain FNV-1a hash
        // (`cpu = h % NB_WORKERS`), which is then used as the key into CPUMAP.
        // On BPF_MAP_TYPE_CPUMAP the key IS the kernel CPU ID — so we must ensure
        // indices 0..effective_workers-1 all correspond to physical cores (no HT
        // siblings).  physical_cores() returns them sorted and consecutive from 0
        // on all supported Intel/AMD layouts (siblings are offset by ncpus/2).
        // Capping here guarantees NB_WORKERS ≤ physical_core_count regardless of
        // what the driver reports as queue_count.
        let phys_cores = crate::cpu::physical_cores();
        let phys_count = phys_cores.len().max(1) as u32;
        let effective_workers = nb_workers.max(1).min(phys_count);

        // Try full binary (with CPUMAP).
        let bpf_result = load_ebpf_bytes(XDP_PROG, effective_workers, routing_flag);

        let (mut bpf, actual_routing) = match bpf_result {
            Ok(bpf) => (bpf, domain_routing),
            Err(ref e) if is_cpumap_error(e) => {
                tracing::warn!(
                    err = %e,
                    "CPUMAP creation failed — domain routing disabled, \
                     retrying with minimal XDP binary (no CPUMAP)"
                );
                let bpf = load_ebpf_bytes(XDP_PROG_MINIMAL, effective_workers, 0)
                    .map_err(|e2| format!("minimal BPF ELF load also failed: {e2}"))?;
                (bpf, false)
            }
            Err(e) => return Err(e),
        };

        let program: &mut Xdp = bpf
            .program_mut("dns_xdp")
            .ok_or_else(|| "dns_xdp program section not found in ELF".to_string())?
            .try_into()
            .map_err(|e| format!("program type mismatch: {e}"))?;

        program
            .load()
            .map_err(|e| format!("XDP prog load failed: {e}"))?;

        // Try DRV mode (zero-copy capable drivers). Fall back to SKB mode
        // (works on every NIC, slightly higher latency due to SKB allocation).
        let (link_id, mode) = program
            .attach(iface, XdpFlags::DRV_MODE)
            .map(|id| (id, XdpMode::Drv))
            .or_else(|_| {
                program
                    .attach(iface, XdpFlags::SKB_MODE)
                    .map(|id| (id, XdpMode::Skb))
            })
            .map_err(|e| format!("XDP attach to {iface} failed: {e}"))?;

        tracing::info!(
            iface   = %iface,
            mode    = ?mode,
            hash    = "fnv1a",
            "XDP program attached"
        );

        let mut handle = XdpHandle {
            bpf,
            link_id: Some(link_id),
            mode,
            governor_guard: None,
            domain_routing_active: actual_routing,
        };

        // #155 — WARN: domain-routing (CPUMAP) is mutually exclusive with zerocopy.
        //
        // bpf_redirect_map(CPUMAP) re-queues the packet on the target CPU's NAPI
        // backlog (new scheduling context, outside the driver ZC ring) — the frame
        // is no longer in the original DRV ZC ring → copy/SKB path.  Measured impact:
        // 4.77 M qps (ZC) → 120 k qps (CPUMAP redirect) = ×40 regression (#155).
        //
        // Design decision (architect, 2026-06-03): ZC wins on ZC-capable interfaces.
        // domain-routing is silently gated OFF when zerocopy is confirmed on any
        // socket (worker.rs, after bind); this WARN uses `domain_routing` (the raw
        // user config) rather than `actual_routing` so the operator always sees it,
        // even after the gate-off has already forced actual_routing=false.
        // XdpMode::Drv is a proxy for ZC-capable here; the true gate uses
        // sock.zerocopy (confirmed after bind) in worker.rs.
        if domain_routing && matches!(mode, XdpMode::Drv) {
            tracing::warn!(
                iface          = %iface,
                xdp_mode       = "DRV (zerocopy)",
                "xdp-domain-routing: yes IGNORÉ sur cette interface zerocopy. \
                 CPUMAP redirect exits the ZC ring (bpf_redirect_map re-queues via \
                 NAPI backlog) — measured: 4.77 M → 120 k qps (×40 regression). \
                 domain-routing is forced OFF once ZC is confirmed on any socket \
                 (worker.rs); it remains available in SKB/copy mode only. (#155)"
            );
        }

        // #155 — Initialise domain_routing_cfg Array map (runtime-flippable flag).
        // Must happen before init_cpumap so the eBPF flag is consistent with the
        // CPUMAP entries.  worker.rs will flip to 0 after ZC bind if any sock is ZC.
        if let Err(e) = handle.init_domain_routing_cfg(actual_routing) {
            tracing::warn!(err=%e, "domain_routing_cfg init failed — domain routing disabled");
            handle.domain_routing_active = false;
        }

        // Init CPUMAP entries when domain routing is enabled.
        // Silently skip on any error so the XDP path still works via XSKMAP fallback.
        if actual_routing {
            if let Err(e) = handle.init_cpumap(effective_workers) {
                tracing::warn!(err=%e, "CPUMAP init failed — domain routing disabled, falling back to RSS");
            } else {
                tracing::info!(workers = effective_workers, "CPUMAP domain routing enabled");
            }
        }

        Ok(handle)
    }

    /// #155 — Force domain-routing OFF when zerocopy is confirmed on any socket.
    ///
    /// Called from `worker.rs` after AF_XDP sockets are bound and `sock.zerocopy`
    /// is the ground truth.  Writes `enabled=0` into the `domain_routing_cfg`
    /// BPF Array map so the eBPF program takes the XSKMAP path on the NEXT packet.
    ///
    /// # Why not clear CPUMAP entries?
    /// The former approach cleared CPUMAP entries but left `DOMAIN_ROUTING_ENABLED=1`
    /// (frozen .rodata) — the eBPF still entered the CPUMAP branch →
    /// `bpf_redirect_map` on an empty map → `XDP_PASS` → slow-path kernel socket,
    /// NOT the ZC XSK.  Writing 0 to the Array map flag is the only correct gate (#155).
    ///
    /// # Errors
    /// Returns `Err(String)` if the map write fails; caller logs and handles.
    pub fn disable_domain_routing(&mut self) -> Result<(), String> {
        let map = self
            .bpf
            .map_mut("domain_routing_cfg")
            .ok_or_else(|| "domain_routing_cfg map not found".to_string())?;
        let mut arr = Array::<_, DomainRoutingCfgEntry>::try_from(map)
            .map_err(|e| e.to_string())?;
        arr.set(0, DomainRoutingCfgEntry { enabled: 0, _pad: [0; 3] }, 0)
            .map_err(|e| format!("domain_routing_cfg.set(0): {e}"))?;
        self.domain_routing_active = false;
        tracing::info!(
            "domain_routing_cfg[0].enabled → 0: CPUMAP path disabled, ZC XSKMAP fast path preserved (#155)"
        );
        Ok(())
    }

    /// #155 — Initialise the `domain_routing_cfg` BPF Array map at load time.
    /// Sets `enabled` to 1 if `active`, 0 otherwise.
    fn init_domain_routing_cfg(&mut self, active: bool) -> Result<(), String> {
        let map = self
            .bpf
            .map_mut("domain_routing_cfg")
            .ok_or_else(|| "domain_routing_cfg map not found".to_string())?;
        let mut arr = Array::<_, DomainRoutingCfgEntry>::try_from(map)
            .map_err(|e| e.to_string())?;
        arr.set(
            0,
            DomainRoutingCfgEntry { enabled: active as u8, _pad: [0; 3] },
            0,
        )
        .map_err(|e| format!("domain_routing_cfg.set(0): {e}"))?;
        Ok(())
    }

    /// Update the ICMP config BPF map live — no reload required (#89).
    pub fn icmp_update_config(
        &mut self,
        enabled: bool,
        rate_pps: u32,
        burst: u32,
    ) -> Result<(), String> {
        let map = self
            .bpf
            .map_mut("icmp_cfg")
            .ok_or_else(|| "icmp_cfg map not found".to_string())?;
        let mut arr = Array::<_, IcmpCfgEntry>::try_from(map).map_err(|e| e.to_string())?;
        let entry = IcmpCfgEntry {
            enabled: enabled as u8,
            _pad: [0; 3],
            rate_pps,
            burst,
        };
        arr.set(0, entry, 0).map_err(|e| e.to_string())
    }

    /// Read the ICMP per-CPU stat counters and return `[handled, replied, dropped, rate_limited]`.
    pub fn icmp_read_stats(&mut self) -> Result<[u64; 4], String> {
        let map = self
            .bpf
            .map_mut("icmp_stats")
            .ok_or_else(|| "icmp_stats map not found".to_string())?;
        let arr = PerCpuArray::<_, u64>::try_from(map).map_err(|e| e.to_string())?;
        let mut out = [0u64; 4];
        for i in 0u32..4 {
            let vals = arr.get(&i, 0).map_err(|e| e.to_string())?;
            out[i as usize] = vals.iter().sum();
        }
        Ok(out)
    }

    /// Read per-IP rate-limited hit counts and reset (delete) each processed entry.
    /// Returns `(ip_be32, total_count)` pairs for IPs with count > 0.
    /// The PERCPU map stores one u64 per CPU; we sum all slots.
    pub fn icmp_read_and_reset_rl(&mut self) -> Result<Vec<(u32, u64)>, String> {
        let map = self
            .bpf
            .map_mut("icmp_rl_counts")
            .ok_or_else(|| "icmp_rl_counts map not found".to_string())?;
        let mut hash = PerCpuHashMap::<_, u32, u64>::try_from(map).map_err(|e| e.to_string())?;
        let keys: Vec<u32> = hash
            .keys()
            .filter_map(|r| r.ok())
            .collect();
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Ok(vals) = hash.get(&key, 0) {
                let total: u64 = vals.iter().sum();
                if total > 0 {
                    out.push((key, total));
                }
                let _ = hash.remove(&key);
            }
        }
        Ok(out)
    }

    /// Insert `ip_be32` (network-byte-order IPv4) into the BPF `icmp_banned` map.
    pub fn icmp_ban_ip(&mut self, ip_be32: u32) -> Result<(), String> {
        let map = self
            .bpf
            .map_mut("icmp_banned")
            .ok_or_else(|| "icmp_banned map not found".to_string())?;
        let mut hash = HashMap::<_, u32, u8>::try_from(map).map_err(|e| e.to_string())?;
        hash.insert(ip_be32, 1u8, 0).map_err(|e| e.to_string())
    }

    /// Remove `ip_be32` from the BPF `icmp_banned` map (unban).
    pub fn icmp_unban_ip(&mut self, ip_be32: u32) -> Result<(), String> {
        let map = self
            .bpf
            .map_mut("icmp_banned")
            .ok_or_else(|| "icmp_banned map not found".to_string())?;
        let mut hash = HashMap::<_, u32, u8>::try_from(map).map_err(|e| e.to_string())?;
        hash.remove(&ip_be32).map_err(|e| e.to_string())
    }

    /// Initialise CPUMAP entries for `nb_workers` physical CPUs.
    ///
    /// Each entry is initialised with `queue_size=192` packets (enough headroom
    /// for burst traffic) and no chained BPF program.
    ///
    /// # #155 — Physical-core guarantee
    ///
    /// `BPF_MAP_TYPE_CPUMAP` uses the map key as the kernel CPU ID.  The eBPF
    /// program computes `cpu = fnv1a(qname) % NB_WORKERS` and calls
    /// `bpf_redirect_map(&CPUMAP, cpu, XDP_PASS)` — so key `cpu` must map to a
    /// physical core, never to an HT sibling.
    ///
    /// `physical_cores()` returns CPU IDs that are the lowest-numbered member of
    /// their `thread_siblings_list` group (i.e. the physical representative).
    /// On Intel/AMD these IDs are 0..ncores-1 (siblings start at ncores), so
    /// CPUMAP[0..NB_WORKERS-1] == physical cores.  This is correct on the supported
    /// Intel/AMD layout where physical cores are numbered 0..N-1 contiguous.  On
    /// non-linear topologies (e.g. NUMA where physicals = [0,2,4,…]) the eBPF hash
    /// `h % NB_WORKERS` would produce keys 0,1,2,… while CPUMAP only has entries
    /// at 0,2,4,… → CPUMAP[1] uninitialised → XDP_PASS (silent packet loss).
    /// A runtime WARN fires on each such mismatch; true robustness requires a
    /// worker_index→cpu_id indirection map (tracked as #155 follow-up).
    fn init_cpumap(&mut self, nb_workers: u32) -> Result<(), String> {
        let map = self
            .bpf
            .map_mut("CPUMAP")
            .ok_or_else(|| "CPUMAP map not found in BPF object".to_string())?;
        let mut cpu_map =
            CpuMap::try_from(map).map_err(|e| format!("CPUMAP is not a CpuMap: {e}"))?;

        // #155: use physical_cores() so we never initialise a sibling HT entry.
        // The eBPF hash `cpu = h % NB_WORKERS` produces keys in [0, NB_WORKERS).
        // physical_cores() is sorted ascending; the first NB_WORKERS entries are
        // guaranteed to be physical (NB_WORKERS was already capped in load()).
        let phys = crate::cpu::physical_cores();
        let n = (nb_workers as usize).min(phys.len());
        for i in 0..n {
            let cpu_id = phys[i] as u32;
            // Safety net for non-linear CPU numbering: the eBPF hash produces
            // slot indices 0..N-1; if cpu_id != slot, CPUMAP[slot] will be
            // uninitialised and bpf_redirect_map returns XDP_PASS (silent loss).
            // On supported Intel/AMD layouts cpu_id == i — WARN loudly otherwise.
            if cpu_id != i as u32 {
                tracing::warn!(
                    slot      = i,
                    cpu_id    = cpu_id,
                    "CPUMAP slot {i} → cpu_id {cpu_id}: non-linear CPU numbering \
                     detected — eBPF hash will miss this slot, causing silent \
                     XDP_PASS for ~1/NB_WORKERS traffic. \
                     True fix: worker_index→cpu_id indirection map (#155 follow-up)"
                );
            }
            cpu_map
                .set(cpu_id, 192, None, 0)
                .map_err(|e| format!("CpuMap::set cpu_id={cpu_id} (slot {i}): {e}"))?;
        }
        if n < nb_workers as usize {
            tracing::warn!(
                requested = nb_workers,
                physical  = n,
                "CPUMAP: fewer physical cores than requested workers —                  capped to physical count to prevent HT-sibling routing (#155)"
            );
        }
        Ok(())
    }

    /// Reload the XDP blacklist map with the given list of domain names.
    ///
    /// Clears existing entries then inserts each domain (dotted ASCII, e.g.
    /// "example.com") converted to DNS wire-format QNAME. Silently skips
    /// domains that are too long or malformed.
    /// Returns the number of domains successfully inserted.
    pub fn blacklist_reload(&mut self, domains: &[impl AsRef<str>]) -> Result<usize, String> {
        let map_ref = self
            .bpf
            .map_mut("dns_blacklist")
            .ok_or_else(|| "dns_blacklist map not found".to_string())?;
        let mut map = HashMap::<_, [u8; 256], u8>::try_from(map_ref)
            .map_err(|e| e.to_string())?;
        let keys: Vec<[u8; 256]> = map.keys().filter_map(|r| r.ok()).collect();
        for key in &keys {
            let _ = map.remove(key);
        }
        let mut count = 0usize;
        for d in domains.iter().take(super::blacklist::BLACKLIST_MAX) {
            if let Some(key) = super::blacklist::domain_to_key(d.as_ref()) {
                if map.insert(key, 1u8, 0).is_ok() {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Clear all entries from the XDP blacklist map.
    pub fn blacklist_clear(&mut self) -> Result<(), String> {
        let map_ref = self
            .bpf
            .map_mut("dns_blacklist")
            .ok_or_else(|| "dns_blacklist map not found".to_string())?;
        let mut map = HashMap::<_, [u8; 256], u8>::try_from(map_ref)
            .map_err(|e| e.to_string())?;
        let keys: Vec<[u8; 256]> = map.keys().filter_map(|r| r.ok()).collect();
        for key in &keys {
            let _ = map.remove(key);
        }
        Ok(())
    }

    /// Read the total number of packets blocked by the XDP blacklist.
    /// Sums all per-CPU slots from block_stats[0].
    pub fn block_stats_read(&mut self) -> Result<u64, String> {
        let map_ref = self
            .bpf
            .map_mut("block_stats")
            .ok_or_else(|| "block_stats map not found".to_string())?;
        let arr = PerCpuArray::<_, u64>::try_from(map_ref).map_err(|e| e.to_string())?;
        let vals = arr.get(&0u32, 0).map_err(|e| e.to_string())?;
        Ok(vals.iter().sum())
    }

    /// Register an AF_XDP socket with the XSKMAP at the given queue index.
    ///
    /// Must be called after `create_xsk_socket` so the kernel can redirect
    /// frames for that queue directly into the AF_XDP ring buffer.
    pub fn register_socket(&mut self, queue_id: u32, sock_fd: RawFd) -> Result<(), String> {
        let map = self
            .bpf
            .map_mut("XSKS")
            .ok_or_else(|| "XSKS map not found in BPF object".to_string())?;

        let mut xsk_map =
            XskMap::try_from(map).map_err(|e| format!("XSKS is not an XskMap: {e}"))?;

        xsk_map
            .set(queue_id, sock_fd, 0)
            .map_err(|e| format!("XskMap::set q={queue_id} fd={sock_fd}: {e}"))
    }
}

/// Align `bytes` to 8-byte boundary (required by aya's ELF64 parser), inject
/// global constants, and call `Ebpf::load()`.
fn load_ebpf_bytes(bytes: &[u8], nb_workers: u32, routing_flag: u32) -> Result<Ebpf, String> {
    // Vec<u64> is guaranteed 8-byte aligned by any conforming allocator,
    // satisfying the object crate's FileHeader64 alignment check inside aya.
    let words = bytes.len().div_ceil(8);
    let mut storage: Vec<u64> = vec![0u64; words];
    // SAFETY: storage has len=words*8 ≥ bytes.len(), u64 → u8 cast is valid.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), storage.as_mut_ptr() as *mut u8, bytes.len());
    }
    let aligned = unsafe { std::slice::from_raw_parts(storage.as_ptr() as *const u8, bytes.len()) };

    EbpfLoader::new()
        .set_global("NB_WORKERS", &nb_workers, false)
        .set_global("DOMAIN_ROUTING_ENABLED", &routing_flag, false)
        .load(aligned)
        .map_err(|e| format!("BPF ELF load failed: {e}"))
}

/// Returns true when the aya error string indicates a CPUMAP map creation
/// failure, so the caller can retry with the minimal (no-CPUMAP) binary.
fn is_cpumap_error(e: &str) -> bool {
    let lower = e.to_ascii_lowercase();
    lower.contains("cpumap") || lower.contains("cpu_map")
}
