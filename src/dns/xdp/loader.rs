// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Load the compiled XDP eBPF program, attach it to a NIC, and manage the
// XSKMAP that maps queue_id → AF_XDP socket fd.
//
// The dns_xdp.o object is embedded at compile time — no files to deploy.
// Aya (pure Rust) handles ELF parsing, BPF syscalls, and map creation.

use std::os::fd::RawFd;

use aya::{
    Ebpf, EbpfLoader,
    maps::{CpuMap, XskMap},
    programs::{Xdp, XdpFlags},
};
use aya::programs::xdp::XdpLinkId;

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

/// XDP attachment mode — reported by GET /api/system as `xdp_mode`.
#[derive(Clone, Copy, Debug)]
pub enum XdpMode { Drv, Skb }

/// RAII handle for the loaded XDP program.
///
/// Dropping this struct detaches the XDP program from the NIC and destroys
/// all BPF maps. Without explicit detach the program would remain attached
/// after process exit (prevents NIC hot-unplug and re-attach on restart).
pub struct XdpHandle {
    bpf:     Ebpf,
    link_id: Option<XdpLinkId>,
    pub mode: XdpMode,
    /// #69: (core_id, original_governor) pairs saved before switching to "performance".
    /// Restored on Drop so the OS scheduler is left in its original state.
    pub(crate) governor_backups: Vec<(usize, String)>,
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
        for (core_id, original) in &self.governor_backups {
            crate::cpu::restore_governor(*core_id, original);
        }
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
        let routing_flag: u32  = if domain_routing { 1 } else { 0 };
        let effective_workers  = nb_workers.max(1);

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

        program.load()
            .map_err(|e| format!("XDP prog load failed: {e}"))?;

        // Try DRV mode (zero-copy capable drivers). Fall back to SKB mode
        // (works on every NIC, slightly higher latency due to SKB allocation).
        let (link_id, mode) = program
            .attach(iface, XdpFlags::DRV_MODE)
            .map(|id| (id, XdpMode::Drv))
            .or_else(|_| program.attach(iface, XdpFlags::SKB_MODE).map(|id| (id, XdpMode::Skb)))
            .map_err(|e| format!("XDP attach to {iface} failed: {e}"))?;

        tracing::info!(
            iface   = %iface,
            mode    = ?mode,
            hash    = "fnv1a",
            "XDP program attached"
        );

        let mut handle = XdpHandle { bpf, link_id: Some(link_id), mode, governor_backups: Vec::new() };

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

    /// Initialise CPUMAP entries for `nb_workers` CPUs.
    ///
    /// Each entry is initialised with `queue_size=192` packets (enough headroom
    /// for burst traffic) and no chained BPF program.
    fn init_cpumap(&mut self, nb_workers: u32) -> Result<(), String> {
        let map = self.bpf
            .map_mut("CPUMAP")
            .ok_or_else(|| "CPUMAP map not found in BPF object".to_string())?;
        let mut cpu_map = CpuMap::try_from(map)
            .map_err(|e| format!("CPUMAP is not a CpuMap: {e}"))?;
        for cpu_idx in 0..nb_workers {
            cpu_map
                .set(cpu_idx, 192, None, 0)
                .map_err(|e| format!("CpuMap::set cpu={cpu_idx}: {e}"))?;
        }
        Ok(())
    }

    /// Register an AF_XDP socket with the XSKMAP at the given queue index.
    ///
    /// Must be called after `create_xsk_socket` so the kernel can redirect
    /// frames for that queue directly into the AF_XDP ring buffer.
    pub fn register_socket(&mut self, queue_id: u32, sock_fd: RawFd) -> Result<(), String> {
        let map = self.bpf
            .map_mut("XSKS")
            .ok_or_else(|| "XSKS map not found in BPF object".to_string())?;

        let mut xsk_map = XskMap::try_from(map)
            .map_err(|e| format!("XSKS is not an XskMap: {e}"))?;

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
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            storage.as_mut_ptr() as *mut u8,
            bytes.len(),
        );
    }
    let aligned = unsafe {
        std::slice::from_raw_parts(storage.as_ptr() as *const u8, bytes.len())
    };

    EbpfLoader::new()
        .set_global("NB_WORKERS",            &nb_workers,   false)
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
