// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Load the compiled XDP eBPF program, attach it to a NIC, and manage the
// XSKMAP that maps queue_id → AF_XDP socket fd.
//
// The dns_xdp.o object is embedded at compile time — no files to deploy.
// Aya (pure Rust) handles ELF parsing, BPF syscalls, and map creation.

use std::os::fd::RawFd;

use aya::{
    Ebpf,
    maps::XskMap,
    programs::{Xdp, XdpFlags},
};
use aya::programs::xdp::XdpLinkId;

/// Compiled XDP program bytes, embedded at build time.
/// `include_bytes!` aligns to 1 byte, but aya's ELF64 parser (via the `object`
/// crate) requires 8-byte alignment for the ELF header read. We copy to a
/// heap-allocated Vec inside `XdpHandle::load()` before calling `Ebpf::load()`.
static XDP_PROG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dns_xdp.o"));

/// RAII handle for the loaded XDP program.
///
/// Dropping this struct detaches the XDP program from the NIC and destroys
/// all BPF maps. Without explicit detach the program would remain attached
/// after process exit (prevents NIC hot-unplug and re-attach on restart).
pub struct XdpHandle {
    bpf:     Ebpf,
    link_id: Option<XdpLinkId>,
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
    }
}

impl XdpHandle {
    /// Load and attach the DNS XDP filter to `iface`.
    ///
    /// Tries native (DRV) mode first for lowest latency; falls back to
    /// generic (SKB) mode if the driver does not support native XDP.
    pub fn load(iface: &str) -> Result<Self, String> {
        // Vec<u64> is guaranteed 8-byte aligned by any conforming allocator,
        // satisfying the object crate's FileHeader64 alignment check inside aya.
        // Vec<u8>.to_vec() does NOT guarantee 8-byte alignment.
        let words = XDP_PROG.len().div_ceil(8);
        let mut storage: Vec<u64> = vec![0u64; words];
        // SAFETY: storage has len=words*8 ≥ XDP_PROG.len(), u64 → u8 cast is valid.
        unsafe {
            std::ptr::copy_nonoverlapping(
                XDP_PROG.as_ptr(),
                storage.as_mut_ptr() as *mut u8,
                XDP_PROG.len(),
            );
        }
        let aligned = unsafe {
            std::slice::from_raw_parts(storage.as_ptr() as *const u8, XDP_PROG.len())
        };
        let mut bpf = Ebpf::load(aligned)
            .map_err(|e| format!("BPF ELF load failed: {e}"))?;

        let program: &mut Xdp = bpf
            .program_mut("dns_xdp")
            .ok_or_else(|| "dns_xdp program section not found in ELF".to_string())?
            .try_into()
            .map_err(|e| format!("program type mismatch: {e}"))?;

        program.load()
            .map_err(|e| format!("XDP prog load failed: {e}"))?;

        // Try DRV mode (zero-copy capable drivers). Fall back to SKB mode
        // (works on every NIC, slightly higher latency due to SKB allocation).
        let link_id = program
            .attach(iface, XdpFlags::DRV_MODE)
            .or_else(|_| program.attach(iface, XdpFlags::SKB_MODE))
            .map_err(|e| format!("XDP attach to {iface} failed: {e}"))?;

        tracing::info!(iface = %iface, link_id = ?link_id, "XDP program attached");

        Ok(XdpHandle { bpf, link_id: Some(link_id) })
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
