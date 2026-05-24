// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// AF_XDP UMEM — shared memory region between kernel and user space.
//
// Layout:  FRAME_COUNT contiguous frames of FRAME_SIZE bytes each.
//   Frames 0 …  FRAME_COUNT/2-1  → RX pool (seeded into the fill ring at startup)
//   Frames FRAME_COUNT/2 … end   → TX pool (managed by the handler)
//
// Ring buffer mapping offsets come from XDP_MMAP_OFFSETS setsockopt.
// All ring accesses use explicit acquire/release fences — the kernel and
// user space share these rings without any other synchronization mechanism.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use std::collections::VecDeque;
use std::os::fd::RawFd;
use std::sync::atomic::{fence, Ordering};
use std::{ptr, slice};

use libc::{
    mmap, munmap, sysconf, _SC_PAGESIZE, MAP_ANONYMOUS, MAP_FAILED, MAP_POPULATE, MAP_SHARED,
    PROT_READ, PROT_WRITE,
};

// ── Frame configuration ────────────────────────────────────────────────────

/// Bytes per frame. 4 KiB = one OS page, aligns with virtually all NICs.
/// DNS packets are ≤ 4096 bytes (EDNS0 UDP), so one frame = one packet.
pub const FRAME_SIZE: u32 = 4096;

/// Configurable AF_XDP ring sizes (powers of 2, each in [64, 65536]).
/// UMEM frame count = rx + tx; fill/comp are independent metadata rings.
/// Defaults match the previous hard-coded 4096 (no breaking change).
#[derive(Debug, Clone, Copy)]
pub struct XdpRingSizes {
    /// Fill ring size (user→kernel, free RX frames). Default: 4096.
    pub fill: u32,
    /// Completion ring size (kernel→user, TX reclaim). Default: 4096.
    pub comp: u32,
    /// RX descriptor ring size. Default: 4096.
    pub rx: u32,
    /// TX descriptor ring size. Default: 4096.
    pub tx: u32,
}

impl Default for XdpRingSizes {
    fn default() -> Self {
        Self {
            fill: 4096,
            comp: 4096,
            rx: 4096,
            tx: 4096,
        }
    }
}

// ── Kernel structures (from <linux/if_xdp.h>) ─────────────────────────────

pub const SOL_XDP: libc::c_int = 283;
pub const XDP_MMAP_OFFSETS: libc::c_int = 1;
pub const XDP_RX_RING: libc::c_int = 2;
pub const XDP_TX_RING: libc::c_int = 3;
pub const XDP_UMEM_REG: libc::c_int = 4;
pub const XDP_UMEM_FILL_RING: libc::c_int = 5;
pub const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;

pub const XDP_PGOFF_RX_RING: libc::off_t = 0;
pub const XDP_PGOFF_TX_RING: libc::off_t = 0x8000_0000;
pub const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x1_8000_0000;

pub const XDP_RING_NEED_WAKEUP: u32 = 1;

/// Bind flags (sxdp_flags)
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_COPY: u16 = 1 << 1;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

#[repr(C)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
    pub tx_metadata_len: u32,
}

#[repr(C)]
pub struct XdpRingOffsets {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[repr(C)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffsets,
    pub tx: XdpRingOffsets,
    pub fr: XdpRingOffsets, // fill
    pub cr: XdpRingOffsets, // completion
}

/// RX / TX descriptor
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct XdpDesc {
    /// Offset into UMEM (NOT a virtual address)
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

#[repr(C)]
pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

// ── Ring buffer abstractions ───────────────────────────────────────────────

/// A fill or completion ring (descriptors are plain u64 UMEM offsets).
pub struct AddrRing {
    _map: *mut u8,
    _mapsize: usize,
    producer: *mut u32,
    consumer: *mut u32,
    flags: *mut u32,
    descs: *mut u64,
    pub size: u32,
    pub mask: u32,
}

unsafe impl Send for AddrRing {}

impl AddrRing {
    /// Enqueue up to `addrs.len()` frame addresses.
    /// Returns the number actually enqueued (limited by available ring slots).
    pub fn enqueue_batch(&self, addrs: &[u64]) -> usize {
        // SAFETY: `self.producer` and `self.consumer` point into an mmap'd ring
        //         shared with the kernel (mapped in `mmap_addr_ring`). The mapping
        //         lives as long as `AddrRing` is live. Volatile reads/writes are
        //         required because the kernel may update `consumer` concurrently.
        let prod = unsafe { ptr::read_volatile(self.producer) };
        // SAFETY: Same rationale as `self.producer` above.
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let free = self.size.wrapping_sub(prod.wrapping_sub(cons)) as usize;
        let n = addrs.len().min(free);
        for (i, &a) in addrs[..n].iter().enumerate() {
            let idx = (prod.wrapping_add(i as u32)) & self.mask;
            // SAFETY: `idx` is masked to [0, size), so `self.descs.add(idx)` is
            //         within the mmap'd descriptor array whose length is `size`.
            unsafe {
                ptr::write_volatile(self.descs.add(idx as usize), a);
            }
        }
        fence(Ordering::Release);
        // SAFETY: `self.producer` is valid (see above); we publish the updated
        //         producer index after the release fence so the kernel sees the
        //         descriptor writes before the counter increment.
        unsafe {
            ptr::write_volatile(self.producer, prod.wrapping_add(n as u32));
        }
        n
    }

    /// Drain all completed addresses from the ring.
    /// Returns a vec of frame addresses that are now free.
    pub fn dequeue_all(&self) -> Vec<u64> {
        fence(Ordering::Acquire);
        // SAFETY: `self.producer` points into the mmap'd ring shared with the
        //         kernel (see `mmap_addr_ring`). The acquire fence above ensures
        //         we see descriptor writes made by the kernel before this read.
        let prod = unsafe { ptr::read_volatile(self.producer) };
        // SAFETY: Same mapping; volatile read required for shared-memory ring.
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let available = prod.wrapping_sub(cons) as usize;
        let mut out = Vec::with_capacity(available);
        for i in 0..available {
            let idx = (cons.wrapping_add(i as u32)) & self.mask;
            // SAFETY: `idx` is masked to [0, size), so `self.descs.add(idx)` is
            //         within the mmap'd descriptor array.
            out.push(unsafe { ptr::read_volatile(self.descs.add(idx as usize)) });
        }
        if available > 0 {
            // SAFETY: `self.consumer` is valid; we advance the consumer index to
            //         release the slots back to the kernel.
            unsafe {
                ptr::write_volatile(self.consumer, cons.wrapping_add(available as u32));
            }
        }
        out
    }

    /// Like `dequeue_all` but appends into a caller-supplied Vec (avoids heap allocation).
    /// The caller is responsible for clearing `out` before each call.
    pub fn dequeue_all_into(&self, out: &mut Vec<u64>) {
        fence(Ordering::Acquire);
        // SAFETY: `self.producer` points into the mmap'd ring shared with the
        //         kernel (see `mmap_addr_ring`). Acquire fence above ensures
        //         we observe all descriptor writes before reading the counter.
        let prod = unsafe { ptr::read_volatile(self.producer) };
        // SAFETY: Same mapping; volatile read required for shared-memory ring.
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let available = prod.wrapping_sub(cons) as usize;
        for i in 0..available {
            let idx = (cons.wrapping_add(i as u32)) & self.mask;
            // SAFETY: `idx` is masked to [0, size), within the mmap'd descriptor array.
            out.push(unsafe { ptr::read_volatile(self.descs.add(idx as usize)) });
        }
        if available > 0 {
            // SAFETY: `self.consumer` is valid; advances consumer to release slots.
            unsafe {
                ptr::write_volatile(self.consumer, cons.wrapping_add(available as u32));
            }
        }
    }

    /// True if the kernel has set the NEED_WAKEUP flag on this ring.
    pub fn needs_wakeup(&self) -> bool {
        fence(Ordering::Acquire);
        // SAFETY: `self.flags` points into the mmap'd ring region (see `mmap_addr_ring`).
        //         Volatile read is required; the kernel may set this flag concurrently.
        (unsafe { ptr::read_volatile(self.flags) } & XDP_RING_NEED_WAKEUP) != 0
    }

    /// Read the current producer index (volatile).
    /// A non-zero value confirms the ring was seeded at startup.
    pub fn producer_count(&self) -> u32 {
        // SAFETY: `self.producer` points into the mmap'd ring region (see `mmap_addr_ring`).
        //         Volatile read is necessary because the kernel updates this field.
        unsafe { ptr::read_volatile(self.producer) }
    }
}

/// An RX or TX ring (descriptors are XdpDesc).
pub struct DescRing {
    _map: *mut u8,
    _mapsize: usize,
    producer: *mut u32,
    consumer: *mut u32,
    pub flags: *mut u32,
    descs: *mut XdpDesc,
    pub size: u32,
    pub mask: u32,
}

unsafe impl Send for DescRing {}

impl DescRing {
    /// Consume all pending RX descriptors.
    pub fn consume_rx(&self) -> Vec<XdpDesc> {
        fence(Ordering::Acquire);
        // SAFETY: `self.producer` points into the mmap'd ring shared with the
        //         kernel (see `mmap_desc_ring`). Acquire fence above ensures we
        //         observe all descriptor writes before reading the counter.
        let prod = unsafe { ptr::read_volatile(self.producer) };
        // SAFETY: Same mapping; volatile read required for shared-memory ring.
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let available = prod.wrapping_sub(cons) as usize;
        if available == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(available);
        for i in 0..available {
            let idx = (cons.wrapping_add(i as u32)) & self.mask;
            // SAFETY: `idx` is masked to [0, size), so `self.descs.add(idx)` is
            //         within the mmap'd XdpDesc array.
            out.push(unsafe { ptr::read_volatile(self.descs.add(idx as usize)) });
        }
        // SAFETY: `self.consumer` is valid; advances consumer to release slots.
        unsafe {
            ptr::write_volatile(self.consumer, cons.wrapping_add(available as u32));
        }
        out
    }

    /// Like `consume_rx` but appends into a caller-supplied Vec (avoids heap allocation).
    /// The caller is responsible for clearing `out` before each call.
    /// Returns the number of descriptors consumed.
    pub fn consume_rx_into(&self, out: &mut Vec<XdpDesc>) -> usize {
        fence(Ordering::Acquire);
        // SAFETY: `self.producer` points into the mmap'd ring shared with the
        //         kernel (see `mmap_desc_ring`). Acquire fence ensures we observe
        //         descriptor writes before reading the counter.
        let prod = unsafe { ptr::read_volatile(self.producer) };
        // SAFETY: Same mapping; volatile read required for shared-memory ring.
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let available = prod.wrapping_sub(cons) as usize;
        if available == 0 {
            return 0;
        }
        for i in 0..available {
            let idx = (cons.wrapping_add(i as u32)) & self.mask;
            // SAFETY: `idx` is masked to [0, size), within the mmap'd XdpDesc array.
            out.push(unsafe { ptr::read_volatile(self.descs.add(idx as usize)) });
        }
        // SAFETY: `self.consumer` is valid; advances consumer to release slots.
        unsafe {
            ptr::write_volatile(self.consumer, cons.wrapping_add(available as u32));
        }
        available
    }

    /// Enqueue TX descriptors. Returns the number actually enqueued.
    pub fn enqueue_tx(&self, descs: &[XdpDesc]) -> usize {
        // SAFETY: `self.producer` and `self.consumer` point into the mmap'd ring
        //         shared with the kernel (see `mmap_desc_ring`). Volatile reads
        //         are required because the kernel may update `consumer`.
        let prod = unsafe { ptr::read_volatile(self.producer) };
        // SAFETY: Same mapping; volatile read required for shared-memory ring.
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let free = self.size.wrapping_sub(prod.wrapping_sub(cons)) as usize;
        let n = descs.len().min(free);
        for (i, d) in descs[..n].iter().enumerate() {
            let idx = (prod.wrapping_add(i as u32)) & self.mask;
            // SAFETY: `idx` is masked to [0, size), within the mmap'd XdpDesc array.
            unsafe {
                ptr::write_volatile(self.descs.add(idx as usize), *d);
            }
        }
        fence(Ordering::Release);
        // SAFETY: Publishes updated producer index after the release fence so the
        //         kernel sees all descriptor writes before the counter increment.
        unsafe {
            ptr::write_volatile(self.producer, prod.wrapping_add(n as u32));
        }
        n
    }

    /// True if the kernel has set the NEED_WAKEUP flag.
    pub fn needs_wakeup(&self) -> bool {
        fence(Ordering::Acquire);
        // SAFETY: `self.flags` points into the mmap'd ring region (see `mmap_desc_ring`).
        //         Volatile read required; the kernel may set this flag concurrently.
        (unsafe { ptr::read_volatile(self.flags) } & XDP_RING_NEED_WAKEUP) != 0
    }
}

// ── UMEM ──────────────────────────────────────────────────────────────────

/// Allocate the UMEM backing memory.
/// Tries 2 MiB huge pages first (when `hugepages` is true) to reduce TLB pressure
/// at high packet rates. Falls back to standard 4 KiB pages on any failure.
fn alloc_umem_area(size: usize, hugepages: bool) -> Result<*mut libc::c_void, String> {
    #[cfg(target_os = "linux")]
    if hugepages {
        // MAP_HUGE_2MB = 21 << MAP_HUGE_SHIFT (MAP_HUGE_SHIFT = 26)
        // SAFETY: mmap with MAP_HUGETLB|MAP_ANONYMOUS allocates huge pages.
        //         fd=-1 is required with MAP_ANONYMOUS. size is page-aligned.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS | libc::MAP_HUGETLB | (21 << libc::MAP_HUGE_SHIFT),
                -1,
                0,
            )
        };
        if ptr != MAP_FAILED {
            tracing::info!(size, "UMEM allocated with huge pages");
            return Ok(ptr);
        }
        tracing::debug!("huge pages unavailable, falling back to standard pages");
    }

    // Standard 4 KiB pages (also used when hugepages=false)
    // SAFETY: mmap with MAP_ANONYMOUS|MAP_SHARED allocates a new anonymous mapping.
    //         MAP_POPULATE pre-faults pages to avoid hot-path page faults.
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
            -1,
            0,
        )
    };
    if ptr == MAP_FAILED {
        return Err(format!(
            "UMEM mmap failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if hugepages {
        tracing::info!(
            size,
            "UMEM allocated with standard pages (huge pages unavailable)"
        );
    } else {
        tracing::debug!(size, "UMEM allocated with standard pages");
    }
    Ok(ptr)
}

pub struct Umem {
    /// Base address of the mmap'd memory region (shared with kernel)
    pub area: *mut u8,
    pub area_len: usize,
    /// Pool of TX frame offsets available for writing responses
    pub tx_free: VecDeque<u64>,
    /// Fill ring: user→kernel (give free frames to kernel for RX)
    pub fill: AddrRing,
    /// Completion ring: kernel→user (TX frames the kernel is done with)
    pub comp: AddrRing,
}

unsafe impl Send for Umem {}

impl Umem {
    /// Allocate and register a UMEM with the given AF_XDP socket.
    /// On success returns the Umem plus the fill/completion ring maps;
    /// the caller passes `fd` to register_rings() after obtaining RX/TX offsets.
    pub unsafe fn new(
        xsk_fd: RawFd,
        hugepages: bool,
        sizes: &XdpRingSizes,
    ) -> Result<Self, String> {
        let page = unsafe { sysconf(_SC_PAGESIZE) } as usize;
        let frame_count = sizes.rx + sizes.tx;
        let area_len = (frame_count * FRAME_SIZE) as usize;
        // Round up to page boundary (should already be page-aligned)
        let area_len = (area_len + page - 1) & !(page - 1);

        // #62: try 2 MiB huge pages first to reduce TLB pressure at high packet rates.
        // Falls back silently to standard 4 KiB pages when huge pages are unavailable.
        let area = alloc_umem_area(area_len, hugepages)?;
        let area = area as *mut u8;

        // Register this memory region as a UMEM with the XDP socket
        let reg = XdpUmemReg {
            addr: area as u64,
            len: area_len as u64,
            chunk_size: FRAME_SIZE,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        // SAFETY: `xsk_fd` is a valid AF_XDP socket fd (caller guarantee).
        //         `&reg` is a valid pointer to an initialised XdpUmemReg.
        //         The socklen matches sizeof(XdpUmemReg).
        let rc = unsafe {
            libc::setsockopt(
                xsk_fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &reg as *const _ as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            // SAFETY: `area` is the non-null pointer returned by `mmap` above,
            //         and `area_len` is the exact length passed to that call.
            unsafe { munmap(area as *mut libc::c_void, area_len) };
            return Err(format!(
                "XDP_UMEM_REG failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set ring sizes
        for (opt, sz) in [
            (XDP_UMEM_FILL_RING, sizes.fill),
            (XDP_UMEM_COMPLETION_RING, sizes.comp),
        ] {
            // SAFETY: `xsk_fd` is a valid AF_XDP socket fd. `&sz` is a valid
            //         pointer to an initialised u32. The socklen matches sizeof(u32).
            let rc = unsafe {
                libc::setsockopt(
                    xsk_fd,
                    SOL_XDP,
                    opt,
                    &sz as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                // SAFETY: Same as the munmap above — area is valid and non-null.
                unsafe { munmap(area as *mut libc::c_void, area_len) };
                return Err(format!(
                    "setsockopt ring size ({opt}): {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        // Retrieve ring offsets
        let offsets = unsafe { get_mmap_offsets(xsk_fd) }?;

        // mmap fill ring
        let fill =
            unsafe { mmap_addr_ring(xsk_fd, XDP_UMEM_PGOFF_FILL_RING, &offsets.fr, sizes.fill) }?;
        // mmap completion ring
        let comp = unsafe {
            mmap_addr_ring(
                xsk_fd,
                XDP_UMEM_PGOFF_COMPLETION_RING,
                &offsets.cr,
                sizes.comp,
            )
        }?;

        // Pre-populate fill ring with RX frame offsets (give them to the kernel)
        let rx_addrs: Vec<u64> = (0..sizes.rx).map(|i| (i * FRAME_SIZE) as u64).collect();
        fill.enqueue_batch(&rx_addrs);

        // TX free pool = frames after the RX region
        let tx_free: VecDeque<u64> = (sizes.rx..sizes.rx + sizes.tx)
            .map(|i| (i * FRAME_SIZE) as u64)
            .collect();

        Ok(Umem {
            area,
            area_len,
            tx_free,
            fill,
            comp,
        })
    }

    /// Get a mutable slice for the frame at the given UMEM offset.
    /// Returns `None` if the bounds check fails (malformed kernel descriptor).
    /// # Safety
    /// `offset` must be a valid UMEM frame offset (multiple of FRAME_SIZE),
    /// and `len` must not exceed FRAME_SIZE.
    pub unsafe fn frame_mut(&mut self, offset: u64, len: usize) -> Option<&mut [u8]> {
        if (offset as usize).saturating_add(len) > self.area_len {
            return None;
        }
        // SAFETY: The bounds check above ensures `offset + len <= area_len`, so
        //         `self.area.add(offset)` through `+len` is within the mmap'd region.
        //         The region is mapped PROT_READ|PROT_WRITE. `self.area` is u8-aligned.
        //         Lifetime: the returned slice borrows `self` mutably, so the
        //         caller cannot alias this slice with another frame slice.
        Some(unsafe { slice::from_raw_parts_mut(self.area.add(offset as usize), len) })
    }

    /// Get an immutable slice for the frame at the given UMEM offset.
    /// Returns `None` if the bounds check fails (malformed kernel descriptor).
    pub unsafe fn frame(&self, offset: u64, len: usize) -> Option<&[u8]> {
        if (offset as usize).saturating_add(len) > self.area_len {
            return None;
        }
        // SAFETY: The bounds check above ensures `offset + len <= area_len`, so
        //         `self.area.add(offset)` through `+len` is within the mmap'd region.
        //         The region is PROT_READ|PROT_WRITE; u8 has alignment 1.
        //         Lifetime: the slice borrows `self` immutably for its duration.
        Some(unsafe { slice::from_raw_parts(self.area.add(offset as usize), len) })
    }

    /// Reclaim TX completion frames back into the free pool.
    pub fn reclaim_tx(&mut self) {
        for addr in self.comp.dequeue_all() {
            self.tx_free.push_back(addr);
        }
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: `self.area` is the non-null pointer returned by `mmap` in
        //         `Umem::new`, and `self.area_len` is the exact length passed to
        //         that call. `Drop` is called exactly once, so there is no
        //         double-unmap.
        unsafe {
            munmap(self.area as *mut libc::c_void, self.area_len);
        }
    }
}

// ── NUMA locality ──────────────────────────────────────────────────────────

/// Migrate UMEM pages to the local NUMA node of the calling thread.
///
/// Call this from the XDP worker thread right after CPU pinning so that memory
/// is co-located with the core processing it. Silent no-op on single-node
/// systems, containers without NUMA, or when the kernel returns any error.
#[cfg(target_os = "linux")]
pub fn rebind_to_local_numa(area: *mut u8, area_len: usize) {
    let mut node: u32 = 0;
    // getcpu: vDSO call — fills current NUMA node without a full syscall round-trip.
    // SAFETY: passing null for cpu (we only need the node) and null for tcache.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_getcpu,
            std::ptr::null::<u32>(),
            &mut node as *mut u32,
            std::ptr::null::<libc::c_void>(),
        )
    };
    if rc != 0 || node >= 64 {
        return;
    }

    // nodemask: one bit per NUMA node; node < 64 is always true in practice.
    let nodemask: u64 = 1u64 << node;
    // max_node must be strictly greater than the highest set bit index.
    let max_node: u64 = node as u64 + 2;

    // MPOL_PREFERRED=1: prefer node but fall back on exhaustion (non-strict).
    // MPOL_MF_MOVE=2:   migrate already-allocated pages to the preferred node.
    // SAFETY: `area` is a valid mmap'd region of `area_len` bytes owned by this
    //         process. mbind failure (ENOSYS, EPERM, ENOTSUP) leaves the pages
    //         on their current node — the UMEM remains fully functional.
    unsafe {
        libc::syscall(
            libc::SYS_mbind,
            area as *mut libc::c_void,
            area_len,
            1i64, // MPOL_PREFERRED
            &nodemask as *const u64,
            max_node,
            2u64, // MPOL_MF_MOVE
        );
    }
}

// ── Ring setup helpers ─────────────────────────────────────────────────────

/// Returns (rx_offsets, tx_offsets) — convenience wrapper for socket setup.
pub unsafe fn get_rx_tx_offsets(fd: RawFd) -> Result<(XdpRingOffsets, XdpRingOffsets), String> {
    let o = unsafe { get_mmap_offsets(fd) }?;
    Ok((o.rx, o.tx))
}

pub unsafe fn get_mmap_offsets(fd: RawFd) -> Result<XdpMmapOffsets, String> {
    let mut offsets = std::mem::MaybeUninit::<XdpMmapOffsets>::uninit();
    let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
    // SAFETY: `fd` is a valid AF_XDP socket fd (caller guarantee).
    //         `offsets.as_mut_ptr()` is a valid writable pointer to a
    //         MaybeUninit<XdpMmapOffsets>; the kernel will fully initialise it
    //         on success, after which `assume_init()` is safe.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            offsets.as_mut_ptr() as *mut libc::c_void,
            &mut optlen,
        )
    };
    if rc != 0 {
        return Err(format!(
            "XDP_MMAP_OFFSETS: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `getsockopt` returned 0, so the kernel has initialised the struct.
    Ok(unsafe { offsets.assume_init() })
}

unsafe fn mmap_addr_ring(
    fd: RawFd,
    pgoff: libc::off_t,
    off: &XdpRingOffsets,
    size: u32,
) -> Result<AddrRing, String> {
    let mapsize = off.desc as usize + size as usize * std::mem::size_of::<u64>();
    // SAFETY: `fd` is a valid AF_XDP socket fd. `pgoff` is one of the
    //         XDP_UMEM_PGOFF_* constants defined by the kernel ABI. `mapsize` is
    //         computed from the offsets returned by XDP_MMAP_OFFSETS and covers
    //         the full descriptor array. PROT_READ|PROT_WRITE is required because
    //         user space writes to the fill ring and reads from the completion ring.
    //         MAP_SHARED is required for the kernel to see our writes.
    let map = unsafe {
        mmap(
            ptr::null_mut(),
            mapsize,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd,
            pgoff,
        )
    };
    if map == MAP_FAILED {
        return Err(format!(
            "ring mmap (pgoff={pgoff:#x}): {}",
            std::io::Error::last_os_error()
        ));
    }
    let map = map as *mut u8;
    // SAFETY: All pointer arithmetic below uses offsets supplied by the kernel via
    //         XDP_MMAP_OFFSETS. The mapping covers at least `mapsize` bytes, which
    //         was computed to include every field. `u32` and `u64` have alignments
    //         of 4 and 8 respectively; the kernel guarantees these offsets are
    //         properly aligned.
    Ok(AddrRing {
        _map: map,
        _mapsize: mapsize,
        producer: unsafe { map.add(off.producer as usize) } as *mut u32,
        consumer: unsafe { map.add(off.consumer as usize) } as *mut u32,
        flags: unsafe { map.add(off.flags as usize) } as *mut u32,
        descs: unsafe { map.add(off.desc as usize) } as *mut u64,
        size,
        mask: size - 1,
    })
}

pub unsafe fn mmap_desc_ring(
    fd: RawFd,
    pgoff: libc::off_t,
    off: &XdpRingOffsets,
    size: u32,
) -> Result<DescRing, String> {
    let mapsize = off.desc as usize + size as usize * std::mem::size_of::<XdpDesc>();
    // SAFETY: `fd` is a valid AF_XDP socket fd. `pgoff` is one of the
    //         XDP_PGOFF_RX_RING / XDP_PGOFF_TX_RING constants (kernel ABI).
    //         `mapsize` covers the full XdpDesc array as computed from offsets
    //         returned by XDP_MMAP_OFFSETS. PROT_READ|PROT_WRITE + MAP_SHARED
    //         are required for the kernel/user ring sharing protocol.
    let map = unsafe {
        mmap(
            ptr::null_mut(),
            mapsize,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd,
            pgoff,
        )
    };
    if map == MAP_FAILED {
        return Err(format!(
            "desc ring mmap (pgoff={pgoff:#x}): {}",
            std::io::Error::last_os_error()
        ));
    }
    let map = map as *mut u8;
    // SAFETY: Offsets come from XDP_MMAP_OFFSETS (kernel ABI). The mapping is
    //         large enough to contain all fields. `u32` fields are 4-byte aligned
    //         and `XdpDesc` fields are aligned as guaranteed by the kernel ABI.
    Ok(DescRing {
        _map: map,
        _mapsize: mapsize,
        producer: unsafe { map.add(off.producer as usize) } as *mut u32,
        consumer: unsafe { map.add(off.consumer as usize) } as *mut u32,
        flags: unsafe { map.add(off.flags as usize) } as *mut u32,
        descs: unsafe { map.add(off.desc as usize) } as *mut XdpDesc,
        size,
        mask: size - 1,
    })
}
