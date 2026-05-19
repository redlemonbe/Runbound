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

#![allow(dead_code)]

use std::collections::VecDeque;
use std::os::fd::RawFd;
use std::sync::atomic::{fence, Ordering};
use std::{ptr, slice};

use libc::{
    MAP_ANONYMOUS, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE,
    mmap, munmap, sysconf, _SC_PAGESIZE,
};

// ── Frame configuration ────────────────────────────────────────────────────

/// Bytes per frame. 4 KiB = one OS page, aligns with virtually all NICs.
/// DNS packets are ≤ 4096 bytes (EDNS0 UDP), so one frame = one packet.
pub const FRAME_SIZE: u32 = 4096;

/// Total frames in the UMEM. 4096 × 4096 = 16 MiB per socket.
pub const FRAME_COUNT: u32 = 4096;

/// Ring capacity (must be a power of 2, ≤ FRAME_COUNT/2).
pub const RING_SIZE: u32 = 2048;

/// Number of frames reserved for RX (seeded into fill ring at startup).
pub const RX_FRAME_COUNT: u32 = RING_SIZE;

/// Number of frames reserved for TX (managed by the handler free pool).
pub const TX_FRAME_COUNT: u32 = RING_SIZE;

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
    _map:     *mut u8,
    _mapsize: usize,
    producer: *mut u32,
    consumer: *mut u32,
    flags:    *mut u32,
    descs:    *mut u64,
    pub size: u32,
    pub mask: u32,
}

unsafe impl Send for AddrRing {}

impl AddrRing {
    /// Enqueue up to `addrs.len()` frame addresses.
    /// Returns the number actually enqueued (limited by available ring slots).
    pub fn enqueue_batch(&self, addrs: &[u64]) -> usize {
        let prod = unsafe { ptr::read_volatile(self.producer) };
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let free = self.size.wrapping_sub(prod.wrapping_sub(cons)) as usize;
        let n = addrs.len().min(free);
        for (i, &a) in addrs[..n].iter().enumerate() {
            let idx = (prod.wrapping_add(i as u32)) & self.mask;
            unsafe { ptr::write_volatile(self.descs.add(idx as usize), a); }
        }
        fence(Ordering::Release);
        unsafe { ptr::write_volatile(self.producer, prod.wrapping_add(n as u32)); }
        n
    }

    /// Drain all completed addresses from the ring.
    /// Returns a vec of frame addresses that are now free.
    pub fn dequeue_all(&self) -> Vec<u64> {
        fence(Ordering::Acquire);
        let prod = unsafe { ptr::read_volatile(self.producer) };
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let available = prod.wrapping_sub(cons) as usize;
        let mut out = Vec::with_capacity(available);
        for i in 0..available {
            let idx = (cons.wrapping_add(i as u32)) & self.mask;
            out.push(unsafe { ptr::read_volatile(self.descs.add(idx as usize)) });
        }
        if available > 0 {
            unsafe { ptr::write_volatile(self.consumer, cons.wrapping_add(available as u32)); }
        }
        out
    }

    /// Like `dequeue_all` but appends into a caller-supplied Vec (avoids heap allocation).
    /// The caller is responsible for clearing `out` before each call.
    pub fn dequeue_all_into(&self, out: &mut Vec<u64>) {
        fence(Ordering::Acquire);
        let prod = unsafe { ptr::read_volatile(self.producer) };
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let available = prod.wrapping_sub(cons) as usize;
        for i in 0..available {
            let idx = (cons.wrapping_add(i as u32)) & self.mask;
            out.push(unsafe { ptr::read_volatile(self.descs.add(idx as usize)) });
        }
        if available > 0 {
            unsafe { ptr::write_volatile(self.consumer, cons.wrapping_add(available as u32)); }
        }
    }

    /// True if the kernel has set the NEED_WAKEUP flag on this ring.
    pub fn needs_wakeup(&self) -> bool {
        fence(Ordering::Acquire);
        (unsafe { ptr::read_volatile(self.flags) } & XDP_RING_NEED_WAKEUP) != 0
    }
}

/// An RX or TX ring (descriptors are XdpDesc).
pub struct DescRing {
    _map:     *mut u8,
    _mapsize: usize,
    producer: *mut u32,
    consumer: *mut u32,
    pub flags: *mut u32,
    descs:    *mut XdpDesc,
    pub size: u32,
    pub mask: u32,
}

unsafe impl Send for DescRing {}

impl DescRing {
    /// Consume all pending RX descriptors.
    pub fn consume_rx(&self) -> Vec<XdpDesc> {
        fence(Ordering::Acquire);
        let prod = unsafe { ptr::read_volatile(self.producer) };
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let available = prod.wrapping_sub(cons) as usize;
        if available == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(available);
        for i in 0..available {
            let idx = (cons.wrapping_add(i as u32)) & self.mask;
            out.push(unsafe { ptr::read_volatile(self.descs.add(idx as usize)) });
        }
        unsafe { ptr::write_volatile(self.consumer, cons.wrapping_add(available as u32)); }
        out
    }

    /// Like `consume_rx` but appends into a caller-supplied Vec (avoids heap allocation).
    /// The caller is responsible for clearing `out` before each call.
    /// Returns the number of descriptors consumed.
    pub fn consume_rx_into(&self, out: &mut Vec<XdpDesc>) -> usize {
        fence(Ordering::Acquire);
        let prod = unsafe { ptr::read_volatile(self.producer) };
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let available = prod.wrapping_sub(cons) as usize;
        if available == 0 {
            return 0;
        }
        for i in 0..available {
            let idx = (cons.wrapping_add(i as u32)) & self.mask;
            out.push(unsafe { ptr::read_volatile(self.descs.add(idx as usize)) });
        }
        unsafe { ptr::write_volatile(self.consumer, cons.wrapping_add(available as u32)); }
        available
    }

    /// Enqueue TX descriptors. Returns the number actually enqueued.
    pub fn enqueue_tx(&self, descs: &[XdpDesc]) -> usize {
        let prod = unsafe { ptr::read_volatile(self.producer) };
        let cons = unsafe { ptr::read_volatile(self.consumer) };
        let free = self.size.wrapping_sub(prod.wrapping_sub(cons)) as usize;
        let n = descs.len().min(free);
        for (i, d) in descs[..n].iter().enumerate() {
            let idx = (prod.wrapping_add(i as u32)) & self.mask;
            unsafe { ptr::write_volatile(self.descs.add(idx as usize), *d); }
        }
        fence(Ordering::Release);
        unsafe { ptr::write_volatile(self.producer, prod.wrapping_add(n as u32)); }
        n
    }

    /// True if the kernel has set the NEED_WAKEUP flag.
    pub fn needs_wakeup(&self) -> bool {
        fence(Ordering::Acquire);
        (unsafe { ptr::read_volatile(self.flags) } & XDP_RING_NEED_WAKEUP) != 0
    }
}

// ── UMEM ──────────────────────────────────────────────────────────────────

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
    pub unsafe fn new(xsk_fd: RawFd) -> Result<Self, String> {
        let page = sysconf(_SC_PAGESIZE) as usize;
        let area_len = (FRAME_COUNT * FRAME_SIZE) as usize;
        // Round up to page boundary (should already be page-aligned)
        let area_len = (area_len + page - 1) & !(page - 1);

        // Allocate the shared memory (MAP_ANONYMOUS + MAP_SHARED required by AF_XDP)
        let area = mmap(
            ptr::null_mut(),
            area_len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
            -1,
            0,
        );
        if area == MAP_FAILED {
            return Err(format!("UMEM mmap failed: {}", std::io::Error::last_os_error()));
        }
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
        let rc = libc::setsockopt(
            xsk_fd,
            SOL_XDP,
            XDP_UMEM_REG,
            &reg as *const _ as *const libc::c_void,
            std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
        );
        if rc != 0 {
            munmap(area as *mut libc::c_void, area_len);
            return Err(format!("XDP_UMEM_REG failed: {}", std::io::Error::last_os_error()));
        }

        // Set ring sizes
        for (opt, sz) in [
            (XDP_UMEM_FILL_RING,        RING_SIZE),
            (XDP_UMEM_COMPLETION_RING,  RING_SIZE),
        ] {
            let rc = libc::setsockopt(
                xsk_fd, SOL_XDP, opt,
                &sz as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
            if rc != 0 {
                munmap(area as *mut libc::c_void, area_len);
                return Err(format!("setsockopt ring size ({opt}): {}", std::io::Error::last_os_error()));
            }
        }

        // Retrieve ring offsets
        let offsets = get_mmap_offsets(xsk_fd)?;

        // mmap fill ring
        let fill = mmap_addr_ring(
            xsk_fd,
            XDP_UMEM_PGOFF_FILL_RING,
            &offsets.fr,
            RING_SIZE,
        )?;
        // mmap completion ring
        let comp = mmap_addr_ring(
            xsk_fd,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            &offsets.cr,
            RING_SIZE,
        )?;

        // Pre-populate fill ring with RX frame offsets (give them to the kernel)
        let rx_addrs: Vec<u64> = (0..RX_FRAME_COUNT)
            .map(|i| (i * FRAME_SIZE) as u64)
            .collect();
        fill.enqueue_batch(&rx_addrs);

        // TX free pool = frames after the RX region
        let tx_free: VecDeque<u64> = (RX_FRAME_COUNT..RX_FRAME_COUNT + TX_FRAME_COUNT)
            .map(|i| (i * FRAME_SIZE) as u64)
            .collect();

        Ok(Umem { area, area_len, tx_free, fill, comp })
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
        Some(slice::from_raw_parts_mut(self.area.add(offset as usize), len))
    }

    /// Get an immutable slice for the frame at the given UMEM offset.
    /// Returns `None` if the bounds check fails (malformed kernel descriptor).
    pub unsafe fn frame(&self, offset: u64, len: usize) -> Option<&[u8]> {
        if (offset as usize).saturating_add(len) > self.area_len {
            return None;
        }
        Some(slice::from_raw_parts(self.area.add(offset as usize), len))
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
        unsafe { munmap(self.area as *mut libc::c_void, self.area_len); }
    }
}

// ── Ring setup helpers ─────────────────────────────────────────────────────

/// Returns (rx_offsets, tx_offsets) — convenience wrapper for socket setup.
pub unsafe fn get_rx_tx_offsets(fd: RawFd) -> Result<(XdpRingOffsets, XdpRingOffsets), String> {
    let o = get_mmap_offsets(fd)?;
    Ok((o.rx, o.tx))
}

pub unsafe fn get_mmap_offsets(fd: RawFd) -> Result<XdpMmapOffsets, String> {
    let mut offsets = std::mem::MaybeUninit::<XdpMmapOffsets>::uninit();
    let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
    let rc = libc::getsockopt(
        fd, SOL_XDP, XDP_MMAP_OFFSETS,
        offsets.as_mut_ptr() as *mut libc::c_void,
        &mut optlen,
    );
    if rc != 0 {
        return Err(format!("XDP_MMAP_OFFSETS: {}", std::io::Error::last_os_error()));
    }
    Ok(offsets.assume_init())
}

unsafe fn mmap_addr_ring(
    fd: RawFd,
    pgoff: libc::off_t,
    off: &XdpRingOffsets,
    size: u32,
) -> Result<AddrRing, String> {
    let mapsize = off.desc as usize + size as usize * std::mem::size_of::<u64>();
    let map = mmap(
        ptr::null_mut(),
        mapsize,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_POPULATE,
        fd,
        pgoff,
    );
    if map == MAP_FAILED {
        return Err(format!("ring mmap (pgoff={pgoff:#x}): {}", std::io::Error::last_os_error()));
    }
    let map = map as *mut u8;
    Ok(AddrRing {
        _map: map,
        _mapsize: mapsize,
        producer: map.add(off.producer as usize) as *mut u32,
        consumer: map.add(off.consumer as usize) as *mut u32,
        flags:    map.add(off.flags    as usize) as *mut u32,
        descs:    map.add(off.desc     as usize) as *mut u64,
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
    let map = mmap(
        ptr::null_mut(),
        mapsize,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_POPULATE,
        fd,
        pgoff,
    );
    if map == MAP_FAILED {
        return Err(format!("desc ring mmap (pgoff={pgoff:#x}): {}", std::io::Error::last_os_error()));
    }
    let map = map as *mut u8;
    Ok(DescRing {
        _map: map,
        _mapsize: mapsize,
        producer: map.add(off.producer as usize) as *mut u32,
        consumer: map.add(off.consumer as usize) as *mut u32,
        flags:    map.add(off.flags    as usize) as *mut u32,
        descs:    map.add(off.desc     as usize) as *mut XdpDesc,
        size,
        mask: size - 1,
    })
}
