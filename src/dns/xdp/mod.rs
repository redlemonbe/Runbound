// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// AF_XDP kernel-bypass fast path for local-zone DNS queries.
//
// Architecture:
//   1. An eBPF XDP program (dns_xdp.o, compiled at build time) is attached to
//      the NIC. It inspects every incoming Ethernet frame and redirects
//      UDP/port-53 packets to an AF_XDP XSKMAP instead of passing them up
//      through the kernel network stack.
//
//   2. One XskSocket is created per NIC RX queue (SO_REUSEPORT equivalent at
//      the XDP layer). Each socket owns a UMEM region shared with the kernel.
//
//   3. One worker thread per queue polls the RX ring, processes local-zone DNS
//      queries entirely in user space (zero system calls on the hot path), and
//      enqueues responses on the TX ring.
//
//   4. Queries that cannot be answered locally (recursive, ANY, non-local name)
//      are dropped — the XDP program is configured with XDP_PASS fallback so
//      they continue up through the normal hickory-server path.
//
// Enabled via: cargo build --features xdp

#![deny(unsafe_op_in_unsafe_fn)]

// UNSAFE INVENTORY (src/dns/xdp/):
//
// umem.rs:135-215  — volatile read/write of producer/consumer/flags/descs in AddrRing
//                    (mmap'd shared memory ring; volatile required for kernel/user sharing)
// umem.rs:240-311  — volatile read/write of producer/consumer/flags/descs in DescRing
//                    (same rationale as AddrRing above)
// umem.rs:336      — sysconf(_SC_PAGESIZE): safe C call, no invariants beyond valid fd
// umem.rs:347      — alloc_umem_area: mmap(MAP_HUGETLB|MAP_ANONYMOUS) for huge pages, falls back to MAP_POPULATE
// umem.rs:374      — setsockopt(XDP_UMEM_REG): registers mmap'd area with AF_XDP socket
// umem.rs:386      — munmap on error path: same ptr/len as the mmap above
// umem.rs:397      — setsockopt(ring sizes): sets fill/completion ring capacities
// umem.rs:406      — munmap on error path: same ptr/len as the mmap above
// umem.rs:412      — get_mmap_offsets: getsockopt to retrieve ring byte offsets from kernel
// umem.rs:415,424  — mmap_addr_ring: mmap fill/completion rings; checked != MAP_FAILED
// umem.rs:461      — slice::from_raw_parts_mut for UMEM frame: bounds-checked before call
// umem.rs:474      — slice::from_raw_parts for UMEM frame: bounds-checked before call
// umem.rs:491      — munmap in Drop: exact ptr/len from Umem::new; called exactly once
// umem.rs:499      — get_mmap_offsets (wrapper): delegates to getsockopt; see line 412
// umem.rs:510      — getsockopt(XDP_MMAP_OFFSETS): MaybeUninit fully written by kernel on Ok
// umem.rs:521      — assume_init after getsockopt returned 0 (kernel initialised struct)
// umem.rs:537      — mmap(MAP_SHARED) for addr ring (fill/completion); checked != MAP_FAILED
// umem.rs:559-562  — ptr arithmetic into mmap'd region using kernel-supplied offsets (AddrRing)
// umem.rs:580      — mmap(MAP_SHARED) for desc ring (RX/TX); checked != MAP_FAILED
// umem.rs:600-603  — ptr arithmetic into mmap'd region using kernel-supplied offsets (DescRing)
//
// socket.rs:44     — libc::close in Drop: fd owned exclusively by XskSocket; called once
// socket.rs:61     — libc::socket(AF_XDP): syscall with valid constants
// socket.rs:71     — Umem::new: delegates to umem.rs unsafe path; fd valid at this point
// socket.rs:74     — libc::close on error path: fd not yet owned; closed once
// socket.rs:81     — setsockopt(XDP_RX_RING/TX_RING): fd valid, &sz is stack-allocated u32
// socket.rs:91     — libc::close on error path: fd not yet owned; closed once
// socket.rs:101    — get_rx_tx_offsets: delegates to getsockopt; fd valid
// socket.rs:103    — mmap_desc_ring (RX): delegates to umem mmap; offsets from kernel
// socket.rs:106    — libc::close on error path after failed RX ring mmap
// socket.rs:109    — mmap_desc_ring (TX): delegates to umem mmap; offsets from kernel
// socket.rs:112    — libc::close on error path after failed TX ring mmap
// socket.rs:132    — libc::bind(sockaddr_xdp): sa fully initialised, addrlen matches sizeof
// socket.rs:141    — libc::close on bind error path: fd not yet owned; closed once
// socket.rs:192    — libc::if_nametoindex: CString NUL-terminated, lifetime covers the call
// socket.rs:204    — libc::getifaddrs: out-pointer valid; result freed via freeifaddrs below
// socket.rs:213    — deref ifaddrs node: non-null pointer, valid until freeifaddrs
// socket.rs:217    — read sa_family + cast sockaddr to sockaddr_in/in6: guarded by family check
// socket.rs:240    — CStr::from_ptr(ifa_name): valid NUL-terminated C string from getifaddrs
// socket.rs:252    — libc::freeifaddrs: called exactly once after getifaddrs succeeded
//
// worker.rs:114-115 — create_xsk_socket: delegates to socket.rs; ifidx and queue_id valid
// worker.rs:168     — Umem::frame_mut for TX frame injection (self-test): bounds-checked inside
// worker.rs:186     — libc::sendto(null, 0, MSG_DONTWAIT) to kick TX driver (self-test)
// worker.rs:207     — libc::poll (self-test): pollfd on stack, nfds=1, non-negative timeout
// worker.rs:301     — libc::poll (hot loop): pollfd on stack, nfds=1, timeout=1 ms
// worker.rs:328     — slice::from_raw_parts{_mut} for RX/TX frames: bounds-checked above the block
// worker.rs:385     — libc::sendto(null, 0, MSG_DONTWAIT) to kick TX driver (hot loop)

pub mod socket;
pub mod umem;

#[cfg(feature = "xdp")]
mod loader;
#[cfg(feature = "xdp")]
mod worker;

#[cfg(feature = "xdp")]
pub use worker::start_xdp;
#[cfg(feature = "xdp")]
pub use loader::XdpMode;
