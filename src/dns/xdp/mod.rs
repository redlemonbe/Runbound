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

pub mod socket;
pub mod umem;

#[cfg(feature = "xdp")]
mod loader;
#[cfg(feature = "xdp")]
mod worker;

#[cfg(feature = "xdp")]
pub use worker::start_xdp;
