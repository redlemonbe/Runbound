// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// XDP filter — redirects UDP port 53 (IPv4 + IPv6) to AF_XDP sockets.
// The user-space handler answers local-zone queries directly from the NIC
// ring buffer, bypassing the kernel network stack entirely.
//
// Packets that don't match (not UDP/53, not IP) are passed to the kernel
// stack with XDP_PASS so TCP/DoT/DoH/DoQ and non-DNS traffic are unaffected.
//
// Optional: DNS-aware CPUMAP routing (#67)
//   When DOMAIN_ROUTING_ENABLED != 0, each DNS query is hashed by question
//   name and redirected to a specific CPU (CPUMAP), achieving per-domain
//   affinity.  This improves XDP cache locality — queries for the same name
//   always land on the same CPU and its warm cache entries.
//   Falls back to XSKMAP (RSS) when the feature is disabled.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XSK map: NIC queue index → AF_XDP socket fd.
// Populated by user-space after creating the sockets.
// bpf_redirect_map falls back to XDP_PASS for unmapped queues.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u32);
} XSKS SEC(".maps");

// CPUMAP: maps CPU index → queue for domain-affinity routing (#67).
// Entries are initialised from Rust after the worker threads are started.
// max_entries=256 covers any realistic machine; unused entries are 0-qsize
// (not callable) and bpf_redirect_map returns XDP_PASS for them.
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, 256);
    __type(key,   __u32);
    __type(value, struct bpf_cpumap_val);
} CPUMAP SEC(".maps");

// Number of XDP worker threads — injected by Rust at load time via aya.
// Used as the modulus for the per-domain hash so each name always maps to
// the same worker.
volatile const __u32 NB_WORKERS = 1;

// Set to 1 by Rust when xdp-domain-routing: yes is configured.
// When 0 (default), the CPUMAP path is skipped and XSKMAP (RSS) is used.
volatile const __u32 DOMAIN_ROUTING_ENABLED = 0;

// CRC32C (Castagnoli polynomial 0x82F63B78) software hash over the first
// 64 bytes of the DNS QNAME at `off`.
//
// Bytes are ASCII-lowercased so "Example.com" and "example.com" hash
// identically.  Iteration is capped at 64 — handles names up to ~60 chars
// without heap allocation and keeps the generated BPF instruction count
// within verifier limits.
//
// NOTE: __builtin_ia32_crc32qi is an x86 intrinsic and cannot be used when
// compiling with -target bpf.  This software implementation achieves the same
// CRC32C result and works on every kernel that supports XDP.  The BPF JIT on
// x86 may further optimise the inner loop to hardware CRC instructions.
// No kernel-version gating is needed: software CRC32C works from kernel 4.8+.
static __always_inline __u32 dns_qname_hash(
    const void *data, const void *data_end, __u32 off)
{
    __u32 crc = 0xFFFFFFFF;
    int i;

    for (i = 0; i < 64; i++) {
        const __u8 *p = (const __u8 *)data + off + i;
        if ((void *)(p + 1) > data_end || *p == 0) break;
        __u8 b = *p | 0x20u;  // ASCII lowercase (no-op for digits / dots)
        crc ^= b;
        // Inner loop unrolled: 8 CRC steps per byte.
        // Branchless mask: (0 - (crc & 1)) == 0xFFFFFFFF when bit=1, 0 when bit=0.
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            __u32 mask = (__u32)(0 - (crc & 1));
            crc = (crc >> 1) ^ (mask & 0x82F63B78u);
        }
    }
    return crc ^ 0xFFFFFFFF;
}

SEC("xdp")
int dns_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    struct udphdr *udp;

    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->protocol != IPPROTO_UDP)
            return XDP_PASS;
        /* Assume standard IPv4 header (no options). Packets with IP options
         * are extremely rare on DNS traffic — pass them to the kernel.
         * This avoids adding a scalar variable to a packet pointer, which
         * the BPF verifier prohibits (r3 += r4 with packet ptr). */
        if ((ip->ihl & 0xF) != 5)
            return XDP_PASS;
        udp = (struct udphdr *)((void *)ip + 20);

    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        if (ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;
        // Fixed 40-byte IPv6 header — direct struct pointer arithmetic.
        udp = (struct udphdr *)(ip6 + 1);

    } else {
        return XDP_PASS;
    }

    // Bounds check required by the BPF verifier
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    // ── Domain-affinity routing via CPUMAP (#67) ─────────────────────────────
    // When enabled: hash the DNS QNAME and route to a dedicated CPU/worker.
    // This ensures all queries for a given domain land on the same core, keeping
    // the XDP cache hot for repeated lookups of the same name.
    //
    // The CPUMAP redirect hands the packet to a different CPU's net_rx softirq
    // and re-runs the XDP program on that CPU before the AF_XDP socket receives it.
    //
    // qname_off is computed from known constant header sizes — IHL=5 was
    // verified above, IPv6 header is always fixed 40 bytes — so no packet
    // pointer arithmetic is needed here (BPF verifier forbids ptr-ptr subtraction).
    if (DOMAIN_ROUTING_ENABLED) {
        __u32 nb = NB_WORKERS;
        if (nb > 1) {
            // Constant offsets per protocol — no pointer subtraction.
            // IPv4: eth(14) + ip(20, IHL=5 verified) + udp(8) + dns_header(12) = 54
            // IPv6: eth(14) + ip6(40)                + udp(8) + dns_header(12) = 74
            __u32 qname_off = (eth_proto == ETH_P_IP) ? 54u : 74u;
            __u32 h = dns_qname_hash(data, data_end, qname_off);
            __u32 cpu = h % nb;
            // bpf_redirect_map returns XDP_PASS when the entry is not initialised.
            return bpf_redirect_map(&CPUMAP, cpu, XDP_PASS);
        }
    }

    // ── Default path: redirect to AF_XDP socket for this NIC queue ────────────
    // XDP_PASS fallback: if queue not yet registered (e.g. during startup)
    // the packet falls to the normal kernel socket.
    return bpf_redirect_map(&XSKS, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
