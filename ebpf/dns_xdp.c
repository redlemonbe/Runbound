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

// FNV-1a hash over the first 64 bytes of the DNS QNAME at `qname_off`.
// Bytes are ASCII-lowercased so "Example.com" and "example.com" hash identically.
// Iteration capped at 64 — handles names up to ~60 chars without heap allocation
// and keeps the generated BPF instruction count within verifier limits.
static __always_inline __u32 dns_qname_hash(
    void *data, void *data_end, __u32 qname_off)
{
    __u32 hash = 2166136261u;  // FNV-1a offset basis
    int i;

    for (i = 0; i < 64; i++) {
        __u8 *p = (__u8 *)data + qname_off + i;
        if (p + 1 > (__u8 *)data_end)
            break;
        __u8 b = *p;
        if (b == 0)
            break;                  // root label — end of QNAME
        hash ^= (b | 0x20u);       // cheap ASCII lowercase (no-op for non-alpha)
        hash *= 16777619u;          // FNV-1a prime
    }
    return hash;
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
    __u32 dns_off;

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
    if (DOMAIN_ROUTING_ENABLED) {
        __u32 nb = NB_WORKERS;
        if (nb > 1) {
            // DNS header is 12 bytes; QNAME starts at byte 12 of the DNS payload.
            __u32 udp_off = (char *)udp - (char *)data;
            // DNS payload offset = UDP header (8 bytes) after udp pointer
            __u32 qname_off = udp_off + 8 + 12;
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
