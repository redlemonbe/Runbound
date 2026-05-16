// XDP filter — redirects UDP port 53 (IPv4 + IPv6) to AF_XDP sockets.
// The user-space handler answers local-zone queries directly from the NIC
// ring buffer, bypassing the kernel network stack entirely.
//
// Packets that don't match (not UDP/53, not IP) are passed to the kernel
// stack with XDP_PASS so TCP/DoT/DoH/DoQ and non-DNS traffic are unaffected.

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

// Inline helper — check UDP dest port and redirect.
// Offset is the byte offset of the UDP header from the start of the frame.
static __always_inline int redirect_dns_udp(struct xdp_md *ctx, __u32 udp_off)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct udphdr *udp = data + udp_off;

    // Bounds check required by the BPF verifier
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    // Redirect to the AF_XDP socket registered for this NIC queue.
    // XDP_PASS fallback: if queue not yet registered (e.g. during startup)
    // the packet falls to the normal kernel socket.
    return bpf_redirect_map(&XSKS, ctx->rx_queue_index, XDP_PASS);
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

    // IPv4 — variable-length IP header (IHL field)
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->protocol != IPPROTO_UDP)
            return XDP_PASS;
        __u32 ihl = ip->ihl * 4;
        // Sanity-check IHL (must be ≥ 20 bytes, ≤ 60 bytes)
        if (ihl < 20 || ihl > 60)
            return XDP_PASS;
        return redirect_dns_udp(ctx, sizeof(struct ethhdr) + ihl);
    }

    // IPv6 — fixed 40-byte header (no options for UDP; extension headers skipped)
    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        if (ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;
        return redirect_dns_udp(ctx,
            sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
