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
// Inline ICMP definitions — avoid linux/icmp.h which pulls in linux/if.h
// and triggers stubs-32.h dependency on clang-for-BPF builds.
#define ICMP_ECHOREPLY  0
#define ICMP_ECHO       8
struct icmphdr {
    __u8   type;
    __u8   code;
    __sum16 checksum;
    union {
        struct { __be16 id; __be16 sequence; } echo;
        __be32  gateway;
        __u8    reserved[4];
    } un;
};
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
// Excluded via -DNO_CPUMAP on systems where BPF_MAP_TYPE_CPUMAP creation
// fails (missing CAP_BPF or old kernel) — the minimal binary falls back to
// RSS-based XSKMAP routing.
#ifndef NO_CPUMAP
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, 256);
    __type(key,   __u32);
    __type(value, struct bpf_cpumap_val);
} CPUMAP SEC(".maps");
#endif

// Number of XDP worker threads — injected by Rust at load time via aya.
// Used as the modulus for the per-domain hash so each name always maps to
// the same worker.
// ── ICMP echo responder (#89) ─────────────────────────────────────────────

// Per-source-IP rate limit state.
struct icmp_rate_entry {
    __u64 count;       // requests in current 1-second window
    __u64 window_ns;   // start of the window (bpf_ktime_get_ns)
    __u32 burst_left;  // remaining burst tokens (set from cfg->burst on new entry)
    __u32 _pad;
};

// Live config pushed from userspace (Array, 1 entry).
// Separate from volatile-const globals so it can be updated without reload.
struct icmp_cfg_entry {
    __u8  enabled;     // 0 = pass all ICMP, 1 = reply to echo requests
    __u8  _pad[3];
    __u32 rate_pps;    // max echo requests per second per source IP
    __u32 burst;       // allowed burst above rate_pps (reserved, not yet used)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_cfg_entry);
} icmp_cfg SEC(".maps");

// Per-CPU counters — summed in userspace. No atomics needed (each CPU owns its slice).
// Index 0: handled     (echo request reached rate-limit check)
// Index 1: replied     (XDP_TX sent)
// Index 2: banned_drop (source IP in icmp_banned — dropped before rate-limit check)
// Index 3: rate_limited (dropped by rate limiter)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} icmp_stats SEC(".maps");

// Per-source-IP rate limit — LRU evicts oldest entry under pressure.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, struct icmp_rate_entry);
} icmp_rate_limit SEC(".maps");

// Per-IP rate-limited hit counter — polled and reset by userspace every second.
// PERCPU: each CPU increments its own slot (no SMP contention).
// Userspace sums all CPU slots then deletes the entry to reset.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, __u64);
} icmp_rl_counts SEC(".maps");

// IPs banned by userspace flood detector — XDP_DROP before rate-limit check.
// Written by userspace; LRU evicts oldest ban under memory pressure.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);  // source IPv4 in network byte order
    __type(value, __u8);  // 1 = banned
} icmp_banned SEC(".maps");

// DNS wire-format QNAME → u8 (1 = block). Populated/cleared by userspace.
// Key is the raw QNAME bytes from the DNS packet, zero-padded to 256 bytes.
// Only the first 128 bytes are matched (covers all practical domain names).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 500000);
    __type(key, char[256]);
    __type(value, __u8);
} dns_blacklist SEC(".maps");

// Per-CPU blocked-packet counter. Index 0 = total blocks.
// Summed by userspace; no atomics required (each CPU owns its slice).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} block_stats SEC(".maps");

// DNS header wire layout — used for in-place NXDOMAIN response forge.
struct dnshdr {
    __be16 id;
    __be16 flags;   // QR/OPCODE/AA/TC/RD | RA/Z/AD/CD/RCODE
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

// One's complement 16-bit add with carry fold (endianness-agnostic).
static __always_inline __u16 csum16_add(__u16 a, __u16 b)
{
    __u32 s = (__u32)a + b;
    return (__u16)(s + (s >> 16));
}

volatile const __u32 NB_WORKERS = 1;

// #155 — domain-routing runtime flag: BPF_MAP_TYPE_ARRAY (1 entry, key=0).
//
// Replaces volatile const DOMAIN_ROUTING_ENABLED which is .rodata — frozen at
// eBPF load time and cannot be flipped post-bind.  Using an Array map allows
// worker.rs to write 0 AFTER zerocopy bind succeeds (when sock.zerocopy is
// the ground truth), preserving the ZC fast path.
//
// Layout mirrors struct domain_routing_cfg_entry in loader.rs (repr(C)):
//   u8  enabled   — 0 = use XSKMAP (RSS/ZC fast path), 1 = use CPUMAP routing
//   u8  _pad[3]   — alignment padding
struct domain_routing_cfg_entry {
    __u8  enabled;
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct domain_routing_cfg_entry);
} domain_routing_cfg SEC(".maps");

// FNV-1a hash over the first 64 bytes of the DNS QNAME.
//
// CRC32C's 8-iteration inner loop (#pragma unroll 8) causes exponential
// scalar state explosion in the BPF verifier and is rejected.  FNV-1a's
// single multiply per byte bounds scalar state cleanly and passes the
// verifier on all kernels that support XDP (4.8+).
//
// Bytes are ASCII-lowercased so "Example.com" and "example.com" hash
// identically.  Iteration is capped at 64 — handles names up to ~60 chars.
//
// #pragma unroll forces the compiler to emit 64 sequential copies of the loop
// body — no back-edge, no loss of bounds at the loop head.  Without unroll,
// `qname[i]` compiles to `r0 += r1` (PTR_TO_PACKET + loop_var); at the
// back-edge the verifier loses the minimum bound on r1 and marks it
// scalar() (unbounded), causing "math between pkt pointer and register with
// unbounded min value".  With unroll each copy has its own concrete pointer
// arithmetic — the verifier processes them in linear sequence and the per-
// iteration bounds check `qname + 1 > data_end` constrains the pointer
// correctly.  FNV-1a has only XOR + multiply — O(N) verifier states vs the
// O(2^N) explosion from CRC32C's inner bit loop.
static __always_inline __u32 dns_qname_hash(const __u8 *qname, const __u8 *data_end)
{
    __u32 h = 2166136261u; // FNV offset basis
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (qname + 1 > data_end) break;
        __u8 b = *qname;
        if (b == 0) break;
        h ^= (b | 0x20u); // ASCII lowercase (no-op for digits / dots)
        h *= 16777619u;   // FNV prime
        qname++;
    }
    return h;
}

// Copy up to 128 bytes of the QNAME (starting at qname_start) into key[256].
// Fixed-count unrolled loop: each iteration has a concrete constant offset so
// the BPF verifier can track packet bounds without scalar state explosion.
// key[128..255] remain zero (zeroed by caller) — matching Rust insertion padding.
static __always_inline void extract_qname_key(
    const __u8 *qname_start, const __u8 *data_end, char key[256])
{
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        const __u8 *p = qname_start + i;
        if ((const void *)(p + 1) > data_end)
            break;
        key[i] = (char)*p;
    }
}

// Forge an NXDOMAIN response in-place for an IPv4 DNS query.
// Swaps MACs, swaps IP src/dst, swaps UDP ports, sets DNS QR=1 RA=1 RCODE=3.
// UDP checksum is cleared (valid for IPv4 per RFC 768).
// Returns 0 on success; -1 if DNS header is out of bounds.
static __always_inline int forge_nxdomain_ipv4(
    struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, void *data_end)
{
    struct dnshdr *dns = (struct dnshdr *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return -1;

    // Swap Ethernet MACs
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac,           eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source,     eth->h_dest,   ETH_ALEN);
    __builtin_memcpy(eth->h_dest,       tmp_mac,       ETH_ALEN);

    // Swap IP src/dst (IP checksum unchanged — swap preserves ones-complement sum)
    __be32 tmp_ip  = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // Swap UDP ports
    __be16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest   = tmp_port;

    // Clear UDP checksum (optional for IPv4, avoids recalculation)
    udp->check = 0;

    // Set DNS response flags: QR=1, RA=1, RCODE=3 (NXDOMAIN), preserve RD
    __u16 rd = bpf_ntohs(dns->flags) & 0x0100u;
    dns->flags = bpf_htons(0x8083u | rd);

    // Zero answer counts (should already be 0 in a query — be defensive)
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    return 0;
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

    /* ── 802.1Q VLAN tagged frames (#188) ───────────────────────────────────
     * DC fabrics (e.g. Latitude private networks) deliver the link as a tagged
     * VLAN. With rx-vlan-offload OFF the tag stays in the frame, so the XDP gate
     * must skip the 4-byte tag to reach the inner IP/UDP and redirect DNS to the
     * AF_XDP socket. Self-contained branch: the untagged fast path below is left
     * byte-for-byte unchanged (no per-packet cost added to untagged traffic).
     * In-kernel ICMP-echo / blacklist replies are intentionally NOT mirrored for
     * tagged traffic — tagged DNS goes straight to the AF_XDP worker, which
     * carries the tag through to its in-place TX response.                       */
    if (eth_proto == ETH_P_8021Q) {
        struct vlan_hdr { __be16 tci; __be16 inner; };
        struct vlan_hdr *vh = (void *)(eth + 1);
        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;
        __u16 inner = bpf_ntohs(vh->inner);
        if (inner == ETH_P_IP) {
            struct iphdr *ip = (void *)(vh + 1);
            if ((void *)(ip + 1) > data_end)
                return XDP_PASS;
            if (ip->protocol != IPPROTO_UDP)
                return XDP_PASS;
            if ((ip->ihl & 0xF) != 5)
                return XDP_PASS;
            struct udphdr *u = (struct udphdr *)((void *)ip + 20);
            if ((void *)(u + 1) > data_end)
                return XDP_PASS;
            if (u->dest != bpf_htons(53))
                return XDP_PASS;
            return bpf_redirect_map(&XSKS, ctx->rx_queue_index, XDP_PASS);
        } else if (inner == ETH_P_IPV6) {
            struct ipv6hdr *ip6 = (void *)(vh + 1);
            if ((void *)(ip6 + 1) > data_end)
                return XDP_PASS;
            if (ip6->nexthdr != IPPROTO_UDP)
                return XDP_PASS;
            struct udphdr *u = (struct udphdr *)(ip6 + 1);
            if ((void *)(u + 1) > data_end)
                return XDP_PASS;
            if (u->dest != bpf_htons(53))
                return XDP_PASS;
            return bpf_redirect_map(&XSKS, ctx->rx_queue_index, XDP_PASS);
        }
        return XDP_PASS;
    }

    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->protocol == IPPROTO_ICMP) {
            // Reject IP-with-options: only standard 20-byte headers handled.
            if ((ip->ihl & 0xF) != 5)
                return XDP_PASS;
            struct icmphdr *icmp = (struct icmphdr *)((void *)ip + 20);
            if ((void *)(icmp + 1) > data_end)
                return XDP_PASS;

            if (icmp->type != ICMP_ECHO)
                return XDP_PASS; // non-echo ICMP → kernel

            // Check config
            __u32 cfg_key = 0;
            struct icmp_cfg_entry *cfg = bpf_map_lookup_elem(&icmp_cfg, &cfg_key);
            if (!cfg || !cfg->enabled)
                return XDP_PASS;

            __be32 src_ip = ip->saddr;

            // Drop packets from IPs banned by userspace flood detector
            {
                __u8 *ban = bpf_map_lookup_elem(&icmp_banned, &src_ip);
                if (ban && *ban) {
                    __u32 bk = 2; // STAT_BANNED_DROP
                    __u64 *bv = bpf_map_lookup_elem(&icmp_stats, &bk);
                    if (bv) (*bv)++;
                    return XDP_DROP;
                }
            }

            // Stat: handled (reached rate-limit check)
            __u32 sk = 0;
            __u64 *sv = bpf_map_lookup_elem(&icmp_stats, &sk);
            if (sv) (*sv)++;

            // Rate limit (1-second sliding window, per source IPv4)
            __u64 now = bpf_ktime_get_ns();
            struct icmp_rate_entry new_r = {};
            struct icmp_rate_entry *r = bpf_map_lookup_elem(&icmp_rate_limit, &src_ip);
            if (r) {
                // Consume a burst token if available (bypasses per-second window).
                if (r->burst_left > 0) {
                    new_r.count      = r->count;
                    new_r.window_ns  = r->window_ns;
                    new_r.burst_left = r->burst_left - 1;
                } else if (now - r->window_ns < 1000000000ULL) {
                    if (r->count >= cfg->rate_pps) {
                        sk = 3; // STAT_RATE_LIMITED
                        sv = bpf_map_lookup_elem(&icmp_stats, &sk);
                        if (sv) (*sv)++;
                        // Accumulate per-IP counter for userspace flood detection
                        {
                            __u64 one = 1;
                            __u64 *rl = bpf_map_lookup_elem(&icmp_rl_counts, &src_ip);
                            if (rl) (*rl)++;
                            else bpf_map_update_elem(&icmp_rl_counts, &src_ip, &one, BPF_ANY);
                        }
                        return XDP_DROP;
                    }
                    new_r.count      = r->count + 1;
                    new_r.window_ns  = r->window_ns;
                    new_r.burst_left = 0;
                } else {
                    new_r.count      = 1;
                    new_r.window_ns  = now;
                    new_r.burst_left = 0;
                }
            } else {
                // New source IP: grant initial burst tokens.
                new_r.count      = 0;
                new_r.window_ns  = now;
                new_r.burst_left = (cfg->burst > 0) ? cfg->burst - 1 : 0;
            }
            bpf_map_update_elem(&icmp_rate_limit, &src_ip, &new_r, BPF_ANY);

            // Build echo reply in-place
            // 1. Swap Ethernet MACs
            __u8 tmp[ETH_ALEN];
            __builtin_memcpy(tmp,            eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source,  eth->h_dest,   ETH_ALEN);
            __builtin_memcpy(eth->h_dest,    tmp,           ETH_ALEN);

            // 2. Swap IP src/dst — IP checksum is unchanged (swap preserves sum)
            __be32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;

            // 3. Set type to ECHOREPLY, update checksum incrementally
            // Type changes 8→0: one's complement sum decreases by 0x0800 (BE),
            // so checksum must increase by 0x0800.
            icmp->type     = ICMP_ECHOREPLY;
            icmp->checksum = csum16_add(icmp->checksum, bpf_htons(ICMP_ECHO << 8));

            // Stat: replied
            sk = 1;
            sv = bpf_map_lookup_elem(&icmp_stats, &sk);
            if (sv) (*sv)++;

            return XDP_TX;
        }

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

    // ── Blacklist fast-block (#153) ──────────────────────────────────────────────
    // IPv4 only: forge NXDOMAIN in-place and XDP_TX back to client (~1 µs RTT).
    // IPv6 blacklisted queries fall through to AF_XDP / hickory slow path.
    if (eth_proto == ETH_P_IP) {
        // QNAME sits 54 bytes from frame start: ETH(14)+IPv4(20)+UDP(8)+DNS_HDR(12)
        char key[256] = {};
        extract_qname_key((const __u8 *)data + 54u, (const __u8 *)data_end, key);
        __u8 *hit = bpf_map_lookup_elem(&dns_blacklist, key);
        if (hit && *hit) {
            __u32 bsk = 0;
            __u64 *bsv = bpf_map_lookup_elem(&block_stats, &bsk);
            if (bsv) (*bsv)++;
            struct iphdr *bl_ip = (void *)(eth + 1);
            if ((void *)(bl_ip + 1) > data_end) return XDP_PASS;
            if (forge_nxdomain_ipv4(eth, bl_ip, udp, data_end) == 0)
                return XDP_TX;
        }
    }

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
    // #155 — runtime flag: read domain_routing_cfg[0].enabled (Array map).
    // Returns XDP_PASS (→ ZC XSKMAP path below) if map lookup fails or enabled=0.
    {
        __u32 dr_key = 0;
        struct domain_routing_cfg_entry *dr_cfg =
            bpf_map_lookup_elem(&domain_routing_cfg, &dr_key);
        if (dr_cfg && dr_cfg->enabled) {
#ifndef NO_CPUMAP
        __u32 nb = NB_WORKERS;
        if (nb > 1) {
            // Constant offsets per protocol — no pointer subtraction.
            // IPv4: eth(14) + ip(20, IHL=5 verified) + udp(8) + dns_header(12) = 54
            // IPv6: eth(14) + ip6(40)                + udp(8) + dns_header(12) = 74
            __u32 qname_off = (eth_proto == ETH_P_IP) ? 54u : 74u;
            __u32 h = dns_qname_hash((const __u8 *)data + qname_off, (const __u8 *)data_end);
            __u32 cpu = h % nb;
            // Guard: after h *= FNV_prime, h is an unbounded scalar.
            // h % nb is still unbounded from the verifier's perspective
            // (nb is a runtime value).  The explicit bound check below
            // proves cpu ∈ [0, 63] — matching CPUMAP max_entries=64 —
            // so bpf_redirect_map can verify the key is in range.
            if (cpu >= 64) return XDP_PASS;
            return bpf_redirect_map(&CPUMAP, cpu, XDP_PASS);
        }
#endif
        } // if (dr_cfg && dr_cfg->enabled)
    } // domain_routing_cfg lookup

    // ── Default path: redirect to AF_XDP socket for this NIC queue ────────────
    // XDP_PASS fallback: if queue not yet registered (e.g. during startup)
    // the packet falls to the normal kernel socket.
    return bpf_redirect_map(&XSKS, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
