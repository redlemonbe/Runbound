# 02 — The XDP fast path

This chapter follows a UDP/53 frame from the wire to the response when `xdp = yes`.
The path has four parts: the eBPF program decides what to do with the frame; AF_XDP
sockets carry chosen frames into user space with zero copy; worker threads parse and
answer; and anything not answerable falls through to the slow path.

Files: `ebpf/dns_xdp.c`, `src/dns/xdp/{loader,socket,umem,worker}.rs`, `src/dns/wire_builder.rs`.

---

## 2.1 The eBPF decision tree

`dns_xdp` (`ebpf/dns_xdp.c:311`) runs on every frame the NIC delivers to the XDP hook,
before the kernel network stack. Its logic, in order:

1. **Parse Ethernet.** If the frame carries one 802.1Q VLAN tag (`ETH_P_8021Q`), skip
   exactly one tag to reach the inner ethertype (#188, `ebpf/dns_xdp.c:324` — on a tagged
   fabric with `rx-vlan-offload` off the tag stays inside the frame). If the result is
   not IPv4/IPv6, `XDP_PASS` (hand to kernel). Untagged traffic pays one extra ethertype
   compare per frame and is otherwise byte-for-byte unchanged.
2. **ICMP echo (IPv4).** If enabled in config, rate-limit per source IP and answer the
   echo in place with `XDP_TX` (see §3.7). Otherwise `XDP_PASS`.
3. **Must be UDP, dest port 53.** Anything else (TCP for DoT/DoH/AXFR, other ports)
   `XDP_PASS` — so the kernel stack still serves TCP/TLS DNS normally.
4. **DDoS abuse-engine kernel ban (IPv4 + IPv6).** Gated on a `bans_active` array-map flag
   (one lookup when idle, no measurable fast-path cost): if set, look the source address up
   in the `icmp_banned` LRU hash (IPv4) or the `icmp_banned_v6` LRU hash (IPv6, keyed on the
   16-byte `struct in6_addr` — added in #228 so an IPv6 flood is shed at XDP speed too, not
   only in the slow path) and `XDP_DROP` on a hit. Bans are populated by the userspace
   abuse engine — escalation to `tarpit`/`block` only happens for **verified** sources
   (TCP/DoT/DoH/DoQ or UDP carrying a valid DNS cookie), so a spoofed UDP source can never
   get a victim banned. (`ebpf/dns_xdp.c:526` IPv4, `:553` IPv6)
5. **Blacklist (IPv4).** Extract the QNAME key, look it up in the `dns_blacklist` hash
   map; on a hit, forge NXDOMAIN in place and `XDP_TX` (~µs round-trip, never wakes user
   space). (`ebpf/dns_xdp.c:571`)
6. **Optional domain-affinity routing.** If `domain_routing_cfg.enabled`, hash the QNAME
   (FNV-1a, §3.6) and `bpf_redirect_map` to a specific CPU via `CPUMAP`, so repeated
   queries for one name always hit the same core's warm cache. (`ebpf/dns_xdp.c:590`)
7. **Default.** `bpf_redirect_map(&XSKS, rx_queue_index, XDP_PASS)` — hand the frame to
   the AF_XDP socket bound to this NIC queue. If no socket is registered for the queue
   (e.g. during startup), the `XDP_PASS` fallback sends it to the normal kernel socket.
   (`ebpf/dns_xdp.c:632`)

The key design property: **everything the fast path does not explicitly claim is passed
to the kernel.** TCP, DoT/DoH/DoQ, non-DNS traffic, IPv6 blacklist hits, IP-with-options
packets — all fall through untouched. The fast path is purely additive.

### Why a runtime flag for routing, not a constant

Domain routing is gated by a `BPF_MAP_TYPE_ARRAY` entry, not a `volatile const`
(`ebpf/dns_xdp.c:211`). A `.rodata` constant is frozen at eBPF load time. The Array map
lets user space flip routing **after** the AF_XDP zero-copy bind has succeeded — because
whether zero-copy actually engaged is only known post-bind, and the routing choice depends
on it. This preserves the zero-copy fast path (issue #155).

---

## 2.2 Loading the program — embedded, pure-Rust

`src/dns/xdp/loader.rs` loads the program with [aya](https://aya-rs.dev/) (pure Rust — no
libbpf, no clang at runtime). The compiled object is embedded at build time via
`include_bytes!(concat!(env!("OUT_DIR"), "/dns_xdp.o"))` (`src/dns/xdp/loader.rs`), so
there is nothing to deploy alongside the binary.

Two objects are embedded:

- **`dns_xdp.o`** — full program, includes `BPF_MAP_TYPE_CPUMAP` for domain routing.
- **`dns_xdp_minimal.o`** — compiled with `-DNO_CPUMAP`, used as a fallback when CPUMAP
  creation fails (restricted `CAP_BPF`, older kernel). Domain routing is disabled; RSS via
  XSKMAP is used. This is why the slave (a restricted musl/static deployment) still works.

aya's ELF parser needs 8-byte alignment, but `include_bytes!` aligns to 1 — so the loader
copies the bytes into a heap `Vec<u64>` before `Ebpf::load()` (`src/dns/xdp/loader.rs`).

### The detach-on-drop guard

The attached program is tracked by an `XdpLinkId` held in an `XdpHandle` whose `Drop`
detaches the program. Without this, a crash would leave the XDP program bound to the NIC —
and on a `xdp: no` box that stray program would then silently drop LAN UDP/53. The Rust
ownership model is used here as the cleanup mechanism. The Rust structs that mirror eBPF
maps (`IcmpCfgEntry`, `domain_routing_cfg_entry`, …) are `#[repr(C)]` and marked
`unsafe impl aya::Pod`, and must match the C struct layout byte-for-byte
(`src/dns/xdp/loader.rs`).

---

## 2.3 AF_XDP: UMEM and the four rings

File: `src/dns/xdp/umem.rs`, `src/dns/xdp/socket.rs`.

AF_XDP moves frames between the kernel and user space through a **shared memory region**
(UMEM) and four single-producer/single-consumer ring buffers. Runbound's UMEM layout
(`src/dns/xdp/umem.rs`):

- **Frame size = 4096 bytes** = one OS page. DNS packets (including EDNS0 UDP) fit in one
  frame, so one frame = one packet.
- The frame pool is split in half: the lower half seeds the **RX pool** (handed to the
  kernel via the fill ring at startup), the upper half is the **TX pool** (managed by the
  worker).

The four rings:

| Ring | Direction | Carries |
|------|-----------|---------|
| Fill | user → kernel | free frames the kernel may fill with received packets |
| RX | kernel → user | descriptors of received packets |
| TX | user → kernel | descriptors of packets to transmit |
| Completion | kernel → user | frames the kernel has finished transmitting (reclaimed) |

The kernel and user space share these rings with **no lock** — synchronisation is purely
through the ring head/tail indices, accessed with explicit acquire/release memory fences
(`src/dns/xdp/umem.rs`, `std::sync::atomic::fence`). This is the standard AF_XDP
producer/consumer protocol; correctness depends on getting those fences right, which is
why the ring code is isolated and `#![deny(unsafe_op_in_unsafe_fn)]`.

### Socket setup and zero-copy

`src/dns/xdp/socket.rs` creates one `XskSocket` per NIC queue:
`socket(AF_XDP)` → register UMEM (`XDP_UMEM_REG`) → set ring sizes → `mmap` the four rings
→ `bind` to `{ifindex, queue_id}`. It requests **zero-copy** (`XDP_ZEROCOPY`) and falls
back to **copy mode** (`XDP_COPY`) when the driver/NIC cannot do ZC. Ring sizes are
configurable (powers of two in [64, 65536], default 4096; `XdpRingSizes`,
`src/dns/xdp/umem.rs`). The socket layer also drives `ethtool` channel/ring queries
(`ETHTOOL_GCHANNELS`, etc.) to align AF_XDP queues with NIC RSS queues.

---

## 2.4 The worker loop

File: `src/dns/xdp/worker.rs`. One worker owns one `XskSocket` (one NIC queue) and runs on
a dedicated OS thread, so the hot path never contends with the Tokio executor
(`src/dns/xdp/worker.rs:6`). The loop:

```
poll() → consume_rx() → parse eth/ip/udp/dns → LocalZoneSet lookup →
build response → enqueue_tx() → kick if needed → return frames to fill ring
```

The per-query answer is `answer_dns_wire`, which returns a three-way result rather than an
ambiguous `Option<usize>` (`src/dns/xdp/worker.rs:WireResult`):

- `Answered(len)` — response written into the TX frame, send it.
- `Fallback` — wire builder doesn't handle this case → hand to the slow-path handler over a
  bounded channel (`FallbackMsg`, `src/dns/xdp/worker.rs:1350`). That handler is
  the wire-native `serve_wire`.
- `Drop` — ACL Deny or unrecoverable error → silent drop, no TX, no fallback.

The explicit enum exists to avoid an ambiguous `Some(0)` sentinel (#155 review).

### Split-horizon on the fast path (#187)

Each configured split-horizon view is compiled into a **per-view wire snapshot**
(`crate::dns::cache_snapshot::ViewSnapshots`). The worker loads the view set once per RX
batch with a lock-free `ArcSwap` read (`src/dns/xdp/worker.rs:985`) and, per query,
matches the client source IP to its view **before** consulting the global cache
(`src/dns/xdp/worker.rs:1310-1320`) — so a per-source override always wins on the fast path and
answers cannot leak across views. View edits through the API hot-swap the snapshots live
(no restart), reusing the same wire serialisation as the global local-data preload.
Coverage is A/AAAA — the same as the global preload; other record types in a view fall
through to the slow path. When no split-horizon is configured the per-packet cost is zero
(the `Option` is `None`).

### VLAN tag on TX

The in-place reply preserves the 802.1Q tag that arrived in the frame. For NICs that
strip the RX tag in hardware and refuse to disable it (e.g. bnxt), `RUNBOUND_XDP_VLAN=<vid>`
re-inserts one tag on the reply (`src/dns/xdp/worker.rs:97`).

---

## 2.5 The zero-allocation response builder

File: `src/dns/wire_builder.rs` — shared by both the AF_XDP fast path and the kernel-UDP
fallback path (there is no separate `src/dns/xdp/wire_builder.rs`). The builder writes DNS
wire responses directly for the common case (A/AAAA from local zones).

- **Parse** (`parse_query`, `src/dns/wire_builder.rs:96`): validates a single-question
  query, finds the QNAME terminator with `simd::find_zero`, reads qtype/qclass, and parses
  any EDNS OPT RR. No heap allocation — the `qname_wire` is a slice into the original
  buffer (zero copy).
- **EDNS / DNSSEC** (`EdnsInfo`, `src/dns/wire_builder.rs:57`): if the OPT RR has the
  DO bit set, the query wants DNSSEC → the wire builder returns `Fallback` so the slow-path
  handler (`serve_wire`, which does the DNSSEC signing/serving) handles it. The wire fast
  path never fakes DNSSEC.
- **Build**: writes the answer directly into the output (TX UMEM) slice. The response uses
  a DNS **name-compression pointer** (`0xC0 0x0C`, `src/dns/wire_builder.rs:36`) to
  point the answer's owner name back at the question at offset 12 — so the name is not
  repeated, saving bytes and a copy. Flags are set to `QR=1 AA=1 RD RA RCODE=0`
  (authoritative NOERROR, `src/dns/wire_builder.rs:32`).

Positive answers are wire-built for A (1) and AAAA (28). Negative and error responses also
have wire builders: `build_nxdomain` / `build_nodata` / `build_refused`
(`src/dns/wire_builder.rs:388-520`) write RFC-minimal responses (no SOA in authority)
directly into the TX frame. Of these, only `build_refused` is currently wired into the
fast-path hot loop (`answer_dns_wire` in `worker.rs`); `build_nodata` is
`#[allow(dead_code)]`, reserved for a future wildcard-aware fast path, and `build_nxdomain`
is exercised only by unit tests. Recursor/forwarder **negative answers are now cached**
(#166/#210, RFC 2308): `NXDOMAIN`/`NODATA` datagrams are stored in the same snapshot the
fast path reads — keyed by (name, type) with a `min(SOA.minimum, SOA.ttl)` TTL (capped) —
so a repeated negative is served from cache like any positive. `Bogus` (CD-served) answers
are never cached. The in-kernel eBPF blacklist `NXDOMAIN` is still forged fresh per packet.

---

## 2.6 The recursion-miss reply socket

When the XDP path cannot answer (a forwarded query, a cache miss), it falls back to the
slow-path handler (`serve_wire`). But XDP workers have **no kernel arrival socket** to reply
on. Replying from an ephemeral port causes clients to silently reject the answer (the source
port doesn't match :53). A shared reply socket bound to `:53`, `XDP_FALLBACK_REPLY_SOCK`
(`src/dns/kernel_loop.rs:56`), carries all XDP-mode fallback replies (#167). This constraint
is specific to the zero-copy model and is documented here because it shapes the code.

---

## 2.7 What the fast path deliberately does *not* do

- It does not handle TCP, DoT, DoH, DoQ — those `XDP_PASS` to the kernel and the slow-path
  handler (`serve_wire`).
- It does not validate DNSSEC — DO-bit queries fall back.
- It does not do recursion — misses fall back.
- IPv6 blacklist hits fall through to the slow path (only IPv4 NXDOMAIN is forged in eBPF).

The fast path's job is to make the **most frequent, simplest** queries nearly free, and to
get out of the way for everything else. The performance consequences — and the measured
ceilings where the bottleneck moves to the PCIe/NIC bus rather than Runbound — are in
[08-performance.md](08-performance.md).
