# Runbound Internals — Packet Lifecycle & Architecture

Audience: kernel/network engineers, performance analysts, contributors.  
Version: v0.15.0.

---

## Overview

Runbound has two parallel processing paths for incoming DNS queries:

```
NIC hardware
    │
    ├─── [XDP fast path] ──── eBPF filter ──── AF_XDP socket ──── XDP worker thread
    │                                                                      │
    │                                                              answer from:
    │                                                              · local zone
    │                                                              · cache snapshot
    │                                                              · rate-limit drop
    │                                                              · ACL drop/REFUSED
    │
    └─── [XDP_PASS] ─── kernel UDP stack ─── SO_REUSEPORT ─── Tokio worker
                                                                     │
                                                             hickory-server:
                                                             · recursive resolve
                                                             · upstream forward (DoT/UDP)
                                                             · DNSSEC validation
                                                             · blacklist / feeds
```

The XDP path handles the hot path (local zones + cache hits) at kernel-bypass speed.  
The Tokio path handles everything else (cache misses, recursion, management API).

---

## 1. NIC layer

### Hardware RX ring

**Implemented v0.6.9.** `maximize_nic_ring()` in `src/dns/xdp/socket.rs`.

At startup, before attaching the XDP program:

```
SIOCETHTOOL → ETHTOOL_GRINGPARAM  →  read rx_max_pending, tx_max_pending
SIOCETHTOOL → ETHTOOL_SRINGPARAM  →  set rx_pending = rx_max_pending
```

| Driver | Default ring | Max ring | After v0.6.9 |
|--------|-------------|---------|--------------|
| ixgbe (X520, X540) | 512 | 4096 | 4096 |
| igc (I225/I226) | 256 | 4096 | 4096 |
| i40e (X710) | 512 | 4096 | 4096 |
| virtio-net | 256 | 256 | 256 (fallback) |

Fallback: `EOPNOTSUPP` or `EPERM` → WARN + continue with driver default.

**Why it matters:** at 10 M QPS = 10 packets/µs, a 512-descriptor ring gives 51 µs of tolerance. Any scheduling jitter longer than 51 µs overflows the NIC FIFO. The overflow is silent — `rx_no_buffer_count` increments in `ethtool -S`, nothing in Runbound logs.

**Monitor:** `GET /api/system` → `nic_rx_ring`, `nic_rx_ring_max`, `nic_rx_dropped`.

### IRQ affinity

**Implemented (#68).** At startup, after spawning XDP workers, Runbound reads `/proc/interrupts` to find the IRQ numbers for the active NIC interface, then writes the correct core mask to `/proc/irq/<N>/smp_affinity_list` — one IRQ per queue, pinned to the same physical core as its XDP worker.

Requires `CAP_NET_ADMIN` (already required for XDP attach). Enabled via config:

```
server:
    xdp-irq-affinity: auto    # default: off
```

Effect: eliminates cross-core IRQ delivery. Without pinning, the kernel may wake a different core to handle the interrupt, causing guaranteed L1/L2 cache misses when the XDP worker reads the packet. Gain: 1–3% throughput, −1–5 µs latency variance (theoretical).

---

## 2. eBPF XDP program

**File:** `ebpf/dns_xdp.c` (~154 lines). Compiled at build time, embedded in the binary via `aya`.

### Execution context

- Runs in driver hook, before `sk_buff` allocation
- No heap, no blocking, no loops > 64 iterations (BPF verifier limit)
- Access: raw packet bytes via bounded pointer arithmetic

### Packet classification (per packet, ~50 ns)

```
ethernet header  →  ethertype == 0x0800 (IPv4) or 0x86DD (IPv6) ?
                         ↓ yes
IP/IPv6 header   →  protocol == UDP (17) ?
                         ↓ yes
UDP header       →  dport == 53 ?
                         ↓ yes
DNS header       →  QR bit == 0 (query, not response) ?
                         ↓ yes
→ redirect to AF_XDP socket or CPUMAP
                         ↓ no (any check fails)
→ XDP_PASS (kernel path)
```

All header accesses are bounds-checked against `data_end` — BPF verifier rejects the program otherwise.

### CPUMAP routing (#67)

**Implemented.** FNV-1a hash of QNAME → `hash % NB_WORKERS` → always the same CPU for the same domain. Enabled with `xdp-domain-routing: yes`.

```c
// ebpf/dns_xdp.c — dns_qname_hash()
uint32_t h = 2166136261u;  // FNV-1a offset basis
for (int i = 0; i < 64 && ...; i++) {
    h ^= (b | 0x20u);      // ASCII lowercase
    h *= 16777619u;         // FNV-1a prime
}
bpf_redirect_map(&CPUMAP, h % nb_workers, XDP_PASS);
```

Effect: L1/L2 cache stays warm for each domain on its dedicated core. Cross-core cache line bouncing eliminated. CPUMAP initialized in `src/dns/xdp/loader.rs`, flag `DOMAIN_ROUTING_ENABLED` passed via aya global.

### XSKMAP

`XSKMAP max_entries = 64` — architectural limit. Runbound rejects `queue_id >= 64` at load time. On cards with > 64 queues, excess queues fall back to XDP_PASS.

### ICMP kernel-bypass responder (v0.9.1)

Runbound handles ICMP echo requests (ping) entirely inside the eBPF program — no packet
ever reaches the kernel IP stack for ICMP, eliminating per-packet softirq cost.

**BPF maps:**

| Map | Type | Purpose |
|-----|------|---------|
| `icmp_cfg` | `BPF_MAP_TYPE_ARRAY` | Config flags: enabled/disabled |
| `icmp_rate_limit` | `BPF_MAP_TYPE_LRU_HASH` | Per-source IP token bucket (tokens remaining, last_ts) |
| `icmp_banned` | `BPF_MAP_TYPE_LRU_HASH` | Temporarily banned IPs (flood detection) |

**Per-packet logic:**

```
ICMP echo request received
    ↓
icmp_cfg[0].enabled == 0 ?  →  XDP_PASS (kernel handles normally)
    ↓
icmp_banned[src_ip] present ?  →  XDP_DROP (ban still active)
    ↓
icmp_rate_limit[src_ip]: tokens > 0 ?
    no  →  insert icmp_banned[src_ip]  →  XDP_DROP
    yes →  decrement token, continue
    ↓
swap src/dst MAC + IP, set type=ECHO_REPLY, recompute checksum
    ↓
XDP_TX (transmit directly from driver, zero kernel involvement)
```

Rate limit and ban thresholds are configurable via `POST /api/icmp`. Values are written
to BPF maps via `aya` map handles — no XDP detach/reattach needed.

---

## 3. AF_XDP socket and UMEM

**Files:** `src/dns/xdp/umem.rs`, `src/dns/xdp/socket.rs`.

### Memory layout

```
UMEM = contiguous mmap region
  ├─ frame 0    (4096 bytes)  ← one DNS packet max
  ├─ frame 1    (4096 bytes)
  ├─ ...
  └─ frame 8191 (4096 bytes)
                               total: 32 MiB per socket (per NIC queue)
```

Hugepages (`MAP_HUGETLB`) reduce TLB pressure — one 2 MiB hugepage covers 512 frames. Enable with `xdp-hugepages: 512` in config and `vm.nr_hugepages = 512` in sysctl.

### Ring layout (all depths = 4096)

```
fill ring   →  kernel writes available frame addresses (worker → kernel)
rx ring     ←  kernel deposits received frames (kernel → worker)
tx ring     →  worker writes frames to send (worker → kernel)
comp ring   ←  kernel returns transmitted frames (kernel → worker)
```

Ring access uses `read_volatile` / `write_volatile` + `Ordering::Acquire` / `Release` fences — required for correct visibility between kernel and userspace without a syscall.

### NUMA affinity

**Implemented v0.6.9.** After CPU pinning, `rebind_to_local_numa()` in `src/dns/xdp/umem.rs`:

```
SYS_getcpu  (vDSO, ~3 ns)    →  get current NUMA node
mbind(MPOL_PREFERRED|MF_MOVE) →  migrate UMEM pages to local node
```

Gain: −30–40 ns/packet on dual-socket servers (theoretical — derived from ~120 ns cross-node vs ~40 ns local DRAM latency). Silent fallback on single-socket and containers.

---

## 4. XDP worker thread

**File:** `src/dns/xdp/worker.rs`. One OS thread per NIC queue, pinned to a physical core.

### Per-packet processing (hot path)

```
poll() wakeup           ~100 ns   kernel notifies worker of available RX frames
parse Eth/IP/UDP         ~50 ns   inline, no allocation, pointer arithmetic on UMEM frame
parse DNS question       ~80 ns   QNAME decompression, QTYPE/QCLASS extraction
ACL lookup               ~50 ns   ArcSwap<Vec<IpNet>> load + CIDR match
rate limiter            ~100 ns   DashMap<IpAddr, TokenBucket> lookup + decrement
LocalZoneSet lookup     ~200 ns   ArcSwap<HashMap<Name, ZoneEntry>> load + get
cache snapshot lookup   ~100 ns   ArcSwap<HashMap<QuestionKey, CacheEntry>> load + get
build response          ~200 ns   memcpy DNS header + answer into TX UMEM frame, patch QueryID
TX enqueue + kick        ~50 ns   batch of 32 frames per sendto() kick
                        ────────
total (cache hit)      ~930 ns   ≈ 1 µs/query
```

### SIMD hot-path dispatch (v0.9.46)

`src/dns/simd.rs` detects the CPU feature level once at startup via `OnceLock`:

```
SimdLevel::detect() → CPUID → Scalar | SSE2 | SSE42 | AVX2 | AVX512
```

The detected level is applied transparently to three hot-path operations:

| Operation | Scalar | SSE2 | AVX2 |
|-----------|--------|------|------|
| QNAME label lowercase | 1 byte/cycle | 16 bytes/cycle | 32 bytes/cycle |
| QNAME parse (label scan + dot insert) | 2 passes | 1 pass (fused) | 1 pass (fused) |
| `QuestionKey` equality | byte loop | `pcmpeqb`+`pmovmskb` | `vpcmpeqb`+`vpmovmskb` |

**CRC32c domain hashing** (`src/dns/hasher.rs`): hardware `_mm_crc32_u64` replaces FNV-1a. ~20 ns/lookup on SSE4.2 CPUs vs ~80 ns for FNV-1a.

```rust
// src/dns/simd.rs — level detected once, then static
pub fn simd_level() -> SimdLevel {
    static LEVEL: OnceLock<SimdLevel> = OnceLock::new();
    *LEVEL.get_or_init(SimdLevel::detect)
}
```

No runtime branch overhead — dispatch is a single indirect call resolved at init.

### Cache snapshot

**Implemented.** `ArcSwap<HashMap<QuestionKey, CacheEntry>>` in `src/dns/cache_snapshot.rs`.

- XDP worker calls `cache.load()` — atomic pointer load, no lock, no syscall
- Cache insertions go through `DashMap<QuestionKey, CacheEntry>` (16-shard RwLock, no global contention)
- Publish loop stores a new `Arc<HashMap>` atomically

**Generation-skipping publish (v0.9.17, PERF-1/#135):** the publish loop no longer
clones the DashMap unconditionally every 10 ms. A `CACHE_WRITE_GEN` atomic counter
is incremented only on `cache_insert`. The publish loop compares it to the last
published generation and skips the O(n) clone when no writes occurred. A forced
eviction pass runs every 256 ticks (~2.56 s) to drop TTL-expired entries regardless.

Effect: at steady-state (warm cache, no new upstream responses), CPU usage of the
publish loop drops to near zero. Under heavy ingest the full clone still runs.

**Wire format cache (v0.6.8, #64):** `CacheEntry` stores a pre-serialized UDP payload
(`wire_payload: Bytes`) built at cache-insert time. XDP worker answers cache hits with a
direct `memcpy` + 2-byte QueryID patch — no DNS parsing on the hot path. Reduces
cache-hit latency from ~930 ns to ~580 ns.

```rust
// src/dns/cache_snapshot.rs
struct CacheEntry {
    wire_payload: Bytes,  // full UDP payload, QID zeroed at bytes [0..2]
    expires_at: Instant,
}
// worker (src/dns/xdp/worker.rs):
let wire = &entry.wire_payload;
frame[..wire.len()].copy_from_slice(wire);
frame[0..2].copy_from_slice(&query_id.to_be_bytes());  // patch QueryID
```

### TX batching

**Implemented v0.6.8.** All TX descriptors from the current RX batch are enqueued in a single `enqueue_tx(&tx_descs[..n])` call before kicking the TX ring. Reduces syscalls from 1/packet to 1/batch (~32 packets). Gain: +10–15% throughput (theoretical).

### Descriptor safety

Every RX descriptor from the kernel is validated before memory access:

```rust
let end = (desc.addr as usize).checked_add(desc.len as usize);
if desc.len > FRAME_SIZE || end.map(|e| e > umem.area_len).unwrap_or(true) {
    // drop — kernel bug or confused-deputy
}
```

---

## 5. Tokio slow path

**Files:** `src/dns/`, `src/api/`. Standard async Rust.

### UDP listener

32 `SO_REUSEPORT` UDP sockets, one per physical core. The kernel distributes incoming packets across sockets by 4-tuple hash. Each Tokio worker owns one socket — no cross-thread contention on the receive path.

**SO_BUSY_POLL (v0.9.17):** when XDP is unavailable (containers, cloud VMs), Runbound
applies `SO_BUSY_POLL` to each socket:

```rust
setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &50u32)  // 50 µs kernel spin-poll
```

The kernel spins on the driver RX queue for up to 50 µs before sleeping, eliminating
the scheduler wakeup for high-QPS bursts. Configurable via config:

```
server:
    busy-poll-us: 50    # default: 50 (0 = disabled)
```

Effect: −20–60 µs p50 latency on the slow path at the cost of one pinned CPU. Disabled
automatically when XDP is active (XDP workers spin-poll AF_XDP rings natively).

### Resolver

`hickory-server` with `hickory-resolver` for upstream forwarding.

- **Local zones:** `ArcSwap<LocalZoneSet>` — reads are lock-free, writes clone + swap
- **Blacklist / feeds:** `ArcSwap<BlacklistSet>` — same pattern
- **Upstream pool:** `ArcSwap<SharedResolver>` — rebuilt on every add/remove/reconnect

### DoT pool

**Fixed v0.6.9 (#77).** `hickory-resolver` opens TLS connections lazily. On first query after idle, the pool is empty → SERVFAIL. Fix: `rebuild_and_swap` calls `warm_up()` (3 × 250 ms probes) before atomically swapping the resolver. `POST /api/upstreams/reconnect` triggers a synchronous reconnect + warm-up.

### Cache insertion

DNS responses from upstream are inserted into `DashMap<QuestionKey, CacheEntry>` (lock-free at entry level). The XDP cache snapshot picks them up within 10 ms.

### Cgroup v2 memory awareness (v0.9.28)

At startup, Runbound inspects its own cgroup to determine available memory before
sizing the DNS cache:

```
/proc/self/cgroup  →  parse v2 path  →  /sys/fs/cgroup/<path>/memory.max
                                         /sys/fs/cgroup/<path>/memory.current
```

Cache size formula:

```
available = memory.max - memory.current
cache_size = min(available × 0.60, 1 GiB)
```

If `memory.max` is `max` (unlimited), falls back to `MemAvailable` from `/proc/meminfo`.
The `MemoryMax=2G` directive in the systemd unit sets the cgroup limit. With a fresh
start (~80 MiB RSS), Runbound allocates ~(2048−80)×0.60 ≈ 1.18 GiB → rounded to 1 GiB.

Logged at startup: `INFO runbound::dns::server: cache size auto-sized from MemAvailable cache_size=N`

### Serve-stale (RFC 8767, v0.9.3)

When all upstreams are unreachable, Runbound answers from expired cache entries rather
than returning SERVFAIL (`src/dns/serve_stale.rs`):

```
upstream timeout / all upstreams unreachable
    ↓
cache lookup (expired entries included)
    found  →  answer with TTL clamped to serve-stale-ttl + EDE code 3 (Stale Answer)
    missing →  SERVFAIL
```

```
server:
    serve-stale: yes              # default: no
    serve-stale-ttl: 30           # TTL reported for stale answers (seconds)
    serve-stale-max-age: 86400    # refuse entries expired longer than this
```

Stale entries are replaced by fresh upstream responses as soon as connectivity recovers.

### Per-client alert thresholds (v0.9.12)

`src/alerts.rs` implements configurable per-client-IP alert rules. Each rule watches
one metric (query rate, NXDOMAIN rate, or blocked-query rate) and fires an action (log,
webhook, or auto-block):

```
IncomingQuery { src_ip, qtype, blocked, nxdomain }
    ↓
AlertSet::check(&src_ip, &event)
    → TokenBucket per (rule_id, src_ip) in DashMap
    → threshold exceeded? → log / POST webhook / add to blacklist
```

```
alert:
    name:    "flood detector"
    metric:  qps          # qps | nxdomain-rate | blocked-rate
    limit:   500
    window:  10           # seconds
    action:  log          # log | webhook | block
    webhook: "http://..."
```

Multiple `alert:` blocks supported. Managed via `GET/POST/DELETE /api/alerts`.

### Zone transfer — AXFR / IXFR (v0.9.13)

`src/dns/axfr.rs` implements outgoing zone transfers (RFC 5936 AXFR, RFC 1995 IXFR)
for secondary nameservers.

**AXFR (TCP only):** SOA serial checked, `allow-axfr` ACL enforced, records streamed in
batches of 64 to avoid holding the zone lock across the full transfer. TSIG
(HMAC-SHA256 or HMAC-SHA512) supported.

**IXFR (incremental):** Runbound keeps a per-zone journal (ring buffer, last 10 changes).
If the client's SOA serial is within the journal window → incremental diff; otherwise
falls back to full AXFR.

```
zone "home." {
    type master;
    allow-axfr: 192.168.8.0/24;
    tsig-key-name: "axfr-key";
}
tsig-key "axfr-key" {
    algorithm: hmac-sha256;
    secret: "base64==";
}
```

### RFC 2136 DDNS + TSIG (v0.9.3)

`src/dns/ddns.rs` implements RFC 2136 dynamic DNS updates. Clients (`nsupdate`, DHCP
servers, router firmware) send DNS UPDATE messages to add, modify, or delete records
without a Runbound restart.

All UPDATE messages must carry a valid TSIG RR (RFC 2845). Unsigned updates are refused.
Anti-replay: `|now − ts| > 300 s` → RCODE=BADTIME.

```
DNS UPDATE (TCP/UDP port 53)
    ↓
parse + TSIG verify  →  fail → RCODE=BADSIG
    ↓
prerequisite check   →  fail → RCODE=NXRRSET / YXRRSET
    ↓
apply to LocalZoneSet → ArcSwap swap → persist to dns_entries.json (async)
    ↓
RCODE=NOERROR
```

---

## 6. Timing budget summary

> Latency estimates below are **theoretical** (derived from instruction counts and hardware data sheets). See [benchmark/INDEX.md](benchmark/INDEX.md) and [whitepaper/08-performance.md](whitepaper/08-performance.md) for measured results.

| Stage | Implemented | Latency |
|-------|-------------|---------|
| NIC DMA → UMEM | v0.4.14 | ~0 ns |
| eBPF XDP filter | v0.4.14 | ~50 ns |
| AF_XDP ring enqueue | v0.4.14 | ~0 ns |
| poll() wakeup | v0.4.14 | ~100 ns |
| Parse Ethernet/IP/UDP | v0.4.14 | ~50 ns |
| Parse DNS QNAME (SSE2 1-pass, v0.9.46) | v0.9.46 | ~40 ns |
| ACL check | v0.5.0 | ~50 ns |
| Rate limiter (DashMap) | v0.5.0 | ~100 ns |
| LocalZoneSet lookup | v0.4.14 | ~200 ns |
| Domain hash (CRC32c SSE4.2, v0.9.46) | v0.9.46 | ~20 ns |
| Cache snapshot lookup (DashMap) | v0.6.9 | ~100 ns |
| Build response (wire_payload memcpy + QueryID patch) | v0.6.8 | ~80 ns |
| TX enqueue + kick (batch/32) | v0.6.8 | ~50 ns |
| **Total — cache hit (wire format + SIMD, v0.9.46)** | | **~530 ns** |
| Slow path — local zone (Tokio) | v0.4.14 | ~200 µs |
| Slow path — upstream UDP | v0.4.14 | RTT + ~50 µs |
| Slow path — upstream DoT | v0.6.7 | RTT + ~2 ms |

---

## 7. Throughput model

> All numbers in this section are **theoretical** estimates derived from the per-stage timing budget above. Measured AF/XDP throughput on bare-metal Intel ixgbe will be published in v0.8.

```
QPS per core = 1 / hot_path_latency
             = 1 / 1 µs
             = 1 M QPS/core   (theoretical)

Total XDP QPS = QPS/core × nb_xdp_workers × cache_hit_rate
```

With 8 XDP workers and 95% cache hit rate (typical for a resolver with hot domains):

```
8 × 1 M × 0.95 = 7.6 M QPS   (theoretical)
```

With wire format cache (#64, v0.6.8, implemented):

```
8 × 3.3 M × 0.95 = 25 M QPS   (theoretical)
```

Practical ceiling: 10 GbE wire speed = **14.88 M 64-byte packets/second**.

---

## 8. Roadmap

### Implemented — v0.9.46 (asm-hotpath)

| Feature | Issue | Location |
|---------|-------|----------|
| CRC32c SSE4.2 domain hashing | #72 | `src/dns/hasher.rs` |
| SSE2 label lowercasing (16 bytes/iter) | #151 | `src/dns/simd.rs`, `src/dns/xdp/worker.rs` |
| AVX2 label lowercasing (32 bytes/iter) | #151 | `src/dns/simd.rs` |
| SSE2 `QuestionKey` equality (`pcmpeqb`+`pmovmskb`) | #151 | `src/dns/simd.rs` |
| Bulk SIMD QNAME 1-pass parse | #152 | `src/dns/simd.rs` |
| CPU feature OnceLock dispatch (SimdLevel) | #152 | `src/cpu.rs` |

### Planned — v1.0

| Feature | Issue | Notes |
|---------|-------|-------|
| io_uring slow path | #65 | Replace recvmsg/sendmsg on Tokio UDP path with io_uring SQEs. Useful for containers/cloud VMs without XDP. |
| rkyv zero-copy cache persistence | #29 | Replace bincode with rkyv. Target: < 5 ms restart with 1M entries. |
| DNSSEC full validation | #34 | Chain of trust from root, NSEC/NSEC3, DS/DNSKEY. Full resolver mode — not a patch. |
| eBPF XDP program in Rust (aya-bpf) | — | Rewrite `ebpf/dns_xdp.c` in Rust using `aya-bpf` crate. Eliminates clang build dependency. |

---

## 9. Data structures — quick reference

| Structure | Location | Purpose |
|-----------|----------|---------|
| `ArcSwap<LocalZoneSet>` | `src/dns/zones.rs` | Local DNS records — zero-lock reads |
| `ArcSwap<BlacklistSet>` | `src/dns/blacklist.rs` | Blocked domains — zero-lock reads |
| `ArcSwap<SharedResolver>` | `src/dns/resolver.rs` | Upstream forwarder — atomic swap on change |
| `ArcSwap<CacheSnapshot>` | `src/dns/cache_snapshot.rs` | XDP-readable cache — generation-skipping publish |
| `DashMap<QuestionKey, CacheEntry>` | `src/dns/cache_snapshot.rs` | Mutable cache — lock-free inserts |
| `DashMap<IpAddr, TokenBucket>` | `src/dns/xdp/worker.rs` | Per-IP rate limiter |
| `DashMap<(RuleId, IpAddr), TokenBucket>` | `src/alerts.rs` | Per-client alert thresholds |
| `XSKMAP` (BPF map) | `ebpf/dns_xdp.c` | XDP → AF_XDP socket redirect, max 64 entries |
| `CPUMAP` (BPF map) | `ebpf/dns_xdp.c` | XDP → CPU redirect (QNAME-aware) |
| `icmp_cfg` (BPF array) | `ebpf/dns_xdp.c` | ICMP responder enable/disable flag |
| `icmp_rate_limit` (BPF LRU hash) | `ebpf/dns_xdp.c` | Per-IP ICMP token bucket |
| `icmp_banned` (BPF LRU hash) | `ebpf/dns_xdp.c` | ICMP flood ban list |
| `OnceLock<String>` | `src/dns/xdp/socket.rs` | Active interface name — read by API without lock |
| `OnceLock<ArcSwap<String>>` | `src/api/mod.rs` | API key — ArcSwap inner allows live rotation via `POST /api/rotate-key` without restart |
| `AtomicU64` — `CACHE_WRITE_GEN` | `src/dns/cache_snapshot.rs` | Generation counter for publish-loop skip |
| `AtomicU32` × 2 | `src/dns/xdp/socket.rs` | `nic_rx_ring`, `nic_rx_ring_max` — read by API |

---

## 10. Build flags

| Feature | Default | Effect |
|---------|---------|--------|
| `xdp` | ✅ enabled | Compile eBPF program and AF_XDP code |
| `jemalloc` | ✅ enabled | Replace system allocator — better multi-thread perf |
| `hsm` | ❌ disabled | PKCS#11 hardware key support |

```bash
# Full release build (all targets)
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-musl

# Disable XDP (containers, cloud VMs without CAP_BPF)
cargo build --release --no-default-features
```

The eBPF C program (`ebpf/dns_xdp.c`) is compiled by `build.rs` using the system `clang`. The resulting `.o` is embedded in the Rust binary via `include_bytes!` — no external file needed at runtime.
