# Runbound Internals — Packet Lifecycle & Architecture

Audience: kernel/network engineers, performance analysts, contributors.  
Version: v0.6.9. Planned items are marked **[planned]**.

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

Effect: eliminates cross-core IRQ delivery. Without pinning, the kernel may wake a different core to handle the interrupt, causing guaranteed L1/L2 cache misses when the XDP worker reads the packet. Gain: 1–3% throughput, −1–5 µs latency variance.

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

Gain: −30–40 ns/packet on dual-socket servers (eliminates cross-node DRAM access at ~120 ns vs local ~40 ns). Silent fallback on single-socket and containers.

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

### Cache snapshot

**Implemented.** `ArcSwap<HashMap<QuestionKey, CacheEntry>>` in `src/dns/cache_snapshot.rs`.

- Publish loop runs every **10 ms** (reduced from 100 ms in v0.6.9)
- XDP worker calls `cache.load()` — atomic pointer load, no lock, no syscall
- Cache insertions go through `DashMap<QuestionKey, CacheEntry>` (16-shard RwLock, no global contention)
- Publish loop snapshots the DashMap via shard iteration and stores a new `Arc<HashMap>` atomically

**Planned (#64 — wire format cache):** pre-serialize the DNS response payload at insert time. XDP worker skips DNS parsing entirely — just `memcpy` the pre-built UDP payload into the TX frame and patch the QueryID (2 bytes). Expected hot path: **< 300 ns** total.

```rust
// planned
struct CacheEntry {
    wire: Bytes,        // pre-serialized UDP payload (DNS header + answer section)
    expires: Instant,
}
// worker:
frame[..entry.wire.len()].copy_from_slice(&entry.wire);
frame[10..12].copy_from_slice(&query_id.to_be_bytes());  // patch QueryID
```

### TX batching

**Implemented v0.6.8.** All TX descriptors from the current RX batch are enqueued in a single `enqueue_tx(&tx_descs[..n])` call before kicking the TX ring. Reduces syscalls from 1/packet to 1/batch (~32 packets). Gain: +10–15% throughput.

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

### Resolver

`hickory-server` with `hickory-resolver` for upstream forwarding.

- **Local zones:** `ArcSwap<LocalZoneSet>` — reads are lock-free, writes clone + swap
- **Blacklist / feeds:** `ArcSwap<BlacklistSet>` — same pattern
- **Upstream pool:** `ArcSwap<SharedResolver>` — rebuilt on every add/remove/reconnect

### DoT pool

**Fixed v0.6.9 (#77).** `hickory-resolver` opens TLS connections lazily. On first query after idle, the pool is empty → SERVFAIL. Fix: `rebuild_and_swap` calls `warm_up()` (3 × 250 ms probes) before atomically swapping the resolver. `POST /api/upstreams/reconnect` triggers a synchronous reconnect + warm-up.

### Cache insertion

DNS responses from upstream are inserted into `DashMap<QuestionKey, CacheEntry>` (lock-free at entry level). The XDP cache snapshot picks them up within 10 ms.

---

## 6. Timing budget summary

| Stage | Implemented | Latency |
|-------|-------------|---------|
| NIC DMA → UMEM | v0.4.14 | ~0 ns |
| eBPF XDP filter | v0.4.14 | ~50 ns |
| AF_XDP ring enqueue | v0.4.14 | ~0 ns |
| poll() wakeup | v0.4.14 | ~100 ns |
| Parse Ethernet/IP/UDP | v0.4.14 | ~50 ns |
| Parse DNS QNAME | v0.4.14 | ~80 ns |
| ACL check | v0.5.0 | ~50 ns |
| Rate limiter (DashMap) | v0.5.0 | ~100 ns |
| LocalZoneSet lookup | v0.4.14 | ~200 ns |
| Cache snapshot lookup (DashMap) | v0.6.9 | ~100 ns |
| Build response (wire_payload memcpy + QueryID patch) | v0.6.9 | ~80 ns |
| TX enqueue + kick (batch/32) | v0.6.8 | ~50 ns |
| **Total — cache hit (wire format)** | | **~580 ns** |
| Slow path — local zone (Tokio) | v0.4.14 | ~200 µs |
| Slow path — upstream UDP | v0.4.14 | RTT + ~50 µs |
| Slow path — upstream DoT | v0.6.7 | RTT + ~2 ms |

---

## 7. Throughput model

```
QPS per core = 1 / hot_path_latency
             = 1 / 1 µs
             = 1 M QPS/core

Total XDP QPS = QPS/core × nb_xdp_workers × cache_hit_rate
```

With 8 XDP workers and 95% cache hit rate (typical for a resolver with hot domains):

```
8 × 1 M × 0.95 = 7.6 M QPS
```

With wire format cache (#64, planned):

```
8 × 3.3 M × 0.95 = 25 M QPS   (theoretical)
```

Practical ceiling: 10 GbE wire speed = **14.88 M 64-byte packets/second**.

---

## 8. Planned optimisations

### #65 — io_uring slow path

### #65 — io_uring slow path

Replace `recvmsg`/`sendmsg` syscalls on the Tokio UDP path with `io_uring` submission queues. Reduces syscall overhead on the slow path. Useful when XDP is unavailable (containers, cloud VMs).

### #29 — rkyv zero-copy cache persistence

Replace `bincode` serialization with `rkyv` zero-copy deserialization for the on-disk cache snapshot. Target: < 5 ms restart with 1 M cache entries (currently ~800 ms with bincode).

### DNSSEC (v1.x)

Full recursive DNSSEC validation — chain of trust from root, NSEC/NSEC3 negative proof, DS/DNSKEY management. Not a patch — a full resolver mode. Planned for v1.x after the XDP optimisation work is complete.

---

## 9. Data structures — quick reference

| Structure | Location | Purpose |
|-----------|----------|---------|
| `ArcSwap<LocalZoneSet>` | `src/dns/zones.rs` | Local DNS records — zero-lock reads |
| `ArcSwap<BlacklistSet>` | `src/dns/blacklist.rs` | Blocked domains — zero-lock reads |
| `ArcSwap<SharedResolver>` | `src/dns/resolver.rs` | Upstream forwarder — atomic swap on change |
| `ArcSwap<CacheSnapshot>` | `src/dns/cache_snapshot.rs` | XDP-readable cache — refreshed every 10 ms |
| `DashMap<QuestionKey, CacheEntry>` | `src/dns/cache_snapshot.rs` | Mutable cache — lock-free inserts |
| `DashMap<IpAddr, TokenBucket>` | `src/dns/xdp/worker.rs` | Per-IP rate limiter |
| `XSKMAP` (BPF map) | `ebpf/dns_xdp.c` | XDP → AF_XDP socket redirect, max 64 entries |
| `CPUMAP` (BPF map) | `ebpf/dns_xdp.c` | XDP → CPU redirect (QNAME-aware, planned) |
| `OnceLock<String>` | `src/dns/xdp/socket.rs` | Active interface name — read by API without lock |
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
