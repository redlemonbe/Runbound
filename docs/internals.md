# Runbound Internals — Packet Lifecycle & Architecture

Audience: kernel/network engineers, performance analysts, contributors.  
Version: 0.9.1.

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
                                                             serve_wire (wire-native):
                                                             · local-zone + split-horizon
                                                             · upstream forward (DoT/UDP)
                                                             · AXFR/IXFR · TSIG · DDNS
                                                             · DNSSEC signing
                                                             · blacklist / feeds
```

The XDP path handles the hot path (local zones + cache hits) at kernel-bypass speed.  
The Tokio path handles everything else (cache misses, forwarding, management API).

> DNS is served **entirely on Runbound's own DNS wire codec** (`src/dns/wire/`, the
> `serve_wire` path in `src/dns/server.rs`) on every path, including full-recursion. The
> sovereign **full-recursion** resolver (`src/dns/recursor_wire.rs`) and DNSSEC validation
> (`src/dns/dnssec_*.rs`) are entirely in-house and always compiled in (no Cargo
> feature gates them) — there is no `recursor` Cargo feature. Both are
> **off by runtime default**, though: `resolution: forward` and
> `dnssec-validation: no` are the config defaults (`UnboundConfig::defaults()`,
> `src/config/parser.rs`); full-recursion and DNSSEC validation are opt-in via
> `resolution: full-recursion` / `dnssec-validation: yes`, not a build flag.
> `hickory-proto` is **only** a `[dev-dependencies]` entry, used exclusively
> by the differential oracle tests (`cargo tree -e normal` is hickory-free).

---

## 1. NIC layer

### Hardware RX ring

`maximize_nic_ring()` in `src/dns/xdp/socket.rs`.

At startup, before attaching the XDP program:

```
SIOCETHTOOL → ETHTOOL_GRINGPARAM  →  read rx_max_pending, tx_max_pending
SIOCETHTOOL → ETHTOOL_SRINGPARAM  →  set rx_pending = rx_max_pending
```

| Driver | Default ring | Max ring | Applied |
|--------|-------------|---------|---------|
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

### ICMP kernel-bypass responder

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

Rate limit and ban thresholds are configurable via `PUT /api/icmp/config` (there is a
separate `GET /api/icmp/stats` for counters; no bare `/api/icmp` route exists). Values are written
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

After CPU pinning, `rebind_to_local_numa()` in `src/dns/xdp/umem.rs`:

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

### SIMD hot-path dispatch

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

**Generation-skipping publish (PERF-1/#135):** the publish loop does not
clone the DashMap unconditionally every 10 ms. A `CACHE_WRITE_GEN` atomic counter
is incremented only on `cache_insert`. The publish loop compares it to the last
published generation and skips the O(n) clone when no writes occurred. A forced
eviction pass runs every 256 ticks (~2.56 s) to drop TTL-expired entries regardless.

Effect: at steady-state (warm cache, no new upstream responses), CPU usage of the
publish loop drops to near zero. Under heavy ingest the full clone still runs.

**Wire format cache (#64):** `CacheEntry` stores a pre-serialized UDP payload
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

All TX descriptors from the current RX batch are enqueued in a single `enqueue_tx(&tx_descs[..n])` call before kicking the TX ring. Reduces syscalls from 1/packet to 1/batch (~32 packets). Gain: +10–15% throughput (theoretical).

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

**SO_BUSY_POLL:** the AF_XDP socket setup (`src/dns/xdp/socket.rs`) applies
NAPI busy-poll hints unconditionally, best-effort:

```rust
setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, &1u32)
setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL,        &20u32)  // 20 µs kernel spin-poll budget
setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &64u32)  // max packets/cycle
```

The kernel spins on the driver RX queue for up to 20 µs before sleeping, eliminating
the scheduler wakeup for high-QPS bursts (silently ignored on pre-5.11 kernels). This
value is hardcoded, not config-tunable. Separately, there is a boolean
`udp-busy-poll: yes/no` config directive (default: `no`) that is parsed and persisted
but currently has no effect on the Tokio UDP listener — no `setsockopt` call in the
slow path is gated on it yet:

```
server:
    udp-busy-poll: no    # default: no — parsed but not yet wired to the slow-path socket
```

Effect (theoretical): reduced wakeup latency for the AF_XDP socket under high-QPS
bursts, at the cost of extra CPU spin time on the XDP worker core. This is separate
from — and not to be confused with — busy-polling on the Tokio UDP slow-path sockets,
which is not currently implemented.

### Resolver

The slow path is **wire-native** (`serve_wire` in `src/dns/server.rs`): incoming queries
are parsed and answered with Runbound's own DNS wire codec (`src/dns/wire/`). Cache misses
in `forward` mode are forwarded by the in-house forwarder (`src/dns/forward.rs`). The
forwarder validates the upstream response's transaction ID and question (name/type/class)
before accepting it — a cache-poisoning defence (`forward.rs::response_matches`).
The sovereign full-recursion resolver is entirely in-house and always compiled in;
see [§5 Full-recursion](#full-recursion).

- **Local zones:** `ArcSwap<LocalZoneSet>` — reads are lock-free, writes clone + swap
- **Blacklist / feeds:** `ArcSwap<BlacklistSet>` — same pattern
- **Upstream pool:** `ArcSwap<SharedResolver>` — rebuilt on every add/remove/reconnect

### DoT pool

**(#77).** The DoT upstream pool opens TLS connections lazily. On first query after idle, the pool is empty → SERVFAIL. Fix: `rebuild_and_swap` calls `warm_up()` (3 × 250 ms probes) before atomically swapping the resolver. `POST /api/upstreams/reconnect` triggers a synchronous reconnect + warm-up.

### Cache insertion

DNS responses from upstream are inserted into `DashMap<QuestionKey, CacheEntry>` (lock-free at entry level). The XDP cache snapshot picks them up within 10 ms.

### Cgroup v2 memory awareness

At startup, Runbound inspects its own cgroup to determine available memory before
sizing the DNS cache:

```
/proc/self/cgroup  →  parse v2 path  →  /sys/fs/cgroup/<path>/memory.max
                                         /sys/fs/cgroup/<path>/memory.current
```

Cache size formula (`cache_size_from_meminfo()`, `src/dns/server.rs`):

```
available = memory.max - memory.current                    (KiB)
entries   = available_kb × 1024 / 4 / 512                   (~25% of available memory,
                                                               in 512-byte cache entries)
cache_entries = clamp(entries, 8192, 64 × 1024 × 1024)      (8K floor ≈ 4 MiB,
                                                               64M ceiling ≈ 32 GiB)
```

If `memory.max` is `max` (unlimited), falls back to `MemAvailable` from `/proc/meminfo`.
There is no fixed 1 GiB cap — the ceiling is 64M entries (~32 GiB). An explicit
`cache-size:` directive in config overrides the auto-sized value entirely.

Logged at startup: `INFO runbound::dns::server: cache size auto-sized from MemAvailable cache_size=N`

### Serve-stale (RFC 8767)

When all upstreams are unreachable, Runbound answers from expired cache entries rather
than returning SERVFAIL (logic inline in `src/dns/server.rs`, gated by `serve_stale` /
`stale_answer_ttl` / `stale_max_age` on the config struct in `src/config/parser.rs`):

```
upstream timeout / all upstreams unreachable
    ↓
cache lookup (expired entries included, within stale-max-age)
    found  →  answer with TTL clamped to stale-answer-ttl + EDE code 3 (Stale Answer)
    missing →  SERVFAIL
```

```
server:
    serve-stale: yes              # default: yes
    stale-answer-ttl: 30          # alias: serve-expired-reply-ttl — TTL reported for stale answers (seconds)
    stale-max-age: 86400          # alias: serve-expired-ttl — refuse entries expired longer than this
```

Stale entries are replaced by fresh upstream responses as soon as connectivity recovers.

### Per-client alert thresholds

`src/alerts.rs` implements configurable per-client-IP alert rules via `AlertTracker`.
The config schema (`AlertRule`, `src/config/parser.rs`) currently accepts `nxdomain-rate`
and `blocked-rate` as `metric` values, but only `client-qps` is actually evaluated —
`AlertTracker::record()` skips any rule whose `metric != "client-qps"`, so
`nxdomain-rate`/`blocked-rate` rules are parsed and stored but silently inert:

```
AlertTracker::record(&self, ip: IpAddr, verified: bool) -> AbuseVerdict
    ↓
already blocked? → Block
no rules, or source unverified (anti-spoof gate)? → Serve
    ↓
for each rule where metric == "client-qps":
    per-ip sliding window count (DashMap<IpAddr, ClientBucket>)
    → count == threshold + 1 ? → trigger() once per window
        → action: log (warn-log only) | block (ban + push to XDP ban map) |
                  tarpit (delay, no XDP push) | notify(notify_url) (webhook only)
    ↓
Block | Tarpit | Serve
```

```
alert:
    name:       "flood detector"
    metric:     client-qps   # only client-qps is evaluated; nxdomain-rate/blocked-rate parsed but inert
    threshold:  500
    window-s:   10           # seconds
    action:     log          # log | block | tarpit | notify
    notify-url: "http://..."
    block-duration-s: 300    # 0 = permanent until restart (action: block/tarpit only)
```

Multiple `alert:` blocks supported. Managed via `GET /api/alerts` (and alias
`GET /api/alerts/rules`), `PUT /api/alerts/rules` (replace rule set), and
`PUT`/`DELETE /api/alerts/blocked/:ip` (manual block/unblock).

### Zone transfer — AXFR / IXFR

`src/dns/axfr.rs` + `src/dns/wire_serve.rs::axfr_response` implement outgoing zone
transfers (RFC 5936 AXFR, RFC 1995 IXFR) for secondary nameservers, served entirely on
Runbound's own wire codec. `serve_wire` dispatches AXFR/IXFR before
the generic query path; IXFR is answered as a full AXFR.

**AXFR (TCP only):** SOA serial checked, `axfr-allow` ACL enforced against the **real
client IP** (carried to the handler over the loopback relay via a PROXY v2 header).
`axfr_response()` builds the entire transfer (`SOA … records … SOA`, RFC 5936 §2.2) as a
**single in-memory message** — there is no batching or streaming across multiple
messages (local zones are expected to fit comfortably within one message). TSIG
(RFC 8945, `ring` HMAC — SHA-1/256/384/512, `src/dns/tsig.rs`) supported.

**IXFR:** there is no incremental journal — IXFR is served as a full AXFR. Every IXFR
request gets the full zone, regardless of the client's SOA serial.

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

### RFC 2136 DDNS + TSIG

`src/dns/ddns.rs::handle_update_wire` implements RFC 2136 dynamic DNS updates, dispatched
from `serve_wire` and answered on Runbound's own wire codec. Clients
(`nsupdate`, DHCP servers, router firmware) send DNS UPDATE messages to add, modify, or
delete records without a Runbound restart.

All UPDATE messages must carry a valid TSIG RR (RFC 8945, verified on `ring` HMAC via
`src/dns/tsig.rs`; the key-name lookup is constant-time). Unsigned updates are refused.
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

### Full-recursion

The sovereign full-recursion resolver (`src/dns/recursor_wire.rs`) is entirely in-house,
always compiled in, and always available in the default build — there is no Cargo
feature gating it. Full-recursion is a **runtime config toggle**
(`resolution: full-recursion` vs the default `forward`), not a compile-time feature: no
special build or rebuild is needed. When enabled, cache misses are resolved
**iteratively from the root** (RFC 9156 QNAME minimisation, anti-SSRF guards on
glue/NS/CNAME addresses, and DNSSEC validation when `dnssec-validation: yes`). Under
`dnssec-validation: yes`, validated answers are also held in a dedicated validating cache
(`VALIDATED_CACHE`, keyed by `(qname, qtype)`) so DO=1 clients are served from cache
instead of re-recursing on every hit (0.9.3); entry lifetime is bounded by both the
smallest record/authority TTL and the nearest RRSIG expiration, and `Bogus` results are
never cached. The mode is toggled live via `PUT /api/resolution` (master
propagates to slaves over the relay); `src/dns/recursor_wire.rs::rebuild_shared`
hot-swaps the `ArcSwap<Option<…>>` handle.

Every query path — forward, full-recursion, local, AXFR, DDNS, TSIG — is served by
`serve_wire` on Runbound's own wire codec.

---

## 6. Timing budget summary

> Latency estimates below are **theoretical** (derived from instruction counts and hardware data sheets). See [benchmark/INDEX.md](benchmark/INDEX.md) and [whitepaper/08-performance.md](whitepaper/08-performance.md) for measured results.

| Stage | Latency |
|-------|---------|
| NIC DMA → UMEM | ~0 ns |
| eBPF XDP filter | ~50 ns |
| AF_XDP ring enqueue | ~0 ns |
| poll() wakeup | ~100 ns |
| Parse Ethernet/IP/UDP | ~50 ns |
| Parse DNS QNAME (SSE2 1-pass) | ~40 ns |
| ACL check | ~50 ns |
| Rate limiter (DashMap) | ~100 ns |
| LocalZoneSet lookup | ~200 ns |
| Domain hash (CRC32c SSE4.2) | ~20 ns |
| Cache snapshot lookup (DashMap) | ~100 ns |
| Build response (wire_payload memcpy + QueryID patch) | ~80 ns |
| TX enqueue + kick (batch/32) | ~50 ns |
| **Total — cache hit (wire format + SIMD)** | **~530 ns** |
| Slow path — local zone (Tokio) | ~200 µs |
| Slow path — upstream UDP | RTT + ~50 µs |
| Slow path — upstream DoT | RTT + ~2 ms |

---

## 7. Throughput model

> All numbers in this section are **theoretical** estimates derived from the per-stage timing budget above. See [benchmark/INDEX.md](benchmark/INDEX.md) for measured AF/XDP throughput on bare-metal Intel ixgbe.

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

With wire format cache (#64):

```
8 × 3.3 M × 0.95 = 25 M QPS   (theoretical)
```

Practical ceiling: 10 GbE wire speed = **14.88 M 64-byte packets/second**.

---

## 8. Roadmap

### Implemented

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
| eBPF XDP program in Rust (aya-bpf) | — | Rewrite `ebpf/dns_xdp.c` in Rust using `aya-bpf` crate. Eliminates clang build dependency. |

> **DNSSEC full validation (#34).** Chain-of-trust validation from the root
> (NSEC/NSEC3, DS/DNSKEY) is in the sovereign full-recursion resolver
> (`src/dns/recursor_wire.rs`, `src/dns/dnssec_*.rs`), entirely in-house and always
> compiled into the default build (no Cargo feature gates it) — but **off by runtime
> default**: `dnssec-validation: no` is the config default, enforced only when
> `dnssec-validation: yes` is set. Separately, **authoritative DNSSEC signing** for
> local zones (in-house ECDSA P-256 on `ring`, RFC 6605/4034/5155/9276) is served
> wire-native on the default path.

---

## 9. Data structures — quick reference

| Structure | Location | Purpose |
|-----------|----------|---------|
| `ArcSwap<LocalZoneSet>` | `src/dns/zones.rs` | Local DNS records — zero-lock reads |
| `ArcSwap<BlacklistSet>` | `src/dns/blacklist.rs` | Blocked domains — zero-lock reads |
| `ArcSwap<ForwardPool>` (`SharedPool`) | `src/dns/forward.rs` | In-house upstream forwarder pool — atomic swap on change |
| `ArcSwap<CacheSnapshot>` | `src/dns/cache_snapshot.rs` | XDP-readable cache — generation-skipping publish |
| `DashMap<QuestionKey, CacheEntry>` | `src/dns/cache_snapshot.rs` | Mutable cache — lock-free inserts |
| `DashMap<IpAddr, TokenBucket>` | `src/dns/xdp/worker.rs` | Per-IP rate limiter |
| `DashMap<IpAddr, ClientBucket>` | `src/alerts.rs` | Per-client alert thresholds (`AlertTracker`) |
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
| `xdp` | ✅ enabled (`default`) | Compile eBPF program and AF_XDP code (`dep:aya`) |
| `fuzz` | ❌ disabled | Expose internal parsing functions for cargo-fuzz targets — never enabled in release |
| `xdp-debug-counters` | ❌ disabled | Per-interface TX/RX instrumentation counters for debugging XDP — never enabled in benchmarks |

There is no `recursor` and no `hsm` Cargo feature. Full-recursion (`src/dns/recursor_wire.rs`),
DNSSEC validation (`src/dns/dnssec_*.rs`), and HSM/PKCS#11 support (`src/hsm.rs`) are entirely
in-house, always compiled into the binary (no Cargo feature gates them), and toggled purely
via **runtime config** (`resolution: full-recursion`, `dnssec-validation: yes`,
`hsm-pkcs11-lib`) — never a compile-time flag. Both full-recursion and DNSSEC validation
are **off by default at runtime** (`resolution: forward`, `dnssec-validation: no`); HSM is
unset/disabled by default too.

> DNS is served end-to-end by the in-house wire codec on every
> path. `hickory-proto` is **only** a `[dev-dependencies]` entry, used
> exclusively by the differential oracle tests — it is not a runtime dependency at all.
> `cargo tree -e normal` is hickory-free.

```bash
# Default release build — wire-native serving path,
# full-recursion + DNSSEC validation always compiled in
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-musl

# Enable full-recursion at runtime — no special build needed
# (set in config: resolution: full-recursion)

# Disable XDP (containers, cloud VMs without CAP_BPF)
cargo build --release --no-default-features
```

The eBPF C program (`ebpf/dns_xdp.c`) is compiled by `build.rs` using the system `clang`. The resulting `.o` is embedded in the Rust binary via `include_bytes!` — no external file needed at runtime.
