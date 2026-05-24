# Runbound — Performance Issues and Analysis

**Extracted from:** docs/security-audit.md v0.6.9 audit (AUDIT-PRINCIPLES.md Rule 2 — performance items are not security findings)  
**Date:** 2026-05-23  
**Version analyzed:** v0.6.9

---

## XDP Hot Path Analysis (Architecture Context)

Critical path for a DNS query in XDP mode:

```
[Packet arrives at NIC]
    ↓ ~0 ns   — Hardware DMA → UMEM frame
    ↓ ~50 ns  — eBPF filter (bounds checks + FNV-1a hash if CPUMAP)
    ↓ ~0 ns   — AF_XDP ring enqueue
    ↓ ~100 ns — poll() wakeup XDP worker thread
    ↓ ~200 ns — parse Ethernet/IP/UDP/DNS (inline, no allocation)
    ↓ ~50 ns  — ACL check (ArcSwap load, DashMap lookup)
    ↓ ~100 ns — rate limiter (DashMap per-IP)
    ↓ ~200 ns — LocalZoneSet lookup (hashmap)
    ↓ ~100 ns — Cache snapshot lookup (ArcSwap load + HashMap)
    ↓ ~200 ns — Build DNS response (inline into TX UMEM frame)
    ↓ ~50 ns  — TX ring enqueue + kick
    ↓ ~0 ns   — Hardware DMA → NIC TX
Total estimated: ~1 µs (single-threaded, cache-warm)
```

Theoretical throughput: at 1 µs/query on 1 core → 1 M QPS/core. With 8 XDP cores → 8 M QPS.

---

## AF_XDP Configuration

| Parameter | Current value | Assessment |
|-----------|--------------|------------|
| `FRAME_SIZE` | 4,096 bytes | ✅ Optimal (1 page = 1 DNS packet) |
| `FRAME_COUNT` | 8,192 | ✅ 32 MiB/socket |
| `RX_RING_SIZE` | 4,096 | ✅ Deep enough for 10 µs burst |
| `TX_RING_SIZE` | 4,096 | ✅ |
| `FILL_RING_SIZE` | 4,096 | ✅ |
| `COMP_RING_SIZE` | 4,096 | ✅ |
| NIC ring buffer | `maximize_nic_ring()` auto | ✅ Maximized before XDP attach |
| Hugepages | Optional, 4K fallback | ⚠️ Enable in production (reduce TLB misses) |

Buffer margin at 10 M QPS:
- 10 M QPS / 10 queues = 1 M QPS/queue = 1 packet/µs
- Ring depth 4,096 × 1 µs/packet = 4 ms buffer
- Overflow tolerance: 4 ms — sufficient

---

## Performance Findings

Severity uses a separate scale from security findings (MAJOR/MEDIUM/LOW) — these are throughput/latency optimizations, not vulnerabilities.

### PERF-01 — MAJOR: Cache snapshot publish interval 100 ms

```rust
// cache_snapshot.rs, line 107
let mut interval = tokio::time::interval(Duration::from_millis(100));
```

Impact: New cache entries are visible to XDP workers with up to 100 ms latency. At 1 M QPS on a popular domain, the first 100 ms pass through the slow path (hickory) — ~100,000 unnecessarily forwarded queries per popularity burst.

**Fix: Reduce to 10 ms** (still non-blocking, negligible CPU cost).  
**Status:** ✅ Fixed in v0.7.0

### PERF-02 — MAJOR: Mutex on mutable cache

```rust
// cache_snapshot.rs, line 90
let mut map = mutable.lock().unwrap_or_else(|e| e.into_inner());
```

The `Mutex<MutableCacheMap>` is contended by the DNS insertion thread (Tokio) AND the publish loop every 100 ms. Above 500 K insertions/second, this mutex becomes a bottleneck.

**Fix: Replace with `DashMap`** (sharded RwLock) or `crossbeam::SkipMap`.  
**Status:** ✅ Fixed in v0.7.0 (DashMap)

### PERF-03 — MEDIUM: No NUMA awareness

On dual-socket servers (2× EPYC or 2× Xeon), XDP workers for socket-0 queues potentially access UMEM allocated on socket-1 — 3× memory latency.

**Fix:** Allocate UMEM with `mbind()` or `numactl --cpunodebind` consistent with worker affinity.  
**Status:** Open — targeted v1.0 (single-socket deployments not affected)

### PERF-04 — MEDIUM: Hugepages optional

**Fix:** Enable in production config and set `vm.nr_hugepages = 8192` in sysctl.  
**Status:** Open — operator configuration item

### PERF-05 — LOW: No explicit TX batching

Responses are sent individually via `sock.tx.enqueue_tx(&[desc])`. Batching 16–64 responses per `sendto()`/kick call would reduce syscalls. Estimated impact: +10–15% throughput.

**Status:** Open — targeted v1.0 (low priority)

### PERF-06 — MEDIUM: SO_REUSEPORT on UDP fallback

The Tokio path uses 32 UDP sockets, but if XDP is disabled (fallback), verify that `SO_REUSEPORT` is active on all UDP listeners — otherwise single-threaded bottleneck.

**Status:** Open — to verify

### PERF-07 — jemalloc

jemalloc configured as global allocator — correct for multi-threaded workload.  
**Status:** ✅ Configured

### PERF-08 — CPU affinity

XDP workers pinned to physical cores.  
**Status:** ✅ Physical cores

### PERF-09 — IRQ affinity

Optional but recommended: `irqbalance` affinity matching XDP worker cores.  
**Status:** ✅ Optional, recommended

### PERF-10 — NIC ring maximized

`maximize_nic_ring()` called via SIOCETHTOOL before XDP attach.  
**Status:** ✅ SIOCETHTOOL auto

---

## Performance Projection

| Scenario | Hardware | Estimated QPS | p99 latency |
|----------|---------|--------------|------------|
| XDP disabled (Tokio only) | 32 cores | ~500 K QPS | 2–5 ms |
| XDP + 4 NIC queues | 4 XDP cores | ~4 M QPS | < 200 µs |
| XDP + 8 NIC queues | 8 XDP cores | ~8 M QPS | < 150 µs |
| XDP + 8 queues + hugepages + CPUMAP | 8 dedicated cores | ~10 M QPS | < 100 µs |

---

## Limitations

These projections are theoretical estimates based on [AI-INTERNAL] code analysis. No benchmarks have been run against actual hardware. Actual throughput depends on NIC driver, kernel version, CPU microarchitecture, memory bus bandwidth, and workload characteristics. See `docs/bench-runs/` for measured results when available.
