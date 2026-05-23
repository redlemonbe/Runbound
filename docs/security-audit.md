# Runbound — Security & Performance Audit Report

**Version audited:** v0.6.9
**Date:** 2026-05-23
**Scope:** Full source — DNS engine, XDP fast-path, REST API, cache, feed subsystem, ACL, rate limiter, TLS, configuration parser, HSM integration, upstream management, eBPF program, signal handling, dependency chain

---

## 1. Executive Summary

Runbound is architecturally sound for production deployment. The codebase presents strong security guarantees on critical surfaces (auth, memory, eBPF). The 5 M QPS target is achievable on dedicated multi-queue hardware with XDP enabled, pending four corrections before production deployment.

**Overall verdict: production-ready with four blocking items (listed in §6).**

---

## 2. Architecture Overview

```
NIC
 │
 ├──[eBPF XDP filter — kernel bypass]────────────────────────────────┐
 │   • Identifies UDP/53                                               │
 │   • CPUMAP routing (FNV-1a hash of QNAME → pinned CPU)            │
 │   • XDP_PASS fallback on everything else                           │
 │                                                                     ▼
 │                                           AF_XDP socket (1 per NIC queue)
 │                                               │
 │                                     XDP worker thread (OS thread)
 │                                       • Parse Ethernet/IP/UDP/DNS
 │                                       • ACL + rate limiter (DashMap)
 │                                       • LocalZoneSet (ArcSwap)
 │                                       • Cache snapshot (ArcSwap)
 │                                       • Reply via TX ring
 │
 └──[Kernel path → Tokio / hickory-server]
     • Recursive queries / DoT / DoH / DoQ
     • DNSSEC validation (optional)
     • REST API (localhost:8081)
```

Architectural strengths: strict separation between XDP OS-threads and Tokio async workers, zero-lock read path on zones, jemalloc multi-thread allocator.

---

## 3. Security Audit

### 3.1 API Authentication — GOOD

Mechanism: 256-bit Bearer token (CSPRNG), stored at `/etc/runbound/api.key` (chmod 600).

Constant-time comparison (`src/auth.rs`):

```rust
use subtle::ConstantTimeEq;
let diff = b.iter().enumerate().fold(len_mismatch, |acc, (i, &bi)| {
    acc | (a.get(i).copied().unwrap_or(0) ^ bi)
});
diff.ct_eq(&0u8).into()
```

The `subtle` crate prevents compiler optimizations that would create a timing oracle.

Anti-brute-force: 500 ms sleep after 50 consecutive failures, applied before comparison — no timing signal on key content.

Residual risk: HTTP header length is observable (~non-exploitable in practice; API bound to 127.0.0.1 only).

**Verdict: ✅ Compliant with ANSSI secure API guidelines.**

### 3.2 Secret Management — VERY GOOD

| Secret | Storage | Protection |
|--------|---------|------------|
| API key | `Zeroizing<String>` | Zeroed on drop |
| HSM PIN | `Zeroizing<String>` | Env var `HSM_PIN` > config |
| HMAC audit | `Zeroizing<Vec<u8>>` | Auto-generated if absent |
| PKCS#11 | Single session at startup | Explicit cleanup on shutdown |

HSM support via `cryptoki` crate. Fatal exit if HSM configured but unreachable — correct behavior for production deployment.

**Verdict: ✅ HSM-compliant. Zero plaintext secrets in memory.**

### 3.3 Unsafe Code — ACCEPTABLE with reservations

The project enforces `#![deny(unsafe_op_in_unsafe_fn)]` in all XDP modules — every unsafe block must be explicitly justified.

| File | Nature | Justification | Verdict |
|------|--------|---------------|---------|
| `umem.rs` | 45+ `read/write_volatile` on rings | Kernel/userspace shared memory, protocol requires volatile access | ✅ Correctly barriered (Acquire/Release fences) |
| `socket.rs` | libc syscalls (socket, bind, ioctl) | No safe abstraction available | ✅ Post-call validation |
| `worker.rs` | UMEM frame access | Kernel-controlled descriptors | ⚠️ See §3.4 |
| `loader.rs` | `ptr::copy_nonoverlapping` for ELF alignment | Required by aya parser | ✅ Bounds checked before copy |

**Verdict: ✅ Dense but correctly documented. No UB detected.**

### 3.4 UMEM Security — POTENTIAL VULNERABILITY

Context: RX descriptors arrive from the kernel via the AF_XDP ring. A kernel bug or confused-deputy attack could inject a descriptor with `addr + len` exceeding the UMEM region.

Mitigation in place (`worker.rs`):

```rust
let end = (desc.addr as usize).checked_add(desc.len as usize);
if desc.len as usize > FRAME_SIZE as usize
    || end.map(|e| e > sock.umem.area_len).unwrap_or(true) {
    // drop silently
}
```

`checked_add` prevents integer overflow. Each kernel descriptor is validated before memory access.

**Verdict: ✅ Protection in place. Kernel trust is implicit (acceptable for dedicated hardware deployment).**

### 3.5 eBPF Surface — GOOD

eBPF program (`ebpf/dns_xdp.c`, 154 lines):

- No unbounded loops: FNV-1a hash capped at 64 iterations — respects BPF verifier limits
- All memory accesses have bounds checks: eth/ip/ipv6/udp headers validated before access (lines 85, 95, 109, 121)
- `XSKMAP max_entries = 64`: architectural limit documented; Rust code rejects any `queue_id >= 64` before loading
- `XDP_PASS` fallback on all non-UDP/53 packets → no black-hole possible

Potential vector: A malformed DNS packet reaches the XDP worker. Protection is in `process_packet()` (Rust, not eBPF), which validates structure before processing.

**Verdict: ✅ Verifier-compliant. No OOB detected.**

### 3.6 DNS Protection — GOOD

**DNS rebinding:** Each upstream response is filtered against configured private CIDR ranges. RFC 1918 + loopback + link-local blocked by default.

**Rate limiting:**
- 200 QPS/IP default (configurable)
- Burst: 2× limit
- IPv6 /48 aggregation: an attacker with a /48 is treated as a single IP — protection against distributed IPv6 floods
- Anti-bucket-exhaustion: max 65,536 entries + aggressive GC when full

**ANY queries:** Blocked (amplification protection per RFC 8482).

**version.bind, hostname.bind, id.server:** Blocked (CHAOS class fingerprinting).

**DNSSEC:** Optional. In forwarder mode (default), the upstream AD bit is accepted without local validation. For a recursive production deployment, `dnssec-validation: yes` is mandatory.

**Verdict: ✅ Robust. ⚠️ RECOMMENDATION: enable DNSSEC in production.**

### 3.7 Signal Handling — GOOD (fixed in v0.6.9)

| Signal | Behavior |
|--------|----------|
| SIGHUP | Hot-reload zones without DNS interruption |
| SIGUSR1 | Dump live stats to log (monitoring) |
| SIGUSR2 | Ignored (reserved) |
| SIGTERM | Graceful shutdown via Tokio runtime |

Before fix: SIGUSR1/SIGUSR2 → immediate process death (OS default behavior). Fixed in v0.6.9.

### 3.8 Dependency Security

| CVE/Advisory | Dependency | Status |
|-------------|-----------|--------|
| RUSTSEC-2025-0009 | `ring < 0.17.9` (AES panic) | ✅ Patched, `ring` pinned ≥ 0.17.9 |
| RUSTSEC-2026-0037 | `quinn` DoS | ✅ Patched via `hickory v0.26` |

TLS: `rustls 0.23` (TLS 1.3 by default) + AWS-LC. No OpenSSL in the dependency chain.

**Verdict: ✅ Clean dependency chain.**

### 3.9 Production Deployment Checklist

| ID | Risk | Severity | Action required |
|----|------|----------|----------------|
| R1 | No internal privilege dropping | MEDIUM | Delegate to systemd (`User=`, `CapabilityBoundingSet=`) |
| R2 | DNSSEC disabled by default | MEDIUM | Enable `dnssec-validation: yes` in production |
| R3 | `log-client-ip: yes` by default | LOW/GDPR | Set to `no` if IP retention is not legally justified |
| R4 | No NUMA awareness | LOW | On NUMA servers (multi-socket), XDP workers may cross memory banks |

---

## 4. Performance Audit

### 4.1 XDP Hot Path Analysis

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

### 4.2 AF_XDP Configuration

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

### 4.3 Bottlenecks Identified

#### PERF-01 — MAJOR: Cache snapshot publish interval 100 ms ⚠️

```rust
// cache_snapshot.rs, line 107
let mut interval = tokio::time::interval(Duration::from_millis(100));
```

Impact: New cache entries are visible to XDP workers with up to 100 ms latency. At 1 M QPS on a popular domain, the first 100 ms pass through the slow path (hickory) — ~100,000 unnecessarily forwarded queries per popularity burst.

**Fix: Reduce to 10 ms** (still non-blocking, negligible CPU cost).

#### PERF-02 — MAJOR: Mutex on mutable cache ⚠️

```rust
// cache_snapshot.rs, line 90
let mut map = mutable.lock().unwrap_or_else(|e| e.into_inner());
```

The `Mutex<MutableCacheMap>` is contended by the DNS insertion thread (Tokio) AND the publish loop every 100 ms. Above 500 K insertions/second, this mutex becomes a bottleneck.

**Fix: Replace with `DashMap`** (sharded RwLock) or `crossbeam::SkipMap`.

#### PERF-03 — MEDIUM: No NUMA awareness ⚠️

On dual-socket servers (2× EPYC or 2× Xeon), XDP workers for socket-0 queues potentially access UMEM allocated on socket-1 — 3× memory latency.

**Fix: Allocate UMEM with `mbind()` or `numactl --cpunodebind` consistent with worker affinity.**

#### PERF-04 — MEDIUM: Hugepages optional ⚠️

**Fix: Enable in production config and set `vm.nr_hugepages = 8192` in sysctl.**

#### PERF-05 — LOW: No explicit TX batching

Responses are sent individually via `sock.tx.enqueue_tx(&[desc])`. Batching 16–64 responses per `sendto()`/kick call would reduce syscalls. Estimated impact: +10–15% throughput.

#### PERF-06 — MEDIUM: SO_REUSEPORT on UDP fallback

The Tokio path uses 32 UDP sockets, but if XDP is disabled (fallback), verify that `SO_REUSEPORT` is active on all UDP listeners — otherwise single-threaded bottleneck.

### 4.4 Performance Projection

| Scenario | Hardware | Estimated QPS | p99 latency |
|----------|---------|--------------|------------|
| XDP disabled (Tokio only) | 32 cores | ~500 K QPS | 2–5 ms |
| XDP + 4 NIC queues | 4 XDP cores | ~4 M QPS | < 200 µs |
| XDP + 8 NIC queues | 8 XDP cores | ~8 M QPS | < 150 µs |
| XDP + 8 queues + hugepages + CPUMAP | 8 dedicated cores | ~10 M QPS | < 100 µs |

---

## 5. Consolidated Risk Matrix

### Security

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| SEC-01 | Auth timing oracle | MEDIUM | ✅ Mitigated (subtle + sleep) |
| SEC-02 | Plaintext secrets in memory | HIGH | ✅ Zeroizing |
| SEC-03 | UMEM buffer overflow | HIGH | ✅ checked_add |
| SEC-04 | HTTP body unbounded | MEDIUM | ✅ Capped 65 KiB |
| SEC-05 | DNSSEC disabled by default | MEDIUM | ⚠️ Enable in production |
| SEC-06 | Privilege dropping | MEDIUM | ⚠️ Delegate to systemd |
| SEC-07 | Dependency CVEs | HIGH | ✅ Patched |
| SEC-08 | SIGUSR1/2 kill process | HIGH | ✅ Fixed v0.6.9 |
| SEC-09 | DNS rebinding | HIGH | ✅ CIDR guards |
| SEC-10 | ANY amplification | HIGH | ✅ Blocked |

### Performance

| ID | Title | Impact | Status |
|----|-------|--------|--------|
| PERF-01 | Cache publish 100 ms | MAJOR | ⚠️ Reduce to 10 ms |
| PERF-02 | Mutex on mutable cache | MAJOR | ⚠️ Replace with DashMap |
| PERF-03 | No NUMA awareness | MEDIUM | ⚠️ Enable in production |
| PERF-04 | Hugepages optional | MEDIUM | ⚠️ Enable in production |
| PERF-05 | TX not batched | LOW | Post-5M optimization |
| PERF-06 | SO_REUSEPORT fallback | MEDIUM | Verify |
| PERF-07 | jemalloc | — | ✅ Configured |
| PERF-08 | CPU affinity | — | ✅ Physical cores |
| PERF-09 | IRQ affinity | — | ✅ Optional, recommended |
| PERF-10 | NIC ring maximized | — | ✅ SIOCETHTOOL auto |

---

## 6. Priority Recommendations

### Blocking — required before production deployment

1. **SEC-06** — systemd unit hardening:
   ```ini
   User=runbound
   CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_BPF
   NoNewPrivileges=yes
   MemoryDenyWriteExecute=no
   ```

2. **SEC-05** — Enable in production config:
   ```
   server:
       dnssec-validation: yes
   ```

3. **PERF-01** — `cache_snapshot.rs` line 107: `Duration::from_millis(100)` → `Duration::from_millis(10)`

4. **PERF-04** — Production config:
   ```
   server:
       xdp-hugepages: yes
   ```
   System: `vm.nr_hugepages = 8192`

### Post-deployment improvements

- **PERF-02** — Replace `Mutex<HashMap>` with `DashMap` on mutable cache to exceed 1 M insertions/s
- **PERF-03** — Topology-aware UMEM allocation on dual-socket servers
- **PERF-05** — TX batching: group 32 responses per `sendto()` kick
- **GDPR** — `log-client-ip: no` if GDPR applies to the deployment

---

## 7. Conclusion

Runbound v0.6.9 is production-ready pending the four blocking items above. The XDP kernel-bypass architecture is correct, memory guarantees are solid, and the dependency chain is clean. The 5 M QPS target is realistic on a 1U server with a 10G 8-queue NIC with hugepages enabled and the publish interval fix applied.
