# 04 — The slow path (hickory-server)

In `xdp: no` mode the receive side is the **kernel fast loop** (§4.0), not hickory: it
serves cache hits through the same wire responder the AF_XDP fast path uses, and only
genuine misses (recursion, CNAME/MX/TSIG, DNSSEC) reach the full
[hickory](https://github.com/hickory-dns/hickory-dns) stack
(`hickory-server`/`-resolver`/`-proto` 0.26, `src/dns/server.rs`) described below. The
hickory **fallback** pipeline:

1. **ACL check** per source IP (from `unbound.conf`) — `src/dns/acl.rs`.
2. **Rate limit** per source IP, token bucket, default 200 qps (`RATE_LIMIT_QPS_DEFAULT`,
   `src/dns/server.rs`).
3. **Local zones** (local-data, blacklist, feeds) in memory → instant answer.
4. Otherwise → **recursive resolver** (hickory-resolver), UDP+TCP on the configured port.

## 4.0 The kernel fast loop — the real `xdp: no` hot path

`xdp: no` is **not** "one hickory task per query". The receive side is a tight kernel loop
(`src/dns/kernel_loop.rs`) that mirrors the AF_XDP worker without eBPF:

- **One `SO_REUSEPORT` UDP socket per physical core** (minus one reserved for the rest of
  the process; capped at 16 on a Xeon-v2 + X520 host). The kernel's default 4-tuple hash is
  uneven for a few flows, so (since v0.18.0) an `SO_ATTACH_REUSEPORT_CBPF` program returning
  `SKF_AD_RANDOM` spreads datagrams evenly across the group **independent of source-flow
  count** — flat per-socket load with **no RPS** (RPS collapses the i40e/X710 NAPI: measured
  16.8M softnet drops/s). On a few-flow benchmark generator this is what lets every serving
  core stay busy; on real traffic (thousands of source ports) the default hash already would.
- **Batched receive with `recvmmsg`** (`MSG_WAITFORONE`): one syscall drains up to 64
  datagrams (`BATCH = 64`, `src/dns/kernel_loop.rs:233`; raised from 32 in v0.17.0)
  instead of one syscall per datagram. Per-packet `recv_from` cannot keep the
  socket buffer empty under burst — the overflow shows up as `UdpRcvbufErrors`, not a NIC
  drop. `MSG_WAITFORONE` returns as soon as ≥1 datagram is ready, so a lone query (e.g.
  `dig`) is still answered immediately — no batching latency for single queries.
- **Batched transmit with `sendmmsg`** (v0.17.0): answered responses from one `recvmmsg`
  batch are collected and flushed with a **single** `sendmmsg`
  (`src/dns/kernel_loop.rs:235`) — one syscall per batch on the TX side too, with the
  iovec/header arrays allocated once, not per batch.
- **32 MiB socket buffers**: each kloop socket requests `SO_RCVBUF = 32 MiB`
  (`RCVBUF_SIZE`, `src/dns/kernel_loop.rs:64`) so NAPI bursts are absorbed instead of
  dropped as `UdpRcvbufErrors`; startup auto-raises `net.core.rmem_max`/`wmem_max` to
  match (best-effort, root — `src/dns/server.rs:2603`) and warns if the kernel clamps
  the buffer.
- **The shared per-source gate.** Every datagram passes the *same* gate the XDP path uses,
  driven by the *same* objects: `rl_should_drop()` (the memoized per-source rate-limit) and
  `icmp_stats.is_banned()` (the ban set). One mechanism governs both routes, exactly like
  the blacklist — so rate-limit and bans are enforced in `xdp: no` too, not only in XDP
  (§07). The ban check is a single relaxed atomic load when nothing is banned (the common
  case), so it is free on the hot path.
- **Then the shared SIMD/ASM responder** — `answer_dns_wire` (local-data / wire) and
  `answer_from_cache` (cache snapshot, §05). Only `WireResult::Fallback` (cache miss,
  CNAME/MX/DNSSEC DO=1, ANY) is handed to the hickory fallback via a bounded channel.

The net effect: in `xdp: no` the cache-hit path is the same hand-written wire builder as
XDP, on a kernel UDP socket; hickory only sees the genuine misses.

## 4.1 Backpressure against flood — a hard inflight cap

hickory-server spawns one Tokio task per incoming request **with no backpressure**; under
a flood this exhausts RAM. Runbound bounds it with a semaphore of `MAX_INFLIGHT_REQUESTS =
4096` (`src/dns/server.rs:62`). A **non-blocking** `try_acquire` returns `REFUSED`
instantly without allocating, so the bound holds even at line rate. This is a deliberate
availability trade-off: shed load rather than OOM.

## 4.2 Recursion, racing, and the hard timeout

- **Upstream racing** (`upstream-racing: yes`): the resolver issues queries to multiple
  upstreams in parallel and takes the first success via `futures_util::future::select_ok`
  (`src/dns/server.rs`).
- **Hard lookup timeout** (#83): resolver lookups are wrapped in a hard timeout to prevent
  a stuck upstream from pinning a task/Tokio worker indefinitely (a deadlock root cause
  that was measured and fixed).
- **TLS** via `rustls` 0.23 (TLS 1.2 + 1.3) for DoT/DoH/DoQ.
- **TSIG** supported (`hickory_proto::rr::rdata::tsig`).

## 4.3 Upstream health monitoring

`src/upstreams.rs` probes upstreams every 30 s (2 s timeout):

- **UDP upstreams**: a 28-byte DNS probe for `. IN A` carrying an EDNS0 OPT RR with the
  **DO bit set** (`DNS_PROBE_PACKET`, `src/upstreams.rs:39`). The reply confirms liveness
  and the **AD bit** reveals whether the upstream does DNSSEC validation.
- **DoT upstreams**: a TCP+TLS connect+handshake (no DNS query needed).
- **Backoff** on failure: 30 → 60 → 120 → 300 s cap, so a dead upstream does not spam
  logs; recovery resets the backoff and logs an INFO line.

## 4.4 Caching hand-off

In `xdp: no` the kernel fast loop (§4.0) answers cache hits directly from the **same
cache snapshot** the AF_XDP path reads (`answer_from_cache`, chapter 05) — built in both
modes since the #183 fix. Before that fix the snapshot was built only for `xdp: yes` and
the racing resolvers carried no cache, so `xdp: no` forwarded *every* query (cache-hit ≈
0 %) — the production-relevant regression that motivated the unified slow-path cache. The
hickory **fallback** still infers a hit from latency (a lookup under
`CACHE_HIT_THRESHOLD_US`, `crate::stats`).

## 4.5 NIC auto-tune at startup (v0.17.0, `xdp: no` only)

When a slow-path interface is **explicitly named** in the config, startup reads the live
topology and tunes the NIC for kernel-UDP throughput (`src/dns/server.rs:2590-2675`):

- **RX queue count = the NIC's NUMA-node logical-CPU count**, capped at 32
  (`SLOWPATH_QUEUE_CAP`) and at the serving-core count. The kernel-UDP path is bounded by
  NAPI saturating the NIC-node-local cores, so one RX queue (and IRQ) per node-local
  logical CPU drains the ring at line rate while leaving the rest of the machine to the
  serving threads.
- **One IRQ pinned per node-local CPU** (`crate::cpu::set_irq_affinity`), wrapping if
  queues exceed node CPUs, after a 300 ms settle so the driver recreates its IRQs
  post-channel-change.
- **RPS spread across all physical serving cores** (`crate::cpu::set_rps_cores`) — the
  dominant lever: the in-code measurement note records 0.5 M → 6.4 M qps from RPS alone
  on the X710/5995WX rig.
- **`rx-usecs 25`, adaptive-rx off** (moderate coalescing — fewer NAPI re-arms at a
  ~25 µs latency cost) and **`rx-flow-hash udp4 sdfn`** so a few client IPs (NATs,
  forwarders, a benchmark generator) still fan across all queues. Best-effort `ethtool`
  shell-outs; skipped if `ethtool` is absent.

Safety: queue/IRQ retuning happens **only on an explicitly named NIC** — a
combined-channel change resets the link and must never hit a management interface. RPS,
which is harmless on an idle NIC, is applied to every detected physical NIC. Per the
CHANGELOG (v0.17.0), this took the measured kernel slow path from ~3.4 M to ~7.3 M+
served qps (peak 8.16 M, at the i40e NAPI ceiling) on the X710/5995WX rig, with the
AF_XDP fast path byte-for-byte unchanged. The auto-tune adapts to the card (which NUMA
node it sits on) and the CPU (node size); NIC families with hardware flow steering (e.g.
mlx5 aRFS) may prefer a different strategy — a driver-aware path is future work.

## To expand (verify against code)
- serve-stale (#108) exact TTL policy.
- resolv.conf emergency fallback (#94).
- (Negative caching #166 is documented in [02-fast-path-xdp.md](02-fast-path-xdp.md) §2.5
  — the kloop serves the same snapshot, see §4.4.)


## 4.7 Physical cores only (never HyperThread)

Every Runbound thread — the kloop, the AF_XDP workers, and the tokio control-plane /
fallback runtime — is confined to **physical cores** (a process-wide affinity mask set at
startup; per-worker pins narrow it to one physical core). The hand-written SIMD/ASM wire
path saturates a physical core's execution units, so a thread scheduled on the SMT sibling
steals throughput instead of adding it. HT only helps code that leaves execution units
idle; the wire builder leaves none. Residual SMT-core activity under load is kernel
housekeeping (ksoftirqd), not Runbound.
