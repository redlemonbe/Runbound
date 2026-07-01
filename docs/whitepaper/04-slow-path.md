# 04 — The slow path (wire-native `serve_wire`)

> **Status: current (v0.23.8).** As of v0.23 hickory is fully removed from the runtime:
> the slow path is served entirely by the in-house wire codec (`serve_wire`,
> `src/dns/server.rs`), and recursion + DNSSEC validation are in-house too
> (`src/dns/recursor_wire.rs`, `src/dns/dnssec_*.rs`), always on by default — there is
> no `recursor` Cargo feature anymore. `hickory-proto` remains only as a
> `[dev-dependencies]` entry for the differential oracle tests. The pipeline below is
> unchanged in behaviour — only its implementation moved from hickory to the wire codec.

In `xdp: no` mode the receive side is the **kernel fast loop** (§4.0): it serves cache hits through
the same wire responder the AF_XDP fast path uses, and genuine misses (forward, CNAME/MX, TSIG,
AXFR, DDNS, DNSSEC signing) are handled by `serve_wire` — no hickory handler. The **fallback**
pipeline:

1. **ACL check** per source IP (from `unbound.conf`) — `src/dns/acl.rs`. For TCP/DoT/DoH the real
   client IP is carried to the handler via a PROXY v2 header on the loopback relay (so `axfr-allow`
   and split-horizon evaluate the true source).
2. **Rate limit** per source IP, token bucket, default 200 qps (`RATE_LIMIT_QPS_DEFAULT`,
   `src/dns/server.rs`).
3. **Local zones** (local-data, blacklist, feeds), AXFR/IXFR, TSIG-authenticated DDNS, and
   DNSSEC-signed serving (in-house ECDSA P-256 signer) → answered wire-native.
4. Otherwise → **forward** over the own wire forward pool (plain UDP / DoT), or, when
   `resolution: full-recursion` is set in `unbound.conf` (a runtime config toggle, not a
   build flag — always compiled in), the sovereign in-house iterative resolver
   (`src/dns/recursor_wire.rs`).

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
  datagrams (`BATCH = 64`, `src/dns/kernel_loop.rs:236`; raised from 32 in v0.17.0)
  instead of one syscall per datagram. Per-packet `recv_from` cannot keep the
  socket buffer empty under burst — the overflow shows up as `UdpRcvbufErrors`, not a NIC
  drop. `MSG_WAITFORONE` returns as soon as ≥1 datagram is ready, so a lone query (e.g.
  `dig`) is still answered immediately — no batching latency for single queries.
- **Batched transmit with `sendmmsg`** (v0.17.0): answered responses from one `recvmmsg`
  batch are collected and flushed with a **single** `sendmmsg`
  (`src/dns/kernel_loop.rs:444`) — one syscall per batch on the TX side too, with the
  iovec/header arrays allocated once, not per batch.
- **32 MiB socket buffers**: each kloop socket requests `SO_RCVBUF = 32 MiB`
  (`RCVBUF_SIZE`, `src/dns/kernel_loop.rs:65`) so NAPI bursts are absorbed instead of
  dropped as `UdpRcvbufErrors`; startup auto-raises `net.core.rmem_max`/`wmem_max` to
  match (best-effort, root — `src/dns/server.rs:2735`) and warns if the kernel clamps
  the buffer.
- **The shared per-source gate.** Every datagram passes the *same* gate the XDP path uses,
  driven by the *same* objects: `rl_should_drop()` (the memoized per-source rate-limit) and
  `icmp_stats.is_banned()` (the ban set). One mechanism governs both routes, exactly like
  the blacklist — so rate-limit and bans are enforced in `xdp: no` too, not only in XDP
  (§07). The ban check is a single relaxed atomic load when nothing is banned (the common
  case), so it is free on the hot path.
- **Then the shared SIMD/ASM responder** — `answer_dns_wire` (local-data / wire) and
  `answer_from_cache` (cache snapshot, §05). Only `WireResult::Fallback` (cache miss,
  CNAME/MX/DNSSEC DO=1, ANY) is handed to the slow-path handler `serve_wire`
  (`src/dns/server.rs:416`) via a bounded channel.

The net effect: in `xdp: no` the cache-hit path is the same hand-written wire builder as
XDP, on a kernel UDP socket; the wire-native `serve_wire` handler only sees the genuine
misses.

## 4.1 Backpressure against flood — a hard inflight cap

A spawn-per-request handler with no backpressure (as the old hickory `ServerFuture` was)
exhausts RAM under a flood. The wire-native handler bounds concurrency with a semaphore of
`MAX_INFLIGHT_REQUESTS = 4096` (`src/dns/server.rs:48`). A **non-blocking** `try_acquire`
returns `REFUSED` instantly without allocating, so the bound holds even at line rate. This
is a deliberate availability trade-off: shed load rather than OOM.

## 4.2 Forwarding, racing, and the hard timeout

Forwarding is wire-native since v0.22 — the in-house forward pool (`src/dns/forward.rs`),
not a hickory resolver:

- **Upstream racing** (`upstream-racing: yes`): the forward pool queries all upstreams in
  parallel and the first **definitive** result (positive or authoritative negative) ends
  the race; a `Servfail` is not definitive (`Forward::is_definitive`,
  `src/dns/forward.rs:61`; racing logic in `ForwardPool::forward`, `src/dns/forward.rs:387`).
- **txid + question validation** (SEC-O1): a plain-UDP upstream response is accepted only
  when its transaction ID and its question (name case-insensitive + type + class) match the
  query (`response_matches`, `src/dns/forward.rs`) — a cache-poisoning defence the de-hickory
  forwarder added.
- **Hard lookup timeout** (#83): forward lookups are wrapped in a hard timeout so a stuck
  upstream cannot pin a task/Tokio worker indefinitely (a measured-and-fixed deadlock root
  cause).
- **TLS** via `rustls` 0.23 (TLS 1.2 + 1.3) for DoT/DoH/DoQ.
- **TSIG** is wire-native on `ring` HMAC (RFC 8945), `src/dns/tsig.rs` — no longer
  `hickory_proto`'s TSIG; the key-name lookup is constant-time (§07).

Sovereign full-recursion is a **runtime config toggle**, not a Cargo feature — set
`resolution: full-recursion` under `server:` in `unbound.conf` to switch the cache-miss
backend from forward to the in-house iterative resolver (`src/dns/recursor_wire.rs`); the
default is `resolution: forward`. Both code paths ship in every build; there is no
`recursor` build flag and no `hickory-resolver` dependency.

## 4.3 Upstream health monitoring

`src/upstreams.rs` probes upstreams every 30 s (2 s timeout):

- **UDP upstreams**: a 28-byte DNS probe for `. IN A` carrying an EDNS0 OPT RR with the
  **DO bit set** (`DNS_PROBE_PACKET`, `src/upstreams.rs:41`). The reply confirms liveness
  and the **AD bit** reveals whether the upstream does DNSSEC validation.
- **DoT upstreams**: a TCP+TLS connect+handshake (no DNS query needed).
- **Backoff** on failure: 30 → 60 → 120 → 300 s cap, so a dead upstream does not spam
  logs; recovery resets the backoff and logs an INFO line.

## 4.4 Caching hand-off

In `xdp: no` the kernel fast loop (§4.0) answers cache hits directly from the **same
cache snapshot** the AF_XDP path reads (`answer_from_cache`, chapter 05) — built in both
modes since the #183 fix. Before that fix the snapshot was built only for `xdp: yes` and
the racing forwarders carried no cache, so `xdp: no` forwarded *every* query (cache-hit ≈
0 %) — the production-relevant regression that motivated the unified slow-path cache. The
`serve_wire` **fallback** still infers a hit from latency (a lookup under
`CACHE_HIT_THRESHOLD_US`, `crate::stats`).

## 4.5 NIC auto-tune at startup (v0.17.0, `xdp: no` only)

When a slow-path interface is **explicitly named** in the config, startup reads the live
topology and tunes the NIC for kernel-UDP throughput (`src/dns/server.rs:2663-2830`):

- **RX queue count = the NIC's NUMA-node logical-CPU count**, capped at 32
  (`SLOWPATH_QUEUE_CAP`) and at the serving-core count. The kernel-UDP path is bounded by
  NAPI saturating the NIC-node-local cores, so one RX queue (and IRQ) per node-local
  logical CPU drains the ring at line rate while leaving the rest of the machine to the
  serving threads.
- **One IRQ pinned per node-local CPU** (`crate::cpu::set_irq_affinity`), wrapping if
  queues exceed node CPUs, after a 300 ms settle so the driver recreates its IRQs
  post-channel-change.
- **RX softirq spread via the random reuseport cBPF** (`kernel_loop.rs`), **not RPS**.
  RPS was tried as the spread lever but collapses on i40e (measured ~16.8 M softnet
  drops/s, ~1.39 M qps), so it was removed: the kloop relies on `SO_REUSEPORT` + a
  random-steering cBPF to distribute serving across cores, flow-independent and i40e-safe.
- **`rx-usecs 25`, adaptive-rx off** (moderate coalescing — fewer NAPI re-arms at a
  ~25 µs latency cost) and **`rx-flow-hash udp4 sdfn`** so a few client IPs (NATs,
  forwarders, a benchmark generator) still fan across all queues. Best-effort `ethtool`
  shell-outs; skipped if `ethtool` is absent.

Safety, and an important limitation: queue/IRQ retuning happens **only on an explicitly
named NIC** (`xdp-interface:`) — a combined-channel change resets the link and must never
hit a management interface. The consequence is that **out of the box, with no named NIC,
the queue/IRQ stage does nothing** (`nic_queues=0 irqs_pinned=0`) and the slow path runs
untuned ([#190](https://github.com/redlemonbe/Runbound/issues/190)). To enable slow-path
tuning under `xdp: no`, name the data NIC with `xdp-interface:`.

On i40e/X710 the kernel slow path is **tuning-sensitive**, three measured figures:
**~3.71 M qps served at ~19 % CPU** under the benchmark methodology (NIC tuned, 63
`SO_REUSEPORT` workers, kernel-UDP generator — the canonical `…-x710-noxdp` report, ~2×
BIND/unbound); **~1.5 M** (best ~1.59 M) **out of the box, not retuned** — i40e NAPI-bound
([#190](https://github.com/redlemonbe/Runbound/issues/190)/[#165](https://github.com/redlemonbe/Runbound/issues/165));
and the historical **~7.3 M** which was **ixgbe/X520** (a different datapath, **not
reproducible on i40e**). The lever between the first two is node-local queues/IRQs; real
slow-path scaling on i40e is tracked in #165.
The AF_XDP fast path is byte-for-byte unchanged throughout. The auto-tune adapts to the
card (which NUMA node it sits on) and the CPU (node size); NIC families with hardware flow
steering (e.g. mlx5 aRFS) may prefer a different strategy — a driver-aware path is future
work.

## 4.6 Feature parity restored on the wire path (v0.22)

These features had lived only in the now-default-disabled hickory handler; v0.22 re-implements
them in `serve_wire` so the default (wire) path keeps them:

- **Query logging** — wire-native, feeds the WebUI Logs panel and `GET /api/logs`
  (`log_query_wire`, `src/dns/server.rs:336`).
- **serve-stale** (#108, RFC 8767) — a wire-native stale cache (`stale_cache_wire`,
  `src/dns/server.rs:126`) keyed by `(name, type)`, serving an expired answer on a transient
  upstream SERVFAIL. This is the only stale-cache implementation — there is no separate
  hickory-typed variant.
- **resolv.conf emergency fallback** (#94) — when all configured upstreams are down the
  forward path falls back to `/etc/resolv.conf` and recovers automatically
  (`src/dns/server.rs:793`, recovery probe at `:2459`).
- **Per-upstream racing-win metric** (#33, in `GET /api/system`) and **top-domains
  slow-path counting** (#5) are likewise restored on the wire path.

## To expand (verify against code)
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
