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
  uneven for a few flows, so an `SO_ATTACH_REUSEPORT_CBPF` *by-CPU* program (returning
  `SKF_AD_CPU`) plus RPS spreads datagrams evenly across the group — flat per-socket load.
- **Batched receive with `recvmmsg`** (`MSG_WAITFORONE`): one syscall drains up to 32
  datagrams instead of one syscall per datagram. Per-packet `recv_from` cannot keep the
  socket buffer empty under burst — the overflow shows up as `UdpRcvbufErrors`, not a NIC
  drop. `MSG_WAITFORONE` returns as soon as ≥1 datagram is ready, so a lone query (e.g.
  `dig`) is still answered immediately — no batching latency for single queries.
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

## To expand (verify against code)
- Negative caching state machine (RFC 2308, #166): NXDOMAIN cached vs SERVFAIL treated as
  transient (must not be cached long — false-negative trap).
- serve-stale (#108) exact TTL policy.
- resolv.conf emergency fallback (#94).
