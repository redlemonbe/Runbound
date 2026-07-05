# Runbound — Benchmark index

## Full suite (2026-07-03, dnsmark 1.0)

The whole reference suite run under the [README.md](README.md) methodology with **dnsmark 1.0 + dnsperf 2.14.0**: Runbound 0.9 (`xdp:no`, `xdp:yes`, dual-link), plus the
BIND 9.20.23 and unbound 1.22.0 baselines — same host, generator, links, corpus; only the
resolver, datapath and NIC change (rule 6). Every throughput figure is cross-checked
against the receiver NIC `tx_packets` (agreement 0.1–1.0 %). The **served rate** below is
the open-loop flood NIC-rx (the service ceiling); for the fast path it is line-bound, for
the kernel resolvers it is the open-loop rate (Runbound/unbound do not livelock; BIND
does — see notes).

**Throughput — served rate at the receiver NIC (single 10 GbE link unless noted):**

| Served (NIC rx) | NOERROR | NIC cross-check | Cache-hit latency p50 | Host CPU (128 c) | Config | Link |
|----------------:|--------:|:---------------:|----------------------:|-----------------:|--------|------|
| **~20.3 M** (ramp) / 19.4 M (flood) | 99.99 % | 0.4 % | 30 µs (wire-lat) | 24.4 % | **Runbound 0.9 `xdp:yes` dual-link** — 99 % of 20 G | X710+X520 |
| **~9.85 M** (line-rate) | 99.99 % | 0.3 % | 31 µs (wire-lat) | **10.1 %** | **Runbound `xdp:yes`** (AF_XDP) — wire-bound | X710 (i40e) |
| **~9.81 M** (line-rate) | 99.99 % | 0.4 % | 34 µs (wire-lat) | **8.2 %** | **Runbound `xdp:yes`** (AF_XDP) — wire-bound | X520 (ixgbe) |
| **~2.86 M** | 99.96 % | 0.6 % | 24.6 µs (tcpdump) | 17.7 % | **Runbound `xdp:no`** (kernel slow path) | X710 (i40e) |
| **~2.18 M** | 99.95 % | 0.1 % | 25.2 µs (tcpdump) | 17.1 % | **Runbound `xdp:no`** (kernel slow path) | X520 (ixgbe) |
| ~1.91 M | 99.88 % | 0.4 % | **12.8 µs** (tcpdump) | 19.1 % | unbound 1.22.0 | X710 (i40e) |
| ~1.46 M | 99.89 % | 0.4 % | 17.5 µs (tcpdump) | 20.4 % | unbound 1.22.0 | X520 (ixgbe) |
| ~1.49 M | 98.42 % (1.5 % SERVFAIL) | 1.0 % | 24.0 µs (tcpdump) | 17.6 % | BIND 9.20.23 | X710 (i40e) |
| ~1.26 M | **66.74 %** (33 % SERVFAIL — livelock) | 0.9 % | 29.8 µs (tcpdump) | 21.7 % | BIND 9.20.23 | X520 (ixgbe) |

**Reports (one per run, per [TEMPLATE.md](TEMPLATE.md)):**
Runbound 0.9 `xdp:yes` [X710](RUNBOUND-v0.9-threadripper-5995wx-x710-xdp-2026-07-03.md) ·
[X520](RUNBOUND-v0.9-threadripper-5995wx-x520-xdp-2026-07-03.md) ·
[dual](RUNBOUND-v0.9-threadripper-5995wx-dual-xdp-2026-07-03.md) — `xdp:no`
[X710](RUNBOUND-v0.9-threadripper-5995wx-x710-noxdp-2026-07-03.md) ·
[X520](RUNBOUND-v0.9-threadripper-5995wx-x520-noxdp-2026-07-03.md) ·
unbound [X710](BASELINE-unbound-1.22.0-threadripper-5995wx-x710-2026-07-03.md) ·
[X520](BASELINE-unbound-1.22.0-threadripper-5995wx-x520-2026-07-03.md) ·
BIND [X710](BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-07-03.md) ·
[X520](BASELINE-bind9-9.20.23-threadripper-5995wx-x520-2026-07-03.md)

**What the numbers say.**

- **Runbound's AF_XDP fast path tops the table and never reaches its own ceiling.** ~9.85 M
  qps per 10 G link at 99.99 % NOERROR on ~8–10 % host CPU — the wire (103 B replies → ~9.85 M/s)
  is the wall, not Runbound. Dual-link doubles to ~19.4 M (99 % of 20 G). The fast-path
  saturation point was not reached on this rig: **I cannot confirm** it.
- **Runbound wins even without XDP.** Its kernel slow path serves ~2.86 M (X710) / 2.18 M
  (X520) at 99.9 % NOERROR — ~1.5× unbound, ~1.9× BIND on the same rig — and, unlike BIND,
  **does not livelock** under the firehose.
- **BIND is the only resolver that livelocks** (X520: 33 % SERVFAIL under flood, ~0.84 M
  useful/s), and uses the most CPU for the least correct output. unbound holds 99.9 % and
  has the lowest cache-hit latency (12.8 µs) but the lowest kernel-resolver throughput
  after BIND.
- **Ramp DSD caveat.** For the kernel resolvers the closed-loop kernel-UDP ramp knee
  (BIND 268–295 k, unbound 498–605 k, Runbound 320–379 k) is **generator-recv bound**, an
  order of magnitude below the open-loop served rate; it is reported in each report for
  completeness, not as the server ceiling. The open-loop NIC-rx (with 99.9 % NOERROR
  confirming no degradation) is the service rate — except for BIND, where the flood
  degrades and the figure is labelled accordingly.
- **Latency method.** Kernel path: tcpdump at the receiver → tshark `dns.time` (pure
  server service time, rule 7). Fast path: dnsmark `--wire-latency` (server+link) — XDP
  bypasses the receiver stack so tcpdump sees nothing there.
- **Host CPU column** is whole-machine `mpstat` host utilisation (`usr+nice+sys+irq+soft`)
  over all 128 cores during the flood, **including** softirq/NIC cost, with VM
  `%guest`/`%steal` excluded (this host runs unrelated VMs). Idle baseline ~1 %.
  Efficiency (served per point of host CPU) is the story: Runbound `xdp:yes` ~0.97 M/%
  (X710) is ~6× its own kernel path, ~10× unbound, ~11× BIND. (See README "CPU
  accounting".)

## Files

- [README.md](README.md) — the standard methodology (warmup + ramp, NIC-counter truth, host
  setup, writing rules). **Read this first.**
- [TEMPLATE.md](TEMPLATE.md) — the report template every run follows.
- [runbound-receiver-bench.conf](runbound-receiver-bench.conf) — the receiver config for the
  Runbound runs (`xdp:no`, real forward-zone, no local-data, `rate-limit: 0`).
- **Full suite (2026-07-03, dnsmark 1.0)**
  - Runbound 0.9 `xdp:yes` — [X710](RUNBOUND-v0.9-threadripper-5995wx-x710-xdp-2026-07-03.md) · [X520](RUNBOUND-v0.9-threadripper-5995wx-x520-xdp-2026-07-03.md) · [dual-link](RUNBOUND-v0.9-threadripper-5995wx-dual-xdp-2026-07-03.md)
  - Runbound 0.9 `xdp:no` — [X710](RUNBOUND-v0.9-threadripper-5995wx-x710-noxdp-2026-07-03.md) · [X520](RUNBOUND-v0.9-threadripper-5995wx-x520-noxdp-2026-07-03.md)
  - unbound 1.22.0 — [X710](BASELINE-unbound-1.22.0-threadripper-5995wx-x710-2026-07-03.md) · [X520](BASELINE-unbound-1.22.0-threadripper-5995wx-x520-2026-07-03.md)
  - BIND 9.20.23 — [X710](BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-07-03.md) · [X520](BASELINE-bind9-9.20.23-threadripper-5995wx-x520-2026-07-03.md)

## Related (outside this directory)

- [Whitepaper §08 — Performance](../whitepaper/08-performance.md) — the narrative version of
  these numbers, with the slow-path/fast-path internals.
- **Independent cross-validation with `dnsperf`** (DNS-OARC), published in the dnsmark
  repository: `docs/cross-validation-dnsperf.md` at <https://github.com/redlemonbe/dnsmark>.
