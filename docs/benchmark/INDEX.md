# Runbound — Benchmark index

> **Archive note (2026-07-03).** All runs in the "at a glance" table below predate the
> current methodology revision (dnsmark-vs-NIC cross-check table + ramp/DSD rules in
> [README.md](README.md)) and have been moved to [OLD/](OLD/). They remain valid
> measurements under the methodology of their time. New-methodology runs are listed
> directly under the heading immediately below.

## Current campaign — full suite (revised methodology, 2026-07-03, dnsmark v2.7.7)

The whole reference suite re-run under the [README.md](README.md) revision with **dnsmark
v2.7.7 + dnsperf 2.14.0**: Runbound v0.23.13 (`xdp:no`, `xdp:yes`, dual-link), plus the
BIND 9.20.23 and unbound 1.22.0 baselines — same host, generator, links, corpus; only the
resolver, datapath and NIC change (rule 6). Every throughput figure is cross-checked
against the receiver NIC `tx_packets` (agreement 0.1–1.0 %). The **served rate** below is
the open-loop flood NIC-rx (the service ceiling); for the fast path it is line-bound, for
the kernel resolvers it is the open-loop rate (Runbound/unbound do not livelock; BIND
does — see notes).

**Throughput — served rate at the receiver NIC (single 10 GbE link unless noted):**

| Served (NIC rx) | NOERROR | NIC cross-check | Cache-hit latency p50 | CPU (of 128) | Config | Link |
|----------------:|--------:|:---------------:|----------------------:|-------------:|--------|------|
| **~20.3 M** (ramp) / 19.4 M (flood) | 99.99 % | 0.4 % | 30 µs (wire-lat) | ~21.9 c | **Runbound v0.23.13 `xdp:yes` dual-link** — 99 % of 20 G | X710+X520 |
| **~9.85 M** (line-rate) | 99.99 % | 0.3 % | 31 µs (wire-lat) | ~6.0 c | **Runbound `xdp:yes`** (AF_XDP) — wire-bound | X710 (i40e) |
| **~9.81 M** (line-rate) | 99.99 % | 0.4 % | 34 µs (wire-lat) | ~6.0 c | **Runbound `xdp:yes`** (AF_XDP) — wire-bound | X520 (ixgbe) |
| **~2.86 M** | 99.96 % | 0.6 % | 24.6 µs (tcpdump) | ~13.7 c | **Runbound `xdp:no`** (kernel slow path) | X710 (i40e) |
| **~2.18 M** | 99.95 % | 0.1 % | 25.2 µs (tcpdump) | ~11.1 c | **Runbound `xdp:no`** (kernel slow path) | X520 (ixgbe) |
| ~1.91 M | 99.88 % | 0.4 % | **12.8 µs** (tcpdump) | ~15.7 c | unbound 1.22.0 | X710 (i40e) |
| ~1.46 M | 99.89 % | 0.4 % | 17.5 µs (tcpdump) | ~15.4 c | unbound 1.22.0 | X520 (ixgbe) |
| ~1.49 M | 98.42 % (1.5 % SERVFAIL) | 1.0 % | 24.0 µs (tcpdump) | ~18.2 c | BIND 9.20.23 | X710 (i40e) |
| ~1.26 M | **66.74 %** (33 % SERVFAIL — livelock) | 0.9 % | 29.8 µs (tcpdump) | ~16.1 c | BIND 9.20.23 | X520 (ixgbe) |

**Reports:** [Runbound v0.23.13 (all 5 runs)](RUNBOUND-v0.23.13-threadripper-5995wx-2026-07-03.md) ·
[unbound 1.22.0](BASELINE-unbound-1.22.0-threadripper-5995wx-2026-07-03.md) ·
[BIND 9.20.23](BASELINE-bind9-9.20.23-threadripper-5995wx-2026-07-03.md)

**What the numbers say.**

- **Runbound's AF_XDP fast path tops the table and never reaches its own ceiling.** ~9.85 M
  qps per 10 G link at 99.99 % NOERROR on ~6 cores — the wire (103 B replies → ~9.85 M/s)
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
- **CPU column** is `pidstat` on the server PID = **userspace CPU of the server process
  only**; softirq/kernel cost (NIC IRQ, `ksoftirqd`) is not attributed to the PID, so it
  under-states whole-system cost. Consistent across servers → good for relative
  efficiency, not the total system CPU. (See README "CPU accounting".)

## Superseded — first-pass BIND (2026-07-03, dnsmark v2.7.5, latency v2.7.7)

The initial BIND-only pass (per-link reports) was folded into the consolidated BIND
report above when the full suite was re-run on v2.7.7. Its throughput figures
(v2.7.5 datapath) match the v2.7.7 re-run within flood variance.

## Measured speeds at a glance (archived — pre-revision, see [OLD/](OLD/))

Maximum **served** throughput per run — receiver NIC hardware counters, never the
generator's self-reported rate. Full context behind every number in its report.

> **Full re-benchmark (2026-06-13).** The whole suite was re-run from scratch on a new rig
> (X710 + X510 direct links) with **Runbound v0.18.1 + dnsmark v2.3.0**. This index lists only
> this current round; pre-v0.18.1 results (X520, X710 v0.16.x, EPYC/bnxt) were measured on a
> different binary and are superseded — recoverable from git history if ever needed.

## Re-run on v0.23.8 (2026-07-01) — same rig, official release binaries, NIC-counter ground truth

Re-validated after the de-hickory rewrite (recursion + DNSSEC now fully in-house). Both
Runbound (v0.23.8) and the generator (dnsmark v2.6.0) were the **official, minisig-signed
GitHub release binaries** — no local compilation. This round also **directly measured and
quantified** the gap between dnsmark's own self-reported throughput and the receiver's NIC
hardware counters (the latter is what this table has always used): dnsmark under-reported
by 12–34% at saturation across all three configurations below — see the report for the
side-by-side numbers. **Caveat affecting every row below:** 2 MiB huge pages were unavailable
this session (host memory fragmentation, unrelated to any user VM); Runbound's own logging
confirms this is a lower-throughput fallback path, so these figures are a **floor, not the
tuned ceiling** — a post-reboot re-run is needed for that.

| Max served | Latency (p50) | Receiver CPU | Configuration | Link / NIC | Report |
|-----------:|--------------:|-------------:|---------------|-----------|--------|
| **~19.9 M qps** | 0.591 ms (at knee) | not isolated (aggregate run) | **Runbound v0.23.8** `xdp: yes` **dual-link**, one generator process on both NICs — **generator-imbalanced** (dnsmark issue #15-P2: X710 share starved to 8.55M of its own 12.56M solo ceiling) | X710 + X520 | [report](OLD/RUNBOUND-v0.23.8-threadripper-5995wx-2026-07-01.md) |
| **~12.56 M qps** | 0.212 ms (sustained) / 0.876 ms (at knee) | **~9.3 %** | **Runbound v0.23.8** `xdp: yes` (AF_XDP fast path), no huge pages this run | X710 (i40e) | [report](OLD/RUNBOUND-v0.23.8-threadripper-5995wx-2026-07-01.md) |
| **~11.88 M qps** | 0.138 ms (sustained) / 0.942 ms (at knee) | not isolated | **Runbound v0.23.8** `xdp: yes` (AF_XDP fast path), no huge pages this run | X520 (ixgbe) | [report](OLD/RUNBOUND-v0.23.8-threadripper-5995wx-2026-07-01.md) |

**No regression vs the v0.18.1/v0.19.3 baseline below** — single-link X710 rose from ~10.12 M
to ~12.56 M served at lower CPU (~24% → ~9.3%), consistent with no fast-path code having
moved during the de-hickory rewrite. The dual-link figure (~19.9 M) is **not directly
comparable** to the v0.19.3 dual-link row (~20.3 M): that earlier run used two separate
generator cards to avoid the exact imbalance this session's single-process, single-card-pair
setup hit — see the report's §5 for the full explanation.

## New bench rig (2026-06-13) — X710 + X510 direct links, **non-XDP generator**

A fresh rig to re-run the whole suite: the same hosts (5995WX receiver / dual Xeon E5-2690 v2
generator) joined by **two direct DAC links isolated from the prod LAN** — Intel **X710 (i40e)**
and **X510 (ixgbe)**. The reference-resolver baselines are measured first; the Runbound runs
follow.

**Methodology note:** the **kernel-path** rows (Runbound `xdp: no`, unbound, BIND) use a
**non-XDP (kernel-UDP) generator** capped at ~6 M q/s offered — they are generator/RX-bound, not
the resolver's ceiling (each sits at ~17–23 % CPU). The **fast-path** rows (Runbound `xdp: yes`)
use an **AF_XDP (`--xdp`) generator** (~13 M offered) — the only way to feed the fast path; those
are bounded by the **10 G link's response direction (~10.1 M pps)**, again not Runbound (≤24 % CPU).

| Max served | Latency (p50) | Receiver CPU | Configuration | Link / NIC | Report |
|-----------:|--------------:|-------------:|---------------|-----------|--------|
| **~20.3 M qps** | 0.188 (ixgbe link) | **~13 %** | **Runbound v0.19.3** `xdp: yes` **dual-link**, AF_XDP gen on **2 cards** — **2×10 G line-bound** (server not saturated) | X510 + X710 | [report](OLD/RUNBOUND-v0.19.3-threadripper-5995wx-x510x710-dual-xdp-2026-06-15.md) |
| **~13.50 M qps** | 0.100 | **~10 %** | **Runbound v0.19.3** `xdp: yes` **dual-link**, AF_XDP gen on **1 card** — **generator-bound** | 2× X710 (i40e) | [report](OLD/RUNBOUND-v0.19.3-threadripper-5995wx-x710-dual-xdp-2026-06-15.md) |
| **~10.12 M qps** | **0.045 ms** (wire) | **~11 %** | **Runbound v0.18.1** `xdp: yes` (AF_XDP fast path), AF_XDP generator — **link-bound** | X710 (i40e) | [report](OLD/RUNBOUND-v0.18.1-threadripper-5995wx-x710-xdp-2026-06-13.md) |
| **~10.12 M qps** | 0.054 ms (wire) | **~24 %** | **Runbound v0.18.1** `xdp: yes` (AF_XDP fast path), AF_XDP generator — **link-bound** (ixgbe heavier) | X510 (ixgbe) | [report](OLD/RUNBOUND-v0.18.1-threadripper-5995wx-x510-xdp-2026-06-13.md) |
| **~3.71 M qps** | 0.066 ms @921 k egress | **19.1 %** | **Runbound v0.18.1** `xdp: no` (kernel slow path), non-XDP generator | X710 (i40e) | [report](OLD/RUNBOUND-v0.18.1-threadripper-5995wx-x710-noxdp-2026-06-13.md) |
| **~2.51 M qps** | 1.013 ms @512 k egress | **19.7 %** | **Runbound v0.18.1** `xdp: no` (kernel slow path), non-XDP generator | X510 (ixgbe) | [report](OLD/RUNBOUND-v0.18.1-threadripper-5995wx-x510-noxdp-2026-06-13.md) |
| **~2.09 M qps** | 0.227 ms @927 k egress | **20.5 %** | **unbound 1.22.0** baseline, non-XDP generator (generator/RX-bound) | X710 (i40e) | [baseline](OLD/BASELINE-unbound-1.22.0-threadripper-5995wx-x710-2026-06-13.md) |
| **~1.84 M qps** | 0.320 ms @872 k egress | **17.3 %** | **BIND 9.20.23** baseline, non-XDP generator (generator/RX-bound) | X710 (i40e) | [baseline](OLD/BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-06-13.md) |
| **~1.65 M qps** | 1.026 ms @513 k egress | **23.2 %** | **unbound 1.22.0** baseline, non-XDP generator (ixgbe RX-bound) | X510 (ixgbe) | [baseline](OLD/BASELINE-unbound-1.22.0-threadripper-5995wx-x510-2026-06-13.md) |
| **~1.46 M qps** | 1.051 ms @500 k egress | **21.8 %** | **BIND 9.20.23** baseline, non-XDP generator (ixgbe RX-bound) | X510 (ixgbe) | [baseline](OLD/BASELINE-bind9-9.20.23-threadripper-5995wx-x510-2026-06-13.md) |

**Runbound's AF_XDP fast path tops the table — and never reaches its own ceiling.** Single 10 G
link: ~10.12 M served at ≤24 % CPU (link-bound). **Dual-link X510+X710: ~20.3 M at ~13 % CPU**,
both 10 G links at line rate at once — the 2×10 G aggregate is the wall, not the server (still
the receiver far from saturated). The dual-X710 row (13.50 M) is *generator*-bound: both its links are fed from the
two ports of the generator's single X710 card (one PCIe bus, ~13 M); using two *separate* generator
cards (the mixed row) lifts it to ~20.3 M. On a single link the fast path is ~5.5× unbound, ~6.9×
BIND, ~2.7× Runbound's own slow path, at lower CPU and lower latency (p50 0.045 ms). The rows below
compare the **kernel paths** (Runbound `xdp: no` vs the two kernel-UDP resolvers), same host,
generator, links and methodology. Findings, all consistent with the X520 archive:

- **Runbound's slow path serves ~2× the references** (X710 3.71 M vs unbound 2.09 M / BIND
  1.84 M; X510 2.51 M vs 1.65 M / 1.46 M) at the same ~19–23 % CPU — the "2–2.5×" ordering of
  the archive, from `recvmmsg` batching + the shared SIMD/ASM wire responder. Its closed-loop
  latency on the i40e link is in another class: **p99 0.371 ms vs unbound 7.1 / BIND 8.8 ms**.
- **RX efficiency tells the bottleneck.** Served / received: Runbound **81 % (X710) / 99 % (X510)**,
  unbound 49 % / 65 %, BIND 41 % / 59 %. On the ixgbe all three receive ~2.5 M/s (the NIC RX wall,
  ~3.35 M/s dropped before the resolver) — only Runbound turns nearly all of it into answers, the
  clearest proof it is **RX-bound, not CPU-bound** (19.7 % CPU).
- **Link/NIC:** same binary, only the link changes — the **i40e delivers ~4.5 M/s** (Runbound →
  3.7 M served) where the **ixgbe delivers ~2.5 M/s** (Runbound → 2.5 M served): give Runbound a
  NIC that ingests more and its served rate scales straight up.

The limit on the kernel-path rows is the **kernel-UDP RX path + the non-XDP generator (~5–6 M
offered)**, not the resolver — each sits at ~17–23 % CPU at its peak. On the fast-path rows the
limit is the **10 G link's response direction**, again not Runbound (≤24 % CPU). At no point in
this round did any server reach its own saturation ceiling. (dnsperf reads lower in closed-loop —
unbound on ixgbe loses 14.68 % to RX drops, Runbound 3.51 % — the open-loop dnsmark NIC counters
are the throughput truth; see each report's §5.)

**Truth source:** receiver NIC hardware counters (`tx_packets`/`rx_packets`, `ethtool -S`
`rx_missed`/`rx_no_dma`/`rx_dropped`), 1 Hz deltas over a 6 s steady window. Latency: dnsmark
round-trip. Every run follows [README.md](README.md) (warmup + ramp) and [TEMPLATE.md](TEMPLATE.md).

## Files

- [README.md](README.md) — the standard methodology (warmup + ramp, NIC-counter truth, host
  setup, writing rules). **Read this first.**
- [TEMPLATE.md](TEMPLATE.md) — the report template every run follows.
- [runbound-receiver-bench.conf](runbound-receiver-bench.conf) — the receiver config for the
  Runbound runs (`xdp:no`, real forward-zone, no local-data, `rate-limit: 0`).
- **Full suite (2026-07-03, dnsmark v2.7.7) — current**
  - [Runbound v0.23.13 — `xdp:no`, `xdp:yes`, dual-link (X710 + X520, all five runs)](RUNBOUND-v0.23.13-threadripper-5995wx-2026-07-03.md)
  - [unbound 1.22.0 — X710 + X520](BASELINE-unbound-1.22.0-threadripper-5995wx-2026-07-03.md)
  - [BIND 9.20.23 — X710 + X520](BASELINE-bind9-9.20.23-threadripper-5995wx-2026-07-03.md)
- **Re-run on v0.23.8 (2026-07-01) — official release binaries, NIC-counter ground truth**
  - [Runbound v0.23.8 `xdp: yes` — X710 (i40e) + X520 (ixgbe) single-link + dual-link (all three in one report)](OLD/RUNBOUND-v0.23.8-threadripper-5995wx-2026-07-01.md)
- **New bench rig (2026-06-13) — X710 + X510 direct links**
  - [Runbound v0.19.3 `xdp: yes` **dual-link X510+X710** (20.3 M, link-bound; per-link p99 ≤0.26 ms)](OLD/RUNBOUND-v0.19.3-threadripper-5995wx-x510x710-dual-xdp-2026-06-15.md)
  - [Runbound v0.19.3 `xdp: yes` **dual-link X710** (13.50 M, generator-bound; p50/p95/p99 0.100/0.247/0.251 ms)](OLD/RUNBOUND-v0.19.3-threadripper-5995wx-x710-dual-xdp-2026-06-15.md)
  - [Runbound v0.18.1 `xdp: yes` (AF_XDP fast path) — X710 (i40e)](OLD/RUNBOUND-v0.18.1-threadripper-5995wx-x710-xdp-2026-06-13.md)
  - [Runbound v0.18.1 `xdp: yes` (AF_XDP fast path) — X510 (ixgbe)](OLD/RUNBOUND-v0.18.1-threadripper-5995wx-x510-xdp-2026-06-13.md)
  - [Runbound v0.18.1 `xdp: no` (kernel slow path) — X710 (i40e)](OLD/RUNBOUND-v0.18.1-threadripper-5995wx-x710-noxdp-2026-06-13.md)
  - [Runbound v0.18.1 `xdp: no` (kernel slow path) — X510 (ixgbe)](OLD/RUNBOUND-v0.18.1-threadripper-5995wx-x510-noxdp-2026-06-13.md)
  - [unbound 1.22.0 — X710 (i40e)](OLD/BASELINE-unbound-1.22.0-threadripper-5995wx-x710-2026-06-13.md)
  - [unbound 1.22.0 — X510 (ixgbe)](OLD/BASELINE-unbound-1.22.0-threadripper-5995wx-x510-2026-06-13.md)
  - [BIND 9.20.23 — X710 (i40e)](OLD/BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-06-13.md)
  - [BIND 9.20.23 — X510 (ixgbe)](OLD/BASELINE-bind9-9.20.23-threadripper-5995wx-x510-2026-06-13.md)

## Related (outside this directory)

- [Whitepaper §08 — Performance](../whitepaper/08-performance.md) — the narrative version of
  these numbers, with the slow-path/fast-path internals.
- **Independent cross-validation with `dnsperf`** (DNS-OARC), published in the dnsmark
  repository: `docs/cross-validation-dnsperf.md` at <https://github.com/redlemonbe/dnsmark>.
