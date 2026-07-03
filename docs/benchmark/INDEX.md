# Runbound — Benchmark index

> **Archive note (2026-07-03).** All runs in the "at a glance" table below predate the
> current methodology revision (dnsmark-vs-NIC cross-check table + ramp/DSD rules in
> [README.md](README.md)) and have been moved to [OLD/](OLD/). They remain valid
> measurements under the methodology of their time. New-methodology runs are listed
> directly under the heading immediately below.

## Current campaign (revised methodology, 2026-07-03)

Runs under the [README.md](README.md) revision. The **throughput figure is the
closed-loop SLO knee** (ramp DSD), cross-checked against receiver NIC counters. The
open-loop firehose is **not** used as a capacity number — it is a DoS that livelocks the
resolver; it appears here only as an overload observation and as a check that dnsmark's
NIC-rx instrumentation is exact at high pps.

**Reference resolvers — BIND 9.20.23** (dnsmark 2.7.5 + dnsperf 2.14.0 generators,
corpus warmed 100 k):

| **Capacity — closed-loop knee (SLO)** | Under overload firehose (not a measure) | Tool cross-check | Link / NIC | Report |
|--------------------------------------:|-----------------------------------------|:----------------:|-----------|--------|
| **~1.40 M qps** (99.90 % NOERROR, p50 0.133 ms) | 18 % SERVFAIL livelock; NIC ingested 4.96 M/s, 0 drops | dnsmark 1.589 M vs NIC tx 1.611 M = **1.4 %** | X710 (i40e) | [report](BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-07-03.md) |
| **~1.12 M qps** (Within-SLO 1.09 M) | 50 % SERVFAIL livelock; 82599 dropped ~2.7 M/s at `rx_no_dma` before BIND | dnsmark 1.204 M vs NIC tx 1.202 M = **0.2 %** | X520 / 82599ES (ixgbe) | [report](BASELINE-bind9-9.20.23-threadripper-5995wx-x520-2026-07-03.md) |

Back-to-back, same host/binary/generator, only the link changed (rule 6): the i40e
ingests 4.96 M/s with zero drops → BIND knee ~1.40 M; the 82599 hits its RX-DMA wall at
~2.69 M/s ingested (~2.7 M/s dropped before the resolver) → BIND knee ~1.12 M. The
difference is the NIC, not BIND (CPU ≤17.5 of 128 cores on both). Runbound runs under
this methodology follow.

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
