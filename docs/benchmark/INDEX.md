# Runbound — Benchmark index

## Measured speeds at a glance

Maximum **served** throughput per run — receiver NIC hardware counters, never the
generator's self-reported rate. Full context behind every number in its report.

> **Re-benchmark in progress (2026-06-13).** The whole suite is being re-run on a new rig
> (X710 + X510 direct links) with **Runbound v0.18.1 + dnsmark v2.3.0**. This index lists
> only the current round. All pre-v0.18.1 results (X520, X710 v0.16.x, EPYC/bnxt) are kept,
> unchanged, in [`archive/`](archive/README.md) — they used a different binary and, for the
> baselines, an AF-XDP generator, so they are **not** comparable to the rows below.

## New bench rig (2026-06-13) — X710 + X510 direct links, **non-XDP generator**

A fresh rig to re-run the whole suite: the same hosts (5995WX receiver / dual Xeon E5-2690 v2
generator) joined by **two direct DAC links isolated from the prod LAN** — Intel **X710 (i40e)**
and **X510 (ixgbe)**. The reference-resolver baselines are measured first; the Runbound runs
follow.

**Methodology note:** this round drives the generator **non-XDP (kernel UDP)**, capped at
~6 M q/s offered on the Xeon v2. So the served peaks below are **generator/RX-bound, not the
resolver's saturation ceiling** — each resolver sits at ~17–23 % CPU at its peak here. These
are the non-XDP reference for the matching non-XDP Runbound runs (identical host + generator).

| Max served | Latency (p50, closed-loop) | Receiver CPU | Configuration | Link / NIC | Report |
|-----------:|---------------------------:|-------------:|---------------|-----------|--------|
| **~2.09 M qps** | 0.227 ms @927 k egress | **20.5 %** | **unbound 1.22.0** baseline, non-XDP generator (generator/RX-bound) | X710 (i40e) | [baseline](BASELINE-unbound-1.22.0-threadripper-5995wx-x710-2026-06-13.md) |
| **~1.84 M qps** | 0.320 ms @872 k egress | **17.3 %** | **BIND 9.20.23** baseline, non-XDP generator (generator/RX-bound) | X710 (i40e) | [baseline](BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-06-13.md) |
| **~1.65 M qps** | 1.026 ms @513 k egress | **23.2 %** | **unbound 1.22.0** baseline, non-XDP generator (ixgbe RX-bound) | X510 (ixgbe) | [baseline](BASELINE-unbound-1.22.0-threadripper-5995wx-x510-2026-06-13.md) |
| **~1.46 M qps** | 1.051 ms @500 k egress | **21.8 %** | **BIND 9.20.23** baseline, non-XDP generator (ixgbe RX-bound) | X510 (ixgbe) | [baseline](BASELINE-bind9-9.20.23-threadripper-5995wx-x510-2026-06-13.md) |

Two axes, both consistent with the X520 archive:

- **Resolver:** on each link unbound serves ~13–14 % more than BIND (X710 2.09 M vs 1.84 M;
  X510 1.65 M vs 1.46 M) at comparable CPU, with a cleaner success rate and a much tighter
  closed-loop tail (unbound X510 p999 **1.161 ms** vs BIND **13.663 ms**). Same ordering as
  the archived X520 run (unbound 3.59 M > BIND 2.98 M).
- **Link/NIC:** same resolver, same generator, only the link changes — the **i40e ingests
  ~4.3–4.5 M/s (drops ~1.1–1.2 M/s)** where the **ixgbe ingests ~2.5 M/s (drops ~3.5 M/s)**
  under the identical ~6 M offered, so both resolvers serve more behind the i40e at the same CPU.

The limit on both links, both resolvers, is the **kernel-UDP RX path and the non-XDP generator
(~6 M offered)**, not the resolver. (dnsperf reads much lower in closed-loop, especially unbound
on ixgbe where RX drops inflate its "lost" count; the open-loop dnsmark NIC counters are the
throughput truth — see each report's §5.)

**Truth source:** receiver NIC hardware counters (`tx_packets`/`rx_packets`, `ethtool -S`
`rx_missed`/`rx_no_dma`/`rx_dropped`), 1 Hz deltas over a 6 s steady window. Latency: dnsmark
round-trip. Every run follows [README.md](README.md) (warmup + ramp) and [TEMPLATE.md](TEMPLATE.md).

## Files

- [README.md](README.md) — the standard methodology (warmup + ramp, NIC-counter truth, host
  setup, writing rules). **Read this first.**
- [TEMPLATE.md](TEMPLATE.md) — the report template every run follows.
- [runbound-receiver-bench.conf](runbound-receiver-bench.conf) — the receiver config for the
  Runbound runs (`xdp:no`, real forward-zone, no local-data, `rate-limit: 0`).
- **New bench rig (2026-06-13) — non-XDP generator, X710 + X510**
  - [unbound 1.22.0 — X710 (i40e)](BASELINE-unbound-1.22.0-threadripper-5995wx-x710-2026-06-13.md)
  - [unbound 1.22.0 — X510 (ixgbe)](BASELINE-unbound-1.22.0-threadripper-5995wx-x510-2026-06-13.md)
  - [BIND 9.20.23 — X710 (i40e)](BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-06-13.md)
  - [BIND 9.20.23 — X510 (ixgbe)](BASELINE-bind9-9.20.23-threadripper-5995wx-x510-2026-06-13.md)
  - _Runbound v0.18.1 runs to follow._
- **Rigs**
  - [Latitude.sh rs4.metal.xlarge (fra2)](rigs/latitude-rs4-metal-xlarge-fra2.md)
- **Archive** — all pre-v0.18.1 results (X520, X710 v0.16.x, EPYC/bnxt): [archive/README.md](archive/README.md)

## Related (outside this directory)

- [Whitepaper §08 — Performance](../whitepaper/08-performance.md) — the narrative version of
  these numbers, with the slow-path/fast-path internals.
- **Independent cross-validation with `dnsperf`** (DNS-OARC), published in the dnsmark
  repository: `docs/cross-validation-dnsperf.md` at <https://github.com/redlemonbe/dnsmark>.
