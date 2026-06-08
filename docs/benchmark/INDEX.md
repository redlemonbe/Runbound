# Runbound — Benchmark index

This directory holds every Runbound performance benchmark, each produced under the same
[methodology](README.md) and [report template](TEMPLATE.md). Truth is always the **receiver
NIC hardware counters** (`ethtool -S`: `tx_pkts_nic` served, `rx_pkts_nic` received, plus
`rx_no_dma_resources`/`rx_missed_errors` drops), not the generator's self-reported
round-trip.

## Summary — same rig, same generator, same methodology

All runs below: **AMD Threadripper PRO 5995WX**, single **Intel X520 / 82599** (10 GbE,
PCIe 2.0 x8), generator **dnsmark** (AF_XDP open-loop) on dual Xeon E5-2690 v2, warm cache,
no local-data, governor `performance`, flow-control off, RSS `udp4 sdfn`.

| Server | Max served (NIC truth) | Cores at max | Cache-hit latency (p50) | Report |
|--------|-----------------------:|--------------|------------------------:|--------|
| **Runbound `xdp: yes`** (AF_XDP fast path) | **~10.1 M QPS** | ~31 | 0.062 ms | [report](RUNBOUND-v0.16.1-threadripper-5995wx-x520-xdp-2026-06-07.md) |
| **Runbound `xdp: no`** (kernel slow path) | **~7.3 M QPS** | ~70 | ~0.09 ms | [report](RUNBOUND-v0.16.1-threadripper-5995wx-x520-noxdp-2026-06-07.md) |
| unbound 1.22.0 | ~3.59 M QPS | 64 (~65% CPU) | 0.195 ms | [baseline](BASELINE-unbound-1.22.0-threadripper-5995wx-x520-2026-06-08.md) |
| BIND 9.20.23 | ~2.98 M QPS | 128 (all, 100%) | 0.068 ms | [baseline](BASELINE-bind9-9.20.23-threadripper-5995wx-x520-2026-06-08.md) |

On this rig Runbound's kernel slow path serves roughly **2–2.5×** the two reference
resolvers, and its AF_XDP fast path roughly **2.8–3.4×**, at lower latency and far fewer
engaged cores. Both baselines were measured with an explicit offered-load ramp (the
built-in `--ramp` yields no RTT samples against a flooded kernel-UDP server); see each
report for the full curve and the saturation knee.

## The ceiling on this rig is the NIC bus, not Runbound

At 10.1 M served the AF_XDP fast path used **~11 % CPU** — it is **bus-bound** by the X520's
PCIe 2.0 x8 RX path (the NIC receives ~10.7 M pps and drops the rest), not CPU-bound. The
two reference resolvers, by contrast, plateau on their own per-query kernel-UDP cost
(BIND saturates all 128 cores; unbound peaks at 64 threads). Because Runbound keeps large
CPU headroom, a NIC without the PCIe 2.0 RX cap (e.g. a PCIe-3.0 card) would raise its
numbers toward the link rate; the reference resolvers would not move as much, being
CPU-limited first. Any such figure is **a function of this rig**, recorded in the reports,
not asserted as a universal claim.

## Files

- [README.md](README.md) — the standard methodology (warmup + ramp, NIC-counter truth, host
  setup, writing rules). **Read this first.**
- [TEMPLATE.md](TEMPLATE.md) — the report template every run follows.
- [runbound-receiver-bench.conf](runbound-receiver-bench.conf) — the receiver config used
  for the Runbound runs (`xdp:no`, real forward-zone, no local-data, `rate-limit: 0`).
- **Runbound runs**
  - [`xdp: yes` (AF_XDP fast path)](RUNBOUND-v0.16.1-threadripper-5995wx-x520-xdp-2026-06-07.md)
  - [`xdp: no` (kernel slow path)](RUNBOUND-v0.16.1-threadripper-5995wx-x520-noxdp-2026-06-07.md)
- **Reference-server baselines** (same rig + methodology)
  - [unbound 1.22.0](BASELINE-unbound-1.22.0-threadripper-5995wx-x520-2026-06-08.md)
  - [BIND 9.20.23](BASELINE-bind9-9.20.23-threadripper-5995wx-x520-2026-06-08.md)

## Related (outside this directory)

- [Whitepaper §08 — Performance](../whitepaper/08-performance.md) — the narrative version of
  these numbers, with the slow-path/fast-path internals.
- **Independent cross-validation with `dnsperf`** (DNS-OARC), published in the dnsmark
  repository: `docs/cross-validation-dnsperf.md` at
  <https://github.com/redlemonbe/dnsmark>. A third-party tool confirms served = received
  (zero drops), 99.85 % NOERROR, sub-150 µs latency at ~3.4 % receiver CPU on `xdp: no`;
  dnsperf is generator-bound (~238 k QPS, closed-loop kernel-UDP) so it cross-checks
  correctness and latency rather than the ceiling.
