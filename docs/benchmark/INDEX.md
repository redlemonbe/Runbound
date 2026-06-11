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

## X710 (PCIe 3.0) — the X520 bus cap lifted

Same hosts and methodology, single Intel **X710** (i40e, PCIe 3.0) DAC replacing the
X520, second receiver port administratively down (single-link case):

| Run | Max served (NIC truth) | Offered peak | Knee (p50 < 1 ms) | NIC RX loss | Report |
|-----|-----------------------:|-------------:|------------------:|------------:|--------|
| Runbound v0.16.9 `xdp: yes` | ~10.1 M QPS | ~13.0 M (10G line rate) | 10.56 M offered | ~0 | [report](RUNBOUND-v0.16.9-threadripper-5995wx-x710-xdp-2026-06-10.md) |
| Runbound v0.16.11 `xdp: yes` | **10.09 M QPS** (timestamped) | 13.04 M | 10.56 M offered | 0 | [report](RUNBOUND-v0.16.11-threadripper-5995wx-x710-xdp-2026-06-10.md) |
| Runbound v0.16.11 `xdp: yes` **dual link** | **13.15 M QPS** (sum of 2 ports, 99.8% of offered) | 13.18 M (generator cap) | ~13.0 M total | ~0.002 %/run | [report](RUNBOUND-v0.16.11-threadripper-5995wx-x710-dual-xdp-2026-06-10.md) |

The v0.16.11 single-link run includes a same-method A/B against the previous binary:
served -0.06 %, knee +0.02 % — the 802.1Q VLAN path (#188) and the per-view
split-horizon snapshots (#187) cost nothing measurable on the untagged, no-view hot
path. The **dual-link** run answers the single-link open question: with two links the
served total rises to 13.15 M (+30 %) at ~11 % receiver CPU and 99.8 % of offered —
the single-link 10.09 M served cap was the link's response direction, not the server.
In dual-link the ceiling moves to the **generator** (dual Xeon v2 pushes ~13.2 M pps
total across any number of NICs); Runbound's own ceiling on this rig was not reached.

## EPYC 9554P + Broadcom BCM57508 100 G (Latitude fra2) — the bnxt copy-mode reference

Two identical Latitude.sh `rs4.metal.xlarge` ([rig](rigs/latitude-rs4-metal-xlarge-fra2.md)),
Runbound **v0.17.2**, generator dnsmark v2.2.1 over **kernel-UDP** (`bnxt_en` has **no AF_XDP
zero-copy** — `XDP_ZEROCOPY` bind = errno 95 on both hosts, re-verified on kernel 6.8 after 6.12 —
so `--xdp` generation is unusable and the receiver's AF_XDP fast path runs in **copy mode**),
802.1Q VLAN 100 G test link, warm cache, same methodology:

| Run | Max served (NIC truth) | CPU at max | Wire p50 (30 k qps) | Report |
|-----|-----------------------:|-----------:|--------------------:|--------|
| `xdp: no` (kernel slow path) | 4.09 M sustained (5.45 M burst); collapses to ~2.5–2.9 M under an 11 M flood | 32 % | 0.047 ms | [report](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-noxdp-2026-06-11.md) |
| `xdp: yes` single link (copy mode) | **7.85 M sustained** under a 10.8 M flood, no collapse, 0 discards | 8 % | 0.024 ms | [report](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-xdp-2026-06-11.md) |
| `xdp: yes` dual link (copy mode) | **9.07 M sustained / 11.13 M peak** (+15.5 % vs single) | 27 % | — | [report](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-dual-xdp-2026-06-11.md) |

Every figure on this rig is bounded by the missing `bnxt_en` zero-copy (generator capped at
~10.6 M qps kernel-UDP; receiver XSK drain in copy mode) — Runbound was never the limiting
component (0 NIC ring discards, ≤27 % CPU). The real fast-path ceiling of this CPU class on
100 G needs a zero-copy NIC (Intel `ice`/`i40e`, Mellanox `mlx5`); the earlier
[v0.16.9 attempt](RUNBOUND-v0.16.9-latitude-epyc9554p-bnxt-2026-06-10.md) on this rig is
superseded by these three runs.

## Files

- [README.md](README.md) — the standard methodology (warmup + ramp, NIC-counter truth, host
  setup, writing rules). **Read this first.**
- [TEMPLATE.md](TEMPLATE.md) — the report template every run follows.
- [runbound-receiver-bench.conf](runbound-receiver-bench.conf) — the receiver config used
  for the Runbound runs (`xdp:no`, real forward-zone, no local-data, `rate-limit: 0`).
- **Runbound runs**
  - [Latitude EPYC 9554P / bnxt v0.17.2 `xdp: no`](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-noxdp-2026-06-11.md)
  - [Latitude EPYC 9554P / bnxt v0.17.2 `xdp: yes` single](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-xdp-2026-06-11.md)
  - [Latitude EPYC 9554P / bnxt v0.17.2 `xdp: yes` dual](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-dual-xdp-2026-06-11.md)
  - [X710 v0.16.11 `xdp: yes` single-link](RUNBOUND-v0.16.11-threadripper-5995wx-x710-xdp-2026-06-10.md)
  - [X710 v0.16.11 `xdp: yes` dual-link](RUNBOUND-v0.16.11-threadripper-5995wx-x710-dual-xdp-2026-06-10.md)
  - [X710 v0.16.9 `xdp: yes`](RUNBOUND-v0.16.9-threadripper-5995wx-x710-xdp-2026-06-10.md)
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
