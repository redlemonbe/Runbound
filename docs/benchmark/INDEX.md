# Runbound — Benchmark index

## Measured speeds at a glance

Maximum **served** throughput per run — receiver NIC hardware counters, never the
generator's self-reported rate. Full context behind every number in its report.

| Max served | Latency (p50) | Receiver CPU | Configuration | Rig / NIC | Report |
|-----------:|--------------:|-------------:|---------------|-----------|--------|
| **13.15 M qps** | 0.21–0.30 ms band to ~12.8 M | **~11 %** | Runbound v0.16.11 — `xdp: yes`, **dual link**, AF_XDP **zero-copy** | 5995WX + 2× X710 10G | [report](archive/RUNBOUND-v0.16.11-threadripper-5995wx-x710-dual-xdp-2026-06-10.md) |
| **10.09 M qps** | p50 < 1 ms up to 10.56 M offered | ~11 % | Runbound v0.16.11 — `xdp: yes`, single link, zero-copy (served cap = link response direction) | 5995WX + X710 10G | [report](archive/RUNBOUND-v0.16.11-threadripper-5995wx-x710-xdp-2026-06-10.md) |
| **~10.1 M qps** | 0.062 ms | ~11 % (≈31 cores) | Runbound v0.16.1 — `xdp: yes`, zero-copy (NIC PCIe-2.0 bus-bound) | 5995WX + X520 10G | [report](archive/RUNBOUND-v0.16.1-threadripper-5995wx-x520-xdp-2026-06-07.md) |
| **9.07 M qps** (peak 11.13 M) | — | ~27 % | Runbound v0.17.2 — `xdp: yes`, dual link, **copy mode** (bnxt: no zero-copy) | EPYC 9554P + 2× BCM57508 100G | [report](archive/RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-2026-06-11.md) |
| **7.85 M qps** | wire p50 **0.024 ms** | **~8 %** | Runbound v0.17.2 — `xdp: yes`, single link, copy mode, no collapse under 10.8 M flood | EPYC 9554P + BCM57508 100G | [report](archive/RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-2026-06-11.md) |
| **~7.3 M qps** | ~0.09 ms | ~55 % (≈70 cores) | Runbound v0.16.1 — **`xdp: no`** (kernel slow path) | 5995WX + X520 10G | [report](archive/RUNBOUND-v0.16.1-threadripper-5995wx-x520-noxdp-2026-06-07.md) |
| **4.09–5.03 M qps** | wire p50 0.047 ms | ~32 % | Runbound v0.17.2 — `xdp: no` (kernels 6.8 / 6.17; auto-tune no-ops on bnxt, #190) | EPYC 9554P + BCM57508 100G | [report](archive/RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-2026-06-11.md) |
| 3.59 M qps | 0.195 ms | ~65 % (64 thr) | **unbound 1.22.0** (baseline) | 5995WX + X520 10G | [baseline](archive/BASELINE-unbound-1.22.0-threadripper-5995wx-x520-2026-06-08.md) |
| 2.98 M qps | 0.068 ms | 100 % (128 thr) | **BIND 9.20.23** (baseline) | 5995WX + X520 10G | [baseline](archive/BASELINE-bind9-9.20.23-threadripper-5995wx-x520-2026-06-08.md) |

Reading rules for this table:

- **Compare within one rig only** (methodology rule 6). Same-rig comparisons that hold:
  Runbound fast path vs slow path vs unbound vs BIND on the X520 rig; single vs dual on
  X710; `xdp: no` vs copy-mode XDP on the EPYC/bnxt rig. Cross-rig numbers are functions
  of their NIC/driver/kernel.
- **No run above saturates Runbound itself.** X710 dual: ceiling = generator (~13.2 M pps).
  X520: NIC PCIe-2.0 bus. EPYC/bnxt: missing `bnxt_en` zero-copy (copy-mode drain ~8 M
  qps/port) and generator. At every fast-path maximum Runbound sits at ≤27 % CPU with
  ~0 NIC drops — the measured numbers are floors, not the server's ceiling.
- Truth source: receiver NIC hardware counters (`ethtool -S` — driver-specific names:
  `tx_pkts_nic`/`rx_pkts_nic` on i40e, `tx_ucast_frames`/`rx_ucast_frames` on bnxt),
  timestamped 1 Hz deltas. Latency: dnsmark round-trip, wire-anchored by tcpdump where
  stated. Every run follows [README.md](README.md) (warmup + ramp) and
  [TEMPLATE.md](TEMPLATE.md).

## New bench rig (2026-06-13) — X710 + X510 direct links, **non-XDP generator**

A fresh rig was built to re-run the whole suite on **Runbound v0.18.1 + dnsmark v2.3.0**:
the same hosts (5995WX receiver / dual Xeon E5-2690 v2 generator) now joined by **two
direct DAC links isolated from the prod LAN** — Intel **X710 (i40e)** and **X510 (ixgbe)**.
The reference-resolver baselines are re-measured first; the Runbound runs follow.

**Important methodology change vs the X520 archive:** this round drives the generator
**non-XDP (kernel UDP)**, capped at ~6 M q/s offered on the Xeon v2. The archived X520
baselines used an AF-XDP generator pushing 12 M offered. So the new served peaks are
**generator/RX-bound, not the resolver's saturation ceiling** — BIND sits at ~17–22 % CPU
at its peak here. Read these as the non-XDP reference for the matching non-XDP Runbound
runs (identical host + generator), **not** as comparable to the AF-XDP X520 numbers below.

| Max served | Latency (p50, closed-loop) | Receiver CPU | Configuration | Link / NIC | Report |
|-----------:|---------------------------:|-------------:|---------------|-----------|--------|
| **~1.84 M qps** | 0.320 ms @872 k egress | **17.3 %** | **BIND 9.20.23** baseline, non-XDP generator (generator/RX-bound) | X710 (i40e) | [baseline](BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-06-13.md) |
| **~1.46 M qps** | 1.051 ms @500 k egress | **21.8 %** | **BIND 9.20.23** baseline, non-XDP generator (ixgbe RX-bound) | X510 (ixgbe) | [baseline](BASELINE-bind9-9.20.23-threadripper-5995wx-x510-2026-06-13.md) |

Same host, same BIND, same generator — only the link changed: the **i40e ingests ~4.52 M/s
(drops 1.22 M/s)** where the **ixgbe ingests ~2.46 M/s (drops 3.60 M/s)** under the identical
~6 M offered, so BIND serves more behind the i40e (~1.84 M vs ~1.46 M) at the same CPU. The
limit on both links is the kernel-UDP RX path and the non-XDP generator, not BIND.

## X520 rig — Runbound vs reference resolvers (same rig, same generator)

**AMD Threadripper PRO 5995WX**, single **Intel X520 / 82599** (10 GbE, PCIe 2.0 x8),
generator **dnsmark** (AF_XDP open-loop) on dual Xeon E5-2690 v2, warm cache, no
local-data, governor `performance`, flow-control off, RSS `udp4 sdfn`.

On this rig Runbound's kernel slow path serves roughly **2–2.5×** the two reference
resolvers, and its AF_XDP fast path roughly **2.8–3.4×**, at lower latency and far fewer
engaged cores. Both baselines were measured with an explicit offered-load ramp (the
built-in `--ramp` yields no RTT samples against a flooded kernel-UDP server); see each
report for the full curve and the saturation knee.

At 10.1 M served the AF_XDP fast path used ~11 % CPU — it is **bus-bound** by the X520's
PCIe 2.0 x8 RX path (the NIC receives ~10.7 M pps and drops the rest), not CPU-bound. The
two reference resolvers, by contrast, plateau on their own per-query kernel-UDP cost
(BIND saturates all 128 cores; unbound peaks at 64 threads). Because Runbound keeps large
CPU headroom, a NIC without the PCIe 2.0 RX cap raises its numbers toward the link rate;
the reference resolvers would not move as much, being CPU-limited first.

## X710 rig (PCIe 3.0) — the X520 bus cap lifted

Same hosts and methodology, single Intel **X710** (i40e, PCIe 3.0) DAC replacing the
X520, second receiver port administratively down in the single-link case.

The v0.16.11 single-link run includes a same-method A/B against the previous binary
(v0.16.9, measured at ~10.1 M on the same rig): served -0.06 %, knee +0.02 % — the
802.1Q VLAN path (#188) and the per-view split-horizon snapshots (#187) cost nothing
measurable on the untagged, no-view hot path. The **dual-link** run answers the
single-link open question: with two links the served total rises to 13.15 M (+30 %) at
~11 % receiver CPU and 99.8 % of offered — the single-link 10.09 M served cap was the
link's response direction, not the server. In dual-link the ceiling moves to the
**generator** (dual Xeon v2 pushes ~13.2 M pps total across any number of NICs);
Runbound's own ceiling on this rig was not reached.

## EPYC 9554P + Broadcom BCM57508 100 G (Latitude fra2) — the bnxt copy-mode reference

Two identical Latitude.sh `rs4.metal.xlarge` ([rig](rigs/latitude-rs4-metal-xlarge-fra2.md)),
Runbound **v0.17.2**, generator dnsmark v2.2.1 over **kernel-UDP** — `bnxt_en` has **no
AF_XDP zero-copy** in any kernel (`XDP_ZEROCOPY` bind = errno 95; verified on 6.8, 6.12
and 6.17), so `--xdp` generation is unusable and the receiver's AF_XDP fast path runs in
**copy mode**. Four runs (xdp:no, XDP single, XDP dual, kernel-6.17 follow-up) in one
[consolidated report](archive/RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-2026-06-11.md).

Every figure on this rig is bounded by the missing `bnxt_en` zero-copy (generator capped
at ~10.6 M qps kernel-UDP on 6.8, 14.0 M on 6.17; receiver XSK drain in copy mode, **~8 M
qps/port** across kernels) — Runbound was never the limiting component (0 NIC ring
discards, ≤27 % CPU). These copy-mode figures must **not** be compared with the X710
zero-copy figures above. The real fast-path ceiling of this CPU class on 100 G needs a
zero-copy NIC (Intel `ice`/`i40e`, Mellanox `mlx5`) — verify the exact NIC model before
renting; "100 G" alone says nothing.

## Files

- [README.md](README.md) — the standard methodology (warmup + ramp, NIC-counter truth, host
  setup, writing rules). **Read this first.**
- [TEMPLATE.md](TEMPLATE.md) — the report template every run follows.
- [runbound-receiver-bench.conf](runbound-receiver-bench.conf) — the receiver config used
  for the Runbound runs (`xdp:no`, real forward-zone, no local-data, `rate-limit: 0`).
- **Runbound runs**
  - [X710 v0.16.11 `xdp: yes` single-link](archive/RUNBOUND-v0.16.11-threadripper-5995wx-x710-xdp-2026-06-10.md)
  - [X710 v0.16.11 `xdp: yes` dual-link](archive/RUNBOUND-v0.16.11-threadripper-5995wx-x710-dual-xdp-2026-06-10.md)
  - [X520 v0.16.1 `xdp: yes` (AF_XDP fast path)](archive/RUNBOUND-v0.16.1-threadripper-5995wx-x520-xdp-2026-06-07.md)
  - [X520 v0.16.1 `xdp: no` (kernel slow path)](archive/RUNBOUND-v0.16.1-threadripper-5995wx-x520-noxdp-2026-06-07.md)
  - [Latitude EPYC 9554P / bnxt v0.17.2 — consolidated (xdp:no, XDP single, XDP dual, kernel 6.17)](archive/RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-2026-06-11.md)
- **New bench rig (2026-06-13) — non-XDP generator, X710 + X510**
  - [BIND 9.20.23 — X710 (i40e)](BASELINE-bind9-9.20.23-threadripper-5995wx-x710-2026-06-13.md)
  - [BIND 9.20.23 — X510 (ixgbe)](BASELINE-bind9-9.20.23-threadripper-5995wx-x510-2026-06-13.md)
- **Reference-server baselines — X520 archive** (AF-XDP generator, same rig + methodology)
  - [unbound 1.22.0](archive/BASELINE-unbound-1.22.0-threadripper-5995wx-x520-2026-06-08.md)
  - [BIND 9.20.23](archive/BASELINE-bind9-9.20.23-threadripper-5995wx-x520-2026-06-08.md)
- **Rigs**
  - [Latitude.sh rs4.metal.xlarge (fra2)](rigs/latitude-rs4-metal-xlarge-fra2.md)

## Related (outside this directory)

- [Whitepaper §08 — Performance](../whitepaper/08-performance.md) — the narrative version of
  these numbers, with the slow-path/fast-path internals.
- **Independent cross-validation with `dnsperf`** (DNS-OARC), published in the dnsmark
  repository: `docs/cross-validation-dnsperf.md` at
  <https://github.com/redlemonbe/dnsmark>. A third-party tool confirms served = received
  (zero drops), 99.85 % NOERROR, sub-150 µs latency at ~3.4 % receiver CPU on `xdp: no`;
  dnsperf is generator-bound (~238 k QPS, closed-loop kernel-UDP) so it cross-checks
  correctness and latency rather than the ceiling.
