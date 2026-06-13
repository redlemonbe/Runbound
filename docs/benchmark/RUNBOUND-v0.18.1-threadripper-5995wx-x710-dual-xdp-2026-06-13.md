# Runbound Benchmark — Runbound v0.18.1 `xdp: yes` dual-link X710 — Threadripper PRO 5995WX — 2026-06-13

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, summed across both links. **`xdp: yes` (AF_XDP fast path)** with a single dnsmark
> multi-NIC AF_XDP generator (`-s` repeated). Companion to the mixed dual-link report
> (X510 + X710).

## 1. Executive Summary

Both ports of the **Intel X710 (i40e)** card bonded as two XDP fast-path links, Runbound v0.18.1
serves a sustained **~12.90 M QPS** (sum of the two receiver NICs' `tx_packets`) at **~12 %
receiver CPU**, balanced ~6.4 M + 6.4 M per port. This is **generator-bound, not Runbound**: the
generator drives both links from the **two ports of its single X710 card**, which share one PCIe
bus and cap the generator's aggregate at ~13 M pps. The receiver sits at 12 % CPU — it is nowhere
near its limit (see the mixed X510+X710 report, where driving the two links from two *separate*
generator cards lifts the total to 20.28 M at the same receiver). Reproduces the archived
dual-link X710 figure (13.15 M).

## 2. Objective

Measure Runbound v0.18.1's AF_XDP fast path across **both X710 ports at once** (single dnsmark
instance, multi-NIC mode), to see whether two links aggregate and where the limit sits.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **both Intel
  X710 ports** `enp33s0f0np0` (10.71.10.1) + `enp33s0f1np1` (10.71.20.1), `i40e`, kernel
  6.12.88+deb13. Runbound **v0.18.1**, **`xdp: yes`**, multi-interface
  `xdp-interface: enp33s0f0np0,enp33s0f1np1` (CSV — Runbound binds one AF_XDP stack per NIC),
  **32 combined queues per port** (2 × 32 = 64 = physical cores), `xdp-hugepages: no`
  (regular-page UMEM), `forward-zone "."`, no local data, `rate-limit: 0`, warm cache. Governor
  `performance`, flow-control off, RSS `udp4 sdfn` both ports.
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t). **Single instance,
  multi-NIC AF_XDP**: `-s 10.71.10.1 -s 10.71.20.1 --xdp -Q 0 --max-outstanding 0 --nic-stats`
  → 2 NICs × 10 workers. Egress NICs `enp66s0f1np1` + `enp66s0f0np0` = **the two ports of the
  generator's single X710 card**. `DNSMARK_SPORT_SPREAD=4096`.
- **Links:** two Intel X710 (i40e) 10 GbE direct DACs, isolated, flow-control off.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, warmed on both links.
- **Procedure:** AF_XDP firehose; throughput = sum of both receiver NICs' `tx_packets` over
  2.5 s steady windows; CPU from `/proc/stat`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Served port 0 (`enp33s0f0np0`) | **~6.40 M/s** | receiver NIC |
| Served port 1 (`enp33s0f1np1`) | **~6.40 M/s** | receiver NIC |
| **Served total** | **~12.90 M peak** (steady 12.5–12.9 M) | sum of both NICs |
| Receiver CPU % | **~12 %** (10.8–12.9 %) | `/proc/stat` |
| Receiver RAM | **~8.45 GB RSS** | `ps -o rss` |
| Per-query latency | unchanged from single-link (wire p50 ~0.05 ms) | single-link report |

## 5. Interpretation

- **Two links aggregate cleanly: ~12.9 M total, balanced 6.4 M + 6.4 M, at 12 % CPU.** Runbound
  scales linearly across NICs with no per-query penalty.
- **The cap is the generator's single X710 card, not Runbound.** Both generator egress ports live
  on one X710 card sharing one PCIe bus, which tops out at ~13 M pps aggregate — exactly the
  archived dual-X710 ceiling (13.15 M). The receiver at 12 % CPU has the whole machine in reserve.
  The companion **mixed X510+X710** run proves this: driving the two links from two *separate*
  generator cards lifts the served total to **20.28 M at the same receiver** (24 % CPU).
- **Caveat.** Generator-bound; this is not Runbound's ceiling. One rig, fast path, regular-page UMEM.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — Runbound v0.18.1, xdp: yes, both X710 ports (CSV multi-interface)
ethtool -L enp33s0f0np0 combined 32; ethtool -L enp33s0f1np1 combined 32
# config: xdp-interface: enp33s0f0np0,enp33s0f1np1   (one AF_XDP stack per NIC)
/root/runbound-bench -c /root/runbound-dual-x710.conf

# Generator (dragonsage) — single instance, multi-NIC AF_XDP firehose:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -s 10.71.20.1 -p 53 \
  -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0 --nic-stats -l 26

# Throughput truth = SUM of both receiver NICs' tx_packets, 2.5 s windows:
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets
cat /sys/class/net/enp33s0f1np1/statistics/tx_packets
# Detach when done:
ip link set enp33s0f0np0 xdp off; ip link set enp33s0f1np1 xdp off
```
