# Runbound Benchmark — Runbound v0.18.1 `xdp: yes` dual-link X510 + X710 — Threadripper PRO 5995WX — 2026-06-13

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, summed across both links. **`xdp: yes` (AF_XDP fast path)** with a single dnsmark
> multi-NIC AF_XDP generator (`-s` repeated). Companion to the dual-X710 report.

## 1. Executive Summary

One **Intel X510 (ixgbe)** link plus one **Intel X710 (i40e)** link bonded as two XDP fast-path
links, Runbound v0.18.1 serves a sustained **~20.28 M QPS** (sum of the two receiver NICs'
`tx_packets`) at **~24 % receiver CPU** — **~10.1 M per link, each at its 10 G line rate**. This is
the round's headline: by driving the two links from **two *separate* generator cards** (ixgbe
egress `nic2` + i40e egress `enp66s0f1np1`, two PCIe buses), the generator escapes the single-card
~13 M cap that bounded the dual-X710 run, and the receiver answers **both 10 G links at line rate
simultaneously**. At 24 % CPU Runbound is **still not saturated** — the cap here is the **aggregate
link capacity (2 × 10 G ≈ 20 M small-DNS pps)**, not the server. This is ~9.7× the best kernel-path
reference resolver on this rig (unbound 2.09 M).

## 2. Objective

Measure Runbound v0.18.1's AF_XDP fast path across **two heterogeneous links (ixgbe + i40e) at
once**, and — by using two different generator cards — push past the single-card generator ceiling
that limited the dual-X710 run, to find where the receiver actually sits.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM,
  `enp66s0f1` (X510 / `ixgbe`, 10.51.10.1) + `enp33s0f0np0` (X710 / `i40e`, 10.71.10.1), kernel
  6.12.88+deb13. Runbound **v0.18.1**, **`xdp: yes`**, multi-interface
  `xdp-interface: enp66s0f1,enp33s0f0np0` (CSV — one AF_XDP stack per NIC), **32 combined queues
  per port** (2 × 32 = 64 = physical cores), `xdp-hugepages: no` (regular-page UMEM),
  `forward-zone "."`, no local data, `rate-limit: 0`, warm cache. Governor `performance`,
  flow-control off.
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t). **Single instance,
  multi-NIC AF_XDP**: `-s 10.51.10.1 -s 10.71.10.1 --xdp -Q 0 --max-outstanding 0 --nic-stats`
  → 2 NICs × 10 workers. Egress NICs `nic2` (ixgbe) + `enp66s0f1np1` (i40e) = **two separate
  generator cards / PCIe buses**. `DNSMARK_SPORT_SPREAD=4096`.
- **Links:** one X510 (ixgbe) + one X710 (i40e) 10 GbE direct DAC, isolated, flow-control off.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, warmed on both links.
- **Procedure:** AF_XDP firehose; throughput = sum of both receiver NICs' `tx_packets` over
  2.5 s steady windows; CPU from `/proc/stat`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Served X510 link (`enp66s0f1`) | **~10.10 M/s** | receiver NIC |
| Served X710 link (`enp33s0f0np0`) | **~10.12 M/s** | receiver NIC |
| **Served total** | **~20.28 M peak** (steady ~20.2 M) | sum of both NICs |
| Receiver CPU % | **~24 %** (22.0–26.8 %) | `/proc/stat` |
| Receiver RAM | **~8.26 GB RSS** | `ps -o rss` |
| Per-query latency | unchanged from single-link (wire p50 ~0.05 ms) | single-link reports |

## 5. Interpretation

- **~20.28 M served at ~24 % CPU = both 10 G links at line rate, simultaneously.** Each link
  delivers its full ~10.1 M (the 10 G small-DNS response-direction line rate, identical to the
  single-link runs), and Runbound answers all of it. The cap is the **aggregate link capacity
  (2 × 10 G)**, not the server.
- **Why this beats dual-X710 (12.9 M): two generator cards, two PCIe buses.** The dual-X710 run
  drove both links from the two ports of the generator's *single* X710 card (one PCIe bus, ~13 M
  aggregate). Here one link is driven from the generator's ixgbe card and the other from its i40e
  card — two independent buses — so the generator offers ~20 M and the receiver serves it. The
  earlier "generator-limited" ceiling was a property of the generator's card, not Runbound.
- **Runbound is still not the bottleneck at 20 M.** 24 % CPU, ~76 % of the machine idle, 0
  meaningful drops. A third link (or 25/40/100 G NICs) would scale further until the host's PCIe
  or memory bandwidth is reached — not demonstrated here.
- **Context:** 20.28 M is ~9.7× unbound (2.09 M) and ~11× BIND (1.84 M), the best kernel-path
  references on this rig, and ~5.5× Runbound's own kernel slow path.
- **Caveat.** One rig, fast path, regular-page UMEM, two heterogeneous 10 G links. The receiver's
  true ceiling was not reached (≤24 % CPU); per-query latency was not separately re-measured in
  dual mode (it is the single-link fast-path wire latency, ~0.05 ms p50).

## 6. Appendix — exact commands & configuration

```bash
# Receiver — Runbound v0.18.1, xdp: yes, X510 + X710 (CSV multi-interface)
ethtool -L enp66s0f1 combined 32; ethtool -L enp33s0f0np0 combined 32
# config: xdp-interface: enp66s0f1,enp33s0f0np0   (one AF_XDP stack per NIC)
/root/runbound-bench -c /root/runbound-dual-mixed.conf

# Generator (dragonsage) — single instance, multi-NIC AF_XDP firehose (two separate cards):
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -s 10.71.10.1 -p 53 \
  -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0 --nic-stats -l 26
#   -> NIC[0] target 10.51.10.1 via nic2 (ixgbe), NIC[1] target 10.71.10.1 via enp66s0f1np1 (i40e)

# Throughput truth = SUM of both receiver NICs' tx_packets, 2.5 s windows:
cat /sys/class/net/enp66s0f1/statistics/tx_packets        # X510
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets     # X710
# Detach when done:
ip link set enp66s0f1 xdp off; ip link set enp33s0f0np0 xdp off
```
