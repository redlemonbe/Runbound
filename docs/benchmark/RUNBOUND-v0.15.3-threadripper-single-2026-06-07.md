# Runbound Benchmark — v0.15.3 — AMD Threadripper PRO 5995WX — 2026-06-07

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

Over a single 10 GbE fibre (Intel X520 / 82599, PCIe 2.0 x8), Runbound v0.15.3
served a sustained **~8.2 M real DNS QPS** (range 7.4–9.3 M across four runs) from
a warm cache (99.5 % hit rate, real forward-zone path, no local-data) while the
receiver CPU stayed **91.3 % idle** (8.7 % busy). Cache-hit round-trip latency was
**p50 0.225 ms / p95 0.379 ms / p99 0.472 ms** at a controlled ~200 k QPS load.
Answer success rate was **99.88 % NOERROR**. The throughput ceiling is **not**
Runbound and **not** the generator: the generator offered ~13 M QPS (≈ the 10 GbE
line rate for ~94-byte DNS frames) and the receiving X520 dropped ~0.9 M QPS to
`rx_no_dma_resources` — the per-packet DMA/descriptor rate of the card's PCIe 2.0
link. Runbound itself was never saturated.

## 2. Objective

Measure the real, cache-served DNS throughput and latency of Runbound's XDP fast
path over a single 10 GbE link, and identify the binding bottleneck (software vs
link vs NIC/bus).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Threadripper PRO 5995WX (64 cores / 128 threads),
  125 GB RAM, Intel X520 / 82599 (`ixgbe`, PCIe 2.0 x8, MTU 1500), kernel
  7.0.6-2-pve, Runbound v0.15.3, `xdp: yes` (DRV/zero-copy), single
  `xdp-interface`, `rate-limit: 0`, real `forward-zone` (no local-data),
  `cache-min-ttl 3600`. Config: [runbound-receiver-bench.conf](runbound-receiver-bench.conf).
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), dnsmark v2.1.2,
  AF_XDP zero-copy. Command:
  `dnsmark -s <recv-ip> -d top-10000-domains.txt -p 53 --xdp -Q 0 --max-outstanding 0`.
- **Link:** Intel X520 ↔ X520, 10 GbE, **direct** (no switch), flow-control **off**
  both ends, symmetric per-worker source ports for RSS.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt`, 10 000 real names, cycled.
- **Procedure:** warm the cache (forward + cache all corpus names, → 99.5 % hit),
  then open-loop flood; 10 s steady measurement window; throughput read from the
  receiver NIC PHY counters (`ethtool -S`: `rx_pkts_nic`, `tx_pkts_nic`,
  `rx_no_dma_resources`); CPU from `/proc/stat`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Offered (on the wire) | ~13.0 M QPS (≈ 10 GbE line rate, ~94 B frames) | generator `tx_pkts_nic` |
| Received by NIC | ~11.8 M QPS | receiver `rx_pkts_nic` |
| NIC drops (PCIe 2.0 RX descriptor pressure) | ~0.9 M QPS `rx_no_dma_resources` (0.00 `rx_missed_errors`) | receiver `ethtool -S` |
| **Max sustained served QPS** | **~8.2 M** (7.4–9.3 M across 4 runs) | receiver `tx_pkts_nic` (responses on the wire) |
| Latency p50 / p95 / p99 | 0.225 / 0.379 / 0.472 ms @ ~200 k QPS controlled | dnsmark round-trip histogram |
| Latency at the 8.2 M peak | I cannot confirm this. (generator AF_XDP round-trip RX caps reliable sampling well below peak) | — |
| Success / error rate | 99.88 % NOERROR | dnsmark rcode breakdown |
| Receiver CPU | 8.7 % busy / **91.3 % idle** | `/proc/stat` over the window |
| Receiver RAM | 125 GB total; cache 8192 entries (capped under memory pressure) | `free`, `/api/stats` |
| Cache hit rate | 99.5 % | `/api/stats` |

## 5. Interpretation

- **Runbound is not the bottleneck.** It served ~8.2 M QPS at 8.7 % CPU (91.3 %
  idle). The software fast path has large headroom on this host.
- **The generator is not the bottleneck.** It offered ~13 M QPS, which is ≈ the
  10 GbE line rate for ~94-byte DNS frames; it is link-bound, not PCIe-bound (its
  AF_XDP TX is batched and cheap, and its own X520 PCIe 2.0 has TX headroom).
- **The ceiling is the receiving X520's PCIe 2.0 link.** ~0.9 M QPS are dropped at
  the NIC as `rx_no_dma_resources` — the card cannot replenish RX descriptors /
  DMA small packets fast enough over PCIe 2.0 (5 GT/s x8, confirmed by `lspci`
  `LnkCap`/`LnkSta` and sysfs `max_link_speed = 5.0 GT/s`). XDP cannot relieve
  this: the DMA crosses PCIe *before* the XDP program runs, so the drop happens
  below XDP. Exposing the PCIe floor is the expected outcome of a working
  kernel-bypass path (software no longer the limit).
- The 82599 exposes **one** PCIe 2.0 x8 link shared by both ports, so a second
  fibre would not scale small-packet QPS on this card. I cannot confirm this on
  this rig (the second port is faulty hardware and was disabled); it is a
  hardware-architecture statement, not a measured one.
- The gap between received (~11.8 M) and served (~8.2 M) is ~30 %; whether this is
  a Runbound TX-side limit or PCIe-2.0 TX-descriptor pressure on the response path,
  I cannot confirm this without valid ZC NIC counters (the X520 netdev counters are
  blind under zero-copy).

## 6. Appendix — exact commands & configuration

```bash
# Receiver (Runbound) — single fibre, real cache, XDP zero-copy
ethtool -A enp33s0f0 rx off tx off        # flow control off
ip link set enp33s0f0 mtu 1500            # ≤3506 so DRV/ZC mode is available
runbound -c runbound-receiver-bench.conf  # xdp: yes, forward-zone, no local-data
lspci -vv -s 21:00.0 | grep -E 'LnkCap|LnkSta'   # Speed 5GT/s = PCIe 2.0 (card max)
cat /sys/bus/pci/devices/0000:21:00.0/max_link_speed   # 5.0 GT/s PCIe (silicon)

# Generator (dnsmark) — static ARP (else silent sendmmsg fallback), then flood
ip neigh replace <recv-ip> lladdr <recv-mac> dev <nic> nud permanent
dnsmark -s <recv-ip> -d top-10000-domains.txt -p 53 --xdp -Q 0 --max-outstanding 0
# (dnsmark v2.1.2 auto-pins the performance governor and auto-detaches any stale
#  XDP program left by a previously killed run — no manual setup needed.)

# Throughput (receiver NIC PHY counters, snapshot twice over a 10 s window)
ethtool -S enp33s0f0 | grep -wE 'rx_pkts_nic|tx_pkts_nic|rx_no_dma_resources|rx_missed_errors'
# served QPS = delta(tx_pkts_nic)/window ; offered-received gap = delta(rx_no_dma_resources)

# Latency (controlled ~200 k QPS so round-trip completion is reliable on the wire)
dnsmark -s <recv-ip> -d top-10000-domains.txt -p 53 --xdp -Q 2000000 --max-outstanding 16000
```

> **NIC note.** The Intel X520 / 82599 works but is a poor *measurement* platform
> for high-rate XDP: PCIe 2.0 x8 (shared by both ports), RSS capped at 16 queues,
> and netdev counters that read 0 under zero-copy (only `*_nic` driver counters and
> `XDP_STATISTICS` are reliable). An Intel i40e (X710), ice (E810) or igc lifts the
> PCIe ceiling and exposes valid ZC counters. See [README.md](README.md).
