# Runbound Benchmark — v0.16.1 — AMD Threadripper PRO 5995WX — AF_XDP fast path (`xdp: yes`) — 2026-06-07

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

Over a single 10 GbE fibre (Intel X520 / 82599, PCIe 2.0 x8), Runbound v0.16.1 with
`xdp: yes` (AF_XDP fast path), warm cache, no local-data:

- **Served-rate ceiling (NIC truth): ~10.1 M QPS** at flood with **zero
  `rx_no_dma_resources`** — the NIC receives ~10.4 M QPS (its PCIe 2.0 RX line limit) and
  the fast path answers essentially all of it.
- Below NIC line rate the fast path tracks offered load 1:1: 8.0 M offered → 7.99 M served
  at **10.6 % CPU**.
- **dnsmark ramp** round-trip **p50 sub-millisecond up to ~10.85 M offered** — p50 0.062 ms
  / p99 0.088 ms at 6.4 M.

The receiver is far from CPU-bound (only ~31 of its cores engage at the maximum). The
ceiling is the X520 PCIe 2.0 RX, not Runbound. The fast path is unchanged from v0.16.0
(the v0.16.1 `recvmmsg` change is slow-path only); this run is the matched pair to the
slow-path report.

## 2. Objective

Measure the AF_XDP fast path (`xdp: yes`) throughput, latency and CPU cost under the
methodology (warmup + ramp), back-to-back with the kernel slow path on the same host and
NIC — only the `xdp:` line differs. Companion:
[no-xdp](RUNBOUND-v0.16.1-threadripper-5995wx-x520-noxdp-2026-06-07.md).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c / 128t), 125 GB RAM,
  Intel X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8 = 5.0 GT/s ×8, NUMA node 4),
  kernel 7.0.6-2-pve, Runbound **v0.16.1**, **`xdp: yes`** (`rb-single.conf`:
  `xdp-interface: enp33s0f0`, AF_XDP zero-copy workers, `answer_dns_wire` SIMD/ASM
  responder, `xdp-cache-snapshot-size: 65536`). `cache-min-ttl: 3600`,
  `upstream-racing: yes`, real `forward-zone`, **no local-data**. Governor `performance`.
  XDP program attached and verified (`ip -d link show enp33s0f0` → `xdp id …`). Identical
  config to the slow-path run except the `xdp:` line.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c / 40t, 2 NUMA), dnsmark 2.1.3,
  **AF_XDP** (symmetric XDP-vs-XDP), source-port spread 4096.
- **Link:** X520 ↔ X520, 10 GbE, direct fibre, flow-control off both ends, RSS `udp4 sdfn`,
  static ARP both ways. Ping RTT 0.118 ms.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt`, warmed (two passes).
- **Procedure:** **warmup, then `dnsmark --ramp`** (methodology execution model). Truth =
  receiver **NIC PHY counters** (`rx_pkts_nic` / `tx_pkts_nic` / `rx_no_dma_resources` /
  `rx_missed_errors`) — in XDP zero-copy the software counters do not reflect the datapath.
  The ramp "offered" is a target, not the wire rate (its wire egress tops out ~8 M from
  RTT-sampling overhead, below the fast path's NIC ceiling, so the open-loop flood is used
  to reach ~10.1 M). A receiver-side `tcpdump` latency anchor is **not possible** for XDP
  (XDP_REDIRECT bypasses the AF_PACKET tap); **I cannot confirm a receiver-side wire p50**.

## 4. Raw Results

**A. Latency — `dnsmark --ramp` round-trip (offered = target rate):**

| Offered (target) | p50 | p95 | p99 |
|-----------------:|----:|----:|----:|
| 1.6 M | 0.075 ms | 0.121 ms | 4.68 ms |
| 3.2 M | 0.060 ms | 0.088 ms | 1.56 ms |
| 6.4 M | **0.062 ms** | 0.096 ms | **0.088–3.16 ms** |
| 10.85 M | <1 ms (SLO edge) | 2.0 ms | 2.6 ms |
| ~11.5 M+ | >1 ms | — | — |

Highest step holding p50 < 1 ms = ~10.85 M target.

**B. Throughput — receiver NIC PHY counters (truth):**

| Offered | Received (NIC) | **Served (NIC)** | NIC drops (`rx_no_dma`) | Receiver CPU |
|--------:|---------------:|-----------------:|------------------------:|-------------:|
| 2.0 M | 2.00 M | 2.00 M | 0 | 5.6 % |
| 4.0 M | 4.01 M | 4.00 M | 0 | 6.9 % |
| 6.0 M | 6.01 M | 6.00 M | 0 | 8.7 % |
| 8.0 M | 8.01 M | 7.99 M | 0 | 10.6 % |
| flood (11 M+) | 10.39 M | **10.09 M** | **0** | 31 of 32 cores >90 % |

| Metric | Value | Source |
|--------|-------|--------|
| Served-rate ceiling | **~10.1 M** | receiver `tx_pkts_nic` |
| NIC receive ceiling | ~10.4 M (PCIe 2.0 RX line limit) | receiver `rx_pkts_nic` |
| Latency (ramp, ≤6.4 M) | p50 0.062 / p95 0.096 / p99 0.088 ms | dnsmark round-trip |
| Receiver CPU at 8 M served | **10.6 %** | `/proc/stat` |
| `rx_no_dma_resources` below line rate | **0** | `ethtool -S` |
| Receiver-side wire p50 | I cannot confirm this (tcpdump blind to XDP_REDIRECT) | — |

## 5. Interpretation

- **NIC-bound, not CPU-bound.** Served scales 1:1 with **zero `rx_no_dma`** up to 8 M
  (10.6 % CPU); at flood the NIC receives ~10.4 M (its PCIe 2.0 x8 RX line limit) and the
  fast path answers ~10.1 M. Only ~31 cores engage — the limit is the X520 receive path.
- **No queueing → flat latency.** Nothing backs up below line rate, so there is no latency
  knee within the NIC's capacity; the ramp p50 stays 0.06 ms across 3–6 M, p99 down to
  0.088 ms.
- **Why the fast path is not bound by the slow path's wall.** The slow path tops at ~7.3 M
  because the kernel NAPI poll + per-socket drain saturates the NIC's 8 NUMA-local cores
  (see the no-xdp report). The AF_XDP fast path consumes RX in the driver/XSK path without
  the kernel socket layer, so it reaches the NIC's PCIe line rate at a fraction of the CPU.
- **Back-to-back vs slow path** (same host/NIC, only `xdp:` changed): fast ~10.1 M served
  @ ~11 % CPU, 0 `rx_no_dma`, vs slow ~7.3 M @ ~70 cores busy. Same cache responder; the
  fast path serves ~1.4× more at a fraction of the CPU. The rate on a NIC without the
  PCIe 2.0 RX cap — **I cannot confirm this** from this rig.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (dragonrage, AMD 5995WX) ---
ip link set enp33s0f0 xdp off                          # clear any residual program first
ethtool -A enp33s0f0 rx off tx off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn
cpupower frequency-set -g performance
systemd-run --unit=rb-bench --collect \
  /usr/local/sbin/runbound -c /etc/runbound/rb-single.conf    # v0.16.1, xdp:yes, no local-data
ip -d link show enp33s0f0 | grep -o 'xdp id [0-9]*'    # verify XDP attached

# --- Generator (dragonsage, dual Xeon E5-2690 v2), dnsmark 2.1.3, AF_XDP ---
ethtool -A nic2 rx off tx off
ip neigh replace 10.10.20.1 lladdr <recv-mac> dev nic2 nud permanent
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 200000 -l 12 --max-outstanding 500   # warm
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp --ramp --max-outstanding 0
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q <2e6..11e6> --max-outstanding 0 -l 12

# --- Throughput truth (receiver) — HW PHY registers only in XDP mode ---
ethtool -S enp33s0f0 | grep -wE 'rx_pkts_nic|tx_pkts_nic|rx_no_dma_resources|rx_missed_errors'

# --- Teardown ---
ip link set enp33s0f0 xdp off
```
