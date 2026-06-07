# Runbound Benchmark — v0.16.0 — AMD Threadripper PRO 5995WX — kernel slow path (`xdp: no`) — 2026-06-07

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

Over a single 10 GbE fibre (Intel X520 / 82599, PCIe 2.0 x8), Runbound v0.16.0 with
`xdp: no` (kernel slow path) served from a warm cache, no local-data:

- **Maximum sustained served rate (NIC truth): ~6.9 M QPS** (band 6.7–7.0 M across runs)
  at **~61 % receiver CPU**, with the receiver NIC receiving ~10 M QPS and dropping the
  excess (~5 M QPS) in hardware as `rx_no_dma_resources` + `rx_missed_errors` (PCIe 2.0
  RX limit). At this point latency is in the tens of milliseconds (the link is past its
  knee).
- **Maximum rate under a sub-millisecond median SLO (p50 < 1 ms): ~4.6 M QPS served**
  (5.0 M offered), wire p50 **0.746 ms**, at **~43 % receiver CPU**, zero NIC drops.

The receiver was not CPU-bound at either point (≥39 % idle). Cache-hit serving latency
sampled on the receiver wire at low load was p50 **0.019 ms** / p99 0.064 ms. The p95/p99
tail under load is the ~0.2 % of corpus names that miss the cache and are forwarded to the
real upstreams over the internet (tens to hundreds of ms); the median is robust to it,
which is why it is the SLO signal.

## 2. Objective

Measure the cache-served throughput and latency of the kernel slow path (`xdp: no`) on a
high-core-count host, and find the saturation point under the methodology, for direct
back-to-back comparison with the AF_XDP fast path on the same host and NIC (companion
report: [xdp](RUNBOUND-v0.16.0-threadripper-5995wx-x520-xdp-2026-06-07.md)).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c / 128t), 125 GB RAM,
  Intel X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8 = 5.0 GT/s ×8 confirmed via sysfs,
  MTU 1500), kernel 7.0.6-2-pve, Runbound **v0.16.0**, **`xdp: no`** (config
  `rb-single-noxdp.conf`: kernel fast loop, one SO_REUSEPORT UDP socket per physical core
  minus one reserved; even distribution via the v0.16.0 `SO_ATTACH_REUSEPORT_CBPF` by-CPU
  program + RPS; `answer_from_cache` SIMD/ASM responder — the same one the XDP fast path
  uses). `rate-limit: 0`, `cache-min-ttl: 3600`, `upstream-racing: yes`, real
  `forward-zone` (1.1.1.1 / 8.8.8.8 / 9.9.9.9, plain UDP), **no local-data**. Governor
  `performance`. RX ring 8192, `net.core.rmem_max` 32 MiB, RPS = all cores on every rx
  queue.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c / 40t, 2 NUMA), dnsmark 2.1.3,
  AF_XDP TX firehose, source-port spread 4096 (`DNSMARK_SPORT_SPREAD=4096`) so the
  receiver's RSS fans flows across all rx queues. The frames on the wire are standard
  UDP/53 datagrams; the receiver processes them through its kernel slow path regardless of
  how the generator built them.
- **Link:** Intel X520 ↔ Intel X520, 10 GbE, direct fibre (no switch), flow-control off
  on both ends (`ethtool -A … rx off tx off`), RSS `rx-flow-hash udp4 sdfn`, static ARP
  both directions. Ping RTT 0.118 ms.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt` (10 000 real names). Cache warmed
  by two full passes before measurement (first pass forwards misses; second pass
  99.86 % NOERROR, tail collapsed).
- **Procedure:** warmup, then an **offered-load sweep** (2 → 6 M QPS in steps, plus a
  line-rate flood). At each step the **truth = receiver NIC PHY counters** (`ethtool -S`:
  `rx_pkts_nic`, `tx_pkts_nic`, `rx_no_dma_resources`, `rx_missed_errors`) over a fixed
  window; receiver CPU from `/proc/stat`; **latency anchored to a `tcpdump` capture on the
  receiver** (request-arrival → response-departure on the wire), per measurement rule 7.
  Saturation criterion: highest offered load holding wire p50 < 1 ms.
  - *Note on `--ramp`:* dnsmark's built-in ramp reported a misleadingly high SLO point
    because the generator's single AF_XDP **RX** queue caps the *observed* round-trip at
    ~245 k/s, so its self-reported p50 stays low while most answers are simply not seen by
    the generator. Per rules 1 and 7, saturation was instead determined from receiver NIC
    counters and receiver-side wire latency, not the generator's round-trip.

## 4. Raw Results

Offered-load sweep (warm cache, no local-data). Served = receiver `tx_pkts_nic` delta
(responses on the wire). Wire p50 = `tcpdump` on the receiver.

| Offered | Received (NIC) | **Served (NIC)** | NIC drops | Receiver CPU | Wire p50 |
|--------:|---------------:|-----------------:|----------:|-------------:|---------:|
| 2.0 M | 2.01 M | 2.00 M | 0 | 23 % | 0.202 ms |
| 3.0 M | 3.01 M | 3.01 M | 0 | 31 % | 0.334 ms |
| 4.0 M | 4.03 M | 3.89 M | 0 | 36 % | 0.377 ms |
| 5.0 M | 5.04 M | **4.60 M** | 0 | 43 % | **0.746 ms** ← SLO knee |
| 5.5 M | 5.54 M | 4.96 M | 0 | 45 % | 18.2 ms |
| 6.0 M | 6.04 M | 5.36 M | ~3 k | 50 % | 47 ms |
| ~10 M (flood) | ~10.0 M | **~6.9 M** | ~5.0 M | 61 % | ~32 ms |

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained served QPS (NIC-bound) | **~6.9 M** (band 6.7–7.0 M) | receiver `tx_pkts_nic` |
| Max served QPS under p50 < 1 ms SLO | **~4.6 M** (5.0 M offered) | receiver `tx_pkts_nic` |
| Cache-hit serving latency, low load (wire) | p50 **0.019** / p95 0.049 / p99 0.064 ms | receiver `tcpdump` |
| Latency under SLO knee (5 M offered, wire) | p50 **0.746** ms | receiver `tcpdump` |
| Success / error rate | 99.86 % NOERROR / ~0.01 % SERVFAIL | dnsmark rcode breakdown |
| Receiver CPU at NIC-bound max | **~61 %** busy (≥39 % idle) | `/proc/stat` |
| Receiver RAM | well within 125 GB (cache resident) | — |
| NIC drops at flood | ~2 M `rx_no_dma_resources` + ~3 M `rx_missed_errors` | receiver `ethtool -S` |

## 5. Interpretation

- **Two distinct ceilings.** The raw throughput ceiling (~6.9 M served) is reached when
  the X520 RX is saturated: the NIC receives ~10 M QPS and drops ~5 M in hardware (PCIe
  2.0 x8 RX limit), so served plateaus while latency rises into the tens of ms. The
  SLO-respecting ceiling (~4.6 M served, p50 0.746 ms) is reached earlier; beyond ~5 M
  offered the wire p50 jumps from 0.746 ms (5 M) to 18 ms (5.5 M) — the queueing knee.
- **Not CPU-bound.** At the raw max the receiver is ~61 % busy; at the SLO knee ~43 %.
  Headroom remains at both points. The limit is the NIC RX path and per-socket queue
  build-up under imbalance, not Runbound's serving logic.
- **The tail is forwarding, not serving.** Wire p50 (cache hits) is sub-millisecond up to
  the knee; p95/p99 in the sweep are dominated by the ~0.2 % of names that miss the cache
  and are forwarded to the real upstreams (1.1.1.1 / 8.8.8.8 / 9.9.9.9) over the internet,
  costing tens to hundreds of ms. This is inherent to a forwarding resolver on a real
  corpus and is why the median is the SLO signal.
- **Distribution matters.** With a single source flow the receiver served only ~0.49 M at
  12 % CPU — all traffic landed on one rx queue / one core. With RSS `sdfn` + generator
  source-port spread + RPS + the v0.16.0 by-CPU cBPF reuseport, served rose to ~6.9 M.
  This is a benchmark-setup property (flow diversity), reported for reproducibility.
- **Comparison.** On the same host and NIC the AF_XDP fast path served ~10.1 M at ~21 %
  CPU with zero drops below NIC line rate (companion report). The slow path reaches the
  same order of magnitude but pays per-packet kernel-UDP syscalls — higher CPU and an
  earlier latency knee. Both are ultimately bounded by the X520 PCIe 2.0 RX; a NIC without
  that cap would scale both higher. The magnitude of that headroom on a faster NIC —
  **I cannot confirm this** without measuring on such hardware.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (dragonrage, AMD 5995WX) ---
cat /sys/class/net/enp33s0f0/device/max_link_speed   # 5.0 GT/s PCIe  (PCIe 2.0)
cat /sys/class/net/enp33s0f0/device/max_link_width    # x8
ethtool -A enp33s0f0 rx off tx off                    # flow control off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn           # RSS spread
ethtool -G enp33s0f0 rx 8192
sysctl -w net.core.rmem_max=33554432 net.core.netdev_max_backlog=300000
for q in /sys/class/net/enp33s0f0/queues/rx-*/rps_cpus; do echo ff..ff > $q; done   # RPS all cores
cpupower frequency-set -g performance                 # governor (already performance)
ip neigh replace 10.10.20.2 lladdr <gen-mac> dev enp33s0f0 nud permanent
ss -ulpn | grep 10.10.20.1:53                         # rule 5: only runbound owns :53
runbound -c /etc/runbound/rb-single-noxdp.conf        # xdp:no, racing:yes, cache-min-ttl 3600, no local-data

# --- Generator (dragonsage, dual Xeon E5-2690 v2), dnsmark 2.1.3 ---
ethtool -A nic2 rx off tx off
ip neigh replace 10.10.20.1 lladdr <recv-mac> dev nic2 nud permanent
# warmup (two passes)
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 100000  -l 15
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 500000  -l 8  --max-outstanding 2000
# offered-load sweep (per step), source-port spread so receiver RSS fans out
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q <2e6..6e6> --max-outstanding 0 -l 12
# line-rate flood
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0 -l 26

# --- Throughput truth (receiver, sampled over the window) ---
ethtool -S enp33s0f0 | grep -wE 'rx_pkts_nic|tx_pkts_nic|rx_no_dma_resources|rx_missed_errors'
# --- Latency anchor (receiver wire) ---
tcpdump -i enp33s0f0 -nn -tt -c 120000 'udp port 53'   # pair request→response by DNS id
```
