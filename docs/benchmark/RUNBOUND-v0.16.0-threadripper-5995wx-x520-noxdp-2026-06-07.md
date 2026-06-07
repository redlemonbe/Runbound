# Runbound Benchmark — v0.16.0 — AMD Threadripper PRO 5995WX — kernel slow path (`xdp: no`) — 2026-06-07

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

Over a single 10 GbE fibre (Intel X520 / 82599, PCIe 2.0 x8), Runbound v0.16.0 with
`xdp: no` (kernel slow path), warm cache, no local-data:

- **Served-rate ceiling (NIC truth): ~6.9 M QPS** at **~61 % receiver CPU**. The NIC
  receives ~10 M QPS and drops the excess (~5 M) in hardware (`rx_no_dma_resources` +
  `rx_missed_errors`, PCIe 2.0 RX limit).
- The receiver tracks offered load 1:1 up to ~3 M and then begins to drop: 4 M offered →
  3.89 M served, 5 M → 4.60 M, 6 M → 5.36 M.
- **dnsmark ramp** (the methodology's tool): the round-trip **p50 holds sub-millisecond
  up to ~6.4 M offered** (0.106 ms) with p95 ≈ 0.21 ms; the median crosses 1 ms around
  8.4 M offered (6.3 M on the wire). **Caveat:** at those steps only ~6 % of queries
  complete back at the generator — see §3/§5; that loss is dominated by the generator's
  single AF_XDP RX queue, not by the receiver, so the ramp p50 is computed over a
  survivorship sample and must be read together with the NIC served-rate, not alone.

The receiver was not CPU-bound at the ceiling (≥39 % idle). The hard limit is the X520
PCIe 2.0 RX path, not Runbound.

## 2. Objective

Measure the kernel slow path (`xdp: no`) throughput and latency under the methodology
(warmup + ramp), and compare back-to-back with the AF_XDP fast path on the same host and
NIC — only the `xdp:` config line differs. Companion:
[xdp](RUNBOUND-v0.16.0-threadripper-5995wx-x520-xdp-2026-06-07.md).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c / 128t), 125 GB RAM,
  Intel X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8 = 5.0 GT/s ×8 confirmed via sysfs,
  MTU 1500), kernel 7.0.6-2-pve, Runbound **v0.16.0**, **`xdp: no`**
  (`rb-single-noxdp.conf`: kernel fast loop, one SO_REUSEPORT UDP socket per physical core
  minus one reserved → 63 `kloop` threads; v0.16.0 `SO_ATTACH_REUSEPORT_CBPF` by-CPU
  spread + RPS; shared SIMD/ASM cache responder). `rate-limit: 0`, `cache-min-ttl: 3600`,
  `upstream-racing: yes`, real `forward-zone` (1.1.1.1 / 8.8.8.8 / 9.9.9.9, plain UDP),
  **no local-data**. Governor `performance`, RX ring 8192, RPS = all cores.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c / 40t, 2 NUMA), dnsmark 2.1.3,
  AF_XDP, source-port spread 4096 (`DNSMARK_SPORT_SPREAD=4096`) so the receiver's RSS fans
  flows across all rx queues.
- **Link:** X520 ↔ X520, 10 GbE, direct fibre, flow-control off both ends, RSS
  `rx-flow-hash udp4 sdfn`, static ARP both ways. Ping RTT 0.118 ms.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt`, warmed (two passes; 2nd pass
  99.86 % NOERROR).
- **Procedure:** **warmup, then `dnsmark --ramp`** (the methodology execution model:
  auto-scale + bisect to the highest step holding p50 < 1 ms). Two independent truths are
  recorded and cross-checked:
  1. **Latency** = the ramp's round-trip p50/p95/p99 (dnsmark timestamps at AF_XDP TX
     submit and RX completion).
  2. **Throughput** = receiver **NIC PHY counters** (`ethtool -S`: `rx_pkts_nic`,
     `tx_pkts_nic`, `rx_no_dma_resources`, `rx_missed_errors`) — measurement rule 1.
- **Two measurement limits, stated up front (rule: say so where a metric is uncertain):**
  - The ramp reports an **offered target**, not the wire rate. At the SLO step the target
    was ~8.4 M but the NIC PHY **wire egress was 6.3 M** — the generator could not actually
    send 8.4 M. The wire-egress figure is the real offered load.
  - The generator has a **single AF_XDP RX queue**, which caps the *observed* completion at
    a few hundred k/s. So "94–96 % lost" at the top steps is mostly answers the generator
    could not receive back, not answers the receiver failed to send. This biases the ramp
    p50 low (only completed queries are timed). Therefore the served rate is taken from the
    receiver NIC, not from the ramp's completion count.
  - A `tcpdump` latency anchor on the receiver was attempted but **discarded above ~3 M**:
    tcpdump cannot keep up at multi-million pps and its timestamps lag under overload,
    inflating latency. **I cannot confirm a reliable wire-anchored p50 at saturation** with
    the available tooling; the dnsmark round-trip (no-loss region) + NIC counters are used
    instead.

## 4. Raw Results

**A. Latency — `dnsmark --ramp` round-trip (offered = target rate):**

| Offered (target) | p50 | p95 | p99 |
|-----------------:|----:|----:|----:|
| 0.8 M | 0.116 ms | 0.151 ms | 8.30 ms |
| 1.6 M | 0.072 ms | 0.111 ms | 5.66 ms |
| 3.2 M | 0.103 ms | 0.234 ms | 7.40 ms |
| 6.4 M | **0.106 ms** | 0.206 ms | 5.97 ms |
| 8.4 M | 0.496 ms | 6.39 ms | 7.64 ms |
| ~9.6–12.8 M | 1.5–6.9 ms | — | — |

Ramp verdict: highest step holding p50 < 1 ms = ~8.4 M **target**; wire egress at that
step = **6.3 M** (NIC PHY). The p95/p99 tail across all steps is the ~0.14 % of names that
miss the cache and are forwarded to the real upstreams over the internet.

**B. Throughput — receiver NIC PHY counters (truth):**

| Offered | Received (NIC) | **Served (NIC)** | NIC drops | Receiver CPU |
|--------:|---------------:|-----------------:|----------:|-------------:|
| 2.0 M | 2.01 M | 2.00 M | 0 | 23 % |
| 3.0 M | 3.01 M | 3.01 M | 0 | 31 % |
| 4.0 M | 4.03 M | 3.89 M | 0 | 36 % |
| 5.0 M | 5.04 M | 4.60 M | 0 | 43 % |
| 6.0 M | 6.04 M | 5.36 M | ~3 k | 50 % |
| flood (~10 M) | ~10.0 M | **~6.9 M** | ~5.0 M | 61 % |

| Metric | Value | Source |
|--------|-------|--------|
| Served-rate ceiling | **~6.9 M** (band 6.7–7.0 M) | receiver `tx_pkts_nic` |
| Highest offered with no receiver drop | ~3 M (served = offered) | receiver `tx_pkts_nic` |
| Latency, no-loss region (ramp) | p50 0.07–0.11 ms (≤6.4 M target) | dnsmark round-trip |
| Success / error rate | 99.86 % NOERROR / ~0.01 % SERVFAIL | dnsmark rcodes |
| Receiver CPU at ceiling | ~61 % busy (≥39 % idle) | `/proc/stat` |
| NIC drops at flood | ~2 M `rx_no_dma_resources` + ~3 M `rx_missed_errors` | `ethtool -S` |
| Wire-anchored p50 at saturation | I cannot confirm this (tcpdump unreliable under overload) | — |

## 5. Interpretation

- **NIC-bound, not CPU-bound.** At the ceiling the NIC receives ~10 M and drops ~5 M in
  hardware (PCIe 2.0 x8 RX); served plateaus at ~6.9 M while the CPU is ~61 % (≥39 % idle).
  The limit is the X520 receive path, not Runbound's serving logic.
- **Read the ramp and the NIC together.** The ramp's sub-ms p50 up to ~6.4 M target is
  real *for the queries that complete*, but completion is throttled by the generator's
  single AF_XDP RX queue, so the ramp alone overstates the sustainable point. The NIC
  counters show the receiver itself starts dropping above ~3 M offered (4 M → 3.89 M
  served), so the genuinely loss-free, sub-ms region is ~3–4 M served; beyond that the
  receiver still serves more (up to ~6.9 M) but with drops.
- **The tail is forwarding, not serving.** p50 (cache hits) is sub-ms in the no-loss
  region; p95/p99 are dominated by the ~0.14 % cache-miss names forwarded to real upstreams
  (tens to hundreds of ms). This is why the median is the SLO signal.
- **Flow distribution is a setup variable.** A single source flow served only ~0.49 M at
  12 % CPU (one rx queue / one core); RSS `sdfn` + generator source-port spread + RPS +
  the v0.16.0 by-CPU cBPF reuseport raised it to ~6.9 M. Reported for reproducibility.
- **Back-to-back vs fast path.** On the same host/NIC the AF_XDP fast path served ~10.1 M
  at ~21 % CPU with zero drops below NIC line rate (companion report). The slow path shares
  the same cache responder but pays a per-packet kernel-UDP syscall: lower ceiling, ~3×
  the CPU, earlier onset of drops. Both are bounded by the X520 PCIe 2.0 RX. The headroom
  on a NIC without that cap — **I cannot confirm this** without such hardware.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (dragonrage, AMD 5995WX) ---
cat /sys/class/net/enp33s0f0/device/max_link_speed   # 5.0 GT/s PCIe (PCIe 2.0); width x8
ethtool -A enp33s0f0 rx off tx off                    # flow control off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn           # RSS spread
ethtool -G enp33s0f0 rx 8192
for q in /sys/class/net/enp33s0f0/queues/rx-*/rps_cpus; do echo ff..ff > $q; done   # RPS
cpupower frequency-set -g performance
ip neigh replace 10.10.20.2 lladdr <gen-mac> dev enp33s0f0 nud permanent
ss -ulpn | grep 10.10.20.1:53                         # rule 5: only runbound owns :53
runbound -c /etc/runbound/rb-single-noxdp.conf        # xdp:no, racing:yes, cache-min-ttl 3600, no local-data

# --- Generator (dragonsage, dual Xeon E5-2690 v2), dnsmark 2.1.3 ---
ethtool -A nic2 rx off tx off
ip neigh replace 10.10.20.1 lladdr <recv-mac> dev nic2 nud permanent
# warmup
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 100000 -l 15
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 500000 -l 8 --max-outstanding 2000
# RAMP (methodology execution model) — with source-port spread so RSS fans out
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp --ramp --max-outstanding 0
# NIC served-vs-offered cross-check (per offered step)
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q <2e6..6e6> --max-outstanding 0 -l 12

# --- Throughput truth (receiver, sampled over the window) ---
ethtool -S enp33s0f0 | grep -wE 'rx_pkts_nic|tx_pkts_nic|rx_no_dma_resources|rx_missed_errors'
```
