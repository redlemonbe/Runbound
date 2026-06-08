# Runbound Benchmark — v0.16.1 — AMD Threadripper PRO 5995WX — kernel slow path (`xdp: no`) — 2026-06-07

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

Over a single 10 GbE fibre (Intel X520 / 82599, PCIe 2.0 x8), Runbound v0.16.1 with
`xdp: no` (kernel slow path, batched `recvmmsg` receive), warm cache, no local-data:

- **Served-rate ceiling (NIC truth): ~7.3 M QPS** at flood. The NIC receives ~10 M QPS
  and drops the excess (~4.6 M) in hardware (`rx_no_dma_resources` + `rx_missed_errors`,
  PCIe 2.0 RX limit).
- The receiver tracks offered load 1:1 to ~3 M, then drops a growing fraction: 5 M
  offered → 4.63 M served (43 % CPU), 7 M → 6.16 M (54 % CPU).
- **dnsmark ramp** round-trip **p50 sub-millisecond up to ~6.4 M offered** (0.089 ms),
  knee at ~8.8 M *target* / 6.35 M on the wire.

v0.16.1 re-introduces the `recvmmsg` batch (reverted in v0.16.0) with `MSG_WAITFORONE`
so single queries still return immediately: same served rate as per-packet `recv_from`
but ~⅓ fewer saturated cores, and the flood ceiling rises from ~6.9 M to ~7.3 M. The
hard limit is the NIC's NAPI poll saturating its 8 NUMA-local cores (see §5), not
Runbound.

## 2. Objective

Measure the kernel slow path (`xdp: no`) throughput and latency under the methodology
(warmup + ramp), back-to-back with the AF_XDP fast path on the same host and NIC — only
the `xdp:` line differs. Companion:
[xdp](RUNBOUND-v0.16.1-threadripper-5995wx-x520-xdp-2026-06-07.md).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c / 128t, 8 NUMA nodes /
  NPS4), 125 GB RAM, Intel X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8 = 5.0 GT/s ×8,
  on **NUMA node 4 = cores 32-39**), kernel 7.0.6-2-pve, Runbound **v0.16.1**,
  **`xdp: no`** (`rb-single-noxdp.conf`: kernel fast loop, one SO_REUSEPORT UDP socket per
  physical core minus one reserved → 63 `kloop` threads; **batched `recvmmsg`** drain
  (`MSG_WAITFORONE`); `SO_ATTACH_REUSEPORT_CBPF` by-CPU spread; shared SIMD/ASM responder).
  `rate-limit: 0`, `cache-min-ttl: 3600`, `upstream-racing: yes`, real `forward-zone`
  (1.1.1.1 / 8.8.8.8 / 9.9.9.9), **no local-data**. Governor `performance`, RX ring 8192.
- **Host tuning:** NIC IRQs on the NIC's NUMA node (cores 32-39 + SMT 96-103, irqbalance
  off); **RPS = all cores** (required — see §5); `rx-usecs 25`.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c / 40t, 2 NUMA), dnsmark 2.1.3,
  AF_XDP, source-port spread 4096 (`DNSMARK_SPORT_SPREAD=4096`).
- **Link:** X520 ↔ X520, 10 GbE, direct fibre, flow-control off both ends, RSS
  `rx-flow-hash udp4 sdfn`, static ARP both ways. Ping RTT 0.118 ms.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, warmed (two passes).
- **Procedure:** **warmup, then `dnsmark --ramp`** (methodology execution model). Two
  truths cross-checked: (1) latency = ramp round-trip p50/p95/p99; (2) throughput =
  receiver **NIC PHY counters** (`ethtool -S`). Same two stated limits as the fast-path
  report: the ramp "offered" is a target (wire egress is the real load), and the
  generator's single AF_XDP RX queue caps observed completion, so the ramp p50 is a
  survivorship sample read together with the NIC served-rate, not alone. A receiver-side
  `tcpdump` latency anchor is unreliable above ~3 M (tcpdump cannot keep up at multi-million
  pps); **I cannot confirm a wire-anchored p50 at saturation**.

## 4. Raw Results

**A. Latency — `dnsmark --ramp` round-trip (offered = target rate):**

| Offered (target) | p50 | p95 | p99 |
|-----------------:|----:|----:|----:|
| 1.6 M | 0.076 ms | 0.125 ms | 3.88 ms |
| 3.2 M | 0.065 ms | 0.154 ms | 4.76 ms |
| 6.4 M | **0.089 ms** | 0.158 ms | 4.44 ms |
| 8.0 M | 0.139 ms | 3.80 ms | 7.59 ms |
| ~8.8 M+ | >1 ms | — | — |

Highest step holding p50 < 1 ms = ~8.8 M target; wire egress there ≈ 6.35 M. p95/p99 tail
= the ~0.14 % cache-miss names forwarded to the real upstreams.

**B. Throughput — receiver NIC PHY counters (truth):**

| Offered | Received (NIC) | **Served (NIC)** | NIC drops | Receiver CPU |
|--------:|---------------:|-----------------:|----------:|-------------:|
| 2.0 M | 2.00 M | 2.00 M | 0 | 21 % |
| 4.0 M | 4.01 M | 3.88 M | 0 | 37 % |
| 5.0 M | 5.01 M | 4.63 M | 0 | 43 % |
| 6.0 M | 6.02 M | 5.42 M | 0 | 48 % |
| 7.0 M | 7.02 M | 6.16 M | 0 | 54 % |
| flood (~10 M) | ~10.1 M | **~7.3 M** | ~4.6 M | 70 of 72 cores >90 % |

| Metric | Value | Source |
|--------|-------|--------|
| Served-rate ceiling | **~7.3 M** | receiver `tx_pkts_nic` |
| Highest offered with no receiver drop | ~3 M | receiver `tx_pkts_nic` |
| Latency, no-loss region (ramp) | p50 0.065–0.089 ms (≤6.4 M) | dnsmark round-trip |
| Success / error rate | 99.86 % NOERROR | dnsmark rcodes |
| Receiver CPU at 7 M offered | 54 % | `/proc/stat` |
| NIC drops at flood | ~1.6 M `rx_no_dma_resources` + ~3.0 M `rx_missed_errors` | `ethtool -S` |
| Wire-anchored p50 at saturation | I cannot confirm this | — |

## 5. Interpretation

- **The wall is the NIC's NAPI poll on its 8 NUMA-local cores.** Under load `mpstat`
  shows cores 32-39 (NUMA node 4, where the X520 sits and all 64 rx IRQs are pinned) at
  **100 % softirq**. RPS spreads the *serving* off these cores (turning RPS off drops the
  rate to ~3 M), but the driver NAPI poll itself cannot leave the IRQ cores, so reception
  is bounded by ~8 cores ≈ 7 M pps. This was isolated by direct test:
  - source-port spread 4096 vs primes 4099 / 65521 → identical (no Toeplitz/modulo aliasing);
  - `SO_ATTACH_REUSEPORT_CBPF` on vs off → identical (not the cBPF);
  - interrupt coalescing `rx-usecs` 1 → 500 → no change (NAPI busy-polls under load, never
    returning to the interrupt path);
  - spreading IRQs off the NIC's NUMA node → worse (cross-NUMA penalty, flood ~4.9 M).
  The remaining loss below flood (e.g. 7 M offered → 6.16 M served, with 0 NIC drops) is
  `UdpRcvbufErrors` on those saturated cores, not a NIC drop and not a Runbound logic bug.
- **recvmmsg helps, within that wall.** Batched receive (`MSG_WAITFORONE`) drains the
  socket in one syscall per N datagrams: same served rate at ~⅓ fewer saturated cores
  (back-to-back @7 M: ~13 vs ~22 cores >90 %), and the flood ceiling rises ~6.9 M → ~7.3 M.
  Single-query latency is preserved (`dig` answers immediately), so no functionality is lost.
- **Lifting the wall needs hardware/topology, not code.** A NIC on a NUMA node with more
  cores, NPS1 (single NUMA node → IRQs spreadable to all cores without cross-NUMA cost), or
  a card with a more efficient datapath (PCIe 3.0, e.g. X710) would raise reception past
  ~8 cores. The magnitude on such hardware — **I cannot confirm this** from this rig.
- **Back-to-back vs fast path.** On the same host/NIC the AF_XDP fast path served ~10.1 M
  at ~11 % CPU with zero drops below NIC line rate. The fast path processes in NAPI context
  without the socket layer, so it is not bound by the per-socket drain the slow path pays.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (the receiver host, AMD 5995WX) ---
ethtool -A enp33s0f0 rx off tx off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn
ethtool -G enp33s0f0 rx 8192
ethtool -C enp33s0f0 rx-usecs 25
for q in /sys/class/net/enp33s0f0/queues/rx-*/rps_cpus; do echo ff..ff > $q; done   # RPS (required)
# NIC IRQs on the NIC's NUMA node (here node4 = 32-39,96-103); irqbalance off
for irq in $(grep enp33s0f0 /proc/interrupts|awk '{print $1}'|tr -d :); do echo 32-39,96-103 > /proc/irq/$irq/smp_affinity_list; done
cpupower frequency-set -g performance
runbound -c /etc/runbound/rb-single-noxdp.conf      # v0.16.1, recvmmsg (RUNBOUND_NO_RECVMMSG=1 disables)

# --- Generator (the generator host, dual Xeon E5-2690 v2), dnsmark 2.1.3 ---
ethtool -A nic2 rx off tx off
ip neigh replace 10.0.0.1 lladdr <recv-mac> dev nic2 nud permanent
dnsmark -s 10.0.0.1 -p 53 -d top-10000-domains.txt --xdp -Q 100000 -l 15       # warm
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.0.0.1 -p 53 -d top-10000-domains.txt --xdp --ramp --max-outstanding 0
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.0.0.1 -p 53 -d top-10000-domains.txt --xdp -Q <2e6..7e6> --max-outstanding 0 -l 12

# --- Throughput truth (receiver) ---
ethtool -S enp33s0f0 | grep -wE 'rx_pkts_nic|tx_pkts_nic|rx_no_dma_resources|rx_missed_errors'
# --- Reception wall evidence ---
mpstat -P 32-39 1 1        # 100% %soft on the NIC's NUMA-local cores under load
nstat -az | grep UdpRcvbufErrors
```
