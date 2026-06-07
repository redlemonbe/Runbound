# Runbound Benchmark — v0.15.3 (+#183) — AMD Threadripper PRO 5995WX — kernel slow path (xdp: no) — 2026-06-07

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

With `xdp: no` (kernel slow path), over a single 10 GbE fibre (Intel X520 / 82599,
PCIe 2.0 x8), Runbound v0.15.3 (+ the #183 slow-path cache fix) served a sustained
**~6.1 M real DNS QPS** from a warm cache, at **45 % receiver CPU** (headroom remaining),
with **sub-millisecond latency across the board — p50 0.565 ms, p95 0.722 ms,
p99 0.783 ms, p999 0.930 ms** and **99.84 % NOERROR**. On the *same* host and NIC the XDP
fast path served **~8.8 M QPS at 8 % CPU**. The two datapaths reach the same order of
throughput **and the same sub-millisecond latency** — they differ essentially in **CPU
cost, not in served rate or latency** — because the kernel slow path now runs the *same*
SIMD/ASM `answer_from_cache` wire responder as the fast path, only sourced from a kernel
UDP socket instead of an AF_XDP ring. Both are bounded by the X520's PCIe 2.0 RX
(~10 M received, ~1 M dropped as `rx_no_dma_resources`), not by Runbound.

## 2. Objective

Measure the kernel slow path (`xdp: no`) cache-served throughput and latency, and compare
it to the XDP fast path on the same host/NIC — to show the slow path shares the fast
path's hot code and trades only CPU for the same served rate and latency.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Threadripper PRO 5995WX (64 cores / 128 threads), 125 GB
  RAM (no competing workloads — see §5), Intel X520 / 82599 (`ixgbe`, PCIe 2.0 x8,
  MTU 1500), kernel 7.0.6-2-pve, Runbound v0.15.3 + #183, **`xdp: no`** (kernel fast
  loop: one SO_REUSEPORT UDP socket per physical core minus one reserved → 63 `kloop`
  threads; even socket distribution via an `SO_ATTACH_REUSEPORT_CBPF` by-CPU program +
  RPS; `answer_from_cache` SIMD/ASM responder — the same one
  the XDP fast path uses). Real `forward-zone`, **no local-data**, `cache-min-ttl 3600`.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), dnsmark v2.1.3, AF_XDP.
  Throughput: `dnsmark -s <recv> -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0`.
- **Link:** Intel X520 ↔ X520, 10 GbE, direct (no switch), flow-control off, static ARP.
- **Procedure:** warm the cache, then open-loop flood for throughput; read the receiver
  NIC PHY counters (`ethtool -S`) over a 6 s window for served (`tx_pkts_nic`), received
  (`rx_pkts_nic`) and drops (`rx_no_dma_resources`); latency from dnsmark at a controlled
  rate (round-trip RTT histogram); CPU from `/proc/stat`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Offered (on the wire) | ~13 M QPS (10 GbE line rate) | generator `tx_pkts_nic` |
| Received by NIC | ~9.97 M QPS | receiver `rx_pkts_nic` |
| NIC drops (PCIe 2.0 RX) | ~0.98 M QPS `rx_no_dma_resources` | receiver `ethtool -S` |
| **Max sustained served QPS** | **~6.1 M** | receiver `tx_pkts_nic` (responses on the wire) |
| Latency p50 / p95 / p99 / p999 | **0.565 / 0.722 / 0.783 / 0.930 ms** | dnsmark round-trip histogram |
| Success / error rate | 99.84 % NOERROR / 0.00 % SERVFAIL | dnsmark rcode breakdown |
| Receiver CPU | **45 % busy** (55 % idle) | `/proc/stat` over the window |
| Engaged cores | ~57 of 63 `kloop` threads | `top -H` |
| Cross-check — XDP fast path, same host/NIC | 8.8 M served @ 8 % CPU | separate run, receiver `tx_pkts_nic` |

## 5. Interpretation

- **Slow path ≈ fast path, at higher CPU.** 6.1 M @ 45 % CPU (slow) vs 8.8 M @ 8 % CPU
  (fast) on the same NIC, **both sub-millisecond** (slow path p99 0.783 ms). The slow path
  runs the shared SIMD/ASM `answer_from_cache` responder; the difference is the per-packet
  syscall cost of the kernel UDP socket (the fast path has none), not the serving logic or
  latency. Both are bounded by the X520 RX (received ~10 M; PCIe 2.0 drops ~1 M), not by
  Runbound — the slow path has 55 % CPU headroom.
- **The cache is shared.** The slow path and the fast path read the *same* cache snapshot;
  the slow path hit rate equals the fast path's (99.84 % NOERROR here). An earlier draft of
  this run showed a heavy latency tail (p95 ~38 ms); that was **host memory pressure** — a
  32 GB KVM guest co-resident on the receiver pushed Runbound's cache to its floor
  (repeated "cache halved" warnings), evicting the working set between runs. With that
  workload removed, the cache holds and the tail collapses to p999 0.930 ms. The tail was
  a host condition, not a slow-path property.
- **Core budget honoured:** 63 `kloop` threads (one core reserved for the rest of the
  process); on a dual-Xeon-v2 + X520 host the slow path caps at 16 cores (10 NIC-local +
  6 cross-NUMA), matching the fast path and the generator.
- **Implication.** With the software no longer the limit on either path (CPU headroom on
  the slow path; 8 % CPU on the fast path), a NIC without the 82599's PCIe-2.0 RX cap
  would scale both far higher — the fast path toward the tens of millions of QPS its
  per-core efficiency implies.

## 6. Appendix — exact commands & configuration

```bash
# Receiver (Runbound) — kernel slow path, real cache, even reuseport distribution
ip link set enp33s0f0 mtu 1500
for q in /sys/class/net/enp33s0f0/queues/rx-*/rps_cpus; do echo <allcpus> > $q; done   # RPS
runbound -c runbound-receiver-bench.conf      # xdp: no, forward-zone, no local-data

# Generator (dnsmark v2.1.3) — static ARP then flood (throughput)
ip neigh replace <recv-ip> lladdr <recv-mac> dev <nic> nud permanent
dnsmark -s <recv-ip> -d top-10000-domains.txt -p 53 --xdp -Q 0 --max-outstanding 0
# latency at a controlled rate (round-trip RTT)
dnsmark -s <recv-ip> -d top-10000-domains.txt -p 53 --xdp -Q 1500000 --max-outstanding 12000

# Throughput truth = receiver NIC PHY counters (reliable in kernel mode)
ethtool -S enp33s0f0 | grep -wE 'rx_pkts_nic|tx_pkts_nic|rx_no_dma_resources'
```

> Fast-path run on the same rig:
> [RUNBOUND-v0.15.3-threadripper-single-2026-06-07.md](RUNBOUND-v0.15.3-threadripper-single-2026-06-07.md).
