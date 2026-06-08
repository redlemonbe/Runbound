# Runbound Benchmark — Baseline unbound 1.22.0 — Threadripper PRO 5995WX / X520 — 2026-06-08

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. Same rig, same generator, same host setup as
> the Runbound `xdp:no` / `xdp:yes` reports — only the server under test changed.

## 1. Executive Summary

On this rig unbound 1.22.0 (64 worker threads, warm cache) sustains a peak of **~3.59 M
QPS served** (receiver NIC `tx_pkts_nic`) at **6 M QPS offered load and ~65 % receiver
CPU**; pushed past that knee it falls into congestive collapse (9 M offered → 2.78 M
served). Cache-hit latency at a sustainable rate (0.8 M QPS) is **p50 0.195 ms / p95
0.253 ms / p99 0.257 ms**, success **99.74 % NOERROR**, receiver RAM **~0.48 GB RSS**. The
ceiling is unbound's per-query kernel-UDP cost, reached well below the X520 PCIe-2.0 RX
limit that bounds the Runbound runs.

## 2. Objective

Measure unbound — the resolver Runbound is a drop-in replacement for — on the exact same
bench, generator and methodology as the Runbound runs, so the Runbound numbers sit in a
like-for-like context against a widely deployed reference resolver. The question: at what
offered load does unbound saturate, what does it serve at the knee, and at what CPU.

## 3. Methodology & Architecture

- **Receiver (unbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, Intel
  X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8, MTU 1500), kernel 7.0.6-2-pve. unbound
  1.22.0, kernel UDP, `so-reuseport: yes`, real `forward-zone` (1.1.1.1 / 8.8.8.8 /
  9.9.9.9, plain), **no local-data**, `ratelimit: 0`, `qname-minimisation: no`,
  `prefetch: no`, msg-cache 256 MB / rrset-cache 512 MB, `num-queries-per-thread 8192`.
  `num-threads` swept 16 → 64; 64 is its best config on this rig and the one reported.
  Governor `performance`, RX ring 8192. AppArmor profile in complain mode for the custom
  config path.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), dnsmark, AF_XDP
  open-loop firehose for the throughput ramp; closed-loop (`--max-outstanding 1500`) for
  the latency point. `DNSMARK_SPORT_SPREAD=4096`. Exact commands in §6.
- **Link:** single Intel X520 (82599) 10 GbE, **direct fibre** generator↔receiver (no
  switch), **flow-control off** both ends, RSS `udp4 sdfn`, NIC IRQs pinned to the NIC's
  NUMA-local cores, static ARP. `ss -ulpn` confirms only unbound owns `10.10.20.1:53`
  (64 SO_REUSEPORT sockets).
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read,
  cache warmed (25 s pre-pass before the measured ramp).
- **Procedure:** warm 25 s, then an **offered-load ramp** — dnsmark open-loop at a fixed
  `-Q` per step (1, 2, 3, 4, 5, 6, then 9 M QPS), 16 s per step, **6 s steady measurement
  window** reading the receiver NIC PHY counters (`tx_pkts_nic` served, `rx_pkts_nic`
  received, `rx_no_dma_resources` + `rx_missed_errors` drops) plus receiver CPU from
  `/proc/stat`. **Saturation criterion:** the step where served stops tracking offered
  (knee); the peak served value across the ramp is the reported maximum. dnsmark's built-in
  `--ramp` auto-mode yields `rtt-samples=0` against a flooded single-RX-queue kernel-UDP
  server (RTT timeout under open-loop overload), so the ramp is driven as an explicit
  offered-load sweep instead — the equivalent, with NIC counters as truth.

## 4. Raw Results

**Offered-load ramp (unbound, 64 threads, warm cache):**

| Offered (dnsmark `-Q`) | Received by NIC (`rx_pkts_nic`) | **Served (`tx_pkts_nic`)** | Receiver CPU |
|-----------------------:|--------------------------------:|---------------------------:|-------------:|
| 1 M | 1.00 M | 1.00 M (100 %) | 17.9 % |
| 2 M | 2.00 M | 1.61 M | 38.4 % |
| 3 M | 3.01 M | 2.33 M | 47.8 % |
| 4 M | 4.01 M | 3.00 M | 55.1 % |
| 5 M | 6.56 M | 3.44 M | 65.3 % |
| **6 M** | 6.02 M | **3.59 M (peak)** | 65.2 % |
| 9 M (overload) | 10.9 M | 2.78 M (collapse) | 64.4 % |

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained real QPS | **~3.59 M** (6 M offered, knee) | receiver NIC `tx_pkts_nic` |
| Latency p50 / p95 / p99 | **0.195 / 0.253 / 0.257 ms** (0.8 M, warm) | dnsmark round-trip |
| Success rate / error rate | **99.74 % NOERROR** / 0.13 % NXDOMAIN + 0.13 % SERVFAIL | dnsmark rcodes |
| Receiver CPU % | **~65 %** at peak served | `/proc/stat` |
| Receiver RAM | **~0.48 GB RSS** | `ps -o rss -C unbound` |
| NIC drops (`rx_missed_errors`) | ~3.5 M/s + ~5.4 M/s `rx_no_dma` at overload | receiver `ethtool -S` |

## 5. Interpretation

- **unbound serves all offered load up to ~1 M QPS** (100 % served, 18 % CPU), then served
  falls progressively behind offered as its per-query kernel-UDP cost dominates. **Peak
  served ≈ 3.59 M QPS at 6 M offered and ~65 % CPU.** Beyond the knee it shows **congestive
  collapse** — 9 M offered yields *less* served (2.78 M) than 6 M, the classic open-loop
  overload signature.
- The limit is unbound's own per-query cost, **not** the X520 bus: at the knee the NIC is
  receiving only ~6 M pps (well under the ~10.7 M PCIe-2.0 RX cap that bounds the Runbound
  runs) and the receiver still has CPU headroom. unbound hits its software ceiling first.
- **Same-rig, same-methodology comparison** (receiver NIC truth, dnsmark generator):

  | server (same host + X520 + methodology) | peak served | CPU at peak | latency p50 (cache hit) |
  |---|---:|---|---|
  | unbound 1.22.0 (64 threads) | **~3.59 M** | ~65 % | 0.195 ms |
  | BIND 9.20.23 (128 threads) | **~2.98 M** | 100 % (all cores) | 0.068 ms |
  | Runbound `xdp: no` (kernel slow path) | **~7.3 M** | ~54 % | ~0.09–0.10 ms |
  | Runbound `xdp: yes` (AF_XDP fast path) | **~10.1 M** | ~11 % | 0.062 ms |

  On this rig Runbound's kernel slow path serves roughly **2×** unbound and its AF_XDP fast
  path roughly **2.8×**, at lower latency and with large CPU headroom — the slow-path margin
  from the shared SIMD/ASM wire responder + batched `recvmmsg`, the fast-path margin from
  bypassing the kernel socket layer. unbound and Runbound `xdp:no` both run on kernel UDP;
  the gap is the per-query work, not the transport.
- **Caveat.** One unbound configuration on one rig; unbound tuning, kernel version and NIC
  all move the number. This is what this setup produces under the documented methodology,
  not a universal statement about unbound.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — unbound under test (AppArmor complain for the custom config path)
aa-complain /usr/sbin/unbound
unbound-checkconf /etc/unbound/unbound-bench.conf
unbound -c /etc/unbound/unbound-bench.conf        # num-threads swept 16..64, so-reuseport yes
ss -ulpn | grep 10.10.20.1:53 | wc -l             # rule 5: 64 sockets, only unbound owns :53

# Host (receiver): governor + flow-control + RSS + ring + ARP
cpupower frequency-set -g performance
ethtool -A enp33s0f0 rx off tx off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn
ethtool -G enp33s0f0 rx 8192
# NIC IRQs pinned to NIC-NUMA-local cores; static ARP for 10.10.20.2

# Generator (dragonsage) — offered-load ramp, AF_XDP open-loop, per step:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 \
  -d docs/benchmark/corpus/top-10000-domains.txt --xdp -Q <1e6..9e6> --max-outstanding 0 -l 16

# Generator — latency point (closed-loop, below the knee):
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 \
  -d docs/benchmark/corpus/top-10000-domains.txt --xdp -Q 800000 --max-outstanding 1500 -l 10

# Throughput truth = receiver NIC PHY counters, 6 s steady window per step
ethtool -S enp33s0f0 | grep -wE 'tx_pkts_nic|rx_pkts_nic|rx_no_dma_resources|rx_missed_errors'
# Receiver RAM
ps -o rss= -C unbound | awk '{s+=$1}END{printf "%.2f GB\n", s/1048576}'
```
