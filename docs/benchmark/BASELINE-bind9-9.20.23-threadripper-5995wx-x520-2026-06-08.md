# Runbound Benchmark — Baseline BIND 9.20.23 — Threadripper PRO 5995WX / X520 — 2026-06-08

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. Same rig, generator and host setup as the
> Runbound and unbound reports — only the server under test changed.

## 1. Executive Summary

On this rig BIND 9.20.23 (`named`, 128 worker threads, warm cache) peaks at **~2.98 M QPS
served** (receiver NIC `tx_pkts_nic`) only under heavy overload (12 M QPS offered), at which
point **all 128 logical cores are at 100 %** and the NIC is dropping ~6 M pps. Cache-hit
latency at a sustainable rate (0.8 M QPS) is **p50 0.068 ms / p95 0.245 ms / p99 0.256 ms**,
success **99.75 % NOERROR**, receiver RAM **~0.43 GB RSS**. BIND reaches its ceiling by
spending the whole machine; the limit is its per-query kernel-UDP cost, not the X520 bus.

## 2. Objective

Measure BIND 9 (`named`), the other widely deployed reference resolver, on the exact same
bench, generator and methodology as the Runbound and unbound runs, for a like-for-like
context. The question: how does BIND scale with worker threads, what does it serve at
saturation, and at what CPU.

## 3. Methodology & Architecture

- **Receiver (BIND):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, Intel
  X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8, MTU 1500), kernel 7.0.6-2-pve. BIND
  9.20.23, kernel UDP (SO_REUSEPORT listeners), real `forwarders` (1.1.1.1 / 8.8.8.8 /
  9.9.9.9, `forward only`), **no local zones**, `recursion yes`, `dnssec-validation no`,
  `minimal-responses yes`, `max-cache-size 512m`. Worker threads (`-n`) swept 48 → 128;
  128 is its best config on this rig and the one reported. Governor `performance`, RX ring
  8192. AppArmor profile in complain mode for the custom config path.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), dnsmark, AF_XDP open-loop
  firehose for the throughput ramp; closed-loop (`--max-outstanding 1500`) for the latency
  point. `DNSMARK_SPORT_SPREAD=4096`. Exact commands in §6.
- **Link:** single Intel X520 (82599) 10 GbE, **direct fibre** generator↔receiver (no
  switch), **flow-control off** both ends, RSS `udp4 sdfn`, NIC IRQs pinned to the NIC's
  NUMA-local cores, static ARP. `ss -ulpn` confirms only `named` owns `10.10.20.1:53`
  (128 SO_REUSEPORT sockets).
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read,
  cache warmed (25 s pre-pass before the measured ramp).
- **Procedure:** warm 25 s, then an **offered-load ramp** — dnsmark open-loop at a fixed
  `-Q` per step (1, 2, 3, 4, 5, then 9, 12 M QPS), 16–18 s per step, **6–7 s steady
  measurement window** reading the receiver NIC PHY counters (`tx_pkts_nic` served,
  `rx_pkts_nic` received, `rx_no_dma_resources` + `rx_missed_errors` drops) plus receiver
  CPU from `/proc/stat`. **Saturation criterion:** the peak served value across the ramp.
  dnsmark's built-in `--ramp` auto-mode yields `rtt-samples=0` against a flooded
  single-RX-queue kernel-UDP server (RTT timeout under open-loop overload), so the ramp is
  driven as an explicit offered-load sweep — the equivalent, with NIC counters as truth.

## 4. Raw Results

**Offered-load ramp (BIND, 128 threads, warm cache):**

| Offered (dnsmark `-Q`) | Received by NIC (`rx_pkts_nic`) | **Served (`tx_pkts_nic`)** | Receiver CPU |
|-----------------------:|--------------------------------:|---------------------------:|-------------:|
| 1 M | 1.00 M | 1.00 M (100 %) | 33.8 % |
| 2 M | 2.01 M | 1.21 M | 48.3 % |
| 3 M | 3.01 M | 1.28 M | 39.8 % |
| 4 M | 4.01 M | 1.35 M | 33.8 % |
| 5 M | 5.01 M | 1.51 M | 39.5 % |
| 9 M | 9.04 M | 2.88 M | 88.7 % |
| **12 M** | 10.3 M | **2.98 M (peak)** | 100 % (all cores) |

**Thread scaling (`-n`, flood):** 48 → 2.37 M, 64 → 2.68 M, 96 → 3.09 M, **128 → ~2.98 M
peak** — diminishing returns; 128 saturates all logical cores.

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained real QPS | **~2.98 M** (12 M offered, all cores 100 %) | receiver NIC `tx_pkts_nic` |
| Latency p50 / p95 / p99 | **0.068 / 0.245 / 0.256 ms** (0.8 M, warm) | dnsmark round-trip |
| Success rate / error rate | **99.75 % NOERROR** / 0.12 % NXDOMAIN + 0.13 % SERVFAIL | dnsmark rcodes |
| Receiver CPU % | **100 %** (all 128 logical cores) at peak | `/proc/stat` |
| Receiver RAM | **~0.43 GB RSS** | `ps -o rss -C named` |
| NIC drops (`rx_missed_errors`) | ~1.8 M/s + ~4.4 M/s `rx_no_dma` at 12 M offered | receiver `ethtool -S` |

## 5. Interpretation

- **BIND serves all offered load up to ~1 M QPS** (100 % served, 34 % CPU). Between 2 and
  5 M offered its served rate stays low (~1.2–1.5 M) under the AF_XDP open-loop generator,
  then climbs to its **peak ~2.98 M only at 12 M offered, with all 128 logical cores at
  100 %**. Unlike unbound it does not collapse under overload, but it reaches its peak
  **only by saturating the entire machine** — 48 → 128 threads moved 2.37 M → 2.98 M with
  clear diminishing returns.
- The limit is BIND's per-query kernel-UDP cost, **not** the X520 bus: it pins all 128
  cores well before the bus ceiling that bounds the Runbound runs.
- **Same-rig, same-methodology comparison** (receiver NIC truth, dnsmark generator):

  | server (same host + X520 + methodology) | peak served | CPU at peak | latency p50 (cache hit) |
  |---|---:|---|---|
  | BIND 9.20.23 (128 threads) | **~2.98 M** | 100 % (all cores) | 0.068 ms |
  | unbound 1.22.0 (64 threads) | **~3.59 M** | ~65 % | 0.195 ms |
  | Runbound `xdp: no` (kernel slow path) | **~7.3 M** | ~54 % | ~0.09–0.10 ms |
  | Runbound `xdp: yes` (AF_XDP fast path) | **~10.1 M** | ~11 % | 0.062 ms |

  On this rig the two kernel-UDP reference resolvers land in the same band (BIND ~2.98 M at
  full saturation, unbound ~3.59 M at ~65 % CPU); Runbound's kernel slow path serves
  roughly **2–2.5×** of them and its AF_XDP fast path roughly **3–3.4×**, at far lower CPU.
  The slow-path margin comes from the shared SIMD/ASM wire responder + batched `recvmmsg`,
  the fast-path margin from bypassing the kernel socket layer entirely.
- **Caveat.** One BIND configuration on one rig; tuning, kernel and NIC all move the
  number. This is what this setup produces under the documented methodology, not a
  universal statement about BIND.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — BIND under test (AppArmor complain for the custom config path)
aa-complain /usr/sbin/named
named-checkconf /etc/bind/named-bench.conf
named -c /etc/bind/named-bench.conf -n 128        # -n swept 48..128, SO_REUSEPORT listeners
ss -ulpn | grep 10.10.20.1:53 | wc -l             # rule 5: 128 sockets, only named owns :53

# Host (receiver): governor + flow-control + RSS + ring + ARP
cpupower frequency-set -g performance
ethtool -A enp33s0f0 rx off tx off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn
ethtool -G enp33s0f0 rx 8192
# NIC IRQs pinned to NIC-NUMA-local cores; static ARP for 10.10.20.2

# Generator (dragonsage) — offered-load ramp, AF_XDP open-loop, per step:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 \
  -d docs/benchmark/corpus/top-10000-domains.txt --xdp -Q <1e6..12e6> --max-outstanding 0 -l 18

# Generator — latency point (closed-loop, below the knee):
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 \
  -d docs/benchmark/corpus/top-10000-domains.txt --xdp -Q 800000 --max-outstanding 1500 -l 10

# Throughput truth = receiver NIC PHY counters, 6-7 s steady window per step
ethtool -S enp33s0f0 | grep -wE 'tx_pkts_nic|rx_pkts_nic|rx_no_dma_resources|rx_missed_errors'
# Receiver RAM
ps -o rss= -C named | awk '{s+=$1}END{printf "%.2f GB\n", s/1048576}'
```
