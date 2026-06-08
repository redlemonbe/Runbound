# Baseline — BIND 9.20.23 under the same methodology (dnsmark, single X520)

> Follows [README.md](README.md). Measured data only; truth is the receiver NIC hardware
> counters, not the generator's round-trip. Same rig, generator and host setup as the
> Runbound and unbound reports — only the server under test changed.

## 1. Objective

Measure **BIND 9** (named), the other widely deployed reference resolver, on the exact same
bench, generator and methodology as the Runbound and unbound runs, for a like-for-like
context.

## 2. Methodology & Architecture

- **Receiver (server under test):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB
  RAM, Intel X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8, MTU 1500), kernel 7.0.6-2-pve.
  **BIND 9.20.23**, kernel UDP (SO_REUSEPORT listeners), real `forwarders` (1.1.1.1 /
  8.8.8.8 / 9.9.9.9, `forward only`), **no local zones**, `recursion yes`,
  `dnssec-validation no`, `minimal-responses yes`, `max-cache-size 512m`. Worker threads
  (`-n`) swept 48 → 128.
- **Host setup (identical to the other runs):** governor `performance`, flow-control off,
  RSS `udp4 sdfn`, NIC IRQs on the NIC's NUMA-local cores, RX ring 8192, static ARP;
  `ss -ulpn` confirms only named owns `:53`.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), dnsmark, AF_XDP open-loop
  firehose, source-port spread 4096.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, cache warmed (2 passes; 99.79 %
  NOERROR, p50 0.192 ms warm).
- **Procedure:** warm, then open-loop flood; **truth = receiver NIC PHY counters**
  (`tx_pkts_nic` served, `rx_pkts_nic` received, `rx_no_dma_resources` + `rx_missed_errors`
  drops) over the steady window; receiver CPU from `/proc/stat`.

## 3. Raw Results

**BIND thread scaling (`-n`, flood ~10 M offered on the wire):**

| `-n` (worker threads) | **Served (NIC `tx_pkts_nic`)** | cores >90 % |
|----------------------:|-------------------------------:|------------:|
| 48 | 2.37 M | 32 |
| 64 | 2.68 M | 57 |
| 96 | 3.09 M | 95 |
| **128** | **~3.39 M** | **128 (all saturated)** |

| Metric | Value | Source |
|--------|-------|--------|
| **Max served (best config, `-n 128`)** | **~3.39 M QPS** | receiver `tx_pkts_nic` |
| Received by NIC at flood | ~9.9 M QPS | receiver `rx_pkts_nic` |
| NIC drops at flood | ~3.0 M `rx_no_dma` + ~3.2 M `rx_missed` | receiver `ethtool -S` |
| Latency (cache hits, warm, ~500 k) | p50 **0.192 ms**, p99 0.257 ms | dnsmark round-trip |
| Success rate | 99.79 % NOERROR | dnsmark rcodes |
| CPU at max | all 128 logical cores ≥ 90 % | `/proc/stat` |

## 4. Interpretation

- **BIND scales with `-n` and plateaus at ~3.39 M served**, but only by saturating **all
  128 logical cores** (48 → 128 threads moved 2.37 M → 3.39 M with diminishing returns).
  Its kernel-UDP per-query cost is the limit well before the X520 bus; it spends the whole
  machine to reach this rate.
- **Same-rig, same-methodology comparison** (receiver NIC truth, dnsmark generator):

  | server (same host + X520 + methodology) | max served | cores at max | latency (cache hit) |
  |---|---:|---|---|
  | BIND 9.20.23 | **~3.39 M** | 128 (all) | p50 0.192 ms |
  | unbound 1.22.0 | **~3.68 M** | 64 | p50 0.194 ms |
  | Runbound `xdp: no` (kernel slow path) | **~7.3 M** | ~70 | p50 ~0.09–0.10 ms |
  | Runbound `xdp: yes` (AF_XDP fast path) | **~10.1 M** | ~31 | p50 0.062 ms |

  On this rig the two kernel-UDP reference resolvers land close together (BIND ~3.39 M,
  unbound ~3.68 M); Runbound's kernel slow path serves roughly **2×** of them and its
  AF_XDP fast path roughly **2.7–3×**, at lower latency and far fewer engaged cores. The
  slow-path margin comes from the shared SIMD/ASM wire responder + batched `recvmmsg`; the
  fast-path margin from bypassing the kernel socket layer entirely. All four plateau under
  the same X520 PCIe-2.0 RX ceiling on this rig.
- **Caveat.** One BIND configuration on one rig; tuning, kernel and NIC all move the
  number. This is what this setup produces under the documented methodology, not a
  universal statement about BIND.

## 5. Appendix — exact commands

```bash
# Receiver — BIND under test
named-checkconf /etc/bind/named-bench.conf
named -c /etc/bind/named-bench.conf -n 128       # -n swept 48..128, SO_REUSEPORT listeners
ss -ulpn | grep 10.10.20.1:53                     # rule 5: only named owns :53

# Generator (dragonsage) — dnsmark, AF_XDP open-loop
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0 -l 20

# Throughput truth = receiver NIC PHY counters
ethtool -S enp33s0f0 | grep -wE 'tx_pkts_nic|rx_pkts_nic|rx_no_dma_resources|rx_missed_errors'
```
