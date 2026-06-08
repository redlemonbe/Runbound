# Baseline — unbound 1.22.0 under the same methodology (dnsmark, single X520)

> Follows [README.md](README.md). Measured data only; truth is the receiver NIC hardware
> counters, not the generator's round-trip. Same rig, same generator, same host setup as
> the Runbound `xdp:no` / `xdp:yes` reports — only the server under test changed.

## 1. Objective

Measure **unbound** (the server Runbound is a drop-in replacement for) on the exact same
bench, generator and methodology as the Runbound runs, to put Runbound's numbers in
context against a well-known reference resolver.

## 2. Methodology & Architecture

- **Receiver (server under test):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB
  RAM, Intel X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8, MTU 1500), kernel 7.0.6-2-pve.
  **unbound 1.22.0**, kernel UDP, `so-reuseport: yes`, real `forward-zone` (1.1.1.1 /
  8.8.8.8 / 9.9.9.9, plain), **no local-data**, `cache-min-ttl 3600`, `ratelimit: 0`,
  `qname-minimisation: no`, `prefetch: no`, msg-cache 256 MB / rrset-cache 512 MB,
  `num-queries-per-thread 8192`. `num-threads` swept (16 → 64).
- **Host setup (identical to the Runbound runs):** governor `performance`, flow-control
  off, RSS `udp4 sdfn`, NIC IRQs on the NIC's NUMA-local cores, RX ring 8192, static ARP,
  `ss -ulpn` confirms only unbound owns `:53`.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), dnsmark, AF_XDP open-loop
  firehose, source-port spread 4096.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt`, cache warmed (2 passes; 99.74 %
  NOERROR, p50 0.194 ms warm).
- **Procedure:** warm, then open-loop flood; **truth = receiver NIC PHY counters**
  (`tx_pkts_nic` served, `rx_pkts_nic` received, `rx_no_dma_resources` + `rx_missed_errors`
  drops) over the steady window; receiver CPU from `/proc/stat`.

## 3. Raw Results

**unbound thread scaling (flood, ~10 M offered on the wire):**

| `num-threads` | **Served (NIC `tx_pkts_nic`)** | cores >90 % |
|--------------:|-------------------------------:|------------:|
| 16 | 1.12 M | 18 |
| 32 | 2.79 M | 31 |
| 48 | 3.43 M | 33 |
| **64** | **~3.68 M** | 28 (90 cores >50 %) |

| Metric | Value | Source |
|--------|-------|--------|
| **Max served (best config, 64 threads)** | **~3.68 M QPS** | receiver `tx_pkts_nic` |
| Received by NIC at flood | ~9.6 M QPS | receiver `rx_pkts_nic` |
| NIC drops at flood | ~5.4 M `rx_no_dma` + ~3.5 M `rx_missed` | receiver `ethtool -S` |
| Latency (cache hits, warm, ~500 k) | p50 **0.194 ms**, p99 0.257 ms | dnsmark round-trip |
| Success rate | 99.74 % NOERROR | dnsmark rcodes |
| Served at 2 M offered | 1.69 M (38.8 % CPU) — already dropping | receiver `tx_pkts_nic` |

## 4. Interpretation

- **unbound scales with `num-threads` and plateaus at ~3.68 M served** on this rig (64
  threads; 16 → 64 threads moved 1.12 M → 3.68 M with diminishing returns). It engages most
  of the 128 logical cores at the plateau. Like every server on this rig it is ultimately
  bounded by the X520 PCIe 2.0 RX and by the NIC's NUMA-local reception cores, but unbound's
  per-query kernel-UDP cost places its ceiling well below that bus limit.
- **Same-rig, same-methodology comparison** (receiver NIC truth, dnsmark generator):

  | server (same host + X520 + methodology) | max served | latency (cache hit) |
  |---|---:|---|
  | unbound 1.22.0 (64 threads) | **~3.68 M** | p50 0.194 ms |
  | Runbound `xdp: no` (kernel slow path) | **~7.3 M** | p50 ~0.09–0.10 ms |
  | Runbound `xdp: yes` (AF_XDP fast path) | **~10.1 M** | p50 0.062 ms |

  On this rig Runbound's kernel slow path serves roughly **2×** unbound, and its AF_XDP
  fast path roughly **2.7×**, at lower latency — the slow-path margin comes from the shared
  SIMD/ASM wire responder + batched `recvmmsg`, the fast-path margin from bypassing the
  kernel socket layer entirely. All three plateau under the same X520 PCIe-2.0 RX ceiling;
  a NIC without that cap would raise all three.
- **Caveat.** This is one configuration of unbound on one rig; unbound tuning, kernel
  version and NIC all move the number. The figure is what this setup produces under the
  documented methodology, not a universal statement about unbound.

## 5. Appendix — exact commands

```bash
# Receiver — unbound under test (AppArmor profile in complain mode for the custom config)
aa-complain /usr/sbin/unbound
unbound-checkconf /etc/unbound/unbound-bench.conf
unbound -c /etc/unbound/unbound-bench.conf       # num-threads swept 16..64, so-reuseport yes
ss -ulpn | grep 10.10.20.1:53                     # rule 5: only unbound owns :53

# Generator (dragonsage) — dnsmark, AF_XDP open-loop
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0 -l 20

# Throughput truth = receiver NIC PHY counters
ethtool -S enp33s0f0 | grep -wE 'tx_pkts_nic|rx_pkts_nic|rx_no_dma_resources|rx_missed_errors'
```
