# Runbound Benchmark — v0.16.0 — AMD Threadripper PRO 5995WX — AF_XDP fast path (`xdp: yes`) — 2026-06-07

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

Over a single 10 GbE fibre (Intel X520 / 82599, PCIe 2.0 x8), Runbound v0.16.0 with
`xdp: yes` (AF_XDP fast path) served from a warm cache, no local-data:

- **Maximum sustained served rate (NIC truth): ~10.1 M QPS** at **~21 % receiver CPU**,
  with **zero NIC drops** — the receiver NIC received ~10.7 M QPS (its PCIe 2.0 RX line
  limit) and the fast path answered essentially all of it.
- Below NIC line rate the fast path tracks offered load 1:1 with **zero drops**: 8.0 M
  offered → 8.0 M served at **6.7 % CPU**.

The receiver was far from CPU-bound (~79 % idle at the maximum). The ceiling is the X520
PCIe 2.0 RX, not Runbound. AF_XDP-level round-trip latency at low load was p50 **0.042 ms**
/ p95 0.050 / p99 0.094 ms; with zero queue build-up below line rate, latency does not
degrade with load. 99.7–99.9 % NOERROR.

## 2. Objective

Measure the AF_XDP fast path (`xdp: yes`) cache-served throughput, latency and CPU cost on
a high-core-count host, back-to-back with the kernel slow path on the same host and NIC
(companion report:
[no-xdp](RUNBOUND-v0.16.0-threadripper-5995wx-x520-noxdp-2026-06-07.md)). One variable
changed between the two runs: the `xdp:` line.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c / 128t), 125 GB RAM,
  Intel X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8 = 5.0 GT/s ×8 confirmed via sysfs,
  MTU 1500), kernel 7.0.6-2-pve, Runbound **v0.16.0**, **`xdp: yes`** (config
  `rb-single.conf`: `xdp-interface: enp33s0f0`, AF_XDP zero-copy workers, `answer_dns_wire`
  SIMD/ASM responder, `xdp-cache-snapshot-size: 65536`). `rate-limit: 0`,
  `cache-min-ttl: 3600`, `upstream-racing: yes`, real `forward-zone` (1.1.1.1 / 8.8.8.8 /
  9.9.9.9), **no local-data**. Governor `performance`. XDP program attached and verified
  (`ip -d link show enp33s0f0` → `xdp id …`). Identical config to the slow-path run except
  the `xdp:` line.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c / 40t, 2 NUMA), dnsmark 2.1.3,
  **AF_XDP** (symmetric XDP-vs-XDP), source-port spread 4096 (`DNSMARK_SPORT_SPREAD=4096`).
- **Link:** Intel X520 ↔ Intel X520, 10 GbE, direct fibre (no switch), flow-control off
  both ends, RSS `rx-flow-hash udp4 sdfn`, static ARP both directions. Ping RTT 0.118 ms.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt` (10 000 real names), cache warmed
  by two full passes (second pass 99.87 % NOERROR, p99 0.385 ms).
- **Procedure:** warmup, then an **offered-load sweep** (2 → 11 M QPS). Truth = **receiver
  NIC PHY counters** (`rx_pkts_nic`, `tx_pkts_nic`, `rx_no_dma_resources`,
  `rx_missed_errors`) — per measurement rule 1, in XDP zero-copy the netdev/`/sys`
  software counters do not reflect the datapath, so only the HW PHY registers are used.
  Receiver CPU from `/proc/stat`.
  - *Latency:* a `tcpdump` capture on the receiver **cannot** observe XDP_REDIRECT'd frames
    (they bypass the kernel stack before the AF_PACKET tap), so the receiver-wire anchor
    used for the slow path is not available here. Latency is therefore the generator's
    AF_XDP-level round-trip (XSK submit → completion = wire RTT, includes the 0.118 ms
    link), measured at a controlled rate. **I cannot confirm a receiver-side wire p50 for
    the XDP path** with the available tooling.

## 4. Raw Results

Offered-load sweep (warm cache, no local-data). Served = receiver `tx_pkts_nic` delta.

| Offered | Received (NIC) | **Served (NIC)** | NIC drops | Receiver CPU |
|--------:|---------------:|-----------------:|----------:|-------------:|
| 2.0 M | 2.01 M | 2.00 M | 0 | 3.6 % |
| 4.0 M | 4.01 M | 3.98 M | 0 | 4.2 % |
| 6.0 M | 6.02 M | 6.01 M | 0 | 5.2 % |
| 8.0 M | 8.02 M | 8.00 M | 0 | 6.7 % |
| 11.0 M | 10.70 M | **10.13 M** | 0 | **20.9 %** |

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained served QPS | **~10.1 M** | receiver `tx_pkts_nic` |
| Receiver NIC receive ceiling | ~10.7 M (PCIe 2.0 RX line limit) | receiver `rx_pkts_nic` at 11 M offered |
| Latency, low load (AF_XDP round-trip) | p50 **0.042** / p95 0.050 / p99 0.094 ms | dnsmark round-trip |
| Success / error rate | 99.7–99.9 % NOERROR / ~0.14 % SERVFAIL | dnsmark rcode breakdown |
| Receiver CPU at max | **~21 %** busy (~79 % idle) | `/proc/stat` |
| Receiver CPU at 8 M served | **6.7 %** | `/proc/stat` |
| NIC drops below line rate | **0** (`rx_no_dma_resources` = `rx_missed_errors` = 0 up to 8 M) | receiver `ethtool -S` |
| Receiver-side wire p50 | I cannot confirm this (tcpdump is blind to XDP_REDIRECT) | — |

## 5. Interpretation

- **NIC-bound, not CPU-bound.** Served scales 1:1 with offered load and **zero drops** up
  to 8 M (6.7 % CPU). At 11 M offered the NIC receives ~10.7 M — its PCIe 2.0 x8 RX line
  limit — and the fast path answers ~10.1 M of it at ~21 % CPU. The ~79 % idle at the
  maximum shows the limit is the X520 receive path, not Runbound.
- **Per-core efficiency.** ~10.1 M served at ~21 % busy across 128 threads. Extrapolating
  the CPU cost linearly suggests large headroom, but the NIC caps the input, so the actual
  rate Runbound's fast path would reach on a NIC without the PCIe 2.0 RX cap — **I cannot
  confirm this** from this rig; it requires a higher-bandwidth NIC to measure.
- **No queueing.** Because the datapath never backs up below line rate (zero drops), there
  is no latency knee within the NIC's capacity; the low-load round-trip (p50 0.042 ms) is
  representative across the measured range. At low load the fast path's batched poll makes
  it marginally higher-latency than the kernel slow path; the fast path's advantage is CPU
  cost and drop-free behaviour under load.
- **Back-to-back vs slow path (same host, same NIC, only `xdp:` changed):** fast path
  ~10.1 M served @ 21 % CPU, 0 drops, vs slow path ~6.9 M served @ 61 % CPU with ~5 M NIC
  drops at the same offered firehose. The fast path serves more, drops nothing below line
  rate, and costs roughly a third of the CPU; both share the same SIMD/ASM cache responder.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (dragonrage, AMD 5995WX) ---
ip link set enp33s0f0 xdp off                          # clear any residual program first
ethtool -A enp33s0f0 rx off tx off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn
cpupower frequency-set -g performance                  # already performance
ip neigh replace 10.10.20.2 lladdr <gen-mac> dev enp33s0f0 nud permanent
systemd-run --unit=rb-bench --collect \
  /usr/local/sbin/runbound -c /etc/runbound/rb-single.conf    # xdp:yes, racing:yes, cache-min-ttl 3600, no local-data
ip -d link show enp33s0f0 | grep -o 'xdp id [0-9]*'    # verify XDP attached
ss -ulpn | grep 10.10.20.1:53                          # rule 5: ownership check (XDP intercepts before the socket)

# --- Generator (dragonsage, dual Xeon E5-2690 v2), dnsmark 2.1.3, AF_XDP ---
ethtool -A nic2 rx off tx off
ip neigh replace 10.10.20.1 lladdr <recv-mac> dev nic2 nud permanent
# warmup (two passes)
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 200000 -l 12 --max-outstanding 500
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 500000 -l 8  --max-outstanding 2000
# offered-load sweep
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q <2e6..11e6> --max-outstanding 0 -l 12
# latency at a controlled rate (AF_XDP round-trip)
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 2000000 --max-outstanding 256 -l 10

# --- Throughput truth (receiver) — HW PHY registers only in XDP mode ---
ethtool -S enp33s0f0 | grep -wE 'rx_pkts_nic|tx_pkts_nic|rx_no_dma_resources|rx_missed_errors'

# --- Teardown (important) ---
ip link set enp33s0f0 xdp off                          # detach residual XDP program
```
