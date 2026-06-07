# Runbound Benchmark — v0.16.0 — AMD Threadripper PRO 5995WX — AF_XDP fast path (`xdp: yes`) — 2026-06-07

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

Over a single 10 GbE fibre (Intel X520 / 82599, PCIe 2.0 x8), Runbound v0.16.0 with
`xdp: yes` (AF_XDP fast path), warm cache, no local-data:

- **Served-rate ceiling (NIC truth): ~10.1 M QPS** at **~21 % receiver CPU**, with **zero
  NIC drops** — the NIC receives ~10.7 M QPS (its PCIe 2.0 RX line limit) and the fast path
  answers essentially all of it.
- Below NIC line rate the fast path tracks offered load 1:1 with **zero drops**: 8.0 M
  offered → 8.0 M served at **6.7 % CPU**.
- **dnsmark ramp** (the methodology's tool): round-trip **p50 holds sub-millisecond up to
  ~8 M on the wire** — p50 0.133 ms with **p99 0.254 ms at 6.4 M** offered; the median
  crosses 1 ms only past ~12.3 M *target* (the generator's ramp-mode egress tops out
  ~8 M on the wire, so the ramp cannot drive the fast path to its NIC ceiling — that needs
  the open-loop flood).

The receiver was far from CPU-bound (~79 % idle at the maximum). The ceiling is the X520
PCIe 2.0 RX, not Runbound.

## 2. Objective

Measure the AF_XDP fast path (`xdp: yes`) throughput, latency and CPU cost under the
methodology (warmup + ramp), back-to-back with the kernel slow path on the same host and
NIC — only the `xdp:` line differs. Companion:
[no-xdp](RUNBOUND-v0.16.0-threadripper-5995wx-x520-noxdp-2026-06-07.md).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c / 128t), 125 GB RAM,
  Intel X520 / 82599 `enp33s0f0` (`ixgbe`, PCIe 2.0 x8 = 5.0 GT/s ×8 confirmed via sysfs,
  MTU 1500), kernel 7.0.6-2-pve, Runbound **v0.16.0**, **`xdp: yes`** (`rb-single.conf`:
  `xdp-interface: enp33s0f0`, AF_XDP zero-copy workers, `answer_dns_wire` SIMD/ASM
  responder, `xdp-cache-snapshot-size: 65536`). `cache-min-ttl: 3600`,
  `upstream-racing: yes`, real `forward-zone` (1.1.1.1 / 8.8.8.8 / 9.9.9.9), **no
  local-data**. Governor `performance`. XDP program attached and verified (`ip -d link show
  enp33s0f0` → `xdp id …`). Identical config to the slow-path run except the `xdp:` line.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c / 40t, 2 NUMA), dnsmark 2.1.3,
  **AF_XDP** (symmetric XDP-vs-XDP), source-port spread 4096.
- **Link:** X520 ↔ X520, 10 GbE, direct fibre, flow-control off both ends, RSS `udp4 sdfn`,
  static ARP both ways. Ping RTT 0.118 ms.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt`, warmed (2nd pass 99.87 % NOERROR,
  p99 0.385 ms).
- **Procedure:** **warmup, then `dnsmark --ramp`** (methodology execution model). Two
  truths cross-checked: (1) latency = ramp round-trip p50/p95/p99; (2) throughput =
  receiver **NIC PHY counters** — in XDP zero-copy the netdev/`/sys` software counters do
  not reflect the datapath, so only `rx_pkts_nic` / `tx_pkts_nic` / `rx_no_dma_resources` /
  `rx_missed_errors` are used (measurement rule 1).
- **Stated limits:**
  - The ramp reports an **offered target**, not the wire rate; the NIC PHY egress is the
    real load. In ramp mode the generator's wire egress tops out ~8 M (RTT-sampling
    overhead), below the fast path's NIC-bound ceiling, so the open-loop flood is used to
    reach the ~10.1 M ceiling.
  - A receiver-side `tcpdump` latency anchor is **not possible** here: XDP_REDIRECT'd frames
    bypass the kernel before the AF_PACKET tap. **I cannot confirm a receiver-side wire p50
    for the XDP path**; latency is the dnsmark AF_XDP round-trip (includes the 0.118 ms
    link).

## 4. Raw Results

**A. Latency — `dnsmark --ramp` round-trip (offered = target rate):**

| Offered (target) | p50 | p95 | p99 |
|-----------------:|----:|----:|----:|
| 1.6 M | 0.164 ms | 0.273 ms | 4.49 ms |
| 3.2 M | 0.170 ms | 0.254 ms | 0.284 ms |
| 6.4 M | **0.133 ms** | 0.217 ms | **0.254 ms** |
| 12.3 M | 0.993 ms | 2.18 ms | 4.57 ms |

Highest step holding p50 < 1 ms = ~12.3 M target; wire egress there ≈ 8 M (NIC PHY) — the
generator's ramp-mode ceiling, not the receiver's.

**B. Throughput — receiver NIC PHY counters (truth):**

| Offered | Received (NIC) | **Served (NIC)** | NIC drops | Receiver CPU |
|--------:|---------------:|-----------------:|----------:|-------------:|
| 2.0 M | 2.01 M | 2.00 M | 0 | 3.6 % |
| 4.0 M | 4.01 M | 3.98 M | 0 | 4.2 % |
| 6.0 M | 6.02 M | 6.01 M | 0 | 5.2 % |
| 8.0 M | 8.02 M | 8.00 M | 0 | 6.7 % |
| 11.0 M | 10.70 M | **10.13 M** | 0 | **20.9 %** |

| Metric | Value | Source |
|--------|-------|--------|
| Served-rate ceiling | **~10.1 M** | receiver `tx_pkts_nic` |
| NIC receive ceiling | ~10.7 M (PCIe 2.0 RX line limit) | receiver `rx_pkts_nic` |
| Latency (ramp, ≤6.4 M) | p50 0.133 / p95 0.217 / p99 0.254 ms | dnsmark round-trip |
| Success / error rate | 99.7–99.9 % NOERROR | dnsmark rcodes |
| Receiver CPU at ceiling | **~21 %** busy (~79 % idle) | `/proc/stat` |
| Receiver CPU at 8 M served | 6.7 % | `/proc/stat` |
| NIC drops below line rate | **0** up to 8 M served | `ethtool -S` |
| Receiver-side wire p50 | I cannot confirm this (tcpdump blind to XDP_REDIRECT) | — |

## 5. Interpretation

- **NIC-bound, not CPU-bound.** Served scales 1:1 with **zero drops** to 8 M (6.7 % CPU);
  at 11 M offered the NIC receives ~10.7 M (its PCIe 2.0 x8 RX line limit) and the fast
  path answers ~10.1 M at ~21 % CPU. ~79 % idle at the maximum — the limit is the X520
  receive path.
- **No queueing → flat latency.** Because nothing backs up below line rate (zero drops),
  there is no latency knee within the NIC's capacity; the ramp p50 stays 0.13–0.17 ms and
  p99 0.254 ms across 3–6 M. At very low load the batched AF_XDP poll makes the fast path
  marginally higher-latency than the kernel slow path; its advantages are CPU cost and
  drop-free behaviour under load.
- **Ramp vs flood.** The ramp confirms sub-ms p50 up to ~8 M on the wire but cannot push
  past the generator's ramp-mode egress; the open-loop flood reaches the receiver's NIC
  ceiling (~10.1 M). Both agree where they overlap (8 M offered → 8 M served, sub-ms).
- **Back-to-back vs slow path** (same host/NIC, only `xdp:` changed): fast path ~10.1 M
  served @ 21 % CPU, 0 drops, vs slow path ~6.9 M served @ 61 % CPU with ~5 M NIC drops
  under the same firehose. Same cache responder; the fast path serves more, drops nothing
  below line rate, at ~⅓ the CPU. The rate it would reach on a NIC without the PCIe 2.0 RX
  cap — **I cannot confirm this** from this rig.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (dragonrage, AMD 5995WX) ---
ip link set enp33s0f0 xdp off                          # clear any residual program first
ethtool -A enp33s0f0 rx off tx off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn
cpupower frequency-set -g performance
ip neigh replace 10.10.20.2 lladdr <gen-mac> dev enp33s0f0 nud permanent
systemd-run --unit=rb-bench --collect \
  /usr/local/sbin/runbound -c /etc/runbound/rb-single.conf    # xdp:yes, racing:yes, cache-min-ttl 3600, no local-data
ip -d link show enp33s0f0 | grep -o 'xdp id [0-9]*'    # verify XDP attached

# --- Generator (dragonsage, dual Xeon E5-2690 v2), dnsmark 2.1.3, AF_XDP ---
ethtool -A nic2 rx off tx off
ip neigh replace 10.10.20.1 lladdr <recv-mac> dev nic2 nud permanent
# warmup
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 200000 -l 12 --max-outstanding 500
dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 500000 -l 8  --max-outstanding 2000
# RAMP (methodology execution model)
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp --ramp --max-outstanding 0
# NIC-ceiling cross-check (open-loop flood per offered step)
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.10.20.1 -p 53 -d top-10000-domains.txt --xdp -Q <2e6..11e6> --max-outstanding 0 -l 12

# --- Throughput truth (receiver) — HW PHY registers only in XDP mode ---
ethtool -S enp33s0f0 | grep -wE 'rx_pkts_nic|tx_pkts_nic|rx_no_dma_resources|rx_missed_errors'

# --- Teardown ---
ip link set enp33s0f0 xdp off                          # detach residual XDP program
```
