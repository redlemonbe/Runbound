# Runbound Benchmark — Baseline BIND 9.20.23 — Threadripper PRO 5995WX / X510 (ixgbe) — 2026-06-13

> Follows [README.md](../README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. **Generator is non-XDP (kernel UDP)** this
> round — see §3; this is the deliberate baseline for the upcoming non-XDP Runbound runs on
> the identical rig and generator. Companion to the X710 report (same host, same BIND, same
> generator — only the link/NIC changed).

## 1. Executive Summary

On the new rig, over the direct **Intel X510 (ixgbe) 10 GbE** link, BIND 9.20.23 (`named`,
128 worker threads, warm cache), driven by a **non-XDP (kernel-UDP) dnsmark generator**,
peaks at **~1.46 M QPS served** (receiver NIC `tx_packets`) at **21.8 % receiver CPU** —
again, well short of BIND's own ceiling. The limit on this link is the **ixgbe kernel-UDP RX
path**: of ~6 M q/s offered, the NIC ingests only 2.46 M/s and drops **3.60 M/s**, roughly
half what the i40e link ingests under the same generator. Closed-loop latency at ~500 k QPS
egress is **p50 1.051 ms / p95 1.206 ms / p99 1.388 ms / p999 13.663 ms**, **99.72 % NOERROR**;
dnsperf (closed-loop) sustains **~432 k QPS avg / ~520 k peak** at 95.01 % completed. Receiver
RAM **~0.59 GB RSS**. Generator/RX-bound baseline, not BIND's saturation peak.

## 2. Objective

Re-establish the BIND 9 baseline on the **X510 (ixgbe) link** of the new bench rig with
current tooling (dnsmark v2.3.0, dnsperf), as the non-XDP reference for re-running Runbound
v0.18.1 on the same link, host, and generator. Read alongside the X710 report to isolate the
NIC/RX contribution: same host, same BIND, same generator — only the link changed.

## 3. Methodology & Architecture

- **Receiver (BIND):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **Intel
  X510 / `enp66s0f1` (`ixgbe`, MTU 1500)**, kernel 6.12.88+deb13. BIND 9.20.23, kernel UDP
  (SO_REUSEPORT listeners), real `forwarders` (1.1.1.1 / 8.8.8.8 / 9.9.9.9, `forward only`),
  **no local zones**, `recursion yes`, `dnssec-validation no`, `minimal-responses yes`,
  `max-cache-size 512m`. `named -n 128` (128 worker threads, 3 listen addresses → 384
  SO_REUSEPORT UDP sockets on :53, confirmed by `ss -ulpn`). Governor `performance`,
  flow-control RX/TX off. AppArmor `named` profile disabled for the custom config path;
  `named -g` (foreground).
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t), egress NIC `nic2`
  (ixgbe). **Non-XDP, kernel-UDP** open-loop firehose for the ramp; closed-loop
  (`--max-outstanding 1500`) for the latency point. `DNSMARK_SPORT_SPREAD=4096`. dnsperf as
  a second, closed-loop generator for cross-check. Exact commands in §6.
- **Link:** Intel X510 (ixgbe) 10 GbE, **direct DAC** generator↔receiver (no switch, isolated
  from the LAN), **flow-control off** both ends, static point-to-point addressing
  `10.51.10.2 → 10.51.10.1`. (The X510's second port is a known-dead link, disabled — see
  the rig notes; only link 1 is used.)
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read,
  cache warmed before the measured ramp.
- **Procedure:** identical to the X710 report — warm, `--ramp`, throughput from receiver NIC
  counters over a 6 s steady window, CPU from `/proc/stat`, `named` RSS, latency from the
  closed-loop run below the open-loop knee. Saturation criterion = peak served across the ramp.

## 4. Raw Results

**dnsmark `--ramp` (open-loop, non-XDP generator), at the receiver NIC (X510):**

| Metric | Value | Source |
|--------|-------|--------|
| Offered | **~6 M q/s** (rx+drops at NIC) | dnsmark ramp / NIC counters |
| Received by NIC (`rx_packets`) | **2.46 M/s** | receiver statistics |
| **Served (`tx_packets`)** | **~1.46 M peak** (1.25 M steady 6 s window) | receiver NIC |
| NIC drops/s (`rx_missed`+`rx_no_dma`+`rx_dropped`) | **3.60 M/s** | receiver `ethtool -S` |
| Receiver CPU % | **21.8 %** | `/proc/stat` |
| Receiver RAM | **~0.59 GB RSS** | `ps -o rss -C named` |
| RTT samples under flood | 0 (open-loop overload) | dnsmark `--ramp` |

**dnsmark closed-loop latency (`--max-outstanding 1500`):**

| Metric | Value |
|--------|-------|
| Egress (send throughput) | **~500 k qps** |
| Success | **99.72 % NOERROR** |
| Latency p50 / p95 / p99 / p999 | **1.051 / 1.206 / 1.388 / 13.663 ms** |

**dnsperf cross-check (closed-loop, `-T 20 -c 500 -q 100000`):**

| Metric | Value |
|--------|-------|
| Served peak (receiver NIC `tx_packets`) | **~520 k qps** |
| Queries per second (avg) | **~432 k qps** |
| Completed | **95.01 %** |
| Response codes | **NOERROR 95.54 %, SERVFAIL 4.28 %** |
| Average latency | **~1.7 ms** |

## 5. Interpretation

- **The ixgbe RX path is the bottleneck on this link.** Under the same ~6 M q/s non-XDP
  generator, the X510 (ixgbe) ingests only **2.46 M/s and drops 3.60 M/s**, where the X710
  (i40e) ingests **4.52 M/s and drops 1.22 M/s** (see the X710 report). Fewer/less-efficient
  RX queues on the ixgbe kernel path mean fewer packets ever reach BIND, so it serves
  **~1.46 M vs ~1.84 M** — at the same ~20 % CPU. The difference is the NIC/RX, not BIND.
- **BIND is not the bottleneck.** 21.8 % receiver CPU at the open-loop peak. As on X710, the
  served rate is bounded by the generator's non-XDP offered ceiling and the kernel-UDP RX
  path, not BIND's per-query cost.
- **dnsperf vs dnsmark.** dnsperf (closed-loop) sustains ~432 k avg / ~520 k peak served at
  95.01 % completion and ~1.7 ms average latency; dnsmark `--ramp` (open-loop) reads the
  served ceiling (~1.46 M) off the NIC. Same two lenses as the X710 run.
- **Closed-loop latency is clean here.** At ~500 k egress the distribution is tight — p50
  1.051 / p95 1.206 / p99 1.388 ms — and NOERROR is **99.72 %**, because BIND is comfortably
  below its serve limit at that rate (only the p999 = 13.663 ms tail shows occasional
  forwarder round-trips). Contrast the X710 closed-loop point, taken at a much higher 872 k
  egress, where the tail and SERVFAIL rate climb: same server, the tail is a function of how
  hard it is pushed, not of the NIC.
- **Caveat.** One BIND configuration, one rig, non-XDP generator, ixgbe link with a known
  dead second port (link 1 only). This is what this setup produces under the documented
  methodology, not a universal statement about BIND or the X510, and not BIND's saturation
  ceiling.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — BIND under test (AppArmor profile for the custom path disabled)
named-checkconf /etc/bind/named-bench.conf
named -c /etc/bind/named-bench.conf -g -n 128     # 128 threads, SO_REUSEPORT, foreground
ss -ulpn | grep -c ':53 '                         # 384 (= 128 threads x 3 listen addresses)

# Host (receiver): governor + flow-control (X510 enp66s0f1)
cpupower frequency-set -g performance
ethtool -A enp66s0f1 rx off tx off

# Generator (dragonsage) — non-XDP open-loop ramp:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -p 53 \
  -d top-10000-domains.txt --ramp

# Generator — latency point (closed-loop, non-XDP):
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -p 53 \
  -d top-10000-domains.txt --max-outstanding 1500 -l 12

# Generator — dnsperf cross-check (closed-loop):
dnsperf -s 10.51.10.1 -p 53 -d corpus-dnsperf.txt -T 20 -c 500 -q 100000 -l 16

# Throughput truth = receiver NIC counters, 6 s steady window:
cat /sys/class/net/enp66s0f1/statistics/tx_packets   # served
cat /sys/class/net/enp66s0f1/statistics/rx_packets   # received
ethtool -S enp66s0f1 | grep -E 'rx_missed|rx_no_dma|rx_dropped'   # drops
# Receiver CPU from /proc/stat delta over the window; RAM:
ps -o rss= -C named | awk '{s+=$1}END{printf "%.2f GB\n", s/1048576}'
```
