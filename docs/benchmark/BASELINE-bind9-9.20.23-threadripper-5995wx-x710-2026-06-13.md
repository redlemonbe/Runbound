# Runbound Benchmark — Baseline BIND 9.20.23 — Threadripper PRO 5995WX / X710 (i40e) — 2026-06-13

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. **Generator is non-XDP (kernel UDP)** this
> round — see §3; this is the deliberate baseline for the upcoming non-XDP Runbound runs on
> the identical rig and generator.

## 1. Executive Summary

On the new rig, over the direct **Intel X710 (i40e) 10 GbE** link, BIND 9.20.23 (`named`,
128 worker threads, warm cache), driven by a **non-XDP (kernel-UDP) dnsmark generator**,
peaks at **~1.84 M QPS served** (receiver NIC `tx_packets`) at **17.3 % receiver CPU** —
BIND is nowhere near its own ceiling. The bottleneck here is the kernel-UDP RX path and the
generator's offered ceiling (~5.7 M offered, of which the i40e ingests 4.52 M/s and drops
1.22 M/s), **not** BIND's per-query cost. Closed-loop latency at 872 k QPS egress is **p50
0.320 ms / p95 4.775 ms / p99 8.791 ms / p999 12.655 ms**, 98.7 % completed, 92.00 % NOERROR;
dnsperf (closed-loop) sustains **~786 k QPS avg / 859 k peak** at 97.37 % completed. Receiver
RAM **~0.58 GB RSS**. This is a generator-bound baseline, useful for a like-for-like
non-XDP comparison, not a statement of BIND's saturation peak.

## 2. Objective

Re-establish the BIND 9 baseline on the **new bench rig** (X710 + X510 direct links, isolated
from the prod LAN) with current tooling (dnsmark v2.3.0, dnsperf), as the reference point for
re-running Runbound v0.18.1 **in non-XDP mode** under an identical generator and methodology.
The question: over the X710 link, with a non-XDP generator, what does BIND serve, at what
latency, at what receiver CPU — and where is the bottleneck.

## 3. Methodology & Architecture

- **Receiver (BIND):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **Intel
  X710 / `enp33s0f0np0` (`i40e`, MTU 1500)**, kernel 6.12.88+deb13. BIND 9.20.23, kernel
  UDP (SO_REUSEPORT listeners), real `forwarders` (1.1.1.1 / 8.8.8.8 / 9.9.9.9,
  `forward only`), **no local zones**, `recursion yes`, `dnssec-validation no`,
  `minimal-responses yes`, `max-cache-size 512m`. `named -n 128` (128 worker threads,
  3 listen addresses → 384 SO_REUSEPORT UDP sockets on :53, confirmed by `ss -ulpn`).
  Governor `performance`, RX ring 4096, flow-control RX/TX off, RSS `udp4 sdfn` (full
  4-tuple). AppArmor `named` profile disabled for the custom config path; `named -g`
  (foreground).
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t), egress NIC
  `enp66s0f1np1` (i40e). **Non-XDP, kernel-UDP** open-loop firehose for the ramp;
  closed-loop (`--max-outstanding 1500`) for the latency point. `DNSMARK_SPORT_SPREAD=4096`.
  Exact commands in §6. dnsperf used as a second, closed-loop generator for cross-check.
- **Link:** Intel X710 (i40e) 10 GbE, **direct DAC** generator↔receiver (no switch, isolated
  from the LAN), **flow-control off** both ends, RSS `udp4 sdfn`, static point-to-point
  addressing `10.71.10.2 → 10.71.10.1`.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read,
  cache warmed before the measured ramp.
- **Procedure:** warm the cache, then **`--ramp`** (dnsmark's dichotomic open-loop saturation
  sweep). **Throughput truth = receiver NIC counters** (`tx_packets` served, `rx_packets`
  received, `rx_missed`/`rx_no_dma`/`rx_dropped` drops) over a 6 s steady window, plus
  receiver CPU from `/proc/stat` and `named` RSS. Latency point taken closed-loop below the
  open-loop knee. **Saturation criterion:** peak served across the ramp. Under the open-loop
  flood `--ramp` reports `rtt-samples=0` (RTT times out against a flooded kernel-UDP server),
  so latency is read from the closed-loop run, throughput from the NIC counters.

## 4. Raw Results

**dnsmark `--ramp` (open-loop, non-XDP generator), at the receiver NIC (X710):**

| Metric | Value | Source |
|--------|-------|--------|
| Offered | **~5.68 M q/s** | dnsmark ramp step (`offered`) |
| Received by NIC (`rx_packets`) | **4.52 M/s** | receiver `ethtool`/statistics |
| **Served (`tx_packets`)** | **~1.84 M peak** (1.68 M steady 6 s window) | receiver NIC |
| NIC drops/s (`rx_missed`+`rx_no_dma`+`rx_dropped`) | **1.22 M/s** | receiver `ethtool -S` |
| Receiver CPU % | **17.3 %** | `/proc/stat` |
| Receiver RAM | **~0.58 GB RSS** | `ps -o rss -C named` |
| RTT samples under flood | 0 (open-loop overload) | dnsmark `--ramp` |

**dnsmark closed-loop latency (`--max-outstanding 1500`):**

| Metric | Value |
|--------|-------|
| Egress (send throughput) | **872 884 qps** |
| Round-trip completed | **861 836 qps (98.7 %)** |
| Success | **92.00 % NOERROR** |
| Latency p50 / p95 / p99 / p999 | **0.320 / 4.775 / 8.791 / 12.655 ms** |

**dnsperf cross-check (closed-loop, `-T 20 -c 500 -q 100000`):**

| Metric | Value |
|--------|-------|
| Served peak (receiver NIC `tx_packets`) | **~859 k qps** |
| Queries per second (avg) | **786 202 qps** |
| Completed / lost | **97.37 % / 2.63 %** |
| Response codes | **NOERROR 94.90 %, SERVFAIL 4.92 %, NXDOMAIN 0.18 %** |
| Average latency | **5.626 ms** (min 0.029 ms, max 4.991 s, stddev 18.995 ms) |

## 5. Interpretation

- **BIND is not the bottleneck here.** At the open-loop peak (~1.84 M served) the receiver
  sits at **17.3 % CPU** — BIND has headroom. What caps the served rate is (a) the generator's
  non-XDP offered ceiling (~5.68 M q/s; a Xeon-v2 kernel-UDP sender cannot push more) and
  (b) the kernel-UDP RX path: the i40e ingests 4.52 M/s and drops 1.22 M/s before BIND sees
  them. This is a **generator/RX-bound** baseline, not BIND's saturation peak.
- **Comparison with the archived AF-XDP run.** The 2026-06-08 X520 baseline pushed BIND to
  ~2.98 M served, but **only at 12 M offered with an AF-XDP generator and all 128 cores at
  100 %**. With a non-XDP generator capped at ~5.7 M offered, BIND serves ~1.84 M at 17 % CPU
  — fully consistent with that run's ramp (5 M offered → 1.51 M served on the slower bus).
  The two are not contradictory: different generator mode, different offered load.
- **dnsperf vs dnsmark.** dnsperf is closed-loop (bounded by outstanding × threads round-trip):
  it sustains ~786 k avg / 859 k peak served at 97.37 % completion and ~5.6 ms average latency,
  with ~4.9 % SERVFAIL from forwarder timeouts under load. dnsmark `--ramp` is open-loop and
  reads the served *ceiling* (1.84 M) off the NIC. Both are valid lenses: dnsperf = sustainable
  closed-loop rate + latency, dnsmark = open-loop served ceiling.
- **Closed-loop tail.** At 872 k egress the p50 is tight (0.320 ms) but the tail is fat
  (p99 8.791 ms) and NOERROR drops to 92.00 % — BIND is being pushed close to its cache-serve
  limit at that egress, and forwarder round-trips inflate the tail. Below that rate (see the
  X510 report's 500 k point) the tail collapses and NOERROR returns to ~99.7 %.
- **Caveat.** One BIND configuration, one rig, non-XDP generator. This is what this setup
  produces under the documented methodology, not a universal statement about BIND, and not
  BIND's saturation ceiling (which would need an AF-XDP generator to reach).

## 6. Appendix — exact commands & configuration

```bash
# Receiver — BIND under test (AppArmor profile for the custom path disabled)
named-checkconf /etc/bind/named-bench.conf
named -c /etc/bind/named-bench.conf -g -n 128     # 128 threads, SO_REUSEPORT, foreground
ss -ulpn | grep -c ':53 '                         # 384 (= 128 threads x 3 listen addresses)

# Host (receiver): governor + flow-control + RSS + ring (X710 enp33s0f0np0)
cpupower frequency-set -g performance
ethtool -A enp33s0f0np0 rx off tx off
ethtool -N enp33s0f0np0 rx-flow-hash udp4 sdfn
ethtool -G enp33s0f0np0 rx 4096

# Generator (dragonsage) — non-XDP open-loop ramp:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -p 53 \
  -d top-10000-domains.txt --ramp

# Generator — latency point (closed-loop, non-XDP):
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -p 53 \
  -d top-10000-domains.txt --max-outstanding 1500 -l 12

# Generator — dnsperf cross-check (closed-loop):
dnsperf -s 10.71.10.1 -p 53 -d corpus-dnsperf.txt -T 20 -c 500 -q 100000 -l 16

# Throughput truth = receiver NIC counters, 6 s steady window:
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets   # served
cat /sys/class/net/enp33s0f0np0/statistics/rx_packets   # received
ethtool -S enp33s0f0np0 | grep -E 'rx_missed|rx_no_dma|rx_dropped'   # drops
# Receiver CPU from /proc/stat delta over the window; RAM:
ps -o rss= -C named | awk '{s+=$1}END{printf "%.2f GB\n", s/1048576}'
```
