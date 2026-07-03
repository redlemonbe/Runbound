# Runbound Benchmark — Baseline unbound 1.22.0 — Threadripper PRO 5995WX / X710 (i40e) — 2026-06-13

> Follows [README.md](../README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. **Generator is non-XDP (kernel UDP)** this
> round — see §3; non-XDP reference for the matching non-XDP Runbound runs on the identical
> rig and generator. Companion to the BIND X710 report (same host, same generator, same
> link — only the resolver under test changed).

## 1. Executive Summary

On the new rig, over the direct **Intel X710 (i40e) 10 GbE** link, unbound 1.22.0
(64 threads, warm cache), driven by a **non-XDP (kernel-UDP) dnsmark generator**, peaks at
**~2.09 M QPS served** (receiver NIC `tx_packets`) at **20.5 % receiver CPU** — well short of
its own ceiling. As with BIND, the limit is the kernel-UDP RX path and the generator's offered
ceiling (~5.41 M offered; the i40e ingests 4.29 M/s, drops 1.10 M/s), not unbound's per-query
cost. Closed-loop latency at 927 k QPS egress is **p50 0.227 ms / p95 3.209 ms / p99 7.123 ms /
p999 14.975 ms**, **100.00 % completed, 99.71 % NOERROR**; dnsperf (closed-loop) sustains
**~579 k avg / 939 k peak** at 98.71 % completed and **99.72 % NOERROR**. Receiver RAM
**~0.80 GB RSS**. On this link unbound serves **~14 % more than BIND** (2.09 M vs 1.84 M) at
comparable CPU and a noticeably cleaner success rate — consistent with the archived X520
result. Generator/RX-bound baseline, not unbound's saturation peak.

## 2. Objective

Re-establish the unbound baseline on the **new bench rig** (X710 + X510 direct links, isolated
from the prod LAN) with current tooling (dnsmark v2.3.0, dnsperf), as the non-XDP reference for
re-running Runbound v0.18.1 under an identical generator and methodology. Read alongside the
BIND X710 report (same host, same generator, same link — only the resolver changed) and the
X510 unbound report (same resolver, slower-RX link).

## 3. Methodology & Architecture

- **Receiver (unbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **Intel
  X710 / `enp33s0f0np0` (`i40e`, MTU 1500)**, kernel 6.12.88+deb13. unbound 1.22.0, kernel
  UDP, `so-reuseport: yes`, **64 threads** (its best config on this class of host, matching
  the archived run), `module-config: "iterator"` (no validator, dnssec off), single
  `forward-zone "."` → 1.1.1.1 / 8.8.8.8 / 9.9.9.9 (forward-only), **no local data**,
  `minimal-responses: yes`, `prefetch: yes`, `rrset-cache-size 512m` / `msg-cache-size 256m`.
  192 SO_REUSEPORT UDP sockets on :53 (64 threads × 3 listen addresses), confirmed by
  `ss -ulpn`. Governor `performance`, RX ring 4096, flow-control RX/TX off, RSS `udp4 sdfn`.
  AppArmor `unbound` profile disabled for the custom config path; run foreground (`-d -p`).
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t), egress NIC
  `enp66s0f1np1` (i40e). **Non-XDP, kernel-UDP** open-loop firehose for the ramp; closed-loop
  (`--max-outstanding 1500`) for the latency point. `DNSMARK_SPORT_SPREAD=4096`. dnsperf as a
  second, closed-loop generator for cross-check. Exact commands in §6.
- **Link:** Intel X710 (i40e) 10 GbE, **direct DAC** generator↔receiver (no switch, isolated
  from the LAN), **flow-control off** both ends, RSS `udp4 sdfn`, static point-to-point
  addressing `10.71.10.2 → 10.71.10.1`.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read,
  cache warmed before the measured ramp.
- **Procedure:** warm, then **`--ramp`** (open-loop saturation sweep); **throughput truth =
  receiver NIC counters** over a 6 s steady window; CPU from `/proc/stat`, RSS from `ps`.
  Latency point taken closed-loop below the open-loop knee. Under the open-loop flood
  `--ramp` reports `rtt-samples=0`, so latency comes from the closed-loop run, throughput
  from the NIC counters.

## 4. Raw Results

**dnsmark `--ramp` (open-loop, non-XDP generator), at the receiver NIC (X710):**

| Metric | Value | Source |
|--------|-------|--------|
| Offered | **~5.41 M q/s** | dnsmark ramp step |
| Received by NIC (`rx_packets`) | **4.29 M/s** | receiver statistics |
| **Served (`tx_packets`)** | **~2.09 M peak** (2.03 M steady 6 s window) | receiver NIC |
| NIC drops/s (`rx_missed`+`rx_no_dma`+`rx_dropped`) | **1.10 M/s** | receiver `ethtool -S` |
| Receiver CPU % | **20.5 %** | `/proc/stat` |
| Receiver RAM | **~0.80 GB RSS** | `ps -o rss -C unbound` |

**dnsmark closed-loop latency (`--max-outstanding 1500`):**

| Metric | Value |
|--------|-------|
| Egress / round-trip completed | **927 634 / 927 590 qps (100.0 %)** |
| Success | **99.71 % NOERROR** |
| Latency p50 / p95 / p99 / p999 | **0.227 / 3.209 / 7.123 / 14.975 ms** |

**dnsperf cross-check (closed-loop, `-T 20 -c 500 -q 100000`):**

| Metric | Value |
|--------|-------|
| Served peak (receiver NIC `tx_packets`) | **~939 k qps** |
| Queries per second (avg) | **579 493 qps** |
| Completed / lost | **98.71 % / 1.29 %** |
| Response codes | **NOERROR 99.72 %, SERVFAIL 0.10 %, NXDOMAIN 0.18 %** |
| Average latency | **97.5 ms** (min 0.026 ms, max 2.655 s) — closed-loop queue depth, see §5 |

## 5. Interpretation

- **unbound is not the bottleneck.** 20.5 % receiver CPU at the open-loop peak (~2.09 M served).
  The served rate is bounded by the non-XDP generator (~5.41 M offered) and the kernel-UDP RX
  path (4.29 M/s ingested, 1.10 M/s dropped), not unbound's per-query cost. Generator/RX-bound,
  not the saturation peak — the archived X520 AF-XDP run reached 3.59 M.
- **unbound > BIND on this link.** Same host, generator, link and methodology, unbound serves
  **~2.09 M vs BIND's ~1.84 M (+14 %)** at comparable CPU, and a cleaner closed-loop success
  rate (100 % completed / 99.71 % NOERROR vs BIND 98.7 % / 92.0 %). This matches the archived
  X520 ordering (unbound 3.59 M > BIND 2.98 M).
- **dnsperf average latency is a closed-loop artifact.** dnsperf with `-q 100000` keeps up to
  100 k queries outstanding; by Little's law a deep queue at ~579 k QPS yields ~97 ms average
  even though per-query service is sub-millisecond. The bounded closed-loop point
  (`--max-outstanding 1500`) is the real latency picture: **p50 0.227 ms**, tail to
  p999 14.975 ms. dnsperf's value here is the success rate (99.72 % NOERROR) and the served
  cross-check (~939 k), not the average-latency figure.
- **Caveat.** One unbound configuration (64 threads), one rig, non-XDP generator. This is what
  this setup produces under the documented methodology, not a universal statement about
  unbound, and not its saturation ceiling (which needs an AF-XDP generator to reach).

## 6. Appendix — exact commands & configuration

```bash
# Receiver — unbound under test (AppArmor profile for the custom path disabled)
unbound-checkconf /etc/unbound/unbound-bench.conf
ulimit -n 1048576
unbound -d -p -c /etc/unbound/unbound-bench.conf      # 64 threads, so-reuseport, foreground
ss -ulpn | grep -c ':53 '                             # 192 (= 64 threads x 3 listen addresses)
# key config: num-threads 64, module-config "iterator", forward-zone "." -> 1.1.1.1/8.8.8.8/9.9.9.9,
#   minimal-responses yes, prefetch yes, rrset-cache 512m / msg-cache 256m, dnssec off

# Host (receiver): governor + flow-control + RSS + ring (X710 enp33s0f0np0)
cpupower frequency-set -g performance
ethtool -A enp33s0f0np0 rx off tx off
ethtool -N enp33s0f0np0 rx-flow-hash udp4 sdfn
ethtool -G enp33s0f0np0 rx 4096

# Generator (dragonsage) — non-XDP open-loop ramp / closed-loop latency / dnsperf:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -p 53 -d top-10000-domains.txt --ramp
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -p 53 -d top-10000-domains.txt --max-outstanding 1500 -l 12
dnsperf -s 10.71.10.1 -p 53 -d corpus-dnsperf.txt -T 20 -c 500 -q 100000 -l 16

# Throughput truth = receiver NIC counters, 6 s steady window:
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets   # served
cat /sys/class/net/enp33s0f0np0/statistics/rx_packets   # received
ethtool -S enp33s0f0np0 | grep -E 'rx_missed|rx_no_dma|rx_dropped'   # drops
ps -o rss= -C unbound | awk '{s+=$1}END{printf "%.2f GB\n", s/1048576}'
```
