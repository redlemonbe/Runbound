# Runbound Benchmark — Baseline unbound 1.22.0 — Threadripper PRO 5995WX / X510 (ixgbe) — 2026-06-13

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. **Generator is non-XDP (kernel UDP)** this
> round — see §3; non-XDP reference for the matching non-XDP Runbound runs on the identical
> rig and generator. Companion to the unbound X710 report (same resolver, faster-RX link) and
> the BIND X510 report (same link, same generator — only the resolver changed).

## 1. Executive Summary

On the new rig, over the direct **Intel X510 (ixgbe) 10 GbE** link, unbound 1.22.0
(64 threads, warm cache), driven by a **non-XDP (kernel-UDP) dnsmark generator**, peaks at
**~1.65 M QPS served** (receiver NIC `tx_packets`) at **23.2 % receiver CPU** — short of its own
ceiling. As on X710, the limit is the kernel-UDP RX path (the ixgbe ingests 2.53 M/s and drops
**3.49 M/s** of the ~6 M offered) and the generator, not unbound's per-query cost. Closed-loop
latency at 513 k QPS egress is exceptionally tight — **p50 1.026 ms / p95 1.099 ms / p99
1.125 ms / p999 1.161 ms**, 97.58 % completed, **99.71 % NOERROR**. Receiver RAM **~0.82 GB
RSS**. unbound serves **~13 % more than BIND** on this link (1.65 M vs 1.46 M) at comparable
CPU, and its closed-loop tail is an order of magnitude tighter (p999 1.161 ms vs BIND's
13.663 ms). **dnsperf** (closed-loop) reads low here — ~131 k avg, 14.68 % lost — a closed-loop
/ ixgbe-RX-drop artifact, not a degraded link: the open-loop dnsmark NIC truth (1.65 M served)
confirms the link is healthy. Generator/RX-bound baseline, not unbound's saturation peak.

## 2. Objective

Re-establish the unbound baseline on the **X510 (ixgbe) link** of the new bench rig with current
tooling, as the non-XDP reference for re-running Runbound v0.18.1 on the same link, host and
generator. Read alongside the unbound X710 report to isolate the NIC/RX contribution (same host,
same unbound, same generator — only the link changed) and the BIND X510 report (same link,
different resolver).

## 3. Methodology & Architecture

- **Receiver (unbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **Intel
  X510 / `enp66s0f1` (`ixgbe`, MTU 1500)**, kernel 6.12.88+deb13. unbound 1.22.0, kernel UDP,
  `so-reuseport: yes`, **64 threads**, `module-config: "iterator"` (no validator, dnssec off),
  single `forward-zone "."` → 1.1.1.1 / 8.8.8.8 / 9.9.9.9 (forward-only), **no local data**,
  `minimal-responses: yes`, `prefetch: yes`, `rrset-cache-size 512m` / `msg-cache-size 256m`.
  192 SO_REUSEPORT UDP sockets on :53 (64 threads × 3 listen addresses), confirmed by `ss -ulpn`.
  Governor `performance`, flow-control RX/TX off. AppArmor `unbound` profile disabled; run
  foreground (`-d -p`).
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t), egress NIC `nic2`
  (ixgbe). **Non-XDP, kernel-UDP** open-loop firehose for the ramp; closed-loop
  (`--max-outstanding 1500`) for the latency point. `DNSMARK_SPORT_SPREAD=4096`. dnsperf as a
  second, closed-loop generator for cross-check. Exact commands in §6.
- **Link:** Intel X510 (ixgbe) 10 GbE, **direct DAC** generator↔receiver (no switch, isolated
  from the LAN), **flow-control off** both ends, static `10.51.10.2 → 10.51.10.1`. (The X510's
  second port is a known-dead link, disabled — link 1 only.)
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read, cache
  warmed before the measured ramp.
- **Procedure:** identical to the unbound X710 report — warm, `--ramp`, throughput from receiver
  NIC counters over a 6 s steady window, CPU from `/proc/stat`, RSS from `ps`, latency from the
  closed-loop run.

## 4. Raw Results

**dnsmark `--ramp` (open-loop, non-XDP generator), at the receiver NIC (X510):**

| Metric | Value | Source |
|--------|-------|--------|
| Offered | **~6.0 M q/s** | dnsmark ramp / NIC counters |
| Received by NIC (`rx_packets`) | **2.53 M/s** | receiver statistics |
| **Served (`tx_packets`)** | **~1.65 M peak** (1.57 M steady 6 s window) | receiver NIC |
| NIC drops/s (`rx_missed`+`rx_no_dma`+`rx_dropped`) | **3.49 M/s** | receiver `ethtool -S` |
| Receiver CPU % | **23.2 %** | `/proc/stat` |
| Receiver RAM | **~0.82 GB RSS** | `ps -o rss -C unbound` |

**dnsmark closed-loop latency (`--max-outstanding 1500`):**

| Metric | Value |
|--------|-------|
| Egress / round-trip completed | **512 909 / 500 506 qps (97.6 %)** |
| Success | **99.71 % NOERROR** (97.58 % completed) |
| Latency p50 / p95 / p99 / p999 | **1.026 / 1.099 / 1.125 / 1.161 ms** |

**dnsperf cross-check (closed-loop, `-T 20 -c 500 -q 100000`):**

| Metric | Value |
|--------|-------|
| Served peak (receiver NIC `tx_packets`) | **~253 k qps** |
| Queries per second (avg) | **131 627 qps** |
| Completed / lost | **85.32 % / 14.68 %** (closed-loop / RX-drop artifact, see §5) |
| Response codes | **NOERROR 99.78 %, SERVFAIL 0.05 %, NXDOMAIN 0.17 %** |
| Average latency | **3.4 ms** (min 0.031 ms, max 1.904 s) |

## 5. Interpretation

- **The ixgbe RX path is the bottleneck on this link.** Under the same ~6 M q/s non-XDP
  generator the X510 (ixgbe) ingests **2.53 M/s and drops 3.49 M/s**, where the X710 (i40e)
  ingests **4.29 M/s and drops 1.10 M/s** (see the unbound X710 report). So unbound serves
  **~1.65 M behind the ixgbe vs ~2.09 M behind the i40e**, at the same ~20–23 % CPU. The
  difference is the NIC/RX, not unbound.
- **unbound > BIND on this link too.** 1.65 M vs BIND's 1.46 M (+13 %) at comparable CPU, and a
  dramatically tighter closed-loop tail: **p999 1.161 ms vs BIND's 13.663 ms** at the same ~500 k
  egress, 99.71 % vs 99.72 % NOERROR. unbound's closed-loop latency distribution here is the
  cleanest of any resolver on this rig.
- **The dnsperf X510 figure is a closed-loop / RX-drop artifact, not the link.** dnsperf reads
  ~131 k avg with 14.68 % lost — but the open-loop dnsmark NIC truth shows unbound serving
  **1.65 M** on the same link in the same session. dnsperf is closed-loop: when the ixgbe drops
  request packets at RX under the offered rate, dnsperf waits for responses that never come and
  counts them lost, collapsing its self-reported rate. The link is healthy (dnsmark NIC-truth
  proves it); dnsperf's loss reflects the closed-loop interaction with ixgbe RX drops. Treat the
  dnsperf X510 numbers as a lower bound under that interaction, not unbound's capability.
- **Caveat.** One unbound configuration (64 threads), one rig, non-XDP generator, ixgbe link with
  a known dead second port (link 1 only). Documented-methodology result, not a universal
  statement about unbound or the X510, and not unbound's saturation ceiling.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — unbound under test (AppArmor profile for the custom path disabled)
unbound-checkconf /etc/unbound/unbound-bench.conf
ulimit -n 1048576
unbound -d -p -c /etc/unbound/unbound-bench.conf      # 64 threads, so-reuseport, foreground
ss -ulpn | grep -c ':53 '                             # 192 (= 64 threads x 3 listen addresses)

# Host (receiver): governor + flow-control (X510 enp66s0f1)
cpupower frequency-set -g performance
ethtool -A enp66s0f1 rx off tx off

# Generator (dragonsage) — non-XDP open-loop ramp / closed-loop latency / dnsperf:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -p 53 -d top-10000-domains.txt --ramp
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -p 53 -d top-10000-domains.txt --max-outstanding 1500 -l 12
dnsperf -s 10.51.10.1 -p 53 -d corpus-dnsperf.txt -T 20 -c 500 -q 100000 -l 16

# Throughput truth = receiver NIC counters, 6 s steady window:
cat /sys/class/net/enp66s0f1/statistics/tx_packets   # served
cat /sys/class/net/enp66s0f1/statistics/rx_packets   # received
ethtool -S enp66s0f1 | grep -E 'rx_missed|rx_no_dma|rx_dropped'   # drops
ps -o rss= -C unbound | awk '{s+=$1}END{printf "%.2f GB\n", s/1048576}'
```
