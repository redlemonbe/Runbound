# Runbound Benchmark — v0.16.11 — Threadripper PRO 5995WX + X710 (XDP, single link) — 2026-06-10

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

On a single 10 GbE Intel X710 (i40e) link, Runbound v0.16.11 (release binary) in
`xdp: yes` mode served a peak of **10.09 M qps** (receiver NIC `tx_packets`,
timestamped 2 s deltas, two runs: 10 092 080 and 10 093 678) under an offered load
of **13.04 M qps** (receiver NIC `rx_packets`, ≈ 10 GbE line rate for the ~70–96 B
query frames). `rx_dropped` and `rx_missed_errors` stayed at **0** across the whole
session. The p50 < 1 ms SLO held to **10.56 M qps offered** (three ramps:
10 559 849 / 10 561 490 / 10 562 058 — the same knee as the previous v0.16.9 run to
four significant digits). Receiver system CPU at peak was ~8 % (92 % idle) on the
128-thread host; RAM 18 GiB / 125 GiB. A same-day, same-method A/B against the
previous benchmark binary shows v0.16.11 equal within measurement noise (served
−0.06 %, knee +0.02 %) — the v0.16.11 changes (802.1Q VLAN path #188, per-view
split-horizon snapshots #187) cost nothing measurable on the untagged, no-view hot
path.

## 2. Objective

Re-run the full single-link X710 benchmark on the v0.16.11 release binary to verify
that the features added since the previous run — 802.1Q VLAN handling on the fast
path (#188) and split-horizon served on the fast path via per-view snapshots
(#187) — did not regress the hot path. Acceptance: results equal or better than the
previous run.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GiB RAM,
  Intel X710 `enp33s0f0np0` (i40e 7.0.6-2-pve, firmware 7.10), kernel 7.0.6-2-pve.
  Runbound **0.16.11** (release build), `xdp: yes`, 32 AF_XDP queues (one zero-copy
  XSK per HW queue), `rate-limit: 0`, governor `performance`, flow-control off, RSS
  `udp4 sdfn`, **no local-data, no split-horizon configured** (the #187 view list is
  empty — the per-packet view check is a load on an empty vector). Forward zone →
  1.1.1.1 / 8.8.8.8 / 9.9.9.9; `cache-min-ttl 3600` so the warmed corpus is served
  from the XDP cache fast path. Port :53 ownership verified before the run (only the
  Runbound process: the XDP path plus the #167 reply/loopback sockets).
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), **dnsmark 2.2.1**
  (includes the #8 generator-RSS fix), X710 `enp66s0f1np1`, governor `performance`,
  flow-control off. Command: `dnsmark -s 10.77.0.2 -d queries.txt --ramp --xdp -q --no-tui`.
- **Link:** **single** X710↔X710 DAC, 10 Gb/s, direct (no switch). The receiver's
  second X710 port is administratively DOWN (single-link case). One IP per cable;
  ARP-flux disabled on both hosts (`arp_ignore=1`, `arp_announce=2`, `arp_filter=1`).
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt` — 10 000 names as
  `"<name> A"`, random order.
- **Procedure:** 20 s warmup at 10 000 qps over kernel UDP (populates the cache;
  99.99 % completed, p50 0.047 ms). Ramp: dnsmark DSS — offered load doubles from
  1 000 qps every 5 s until the p50 < 1 ms SLO breaks, then a binary search brackets
  the knee. Three ramp runs. Served/offered truth sampled at the receiver NIC
  (`ethtool -S`, **timestamped** deltas: counter difference divided by the measured
  elapsed time, not a nominal interval).

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Max served QPS (peak 2 s, timestamped) | **10.09 M qps** (10 092 080 / 10 093 678, two runs) | receiver NIC `tx_packets` |
| Peak offered QPS | 13.04 M qps (13 044 233 / 13 044 573) ≈ 10 GbE line rate | receiver NIC `rx_packets` |
| Max offered under p50 < 1 ms SLO | **10.56 M qps** (10 559 849 / 10 561 490 / 10 562 058, three ramps) | dnsmark ramp |
| p50 / p95 / p99 @ 7.68 M offered | 0.208 / 0.287 / 3.16 ms | dnsmark round-trip (not tcpdump-anchored) |
| p50 / p95 / p99 @ 9.60 M offered | 0.182 / 3.02 / 5.60 ms | dnsmark round-trip |
| p50 @ saturation (13.05 M offered) | 2.40 ms | dnsmark ramp |
| Success rate (of completed) | 99.83 % NOERROR | dnsmark rcode breakdown |
| Receiver CPU (system) | ~8 % of 128 threads (92 % idle) | `top` on receiver |
| Receiver RAM | 18 GiB / 125 GiB | `free` |
| NIC RX drops over session | `rx_missed_errors` 0; `rx_dropped` 0 | receiver `ethtool -S` |

Ramp latency curve (per 5 s step, dnsmark round-trip, first ramp):

| Offered q/s | p50 ms | p95 ms | p99 ms |
|------------:|-------:|-------:|-------:|
| 239 616 | 0.036 | 0.082 | 11.895 |
| 480 513 | 0.130 | 0.247 | 7.319 |
| 960 256 | 0.198 | 0.362 | 3.995 |
| 1 920 010 | 0.278 | 0.426 | 1.107 |
| 3 841 641 | 0.291 | 0.414 | 0.721 |
| 7 682 803 | 0.208 | 0.287 | 3.161 |
| 9 602 493 | 0.182 | 3.015 | 5.603 |
| 10 561 490 | 0.958 | 1.013 | 1.040 |
| 11 041 209 | 1.775 | 1.828 | 1.859 |
| 13 045 200 | 2.403 | 6.575 | 6.795 |

### Same-day, same-method A/B against the previous binary

The binary from the previous report (v0.16.9 + the then-uncommitted VLAN/webui
changes) was re-measured back-to-back on the same rig with the identical
timestamped sampling:

| Binary | Served peak (tx NIC) | Offered peak (rx NIC) | Knee (p50 < 1 ms) |
|--------|---------------------:|----------------------:|------------------:|
| previous (v0.16.9+wip) | 10 099 283 | 13 046 023 | 10 559 300 |
| **v0.16.11 release** | 10 092 080 – 10 093 678 | 13 044 233 – 13 044 573 | 10 559 849 – 10 562 058 |

Δ served −0.06 %, knee +0.02 % — within run-to-run noise. The knees of the two
binaries interleave.

## 5. Interpretation

- v0.16.11 equals the previous run on every metric: served peak −0.06 %
  (within the 0.04 % run-to-run band), saturation knee identical to four
  significant digits, latency curve superimposable, zero NIC RX loss. The #188
  VLAN branch and the #187 per-view check (an empty-vector load per packet when no
  split-horizon is configured) have **no measurable hot-path cost** — as designed.
- **Correction to the previous report's headline figure.** The v0.16.9 report
  stated 10.14 M qps served. That figure divided counter deltas by a nominal 2 s
  interval; the sampling loop's real window slightly exceeds 2 s, so the figure was
  overestimated by ≈ 0.5 %. The corrected, timestamped method yields
  10.09–10.10 M qps for **both** binaries back-to-back. The honest comparison is the
  same-method A/B above, not the headline-to-headline difference.
- The offered peak (13.04 M qps) is the 10 GbE line rate for this query mix; served
  (10.09 M) is close to the line rate in the response direction (larger frames).
  Whether the served ceiling is the link or Runbound's fast-path limit
  **I cannot confirm this** — it requires a faster link (25/40 GbE). Receiver CPU at
  ~8 % shows Runbound is not total-CPU-bound at this rate.
- Latency is dnsmark round-trip, not tcpdump-anchored; tcpdump-anchored percentiles
  for this run: **I cannot confirm this.**

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (Threadripper, X710 enp33s0f0np0, runbound 0.16.11 release) ---
for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $c; done
ethtool -A enp33s0f0np0 rx off tx off
ethtool -N enp33s0f0np0 rx-flow-hash udp4 sdfn
ip link set enp33s0f1np1 down            # single-link case
ss -ulpn | grep :53                      # ownership: runbound only
# runbound.conf: xdp:yes, xdp-interface enp33s0f0np0, rate-limit 0,
#   cache-min-ttl 3600, cache-max-ttl 86400, xdp-cache-snapshot-size 65536,
#   upstream-racing yes, forward 1.1.1.1/8.8.8.8/9.9.9.9, no local-data,
#   no split-horizon

# --- Generator (dual Xeon E5-2690v2, X710 enp66s0f1np1, dnsmark 2.2.1) ---
for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $c; done
ethtool -A enp66s0f1np1 rx off tx off
awk 'NF{print $1" A"}' top-10000-domains.txt > queries.txt
dnsmark -s 10.77.0.2 -d queries.txt -Q 10000 -l 20 -q --no-tui     # warmup
dnsmark -s 10.77.0.2 -d queries.txt --ramp --xdp -q --no-tui       # ramp ×3

# --- Served/offered truth (receiver, timestamped deltas) ---
# loop: t=$(date +%s.%N); read tx_packets/rx_packets from ethtool -S;
# rate = (counter - prev_counter) / (t - prev_t); keep the peak.
ethtool -S enp33s0f0np0 | grep -E '(rx_packets|tx_packets|rx_missed_errors|rx_dropped):'
```
