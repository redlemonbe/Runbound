# Runbound Benchmark — v0.16.9 — Threadripper PRO 5995WX + X710 (XDP) — 2026-06-10

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

On a 10 GbE Intel X710 (i40e) link, Runbound v0.16.9 in `xdp: yes` mode served a peak
of **10.14 M qps** (receiver NIC `tx_packets`, peak 2 s sample) under an offered load
of **13.09 M qps** (receiver NIC `rx_packets`, ≈ 10 GbE line rate for the ~96-byte query
frames). Across the entire session the receiver NIC `rx_missed_errors` counter rose by
**4** (no measurable NIC RX loss). Per-query latency p50 stayed sub-millisecond
(0.18–0.30 ms) from ~0.5 M up to 9.6 M qps offered; the p50 < 1 ms SLO held up to
**10.56 M qps offered**, crossing 1 ms near 11 M and reaching 2.75 ms at 13 M
(saturation). Total receiver system CPU during the flood was ~8 % (92 % idle) on the
128-thread host, so Runbound was not total-CPU-bound at this rate. Responses were all
NOERROR (99.88 % of completed). This exceeds the prior X520 result on the same host
(~8.2 M qps, PCIe 2.0 RX-limited — see the X520 reports).

## 2. Objective

Find Runbound's served-throughput ceiling and latency-vs-load curve on the X710 (i40e,
PCIe 3.0, AF_XDP zero-copy), to confirm whether a faster NIC lifts the ~8.2 M qps
ceiling previously measured on the X520 (i82599, PCIe 2.0).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64 cores / 128 threads),
  125 GiB RAM, Intel X710 `enp33s0f0np0` (driver i40e 7.0.6-2-pve, firmware 7.10),
  kernel 7.0.6-2-pve. Runbound **0.16.9**, `xdp: yes`, 32 AF_XDP queues (one XSK per HW
  queue, all zero-copy), `rate-limit: 0`, governor `performance`, NIC flow-control off,
  RSS `udp4 sdfn`. Forward zone → 1.1.1.1 / 8.8.8.8 / 9.9.9.9; `cache-min-ttl 3600` so
  the warmed corpus is answered entirely from the XDP cache fast path.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), dnsmark **2.2.0**,
  Intel X710 `enp66s0f1np1`. Command:
  `dnsmark -s 10.77.0.2 -d queries.txt --ramp --xdp -q --no-tui`.
- **Link:** X710 ↔ X710 (i40e), **10 Gb/s**, direct DAC, no switch. Flow-control off on
  both ends. Generator RSS indirection auto-steered to the bound queues (dnsmark#8 fix,
  see §5). Single deterministic L2 path (one IP per cable, ARP-flux disabled
  `arp_ignore=1 arp_announce=2`).
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt` — 10 000 names, expanded to
  `"<name> A"`, read in random order.
- **Procedure:** 20 s warmup at 10 000 qps (kernel-UDP, populates the cache; all
  subsequent queries are cache hits). Ramp: offered load doubles from 1 000 qps every
  5 s until p50 > 1 ms, then a binary search brackets the knee. Saturation criterion:
  highest 5 s step holding p50 < 1 ms. Served throughput read from receiver NIC
  `ethtool -S` counters, not the generator round-trip.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Max served QPS (peak 2 s) | **10.14 M qps** | receiver NIC `tx_packets` |
| Peak offered QPS | 13.09 M qps (≈ 10 GbE line rate, ~96 B frames) | receiver NIC `rx_packets` |
| p50 / p95 / p99 @ 7.68 M offered | 0.213 / 0.297 / 3.20 ms | dnsmark round-trip (not tcpdump-anchored) |
| p50 / p95 / p99 @ 9.60 M offered | 0.184 / 3.04 / 5.62 ms | dnsmark round-trip |
| Max offered under p50 < 1 ms SLO | 10.56 M qps | dnsmark ramp |
| p50 at saturation (13.05 M offered) | 2.747 ms | dnsmark ramp |
| Success rate (of completed) | 99.88 % NOERROR | dnsmark rcode breakdown |
| Receiver CPU (system) | ~8 % of 128 threads (92 % idle); ≈ 10 cores (XDP busy-poll workers) | `top` on receiver |
| Receiver per-process Runbound CPU | I cannot confirm this (sampling failed) | — |
| Receiver RAM | 18 GiB / 125 GiB | `free` |
| NIC RX drops over session | `rx_missed_errors` +4 total; `rx_dropped` +0 | receiver `ethtool -S` |

Ramp latency curve (per 5 s step, dnsmark round-trip):

| Offered q/s | p50 ms | p95 ms | p99 ms |
|------------:|-------:|-------:|-------:|
| 240 640 | 0.036 | 0.096 | 11.303 |
| 480 000 | 0.129 | 0.246 | 7.071 |
| 960 771 | 0.200 | 0.368 | 3.245 |
| 1 920 517 | 0.290 | 0.428 | 1.413 |
| 3 841 696 | 0.292 | 0.416 | 0.762 |
| 7 683 369 | 0.213 | 0.297 | 3.201 |
| 9 601 470 | 0.184 | 3.037 | 5.623 |
| 10 561 568 | 0.961 | 1.032 | 1.078 |
| 11 040 971 | 1.836 | 1.897 | 1.938 |
| 13 048 738 | 2.747 | 6.939 | 7.071 |

## 5. Interpretation

- Runbound served a peak 10.14 M qps (NIC `tx_packets`) under a 13.09 M qps offered
  load, with `rx_missed_errors` rising by 4 across the whole session — i.e. the NIC
  delivered essentially every offered packet and no measurable RX loss occurred at the
  receiver. The ~3 M qps gap between offered (13.09 M) and served (10.14 M) is queries
  the NIC delivered but Runbound did not answer at that offered rate.
- Total receiver system CPU was ~8 % (92 % idle). Runbound is **not** total-CPU-bound at
  10 M qps on this host. (The ~8 % corresponds to the AF_XDP busy-poll worker cores,
  which spin by design; this is not a headroom measure.)
- The offered peak (13.09 M qps) is approximately the 10 GbE line rate for ~96-byte
  query frames. The served peak (10.14 M qps) is close to the 10 GbE line rate in the
  **response** direction, where frames are larger (~100–110 B). Whether the 10.14 M
  ceiling is the 10 GbE response-direction line rate or Runbound's per-core fast-path
  limit **I cannot confirm this** — it requires re-running on a faster link (25/40 GbE)
  to move the lever. It is stated here as a hypothesis, not a conclusion.
- This result is higher than the X520 measurement on the same receiver host
  (~8.2 M qps, attributed to PCIe 2.0 RX). The X710 (PCIe 3.0) lifted the served peak to
  10.14 M qps.
- Latency: p50 stayed sub-millisecond from ~0.5 M through 9.6 M qps offered (0.18–0.30
  ms) and the p50 < 1 ms SLO held to 10.56 M qps. Tail p99 is elevated at the lowest
  steps (cold-cache / warmup artefact) and at saturation. Latency here is dnsmark
  round-trip, **not** tcpdump-anchored wire truth — tcpdump-anchored p50/p95/p99
  I cannot confirm this for this run.

### Tooling note — dnsmark#8 (found and fixed during this run)

dnsmark `--xdp` initially reported ~100 % loss against a healthy Runbound. Root cause:
the generator binds its AF_XDP RX on a capped subset of queues (q0..N-1), but the NIC's
default RSS indirection table spans all HW queues, and dnsmark query frames use a fixed
UDP source port (12345) — so every response shares one 5-tuple and hashes to a single
RSS queue, frequently outside the bound set. Result: responses landed on an unbound
queue and were dropped before the XSK (false 100 % loss), which also stalled the
closed-loop sender. Receiver NIC counters proved Runbound was answering throughout
(`tx_packets` rising). Fix (dnsmark#8): at XDP setup the generator now steers the RSS
indirection table to span exactly the bound queues (`ethtool -X <if> equal <queue_count>`
— RETA only, no channel reconfig, safe around an active zero-copy bind). With the fix,
round-trip completion is 99.7–99.9 % at moderate rates. Above ~9 M qps the generator's
single active RX queue (one core) saturates and depresses dnsmark's reported completion
% — a generator-side limit, not Runbound. Receiver NIC counters are authoritative for
served throughput in this report.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (Threadripper, X710 enp33s0f0np0) ---
for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $c; done
ethtool -A enp33s0f0np0 rx off tx off
ethtool -N enp33s0f0np0 rx-flow-hash udp4 sdfn
sysctl -w net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2 net.ipv4.conf.all.arp_filter=1
# Runbound 0.16.9, config: xdp:yes, xdp-interface enp33s0f0np0, rate-limit 0,
#   cache-min-ttl 3600, forward 1.1.1.1/8.8.8.8/9.9.9.9
ss -ulpn | grep :53     # ownership check (XDP owns the port; no stray binder)

# --- Generator (dual Xeon E5-2690v2, X710 enp66s0f1np1, 10.77.0.1/24) ---
for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $c; done
ethtool -A enp66s0f1np1 rx off tx off
sysctl -w net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2 net.ipv4.conf.all.arp_filter=1
awk 'NF{print $1" A"}' top-10000-domains.txt > queries.txt
# warmup (populate cache)
dnsmark -s 10.77.0.2 -d queries.txt -Q 10000 -l 20 -q --no-tui
# ramp (dnsmark 2.2.0, dnsmark#8 fix auto-steers generator RSS to bound queues)
dnsmark -s 10.77.0.2 -d queries.txt --ramp --xdp -q --no-tui

# --- Served throughput truth (receiver, sampled every 2 s during the ramp) ---
ethtool -S enp33s0f0np0 | grep -E '(rx_packets|tx_packets|rx_missed_errors):'
# peak 2 s delta: tx 10.14 M/s served, rx 13.09 M/s offered, rx_missed_errors +4 total
```
