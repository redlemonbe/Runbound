# Runbound Benchmark — v0.16.11 — Threadripper PRO 5995WX + X710 ×2 (XDP, dual link) — 2026-06-10

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

With **both** X710 10 GbE ports active (two direct DACs, one AF_XDP stack per port on
each side — no bonding), Runbound v0.16.11 served a peak of **13.15 M qps total**
(receiver NIC `tx_packets`, timestamped: 6 565 645 on port0 + 6 585 251 on port1 —
balanced 49.9 / 50.1 %) under an offered total of **13.18 M qps** — an answer ratio of
**99.8 % at peak**. Receiver CPU peaked at ~11 % (89 % idle); RAM 19 GiB / 125 GiB.
The ceiling in this configuration is the **generator**: the dual-Xeon E5-2690 v2
pushes ~13.2 M pps total whether it floods one NIC or two (same total as the
single-link run), so each 10 G link ran at only ~50 % of line rate. Compared with the
single-link run (served capped at 10.09 M by the response-direction line rate),
dual-link raises served throughput by **+30 %** and shows Runbound answering
essentially everything it is given at 11 % CPU — **Runbound's own ceiling on this rig
was not reached.** This resolves the single-link report's open question: the
10.09 M single-link served cap was the link, not the server.

## 2. Objective

Same methodology and rig as the single-link v0.16.11 run, with the second X710 port
brought up on both hosts (dual-link case). Both dnsmark and Runbound drive multiple
NICs natively (dnsmark: one XDP stack per `-s` target; Runbound:
`xdp-interface: <a>,<b>` — one XDP program + 32 XSK workers per port). No bonding or
bridging is involved anywhere.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GiB RAM,
  Intel X710-DA2 — **both ports**: `enp33s0f0np0` (10.77.0.2/24) and `enp33s0f1np1`
  (10.77.1.2/24), i40e 7.0.6-2-pve, fw 7.10, kernel 7.0.6-2-pve. Runbound **0.16.11**
  (release build), `xdp: yes`, `xdp-interface: enp33s0f0np0,enp33s0f1np1` → one XDP
  program per port, 32 zero-copy XSK queues per port (64 workers total).
  `rate-limit: 0`, governor `performance`, flow-control off and RSS `udp4 sdfn` on
  both ports, no local-data, no split-horizon. Forward zone → 1.1.1.1/8.8.8.8/9.9.9.9,
  `cache-min-ttl 3600` (warmed corpus served from the XDP cache).
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20c/40t), **dnsmark 2.2.1**,
  X710 ports `enp66s0f1np1` (10.77.0.1, link 1) and `enp66s0f0np0` (10.77.1.1,
  link 2), governor `performance`, flow-control off. Command:
  `dnsmark -s 10.77.0.2 -s 10.77.1.2 -d queries.txt --ramp --xdp` — one AF_XDP stack
  per target, each routed via its own NIC/subnet.
- **Links:** two X710↔X710 direct DACs, 10 Gb/s each, distinct /24 per cable, cabling
  verified by per-link MAC before the run (`ip neigh`: link 1 → …d6:60, link 2 →
  …d6:62), ARP-flux disabled on both hosts.
- **Dataset / warmup / ramp:** identical to the single-link run — corpus
  `top-10000-domains.txt` as `"<name> A"`, 15–20 s kernel-UDP warmup (99.98 %
  completed), then dnsmark DSS ramp, two runs. Served/offered truth = receiver NIC
  counters summed over both ports, **timestamped** deltas.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Max served QPS, total (peak 2 s, timestamped) | **13 150 896 qps** (port0 6 565 645 + port1 6 585 251) | receiver NIC `tx_packets`, both ports |
| Peak offered QPS, total | 13 177 865 qps | receiver NIC `rx_packets`, both ports |
| Answer ratio at peak | **99.8 %** | served ÷ offered (NIC truth) |
| Port balance at peak | 49.9 % / 50.1 % | per-port `tx_packets` deltas |
| Knee, p50 < 1 ms (per dnsmark stack) | 6 500 187 (run 1) / 6 562 009 (run 2) ≈ **13.0–13.1 M total** | dnsmark ramp ×2 |
| Receiver CPU (system) at peak | ~11 % of 128 threads (min idle 89 %) | `top` sampled during run |
| Receiver RAM | 19 GiB / 125 GiB | `free` |
| NIC RX loss per run | `rx_missed_errors` +26 314 (run 1) / +15 844 (run 2) ≈ 0.002 % of delivered; `rx_dropped` 0 | receiver `ethtool -S`, both ports |
| Success rate (rcode breakdown) | I cannot confirm this (see generator note) | — |

Ramp latency curve (per 5 s step; dnsmark reports **per-stack** offered in dual mode —
total ≈ 2× given the measured port balance):

| Offered q/s (per stack) | ≈ total | p50 ms | p95 ms | p99 ms |
|------------------------:|--------:|-------:|-------:|-------:|
| 200 448 | 0.40 M | 0.036 | 0.077 | 7.379 |
| 399 873 | 0.80 M | 0.043 | 0.239 | 5.123 |
| 800 512 | 1.60 M | 0.201 | 0.371 | 0.477 |
| 1 600 011 | 3.20 M | 0.295 | 0.422 | 0.466 |
| 3 200 915 | 6.40 M | 0.293 | 0.405 | 0.444 |
| 5 786 263 | 11.57 M | 0.212 | 0.283 | 4.671 |
| 6 410 246 | 12.82 M | 0.205 | 0.300 | 3.443 |
| 6 500 187 | 13.00 M | 0.688 | 6.359 | 6.499 |
| 6 512 757 | 13.03 M | 1.389 | 5.979 | 17.951 |

Steps beyond ~6.5 M per stack show unstable percentiles (p50 0.2–6.4 ms swinging
between adjacent steps): the generator is at its own TX ceiling there and its RTT
measurement degrades — a generator artifact, not a receiver signal (the receiver's
NIC counters show 99.8 % answered at peak throughout).

## 5. Interpretation

- **The generator is the ceiling in dual-link, not Runbound and not the links.** The
  dual-Xeon E5-2690 v2 generator pushed ~13.2 M pps **total** — the same total as in
  the single-link run — whether flooding one NIC or two (TX/bus-bound; each 10 G link
  ran at ~50 % of line rate). Runbound answered 99.8 % of that at ~11 % CPU.
- **The single-link served cap is confirmed to be the link.** Single-link: offered
  13.04 M (line rate), served capped at 10.09 M (response-direction line rate).
  Dual-link: same offered total split over two links → response direction has
  headroom → served rises to 13.15 M (+30 %). Runbound's own ceiling on this rig is
  **above 13.15 M qps** and was not reached; per the single-link report's open
  question, the answer is: the link, not the server.
- Latency: p50 stayed in the 0.04–0.30 ms band from 0.4 M to ~12.8 M qps total —
  the same band as single-link — and the p50 < 1 ms knee (~13.0–13.1 M total) sits at
  the generator's own ceiling rather than at a receiver saturation point.
- NIC RX loss was ≈ 0.002 % per run (`rx_missed_errors` bursts during DSS overshoot
  steps, where the generator briefly bursts past its sustainable rate); `rx_dropped`
  stayed 0.
- **Generator-side issues to note (dnsmark):** (a) in dual-stack mode the final
  summary (rcode breakdown, wire-egress guard) was never printed — the process hangs
  in teardown after the knee line and had to be killed (both runs); rcode breakdown is
  therefore unavailable for the dual runs. (b) dnsmark's per-step "offered" is
  per-stack in dual mode while the receiver counters are total — reports must not
  compare them directly. Both filed as dnsmark issues.
- Latency is dnsmark round-trip, not tcpdump-anchored: tcpdump-anchored percentiles
  **I cannot confirm this.**
- To find Runbound's true ceiling on this rig, the offered load must rise: either a
  stronger generator (the Threadripper itself, or a modern EPYC) or a third link/host.
  Projected numbers without that measurement: **I cannot confirm this.**

## 6. Appendix — exact commands & configuration

```bash
# --- Links (verified before the run) ---
# link1: dragonsage enp66s0f1np1 (10.77.0.1) <-> dragonrage enp33s0f0np0 (10.77.0.2)  MAC ...d6:60
# link2: dragonsage enp66s0f0np0 (10.77.1.1) <-> dragonrage enp33s0f1np1 (10.77.1.2)  MAC ...d6:62
ip neigh show 10.77.0.2 ; ip neigh show 10.77.1.2   # one MAC per link, deterministic

# --- Receiver (runbound 0.16.11 release) ---
# runbound.conf — single change vs the single-link run:
#   xdp-interface: enp33s0f0np0,enp33s0f1np1
ethtool -L enp33s0f1np1 combined 32
ethtool -A enp33s0f1np1 rx off tx off
ethtool -N enp33s0f1np1 rx-flow-hash udp4 sdfn
# (port0 already tuned identically; governor performance on all cores)

# --- Generator (dnsmark 2.2.1, one XDP stack per target) ---
dnsmark -s 10.77.0.2 -d queries.txt -Q 10000 -l 20 -q --no-tui      # warmup
dnsmark -s 10.77.0.2 -s 10.77.1.2 -d queries.txt --ramp --xdp -q --no-tui

# --- Served/offered truth (receiver, timestamped deltas, SUM of both ports) ---
# loop: t=$(date +%s.%N); tx = tx_packets(port0)+tx_packets(port1);
# rate = (tx - prev_tx) / (t - prev_t); keep the peak; same for rx_packets.
ethtool -S enp33s0f0np0 | grep -E '(rx_packets|tx_packets|rx_missed_errors|rx_dropped):'
ethtool -S enp33s0f1np1 | grep -E '(rx_packets|tx_packets|rx_missed_errors|rx_dropped):'
```
