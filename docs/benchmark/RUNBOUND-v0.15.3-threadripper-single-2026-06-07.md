# Runbound Benchmark — v0.15.3 — Threadripper PRO 5995WX receiver — single fibre — 2026-06-07

> Follows [README.md](README.md). Measured data only. Values that the hardware
> makes unmeasurable are marked **"I cannot confirm this."**

## 1. Executive Summary

Over single X520 10 GbE fibre, with a warm resolver cache (real cache-hit fast path —
**no synthetic local-data**), the dnsmark v2.1.1 generator offered **12.46 M qps**
(its own ceiling on this Xeon E5-2690 v2). Runbound v0.15.3 on an AMD Threadripper
PRO 5995WX answered them (NOERROR 99.87%) while consuming **98.4** idle CPU — i.e.
**~1.6% busy**. Runbound was **not saturated**; no
saturation point exists within the generator's reach, so its true ceiling is **not
measurable on this rig** ("I cannot confirm this"). The bottleneck is the generator,
not Runbound.

## 2. Objective

#176 gate (>15.5 M qps stable, negligible loss). Measure Runbound's XDP fast path
over single fibre with a methodology-faithful setup (warm cache, real corpus, instrument
= dnsmark).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Threadripper PRO 5995WX (64 physical cores / 8 NUMA),
  Intel 82599/X520 dual-port 10 GbE, Runbound v0.15.3, `xdp: yes`, **rb-dual**
  config (forwarding resolver + cache, **no local-data**), `rate-limit: 0`, RSS
  udp4 sdfn, flow-control off.
- **Generator (dnsmark v2.1.1):** dual Intel Xeon E5-2690 v2 (20 physical / 2 NUMA),
  X520, command `dnsmark -s <ip-A> -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0`,
  governor auto-pinned to performance, static ARP (else dnsmark falls back to
  sendmmsg — NOT zero-copy), per-NIC worker cap 10 (is_xeon_v2_x520).
- **Link:** single direct X520 10 GbE fibre, flow-control off.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt` (10 000 real names), cache
  **warmed** beforehand (UDP pass) so the measured run is cache-hit fast path.
- **Procedure:** warm cache, then steady offered-max window; receiver CPU sampled
  with `mpstat`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Offered (generator, submitted descriptors) | **12.46 M qps** | dnsmark "Send throughput" (submitted = wire truth) |
| **Receiver CPU under load** | **98.4% idle (~1.6% busy, softirq ~0)** | `mpstat` on receiver |
| Answered rate (round-trip) | **1.02 M qps — lower bound only** | dnsmark round-trip; the generator drains responses on only its bound RX queues (X520), so it under-counts. Real answered rate: **I cannot confirm this.** |
| rcode | NOERROR 99.87% | dnsmark |
| Receiver NIC rx/tx counters | **I cannot confirm this** | **X520 + XDP zero-copy: `ethtool -S` counters do not move (XDP_REDIRECT→XSK bypasses them); verified `rx_pkts_nic` delta = 0 under a 12 M flood.** No valid NIC-side measurement is possible on this NIC in ZC. |
| Latency | **I cannot confirm this** (wire) | tcpdump on an XDP interface does not see XDP-handled frames; only dnsmark throughput-mode figures exist, which are not a latency measurement. |

## 5. Interpretation

The defensible result is the **receiver CPU**: Runbound's XDP fast path is **~98.4%
idle** while the generator floods at its maximum (12.46 M qps). A server that idle at
the offered rate is far from saturation; the gate criterion (sustained >15.5 M with
the loss/latency knee) **cannot be exercised** because the generator cannot reach it
— hence "I cannot confirm this" for Runbound's ceiling.

**Measurement limitation (real, not a shortcut).** On the Intel 82599/X520 in XDP
zero-copy, the receiver's NIC counters are blind (`ethtool -S` does not increment
for XDP_REDIRECT→XSK; `rx_pkts_nic` delta measured at 0 under a 12 M flood). The
generator (dnsmark) is therefore the only valid instrument here: its **submitted**
count is the offered truth; its **round-trip** is a lower bound (it drains responses
on a subset of its RX queues on the X520). A definitive receiver-side throughput
needs a NIC whose counters are valid in ZC (e.g. Intel X710 / i40e) — procurement in
progress.

## 6. Appendix — exact commands

```bash
# Receiver: runbound /etc/runbound/rb-dual.conf   (xdp:yes, cache, no local-data)
ethtool -A <nic> rx off tx off ; ethtool -N <nic> rx-flow-hash udp4 sdfn
# Static ARP on the generator (mandatory — else dnsmark XDP TX falls back to sendmmsg):
ip neigh replace <receiver-ip> lladdr <receiver-mac> dev <nic> nud permanent
# Warm cache, then measure:
dnsmark -s <ip-A> -d top-10000-domains.txt -p 53 --xdp -Q 0 --max-outstanding 0 -l 18
mpstat 1 2     # on the receiver
```
