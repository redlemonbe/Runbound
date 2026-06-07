# Runbound CPU-headroom PROBE (not a methodology-compliant benchmark) — v0.15.3 — Threadripper PRO 5995WX receiver — 2026-06-07

> **NOT a methodology-compliant run.** This is a preliminary CPU-headroom *probe*,
> not the benchmark defined in [README.md](README.md). It deviates on three core
> points: (1) it uses open-loop **flood** (`--max-outstanding 0`), not the required
> warm-up + **ramp-to-saturation**; (2) it does **not** measure at NIC HW counters
> (XDP zero-copy made `ethtool -S` blind and the HW-register read was not resolved);
> (3) latency is dnsmark throughput-mode, not `tcpdump`-anchored. The official
> #176 result must be produced under README.md (ramp, NIC counters, tcpdump) — see
> §5. Values that could not be measured are marked **"I cannot confirm this."**

## 1. Executive Summary

Under the maximum load this generator can offer over X520 dual fibre
(~11–15 M qps, peak 15.35 M, realistic corpus), the Runbound v0.15.3 XDP fast path
on an AMD Threadripper PRO 5995WX consumed **~2–3 % of CPU (≈97 % idle, softirq
≈0.1 %)** and returned NOERROR for the queries it answered. Runbound was **not
saturated**; its fast-path ceiling is materially higher than the offered rate and
**could not be measured** with this generator. The >15.5 M-qps stability gate (#176)
therefore **cannot be confirmed or refuted here** — the generator, not Runbound, is
the limit.

## 2. Objective

#176 gate: confirm Runbound sustains >15.5 M qps with negligible loss on the XDP
fast path. Secondary: characterise the dnsmark generator after its v2.1.0 rework.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Threadripper PRO 5995WX (64 physical cores, 8 NUMA
  nodes), Intel 82599/X520 dual-port 10 GbE, kernel 6.x (pve), Runbound v0.15.3,
  `xdp: yes`, local-data zone (corpus names answered from the eBPF/XSK fast path,
  64 ZC queues), `rate-limit: 0`.
- **Generator (dnsmark):** dual Intel Xeon E5-2690 v2 (20 physical cores / 2 NUMA),
  Intel 82599/X520 dual-port 10 GbE, dnsmark v2.1.0, command:
  `dnsmark -s <ip-A> -s <ip-B> -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0 -l 15`.
- **Link:** X520 dual fibre, direct (two point-to-point 10 GbE), flow-control OFF,
  RSS udp4 sdfn.
- **Dataset:** `benchmark/corpus/top-10000-domains.txt` (10 000 real names, avg 11.8
  chars), read in worker-local order.
- **Procedure:** dnsmark auto warm-up 3 s (XSK bind / ring fill / NIC ramp) then a
  steady-state window; CPU sampled with `mpstat`/`top` on the receiver.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Offered (generator, submitted descriptors) | ~11–15 M qps dual (peak 15.35 M) | dnsmark "Send throughput", reliable submitted counter |
| Receiver CPU under load | **~2–3 % (≈97 % idle, softirq ≈0.1 %)** | `mpstat -P ALL`, `top` on receiver |
| Answered rate (round-trip) | **I cannot confirm this** | generator round-trip is bounded by its own RX-queue accounting (drains 10/40 queues) and the receiver's ZC counters are not visible to `ethtool -S` |
| rcode of answered queries | NOERROR (local-data) | dnsmark rcode breakdown |
| Receiver NIC drops | **I cannot confirm this** | XDP zero-copy: `ethtool -S` rx/tx packet counters do not move on the ZC datapath |
| Latency (throughput mode) | p50 ~3.5 ms, p99 ~14.6 ms | dnsmark — throughput-mode, per-batch timestamps, NOT a latency measurement |

## 5. Interpretation

The only fully defensible measurement is the **receiver CPU**: Runbound's XDP fast
path is **≈97 % idle** while the generator floods at its maximum (~15 M qps). The
work is done in the eBPF/XSK datapath (softirq ≈0.1 %), so the user-space process is
near-idle by design. A server that is 97 % idle at the offered rate is **far from its
ceiling**; the ceiling itself is not observable here because the generator cannot
push harder.

The end-to-end "answered" rate (round-trip) is **not** a valid Runbound throughput
figure: (a) the generator, after its core-cap rework, drains responses on only its
NIC-local queues, and (b) Runbound's ZC RX/TX is invisible to `ethtool -S`. Both are
documented measurement limits, not Runbound behaviour — hence "I cannot confirm
this" for answered rate and NIC drops.

**Generator ceiling (separate finding).** The dnsmark generator reproducibly offers
~15 M qps dual over X520 dual fibre from the Xeon E5-2690 v2 (peak 15.35 M). This is
a per-queue limit of the 82599/ixgbe AF_XDP zero-copy datapath (~0.93 M qps/queue,
**identical** on the AMD host — strong evidence it is NIC/kernel-bound, not
CPU-bound) multiplied by the queues a 2-socket Xeon v2 can drive before the QPI
saturates (10 NIC-local + 6 cross-NUMA = 16). Hand-written ASM for the per-packet
stamper did **not** raise it (it is queue-bound, not fill-bound). Exceeding ~15 M
needs a NIC with a higher per-queue rate (e.g. Intel X710 / i40e, PCIe 3.0) or a CPU
without the QPI 16-queue limit.

**#176 verdict.** Not provable on this bench. Runbound is not the bottleneck (97 %
idle at ~15 M). A definitive >15.5 M number requires a generator that can offer more
than Runbound can absorb — currently unavailable with X520 + Xeon v2.

## 6. Appendix — exact commands & configuration

```bash
# Receiver (Runbound, fast path):
ethtool -A enp33s0f0 rx off tx off; ethtool -A enp33s0f1 rx off tx off
ethtool -N enp33s0f0 rx-flow-hash udp4 sdfn; ethtool -N enp33s0f1 rx-flow-hash udp4 sdfn
runbound /etc/runbound/<local-data>.conf      # xdp: yes, rate-limit: 0

# Generator (dnsmark v2.1.0), governor auto-pinned to performance by dnsmark:
dnsmark -s <ip-A> -s <ip-B> -d top-10000-domains.txt -p 53 \
        --xdp -Q 0 --max-outstanding 0 -l 15
# Reading: dnsmark "Send throughput (egress)" = submitted descriptors (wire truth).
# Receiver load: mpstat -P ALL 1 ; top -bH (Runbound user threads + softirq).
```
