# unbound 1.22.0 baseline — threadripper-5995wx — X710 + X520 — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."** Generator: dnsmark
> v2.7.7 + dnsperf 2.14.0. Two single-link runs (X710 i40e, X520 82599ES/ixgbe).

## 1. Executive Summary

unbound 1.22.0 as a forward+cache resolver, warmed on the 100 000-name corpus, served an
open-loop **~1.91 M qps (X710) / ~1.46 M (X520) at 99.9 % NOERROR** — it does not
livelock under the firehose. dnsperf closed-loop peaks around ~1.36 M (X710) / ~1.18 M
(X520). Cache-hit service latency at the wire is the lowest of the three kernel
resolvers: **p50 12.8 µs (X710) / 17.5 µs (X520)**. Every throughput figure is
cross-checked against the receiver NIC `tx_packets` (0.4 % agreement). Receiver host CPU
~19–20 % of 128 cores; RSS ~0.2–0.5 GiB.

## 2. Objective

Re-establish the unbound baseline under the revised methodology (dnsmark-vs-NIC
cross-check, ramp DSD, flood overload probe, tcpdump latency) with dnsmark v2.7.7,
back-to-back with the same-day BIND and Runbound runs — same host, generator, links,
corpus; only the resolver and NIC change (rule 6).

## 3. Methodology & Architecture

- **Receiver (unbound 1.22.0):** dragonrage — Threadripper PRO 5995WX, 128 cores,
  125 GiB, kernel `7.0.6-2-pve`, governor `performance`. Config
  `/etc/unbound/unbound-bench.conf`: parity with BIND — forward-only to 1.1.1.1 /
  8.8.8.8 / 9.9.9.9, no local zones, dnssec off, `num-threads 64`, `rrset-cache-size
  512m`, `msg-cache-size 256m`, SO_REUSEPORT. `:53` sole owner verified.
- **Generator:** dragonsage — dual Xeon E5-2690 v2, dnsmark 2.7.7 + dnsperf 2.14.0.
- **Links:** X710 (i40e) 10.71.10.1 and X520/82599ES (ixgbe) 10.51.10.1, direct DAC, flow
  control off, RSS `udp4 sdfn`.
- **Dataset:** `/root/queries-A.txt` — 100 000 names, warmed before each run.
- **Procedure:** ramp DSD, open-loop flood with receiver NIC + CPU sampling, dnsperf
  sweep (q=200/1000/2000/4000), tcpdump@receiver→tshark `dns.time` + dnsmark
  `--wire-latency`.

## 4. Raw Results

| Metric | X710 (i40e) | X520 (ixgbe) | Source |
|--------|------------:|-------------:|--------|
| **Flood served (NIC rx)** | **1.910 M** | **1.464 M** | dnsmark open-loop |
| — NOERROR under flood | 99.88 % | 99.89 % | dnsmark rcodes (no livelock) |
| — confirmed by receiver NIC tx | 1.903 M (**0.4 %**) | 1.470 M (**0.4 %**) | nic-sample Δtx |
| dnsperf sweep peak | ~1.36 M @ q1000 | ~1.18 M @ q1000 | dnsperf |
| Ramp DSD knee (closed-loop, gen-bound) | 498 k | 605 k | dnsmark `--ramp` |
| **Wire latency cache-hit** p50/p95/p99 | **12.8 / 25.1 / 38.8 µs** | **17.5 / 58.4 / 100.9 µs** | tcpdump→tshark `dns.time` |
| wire-latency (server+link) p50 | 28 µs | 35 µs | dnsmark `--wire-latency` |
| Receiver host CPU (flood) | 19.1 % of 128 c | 20.4 % of 128 c | mpstat (idle ~1 %) |
| Receiver RSS | 214 MiB | 521 MiB | pidstat |

## 5. Interpretation

- **Counters agree, so the figures are trustworthy.** dnsmark's flood NIC-rx matches the
  receiver's own `tx_packets` to 0.4 % on both links.
- **unbound does not livelock under the firehose** (99.9 % NOERROR), so its flood NIC-rx
  is a fair open-loop service rate: ~1.91 M (X710) / ~1.46 M (X520). That places it
  **above BIND** (X710 1.49 M @ 98.4 %, X520 1.26 M @ 66.7 % — BIND livelocks) and
  **below Runbound's kernel path** (X710 2.86 M, X520 2.18 M) on the same rig.
- **Lowest cache-hit latency of the three.** At p50 12.8 µs (X710) unbound's cache-hit
  service latency is below BIND (24 µs) and Runbound `xdp:no` (24.6 µs) — unbound's
  in-memory cache lookup is fast; where it falls behind is sustained throughput under
  load, not per-hit latency.
- **The ramp knee is generator-recv bound, not unbound's ceiling** (498 k / 605 k
  closed-loop vs 1.9 M / 1.46 M open-loop served). Same methodology caveat as the other
  kernel resolvers; the open-loop NIC-rx is the service rate.
- **Link effect.** Same binary, only the NIC changes: i40e delivers more to unbound
  (1.91 M served) than ixgbe (1.46 M) — the ixgbe ingest path is heavier, as in every
  other resolver this day.

## 6. Appendix — exact commands

```bash
unbound-checkconf /etc/unbound/unbound-bench.conf && unbound -c /etc/unbound/unbound-bench.conf
ss -ulpn | grep ':53 '                                   # sole owner: unbound
# per link (10.71.10.1 / enp33s0f0np0, 10.51.10.1 / enp66s0f1), via /root/bench-methodo.sh:
dnsmark -s <ip> -d /root/queries-A.txt --ramp
dnsmark -s <ip> -d /root/queries-A.txt -Q 0 --max-outstanding 0 -l 20   # + receiver nic-sample
for Q in 200 1000 2000 4000; do dnsperf -s <ip> -d /root/queries-A.txt -l 15 -c 20 -T 20 -q $Q -t 3; done
# tcpdump@receiver→tshark dns.time ; dnsmark -s <ip> --wire-latency -Q 5000 -l 6
```

**Notes.** Cache warmed hot before measuring (rule 2), flow control off (rule 3), RSS
spread (rule 4), `:53` sole-owner verified (rule 5). Flood is an overload probe; unbound
happens not to degrade (99.9 % NOERROR) so its NIC-rx doubles as the open-loop service
rate. **Host CPU** is whole-machine `mpstat` utilisation (`usr+nice+sys+irq+soft`) over
128 cores during the flood, including softirq/NIC cost, VM `%guest` excluded (idle
~1 %). unbound's ~19–20 % for ~1.9/1.46 M served ≈ 0.10 M qps per 1 % host CPU — below
Runbound's kernel path (~0.16 M/%) and far below its fast path (~0.97 M/%). See README
"CPU accounting".
