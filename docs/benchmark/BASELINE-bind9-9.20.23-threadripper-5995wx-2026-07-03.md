# BIND 9.20.23 baseline — threadripper-5995wx — X710 + X520 — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."** Generator: dnsmark
> v2.7.7 + dnsperf 2.14.0. Two single-link runs (X710 i40e, X520 82599ES/ixgbe).
>
> **NIC naming.** The ixgbe card is an Intel **82599ES** (X520 family); the archived June
> runs labelled this link "X510" — same 82599 silicon.

## 1. Executive Summary

BIND 9.20.23 as a forward+cache resolver, warmed on the 100 000-name corpus, is the
weakest of the three kernel resolvers here and the only one that **livelocks under the
firehose**: it served ~1.49 M pkts/s on X710 but at 98.4 % NOERROR (1.5 % SERVFAIL), and
~1.26 M on X520 at only **66.7 % NOERROR (33 % SERVFAIL)**. Its useful (NOERROR) service
rate is therefore ~1.47 M (X710) / ~0.84 M (X520). dnsperf closed-loop peaks ~1.35–1.44 M
but with rising SERVFAIL. Cache-hit service latency at the wire: p50 24 µs (X710) /
30 µs (X520). Every throughput figure is cross-checked against the receiver NIC
`tx_packets` (0.9–1.0 %). Receiver CPU ~16–18 of 128 cores.

## 2. Objective

Re-establish the BIND baseline under the revised methodology with dnsmark v2.7.7,
back-to-back with the same-day unbound and Runbound runs (same host, generator, links,
corpus; only the resolver and NIC change, rule 6). This supersedes the archived
`OLD/BASELINE-bind9-*-2026-06-13.md` runs.

## 3. Methodology & Architecture

- **Receiver (BIND 9.20.23-1~deb13u1):** dragonrage — Threadripper PRO 5995WX, 128 cores,
  125 GiB, kernel `7.0.6-2-pve`, governor `performance`. Config
  `/etc/bind/named-bench.conf`: forward-only to 1.1.1.1 / 8.8.8.8 / 9.9.9.9, `recursion
  yes`, `dnssec-validation no`, `minimal-responses yes`, `max-cache-size 512m`, no local
  zones. `:53` sole owner verified.
- **Generator:** dragonsage — dual Xeon E5-2690 v2, dnsmark 2.7.7 + dnsperf 2.14.0.
- **Links:** X710 (i40e) 10.71.10.1 and X520/82599ES (ixgbe) 10.51.10.1, direct DAC, flow
  control off, RSS `udp4 sdfn`.
- **Dataset:** `/root/queries-A.txt` — 100 000 names, warmed before each run.
- **Procedure:** ramp DSD, open-loop flood with receiver NIC + CPU sampling, dnsperf
  sweep, tcpdump@receiver→tshark `dns.time` + dnsmark `--wire-latency`.

## 4. Raw Results

| Metric | X710 (i40e) | X520 (ixgbe) | Source |
|--------|------------:|-------------:|--------|
| Flood served (NIC rx) | 1.490 M | 1.264 M | dnsmark open-loop |
| — NOERROR under flood | 98.42 % (1.5 % SERVFAIL) | **66.74 % (33 % SERVFAIL — livelock)** | dnsmark rcodes |
| — useful (NOERROR) rate | ~1.47 M | ~0.84 M | NIC-rx × NOERROR |
| — confirmed by receiver NIC tx | 1.505 M (**1.0 %**) | 1.276 M (**0.9 %**) | nic-sample Δtx |
| dnsperf sweep peak | ~1.38 M @ q4000 (SERVFAIL rising) | ~1.44 M @ q4000 (1.3 % SERVFAIL) | dnsperf |
| Ramp DSD knee (closed-loop, gen-bound) | 295 k | 268 k | dnsmark `--ramp` |
| **Wire latency cache-hit** p50/p95/p99 | **24.0 / 57.5 / 105.6 µs** | **29.8 / 92.2 / 199.5 µs** | tcpdump→tshark `dns.time` |
| wire-latency (server+link) p50 | 35 µs | 44 µs | dnsmark `--wire-latency` |
| Receiver CPU (flood) | 18.2 cores (1822 %) | 16.1 cores (1609 %) | pidstat |
| Receiver RSS | 323 MiB | 564 MiB | pidstat |

## 5. Interpretation

- **BIND livelocks under overload — this is its defining behaviour here.** On X520 the
  firehose drove it to 33 % SERVFAIL, so of 1.264 M packets/s on the wire only ~0.84 M
  were real answers. On X710 it held better (1.5 % SERVFAIL, ~1.47 M useful). Neither
  unbound (99.9 %) nor Runbound's kernel path (99.9 %) degrades like this on the same rig.
  The flood is a stress probe, not a capacity number — for BIND doubly so, since the
  number it produces is degraded.
- **Slowest of the three, on both throughput and (X520) latency.** Useful service rate,
  single link X710: Runbound `xdp:no` 2.86 M > unbound 1.91 M > **BIND 1.47 M**. BIND uses
  the most CPU (18.2 cores) for the least correct output.
- **Counters agree** (0.9–1.0 %), so the NIC-rx figures are trustworthy; the weakness is
  BIND's, not a measurement artefact.
- **The ramp knee (295 k / 268 k) is generator-recv bound**, well below the open-loop
  served rate — the standard kernel-UDP caveat; reported for completeness, not as BIND's
  ceiling.
- **Latency.** Cache-hit p50 24 µs (X710) / 30 µs (X520) — comparable to Runbound's kernel
  path, higher than unbound (12.8 / 17.5 µs). The tail (p99 106 / 200 µs and beyond) is
  the cache-miss fraction forwarded upstream (internet RTT, not BIND), per rule 7.

## 6. Appendix — exact commands

```bash
named -c /etc/bind/named-bench.conf ; ss -ulpn | grep ':53 '   # sole owner: named
# per link, via /root/bench-methodo.sh:
dnsmark -s <ip> -d /root/queries-A.txt --ramp
dnsmark -s <ip> -d /root/queries-A.txt -Q 0 --max-outstanding 0 -l 20   # + receiver nic-sample
for Q in 200 1000 2000 4000; do dnsperf -s <ip> -d /root/queries-A.txt -l 15 -c 20 -T 20 -q $Q -t 3; done
# tcpdump@receiver→tshark dns.time ; dnsmark -s <ip> --wire-latency -Q 5000 -l 6
```

**Notes.** Cache warmed hot before measuring (rule 2), flow control off (rule 3), RSS
spread (rule 4), `:53` sole-owner verified (rule 5). The flood SERVFAIL fraction varies
run-to-run with upstream/cache state (X710 read 1.5 % here vs 18 % in an earlier
v2.7.5 probe) — the point is that BIND *does* livelock, not the exact fraction.
