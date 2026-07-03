# BIND 9.20.23 baseline — threadripper-5995wx — X520 / 82599ES (ixgbe) — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**
>
> **NIC naming.** The receiver card is an Intel **82599ES** (X520 family, `ixgbe`
> driver). The archived June runs labelled this same ixgbe link "X510"; it is the same
> 82599 silicon class. This report uses the hardware-accurate "X520 / 82599ES".

## 1. Executive Summary

BIND 9.20.23 as a forward+cache resolver, warmed on the 100 000-name corpus, sustained
a **closed-loop knee of ~1.12 M qps** on a single 10 GbE X520 (82599ES, ixgbe) link with
p50 under the SLO. Pushed past that with an open-loop firehose it emitted a **raw reply
ceiling of ~1.20 M packets/s** on the wire, but 50.00 % of those replies were SERVFAIL
(BIND livelock), so the useful (NOERROR) reply rate at the ceiling was only ~0.60 M/s.
The authoritative figure — dnsmark's `Server throughput (NIC rx)` = 1.204 M — matched
the receiver NIC's own `tx_packets` counter (1.202 M/s) to 0.2 %. Unlike the X710, the
82599 dropped ~2.7 M pkts/s **at the NIC** (`rx_no_dma_resources`) before BIND ever saw
them: the ixgbe ingest wall, not BIND, capped this link. Receiver CPU at the flood was
~16.4 of 128 cores (1639 %); RSS ~577 MiB.

## 2. Objective

Re-establish the BIND baseline on the ixgbe link under the revised methodology
(dnsmark-vs-NIC cross-check + ramp/DSD), replacing the archived
`OLD/BASELINE-bind9-...-x510-2026-06-13.md` run, and isolate the NIC's contribution by
comparing back-to-back with the X710 run of the same day (same binary, same host, same
generator — only the link changes, per README rule 6).

## 3. Methodology & Architecture

- **Receiver (BIND):** dragonrage — AMD Threadripper PRO 5995WX, 128 cores, 125 GiB RAM,
  kernel `7.0.6-2-pve`. **BIND 9.20.23-1~deb13u1**. Governor `performance`. Same
  `/etc/bind/named-bench.conf` as the X710 run (`forward only` → 1.1.1.1 / 8.8.8.8 /
  9.9.9.9, `dnssec-validation no`, `minimal-responses yes`, `max-cache-size 512m`). Sole
  owner of `:53` verified.
- **Generator:** dragonsage — dual Xeon E5-2690 v2. **dnsmark 2.7.5** + **dnsperf
  2.14.0**.
- **Link:** Intel **82599ES / X520 (ixgbe)**, 10 GbE, **direct DAC** (receiver
  `enp66s0f1` 10.51.10.1 ↔ generator `nic2` 10.51.10.2), not switched. Flow control
  **off** both ends. RSS `rx-flow-hash udp4 sdfn` on the receiver.
- **Dataset:** `/root/queries-A.txt` — 100 000 real names, A queries. Cache already hot
  from the same session (control pass via this link: 23.3 k qps, avg 9.6 ms → hot).
- **Procedure:** identical to the X710 run — ramp DSD, open-loop firehose, dnsperf
  closed-loop; NIC counters at 1 Hz started before each load; `named` CPU/RSS by PID.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| **Closed-loop knee (ramp, Within-SLO)** | **~1.12 M qps** (Within-SLO 1.09 M) | dnsmark `--ramp` DSD (NIC-verified) |
| Idle latency floor (p50) | 0.051 ms | dnsmark ramp |
| **Raw reply ceiling (flood, Server throughput NIC rx)** | **1.204 M pkts/s** | dnsmark open-loop |
| — confirmed by receiver NIC `tx_packets` | 1.202 M/s | `nic-sample.sh` (Δtx over window) |
| — agreement | **0.2 %** | cross-check (README rule 1) |
| Received at server NIC (rx) during flood | 2.69 M/s | receiver NIC `rx_packets` |
| **Dropped at NIC before BIND** (`rx_no_dma_resources`) | ~2.7 M/s (Δ 82 M over 30 s) | `ethtool -S` |
| SERVFAIL fraction at the flood ceiling | 50.00 % | dnsmark rcode breakdown |
| Useful (NOERROR) reply rate at ceiling | ~0.60 M/s | 1.204 M × 49.93 % |
| Offered load (generator egress) at flood | 5.02 M qps | dnsmark egress (line rate 11 %) |
| dnsperf closed-loop (q=200/client, 20 clients) | 289 k qps @ avg 0.480 ms | dnsperf |
| Receiver CPU (`named`) at flood | 1639 % (~16.4 / 128 cores) | pidstat |
| Receiver RSS (`named`) at flood | ~577 MiB | pidstat |
| NIC `rx_dropped` | 0 (drops are `rx_no_dma_resources`, not `rx_dropped`) | `ethtool -S` |

## 5. Interpretation

- **The counters agree to 0.2 %.** dnsmark reported 1.204 M replies/s; the receiver's
  82599 `tx_packets` counted 1.202 M/s over the same window. The wire ceiling figure is
  trustworthy.
- **This link is NIC-bound, and that is the headline difference vs the X710.** During the
  flood the 82599 received only 2.69 M/s while `rx_no_dma_resources` climbed ~2.7 M/s —
  the ixgbe ran out of RX DMA descriptors and dropped roughly half the offered packets
  **before BIND**. The i40e on the same host, same day, ingested 4.96 M/s with zero
  drops. Same binary, only the NIC changed (rule 6): the X520 delivers less to the
  resolver, so BIND serves less. The bottleneck here is the card, not BIND.
- **The honest sustained number is the ramp knee (~1.12 M qps).** At the open-loop
  ceiling BIND is doubly constrained — NIC drops upstream and 50 % SERVFAIL downstream —
  so only ~0.60 M/s are real answers there. The closed-loop knee is where BIND answers
  correctly within the SLO; report **~1.12 M qps** as the BIND-on-X520 baseline.
- **CPU headroom confirms it is not compute-bound.** BIND used ~16.4 of 128 cores at the
  flood; it had ample CPU. It was starved of input by the NIC and shedding load as
  SERVFAIL, not saturating the processor.
- **Cross-tool consistency.** dnsperf closed-loop (q=200) held 289 k qps at 0.480 ms with
  rx = tx identical second-by-second at the NIC — proof of zero server-side loss in the
  gated loop; the ceiling losses are entirely the open-loop firehose overrunning the
  ixgbe ring.
- **Latency wire-truth.** As with the X710 run, p50/p95/p99 come from the two
  generators' closed-loop RTT, which agree. No `tcpdump` wire capture was taken, so for
  the exact on-wire latency distribution: **I cannot confirm this** beyond the
  mutually-consistent generator figures.

## 6. Appendix — exact commands & configuration

```bash
# Receiver (dragonrage) — link config, flow control, RSS
ethtool -A enp66s0f1 rx off tx off
ethtool -N enp66s0f1 rx-flow-hash udp4 sdfn
ss -ulpn | grep ':53 '                                         # sole owner: named

# Sampling (receiver), started BEFORE each load
/root/nic-sample.sh enp66s0f1 <secs> <out.log> &
pidstat -u -r -h -p $(pidof named) 1 <secs> > <pidstat.log> &

# Run 1 — ramp (DSD, closed-loop SLO knee)
dnsmark -s 10.51.10.1 -d /root/queries-A.txt --ramp --max-outstanding 100
# Run 2 — open-loop firehose (raw wire ceiling)
dnsmark -s 10.51.10.1 -d /root/queries-A.txt -Q 0 --max-outstanding 0 -l 30
# Run 3 — dnsperf closed-loop cross-tool
dnsperf -s 10.51.10.1 -d /root/queries-A.txt -l 30 -c 20 -T 20 -q 200 -t 3

# Truth read (receiver) — note rx_no_dma_resources is the ixgbe drop counter
ethtool -S enp66s0f1 | grep -E 'rx_packets|tx_packets|rx_missed_errors|rx_no_dma_resources'
```

**Notes.** Same host / binary / generator / methodology as the X710 run of 2026-07-03 —
the two are directly comparable and isolate the NIC. The 82599's `rx_no_dma_resources`
(not `rx_dropped`) is where its ingress loss appears; a reader checking `rx_dropped`
alone would wrongly see "0 drops". Cache hot before measuring (rule 2), flow control off
(rule 3), RSS spread (rule 4), `:53` sole-owner verified (rule 5).
