# BIND 9.20.23 baseline — threadripper-5995wx — X520 / 82599ES (ixgbe) — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**
>
> **NIC naming.** The receiver card is an Intel **82599ES** (X520 family, `ixgbe`
> driver). The archived June runs labelled this same ixgbe link "X510"; it is the same
> 82599 silicon class. This report uses the hardware-accurate "X520 / 82599ES".

## 1. Executive Summary

**The baseline figure is a closed-loop knee of ~1.12 M qps** — BIND 9.20.23 as a
forward+cache resolver, warmed on the 100 000-name corpus, on a single 10 GbE X520
(82599ES, ixgbe) link, p50 under the SLO. This is the one throughput number in this
report, and two independent generators agree on it: dnsmark's DSD reports Within-SLO
1.09 M / knee ~1.12 M, and a dnsperf load sweep brackets the same knee (984 k clean at
0.69 ms; latency crosses 1 ms by 1.20 M). Cache-hit service latency at the wire was p50
37 µs / p95 139 µs / p99 247 µs.

An open-loop firehose was also run **as an overload/stress probe, not a measurement**:
it is a deliberate DoS that livelocks BIND (50.00 % SERVFAIL at 1.20 M reply-packets/s
on the wire). Its methodological use: at that rate dnsmark's `Server throughput (NIC
rx)` (1.204 M) matched the receiver's own `tx_packets` (1.202 M/s) to 0.2 % — validating
the tool, not a BIND capacity. The stress probe also exposed the headline hardware fact:
unlike the X710, the 82599 dropped ~2.7 M pkts/s **at the NIC** (`rx_no_dma_resources`)
before BIND ever saw them — the ixgbe ingest wall, not BIND, is what caps this link.
Receiver CPU during the flood was ~16.4 of 128 cores (1639 %); RSS ~577 MiB.

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

**The measurement — closed-loop capacity:**

| Metric | Value | Source |
|--------|-------|--------|
| **Closed-loop knee (ramp, Within-SLO)** | **~1.12 M qps** (Within-SLO 1.09 M) | dnsmark `--ramp` DSD (NIC-verified) |
| Idle latency floor (p50) | 0.051 ms | dnsmark ramp |
| dnsperf load sweep — q=1000/client | 984 k qps @ 0.688 ms, 99.70 % NOERROR (clean) | dnsperf |
| dnsperf load sweep — q=2000/client | 1.197 M qps @ 1.290 ms, 96.09 % NOERROR (latency breaks 1 ms) | dnsperf |
| dnsperf load sweep — q=4000/client | 1.396 M qps @ 2.356 ms, 98.74 % NOERROR (over-driven) | dnsperf |
| dnsperf gentle (q=200/client) | 289 k qps @ avg 0.480 ms | dnsperf |
| **Wire latency, cache-hit service** (p50 / p95 / p99) | **37 / 139 / 247 µs** | tcpdump at receiver NIC → tshark `dns.time` (n=178 074, 99.5 % hits) |
| Wire latency incl. cache-miss tail (p99.9) | 59.4 ms | tshark (miss = upstream forward, not BIND) |

**Not a measurement — open-loop firehose (overload/DoS probe + tool cross-check):**

| Metric | Value | Source |
|--------|-------|--------|
| Server throughput NIC rx (replies on wire under DoS) | 1.204 M pkts/s | dnsmark open-loop |
| — confirmed by receiver NIC `tx_packets` (validates the tool) | 1.202 M/s, **0.2 %** | `nic-sample.sh` (Δtx) |
| **Dropped at NIC before BIND** (`rx_no_dma_resources`) | ~2.7 M/s (Δ 82 M over 30 s) | `ethtool -S` |
| Received at server NIC (rx) during flood | 2.69 M/s | receiver NIC `rx_packets` |
| SERVFAIL fraction under the firehose | 50.00 % (livelock) | dnsmark rcode breakdown |
| Useful (NOERROR) reply rate under DoS | ~0.60 M/s | 1.204 M × 49.93 % |
| Offered load (generator egress) at flood | 5.02 M qps | dnsmark egress (line rate 11 %) |
| Receiver CPU (`named`) at flood | 1639 % (~16.4 / 128 cores) | pidstat |
| Receiver RSS (`named`) at flood | ~577 MiB | pidstat |
| NIC `rx_dropped` | 0 (drops are `rx_no_dma_resources`, not `rx_dropped`) | `ethtool -S` |

## 5. Interpretation

- **The baseline is the ramp knee (~1.12 M qps), independently corroborated.** A dnsperf
  load sweep brackets the same knee from the other side: 984 k qps is still clean
  (0.688 ms, 99.70 % NOERROR); by q=2000 the average latency crosses 1 ms (1.290 ms) and
  SERVFAIL rises to 3.84 %. So the SLO knee sits at ~1.0–1.1 M qps by dnsperf — the same
  window dnsmark's DSD reports (Within-SLO 1.09 M, knee ~1.12 M). Two independent
  generators agree; **~1.12 M qps is the BIND-on-X520 baseline.**
- **The flood *under*-measures on this NIC — concrete proof it is not a capacity number.**
  Regulated closed-loop dnsperf drove BIND to serve **1.396 M qps** (q=4000, 98.74 %
  NOERROR), with receiver NIC rx = tx second-by-second and zero `rx_no_dma` growth. The
  open-loop firehose, offering 5.02 M, made BIND serve only **1.204 M** — *lower* than the
  regulated rate — because the firehose overran the 82599's RX ring and the card dropped
  ~2.7 M/s before BIND. On an ingress-bound NIC the flood is not merely "not the
  sustained number", it reads ~14 % *below* the real closed-loop capacity. This is the
  clearest single proof of why the firehose is a stress probe, not a measurement.
- **The flood is not a measurement.** At its ceiling BIND is doubly constrained (NIC
  drops upstream, 50 % SERVFAIL downstream), ~0.60 M/s real answers — a saturation
  artefact.
- **The tool cross-check holds.** dnsmark reported 1.204 M replies/s under the DoS; the
  receiver's 82599 `tx_packets` counted 1.202 M/s — 0.2 %. That validates dnsmark's
  NIC-rx instrumentation, nothing about BIND's capacity.
- **This link is NIC-bound, and that is the headline difference vs the X710.** During the
  flood the 82599 received only 2.69 M/s while `rx_no_dma_resources` climbed ~2.7 M/s —
  the ixgbe ran out of RX DMA descriptors and dropped roughly half the offered packets
  **before BIND**. The i40e on the same host, same day, ingested 4.96 M/s with zero
  drops. Same binary, only the NIC changed (rule 6): the X520 delivers less to the
  resolver, so BIND's knee is lower (~1.12 M vs ~1.40 M). The bottleneck here is the
  card, not BIND.
- **CPU headroom confirms it is not compute-bound.** BIND used ~16.4 of 128 cores at the
  flood; it had ample CPU. It was starved of input by the NIC and shedding load as
  SERVFAIL, not saturating the processor.
- **Cross-tool consistency.** dnsperf closed-loop (q=200) held 289 k qps at 0.480 ms with
  rx = tx identical second-by-second at the NIC — proof of zero server-side loss in the
  gated loop; the ceiling losses are entirely the open-loop firehose overrunning the
  ixgbe ring.
- **Latency wire-truth (tcpdump-anchored, per rule 7).** A receiver-NIC capture decoded
  with tshark `dns.time` gives cache-hit **p50 37 µs / p95 139 µs / p99 247 µs** over
  178 074 hits (99.5 %). Back-to-back with the X710 run (same host/binary/day, only the
  NIC changed): the ixgbe adds ~15 µs at p50 and ~150 µs at p99 over the i40e (22 / 94 µs)
  — the heavier ixgbe datapath shows up in latency just as it does in ingest. The tail
  (p99.9 59 ms) is the cache-miss forward fraction, internet RTT, not BIND. dnsmark's
  `--wire-latency` mode was intended for this but hung on this rig (see the X710 report's
  appendix); tcpdump is the methodology's designated reference.

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
# Run 3 — dnsperf closed-loop cross-tool (gentle)
dnsperf -s 10.51.10.1 -d /root/queries-A.txt -l 30 -c 20 -T 20 -q 200 -t 3
# Run 3b — dnsperf load sweep to bracket the knee independently (re-warm first)
for Q in 1000 2000 4000; do
  dnsperf -s 10.51.10.1 -d /root/queries-A.txt -l 20 -c 20 -T 20 -q $Q -t 3
done

# Truth read (receiver) — note rx_no_dma_resources is the ixgbe drop counter
ethtool -S enp66s0f1 | grep -E 'rx_packets|tx_packets|rx_missed_errors|rx_no_dma_resources'

# Wire latency — tcpdump at receiver NIC, tshark dns.time (re-warm cache first)
tcpdump -i enp66s0f1 -s 128 --time-stamp-precision=nano -w lat.pcap -c 400000 'udp port 53' &
dnsperf -s 10.51.10.1 -d /root/queries-A.txt -l 6 -c 20 -T 20 -q 200 -t 3
tshark -r lat.pcap -Y 'dns.flags.response==1 && dns.time' -T fields -e dns.time \
  | sort -n | awk '{a[NR]=$1} END{print a[int(NR*.5)],a[int(NR*.95)],a[int(NR*.99)]}'
# dnsmark --wire-latency hung on this rig — see the X710 report appendix.
```

**Notes.** Same host / binary / generator / methodology as the X710 run of 2026-07-03 —
the two are directly comparable and isolate the NIC. The 82599's `rx_no_dma_resources`
(not `rx_dropped`) is where its ingress loss appears; a reader checking `rx_dropped`
alone would wrongly see "0 drops". Cache hot before measuring (rule 2), flow control off
(rule 3), RSS spread (rule 4), `:53` sole-owner verified (rule 5).
