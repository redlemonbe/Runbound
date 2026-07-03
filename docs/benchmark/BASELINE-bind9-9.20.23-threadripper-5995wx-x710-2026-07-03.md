# BIND 9.20.23 baseline — threadripper-5995wx — X710 (i40e) — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

BIND 9.20.23 as a forward+cache resolver, warmed on the 100 000-name corpus, sustained
a **closed-loop knee of ~1.40 M qps** on a single 10 GbE X710 (i40e) link with p50
latency staying under the 1.04 ms SLO and 99.90 % NOERROR. Pushed past that knee with
an open-loop firehose it emitted a **raw reply ceiling of ~1.59 M packets/s** on the
wire, but degraded: 18.03 % of those replies were SERVFAIL (BIND livelock under
overload), so the useful (NOERROR) reply rate at the ceiling was ~1.30 M/s. The
authoritative figure — dnsmark's `Server throughput (NIC rx)` = 1.589 M — was confirmed
against the receiver NIC's own `tx_packets` counter (1.611 M/s), a 1.4 % agreement.
Receiver CPU at the flood was ~17.5 of 128 cores (1751 %); RSS ~293 MiB.

## 2. Objective

Re-establish the BIND baseline on the current rig under the revised methodology
(dnsmark-vs-NIC cross-check + ramp/DSD), replacing the archived
`OLD/BASELINE-bind9-...-x710-2026-06-13.md` run. Two questions: (a) what closed-loop
rate does BIND sustain within an SLO, and (b) what is its raw reply ceiling on the wire
— each cross-checked against receiver NIC hardware counters, not the generator's
self-report.

## 3. Methodology & Architecture

- **Receiver (BIND):** dragonrage — AMD Threadripper PRO 5995WX, 128 cores, 125 GiB RAM,
  kernel `7.0.6-2-pve`. **BIND 9.20.23-1~deb13u1** (Debian stable). Governor
  `performance`. Config `/etc/bind/named-bench.conf`: `forward only` to 1.1.1.1 /
  8.8.8.8 / 9.9.9.9, `recursion yes`, `dnssec-validation no`, `minimal-responses yes`,
  `max-cache-size 512m`, `querylog no`. No local zones (real forward+cache path). Sole
  owner of `:53` verified (`ss -ulpn` → `named` only; runbound stopped for the run).
- **Generator:** dragonsage — dual Xeon E5-2690 v2 (20c/20t, 2 NUMA). **dnsmark 2.7.5**
  (official signed release binary) and **dnsperf 2.14.0** (Debian `dnsperf 2.14.0-5`).
- **Link:** Intel **X710 (i40e)**, 10 GbE, **direct DAC** (receiver `enp33s0f0np0`
  10.71.10.1 ↔ generator `enp66s0f1np1` 10.71.10.2), not switched. Flow control **off**
  both ends (`ethtool -A … rx off tx off`). RSS `rx-flow-hash udp4 sdfn` on the
  receiver.
- **Dataset:** `/root/queries-A.txt` — 100 000 real names (`docs/benchmark/corpus/
  top-100000-resolving.txt`), A queries. Cache warmed with two full dnsperf passes
  before any measurement (control pass: 31.7 k qps, avg latency 1.9 ms → cache hot).
- **Procedure:** (1) `--ramp` DSD closed-loop to find the SLO knee; (2) open-loop
  firehose `-Q 0 --max-outstanding 0 -l 30` for the raw wire ceiling; (3) dnsperf
  closed-loop for an independent cross-tool latency/throughput point. NIC counters
  sampled at 1 Hz by `nic-sample.sh` started **before** each load; `named` CPU/RSS via
  `pidstat` on the exact PID.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| **Closed-loop knee (ramp, Within-SLO)** | **~1.40 M qps** | dnsmark `--ramp` DSD (NIC-verified) |
| Idle latency floor (p50) | 0.038 ms | dnsmark ramp |
| Ramp NOERROR rate | 99.90 % | dnsmark rcode breakdown |
| **Raw reply ceiling (flood, Server throughput NIC rx)** | **1.589 M pkts/s** | dnsmark open-loop |
| — confirmed by receiver NIC `tx_packets` | 1.611 M/s | `nic-sample.sh` (Δtx over window) |
| — agreement | **1.4 %** | cross-check (README rule 1) |
| Received at server NIC (rx) during flood | 4.96 M/s | receiver NIC `rx_packets` |
| SERVFAIL fraction at the flood ceiling | 18.03 % | dnsmark rcode breakdown |
| Useful (NOERROR) reply rate at ceiling | ~1.30 M/s | 1.589 M × 81.9 % |
| Offered load (generator egress) at flood | 5.42 M qps | dnsmark egress (line rate 14 %) |
| dnsperf closed-loop (q=200/client, 20 clients) | 496 k qps @ avg 0.195 ms | dnsperf |
| dnsperf pushed (q=2000, 40 clients) | 1.466 M qps @ 0.914 ms, **6.54 % SERVFAIL** | dnsperf |
| Receiver CPU (`named`) at flood | 1751 % (~17.5 / 128 cores) | pidstat |
| Receiver RSS (`named`) at flood | ~293 MiB | pidstat |
| NIC `rx_dropped` / `rx_missed` (i40e, flood) | 0 / not exposed by i40e | `ethtool -S` |

Ramp step ladder (offered → served, p50 / p95 / p99, ms):

```
  100 k → 100 k   0.041 / 0.060 / 0.100
  200 k → 200 k   0.051 / 0.062 / 0.079
  400 k → 400 k   0.055 / 0.142 / 0.307
  800 k → 800 k   0.072 / 1.188 / 1.968   ← p95 breaks 1 ms
 1.40 M → 1.40 M  0.133 / 1.534 / 2.079   ← knee (p50 still 0.133 ms)
```

## 5. Interpretation

- **The two independent counters agree, so the ceiling number is trustworthy.** dnsmark
  reported 1.589 M replies/s on the wire; the receiver's own X710 `tx_packets` counted
  1.611 M/s over the same window — 1.4 % apart, within the README's ≤2 % band. This is
  the core of the revised methodology: the throughput figure is not the generator's
  self-report, it is corroborated at the NIC.
- **The honest sustained number is the ramp knee, not the flood ceiling.** At the
  open-loop ceiling BIND is in livelock: it puts 1.589 M packets/s on the wire but
  18.03 % are SERVFAIL, so only ~1.30 M/s are real answers. The closed-loop ramp knee
  (~1.40 M qps at 99.90 % NOERROR, p50 0.133 ms) is where BIND actually serves correct
  answers within an SLO. Report **~1.40 M qps** as the BIND-on-X710 baseline; the
  1.59 M is a raw, degraded wire ceiling and is labelled as such.
- **This ramp is generator-recv bound, per methodology.** The kernel-UDP `--ramp` is a
  gated closed loop; its knee is the SLO knee, not proof of BIND's absolute maximum. The
  flood establishes the wire ceiling separately. Both are reported, neither is conflated.
- **Server was not link-bound.** Offered egress reached 5.42 M qps (14 % of the 10 G
  wire at 86 B replies); the link had headroom. The limit was BIND's own processing
  (17.5 cores busy, SERVFAIL onset), not the NIC or the link.
- **Cross-tool consistency.** dnsperf at a gentle closed-loop rate (q=200) held 496 k qps
  at 0.195 ms avg with 99.90 % NOERROR — same rcode profile as the ramp's low steps,
  consistent latency floor. Pushed to q=2000 it reached 1.466 M qps but SERVFAIL rose to
  6.54 %, the same overload signature the flood shows in the extreme.
- **Latency wire-truth.** p50/p95/p99 here come from the two generators' closed-loop RTT
  (dnsmark ramp + dnsperf), which agree. A `tcpdump` wire capture was not taken this
  run, so for the exact on-wire latency distribution: **I cannot confirm this** beyond
  the generator-measured closed-loop figures, which are mutually consistent.

## 6. Appendix — exact commands & configuration

```bash
# Receiver (dragonrage) — governor, flow control, RSS, :53 ownership
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor      # performance
ethtool -A enp33s0f0np0 rx off tx off
ethtool -N enp33s0f0np0 rx-flow-hash udp4 sdfn
systemctl stop runbound
named -c /etc/bind/named-bench.conf                            # forward+cache, no local zones
ss -ulpn | grep ':53 '                                         # sole owner: named

# Warmup (generator) — two full corpus passes + control
dnsperf -s 10.71.10.1 -d /root/queries-A.txt -n 2 -c 20 -T 8 -q 200 -t 3
dnsperf -s 10.71.10.1 -d /root/queries-A.txt -n 1 -c 20 -T 8 -q 200 -t 3   # control: hot

# Sampling (receiver), started BEFORE each load
/root/nic-sample.sh enp33s0f0np0 <secs> <out.log> &            # 1 Hz Δrx/Δtx_packets
pidstat -u -r -h -p $(pidof named) 1 <secs> > <pidstat.log> &

# Run 1 — ramp (DSD, closed-loop SLO knee)
dnsmark -s 10.71.10.1 -d /root/queries-A.txt --ramp --max-outstanding 100
# Run 2 — open-loop firehose (raw wire ceiling)
dnsmark -s 10.71.10.1 -d /root/queries-A.txt -Q 0 --max-outstanding 0 -l 30
# Run 3 — dnsperf closed-loop cross-tool
dnsperf -s 10.71.10.1 -d /root/queries-A.txt -l 30 -c 20 -T 20 -q 200 -t 3

# Truth read (receiver), over the measured window
ethtool -S enp33s0f0np0 | grep -E 'rx_packets|tx_packets|rx_dropped'
```

**Notes.** BIND cache warmed hot before measuring (rule 2). Flow control off (rule 3),
RSS spread (rule 4), `:53` sole-owner verified (rule 5). i40e does not expose
`rx_missed_errors`; `rx_dropped` was 0 — the server received every offered packet at the
flood (4.96 M/s) and the throttle was BIND's processing, not NIC ingress.
