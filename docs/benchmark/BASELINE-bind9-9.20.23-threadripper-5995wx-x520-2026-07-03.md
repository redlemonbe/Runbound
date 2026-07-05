# BIND 9.20.23 baseline — threadripper-5995wx — X520/82599ES (ixgbe) — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

BIND 9.20.23 forward+cache under the open-loop firehose served ~1.264 M pkts/s but at only **66.74 % NOERROR (33 % SERVFAIL) — it livelocks hard** — using **21.7 % of the host's 128 cores**; useful (NOERROR) rate only ~0.84 M. dnsperf reaches ~1.44 M @ q4000 with SERVFAIL. Cache-hit wire latency p50 29.8 µs. `Server throughput (NIC rx)` 1.264 M matched receiver NIC tx 1.276 M to 0.9 %.

## 2. Objective

Re-establish the BIND baseline on the ixgbe link; the worst-case livelock of the suite.

## 3. Methodology & Architecture

- **Receiver (BIND 9.20.23-1~deb13u1):** dragonrage — Threadripper PRO 5995WX, 128 cores, 125 GiB RAM, kernel `7.0.6-2-pve`, governor `performance`. BIND 9.20.23-1~deb13u1, `/etc/bind/named-bench.conf`: `forward only` 1.1.1.1/8.8.8.8/9.9.9.9, `recursion yes`, `dnssec-validation no`, `minimal-responses yes`, `max-cache-size 512m`, no local zones. `:53` sole owner verified.
- **Generator (dnsmark):** dragonsage (dual Xeon E5-2690 v2), **dnsmark 1.0** + **dnsperf 2.14.0**. kernel-UDP generator (no `--xdp`; symmetric with the kernel-path server). Exact: `dnsmark -s 10.51.10.1 -d /root/queries-A.txt --ramp` and `… -Q 0 --max-outstanding 0 -l 20`.
- **Link:** Intel **X520 / 82599ES (ixgbe)**, 10 GbE, **direct DAC** (receiver `enp66s0f1` 10.51.10.1 ↔ generator `nic2` 10.51.10.2), flow control off, RSS `udp4 sdfn`
- **Dataset:** `/root/queries-A.txt` — 100 000 real names (`docs/benchmark/corpus/top-100000-resolving.txt`), warmed before the run.
- **Procedure:** warm ×3 (dnsperf); ramp DSD; open-loop flood (`-Q 0 --max-outstanding 0 -l 20`) with 1 Hz receiver NIC sampling; dnsperf load sweep (q=200/1000/2000/4000); tcpdump at receiver → tshark `dns.time` + `--wire-latency`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Flood served (NIC rx) | 1.264 M pkts/s | dnsmark open-loop |
| — NOERROR under flood | **66.74 % (33 % SERVFAIL — livelock)** | dnsmark rcodes |
| — useful (NOERROR) rate | ~0.84 M | NIC-rx × NOERROR |
| — confirmed by receiver NIC tx | 1.276 M/s (**0.9 %**) | nic-sample Δtx |
| dnsperf sweep peak | ~1.44 M @ q4000 (1.3 % SERVFAIL) | dnsperf |
| Ramp DSD knee (closed-loop, gen-bound) | 268 k (idle p50 0.049 ms) | dnsmark `--ramp` |
| Wire latency cache-hit p50 / p95 / p99 | 29.8 / 92.2 / 199.5 µs | tcpdump → tshark `dns.time` |
| wire-latency (server+link) p50 | 44 µs | dnsmark `--wire-latency` |
| Host CPU (flood) | 21.7 % of 128 cores | mpstat (idle ~1 %) |
| Receiver RSS | 564 MiB | pidstat |

## 5. Interpretation

- **Hardest livelock of the suite:** 33 % SERVFAIL under the firehose, so of 1.264 M packets/s on the wire only ~0.84 M are real answers. The flood is a stress probe, not a capacity number — for BIND doubly so, since the number it produces is degraded.
- Uses the most CPU (21.7 %) for the least correct output — least efficient of the suite.
- **Ramp knee 268 k is generator-recv bound**, not BIND's ceiling. **Cross-check** 0.9 %. Cache-hit latency p50 29.8 µs; tail is cache-miss forward (internet RTT), per rule 7.

## 6. Appendix — exact commands & configuration

```bash
systemctl stop runbound; ip link set <if> xdp off   # detach residual XDP
cp /root/rb-bench-noxdp.conf /etc/runbound/runbound.conf; systemctl start runbound   # (runbound noxdp)
# or: named -c /etc/bind/named-bench.conf   /   unbound -c /etc/unbound/unbound-bench.conf
ss -ulpn | grep ':53 '
dnsmark -s <ip> -d /root/queries-A.txt --ramp
dnsmark -s <ip> -d /root/queries-A.txt -Q 0 --max-outstanding 0 -l 20   # + receiver nic-sample
for Q in 200 1000 2000 4000; do dnsperf -s <ip> -d /root/queries-A.txt -l 15 -c 20 -T 20 -q $Q -t 3; done
tcpdump -i <if> -s 128 --time-stamp-precision=nano -w lat.pcap -c 400000 'udp port 53' &
dnsperf -s <ip> ... -q 200 ; tshark -r lat.pcap -Y 'dns.flags.response==1 && dns.time' -T fields -e dns.time
dnsmark -s <ip> -d /root/queries-A.txt --wire-latency -Q 5000 -l 6
```

**Notes.** Cache warmed hot before measuring (rule 2), flow control off (rule 3), RSS spread (rule 4), `:53` sole-owner verified (rule 5). Host CPU = whole-machine `mpstat` utilisation (`usr+nice+sys+irq+soft`) over 128 cores, softirq/NIC cost included, VM `%guest` excluded (idle ~1 %); see README "CPU accounting".