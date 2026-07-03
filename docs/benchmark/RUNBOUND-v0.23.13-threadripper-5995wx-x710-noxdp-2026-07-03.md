# Runbound v0.23.13 — threadripper-5995wx — X710 (i40e) — `xdp:no` — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

Runbound's kernel slow path served an open-loop **~2.865 M qps at 99.96 % NOERROR** on a single X710 link — **without livelock** — using **17.7 % of the host's 128 cores**. dnsperf closed-loop peaks ~878 k under the SLO. Cache-hit service latency at the wire p50 24.6 µs (tcpdump). `Server throughput (NIC rx)` 2.865 M matched receiver NIC tx 2.883 M to 0.6 %.

## 2. Objective

Measure the Runbound kernel (`xdp:no`) slow path on X710, back-to-back with the XDP path and the BIND/unbound baselines.

## 3. Methodology & Architecture

- **Receiver (Runbound v0.23.13):** dragonrage — Threadripper PRO 5995WX, 128 cores, 125 GiB RAM, kernel `7.0.6-2-pve`, governor `performance`. Runbound v0.23.13, `xdp: no` (kernel slow path), `/root/rb-bench-noxdp.conf`: real `forward-zone` 1.1.1.1/8.8.8.8/9.9.9.9, `cache-size 131072`, `rate-limit 0`, interface 0.0.0.0, no `local-data`; started via systemd. `:53` sole owner verified.
- **Generator (dnsmark):** dragonsage (dual Xeon E5-2690 v2), **dnsmark 2.7.7** + **dnsperf 2.14.0**. kernel-UDP generator (no `--xdp`; symmetric with the kernel-path server). Exact: `dnsmark -s 10.71.10.1 -d /root/queries-A.txt --ramp` and `… -Q 0 --max-outstanding 0 -l 20`.
- **Link:** Intel **X710 (i40e)**, 10 GbE, **direct DAC** (receiver `enp33s0f0np0` 10.71.10.1 ↔ generator `enp66s0f1np1` 10.71.10.2), flow control off, RSS `udp4 sdfn`
- **Dataset:** `/root/queries-A.txt` — 100 000 real names (`docs/benchmark/corpus/top-100000-resolving.txt`), warmed before the run.
- **Procedure:** warm ×3 (dnsperf); ramp DSD; open-loop flood (`-Q 0 --max-outstanding 0 -l 20`) with 1 Hz receiver NIC sampling; dnsperf load sweep (q=200/1000/2000/4000); tcpdump at receiver → tshark `dns.time` + `--wire-latency`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Flood served (NIC rx) | 2.865 M pkts/s | dnsmark open-loop |
| — confirmed by receiver NIC tx | 2.883 M/s (**0.6 %**) | nic-sample Δtx |
| NOERROR under flood | 99.96 % (no livelock) | dnsmark rcodes |
| dnsperf sweep peak | 878 k @ q4000 (p50 < 1 ms) | dnsperf |
| Ramp DSD knee (closed-loop, gen-bound) | 320 k (idle p50 0.034 ms) | dnsmark `--ramp` |
| Wire latency cache-hit p50 / p95 / p99 | 24.6 / 105 / 284 µs | tcpdump → tshark `dns.time` |
| wire-latency (server+link) p50 | 28 µs | dnsmark `--wire-latency` |
| Host CPU (flood) | 17.7 % of 128 cores | mpstat (idle ~1 %) |
| Receiver RSS | 541 MiB | pidstat |

## 5. Interpretation

- **Serves 2.865 M/s at 99.96 % NOERROR under the firehose — it does not livelock.** This is the sharp contrast with BIND (which collapses to SERVFAIL). Because Runbound does not degrade, the open-loop NIC-rx doubles as its service rate — ~1.5× unbound (1.91 M) and ~1.9× BIND (useful ~1.47 M) on the same rig.
- **Do not read the ramp knee as the ceiling.** The kernel-UDP `--ramp` DSD reports 320 k, but that is the closed-loop, generator-recv-bound SLO knee — an order of magnitude below the open-loop served rate. The standard kernel-UDP caveat; the served NIC-rx (99.96 % NOERROR) is the service rate.
- **Cross-check** 0.6 %. Cache-hit latency p50 24.6 µs; the tail (p99 284 µs and beyond) is the cache-miss fraction forwarded upstream (internet RTT, not Runbound), per rule 7.

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