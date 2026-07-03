# unbound 1.22.0 baseline — threadripper-5995wx — X710 (i40e) — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

unbound 1.22.0 forward+cache served an open-loop **~1.91 M qps at 99.88 % NOERROR** on a single X710 link (no livelock), using **19.1 % of the host's 128 cores**. dnsperf closed-loop peaks ~1.36 M. Cache-hit wire latency is the lowest of the three kernel resolvers: **p50 12.8 µs**. `Server throughput (NIC rx)` 1.910 M matched receiver NIC tx 1.903 M to 0.4 %.

## 2. Objective

Re-establish the unbound baseline on X710 under the revised methodology, back-to-back with BIND and Runbound.

## 3. Methodology & Architecture

- **Receiver (unbound 1.22.0):** dragonrage — Threadripper PRO 5995WX, 128 cores, 125 GiB RAM, kernel `7.0.6-2-pve`, governor `performance`. unbound 1.22.0, `/etc/unbound/unbound-bench.conf`: forward-only 1.1.1.1/8.8.8.8/9.9.9.9, no local zones, dnssec off, `num-threads 64`, `rrset-cache-size 512m`, SO_REUSEPORT. `:53` sole owner verified.
- **Generator (dnsmark):** dragonsage (dual Xeon E5-2690 v2), **dnsmark 2.7.7** + **dnsperf 2.14.0**. kernel-UDP generator (no `--xdp`; symmetric with the kernel-path server). Exact: `dnsmark -s 10.71.10.1 -d /root/queries-A.txt --ramp` and `… -Q 0 --max-outstanding 0 -l 20`.
- **Link:** Intel **X710 (i40e)**, 10 GbE, **direct DAC** (receiver `enp33s0f0np0` 10.71.10.1 ↔ generator `enp66s0f1np1` 10.71.10.2), flow control off, RSS `udp4 sdfn`
- **Dataset:** `/root/queries-A.txt` — 100 000 real names (`docs/benchmark/corpus/top-100000-resolving.txt`), warmed before the run.
- **Procedure:** warm ×3 (dnsperf); ramp DSD; open-loop flood (`-Q 0 --max-outstanding 0 -l 20`) with 1 Hz receiver NIC sampling; dnsperf load sweep (q=200/1000/2000/4000); tcpdump at receiver → tshark `dns.time` + `--wire-latency`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Flood served (NIC rx) | 1.910 M pkts/s | dnsmark open-loop |
| — confirmed by receiver NIC tx | 1.903 M/s (**0.4 %**) | nic-sample Δtx |
| NOERROR under flood | 99.88 % (no livelock) | dnsmark rcodes |
| dnsperf sweep peak | ~1.36 M @ q1000 | dnsperf |
| Ramp DSD knee (closed-loop, gen-bound) | 498 k (idle p50 0.033 ms) | dnsmark `--ramp` |
| Wire latency cache-hit p50 / p95 / p99 | **12.8** / 25.1 / 38.8 µs | tcpdump → tshark `dns.time` |
| wire-latency (server+link) p50 | 28 µs | dnsmark `--wire-latency` |
| Host CPU (flood) | 19.1 % of 128 cores | mpstat (idle ~1 %) |
| Receiver RSS | 214 MiB | pidstat |

## 5. Interpretation

- **No livelock** (99.88 %), so the flood NIC-rx (1.91 M) is a fair service rate — above BIND (useful ~1.47 M) and below Runbound's kernel path (2.865 M) on X710.
- **Lowest cache-hit latency of the three** (p50 12.8 µs vs BIND 24 µs, Runbound `xdp:no` 24.6 µs) — unbound's in-memory cache lookup is fast; where it trails is sustained throughput and CPU efficiency (~0.10 M served per 1 % host CPU).
- **Ramp knee 498 k is generator-recv bound**, not unbound's ceiling. **Cross-check** 0.4 %.

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