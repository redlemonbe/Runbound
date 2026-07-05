# Runbound v0.9 — threadripper-5995wx — X710 (i40e) — `xdp:yes` — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

Runbound's AF_XDP fast path served **~9.85 M qps at 99.99 % NOERROR on a single 10 GbE X710 link — line rate** (103 B replies saturate the 10 G wire, ceiling ~9.85 M/s), using **10.1 % of the host's 128 cores** (idle ~1.2 %). The link, not Runbound, is the wall. Wire round-trip latency p50 31 µs (`--wire-latency`, server+link). dnsmark's `Server throughput (NIC rx)` (9.848 M) matched the receiver NIC `tx_packets` (9.882 M) to 0.3 %.

## 2. Objective

Measure the Runbound AF_XDP fast path on a single X710 link under the standard methodology (dnsmark 1.0), back-to-back with the other same-day runs.

## 3. Methodology & Architecture

- **Receiver (Runbound v0.9):** dragonrage — Threadripper PRO 5995WX, 128 cores, 125 GiB RAM, kernel `7.0.6-2-pve`, governor `performance`. Runbound v0.9, `xdp: yes` (AF_XDP fast path), `/etc/runbound/runbound.conf`: real `forward-zone` 1.1.1.1/8.8.8.8/9.9.9.9, `cache-size 131072`, `rate-limit 0`, `xdp-interface enp33s0f0np0,enp66s0f1`, no `local-data`; started via systemd. `:53` sole owner verified.
- **Generator (dnsmark):** dragonsage (dual Xeon E5-2690 v2), **dnsmark 1.0** + **dnsperf 2.14.0**. AF_XDP generator (`--xdp`), egress NIC X710 i40e. Exact: `dnsmark -s 10.71.10.1 -d /root/queries-A.txt --xdp --ramp` and `… --xdp -Q 0 --max-outstanding 0 -l 20`.
- **Link:** Intel **X710 (i40e)**, 10 GbE, **direct DAC** (receiver `enp33s0f0np0` 10.71.10.1 ↔ generator `enp66s0f1np1` 10.71.10.2), flow control off, RSS `udp4 sdfn`
- **Dataset:** `/root/queries-A.txt` — 100 000 real names (`docs/benchmark/corpus/top-100000-resolving.txt`), warmed before the run.
- **Procedure:** warm ×3 (dnsperf); ramp DSD (`--xdp --ramp`); open-loop flood (`--xdp -Q 0 --max-outstanding 0 -l 20`) with 1 Hz receiver NIC sampling; wire latency via `--wire-latency` (tcpdump at the receiver sees nothing — XDP bypasses the kernel stack).

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Ramp knee (NIC-verified) | 9.852 M qps (idle p50 0.030 ms) | dnsmark `--xdp --ramp` |
| Flood served (NIC rx) | 9.848 M pkts/s | dnsmark open-loop |
| — confirmed by receiver NIC tx | 9.882 M/s (**0.3 %**) | nic-sample Δtx |
| NOERROR under flood | 99.99 % | dnsmark rcodes |
| Line rate | **100 % of 10 G** (wire-bound) | dnsmark |
| Wire latency p50 / p95 / p99 | 31 / 183 / 233 µs (server+link) | dnsmark `--wire-latency` |
| Host CPU (flood) | 10.1 % of 128 cores | mpstat (idle ~1.2 %) |
| Receiver RSS | 8.77 GiB | pidstat |
| NIC drops (rx_dropped) | 0 | `ethtool -S` |

## 5. Interpretation

- **Link-bound, not server-bound.** At ~9.85 M qps the 10 G wire (103 B replies) is the ceiling; Runbound sits at 10.1 % host CPU and 99.99 % NOERROR, far from its own limit. Measuring Runbound's own XDP ceiling would need >10 G of egress: on this rig **I cannot confirm** the fast-path saturation point — it was not reached.
- **Cross-check holds** (0.3 %): the receiver's `/sys tx_packets` tracks the AF_XDP datapath on this i40e, so the throughput is corroborated at the NIC, not self-reported.
- **Latency** is the generator-side `--wire-latency` (server+link); a receiver-side tcpdump capture is empty because XDP bypasses the kernel stack, so for a pure server-only latency at the receiver: **I cannot confirm this** on the XDP path.

## 6. Appendix — exact commands & configuration

```bash
systemctl stop runbound; cp /etc/runbound/runbound.conf.xdp-bak /etc/runbound/runbound.conf
systemctl start runbound; ss -ulpn | grep ':53 '   # sole owner: runbound
dnsmark -s <ip> -d /root/queries-A.txt --xdp --ramp
dnsmark -s <ip> -d /root/queries-A.txt --xdp -Q 0 --max-outstanding 0 -l 20   # + receiver nic-sample
dnsmark -s <ip> -d /root/queries-A.txt --wire-latency -Q 5000 -l 6
# receiver host CPU: mpstat 1 12 during the flood (usr+nice+sys+irq+soft)
```

**Notes.** Cache warmed hot before measuring (rule 2), flow control off (rule 3), RSS spread (rule 4), `:53` sole-owner verified (rule 5). Host CPU = whole-machine `mpstat` utilisation (`usr+nice+sys+irq+soft`) over 128 cores, softirq/NIC cost included, VM `%guest` excluded (idle ~1 %); see README "CPU accounting".