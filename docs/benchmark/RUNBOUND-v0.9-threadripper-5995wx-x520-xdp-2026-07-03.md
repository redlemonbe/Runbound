# Runbound v0.9 — threadripper-5995wx — X520/82599ES (ixgbe) — `xdp:yes` — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

Runbound's AF_XDP fast path served **~9.81 M qps at 99.99 % NOERROR on a single 10 GbE X520 (82599ES) link — line rate**, using **8.2 % of the host's 128 cores**. As on the X710, the 10 G wire is the wall, not Runbound. Wire latency p50 34 µs (p95 36 / p99 38 µs). `Server throughput (NIC rx)` 9.810 M matched receiver NIC tx 9.849 M to 0.4 %.

## 2. Objective

Measure the Runbound AF_XDP fast path on the ixgbe link, back-to-back with the X710 XDP run.

## 3. Methodology & Architecture

- **Receiver (Runbound v0.9):** dragonrage — Threadripper PRO 5995WX, 128 cores, 125 GiB RAM, kernel `7.0.6-2-pve`, governor `performance`. Runbound v0.9, `xdp: yes` (AF_XDP fast path), `/etc/runbound/runbound.conf`: real `forward-zone` 1.1.1.1/8.8.8.8/9.9.9.9, `cache-size 131072`, `rate-limit 0`, `xdp-interface enp33s0f0np0,enp66s0f1`, no `local-data`; started via systemd. `:53` sole owner verified.
- **Generator (dnsmark):** dragonsage (dual Xeon E5-2690 v2), **dnsmark 1.0** + **dnsperf 2.14.0**. AF_XDP generator (`--xdp`), egress NIC X710 i40e. Exact: `dnsmark -s 10.51.10.1 -d /root/queries-A.txt --xdp --ramp` and `… --xdp -Q 0 --max-outstanding 0 -l 20`.
- **Link:** Intel **X520 / 82599ES (ixgbe)**, 10 GbE, **direct DAC** (receiver `enp66s0f1` 10.51.10.1 ↔ generator `nic2` 10.51.10.2), flow control off, RSS `udp4 sdfn`
- **Dataset:** `/root/queries-A.txt` — 100 000 real names (`docs/benchmark/corpus/top-100000-resolving.txt`), warmed before the run.
- **Procedure:** warm ×3 (dnsperf); ramp DSD (`--xdp --ramp`); open-loop flood (`--xdp -Q 0 --max-outstanding 0 -l 20`) with 1 Hz receiver NIC sampling; wire latency via `--wire-latency` (tcpdump at the receiver sees nothing — XDP bypasses the kernel stack).

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Ramp knee (NIC-verified) | 9.912 M qps (idle p50 0.036 ms) | dnsmark `--xdp --ramp` |
| Flood served (NIC rx) | 9.810 M pkts/s | dnsmark open-loop |
| — confirmed by receiver NIC tx | 9.849 M/s (**0.4 %**) | nic-sample Δtx |
| NOERROR under flood | 99.99 % | dnsmark rcodes |
| Line rate | **100 % of 10 G** (wire-bound) | dnsmark |
| Wire latency p50 / p95 / p99 | 34 / 36 / 38 µs (server+link) | dnsmark `--wire-latency` |
| Host CPU (flood) | 8.2 % of 128 cores | mpstat (idle ~1.4 %) |
| Receiver RSS | 8.71 GiB | pidstat |
| NIC drops (rx_dropped) | 0 | `ethtool -S` |

## 5. Interpretation

- **Link-bound.** ~9.81 M qps at 8.2 % host CPU, 99.99 % NOERROR — the ixgbe 10 G wire is the ceiling. The XDP fast path reaches line rate on the 82599 just as on the i40e; the ixgbe's heavier ingest (visible on the kernel path) does not bind the XDP path here. Runbound's own XDP ceiling was not reached: **I cannot confirm this**.
- **Cross-check** 0.4 % (dnsmark 9.810 M vs receiver NIC tx 9.849 M).
- **Latency** is `--wire-latency` (server+link); receiver-side tcpdump is empty on the XDP path.

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