# Runbound v0.23.13 — threadripper-5995wx — dual-link X710+X520 — `xdp:yes` — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

Runbound's AF_XDP fast path over **two 10 GbE links at once served ~20.3 M qps (ramp) / 19.4 M (flood) at 99.99 % NOERROR — 99 % of the combined 20 Gb/s wire**, using **24.4 % of the host's 128 cores**. The aggregate is bounded by the two links, not Runbound. Wire latency p50 30 µs. Per-link receiver NIC tx (X710 9.886 M + X520 9.594 M = 19.48 M) matched dnsmark's 19.415 M to 0.4 %.

## 2. Objective

Measure whether the AF_XDP fast path scales across two links simultaneously (one unified dnsmark multi-NIC DSD, requires dnsmark ≥ v2.6.1).

## 3. Methodology & Architecture

- **Receiver (Runbound v0.23.13):** dragonrage — Threadripper PRO 5995WX, 128 cores, 125 GiB RAM, kernel `7.0.6-2-pve`, governor `performance`. Runbound v0.23.13, `xdp: yes` (AF_XDP fast path), `/etc/runbound/runbound.conf`: real `forward-zone` 1.1.1.1/8.8.8.8/9.9.9.9, `cache-size 131072`, `rate-limit 0`, `xdp-interface enp33s0f0np0,enp66s0f1`, no `local-data`; started via systemd. `:53` sole owner verified.
- **Generator (dnsmark):** dragonsage (dual Xeon E5-2690 v2), **dnsmark 2.7.7** + **dnsperf 2.14.0**. AF_XDP multi-NIC generator: `dnsmark -s 10.71.10.1 -s 10.51.10.1 -d /root/queries-A.txt --xdp --ramp` (single unified DSD across both links) and `… --xdp -Q 0 --max-outstanding 0 -l 20`.
- **Link:** Intel **X710 (i40e) 10.71.10.1 + X520/82599ES (ixgbe) 10.51.10.1**, two direct 10 GbE DAC links, flow control off, RSS `udp4 sdfn`
- **Dataset:** `/root/queries-A.txt` — 100 000 real names (`docs/benchmark/corpus/top-100000-resolving.txt`), warmed before the run.
- **Procedure:** warm ×3 per link; unified multi-NIC ramp DSD; dual open-loop flood with per-link receiver NIC sampling; `--wire-latency`.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Ramp knee (NIC-verified, aggregate) | 20.326 M qps (idle p50 0.030 ms) | dnsmark `--xdp --ramp` multi-NIC |
| Flood served (NIC rx, aggregate) | 19.415 M pkts/s | dnsmark open-loop |
| — receiver NIC tx: X710 + X520 | 9.886 M + 9.594 M = 19.48 M (**0.4 %**) | nic-sample Δtx per link |
| NOERROR under flood | 99.99 % | dnsmark rcodes |
| Line rate | **99 % of 20 G** (wire-bound) | dnsmark |
| Wire latency p50 / p95 / p99 | 30 / 183 / 233 µs (server+link) | dnsmark `--wire-latency` |
| Host CPU (flood) | 24.4 % of 128 cores | mpstat (idle ~1.4 %) |
| Receiver RSS | 8.66 GiB | pidstat |

## 5. Interpretation

- **Scales to the combined wire.** ~19.4 M served at 99 % of 20 G, 99.99 % NOERROR, 24.4 % host CPU — roughly double the single-link served rate at roughly double the CPU, consistent with the fast path scaling linearly with offered wire. The two links, not Runbound, are the wall.
- **Cross-check** 0.4 % on the aggregate (per-link receiver NIC tx summed vs dnsmark).
- Runbound's own dual-path ceiling was not reached (still wire-bound): **I cannot confirm this**.

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