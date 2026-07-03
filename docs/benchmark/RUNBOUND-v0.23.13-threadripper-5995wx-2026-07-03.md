# Runbound v0.23.13 — threadripper-5995wx — X710 + X520 — 2026-07-03

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."** Generator: dnsmark
> v2.7.7 + dnsperf 2.14.0. Five runs: `xdp:no` (kernel slow path) and `xdp:yes` (AF_XDP
> fast path) on each of the X710 (i40e) and X520 (82599ES / ixgbe) links, plus a
> dual-link XDP run.

## 1. Executive Summary

On a single 10 GbE link Runbound's **AF_XDP fast path serves ~9.85 M qps at 99.99 %
NOERROR — line-rate — using ~6 of 128 cores**; the link, not Runbound, is the wall.
**Dual-link (X710+X520) reaches ~20.3 M qps** (ramp) / 19.4 M (flood), 99 % of the
combined 20 Gb/s wire, at ~22 cores. Runbound's **kernel slow path (`xdp:no`) serves
~2.86 M qps (X710) / 2.18 M (X520) at 99.9+ % NOERROR without livelock** — already ~1.5×
unbound and ~1.9× BIND on the same rig (see the BIND and unbound baselines of the same
day). Every throughput figure is cross-checked against the receiver NIC hardware
counters (agreement 0.1–0.6 %). Cache-hit service latency at the wire: p50 24–25 µs
(kernel path, tcpdump) and p50 30–34 µs (XDP path, generator SO_TIMESTAMPING).

## 2. Objective

Re-benchmark Runbound under the revised methodology (dnsmark-vs-NIC cross-check, ramp
DSD, flood as overload probe, tcpdump/wire-latency) with the current generator
(dnsmark v2.7.7), across both datapaths and both NICs, back-to-back with the BIND and
unbound baselines of the same day so the numbers are directly comparable.

## 3. Methodology & Architecture

- **Server (Runbound v0.23.13):** dragonrage — AMD Threadripper PRO 5995WX, 128 cores,
  125 GiB RAM, kernel `7.0.6-2-pve`. Governor `performance`. Config: real
  `forward-zone` to 1.1.1.1 / 8.8.8.8 / 9.9.9.9, `cache-size 131072`, `cache-min-ttl
  3600`, `rate-limit 0`, no `local-data`. `xdp:no` run = `/root/rb-bench-noxdp.conf`
  (interface 0.0.0.0); `xdp:yes` run = `/etc/runbound/runbound.conf`
  (`xdp-interface enp33s0f0np0,enp66s0f1`). Started via systemd. `:53` sole owner
  verified each run.
- **Generator:** dragonsage — dual Xeon E5-2690 v2. **dnsmark 2.7.7** (official signed
  release) + **dnsperf 2.14.0**. `--xdp` generator for the fast-path runs, kernel-UDP
  generator for the slow-path runs (never mixed).
- **Links:** Intel **X710 (i40e)** 10 GbE DAC (recv `enp33s0f0np0` 10.71.10.1) and
  **X520 / 82599ES (ixgbe)** 10 GbE DAC (recv `enp66s0f1` 10.51.10.1), both direct, flow
  control off, RSS `udp4 sdfn`.
- **Dataset:** `/root/queries-A.txt` — 100 000 real names, warmed before each run.
- **Truth:** dnsmark `Server throughput (NIC rx)` cross-checked against the receiver
  NIC's own `tx_packets` (1 Hz `nic-sample.sh`, steady t=8..24 window). Latency: tcpdump
  at the receiver → tshark `dns.time` (kernel path) and dnsmark `--wire-latency` (both
  paths).

## 4. Raw Results

**Fast path (`xdp:yes`, AF_XDP) — the throughput number is the ramp/flood NIC-verified rate:**

| Link | Ramp knee (NIC-verified) | Flood served (NIC rx) | dnsmark vs recv NIC tx | NOERROR | Line rate | CPU / RSS | Wire latency p50/p95/p99 |
|------|-------------------------:|----------------------:|:----------------------:|--------:|----------:|-----------|--------------------------|
| X710 (i40e) | 9.85 M qps | 9.848 M | 9.848 vs 9.882 M = **0.3 %** | 99.99 % | **100 % of 10 G** | ~6.0 cores / 8.77 GiB | 31 / 183 / 233 µs |
| X520 (ixgbe) | 9.91 M qps | 9.810 M | 9.810 vs 9.849 M = **0.4 %** | 99.99 % | **100 % of 10 G** | ~6.0 cores / 8.71 GiB | 34 / 36 / 38 µs |
| **Dual-link** | **20.33 M qps** | 19.415 M | 19.415 vs 19.480 M = **0.4 %** | 99.99 % | **99 % of 20 G** | ~21.9 cores / 8.66 GiB | 30 / 183 / 233 µs |

Both single links are **wire-bound** (10 G saturated at 103 B replies → ~9.85 M/s
ceiling); Runbound is far from its own limit (~6 cores). The dual-link aggregate (X710
9.886 M + X520 9.594 M = 19.48 M received tx) is 99 % of the 20 G wire — again the links,
not Runbound (~22 cores), are the wall.

**Slow path (`xdp:no`, kernel) — flood NIC-rx is the open-loop service rate; ramp DSD is
generator-recv bound (see §5):**

| Link | Flood served (NIC rx) | NOERROR | dnsmark vs recv NIC tx | dnsperf sweep max | CPU / RSS | tcpdump p50/p95/p99 | wire-lat p50 |
|------|----------------------:|--------:|:----------------------:|------------------:|-----------|---------------------|-------------:|
| X710 (i40e) | **2.865 M** | 99.96 % | 2.865 vs 2.883 M = **0.6 %** | 878 k @ p50<1 ms | ~13.7 cores / 541 MiB | 24.6 / 105 / 284 µs | 28 µs |
| X520 (ixgbe) | **2.184 M** | 99.95 % | 2.184 vs 2.187 M = **0.1 %** | 880 k | ~11.1 cores / 527 MiB | 25.2 / 77 / 132 µs | 36 µs |

Kernel-path ramp DSD knees (closed-loop, generator-recv bound, **not** the server
ceiling): X710 320 k, X520 379 k. See §5.

## 5. Interpretation

- **The fast path is link-bound, not server-bound.** At ~9.85 M qps per 10 G link
  Runbound uses ~6 of 128 cores at 99.99 % NOERROR; the 10 G wire (103 B replies) is the
  ceiling. To measure Runbound's own XDP ceiling would need >10 G of egress. On this rig,
  **I cannot confirm** the fast-path saturation point — it was never reached. The
  dual-link run doubling to ~19.4 M (99 % of 20 G) at ~22 cores is consistent with the
  fast path scaling linearly with offered wire.
- **The slow path does not livelock — this is the sharp contrast with BIND.** Under the
  open-loop firehose Runbound `xdp:no` serves 2.865 M (X710) / 2.184 M (X520) replies/s at
  **99.9+ % NOERROR**. BIND on the same rig collapses to 98.4 % (X710) / 66.7 % (X520)
  NOERROR (1.5 % / 33 % SERVFAIL livelock); unbound holds ~99.9 %. So Runbound's kernel
  path both serves more and stays correct under overload. Useful (NOERROR) service rate,
  single link X710: **Runbound 2.86 M > unbound 1.91 M > BIND 1.47 M** — Runbound ~1.5×
  unbound, ~1.9× BIND, consistent with the archived "~2× references" ordering.
- **Do not read the kernel-path ramp knee as Runbound's capacity.** The kernel-UDP
  `--ramp` DSD reports 320 k (X710) / 379 k — but that is the closed-loop, generator-recv
  bound SLO knee, an order of magnitude below what the open-loop flood shows the server
  actually serving (2.865 M). This is the exact methodology caveat: for a fast kernel
  resolver the closed-loop kernel-UDP knee under-measures; the open-loop NIC-rx (with
  99.9 % NOERROR confirming no degradation) is the service ceiling.
- **Cross-checks hold across all five runs** (0.1–0.6 %), including the XDP runs: the
  receiver's `/sys tx_packets` tracks the AF_XDP datapath on this i40e/ixgbe, so
  dnsmark's `Server throughput (NIC rx)` is corroborated at the NIC, not self-reported.
- **Latency.** Kernel-path cache-hit service latency at the wire (tcpdump `dns.time`,
  server-only): p50 24.6 µs (X710) / 25.2 µs (X520). Fast-path latency (dnsmark
  `--wire-latency`, server+link, since XDP bypasses the receiver stack so tcpdump sees
  nothing): p50 31 µs (X710) / 34 µs (X520). The two paths are in the same tens-of-µs
  class; the XDP figure is server+link so not directly comparable to the tcpdump
  server-only figure.

## 6. Appendix — exact commands

```bash
# Server switch (dragonrage), verify :53 each time
systemctl stop runbound; ip link set enp33s0f0np0 xdp off; ip link set enp66s0f1 xdp off  # before kernel run
cp /root/rb-bench-noxdp.conf /etc/runbound/runbound.conf   # xdp:no   (or the xdp:yes conf)
systemctl start runbound; ss -ulpn | grep ':53 '           # sole owner: runbound

# Per-target run (generator), driven by /root/bench-methodo.sh:
#   warm ×3 (dnsperf), ramp DSD, flood -Q0 --max-outstanding 0 (+ receiver nic-sample & pidstat),
#   dnsperf sweep (kernel only), tcpdump@receiver→tshark dns.time, dnsmark --wire-latency.
dnsmark -s <ip> [-s <ip2>] -d /root/queries-A.txt [--xdp] --ramp
dnsmark -s <ip> [-s <ip2>] -d /root/queries-A.txt [--xdp] -Q 0 --max-outstanding 0 -l 20
dnsmark -s <ip> -d /root/queries-A.txt --wire-latency -Q 5000 -l 6
```

**Notes.** XDP residual detached (`ip link set … xdp off`) before switching to kernel
runs — otherwise a stale XDP prog drops UDP:53. In XDP the receiver-side tcpdump sees no
packets (XDP bypasses the kernel stack), so fast-path latency is the generator-side
`--wire-latency` only, noted as server+link. Flood is an overload probe; for Runbound it
happens not to degrade (99.9 % NOERROR), so its NIC-rx doubles as the open-loop service
rate — unlike BIND, where the flood livelocks and is not a capacity number.
