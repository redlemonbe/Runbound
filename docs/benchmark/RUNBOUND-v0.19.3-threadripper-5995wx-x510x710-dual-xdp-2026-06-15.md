# Runbound Benchmark — Runbound v0.19.3 `xdp: yes` dual-link X510 + X710 — Threadripper PRO 5995WX — 2026-06-15

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, summed across both links. **`xdp: yes` (AF_XDP fast path)** with a single dnsmark
> multi-NIC AF_XDP generator (`-s` repeated). Companion to the dual-X710 report. Re-run of
> the v0.18.1 mixed dual-link report to add the missing per-query latency; datapath is
> byte-identical across these versions, so throughput reproduces.

## 1. Executive Summary

One **Intel X510 (ixgbe)** link plus one **Intel X710 (i40e)** link driven as two XDP
fast-path links, Runbound v0.19.3 serves a sustained **~20.3 M QPS** (sum of the two
receiver NICs' `tx_packets`) — **~10.1 M (X510) + ~10.18 M (X710)**, each at its 10 G line
rate — with **8.26 GB RSS**. Per-link wire latency, capped sub-saturation (closed-loop
AF_XDP, `rate-limit: 0`, warm cache): **X710/i40e p50 0.073 / p95 0.203 / p99 0.245 ms;
X510/ixgbe p50 0.188 / p95 0.250 / p99 0.256 ms** — both sub-millisecond, 99.8 % NOERROR. By
driving the two links
from **two separate generator cards** (ixgbe + i40e, two PCIe buses), the generator escapes
the single-card ~13.5 M cap of the dual-X710 run, and the receiver answers both 10 G links
at line rate at once. The cap here is the **aggregate link capacity (2 × 10 G ≈ 20 M
small-DNS pps)**, not the server.

## 2. Objective

Measure Runbound's AF_XDP fast path across **two heterogeneous links (ixgbe + i40e) at
once**, including the per-query latency the v0.18.1 report omitted, and — by using two
separate generator cards — push past the single-card generator ceiling that limited the
dual-X710 run.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM,
  `enp66s0f1` (X510 / `ixgbe`, 10.51.10.1) + `enp33s0f0np0` (X710 / `i40e`, 10.71.10.1),
  kernel 6.12.88+deb13. Runbound **v0.19.3**, **`xdp: yes`**, multi-interface
  `xdp-interface: enp66s0f1,enp33s0f0np0` (CSV — one AF_XDP stack per NIC), **32 combined
  queues per port** (2 × 32 = 64 = physical cores), per-port IRQs pinned (X510 → cores 0–31,
  X710 → cores 32–63), `xdp-hugepages: no` (regular-page UMEM), `forward-zone "."`
  → 1.1.1.1 / 8.8.8.8 / 9.9.9.9, no local data, `rate-limit: 0`, warm cache. Governor
  `performance`, flow-control off both ports. Host VMs stopped.
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t). **Single instance,
  multi-NIC AF_XDP**: `-s 10.51.10.1 -s 10.71.10.1 --xdp -Q 0 --max-outstanding 0` for
  throughput; `-Q 3000000 --max-outstanding 800` for latency. Egress NICs `nic2` (ixgbe) +
  `enp66s0f1np1` (i40e) = **two separate generator cards / PCIe buses**.
  `DNSMARK_SPORT_SPREAD=4096`.
- **Links:** one X510 (ixgbe) + one X710 (i40e) 10 GbE direct DAC, isolated, flow-control off.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, warmed on both links. Replies
  1:1 with queries, UDP, ~57 B average (single frame).
- **Procedure:** ~18 s warmup; AF_XDP firehose; throughput = sum of both receiver NICs'
  `tx_packets` over 1 s steady windows (steady t+5…t+21). Latency from a separate capped
  closed-loop AF_XDP run. CPU from `/proc/stat` over the firehose window.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Served X510 link (`enp66s0f1`) | **~10.1 M/s** (10.0–10.16 M) | receiver NIC `tx_packets` |
| Served X710 link (`enp33s0f0np0`) | **~10.18 M/s** | receiver NIC `tx_packets` |
| **Served total** | **~20.3 M peak** (steady ~20.0–20.34 M) | sum of both NICs |
| Latency p50/p95/p99 — X710/i40e link | **0.073 / 0.203 / 0.245 ms** | dnsmark closed-loop AF_XDP, capped |
| Latency p50/p95/p99 — X510/ixgbe link | **0.188 / 0.250 / 0.256 ms** | dnsmark closed-loop AF_XDP, capped |
| Success rate | **99.76 % NOERROR** | dnsmark rcode breakdown |
| NIC drops (`rx_missed_errors`) | **X510 ~33.3 M total; X710 ~23 k** over the run | `ethtool -S` |
| Receiver CPU % | **~13 %** over the firehose window | `/proc/stat` |
| Receiver RAM | **8.26 GB RSS** | `ps -o rss` |

Caveats (per methodology):
- **The X510 ingress dropped ~33.3 M packets** (`rx_missed_errors`) over the run while serving
  ~10.1 M/s. The served figure is the truth; the drops are the generator's ixgbe egress
  offering more than the X510 link's response direction can return (~10 G small-DNS pps), so
  the excess backs up and is dropped at ingress. It is a property of offering past the link's
  return cap, not a server fault. The X710 link (offered ≈ served) dropped ~0.
- **Latency is measured per-link at a capped, sub-saturation rate** (`rate-limit: 0`, warm
  cache, **0 rate-limit events server-side**): both links are sub-millisecond (i40e p99
  0.245 ms, ixgbe p99 0.256 ms). It is dnsmark closed-loop AF_XDP wire RTT — tcpdump cannot
  observe the fast path (XDP bypasses the kernel tap), so rule 7 does not apply there.
  **Latency must be read at a capped rate, not under the firehose**: at full firehose the
  X510 is over-offered past its 10 G return cap (the 33 M ingress drops above), which adds a
  saturation queue tail (a ~3 ms p99) — that is the over-offer artifact, not the service
  latency. dnsmark's closed-loop `--xdp` under-counts *completions* (generator-side), so the
  completion ratio is not a success rate; the sampled RTT is the valid figure.
- The CPU figure is an average over the full firehose window (includes ramp transients), a
  floor on steady-state CPU. The v0.18.1 report measured ~24 % under different conditions
  (host load, build); the difference I cannot fully confirm.

## 5. Interpretation

- **Two heterogeneous links aggregate to ~20.3 M served, ~10 M each at line rate.** Runbound
  binds one AF_XDP stack per NIC (ixgbe and i40e) and answers both 10 G links at their return
  line rate simultaneously.
- **The cap is the aggregate link capacity (2 × 10 G), not the server.** Using two separate
  generator cards lifts the offered load past the single-card ~13.5 M ceiling of the
  dual-X710 run; the receiver then serves ~20 M at ~13 % window-average CPU. The X510 ingress
  drops (~33 M) confirm the generator over-offered on that link beyond its 10 G return cap;
  the served 10.1 M is the link's line rate, not a server limit.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — Runbound v0.19.3, xdp: yes, X510 (ixgbe) + X710 (i40e)
cpupower frequency-set -g performance
for n in enp66s0f1 enp33s0f0np0; do
  ethtool -L $n combined 32; ethtool -A $n rx off tx off; ethtool -N $n rx-flow-hash udp4 sdfn
done
# IRQs: X510 -> cores 0-31, X710 -> cores 32-63 (one per core); ulimit -l unlimited
# config: xdp: yes, xdp-interface enp66s0f1,enp33s0f0np0, 32 q/port,
#   xdp-hugepages no, forward-zone "." -> 1.1.1.1/8.8.8.8/9.9.9.9, rate-limit 0, no local data
runbound -c runbound-bench-x510x710.conf

# Generator (dragonsage) — single multi-NIC AF_XDP instance, two separate cards:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -s 10.71.10.1 -p 53 -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0 -l 18
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -s 10.71.10.1 -p 53 -d top-10000-domains.txt --xdp -Q 3000000 --max-outstanding 800 -l 12

# Throughput truth = sum of both receiver NICs, 1 s windows:
cat /sys/class/net/enp66s0f1/statistics/tx_packets
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets
ethtool -S <nic> | grep rx_missed_errors
# Detach the XDP prog when done:
for n in enp66s0f1 enp33s0f0np0; do ip link set $n xdp off; done
```
