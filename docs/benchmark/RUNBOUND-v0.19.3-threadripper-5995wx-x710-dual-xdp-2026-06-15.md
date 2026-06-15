# Runbound Benchmark — Runbound v0.19.3 `xdp: yes` dual-link X710 — Threadripper PRO 5995WX — 2026-06-15

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, summed across both links. **`xdp: yes` (AF_XDP fast path)** with a single dnsmark
> multi-NIC AF_XDP generator (`-s` repeated). Companion to the mixed dual-link report
> (X510 + X710). Re-run of the v0.18.1 dual-X710 report to add the missing per-query
> latency; datapath is byte-identical across these versions, so throughput reproduces.

## 1. Executive Summary

Both ports of the **Intel X710 (i40e)** card driven as two XDP fast-path links, Runbound
v0.19.3 serves a sustained **~13.50 M QPS** (sum of the two receiver NICs' `tx_packets`),
balanced **~6.75 M + ~6.75 M** per port, with **0 NIC drops** (`rx_missed_errors` = 0 on
both ports) and **8.27 GB RSS**. Per-query wire latency (closed-loop AF_XDP, capped):
**p50 0.100 ms / p95 0.247 ms / p99 0.251 ms**, 99.72 % NOERROR. This is generator-bound,
not Runbound: the generator drives both links from the two ports of its single X710 card,
which share one PCIe bus and cap the aggregate at ~13.5 M pps. Reproduces the archived
dual-X710 figure (12.9–13.15 M).

## 2. Objective

Measure Runbound's AF_XDP fast path across **both X710 ports at once** (single dnsmark
instance, multi-NIC mode), including the per-query latency that the v0.18.1 report omitted,
and confirm where the limit sits.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **both
  Intel X710 ports** `enp33s0f0np0` (10.71.10.1) + `enp33s0f1np1` (10.71.20.1), `i40e`,
  kernel 6.12.88+deb13. Runbound **v0.19.3**, **`xdp: yes`**, multi-interface
  `xdp-interface: enp33s0f0np0,enp33s0f1np1` (CSV — one AF_XDP stack per NIC), **32 combined
  queues per port** (2 × 32 = 64 = physical cores), per-port IRQs pinned (port 0 → cores
  0–31, port 1 → cores 32–63), `xdp-hugepages: no` (regular-page UMEM), `forward-zone "."`
  → 1.1.1.1 / 8.8.8.8 / 9.9.9.9, no local data, `rate-limit: 0`, warm cache. Governor
  `performance`, flow-control RX/TX off, RSS `udp4 sdfn` both ports. Host VMs stopped.
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t). **Single instance,
  multi-NIC AF_XDP**: `-s 10.71.10.1 -s 10.71.20.1 --xdp -Q 0 --max-outstanding 0` for
  throughput; `-Q 3000000 --max-outstanding 800` for the latency samples. Egress NICs
  `enp66s0f1np1` + `enp66s0f0np0` = **the two ports of the generator's single X710 card**.
  `DNSMARK_SPORT_SPREAD=4096`.
- **Links:** two Intel X710 (i40e) 10 GbE direct DACs, isolated, flow-control off both ends.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read,
  warmed on both links. Replies are 1:1 with queries, UDP, ~57 B average (single frame).
- **Procedure:** ~18 s warmup; AF_XDP firehose; throughput = sum of both receiver NICs'
  `tx_packets` over 1 s steady windows (steady t+5…t+22). Latency from a separate capped
  closed-loop AF_XDP run. CPU from `/proc/stat` over the firehose window.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Served port 0 (`enp33s0f0np0`) | **~6.75 M/s** | receiver NIC `tx_packets` |
| Served port 1 (`enp33s0f1np1`) | **~6.75 M/s** | receiver NIC `tx_packets` |
| **Served total** | **~13.50 M sustained** (steady 13.50–13.55 M) | sum of both NICs |
| Latency p50 / p95 / p99 | **0.100 / 0.247 / 0.251 ms** | dnsmark closed-loop AF_XDP wire samples |
| Success rate | **99.72 % NOERROR** | dnsmark rcode breakdown |
| NIC drops (`rx_missed_errors`) | **0 / 0** (both ports) | `ethtool -S` |
| Receiver CPU % | **~10 %** over the firehose window | `/proc/stat` |
| Receiver RAM | **8.27 GB RSS** | `ps -o rss` |

Caveats (per methodology):
- **Latency = dnsmark closed-loop AF_XDP wire RTT (generator TX/RX timestamps).** tcpdump
  cannot observe the AF_XDP fast path — XDP redirects to the XSK before the kernel AF_PACKET
  tap — so the wire RTT is taken at the generator, not via tcpdump (methodology rule 7 is not
  applicable to the fast path for that reason). Measured with `rate-limit: 0` (**0 rate-limit
  events server-side**) on a warm cache; the distribution is sub-millisecond and matches the
  clean single-link i40e run (p50 0.073 / p95 0.203 / p99 0.245 ms). dnsmark's closed-loop
  `--xdp` under-counts *completions* (a generator-side accounting limitation, not the server),
  so the completion ratio is not a success/error rate — the RTT of the sampled responses is
  the valid figure.
- The CPU figure is an average over the full firehose window (includes ramp transients), so
  it is a floor on steady-state CPU; the exact steady-state value I cannot confirm.

## 5. Interpretation

- **Two links aggregate cleanly: ~13.50 M total, balanced 6.75 M + 6.75 M, 0 drops.** Runbound
  binds one AF_XDP stack per NIC and adds no measured per-query penalty at this load (latency
  matches the single-link report).
- **The cap is the generator's single X710 card, not Runbound.** Both generator egress ports
  share one X710 card / one PCIe bus, topping out at ~13.5 M pps aggregate — the same ceiling
  as the archived dual-X710 run. The receiver at ~10 % CPU has the machine in reserve; the
  mixed X510+X710 report, driving from two separate generator cards, reaches ~20 M at the same
  receiver.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — Runbound v0.19.3, xdp: yes, both X710 ports
ip link set enp33s0f1np1 up; ip addr add 10.71.20.1/24 dev enp33s0f1np1
cpupower frequency-set -g performance
for n in enp33s0f0np0 enp33s0f1np1; do
  ethtool -L $n combined 32; ethtool -A $n rx off tx off; ethtool -N $n rx-flow-hash udp4 sdfn
done
# IRQs: port0 -> cores 0-31, port1 -> cores 32-63 (one per core); ulimit -l unlimited
# config: xdp: yes, xdp-interface enp33s0f0np0,enp33s0f1np1, 32 q/port,
#   xdp-hugepages no, forward-zone "." -> 1.1.1.1/8.8.8.8/9.9.9.9, rate-limit 0, no local data
runbound -c runbound-bench-dualx710.conf

# Generator (dragonsage) — single multi-NIC AF_XDP instance:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -s 10.71.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 0 --max-outstanding 0 -l 18
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -s 10.71.20.1 -p 53 -d top-10000-domains.txt --xdp -Q 3000000 --max-outstanding 800 -l 12

# Throughput truth = sum of both receiver NICs, 1 s windows:
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets
cat /sys/class/net/enp33s0f1np1/statistics/tx_packets
ethtool -S <nic> | grep rx_missed_errors
# Detach the XDP prog when done:
for n in enp33s0f0np0 enp33s0f1np1; do ip link set $n xdp off; done
```
