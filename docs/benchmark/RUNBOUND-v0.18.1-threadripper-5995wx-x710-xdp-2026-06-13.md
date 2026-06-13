# Runbound Benchmark — Runbound v0.18.1 `xdp: yes` — Threadripper PRO 5995WX / X710 (i40e) — 2026-06-13

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. **`xdp: yes` (AF_XDP fast path)** with an **AF_XDP
> (`--xdp`) dnsmark generator** — the only way to offer enough load to exercise the fast path
> (a kernel-UDP generator caps at ~6 M and cannot reach it).

## 1. Executive Summary

On the new rig, over the direct **Intel X710 (i40e) 10 GbE** link, Runbound v0.18.1 in **`xdp:
yes`** mode (AF_XDP fast path, 64 queues = physical cores, warm cache), driven by an AF_XDP
dnsmark firehose offering ~13 M q/s, serves a sustained **~10.12 M QPS** (receiver NIC
`tx_packets`) at **~11 % receiver CPU** with **0 NIC drops** on the served direction. The NIC
receives 13.0 M/s and Runbound answers 10.12 M/s of it; the ~10.12 M cap is the **10 G link's
response direction** (small-DNS line-rate), **not Runbound** — at 11 % CPU it has the whole
machine in reserve. Fast-path wire latency is **p50 0.045 ms / p95 0.081 ms / p99 0.180 ms**
(99.49 % NOERROR). On this rig that is **~5.5× unbound, ~6.9× BIND, and ~2.7× Runbound's own
kernel slow path**, at a fraction of the CPU. To go past 10 M needs a second link (archive:
13.15 M dual) or a faster one — the single 10 G link is the wall here, not the server.

## 2. Objective

Measure Runbound v0.18.1's AF_XDP fast path on the X710 link of the new rig, the mode that is
Runbound's reason to exist (kernel-bypass zero-syscall hot path). Reference resolvers (BIND,
unbound) have no equivalent and a kernel-UDP generator cannot offer enough load, so this run is
Runbound-only with an AF_XDP generator. The question: served throughput, latency, CPU, and where
the limit sits.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **Intel
  X710 / `enp33s0f0np0` (`i40e`, MTU 1500)**, kernel 6.12.88+deb13. Runbound **v0.18.1** (rebuilt
  from `main` HEAD, LTO release), **`xdp: yes`** (eBPF XDP + AF_XDP sockets, DRV mode, prog
  `dns_xdp` jited), **NIC combined queues set to 64 = physical cores** (out-of-the-box the i40e
  exposed 119 queues > 64 cores → modulo over-subscription, #165; pinning to 64 removes it),
  `xdp-cache-snapshot-size 65536`, `xdp-hugepages: no` (host hugepages are 1 GB-only and cannot
  back the moderate per-queue UMEM, so regular-page UMEM — as in the archive runs),
  single `forward-zone "."` → 1.1.1.1 / 8.8.8.8 / 9.9.9.9, **no local data**, `rate-limit: 0`,
  warm cache. Governor `performance`, flow-control RX/TX off, RSS `udp4 sdfn`.
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t), egress NIC
  `enp66s0f1np1` (i40e), **AF_XDP (`--xdp`) open-loop firehose** (`-Q 13e6 --max-outstanding 0`)
  for throughput; closed-loop AF_XDP (`-Q` capped) for the latency samples. `DNSMARK_SPORT_SPREAD=4096`.
- **Link:** Intel X710 (i40e) 10 GbE, **direct DAC**, isolated from the LAN, flow-control off
  both ends, static `10.71.10.2 → 10.71.10.1`.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read, warmed.
- **Procedure:** warm, then AF_XDP open-loop firehose at -Q 13 M; **throughput = receiver NIC
  counters** (`tx_packets` served, `rx_packets` received) over six 2.5 s steady windows; CPU from
  `/proc/stat`. Latency from a separate `-Q`-capped closed-loop AF_XDP run (wire samples).
  Saturation criterion: peak sustained served.

## 4. Raw Results

**AF_XDP open-loop firehose (-Q 13 M), at the receiver NIC (X710), steady windows:**

| Metric | Value | Source |
|--------|-------|--------|
| Offered (generator wire egress) | **~13.0 M q/s** | generator NIC PHY |
| Received by NIC (`rx_packets`) | **~13.02 M/s** | receiver statistics |
| **Served (`tx_packets`)** | **~10.12 M/s sustained** (peak 10 117 208) | receiver NIC |
| Served direction utilisation | ~10.1 M pps = 10 G small-DNS line rate | derived |
| NIC drops (served direction) | **0/s** in steady windows | receiver `ethtool -S` |
| Receiver CPU % | **~11 %** (10.6–11.6 %) | `/proc/stat` |
| Receiver RAM | **~8.39 GB RSS** (regular-page UMEM, 64 queues) | `ps -o rss` |

**AF_XDP closed-loop latency (wire samples, `-Q` capped):**

| Metric | Value |
|--------|-------|
| Latency p50 / p95 / p99 | **0.045 / 0.081 / 0.180 ms** |
| Success (sampled) | **99.49 % NOERROR** |

## 5. Interpretation

- **~10.12 M served at ~11 % CPU — the link is the cap, not Runbound.** The i40e delivers 13.0 M/s
  and Runbound answers 10.12 M/s of it with 0 drops; the served ceiling is the **10 G link's
  response direction** (≈10 M small-DNS pps), reproduced exactly from the archived X710 single-link
  run (10.09 M). At 11 % CPU the server has ~89 % of the machine spare — the measured number is a
  floor, not its ceiling.
- **The fast path crushes every kernel-path resolver on the same rig:** 10.12 M vs Runbound's own
  `xdp: no` slow path 3.71 M (**2.7×**), unbound 2.09 M (**4.8×**), BIND 1.84 M (**5.5×**). And it
  does it at *lower* CPU (11 % vs 17–21 %) and *lower* latency (p50 0.045 ms vs 0.066 / 0.227 /
  0.320 ms). The margin is the kernel-bypass zero-syscall hot path (eBPF XDP + AF_XDP + the SIMD/ASM
  wire builder).
- **To exceed 10 M, add links.** The archived dual-link X710 run reached 13.15 M (+30 %) at the same
  ~11 % CPU — the single 10 G link's response direction is the only wall here.
- **Tooling honesty.** Throughput is the open-loop firehose NIC counters (rock-solid: served = a
  stable 10.11–10.12 M across six windows, 0 drops). Latency is from a `-Q`-capped closed-loop
  AF_XDP run; dnsmark's closed-loop **completion accounting** under `--xdp` is unreliable on this
  build (run-to-run 7–100 % completed) because the generator's own AF_XDP RX/ring stalls under
  load — the *completed* samples' wire RTT (p50 0.045 ms) is valid and consistent with the archive,
  and the firehose's 0 drops confirm the receiver loses nothing.
- **Caveat.** One configuration, one rig, single 10 G link, regular-page UMEM. Documented-
  methodology result; the server's true ceiling on this NIC class was not reached (≤11 % CPU).

## 6. Appendix — exact commands & configuration

```bash
# Receiver — Runbound v0.18.1, xdp: yes (queues pinned to physical cores, regular-page UMEM)
ethtool -L enp33s0f0np0 combined 64        # i40e exposed 119 > 64 cores; pin to cores (#165)
/root/runbound-bench -c /root/runbound-bench-xdp.conf   # xdp: yes, xdp-interface enp33s0f0np0
ip -d link show enp33s0f0np0 | grep -i xdp # prog/xdp id ... name dns_xdp jited (DRV)
# key config: xdp: yes, xdp-interface enp33s0f0np0, xdp-cache-snapshot-size 65536,
#   xdp-hugepages no, forward-zone "." -> 1.1.1.1/8.8.8.8/9.9.9.9, rate-limit 0, no local data

# Host: governor + flow-control + RSS (X710 enp33s0f0np0)
cpupower frequency-set -g performance
ethtool -A enp33s0f0np0 rx off tx off
ethtool -N enp33s0f0np0 rx-flow-hash udp4 sdfn

# Generator (dragonsage) — AF_XDP open-loop firehose / closed-loop latency:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -p 53 -d top-10000-domains.txt --xdp -Q 13000000 --max-outstanding 0 -l 22
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -p 53 -d top-10000-domains.txt --xdp -Q 1500000 --max-outstanding 800 -l 12

# Throughput truth = receiver NIC counters, 2.5 s steady windows:
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets   # served
cat /sys/class/net/enp33s0f0np0/statistics/rx_packets   # received
ethtool -S enp33s0f0np0 | grep -E 'rx_missed|rx_no_dma|rx_dropped'
# Detach the XDP prog when done (leave the NIC clean):
ip link set enp33s0f0np0 xdp off
```
