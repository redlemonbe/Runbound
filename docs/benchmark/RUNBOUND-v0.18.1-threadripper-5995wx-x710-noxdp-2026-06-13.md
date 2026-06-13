# Runbound Benchmark — Runbound v0.18.1 `xdp: no` — Threadripper PRO 5995WX / X710 (i40e) — 2026-06-13

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. **`xdp: no` (kernel slow path)** and a **non-XDP
> (kernel UDP) generator** this round — the like-for-like kernel-path comparison against the
> BIND and unbound X710 baselines (same host, generator, link, methodology).

## 1. Executive Summary

On the new rig, over the direct **Intel X710 (i40e) 10 GbE** link, Runbound v0.18.1 in **`xdp:
no`** mode (kernel slow path, 63 SO_REUSEPORT workers, warm cache), driven by a **non-XDP
(kernel-UDP) dnsmark generator**, peaks at **~3.71 M QPS served** (receiver NIC `tx_packets`) at
**19.1 % receiver CPU** — roughly **2.0× BIND (1.84 M) and 1.8× unbound (2.09 M)** on the same
link, host, generator and methodology. It drains the NIC far better: of 4.59 M/s received it
serves 3.70 M/s and drops only **396 k/s**, where BIND and unbound drop ~1.1–1.2 M/s of a
similar receive rate. Closed-loop latency at 921 k QPS egress is **p50 0.066 ms / p95 0.207 ms /
p99 0.371 ms / p999 6.887 ms** — about **20× tighter at p99** than BIND (8.791 ms) or unbound
(7.123 ms) at comparable egress, 99.94 % completed, 99.74 % NOERROR. dnsperf (closed-loop)
sustains **~1.99 M avg / 2.05 M peak** at 99.52 % completed, 0.48 % lost — 2.5–3.4× the
reference resolvers in the same closed-loop test. Receiver RAM **~0.30 GB RSS**. At 19 % CPU
this is **generator/RX-bound, not Runbound's ceiling** — the AF-XDP fast path on this NIC class
reaches 10 M+ (see archive).

## 2. Objective

Complete the new-rig kernel-path triangle: measure Runbound v0.18.1 in `xdp: no` (its kernel
slow path, the apples-to-apples mode against BIND and unbound, both kernel-UDP) on the X710
link, with the identical non-XDP generator, host and methodology as the two baselines. The
question: served throughput, latency and RX efficiency of Runbound's slow path vs the reference
resolvers, and where the limit sits.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **Intel
  X710 / `enp33s0f0np0` (`i40e`, MTU 1500)**, kernel 6.12.88+deb13. Runbound **v0.18.1**
  (rebuilt from `main` HEAD, LTO release), **`xdp: no`** (kernel slow path, `recvmmsg` batching
  + the shared SIMD/ASM wire responder), **63 SO_REUSEPORT workers** auto-tuned, single
  `forward-zone "."` → 1.1.1.1 / 8.8.8.8 / 9.9.9.9, **no local data**, `rate-limit: 0`,
  `upstream-racing: no` (slow-path cache correctness, matches prod — avoids the #183
  racing/cache interaction), `cache-min-ttl 3600` / `cache-max-ttl 86400`. Bound to the single
  test IP `10.71.10.1:53` (the config parser honours one `interface:` line; one link benched at
  a time). Governor `performance`, RX ring 4096, flow-control RX/TX off, RSS `udp4 sdfn`.
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t), egress NIC
  `enp66s0f1np1` (i40e). **Non-XDP, kernel-UDP** open-loop firehose for the ramp; closed-loop
  (`--max-outstanding 1500`) for the latency point. `DNSMARK_SPORT_SPREAD=4096`. dnsperf as a
  second, closed-loop generator for cross-check. Exact commands in §6.
- **Link:** Intel X710 (i40e) 10 GbE, **direct DAC**, isolated from the LAN, flow-control off
  both ends, RSS `udp4 sdfn`, static `10.71.10.2 → 10.71.10.1`.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read, cache
  warmed before the measured ramp.
- **Procedure:** warm, then `--ramp`; throughput from receiver NIC counters over a 6 s steady
  window; CPU from `/proc/stat`, RSS from `ps`; latency from the closed-loop run.

## 4. Raw Results

**dnsmark `--ramp` (open-loop, non-XDP generator), at the receiver NIC (X710):**

| Metric | Value | Source |
|--------|-------|--------|
| Offered | **~4.99 M q/s** | dnsmark ramp step |
| Received by NIC (`rx_packets`) | **4.59 M/s** | receiver statistics |
| **Served (`tx_packets`)** | **~3.71 M peak** (3.70 M steady 6 s window) | receiver NIC |
| NIC drops/s (`rx_missed`+`rx_no_dma`+`rx_dropped`) | **396 k/s** | receiver `ethtool -S` |
| Served / received | **81 %** | derived |
| Receiver CPU % | **19.1 %** | `/proc/stat` |
| Receiver RAM | **~0.30 GB RSS** | `ps -o rss -C runbound-bench` |

**dnsmark closed-loop latency (`--max-outstanding 1500`):**

| Metric | Value |
|--------|-------|
| Egress / round-trip completed | **921 282 / 920 746 qps (99.9 %)** |
| Success | **99.74 % NOERROR** (99.94 % completed) |
| Latency p50 / p95 / p99 / p999 | **0.066 / 0.207 / 0.371 / 6.887 ms** |

**dnsperf cross-check (closed-loop, `-T 20 -c 500 -q 100000`):**

| Metric | Value |
|--------|-------|
| Served peak (receiver NIC `tx_packets`) | **~2.05 M qps** |
| Queries per second (avg) | **1 988 869 qps** |
| Completed / lost | **99.52 % / 0.48 %** |
| Response codes | **NOERROR 99.68 %, SERVFAIL 0.14 %, NXDOMAIN 0.18 %** |
| Average latency | **4.66 ms** (min 0.025 ms, max 1.160 s) |

## 5. Interpretation

- **Runbound's slow path serves ~2× the reference resolvers on this link** (3.71 M vs BIND
  1.84 M, unbound 2.09 M) at comparable CPU (~19 %), matching the "2–2.5×" ordering of the
  archived X520 run. The margin comes from `recvmmsg` batching + the shared SIMD/ASM wire
  responder (no per-query thread/spawn).
- **It drains the NIC, where the others leave packets on the floor.** Served/received: Runbound
  **81 %** (3.70 M of 4.59 M), unbound 49 %, BIND 41 %. With only 396 k/s NIC drops vs ~1.1–1.2 M/s
  for the others, Runbound turns far more of what the i40e delivers into answers.
- **Latency is in a different class.** Closed-loop p99 **0.371 ms** vs unbound 7.123 ms and BIND
  8.791 ms at comparable egress (~870–930 k); p50 0.066 ms vs 0.227 / 0.320 ms. dnsperf confirms
  the throughput edge (1.99 M avg, 0.48 % lost) where unbound/​BIND sat at 0.13–0.79 M.
- **Generator/RX-bound, not Runbound's ceiling.** 19.1 % CPU at the open-loop peak; the
  non-XDP generator caps offered at ~4.99 M and the i40e RX drops 396 k/s. Runbound's true
  ceiling on this NIC class is the AF-XDP fast path (10 M+ in the archive), not this number —
  this run measures the kernel slow path under a non-XDP generator, for the like-for-like
  comparison only.
- **Caveat.** One configuration, one rig, non-XDP generator, kernel slow path. Documented-
  methodology result, not a universal statement, and not the fast-path ceiling.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — Runbound v0.18.1 under test (xdp: no), bound to the single test IP
/root/runbound-bench --version                        # runbound 0.18.1
/root/runbound-bench -c /root/runbound-bench.conf     # xdp: no, 63 SO_REUSEPORT workers
ss -ulpn | grep -c ':53 '                             # 63 sockets on 10.71.10.1:53
# key config: xdp: no, interface 10.71.10.1, forward-zone "." -> 1.1.1.1/8.8.8.8/9.9.9.9,
#   rate-limit 0, upstream-racing no, cache-min-ttl 3600 / cache-max-ttl 86400, no local data

# Host (receiver): governor + flow-control + RSS + ring (X710 enp33s0f0np0)
cpupower frequency-set -g performance
ethtool -A enp33s0f0np0 rx off tx off
ethtool -N enp33s0f0np0 rx-flow-hash udp4 sdfn
ethtool -G enp33s0f0np0 rx 4096

# Generator (dragonsage) — non-XDP open-loop ramp / closed-loop latency / dnsperf:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -p 53 -d top-10000-domains.txt --ramp
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.71.10.1 -p 53 -d top-10000-domains.txt --max-outstanding 1500 -l 12
dnsperf -s 10.71.10.1 -p 53 -d corpus-dnsperf.txt -T 20 -c 500 -q 100000 -l 16

# Throughput truth = receiver NIC counters, 6 s steady window:
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets   # served
cat /sys/class/net/enp33s0f0np0/statistics/rx_packets   # received
ethtool -S enp33s0f0np0 | grep -E 'rx_missed|rx_no_dma|rx_dropped'   # drops
ps -o rss= -C runbound-bench | awk '{s+=$1}END{printf "%.2f GB\n", s/1048576}'
```
