# Runbound Benchmark — Runbound v0.18.1 `xdp: no` — Threadripper PRO 5995WX / X510 (ixgbe) — 2026-06-13

> Follows [README.md](../README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. **`xdp: no` (kernel slow path)** and a **non-XDP
> (kernel UDP) generator** this round — the like-for-like kernel-path comparison against the
> BIND and unbound X510 baselines (same host, generator, link, methodology). Companion to the
> Runbound X710 report (same binary, faster-RX link).

## 1. Executive Summary

On the new rig, over the direct **Intel X510 (ixgbe) 10 GbE** link, Runbound v0.18.1 in **`xdp:
no`** mode (kernel slow path, 63 SO_REUSEPORT workers, warm cache), driven by a **non-XDP
(kernel-UDP) dnsmark generator**, peaks at **~2.51 M QPS served** (receiver NIC `tx_packets`) at
**19.7 % receiver CPU** — **1.7× BIND (1.46 M) and 1.5× unbound (1.65 M)** on the same link. The
headline here: of **2.54 M/s received it serves 2.51 M/s — 99 %** — where BIND serves 59 % and
unbound 65 % of their (similar) receive rate. The ixgbe drops ~3.35 M/s at RX (same NIC limit
for all three); Runbound simply converts almost everything the NIC delivers into answers, which
is direct evidence it is **RX-bound, not CPU-bound** (19.7 % CPU). Closed-loop latency at 512 k
QPS egress is **p50 1.013 / p95 1.090 / p99 1.113 / p999 3.809 ms** — at this rate it ties BIND
and unbound (~1 ms is the ixgbe link floor, see §5), 97.60 % completed, 99.72 % NOERROR. dnsperf
(closed-loop) sustains **~676 k avg / 758 k peak**, 3.51 % lost (vs unbound's 14.68 %), average
latency **0.585 ms**. Receiver RAM **~0.32 GB RSS**. Generator/RX-bound, not Runbound's ceiling.

## 2. Objective

Complete the kernel-path triangle on the X510 (ixgbe) link: Runbound v0.18.1 `xdp: no` vs the
BIND and unbound X510 baselines, identical host/generator/methodology. Read with the Runbound
X710 report to isolate the NIC/RX contribution (same binary, only the link changed).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **Intel
  X510 / `enp66s0f1` (`ixgbe`, MTU 1500)**, kernel 6.12.88+deb13. Runbound **v0.18.1** (rebuilt
  from `main` HEAD, LTO release), **`xdp: no`** (kernel slow path, `recvmmsg` + shared SIMD/ASM
  wire responder), **63 SO_REUSEPORT workers** auto-tuned, single `forward-zone "."` → 1.1.1.1 /
  8.8.8.8 / 9.9.9.9, **no local data**, `rate-limit: 0`, `upstream-racing: no`,
  `cache-min-ttl 3600` / `cache-max-ttl 86400`. Bound to the single test IP `10.51.10.1:53` (one
  link benched at a time). Governor `performance`, flow-control RX/TX off.
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t), egress NIC `nic2`
  (ixgbe). **Non-XDP, kernel-UDP** open-loop firehose for the ramp; closed-loop
  (`--max-outstanding 1500`) for the latency point. `DNSMARK_SPORT_SPREAD=4096`. dnsperf as a
  second, closed-loop generator for cross-check. Exact commands in §6.
- **Link:** Intel X510 (ixgbe) 10 GbE, **direct DAC**, isolated from the LAN, flow-control off
  both ends, static `10.51.10.2 → 10.51.10.1`. (The X510's second port is a known-dead link,
  disabled — link 1 only.)
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read, warmed.
- **Procedure:** identical to the Runbound X710 report — warm, `--ramp`, NIC-counter truth over
  a 6 s window, CPU from `/proc/stat`, RSS from `ps`, latency from the closed-loop run.

## 4. Raw Results

**dnsmark `--ramp` (open-loop, non-XDP generator), at the receiver NIC (X510):**

| Metric | Value | Source |
|--------|-------|--------|
| Offered | **~6.0 M q/s** | dnsmark ramp / NIC counters |
| Received by NIC (`rx_packets`) | **2.54 M/s** | receiver statistics |
| **Served (`tx_packets`)** | **~2.51 M peak** (steady 6 s window) | receiver NIC |
| NIC drops/s (`rx_missed`+`rx_no_dma`+`rx_dropped`) | **3.35 M/s** | receiver `ethtool -S` |
| Served / received | **99 %** | derived |
| Receiver CPU % | **19.7 %** | `/proc/stat` |
| Receiver RAM | **~0.32 GB RSS** | `ps -o rss -C runbound-bench` |

**dnsmark closed-loop latency (`--max-outstanding 1500`):**

| Metric | Value |
|--------|-------|
| Egress / round-trip completed | **512 299 / 500 007 qps (97.6 %)** |
| Success | **99.72 % NOERROR** (97.60 % completed) |
| Latency p50 / p95 / p99 / p999 | **1.013 / 1.090 / 1.113 / 3.809 ms** |

**dnsperf cross-check (closed-loop, `-T 20 -c 500 -q 100000`):**

| Metric | Value |
|--------|-------|
| Served peak (receiver NIC `tx_packets`) | **~758 k qps** |
| Queries per second (avg) | **675 792 qps** |
| Completed / lost | **96.49 % / 3.51 %** |
| Response codes | **NOERROR 99.69 %, SERVFAIL 0.14 %, NXDOMAIN 0.17 %** |
| Average latency | **0.585 ms** (min 0.030 ms, max 0.428 s) |

## 5. Interpretation

- **Runbound serves ~99 % of what the ixgbe delivers.** Received 2.54 M/s → served 2.51 M/s. The
  ixgbe drops ~3.35 M/s of the ~6 M offered at its RX (the same NIC RX wall all three resolvers
  hit — BIND received 2.46 M, unbound 2.53 M), but only Runbound turns nearly all of it into
  answers. BIND serves 59 % of its receive rate, unbound 65 %, Runbound **99 %** — at 19.7 % CPU.
  This is the cleanest single proof on this rig that Runbound's slow path is **RX-bound, not
  CPU-bound**: give it a NIC that delivers more (X710: 4.59 M received → 3.70 M served) and it
  scales straight up.
- **~1.7× BIND, ~1.5× unbound** on served peak (2.51 M vs 1.46 M / 1.65 M), same ordering as
  the X710 run and the archived X520 baselines.
- **Closed-loop latency ties at ~500 k — that is the link floor, not the server.** At this rate
  all three sit at p50 ~1.0 ms (Runbound 1.013 / unbound 1.026 / BIND 1.051): the ixgbe RX/
  coalescing path imposes a ~1 ms floor that dominates the server's own sub-100 µs service time
  (visible on the i40e link, where Runbound's closed-loop p50 was 0.066 ms). Runbound's p999
  (3.809 ms) sits between unbound's (1.161 ms) and BIND's (13.663 ms). dnsperf shows the
  throughput/loss edge clearly: 676 k avg at 3.51 % lost vs unbound's 131 k at 14.68 % lost.
- **Generator/RX-bound, not Runbound's ceiling.** 19.7 % CPU; the ixgbe RX caps received at
  ~2.54 M/s. The AF-XDP fast path bypasses this entirely (archive: 10 M+ on a faster NIC).
- **Caveat.** One configuration, one rig, non-XDP generator, ixgbe link with a known dead second
  port (link 1 only). Documented-methodology result, not the fast-path ceiling.

## 6. Appendix — exact commands & configuration

```bash
# Receiver — Runbound v0.18.1 under test (xdp: no), bound to the single test IP
/root/runbound-bench --version                        # runbound 0.18.1
/root/runbound-bench -c /root/runbound-bench.conf     # xdp: no, 63 SO_REUSEPORT workers
ss -ulpn | grep -c ':53 '                             # 63 sockets on 10.51.10.1:53

# Host (receiver): governor + flow-control (X510 enp66s0f1)
cpupower frequency-set -g performance
ethtool -A enp66s0f1 rx off tx off

# Generator (dragonsage) — non-XDP open-loop ramp / closed-loop latency / dnsperf:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -p 53 -d top-10000-domains.txt --ramp
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -p 53 -d top-10000-domains.txt --max-outstanding 1500 -l 12
dnsperf -s 10.51.10.1 -p 53 -d corpus-dnsperf.txt -T 20 -c 500 -q 100000 -l 16

# Throughput truth = receiver NIC counters, 6 s steady window:
cat /sys/class/net/enp66s0f1/statistics/tx_packets   # served
cat /sys/class/net/enp66s0f1/statistics/rx_packets   # received
ethtool -S enp66s0f1 | grep -E 'rx_missed|rx_no_dma|rx_dropped'   # drops
ps -o rss= -C runbound-bench | awk '{s+=$1}END{printf "%.2f GB\n", s/1048576}'
```
