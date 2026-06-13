# Runbound Benchmark — Runbound v0.18.1 `xdp: yes` — Threadripper PRO 5995WX / X510 (ixgbe) — 2026-06-13

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."** Truth is the receiver NIC hardware
> counters, not the generator's round-trip. **`xdp: yes` (AF_XDP fast path)** with an **AF_XDP
> (`--xdp`) dnsmark generator**. Companion to the Runbound X710 `xdp: yes` report (same binary,
> different NIC/driver).

## 1. Executive Summary

On the new rig, over the direct **Intel X510 (ixgbe) 10 GbE** link, Runbound v0.18.1 in **`xdp:
yes`** mode (AF_XDP fast path, 63 queues = NIC max, warm cache), driven by an AF_XDP dnsmark
firehose, serves a sustained **~10.12 M QPS** (receiver NIC `tx_packets`) at **~24 % receiver
CPU**. The ixgbe receives ~10.26 M/s and Runbound answers 10.12 M/s of it — identical served
ceiling to the X710 run, because the cap is the **10 G link's response direction**, not the NIC
or the server. The one difference vs the i40e link is cost: the ixgbe XDP path takes **~24 % CPU
for the same 10.12 M** where the i40e took ~11 % — the ixgbe driver's XDP/AF_XDP path is heavier,
but Runbound still has ~76 % of the machine spare. Fast-path wire latency is **p50 0.054 ms /
p95 0.176 ms / p99 0.183 ms** (100 % completed, 99.68 % NOERROR). ~6.1× unbound and ~6.9× BIND on
this link, ~4× Runbound's own kernel slow path.

## 2. Objective

Measure Runbound v0.18.1's AF_XDP fast path on the X510 (ixgbe) link, alongside the X710 (i40e)
fast-path run, to see what the ixgbe driver costs vs the i40e at the same served rate, and confirm
the link cap. Runbound-only with an AF_XDP generator (reference resolvers have no fast path).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64c/128t), 125 GB RAM, **Intel
  X510 / `enp66s0f1` (`ixgbe`, MTU 1500)**, kernel 6.12.88+deb13. Runbound **v0.18.1** (rebuilt
  from `main` HEAD, LTO release), **`xdp: yes`** (eBPF XDP + AF_XDP, DRV mode, prog `dns_xdp`
  jited), **NIC combined queues = 63 (ixgbe HW max)**, `xdp-cache-snapshot-size 65536`,
  `xdp-hugepages: no` (regular-page UMEM), single `forward-zone "."` → 1.1.1.1 / 8.8.8.8 / 9.9.9.9,
  **no local data**, `rate-limit: 0`, warm cache. Governor `performance`, flow-control RX/TX off.
- **Generator (dnsmark v2.3.0):** dual Intel Xeon E5-2690 v2 (20c/40t), egress NIC `nic2`
  (ixgbe), **AF_XDP (`--xdp`) open-loop firehose** (`-Q 13e6 --max-outstanding 0`) for throughput;
  closed-loop AF_XDP (`-Q` capped) for the latency samples. `DNSMARK_SPORT_SPREAD=4096`.
- **Link:** Intel X510 (ixgbe) 10 GbE, **direct DAC**, isolated from the LAN, flow-control off,
  static `10.51.10.2 → 10.51.10.1`. (The X510's second port is a known-dead link, disabled.)
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 names, random read, warmed.
- **Procedure:** identical to the X710 `xdp: yes` report — AF_XDP firehose, receiver NIC-counter
  truth over 2.5 s steady windows, CPU from `/proc/stat`, latency from a `-Q`-capped closed-loop run.

## 4. Raw Results

**AF_XDP open-loop firehose (-Q 13 M), at the receiver NIC (X510), steady windows:**

| Metric | Value | Source |
|--------|-------|--------|
| Received by NIC (`rx_packets`) | **~10.26 M/s** | receiver statistics |
| **Served (`tx_packets`)** | **~10.12 M/s sustained** (peak 10 120 090) | receiver NIC |
| Served direction utilisation | ~10.1 M pps = 10 G small-DNS line rate | derived |
| Receiver CPU % | **~24 %** (21.8–24.7 %) | `/proc/stat` |
| Receiver RAM | **~8.23 GB RSS** (regular-page UMEM, 63 queues) | `ps -o rss` |

**AF_XDP closed-loop latency (wire samples, `-Q` capped):**

| Metric | Value |
|--------|-------|
| Latency p50 / p95 / p99 | **0.054 / 0.176 / 0.183 ms** |
| Completed / success | **100 % completed / 99.68 % NOERROR** |

## 5. Interpretation

- **Same ~10.12 M served as the X710 link — the 10 G response direction is the cap.** The ixgbe
  receives ~10.26 M/s (a touch below the i40e's 13 M ingest) and Runbound answers 10.12 M/s. Both
  links land on the same served ceiling because both are 10 GbE and the response direction is the
  wall, not the NIC or Runbound.
- **The ixgbe costs ~2× the CPU of the i40e for the same work.** ~24 % CPU here vs ~11 % on the
  X710 at an identical 10.12 M served. The ixgbe driver's XDP/AF_XDP datapath is heavier per packet;
  Runbound still keeps ~76 % of the machine idle, so the link remains the limit, not the server.
- **Versus the kernel-path field on this link:** 10.12 M vs unbound 1.65 M (**6.1×**), BIND 1.46 M
  (**6.9×**), Runbound's own `xdp: no` slow path 2.51 M (**4.0×**) — at lower latency (p50 0.054 ms).
- **Tooling honesty.** Throughput is the open-loop firehose NIC counters (served stable at
  10.11–10.12 M across windows). Latency is from a `-Q`-capped closed-loop AF_XDP run that
  completed 100 % here (the X710 run's low completion was a generator-side closed-loop accounting
  artifact, run-to-run); both links give p50 ≈ 0.05 ms, consistent with the archive.
- **Caveat.** One configuration, one rig, single 10 G link, regular-page UMEM, ixgbe link with a
  known dead second port. Documented-methodology result; the server's true ceiling was not reached
  (≤24 % CPU).

## 6. Appendix — exact commands & configuration

```bash
# Receiver — Runbound v0.18.1, xdp: yes (ixgbe, queues = HW max 63, regular-page UMEM)
ethtool -L enp66s0f1 combined 63
/root/runbound-bench -c /root/runbound-bench-xdp.conf   # xdp: yes, xdp-interface enp66s0f1
ip -d link show enp66s0f1 | grep -i xdp                 # prog/xdp id ... name dns_xdp jited

# Host: governor + flow-control (X510 enp66s0f1)
cpupower frequency-set -g performance
ethtool -A enp66s0f1 rx off tx off

# Generator (dragonsage) — AF_XDP open-loop firehose / closed-loop latency:
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -p 53 -d top-10000-domains.txt --xdp -Q 13000000 --max-outstanding 0 -l 22
DNSMARK_SPORT_SPREAD=4096 dnsmark -s 10.51.10.1 -p 53 -d top-10000-domains.txt --xdp -Q 1500000 --max-outstanding 800 -l 12

# Throughput truth = receiver NIC counters, 2.5 s steady windows:
cat /sys/class/net/enp66s0f1/statistics/tx_packets   # served
cat /sys/class/net/enp66s0f1/statistics/rx_packets   # received
ethtool -S enp66s0f1 | grep -E 'rx_missed|rx_no_dma|rx_dropped'
# Detach the XDP prog when done:
ip link set enp66s0f1 xdp off
```
