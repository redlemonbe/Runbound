# Runbound Benchmark — v0.17.2 — Latitude rs4.metal.xlarge (EPYC 9554P / BCM57508 100G), `xdp: no` — 2026-06-11

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

Runbound v0.17.2 in `xdp: no` (kernel slow path, v0.17.0 auto-tune active) on an
EPYC 9554P with a Broadcom BCM57508 100 G port (802.1Q VLAN link) served a sustained
**~4.09 M qps** (receiver NIC `tx_ucast_frames`, 12 s window) under 4.65 M qps offered
(88 % answered), at ~32 % CPU of 128 threads and 0.41 GiB RSS, with **0 NIC ring
discards** — losses above that rate occur at the UDP socket layer (`RcvbufErrors`).
Short bursts reached 5.45 M qps served. Under a sustained open-loop flood of ~11 M qps
offered, serving **collapses to ~2.5–2.9 M qps** with NIC ring discards (~1.9 M/s) —
classic kernel-path overload. Wire-anchored latency (generator-side tcpdump, 30 k qps,
warm cache): **p50 0.047 ms / p95 0.063 / p99 0.079**.

## 2. Objective

First of three runs on the (reinstalled) Latitude rig: validate the full bench setup
end-to-end (link, corpus, warmup, counters, tooling) on the kernel slow path, and
produce the `xdp: no` baseline that the two XDP runs are compared against
back-to-back. Replaces the v0.16.9 attempt on this rig which produced no usable
number (see [previous report](RUNBOUND-v0.16.9-latitude-epyc9554p-bnxt-2026-06-10.md)).

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD EPYC 9554P (64c/128t, 1 NUMA node), 1.5 TiB DDR5-3600,
  Broadcom **BCM57508** 100 G (`bnxt_en`, fw 227.0.131.0/pkg 227.1.111.0), **Ubuntu
  24.04.4**, kernel **6.8.0-124-generic** (reinstall — the 2026-06-10 run was Debian 13 /
  6.12.90; see the updated [rig doc](rigs/latitude-rs4-metal-xlarge-fra2.md)).
  Runbound **v0.17.2** (release `runbound-x86_64-linux-gnu`, SHA256 verified),
  `xdp: no` — config = repo
  [`runbound-receiver-bench.conf`](runbound-receiver-bench.conf) adapted only in:
  bind IP `10.21.26.2`, ACL, `xdp: no`. `rate-limit: 0`, `cache-min-ttl: 3600`,
  real forward-zone (1.1.1.1/8.8.8.8/9.9.9.9), no local-data.
  v0.17.0 slow-path auto-tune ran at startup: `rps_queues=32`, `nic_queues=0`,
  `irqs_pinned=0` (RPS applied; queue/IRQ layout left as-is on this bnxt).
  63 kernel-UDP worker threads, 64 SO_REUSEPORT sockets.
- **Generator (dnsmark):** second identical host, **dnsmark v2.2.1** (release musl,
  SHA256 verified), **kernel-UDP transport** (no `--xdp`: `bnxt_en` has no AF_XDP
  zero-copy — see §5 of the [XDP single report](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-xdp-2026-06-11.md)).
- **Link:** eno2 ↔ eno2 via **Latitude private network, 802.1Q VID 2126**
  (`eno2.2126`, 10.21.26.1 ↔ 10.21.26.2, ping RTT 0.37 ms, 0 % loss). Flow-control
  off, RSS `udp4 sdfn`, rings 2047/2047 (max), governor `performance` ×128,
  hugepages 2 MiB ×4096, `irqbalance` inactive, rmem/wmem_max 64 MiB, both hosts.
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt` as `"<name> A"`, random
  read. Warmup: two kernel-UDP passes (~1.3 M queries) → 99.74 % NOERROR, p50 0.049 ms
  (warm cache) before any measurement.
- **Procedure:** `dnsmark --ramp` (DSS) first; against a flooded kernel-UDP receiver
  it yields no RTT samples (known from the unbound/BIND baselines), so the curve was
  measured with **N parallel closed-loop dnsmark instances** (N = 1…32,
  `--max-outstanding 20000 -t 100`, 12 s/step) + one open-loop flood
  (`--max-outstanding 0`). Truth = receiver NIC port counters
  (`ethtool -S`: `rx_ucast_frames`/`tx_ucast_frames` — the bnxt port-level HW
  counters on kernel 6.8; discards = `rx_total_ring_discards`), sampled at 1 Hz,
  timestamped deltas. `ss -ulpn | grep :53` checked: only Runbound owns the bench IP
  (systemd-resolved stub on 127.0.0.53/54 only).

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained served QPS | **4 086 970 qps** avg over 12 s (offered 4 651 347; 88 %) | receiver NIC `tx_ucast_frames` deltas |
| Served burst peak | 5 456 220 qps (1 s) | same |
| Served under ~11 M flood | ~2.5–2.9 M qps (collapse) + ring discards ~1.9 M/s | same + `rx_total_ring_discards` |
| Generator kernel-UDP ceiling | ~11.0–11.9 M qps egress sustained | dnsmark egress + receiver `rx_ucast_frames` |
| Latency (wire, 30 k qps) | **p50 0.047 / p95 0.063 / p99 0.079 ms** | generator-side tcpdump, 29 941 query/response pairs by (port, txid) |
| Latency (dnsmark RTT, 537 k qps closed-loop) | p50 0.037 / p99 0.32 ms | dnsmark |
| Success rate (warm) | 99.73–99.79 % NOERROR, ~0.2 % NXDOMAIN, ≤0.06 % SERVFAIL | dnsmark rcode breakdown |
| Receiver CPU at max served | ~32 % of 128 threads | /proc/stat sampler |
| Receiver RAM (runbound RSS) | 0.41 GiB | `ps -o rss` |
| NIC ring discards below knee | **0** (loss is `Udp: RcvbufErrors` at the socket layer) | `ethtool -S` + `/proc/net/snmp` |

Load curve (N parallel closed-loop instances, NIC truth, 12 s windows):

| N | offered (NIC rx/s) | served (NIC tx/s) | served/offered | ring discards | CPU % |
|--:|---:|---:|---:|---:|---:|
| 1 | 614 262 | 612 958 | 99.8 % | 0 | 4.6 |
| 2 | 1 012 760 | 744 796 | 73.5 % | 0 | 7.4 |
| 4 | 2 659 420 | 2 289 102 | 86.1 % | 0 | 18.9 |
| 8 | 4 651 347 | **4 086 970** | 87.9 % | 12 | 32.0 |
| 16 | 4 444 256 | 3 869 235 | 87.1 % | 809 099 | 36.8 |
| 24 | 4 727 462 | 3 495 590 | 73.9 % | 3 902 351 | 39.9 |
| 32 | 4 685 890 | 3 592 468 | 76.7 % | 3 487 949 | 41.3 |
| flood | ~11 000 000 | ~2 500 000–2 900 000 | ~25 % | ~1.9 M/s | ~33 |

## 5. Interpretation

- **The serving knee sits around 4–4.6 M qps offered.** Up to ~600 k the path is
  lossless; from ~1 M offered a growing share is dropped at the **UDP socket layer**
  (`RcvbufErrors` grew by 1.6 × 10⁹ across the runs; NIC ring discards stayed 0 below
  the knee). CPU at the 4.09 M point is only ~32 % — the limit is the per-socket
  softirq/drain pipeline, not aggregate CPU.
- **Deep overload collapses throughput.** At ~11 M offered the receiver serves less
  (~2.5–2.9 M) than at 4.6 M offered — receive-livelock behaviour; the NIC then also
  drops at the ring (~1.9 M/s).
- This is **not comparable to the X710/Threadripper `xdp: no` figure (7.3 M)** —
  different NIC, driver, kernel, and an 802.1Q-tagged link (methodology rule 6).
- **Generator-side limits found (filed):** dnsmark kernel transport ignores `-Q`
  pacing when `--max-outstanding 0` (open loop = full flood) and caps at ~530–615 k
  qps per process in closed loop; under flood its RTT histogram is empty. The N-instance
  workaround produces offered steps but not exact target rates.
- dnsmark p50 (0.037 ms) sits 10 µs **below** the wire p50 (0.047 ms) measured at a
  different rate (537 k vs 30 k) — the two are consistent within the tool-overhead
  band documented by dnsmark; a wire anchor at the saturation point is not possible
  (tcpdump cannot keep up at multi-M pps): **I cannot confirm this** (wire p50 at
  4 M qps).

## 6. Appendix — exact commands & configuration

```bash
# --- Host tuning, both machines (tune-common.sh) ---
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sysctl -w net.core.rmem_max=67108864 net.core.wmem_max=67108864 net.core.netdev_max_backlog=250000
systemctl stop irqbalance
ethtool -A eno2 rx off tx off ; ethtool -N eno2 rx-flow-hash udp4 sdfn ; ethtool -G eno2 rx 2047 tx 2047

# --- Link (VLAN 2126, both ends) ---
ip link add link eno2 name eno2.2126 type vlan id 2126
ip addr add 10.21.26.2/24 dev eno2.2126 ; ip link set eno2.2126 up   # .1 on the generator

# --- Receiver ---
# config = docs/benchmark/runbound-receiver-bench.conf with: interface: 10.21.26.2 ; xdp: no
./runbound -c runbound-noxdp.conf
ss -ulpn | grep :53        # 64 sockets on 10.21.26.2:53, resolved stub on 127.0.0.53 only

# --- Generator (dnsmark 2.2.1, kernel-UDP) ---
dnsmark -s 10.21.26.2 -d corpus_a.txt -Q 200000 -l 20 -q --no-tui          # warmup ×2
dnsmark -s 10.21.26.2 -d corpus_a.txt --ramp -q --no-tui                   # DSS (no RTT samples when flooded)
# curve: N ∈ {1,2,4,8,16,24,32} parallel instances, 12 s steps:
dnsmark -s 10.21.26.2 -d corpus_a.txt -Q 0 --max-outstanding 20000 -t 100 -l 12 -q --no-tui
# flood: dnsmark -s 10.21.26.2 -d corpus_a.txt -Q 0 --max-outstanding 0 -l 25 -q --no-tui

# --- Truth (receiver, 1 Hz, timestamped deltas) ---
ethtool -S eno2 | grep -E 'rx_ucast_frames|tx_ucast_frames|rx_total_ring_discards|rx_stat_discard'
grep '^Udp:' /proc/net/snmp     # RcvbufErrors = socket-layer loss

# --- Wire latency anchor (generator side; receiver-side capture is fine in xdp:no) ---
dnsmark -s 10.21.26.2 -d corpus_a.txt -Q 50000 -l 12 -q --no-tui &
tcpdump -i eno2 -nn --time-stamp-precision=micro -c 60000 -w t1.pcap 'udp port 53'
# pair queries/responses by (client port, DNS txid) → p50/p95/p99
```
