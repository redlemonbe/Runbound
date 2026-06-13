# Runbound Benchmark — v0.17.2 — Latitude rs4.metal.xlarge (EPYC 9554P / Broadcom BCM57508 100G) — 2026-06-11

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**
>
> Consolidated report — four runs, one rig, one day: `xdp: no`, `xdp: yes` single
> link, `xdp: yes` dual link (kernel 6.8), and a kernel-6.17 follow-up. Supersedes
> the v0.16.9 attempt on this rig (which produced no measurable number).

## 1. Executive Summary

On a public, rentable bare-metal SKU (EPYC 9554P 64c/128t, 2 × 100 G Broadcom
BCM57508), Runbound v0.17.2 served — receiver NIC hardware counters as truth:

| Run | Served (sustained) | Peak | CPU | Wire p50 |
|-----|-------------------:|-----:|----:|---------:|
| `xdp: no` (kernel slow path), 6.8 | 4.09 M qps | 5.45 M | 32 % | 0.047 ms |
| `xdp: yes` single link (AF_XDP **copy mode**), 6.8 | **7.85 M qps** | ~9.7 M | 8 % | 0.024 ms |
| `xdp: yes` dual link (copy mode), 6.8 | **9.07 M qps** | **11.13 M** | 27 % | — |
| `xdp: yes` single link, kernel 6.17 | 7.3–8.0 M qps | 9.1 M | ≤10 % | — |

**Every number is bounded by the NIC driver, not by Runbound**: `bnxt_en` has no
AF_XDP zero-copy in any kernel (`XDP_ZEROCOPY` bind → errno 95, verified on 6.8,
6.12 and 6.17, and absent from mainline `bnxt_xdp.c`), so the fast path runs in
**copy mode** with a drain ceiling of **~8 M qps/port** (stable across kernels,
paths and queue counts), and the generator is capped at ~10.6–14.0 M qps
(kernel-UDP; dnsmark `--xdp` generation is unusable on this NIC). Runbound showed
0 NIC ring discards and ≤27 % CPU at every fast-path operating point — its own
ceiling on this hardware was **not reached**: I cannot confirm it. The conclusion
for record-class measurements is unchanged from v0.16.9: same CPU class, different
NIC (Intel `ice`/`i40e`, Mellanox `mlx5`). **This SKU is not suitable for
zero-copy XDP work.**

## 2. Objective

Three runs requested by the maintainer on the (reinstalled) Latitude rig — validate
the setup on the kernel slow path, then measure the AF_XDP fast path on one and two
links — followed by an investigation of the absolute numbers (kernel upgrade
6.8 → 6.17, manual NIC tuning, copy-mode behaviour on both sides). All back-to-back:
same hosts, same corpus, same generator; one variable at a time.

## 3. Methodology & Architecture

- **Hosts:** two identical Latitude.sh `rs4.metal.xlarge` (fra2) — full hardware
  and tuning in the [rig doc](rigs/latitude-rs4-metal-xlarge-fra2.md). AMD EPYC
  9554P (64c/128t, 1 NUMA), 1.5 TiB DDR5-3600, Broadcom **BCM57508** 2 × 100 G
  (`bnxt_en` fw 227.0.131.0), Ubuntu 24.04.4, kernel **6.8.0-124** (runs 1–3) then
  **6.17.0-35 HWE** (follow-up). Governor `performance` ×128, 2 MiB hugepages
  ×4096, flow-control off, RSS `udp4 sdfn`, rings 2047 (max), irqbalance off,
  rmem/wmem_max 64 MiB.
- **Receiver:** Runbound **v0.17.2** (release gnu binary, SHA256 verified). Config =
  repo [`runbound-receiver-bench.conf`](runbound-receiver-bench.conf) adapted only
  in bind IP / ACL / `xdp:` / `xdp-interface:`. `rate-limit: 0`,
  `cache-min-ttl: 3600`, real forward-zone (1.1.1.1/8.8.8.8/9.9.9.9), no
  local-data. `ss -ulpn` checked before every run (rule 5).
- **Generator:** **dnsmark v2.2.1** (release musl, SHA256 verified), **kernel-UDP
  transport** — `--xdp` is unusable on this NIC (§5). Asymmetric pairing (kernel
  client → XDP server), stated per the dnsmark methodology; it bounds the server
  from below and keeps client-side RTT comparable across runs.
- **Links:** run 1–2 over the **Latitude private network, 802.1Q VID 2126**
  (`eno2.2126`, 10.21.26.1 ↔ .2, RTT 0.37 ms, lossless at ≥10.5 M pps; delivered on
  eno2 only). Run 3 (dual) = VLAN on eno2 **+ the routed public path on eno1**
  (1 hop, 0.24 ms; the fabric drops ~8 % at ~10.5 M pps). Follow-up over the public
  path (the VLAN had been removed; untagged private delivery does not bridge —
  ARP FAILED, verified).
- **Dataset / warmup:** corpus `top-10000-domains.txt` as `"<name> A"`, random;
  two kernel-UDP warmup passes before each measurement (99.7 % NOERROR, p50
  0.035–0.049 ms warm).
- **Load procedure:** dnsmark's `--ramp` yields no RTT samples against a flooded
  server and its kernel transport does not honour `-Q` open-loop (filed, dnsmark
  #10), so: curve = **N parallel closed-loop instances** (`--max-outstanding 20000
  -t 100`, 12 s/step), plus an **open-loop flood** (`--max-outstanding 0`).
  Truth = receiver NIC **port HW counters** (`rx_ucast_frames`/`tx_ucast_frames`;
  6.17 also exposes `*_packets` software counters — not used), 1 Hz timestamped
  deltas; discards = `rx_total_ring_discards`. Latency = generator-side `tcpdump`
  wire anchor at 30 k qps (paired by client port + DNS txid); receiver-side capture
  is impossible in XDP DRV mode (datapath bypasses the kernel tap).
- **VLAN / 802.1Q handling (#188):** two configurations validated on bnxt —
  (1) default HW RX-tag strip + `RUNBOUND_XDP_VLAN=2126` re-tag; (2) `ethtool -K
  eno2 rxvlan off` (accepted on this kernel) + per-packet tag preserve, **no env
  var** — required for the mixed tagged+untagged dual attach. Both passed
  functional and load tests.
- **Safety:** XDP attach on eno1 (the SSH port) done behind a dead-man's switch
  (`systemd-run --on-active` detaching XDP unless cancelled).

## 4. Raw Results

### Run 1 — `xdp: no` (kernel slow path, VLAN link, kernel 6.8)

v0.17.0 slow-path auto-tune logged `nic_queues=0 irqs_pinned=0 rps_queues=32` —
only RPS applied on bnxt (filed as Runbound #190). 63 kloop threads, 64
SO_REUSEPORT sockets.

| N instances | offered (NIC rx/s) | served (NIC tx/s) | ratio | ring discards | CPU % |
|--:|---:|---:|---:|---:|---:|
| 1 | 614 262 | 612 958 | 99.8 % | 0 | 4.6 |
| 4 | 2 659 420 | 2 289 102 | 86.1 % | 0 | 18.9 |
| 8 | 4 651 347 | **4 086 970** | 87.9 % | 12 | 32.0 |
| 16 | 4 444 256 | 3 869 235 | 87.1 % | 809 099 | 36.8 |
| 32 | 4 685 890 | 3 592 468 | 76.7 % | 3 487 949 | 41.3 |
| flood ~11 M | ~11 000 000 | ~2 500 000–2 900 000 | ~25 % | ~1.9 M/s | ~33 |

Loss below the knee is at the **UDP socket layer** (`RcvbufErrors`, +1.6 × 10⁹
across the runs; NIC ring discards 0 below the knee). Burst peak 5 456 220 qps.
Wire latency @30 k: p50 0.047 / p95 0.063 / p99 0.079 ms. RSS 0.41 GiB.

### Run 2 — `xdp: yes` single link (VLAN link, kernel 6.8)

XDP attached **mode=Drv**, 32 queues, AF_XDP rings 16384, UMEM on hugepages —
**every queue bound `mode="copy"`** (zero-copy bind: errno 95 on every queue).
XDP cache snapshot: 9 985 / 10 000 names. Fast-path attribution confirmed via
`/api/system` worker distribution (627 M served by XSK workers).

| N instances | offered (NIC rx/s) | served (NIC tx/s) | ratio | CPU % |
|--:|---:|---:|---:|---:|
| 1 | 558 583 | 556 517 | 99.6 % | 2.9 |
| 8 | 6 063 845 | 6 001 908 | 99.0 % | 15.7 |
| 16 | 6 415 436 | **6 379 385** | **99.4 %** | 17.0 |
| flood ~10.8 M | ~10 800 000 | **~7 850 000** | ~73 % | **7.9** |

**No overload collapse** (served stays 7.8–7.9 M/s through the flood), **0 NIC ring
discards** throughout. Wire latency @30 k: p50 0.024 / p95 0.045 / p99 0.054 ms —
half the slow-path p50. At ~550 k closed-loop the dnsmark RTT shows p50 0.19 ms
with a heavy tail (p95 ~20 ms) absent on the kernel path at the same rate
(copy-mode wakeup/batching). dnsmark `--xdp` as generator: ~8.3 k qps completed
(copy-mode TX) — unusable for rate.

### Run 3 — `xdp: yes` dual link (eno2 VLAN + eno1 public, kernel 6.8)

`xdp-interface: eno1,eno2`, 2 × 32 copy-mode queues, `rxvlan off`, no env var.
dnsmark dual-target open loop collapses to ~4.8 M total (filed, dnsmark #11) →
max flood = two parallel single-target processes.

| Load | offered total/s | served total/s | port eno1 / eno2 tx/s | peak total/s | CPU % |
|--|---:|---:|---:|---:|---:|
| N=16 closed-loop | 7 908 181 | **7 851 869** (99.3 %) | 4 024 126 / 3 827 744 | 9 552 084 | 27.0 |
| flood ×2 | 10 611 396 | **9 067 337** (85.5 %) | 3 938 834 / 5 128 503 | **11 131 215** | 26.9 |

0 NIC ring discards. Dual raises served **+15.5 %** over single at the same total
offered — part of the single-link gap is per-port. The two links are not
equivalent: the VLAN port answered 97.9 % of its offered share, the public port
73.3 %, and the provider fabric itself dropped ~8 % of generator egress before the
NIC on an eno1-only flood (gen 10.49 M → NIC rx 9.68 M → served 6.48 M). Whether
the residual eno1 deficit is port asymmetry, management-traffic interference or
path policing: **I cannot confirm this.**

### Follow-up — kernel 6.17.0-35 (public path; the VLAN had been removed)

| Measurement | kernel 6.8 | kernel 6.17 |
|--|---:|---:|
| Generator kernel-UDP egress (flood) | 11.9–12.0 M | **13.4–14.0 M** |
| dnsmark XSK TX, copy mode (true XDP TX) | **0 qps** (wedged) | **6.9 M** (kernel-side fix; still < kernel-UDP) |
| `xdp: no` served max | 4.09 M (VLAN) / 4.73 M (public + manual IRQ pin) | **5.03 M** — flood collapse persists |
| XDP copy served, 1 port, 32 queues | 7.85 M (eno2) / 6.8 M (eno1) | **7.98 M** @11.1 M offered; 7.34 M @12.9 M; peak 9.09 M; 0 discards |
| XDP copy, 1 port, **64 queues** | — | 6.64 M + ring discards (**worse** than 32) |
| AF_XDP zero-copy bind | errno 95 | **errno 95 (unchanged)** |

dnsmark XSK TX on the routed path requires a static neighbour entry for the target
IP at the **gateway MAC** (`ip neigh replace … nud permanent`); without it dnsmark
silently falls back to `sendmmsg` TX.

## 5. Interpretation

- **The NIC driver is the limit on this rig — for both roles.** No AF_XDP zero-copy
  in `bnxt_en` (any kernel): the receiver's fast path runs in copy mode with a
  **~8 M qps/port drain ceiling** (stable 6.8 → 6.17, VLAN/public, and worse with
  more queues — copy bandwidth contention), and high-rate `--xdp` generation is
  impossible. Runbound was never the limiting component: 0 NIC ring discards and
  ≤27 % CPU at every fast-path point; its true ceiling here is unmeasured —
  **I cannot confirm it.**
- **Fast path vs slow path, same rig, same flood:** 7.85 M served at 8 % CPU and no
  collapse, versus 2.5–2.9 M (collapsed) at ~33 % — copy-mode AF_XDP is
  structurally far ahead of the kernel sk_buff path even without zero-copy, and
  halves the wire p50 (24 µs vs 47 µs) at light load.
- **The earlier "~10 M `xdp: no`, no loss" expectation is resolved**: the v0.16.9
  off-rig reference line ("≈10.3 M received, 0 drops") is **absorption, not
  serving** — socket-layer drops are invisible to NIC counters. Measured serving
  tops at 4–5 M on this slow path (the v0.17.0 auto-tune that lifted the X710 rig
  to 7.3 M no-ops on bnxt — Runbound #190; manual IRQ pinning recovered ~+0.6 M).
- **Numbers from this rig must not be compared with the X710 rig's** (rule 6): the
  X710 figures (10.09 M single / 13.15 M dual) are **zero-copy**; these are copy
  mode. For the fast-path record on a 100 G EPYC-class rig, the v0.16.9
  recommendation stands: Intel `ice`/`i40e` or Mellanox `mlx5` — and verify the
  exact NIC model before renting; "100 G" alone says nothing.
- Issues filed from this work: Runbound **#190** (auto-tune no-op on bnxt); dnsmark
  **#10** (-Q ignored open-loop), **#11** (dual-target collapse), **#12** (PHY
  wire-guard blind on bnxt), **#13** (--xdp non-root error message).
- The dual run predates the VLAN removal and is **not reproducible on the current
  rig state** (no second L2 path); re-renting the SKU and re-creating the private
  network reproduces it.

## 6. Appendix — exact commands & configuration

```bash
# --- Host tuning, both machines, after every reboot ---
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sysctl -w net.core.rmem_max=67108864 net.core.wmem_max=67108864 net.core.netdev_max_backlog=250000
systemctl stop irqbalance
ethtool -A <nic> rx off tx off ; ethtool -N <nic> rx-flow-hash udp4 sdfn ; ethtool -G <nic> rx 2047 tx 2047
# xdp:no runs — the auto-tune no-ops on bnxt (#190), pin IRQs manually:
i=0; for irq in $(grep <nic> /proc/interrupts | cut -d: -f1); do echo $i > /proc/irq/$irq/smp_affinity_list; i=$((i+1)); done
ethtool -C <nic> rx-usecs 25

# --- Links ---
ip link add link eno2 name eno2.2126 type vlan id 2126 ; ip addr add 10.21.26.2/24 dev eno2.2126  # .1 generator
ethtool -K eno2 rxvlan off        # tag reaches XDP; #188 preserves per packet; no RUNBOUND_XDP_VLAN

# --- Receiver (config = runbound-receiver-bench.conf, adapted) ---
# run 1: interface 10.21.26.2 ; xdp: no
# run 2: + xdp: yes ; xdp-interface: eno2
# run 3: interface 10.21.26.2 + 109.94.96.53 ; xdp-interface: eno1,eno2 ; ACL + 109.94.96.43/32
#        (eno1 carries SSH -> dead-man first:)
systemd-run --on-active=480 --unit=deadman bash -c 'pkill -x runbound; ip link set eno1 xdp off; ip link set eno2 xdp off'
./runbound -c <conf> ; ss -ulpn | grep :53

# --- Generator (dnsmark v2.2.1, kernel-UDP) ---
dnsmark -s <ip> -d corpus_a.txt -Q 200000 -l 20 -q --no-tui                       # warmup x2
dnsmark -s <ip> -d corpus_a.txt -Q 0 --max-outstanding 20000 -t 100 -l 12 -q --no-tui   # 1 curve step (xN parallel)
dnsmark -s <ip> -d corpus_a.txt -Q 0 --max-outstanding 0 -l 25 -q --no-tui              # flood
# zero-copy check (root): dnsmark -s <ip> -d corpus_a.txt --xdp -Q 100000 -l 5 --no-tui  -> errno 95 x queues
# XSK TX on a routed path needs the next-hop MAC:
ip neigh replace <dst_ip> lladdr $(ip neigh show <gw_ip> | awk '{print $5}') dev eno1 nud permanent

# --- Truth (receiver, 1 Hz timestamped deltas; SUM of ports in dual) ---
ethtool -S <nic> | grep -E 'rx_ucast_frames|tx_ucast_frames|rx_total_ring_discards'
grep '^Udp:' /proc/net/snmp     # RcvbufErrors = socket-layer loss (xdp:no)

# --- Wire latency anchor (generator side; receiver tap bypassed in XDP DRV) ---
dnsmark -s <ip> -d corpus_a.txt -Q 50000 -l 12 -q --no-tui &
tcpdump -i <nic> -nn --time-stamp-precision=micro -c 60000 -w t.pcap 'udp port 53'
# pair queries/responses by (client port, DNS txid) -> p50/p95/p99
```
