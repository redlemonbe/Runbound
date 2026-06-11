# Runbound Benchmark — v0.17.2 — Latitude rs4.metal.xlarge (EPYC 9554P / BCM57508 100G), kernel 6.17 follow-up — 2026-06-11

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

Follow-up to the three same-day v0.17.2 runs on this rig, after the maintainer
questioned the absolute numbers. Both hosts were upgraded **kernel 6.8.0-124 →
6.17.0-35 (Ubuntu HWE)** and re-measured over the **public untagged path** (the
maintainer removed the VLAN; an untagged private delivery does not bridge the hosts,
re-verified). On 6.17: the kernel-UDP generator rises **11.9 → 14.0 M qps egress**;
Runbound's AF_XDP **copy-mode** fast path serves **7.3–8.0 M qps sustained per port
(peak 9.1 M, 0 ring discards, no collapse)**; the kernel slow path (`xdp: no`)
improves to **5.03 M qps** served max but still collapses under deep flood
(14 M offered → ~3.1 M served). dnsmark's XSK **TX** in copy mode goes from **0 qps
(wedged) on 6.8 to 6.9 M on 6.17** — a kernel-side bnxt fix — but stays below
kernel-UDP generation, which therefore remains the load source. The structural
conclusion is unchanged and now better quantified: **~8 M qps/port is the AF_XDP
copy-mode drain ceiling on `bnxt_en`** (insensitive to kernel 6.8→6.17 and to queue
count; 64 queues measured *worse* than 32), and `XDP_ZEROCOPY` remains `EOPNOTSUPP`
(errno 95) on 6.17. The earlier expectation of "~10 M `xdp: no` with no loss" on
this rig traces to the v0.16.9 report's **off-rig reference line — 10.3 M *received*
with 0 NIC drops is absorption, not serving** (socket-layer drops are invisible to
NIC counters); no tested configuration reproduces it as a served rate.

## 2. Objective

Answer two maintainer challenges to the published numbers: (a) "`xdp: no` should do
~10 M with no loss on this class of machine" (per the v0.16.9 reference line), and
(b) "XDP below a 10 G X710 on a 100 G NIC is not normal". Levers tested, one at a
time: test path (VLAN tagged → public untagged), manual NIC tuning (the v0.17.0
auto-tune partially no-ops on bnxt), receiver queue count, kernel version
(6.8 → 6.17), and forcing AF_XDP copy mode on both sides.

## 3. Methodology & Architecture

Same hosts, binaries (Runbound v0.17.2, dnsmark v2.2.1), corpus, warmup and
NIC-counter truth as the three main reports, with these differences:

- **Path:** public routed `eno1` (109.94.96.43 → 109.94.96.53, 1 hop, ~0.24 ms).
  The VLAN was **removed from the Latitude private network by the maintainer**
  mid-investigation; untagged private delivery does not bridge (ARP FAILED,
  re-verified) — single-port runs only, the dual case is not reproducible on the
  current rig.
- **Kernel:** both hosts `linux-generic-hwe-24.04` → **6.17.0-35-generic**, reboot,
  full re-tune (nothing persists: governor, hugepages, flow-control, RSS, rings,
  IRQ pin, `rx-usecs 25`).
- **Manual NIC tune added:** the v0.17.0 slow-path auto-tune logs
  `nic_queues=0 irqs_pinned=0` on bnxt (only RPS is applied) — filed as a Runbound
  issue; the 32 `eno1` IRQs were pinned 1:1 to cores 0–31 by hand.
- **Counters on 6.17:** both `*_packets` (sw) and `*_ucast_frames` (port HW) exist;
  the HW `rx_ucast_frames`/`tx_ucast_frames` were used (methodology rule 1).
- dnsmark XSK TX on a **routed** path needs a static neighbour entry pointing the
  target IP at the **gateway MAC** (`ip neigh replace <dst> lladdr <gw_mac> dev eno1
  nud permanent`); without it dnsmark silently falls back to `sendmmsg` TX.

## 4. Raw Results

All rates = receiver NIC port HW counters, 1 Hz timestamped deltas, ≥12 s windows.

**Kernel comparison (same hosts, same day, one variable at a time):**

| Measurement | kernel 6.8.0-124 | kernel 6.17.0-35 |
|---|---:|---:|
| Generator kernel-UDP egress (flood) | 11.9–12.0 M qps | **13.4–14.0 M qps** |
| dnsmark XSK TX copy mode (true XDP TX) | **0 qps** (wedged; v0.16.9 reproduced) | **6.9 M qps** |
| `xdp: no` served max (closed-loop curve) | 4.09 M (VLAN) / 4.73 M (public + manual IRQ pin) | **5.03 M** (public) |
| `xdp: no` under flood | ~2.5–3.1 M (collapse, ring discards) | ~3.07 M (collapse, 14.3 M offered) |
| XDP copy served, 1 port, 32 queues | 7.85 M (eno2/VLAN) / 6.8 M (eno1/public) | **7.98 M @ 11.1 M offered; 7.34 M @ 12.9 M offered; peak 9.09 M; 0 discards** |
| XDP copy served, 1 port, **64 queues** | — | 6.64 M + ring discards (**worse** than 32) |
| AF_XDP zero-copy bind | errno 95 | **errno 95 (unchanged)** |

**Setup checks:** warm-cache NOERROR 99.7 % everywhere; closed-loop p50 0.035–0.049 ms
at moderate rates on both kernels and both paths.

## 5. Interpretation

- **(a) The "~10 M no-loss `xdp: no`" expectation is not reproducible** — on either
  kernel, either path, with or without manual IRQ pinning. The v0.16.9 line it comes
  from says "≈10.3 M qps **received**, 0 drops, generator-limited, *(reference,
  off-rig)*": NIC counters show arrival, not service; a host that drops at the UDP
  socket layer (`RcvbufErrors`) still shows 0 NIC drops. Every *serving* measurement
  of this slow path lands at 4–5 M with a deep-flood collapse — consistent with the
  X710 rig where the same v0.17.0 slow path, **with its auto-tune fully working**,
  measured 7.3 M. On bnxt the auto-tune applies only RPS (`nic_queues=0,
  irqs_pinned=0` — filed), and manual IRQ pinning recovered only ~+0.6 M.
- **(b) "XDP below the X710" is structural: copy mode vs zero-copy.** The copy-mode
  drain ceiling is ~8 M qps/port — stable across kernels (7.85 → 7.98 M), paths
  (VLAN/public), and queue counts (64 queues is worse: more workers contending for
  the same copy bandwidth). The X710's 10.1 M on a 10 G link is a **zero-copy**
  number. `bnxt_en` still has no ZC on 6.17 (errno 95). On this NIC the gap is not
  closable in software; the rig recommendation stands (Intel `ice`/`i40e` or
  Mellanox `mlx5` to measure the real ceiling, which CPU-wise is far above —
  8 M/port is served at ≤10 % CPU).
- **Kernel 6.17 is worth keeping on this rig**: +18 % generator egress, the bnxt XSK
  TX un-wedged (0 → 6.9 M — relevant to dnsmark, still below its kernel-UDP path),
  and `rxvlan off` accepted (already true on 6.8-Ubuntu, unlike 6.12-Debian).
- The dual-link result (9.07 M avg / 11.13 M peak) predates the VLAN removal and
  could not be re-run on 6.17 (no second L2 path). Projected 6.17 dual figures:
  **I cannot confirm this.**

## 6. Appendix — exact commands & configuration

```bash
# Kernel upgrade (both hosts) + reboot
apt-get install -y linux-generic-hwe-24.04   # installs 6.17.0-35-generic on 24.04.4
# after reboot: re-run tune-common.sh (governor, hugepages, sysctl, flow-control, RSS, rings)
# + manual IRQ pin (auto-tune no-ops on bnxt) + coalescing:
i=0; for irq in $(grep eno1 /proc/interrupts | cut -d: -f1); do echo $i > /proc/irq/$irq/smp_affinity_list; i=$((i+1)); done
ethtool -C eno1 rx-usecs 25

# Receiver configs: as the main reports, bound to 109.94.96.53 (public path)
#   xdp:no  -> runbound-noxdp-pub.conf ; xdp:yes -> runbound-xdp-pub.conf (xdp-interface: eno1)

# Queue-count test
ethtool -L eno1 combined 64   # then re-pin IRQs; measured worse than 32 -> reverted

# dnsmark XSK TX on a routed path (true XDP TX requires the next-hop MAC):
ip neigh replace 109.94.96.53 lladdr $(ip neigh show 109.94.96.42 | awk '{print $5}') dev eno1 nud permanent
sudo dnsmark -s 109.94.96.53 -d corpus_a.txt --xdp -Q 0 --max-outstanding 0 -l 15 -q --no-tui

# Loads, truth and wire procedure: identical to the main reports (kernel-UDP floods,
# N-instance closed-loop curve, ethtool -S port HW counters at 1 Hz).
# 6.17 counter note: use rx_ucast_frames / tx_ucast_frames (port HW), not *_packets (sw).
```
