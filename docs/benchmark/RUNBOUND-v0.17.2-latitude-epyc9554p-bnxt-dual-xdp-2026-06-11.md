# Runbound Benchmark — v0.17.2 — Latitude rs4.metal.xlarge (EPYC 9554P / BCM57508 100G), `xdp: yes` dual link — 2026-06-11

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

With the AF_XDP fast path attached to **both** BCM57508 100 G ports — eno2 carrying
the 802.1Q VLAN test link and eno1 carrying the untagged routed public path
(`xdp-interface: eno1,eno2`, one XDP program + 32 copy-mode XSK queues per port) —
Runbound v0.17.2 served a sustained **9.07 M qps total** (sum of both ports' NIC
`tx_ucast_frames`, 18 s window; **peak 11.13 M qps**) under ~10.6 M qps offered
total, at ~27 % CPU and **0 NIC ring discards**. That is **+15.5 % over the
single-link flood** (7.85 M) at the same total offered load, confirming part of the
single-link offered−served gap is a per-port XSK drain limit. The ceiling of this
run is the **generator** (~10.5–10.6 M qps total, dnsmark kernel-UDP, whether it
floods one port or two) and the copy-mode drain — not Runbound (CPU 27 %, zero
discards). The mixed tagged+untagged dual attach ran with `rxvlan off` on the tagged
port and **no `RUNBOUND_XDP_VLAN`**: each reply preserves per-packet whatever the
query carried (#188).

## 2. Objective

Third run: bring the second port into play, back-to-back against the single-link run
([report](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-xdp-2026-06-11.md)). The VLAN is
delivered on eno2 only (eno1.2126 = 100 % loss, tested), so per the maintainer's
instruction the second link is the **untagged routed public path** (109.94.96.43 →
109.94.96.53, same Latitude fra2 fabric, 1 hop, 0.24 ms) — which also exercises the
mixed tagged/untagged dual-port case that `RUNBOUND_XDP_VLAN` (global) cannot serve.

## 3. Methodology & Architecture

Identical to the single-link run except:

- **Receiver:** `xdp-interface: eno1,eno2`, `interface:` both 10.21.26.2 and
  109.94.96.53, ACL `10.21.26.0/24` + `109.94.96.43/32`. `ethtool -K eno2 rxvlan off`
  (tag reaches XDP; #188 skips it on RX and preserves it on TX per packet — no env
  var; eno1 frames are untagged and replies stay untagged). eno1 tuned like eno2
  (flow-control off, RSS `udp4 sdfn`, rings 2047). XDP attached **mode=Drv** on both
  ports, 2 × 32 copy-mode XSK queues (zero-copy: errno 95, as single-link).
  Since eno1 also carries SSH/management, the attach was done behind a
  **dead-man's switch** (systemd-run timer detaching XDP + killing runbound unless
  cancelled).
- **Links:** link 1 = eno2↔eno2, 802.1Q VID 2126 (10.21.26.1 ↔ 10.21.26.2);
  link 2 = eno1↔eno1 via the provider's routed /31s (109.94.96.43 ↔ 109.94.96.53,
  TTL 63 = 1 hop). Both 100 Gb/s. Not two identical L2 paths — stated, and visible
  in the per-port results (§4).
- **Generator:** dnsmark v2.2.1 kernel-UDP. The dual-target form
  (`-s a -s b`) collapses to ~4.8 M total egress in open loop (multi-target
  artifact — filed), so the max-offered flood used **two single-target processes in
  parallel** (one per destination). Curve: N parallel closed-loop instances
  alternating targets.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained served QPS, total | **9 067 337 qps** avg over 18 s (port eno1 3 938 834 + port eno2 5 128 503) | sum of both ports' NIC `tx_ucast_frames`, 1 Hz deltas |
| Served peak, total | **11 131 215 qps** (1 s) | same |
| Offered at that window, total | 10 611 396 qps avg / 13 064 690 peak | both ports' `rx_ucast_frames` |
| Answer ratio at max offered | 85.5 % avg (97.9 % on the VLAN port, 73.3 % on the public port) | served ÷ offered per port |
| vs single-link flood (same offered ~10.6–10.8 M) | **+15.5 %** (9.07 M vs 7.85 M) | both runs' NIC truth |
| NIC ring discards | **0** (curve + both floods) | `rx_total_ring_discards`, both ports |
| Receiver CPU at max | ~27 % of 128 threads | /proc/stat sampler |
| Receiver RAM (runbound RSS) | 0.41 GiB | `ps -o rss` |
| Public-path fabric loss | generator egress 10.49 M → receiver NIC rx 9.68 M (**~8 % lost upstream of the NIC**) on the eno1-only flood | dnsmark egress vs NIC `rx_ucast_frames` |
| eno1-only flood (single public port) | offered 9.68 M → served 6.48 M (67 %) | NIC counters |
| Success rate (warm, closed-loop) | 99.7 % NOERROR | dnsmark rcode breakdown |
| Latency | kernel-client RTT at N=2 (~1 M qps total): p50 0.19 ms; wire anchor not repeated in dual: **I cannot confirm this** | dnsmark |

Load curve (N parallel closed-loop instances alternating targets, NIC truth, 12 s):

| N | offered total/s | served total/s | port eno1 tx/s | port eno2 tx/s | peak total/s | CPU % |
|--:|---:|---:|---:|---:|---:|---:|
| 2 | 979 208 | 978 204 | 488 685 | 489 519 | 994 977 | 5.9 |
| 4 | 1 698 808 | 1 640 379 | 836 428 | 803 951 | 2 012 506 | 9.3 |
| 8 | 6 968 723 | 6 821 801 | 3 452 255 | 3 369 546 | 6 966 206 | 25.2 |
| 16 | 7 908 181 | **7 851 869** | 4 024 126 | 3 827 744 | **9 552 084** | 27.0 |
| 24 | 7 727 021 | 7 681 890 | 3 916 901 | 3 764 989 | 7 789 744 | 26.9 |
| 32 | 7 388 607 | 7 298 928 | 3 836 307 | 3 462 622 | 7 604 846 | 26.0 |
| flood ×2 | 10 611 396 | **9 067 337** | 3 938 834 | 5 128 503 | 11 131 215 | 26.9 |

## 5. Interpretation

- **Dual-link raises the served ceiling: 9.07 M vs 7.85 M (+15.5 %) at the same
  ~10.6–10.8 M offered.** The single-link gap is therefore partly **per-port** (XSK
  copy-mode drain), not a host-global limit. Runbound itself was again never the
  bottleneck: 27 % CPU, 0 NIC discards, served = offered on the curve up to ~7.9 M
  (99.3 % at N=16).
- **The two links are not equivalent, and the public one is worse end-to-end.** The
  VLAN port answered 97.9 % of its offered flood; the public port 73.3 %, and the
  provider fabric itself dropped ~8 % of the generator's egress before the receiver
  NIC on the eno1-only flood. Whether the eno1 deficit beyond the fabric loss is
  port asymmetry, management-traffic interference, or path policing:
  **I cannot confirm this.**
- **The generator is the offered-load ceiling in dual too** (~10.5–10.6 M total
  kernel-UDP, single or dual destination — same pattern as the X710 dual run where
  the Xeon-v2 generator capped at ~13.2 M regardless of port count). On top of that,
  dnsmark's dual-target mode itself collapses to ~4.8 M (filed); two single-target
  processes were required to reach the generator's real total.
- **Runbound's own ceiling on this rig was not reached** in any of the three runs.
  Given 100 GbE line rate for DNS-sized frames is in the ~100 M pps class, every
  number here is bounded by `bnxt_en`'s missing AF_XDP zero-copy (both sides) and
  the kernel-UDP generator — a **driver-feature gap, not hardware, not fixable by
  kernel upgrade** (re-verified on 6.8 after 6.12). The v0.16.9 recommendation
  stands unchanged: same EPYC class, different NIC (Intel `ice`/`i40e`, Mellanox
  `mlx5`) to measure the real fast-path ceiling.

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver ---
# runbound-xdp-dual.conf: interface: 10.21.26.2 + 109.94.96.53 ; xdp: yes ; xdp-interface: eno1,eno2 ;
#                         access-control: 10.21.26.0/24 + 109.94.96.43/32 ; rate-limit: 0
ethtool -K eno2 rxvlan off                       # tag reaches XDP; #188 preserves per packet; no env var
ethtool -A eno1 rx off tx off ; ethtool -N eno1 rx-flow-hash udp4 sdfn ; ethtool -G eno1 rx 2047 tx 2047
# dead-man (eno1 = SSH port): auto-detach unless cancelled
systemd-run --on-active=480 --unit=deadman-xdp bash -c \
  'pkill -x runbound; ip link set eno1 xdp off; ip link set eno2 xdp off'
./runbound -c runbound-xdp-dual.conf             # "XDP program attached" ×2 (eno1, eno2), 2×32 copy queues
dig @10.21.26.2 google.com ; dig @109.94.96.53 google.com   # both NOERROR → cancel dead-man

# --- Generator ---
dnsmark -s 10.21.26.2  -d corpus_a.txt -Q 200000 -l 10 -q --no-tui   # warmup path 1
dnsmark -s 109.94.96.53 -d corpus_a.txt -Q 200000 -l 10 -q --no-tui  # warmup path 2
# curve: N instances alternating -s 10.21.26.2 / -s 109.94.96.53, -Q 0 --max-outstanding 20000 -t 100 -l 12
# max flood (dual-target -s a -s b collapses to ~4.8M — filed): two parallel single-target processes:
dnsmark -s 10.21.26.2  -d corpus_a.txt -Q 0 --max-outstanding 0 -l 20 -q --no-tui &
dnsmark -s 109.94.96.53 -d corpus_a.txt -Q 0 --max-outstanding 0 -l 20 -q --no-tui &

# --- Truth (receiver, SUM of both ports, 1 Hz timestamped deltas) ---
ethtool -S eno1 | grep -E 'rx_ucast_frames|tx_ucast_frames|rx_total_ring_discards'
ethtool -S eno2 | grep -E 'rx_ucast_frames|tx_ucast_frames|rx_total_ring_discards'
```
