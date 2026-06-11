# Runbound Benchmark — v0.17.2 — Latitude rs4.metal.xlarge (EPYC 9554P / BCM57508 100G), `xdp: yes` single link — 2026-06-11

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, this report writes exactly **"I cannot confirm this."**

## 1. Executive Summary

Runbound v0.17.2 with the AF_XDP fast path on one BCM57508 100 G port (802.1Q VLAN
link) served a sustained **7.85 M qps** (receiver NIC `tx_ucast_frames`) under an
open-loop offered load of ~10.8 M qps, at **~8 % CPU** of 128 threads, 0.41 GiB RSS,
**0 NIC ring discards and no overload collapse** — back-to-back against `xdp: no` on
the same rig (4.09 M served at 32 % CPU, collapsing under flood), the fast path serves
**+92 %** at a quarter of the CPU. This is achieved **entirely in AF_XDP copy mode**:
`bnxt_en` still has **no AF_XDP zero-copy** (`XDP_ZEROCOPY` bind → `EOPNOTSUPP`,
errno 95, every queue — re-confirmed on Ubuntu 24.04 / kernel 6.8). Wire-anchored
latency (generator-side tcpdump, 30 k qps, warm cache): **p50 0.024 ms / p95 0.045 /
p99 0.054** — half the slow-path wire p50. The ceiling of this run is the offered
load and the copy-mode XSK drain, not Runbound's CPU; the true fast-path ceiling on a
zero-copy NIC remains unmeasured on this rig: **I cannot confirm this.**

## 2. Objective

Second of three runs: measure the AF_XDP fast path on one 100 G port,
back-to-back against the `xdp: no` baseline
([report](RUNBOUND-v0.17.2-latitude-epyc9554p-bnxt-noxdp-2026-06-11.md)) — same hosts,
same link, same corpus, same generator, one variable changed. Also: re-test the
v0.16.9 blockers on the new OS (Ubuntu 24.04 / kernel 6.8): AF_XDP zero-copy
availability on `bnxt_en`, and the 802.1Q VLAN fast path (#188).

## 3. Methodology & Architecture

Identical to the `xdp: no` run except:

- **Receiver:** `xdp: yes`, `xdp-interface: eno2` (physical port; the 802.1Q tag is
  handled by the #188 VLAN-aware fast path). XDP program attached **mode=Drv**
  (native), 32 queues, AF_XDP rings auto-sized 16384 from the 8191 HW ring, UMEM on
  2 MiB hugepages — **every queue bound `mode="copy"`** (zero-copy unavailable, see
  §4/§5). XDP cache snapshot held 9 985 of the 10 000 corpus names after warmup.
- **VLAN handling — two validated configurations on bnxt:**
  1. default `rx-vlan-offload on` (HW strips the RX tag before XDP) +
     `RUNBOUND_XDP_VLAN=2126` to re-tag replies — as documented in #188;
  2. **`ethtool -K eno2 rxvlan off`** — accepted on this kernel (it was refused on
     the 6.12 kernel of the v0.16.9 run): the tag reaches XDP, the #188 parse skips
     it and the in-place TX reply **preserves it per packet, no env var needed**.
     Both passed functional + load tests; the measurements below used (1) for the
     curve/flood and (2) was validated at 200 k qps (99.74 % NOERROR, p50 0.037 ms).
- **Generator:** dnsmark v2.2.1 kernel-UDP transport (see §5 — `--xdp` is unusable
  on this NIC). Same N-parallel-instance curve + open-loop flood as the baseline.
  This is an asymmetric datapath pairing (kernel client → XDP server); it measures
  the server's serving rate and a kernel-client RTT, both comparable with the
  baseline run which used the same generator datapath.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained served QPS | **7 850 000 qps** avg over 20+ s under ~10.8 M offered (72.7 %) | receiver NIC `tx_ucast_frames` 1 Hz deltas |
| Served burst peak | ~9.7 M qps (1 s) | same |
| Overload behaviour | **no collapse**: served stays 7.8–7.9 M/s for the whole flood | same |
| NIC ring discards | **0** throughout (curve + flood) | `rx_total_ring_discards` |
| AF_XDP zero-copy | **Unavailable** — `bind … zerocopy=true: Not supported (os error 95)`, every queue | dnsmark XSK bind log; matches v0.16.9 mainline-source verdict |
| dnsmark `--xdp` (copy mode) generation | unusable for rate: ~8.3 k qps completed closed-loop; ramp claims 123 k egress while its PHY wire-guard reads 0 (bnxt counter-name gap — filed) | dnsmark output |
| Fast-path attribution | xdp_worker_distribution sum = 627 M queries served by XSK workers; `xdp_mode=drv`, `xdp_active=true` | `/api/system` |
| Latency (wire, 30 k qps) | **p50 0.024 / p95 0.045 / p99 0.054 ms** | generator-side tcpdump, 29 911 pairs |
| Latency (dnsmark RTT, ~550 k closed-loop) | p50 0.19 ms, p95 ~20 ms, p99 ~78 ms (heavy tail, stable across 2 runs) | dnsmark |
| Success rate (warm) | 99.74–99.81 % NOERROR | dnsmark rcode breakdown |
| Receiver CPU during flood (7.85 M served) | **~7.9 %** of 128 threads | /proc/stat sampler |
| Receiver CPU at 6.4 M served (curve) | ~17 % | same |
| Receiver RAM (runbound RSS) | 0.41 GiB | `ps -o rss` |

Load curve (N parallel closed-loop instances, NIC truth, 12 s windows):

| N | offered (NIC rx/s) | served (NIC tx/s) | served/offered | CPU % |
|--:|---:|---:|---:|---:|
| 1 | 558 583 | 556 517 | 99.6 % | 2.9 |
| 2 | 1 043 697 | 1 016 535 | 97.4 % | 4.8 |
| 4 | 1 786 554 | 1 606 704 | 89.9 % | 6.9 |
| 8 | 6 063 845 | 6 001 908 | 99.0 % | 15.7 |
| 16 | 6 415 436 | **6 379 385** | **99.4 %** | 17.0 |
| 24 | 5 591 920 | 5 578 668 | 99.8 % | 16.1 |
| 32 | 5 576 808 | 5 563 758 | 99.8 % | 16.3 |
| flood | ~10 800 000 | **~7 850 000** | ~73 % | 7.9 |

## 5. Interpretation

- **The fast path nearly answers everything the generator can offer** up to ~6.4 M
  (99.4 % served at 17 % CPU, 0 discards), and under a 10.8 M flood it serves a
  stable 7.85 M/s at 8 % CPU with no collapse — versus the kernel path's collapse to
  2.5–2.9 M on the same flood. Same rig, same generator: **+92 % served at the flood,
  ~4× less CPU.**
- **The 27 % offered−served gap at the flood (10.8 → 7.85 M) is the copy-mode XSK
  drain limit, not CPU** (8 % busy) and not the NIC ring (0 discards). Per-queue drop
  attribution is not exposed by `bnxt_en`: **I cannot confirm the exact drop point.**
- **Zero-copy remains the blocker on this NIC.** Errno 95 on every queue, unchanged
  by the OS reinstall (Ubuntu 24.04 / 6.8 vs Debian 13 / 6.12). Both rig conclusions
  of v0.16.9 stand: it is a driver-feature gap (`bnxt_xdp.c` has no XSK pool
  support), only a different NIC (Intel `ice`/`i40e`/`ixgbe`, Mellanox `mlx5`)
  lifts it. With ZC unavailable, **the true fast-path ceiling of this CPU class on
  100 G is not measurable here**: I cannot confirm this.
- **The #188 VLAN fast path is now throughput-validated in copy mode** (it was only
  functionally validated in v0.16.9): 7.85 M qps served over the tagged link, and —
  new on this kernel — `rxvlan off` works on bnxt, enabling the env-var-free
  per-packet tag-preserve path. The "100 % loss before the fix" failure mode did not
  reappear.
- **Latency trade-off:** at light load the fast path halves the wire p50 (24 µs vs
  47 µs). At ~550 k closed-loop the dnsmark RTT shows p50 0.19 ms with a heavy tail
  (p95 ~20 ms) not present on the kernel path at the same rate — consistent with
  copy-mode wakeup/batching under concurrent load. Receiver-side wire capture is
  impossible in XDP DRV mode (the datapath bypasses the kernel tap): **I cannot
  confirm receiver-side wire latency.**
- dnsmark issues found this run (to file): (a) the wire-truth PHY guard reads 0 on
  bnxt (counter-name gap → "fictional egress" warning even when responses flow);
  (b) `--xdp` not available as non-root (silent "AF_XDP not available").

## 6. Appendix — exact commands & configuration

```bash
# --- Receiver (same host tuning as the xdp:no run) ---
# config = runbound-receiver-bench.conf with: interface: 10.21.26.2 ; xdp: yes ; xdp-interface: eno2
RUNBOUND_XDP_VLAN=2126 ./runbound -c runbound-xdp-single.conf       # variant 1 (HW strip + re-tag)
#   or:
ethtool -K eno2 rxvlan off && ./runbound -c runbound-xdp-single.conf  # variant 2 (#188 per-packet preserve)
# startup log: "XDP program attached iface=eno2 mode=Drv", 32× "queue bound mode=\"copy\"",
#              "UMEM: huge pages active (2 MiB)", rings 16384 from HW 8191

# --- Zero-copy availability check (generator, root required) ---
sudo DNSMARK_VLAN=2126 ./dnsmark -s 10.21.26.2 -d corpus_a.txt --xdp -Q 100000 -l 5 --no-tui
#  → "AF_XDP zero-copy FAILED — fell back to COPY mode (slow) … Not supported (os error 95)" ×8 queues

# --- Load (kernel-UDP generator, same as baseline) ---
dnsmark -s 10.21.26.2 -d corpus_a.txt -Q 200000 -l 20 -q --no-tui            # warmup
# curve N ∈ {1..32}: dnsmark … -Q 0 --max-outstanding 20000 -t 100 -l 12
# flood:             dnsmark … -Q 0 --max-outstanding 0 -l 25

# --- Truth (receiver) ---
ethtool -S eno2 | grep -E 'rx_ucast_frames|tx_ucast_frames|rx_total_ring_discards'
curl -H "Authorization: Bearer $(cat api.key)" localhost:8080/api/system   # xdp_mode, worker distribution

# --- Wire anchor (generator side only; receiver tap is bypassed in DRV mode) ---
dnsmark -s 10.21.26.2 -d corpus_a.txt -Q 50000 -l 12 -q --no-tui &
tcpdump -i eno2 -nn --time-stamp-precision=micro -c 60000 -w t2.pcap 'udp port 53'
```
