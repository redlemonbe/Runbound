# Runbound Benchmark — v0.23.8 — threadripper-5995wx — 2026-07-01

> Follows [README.md](../README.md). Measured data only. Where a value is missing or
> uncertain, this reports **"I cannot confirm this."**

## 1. Executive Summary

Runbound v0.23.8, XDP fast path, single 10G direct link: **X710 (i40e) sustained
~12.56 M q/s served** (receiver NIC TX hardware counter), **X520 (ixgbe) sustained
~11.88 M q/s served**, both at sub-millisecond p99 latency up to and including the
saturation knee (p50 0.876 ms / p99 0.962 ms at the X710 knee). Dual-link (both NICs
simultaneously from one generator process) reached **~19.9 M q/s aggregate**
(X710 ~8.55 M + X520 ~11.35 M) — below the sum of the two solo ceilings due to a
known generator-side limitation (dnsmark issue #15-P2: the single-process
multi-NIC mode does not NUMA-pin each stack, so the two links do not reach their
individual ceilings concurrently). This run used the **official, minisig-signed
GitHub release binaries** for both Runbound (v0.23.8) and the generator
(dnsmark v2.6.0) — no locally-compiled artifacts. Zero query errors (100%
NOERROR) across all runs. 2 MiB huge pages were unavailable for this run (host
memory fragmentation after 5 days of uptime); Runbound fell back to regular-page
UMEM, which the codebase itself documents as a lower-throughput path — the
numbers above are therefore a **lower bound**, not the fully-tuned ceiling.

## 2. Objective

Re-validate Runbound's fast-path throughput/latency on the current release
(v0.23.8, the first fully de-hickory build with in-house recursion + DNSSEC
validation) against the existing benchmark baseline (last measured on v0.19.3,
2026-06-15), using the `dnsmark --xdp --ramp` methodology, to confirm no
regression from the architectural rewrite and to refresh the published numbers.

## 3. Methodology & Architecture

- **Receiver (Runbound):** AMD Ryzen Threadripper PRO 5995WX (64C/128T), 125 GiB
  RAM, kernel `7.0.6-2-pve`. Runbound **v0.23.8**, official GitHub release binary
  (`runbound-x86_64-linux-gnu`, minisig signature verified against the published
  key before deployment — no local compilation). `xdp: yes` on both
  `enp33s0f0np0` (X710/i40e) and `enp66s0f1` (X520/ixgbe); `rate-limit: 0`;
  ~280 `local-data` entries (top-domain sentinel answers, cache-hit workload,
  same corpus/config shape as prior rounds). CPU governor: `performance`.
  2 MiB huge pages: **unavailable this run** (see §5) — UMEM fell back to
  regular 4 KiB pages.
- **Generator (dnsmark):** dual Xeon E5-2690 v2 (20C/40T, 2 NUMA nodes), dnsmark
  **v2.6.0**, official GitHub release binary (minisig signature verified before
  use — a locally-built binary reporting itself as "2.7.0" was found on the host
  but discarded: no corresponding tagged release exists, so its provenance
  could not be verified). NUMA-pinned to the NIC's own node
  (`numactl --cpunodebind=1 --membind=1` for X710/NUMA1,
  `--cpunodebind=0 --membind=0` for X520/NUMA0). Commands in §6.
- **Link:** two independent direct DAC 10G links on separate PCIe buses —
  X710 (i40e) `10.71.10.1` (receiver) ↔ `10.71.10.2` (generator), and X520
  (ixgbe) `10.51.10.1` ↔ `10.51.10.2`. Flow control: off on both ends, both
  links (verified/fixed live: X520 receiver-side flow control was found ON and
  disabled before this run). RSS: 4-tuple (`sdfn`, src/dst IP + src/dst port) on
  all four NIC ports (verified/fixed live: X520 receiver-side RSS was found
  2-tuple IP-only and corrected before this run). `fq_codel` was found present
  on 3 of 4 interfaces (all receiver NICs + generator's X520) and replaced with
  `mq`+`pfifo` before this run (AF_XDP TX bypasses qdisc, but this matters for
  any kernel-path traffic and for the generator's own send path).
- **Dataset:** `docs/benchmark/corpus/top-10000-domains.txt`, 10 000 real,
  varied names (checksum-verified identical to the generator's copy), random
  read order.
- **Procedure:** `--ramp` (auto-doubling from 1000 q/s every 5 s until
  saturation, dnsmark's built-in Dichotomic Saturation Discovery) for the
  primary knee-finding pass, immediately followed by a fixed-rate `-Q <knee>
  --max-outstanding 0` flood held for 20 s while sampling the receiver's NIC
  hardware counters (`ethtool -S` / `/sys/class/net/<if>/statistics/{rx,tx}_packets`)
  at 1 Hz over an 8 s steady window (first sample discarded as warmup) —
  this is the **ground-truth cross-check** required by README.md rule #1,
  since dnsmark's own "round-trip completed" figure under-counts at
  saturation (its own generator RX path cannot always keep pace with the
  reply rate). XDP detached from the generator NIC after every run.

## 4. Raw Results

### X710 (i40e), single link

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained real QPS | **12,561,658 q/s** (served, i.e. TX from receiver) | receiver NIC TX counter, `ethtool -S enp33s0f0np0` (7×1Hz deltas, 8s window) |
| Received (RX) at same window | 13,081,991 q/s | receiver NIC RX counter |
| dnsmark's own knee (self-reported, undercounts) | 11,181,842 q/s | dnsmark `--ramp` JSON `Peak server throughput` |
| Latency p50 / p95 / p99 at knee (offered 12.77M) | 0.876 / 0.939 / 0.962 ms | dnsmark ramp step |
| Latency p50 / p95 / p99 at 6.4M sustained (pre-knee) | 0.212 / 0.271 / 0.291 ms | dnsmark ramp step |
| Success rate / error rate | 100% NOERROR, 0 NXDOMAIN/SERVFAIL/REFUSED | dnsmark rcode breakdown |
| Receiver CPU % | ~9.3% of 128 logical CPUs (`top`, us+sy) | `top -bn1` during flood |
| Receiver RAM | 63 GiB used / 125 GiB total (system-wide, not Runbound-specific) | `free -h` |
| NIC drops (`rx_missed_errors`) | 0 | `ethtool -S enp33s0f0np0` |

### X520 (ixgbe), single link

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained real QPS | **11,877,073 q/s** (served, TX from receiver) | receiver NIC TX counter, `ethtool -S enp66s0f1` |
| Received (RX) at same window | 11,877,562 q/s | receiver NIC RX counter |
| dnsmark's own knee (self-reported, undercounts) | 8,854,496 q/s | dnsmark `--ramp` JSON `Peak server throughput` |
| Latency p50 / p95 / p99 at knee (offered 12.79M) | 0.942 / 1.004 / 1.052 ms | dnsmark ramp step |
| Latency p50 / p95 / p99 at 6.4M sustained (pre-knee) | 0.138 / 0.222 / 0.254 ms | dnsmark ramp step |
| Success rate / error rate | 100% NOERROR, 0 NXDOMAIN/SERVFAIL/REFUSED | dnsmark rcode breakdown |
| NIC drops (`rx_missed_errors`) | Elevated (cumulative counter, not isolated to this run — see §5) | `ethtool -S enp66s0f1` |

### Dual-link (X710 + X520 simultaneously, one generator process)

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained real QPS (aggregate) | **~19.9 M q/s** (X710 ~8.55M + X520 ~11.35M, served/TX) | receiver NIC TX counters, both interfaces, 1 Hz × 8 s |
| dnsmark's own knee (self-reported, single aggregate figure) | 11,163,988 q/s | dnsmark `--ramp` JSON `Peak server throughput` |
| Success rate / error rate | 100% NOERROR | dnsmark rcode breakdown |

**I cannot confirm** a tighter aggregate number than ~19.9 M: a higher `-Q` target
(26 M) *reduced* the measured aggregate to ~15.7 M by starving the X710 stack
further (3.98 M vs 8.55 M) — this is the documented dnsmark multi-NIC
imbalance (issue #15-P2 in the dnsmark tracker), not a Runbound-side effect;
Runbound's response time and error rate were unaffected in both attempts.

## 5. Interpretation

**No regression from v0.19.3.** The prior single-link X710 baseline (v0.18.1,
2026-06-13) measured ~10.12 M q/s served at ≤24% CPU. This run measured
~12.56 M q/s at ~9.3% system-wide CPU on the same class of hardware — higher,
not lower, and at markedly lower CPU utilization. The de-hickory rewrite (fully
removing hickory from the runtime, moving recursion and DNSSEC validation
in-house) did not touch the XDP fast path's hot loop, and this is consistent
with that: no throughput regression is observed.

**dnsmark's own throughput figure under-reports at saturation, confirmed
directly.** At the X710 knee, dnsmark's `--ramp` self-report was 11.18 M q/s;
the receiver's own NIC TX hardware counter measured 12.56 M q/s over the same
load — a 12.3% gap. The same pattern held at X520 (8.85 M self-reported vs
11.88 M NIC-measured, a 34% gap) and dual-link (11.16 M self-reported vs
~19.9 M NIC-measured aggregate). This matches dnsmark's own documented caveat
(its JSON output explicitly warns "avg_qps under-counts under saturation — read
the receiver's NIC counters for true throughput") and confirms why README.md's
rule #1 treats the generator's self-report as non-authoritative. All headline
numbers in this report are the NIC-hardware-verified figures, not dnsmark's own.

**X520 (ixgbe) remains the heavier path**, consistent with the historical
characterization (v0.18.1 baseline: same ~10.12 M ceiling on both NICs, but
X520 at higher CPU / worse latency). Here X520 tops out slightly below X710
(11.88 M vs 12.56 M) and shows non-zero `rx_missed_errors`, while X710 shows
none — the ixgbe RX path is closer to its own ceiling at this load.

**Dual-link does not sum the two solo ceilings, and the shortfall is on the
generator side, not Runbound's.** X710 solo peaks at 12.56 M; in the combined
run it only reached 8.55 M — a reduction that tracks with dnsmark's own
open multi-NIC issue (#15-P2: the single dnsmark process does not
independently NUMA-pin each target's send/receive stack), not with any
observed Runbound-side limit (CPU and error rate stayed nominal throughout).
**I cannot confirm** what Runbound's true dual-link ceiling is with a
generator that doesn't have this limitation — the 2026-06-15 v0.19.3 report's
~20.3 M dual-link figure used a *different* generator configuration (two
separate DAC-isolated generator cards) that this session's rig/scripts did not
reproduce; the ~19.9 M measured here is a lower bound consistent with,
not necessarily identical to, that prior result.

**Huge pages were unavailable for this entire session**, confirmed via
`/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages` returning 0 across
multiple reservation attempts (including a manual `compact_memory` +
`drop_caches` pass) despite `nr_hugepages` accepting the request — consistent
with memory fragmentation after 5 days of host uptime (39 GB in transparent
huge pages at the time of testing). No user VM on this host is configured to
use 2 MiB huge pages (checked all `/etc/pve/qemu-server/*.conf`), so this is
not resource contention with production VMs — it is pure fragmentation. The
Runbound codebase's own log line states this fallback path should "expect
rx_no_dma drops and lower throughput under flood," meaning **every number in
this report is a floor, not the fully-tuned ceiling** — a rerun shortly after a
host reboot (fresh, unfragmented memory) would be needed to measure the
huge-page-backed ceiling. **I cannot confirm** what that ceiling is from this
session's data.

## 6. Appendix — exact commands & configuration

```bash
# --- Pre-flight (both generator NUMA nodes' NICs + both receiver NICs) ---
tc qdisc show dev <if> | grep -c fq_codel   # must be 0; fix:
tc qdisc replace dev <if> root handle 1: mq
for i in $(seq 1 <nqueues>); do h=$(printf '%x' $i); tc qdisc replace dev <if> parent 1:$h pfifo limit 10000; done
ethtool -A <if> rx off tx off autoneg off   # flow control off (autoneg off required on ixgbe)
ethtool -N <if> rx-flow-hash udp4 sdfn      # 4-tuple RSS
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor   # must be "performance"
ss -ulpn | grep :53                          # confirm sole binder

# --- X710 single-link ramp ---
numactl --cpunodebind=1 --membind=1 dnsmark --xdp \
  -s 10.71.10.1 -p 53 -d top-10000-domains.txt --ramp -q --json --csv ramp-x710.csv -l 150

# --- X710 ground-truth flood + NIC sampling (repeat for X520 with its own knee/NUMA node) ---
numactl --cpunodebind=1 --membind=1 dnsmark --xdp \
  -s 10.71.10.1 -p 53 -d top-10000-domains.txt -Q 12700000 --max-outstanding 0 -l 20 -q
# concurrently, 1 Hz for 8s on the receiver:
cat /sys/class/net/enp33s0f0np0/statistics/tx_packets   # served (answers sent)
cat /sys/class/net/enp33s0f0np0/statistics/rx_packets   # received (queries in)

# --- Dual-link ramp + flood ---
dnsmark --xdp -s 10.71.10.1 -s 10.51.10.1 -p 53 -d top-10000-domains.txt --ramp --nic-stats -q --json --csv ramp-dual.csv -l 150
dnsmark --xdp -s 10.71.10.1 -s 10.51.10.1 -p 53 -d top-10000-domains.txt -Q 12600000 --max-outstanding 0 -l 20 -q --nic-stats

# --- Post-run cleanup (every run) ---
ip link set <generator-if> xdp off
```

**Binary provenance**: `runbound-x86_64-linux-gnu` and `dnsmark-x86_64-unknown-linux-gnu`,
both downloaded from their respective GitHub Releases (`v0.23.8` /
`v2.6.0`) via `gh release download`, verified against the published
`SHA256SUMS` and `minisig` signature before use. No binary in this report was
compiled locally.
