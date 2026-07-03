<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Bench notes — de-hickory branch, 100k corpus (2026-06-20)

> **RESOLVED in v0.22.3 (2026-06-23, #209).** The 100 K dual-NIC throughput question this file
> left open turned out to be a real regression: `DomainStats::flush_tl` called `DashMap::len()`
> (all-shard read lock) per untracked key, and at >`MAX_TRACKED` cardinality with many workers that
> lock storm halved aggregate serving (dual X710+X520: 12.4M → 21.1M after the fix). It was *not*
> a cache/memory-bandwidth limit (a 100 K table is ~10 MB, fits the 5995WX's 256 MB L3 25×). See
> CHANGELOG `[0.22.3]` and issue #209.

Run of the fast/slow-path bench against the `feat/dehickory` build with a
**100 000-domain** corpus (vs the standard 10 000), per request. This file is
**notes, not a results report** — the throughput A/B came out **inconclusive**
because the X710 wedged mid-run. The honest state is recorded so the next run
starts clean.

## Rig
- Receiver: dragonrage (Threadripper 5995WX, 128c), X710 `enp33s0f0np0` =
  10.71.10.1, single-NIC. Governor `performance`, flow-control off, combined 64.
  Config = `runbound-bench-x710-xdp.conf` with `xdp-cache-snapshot-size` bumped
  **65536 → 131072** so the 100k corpus fits the snapshot. **Windows VMs were
  off** (only DNS-Server-01 running; host load avg ~4 / 128 — no CPU contention).
- Generator: dragonsage (Xeon E5-2690 v2 ×2), X710 `enp66s0f1np1` = 10.71.10.2.
- Corpus: Umbrella top-1m → first 100 000 domains.
- Binaries: `runbound-bench-dehickory` (0.21.0, this branch) vs
  `runbound-bench-020` (0.20.0 baseline).

## Methodology fixes established this run (the keep-able wins)
1. **Generator was NUMA-starved.** `dnsmark --xdp` ran at only ~2.3 M qps egress.
   The egress NIC is on **NUMA node 1**; pinning dnsmark to it
   (`numactl --cpunodebind=1 --membind=1 dnsmark …`) jumped egress to
   **~11.18 M qps** — the expected ~10M+. Cross-NUMA was the cap, exactly the
   "16q@core0 → 1.78M" hazard. **All `--xdp` generator runs must use numactl.**
2. **Warmup must be rate-limited, not a flood.** A flood (`--max-outstanding 0`)
   drowns the slow path so it forwards almost nothing → cache never fills
   (round-trip ~4%). A controlled warmup (`--max-outstanding 1000`, ~400k qps)
   fills it cleanly → **96.6 % round-trip**. The warmup's job is to fill the
   cache; it can't do that while saturating the box.
3. **In XDP zero-copy mode the software `tx_packets` counter reads 0.** Truth on
   the served direction is the ASIC counter **`tx_unicast`** (+ `rx_unicast`,
   `rx_missed_errors`) from `ethtool -S`, not `tx_packets` and not dnsmark's
   self-reported round-trip (which under-counts massively on the XDP path).

## What was measured (and why it is NOT trustworthy)
- de-hickory, cache warm: **~7.26 M served (`tx_unicast`), 13.5 % `rx_missed`**.
- baseline 0.20.0: **0 served, 55 % drops** — its warmup had been cut by an SSH
  timeout, so the cache was empty; not a valid point.

Both are unreliable: the receiver logged
`maximize_nic_ring: Device or resource busy` and
`XDP self-test: no loopback frames … expected in SKB mode` — i.e. the X710 had
fallen into a **degraded / SKB-fallback XDP state**, wedged by repeated XDP
attach/detach + floods (the documented i40e wedge). SSH to the host then went
unresponsive (pings, SSH hangs). A degraded XDP path explains 7.26M-with-drops
vs the published baseline (10.12 M single-NIC at ~11 % CPU, **0 drops**, 10k
corpus, native DRV — the 10 G link is the cap there, not the server).

**No regression verdict is drawn.** The de-hickory hot loop (`answer_dns_wire`,
the A/AAAA fast path) is byte-identical to baseline — the branch only changed the
slow-path fallback and removed unused imports — so in principle the fast path is
unaffected, but that is **not proven here** because the rig wedged before a clean
A/B on the same 100k corpus.

## To get a clean number next time
1. **Reboot / FLR the X710** on the receiver first (de-wedge the i40e), confirm
   native DRV attach (no SKB self-test warning, no ring-busy).
2. Single clean sequence per binary: start receiver → **numactl** controlled
   warmup until round-trip ≥ 95% → `--xdp -Q 0 --max-outstanding 0` (numactl)
   throughput window → read `tx_unicast` delta over a timed window. Then the
   other binary, identical steps. A/B on `tx_unicast`.
3. 100k corpus has more dead domains than 10k → a higher steady miss rate that
   drives slow-path forwarding; expect lower served + some drops vs the 10k
   numbers regardless of branch. Compare branch-vs-branch on the **same** corpus,
   never branch-vs-published-10k.
