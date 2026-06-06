# 08 — Performance

> **Status: draft outline** — governed by `docs/benchmark/README.md` (the methodology) and
> the per-run reports under `docs/benchmark/`.

This chapter will hold **only measured numbers produced under the documented methodology**.
Until a run is completed under that methodology at the current version, this chapter states
the methodology and the known ceilings, and explicitly says **"I cannot confirm this"** for
any figure not yet re-measured.

## Methodology (summary — see docs/benchmark/README.md)
- Generator: dnsmark. Warmup + ramp to saturation, then a sustained **hold** = the stable
  figure (not the ramp peak). Corpus: Tranco top-10 000, random order.
- **Truth is the NIC hardware counters** (`ethtool -S`: `rx_packets`, `rx_missed_errors`),
  not the generator's self-reported round-trip — in zero-copy mode the software counters do
  not reflect the datapath.
- Governor pinned `performance`; Ethernet flow control off; RSS spread; verify `:53`
  ownership before each run; compare back-to-back only (one variable at a time).

## Known ceilings (context, not a claim of current performance)
- On dual Xeon E5-2690 v2 + X520, the XDP path is limited by the **PCIe/NIC bus served by
  a NUMA node**, not by Runbound CPU — Runbound CPU stayed low while throughput plateaued.
  The exact figure is a function of that rig, not of the software; it is documented in the
  benchmark reports, not asserted here.
- The naïve hickory slow path measured **1.78× Unbound's instructions/query** — the reason
  the fast paths exist (§1.2).

## To expand
- The official v0.15.0 benchmark report once run under supervision.
