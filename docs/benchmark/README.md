# Runbound — DNS Benchmarking Methodology

This directory defines the **standard methodology** for every Runbound performance
benchmark. Each run produces one report file following [TEMPLATE.md](TEMPLATE.md).
Previous ad-hoc reports were removed; all future numbers are produced under this
process so they are comparable and reproducible.

---

## Writing rules (non-negotiable)

- **Objectivity.** State only what the raw data shows. Never invent, speculate, or
  guess. Every claim must trace to a measured value.
- **Transparency.** If a conclusion is not supported by the data, write exactly:
  **"I cannot confirm this."** Do not fill gaps with assumption.
- **Accuracy over prose.** Technical accuracy first. No marketing language, no
  superlatives, no personal bias. The numbers speak for themselves.
- **Forbidden words** (per the security-audit conventions): *production-ready,
  blazing, world-first, military-grade, rock-solid, unbreakable, guaranteed.*

---

## Tooling

- **Generator:** [dnsmark](https://github.com/redlemonbe/dnsmark).
- **Execution model:**
  1. **Warmup phase** — initialise caches, network buffers, and (XDP) the NIC rings
     before any measurement is recorded.
  2. **Ramp phase** — progressively increase offered load to find the **exact
     saturation point** (the QPS beyond which loss or latency degrades).
- **Dataset:** `benchmark/corpus/top-10000-domains.txt` — 10 000 real, varied DNS
  names, read in **random** order (not round-robin, to avoid an unrealistic cache
  pattern).

---

## Measurement rules (lessons learned — apply every time)

These exist because earlier numbers were wrong for these exact reasons:

1. **Measure at the NIC, not the round-trip.** Truth = receiver NIC counters
   (`ethtool -S <nic>`: `rx_packets` + `rx_missed_errors`, and ASIC `tx_packets`),
   **not** the generator's self-reported round-trip QPS. In XDP zero-copy mode the
   `/sys` and ethtool `tx/rx_packets` software counters do **not** reflect the
   datapath — read the HW registers.
2. **Pin the CPU governor to `performance` and warm up** before measuring. DVFS
   ramp-up alone moved the same binary from 5.9M to 7.2M qps. Without this, results
   are not comparable.
3. **Disable Ethernet flow control** on the test link (`ethtool -A <nic> rx off tx off`)
   — 802.3x PAUSE frames otherwise throttle to an artificial plateau.
4. **Spread RSS** so the receiver uses all intended cores
   (`ethtool -N <nic> rx-flow-hash udp4 sdfn`); otherwise everything lands on one queue.
5. **Verify port :53 ownership** (`ss -ulpn | grep :53`) before every run — a
   leftover BIND/Unbound or a second SO_REUSEPORT binder silently contaminates results.
6. **Compare back-to-back only** — same binary, same host, same setup, changed one
   variable at a time. Never compare across machines or kernels as if equal.
7. **Latency truth.** When latency matters, anchor p50/p95/p99 to a `tcpdump`
   capture (wire truth), and document the generator's own overhead separately.
8. **Report a band, not a false-precision point**, when a counter is an estimate
   (e.g. a TX figure derived from `tx_bytes ÷ frame_size`).

If any rule above could not be satisfied for a given run, say so in the report and
write **"I cannot confirm this"** for the affected metric.

---

## Report structure (every run follows this)

1. **Executive Summary** — ultra-concise, factual statement of peak performance.
2. **Objective** — why this benchmark was run.
3. **Methodology & Architecture** — hardware, network, dnsmark configuration,
   dataset distribution. Must be complete enough to reproduce.
4. **Raw Results** — key metrics: real maximum QPS, latency p95/p99, success/error
   rate, CPU/RAM consumption.
5. **Interpretation** — analysis strictly correlated to the raw results. No claim
   without a number behind it.
6. **Appendix** — exact commands and configurations used, for reproducibility.

Name reports `RUNBOUND-vX.Y.Z-<host>-<date>.md` (e.g.
`RUNBOUND-v0.12.0-threadripper-2026-06-07.md`).
