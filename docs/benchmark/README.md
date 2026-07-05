# Runbound — DNS Benchmarking Methodology

> **Results & links:** see [INDEX.md](INDEX.md) for a summary of every run.

This directory defines the **standard methodology** for every Runbound performance
benchmark. Each run produces one report file following [TEMPLATE.md](TEMPLATE.md).
All numbers are produced under this process so they are comparable and reproducible.

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
- **Dataset:** `docs/benchmark/corpus/top-100000-resolving.txt` — 100 000 real, varied DNS
  names, read in **random** order (not round-robin, to avoid an unrealistic cache
  pattern).

---

## Measurement rules (apply every time)

Each rule below prevents a specific way a measurement goes wrong:

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

**CPU accounting.** The receiver-CPU figure is the **whole-machine host utilisation**
during the flood window, from `mpstat` on the receiver: `%usr + %nice + %sys + %irq +
%soft`, averaged over all 128 cores. This includes the softirq/kernel cost (NIC IRQs,
`ksoftirqd`, ring fill/drain) — i.e. the *total* host cost of serving, not just the
resolver process. `%guest`/`%steal` (this host also runs unrelated VMs) are **excluded**
so the figure reflects the DNS bench, not co-tenant load. Report it as a percentage of
the machine (e.g. "10 % of 128 cores"), with the idle baseline for context. Do **not**
report a per-process core count — it misses the softirq cost and is not what this column
means.

---

## Cross-checking dnsmark output against NIC counters

Rule 1 in practice: every dnsmark figure must be confirmed by an independent NIC
counter before it goes into a report. Use dnsmark 1.0 and still cross-check every figure against the NIC counter — a
self-reported round-trip can under-count in firehose mode, which is the
reason rule 1 exists; prefer the latest signed release.

| dnsmark output line | Confirming counter | Expected agreement |
|---|---|---|
| `Send throughput (egress)` | Receiver NIC `rx_packets + rx_missed_errors` ÷ window | ≤ ~2 % (offered load actually reached the server) |
| `Wire egress (NIC PHY)` | Generator NIC PHY/HW TX register ÷ window | ≤ ~1 % (AF_XDP ZC bypasses the software `tx_packets`; read HW registers) |
| `Server throughput (NIC rx)` — **authoritative** | Receiver NIC `tx_packets` (ASIC) ÷ window | ≤ ~2 % — this pair is the headline number |
| `Round-trip completed` (userspace) | none — diagnostic only | ≤ `Server throughput (NIC rx)`; the gap is **generator-side** loss (kernel socket / ring overflow), not server loss |

How to read a mismatch:

- **`Server throughput (NIC rx)` vs receiver `tx_packets` disagree** → the measurement
  window is wrong (samples taken outside the load window) or another flow shares the
  NIC. Fix the run; do not report either number.
- **`Round-trip completed` well below `Server throughput (NIC rx)`** → dnsmark prints a
  NOTE; the NIC-rx figure is the truth. Report NIC-rx as server throughput and mention
  the generator drop. Never report the userspace round-trip as server capacity.
- **`Send throughput` vs receiver rx disagree** → frames were lost before the server
  (flow control back on? switch in the path?). Re-check rule 3 and the link.

Measured reference for the agreement bands (X710 10 GbE direct link, 2026-06-23):
receiver NIC `tx_packets` 5.15M/s vs dnsmark 5.13M/s (kernel path, 0.4 %) and 11.24M/s
vs 11.19M/s (XDP path, 0.5 %). The window is the run duration printed by dnsmark;
sample the receiver counters with a per-second sampler started **before** the flood
(`nic-sample.sh`-style), because SSH polling during an XDP flood is unreliable on the
flooded host.

---

## Ramp mode (Dichotomic Saturation Discovery)

`--ramp` is the standard way to find the saturation knee (Tooling, phase 2). It runs
in two phases:

1. **Logarithmic discovery** — start low and double the offered QPS until the p50
   round-trip latency breaks the SLO (auto-computed as `max(3 × floor, floor + 1 ms)`,
   floor = minimum p50 observed at low load).
2. **Dichotomic convergence** — binary-search inside the last good/bad bracket until
   within 5 %, and report the real knee, not the lower power of two.

The saturation signal is the **median (p50)**, not p95/p99: forwarded cache-misses
produce tail outliers that are a property of the workload, not of server saturation.
Each step resets its latency histogram, so percentiles describe that step only.

What the final `Capacity` line means depends on the datapath — do not mix them up in
reports:

- **`--xdp` ramp** = open-loop firehose with lossless zero-copy RX → `Capacity` is the
  **NIC-verified wire ceiling** (max replies/s on the wire).
- **kernel-UDP ramp** (default transport) = gated closed loop, generator-recv bound →
  `Capacity` is the **closed-loop SLO knee, NOT the server's raw ceiling**. For the raw
  ceiling run an open-loop flood (`dnsmark -s <ip> -Q 0 --max-outstanding 0`) and read
  `Server throughput (NIC rx)`.

Reporting requirements for every ramp run:

- Report the **knee bracket** `[low ; high] (±%)` as printed — a band, per rule 8 —
  plus the idle latency floor and the Within-SLO rate.
- Label the Capacity figure with its datapath meaning (wire ceiling vs closed-loop
  knee) exactly as dnsmark prints it.
- Record the dnsmark version. Multi-NIC ramps use a single unified DSD
  across links: one aggregate knee + per-NIC breakdown. An independent ramp per NIC
  cross-couples through the shared server CPU and does not converge, so the unified
  DSD is required.
- A ramp answers "where is the knee"; a fixed/flood run answers "what is the raw
  ceiling". A full report needs both, cross-checked against NIC counters as above.

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
`RUNBOUND-v0.9-threadripper-2026-06-07.md`).
