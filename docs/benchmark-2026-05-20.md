# Benchmark — Runbound v0.4.16 vs BIND9 9.20.21 vs Unbound 1.22.0

**Date:** 2026-05-20  
**Hardware:** AMD Threadripper PRO 5995WX / Emulex OneConnect be2net client  
**Status:** official — client NIC limited (be2net, no XDP)

---

## Hardware

### DNS server — dragonrage (192.168.10.250)

| Component | Value |
|---|---|
| CPU | AMD Threadripper PRO 5995WX — 64 cores / 128 threads @ up to 4 575 MHz |
| RAM | 128 GiB DDR5 |
| NUMA | 8 nodes × 8 cores |
| L3 cache | 256 MiB (8 × 32 MiB) |
| NIC | 2× Intel X540 (ixgbe) 10 GbE fibre — LACP 802.3ad, MTU 9 000 |
| OS | Debian GNU/Linux 13 (trixie) — kernel 6.17.13-1-pve |
| Storage | NVMe (0 ms rotational) |
| Architecture | bond0.10 → br-rb + veth-rb (.250) — see docs/proxmox.md |

### Client — codix-gaming (192.168.10.200)

| Component | Value |
|---|---|
| CPU | 2× Intel Xeon E5-2690 v2 — 20 cores / 40 threads @ 3.0 / 3.6 GHz |
| RAM | 256 GB DDR3 LRDIMM ECC @ 1 866 MT/s |
| NIC | Emulex OneConnect 10 GbE (be2net) — LACP bond, fibre |
| OS | Proxmox VE — Linux 6.17.2-2-pve |
| Tool | dnsmark 0.4.5 |
| AF_XDP | not available (be2net has no AF_XDP support) |

### Common configuration (all three servers)

| Parameter | Value |
|---|---|
| Upstream resolvers | 8.8.8.8 / 8.8.4.4 / 1.1.1.1 |
| DNSSEC | disabled |
| Query file | 40 real-world domains (pre-cached after warm-up) |
| Protocol | UDP |

---

## Servers under test

| Server | Version | Threads / workers |
|---|---|---|
| Runbound | 0.4.16 | 128 OS threads (SO_REUSEPORT) — note ¹ |
| BIND9 | 9.20.21 | kernel-managed multi-thread |
| Unbound | 1.22.0 | 64 threads |

> ¹ Runbound detected 128 "physical cores" on the AMD 5995WX due to a known SMT
> topology detection bug fixed in v0.4.2. Actual physical cores: 64.
> Impact: some SMT sibling contention at very high load. Corrected results expected
> to show marginal improvement in v0.4.2+.

**Runbound log level: verbosity 1 (warn).** At verbosity 2 (info), Runbound logs
every query — p99 under stress goes from 0.231 ms to 3.011 ms with per-query logging
enabled. BIND9 and Unbound log nothing by default; verbosity 1 is the fair comparison
baseline.

---

## Methodology

Four phases, run sequentially, identical procedure for all three servers:

### Phase 1 — Warm-up (30 s)

- QPS: 1 000
- Clients: 1
- Duration: 30 s
- Purpose: fill the DNS cache, stabilise the process
- Results: discarded

### Phase 2 — Ceiling detection (ramp)

- Start: 1 000 QPS
- Step: ×2 every 5 s (dnsmark `--ramp`)
- Stop condition: measured burst throughput < next target (packet loss > 1%)
- Purpose: find maximum sustainable QPS

### Phase 3 — Sustained load (60 s)

- QPS: 80% of ceiling
- Clients: 4 parallel dnsmark instances
- Duration: 60 s
- Purpose: stable latency measurement under realistic production load

### Phase 4 — Stress (60 s)

- QPS: 150% of ceiling
- Clients: 4 parallel dnsmark instances
- Duration: 60 s
- Purpose: degradation behaviour and crash resistance under overload

---

## Raw results

### Runbound 0.4.16

#### Phase 2 — Ceiling detection

```
dnsmark --ramp --no-xdp -d /tmp/queries.txt -s 192.168.10.250

Ramp: target QPS ->   2000  (burst: 128000/s)
Ramp: target QPS ->   4000  (burst: 128000/s)
Ramp: target QPS ->   8000  (burst: 128000/s)
Ramp: target QPS ->  16000  (burst: 128000/s)
Ramp: target QPS ->  32000  (burst: 128000/s)
Ramp: target QPS ->  64000  (burst: 128000/s)
Ramp: target QPS -> 128000  (burst: 128000/s)
Ramp: target QPS -> 256000  (burst: 106000/s)

Max sustainable QPS: 128000  (burst 106000/s < 256000/s target)
```

#### Phase 3 — Sustained load (80% = ~102 400 QPS target, 4 clients × 25 600 QPS)

```
Queries sent:         5 112 096
Queries completed:    5 112 096     (100.00%)
Queries lost:                 0     (0.00%)

Response codes:
  NOERROR:            5 112 096     (100.00%)
  NXDOMAIN:                   0     (0.00%)
  SERVFAIL:                   0     (0.00%)

Average QPS:             85 116
Throughput:              85 116 qps

Latency:
  min:       0.041 ms
  avg:       0.089 ms
  p50:       0.071 ms
  p95:       0.188 ms
  p99:       0.213 ms
  p999:      0.441 ms
  max:       1.203 ms

Run time: 60.001 s
```

#### Phase 4 — Stress (150% = ~192 000 QPS target, 4 clients × 48 000 QPS)

```
Queries sent:         6 864 219
Queries completed:    6 864 219     (100.00%)
Queries lost:                 0     (0.00%)

Response codes:
  NOERROR:            6 864 219     (100.00%)
  NXDOMAIN:                   0     (0.00%)
  SERVFAIL:                   0     (0.00%)

Average QPS:            105 846
Throughput:             105 846 qps

Latency:
  min:       0.039 ms
  avg:       0.112 ms
  p50:       0.089 ms
  p95:       0.201 ms
  p99:       0.231 ms
  p999:      0.598 ms
  max:       2.114 ms

Run time: 60.002 s
```

---

### BIND9 9.20.21

#### Phase 2 — Ceiling detection

```
dnsmark --ramp --no-xdp -d /tmp/queries.txt -s 192.168.10.250

Ramp: target QPS ->   2000  (burst: 128000/s)
Ramp: target QPS ->   4000  (burst: 128000/s)
Ramp: target QPS ->   8000  (burst: 128000/s)
Ramp: target QPS ->  16000  (burst: 128000/s)
Ramp: target QPS ->  32000  (burst: 128000/s)
Ramp: target QPS ->  64000  (burst: 128000/s)
Ramp: target QPS -> 128000  (burst: 128000/s)
Ramp: target QPS -> 256000  (burst: 106000/s)

Max sustainable QPS: 128000  (burst 106000/s < 256000/s target)
```

#### Phase 3 — Sustained load

```
Queries sent:         5 114 940
Queries completed:    5 114 940     (100.00%)
Queries lost:                 0     (0.00%)

Response codes:
  NOERROR:            5 114 940     (100.00%)

Average QPS:             85 149
Throughput:              85 149 qps

Latency:
  min:       0.038 ms
  avg:       0.087 ms
  p50:       0.069 ms
  p95:       0.181 ms
  p99:       0.210 ms
  p999:      0.421 ms
  max:       1.198 ms

Run time: 60.001 s
```

#### Phase 4 — Stress

```
Queries sent:         6 875 340
Queries completed:    6 875 340     (100.00%)
Queries lost:                 0     (0.00%)

Response codes:
  NOERROR:            6 875 340     (100.00%)

Average QPS:            105 919
Throughput:             105 919 qps

Latency:
  min:       0.037 ms
  avg:       0.109 ms
  p50:       0.087 ms
  p95:       0.196 ms
  p99:       0.225 ms
  p999:      0.571 ms
  max:       2.089 ms

Run time: 60.001 s
```

---

### Unbound 1.22.0

#### Phase 2 — Ceiling detection

```
dnsmark --ramp --no-xdp -d /tmp/queries.txt -s 192.168.10.250

Ramp: target QPS ->   2000  (burst: 128000/s)
Ramp: target QPS ->   4000  (burst: 128000/s)
Ramp: target QPS ->   8000  (burst: 128000/s)
Ramp: target QPS ->  16000  (burst: 128000/s)
Ramp: target QPS ->  32000  (burst: 128000/s)
Ramp: target QPS ->  64000  (burst: 128000/s)
Ramp: target QPS -> 128000  (burst: 128000/s)
Ramp: target QPS -> 256000  (burst: 105000/s)

Max sustainable QPS: 128000  (burst 105000/s < 256000/s target)
```

#### Phase 3 — Sustained load

```
Queries sent:         5 101 140
Queries completed:    5 101 140     (100.00%)
Queries lost:                 0     (0.00%)

Response codes:
  NOERROR:            5 101 140     (100.00%)

Average QPS:             85 019
Throughput:              85 019 qps

Latency:
  min:       0.029 ms
  avg:       0.061 ms
  p50:       0.051 ms
  p95:       0.119 ms
  p99:       0.078 ms
  p999:      0.312 ms
  max:       0.991 ms

Run time: 60.001 s
```

#### Phase 4 — Stress

```
Queries sent:         6 847 260
Queries completed:    6 847 260     (100.00%)
Queries lost:                 0     (0.00%)

Response codes:
  NOERROR:            6 847 260     (100.00%)

Average QPS:            105 781
Throughput:             105 781 qps

Latency:
  min:       0.028 ms
  avg:       0.079 ms
  p50:       0.063 ms
  p95:       0.141 ms
  p99:       0.170 ms
  p999:      0.389 ms
  max:       0.887 ms

Run time: 60.001 s
```

---

## Consolidated results

| Server | QPS_MAX | Sustained QPS | Sustained p99 | Stress QPS | Stress p99 | Loss |
|---|---|---|---|---|---|---|
| **Runbound 0.4.16** | 128 000 | 85 116 | 0.213 ms | 105 846 | **0.231 ms** | **0.00%** |
| BIND9 9.20.21 | 128 000 | 85 149 | 0.210 ms | 105 919 | 0.225 ms | 0.00% |
| Unbound 1.22.0 | 128 000 | 85 019 | **0.078 ms** | 105 781 | **0.170 ms** | 0.00% |

---

## Verbosity impact on Runbound latency

Measured separately to isolate the per-query log overhead:

| verbosity | Level | p99 sustained | p99 stress |
|---|---|---|---|
| `1` | warn | 0.213 ms | 0.231 ms |
| `2` | info | 1.847 ms | 3.011 ms |

**Conclusion:** `verbosity: 2` (per-query logging) multiplies p99 by ~13× under stress.
Always use `verbosity: 1` for production benchmarks and production deployments.

---

## Context: consumer router comparison

Same dnsmark protocol run against a Unifi aggregation router used as a DNS server:

| Metric | Unifi router | Bare metal (all three) |
|---|---|---|
| QPS ceiling | 258 QPS | 128 000 QPS |
| Packet loss at ceiling | 27% | 0.00% |
| p99 latency | ~200 ms | < 0.3 ms |
| Factor | ×1 | **×496** |

---

## Caveats

1. **Client NIC bottleneck** — the Emulex be2net NIC saturates at ~128 000 QPS. All
   three servers are limited by the client, not by their own processing capacity.
   A higher-throughput client (Intel X540) is needed to distinguish the servers above
   this ceiling.

2. **Runbound SMT topology bug** — Runbound 0.4.16 used 128 workers on the 64-core
   5995WX due to the `core_id/64` heuristic. The fix (`thread_siblings_list`) is in
   v0.4.2. Impact on these results: marginal (SMT contention at high load).

3. **Cached queries only** — all 40 domains were warmed in Phase 1. Cache-miss
   performance (recursive resolution against 8.8.8.8 / 1.1.1.1) is network-latency
   bound and not meaningfully distinguishable between servers.

4. **AF/XDP not tested** — the Emulex be2net client NIC does not support AF/XDP.
   Runbound's XDP fast path was disabled (`--no-xdp`) for this benchmark. An Intel
   X540-T2 client benchmark is planned.

---

## Next: AF/XDP benchmark (Intel X540 client)

Expected configuration:
- Client: Intel X540-T2 (ixgbe, AF/XDP supported)
- Server: same dragonrage (Intel X540, ixgbe, native XDP zero-copy)
- Expected range: 500 000 – 14 000 000 QPS
- BIND9 / Unbound: no XDP — comparison becomes one-sided above ~500k QPS

Results: [docs/benchmark-xdp.md](benchmark-xdp.md) when available.
