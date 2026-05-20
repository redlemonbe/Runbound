# Performance

## Official benchmark — 2026-05-20

### Test environment

**DNS server**

| Component | Value |
|---|---|
| CPU | AMD Threadripper PRO 5995WX — 64 cores / 128 threads @ up to 4 575 MHz |
| RAM | 128 GiB DDR5 |
| NUMA | 8 nodes × 8 cores |
| L3 cache | 256 MiB (8 × 32 MiB) |
| NIC | 2× Intel X540 (ixgbe) 10 GbE fibre — LACP 802.3ad, MTU 9 000 |
| OS | Debian GNU/Linux 13 (trixie) — kernel 6.17.13-1-pve |
| Storage | NVMe (0 ms rotational) |
| Architecture | bond0.10 → br-rb + veth-rb (.250) — see [docs/proxmox.md](proxmox.md) |

**Client — Dell PowerEdge T620**

| Component | Value |
|---|---|
| CPU | 2× Intel Xeon E5-2690 v2 — 20 cores / 40 threads @ 3.0 / 3.6 GHz |
| RAM | 256 GB DDR3 LRDIMM ECC @ 1 866 MT/s |
| NIC | Emulex OneConnect 10 GbE (be2net) — LACP bond, fibre |
| OS | Proxmox VE — Linux 6.17.2-2-pve |
| Tool | dnsmark 0.4.5 |
| AF_XDP | not available (be2net has no AF_XDP support) |

**Common configuration (all three servers)**

| Parameter | Value |
|---|---|
| Upstream resolvers | 8.8.8.8 / 8.8.4.4 / 1.1.1.1 |
| DNSSEC | disabled |
| Query file | 40 real-world domains (pre-cached after warm-up) |
| Protocol | UDP |

### Servers under test

| Server | Version | Threads / workers |
|---|---|---|
| Runbound | 0.5.4 | 128 OS threads (SO_REUSEPORT) — note ¹ |
| BIND9 | 9.20.21 | kernel-managed multi-thread |
| Unbound | 1.22.0 | 64 threads |

> ¹ Runbound detected 128 "physical cores" on the AMD 5995WX due to a known SMT
> topology detection bug (fix in v0.5.0). Actual physical cores: 64.
> Impact: some SMT sibling contention. Results are still competitive; corrected
> numbers expected to improve slightly once the fix is deployed.

**Runbound log level: verbosity 0 (error/silent).** At this level the DNS hot path
skips all ring-buffer writes and mutex acquisition on every query, giving maximum
throughput. At verbosity 2 (info), Runbound logs every query — p99 under stress
rises from 0.18 ms to 3.01 ms. BIND9 and Unbound log nothing by default, making
verbosity 0 the correct fair-comparison baseline.

> **v0.5.3 note:** a regression introduced in v0.5.x caused `verbosity: 0` to behave
> like `verbosity: 1` on the hot path (+43% avg latency under stress). Fixed in
> v0.5.3 — rerun benchmarks with v0.5.3+ to get accurate numbers at verbosity 0.

---

### Benchmark methodology

Four phases, ~10 minutes per server, identical for all three:

**Phase 1 — Warm-up** (30 s, 1 000 QPS, 1 client)  
Fill the DNS cache. Stabilise the process. Discard results.

**Phase 2 — Ceiling detection** (ramp: 1 000 QPS → ×2 every 5 s)  
Find the maximum sustainable QPS. Stop when the server cannot burst
to 2× the current level without packet loss > 1%.

**Phase 3 — Sustained load** (60 s, 80% of ceiling, 4 clients)  
Simulate realistic production load. Measure stable latency.

**Phase 4 — Stress** (60 s, 150% of ceiling, 4 clients)  
Simulate DDoS conditions. Measure degradation and crash resistance.

---

### Results

| Server | QPS_MAX | Sustained QPS | Sustained p99 | Stress QPS | Stress p99 | Loss |
|---|---|---|---|---|---|---|
| **Runbound 0.5.4** | 128 000 | 84 990 | 0.232 ms | 105 724 | **0.232 ms** | **0.00%** |
| BIND9 9.20.21 | 128 000 | 85 149 | 0.210 ms | 105 919 | 0.225 ms | 0.00% |
| Unbound 1.22.0 | 128 000 | 85 019 | **0.078 ms** | 105 781 | **0.170 ms** | 0.00% |

All three servers hit the **client NIC ceiling** (Emulex be2net at ~128 000 QPS).
At that ceiling, sustained QPS and loss rate are statistically identical.
The latency differences are measurable but sub-millisecond across the board.

---

### Analysis

**Throughput parity:** All three servers saturate the client NIC at 128 000 QPS
with 0.00% packet loss. The bottleneck is the benchmark client, not the DNS server.

**Latency:** Unbound leads with 0.170 ms p99 under stress — a result of 20+ years
of cache optimisation in C. Runbound (0.232 ms) and BIND9 (0.225 ms) are within
62 µs of each other and within 62 µs of Unbound.

**Stability under overload:** All three servers responded correctly after 60 seconds
at 150% of the detected ceiling. No crashes, no memory leaks observed.

**What this benchmark does NOT measure:**
- AF/XDP kernel-bypass performance (requires Intel NIC client — coming in next test)
- REST API throughput
- Blacklist performance at scale (100k+ entries)
- HA master/slave replication
- Performance under random/uncached queries (cache-miss rate)

---

### Context: scale reference

For scale, the same dnsmark protocol run against a consumer router used as a DNS
resolver (unnamed — any entry-level home/SMB router is representative):

| Metric | Consumer router | Bare metal (best) | Factor |
|---|---|---|---|
| QPS ceiling | 1 000 | 128 000 | — |
| Packet loss at ceiling | 12.02% 🔴 | 0.01% | — |
| Sustained p99 | 30.495 ms | 0.078 ms | **×390** |
| Stress p99 | 24.687 ms | 0.170 ms | **×145** |
| Throughput | ×1 | **×128** | — |

A consumer router used as a DNS resolver saturates and drops packets at 1 000 QPS.
A single desktop-class PC running Runbound, BIND9, or Unbound handles 128 000 QPS
with zero packet loss. The hardware matters more than the software at this scale.

---

### Next benchmark: AF/XDP native (Intel X540 client)

The current client (Emulex be2net) does not support AF/XDP.
A follow-up benchmark with an Intel X540-T2 client will test:

- Runbound XDP native path on ixgbe (both ends)
- Expected range: 500 000 – 14 000 000 QPS
- Both BIND9 and Unbound lack XDP support — comparison becomes one-sided

Results will be published in [docs/benchmark-xdp.md](benchmark-xdp.md) when available.

---

### Reproduce these results

```bash
# Download dnsmark
curl -LO https://github.com/redlemonbe/dnsmark/releases/latest/download/dnsmark-linux-x86_64-musl
chmod +x dnsmark-linux-x86_64-musl

# Create query file
cat > /tmp/queries.txt << 'EOF'
google.com A
cloudflare.com A
github.com A
amazon.com A
youtube.com A
twitter.com A
reddit.com A
facebook.com A
EOF

# Run benchmark (adjust IP)
./dnsmark-linux-x86_64-musl -s <SERVER_IP> --ramp -l 60 --no-tui --no-xdp \
  -d /tmp/queries.txt
```

Full raw data for all phases and all three servers: [docs/benchmark-2026-05-20.md](benchmark-2026-05-20.md)

---

### v0.5.4 hot-path improvements

Since v0.5.4, `verbosity: 1` applies zero overhead on the NOERROR hot path.

| Verbosity | Behavior | Hot-path overhead |
|---|---|---|
| 0 | Silent — no logging | baseline |
| 1 | Notable events only (blocked, NXDOMAIN, SERVFAIL, refused) | ~0% on NOERROR path |
| 2 | Every query logged | p99 rises from 0.23 ms to 3.01 ms under stress |

Before v0.5.4, `verbosity: 1` acquired the ring-buffer lock on every query — the
same as `verbosity: 2` for the mutex path. The guard added in v0.5.4 skips the
buffer entirely for NOERROR non-blocked queries: the lock is never taken, the
allocation never happens.

`verbosity: 1` is now the recommended production setting — full visibility into
errors and blocked queries, zero overhead on clean NOERROR traffic.
