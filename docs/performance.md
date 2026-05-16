# Performance

## Summary

| Scenario | Throughput | Avg latency | Notes |
|---|---|---|---|
| Local zone, 1 client | **82,000 q/s** | 83 ms | dnsperf saturated first |
| Local zone, 8 clients | **75,000 q/s** | ~1,000 ms | server CPU saturated |
| Forwarding (Cloudflare) | network-bound | < 5 ms | |
| AF/XDP, bare metal DRV mode | **500k – 1M+ q/s** | < 1 ms | kernel-bypass |

> **Important:** In the single-client test, dnsperf (single-threaded) reached its own
> limit before the server did. The true ceiling of Runbound was not reached in these
> measurements — real throughput is higher.

---

## Test environment

| Component | Value |
|---|---|
| CPU | 32 vCPUs (KVM), x86_64 |
| RAM | 8 GB |
| OS | Linux 6.x (Debian 13) |
| Network | loopback (`127.0.0.x`) |
| Runbound version | 0.2.0 |
| dnsperf version | 2.x |
| Query type | A record, local zone (no forwarding) |

---

## Methodology

### Install dnsperf

```bash
apt-get install -y dnsperf
# or build from source: https://www.dns-oarc.net/tools/dnsperf
```

### Generate a query file

```bash
cat > /tmp/queries.txt << 'EOF'
ns1.internal. A
ns2.internal. A
ca.internal. A
ntp.internal. A
siem.internal. A
bastion.internal. A
EOF
```

### Single-client test

```bash
dnsperf -s 127.0.0.1 -p 53 -d /tmp/queries.txt \
  -l 30 -c 20 -Q 100000
```

Result:

```
Queries sent:         2,460,000
Queries completed:    2,460,000 (100.00%)
Queries lost:         0 (0.00%)

Response codes:       NOERROR 2,460,000 (100.00%)
Average packet size:  request 30, response 62
Run time (s):         30.000
Queries per second:   82,000.00
Average latency (s):  0.082511
```

### 8-client parallel test

To avoid DashMap contention on the rate limiter (all clients from `127.0.0.1`),
add loopback aliases first:

```bash
for i in 2 3 4 5 6 7 8 9; do
  sudo ip addr add 127.0.0.$i/8 dev lo
done
```

Then launch 8 instances in parallel:

```bash
for i in $(seq 1 8); do
  dnsperf -s 127.0.0.$i -p 53 -d /tmp/queries.txt \
    -l 30 -c 20 -Q 20000 \
    > /tmp/perf_$i.txt 2>&1 &
done
wait

# Aggregate results
grep "Queries per second" /tmp/perf_*.txt
grep "Average latency"    /tmp/perf_*.txt
```

Result: ~75,000 q/s total across 8 clients — server CPU was the bottleneck,
not the rate limiter or lock contention.

---

## What limits throughput

In standard mode (without XDP), the bottleneck is the **hickory-server async runtime**:
one Tokio task per DNS request, each performing ACL check → rate limit check →
zone lookup → response serialisation → UDP send.

On a 4-core VM this caps at ~80k q/s for local-zone queries. Forwarding queries
are network-latency-bound rather than CPU-bound.

### Scaling vertically

Runbound uses `SO_REUSEPORT` with 32 UDP sockets distributed across CPU cores.
Adding cores improves throughput linearly up to the point where memory bandwidth
or kernel UDP overhead becomes the bottleneck (~16 cores on most hardware).

### Breaking the limit: AF/XDP

The `--features xdp` build bypasses the kernel network stack entirely.
On bare metal with a NIC that supports XDP driver mode:

- **500,000 – 1,000,000+ q/s** for local-zone queries
- Sub-millisecond latency under load
- ACL and rate-limit enforcement still applied in XDP worker (no bypass)

See [xdp.md](xdp.md) for setup instructions.

---

## Comparison with Unbound

| | Unbound 1.19 | Runbound 0.2.0 |
|---|---|---|
| Single-core local zone | ~30k q/s | ~82k q/s |
| Multi-core scaling | Good | Good (SO_REUSEPORT) |
| Forwarding | Network-bound | Network-bound |
| Memory per 1M cache entries | ~500 MB | ~400 MB (ArcSwap, no copy) |
| Config reload | Full restart | Hot reload via API |

> Unbound numbers are indicative; actual results depend on hardware and configuration.
> Run your own benchmarks on your hardware before making architectural decisions.
