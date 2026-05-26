# Performance

Benchmark reports are in [`docs/benchmark/`](benchmark/).

| Date | Version | Report | Key result |
|------|---------|--------|------------|
| 2026-05-26 | v0.9.45 | [v0.9.45.md](benchmark/v0.9.45.md) | Runbound +21–37% QPS vs BIND9/Unbound (userspace) |

## XDP benchmark

Pending — requires Intel X540-capable client. Expected: 500k–14M QPS vs ~0 for BIND9/Unbound (no XDP support).

## Reproduce

See [docs/config-examples/benchmark.conf](config-examples/benchmark.conf) and [dnsmark](https://github.com/redlemonbe/dnsmark).
