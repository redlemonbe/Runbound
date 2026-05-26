# Performance

Benchmark reports are stored in [`docs/bench-runs/`](bench-runs/).

| Run | Version | Author | Hardware | Report |
|-----|---------|--------|----------|--------|
| 2026-05-26 | v0.9.45 | Agent (Claude Sonnet 4.6) | Xeon E5-2690 v2 / Threadripper PRO 5995WX | [v0.9.45_userspace.md](bench-runs/agent/v0.9.45_userspace.md) |
| 2026-05-26 | v0.9.45 | Agent (Claude Sonnet 4.6) | Threadripper PRO 5995WX (server) / Xeon E5-2690 v2 (client) | [v0.9.45_threadripper_server.md](bench-runs/agent/v0.9.45_threadripper_server.md) |

## Methodology

All benchmark runs follow the dnsmark protocol (see [`docs/bench-runs/`](bench-runs/) for details per run):

- **Phase A** — ceiling detection (ramp 1k → max QPS, UDP)
- **Phase B** — sustained load (80% ceiling, 60s, multi-client)
- **Phase C** — stress (150% ceiling, 60s)

Runs labeled `agent/` were produced by an AI agent on the infrastructure described in each report. Runs labeled `maintainer/` were produced by the project maintainer. Discrepancies > 5% between the two are logged in [`discrepancies.md`](bench-runs/discrepancies.md).

## XDP benchmark

The v0.9.45 report covers userspace only (XDP disabled). An XDP-enabled comparative benchmark will be added once an Intel X540-capable client is available. Expected range with XDP: 500k–14M QPS (unverified — pending hardware).

## Reproduce

```bash
# dnsmark (companion benchmark tool)
curl -LO https://github.com/redlemonbe/dnsmark/releases/latest/download/dnsmark-linux-x86_64-musl
chmod +x dnsmark-linux-x86_64-musl

# Example: ceiling detection against a running Runbound instance
./dnsmark-linux-x86_64-musl -s <SERVER_IP>:53 --ramp -l 60 --no-xdp -d /tmp/queries.txt
```

See [`docs/config-examples/benchmark.conf`](config-examples/benchmark.conf) for the recommended Runbound configuration during benchmark runs.
