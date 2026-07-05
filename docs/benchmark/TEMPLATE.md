# Runbound Benchmark — vX.Y.Z — <host> — <date>

> Follows [README.md](README.md). Measured data only. Where a value is missing or
> uncertain, write exactly **"I cannot confirm this."**

## 1. Executive Summary

<One paragraph, factual: sustained real maximum QPS, p95/p99 latency, error rate,
and at what receiver CPU/RAM. No adjectives.>

## 2. Objective

<Why this benchmark was run; what question it answers.>

## 3. Methodology & Architecture

- **Receiver (Runbound):** CPU model + core count, RAM, NIC model, kernel, Runbound
  version, `xdp:` mode, relevant config (rate-limit, queues, governor).
- **Generator (dnsmark):** host, dnsmark version, exact command.
- **Link:** NIC model, speed, direct vs switched, flow-control state, RSS config.
- **Dataset:** corpus file (`docs/benchmark/corpus/top-10000-domains.txt`), 10 000 names,
  random read.
- **Procedure:** warmup duration; ramp steps; measurement window; saturation criterion.

## 4. Raw Results

| Metric | Value | Source |
|--------|-------|--------|
| Max sustained real QPS | | receiver NIC counters (`ethtool -S`) |
| Latency p50 / p95 / p99 | | tcpdump (wire) / dnsmark |
| Success rate / error rate | | dnsmark rcode breakdown |
| Receiver CPU % | | |
| Receiver RAM | | |
| NIC drops (`rx_missed_errors`) | | `ethtool -S` |

## 5. Interpretation

<Analysis strictly correlated to the numbers above. No claim without a number behind
it. Mark any unproven statement "I cannot confirm this.">

## 6. Appendix — exact commands & configuration

```bash
# governor pin, flow control off, RSS hash, ARP, ss :53 ownership check,
# dnsmark warmup + ramp command, and the ethtool -S reads used for the numbers
```
