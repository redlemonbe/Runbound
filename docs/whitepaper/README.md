# Runbound — Technical Whitepaper

This whitepaper documents the internal design of **Runbound**, an authoritative/recursive
DNS server written in Rust, intended as a drop-in replacement for Unbound, with an
eBPF/XDP + AF_XDP fast path, a REST API, an embedded web UI, and an encrypted
master→slave relay.

It is written for **developers and reviewers** who want to understand not only *what*
Runbound does but *how* and *why* — down to the hand-written assembly on the hot path
and the eBPF verifier constraints that shaped the in-kernel code.

> **Status & honesty.** This document describes the code as it exists in the repository
> at **0.9.2** (last full sync pass: 2026-07-07 — QNAME minimisation #231, compact denial
> #232, IPv6 slow-path binding #233, a live-editable per-source DNS rate limit, auto-ban
> hardening across both datapaths, and a full `docs/api.md` resync). Where a claim is not backed by a
> measurement or by the code, it is marked **"I cannot confirm this."** No marketing
> language is used: the words *production-ready, blazing, world-first, military-grade,
> rock-solid, unbreakable, guaranteed* are banned, in line with the project's
> security-audit conventions.

---

## How to read this

Each chapter is a standalone Markdown file. Line references point at real source files
(`path:line`) so you can read the code alongside the prose.

| # | Chapter | What it covers |
|---|---------|----------------|
| 01 | [Architecture](01-architecture.md) | The dual-path model (XDP fast path / kernel slow path), the wire-native `serve_wire` handler, process model, packet life-cycle, the shared wire answer routine |
| 02 | [The XDP fast path](02-fast-path-xdp.md) | eBPF program, AF_XDP zero-copy, XSKMAP/CPUMAP routing, 802.1Q tagged fabrics, per-view split-horizon snapshots, the zero-alloc wire response builder (positive + negative answers) |
| 03 | [SIMD & hand-written assembly](03-simd-and-asm.md) | CRC32c domain hashing, AVX2/SSE2 label lowercasing & comparison, the eBPF FNV-vs-CRC verifier story |
| 04 | [The slow path](04-slow-path.md) | the `xdp:no` kernel fast loop (SO_REUSEPORT per core, by-CPU cBPF + RPS, batched recvmmsg/sendmmsg, shared rate-limit/ban gate, shared wire responder); startup NIC auto-tune (NUMA-local queues/IRQs, RPS, coalescing); the wire-native `serve_wire` handler (forward, DoT/DoH, AXFR/IXFR, TSIG, DDNS, DNSSEC signing, serve-stale); the in-house sovereign full-recursion resolver, always compiled in but off by runtime default (a config toggle, not a Cargo feature) |
| 05 | [Caching](05-cache.md) | Cache sizing under cgroup v2, stale serving, negative cache |
| 06 | [Control plane](06-control-plane.md) | REST API (axum), config-writer (atomic full-regen), web UI, HMAC relay, SSE, split-horizon, Unix socket |
| 07 | [Security](07-security.md) | rate-limit + bans on both datapaths (one shared gate), DNSSEC AD, constant-time auth, least-privilege systemd, HMAC relay, reproducible build + signatures, SBOM, audit discipline |
| 08 | [Performance](08-performance.md) | Benchmark methodology, measured ceilings, lessons learned |
| 09 | [Design decisions](09-design-decisions.md) | Rust, aya, wire-native codec, XDP DRV vs SKB — the trade-offs and the why |
| 10 | [Appendices](10-appendices.md) | Config reference, API reference, glossary |

---

## One-paragraph abstract

Runbound answers the most common DNS queries (A/AAAA from local zones, and blacklist
NXDOMAIN) **without ever entering the kernel network stack**: an XDP eBPF program
redirects UDP/53 frames into AF_XDP sockets, and user-space worker threads parse the
query and forge the reply directly inside the NIC ring buffer (zero copy, zero syscall
on the hot path). Everything the fast path cannot answer — forwarding/recursion, TCP, DoT/DoH/DoQ,
DNSSEC, anything non-trivial — falls through to the kernel slow path. In `xdp: no` that slow path is itself a tight
kernel-UDP loop that serves cache hits through the *same* hand-written wire responder
(behind the same per-source rate-limit/ban gate), routing only genuine misses to the
in-house wire-native handler (`serve_wire`, `src/dns/server.rs`, which calls into the wire
codec library at `src/dns/wire/`). The request path is wire-native throughout:
forwarding, local zones, AXFR/IXFR, TSIG, DDNS and DNSSEC signing are all served
wire-native, and the sovereign full-recursion resolver
(`src/dns/recursor_wire.rs`) and DNSSEC validation (`src/dns/dnssec_*.rs`) are entirely
in-house and always compiled in (no Cargo feature gates them) — but OFF by runtime
default: `resolution: forward` and `dnssec-validation: no` are the defaults; full-recursion
and DNSSEC validation are opt-in via config (`resolution: full-recursion`,
`dnssec-validation: yes`), not a build flag. There is no `recursor` Cargo feature.
`hickory-proto` is a `[dev-dependencies]` entry for the differential oracle tests. All paths
share a single normalisation and hashing contract so that a name resolves identically
whichever path serves it. The control plane (REST API, web UI, relay) is isolated on a
separate Tokio runtime so that DNS load cannot starve management, and vice-versa.
