# Runbound — Technical Whitepaper

This whitepaper documents the internal design of **Runbound**, an authoritative/recursive
DNS server written in Rust, intended as a drop-in replacement for Unbound, with an
eBPF/XDP + AF_XDP fast path, a REST API, an embedded web UI, and an encrypted
master→slave relay.

It is written for **developers and reviewers** who want to understand not only *what*
Runbound does but *how* and *why* — down to the hand-written assembly on the hot path
and the eBPF verifier constraints that shaped the in-kernel code.

> **Status & honesty.** This document describes the code as it exists in the repository
> at the stated version. Where a claim is not backed by a measurement or by the code,
> it is marked **"I cannot confirm this."** No marketing language is used: the words
> *production-ready, blazing, world-first, military-grade, rock-solid, unbreakable,
> guaranteed* are banned, in line with the project's security-audit conventions.

---

## How to read this

Each chapter is a standalone Markdown file. Line references point at real source files
(`path:line`) so you can read the code alongside the prose.

| # | Chapter | What it covers |
|---|---------|----------------|
| 01 | [Architecture](01-architecture.md) | The dual-path model (XDP fast path / hickory slow path), process model, packet life-cycle |
| 02 | [The XDP fast path](02-fast-path-xdp.md) | eBPF program, AF_XDP zero-copy, XSKMAP/CPUMAP routing, the zero-alloc wire response builder |
| 03 | [SIMD & hand-written assembly](03-simd-and-asm.md) | CRC32c domain hashing, AVX2/SSE2 label lowercasing & comparison, the eBPF FNV-vs-CRC verifier story |
| 04 | [The slow path](04-slow-path.md) | hickory-server, recursion, DoT/DoH, DNSSEC, serve-stale, negative caching |
| 05 | [Caching](05-cache.md) | Cache sizing under cgroup v2, stale serving, negative cache |
| 06 | [Control plane](06-control-plane.md) | REST API (axum), config-writer (atomic full-regen), web UI, HMAC relay, SSE, split-horizon, Unix socket |
| 07 | [Security](07-security.md) | Threat model, transport crypto, firewall, reproducible build + signatures, SBOM |
| 08 | [Performance](08-performance.md) | Benchmark methodology, measured ceilings, lessons learned |
| 09 | [Design decisions](09-design-decisions.md) | Rust, aya, hickory, XDP DRV vs SKB — the trade-offs and the why |
| 10 | [Appendices](10-appendices.md) | Config reference, API reference, glossary |

---

## One-paragraph abstract

Runbound answers the most common DNS queries (A/AAAA from local zones, and blacklist
NXDOMAIN) **without ever entering the kernel network stack**: an XDP eBPF program
redirects UDP/53 frames into AF_XDP sockets, and user-space worker threads parse the
query and forge the reply directly inside the NIC ring buffer (zero copy, zero syscall
on the hot path). Everything the fast path cannot answer — recursion, TCP, DoT/DoH/DoQ,
DNSSEC validation, anything non-trivial — falls through to a full
[hickory-server](https://github.com/hickory-dns/hickory-dns) slow path. The two paths
share a single normalisation and hashing contract so that a name resolves identically
whichever path serves it. The control plane (REST API, web UI, relay) is isolated on a
separate Tokio runtime so that DNS load cannot starve management, and vice-versa.
