# Design philosophy — Runbound vs traditional DNS servers

## The generation gap

BIND9 was first released in 1988. Unbound in 2006. Both are written in C.
This is not a criticism — they are battle-tested, reliable, and widely deployed.
But the threat landscape of 2026 is not the threat landscape of 1988.

Runbound was designed in 2024 with a different set of assumptions.

---

## Memory safety

**BIND9 and Unbound** are written in C. The majority of their CVEs over the past
decade are memory-safety bugs: buffer overflows, use-after-free, null pointer
dereferences, memory leaks under load. These are not bugs caused by bad programmers —
they are structural properties of manual memory management at scale.

Selected BIND9 CVEs (recent):
- CVE-2024-1975: assertion failure → crash via crafted SIG queries
- CVE-2023-3341: stack exhaustion via recursive zone processing
- CVE-2023-2911: denial of service via recursive resolver

These classes of vulnerability **cannot exist in Runbound**. Rust's ownership model
enforces memory safety at compile time. No buffer overflows. No use-after-free.
No null pointer dereferences. This is not a claim — it is a property of the language.

---

## Built-in security surface

Traditional DNS servers were designed to resolve queries. Security was added
incrementally over decades, often as external tooling.

Runbound was designed with security as a first-class feature:

| Feature | Runbound | BIND9 | Unbound |
|---|---|---|---|
| Constant-time API authentication | ✅ | ✗ | ✗ |
| Anti-brute-force sleep on auth failure | ✅ | ✗ | ✗ |
| Per-IP TCP connection cap (DNS + DoT + DoH) | ✅ | ✗ | ✗ |
| Per-IP DNS rate limiting | ✅ | external (RRL module) | ✅ |
| HMAC-signed audit log | ✅ | ✗ | ✗ |
| SSRF protection on feed URLs | ✅ | N/A | N/A |
| HSM support for API key storage | ✅ | ✗ | ✗ |
| REST API with authenticated management | ✅ native | rndc (separate daemon) | ✗ |
| Public pentest cycle with published reports | ✅ | ✗ | ✗ |

---

## The performance trade-off that isn't

A common assumption: security features degrade performance.

The security surface (ACLs, rate limiting, the relay HMAC, the hardened parser) is
**active in every benchmark** — none of it is disabled to produce the headline numbers.
With it on, the kernel slow path still serves ~3.71 M qps at ~19 % CPU on the X710 — about
2× BIND (1.84 M) and unbound (2.09 M) on the same rig — at a **p99 of 0.371 ms vs ~7–9 ms**
for those two; the AF_XDP fast path serves ~10 M+/link at sub-millisecond p99 (0.245 ms).
The only verbosity cost we can isolate is logging: production `verbosity: 1` adds ~0.01 ms
p50 over benchmark `verbosity: 0` (`configuration.md`). In other words the security features
do not show up as a measurable penalty on the hot path — they live inside an envelope that
is already several times faster than the reference resolvers. (Full numbers and method:
`docs/benchmark/`.)

---

## XDP: a different performance category

BIND9 and Unbound process DNS over the kernel UDP stack. This involves:
- A syscall per packet (recvmmsg/sendmmsg)
- Kernel → userspace memory copy per packet
- Kernel network stack processing overhead

Runbound implements AF_XDP zero-copy receive and transmit. When running on
supported hardware (Intel ixgbe: X520, X540, X550; Mellanox mlx5), packets are
delivered directly from the NIC ring buffer to Runbound's UMEM — bypassing the
kernel UDP stack entirely.

Benchmark results on be2net (Emulex, no AF_XDP): ceiling 128,000 QPS.
Expected results on Intel X540 (ixgbe, native AF_XDP): 400,000–600,000+ QPS (theoretical estimate — not yet measured; benchmark planned).

BIND9 and Unbound have no AF_XDP implementation. This performance tier is
exclusive to Runbound.

---

## Commercial use

Runbound is licensed under AGPL v3. Organizations that cannot comply with the
AGPL (proprietary products, SaaS deployments without source disclosure) can
obtain a commercial license.

Contact: [contact@runasm.com]

---

## Summary

Runbound is not a replacement for BIND9 or Unbound in every context.
If you need a battle-tested resolver with 30 years of production deployment
history, use Unbound.

If you need:
- Memory-safe implementation (no CVE class "buffer overflow in DNS parser")
- Built-in authenticated REST management API
- AF_XDP zero-copy for extreme throughput
- Security audit trail with tamper detection
- Per-IP protection without external tooling

Then Runbound was built for you.
