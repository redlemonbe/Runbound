# 09 — Design decisions and rationale

> **Status: current (v0.20.0)** — condensed decision table.

| Decision | Why | Trade-off |
|----------|-----|-----------|
| **Rust** | Memory safety on a path full of raw pointers, `unsafe`, and hand asm; ownership used for resource cleanup (XDP detach-on-drop) | `unsafe` blocks still need careful review; long compile times |
| **aya (pure-Rust eBPF)** | No libbpf/clang at runtime; the `.o` is embedded in the binary | Reimplements some libbpf conveniences |
| **hickory as fallback, not hot path** | A correct, complete DNS implementation for the hard cases; but its per-query `tokio::spawn` + generic codec was 1.78× Unbound's instructions | Two code paths to keep consistent (guarded by the round-trip test) |
| **XDP + AF_XDP** | Bypass the kernel stack for the common case; zero copy, zero syscall on the hot path | Driver/NIC dependent; ZC not always available; debugging is harder |
| **FNV-1a in eBPF, CRC32c in user space** | CRC32c's unrolled bit loop explodes the BPF verifier; FNV-1a is O(N) states | Two different hashes (used for different maps, never compared) |
| **Hand-written SIMD/asm kernels** | Lowercase/compare/hash dominate the hot path; each is a branchless byte kernel | Must be proven equal to a scalar reference (enforced by tests) |
| **Full config regeneration (atomic)** | One source of truth; survives round-trips; preserves unknown directives | Some changes need a restart (e.g. split-horizon resolver table) |
| **Separate API Tokio runtime** | DNS load (DoT rebuild storms) must not freeze management | Slightly more memory; two schedulers |
| **XDP DRV → SKB fallback** | DRV fails on virtio-net above the single-buffer MTU | SKB is slower than DRV |

## To expand
- Per-decision links to the code and the issues that drove them.
