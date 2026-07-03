# 09 — Design decisions and rationale

> **Status: current (v0.23.13, last full sync pass: 2026-07-03)** — condensed decision table.

| Decision | Why | Trade-off |
|----------|-----|-----------|
| **Rust** | Memory safety on a path full of raw pointers, `unsafe`, and hand asm; ownership used for resource cleanup (XDP detach-on-drop) | `unsafe` blocks still need careful review; long compile times |
| **aya (pure-Rust eBPF)** | No libbpf/clang at runtime; the `.o` is embedded in the binary | Reimplements some libbpf conveniences |
| **De-hickory: wire-native default handler (v0.22)** | The hickory `ServerFuture` per-query `tokio::spawn` + generic codec was 1.78× Unbound's instructions; the in-house wire codec (`src/dns/wire/`, `serve_wire`) serves forward/full-recursion/local/AXFR/TSIG/DDNS/DNSSEC-signing on every path, and there is no hickory request handler left anywhere in the runtime | A full DNS message/codec to own and keep RFC-correct (guarded by differential oracles vs hickory + `delv`); `hickory-proto` remains only as a `[dev-dependencies]` entry for those oracle tests |
| **Sovereign recursion, always compiled in** | Full iterative recursion (`src/dns/recursor_wire.rs`) and DNSSEC validation (`src/dns/dnssec_*.rs`) are entirely in-house and always compiled in (no Cargo feature gates them — there is no `recursor` feature anymore) — but OFF by runtime default: `resolution: forward` and `dnssec-validation: no` are the defaults; full-recursion and DNSSEC validation are opt-in via config (`resolution: full-recursion`, `dnssec-validation: yes`), not a build flag | The in-house recursor + validator must be kept RFC-correct without falling back to a library implementation |
| **XDP + AF_XDP** | Bypass the kernel stack for the common case; zero copy, zero syscall on the hot path | Driver/NIC dependent; ZC not always available; debugging is harder |
| **FNV-1a in eBPF, hardware CRC32c in user space (FNV-1a fallback)** | CRC32c's unrolled bit loop explodes the BPF verifier; FNV-1a is O(N) states. User space uses hardware CRC32c (SSE4.2 / ARM CRC) only when detected at startup (`src/dns/hasher.rs::init()`); without it, user space also falls back to software FNV-1a | Two (or three) different hashes (used for different maps, never compared); user-space hash choice depends on the CPU running the binary |
| **Hand-written SIMD/asm kernels** | Lowercase/compare/hash dominate the hot path; each is a branchless byte kernel | Must be proven equal to a scalar reference (enforced by tests) |
| **Full config regeneration (atomic)** | One source of truth; survives round-trips; preserves unknown directives | Some changes need a restart (e.g. split-horizon resolver table) |
| **Separate API Tokio runtime** | DNS load (DoT rebuild storms) must not freeze management | Slightly more memory; two schedulers |
| **XDP DRV → SKB fallback** | DRV fails on virtio-net above the single-buffer MTU | SKB is slower than DRV |

## To expand
- Per-decision links to the code and the issues that drove them.
