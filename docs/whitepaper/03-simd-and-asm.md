# 03 — SIMD & hand-written assembly

This chapter documents the hand-optimised code on the DNS hot path: domain-name
hashing, label lowercasing, byte comparison, and the zero-scan, plus the eBPF
equivalents and the verifier constraints that forced different choices in-kernel.

Every code reference below points at a real source line. The functions are exercised
by unit tests that assert the optimised path produces **bit-identical** results to a
scalar/intrinsic reference (see the `tests` modules in each file).

---

## 3.1 Why hand-written assembly at all

The DNS hot path does three things to every query name, millions of times per second:

1. **Lowercase** the labels — DNS names are ASCII case-insensitive (RFC 1034), so
   `Example.COM` and `example.com` must be treated as one key.
2. **Hash** the normalised wire name into a 64-bit cache/zone key.
3. **Compare** a candidate name against a stored one on a hash hit (to reject collisions).

All three are pure byte-stream kernels with no branches in the common case — the exact
shape where SIMD and a tight dependency chain win. Runbound implements each with a
runtime-dispatched SIMD/ASM kernel and a scalar fallback, selected once at startup based
on detected CPU features (`crate::cpu::simd_level()` and `hasher::init()`).

The design rule throughout: **the optimised kernel must be provably equal to a simple
reference.** This is enforced by tests, not by inspection — e.g. `asm_matches_intrinsic`
compares the raw-`asm!` CRC against the intrinsic CRC for every input length 0..=80
(`src/dns/hasher.rs:330`).

---

## 3.2 Domain hashing — CRC32c via raw `asm!`

File: `src/dns/hasher.rs`.

### Backend selection

`hasher::init()` probes the CPU once and latches a global flag (`src/dns/hasher.rs:17`):

- **x86_64** with `sse4.2` → hardware CRC32c.
- **aarch64** with `crc` → ARM CRC32c.
- otherwise → **FNV-1a 64-bit** software fallback.

The chosen backend is logged at startup, so an operator can see which path is live.

### The intrinsic version (reference)

`crc32c_sse42` (`src/dns/hasher.rs:40`) uses `align_to::<u64>()` to split the byte slice
into an unaligned prefix, a `u64`-aligned middle processed with `_mm_crc32_u64`, and a
trailing suffix. Correct, but `align_to` has overhead that dominates for the **short**
inputs DNS names actually are (8–64 bytes).

### The `asm!` version (hot path)

`crc32c_sse42_asm` (`src/dns/hasher.rs:70`) drops `align_to` entirely and issues the
`crc32` instruction directly over **unaligned** reads, in three stages — 8 bytes, then
4, then the byte tail:

```rust
while remaining >= 8 {
    let word = ptr.cast::<u64>().read_unaligned();
    let mut crc64 = crc as u64;
    core::arch::asm!(
        "crc32 {acc}, {word}",
        acc  = inout(reg) crc64,
        word = in(reg)    word,
        options(nostack, nomem, pure),
    );
    crc = crc64 as u32;
    ptr = ptr.add(8);
    remaining -= 8;
}
```

`options(pure, nomem, nostack)` tells the compiler the asm has no side effects and reads
no memory through the asm itself (the load is the separate `read_unaligned`), so it is
free to schedule the instruction and reuse the result. The header comment documents the
micro-architecture reality: `crc32` has **3-cycle latency, 1/cycle throughput**, so for
short names the sequential dependency chain — not throughput — is the limiter. A
3-stream parallel CRC (folding three independent accumulators) is noted as a TODO; it is
**not** implemented, so I cannot claim that speedup today.

### 32-bit → 64-bit spread

CRC32c yields 32 bits. Used directly as a hash-table key the high 32 bits would be zero
and the low bits would cluster. `finish()` (`src/dns/hasher.rs:184`) spreads it to 64
bits with a Fibonacci multiply:

```rust
let c = self.crc as u64;
c ^ c.wrapping_mul(0x9e37_79b9_7f4a_7c15)
```

### IdentityHasher — not re-hashing a good hash

`WireRecordIndex` keys are already high-entropy 64-bit values from `hash_wire_qname`.
Feeding them through `HashMap`'s default hasher would waste cycles re-mixing an
already-good key. `IdentityHasherBuilder` (`src/dns/hasher.rs:534`) passes a `u64`
straight through (`write_u64` stores, `finish` returns it). The safety note is explicit:
this is only valid because the keys have uniform 64-bit entropy.

### eBPF cannot use this

The in-kernel program uses FNV-1a, not CRC32c — see §3.6. The two hashes are
**different** and are used for different maps (kernel-side blacklist/affinity vs
user-side zone/cache index); they are never compared to each other.

---

## 3.3 Label lowercasing — AVX2 / SSE2

File: `src/dns/simd.rs`, `copy_lowercase_label` (`src/dns/simd.rs:22`).

DNS labels are lowercased 16 bytes/iter (SSE2, the Xeon E5 v2 baseline) or 32 bytes/iter
(AVX2, Haswell / Xeon E5 v3+), dispatched at runtime. The interesting part is the
**branchless uppercase detection**, documented at `src/dns/simd.rs:10`.

SSE/AVX integer compares (`pcmpgtb`) are **signed**. To test `b >= 'A' (0x41)` and
`b <= 'Z' (0x5A)` without an unsigned compare, every byte is first biased into the signed
domain by XOR `0x80`:

```
biased  = byte XOR 0x80
lo_pass = biased > 0xC0 (signed)   → byte >= 'A'
hi_pass = 0xDB > biased (signed)   → byte <= 'Z'
mask    = lo_pass AND hi_pass      → 0xFF where byte ∈ [A-Z]
result  = byte OR (mask AND 0x20)  → set the 0x20 lowercase bit only on A-Z
```

The SSE2 inner loop is hand-written asm (`src/dns/simd.rs:62`): `movdqu` load, `pxor`
bias, two `pcmpgtb`, two `pand`, `por`, `movdqu` store. The AVX2 path (`src/dns/simd.rs:103`)
is the VEX-encoded 32-byte equivalent, and its 16-byte tail is also **VEX-encoded**
(`vmovdqu` etc., `src/dns/simd.rs:153`) specifically to avoid the AVX→SSE state-transition
penalty that mixing legacy SSE encodings with AVX would incur. A scalar loop handles the
final < 16 bytes.

Correctness is pinned by `sse2_explicit_all_lengths` and `avx2_explicit_all_lengths`,
which check every length 0..=80 against a scalar reference (`src/dns/simd.rs:511`, `:524`).

---

## 3.4 Byte equality — early-exit SIMD compare

`bytes_eq` (`src/dns/simd.rs:193`) returns `false` immediately on length mismatch, then
compares 32 bytes/iter (AVX2) or 16 (SSE2). Each iteration does `pcmpeqb` + `pmovmskb`
and checks the mask against all-ones; a single differing byte makes the mask `!= 0xFFFF`
and the function returns early (`src/dns/simd.rs:234`). This is the collision-rejection
step after a hash hit — it must be correct for every offset, which
`bytes_eq_mismatch_at_each_position` verifies (`src/dns/simd.rs:572`).

---

## 3.5 QNAME terminator scan — `find_zero`

`find_zero` (`src/dns/simd.rs:318`) locates the `\0` that terminates a wire QNAME, capped
at 255 bytes. SSE2 path: `pcmpeqb` against a zero vector + `pmovmskb`, and the position is
`mask.trailing_zeros()` within the first matching 16-byte block (`src/dns/simd.rs:349`).
This is how `parse_query` finds the end of the name in one pass before lowercasing
(`src/dns/wire_builder.rs:120`).

---

## 3.6 The eBPF hash: why FNV-1a, not CRC32c

File: `ebpf/dns_xdp.c`, `dns_qname_hash` (`ebpf/dns_xdp.c:237`).

In **user space** Runbound hashes with CRC32c. In **the kernel** it uses FNV-1a. This is
not an oversight — it is forced by the BPF verifier, and the reasoning is documented in
the source (`ebpf/dns_xdp.c:217`):

> CRC32C's 8-iteration inner loop (`#pragma unroll 8`) causes exponential scalar-state
> explosion in the BPF verifier and is rejected. FNV-1a's single multiply per byte bounds
> scalar state cleanly and passes the verifier on all kernels that support XDP (4.8+).

The loop is `#pragma unroll`-ed to 64 iterations on purpose. Without unrolling, indexing
`qname[i]` compiles to pointer-plus-loop-variable arithmetic; at the loop back-edge the
verifier loses the minimum bound on the index and rejects the program with *"math between
pkt pointer and register with unbounded min value."* Fully unrolled, each of the 64 copies
has a concrete constant offset and its own `qname + 1 > data_end` bounds check, so the
verifier processes them in linear sequence. FNV-1a (XOR + multiply per byte) yields O(N)
verifier states; CRC32c's bit loop would be O(2^N).

The kernel hash is only used for **optional** per-domain CPUMAP affinity routing
(`ebpf/dns_xdp.c:623`); the default path is RSS via XSKMAP and uses no hash at all.

---

## 3.7 eBPF in-place response forges

The eBPF program can answer two things without ever touching user space:

- **ICMP echo reply** (`ebpf/dns_xdp.c:395`): swap MACs, swap IP src/dst (the IP checksum
  is unchanged because swapping preserves the one's-complement sum), set type 8→0, and fix
  the ICMP checksum **incrementally** — `csum16_add(checksum, htons(ICMP_ECHO << 8))`
  rather than recomputing it (`ebpf/dns_xdp.c:486`). Then `XDP_TX` bounces the frame back
  out the same NIC. Rate-limited per source IP via an LRU hash map with a 1-second sliding
  window and burst tokens.
- **Blacklist NXDOMAIN** (`forge_nxdomain_ipv4`, `ebpf/dns_xdp.c:272`): on a blacklist hit,
  forge the response in place (swap MACs/IPs/ports, clear UDP checksum — legal for IPv4 per
  RFC 768, set DNS flags to `QR=1 RA=1 RCODE=3` while preserving the RD bit) and `XDP_TX`.
  Round-trip is on the order of a microsecond and never wakes a user-space thread.

Both rely on the fact that for a same-length in-place edit, most of the checksum can be
preserved or incrementally patched rather than recomputed.

---

## 3.8 Summary table

| Kernel | Where | Technique | Reference impl tested against |
|--------|-------|-----------|-------------------------------|
| Domain hash (user) | `hasher.rs:70` | CRC32c raw `asm!`, 8/4/1-byte stages | intrinsic `crc32c_sse42` (`:330`) |
| Domain hash (kernel) | `dns_xdp.c:237` | FNV-1a, `#pragma unroll 64` | verifier-bounded by construction |
| Lowercase | `simd.rs:22` | AVX2/SSE2, XOR-0x80 signed-compare trick | scalar, all lengths 0..=80 |
| Byte equality | `simd.rs:193` | AVX2/SSE2 `pcmpeqb`+`pmovmskb`, early exit | scalar, mismatch at each pos |
| Zero scan | `simd.rs:318` | SSE2 `pcmpeqb` + `trailing_zeros` | scalar `position` |

> **Measurement note.** This chapter explains *what the code does and why*. It does **not**
> assign a qps figure to any single kernel — per-kernel microbenchmarks are not part of
> the current benchmark suite, so I cannot confirm an isolated speedup number here. The
> end-to-end performance figures live in [08-performance.md](08-performance.md).
