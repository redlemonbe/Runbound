# 01 — Architecture

## 1.1 The core idea

A DNS resolver spends most of its CPU on a tiny, repetitive task: receive a UDP
datagram, look up a name, send a UDP datagram. The general-purpose kernel network stack —
sockets, softirqs, the full IP/UDP receive path, one async task per query — adds a large
constant cost to that tiny task.

Runbound's thesis is to **answer the common case as close to the wire as possible** and
fall back to a full DNS server only for everything else. Concretely, there are three
tiers, fastest first:

```
                         ┌─────────────────────────────────────────────┐
   UDP/53 frame  ───────▶│ Tier 1 — XDP fast path  (cfg: xdp = yes)     │
                         │   eBPF redirect → AF_XDP → user-space worker  │
                         │   parse + answer inside the NIC ring (no copy)│
                         └───────────────┬─────────────────────────────┘
                                         │ cannot answer (recursion, TCP, DNSSEC…)
                         ┌───────────────▼─────────────────────────────┐
   UDP/53 frame  ───────▶│ Tier 2 — kernel UDP fast loop (xdp = no)     │
                         │   SO_REUSEPORT per-core thread                │
                         │   recv_from → wire answer → cache → fallback  │
                         └───────────────┬─────────────────────────────┘
                                         │ fallback channel
                         ┌───────────────▼─────────────────────────────┐
                         │ Tier 3 — wire-native handler `serve_wire`    │
                         │   forward, TCP, DoT/DoH/DoQ, DNSSEC signing,  │
                         │   TSIG, AXFR/IXFR, DDNS, CNAME/MX, EDNS DO=1   │
                         │   (optional `recursor` feature = full         │
                         │    recursion via hickory-resolver)            │
                         └───────────────────────────────────────────────┘
```

Tier 1 and Tier 2 are mutually exclusive at runtime (chosen by the `xdp` config
directive). Both share the **same** zero-allocation wire answer routine. Tier 3 is always
present. As of **v0.22 ("de-hickory")** Tier 3 is the in-house wire handler `serve_wire`
(`src/dns/server.rs:1195`, codec in `src/dns/wire/`): the `hickory-server` request handler
is gone from the default binary. The only place a hickory request handler still runs is the
sovereign full-recursion resolver, gated behind the optional `recursor` Cargo feature
(`Cargo.toml:180`, `dep:hickory-resolver` + `dep:hickory-server`). `hickory-proto` stays a
default dependency — it backs part of the in-memory data model and the XDP response
builders, and is a differential-oracle dev-dependency for tests — but no hickory handler is
on the default serving path.

## 1.2 Why this shape — the measurement that drove it

The split is not premature optimisation; it is a response to a measured cost. On a dual
Xeon E5-2690 v2 with an X520 NIC, at a fixed 200k qps, the comparison was
(`src/dns/kernel_loop.rs:6`):

| | instructions | cycles | IPC |
|---|---|---|---|
| Runbound, naïve hickory slow path | 72.8 G | 159 G | 0.46 |
| Unbound (reference) | 40.8 G | 83 G | 0.49 |

That is **1.78× more instructions per query** than Unbound, and the root cause was
identified as the hickory `ServerFuture` model: one `tokio::spawn` per UDP query plus a
generic `Message::emit` codec on the hot path. The wire fast path
(`answer_dns_wire`) and the cache fast path exist to take the common queries *out* of that
model entirely; the wire-native `serve_wire` handler then deals with what genuinely needs a
full server. The v0.22 de-hickory work removed the hickory request handler from the default
build outright, so even the fallback path no longer pays the `ServerFuture` per-query cost.

> This is also why the whitepaper is careful with performance claims: the slow path was
> measurably heavier than Unbound, and the fast paths are the remedy. The end-to-end
> numbers belong in [08-performance.md](08-performance.md), under the project's
> benchmark methodology, not in the architecture chapter.

## 1.3 The shared wire answer routine

Both fast tiers call the same function, `answer_dns_wire` (exposed as
`answer_dns_wire_pub` for the kernel loop, `src/dns/kernel_loop.rs:202`). It:

1. parses the query with `parse_query` (no allocation, SIMD `find_zero`),
2. looks the name up in a `WireRecordIndex` keyed by CRC32c `hash_wire_qname`,
3. builds the A/AAAA answer directly into the output buffer with a name-compression
   pointer to the question (`src/dns/xdp/wire_builder.rs`).

If the query is anything the wire path does not handle (EDNS DO=1 / DNSSEC, CNAME, MX,
TSIG, AXFR, TCP, or a cache/zone miss requiring recursion), the routine returns
`Fallback` and the query is handed up a tier. The contract that the two normalisation
paths (load-time hickory `Name` and hot-path raw wire) produce **byte-identical** keys is
enforced by the `wire_qname_roundtrip` test (`src/dns/hasher.rs:411`); if it ever broke,
fast-path lookups would silently miss, so the test is the guard against a silent no-op.

## 1.4 Process and runtime model

- **DNS data plane.** Tier 1 uses dedicated OS worker threads pinned to physical,
  NUMA-local cores, one per AF_XDP queue. Tier 2 uses one blocking OS thread per
  NUMA-local core, each owning a `SO_REUSEPORT` UDP socket (`src/dns/kernel_loop.rs:117`).
  Buffers are stack-allocated (`[u8; 4096]`), never heap, on the hot path
  (`src/dns/kernel_loop.rs:177`). `SO_RCVBUF`/`SO_SNDBUF` are set to 8 MiB and the code
  warns if the kernel clamps them (`net.core.rmem_max` too low).
- **Control plane.** The REST API runs on a **separate, dedicated 2-thread Tokio runtime**
  (`src/main.rs`, the `runbound-api` runtime). The rationale, documented inline: under DoT
  rebuild storms the DNS runtime can be flooded with hundreds of tasks/second, which would
  otherwise starve axum's task slots and freeze the API. Isolating the runtimes means DNS
  load cannot freeze management, and management cannot steal the DNS schedulers.
- **Listener fd handoff.** The API TCP listener is bound with `std::net::TcpListener` and
  set non-blocking, then converted inside the API runtime — so the file descriptor is
  runtime-agnostic at bind time.

## 1.5 Source-tree map

| Area | Path | Role |
|------|------|------|
| XDP fast path | `src/dns/xdp/` | eBPF loader, AF_XDP sockets, UMEM, worker, wire builder |
| eBPF program | `ebpf/dns_xdp.c` | XDP hook compiled at build, embedded in the binary |
| Kernel UDP fast loop | `src/dns/kernel_loop.rs` | `SO_REUSEPORT` per-core fast loop (xdp: no) |
| Slow path (wire-native) | `src/dns/server.rs` (`serve_wire`), `src/dns/wire_serve.rs` | forward, DoT/DoH, AXFR/IXFR, TSIG, DDNS, DNSSEC signing |
| Wire DNS codec | `src/dns/wire/` | in-house message/name/rdata encode+decode (de-hickory) |
| Optional recursor | `src/dns/recursor.rs` (`recursor` feature) | sovereign full recursion (hickory-resolver) |
| SIMD/ASM kernels | `src/dns/simd.rs`, `src/dns/hasher.rs` | lowercasing, comparison, hashing |
| Local zones | `src/dns/local.rs` | `LocalZoneSet`, `WireRecordIndex` |
| REST API | `src/api/` | axum CRUD, relay, SSE, backup, split-horizon |
| Config | `src/config/` | unbound.conf-style parser + atomic config-writer |
| Web UI | `src/webui/` | embedded static UI (gzipped at build) |
| Relay / sync | `src/sync.rs`, `src/api/relay.rs` | HMAC master→slave relay, auto-registration |

## 1.6 Failure modes and escape hatches

- `RUNBOUND_DISABLE_XDP=1` — emergency switch that forces the kernel UDP path even when
  the config requests XDP.
- XDP DRV mode fails on `virtio-net` when the MTU exceeds the single-buffer limit; the
  loader falls back to SKB mode.
- The attached XDP program is tracked by an `XdpHandle` whose `Drop` detaches it, so the
  program is not left bound to the NIC after a crash. (If a stray program is ever left
  attached, `ip link set <iface> xdp off` removes it.)
- In XDP mode, recursion-miss fallbacks must be replied from a socket bound to `:53` — not
  an ephemeral port, which clients silently reject. This is the `XDP_FALLBACK_REPLY_SOCK`
  mechanism (`src/dns/kernel_loop.rs:55`, issue #167).
