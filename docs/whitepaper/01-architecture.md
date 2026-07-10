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
                         │   (full-recursion: in-house, always compiled  │
                         │    in, off by default — opt-in via the        │
                         │    `resolution` config, not a Cargo feature)   │
                         └───────────────────────────────────────────────┘
```

Tier 1 and Tier 2 are mutually exclusive at runtime for the physical NIC (chosen by the
`xdp` config directive) — with one exception: in XDP mode, loopback (`127.0.0.1`) traffic
is served by an always-started, one-core kernel UDP fast loop (`src/dns/kernel_loop.rs`,
issue #167b) running *alongside* the XDP workers, because XDP only owns the physical NIC
and local resolution still needs a kernel path. So for loopback traffic specifically, Tier
1 and Tier 2 run concurrently. Both share the **same** zero-allocation wire answer routine.
Tier 3 is always present: it is the in-house wire handler
`serve_wire` (`src/dns/server.rs:464`, codec in `src/dns/wire/`). Every path (forward,
full-recursion, local, AXFR, DDNS, TSIG, …) is served by `serve_wire`. The sovereign
full-recursion resolver (`src/dns/recursor_wire.rs`) and DNSSEC validation
(`src/dns/dnssec_*.rs`) are entirely in-house and always compiled in (no Cargo feature
gates them) — but OFF by runtime default: `resolution: forward` and `dnssec-validation: no`
are the defaults; full-recursion and DNSSEC validation are opt-in via config
(`resolution: full-recursion`, `dnssec-validation: yes`), not a build flag; no such
`recursor` feature exists. `hickory-proto` is a `[dev-dependencies]` entry only, used
solely by the differential-oracle tests — it is not a runtime dependency and does not back
the in-memory data model or the XDP response builders.

## 1.2 Why this shape — the measurement that drove it

The split is not premature optimisation; it is a response to a measured cost. A naïve
spawn-per-query slow path (one `tokio::spawn` per UDP query plus a generic message-emit
codec on the hot path) costs about **1.78× more instructions per query** than Unbound at a
fixed 200k qps on a dual Xeon E5-2690 v2 with an X520 NIC (`src/dns/kernel_loop.rs:6`). The
wire fast path (`answer_dns_wire`) and the cache fast path take the common queries *out* of
that model entirely; the wire-native `serve_wire` handler then deals with what genuinely
needs a full server. Even the fallback path pays no per-query `ServerFuture` cost: it is the
in-house wire handler throughout.

> This is also why the whitepaper is careful with performance claims: a spawn-per-query
> slow path is measurably heavier than Unbound, and the fast paths are the remedy. The
> end-to-end numbers belong in [08-performance.md](08-performance.md), under the project's
> benchmark methodology, not in the architecture chapter.

## 1.3 The shared wire answer routine

Both fast tiers call the same function, `answer_dns_wire` (exposed as
`answer_dns_wire_pub` in `src/dns/xdp/worker.rs`, called from the kernel loop at
`src/dns/kernel_loop.rs:375` (`answer_dns_wire_pub`)). It:

1. parses the query with `parse_query` (no allocation, SIMD `find_zero`),
2. looks the name up in a `WireRecordIndex` keyed by CRC32c `hash_wire_qname`,
3. builds the A/AAAA answer directly into the output buffer with a name-compression
   pointer to the question (`src/dns/wire_builder.rs`, shared with the kernel-UDP
   fallback path — there is no separate copy under `src/dns/xdp/`).

If the query is anything the wire path does not handle (EDNS DO=1 / DNSSEC, CNAME, MX,
TSIG, AXFR, TCP, or a cache/zone miss requiring recursion), the routine returns
`Fallback` and the query is handed up a tier. The contract that the two normalisation
paths (load-time name parsing and hot-path raw wire) produce **byte-identical** keys is
enforced by the `wire_qname_roundtrip` test (`src/dns/hasher.rs:412`); if it ever broke,
fast-path lookups would silently miss, so the test is the guard against a silent no-op.

## 1.4 Process and runtime model

- **DNS data plane.** Tier 1 uses dedicated OS worker threads pinned to physical,
  NUMA-local cores, one per AF_XDP queue. Tier 2 uses one blocking OS thread per
  NUMA-local core, each owning a `SO_REUSEPORT` UDP socket (`start_kernel_fast_loop`, `src/dns/kernel_loop.rs:152-153`).
  The per-worker RX/TX scratch buffers are `Vec<[u8; DNS_BUF_SIZE]>` (heap), allocated
  **once** before the hot loop and reused every batch — so there is **zero allocation per
  packet** on the hot path (`rx_bufs`/`tx_bufs`, `src/dns/kernel_loop.rs:256` and `:261`; `DNS_BUF_SIZE = 4096`).
  `SO_RCVBUF`/`SO_SNDBUF` are set to 32 MiB and the code warns if the kernel clamps them
  (`net.core.rmem_max` too low).
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
| Wire DNS codec | `src/dns/wire/` | in-house message/name/rdata encode+decode |
| Full recursion | `src/dns/recursor_wire.rs` | sovereign full recursion, in-house, always compiled in but off by default (runtime config toggle, not a Cargo feature) |
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
  mechanism (`src/dns/kernel_loop.rs:56`, issue #167).
