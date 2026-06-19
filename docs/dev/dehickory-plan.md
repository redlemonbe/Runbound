<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Removing hickory from Runbound's data path — plan & status

**Status: phase 1 landed (own wire codec, proven). Phases 2–6 are a data-model
re-keying, scoped below.**

## Goal

Drop `hickory-proto` / `hickory-server` / `hickory-resolver` from the default
build. They pull a 271-crate tree (the whole `quinn` / `h2` / `hickory-net`
subtree is pulled *only* by them) into an 18 MB binary, and the slow path pays
~1.78× the instructions of unbound partly because of hickory + a spawn per
request. The fast (XDP) path is already almost hickory-free.

## Decision (chosen)

**Forwarder/authoritative by default; sovereign recursion stays an opt-in
island.** Runbound as deployed is a forwarder (it forwards to upstreams over
DoT; the #202 recursor is opt-in, default-off, never deployed). So:

- The **default build** becomes hickory-free: own codec + own listeners + own
  forward client. DNSSEC in forward mode is delegated to the validating
  upstream over the authenticated DoT channel; locally-signed zones are already
  covered by `zone_signer` (#201).
- **`--features recursor`** keeps `hickory-resolver` for #202 + local DNSSEC
  validation. It becomes the *only* thing pulling hickory. **We do not
  hand-roll a DNSSEC validator or a recursive resolver, and we do not hand-roll
  crypto** — that would defeat the security goal. ASM/SIMD belongs in the codec
  hot loops, nowhere near crypto or validation.

## What hickory actually is, in this tree

| Surface | Crate | Where |
|---|---|---|
| Wire codec (Name, Record, RData, OPT) | `hickory-proto` | everywhere — the spine |
| `RequestHandler` / listeners (UDP/TCP/DoT/DoH/DoQ) | `hickory-server` | `server.rs`, `axfr.rs`, `ddns.rs` |
| Recursor + upstream + DNSSEC validation | `hickory-resolver` | `recursor.rs`, `server.rs`, `api/mod.rs` |

`hickory-proto` is load-bearing under the other two: you cannot half-remove it.

## The real coupling (the thing phase 2 is actually about)

`hickory_proto::rr::Name` / `LowerName` is the **pervasive key type** (12 source
files). Concretely:

- The zone store (`local.rs`, `LocalZoneSet`) is keyed on `LowerName` and stores
  hickory `Record`s: `find(&LowerName)`, `local_records(&LowerName, RecordType)`.
- The cache snapshots and ACLs use the same name type.
- The fast path's *only remaining hickory allocation* is `wire_qname →
  LowerName` to look up in that store (`wire_builder.rs:204`).

So removing hickory from the data path = **re-keying the data model on
`wire::Name` / `wire::Record`**, then everything else falls out.

**Refinement found while wiring:** the *hot* path is already hickory-free at
query time — A/AAAA serve from `wire_records` (a wire-keyed index) + the XDP
cache, with no hickory access per packet. hickory in `local.rs` is at **load
time** (`parse_local_data` builds hickory `Record`s) and in the **slow path**
(`answer_dns` serves hickory `Record`s). So phase 2 splits cleanly:
load-time parsing (replaceable now — see below) and slow-path serving (phase 3).

### Phase 2 progress

- **Done:** `wire::present::parse_rr_line` — a hickory-free presentation parser
  for `local-data`, proven byte-identical to `parse_local_data` for
  A/AAAA/NS/CNAME/PTR/MX/TXT/SRV (differential test). The rarer types
  (CAA/SSHFP/TLSA/NAPTR) are next, then the zone store builds from our records.

## Phase ladder (each rung ships, is A/B benched, rolls back trivially)

- **Phase 1 — own codec. DONE.** `src/dns/wire/`: bounds-checked decoder,
  compressing encoder, `Name` (triple-bounded decompression — backward-only
  pointers, pointer cap, 255-octet budget), `Header`, `Question`, `Rdata`
  (A/AAAA/NS/CNAME/SOA/PTR/MX/TXT/SRV/CAA + RFC 3597 opaque passthrough),
  `Record`, `Message`, EDNS. Proven: unit round-trips + the name DoS cases;
  differential tests vs hickory as an oracle (canonical-bytes equality) for
  A/AAAA/CNAME/NS/MX/PTR/SOA/TXT/SRV + EDNS; a 50k-iter no-panic/no-hang fuzz;
  and a proof that `wire::Name` ≡ hickory `LowerName` as a lookup key. hickory
  stays a dev-time oracle for differential fuzzing for the whole project.
- **Phase 2 — re-key the data model.** Introduce `wire::Name`/`wire::Record`
  into `local.rs` + cache, behind conversions at the boundary so existing
  hickory-typed callers keep working. Differential test: every lookup returns
  the same answer as the hickory-keyed store. Then the fast path's last hickory
  allocation becomes `wire_qname → wire::Name` (no hickory).
- **Phase 3 — own listeners.** Replace `hickory_server::ServerFuture` with tokio
  UDP/TCP + DoT (rustls). DoH is already ours. Drops `hickory-server` (+ `h2`).
  Port `axfr.rs` / `ddns.rs` onto the codec + new listeners.
- **Phase 4 — own forward client.** Stub upstream over UDP/TCP/DoT(rustls)/DoH.
  DNSSEC forward = set DO/CD, trust upstream AD over DoT. Drops
  `hickory-resolver` from the default path. Racing + cache already exist; retarget.
- **Phase 5 — gate the recursor.** Move #202 + local validation behind
  `--features recursor`. Default build compiles with **zero** hickory. Measure
  271→? crates, 18 MB→?.
- **Phase 6 — DoQ.** Re-add `quinn` directly (leaner) if DoQ stays in the
  default, else gate it too.

## Guardrails (non-negotiable, every phase)

- hickory kept as a **dev-dependency oracle** for differential fuzzing.
- `cargo-fuzz` on the parser (the #1 risk surface); the in-tree 50k fuzz is the
  floor.
- Hard bounds in the parser (already): name ≤255, label ≤63, backward-only
  compression pointers, pointer-chase cap, header-count vs body.
- A/B X710 NIC-truth bench on every data-path phase: no regression, byte-identical
  answers where the path was byte-identical before.
- Two-AI audit on the security-sensitive phases (parser, forward DNSSEC delegation).
- Crypto via `ring`/`aws-lc-rs`. No DIY validator in the default path.
