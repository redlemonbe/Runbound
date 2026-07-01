<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Removing hickory from Runbound's data path — plan & status (COMPLETE)

**Status: de-hickory migration complete (v0.23.8). Phases 1–5 below landed;
phase 6 (DoQ) is the sole exception and remains unshipped (tracked separately,
not a hickory issue). hickory is fully removed from the runtime — `cargo tree
-e normal` is hickory-free. `hickory-proto` remains only as a
`[dev-dependencies]` oracle for differential tests. This document is kept as a
historical record of how the migration was planned and executed; it is no
longer a live plan.**

## Goal (achieved)

Drop `hickory-proto` / `hickory-server` / `hickory-resolver` from the default
build. They pulled a 271-crate tree (the whole `quinn` / `h2` / `hickory-net`
subtree was pulled *only* by them) into an 18 MB binary, and the slow path paid
~1.78× the instructions of unbound partly because of hickory + a spawn per
request. The fast (XDP) path was already almost hickory-free before this work
started.

## Decision (chosen and shipped)

**Forwarder/authoritative by default; sovereign full-recursion is an opt-in
runtime mode, not a build-time gate.** Runbound as typically deployed is a
forwarder (it forwards to upstreams over DoT); full-recursion (`dns::recursor_wire`)
is opt-in via the runtime config directive `resolution: full-recursion` — it is
**always compiled into the binary** and toggled at runtime, not behind a Cargo
feature. (Earlier drafts of this plan floated a `--features recursor` build
flag; that approach was dropped in favor of always-on compilation + runtime
toggle, matching how `hsm-pkcs11-lib` gates HSM/PKCS#11 support.) So:

- The **default build** is hickory-free: own codec (`dns::wire`) + own
  listeners + own forward client. DNSSEC in forward mode is delegated to the
  validating upstream over the authenticated DoT channel by default, and
  Runbound also does full DNSSEC validation in-house (`dns::dnssec_verify`,
  `dns::dnssec_chain`, `dns::dnssec_denial`) when full-recursion is enabled;
  locally-signed zones are covered by the in-house signer (`dns::dnssec_sign`).
- **Full-recursion + local DNSSEC validation** are in-house
  (`dns::recursor_wire` + `dns::dnssec_*`), not `hickory-resolver`. **We did
  not hand-roll a DNSSEC validator or a recursive resolver casually, and we did
  not hand-roll crypto** — validation and signing go through `ring`, matching
  the original security guardrail. ASM/SIMD stayed in the codec hot loops,
  nowhere near crypto or validation.

## What hickory used to be, in this tree (pre-migration)

| Surface | Crate | Where |
|---|---|---|
| Wire codec (Name, Record, RData, OPT) | `hickory-proto` | everywhere — the spine |
| `RequestHandler` / listeners (UDP/TCP/DoT/DoH/DoQ) | `hickory-server` | `server.rs`, `axfr.rs`, `ddns.rs` |
| Recursor + upstream + DNSSEC validation | `hickory-resolver` | `recursor.rs`, `server.rs`, `api/mod.rs` |

`hickory-proto` was load-bearing under the other two: it could not be
half-removed. All three rows above are now gone from the runtime; DNS is
served entirely by the in-house wire codec (`serve_wire`) on every path
(forward, full-recursion, local, AXFR, DDNS, TSIG). `hickory-proto` survives
only as a `[dev-dependencies]` differential-oracle for tests.

## The real coupling that had to be untangled (historical — resolved)

At the time this plan was written, `hickory_proto::rr::Name` / `LowerName` was
the **pervasive key type** (12 source files). Concretely:

- The zone store (`local.rs`, `LocalZoneSet`) was keyed on `LowerName` and
  stored hickory `Record`s: `find(&LowerName)`, `local_records(&LowerName,
  RecordType)`.
- The cache snapshots and ACLs used the same name type.
- The fast path's *only remaining hickory allocation* was `wire_qname →
  LowerName` to look up in that store.

So removing hickory from the data path meant **re-keying the data model on
`wire::Name` / `wire::Record`**, then everything else fell out. This is now
done: see phase 2 in the ladder below.

**Refinement found while wiring:** the *hot* path was already hickory-free at
query time — A/AAAA served from `wire_records` (a wire-keyed index) + the XDP
cache, with no hickory access per packet. hickory in `local.rs` was only at
**load time** (the old `parse_local_data` built hickory `Record`s) and in the
**slow path** (`answer_dns` served hickory `Record`s). So the re-keying split
cleanly into load-time parsing (phase 2) and slow-path serving (phase 3) —
both now shipped.

### What phase 2 delivered

- `wire::present::parse_rr_line` — a hickory-free presentation parser for
  `local-data`, proven byte-identical to the old `parse_local_data` for **all
  twelve types** (A/AAAA/NS/CNAME/PTR/MX/TXT/SRV/CAA/SSHFP/TLSA/NAPTR) via a
  differential test. This replaced the load-time parse; `parse_local_data`
  itself now lives only behind `#[cfg(test)]` as the differential oracle.
- Proof that `wire::Name` preserves hickory's exact wire lookup-key bytes, so
  the re-keying was byte-safe.

### The flip was one coupled refactor, done deliberately

Storing `wire::Record` instead of hickory `Record` was not local to
`local.rs`: the hickory `Record` had been the **lingua franca of the entire
zone subsystem**, read and mutated across ~8 prod-critical files:

| Consumer | File |
|---|---|
| slow-path serving (`find`/`local_records`/`answer_dns`) | `server.rs`, `xdp/worker.rs` |
| AXFR zone transfer (iterates `.records`, emits) | `axfr.rs` |
| dynamic updates (mutates `.records`) | `ddns.rs` |
| REST zone CRUD (adds/removes `.records`) | `api/mod.rs` |
| DNSSEC signing | `zone_signer.rs` |
| master→slave replication | `sync.rs` |

The storage flip + slow-path serving were, as anticipated, a single coupled
refactor across DDNS / AXFR / signing / API / serving. It shipped attentively,
with integration tests green at every step — see the phase ladder below for
what actually landed.

## Phase ladder (each rung shipped, was A/B benched, rolled back trivially if needed)

- **Phase 1 — own codec. DONE.** `src/dns/wire/`: bounds-checked decoder,
  compressing encoder, `Name` (triple-bounded decompression — backward-only
  pointers, pointer cap, 255-octet budget), `Header`, `Question`, `Rdata`
  (A/AAAA/NS/CNAME/SOA/PTR/MX/TXT/SRV/CAA + RFC 3597 opaque passthrough),
  `Record`, `Message`, EDNS. Proven: unit round-trips + the name DoS cases;
  differential tests vs hickory as an oracle (canonical-bytes equality) for
  A/AAAA/CNAME/NS/MX/PTR/SOA/TXT/SRV + EDNS; a 50k-iter no-panic/no-hang fuzz;
  and a proof that `wire::Name` ≡ hickory `LowerName` as a lookup key. hickory
  stays a dev-time oracle for differential fuzzing for the whole project.
- **Phase 2 — re-key the data model. DONE.** `local.rs` / `LocalZoneSet` now
  stores `wire::Record` (`records_wire`, keyed on wire-form bytes via
  `wire_name_key`), alongside the legacy hickory-keyed store kept for
  `#[cfg(test)]` differential comparison only. The old `parse_local_data`
  hickory-typed parser is now itself `#[cfg(test)]`-gated (a test-only oracle);
  the real load-time parser is `wire::present::parse_rr_line`. The fast path's
  lookup is `wire_qname → wire::Name`, no hickory allocation.
- **Phase 3 — own listeners. DONE.** `hickory_server::ServerFuture` is gone;
  `dns::server` runs its own tokio UDP/TCP/DoT (rustls) listeners, and DoH is
  served by Runbound's own `doh_service` (hickory's DoH handler rejected
  bodyless RFC 8484 GETs, which real browsers send). `serve_wire` /
  `serve_datagram` (own wire codec) answer every query on every listener.
  `axfr.rs` / `ddns.rs` run on the codec + these listeners. **DoQ is the one
  exception:** the QUIC listener is still an explicit no-op stub in
  `dns::server` ("DNS-over-QUIC: not supported in this build") — `quic-port` is
  parsed and stored in config but not served. This is a real gap, tracked
  separately from the de-hickory migration (see phase 6 below).
- **Phase 4 — own forward client. DONE.** Upstream forwarding runs over
  UDP/TCP/DoT (rustls); DNSSEC in forward mode sets DO/CD and trusts upstream
  AD over the authenticated DoT channel. `hickory-resolver` is gone from the
  forward path. Racing + cache retargeted onto the new client.
- **Phase 5 — full-recursion + DNSSEC validation, always compiled in. DONE
  (with a design change from the original plan).** Rather than gating
  full-recursion behind a `--features recursor` Cargo feature as originally
  planned, it shipped as `dns::recursor_wire` + `dns::dnssec_verify` /
  `dnssec_chain` / `dnssec_denial` — **always compiled into the default
  binary**, toggled at runtime via `resolution: full-recursion` in config
  (default is `forward`). This mirrors how HSM/PKCS#11 support (`src/hsm.rs`)
  is gated by the runtime directive `hsm-pkcs11-lib` rather than a build flag.
  Net result matches the phase's goal: the default build compiles with
  **zero** hickory in `cargo tree -e normal`; `hickory-proto` is a
  `[dev-dependencies]`-only differential oracle.
- **Phase 6 — DoQ. NOT DONE — still open.** `quinn` is not a direct runtime
  dependency and there is no DoQ listener; the QUIC path in `dns::server` is a
  stub. This is the one item from the original plan that has not shipped.

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
