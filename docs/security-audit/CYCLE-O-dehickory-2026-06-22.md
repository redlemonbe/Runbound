# Cycle O — v0.22.0 (`feat/dehickory`) → de-hickory total — two-AI adversarial audit

**Date:** 2026-06-22
**Sources:** [AI-INTERNAL] Claude Opus 4.8 — read-only audit of the de-hickory delta, every
finding verified at the source. [AI-ADVERSARIAL] Gemini 3.1 Pro — independent cross-model pass over
the auth/crypto/forward surface (`tsig.rs`, `ddns.rs`, `forward.rs`, the `serve_wire` excerpt).
**Scope:** the new wire serving introduced by the de-hickory refactor — AXFR/IXFR (`axfr.rs` +
`wire_serve::axfr_response`), TSIG verification (`tsig.rs`, RFC 8945), DNS UPDATE (`ddns.rs`,
RFC 2136), the in-house DNSSEC signer (`dnssec_sign.rs`, `zone_signer.rs`), the own upstream
forwarder (`forward.rs`, replacing hickory-resolver), and the `serve_wire` gate/serving path
(`server.rs`). The XDP/eBPF/AF_XDP datapath is **unchanged** (`git diff 8a5fc23..HEAD -- src/dns/xdp/`
is empty) — no fast-path finding can have been introduced.

| ID | Severity | Status | Finding |
|---|---|---|---|
| SEC-O1 | HIGH | ✅ Fixed | **Forward cache-poisoning — missing transaction-ID and question validation.** `forward::UdpUpstream::do_query` sends the query and accepts the first datagram `recv()` returns, parsing it as the answer **without checking the response's DNS transaction ID matches the query, nor that the response question matches the query question** (`parse_response` only reads the rcode/answers). hickory-resolver — which this code replaced — validated both; the de-hickory rewrite dropped it (**regression**). Mitigations present: the socket is `connect()`ed to the upstream (kernel source-address/port filter) and the source port is randomised (`bind 0.0.0.0:0`). But an attacker able to spoof the upstream's source IP:port (on-path, shared L2, a NATing/compromised upstream) can inject a forged response the kernel accepts, and with no txid/question check it is taken verbatim → cache poisoning. **Both the internal and the Gemini pass found this independently.** The DoT path is unaffected (TLS authenticates the upstream). **Fixed:** the query txid + question are captured before send; on `recv` the response is rejected unless `id` and the first question (name case-insensitive + type + class) match, and the socket keeps reading until a matching response or the timeout (a single spoofed non-matching datagram no longer aborts resolution). |
| SEC-O2 | MEDIUM | ✅ Fixed | **FD exhaustion in the forward path.** `do_query` binds **one fresh UDP socket per forward query**; with `MAX_INFLIGHT_REQUESTS = 4096` a cache-miss burst opens up to 4096 sockets at once, exceeding a default soft `RLIMIT_NOFILE` of 1024 → `bind: Too many open files` → forwarding collapses under load (observed on the bench when launched outside the systemd unit's `LimitNOFILE`). In production (systemd `LimitNOFILE=65536`) it does not trigger, but the binary must not depend on the launcher. **Fixed (commit `3134b31`):** `main()` self-raises `RLIMIT_NOFILE` to ~1M (soft+hard) as its first action. **Residual enhancement → OPEN-O1:** the per-query socket bind is still wasteful; a per-upstream socket pool would bound FD use and cut churn. |
| SEC-O3 | LOW | 🟡 Accepted | **TSIG replay inside the fudge window.** `tsig::verify_request` enforces a ±300 s time window but keeps no replay nonce, so a captured valid TSIG-signed UPDATE can be replayed within 300 s and re-applied. This is the inherent single-message TSIG property (RFC 8945 §5.2.3 leaves it to the timer); the relay/sync path has a nonce (SEC-N5), DDNS does not. Accepted: requires capturing a valid signed UPDATE and a 300 s window; add/delete are idempotent for the common case. Candidate enhancement if DDNS exposure widens. |
| SEC-O4 | INFO | ⛔ Disputed | (Gemini) "the TSIG digest does not substitute the Original ID into the header before computing the MAC (RFC 8945 §4.3.3)." **Refuted for request verification:** for a request the received header ID **equals** the Original ID (the client sets them equal and signs over the actual ID). `request_digest_data` reconstructs over the verbatim received header, so a matching request verifies and a request whose ID was tampered in transit **fails** the MAC — which is the correct, *stronger* behaviour. Substituting Original ID would let an attacker rewrite the ID and still pass. The substitution only matters for an ID-rewriting forwarder in front of the signer, which is not the direct client→server DDNS path. No security impact. |
| SEC-O5 | INFO | 🟡 Accepted | **TSIG truncated-MAC not accepted.** RFC 8945 §5.2.2.1 permits a MAC truncated to ≥ max(10, half the algorithm output); `verify_request` compares the full tag (`ring::hmac::verify`), so a legitimately truncated TSIG is rejected. Interop, not security (a forged short MAC still fails). Accepted — Runbound signs full-length MACs; revisit only for a client that truncates. |
| SEC-O6 | INFO | ✅ Fixed | **Stale comment.** `server.rs` carried "Hickory handles recursion/TSIG/AXFR via the fallback channel only" — TSIG and AXFR are now served wire-native; only the (feature-gated) recursor uses the fallback. Comment corrected. |

**Negative space (re-confirmed, carry no finding):**
- `wire::Name::parse` is robust against the classic compression-pointer DoS: `MAX_POINTERS` cap,
  strictly-backward pointers (`target >= pos` rejected), `MAX_NAME_WIRE` budget, full bounds checks,
  reserved label types rejected.
- TSIG MAC comparison is constant-time (`ring::hmac::verify`); verification is fail-closed
  (no keys configured → REFUSED; `allow-update: no` → REFUSED before any parse).
- `parse_for_tsig` and the wire decoder are bounded by the packet length; no unbounded loop or
  unchecked indexing on attacker-controlled input in the new `tsig.rs` / `ddns.rs`.
- ACL `Deny` returns an empty buffer which **both** the UDP and TCP listeners drop without sending
  (`if !resp.is_empty()` / `if resp.is_empty() { continue }`), so deny is a silent drop, not a
  malformed empty datagram.
- DDNS enforces the static-zone delete guard via `static_names_wire`; the DNSSEC signer is
  oracle-proven byte-identical to hickory and delv-validated (positive, SOA, CNAME chain,
  NSEC3 NXDOMAIN + NODATA all "fully validated").

**Open:** OPEN-O1 (enhancement) — per-upstream UDP socket pool to bound FD use / cut bind churn.

**Remediation & datapath.** SEC-O1 and SEC-O6 fixed in `forward.rs` / `server.rs`; SEC-O2 fixed in
`main.rs` (commit `3134b31`). SEC-O3/O5 accepted, SEC-O4 disputed. The XDP/eBPF/AF_XDP packet code is
byte-identical to the pre-de-hickory baseline. CI gate: `cargo test --release --bin runbound` green.

> Consistent with prior cycles, the cross-model (Gemini) pass over-rated one item (SEC-O4) but
> **independently converged with the internal pass on the one real HIGH (SEC-O1)** — the value of
> the two-AI process. No item is "100% fixed": SEC-O3/O5 accepted, SEC-O4 disputed, OPEN-O1 open.
