# Runbound — Double-pass security audit (2026-07-07)

**Cycle label:** `[AI-ADVERSARIAL]`
**Target:** branch `v0.9.2`, HEAD `803634c` (pre-fix); fixes landed in this cycle.
**Method:** four independent adversarial AI auditors run on disjoint attack surfaces
(memory-safety/crash/DoS, DNSSEC integrity/cache-poisoning/spoofing, injection/RCE/SSRF,
auth/authz/relay/control-plane), each required to produce a concrete reproducible trigger;
every candidate then re-verified at the source before acceptance (an unreproduced candidate
is discarded, not recorded as a finding). Prior cycles (`SECURITY-AUDIT.md`,
`QMIN-231-2026-07-06.md`, `PENTEST-2026-07-06.md`) were read first and their
Fixed/Accepted/Disputed items excluded — this cycle targets the surfaces landed **after**
those (RFC 2308 negative cache, compact-denial→NXDOMAIN, IPv6 slow path, prefetch cache-scan,
logfile/pidfile wiring, the do-udp/do-tcp + axfr-enable gates, dnssec-log-bogus, the inlined
cache-insert).

No CRITICAL or HIGH finding with a reproducible trigger. The data-path parsers were fuzzed
(`Message::parse`, 1 746 022 executions / 60 s, zero crash, flat RSS); rkyv cache load is the
validating path; recursor budgets and DNSSEC denial remain fail-closed and bailiwick-bound.
Findings are defence-in-depth hardening plus one control-plane authorization gap.

---

## Findings

### SEC-2026-07-J — MEDIUM — Audit log readable by any authenticated non-admin key — **Fixed**

`GET /api/audit/tail` (`src/api/mod.rs`, `audit_tail_handler`) took `(State, Query)` only and
performed no `caller.admin` check. The auth middleware enforces RBAC on **writes** (`may_write`);
every GET is reachable by any valid key, so in multi-user mode a scoped `Read`/`Dns`/`Operator`
key could `GET /api/audit/tail?n=1000` and read the tamper-evident action log — per-actor
usernames of every other user/admin, auth-failure paths, config reloads, key rotations. The
maintainer already gates the sibling disclosure `/api/backup/export` to admins (SEC-N1); the
audit trail is a security control, not operational telemetry, and belongs behind the same gate.

- **Repro:** issue a non-admin key in multi-user mode → `curl -H "Authorization: Bearer <read-key>"
  http://127.0.0.1:8080/api/audit/tail` returned the full tail (200).
- **Fix:** added the `caller_ext` extractor + `if !caller.admin { 403 }` gate used by every other
  privileged handler. No-op in single-user mode (the only key is admin).

### SEC-2026-07-K — LOW — Backup import writes secret files without 0600 — **Fixed**

`backup_import_handler` (`src/api/mod.rs`) wrote each restored file via
`OpenOptions::write(true).create_new(true)` with **no `.mode(0o600)`**. `BACKUP_STATE_FILES`
includes `api.key`, `webui-auth.conf`, `sync-key.pem`, `webui-ca-key.pem`; under the common
`umask 022` these landed `0644` (world-readable) — a window an unprivileged local reader could
use. Every other secret-write path (`tls_write_key_0600`, `sync::write_key_0600`, the rotate-key
persist) explicitly forces `0600`; this one path was the outlier.

- **Precondition/scope:** admin-gated (only an admin imports a backup) + a local unprivileged
  reader — hence LOW, but a real regression of the deliberate 0600 invariant (re-opens the
  window SEC-J7/SEC-L3 closed).
- **Fix:** `.mode(0o600)` on the tmp-file creation (applied to all restored files; harmless for
  data files).
- **Correctness sub-note (Fixed):** `apply_config_hot_reload` re-reads zones/alerts/resolution
  only — a restored `api.key`/registry/WebUI creds bind at startup and are **inert** until
  restart while the old secret keeps working (fails safe, not a bypass). The success response
  previously claimed "applied live — no restart needed" for these too; now, when a restored file
  is secret material, the note states a restart is required for it to take effect.

### SEC-2026-07-L — LOW — Forward negative-cache trusts the authority SOA with no in-bailiwick check — **Fixed**

In `Forward` mode (the **default**), `parse_response` / `soa_min_ttl` (`src/dns/forward.rs`)
derived the RFC 2308 negative TTL from **any** `Rdata::Soa` in `msg.authority`, with no check that
the SOA owner encloses the qname — unlike the recursor path, which routes through
`validated_negative_authority` and drops a forged/unsigned/out-of-bailiwick SOA. A malicious/NATing
upstream, or an on-path spoofer who already defeats the SEC-O1 window (txid + question + connected
socket + random source port), could pin a negative for a name under an unrelated zone's SOA.

- **Severity bounded to LOW:** forward mode does not DNSSEC-validate — the configured upstream is a
  trusted actor already entitled to deny the name — and the only untrusted actor (on-path spoofer)
  must already beat SEC-O1, with which it could inject a forged **positive** answer instead; the
  negative-cache path grants no new capability. Poisoning is scoped to the exact `(qname, qtype)`
  and the TTL is hard-clamped to `NEG_CACHE_MAX_TTL = 900 s`.
- **Fix:** `zone_soas()` / the `soa_min_ttl` guard now keep only SOAs where
  `qname.is_in_zone(&soa.name)`, using the response's own (SEC-O1-matched) question as the anchor.
  Mirrors the recursor's in-bailiwick behaviour for laterally-unrelated SOAs. New unit test
  `negative_soa_out_of_bailiwick_is_dropped`.
- **Documented limitation:** `is_in_zone` treats the root/an ancestor zone as enclosing, so this
  rejects a laterally-unrelated SOA (`other.tld` for `www.victim.tld`) but not an ancestor SOA
  (`.`/`tld`); the impact of an ancestor SOA is nonetheless identical and already bounded (exact-key
  scope + 900 s clamp), so no stronger check is warranted without the delegation chain forward mode
  does not have.

### SEC-2026-07-M — INFO — `parse_nsec` sliced the type bitmap at the presentation name length — **Fixed (hardening)**

`parse_nsec` (`src/dns/dnssec_denial.rs`) computed the bitmap offset as `next.len()` (decompressed
presentation length) rather than the decoder's consumed byte count. RFC 4034 §4.1.1 forbids
compression in the NSEC next-name, so in practice `next.len()` == bytes-consumed; a violating peer
could mis-offset the bitmap, but the path is fail-closed (a compression pointer inside the RDATA
parses backward and hits `NameTooLong`/`MAX_POINTERS` → `Err` → `None`; the `> rdata.len()` guard
keeps the slice panic-free) and config-gated behind `resolution: full-recursion` +
`dnssec-validation: yes`; the worst case is a denial proof failing → Bogus → SERVFAIL (safe
direction). Fixed to slice at `dec.pos()` (exact bytes read).

---

## Accepted (understood residual)

- **SEC-2026-07-K/A — neg-TTL floored to `cache_min_ttl`.** A tiny SOA `minimum` is bumped up to
  `cache_min_ttl` before the 900 s clamp, so an authoritative-zone controller can make its own
  random-subdomain negatives linger up to `min(cache_min_ttl, 900 s)`. Same bounded cache-pollution
  class already Accepted as SEC-H5/SEC-I7 (capped by `cache_max_entries` + sentinel-guarded eviction
  + the #165 `retain`). No change.
- **Forward mode does not DNSSEC-validate.** By design — forward mode trusts the configured
  upstream (`resolution: forward`). Users needing on-path integrity use `resolution: full-recursion`
  (in-house validation, fail-closed). SEC-2026-07-L hardens the SOA hygiene within that trust model.

## Open (not remediated — pending maintainer decision)

- **SEC-2026-07-N — LOW — WebUI session is 8 h absolute; the advertised "5-minute idle auto-logout"
  is client-side JS only.** `SESSION_TTL = 8h` (`src/webui/mod.rs`) is never refreshed and not
  idle-bounded server-side; a stolen `rb_session` cookie is honoured for the full 8 h regardless of
  the `index.html` idle timer. Closing it means a server-side sliding idle expiry, which changes
  session semantics — left Open for a maintainer decision rather than silently changing behaviour.

## Disputed (candidate refuted at source)

- **Fast-path DO-bit gate "fails toward serving a DO=0 answer" — refuted as a security finding.**
  If a non-OPT additional RR precedes the OPT, `parse_opt_rr` returns `None` and the fast path could
  serve the cached RRSIG-free payload to a DO=1 client. This is **not** a fail-open: no forged data
  is accepted as valid; the DO=1 client fails its own validation (self-inflicted SERVFAIL). It is
  also not attacker-triggerable — a real DO=1 resolver sends an OPT-only additional section and the
  attacker does not control the victim's query structure. Recorded; a full EDNS additional-section
  scan would close the cosmetic edge but is not required.

## Documentation corrections (Fixed)

- `UserAccount::generate_key` comment claimed "128 bits"; a UUIDv4 carries 122 bits of entropy
  (6 bits fixed) — comment corrected (still well beyond brute-force; key format unchanged).

---

## Verified solid (attacked, no bypass)

- **Wire parsers** — every read bounds-checked through the single `Decoder` choke point;
  decompression triple-bounded (strictly-backward pointers, `MAX_POINTERS`, `MAX_NAME_WIRE`);
  fuzzed 1.7 M exec / 0 crash.
- **Recursor** — hard budgets (`MAX_QUERIES`/`MAX_DEPTH`/`MAX_CNAME`/`MAX_MINIMISE`/timeouts);
  referrals must move strictly down-tree; qname-min widening bounded.
- **DNSSEC** — negative cache never stores Bogus; compact-denial NODATA→NXDOMAIN gated on a
  validated NSEC with `owner == qname` carrying NXNAME(128); downgrade binding qname↔zone;
  denial proofs require RRSIG-validated NSEC/NSEC3.
- **rkyv cache load** — validating `from_bytes` (not `access_unchecked`), magic-prefixed, corrupt
  file ignored (cold start).
- **Control plane** — bearer compare constant-time behind a pre-auth brake; RBAC path-keyed on the
  un-stripped URI; relay HMAC covers method+path+ts+body with a bounded anti-replay cache and TOFU
  pinning; WebUI constant-time username + always-run argon2id, CSRF double-submit, no static
  admin/admin; API binds loopback and never trusts XFF; audit-log actor folded into the per-entry
  MAC (not header-spoofable).
- **Transport gates** — `axfr-enable: no` hands the server an empty allow-list and refuses every
  transfer (the real list is never read on a disabled gate); config writer escapes injection-relevant
  fields; unescaped fields are config-file-only (no API/trust-boundary crossing).

## Validation

Build clean, `cargo clippy --release --all-targets` zero warnings, `cargo test --release`
468 passed / 0 failed (incl. the new in-bailiwick test). Performance-sensitive hot path untouched;
no re-bench required for this cycle.
