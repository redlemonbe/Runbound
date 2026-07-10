# 07 — Security

> **Status: current (0.9.3, last full sync pass: 2026-07-09)** — condensed, with code anchors; open items are listed
> at the end. Cross-references `SECURITY.md`, `THREAT_MODEL.md`,
> `docs/security-audit/SECURITY-AUDIT.md`, `docs/BUILD.md`.

- **Transport crypto.** `rustls` 0.23 (TLS 1.2 + 1.3) for DoT/DoH and the relay. DoQ
  (DNS-over-QUIC, RFC 9250) runs on `quinn` (QUIC transport) over the same `rustls`
  TLS 1.3 stack and the same request path as DoT/DoH; the listener is bound at startup
  (`src/dns/doq.rs`, wired in `src/dns/server.rs`). `quinn` is a direct dependency
  with minimal features (ring crypto, no platform-verifier).
- **Relay authentication.** HMAC-SHA256 over method + path + timestamp **+ body**
  (SEC-I14), anti-replay ±30 s (`replay_check_and_record`, `src/sync.rs:117`),
  constant-time compare (`hmac_verify_with_ts`, `src/sync.rs:145`); TOFU cert pinning.
  Only the body-covering signature is accepted (SEC-J5). Registration rejects
  loopback/link-local/ULA and (by default) RFC 1918 relay hosts —
  `sync-allow-private-relay` opts LAN deployments in (§6.3).
- **API.** Localhost-only bind; bearer token (env var preferred over config); optional
  PKCS#11 HSM storage for the API key and relay HMAC key; optional Unix socket (0600).
- **Rate limit + bans on *both* datapaths.** Per-source-IP token-bucket rate limiting
  (default 200 qps) runs through **one shared function** (`rl_should_drop()`) called from
  **both** the AF_XDP fast path and the kernel slow loop. Bans are **a shared ban set,
  enforced on each datapath** — the fast path drops banned sources with `XDP_DROP` in eBPF
  (`icmp_banned`/`icmp_banned_v6`) while the kernel slow loop checks the same set via
  `icmp_stats.is_banned()`. Both paths are driven by the same objects, so — like the
  blacklist — both routes see the same state. Both are enforced in `xdp: no` as well as in XDP. The limits are
  **live-editable**: `rps`/`burst` are read as `AtomicU64` on the hot path
  (`RateLimiter::check`/`set_limits`, `src/dns/ratelimit.rs:105`/`:95`), so a `PATCH
  /api/config` edit applies to both datapaths with no restart; a live `burst: 0` is clamped
  to ≥1 when `rps>0` so an edit cannot self-DoS the node. **Loopback is never
  rate-limited or banned** on either mechanism (`ip.is_loopback()` shortcut in
  `RateLimiter::check`, `src/dns/ratelimit.rs:112`; the ban insert refuses
  loopback/unspecified, `src/icmp.rs:118`) — local health checks and `dig @127.0.0.1`
  cannot be dropped, and a spoofed loopback cannot persist a self-ban across reboots. A
  separate per-source ICMP rate limit + flood detector bans source IPs at
  the XDP layer via `ebpf/dns_xdp.c`. Permanent ("blacklisted") bans are persisted to a
  `0600` file and reloaded at startup (capped on both write and read).
- **DNSSEC `AD`.** On the forward path Runbound does not itself validate DNSSEC. Since v0.9.3 it **relays**
  the upstream's `AD` to a client that asked for validation (its query set `AD` or `DO`), but
  **only** when the answer arrived over an authenticated **DoT** channel (`forward-tls-upstream`)
  and the upstream itself set `AD` (`authenticated = msg.header.ad() && authed_channel`,
  `src/dns/forward.rs`); a plaintext UDP/TCP answer carries a spoofable `AD` and is never
  propagated (`authenticated = false`). The bit is applied to the served copy only, **after**
  the cache has stored the AD-less base form, so DO=0 fast-path clients never receive a spurious
  `AD` (`src/dns/server.rs`). `dnssec-validation` only affects the sovereign resolver below. The wire serving path never sets `AD` on its own
  authoritative answers either (`wire_serve` clears it, `src/dns/wire_serve.rs:66`). With `resolution:
  full-recursion` (a runtime config toggle, not a Cargo feature), the sovereign in-house
  resolver (`src/dns/recursor_wire.rs`, `src/dns/dnssec_*.rs`) attaches a per-record `Proof`
  and sets `AD` only when the answer is cryptographically `Secure` **and** the query's
  own `DO` bit is set (`set_ad = val.verdict == Verdict::Secure && do_bit`,
  `src/dns/server.rs:819`) — `Bogus` is SERVFAIL'd (unless the client set `CD`), and
  insecure/unsigned or DO-less answers leave `AD` clear. Outbound DNSSEC **signing** of
  local zones is wire-native — an in-house ECDSA P-256 signer on `ring` (RFC
  6605/4034/5155/9276), validated byte-identical
  to a hickory-proto oracle in dev-only differential tests and against `delv`.
- **API auth is constant-time.** The bearer token is compared with `subtle::ConstantTimeEq`
  (no early-exit timing side-channel). The unauthenticated surface is a single `/health`
  liveness route (no version or secrets).
- **Constant-time TSIG key-name lookup.** The wire-native TSIG verifier compares the request
  key name against the configured key with `subtle::ConstantTimeEq` (`src/dns/tsig.rs:252`),
  so a signed UPDATE's key selection is not a timing oracle.
- **Forward path validates the upstream response.** A plain-UDP upstream answer is accepted
  only when its transaction ID **and** its question (name case-insensitive + type + class)
  match the query (SEC-O1, `response_matches`, `src/dns/forward.rs:335`) — a cache-poisoning defence the
  forwarder enforces.
- **Firewall integration.** `src/firewall/` manages backend rules automatically.
- **Availability under flood.** A hard inflight cap (`MAX_INFLIGHT_REQUESTS = 4096`,
  non-blocking semaphore → instant `REFUSED`, `src/dns/server.rs:72`) bounds memory even at
  line rate — a spawn-per-request handler with no backpressure would OOM under a flood.
  Per-source-IP token-bucket rate limiting
  (default 200 qps) sits in front.
- **Relay trust model (honest).** Relay auth = HMAC-SHA256 (timestamped, anti-replay ±30 s);
  TLS provides confidentiality but the client verifier does **not** validate the cert chain
  (`NoCertVerifier`, `src/api/relay.rs:35`) — identity is TOFU fingerprint pinning. Trust
  rests on the HMAC key + fingerprint, not a CA. A reviewer must confirm the TOFU
  enforcement point.
- **Supply-chain integrity (#171, #172).**
  - **Verifiable build (SBOM + checksums + signatures)** — `docs/BUILD.md`: toolchain +
    `Cargo.lock`; `SHA256SUMS` published per release. (Byte-for-byte reproducibility is not
    claimed — there is no rebuild-and-diff, no `SOURCE_DATE_EPOCH`, and the `stable`
    toolchain is not pinned to an exact version.)
  - **Signatures** — minisign signing in CI (key in `MINISIGN_SECRET`, optional
    passphrase in `MINISIGN_PASSWORD`); public key in `docs/BUILD.md`.
  - **SBOM** — CycloneDX generated by `cargo-cyclonedx` in CI, attached to each release.
- **Least privilege (PENT-3).** The service runs as a dedicated non-root
  user (`User=runbound`) with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`.
  Since `xdp: yes` is the shipped default (out-of-the-box, best performance), the default
  capability set (`AmbientCapabilities` + `CapabilityBoundingSet` in `runbound.service` /
  `install.sh`) includes `CAP_NET_RAW`/`CAP_NET_ADMIN`/`CAP_BPF`/`CAP_PERFMON` alongside
  `CAP_NET_BIND_SERVICE` by default — this doesn't enlarge the *lasting* blast radius since
  `CAP_BPF`/`CAP_PERFMON` are only checked at load time and are dropped again right after XDP
  attaches (`src/caps_drop.rs`), before the server answers a single query. The narrower
  `CAP_NET_BIND_SERVICE`-only set is available as a commented alternative for deployments that
  explicitly set `xdp: no` and `firewall-manage: no`.
- **Cycle I remediations.** The Cycle I two-AI adversarial audit
  (Claude Opus 4.8 × Gemini 2.5 Pro; full report `docs/security-audit/SECURITY-AUDIT.md`)
  closed every Open and Accepted finding. The user-visible hardening:
  relay HMAC covers the body (SEC-I14, above); **ACL enforced on the real client IP for
  TCP/DoT/DoH** before the loopback relay (SEC-I23 — closed an ACL bypass that made TCP
  clients look like 127.0.0.1); WebUI CSRF token and login username compared in constant
  time; `/api` proxy rejects `..` traversal; config serialization escapes every string
  field and config writes use `O_EXCL` + an unpredictable temp name; the nftables
  firewall rule arguments are correct (the rule installs reliably) and `ufw`
  deletes only the exact tagged rule; rate-limiter integer-overflow hardening (u128
  refill, `/0` mask); `/api/clients` aggregation memoized (2 s); per-IP domain map
  capped; both fast paths serve class IN only; kernel slow-path `sendmmsg` length clamp;
  `CPU_SET` and interface-name bounds checks. 5 adversarial findings were re-verified
  and recorded as **Disputed** (false positives) with refuting evidence, not silently
  dropped.
- **Reduced-attack-surface hardening (Cycle O + aggressive pentest — `docs/security-audit/`).**
  - **Wire-native serving path.** The default serving path is the in-house wire codec and
    does not carry a large message-parsing dependency on the network-facing path.
    `hickory-proto` is a `[dev-dependencies]`-only entry used solely by differential oracle
    tests — it is not a runtime dependency, in any configuration. Full recursion
    (`src/dns/recursor_wire.rs`) and DNSSEC validation/signing are entirely in-house and
    always compiled in (no Cargo feature gates them — there is no `recursor` or `dnssec`
    feature) — but **off by runtime default**: `UnboundConfig::defaults()` sets
    `resolution_mode: ResolutionMode::Forward` and `dnssec_validation: false`
    (`src/config/parser.rs`). Full recursion + DNSSEC validation are opt-in via config
    (`resolution: full-recursion`, `dnssec-validation: yes`), not a build flag.
  - **AXFR allow-list & split-horizon on the real client IP (PENT-1/PENT-2).** TCP/DoT/DoH
    are proxied through an internal loopback relay; the relay now carries the **real client
    IP via a PROXY v2 header** read **before** the TLS handshake for DoT/DoH
    (`src/dns/server.rs:2178` builds it — `proxy_v2_header` —, `:2208` parses it —
    `read_proxy_v2`). `axfr-allow` and split-horizon therefore evaluate the true source
    instead of `127.0.0.1` — closing a real ACL bypass.
  - **Least privilege default `CAP_NET_BIND_SERVICE`** (PENT-3, above).
  - **WebUI binds `127.0.0.1` by default** (PENT, `ui-bind` default,
    `src/config/parser.rs:560`).
  - Config-parser correctness: a `server:` directive written after an `axfr:`/`io-uring:`
    sub-block is parsed; a `tsig-key` name with a trailing dot is normalized to match the
    verifier so signed UPDATEs are not rejected with `UnknownKey`.
  - Full detail in `docs/security-audit/pentest-aggressive-2026-06-22.md` and
    `docs/security-audit/CYCLE-O-2026-06-22.md`.
- **Audit discipline.** All findings live in one `SECURITY-AUDIT.md` with strict severities
  and mixed statuses (Fixed/Accepted/Open/Disputed); re-audits use a different model/session
  (Cycle O + an aggressive pentest alongside Cycle I, a two-AI adversarial review — Claude
  Opus 4.8 × Gemini 2.5 Pro). Marketing language is banned.

## Abuse detection, tarpit & kernel bans (#ddos)

On top of the per-source token-bucket rate limit, an **abuse engine** (per-client
query-rate rules: `log` / `tarpit` / `block` / `notify`) escalates only **verified
sources** — connection transports (TCP/DoT/DoH; DoQ is connection-verified at the QUIC
layer but its abuse-engine integration is not yet wired) or
UDP carrying a valid DNS Cookie (RFC 7873). An unverified UDP source is **never**
tarpitted or banned: spoofing a victim's IP must not let an attacker get the victim
banned, nor make Runbound reflect responses toward a spoofed victim. Unverified UDP
floods are handled by the rate limiter + `BADCOOKIE`.

- **Tarpit** holds a verified abuser's request a bounded delay (then REFUSED); on
  connection transports the relay holds the connection itself, wasting the attacker's
  time at near-zero cost (capped by a semaphore to prevent self-DoS).
- **Block** is enforced at the **kernel**: the userspace detector pushes the IP to a BPF
  map and the XDP program `XDP_DROP`s its DNS before userspace — gated by a `bans_active`
  flag so an idle server pays only a single array lookup per packet (bench-verified: no
  fast-path regression). **Both IPv4 and IPv6 are dropped at the XDP layer** (`icmp_banned`
  and `icmp_banned_v6` respectively — #228 closed the earlier IPv4-only gap). The same
  rule-triggered block is **mirrored into the shared `icmp_stats` ban set**
  (`BanSource::Bot`, `src/alerts.rs:316`) — the object the shared gate consults
  (`icmp_stats.is_banned()`) — so the kernel-UDP loop (`xdp: no`) enforces it on cache hits
  too, matching the manual/relay ban paths. On connection
  transports the ban is enforced at the relay (the handler sees only the loopback relay
  address); in `xdp: no` mode the drop is enforced by the kernel-UDP loop instead.
- Rules **and the per-source rate limit** (`rate-limit` / `rate-limit-burst`) are editable
  **live** — WebUI Protection tab, `PUT /api/alerts/rules` / `PATCH /api/config` — applied to
  both datapaths without a restart, persisted
  to config and hot-applied without a restart.

## Audit trail — who did what

Every authenticated **mutating** request (config change, ban, rule edit, …) is recorded
in the tamper-evident audit log (`audit-log: yes`) as an `admin_action` event carrying the
**actor** (username), method, path and result status; the actor is inside the per-entry HMAC-SHA256
fields. The WebUI **Logs** tab surfaces this audit stream alongside the query log, with a
functional text search across both. Auth failures are recorded too.

## To expand
- Full threat model table; the audit cycles (A–I) summary; HSM setup.
