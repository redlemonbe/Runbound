# Changelog

All notable changes to Runbound are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.22.3] - 2026-06-23

### Fixed
- **#209: XDP dual-NIC throughput collapse at high domain cardinality.** `DomainStats::flush_tl`
  called `DashMap::len()` — which read-locks *every* shard — for each untracked domain key. Once the
  top-domains map is full at `MAX_TRACKED` (10 000), a large working set makes nearly every flushed
  key take that all-shard lock; with 64 XDP workers (dual-NIC) the lock storm halved aggregate
  serving. Single-NIC and ≤10 K cardinality were unaffected, which masked it behind the 0.22.2
  `inc_wire` sampling fix until the dual-card 100 K bench. `len()` is replaced by an approximate
  `entries: AtomicUsize` maintained on insert (a cheap relaxed load); top-N tracking is unchanged
  (the `Entry` API bumps the counter only on a genuine insert). Measured on an X710 + X520 dual-link
  receiver with a 100 K-name working set: **12.4M → 21.1M pps** (both links back at line rate),
  matching the ≤10 K and pre-de-hickory (v0.19.3, 20.3M) numbers.

## [0.22.2] - 2026-06-23

### Fixed
- **#165 reintroduced: resolver cache capped at ~10 000 entries regardless of RAM.** The cache
  cap (`cache_max_entries`) was wired to `xdp-cache-snapshot-size` (default 10 000) at the
  `run_dns_server` call site, while `cache-size` was parsed into the "accepted but unused" bucket
  and the RAM-scaled `cache_size_from_meminfo()` value was computed, logged, then discarded. With
  long cache TTLs (nothing to evict) the cache plateaued at 10 000 entries on any host — even with
  512 GiB of RAM. Now `cache_max_entries` is the RAM-scaled ceiling (or an explicit `cache-size`
  when set), fully decoupled from `xdp-cache-snapshot-size`; `cache-size` is honoured.
- **XDP throughput collapse at high domain cardinality (regression introduced in 0.22.1).** The
  per-hit top-domains attribution added in 0.22.1 (`domain_stats::inc_wire`) flushed the shared
  top-domains map on the XDP cache hot path; at a large working set the shard-lock contention on
  flush crushed throughput ~26× (≈11.1M → ≈0.42M pps at 100 K unique names; invisible at 8 K).
  `inc_wire` now **samples 1/32 of hits and weights the count by 32** (statistically unbiased
  top-N), so the hot path pays only a thread-local counter bump on the other 31/32. Throughput at
  100 K recovers to the 8 K level. qtype attribution (256-slot thread-local array, no shared map)
  is unchanged.

## [0.22.1] - 2026-06-23

### Fixed
- **RA flag missing on local-zone / blacklist / split-horizon responses.** The wire local
  serving path (`wire_serve::answer_local`) set `RA=0` on every blocked or local answer (feed
  `refuse`→REFUSED, `nxdomain`→NXDOMAIN, block-page, and split-horizon views), while the forward
  path and the XDP fast-path builders set `RA=1`. A recursive/forwarding resolver must advertise
  recursion-available consistently: without it, `dig` warned "recursion requested but not
  available", and a client could treat the resolver as non-recursive and retry a blocked name on a
  secondary resolver, bypassing the block. `answer_local` now sets `RA=1`, matching the rest of the
  serving paths.
- **Observability blind to the XDP fast path (stats under-counted in `xdp: yes`).** The XDP
  cache-hit hot path intentionally skipped all per-query stats, counting only `XDP_WORKER_PKTS`.
  In `xdp: yes` this left `total_queries`, `cache_hits/misses`, `cache_hit_rate`, `qtype_stats`
  and `top-domains` blind to fast-path cache hits (e.g. `total` showed slow-path/fallback traffic
  only; a cache-friendly hot domain was under-counted). Latent because production ran `xdp: no`.
  Fixed:
  - `total_queries` now adds the per-worker XDP hits (same sum `qps_update_loop` already used).
  - `cache_hits`/`cache_misses`/`cache_hit_rate` are **summed across both datapaths** instead of
    switching to XDP-only when XDP is active; raw `cache_hits`/`cache_misses` are now exposed in
    `/api/stats`, and `xdp_cache_hits`/`xdp_cache_misses` plus the in-kernel
    `xdp_kernel_snapshot_*` counters in `/api/system`.
  - `qtype_stats` and `top-domains` now include XDP fast-path cache hits, attributed on the hot
    path via **contention-free, allocation-free thread-local accumulators** (no shared atomic — the
    pattern that caused the v0.9.9 regression — and `inc_wire` decodes the wire QNAME into a reused
    buffer, allocating only when a domain is first seen).
- **OpenMetrics mislabelled / XDP-only.** `runbound_cache_hits_total` reported XDP-worker hits only
  when XDP was active (ignoring the slow path); `runbound_xdp_cache_hits_total` reported the
  in-kernel eBPF snapshot (0 in AF_XDP copy mode) so it read 0 even while the workers served the
  bulk of traffic. Now `runbound_cache_hits_total` is the true cross-datapath total,
  `runbound_xdp_cache_hits_total` is the XDP fast-path (per-worker) hits, and the in-kernel snapshot
  is exposed separately as `runbound_xdp_kernel_snapshot_{hits,misses}_total`.

### Changed
- **Huge pages now work under the unprivileged `runbound` user.** Reserving the 2 MiB pool needs
  root, but consuming it (`mmap(MAP_HUGETLB)`) needs no privilege. The unit now reserves the pool at
  boot via `ExecStartPre=+` (full privileges, outside the sandbox) driven by `RUNBOUND_HUGEPAGES_2M`
  (default `0`; set per worker `ceil(UMEM/2MiB)` for `xdp: yes`), so the daemon no longer needs to
  run as root or hold `CAP_SYS_ADMIN` to get huge pages. The fallback warning now points to this
  knob instead of "run as root".

## [0.22.0] - 2026-06-23

Major release: the default build now serves DNS **entirely on an in-house wire codec** — the
hickory-dns request handler is removed from the default binary (the sovereign full-recursion
resolver stays available behind the `recursor` feature). Every serving path was reimplemented
wire-native and validated against hickory as a differential oracle.

### Changed
- **De-hickory: in-house DNS wire codec on the default serving path.** Forward/local-zone
  resolution, split-horizon, DNS cookies (RFC 7873), and the CHAOS/ANY/HTTPS rejections are served
  by `serve_wire` with no hickory handler. `cargo tree -i hickory-server` is empty for the default
  build.
- **In-house DNSSEC signing crypto** (ECDSA P-256 on `ring`, RFC 6605/4034/5155/9276) replacing
  hickory's signer — proven byte-identical to hickory by differential oracles and `delv`-validated
  (positive, SOA, CNAME chains, NSEC3 NXDOMAIN/NODATA all "fully validated").
- **AXFR/IXFR (#22), TSIG (RFC 8945) and DNS UPDATE / DDNS (RFC 2136)** reimplemented wire-native;
  the TSIG verifier runs on `ring` HMAC and is oracle-checked against hickory, DDNS validated with
  the BIND `nsupdate` client.
- **Default Linux capabilities reduced to `CAP_NET_BIND_SERVICE`** in `runbound.service` /
  `install.sh`; the XDP and firewall-manage capabilities (`NET_RAW`/`NET_ADMIN`/`BPF`/`PERFMON`) are
  now an explicit, commented opt-in (PENT-3).
- **WebUI binds `127.0.0.1` by default** — exposing the admin panel on the network now requires an
  explicit `ui-bind: 0.0.0.0` (PENT-4).

### Added
- **Wire serving path feature parity** (these lived only in the now-default-disabled hickory
  handler and were silently inactive in the shipped binary): query logging → `GET /api/logs`,
  serve-stale (#108, RFC 8767), resolv.conf emergency fallback (#94), per-upstream racing-win
  metric (#33), and top-domains slow-path counting (#5). All proven live.

### Security
Aggressive two-AI pentest (Claude Opus 4.8 live attacks × Gemini source pass) on a live install,
plus a prior Cycle O audit. See `docs/security-audit/`.
- **PENT-1 (HIGH) — AXFR allow-list bypass fixed.** Zone transfers are TCP (and DoT/DoH), proxied
  through a loopback relay, so the handler saw `127.0.0.1` and the `axfr-allow` list matched
  everyone (or no one). The relay now carries the **real client IP via a PROXY v2 header** to every
  loopback listener (plain TCP, and DoT/DoH before the TLS handshake), so `axfr-allow` and
  split-horizon evaluate the true source. Re-tested: external transfer `REFUSED`, loopback served.
- **PENT-2 (MEDIUM) — split-horizon now sees the real client IP** on TCP, DoT and DoH (same fix);
  proven with a per-subnet view over UDP/DoT/DoH.
- **PENT-5 (LOW) — TSIG key-name lookup is constant-time** (`subtle::ConstantTimeEq`, no early-exit
  timing oracle).
- **SEC-O1 (HIGH) — forward cache-poisoning fixed:** the de-hickory UDP forwarder now validates the
  upstream response transaction-ID and question before accepting it.
- Plus PENT-3 / PENT-4 hardening (see Changed). Negative space confirmed robust: 2091 hostile
  packets caused 0 crashes; no log injection, blacklist bypass, path traversal, secret leak,
  command injection, or config-write RCE; rate-limit and per-IP TCP cap enforced.

### Fixed
- **TSIG key name with a trailing dot** (`tsig-key: "name." …`) silently failed every signed UPDATE
  with `UnknownKey`; the handler now normalizes the stored name to match the verifier (VAL-1).
- **Config `axfr:` / `io-uring:` sub-blocks** no longer swallow the `server:` directives written
  after them (e.g. `api-port`, `ui-enabled`) — they were misattributed to the sub-block section and
  dropped (VAL-2).
- **`RLIMIT_NOFILE` self-raised at startup** so a forward burst (one socket per query) never hits
  `EMFILE` regardless of the launcher's limit.
- Dead-code cleanup: 0 dead-code/unused warnings in both the default and `recursor` builds.

### Tests
- `cargo test --release --bin runbound` → **413 passed / 0 failed**; default and `recursor` builds
  both compile; 4 cross targets (x86_64/aarch64 × gnu/musl) build.

## [0.21.1] - 2026-06-20

### Fixed
- **Metrics correctness on the sovereign full-recursion path.** The `resolution: full-recursion` resolver now counts forwarded queries and response rcodes (`nxdomain` / `servfail` / `refused`), and `/api/metrics` reads cache hit-rate, hits and misses from one consistent source. On a full-recursion forwarder these were stuck at 0 / mutually inconsistent. Thanks to cschanhniem (Lumi AI Workspace) for the observability work that surfaced this (#208).

### Security
Two-AI Cycle N audit (Claude Opus 4.8 × Gemini 2.5 Pro) plus a live pentest. All fixes are in the slow-path API / sync / config layers; the packet hot path is unchanged. See `docs/security-audit/SECURITY-AUDIT.md`.
- **SEC-N1 (HIGH) — backup endpoints admin-gated.** `GET /api/backup/export` no longer exposes the config and secret state files (master API key, relay HMAC key, WebUI CA private key) to a non-admin key; all backup handlers now require admin (a no-op in single-user mode).
- **SEC-N2 (HIGH) — per-user zone scope enforced on DNS writes.** `add_dns_handler` / `delete_dns_handler` now enforce each user's `zone_prefixes`, so a non-admin Dns/Operator role can no longer write outside its zone.
- **SEC-N10 / NEW-N1 (live pentest) — RBAC `may_write` checks the original un-stripped path.** axum nest-prefix stripping had broken non-admin write roles (fail-closed regression); `may_write` now evaluates the original path, restoring legitimate non-admin write roles while keeping the gate closed.
- **SEC-N3 — protected-IP ban allowlist** so the abuse engine cannot ban an infrastructure address.
- **SEC-N4 / SEC-N5 — relay/register hardening.** Request bodies are size-capped before buffering, and HMAC requests carry an anti-replay nonce cache.
- **SEC-N6 / SEC-N7 (defence-in-depth) — config-writer field escaping, webhook SSRF re-check of resolved IPs, and explicit admin gates on rotate-key and relay-forward.**

### Docs
- Document `GET /api/tls/ca` (download the Runbound Local CA) in the API reference.
- Publish the Cycle N two-AI audit + live pentest in `docs/security-audit/SECURITY-AUDIT.md`.

### Credits
- Thanks to **cschanhniem (Lumi AI Workspace)** for issue #208 (OpenMetrics `/api/metrics`).

## [0.21.0] - 2026-06-19

### Added
- **DDoS abuse engine — verified-source tarpit & kernel bans.** Per-client query-rate rules now support `tarpit` (hold a verified abuser then REFUSED, near-zero cost to the server) and `block` in addition to `log`/`notify`. **Escalation (tarpit/block) applies only to verified sources** — TCP/DoT/DoH/DoQ or UDP carrying a valid DNS cookie — so a spoofed UDP source can never get a victim banned. Bans are dropped at the **kernel**: a `bans_active`-gated eBPF check `XDP_DROP`s a banned IP's DNS on the fast path (one array lookup when idle, bench-verified no fast-path regression), and the public→loopback relay enforces verdicts on the real client IP for TCP/DoT/DoH. New `abuse-tarpit-delay-ms` / `abuse-tarpit-max-conns` knobs; recommended base rules ship in the example configs and a one-click **Load recommended** button in the WebUI Protection tab.
- **Edit alert rules from the WebUI/API.** `PUT /api/alerts/rules` (admin) replaces the rule set, validated, persisted to config and hot-applied with no restart; an editor in the WebUI Protection tab (add/remove, action incl. tarpit, thresholds).
- **Actor-attributed audit — who did what.** Every authenticated mutating API/WebUI request is recorded as an `admin_action` event (actor, method, path, status) in the HMAC-chained audit log. The WebUI **Logs** tab surfaces this "Admin & config audit" stream and adds a **functional search** across the query log, the audit log and the auth activity.
- **Download the local CA + trust encrypted DNS.** A WebUI/API self-signed certificate is now signed by the **Runbound Local CA**; `GET /api/tls/ca` (and a WebUI button) exports it to import once into a browser/OS trust store so Firefox/Chrome accept DoT/DoH. The generated chain passes strict X.509 validation (Authority Key Identifier, KeyUsage, ExtendedKeyUsage).
- **Prometheus `/metrics` completed (#208).** Added ICMP-gate counters, banned/tarpitted-IP gauges, `tcp_connections_active` (listener saturation), and per-record-type/upstream families — 35 metric families for operator observability.
- **Firewall manages the encrypted-DNS ports.** When `firewall-manage` is on, DoT/DoH/DoQ ports open at startup and re-sync live as encrypted DNS is enabled/disabled/re-ported.
- **Public encrypted resolver — DDR auto-discovery (#204).** `ddr: yes` publishes DDR (RFC 9462) SVCB records at `_dns.resolver.arpa` advertising the node's DoT/DoH/DoQ endpoints (alpn + port + dohpath), so plain-DNS clients auto-upgrade to encrypted. New deployment guide `docs/public-resolver.md` (Let's Encrypt cert, ports/firewall, mTLS-vs-open access profiles, anycast).
- **Anti-amplification for public exposure (#203).** `dns-cookies` requires DNS Cookies (RFC 7873) on the UDP slow path — unverified clients get BADCOOKIE + a server cookie and must retry, defeating spoofed-source amplification (legacy cookie-less clients stay answered). `rrl-slip` adds RRL slip: leak 1-in-N over-rate UDP queries and silently drop the rest. `ANY` is already refused (RFC 8482, #180).
- **Anycast readiness (#21).** `/health` returns **503** when degraded (configurable `health-servfail-threshold` / `health-latency-threshold` / `health-min-qps`) so an external BGP daemon withdraws the route; `node-id` surfaces in `/health`, the `runbound_node_info` metric and logs; `drain-timeout` keeps serving briefly after SIGTERM; `proxy-protocol` accepts PROXY protocol v2 on TCP/DoT/DoH so the real client IP behind an L4 load balancer drives ACL/rate-limit/logging.
- **Encrypted DNS applies live — no restart.** Enabling, disabling, re-keying or re-porting DoT/DoH/DoQ from the WebUI/API now (re)binds the listeners on a dedicated supervised ServerFuture; the plain UDP/TCP `:53` path is never interrupted (bench-verified: 0 lost queries across enable/rekey/disable). `restart_required` is now always `false`.
- **WebUI: dedicated Account tab.** Per-user settings (change password, session info, recent auth events) moved out of Settings into their own tab; centred tabs unified to a consistent width.
- **White-label branding via a dedicated `branding.conf` file (#25).** Set `branding: yes` in the main config and Runbound loads `branding.conf` from the same directory: `brand-name`, `accent-color`, `logo-url`, `favicon-url`, plus About-tab fields `about-org`, `about-text`, `about-support-url`. Branding is WebUI-only and has **no REST API impact**. Example in `examples/branding.conf`.

### Fixed
- **DNS-over-HTTPS GET now works.** The embedded hickory HTTPS listener rejected every RFC 8484 **GET** request (it required a `Content-Type` that a bodyless GET cannot have), so DoH was unusable from Firefox/Chrome. Runbound now serves DoH from its own RFC 8484 h2 handler (GET `?dns=` + POST `application/dns-message`) behind the same ACL/conn-cap/PROXY relay.
- **Config parser:** a `#` inside a double-quoted value is no longer treated as a comment, so hex colours such as `accent-color: "#22d3ee"` survive parsing (#25).

### Security
- **SEC-M1 (HIGH) — config-directive injection via alert rules, fixed.** The alert-rule writer emitted string fields (notably `notify-url`) unescaped; a malicious admin-reachable value with an embedded newline could inject a separate config directive (the SEC-J1 class → command-running hook → RCE). Fixed by escaping all alert string fields and validating `notify-url`. Found and verified closed by the Cycle M two-AI audit + live pentest (Claude Opus 4.8 × Gemini 2.5 Pro) — no other exploitable finding. See `docs/security-audit/SECURITY-AUDIT.md`.

## [0.20.0] - 2026-06-18

### Added
- **Authoritative DNSSEC signing of local zones (#201).** `local-zone-dnssec: yes` makes Runbound an online signer for its `local-zone`/`local-data`: per-zone KSK+ZSK (ECDSAP256SHA256) auto-generated and persisted (0600), answers carry RRSIGs, NXDOMAIN/NODATA proven with NSEC3 (RFC 5155/9276 — SHA-1, 0 iterations, empty salt, closest-encloser), apex DNSKEY/SOA synthesised, and the DS surfaced via `GET /api/dnssec/ds` to publish at the parent. CNAME chains are signed end-to-end. HA: the master replicates zone keys to slaves over the encrypted relay (model B) so both nodes serve answers validatable against the same DS.
- **Sovereign full-recursion (#202).** `resolution: full-recursion` switches cache-miss resolution from forwarding to an in-tree iterative-from-root recursor (opt-in; `forward` stays default). DNSSEC validated and enforced (Bogus → SERVFAIL, AD bit, RFC 4035 §3.2.1 strip), anti-SSRF server filters (loopback / RFC 1918 / 169.254 metadata / ULA, on glue + CNAME + NS), QNAME minimisation, 0x20, serve-stale (RFC 8767). Toggle live via `PUT /api/resolution`.
- **Encrypted DNS (DoT / DoH / DoQ) from the WebUI.** A Settings panel + `/api/tls/*` endpoints enable DNS-over-TLS (853), DNS-over-HTTPS (443) and DNS-over-QUIC (853/udp) by generating a self-signed certificate or importing your own (validated against rustls). Private keys written 0600 atomically. Activation requires a restart.

### Security
- **Cycle L two-model audit (Claude Opus 4.8 — 3 adversarial agents — × Gemini 2.5 Pro) + live pentest** — see `docs/security-audit/SECURITY-AUDIT.md`. 0 CRITICAL. **SEC-L0 (HIGH, fixed):** a `TcpConnTracker` DashMap self-deadlock let the first inbound DNS-over-TCP / DoT / DoH connection from any tracked client freeze all subsequent TCP/DoT/DoH accepts — a remote, unauthenticated DoS reachable with one connection; fixed by scoping the shard guard before `remove_if`. **MEDIUM (fixed):** per-query signer reconstruction → cached per-zone signer (SEC-L1); unsigned-denial downgrade now fails closed to SERVFAIL (SEC-L2); DoT private-key TOCTOU/world-readable → atomic 0600 write (SEC-L3); DNSSEC-toggle recursor desync → rebuilt on toggle (SEC-L4). **LOW/INFO (fixed):** RRSIG inception skew (L5), recursion time-fuse (L6), CNAME-chain signing (L7), `/api/dnssec/ds` no longer generates keys on a read (L9), `/api/tls/*` admin guard (L10), `import_key` filename guard (L11). SEC-L12 (coarse rate-limiter) accepted; OPEN-L1 (per-answer RRSIG/NSEC3 cache) open. Two Gemini findings (path traversal, NSEC3 empty-salt) disputed-down at the code. Live pentest: no exploitable finding.

### Notes
- The XDP/eBPF/kernel-UDP datapath is byte-identical to v0.19.3; the X710 bench reproduces the published fast path (~13.6 M qps, 0 NIC drops) and slow path (~3.7 M qps, 19% CPU). All new code is off the packet hot path.


## [0.19.3] - 2026-06-14

### Fixed
- **Cluster view: slave XDP status now reported truthfully.** The slave relay `/system`
  endpoint (served on the sync port, a deliberately reduced payload distinct from the
  main `/api/system`) hardcoded `xdp_active: false` / `xdp_mode: "disabled"`. A slave
  actually running the XDP fast path therefore showed a wrong XDP badge in the master
  WebUI cluster view. The XDP attach mode is now published to a single global source of
  truth (`XDP_MODE`) at the same instant the API state is updated, and both the API and
  the relay handler read it — so master and slave can never disagree. The change under
  `src/dns/` is additive and read-only (the `XDP_MODE` global + two status accessors); the
  packet hot path (socket/ring/recv/tx) is byte-identical.

### Security
- **Cycle K two-AI audit (Claude Opus 4.8 × Gemini 2.5 Pro) of the anycast feature** —
  see `docs/security-audit/SECURITY-AUDIT.md`. **SEC-K1 (LOW, fixed):** the operator
  `exabgp-path` is now validated (no whitespace / shell metacharacters, must resolve to an
  existing regular file) before it is spawned — defence-in-depth (the value is config-file
  only, with no API setter, so it never crossed a privilege boundary; Gemini's HIGH "RCE"
  rating was disputed down to LOW because `Command::new` does no shell or argument splitting).
  A live pentest confirms the exabgp-config injection guard and the new path check both fail
  closed (anycast is disabled and the DNS server keeps serving). SEC-K2 (writer escaping) is
  accepted as currently unreachable; OPEN-K1 (readiness-based BGP withdrawal) is filed as a
  future enhancement.


## [0.19.2] - 2026-06-14

### Fixed
- **WebUI cluster view — slave anycast state.** The master fetches each slave's status over the relay, whose sync-port `/system` handler returned a fixed field subset that omitted `anycast`, so the WebUI **System** tab showed a slave's anycast as `—` even while it was announcing. The relay `/system` response now includes the `anycast` object (matching `/api/system`); the master's cluster view shows each slave's announced/withdrawn state. (Found while validating the v0.19.1 anycast deployment on the live master/slave pair.)

## [0.19.1] - 2026-06-14

### Fixed
- **Anycast under a privilege-dropped deployment.** The generated exabgp config was written to `/run/runbound-anycast.conf`, which a `User=runbound` (non-root) systemd service cannot write — so the `anycast:` block failed with `Permission denied` on the standard production setup (it worked only when Runbound ran as root, as in the v0.19.0 lab validation). The config now lives in Runbound's runtime base directory (`base_dir()`, writable by the runbound user) and exabgp spawns correctly. Found and fixed on a live production node.
  - On Debian, `exabgp` installs to `/usr/sbin` — off the `runbound` user's `PATH`. Set `exabgp-path: /usr/sbin/exabgp` in the `anycast:` block (the directive already existed; documented in `docs/anycast.md` / `docs/configuration.md`).

## [0.19.0] - 2026-06-14

### Added
- **Anycast deployment — one VIP served from many nodes over BGP.** A new `anycast:` config block turns Runbound into a turnkey anycast node: it renders the exabgp config, supervises exabgp as a child, announces the VIP `/32` while serving, and withdraws it on shutdown (the supervising cgroup reaps exabgp on a hard death — run under systemd). **No datapath change** — the XDP fast path already reflects the query's destination IP, and the slow path sources replies from the bound VIP (so anycast is additive; a missing/invalid block keeps DNS serving). `/api/system` now exposes the node's anycast state, and the WebUI **System** tab shows it per node (master + each slave via the relay). Full guide and bench validation in `docs/anycast.md`.
  - Bench-validated end-to-end with **real BGP** (FRR ECMP router + two Runbound nodes): announce, ECMP split across nodes, graceful **and** hard-kill withdrawal — **0 client failures** in every case.
  - Anycast string fields (`address`/`peer`/`local-address`/`router-id`) are restricted to IPv4/IPv6/CIDR characters to prevent exabgp config injection (an injected `process { run … }` block would be root RCE).

### Notes
- The DNS datapath is **byte-identical to 0.18.1** (no files changed under `src/dns/`). Re-verified on the X710 rig: fast path **~10.1 M qps** (0 NIC drops, ~13 % CPU), slow path **~3.6 M qps** — within DVFS run-to-run noise of the 0.18.1 figures. **286 tests pass, clippy `-D warnings` clean.**

## [0.18.1] - 2026-06-13

### Security
- **Cycle J two-AI security audit + pentest remediation** (Claude Opus 4.8 × Gemini 2.5 Pro; full report in `docs/security-audit/SECURITY-AUDIT.md`). All fixes are outside the slow/fast DNS datapath; verified with 282 tests, clippy `-D warnings` clean, and an A/B bench (fastpath 11.16M qps, slowpath unchanged — datapath byte-identical).
  - **SEC-J1 (HIGH)** — config-directive injection via the split-horizon API. The config writer now escapes `name`/`subnet`/`local-data`, and the API rejects control/newline characters. Closes an authenticated-API → root escalation (an injected `ui-acme-hook` would run as root on the next ACME challenge). (#191)
  - **SEC-J2** — the WebUI no longer falls back to `admin`/`admin`; a random one-time password is generated, logged once, and persisted. (#192)
  - **SEC-J3** — upstream health probes use a random DNS transaction ID, verified in the reply (off-path spoofing). (#193)
  - **SEC-J5** — the legacy header-only HMAC relay signature (request body not covered) is no longer accepted; only the body-covering signature verifies.
  - **SEC-J7** — TLS private keys are written atomically (mode 0600 from creation), closing a brief world-readable window.
  - **SEC-J13** — the optional API Unix socket is unlinked only if the path is actually a socket (TOCTOU).
  - **SEC-J14** — `add_upstream` dedups on (addr, port, protocol) and is capped.

## [0.18.0] - 2026-06-13

### Added
- **Fast path: automatic UMEM fallback to regular pages.** When the hugepage-backed
  `XDP_UMEM_REG` fails (observed on i40e/X710 + kernel 6.12: `ENOMEM` even with 2 MiB
  hugepages free), the worker retries the UMEM on regular pages for all queues instead of
  disabling the fast path. The fast path now comes up at full speed out-of-the-box with the
  default `xdp-hugepages: yes` (measured 11.2 Mqps on the X710, generator-bound).
- **Slow path: flow-independent serving spread.** The `SO_REUSEPORT` cBPF now returns
  `SKF_AD_RANDOM` instead of `SKF_AD_CPU`, so datagrams fan out across all serving sockets
  regardless of how many source flows the traffic has — no RPS required (RPS collapses on
  i40e). The kernel-UDP slow path serves cache hits across the NIC node's physical cores.
- **Process-wide physical-core affinity (never HyperThread).** Every Runbound thread —
  kloop, AF_XDP workers, the tokio control-plane/fallback runtime, the API/UI runtimes — is
  confined to physical cores. The hand-written SIMD/ASM wire path saturates a physical core's
  execution units, so a thread on the SMT sibling steals throughput instead of adding it.
- **Cache auto-sizing scales with RAM.** The resolver cache is sized to ~1/4 of available
  memory (cgroup-aware), capped at ~32 GiB, instead of a fixed 65 536-entry (~32 MiB) cap.
  It is a ceiling, not an upfront allocation; the existing memory-pressure watermarks shrink
  it dynamically, so growth stays OOM-safe.

### Changed
- **Slow-path NIC auto-tune** disables the i40e/ixgbe flow-director ATR (`ntuple off` +
  `flow-director-atr off`): ATR re-steers flows to the queue the app last transmitted from and
  fights any softirq spread (measured 16.8M → 152k softnet drops/s when disabled). IRQs are
  pinned to the NIC node's physical cores; the RPS step was removed (it collapses on i40e).

### Fixed
- Slow-path queue-cap: `SCHANNELS` now reuses the `GET`-ed channel struct (preserving
  `other_count`), so the i40e accepts the combined-queue reduction instead of staying at its
  default.
- Slow-path: the cache snapshot is loaded once per `recvmmsg` batch instead of once per
  datagram, removing per-packet ArcSwap refcount contention on the serving cores.
- WebUI: the "Auth events" notice no longer hard-codes port 8091 — it shows the actual
  listener port. (Default UI port stays 8090; the UI's API calls were already relative.)

## [0.17.2] - 2026-06-11

### Fixed
- `/api/audit/tail` now resolves the configured `audit-log-path` (it previously always read `<base_dir>/audit.log`, so the endpoint returned 404 when a custom audit-log path was configured). Found during the Cycle I QA.

### Added
- `uninstall.sh` convenience wrapper around `install.sh --uninstall` / `--purge`.

## [0.17.1] - 2026-06-11

### Security
Cycle I two-AI audit (Claude Opus 4.8 x Gemini 2.5 Pro) remediation — every Open and Accepted finding fixed (full report: docs/security-audit/SECURITY-AUDIT.md):
- **Relay HMAC now covers the request body** (SEC-I14), not just method/path/timestamp. Backward-compatible: a v0.17.1 node also accepts the legacy header-only signature during a rolling upgrade. **Deploy note: the relay is fully functional only once BOTH master and slave are >= v0.17.1.**
- **ACL enforced on the real client IP for TCP/DoT/DoH** before the loopback relay (SEC-I23) — closes an ACL bypass that let TCP clients be seen as 127.0.0.1.
- WebUI CSRF token + login username compared in constant time; `/api` proxy rejects `..` path traversal.
- Config serialization escapes every string field; config writes use `O_EXCL` + an unpredictable temp name.
- Firewall: nftables rule arguments fixed (the rule previously never installed); `ufw` deletes only the exact tagged rule.
- Rate-limiter integer-overflow hardening (u128 refill, `/0` mask); `/api/clients` aggregation memoized (2 s) to bound CPU; per-IP domain map capped; both fast paths serve class IN only; kernel slow-path `sendmmsg` length clamp; `CPU_SET` and interface-name bounds checks.

### Notes
- 5 adversarial findings were re-verified and recorded as false positives (Disputed) with refuting evidence, not silently dropped.

## [0.17.0] - 2026-06-10

### Added
- **Out-of-the-box kernel slow-path (`xdp: no`) NIC auto-tune.** On startup, when a slow-path interface is named, Runbound reads the live topology and tunes the NIC for kernel-UDP throughput: RX queue count = the NIC's NUMA-node logical-CPU count (capped), one IRQ pinned per node-local CPU (NAPI stays node-local), RPS spread across all physical serving cores, `rx-usecs 25`, and `rx-flow-hash udp4 sdfn`. It adapts to the card (which NUMA node the NIC sits on) and the CPU (node size) with no manual host tuning. **Correction ([#190](https://github.com/redlemonbe/Runbound/issues/190)):** the figure originally published here — kernel slow-path ~3.4M -> ~7.3M+ QPS (peak 8.16M) "at the i40e NAPI ceiling" — is **not reproducible on i40e**; that ~7.3M was an **ixgbe/X520** result (a different datapath). On i40e/X710 the kernel slow path is NAPI-bound and plateaus at **~1.5M served** (best ~1.59M with kloop-core isolation, [#165](https://github.com/redlemonbe/Runbound/issues/165)). The queue/IRQ retune also only runs when a NIC is named via `xdp-interface:`, so it is **not** applied out of the box. Slow-path only -- gated on `xdp: no`, so the AF_XDP fast path is byte-for-byte unchanged (re-verified 11.18M QPS on the same rig).
- **Batched `sendmmsg` TX on the kernel slow path.** Answered datagrams from a `recvmmsg` batch are flushed with a single `sendmmsg` (one syscall per batch instead of one `send_to` per datagram), cutting per-packet syscall cost on the serving cores.

### Changed
- Kernel slow-path socket receive/send buffers raised to 32 MiB, and `net.core.rmem_max`/`wmem_max` auto-raised to match (best-effort, root) so NAPI bursts are absorbed instead of dropped as `UdpRcvbufErrors`. `recvmmsg` batch size 32 -> 64.

### Notes
- The slow-path auto-tune retunes queues/IRQs only on an explicitly named interface (a channel change resets the link -- never done to an unnamed/management NIC); RPS, which is harmless on an idle NIC, is applied to detected physical NICs. NIC families with hardware flow steering (e.g. mlx5 aRFS) may prefer a different strategy; a driver-aware path is future work.

## [0.16.11] - 2026-06-10

### Added
- **Split-horizon served on the XDP fast path (#187).** Each split-horizon view is compiled into a per-view wire snapshot; the XDP worker matches the client IP to its view and serves the view's answer BEFORE the global cache, so per-source overrides win on the fast path with no cross-view leak. Views hot-swap live on API edits (no restart), reusing the exact wire serialisation of the global preload. Zero per-packet cost when no split-horizon is configured.

### Fixed
- **Split-horizon was not served at all in `xdp: yes` mode.** Queries for a view name arrived via the AF_XDP worker, which only knew the global zones — a view name under a static global zone returned NXDOMAIN (verified A/B on X710), and otherwise was forwarded upstream. The per-view fast-path snapshots (#187) fix this; verified on i40e with two views (alternating sources, no leak), global local-data, recursion, and live API edits.

### Notes
- Per-view fast-path snapshots cover A/AAAA records — the same coverage as the global local-data preload. Other record types in a view still fall through to the slow path.

## [0.16.10] - 2026-06-10

### Added
- **802.1Q VLAN support on the XDP fast path (#188).** When `rx-vlan-offload` is off, a tagged fabric (e.g. a provider private VLAN) keeps the 802.1Q tag inside the frame; the eBPF gate and the AF_XDP worker now skip a single tag to reach the inner IP/UDP, and the in-place TX reply preserves it. The untagged hot path is byte-for-byte unchanged (one extra ethertype compare per frame; no per-packet cost for untagged traffic). On NICs that strip the RX tag in hardware and refuse to disable it (e.g. bnxt), `RUNBOUND_XDP_VLAN=<vid>` re-inserts one tag on the reply.
- **Dashboard latency window selector (1m / 5m / 1h / 12h / 24h).** The Latency card shows min/avg/max over a selectable window, backed by a 24 h per-minute ring exposed at `/api/stats` -> `latency_windows`. The ring is fed only on the slow path, so the XDP fast path adds no atomic contention.

### Docs
- Benchmark report: Runbound on Threadripper PRO 5995WX + Intel X710 (i40e), XDP - peak **10.14 M qps served** (receiver NIC counters), p50 < 1 ms up to 10.56 M qps offered, no measurable NIC RX loss; lifts the X520 (PCIe 2.0) ceiling.
- Benchmark report: Latitude EPYC 9554P + Broadcom 100 G - `bnxt_en` has no AF_XDP zero-copy (errno 95); documents the limitation and rig tuning.
- `install.sh` auto-disables `systemd-resolved` so a fresh Debian/Ubuntu install takes `:53` cleanly.
- `TRADEMARK.md` added; contact emails migrated to runasm.com.

## [0.16.9] - 2026-06-09

### Fixed
- **Live cache coherency on zone writes + split-horizon hot-swap (#186).** Local-zone / blacklist / feed writes now evict the XDP cache across all seven write paths, and split-horizon views hot-swap live via `ArcSwap` with no restart.

## [0.16.8] - 2026-06-09

### Fixed
- **XDP fast path failed to load on native-XDP NICs** (e.g. vmxnet3). The hardened service unit ran without `CAP_PERFMON`, so loading the XDP/CPUMAP program returned `EACCES` even though the verifier passed. Added `CAP_PERFMON` to `AmbientCapabilities`/`CapabilityBoundingSet` (install.sh, runbound.service, docs) — the AF_XDP fast path now attaches in **DRV mode** on native-XDP NICs. The `BPF_PROG_LOAD` errno is now surfaced in the log. (#184)
- **Dashboard hid the latency `max` for values >= 2000 ms** — the webui formatter returned an em-dash for any value >= 2000 ms; it now formats >= 1000 ms as seconds, so a real 2.5 s max shows instead of nothing. (#185)
- Dashboard "Security Audit" link now points to the canonical GitHub document instead of a build-frozen embedded copy.


---

## [0.16.7] - 2026-06-08

> No server code changes — the resolver binary is functionally identical to 0.16.6 (verified: identical `.text` section, same machine code as the benchmarked build). This release packages installer hardening, CI, and documentation corrections.

### Added
- **`install.sh` integrity verification**: the downloaded binary is checked against the release `SHA256SUMS` (enforced when `sha256sum` is present) and, when `minisign` is installed, the `SHA256SUMS` signature is verified against the published key. Degrades to a warning only if the tools/assets are absent.
- **`install.sh --purge`**: full removal (service, binary, `/etc/runbound`, `/var/lib/runbound`, and the `runbound` user/group). `--uninstall` still keeps config and data.
- **`install.sh --help`** and rejection of unknown options.
- **`docs/INSTALL.md`**: end-to-end installer guide (options, integrity, file locations, env vars, port-53 handling, troubleshooting).
- **CI workflow** (`.github/workflows/ci.yml`): `cargo build --release`, `cargo clippy --all-targets -- -D warnings` and `cargo test` on every push to `main` and every pull request.

### Changed
- `cargo clippy --all-targets -- -D warnings` is now clean (annotations only; the compiled binary is byte-for-byte unchanged — no perf/behaviour impact).
- Benchmark baselines (unbound 1.22.0, BIND 9.20.23) re-measured under the documented offered-load ramp and reformatted to the report template, consolidated under `docs/benchmark/`.

### Fixed
- **`install.sh` API key** is no longer silently empty when `openssl` is absent (`/dev/urandom` fallback + hard length check).
- **`install.sh` port-53 conflict** now aborts with the exact `systemctl disable --now <svc>` command instead of failing cryptically at startup; cleaner start-failure message.
- **Docs**: removed the incorrect claim that the AF/XDP fast path requires a commercial license — it is part of the default feature set and always active in AGPL builds (dual-licensing to waive AGPL obligations is unchanged). Corrected stale version/perf references (`docs/xdp.md`, `docs/internals.md`, `SECURITY.md`, the security-audit header, the whitepaper) and backfilled the missing `0.9.61`/`0.9.62`/`0.9.63` CHANGELOG sections.
- **`test(api)`**: `health_schema` aligned with the version-less `/health` contract (0.16.5 anti-fingerprinting).

---

## [0.16.6] - 2026-06-08

### Security
- Independent second-model audit pass (Qwen3-Coder-30B, local): `load_blacklist` now caps entries on read as well as write (defense-in-depth against a tampered/oversized `ip-blacklist.json`). The other findings from the pass were cross-checked and dismissed. See `docs/security-audit/SECURITY-AUDIT.md` (Cycle H).

---

## [0.16.5] - 2026-06-08

### Security
- `/health` no longer discloses the build version (anti-fingerprinting); it keeps `status` + operational counters.
- The persistent IP blacklist (`ip-blacklist.json`) is written `0600` and capped at 100 000 entries.
- Added unit tests for the `unsafe` `recvmmsg` source-address parser (`sockaddr_to_std`): IPv4 round-trip; `AF_UNSPEC`/unknown family rejected without panic/UB.
- The slave runs `dnssec-validation: yes` to match the master (operator config), so both nodes signal `AD`.

### Changed
- WebUI tagline → **ASM-Accelerated XDP DNS Server**.

---

## [0.16.4] - 2026-06-08

### Changed
- Release profile tuned for performance: `lto = "fat"` + `codegen-units = 1` (tighter inlining, smaller binary; no `target-cpu=native`, binaries stay portable).

### Removed
- Dead-code cleanup; **zero build warnings** on all targets (x86_64/aarch64, gnu/musl).

---

## [0.16.3] - 2026-06-07

### Fixed
- **DNSSEC `AD` flag.** Forwarded answers now set the `AD` (authentic_data) flag when `dnssec-validation: yes` and the answer validates as `Secure` (hickory per-record proof); previously `AD` was never set. Signed domains return `ad`; unsigned do not.

### Added
- Persistent IP blacklist: permanent ("blacklisted") bans are saved to `<base>/ip-blacklist.json` and reloaded at startup (re-applied to the in-memory set and the XDP `icmp_banned` map).

---

## [0.16.2] - 2026-06-07

### Security
- **Rate-limit and IP bans are now enforced on the kernel slow path too (`xdp: no`).** They were applied on the AF_XDP fast path and the hickory path, but the kernel slow loop served cache hits with neither check (a single source could flood cached answers unthrottled, and banned IPs were only dropped in XDP). A shared per-source gate (`rl_should_drop` + `is_banned`) driven by the same objects now governs both routes — one mechanism, like the blacklist. Over-limit/banned sources are dropped on both paths.
- New `GET /api/protection/banned` (list) and `POST /api/protection/banned/:ip/blacklist` (permanent ban); ban/unban remain `PUT`/`DELETE /api/alerts/blocked/:ip`, all propagated to slaves via the HMAC relay.

### Added
- WebUI: banned-IP count tile in the Overview; banned-IP table in the Protection tab with per-row Blacklist + Unban buttons.

### Fixed
- Zero per-packet cost when `rate-limit: 0` (atomic short-circuit before the gate).

---

## [0.16.1] - 2026-06-07

### Performance
- Batched `recvmmsg` receive on the kernel slow loop, with `MSG_WAITFORONE` so a lone query (e.g. `dig`) is still answered immediately. One syscall drains up to 32 datagrams, reducing `UdpRcvbufErrors` under burst and the number of saturated cores for the same served rate. Escape hatch: `RUNBOUND_NO_RECVMMSG=1`.

---

## [0.16.0] - 2026-06-07

### Fixed
- **#183 — the slow path served nothing from cache.** With `upstream-racing: yes`, the per-upstream resolvers were built cache-less and the cache snapshot was built for `xdp: yes` only, so `xdp: no` forwarded **every** query (cache hit ≈ 0 %) since v0.6.12. The racing resolvers now carry a cache and the snapshot is built in both modes, so the kernel fast loop serves cache hits through the same SIMD/ASM responder as the XDP fast path.

### Performance
- Even `SO_REUSEPORT` distribution via a by-CPU `SO_ATTACH_REUSEPORT_CBPF` program (with RPS), so the kernel slow path engages all cores instead of a hashed subset.

---

## [0.15.3] - 2026-06-07

### Fixed
- **#179** — Intermittent NXDOMAIN / cache-miss query loss (~20%) under load on the
  kernel UDP fast path (xdp:no). Root cause: a fallback reply socket was bound to
  the listen port with SO_REUSEPORT but never recv()'d; the kernel reuseport hash
  therefore steered ~1/N of inbound queries to it, filling its (default-sized)
  receive buffer and silently dropping them (UdpRcvbufErrors). The fallback reader
  now replies through the per-message arrival socket (the drained per-core 8 MiB
  socket the query actually came in on; the #167 reply socket under XDP), and the
  phantom socket is no longer bound. Hot path unchanged. Verified at runtime:
  50/50 sequential NXDOMAIN answered, UdpRcvbufErrors stays 0 under burst.

## [0.15.2] — 2026-06-06

### Fixed

- **ANY queries return REFUSED** (#180) instead of NOTIMP — NOTIMP was semantically wrong (the OPCODE is implemented; only QTYPE=ANY is declined) and some clients treat it as a broken server. Amplification is still mitigated (no large answer).
- **API auth lockout without self-DoS** (#182): after 20 consecutive invalid bearer tokens the API returns `429`; a **valid** key always passes (it resets the failure counter before that branch), so a legitimate caller is never locked out.

### Added

- **`RUNBOUND_API_KEY_FILE`** (#181): the API key can be read from a 0600 file whose *path* is in the environment, so the key **value** is never exposed in `/proc/<pid>/environ`. Set `RUNBOUND_API_KEY_FILE=/path` (and drop `RUNBOUND_API_KEY=<value>`) to harden the deployment.

### Improved (not fully resolved)

- **#179 (negative-answer forwarding):** racing now short-circuits on the first **definitive** result — an answer *or* an authoritative NXDOMAIN/NODATA — instead of waiting for the slowest/stalled upstream, lowering NXDOMAIN tail latency. This is a **partial** improvement: an intermittent negative-response loss remains under cache-miss bursts and its root cause is not yet pinned. **#179 stays open.** `upstream-racing: yes` is a recommended partial mitigation.

---

## [0.15.0] — 2026-06-06

### Added

- **REST API Unix-domain socket** (#174): optional `api-socket: "/path.sock"` directive. The API also listens on a mode-`0600`, owner-only Unix socket **in addition to** the localhost TCP port — a file-permission-gated transport that avoids the bearer token travelling over localhost HTTP. The TCP listener stays active (the socket is additive). axum 0.7 `serve()` is TCP-only, so the socket is served through a small hyper-util accept loop adapting the axum `Router` via `tower::Service`.

### Security

- **Signed releases (#171).** Every release artifact (the four binaries + SBOM + `SHA256SUMS`) is now signed with minisign using a passphrase-protected key. Verify with the public key published in `docs/BUILD.md`, e.g. `minisign -Vm runbound-x86_64-linux-gnu -P <pubkey>`. Reproducible-build instructions are documented alongside it.
- **Two-AI security audit (Cycle G).** Independent + adversarial review by Claude and a local Qwen3-Coder-30B (private repo never left the LAN). No active vulnerability identified. Fixed **SEC-G1** (LOW): in `axfr.rs`, an AXFR-allow entry with a `/0` prefix computed `1u32 << 32` (panic in debug builds, fail-closed in release); `/0` now correctly matches all addresses. Full cycle in `docs/security-audit/SECURITY-AUDIT.md`.

### Documentation

- **Technical whitepaper** under `docs/whitepaper/` (ten chapters): architecture, the XDP fast path, SIMD & hand-written assembly, the slow path, caching, the control plane, security, performance methodology, and design rationale — written against the source with `file:line` references.

---

## [0.14.0] — 2026-06-06

### Added

- **Full backup & restore.** `GET /api/backup/export` downloads the **complete** state as one base64 JSON: `runbound.conf` + every store (`dns_entries`, `blacklist`, `feeds`, `upstreams`, `alert-blocks`, `icmp`, `slaves`) with their `.mac` integrity files + secrets/certs (`api.key`, `webui-auth.conf`, sync & CA keys). `POST /api/backup/import` restores it — whitelisted filenames, path-traversal-safe, atomic writes — applied on the next service restart. New **Full backup / restore** controls in the WebUI **System** tab. Admin-only; slave nodes are read-only. The backup contains secrets — store it securely.

---

## [0.13.0] — 2026-06-06

### Added

- **Split-horizon DNS configurable via API + WebUI** (#10): new `/api/split-horizon` CRUD endpoints (GET / POST / DELETE) and a WebUI tab to manage per-subnet answer zones (name, subnets, local-data). Entries are persisted to `runbound.conf` (config-writer) and applied on the next service restart — the resolver's split-horizon table is built at boot, so the slow path is untouched. Slave nodes are read-only (503).
- **XDP cache-hit-rate counter restored for `xdp: yes`**: a per-worker miss counter (`XDP_WORKER_MISS`) mirrors the existing served counter (`XDP_WORKER_PKTS` = hits). The hot-path hit branch is unchanged — only the already-slow fallback branch gains one increment — and the rate is computed in Rust off the hot path. The WebUI cache-hit rate is now meaningful in XDP mode (previously slow-path-only).

---

## [0.12.0] — 2026-06-06

### Added

- **Config persistence to `runbound.conf`** (fixes the DNSSEC-toggle-not-saved and upstreams-not-in-config bugs): WebUI/API changes to **DNSSEC validation** and **upstreams** are now written back to `runbound.conf` via a faithful full-regeneration writer. The writer is round-trip tested on every shipped example config; unmanaged/unknown directives are preserved verbatim (`raw_passthrough`); writes are atomic (render → re-parse validation gate → rename). The DNSSEC toggle now survives a restart, and upstreams live in — and are editable from — the config file. A legacy `upstreams.json` store is migrated into the config once at boot, then archived. Slow path (hickory) untouched.
- **Deep-space WebUI background** ported from the RunIA login page (navy `#080d1c` + radial gradients + three drifting orbs), applied to both the dashboard and the login page.

---

## [0.11.1] — 2026-06-06

### Added

- **WebUI latency shows min / average / max** instead of p50/p95/p99. Percentiles are dominated by upstream and DNS-path variance, so they were misleading on the dashboard; min/avg/max are the honest, readable signal. The backend now tracks exact min/avg/max in `record_latency_us`; Prometheus `/metrics` keeps the percentiles for compatibility.
- **Default-password prompt on connect** (#webui): a new authenticated endpoint `GET /api/webui/password-status` reports whether the WebUI still uses the default `admin`/`admin` credentials (argon2-verified). The dashboard shows a one-time modal nudging the operator to change them, with a shortcut to the change-password form. No-op once the password has been changed.

### Fixed

- **Cluster node aggregation for rates**: `cache_hit_rate` and `blocked_percent` used a flat mean across nodes, so a node at 0%% and one at 100%% displayed 50%%. They are now weighted by resolution volume (`total`) — idle nodes (`total=0`) are excluded and a busier node counts proportionally; for a rate this equals `Σhits / Σtotal`. Cluster latency is min/max over active nodes with a volume-weighted average.

---

## [0.11.0] — 2026-06-06

### Added

- **Automatic NIC queue scaling on the XDP fast path** (#169): before attaching XDP, runbound raises the NIC's `combined` queue count to the hardware maximum (`ETHTOOL_SCHANNELS`), capped by the physical core count and the AF_XDP / XSKMAP per-NIC budget. On a **Xeon v2 + X520** host — PCIe-bus-bound at ~16 cores — the call is a deliberate no-op (the `ixgbe` driver default is kept), because adding queues there only adds cross-core contention. On any modern CPU the workers spread across every NIC queue automatically, with no manual `ethtool -L`. CPU/NIC detection reuses `is_xeon_v2_x520_host()` (CPU family 6 / model 62 + `ixgbe`). Slow path (hickory) unchanged.

---

## [0.10.5] — 2026-06-06

### Added

- **Negative caching on the XDP fast path** (#166, RFC 2308): `NODATA` (NOERROR with no answer) and `NXDOMAIN` responses are now cached as wire answers, keyed by name + type, with a TTL derived from the SOA `MINIMUM` field (clamped to `[60, 900]` s). `SERVFAIL` is deliberately never cached — it is a transient condition. On a Tranco top-10000 real-corpus run this eliminated a **17% cache-miss rate**, dominated by repeated `NODATA` / `AAAA` lookups, bringing the steady-state miss rate down to ~0.2%.

---

## [0.10.4] — 2026-06-06

### Added

- **Self-configuring AF_XDP** — automatic rings and huge pages: the fill / completion / RX / TX ring sizes are derived from the NIC's hardware ring depth (read per-socket via a GET-only `ethtool` ioctl), and huge pages are self-provisioned at startup (2 MiB, falling back to 1 GiB, then to normal pages). No manual `xdp-*-ring-size` tuning or `nr_hugepages` setup is required for typical deployments.

---

## [0.10.3] — 2026-06-05

### Fixed

- **XDP recursion-miss replies now leave from the server port, not an ephemeral one** (#167): cache-miss queries recursed in XDP mode were answered from an ephemeral socket, so some clients rejected the reply on a source-port mismatch. Fallback answers now leave from the bound `:53` socket.
- **Loopback (`127.0.0.1`) served via the kernel slow-path listener in XDP mode** (#167b): queries to the loopback address are handled by the normal kernel listener instead of the XDP fast path, fixing local `dig @127.0.0.1` under `xdp: yes`.

### Changed

- **Unified XDP cache ↔ local-data lookup on a single ASM path**: the per-packet hot path now performs a single CRC32c + identity-hash lookup (replacing the previous `SmallVec` + `QuestionKey` + ahash chain), and per-packet cache statistics were removed from the hot path — a CPU-efficiency improvement on the fast path.

---

## [0.10.2] — 2026-06-05

### Fixed

- **XDP cache-misses now recurse instead of being silently dropped** (critical): in `xdp: yes` mode, a cache-miss for a non-local name was dropped instead of being forwarded to the recursive resolver, so the first query for any uncached name timed out. Misses now fall through to the hickory slow path concurrently, bounded by a 1024-permit semaphore. Production deployments running `xdp: no` were unaffected.
- Log hygiene on the XDP fallback path.

---

## [0.10.1] — 2026-06-04

### Fixed

- **EDNS OPT echo on every response path** (#160, RFC 6891 §7): runbound now includes an OPT RR in responses to EDNS queries on **all** response paths — local-zone static/redirect, blockpage, CNAME chains, `NXDOMAIN`/`SERVFAIL`/`REFUSED` errors, serve-stale, HTTPS suppression, and forwarded/recursive answers — not just the XDP wire fast path. A shared `make_opt_edns()` helper applies the echo (advertised UDP payload clamped to [512, 1232], DO bit reflected) at all 8 emission sites in `server.rs` plus the XDP slow-path fallback (`answer_dns`). A query **without** an OPT gets a response without OPT (unchanged). Validated on the authoritative (UDP + TCP), error, and forward paths.

### Changed

- **Per-interface XDP metrics** (#159): `XDP_ACTIVE_IFACE` / `XDP_QUEUE_MODES` and the NIC ring-size counters were process-global `OnceLock`/`Atomic`s that only ever captured the **first** interface. They are now per-interface (a registry keyed by interface name), and `/api/stats`, `/api/system`, `/api/metrics` report **all** active XDP interfaces instead of just the first. Metrics only — no data-path impact.

---

## [0.10.0] — 2026-06-04

### Added

- **Multi-interface XDP fast path** — runbound can now attach XDP to N interfaces simultaneously. `xdp-interface` accepts: a single name (unchanged), a comma-separated list (`nic2,nic3`), or `auto` (all eligible interfaces). `auto` skips loopback, virtual (`vmbr*`/`tap*`/`veth*`) and **bonded** interfaces (XDP is incompatible with bonding — WARN + skip). Absent + `xdp: yes` keeps the legacy single-interface auto-detect; `xdp: no` (pure hickory slow path) is unchanged. Each interface gets its own independent XSK sockets, workers, and eBPF program. Worker CPU-core assignment is offset per interface (distinct core block per NIC, no cross-interface collision); the performance governor is pinned across all XDP interfaces' cores and restored on SIGTERM/SIGINT.
  - Measured (2× Intel X520 10 GbE, Threadripper receiver, dnsmark generator): **~17–18M qps aggregate on dual-fibre at ~13% CPU**, near-zero NIC drops. Generator-limited — the receiver had large headroom. See `docs/benchmark/`.

### Fixed

- **Multi-interface XDP programs now stay attached for the process lifetime** (critical): non-primary `XdpHandle`s were dropped right after setup, and `XdpHandle::Drop` calls `detach()` — silently removing the 2nd+ interface's XDP program from the NIC. The interface received packets at the NIC but never redirected them to its AF_XDP sockets (workers drained 0). The full handle set is now captured by the long-lived task and never dropped while the process runs. Verified at the kernel level (`bpftool net show` shows a program on every XDP interface).
- XDP worker no longer exits silently on a transient `poll()` error — it warns and continues instead of breaking out of the loop.

### Internal

- Per-interface debug counters (`[DBG-TX]`) are gated behind the `xdp-debug-counters` cargo feature (off by default) — zero hot-path cost in release builds; rebuild with `--features "xdp xdp-debug-counters"` to re-enable.

---

## [0.9.69] — 2026-06-03

### Added

- **Incremental IPv4 header checksum (RFC 1624)** on the XDP wire-builder response path (#156): the response checksum is updated from the request's already-valid checksum (only `total_length` differs between query and reply; the src/dst address swap is checksum-neutral) instead of a full recompute over the header. `ipv4_checksum` was the #2 CPU hotspot (~20% of per-packet CPU) under `perf`; the incremental update removes it. This is a CPU-efficiency and latency improvement. On a 10 GbE link the A/AAAA answer path is RX/NIC-bound (not CPU-bound), so single-link peak throughput is unchanged — the freed headroom matters for CPU-bound or 25 GbE+ deployments. A round-trip test pins the incremental result byte-identical to the full recompute.
- **`xdp-busy-poll` config option** (default `yes`): the XDP worker drains the RX ring before sleeping (drain-first) and sets the NAPI busy-poll socket hints (`SO_PREFER_BUSY_POLL`, `SO_BUSY_POLL`, `SO_BUSY_POLL_BUDGET`), best-effort with silent fallback on older kernels. This reduces first-packet latency at low/idle load. Under saturation it is a no-op (`poll()` returns immediately when frames are queued, so drain-first and poll-first are equivalent) — peak throughput is unchanged. Set `xdp-busy-poll: no` for the legacy poll-first loop.

### Performance

- Reference benchmark (see `docs/benchmark/`): **8.83M qps** on the local-zone A answer path, measured at the receiver NIC counters on a **2013 dual Xeon E5-2690 v2** (16 RSS cores, 53% CPU) under a 10 GbE saturating flood — **~78% of the 10 GbE fibre line-rate**. The receiver is RX/NIC-buffer-bound, not CPU-bound, at this operating point.

---

## [0.9.68] — 2026-06-03

### Added

- **`xdp-cpu-governor` config option** (#158): opt-in (default off) pinning of the `performance` CPU frequency governor on the XDP worker cores at startup. The default OS governors (`schedutil`/`powersave`) under-clock the bursty DNS hot path mid-flood, adding frequency-ramp jitter; pinning `performance` stabilises per-core frequency. Enable with `xdp-cpu-governor: performance` in the `server:` block. Best-effort: WARNs and continues if the cpufreq sysfs is absent (VMs/containers) or the write is refused (no `CAP_SYS_ADMIN`); only the cores actually used by XDP workers are touched.

### Fixed

- **Governor restoration now runs on SIGTERM/SIGINT** (#158): Runbound had no terminate handler, so `systemctl stop` (SIGTERM) killed the process without unwinding the stack — a pinned `performance` governor stayed in place indefinitely after stop. A graceful SIGTERM/SIGINT handler now restores each core's original governor before exit (extracted out of the detached XDP poll task; verified on bare metal that cores return to their original governor after stop). The `Drop` restore is kept as a fallback for the clean-return path.

---

## [0.9.67] — 2026-06-03

### Added

- **EDNS OPT echo in the XDP wire fast path** (#156): the hand-rolled wire builder now parses the query OPT RR and echoes a correct OPT record (advertised UDP payload size) in local-zone A/AAAA answers, so the fast path serves real EDNS traffic instead of falling back to hickory. Queries with DO=1 (DNSSEC) still fall back to hickory.

### Changed

- **Local-zone lookup no longer allocates per packet** (#156): `LocalZoneSet` gained a wire-QNAME index (`WireRecordIndex`, CRC32c-keyed via an identity hasher) holding pre-serialised A/AAAA rdata. The A/AAAA hot path now lowercases the QNAME in place and looks up by hash, eliminating the last per-packet hickory allocations (`Name::read`, `LowerName::from`, the `Vec<&Record>` and RData dispatch). A round-trip test pins the in-place normalisation byte-identical to the load-side serialisation.

### Performance

- Controlled A/B on an X520 10 GbE link (performance governor, warm, 5-run medians): local-zone A/AAAA answer path **~6.80M → ~7.18M qps (+6%)** vs v0.9.66, p50 unchanged (~0.33ms). Note: absolute throughput is CPU-governor dependent — the v0.9.66 figures (~4.6M) were measured without the performance governor pinned; with it pinned both versions run ~7M.

---

## [0.9.66] — 2026-06-03

### Added

- **XDP wire-format response builder for local-zone A/AAAA queries** (#156): `answer_dns_wire()` parses the query and writes the response directly into the UMEM TX frame, bypassing `hickory_proto::Message` parse/serialize and all heap allocation on the answer hot path.
  - Measured on an X520 10 GbE link (controlled back-to-back A/B, 5 runs each, medians): local-zone A answer path **+21% throughput** (~3.80M → ~4.63M qps) and **−35% p50 latency** (0.52ms → 0.34ms).
  - Everything not covered — NXDOMAIN, NODATA, wildcards, CNAME/MX/TXT, EDNS, ACL Deny, ANY, malformed — transparently falls back to hickory. No behaviour change, no regression.
  - See `docs/benchmark/` and `docs/xdp.md`.

### Fixed

- **`xdp-domain-routing` (CPUMAP) no longer breaks zero-copy** (#155): enabling CPUMAP domain-routing on a zero-copy interface collapsed throughput ~40× (4.77M → 120k qps) and routed packets onto HyperThread siblings.
  - `DOMAIN_ROUTING_ENABLED` moved from a frozen `volatile const` to a runtime map flag (`domain_routing_cfg`), forced OFF once zero-copy is confirmed on a socket → the XDP program falls through to the XSK zero-copy path.
  - CPUMAP indices now map to physical cores only (`cpu::physical_cores()`), never HT siblings.
  - domain-routing remains available in SKB/copy mode (cache locality).

---

## [0.9.63] — 2026-05-27

### Added
- **Split-horizon DNS (#10).** Per-subnet zone overrides: different `local-data` answers based on source IP. Config via `split-horizon:` blocks with `subnet:` and `local-data:` directives; queries from a matching subnet check the override zone before the global zones. Multiple blocks supported, first matching subnet wins. (Later exposed via the `/api/split-horizon` CRUD endpoints and a WebUI tab in v0.13.0.)

---

## [0.9.62] — 2026-05-27

### Added
- **RBAC (#13).** API-key roles `read` / `dns` / `operator` / `admin`, configured through `api-key-extra` config blocks, so a key can be scoped to read-only, DNS-only, operational or full-admin access.

---

## [0.9.61] — 2026-05-27

### Added
- **White-label UI branding (#25).** `ui-brand-name` / `ui-brand-logo` / `ui-brand-accent` / `ui-brand-favicon` config directives, a `/webui/branding` endpoint and dynamic JS that applies the brand at load — the WebUI can be re-skinned without rebuilding.

---

## [0.9.58] — 2026-05-26

### Added

- **Webhook notifications** (#11): multi-target webhook system for system event alerts.
  - 4 formats: Slack (blocks API), Discord (embeds + color), ntfy (Priority/Tags headers), GenericJson
  - Per-target event filtering: `domain_blocked`, `slave_disconnect`, `qps_spike`, `feed_error`, `key_rotated`, `config_reloaded`, `alert_threshold`, `all`
  - Retry: 3 attempts with exponential backoff (1s, 2s); rejects private/loopback URLs
  - Config directives: `webhook-url`, `webhook-format`, `webhook-token`, `webhook-events`
  - `POST /api/webhooks/test` — fire a test notification to all configured targets
  - `config_reloaded` event auto-fires on successful config reload

---

## [0.9.57] — 2026-05-26

### Added

- **Hot backup**: `POST /api/backup` — snapshots config (`runbound.conf`) + DNS entries + blacklist + feeds + upstreams to `base_dir/backups/backup_<ts>[_label]/`. Optional `label` field for named snapshots.
- **Backup listing**: `GET /api/backup` — returns JSON array with id, timestamp, and file list.
- **Hot restore**: `POST /api/backup/restore` with `{"id": "backup_<ts>"}` — copies all snapshot files back and triggers a hot-reload of the config.
- **Backup deletion**: `DELETE /api/backup/:id` — removes a snapshot directory.

---

## [0.9.52] — 2026-05-26

### Changed

- **Multi-user zone enforcement**: DNS, blacklist, and feed handlers now enforce per-user ownership:
  - `GET /api/dns` and `GET /api/blacklist`: non-admin users see only their own entries plus admin-owned entries (backward-compat: entries with no `owner_user_id` are treated as admin-owned and visible to all).
  - `POST /api/dns` and `POST /api/blacklist`: non-admin must pass `may_manage_name` check (name must be under one of their `zone_prefixes`); entry is tagged with `owner_user_id`.
  - `DELETE /api/dns/:id` and `DELETE /api/blacklist/:id`: non-admin can only delete their own entries.
  - `POST /api/feeds` and `DELETE /api/feeds/:id`: admin-only.

---

## [0.9.51] — 2026-05-26

### Added

- **Multi-user mode**: Per-user API keys, zone ownership isolation, and user management REST API.
  - New module `src/multiuser/`: `UserAccount`, `UserRegistry` (DashMap-backed, persisted to `users.json`), `RequestUser` extension injected by auth middleware.
  - Users have `zone_prefixes` -- they can only read/write DNS entries and blacklist entries whose name falls under one of their prefixes. Admins have unrestricted access.
  - `DnsEntry`, `BlacklistEntry`, `Feed` structs carry an optional `owner_user_id` field (backward-compatible: existing data treated as admin-owned).
  - New routes: `GET /api/users`, `POST /api/users`, `DELETE /api/users/:id`, `GET /api/users/me`, `POST /api/users/:id/rotate-key`.
  - Auth middleware accepts both the master API key (admin context) and per-user keys (user context injected via axum Extension).
  - Single-user mode preserved: if `users.json` is absent, multi-user registry is not loaded and behaviour is unchanged.

---

## [0.9.50] — 2026-05-26

### Security

- **SEC-F1 fix: cap AlertTracker blocked map at 50 000 entries** (Cycle F): The blocked DashMap in AlertTracker had no size cap. Under an IP-rotation flood (many distinct source IPs triggering the bot trap), the map could grow unboundedly between the 60s eviction cycles, exhausting RAM. Added MAX_BLOCKED_ENTRIES = 50_000 constant; block_bot, block_manual, and trigger now check the cap before inserting new IPs. Existing IPs (re-bans / updates) are exempt. Excess bans are logged as WARN and silently dropped until the next eviction cycle clears space.

- **Security audit Cycle F complete**: All Cycle D pending items resolved (SEC-F1 fixed; ACC-F1 / ACC-F2 / ACC-F3 accepted after code review showed no exploitable issues). Zero open findings as of v0.9.50. See docs/security-audit/SECURITY-AUDIT.md.

---

## [0.9.46] — 2026-05-26

### Performance

- **SIMD dispatch: CPU feature detection at startup** (#152): New `SimdLevel` enum (Scalar → SSE2 → SSE4.2 → AVX2 → AVX512) detected once via `OnceLock` in `src/dns/simd.rs`. Dispatch is resolved at boot, not per-packet. No runtime branching overhead on the hot path.

- **CRC32c SSE4.2 domain hashing** (#72): `src/dns/hasher.rs` replaces the FNV-1a domain hash with hardware-accelerated CRC32c (x86 `_mm_crc32_u64`, aarch64 `__crc32cd`). Hash computation drops from ~80 ns to ~20 ns per lookup on SSE4.2-capable CPUs. Fallback to FNV-1a on older hardware.

- **SSE2 label lowercasing in XDP hot path**: `src/dns/xdp/worker.rs` lowercases QNAME labels 16 bytes/iteration using `_mm_or_si128` + bitmask instead of byte-by-byte OR. Throughput: 4× labels/cycle on SSE2; no branch inside the loop.

- **AVX2 dispatch for label lowercasing**: On Haswell+ CPUs, the QNAME lowercasing loop processes 32 bytes/iteration via `_mm256_or_si256`. Halves the instruction count vs SSE2 for labels > 16 bytes.

- **SSE2 `QuestionKey` equality**: `src/dns/hasher.rs` compares fixed-width `QuestionKey` fields with `_mm_cmpeq_epi8` + `_mm_movemask_epi8`. Replaces byte-by-byte comparison; one instruction handles 16-byte blocks.

- **Bulk SIMD QNAME parse 1-pass** (#152): `src/dns/simd.rs` fuses label-length scanning, ASCII-lowercase, and dot-separator insertion into a single SSE2 pass over the wire QNAME. Eliminates the second validation scan previously required by the hickory-server path.

- **Measured result**: loopback benchmark (cache-warm, no XDP, dev VM) → **195 358 QPS** | avg 0.149 ms | p99 0.348 ms | 99.99% completion. Up from 147k QPS (v0.9.45), **+33%** without hardware changes.

---

## [0.9.45] — 2026-05-26

### Fixed

- **ban_bot: skip loopback and RFC-1918 addresses**: `ban_bot` now checks the incoming IP before calling `is_blocked()`. Loopback (`127.x`, `::1`), RFC-1918 private ranges, link-local, and ULA (`fc00::/7`) addresses are silently skipped with a `DEBUG` log. Prevents the server from accidentally banning its own reverse-proxy or local admin.

- **burst_tracker: evict stale entries**: The 5-minute session-cleanup task now also evicts `burst_tracker` entries older than 60 s. Without this, every unique IP that triggered a bad request accumulated indefinitely in memory.

### Changed

- **Login page: autofocus on username field**: The `rb_user` input now carries the `autofocus` attribute and receives `focus()` on load. The password field no longer steals focus on page load.

### Added

- **Header clock**: A live `HH:MM:SS` clock (`id="local-clock"`) appears in the header bar between the uptime stat and the Reload button (hidden on mobile, visible ≥ `sm`).

- **Node card active border**: Active node card selection now renders a 2 px `cyan-400` border (`border-2 border-cyan-400`) instead of the previous 1 px `cyan-600`. Inactive cards use `border-2 border-transparent hover:border-cyan-900` for stable layout with no shift on selection.

---

## [0.9.44] — 2026-05-26

### Fixed

- **#148 — alert `name:` directive silently required**: Directives in an `alert:` block that appear before `name:` were silently dropped because `last_mut()` returned `None` on an empty vec. A warning is now emitted and a placeholder rule (named `alert-{lineno}`) is auto-inserted so no directives are lost. Always place `name:` first in each alert block.

- **#149 — `POST /api/reload` did not reload alert rules**: `AlertTracker.rules` was a plain `Vec<AlertRule>` with no way to update it without a restart. The field is now wrapped in `std::sync::RwLock<Vec<AlertRule>>`. A new `update_rules()` method atomically replaces the rule set. The reload handler calls it after rebuilding zones, so alert rules now take effect immediately on `POST /api/reload`. The response body includes an `"alert_rules"` count field.

- **#150 — WebUI TLS cert missing IP SAN**: The auto-generated WebUI certificate only listed `localhost` as a Subject Alternative Name. Accessing the WebUI by IP (e.g. `https://192.168.1.10:8091`) caused a TLS validation failure in all browsers. Auto-generated certs now always include `127.0.0.1` and `::1`. A new `ui-tls-san` config directive (repeatable) adds custom IPs or hostnames. Existing certs must be deleted and the service restarted to regenerate with the new SANs.

### Documentation

- `docs/configuration.md`: added `ui-tls-san` directive reference and new **WebUI TLS certificate SANs** section; added **Bot defense** section; updated alert status persistence note to mention auto-deban and bot bans; added `name:` ordering note to alert directive table.
- `docs/api.md`: updated `POST /api/reload` response example to include `"alert_rules"`; corrected the reload note to reflect that alert rules are now reloaded live; added bot defense ban note to `GET /api/alerts`.
- `docs/web-ui.md`: added **Bot Defense** section covering honeypot, scanner trap, behavioral burst, viewing bans, and configuration.
- `docs/tls.md`: added **WebUI TLS — auto-generated certificate SANs** section documenting default SANs and `ui-tls-san` usage.

---

## [0.9.43] — 2026-05-26

### Added

- **Advanced Bot Defense with Auto-Deban**:
  - **Honeypot**: WebUI login form renames real fields to `rb_user`/`rb_pass`; hidden `username`/`password` fields trap form-filling bots — ban on any honeypot field filled (requires `bot-honeypot-enabled: yes` in config).
  - **Scanner detection**: catch-all handler for 19 known scanner paths (`/wp-admin`, `/.env`, `/.git/*`, `/phpmyadmin`, `/xmlrpc.php`, `/actuator/*`, etc.) — instant ban on access.
  - **Behavioral burst**: ban after 10 failed login attempts in a 5-second sliding window (`bot-burst` rule).
  - **XDP enforcement**: bot bans inject into the eBPF `icmp_banned` BPF map (IPv4) for zero-syscall drop, same path as ICMP flood bans.
  - **Auto-deban**: background task evicts expired bans every 60s, sends `IcmpBanCmd::Unban` to XDP, and pushes `SyncOp::DeleteGlobalBan` to slaves.
  - **Cross-cluster sync**: `SyncOp::AddGlobalBan` / `SyncOp::DeleteGlobalBan` propagated to all slaves via the sync journal; slaves apply bot bans to their own XDP map.
  - **Audit trail**: all bot bans visible in `GET /api/alerts` and WebUI alert log with rule name (`bot-honeypot`, `bot-scanner`, `bot-burst`).
  - **Config**: `bot-ban-duration-secs` (default: 86400), `bot-honeypot-enabled` (default: no).

## [0.9.42] — 2026-05-25

### Added

- WebUI: new route `/webui/security-audit` — the consolidated security audit document (all cycles A/B/C) is now accessible directly from the WebUI without requiring internet access.
- WebUI: About tab — "Security Audit" link added to the Links card, opening the embedded audit document.
- `docs/api.md`: documented `PATCH /api/config` (DNSSEC toggle), `GET /api/alerts`, `PUT/DELETE /api/alerts/blocked/:ip` (manual block/unblock), and `priority`/`value`/`ttl`/`weight`/`port` fields in `POST /api/dns`.
- `docs/configuration.md`: fixed incorrect `/api/alerts/block` endpoint URL (→ `/alerts/blocked`); corrected persistence note (alert blocks survive restarts via `alert-blocks.json`, SEC-B7).

### Fixed

- `docs/api.md`: `POST /api/reload` note now lists alert rules as requiring a full restart (not just a reload).

---

## [0.9.41] — 2026-05-25

### Fixed

- `src/config/parser.rs`, `src/dns/server.rs`: new `forward-tls-hostname` directive in `forward-zone:` blocks — `build_resolver` passes the configured hostname to `dot_tls_name`, enabling custom DoT servers outside the built-in IP→hostname map (SEC-B13).
- `src/api/relay.rs`: relay outbound connections (`relay_request`, `register`) now derive TLS SNI from the peer address (`host:port` → `host`) using `ServerName::IpAddress` for IPv4/IPv6 peers and DNS name parsing for hostname peers — removes hardcoded `"runbound-relay"` (SEC-B13).
- `src/sync.rs`: `sync_get` derives TLS SNI from `host_port` — removes hardcoded `"runbound-sync"` (SEC-B13).
- `src/api/mod.rs`, `src/dns/server.rs`: test code updated — `ForwardZone` initializers include `tls_hostname: None`; `AlertTracker::new` calls pass `None` as `base_dir`.

### Added

- `docs/configuration.md`: `forward-tls-hostname` directive documented with built-in SNI map table and custom server example.

---

## [0.9.40] — 2026-05-25

### Fixed

- `src/api/relay.rs`: `push_to_slaves` now uses `pinned_client_config(fingerprint)` when a certificate fingerprint is configured for a slave — TLS certificate pinning was accepted but not applied on outbound relay calls (SEC-C1).
- `src/alerts.rs`: `AlertTracker` persists blocked IPs to `{base_dir}/alert-blocks.json` on every change and reloads on startup — alert-triggered bans now survive service restarts (SEC-B7).

### Changed

- `ebpf/dns_xdp.c`: `icmp_rl_counts` BPF map `max_entries` increased from 8192 to 65536 — eliminates map overflow under ~8 000 concurrent ICMP sources (SEC-C4).

### Added

- `src/icmp.rs`: `IcmpStats::cleanup_expired_bans(ttl_secs)` — removes stale entries from the in-memory ICMP ban table and issues corresponding XDP unban commands.
- `src/main.rs`: hourly background task calling `cleanup_expired_bans(86_400)` — ICMP bans now expire after 24 h without a service restart (SEC-C3).
- `docs/security-audit/SECURITY-AUDIT.md`: consolidated master audit document — merges all per-version reports from cycles A, B, and C into a single source of truth.

### Removed

- 17 superseded per-version audit files under `docs/security-audit/` (cycles A and B) — replaced by `SECURITY-AUDIT.md`.

---

## [0.9.39] — 2026-05-25

### Fixed

- `src/dns/hasher.rs`: removed redundant `unsafe {}` blocks inside `unsafe fn crc32c_sse42` and `unsafe fn crc32c_arm` — an `unsafe fn` body is already an unsafe context; inner blocks were noise without effect.
- `src/api/mod.rs`: Unicode bidirectional control characters (U+202A–U+202E, U+2066–U+2069, U+200F, U+061C) now rejected in `validate_no_control_chars` — prevents homoglyph domain injection (SEC-B16).
- `src/webui/mod.rs`: background task evicts expired WebUI sessions from the session DashMap every 5 minutes — unbounded session accumulation fixed (SEC-B10).
- `src/api/relay.rs` (`sync.rs`): relay ban handler calls both `icmp_stats.ban()` (DashMap) and `ban_cmd_tx.send()` (XDP) — ban was previously recorded in-memory but not enforced at the XDP layer (SEC-C2).

### Added

- `src/dns/hasher.rs`: CRC32c hardware-accelerated domain hasher — SSE4.2 on x86_64, ARM CRC extension on aarch64, FNV-1a software fallback. Runtime-detected via `HAS_HW_CRC32C: AtomicBool`. Wired at startup via `dns::hasher::init()` (PERF-C1).
- `src/main.rs`: `dns::hasher::init()` call at startup for CPU feature detection.

---

## [0.9.38] — 2026-05-25

### Fixed

- `src/webui/mod.rs`: `include_str!` and `include_bytes!` paths corrected to `"index.html"` and `"favicon.ico"` after the source move to `src/webui/` in v0.9.37.
- `install.sh`: health check URL corrected from port `8081` to `8080`.
- `src/api/mod.rs`: removed leftover `eprintln!` debug statement from rate-limiter test.

### Changed

- `Cargo.toml`: package description updated to reflect the project's current scope.
- `README.md`: dashboard section rewritten — nginx setup removed, replaced with embedded UI instructions (available since v0.9.0).
- `docs/api.md`: removed dead reference to `examples/web-ui/`; version examples updated to v0.9.37.
- `docs/index.md`: removed pinned version string.
- `AUDIT-PRINCIPLES.md`: removed from repository root.
- `.github/workflows/release.yml`: release creation made idempotent; asset upload uses `--clobber`; binary naming aligned to `runbound-{arch}-linux-{libc}`.

---

## [0.9.37] — 2026-05-25

### Changed

- Web UI source moved from `examples/web-ui/` to `src/webui/` — compiled into the binary, no external files needed at runtime.
- `examples/web-ui/` directory removed.

---

## [0.9.36] — 2026-05-25

### Fixed

- WebUI Protection: bouton "Apply to all" aligné à la même hauteur (38 px) que "Enable/Disable" via `.icmp-config-row>.btn-secondary { height:38px; line-height:38px }`.

---

## [0.9.35] — 2026-05-25

### Changed

- WebUI Protection: refonte du formulaire ICMP (suppression spin buttons, inputs compacts centrés, boutons primary/outline). Remplacé par v0.9.36 (trop intrusif).

---

## [0.9.34] — 2026-05-25

### Fixed

- WebUI: point de connexion (conn-dot, blink vert/rouge) restauré dans le banner — supprimé par erreur en v0.9.33.
- WebUI: copyright en bas retiré du positionnement `fixed` — affiché en fin de page (flux normal).

---

## [0.9.33] — 2026-05-25

### Changed

- WebUI: badge "connected / not connected" supprimé du banner (le point coloré suffit).
- WebUI: logo ASCII éclairci (`#1e4d6b` → `#2d7ab5`) pour meilleure lisibilité sur fond sombre.
- WebUI Settings: section DNSSEC déplacée en première position.

---

## [0.9.32] — 2026-05-25

### Added

- Config option `block-https-record: yes` : retourne NOERROR vide pour les requêtes de type HTTPS (type 65), empêchant les navigateurs de négocier HTTP/3 (QUIC) quand UDP/443 est bloqué sur le réseau.

---

## [0.9.31] — 2026-05-25

### Fixed

- Détection cgroup v2 : lecture de `/proc/self/cgroup` pour résoudre le chemin exact du cgroup du processus au lieu d'utiliser `/sys/fs/cgroup` (racine), qui n'a pas de `memory.max` sous cgroup v2 unified hierarchy.
- Ajout `MemoryMax=2G` dans l'unit systemd pour fixer la limite cgroup et éviter la pression mémoire faussement reportée.

---

## [0.9.30] — 2026-05-25

### Fixed

- Relay : accumulation de connexions TCP en état CLOSE-WAIT sur le port 8082 du slave. La tâche hyper HTTP/1.1 était fire-and-forget — le handle de connexion est maintenant attendu avec timeout 500 ms après collecte de la réponse. Header `Connection: close` ajouté pour signaler la fermeture au serveur distant.

---

## [0.9.29] — 2026-05-25

### Changed

- WebUI: globe icon (Lucide style, `#22d3ee`, transparent background) added as SVG favicon (inline `data:` URI, no external file needed) and in the header banner alongside the RUNBOUND title, using `display:flex; align-items:center; gap:0.5rem`.

---

## [0.9.28] — 2026-05-25

### Added

- ICMP flood ban (XDP-level): `icmp_banned` BPF LRU_HASH map; IPs exceeding `ban_threshold` rate-limited packets per poll interval are dropped at XDP layer without touching the kernel network stack.
- Cross-cluster ban propagation: `PUT /api/alerts/blocked/:ip` and `DELETE /api/alerts/blocked/:ip` are forwarded to all registered slaves via the relay.
- `icmp.json` config: `enable`, `rate_limit` (pps), `burst`, `ban_threshold` fields.

### Fixed

- **SEC-B2** regression: RFC 1918 relay registration check blocked LAN slaves. New opt-in config flag `sync-allow-private-relay: yes` bypasses the check for private deployments.
- Relay CLOSE-WAIT accumulation: hyper HTTP/1.1 keep-alive on the sync server left connections in CLOSE-WAIT after master closed the write side. Fixed with `.keep_alive(false)` on both server builders (`src/sync.rs`).

---

## [0.9.27] — 2026-05-25

### Added

- ACME DNS-01 challenge support: automatic Let's Encrypt certificate issuance and renewal with no port 80 requirement. Supports Cloudflare DNS-01 hook or custom shell hook script. Hot-swap on renewal — no restart needed. (`src/api/acme.rs`, `src/tls.rs`)

---

## [0.9.26] — 2026-05-25

### Added

- Local CA mode: Runbound generates a self-signed CA at startup if none exists. One-time CA certificate install in the browser/OS trust store gives zero-warning HTTPS for all management connections. Served at `GET /webui/ca.crt`. (`src/tls.rs`, `src/webui/mod.rs`)

---

## [0.9.25] — 2026-05-25

### Fixed

- Protection tab: CSRF token missing on ICMP form submissions — added `X-CSRF-Token` header to all protection API calls.
- HTTP → HTTPS redirect now returns 301 with correct `Location` header including path and query string.
- Button style inconsistencies in Protection tab resolved.

---

## [0.9.24] — 2026-05-25

### Added

- Protection tab: WebUI section for ICMP flood protection — enable/disable, rate limit, burst, and ban threshold controls; per-node badge showing `ok` / `flooding` / `banned` status based on delta counters.
- HTTPS WebUI: embedded TLS server (rustls) serves the management console over HTTPS with auto-generated self-signed certificate.
- Gzip compression for static WebUI assets (compile-time, `flate2`).

---

## [0.9.23] — 2026-05-25

### Changed

- WebUI static assets (HTML, CSS) compressed with gzip at compile time and served with `Content-Encoding: gzip` — reduces transfer size by ~75%.

---

## [0.9.22] — 2026-05-25

### Fixed

- WebUI: QPS sparkline on slave node view was displaying master QPS data instead of the selected slave's metrics.

---

## [0.9.21] — 2026-05-25

### Fixed

- WebUI: live QPS sparkline timing and bar height calculation corrected.
- System and About tab content horizontal centering fixed.

---

## [0.9.20] — 2026-05-25

### Fixed

- WebUI: button reset styles, missing body margin, top-domains aggregation across nodes, sparkline rendering for all-nodes view.

---

## [0.9.19] — 2026-05-25

### Changed

- WebUI: Tailwind CDN replaced by a custom utility CSS bundle embedded at compile time. Eliminates the external CDN dependency — WebUI works fully offline. Bundle covers only the classes actually used (~4 KB minified). (`examples/web-ui/index.html`)

---

## [0.9.18] — 2026-05-25

### Fixed

- WebUI: duplicate `QPS_BUF` declaration causing a JavaScript runtime error on the overview tab.

---

## [0.9.17] — 2026-05-25

### Performance

- Cache snapshot: periodic RwLock-free snapshot eliminates lock contention on hot read paths under high QPS.
- Domain stats (`/api/stats/domains`): O(1) per-domain counter update, served from snapshot.
- Rate limiter: per-client token-bucket refill moved off the hot path.
- Startup time: parallel zone loading, lazy BPF map initialisation.
- `SO_BUSY_POLL`: enabled on AF_XDP sockets to reduce interrupt latency on supported NICs. (#145)

---

## [0.9.16] — 2026-05-25

### Security

- **SEC-B10** [MEDIUM]: Idle session cleanup task now runs every 60 s and removes sessions expired for more than 30 min — prevents unbounded session table growth. (`src/webui/mod.rs`)
- **SEC-B16** [LOW]: Unicode control characters (U+0000–U+001F, U+007F, U+0080–U+009F) rejected in all free-text API input fields — prevents log injection and terminal escape sequences. (`src/api/mod.rs`)

---

## [0.9.15] — 2026-05-25

### Security

- **SEC-B1** [HIGH]: Relay HMAC window tightened from ±60 s to ±30 s; replay window uses a per-connection nonce set (BTreeSet, evicted after TTL). (`src/api/relay.rs`)
- **SEC-B2** [HIGH]: Relay registration handler rejects RFC 1918 `relay_host` values by default. Opt-in `sync-allow-private-relay: yes` allows private-IP slaves. (`src/sync.rs`)
- **SEC-B3** [MEDIUM]: `relay_host` validated as a valid hostname or IP at registration time; rejects raw URLs, path traversal, and embedded newlines. (`src/sync.rs`)
- **SEC-B5** [MEDIUM]: Webhook URL validated against allowlist schema (https only, no private IPs) before delivery. (`src/api/mod.rs`)
- **SEC-B9** [MEDIUM]: AXFR `axfr-allow` CIDR list validated at config parse time; malformed CIDRs cause startup failure with a clear error message. (`src/config/parser.rs`)
- **SEC-B14** [LOW]: Rate limiter counters use saturating arithmetic to prevent u64 overflow under sustained flood. (`src/api/mod.rs`)
- **SEC-B17** [LOW]: `/api/logs` pagination parameters clamped to `[0, 10_000]` to prevent OOM from large `limit` values. (`src/api/mod.rs`)

---

## [0.9.14] — 2026-05-25

### Added

- io_uring slow path: `use-io-uring: yes` config option enables the Tokio io-uring backend for the DNS slow path (TCP, DoT, fallback UDP). Detected at startup; graceful fallback to epoll if io_uring is unavailable. (#65) (`src/dns/server.rs`)

---

## [0.9.13] — 2026-05-25

### Added

- AXFR/IXFR zone transfer support (#22): Runbound can serve authoritative zones to secondary nameservers. `axfr-allow` CIDR whitelist controls which secondaries may transfer. Synthetic SOA generated from zone data. TSIG-ready architecture for authenticated transfers. (`src/dns/axfr.rs`)

---

## [0.9.12] — 2026-05-25

### Added

- Alert thresholds (#12): per-client QPS tracking with configurable `block`, `notify`, and `log` actions. New endpoints: `GET /api/alerts`, `PUT /api/alerts/blocked/:ip`, `DELETE /api/alerts/blocked/:ip`. Webhook delivery for notify events. (`src/api/mod.rs`, `src/alerts.rs`)

---

## [0.9.11] — 2026-05-25

### Security

- **SEC-A1** [HIGH]: Login endpoint rate-limited to 5 attempts per IP per minute (token bucket, in-memory). Excess attempts return 429 with `Retry-After` header. (`src/webui/mod.rs`)
- **SEC-A2** [MEDIUM]: Session cookie gains `Secure` flag when the WebUI is served over HTTPS. (`src/webui/mod.rs`)
- **SEC-A3** [MEDIUM]: Minimum password length enforced at 12 characters on `POST /api/webui/password`. (`src/webui/mod.rs`)
- **SEC-A5** [LOW]: IPv6 link-local addresses (`fe80::/10`) rejected as `relay_host` values — they are non-routable and would silently fail. (`src/sync.rs`)

---

## [0.9.10] — 2026-05-25

### Changed

- Dead code removed across all modules; zero compiler warnings in release build.

---

## [0.9.9] — 2026-05-25

### Added

- XDP cache-hit counter: `CACHE_HITS` per-CPU BPF array incremented on every XDP-served response; exposed via `GET /api/stats` as `xdp_cache_hits`. (`ebpf/dns_xdp.c`, `src/dns/xdp/worker.rs`)
- Relay top-domains: `GET /api/nodes/:id/relay/stats/domains` proxied correctly to slave. (`src/api/relay.rs`)
- Relay system info: `GET /api/nodes/:id/relay/system` returns slave `GET /api/system` response. (`src/api/relay.rs`)

---

## [0.9.8] — 2026-05-25

### Added

- WebUI: node-aware QPS sparkline — per-node mini bar chart on the Overview tab updates independently as the selected node changes.
- WebUI: relay top-domains panel in the Overview tab shows the top queried domains aggregated across all nodes.

### Fixed

- WebUI: login page placeholder text removed; unused credential hints cleared.

---

## [0.9.7] — 2026-05-25

### Fixed

- DoT upstream silent failures: connection errors now correctly logged and the upstream marked unhealthy. Reconnect logic retried with exponential backoff. (`src/upstreams.rs`)
- DNSSEC stats not updating after API toggle: `dnssec_probe` task now respects the live config state change without restart. (`src/upstreams.rs`)

---

## [0.9.6] — 2026-05-25

### Added

- Auth activity in Logs tab: `login_ok`, `login_fail`, and `logout` events appear in the log stream with IP address.
- `GET /api/relay/top-domains` endpoint added to slave API.
- Favicon served at `/favicon.ico`.

### Fixed

- CORS headers on API responses: missing `Access-Control-Allow-Origin` for preflight requests resolved.
- `GET /api/relay/system` returning 404 on some slave configurations.
- Login page body background color incorrect in dark mode.
- DNSSEC statistics not propagated to slave via config push.

### Changed

- Tailwind stylesheet file renamed from `tailwind.css` to `rb-styles.css`; `dns-prefetch` enabled by default.
- Logs tab auto-refresh interval set to 5 s.

---

## [0.9.5] — 2026-05-25

### Fixed

- WebUI: dark theme CSS autofill override (SEC-19 follow-up) — browser autofill no longer overrides dark background on login and settings forms. (`examples/web-ui/index.html`)
- Settings form indentation corrected.

---


## [0.9.4] — 2026-05-25

### Security

- **SEC-19** [HIGH]: CSRF double-submit cookie on WebUI. Login now sets a non-HttpOnly
  `rb_csrf` cookie; `POST /api/webui/password` and `POST /logout` verify the
  `X-CSRF-Token` request header matches the session-stored token.
  (`src/webui/mod.rs`)

- **SEC-AGV-01** [HIGH]: DDNS UPDATE handler rejects DELETE operations targeting
  statically configured zone names. `LocalZoneSet` now carries a `static_names:
  HashSet<Name>` populated from `unbound.conf` at startup; any DELETE with a matching
  name returns `REFUSED`. Prevents TSIG-authenticated zone hijacking.
  (`src/dns/ddns.rs`, `src/dns/local.rs`)

- **SEC-20** [MEDIUM]: TSIG key material decoded once at startup instead of
  base64-decoding on every UPDATE request. Stored as
  `Vec<(String, TsigAlgorithm, Vec<u8>)>`.
  (`src/dns/server.rs`)

- **SEC-21** [MEDIUM]: Stale cache capped at `cache_max_entries` with simple eviction
  to prevent OOM growth under high-cardinality domain traffic.
  (`src/dns/server.rs`)

- **SEC-AGV-02** [MEDIUM]: Schedule window validation in blacklist API handler — rejects
  non-HH:MM values before storage. `is_active_now()` uses safe `.get(..2)` / `.get(3..5)`
  slice access to prevent panics on short strings.
  (`src/api/mod.rs`, `src/store.rs`)

- **SEC-24** [LOW]: DNSSEC stripping detection now requires 2 consecutive AD=0 probe
  results before setting `dnssec_stripping = true` — eliminates false positives from
  upstream oscillation.
  (`src/upstreams.rs`)

- **SEC-26** [INFO]: SSE sparkline reconnect uses exponential backoff (1 s → 30 s max)
  instead of silently dropping on stream close.
  (`examples/web-ui/index.html`)

### Added

- **WebUI: logout button** in the management console header bar.
- **WebUI: auto-logout** after 30 minutes of user inactivity (idle timer reset on
  click/keydown/mousemove/touchstart).
- **WebUI: Settings tab** — change username and password via `POST /api/webui/password`.
  Active sessions are invalidated on credential change (SEC-25 fix from v0.9.3).
- **WebUI: POST /logout** route alongside existing GET — required for CSRF-protected
  logout from the embedded WebUI server.
- **WebUI: CSRF in all API calls** — `api()` helper reads `rb_csrf` cookie and injects
  `X-CSRF-Token` header on every non-GET request.

### Fixed

- **WebUI: QPS sparkline** always showed 0 on low-traffic servers because `qps_1m` is
  an exponentially smoothed average that takes time to accumulate. Fixed to compute
  instantaneous QPS from the delta of the `total` counter between SSE frames.

---
## [0.9.2] — 2026-05-24

### Security
- **SEC-12 fix**: XDP ICMP handler now rejects IPv4 packets with options (IHL≠5) instead
  of parsing the ICMP header at wrong offset. Packets with IP options pass to kernel.
- **SEC-16 fix**: WebUI reverse proxy body limit aligned to 65536 bytes (matching API
  `MAX_BODY_BYTES`) — prevents up to 8 MB per-request heap allocation.

### Fixed
- **SEC-13 fix**: `icmp-rate-limit-burst` config now takes effect. New source IPs receive
  `burst` initial free tokens before per-second rate limiting applies. Backed by a
  `burst_left` field in the BPF `icmp_rate_entry` map value.

---

## [0.9.1] — 2026-05-24

### Added
- **XDP ICMP echo responder (#89)** (`ebpf/dns_xdp.c`, `src/icmp.rs`, `src/dns/xdp/loader.rs`)
  Runbound now responds to ICMP echo requests at the XDP driver layer — zero kernel-
  stack overhead. Per-source-IP token bucket rate limiting (configurable pps and burst)
  drops excess pings with a BPF counter increment, no reply generated.

  Configure via `runbound.conf`:
  ```
  icmp {
      enable: yes
      rate-limit: 20        # pings/s per source IP (default: 10)
      rate-limit-burst: 8   # burst capacity (default: 5)
  }
  ```

  Live config updates: `PUT /api/icmp/config` — applied to BPF within 1 second.
  Stats: `GET /api/icmp/stats` returns `handled`, `replied`, `dropped`, `rate_limited`
  counters from BPF per-CPU arrays (PR #122).

---

## [0.9.0] — 2026-05-24

### Added
- **Embedded web UI server (#4/#91)** (`src/webui/mod.rs`, `src/config/parser.rs`, `src/main.rs`)
  Runbound now serves the management dashboard directly — no nginx required.
  Enable with `ui-enabled: yes` in `runbound.conf`; configure port (`ui-port`, default 8090)
  and bind address (`ui-bind`, default `0.0.0.0`). The embedded server proxies every
  `/api/*` request to the local API (127.0.0.1), keeping the REST endpoint off the
  network. Supports streaming responses (SSE live-events) through the proxy (PR #121).

---

## [0.8.2] — 2026-05-24

### Added
- **Top domains API (#5)** (`src/domain_stats.rs`, `src/api/mod.rs`)
  `GET /api/stats/top-domains?limit=N` returns the most-queried domain names
  since process start. Backed by a lock-free `DashMap<Box<str>, AtomicU64>` capped
  at 10,000 domains. Overview tab shows a top-10 table with inline progress bars
  (PR #117).

- **Auto firewall management (#90)** (`src/firewall/`, `src/config/parser.rs`, `src/main.rs`)
  Opt-in (`firewall-manage: yes`): on startup Runbound opens required ports
  (DNS UDP+TCP, API, sync) in the host firewall; closes them on clean shutdown.
  Detects UFW, nftables, iptables automatically or via `firewall-backend:`.
  Tagged rules only — never flushes chains (PR #118).

### Fixed
- **SEC-2026-05-24-03 (#110)**: `is_private_ip()` accepted `::ffff:127.0.0.1` and
  other IPv4-compatible IPv6 addresses as public, enabling SSRF via feed registration
  (PR #115).
- **SEC-2026-05-24-04 (#111)**: `cert_rl` rate-limit map keyed on `IP:port` rather
  than IP alone; attacker could bypass per-IP cert-request limit by rotating ephemeral
  source ports (PR #115).
- **SEC-2026-05-24-05 (#112)**: `Acl::check()` called `to_ipv4_mapped()` on the
  client address before matching, so `::ffff:192.168.1.1` could bypass IPv6 ACL rules
  (PR #115).
- **SEC-2026-05-24-06 (#113)**: `relay_host` was not validated at slave registration;
  a malicious slave could register an internal address and cause SSRF from master relay
  calls (PR #115).

---

## [0.8.1] — 2026-05-24

### Security
- **SEC-2026-05-24-01**: `is_private_ip()` did not canonicalise IPv4-in-IPv6 addresses
  before the private-range check; `::127.0.0.1` bypassed SSRF protection on feed
  registration (MEDIUM).
- **SEC-2026-05-24-02**: Relay registration allowed registering slave addresses in
  RFC-1918 ranges other than the relay host's own subnet, enabling internal-network
  SSRF (MEDIUM).

---

## [0.8.0] - 2026-05-24

### Performance
- fix(#97): rate limiter per-/24 subnet bucketing, reduces DashMap contention by ~256x
- feat(#96): configurable AF/XDP ring sizes via config (xdp-rx-ring-size etc), power-of-2 validated

### Observability
- fix(#98): XDP per-queue mode logging at startup, zerocopy vs copy per queue
- fix(#98): /api/stats now exposes xdp_queues array with per-queue mode
- fix(#93): ANSI startup banner showing version, ports, XDP mode (TTY only)

### Documentation
- Fixed unsubstantiated perf claims (0ms latency removed, throughput marked TBD)
- Added experimental status banner to README
- Added docs/unbound-migration.md with Unbound config compatibility matrix
- Corrected BIND9 comparison table and AI-role disclosure in METHODOLOGY.md

---

## [0.7.0] — 2026-05-24

### Added

- **resolv.conf emergency fallback (#94)** (`src/config/parser.rs`, `src/upstreams.rs`, `src/dns/server.rs`)

  When all configured upstreams become unreachable, Runbound automatically reads
  `/etc/resolv.conf` and injects the listed `nameserver` entries as temporary
  plain-UDP upstreams. The fallback is removed as soon as any primary upstream
  recovers (checked every 30 s).

  - Temporary upstreams are visible in `GET /api/upstreams` with `"source": "resolv.conf"` and `"temporary": true`.
  - Config directive: `resolv-fallback: no` to disable (default: `yes`).
  - Temporary entries are never persisted to `upstreams.json`.

- **SSE node-status push (#86)** (`src/sync.rs`, `src/api/mod.rs`, `src/main.rs`)

  New endpoint `GET /api/events` (Server-Sent Events): real-time stream of slave
  health state changes. An event is emitted whenever a slave transitions between
  health categories.

  Thresholds (`last_seen_secs`):
  - `ok`: < 15 s (slave actively syncing)
  - `warn`: 15–59 s (one sync cycle missed, may be transient)
  - `error`: ≥ 60 s (slave likely unreachable)

  Event JSON format:
  ```json
  {"node_id":"…","addr":"…","status":"warn","reason":"last seen 42s ago","ts":1748131200}
  ```

  Master only — returns `404` on slave and standalone nodes.  
  Keep-alive every 15 s. Broadcast channel capacity: 64 events.

---

## [0.6.24] — 2026-05-24

### Fixed

- **Relay forwarding NOT_FOUND (#95 round 3)** (`src/sync.rs`, `src/stats.rs`, `src/api/mod.rs`)

  `GET /relay/stats` et `GET /relay/upstreams` retournaient 404 `{"error":"NOT_FOUND"}` : le handler du serveur relay slave ne couvrait que les opérations d'écriture (dns/blacklist/upstreams POST/DELETE + snapshot). Les requêtes en lecture tombaient dans le `_ => 404`.

  Fix : deux nouveaux arms dans `handle_relay_request` :
  - `("GET", "stats")` → retourne le snapshot live de stats (qps, cache, DNSSEC, latences).
  - `("GET", "upstreams")` → retourne la liste des upstreams avec état de santé.

  `stats_json` extrait de `api/mod.rs` vers `stats::snapshot_to_json` (pub) pour éviter la duplication et la dépendance circulaire.

---

## [0.6.23] — 2026-05-23

### Fixed

- **Relay registration : retry + visibilité (#95 round 2)** (`src/main.rs`, `src/api/relay.rs`)

  Deux bugs résiduels corrigés après le fix TLS du round 1 :

  1. **Enregistrement one-shot sans retry** — la registration slave→master était tentée une seule fois (T+2 s au démarrage). Si le master n'était pas encore prêt, ou si le réseau flanchait, le slave restait orphelin sans jamais réessayer. Fix : boucle de retry avec backoff exponentiel (2 s → 4 s → 8 s → … → max 300 s) jusqu'au premier succès (HTTP 200).

  2. **Logs de registration invisibles à verbosity 1** — les messages `"Slave relay disabled"` (info) et `"Registered with master"` (info) étaient filtrés par le filtre `error,runbound=warn` actif à `verbosity: 1`. Passés en `warn!` pour être visibles dans la configuration par défaut.

---

## [0.6.22] — 2026-05-23

### Changed

- **Thin LTO — build multithread par défaut** (`Cargo.toml`)

  `lto = true` (fat LTO, single-thread) → `lto = "thin"` (thin LTO, parallélisé sur tous les cœurs). `codegen-units = 1` supprimé — retour au défaut release (16 unités, compilation parallèle). Résultat local : 45 s au lieu de ~2 min. CI attendu : ~7-8 min au lieu de 19 min. Impact perf binaire : négligeable — thin LTO conserve ~95 % des gains d'optimisation de fat LTO.

---

## [0.6.21] — 2026-05-23

### Fixed

- **Relay TLS handshake (#95)** (`src/main.rs`, `src/sync.rs`)

  Quatre bugs corrigés dans le relay chiffré v0.6.20 :

  1. **`relay_host` erroné (`0.0.0.0:8082`)** — le slave utilisait `cfg.interfaces.first()` (adresse de bind) pour construire l'adresse relay envoyée au master. Avec `interface: 0.0.0.0`, le master enregistrait `0.0.0.0:8082` et ne pouvait jamais se connecter. Fix : détection de l'IP sortante réelle via une socket UDP (`connect()` sans envoi, puis `local_addr()`) — technique standard de résolution de route. Fallback sur la première interface non-wildcard si la socket échoue.

  2. **`ensure_relay_cert()` appelé deux fois** — le cert était chargé/généré séparément pour le serveur relay et pour l'enregistrement. Refactorisé en un seul appel, résultat réutilisé pour les deux.

  3. **Erreurs relay loggées en `warn` au lieu de `error`** — les échecs de génération du cert relay (`ensure_relay_cert`) et du fingerprint passaient silencieusement. Passés en `error!`. Ajout d'un `info!` explicite quand `sync-port` est absent de la config slave (relay désactivé intentionnellement vs silencieusement).

  4. **Fingerprint stale → message générique** — quand le cert du master change après le TOFU initial, le slave loggait `"initial full sync failed: TLS handshake: Connection reset by peer"` sans explication. Désormais : `error!` avec instruction explicite pour supprimer le fichier `sync-master.fingerprint` et redémarrer.

  Bonus : le master ajoute un hint `"plain-HTTP client?"` dans les logs TLS `InvalidContentType` (connexion non-TLS sur le port sync).

---

## [0.6.20] — 2026-05-23

### Added

- **Relay chiffré master→slave (#85)** (`src/api/relay.rs`, `src/sync.rs`)

  Les handlers de l'API maître acceptent désormais `GET|POST|PUT|DELETE /api/nodes/{node_id}/relay/*path` et relaient la requête vers l'esclave identifié avec un canal HMAC-SHA256 (sync-key partagé). Chaque requête est signée via `X-Runbound-TS` (timestamp Unix) + `X-Runbound-Sig` (HMAC-SHA256 hex). Protection anti-rejeu : le serveur esclave rejette tout timestamp avec |now − ts| > 30 s. La clé sync est réutilisée ; la vérification est en temps constant (`subtle`). Le serveur relay de l'esclave écoute sur `sync-port` (TLS auto-signé, même infrastructure que le sync), accessible depuis le maître.

- **Config push master→slaves (#87)** (`src/api/mod.rs`, `src/api/relay.rs`)

  Après chaque mutation réussie sur le maître (POST/DELETE dns, blacklist, upstreams), le maître pousse la même opération vers tous les esclaves enregistrés via le canal relay HMAC. Implémenté en fire-and-forget (spawn) : l'opération maître n'est jamais bloquée par un esclave injoignable. Les journaux retracent les succès et échecs par node_id. Nouveaux variants `AddUpstream` / `DeleteUpstream` dans `SyncOp` pour la réplication des upstreams.

- **Slave auto-registration (#88)** (`src/sync.rs`, `src/main.rs`)

  À démarrage, chaque esclave génère (ou recharge depuis `node-id`) un UUID stable et s'enregistre auprès du maître via `POST /nodes/register` sur le sync-port TLS (HMAC signé). L'enregistrement inclut `node_id`, `relay_host` (`ip:port`) et le fingerprint SHA-256 du cert relay. Le maître persiste les enregistrements dans `slaves.json` (rechargé à chaque démarrage). Nouvel endpoint `GET /api/nodes` retourne la liste des esclaves enregistrés avec relay capability.

---

## [0.6.19] — 2026-05-23

### Fixed

- **XDP SKB mode deadlock Tokio runtime — pool exhaustion (#83)** (`src/dns/server.rs`)

  **Cause** : `opts.timeout = 3 s × opts.attempts = 2` → chaque `lookup()` peut bloquer un worker Tokio pendant 6 s. Sous charge (XDP SKB mode produit des rafales), N lookups simultanés occupent les N workers et la tâche background de reconnexion du pool ne peut plus s'exécuter — deadlock complet (même le loopback cesse de répondre).

  **Fix 1 — timeout externe par lookup** : chaque appel à `resolver.lookup()` est désormais enveloppé dans `tokio::time::timeout(2500 ms)` via `timed_lookup()`. La future hickory est **annulée** (droppée) si elle ne répond pas dans les 2,5 s, libérant immédiatement le worker quelle que soit l'état interne du pool. Appliqué à tous les chemins : mode normal, mode racing (`select_ok`), retry post-rebuild.

  **Fix 2 — rebuild spawné en tâche indépendante** : le `rebuild_and_swap()` (qui appelle `warm_up()` en interne, pouvant bloquer 3 s) est désormais `tokio::spawn`-é au lieu d'être `await`-é dans le query handler. Le handler retourne SERVFAIL pour la requête courante ; la requête suivante utilisera le resolver reconstruit. Supprime le risque d'enchaîner un blocage de 3 s (warm-up) immédiatement après un blocage de 2,5 s (timeout lookup).

---

## [0.6.18] — 2026-05-23

### Fixed

- **DoT pool exhaustion: boucle de rebuild sans backoff** (`src/dns/server.rs`)  
  Sous charge soutenue, chaque query échouant sur `NoConnections` déclenchait immédiatement un `rebuild_and_swap`, produisant des centaines de rebuilds/seconde. Chaque rebuild crée N tâches Tokio supplémentaires qui génèrent à leur tour d'autres rebuilds — boucle de feedback positive.  
  Fix : debounce global avec deux atomiques `AtomicU64`. Le rebuild n'est autorisé qu'une fois toutes les 2 s via `compare_exchange`. Les queries concurrentes qui perdent la CAS retournent SERVFAIL immédiatement sans déclencher de rebuild. Le log est throttlé à au plus une ligne toutes les 10 s (niveau `INFO`).

- **API HTTP freeze sous charge Tokio** (`src/main.rs`)  
  Le serveur axum (REST API) partageait le runtime Tokio DNS principal. Lors d'une storm de rebuilds DoT, le scheduler était saturé de tâches et les handlers axum ne recevaient plus de slots CPU. La socket TCP restait en `LISTEN` mais les accepts n'étaient jamais traités — nginx renvoyait `504`.  
  Fix : runtime Tokio dédié à 2 threads (`runbound-api`) pour axum, isolé du runtime DNS. Le fd TCP est lié avec `std::net::TcpListener` (runtime-agnostic) puis converti en `tokio::net::TcpListener` à l'intérieur du runtime API. Le runtime est `Box::leak`-é pour vivre toute la durée du process.

---

## [0.6.17] — 2026-05-23

### Fixed

- **XDP self-test false failure in SKB mode / VM environments** (`src/dns/xdp/worker.rs`)  
  On virtio-net with MTU > 3506 (KVM/Proxmox), XDP loads in SKB mode because the driver has no native XDP support at that MTU. In SKB mode, AF_XDP TX frames go through the kernel SKB path and do **not** re-enter the XDP ingress path — the loopback round-trip the self-test relies on never completes. The fill ring is correctly seeded, the socket is bound, and the BPF program is attached; real ingress DNS traffic is delivered correctly.  
  Fix: the 200 ms deadline expiry is now `tracing::warn!` + `Ok(())` instead of `Err(...)`. The hard `Err` path is preserved only for `fill.producer_count() == 0` (genuine UMEM misconfiguration). XDP remains active and the warning message names SKB mode / VM environment as the expected cause.

---

## [0.6.16] — 2026-05-23

### Fixed

- **BPF verifier: `math between pkt pointer and register with unbounded min value`** (`ebpf/dns_xdp.c`)  
  Root cause: `qname[i]` compiles to `r0 += r1` (PTR_TO_PACKET + loop variable). At the loop back-edge the verifier loses the minimum bound on `r1` and marks it `scalar()` (unbounded) — any `PTR_TO_PACKET + loop_var` arithmetic is then rejected, regardless of index bounds or guard checks.  
  Fix: `#pragma unroll` on the FNV-1a loop. The compiler emits 64 sequential copies of the loop body with no back-edge. The verifier processes them linearly; each iteration's `qname + 1 > data_end` bounds check constrains the pointer correctly, and `qname++` is a single `r6 += 1` on an already-validated pointer. FNV-1a's XOR + multiply generates O(N) verifier states (unlike CRC32C's bit loop which was O(2^N)).

---

## [0.6.15] — 2026-05-23

### Fixed

- **BPF verifier: `math between pkt pointer and register with unbounded min value`** (`ebpf/dns_xdp.c`)  
  After `h *= 16777619u` (FNV-1a prime), `h` becomes an unbounded scalar. `h % nb_workers` remains unbounded from the verifier's perspective because `nb_workers` is a runtime value — the verifier cannot prove the result is within `[0, max_entries)` of CPUMAP. Fix: add `if (cpu >= 64) return XDP_PASS;` immediately after the modulo. 64 matches `CPUMAP max_entries`; the explicit bound proves `cpu ∈ [0, 63]` statically.

---

## [0.6.14] — 2026-05-23

### Fixed

- **BPF verifier rejects `qname++` on PTR_TO_PACKET** (`ebpf/dns_xdp.c`)  
  In `dns_qname_hash()`, incrementing the `qname` pointer (`qname++`) creates a
  `PTR_TO_PACKET` with variable offset. The verifier calculates the worst-case
  advance (`packet_end − qname_start`, up to 786 bytes on a 840-byte packet) and
  rejects the program because `qname + worst_case + 1` exceeds the verified range.
  Fix: keep `qname` immobile, use `qname[i]` with bounded index `i < 64`.
  The bounds check `(qname + i + 1) > data_end` is then statically provable.
  Same fix class as the v0.6.10 `pointer -= pointer` verifier rejection.
  Hash output is unchanged — FNV-1a logic (seed, XOR, multiply) is identical.

---

## [0.6.13] — 2026-05-23

### Fixed

- **Bug 1 — BPF verifier rejects CRC32C** (`ebpf/dns_xdp.c`)  
  CRC32C's 8-iteration inner loop (`#pragma unroll 8`) generates exponential scalar state explosion in the BPF verifier, causing program rejection. Replaced with FNV-1a: `h ^= (*qname | 0x20u); h *= 16777619u;` — single multiply per byte, scalar state bounded cleanly. Function signature updated to `dns_qname_hash(const __u8 *qname, const __u8 *data_end)` — pointer passed directly instead of offset arithmetic.

- **Bug 2 — CPUMAP creation fails on slave VM** (`ebpf/dns_xdp.c`, `build.rs`, `src/dns/xdp/loader.rs`)  
  `EbpfLoader::load()` creates ALL ELF maps at once; if `BPF_MAP_TYPE_CPUMAP` fails (missing `CAP_BPF`, old kernel, slave VM), the entire XDP subsystem was disabled. Fix: compile two eBPF binaries — `dns_xdp.o` (full, with CPUMAP) and `dns_xdp_minimal.o` (`-DNO_CPUMAP`). CPUMAP struct and `bpf_redirect_map` call are guarded with `#ifndef NO_CPUMAP` in C. `loader.rs` tries the full binary first; if the aya error contains "cpumap", it retries with the minimal binary and disables domain routing automatically.

- **#64 — UDP checksum computed over stale bytes** (`src/dns/xdp/worker.rs`)  
  In `process_packet`, the UDP checksum was computed over `tx[udp_off..dns_off+len]` before the DNS payload was copied into `tx[dns_off..]`, producing a checksum over uninitialised frame bytes. Fixed by restructuring: DNS payload is written into `tx` first, then Ethernet/IP/UDP headers are set, then the checksum is computed.

### Changed

- **#64 — Zero-copy cache hits eliminate intermediate Vec** (`src/dns/xdp/worker.rs`)  
  `answer_from_cache` signature changed from `(…, out: &mut Vec<u8>) -> bool` to `(…, tx_dns: &mut [u8]) -> Option<usize>`. Cache responses are written directly into the TX UMEM frame (`tx[dns_off..]`) with no intermediate allocation. Eliminates one `extend_from_slice` + one `copy_from_slice` per cache hit.

---

## [0.6.12] — 2026-05-23

### Added

- **#33 — Upstream racing** (`src/dns/server.rs`, `src/config/parser.rs`, `src/api/mod.rs`)  
  New directive `upstream-racing: yes` sends the query to **all** configured upstreams simultaneously and returns the first valid response. Losers are silently dropped. Per-upstream win counters exposed in `GET /api/system` as `upstream_racing_wins: {"ip": count}`. Racing resolvers are rebuilt when upstreams are added, deleted, or reconnected via the API. Falls back to single-resolver path when fewer than 2 upstreams are available or racing is disabled.

- **#29 — rkyv zero-copy cache persistence** (`src/dns/cache_snapshot.rs`)  
  `save_xdp_cache` and `load_xdp_cache` use rkyv 0.8 binary format prefixed with magic header `b"RBv1"`. Cache is saved atomically (temp file + rename) on **SIGUSR2**. Cache is loaded on startup if the file exists and the magic matches. Stale/corrupt files are silently ignored. `Instant` → UNIX timestamp, `Bytes/SmallVec` → `Vec<u8>` for serialization compatibility.

- **#64 — Zero-copy XDP cache hits** (`src/dns/xdp/worker.rs`)  
  `answer_from_cache` now parses raw DNS wire bytes directly (header flags, OPCODE, QDCOUNT, QNAME label walk, QTYPE/QCLASS) without invoking the hickory DNS parser. QTYPE ANY (255) is rejected. Compression pointers are rejected (must not appear in client queries). Label content bytes are ASCII-lowercased with `| 0x20` to match the server-side `LowerName` normalization. Target: < 300 ns per cache hit on x86_64.

### Changed

- **`GET /api/system`**: new fields `upstream_racing` (bool), `upstream_racing_wins` (object).

- **SIGUSR2**: repurposed from "ignored" to XDP cache persistence trigger.

### Fixed

- **#72 — CRC32 hardware hash** (eBPF): `__builtin_ia32_crc32qi` is an x86 intrinsic and cannot compile with `clang -target bpf`. Software CRC32C (Castagnoli polynomial 0x82F63B78) was correctly implemented in v0.6.10. No code change needed — BPF JIT on x86 may emit hardware CRC instructions automatically.

---

## [0.6.9] — 2026-05-23

### Added

- **#80 — NIC ring auto-sizing** (`src/dns/xdp/socket.rs`)  
  `maximize_nic_ring()` queries the driver via `SIOCETHTOOL` ioctl (`ETHTOOL_GRINGPARAM`) then applies the hardware maximum (`ETHTOOL_SRINGPARAM`) before XDP attach. Prevents silent hardware FIFO drops at high QPS on Intel ixgbe (default ring 512 → max 4096). Graceful fallback on `EOPNOTSUPP` / `EPERM`.

- **`xdp-ring-size` config directive** — `auto` (default) or explicit integer, capped at driver max.

- **`GET /api/system`**: new fields `nic_rx_ring`, `nic_rx_ring_max`, `nic_rx_dropped`  
  `nic_rx_dropped` read from `/sys/class/net/<iface>/statistics/rx_dropped`.

- **Prometheus**: `runbound_nic_rx_ring`, `runbound_nic_rx_ring_max`, `runbound_nic_rx_dropped_total`

- **AF_XDP ring constants** split into `FILL/COMP/RX/TX_RING_SIZE = 4096`; `FRAME_COUNT` raised to 8192 (32 MiB/socket).

- **SIGUSR1 handler**: dumps live stats to log (total, forwarded, blocked, 1 m QPS, cache hit rate, uptime). Previously OS-default = terminate.

- **SIGUSR2 handler**: silently ignored. Previously OS-default = terminate.

- **PERF-03 — NUMA-aware UMEM** (`src/dns/xdp/umem.rs`): `rebind_to_local_numa()` called in XDP worker after CPU pinning. Migrates UMEM pages to local NUMA node via `mbind(MPOL_PREFERRED|MPOL_MF_MOVE)`. Fallback on non-NUMA and containers.

### Changed

- **PERF-01 — Cache publish interval**: `100 ms → 10 ms` — XDP workers see new cache entries within 10 ms (was up to 100 ms).

- **PERF-02 — Lock-free cache inserts**: `Mutex<HashMap>` → `DashMap` on `MutableCacheMap`. Concurrent inserts no longer block the publish loop. Scales past 500 K insertions/second.

- **GDPR — `log-client-ip` default**: `yes → no`. Client IPs appear as `[redacted]` by default in `/api/logs` and the logfile. Opt-in: `log-client-ip: yes`. Audit log unaffected.

- **systemd unit hardened**: `LimitNOFILE=131072`, `LimitNPROC=4096`, `LimitMEMLOCK=infinity`, `MemoryDenyWriteExecute=no`, full XDP capability set (`CAP_NET_RAW CAP_NET_ADMIN CAP_BPF`), `RestrictAddressFamilies=AF_XDP`.

### Removed

- **guestdns**: companion service removed — `systemctl stop/disable`, service file and binary deleted.

---

## [0.6.8] — 2026-05-23

### Added

- **#75 — `POST /api/dns/lookup`**: on-demand DNS resolution via API with cache hit indicator.

- **#76 — `blocked_count` in `GET /api/feeds`**: per-feed count of currently active blocked domains.

- **#78 — `POST /api/upstreams/reconnect`**: force DoT pool reconnect without restart. Accepts `{"warm_up": true}` to pre-warm connections (3 × 250 ms probes).

- **#58 — Slave version and zones**: `GET /api/sync/slaves` now includes `version` and `zones_synced` per slave.

- **Web UI — DNS Lookup panel**: live resolve with cache hit indicator (tab DNS Entries).

- **Web UI — Reconnect DoT button**: per-upstream `↺` button in the Upstreams tab.

- **Web UI — `cfg` badge**: upstream entries coming from the config file are marked with a `cfg` badge.

- **Web UI — Feed `blocked_count`** and full `last_error` display (closes #55).

- **Web UI — Slave `version` + `zones_synced`** in the System tab.

### Changed

- **`/health`** enriched (unauthenticated): `version`, `uptime_secs`, `xdp_active`, `upstreams_healthy`, `cache_entries`.

- **`GET /api/upstreams`**: new `source` field (`"config"` or `"runtime"`).

- **#64 — Wire format cache** (`src/dns/cache_snapshot.rs`): `CacheEntry` now stores a pre-serialized UDP payload (`wire_payload: Bytes`). XDP worker answers cache hits with a direct `memcpy` + QueryID patch — no DNS parsing on the hot path. Reduces cache-hit latency to ~580 ns.

- **#67 — DNS-aware CPUMAP routing** (`ebpf/dns_xdp.c`, `src/dns/xdp/loader.rs`): FNV-1a hash of QNAME (`dns_qname_hash()`, ASCII-lowercased, max 64 bytes) selects a dedicated CPU via CPUMAP. All queries for the same domain always land on the same core — L1/L2 stays warm. Enable with `xdp-domain-routing: yes`. Falls back to RSS with a `WARN` if CPUMAP init fails.

### Fixed

- **#77 — DoT pool exhaustion after idle**: `rebuild_and_swap` now calls `warm_up()` (3 × 250 ms probes) on new resolvers before swapping. Eliminates SERVFAIL burst on first post-idle query.

---

## [0.6.7] — 2026-05-22

### Fixed

- **FIX #56 — DoT SNI mismatch: IP passed as TLS server name** (`src/dns/server.rs`)  
  `build_resolver` and `build_resolver_from_addrs` previously called  
  `ConnectionConfig::tls(Arc::from(ip.to_string()))`, which caused hickory to  
  present the IP literal as a `DnsName` SNI (e.g. `"1.1.1.1"`). Cloudflare's  
  certificate advertises `"cloudflare-dns.com"`, not `"1.1.1.1"`, so rustls  
  rejected the handshake → all real DNS queries over DoT returned SERVFAIL.  
  The health probe was unaffected because it uses `ServerName::try_from(ip)`  
  which creates a `ServerName::IpAddress` that matches the IP SAN — masking  
  the bug.

  New `dot_tls_name(ip, explicit)` derives the correct SNI hostname:  
  - If an explicit `tls_hostname` is provided (e.g. via API), it is used as-is.  
  - Well-known IPs are mapped to their certificate SANs:  
    `1.1.1.1 / 1.0.0.1` → `cloudflare-dns.com`,  
    `9.9.9.9 / 149.112.112.112` → `dns.quad9.net`,  
    `8.8.8.8 / 8.8.4.4` → `dns.google`,  
    `208.67.222.222 / 208.67.220.220` → `dns.opendns.com`.  
  - Unknown IPs fall back to the IP string (produces the previous behaviour —
    the operator must set `tls_hostname` explicitly for non-standard servers).

### Added

- **`tls_hostname` field on `UpstreamStatus`** (`src/upstreams.rs`)  
  New optional field persisted in `upstreams.json`.  
  Omitted from JSON when `None` (`skip_serializing_if`).  
  Backward-compatible: existing files without the field parse as `None`.

- **`tls_hostname` on `POST /api/upstreams`** (`src/api/mod.rs`)  
  Optional field in the request body. Validated: max 253 chars, no control  
  characters. `None` / absent → auto-derive via `dot_tls_name`.

- **`tls_hostname` patchable via `PATCH /api/upstreams/:id`** (`src/api/mod.rs`)  
  Now accepts `"name"` and `"tls_hostname"` (both optional).  
  Empty string or `null` clears the field (falls back to auto-derive).

- **`tls_hostname` in `GET /api/upstreams/presets`** (`src/api/mod.rs`)  
  All DoT preset entries now include `tls_hostname` so the field is  
  persisted automatically when a preset is added via the UI.  
  Added missing presets: Cloudflare DoT alt, Google DoT, Google DoT alt,  
  Quad9 alt, Quad9 DoT alt.

---

## [0.6.6] — 2026-05-22

### Added

- **FEAT #53 — `last_error` field on upstream health failures** (`src/upstreams.rs`)  
  `UpstreamStatus` now exposes a `last_error` string when a probe fails.
  The field is runtime-only (not persisted), omitted from JSON when `None`,
  and cleared on the next successful probe.  
  Error strings are deliberately generic (no OS details):  
  - UDP: `"bind failed"`, `"send failed"`, `"timeout"`, `"short response"`, `"id mismatch"`  
  - DoT: `"TCP connect failed"`, `"TLS handshake failed"`, `"DNS send failed"`,
    `"DNS response timeout"`, `"short response"`, `"id mismatch"`

- **FEAT #54 — `POST /api/upstreams/:id/probe` — on-demand upstream probe** (`src/api/mod.rs`)  
  Triggers an immediate health probe for one upstream without waiting for
  the background health loop. The probe runs in `spawn_blocking` (blocking I/O
  off the async thread pool). Result fields `healthy`, `latency_ms`,
  `dnssec_supported`, `last_error`, and `last_check` are written back by UUID.
  `consecutive_failures` and `next_check_at` are intentionally left untouched.
  Returns `200 {"status":"ok","upstream":{...}}` or `404` if the id is unknown.

---

## [0.6.5] — 2026-05-22 (rev2 — security + performance hardening)

### Security

- **SEC H1 — Malformed `Content-Length` rejected** (`src/api/mod.rs`)  
  Non-parseable `Content-Length` headers now return `400 BAD_REQUEST` instead of
  silently defaulting to 0, which previously allowed the size-limit check to be
  bypassed entirely.

- **SEC H2 — Feed download: streaming with per-chunk size check** (`src/feeds/mod.rs`)  
  Feed HTTP responses are now consumed chunk-by-chunk. Both the `Content-Length`
  pre-check and an accumulated-bytes counter enforce the `MAX_FEED_BYTES` limit,
  preventing an OOM if a server sends a large body without a declared length.

- **SEC H3 — `TcpConnTracker` entry cleanup on release** (`src/dns/server.rs`)  
  DashMap entries are removed when the per-IP connection count reaches 0, capping
  unbounded memory growth under high-churn connection patterns.

- **SEC H4 — ACME credentials zeroed from memory on drop** (`src/acme.rs`)  
  The JSON string containing the ACME account private key is now wrapped in
  `zeroize::Zeroizing<String>`; the allocator buffer is overwritten with zeros
  as soon as the variable goes out of scope.

- **SEC M1 — Rate-limit on `POST /sync/cert`** (`src/sync.rs`)  
  Per-IP sliding window: 10 requests per 60 s. Excess requests receive `429 RATE_LIMITED`.
  Uses a lock-free `DashMap<String, (u32, Instant)>`.

- **SEC M2 — Minimum valid DNS response raised to 12 bytes** (`src/upstreams.rs`)  
  UDP and DoT health probes previously accepted 4-byte responses (header only).
  The threshold is now 12 bytes (full DNS header), matching RFC 1035 §4.1.

- **SEC M3 — Feed URL query string redacted from logs** (`src/feeds/mod.rs`)  
  Everything from `?` onward is stripped before writing the URL to the tracing
  log, preventing API keys or tokens embedded in feed URLs from leaking into logs.

- **SEC C1 — TOCTOU eliminated in upstream health loop** (`src/upstreams.rs`)  
  The health loop previously captured Vec indices; a concurrent add/remove could
  shift entries before the write-back. Probes now capture UUID strings and the
  write-back finds entries by UUID, making it race-free.

### Performance

- **PERF P1 — Lazy `SanitizedDnsName` Display wrapper** (`src/dns/server.rs`)  
  `sanitize_dns_name` now returns a zero-cost `SanitizedDnsName<'_>` struct
  implementing `Display`. The sanitized string is only allocated when the log
  level is enabled, eliminating a per-query heap allocation at `verbosity: 0/1`.

- **PERF P3 — Parallel upstream health probes** (`src/upstreams.rs`)  
  All upstreams due for a probe are dispatched in parallel via
  `tokio::task::spawn_blocking` + `futures_util::future::join_all`, replacing
  sequential probing. Latency impact on the DNS path during health checks is
  eliminated.

- **PERF P4 — Lock-free `PrefetchTracker`** (`src/dns/prefetch.rs`)  
  `Mutex<HashMap<String, u32>>` replaced with `DashMap<String, AtomicU32,
  ahash::RandomState>`. Increment operations on existing entries are now fully
  lock-free (atomic CAS only); the mutex is only taken on first insertion of a
  new domain.

- **PERF P5 — `/proc/meminfo` read moved to `spawn_blocking`** (`src/dns/server.rs`)  
  Reading `/proc/meminfo` is a blocking syscall; it previously ran on the tokio
  async thread pool. Moved to `spawn_blocking` to avoid stalling async tasks.

- **PERF P6 — Pre-computed `ArcSwap<StatsSnapshot>` for API handlers** (`src/stats.rs`, `src/api/mod.rs`, `src/main.rs`)  
  The `qps_update_loop` (already ticking every second) now also publishes a fresh
  `StatsSnapshot` into an `ArcSwap`. All API handlers (`/stats`, `/health`,
  `/system`, `/stats/stream`) load the pre-computed snapshot with a single atomic
  pointer load instead of calling `stats.snapshot()` which performed ~360 atomic
  loads per request.

- **PERF P7 — Client IP filter pre-formatted once in `LogBuffer::query`** (`src/logbuffer.rs`)  
  The `IpAddr → String` conversion for the client-IP filter is now done once
  before the loop instead of inside, removing N redundant allocations per query.

### Fixed

- **FIX — `GET /api/cache/stats` always returned 0 for hits/misses** (`src/api/mod.rs`)  
  The handler was reading from dead `AppState.cache_hits/misses` fields (never
  incremented). Now reads directly from `s.stats.cache_hits/misses`. The dead
  fields have been removed from `AppState`.

---

### Added

- **FEAT #48 — DNSSEC auto-detection via DO bit / AD bit** (`src/upstreams.rs`)  
  The UDP health probe now includes an EDNS0 OPT RR with the DO bit set (RFC 6891,
  RFC 3225). If the upstream sets the AD (Authenticated Data) bit in its response,
  `dnssec_supported: true` is reported in `GET /api/upstreams`. The field is absent
  from the JSON response when `None` (not yet probed or unhealthy). DoT upstreams
  perform TLS-only probes and always return `None`.

- **FEAT #49 — Rolling latency history per upstream** (`src/upstreams.rs`)  
  Each upstream now maintains a `latency_history` ring buffer of the last 5
  successful probe round-trip times (ms). The field appears as a JSON array in
  `GET /api/upstreams`. Failed probes do not append to the history. The buffer
  is runtime-only and not persisted across restarts.

- **FEAT #50 — `PATCH /api/upstreams/:id` to rename upstreams** (`src/api/mod.rs`,
  `src/upstreams.rs`)  
  Accepts a JSON body `{"name": "My Resolver"}`. Only the `name` field is
  patchable — any other key returns `400 INVALID_FIELD`. An empty string or `null`
  clears the name. The rename is persisted to `upstreams.json` immediately.

- **FEAT #51 — `GET /api/cache/stats` DNS cache counters** (`src/api/mod.rs`,
  `src/main.rs`)  
  New endpoint exposing `cache_hits`, `cache_misses`, `cache_evictions` (AtomicU64
  counters), and `hit_rate_pct` (null when both hits and misses are zero).
  All counters reset to zero on `POST /api/cache/flush`.

---

## [0.6.4] — 2026-05-22

### Fixed

- **FIX #45 — DoT upstream health probe via TCP+TLS** (`src/upstreams.rs`)  
  `probe_upstream` now routes by protocol: UDP upstreams use the existing DNS/UDP
  probe; DoT upstreams open a TCP connection and complete a TLS handshake
  (`rustls::StreamOwned::flush → complete_io`). A successful handshake confirms
  the server is up and speaking TLS — no DNS query is needed.  
  Root CAs: system native certs (`rustls-native-certs`) with fallback to bundled
  WebPKI roots (`webpki-roots`).  
  Cloudflare DoT (1.1.1:853) and Quad9 DoT (9.9.9.9:853) now report
  `healthy: true`.

### Added

- **FEAT #46 — Cache flush cooldown** (`src/api/mod.rs`, `src/config/parser.rs`)  
  `POST /api/cache/flush` returns `429 FLUSH_COOLDOWN` with a `Retry-After` header
  if called within `cache-flush-cooldown` seconds of the previous flush.  
  Config directive: `cache-flush-cooldown: 60` (default 60 s; set to 0 to disable).

- **FEAT #47 — Upstream health and prefetch fields in GET /api/system**
  (`src/api/mod.rs`)  
  Response now includes:
  - `prefetch_enabled: bool` — true when `prefetch: yes` is set in config
  - `upstreams_healthy: u32` — count of upstreams with `healthy == true`
  - `upstreams_total: u32` — total registered upstreams

---

## [0.6.3] — 2026-05-22

### Fixed

- **FIX #40 — Reject unsafe upstream addresses** (`src/api/mod.rs`)  
  `POST /api/upstreams` now returns `400 INVALID_ADDR` for loopback addresses
  (`127.x.x.x`, `::1`) and IPv4 link-local addresses (`169.254.x.x`).
  IPv4 private ranges (RFC 1918) and IPv6 ULA (`fc00::/7`) remain allowed,
  supporting split-horizon deployments with internal resolvers.

- **FIX #41 — Guard last upstream deletion** (`src/api/mod.rs`)  
  `DELETE /api/upstreams/:id` returns `409 LAST_UPSTREAM` when the target is
  the only registered upstream. Deleting all upstreams would leave the resolver
  with an empty forward list; the upstream is left untouched on 409.

- **FIX #42 — Presets DoT: port as separate field** (`src/api/mod.rs`)  
  All `GET /api/upstreams/presets` DoT entries now return
  `"addr":"1.1.1.1","port":853` instead of the previous `"addr":"1.1.1.1@853"`.
  The `@port` syntax was an Unbound config-file convention and must not appear
  in JSON API responses.

- **FIX #43 — Upstream persistence across restarts** (`src/upstreams.rs`, `src/main.rs`)  
  Upstreams added via the REST API are now written to `$BASE_DIR/upstreams.json`
  (atomic write via `.tmp` rename). An optional HMAC sidecar (`.mac`) is
  generated when `RUNBOUND_STORE_KEY` is set. On startup, `load_upstreams` reads
  the file, verifies the HMAC, and `merge_persisted` merges API entries over
  config-file entries (persisted entry wins on `(addr, protocol)` conflict).
  Save is called after every successful `POST` or `DELETE`.

- **FIX #44 — Explicit `port` field on upstreams** (`src/upstreams.rs`, `src/api/mod.rs`)  
  `UpstreamStatus` now carries a `port: u16` field. Defaults: 53 for UDP,
  853 for DoT. Callers may supply an explicit port via `POST /api/upstreams`
  `{"port":N}`; port 0 is rejected with `400 INVALID_PORT`. The explicit port
  is propagated through `upstream_addrs` → `rebuild_and_swap` →
  `build_resolver_from_addrs`, eliminating `@port` string parsing at resolver
  build time.

### Added

- **FEAT #16 — DNS prefetching** (`src/dns/prefetch.rs`, `src/dns/server.rs`,
  `src/config/parser.rs`, `src/main.rs`)  
  When `prefetch: yes` is set in `unbound.conf`, Runbound tracks forwarded-query
  counts per domain in a `PrefetchTracker` (`Arc<Mutex<HashMap<String, u32>>>`).
  Every 30 s a background task calls `take_hot(threshold)` and fires
  `resolver.lookup(name, A)` for each hot domain. All activity is logged at
  `DEBUG` level only — no operational noise.  
  Config directives: `prefetch: yes|no` (default `no`),
  `prefetch-threshold: N` (minimum hit count per window, default `5`).

---

## [0.6.2] — 2026-05-22

### Security (polish pass — static audit)

- **24 `unwrap()` / `expect()` calls hardened** — all replaced with explicit
  panic messages (Mutex/RwLock poison, CSPRNG failure, OnceLock init order)
  or `unreachable!()` with documented invariant (HMAC key length, hardcoded
  IP literals, hyper response builder with fixed headers).
  Clippy flags `-D clippy::unwrap_used -D clippy::expect_used` now pass clean.
  (`src/api/mod.rs`, `src/dns/xdp/worker.rs`, `src/upstreams.rs`, and 6 other files)

- **Log injection guard confirmed** — all `tracing::warn!` / `tracing::error!`
  calls on the XDP hot path reviewed; no raw domain-name data emitted at WARN+
  level (domain names are only logged at DEBUG).

- **Input validation confirmed on all v0.6.2 endpoints** — `POST /api/upstreams`
  rejects unknown protocols (400) and invalid IP addresses (400) before any
  processing; `DELETE /api/upstreams/:id` returns 404 on unknown UUID.

### Added

- **`POST /api/cache/flush`** — Rebuilds the hickory `TokioResolver` with an empty
  cache and swaps it in atomically via `ArcSwap`. Returns
  `{"status":"ok","flushed_entries":N}`. Since hickory has no native flush API,
  rebuild-and-swap is the safest zero-downtime approach.
  (`src/api/mod.rs`, `src/dns/server.rs`)

- **`GET /api/sync/slaves`** — Lists slave nodes that contacted the master in the
  last 5 minutes. Returns `{"slaves":[…],"total":N}`. Returns an empty list with
  a note when the node is not configured as master.
  (`src/api/mod.rs`, `src/sync.rs`)

- **Upstream CRUD via REST API**
  - `POST /api/upstreams` — Add a runtime resolver (`{"addr","protocol","name"}`).
    Validates that `addr` is a valid IP and `protocol` is `"udp"` or `"dot"`.
    Rebuilds the resolver immediately after insertion.
  - `DELETE /api/upstreams/:id` — Remove a resolver by UUID. Rebuilds the resolver.
  - `GET /api/upstreams/presets` — Returns a list of nine well-known resolvers
    (Cloudflare, Google, Quad9, OpenDNS — UDP and DoT variants).
  (`src/api/mod.rs`, `src/upstreams.rs`, `src/dns/server.rs`)

- **`GET /health` cleanup** — Response now contains `version` (from
  `CARGO_PKG_VERSION`) and `uptime_secs`. The `hsm` field has been removed; HSM
  status is available via `GET /api/config`.
  (`src/api/mod.rs`)

- **`last_error` field on feeds** — Each feed in `GET /api/feeds` now includes
  `"last_error": null` when the last update succeeded, or an error string when it
  failed. The field is persisted to `feeds.json`.
  (`src/feeds/mod.rs`)

- **Shared `SharedResolver`** — The DNS resolver is now created once in
  `build_and_launch` and shared between the DNS server handler, the memory-pressure
  guard, and all API handlers that need to rebuild it. This enables cache flush and
  upstream CRUD without restarting the server.
  (`src/dns/server.rs`, `src/main.rs`, `src/api/mod.rs`)

### Fixed

- **`manual_map` pattern** — `if let Some(pos) = ... { Some(...) } else { None }`
  replaced with `.map(|pos| list.remove(pos))` in `src/upstreams.rs:129`.

### Tests

- 39/39 tests pass. +13 tests added for v0.6.2 endpoints covering auth (401),
  invalid input (400/404), and happy path for all new handlers.

---

## [0.6.1] — 2026-05-22

### Fixed

- **All API routes now served under `/api/` prefix (Fix #37)** — `GET /health`
  remains at root (no-auth, load balancer probe). All other endpoints require
  `/api/` prefix and Bearer authentication. Legacy paths (`/stats`, `/dns`, etc.)
  return 404. (`src/api/mod.rs`)

- **UDP/IP checksum 8-byte accumulation (Fix #38)** — `ones_complement_sum()`
  now accumulates 8 bytes per iteration (u64) instead of 2 bytes (u16),
  reducing loop iterations by 4× on the XDP TX hot path.
  (`src/dns/xdp/worker.rs`)

- **`xdp_mode` field in `GET /api/system` (Fix #39)** — Response now includes
  `"xdp_mode": "drv" | "skb" | "disabled"` in addition to the existing
  `xdp_active` boolean, allowing monitoring dashboards to distinguish native
  zero-copy from generic SKB fallback. (`src/api/mod.rs`)

- **`GET /health` response cleaned** — Removed `hsm` field (vestige). Response
  is now `{"status":"ok","version":"0.6.1","uptime_secs":N}`. (`src/api/mod.rs`)

---

## [0.6.0] — 2026-05-22

### Fixed

- **XDP detach on shutdown (Bug A)** — `XdpHandle` now implements `Drop`: calls
  `Xdp::detach(link_id)` to remove the NIC attachment before the process exits.
  Previously the XDP program and XSKMAP lingered in the kernel after shutdown,
  blocking hot-restart and NIC hot-unplug.
  (`src/dns/xdp/loader.rs`)

- **MTU warning before XDP attach (Bug B)** — Added a sysfs MTU check before
  attaching the XDP program. When `MTU > 3506` on virtio-net (single-buffer XDP
  limit), a tracing WARN is emitted and DRV-mode falls back to SKB-mode rather
  than silently degrading performance.
  (`src/dns/xdp/worker.rs`)

- **Emergency XDP escape hatch (Bug C)** — Setting `RUNBOUND_DISABLE_XDP=1` in
  the environment now skips the entire XDP fast path without editing the config
  file. Useful when the host is unreachable after XDP attaches to the wrong NIC.
  (`src/dns/xdp/worker.rs`)

- **Single-queue multi-CPU warning (Bug D)** — When virtio-net reports a single
  RX queue but the host has multiple CPUs, a WARN is logged advising the operator
  to set `queues=<N>` in the VM NIC config for multi-queue XDP performance.
  (`src/dns/xdp/worker.rs`)

- **XSKMAP queue_id bounds check (S1)** — Added an explicit guard: `queue_id ≥ 64`
  (the XSKMAP `max_entries`) now returns an error instead of silently writing
  outside the BPF map.
  (`src/dns/xdp/worker.rs`)

- **UMEM descriptor overflow (S3)** — The hot-loop descriptor bounds check now
  uses `checked_add` to prevent wrapping on 32-bit platforms, and also validates
  `desc.len ≤ FRAME_SIZE` before any UMEM access.
  (`src/dns/xdp/worker.rs`)

- **Rate-limiter deny-by-default for non-IP frames (S4)** — Changed
  `unwrap_or(false)` to `unwrap_or(true)` for frames whose source IP cannot be
  parsed. Non-IP frames that somehow reach port 53 are now silently dropped.
  (`src/dns/xdp/worker.rs`)

- **Unicast MAC in XDP self-test frame (S5)** — `build_test_frame` now reads the
  interface's own unicast MAC from `/sys/class/net/<iface>/address` and uses it
  as the Ethernet destination, replacing the hardcoded broadcast `ff:ff:ff:ff:ff:ff`
  that could trigger ARP storms on busy networks. Falls back to broadcast if the
  address cannot be read.
  (`src/dns/xdp/worker.rs`, `src/dns/xdp/socket.rs`)

- **Latency histogram stuck at 750 ms (Fix #18)** — Extended `HIST_BOUNDS_US`
  from 9 bounds (10 buckets) to 12 bounds (13 buckets), adding finer resolution
  at 250 ms, 1 s, and 3 s. Fixed `percentile_ms()` overflow bucket: the
  `unwrap_or(1_000_000)` midpoint calculation that produced a spurious 750 ms
  artifact is replaced by returning the lower bound of the open-ended bucket.
  (`src/stats.rs`)

- **OISD preset 0 entries (Fix #24)** — The built-in OISD Basic and OISD Big
  presets declared `format: "domains"` but the URLs (`small.oisd.nl`,
  `big.oisd.nl`) serve Adblock Plus format. Changed to `format: "adblock"`.
  (`src/feeds/mod.rs`)

- **Cache overcommit inside cgroup v2 containers (Fix #27)** — `cache_size_from_meminfo()`
  and `read_meminfo()` now check `/sys/fs/cgroup/memory.max` and
  `/sys/fs/cgroup/memory.current` first. When running inside a container with a
  hard memory limit, the cache is sized against the cgroup budget rather than
  the host's `/proc/meminfo`, preventing OOM kills under memory pressure.
  (`src/dns/server.rs`)

### Added

- **`GET /system` endpoint (Feature #19)** — Returns process and host info:
  `version`, `uptime_secs`, `xdp_active`, `cpu_cores`, `cpu_percent`,
  `mem_total_mb`, `mem_avail_mb`, `cache_entries`, `workers`. Useful for
  dashboards and health monitoring without parsing `/stats`. Documented in
  `GET /help`.
  (`src/api/mod.rs`, `src/main.rs`)

---

## [0.5.7] — 2026-05-20

### Fixed
- **verbosity:1 throughput regression** — `with_max_level(Level::WARN)` enabled WARN
  globally for all dependencies (hickory-resolver, hickory-proto, tokio), preventing
  their tracing callsites from being cached as "Never". Under load, this added overhead
  on every DNS resolution even for NOERROR cache hits.
  Fix: replace `with_max_level` with a scoped `EnvFilter` that restricts WARN to
  Runbound's own modules only (`error,runbound=warn`). At `verbosity: 1`, dependency
  crates now run at ERROR level — their callsites are "Never" again.
  Measured impact: QPS ceiling at verbosity:1 restored from 64k → 128k (client NIC
  limit). p99 sustained latency unchanged.

---

## [0.5.5] — 2026-05-20

### Tests

- Added `reload_http_concurrent_429`: HTTP-level regression test for `POST /reload`
  rate limiting. Builds one router, clones it 20 times, sends 20 concurrent requests
  via tokio + Barrier. Asserts ≤2 get 200 and ≥18 get 429. Catches the class of bug
  where independent `AppState` instances bypass the shared `Arc<ReloadLimiter>`.

### Documentation

- `docs/benchmark-2026-05-20.md`: updated to v0.5.4 measurements (QPS 105 724,
  avg 0.128 ms, p99 0.232 ms stress); verbosity baseline changed to 0; added
  regression caveat for v0.5.0–v0.5.3.
- `docs/philosophy.md` (new): design philosophy — memory safety, security surface
  comparison vs BIND9/Unbound, XDP performance tier, commercial licensing.
- `README.md`: "Why Runbound?" section, updated benchmark figures, verbosity tip.

### Chores

- `Cargo.toml`: exclude `runbound.json` (CycloneDX artifact) from crates.io package.

---

## [0.5.4] — 2026-05-20

### Performance

- **`record_query()` hot path at `verbosity: 1`** — NOERROR queries (forwarded, cached,
  local) now bypass `sanitize_dns_name()`, mutex, and `SystemTime::now()` entirely.
  Only notable events (blocked, NXDOMAIN, SERVFAIL, refused/rate-limited) trigger a
  log buffer push at `verbosity: 1`. `/logs` remains functional and shows only
  actionable events. `verbosity: 2` required for full per-query history.

### Notes

- `verbosity: 0` — maximum performance, `/logs` empty.
- `verbosity: 1` — production standard. `/logs` active for notable events only
  (blocked, NXDOMAIN, SERVFAIL, rate-limited). NOERROR hot path: zero overhead.
- `verbosity: 2` — full per-query logging. Degrades p99 under sustained high load.

---

## [0.5.3] — 2026-05-20

### Performance

- **Hot-path regression fixed** (`src/dns/server.rs`) — `record_query()` was calling
  `sanitize_dns_name()` + `ShardedLogBuffer::push_query()` on every DNS query even at
  `verbosity: 0`, because `log_buffer.is_enabled()` returns `true` with the default
  `log-retention: 1000`. `push_query()` executes an atomic increment, a mutex
  acquisition, `SystemTime::now()`, a heap allocation (`client_ip.to_string()`),
  and fixed-size array copies per query. At 105 k QPS under stress load, the queuing
  amplification turned this ~200 ns constant overhead into a +43 % avg latency
  regression vs v0.4.2 (which had no log buffer).

  **Fix:** added `tracing::enabled!(WARN)` as the outer guard. At `verbosity: 0`
  (`Level::ERROR`), WARN events are disabled → the entire block is short-circuited →
  zero allocation, zero mutex, zero `SystemTime::now()` on the hot path.
  `verbosity: 0` is the performance-maximum mode; the REST API `/logs` endpoint
  returns empty in that mode. Use `verbosity: 1` to retain query history.

  Root cause: avg latency 0.160 ms → ≤ 0.120 ms target at `verbosity: 0` (stress benchmark).

---

## [0.5.2] — 2026-05-20

### Fixed

- **ReloadLimiter race condition** (`src/api/mod.rs`) — `POST /reload` did not return
  429 under parallel load. The token bucket used integer arithmetic with a conditional
  `last_refill` update (`if new > 0 { *last = now }`): when `elapsed_ms < 1` the
  timestamp was not advanced, allowing accumulated elapsed time to be double-counted
  by subsequent callers. Rewritten with `f64` arithmetic and an unconditional
  `last_refill = now` on every `check()` call — refill and consumption are
  serialised under a single `std::sync::Mutex` with no TOCTOU possible.
  Burst capacity: 2 requests, rate: 2 req/s.
  Verified: 20 simultaneous threads → ≤ 2 allowed, ≥ 18 denied (`reload_limiter_parallel` test).

---

## [0.5.1] — 2026-05-20

### Fixed

- **Memory pressure: cache floor** (`src/dns/server.rs`, `src/config/parser.rs`) — the
  cache halving loop previously had a hard floor of 512 entries. On memory-constrained
  systems (< 4 GB RAM) where other processes hold significant RSS, the used-memory ratio
  never dropped below the 70 % threshold after halving, causing the cache to be destroyed
  to 0. A new `cache-min-entries` config directive (default: 2048) sets the floor. The
  loop stops halving and logs `WARN cache at minimum size` once the floor is reached.

- **Memory pressure: 5-minute cooldown between halvings** (`src/dns/server.rs`) — a
  `CACHE_HALVE_COOLDOWN` of 300 s prevents the halving loop from firing on every 30 s
  check cycle in a tight loop. At most one halving occurs per 5 minutes.

- **Memory pressure: no-effect detection** (`src/dns/server.rs`) — after each halving,
  the next check cycle compares system memory usage before and after. If used_pct has
  not decreased by at least 5 percentage points, halvings are permanently disabled for
  the current process lifetime and a `WARN` message is emitted explaining the cause and
  pointing to the remediation (increase `MemoryMax` or reduce other workloads).

- **Upstream health checks: exponential backoff** (`src/upstreams.rs`) — a permanently
  unreachable upstream previously generated a `WARN` log every 30 s indefinitely (120+
  lines/hour). Failed upstreams now back off exponentially: 30 s → 60 s → 120 s → 300 s
  cap. The attempt count and next-check interval are included in the `WARN` message.
  When the upstream recovers, the backoff resets to 30 s and an `INFO` recovery message
  is logged.

- **`parse_config_str` compile guard** (`src/lib.rs`) — the function was gated with
  `#[cfg(any(test, feature = "fuzz"))]` but references the `config` module which is only
  available under `feature = "fuzz"`. Changed to `#[cfg(feature = "fuzz")]`, fixing
  `cargo test` failures without the fuzz feature.

---

## [0.5.0] — performance improvements (unreleased at tagging)

### Performance

- **TTL-cap clone eliminated on the common path** (`src/dns/server.rs`) — the upstream
  resolver response was previously cloned unconditionally into a `Vec<Record>` so that
  individual TTLs could be capped to `cache-max-ttl`. The path now performs a single
  `any()` scan first; when no record exceeds the cap (the common case), the original
  borrowed slice is used directly and no allocation occurs.  A clone is still performed
  when at least one TTL actually needs rewriting.

- **`sanitize_dns_name` hot-path allocation removed at verbosity 1** (`src/dns/server.rs`,
  `src/logbuffer.rs`) — the DNS name was sanitized and converted to a `String` on every
  query to feed both the log-buffer ring and the `info!` tracing macro.  At `verbosity: 1`
  (warn) the `info!` macro is a no-op, and the ring buffer may also be disabled
  (`log-retention: 0`).  The sanitise+push block is now guarded by
  `log_buffer.is_enabled() || tracing::enabled!(INFO)`: when both are false the
  `name.to_string()` allocation is skipped entirely.  `ShardedLogBuffer` exposes a new
  `is_enabled() -> bool` method backed by a `total_capacity: usize` field set at
  construction — zero-cost to read on the hot path.

- **Rate-limiter GC contention eliminated** (`src/dns/ratelimit.rs`) — the periodic
  `DashMap::retain()` cleanup was triggered by a shared `AtomicU64` counter incremented
  on every query (`fetch_add(Relaxed)`).  Under high QPS with many threads, all cores
  write to the same counter, causing cache-line bouncing.  The counter is replaced by a
  time-based `next_gc_ns: AtomicU64` (nanoseconds since `RateLimiter::start`).  The hot
  path now performs a single `load(Relaxed)` (read-only, stays in shared cache state
  across all cores) followed by a branch that is almost always not-taken.  One thread per
  10-second window wins a CAS and runs `retain()`; all others see the updated timestamp
  and skip it.

---

## [0.5.0] — 2026-05-20

### Security

- **DoT/DoH TCP cap enforced (VUL-NEW-01)** (`src/dns/server.rs`) — DoT (port 853) and DoH
  (port 443) TCP listeners previously bypassed `run_tcp_with_limit`, allowing a client to open
  more than `TCP_CONN_PER_IP_MAX` (20) concurrent TLS connections per source IP. Both listeners
  now use the same relay pattern as DNS/TCP: a public `TcpListener` feeds `run_tcp_with_limit`,
  which enforces the 20-connection per-IP cap before relaying accepted connections to a loopback
  listener owned by hickory-server. The `TcpConnTracker` is shared across DNS/TCP, DoT, and DoH.

- **IPv6 loopback check before `normalize_tcp_ip` (VUL-NEW-03)** (`src/dns/server.rs`) — `::1`
  was normalized to `::` (all-zeros) before the `is_loopback()` check, causing `::1` connections
  to be subjected to the TCP cap rather than unconditionally allowed as health checks. The
  loopback check now runs on `peer.ip()` directly, before normalization.

- **sysfs path sanitization for interface names (VUL-NEW-04)** (`src/dns/xdp/socket.rs`) — four
  functions that build `/sys/class/net/{iface}/…` paths now call `sanitize_iface_name()` before
  interpolation. The validator rejects names longer than 15 characters (Linux `IFNAMSIZ`) or
  containing characters other than ASCII alphanumeric, hyphen, period, and underscore, returning
  a safe default instead.

- **`CPU_SET` UB guard for `cpu_id >= 1024` (VUL-NEW-05)** (`src/cpu.rs`) — `libc::CPU_SET` is
  undefined behaviour for `cpu_id >= 1024` because `cpu_set_t` is only 128 bytes (1 024 bits).
  `pin_to_cpu` now returns early for any `cpu_id >= 1024` before entering the `unsafe` block.

- **`add_feed_handler` uses `ApiJson` extractor (VUL-NEW-06)** (`src/api/mod.rs`) — the handler
  was using raw `axum::Json`, returning a plain-text 422 on deserialization failure. Changed to
  `ApiJson<AddFeedRequest>` for consistent structured JSON error responses, matching all other
  mutation handlers.

- **`validate_dns_entry` PARSE_FAILED detail redacted (VUL-NEW-07)** (`src/api/mod.rs`) — the
  HTTP 400 error for RR parse failures previously included the full internal RR string in the
  response body, leaking zone-syntax details. The response now returns the static string
  `"Record validation failed"`; the RR string is logged server-side at `warn!` level.

### Known limitations

- **TCP rate limiting via loopback relay (VUL-NEW-02)** — the relay architecture causes hickory
  to see `127.0.0.1` for all TCP clients, so the per-IP DNS rate limiter uses a shared loopback
  bucket for DNS/TCP, DoT, and DoH. The TCP connection cap (20 per source IP) is the primary
  DoS protection. See `docs/security.md#known-limitations` for the full analysis.

### Fixed

- Default API port corrected from `8081` to `8080` in `src/main.rs` (`api_port.unwrap_or`).

---

## [0.4.2] — 2026-05-19

### Added

- **`verbosity: <0–3>` directive in `unbound.conf`** — controls the log level without touching
  the systemd service file. `0` = error, `1` = warn (default), `2` = info (every query),
  `3` = debug. Priority: `RUST_LOG` env var > `verbosity:` directive > default `warn`.
  Mirrors the Unbound `verbosity:` directive so existing configs work unchanged.

- **`verbosity:` performance warning in `--check-config`** — if `verbosity: 2` or higher is
  set on port 53 with rate-limiting active, `--check-config` now emits a `[WARN]` line:
  *"verbosity: 2 (info) logs every query — expect significant CPU overhead above 10k QPS."*

### Changed

- **Default log level is now `warn` (`verbosity: 1`)** — previously the server defaulted to
  `info` (every-query logging) via a hardcoded `Environment="RUST_LOG=runbound=info"` in the
  service file, which silently overrode any `EnvironmentFile`. Production servers no longer
  log every query by default; set `verbosity: 2` explicitly to restore the previous behaviour.

### Fixed

- **Physical core detection corrected for AMD SMT (Threadripper PRO / EPYC)** — the previous
  heuristic keyed on `(cpu_id / 64, core_id)`, which misidentified SMT siblings as separate
  physical cores on AMD CPUs where sibling threads are numbered non-contiguously (e.g. cpu0
  and cpu64 both have `core_id=0` but `cpu_id/64` puts them in different synthetic sockets).
  The fix reads `thread_siblings_list` for each online CPU and keeps only the lowest-numbered
  CPU in each sibling group as the physical-core representative. Behaviour is identical on
  Intel HT and AMD SMT; a 64-core/128-thread EPYC now reports 64 physical cores, not 128.

- **`EnvironmentFile=-/etc/runbound/environment` no longer overridden by the service file** —
  the hardcoded `Environment="RUST_LOG=runbound=info"` line in `runbound.service` was shadowing
  the operator's `EnvironmentFile`. The line is replaced by a comment; `EnvironmentFile` is now
  active. Operators who relied on `RUST_LOG=info` via that line should add `verbosity: 2` to
  their `unbound.conf`.

- **`xdp: no` config directive and `--no-xdp` CLI flag** — disable the AF/XDP kernel-bypass
  fast path at runtime without recompiling. Useful for containers, cloud VMs, and environments
  without `CAP_NET_ADMIN`/`CAP_BPF`/`AF_XDP`. The server falls back to the standard
  `SO_REUSEPORT` path; all DNS and security features remain active.

- **XDP virtual interface detection** — `start_xdp()` now detects virtual interfaces (bridge,
  bond, veth, ipvlan, macvlan) via sysfs before attaching. If a physical parent is found
  (e.g. the first physical port of a Proxmox `vmbr0` bridge), XDP attaches there with a
  warning. If no parent is detectable (isolated veth, internal bridge), XDP is cleanly
  disabled and DNS falls back to `SO_REUSEPORT` — no crash, no silent failure.

- **XDP parent interface resolution** — three-level sysfs search: `lower_*` entries
  (ipvlan / macvlan), `master` symlink (bond slave / bridge port), `brif/` directory
  (physical ports of a bridge). VLAN sub-interfaces (`eth0.10`, `bond0.10`) with
  `DEVTYPE=vlan` in their uevent are treated as physical and accepted directly.

- **XDP fill ring self-test** — before spawning worker threads, `start_xdp_on_iface()`
  validates the UMEM fill ring producer count (must be > 0 after `Umem::new()` seeds it)
  and injects 3 synthetic DNS frames into the TX ring, then polls the RX ring for 200 ms.
  If the fill ring is unseeded or no frames arrive, XDP is disabled with a `WARN` log and
  DNS falls back to the normal path. `--check-config` now also reports whether the
  configured interface is physical or virtual (step 8 in the check output).

- **XDP interface selected via `getifaddrs()` on configured IP** — `iface_for_ip()` now
  calls `getifaddrs()` directly instead of using the routing table. This eliminates wrong
  interface selection when multiple interfaces (e.g. `br-rb` and `veth-rb`) share the same
  `/24` subnet. The routing table heuristic is kept as the fallback when no specific IP is
  configured (`0.0.0.0` or empty).

- **DEBUG log explains interface selection at startup** — when XDP selects an interface,
  a `DEBUG` log line now records whether the selection came from `getifaddrs()` (specific IP)
  or the routing table (default route), making it easier to diagnose wrong-interface issues.

- **`--check-config` RLIMIT_MEMLOCK false positive outside systemd** — the RLIMIT_MEMLOCK
  check now detects whether `--check-config` is running under systemd (via `INVOCATION_ID`
  env var or `/proc/1/comm`). When run outside systemd (e.g. directly from a shell), a
  limited `RLIMIT_MEMLOCK` is reported as `[INFO]` rather than `[WARN]`, because the
  service file's `LimitMEMLOCK=infinity` will apply at runtime regardless.

- **`/reload` rate limit (2 RPS) now correctly enforced** — regression from v0.4.16 where the
  dedicated token bucket was not wired into the request path.

- **TCP per-IP connection cap (20) now enforced for non-loopback sources** — regression from
  v0.4.16; loopback exemption (127.0.0.1 / ::1) remains by design.

### Documentation

- **New [docs/proxmox.md](docs/proxmox.md)** — Proxmox bare-metal XDP setup guide covering:
  bridge `rx_handler` conflict and fix, why a dedicated IP is required, working reference
  architecture (bond → VLAN → bridge → veth pair), AF/XDP generic-mode limitation on
  VLAN sub-interfaces, `ethtool` flow steering for ixgbe/igc, and `RLIMIT_MEMLOCK` setup.

---

## [0.4.16] — 2026-05-19

### Security

- **UMEM descriptor bounds enforced in release builds** — `frame_mut` / `frame` in
  `src/dns/xdp/umem.rs` replaced `debug_assert!` with hard release-mode checks that
  return `None` on out-of-bounds access; the XDP worker skips malformed descriptors
  silently. Hardens against future kernel bugs or UMEM ring corruption without any
  performance impact on the hot path (VUL-2.1).
- **IPv6 rate limiting aggregated at /48 prefix** — the DNS rate limiter now truncates
  IPv6 source addresses to their /48 prefix before bucket lookup.  A flood from a
  single routed /48 block fills at most one bucket instead of exhausting all 65 536
  slots with distinct /128 addresses (VUL-6.1).
- **TCP per-source-IP connection cap (20 connections)** — a pre-accept filter runs
  ahead of hickory-server's TCP listener.  Connections from a source IP (or /48 for
  IPv6) that already holds 20 concurrent connections are dropped immediately, bounded
  the FD exhaustion attack surface.  Loopback addresses are exempt (VUL-6.2).
- **API error responses no longer expose file-system paths** — `e.to_string()` in HTTP
  error bodies is replaced with `sanitize_error()`, which returns `"internal error"` if
  the error string contains `/`.  The full error (with path) is always logged internally
  at `WARN` level (VUL-3.4).
- **`/reload` endpoint rate-limited independently (2 RPS)** — a dedicated token bucket
  separate from the main API limiter prevents an authenticated caller from triggering a
  burst of zone-set rebuilds even at low overall API rates (VUL-3.2).

### Added

- **XDP default feature** — `xdp` is now in the `default` feature set; `cargo build --release`
  produces a binary with the AF/XDP fast path without any extra flags.
  Opt out with `--no-default-features`.

### Changed

- **Sharded log buffer** — the query log ring buffer is now split across 16
  independent shards (per-shard `Mutex<LogBuffer>`). DNS workers round-robin
  across shards with an atomic counter, reducing hot-path Mutex contention by
  up to 16×.  The REST `/logs` read path merges all shards transparently.
- **Lazy `sanitize_dns_name`** — skips the second `String` allocation on the
  common path (name contains only printable ASCII). Control characters are
  still replaced before structured log emission (MED-06).
- **XDP worker CPU affinity** — each XDP worker thread is now pinned to a
  physical core at startup via `sched_setaffinity`, matching the Tokio workers.
  Pinning failure is logged as a warning and never aborts the worker.
- **XDP scratch buffers** — per-batch `Vec` allocations in the XDP poll loop
  are replaced with pre-allocated scratch buffers reused across iterations
  (`rxds`, `tx_descs`, `rx_addrs`, `dns_scratch`).
- **XDP DNS scratch** — the per-packet `dns_out: Vec<u8>` in `process_packet`
  is now a caller-supplied scratch buffer, eliminating heap allocation on every
  local-zone response.
- **Resolver lease** — upstream lookups now use `resolver.load()` instead of
  `load_full()`, avoiding one `Arc` reference-count increment (AtomicUsize CAS)
  per upstream query.
- **Rate limiter single hash** — the `contains_key` capacity pre-check is now
  guarded by `len() >= MAX` first; in the common case (table not full) the hash
  is computed only once by the subsequent `entry(ip)` call.  `or_insert_with`
  avoids constructing the `IpBucket` when the key already exists.
- **CNAME chain pre-alloc** — `follow_local_cname` pre-allocates the chain
  `Vec` to capacity 8 (the maximum chain depth), avoiding up to 3 reallocations.

---

## [0.4.15] — 2026-05-19

### Added

- **`runbound --check-config [path]`** — validate config and systemd security
  parameters without starting the server. Checks: config parse, rate-limit,
  data directory writable, port 53 availability, `CAP_NET_RAW` / `CAP_NET_ADMIN` /
  `CAP_BPF` (XDP capabilities), `RLIMIT_MEMLOCK` (XDP UMEM). Exit codes:
  `0` = clean, `1` = critical error, `2` = warnings only.
- **`docs/hardening.md`** — silent-failure reference for every security-sensitive
  systemd parameter: capabilities, `AF_XDP`, `LimitMEMLOCK`, `MemoryDenyWriteExecute`,
  `ProtectKernelModules`, `rate-limit` semantics. Includes a complete hardened
  service file template.

### Changed

- **README installation section** restructured — recommended automatic script vs
  manual installation, with explicit warning about silent misconfigurations and
  pointer to `docs/hardening.md` and `--check-config`.
- **`docs/security.md`** updated to v0.4.14: memory guard 4-band description,
  auto-sized cache, XDP default-on section, CPU affinity section, `rate-limit: 0`
  corrected, audit findings v0.4.6 → v0.4.14 added.
- All occurrences of "military audit" replaced with "IA audit" across documentation.

---

## [0.4.14] — 2026-05-18

### Added

- **XDP kernel-bypass fast path** — AF_XDP enabled in all published binaries.
  Local-zone queries answered at NIC driver level, bypassing the kernel network
  stack entirely. Validated on virtio (Proxmox VM) and designed for Intel bare
  metal NICs (ixgbe/i40e/ice/igc).

### Fixed

- `LimitMEMLOCK=infinity` added to `runbound.service` and `install.sh` —
  required for AF_XDP UMEM allocation under systemd sandboxing.
- eBPF XDP program rewritten to use constant IHL=20 assumption — eliminates
  BPF verifier rejection (`r3 += r4` prohibited for non-root packet pointers).
  Packets with IP options are passed via `XDP_PASS`.
- XDP errors now produce descriptive `WARN` messages with actionable hints
  instead of a generic failure. Process no longer panics on XDP init failure —
  falls back cleanly to SO_REUSEPORT path.
- `install.sh` now detects Intel XDP-native NICs and configures the service
  file accordingly (`AF_XDP`, `CAP_NET_RAW/ADMIN/BPF`, `LimitMEMLOCK`).

### Notes

- Versions v0.4.10–v0.4.13 had progressive XDP issues (missing feature flag,
  BPF verifier rejection, UMEM allocation failure). v0.4.14 is the first
  stable XDP release.

---

## [0.4.9] — 2026-05-18

### Changed

- **DNS socket workers use physical core count** (HT excluded) instead of `available_parallelism()`. Consistent with the tokio runtime pinning introduced in v0.4.8.

- **Cache size is now auto-sized from available RAM** and adjusts dynamically under memory pressure.
  At startup, Runbound allocates up to 10 % of `MemAvailable` (1 entry ≈ 512 B), clamped to [512, 65 536] entries and logged as `cache_size=N entries (auto-sized from MemAvailable)`.
  The memory guard (every 30 s) now operates in four bands:
  - **< 60 % used** — scale up: restore cache toward the current optimal size (5-minute cooldown between upscales).
  - **60–70 %** — stable, no action.
  - **70–80 %** — halve cache size (floor 512).
  - **≥ 80 %** — recalculate from current RAM, flush rate limiter.

---

## [0.4.8] — 2026-05-18

### Added

- **CPU affinity for tokio worker threads** (`cpu-affinity: yes/no`, default `yes`).
  Each tokio worker is pinned to a distinct physical core, HyperThreading siblings excluded.
  Reduces cache thrashing and improves tail latency consistency at high QPS.
  Startup log reports the number of pinned cores.
  Silent fallback when `/sys` is unavailable (containers, non-Linux).

---

## [0.4.7] — 2026-05-18

### Fixed

- **`rate-limit: 0` now disables rate limiting** (was: refuse every query).
  When `rate-limit` is set to `0` in `unbound.conf`, the token-bucket `check()`
  now returns `true` immediately without touching the bucket table. Previously,
  `rps = 0` produced `burst = 0`, the initial bucket had `tokens = 0`, the
  refill formula added `(0 × elapsed) / 1000 = 0` tokens, and every query was
  answered `REFUSED`.  
  Startup log now prints `rate limiting disabled (rate-limit: 0)` instead of
  `rps=0 burst=0`.

---

## [0.4.6] — 2026-05-18

### Changed — code quality & performance (senior Rust audit follow-up)

- **QUAL-05** (`src/main.rs`) — Decomposed 344-line `main()` into three private helpers:
  `handle_cli_flags()`, `init_runtime()`, `build_and_launch()`. `main()` is now a
  40-line dispatcher with clear separation of concerns.

- **QUAL-06** (`src/dns/server.rs`) — Extracted `handle_local_zone()` and
  `resolve_upstream()` from the 298-line `handle_request()`. Uses `Result<ResponseInfo, R>`
  to safely transfer `ResponseHandler` ownership without cloning. `handle_request()` is
  now a 40-line dispatcher; zero behavior change.

- **QUAL-07** (`src/api/mod.rs`) — Extracted `validate_dns_entry()` (all validation,
  RR construction, parse) and `persist_and_swap()` (mutex, store, ArcSwap) from
  `add_dns_handler()`. Handler body reduced to 3 lines.

- **QUAL-08** (`src/api/mod.rs`) — Extracted `fmt_counter()`, `fmt_gauge()`, and
  `render_prometheus_metrics()` from `metrics_handler()`. Handler body reduced to 2 lines.

- **PERF-02** (`src/dns/server.rs`) — Zero-alloc identity-probe check: static
  `OnceLock<[LowerName; 4]>` initialised once, compared by reference per query.
  Eliminates a `String` allocation on every DNS request.

- **PERF-03/QUAL-03** (`src/upstreams.rs`) — `BIND_V4` / `BIND_V6` are now `const
  SocketAddr` (Rust 1.82+), removing two `.parse().unwrap()` calls in the hot probe path.

- **QUAL-01** (`src/sync.rs`) — `.unwrap()` → `.expect("…")` on all Mutex locks for
  clearer panic diagnostics.

- **QUAL-02** (`src/upstreams.rs`) — `.unwrap()` → `.expect("…")` on all RwLock
  accesses in the health-loop task.

- **QUAL-04** (`src/api/mod.rs`) — Removed duplicate section comment before
  `POST /rotate-key`.

- **QUAL-09** (`src/config/parser.rs`) — Added intent comment above the
  `match key {}` block in `parse_server_directive`.

- **PERF-01 doc** (`docs/api.md`) — Added copy-on-write write-performance note
  under the DNS entries section explaining the `ArcSwap` clone-on-write zone store
  and its lock-free read behaviour.

- **docs** (`docs/code-audit.md`, `docs/security.md`) — Added full 23-finding senior
  Rust audit report (QUAL, PERF, BUILD, ARCH categories); linked from security.md.

---

## [0.4.5] — 2026-05-17

### Security — pentest v0.4.4 follow-up

- **NEW-HIGH — Timing oracle on Bearer token eliminated** (`src/api/mod.rs`)  
  The brute-force brake (`tokio::time::sleep(500 ms)` at ≥ 50 auth failures) was on the
  critical path *after* `constant_time_eq`, creating a measurable timing signal for keys
  that shared a long prefix with the valid key (observed: +183 ms vs. random key).  
  Fix: the sleep is now applied **before** `constant_time_eq`, uniformly to all requests
  when the failure counter is high, so it cannot reveal key content. Post-comparison side
  effects (audit event, periodic `warn!`) are moved to `tokio::spawn` — the 401 is
  returned immediately with no timing leakage.

- **SEC-02 MEDIUM — Domain length validation confirmed + HTTP integration tests** (`src/api/mod.rs`)  
  Pentest claimed "254-char name → HTTP 201". Investigation confirms this is the same false
  positive as the IA audit: the test used a 253-char name + trailing FQDN dot (= 254
  bytes submitted), which is correctly accepted (trailing dot stripped before the 253-char
  check per RFC 1035 §2.3.4). Added three HTTP-level integration tests
  (`dns_name_254_chars_is_rejected`, `blacklist_name_254_chars_is_rejected`,
  `dns_name_253_chars_no_trailing_dot_passes_validation`) that prove the boundary
  end-to-end and will catch any regression.

- **SEC-04 LOW — JSON POST without `Content-Length` now returns 411** (`src/api/mod.rs`)  
  Chunked JSON bodies (no `Content-Length` header) bypassed the early 413 check in the
  security middleware and caused `DefaultBodyLimit` to drop the TCP connection for large
  bodies (observed for 512 KB and 5 MB payloads) instead of returning 413. Fix: JSON
  requests without `Content-Length` now receive **411 Length Required** before reaching
  rate limiting or auth. Non-JSON POST endpoints (`/reload`, `/feeds/update`, etc.)
  are unaffected. New integration tests confirm 411 behaviour.

- **NEW-LOW — UUID null byte TCP drop** (`docs/security-audit.md`)  
  A raw `\x00` in an HTTP path is rejected by hyper at the HTTP/1.1 parse layer before
  any application code runs. Documented as a known hyper limitation; not addressable at
  the application level.

---

## [0.4.4] — 2026-05-17

### Added — supply-chain security & HSM key storage

- **Supply-chain audit tooling** (`deny.toml`, `Makefile`, `docs/audit.md`)  
  Added `cargo-deny` configuration (`deny.toml`) with advisory blocking, license whitelist
  (MIT, Apache-2.0, BSD-2/3, ISC, Zlib, Unicode-3.0, CDLA-Permissive-2.0; AGPL-3.0-or-later
  for runbound itself), and dependency ban rules. New `Makefile` targets: `audit`
  (`cargo audit --deny warnings`), `deny` (`cargo deny check`), `sbom`
  (`cargo cyclonedx --format json`), `audit-full` (all three + `cargo outdated`).
  Full process documented in `docs/audit.md`.

- **HSM key storage via PKCS#11** (`src/hsm.rs`, `docs/hsm.md`)  
  Sensitive key material (REST API Bearer token, JSON store HMAC key) can now be loaded
  from a Hardware Security Module via PKCS#11 (`cryptoki 0.6`). Keys are extracted once at
  startup into `Zeroizing<T>` buffers (memory scrubbed on drop) and the HSM session is
  closed immediately after. Priority chain: HSM > `RUNBOUND_API_KEY`/`RUNBOUND_STORE_KEY`
  env vars > config file > auto-generated. Failure to load keys from a configured HSM is
  **fatal** — no silent fallback. Supported: SoftHSM2 (dev/CI), YubiHSM 2, Nitrokey HSM 2,
  AWS CloudHSM, Thales Luna (any PKCS#11-compliant `.so`). New config directives:
  `hsm-pkcs11-lib`, `hsm-slot`, `hsm-pin` (WARN if in config; prefer `HSM_PIN` env var),
  `hsm-api-key-label`, `hsm-store-key-label`. `/health` now reports `"hsm": true/false`;
  `/config` masks the PIN as `"***"`. Full setup guide in `docs/hsm.md`.

---

## [0.4.3] — 2026-05-17

### Fixed — second IA audit follow-up (all findings closed)

- **SEC-02 INFO — Domain name length validation confirmed correct** (`src/api/mod.rs`)  
  Added six unit tests for `validate_dns_name()` to document and verify RFC 1035 §2.3.4
  compliance: 253-char names accepted, 254-char names rejected, trailing-dot stripping
  before length check, per-label 63-char enforcement. Audit finding was a false positive —
  the auditor counted the trailing dot as part of the name length; the existing `n.len() > 253`
  check (where `n` is the name with the trailing dot stripped) is correct per RFC.

- **SEC-03 LOW — Identity probes inconsistently blocked** (`src/dns/server.rs`)  
  The CHAOS class check (`u16::from(query_class()) == 3`) was in place but hickory
  normalises the CHAOS class to IN before invoking our handler for some query paths,
  causing `version.bind.` to return NOERROR and `hostname.bind.` to return NXDOMAIN
  instead of REFUSED/NOTIMP.  
  Added a defense-in-depth name-based check immediately after the class check: any query
  for `version.bind.`, `hostname.bind.`, `id.server.`, or `version.server.` — regardless
  of query class — now returns REFUSED.

- **DOC-01 INFO — README showed v0.3.4 binary names** (`README.md`)  
  Updated all hardcoded binary filename references from `v0.3.4` to `v0.4.3`.

- **DOC-02 INFO — Non-configurable runtime limits undocumented** (`docs/configuration.md`)  
  Added "Fixed runtime limits" section documenting all compiled-in constants:
  API max payload (64 KB), API rate limit (30 req/s, burst 60), sync ring buffer
  (1,000 events), memory purge thresholds (80 % → 50 %), and hard caps on DNS
  entries (10,000), blacklist entries (100,000), and feed subscriptions (100).

- **DOC-03 INFO — Slave DNS behaviour not documented** (`docs/ha.md`)  
  Added "Slave DNS behaviour" section documenting that replicated entries are served
  by the slave's DNS engine immediately after each sync cycle (fixed in v0.4.2), the
  behaviour on slave restart (zones rebuilt from disk before accepting queries), and
  what happens during a sync cycle (atomic zone-trie updates under mutex).

---

## [0.4.2] — 2026-05-17

### Fixed

- **MEDIUM — Replicated entries not served by DNS on slave nodes** (`src/sync.rs`, `src/main.rs`)  
  `SlaveClient::apply_event` was writing deltas to the on-disk store but never updating
  the in-memory `ArcSwap<LocalZoneSet>` that hickory uses to answer queries. The slave's
  `/dns` API showed the entry; DNS returned NXDOMAIN.  
  `POST /reload` was correctly blocked (`READ_ONLY`) on slaves, leaving no path to apply
  changes without a restart.

  Fix — `SlaveClient` now holds `Arc<ArcSwap<LocalZoneSet>>`, the shared `zones_mutex`,
  and the `UnboundConfig`. For each delta operation:
  - `AddDns` — injects the new record directly into the zone trie (same path as the API
    handler), under `zones_mutex` to prevent concurrent write races.
  - `DeleteDns` — saves the store then calls `build_zone_set()` for a full rebuild
    (deletion requires removing from the trie; incremental removal is not worth the complexity).
  - `AddBlacklist` — calls `override_zone()` on the current zone set (same as the API).
  - `DeleteBlacklist` — full rebuild via `build_zone_set()`.
  - `full_sync` — saves all three stores then rebuilds zones atomically under `zones_mutex`.

  `zones_mutex` is now hoisted before slave/AppState construction in `main.rs` so both
  share the same `Arc<Mutex<()>>` instance — zone mutations from the API and from sync
  are mutually exclusive.

---

## [0.4.1] — 2026-05-17

### Fixed — v0.4.0 audit follow-up (all findings closed)

- **BUG-01 BLOCKING — Sync HTTPS server panic** (`src/main.rs`)  
  rustls 0.23 panics when `ServerConfig::builder()` is called without a default
  `CryptoProvider` installed. Added `rustls::crypto::ring::default_provider().install_default().ok()`
  early in `main()`. Port 8082 now opens; HA master/slave sync is functional.

- **S-10 MEDIUM — CNAME/MX/NS/PTR/SRV target values not length-validated** (`src/api/mod.rs`)  
  `validate_dns_name()` was only applied to the DNS `name` field and blacklist `domain`.
  Target `value` fields for CNAME, MX, NS, PTR, SRV and the `replacement` field for
  NAPTR are now validated as domain names (max 253 chars, labels max 63 chars, RFC 1035
  character set). Rejects RFC-violating records with HTTP 400.

- **S-11 LOW — 1 MB body returned HTTP 429 instead of 413** (`src/api/mod.rs`)  
  `DefaultBodyLimit` fires at extraction time inside the handler, after the rate limiter.
  Added `Content-Length` header pre-check at the top of `security_middleware` — oversized
  requests are rejected with JSON HTTP 413 before the rate-limit token is consumed.

- **Q-01/Q-02/Q-03 LOW — JSON deserialization failures returned plain-text 422** (`src/api/mod.rs`)  
  axum's default `Json<T>` extractor returns a plain-text body on `JsonRejection`.
  Replaced with a custom `ApiJson<T>` extractor (`#[axum::async_trait] FromRequest`)
  that converts all `JsonRejection` variants to structured JSON:
  `{"error": "INVALID_REQUEST", "details": "..."}`. Applied to `POST /dns`,
  `POST /blacklist`, `POST /rotate-key`.

- **Q-04 LOW — GET /logs?page=-1 returned plain-text 400** (`src/api/mod.rs`)  
  `Query<LogsParams>` with `page: usize` would panic the extractor on negative input.
  Changed to `Result<Query<LogsParams>, QueryRejection>` — parse failure returns
  `{"error": "INVALID_PARAM", "details": "..."}` with HTTP 400.

### Documentation

- **`docs/security.md`** — Complete rewrite to reflect v0.4.0 architecture:
  HMAC store integrity, connection-layer SSRF resolver, mutual TLS for DoT,
  rustls 0.23 TLS stack, updated defensive-layers diagram, full audit table
  through v0.4.1.

---

## [0.4.0] — 2026-05-17

### Security — all open audit findings closed

- **HIGH-06 — HMAC-SHA256 store integrity** (`src/integrity.rs`, `src/store.rs`, `src/feeds/mod.rs`)  
  Set `RUNBOUND_STORE_KEY` (env var, hex 32+ bytes or UTF-8) to enable.  
  Every JSON write produces a sidecar `.mac` file (`HMAC-SHA256(content, key)`, hex).  
  On load: missing `.mac` with key set → WARN; HMAC mismatch → ERROR, load refused.  
  Domain caches are regeneratable: mismatch discards cache with WARN and triggers re-fetch.

- **HIGH-07 — hickory 0.24 → 0.26, rustls 0.21 → 0.23** (`Cargo.toml`, `src/dns/server.rs`, `src/sync.rs`)  
  Resolves six CVEs: RUSTSEC-2026-0119, -0037, -2025-0009, -2026-0104, -0098, -0099.  
  rustls 0.23 defaults to TLS 1.3 + approved cipher suites (BSI TR-02102 / NIST SP 800-52 Rev 2).  
  DoQ uses `builder_with_protocol_versions(&[&TLS13])` — Quinn enforces TLS 1.3 only.  
  All `audit.toml` ignores removed.

- **HIGH-08 — DoT mutual TLS** (`src/dns/server.rs`, `src/config/parser.rs`)  
  New `dot-client-auth-ca:` directive. When set, `WebPkiClientVerifier` requires clients  
  to present a certificate signed by the configured CA. DoH and DoQ unaffected.

- **MED-03 — SSRF at TCP connection layer** (`src/feeds/mod.rs`)  
  `SsrfSafeDnsResolver` implements `reqwest::dns::Resolve`.  
  Every hostname resolution by the feed HTTP client filters private/loopback addresses  
  before the TCP connection is established — independent of the system resolver.

- **MED-06 — qname log injection** (`src/dns/server.rs`)  
  `sanitize_dns_name()` replaces ASCII control chars (0x00–0x1F, 0x7F) and non-ASCII  
  bytes with `?` before any structured log emission. Prevents log injection via crafted  
  DNS names in JSON-mode logging (Elasticsearch, Splunk consumers).

- **LOW-03 — Config entry cap** (`src/config/parser.rs`)  
  `MAX_LOCAL_ZONES = MAX_LOCAL_DATA = 1_000_000`. Entries above the cap are dropped  
  with a WARN. Prevents startup OOM from pathological configs.

### Changed

- `hickory-server`, `hickory-resolver`, `hickory-proto` bumped to `0.26`.
- `rustls` bumped to `0.23`, `rustls-pemfile` to `2`, `tokio-rustls` to `0.26`.
- `TokioAsyncResolver` renamed to `TokioResolver` (hickory 0.26 API).
- `ServerFuture` renamed to `Server`; `register_listener` gains `response_buffer_size` arg.
- `MessageResponseBuilder` moved to `hickory_server::zone_handler`.
- `RequestHandler::handle_request` gains `T: Time` type parameter (hickory 0.26).
- `ResolverConfig::new()` → `from_parts(None, vec![], vec![])`.
- `record.name()` → `record.name` field access (hickory 0.26 public fields).
- `Record::new()` → `Record::from_rdata(name, ttl, rdata)`.
- rustls `Certificate`/`PrivateKey` → `pki_types::{CertificateDer, PrivateKeyDer}`.
- `ServerCertVerifier` → `rustls::client::danger::ServerCertVerifier`.
- `verify_server_cert` no longer takes `_scts`; uses `UnixTime` instead of `SystemTime`.

---

## [0.3.5] — 2026-05-17

### Fixed

- **`GET /config` missing `log_retention` / `log_client_ip`** — the two GDPR privacy
  directives added in v0.3.4 were not exposed in the config snapshot endpoint.
  Both fields now appear in the response alongside all other runtime parameters.
- **CHAOS class returning NOERROR** — confirmed that `version.bind CH TXT` and
  `hostname.bind CH TXT` correctly return `NOTIMP` (SEC-10). The finding was caused by
  the pentest tooling hitting the system Unbound on port 53 rather than Runbound.
  No code change required; this entry documents the root-cause analysis.

---

## [0.3.4] — 2026-05-17

### Added

- **AGPL-3.0 dual license** — Runbound switches from PolyForm Noncommercial to AGPL-3.0
  for open-source use. A commercial license remains available for organizations that
  cannot comply with the AGPL (see `COMMERCIAL_LICENSE.md`).
- **SPDX headers** — every `.rs` source file now carries `SPDX-License-Identifier: AGPL-3.0-or-later`.
- **`log-retention` config directive** — controls the size of the in-RAM query log ring
  buffer (default: 1000). Set to `0` to disable `/logs` entirely and hold no client IPs
  in memory (GDPR data minimisation).
- **`log-client-ip` config directive** — when set to `no`, client IPs are replaced with
  `[redacted]` before being stored in the ring buffer and the logfile. The audit log is
  unaffected (IPs are required for PCI-DSS / NIS2 traceability).
- **`DELETE /logs`** — authenticated endpoint that clears the in-memory query log ring
  buffer and records the action in the audit log (`event: "logs_clear"`). Allows operators
  to respond to GDPR right-to-erasure requests without restarting the server.
- **`docs/gdpr.md`** — GDPR compliance guide covering data inventory, operator
  responsibilities, and concrete configuration recipes.
- **`CLA.md` rewrite** — plain-language one-page CLA; grants the maintainer the right
  to redistribute contributions under any license (AGPL or commercial) with mandatory
  changelog attribution.

---

## [0.3.3] — 2026-05-17

### Fixed

- **Bug 1 — `POST /rotate-key` silent no-op** (`src/api/mod.rs`)  
  The handler was reading `RUNBOUND_API_KEY` from the process environment,
  which is frozen at startup — updating the systemd EnvironmentFile without
  a restart had no effect. New contract: caller sends `{"new_key":"<32+ chars>"}`
  in the JSON body. Validates minimum length (32 chars), rejects control characters,
  atomically swaps the in-memory key, and persists to `base_dir/api.key` (chmod 600).

- **Bug 2 — CHAOS class queries returned NOERROR** (`src/dns/server.rs`)  
  The `DNSClass::CH` enum comparison could fail when hickory parsed the class
  as `Unknown(3)` for some query variants, bypassing the filter. Fixed by
  comparing the numeric wire value directly (`u16::from(class) == 3`).
  Response changed from REFUSED to NOTIMP per RFC 5358 §4.

- **Bug 3 — Payloads ≥512 KB dropped TCP connection instead of HTTP 413** (`src/api/mod.rs`)  
  `tower_http::RequestBodyLimitLayer` drops the TCP connection for very large
  payloads instead of returning 413. Replaced with `axum::extract::DefaultBodyLimit::max()`
  which enforces the limit at the stream level and always sends a proper 413
  before reading the body into RAM, regardless of payload size.

- **Bug 4 — Negative TTL returned plain-text 422 instead of JSON** (`src/api/mod.rs`)  
  TTL field changed from `u32` to `i64` so serde accepts negative values
  without aborting deserialization. Explicit validation now returns
  `{"error":"INVALID_TTL","details":"TTL must be between 0 and 2147483647"}` HTTP 422.

### Security (audit)

- **[HIGH] Sync Bearer comparison was not constant-time** (`src/sync.rs`)  
  `auth != format!(...)` string comparison exits early on the first differing
  byte — a timing oracle for the sync-key length and content. Replaced with
  `subtle::ConstantTimeEq`.

- **[MEDIUM] Feed URLs with embedded credentials accepted** (`src/feeds/mod.rs`)  
  `https://user:pass@host/path` would strip credentials for the SSRF host check
  but store the URL with credentials in the config. Now explicitly rejected with
  a clear error message.

- **[MEDIUM] `rate-limit: 18446744073709551615` silently disabled rate limiting** (`src/config/parser.rs`)  
  Extreme values parsed as `u64::MAX` effectively disable the rate limiter.
  Capped at 1,000,000 rps.

- **[LOW] `unwrap()` on production RwLock/Mutex** (`src/api/mod.rs`, `src/store.rs`)  
  `upstreams.read().unwrap()`, `log_buffer.lock().unwrap()`, and two
  `path.parent().unwrap()` calls replaced with explicit error handling that
  returns HTTP 500 JSON or propagates `AppError::Internal`.

### Audit findings (acknowledged, not fixed — target v0.4.0)

Six CVEs in `hickory-proto 0.24` transitive dependencies require upgrading
to `hickory 0.26`. The migration breaks ~50 API sites across the codebase
(rustls 0.21→0.23, renamed types, restructured modules) and is tracked for
v0.4.0. See `audit.toml` for per-CVE exposure analysis and mitigations.

- RUSTSEC-2026-0119 — hickory-proto: O(n²) name compression (CPU exhaustion)
- RUSTSEC-2026-0037 — quinn-proto: DoS (CRITICAL — mitigate: firewall 853/UDP)
- RUSTSEC-2025-0009 — ring: AES panic with overflow checks (release builds unaffected)
- RUSTSEC-2026-0104/98/99 — rustls-webpki: CRL/name constraint issues (no exploitable path)

---

## [0.3.2] — 2026-05-17

### Added

- **`GET /metrics` — Prometheus/OpenMetrics exposition** (`src/api/mod.rs`)  
  All stats counters and gauges are now available in Prometheus text format
  (`text/plain; version=0.0.4`). Compatible with Prometheus, Grafana Agent,
  VictoriaMetrics, and OTEL Collector. Requires Bearer authentication.

  Exposed metrics: `runbound_queries_total`, `runbound_blocked_total`,
  `runbound_nxdomain_total`, `runbound_refused_total`, `runbound_servfail_total`,
  `runbound_forwarded_total`, `runbound_local_hits_total`, `runbound_uptime_seconds`,
  `runbound_qps{window}`, `runbound_latency_ms{quantile}`,
  `runbound_cache_hit_rate`, `runbound_cache_entries`,
  `runbound_dnssec_total{status}`.

- **`POST /rotate-key` — live API key rotation without restart** (`src/api/mod.rs`)  
  Atomically replaces the active Bearer token from the `RUNBOUND_API_KEY` environment
  variable. The old key is invalidated immediately. DNS service is uninterrupted.
  Designed for PCI-DSS and NIS2 periodic key rotation requirements. The rotation is
  recorded in the audit log as a `ConfigReload` event.

  The API key is now stored in an `ArcSwap<String>` (previously `OnceLock<String>`)
  to allow lock-free atomic swaps on every auth check with zero overhead.

### Fixed (documentation)

- **DoH not documented in `docs/tls.md`** — Added full DoH section: port 443,
  path `/dns-query`, `curl`/`kdig`/`doggo` test examples, browser and OS client
  configuration (Firefox, Chrome, Windows 11, Android). All three encrypted protocols
  (DoT, DoH, DoQ) now documented with a comparison table.

- **ACME timer ambiguity in `docs/configuration.md`** — Clarified that the "60 days"
  value is the cert file mtime threshold (not a configurable TTL). Let's Encrypt issues
  90-day certs; a 60-day mtime check triggers renewal with ≥ 30 days of validity
  remaining. Added a summary line: check interval = 6 h · threshold = 60 days ·
  minimum remaining validity = 30 days.

- **`/help` auth ambiguity** — `GET /help` requires Bearer authentication on all nodes.
  Documentation harmonised across `docs/api.md` with a security rationale note
  (fingerprinting prevention, consistent with AUDIT-HIGH-02).

- **`access-control` default not explicit** — The implicit `refuse` catch-all when no
  rule matches is now shown as a row in the action table with a bold label and a note
  that an empty `access-control` block blocks all clients.

- **`sync-cert.pem` path undocumented in `docs/ha.md`** — Added a file reference table
  documenting the exact paths for `sync-cert.pem`, `sync-key.pem`, and
  `sync-master.fingerprint`. Noted that all runtime files follow the config file
  directory (`base_dir`), with guidance for non-standard install paths and re-TOFU
  procedure.

---

## [0.3.1] — 2026-05-17

### Added

- **Immutable HMAC-SHA256 audit log** (`src/audit.rs`, `src/config/parser.rs`, `src/api/mod.rs`, `src/main.rs`)  
  Every security-relevant API operation is written to an append-only structured log
  (`audit.log` in the config directory) with a monotonic sequence number and an
  HMAC-SHA256 chain. Tampering with any line — or deleting lines — breaks the chain
  and is detectable by replaying `mac = HMAC-SHA256(key, seq || ts || event || fields)`.

  The log is driven by a dedicated tokio task over an unbounded channel — callers
  (API handlers) never block on the hot path. The HMAC key is auto-generated on first
  run (256-bit, chmod 600, `audit-hmac.key`). The monotonic sequence is persisted in
  `audit-seq.dat` (flushed every 100 events and on clean shutdown) so it survives restarts.

  **Events logged:** `startup`, `shutdown`, `dns_add`, `dns_delete`, `blacklist_add`,
  `blacklist_delete`, `feed_add`, `feed_delete`, `config_reload`, `auth_failure`.

  **New endpoint:** `GET /audit/tail?n=100` — returns the last N lines (max 1,000) as a
  JSON array. Useful for SIEM integration.

  **Config directives:**
  ```
  audit-log:          yes                      # default: no
  audit-log-path:     /var/log/runbound/audit.log  # default: <config_dir>/audit.log
  audit-log-hmac-key: "hex-or-raw-key"         # default: auto-generated
  ```

- **Automatic Let's Encrypt certificate provisioning via ACME** (`src/acme.rs`, `src/config/parser.rs`, `src/main.rs`)  
  Runbound can now request, obtain, and renew TLS certificates from Let's Encrypt
  automatically — no certbot, no manual renewal scripts.

  Uses ACME HTTP-01 challenge: a temporary HTTP listener on port 80 is started only
  during the challenge phase, then shut down. The cert is written atomically via
  temp-file → rename. A background task checks every 6 hours and renews when
  ≤ 30 days remain (Let's Encrypt certs are valid 90 days).

  Transport: `instant-acme 0.8.5` (ring backend) with a custom `reqwest`-based HTTP
  client, avoiding the `rustls 0.21 / 0.23` version conflict with hickory-server.

  **Config directives:**
  ```
  acme-email:          admin@example.com    # Let's Encrypt account contact
  acme-domain:         dns.example.com      # SANs (repeat for multiple)
  acme-cache-dir:      /etc/runbound/acme   # account credentials + temp files
  acme-staging:        no                   # yes = use LE Staging API (testing)
  acme-challenge-port: 80                   # HTTP-01 challenge port (default: 80)
  ```

  The cert and key paths come from `tls-service-pem` / `tls-service-key` (or fall back
  to `cert.pem` / `key.pem` in the config directory). Once obtained, DoT/DoH/DoQ are
  active with a publicly trusted certificate.

- **DNSSEC full local validation stats** (`src/stats.rs`, `src/dns/server.rs`, `src/api/mod.rs`)  
  New config directive `dnssec-log-bogus: yes` (default: no) triggers WARN logs for
  every DNSSEC-bogus query. Bogus queries (`RrsigsNotPresent`) return SERVFAIL and
  increment `dnssec.bogus`. Secure responses (RRSIG present) increment `dnssec.secure`;
  unsigned queries increment `dnssec.insecure`. All counters are `AtomicU64`.  
  Exposed in `GET /stats` as:
  ```json
  "dnssec": {"secure": 1204, "bogus": 3, "insecure": 8821}
  ```

- **Runtime files relative to config directory** (`src/runtime.rs`)  
  All runtime files (`api.key`, `dns_entries.json`, `blacklist.json`, `feeds.json`,
  `sync-cert.pem`, `audit.log`, …) are now stored in the **same directory as the config
  file** — not hardcoded under `/etc/runbound/`. This allows a master and slave to run
  on the same machine using separate config directories without any path collisions.

### Fixed

- All pre-existing `cargo clippy -- -D warnings` failures resolved:
  `clippy::upper_case_acronyms` on `DnsType` variants; `trim_split_whitespace`;
  `is_multiple_of`; redundant `into_iter()`; `map_err` → `inspect_err` in XDP socket;
  `last()` on `DoubleEndedIterator`; manual prefix stripping; double-`Ok` + `?`;
  `unwrap()` after `is_some()`.

---

## [0.3.0] — 2026-05-17

### Added

- **`GET /stats` — 9 new fields** (`src/stats.rs`, `src/api/mod.rs`)  
  The stats endpoint now reports QPS sliding window (`qps_1m`, `qps_5m`, all-time `qps_peak`),
  latency percentiles (`latency_p50_ms`, `latency_p95_ms`, `latency_p99_ms`), cache metrics
  (`cache_hit_rate`, `cache_entries`), and local zone resolution count (`local_hits`).  
  Implementation: fixed 10-bucket latency histogram (zero allocation per query via `partition_point`);
  300-slot QPS ring buffer (`AtomicU64` × 300, updated by a 1-second background task);
  cache hit detection via timing heuristic (< 2 ms = hickory in-process cache hit).
  All hot-path counters are `AtomicU64` — no mutex, no allocation on the DNS query path.

- **`GET /stats/stream` — Server-Sent Events live stats** (`src/api/mod.rs`)  
  Streams a JSON stats snapshot every second using SSE (`text/event-stream`).
  Implementation uses `futures_util::stream::unfold` — no background task or channel leak.
  When the client disconnects, axum drops the SSE stream and cancels the in-flight sleep.
  `X-Accel-Buffering: no` header ensures nginx proxies events immediately.

- **`GET /upstreams` — upstream DNS health check** (`src/upstreams.rs`, `src/api/mod.rs`)  
  Reports reachability and latency for each configured `forward-addr`.
  Probed every 30 seconds via a minimal RFC 1035 UDP DNS query (17-byte hardcoded packet for `. IN A`).
  2-second per-probe timeout. WARN log on failure. Response includes `healthy` / `total` counts.

- **`GET /logs` — ring buffer query log** (`src/logbuffer.rs`, `src/dns/server.rs`, `src/api/mod.rs`)  
  Captures up to 10,000 recent DNS queries in a fixed-size pre-allocated ring buffer.
  Each `LogEntry` is a fixed-size struct (no heap pointers) — zero allocation after startup.
  Fields: timestamp (RFC 3339 UTC), DNS name, client IP, qtype, action, elapsed ms.  
  Actions: `forwarded`, `cached`, `local`, `blocked`, `nxdomain`, `refused`, `servfail`.  
  Query params: `limit` (default 100, max 1,000), `page` (0-based), `action`, `client` (IP), `since` (Unix timestamp).
  Invalid params return `400 Bad Request`; `limit > 1000` returns `422 Unprocessable Entity`.

- **Slave/master replication** (`src/sync.rs`, `src/config/parser.rs`, `src/api/mod.rs`, `src/main.rs`)  
  Runbound now supports a master/slave topology for high-availability DNS. A master node
  records every write operation (DNS entries, blacklist, feeds) in a delta journal and serves
  it over a dedicated HTTPS sync port. Slave nodes poll the master, apply deltas, and
  rebuild their local zone set on change — with zero API downtime.

  **Architecture:**
  - `SyncJournal` — ring buffer of 1,000 `SyncEvent`s (`VecDeque<SyncEvent>`, monotonic `AtomicU64` seq).
    When a slave falls more than 1,000 events behind, it performs a full config snapshot instead.
  - **Sync endpoints** (master, HTTPS on `sync-port`, separate from REST API):
    - `GET /sync/cert` — returns the master's SHA-256 cert fingerprint (public, no auth required, for TOFU bootstrap).
    - `GET /sync/state` — current journal sequence number.
    - `GET /sync/config` — full state snapshot (DNS + blacklist + feeds + seq). Used on first sync or after 410.
    - `GET /sync/delta?since=N` — events with seq ≥ N. Returns 410 Gone when N is too old.
  - **TOFU TLS** — master auto-generates a self-signed certificate via rcgen (`/etc/runbound/sync-cert.pem`).
    On first slave connect, the cert fingerprint is downloaded from `/sync/cert` and cross-verified
    against the TLS handshake, then saved to `/etc/runbound/sync-master.fingerprint` with a WARN log.
    All subsequent connections use rustls pinned cert verification (SHA-256 of DER). No CA or PKI needed.
  - **Slave read-only** — when `mode: slave`, all non-GET API requests return `503 READ_ONLY`.
    The slave applies changes exclusively via the replication protocol.
  - **Slave feed updates** — on `UpdateFeed` events, the slave re-downloads the same URL stored
    in its local feeds config, without requiring the master to forward feed content.
  - **Exponential backoff** — on network errors, retry delay doubles (5 s → 10 → 20 → … cap 300 s).
    On 410 Gone, a full sync is triggered immediately without waiting for the backoff interval.

  **Configuration (master):**
  ```
  server:
      mode:      master        # default — may be omitted
      sync-port: 8082          # enables HTTPS sync server on 0.0.0.0:8082
      sync-key:  <shared-secret>
  ```

  **Configuration (slave):**
  ```
  server:
      mode:          slave
      sync-master:   192.168.1.10:8082    # master ip:port
      sync-key:      <same-shared-secret>
      sync-interval: 30                   # poll interval in seconds (default: 30)
  ```

### Changed

- **`blocked_percent` — now a float** (`src/api/mod.rs`)  
  Previously rounded to `u64`, now `f64` with one decimal place (e.g. `4.7` instead of `5`).

- **`GET /help` — updated endpoint list** to include `/stats/stream`, `/upstreams`, `/logs`.

---

## [0.2.5] — 2026-05-17

### Security

- **SEC-HIGH-02 — `/help` endpoint now requires Bearer authentication** (`src/api/mod.rs`)  
  `/help` was previously public, exposing the endpoint list and RFCs to unauthenticated callers.
  Fingerprinting a running Runbound instance and cross-referencing with known CVEs is now blocked.
  All endpoints — including `/help` — now require a valid Bearer token.

- **SEC-MED-05 — Global auth-failure counter with automated lockout** (`src/api/mod.rs`)  
  Repeated authentication failures now increment a global `AUTH_FAILURES` AtomicU64 counter.
  Every 10th failure emits a `WARN`-level log. After 50 consecutive failures a 500 ms delay is
  injected before the 401 response, slowing automated guessing without blocking legitimate retries.
  The counter resets on every successful authentication.

- **SEC-HIGH-05 — Rate limiter bucket exhaustion mitigation** (`src/dns/ratelimit.rs`)  
  When the bucket table reaches `MAX_RATE_LIMIT_BUCKETS = 65,536`, the old code silently refused
  all new source IPs — enabling a targeted DoS by flooding from 65 k distinct IPs to fill the table.
  On exhaustion, buckets idle for more than 10 s are now aggressively evicted before dropping the
  new IP. Under a real flood (all buckets active) the drop still fires; under a spoofed exhaustion
  attack with stale buckets, legitimate IPs are admitted after eviction.

- **PENTEST-01 — HTTP feed URLs upgraded from warn to hard reject** (`src/feeds/mod.rs`)  
  SEC-08 (v0.2.0) added a `WARN`-level log for `http://` feed subscriptions but still accepted
  and fetched them. A pentest confirmed that a man-in-the-middle between Runbound and the feed
  server could inject arbitrary block-list entries with no cryptographic protection.
  `validate_feed_url()` now returns `400 Bad Request` for any non-HTTPS URL. HTTP feeds are
  completely blocked at the API layer; the downstream `reqwest` call is never reached.

- **PENTEST-02 — Feed update did not rebuild zone set; blocked stats undercounted** (`src/api/mod.rs`)  
  `POST /feeds/update` and `POST /feeds/:id/update` fetched and cached feed data but never
  called `build_zone_set()`. Feed domains were never added to the active `ArcSwap<LocalZoneSet>`,
  so they were not resolved as blocked and the `/stats` blocked counter was understated.
  Both handlers now call `build_zone_set()` and atomically swap the zone pointer after a
  successful fetch. Feed blocks are effective immediately without a manual `/reload`.

- **PENTEST-03 — CRLF injection in DNS entry text fields** (`src/api/mod.rs`)  
  DNS record fields that are embedded verbatim into zone-file-style RR strings (`value`,
  `tag`, `description`, `fingerprint`, `cert_data`, `services`, `regexp`, `replacement`,
  `flags_naptr`) and the blacklist `description` field accepted arbitrary bytes, including
  `\r` and `\n`. A crafted entry could inject additional resource records into the in-memory
  zone when the RR string was parsed downstream.
  A new `validate_no_control_chars()` helper rejects any byte below `0x20` or equal to
  `0x7f` (DEL) across all affected fields, returning `400 Bad Request`.

- **PENTEST-04 — TTL exceeding RFC 2181 §8 maximum accepted silently** (`src/api/mod.rs`)  
  RFC 2181 §8 defines the maximum DNS TTL as 2,147,483,647 (signed 32-bit maximum).
  `POST /dns` accepted any `u32` TTL (up to ~4.29 billion) and silently capped it at 86,400 s.
  An out-of-range TTL now returns `400 Bad Request` with `INVALID_TTL` before the entry is
  validated further, matching RFC-compliant resolver behaviour.

- **PENTEST-05 — version.bind CHAOS query disclosed server identity** (`src/dns/server.rs`)  
  `dig CHAOS TXT version.bind @<host>` returned identifying information from the underlying
  hickory-server resolver. CHAOS class (`DNSClass::CH`) is now intercepted at the start of
  `handle_request()`, before any zone lookup, and answered with REFUSED.
  The check precedes the existing ANY-query block so it cannot be bypassed by query type.

### Fixed

- **TCP / DoT / DoH / DoQ idle timeout 5 s → 30 s** (`src/dns/server.rs`)  
  The 5-second TCP idle timeout was too aggressive for DNSSEC responses (large RRSIG/DNSKEY
  payloads can take several round-trips). All TCP listeners now use a 30-second timeout.

- **Hand-rolled UTC timestamp replaced with humantime** (`src/feeds/mod.rs`)  
  `utc_now_rfc3339()` implemented a custom date/time calculation (including leap-year arithmetic)
  that had no fuzz coverage and could have edge-case bugs around year boundaries.
  Replaced with `humantime::format_rfc3339(SystemTime::now())` — a well-tested library already
  in the dependency graph.

### Added

- **`GET /health` endpoint** (`src/api/mod.rs`)  
  Liveness probe — returns `{"status":"ok","uptime_secs":…,"queries":…}`.
  Useful for load balancers and monitoring systems. Previously returned HTTP 404.

- **`GET /stats` endpoint** (`src/api/mod.rs`)  
  Query statistics: total, blocked, forwarded, NXDOMAIN, REFUSED, SERVFAIL,
  `blocked_percent`, and `uptime_secs`. Counters are maintained as `AtomicU64` in the
  DNS handler hot path; reads from `/stats` never contend with query processing.
  Previously returned HTTP 404.

- **`GET /config` endpoint** (`src/api/mod.rs`)  
  Dumps the active configuration (sanitised — `api-key` is intentionally omitted).
  Previously returned HTTP 404.

- **`POST /reload` endpoint** (`src/api/mod.rs`)  
  Hot-reload equivalent: re-parses `runbound.conf` and rebuilds all in-memory DNS data
  atomically via ArcSwap. Equivalent to `systemctl reload runbound` (SIGHUP).
  Previously returned HTTP 404.

- **`dnssec-validation` config directive** (`src/config/parser.rs`, `src/dns/server.rs`)  
  Mirrors Unbound's `dnssec-validation` directive. When set to `yes`, hickory-resolver
  performs local DNSSEC re-validation. Default remains `no` (forwarder mode — trust upstream
  AD bit) because forwarders strip RRSIGs and local re-validation would SERVFAIL every
  signed domain. Enable only for full recursive deployments with complete RRSIG chains.

- **`src/stats.rs`** — `Stats` / `StatsSnapshot` types with per-outcome AtomicU64 counters,
  shared between `RunboundHandler` and `AppState` via `Arc<Stats>`.

---

## [0.2.4] — 2026-05-16

### Security

- **SEC-CRIT-03 — IPv6 ULA / link-local addresses bypassed SSRF guard** (`src/feeds/mod.rs`)  
  `is_private_ip()` only covered `::1` and `::`. ULA (`fc00::/7`), link-local (`fe80::/10`),
  IPv4-mapped (`::ffff:0:0/96`), and NAT64 well-known (`100::/64`) ranges were not blocked.
  A feed hostname resolving to `fd00::1` or `fe80::1` bypassed the SSRF check entirely.
  All IPv6 private/internal ranges are now covered.

- **SEC-CRIT-04 — SSRF redirect policy only inspected literal IP destinations** (`src/feeds/mod.rs`)  
  A feed server could redirect to `http://internal.corp/data` and the redirect would be
  followed without any hostname validation. The redirect policy now blocks redirects to
  well-known internal hostnames (`.local`, `.internal`, `.corp`, `.lan`, `localhost`,
  `169.254.169.254`, `metadata.google.internal`).

- **SEC-HIGH-01 — No feed subscription count limit** (`src/api/mod.rs`)  
  An authenticated client could add unlimited feeds. Since each feed can download up to
  100 MiB, this enabled an authenticated DoS via memory/disk exhaustion.
  Hard cap `MAX_FEEDS = 100` is now enforced on `POST /feeds`.

- **SEC-HIGH-03 — Silent fallback to Cloudflare when no forward-zone configured** (`src/dns/server.rs`)  
  Misconfigured or stripped config files caused all queries to be silently routed to
  Cloudflare. A `WARN`-level log is now emitted to alert operators.

- **SEC-MED-04 — XDP frame_mut() had no bounds assertion** (`src/dns/xdp/umem.rs`)  
  A malformed XDP ring descriptor could produce an out-of-bounds write in the XDP fast path.
  `debug_assert!` bounds checks added to `frame_mut()` and `frame()`.

- **SEC-MED-07 — api-key in config file accepted silently** (`src/config/parser.rs`)  
  Using `api-key:` in `runbound.conf` stores the token in cleartext. A `WARN`-level log
  is now emitted directing operators to use `RUNBOUND_API_KEY` in the env file instead.

### Fixed

- **API docs: ghost endpoints removed** (`docs/api.md`)  
  `GET /health`, `GET /stats`, `GET /config`, and `POST /reload` were documented as
  implemented but returned HTTP 404. The docs now accurately reflect the implemented
  endpoints and note the missing ones as open work items.

- **API docs: path parameters corrected** (`docs/api.md`)  
  `DELETE /dns/{name}` and `DELETE /feeds/{name}` used name-based paths in the docs
  but the actual implementation uses UUID (`DELETE /dns/:id`, `DELETE /feeds/:id`).
  `POST /feeds/{name}/refresh` → `POST /feeds/:id/update`. All corrected.

- **systemd.md: SIGHUP table: ACL is NOT reloaded** (`docs/systemd.md`)  
  The hot-reload table incorrectly stated that `access-control` rules are reloaded on
  SIGHUP. The `Arc<Acl>` is built once at startup; only local zones, DNS entries,
  blacklist, and feed entries are reloaded. ACL changes require a full restart.

### Added

- **`docs/security-audit.md`** — Full white-box security audit (23 findings, CRIT→LOW).

---

## [0.2.3] — 2026-05-16

### Fixed

- **`/etc/guestdns/` → `/etc/runbound/`** (`src/feeds/mod.rs`, `src/main.rs`)  
  Feed subscriptions and cache were stored in `/etc/guestdns/feeds.json` and
  `/etc/guestdns/feed_cache/` — a leftover path from the project's internal predecessor.
  All paths are now under `/etc/runbound/`, consistent with every other Runbound data file.
  The `--help` text is also corrected.

- **SIGHUP now hot-reloads zones instead of killing the process** (`src/main.rs`)  
  `systemctl reload runbound` previously terminated the DNS server because SIGHUP had no
  handler and the OS default action (terminate) fired. A `tokio::signal::unix` handler is
  now installed at startup: on SIGHUP, the config file is re-parsed and all local zones,
  persisted DNS entries, blacklist, and feed entries are rebuilt atomically via ArcSwap.
  In-flight DNS queries are not interrupted. `ExecReload=/bin/kill -HUP $MAINPID` in the
  systemd unit file now works correctly.

- **OISD Full preset URL returned HTTP 410 Gone** (`src/feeds/mod.rs`)  
  `https://dbl.oisd.nl/` was deprecated upstream. Updated to `https://big.oisd.nl/`
  (domains format). OISD Basic updated from `https://dbl.oisd.nl/basic/` to
  `https://small.oisd.nl/` (domains format).

- **Local CNAME chain not followed** (`src/dns/server.rs`)  
  A query for `alias.local A` where `alias.local CNAME tardis.local` and
  `tardis.local A 192.168.1.1` were both local-data entries returned an empty answer.
  RFC 1034 §3.6.2 requires the resolver to follow the chain and include all records.
  `follow_local_cname()` now walks up to 8 hops within local zones and returns the
  full CNAME chain + final A/AAAA records in one response.

- **Download URLs in docs were unversioned** (`README.md`, `docs/unbound-migration.md`)  
  Links pointed to `runbound-x86_64-linux-musl` but release assets are named
  `runbound-vX.Y.Z-x86_64-linux-musl`. Following the doc URL caused a 404.
  All references now include the version prefix and note to check the releases page.

- **`/health` documented as public — actually requires Bearer token** (`docs/api.md`)  
  The API reference incorrectly stated "No authentication required" for `GET /health`.
  The endpoint enforces the same auth as all others. Doc corrected.

- **`install.sh` required a local Rust build** (`install.sh`)  
  The installer checked for `./target/release/runbound` and failed for users without
  a Rust toolchain. Rewritten to auto-detect architecture, fetch the versioned binary
  from the GitHub release, verify it with `--version`, and write the systemd unit inline.
  Supports `--version <tag>` for pinned installs. `--uninstall` still works.

---

## [0.2.2] — 2026-05-16

### Added

- **`api-port` directive** (`src/config/parser.rs`, `src/main.rs`)  
  The REST API port is now configurable via the config file (`api-port: 9090`).
  Defaults to `8081` when absent. Removes the hardcoded `API_PORT` constant.

- **`cache-max-ttl` directive** (`src/config/parser.rs`, `src/dns/server.rs`)  
  Maximum TTL cap for cached records is now configurable (`cache-max-ttl: 3600`).
  Defaults to `86400` (24 h) when absent. Removes the hardcoded `MAX_TTL_CAP` constant.
  Mirrors Unbound's `cache-max-ttl` directive.

- **`private-address` directive — DNS rebinding protection** (`src/config/parser.rs`, `src/dns/acl.rs`, `src/dns/server.rs`)  
  CIDR ranges configured with `private-address` are now enforced: if any A or AAAA record
  returned by an upstream resolver falls within a configured private range, the query is
  answered with SERVFAIL instead of forwarding the private IP to the client.
  Mirrors Unbound's `private-address` directive. A new `PrivateAddressSet` type in
  `acl.rs` provides zero-extra-crate CIDR matching using the same bit-shift/mask logic
  as the ACL engine. `CidrBlock` is factored out to avoid code duplication.

- **`forward-tls-upstream` directive — DNS-over-TLS to upstream** (`src/config/parser.rs`, `src/dns/server.rs`)  
  Adding `forward-tls-upstream: yes` to a `forward-zone:` block now sends queries to
  upstream resolvers over an encrypted TLS connection (port 853 by default, overridable
  with `addr@port` syntax). Without the directive, plain UDP+TCP is used (existing behaviour).
  Mirrors Unbound's `forward-tls-upstream` directive.

---

## [0.2.1] — 2026-05-16

### Performance

- **OPT-01 — Eliminate `Name::from(qname.clone())` on every DNS query** (`src/dns/local.rs`, `src/dns/server.rs`)
  `LocalZoneSet::find()`, `local_records()`, and `name_has_records()` now accept `&LowerName`
  directly instead of `&Name`. Previously, every incoming query paid two heap allocations
  (clone `LowerName` + `Name::from`) before the first zone lookup. The hot path now uses
  `LowerName: Borrow<Name>` to perform the `HashMap` lookup with zero allocation.
  The walk-up hierarchy path (`find()` parent-zone traversal) uses `LowerName::base_name()`
  end-to-end, avoiding an additional `Name` clone per label trimmed.
  The XDP fast path benefits from the same change with no callsite modification.

### Fixed

- **`*response_code` in resolver error path** (`src/dns/server.rs`)
  `ResolveErrorKind::NoRecordsFound::response_code` binds as `&ResponseCode` under match
  ergonomics. The dereference was correct but the compiler's error reporting was misleading
  when other errors were present in the same compilation unit. Confirmed and preserved as-is.

---

## [0.2.0] — 2026-05-16

### Security

- **SEC-01 — Race condition on concurrent API writes** (`src/api/mod.rs`)  
  `store::load` / `store::save` are now performed inside the `zones_mutex` critical section, making the entire read→validate→write→swap sequence atomic. Previously two concurrent `POST /dns` requests could both read the same snapshot and one silently overwrite the other.

- **SEC-02 — XDP fast-path bypassed ACL entirely** (`src/dns/xdp/worker.rs`)  
  The AF_XDP worker answered DNS queries without consulting the ACL. An attacker on a refused subnet could bypass the access-control policy by sending raw UDP on an XDP-attached interface. ACL is now checked in `answer_dns()` before any zone lookup; `Deny` → silent drop, `Refuse` → crafts a REFUSED DNS frame.

- **SEC-03 — IPv4-mapped IPv6 addresses skipped ACL rules** (`src/dns/acl.rs`)  
  A client connecting over IPv6 with address `::ffff:10.0.0.1` would not match the IPv4 `10.0.0.0/8` allow entry and would fall through to the default `Refuse`. Address normalisation now maps `::ffff:a.b.c.d` → `a.b.c.d` before matching, ensuring consistent ACL behaviour across transports.

- **SEC-04 — SSRF via HTTP redirect** (`src/feeds/mod.rs`)  
  `reqwest` follows redirects by default. A malicious feed server could redirect to `http://169.254.169.254/` (cloud metadata) or any private IP. A custom redirect `Policy` now blocks HTTPS→HTTP downgrades and redirects whose destination resolves to a private or loopback address.

- **SEC-05 — TOCTOU on feed URL validation** (`src/feeds/mod.rs`)  
  Feed URLs were validated once at subscription time; subsequent `update_feed()` calls reused the stored URL without re-checking. A race between subscribe and first fetch, or a compromised feed record, could bypass validation. `update_feed()` now re-validates the URL on every invocation.

- **SEC-06 — Unbounded data-store growth** (`src/api/mod.rs`)  
  No limit was enforced on the number of DNS entries or blacklist entries. An authenticated client could fill disk / exhaust memory. Limits are now enforced: `MAX_DNS_ENTRIES = 10 000`, `MAX_BLACKLIST_ENTRIES = 100 000`; `POST` requests beyond the limit return `422 Unprocessable Entity`.

- **SEC-07 — Feed data files world-readable** (`src/feeds/mod.rs`)  
  Serialised feed files were created with the process umask (typically `0644`). Feeds may contain sensitive block-list intelligence. A `chmod 640` is now applied after each atomic rename so files are readable only by owner and group.

- **SEC-08 — Plaintext HTTP feeds** (`src/feeds/mod.rs`)  
  HTTP feed URLs were silently accepted. A `WARN`-level log is now emitted for any `http://` feed URL, flagging the man-in-the-middle injection risk.

### Changed

- ACL logic extracted into a dedicated `src/dns/acl.rs` module with a public `Acl` / `AclAction` API, shared by both the hickory-server path and the XDP worker.
- `run_dns_server()` and `start_xdp()` now accept an `Arc<Acl>` built once in `main()` and shared across all paths.
- Version bumped to `0.2.0` in `Cargo.toml`.

### Added

- `examples/home.conf` — Home / Pi-hole replacement configuration.
- `examples/office.conf` — SMB office split-horizon DNS configuration.
- `examples/server.conf` — Public/shared recursive resolver configuration.
- `examples/secure.conf` — High-security / air-gapped / IA audit configuration.
- `README.md` — Comprehensive GitHub documentation: installation, configuration reference, full REST API reference, performance benchmarks, security architecture, systemd setup, XDP fast-path guide, Unbound compatibility table, and sysadmin-oriented comparison.
- `.gitignore` — Comprehensive ignore rules covering build artefacts, PGO data, TLS secrets, editor files, and test artefacts.

---

## [0.1.0] — 2026-04-01

### Added

- High-performance DNS server written in Rust, drop-in replacement for Unbound.
- Unbound-compatible configuration file parser (`server:`, `forward-zone:`, `local-zone:`, `local-data:`, `access-control:` directives).
- UDP + TCP DNS on port 53; DNS-over-TLS on port 853.
- REST API on port 8081 with Bearer-token authentication (`subtle::ConstantTimeEq` timing-safe comparison).
- AF_XDP kernel-bypass fast path for high-throughput deployments (`--features xdp`).
- Token-bucket rate limiter (`DashMap<IpAddr, IpBucket>` with `ahash`) shared between hickory and XDP paths.
- Inflight-request semaphore (`MAX_INFLIGHT_REQUESTS = 4096`) providing a hard OOM backstop under flood conditions.
- Lock-free `ArcSwap<LocalZoneSet>` for zero-contention zone data reads on the hot path.
- `SO_REUSEPORT` with 32 UDP sockets per CPU for parallel UDP handling.
- REST API endpoints:
  - `GET  /health` — liveness probe
  - `GET  /dns`   — list all local DNS entries
  - `POST /dns`   — add a local DNS entry
  - `DELETE /dns/{name}` — remove a local DNS entry
  - `GET  /blacklist` — list blacklisted domains
  - `POST /blacklist` — add a domain to the blacklist
  - `DELETE /blacklist/{domain}` — remove a domain from the blacklist
  - `GET  /feeds` — list configured feed subscriptions
  - `POST /feeds` — subscribe to a remote block-list feed
  - `DELETE /feeds/{name}` — remove a feed subscription
  - `POST /feeds/{name}/refresh` — force immediate feed refresh
  - `GET  /stats` — query statistics (total, blocked, forwarded, NXDOMAIN)
  - `GET  /config` — dump active configuration (sanitised — no secrets)
  - `POST /reload` — hot-reload configuration without restart
- Persistent JSON store for DNS entries, blacklist, and feed subscriptions; atomic file writes via rename.
- Feed auto-refresh scheduler with configurable interval.
- Systemd service file template.

---

[Unreleased]: https://github.com/redlemonbe/Runbound/compare/v0.9.41...HEAD
[0.9.41]: https://github.com/redlemonbe/Runbound/compare/v0.9.40...v0.9.41
[0.9.40]: https://github.com/redlemonbe/Runbound/compare/v0.9.39...v0.9.40
[0.9.39]: https://github.com/redlemonbe/Runbound/compare/v0.9.38...v0.9.39
[0.9.38]: https://github.com/redlemonbe/Runbound/compare/v0.9.37...v0.9.38
[0.9.37]: https://github.com/redlemonbe/Runbound/compare/v0.9.36...v0.9.37
[0.9.36]: https://github.com/redlemonbe/Runbound/compare/v0.9.35...v0.9.36
[0.9.35]: https://github.com/redlemonbe/Runbound/compare/v0.9.34...v0.9.35
[0.9.34]: https://github.com/redlemonbe/Runbound/compare/v0.9.33...v0.9.34
[0.9.33]: https://github.com/redlemonbe/Runbound/compare/v0.9.32...v0.9.33
[0.9.32]: https://github.com/redlemonbe/Runbound/compare/v0.9.31...v0.9.32
[0.9.31]: https://github.com/redlemonbe/Runbound/compare/v0.9.30...v0.9.31
[0.9.30]: https://github.com/redlemonbe/Runbound/compare/v0.9.29...v0.9.30
[0.9.29]: https://github.com/redlemonbe/Runbound/compare/v0.9.28...v0.9.29
[0.9.28]: https://github.com/redlemonbe/Runbound/compare/v0.9.27...v0.9.28
[0.9.27]: https://github.com/redlemonbe/Runbound/compare/v0.9.26...v0.9.27
[0.9.26]: https://github.com/redlemonbe/Runbound/compare/v0.9.25...v0.9.26
[0.9.25]: https://github.com/redlemonbe/Runbound/compare/v0.9.24...v0.9.25
[0.9.24]: https://github.com/redlemonbe/Runbound/compare/v0.9.23...v0.9.24
[0.9.23]: https://github.com/redlemonbe/Runbound/compare/v0.9.22...v0.9.23
[0.9.22]: https://github.com/redlemonbe/Runbound/compare/v0.9.21...v0.9.22
[0.9.21]: https://github.com/redlemonbe/Runbound/compare/v0.9.20...v0.9.21
[0.9.20]: https://github.com/redlemonbe/Runbound/compare/v0.9.19...v0.9.20
[0.9.19]: https://github.com/redlemonbe/Runbound/compare/v0.9.18...v0.9.19
[0.9.18]: https://github.com/redlemonbe/Runbound/compare/v0.9.17...v0.9.18
[0.9.17]: https://github.com/redlemonbe/Runbound/compare/v0.9.16...v0.9.17
[0.9.16]: https://github.com/redlemonbe/Runbound/compare/v0.9.15...v0.9.16
[0.9.15]: https://github.com/redlemonbe/Runbound/compare/v0.9.14...v0.9.15
[0.9.14]: https://github.com/redlemonbe/Runbound/compare/v0.9.13...v0.9.14
[0.9.13]: https://github.com/redlemonbe/Runbound/compare/v0.9.12...v0.9.13
[0.9.12]: https://github.com/redlemonbe/Runbound/compare/v0.9.11...v0.9.12
[0.9.11]: https://github.com/redlemonbe/Runbound/compare/v0.9.10...v0.9.11
[0.9.10]: https://github.com/redlemonbe/Runbound/compare/v0.9.9...v0.9.10
[0.9.9]: https://github.com/redlemonbe/Runbound/compare/v0.9.8...v0.9.9
[0.9.8]: https://github.com/redlemonbe/Runbound/compare/v0.9.7...v0.9.8
[0.9.7]: https://github.com/redlemonbe/Runbound/compare/v0.9.6...v0.9.7
[0.9.6]: https://github.com/redlemonbe/Runbound/compare/v0.9.5...v0.9.6
[0.9.5]: https://github.com/redlemonbe/Runbound/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/redlemonbe/Runbound/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/redlemonbe/Runbound/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/redlemonbe/Runbound/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/redlemonbe/Runbound/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/redlemonbe/Runbound/compare/v0.8.3...v0.9.0
[0.8.3]: https://github.com/redlemonbe/Runbound/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/redlemonbe/Runbound/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/redlemonbe/Runbound/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/redlemonbe/Runbound/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/redlemonbe/Runbound/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/redlemonbe/Runbound/compare/v0.6.24...v0.7.0
[0.6.24]: https://github.com/redlemonbe/Runbound/compare/v0.6.23...v0.6.24
[0.6.23]: https://github.com/redlemonbe/Runbound/compare/v0.6.22...v0.6.23
[0.6.22]: https://github.com/redlemonbe/Runbound/compare/v0.6.21...v0.6.22
[0.6.21]: https://github.com/redlemonbe/Runbound/compare/v0.6.20...v0.6.21
[0.6.20]: https://github.com/redlemonbe/Runbound/compare/v0.6.19...v0.6.20
[0.6.19]: https://github.com/redlemonbe/Runbound/compare/v0.6.18...v0.6.19
[0.6.18]: https://github.com/redlemonbe/Runbound/compare/v0.6.17...v0.6.18
[0.6.17]: https://github.com/redlemonbe/Runbound/compare/v0.6.16...v0.6.17
[0.6.16]: https://github.com/redlemonbe/Runbound/compare/v0.6.15...v0.6.16
[0.6.15]: https://github.com/redlemonbe/Runbound/compare/v0.6.14...v0.6.15
[0.6.14]: https://github.com/redlemonbe/Runbound/compare/v0.6.13...v0.6.14
[0.6.13]: https://github.com/redlemonbe/Runbound/compare/v0.6.12...v0.6.13
[0.6.12]: https://github.com/redlemonbe/Runbound/compare/v0.6.11...v0.6.12
[0.6.11]: https://github.com/redlemonbe/Runbound/compare/v0.6.10...v0.6.11
[0.6.10]: https://github.com/redlemonbe/Runbound/compare/v0.6.9...v0.6.10
[0.6.9]: https://github.com/redlemonbe/Runbound/compare/v0.6.8...v0.6.9
[0.6.8]: https://github.com/redlemonbe/Runbound/compare/v0.6.7...v0.6.8
[0.6.7]: https://github.com/redlemonbe/Runbound/compare/v0.6.6...v0.6.7
[0.6.6]: https://github.com/redlemonbe/Runbound/compare/v0.6.5...v0.6.6
[0.6.5]: https://github.com/redlemonbe/Runbound/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/redlemonbe/Runbound/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/redlemonbe/Runbound/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/redlemonbe/Runbound/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/redlemonbe/Runbound/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/redlemonbe/Runbound/compare/v0.5.7...v0.6.0
[0.5.7]: https://github.com/redlemonbe/Runbound/compare/v0.5.5...v0.5.7
[0.5.5]: https://github.com/redlemonbe/Runbound/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/redlemonbe/Runbound/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/redlemonbe/Runbound/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/redlemonbe/Runbound/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/redlemonbe/Runbound/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/redlemonbe/Runbound/compare/v0.4.16...v0.5.0
[0.4.16]: https://github.com/redlemonbe/Runbound/compare/v0.4.15...v0.4.16
[0.4.15]: https://github.com/redlemonbe/Runbound/compare/v0.4.14...v0.4.15
[0.4.14]: https://github.com/redlemonbe/Runbound/compare/v0.4.9...v0.4.14
[0.4.9]: https://github.com/redlemonbe/Runbound/compare/v0.4.8...v0.4.9
[0.4.8]: https://github.com/redlemonbe/Runbound/compare/v0.4.7...v0.4.8
[0.4.7]: https://github.com/redlemonbe/Runbound/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/redlemonbe/Runbound/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/redlemonbe/Runbound/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/redlemonbe/Runbound/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/redlemonbe/Runbound/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/redlemonbe/Runbound/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/redlemonbe/Runbound/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/redlemonbe/Runbound/compare/v0.3.5...v0.4.0
[0.3.5]: https://github.com/redlemonbe/Runbound/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/redlemonbe/Runbound/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/redlemonbe/Runbound/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/redlemonbe/Runbound/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/redlemonbe/Runbound/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/redlemonbe/Runbound/compare/v0.2.5...v0.3.0
[0.2.5]: https://github.com/redlemonbe/Runbound/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/redlemonbe/Runbound/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/redlemonbe/Runbound/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/redlemonbe/Runbound/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/redlemonbe/Runbound/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/redlemonbe/Runbound/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/redlemonbe/Runbound/releases/tag/v0.1.0
