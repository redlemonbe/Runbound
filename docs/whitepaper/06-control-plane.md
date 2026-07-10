# 06 — Control plane

The control plane runs on its own Tokio runtimes, separate from the DNS runtime, so DNS
load and management cannot starve each other (§1.4): the REST API gets a dedicated
**2-thread runtime** (`api_rt`, `worker_threads(2)`), while the embedded web UI gets a
**separate 1-thread runtime** (`ui_rt`, `worker_threads(1)`) — both set up in
`src/main.rs`. Files: `src/api/`, `src/config/writer.rs`, `src/sync.rs`,
`src/api/relay.rs`, `src/webui/`.

## 6.1 REST API (axum 0.7)

CRUD for zones, blacklist/feeds, upstreams, stats, `/system`, `/api/events`, backup,
split-horizon. Binds `127.0.0.1` only; bearer-token auth (env var `RUNBOUND_API_KEY`
preferred over config; optionally stored in a PKCS#11 HSM). Optionally also listens on a
**Unix-domain socket** (`api-socket`, mode 0600, #174), served via a hyper-util accept loop
because axum 0.7 `serve()` is TCP-only (chapter 02 of the API; see also the socket commit).

### 6.1.1 Stats counters — the whole query mix, not just local zones (#veracity)

The `/api/system` counters and the latency histogram behind them cover **every** answer path,
not only local-zone answers:

- **Forward/recursion feeds the latency histogram.** A completed forwarded/recursed lookup
  now records its round-trip into the same fixed-bucket histogram as local answers
  (`record_forward` → `record_latency_us`, `src/stats.rs:343`), driving p50/p95/p99. Before
  this, only local-zone answers recorded latency, so a pure forwarding/recursing server
  reported p50/p95/p99 = 0.
- **NODATA / NXDOMAIN count their round-trip.** Negative answers record a `record_forward`
  (miss + latency) like the positive `Answer` arm (`src/dns/server.rs:1060`); NODATA
  (NOERROR + empty answer) is counted as `forwarded` rather than mis-attributed to
  `servfail` (`src/dns/server.rs:1055`), so the sub-counters reconcile with `total_queries`.
- **Cache flush resets the XDP hit counters.** A resolver cache flush zeroes not only
  `cache_hits`/`cache_misses`/`cache_entries` but also the per-worker XDP packet counters
  (`XDP_WORKER_PKTS`), which carry all cache hits under `xdp: no`
  (`Stats::reset_cache`, `src/stats.rs:363`). Without this, a flush left the hit-rate stuck
  at 100 % (hits > 0, misses 0) with no traffic afterwards.
- **DNSSEC verdict families in OpenMetrics (0.9.3).** `GET /api/metrics` exposes
  `runbound_dnssec_secure_total`, `runbound_dnssec_bogus_total` and
  `runbound_dnssec_insecure_total` (`src/api/mod.rs:4036-4050`), fed by the per-verdict
  counters the validating resolver increments. The latency histogram also gained two finer
  buckets above 1 s — upper bounds `1_500_000` and `2_000_000` µs (`HIST_BOUNDS_US`,
  `src/stats.rs:45`; 13 → 15 buckets) — so a slow cold-recursion tail is visible instead of
  collapsing into one "> 1 s" bucket.
- **`cache_min_ttl` reported by `GET /api/config` (0.9.3).** The `cache-min-ttl` TTL floor
  was applied internally but not surfaced; `/api/config` now returns it
  (`src/api/mod.rs:1416`) next to `cache_max_ttl`.

## 6.2 Config-writer — full regeneration, atomic

`src/config/writer.rs` regenerates the entire `runbound.conf` from the in-memory model:
**render → re-parse to validate → atomic rename**. Properties:

- **Unknown/unmanaged directives are preserved verbatim** via `raw_passthrough` captured by
  the parser; a shared `is_managed_directive()` is the single source of truth between
  parser and writer.
- A scalar is emitted **only when it differs from the parser's empty-config reference**
  (`parse_str("server:\n")`), to avoid clamp/default drift on round-trips.
- Round-trip tests (examples, passthrough preservation, kitchen-sink, upstreams) guard
  against silent corruption.

Most changes apply live: DNSSEC toggle, upstreams via forward-zone rebuild, and
split-horizon — `add_split_horizon`/`delete_split_horizon` (`src/api/mod.rs`) call
`apply_split_horizon_live()`, which hot-swaps an `ArcSwap<SplitHorizonTable>`
(`src/dns/server.rs`) with **zero restart** (the API response literally returns
`"note":"applied live (no restart)"`).

## 6.3 Master↔slave relay (HMAC-SHA256) — and an honest security note

`src/api/relay.rs` + `src/sync.rs` implement encrypted command forwarding (issues #85/#87/
#88):

- **Authentication = HMAC-SHA256 over method + path + timestamp + request body**
  (SEC-I14), carried in the `x-runbound-ts` + `x-runbound-sig` headers
  (`src/api/relay.rs:136`), anti-replay window ±30 s. Verification is constant-time (no
  secret-dependent short-circuit — `hmac_verify_with_ts`, `src/sync.rs:145`). **Only the
  body-covering signature is accepted** (SEC-J5), so the body is always authenticated.
- **Confidentiality = rustls TLS**, but with a **custom verifier that does not validate the
  certificate chain** (`NoCertVerifier`, `src/api/relay.rs:35`). The comment is explicit:
  *"HMAC-SHA256 provides authentication; the TLS layer still encrypts — only cert
  validation is skipped."* The slave uses a self-signed cert and the design relies on
  **TOFU fingerprint pinning** for cert identity.
  > **Audit-relevant.** Authentication rests entirely on the HMAC key and the TOFU
  > fingerprint, not on a CA chain. This is a deliberate trade-off for a self-hosted
  > master/slave pair; the exact point where the TOFU fingerprint is enforced should be
  > confirmed in code during a security review.
- **Sync** is a delta journal (`SyncJournal`, capacity 1000) over TOFU TLS, with SHA-256
  content hashing (`src/sync.rs`).
- **Auto-registration**: the slave registers itself to the master on startup
  (`POST /nodes/register`, HMAC-signed, `src/sync.rs:1017`). The master validates the
  advertised `relay_host` against SSRF: loopback, unspecified, link-local, IPv6 ULA and
  — unless `sync-allow-private-relay: yes` is set on the master — **RFC 1918 private
  ranges are rejected with 400** (`src/sync.rs:1144`). LAN deployments (a slave at a
  private address, the common self-hosted case) therefore **require**
  `sync-allow-private-relay: yes` in the master config; without it registration fails
  with `INVALID_RELAY_HOST` and the slave logs only `Registration returned non-200
  status=400`.

## 6.4 SSE, backup/restore, split-horizon, web UI

- **SSE**: `GET /api/events`, `node_status` events `{node_id, addr, status, reason, ts}`
  (`NodeStatusEvent`, `src/sync.rs`).
- **Backup/restore** — two separate mechanisms:
  - `POST /api/backup` / `GET /api/backup`: create/list on-disk snapshot directories
    (`backup_<ts>[_label]/`) holding plain copies of `runbound.conf` + the data files
    (`dns_entries.json`, `blacklist.json`, `feeds.json`, `upstreams.json`); restored via
    `POST /api/backup/restore` (no base64 involved).
  - `GET /api/backup/export` / `POST /api/backup/import`: full backup as a single
    downloadable **base64-encoded JSON document** (`runbound-backup-v1`) covering
    `runbound.conf` plus secret/state files (API key, sync cert/key, WebUI auth); import
    is name-whitelisted (rejects path separators/`..`) and written atomically — apply
    requires a restart.
- **Split-horizon**: per-client-network answer sets, CRUD via API + web UI.
- **Per-subnet/VLAN policies (#8)**: `/api/policies` adds domain blocks scoped to one
  subnet, additive to the global blacklist/feeds filter (never less permissive), applied
  live with no restart. Merged into the WebUI **Subnets** tab alongside split-horizon.
- **Embedded web UI**: static HTML gzipped at build (`include_bytes!` of
  `OUT_DIR/index.html.gz`), served by the binary — no nginx. The admin panel **binds
  `127.0.0.1` by default** (`ui-bind` default `127.0.0.1`, `src/config/parser.rs:560`);
  exposing it on the network requires an explicit `ui-bind: 0.0.0.0`.
