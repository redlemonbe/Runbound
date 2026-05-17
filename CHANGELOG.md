# Changelog

All notable changes to Runbound are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- `examples/secure.conf` — High-security / air-gapped / military-grade configuration.
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

[0.2.5]: https://github.com/redlemonbe/Runbound/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/redlemonbe/Runbound/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/redlemonbe/Runbound/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/redlemonbe/Runbound/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/redlemonbe/Runbound/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/redlemonbe/Runbound/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/redlemonbe/Runbound/releases/tag/v0.1.0
