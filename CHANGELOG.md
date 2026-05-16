# Changelog

All notable changes to Runbound are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.3]: https://github.com/redlemonbe/Runbound/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/redlemonbe/Runbound/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/redlemonbe/Runbound/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/redlemonbe/Runbound/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/redlemonbe/Runbound/releases/tag/v0.1.0
