# Changelog

All notable changes to Runbound are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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

[Unreleased]: https://github.com/redlemonbe/Runbound/compare/v0.5.7...HEAD
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
