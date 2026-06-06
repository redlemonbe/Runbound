# 06 — Control plane

> **Status: draft outline** — to be expanded from `src/api/`, `src/config/writer.rs`,
> `src/sync.rs`, `src/webui/`.

The control plane runs on a **separate 2-thread Tokio runtime** so DNS load and management
cannot starve each other (§1.4).

- **REST API (axum 0.7).** CRUD for zones, blacklist/feeds, upstreams, stats, `/system`,
  events, backup, split-horizon. Binds `127.0.0.1` only; bearer-token auth; optional
  **Unix-domain socket** (`api-socket`, mode 0600, #174) in addition to TCP — served via a
  hyper-util accept loop because axum 0.7 `serve()` is TCP-only.
- **Config-writer (full regeneration, atomic).** The live config is regenerated from the
  in-memory model into `runbound.conf` via render → re-parse validation → atomic rename.
  Unmanaged/unknown directives are preserved verbatim (`raw_passthrough`); a shared
  `is_managed_directive()` is the single source of truth between parser and writer. A
  scalar is emitted only when it differs from the parser's empty-config reference, to
  avoid clamp/default drift. Round-trip tests guard against silent corruption.
- **Encrypted relay (master→slave).** HMAC-SHA256 with `X-Relay-Timestamp` +
  `X-Relay-HMAC`, anti-replay ±30 s; TLS with TOFU certificate fingerprint pinning.
- **SSE health push** — `GET /api/events`, `node_status` events.
- **Auto-registration** — slave registers to the master (`src/sync.rs`).
- **Backup/restore** — `GET/POST /api/backup` export/import (base64 JSON of the managed
  state files + `runbound.conf`), whitelisted paths, atomic write on import.
- **Split-horizon** — per-client-network answer sets, CRUD via API + web UI.
- **Embedded web UI** — static HTML gzipped at build (`include_bytes!` of
  `OUT_DIR/index.html.gz`), served by the binary (no nginx since v0.9.0).

## To expand
- Auth/rate-limit specifics; relay handshake; SSE event schema; config-writer field table.
