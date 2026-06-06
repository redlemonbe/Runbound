# 06 — Control plane

The control plane runs on a **separate 2-thread Tokio runtime** so DNS load and management
cannot starve each other (§1.4). Files: `src/api/`, `src/config/writer.rs`, `src/sync.rs`,
`src/api/relay.rs`, `src/webui/`.

## 6.1 REST API (axum 0.7)

CRUD for zones, blacklist/feeds, upstreams, stats, `/system`, `/api/events`, backup,
split-horizon. Binds `127.0.0.1` only; bearer-token auth (env var `RUNBOUND_API_KEY`
preferred over config; optionally stored in a PKCS#11 HSM). Optionally also listens on a
**Unix-domain socket** (`api-socket`, mode 0600, #174), served via a hyper-util accept loop
because axum 0.7 `serve()` is TCP-only (chapter 02 of the API; see also the socket commit).

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

Some changes apply live (DNSSEC toggle, upstreams via forward-zone rebuild); others need a
restart (split-horizon, whose resolver table is built at boot).

## 6.3 Master↔slave relay (HMAC-SHA256) — and an honest security note

`src/api/relay.rs` + `src/sync.rs` implement encrypted command forwarding (issues #85/#87/
#88):

- **Authentication = HMAC-SHA256** over the request, with `X-Relay-Timestamp` +
  `X-Relay-HMAC`, anti-replay window ±30 s.
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
- **Auto-registration**: the slave registers itself to the master on startup.

## 6.4 SSE, backup/restore, split-horizon, web UI

- **SSE**: `GET /api/events`, `node_status` events `{node_id, addr, status, ts}`.
- **Backup/restore**: `GET/POST /api/backup` export/import — base64 JSON of the managed
  state files + `runbound.conf`; import is path-whitelisted and written atomically.
- **Split-horizon**: per-client-network answer sets, CRUD via API + web UI.
- **Embedded web UI**: static HTML gzipped at build (`include_bytes!` of
  `OUT_DIR/index.html.gz`), served by the binary — no nginx since v0.9.0.
