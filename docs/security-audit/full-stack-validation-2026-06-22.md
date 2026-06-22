# Full-stack functional validation — v0.22.0 (`feat/dehickory`) — 2026-06-22

Live validation of the de-hickory binary (default build, **no `recursor`**) installed the
**documented** way: `runbound.service` (systemd) + the repo paths (`/usr/local/sbin/runbound`,
`/etc/runbound/runbound.conf`, runbound user, `LimitNOFILE=65536`). Goal: 100 % of old + new
functionality + API + WebUI, with the data verified correct.

## DNS serving (old functionality) — all correct
| Area | Result |
|---|---|
| Local zone multi-type | A, AAAA, MX, TXT, CNAME (+chain), SOA, NS, PTR — all served with correct data |
| Forward (racing 1.1.1.1 / 8.8.8.8) | example.com, cloudflare.com, … resolve |
| NXDOMAIN | NXDOMAIN (signed zone → NSEC3) |
| RFC rejections | CHAOS version.bind → NOTIMP; ANY → REFUSED; HTTPS type65 → empty NOERROR (block-https-record) |
| AXFR/IXFR | full transfer (10 RRs, SOA first+last per RFC 5936); refused outside `axfr allow` |
| DNSSEC signing (#201) | **delv: "fully validated"** for positive A, SOA apex, CNAME chain, and NSEC3 NXDOMAIN/NODATA. ECDSA P-256 (algo 13). |
| DDNS / TSIG (#14, RFC 2136/8945) | `nsupdate` add/delete with the correct key → applied + served; wrong key → REFUSED, no mutation. DDNS records in the signed zone are **signed on-the-fly** (delv "fully validated"). |

## New functionality (ported to serve_wire this session) — all proven live
| Feature | Proof |
|---|---|
| PAR-1 query logging | `GET /api/logs` returns served queries (NXDOMAIN at default verbosity; all at INFO). Was empty before the port. |
| PAR-2 serve-stale (#108) | cache expired + upstreams black-holed → answer served with **TTL = stale_answer_ttl (30)** and **`stale_served` = 1**; an un-cached name → SERVFAIL. |
| PAR-4 racing_wins (#33) | `GET /api/system` → `upstream_racing_wins {1.1.1.1@53: 10, 8.8.8.8@53: 3}` |
| PAR-5 top-domains (#5) | `GET /api/stats/top-domains` populated from slow-path queries (burst domain on top) |

## REST API — conform + coherent
- Auth: no key → **401**. Endpoints respond 200 with correct schemas.
- CRUD round-trip: `POST /api/dns` (201) → `GET /api/dns` shows it → `dig` serves it (proves
  API↔wire sync) → `DELETE /api/dns/:id` (200) → gone.
- `POST /api/blacklist` → the domain is then **REFUSED** by DNS (filtering applied on the wire path).
- Stats coherent with traffic (total / forwarded / local_hits / nxdomain / stale_served).

## WebUI — working
Served over **HTTPS** (auto local CA + TLS cert), SPA `Runbound — Sign in`. Login `POST /login`
with `rb_user`/`rb_pass` (the `username`/`password` fields are **anti-bot honeypots** — filling
them is correctly rejected) → 303 + session cookie → protected endpoints (`/api/webui/password-status`,
`/api/stats`) return data. One-time random admin password generated and logged on first start.

## Findings
| ID | Severity | Status | Finding |
|---|---|---|---|
| VAL-1 | MEDIUM | ✅ Fixed | **TSIG key-name trailing-dot mismatch.** `verify_request` looks up the request key name with the trailing dot stripped, but the handler stored the config name verbatim (`"name."`). A config `tsig-key: "name." …` therefore failed every signed UPDATE with `UnknownKey` (silent DDNS breakage). Fixed: the handler now stores `name.trim_end_matches('.').to_ascii_lowercase()` (server.rs). Regression test added (`tsig::tests::config_key_name_trailing_dot_is_normalized`). |
| VAL-2 | LOW | 🟡 Doc | **Config footgun: `axfr:` is a *section*.** Writing `axfr:` (colon) inside the `server:` block starts a new "axfr" section; subsequent `server:` directives (e.g. `api-port`, `ui-enabled`) fall into it and are dropped (with a `warn!("unknown axfr directive … — ignored")`). The documented form is `axfr { … }` (braces); with the colon form, place it last or re-open `server:` after it. No code change — unbound-style section semantics. |

## Verification
`cargo test --release --bin runbound` → **411 passed / 0 failed**. Both default and `recursor`
builds compile. Live checks above run against the systemd-installed binary on worker-dr.
