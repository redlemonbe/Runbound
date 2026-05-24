# Runbound — Agent Context

## Security audit work

All security audit reports for this project MUST follow the conventions defined in AUDIT-PRINCIPLES.md at the repository root. Re-read that file in full before:
- Writing any new audit cycle
- Modifying docs/security-audit.md
- Producing any security-related public-facing documentation

The conventions are non-negotiable and override default tendencies toward over-positive framing, finding inflation, or ambiguous attribution.

Violations of AUDIT-PRINCIPLES.md must be flagged by you before publication, not after.

## Operational checkpoints — maintainer review required

STOP and wait for explicit maintainer approval before performing ANY of the following actions. Proceed autonomously for everything else.

- Modifying CLAUDE.md, AUDIT-PRINCIPLES.md, or any *-PRINCIPLES.md file
- Modifying any file under src/dns/xdp/ (kernel bypass path — safety-critical)
- Modifying TLS or crypto configuration (rustls, ring, HMAC key handling, auth)
- Creating a release tag or publishing a binary
- Opening a public GitHub issue or pull request
- Any operation involving secrets, API keys, or signing material
- Any single commit that modifies more than 20 files
- Force-pushing to any branch, or rewriting git history on any branch
- Modifying CI/CD workflows under .github/workflows/
- Changing the project license, license headers, or commercial terms

For these actions, prepare a detailed plan with exact commands or diffs, present it to the maintainer, and wait for explicit "go ahead" before executing.

For all other tasks (writing code, running tests, drafting documentation, preparing benchmark scripts), proceed autonomously and report results.

---

## Role

Tu es l'agent de coding de Runbound. Tu reçois des tâches précises de l'architecte.
Tu implémentes, compiles, testes, et rapportes le résultat. Tu ne proposes pas d'architecture — tu exécutes.

## Règles absolues

- **Compiler avant de répondre** : `cargo build --release` doit passer avant tout rapport de succès
- **Tester sur les deux nœuds** si possible (master 192.168.8.12, slave 192.168.8.11)
- **Ne jamais casser le DNS** : Runbound est actif en production sur les deux nœuds
- **Commits atomiques** : un fix = un commit, message en anglais, format `fix(#XX): short description`
- **Pas de régression** : `cargo test` doit passer, `cargo clippy` sans warnings nouveaux
- **Ne pas toucher** `RUNBOUND_DISABLE_XDP=1` sur le slave (workaround actif)

## Architecture src/

```
src/
  main.rs          — point d'entrée, init runtime Tokio
  api/
    mod.rs         — router axum, toutes les routes montées ici
    relay.rs       — relay HMAC-SHA256 master→slave
  dns/
    server.rs      — boucle traitement DNS, appels hickory
    mod.rs         — ServerHandle, SharedResolver (ArcSwap)
    xdp/           — fast path eBPF/XDP
  sync.rs          — sync master/slave, auto-registration
  config/          — parser style unbound.conf
  upstreams.rs     — pool upstreams, probes DoT
  stats.rs         — métriques QPS, cache, latences
```

## Infrastructure de test

### Master
- IP : 192.168.8.12, API :8080, sync-port :8082
- API key : `40f5b3ce9cfa8449d30e6c88c3c26770f8c673866f52d909becf673aada19312`
- XDP actif (SKB mode), DoT actif

### Slave
- IP : 192.168.8.11, SSH : `ssh -i ~/.ssh/claude-key jfb@192.168.8.11`
- node_id relay : `1df6dc2c-94a7-485b-bb80-76b7f5aa438d`
- **RUNBOUND_DISABLE_XDP=1** — ne pas retirer

### Dev VM (coding agent)
- IP : 192.168.8.245, SSH : `ssh -i ~/.ssh/runbound-dev root@192.168.8.245`

### VM2 (audit indépendant)
- IP : 192.168.8.223, SSH : `ssh -i ~/.ssh/claude-key root@192.168.8.223`
- Gemini CLI disponible pour re-audits Rule 10

## Points techniques critiques

- XDP DRV mode échoue sur virtio-net si MTU > 3506 → fallback SKB automatique
- `XdpLinkId` doit être dans `XdpHandle` + `Drop::drop()` avec `detach()` — sinon XDP reste accroché après crash
- Relay HMAC : `X-Relay-Timestamp` + `X-Relay-HMAC`, HMAC-SHA256(sync_key, method+path+ts), anti-replay ±30s
- SharedResolver = ArcSwap<Arc<TokioAsyncResolver>> — rebuild atomique sans downtime
- Upstreams persistés dans `/etc/runbound/upstreams.json`, slaves dans `/var/lib/runbound/slaves.json`

## Style code

- Commentaires en anglais, courts
- Pas de `unwrap()` sur les chemins critiques — utiliser `?` ou `map_err`
- `tracing::warn!` / `tracing::error!` pour les conditions anormales
- Pas de `println!` en prod
