# Runbound — FINDINGS (agent Nexus)

**Branche de travail :** `perf/xdp-fastpath`  
**Dernier commit ingéré :** `81591c5` (2026-06-03 13:17:54 — identique à `main`)  
**Mis à jour :** 2026-06-03

---

## ÉTAPE 0 : Ingestion — statut

| Fichier | Lu | Notes |
|---------|----|-----------|
| README.md | ✅ | Drop-in Unbound, XDP commercial license, 4.77M QPS table |
| CLAUDE.md | ✅ | Absent du repo |
| Cargo.toml | ✅ | v0.9.65, feature xdp = dep:aya, musl, thin-LTO strip |
| docs/benchmark/v0.9.65.md | ✅ | **Référence perf** — 4.77M QPS, p50 1.25ms, p99 3.72ms |
| docs/xdp.md | ✅ | Architecture, requirements, modes, SIMD dispatch |
| docs/internals.md | ✅ | Pipeline ZC, CPUMAP FNV-1a hash, XSKMAP limits |
| docs/performance.md | ✅ | Tableau historique bench |
| docs/configuration.md | ✅ | Directives xdp-domain-routing, benchmark.conf |
| docs/git-workflow.md | ✅ | Solo maintainer, enforce_admins, PR flow |
| docs/security-audit/SECURITY-AUDIT.md | ✅ | 12 conventions audit, 0 finding ouvert à v0.9.50 |
| src/cpu.rs | ✅ | physical_cores() — thread_siblings_list, min du groupe |
| src/dns/xdp/loader.rs | ✅ | XdpHandle::load(), init_cpumap() (blob partiel ~7k) |
| src/dns/xdp/worker.rs | ✅ | start_xdp(), start_xdp_on_iface() (blob partiel) |
| src/dns/xdp/mod.rs | ✅ | Inventaire unsafe, modules |
| src/dns/xdp/socket.rs | ✅ (listing) | create_xsk_socket, maximize_nic_ring |
| src/dns/xdp/umem.rs | ✅ | FRAME_SIZE=4096, XdpRingSizes, AddrRing/DescRing |
| ebpf/dns_xdp.c | ✅ | XSKMAP max=64, CPUMAP max=256, NB_WORKERS, FNV-1a QNAME hash |
| examples/benchmark.conf | ✅ | xdp-domain-routing: yes (problème documenté ci-dessous) |
| docs/benchmark/v0.9.45.md | listing |
| docs/benchmark/v0.9.46.md | listing |

**Fichiers encore à lire :** init_cpumap() complet (blob tronqué), hot loop worker.rs (~300+), simd.rs, hasher.rs, docs restants (hardening, security, ha, sync, api, web-ui, troubleshooting…)

---

## Baseline de référence — 4.77M QPS

```
Hardware  : Intel Xeon E5-2690 v2 ×2 (40C/80T), NIC Intel X520/82599
Mode      : AF_XDP DRV zero-copy (ixgbe)
Queues    : 16 (RSS 82599 max)
Workers   : 16 threads XDP sur cœurs physiques
QPS       : 4,772,073
p50       : 1.251 ms   p99: 3.719 ms   p999: 4.065 ms
Flood     : 12.3M pps tenu sans crash
Condition : ethtool -N nic3 rx-flow-hash udp4 sdfn
            ethtool -A nic3 rx off tx off
            rate-limit: 0, local-zone wildcard → IP publique
```

**~298k qps/cœur ZC.** Plafond = RSS 82599 (16 rings max). Sur X520, plafond réaliste ~6M (20 cœurs physiques).

---

## Issue #155 — xdp-domain-routing (CPUMAP) casse le fast path

### Symptôme mesuré
- `xdp-domain-routing: yes` engage 40 cœurs MAIS → **120k qps** (×40 pire que 4.77M)
- Cause 1 : CPUMAP redirect repasse par le stack kernel → perd le zerocopy
- Cause 2 : `init_cpumap()` mappe les entrées vers des CPU IDs bruts (0..NB_WORKERS) sans consulter `physical_cores()` → route sur des siblings HT (cpu24-38 sur le Xeon)

### Localisation du bug (vérifiée en source)
- `src/dns/xdp/loader.rs` : `init_cpumap(effective_workers)` — **code exact à relire** (blob tronqué)
- `ebpf/dns_xdp.c` : `bpf_redirect_map(&CPUMAP, h % nb_workers, XDP_PASS)` — le CPUMAP index = hash % nb_workers, mappé vers un CPU ID
- `src/dns/xdp/worker.rs` : `XdpHandle::load(iface, queue_count, domain_routing)` avec `nb_workers = queue_count`

### Plan #155 — 3 commits atomiques

**Commit 1 — fix HT (safe, ne touche pas au ZC)** :
- Dans `init_cpumap()` : remplacer le mapping `[i → i]` par `[i → physical_cores()[i % physical_cores().len()]]`
- NB_WORKERS injecté = `physical_cores().len().min(queue_count)` (ou queue_count, selon ce que révèle la lecture complète d'init_cpumap)

**Commit 2 — WARN CPUMAP + ZC** :
- Dans `start_xdp_on_iface()` : si `domain_routing=true` ET `mode=DRV` → émettre un `tracing::warn!` explicite
- Message : "xdp-domain-routing: yes redirects via CPUMAP which breaks AF_XDP zero-copy (measured: ×40 throughput drop). Disable for maximum QPS. Use only for cache-locality on non-ZC paths."

**Commit 3 — benchmark.conf corrigé** :
- Changer `xdp-domain-routing: yes` → `xdp-domain-routing: no` dans `examples/benchmark.conf`
- Ajouter un commentaire expliquant pourquoi

**Commit 4 (optionnel, exploratoire) — gate OFF domain_routing sur interface ZC** :
- Si `domain_routing=true` ET mode=DRV détecté après attach → forcer `domain_routing=false`, logger WARN
- À discuter avec l'architecte avant d'implémenter (comportement-surprise possible)

### Question à trancher avant le commit 4
CPUMAP peut-il préserver le ZC en chaînant vers un XSK sur le CPU cible ? Réponse probable : non (CPUMAP reschedulée par kthread, perd le contexte XDP driver). À confirmer en doc kernel (kernel.org/doc/html/latest/networking/af_xdp.html) avant de décider.

---

## Issue #156 — Monter sur X520 sans casser le ZC (exploratoire)

### Piste 1 : cross-queue XSK redirect en ZC
- Rediriger un paquet reçu sur RX queue N vers un XSK lié à la queue M, en ZC, sur ixgbe
- Si faisable → 16 → 20 cœurs physiques (les 4 cœurs 16-19 idle sur le bench)
- **Non vérifié** — à rechercher dans la doc ixgbe et les patchsets AF_XDP upstream

### Piste 2 : efficacité par cœur (profiling hot path worker.rs)
- Identifier où passe le temps par paquet : parse eth/ip/udp/dns → lookup LocalZoneSet/cache snapshot → build réponse → enqueue TX
- À faire : `perf stat -e cache-misses,instructions,cycles` sur un worker thread en bench
- Gain per-cœur → gain global sans toucher au NIC

---

## Règles absolues rappelées

1. Ne jamais toucher `main` — commits sur `perf/xdp-fastpath` uniquement
2. ZC (AF_XDP DRV) est sacré — toute régression ZC est inacceptable
3. Cœurs physiques uniquement via `cpu::physical_cores()` — jamais de siblings HT
4. Mesure débit bout en bout, jamais de métrique-proxy
5. AGPL-3.0 headers sur tous les nouveaux fichiers
