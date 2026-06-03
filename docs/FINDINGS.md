# Runbound — FINDINGS (agent Nexus)

**Branche de travail :** `perf/xdp-fastpath`  
**Mis à jour :** 2026-06-03 (session #155 — commits 1-3 approuvés, C4 en cours)

---

## Baseline de référence — 4.77M QPS

```
Hardware  : Intel Xeon E5-2690 v2 ×2 (40C/80T), NIC Intel X520/82599
Mode      : AF_XDP DRV zero-copy (ixgbe)
Queues    : 16 (RSS 82599 max)
Workers   : 16 threads XDP sur cœurs physiques 0-15
QPS       : 4,772,073
p50       : 1.251 ms   p99: 3.719 ms   p999: 4.065 ms
Flood     : 12.3M pps tenu sans crash
Condition : ethtool -N nic3 rx-flow-hash udp4 sdfn
            ethtool -A nic3 rx off tx off
            rate-limit: 0, local-zone wildcard → IP publique
            dnsmark ≥ v1.2.1, --max-outstanding 0, port source varié
```

**~298k qps/cœur ZC.** Plafond RSS 82599 = 16 rings max. Plafond réaliste X520 ~6M (20 cœurs physiques).

---

## Issue #155 — CPUMAP casse le fast path ZC

### Symptôme mesuré
- `xdp-domain-routing: yes` → **120k qps** au lieu de 4.77M (**×40 pire**)
- Cause 1 : `bpf_redirect_map(CPUMAP)` ré-enfile le paquet sur le backlog/NAPI du CPU cible  
  (nouveau contexte, hors ring driver ZC) → chemin copy/skb
- Cause 2 : `init_cpumap()` initialisait les entrées CPUMAP avec des CPU IDs bruts (0..NB_WORKERS)  
  sans consulter `physical_cores()` → routage sur siblings HT (cpu20-39 sur E5-2690 v2)

### Décision d'architecte (2026-06-03) — ACTÉE
- **CPUMAP et ZC sont mutuellement exclusifs.** Structurel : impossible de préserver le ZC  
  dans un `bpf_redirect_map(CPUMAP)` (kthread NAPI, hors contexte driver).
- **ZC gagne sur interface ZC.** `domain_routing` reste disponible uniquement en mode  
  SKB/copy (sa localité cache a un sens là uniquement).

### Commits posés (branche perf/xdp-fastpath)

| # | Commit | Statut | Hash |
|---|--------|--------|------|
| 1 | `fix(xdp): #155 init_cpumap uses physical_cores() — no HT siblings` | ✅ APPROUVÉ | `3a7aa67` |
| 2 | `warn(xdp): #155 domain-routing breaks ZC — runtime warning` | ✅ APPROUVÉ | `bf8f8cd` |
| 3 | `conf(benchmark): #155 fix two silent traps in benchmark.conf` | ✅ poussé, en review | `b74c83f` |
| 4 | `fix(xdp): #155 gate domain-routing OFF when ZC active` | ⏳ à coder | — |

---

### Détail Commit 1 — physical_cores() dans init_cpumap()

**Bug :** `for cpu_idx in 0..nb_workers { cpu_map.set(cpu_idx, ...) }` — clé = CPU ID brut.  
Sur E5-2690 v2, siblings = cpu20-39 → si queue_count>20, entrées CPUMAP sur HT.

**Fix :**
- Dans `load()` : `effective_workers = nb_workers.max(1).min(phys_count)` (plafonne NB_WORKERS eBPF)
- Dans `init_cpumap()` : itère sur `physical_cores()[0..n]`, initialise `CPUMAP[phys[i]]`
- WARN bruyant si `cpu_id != i as u32` (topologie non-linéaire — perte silencieuse signalée)

**Limite connue (follow-up #155) :** sur NUMA exotique avec IDs physiques non-contigus (ex: [0,2,4,…]),
l'eBPF hash `h % NB_WORKERS` produit des clés 0..N-1 mais seules les clés paires seraient initialisées
→ perte silencieuse de paquets (XDP_PASS). Vraie robustesse = table d'indirection `worker_slot → cpu_id`
dans l'eBPF. Non requis sur hardware supporté (Intel/AMD : physiques = 0..N-1 contigus, vérifié sur E5-2690 v2).

---

### Détail Commit 2 — WARN démarrage

**Point d'injection :** `loader.rs::load()`, après l'attach XDP (mode connu), avant `init_cpumap()`.  
**Condition :** `actual_routing && matches!(mode, XdpMode::Drv)`

**⚠️ Notes architecte pour Commit 4 (à appliquer) :**

1. **DRV ≠ ZC strict** : `XdpMode::Drv` = driver natif XDP, pas nécessairement ZC actif  
   (on peut avoir DRV + XDP_COPY si le bind ZC échoue). Vérité terrain = `sock.zerocopy`  
   par socket, connu après `load()`. Pour WARN, DRV est proxy acceptable.  
   Pour gate-off dur (C4) : préférer `sock.zerocopy` si atteignable ; sinon DRV reste raisonnable.  
   **Ne pas désactiver domain-routing sur DRV+copy** (pas de ZC à protéger dans ce cas).

2. **Réconcilier WARN et gate (Commit 4) :** si C4 met `actual_routing = false` sur interface ZC,  
   le WARN actuel (sur `actual_routing`) ne se déclenchera plus — contradiction.  
   → **Solution C4 :** garder `requested_domain_routing` (config brute), faire le WARN sur  
   `requested_domain_routing && ZC_active`, wording :  
   _"xdp-domain-routing: yes IGNORÉ sur interface zerocopy — casserait le ZC (×40).  
   domain-routing actif uniquement en mode SKB/copy."_  
   L'utilisateur doit savoir que sa conf a été neutralisée, pas juste "accepte la régression".

---

### Détail Commit 3 — benchmark.conf

**Bombe 1 :** `xdp-domain-routing: yes` → `no` + commentaire `!! BENCHMARK TRAP` explicite.  
**Bombe 2 :** exemples `local-data: 10.0.0.1/10.0.0.2` → `203.0.113.1/203.0.113.2`  
(RFC 5737 TEST-NET-3, non routé, non bloqué par `private-address`).  
`private-address: 10.0.0.0/8` conservé (protection anti-rebinding légitime).  
Ajout commentaire `!! BENCHMARK TRAP` expliquant l'interaction private-address/local-data.

---

### Commit 4 — plan (à coder après feu vert Commit 3)

- Lire `worker.rs` : où et quand `sock.zerocopy` est connu (après bind XSK)
- Si `sock.zerocopy` accessible depuis `loader.rs::load()` → gate-off sur signal réel
- Sinon → gate-off sur `XdpMode::Drv` (proxy raisonnable, note 1 ci-dessus)
- Séparer `requested_domain_routing` (config) vs `actual_routing` (effective)
- WARN sur `requested` (pas `actual`) avec wording "IGNORÉ" — l'utilisateur doit savoir
- Garder `domain_routing` fonctionnel en `XdpMode::Skb` (son cas d'usage légitime)

---

## Issue #156 — Monter sur X520 sans casser le ZC (exploratoire, après #155)

### Piste 1 : cross-queue XSK redirect ZC
- Rediriger RX queue N → XSK queue M en ZC sur ixgbe — à valider en source ixgbe
- Si faisable → 16→20 cœurs physiques (cœurs 16-19 idle au bench actuel)

### Piste 2 : efficacité par cœur
- Profiler hot path worker.rs (parse eth/ip/udp/dns → lookup → build réponse → TX)
- `perf stat -e cache-misses,instructions,cycles` sur worker thread en bench
- Gain per-cœur → gain global sans toucher NIC

---

## Règles absolues

1. Ne jamais toucher `main` — commits sur `perf/xdp-fastpath` uniquement
2. ZC (AF_XDP DRV) sacré — toute régression ZC est inacceptable
3. `cpu::physical_cores()` obligatoire pour tout placement worker/CPUMAP
4. Mesure débit bout en bout — jamais de métrique-proxy
5. AGPL-3.0 headers sur tous les nouveaux fichiers
6. Bench de validation obligatoire avant tout merge dans main :  
   domain_routing OFF → ≥4.77M qps, ZC actif, cœurs 0-15 physiques uniquement, p99 stable, zéro crash
