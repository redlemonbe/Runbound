# Runbound — FINDINGS (agent Nexus)

**Branche de travail :** `perf/xdp-fastpath`  
**Mis à jour :** 2026-06-03 (session #155 — commits 1-3b approuvés, C4 reworké après faille critique)

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
- **CPUMAP et ZC sont mutuellement exclusifs.** Structurel.
- **ZC gagne sur interface ZC.** `domain_routing` reste disponible uniquement en mode SKB/copy.

### Commits posés (branche perf/xdp-fastpath)

| # | Commit | Statut | Hash |
|---|--------|--------|------|
| 1 | `fix(xdp): #155 init_cpumap uses physical_cores() — no HT siblings` | ✅ APPROUVÉ | `3a7aa67` |
| 2 | `warn(xdp): #155 domain-routing breaks ZC — runtime warning` | ✅ APPROUVÉ | `bf8f8cd` |
| 3 | `conf(benchmark): #155 fix two silent traps in benchmark.conf` | ✅ APPROUVÉ | `b74c83f` |
| 3b | `conf(benchmark): #155 fix silent trap #3 — missing ethtool pre-run` | ✅ APPROUVÉ | `afcc57a` |
| 4 | `fix(xdp): #155 gate domain-routing OFF when ZC active` | ⏳ en review (reworké v2) | `1f56aea` |

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

### Détail Commit 2 — WARN démarrage (réconcilié post-C4)

**Condition finale :** `domain_routing && matches!(mode, XdpMode::Drv)` — teste la config **brute**
(pas `actual_routing`) → le WARN reste visible même après gate-off de C4. ✅

---

### Détail Commit 3 + 3b — benchmark.conf

Trois pièges silencieux corrigés :
1. `xdp-domain-routing: yes` → `no` (×40 de régression mesurée)
2. `local-data` en IP privée (10.x) derrière `private-address: 10.0.0.0/8` → 0% réponse.
   IP exemples remplacées par RFC 5737 TEST-NET-3 (`203.0.113.x`)
3. Commandes ethtool pré-run manquantes dans l'en-tête :
   - `ethtool -N <nic> rx-flow-hash udp4 sdfn` → sans ça : 1 seul cœur, 448k qps
   - `ethtool -A <nic> rx off tx off` → sans ça : flow control, ~1.3M plafond

---

### Détail Commit 4 — gate-off domain-routing sur interface ZC (v2 reworkée)

**Faille critique identifiée par l'architecte sur la v1 :**
`disable_domain_routing()` v1 vidait les entrées CPUMAP mais laissait `DOMAIN_ROUTING_ENABLED=1`
(un `volatile const __u32` en `.rodata` eBPF — gelé au load, impossible à changer post-bind).
→ l'eBPF entrait toujours dans la branche CPUMAP → `bpf_redirect_map` sur CPUMAP vide →
fallback `XDP_PASS` → slow path kernel (SO_REUSEPORT Tokio), PAS le XSK zerocopy.

**Fix (v2, commit 1f56aea) — trois fichiers :**

#### `ebpf/dns_xdp.c`
- Supprime `volatile const __u32 DOMAIN_ROUTING_ENABLED` (`.rodata`, gelé au load)
- Ajoute `BPF_MAP_TYPE_ARRAY` 1 entrée `domain_routing_cfg` (struct `{u8 enabled, u8 _pad[3]}`)
- Remplace `if (DOMAIN_ROUTING_ENABLED)` par `bpf_map_lookup_elem(&domain_routing_cfg, &key)`
- Vérifié en source binaire : `domain_routing_cfg` dans `.maps`, `DOMAIN_ROUTING_ENABLED` absent

#### `loader.rs`
- Ajoute `DomainRoutingCfgEntry { enabled: u8, _pad: [u8;3] }` (repr(C), aya::Pod)
- `fn init_domain_routing_cfg(active)` → `arr.set(0, {enabled: active as u8}, 0)`
- `disable_domain_routing()` → écrit `enabled=0` dans la map (retourne `Result<(), String>`)
- Commentaire "# Why not clear CPUMAP entries?" documente la faille évitée

#### `worker.rs`
- Gate-off sur `any_zerocopy` (vérité terrain post-bind)
- Appelle `handle.disable_domain_routing()` et gère l'`Err` (WARN non-fatal)

**Matrice de comportements :**

| Config | Interface | Résultat |
|--------|-----------|----------|
| `domain-routing: no` | ZC ou SKB | Inchangé, ZC intact |
| `domain-routing: yes` | SKB/copy | CPUMAP actif, nominal |
| `domain-routing: yes` | DRV (ZC réussi) | WARN + gate-off → ZC préservé |
| `domain-routing: yes` | DRV + bind ZC échoué | WARN proxy + `any_zerocopy=false` → gate-off NON déclenché → CPUMAP actif ✅ |

**Critère de validation C4 :**
`domain-routing: yes` + interface ZC → **4.77M qps en ZC** (pas <1M = slow path).

---

## Issue #156 — Montée en charge X520 sans casser le ZC (à venir)

Deux pistes post-#155 :
1. Redirect XSK cross-queue en restant ZC (queue RX N → XSK lié à queue M, en ZC sur ixgbe)
2. Profiling hot path userspace → gain par cœur

---

## Porte de validation (avant merge main)

- `domain_routing OFF` → 4.77M qps, ZC actif, cœurs 0-15 physiques (aucun cpu20-39 occupé)
- `domain_routing ON + interface ZC` → gaté → 4.77M qps ZC (critère C4)
- `domain_routing ON + interface SKB` → CPUMAP actif, cœurs physiques uniquement
- p99 stable, zéro crash sous flood 12M pps
- Méthodo : `ethtool -N <nic> rx-flow-hash udp4 sdfn` + `ethtool -A <nic> rx off tx off`
  + `rate-limit: 0` + `dnsmark ≥ v1.2.1 --max-outstanding 0`

---

## #156 — Étape 0 : Analyse statique du hot path (2026-06-03)

### Contrainte réelle : profil perf non exécutable depuis le worker

**Faits établis :**
- worker-amd64 (192.168.8.231) = LXC Proxmox, CPU AMD Threadripper PRO, NIC veth — PAS le récepteur X520
- `perf` absent sur le worker + `perf_event_paranoid=4` (interdit même root)
- Runbound non running sur le worker
- → Le profil `perf record -g` doit être exécuté sur la machine récepteur par l'architecte

**Ce document = analyse statique du code source, pas un profil mesuré.**
Labellisé SUPPOSÉ/SUSPECTÉ — autorité = perf réel sur le récepteur.

---

### Hot path par paquet (lu en source primaire — worker.rs)

```
Boucle principale xdp_worker() :
  1. poll(fd, 1ms timeout)                       ← syscall, 1ms min latency
  2. sock.umem.reclaim_tx()                      ← retire frames TX completed
  3. sock.rx.consume_rx_into(&mut rxds)          ← lecture ring RX (userspace, ZC)
  4. zones.load()                                ← ArcSwap::load() — atomic pointer swap, cheap
  5. cache_snapshot.load_full()                  ← Arc clone, O(1)
  6. prefetch next frame (_mm_prefetch T0)       ← SSE prefetch, inline asm
  7. Per-paquet :
     a. extract_src_ip(rx_frame)                 ← 2 branches, ~5 instructions
     b. TL_RL rate-limiter (thread_local cache)  ← HashMap lookup, ~10ns si hit
     c. process_packet() :
        i.   parse Eth/IP/UDP headers            ← ~15 instructions, slice indexing
        ii.  answer_dns() — local zone path :
               Message::from_bytes(query_bytes)  ← *** HICKORY DESERIALIZE — SUSPECT #1 ***
               BinEncoder::new() + emit()        ← *** HICKORY SERIALIZE — SUSPECT #1 ***
        iii. answer_from_cache() — cache path :
               QNAME wire extraction (loop)      ← SUSPECT #2 : boucle octets wire
               HashMap::get(&QuestionKey)        ← hash CRC32c SSE4.2 + eq (simd::bytes_eq)
               copy_from_slice(wire)             ← memcpy direct en TX UMEM, O(len)
     d. UDP checksum (ones_complement_sum)       ← SUSPECT #3 : scalar 8B/iter
     e. IPv4 checksum                            ← même implémentation
  8. sock.umem.fill.enqueue_batch(&rx_addrs)     ← retour frames kernel
  9. sock.tx.enqueue_tx(&tx_descs)               ← TX ring push
 10. sendto() si NEED_WAKEUP                     ← syscall conditionnel
```

---

### Suspects hotspot (SUPPOSÉS — à valider par perf réel)

#### SUSPECT #1 — CRITIQUE : Sérialisation hickory dans answer_dns() (local zone path)

`Message::from_bytes()` + `BinEncoder::new()` + `resp.emit()` = allocation dynamique
(hickory BinEncoder utilise un Vec interne) + parsing complet du message DNS via
l'AST hickory (Message → queries → records). Sur le chemin local-zone (le plus
chaud en bench), c'est potentiellement **la fonction la plus coûteuse par paquet**.

**Estimation :** 50-200 ns/paquet selon la complexité du nom et la taille de la réponse.
À 322k qps/cœur = 3.1µs/paquet. Si hickory coûte 200ns → ~6% du budget.

**Comparaison :** le chemin cache (`answer_from_cache()`) n'utilise PAS hickory —
lookup HashMap + copy_from_slice wire → ~20-50ns. C'est probablement 3-5× plus rapide.

**Implication #156 :** si le bench est majoritairement sur local-zone (vs cache), remplacer
`answer_dns()` par un sérialiseur wire minimal sans allocation ni AST hickory pourrait
être le gain Levier B le plus important.

#### SUSPECT #2 — MODÉRÉ : Extraction QNAME dans answer_from_cache()

```rust
// Boucle octet par octet sur le wire QNAME
let lb = *query_bytes.get(vpos)?;
vpos += 1 + lb as usize;
```
Sur des noms longs (ex. `a.bench.local.` = 14 bytes), c'est ~5 iterations.
SmallVec<[u8;64]> évite le heap. Le hash CRC32c SSE4.2 est déjà optimal.
**Suspect mineur sauf si les noms sont très longs.**

#### SUSPECT #3 — MINEUR : Checksums UDP/IPv4 scalaires

`ones_complement_sum()` traite 8 bytes/iter (4 u16 accumulés dans u64) — pas vectorisé.
Sur un paquet DNS typique de 80 bytes payload : ~10 iterations. Probablement <5ns.
**Suspect mineur sur DNS (paquets courts). Non prioritaire.**

#### SUSPECT #4 — POLL SYSCALL : timeout 1ms

`poll(fd, 1ms)` avec 12M pps entrant → le ring RX ne sera jamais vide → poll retourne
immédiatement (POLLIN toujours set). Le 1ms timeout est une borne max, pas un délai réel.
**Non suspect sous flood. Serait un problème à faible charge uniquement.**

---

### Levier A — Cross-queue ZC : question ouverte à trancher en mesure

**Situation :** RSS 82599 = 16 queues max. Cœurs physiques 0-19 disponibles (20 physiques).
4 cœurs idle (16-19) car pas de queue RX associée.

**Question :** `bpf_redirect_map(&XSKS, hash % 20, XDP_PASS)` sur 20 XSKs liés à 20 queues,
quand le RSS ne remplit que 16 queues → les 4 XSKs "extra" (queues 16-19) reçoivent
des paquets via redirect, pas via RX ring natif. Le ZC tient-il ?

**Réponse supposée (NON confirmée) :** Sur ixgbe, `XDP_REDIRECT` vers un XSK lié à une queue
qui ne reçoit pas de trafic RSS natif peut fonctionner en ZC si l'XSK est lié en mode
`XDP_ZEROCOPY` — le driver ixgbe supporte `ndo_xsk_wakeup` sur toutes les queues, pas
seulement celles actives en RSS. Mais ce n'est pas documenté explicitement pour le cas
"RSS queue count < XSK count".

**Action nécessaire (architecte) :** tester empiriquement. Créer 20 XSKs, XSKMAP[0..19],
eBPF hash % 20, ethtool queues=16. Observer :
- `ip xfrm` / `ethtool -S` : compteurs ZC (zerocopy_rx) sur queues 16-19
- Logs Runbound : "zerocopy" sur toutes les queues
- Débit vs baseline 16-queue

**Si ZC casse sur queues 16-19 → même problème que CPUMAP (#155) → Levier A abandonné.**

---

### Plan d'action #156 (conditionné par le profil réel)

1. **Architecte : exécuter `perf record -g` sur récepteur** pendant dnsmark flood 12M pps
   → top 10 fonctions → valider/invalider les suspects ci-dessus
2. Si Suspect #1 confirmé → Levier B : sérialiseur wire minimal dans answer_dns()
3. Levier A : test empirique cross-queue ZC (16→20 queues)
4. Combiner A + B si les deux tiennent → cible 10M qps

