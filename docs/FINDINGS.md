# FINDINGS — Runbound perf/xdp-fastpath (#155)

> Nexus — agent développement. Dernière mise à jour : 2026-06-03.

## État de la branche

```
perf/xdp-fastpath HEAD = 04cbd04
7 commits devant main (81591c5)
```

## Commits #155 — tous poussés, cargo check ✅ exit=0

| Commit | Hash | Statut |
|--------|------|--------|
| C1 fix(xdp): init_cpumap uses physical_cores() — no HT siblings | 3a7aa67 | ✅ mergeable |
| C2 warn(xdp): domain-routing breaks ZC — runtime warning | bf8f8cd | ✅ mergeable |
| C3 conf(benchmark): fix two silent traps (domain-routing + private-address) | b74c83f | ✅ mergeable |
| C3b conf(benchmark): fix silent trap #3 — missing ethtool pre-run commands | afcc57a | ✅ mergeable |
| C4 fix(xdp): gate domain-routing OFF when ZC active | 04cbd04 | ✅ mergeable |

## Architecture — décisions vérifiées en source primaire

### Bug #155 — racine

- `init_cpumap(nb_workers)` boucle `for cpu_idx in 0..nb_workers` → indices raw kernel.
- `NB_WORKERS` injecté dans eBPF = `queue_count` brut (max 16 X520, mais `ethtool -X equal 40` → 40).
- eBPF : `cpu = h % NB_WORKERS` → `bpf_redirect_map(&CPUMAP, cpu, XDP_PASS)`. Clé CPUMAP = CPU ID kernel.
- Sur E5-2690 v2 40C/80T : physiques = 0-19, HT siblings = 20-39. Avec nb_workers=40 → CPUMAP[20-39] = HT siblings.

### Fix C1 — `loader.rs`

- `effective_workers = min(nb_workers, physical_core_count)` → plafond avant injection eBPF.
- `init_cpumap` : boucle sur `physical_cores()[0..n]` au lieu de `0..nb_workers`.
- WARN par-entrée si `cpu_id != slot` (non-linear topology).
- **Limite documentée** : correct sur layout Intel/AMD 0..N-1 contigus. Sur NUMA non-linéaire (physiques = [0,2,4…]), le hash eBPF `h % N` produit des clés 0,1,2… mais CPUMAP[1] non initialisé → XDP_PASS silencieux. Follow-up #155 : indirection map `worker_index→cpu_id`.

### Fix C2 — WARN loader.rs

- Signal : `domain_routing` (config brute, pas `actual_routing`) && `XdpMode::Drv`.
- Proxy DRV acceptable pour WARN précoce (avant bind socket).
- Wording : "IGNORÉ" (pas "accepte la régression").

### Fix C3 — benchmark.conf (3 bombes silencieuses)

1. `xdp-domain-routing: yes → no` (×40 regression).
2. `local-data` IPs privées → RFC 5737 TEST-NET `203.0.113.x` (non bloquées par `private-address`).
3. Pre-run manquait `ethtool -N rx-flow-hash udp4 sdfn` (RSS 1 cœur → 448k) et `ethtool -A rx off tx off` (PAUSE → 1.3M).

### Fix C4 — gate-off `worker.rs` + `disable_domain_routing()` `loader.rs`

- Signal terrain : `sock.zerocopy` (bool sur `XskSocket`), connu après AF_XDP bind.
- `any_zerocopy = sockets.iter().any(|s| s.zerocopy)` → vrai signal, pas proxy DRV.
- Si `domain_routing && any_zerocopy` → `handle.disable_domain_routing()` : vide CPUMAP (queue_size=0 → XDP_PASS → XSKMAP), `domain_routing_active = false`.
- domain-routing reste fonctionnel en SKB/copy (aucun ZC à protéger).
- Le WARN C2 reste déclenché sur config brute même après gate-off.
- **Note architecte (à ne pas confondre)** : ne pas gate sur DRV+copy (pas de ZC à protéger).

## Validation requise avant merge dans main

```bash
# Récepteur
sudo ethtool -N <nic> rx-flow-hash udp4 sdfn
sudo ethtool -A <nic> rx off tx off
# Config : rate-limit: 0, xdp-domain-routing: no, local-zone wildcard IP publique

# Générateur
dnsmark >= v1.2.1, --flood --max-outstanding 0, port source varié

# Critères pass
# 1. domain_routing OFF → ≥ 4.77M qps, logs "zerocopy", cœurs 0-15 physiques (aucun 20-39)
# 2. domain_routing ON + ZC → gaté OFF automatiquement, WARN "IGNORÉ" visible, débit = baseline
# 3. p99 stable, zéro crash sous flood 12.3M pps
```

## #156 — Prochaine session (non commencée)

Deux pistes :
- Redirect XSK cross-queue ZC : paquet RX queue N → XSK lié queue M, en ZC, sur ixgbe ?
- Efficacité par cœur : profiler hot path worker (parse→lookup→build→TX) — où passe le temps ?
