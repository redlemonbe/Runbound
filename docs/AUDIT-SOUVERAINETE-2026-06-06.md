# RUNBOUND — RAPPORT D'AUDIT SENIOR
**Architecte Systeme Defense/Souverainete + Securite Offensive**  
**Nexus / 2026-06-06**

> **Perimetre** : documentation publique (README, METHODOLOGY, REVIEW-CHECKLIST, architecture XDP, issues #155/#165, API docs). Aucun pentest ni audit de code formel — evaluation niveau 1.  
> Les deux IA (Gemini 2.5 Pro + Qwen3-Coder 30B) ont produit des analyses convergentes ; ce document est la synthese fusionnee.

---

# PARTIE 1 — AUDIT DOCUMENTATION

## Ce qui est bien

### 1. Rigueur des claims de performance
La hierarchie `MEASURED / theoretical / [UNVERIFIED]` dans `REVIEW-CHECKLIST.md` est **exceptionnellement rare** dans l'open-source. Signal de serieux intellectuel fort.

### 2. Transparence sur les limites
`README` porte : *"Experimental — not recommended for production"* + `METHODOLOGY.md` assume le workflow IA-first sans le cacher. Honnete.

### 3. Chiffres coherents et sources
8.83M qps (Xeon E5-2690 v2 + X520) et 16-17M qps (Threadripper 5995WX + dual X520) : plausibles et coherents avec la litterature AF_XDP (Cloudflare, Meta, Fastly). Hardware precisement specifie → reproductible.

### 4. Architecture documentee
Pipeline `NIC → eBPF → XSKMAP → AF_XDP → worker` documente + issues techniques (CPUMAP/ZC exclusion, hot path stats) tracees avec impact mesure. Vrai engineering log, pas du marketing.

---

## Problemes documentaires

### 1. "World's First ASM-Accelerated DNS Server" — BULLSHIT MARKETING [CRITIQUE]
- Inverable, non source, probablement faux
- Knot DNS a du XDP natif depuis 2020 ; PowerDNS dnsdist a DPDK
- **Pour un acheteur institutionnel : declenche la mefiance IMMEDIATEMENT**
- A SUPPRIMER ou remplacer par comparatif factuel direct avec benchmark

### 2. Incoherence 128k vs 195k qps userspace
- README annonce 195k qps SO_REUSEPORT
- REVIEW-CHECKLIST cite 128k qps comme "ceiling"
- Sans explication = red flag d'exactitude pour un auditeur institutionnel

### 3. Threat Model absent [BLOQUANT pour usage etatique]
- Aucun document `THREAT_MODEL.md` dans le repo
- Qui sont les attaquants modelises ? APT niveau etat ? Script kiddie ?
- Sans threat model formel, la "securite" du projet est non evaluable

### 4. Cryptographie non documentee [BLOQUANT]
- DoT/DoH annonces mais specs crypto non detaillees (TLS 1.2/1.3 ? suites ? FIPS ?)
- ACME TLS : quelle CA ? Certificats intermediaires ?
- Pour ANSSI/FIPS : absence totale de mention = redhibitoire

### 5. Audit securite tiers absent [BLOQUANT]
- "External human security review is planned before v1.0" = pas fait
- Le "pentester IA" du workflow ne remplace pas un auditeur humain
- Necessite : CESTI pour CC, ou NCC Group / Trail of Bits

### 6. Clause AGPL — probleme etatique
- AGPL v3 = obligation de publier les modifications si service expose reseau
- La licence commerciale parallele (`COMMERCIAL_LICENSE.md`) est la bonne voie
- A mettre en avant pour usage etatique

### 7. Roadmap / SLA / support absent
- Aucune roadmap v1.0 datee publiquement, aucun CVE response SLA
- Pour acheteur institutionnel : sans SLA, zero confiance

---

## Recommandations prioritaires

**P0 (bloquant avant tout pitch institutionnel) :**
- [ ] Supprimer "World's First" → comparatif factuel Knot DNS XDP / dnsdist DPDK
- [ ] Rediger `THREAT_MODEL.md` (attaquants, assets, contre-mesures, residuel)
- [ ] Rediger `SECURITY.md` (algos crypto, TLS version, contact CVE, response SLA)

**P1 (necessaire pour credibilite) :**
- [ ] Clarifier incoherence 128k vs 195k qps userspace
- [ ] Roadmap v1.0 publique avec jalons dates
- [ ] Clarification AGPL vs licence commerciale pour usage etatique

**P2 (pour atteindre la maturite institutionnelle) :**
- [ ] Audit tiers humain (Trail of Bits, NCC Group, ou CESTI agree ANSSI)
- [ ] SBOM (Software Bill of Materials) — dependances Rust + versions + CVEs
- [ ] Build reproductible documente (hash des binaires publies verifiable)
- [ ] Compliance checklist partielle (FIPS, CC EAL2 au minimum)

---

# PARTIE 2 — AUDIT PERFORMANCE & USAGE MILITAIRE/SOUVERAINETE

## Pertinence de la perf XDP pour usage defense

### 1. DNS Sink Hole / Filtrage C2 [HAUTE VALEUR]
- Filtrage domaines malveillants (C2, malware, exfiltration DNS) a 16M qps = aucun trafic ne passe sans inspection meme sur backbone
- XDP blacklist NXDOMAIN in-place (~1µs) : reponse avant que le kernel ne voie le paquet
- **Use case operationnel direct : DNS resolver national de filtrage souverain**

### 2. Protection anti-amplification DNS [HAUTE VALEUR]
- A 8-16M qps, Runbound absorbe le flood DNS sans drop et peut repondre ou blackholer
- XDP ICMP rate-limiter protege le canal de management
- Mais : pas de protection DDoS volumetrique reseau (hors perimetre DNS)

### 3. DNS interne infrastructure critique [VALEUR MODEREE]
- 16M qps surdimensionne pour DNS interne mais la valeur = resilience + API live + split-horizon
- Cas d'usage : OIV (Operateurs d'Importance Vitale), reseaux de commandement

### 4. Deploiement forward resolver [VALEUR CONTEXTUELLE]
- 195k qps userspace sur ARM = suffisant pour reseaux tactiques contraints

---

## Stack Rust + eBPF + XDP — Analyse souverainete

**POUR :**
- Rust = memoire safe, pas de buffer overflow / use-after-free
- eBPF = standard Linux kernel, pas de kernel module custom a maintenir
- Static binary musl = deploiement simple, pas de libc dependency hell
- Compilation native depuis source = supply chain controlable

**CONTRE / RISQUES :**
- Dependances Cargo (crates.io) : sans SBOM et audit, supply chain attack non controlee
- eBPF rootkit territory : `CAP_BPF` peut lire la memoire kernel si compromis
- Reproductibilite non documentee : impossible de verifier binaire = source

**Mitigation possible :**
- `cargo audit` automatise en CI
- Build reproductible + sha256sum des releases
- Revue crates critiques (aya-bpf, tokio, hickory-dns)
- SBOM a chaque release (`cargo-cyclonedx` ou `cargo-sbom`)

---

## Surface d'attaque reelle

### 1. API HTTP localhost — vecteurs de pivot
- SSRF depuis une app web colocalisee → atteint l'API Runbound
- Bearer token en HTTP sur localhost lisible par un process local via `/proc`
- **Recommandation** : Unix socket ou HTTPS localhost avec mTLS pour API admin

### 2. eBPF — risque privilege escalation
- Requiert `CAP_BPF` + `CAP_NET_ADMIN` (ou root)
- Vulnerabilite verifier eBPF → kernel privilege escalation (CVE-2021-3490, CVE-2022-0500 : precedents reels)
- **Non documente** : separation loader (root) / worker DNS (user non-privilege)
- **CRITIQUE pour usage militaire** : modele de privileges explicite obligatoire

### 3. Blacklist XDP — contournements
- BPF map 500k entries max → DOS potentiel par flood d'entrees via API
- **Fragmentation IP** : paquet DNS fragmente → XDP voit le fragment, pas le DNS complet → XDP_PASS vers slow path non filtre
- **DNS-over-TCP** : si blacklist XDP filtre UDP uniquement, TCP DNS bypasse le filtre
- Ces vecteurs **ne sont pas documentes** dans les limites connues

### 4. Flood DNS / amplification
- **Pas de RRL (Response Rate Limiting) DNS** documente
- RFC 5358, BIND et Knot l'ont nativement
- **Point manquant important** pour tout DNS expose ou semi-expose

---

## Ce qui manque absolument pour deploiement militaire

**BLOQUANT :**
- [ ] **Integrite binaire** : signatures GPG/minisign, sha256 public, build reproductible documente
- [ ] **Modele de privileges explicite** : loader eBPF (root) → drop vers user dedie. Systemd hardening (`CapabilityBoundingSet`, `NoNewPrivileges`, etc.)
- [ ] **Logs auditables SIEM-ready** : JSON/CEF/syslog RFC5424 — chaque requete DNS, chaque action API (who/what/when/from), chaque evenement de securite
- [ ] **Response Rate Limiting DNS (RRL)** : protection anti-amplification obligatoire
- [ ] **Air-gap / offline support** : ACME TLS inutilisable en reseau isole — documenter mode PKI interne + MAJ blacklists offline

**IMPORTANT :**
- [ ] Audit log des actions par role (traçabilite reglementaire)
- [ ] HA / failover procedure documentee
- [ ] Isolation multi-tenant formellement documentee

---

## Verdict global

> **Ce projet peut-il interesser un etat-nation ? OUI, MAIS PAS EN L'ETAT.**

**Atouts techniques :**
- Performance XDP reelle et mesuree — pas du benchmark synthetique
- Architecture Rust = memoire safe par design
- Blacklisting XDP-layer = filtrage souverain a vitesse reseau (C2, malware, exfiltration)
- Split-horizon DNS = separation logique reseau interne/externe
- API live sans restart = gestion operationnelle sans interruption
- Static binary = deploiement predictible et controlable
- Honnetete intellectuelle dans la doc = signal de confiance rare

**Ce qui bloque un deploiement etatique aujourd'hui :**
- Pas d'audit securite tiers → non validable par RSSI
- Pas de threat model → surface d'attaque non formalisee
- Pas d'integrite binaire verifiable → supply chain non controlee
- Statut "Experimental" → engage la responsabilite de l'acheteur
- Pas de RRL DNS anti-amplification
- Modele de privileges eBPF non documente
- Logs forensic non specifies
- Pas de SLA ni roadmap de support engagee
- AGPL necessite clarification juridique pour usage etatique

**Niveau de maturite actuel : TRL 4-5** (validation en labo, pas en operations)  
**Cible pour usage etatique : TRL 7-8** (demonstration en environnement representatif)

**Chemin critique (ordre de priorite) :**
1. Audit securite tiers humain qualifie (6-12 semaines)
2. Threat model + documentation cryptographie (2-4 semaines)
3. Build reproductible + signatures binaires (1-2 semaines)
4. RRL DNS + modele privileges eBPF documente (2-4 semaines)
5. Logs structures SIEM-ready (2-4 semaines)
6. Licence commerciale clarifiee pour usage etatique (juridique, parallele)
7. Certification partielle CC EAL2 ou qualification ANSSI (12-24 mois apres)

---

> **Conclusion** : Runbound a les fondations techniques pour etre un outil souverain serieux. La performance XDP est reelle. L'architecture Rust est saine. L'honnetete intellectuelle de la documentation est un avantage competitif rare.  
> Mais entre "fondations techniques solides" et "deployable par un etat-nation", il y a 12 a 18 mois de travail sur la securite, l'audit, la compliance et la gouvernance.  
> **Le projet ne manque pas de code — il manque de paperasse de confiance. Et dans l'univers etatique, c'est precisement ce qu'on achete.**
