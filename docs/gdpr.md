# RGPD / GDPR

## Responsabilités

Runbound est un logiciel. Son auteur est **éditeur** au sens du RGPD —
il ne traite aucune donnée personnelle de vos utilisateurs.

L'**opérateur** qui déploie Runbound est le responsable de traitement.
Il lui appartient de définir la base légale, la durée de conservation,
et les procédures d'exercice des droits.

## Données traitées par Runbound

| Donnée | Où | Durée | Configurable |
|--------|----|-------|--------------|
| IP source des requêtes DNS | Ring buffer RAM (`/logs`) | Jusqu'au redémarrage ou rotation | `log-retention`, `log-client-ip` |
| Domaines interrogés | Ring buffer RAM (`/logs`) | Jusqu'au redémarrage ou rotation | `log-retention` |
| IP source des appels API | Audit log | Jusqu'à rotation manuelle | `audit-log-path` |
| Clé API (hash) | Mémoire uniquement | Durée du process | — |

Runbound **ne stocke pas** de données DNS sur disque par défaut.
Le `logfile:` est désactivé par défaut.

## Recommandations pour la conformité

**Minimisation :** désactiver `/logs` si vous n'en avez pas l'usage :

```
log-retention: 0
```

**Pseudonymisation :** masquer les IPs clientes :

```
log-client-ip: no
```

> Ces deux directives nécessitent un **redémarrage** pour prendre effet
> (le SIGHUP ne recharge que les zones DNS, pas le ring buffer).


**Droit à l'oubli :** vider le ring buffer à la demande :

```
curl -X DELETE http://localhost:8081/logs -H "Authorization: Bearer $KEY"
```

**Logfile disque :** si vous activez `logfile:`, mettez en place une
rotation avec `logrotate` et une durée de conservation explicite.

## Transferts hors UE

Les feeds de blocklists (Hagezi, etc.) sont téléchargés depuis des CDN
internationaux. Aucune donnée personnelle n'est transmise lors de ces
téléchargements — seule une requête HTTP GET sans payload est émise.
