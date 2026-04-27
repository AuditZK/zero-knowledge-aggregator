# Procédure de release — push d'un nouveau binaire en prod

> Pour le **premier** déploiement avec B2 (v0 → v1), voir
> [MIGRATION_FROM_LEGACY.md](MIGRATION_FROM_LEGACY.md). Ce doc couvre
> les déploiements suivants (v_N → v_N+1) où les deux versions ont
> le code B2 et savent se parler via attested handoff.

## Vue d'ensemble

```
┌──────────────────┐                          ┌──────────────────┐
│  v_N (running)   │                          │  v_N+1 (booting) │
│  master_key_v_N  │                          │  measurement_N+1 │
│  serves users    │                          │  → not yet usable│
│  + handoff srv   │ ◄─── attested ECIES ──── │  + handoff client│
└──────────────────┘                          └──────────────────┘
                                                       │
                                                       ▼ master_key reçue
                                              ┌──────────────────┐
                                              │  v_N+1 unwrap    │
                                              │  DEK from DB     │
                                              │  takes over      │
                                              └──────────────────┘
```

Trois actions opérateur, du laptop :

1. **Build** : compiler le binaire, capturer son measurement.
2. **Sign** : ajouter ce measurement au signed allowlist via
   `cmd/release-sign sign`.
3. **Deploy** : push vers la VM Milan, demarrer v_N+1 à côté de v_N,
   handoff automatique.

## Prérequis

- Tu as ta keypair Ed25519 d'opérateur (`~/.tee/operator` + `.pub`,
  passphrase mémorisée).
- v_N tourne en prod et a le code B2 (handoff serveur dispo sur
  `/api/v1/admin/handoff`).
- Tu as l'allowlist actuelle (le `signed_allowlist.json` que v_N
  connaît, généralement stocké en GCP metadata `signed-allowlist`).

## Procédure

### Étape 1 — Build local

```bash
cd ~/repo
git checkout main && git pull

# Build reproducible (mêmes flags que Dockerfile.production)
docker build -f Dockerfile.production -t enclave-go:v_N+1 .

# Pour récupérer le measurement attendu, on peut soit:
# A. Le calculer localement avec snphost (besoin AMD SEV-SNP toolkit)
# B. L'observer au démarrage de v_N+1 sur la VM (le log
#    "master key derived from SEV-SNP measurement" l'affiche)
#
# Pour la phase 1 du déploiement, suppose qu'on l'observe en B :
# on lance v_N+1 D'ABORD avec un signed_allowlist temporaire qui
# autorise un measurement bidon, on observe le vrai, puis on signe
# le vrai et on relance.
#
# Plus propre : reproducible build + tool offline qui calcule le
# measurement déterministe. À implémenter quand on aura le temps.
```

### Étape 2 — Récupère le measurement depuis v_N+1 (one-shot)

Démarre temporairement v_N+1 sur la VM SANS handoff (pour qu'il loggue
son measurement et meurt rapidement) :

```bash
# Sur tee-milan-01
docker run --rm \
  --device /dev/sev-guest:/dev/sev-guest \
  -e ENV=development \
  enclave-go:v_N+1 \
  /app/admin-probe measurement
# → output: "12068361369cf917..."
```

(Si `admin-probe` ne supporte pas la sub-commande `measurement`, tu
peux extraire le measurement depuis un démarrage à blanc avec ENV=
`development` et `DATABASE_URL=` vide ; le log
`master key derived from SEV-SNP measurement {"measurement_prefix": ...}`
le donne à la première seconde.)

### Étape 3 — Sign l'allowlist

```bash
# Sur ton laptop
./release-sign sign \
  --key ~/.tee/operator \
  --measurement 12068361369cf917... \
  --label "go-enclave-v$(date +%Y%m%d-%H%M%S)" \
  --previous signed_allowlist.json \
  --out signed_allowlist.json
# → demande passphrase, écrit le nouveau fichier
```

`--previous` est important : ça inclut TOUS les measurements précédents
en plus du nouveau. Ainsi v_N peut autoriser v_N+1 (qui contient son
measurement à elle ET le nouveau). Une fois v_N+1 stable, tu peux
optionnellement retirer le measurement de v_N de la liste.

### Étape 4 — Push l'allowlist vers GCP metadata

```bash
INSTANCE_NAME=tee-milan-01
ZONE=$(gcloud compute instances list --filter="name=$INSTANCE_NAME" --format="value(zone)")

gcloud compute instances add-metadata "$INSTANCE_NAME" \
  --zone="$ZONE" \
  --metadata-from-file=signed-allowlist=signed_allowlist.json
```

### Étape 5 — Démarre v_N+1 à côté de v_N

Sur la VM, le script `start-enclave.sh` standard prend un flag pour
démarrer un container "next" sans toucher au running. Si tu n'as pas
ce flag, fais-le manuellement :

```bash
# Sur tee-milan-01
ssh tee-milan-01

PEER_URL="https://localhost:3050/api/v1/admin/handoff"  # v_N
SIGNED_ALLOWLIST=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/signed-allowlist")

# Démarre v_N+1 avec HANDOFF_PEER_URL
docker run -d \
  --name enclave_go_prod_next \
  --device /dev/sev-guest:/dev/sev-guest \
  -p 3055:3050 -p 50055:50051 -p 50056:50052 \
  -e ENV=production \
  -e DATABASE_URL="$DATABASE_URL" \
  -e ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  -e ENCLAVE_JWT_SECRET="$ENCLAVE_JWT_SECRET" \
  -e HANDOFF_PEER_URL="$PEER_URL" \
  -e HANDOFF_SIGNED_ALLOWLIST="$SIGNED_ALLOWLIST" \
  -e GOMEMLIMIT=480MiB -e GOGC=75 \
  -v ~/tee-aggregator-go/certs:/etc/enclave:ro \
  enclave-go:v_N+1
```

v_N+1 boot, fait son attestation, contacte v_N (qui valide le
measurement contre l'allowlist + le binding ECIES), reçoit
`master_key`, unwrap le DEK, devient opérationnel.

### Étape 6 — Vérifie

```bash
docker logs --tail 30 enclave_go_prod_next

# Tu dois voir, dans l'ordre:
#   "B2 handoff: requesting master key from predecessor"
#   "handoff client: master key received and decrypted"
#   "encryption service bound to unwrapped DEK from data_encryption_keys"
#   "enclave worker ready"  database=true
```

Smoke test :

```bash
curl -k https://localhost:3055/health
curl -k https://localhost:3055/api/v1/attestation | jq .attestation.measurement
# → doit afficher le measurement de v_N+1 (= celui de l'allowlist)
```

### Étape 7 — Bascule du trafic

Côté ton VPS backend, modifie l'upstream du gateway pour pointer vers
`tee-milan-01:3055` (v_N+1) au lieu de `tee-milan-01:3050` (v_N).
Reload nginx / restart gateway.

### Étape 8 — Stop v_N

Une fois que tu observes que v_N+1 sert le trafic sans erreur depuis
au moins quelques minutes :

```bash
docker stop enclave_go_prod
docker rm enclave_go_prod

# Renomme v_N+1 vers le nom canonique
docker rename enclave_go_prod_next enclave_go_prod
# (ou redeploy via start-enclave.sh sans HANDOFF_PEER_URL)
```

### Étape 9 — Wipe `HANDOFF_PEER_URL`

Si tu as gardé HANDOFF_PEER_URL dans GCP metadata, retire-le :

```bash
gcloud compute instances remove-metadata "$INSTANCE_NAME" \
  --zone="$ZONE" \
  --keys=handoff-peer-url
```

Sinon au prochain reboot, v_N+1 essaierait de faire un handoff vers
un v_N qui n'existe plus → boot fail.

## Plan de rollback

| Symptôme | Action |
|---|---|
| v_N+1 ne démarre pas (handoff fail) | Le container exit. v_N tourne toujours, pas d'impact. Investigate logs, fix, relance |
| v_N+1 démarre mais errors sur les requêtes | `docker stop enclave_go_prod_next`, garde v_N en service |
| v_N+1 a pris le trafic mais sync foire | Re-pointe gateway vers `:3050` (v_N), stop v_N+1 |

## Notes opérationnelles

- **Reboot pendant la fenêtre handoff** : si la VM crash entre l'étape 7
  (gateway pointe vers v_N+1) et l'étape 8 (v_N stoppé), v_N+1 va essayer
  de re-handoff vers v_N qui ne tourne plus. Boot fail. → Fix : commencer
  par stopper v_N (étape 8 avant 7) si tu acceptes une courte coupure
  pendant la bascule (de 0 à 30s).
- **Allowlist size** : garde uniquement les versions **réellement
  déployées** + la prochaine candidate. Plus la liste est petite, plus
  l'audit côté user est simple.
- **Audit côté user** : un user paranoiaque peut, à tout moment, faire
  `curl /api/v1/attestation` et vérifier que le measurement retourné est
  dans le `signed-allowlist` qu'il connaît (signé par la pubkey
  hardcodée dans le code GitHub).

## Ce qui ne nécessite PAS cette procédure

- Restart du container (sans changement de binaire) : aucun handoff,
  v_N redérive son master_key du measurement (inchangé) et unwrap le
  DEK normalement.
- Mise à jour des runtime secrets (ENCRYPTION_KEY rotation,
  DATABASE_URL changement, etc.) : push dans GCP metadata + restart,
  aucun handoff nécessaire.
- Ajout d'une migration SQL : `AUTO_MIGRATE=true` au prochain restart,
  aucun handoff.
