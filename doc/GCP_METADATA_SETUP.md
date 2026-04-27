# Setup GCP Metadata pour la VM enclave

> Ce doc liste les étapes ops pour migrer les runtime secrets de `.env` vers
> les **GCP instance metadata custom attributes**.
>
> Pourquoi instance metadata et pas Secret Manager ? Instance metadata est
> **gratuit** (Secret Manager ~$0.06/secret/mois). Pour notre threat model
> (admin host = opérateur = trusted pour les runtime secrets non-DEK), les
> deux donnent la même garantie : pas de `.env` files versionnables, plus
> jamais. Si un jour tu veux des audit logs détaillés ou de la rotation
> automatique, migre vers Secret Manager (le code Go ne change pas).

## 1. Pré-requis

- VM GCP Confidential Compute (SEV-SNP) déjà provisionnée pour Milan
- `gcloud` CLI installée + authentifiée sur ton laptop
- Variables d'environnement actuelles documentées (extraites depuis le
  `.env` ou le `docker inspect` du container existant)

## 2. Setting up — clés requises

Les **3 secrets obligatoires** :

| Clé metadata | Description | Exemple |
|---|---|---|
| `database-url` | URL Postgres complète | `postgresql://enclave_user:PASS@87.106.4.85:5436/enclave_db?sslmode=disable` |
| `encryption-key` | Master key fallback (32 bytes hex) | `dee9448a9550...` |
| `enclave-jwt-secret` | HS256 secret (≥32 bytes) | `b2f3a9c8e7d6b5a4...` |

```bash
INSTANCE_NAME=tee-milan-01
ZONE=$(gcloud compute instances list --filter="name=$INSTANCE_NAME" --format="value(zone)")

gcloud compute instances add-metadata "$INSTANCE_NAME" \
  --zone="$ZONE" \
  --metadata="database-url=postgresql://enclave_user:PASS@87.106.4.85:5436/enclave_db?sslmode=disable" \
  --metadata="encryption-key=dee9448a9550aec8cf808724c2d65777ded32a986e04ab88a45ba808c4a024c6" \
  --metadata="enclave-jwt-secret=$(openssl rand -hex 32)"
```

**Important** : `enclave-jwt-secret` doit être un secret nouveau (au moins 32
bytes random hex). Ne réutilise PAS un secret existant côté frontend ou autre
service — il y aurait risque de cross-confusion JWT.

## 3. Setting up — clés optionnelles (recommandées en prod)

| Clé metadata | Description | Quand l'utiliser |
|---|---|---|
| `cors-origin` | Origine CORS autorisée (CORS-001) | Toujours en prod (refuse `*`) |
| `measurement-allowlist` | SEV-SNP measurements autorisés (SEC-106) | Pour pin la version exacte attendue |
| `grpc-client-cn-allowlist` | CN allowlist mTLS gRPC (AUTH-001) | Toujours en prod |
| `jwt-expected-issuer` | Issuer JWT attendu (AUTH-002) | Si ton frontend signe avec un issuer |
| `enclave-domain` | Domain TLS (Let's Encrypt) | Pour le path TLS_CERT_PATH |
| `log-level` | `debug` / `info` / `warn` / `error` | Défaut `info` |
| `log-server-api-key` | API key pour le log stream SSE | Si tu publies les logs |
| `benchmark-service-url` | URL du benchmark service | Si utilisé |
| `ctrader-client-id`, `ctrader-client-secret` | OAuth cTrader | Si cTrader supporté |
| `mt-bridge-url`, `mt-bridge-hmac-secret` | Bridge MetaTrader | Si MT supporté |
| `exchange-http-proxy` | Proxy HTTP pour les exchanges geo-restreints | Si Binance EU etc. |

```bash
gcloud compute instances add-metadata "$INSTANCE_NAME" \
  --zone="$ZONE" \
  --metadata="cors-origin=https://app.auditzk.com" \
  --metadata="grpc-client-cn-allowlist=report-service,gateway" \
  --metadata="enclave-domain=enclave.auditzk.com" \
  --metadata="log-level=info"
```

## 4. Setting up — clés B2 handoff (à utiliser plus tard, lors d'un upgrade)

Ces clés ne servent QUE pendant la fenêtre d'upgrade entre deux versions
de l'enclave (v_N → v_N+1). En régime nominal, elles sont vides ou absentes.

| Clé metadata | Description | Quand la set |
|---|---|---|
| `handoff-peer-url` | URL du prédécesseur v_N depuis lequel récupérer la master_key | UNIQUEMENT pendant l'upgrade window |
| `signed-allowlist` | Override de la signed_allowlist hardcodée dans le binaire (rare) | Quasi jamais |

Voir `doc/RFC_B2_HANDOFF.md` (à créer) pour la procédure complète.

## 5. Vérification

Sur la VM, vérifie que tu peux lire les metadata :

```bash
ssh tee-milan-01

# Lister tous les attributes metadata
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true&alt=json" \
  | jq

# Lire une clé spécifique (pour debug seulement, ne PAS log les secrets)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/database-url"
```

## 6. Migration depuis l'archi `.env` actuelle

### Étape 1 — Inventaire

```bash
# Sur tee-milan-01
docker inspect enclave_go_test --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep -E '^(DATABASE_URL|ENCRYPTION_KEY|ENCLAVE_JWT_SECRET|CORS_ORIGIN|...)=' \
  > /tmp/env-snapshot.txt
```

Vérifie que toutes les variables nécessaires sont là. Note les valeurs (ne pas
les commit).

### Étape 2 — Push vers metadata

```bash
# Sur ton laptop (avec gcloud + auth)
source /tmp/env-snapshot.txt
gcloud compute instances add-metadata "$INSTANCE_NAME" \
  --zone="$ZONE" \
  --metadata="database-url=$DATABASE_URL" \
  --metadata="encryption-key=$ENCRYPTION_KEY" \
  --metadata="enclave-jwt-secret=$ENCLAVE_JWT_SECRET"
```

### Étape 3 — Bascule sans downtime (optionnel)

Tant que `enclave_go_test` actuel tourne (lancé via `docker-compose.parallel-test.yml`
qui charge depuis `.env.parallel-test`), il continue à fonctionner. Pour basculer :

```bash
# Sur tee-milan-01
cd ~/tee-aggregator
git checkout fix/audit-security-remediations
git pull origin fix/audit-security-remediations

# Test le script en mode dry (just check metadata access, do not start)
bash -n scripts/start-enclave.sh   # syntax check
./scripts/start-enclave.sh --build  # builds + starts NEW container "enclave_go_prod"
```

Le script lance `enclave_go_prod` (port 3050/50051/50052) **à côté** de
`enclave_go_test` (port 3060/50061/50062). Pas de collision.

### Étape 4 — Sanity check du nouveau container

```bash
docker logs enclave_go_prod --tail 50

# Doit montrer:
#   "starting enclave worker" ENV=production
#   "REST TLS certificate loaded"
#   "database connected"
#   "DEK loaded" (ou "wrote fresh DEK" si DB neuve)
#   "report signer initialized"
#   "report signer bound to SEV-SNP attestation" platform=sev-snp attested=true
#   "enclave worker ready" database=true tls=true e2e=true attestation=true

curl -k https://localhost:3050/health
curl -k https://localhost:3050/api/v1/attestation | jq .attestation.measurement
```

### Étape 5 — Bascule du trafic (côté nginx/gateway)

Côté ton VPS backend (où tourne `auditzk_gateway`), modifie l'upstream
pour pointer vers `tee-milan-01:3050` (nouveau) au lieu de `tee-milan-01:3060` (ancien).

```bash
# Sur le VPS backend, dans le fichier conf nginx ou compose du gateway
# Avant: ENCLAVE_URL=https://tee-milan-01:3060
# Après: ENCLAVE_URL=https://tee-milan-01:3050
```

Reload le gateway. Les requêtes futures partent vers `enclave_go_prod`.

### Étape 6 — Suppression de l'ancien

Une fois que tu as validé que `enclave_go_prod` tourne stable depuis 24-48h :

```bash
docker stop enclave_go_test
docker rm enclave_go_test

# Optionnel : supprimer les .env files
rm -f ~/zero-knowledge-aggregator-go-test/.env*
```

## 7. Rollback

Si quelque chose ne va pas après l'étape 5 :

```bash
# Re-pointe le gateway vers l'ancien container (qui tourne toujours)
# Sur le VPS backend
# ENCLAVE_URL=https://tee-milan-01:3060

# Stoppe le nouveau
docker stop enclave_go_prod
```

`enclave_go_test` n'a pas été touché → service revient à l'état précédent.

## 8. Audit / monitoring

GCP fournit un audit log automatique de tous les changements de metadata :

```bash
gcloud logging read \
  'resource.type="gce_instance" AND
   protoPayload.methodName="v1.compute.instances.setMetadata"' \
  --limit=20 --format=json
```

Tu peux configurer une alerte Cloud Monitoring sur ce log pour être notifié
de toute modification non-attendue des metadata (compromise potentiel).

## 9. Notes de sécurité

- Les metadata sont accessibles à **tout process** tournant sur la VM (read-only),
  via `metadata.google.internal`. Ce n'est PAS un mécanisme d'isolation entre
  containers sur la même VM.
- Les metadata sont visibles aux **utilisateurs IAM** ayant `compute.instances.get`
  sur le projet. Limite ce rôle aux opérateurs.
- Les metadata sont **versionnées** automatiquement par GCP, mais les versions
  passées ne sont pas accessibles via metadata server (uniquement via Audit Logs).
  Pour des secrets nécessitant rotation rapide + lecture historique, utilise
  Secret Manager.
- Les metadata ne sont pas chiffrées au repos par une clé sous ton contrôle
  (Google KMS-managed). Si ce point te bloque, passe à Secret Manager + CMEK.
