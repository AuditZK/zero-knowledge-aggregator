# Migration v0 → v1 : premier déploiement avec B2 trustless handoff

> **Quand utiliser ce doc** : tu déploies pour la première fois un binaire
> qui inclut le code B2 (signed binary identity + handoff serveur). Le
> binaire actuellement en prod n'a pas ce code, donc il ne peut pas servir
> de prédécesseur dans un handoff normal. Cette migration est *one-shot*.
>
> Pour les déploiements suivants (v1 → v2 → vN), utilise [doc/RELEASE_PROCEDURE.md](RELEASE_PROCEDURE.md) — le handoff B2 normal s'applique.

## Pré-requis

- Le binaire v0 actuellement déployé tourne avec un DEK valide (vérifie
  via `docker logs` que tu vois `loaded active DEK from database` au
  démarrage).
- Tu as ta keypair Ed25519 d'opérateur (générée via
  `cmd/release-sign keygen`) et tu as remplacé `operatorPubkey` dans
  [internal/bootstrap/signed_allowlist.go](../internal/bootstrap/signed_allowlist.go)
  par ta vraie pubkey (la pubkey placeholder fait fail-close au boot).
- Tu as buildé v1 et noté son SEV-SNP measurement (le hash que GitHub
  Actions ou ton build local affiche après `go build`).
- Ta v1 est signée : tu as un `signed_allowlist.json` qui contient le
  measurement de v1, signé avec ta privkey.

## Pourquoi un chemin spécial ?

Schéma du DEK normal :

```
SEV-SNP measurement → HKDF → master_key → wrap(DEK) → DB
```

v0 a un measurement ≠ v1. Donc `master_key_v0` ≠ `master_key_v1`. Le
DEK wrappé en DB a été chiffré par `master_key_v0` ; v1 ne peut pas
l'ouvrir avec `master_key_v1`.

Solution one-shot pour la migration :

1. Pendant que v0 tourne, on extrait `master_key_v0` (qui vit dans la
   RAM TEE de v0).
2. On le passe à v1 via `LEGACY_MASTER_KEY_HEX`.
3. v1 boot, voit la variable, l'utilise pour unwrap le DEK existant.
4. v1 re-wrappe immédiatement le DEK avec son `master_key_v1`
   (mesurement-derived) et update la ligne `data_encryption_keys`.
5. À partir du 2e boot de v1, plus besoin de la variable — v1 dérive
   `master_key_v1` du measurement et unwrap le DEK ré-wrappé.
6. Pour v2 → vN à venir : handoff B2 normal (v1 sert le predecessor).

## Procédure pas-à-pas

### Étape 1 — Compile l'admin tool

Sur ton laptop, depuis la branche qui a le code B2 :

```bash
GOOS=linux GOARCH=amd64 go build -trimpath \
  -o /tmp/admin-export-master-key \
  ./cmd/admin-export-master-key
```

### Étape 2 — Sur la VM Milan, drop le tool dans le container v0 actuel

```bash
ssh tee-milan-01

# Copie le binaire dans le container running v0 (lui hérite du même
# SEV-SNP measurement que v0, donc dérive la même master_key_v0).
docker cp /tmp/admin-export-master-key enclave_go_test:/tmp/

# Vérifie que le tool peut voir la DB et /dev/sev-guest.
docker exec enclave_go_test ls -la /dev/sev-guest /tmp/admin-export-master-key
```

### Étape 3 — Extrait `master_key_v0`

⚠️ **Maintenance window starts here**. Le master key transite en clair
brièvement (stdout du tool → fichier sur ta VM → metadata GCP). Voir
"Threat model" en bas pour limiter la fenêtre.

```bash
# Sur Milan, sortie sur stdout (32 bytes hex = 64 chars).
docker exec enclave_go_test /tmp/admin-export-master-key 2>/tmp/migration.log \
  > /tmp/master.key.hex

# Sanity check
wc -c /tmp/master.key.hex     # devrait afficher "65 /tmp/master.key.hex" (64 + newline)
cat /tmp/migration.log         # diagnostics (DEK id, master_key_id, etc.)
```

### Étape 4 — Push dans GCP metadata

```bash
INSTANCE_NAME=tee-milan-01
ZONE=$(gcloud compute instances list --filter="name=$INSTANCE_NAME" --format="value(zone)")

gcloud compute instances add-metadata "$INSTANCE_NAME" \
  --zone="$ZONE" \
  --metadata-from-file=legacy-master-key-hex=/tmp/master.key.hex

# Wipe la copie locale
shred -u /tmp/master.key.hex
```

### Étape 5 — Push aussi le `signed-allowlist` dans metadata

(Si tu n'as pas encore mis à jour la `operatorPubkey` constante côté
binaire, fais-le maintenant et rebuild — la pubkey hardcodée DOIT
matcher ta privkey de signature.)

```bash
gcloud compute instances add-metadata "$INSTANCE_NAME" \
  --zone="$ZONE" \
  --metadata-from-file=signed-allowlist=signed_allowlist.json
```

### Étape 6 — Update `start-enclave.sh` pour lire `legacy-master-key-hex`

Ajoute dans le script (juste à côté des autres lectures de metadata) :

```bash
LEGACY_MASTER_KEY_HEX=$(get_metadata "legacy-master-key-hex")
```

Puis dans le `docker run` :

```bash
  -e LEGACY_MASTER_KEY_HEX="${LEGACY_MASTER_KEY_HEX:-}" \
```

(Cette modification est temporaire pour la migration ; tu peux la
laisser dans le script — elle sera no-op quand metadata est vide.)

### Étape 7 — Build & deploy v1

```bash
# Sur Milan
cd ~/tee-aggregator
git pull origin fix/audit-security-remediations  # ou la branche qui a le code B2

# Build l'image v1 prod
docker build -f Dockerfile.production -t enclave-go:prod .

# Capture le measurement réel pour ton allowlist (à inclure dans
# signed_allowlist.json si tu ne l'as pas déjà fait — voir
# cmd/release-sign sign --measurement <hash>).

# Stop v0 (il a déjà donné son master_key, il n'est plus utile)
docker stop enclave_go_test
# Ne le supprime PAS encore : c'est ton fallback de rollback (étape 10).

# Démarre v1 via le script (qui lit le metadata légèrement modifié)
./scripts/start-enclave.sh
```

### Étape 8 — Vérifie que v1 a fait l'auto-rewrap

```bash
docker logs enclave_go_prod 2>&1 | grep -E "legacy migration|encryption service bound"
```

Attendu :

```
INFO ... legacy migration: re-wrapping DEK with measurement-derived master key
INFO ... legacy migration complete: DEK re-wrapped with measurement master key
        hint: you can now safely remove LEGACY_MASTER_KEY_HEX from the deploy env
INFO ... encryption service bound to unwrapped DEK from data_encryption_keys
```

Vérifie aussi que les credentials clients sont déchiffrables :

```bash
# Test via gateway / frontend : un user devrait pouvoir voir ses snapshots,
# le scheduler quotidien doit pouvoir sync sans erreur de décryption.
# Sinon : ne PAS retirer la legacy-master-key-hex (étape 9), revenir
# en arrière (étape 10).
```

### Étape 9 — Wipe le legacy master key de metadata

⚠️ **Maintenance window ends here**. À ne faire QUE quand tu es certain
que v1 marche stable.

```bash
gcloud compute instances remove-metadata "$INSTANCE_NAME" \
  --zone="$ZONE" \
  --keys=legacy-master-key-hex
```

Confirme avec un reboot test :

```bash
docker restart enclave_go_prod
docker logs --tail 30 enclave_go_prod
# Doit afficher:
#   - "master key derived from SEV-SNP measurement"
#   - PAS "legacy migration"
#   - "encryption service bound to unwrapped DEK"
```

### Étape 10 — Cleanup final

```bash
# Supprime l'ancien container v0
docker rm enclave_go_test

# Supprime le binaire admin du container (s'il existe encore)
# Note: il a déjà été supprimé avec le container, mais bon
docker exec enclave_go_prod rm -f /tmp/admin-export-master-key 2>/dev/null || true
```

## Plan de rollback

À chaque étape, voici comment revenir :

| Si ça échoue à... | Action de rollback |
|---|---|
| Étape 3 (export fail) | Aucune action — v0 continue à tourner normalement, rien n'a changé |
| Étape 7 (v1 ne boot pas) | `docker start enclave_go_test` (v0 redémarre, lit toujours sa propre DB normalement) |
| Étape 8 (v1 boot mais sync fail) | `docker stop enclave_go_prod && docker start enclave_go_test` |
| Étape 9 (après remove-metadata, reboot v1 fail) | Re-push `legacy-master-key-hex` dans metadata + `docker restart enclave_go_prod` |

⚠️ Garde `/tmp/master.key.hex` dans un coffre offline (pas sur la VM)
**jusqu'à ce que l'étape 9 soit confirmée stable**. Si tu fais
`shred -u` trop tôt et qu'un rollback est nécessaire, tu n'auras plus
le legacy key.

## Threat model pendant la migration

Pendant les étapes 3-9, le master key transite en clair :

| Étape | Surface | Mitigation |
|---|---|---|
| 3 | stdout du `docker exec` | Tu es seul devant le shell, redirige direct vers fichier |
| 3-4 | fichier `/tmp/master.key.hex` sur la VM | `shred -u` après step 4 |
| 4-9 | metadata GCP (lisible par anyone avec `compute.instances.get`) | Limite l'IAM ; cette fenêtre est de quelques heures max |
| 4-9 | env var dans le container `enclave_go_prod` (visible via `docker inspect`) | Tu es l'admin host ; cette fenêtre se ferme à l'étape 9 |

**Cette migration est un événement unique**. Une fois v1 stable et la
metadata supprimée, le système retourne à son threat model trustless :
plus aucune copie en clair du master key n'existe ailleurs que dans la
RAM TEE de v1.

Pour les futurs upgrades v1 → v2 → vN, le handoff B2 transfère le
master key entre enclaves via ECIES bound à l'attestation. Aucune
copie en clair ne quitte jamais le TEE.

## Si tu n'as PAS encore mis à jour `operatorPubkey`

Avant l'étape 7, tu DOIS remplacer la pubkey placeholder dans
[internal/bootstrap/signed_allowlist.go](../internal/bootstrap/signed_allowlist.go) :

```go
var operatorPubkey = "AAAAC3NzaC1lZDI1NTE5AAAAIPLACEHOLDERPLACEHOLDERPLACEHOLDERPLACEHO"
```

Procédure :

```bash
# 1. Génère ta keypair (UNE FOIS, à conserver précieusement)
./release-sign keygen --out ~/.tee/operator
# → demande passphrase, écrit ~/.tee/operator (chiffré) + ~/.tee/operator.pub

# 2. Affiche la valeur exacte à coller dans le code
./release-sign pubkey ~/.tee/operator.pub
# → "Constant value to paste in internal/bootstrap/signed_allowlist.go:"
# → const OperatorPubkey = "AAAAC3...etc"

# 3. Édite signed_allowlist.go : remplace operatorPubkey value
# 4. Commit + rebuild v1

# 5. Backup ~/.tee/operator vers 2 USB drives offline + 1 paper backup
#    de la passphrase. Ce key est la racine de confiance permanente.
```

Si tu perds la privkey ET la passphrase, tu ne pourras plus signer de
nouvelle release et la prochaine migration v1 → v2 sera impossible
sans un nouveau "événement migration" comme celui-ci.
