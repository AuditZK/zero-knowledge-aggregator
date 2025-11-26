# Production Setup Guide

Guide pratique pour déployer l'enclave en production.

## 📋 Vue d'ensemble

Ce guide couvre **uniquement l'essentiel** pour un déploiement production minimal et sécurisé.

### Ce qui est OBLIGATOIRE ✅

1. **Health checks robustes** - Pour que Kubernetes/Docker sache si l'enclave fonctionne
2. **Metrics Prometheus** - Pour surveiller CPU, RAM, requêtes/s (sinon tu voles à l'aveugle)
3. **Variables d'environnement production** - Configuration séparée dev/prod
4. **Secrets managés** - ENCRYPTION_KEY injectée via vault (pas hardcodée)

### Ce qui est OPTIONNEL (Phase 2) ⚠️

- Distributed tracing (OpenTelemetry) - Nice to have mais pas critique
- Logs centralisés (Loki/Elasticsearch) - Commence avec logs locaux
- Grafana dashboards - Commence avec Prometheus, ajoute Grafana après

---

## 🚀 Quick Start (Staging/Production-like)

### 1. Créer la configuration production

```bash
# Copier le template de production
cp .env.production.example .env.production

# Générer les clés de sécurité
openssl rand -hex 32  # ENCRYPTION_KEY
openssl rand -hex 32  # JWT_SECRET

# Éditer .env.production avec les vraies valeurs
nano .env.production
```

**IMPORTANT** : Ne JAMAIS commiter `.env.production` dans Git !

### 2. Lancer l'environnement de staging

```bash
# Build de l'image production
docker build -f Dockerfile.reproducible -t track-record-enclave:1.0.0 .

# Lancer avec docker-compose production
docker-compose -f docker-compose.prod.yml up -d

# Vérifier les health checks
docker ps  # Doit montrer "healthy"

# Voir les logs
docker logs track-record-enclave-prod

# Vérifier les metrics
curl http://localhost:9091/metrics
```

### 3. Vérifier que tout fonctionne

```bash
# Health check manuel
curl http://localhost:9090/health

# Metrics Prometheus
curl http://localhost:9090/metrics | grep grpc_requests_total

# Logs JSON
docker logs track-record-enclave-prod --tail 50
```

---

## 📊 Monitoring Essentiel

### Metrics Prometheus (Port 9090)

Le service de metrics expose automatiquement :

| Métrique | Type | Description |
|----------|------|-------------|
| `grpc_requests_total` | Counter | Nombre total de requêtes gRPC |
| `grpc_request_duration_seconds` | Histogram | Durée des requêtes gRPC |
| `grpc_active_connections` | Gauge | Connexions gRPC actives |
| `db_queries_total` | Counter | Requêtes DB totales |
| `process_memory_bytes` | Gauge | Mémoire utilisée (bytes) |
| `process_cpu_usage_percent` | Gauge | CPU utilisé (%) |
| `enclave_attestation_success_total` | Counter | Attestations AMD SEV-SNP réussies |
| `sync_jobs_total` | Counter | Jobs de sync traités |

**Accès** : `http://localhost:9090/metrics` (interne uniquement)

### Health Checks Robustes

Le health check vérifie :

- ✅ Serveur gRPC répond (port 50051)
- ✅ Base de données connectée
- ✅ Mémoire < 1.8GB (90% de la limite)
- ✅ Attestation AMD SEV-SNP valide (si activé)

**Test manuel** :

```bash
# Via Docker
docker exec track-record-enclave-prod node dist/health-check.js

# Doit afficher:
# Health Check: ✓ HEALTHY
#   ✓ grpc_server: pass (12ms)
#   ✓ database: pass (45ms)
#   ✓ memory: pass (2ms)
```

### Alertes Prometheus (Recommandées)

Créer `monitoring/alerts/enclave.yml` :

```yaml
groups:
  - name: enclave_critical
    interval: 30s
    rules:
      # Enclave down > 2 minutes
      - alert: EnclaveDown
        expr: up{job="enclave"} == 0
        for: 2m
        labels:
          severity: critical

      # Mémoire > 90%
      - alert: HighMemory
        expr: process_memory_bytes > 1.8e9
        for: 5m
        labels:
          severity: warning

      # Erreurs gRPC > 1%
      - alert: HighErrorRate
        expr: rate(grpc_requests_total{status="error"}[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
```

---

## 🔐 Gestion des Secrets

### Méthode 1 : Azure Key Vault (Recommandé)

```bash
# Créer le vault
az keyvault create --name track-record-vault --resource-group enclave-rg

# Stocker ENCRYPTION_KEY
az keyvault secret set --vault-name track-record-vault \
  --name encryption-key \
  --value "$(openssl rand -hex 32)"

# Injecter dans .env.production (via script Azure)
ENCRYPTION_KEY=$(az keyvault secret show --vault-name track-record-vault \
  --name encryption-key --query value -o tsv)
```

### Méthode 2 : Docker Secrets (Docker Swarm)

```bash
# Créer un secret
echo "$(openssl rand -hex 32)" | docker secret create encryption_key -

# Référencer dans docker-compose.prod.yml
secrets:
  encryption_key:
    external: true

services:
  enclave:
    secrets:
      - encryption_key
```

### Méthode 3 : Kubernetes Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: enclave-secrets
type: Opaque
data:
  encryption-key: <base64-encoded-key>
```

---

## 🗄️ Base de Données Production

### Option 1 : Azure Database for PostgreSQL

```bash
# Créer l'instance
az postgres flexible-server create \
  --name track-record-db \
  --resource-group enclave-rg \
  --location eastus \
  --admin-user enclave_admin \
  --admin-password "$(openssl rand -base64 32)" \
  --sku-name Standard_D2s_v3 \
  --storage-size 128 \
  --version 15

# Configurer le firewall (IP de l'enclave uniquement)
az postgres flexible-server firewall-rule create \
  --resource-group enclave-rg \
  --name track-record-db \
  --rule-name allow-enclave \
  --start-ip-address 10.0.1.5 \
  --end-ip-address 10.0.1.5

# Connection string
DATABASE_URL="postgresql://enclave_admin:PASSWORD@track-record-db.postgres.database.azure.com:5432/aggregator_db?sslmode=require"
```

### Option 2 : AWS RDS PostgreSQL

```bash
# Via Terraform (recommandé)
resource "aws_db_instance" "enclave_db" {
  identifier           = "track-record-enclave-db"
  engine               = "postgres"
  engine_version       = "15.3"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  storage_encrypted    = true
  db_name              = "aggregator_db"
  username             = "enclave_admin"
  password             = var.db_password  # From AWS Secrets Manager
  vpc_security_group_ids = [aws_security_group.enclave_db.id]
  backup_retention_period = 30
  multi_az             = true  # High availability
}
```

---

## 🔒 Certificats TLS

### Production : Certificats CA-signés

```bash
# Option 1 : Let's Encrypt (gratuit)
certbot certonly --standalone -d enclave.trackrecord.com

# Option 2 : Certificat corporate (exemple avec OpenSSL)
# 1. Générer CSR
openssl req -new -newkey rsa:4096 -nodes \
  -keyout server.key \
  -out server.csr \
  -subj "/CN=enclave.trackrecord.com/O=Track Record/C=US"

# 2. Soumettre CSR à votre CA

# 3. Installer les certificats
sudo mkdir -p /etc/enclave/certs
sudo mv ca.crt server.crt server.key /etc/enclave/certs/
sudo chmod 600 /etc/enclave/certs/*.key
sudo chmod 644 /etc/enclave/certs/*.crt
```

### Rotation automatique (Kubernetes cert-manager)

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: enclave-tls
spec:
  secretName: enclave-tls-secret
  duration: 2160h  # 90 days
  renewBefore: 360h  # 15 days before expiry
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - enclave.trackrecord.internal
```

---

## 🏗️ Déploiement Kubernetes (Recommandé pour production)

### Manifest minimal

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: track-record-enclave
  namespace: production
spec:
  replicas: 2  # High availability
  selector:
    matchLabels:
      app: enclave
  template:
    metadata:
      labels:
        app: enclave
    spec:
      # AMD SEV-SNP node selector
      nodeSelector:
        enclave.azure.com/sev-snp: "true"

      containers:
      - name: enclave
        image: yourregistry.azurecr.io/track-record-enclave:1.0.0
        imagePullPolicy: Always

        # Security context
        securityContext:
          runAsUser: 1000
          runAsNonRoot: true
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
            add:
              - IPC_LOCK

        # Environment from secrets
        envFrom:
        - secretRef:
            name: enclave-secrets

        # Ports
        ports:
        - containerPort: 50051
          name: grpc
        - containerPort: 9090
          name: metrics

        # Resource limits
        resources:
          requests:
            memory: "1Gi"
            cpu: "1"
          limits:
            memory: "2Gi"
            cpu: "2"

        # Health checks
        livenessProbe:
          exec:
            command:
            - node
            - dist/health-check.js
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 10

        readinessProbe:
          exec:
            command:
            - node
            - dist/health-check.js
          initialDelaySeconds: 10
          periodSeconds: 10

        # Volume mounts
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/enclave/certs
          readOnly: true

      volumes:
      - name: tls-certs
        secret:
          secretName: enclave-tls-secret
```

---

## 📈 Dashboards Grafana (Optionnel - Phase 2)

Si tu veux des dashboards visuels (pas obligatoire pour MVP) :

```bash
# Lancer Grafana avec docker-compose
# Décommenter la section 'grafana' dans docker-compose.prod.yml

docker-compose -f docker-compose.prod.yml up -d grafana

# Accès : http://localhost:3000
# Login : admin / admin (changer le mot de passe)
```

Import dashboard JSON : `monitoring/grafana-dashboards/enclave-overview.json`

---

## ✅ Checklist de Déploiement

Avant de déployer en production :

### Sécurité
- [ ] `ENCRYPTION_KEY` injectée depuis vault (pas hardcodée)
- [ ] `DATABASE_URL` pointe vers PostgreSQL managé avec SSL
- [ ] Certificats TLS signés par CA (pas auto-signés)
- [ ] `AMD_SEV_SNP=true` sur hardware AMD SEV-SNP
- [ ] `LOG_LEVEL=info` (JAMAIS debug en prod)
- [ ] `ATTESTATION_REQUIRED=true`
- [ ] `GRPC_MTLS_ENABLED=true`
- [ ] `ENABLE_DEBUG_ENDPOINTS=false`

### Monitoring
- [ ] Health checks configurés (Kubernetes/Docker Swarm)
- [ ] Prometheus scrape les metrics sur port 9090
- [ ] Alertes configurées (EnclaveDown, HighMemory, HighErrorRate)
- [ ] Logs en format JSON pour agrégation

### Infrastructure
- [ ] Firewall : Port 50051 interne uniquement
- [ ] Réseau : Enclave isolée dans subnet privé
- [ ] Backup DB : Quotidien, rétention 30 jours
- [ ] ENCRYPTION_KEY backupée dans vault

### Tests
- [ ] Build reproductible testé (`docker build -f Dockerfile.reproducible`)
- [ ] Health check manuel réussi (`docker exec ... node dist/health-check.js`)
- [ ] Metrics accessibles (`curl localhost:9090/metrics`)
- [ ] Test de connexion gRPC depuis Gateway

---

## 🆘 Troubleshooting

### Health check échoue

```bash
# Voir les logs détaillés
docker logs track-record-enclave-prod --tail 100

# Tester chaque composant individuellement
docker exec -it track-record-enclave-prod sh

# Vérifier gRPC
nc -zv localhost 50051

# Vérifier DB
psql $DATABASE_URL -c "SELECT 1"
```

### Metrics Prometheus vides

```bash
# Vérifier que METRICS_ENABLED=true
docker exec track-record-enclave-prod env | grep METRICS_ENABLED

# Tester l'endpoint
curl http://localhost:9090/metrics

# Vérifier les logs du service de metrics
docker logs track-record-enclave-prod | grep MetricsService
```

### Attestation AMD SEV-SNP échoue

```bash
# Vérifier le device
ls -la /dev/sev-guest

# Vérifier les logs
docker logs track-record-enclave-prod | grep -i attestation

# Tester manuellement (sur la VM AMD SEV-SNP)
snpguest report --format json
```

---

## 📚 Ressources

- [Dockerfile.reproducible](Dockerfile.reproducible) - Build production
- [docker-compose.prod.yml](docker-compose.prod.yml) - Configuration production
- [.env.production.example](.env.production.example) - Variables d'environnement
- [monitoring/prometheus.yml](monitoring/prometheus.yml) - Config Prometheus
- [src/health-check.ts](src/health-check.ts) - Health check robuste
- [src/services/metrics.service.ts](src/services/metrics.service.ts) - Service de metrics

---

## 🎯 Prochaines Étapes

**MVP Production (Essentiel)** :
1. ✅ Configuration production créée
2. ✅ Health checks robustes
3. ✅ Metrics Prometheus basiques
4. ⏳ Tests sur hardware AMD SEV-SNP réel
5. ⏳ Audit de sécurité externe

**Phase 2 (Améliorations)** :
- Logs centralisés (Loki)
- Dashboards Grafana
- Distributed tracing (OpenTelemetry)
- Alerting avancé (PagerDuty)
