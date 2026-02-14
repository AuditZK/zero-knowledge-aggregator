# Development Setup Guide — Zero-Knowledge Aggregator Go

## Quick Start (Docker Compose)

### 1. Configuration initiale

```bash
# Copier la configuration de développement
cp .env.dev .env

# Optionnel : Générer une nouvelle clé de chiffrement
# openssl rand -hex 32
```

### 2. Démarrage avec Docker Compose

```bash
# Build et démarrage en mode dev
docker compose -f docker-compose.dev.yml up -d --build

# Voir les logs en temps réel
docker compose -f docker-compose.dev.yml logs -f

# Vérifier le statut
docker compose -f docker-compose.dev.yml ps
```

### 3. Vérification des services

```bash
# Health check
curl http://localhost:8081/health

# Attestation (mode dev, pas de vraie attestation SEV-SNP)
curl http://localhost:8081/api/v1/attestation | jq

# TLS fingerprint
curl http://localhost:8081/api/v1/tls/fingerprint | jq

# Métriques Prometheus
curl http://localhost:9091/metrics

# Logs stream (SSE)
curl http://localhost:50052/logs
```

## Ports utilisés (mode dev)

| Service | Port | Description |
|---------|------|-------------|
| REST API | **8081** | HTTP API (changé pour éviter conflit avec TS sur 8080) |
| gRPC | 50051 | gRPC service |
| Log Stream | 50052 | Server-Sent Events (SSE) pour logs temps réel |
| Metrics | **9091** | Prometheus metrics (changé pour éviter conflit) |
| PostgreSQL | 5436 | Base de données (port externe, interne 5432) |

## Alternative : Exécution locale (sans Docker)

### Prérequis

- Go 1.24+
- PostgreSQL 16
- OpenSSL

### 1. Démarrer uniquement PostgreSQL

```bash
docker compose -f docker-compose.dev.yml up -d enclave-go-db

# Attendre que la DB soit prête
docker compose -f docker-compose.dev.yml logs enclave-go-db
```

### 2. Build et exécution

```bash
# Build
make build
# ou
go build -o bin/enclave ./cmd/enclave

# Exécution avec variables d'environnement
ENV=development \
DATABASE_URL="postgres://enclave:enclave@localhost:5436/enclave_go?sslmode=disable" \
ENCRYPTION_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
GRPC_PORT=50051 \
REST_PORT=8080 \
LOG_LEVEL=debug \
GRPC_INSECURE=true \
CORS_ORIGIN="*" \
METRICS_PORT=9090 \
./bin/enclave
```

### 3. Hot-reload avec Air (optionnel)

```bash
# Installer air
go install github.com/cosmtrek/air@latest

# Lancer avec hot-reload
air
```

## Commandes utiles

### Docker Compose

```bash
# Logs d'un service spécifique
docker compose -f docker-compose.dev.yml logs -f enclave-go-dev

# Restart d'un service
docker compose -f docker-compose.dev.yml restart enclave-go-dev

# Rebuild après changement de code
docker compose -f docker-compose.dev.yml up -d --build enclave-go-dev

# Arrêt
docker compose -f docker-compose.dev.yml down

# Arrêt avec suppression des volumes (reset DB)
docker compose -f docker-compose.dev.yml down -v
```

### Database

```bash
# Connexion à la base de données
docker exec -it enclave_go_db_dev psql -U enclave -d enclave_go

# Exemples de requêtes SQL
\dt                                    # Lister les tables
SELECT * FROM users;                   # Lister les users
SELECT * FROM exchange_connections;    # Lister les connexions
SELECT * FROM snapshot_data ORDER BY timestamp DESC LIMIT 10;  # Derniers snapshots
\q                                     # Quitter
```

### Tests

```bash
# Tests unitaires
make test
# ou
go test ./... -v

# Tests avec race detection
make test-race
# ou
go test -race ./...

# Coverage
make test-cover
# ou
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Linting

```bash
# Linter
make lint
# ou
golangci-lint run

# Vérification des vulnérabilités
govulncheck ./...

# Format du code
gofmt -s -w .
# ou
go fmt ./...
```

## API Examples

### Créer une connexion exchange

```bash
curl -X POST http://localhost:8081/api/v1/connection \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "exchange": "binance",
    "label": "My Binance Account",
    "credentials": {
      "apiKey": "YOUR_API_KEY",
      "apiSecret": "YOUR_API_SECRET"
    }
  }'
```

### Déclencher un sync manuel

```bash
curl -X POST http://localhost:8081/api/v1/sync \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "exchange": "binance"
  }'
```

### Récupérer les métriques

```bash
curl http://localhost:8081/api/v1/metrics?user_id=user123 | jq
```

### Récupérer les snapshots

```bash
curl "http://localhost:8081/api/v1/snapshots?user_id=user123&limit=10" | jq
```

### Générer un rapport signé

```bash
curl -X POST http://localhost:8081/api/v1/report \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "start_date": "2026-01-01T00:00:00Z",
    "end_date": "2026-02-14T00:00:00Z"
  }' | jq
```

## gRPC Testing avec grpcurl

```bash
# Installer grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Lister les services
grpcurl -plaintext localhost:50051 list

# Appeler HealthCheck
grpcurl -plaintext localhost:50051 enclave.EnclaveService/HealthCheck

# Créer une connexion
grpcurl -plaintext -d '{
  "user_id": "user123",
  "exchange": "binance",
  "label": "Test",
  "credentials": "{\"apiKey\":\"test\",\"apiSecret\":\"test\"}"
}' localhost:50051 enclave.EnclaveService/CreateUserConnection
```

## Troubleshooting

### Port déjà utilisé

```bash
# Vérifier quel processus utilise le port 8081
sudo lsof -i :8081
# ou
sudo netstat -tlnp | grep 8081

# Tuer le processus
sudo kill -9 <PID>
```

### Database connection failed

```bash
# Vérifier que PostgreSQL est démarré
docker compose -f docker-compose.dev.yml ps enclave-go-db

# Vérifier les logs
docker compose -f docker-compose.dev.yml logs enclave-go-db

# Reset de la database
docker compose -f docker-compose.dev.yml down -v
docker compose -f docker-compose.dev.yml up -d enclave-go-db
```

### Logs verbeux pour debugging

```bash
# Modifier .env
LOG_LEVEL=debug

# Redémarrer
docker compose -f docker-compose.dev.yml restart enclave-go-dev

# Voir les logs
docker compose -f docker-compose.dev.yml logs -f enclave-go-dev
```

## Différences avec le mode production

| Feature | Development | Production |
|---------|------------|------------|
| TLS | Désactivé (`GRPC_INSECURE=true`) | Obligatoire (ECDSA P-256) |
| CORS | Ouvert (`*`) | Configuré par domaine |
| Logs | Debug level | Info level |
| Attestation SEV-SNP | Fallback/mock | Vraie attestation hardware |
| Read-only filesystem | Non | Oui |
| Memory locking | Non (Windows/dev) | Oui (Linux production) |
| Encryption key | Fixe (pour persistance dev) | Dérivée ou fournie sécurisée |
| Ports exposés | Tous | Seulement nécessaires |

## Next Steps

1. ✅ Setup dev environment
2. 📝 Lire [AGENTS.md](AGENTS.md) pour les standards de code
3. 🔍 Lancer l'audit TypeScript → Go avec [.agents/prompts/typescript-to-go-migration.md](.agents/prompts/typescript-to-go-migration.md)
4. 🧪 Écrire des tests (coverage cible : 70% global, 90% encryption)
5. 🚀 Feature parity avec la version TypeScript
