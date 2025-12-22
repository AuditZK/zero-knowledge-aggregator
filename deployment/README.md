# Deployment Guide - Sans Kubernetes

Guide de déploiement simple pour production **sans orchestrateur complexe**.

## 🎯 Philosophie

**Kubernetes n'est PAS obligatoire** pour un projet comme celui-ci :
- 1 Enclave Worker = 1 VM AMD SEV-SNP
- Pas besoin de scaling horizontal (hardware limité)
- La simplicité = moins de bugs, moins de CVEs

**Solution recommandée : Docker Compose + systemd**

---

## 🚀 Déploiement Rapide (Production)

### Prérequis

- VM Ubuntu 22.04 LTS avec AMD SEV-SNP
- Docker et Docker Compose installés
- PostgreSQL (local ou managé)

### Installation en 3 étapes

```bash
# 1. Cloner et déployer
git clone https://github.com/your-org/track-record-enclave.git
cd track-record-enclave
chmod +x deployment/deploy-simple.sh
sudo ./deployment/deploy-simple.sh

# 2. Configurer les secrets (éditer le fichier créé)
sudo nano /etc/enclave/.env.production

# Mettre les vraies valeurs :
# - DATABASE_URL (PostgreSQL managé)

# 3. Démarrer
sudo systemctl start enclave
sudo systemctl status enclave
```

### Vérification

```bash
# Health check
curl http://localhost:9090/health
# {"status":"ok"}

# Metrics
curl http://localhost:9090/metrics | grep grpc_requests_total

# Logs
sudo journalctl -u enclave -f --output json-pretty
```

---

## 📁 Fichiers Importants

| Fichier | Utilité |
|---------|---------|
| [`deploy-simple.sh`](deploy-simple.sh) | Script de déploiement automatisé |
| [`systemd/enclave.service`](systemd/enclave.service) | Service systemd pour auto-restart |
| [`monitoring/simple-alerts.sh`](monitoring/simple-alerts.sh) | Script d'alerting simple (email, Slack, PagerDuty) |
| [`DEPLOYMENT_COMPARISON.md`](DEPLOYMENT_COMPARISON.md) | Comparaison Docker Compose vs Swarm vs Kubernetes |

---

## 🔧 Gestion du Service (systemd)

```bash
# Démarrer
sudo systemctl start enclave

# Arrêter
sudo systemctl stop enclave

# Restart
sudo systemctl restart enclave

# Status
sudo systemctl status enclave

# Activer au boot
sudo systemctl enable enclave

# Désactiver au boot
sudo systemctl disable enclave

# Logs en temps réel
sudo journalctl -u enclave -f

# Logs JSON
sudo journalctl -u enclave -o json-pretty

# Logs depuis la dernière heure
sudo journalctl -u enclave --since "1 hour ago"
```

---

## 📊 Monitoring (Sans Prometheus Operator)

### Metrics Prometheus

Les metrics sont exposées sur `http://localhost:9090/metrics` (interne uniquement).

**Metrics critiques :**
```bash
# Requêtes gRPC
curl -s http://localhost:9090/metrics | grep grpc_requests_total

# Mémoire
curl -s http://localhost:9090/metrics | grep process_memory_bytes

# CPU
curl -s http://localhost:9090/metrics | grep process_cpu_usage_percent

# Attestations
curl -s http://localhost:9090/metrics | grep enclave_attestation
```

### Alerting Simple (Cron Job)

```bash
# Installer le script d'alerting
sudo chmod +x /opt/track-record-enclave/deployment/monitoring/simple-alerts.sh

# Ajouter au cron (check toutes les 5 minutes)
sudo crontab -e

# Ajouter cette ligne :
*/5 * * * * /opt/track-record-enclave/deployment/monitoring/simple-alerts.sh >> /var/log/enclave-alerts.log 2>&1

# Configurer les alertes (variables d'environnement)
sudo nano /etc/environment

# Ajouter :
ALERT_EMAIL="ops@trackrecord.com"
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK"
PAGERDUTY_KEY="your-pagerduty-integration-key"
```

Le script vérifie automatiquement :
- ✅ Enclave est UP
- ✅ Mémoire < 1.8GB
- ✅ Taux d'erreur gRPC < 1%
- ✅ Pas d'échec d'attestation AMD SEV-SNP

Et envoie des alertes via :
- Email (sendmail)
- Slack (webhook)
- PagerDuty (API)

### Grafana (Optionnel)

Si tu veux des dashboards visuels (pas obligatoire pour MVP) :

```bash
# Décommenter la section grafana dans docker-compose.prod.yml
sudo nano /opt/track-record-enclave/docker-compose.prod.yml

# Restart
sudo systemctl restart enclave

# Accès : http://<VM_IP>:3000
# Login : admin / admin
```

---

## 🔒 Secrets Management

```bash
# Créer le fichier
sudo nano /etc/enclave/.env.production

# Contenu (exemple) :
DATABASE_URL="postgresql://user:pass@your-db-host:5432/aggregator_db?sslmode=require"
JWT_SECRET="your-jwt-secret"

# Sécuriser les permissions (IMPORTANT)
sudo chmod 600 /etc/enclave/.env.production
sudo chown root:root /etc/enclave/.env.production
```

---

## 🗄️ Base de Données Production

### PostgreSQL

```bash
# Connection string (exemple)
DATABASE_URL="postgresql://enclave_user:PASSWORD@your-db-host:5432/aggregator_db?sslmode=require"
```

**Recommandations** :
- Configurer le firewall pour n'autoriser que l'IP de la VM enclave
- Activer les backups automatiques (30 jours de rétention minimum)
- Utiliser SSL/TLS pour les connexions

---

## 🔄 Updates et Maintenance

### Mise à jour de l'enclave

```bash
# 1. Arrêter le service
sudo systemctl stop enclave

# 2. Backup (optionnel)
sudo cp -r /opt/track-record-enclave /opt/track-record-enclave.backup

# 3. Pull nouvelle version
cd /opt/track-record-enclave
sudo git pull origin main

# 4. Rebuild l'image Docker
sudo docker build -f Dockerfile.reproducible -t track-record-enclave:latest .

# 5. Redémarrer
sudo systemctl start enclave

# 6. Vérifier
sudo systemctl status enclave
curl http://localhost:9090/health
```

**Downtime : ~10-30 secondes** (temps de rebuild + restart)

### Rolling Update (Zéro Downtime)

Si tu as vraiment besoin de zéro downtime, passe à **Docker Swarm** (voir [`DEPLOYMENT_COMPARISON.md`](DEPLOYMENT_COMPARISON.md)).

---

## 🔥 Troubleshooting

### Enclave ne démarre pas

```bash
# Voir les logs détaillés
sudo journalctl -u enclave -n 100 --no-pager

# Vérifier les containers Docker
sudo docker ps -a

# Logs du container
sudo docker logs track-record-enclave-prod

# Vérifier la config
sudo docker-compose -f /opt/track-record-enclave/docker-compose.prod.yml config
```

### Health check échoue

```bash
# Tester manuellement
sudo docker exec track-record-enclave-prod node dist/health-check.js

# Vérifier gRPC
nc -zv localhost 50051

# Vérifier PostgreSQL
psql $DATABASE_URL -c "SELECT 1"
```

### Attestation AMD SEV-SNP échoue

```bash
# Vérifier le device
ls -la /dev/sev-guest

# Tester avec snpguest (si installé)
snpguest report --format json

# Logs d'attestation
sudo docker logs track-record-enclave-prod | grep -i attestation
```

### Mémoire saturée

```bash
# Voir l'utilisation mémoire
curl http://localhost:9090/metrics | grep process_memory_bytes

# Augmenter la limite (si nécessaire)
sudo nano /opt/track-record-enclave/docker-compose.prod.yml
# Changer: memory: 4G (au lieu de 2G)

# Restart
sudo systemctl restart enclave
```

---

## 💰 Estimation des Coûts

### Configuration Minimale (MVP)

| Composant | Type | Coût/mois |
|-----------|------|-----------|
| VM AMD SEV-SNP | 2 vCPUs, 4GB RAM | ~$100 |
| PostgreSQL | Managé ou self-hosted | ~$50 |
| Stockage | 128GB SSD | ~$10 |
| **TOTAL** | | **~$160/mois** |

**Note** : Docker Compose suffit pour la majorité des cas d'usage.

---

## 🎯 Migration vers Kubernetes (Si vraiment nécessaire)

Si tu dois vraiment passer à Kubernetes plus tard :

```bash
# 1. Convertir docker-compose.prod.yml en Kubernetes manifests
kompose convert -f docker-compose.prod.yml

# 2. Ou utiliser Helm (plus propre)
helm create track-record-enclave

# 3. Deploy
kubectl apply -f k8s/
```

Mais **demande-toi d'abord** : Est-ce vraiment nécessaire ?
- Tu as besoin de 10+ instances ? (Probablement non)
- Tu as une équipe DevOps dédiée ? (Si non, c'est un cauchemar)
- Tu gères déjà Kubernetes pour d'autres services ? (Sinon, pourquoi commencer ?)

---

## 📚 Ressources

- [DEPLOYMENT_COMPARISON.md](DEPLOYMENT_COMPARISON.md) - Comparaison détaillée des options
- [deploy-simple.sh](deploy-simple.sh) - Script de déploiement automatisé
- [systemd/enclave.service](systemd/enclave.service) - Service systemd
- [monitoring/simple-alerts.sh](monitoring/simple-alerts.sh) - Script d'alerting
- [../docker-compose.prod.yml](../docker-compose.prod.yml) - Config Docker Compose production
- [../PRODUCTION_SETUP.md](../PRODUCTION_SETUP.md) - Guide de setup production global

---

## ✅ Checklist de Production

Avant de mettre en prod :

- [ ] VM AMD SEV-SNP créée
- [ ] PostgreSQL managé configuré (avec SSL)
- [ ] AMD SEV-SNP attestation vérifiée (clés de chiffrement dérivées du hardware)
- [ ] TLS certificates CA-signés installés dans `/etc/enclave/certs/`
- [ ] Firewall configuré (port 50051 interne uniquement)
- [ ] systemd service activé (`systemctl enable enclave`)
- [ ] Monitoring configuré (cron job + alerting)
- [ ] Backups PostgreSQL vérifiés (30 jours de rétention)
- [ ] Health checks testés (`curl localhost:9090/health`)
- [ ] Attestation AMD SEV-SNP vérifiée (logs)

---

**Prêt pour la production sans Kubernetes !** 🚀
