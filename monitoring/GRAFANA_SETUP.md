# Grafana Setup Guide - Monitoring Sécurisé

Guide pour configurer Grafana **sans leak de données sensibles**.

---

## 🚀 Installation Rapide

### Option 1 : Docker Compose (Recommandé)

```bash
# Décommenter la section grafana dans docker-compose.prod.yml
cd /opt/track-record-enclave
sudo nano docker-compose.prod.yml

# Décommenter les lignes grafana (lignes 150-175 environ)

# Restart
sudo systemctl restart enclave

# Vérifier
sudo docker ps | grep grafana
```

Accès : `http://<VM_IP>:3000`
Login : `admin` / `admin` (changer le mot de passe au premier login)

### Option 2 : Installation native

```bash
# Ubuntu/Debian
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install grafana

# Démarrer
sudo systemctl enable grafana-server
sudo systemctl start grafana-server

# Vérifier
sudo systemctl status grafana-server
```

---

## 📊 Configuration Prometheus Data Source

### 1. Ajouter Prometheus

1. Aller sur `http://<VM_IP>:3000`
2. Login (`admin` / `admin`)
3. Menu → Configuration → Data Sources → Add data source
4. Sélectionner **Prometheus**
5. Configurer :
   - **URL** : `http://enclave:9090` (Docker) ou `http://localhost:9090` (native)
   - **Access** : Server (default)
   - **Scrape interval** : 15s

6. Cliquer **Save & Test** → Doit afficher "Data source is working"

### 2. Importer le Dashboard Sécurisé

1. Menu → Dashboards → Import
2. Cliquer **Upload JSON file**
3. Sélectionner `monitoring/grafana-dashboards/enclave-dashboard.json`
4. Sélectionner la data source Prometheus
5. Cliquer **Import**

**Dashboard disponible** : "Track Record Enclave - Production Monitoring"

---

## 🔒 Sécurisation de Grafana

### 1. Changer les Credentials Admin

```bash
# Via Grafana UI
Settings → Users → admin → Change Password

# Ou via CLI
sudo grafana-cli admin reset-admin-password <nouveau-mot-de-passe>
```

### 2. Désactiver Anonymous Access

```bash
# Éditer la config
sudo nano /etc/grafana/grafana.ini

# Trouver et modifier :
[auth.anonymous]
enabled = false

# Restart
sudo systemctl restart grafana-server
```

### 3. Configurer HTTPS (Production)

```nginx
# /etc/nginx/sites-available/grafana

server {
  listen 443 ssl;
  server_name grafana.trackrecord.internal;

  ssl_certificate /etc/letsencrypt/live/trackrecord.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/trackrecord.com/privkey.pem;

  location / {
    proxy_pass http://localhost:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
  }
}
```

### 4. IP Whitelist

```bash
# Firewall : Autoriser seulement réseau interne
sudo ufw allow from 10.0.0.0/8 to any port 3000
sudo ufw deny 3000/tcp
```

---

## 📈 Panels du Dashboard

### 1. gRPC Request Rate
- **Metric** : `rate(grpc_requests_total[5m])`
- **Ce qu'il montre** : Requêtes gRPC par seconde
- **Sécurité** : ✅ Agrégé, pas de user IDs

### 2. gRPC Error Rate
- **Metric** : `rate(grpc_requests_total{status="error"}[5m]) / rate(grpc_requests_total[5m]) * 100`
- **Ce qu'il montre** : % d'erreurs gRPC
- **Alert** : ⚠️ Si > 1% pendant 5 minutes
- **Sécurité** : ✅ Pas de détails sur qui a échoué

### 3. Memory Usage
- **Metric** : `process_memory_bytes / 1024 / 1024 / 1024`
- **Ce qu'il montre** : RAM utilisée (GB)
- **Alert** : ⚠️ Si > 1.8GB (90% de 2GB)
- **Sécurité** : ✅ Aucune donnée utilisateur

### 4. CPU Usage
- **Metric** : `process_cpu_usage_percent`
- **Ce qu'il montre** : CPU utilisé (%)
- **Sécurité** : ✅ Agrégé

### 5. Active Connections
- **Metric** : `grpc_active_connections`
- **Ce qu'il montre** : Connexions gRPC actives
- **Sécurité** : ✅ Count uniquement, pas d'IPs

### 6. Request Duration (p95)
- **Metric** : `histogram_quantile(0.95, rate(grpc_request_duration_seconds_bucket[5m]))`
- **Ce qu'il montre** : Latence p95
- **Sécurité** : ✅ Pas de user-specific data

### 7. Database Query Duration
- **Metric** : `rate(db_query_duration_seconds_sum[5m]) / rate(db_query_duration_seconds_count[5m])`
- **Ce qu'il montre** : Durée moyenne des queries
- **Sécurité** : ✅ Pas de contenu SQL

### 8. Sync Jobs Success Rate
- **Metric** : `rate(sync_jobs_total{status="success"}[5m]) / rate(sync_jobs_total[5m]) * 100`
- **Ce qu'il montre** : % de syncs réussis
- **Sécurité** : ✅ Agrégé, pas de user IDs

### 9. Snapshots Created (Total)
- **Metric** : `snapshots_created_total`
- **Ce qu'il montre** : Nombre total de snapshots
- **Sécurité** : ✅ Count uniquement, pas de montants

### 10. AMD SEV-SNP Attestation
- **Metric** : `enclave_attestation_success_total` / `enclave_attestation_failure_total`
- **Ce qu'il montre** : Succès/échecs d'attestation
- **Sécurité** : ✅ Pas de détails techniques

---

## 🚨 Alertes Grafana

### Configurer les Notifications

#### Slack

1. Menu → Alerting → Notification channels → New channel
2. Type : **Slack**
3. Webhook URL : `https://hooks.slack.com/services/YOUR/WEBHOOK`
4. Username : `Grafana Enclave`
5. Channel : `#enclave-alerts`
6. **Save**

#### Email

1. Éditer `/etc/grafana/grafana.ini` :

```ini
[smtp]
enabled = true
host = smtp.gmail.com:587
user = alerts@trackrecord.com
password = your-app-password
from_address = alerts@trackrecord.com
from_name = Grafana Enclave
```

2. Restart Grafana : `sudo systemctl restart grafana-server`

### Alertes Configurées

Le dashboard inclut déjà ces alertes :

1. **High gRPC Error Rate** (> 1% pendant 5 min)
2. **High Memory Usage** (> 1.8GB)

Pour ajouter d'autres alertes :

1. Ouvrir le panel
2. Onglet **Alert**
3. Cliquer **Create Alert**
4. Configurer les conditions
5. Sélectionner notification channel
6. **Save**

---

## 🔍 Queries PromQL Utiles

### Performance

```promql
# Requêtes par seconde
rate(grpc_requests_total[5m])

# Latence moyenne
rate(grpc_request_duration_seconds_sum[5m]) / rate(grpc_request_duration_seconds_count[5m])

# Taux d'erreur
rate(grpc_requests_total{status="error"}[5m]) / rate(grpc_requests_total[5m])
```

### Ressources

```promql
# Mémoire en GB
process_memory_bytes / 1024 / 1024 / 1024

# CPU %
process_cpu_usage_percent

# Connexions actives
grpc_active_connections
```

### Business Metrics (Agrégées)

```promql
# Nombre de snapshots créés dans la dernière heure
increase(snapshots_created_total[1h])

# Taux de succès des syncs
rate(sync_jobs_total{status="success"}[5m]) / rate(sync_jobs_total[5m])

# Attestations échouées (alerte critique)
increase(enclave_attestation_failure_total[1h])
```

---

## ⚠️ CE QU'IL NE FAUT JAMAIS FAIRE

### ❌ Queries INTERDITES

```promql
# ❌ DANGER : Expose user IDs
grpc_requests_total{user_uid="user_12345"}

# ❌ DANGER : Expose balances
user_balance{user_id="user_12345"}

# ❌ DANGER : Expose symboles tradés
trades_total{symbol="BTCUSD"}
```

Si tu vois de telles queries dans le dashboard → **SUPPRIMER IMMÉDIATEMENT**

### ❌ Panels à éviter

- Tables avec user IDs
- Logs bruts (utiliser Loki séparément, pas Grafana)
- Métriques avec labels `user_uid`, `exchange`, `symbol`

---

## 📊 Variables Dashboard (Optionnel)

Pour filtrer par méthode gRPC :

1. Dashboard settings → Variables → New variable
2. Name : `method`
3. Type : **Query**
4. Data source : **Prometheus**
5. Query : `label_values(grpc_requests_total, method)`
6. **Save**

Utiliser dans les queries :

```promql
rate(grpc_requests_total{method="$method"}[5m])
```

---

## 🔒 Audit du Dashboard

Avant de mettre en prod, vérifier :

- [ ] Aucun panel avec label `user_uid`, `user_id`, `client_id`
- [ ] Aucune query avec `user_balance`, `user_equity`
- [ ] Aucune query avec symboles de trading
- [ ] Endpoint `/metrics` protégé par firewall
- [ ] Grafana accessible uniquement en interne ou via VPN
- [ ] HTTPS activé (pas de HTTP en production)
- [ ] Credentials admin changés
- [ ] Anonymous access désactivé

### Script d'audit

```bash
# Vérifier qu'aucune query du dashboard ne contient "user"
cat monitoring/grafana-dashboards/enclave-dashboard.json | grep -i "user_uid" && echo "⚠️ LEAK DETECTED" || echo "✅ SAFE"

cat monitoring/grafana-dashboards/enclave-dashboard.json | grep -i "balance" && echo "⚠️ LEAK DETECTED" || echo "✅ SAFE"
```

---

## 📚 Ressources

- [MONITORING_SECURITY.md](../MONITORING_SECURITY.md) - Guidelines de sécurité
- [enclave-dashboard.json](grafana-dashboards/enclave-dashboard.json) - Dashboard sécurisé
- [prometheus.yml](prometheus.yml) - Config Prometheus
- [Grafana Documentation](https://grafana.com/docs/grafana/latest/)
- [PromQL Basics](https://prometheus.io/docs/prometheus/latest/querying/basics/)

---

## 🎯 Quick Start

```bash
# 1. Démarrer Grafana
sudo systemctl start grafana-server

# 2. Accès
http://localhost:3000 (admin / admin)

# 3. Ajouter Prometheus data source
URL: http://localhost:9090

# 4. Importer dashboard
monitoring/grafana-dashboards/enclave-dashboard.json

# 5. Vérifier les metrics
curl http://localhost:9090/metrics | grep grpc_requests_total

# 6. Audit de sécurité
curl http://localhost:9090/metrics | grep -i "user_uid" && echo "⚠️ LEAK" || echo "✅ SAFE"
```

**Dashboard prêt à l'emploi en 5 minutes !** 🚀

---

**Note** : Ce dashboard est conçu pour monitorer l'enclave **sans compromettre la sécurité**. Toutes les metrics sont agrégées, aucune donnée utilisateur n'est exposée.
