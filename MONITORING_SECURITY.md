# Monitoring Security Guidelines

Guide pour monitorer l'enclave **sans leak de données sensibles**.

---

## 🚨 RÈGLES CRITIQUES - Ce qui NE DOIT JAMAIS apparaître dans les metrics

### ❌ INTERDIT dans Prometheus/Grafana

```
❌ User IDs en clair (userUid)
❌ Exchange credentials (API keys, secrets)
❌ Prix individuels de trades
❌ Timestamps précis de trades
❌ Quantités de positions
❌ Balances utilisateurs individuelles
❌ Symboles de trading (BTCUSD, ETHUSDT)
❌ Adresses IP d'utilisateurs
❌ ENCRYPTION_KEY ou JWT_SECRET
❌ Connection strings (DATABASE_URL)
```

### ✅ AUTORISÉ dans Prometheus/Grafana

```
✅ Compteurs agrégés (total de requêtes gRPC)
✅ Taux d'erreur global (% de requêtes échouées)
✅ Latences (p50, p95, p99)
✅ Utilisation ressources (CPU, RAM, disk)
✅ Nombre de connexions actives
✅ Nombre de snapshots créés (sans détails)
✅ Taux de succès d'attestation AMD SEV-SNP
✅ Statut de la base de données (up/down)
✅ Durée des syncs (temps moyen)
```

---

## 📊 Metrics SAFE à Exposer

### 1. Metrics Système (100% safe)

```prometheus
# CPU
process_cpu_usage_percent

# Mémoire
process_memory_bytes
process_memory_heap_used_bytes
process_memory_heap_total_bytes

# Disk
disk_usage_bytes

# Network
network_bytes_sent_total
network_bytes_received_total
```

### 2. Metrics gRPC (agrégées uniquement)

```prometheus
# Total de requêtes par méthode (SANS user ID)
grpc_requests_total{method="ProcessSyncJob",status="success"}
grpc_requests_total{method="GetAggregatedMetrics",status="error"}

# Durée des requêtes (SANS user ID)
grpc_request_duration_seconds{method="ProcessSyncJob"}

# Connexions actives (total, SANS IP)
grpc_active_connections
```

**IMPORTANT** : Jamais de label avec `user_uid` ou `exchange` individuel !

### 3. Metrics Database (agrégées)

```prometheus
# Nombre de queries (SANS contenu SQL)
db_queries_total{operation="SELECT"}
db_queries_total{operation="INSERT"}

# Durée des queries (moyenne)
db_query_duration_seconds{operation="SELECT"}

# Pool de connexions
db_connections_active
db_connections_idle
```

### 4. Metrics Enclave-Specific (sécurisées)

```prometheus
# Attestations AMD SEV-SNP (OK/KO, SANS détails)
enclave_attestation_success_total
enclave_attestation_failure_total

# Snapshots créés (count, SANS montants)
snapshots_created_total

# Sync jobs (count, SANS user/exchange)
sync_jobs_total{status="success"}
sync_jobs_total{status="failed"}

# Rate limiting (count, SANS user ID)
sync_rate_limit_hits_total
```

---

## ⚠️ Exemples de Leaks à ÉVITER

### ❌ BAD : Leak de user IDs

```prometheus
# DANGER : Expose tous les user IDs !
grpc_requests_total{method="ProcessSyncJob",user_uid="user_12345",status="success"}
```

**Pourquoi c'est dangereux :**
- Révèle la liste de tous les utilisateurs
- Permet de tracker l'activité individuelle
- Peut être corrélé avec d'autres données

### ❌ BAD : Leak de balances

```prometheus
# DANGER : Expose les balances !
snapshot_total_equity{user_uid="user_12345"} 10500.50
```

**Pourquoi c'est dangereux :**
- Révèle les montants exacts des utilisateurs
- Viole le principe de zero-knowledge

### ❌ BAD : Leak de symboles tradés

```prometheus
# DANGER : Révèle les stratégies de trading !
trades_total{user_uid="user_12345",symbol="BTCUSD"} 42
```

**Pourquoi c'est dangereux :**
- Révèle les actifs tradés par chaque utilisateur
- Permet de reverse-engineer les stratégies

### ✅ GOOD : Metrics agrégées

```prometheus
# SAFE : Compteurs globaux uniquement
grpc_requests_total{method="ProcessSyncJob",status="success"} 1523
grpc_requests_total{method="ProcessSyncJob",status="error"} 7

# SAFE : Latences moyennes
grpc_request_duration_seconds{method="ProcessSyncJob",quantile="0.95"} 0.523

# SAFE : Ressources système
process_memory_bytes 1200000000
process_cpu_usage_percent 15.3

# SAFE : Taux de succès global
sync_jobs_total{status="success"} 1450
sync_jobs_total{status="failed"} 12
```

---

## 🔒 Règles d'Implémentation

### 1. Jamais de labels avec données utilisateur

```typescript
// ❌ BAD
metricsService.incrementCounter('grpc_requests_total', {
  method: 'ProcessSyncJob',
  user_uid: userUid,  // DANGER !
  exchange: exchange  // DANGER !
});

// ✅ GOOD
metricsService.incrementCounter('grpc_requests_total', {
  method: 'ProcessSyncJob',
  status: 'success'  // OK, générique
});
```

### 2. Hasher les identifiants si nécessaire

Si tu **dois** tracker par utilisateur (pour debug), utilise un hash :

```typescript
// ✅ ACCEPTABLE (avec hash)
import { createHash } from 'crypto';

const userHash = createHash('sha256')
  .update(userUid + process.env.METRICS_SALT)  // Salt unique
  .digest('hex')
  .substring(0, 8);  // 8 premiers chars

metricsService.incrementCounter('user_sync_total', {
  user_hash: userHash  // Hash non-réversible
});
```

**Limitations** :
- Hash doit être salé (pas juste SHA256 du user ID)
- Ne pas exposer le mapping hash → user ID
- Utiliser **uniquement** pour debug, pas en production

### 3. Agréger avant d'exporter

```typescript
// ❌ BAD : Export individuel
for (const user of users) {
  metricsService.setGauge('user_balance', user.balance, { user_id: user.id });
}

// ✅ GOOD : Export agrégé
const totalUsers = users.length;
const avgBalance = users.reduce((sum, u) => sum + u.balance, 0) / totalUsers;

metricsService.setGauge('total_active_users', totalUsers);
metricsService.setGauge('avg_user_balance', avgBalance);  // Moyenne, pas individuel
```

### 4. Logs vs Metrics

```typescript
// ✅ Logs (OK car pas exposés à Grafana)
logger.info('Sync completed', {
  userUid: userUid,        // OK dans les logs (internes)
  exchange: exchange,
  snapshotId: snapshotId
});

// ✅ Metrics (agrégées, sans user ID)
metricsService.incrementCounter('sync_jobs_total', {
  status: 'success'  // Pas de userUid !
});
```

**Principe** : Les logs peuvent contenir des données sensibles (stockage sécurisé), mais les metrics **ne doivent jamais** en contenir (exposées à Grafana).

---

## 📊 Dashboard Grafana Sécurisé

### Panels Autorisés

1. **gRPC Requests Rate**
   ```promql
   rate(grpc_requests_total[5m])
   ```

2. **gRPC Error Rate**
   ```promql
   rate(grpc_requests_total{status="error"}[5m]) /
   rate(grpc_requests_total[5m])
   ```

3. **Request Duration (p95)**
   ```promql
   histogram_quantile(0.95, grpc_request_duration_seconds)
   ```

4. **Memory Usage**
   ```promql
   process_memory_bytes / 1024 / 1024 / 1024  # Convert to GB
   ```

5. **Active Connections**
   ```promql
   grpc_active_connections
   ```

6. **Sync Success Rate**
   ```promql
   rate(sync_jobs_total{status="success"}[5m]) /
   rate(sync_jobs_total[5m])
   ```

7. **Attestation Failures**
   ```promql
   increase(enclave_attestation_failure_total[1h])
   ```

### Panels INTERDITS

❌ Toute query avec label `user_uid`, `user_id`, `client_id`
❌ Toute metric avec des montants individuels
❌ Toute metric avec des symboles de trading

---

## 🔍 Audit des Metrics (Checklist)

Avant de déployer en production, vérifier :

- [ ] Aucune metric avec label `user_uid` ou équivalent
- [ ] Aucun montant financier individuel (seulement moyennes/totaux)
- [ ] Aucun symbole de trading dans les labels
- [ ] Aucun credential ou secret dans les metrics
- [ ] Aucune IP d'utilisateur dans les labels
- [ ] Toutes les metrics sont agrégées (count, rate, avg)
- [ ] Les logs ne sont PAS envoyés à Grafana (uniquement Prometheus metrics)
- [ ] L'endpoint `/metrics` est **interne uniquement** (pas exposé à internet)

### Script d'audit automatique

```bash
# Vérifier qu'aucune metric ne contient "user_uid"
curl -s http://localhost:9090/metrics | grep -i "user_uid" && echo "⚠️ LEAK DETECTED" || echo "✅ SAFE"

# Vérifier qu'aucune metric ne contient "balance"
curl -s http://localhost:9090/metrics | grep -i "balance" && echo "⚠️ LEAK DETECTED" || echo "✅ SAFE"

# Vérifier qu'aucune metric ne contient des symboles
curl -s http://localhost:9090/metrics | grep -E "(BTC|ETH|USD)" && echo "⚠️ LEAK DETECTED" || echo "✅ SAFE"
```

---

## 🛡️ Protection de l'Endpoint /metrics

### 1. Firewall (OBLIGATOIRE)

```bash
# Bloquer l'accès depuis l'extérieur
sudo ufw deny 9090/tcp

# Autoriser seulement localhost
sudo ufw allow from 127.0.0.1 to any port 9090
```

### 2. Reverse Proxy avec Auth (si exposition nécessaire)

```nginx
# /etc/nginx/sites-available/metrics

server {
  listen 443 ssl;
  server_name metrics.internal.trackrecord.com;

  ssl_certificate /etc/letsencrypt/live/trackrecord.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/trackrecord.com/privkey.pem;

  location /metrics {
    # Basic auth (username/password)
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # IP whitelist
    allow 10.0.0.0/8;  # Internal network only
    deny all;

    proxy_pass http://localhost:9090/metrics;
  }
}
```

### 3. mTLS (Production)

```typescript
// src/services/metrics.service.ts

import * as https from 'https';
import * as fs from 'fs';

startMetricsServer(port: number): void {
  const server = https.createServer({
    key: fs.readFileSync(process.env.TLS_SERVER_KEY!),
    cert: fs.readFileSync(process.env.TLS_SERVER_CERT!),
    ca: fs.readFileSync(process.env.TLS_CA_CERT!),
    requestCert: true,  // Require client cert
    rejectUnauthorized: true
  }, (req, res) => {
    // ... handler
  });

  server.listen(port, '0.0.0.0');
}
```

---

## 📚 Résumé

### DO ✅

- Utiliser des metrics agrégées uniquement
- Compter les requêtes totales, taux d'erreur, latences
- Monitorer les ressources système (CPU, RAM, disk)
- Protéger `/metrics` avec firewall + auth
- Auditer régulièrement les metrics exposées

### DON'T ❌

- Jamais de user IDs en clair dans les labels
- Jamais de montants financiers individuels
- Jamais de symboles de trading
- Jamais de credentials ou secrets
- Jamais d'exposition publique de `/metrics`

---

**Principe général** : Si Grafana est compromis, l'attaquant ne doit **rien** apprendre sur les utilisateurs individuels.
