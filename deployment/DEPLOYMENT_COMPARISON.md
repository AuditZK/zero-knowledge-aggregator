# Comparaison des Options de Déploiement

Guide objectif pour choisir entre Docker Compose, Docker Swarm et Kubernetes.

## 🎯 TL;DR - Quelle option choisir ?

| Situation | Recommandation |
|-----------|----------------|
| **MVP / Single enclave** | ✅ **Docker Compose + systemd** (le plus simple) |
| **High availability (2-3 instances)** | ✅ **Docker Swarm** (juste milieu) |
| **Enterprise / Multi-services** | ⚠️ **Kubernetes** (si tu as une équipe DevOps) |

---

## 📊 Comparaison Objective

### Docker Compose + systemd (RECOMMANDÉ pour MVP)

**Ce que ça fait :**
- systemd démarre Docker Compose au boot
- Docker Compose gère le(s) container(s)
- Auto-restart si crash
- Logs via journalctl

**Avantages :**
- ✅ **Ultra simple** - 1 fichier YAML, 3 commandes
- ✅ **Zéro overhead** - Pas de composant supplémentaire
- ✅ **Parfait pour 1 VM** - Ton cas (AMD SEV-SNP = 1 VM dédiée)
- ✅ **Coût = $0** - Pas de managed service
- ✅ **Debuggage facile** - `docker logs`, pas de YAML complexe

**Inconvénients :**
- ❌ Pas de high availability automatique
- ❌ Pas de rolling updates (downtime de 5-10s)
- ❌ Pas de service discovery multi-VMs

**Commandes :**
```bash
# Déployer
sudo systemctl start enclave

# Voir les logs
sudo journalctl -u enclave -f

# Restart
sudo systemctl restart enclave

# Status
sudo systemctl status enclave
```

**Coût total :** VM uniquement (~$50-150/mois selon taille)

---

### Docker Swarm

**Ce que ça fait :**
- Orchestrateur léger de Docker
- Multiple VMs en cluster
- Load balancing automatique
- Rolling updates

**Avantages :**
- ✅ Simple à configurer (vs Kubernetes)
- ✅ High availability (2-3 instances)
- ✅ Rolling updates (zéro downtime)
- ✅ Secrets management intégré
- ✅ Même syntaxe que Docker Compose

**Inconvénients :**
- ⚠️ Nécessite 3 VMs minimum (1 manager + 2 workers)
- ⚠️ Moins populaire que Kubernetes (communauté plus petite)
- ❌ Pas de scaling automatique (HPA)
- ❌ Monitoring moins mature

**Setup :**
```bash
# Manager node
docker swarm init --advertise-addr 10.0.1.5

# Worker nodes
docker swarm join --token <token> 10.0.1.5:2377

# Deploy
docker stack deploy -c docker-compose.prod.yml enclave

# Scale
docker service scale enclave_enclave=3
```

**Coût total :** 3 VMs (~$150-450/mois)

---

### Kubernetes (EKS/AKS/GKE)

**Ce que ça fait :**
- Orchestrateur enterprise-grade
- Auto-scaling
- Self-healing
- Service mesh (Istio, Linkerd)

**Avantages :**
- ✅ Industry standard (beaucoup de docs, outils)
- ✅ Auto-scaling horizontal/vertical
- ✅ Ecosystem riche (Helm, cert-manager, Prometheus Operator)
- ✅ Multi-cloud portable

**Inconvénients :**
- ❌ **TRÈS complexe** - Learning curve énorme
- ❌ **Coût élevé** - Control plane $70-150/mois + worker nodes
- ❌ **Overkill pour 1 service** - Justifié si tu as 10+ microservices
- ❌ **YAML hell** - ConfigMaps, Secrets, Deployments, Services, Ingress...
- ❌ **Debugging difficile** - Logs dans pods éphémères

**Setup (minimal) :**
```bash
# Deploy
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

**Coût total :** $200-500/mois minimum (control plane + nodes)

---

## 🤔 Questions pour Choisir

### Q1 : Combien d'instances de l'enclave tu as besoin ?

- **1 instance** → **Docker Compose + systemd**
- **2-3 instances** → **Docker Swarm**
- **10+ instances** → Kubernetes (mais pourquoi tu aurais besoin de 10 enclaves ?)

### Q2 : C'est quoi ton budget infrastructure ?

- **< $200/mois** → **Docker Compose** (1 VM suffit)
- **$200-500/mois** → Docker Swarm (3 VMs)
- **> $500/mois** → Kubernetes (si justifié)

### Q3 : Tu as une équipe DevOps ?

- **Non, je suis seul(e)** → **Docker Compose** (pas le temps d'apprendre K8s)
- **Oui, 1-2 personnes** → Docker Swarm
- **Oui, équipe dédiée** → Kubernetes

### Q4 : Downtime de 10 secondes acceptable ?

- **Oui** (updates à 3h du matin) → **Docker Compose**
- **Non** (besoin 99.99% uptime) → Swarm ou Kubernetes

### Q5 : Tu gères déjà Kubernetes ailleurs ?

- **Oui, on a déjà un cluster** → OK, ajoute l'enclave dedans
- **Non** → **Ne crée pas un cluster juste pour 1 service**

---

## 📋 Checklist de Décision

### Utilise Docker Compose + systemd si :

- [ ] Tu déploies sur **1 seule VM AMD SEV-SNP**
- [ ] Tu n'as pas besoin de high availability (99.9% uptime suffit)
- [ ] Tu veux **minimiser la complexité**
- [ ] Downtime de 10s pour updates est acceptable
- [ ] Budget limité (< $200/mois)

### Utilise Docker Swarm si :

- [ ] Tu veux **high availability** (2-3 instances)
- [ ] Rolling updates sans downtime nécessaires
- [ ] Tu veux rester simple (pas de K8s)
- [ ] Budget $200-500/mois OK

### Utilise Kubernetes si :

- [ ] Tu as déjà un cluster Kubernetes existant
- [ ] Tu as **10+ microservices** à gérer
- [ ] Tu as une équipe DevOps dédiée
- [ ] Tu as besoin d'auto-scaling agressif
- [ ] Budget > $500/mois

---

## 🚀 Mon Recommandation pour TON Projet

**Commence avec Docker Compose + systemd** pour ces raisons :

### 1. Architecture du projet
```
1 Enclave Worker
     ↓
1 VM AMD SEV-SNP dédiée
     ↓
1 container Docker
```
→ **Pas besoin d'orchestrateur** pour gérer 1 container

### 2. AMD SEV-SNP = Hardware limité
- Tu ne peux pas avoir 10 enclaves AMD SEV-SNP en même temps sur 1 VM
- Chaque VM = 1 enclave maximum
- Multi-VMs = coût élevé sans bénéfice réel

### 3. Simplicité = Sécurité
- Moins de composants = moins de surface d'attaque
- systemd est audité depuis 20 ans
- Kubernetes ajoute des CVEs potentielles (API server, etcd, kubelet...)

### 4. Évolution possible
Si tu as vraiment besoin de scale après :
```
Phase 1: Docker Compose (1 VM)
         ↓ (si besoin)
Phase 2: Docker Swarm (3 VMs)
         ↓ (si vraiment besoin)
Phase 3: Kubernetes (cluster)
```

Le fichier `docker-compose.prod.yml` que j'ai créé **fonctionne aussi avec Swarm** (juste `docker stack deploy`).

---

## 📝 Setup Recommandé (MVP Production)

### Infrastructure
```
┌─────────────────────────────────────┐
│  VM AMD SEV-SNP                     │
│  - AMD SEV-SNP enabled              │
│  - Ubuntu 22.04 LTS                 │
│  - 2 vCPUs, 4GB RAM                 │
│  - Coût: ~$100/mois                 │
│                                     │
│  ┌───────────────────────────────┐  │
│  │  systemd (auto-start)         │  │
│  │        ↓                      │  │
│  │  docker-compose               │  │
│  │        ↓                      │  │
│  │  ┌─────────────────────────┐ │  │
│  │  │ Enclave Container       │ │  │
│  │  │ - gRPC :50051           │ │  │
│  │  │ - Metrics :9090         │ │  │
│  │  └─────────────────────────┘ │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
            │
            ↓ (internal network)
┌─────────────────────────────────────┐
│  PostgreSQL                         │
│  - Managed or self-hosted           │
│  - Automated backups                │
│  - Coût: ~$50/mois                  │
└─────────────────────────────────────┘
```

**Coût total : ~$150/mois** (vs $500+/mois avec Kubernetes)

### Déploiement en 3 commandes

```bash
# 1. Cloner et déployer
git clone https://github.com/your-org/track-record-enclave.git
cd track-record-enclave
chmod +x deployment/deploy-simple.sh
sudo ./deployment/deploy-simple.sh

# 2. Configurer les secrets
sudo nano /etc/enclave/.env.production
# → Mettre DATABASE_URL, JWT_SECRET

# 3. Démarrer
sudo systemctl start enclave
sudo systemctl status enclave
```

### Monitoring (même sans Kubernetes)

```bash
# Metrics Prometheus
curl http://localhost:9090/metrics

# Health check
curl http://localhost:9090/health

# Logs en temps réel
sudo journalctl -u enclave -f --output json-pretty

# Alerting (cron job simple)
# /etc/cron.d/enclave-healthcheck
*/5 * * * * root curl -sf http://localhost:9090/health || /usr/local/bin/alert-oncall.sh
```

---

## 🎯 Conclusion

**Pour le MVP de Track Record Enclave :**

✅ **Utilise Docker Compose + systemd**

**Raisons :**
1. Simplicité maximale (MVP = speed to market)
2. Coût minimal ($150/mois vs $500+/mois)
3. Architecture 1 enclave = 1 VM (pas besoin d'orchestrateur)
4. Sécurité (moins de composants = moins de CVEs)
5. Évolution possible vers Swarm/K8s si vraiment nécessaire

**Tu pourras toujours migrer vers Kubernetes plus tard si :**
- Tu as besoin de 10+ enclaves (vraiment ?)
- Tu lèves des fonds et as une équipe DevOps
- Tu ajoutes 20 autres microservices

**Mais pour le MVP : KISS (Keep It Simple, Stupid)**

---

## 📚 Ressources

- [deployment/deploy-simple.sh](deploy-simple.sh) - Script de déploiement automatisé
- [deployment/systemd/enclave.service](systemd/enclave.service) - Service systemd
- [../docker-compose.prod.yml](../docker-compose.prod.yml) - Config Docker Compose production
- [../PRODUCTION_SETUP.md](../PRODUCTION_SETUP.md) - Guide de setup production
