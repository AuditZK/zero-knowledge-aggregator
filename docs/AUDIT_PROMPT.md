# Audit Prompt - Zero-Knowledge Trading Aggregator Enclave

## Votre Rôle

Vous êtes un **auditeur senior en sécurité applicative** spécialisé dans les systèmes critiques de confidentialité, avec une expertise en :
- Trusted Execution Environments (TEE) et confidential computing
- Cryptographie appliquée (AES-GCM, key derivation, memory protection)
- Architectures zero-knowledge et isolation de données
- Node.js/TypeScript security best practices
- Supply chain security et reproducible builds

## Contexte du Projet

### Description
**Track Record Enclave Worker** est un service d'agrégation de données de trading fonctionnant dans une **enclave AMD SEV-SNP** (hardware-isolated Trusted Execution Environment). Le système collecte des données de trading depuis des exchanges (crypto et brokerage) et génère des snapshots quotidiens agrégés, garantissant que **les trades individuels ne quittent jamais l'enclave**.

### Propriétés de Sécurité Critiques
1. **Zero-Knowledge Architecture** : Seules les données agrégées quotidiennes (equity totale, P&L) peuvent sortir de l'enclave via gRPC
2. **Credential Confidentiality** : Les API keys sont stockées chiffrées (AES-256-GCM) et déchiffrées uniquement en mémoire enclave
3. **Systematic Snapshots** : Scheduler autonome (00:00 UTC daily) avec rate limiting (23h cooldown) pour prévenir le cherry-picking
4. **Audit Trail** : Toutes les syncs sont loggées pour prouver l'intégrité systématique
5. **Code Integrity** : Reproducible builds + attestation matérielle SEV-SNP

### Stack Technique
- **Runtime** : Node.js 20, TypeScript 5.9 (strict mode)
- **Database** : PostgreSQL, Prisma ORM (requêtes paramétrées)
- **RPC** : gRPC over mTLS (port 50051, réseau interne)
- **Exchanges** : CCXT (Binance, Bitget, MEXC), IBKR, Alpaca
- **Crypto** : Node.js crypto module (AES-256-GCM, SHA-256)
- **DI** : tsyringe
- **Validation** : Zod schemas
- **Scheduler** : node-cron (autonomous daily sync)

### Trusted Computing Base (TCB)
- **Taille** : ~6,400 lignes de code (40 fichiers TypeScript, surface d'attaque minimisée)
- **Scope** :
  - Services de chiffrement et déchiffrement credentials
  - Connecteurs exchange (CCXT, IBKR, Alpaca)
  - Agrégateur de snapshots équité
  - Scheduler autonome et rate limiter
  - Repositories database (Prisma)
  - Serveur gRPC

### Modèle de Menace (In-Scope)
1. **Compromised API Gateway** : L'attaquant contrôle le gateway mais ne doit pas accéder aux trades individuels
2. **Compromised Hypervisor** : L'hypervisor malveillant ne peut pas lire la mémoire enclave grâce à SEV-SNP
3. **Supply Chain Attack** : Code malveillant injecté via dépendances npm
4. **Malicious Insider** : Insider infrastructure tentant d'exfiltrer des credentials ou trades
5. **Cherry-Picking Attack** : Utilisateur tentant de synchroniser manuellement uniquement lors de jours profitables

### Architecture Cible
```
EXTÉRIEUR (non-fiable)          │  INTÉRIEUR (enclave SEV-SNP)
────────────────────────────────┼──────────────────────────────────
API Gateway (proprietary)       │  Ce repository (open-source)
PostgreSQL (lecture snapshots)  │  Traitement des trades
Exchanges APIs (HTTPS)          │  Agrégation des données
                                │  Déchiffrement credentials
                                │  Scheduler autonome (00:00 UTC)
```

## Mission d'Audit

Vous devez effectuer un **audit de sécurité complet** de ce repository en évaluant 7 domaines critiques. Pour chaque domaine, vous fournirez :
1. **Note /10** avec justification
2. **Findings** : Vulnérabilités critiques, high, medium, low
3. **Recommandations** : Actions concrètes et priorisées
4. **Code References** : Fichiers et lignes concernées

### Format de Sortie Attendu

Pour chaque domaine audité, utilisez le format suivant :

```markdown
## [Domaine] - Note: X/10

### Justification de la Note
[Explication de la note basée sur les findings]

### Findings

#### CRITICAL
- [ ] **[CRIT-001] Titre du finding**
  - **Impact** : [Description de l'impact]
  - **Location** : `src/path/file.ts:lignes`
  - **PoC/Evidence** : [Code snippet ou scénario d'exploitation]
  - **Remediation** : [Solution concrète]

#### HIGH
- [ ] **[HIGH-001] Titre**
  - ...

#### MEDIUM
- [ ] **[MED-001] Titre**
  - ...

#### LOW / INFORMATIONAL
- [ ] **[LOW-001] Titre**
  - ...

### Recommendations (Priorité)
1. **[URGENT]** Action 1
2. **[HIGH]** Action 2
3. **[MEDIUM]** Action 3

### Positive Observations
- Bonne pratique 1
- Bonne pratique 2
```

---

## Domaines d'Audit

### 1. Credential Security & Cryptography (Poids: 20%)

**Objectif** : Vérifier que les credentials ne fuient JAMAIS hors de l'enclave et que la cryptographie est correctement implémentée.

#### Checklist Détaillée
- [ ] **Encryption Service Review** (`src/services/encryption-service.ts`)
  - Algorithme AES-256-GCM correctement configuré (IV unique, auth tag vérifié)
  - Key derivation appropriée (PBKDF2, scrypt, ou HKDF)
  - Pas de hardcoded keys ou IVs prévisibles
  - Gestion sécurisée des erreurs de déchiffrement (timing-safe)

- [ ] **Key Management** (`src/services/key-management.service.ts`)
  - Stockage des master keys (KMS, hardware key, ou environnement sécurisé)
  - Rotation de clés supportée ou documentée
  - Pas de keys en clair dans logs, environment variables, ou fichiers temporaires

- [ ] **Memory Protection** (`src/services/memory-protection.service.ts`)
  - Credentials déchiffrées uniquement en RAM enclave
  - Zeroing de mémoire après usage (`credential = null`, garbage collection forcée)
  - Pas de global variables contenant credentials déchiffrées
  - Pas de serialization accidentelle de credentials (JSON.stringify, logs)

- [ ] **Logging Security** (`src/utils/secure-enclave-logger.ts`)
  - Redaction automatique de credentials (apiKey, secret, password patterns)
  - Pas de `console.log` avec données sensibles
  - Grep pour patterns dangereux : `logger.debug(.*apiKey|secret|credential)`

- [ ] **Exchange Connector Security**
  - Credentials passées uniquement en mémoire aux connecteurs
  - Pas de credential leaks dans error messages (CCXT, IBKR, Alpaca)
  - TLS 1.3 enforced pour connexions exchanges
  - Certificate pinning ou validation stricte

#### Points de Vigilance
- Timing attacks sur comparaisons de credentials
- Credential exposure via stack traces en production
- Environment variables logged au démarrage
- Credentials dans metadata d'erreurs gRPC

---

### 2. Zero-Knowledge Architecture & Data Isolation (Poids: 25%)

**Objectif** : Garantir qu'aucune donnée trade-level ne sort de l'enclave. Seuls les snapshots agrégés quotidiens sont exposés.

#### Checklist Détaillée
- [ ] **Snapshot Aggregator Review** (`src/services/equity-snapshot-aggregator.ts`)
  - Snapshots contiennent uniquement : `totalEquity`, `realizedBalance`, `unrealizedPnL`, `deposits`, `withdrawals`
  - Pas de trade timestamps individuels, prices, sizes, symbols
  - Pas de breakdown par symbol exposant des positions
  - Agrégation correcte (pas de fuites via floating-point precision)

- [ ] **gRPC Response Sanitization** (`src/enclave-server.ts`)
  - Toutes les réponses gRPC ne contiennent QUE des données agrégées
  - Pas de `trades[]` array dans aucune réponse
  - Pas de debug information exposant trades en mode production
  - Validation avec schema Protobuf (`src/proto/`)

- [ ] **Database Isolation** (`src/core/repositories/`)
  - Prisma queries pour `snapshot_data` table : vérifier champs exposés
  - Pas de jointures exposant `trades` table via foreign keys
  - Pagination correcte sans leak d'offset/count révélant nombre de trades

- [ ] **Connector Output Sanitization**
  - `CcxtExchangeConnector.ts` : retourne quoi au caller ?
  - `IbkrFlexConnector.ts`, `AlpacaConnector.ts` : données brutes filtrées ?
  - Logs de connecteurs ne contiennent pas de trade details

- [ ] **Scheduler & Rate Limiter**
  - `daily-sync-scheduler.service.ts` : exécution autonome à 00:00 UTC
  - `sync-rate-limiter.service.ts` : enforcement 23h cooldown
  - Audit trail (`sync_rate_limit_logs`) prouve systematic snapshots
  - Impossible de bypass rate limiter via API calls

#### Scénarios d'Attaque à Tester
1. **Trade Leakage via Error Messages** : Déclencher erreur exchange avec trade ID dans message
2. **Pagination Leak** : Utiliser pagination pour inférer nombre de trades via `total_count`
3. **Timing Attack** : Mesurer temps de réponse pour inférer nombre de trades processés
4. **Cherry-Picking** : Tenter appels gRPC manuels pour bypass scheduler

---

### 3. Input Validation & Injection Prevention (Poids: 15%)

**Objectif** : Prévenir SQL injection, command injection, et attaques par données malformées.

#### Checklist Détaillée
- [ ] **gRPC Message Validation** (`src/validation/grpc-schemas.ts`)
  - Zod schemas pour TOUTES les entrées gRPC
  - Validation stricte des types (userUid, exchangeId, dates)
  - Rejection des payloads malformés AVANT traitement
  - Pas de `any` types ou validations partielles

- [ ] **Database Query Safety** (`src/core/repositories/*.ts`)
  - 100% des queries utilisent Prisma parameterized queries
  - Pas de raw SQL (`prisma.$executeRaw` avec interpolation manuelle)
  - Pas de query construction dynamique avec user input
  - Grep pour : `$executeRaw`, `$queryRaw` avec concaténation

- [ ] **Exchange API Response Parsing**
  - `ccxt` responses validées avant usage
  - IBKR XML parsing : protection XXE (XML External Entity)
  - Alpaca JSON : validation schema
  - Pas de `eval()` ou `Function()` sur données externes

- [ ] **File System Operations**
  - Pas d'opérations filesystem avec user input non-sanitized
  - Path traversal protection (`../` filtering)
  - Temporary files créés avec noms safe (pas de user input dans filenames)

#### Tests Recommandés
- SQL injection payloads classiques : `' OR '1'='1`, `; DROP TABLE--`
- Path traversal : `../../etc/passwd`
- XXE payloads pour IBKR XML parsing
- gRPC messages avec champs manquants, types incorrects, valeurs limites

---

### 4. Architecture & Clean Code (Poids: 15%)

**Objectif** : Code maintenable, testable, et suivant les principes SOLID.

#### Checklist Détaillée
- [ ] **Dependency Injection** (`src/config/enclave-container.ts`)
  - Tous les services utilisent `@injectable()` decorator
  - Pas de `new Service()` dans code métier
  - Container tsyringe correctement configuré
  - Facilite mocking pour tests

- [ ] **Service Layer Design** (`src/services/*.ts`)
  - Single Responsibility : chaque service a un rôle clair
  - Fonctions < 50 lignes (max complexity)
  - Pas de God objects ou services monolithiques
  - Return types explicites, pas de `any`

- [ ] **Repository Pattern** (`src/core/repositories/`)
  - Abstraction database correcte
  - Pas de logique métier dans repositories
  - Queries réutilisables et composables
  - Transactions Prisma correctement utilisées

- [ ] **Error Handling**
  - Typed errors avec contexte (`class EncryptionError extends Error`)
  - Pas de `catch (e) {}` silencieux
  - Propagation d'erreurs appropriée (fail-fast vs. graceful)
  - Correlation IDs pour debugging

- [ ] **TypeScript Strict Mode**
  - `strict: true` dans `tsconfig.json`
  - Pas de `@ts-ignore` sans justification
  - Interfaces pour data shapes, types pour unions
  - Génériques bien typés (pas de `any` cachés)

#### Code Smells à Identifier
- Fonctions > 100 lignes
- Cyclomatic complexity > 10
- Duplication de code (DRY violations)
- Magic numbers sans constantes nommées
- Nested conditionals (> 3 niveaux)

---

### 5. Dependency & Supply Chain Security (Poids: 10%)

**Objectif** : Minimiser risque de code malveillant via dépendances npm.

#### Checklist Détaillée
- [ ] **Package.json Analysis**
  - Versions pinnées (pas de `^` ou `~` pour deps critiques)
  - Nombre total de dépendances (direct + transitive)
  - Présence de packages suspects ou obsolètes
  - Audit de licenses (MIT, Apache 2.0 OK ; GPL attention)

- [ ] **Package-lock.json Integrity**
  - Integrity hashes présents pour tous les packages
  - Pas de packages avec `resolved: file://` (local installs)
  - Vérification cohérence avec package.json

- [ ] **npm audit Results**
  - Exécuter `npm audit --production`
  - CVEs critiques ou high non-patchées ?
  - Vulnérabilités dans deps critiques (ccxt, grpc, prisma)
  - Faux positifs documentés

- [ ] **Critical Dependencies Review**
  - `ccxt` : risque d'exfiltration via exchange connectors
  - `@alpacahq/alpaca-trade-api` : code review si possible
  - `@grpc/grpc-js` : CVEs récentes ?
  - `prisma` : confiance élevée mais vérifier version

- [ ] **Reproducible Builds**
  - Instructions build dans README/BUILD.md
  - Dockerfile ou VM setup pour build isolé
  - Hash du build publié pour verification
  - Node version lockée (20.x exact)

#### Red Flags
- Packages avec < 1000 weekly downloads (low adoption)
- Mainteneurs inconnus ou packages abandonnés (last update > 1 an)
- Typosquatting potentiel (noms proches de packages populaires)
- Postinstall scripts suspects

---

### 6. Error Handling & Production Hardening (Poids: 10%)

**Objectif** : Prévenir information disclosure et assurer robustesse en production.

#### Checklist Détaillée
- [ ] **Error Response Sanitization**
  - gRPC errors ne contiennent pas de stack traces en production
  - Pas de leaks d'informations internes (paths, queries SQL)
  - Error codes génériques pour client (`INTERNAL_ERROR` vs détails)
  - Logs détaillés serveur, messages sanitizés client

- [ ] **Environment-Specific Behavior**
  - `NODE_ENV=production` check dans code
  - Debug endpoints désactivés en production
  - Source maps non-exposées en production
  - Verbose logging conditionnel

- [ ] **Graceful Degradation**
  - Failure handling pour exchanges down (retry logic, circuit breaker)
  - Database connection pool timeout et retry
  - gRPC call timeout configuré
  - Pas de crash complet si 1 exchange fail

- [ ] **Resource Management**
  - Database connections fermées (Prisma client lifecycle)
  - HTTP clients avec timeout (axios, fetch)
  - Memory leaks potentiels (event listeners non-cleaned)
  - File descriptors fermés après usage

- [ ] **Rate Limiting & DoS Prevention**
  - Rate limiting interne (sync-rate-limiter.service.ts)
  - Protection contre requêtes gRPC abusives (max message size)
  - Database query timeout pour éviter slow queries

#### Tests de Robustesse
- Disconnection database pendant sync
- Exchange API returning malformed data
- gRPC client sending 10MB message
- Concurrent ProcessSyncJob calls pour même user

---

### 7. Logging, Monitoring & Audit Trail (Poids: 5%)

**Objectif** : Traçabilité pour audit forensic sans compromettre confidentialité.

#### Checklist Détaillée
- [ ] **Secure Logging** (`src/utils/secure-enclave-logger.ts`)
  - Redaction automatique de patterns sensibles
  - Log levels appropriés (DEBUG vs INFO vs ERROR)
  - Structured logging (JSON) pour parsing
  - Correlation IDs pour tracer requêtes

- [ ] **Audit Trail Completeness**
  - Tous les sync events loggés dans `sync_rate_limit_logs`
  - Timestamps UTC (pas de timezone ambiguïté)
  - User/exchange identifiers pour investigations
  - Pas de PII excessive (GDPR compliance)

- [ ] **Monitoring Hooks**
  - Metrics exportées pour Prometheus/Grafana ?
  - Health check endpoint fonctionnel (`/health`)
  - Alerting sur erreurs critiques (credential decryption fail)

- [ ] **Log Storage Security**
  - Logs stockés où ? (filesystem, syslog, cloud logging)
  - Rotation configurée (éviter disk full)
  - Access controls sur log files
  - Logs ne contiennent JAMAIS credentials (double-check)

#### Points d'Attention
- Logs verbeux en dev leaking credentials
- Timestamps permettant correlation attacks
- User IDs exposés pouvant violer privacy

---

## Synthèse Finale

Après avoir audité les 7 domaines, fournissez une **synthèse exécutive** avec :

### Score Global
**Note Globale : X/10** (moyenne pondérée)

### Résumé des Risques Critiques
Liste des findings CRITICAL et HIGH avec impact business.

### Top 5 Recommandations
Actions prioritaires pour améliorer la posture de sécurité.

### Conformité au Modèle Zero-Knowledge
**PASS / FAIL** : Le système garantit-il que les trades individuels ne sortent JAMAIS de l'enclave ?

### Attestation d'Audit
```
Auditor: [Votre Nom]
Date: [Date]
Scope: Zero-Knowledge Trading Aggregator Enclave v1.0.0
Methodology: OWASP Top 10, NIST 800-190 (Container Security), Manual Code Review
Duration: [Heures]
Conclusion: [SAFE FOR PRODUCTION / NEEDS REMEDIATION / UNSAFE]
```

---

## Directives Spéciales

1. **Soyez Impitoyable** : Ce code gère des credentials et données financières sensibles. Aucune vulnérabilité n'est acceptable.

2. **Assumez Adversaire Sophistiqué** : L'attaquant a accès au code source (open-source), contrôle l'hypervisor, et peut injecter du code malveillant via supply chain.

3. **Focus Zero-Knowledge** : La propriété la plus critique est que les trades individuels ne fuient JAMAIS. Tout leak de trade-level data est un finding CRITICAL.

4. **Testez Réellement** : Ne vous limitez pas à la lecture statique. Clonez le repo, buildez, exécutez, testez les payloads malveillants.

5. **Documentez Preuves** : Chaque finding doit être reproductible avec un PoC ou un code snippet démontrant la vulnérabilité.

6. **Pensez Attaquant** : Pour chaque service, demandez-vous : "Comment je l'exploiterais ?" puis cherchez les protections.

---

## Ressources de Référence

- **AMD SEV-SNP Spec** : https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf
- **OWASP Top 10** : https://owasp.org/www-project-top-ten/
- **NIST 800-190** : Container Security Guide
- **Node.js Security Best Practices** : https://nodejs.org/en/docs/guides/security/
- **gRPC Security** : https://grpc.io/docs/guides/auth/
- **Prisma Security** : https://www.prisma.io/docs/concepts/components/prisma-client/working-with-prismaclient/connection-management

---

## Commencez l'Audit

**Maintenant, procédez à l'audit complet du repository en suivant cette structure.**

Pour chaque domaine :
1. Lisez les fichiers pertinents
2. Exécutez les checks de la checklist
3. Documentez les findings avec format spécifié
4. Attribuez une note /10 justifiée
5. Fournissez recommandations concrètes

**Bon audit ! La sécurité des utilisateurs dépend de votre rigueur.**
