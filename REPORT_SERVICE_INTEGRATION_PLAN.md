# Report Service Integration Plan

## Overview

Migration du calcul des métriques de rapport du frontend vers l'Aggregator (Enclave) avec signature cryptographique.

## Architecture Cible

```
Frontend                              Enclave Aggregator
┌────────────────────┐                ┌─────────────────────────────┐
│ User Config UI     │                │ ReportGeneratorService      │
│ (generate/page.tsx)│──gRPC─────────▶│  - Fetch snapshots (DB)     │
│                    │                │  - Calculate ALL metrics    │
│ PDF Generation     │◀───────────────│  - Sign with enclave key    │
│ (Puppeteer)        │                │  - Return SignedReport      │
│                    │                └─────────────────────────────┘
│ Report Storage     │
│ (Platform DB)      │
└────────────────────┘
```

## Métriques à calculer dans l'Enclave

### 1. Return Metrics
- `totalReturn` - Rendement cumulé (%)
- `annualizedReturn` - CAGR (%)
- `dailyReturns[]` - Array de rendements journaliers
- `monthlyReturns[]` - Array de rendements mensuels

### 2. Risk Metrics
- `volatility` - Écart-type annualisé (%)
- `maxDrawdown` - Drawdown maximum (%)
- `sharpeRatio` - Rendement / Risque
- `sortinoRatio` - Rendement / Downside risk
- `calmarRatio` - Rendement annualisé / Max drawdown

### 3. Advanced Risk Metrics
- `var95` - Value at Risk 95%
- `var99` - Value at Risk 99%
- `expectedShortfall` - Perte moyenne au-delà du VaR
- `skewness` - Asymétrie de la distribution
- `kurtosis` - Queues de distribution

### 4. Benchmark Metrics (si benchmark fourni)
- `alpha` - Rendement excédentaire vs benchmark
- `beta` - Sensibilité au marché
- `informationRatio` - Alpha / Tracking Error
- `trackingError` - Volatilité des rendements actifs
- `correlation` - Corrélation avec le benchmark

## Fichiers à créer dans l'Enclave

### 1. `src/services/report-generator.service.ts` (~500 lignes)

```typescript
@injectable()
export class ReportGeneratorService {
  constructor(
    @inject(SnapshotDataRepository) private snapshotRepo,
    @inject(PerformanceMetricsService) private metricsService,
    @inject(ReportSigningService) private signingService
  ) {}

  async generateSignedReport(request: ReportRequest): Promise<SignedReport>

  // Méthodes privées:
  private aggregateToDailyReturns(snapshots): DailyReturn[]
  private aggregateToMonthlyReturns(dailyReturns): MonthlyReturn[]
  private calculateRiskMetrics(dailyReturns): RiskAnalysis
  private calculateBenchmarkMetrics(dailyReturns, benchmark): BenchmarkMetrics
}
```

### 2. `src/services/report-signing.service.ts` (~150 lignes)

```typescript
@injectable()
export class ReportSigningService {
  // Clé privée de l'enclave pour signer les rapports
  private enclavePrivateKey: Buffer

  async signReport(reportData: ReportData): Promise<SignedReport>
  async verifySignature(signedReport: SignedReport): Promise<boolean>

  // Génère un hash du rapport pour vérification
  private generateReportHash(reportData): string
}
```

### 3. Modifications `src/proto/enclave.proto`

```protobuf
// Nouveau message
message ReportRequest {
  string user_uid = 1;
  string start_date = 2;      // YYYY-MM-DD
  string end_date = 3;        // YYYY-MM-DD
  string benchmark = 4;       // "SPY" | "BTC-USD" | ""
  bool include_risk_metrics = 5;
  bool include_drawdown = 6;
  string report_name = 7;
  string base_currency = 8;
}

message SignedReportResponse {
  bool success = 1;
  string report_id = 2;
  string signature = 3;       // Signature cryptographique
  string public_key = 4;      // Clé publique pour vérification

  // Métadonnées
  string generated_at = 5;
  string enclave_version = 6;
  string attestation_id = 7;

  // Métriques
  double total_return = 10;
  double annualized_return = 11;
  double volatility = 12;
  double sharpe_ratio = 13;
  double sortino_ratio = 14;
  double max_drawdown = 15;
  double calmar_ratio = 16;

  // Benchmark (optionnel)
  double alpha = 20;
  double beta = 21;
  double information_ratio = 22;
  double tracking_error = 23;
  double correlation = 24;

  // Risk metrics avancés (optionnel)
  double var_95 = 30;
  double var_99 = 31;
  double expected_shortfall = 32;
  double skewness = 33;
  double kurtosis = 34;

  // Données pour les charts
  repeated DailyReturnData daily_returns = 40;
  repeated MonthlyReturnData monthly_returns = 41;

  string error = 99;
}

message DailyReturnData {
  string date = 1;
  double net_return = 2;
  double benchmark_return = 3;
  double outperformance = 4;
  double cumulative_return = 5;
  double nav = 6;
}

message MonthlyReturnData {
  string date = 1;
  double net_return = 2;
  double benchmark_return = 3;
  double outperformance = 4;
  double aum = 5;
}

// Nouveau RPC
service EnclaveService {
  // ... existing RPCs ...
  rpc GenerateSignedReport(ReportRequest) returns (SignedReportResponse);
  rpc VerifyReportSignature(VerifySignatureRequest) returns (VerifySignatureResponse);
}
```

## Étapes d'implémentation

### Phase 1: Core Service (3-4h)
1. [ ] Créer `src/types/report.types.ts` - Interfaces TypeScript
2. [ ] Créer `src/services/report-generator.service.ts` - Calculs de métriques
3. [ ] Tester les calculs avec les snapshots existants

### Phase 2: Signing Service (1-2h)
4. [ ] Créer `src/services/report-signing.service.ts` - Signature ECDSA
5. [ ] Générer/stocker la clé privée de l'enclave
6. [ ] Implémenter vérification de signature

### Phase 3: gRPC Integration (2h)
7. [ ] Modifier `src/proto/enclave.proto` - Nouveaux messages
8. [ ] Modifier `src/enclave-server.ts` - Handler gRPC
9. [ ] Modifier `src/enclave-worker.ts` - Logique métier
10. [ ] Enregistrer dans DI container

### Phase 4: Testing & Frontend (2h)
11. [ ] Créer script de test gRPC
12. [ ] Modifier frontend pour appeler l'enclave au lieu de calculer localement
13. [ ] Afficher la signature/attestation dans le rapport

## Différences avec le code Frontend actuel

| Aspect | Frontend (actuel) | Enclave (cible) |
|--------|-------------------|-----------------|
| Source des données | API /api/returns, /api/metrics | Direct DB (SnapshotDataRepository) |
| Benchmark | API /api/benchmark/{symbol} | Direct DB ou API interne |
| Signature | Aucune | ECDSA avec clé enclave |
| Attestation | Aucune | SEV-SNP attestation ID |
| Attribution | Données mock | Supprimé (pas de vraies données) |

## Sécurité

- **Clé privée enclave**: Générée au démarrage, stockée en mémoire uniquement
- **Signature**: ECDSA P-256 du hash SHA-256 du rapport
- **Attestation**: ID de l'attestation SEV-SNP inclus dans le rapport
- **Vérification**: Clé publique incluse pour vérification externe

## Questions à valider

1. **Benchmark data**: L'enclave doit-elle accéder au benchmark service directement ou via la Platform DB?
2. **Attribution analysis**: Supprimer (données mock) ou implémenter vraiment?
3. **Format signature**: ECDSA P-256 ou Ed25519?
4. **Clé enclave**: Générée à chaque démarrage ou persistée?
