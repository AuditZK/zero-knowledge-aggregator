/**
 * Report Types for Enclave-Signed Track Records
 *
 * SECURITY: All reports generated in enclave are cryptographically signed
 * to prove authenticity and data integrity.
 */

// ============================================================================
// Request Types
// ============================================================================

export interface ReportRequest {
  userUid: string;
  startDate?: string;      // YYYY-MM-DD (optional, defaults to first snapshot)
  endDate?: string;        // YYYY-MM-DD (optional, defaults to last snapshot)
  benchmark?: 'SPY' | 'BTC-USD';  // Optional benchmark comparison
  includeRiskMetrics?: boolean;   // Include VaR, skewness, kurtosis
  includeDrawdown?: boolean;      // Include drawdown chart data
  reportName?: string;
  baseCurrency?: string;   // USD, EUR, etc.
}

// ============================================================================
// Daily & Monthly Return Data
// ============================================================================

export interface DailyReturn {
  date: string;            // YYYY-MM-DD
  netReturn: number;       // Daily return in %
  benchmarkReturn: number; // Benchmark return in % (0 if no benchmark)
  outperformance: number;  // Portfolio - Benchmark
  cumulativeReturn: number; // Cumulative return factor (1.0 = no change)
  nav: number;             // Net Asset Value
}

export interface MonthlyReturn {
  date: string;            // YYYY-MM
  netReturn: number;       // Monthly return in %
  benchmarkReturn: number; // Benchmark return in %
  outperformance: number;  // Portfolio - Benchmark
  aum: number;             // Assets Under Management (NAV at month end)
}

// ============================================================================
// Metrics Types
// ============================================================================

export interface CoreMetrics {
  totalReturn: number;       // Total cumulative return (%)
  annualizedReturn: number;  // CAGR (%)
  volatility: number;        // Annualized volatility (%)
  sharpeRatio: number;       // Risk-adjusted return
  sortinoRatio: number;      // Downside risk-adjusted return
  maxDrawdown: number;       // Maximum peak-to-trough decline (%)
  calmarRatio: number;       // Annualized return / Max drawdown
}

export interface RiskMetrics {
  var95: number;             // Value at Risk 95% confidence
  var99: number;             // Value at Risk 99% confidence
  expectedShortfall: number; // Expected loss beyond VaR (CVaR)
  skewness: number;          // Distribution asymmetry
  kurtosis: number;          // Tail behavior (excess kurtosis)
}

export interface BenchmarkMetrics {
  alpha: number;             // Excess return vs benchmark (annualized %)
  beta: number;              // Portfolio sensitivity to market
  informationRatio: number;  // Alpha / Tracking Error
  trackingError: number;     // Volatility of active returns (%)
  correlation: number;       // Correlation with benchmark (-1 to 1)
}

export interface DrawdownData {
  maxDrawdownDuration: number;  // Days in max drawdown
  currentDrawdown: number;      // Current drawdown from peak (%)
  drawdownPeriods: DrawdownPeriod[];
}

export interface DrawdownPeriod {
  startDate: string;
  endDate: string;
  depth: number;        // Max drawdown during period (%)
  duration: number;     // Days
  recovered: boolean;
}

// ============================================================================
// Full Report Types
// ============================================================================

export interface ReportMetrics extends CoreMetrics {
  riskMetrics?: RiskMetrics;
  benchmarkMetrics?: BenchmarkMetrics;
  drawdownData?: DrawdownData;
}

export interface ReportData {
  // Metadata
  reportId: string;
  userUid: string;
  reportName: string;
  generatedAt: Date;
  periodStart: Date;
  periodEnd: Date;
  baseCurrency: string;
  benchmark?: string;
  dataPoints: number;

  // Metrics
  metrics: ReportMetrics;

  // Chart data
  dailyReturns: DailyReturn[];
  monthlyReturns: MonthlyReturn[];
}

// ============================================================================
// Signed Report Types
// ============================================================================

export interface SignedReport {
  // Report content
  report: ReportData;

  // Cryptographic signature
  signature: string;         // Base64 encoded ECDSA signature
  publicKey: string;         // Base64 encoded public key for verification
  signatureAlgorithm: string; // e.g., "ECDSA-P256-SHA256"

  // Enclave attestation
  enclaveVersion: string;
  attestationId?: string;    // SEV-SNP attestation ID if available
  enclaveMode: 'production' | 'development';

  // Integrity
  reportHash: string;        // SHA-256 hash of report data
}

export interface VerifySignatureRequest {
  reportHash: string;
  signature: string;
  publicKey: string;
}

export interface VerifySignatureResponse {
  valid: boolean;
  error?: string;
}

// ============================================================================
// gRPC Response Types (for enclave-server)
// ============================================================================

export interface GenerateReportResult {
  success: boolean;
  signedReport?: SignedReport;
  error?: string;
  cached?: boolean;  // True if report was returned from cache (same period already generated)
}
