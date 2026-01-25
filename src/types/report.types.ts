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
  baseCurrency?: string;   // USD, EUR, etc.

  // Display parameters - NOT part of signed data (can be customized per request)
  displayParams?: DisplayParameters;
}

// ============================================================================
// Display Parameters (NOT signed - presentation only)
// ============================================================================

/**
 * Display parameters are NOT part of the cryptographic signature.
 * This allows users to customize the report presentation (name, manager, firm)
 * without invalidating the cached signed data.
 *
 * The signature proves the FINANCIAL DATA is authentic, not arbitrary text.
 */
export interface DisplayParameters {
  reportName?: string;      // Custom report name (default: "Track Record Report")
  managerName?: string;     // Portfolio manager name
  firmName?: string;        // Firm/company name
  strategy?: string;        // Strategy description
  disclaimers?: string;     // Custom disclaimers
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

/**
 * Signed Financial Data - This is what gets cryptographically signed
 *
 * SECURITY: Only financial data is signed. Display parameters (names, labels)
 * are NOT included in the signature. This ensures:
 * 1. Same period = same signature (deduplication works)
 * 2. Users can customize presentation without invalidating proof
 * 3. The signature proves the NUMBERS are authentic
 */
export interface SignedFinancialData {
  // Immutable identifiers
  reportId: string;
  userUid: string;
  generatedAt: Date;
  periodStart: Date;
  periodEnd: Date;
  baseCurrency: string;
  benchmark?: string;
  dataPoints: number;

  // Connected exchanges (SIGNED) - proves which brokers were used
  // This is cryptographically bound to the report via the signature
  exchanges: string[];

  // Financial metrics (SIGNED)
  metrics: ReportMetrics;

  // Chart data (SIGNED)
  dailyReturns: DailyReturn[];
  monthlyReturns: MonthlyReturn[];
}

/**
 * Full Report Data - Combines signed financial data with display parameters
 *
 * When generating a report:
 * 1. Check cache for existing SignedFinancialData (same period)
 * 2. If cached, apply new display parameters
 * 3. If not cached, generate and sign financial data, then apply display params
 */
export interface ReportData extends SignedFinancialData {
  // Display parameters (NOT signed - can be customized per request)
  displayParams: DisplayParameters;
}

// ============================================================================
// Signed Report Types
// ============================================================================

/**
 * Signed Report - Contains cryptographically signed financial data
 *
 * IMPORTANT: The signature is computed on SignedFinancialData ONLY.
 * Display parameters are included but NOT part of the hash/signature.
 * This allows users to customize presentation without invalidating the proof.
 */
export interface SignedReport {
  // Signed financial data (this is what the signature proves)
  financialData: SignedFinancialData;

  // Display parameters (NOT signed - presentation only)
  displayParams: DisplayParameters;

  // Cryptographic signature (computed on financialData only)
  signature: string;         // Base64 encoded ECDSA signature
  publicKey: string;         // Base64 encoded public key for verification
  signatureAlgorithm: string; // e.g., "ECDSA-P256-SHA256"

  // Enclave attestation
  enclaveVersion: string;
  attestationId?: string;    // SEV-SNP attestation ID if available
  enclaveMode: 'production' | 'development';

  // AMD SEV-SNP Measurement - Hash of enclave code (compare with GitHub releases)
  measurement?: string;      // 384-bit hash of enclave code (hex)

  // Integrity (hash of financialData only, NOT displayParams)
  reportHash: string;        // SHA-256 hash of financial data
}

/**
 * @deprecated Use SignedReport.financialData instead
 * Kept for backward compatibility with existing code
 */
export interface SignedReportLegacy {
  report: ReportData;
  signature: string;
  publicKey: string;
  signatureAlgorithm: string;
  enclaveVersion: string;
  attestationId?: string;
  enclaveMode: 'production' | 'development';
  reportHash: string;
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
