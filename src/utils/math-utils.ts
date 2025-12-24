/**
 * Math utilities for performance metrics calculation
 * Shared between ReportGeneratorService and PerformanceMetricsService
 */

const TRADING_DAYS_PER_YEAR = 252;

/**
 * Calculate volatility (standard deviation of returns)
 */
export function calculateVolatility(returns: number[]): number {
  if (returns.length <= 1) return 0;
  const mean = returns.reduce((sum, r) => sum + r, 0) / returns.length;
  const variance = returns.reduce((sum, r) => sum + Math.pow(r - mean, 2), 0) / (returns.length - 1);
  return Math.sqrt(variance);
}

/**
 * Calculate annualized volatility
 */
export function calculateAnnualizedVolatility(returns: number[]): number {
  return calculateVolatility(returns) * Math.sqrt(TRADING_DAYS_PER_YEAR);
}

/**
 * Calculate downside deviation (volatility of negative returns only)
 * MAR (Minimum Acceptable Return) = 0
 */
export function calculateDownsideDeviation(returns: number[]): number {
  const negativeReturns = returns.filter(r => r < 0);
  if (negativeReturns.length <= 1) return 0;
  const variance = negativeReturns.reduce((sum, r) => sum + Math.pow(r, 2), 0) / negativeReturns.length;
  return Math.sqrt(variance);
}

/**
 * Calculate maximum drawdown from cumulative returns
 */
export function calculateMaxDrawdownFromCumulative(cumulativeReturns: number[]): number {
  if (cumulativeReturns.length === 0) return 0;
  let peak = cumulativeReturns[0] ?? 1;
  let maxDrawdown = 0;

  for (const current of cumulativeReturns) {
    if (current > peak) peak = current;
    const drawdown = ((peak - current) / peak) * 100;
    if (drawdown > maxDrawdown) maxDrawdown = drawdown;
  }

  return -maxDrawdown; // Return as negative value
}

/**
 * Calculate Sharpe Ratio
 * @param annualizedReturn Annual return in percentage
 * @param annualizedVolatility Annual volatility in percentage
 * @param riskFreeRate Annual risk-free rate in percentage (default 2.5%)
 */
export function calculateSharpeRatio(
  annualizedReturn: number,
  annualizedVolatility: number,
  riskFreeRate: number = 2.5
): number {
  if (annualizedVolatility === 0) return 0;
  return (annualizedReturn - riskFreeRate) / annualizedVolatility;
}

/**
 * Calculate Sortino Ratio
 */
export function calculateSortinoRatio(
  annualizedReturn: number,
  downsideDeviation: number,
  riskFreeRate: number = 2.5
): number {
  if (downsideDeviation === 0) return 0;
  return (annualizedReturn - riskFreeRate) / downsideDeviation;
}

/**
 * Calculate Calmar Ratio
 */
export function calculateCalmarRatio(annualizedReturn: number, maxDrawdown: number): number {
  if (Math.abs(maxDrawdown) === 0) return 0;
  return annualizedReturn / Math.abs(maxDrawdown);
}

/**
 * Calculate win rate (% of positive returns)
 */
export function calculateWinRate(returns: number[]): number {
  if (returns.length === 0) return 0;
  const wins = returns.filter(r => r > 0).length;
  return (wins / returns.length) * 100;
}

/**
 * Calculate profit factor (sum of gains / sum of losses)
 */
export function calculateProfitFactor(returns: number[]): number | null {
  const gains = returns.filter(r => r > 0);
  const losses = returns.filter(r => r < 0);
  const totalGains = gains.reduce((sum, r) => sum + r, 0);
  const totalLosses = Math.abs(losses.reduce((sum, r) => sum + r, 0));

  if (totalLosses === 0) return totalGains > 0 ? null : 0; // null = infinite
  return totalGains / totalLosses;
}

/**
 * Calculate VaR (Value at Risk) at given confidence level
 */
export function calculateVaR(returns: number[], confidence: number = 0.95): number {
  if (returns.length === 0) return 0;
  const sorted = [...returns].sort((a, b) => a - b);
  const index = Math.max(0, Math.floor(returns.length * (1 - confidence)));
  return sorted[index] ?? 0;
}

/**
 * Calculate Expected Shortfall (CVaR) - average of returns below VaR
 */
export function calculateExpectedShortfall(returns: number[], confidence: number = 0.95): number {
  if (returns.length === 0) return 0;
  const sorted = [...returns].sort((a, b) => a - b);
  const varIndex = Math.max(0, Math.floor(returns.length * (1 - confidence)));
  const tailReturns = sorted.slice(0, varIndex + 1);
  if (tailReturns.length === 0) return 0;
  return tailReturns.reduce((sum, r) => sum + r, 0) / tailReturns.length;
}

/**
 * Calculate skewness of returns
 */
export function calculateSkewness(returns: number[]): number {
  if (returns.length === 0) return 0;
  const mean = returns.reduce((sum, r) => sum + r, 0) / returns.length;
  const stdDev = calculateVolatility(returns);
  if (stdDev === 0) return 0;
  return returns.reduce((sum, r) => sum + Math.pow((r - mean) / stdDev, 3), 0) / returns.length;
}

/**
 * Calculate excess kurtosis of returns
 */
export function calculateKurtosis(returns: number[]): number {
  if (returns.length === 0) return 0;
  const mean = returns.reduce((sum, r) => sum + r, 0) / returns.length;
  const stdDev = calculateVolatility(returns);
  if (stdDev === 0) return 0;
  return returns.reduce((sum, r) => sum + Math.pow((r - mean) / stdDev, 4), 0) / returns.length - 3;
}
