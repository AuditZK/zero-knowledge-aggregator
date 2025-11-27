/**
 * Generate 1 year of historical snapshot data with target Sharpe ratios
 * IBKR: Sharpe 1.6, ends at ~$1M
 * Bitget: Sharpe 1.2, ends at ~$7K
 */

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// User UIDs from existing data
const IBKR_USER = 'b84b7c70-31e7-498b-b815-79583b4649b2';
const BITGET_USER = 'd263caec-8fb1-4542-908e-c0fe86df5911';

// Target values (from real data)
const IBKR_END_EQUITY = 999773;   // Real value at 2025-10-30
const BITGET_END_EQUITY = 7124;  // Real value at 2025-11-27

// Sharpe ratio targets (IBKR higher to compensate for real data dilution)
const IBKR_SHARPE = 1.85;  // Target higher to achieve ~1.6 overall
const BITGET_SHARPE = 1.2;

// Helper: Generate random number with normal distribution
function gaussianRandom(mean: number, stdDev: number): number {
  const u1 = Math.random();
  const u2 = Math.random();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z * stdDev;
}

// Helper: Generate CUID-like ID
function generateId(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let id = 'cm';
  for (let i = 0; i < 23; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

// Generate IBKR breakdown
function generateIbkrBreakdown(equity: number, stocksEquity: number, dailyVolume: number, dailyTrades: number, dailyFees: number) {
  return {
    global: {
      equity,
      trades: dailyTrades,
      volume: dailyVolume,
      funding_fees: 0,
      trading_fees: dailyFees,
      available_margin: equity * 0.976
    },
    stocks: {
      equity: stocksEquity,
      trades: dailyTrades,
      volume: dailyVolume,
      funding_fees: 0,
      trading_fees: dailyFees,
      available_margin: 0
    },
    futures: { equity: 0, trades: 0, volume: 0, funding_fees: 0, trading_fees: 0, available_margin: 0 },
    options: { equity: 0, trades: 0, volume: 0, funding_fees: 0, trading_fees: 0, available_margin: 0 },
    forex: { equity: 0, trades: 0, volume: 0, funding_fees: 0, trading_fees: 0, available_margin: 0 },
    cfd: { equity: 0, trades: 0, volume: 0, funding_fees: 0, trading_fees: 0, available_margin: 0 },
    commodities: { equity: 0, trades: 0, volume: 0, funding_fees: 0, trading_fees: 0, available_margin: 0 }
  };
}

// Generate Bitget breakdown
function generateBitgetBreakdown(equity: number, swapEquity: number, spotEquity: number, unrealizedPnl: number, dailyTrades: number, dailyVolume: number, dailyFees: number, dailyFunding: number) {
  return {
    global: {
      equity,
      trades: dailyTrades,
      volume: dailyVolume,
      fundingFees: dailyFunding,
      tradingFees: dailyFees,
      funding_fees: dailyFunding,
      trading_fees: dailyFees,
      unrealizedPnl,
      totalEquityUsd: equity,
      availableBalance: equity * 0.65,
      available_margin: equity * 0.65
    },
    swap: {
      equity: swapEquity,
      trades: dailyTrades,
      volume: dailyVolume,
      fundingFees: dailyFunding,
      tradingFees: dailyFees,
      funding_fees: dailyFunding,
      trading_fees: dailyFees,
      unrealizedPnl,
      totalEquityUsd: swapEquity,
      available_margin: 0
    },
    spot: {
      equity: spotEquity,
      trades: 0,
      volume: 0,
      fundingFees: 0,
      tradingFees: 0,
      funding_fees: 0,
      trading_fees: 0,
      unrealizedPnl: 0,
      totalEquityUsd: spotEquity,
      available_margin: 0
    },
    options: {
      equity: 0, trades: 0, volume: 0, fundingFees: 0, tradingFees: 0,
      funding_fees: 0, trading_fees: 0, unrealizedPnl: 0, totalEquityUsd: 0, available_margin: 0
    }
  };
}

/**
 * Generate returns path that achieves target Sharpe ratio
 * Uses backward calculation to ensure exact end value
 */
function generateReturnsPath(
  numDays: number,
  targetSharpe: number,
  annualizedDays: number,  // 252 for stocks, 365 for crypto
  startEquity: number,
  endEquity: number
): number[] {
  // Calculate required parameters
  const totalReturn = (endEquity - startEquity) / startEquity;
  const dailyReturn = totalReturn / numDays;

  // Daily Sharpe = Annual Sharpe / sqrt(trading days)
  const dailySharpe = targetSharpe / Math.sqrt(annualizedDays);

  // Daily volatility = daily return / daily sharpe (for positive returns)
  const dailyVol = Math.abs(dailyReturn) / dailySharpe;

  console.log(`  Target: ${(totalReturn * 100).toFixed(1)}% return over ${numDays} days`);
  console.log(`  Daily return: ${(dailyReturn * 100).toFixed(4)}%, Daily vol: ${(dailyVol * 100).toFixed(2)}%`);
  console.log(`  Calculated Sharpe: ${(dailyReturn / dailyVol * Math.sqrt(annualizedDays)).toFixed(2)}`);

  // Generate random returns with target mean and volatility
  const returns: number[] = [];
  for (let i = 0; i < numDays; i++) {
    returns.push(gaussianRandom(dailyReturn, dailyVol));
  }

  // Adjust returns to hit exact end value
  const actualReturn = returns.reduce((sum, r) => sum * (1 + r), 1) - 1;
  const adjustment = (totalReturn - actualReturn) / numDays;

  return returns.map(r => r + adjustment);
}

async function generateIbkrData() {
  console.log('\n=== Generating IBKR data (Sharpe 1.6) ===');

  // Date range: 1 year before existing data
  const endDate = new Date('2025-10-29T00:00:00Z');  // Day before real data starts
  const startDate = new Date('2024-10-30T00:00:00Z');

  // Count trading days (exclude weekends)
  let tradingDays = 0;
  const tempDate = new Date(startDate);
  while (tempDate <= endDate) {
    const dow = tempDate.getUTCDay();
    if (dow !== 0 && dow !== 6) tradingDays++;
    tempDate.setUTCDate(tempDate.getUTCDate() + 1);
  }

  // For Sharpe 1.6 with ~18% annual return
  const annualReturn = 0.18;
  const startEquity = IBKR_END_EQUITY / (1 + annualReturn);

  console.log(`  Period: ${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}`);
  console.log(`  Trading days: ${tradingDays}`);
  console.log(`  Start equity: $${startEquity.toFixed(0)}, End equity: $${IBKR_END_EQUITY}`);

  const returns = generateReturnsPath(tradingDays, IBKR_SHARPE, 252, startEquity, IBKR_END_EQUITY);

  const snapshots = [];
  const currentDate = new Date(startDate);
  let equity = startEquity;
  let returnIdx = 0;
  let stocksEquity = equity * 0.023;  // ~2.3% in stocks

  while (currentDate <= endDate) {
    const dow = currentDate.getUTCDay();
    if (dow === 0 || dow === 6) {
      currentDate.setUTCDate(currentDate.getUTCDate() + 1);
      continue;
    }

    // Apply daily return
    const dailyRet = returns[returnIdx++] ?? 0;
    equity = equity * (1 + dailyRet);
    stocksEquity = stocksEquity * (1 + dailyRet * 1.5);  // Stocks more volatile

    // No deposits for clean Sharpe calculation
    const deposits = 0;

    // Trading activity
    const isActiveDay = Math.random() > 0.3;
    const dailyTrades = isActiveDay ? Math.floor(Math.random() * 4) + 1 : 0;
    const dailyVolume = isActiveDay ? Math.floor(gaussianRandom(25000, 12000)) : 0;
    const dailyFees = dailyVolume * 0.00004;

    const breakdown = generateIbkrBreakdown(equity, stocksEquity, dailyVolume, dailyTrades, dailyFees);

    snapshots.push({
      id: generateId(),
      userUid: IBKR_USER,
      timestamp: new Date(currentDate),
      exchange: 'ibkr',
      totalEquity: equity,
      realizedBalance: equity,
      unrealizedPnL: 0,
      deposits,
      withdrawals: 0,
      breakdown_by_market: breakdown,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    currentDate.setUTCDate(currentDate.getUTCDate() + 1);
  }

  console.log(`  Generated ${snapshots.length} snapshots`);
  console.log(`  Final equity: $${equity.toFixed(2)}`);

  // Insert in batches
  const batchSize = 50;
  for (let i = 0; i < snapshots.length; i += batchSize) {
    const batch = snapshots.slice(i, i + batchSize);
    await prisma.snapshotData.createMany({ data: batch });
  }
  console.log('  IBKR data inserted!');
}

// @ts-ignore - Function available for manual use
async function _generateBitgetData() {
  console.log('\n=== Generating Bitget data (Sharpe 1.2) ===');

  // Date range: 1 year before existing data
  const endDate = new Date('2025-11-26T00:00:00Z');  // Day before real data
  const startDate = new Date('2024-11-27T00:00:00Z');

  // Count all days (crypto trades 24/7)
  const totalDays = Math.floor((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24)) + 1;

  // For Sharpe 1.2 with ~45% annual return (crypto)
  const annualReturn = 0.45;
  const startEquity = BITGET_END_EQUITY / (1 + annualReturn);

  console.log(`  Period: ${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}`);
  console.log(`  Total days: ${totalDays}`);
  console.log(`  Start equity: $${startEquity.toFixed(0)}, End equity: $${BITGET_END_EQUITY}`);

  const returns = generateReturnsPath(totalDays, BITGET_SHARPE, 365, startEquity, BITGET_END_EQUITY);

  const snapshots = [];
  const currentDate = new Date(startDate);
  let equity = startEquity;
  let returnIdx = 0;
  let realizedBalance = startEquity * 1.3;  // Started with more capital

  while (currentDate <= endDate) {
    // Apply daily return
    const dailyRet = returns[returnIdx++] ?? 0;
    equity = equity * (1 + dailyRet);

    const swapEquity = equity * 0.9995;
    const spotEquity = equity * 0.0005;
    const unrealizedPnl = gaussianRandom(-200, 400);

    // No deposits/withdrawals for clean Sharpe calculation
    const deposits = 0;
    const withdrawals = 0;

    // Trading activity (crypto is active)
    const dailyTrades = Math.floor(Math.random() * 6) + 1;
    const dailyVolume = Math.floor(gaussianRandom(2500, 1200));
    const dailyFees = dailyVolume * 0.0006;
    const dailyFunding = gaussianRandom(0.4, 0.25);

    const breakdown = generateBitgetBreakdown(
      equity, swapEquity, spotEquity, unrealizedPnl,
      dailyTrades, dailyVolume, dailyFees, dailyFunding
    );

    snapshots.push({
      id: generateId(),
      userUid: BITGET_USER,
      timestamp: new Date(currentDate),
      exchange: 'bitget',
      totalEquity: equity,
      realizedBalance: realizedBalance,
      unrealizedPnL: unrealizedPnl,
      deposits,
      withdrawals,
      breakdown_by_market: breakdown,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    currentDate.setUTCDate(currentDate.getUTCDate() + 1);
  }

  console.log(`  Generated ${snapshots.length} snapshots`);
  console.log(`  Final equity: $${equity.toFixed(2)}`);

  // Insert in batches
  const batchSize = 50;
  for (let i = 0; i < snapshots.length; i += batchSize) {
    const batch = snapshots.slice(i, i + batchSize);
    await prisma.snapshotData.createMany({ data: batch });
  }
  console.log('  Bitget data inserted!');
}

async function verifySharpeRatios() {
  console.log('\n=== Verifying Sharpe Ratios ===');

  for (const exchange of ['ibkr', 'bitget']) {
    const snapshots = await prisma.snapshotData.findMany({
      where: { exchange },
      orderBy: { timestamp: 'asc' },
      select: { totalEquity: true, timestamp: true }
    });

    if (snapshots.length < 2) continue;

    // Calculate daily returns
    const returns: number[] = [];
    for (let i = 1; i < snapshots.length; i++) {
      const curr = snapshots[i]!;
      const prev = snapshots[i-1]!;
      const ret = (curr.totalEquity - prev.totalEquity) / prev.totalEquity;
      returns.push(ret);
    }

    // Calculate statistics
    const meanReturn = returns.reduce((a, b) => a + b, 0) / returns.length;
    const variance = returns.reduce((sum, r) => sum + Math.pow(r - meanReturn, 2), 0) / returns.length;
    const stdDev = Math.sqrt(variance);

    const annualFactor = exchange === 'ibkr' ? 252 : 365;
    const annualizedReturn = meanReturn * annualFactor;
    const annualizedVol = stdDev * Math.sqrt(annualFactor);
    const sharpe = annualizedReturn / annualizedVol;

    const firstEquity = snapshots[0]!.totalEquity;
    const lastEquity = snapshots[snapshots.length - 1]!.totalEquity;
    const totalReturn = (lastEquity - firstEquity) / firstEquity;

    console.log(`\n${exchange.toUpperCase()}:`);
    console.log(`  Snapshots: ${snapshots.length}`);
    console.log(`  Equity: $${firstEquity.toFixed(0)} → $${lastEquity.toFixed(0)} (${(totalReturn * 100).toFixed(1)}%)`);
    console.log(`  Daily return: ${(meanReturn * 100).toFixed(4)}%`);
    console.log(`  Daily volatility: ${(stdDev * 100).toFixed(3)}%`);
    console.log(`  Annualized return: ${(annualizedReturn * 100).toFixed(1)}%`);
    console.log(`  Annualized volatility: ${(annualizedVol * 100).toFixed(1)}%`);
    console.log(`  SHARPE RATIO: ${sharpe.toFixed(2)}`);
  }
}

async function deleteOldIbkrHistorical() {
  console.log('\n=== Deleting old IBKR historical data ===');
  // Delete only historical data (before 2025-10-30)
  const cutoffDate = new Date('2025-10-30T00:00:00Z');
  const result = await prisma.snapshotData.deleteMany({
    where: {
      exchange: 'ibkr',
      timestamp: { lt: cutoffDate }
    }
  });
  console.log(`  Deleted ${result.count} old IBKR snapshots`);
}

async function main() {
  console.log('========================================');
  console.log('Historical Data Generation with Target Sharpe Ratios');
  console.log('========================================');

  try {
    await deleteOldIbkrHistorical();
    await generateIbkrData();
    // await generateBitgetData();  // Already generated with correct Sharpe
    await verifySharpeRatios();

    console.log('\n=== Final Summary ===');
    const counts = await prisma.snapshotData.groupBy({
      by: ['exchange'],
      _count: { id: true }
    });
    counts.forEach(c => console.log(`${c.exchange}: ${c._count.id} snapshots`));

  } catch (error) {
    console.error('Error:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

main();
