/**
 * Seed Test Data for Report Generation Testing
 *
 * Creates a test user with realistic snapshot data
 *
 * Usage: npx ts-node seed-test-data.ts
 */

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const TEST_USER_UID = 'b26e86aa-d7e0-471a-ad0e-9cf7e5106660';

async function seedTestData() {
  console.log('Seeding test data...\n');

  // 1. Create test user (schema has no email field)
  const user = await prisma.user.upsert({
    where: { uid: TEST_USER_UID },
    update: {},
    create: {
      uid: TEST_USER_UID,
      syncIntervalMinutes: 1440
    }
  });
  console.log('Created user:', user.uid);

  // 2. Generate 365 days of realistic snapshot data
  const startDate = new Date('2024-01-01');
  const snapshots: Array<{
    userUid: string;
    exchange: string;
    timestamp: Date;
    totalEquity: number;
    realizedBalance: number;
    unrealizedPnL: number;
    deposits: number;
    withdrawals: number;
  }> = [];

  let equity = 100000; // Starting equity $100k
  let realizedBalance = 100000;

  for (let i = 0; i < 365; i++) {
    const date = new Date(startDate);
    date.setDate(date.getDate() + i);
    date.setUTCHours(0, 0, 0, 0); // Set to 00:00 UTC

    // Simulate daily returns (realistic: -3% to +3% with slight positive bias)
    const dailyReturn = (Math.random() - 0.48) * 0.03; // Slight positive bias
    equity = equity * (1 + dailyReturn);

    // Daily deposits/withdrawals (most days = 0)
    let dailyDeposit = 0;
    let dailyWithdrawal = 0;

    // Occasionally add deposits/withdrawals
    if (i === 30) {
      dailyDeposit = 10000;
      equity += 10000;
      realizedBalance += 10000;
    }
    if (i === 180) {
      dailyWithdrawal = 5000;
      equity -= 5000;
      realizedBalance -= 5000;
    }

    // Update realized balance (simulating some trades closing)
    if (Math.random() > 0.8) {
      const pnlRealized = equity * (Math.random() - 0.5) * 0.01;
      realizedBalance += pnlRealized;
    }

    const unrealizedPnL = equity - realizedBalance;

    snapshots.push({
      userUid: TEST_USER_UID,
      exchange: 'test_exchange',
      timestamp: date,
      totalEquity: equity,
      realizedBalance: realizedBalance,
      unrealizedPnL: unrealizedPnL,
      deposits: dailyDeposit,
      withdrawals: dailyWithdrawal
    });
  }

  // 3. Insert snapshots (delete existing first)
  const deleted = await prisma.snapshotData.deleteMany({
    where: { userUid: TEST_USER_UID }
  });
  console.log(`Deleted ${deleted.count} existing snapshots`);

  // Insert in batches to avoid issues
  const batchSize = 100;
  let inserted = 0;
  for (let i = 0; i < snapshots.length; i += batchSize) {
    const batch = snapshots.slice(i, i + batchSize);
    await prisma.snapshotData.createMany({
      data: batch,
      skipDuplicates: true
    });
    inserted += batch.length;
  }

  console.log(`Created ${inserted} snapshots`);

  // 4. Summary
  const firstSnapshot = snapshots[0];
  const lastSnapshot = snapshots[snapshots.length - 1];

  if (firstSnapshot && lastSnapshot) {
    console.log('\n=== Test Data Summary ===');
    console.log(`User UID: ${TEST_USER_UID}`);
    console.log(`Period: ${firstSnapshot.timestamp.toISOString().split('T')[0]} -> ${lastSnapshot.timestamp.toISOString().split('T')[0]}`);
    console.log(`Starting Equity: $${firstSnapshot.totalEquity.toFixed(2)}`);
    console.log(`Ending Equity: $${lastSnapshot.totalEquity.toFixed(2)}`);
    console.log(`Total Return: ${(((lastSnapshot.totalEquity - 100000) / 100000) * 100).toFixed(2)}%`);
  }

  console.log('\nTest data seeded successfully!');
  console.log('\nNow run: npx ts-node test-report-generation.ts');
}

seedTestData()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
