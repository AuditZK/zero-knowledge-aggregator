/**
 * Fix Initial Deposits for Existing Exchange Connections
 *
 * When a user connects a new exchange, the first snapshot should mark
 * the initial equity as a deposit so TWR calculations correctly exclude
 * pre-existing balances from performance returns.
 *
 * IMPORTANT: Only fixes the chronologically FIRST snapshot per user+exchange
 * (across all labels). Label migrations (same exchange, new label name) are
 * NOT touched because the equity already existed under the old label.
 *
 * Usage:
 *   npx ts-node scripts/fix-initial-deposits.ts              # dry-run (default)
 *   npx ts-node scripts/fix-initial-deposits.ts --apply       # apply changes
 *   npx ts-node scripts/fix-initial-deposits.ts --user <uid>  # fix specific user
 */

import 'dotenv/config';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface SnapshotRow {
  id: string;
  userUid: string;
  exchange: string;
  label: string;
  timestamp: Date;
  totalEquity: number;
  deposits: number;
}

async function fixInitialDeposits(dryRun: boolean, targetUser?: string) {
  console.log(`\n=== Fix Initial Deposits ${dryRun ? '(DRY RUN)' : '(APPLYING)'} ===\n`);

  // Step 1: Find all unique user+exchange combinations (ignoring label)
  const exchangeGroups = await prisma.snapshotData.groupBy({
    by: ['userUid', 'exchange'],
    ...(targetUser ? { where: { userUid: targetUser } } : {}),
  });

  console.log(`Found ${exchangeGroups.length} user+exchange combinations\n`);

  let fixed = 0;
  let skipped = 0;
  let alreadyCorrect = 0;
  let labelMigrations = 0;

  for (const group of exchangeGroups) {
    // Step 2: Find the VERY FIRST snapshot for this user+exchange across ALL labels
    const firstSnapshot = await prisma.snapshotData.findFirst({
      where: {
        userUid: group.userUid,
        exchange: group.exchange,
      },
      orderBy: { timestamp: 'asc' },
    }) as SnapshotRow | null;

    if (!firstSnapshot) continue;

    // Skip if equity is 0 (empty account at connection time)
    if (firstSnapshot.totalEquity <= 0) {
      skipped++;
      continue;
    }

    // Skip if deposits already includes the equity (already correct)
    if (firstSnapshot.deposits >= firstSnapshot.totalEquity) {
      alreadyCorrect++;
      continue;
    }

    const depositToAdd = firstSnapshot.totalEquity - firstSnapshot.deposits;

    console.log(
      `[FIX] ${firstSnapshot.userUid} / ${firstSnapshot.exchange} / ${firstSnapshot.label || '(default)'}` +
      `\n      First snapshot: ${firstSnapshot.timestamp.toISOString().split('T')[0]}` +
      `\n      Equity: ${firstSnapshot.totalEquity.toFixed(2)}` +
      `\n      Current deposits: ${firstSnapshot.deposits.toFixed(2)}` +
      `\n      Adding deposit: +${depositToAdd.toFixed(2)}\n`
    );

    if (!dryRun) {
      await prisma.snapshotData.update({
        where: { id: firstSnapshot.id },
        data: {
          deposits: firstSnapshot.deposits + depositToAdd,
        },
      });
    }

    fixed++;

    // Step 3: Check for later labels that might be new sub-accounts
    const allLabels = await prisma.snapshotData.groupBy({
      by: ['label'],
      where: {
        userUid: group.userUid,
        exchange: group.exchange,
      },
    });

    if (allLabels.length > 1) {
      for (const labelGroup of allLabels) {
        if (labelGroup.label === firstSnapshot.label) continue;

        const labelFirst = await prisma.snapshotData.findFirst({
          where: {
            userUid: group.userUid,
            exchange: group.exchange,
            label: labelGroup.label,
          },
          orderBy: { timestamp: 'asc' },
        }) as SnapshotRow | null;

        if (!labelFirst || labelFirst.totalEquity <= 0) continue;

        // Check if old labels were still active when this label started
        // (snapshots exist for other labels AFTER this label's start date)
        const overlappingSnapshots = await prisma.snapshotData.count({
          where: {
            userUid: group.userUid,
            exchange: group.exchange,
            label: { not: labelGroup.label },
            timestamp: { gte: labelFirst.timestamp },
          },
        });

        if (overlappingSnapshots > 0 && labelFirst.deposits < labelFirst.totalEquity) {
          // Other labels still active = likely a new sub-account
          const subDeposit = labelFirst.totalEquity - labelFirst.deposits;
          console.log(
            `[SUB-ACCOUNT] ${labelFirst.userUid} / ${labelFirst.exchange} / ${labelFirst.label}` +
            `\n      First snapshot: ${labelFirst.timestamp.toISOString().split('T')[0]}` +
            `\n      Equity: ${labelFirst.totalEquity.toFixed(2)}` +
            `\n      Other labels still active → likely new wallet` +
            `\n      Adding deposit: +${subDeposit.toFixed(2)}\n`
          );

          if (!dryRun) {
            await prisma.snapshotData.update({
              where: { id: labelFirst.id },
              data: {
                deposits: labelFirst.deposits + subDeposit,
              },
            });
          }

          fixed++;
        } else {
          // No overlapping snapshots = label migration (same account renamed)
          labelMigrations++;
          console.log(
            `[SKIP] ${labelFirst.userUid} / ${labelFirst.exchange} / ${labelFirst.label}` +
            `\n      First snapshot: ${labelFirst.timestamp.toISOString().split('T')[0]}` +
            `\n      Equity: ${labelFirst.totalEquity.toFixed(2)}` +
            `\n      → Label migration (old label stopped), skipping\n`
          );
        }
      }
    }
  }

  console.log('\n=== Summary ===');
  console.log(`Total user+exchange: ${exchangeGroups.length}`);
  console.log(`Fixed:               ${fixed}`);
  console.log(`Already correct:     ${alreadyCorrect}`);
  console.log(`Skipped (0 equity):  ${skipped}`);
  console.log(`Label migrations:    ${labelMigrations} (correctly skipped)`);
  console.log(`Mode:                ${dryRun ? 'DRY RUN (use --apply to commit)' : 'APPLIED'}\n`);
}

async function main() {
  const args = process.argv.slice(2);
  const dryRun = !args.includes('--apply');
  const userIdx = args.indexOf('--user');
  const targetUser = userIdx !== -1 ? args[userIdx + 1] : undefined;

  try {
    await fixInitialDeposits(dryRun, targetUser);
  } catch (error) {
    console.error('Fix failed:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();
