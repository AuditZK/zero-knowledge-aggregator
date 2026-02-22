/**
 * Fix Initial Deposits for Existing Exchange Connections
 *
 * When a user connects a new exchange, the first snapshot should mark
 * the initial equity as a deposit so TWR calculations correctly exclude
 * pre-existing balances from performance returns.
 *
 * Detection logic for multi-label exchanges:
 * - For each user+exchange, find ALL labels sorted by earliest first snapshot
 * - The FIRST label chronologically is the true first connection → FIX
 * - For subsequent labels, check if ANY earlier label is still active
 *   (has snapshots on or after the new label's start date):
 *   - If earlier labels stopped → label migration (renamed) → SKIP
 *   - If earlier labels still active → new sub-account/wallet → FIX
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

async function applyFix(snapshot: SnapshotRow, dryRun: boolean): Promise<void> {
  const depositToAdd = snapshot.totalEquity - snapshot.deposits;
  if (!dryRun) {
    await prisma.snapshotData.update({
      where: { id: snapshot.id },
      data: { deposits: snapshot.deposits + depositToAdd },
    });
  }
}

async function fixInitialDeposits(dryRun: boolean, targetUser?: string) {
  console.log(`\n=== Fix Initial Deposits ${dryRun ? '(DRY RUN)' : '(APPLYING)'} ===\n`);

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
    // Get all labels for this user+exchange
    const allLabels = await prisma.snapshotData.groupBy({
      by: ['label'],
      where: { userUid: group.userUid, exchange: group.exchange },
    });

    // Get first snapshot per label, sorted chronologically
    const labelFirstSnapshots: SnapshotRow[] = [];
    for (const labelGroup of allLabels) {
      const first = await prisma.snapshotData.findFirst({
        where: {
          userUid: group.userUid,
          exchange: group.exchange,
          label: labelGroup.label,
        },
        orderBy: { timestamp: 'asc' },
      }) as SnapshotRow | null;
      if (first) labelFirstSnapshots.push(first);
    }
    labelFirstSnapshots.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    if (labelFirstSnapshots.length === 0) continue;

    // --- Handle the FIRST label (true first connection) ---
    const original = labelFirstSnapshots[0]!;

    if (original.totalEquity <= 0) {
      skipped++;
    } else if (original.deposits >= original.totalEquity) {
      alreadyCorrect++;
    } else {
      const depositToAdd = original.totalEquity - original.deposits;
      console.log(
        `[FIX] ${original.userUid} / ${original.exchange} / ${original.label || '(default)'}` +
        `\n      First snapshot: ${original.timestamp.toISOString().split('T')[0]}` +
        `\n      Equity: ${original.totalEquity.toFixed(2)}` +
        `\n      Current deposits: ${original.deposits.toFixed(2)}` +
        `\n      Adding deposit: +${depositToAdd.toFixed(2)}\n`
      );
      await applyFix(original, dryRun);
      fixed++;
    }

    // --- Handle subsequent labels ---
    for (let i = 1; i < labelFirstSnapshots.length; i++) {
      const current = labelFirstSnapshots[i]!;

      if (current.totalEquity <= 0) { skipped++; continue; }
      if (current.deposits >= current.totalEquity) { alreadyCorrect++; continue; }

      // Check if ANY earlier label is still active when this label started
      // (has snapshots on or after this label's first snapshot date)
      let earlierLabelStillActive = false;
      let activeLabel = '';

      for (let j = 0; j < i; j++) {
        const earlierLabel = labelFirstSnapshots[j]!;
        const laterSnapshot = await prisma.snapshotData.findFirst({
          where: {
            userUid: group.userUid,
            exchange: group.exchange,
            label: earlierLabel.label,
            timestamp: { gte: current.timestamp },
          },
        });
        if (laterSnapshot) {
          earlierLabelStillActive = true;
          activeLabel = earlierLabel.label;
          break;
        }
      }

      if (earlierLabelStillActive) {
        // Earlier label still receiving snapshots → new wallet/sub-account
        const depositToAdd = current.totalEquity - current.deposits;
        console.log(
          `[SUB-ACCOUNT] ${current.userUid} / ${current.exchange} / ${current.label}` +
          `\n      First snapshot: ${current.timestamp.toISOString().split('T')[0]}` +
          `\n      Equity: ${current.totalEquity.toFixed(2)}` +
          `\n      Label "${activeLabel || '(default)'}" still active → new wallet` +
          `\n      Adding deposit: +${depositToAdd.toFixed(2)}\n`
        );
        await applyFix(current, dryRun);
        fixed++;
      } else {
        // All earlier labels stopped → label migration (same account renamed)
        labelMigrations++;
        console.log(
          `[SKIP] ${current.userUid} / ${current.exchange} / ${current.label}` +
          `\n      First snapshot: ${current.timestamp.toISOString().split('T')[0]}` +
          `\n      Equity: ${current.totalEquity.toFixed(2)}` +
          `\n      All earlier labels stopped → label migration, skipping\n`
        );
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
