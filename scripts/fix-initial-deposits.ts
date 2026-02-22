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
 * - For subsequent labels, compare their first snapshot equity against
 *   the most recent snapshot from other labels just before they started:
 *   - If equity is similar (±30%) and within 3 days → label migration → SKIP
 *   - If equity is very different → new sub-account/wallet → FIX
 *
 * Usage:
 *   npx ts-node scripts/fix-initial-deposits.ts              # dry-run (default)
 *   npx ts-node scripts/fix-initial-deposits.ts --apply       # apply changes
 *   npx ts-node scripts/fix-initial-deposits.ts --user <uid>  # fix specific user
 */

import 'dotenv/config';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const DAY_MS = 1000 * 60 * 60 * 24;
const EQUITY_TOLERANCE = 0.3; // 30% tolerance for migration detection
const TIME_TOLERANCE_DAYS = 3;

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

  // Group by user+exchange (ignoring label)
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
    const original = labelFirstSnapshots[0];

    if (original.totalEquity <= 0) {
      skipped++;
      // Still process subsequent labels (they might be real sub-accounts)
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
      const current = labelFirstSnapshots[i];

      // Skip if equity is 0 or already correct
      if (current.totalEquity <= 0) { skipped++; continue; }
      if (current.deposits >= current.totalEquity) { alreadyCorrect++; continue; }

      // Find the most recent snapshot from ANY OTHER label just before this label started
      const previousSnapshot = await prisma.snapshotData.findFirst({
        where: {
          userUid: group.userUid,
          exchange: group.exchange,
          label: { not: current.label },
          timestamp: { lt: current.timestamp },
        },
        orderBy: { timestamp: 'desc' },
      }) as SnapshotRow | null;

      let isMigration = false;

      if (previousSnapshot && previousSnapshot.totalEquity > 0) {
        const timeDiffDays = (current.timestamp.getTime() - previousSnapshot.timestamp.getTime()) / DAY_MS;
        const equityRatio = current.totalEquity / previousSnapshot.totalEquity;

        // If equity is similar and timestamps are close → label migration
        if (timeDiffDays <= TIME_TOLERANCE_DAYS && equityRatio > (1 - EQUITY_TOLERANCE) && equityRatio < (1 + EQUITY_TOLERANCE)) {
          isMigration = true;
          labelMigrations++;
          console.log(
            `[SKIP] ${current.userUid} / ${current.exchange} / ${current.label}` +
            `\n      First snapshot: ${current.timestamp.toISOString().split('T')[0]}` +
            `\n      Equity: ${current.totalEquity.toFixed(2)}` +
            `\n      Previous label "${previousSnapshot.label || '(default)'}" had ${previousSnapshot.totalEquity.toFixed(2)} (${timeDiffDays.toFixed(1)}d ago)` +
            `\n      → Label migration (equity ratio: ${equityRatio.toFixed(2)}), skipping\n`
          );
        }
      }

      if (!isMigration) {
        const depositToAdd = current.totalEquity - current.deposits;
        console.log(
          `[SUB-ACCOUNT] ${current.userUid} / ${current.exchange} / ${current.label}` +
          `\n      First snapshot: ${current.timestamp.toISOString().split('T')[0]}` +
          `\n      Equity: ${current.totalEquity.toFixed(2)}` +
          (previousSnapshot
            ? `\n      Previous label "${previousSnapshot.label || '(default)'}" had ${previousSnapshot.totalEquity.toFixed(2)}`
            : `\n      No previous label found`) +
          `\n      → New wallet/sub-account` +
          `\n      Adding deposit: +${depositToAdd.toFixed(2)}\n`
        );
        await applyFix(current, dryRun);
        fixed++;
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
