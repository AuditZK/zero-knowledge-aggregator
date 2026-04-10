#!/usr/bin/env node
/**
 * DEK Migration Script
 *
 * Re-wraps existing DEKs from an OLD master key (derived from old measurement)
 * to the NEW master key (derived from current measurement).
 *
 * Usage:
 *   OLD_MEASUREMENT=<hex> npx ts-node scripts/migrate-dek.ts
 *
 * Required env:
 *   OLD_MEASUREMENT  - Old SEV-SNP measurement (hex string, 96 chars = 48 bytes)
 *   DATABASE_URL     - PostgreSQL connection string
 *
 * Optional env:
 *   OLD_PLATFORM_VERSION - Old platform version (used as HKDF salt, usually empty)
 *
 * This script:
 *   1. Derives OLD master key from OLD_MEASUREMENT
 *   2. Derives NEW master key from current hardware measurement (via snpguest)
 *   3. Fetches all active DEKs from database
 *   4. Unwraps each DEK with OLD master key
 *   5. Re-wraps each DEK with NEW master key
 *   6. Updates database with new wrapped DEKs
 */

import * as crypto from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const HKDF_INFO = 'track-record-enclave-dek';
const KEY_LENGTH = 32;

function deriveMasterKey(measurementHex: string, platformVersion?: string): Buffer {
  const measurementBuffer = Buffer.from(measurementHex, 'hex');
  if (measurementBuffer.length !== 48) {
    throw new Error(`Invalid measurement length: ${measurementBuffer.length}, expected 48 bytes`);
  }

  const salt = platformVersion
    ? Buffer.from(platformVersion, 'utf8')
    : Buffer.alloc(0);

  const masterKey = crypto.hkdfSync(
    'sha256',
    measurementBuffer,
    salt,
    Buffer.from(HKDF_INFO, 'utf8'),
    KEY_LENGTH
  );

  return Buffer.from(masterKey);
}

function getMasterKeyId(masterKey: Buffer): string {
  return crypto.createHash('sha256').update(masterKey).digest('hex').slice(0, 16);
}

function unwrapDEK(
  wrappedDEK: { encryptedDEK: string; iv: string; authTag: string },
  masterKey: Buffer
): Buffer {
  const iv = Buffer.from(wrappedDEK.iv, 'base64');
  const encryptedDEK = Buffer.from(wrappedDEK.encryptedDEK, 'base64');
  const authTag = Buffer.from(wrappedDEK.authTag, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encryptedDEK), decipher.final()]);
}

function wrapDEK(dek: Buffer, masterKey: Buffer): {
  encryptedDEK: string;
  iv: string;
  authTag: string;
  keyVersion: string;
} {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);

  const encryptedDEK = Buffer.concat([cipher.update(dek), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encryptedDEK: encryptedDEK.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    keyVersion: 'v1'
  };
}

async function getCurrentMeasurement(): Promise<string> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'migrate-snp-'));
  const reportPath = path.join(tmpDir, 'report.bin');

  try {
    // Generate attestation report
    execSync(`/usr/bin/snpguest report ${reportPath} --random`, { stdio: 'pipe' });

    // Parse measurement from report (offset 144, 48 bytes)
    const reportBuffer = fs.readFileSync(reportPath);
    const measurement = reportBuffer.subarray(144, 144 + 48).toString('hex').toUpperCase();

    return measurement;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function main() {
  const oldMeasurement = process.env.OLD_MEASUREMENT;
  if (!oldMeasurement) {
    console.error('ERROR: OLD_MEASUREMENT env var required');
    console.error('Usage: OLD_MEASUREMENT=<hex> npx ts-node scripts/migrate-dek.ts');
    process.exit(1);
  }

  const oldPlatformVersion = process.env.OLD_PLATFORM_VERSION || undefined;

  console.log('=== DEK Migration Script ===');
  console.log('Old measurement:', oldMeasurement.slice(0, 16) + '...');

  // Get current measurement
  console.log('\nFetching current hardware measurement...');
  const newMeasurement = await getCurrentMeasurement();
  console.log('New measurement:', newMeasurement.slice(0, 16) + '...');

  if (oldMeasurement.toUpperCase() === newMeasurement.toUpperCase()) {
    console.log('\nMeasurements are identical - no migration needed');
    return;
  }

  // Derive master keys
  const oldMasterKey = deriveMasterKey(oldMeasurement, oldPlatformVersion);
  const newMasterKey = deriveMasterKey(newMeasurement);

  const oldMasterKeyId = getMasterKeyId(oldMasterKey);
  const newMasterKeyId = getMasterKeyId(newMasterKey);

  console.log('\nOld master key ID:', oldMasterKeyId);
  console.log('New master key ID:', newMasterKeyId);

  // Connect to database
  const prisma = new PrismaClient();

  try {
    // Fetch all DEKs
    const deks = await prisma.$queryRaw<Array<{
      id: string;
      encryptedDEK: string;
      iv: string;
      authTag: string;
      keyVersion: string;
      masterKeyId: string;
      isActive: boolean;
    }>>`SELECT id, "encryptedDEK", iv, "authTag", "keyVersion", "masterKeyId", "isActive" FROM data_encryption_keys`;

    console.log(`\nFound ${deks.length} DEK(s) in database`);

    let migrated = 0;
    let skipped = 0;
    let failed = 0;

    for (const dek of deks) {
      console.log(`\nProcessing DEK ${dek.id} (masterKeyId=${dek.masterKeyId}, active=${dek.isActive})`);

      if (dek.masterKeyId === newMasterKeyId) {
        console.log('  Already wrapped with new master key, skipping');
        skipped++;
        continue;
      }

      if (dek.masterKeyId !== oldMasterKeyId) {
        console.log(`  WARNING: DEK master key ID mismatch (expected ${oldMasterKeyId}, got ${dek.masterKeyId})`);
        console.log('  Attempting unwrap anyway...');
      }

      try {
        // Unwrap with old master key
        const unwrappedDEK = unwrapDEK(
          {
            encryptedDEK: dek.encryptedDEK,
            iv: dek.iv,
            authTag: dek.authTag,
          },
          oldMasterKey
        );
        console.log('  DEK unwrapped successfully');

        // Re-wrap with new master key
        const newWrapped = wrapDEK(unwrappedDEK, newMasterKey);
        console.log('  DEK re-wrapped with new master key');

        // Update database
        await prisma.$executeRaw`
          UPDATE data_encryption_keys
          SET "encryptedDEK" = ${newWrapped.encryptedDEK},
              iv = ${newWrapped.iv},
              "authTag" = ${newWrapped.authTag},
              "masterKeyId" = ${newMasterKeyId}
          WHERE id = ${dek.id}
        `;

        console.log('  Database updated');
        migrated++;
      } catch (error) {
        console.error(`  FAILED to migrate DEK ${dek.id}:`, (error as Error).message);
        failed++;
      }
    }

    console.log('\n=== Migration Summary ===');
    console.log(`Migrated: ${migrated}`);
    console.log(`Skipped:  ${skipped}`);
    console.log(`Failed:   ${failed}`);

    if (failed > 0) {
      process.exit(1);
    }
  } finally {
    await prisma.$disconnect();
  }
}

main().catch(error => {
  console.error('Migration failed:', error);
  process.exit(1);
});
