#!/usr/bin/env node
/**
 * Simple DEK Migration Script (no Prisma dependency)
 *
 * Re-wraps DEKs from OLD master key to NEW master key after SEV-SNP measurement change.
 *
 * Usage:
 *   OLD_MEASUREMENT=<hex> NEW_MEASUREMENT=<hex> DATABASE_URL=<url> node scripts/migrate-dek-simple.js [--dry-run]
 *
 * Env:
 *   OLD_MEASUREMENT - Old SEV-SNP measurement (hex, 96 chars)
 *   NEW_MEASUREMENT - New SEV-SNP measurement (hex, 96 chars)
 *   DATABASE_URL    - PostgreSQL connection string
 *   --dry-run       - Test unwrap/rewrap without writing to DB
 */

const crypto = require('node:crypto');
const { Client } = require('pg');

const HKDF_INFO = 'track-record-enclave-dek';
const KEY_LENGTH = 32;

function deriveMasterKey(measurementHex, platformVersion) {
  const measurementBuffer = Buffer.from(measurementHex, 'hex');
  if (measurementBuffer.length !== 48) {
    throw new Error(`Invalid measurement length: ${measurementBuffer.length} bytes (expected 48)`);
  }
  const salt = platformVersion ? Buffer.from(platformVersion, 'utf8') : Buffer.alloc(0);
  return Buffer.from(crypto.hkdfSync('sha256', measurementBuffer, salt, Buffer.from(HKDF_INFO, 'utf8'), KEY_LENGTH));
}

function getMasterKeyId(masterKey) {
  return crypto.createHash('sha256').update(masterKey).digest('hex').slice(0, 16);
}

function unwrapDEK(wrapped, masterKey) {
  const iv = Buffer.from(wrapped.iv, 'base64');
  const encryptedDEK = Buffer.from(wrapped.encryptedDEK, 'base64');
  const authTag = Buffer.from(wrapped.authTag, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encryptedDEK), decipher.final()]);
}

function wrapDEK(dek, masterKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  const encryptedDEK = Buffer.concat([cipher.update(dek), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    encryptedDEK: encryptedDEK.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

async function main() {
  const OLD = process.env.OLD_MEASUREMENT;
  const NEW = process.env.NEW_MEASUREMENT;
  const DB = process.env.DATABASE_URL;
  const dryRun = process.argv.includes('--dry-run');

  if (!OLD || !NEW || !DB) {
    console.error('Required: OLD_MEASUREMENT, NEW_MEASUREMENT, DATABASE_URL');
    process.exit(1);
  }

  console.log('=== DEK Migration Script ===');
  console.log(`Mode: ${dryRun ? 'DRY-RUN (no DB writes)' : 'LIVE'}`);
  console.log(`Old measurement: ${OLD.slice(0, 16)}...`);
  console.log(`New measurement: ${NEW.slice(0, 16)}...`);

  const oldMasterKey = deriveMasterKey(OLD);
  const newMasterKey = deriveMasterKey(NEW);
  const oldMasterKeyId = getMasterKeyId(oldMasterKey);
  const newMasterKeyId = getMasterKeyId(newMasterKey);

  console.log(`Old masterKeyId: ${oldMasterKeyId}`);
  console.log(`New masterKeyId: ${newMasterKeyId}\n`);

  const client = new Client({ connectionString: DB });
  await client.connect();

  try {
    const { rows } = await client.query(
      'SELECT id, "encryptedDEK", iv, "authTag", "keyVersion", "masterKeyId", "isActive" FROM data_encryption_keys'
    );

    console.log(`Found ${rows.length} DEK(s)\n`);

    let migrated = 0, skipped = 0, failed = 0;

    for (const dek of rows) {
      console.log(`DEK ${dek.id} (masterKeyId=${dek.masterKeyId}, active=${dek.isActive})`);

      if (dek.masterKeyId === newMasterKeyId) {
        console.log('  -> already migrated, skip');
        skipped++;
        continue;
      }

      if (dek.masterKeyId !== oldMasterKeyId) {
        console.log(`  -> masterKeyId mismatch (expected ${oldMasterKeyId})`);
        failed++;
        continue;
      }

      try {
        const unwrapped = unwrapDEK(
          { encryptedDEK: dek.encryptedDEK, iv: dek.iv, authTag: dek.authTag },
          oldMasterKey
        );
        console.log(`  -> unwrapped OK (${unwrapped.length} bytes)`);

        const rewrapped = wrapDEK(unwrapped, newMasterKey);
        console.log('  -> re-wrapped OK');

        // Verify round-trip
        const verifyUnwrap = unwrapDEK(rewrapped, newMasterKey);
        if (!verifyUnwrap.equals(unwrapped)) {
          throw new Error('Round-trip verification failed');
        }
        console.log('  -> round-trip verified');

        if (!dryRun) {
          await client.query(
            `UPDATE data_encryption_keys
             SET "encryptedDEK" = $1, iv = $2, "authTag" = $3, "masterKeyId" = $4, "updatedAt" = NOW()
             WHERE id = $5`,
            [rewrapped.encryptedDEK, rewrapped.iv, rewrapped.authTag, newMasterKeyId, dek.id]
          );
          console.log('  -> DB updated');
        } else {
          console.log('  -> DB update SKIPPED (dry-run)');
        }

        migrated++;
      } catch (err) {
        console.error(`  -> FAILED: ${err.message}`);
        failed++;
      }
    }

    console.log('\n=== Summary ===');
    console.log(`Migrated: ${migrated}`);
    console.log(`Skipped:  ${skipped}`);
    console.log(`Failed:   ${failed}`);

    if (failed > 0) process.exit(1);
  } finally {
    await client.end();
  }
}

main().catch(e => { console.error(e); process.exit(1); });
