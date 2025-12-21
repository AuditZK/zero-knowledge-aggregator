#!/usr/bin/env node
/**
 * Client-side E2E Encryption Helper
 *
 * This script encrypts credentials client-side using the enclave's public key.
 * The encrypted credentials can then be safely sent via HTTPS to the enclave.
 *
 * Even if the VPS performs a MITM attack on TLS, the encrypted credentials
 * remain unreadable without the enclave's private key.
 *
 * Usage:
 *   node client-encrypt-helper.js <user_uid> <exchange> <api_key> <api_secret> [passphrase]
 *
 * Example:
 *   node client-encrypt-helper.js user_abc123 binance mykey mysecret
 */

const crypto = require('crypto');
const https = require('https');

const ENCLAVE_URL = process.env.ENCLAVE_URL || 'https://136.119.67.234:3050';

/**
 * Fetch attestation and extract E2E public key
 */
async function getEnclavePublicKey() {
  return new Promise((resolve, reject) => {
    https.get(`${ENCLAVE_URL}/api/v1/attestation`, {
      rejectUnauthorized: false // Accept self-signed cert (verify attestation separately)
    }, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const attestation = JSON.parse(data);

          console.error('✅ Attestation retrieved');
          console.error('   SEV-SNP verified:', attestation.attestation.vcekVerified);
          console.error('   Measurement:', attestation.attestation.measurement?.slice(0, 16) + '...');
          console.error('   E2E algorithm:', attestation.e2eEncryption.algorithm);

          resolve(attestation.e2eEncryption.publicKey);
        } catch (error) {
          reject(new Error('Failed to parse attestation: ' + error.message));
        }
      });
    }).on('error', reject);
  });
}

/**
 * Encrypt credentials using ECIES (ECDH + AES-256-GCM)
 */
function encryptCredentials(publicKeyPem, credentials) {
  // 1. Generate ephemeral key pair
  const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } =
    crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

  // 2. Perform ECDH with enclave's public key
  const enclavePublicKey = crypto.createPublicKey(publicKeyPem);
  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(ephemeralPrivateKey),
    publicKey: enclavePublicKey
  });

  // 3. Derive AES key from shared secret using HKDF
  const aesKey = crypto.hkdfSync(
    'sha256',
    sharedSecret,
    Buffer.alloc(0), // no salt
    Buffer.from('enclave-e2e-encryption'), // info
    32 // 256 bits for AES-256
  );

  // 4. Encrypt credentials with AES-256-GCM
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

  const credentialsJson = JSON.stringify(credentials);
  let ciphertext = cipher.update(credentialsJson, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const tag = cipher.getAuthTag();

  return {
    ephemeralPublicKey: ephemeralPublicKey,
    iv: iv.toString('hex'),
    ciphertext,
    tag: tag.toString('hex')
  };
}

/**
 * Main function
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length < 4) {
    console.error('Usage: node client-encrypt-helper.js <user_uid> <exchange> <api_key> <api_secret> [passphrase]');
    console.error('');
    console.error('Example:');
    console.error('  node client-encrypt-helper.js user_abc123 binance mykey mysecret');
    console.error('  node client-encrypt-helper.js user_abc123 bitget mykey mysecret mypassphrase');
    process.exit(1);
  }

  const [userUid, exchange, apiKey, apiSecret, passphrase] = args;

  console.error('🔒 E2E Encryption Helper');
  console.error('========================');
  console.error('');
  console.error('Fetching enclave public key...');

  try {
    // Get enclave's E2E public key
    const publicKey = await getEnclavePublicKey();

    // Prepare credentials
    const credentials = {
      api_key: apiKey,
      api_secret: apiSecret
    };

    if (passphrase) {
      credentials.passphrase = passphrase;
    }

    console.error('');
    console.error('Encrypting credentials...');

    // Encrypt credentials
    const encrypted = encryptCredentials(publicKey, credentials);

    console.error('✅ Credentials encrypted successfully');
    console.error('');
    console.error('Send this JSON payload via POST to', ENCLAVE_URL + '/api/v1/credentials/connect:');
    console.error('');

    // Output the encrypted payload (this is what the user sends)
    const payload = {
      user_uid: userUid,
      exchange: exchange,
      encrypted: encrypted
    };

    console.log(JSON.stringify(payload, null, 2));

    console.error('');
    console.error('Example curl command:');
    console.error('');
    console.error(`curl -X POST ${ENCLAVE_URL}/api/v1/credentials/connect \\`);
    console.error(`  -H "Content-Type: application/json" \\`);
    console.error(`  -d '${JSON.stringify(payload)}' \\`);
    console.error(`  -k`);

  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

main();
