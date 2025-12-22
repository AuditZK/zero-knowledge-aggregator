# Zero-Knowledge Credential Submission Guide

**Complete manual workflow for maximum-security credential submission to the enclave.**

This guide is for users who want **absolute security** and complete transparency. By following these steps from your own terminal, you can ensure:

1. **AMD SEV-SNP attestation verified** - Cryptographic proof the enclave code matches audited source
2. **TLS certificate bound to attestation** - Prevents VPS from intercepting TLS connection
3. **End-to-End encryption** - Credentials encrypted client-side, even VPS MITM cannot read them
4. **Complete auditability** - Every step visible and verifiable

---

## Architecture: Double Encryption Layer

```
┌─────────────────────────────────────────────────────────────────┐
│  YOUR TERMINAL (Trusted)                                         │
│                                                                  │
│  1. Verify AMD SEV-SNP attestation                               │
│  2. Verify TLS certificate binding                               │
│  3. Encrypt credentials with enclave's E2E public key            │
│  4. Send double-encrypted (E2E + TLS)                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ HTTPS (TLS encryption)
┌─────────────────────────────────────────────────────────────────┐
│  VPS (Untrusted - potential MITM)                                │
│                                                                  │
│  Sees: Encrypted TLS traffic only                                │
│  Cannot: Decrypt TLS (cert verified via attestation)             │
│  Cannot: Decrypt E2E (no private key)                            │
│                                                                  │
│  └─ Even if VPS breaks TLS → E2E encryption still protects      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ TCP routing only
┌─────────────────────────────────────────────────────────────────┐
│  ENCLAVE (AMD SEV-SNP - Trusted)                                 │
│                                                                  │
│  1. TLS terminates HERE (private key in enclave RAM only)        │
│  2. E2E decrypts with enclave's private ECDH key                 │
│  3. Credentials visible ONLY in enclave RAM                      │
│                                                                  │
│  VPS never sees plaintext credentials                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- `curl` (HTTP client)
- `openssl` (TLS/certificate tools)
- `node` or `python` (for E2E encryption)
- `jq` (JSON parser, optional but recommended)
- Linux, macOS, or WSL on Windows

---

## Method 1: Maximum Security (E2E + TLS + Attestation)

### Step 1: Clone the enclave repository

```bash
git clone https://github.com/AuditZK/zero-knowledge-aggregator.git
cd zero-knowledge-aggregator
```

### Step 2: Verify AMD SEV-SNP attestation

```bash
# Fetch attestation report
curl -k https://<YOUR_ENCLAVE_IP>:3050/api/v1/attestation | jq . > attestation.json

# Inspect attestation
cat attestation.json
```

**Verify these critical fields:**

```bash
# 1. AMD signature verified
jq -r '.attestation.vcekVerified' attestation.json
# Must be: true

# 2. Measurement (code hash)
jq -r '.attestation.measurement' attestation.json
# Compare with public build measurement (see README.md)

# 3. TLS certificate binding
jq -r '.attestation.reportData' attestation.json
# This should match SHA-256 of the TLS certificate (verify in Step 3)

# 4. E2E public key present
jq -r '.e2eEncryption.publicKey' attestation.json > enclave_e2e_public.pem
```

### Step 3: Verify TLS certificate binding

```bash
# Extract TLS certificate during handshake
echo | openssl s_client -connect <YOUR_ENCLAVE_IP>:3050 -showcerts 2>/dev/null | \
  openssl x509 -outform PEM > tls_cert.pem

# Calculate SHA-256 of certificate
CERT_HASH=$(openssl x509 -in tls_cert.pem -noout -fingerprint -sha256 | \
  sed 's/SHA256 Fingerprint=//' | sed 's/://g' | tr '[:upper:]' '[:lower:]')

# Compare with attestation reportData
REPORT_DATA=$(jq -r '.attestation.reportData' attestation.json)

if [ "$CERT_HASH" == "$REPORT_DATA" ]; then
  echo "✅ TLS VERIFIED: Certificate matches attestation"
  echo "✅ VPS cannot MITM the TLS connection"
else
  echo "❌ MITM DETECTED: Certificate does NOT match attestation!"
  echo "❌ DO NOT PROCEED"
  exit 1
fi
```

### Step 4: Encrypt credentials with E2E encryption

```bash
# Use the provided Node.js helper script
node client-encrypt-helper.js \
  YOUR_SERVICE_UID \
  binance \
  YOUR_API_KEY \
  YOUR_API_SECRET

# This outputs the encrypted JSON payload
```

**What this does:**
1. Fetches enclave's E2E public key from attestation
2. Generates ephemeral ECDH key pair
3. Performs ECDH key agreement
4. Encrypts credentials with AES-256-GCM
5. Outputs ready-to-send JSON

### Step 5: Send encrypted credentials

```bash
# Copy the JSON output from step 4 and send it
curl -X POST https://<YOUR_ENCLAVE_IP>:3050/api/v1/credentials/connect \
  -H "Content-Type: application/json" \
  -d '{
    "user_uid": "YOUR_SERVICE_UID",
    "exchange": "binance",
    "encrypted": {
      "ephemeralPublicKey": "-----BEGIN PUBLIC KEY-----...",
      "iv": "hex...",
      "ciphertext": "hex...",
      "tag": "hex..."
    }
  }' \
  -k
```

**Security guarantees at this point:**
- ✅ AMD SEV-SNP verified (genuine enclave)
- ✅ TLS certificate verified (no TLS MITM)
- ✅ Credentials encrypted E2E (even if TLS broken, credentials safe)
- ✅ VPS sees only: `{"encrypted": {"ciphertext": "unreadable hex"}}`

---

## Method 2: TLS-Only (Simpler, requires attestation verification)

If you trust the TLS layer and have verified attestation:

```bash
# 1. Verify attestation (Steps 1-3 from Method 1)

# 2. Send credentials in plaintext (protected by TLS)
curl -X POST https://<YOUR_ENCLAVE_IP>:3050/api/v1/credentials/connect \
  -H "Content-Type: application/json" \
  -d '{
    "user_uid": "YOUR_SERVICE_UID",
    "exchange": "binance",
    "api_key": "YOUR_API_KEY",
    "api_secret": "YOUR_API_SECRET"
  }' \
  -k
```

**Important:** This method is secure ONLY if:
- ✅ You verified AMD SEV-SNP attestation
- ✅ You verified TLS certificate binding
- ✅ The VPS does NOT perform kernel-level TLS interception

**Recommended:** Use Method 1 (E2E encryption) for maximum security.

---

## Supported Exchanges

### Brokers
- `alpaca` - Alpaca Markets (API Key + API Secret)
- `ibkr` - Interactive Brokers (Flex Token + Flex Query ID)

### Crypto Exchanges
- `binance` - Binance (API Key + API Secret)
- `bitget` - Bitget (API Key + API Secret + Passphrase)
- `mexc` - MEXC (API Key + API Secret)
- `coinbase` - Coinbase (API Key + API Secret)

---

## Security Model Comparison

| Security Layer | Method 1 (E2E + TLS) | Method 2 (TLS Only) | Frontend/Scripts |
|----------------|----------------------|---------------------|------------------|
| **AMD SEV-SNP attestation** | ✅ Verified | ✅ Verified | ❌ Not verified |
| **TLS cert binding** | ✅ Verified | ✅ Verified | ❌ Not verified |
| **E2E encryption** | ✅ Encrypted | ❌ Plaintext | ❌ Plaintext |
| **VPS MITM TLS** | ✅ Protected | ⚠️ Vulnerable | ⚠️ Vulnerable |
| **VPS reads credentials** | ❌ Impossible | ⚠️ Possible | ⚠️ Possible |

**Recommendation:**
- **Maximum security users:** Method 1 (E2E + TLS + Attestation)
- **Technical users:** Method 2 (TLS + Attestation verification)
- **Casual users:** Frontend (relies on TLS, no attestation check)

---

## E2E Encryption Technical Details

**Algorithm:** ECIES (Elliptic Curve Integrated Encryption Scheme)

**Steps:**
1. Client fetches enclave's ECDH P-256 public key
2. Client generates ephemeral ECDH P-256 key pair
3. Client performs ECDH → shared secret
4. Client derives AES-256 key via HKDF-SHA256
5. Client encrypts credentials with AES-256-GCM
6. Client sends: `{ephemeralPublicKey, iv, ciphertext, tag}`
7. Enclave performs ECDH with ephemeral public key → same shared secret
8. Enclave derives same AES-256 key
9. Enclave decrypts credentials

**Key property:** Enclave's private ECDH key never leaves enclave RAM.

---

## Python E2E Encryption Example

If you prefer Python over Node.js:

```python
#!/usr/bin/env python3
import requests
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

ENCLAVE_URL = "https://<YOUR_ENCLAVE_IP>:3050"

# 1. Fetch attestation
resp = requests.get(f"{ENCLAVE_URL}/api/v1/attestation", verify=False)
attestation = resp.json()
public_key_pem = attestation['e2eEncryption']['publicKey']

# 2. Load enclave's public key
from cryptography.hazmat.backends import default_backend
enclave_public_key = serialization.load_pem_public_key(
    public_key_pem.encode(), backend=default_backend()
)

# 3. Generate ephemeral key pair
ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
ephemeral_public_key = ephemeral_private_key.public_key()

# 4. Perform ECDH
shared_secret = ephemeral_private_key.exchange(ec.ECDH(), enclave_public_key)

# 5. Derive AES key
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'enclave-e2e-encryption'
).derive(shared_secret)

# 6. Encrypt credentials
credentials = json.dumps({
    "api_key": "YOUR_API_KEY",
    "api_secret": "YOUR_API_SECRET"
})

iv = os.urandom(12)
aesgcm = AESGCM(aes_key)
ciphertext = aesgcm.encrypt(iv, credentials.encode(), None)

# 7. Prepare payload
ephemeral_public_pem = ephemeral_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

payload = {
    "user_uid": "YOUR_SERVICE_UID",
    "exchange": "binance",
    "encrypted": {
        "ephemeralPublicKey": ephemeral_public_pem,
        "iv": iv.hex(),
        "ciphertext": ciphertext[:-16].hex(),  # ciphertext without tag
        "tag": ciphertext[-16:].hex()          # last 16 bytes = tag
    }
}

# 8. Send to enclave
resp = requests.post(
    f"{ENCLAVE_URL}/api/v1/credentials/connect",
    json=payload,
    verify=False
)
print(resp.json())
```

---

## Troubleshooting

### Attestation verification fails

```bash
# Check if enclave is reachable
curl -k https://<YOUR_ENCLAVE_IP>:3050/health
```

### TLS certificate mismatch

**Cause:** Enclave was restarted (new TLS certificate generated)

**Solution:** Re-fetch attestation and verify again

### E2E decryption fails on enclave

**Cause:**
- Incorrect ephemeral public key format
- Corrupted ciphertext
- Wrong AES-GCM tag

**Solution:** Verify encryption code matches the format in `client-encrypt-helper.js`

---

## References

- [AMD SEV-SNP Whitepaper](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
- [ECIES Specification](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)
- [Track Record Security Overview](/tee-security)
- [Enclave Source Code](https://github.com/AuditZK/zero-knowledge-aggregator)

---

**Last Updated**: 2024-12-21
**Enclave Version**: 3.0.0
**Security Model**: Double encryption (TLS + E2E) with AMD SEV-SNP attestation
