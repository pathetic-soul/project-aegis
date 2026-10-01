# Project Aegis

Project Aegis is an offline MVP for broadcast-encrypted PDF distribution with recipient-specific forensic attribution. A document is encrypted once with AES-256-GCM; the same content key is wrapped for each recipient using NIST ML-KEM-768. On decryption, Aegis embeds a unique invisible PDF marker, has the recipient sign the complete event with ML-DSA-65, and commits it to a four-validator quorum-signed hash chain before releasing the PDF.

## Run the demo

Requirements: Linux, Python 3.11+, and OpenSSL 3.5+ with ML-KEM and ML-DSA enabled.

```bash
chmod +x run.sh
./run.sh
```

Open <http://127.0.0.1:8000>. The first launch provisions encrypted recipient key files and four validator identities. Once dependencies are installed, the application performs its entire workflow without network access.

Role-based demonstration accounts:

| Role | Username | Passphrase | Permission |
|---|---|---|---|
| Administrator | `admin` | `aegis-admin` | Create distributions and inspect the ledger |
| Recipient | `alice` | `alice123` | Decrypt and sign as Alice Sharma |
| Recipient | `bob` | `bob123` | Decrypt and sign as Bob Nair |
| Recipient | `charlie` | `charlie123` | Decrypt and sign as Charlie Singh |
| Investigator | `investigator` | `audit123` | Investigate leaked copies and verify the ledger |

The login uses a local identity registry, PBKDF2 password hashes, and a signed, four-hour session cookie. Route-level role checks prevent recipients from distributing files or opening the audit ledger, and prevent administrators from invoking a recipient private key.

Administrators can add trusted recipients and investigators from the workspace. Recipient enrollment generates encrypted ML-KEM-768 and ML-DSA-65 private keys on the local machine, writes their public-key fingerprints into a quorum-certified identity event, and activates the account only after that ledger commit succeeds. Every new user must replace the temporary passphrase on first sign in. For recipients, rotation re-encrypts both private keys so the user's login and key passphrase remain aligned. Administrators can suspend or restore identities, with every status change recorded on the same ledger.

## 90-second demo

1. Sign in as `admin` and enroll a trusted recipient with a temporary passphrase.
2. Sign in as that recipient and replace the temporary passphrase to claim the identity.
3. Return as `admin`, download the sample PDF, and distribute it to the new recipient.
4. Sign in as the recipient, decrypt the package, and download the fingerprinted copy.
5. Sign in as `investigator` and upload the released copy under **Forensic verification**.
6. Show the verified identity, session, output hash, recipient signature, and validator certificate.
7. Open **Audit ledger** to show enrollment, account status, decryption, and four validator acknowledgements.

After a successful exact-copy investigation, download both the human-readable PDF and the portable JSON proof bundle. Retain the validator trust anchor separately, then verify the bundle on another offline machine:

```bash
python3 tools/verify_evidence.py aegis-evidence_....json \
  --trust-anchor aegis-offline-trust-anchor.json \
  --suspect leaked-copy.pdf
```

The verifier checks the suspect hash, recipient ML-DSA signature, ledger-anchored recipient key, target block certificate, and a fresh quorum-signed ledger checkpoint. The trust anchor must be obtained and retained before an incident; accepting an anchor supplied alongside untrusted evidence would not establish validator identity.

## Verification

```bash
.venv/bin/python tests/smoke.py
```

The smoke test checks real ML-KEM/ML-DSA operations, unique markers across recipients, pixel-identical rendering, exact-copy attribution, recipient signatures, quorum certificates, chain integrity and tamper detection.

## Architecture

```text
Sender PDF
   │  random content key + AES-256-GCM (encrypt once)
   ├── ML-KEM-768 envelope → Alice
   ├── ML-KEM-768 envelope → Bob
   └── ML-KEM-768 envelope → Charlie

Recipient decrypts locally
   │
   ├── unique 128-bit invisible PDF marker
   ├── output SHA-256 + document/package/session identifiers
   └── recipient ML-DSA-65 signature
              │
              ▼
     4 validator identities sign block hash
     3-of-4 quorum required before PDF release
              │
              ▼
 Leak PDF → marker extraction → ledger lookup → full evidence verification
```

All identities, key material, packages, output PDFs, and ledger replicas live under `data/`. Recipient private keys are encrypted at rest with their current passphrases. No public blockchain, cloud KMS, cloud identity provider, or external service is used.

## Honest MVP boundaries

- The current invisible PDF text marker traces an unchanged digital copy. PDF sanitization, screenshots and print/scan can destroy it. A production version should use redundant content-adaptive image and text perturbations with error-correcting codes.
- Four validators are implemented as separately keyed ledger replicas on one computer. Real protection from one administrator requires those validator processes and private keys to be placed on independently administered air-gapped machines, with authenticated peer transport and production BFT consensus.
- Existing records created before the identity-key anchoring upgrade remain cryptographically checkable but cannot produce a fully trusted portable bundle. New decryptions bind the recipient key to an earlier quorum-certified identity block.
- The evidence proves that a recipient key authorized a specific decryption session and that the investigated file exactly matches its signed output. It does not by itself prove who intentionally disclosed the file.
- The controlled application must prevent access to plaintext before fingerprinting. A production deployment needs hardened endpoints, device-bound keys and process isolation.

# project-aegis
