# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Python, FastAPI, Jinja templates, native CSS, OpenSSL 3.5 post-quantum primitives, PyMuPDF, and local JSON storage.

## Users

- Security administrators distribute sensitive PDF documents to authorized recipients.
- Recipients decrypt documents with their own protected post-quantum private keys.
- Investigators examine leaked copies and verify attribution evidence.
- Technical judges evaluate the complete workflow in a time-limited offline demonstration.

## Product Purpose

Project Aegis distributes one encrypted document to a group while producing a unique forensic copy at each authorized decryption. A leaked copy can be resolved to a signed recipient session and verified against a quorum-certified offline ledger.

## Positioning

Aegis combines decryption-time watermarking, recipient-controlled ML-DSA signatures, and a permissioned offline audit ledger. Attribution evidence is bound to the exact released file rather than to server logs alone.

## Operating Context

The complete demonstration runs on an offline or air-gapped computer. Administrators create distributions, recipients decrypt authorized packages, and investigators upload suspect PDFs. The interface must make role boundaries, cryptographic proof, and ledger integrity understandable within seconds.

## Capabilities and Constraints

- ML-KEM-768 recipient key encapsulation and ML-DSA-65 event signatures.
- AES-256-GCM content encryption.
- Unique invisible PDF marker per recipient session.
- Four locally keyed validator replicas with a 3-of-4 quorum certificate.
- Administrator-controlled local enrollment for trusted recipients and investigators.
- Forced first-sign-in passphrase rotation with recipient private-key re-encryption.
- Ledger-backed enrollment, suspension, and restoration events.
- No cloud KMS, public blockchain, or external service dependency during operation.
- The MVP traces unchanged digital PDF copies. It does not claim screenshot or print-scan survival.
- Validator independence is simulated locally for the MVP; production deployment requires independently administered machines and keys.

## Brand Commitments

The product name is Project Aegis. The voice is factual, calm, precise, and security-conscious. Claims must distinguish verified evidence from investigative leads and must not overstate the MVP's production guarantees.

## Evidence on Hand

- Working end-to-end implementation in `app/`.
- Repeatable test in `tests/smoke.py` covering PQC, unique markers, identical rendering, attribution, quorum, and tamper detection.
- Generated hero photograph in `static/assets/aegis-forensic-document.png`.
- Local sample PDF and signed demonstration records under `data/`.

## Product Principles

- Release plaintext only after fingerprinting and quorum commit.
- Show the evidence behind every attribution result.
- Keep cryptographic operations local and offline.
- Make role boundaries explicit in both access control and interface structure.
- State prototype boundaries clearly.

## Accessibility & Inclusion

Keyboard access, visible focus, WCAG AA contrast, reduced-motion support, descriptive labels, and responsive layouts are required.
