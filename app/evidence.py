from __future__ import annotations

from typing import Any

from . import ledger
from .crypto import sha256
from .store import EVIDENCE, TRUST_ANCHOR_FILE, canonical, new_id, now_iso, read_json, write_json


def create_evidence_bundle(result: dict[str, Any], source_filename: str | None) -> dict[str, Any]:
    if result.get("status") != "verified":
        raise ValueError("A portable evidence bundle requires an exact, fully verified copy")
    block = result["block"]
    verification = result["evidence"]
    if not verification.get("identity_binding_temporal_valid"):
        raise ValueError("A portable proof requires the recipient key to be ledger-anchored before decryption")
    anchor = read_json(TRUST_ANCHOR_FILE)
    if not anchor:
        raise RuntimeError("Offline validator trust anchor is unavailable")
    bundle_id = new_id("evidence")
    bundle = {
        "schema": "aegis.forensic-evidence-bundle.v1",
        "bundle_id": bundle_id,
        "generated_at": now_iso(),
        "verification_profile": "exact-digital-copy",
        "investigation": {
            "source_filename": source_filename or "suspect-document.pdf",
            "uploaded_sha256": result["uploaded_hash"],
            "extracted_watermark_token": result["token"],
            "exact_output_hash_match": result["exact_hash_match"],
        },
        "recipient_signature_valid": verification["recipient_signature_valid"],
        "identity_key_anchored": verification["identity_key_anchored"],
        "identity_binding_temporal_valid": verification["identity_binding_temporal_valid"],
        "target_block": block,
        "identity_binding_block": verification.get("identity_binding_block"),
        "ledger_checkpoint": ledger.create_checkpoint(block),
        "trust_anchor_sha256": sha256(canonical(anchor)),
        "algorithms": {
            "key_establishment": "ML-KEM-768 (FIPS 203)",
            "recipient_signature": "ML-DSA-65 (FIPS 204)",
            "validator_signature": "ML-DSA-65 (FIPS 204)",
            "content_encryption": "AES-256-GCM",
            "hash": "SHA-256",
        },
        "claim": "The supplied exact digital copy matches a quorum-certified decryption event signed by the recipient key identified in the event.",
        "limitations": [
            "This proof attributes the signing key and exact digital output; it does not establish human intent.",
            "The current single-host validator deployment demonstrates quorum protocol behavior but not independent physical custody.",
        ],
    }
    write_json(EVIDENCE / f"{bundle_id}.json", bundle)
    return bundle


def load_evidence_bundle(bundle_id: str) -> dict[str, Any] | None:
    if not bundle_id.startswith("evidence_") or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in bundle_id):
        return None
    return read_json(EVIDENCE / f"{bundle_id}.json")
