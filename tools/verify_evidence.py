#!/usr/bin/env python3
"""Verify an Aegis evidence bundle on an offline machine using OpenSSL 3.5+."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def verify_signature(public_key_pem: str, message: bytes, signature_b64: str) -> bool:
    try:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            key_path, message_path, signature_path = root / "key.pem", root / "message", root / "signature"
            key_path.write_text(public_key_pem, "utf-8")
            message_path.write_bytes(message)
            signature_path.write_bytes(base64.b64decode(signature_b64, validate=True))
            result = subprocess.run([
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(key_path),
                "-in", str(message_path), "-sigfile", str(signature_path),
            ], capture_output=True, check=False)
            return result.returncode == 0
    except (OSError, ValueError):
        return False


def verify_certificate(record_hash: str, certificate: list[dict[str, Any]], anchor: dict[str, Any]) -> tuple[bool, int]:
    valid = set()
    for vote in certificate:
        validator_id = vote.get("validator_id")
        validator = anchor.get("validators", {}).get(validator_id)
        if not validator or validator_id in valid:
            continue
        if digest(validator["public_key_pem"].encode())[:24] != validator["public_key_fingerprint"]:
            continue
        try:
            message = bytes.fromhex(record_hash)
        except ValueError:
            continue
        if verify_signature(validator["public_key_pem"], message, vote.get("signature", "")):
            valid.add(validator_id)
    quorum = int(anchor.get("quorum", 3))
    return len(valid) >= quorum, len(valid)


def verify_block(block: dict[str, Any], anchor: dict[str, Any]) -> list[str]:
    errors = []
    if not all(key in block for key in ("height", "timestamp", "previous_hash", "event")):
        return ["ledger block is missing required fields"]
    core = {key: block[key] for key in ("height", "timestamp", "previous_hash", "event")}
    expected_hash = digest(canonical(core))
    if block.get("block_hash") != expected_hash:
        errors.append(f"block #{block.get('height')}: hash mismatch")
    certificate_ok, signer_count = verify_certificate(expected_hash, block.get("certificate", []), anchor)
    if not certificate_ok:
        errors.append(f"block #{block.get('height')}: validator quorum invalid ({signer_count}/{anchor.get('quorum', 3)})")
    return errors


def verify_bundle(bundle: dict[str, Any], anchor: dict[str, Any], suspect: Path | None) -> list[str]:
    errors = []
    if bundle.get("schema") != "aegis.forensic-evidence-bundle.v1":
        errors.append("unsupported evidence schema")
    if digest(canonical(anchor)) != bundle.get("trust_anchor_sha256"):
        errors.append("bundle does not match the supplied offline trust anchor")

    target = bundle.get("target_block") or {}
    errors.extend(verify_block(target, anchor))
    identity_block = bundle.get("identity_binding_block")
    if not identity_block:
        errors.append("recipient key has no ledger identity binding")
        return errors
    errors.extend(verify_block(identity_block, anchor))

    event = target.get("event", {})
    identity_event = identity_block.get("event", {})
    if identity_event.get("identity_id") != event.get("recipient_id"):
        errors.append("identity binding belongs to a different recipient")
    if identity_block.get("height", 0) > target.get("height", 0):
        errors.append("recipient key was anchored after the claimed decryption event")
    public_key_pem = identity_event.get("signing_public_key_pem", "")
    key_fingerprint = digest(public_key_pem.encode())[:24] if public_key_pem else ""
    if key_fingerprint != event.get("recipient_signing_key_id") or key_fingerprint != identity_event.get("signing_key_id"):
        errors.append("recipient signing-key fingerprint mismatch")
    event_core = {key: value for key, value in event.items() if key != "recipient_signature"}
    if not public_key_pem or not verify_signature(public_key_pem, canonical(event_core), event.get("recipient_signature", "")):
        errors.append("recipient ML-DSA signature is invalid")

    checkpoint = bundle.get("ledger_checkpoint") or {}
    checkpoint_core = {key: checkpoint[key] for key in (
        "schema", "created_at", "ledger_height", "ledger_head_hash", "target_height", "target_block_hash"
    ) if key in checkpoint}
    expected_checkpoint_hash = digest(canonical(checkpoint_core))
    if checkpoint.get("checkpoint_hash") != expected_checkpoint_hash:
        errors.append("ledger checkpoint hash mismatch")
    checkpoint_ok, checkpoint_signers = verify_certificate(expected_checkpoint_hash, checkpoint.get("certificate", []), anchor)
    if not checkpoint_ok:
        errors.append(f"ledger checkpoint quorum invalid ({checkpoint_signers}/{anchor.get('quorum', 3)})")
    if checkpoint.get("target_block_hash") != target.get("block_hash") or checkpoint.get("target_height") != target.get("height"):
        errors.append("checkpoint does not bind the target block")

    investigation = bundle.get("investigation", {})
    if not investigation.get("exact_output_hash_match"):
        errors.append("bundle does not record an exact output-hash match")
    if investigation.get("uploaded_sha256") != event.get("output_hash"):
        errors.append("recorded suspect hash differs from signed output hash")
    if suspect and digest(suspect.read_bytes()) != investigation.get("uploaded_sha256"):
        errors.append("supplied suspect file differs from the investigated file")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Project Aegis forensic evidence bundle offline")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--trust-anchor", required=True, type=Path)
    parser.add_argument("--suspect", type=Path, help="Optional suspect PDF to bind to the proof")
    args = parser.parse_args()
    try:
        bundle = json.loads(args.bundle.read_text("utf-8"))
        anchor = json.loads(args.trust_anchor.read_text("utf-8"))
        errors = verify_bundle(bundle, anchor, args.suspect)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"FAILED: evidence bundle could not be processed: {exc}")
        return 1
    if errors:
        print("FAILED: evidence bundle is not valid")
        for error in errors:
            print(f"- {error}")
        return 1
    event = bundle["target_block"]["event"]
    print("VERIFIED: portable Aegis evidence bundle")
    print(f"Recipient: {event.get('recipient_name')} (@{event.get('recipient_id')})")
    print(f"Document: {event.get('document_id')}")
    print(f"Session: {event.get('session_id')}")
    print(f"Ledger block: #{bundle['target_block']['height']} {bundle['target_block']['block_hash']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
