from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

import pymupdf as fitz

from . import ledger
from .crypto import (
    CryptoError, aes_decrypt, aes_encrypt, b64, derive_kek, kem_decapsulate,
    kem_encapsulate, sha256, sign, unb64, verify,
)
from .store import (
    OUTPUTS, PACKAGES, all_people, canonical, new_id, now_iso,
    public_key_fingerprint, read_json, recipient_paths, recipient_registry, write_json,
)
from .watermark import embed, extract


def create_package(filename: str, pdf_bytes: bytes, recipient_ids: list[str]) -> dict[str, Any]:
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        if doc.page_count < 1:
            raise ValueError("PDF has no pages")
        doc.close()
    except Exception as exc:
        raise ValueError("Upload a valid PDF document") from exc
    active_recipients = recipient_registry()
    recipient_ids = list(dict.fromkeys(item for item in recipient_ids if item in active_recipients))
    if not recipient_ids:
        raise ValueError("Select at least one authorized recipient")

    package_id = new_id("pkg")
    document_id = new_id("doc")
    content_key = os.urandom(32)
    content_nonce, ciphertext = aes_encrypt(content_key, pdf_bytes, document_id.encode())
    envelopes: dict[str, Any] = {}
    for recipient_id in recipient_ids:
        paths = recipient_paths(recipient_id)
        kem_ciphertext, shared_secret = kem_encapsulate(paths["kem_public"])
        kek = derive_kek(shared_secret, document_id, recipient_id)
        wrap_nonce, wrapped_key = aes_encrypt(kek, content_key, f"{document_id}:{recipient_id}".encode())
        envelopes[recipient_id] = {
            "kem": "ML-KEM-768",
            "kem_ciphertext": b64(kem_ciphertext),
            "wrap_nonce": b64(wrap_nonce),
            "wrapped_key": b64(wrapped_key),
            "recipient_key_id": public_key_fingerprint(paths["kem_public"]),
        }
    package = {
        "package_id": package_id,
        "document_id": document_id,
        "filename": Path(filename).name or "document.pdf",
        "created_at": now_iso(),
        "content_algorithm": "AES-256-GCM",
        "content_nonce": b64(content_nonce),
        "ciphertext": b64(ciphertext),
        "encrypted_hash": sha256(ciphertext),
        "source_hash": sha256(pdf_bytes),
        "recipients": recipient_ids,
        "envelopes": envelopes,
    }
    write_json(PACKAGES / f"{package_id}.json", package)
    return package


def decrypt_and_fingerprint(package_id: str, recipient_id: str, password: str) -> dict[str, Any]:
    package_path = PACKAGES / f"{package_id}.json"
    package = read_json(package_path)
    if not package:
        raise ValueError("Distribution package does not exist")
    if recipient_id not in package.get("envelopes", {}):
        raise PermissionError("This recipient is not authorized for the document")
    people = all_people()
    if recipient_id not in people or people[recipient_id].get("role") != "recipient" or not people[recipient_id].get("active"):
        raise PermissionError("Unknown or inactive recipient")

    paths = recipient_paths(recipient_id)
    envelope = package["envelopes"][recipient_id]
    try:
        shared_secret = kem_decapsulate(paths["kem_private"], unb64(envelope["kem_ciphertext"]), password)
        kek = derive_kek(shared_secret, package["document_id"], recipient_id)
        content_key = aes_decrypt(
            kek, unb64(envelope["wrap_nonce"]), unb64(envelope["wrapped_key"]),
            f"{package['document_id']}:{recipient_id}".encode(),
        )
        plaintext = aes_decrypt(
            content_key, unb64(package["content_nonce"]), unb64(package["ciphertext"]),
            package["document_id"].encode(),
        )
    except Exception as exc:
        # Keep the public error independent of whether the password or envelope failed.
        raise PermissionError("Credentials are invalid or the package is corrupted") from exc

    token = secrets.token_hex(16)
    fingerprinted = embed(plaintext, token)
    if extract(fingerprinted) != token:
        raise RuntimeError("Watermark self-check failed; document was not released")
    output_id = new_id("out")
    output_name = f"{Path(package['filename']).stem}-{recipient_id}-{output_id[-6:]}.pdf"
    output_path = OUTPUTS / output_name

    event_core = {
        "schema": "aegis.decryption.v1",
        "event_id": new_id("evt"),
        "document_id": package["document_id"],
        "package_id": package_id,
        "encrypted_hash": package["encrypted_hash"],
        "recipient_id": recipient_id,
        "recipient_name": people[recipient_id]["name"],
        "recipient_signing_key_id": public_key_fingerprint(paths["sign_public"]),
        "session_id": new_id("session"),
        "watermark_token": token,
        "output_hash": sha256(fingerprinted),
        "decrypted_at": now_iso(),
        "signature_algorithm": "ML-DSA-65 (FIPS 204)",
    }
    try:
        recipient_signature = sign(paths["sign_private"], canonical(event_core), password)
    except CryptoError as exc:
        output_path.unlink(missing_ok=True)
        raise PermissionError("Unable to sign with the recipient private key") from exc
    event = {**event_core, "recipient_signature": b64(recipient_signature)}
    try:
        block = ledger.append_event(event)
    except Exception:
        raise

    # Plaintext is persisted only after the signed event has a validator quorum.
    # An atomic replace prevents a partially written release from being exposed.
    output_temp = output_path.with_suffix(output_path.suffix + ".pending")
    try:
        output_temp.write_bytes(fingerprinted)
        os.replace(output_temp, output_path)
    finally:
        output_temp.unlink(missing_ok=True)

    metadata = {
        "output_id": output_id,
        "filename": output_name,
        "path": str(output_path),
        "created_at": now_iso(),
        "recipient_id": recipient_id,
        "event_id": event["event_id"],
        "block_height": block["height"],
        "block_hash": block["block_hash"],
        "output_hash": event["output_hash"],
        "watermark_token": token,
    }
    write_json(OUTPUTS / f"{output_id}.json", metadata)
    return {"output": metadata, "event": event, "block": block}


def verify_event(block: dict[str, Any]) -> dict[str, Any]:
    event = block["event"]
    signature = event.get("recipient_signature", "")
    event_core = {key: value for key, value in event.items() if key != "recipient_signature"}
    recipient_id = event.get("recipient_id")
    recipient_ok = False
    people = all_people()
    key_binding = ledger.find_identity_key(recipient_id, event.get("recipient_signing_key_id", ""))
    binding_temporal_valid = bool(key_binding and key_binding.get("height", 0) <= block.get("height", 0))
    if key_binding:
        try:
            from .crypto import verify_pem
            recipient_ok = verify_pem(key_binding["event"]["signing_public_key_pem"], canonical(event_core), unb64(signature))
        except Exception:
            recipient_ok = False
    elif recipient_id in people and people[recipient_id].get("role") == "recipient":
        # Compatibility for records created before ledger-anchored identity keys.
        try:
            recipient_ok = verify(recipient_paths(recipient_id)["sign_public"], canonical(event_core), unb64(signature))
        except Exception:
            recipient_ok = False
    chain_status = ledger.verify_chain()
    block_valid, block_errors = ledger.verify_block(block, block.get("previous_hash", ""))
    return {
        "recipient_signature_valid": recipient_ok,
        "identity_key_anchored": bool(key_binding),
        "identity_binding_temporal_valid": binding_temporal_valid,
        "identity_binding_block": key_binding,
        "block_certificate_valid": block_valid,
        "ledger_valid": chain_status["valid"],
        "block_errors": block_errors,
        "chain_status": chain_status,
    }


def investigate(pdf_bytes: bytes) -> dict[str, Any]:
    try:
        token = extract(pdf_bytes)
    except Exception as exc:
        raise ValueError("The uploaded file is not a readable PDF") from exc
    if not token:
        return {"status": "no_marker", "uploaded_hash": sha256(pdf_bytes)}
    block = ledger.find_by_token(token)
    if not block:
        return {"status": "unknown_marker", "token": token, "uploaded_hash": sha256(pdf_bytes)}
    evidence = verify_event(block)
    uploaded_hash = sha256(pdf_bytes)
    exact_match = uploaded_hash == block["event"]["output_hash"]
    cryptographic_match = exact_match and evidence["recipient_signature_valid"] and evidence["block_certificate_valid"] and evidence["ledger_valid"]
    verified = cryptographic_match and evidence["identity_binding_temporal_valid"]
    return {
        "status": "verified" if verified else ("legacy_binding" if cryptographic_match else "marker_only"),
        "token": token,
        "uploaded_hash": uploaded_hash,
        "exact_hash_match": exact_match,
        "block": block,
        "evidence": evidence,
    }
