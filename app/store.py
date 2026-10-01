from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pymupdf as fitz

from .crypto import generate_keypair, sha256


ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
IDENTITIES = DATA / "identities"
VALIDATORS = DATA / "validators"
PACKAGES = DATA / "packages"
OUTPUTS = DATA / "outputs"
EVIDENCE = DATA / "evidence"
LEDGER = DATA / "ledger"
USERS_FILE = DATA / "users.json"
TRUST_ANCHOR_FILE = DATA / "trust-anchor.json"

DEMO_RECIPIENT_PASSWORDS = {
    "alice": "alice123",
    "bob": "bob123",
    "charlie": "charlie123",
}

DEFAULT_USERS: dict[str, dict[str, Any]] = {
    "admin": {"name": "Aegis Administrator", "department": "Security Office", "role": "administrator", "password_hash": "020f7308df57dc528543fc377c1490ef58901a7e90934461f507086a25903240"},
    "alice": {"name": "Alice Sharma", "department": "Research", "role": "recipient", "password_hash": "c6860d6b5411333a3a894a198bdc030c28756252aa6f2633aeee42d544b8a4c8"},
    "bob": {"name": "Bob Nair", "department": "Operations", "role": "recipient", "password_hash": "e816fae75eb95774f11b42715ad004e9a03f9aad8599e555e62a83b3df63390d"},
    "charlie": {"name": "Charlie Singh", "department": "Legal", "role": "recipient", "password_hash": "9a75849fee38c7b50ec6aa824d9311ac5f4c19e593baae9398e77b53445fbc97"},
    "investigator": {"name": "Forensic Investigator", "department": "Audit Office", "role": "investigator", "password_hash": "2e2f88aab25054021f94f14b657c1580d8728b2ca112237357fb70afcb458fe0"},
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text("utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False), "utf-8")
    os.replace(temp, path)


def _default_registry() -> dict[str, dict[str, Any]]:
    created = "2026-09-30T00:00:00Z"
    return {
        username: {
            "username": username,
            **profile,
            "password_salt": f"aegis:{username}:v1".encode().hex(),
            "password_iterations": 240_000,
            "active": True,
            "must_change_password": False,
            "created_at": created,
            "created_by": "system-bootstrap",
            "enrollment_status": "bootstrap",
        }
        for username, profile in DEFAULT_USERS.items()
    }


def get_users() -> dict[str, dict[str, Any]]:
    users = read_json(USERS_FILE, {})
    return users if isinstance(users, dict) else {}


def save_users(users: dict[str, dict[str, Any]]) -> None:
    write_json(USERS_FILE, users)


def all_people() -> dict[str, dict[str, Any]]:
    hidden = {"password_hash", "password_salt", "password_iterations"}
    return {
        username: {key: value for key, value in profile.items() if key not in hidden}
        for username, profile in get_users().items()
    }


def recipient_registry(active_only: bool = True) -> dict[str, dict[str, Any]]:
    return {
        username: profile
        for username, profile in all_people().items()
        if profile.get("role") == "recipient" and (profile.get("active") or not active_only)
    }


def recipient_paths(recipient_id: str) -> dict[str, Path]:
    root = IDENTITIES / recipient_id
    return {
        "kem_private": root / "kem-private.pem",
        "kem_public": root / "kem-public.pem",
        "sign_private": root / "sign-private.pem",
        "sign_public": root / "sign-public.pem",
    }


def validator_paths(validator_id: str) -> dict[str, Path]:
    root = VALIDATORS / validator_id
    return {"private": root / "private.pem", "public": root / "public.pem"}


def provision() -> None:
    for folder in (IDENTITIES, VALIDATORS, PACKAGES, OUTPUTS, EVIDENCE, LEDGER):
        folder.mkdir(parents=True, exist_ok=True)

    if not USERS_FILE.exists():
        save_users(_default_registry())

    for recipient_id, password in DEMO_RECIPIENT_PASSWORDS.items():
        paths = recipient_paths(recipient_id)
        if not paths["kem_private"].exists():
            generate_keypair("ML-KEM-768", paths["kem_private"], paths["kem_public"], password)
        if not paths["sign_private"].exists():
            generate_keypair("ML-DSA-65", paths["sign_private"], paths["sign_public"], password)

    for number in range(1, 5):
        validator_id = f"validator-{number}"
        paths = validator_paths(validator_id)
        if not paths["private"].exists():
            generate_keypair("ML-DSA-65", paths["private"], paths["public"])
        chain = LEDGER / validator_id / "chain.json"
        if not chain.exists():
            write_json(chain, [])

    anchor = {
        "schema": "aegis.validator-trust-anchor.v1",
        "quorum": 3,
        "validators": {
            f"validator-{number}": {
                "public_key_fingerprint": public_key_fingerprint(validator_paths(f"validator-{number}")["public"]),
                "public_key_pem": validator_paths(f"validator-{number}")["public"].read_text("utf-8"),
            }
            for number in range(1, 5)
        },
    }
    existing_anchor = read_json(TRUST_ANCHOR_FILE)
    if existing_anchor and existing_anchor != anchor:
        raise RuntimeError("Validator keys do not match the pinned offline trust anchor")
    if not existing_anchor:
        write_json(TRUST_ANCHOR_FILE, anchor)

    # Anchor every recipient signing key in the quorum-certified ledger. Existing
    # fingerprints remain verifiable even if registry files are later replaced.
    from . import ledger
    for recipient_id, profile in recipient_registry(active_only=False).items():
        paths = recipient_paths(recipient_id)
        if not paths["sign_public"].exists() or not paths["kem_public"].exists():
            continue
        signing_key_id = public_key_fingerprint(paths["sign_public"])
        if ledger.find_identity_key(recipient_id, signing_key_id):
            continue
        ledger.append_event({
            "schema": "aegis.identity.key-binding.v1",
            "event_id": new_id("evt"),
            "identity_id": recipient_id,
            "identity_name": profile["name"],
            "department": profile.get("department", ""),
            "role": profile["role"],
            "kem_algorithm": "ML-KEM-768 (FIPS 203)",
            "kem_key_id": public_key_fingerprint(paths["kem_public"]),
            "kem_public_key_pem": paths["kem_public"].read_text("utf-8"),
            "signature_algorithm": "ML-DSA-65 (FIPS 204)",
            "signing_key_id": signing_key_id,
            "signing_public_key_pem": paths["sign_public"].read_text("utf-8"),
            "binding_reason": "bootstrap" if profile.get("enrollment_status") == "bootstrap" else "legacy-enrollment-upgrade",
            "bound_at": now_iso(),
        })

    sample = DATA / "sample-confidential.pdf"
    if not sample.exists():
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        page.insert_text((58, 82), "PROJECT AEGIS", fontsize=24, fontname="hebo", color=(0.05, 0.11, 0.18))
        page.insert_text((58, 122), "CONFIDENTIAL RESEARCH BRIEF", fontsize=12, color=(0.1, 0.55, 0.48))
        text = (
            "This document demonstrates broadcast encryption with recipient-specific\n"
            "forensic fingerprinting at the moment of decryption.\n\n"
            "Every authorized recipient sees the same visible content. Each decrypted\n"
            "copy carries a unique non-rendering session marker, bound to an ML-DSA-65\n"
            "signature and a quorum-certified audit record.\n\n"
            "Classification: Restricted  |  Offline demonstration asset"
        )
        page.insert_textbox(fitz.Rect(58, 170, 537, 430), text, fontsize=13, lineheight=1.5, color=(0.15, 0.18, 0.22))
        page.draw_rect(fitz.Rect(48, 52, 547, 790), color=(0.1, 0.55, 0.48), width=1)
        doc.save(sample)
        doc.close()


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def list_packages() -> list[dict[str, Any]]:
    items = [read_json(path) for path in PACKAGES.glob("*.json")]
    return sorted(items, key=lambda item: item.get("created_at", ""), reverse=True)


def list_outputs() -> list[dict[str, Any]]:
    items = [read_json(path) for path in OUTPUTS.glob("*.json")]
    return sorted(items, key=lambda item: item.get("created_at", ""), reverse=True)


def public_key_fingerprint(path: Path) -> str:
    return sha256(path.read_bytes())[:24]
