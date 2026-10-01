from __future__ import annotations

from typing import Any

from .crypto import b64, sha256, sign, unb64, verify
from .store import LEDGER, canonical, now_iso, read_json, validator_paths, write_json


VALIDATOR_IDS = [f"validator-{number}" for number in range(1, 5)]
QUORUM = 3


def _chain(validator_id: str) -> list[dict[str, Any]]:
    return read_json(LEDGER / validator_id / "chain.json", [])


def primary_chain() -> list[dict[str, Any]]:
    chains = [_chain(validator_id) for validator_id in VALIDATOR_IDS]
    return max(chains, key=len, default=[])


def block_core(block: dict[str, Any]) -> dict[str, Any]:
    return {
        "height": block["height"],
        "timestamp": block["timestamp"],
        "previous_hash": block["previous_hash"],
        "event": block["event"],
    }


def append_event(event: dict[str, Any]) -> dict[str, Any]:
    chain = primary_chain()
    core = {
        "height": len(chain) + 1,
        "timestamp": now_iso(),
        "previous_hash": chain[-1]["block_hash"] if chain else "0" * 64,
        "event": event,
    }
    block_hash = sha256(canonical(core))
    certificate = []
    for validator_id in VALIDATOR_IDS:
        paths = validator_paths(validator_id)
        signature = sign(paths["private"], bytes.fromhex(block_hash))
        certificate.append({"validator_id": validator_id, "signature": b64(signature)})
    if len(certificate) < QUORUM:
        raise RuntimeError("Validator quorum unavailable")
    block = {**core, "block_hash": block_hash, "certificate": certificate}
    for validator_id in VALIDATOR_IDS:
        node_chain = _chain(validator_id)
        node_chain.append(block)
        write_json(LEDGER / validator_id / "chain.json", node_chain)
    return block


def verify_block(block: dict[str, Any], previous_hash: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    expected_hash = sha256(canonical(block_core(block)))
    if block.get("block_hash") != expected_hash:
        errors.append("block hash mismatch")
    if block.get("previous_hash") != previous_hash:
        errors.append("previous hash mismatch")
    valid_signers = set()
    for vote in block.get("certificate", []):
        validator_id = vote.get("validator_id")
        if validator_id not in VALIDATOR_IDS or validator_id in valid_signers:
            continue
        try:
            ok = verify(
                validator_paths(validator_id)["public"],
                bytes.fromhex(expected_hash), unb64(vote["signature"]),
            )
        except Exception:
            ok = False
        if ok:
            valid_signers.add(validator_id)
    if len(valid_signers) < QUORUM:
        errors.append(f"validator quorum invalid ({len(valid_signers)}/{QUORUM})")
    return not errors, errors


def verify_chain() -> dict[str, Any]:
    chain = primary_chain()
    previous = "0" * 64
    errors: list[str] = []
    for index, block in enumerate(chain, start=1):
        if block.get("height") != index:
            errors.append(f"block {index}: invalid height")
        valid, block_errors = verify_block(block, previous)
        errors.extend(f"block {index}: {item}" for item in block_errors)
        previous = block.get("block_hash", "")
    node_heads = {}
    for validator_id in VALIDATOR_IDS:
        node_chain = _chain(validator_id)
        node_heads[validator_id] = node_chain[-1]["block_hash"] if node_chain else "genesis"
    if len(set(node_heads.values())) > 1:
        errors.append("validator replicas do not agree on ledger head")
    return {
        "valid": not errors,
        "height": len(chain),
        "quorum": f"{QUORUM}/{len(VALIDATOR_IDS)}",
        "node_heads": node_heads,
        "errors": errors,
    }


def find_by_token(token: str) -> dict[str, Any] | None:
    for block in reversed(primary_chain()):
        if block.get("event", {}).get("watermark_token") == token:
            return block
    return None


def find_by_event(event_id: str) -> dict[str, Any] | None:
    for block in reversed(primary_chain()):
        if block.get("event", {}).get("event_id") == event_id:
            return block
    return None


def find_identity_key(identity_id: str, signing_key_id: str) -> dict[str, Any] | None:
    for block in reversed(primary_chain()):
        event = block.get("event", {})
        if (
            event.get("identity_id") == identity_id
            and event.get("signing_key_id") == signing_key_id
            and event.get("signing_public_key_pem")
        ):
            return block
    return None


def create_checkpoint(target_block: dict[str, Any]) -> dict[str, Any]:
    chain = primary_chain()
    if not chain:
        raise RuntimeError("Cannot checkpoint an empty ledger")
    core = {
        "schema": "aegis.ledger-checkpoint.v1",
        "created_at": now_iso(),
        "ledger_height": len(chain),
        "ledger_head_hash": chain[-1]["block_hash"],
        "target_height": target_block["height"],
        "target_block_hash": target_block["block_hash"],
    }
    checkpoint_hash = sha256(canonical(core))
    certificate = []
    for validator_id in VALIDATOR_IDS:
        signature = sign(validator_paths(validator_id)["private"], bytes.fromhex(checkpoint_hash))
        certificate.append({"validator_id": validator_id, "signature": b64(signature)})
    if len(certificate) < QUORUM:
        raise RuntimeError("Validator quorum unavailable for checkpoint")
    return {**core, "checkpoint_hash": checkpoint_hash, "certificate": certificate}
