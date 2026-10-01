"""End-to-end verification for the Aegis MVP. Run with .venv/bin/python tests/smoke.py."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pymupdf

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import ledger
from app.auth import authenticate
from app.evidence import create_evidence_bundle
from app.service import create_package, decrypt_and_fingerprint, investigate, verify_event
from app.store import DATA, EVIDENCE, TRUST_ANCHOR_FILE, provision


def rendered_hash(pdf: bytes) -> str:
    doc = pymupdf.open(stream=pdf, filetype="pdf")
    digest = hashlib.sha256()
    for page in doc:
        digest.update(page.get_pixmap(matrix=pymupdf.Matrix(1.5, 1.5), alpha=False).samples)
    doc.close()
    return digest.hexdigest()


def main() -> None:
    assert authenticate("admin", "aegis-admin")["role"] == "administrator"
    assert authenticate("alice", "alice123")["role"] == "recipient"
    assert authenticate("investigator", "audit123")["role"] == "investigator"
    assert authenticate("admin", "wrong-password") is None
    provision()
    source = (DATA / "sample-confidential.pdf").read_bytes()
    package = create_package("smoke.pdf", source, ["alice", "bob"])
    alice = decrypt_and_fingerprint(package["package_id"], "alice", "alice123")
    bob = decrypt_and_fingerprint(package["package_id"], "bob", "bob123")
    alice_pdf = Path(alice["output"]["path"]).read_bytes()
    bob_pdf = Path(bob["output"]["path"]).read_bytes()

    assert alice["event"]["watermark_token"] != bob["event"]["watermark_token"]
    assert alice["event"]["output_hash"] != bob["event"]["output_hash"]
    assert rendered_hash(source) == rendered_hash(alice_pdf) == rendered_hash(bob_pdf)

    result = investigate(bob_pdf)
    assert result["status"] == "verified"
    assert result["block"]["event"]["recipient_id"] == "bob"
    assert result["evidence"]["recipient_signature_valid"]
    assert result["evidence"]["block_certificate_valid"]
    assert result["evidence"]["identity_key_anchored"]
    assert result["evidence"]["identity_binding_temporal_valid"]
    assert ledger.verify_chain()["valid"]

    bundle = create_evidence_bundle(result, "smoke-bob.pdf")
    verified = subprocess.run([
        sys.executable, str(Path(__file__).resolve().parent.parent / "tools" / "verify_evidence.py"),
        str(EVIDENCE / f"{bundle['bundle_id']}.json"),
        "--trust-anchor", str(TRUST_ANCHOR_FILE),
        "--suspect", str(bob["output"]["path"]),
    ], capture_output=True, text=True, check=False)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    with tempfile.TemporaryDirectory() as folder:
        tampered_bundle = copy.deepcopy(bundle)
        tampered_bundle["target_block"]["event"]["recipient_name"] = "Mallory"
        tampered_path = Path(folder) / "tampered.json"
        tampered_path.write_text(json.dumps(tampered_bundle), "utf-8")
        rejected = subprocess.run([
            sys.executable, str(Path(__file__).resolve().parent.parent / "tools" / "verify_evidence.py"),
            str(tampered_path), "--trust-anchor", str(TRUST_ANCHOR_FILE),
        ], capture_output=True, text=True, check=False)
        assert rejected.returncode == 1
        assert "hash mismatch" in rejected.stdout

    tampered = copy.deepcopy(result["block"])
    tampered["event"]["recipient_name"] = "Mallory"
    tamper_evidence = verify_event(tampered)
    assert not tamper_evidence["recipient_signature_valid"]
    assert not tamper_evidence["block_certificate_valid"]
    print("PASS: PQC, unique markers, identical rendering, anchored identity, portable proof, quorum and tamper detection")


if __name__ == "__main__":
    main()
