from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


OPENSSL = os.environ.get("OPENSSL_BIN", "openssl")


class CryptoError(RuntimeError):
    pass


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(args: list[str], *, input_data: bytes | None = None, secret: str | None = None) -> bytes:
    child_env = os.environ.copy()
    if secret is not None:
        child_env["AEGIS_KEY_PASSWORD"] = secret
    proc = subprocess.run(
        [OPENSSL, *args], input=input_data, capture_output=True, check=False,
        env=child_env,
    )
    if proc.returncode:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise CryptoError(detail or "OpenSSL operation failed")
    return proc.stdout


def generate_keypair(algorithm: str, private_path: Path, public_path: Path, password: str | None = None) -> None:
    private_path.parent.mkdir(parents=True, exist_ok=True)
    args = ["genpkey", "-algorithm", algorithm]
    if password:
        args += ["-aes-256-cbc", "-pass", "env:AEGIS_KEY_PASSWORD"]
    args += ["-out", str(private_path)]
    _run(args, secret=password)
    public_args = ["pkey", "-in", str(private_path)]
    if password:
        public_args += ["-passin", "env:AEGIS_KEY_PASSWORD"]
    public_args += ["-pubout", "-out", str(public_path)]
    _run(public_args, secret=password)


def reencrypt_private_key(source: Path, destination: Path, old_password: str, new_password: str) -> None:
    child_env = os.environ.copy()
    child_env["AEGIS_OLD_PASSWORD"] = old_password
    child_env["AEGIS_NEW_PASSWORD"] = new_password
    proc = subprocess.run([
        OPENSSL, "pkey", "-in", str(source), "-passin", "env:AEGIS_OLD_PASSWORD",
        "-aes-256-cbc", "-passout", "env:AEGIS_NEW_PASSWORD", "-out", str(destination),
    ], capture_output=True, check=False, env=child_env)
    if proc.returncode:
        destination.unlink(missing_ok=True)
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise CryptoError(detail or "Unable to rotate the private key passphrase")


def kem_encapsulate(public_key: Path) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        ct_path, secret_path = root / "ct", root / "secret"
        _run([
            "pkeyutl", "-encap", "-pubin", "-inkey", str(public_key),
            "-out", str(ct_path), "-secret", str(secret_path),
        ])
        return ct_path.read_bytes(), secret_path.read_bytes()


def kem_decapsulate(private_key: Path, ciphertext: bytes, password: str) -> bytes:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        ct_path, secret_path = root / "ct", root / "secret"
        ct_path.write_bytes(ciphertext)
        _run([
            "pkeyutl", "-decap", "-inkey", str(private_key),
            "-passin", "env:AEGIS_KEY_PASSWORD", "-in", str(ct_path),
            "-secret", str(secret_path),
        ], secret=password)
        return secret_path.read_bytes()


def sign(private_key: Path, message: bytes, password: str | None = None) -> bytes:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        msg_path, sig_path = root / "message", root / "signature"
        msg_path.write_bytes(message)
        args = ["pkeyutl", "-sign", "-rawin", "-inkey", str(private_key)]
        if password:
            args += ["-passin", "env:AEGIS_KEY_PASSWORD"]
        args += ["-in", str(msg_path), "-out", str(sig_path)]
        _run(args, secret=password)
        return sig_path.read_bytes()


def verify(public_key: Path, message: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        msg_path, sig_path = root / "message", root / "signature"
        msg_path.write_bytes(message)
        sig_path.write_bytes(signature)
        proc = subprocess.run([
            OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(public_key), "-in", str(msg_path),
            "-sigfile", str(sig_path),
        ], capture_output=True, check=False)
        return proc.returncode == 0


def verify_pem(public_key_pem: str, message: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as folder:
        public_key = Path(folder) / "public.pem"
        public_key.write_text(public_key_pem, "utf-8")
        return verify(public_key, message, signature)


def derive_kek(shared_secret: bytes, document_id: str, recipient_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=document_id.encode(),
        info=f"aegis-wrap:{recipient_id}".encode(),
    ).derive(shared_secret)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
