from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any

from fastapi import HTTPException, Request

from .crypto import generate_keypair, reencrypt_private_key
from .store import get_users, now_iso, recipient_paths, save_users


ROLE_LABELS = {"administrator": "Administrator", "recipient": "Recipient", "investigator": "Investigator"}
USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{2,31}$")


def _hash_password(password: str, salt_hex: str, iterations: int = 240_000) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iterations).hex()


def _safe_user(username: str, user: dict[str, Any]) -> dict[str, Any]:
    return {"username": username, "name": user["name"], "department": user.get("department", ""), "role": user["role"], "active": bool(user.get("active")), "must_change_password": bool(user.get("must_change_password"))}


def _password_valid(password: str) -> bool:
    return len(password) >= 10 and any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password)


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    key = username.strip().lower()
    user = get_users().get(key)
    if not user or not user.get("active"):
        return None
    computed = _hash_password(password, user["password_salt"], int(user.get("password_iterations", 240_000)))
    if not hmac.compare_digest(computed, user["password_hash"]):
        return None
    return _safe_user(key, user)


def current_user(request: Request) -> dict[str, Any] | None:
    session_user = request.session.get("user")
    if not isinstance(session_user, dict):
        return None
    username = session_user.get("username")
    source = get_users().get(username)
    if not source or not source.get("active") or source.get("role") != session_user.get("role"):
        request.session.clear()
        return None
    current = _safe_user(username, source)
    request.session["user"] = current
    return current


def require_user(request: Request, roles: set[str] | None = None, allow_password_change: bool = False) -> dict[str, Any]:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    if user.get("must_change_password") and not allow_password_change:
        raise HTTPException(status_code=428, detail="Change the temporary passphrase before continuing")
    if roles and user["role"] not in roles:
        raise HTTPException(status_code=403, detail="Your role cannot perform this action")
    return user


def create_account(name: str, username: str, department: str, role: str, temporary_password: str, created_by: str) -> dict[str, Any]:
    username = username.strip().lower()
    name = " ".join(name.split())
    department = " ".join(department.split())
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must be 3 to 32 characters and use lowercase letters, numbers, dots, hyphens, or underscores")
    if not 2 <= len(name) <= 80:
        raise ValueError("Enter a full name between 2 and 80 characters")
    if not 2 <= len(department) <= 60:
        raise ValueError("Enter a department between 2 and 60 characters")
    if role not in {"recipient", "investigator"}:
        raise ValueError("Select Recipient or Investigator")
    if not _password_valid(temporary_password):
        raise ValueError("Temporary passphrase must have 10 characters with uppercase, lowercase, and a number")
    users = get_users()
    if username in users:
        raise ValueError("That username already exists")

    salt = os.urandom(16).hex()
    created_at = now_iso()
    account = {"username": username, "name": name, "department": department, "role": role, "password_hash": _hash_password(temporary_password, salt), "password_salt": salt, "password_iterations": 240_000, "active": False, "must_change_password": True, "created_at": created_at, "created_by": created_by, "enrollment_status": "pending-ledger-commit"}
    if role == "recipient":
        paths = recipient_paths(username)
        try:
            generate_keypair("ML-KEM-768", paths["kem_private"], paths["kem_public"], temporary_password)
            generate_keypair("ML-DSA-65", paths["sign_private"], paths["sign_public"], temporary_password)
        except Exception:
            for path in paths.values():
                path.unlink(missing_ok=True)
            raise
    users[username] = account
    save_users(users)
    return _safe_user(username, account) | {"created_at": created_at, "created_by": created_by}


def activate_enrollment(username: str) -> None:
    users = get_users()
    users[username]["active"] = True
    users[username]["enrollment_status"] = "committed"
    save_users(users)


def set_account_status(username: str, active: bool, actor: str) -> dict[str, Any]:
    users = get_users()
    account = users.get(username)
    if not account:
        raise ValueError("Trusted identity does not exist")
    if account["role"] == "administrator":
        raise ValueError("The bootstrap administrator cannot be suspended")
    account["active"] = active
    account["status_changed_at"] = now_iso()
    account["status_changed_by"] = actor
    save_users(users)
    return _safe_user(username, account)


def change_password(username: str, current_password: str, new_password: str) -> dict[str, Any]:
    users = get_users()
    account = users.get(username)
    if not account or not account.get("active"):
        raise ValueError("Account is unavailable")
    computed = _hash_password(current_password, account["password_salt"], int(account.get("password_iterations", 240_000)))
    if not hmac.compare_digest(computed, account["password_hash"]):
        raise ValueError("Current passphrase is incorrect")
    if not _password_valid(new_password):
        raise ValueError("New passphrase must have 10 characters with uppercase, lowercase, and a number")
    if current_password == new_password:
        raise ValueError("Choose a new passphrase")

    if account["role"] == "recipient":
        paths = recipient_paths(username)
        kem_temp = paths["kem_private"].with_suffix(".rekey")
        sign_temp = paths["sign_private"].with_suffix(".rekey")
        try:
            reencrypt_private_key(paths["kem_private"], kem_temp, current_password, new_password)
            reencrypt_private_key(paths["sign_private"], sign_temp, current_password, new_password)
            os.replace(kem_temp, paths["kem_private"])
            os.replace(sign_temp, paths["sign_private"])
        finally:
            kem_temp.unlink(missing_ok=True)
            sign_temp.unlink(missing_ok=True)

    salt = os.urandom(16).hex()
    account["password_salt"] = salt
    account["password_hash"] = _hash_password(new_password, salt)
    account["must_change_password"] = False
    account["password_changed_at"] = now_iso()
    save_users(users)
    return _safe_user(username, account)
