"""
vault/passwords.py — CRUD operations for the passwords sub-collection.

Firestore path: users/{uid}/passwords/{pid}

All sensitive fields are encrypted before any Firestore write.
The raw password is never included in list responses — it is only accessible
via get_decrypted_password(), called exclusively by the /copy endpoint.
"""

import logging
from typing import Any

from firebase_admin import firestore
from cryptography.fernet import InvalidToken
from google.api_core.exceptions import NotFound

from crypto import decrypt, encrypt
from db import get_db

logger = logging.getLogger(__name__)

_FIELD_MAX: dict[str, int] = {
    "site_name": 200,
    "site_url":  500,
    "username":  200,
    "password":  500,
    "notes":     1000,
}


def _col(uid: str) -> firestore.CollectionReference:
    """Return the passwords CollectionReference for a given user."""
    return (
        get_db()
        .collection("users")
        .document(uid)
        .collection("passwords")
    )


def _safe(value: Any, max_len: int) -> str:
    """Coerce a value to str, strip whitespace, and enforce max_len."""
    return str(value or "").strip()[:max_len]


def _safe_decrypt(payload: dict | None, field_name: str, pid: str) -> str:
    """
    Decrypt a Firestore payload field.
    Returns "" on failure so the frontend receives a clean empty value rather
    than an implementation detail. Logs a warning so data corruption is detectable.
    """
    if not payload:
        return ""
    try:
        return decrypt(payload)
    except (InvalidToken, KeyError, ValueError) as exc:
        logger.warning(
            "Decryption failed for field '%s' on pid=%s: %s",
            field_name, pid, exc,
        )
        return ""


def list_passwords(uid: str) -> list[dict[str, str]]:
    """
    Return all password entries for the user, newest first.
    The raw password field is intentionally omitted from this response.
    """
    docs = (
        _col(uid)
        .order_by("created_at", direction=firestore.Query.DESCENDING)
        .get()
    )
    results: list[dict[str, str]] = []
    for doc in docs:
        d   = doc.to_dict()
        pid = doc.id
        results.append({
            "id":        pid,
            "site_name": _safe_decrypt(d.get("site_name_enc"), "site_name", pid),
            "site_url":  _safe_decrypt(d.get("site_url_enc"),  "site_url",  pid),
            "username":  _safe_decrypt(d.get("username_enc"),  "username",  pid),
            "notes":     _safe_decrypt(d.get("notes_enc"),     "notes",     pid),
            "created_at": (
                d["created_at"].isoformat() if d.get("created_at") else ""
            ),
        })
    return results


def get_decrypted_password(uid: str, pid: str) -> str | None:
    """
    Decrypt and return the raw password for a single entry.
    Only called by the /copy endpoint — never part of a list response.
    Returns None if the document does not exist.
    Raises InvalidToken if the stored ciphertext has been tampered with.
    """
    doc = _col(uid).document(pid).get()
    if not doc.exists:
        logger.warning("Password copy requested for missing doc pid=%s uid=%s", pid, uid)
        return None
    d = doc.to_dict()
    if not d.get("password_enc"):
        logger.warning("Missing password_enc for pid=%s uid=%s", pid, uid)
        return None
    return decrypt(d["password_enc"])


def add_password(uid: str, data: dict[str, Any]) -> str:
    """Encrypt all sensitive fields and write a new document. Returns the new document ID."""
    entry = {
        "site_name_enc": encrypt(_safe(data.get("site_name"), _FIELD_MAX["site_name"])),
        "site_url_enc":  encrypt(_safe(data.get("site_url"),  _FIELD_MAX["site_url"])),
        "username_enc":  encrypt(_safe(data.get("username"),  _FIELD_MAX["username"])),
        "password_enc":  encrypt(_safe(data.get("password"),  _FIELD_MAX["password"])),
        "notes_enc":     encrypt(_safe(data.get("notes"),     _FIELD_MAX["notes"])),
        "created_at":    firestore.SERVER_TIMESTAMP,
    }
    _, ref = _col(uid).add(entry)
    logger.info("Password added: pid=%s uid=%s", ref.id, uid)
    return ref.id


def update_password(uid: str, pid: str, data: dict[str, Any]) -> None:
    """
    Update metadata fields for an existing password entry.
    The stored password is only re-encrypted when a new value is supplied.
    Raises FileNotFoundError if the document does not exist under this uid.
    """
    patch: dict[str, Any] = {
        "site_name_enc": encrypt(_safe(data.get("site_name"), _FIELD_MAX["site_name"])),
        "site_url_enc":  encrypt(_safe(data.get("site_url"),  _FIELD_MAX["site_url"])),
        "username_enc":  encrypt(_safe(data.get("username"),  _FIELD_MAX["username"])),
        "notes_enc":     encrypt(_safe(data.get("notes"),     _FIELD_MAX["notes"])),
        "updated_at":    firestore.SERVER_TIMESTAMP,
    }
    new_password = _safe(data.get("password"), _FIELD_MAX["password"])
    if new_password:
        patch["password_enc"] = encrypt(new_password)

    try:
        _col(uid).document(pid).update(patch)
    except NotFound:
        raise FileNotFoundError(f"Password entry not found: pid={pid} uid={uid}")
    logger.info("Password updated: pid=%s uid=%s", pid, uid)


def delete_password(uid: str, pid: str) -> None:
    """Permanently delete a single password document."""
    _col(uid).document(pid).delete()
    logger.info("Password deleted: pid=%s uid=%s", pid, uid)
