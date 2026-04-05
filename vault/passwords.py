"""
vault/passwords.py — CRUD operations for the passwords sub-collection.

Firestore path:  users/{uid}/passwords/{pid}

Rules enforced here:
  - Every sensitive field is encrypted before any Firestore write.
  - The raw password field is NEVER included in list responses.
  - get_decrypted_password() is the sole path to a plaintext password,
    and it is called only by the /copy API endpoint.
"""

import logging
from typing import Any

from firebase_admin import firestore

from crypto import decrypt, encrypt
from db import get_db

logger = logging.getLogger(__name__)

# Fields that are encrypted at rest.  url and notes are optional.
_ENCRYPTED_FIELDS = ("site_name", "site_url", "username", "password", "notes")

# Maximum lengths — prevents oversized Firestore documents.
_FIELD_MAX: dict[str, int] = {
    "site_name": 200,
    "site_url":  500,
    "username":  200,
    "password":  500,
    "notes":     1000,
}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _col(uid: str):
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


# ── Read ───────────────────────────────────────────────────────────────────────

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
        d = doc.to_dict()
        results.append({
            "id":        doc.id,
            "site_name": decrypt(d["site_name_enc"]),
            "site_url":  decrypt(d["site_url_enc"])  if d.get("site_url_enc")  else "",
            "username":  decrypt(d["username_enc"]),
            "notes":     decrypt(d["notes_enc"])     if d.get("notes_enc")     else "",
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
    """
    doc = _col(uid).document(pid).get()
    if not doc.exists:
        logger.warning("Password copy requested for missing doc pid=%s uid=%s", pid, uid)
        return None
    return decrypt(doc.to_dict()["password_enc"])


# ── Create ─────────────────────────────────────────────────────────────────────

def add_password(uid: str, data: dict[str, Any]) -> str:
    """
    Encrypt all sensitive fields and write a new document.
    Returns the new document ID.
    """
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


# ── Update ─────────────────────────────────────────────────────────────────────

def update_password(uid: str, pid: str, data: dict[str, Any]) -> None:
    """
    Update metadata fields for an existing password entry.
    The stored password is only re-encrypted when a new value is supplied.
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

    _col(uid).document(pid).update(patch)
    logger.info("Password updated: pid=%s uid=%s", pid, uid)


# ── Delete ─────────────────────────────────────────────────────────────────────

def delete_password(uid: str, pid: str) -> None:
    """Permanently delete a single password document."""
    _col(uid).document(pid).delete()
    logger.info("Password deleted: pid=%s uid=%s", pid, uid)
