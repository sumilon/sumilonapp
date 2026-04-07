"""
vault/auth.py — User registration, login, and the login_required decorator.

All Firestore writes for the users collection go through this module.
The passwords sub-collection is handled separately in vault/passwords.py.

register_user uses a Firestore transaction to atomically check for an
existing email and write the new user document, eliminating any TOCTOU race.
"""

import logging
import re
import secrets
from functools import wraps
from typing import Any

from firebase_admin import firestore
from google.cloud.firestore_v1.base_query import FieldFilter
from flask import jsonify, session
from flask.typing import ResponseReturnValue

from crypto import decrypt, encrypt, hash_password, verify_password
from db import get_db

logger = logging.getLogger(__name__)

# Minimal RFC-5322-inspired email regex — catches typos without over-validating.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_MAX_USERNAME_LEN = 120
_MAX_PASSWORD_LEN = 256

_PW_MIN_LEN   = 8
_PW_UPPER_RE  = re.compile(r"[A-Z]")
_PW_LOWER_RE  = re.compile(r"[a-z]")
_PW_DIGIT_RE  = re.compile(r"\d")
_PW_SYMBOL_RE = re.compile(r"[^A-Za-z0-9]")


def login_required(f):
    """Route decorator — returns 401 JSON when the session contains no uid."""
    @wraps(f)
    def _wrapper(*args: Any, **kwargs: Any) -> ResponseReturnValue:
        if "uid" not in session:
            return jsonify({"error": "Unauthorized — please sign in"}), 401
        return f(*args, **kwargs)
    return _wrapper


def _validate_registration(username: str, email: str, password: str) -> str | None:
    """
    Server-side input validation for registration.
    Returns an error string on failure, None on success.
    """
    if not username or not email or not password:
        return "All fields are required"
    if len(username) > _MAX_USERNAME_LEN:
        return f"Name must be {_MAX_USERNAME_LEN} characters or fewer"
    if not _EMAIL_RE.match(email):
        return "Please enter a valid email address"
    if len(password) < _PW_MIN_LEN:
        return f"Password must be at least {_PW_MIN_LEN} characters"
    if len(password) > _MAX_PASSWORD_LEN:
        return f"Password must be {_MAX_PASSWORD_LEN} characters or fewer"

    missing: list[str] = []
    if not _PW_UPPER_RE.search(password):
        missing.append("an uppercase letter")
    if not _PW_LOWER_RE.search(password):
        missing.append("a lowercase letter")
    if not _PW_DIGIT_RE.search(password):
        missing.append("a number")
    if not _PW_SYMBOL_RE.search(password):
        missing.append("a special character")
    if missing:
        return "Password must contain: " + ", ".join(missing)

    return None


def _mask_email(email: str) -> str:
    """Return a masked email like 'j***@example.com' for safe logging."""
    try:
        local, domain = email.split("@", 1)
        return f"{local[0]}***@{domain}" if local else "***@" + domain
    except ValueError:
        return "***"


def register_user(username: str, email: str, password: str) -> dict[str, Any]:
    """
    Create a new user document in Firestore atomically.

    Uses a Firestore transaction to eliminate the TOCTOU race between the
    duplicate-email check and the document write.

    Stored fields:
      uid           — random 32-hex ID (locates sub-collections)
      email         — plain text (required for login query)
      email_enc     — AES-256 encrypted copy (privacy layer)
      username_enc  — AES-256 encrypted
      password_hash — PBKDF2-SHA256 hash — irreversible
      created_at    — server timestamp

    Returns {"ok": True} on success, {"error": "<message>"} on failure.
    """
    email    = email.lower().strip()
    username = username.strip()

    error = _validate_registration(username, email, password)
    if error:
        return {"error": error}

    db  = get_db()
    uid = secrets.token_hex(16)
    user_ref = db.collection("users").document(uid)

    @firestore.transactional
    def _create_in_transaction(transaction) -> bool:
        existing = (
            db.collection("users")
            .where(filter=FieldFilter("email", "==", email))
            .limit(1)
            .get(transaction=transaction)
        )
        if existing:
            return False

        transaction.set(user_ref, {
            "uid":           uid,
            "email":         email,
            "email_enc":     encrypt(email),
            "username_enc":  encrypt(username),
            "password_hash": hash_password(password),
            "created_at":    firestore.SERVER_TIMESTAMP,
        })
        return True

    transaction = db.transaction()
    created = _create_in_transaction(transaction)

    if not created:
        return {"error": "An account with this email already exists"}

    logger.info("New user registered: uid=%s", uid)
    return {"ok": True}


def login_user(email: str, password: str) -> dict[str, Any]:
    """
    Verify credentials and populate the Flask session.

    Uses the same generic error for both "user not found" and "wrong password"
    to prevent username enumeration attacks.

    Returns {"ok": True, "username": "<n>"} on success,
    or {"error": "<message>"} on failure.
    """
    email = email.lower().strip()

    if not email or not password:
        return {"error": "Email and password are required"}

    db   = get_db()
    docs = (
        db.collection("users")
        .where(filter=FieldFilter("email", "==", email))
        .limit(1)
        .get()
    )
    if not docs:
        logger.warning("Login failed — email not found: %s", _mask_email(email))
        return {"error": "Invalid email or password"}

    user = docs[0].to_dict()
    if not verify_password(password, user["password_hash"]):
        logger.warning("Login failed — wrong password for uid=%s", user.get("uid"))
        return {"error": "Invalid email or password"}

    username           = decrypt(user["username_enc"])
    session.permanent  = True
    session["uid"]     = user["uid"]
    session["username"] = username
    logger.info("User logged in: uid=%s", user["uid"])
    return {"ok": True, "username": username}
