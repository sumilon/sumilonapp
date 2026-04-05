"""
vault/auth.py — User registration, login, and the login_required decorator.

All Firestore writes go through this module for the users collection.
The passwords sub-collection is handled separately in vault/passwords.py.
"""

import logging
import re
import secrets
from functools import wraps
from typing import Any

from firebase_admin import firestore
from flask import jsonify, session
from flask.typing import ResponseReturnValue

from crypto import decrypt, encrypt, hash_password, verify_password
from db import get_db

logger = logging.getLogger(__name__)

# Minimal RFC-5322-inspired email regex — not exhaustive, but catches typos.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Maximum field lengths to avoid oversized Firestore writes.
_MAX_USERNAME_LEN = 120
_MAX_PASSWORD_LEN = 256


# ── Decorator ─────────────────────────────────────────────────────────────────

def login_required(f):
    """
    Route decorator — returns 401 JSON when the session has no uid.
    Apply to every password-manager API endpoint.
    """
    @wraps(f)
    def _wrapper(*args: Any, **kwargs: Any) -> ResponseReturnValue:
        if "uid" not in session:
            return jsonify({"error": "Unauthorized — please sign in"}), 401
        return f(*args, **kwargs)
    return _wrapper


# ── Input validation ──────────────────────────────────────────────────────────

def _validate_registration(
    username: str, email: str, password: str
) -> str | None:
    """
    Return an error message string if inputs are invalid, else None.
    Validation is intentionally server-side — never rely on the client alone.
    """
    if not username or not email or not password:
        return "All fields are required"
    if len(username) > _MAX_USERNAME_LEN:
        return f"Name must be {_MAX_USERNAME_LEN} characters or fewer"
    if not _EMAIL_RE.match(email):
        return "Please enter a valid email address"
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if len(password) > _MAX_PASSWORD_LEN:
        return f"Password must be {_MAX_PASSWORD_LEN} characters or fewer"
    return None


# ── Registration ──────────────────────────────────────────────────────────────

def register_user(username: str, email: str, password: str) -> dict[str, Any]:
    """
    Create a new user document in Firestore.

    Stored fields:
      uid           — random 32-hex ID (plain; identifies sub-collections)
      email         — plain text (required for the login WHERE query)
      email_enc     — AES-256 encrypted copy (privacy layer)
      username_enc  — AES-256 encrypted
      password_hash — PBKDF2-SHA256, irreversible
      created_at    — server timestamp

    Returns {"ok": True} on success or {"error": "<message>"} on failure.
    """
    email    = email.lower().strip()
    username = username.strip()

    error = _validate_registration(username, email, password)
    if error:
        return {"error": error}

    db = get_db()

    existing = (
        db.collection("users")
        .where("email", "==", email)
        .limit(1)
        .get()
    )
    if existing:
        return {"error": "An account with this email already exists"}

    uid = secrets.token_hex(16)
    db.collection("users").document(uid).set({
        "uid":           uid,
        "email":         email,
        "email_enc":     encrypt(email),
        "username_enc":  encrypt(username),
        "password_hash": hash_password(password),
        "created_at":    firestore.SERVER_TIMESTAMP,
    })
    logger.info("New user registered: uid=%s", uid)
    return {"ok": True}


# ── Login ─────────────────────────────────────────────────────────────────────

def login_user(email: str, password: str) -> dict[str, Any]:
    """
    Verify credentials and populate the Flask session.

    Deliberately uses the same generic error message for both 'user not found'
    and 'wrong password' to prevent username enumeration.

    Returns {"ok": True, "username": "<name>"} on success,
    or {"error": "<message>"} on failure.
    """
    email = email.lower().strip()

    if not email or not password:
        return {"error": "Email and password are required"}

    db   = get_db()
    docs = (
        db.collection("users")
        .where("email", "==", email)
        .limit(1)
        .get()
    )
    if not docs:
        logger.warning("Login failed — email not found: %s", email)
        return {"error": "Invalid email or password"}

    user = docs[0].to_dict()
    if not verify_password(password, user["password_hash"]):
        logger.warning("Login failed — wrong password for uid=%s", user.get("uid"))
        return {"error": "Invalid email or password"}

    username = decrypt(user["username_enc"])
    session.permanent  = True
    session["uid"]     = user["uid"]
    session["username"] = username
    logger.info("User logged in: uid=%s", user["uid"])
    return {"ok": True, "username": username}
