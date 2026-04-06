"""
crypto.py — Encryption and password-hashing helpers.

Encryption
----------
AES-256 via Fernet (cryptography library).
Each stored value has its own 16-byte random salt.  The Fernet key is
derived from APP_MASTER_KEY + that salt using PBKDF2-HMAC-SHA256
(600 000 iterations — aligned with NIST SP 800-132 / OWASP 2024 guidance).

Key derivation is expensive by design (brute-force resistance), but the
derived key is cached per (master_key, salt) pair so repeated reads of the
same record only pay the cost once per process lifetime.

Password hashing
----------------
Login passwords use PBKDF2-HMAC-SHA256 (600 000 rounds) with a per-user
random salt, stored as "hex_salt:hex_hash".  Comparison uses
hmac.compare_digest for constant-time equality — prevents timing attacks.

Security notes
--------------
- APP_MASTER_KEY must be kept secret.  Anyone with both the Firestore data
  and the master key can decrypt all stored passwords.
- The fallback master key ("local-dev-fallback-key-not-for-prod!") is
  detected at runtime and raises RuntimeError in non-debug environments.
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
from functools import lru_cache

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app

logger = logging.getLogger(__name__)

# NIST SP 800-132 / OWASP 2024 recommended minimum for PBKDF2-SHA256.
_PBKDF2_ITERATIONS = 600_000

# The insecure fallback key value defined in config.py.
_FALLBACK_MASTER_KEY = "local-dev-fallback-key-not-for-prod!"


# ── Key derivation (cached) ───────────────────────────────────────────────────

@lru_cache(maxsize=256)
def _derive_fernet_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet-ready key from master_key + salt.

    Results are cached per (master_key, salt) pair so that repeated reads
    of the same Firestore document only run PBKDF2 once per process.
    maxsize=256 caps memory at ~256 × (32 + 16) bytes ≈ 12 KB.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_key))


def _master_key() -> bytes:
    """
    Return APP_MASTER_KEY as bytes from the current Flask app context.

    Raises RuntimeError in production if the insecure fallback key is active.
    """
    key = current_app.config["APP_MASTER_KEY"]
    if key == _FALLBACK_MASTER_KEY:
        debug = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
        if not debug:
            raise RuntimeError(
                "APP_MASTER_KEY is set to the insecure development fallback. "
                "Set a strong secret in environment variables or Secret Manager "
                "before running in production."
            )
        logger.warning(
            "Using insecure fallback APP_MASTER_KEY — "
            "never deploy this to production!"
        )
    return key.encode()


# ── Symmetric encryption ──────────────────────────────────────────────────────

def encrypt(plaintext: str) -> dict[str, str]:
    """
    Encrypt a UTF-8 string with AES-256 Fernet.

    A fresh 16-byte salt is generated for every call so two encryptions of
    the same value produce different ciphertexts — no pattern leakage.

    Returns a dict suitable for direct storage in Firestore:
        {"ciphertext": "<base64url>", "salt": "<base64url>"}
    """
    salt  = secrets.token_bytes(16)
    key   = _derive_fernet_key(_master_key(), salt)
    token = Fernet(key).encrypt(plaintext.encode("utf-8"))
    return {
        "ciphertext": base64.urlsafe_b64encode(token).decode(),
        "salt":       base64.urlsafe_b64encode(salt).decode(),
    }


def decrypt(payload: dict[str, str]) -> str:
    """
    Decrypt a {"ciphertext", "salt"} dict returned from Firestore.

    Raises:
        KeyError        — if "ciphertext" or "salt" is missing from payload.
        InvalidToken    — if the ciphertext has been tampered with, or the
                          wrong master key is used.
        ValueError      — if the payload fields are not valid base64.
    """
    if "salt" not in payload or "ciphertext" not in payload:
        raise KeyError("Decrypt payload missing 'salt' or 'ciphertext' field")

    try:
        salt  = base64.urlsafe_b64decode(payload["salt"])
        token = base64.urlsafe_b64decode(payload["ciphertext"])
    except Exception as exc:
        raise ValueError("Decrypt payload contains invalid base64 data") from exc

    key = _derive_fernet_key(_master_key(), salt)
    # InvalidToken is raised by Fernet if data is tampered or key is wrong.
    return Fernet(key).decrypt(token).decode("utf-8")


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    Hash a login password with PBKDF2-HMAC-SHA256 (600 000 iterations).

    Returns "hex_salt:hex_hash".  The original password is never stored.
    """
    salt   = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode(), _PBKDF2_ITERATIONS
    )
    return f"{salt}:{digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Verify a login password against a "hex_salt:hex_hash" stored string.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing-based attacks.  Returns False on any malformed input.
    """
    try:
        salt, hex_hash = stored.split(":", 1)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode(), _PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(candidate.hex(), hex_hash)
    except Exception:  # noqa: BLE001
        return False
