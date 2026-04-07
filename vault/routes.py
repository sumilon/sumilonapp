"""
vault/routes.py — HTTP routes for the password manager.

Pages:   GET /vault/  GET /vault/register
Auth:    POST /vault/api/register|login|logout
Passwords (login required):
         GET|POST /vault/api/passwords
         PUT|DELETE /vault/api/passwords/<pid>
         POST /vault/api/passwords/<pid>/copy
         GET /vault/api/passwords/redeem/<token>

The /copy endpoint returns a short-lived (60 s) single-use server-side token
instead of the plaintext password in the response body. The client redeems it
via GET /api/passwords/redeem/<token>. Tokens are stored in process memory —
never in the signed-but-not-encrypted session cookie.
"""

import logging
import secrets
import threading
import time
from cryptography.fernet import InvalidToken
from flask import (
    Blueprint, g, jsonify,
    redirect, request, session, url_for,
)
from flask.typing import ResponseReturnValue

from extensions import limiter
from vault.auth import login_required, login_user, register_user
from vault.passwords import (
    add_password, delete_password,
    get_decrypted_password, list_passwords, update_password,
)
from utils.http import no_cache_page

logger   = logging.getLogger(__name__)
vault_bp = Blueprint("vault", __name__)

_TOKEN_TTL   = 60   # seconds a token remains valid
_TOKEN_STORE: dict[str, dict] = {}
_TOKEN_LOCK  = threading.Lock()


def _store_token(uid: str, password: str) -> str:
    """
    Store password under a fresh random token keyed by uid.
    Returns the token string. Expired entries are pruned on every call.
    """
    token = secrets.token_urlsafe(32)
    now   = time.monotonic()

    with _TOKEN_LOCK:
        # Prune expired tokens to prevent unbounded growth.
        expired = [k for k, v in _TOKEN_STORE.items() if v["expires"] <= now]
        for k in expired:
            del _TOKEN_STORE[k]

        _TOKEN_STORE[token] = {
            "uid":      uid,
            "password": password,
            "expires":  now + _TOKEN_TTL,
        }
    return token


def _redeem_token(token: str, uid: str) -> tuple[str | None, str]:
    """
    Atomically pop and return the password for token if it belongs to uid
    and has not expired. The entire lookup-check-expire-remove cycle is
    performed under a single lock to eliminate any TOCTOU window.

    Returns (password, "ok") on success, or (None, reason) on failure.
    reason is one of: "missing", "forbidden", "expired".
    """
    with _TOKEN_LOCK:
        entry = _TOKEN_STORE.get(token)
        if entry is None:
            return None, "missing"
        if entry["uid"] != uid:
            # Do not remove — the token belongs to a different user.
            return None, "forbidden"
        if time.monotonic() > entry["expires"]:
            del _TOKEN_STORE[token]
            return None, "expired"
        # Valid owner, not expired — consume it (single-use).
        del _TOKEN_STORE[token]

    return entry["password"], "ok"


@vault_bp.get("/")
@vault_bp.get("/login")
def index() -> ResponseReturnValue:
    logged_in = "uid" in session
    return no_cache_page(
        "vault.html",
        logged_in=logged_in,
        username=session.get("username", "") if logged_in else "",
        csp_nonce=g.get("csp_nonce", ""),
    )


@vault_bp.get("/register")
def register_page() -> ResponseReturnValue:
    if "uid" in session:
        return redirect(url_for("vault.index"))
    return no_cache_page(
        "vault.html",
        logged_in=False,
        show_register=True,
        username="",
        csp_nonce=g.get("csp_nonce", ""),
    )


@vault_bp.post("/api/register")
@limiter.limit("3 per minute", error_message="Too many registration attempts. Please wait a minute and try again.")
def api_register() -> ResponseReturnValue:
    body     = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    email    = (body.get("email")    or "").strip()
    password =  body.get("password") or ""
    result   = register_user(username, email, password)
    if "error" in result:
        return jsonify(result), 409 if "already exists" in result["error"] else 400
    return jsonify({"message": "Account created"}), 201


@vault_bp.post("/api/login")
@limiter.limit("3 per minute", error_message="Too many login attempts. Please wait a minute and try again.")
def api_login() -> ResponseReturnValue:
    body   = request.get_json(silent=True) or {}
    result = login_user(body.get("email", ""), body.get("password", ""))
    if "error" in result:
        return jsonify(result), 401
    return jsonify({"message": "ok", "username": result["username"]})


@vault_bp.post("/api/logout")
def api_logout() -> ResponseReturnValue:
    uid = session.get("uid", "anonymous")
    session.clear()
    logger.info("User logged out: uid=%s", uid)
    return jsonify({"message": "ok"})


@vault_bp.get("/api/passwords")
@login_required
def api_list() -> ResponseReturnValue:
    return jsonify(list_passwords(session["uid"]))


@vault_bp.post("/api/passwords")
@login_required
def api_add() -> ResponseReturnValue:
    body = request.get_json(silent=True) or {}
    if not body.get("site_name") or not body.get("username") or not body.get("password"):
        return jsonify({"error": "Site name, username and password are required"}), 400
    pid = add_password(session["uid"], body)
    return jsonify({"message": "Saved", "id": pid}), 201


@vault_bp.put("/api/passwords/<pid>")
@login_required
def api_update(pid: str) -> ResponseReturnValue:
    body = request.get_json(silent=True) or {}
    if not body.get("site_name") or not body.get("username"):
        return jsonify({"error": "Site name and username are required"}), 400
    try:
        update_password(session["uid"], pid, body)
    except FileNotFoundError:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"message": "Updated"})


@vault_bp.delete("/api/passwords/<pid>")
@login_required
def api_delete(pid: str) -> ResponseReturnValue:
    delete_password(session["uid"], pid)
    return jsonify({"message": "Deleted"})


@vault_bp.post("/api/passwords/<pid>/copy")
@login_required
def api_copy(pid: str) -> ResponseReturnValue:
    """Returns a single-use server-side token; never the plaintext password in the response."""
    try:
        pwd = get_decrypted_password(session["uid"], pid)
    except InvalidToken:
        logger.error("Decryption failure on copy for pid=%s uid=%s", pid, session["uid"])
        return jsonify({"error": "Decryption failed — data may be corrupt"}), 500

    if pwd is None:
        return jsonify({"error": "Not found"}), 404

    token = _store_token(session["uid"], pwd)
    return jsonify({"token": token, "ttl": _TOKEN_TTL}), 200


@vault_bp.get("/api/passwords/redeem/<token>")
@login_required
def api_redeem(token: str) -> ResponseReturnValue:
    """
    Redeem a single-use server-side token; consumed immediately after first use.
    Returns 410 if expired so clients can distinguish expired from invalid.
    """
    password, reason = _redeem_token(token, session["uid"])

    if reason == "expired":
        return jsonify({"error": "Token expired — please copy again"}), 410
    if password is None:
        return jsonify({"error": "Invalid or expired token"}), 404

    return jsonify({"password": password}), 200
