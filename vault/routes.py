"""
vault/routes.py — HTTP routes for the password manager.

Pages:   GET /vault/  GET /vault/register
Auth:    POST /vault/api/register|login|logout
Passwords (login required):
         GET|POST /vault/api/passwords
         PUT|DELETE /vault/api/passwords/<pid>
         POST /vault/api/passwords/<pid>/copy
         GET /vault/api/passwords/redeem/<token>

Security fixes applied
----------------------
Fix #1  — /copy no longer returns the plaintext password in the JSON body.
           Returns a short-lived (60 s) single-use token instead; client
           redeems it via GET /api/passwords/redeem/<token>.

Fix #2  — Rate limiting on /api/login and /api/register via Flask-Limiter.
           limiter is imported from extensions.py (no circular import).

Fix #4  — The entire vault blueprint is exempted from Flask-WTF CSRF in
           app.py via csrf.exempt(vault_bp) after registration.

Fix #9  — No-cache responses via shared utils.http.no_cache_page helper.
"""

import logging
import secrets
import time
from cryptography.fernet import InvalidToken
from flask import (
    Blueprint, current_app, g, jsonify,
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

# Single-use password tokens stored in the session.
_TOKEN_TTL = 60  # seconds


# ── Pages ─────────────────────────────────────────────────────────────────────

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


# ── Auth API ──────────────────────────────────────────────────────────────────

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


# ── Passwords API ─────────────────────────────────────────────────────────────

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
    update_password(session["uid"], pid, body)
    return jsonify({"message": "Updated"})


@vault_bp.delete("/api/passwords/<pid>")
@login_required
def api_delete(pid: str) -> ResponseReturnValue:
    delete_password(session["uid"], pid)
    return jsonify({"message": "Deleted"})


@vault_bp.post("/api/passwords/<pid>/copy")
@login_required
def api_copy(pid: str) -> ResponseReturnValue:
    """
    Fix #1 — Returns a single-use token, not the plaintext password.
    Client redeems the token via GET /api/passwords/redeem/<token>.
    """
    try:
        pwd = get_decrypted_password(session["uid"], pid)
    except InvalidToken:
        logger.error(
            "Decryption failure on copy for pid=%s uid=%s", pid, session["uid"]
        )
        return jsonify({"error": "Decryption failed — data may be corrupt"}), 500

    if pwd is None:
        return jsonify({"error": "Not found"}), 404

    token   = secrets.token_urlsafe(32)
    now     = time.monotonic()
    pending = {t: v for t, v in session.get("_pw_tokens", {}).items()
               if v["expires"] > now}  # prune expired tokens
    pending[token] = {"password": pwd, "expires": now + _TOKEN_TTL}
    session["_pw_tokens"] = pending

    return jsonify({"token": token, "ttl": _TOKEN_TTL}), 200


@vault_bp.get("/api/passwords/redeem/<token>")
@login_required
def api_redeem(token: str) -> ResponseReturnValue:
    """Redeem a single-use token; deleted immediately after first use."""
    pending = session.get("_pw_tokens", {})
    entry   = pending.pop(token, None)
    session["_pw_tokens"] = pending

    if entry is None:
        return jsonify({"error": "Invalid or expired token"}), 404
    if time.monotonic() > entry["expires"]:
        return jsonify({"error": "Token expired"}), 410

    return jsonify({"password": entry["password"]}), 200