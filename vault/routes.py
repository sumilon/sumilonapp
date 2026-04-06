"""
vault/routes.py — HTTP routes for the password manager.

Pages:   GET /vault/  GET /vault/register
Auth:    POST /vault/api/register|login|logout
Passwords (login required):
         GET|POST /vault/api/passwords
         PUT|DELETE /vault/api/passwords/<pid>
         POST /vault/api/passwords/<pid>/copy
"""
import logging
from cryptography.fernet import InvalidToken
from flask import (
    Blueprint, jsonify, make_response,
    redirect, render_template, request, session, url_for,
)
from flask.typing import ResponseReturnValue

from vault.auth import login_required, login_user, register_user
from vault.passwords import (
    add_password, delete_password,
    get_decrypted_password, list_passwords, update_password,
)

logger   = logging.getLogger(__name__)
vault_bp = Blueprint("vault", __name__)

_NO_CACHE = "no-store, no-cache, must-revalidate, max-age=0"


def _page(template: str, **ctx) -> ResponseReturnValue:
    resp = make_response(render_template(template, **ctx))
    resp.headers["Cache-Control"] = _NO_CACHE
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
    return resp


# ── Pages ─────────────────────────────────────────────────────────────────────

@vault_bp.get("/")
@vault_bp.get("/login")
def index() -> ResponseReturnValue:
    logged_in = "uid" in session
    return _page(
        "vault.html",
        logged_in=logged_in,
        username=session.get("username", "") if logged_in else "",
    )


@vault_bp.get("/register")
def register_page() -> ResponseReturnValue:
    if "uid" in session:
        return redirect(url_for("vault.index"))
    return _page("vault.html", logged_in=False, show_register=True, username="")


# ── Auth API ──────────────────────────────────────────────────────────────────

@vault_bp.post("/api/register")
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
    try:
        pwd = get_decrypted_password(session["uid"], pid)
    except InvalidToken:
        logger.error(
            "Decryption failure on copy for pid=%s uid=%s", pid, session["uid"]
        )
        return jsonify({"error": "Decryption failed — data may be corrupt"}), 500

    if pwd is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"password": pwd})
