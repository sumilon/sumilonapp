"""
vault/routes.py — HTTP routes for the password-manager.

URL design (simple, no /app suffix):
    GET  /vault/           → login form (or password list if already logged in)
    GET  /vault/register   → registration form

Auth API:
    POST /vault/api/register
    POST /vault/api/login
    POST /vault/api/logout

Password API (login required):
    GET    /vault/api/passwords
    POST   /vault/api/passwords
    PUT    /vault/api/passwords/<pid>
    DELETE /vault/api/passwords/<pid>
    POST   /vault/api/passwords/<pid>/copy
"""

import logging

from flask import (
    Blueprint, jsonify, render_template,
    request, session, url_for, redirect,
)
from flask.typing import ResponseReturnValue

from vault.auth import login_required, login_user, register_user
from vault.passwords import (
    add_password, delete_password,
    get_decrypted_password, list_passwords, update_password,
)

logger   = logging.getLogger(__name__)
vault_bp = Blueprint("vault", __name__)


# ── Pages ─────────────────────────────────────────────────────────────────────

@vault_bp.get("/")
@vault_bp.get("/login")
def index() -> ResponseReturnValue:
    """
    Single entry point for the vault.
    - Logged in  → render the password manager directly.
    - Not logged → render the login/register form.
    Both states use one template; JS receives a flag to know which view to show.
    """
    logged_in = "uid" in session
    return render_template(
        "vault/vault.html",
        logged_in=logged_in,
        username=session.get("username", "") if logged_in else "",
    )


@vault_bp.get("/register")
def register_page() -> ResponseReturnValue:
    if "uid" in session:
        return redirect(url_for("vault.index"))
    return render_template("vault/vault.html", logged_in=False, show_register=True, username="")


# ── Auth API ──────────────────────────────────────────────────────────────────

@vault_bp.post("/api/register")
def api_register() -> ResponseReturnValue:
    body     = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    email    = (body.get("email")    or "").strip()
    password =  body.get("password") or ""

    result = register_user(username, email, password)
    if "error" in result:
        status = 409 if "already exists" in result["error"] else 400
        return jsonify(result), status
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


# ── Password API ──────────────────────────────────────────────────────────────

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
    pwd = get_decrypted_password(session["uid"], pid)
    if pwd is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"password": pwd})
