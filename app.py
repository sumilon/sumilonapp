"""
app.py — Flask application factory.

URL map
-------
  /              → Portfolio
  /calculator    → Financial calculator (client-side JS, no DB)
  /todo          → To-do list (browser localStorage, no DB)
  /vault         → Encrypted password manager (Firestore)
  /health        → Cloud Run liveness probe

Each page is a fully standalone single-page application.
No page links to any other page.

Gunicorn entry point: app:app
  The module-level `app` object is created once at import time so
  Gunicorn can locate it with the standard `module:object` syntax.

Security improvements in this revision
---------------------------------------
  Fix #3  — CSP uses per-request nonces instead of 'unsafe-inline'.
  Fix #4  — Flask-WTF CSRF protection enabled globally; the vault blueprint
             (all JSON APIs) is exempted via csrf.exempt(vault_bp) after
             registration — JSON APIs rely on Content-Type: application/json
             + SameSite=Lax as the CSRF mitigation.
  Fix #2  — Flask-Limiter applied to auth endpoints (see vault/routes.py).

Circular-import fix
-------------------
  csrf and limiter now live in extensions.py so blueprints can import
  them without importing app.py (which would cause a circular import).
"""

import logging
import os
import secrets
from datetime import timedelta

from flask import Flask, g, jsonify
from flask.typing import ResponseReturnValue

from config import Config
from extensions import csrf, limiter
from portfolio.routes  import portfolio_bp
from calculator.routes import calculator_bp
from todo.routes       import todo_bp
from vault.routes      import vault_bp

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        force=True,  # override any handlers Gunicorn may have set before import
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("google").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def create_app() -> Flask:
    """Create, configure and return the Flask application."""
    _configure_logging()

    flask_app = Flask(__name__, template_folder="templates", static_folder=None)

    cfg = Config()
    flask_app.config.update(
        SECRET_KEY=cfg.SECRET_KEY,
        APP_MASTER_KEY=cfg.APP_MASTER_KEY,
        FIREBASE_CREDENTIALS_JSON=cfg.FIREBASE_CREDENTIALS_JSON,
        GOOGLE_APPLICATION_CREDENTIALS=cfg.GOOGLE_APPLICATION_CREDENTIALS,
        AUTH_RATE_LIMIT=cfg.AUTH_RATE_LIMIT,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=not cfg.DEBUG,
        SESSION_COOKIE_NAME="vs",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=cfg.SESSION_LIFETIME_HOURS),
        WTF_CSRF_TIME_LIMIT=3600,
    )

    # ── Extensions ────────────────────────────────────────────────────────────
    csrf.init_app(flask_app)
    limiter.init_app(flask_app)

    # ── Blueprints ────────────────────────────────────────────────────────────
    flask_app.register_blueprint(portfolio_bp,  url_prefix="")
    flask_app.register_blueprint(calculator_bp, url_prefix="/calculator")
    flask_app.register_blueprint(todo_bp,       url_prefix="/todo")
    flask_app.register_blueprint(vault_bp,      url_prefix="/vault")

    # Fix #4 — Exempt the entire vault blueprint from CSRF token checks.
    # All vault routes are JSON APIs; they use Content-Type: application/json
    # + SameSite=Lax cookies as the CSRF mitigation (correct for JSON APIs).
    # csrf.exempt() accepts a Blueprint and marks every view registered on it.
    csrf.exempt(vault_bp)

    # ── Health probe ──────────────────────────────────────────────────────────
    @flask_app.get("/health")
    def health() -> ResponseReturnValue:
        """Cloud Run liveness/readiness probe — no DB, no auth."""
        return jsonify({"status": "ok"}), 200

    # ── Per-request CSP nonce (Fix #3) ────────────────────────────────────────
    @flask_app.before_request
    def _set_csp_nonce() -> None:
        """
        Generate a fresh cryptographic nonce for every request.
        Templates access it via {{ g.csp_nonce }}.
        The nonce is embedded in the CSP header below and in every <script>
        and <style> tag, replacing 'unsafe-inline'.
        """
        g.csp_nonce = secrets.token_urlsafe(16)

    # ── Security headers ──────────────────────────────────────────────────────
    @flask_app.after_request
    def security_headers(response):
        h = response.headers
        h["X-Content-Type-Options"]  = "nosniff"
        h["X-Frame-Options"]         = "DENY"
        h["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        h["X-XSS-Protection"]        = "1; mode=block"
        h["Permissions-Policy"]      = "geolocation=(), camera=(), microphone=()"

        if not cfg.DEBUG:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        nonce = getattr(g, "csp_nonce", "")
        h["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
            f"style-src 'self' 'nonce-{nonce}' "
            f"https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            f"font-src https://fonts.gstatic.com; "
            f"img-src 'self' data:; "
            f"connect-src 'self';"
        )
        return response

    # ── Global error handlers ─────────────────────────────────────────────────
    @flask_app.errorhandler(404)
    def not_found(e) -> ResponseReturnValue:
        return jsonify({"error": "Not found"}), 404

    @flask_app.errorhandler(429)
    def rate_limited(e) -> ResponseReturnValue:
        return jsonify({"error": "Too many requests — please wait and try again"}), 429

    @flask_app.errorhandler(500)
    def internal_error(e) -> ResponseReturnValue:
        logger.exception("Unhandled server error: %s", e)
        return jsonify({"error": "Internal server error"}), 500

    logger.info("Application ready — / /calculator /todo /vault /health")
    return flask_app


# Module-level app object — required by Gunicorn (`gunicorn app:app`).
app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)