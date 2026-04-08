"""
app.py — Flask application factory.

URL map:
  /              → Portfolio
  /calculator    → Financial calculator
  /todo          → To-do list (browser localStorage)
  /vault         → Encrypted password manager (Firestore)
  /health        → Cloud Run liveness probe

Gunicorn entry point: app:app
"""

import logging
import os
import secrets
from datetime import timedelta

from flask import Flask, current_app, g, jsonify
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import HTTPException

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
        force=True,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("google").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def create_app() -> Flask:
    """Create, configure and return the Flask application."""
    _configure_logging()

    flask_app = Flask(__name__, template_folder="templates", static_folder="static")

    cfg = Config()
    flask_app.config.update(
        DEBUG=cfg.DEBUG,
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

    csrf.init_app(flask_app)
    limiter.init_app(flask_app)

    flask_app.register_blueprint(portfolio_bp,  url_prefix="")
    flask_app.register_blueprint(calculator_bp, url_prefix="/calculator")
    flask_app.register_blueprint(todo_bp,       url_prefix="/todo")
    flask_app.register_blueprint(vault_bp,      url_prefix="/vault")

    # Vault routes are JSON APIs — they rely on Content-Type: application/json
    # + SameSite=Lax cookies as the CSRF mitigation.
    csrf.exempt(vault_bp)

    @flask_app.get("/health")
    def health() -> ResponseReturnValue:
        """Cloud Run liveness/readiness probe — no DB, no auth."""
        return jsonify({"status": "ok"}), 200

    @flask_app.get("/favicon.ico")
    @flask_app.get("/favicon.svg")
    def favicon() -> ResponseReturnValue:
        """Serve the SVG app icon for browser tabs and bookmarks."""
        from flask import send_from_directory
        return send_from_directory(
            flask_app.static_folder,
            "logo.svg",
            mimetype="image/svg+xml",
        )

    @flask_app.before_request
    def _set_csp_nonce() -> None:
        """Generate a fresh cryptographic nonce per request for CSP headers."""
        g.csp_nonce = secrets.token_urlsafe(16)

    @flask_app.after_request
    def security_headers(response) -> ResponseReturnValue:
        h = response.headers
        h["X-Content-Type-Options"]  = "nosniff"
        h["X-Frame-Options"]         = "DENY"
        h["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        h["Permissions-Policy"]      = "geolocation=(), camera=(), microphone=()"
        # Prevent caches from serving a user-specific page to a different user.
        h["Vary"] = "Cookie"

        if not current_app.config.get("DEBUG", False):
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        nonce = getattr(g, "csp_nonce", "")
        h["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
            f"style-src 'self' 'nonce-{nonce}' "
            f"https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            f"font-src https://fonts.gstatic.com; "
            f"img-src 'self' data:; "
            f"connect-src 'self' https://fonts.googleapis.com;"
        )
        return response

    @flask_app.errorhandler(404)
    def not_found(e: HTTPException) -> ResponseReturnValue:
        return jsonify({"error": "Not found"}), 404

    @flask_app.errorhandler(429)
    def rate_limited(e: HTTPException) -> ResponseReturnValue:
        return jsonify({"error": "Too many requests — please wait and try again"}), 429

    @flask_app.errorhandler(500)
    def internal_error(e: Exception) -> ResponseReturnValue:
        logger.exception("Unhandled server error: %s", e)
        return jsonify({"error": "Internal server error"}), 500

    logger.info("Application ready — / /calculator /todo /vault /health")
    return flask_app


# Module-level app object required by Gunicorn (`gunicorn app:app`).
app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)