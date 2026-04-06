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
  Using `app:create_app()` with parentheses is not supported by all
  Gunicorn versions and fails on some Cloud Run configurations.
"""

import logging
import os
from datetime import timedelta

from flask import Flask, jsonify
from flask.typing import ResponseReturnValue

from config import Config
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
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=not cfg.DEBUG,
        SESSION_COOKIE_NAME="vs",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=cfg.SESSION_LIFETIME_HOURS),
    )

    flask_app.register_blueprint(portfolio_bp,  url_prefix="")
    flask_app.register_blueprint(calculator_bp, url_prefix="/calculator")
    flask_app.register_blueprint(todo_bp,       url_prefix="/todo")
    flask_app.register_blueprint(vault_bp,      url_prefix="/vault")

    @flask_app.get("/health")
    def health() -> ResponseReturnValue:
        """Cloud Run liveness/readiness probe — no DB, no auth."""
        return jsonify({"status": "ok"}), 200

    @flask_app.after_request
    def security_headers(response):
        response.headers.update({
            "X-Content-Type-Options":  "nosniff",
            "X-Frame-Options":         "DENY",
            "Referrer-Policy":         "strict-origin-when-cross-origin",
            "X-XSS-Protection":        "1; mode=block",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' "
                "https://fonts.googleapis.com https://cdn.jsdelivr.net; "
                "font-src https://fonts.gstatic.com; "
                "img-src 'self' data:; "
                "connect-src 'self';"
            ),
        })
        return response

    logger.info("Application ready — / /calculator /todo /vault /health")
    return flask_app


# ── Module-level app object ───────────────────────────────────────────────────
# Gunicorn entry point: app:app
# This is created once at module import time.
# Cloud Run and Gunicorn locate it via the standard `module:object` syntax
# without needing parentheses, which avoids compatibility issues.
app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
