"""
app.py — Flask application factory.

Registers the two blueprints:
  /vault  — encrypted password manager (Firestore)
  /todo   — in-memory task list (no database)
"""

import logging
import os
from datetime import timedelta

from flask import Flask, redirect, url_for
from flask.typing import ResponseReturnValue

from config import Config
from vault.routes import vault_bp
from todo.routes import todo_bp

# Module-level logger — handlers are configured once in create_app().
logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Set up structured logging for the whole application."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Quieten noisy third-party loggers.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("google").setLevel(logging.WARNING)


def create_app() -> Flask:
    """Create and configure the Flask application."""
    _configure_logging()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # ── Load configuration ────────────────────────────────────────────────
    cfg = Config()
    app.config.update(
        SECRET_KEY=cfg.SECRET_KEY,
        APP_MASTER_KEY=cfg.APP_MASTER_KEY,
        FIREBASE_CREDENTIALS_JSON=cfg.FIREBASE_CREDENTIALS_JSON,
        GOOGLE_APPLICATION_CREDENTIALS=cfg.GOOGLE_APPLICATION_CREDENTIALS,
        # Session security
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=not cfg.DEBUG,  # False in local dev, True in prod
        PERMANENT_SESSION_LIFETIME=timedelta(hours=cfg.SESSION_LIFETIME_HOURS),
    )

    # ── Blueprints ────────────────────────────────────────────────────────
    app.register_blueprint(vault_bp, url_prefix="/vault")
    app.register_blueprint(todo_bp, url_prefix="/todo")

    # ── Root redirect ─────────────────────────────────────────────────────
    @app.get("/")
    def root() -> ResponseReturnValue:
        return redirect(url_for("vault.index"))

    # ── Security headers on every response ───────────────────────────────
    @app.after_request
    def add_security_headers(response):
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options":        "DENY",
            "Referrer-Policy":        "strict-origin-when-cross-origin",
            "X-XSS-Protection":       "1; mode=block",
        })
        return response

    logger.info("Application created successfully.")
    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    create_app().run(host="0.0.0.0", port=port, debug=False)
