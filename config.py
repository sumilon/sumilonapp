"""
config.py — Application configuration.

Secrets are resolved lazily when Config() is instantiated inside create_app().

Secret resolution order (first match wins):
  1. GCP Secret Manager  — production (Cloud Run)
  2. Environment variable — local dev or Cloud Run plain-env fallback
  3. Hard-coded safe default — local dev only (never used in production)
"""

import logging
import os
import secrets as _secrets
from typing import Any, ClassVar, Optional

logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes"}


class Config:
    """
    All configuration lives here.  Instantiate once inside create_app().
    Attributes are resolved from the environment on __init__ so that
    no network calls happen at import time.
    """

    def __init__(self) -> None:
        self.DEBUG: bool = os.environ.get("FLASK_DEBUG", "").lower() in _TRUTHY

        self.SECRET_KEY: str = self._resolve(
            env_var="FLASK_SECRET_KEY",
            secret_name="flask-secret-key",
            fallback=_secrets.token_hex(32),
        )

        self.APP_MASTER_KEY: str = self._resolve(
            env_var="APP_MASTER_KEY",
            secret_name="app-master-key",
            fallback="local-dev-fallback-key-not-for-prod!",
        )

        self.FIREBASE_CREDENTIALS_JSON: str = self._resolve(
            env_var="FIREBASE_CREDENTIALS_JSON",
            secret_name="firebase-creds",
            fallback="",
        )

        self.GOOGLE_APPLICATION_CREDENTIALS: str = os.environ.get(
            "GOOGLE_APPLICATION_CREDENTIALS", ""
        )

        try:
            raw_hours = int(os.environ.get("SESSION_LIFETIME_HOURS", "2"))
            # Clamp to a sensible range: at least 1 h, at most 24 h.
            self.SESSION_LIFETIME_HOURS: int = max(1, min(raw_hours, 24))
            if raw_hours != self.SESSION_LIFETIME_HOURS:
                logger.warning(
                    "SESSION_LIFETIME_HOURS=%d is outside the allowed range "
                    "[1, 24] — clamped to %d.",
                    raw_hours, self.SESSION_LIFETIME_HOURS,
                )
        except ValueError:
            logger.warning("SESSION_LIFETIME_HOURS is not a valid integer — defaulting to 2.")
            self.SESSION_LIFETIME_HOURS = 2

        try:
            raw_limit = int(os.environ.get("AUTH_RATE_LIMIT", "3"))
            # Clamp to a sensible range: at least 1, at most 20.
            self.AUTH_RATE_LIMIT: int = max(1, min(raw_limit, 20))
            if raw_limit != self.AUTH_RATE_LIMIT:
                logger.warning(
                    "AUTH_RATE_LIMIT=%d is outside the allowed range "
                    "[1, 20] — clamped to %d.",
                    raw_limit, self.AUTH_RATE_LIMIT,
                )
        except ValueError:
            logger.warning("AUTH_RATE_LIMIT is not a valid integer — defaulting to 3.")
            self.AUTH_RATE_LIMIT = 3

    @staticmethod
    def _resolve(env_var: str, secret_name: str, fallback: str) -> str:
        """
        Three-tier secret resolution:
          1. GCP Secret Manager
          2. Environment variable
          3. Hard-coded fallback (local dev only)
        """
        sm_value = Config._from_secret_manager(secret_name)
        if sm_value:
            logger.debug("Config '%s' loaded from Secret Manager.", env_var)
            return sm_value

        env_value = os.environ.get(env_var, "").strip()
        if env_value:
            logger.debug("Config '%s' loaded from environment.", env_var)
            return env_value

        logger.warning(
            "Config '%s' not found in Secret Manager or environment — "
            "using fallback. Do NOT use this in production.",
            env_var,
        )
        return fallback

    # Cached Secret Manager client — reuses the gRPC channel across all secret lookups.
    _sm_client: ClassVar[Optional[Any]] = None

    @staticmethod
    def _from_secret_manager(secret_name: str) -> str:
        """
        Read the latest version of a secret from GCP Secret Manager.
        Returns "" (never raises) if unavailable for any reason.
        The client is cached at the class level to reuse the same gRPC channel.
        """
        project = (
            os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCP_PROJECT")
            or ""
        )
        if not project:
            return ""

        try:
            from google.cloud import secretmanager

            if Config._sm_client is None:
                Config._sm_client = secretmanager.SecretManagerServiceClient()

            resource = f"projects/{project}/secrets/{secret_name}/versions/latest"
            response = Config._sm_client.access_secret_version(
                request={"name": resource}
            )
            value = response.payload.data.decode("utf-8").strip()
            return value if value else ""
        except Exception as exc:  # noqa: BLE001
            logger.debug("Secret Manager lookup for '%s' skipped: %s", secret_name, exc)
            return ""

