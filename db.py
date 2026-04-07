"""
db.py — Firestore client (singleton, initialised once per process).

get_db() returns the same Firestore client on every call, avoiding repeated
SDK initialisation.

Credential resolution order:
  1. FIREBASE_CREDENTIALS_JSON env var — JSON string in Cloud Run Console
  2. GOOGLE_APPLICATION_CREDENTIALS   — file path for local dev
  3. Application Default Credentials  — Cloud Run service account with Firebase role
"""

import json
import logging
import threading
from typing import Optional

import firebase_admin
from firebase_admin import credentials, firestore
from flask import current_app

logger = logging.getLogger(__name__)


class _FirestoreClient:
    """Thread-safe, lazily-initialised Firestore client singleton."""

    def __init__(self) -> None:
        self._client: Optional[firestore.Client] = None
        self._lock = threading.Lock()

    def get(self) -> firestore.Client:
        """Return the Firestore client, initialising Firebase on first call."""
        if self._client is not None:
            return self._client

        with self._lock:
            # Double-checked locking — another thread may have initialised
            # between our first check and acquiring the lock.
            if self._client is not None:
                return self._client

            if not firebase_admin._apps:
                self._client = _init_firebase()
            else:
                self._client = firestore.client()

        return self._client

    def reset(self) -> None:
        """Reset the singleton — intended for testing only."""
        with self._lock:
            self._client = None


_singleton = _FirestoreClient()


def get_db() -> firestore.Client:
    """Return the shared Firestore client."""
    return _singleton.get()


def _init_firebase() -> firestore.Client:
    """Initialise the Firebase Admin SDK and return a Firestore client."""
    cred_json = current_app.config.get("FIREBASE_CREDENTIALS_JSON", "").strip()
    cred_path = current_app.config.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

    # Handle GOOGLE_APPLICATION_CREDENTIALS containing raw JSON instead of a file path.
    if not cred_json and cred_path and cred_path.strip().startswith("{"):
        cred_json = cred_path
        cred_path = ""

    if cred_json:
        logger.info("Firebase: initialising from JSON credentials.")
        try:
            cred = credentials.Certificate(json.loads(cred_json))
        except (json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("FIREBASE_CREDENTIALS_JSON is not valid JSON") from exc
    elif cred_path:
        logger.info("Firebase: initialising from credentials file at '%s'.", cred_path)
        cred = credentials.Certificate(cred_path)
    else:
        logger.info("Firebase: initialising with Application Default Credentials.")
        cred = credentials.ApplicationDefault()

    firebase_admin.initialize_app(cred)
    return firestore.client()
