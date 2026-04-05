"""
db.py — Firestore client (singleton, initialised once per process).

get_db() is the only public symbol.  It returns the same Firestore client
on every call within a process, avoiding repeated SDK initialisation.

Credential resolution order:
  1. FIREBASE_CREDENTIALS_JSON env var — JSON string pasted in Cloud Run Console
  2. GOOGLE_APPLICATION_CREDENTIALS   — file path for local dev
  3. Application Default Credentials  — Cloud Run service account with Firebase role
"""

import json
import logging

import firebase_admin
from firebase_admin import credentials, firestore
from flask import current_app

logger = logging.getLogger(__name__)

# Module-level singleton — set once, reused on every request.
_db: firestore.Client | None = None


def get_db() -> firestore.Client:
    """Return the Firestore client, initialising Firebase on first call."""
    global _db
    if _db is not None:
        return _db

    if not firebase_admin._apps:
        _db = _init_firebase()
    else:
        _db = firestore.client()

    return _db


def _init_firebase() -> firestore.Client:
    """Initialise the Firebase Admin SDK and return a Firestore client."""
    cred_json = current_app.config.get("FIREBASE_CREDENTIALS_JSON", "").strip()
    cred_path = current_app.config.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

    if cred_json:
        logger.info("Firebase: initialising from FIREBASE_CREDENTIALS_JSON.")
        cred = credentials.Certificate(json.loads(cred_json))
    elif cred_path:
        logger.info("Firebase: initialising from credentials file at '%s'.", cred_path)
        cred = credentials.Certificate(cred_path)
    else:
        logger.info("Firebase: initialising with Application Default Credentials.")
        cred = credentials.ApplicationDefault()

    firebase_admin.initialize_app(cred)
    return firestore.client()
