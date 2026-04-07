"""
todo/routes.py — serves GET /todo (localStorage-only, no API needed).

Fix #9  — No-cache response uses the shared utils.http.no_cache_page helper.
Fix #12 — Redundant @todo_bp.get("") registration removed; Flask normalises
           the trailing-slash behaviour via the url_prefix="/todo" in app.py.
"""
import logging
from flask import Blueprint, g
from flask.typing import ResponseReturnValue

from utils.http import no_cache_page

logger  = logging.getLogger(__name__)
todo_bp = Blueprint("todo", __name__)


@todo_bp.get("/")
def todo_page() -> ResponseReturnValue:
    return no_cache_page("todo.html", csp_nonce=g.get("csp_nonce", ""))
