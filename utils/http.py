"""
utils/http.py — Shared HTTP response helpers used across blueprints.
"""

from flask import make_response, render_template
from flask.typing import ResponseReturnValue

_NO_CACHE = "no-store, no-cache, must-revalidate, max-age=0"


def no_cache_page(template: str, **ctx) -> ResponseReturnValue:
    """
    Render template and attach headers that prevent all caching.
    Use for any page that shows session-sensitive content so the browser
    never serves a stale cached copy after logout.
    """
    resp = make_response(render_template(template, **ctx))
    resp.headers["Cache-Control"] = _NO_CACHE
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp
