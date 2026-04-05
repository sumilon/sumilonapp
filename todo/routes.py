"""todo/routes.py — serves GET /todo (localStorage-only, no API needed)"""
import logging
from flask import Blueprint, make_response, render_template
from flask.typing import ResponseReturnValue

logger  = logging.getLogger(__name__)
todo_bp = Blueprint("todo", __name__)

_NO_CACHE = "no-store, no-cache, must-revalidate, max-age=0"

@todo_bp.get("/")
@todo_bp.get("")
def todo_page() -> ResponseReturnValue:
    resp = make_response(render_template("todo.html"))
    resp.headers["Cache-Control"] = _NO_CACHE
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
    return resp
