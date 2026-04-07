"""portfolio/routes.py — serves GET /"""
import logging
from flask import Blueprint, g, render_template
from flask.typing import ResponseReturnValue

logger       = logging.getLogger(__name__)
portfolio_bp = Blueprint("portfolio", __name__)


@portfolio_bp.get("/")
def index() -> ResponseReturnValue:
    return render_template("portfolio.html", csp_nonce=g.get("csp_nonce", ""))
