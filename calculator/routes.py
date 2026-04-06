"""calculator/routes.py — serves GET /calculator"""
import logging
from flask import Blueprint, render_template
from flask.typing import ResponseReturnValue

logger        = logging.getLogger(__name__)
calculator_bp = Blueprint("calculator", __name__)

@calculator_bp.get("/")
def index() -> ResponseReturnValue:
    return render_template("calculator.html")
