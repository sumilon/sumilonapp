"""
extensions.py — Shared Flask extension instances.

Defined here (without an app) so that both app.py and any blueprint module
can import them without creating a circular dependency.

Usage:
    from extensions import csrf, limiter

app.py calls csrf.init_app(app) and limiter.init_app(app) inside create_app().
"""

from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

csrf    = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])