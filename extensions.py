"""
extensions.py — Shared Flask extension instances.

Defined here so both app.py and blueprint modules can import them without
creating a circular dependency. app.py calls init_app() inside create_app().
"""

from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
csrf = CSRFProtect()

# In-memory storage is sufficient for a single Cloud Run instance (--workers 1).
# If you scale to multiple instances, replace with a shared backend (e.g. Redis).
limiter = Limiter(key_func=get_remote_address, default_limits=[])
