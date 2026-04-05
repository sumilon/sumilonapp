"""
todo/routes.py — Lightweight in-memory to-do list.

No database is used.  Items are stored in a module-level dict keyed by a
per-browser session ID so each visitor gets their own isolated list.

Data is intentionally ephemeral: server restarts or a new browser session
starts fresh.  This keeps the module completely free — zero Firestore
reads or writes.

Memory management
-----------------
_store is bounded to _MAX_SESSIONS entries.  When the cap is reached the
oldest session is evicted (FIFO via collections.OrderedDict) so the worker
does not grow unboundedly between deploys.

Page routes:
    GET /todo/   → main to-do page

API routes (return JSON):
    GET    /todo/api/items
    POST   /todo/api/items
    PUT    /todo/api/items/<iid>
    DELETE /todo/api/items/<iid>
"""

import logging
import uuid
from collections import OrderedDict
from typing import Any

from flask import Blueprint, jsonify, render_template, request, session
from flask.typing import ResponseReturnValue

logger  = logging.getLogger(__name__)
todo_bp = Blueprint("todo", __name__)

# Allowed priority values — validated server-side.
_PRIORITIES = frozenset({"low", "medium", "high"})

# Maximum items per session — prevents a single session bloating memory.
_MAX_ITEMS = 200

# Maximum concurrent sessions stored in memory.
_MAX_SESSIONS = 500

# Bounded in-memory store:  OrderedDict preserves insertion order for FIFO eviction.
# Structure: { session_id: [ {id, title, notes, priority, due, done}, … ] }
_store: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_items() -> list[dict[str, Any]]:
    """
    Return (lazily creating) the item list for the current browser session.
    Evicts the oldest session if _MAX_SESSIONS is exceeded.
    """
    sid = session.setdefault("todo_sid", str(uuid.uuid4()))

    if sid not in _store:
        # Evict oldest session when the cap is reached.
        if len(_store) >= _MAX_SESSIONS:
            evicted = next(iter(_store))
            del _store[evicted]
            logger.debug("Todo store evicted oldest session: %s", evicted)
        _store[sid] = []
    else:
        # Move to end so recently-used sessions are evicted last.
        _store.move_to_end(sid)

    return _store[sid]


def _clean_str(value: Any, max_len: int = 500) -> str:
    """Coerce to str, strip whitespace, enforce max_len."""
    return str(value or "").strip()[:max_len]


# ── Page ──────────────────────────────────────────────────────────────────────

@todo_bp.get("/")
@todo_bp.get("")
def todo_page() -> ResponseReturnValue:
    return render_template("todo/todo.html")


# ── API ───────────────────────────────────────────────────────────────────────

@todo_bp.get("/api/items")
def api_list() -> ResponseReturnValue:
    return jsonify(_get_items())


@todo_bp.post("/api/items")
def api_add() -> ResponseReturnValue:
    body  = request.get_json(silent=True) or {}
    title = _clean_str(body.get("title"), max_len=200)
    if not title:
        return jsonify({"error": "Title is required"}), 400

    items = _get_items()
    if len(items) >= _MAX_ITEMS:
        return jsonify({"error": f"Maximum {_MAX_ITEMS} items per session"}), 400

    priority = body.get("priority", "medium")
    if priority not in _PRIORITIES:
        priority = "medium"

    item: dict[str, Any] = {
        "id":       str(uuid.uuid4()),
        "title":    title,
        "notes":    _clean_str(body.get("notes"), max_len=1000),
        "priority": priority,
        "due":      _clean_str(body.get("due"), max_len=10),
        "done":     False,
    }
    items.append(item)
    return jsonify(item), 201


@todo_bp.put("/api/items/<iid>")
def api_update(iid: str) -> ResponseReturnValue:
    body  = request.get_json(silent=True) or {}
    items = _get_items()

    for item in items:
        if item["id"] != iid:
            continue

        if "title" in body:
            title = _clean_str(body["title"], max_len=200)
            if not title:
                return jsonify({"error": "Title cannot be empty"}), 400
            item["title"] = title

        if "notes" in body:
            item["notes"] = _clean_str(body["notes"], max_len=1000)

        if "priority" in body:
            priority = body["priority"]
            item["priority"] = priority if priority in _PRIORITIES else "medium"

        if "due" in body:
            item["due"] = _clean_str(body["due"], max_len=10)

        if "done" in body:
            item["done"] = bool(body["done"])

        return jsonify(item)

    return jsonify({"error": "Not found"}), 404


@todo_bp.delete("/api/items/<iid>")
def api_delete(iid: str) -> ResponseReturnValue:
    items  = _get_items()
    before = len(items)
    items[:] = [i for i in items if i["id"] != iid]
    if len(items) == before:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"message": "Deleted"})
