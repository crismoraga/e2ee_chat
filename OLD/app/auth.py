"""Authentication helpers for protecting Flask routes."""

from __future__ import annotations

from functools import wraps
from typing import Callable, Dict, Optional

from flask import current_app, g, jsonify, request

from config import SERVER_SECRET, TOKEN_MAX_AGE

from .crypto import parse_session_token, verify_session_token


def _get_storage():
    storage = current_app.config.get("storage")
    if storage is None:
        raise RuntimeError("Storage backend is not configured on the Flask application")
    return storage


def _find_user(phone: str) -> Optional[Dict[str, str]]:
    storage = _get_storage()
    users = storage.load_users()
    for user in users:
        if user.get("phone") == phone:
            return user
    return None


def require_auth(view: Callable) -> Callable:
    """Decorator that enforces session token authentication."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "missing bearer token"}), 401

        token = header.split(" ", 1)[1].strip()
        parsed = parse_session_token(token)
        if parsed is None:
            return jsonify({"error": "invalid token format"}), 401

        phone, _, _ = parsed
        user = _find_user(phone)
        if user is None:
            return jsonify({"error": "unknown session"}), 401

        if not verify_session_token(token, phone, SERVER_SECRET, TOKEN_MAX_AGE):
            return jsonify({"error": "expired or invalid token"}), 401

        g.current_user = user
        g.current_token = token
        return view(*args, **kwargs)

    return wrapper
