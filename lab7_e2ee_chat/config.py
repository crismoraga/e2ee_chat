"""Central configuration helpers for the TEL252 chat demo."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "chat.db"
SESSION_SECRET_FILE = BASE_DIR / ".session_secret"
PASSWORD_SECRET_FILE = BASE_DIR / ".password_secret"


def load_session_secret() -> bytes:
    """Return a stable HMAC secret, generating it on first use."""

    if "CHAT_SESSION_SECRET" in os.environ:
        return os.environ["CHAT_SESSION_SECRET"].encode("utf-8")

    if SESSION_SECRET_FILE.exists():
        return SESSION_SECRET_FILE.read_bytes()

    secret = os.urandom(32)
    SESSION_SECRET_FILE.write_bytes(secret)
    return secret


def load_password_secret() -> bytes:
    """Return the symmetric key used for HMAC-based password digests."""

    if "CHAT_PASSWORD_SECRET" in os.environ:
        return os.environ["CHAT_PASSWORD_SECRET"].encode("utf-8")

    if PASSWORD_SECRET_FILE.exists():
        return PASSWORD_SECRET_FILE.read_bytes()

    secret = os.urandom(32)
    PASSWORD_SECRET_FILE.write_bytes(secret)
    return secret
