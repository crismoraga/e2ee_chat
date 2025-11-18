"""Configuration values for the TEL252 E2EE chat API."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("E2E_CHAT_DATA_DIR", BASE_DIR / "data"))
USERS_FILE = DATA_DIR / "users.json"
MESSAGES_FILE = DATA_DIR / "messages.json"
SERVER_SECRET = os.environ.get("E2E_CHAT_SERVER_SECRET", "change-this-development-secret")
TOKEN_MAX_AGE = int(os.environ.get("E2E_CHAT_TOKEN_MAX_AGE", "3600"))

DATA_DIR.mkdir(parents=True, exist_ok=True)
