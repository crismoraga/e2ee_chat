"""Thread-safe JSON storage helpers for the TEL252 chat server."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List

from config import MESSAGES_FILE, USERS_FILE


class JsonStorage:
    """Provide synchronized access to the JSON persistence files."""

    def __init__(self, users_path: Path = USERS_FILE, messages_path: Path = MESSAGES_FILE) -> None:
        self.users_path = users_path
        self.messages_path = messages_path
        self._users_lock = Lock()
        self._messages_lock = Lock()
        self._ensure_file(self.users_path, {"users": []})
        self._ensure_file(self.messages_path, {"messages": []})

    @staticmethod
    def _ensure_file(path: Path, template: Dict[str, Any]) -> None:
        if not path.exists():
            path.write_text(json.dumps(template, indent=2), encoding="utf-8")

    def load_users(self) -> List[Dict[str, Any]]:
        with self._users_lock:
            data = json.loads(self.users_path.read_text(encoding="utf-8"))
            return data.get("users", [])

    def save_users(self, users: List[Dict[str, Any]]) -> None:
        with self._users_lock:
            wrapped = json.dumps({"users": users}, indent=2)
            self.users_path.write_text(wrapped, encoding="utf-8")

    def load_messages(self) -> List[Dict[str, Any]]:
        with self._messages_lock:
            data = json.loads(self.messages_path.read_text(encoding="utf-8"))
            return data.get("messages", [])

    def save_messages(self, messages: List[Dict[str, Any]]) -> None:
        with self._messages_lock:
            wrapped = json.dumps({"messages": messages}, indent=2)
            self.messages_path.write_text(wrapped, encoding="utf-8")
