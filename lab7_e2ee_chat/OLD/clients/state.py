"""Persistent state management for local chat clients."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


DEFAULT_STATE_DIR = Path("clients/state")
DEFAULT_STATE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class ContactState:
    phone: str
    shared_key: Optional[str] = None
    context: Optional[str] = None
    identity_public: Optional[str] = None
    signing_public: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "phone": self.phone,
            "shared_key": self.shared_key,
            "context": self.context,
            "identity_public": self.identity_public,
            "signing_public": self.signing_public,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "ContactState":
        return cls(
            phone=data["phone"],
            shared_key=data.get("shared_key"),
            context=data.get("context"),
            identity_public=data.get("identity_public"),
            signing_public=data.get("signing_public"),
        )


@dataclass
class ClientState:
    phone: str
    totp_secret: str
    identity_private: str
    identity_public: str
    signing_private: str
    signing_public: str
    session_token: Optional[str] = None
    session_issued_at: Optional[int] = None
    contacts: Dict[str, ContactState] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "phone": self.phone,
            "totp_secret": self.totp_secret,
            "identity_private": self.identity_private,
            "identity_public": self.identity_public,
            "signing_private": self.signing_private,
            "signing_public": self.signing_public,
            "session_token": self.session_token,
            "session_issued_at": self.session_issued_at,
            "contacts": {phone: contact.to_dict() for phone, contact in self.contacts.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "ClientState":
        contacts_raw = data.get("contacts", {}) or {}
        contacts = {
            phone: ContactState.from_dict(contact)
            for phone, contact in contacts_raw.items()
        }
        return cls(
            phone=data["phone"],
            totp_secret=data["totp_secret"],
            identity_private=data["identity_private"],
            identity_public=data["identity_public"],
            signing_private=data["signing_private"],
            signing_public=data["signing_public"],
            session_token=data.get("session_token"),
            session_issued_at=data.get("session_issued_at"),
            contacts=contacts,
        )


def _state_path(phone: str, base_dir: Path = DEFAULT_STATE_DIR) -> Path:
    normalized = phone.replace("+", "").replace(" ", "")
    return base_dir / f"{normalized}.json"


def load_state(phone: str, base_dir: Path = DEFAULT_STATE_DIR) -> Optional[ClientState]:
    path = _state_path(phone, base_dir)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return ClientState.from_dict(data)


def save_state(state: ClientState, base_dir: Path = DEFAULT_STATE_DIR) -> None:
    path = _state_path(state.phone, base_dir)
    path.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")


def delete_state(phone: str, base_dir: Path = DEFAULT_STATE_DIR) -> None:
    path = _state_path(phone, base_dir)
    if path.exists():
        path.unlink()
