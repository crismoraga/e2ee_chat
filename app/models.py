"""Data models for persistent entities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .crypto import encode_bytes

@dataclass
class User:
    phone: str
    password_hash: str
    totp_secret: str
    identity_public: str
    signing_public: str
    contacts: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "phone": self.phone,
            "password_hash": self.password_hash,
            "totp_secret": self.totp_secret,
            "identity_public": self.identity_public,
            "signing_public": self.signing_public,
            "contacts": self.contacts,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        return cls(
            phone=data["phone"],
            password_hash=data["password_hash"],
            totp_secret=data["totp_secret"],
            identity_public=data["identity_public"],
            signing_public=data["signing_public"],
            contacts=list(data.get("contacts", [])),
        )


@dataclass
class Message:
    sender: str
    recipient: str
    ciphertext: str
    nonce: str
    aad: str
    signature: str
    timestamp: int

    def to_dict(self) -> dict:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "ciphertext": self.ciphertext,
            "nonce": self.nonce,
            "aad": self.aad,
            "signature": self.signature,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_components(
        cls,
        sender: str,
        recipient: str,
        ciphertext: bytes,
        nonce: bytes,
        aad: bytes,
        signature: bytes,
        timestamp: int,
    ) -> "Message":
        return cls(
            sender=sender,
            recipient=recipient,
            ciphertext=encode_bytes(ciphertext),
            nonce=encode_bytes(nonce),
            aad=encode_bytes(aad),
            signature=encode_bytes(signature),
            timestamp=timestamp,
        )
