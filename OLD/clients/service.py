"""High-level client for interacting with the TEL252 E2EE chat API."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import requests

from app.crypto import (
    EncryptedMessage,
    decode_bytes,
    derive_shared_key,
    encode_bytes,
    encrypt_chacha20poly1305,
    decrypt_chacha20poly1305,
    generate_totp_code,
    sign_ed25519,
    verify_ed25519,
)
from clients.state import ClientState, ContactState, DEFAULT_STATE_DIR, load_state, save_state


class APIError(RuntimeError):
    """Raised when the remote API returns an unexpected result."""


@dataclass
class DecryptedMessage:
    direction: str
    sender: str
    recipient: str
    plaintext: Optional[str]
    timestamp: int
    valid_signature: bool
    raw: Dict[str, object]


class E2EEChatClient:
    """Convenience wrapper that keeps local secrets and interacts with the API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:5000",
        state_dir: Path = DEFAULT_STATE_DIR,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.state_dir = Path(state_dir)
        self.timeout = timeout
        self._http = requests.Session()

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------
    def _state_path(self, phone: str) -> Path:
        return self.state_dir / f"{phone.replace('+', '').replace(' ', '')}.json"

    def get_state(self, phone: str) -> Optional[ClientState]:
        return load_state(phone, self.state_dir)

    def _require_state(self, phone: str) -> ClientState:
        state = self.get_state(phone)
        if state is None:
            raise APIError(f"No local state found for {phone}. Register first.")
        return state

    def _save_state(self, state: ClientState) -> None:
        save_state(state, self.state_dir)

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _headers(self, state: ClientState) -> Dict[str, str]:
        if not state.session_token:
            raise APIError("This account is not logged in. Call login() first.")
        return {"Authorization": f"Bearer {state.session_token}"}

    # ------------------------------------------------------------------
    # API operations
    # ------------------------------------------------------------------
    def register(self, phone: str, password: str) -> ClientState:
        response = self._http.post(
            self._url("/register"),
            json={"phone": phone, "password": password},
            timeout=self.timeout,
        )
        if response.status_code != 201:
            raise APIError(f"Registration failed: {response.text}")
        data = response.json()

        identity = data["identity"]
        signing = data["signing"]

        state = ClientState(
            phone=phone,
            totp_secret=data["totp_secret"],
            identity_private=identity["private"],
            identity_public=identity["public"],
            signing_private=signing["private"],
            signing_public=signing["public"],
        )
        self._save_state(state)
        return state, {"totp_uri": data["totp_uri"]}

    def login(self, phone: str, password: str, totp: Optional[str] = None) -> ClientState:
        state = self._require_state(phone)
        code = totp or generate_totp_code(state.totp_secret)

        response = self._http.post(
            self._url("/login"),
            json={"phone": phone, "password": password, "totp": code},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise APIError(f"Login failed: {response.text}")

        data = response.json()
        state.session_token = data["token"]
        state.session_issued_at = int(time.time())
        self._save_state(state)
        return state

    def add_contact(self, phone: str, contact_phone: str) -> Dict[str, object]:
        state = self._require_state(phone)
        response = self._http.post(
            self._url("/contacts"),
            json={"phone": contact_phone},
            headers=self._headers(state),
            timeout=self.timeout,
        )
        if response.status_code not in (200, 201):
            raise APIError(f"Unable to add contact: {response.text}")

        contact_info = response.json()
        self._bootstrap_contact(state, contact_phone)
        return contact_info

    def _bootstrap_contact(self, state: ClientState, contact_phone: str) -> ContactState:
        response = self._http.post(
            self._url("/keys/derive"),
            json={"peer": contact_phone},
            headers=self._headers(state),
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise APIError(f"Unable to obtain peer keys: {response.text}")

        data = response.json()
        context = data["context"]
        peer_identity_public = data["peer_identity_public"]
        peer_signing_public = data["peer_signing_public"]

        shared_key = derive_shared_key(
            decode_bytes(state.identity_private),
            decode_bytes(peer_identity_public),
            context=context.encode("utf-8"),
        )

        contact_state = ContactState(
            phone=contact_phone,
            shared_key=encode_bytes(shared_key),
            context=context,
            identity_public=peer_identity_public,
            signing_public=peer_signing_public,
        )
        state.contacts[contact_phone] = contact_state
        self._save_state(state)
        return contact_state

    def list_contacts(self, phone: str) -> Dict[str, ContactState]:
        state = self._require_state(phone)
        return state.contacts

    def send_message(self, phone: str, recipient: str, plaintext: str) -> Dict[str, object]:
        state = self._require_state(phone)
        contact = state.contacts.get(recipient)
        if contact is None or not contact.shared_key:
            contact = self._bootstrap_contact(state, recipient)

        shared_key = decode_bytes(contact.shared_key)

        aad_payload = {
            "sender": phone,
            "recipient": recipient,
            "timestamp": int(time.time()),
            "context": contact.context,
        }
        aad_bytes = json.dumps(aad_payload, separators=(",", ":")).encode("utf-8")

        encrypted = encrypt_chacha20poly1305(shared_key, plaintext.encode("utf-8"), aad_bytes)

        ciphertext_b64 = encode_bytes(encrypted.ciphertext)
        nonce_b64 = encode_bytes(encrypted.nonce)
        aad_b64 = encode_bytes(encrypted.associated_data)

        signature = sign_ed25519(
            decode_bytes(state.signing_private),
            f"{ciphertext_b64}:{nonce_b64}:{aad_b64}".encode("utf-8"),
        )

        response = self._http.post(
            self._url("/messages"),
            json={
                "recipient": recipient,
                "ciphertext": ciphertext_b64,
                "nonce": nonce_b64,
                "aad": aad_b64,
                "signature": encode_bytes(signature),
            },
            headers=self._headers(state),
            timeout=self.timeout,
        )

        if response.status_code not in (200, 202):
            raise APIError(f"Message delivery failed: {response.text}")

        return response.json()

    def fetch_messages(self, phone: str, peer: Optional[str] = None) -> List[DecryptedMessage]:
        state = self._require_state(phone)

        params = {"peer": peer} if peer else None
        response = self._http.get(
            self._url("/messages"),
            params=params,
            headers=self._headers(state),
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise APIError(f"Unable to retrieve messages: {response.text}")

        messages = response.json().get("messages", [])
        decrypted: List[DecryptedMessage] = []
        for item in messages:
            decrypted.append(self._decrypt_message(state, item))
        return decrypted

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _decrypt_message(self, state: ClientState, message: Dict[str, object]) -> DecryptedMessage:
        sender = message["sender"]
        recipient = message["recipient"]
        direction = "outgoing" if sender == state.phone else "incoming"
        peer_phone = recipient if direction == "outgoing" else sender

        contact = state.contacts.get(peer_phone)
        if contact is None or not contact.shared_key:
            # Without shared key we cannot decrypt or verify the message.
            return DecryptedMessage(
                direction=direction,
                sender=sender,
                recipient=recipient,
                plaintext=None,
                timestamp=message["timestamp"],
                valid_signature=False,
                raw=message,
            )

        ciphertext = decode_bytes(message["ciphertext"])
        nonce = decode_bytes(message["nonce"])
        aad = decode_bytes(message["aad"])
        signature = decode_bytes(message["signature"])

        try:
            aad_payload = json.loads(aad.decode("utf-8"))
        except Exception:
            aad_payload = {}

        expected_context = contact.context
        context_matches = aad_payload.get("context") == expected_context

        valid_signature = False
        if contact.signing_public:
            valid_signature = verify_ed25519(
                decode_bytes(contact.signing_public),
                signature,
                f"{message['ciphertext']}:{message['nonce']}:{message['aad']}".encode("utf-8"),
            )

        plaintext: Optional[str]
        try:
            shared_key = decode_bytes(contact.shared_key)
            decrypted_bytes = decrypt_chacha20poly1305(
                shared_key,
                EncryptedMessage(ciphertext=ciphertext, nonce=nonce, associated_data=aad),
            )
            plaintext = decrypted_bytes.decode("utf-8")
        except Exception:
            plaintext = None

        if not context_matches:
            valid_signature = False

        return DecryptedMessage(
            direction=direction,
            sender=sender,
            recipient=recipient,
            plaintext=plaintext,
            timestamp=message["timestamp"],
            valid_signature=valid_signature,
            raw=message,
        )

    def generate_totp(self, phone: str) -> str:
        state = self._require_state(phone)
        return generate_totp_code(state.totp_secret)
