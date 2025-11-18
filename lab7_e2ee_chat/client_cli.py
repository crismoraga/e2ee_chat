"""Command-line demo client for the TEL252 E2EE chat API."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import textwrap
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from . import crypto

API_BASE = os.environ.get("CHAT_API_BASE", "http://127.0.0.1:5000")
PROFILE_DIR = Path(os.environ.get("CHAT_PROFILE_DIR", Path.home() / ".tel252_chat"))
PROFILE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class Profile:
    identifier: str
    display_name: str
    totp_secret: str
    private_key_pem: str
    public_key_pem: str
    password: str
    session_token: Optional[str] = None

    @property
    def storage_path(self) -> Path:
        return PROFILE_DIR / f"{self.identifier.replace('@', '_at_')}.json"

    def save(self) -> None:
        data = asdict(self)
        self.storage_path.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, identifier: str) -> "Profile":
        path = PROFILE_DIR / f"{identifier.replace('@', '_at_')}.json"
        if not path.exists():
            raise SystemExit(f"Profile for {identifier} not found. Run the register command first.")
        data = json.loads(path.read_text())
        return cls(**data)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def api_post(path: str, payload: Dict[str, Any], token: Optional[str] = None) -> Dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.post(f"{API_BASE}{path}", headers=headers, data=json.dumps(payload), timeout=10)
    if response.status_code >= 400:
        try:
            error = response.json().get("error")
        except ValueError:
            error = response.text
        raise SystemExit(f"API error {response.status_code}: {error}")
    return response.json()


def api_get(path: str, token: Optional[str] = None) -> Dict[str, Any]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(f"{API_BASE}{path}", headers=headers, timeout=10)
    if response.status_code >= 400:
        try:
            error = response.json().get("error")
        except ValueError:
            error = response.text
        raise SystemExit(f"API error {response.status_code}: {error}")
    return response.json()


def api_delete(path: str, token: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(f"{API_BASE}{path}", headers=headers, timeout=10)
    if response.status_code >= 400:
        try:
            error = response.json().get("error")
        except ValueError:
            error = response.text
        raise SystemExit(f"API error {response.status_code}: {error}")


# ---------------------------------------------------------------------------
# CLI actions
# ---------------------------------------------------------------------------


def cmd_register(args: argparse.Namespace) -> None:
    payload = {
        "identifier": args.identifier,
        "display_name": args.display_name,
        "password": args.password,
    }
    response = api_post("/api/register", payload)
    private_key_pem, public_key_pem = crypto.generate_rsa_keypair()

    profile = Profile(
        identifier=response["identifier"],
        display_name=response["display_name"],
        totp_secret=response["totp_secret"],
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        password=args.password,
    )
    profile.save()

    print("Registration successful! Store this TOTP secret in an authenticator app:")
    print(response["totp_secret"])  # noqa: T201
    print("A local profile has been created at", profile.storage_path)  # noqa: T201


def cmd_login(args: argparse.Namespace) -> None:
    profile = Profile.load(args.identifier)
    totp_code = crypto.generate_totp(profile.totp_secret)
    payload = {
        "identifier": profile.identifier,
        "password": profile.password,
        "totp_code": totp_code,
    }
    response = api_post("/api/login", payload)
    profile.session_token = response["token"]
    profile.save()
    print("Logged in successfully. Session token saved.")  # noqa: T201
    print("Current TOTP code:", totp_code)  # noqa: T201


def cmd_register_device(args: argparse.Namespace) -> None:
    profile = Profile.load(args.identifier)
    if not profile.session_token:
        raise SystemExit("Login first to obtain a session token.")

    payload = {
        "device_name": args.device_name,
        "public_key_pem": profile.public_key_pem,
    }
    response = api_post("/api/devices", payload, token=profile.session_token)
    print(f"Device registered with id {response['device_id']}")  # noqa: T201


def cmd_contacts(args: argparse.Namespace) -> None:
    profile = Profile.load(args.identifier)
    if not profile.session_token:
        raise SystemExit("Login first to obtain a session token.")

    response = api_get("/api/users", token=profile.session_token)
    if not response.get("contacts"):
        print("No other users yet. Share the API with a friend!")  # noqa: T201
        return

    print("Available contacts:")  # noqa: T201
    for contact in response["contacts"]:
        status = "✅" if contact.get("public_key_pem") else "⚠️"
        print(f"  {status} {contact['identifier']} ({contact['display_name']})")  # noqa: T201


def cmd_send(args: argparse.Namespace) -> None:
    profile = Profile.load(args.identifier)
    if not profile.session_token:
        raise SystemExit("Login first to obtain a session token.")

    recipient = api_get(f"/api/users/{args.recipient}", token=profile.session_token)
    public_key_pem = recipient.get("public_key_pem")
    if not public_key_pem:
        raise SystemExit("Recipient has not registered a device/public key yet.")

    session_key_b64, nonce_b64, ciphertext_b64, tag_b64 = crypto.encrypt_payload(
        args.message.encode("utf-8"),
        associated_data=f"sender={profile.identifier}".encode("utf-8"),
    )
    session_key_bytes = base64.urlsafe_b64decode(session_key_b64.encode("utf-8"))
    encrypted_session_key = crypto.encrypt_session_key_with_rsa(public_key_pem, session_key_bytes)

    payload = {
        "recipient_identifier": args.recipient,
        "session_key_encrypted": encrypted_session_key,
        "nonce_b64": nonce_b64,
        "ciphertext_b64": ciphertext_b64,
        "tag_b64": tag_b64,
        "associated_data_b64": base64.urlsafe_b64encode(
            f"sender={profile.identifier}".encode("utf-8")
        ).decode("utf-8"),
    }

    response = api_post("/api/messages", payload, token=profile.session_token)
    print(f"Message stored with id {response['message_id']}")  # noqa: T201


def cmd_inbox(args: argparse.Namespace) -> None:
    profile = Profile.load(args.identifier)
    if not profile.session_token:
        raise SystemExit("Login first to obtain a session token.")

    response = api_get("/api/messages", token=profile.session_token)
    messages = response.get("messages", [])
    if not messages:
        print("Inbox empty.")  # noqa: T201
        return

    for entry in messages:
        try:
            session_key_bytes = crypto.decrypt_session_key_with_rsa(
                profile.private_key_pem,
                entry["session_key_encrypted"],
            )
            session_key_b64 = base64.urlsafe_b64encode(session_key_bytes).decode("utf-8")
            associated_data = entry.get("associated_data_b64") or ""
            associated_bytes = (
                base64.urlsafe_b64decode(associated_data.encode("utf-8")) if associated_data else b""
            )
            plaintext = crypto.decrypt_payload(
                session_key_b64,
                entry["nonce_b64"],
                entry["ciphertext_b64"],
                entry["tag_b64"],
                associated_data=associated_bytes,
            )
            associated_text = associated_bytes.decode("utf-8") if associated_bytes else ""
        except Exception as exc:  # noqa: BLE001
            print(f"Message {entry['id']} could not be decrypted: {exc}")  # noqa: T201
            continue

        ts = entry.get("created_at") or ""
        print("-" * 60)  # noqa: T201
        print(f"Message {entry['id']} from {entry['sender_identifier']} at {ts}")  # noqa: T201
        if associated_text:
            print(f"  associated data: {associated_text}")  # noqa: T201
        print("  decrypted text:")  # noqa: T201
        print(textwrap.indent(plaintext.decode("utf-8"), "    "))  # noqa: T201


def cmd_delete(args: argparse.Namespace) -> None:
    profile = Profile.load(args.identifier)
    if not profile.session_token:
        raise SystemExit("Login first to obtain a session token.")

    api_delete(f"/api/messages/{args.message_id}", token=profile.session_token)
    print(f"Message {args.message_id} deleted from the server.")  # noqa: T201


def cmd_totp(args: argparse.Namespace) -> None:
    profile = Profile.load(args.identifier)
    code = crypto.generate_totp(profile.totp_secret)
    remaining = 30 - (int(datetime.utcnow().timestamp()) % 30)
    print(f"Current TOTP code: {code} (valid for {remaining}s)")  # noqa: T201


# ---------------------------------------------------------------------------
# CLI bootstrap
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")

    p_register = sub.add_parser("register", help="Register a new account")
    p_register.add_argument("identifier", help="Email or phone number")
    p_register.add_argument("display_name", help="Human readable name")
    p_register.add_argument("password", help="Strong account password")
    p_register.set_defaults(func=cmd_register)

    p_login = sub.add_parser("login", help="Authenticate using password + TOTP")
    p_login.add_argument("identifier", help="Registered identifier")
    p_login.set_defaults(func=cmd_login)

    p_device = sub.add_parser("register-device", help="Upload the local RSA public key")
    p_device.add_argument("identifier", help="Registered identifier")
    p_device.add_argument("device_name", help="Device label, e.g., Laptop")
    p_device.set_defaults(func=cmd_register_device)

    p_contacts = sub.add_parser("contacts", help="List known users")
    p_contacts.add_argument("identifier", help="Registered identifier")
    p_contacts.set_defaults(func=cmd_contacts)

    p_send = sub.add_parser("send", help="Send an encrypted message")
    p_send.add_argument("identifier", help="Sender identifier")
    p_send.add_argument("recipient", help="Recipient identifier")
    p_send.add_argument("message", help="Plaintext message to encrypt and send")
    p_send.set_defaults(func=cmd_send)

    p_inbox = sub.add_parser("inbox", help="Decrypt pending messages")
    p_inbox.add_argument("identifier", help="Registered identifier")
    p_inbox.set_defaults(func=cmd_inbox)

    p_delete = sub.add_parser("delete", help="Delete a message from the server")
    p_delete.add_argument("identifier", help="Registered identifier")
    p_delete.add_argument("message_id", type=int, help="Server message identifier")
    p_delete.set_defaults(func=cmd_delete)

    p_totp = sub.add_parser("totp", help="Display the current TOTP code")
    p_totp.add_argument("identifier", help="Registered identifier")
    p_totp.set_defaults(func=cmd_totp)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
