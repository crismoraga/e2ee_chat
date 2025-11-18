"""Flask API exposing the TEL252 end-to-end encrypted chat service."""

from __future__ import annotations

import functools
import sqlite3
from pathlib import Path
from typing import Callable, Optional

from flask import Flask, jsonify, request, send_from_directory

from . import crypto
from .config import load_password_secret, load_session_secret
from .database import Database


def create_app(database: Optional[Database] = None) -> Flask:
    app = Flask(__name__)

    db = database or Database()
    session_secret = load_session_secret()
    password_secret = load_password_secret()
    web_client_dir = Path(__file__).resolve().parent / "web_client"

    def _auth_header_token() -> Optional[str]:
        header = request.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            return header.split(" ", 1)[1].strip()
        return None

    def _require_auth() -> tuple:
        token = _auth_header_token()
        if not token:
            return None, ("Missing bearer token", 401)

        session_data = crypto.verify_session_token(token, session_secret)
        if not session_data:
            return None, ("Invalid or expired session", 401)

        user = db.get_user_by_id(session_data["uid"])
        if not user:
            return None, ("Unknown session user", 401)

        return (token, session_data, user), None

    def login_required(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            auth_context, error = _require_auth()
            if error:
                message, status = error
                return jsonify({"error": message}), status
            token, session_data, user = auth_context
            return func(*args, auth_token=token, session=session_data, user=user, **kwargs)

        return wrapper

    # ---------------------------------------------------------------
    # Health check
    # ---------------------------------------------------------------

    @app.get("/healthz")
    def healthcheck():
        return jsonify({"status": "ok"})

    @app.get("/")
    def root():
        if web_client_dir.exists():
            return jsonify({"message": "TEL252 chat API", "ui": "/ui/"})
        return jsonify({"message": "TEL252 chat API"})

    @app.get("/ui/")
    def ui_entrypoint():
        if not web_client_dir.exists():
            return jsonify({"error": "UI assets not found"}), 404
        return send_from_directory(web_client_dir, "index.html")

    @app.get("/ui/<path:filename>")
    def ui_assets(filename: str):
        if not web_client_dir.exists():
            return jsonify({"error": "UI assets not found"}), 404
        return send_from_directory(web_client_dir, filename)

    # ---------------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------------

    @app.post("/api/register")
    def register():
        payload = request.get_json() or {}

        identifier = (payload.get("identifier") or "").strip()
        display_name = (payload.get("display_name") or "").strip()
        password = payload.get("password") or ""

        if not identifier or not display_name or not password:
            return (
                jsonify({"error": "identifier, display_name and password are required"}),
                400,
            )

        if db.get_user_by_identifier(identifier) is not None:
            return jsonify({"error": "identifier already registered"}), 409

        password_hash = crypto.hash_password(password, password_secret)
        totp_secret = crypto.generate_totp_secret()
        user_id = db.create_user(identifier, display_name, password_hash, totp_secret)

        return (
            jsonify(
                {
                    "id": user_id,
                    "identifier": identifier,
                    "display_name": display_name,
                    "totp_secret": totp_secret,
                }
            ),
            201,
        )

    @app.post("/api/login")
    def login():
        payload = request.get_json() or {}

        identifier = (payload.get("identifier") or "").strip()
        password = payload.get("password") or ""
        totp_code = (payload.get("totp_code") or "").strip()

        if not identifier or not password or not totp_code:
            return jsonify({"error": "identifier, password and totp_code are required"}), 400

        user = db.get_user_by_identifier(identifier)
        if not user:
            return jsonify({"error": "invalid credentials"}), 401

        if not crypto.verify_password(password, user["password_hash"], password_secret):
            return jsonify({"error": "invalid credentials"}), 401

        if not crypto.verify_totp(user["totp_secret"], totp_code):
            return jsonify({"error": "invalid code"}), 401

        token = crypto.create_session_token(user["id"], session_secret)
        return jsonify(
            {
                "token": token,
                "user": {
                    "id": user["id"],
                    "identifier": user["identifier"],
                    "display_name": user["display_name"],
                },
            }
        )

    # ---------------------------------------------------------------
    # Device / key management
    # ---------------------------------------------------------------

    @app.post("/api/devices")
    @login_required
    def register_device(*, user, **_):
        payload = request.get_json() or {}
        device_name = (payload.get("device_name") or "").strip()
        public_key_pem = payload.get("public_key_pem") or ""

        if not device_name or not public_key_pem:
            return jsonify({"error": "device_name and public_key_pem are required"}), 400

        if "BEGIN PUBLIC KEY" not in public_key_pem:
            return jsonify({"error": "public_key_pem must be a PEM encoded key"}), 400

        try:
            device_id = db.register_device(user["id"], device_name, public_key_pem)
        except sqlite3.IntegrityError:
            return jsonify({"error": "device name already registered"}), 409

        return jsonify({"device_id": device_id}), 201

    @app.get("/api/devices")
    @login_required
    def list_devices(*, user, **_):
        records = db.list_devices(user["id"])
        return jsonify(
            {
                "devices": [
                    {
                        "id": row["id"],
                        "device_name": row["device_name"],
                        "public_key_pem": row["public_key_pem"],
                        "created_at": row["created_at"],
                    }
                    for row in records
                ]
            }
        )

    # ---------------------------------------------------------------
    # Directory
    # ---------------------------------------------------------------

    @app.get("/api/users")
    @login_required
    def directory(*, user, **_):
        contacts = []
        for row in db.list_users(exclude_user_id=user["id"]):
            public_key = db.get_primary_public_key(row["id"])
            contacts.append(
                {
                    "id": row["id"],
                    "identifier": row["identifier"],
                    "display_name": row["display_name"],
                    "public_key_pem": public_key,
                }
            )
        return jsonify({"contacts": contacts})

    @app.get("/api/users/<identifier>")
    @login_required
    def user_details(identifier: str, **_):
        row = db.get_user_by_identifier(identifier)
        if not row:
            return jsonify({"error": "user not found"}), 404

        public_key = db.get_primary_public_key(row["id"])
        return jsonify(
            {
                "id": row["id"],
                "identifier": row["identifier"],
                "display_name": row["display_name"],
                "public_key_pem": public_key,
            }
        )

    # ---------------------------------------------------------------
    # Messaging
    # ---------------------------------------------------------------

    def _build_encrypted_message(sender_row, payload: dict) -> Optional[crypto.EncryptedMessage]:
        required_fields = (
            "recipient_identifier",
            "session_key_encrypted",
            "nonce_b64",
            "ciphertext_b64",
            "tag_b64",
        )
        for field in required_fields:
            if not payload.get(field):
                return None

        recipient_row = db.get_user_by_identifier(payload["recipient_identifier"])
        if not recipient_row:
            return None

        return crypto.EncryptedMessage(
            sender_id=sender_row["id"],
            recipient_id=recipient_row["id"],
            session_key_encrypted=payload["session_key_encrypted"],
            nonce_b64=payload["nonce_b64"],
            ciphertext_b64=payload["ciphertext_b64"],
            tag_b64=payload["tag_b64"],
            associated_data_b64=payload.get("associated_data_b64", ""),
        )

    @app.post("/api/messages")
    @login_required
    def send_message(*, user, **_):
        payload = request.get_json() or {}
        message = _build_encrypted_message(user, payload)
        if not message:
            return jsonify({"error": "invalid message payload"}), 400

        message_id = db.store_message(message)
        return jsonify({"message_id": message_id}), 201

    @app.get("/api/messages")
    @login_required
    def inbox(*, user, **_):
        records = db.fetch_messages_for_user(user["id"])
        return jsonify(
            {
                "messages": [
                    {
                        "id": row["id"],
                        "sender_identifier": row["sender_identifier"],
                        "sender_display_name": row["sender_display_name"],
                        "session_key_encrypted": row["session_key_encrypted"],
                        "nonce_b64": row["nonce_b64"],
                        "ciphertext_b64": row["ciphertext_b64"],
                        "tag_b64": row["tag_b64"],
                        "associated_data_b64": row["associated_data_b64"],
                        "created_at": row["created_at"],
                    }
                    for row in records
                ]
            }
        )

    @app.delete("/api/messages/<int:message_id>")
    @login_required
    def delete_message(message_id: int, *, user, **_):
        db.delete_message(message_id, user["id"])
        return ("", 204)

    return app


if __name__ == "__main__":
    api = create_app()
    api.run(host="0.0.0.0", port=5000, debug=True)
