"""Flask application entry point for the TEL252 E2EE chat API."""

from __future__ import annotations

import json
import time
from typing import Optional

from flask import Flask, jsonify, request, g

from config import SERVER_SECRET, TOKEN_MAX_AGE
from .auth import require_auth
from .crypto import (
    create_session_token,
    decode_bytes,
    encode_bytes,
    generate_identity_keypair,
    generate_signing_keypair,
    generate_totp_secret,
    hash_password,
    verify_ed25519,
    verify_password,
    verify_totp_code,
)
from .models import Message, User
from .storage import JsonStorage


def create_app(storage: Optional[JsonStorage] = None) -> Flask:
    app = Flask(__name__)
    storage = JsonStorage() if storage is None else storage
    app.config["storage"] = storage

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "timestamp": int(time.time())})

    @app.post("/register")
    def register():
        payload = request.get_json(force=True)
        phone = payload.get("phone", "").strip()
        password = payload.get("password", "")
        if not phone or not password:
            return jsonify({"error": "phone and password required"}), 400

        users = storage.load_users()
        if any(u.get("phone") == phone for u in users):
            return jsonify({"error": "phone already registered"}), 409

        password_hash = hash_password(password)
        totp_secret = generate_totp_secret()
        identity_private, identity_public = generate_identity_keypair()
        signing_private, signing_public = generate_signing_keypair()

        user = User(
            phone=phone,
            password_hash=password_hash,
            totp_secret=totp_secret,
            identity_public=encode_bytes(identity_public),
            signing_public=encode_bytes(signing_public),
        )

        users.append(user.to_dict())
        storage.save_users(users)

        provisioning_uri = (
            f"otpauth://totp/TEL252:{phone}?secret={totp_secret}&issuer=TEL252%20Chat"
        )

        return (
            jsonify(
                {
                    "message": "registered",
                    "phone": phone,
                    "totp_secret": totp_secret,
                    "totp_uri": provisioning_uri,
                    "identity": {
                        "public": user.identity_public,
                        "private": encode_bytes(identity_private),
                    },
                    "signing": {
                        "public": user.signing_public,
                        "private": encode_bytes(signing_private),
                    },
                }
            ),
            201,
        )

    @app.post("/login")
    def login():
        payload = request.get_json(force=True)
        phone = payload.get("phone", "")
        password = payload.get("password", "")
        totp_code = payload.get("totp", "")

        users = storage.load_users()
        user_dict = next((u for u in users if u.get("phone") == phone), None)
        if user_dict is None:
            return jsonify({"error": "invalid credentials"}), 401

        if not verify_password(password, user_dict.get("password_hash", "")):
            return jsonify({"error": "invalid credentials"}), 401

        if not verify_totp_code(user_dict.get("totp_secret", ""), totp_code):
            return jsonify({"error": "invalid totp"}), 401

        token = create_session_token(phone, SERVER_SECRET)
        return jsonify({"token": token, "expires_in": TOKEN_MAX_AGE})

    @app.post("/contacts")
    @require_auth
    def add_contact():
        payload = request.get_json(force=True)
        contact_phone = payload.get("phone", "").strip()
        if not contact_phone:
            return jsonify({"error": "contact phone required"}), 400

        storage_users = storage.load_users()
        me = next(u for u in storage_users if u.get("phone") == g.current_user["phone"])
        if contact_phone == me["phone"]:
            return jsonify({"error": "cannot add self"}), 400

        if not any(u.get("phone") == contact_phone for u in storage_users):
            return jsonify({"error": "contact not registered"}), 404

        contacts = set(me.get("contacts", []))
        contacts.add(contact_phone)
        me["contacts"] = sorted(contacts)
        storage.save_users(storage_users)

        return jsonify({"message": "contact added", "contacts": me["contacts"]})

    @app.get("/profile")
    @require_auth
    def profile():
        user = g.current_user
        return jsonify(
            {
                "phone": user["phone"],
                "contacts": user.get("contacts", []),
                "identity_public": user["identity_public"],
                "signing_public": user["signing_public"],
            }
        )

    @app.post("/messages")
    @require_auth
    def send_message():
        payload = request.get_json(force=True)
        recipient = payload.get("recipient", "").strip()
        ciphertext = payload.get("ciphertext", "")
        nonce = payload.get("nonce", "")
        aad = payload.get("aad", "")
        signature = payload.get("signature", "")

        if not recipient or not ciphertext or not nonce or not aad or not signature:
            return jsonify({"error": "missing fields"}), 400

        storage_users = storage.load_users()
        sender = g.current_user
        me_contacts = set(sender.get("contacts", []))
        if recipient not in me_contacts:
            return jsonify({"error": "recipient not in contacts"}), 403

        recipient_user = next((u for u in storage_users if u.get("phone") == recipient), None)
        if recipient_user is None:
            return jsonify({"error": "recipient not registered"}), 404

        if sender["phone"] not in recipient_user.get("contacts", []):
            return jsonify({"error": "recipient has not added you"}), 403

        try:
            aad_payload = json.loads(decode_bytes(aad).decode("utf-8"))
        except Exception:
            return jsonify({"error": "invalid aad payload"}), 400

        if aad_payload.get("sender") != sender["phone"] or aad_payload.get("recipient") != recipient:
            return jsonify({"error": "aad mismatch"}), 400

        if not verify_ed25519(
            decode_bytes(sender["signing_public"]),
            decode_bytes(signature),
            f"{ciphertext}:{nonce}:{aad}".encode("utf-8"),
        ):
            return jsonify({"error": "invalid signature"}), 400

        message = Message(
            sender=sender["phone"],
            recipient=recipient,
            ciphertext=ciphertext,
            nonce=nonce,
            aad=aad,
            signature=signature,
            timestamp=int(time.time()),
        )

        messages = storage.load_messages()
        messages.append(message.to_dict())
        storage.save_messages(messages)

        return jsonify({"message": "delivered"}), 202

    @app.get("/messages")
    @require_auth
    def list_messages():
        peer = request.args.get("peer", "").strip()
        user_phone = g.current_user["phone"]
        messages = storage.load_messages()
        filtered = [
            msg
            for msg in messages
            if (msg["sender"] == user_phone and (peer == "" or msg["recipient"] == peer))
            or (msg["recipient"] == user_phone and (peer == "" or msg["sender"] == peer))
        ]
        return jsonify({"messages": filtered})

    @app.post("/keys/derive")
    @require_auth
    def derive_pairwise_key():
        payload = request.get_json(force=True)
        peer_phone = payload.get("peer", "").strip()
        if not peer_phone:
            return jsonify({"error": "missing parameters"}), 400

        storage_users = storage.load_users()
        me = g.current_user
        peer = next((u for u in storage_users if u.get("phone") == peer_phone), None)
        if peer is None:
            return jsonify({"error": "peer not registered"}), 404

        if peer_phone not in me.get("contacts", []):
            return jsonify({"error": "peer not in contacts"}), 403

        return jsonify(
            {
                "context": f"TEL252-E2EE:{me['phone']}:{peer_phone}",
                "peer_identity_public": peer["identity_public"],
                "peer_signing_public": peer["signing_public"],
            }
        )

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(debug=True)
