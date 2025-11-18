import base64
import os
import tempfile
from pathlib import Path

import pytest

from lab7_e2ee_chat import crypto
from lab7_e2ee_chat.database import Database
from lab7_e2ee_chat.server import create_app


@pytest.fixture()
def app():
    """
    Flask app fixture with temporary database.
    
    Note: On Windows, SQLite may hold file locks causing teardown warnings.
    This is expected behavior and doesn't affect test validity.
    """
    os.environ["CHAT_SESSION_SECRET"] = "tests_session_secret_key"
    os.environ["CHAT_PASSWORD_SECRET"] = "tests_password_secret_key"

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        database = Database(db_path=db_path)
        flask_app = create_app(database=database)
        flask_app.config.update(TESTING=True)
        yield flask_app
        # Explicitly close connections before cleanup
        database.close_all_connections()
        import time
        time.sleep(0.1)  # Brief pause for Windows to release file locks


@pytest.fixture()
def client(app):
    return app.test_client()


def register_and_login(client, identifier, display_name, password):
    register_resp = client.post(
        "/api/register",
        json={"identifier": identifier, "display_name": display_name, "password": password},
    )
    assert register_resp.status_code == 201
    totp_secret = register_resp.get_json()["totp_secret"]
    totp_code = crypto.generate_totp(totp_secret)

    login_resp = client.post(
        "/api/login",
        json={"identifier": identifier, "password": password, "totp_code": totp_code},
    )
    assert login_resp.status_code == 200
    token = login_resp.get_json()["token"]
    return token, totp_secret


def register_device(client, token, identifier, device_name, public_key_pem):
    response = client.post(
        "/api/devices",
        headers={"Authorization": f"Bearer {token}"},
        json={"device_name": device_name, "public_key_pem": public_key_pem},
    )
    assert response.status_code == 201


def send_encrypted_message(
    client,
    token,
    *,
    plaintext,
    sender_identifier,
    recipient_identifier,
    recipient_public_pem,
):
    session_key_b64, nonce_b64, ciphertext_b64, tag_b64 = crypto.encrypt_payload(
        plaintext.encode("utf-8"),
        associated_data=f"sender={sender_identifier}".encode("utf-8"),
    )
    session_key_bytes = base64.urlsafe_b64decode(session_key_b64.encode("utf-8"))
    encrypted_session_key = crypto.encrypt_session_key_with_rsa(recipient_public_pem, session_key_bytes)
    associated_data_b64 = base64.urlsafe_b64encode(f"sender={sender_identifier}".encode("utf-8")).decode("utf-8")

    return client.post(
        "/api/messages",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "recipient_identifier": recipient_identifier,
            "session_key_encrypted": encrypted_session_key,
            "nonce_b64": nonce_b64,
            "ciphertext_b64": ciphertext_b64,
            "tag_b64": tag_b64,
            "associated_data_b64": associated_data_b64,
        },
    )


def test_full_message_roundtrip(client):
    alice_token, _ = register_and_login(client, "alice@example.com", "Alice", "StrongPass!123")
    bob_token, _ = register_and_login(client, "bob@example.com", "Bob", "OtherPass!456")

    alice_private, alice_public = crypto.generate_rsa_keypair()
    bob_private, bob_public = crypto.generate_rsa_keypair()

    register_device(client, alice_token, "alice@example.com", "Alice Browser", alice_public)
    register_device(client, bob_token, "bob@example.com", "Bob Browser", bob_public)

    send_resp = send_encrypted_message(
        client,
        alice_token,
        plaintext="Hola Bob, mensaje cifrado desde PyTest!",
        sender_identifier="alice@example.com",
        recipient_identifier="bob@example.com",
        recipient_public_pem=bob_public,
    )
    assert send_resp.status_code == 201

    inbox_resp = client.get(
        "/api/messages",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert inbox_resp.status_code == 200
    messages = inbox_resp.get_json()["messages"]
    assert len(messages) == 1
    message = messages[0]

    decrypted_session_key = crypto.decrypt_session_key_with_rsa(bob_private, message["session_key_encrypted"])
    session_key_b64_roundtrip = base64.urlsafe_b64encode(decrypted_session_key).decode("utf-8")
    plaintext = crypto.decrypt_payload(
        session_key_b64_roundtrip,
        message["nonce_b64"],
        message["ciphertext_b64"],
        message["tag_b64"],
        associated_data=base64.urlsafe_b64decode(message["associated_data_b64"].encode("utf-8"))
        if message.get("associated_data_b64")
        else b"",
    )

    assert plaintext.decode("utf-8") == "Hola Bob, mensaje cifrado desde PyTest!"

    # Clean up message from queue and ensure deletion works
    delete_resp = client.delete(
        f"/api/messages/{message['id']}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert delete_resp.status_code == 204

    empty_resp = client.get(
        "/api/messages",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert empty_resp.status_code == 200
    assert empty_resp.get_json()["messages"] == []


def test_login_rejects_invalid_totp(client):
    register_resp = client.post(
        "/api/register",
        json={
            "identifier": "charlie@example.com",
            "display_name": "Charlie",
            "password": "BadPass#123",
        },
    )
    assert register_resp.status_code == 201
    totp_secret = register_resp.get_json()["totp_secret"]
    correct_code = crypto.generate_totp(totp_secret)
    wrong_code = "000000" if correct_code != "000000" else "111111"

    login_resp = client.post(
        "/api/login",
        json={
            "identifier": "charlie@example.com",
            "password": "BadPass#123",
            "totp_code": wrong_code,
        },
    )
    assert login_resp.status_code == 401
    assert "invalid code" in login_resp.get_json()["error"]


def test_send_requires_authentication(client):
    response = client.post(
        "/api/messages",
        json={"recipient_identifier": "nobody", "ciphertext_b64": ""},
    )
    assert response.status_code == 401
    assert "Missing bearer token" in response.get_json()["error"]


def test_inbox_isolated_per_user(client):
    alice_token, _ = register_and_login(client, "alice2@example.com", "Alice2", "StrongPass!123")
    bob_token, _ = register_and_login(client, "bob2@example.com", "Bob2", "OtherPass!456")

    _, alice_public = crypto.generate_rsa_keypair()
    bob_private, bob_public = crypto.generate_rsa_keypair()

    register_device(client, alice_token, "alice2@example.com", "Alice2 Browser", alice_public)
    register_device(client, bob_token, "bob2@example.com", "Bob2 Browser", bob_public)

    send_resp = send_encrypted_message(
        client,
        alice_token,
        plaintext="Solo Bob debería leer esto",
        sender_identifier="alice2@example.com",
        recipient_identifier="bob2@example.com",
        recipient_public_pem=bob_public,
    )
    assert send_resp.status_code == 201

    alice_inbox = client.get(
        "/api/messages",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_inbox.status_code == 200
    assert alice_inbox.get_json()["messages"] == []

    bob_inbox = client.get(
        "/api/messages",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert bob_inbox.status_code == 200
    messages = bob_inbox.get_json()["messages"]
    assert len(messages) == 1

    decrypted_session_key = crypto.decrypt_session_key_with_rsa(
        bob_private, messages[0]["session_key_encrypted"]
    )
    session_key_b64_roundtrip = base64.urlsafe_b64encode(decrypted_session_key).decode("utf-8")
    plaintext = crypto.decrypt_payload(
        session_key_b64_roundtrip,
        messages[0]["nonce_b64"],
        messages[0]["ciphertext_b64"],
        messages[0]["tag_b64"],
        associated_data=base64.urlsafe_b64decode(messages[0]["associated_data_b64"].encode("utf-8")),
    )

    assert plaintext.decode("utf-8") == "Solo Bob debería leer esto"
