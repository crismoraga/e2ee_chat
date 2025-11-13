from __future__ import annotations

import json
import time

from app.crypto import (
    EncryptedMessage,
    decode_bytes,
    derive_shared_key,
    encode_bytes,
    encrypt_chacha20poly1305,
    generate_totp_code,
    sign_ed25519,
    decrypt_chacha20poly1305,
)


def register_user(client, phone: str, password: str):
    response = client.post(
        "/register",
        json={"phone": phone, "password": password},
    )
    assert response.status_code == 201
    data = response.get_json()
    return data


def login_user(client, phone: str, password: str, totp_secret: str):
    totp = generate_totp_code(totp_secret)
    response = client.post(
        "/login",
        json={"phone": phone, "password": password, "totp": totp},
    )
    assert response.status_code == 200
    data = response.get_json()
    return data["token"]


def test_full_chat_flow(client):
    alice = register_user(client, "+56911111111", "wonderland")
    bob = register_user(client, "+56922222222", "builder")

    alice_token = login_user(client, "+56911111111", "wonderland", alice["totp_secret"])
    bob_token = login_user(client, "+56922222222", "builder", bob["totp_secret"])

    # Alice adds Bob and Bob adds Alice
    response = client.post(
        "/contacts",
        json={"phone": "+56922222222"},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert response.status_code == 200

    response = client.post(
        "/contacts",
        json={"phone": "+56911111111"},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert response.status_code == 200

    # Alice fetches peer info for Bob
    response = client.post(
        "/keys/derive",
        json={"peer": "+56922222222"},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert response.status_code == 200
    alice_context = response.get_json()

    # Bob fetches peer info for Alice (verifies mutual state)
    response = client.post(
        "/keys/derive",
        json={"peer": "+56911111111"},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert response.status_code == 200

    # Alice encrypts a message to Bob using the shared key
    shared_key = derive_shared_key(
        decode_bytes(alice["identity"]["private"]),
        decode_bytes(alice_context["peer_identity_public"]),
        alice_context["context"].encode("utf-8"),
    )
    aad_payload = {
        "sender": "+56911111111",
        "recipient": "+56922222222",
        "timestamp": int(time.time()),
        "context": alice_context["context"],
    }
    aad_bytes = json.dumps(aad_payload, separators=(",", ":")).encode("utf-8")
    encrypted = encrypt_chacha20poly1305(shared_key, b"Hola Bob!", aad_bytes)

    ciphertext_b64 = encode_bytes(encrypted.ciphertext)
    nonce_b64 = encode_bytes(encrypted.nonce)
    aad_b64 = encode_bytes(encrypted.associated_data)
    signature = sign_ed25519(
        decode_bytes(alice["signing"]["private"]),
        f"{ciphertext_b64}:{nonce_b64}:{aad_b64}".encode("utf-8"),
    )

    response = client.post(
        "/messages",
        json={
            "recipient": "+56922222222",
            "ciphertext": ciphertext_b64,
            "nonce": nonce_b64,
            "aad": aad_b64,
            "signature": encode_bytes(signature),
        },
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert response.status_code == 202

    # Bob retrieves the messages and ensures Alice's message is present
    response = client.get(
        "/messages",
        query_string={"peer": "+56911111111"},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert response.status_code == 200
    messages = response.get_json()["messages"]
    assert len(messages) == 1
    stored = messages[0]
    assert stored["sender"] == "+56911111111"
    assert stored["recipient"] == "+56922222222"
    assert stored["ciphertext"] == ciphertext_b64
    assert stored["nonce"] == nonce_b64
    assert stored["aad"] == aad_b64

    encrypted_record = EncryptedMessage(
        ciphertext=decode_bytes(stored["ciphertext"]),
        nonce=decode_bytes(stored["nonce"]),
        associated_data=decode_bytes(stored["aad"]),
    )
    shared_key_bob = derive_shared_key(
        decode_bytes(bob["identity"]["private"]),
        decode_bytes(alice["identity"]["public"]),
        alice_context["context"].encode("utf-8"),
    )
    plaintext = decrypt_chacha20poly1305(shared_key_bob, encrypted_record)
    assert plaintext == b"Hola Bob!"