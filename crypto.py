"""Cryptographic primitives for the TEL252 end-to-end encrypted chat demo.

This module centralises every cryptographic building block used by the project.
All functions are deliberately thin wrappers with extensive documentation so the
cryptographic reasoning behind each call is explicit for educational purposes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# ---------------------------------------------------------------------------
# Password authentication (HMAC-SHA256)
# ---------------------------------------------------------------------------

PASSWORD_MAC_ALGO = hashlib.sha256


def hash_password(password: str, secret: bytes) -> str:
    """Produce an HMAC-SHA256 digest for ``password`` using ``secret``.

    This mirrors the MAC construction revisited in Symmetric Crypto III
    (Clase 11). Instead of PBKDF2, we rely on a high-entropy secret key that
    lives solely on the server. Students can inspect how HMAC authenticates the
    password material with a single hashing pass.
    """

    mac = hmac.new(secret, password.encode("utf-8"), PASSWORD_MAC_ALGO).digest()
    return base64.urlsafe_b64encode(mac).decode("utf-8")


def verify_password(password: str, digest_b64: str, secret: bytes) -> bool:
    """Check ``password`` against the stored HMAC digest."""

    expected = base64.urlsafe_b64decode(digest_b64)
    candidate = hmac.new(secret, password.encode("utf-8"), PASSWORD_MAC_ALGO).digest()
    return hmac.compare_digest(candidate, expected)


# ---------------------------------------------------------------------------
# Time-based One-Time Password (TOTP) according to RFC 6238
# ---------------------------------------------------------------------------

TOTP_DIGITS = 6
TOTP_TIME_STEP = 30  # seconds


def generate_totp_secret() -> str:
    """Create a new 160-bit secret encoded in base32 for authenticator apps."""

    return base64.b32encode(get_random_bytes(20)).decode("utf-8").strip("=")


def _totp_counter(timestamp: Optional[int] = None, step: int = TOTP_TIME_STEP) -> int:
    """Compute the moving factor (time counter) used in TOTP."""

    if timestamp is None:
        timestamp = int(time.time())
    return timestamp // step


def generate_totp(secret: str, timestamp: Optional[int] = None) -> str:
    """Generate an RFC 6238 compliant TOTP code for the provided secret."""

    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    counter = _totp_counter(timestamp)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (
        ((h[offset] & 0x7F) << 24)
        | ((h[offset + 1] & 0xFF) << 16)
        | ((h[offset + 2] & 0xFF) << 8)
        | (h[offset + 3] & 0xFF)
    )
    return str(code_int % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Validate a TOTP code, allowing a time drift defined by ``window``.

    The server accepts codes from the current time-step plus/minus ``window``
    steps to mitigate clock drift between client and server devices.
    """

    now = int(time.time())
    for offset in range(-window, window + 1):
        timestamp = now + offset * TOTP_TIME_STEP
        if hmac.compare_digest(generate_totp(secret, timestamp), code):
            return True
    return False


# ---------------------------------------------------------------------------
# RSA helpers
# ---------------------------------------------------------------------------

RSA_KEY_SIZE = 2048


def generate_rsa_keypair(bits: int = RSA_KEY_SIZE) -> Tuple[str, str]:
    """Generate an RSA keypair (PEM encoded) using PyCryptodome.

    Returns the private and public key PEM strings. These keys are used by the
    clients to exchange ephemeral AES session keys securely (via RSA-OAEP).
    """

    key = RSA.generate(bits)
    private_pem = key.export_key(format="PEM").decode("utf-8")
    public_pem = key.publickey().export_key(format="PEM").decode("utf-8")
    return private_pem, public_pem


def encrypt_session_key_with_rsa(public_key_pem: str, session_key: bytes) -> str:
    """Encrypt a random AES session key using RSA-OAEP.

    The ciphertext is returned base64-encoded so that it can be safely
    transported over JSON without binary issues.
    """

    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted = cipher_rsa.encrypt(session_key)
    return base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_session_key_with_rsa(private_key_pem: str, encrypted_b64: str) -> bytes:
    """Inverse operation of :func:`encrypt_session_key_with_rsa`."""

    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    encrypted = base64.urlsafe_b64decode(encrypted_b64)
    return cipher_rsa.decrypt(encrypted)


# ---------------------------------------------------------------------------
# Symmetric encryption (AES-256-GCM)
# ---------------------------------------------------------------------------

AES_KEY_SIZE = 32  # 256-bit symmetric key
GCM_NONCE_SIZE = 12  # 96-bit nonce recommended by NIST


def encrypt_payload(plaintext: bytes, associated_data: bytes = b"") -> Tuple[str, str, str, str]:
    """Encrypt ``plaintext`` with AES-256-GCM and return base64 artefacts.

    The function internally generates a fresh random session key which must be
    distributed using RSA. Returning both the session key and ciphertext keeps
    the server agnostic about the actual message contents.
    """

    session_key = get_random_bytes(AES_KEY_SIZE)
    nonce = get_random_bytes(GCM_NONCE_SIZE)

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return (
        base64.urlsafe_b64encode(session_key).decode("utf-8"),
        base64.urlsafe_b64encode(nonce).decode("utf-8"),
        base64.urlsafe_b64encode(ciphertext).decode("utf-8"),
        base64.urlsafe_b64encode(tag).decode("utf-8"),
    )


def decrypt_payload(
    session_key_b64: str,
    nonce_b64: str,
    ciphertext_b64: str,
    tag_b64: str,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt AES-GCM artefacts created by :func:`encrypt_payload`."""

    session_key = base64.urlsafe_b64decode(session_key_b64)
    nonce = base64.urlsafe_b64decode(nonce_b64)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    tag = base64.urlsafe_b64decode(tag_b64)

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ---------------------------------------------------------------------------
# Session tokens (HMAC-SHA256 protected JSON)
# ---------------------------------------------------------------------------

SESSION_TOKEN_TTL = 60 * 60  # 1 hour


def _sign(session_data: dict, secret: bytes) -> str:
    payload = json.dumps(session_data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    mac = hmac.new(secret, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("utf-8"), payload


def create_session_token(user_id: int, secret: bytes, ttl: int = SESSION_TOKEN_TTL) -> str:
    """Create a tamper-evident session token signed with HMAC-SHA256.

    The token structure is ``header.payload.signature`` all base64 encoded.
    This is intentionally similar to JWTs but implemented manually for
    educational transparency.
    """

    issued_at = int(time.time())
    session_data = {"uid": user_id, "iat": issued_at, "exp": issued_at + ttl}
    signature, payload = _sign(session_data, secret)
    header = base64.urlsafe_b64encode(b"TEL252-HMAC").decode("utf-8")
    return ".".join([
        header,
        base64.urlsafe_b64encode(payload).decode("utf-8"),
        signature,
    ])


def verify_session_token(token: str, secret: bytes) -> Optional[dict]:
    """Verify integrity and expiration of a session token."""

    try:
        header_b64, payload_b64, signature = token.split(".")
        if header_b64 != base64.urlsafe_b64encode(b"TEL252-HMAC").decode("utf-8"):
            return None
        payload = base64.urlsafe_b64decode(payload_b64)
        expected_sig = hmac.new(secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(base64.urlsafe_b64decode(signature), expected_sig):
            return None
        session_data = json.loads(payload.decode("utf-8"))
        if session_data.get("exp", 0) < time.time():
            return None
        return session_data
    except (ValueError, json.JSONDecodeError, binascii.Error):
        return None


# ---------------------------------------------------------------------------
# Utility dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EncryptedMessage:
    """Convenience container representing the artefacts stored for each message."""

    sender_id: int
    recipient_id: int
    session_key_encrypted: str
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str
    associated_data_b64: str = ""


@dataclass(frozen=True)
class PublicIdentity:
    """Expose user metadata alongside their RSA public key."""

    identifier: str
    display_name: str
    public_key_pem: str
