"""Cryptographic primitives and helpers for the TEL252 E2EE chat API."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


@dataclass(frozen=True)
class EncryptedMessage:
    """Container for AEAD encrypted payloads."""

    ciphertext: bytes
    nonce: bytes
    associated_data: bytes


def generate_identity_keypair() -> Tuple[bytes, bytes]:
    """Return a freshly generated X25519 key pair in raw byte form."""

    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def generate_signing_keypair() -> Tuple[bytes, bytes]:
    """Return an Ed25519 key pair in raw byte form."""

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def hkdf_sha3_256(secret: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    """Derive keying material using HKDF with SHA3-256."""

    if salt is None:
        salt = b"\x00" * hashlib.sha3_256().digest_size
    prk = hmac.new(salt, secret, hashlib.sha3_256).digest()
    okm = b""
    previous = b""
    counter = 1
    while len(okm) < length:
        data = previous + info + struct.pack("B", counter)
        previous = hmac.new(prk, data, hashlib.sha3_256).digest()
        okm += previous
        counter += 1
    return okm[:length]


def derive_shared_key(
    private_key_bytes: bytes,
    peer_public_key_bytes: bytes,
    context: bytes,
    length: int = 32,
) -> bytes:
    """Perform X25519 key agreement followed by HKDF-SHA3-256."""

    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return hkdf_sha3_256(shared_secret, salt=None, info=context, length=length)


def encrypt_chacha20poly1305(key: bytes, plaintext: bytes, aad: bytes) -> EncryptedMessage:
    """Encrypt plaintext with ChaCha20-Poly1305 and return the components."""

    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, aad)
    return EncryptedMessage(ciphertext=ciphertext, nonce=nonce, associated_data=aad)


def decrypt_chacha20poly1305(key: bytes, message: EncryptedMessage) -> bytes:
    """Decrypt a ChaCha20-Poly1305 encrypted payload."""

    aead = ChaCha20Poly1305(key)
    return aead.decrypt(message.nonce, message.ciphertext, message.associated_data)


def sign_ed25519(private_key_bytes: bytes, message: bytes) -> bytes:
    """Sign message bytes with an Ed25519 private key."""

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(message)


def verify_ed25519(public_key_bytes: bytes, signature: bytes, message: bytes) -> bool:
    """Return True when the signature verifies under the provided public key."""

    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def hash_password(password: str, pepper: str = "") -> str:
    """
    Hash a password with SHA3-512 using a server-side pepper.
    
    This approach complies with TEL252 Lab 7 restriction: "NO USAR SALT" (no per-user salt).
    Instead, we use a server-wide pepper (SECRET) to mitigate rainbow table attacks.
    
    Security analysis:
    - ✅ Cumple restricción del curso: No hay salt per-user
    - ⚠️ Vulnerabilidad: Sin work factor, contraseñas débiles son crackeables
    - ✅ Mitigación parcial: Pepper server-side añade entropía desconocida al atacante
    - 📚 Fundamentación: Clase 9 (Funciones Hash SHA-3)
    
    Args:
        password: User's password in plaintext
        pepper: Server-side secret (from config.SERVER_SECRET)
    
    Returns:
        Hexadecimal SHA3-512 hash (128 caracteres hex = 512 bits)
    
    Mathematical operation:
        hash = SHA3-512(password || pepper)
        where || denotes concatenation
    """
    from config import SERVER_SECRET
    
    if not pepper:
        pepper = SERVER_SECRET
    
    combined = password.encode("utf-8") + pepper.encode("utf-8")
    digest = hashlib.sha3_512(combined).hexdigest()
    return digest


def verify_password(password: str, stored_hash: str, pepper: str = "") -> bool:
    """
    Check a candidate password against the stored SHA3-512 hash.
    
    Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
    """
    candidate = hash_password(password, pepper)
    return hmac.compare_digest(candidate, stored_hash)



def generate_totp_secret(length: int = 20) -> str:
    """Return a Base32 encoded secret for TOTP authenticators."""

    secret = os.urandom(length)
    return base64.b32encode(secret).decode("ascii")


def _time_counter(interval: int, timestamp: Optional[int] = None) -> int:
    current_time = int(time.time()) if timestamp is None else int(timestamp)
    return current_time // interval


def generate_totp_code(secret: str, interval: int = 30, digits: int = 6, timestamp: Optional[int] = None) -> str:
    """Generate a TOTP code using HMAC-SHA1 as defined in RFC 6238."""

    key = base64.b32decode(secret, casefold=True)
    counter = _time_counter(interval, timestamp)
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (
        ((mac[offset] & 0x7F) << 24)
        | ((mac[offset + 1] & 0xFF) << 16)
        | ((mac[offset + 2] & 0xFF) << 8)
        | (mac[offset + 3] & 0xFF)
    )
    str_code = str(code % (10 ** digits)).zfill(digits)
    return str_code


def verify_totp_code(secret: str, code: str, interval: int = 30, digits: int = 6, window: int = 1) -> bool:
    """Verify a user supplied TOTP value within the provided tolerance window."""

    code = code.strip()
    if not code.isdigit() or len(code) != digits:
        return False
    for offset in range(-window, window + 1):
        timestamp = int(time.time()) + offset * interval
        expected = generate_totp_code(secret, interval=interval, digits=digits, timestamp=timestamp)
        if hmac.compare_digest(expected, code):
            return True
    return False


def create_session_token(phone: str, server_secret: str, issued_at: Optional[int] = None) -> str:
    """Create an HMAC protected session token scoped to the phone number."""

    issued = int(time.time()) if issued_at is None else int(issued_at)
    payload = f"{phone}:{issued}"
    mac = hmac.new(server_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha3_256).hexdigest()
    token = f"{payload}.{mac}"
    return token


def parse_session_token(token: str) -> Optional[Tuple[str, int, str]]:
    """Extract the payload components from a well-formed session token."""

    try:
        payload, mac_hex = token.rsplit(".", 1)
        phone, issued_str = payload.split(":", 1)
        issued = int(issued_str)
        return phone, issued, mac_hex
    except ValueError:
        return None


def verify_session_token(token: str, phone: str, server_secret: str, max_age: int = 3600) -> bool:
    """Validate a session token for the expected phone number and age."""

    parsed = parse_session_token(token)
    if parsed is None:
        return False
    token_phone, issued, mac_hex = parsed

    if token_phone != phone:
        return False

    if int(time.time()) - issued > max_age:
        return False

    payload = f"{token_phone}:{issued}"
    expected_mac = hmac.new(
        server_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha3_256
    ).hexdigest()

    return hmac.compare_digest(expected_mac, mac_hex)


def encode_bytes(data: bytes) -> str:
    """Return URL safe Base64 encoded string without padding."""

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_bytes(data: str) -> bytes:
    """Decode URL safe Base64 string produced by encode_bytes."""

    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
