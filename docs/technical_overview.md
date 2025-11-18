# Technical Overview – TEL252 E2EE Chat

This document walks through every component in the codebase, summarising responsibilities, key functions, and security considerations.

## Module: `crypto.py`

| Section | Responsibility | Key Functions |
| --- | --- | --- |
| Password Authentication | Compute HMAC-SHA256 digests using a server-held secret (pepper), following Clase 11 MAC construction. | `hash_password`, `verify_password` |
| TOTP | Implement RFC 6238 with a 30-second time step, SHA-1, and ±1 drift tolerance. | `generate_totp_secret`, `generate_totp`, `verify_totp` |
| RSA Helpers | Produce RSA-2048 key pairs and wrap/unwrap AES session keys using OAEP with SHA-256. | `generate_rsa_keypair`, `encrypt_session_key_with_rsa`, `decrypt_session_key_with_rsa` |
| Symmetric Encryption | Perform authenticated encryption with AES-256-GCM, returning base64 artefacts for JSON transport. | `encrypt_payload`, `decrypt_payload` |
| Session Tokens | Create and validate HMAC-SHA256 protected tokens inspired by compact JWTs. | `create_session_token`, `verify_session_token` |
| Dataclasses | Make encrypted records explicit and self-documenting. | `EncryptedMessage`, `PublicIdentity` |

All functions are intentionally thin wrappers so that students can audit or replicate the primitives manually during assessments.

## Module: `config.py`

- Resolves the root project directory and canonical SQLite database location.
- Provides `load_session_secret()` which retrieves or generates a 256-bit HMAC key, optionally honouring the `CHAT_SESSION_SECRET` environment override.

## Module: `database.py`

- Ensures the SQLite schema exists (idempotent on every start).
- Stores:
  - `users`: identifier, display name, HMAC password digest, TOTP secret.
  - `devices`: user-bound RSA-2048 public keys (multi-device capable via unique pair).
  - `messages`: encrypted payload metadata (RSA-OAEP wrapped AES key, nonce, ciphertext, tag, optional AAD).
- Exposes CRUD helpers consumed by the Flask app: `create_user`, `get_user_by_identifier`, `register_device`, `store_message`, `fetch_messages_for_user`, etc.

## Module: `server.py`

- Builds the Flask application via `create_app()`.
- Injects a lightweight authentication decorator `login_required` that validates bearer tokens using the cryptographic primitives.
- Endpoints cover:
  - `/api/register`: Onboards users after validating fields, returning TOTP secret.
  - `/api/login`: Validates password + TOTP, issues signed session token.
  - `/api/devices` (GET/POST): Upload and list RSA public keys per user.
  - `/api/users`: Directory lookup for contact discovery including public keys.
  - `/api/messages` (POST/GET/DELETE): Persist opaque encrypted messages, retrieve inbox, and delete after processing.
- Separates transport validation from cryptographic enforcement: the server never decrypts payloads and only manipulates base64 artefacts.

## Module: `client_cli.py`

An educational command-line client that simulates real-world interaction without GUI complexity.

Key behaviours:

1. **Registration**
   - Sends account data to the API, stores returned TOTP secret locally, and generates an RSA key pair immediately for convenience.
2. **Login**
   - Derives a live TOTP code using the same algorithm as the server, proving code path symmetry.
   - Saves HMAC session token for subsequent requests.
3. **Device Registration**
   - Uploads the PEM-encoded RSA public key to the server so others can address encrypted messages.
4. **Message Workflow**
   - Retrieves recipient public keys, encrypts plaintext with AES-256-GCM, wraps the session key via RSA-OAEP, and posts the artefacts to `/api/messages`.
   - Decrypts inbox items by reversing the process, verifying tags, and revealing only authenticated plaintext.
5. **Utility Commands**
   - Displaying current TOTPs and deleting consumed messages emphasise operational hygiene.

Profiles are stored under `%USERPROFILE%\.tel252_chat`, allowing several accounts to coexist during grading.

## Database Schema Narrative

```text
users
 ├─ id INTEGER PRIMARY KEY
 ├─ identifier TEXT UNIQUE (correo/teléfono)
 ├─ display_name TEXT
 ├─ password_hash TEXT (base64 HMAC-SHA256)
 ├─ totp_secret TEXT (base32)
 └─ created_at DATETIME

devices
 ├─ id INTEGER PRIMARY KEY
 ├─ user_id INTEGER REFERENCES users(id)
 ├─ device_name TEXT
 ├─ public_key_pem TEXT
 └─ created_at DATETIME

messages
 ├─ id INTEGER PRIMARY KEY
 ├─ sender_id INTEGER REFERENCES users(id)
 ├─ recipient_id INTEGER REFERENCES users(id)
 ├─ session_key_encrypted TEXT (RSA OAEP, base64)
 ├─ nonce_b64 TEXT (AES-GCM nonce)
 ├─ ciphertext_b64 TEXT
 ├─ tag_b64 TEXT (GCM authenticator)
 ├─ associated_data_b64 TEXT
 └─ created_at DATETIME
```

## Security Notes for Evaluators

- **No plaintext at rest**: Inspecting `chat.db` reveals only random-looking strings. Without the device private key, an attacker cannot reconstruct the session key or decrypt messages.
- **Integrity-first handling**: Any modification to ciphertext, nonce, tag, or associated data raises during decryption because AES-GCM binds them together.
- **Replay mitigation**: Clients delete processed messages. Additionally, since session keys are random per message, replays cannot be interpreted without reusing associated data verbatim, which is detectable.
- **TOTP drift**: `verify_totp` accepts ±1 time-step to accommodate clock skew (a lab-friendly trade-off).

## How to Extend Safely

- Introduce message read receipts by signing status updates with the sender’s RSA key (detached signatures).
- Add forward secrecy by switching RSA to X25519 pre-keys and deriving symmetric keys via HKDF.
- Implement push notifications through Server-Sent Events or WebSockets without altering the cryptographic core.

This overview, combined with in-code comments, should equip graders with a full understanding of how each primitive integrates into the broader E2EE workflow.
