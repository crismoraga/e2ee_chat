# TEL252 Lab 7 – End-to-End Encrypted Chat API

This project implements a demonstrable end-to-end encrypted (E2EE) chat experience for TEL252. It combines symmetric and asymmetric cryptography, password hashing, Time-based One-Time Passwords (TOTP), and HMAC-protected session tokens. A lightweight Flask API coordinates authentication, device key management, and message relay without ever seeing plaintext messages.

## Features at a Glance

- Account onboarding with HMAC-SHA256 password digests (server-held secret) and RFC 6238 compatible TOTPs.
- HMAC-SHA256 signed session tokens for stateless authentication.
- Device public-key registry holding PEM-encoded RSA-2048 keys for every user.
- Client-driven AES-256-GCM encryption with per-message random session keys.
- RSA-OAEP wrapping of session keys so only intended recipients can decrypt.
- SQLite persistence keeping the server self-contained and easy to demo.
- Command-line demo client that can register, authenticate, exchange keys, send encrypted messages, and decrypt inbox items locally.
- Extensive inline documentation and separations of concerns to highlight the cryptographic reasoning.

## Repository Layout

```text
lab7_e2ee_chat/
├── __init__.py            # Package marker
├── client_cli.py          # CLI demo client
├── config.py              # Configuration helpers (DB path, HMAC secret)
├── crypto.py              # Primitivas criptográficas (HMAC-SHA256, TOTP, RSA-OAEP, AES-GCM)
├── database.py            # SQLite wrapper (users, devices, messages)
├── docs/
│   └── architecture.mmd   # Mermaid sequence diagram of message exchange
├── README.md              # This document
└── server.py              # Flask API implementation
```

## Running the API Locally

### Quick Start (3 Steps)

1. **Install dependencies:**

   ```pwsh
   pip install -r requirements.txt
   ```

2. **Launch the server:**

   ```pwsh
   # HTTP local rápido
   python iniciar_servidor.py --host 127.0.0.1 --port 5000

   # Demostración TLS lista para Wireshark (certificado auto-firmado)
   python iniciar_servidor.py --tls --host 0.0.0.0 --port 5443
   ```

   The launcher wraps `create_app()` and exposes convenient flags (`--tls`, `--cert`, `--key`). The legacy
   `python -m lab7_e2ee_chat.server` entry point remains available if you prefer the classic workflow.

3. **Choose your interface:**

   - **Web Client:** Open `http://localhost:5000/ui/` in your browser
   - **CLI Client:** See commands below
   - **Automated Tests:** Run `python -m pytest tests/test_flow.py -v`

### Web Client (Recommended)

1. Navigate to `http://localhost:5000/ui/`
2. **Register** with email, name, and password
3. **Save TOTP secret** – scan the QR or keep the Base32 string safe. The UI stores it encrypted in `localStorage` so you can auto-generar códigos TOTP.
4. **Login** with email + password + TOTP code. Select the session in the new dropdown to reutilizar tokens en cada formulario.
5. **Register your device key** (generated with Web Crypto) and **exchange messages** using the contacts sidebar and chat viewer to prove that solo los participantes descifran la conversación.

**Features:**

- Local persistence (tokens, TOTP secrets, PEMs) via `localStorage` for multi-session demos without retyping secrets.
- Session selector + contactos interactivos para fijar conversaciones y ver burbujas entrantes/salientes descifradas localmente.
- Generate RSA-2048 keys in browser using Web Crypto API and upload only the public PEM.
- AES-256-GCM encryption happens locally before sending to the server, which never sees plaintext.

### Docker Deployment

```pwsh
# Build image
docker build -t tel252-e2ee-chat .

# Run container
docker run -p 5000:5000 `
  -e CHAT_SESSION_SECRET="your_256bit_secret" `
  -e CHAT_PASSWORD_SECRET="your_256bit_pepper" `
  tel252-e2ee-chat
```

---

## Command-Line Demo Client

The supplied CLI illustrates a full end-to-end flow using only the API surface. Every significant cryptographic operation happens client-side.

### 1. Register Two Accounts

```pwsh
python -m lab7_e2ee_chat.client_cli register alice@example.com "Alice" StrongPass!123
python -m lab7_e2ee_chat.client_cli register bob@example.com "Bob" OtherPass!456
```

Each command outputs a TOTP secret. Scan it with an authenticator app or keep it in a safe place. A local profile is saved under `%USERPROFILE%\.tel252_chat` containing the RSA key pair and other metadata.

### 2. Login and Register Devices

```pwsh
python -m lab7_e2ee_chat.client_cli login alice@example.com
python -m lab7_e2ee_chat.client_cli register-device alice@example.com "Alice Laptop"

python -m lab7_e2ee_chat.client_cli login bob@example.com
python -m lab7_e2ee_chat.client_cli register-device bob@example.com "Bob Desktop"
```

The login command automatically computes a current TOTP code from the stored secret. The `register-device` command uploads the locally generated RSA-2048 public key to the server.

### 3. List Contacts and Exchange Messages

```pwsh
python -m lab7_e2ee_chat.client_cli contacts alice@example.com
python -m lab7_e2ee_chat.client_cli send alice@example.com bob@example.com "Hola Bob, esto está cifrado de extremo a extremo!"
python -m lab7_e2ee_chat.client_cli inbox bob@example.com
```

Bob’s inbox command fetches encrypted messages, unwraps the AES session key with his private RSA key, and decrypts the ciphertext locally. The server never learns the plaintext.

### 4. Delete Messages After Reading

```pwsh
python -m lab7_e2ee_chat.client_cli delete bob@example.com 1
```

Removes a message from the server once it has been consumed. (Replace `1` with the actual message id printed in the inbox output.)

### Useful Extras

- `python -m lab7_e2ee_chat.client_cli totp alice@example.com` prints the current TOTP code and remaining validity window.
- Set the environment variable `CHAT_API_BASE` if the Flask server runs on another host or port.

## API Reference

All endpoints reside under `/api` and expect/return JSON.

| Endpoint | Method | Description |
| --- | --- | --- |
| `/healthz` | GET | Simple heartbeat probe |
| `/api/register` | POST | Create a user account. Returns a TOTP secret and metadata. |
| `/api/login` | POST | Authenticate with password + TOTP; returns session token. |
| `/api/devices` | POST | Register a device public key (requires `Authorization: Bearer`). |
| `/api/devices` | GET | List registered devices for the current user. |
| `/api/users` | GET | Directory of other users and their latest public key. |
| `/api/users/<identifier>` | GET | Detailed view of a user (public key, display name). |
| `/api/messages` | POST | Store an encrypted message for a recipient. |
| `/api/messages` | GET | Retrieve encrypted messages addressed to the caller. |
| `/api/messages/<id>` | DELETE | Remove a message (ownership enforced). |

### Authentication Protocol

- Session tokens follow a compact `header.payload.signature` format signed with HMAC-SHA256.
- Tokens expire after 1 hour. Clients should re-authenticate as needed.
- All protected endpoints require the header `Authorization: Bearer <token>`.

## Cryptographic Design Choices

| Component | Primitive | Parameters | Rationale |
| --- | --- | --- | --- |
| Autenticación de contraseñas | HMAC-SHA256 | Llave de 256-bit en el servidor (pepper) | Construcción MAC de Clase 11; evita almacenar salts manteniendo los digests opacos a atacantes. |
| Second factor | RFC 6238 TOTP | SHA-1, 30s window, ±1 drift | Compatible with authenticator apps; user can audit implementation in `crypto.py`. |
| Device identity | RSA-2048 + OAEP | SHA-256 padding hash | Widely taught in TEL252, readily interoperable, sufficient security margin. |
| Content confidentiality | AES-256-GCM | Random 96-bit nonce per message | Provides confidentiality and integrity without manual MAC management. |
| Session tokens | HMAC-SHA256 | Local 256-bit secret | Simplicity and full transparency instead of opaque JWT black boxes. |

Additional security considerations:

- **Server blindness:** Messages arrive already encrypted. Only the recipient’s private key can unwrap the session key. Even administrators cannot decrypt stored ciphertexts.
- **Integrity:** AES-GCM tags and OAEP ensure tamper attempts surface immediately.
- **Replay protection:** Clients delete or mark messages once processed. GCM tags bind the nonce and associated data, making replays detectable.
- **Associated Data (AAD):** Senders attach `sender=<identifier>` as AAD to prove the sender identity during decryption without revealing plaintext to the server.
- **Transport security:** For production use, run Flask behind HTTPS. For the lab demo, loopback plaintext is acceptable.

## Database Schema Overview

- **users**: core profile data, password hash artefacts, TOTP secret.
- **devices**: per-user RSA public keys, allowing multi-device support.
- **messages**: encrypted payload plus metadata (nonce, tag, optional AAD).

Schema migrations are handled automatically on application start-up.

## Diagram

A full sequence diagram describing registration, login, device provisioning, and message exchange lives in [`docs/architecture.mmd`](docs/architecture.mmd). The file uses Mermaid syntax and can be rendered via VS Code’s Mermaid preview or online editors such as <https://mermaid.live>.

## Testing the Encryption Guarantee

1. **View what the server stores:** Inspect `lab7_e2ee_chat/chat.db` using any SQLite browser. Messages appear only as base64 artefacts.
2. **Tamper with ciphertexts:** Modify a stored ciphertext manually. The recipient will fail GCM verification and the client will report decryption failure.
3. **Attempt admin snooping:** Even with database access, the administrator lacks device private keys, so decrypting messages is infeasible.

## TLS Capture Guide (Wireshark)

The dedicated guide in [`docs/CAPTURA_WIRESHARK.md`](docs/CAPTURA_WIRESHARK.md) shows how to run `iniciar_servidor.py --tls`, capture the handshake plus encrypted application data, and explain por qué el analista no puede reconstruir los mensajes pese a contar con el tráfico.

## Extending the Project

- Implement push notifications or WebSocket delivery while retaining the same cryptographic core.
- Replace RSA with X25519 + XChaCha20-Poly1305 to explore modern primitives.
- Introduce key rotation and signed pre-keys (Double Ratchet) to move towards Signal’s full protocol.

## Troubleshooting

- If `pycryptodome` is missing, ensure the virtual environment is active before installing.
- A totp mismatch typically means the local clock differs by more than 30 seconds from the server. Adjust the system clock or adapt the allowed drift in `crypto.verify_totp`.
- Remove the generated `.session_secret` file to rotate the HMAC key and invalidate all sessions.

---
This codebase is heavily commented and structured for educational clarity. Dive into the source modules for a guided tour of each applied primitive.
