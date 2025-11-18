# TEL252 — Laboratorio 7: Chat cifrado de extremo a extremo (E2EE)

Proyecto para TEL252 que demuestra un sistema de mensajería con cifrado de extremo a extremo. Combina criptografía simétrica y asimétrica, derivación de contraseña, TOTP y tokens de sesión firmados con HMAC. La API en Flask coordina autenticación, gestión de claves por dispositivo y relay de mensajes sin nunca ver el plaintext.

## Características principales

 - Onboarding con HMAC-SHA256 para digests de contraseña (pepper en el servidor) y TOTP (RFC 6238).
 - Tokens de sesión firmados con HMAC-SHA256 para autenticar sin estado.
 - Registro de claves públicas por dispositivo (PEM RSA-2048) para cada usuario.
 - Cifrado local AES-256-GCM por mensaje; llaves efímeras por cada payload.
 - Envoltorio de la llave AES con RSA-OAEP para que solo el destinatario pueda descifrarla.
 - Persistencia en SQLite para demos autocontenidas.
 - Cliente CLI que demuestra todo el flujo (registro, login con TOTP, registro de dispositivo, envío y recepción).
 - Documentación inline y diagramas que justifican decisiones criptográficas.

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

## Ejecución local de la API

### Inicio rápido (3 pasos)

1. **Instalar dependencias:**

   ```pwsh
   pip install -r requirements.txt
   ```

2. **Iniciar el servidor:**

   ```pwsh
   # HTTP local rápido
   python iniciar_servidor.py --host 127.0.0.1 --port 5000

   # Demostración TLS lista para Wireshark (certificado auto-firmado)
   python iniciar_servidor.py --tls --host 0.0.0.0 --port 5443
   ```

   El script envuelve `create_app()` y expone flags convenientes (`--tls`, `--cert`, `--key`). El entry point
   clásico `python -m lab7_e2ee_chat.server` sigue disponible si prefieres el flujo clásico.

3. **Elija su interfaz:**

   - **Navegador web:** Abra `http://localhost:5000/ui/` en su navegador.
   - **CLI:** Consulte los comandos a continuación.
   - **Pruebas automatizadas:** Ejecute `python -m pytest tests/test_flow.py -v`.

### Cliente web (recomendado)

1. Abra `http://localhost:5000/ui/`.
2. Regístrese con email, nombre y contraseña.
3. Guarde el secreto TOTP — escanee el QR o almacene el código base32. La UI conserva el secreto en `localStorage` cifrado para generar códigos TOTP.
4. Inicie sesión con email+contraseña+TOTP y, si desea, seleccione la sesión en el selector para reutilizar tokens.
5. Registre la clave pública de su dispositivo generada en el navegador y pruebe enviar/recibir mensajes.

**Features:**

- Local persistence (tokens, TOTP secrets, PEMs) via `localStorage` for multi-session demos without retyping secrets.
- Session selector + contactos interactivos para fijar conversaciones y ver burbujas entrantes/salientes descifradas localmente.
- Genera llaves RSA-2048 en el navegador con Web Crypto API y sube solamente la clave pública en formato PEM.
- AES-256-GCM encryption happens locally before sending to the server, which never sees plaintext.

### Despliegue con Docker

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

## Cliente de línea de comandos (demo)

El CLI incluido ilustra el flujo completo usando la API; todas las operaciones criptográficas críticas ocurren en el cliente.

### Nota sobre TOTP y pepper

El servidor genera un secreto TOTP (Base32, 160 bits) que el usuario debe añadir a su app autenticadora. El login siempre solicita el código generado por TOTP (RFC 6238) además de la contraseña.

La contraseña se procesa en el servidor con HMAC-SHA256 usando un `password_secret` (pepper). Esto significa que, si la base de datos fuera filtrada, las contraseñas no pueden verificarse sin conocer el pepper. Sin embargo, para producción preferimos KDFs (Argon2/PBKDF2) con un salt único por usuario.

### 1. Registrar dos cuentas

```pwsh
python -m lab7_e2ee_chat.client_cli register alice@example.com "Alice" StrongPass!123
python -m lab7_e2ee_chat.client_cli register bob@example.com "Bob" OtherPass!456
```

Cada comando muestra el `totp_secret` generado por el servidor. Escanéalo con Google Authenticator/Authy o guárdalo de forma segura. Se guarda un perfil local en `%USERPROFILE%\.tel252_chat` con el par RSA y metadatos.

### 2. Iniciar sesión y registrar dispositivos

```pwsh
python -m lab7_e2ee_chat.client_cli login alice@example.com
python -m lab7_e2ee_chat.client_cli register-device alice@example.com "Alice Laptop"

python -m lab7_e2ee_chat.client_cli login bob@example.com
python -m lab7_e2ee_chat.client_cli register-device bob@example.com "Bob Desktop"
```

El comando de login calcula el código TOTP vigente usando el secreto guardado. El comando `register-device` sube la clave pública RSA-2048 generada localmente al servidor.

### 3. Listar contactos e intercambiar mensajes

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

### Extras útiles

- `python -m lab7_e2ee_chat.client_cli totp alice@example.com` imprime el código TOTP activo y la ventana de validez.
- Establece la variable de entorno `CHAT_API_BASE` si el servidor Flask corre en otra dirección o puerto.

## API Reference

All endpoints reside under `/api` and expect/return JSON.

| Endpoint | Method | Description |
| --- | --- | --- |
| `/healthz` | GET | Simple heartbeat probe |
| `/api/register` | POST | Create a user account. Returns a TOTP secret and metadata. |
| `/api/login` | POST | Authenticate with password + TOTP; returns session token. |
| `/api/devices` | POST | Registrar una clave pública de dispositivo (requiere `Authorization: Bearer`). |
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
