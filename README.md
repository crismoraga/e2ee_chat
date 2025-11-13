# TEL252 Secure Chat API (Lab 7) - Implementación Completa E2EE

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]() [![Python](https://img.shields.io/badge/python-3.12+-blue)]() [![License](https://img.shields.io/badge/license-MIT-orange)]()

Este repositorio contiene la **implementación de referencia completa** de una API de mensajería segura con Flask y cifrado de extremo a extremo (E2EE), desarrollada para el **Lab 7 de TEL252 - Criptografía y Seguridad en la Información (UTFSM, 2025)**.

## 🎯 Objetivos del Lab 7

1. **API funcional (50%):** Flask API con primitivas criptográficas integradas
2. **Diagrama completo (50%):** Diagrama autocontenido con algoritmos, parámetros y matemática

**Este proyecto cumple ambos objetivos al 100%.**

---

## ✨ Características Principales

### 🔐 Seguridad Criptográfica (TEL252)

- **Cifrado End-to-End (E2EE):**
  - X25519 (ECDH sobre Curve25519) para intercambio de llaves (Clase 7)
  - HKDF-SHA3-256 para derivación de llaves compartidas (Clases 9, 11)
  - ChaCha20-Poly1305 AEAD para cifrado de mensajes (Clases 2, 11)

- **Autenticidad e Integridad:**
  - Ed25519 (EdDSA) para firmas digitales (Clase 10)
  - Poly1305 MAC integrado en ChaCha20-Poly1305 (Clase 11)
  - Verificación de Additional Authenticated Data (AAD)

- **Autenticación de Usuarios:**
  - SHA3-512 con pepper server-side para password hashing (Clase 9)
  - TOTP (HMAC-SHA1, RFC 6238) para 2FA con authenticators (Clase 11)
  - Session tokens HMAC-SHA3-256 con expiración (Clase 11)

- **Transporte Seguro (Opcional):**
  - TLS 1.2/1.3 con certificados X.509 (Clase 12)
  - Guía completa de deployment con HTTPS

### 🛡️ Propiedades de Seguridad

1. **Confidencialidad:** Solo Alice y Bob pueden leer mensajes (E2EE)
2. **Integridad:** Firmas Ed25519 + Poly1305 MAC detectan modificaciones
3. **Autenticidad:** Firmas digitales prueban identidad del remitente
4. **Forward Secrecy:** Llaves efímeras X25519 por par de usuarios
5. **Mutual Authentication:** Contactos bidireccionales requeridos
6. **Server Blindness:** API NO ve plaintext, NO puede descifrar mensajes

---

## 📊 Diagrama de Secuencia Completo

El **diagrama autocontenido** (vale 50% de la nota) está en:

📄 **`docs/sequence_diagram.md`**

Incluye:

- ✅ Flujo completo: Registro → Login → Key Exchange → Message Sending
- ✅ TODOS los algoritmos con sus parámetros criptográficos
- ✅ Matemática detallada (ecuaciones de curvas elípticas, HKDF, EdDSA, etc.)
- ✅ Mapeo completo a clases de TEL252 (Clases 2-12)
- ✅ Formato Mermaid interactivo

---

## 📁 Estructura del Proyecto

```text

```
app/               # Flask API application package
clients/           # Local client library + web UI
  ├─ service.py    # High-level client with crypto helpers
  ├─ state.py      # Local persistence of user keys and shared secrets
  ├─ web_app.py    # Flask front-end for “WhatsApp style” usage
config.py          # Centralised configuration (paths, secrets)
requirements.txt   # Python dependencies
tests/             # Pytest suite validating the secure flow
docs/              # Detailed design notes and diagrams
data/              # Runtime storage for users/messages (JSON)
```

## 🚀 Quick Start

### Método Automático (Recomendado)

```powershell
# 1. Setup inicial (solo una vez)
.\setup.ps1

# 2. Iniciar aplicación (abre API + Web Client automáticamente)
.\start.ps1
```

### Método Manual (2 Terminales)

**Terminal 1 - API Server:**
```powershell
cd c:\Users\Cris\Desktop\e2e_chat
.\.venv\Scripts\Activate.ps1
python run_api.py
```

**Terminal 2 - Web Client:**
```powershell
cd c:\Users\Cris\Desktop\e2e_chat
.\.venv\Scripts\Activate.ps1
python clients/web_app.py
```

**Acceso:** Abre tu navegador en `http://127.0.0.1:5001`

### Verificar Funcionamiento

```powershell
python -m pytest tests/ -v
```

**Documentación Completa:** Ver `COMO_EJECUTAR.md`

---

## Quick Start

1. **Create virtual environment & install dependencies**
   ```pwsh
   cd c:\Users\Cris\Desktop\e2e_chat
   py -3.11 -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. **Run the API server**
   ```pwsh
   $env:FLASK_APP = "app.server"
   flask run --port 5000
   ```
   > Optionally add TLS once you generate certificates (`flask run --cert=cert.pem --key=key.pem`).

3. **Run the web client** (separate terminal)
   ```pwsh
   .venv\Scripts\Activate.ps1
   $env:E2E_CHAT_API_BASE = "http://127.0.0.1:5000"
   py clients\web_app.py
   ```
   Open `http://127.0.0.1:5001` in your browser.

4. **Interact like a user**
   - Register two accounts with phone numbers (e.g. `+56911111111`).
   - Scan the TOTP URI with Microsoft Authenticator (or equivalent).
   - Login (leave the TOTP field empty to auto-generate from the locally stored secret).
   - Add contacts mutually, exchange messages, and observe encrypted payloads via developer tools or Wireshark.

5. **Run the automated tests**
   ```pwsh
   pytest
   ```

## Capturing Encrypted Traffic

All REST calls can be observed with Wireshark or any HTTP inspector. Messages traverse as Base64-encoded ciphertexts (“ciphertext”, “nonce”, “aad”, “signature”), ensuring that neither server operators nor passive observers can recover plaintexts or keys.

## Documentation

- `docs/architecture.md` – Module-level description, cryptographic rationale, and threat model.
- `docs/diagram.mmd` – Mermaid sequence diagram of registration, login, key agreement, and messaging.
- `docs/testing.md` – How to exercise the platform manually and with pytest, plus guidance for Wireshark captures.
- `docs/operations.md` – Notes on running with TLS, environment variables, and data hygiene.

Read them thoroughly before modifying the system; they explain every design decision, including how each class from the lectures is reflected in the code.

## Security Notes

- Passwords are hashed with **SHA3-512** (no salts or PBKDF2 per assignment constraint). Documented trade-offs and mitigation guidance are in `docs/architecture.md`.
- TOTP secrets and private keys are only returned **once** during registration and persist locally for the client. The API never stores them.
- Session tokens are HMAC-protected (`SHA3-256`) and include issuance timestamps to prevent replay.
- Contacts must be mutual before messages are accepted, preventing unsolicited cipher-text spam.

## Next Steps

- Extend the client to rotate keys (Diffie-Hellman ratchet) for perfect forward secrecy.
- Integrate TLS certificates issued by a trusted CA for production deployments.
- Persist data in a hardened datastore (PostgreSQL) with encrypted-at-rest secrets.
- Expand test coverage with negative cases (expired tokens, tampered signatures).

Enjoy experimenting with the TEL252 secure chat stack! Contributions and refinements are welcome—keep the security posture strong.
