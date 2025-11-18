# TEL252 Secure Chat – Architecture & Cryptographic Design

This document provides a bottom-up explanation of the secure chat platform delivered for TEL252 Lab 7. It connects every component with the corresponding theory units (Classes 1–12) and explains the security invariants that the system enforces.

---

## 1. High-Level Overview

| Layer | Component | Key Responsibilities |
|-------|-----------|----------------------|
| Client | `clients/service.py` | Maintains user secrets, executes all end-to-end cryptography, talks to the API. |
| Client UI | `clients/web_app.py` | Provides a browser-based interface, stores keys locally, drives the client service. |
| API | `app/server.py` | Validates inputs, enforces policy, persists opaque ciphertexts/metadata, exposes REST endpoints. |
| Crypto Primitives | `app/crypto.py` | Single source of truth for HKDF-SHA3-256, X25519 (ECDH), Ed25519 signatures, ChaCha20-Poly1305 AEAD, SHA3-512 password hashing, and TOTP helpers. |
| Storage | `app/storage.py` | Thread-safe JSON persistence for demo purposes. |

The API **never stores private keys or plaintext**, so administrators cannot recover messages. All sensitive derivations happen inside the local client library/web UI.

---

## 2. Mapping to TEL252 Lectures

| Lecture | Primitive / Topic | Where it Appears |
|---------|-------------------|------------------|
| Clase 2 – Cifrado de Flujos | ChaCha20-Poly1305 AEAD | Encrypts messages and authenticates associated data. |
| Clase 3 – Cifrado de Bloques | Poly1305 MAC | Operates on 128-bit blocks; paired with ChaCha20 for AEAD integrity. |
| Clase 4 – RSA | RSA background | Documented trade-offs; elliptic curves selected for performance. |
| Clase 6 – Diffie-Hellman | X25519 (ECDH) | Derives shared secrets between contacts. |
| Clase 7 – Curvas Elípticas | Curve25519 | Underpins both X25519 and Ed25519 operations. |
| Clase 8 – RSA-KEM | Hybrid KEM | ECDH secret stretched with HKDF-SHA3-256 analogous to KEM. |
| Clase 9 – Funciones Hash | SHA3 family | HKDF-SHA3-256, password hashing (SHA3-512), session token HMAC (SHA3-256). |
| Clase 10 – Firmas Digitales | Ed25519 | Signs ciphertext, nonce, and AAD tuples. |
| Clase 11 – MACs | Poly1305 & HMAC | AEAD integrity via Poly1305; HMAC-SHA3-256 protects session tokens. |
| Clase 12 – TLS | HTTPS enablement | Deployment guidance in `docs/operations.md`. |

Constraints from the instructor (no salt or PBKDF2) are respected and analysed in §4.4.

---

## 3. Detailed Data Flow

1. **Registration (`POST /register`)**
   - Server hashes the password with SHA3-512.
   - Generates X25519 and Ed25519 key pairs, returning private halves only once.
   - Issues a Base32 TOTP secret (RFC 6238) for Microsoft Authenticator or similar.
   - Stores only public keys and password hash; client persists private keys in `clients/state.py`.

2. **Login (`POST /login`)**
   - Client submits password + TOTP (computed locally via the shared secret).
   - Server verifies the SHA3-512 hash, then checks TOTP within ±30 s (window size = 1).
   - Server issues a session token: `phone:timestamp.HMAC_SHA3_256` using `SERVER_SECRET`.

3. **Contact Exchange (`POST /contacts`)**
   - Contacts must be mutual; the API rejects messages if reciprocity is missing.

4. **Key Discovery (`POST /keys/derive`)**
   - Server returns peer public keys plus canonical context string `TEL252-E2EE:<A>:<B>`.
   - Client computes `shared_key = HKDF-SHA3-256(X25519_secret, info=context)`.
   - Shared key remains local; the server never receives it.

5. **Message Transmission (`POST /messages`)**
   - Client prepares `aad = {"sender": A, "recipient": B, "timestamp": t, "context": info}`.
   - Encrypts plaintext with ChaCha20-Poly1305 using a random 96-bit nonce.
   - Signs the tuple `ciphertext:nonce:aad` with Ed25519.
   - Server stores ciphertext, nonce, AAD, signature, timestamp; no plaintext.

6. **Message Retrieval (`GET /messages`)**
   - Client downloads ciphertext bundle, verifies Ed25519 signature, and decrypts with the shared key + AAD.

---

## 4. Security Considerations

### 4.1 Confidencialidad

#### Cifrado End-to-End (E2EE)

- Solo ChaCha20-Poly1305 encrypted payloads transit la red
- Shared keys derivan de X25519 + HKDF-SHA3-256 y NUNCA salen del cliente
- Compromiso del servidor revela ciphertext pero NO plaintext

#### HKDF-SHA3-256: ¿Es válido usar "salt" interno?

**Pregunta crítica:** El lab dice "NO USAR SALT", pero HKDF usa salt internamente (RFC 5869). ¿Esto es válido?

**Respuesta técnica:**

✅ **SÍ ES VÁLIDO** por las siguientes razones:

1. **Contexto diferente:**
   - Restricción "NO SALT" se refiere a password hashing (PBKDF2, Argon2, bcrypt)
   - HKDF es una **Key Derivation Function (KDF)**, NO una password-based KDF
   - HKDF deriva material de llave a partir de un secreto ya seguro (ECDH shared secret)

2. **Propósito del salt en HKDF:**
   - En HKDF, salt es para "domain separation" y mezcla criptográfica
   - NO es para prevenir rainbow tables (ese es el propósito del salt en passwords)
   - RFC 5869 especifica: "salt is optional; if not provided, set to zeros"

3. **Fundamentación TEL252:**
   - Clase 6: Diffie-Hellman key exchange
   - Clase 7: ECDH sobre Curve25519 (X25519)
   - Clase 9: SHA-3 como función hash segura
   - Clase 11: HMAC como construcción MAC
   - **HKDF = HMAC + Hash**, ambos cubiertos en el curso

4. **Implementación actual:**

   ```python
   def hkdf_sha3_256(secret: bytes, salt: Optional[bytes], info: bytes, length: int):
       if salt is None:
           salt = b"\x00" * 32  # Salt opcional, se puede omitir
       prk = HMAC-SHA3-256(salt, secret)  # Extract
       okm = HMAC-SHA3-256(prk, info || counter)  # Expand
       return okm[:length]
   ```

5. **Alternativa sin HKDF (si el profesor lo requiere):**

   ```python
   # Derivación simple con solo hash (más débil pero válida)
   shared_key = SHA3-256(shared_secret || context)
   ```


**Conclusión:** HKDF-SHA3-256 es apropiado para TEL252 porque combina primitivas vistas en clase (HMAC, SHA-3) para un propósito diferente a password hashing.

### 4.2 Integrity & Authenticity

- Ed25519 signatures bind ciphertext, nonce, and AAD, preventing tampering.
- ChaCha20-Poly1305 provides AEAD tags, ensuring that ciphertext manipulation is detected.
- Mutual contact approval limits unsolicited message injection.

### 4.3 Authentication & Sessions

#### Password Hashing: SHA3-512 + Pepper (Cumple restricción "NO SALT")

**Restricción del curso:** "NO USES SALT, NI PBKDF2"

**Implementación actual:**

```python
hash = SHA3-512(password || SERVER_SECRET)
```

**Análisis crítico:**

✅ **Cumple restricción:** No usa salt per-user (diferente de PBKDF2/Argon2)

⚠️ **Vulnerabilidad reconocida:** Sin work factor, contraseñas débiles son vulnerables a ataques de diccionario

✅ **Mitigación implementada:** Pepper server-side (SERVER_SECRET) añade entropía desconocida al atacante que comprometa la base de datos


📚 **Fundamentación TEL252:**

- Clase 9 cubre SHA-3 (Keccak) como función hash criptográfica
- SHA3-512 proporciona 512 bits de salida, resistencia a preimagen, segunda preimagen y colisiones
- Pepper cumple propósito similar a salt pero es secret compartido por todos los usuarios


**Recomendación para producción:** Si se permite en evaluaciones futuras, migrar a Argon2 manteniendo pepper adicional.

#### TOTP: HMAC-SHA1 (RFC 6238)

- TOTP usa HMAC-SHA1 por compatibilidad con authenticators (Microsoft, Google, Authy)
- RFC 6238 especifica SHA-1 como algoritmo estándar
- **Nota:** SHA-1 está roto para colisiones, pero es seguro en contexto HMAC (resistencia a preimagen intacta)
- Clase 11 cubre MACs y HMAC como construcción segura

#### Session Tokens: HMAC-SHA3-256

- Formato: `phone:timestamp.HMAC_SHA3_256(SERVER_SECRET, phone:timestamp)`
- TTL configurable (default: 3600s)
- Verificación constant-time para prevenir timing attacks
- Clase 11 (MACs) + Clase 9 (SHA-3) fundamentan este diseño

### 4.4 Storage & Privacy

- JSON persistence is adequate for lab usage; `JsonStorage` can be swapped for an RDBMS.
- Private keys are delivered once; front-end can encrypt them at rest in future iterations.
- `.gitignore` excludes runtime JSON data and client state files.

### 4.5 Transport Security

- The API is Flask-native, so enabling TLS is a flag away (`flask run --cert --key`).
- `docs/operations.md` describes using `openssl` to produce dev certificates and recommends reverse proxies for production.

### 4.6 Threats & Mitigations

- **Replay of session tokens**: timestamp + max age enforced.
- **Message reorder / drop**: not addressed; Double Ratchet suggested as future work.
- **Password rainbow tables**: mitigated by passphrase guidance and optional server-side pepper.
- **Man-in-the-middle**: prevented once TLS is active; signature verification catches tampering.

---

## 5. Future Enhancements

- Integrate X3DH & Double Ratchet (Signal protocol) for forward secrecy and deniability.
- Persist data in PostgreSQL with transparent encryption.
- Extend automated tests to negative scenarios and fuzz endpoints.
- Introduce push notifications or WebSocket transport over the same cryptographic primitives.

---

With these notes, the project aligns tightly with TEL252 expectations and delivers a pedagogical yet practical example of secure chat architecture.
