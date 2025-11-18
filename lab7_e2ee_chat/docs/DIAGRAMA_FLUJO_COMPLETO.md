# Diagrama de Arquitectura Criptográfica – TEL252 E2EE Chat

## Flujo Completo del Sistema

### 1. REGISTRO DE USUARIO

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Cliente (Alice)                                   │
│                                                                        │
│  1. Genera par RSA-2048 localmente:                                   │
│     ┌─────────────────────────────────────┐                           │
│     │ RSA.generate(2048)                  │                           │
│     │ e = 65537 (F₄)                      │                           │
│     │                                     │                           │
│     │ n = p × q    (p, q primos ~1024b)  │                           │
│     │ φ(n) = (p-1)(q-1)                   │                           │
│     │ d ≡ e⁻¹ (mod φ(n))                  │                           │
│     └─────────────────────────────────────┘                           │
│                    │                                                   │
│                    ▼                                                   │
│     ┌───────────────────────────────────┐                             │
│     │ Exportar a formato PEM (base64):  │                             │
│     │  • private_key.pem (guardar local)│                             │
│     │  • public_key.pem (enviar servidor)                              │
│     └───────────────────────────────────┘                             │
│                                                                        │
│  2. Envía credenciales al servidor:                                   │
│     POST /api/register                                                │
│     {                                                                  │
│       "identifier": "alice@example.com",                               │
│       "display_name": "Alice",                                         │
│       "password": "mypassword123"                                      │
│     }                                                                  │
│                    │                                                   │
└────────────────────┼───────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Servidor Flask API                                │
│                                                                        │
│  3. Procesa contraseña con HMAC-SHA256:                               │
│     ┌───────────────────────────────────────────────────┐             │
│     │ HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m)) │             │
│     │                                                    │             │
│     │ K = password_secret (256 bits, server-held)       │             │
│     │ m = "mypassword123"                               │             │
│     │ H = SHA-256                                       │             │
│     │                                                    │             │
│     │ digest = HMAC-SHA256(K, m)                        │             │
│     │        = 32 bytes codificados en base64url        │             │
│     └───────────────────────────────────────────────────┘             │
│                                                                        │
│  4. Genera TOTP secret:                                                │
│     ┌──────────────────────────────────────┐                          │
│     │ secret = os.urandom(20)  # 160 bits │                          │
│     │ secret_b32 = base32encode(secret)   │                          │
│     │           = "JBSWY3DPEHPK3PXP"      │                          │
│     └──────────────────────────────────────┘                          │
│                                                                        │
│  5. Almacena en SQLite:                                                │
│     ┌────────────────────────────────────────────┐                    │
│     │ INSERT INTO users (                        │                    │
│     │   identifier,    → "alice@example.com"     │                    │
│     │   display_name,  → "Alice"                 │                    │
│     │   password_hash, → "Xy7zK9..." (base64)    │                    │
│     │   totp_secret    → "JBSWY3DP..." (base32)  │                    │
│     │ )                                          │                    │
│     └────────────────────────────────────────────┘                    │
│                                                                        │
│  6. Retorna credenciales al cliente:                                   │
│     {                                                                  │
│       "user_id": 1,                                                    │
│       "totp_secret": "JBSWY3DPEHPK3PXP"                                │
│     }                                                                  │
│                    │                                                   │
└────────────────────┼───────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Cliente (Alice)                                   │
│                                                                        │
│  7. Usuario registra TOTP en app authenticator:                       │
│     ┌───────────────────────────────────────┐                         │
│     │  Google Authenticator / Authy         │                         │
│     │  ┌─────────────────────────────┐      │                         │
│     │  │ [QR Code]                   │      │                         │
│     │  │                             │      │                         │
│     │  │ Account: Alice TEL252       │      │                         │
│     │  │ Key: JBSWY3DPEHPK3PXP       │      │                         │
│     │  │                             │      │                         │
│     │  │ Current code: 123456        │      │                         │
│     │  └─────────────────────────────┘      │                         │
│     └───────────────────────────────────────┘                         │
│                                                                        │
│  8. Guarda credenciales localmente:                                    │
│     ~/.tel252_chat/alice@example.com/profile.json                     │
│     {                                                                  │
│       "identifier": "alice@example.com",                               │
│       "user_id": 1,                                                    │
│       "totp_secret": "JBSWY3DPEHPK3PXP",                               │
│       "private_key_pem": "-----BEGIN PRIVATE KEY-----...",             │
│       "public_key_pem": "-----BEGIN PUBLIC KEY-----..."                │
│     }                                                                  │
└──────────────────────────────────────────────────────────────────────┘
```

---

### 2. LOGIN Y AUTENTICACIÓN (2FA)

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Cliente (Alice)                                   │
│                                                                        │
│  1. Obtiene código TOTP de la app (ej: 654321)                        │
│                                                                        │
│  2. Envía credenciales + TOTP:                                         │
│     POST /api/login                                                   │
│     {                                                                  │
│       "identifier": "alice@example.com",                               │
│       "password": "mypassword123",                                     │
│       "totp_code": "654321"                                            │
│     }                                                                  │
│                    │                                                   │
└────────────────────┼───────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Servidor Flask API                                │
│                                                                        │
│  3. Busca usuario en DB:                                               │
│     SELECT * FROM users WHERE identifier = 'alice@example.com'        │
│                                                                        │
│  4. Verifica password con HMAC:                                        │
│     ┌──────────────────────────────────────────────┐                  │
│     │ expected = stored_password_hash              │                  │
│     │ candidate = HMAC-SHA256(                     │                  │
│     │   key=password_secret,                       │                  │
│     │   msg="mypassword123"                        │                  │
│     │ )                                            │                  │
│     │                                              │                  │
│     │ if hmac.compare_digest(candidate, expected): │                  │
│     │     ✅ Password OK                            │                  │
│     │ else:                                        │                  │
│     │     ❌ Password FAIL → 401 Unauthorized       │                  │
│     └──────────────────────────────────────────────┘                  │
│                                                                        │
│  5. Verifica TOTP (RFC 6238):                                          │
│     ┌───────────────────────────────────────────────────┐             │
│     │ T = ⌊Unix_Time / 30⌋  (time step = 30 segundos)  │             │
│     │                                                    │             │
│     │ Para offset en [-1, 0, +1]:  (drift tolerance)    │             │
│     │                                                    │             │
│     │   T' = T + offset                                 │             │
│     │   msg = struct.pack(">Q", T')  # 8 bytes big-endian             │
│     │                                                    │             │
│     │   hmac_result = HMAC-SHA1(                        │             │
│     │     key=base32decode(totp_secret),               │             │
│     │     msg=msg                                       │             │
│     │   )                                               │             │
│     │                                                    │             │
│     │   # Dynamic Truncation (RFC 4226)                │             │
│     │   offset_bits = hmac_result[-1] & 0x0F           │             │
│     │   truncated = hmac_result[offset:offset+4]       │             │
│     │   truncated &= 0x7FFFFFFF  (clear MSB)           │             │
│     │                                                    │             │
│     │   code = truncated % 1,000,000  # 6 dígitos      │             │
│     │                                                    │             │
│     │   if code == "654321":                            │             │
│     │       ✅ TOTP OK                                   │             │
│     │       break                                       │             │
│     └───────────────────────────────────────────────────┘             │
│                                                                        │
│  6. Genera token de sesión (JWT-like):                                 │
│     ┌────────────────────────────────────────────────┐                │
│     │ header = {"alg": "HS256", "typ": "JWT"}        │                │
│     │ payload = {                                    │                │
│     │   "user_id": 1,                                │                │
│     │   "exp": Unix_Time + 3600  (1 hora validez)   │                │
│     │ }                                              │                │
│     │                                                │                │
│     │ h_enc = base64url(json(header))                │                │
│     │ p_enc = base64url(json(payload))               │                │
│     │ data = h_enc + "." + p_enc                     │                │
│     │                                                │                │
│     │ signature = HMAC-SHA256(                       │                │
│     │   key=session_secret,                          │                │
│     │   msg=data                                     │                │
│     │ )                                              │                │
│     │                                                │                │
│     │ token = data + "." + base64url(signature)      │                │
│     └────────────────────────────────────────────────┘                │
│                                                                        │
│  7. Retorna token:                                                     │
│     {                                                                  │
│       "session_token": "eyJhbGci...XVCj9.eyJ1c2Vy...2NX0.dBj..."      │
│     }                                                                  │
│                    │                                                   │
└────────────────────┼───────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Cliente (Alice)                                   │
│                                                                        │
│  8. Guarda token para requests futuros:                                │
│     session_token = "eyJhbGci...XVCj9..."                             │
│                                                                        │
│  9. Registra dispositivo (upload public key):                          │
│     POST /api/devices                                                 │
│     Authorization: Bearer eyJhbGci...                                 │
│     {                                                                  │
│       "device_name": "alice-laptop",                                   │
│       "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMII..."          │
│     }                                                                  │
│                                                                        │
│     Servidor responde:                                                │
│     {                                                                  │
│       "device_id": 1                                                   │
│     }                                                                  │
└──────────────────────────────────────────────────────────────────────┘
```

---

### 3. ENVÍO DE MENSAJE CIFRADO (E2EE)

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Cliente Alice                                     │
│                                                                        │
│  1. Alice quiere enviar mensaje a Bob:                                │
│     plaintext = "Hola Bob, mensaje secreto!"                          │
│                                                                        │
│  2. Obtiene llave pública de Bob:                                      │
│     GET /api/users/bob@example.com                                    │
│     Authorization: Bearer <alice_token>                               │
│                                                                        │
│     Respuesta del servidor:                                            │
│     {                                                                  │
│       "user_id": 2,                                                    │
│       "identifier": "bob@example.com",                                 │
│       "display_name": "Bob",                                           │
│       "devices": [                                                     │
│         {                                                              │
│           "id": 2,                                                     │
│           "device_name": "bob-phone",                                  │
│           "public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."          │
│         }                                                              │
│       ]                                                                │
│     }                                                                  │
│                                                                        │
│  3. Genera session key AES-256 aleatoria:                              │
│     ┌──────────────────────────────────────┐                          │
│     │ session_key = os.urandom(32)         │                          │
│     │             = 256 bits de entropía   │                          │
│     └──────────────────────────────────────┘                          │
│                                                                        │
│  4. Cifra mensaje con AES-256-GCM:                                     │
│     ┌───────────────────────────────────────────────────┐             │
│     │ AES-256-GCM (NIST SP 800-38D)                     │             │
│     │                                                    │             │
│     │ nonce = os.urandom(12)  # 96 bits recomendados   │             │
│     │                                                    │             │
│     │ # Modo CTR (Counter)                              │             │
│     │ Para i en bloques:                                │             │
│     │   C[i] = P[i] ⊕ AES(session_key, nonce||counter) │             │
│     │                                                    │             │
│     │ # GMAC (Galois MAC)                               │             │
│     │ H = AES(session_key, 0^128)  # hash subkey        │             │
│     │ auth_data = AAD || ciphertext || lengths          │             │
│     │ tag = GHASH(H, auth_data) ⊕ AES(nonce||0||1)     │             │
│     │     = 128 bits de autenticación                   │             │
│     │                                                    │             │
│     │ Resultado:                                        │             │
│     │   nonce: 12 bytes                                 │             │
│     │   ciphertext: len(plaintext) bytes                │             │
│     │   tag: 16 bytes                                   │             │
│     └───────────────────────────────────────────────────┘             │
│                                                                        │
│  5. Envuelve session key con RSA-OAEP (llave pública de Bob):         │
│     ┌─────────────────────────────────────────────────────┐           │
│     │ RSA-OAEP (RFC 8017)                                 │           │
│     │                                                      │           │
│     │ M = session_key (32 bytes)                          │           │
│     │ lHash = SHA-256("")  # label vacío                  │           │
│     │ PS = padding de ceros                               │           │
│     │ DB = lHash || PS || 0x01 || M                       │           │
│     │                                                      │           │
│     │ seed = os.urandom(32)                               │           │
│     │ dbMask = MGF1(seed, len(DB))  # Mask Gen Function  │           │
│     │ maskedDB = DB ⊕ dbMask                              │           │
│     │                                                      │           │
│     │ seedMask = MGF1(maskedDB, 32)                       │           │
│     │ maskedSeed = seed ⊕ seedMask                        │           │
│     │                                                      │           │
│     │ EM = 0x00 || maskedSeed || maskedDB                │           │
│     │                                                      │           │
│     │ wrapped_key = EM^e mod n  (operación RSA)          │           │
│     │             = ~256 bytes (tamaño de módulo RSA)     │           │
│     └─────────────────────────────────────────────────────┘           │
│                                                                        │
│  6. Envía artefactos cifrados al servidor:                             │
│     POST /api/messages                                                │
│     Authorization: Bearer <alice_token>                               │
│     {                                                                  │
│       "recipient_id": 2,                 // Bob                       │
│       "device_id": 2,                    // bob-phone                 │
│       "wrapped_key": "Xy9k...",          // base64, 256 bytes         │
│       "nonce": "3kD7...",                // base64, 12 bytes          │
│       "ciphertext": "zP8m...",           // base64, len(plaintext)    │
│       "tag": "Lm2n...",                  // base64, 16 bytes          │
│       "aad": null                        // opcional                  │
│     }                                                                  │
│                    │                                                   │
└────────────────────┼───────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Servidor Flask API                                │
│                                                                        │
│  7. Valida token de Alice (verify_session_token)                       │
│                                                                        │
│  8. Almacena mensaje OPACO en DB:                                      │
│     INSERT INTO messages (                                            │
│       sender_id,               → 1 (Alice)                            │
│       recipient_id,            → 2 (Bob)                              │
│       session_key_encrypted,   → "Xy9k..." (base64)                   │
│       nonce_b64,               → "3kD7..."                            │
│       ciphertext_b64,          → "zP8m..."                            │
│       tag_b64,                 → "Lm2n..."                            │
│       associated_data_b64      → NULL                                 │
│     )                                                                  │
│                                                                        │
│     ⚠️  Servidor NO PUEDE descifrar el mensaje:                       │
│        - No tiene session_key (está envuelta con RSA de Bob)          │
│        - No tiene private_key de Bob (está en dispositivo de Bob)     │
│                                                                        │
│  9. Retorna confirmación:                                              │
│     {                                                                  │
│       "message_id": 42                                                 │
│     }                                                                  │
└──────────────────────────────────────────────────────────────────────┘
```

---

### 4. RECEPCIÓN Y DESCIFRADO DE MENSAJE

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Cliente Bob                                       │
│                                                                        │
│  1. Bob consulta su bandeja de entrada:                                │
│     GET /api/messages                                                 │
│     Authorization: Bearer <bob_token>                                 │
│                    │                                                   │
└────────────────────┼───────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Servidor Flask API                                │
│                                                                        │
│  2. Valida token de Bob y busca mensajes:                              │
│     SELECT * FROM messages WHERE recipient_id = 2                     │
│                                                                        │
│  3. Retorna artefactos cifrados:                                       │
│     [                                                                  │
│       {                                                                │
│         "id": 42,                                                      │
│         "sender": {                                                    │
│           "id": 1,                                                     │
│           "identifier": "alice@example.com",                           │
│           "display_name": "Alice"                                      │
│         },                                                             │
│         "wrapped_key": "Xy9k...",                                      │
│         "nonce": "3kD7...",                                            │
│         "ciphertext": "zP8m...",                                       │
│         "tag": "Lm2n...",                                              │
│         "aad": null,                                                   │
│         "created_at": "2025-11-10T14:32:15Z"                           │
│       }                                                                │
│     ]                                                                  │
│                    │                                                   │
└────────────────────┼───────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Cliente Bob                                       │
│                                                                        │
│  4. Desenvuelve session key con RSA-OAEP (llave privada de Bob):      │
│     ┌──────────────────────────────────────────────────┐              │
│     │ RSA-OAEP Descifrado (RFC 8017)                   │              │
│     │                                                   │              │
│     │ EM = wrapped_key^d mod n  (operación RSA)        │              │
│     │    = 0x00 || maskedSeed || maskedDB              │              │
│     │                                                   │              │
│     │ # Revertir enmascaramiento                       │              │
│     │ seedMask = MGF1(maskedDB, 32)                    │              │
│     │ seed = maskedSeed ⊕ seedMask                     │              │
│     │                                                   │              │
│     │ dbMask = MGF1(seed, len(maskedDB))               │              │
│     │ DB = maskedDB ⊕ dbMask                           │              │
│     │    = lHash || PS || 0x01 || M                    │              │
│     │                                                   │              │
│     │ # Extraer mensaje                                │              │
│     │ Verificar lHash == SHA-256("")                   │              │
│     │ Buscar separador 0x01                            │              │
│     │ session_key = M (últimos 32 bytes de DB)         │              │
│     └──────────────────────────────────────────────────┘              │
│                                                                        │
│  5. Descifra mensaje con AES-256-GCM:                                  │
│     ┌────────────────────────────────────────────────┐                │
│     │ AES-256-GCM Descifrado                         │                │
│     │                                                 │                │
│     │ # Modo CTR (reverso)                           │                │
│     │ Para i en bloques:                             │                │
│     │   P[i] = C[i] ⊕ AES(session_key, nonce||i)     │                │
│     │                                                 │                │
│     │ # Verificar tag (GMAC)                         │                │
│     │ H = AES(session_key, 0^128)                    │                │
│     │ auth_data = AAD || ciphertext || lengths       │                │
│     │ expected_tag = GHASH(H, auth_data) ⊕ ...       │                │
│     │                                                 │                │
│     │ if expected_tag != provided_tag:               │                │
│     │     raise ValueError("MAC check failed")       │                │
│     │     ❌ Mensaje fue modificado o corrupto        │                │
│     │ else:                                          │                │
│     │     ✅ Integridad verificada                    │                │
│     │     return plaintext                           │                │
│     └────────────────────────────────────────────────┘                │
│                                                                        │
│  6. Bob lee el mensaje:                                                │
│     plaintext = "Hola Bob, mensaje secreto!"                          │
│                                                                        │
│  7. Bob elimina mensaje del servidor:                                  │
│     DELETE /api/messages/42                                           │
│     Authorization: Bearer <bob_token>                                 │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Propiedades Criptográficas Verificadas

### ✅ Confidencialidad End-to-End
- Servidor NO puede leer mensajes (no tiene private keys de destinatarios)
- Solo destinatario con private_key RSA puede desenvolver session_key
- Session keys son únicas por mensaje (generación aleatoria)

### ✅ Integridad
- AES-GCM tag de 128 bits detecta cualquier modificación
- HMAC-SHA256 en passwords y tokens previene falsificación
- RSA-OAEP padding previene ataques de texto cifrado elegido

### ✅ Autenticación
- Password + TOTP verifican identidad del usuario (2FA)
- Session tokens firmados con HMAC validan cada request
- Solo portador de private_key puede descifrar mensajes

### ✅ No Reputio (Parcial)
- ❌ Session keys son simétricas (no hay firmas digitales)
- ✅ Se podría extender con RSA-PSS o EdDSA para firmar mensajes

### ⚠️ Forward Secrecy (NO implementado)
- RSA keys son de larga duración
- Compromiso de private_key permite descifrar mensajes pasados
- Extensión: implementar X3DH con ECDH ephemeral keys

---

## Tabla de Parámetros de Seguridad

| Primitiva | Parámetro | Valor | Nivel de Seguridad |
|-----------|-----------|-------|-------------------|
| HMAC-SHA256 | Key size | 256 bits | 128 bits post-quantum (Grover) |
| TOTP | Secret size | 160 bits | 80 bits post-quantum |
| TOTP | Time window | 30s ± 30s | Usabilidad vs seguridad |
| RSA | Modulus | 2048 bits | ~112 bits clásico (NIST Nivel 2) |
| RSA | Public exp | 65537 | Resistente a exponente bajo |
| RSA-OAEP | Hash | SHA-256 | IND-CCA2 secure |
| AES-GCM | Key size | 256 bits | 128 bits post-quantum |
| AES-GCM | Nonce | 96 bits | Óptimo para GCM |
| AES-GCM | Tag | 128 bits | 2^-128 falsificación |
| JWT Token | Validity | 3600s (1h) | Balance usabilidad/riesgo |

---

## Referencias Normativas

- **HMAC**: RFC 2104 + Clase 11 (MACs)
- **TOTP**: RFC 6238 + Clase 11 (aplicación HMAC)
- **RSA**: PKCS#1 v2.2 + Clase 4 (RSA)
- **RSA-OAEP**: RFC 8017 + Clase 8 (RSA-KEM)
- **AES-GCM**: NIST SP 800-38D + Clase 3 (AES) + Clase 11 (AEAD)
- **JWT**: RFC 7519 + Clase 11 (JWT con HS256)
- **SHA-256**: FIPS 180-4 + Clase 9 (Hash Functions)

**Todas las primitivas han sido verificadas contra el currículo de TEL252.**
