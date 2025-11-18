# Análisis Criptográfico Completo – TEL252 Lab 7

## Índice
1. [Introducción](#introducción)
2. [Primitivas Criptográficas Utilizadas](#primitivas-criptográficas-utilizadas)
3. [Análisis Detallado por Componente](#análisis-detallado-por-componente)
4. [Flujo Criptográfico End-to-End](#flujo-criptográfico-end-to-end)
5. [Justificación de Decisiones de Diseño](#justificación-de-decisiones-de-diseño)
6. [Propiedades de Seguridad](#propiedades-de-seguridad)
7. [Referencias a Material de Clase](#referencias-a-material-de-clase)

---

## Introducción

Este documento describe **exhaustivamente** todas las primitivas criptográficas implementadas en la API de chat E2EE (End-to-End Encrypted) desarrollada para TEL252. Cada primitiva está justificada con referencia explícita al material de clase, incluyendo la matemática subyacente y los parámetros de seguridad.

### Objetivo del Sistema

Implementar un servicio de mensajería cifrada de extremo a extremo donde:

- **El servidor NO puede leer los mensajes** (solo actúa como relay de paquetes cifrados)
- **La autenticación es robusta** con factor dual (password + TOTP)
- **Todas las primitivas son aprobadas por el currículo** de TEL252
- **La integridad y autenticidad** están garantizadas mediante MACs y AEAD

---

## Primitivas Criptográficas Utilizadas

### Tabla Resumen

| Primitiva | Uso en el Sistema | Clase TEL252 | RFC/Estándar |
|-----------|-------------------|--------------|--------------|
| **HMAC-SHA256** | Autenticación de contraseñas | Clase 11 (MACs) | RFC 2104 |
| **TOTP (RFC 6238)** | Segundo factor de autenticación | Clase 11 (aplicación práctica) | RFC 6238 |
| **RSA-2048** | Generación de pares de llaves por dispositivo | Clase 4 (RSA) | PKCS#1 v2.2 |
| **RSA-OAEP** | Key wrapping (envolvimiento de llaves de sesión AES) | Clase 8 (RSA-KEM) | RFC 8017 |
| **AES-256-GCM** | Cifrado autenticado de mensajes (AEAD) | Clase 3 (AES) + Clase 11 (AEAD) | NIST SP 800-38D |
| **HMAC-SHA256 (tokens)** | Firma de tokens de sesión (similar a JWT) | Clase 11 (MACs) | RFC 2104 |

---

## Análisis Detallado por Componente

### 1. Autenticación de Contraseñas: HMAC-SHA256

#### 🎓 Referencia a Clase
**Clase 11: Criptografía Simétrica III – MACs**

#### Matemática

Según el RFC 2104 y el material de clase:

```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
```

Donde:
- `K`: llave secreta compartida (256 bits generados con `os.urandom(32)`)
- `m`: mensaje (en nuestro caso, la contraseña del usuario)
- `H`: función hash criptográfica (SHA-256)
- `ipad`: constante 0x36 repetida (inner padding)
- `opad`: constante 0x5c repetida (outer padding)

#### Implementación en `crypto.py`

```python
def hash_password(password: str, secret: bytes) -> str:
    """
    Compute HMAC-SHA256 digest of password using server-held secret.
    
    Parámetros:
    - password: contraseña en texto plano (str)
    - secret: llave simétrica de 256 bits (bytes)
    
    Retorna:
    - digest en formato base64url (str)
    """
    digest = hmac.new(secret, password.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")
```

#### ¿Por qué HMAC y no PBKDF2?

**Decisión de diseño según currículo:**

En la **Clase 11**, se estudió HMAC como una MAC (Message Authentication Code) que provee:
- ✅ **Integridad**: detecta modificaciones
- ✅ **Autenticación**: verifica el origen (portador de la llave)

**PBKDF2 NO fue visto en el curso**, por lo tanto se descartó. En su lugar:

1. **Usamos HMAC con un "pepper" del servidor** (secret guardado en `.password_secret`)
2. El "pepper" es una llave secreta de 256 bits que **nunca** se expone
3. Esto equivale a una "firma simétrica" de la contraseña

**Comparación con primitivas de clase:**

| Aspecto | PBKDF2 (NO en clase) | HMAC-SHA256 (Clase 11 ✅) |
|---------|----------------------|---------------------------|
| Iteraciones | Miles de rondas | 2 aplicaciones de SHA-256 |
| Salt por usuario | Sí | No (usamos pepper global) |
| Visto en TEL252 | ❌ | ✅ |
| Resistencia a diccionario offline | Alta (por iteraciones) | Media (depende del pepper) |
| Velocidad | Lenta (intencional) | Rápida |

**Mitigación de ataques:**

- **Contra fuerza bruta**: El atacante necesita el `secret` del servidor (256 bits de entropía)
- **Contra rainbow tables**: El pepper actúa como salt global único por despliegue
- **Contra timing attacks**: Se usa `hmac.compare_digest()` para comparación en tiempo constante

#### Código de Verificación

```python
def verify_password(password: str, digest_b64: str, secret: bytes) -> bool:
    """
    Verifica contraseña contra digest HMAC almacenado.
    
    Usa comparación en tiempo constante para prevenir timing attacks.
    """
    expected = base64.urlsafe_b64decode(digest_b64)
    candidate = hmac.new(secret, password.encode("utf-8"), hashlib.sha256).digest()
    return hmac.compare_digest(candidate, expected)  # ⏱️ Constant-time comparison
```

---

### 2. Segundo Factor de Autenticación: TOTP (RFC 6238)

#### 🎓 Referencia a Clase
**Clase 11: MACs** (aplicación práctica de HMAC en autenticación)

#### Matemática

El Time-based One-Time Password (TOTP) se define como:

```
TOTP = HOTP(K, T) = Truncate(HMAC-SHA1(K, T))
```

Donde:
- `K`: secret compartido (base32-encoded, típicamente 160 bits)
- `T = ⌊(Unix_Time - T₀) / X⌋`: contador de tiempo discreto
  - `T₀ = 0` (época UNIX)
  - `X = 30` segundos (time step)
- `Truncate`: extrae 31 bits del HMAC y aplica `mod 10^6` para obtener 6 dígitos

#### Implementación en `crypto.py`

```python
def generate_totp_secret() -> str:
    """
    Genera un secret TOTP aleatorio de 160 bits.
    
    Retorna:
    - secret codificado en base32 (formato compatible con Google Authenticator)
    """
    return base64.b32encode(os.urandom(20)).decode("ascii")  # 20 bytes = 160 bits

def generate_totp(secret: str, offset: int = 0) -> str:
    """
    Calcula el TOTP de 6 dígitos para el intervalo de tiempo actual.
    
    Parámetros:
    - secret: secret compartido en base32
    - offset: desplazamiento de intervalos (±1 para drift tolerance)
    
    Matemática:
    1. T = ⌊Unix_Time / 30⌋ + offset
    2. HMAC = HMAC-SHA1(K, T)
    3. Offset = último nibble de HMAC
    4. Truncated = HMAC[Offset:Offset+4] & 0x7FFFFFFF
    5. TOTP = Truncated mod 10^6
    """
    key = base64.b32decode(secret)
    timestamp = int(time.time()) // 30 + offset  # Time step de 30s
    
    # Convertir timestamp a bytes (big-endian)
    msg = struct.pack(">Q", timestamp)
    
    # HMAC-SHA1 según RFC 6238
    hmac_result = hmac.new(key, msg, hashlib.sha1).digest()
    
    # Dynamic Truncation
    offset_bits = hmac_result[-1] & 0x0F
    truncated = struct.unpack(">I", hmac_result[offset_bits:offset_bits + 4])[0]
    truncated &= 0x7FFFFFFF  # Clear MSB
    
    # Generar código de 6 dígitos
    code = truncated % 1_000_000
    return f"{code:06d}"

def verify_totp(secret: str, provided_code: str, tolerance: int = 1) -> bool:
    """
    Verifica TOTP con tolerancia de ±1 intervalo (±30s).
    
    Esto mitiga problemas de sincronización de reloj (clock drift).
    """
    for offset in range(-tolerance, tolerance + 1):
        if generate_totp(secret, offset) == provided_code:
            return True
    return False
```

#### Justificación

- **¿Por qué TOTP y no SMS/Email?**
  - TOTP es **offline** (no requiere infraestructura de telco/email)
  - Es el **estándar de facto** en 2FA (Google, GitHub, AWS, etc.)
  - Compatible con apps como Google Authenticator, Authy, 1Password

- **Parámetros de seguridad:**
  - Secret: 160 bits de entropía (similar a SHA-1 output size)
  - Time window: 30 segundos
  - Tolerance: ±1 window (máximo 90 segundos de validez)
  - Integridad: HMAC-SHA1 garantiza que solo el portador del secret puede generar códigos válidos

---

### 3. Criptografía Asimétrica: RSA-2048 + RSA-OAEP

#### 🎓 Referencia a Clase
- **Clase 4: RSA** (generación de claves, propiedades)
- **Clase 8: RSA-KEM** (Key Encapsulation Mechanism, wrapping de llaves simétricas)

#### 3.1 Generación de Pares de Llaves RSA

##### Matemática

RSA se basa en el problema de factorización de enteros grandes:

```
1. Seleccionar primos grandes p, q (cada uno de ~1024 bits)
2. Calcular n = p × q (módulo RSA)
3. Calcular φ(n) = (p-1)(q-1) (función totiente de Euler)
4. Seleccionar e tal que gcd(e, φ(n)) = 1 (típicamente e = 65537)
5. Calcular d ≡ e⁻¹ (mod φ(n)) (inverso multiplicativo)

Llave pública:  (n, e)
Llave privada:  (n, d) + (p, q) para CRT optimization
```

##### Implementación

```python
def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """
    Genera par RSA-2048 con exponente público 65537.
    
    Retorna:
    - (private_key_pem, public_key_pem): tupla de bytes en formato PEM
    
    Parámetros de seguridad:
    - Tamaño de módulo: 2048 bits (recomendación NIST hasta 2030)
    - Exponente público: 65537 (F₄, resistente a ataques de exponente bajo)
    """
    key = RSA.generate(2048)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    return private_pem, public_pem
```

##### Formato PEM

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

- **PEM** (Privacy-Enhanced Mail): codificación base64 de ASN.1 DER
- Compatible con OpenSSL, Web Crypto API, y todas las librerías modernas

#### 3.2 Key Wrapping con RSA-OAEP

##### Matemática

**OAEP** (Optimal Asymmetric Encryption Padding) según RFC 8017:

```
Cifrado:
1. M: mensaje (llave AES de 32 bytes)
2. lHash = SHA-256(L) donde L = "" (label vacío)
3. PS = cadena de ceros para padding
4. DB = lHash || PS || 0x01 || M
5. seed = random(32 bytes)
6. dbMask = MGF1(seed, len(DB))
7. maskedDB = DB ⊕ dbMask
8. seedMask = MGF1(maskedDB, 32)
9. maskedSeed = seed ⊕ seedMask
10. EM = 0x00 || maskedSeed || maskedDB
11. C = EM^e mod n (operación RSA)
```

Donde:
- **MGF1** (Mask Generation Function 1): función de expansión basada en SHA-256
- **Label**: contexto opcional (vacío en nuestra implementación)

##### Implementación

```python
def encrypt_session_key_with_rsa(session_key: bytes, public_key_pem: bytes) -> str:
    """
    Envuelve llave de sesión AES-256 usando RSA-OAEP.
    
    Parámetros:
    - session_key: llave AES de 32 bytes (256 bits)
    - public_key_pem: llave pública RSA en formato PEM
    
    Retorna:
    - wrapped_key en base64url
    
    Parámetros criptográficos:
    - Padding: OAEP
    - Hash: SHA-256 (tanto para OAEP como para MGF1)
    - Label: vacío
    """
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    wrapped = cipher.encrypt(session_key)
    return base64.urlsafe_b64encode(wrapped).decode("ascii")

def decrypt_session_key_with_rsa(wrapped_key_b64: str, private_key_pem: bytes) -> bytes:
    """
    Desenvuelve llave de sesión AES-256 usando RSA-OAEP.
    
    Retorna:
    - session_key: 32 bytes de llave AES
    """
    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    wrapped = base64.urlsafe_b64decode(wrapped_key_b64)
    return cipher.decrypt(wrapped)
```

##### Justificación

- **¿Por qué OAEP y no PKCS#1 v1.5?**
  - PKCS#1 v1.5 es vulnerable a **Bleichenbacher's attack** (padding oracle)
  - OAEP es **IND-CCA2 seguro** (resistente a ataques de texto cifrado elegido adaptativos)
  - OAEP es el **estándar recomendado** por NIST y RSA Labs desde 1998

- **Relación con Clase 8 (RSA-KEM):**
  - RSA-OAEP implementa un **KEM** (Key Encapsulation Mechanism)
  - Se usa para "envolver" llaves simétricas (AES session keys)
  - Esto permite **cifrado híbrido**: asimétrico para key exchange, simétrico para datos

---

### 4. Cifrado Autenticado: AES-256-GCM (AEAD)

#### 🎓 Referencia a Clase
- **Clase 3: Cifrado de Bloques** (AES)
- **Clase 11: MACs** (AEAD, AES-GCM)

#### Matemática

**AES-GCM** = AES en modo CTR + GMAC (Galois Message Authentication Code)

##### 4.1 AES-CTR (Counter Mode)

```
Para i = 1, 2, ..., n bloques:
    C[i] = P[i] ⊕ AES_K(nonce || counter_i)
```

Donde:
- `K`: llave AES de 256 bits
- `nonce`: número usado una sola vez (96 bits recomendados)
- `counter`: contador incremental (32 bits)

##### 4.2 GMAC (Galois MAC)

```
1. H = AES_K(0^128)  (subkey de autenticación)
2. Para cada bloque de ciphertext y AAD:
   acc = (acc ⊕ bloque) · H  (en GF(2^128))
3. Tag = acc ⊕ AES_K(nonce || 0^31 || 1)
```

Donde:
- `·` es multiplicación en el campo de Galois GF(2^128)
- `H` es la "hash key" derivada de la llave K
- `AAD` (Additional Authenticated Data): metadata no cifrada pero autenticada

#### Implementación en `crypto.py`

```python
def encrypt_payload(
    plaintext: bytes,
    session_key: bytes,
    aad: Optional[bytes] = None
) -> tuple[bytes, bytes, bytes]:
    """
    Cifra y autentica mensaje usando AES-256-GCM.
    
    Parámetros:
    - plaintext: datos a cifrar
    - session_key: llave AES de 32 bytes (256 bits)
    - aad: Additional Authenticated Data (opcional)
    
    Retorna:
    - (nonce, ciphertext, tag): tupla de artefactos criptográficos
    
    Especificación:
    - Algoritmo: AES-256-GCM (NIST SP 800-38D)
    - Tamaño de nonce: 96 bits (12 bytes, recomendado para GCM)
    - Tamaño de tag: 128 bits (16 bytes, máxima seguridad)
    """
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=get_random_bytes(12))
    
    if aad:
        cipher.update(aad)  # Autenticar AAD sin cifrar
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return cipher.nonce, ciphertext, tag

def decrypt_payload(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    session_key: bytes,
    aad: Optional[bytes] = None
) -> bytes:
    """
    Descifra y verifica integridad usando AES-256-GCM.
    
    Lanza ValueError si el tag es inválido (mensaje modificado).
    """
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    
    if aad:
        cipher.update(aad)
    
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
```

#### Propiedades de Seguridad (AEAD)

AES-GCM es un **AEAD** (Authenticated Encryption with Associated Data), lo que garantiza:

1. ✅ **Confidencialidad**: El ciphertext no revela información sobre el plaintext
2. ✅ **Integridad**: Cualquier modificación del ciphertext se detecta al verificar el tag
3. ✅ **Autenticidad**: Solo quien posee `session_key` pudo generar el tag válido
4. ✅ **No reutilización de nonce**: Cada mensaje usa un nonce aleatorio único

#### Justificación de Parámetros

| Parámetro | Valor | Razón |
|-----------|-------|-------|
| Tamaño de llave | 256 bits | Resistencia post-cuántica proyectada (Grover: 128 bits de seguridad) |
| Nonce | 96 bits | Óptimo para GCM (según NIST SP 800-38D) |
| Tag | 128 bits | Máxima seguridad (2^-128 probabilidad de falsificación) |
| Modo | GCM | AEAD estándar, más rápido que CBC+HMAC |

#### Comparación con Otros Modos

| Modo | Visto en Clase | Autenticación | Paralelizable | Usado en API |
|------|----------------|---------------|---------------|--------------|
| ECB | ✅ Clase 3 | ❌ | ✅ | ❌ (inseguro) |
| CBC | ✅ Clase 3 | ❌ (requiere HMAC) | ❌ | ❌ |
| CTR | ✅ Clase 3 | ❌ (requiere HMAC) | ✅ | ❌ |
| **GCM** | ✅ **Clase 11** | ✅ (GMAC integrado) | ✅ | ✅ |

---

### 5. Tokens de Sesión: HMAC-SHA256 (JWT-like)

#### 🎓 Referencia a Clase
**Clase 11: MACs** (estándar JWT con HMAC)

#### Estructura

Nuestros tokens de sesión siguen el patrón **JWT** (JSON Web Token, RFC 7519) pero simplificado:

```
Token = Base64Url(header) . Base64Url(payload) . Base64Url(HMAC-SHA256(secret, data))
```

Donde:
- `header`: `{"alg": "HS256", "typ": "JWT"}`
- `payload`: `{"user_id": 123, "exp": 1699999999}`
- `signature`: HMAC-SHA256(secret, header + "." + payload)

#### Implementación en `crypto.py`

```python
def create_session_token(user_id: int, duration: int, secret: bytes) -> str:
    """
    Crea token de sesión firmado con HMAC-SHA256.
    
    Parámetros:
    - user_id: identificador único del usuario
    - duration: validez en segundos (ej: 3600 = 1 hora)
    - secret: llave HMAC del servidor (256 bits)
    
    Retorna:
    - token en formato "header.payload.signature" (base64url)
    
    Equivalente a JWT con algoritmo HS256.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "user_id": user_id,
        "exp": int(time.time()) + duration
    }
    
    # Serializar y codificar
    h_enc = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    
    data = h_enc + b"." + p_enc
    
    # Firmar con HMAC-SHA256
    signature = hmac.new(secret, data, hashlib.sha256).digest()
    s_enc = base64.urlsafe_b64encode(signature).rstrip(b"=")
    
    return (data + b"." + s_enc).decode("ascii")

def verify_session_token(token: str, secret: bytes) -> Optional[int]:
    """
    Verifica token y extrae user_id si es válido.
    
    Retorna:
    - user_id si token es válido y no expirado
    - None si token es inválido, modificado, o expirado
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        h_enc, p_enc, s_provided = parts
        
        # Verificar firma
        data = f"{h_enc}.{p_enc}".encode("ascii")
        s_expected = hmac.new(secret, data, hashlib.sha256).digest()
        s_provided_bytes = base64.urlsafe_b64decode(s_provided + "==")
        
        if not hmac.compare_digest(s_expected, s_provided_bytes):
            return None  # Firma inválida
        
        # Decodificar payload
        payload_json = base64.urlsafe_b64decode(p_enc + "==")
        payload = json.loads(payload_json)
        
        # Verificar expiración
        if payload["exp"] < time.time():
            return None  # Token expirado
        
        return payload["user_id"]
    
    except Exception:
        return None
```

#### Ventajas sobre Sesiones con Base de Datos

| Aspecto | Sesiones en DB | JWT/HMAC Tokens |
|---------|----------------|-----------------|
| Escalabilidad | Baja (lookup por request) | Alta (stateless) |
| Revocación | Fácil (DELETE) | Difícil (requiere blacklist) |
| Latencia | Alta (I/O DB) | Baja (cómputo local) |
| Visto en clase | ❌ | ✅ Clase 11 |

---

## Flujo Criptográfico End-to-End

### Diagrama Completo

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    1. REGISTRO DE USUARIO                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Alice                    API Flask                  SQLite DB          │
│    │                          │                          │              │
│    │  POST /api/register      │                          │              │
│    │  {identifier, password}  │                          │              │
│    ├─────────────────────────>│                          │              │
│    │                          │                          │              │
│    │                          │ digest = HMAC-SHA256(    │              │
│    │                          │   key=server_secret,     │              │
│    │                          │   msg=password           │              │
│    │                          │ )                        │              │
│    │                          │                          │              │
│    │                          │ totp_secret = random(160b)              │
│    │                          │                          │              │
│    │                          │  INSERT INTO users       │              │
│    │                          │  (identifier, digest,    │              │
│    │                          │   totp_secret)           │              │
│    │                          ├─────────────────────────>│              │
│    │                          │                          │              │
│    │  {user_id, totp_secret}  │                          │              │
│    │<─────────────────────────┤                          │              │
│    │                          │                          │              │
│    │ Genera par RSA-2048:     │                          │              │
│    │ (priv_key, pub_key)      │                          │              │
│    │                          │                          │              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    2. AUTENTICACIÓN (LOGIN)                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Alice                    API Flask                  SQLite DB          │
│    │                          │                          │              │
│    │  POST /api/login         │                          │              │
│    │  {identifier, password,  │                          │              │
│    │   totp_code}             │                          │              │
│    ├─────────────────────────>│                          │              │
│    │                          │                          │              │
│    │                          │  SELECT * FROM users     │              │
│    │                          │  WHERE identifier=...    │              │
│    │                          │<─────────────────────────┤              │
│    │                          │                          │              │
│    │                          │ verify_password():       │              │
│    │                          │   HMAC(secret, password) │              │
│    │                          │   == stored_digest ?     │              │
│    │                          │                          │              │
│    │                          │ verify_totp():           │              │
│    │                          │   TOTP(totp_secret)      │              │
│    │                          │   == provided_code ?     │              │
│    │                          │   (con ±1 drift)         │              │
│    │                          │                          │              │
│    │                          │ token = JWT-like:        │              │
│    │                          │   header.payload.sig     │              │
│    │                          │   sig=HMAC(secret,data)  │              │
│    │                          │                          │              │
│    │  {session_token}         │                          │              │
│    │<─────────────────────────┤                          │              │
│    │                          │                          │              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                 3. REGISTRO DE DISPOSITIVO                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Alice                    API Flask                  SQLite DB          │
│    │                          │                          │              │
│    │  POST /api/devices       │                          │              │
│    │  Authorization: token    │                          │              │
│    │  {name, public_key_pem}  │                          │              │
│    ├─────────────────────────>│                          │              │
│    │                          │                          │              │
│    │                          │ verify_token(token)      │              │
│    │                          │ -> user_id               │              │
│    │                          │                          │              │
│    │                          │  INSERT INTO devices     │              │
│    │                          │  (user_id, name,         │              │
│    │                          │   public_key)            │              │
│    │                          ├─────────────────────────>│              │
│    │                          │                          │              │
│    │  {device_id}             │                          │              │
│    │<─────────────────────────┤                          │              │
│    │                          │                          │              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              4. ENVÍO DE MENSAJE CIFRADO (E2EE)                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Alice                    API Flask                  Bob                │
│    │                          │                          │              │
│    │ 1. Obtener pub_key de Bob                          │              │
│    │  GET /api/users/bob      │                          │              │
│    ├─────────────────────────>│                          │              │
│    │  {user_id, devices:[     │                          │              │
│    │    {id, public_key_pem}  │                          │              │
│    │  ]}                      │                          │              │
│    │<─────────────────────────┤                          │              │
│    │                          │                          │              │
│    │ 2. Cifrado local:        │                          │              │
│    │    a) session_key =      │                          │              │
│    │       random(32 bytes)   │                          │              │
│    │                          │                          │              │
│    │    b) nonce, ciphertext, │                          │              │
│    │       tag = AES-GCM(     │                          │              │
│    │         key=session_key, │                          │              │
│    │         plaintext=msg,   │                          │              │
│    │         aad=None         │                          │              │
│    │       )                  │                          │              │
│    │                          │                          │              │
│    │    c) wrapped_key =      │                          │              │
│    │       RSA-OAEP(          │                          │              │
│    │         pub_key=Bob,     │                          │              │
│    │         plaintext=        │                          │              │
│    │           session_key    │                          │              │
│    │       )                  │                          │              │
│    │                          │                          │              │
│    │ 3. Enviar artefactos:    │                          │              │
│    │  POST /api/messages      │                          │              │
│    │  {                       │                          │              │
│    │    recipient_id: bob_id, │                          │              │
│    │    device_id: bob_dev,   │                          │              │
│    │    wrapped_key: "...",   │                          │              │
│    │    nonce: "...",         │                          │              │
│    │    ciphertext: "...",    │                          │              │
│    │    tag: "..."            │                          │              │
│    │  }                       │                          │              │
│    ├─────────────────────────>│                          │              │
│    │                          │                          │              │
│    │                          │ INSERT INTO messages     │              │
│    │                          │ (opaque blob storage)    │              │
│    │                          │                          │              │
│    │  {message_id}            │                          │              │
│    │<─────────────────────────┤                          │              │
│    │                          │                          │              │
│    │                          │  GET /api/messages       │              │
│    │                          │<─────────────────────────┤              │
│    │                          │                          │              │
│    │                          │  [{wrapped_key, nonce,   │              │
│    │                          │    ciphertext, tag}]     │              │
│    │                          ├─────────────────────────>│              │
│    │                          │                          │              │
│    │                          │                  4. Bob descifra:       │
│    │                          │                     a) session_key =    │
│    │                          │                        RSA-OAEP(        │
│    │                          │                          priv_key,      │
│    │                          │                          wrapped_key    │
│    │                          │                        )                │
│    │                          │                                         │
│    │                          │                     b) plaintext =      │
│    │                          │                        AES-GCM(         │
│    │                          │                          session_key,   │
│    │                          │                          nonce,         │
│    │                          │                          ciphertext,    │
│    │                          │                          tag            │
│    │                          │                        )                │
│    │                          │                          │              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Justificación de Decisiones de Diseño

### 1. ¿Por qué NO usamos PBKDF2/Argon2/bcrypt?

**Respuesta:** Ninguna de estas funciones fue vista en TEL252. El currículo solo cubre:
- HMAC (Clase 11) ✅
- Funciones hash (SHA-2, SHA-3) (Clase 9) ✅

**Solución adoptada:**
- HMAC-SHA256 con "pepper" del servidor (secret de 256 bits)
- Equivale a una MAC de la contraseña
- Cumple con el material de clase

### 2. ¿Por qué RSA-OAEP y no RSA-KEM puro?

**Respuesta:** RSA-KEM (Clase 8) y RSA-OAEP son funcionalmente equivalentes para key wrapping:
- **RSA-KEM**: `session_key = KDF(RSA_decrypt(random_blob))`
- **RSA-OAEP**: `session_key = RSA_decrypt(RSA_encrypt(session_key))`

**OAEP es más directo** para nuestra aplicación porque:
- Permite cifrar directamente llaves AES generadas en el cliente
- Es el estándar en todas las librerías (PyCryptodome, Web Crypto API)
- Está explícitamente cubierto en Clase 8 como alternativa a KEM

### 3. ¿Por qué AES-GCM y no ChaCha20-Poly1305?

**Respuesta:** Ambos son AEAD vistos en Clase 11. Elegimos AES-GCM porque:
- Soporte nativo en Web Crypto API (navegadores)
- Aceleración por hardware (AES-NI en CPUs modernas)
- Estándar en TLS 1.3 (visto en Clase 12)

**ChaCha20-Poly1305 es igualmente válido** y podría usarse como alternativa.

### 4. ¿Por qué TOTP y no HOTP?

**Respuesta:** 
- **TOTP** (Time-based): más común en apps 2FA, sincronización automática
- **HOTP** (Counter-based): requiere mantener contador en servidor (estado adicional)

RFC 6238 (TOTP) es extensión de RFC 4226 (HOTP), ambos usan HMAC (Clase 11).

### 5. ¿Por qué no usamos ECDH?

**Respuesta:** ECDH (Clase 7) es excelente para key exchange, pero:
- Requiere **interacción** (ambas partes online simultáneamente)
- Nuestro modelo es **asíncrono** (mensajes almacenados en servidor)

**RSA-OAEP** permite cifrado asíncrono: Alice cifra para Bob incluso si Bob está offline.

**Alternativa válida:** Podríamos implementar **X3DH** (Extended Triple Diffie-Hellman) como Signal, combinando:
- ECDH para PFS (Perfect Forward Secrecy)
- RSA para identidad de largo plazo

Esto está **fuera del alcance** del laboratorio pero sería una extensión natural.

---

## Propiedades de Seguridad

### 1. Confidencialidad End-to-End

✅ **El servidor NO puede leer mensajes**

**Justificación:**
- Mensajes cifrados con AES-256-GCM en el cliente
- Session keys envueltas con RSA-OAEP (solo destinatario puede descifrar)
- Servidor solo almacena: `{wrapped_key, nonce, ciphertext, tag}` (opaco)

**Ataque del servidor:**
- ❌ No puede descifrar ciphertext (no tiene session_key)
- ❌ No puede descifrar wrapped_key (no tiene private_key de Bob)
- ✅ Puede **eliminar** mensajes (ataque de disponibilidad, no de confidencialidad)
- ✅ Puede ver **metadata** (quién envía a quién, cuándo, tamaño)

### 2. Integridad y Autenticidad

✅ **Mensajes no pueden ser modificados sin detección**

**Justificación:**
- AES-GCM produce un **tag** de 128 bits
- Modificar nonce, ciphertext, o AAD invalida el tag
- Probabilidad de falsificación: 2^-128 ≈ 10^-38

**Ataque de modificación:**
```python
# Atacante modifica ciphertext
ciphertext_modified = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

# Bob intenta descifrar
decrypt_payload(nonce, ciphertext_modified, tag, session_key)
# -> ValueError: MAC check failed
```

### 3. Autenticación de Usuario (2FA)

✅ **Acceso requiere password + TOTP**

**Modelo de amenaza:**
- ❌ Atacante roba password: no puede entrar (requiere TOTP)
- ❌ Atacante roba TOTP secret: no puede entrar (requiere password)
- ✅ Atacante roba **ambos**: puede autenticarse (mitigación: rate limiting, detección de anomalías)

**TOTP timing:**
- Ventana de validez: 90 segundos (±1 intervalo de 30s)
- Código de 6 dígitos: 10^6 combinaciones
- Fuerza bruta: 10^6 intentos / 90s ≈ 11,111 intentos/s
- **Mitigación:** Rate limiting a 3 intentos/minuto por usuario

### 4. Forward Secrecy (FS)

❌ **NO tenemos Perfect Forward Secrecy**

**Explicación:**
- PFS requiere **ephemeral keys** (llaves de un solo uso) por sesión
- Nuestras RSA keys son **de larga duración** (por dispositivo)
- Si comprometen private_key de Bob, pueden descifrar **mensajes pasados**

**Mitigación (fuera de alcance del lab):**
- Implementar **X3DH + Double Ratchet** (como Signal)
- Rotar RSA keys periódicamente
- Usar ECDH ephemeral keys con RSA solo para identidad

### 5. Resistencia a Replay Attacks

⚠️ **Protección parcial**

**Vulnerabilidad:**
- Servidor no valida unicidad de mensajes
- Atacante podría reenviar mensaje cifrado antiguo

**Mitigación posible:**
- Incluir **timestamp** en AAD de AES-GCM
- Rechazar mensajes con timestamp > 5 minutos de antigüedad
- Mantener **nonce registry** (costoso en espacio)

### 6. Resistencia a Timing Attacks

✅ **Comparaciones en tiempo constante**

**Implementación:**
```python
# ❌ VULNERABLE:
if password_hash == stored_hash:
    ...

# ✅ SEGURO:
if hmac.compare_digest(password_hash, stored_hash):
    ...
```

**Justificación:**
- `hmac.compare_digest()` compara byte a byte en tiempo constante
- Previene ataques de timing que revelan prefijos válidos

---

## Referencias a Material de Clase

### Mapeo Completo

| Componente | Primitiva | Clase TEL252 | Material Específico |
|------------|-----------|--------------|---------------------|
| Password auth | HMAC-SHA256 | **Clase 11** | Symmetric Crypto III, sección HMAC |
| 2FA | TOTP (RFC 6238) | **Clase 11** | Aplicación práctica de HMAC |
| Key generation | RSA-2048 | **Clase 4** | Asymmetric Crypto I (RSA) |
| Key wrapping | RSA-OAEP | **Clase 8** | RSA-KEM |
| Message encryption | AES-256-GCM | **Clase 3 + 11** | AES (Clase 3), AEAD (Clase 11) |
| Session tokens | HMAC-SHA256 | **Clase 11** | JWT con HS256 |
| Hash functions | SHA-256 | **Clase 9** | Hash Functions |

### Código de Ejemplo de Clase Reproducido

#### HMAC (Clase 11)
```python
# Del notebook "Symmetric Crypto III.ipynb"
from hashlib import sha256
import hmac
import os

key = os.urandom(16)
message = b"TEL252"

mac = hmac.new(key, message, sha256).hexdigest()
print(mac)
```

**Nuestra implementación:**
```python
def hash_password(password: str, secret: bytes) -> str:
    digest = hmac.new(secret, password.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")
```

#### AES-GCM (Clase 11)
```python
# Del notebook "Symmetric Crypto III.ipynb"
from Crypto.Cipher import AES
import os

header = b"TEL252"
message = b"AES_GCM_15_7h3_574nd4rd_SP_800-38D!"
key = os.urandom(32)

cipher = AES.new(key, AES.MODE_GCM)
cipher.update(header)
encrypted, tag = cipher.encrypt_and_digest(message)
```

**Nuestra implementación:**
```python
def encrypt_payload(plaintext: bytes, session_key: bytes, aad: Optional[bytes] = None):
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=get_random_bytes(12))
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag
```

#### JWT con HMAC (Clase 11)
```python
# Del notebook "Symmetric Crypto III.ipynb"
from datetime import datetime, timedelta
import jwt

payload = {
    "user_id": 1, 
    "username": "D-Cryp7",
    "role": "admin",
    "exp": datetime.now() + timedelta(minutes = 30)
}

secret_key = os.urandom(32)
token = jwt.encode(payload, secret_key, algorithm = "HS256")
```

**Nuestra implementación:**
```python
def create_session_token(user_id: int, duration: int, secret: bytes) -> str:
    payload = {"user_id": user_id, "exp": int(time.time()) + duration}
    # ... (construcción manual del JWT)
    signature = hmac.new(secret, data, hashlib.sha256).digest()
    return token
```

---

## Conclusión

Esta implementación demuestra **integración completa** de primitivas criptográficas del curso TEL252:

1. ✅ **Todas las primitivas son del currículo** (Clases 3, 4, 8, 9, 11)
2. ✅ **Cifrado end-to-end funcional** (servidor no ve mensajes)
3. ✅ **Autenticación robusta** (2FA con password + TOTP)
4. ✅ **Integridad garantizada** (AEAD con AES-GCM)
5. ✅ **Documentación exhaustiva** (este documento + código comentado)

### Extensiones Futuras (Fuera de Alcance del Lab)

- **Perfect Forward Secrecy**: X3DH + Double Ratchet (requiere ECDH de Clase 7)
- **Post-Quantum Cryptography**: CRYSTALS-Kyber (no en currículo)
- **Metadata Protection**: Tor/mixnets (no en currículo)
- **Deniability**: OTR messaging (no en currículo)

---

**Autor:** Sistema de Chat E2EE – TEL252 Lab 7  
**Fecha:** Noviembre 2025  
**Versión:** 1.0
