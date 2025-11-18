# Resumen Ejecutivo – Laboratorio 7 TEL252

## Información del Proyecto

- **Asignatura:** TEL252 - Criptografía y Seguridad en la Información
- **Institución:** Universidad Técnica Federico Santa María
- **Semestre:** 2do Semestre, 2025
- **Docente:** Daniel Espinoza
- **Laboratorio:** #7 - Sistema de Chat con Cifrado End-to-End (E2EE)

---

## Objetivo del Laboratorio

Implementar una API funcional en Flask + Python que demuestre **integración práctica** de primitivas criptográficas del curso TEL252, creando un sistema de mensajería cifrada de extremo a extremo donde:

1. ✅ **El servidor NO puede leer los mensajes** (solo actúa como relay)
2. ✅ **Todas las primitivas son del currículo** (Clases 3, 4, 8, 9, 11)
3. ✅ **El sistema es funcional y demostrable** (CLI, Web UI, Tests)
4. ✅ **La documentación es exhaustiva** (análisis matemático, diagramas, guías)

---

## Decisiones de Diseño Criptográficas

### ¿Por qué NO usamos PBKDF2/Argon2/bcrypt?

**Respuesta:** Ninguna de estas funciones fue vista en TEL252.

**Solución adoptada (Clase 11):**
```
Password Authentication: HMAC-SHA256
digest = HMAC(server_secret, password)

Donde:
- server_secret: 256 bits (pepper global)
- password: contraseña del usuario
- digest: 256 bits almacenados en base64url
```

**Justificación:**
- HMAC es una MAC (Message Authentication Code) vista en Clase 11
- El "pepper" del servidor actúa como llave secreta compartida
- Cumple con integridad y autenticación según el material de clase

---

## Arquitectura del Sistema

### Componentes Principales

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENTE (Alice/Bob)                       │
│                                                              │
│  • Genera llaves RSA-2048 localmente                         │
│  • Cifra mensajes con AES-256-GCM                           │
│  • Envuelve session keys con RSA-OAEP                        │
│  • Autentica con password + TOTP (2FA)                       │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   │ HTTPS (en producción)
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                    SERVIDOR FLASK                            │
│                                                              │
│  • Valida HMAC de contraseñas                               │
│  • Verifica TOTP codes (RFC 6238)                           │
│  • Firma tokens con HMAC (JWT-like)                          │
│  • Almacena mensajes OPACOS (no puede descifrar)            │
│  • Sirve cliente web estático                                │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                    BASE DE DATOS SQLite                      │
│                                                              │
│  users:    identifier, password_hash, totp_secret            │
│  devices:  user_id, device_name, public_key_pem             │
│  messages: wrapped_key, nonce, ciphertext, tag              │
└─────────────────────────────────────────────────────────────┘
```

---

## Primitivas Criptográficas Utilizadas

| Primitiva | Clase TEL252 | Uso en el Sistema | Parámetros |
|-----------|--------------|-------------------|------------|
| **HMAC-SHA256** | **Clase 11** | Autenticación de contraseñas | Key: 256 bits (server pepper) |
| **TOTP (RFC 6238)** | **Clase 11** | Segundo factor (2FA) | Secret: 160 bits, Step: 30s |
| **RSA-2048** | **Clase 4** | Generación de llaves por dispositivo | Modulus: 2048 bits, e: 65537 |
| **RSA-OAEP** | **Clase 8** | Key wrapping (envolver session keys) | Hash: SHA-256, MGF1: SHA-256 |
| **AES-256-GCM** | **Clases 3 y 11** | Cifrado autenticado de mensajes (AEAD) | Key: 256 bits, Nonce: 96 bits, Tag: 128 bits |
| **HMAC-SHA256 (tokens)** | **Clase 11** | Firma de tokens de sesión (JWT-like) | Key: 256 bits (server secret) |
| **SHA-256** | **Clase 9** | Función hash en RSA-OAEP y HMAC | Output: 256 bits |

### Todas las primitivas tienen referencias explícitas al material de clase

---

## Flujo End-to-End Simplificado

### 1. Registro (Alice)
```
Alice → Server: {email, password}
Server: digest = HMAC-SHA256(pepper, password)
Server: totp_secret = random(160 bits)
Server → Alice: {user_id, totp_secret}
Alice: Genera par RSA-2048 localmente
Alice: Guarda totp_secret en Google Authenticator
```

### 2. Login (Alice)
```
Alice → Server: {email, password, totp_code}
Server: Verifica HMAC de password ✓
Server: Verifica TOTP con ±1 drift tolerance ✓
Server → Alice: {session_token}  (JWT firmado con HMAC)
Alice → Server: {device_name, public_key_pem}
Server: Almacena llave pública de Alice
```

### 3. Envío de Mensaje (Alice → Bob)
```
Alice: Obtiene public_key_pem de Bob desde servidor
Alice: session_key = random(32 bytes)  # AES-256
Alice: nonce, ciphertext, tag = AES-GCM(session_key, plaintext)
Alice: wrapped_key = RSA-OAEP(bob_public_key, session_key)
Alice → Server: {wrapped_key, nonce, ciphertext, tag}
Server: Almacena artefactos OPACOS (no puede descifrar) ✓
```

### 4. Recepción (Bob)
```
Bob → Server: GET /api/messages  (con token)
Server → Bob: [{wrapped_key, nonce, ciphertext, tag}, ...]
Bob: session_key = RSA-OAEP_decrypt(bob_private_key, wrapped_key)
Bob: plaintext = AES-GCM_decrypt(session_key, nonce, ciphertext, tag)
Bob lee el mensaje ✓
```

---

## Propiedades de Seguridad

### ✅ Confidencialidad End-to-End
- **Garantía:** Servidor NO puede leer mensajes
- **Razón:** Session keys están envueltas con RSA-OAEP (solo destinatario con private_key puede desenvolver)
- **Verificación:** Servidor solo almacena: `{wrapped_key, nonce, ciphertext_opaco, tag}`

### ✅ Integridad
- **Garantía:** Mensajes no pueden ser modificados sin detección
- **Razón:** AES-GCM tag de 128 bits (2^-128 probabilidad de falsificación)
- **Verificación:** Modificar nonce/ciphertext/tag causa `ValueError: MAC check failed`

### ✅ Autenticación
- **Garantía:** Solo usuarios legítimos pueden acceder
- **Razón:** Password + TOTP (2FA) verificados con HMAC
- **Verificación:** Robo de password O totp_secret no es suficiente (requiere ambos)

### ⚠️ Limitaciones Conocidas
- **NO hay Perfect Forward Secrecy:** RSA keys son de larga duración
- **NO hay firmas digitales:** Session keys son simétricas (sin no-repudio)
- **Metadata visible:** Servidor ve quién envía a quién, cuándo, tamaño

---

## Estructura del Código

```
lab7_e2ee_chat/
├── crypto.py              # ⭐ Todas las primitivas criptográficas
│                          #    - HMAC-SHA256 password auth
│                          #    - TOTP (RFC 6238)
│                          #    - RSA-2048 keygen + RSA-OAEP
│                          #    - AES-256-GCM AEAD
│                          #    - HMAC-SHA256 JWT tokens
│
├── config.py              # Configuración de secretos del servidor
│                          #    - load_session_secret() → 256 bits
│                          #    - load_password_secret() → 256 bits
│
├── database.py            # Capa de persistencia SQLite
│                          #    - users (id, identifier, password_hash, totp_secret)
│                          #    - devices (id, user_id, device_name, public_key_pem)
│                          #    - messages (wrapped_key, nonce, ciphertext, tag)
│
├── server.py              # ⭐ API Flask con endpoints REST
│                          #    POST /api/register
│                          #    POST /api/login
│                          #    GET/POST /api/devices
│                          #    GET /api/users
│                          #    GET/POST/DELETE /api/messages
│                          #    GET /ui/ (sirve cliente web)
│
├── client_cli.py          # Cliente de línea de comandos
│                          #    - register, login, send, receive
│
├── web_client/            # ⭐ Cliente web (HTML/CSS/JS)
│   ├── index.html         #    - Interfaz responsiva con cards
│   ├── styles.css         #    - Diseño moderno con gradientes
│   └── script.js          #    - Web Crypto API para RSA y AES-GCM
│
├── tests/
│   └── test_flow.py       # ⭐ Test de integración con pytest
│                          #    - Registro de 2 usuarios
│                          #    - Login con TOTP dinámico
│                          #    - Envío y descifrado de mensaje
│                          #    - Verificación de integridad
│
├── docs/
│   ├── ANALISIS_CRIPTOGRAFICO_TEL252.md  # ⭐ Análisis matemático exhaustivo
│   ├── GUIA_USUARIO.md                   # ⭐ Manual completo de usuario
│   ├── DIAGRAMA_FLUJO_COMPLETO.md        # ⭐ Diagramas paso a paso
│   ├── technical_overview.md             # Descripción técnica
│   └── architecture.mmd                  # Diagrama Mermaid
│
├── Dockerfile             # Containerización con Docker
├── requirements.txt       # Dependencias Python
└── README.md              # Documentación principal
```

---

## Demostración del Sistema

### Opción 1: Cliente Web (Recomendado)

```powershell
# 1. Iniciar servidor
python -m lab7_e2ee_chat.server

# 2. Abrir navegador
http://localhost:5000/ui/

# 3. Flujo de usuario:
#    - Registrar cuenta
#    - Escanear QR TOTP con Google Authenticator
#    - Login con email + password + código TOTP
#    - Enviar mensajes cifrados
#    - Recibir y descifrar mensajes
```

**Características del cliente web:**
- ✅ Generación de llaves RSA-2048 con Web Crypto API
- ✅ Cifrado AES-256-GCM local (servidor no ve plaintext)
- ✅ Interfaz responsive con CSS moderno
- ✅ Soporte para múltiples usuarios

### Opción 2: Cliente CLI

```powershell
# Terminal 1: Alice
python -m lab7_e2ee_chat.client_cli register alice@example.com "Alice" "pass123"
python -m lab7_e2ee_chat.client_cli login alice@example.com "pass123" "123456"
python -m lab7_e2ee_chat.client_cli send alice@example.com bob@example.com "Secreto!"

# Terminal 2: Bob
python -m lab7_e2ee_chat.client_cli register bob@example.com "Bob" "pass456"
python -m lab7_e2ee_chat.client_cli login bob@example.com "pass456" "654321"
python -m lab7_e2ee_chat.client_cli receive bob@example.com
# Output: "Secreto!" (descifrado localmente)
```

### Opción 3: Tests Automatizados

```powershell
cd C:\Users\Cris\Desktop\crypto
python -m pytest lab7_e2ee_chat/tests/test_flow.py -v

# Salida esperada:
# test_full_message_roundtrip PASSED ✅
```

---

## Documentación Exhaustiva

### Documentos Generados

| Documento | Propósito | Páginas | Contenido Clave |
|-----------|-----------|---------|-----------------|
| **ANALISIS_CRIPTOGRAFICO_TEL252.md** | Análisis técnico completo | ~50 | Matemática de cada primitiva, justificaciones, código comentado |
| **GUIA_USUARIO.md** | Manual de usuario | ~40 | Instalación, uso CLI/Web, Docker, troubleshooting |
| **DIAGRAMA_FLUJO_COMPLETO.md** | Flujos visuales | ~30 | Diagramas ASCII con operaciones paso a paso |
| **technical_overview.md** | Arquitectura técnica | ~10 | Descripción de módulos y responsabilidades |
| **architecture.mmd** | Diagrama de secuencia | 1 | Mermaid diagram del flujo completo |
| **README.md** | Inicio rápido | ~15 | Features, instalación, quick start |

### Cobertura de Documentación

✅ **Análisis Matemático:** Todas las primitivas tienen ecuaciones y explicaciones  
✅ **Referencias a Clase:** Cada primitiva cita la clase específica de TEL252  
✅ **Código Comentado:** >500 líneas de documentación inline  
✅ **Diagramas Visuales:** Flujos completos con ASCII art  
✅ **Guías de Usuario:** Paso a paso para CLI, Web, Docker  
✅ **Troubleshooting:** Sección de resolución de problemas comunes  

---

## Validación de Requisitos

### Checklist del Laboratorio

| Requisito | Estado | Evidencia |
|-----------|--------|-----------|
| API funcional en Flask + Python | ✅ | `server.py` con 10 endpoints REST |
| Cifrado End-to-End (servidor no lee mensajes) | ✅ | Session keys envueltas con RSA-OAEP |
| Primitivas del currículo TEL252 | ✅ | Todas las primitivas de Clases 3,4,8,9,11 |
| Integración de primitivas | ✅ | HMAC+TOTP+RSA+AES-GCM+JWT funcionan juntas |
| Diagrama autocontenido | ✅ | `DIAGRAMA_FLUJO_COMPLETO.md` con matemática |
| Especificar algoritmos y parámetros | ✅ | Tablas con tamaños de llave, modos, etc. |
| Matemática en el diagrama | ✅ | Ecuaciones de HMAC, TOTP, RSA-OAEP, AES-GCM |
| GUI/Web client | ✅ | `web_client/` con Web Crypto API |
| Containerización | ✅ | `Dockerfile` funcional con env vars |
| Tests automatizados | ✅ | `tests/test_flow.py` con pytest |
| Documentación exhaustiva | ✅ | 6 documentos markdown + inline comments |

---

## Cómo Evaluar el Proyecto

### 1. Instalación (2 minutos)
```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
pip install -r requirements.txt
python -m lab7_e2ee_chat.server
```

### 2. Demostración Web (5 minutos)
1. Abrir `http://localhost:5000/ui/`
2. Registrar "alice@test.com"
3. Guardar TOTP secret en Google Authenticator
4. Login con email + password + TOTP
5. Registrar "bob@test.com" en otra ventana/navegador
6. Alice envía mensaje a Bob
7. Bob recibe y descifra mensaje

### 3. Verificar Cifrado E2EE (2 minutos)
```powershell
# Abrir base de datos
sqlite3 chat.db
SELECT ciphertext_b64 FROM messages;
# Verificar que es texto ilegible (base64 opaco)
```

### 4. Ejecutar Tests (1 minuto)
```powershell
cd C:\Users\Cris\Desktop\crypto
python -m pytest lab7_e2ee_chat/tests/test_flow.py -v
# Verificar: 1 passed ✅
```

### 5. Revisar Documentación (10 minutos)
1. Abrir `docs/ANALISIS_CRIPTOGRAFICO_TEL252.md`
2. Verificar ecuaciones matemáticas de cada primitiva
3. Confirmar referencias a clases específicas de TEL252
4. Revisar diagramas en `DIAGRAMA_FLUJO_COMPLETO.md`

---

## Conclusión

Este laboratorio demuestra **dominio completo** de los objetivos de TEL252:

1. ✅ **Comprensión de primitivas:** Cada primitiva está justificada matemáticamente
2. ✅ **Integración práctica:** 6 primitivas trabajan juntas en un sistema funcional
3. ✅ **Aplicación realista:** Chat E2EE es caso de uso del mundo real
4. ✅ **Documentación profesional:** >100 páginas de análisis y guías
5. ✅ **Código de calidad:** Modular, testeado, containerizado

### Extensiones Futuras (Fuera de Alcance)

- **Perfect Forward Secrecy:** Implementar X3DH + Double Ratchet (requiere ECDH)
- **Post-Quantum Crypto:** CRYSTALS-Kyber (no en currículo)
- **Group Chat:** Cifrado multi-destinatario con Sender Keys
- **Metadata Protection:** Onion routing / mixnets

---

## Referencias

### Material de Clase TEL252

- **Clase 11:** Criptografía Simétrica III – MACs (HMAC, AES-GCM, JWT)
- **Clase 9:** Funciones Hash (SHA-2, SHA-3)
- **Clase 8:** RSA-KEM (Key Encapsulation Mechanism)
- **Clase 4:** RSA (generación de llaves, propiedades)
- **Clase 3:** Cifrado de Bloques (AES, modos de operación)

### Estándares RFC/NIST

- RFC 2104: HMAC
- RFC 6238: TOTP
- RFC 7519: JWT
- RFC 8017: RSA-OAEP (PKCS#1 v2.2)
- NIST SP 800-38D: AES-GCM

---

**Proyecto desarrollado para TEL252 – Noviembre 2025**  
**Universidad Técnica Federico Santa María**
