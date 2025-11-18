# Guía de Usuario – TEL252 E2EE Chat

## Introducción

Bienvenido al sistema de chat cifrado de extremo a extremo (E2EE) desarrollado para TEL252. Este sistema implementa las primitivas criptográficas vistas en clase para permitir comunicación segura entre usuarios.

---

## Tabla de Contenidos

1. [Requisitos Previos](#requisitos-previos)
2. [Instalación](#instalación)
3. [Arquitectura del Sistema](#arquitectura-del-sistema)
4. [Uso del Cliente CLI](#uso-del-cliente-cli)
5. [Uso del Cliente Web](#uso-del-cliente-web)
6. [Ejecución con Docker](#ejecución-con-docker)
7. [Pruebas Automatizadas](#pruebas-automatizadas)
8. [Resolución de Problemas](#resolución-de-problemas)

---

## Requisitos Previos

### Software Necesario

- **Python 3.9+** (recomendado 3.11)
- **pip** (gestor de paquetes de Python)
- **Navegador moderno** (Chrome, Firefox, Edge) para cliente web
- **Docker** (opcional, para containerización)

### Conocimientos Requeridos

- Conceptos básicos de criptografía (vistos en TEL252)
- Familiaridad con línea de comandos
- Conceptos de API REST

---

## Instalación

### 1. Clonar/Ubicar el Proyecto

```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
```

### 2. Crear Entorno Virtual (Recomendado)

```powershell
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
.\venv\Scripts\Activate.ps1

# Si hay error de permisos en PowerShell:
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 3. Instalar Dependencias

```powershell
pip install -r requirements.txt
```

**Dependencias instaladas:**
- `Flask>=3.0` - Framework web
- `pycryptodome>=3.19` - Primitivas criptográficas
- `requests>=2.31` - Cliente HTTP
- `pytest>=8.0` - Testing framework

### 4. Verificar Instalación

```powershell
python -c "from Crypto.Cipher import AES; print('✅ PyCryptodome OK')"
python -c "import flask; print('✅ Flask OK')"
```

---

## Arquitectura del Sistema

### Componentes

```
lab7_e2ee_chat/
├── crypto.py              # Primitivas criptográficas
├── config.py              # Configuración y secretos
├── database.py            # Persistencia SQLite
├── server.py              # API Flask
├── client_cli.py          # Cliente línea de comandos
├── web_client/            # Cliente web (HTML/CSS/JS)
│   ├── index.html
│   ├── styles.css
│   └── script.js
├── tests/
│   └── test_flow.py       # Tests de integración
├── docs/
│   ├── ANALISIS_CRIPTOGRAFICO_TEL252.md
│   ├── technical_overview.md
│   └── architecture.mmd
├── Dockerfile             # Contenedor Docker
├── requirements.txt       # Dependencias Python
└── README.md              # Documentación principal
```

### Flujo de Datos

1. **Cliente** genera llaves RSA-2048 localmente
2. **Registro**: envía credenciales + recibe TOTP secret
3. **Login**: autentica con password + TOTP → recibe token JWT
4. **Registro de dispositivo**: sube llave pública RSA
5. **Envío de mensaje**:
   - Obtiene llave pública del destinatario
   - Genera session key AES-256 aleatoria
   - Cifra mensaje con AES-GCM
   - Envuelve session key con RSA-OAEP
   - Envía artefactos cifrados al servidor
6. **Recepción de mensaje**:
   - Descarga artefactos cifrados
   - Desenvuelve session key con RSA privada
   - Descifra mensaje con AES-GCM

---

## Uso del Cliente CLI

### Inicio del Servidor

**Terminal 1: Servidor**
```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
python -m lab7_e2ee_chat.server
```

**Salida esperada:**
```
 * Serving Flask app 'server'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

### Registro de Usuario (Alice)

**Terminal 2: Cliente Alice**
```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
python -m lab7_e2ee_chat.client_cli register alice@example.com "Alice" "password123"
```

**Salida:**
```
✅ User registered: ID 1
📱 TOTP Secret: JBSWY3DPEHPK3PXP
⚠️  Save this secret in Google Authenticator or similar app!
🔐 RSA keypair generated and stored
```

**Acción requerida:**
1. Copiar el TOTP secret
2. Agregar a Google Authenticator/Authy:
   - Seleccionar "Añadir cuenta"
   - "Introducir clave de configuración"
   - Nombre: "Alice TEL252"
   - Clave: `JBSWY3DPEHPK3PXP`
   - Tipo: Basado en tiempo

### Login y Registro de Dispositivo (Alice)

```powershell
# Obtener código TOTP de la app (ej: 123456)
python -m lab7_e2ee_chat.client_cli login alice@example.com "password123" "123456"
```

**Salida:**
```
✅ Login successful
🎫 Session token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
📱 Device 'alice-laptop' registered: ID 1
```

### Registro de Segundo Usuario (Bob)

**Terminal 3: Cliente Bob**
```powershell
python -m lab7_e2ee_chat.client_cli register bob@example.com "Bob" "securepass456"
# (guardar TOTP secret en authenticator)

python -m lab7_e2ee_chat.client_cli login bob@example.com "securepass456" "654321"
```

### Envío de Mensaje Cifrado (Alice → Bob)

**Terminal 2 (Alice):**
```powershell
python -m lab7_e2ee_chat.client_cli send alice@example.com bob@example.com "Hola Bob, este mensaje está cifrado E2EE!"
```

**Salida:**
```
🔍 Looking up recipient: bob@example.com
✅ Found user ID 2 with 1 device(s)
🔐 Encrypting message with AES-256-GCM...
📦 Wrapping session key with RSA-OAEP (Bob's public key)...
✅ Message sent: ID 1
```

### Recepción de Mensaje (Bob)

**Terminal 3 (Bob):**
```powershell
python -m lab7_e2ee_chat.client_cli receive bob@example.com
```

**Salida:**
```
📬 You have 1 message(s)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Message #1
From: alice@example.com
Sent: 2025-11-10 14:32:15

🔓 Decrypted content:
Hola Bob, este mensaje está cifrado E2EE!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Message deleted from server
```

### Comandos Disponibles

```powershell
# Ayuda general
python -m lab7_e2ee_chat.client_cli --help

# Registro
python -m lab7_e2ee_chat.client_cli register <email> <nombre> <password>

# Login
python -m lab7_e2ee_chat.client_cli login <email> <password> <totp_code>

# Enviar mensaje
python -m lab7_e2ee_chat.client_cli send <from_email> <to_email> <mensaje>

# Recibir mensajes
python -m lab7_e2ee_chat.client_cli receive <email>

# Listar usuarios
python -m lab7_e2ee_chat.client_cli list-users
```

---

## Uso del Cliente Web

### 1. Iniciar Servidor

```powershell
python -m lab7_e2ee_chat.server
```

### 2. Abrir Navegador

Navegar a: **http://localhost:5000/ui/**

### 3. Interfaz de Usuario

#### Pantalla de Registro

![Registro](https://via.placeholder.com/600x400?text=Registro+de+Usuario)

1. **Identificador**: Email único (ej: `alice@example.com`)
2. **Nombre**: Nombre de display (ej: `Alice`)
3. **Contraseña**: Mínimo 8 caracteres
4. **Botón "Registrar"**

**Resultado:**
- Se muestra el **TOTP Secret** en QR y texto
- Se genera automáticamente el par RSA-2048 en el navegador
- Datos almacenados en `localStorage` del navegador

#### Pantalla de Login

1. **Identificador**: Email registrado
2. **Contraseña**: Tu password
3. **Código TOTP**: 6 dígitos de Google Authenticator
4. **Botón "Iniciar Sesión"**

#### Pantalla de Chat

**Panel Izquierdo: Usuarios**
- Lista de usuarios registrados
- Click para ver llaves públicas

**Panel Central: Mensajes**
- **Destinatario**: Seleccionar de dropdown
- **Mensaje**: Escribir texto (máx 5000 caracteres)
- **Botón "Enviar Mensaje Cifrado"**
  - ✅ Se cifra localmente con Web Crypto API
  - ✅ Servidor solo ve bloques opacos

**Panel Derecho: Bandeja de Entrada**
- **Botón "Recibir Mensajes"**
- Lista de mensajes cifrados
- **Click en mensaje** → Descifra y muestra plaintext
- **Botón "Eliminar"** → Borra del servidor

### 4. Operaciones Criptográficas en el Navegador

#### Generación de Llaves RSA

```javascript
// Código interno en web_client/script.js
async function generateRSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: "SHA-256"
        },
        true, // extractable
        ["encrypt", "decrypt"]
    );
    
    // Exportar a formato PEM
    const publicKeyPem = await exportPublicKey(keyPair.publicKey);
    const privateKeyPem = await exportPrivateKey(keyPair.privateKey);
    
    return { publicKeyPem, privateKeyPem };
}
```

#### Cifrado de Mensaje

```javascript
async function encryptMessage(plaintext, recipientPublicKeyPem) {
    // 1. Generar session key AES-256
    const sessionKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    
    // 2. Cifrar mensaje con AES-GCM
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        sessionKey,
        new TextEncoder().encode(plaintext)
    );
    
    // 3. Extraer tag (últimos 16 bytes)
    const dataView = new Uint8Array(ciphertext);
    const actualCiphertext = dataView.slice(0, -16);
    const tag = dataView.slice(-16);
    
    // 4. Envolver session key con RSA-OAEP
    const rawSessionKey = await crypto.subtle.exportKey("raw", sessionKey);
    const recipientPublicKey = await importPublicKey(recipientPublicKeyPem);
    const wrappedKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPublicKey,
        rawSessionKey
    );
    
    return {
        wrapped_key: arrayBufferToBase64(wrappedKey),
        nonce: arrayBufferToBase64(nonce),
        ciphertext: arrayBufferToBase64(actualCiphertext),
        tag: arrayBufferToBase64(tag)
    };
}
```

#### Descifrado de Mensaje

```javascript
async function decryptMessage(encryptedData, privateKeyPem) {
    // 1. Importar llave privada
    const privateKey = await importPrivateKey(privateKeyPem);
    
    // 2. Desenvolver session key
    const wrappedKeyBuffer = base64ToArrayBuffer(encryptedData.wrapped_key);
    const sessionKeyBuffer = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        wrappedKeyBuffer
    );
    
    // 3. Importar session key
    const sessionKey = await crypto.subtle.importKey(
        "raw",
        sessionKeyBuffer,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
    
    // 4. Reconstruir ciphertext + tag
    const nonce = base64ToArrayBuffer(encryptedData.nonce);
    const ciphertext = base64ToArrayBuffer(encryptedData.ciphertext);
    const tag = base64ToArrayBuffer(encryptedData.tag);
    const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
    combined.set(new Uint8Array(ciphertext), 0);
    combined.set(new Uint8Array(tag), ciphertext.byteLength);
    
    // 5. Descifrar con AES-GCM
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        sessionKey,
        combined
    );
    
    return new TextDecoder().decode(plaintext);
}
```

---

## Ejecución con Docker

### 1. Construir Imagen

```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
docker build -t tel252-e2ee-chat .
```

**Salida esperada:**
```
[+] Building 45.2s (10/10) FINISHED
 => [internal] load build definition
 => => transferring dockerfile: 456B
 => [internal] load .dockerignore
 => [1/5] FROM docker.io/library/python:3.11-slim
 => [2/5] WORKDIR /app
 => [3/5] COPY requirements.txt .
 => [4/5] RUN pip install --no-cache-dir -r requirements.txt
 => [5/5] COPY . .
 => exporting to image
 => => writing image sha256:abc123...
 => => naming to docker.io/library/tel252-e2ee-chat
```

### 2. Ejecutar Contenedor

```powershell
docker run -p 5000:5000 `
  -e CHAT_SESSION_SECRET="mi_secret_de_32_bytes_base64" `
  -e CHAT_PASSWORD_SECRET="otro_secret_de_32_bytes" `
  tel252-e2ee-chat
```

**Parámetros:**
- `-p 5000:5000`: Mapea puerto del contenedor al host
- `-e CHAT_SESSION_SECRET`: Secret para HMAC de tokens (opcional, se genera si no existe)
- `-e CHAT_PASSWORD_SECRET`: Secret para HMAC de passwords (opcional)

### 3. Persistencia con Volúmenes

```powershell
# Crear volumen para base de datos
docker volume create tel252_chat_db

# Ejecutar con volumen montado
docker run -p 5000:5000 `
  -v tel252_chat_db:/app `
  tel252-e2ee-chat
```

**Resultado:**
- Base de datos `chat.db` persiste entre reinicios
- Secrets se regeneran en cada inicio (usar `-e` para fijarlos)

### 4. Docker Compose (Opcional)

Crear `docker-compose.yml`:

```yaml
version: '3.8'

services:
  chat-api:
    build: .
    ports:
      - "5000:5000"
    environment:
      CHAT_SESSION_SECRET: "${SESSION_SECRET}"
      CHAT_PASSWORD_SECRET: "${PASSWORD_SECRET}"
    volumes:
      - chat_data:/app
    restart: unless-stopped

volumes:
  chat_data:
```

**Ejecutar:**
```powershell
docker-compose up -d
```

---

## Pruebas Automatizadas

### Ejecutar Tests

```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
pytest tests/test_flow.py -v
```

**Salida esperada:**
```
============================== test session starts ==============================
platform win32 -- Python 3.11.5, pytest-8.0.0
collected 1 item

tests/test_flow.py::test_full_flow PASSED                                [100%]

=============================== 1 passed in 2.43s ===============================
```

### Contenido del Test

El test `test_full_flow` verifica:

1. ✅ **Registro de dos usuarios** (Alice y Bob)
2. ✅ **Login con TOTP** (generado dinámicamente)
3. ✅ **Registro de dispositivos** (llaves RSA)
4. ✅ **Envío de mensaje cifrado** (Alice → Bob)
5. ✅ **Recepción y descifrado** (Bob lee mensaje)
6. ✅ **Verificación de integridad** (plaintext matches)
7. ✅ **Eliminación de mensaje** (inbox vacía)

### Ejecutar Tests con Cobertura

```powershell
pip install pytest-cov
pytest tests/test_flow.py --cov=lab7_e2ee_chat --cov-report=html
```

**Ver reporte:**
```powershell
start htmlcov/index.html  # Abre en navegador predeterminado
```

### Añadir Más Tests (Opcional)

Crear `tests/test_crypto.py`:

```python
import pytest
from lab7_e2ee_chat import crypto

def test_hmac_password():
    """Verificar hash y verificación de contraseñas."""
    secret = crypto.get_random_bytes(32)
    password = "test_password_123"
    
    # Hash
    digest = crypto.hash_password(password, secret)
    
    # Verificación correcta
    assert crypto.verify_password(password, digest, secret)
    
    # Verificación incorrecta
    assert not crypto.verify_password("wrong_password", digest, secret)

def test_totp_generation():
    """Verificar generación y verificación de TOTP."""
    secret = crypto.generate_totp_secret()
    code = crypto.generate_totp(secret)
    
    assert len(code) == 6
    assert code.isdigit()
    assert crypto.verify_totp(secret, code)

def test_rsa_key_wrapping():
    """Verificar RSA-OAEP key wrapping."""
    priv_pem, pub_pem = crypto.generate_rsa_keypair()
    session_key = crypto.get_random_bytes(32)
    
    # Wrap
    wrapped = crypto.encrypt_session_key_with_rsa(session_key, pub_pem)
    
    # Unwrap
    unwrapped = crypto.decrypt_session_key_with_rsa(wrapped, priv_pem)
    
    assert session_key == unwrapped

def test_aes_gcm_encryption():
    """Verificar AES-256-GCM cifrado/descifrado."""
    session_key = crypto.get_random_bytes(32)
    plaintext = b"Mensaje de prueba para TEL252"
    aad = b"metadata_opcional"
    
    # Cifrar
    nonce, ciphertext, tag = crypto.encrypt_payload(plaintext, session_key, aad)
    
    # Descifrar
    decrypted = crypto.decrypt_payload(nonce, ciphertext, tag, session_key, aad)
    
    assert decrypted == plaintext
    
    # Verificar que tag inválido falla
    with pytest.raises(ValueError):
        crypto.decrypt_payload(nonce, ciphertext, b"wrong_tag_123456", session_key, aad)
```

**Ejecutar:**
```powershell
pytest tests/test_crypto.py -v
```

---

## Resolución de Problemas

### Error: "ModuleNotFoundError: No module named 'Crypto'"

**Solución:**
```powershell
pip uninstall crypto pycrypto pycryptodome
pip install pycryptodome
```

### Error: "Address already in use" (Puerto 5000 ocupado)

**Solución 1:** Cambiar puerto
```powershell
# Editar server.py línea final:
# app.run(debug=True, port=5001)
```

**Solución 2:** Matar proceso
```powershell
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### Error: "TOTP verification failed"

**Causas comunes:**
1. **Reloj desincronizado**: Verificar hora del sistema
2. **Secret incorrecto**: Revisar que se copió correctamente
3. **Código expirado**: TOTP cambia cada 30 segundos

**Solución:**
```powershell
# Sincronizar reloj de Windows
w32tm /resync

# Re-generar TOTP
python -m lab7_e2ee_chat.client_cli login <email> <password> <new_code>
```

### Error: "ValueError: MAC check failed" al descifrar

**Causa:** Mensaje fue modificado o parámetros incorrectos

**Verificar:**
1. ¿Usaste la llave privada correcta?
2. ¿El mensaje fue enviado a tu dispositivo?
3. ¿Los artefactos (nonce, ciphertext, tag) están completos?

**Debug:**
```python
# En client_cli.py, añadir prints:
print(f"Nonce: {len(nonce)} bytes")
print(f"Ciphertext: {len(ciphertext)} bytes")
print(f"Tag: {len(tag)} bytes")
print(f"Wrapped key: {len(wrapped_key_bytes)} bytes")
```

### Error: "sqlite3.OperationalError: database is locked"

**Causa:** Múltiples procesos accediendo a `chat.db`

**Solución:**
```powershell
# Cerrar todos los procesos Python
taskkill /IM python.exe /F

# Eliminar archivo de lock si existe
Remove-Item chat.db-journal -ErrorAction SilentlyContinue

# Reiniciar servidor
python -m lab7_e2ee_chat.server
```

### Cliente Web: "TypeError: Cannot read property 'encrypt' of undefined"

**Causa:** Web Crypto API no disponible (HTTP sin TLS)

**Solución:**
- Usar `http://localhost` o `http://127.0.0.1` (permitidos sin TLS)
- NO usar `http://<IP_externa>` (requiere HTTPS)

### Docker: "Error response from daemon: Conflict"

**Causa:** Contenedor con mismo nombre existe

**Solución:**
```powershell
docker rm -f <container_name>
docker run ...
```

---

## Comandos Útiles de Referencia

### Gestión del Servidor

```powershell
# Iniciar servidor
python -m lab7_e2ee_chat.server

# Iniciar en puerto alternativo
# (editar server.py: app.run(port=5001))

# Ver logs en tiempo real
# (automático en consola)
```

### Gestión de la Base de Datos

```powershell
# Abrir base de datos con SQLite
sqlite3 chat.db

# Dentro de SQLite:
.tables                    # Listar tablas
SELECT * FROM users;       # Ver usuarios
SELECT * FROM devices;     # Ver dispositivos
SELECT * FROM messages;    # Ver mensajes (cifrados)
.exit                      # Salir
```

### Resetear Sistema

```powershell
# Borrar base de datos y secretos
Remove-Item chat.db -ErrorAction SilentlyContinue
Remove-Item .session_secret -ErrorAction SilentlyContinue
Remove-Item .password_secret -ErrorAction SilentlyContinue

# Limpiar perfiles de cliente
Remove-Item -Recurse $HOME\.tel252_chat -ErrorAction SilentlyContinue

# Reiniciar servidor
python -m lab7_e2ee_chat.server
```

---

## Próximos Pasos

### Mejoras Sugeridas

1. **Interfaz Web Mejorada:**
   - Notificaciones push de nuevos mensajes
   - Chat en tiempo real con WebSockets
   - Búsqueda de mensajes

2. **Seguridad Adicional:**
   - Perfect Forward Secrecy con ECDH
   - Rate limiting de requests
   - Logging de eventos de seguridad

3. **Funcionalidades:**
   - Chats grupales
   - Archivos adjuntos cifrados
   - Mensajes que se autodestruyen

4. **Deployment:**
   - Configuración de HTTPS con Let's Encrypt
   - Balanceo de carga con nginx
   - CI/CD con GitHub Actions

---

## Contacto y Soporte

**Desarrollado para:** TEL252 - Criptografía y Seguridad en la Información  
**Institución:** Universidad Técnica Federico Santa María  
**Semestre:** 2do Semestre, 2025  
**Docente:** Daniel Espinoza

**Documentación adicional:**
- `README.md` - Visión general del proyecto
- `docs/ANALISIS_CRIPTOGRAFICO_TEL252.md` - Análisis criptográfico detallado
- `docs/technical_overview.md` - Descripción técnica de módulos
- `docs/architecture.mmd` - Diagrama de secuencia

---

**¡Bienvenido al mundo del cifrado end-to-end!** 🔐
