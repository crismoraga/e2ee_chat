# Instrucciones de Ejecución – Lab 7 TEL252

## Inicio Rápido (3 Comandos)

```powershell
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Iniciar servidor
python -m lab7_e2ee_chat.server

# 3. Abrir navegador
start http://localhost:5000/ui/
```

¡Listo! El sistema está funcionando.

---

## Demostración Completa Paso a Paso

### Preparación del Entorno

```powershell
# Ubicarse en el directorio del proyecto
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat

# Verificar que Python está instalado (>= 3.9)
python --version

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python -c "from Crypto.Cipher import AES; print('OK')"
```

---

## Opción 1: Demo con Cliente Web (Recomendado)

### Terminal 1: Servidor

```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
python -m lab7_e2ee_chat.server
```

**Salida esperada:**
```
 * Serving Flask app 'server'
 * Debug mode: on
WARNING: This is a development server.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

### Navegador: Uso del Sistema

1. **Abrir interfaz web:**
   ```
   http://localhost:5000/ui/
   ```

2. **Registrar primera cuenta (Alice):**
   - Email: `alice@example.com`
   - Nombre: `Alice`
   - Contraseña: `password123`
   - Click "Registrar"
   
3. **Guardar TOTP Secret:**
   - Aparecerá un QR code
   - Abrir Google Authenticator en tu teléfono
   - Escanear el QR code
   - O copiar el secret manualmente: `JBSWY3DPEHPK3PXP` (ejemplo)

4. **Login de Alice:**
   - Email: `alice@example.com`
   - Contraseña: `password123`
   - Código TOTP: `123456` (de Google Authenticator)
   - Click "Iniciar Sesión"

5. **Registrar segunda cuenta (Bob):**
   - Abrir nueva ventana incógnito o usar otro navegador
   - Ir a `http://localhost:5000/ui/`
   - Registrar:
     - Email: `bob@example.com`
     - Nombre: `Bob`
     - Contraseña: `securepass456`
   - Guardar TOTP secret de Bob
   - Login con email + password + TOTP

6. **Alice envía mensaje a Bob:**
   - En la ventana de Alice:
   - Panel central "Enviar Mensaje"
   - Destinatario: `bob@example.com`
   - Mensaje: `Hola Bob! Este mensaje está cifrado E2EE 🔒`
   - Click "Enviar Mensaje Cifrado"
   - Verás confirmación: "✅ Mensaje enviado"

7. **Bob recibe mensaje:**
   - En la ventana de Bob:
   - Panel derecho "Bandeja de Entrada"
   - Click "Recibir Mensajes"
   - Click en el mensaje de Alice
   - Se descifra automáticamente y muestra:
     ```
     De: Alice
     Mensaje: Hola Bob! Este mensaje está cifrado E2EE 🔒
     ```

---

## Opción 2: Demo con Cliente CLI

### Terminal 1: Servidor
```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
python -m lab7_e2ee_chat.server
```

### Terminal 2: Cliente Alice

```powershell
# 1. Registrar Alice
python -m lab7_e2ee_chat.client_cli register alice@example.com "Alice" "password123"

# Salida:
# ✅ User registered: ID 1
# 📱 TOTP Secret: JBSWY3DPEHPK3PXP
# ⚠️  Save this secret in Google Authenticator!
# 🔐 RSA keypair generated and stored

# 2. Agregar TOTP a Google Authenticator
# (escanear QR o copiar secret manualmente)

# 3. Login de Alice (obtener código TOTP del teléfono, ej: 123456)
python -m lab7_e2ee_chat.client_cli login alice@example.com "password123" "123456"

# Salida:
# ✅ Login successful
# 🎫 Session token saved
# 📱 Device registered
```

### Terminal 3: Cliente Bob

```powershell
# 1. Registrar Bob
python -m lab7_e2ee_chat.client_cli register bob@example.com "Bob" "securepass456"

# 2. Agregar TOTP de Bob a Google Authenticator

# 3. Login de Bob (código TOTP: 654321)
python -m lab7_e2ee_chat.client_cli login bob@example.com "securepass456" "654321"
```

### Terminal 2: Alice envía mensaje

```powershell
python -m lab7_e2ee_chat.client_cli send alice@example.com bob@example.com "Mensaje secreto para Bob!"

# Salida:
# 🔍 Looking up recipient: bob@example.com
# ✅ Found user ID 2 with 1 device(s)
# 🔐 Encrypting message with AES-256-GCM...
# 📦 Wrapping session key with RSA-OAEP...
# ✅ Message sent: ID 1
```

### Terminal 3: Bob recibe mensaje

```powershell
python -m lab7_e2ee_chat.client_cli receive bob@example.com

# Salida:
# 📬 You have 1 message(s)
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Message #1
# From: alice@example.com
# Sent: 2025-11-10 15:45:32
#
# 🔓 Decrypted content:
# Mensaje secreto para Bob!
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# ✅ Message deleted from server
```

---

## Opción 3: Ejecutar Tests Automatizados

```powershell
# Desde el directorio padre
cd C:\Users\Cris\Desktop\crypto

# Ejecutar tests
python -m pytest lab7_e2ee_chat/tests/test_flow.py -v

# Salida esperada:
# ============================= test session starts =============================
# collected 1 item
#
# lab7_e2ee_chat/tests/test_flow.py::test_full_message_roundtrip PASSED  [100%]
#
# ============================== 1 passed in 2.43s ==============================
```

**Qué verifica el test:**
1. ✅ Registro de dos usuarios (Alice y Bob)
2. ✅ Generación de TOTP secrets
3. ✅ Login con TOTP dinámico
4. ✅ Generación de llaves RSA-2048
5. ✅ Registro de dispositivos
6. ✅ Envío de mensaje cifrado con AES-256-GCM
7. ✅ Key wrapping con RSA-OAEP
8. ✅ Recepción y descifrado del mensaje
9. ✅ Verificación de integridad (tag GCM)
10. ✅ Eliminación del mensaje

---

## Opción 4: Ejecutar con Docker

### 1. Construir imagen Docker

```powershell
cd C:\Users\Cris\Desktop\crypto\lab7_e2ee_chat
docker build -t tel252-e2ee-chat .
```

**Salida esperada:**
```
[+] Building 45.2s (10/10) FINISHED
 => [1/5] FROM docker.io/library/python:3.11-slim
 => [2/5] WORKDIR /app
 => [3/5] COPY requirements.txt .
 => [4/5] RUN pip install --no-cache-dir -r requirements.txt
 => [5/5] COPY . .
 => exporting to image
 => => writing image sha256:abc123...
Successfully tagged tel252-e2ee-chat:latest
```

### 2. Ejecutar contenedor

```powershell
docker run -p 5000:5000 tel252-e2ee-chat
```

### 3. Acceder al servicio

```
http://localhost:5000/ui/
```

---

## Verificación del Cifrado E2EE

### Comprobar que el servidor NO puede leer mensajes

```powershell
# 1. Enviar un mensaje (desde CLI o web)

# 2. Abrir base de datos SQLite
sqlite3 chat.db

# 3. Consultar mensajes
SELECT 
  id,
  sender_id,
  recipient_id,
  substr(ciphertext_b64, 1, 20) as ciphertext_preview,
  substr(wrapped_key, 1, 20) as wrapped_key_preview
FROM messages;

# Salida ejemplo:
# id|sender_id|recipient_id|ciphertext_preview|wrapped_key_preview
# 1|1|2|zP8mXy9kLm2n3kD7...|Xy9kLm2nzP8m3kD7...
#
# ✅ Todo es texto opaco (base64) - servidor NO puede descifrar

.quit
```

---

## Documentación Disponible

### Documentos Principales

```powershell
# Análisis criptográfico completo (matemática, justificaciones)
start docs/ANALISIS_CRIPTOGRAFICO_TEL252.md

# Guía de usuario completa (instalación, uso, troubleshooting)
start docs/GUIA_USUARIO.md

# Diagramas de flujo con operaciones paso a paso
start docs/DIAGRAMA_FLUJO_COMPLETO.md

# Resumen ejecutivo del laboratorio
start RESUMEN_EJECUTIVO.md

# Documentación técnica de módulos
start docs/technical_overview.md
```

### Estructura de la Documentación

```
docs/
├── ANALISIS_CRIPTOGRAFICO_TEL252.md    # ~50 páginas
│   ├── Matemática de HMAC-SHA256
│   ├── Matemática de TOTP (RFC 6238)
│   ├── Matemática de RSA-OAEP
│   ├── Matemática de AES-256-GCM
│   ├── Implementación detallada de cada primitiva
│   ├── Justificaciones de diseño
│   └── Referencias a clases específicas de TEL252
│
├── GUIA_USUARIO.md                      # ~40 páginas
│   ├── Requisitos e instalación
│   ├── Uso del cliente CLI (paso a paso)
│   ├── Uso del cliente web (paso a paso)
│   ├── Operaciones criptográficas en el navegador
│   ├── Ejecución con Docker
│   ├── Tests automatizados
│   └── Troubleshooting común
│
├── DIAGRAMA_FLUJO_COMPLETO.md           # ~30 páginas
│   ├── Flujo de registro (con operaciones crypto)
│   ├── Flujo de login (HMAC + TOTP)
│   ├── Flujo de envío de mensaje (RSA-OAEP + AES-GCM)
│   ├── Flujo de recepción (descifrado)
│   └── Tabla de parámetros de seguridad
│
├── technical_overview.md                # ~10 páginas
│   ├── Descripción de crypto.py
│   ├── Descripción de database.py
│   ├── Descripción de server.py
│   └── Descripción de client_cli.py
│
└── architecture.mmd                     # Diagrama Mermaid
    └── Sequence diagram del flujo completo

RESUMEN_EJECUTIVO.md                     # ~25 páginas (raíz)
├── Información del proyecto
├── Decisiones de diseño criptográficas
├── Arquitectura del sistema
├── Tabla de primitivas vs clases
├── Flujo E2E simplificado
├── Propiedades de seguridad
├── Checklist de requisitos
└── Cómo evaluar el proyecto
```

---

## Comandos Útiles

### Gestión del Servidor

```powershell
# Iniciar servidor
python -m lab7_e2ee_chat.server

# Iniciar en puerto alternativo (editar server.py)
# Cambiar última línea: app.run(debug=True, port=5001)
```

### Gestión de Base de Datos

```powershell
# Ver usuarios registrados
sqlite3 chat.db "SELECT id, identifier, display_name FROM users;"

# Ver dispositivos
sqlite3 chat.db "SELECT id, user_id, device_name FROM devices;"

# Contar mensajes
sqlite3 chat.db "SELECT COUNT(*) FROM messages;"

# Resetear base de datos
Remove-Item chat.db -ErrorAction SilentlyContinue
python -m lab7_e2ee_chat.server  # Recrea schema automáticamente
```

### Limpieza Completa

```powershell
# Eliminar base de datos y secretos
Remove-Item chat.db -ErrorAction SilentlyContinue
Remove-Item .session_secret -ErrorAction SilentlyContinue
Remove-Item .password_secret -ErrorAction SilentlyContinue

# Eliminar perfiles de cliente CLI
Remove-Item -Recurse $HOME\.tel252_chat -ErrorAction SilentlyContinue

# Eliminar cache de Python
Remove-Item -Recurse __pycache__ -ErrorAction SilentlyContinue
Remove-Item -Recurse .pytest_cache -ErrorAction SilentlyContinue
```

---

## Solución de Problemas Comunes

### Error: "ModuleNotFoundError: No module named 'Crypto'"

```powershell
pip uninstall crypto pycrypto pycryptodome
pip install pycryptodome
```

### Error: "Address already in use (Puerto 5000 ocupado)"

```powershell
# Opción 1: Encontrar y matar proceso
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Opción 2: Usar otro puerto (editar server.py)
```

### Error: "TOTP verification failed"

- ✅ Verificar que el reloj del sistema está sincronizado
- ✅ El código TOTP cambia cada 30 segundos
- ✅ Asegurar que se copió el secret correctamente

### Error: "MAC check failed" al descifrar

- ❌ El mensaje fue modificado
- ❌ Usaste la llave privada incorrecta
- ❌ Los artefactos están incompletos o corruptos

---

## Checklist de Evaluación

### ✅ Instalación y Ejecución
- [ ] Dependencies instaladas sin errores
- [ ] Servidor inicia en puerto 5000
- [ ] Cliente web accesible en `/ui/`
- [ ] Tests pasan correctamente

### ✅ Funcionalidad E2EE
- [ ] Registro de usuarios funciona
- [ ] TOTP se genera y valida correctamente
- [ ] Mensajes se cifran en el cliente
- [ ] Servidor no puede leer mensajes (verificar DB)
- [ ] Destinatario descifra correctamente

### ✅ Primitivas Criptográficas
- [ ] HMAC-SHA256 para passwords (Clase 11) ✓
- [ ] TOTP RFC 6238 (Clase 11) ✓
- [ ] RSA-2048 keygen (Clase 4) ✓
- [ ] RSA-OAEP key wrapping (Clase 8) ✓
- [ ] AES-256-GCM AEAD (Clases 3 y 11) ✓
- [ ] HMAC-SHA256 JWT tokens (Clase 11) ✓

### ✅ Documentación
- [ ] Análisis criptográfico completo ✓
- [ ] Diagramas con matemática ✓
- [ ] Referencias a clases de TEL252 ✓
- [ ] Guía de usuario paso a paso ✓
- [ ] Código extensivamente comentado ✓

### ✅ Extras
- [ ] Cliente web funcional ✓
- [ ] Dockerfile para containerización ✓
- [ ] Tests automatizados con pytest ✓
- [ ] Multiple clients (CLI + Web) ✓

---

## Contacto y Soporte

**Proyecto:** Lab 7 - Chat E2EE  
**Asignatura:** TEL252 - Criptografía y Seguridad en la Información  
**Institución:** Universidad Técnica Federico Santa María  
**Semestre:** 2do Semestre, 2025  
**Docente:** Daniel Espinoza

---

**¡Gracias por evaluar este proyecto!** 🔐
