# Guía de Captura de Tráfico con Wireshark – TEL252 Lab 7

Esta guía demuestra que el tráfico de la API está cifrado end-to-end y que un atacante con acceso a la red (incluso el administrador del servidor) **NO puede ver los mensajes en texto plano**.

---

## Objetivo

Capturar el tráfico HTTP entre el cliente y la API, y verificar que:

1. ✅ Los payloads están cifrados (Base64-encoded ciphertexts)
2. ✅ Los mensajes en plaintext NO aparecen en la captura
3. ✅ Sin las claves privadas del cliente, es imposible descifrar

---

## Requisitos Previos

1. **Wireshark instalado:**
   ```pwsh
   # Windows: Descargar desde https://www.wireshark.org/download.html
   # O instalar con winget
   winget install -e --id WiresharkFoundation.Wireshark
   ```

2. **API y cliente corriendo:**
   - Terminal 1: API server en `http://127.0.0.1:5000`
   - Terminal 2: Web client en `http://127.0.0.1:5001`

---

## Paso 1: Iniciar Captura en Wireshark

1. **Abrir Wireshark** (Ejecutar como Administrador en Windows)

2. **Seleccionar interfaz de red:**
   - Para tráfico local (127.0.0.1), seleccionar **Loopback: lo0** (macOS/Linux) o **Npcap Loopback Adapter** (Windows)
   - Doble clic en la interfaz para iniciar captura

3. **Aplicar filtro de captura:**
   ```
   tcp.port == 5000
   ```
   
   Esto filtra solo el tráfico HTTP hacia/desde la API (puerto 5000)

4. **Iniciar captura:** Click en el ícono de aleta de tiburón azul (Start capturing packets)

---

## Paso 2: Generar Tráfico de la API

### Escenario: Alice envía mensaje cifrado a Bob

1. **Terminal 1 – Iniciar API:**
   ```pwsh
   cd C:\Users\Cris\Desktop\e2e_chat
   python -m flask --app app.server:create_app() run --port 5000
   ```

2. **Terminal 2 – Iniciar Web Client:**
   ```pwsh
   cd C:\Users\Cris\Desktop\e2e_chat
   python clients/web_app.py
   ```

3. **Browser – Registrar Alice:**
   - Ir a `http://127.0.0.1:5001`
   - Registrar usuario: `+56911111111`, password: `wonderland`
   - Copiar TOTP secret y configurar Microsoft Authenticator

4. **Browser – Registrar Bob:**
   - Registrar usuario: `+56922222222`, password: `builder`
   - Configurar TOTP

5. **Browser – Alice envía mensaje:**
   - Login como Alice con TOTP
   - Añadir contacto: `+56922222222`
   - (Bob debe añadir a Alice también)
   - Enviar mensaje: **"Hola Bob! Esta es una prueba de cifrado E2EE 🔐"**

---

## Paso 3: Detener Captura y Analizar Tráfico

1. **Detener captura en Wireshark:** Click en el cuadrado rojo (Stop capturing)

2. **Aplicar filtro de display:**
   ```
   http.request.method == "POST" && http.request.uri contains "/messages"
   ```

3. **Encontrar el POST /messages request:**
   - En la lista de paquetes, buscar: `POST /messages HTTP/1.1`
   - Click derecho → Follow → HTTP Stream

---

## Paso 4: Verificar Cifrado End-to-End

### 🔍 Qué VAS A VER (tráfico cifrado):

```http
POST /messages HTTP/1.1
Host: 127.0.0.1:5000
Authorization: Bearer +56911111111:1699824000.abc123def456...
Content-Type: application/json

{
  "recipient": "+56922222222",
  "ciphertext": "Xk2pLm8qN5rT9wZv3jH7YbK4mP1sA6cE8nF0gQ2uI5xD7vB9lW4hM3oR6tY8zU1pL",
  "nonce": "Qm5vN8yZ2cF4hL6kP1sX9wE3tR7uI0oY",
  "aad": "eyJzZW5kZXIiOiIrNTY5MTExMTExMTEiLCJyZWNpcGllbnQiOiIrNTY5MjIyMjIyMjIiLCJ0aW1lc3RhbXAiOjE2OTk4MjQwMDAsImNvbnRleHQiOiJURUwyNTItRTJFRTorNTY5MTExMTExMTE6KzU2OTIyMjIyMjIyIn0",
  "signature": "Ab3C5dE7fG9hI1jK3lM5nO7pQ9rS1tU3vW5xY7zA1bC3dE5fG7hI9jK1lM3nO5pQ"
}
```

### ❌ Qué NO VAS A VER (plaintext):

- **NO** verás: `"Hola Bob! Esta es una prueba de cifrado E2EE 🔐"`
- **NO** verás: Claves privadas (identity_private, signing_private)
- **NO** verás: Shared key derivada con HKDF

### ✅ Qué SÍ puedes decodificar (pero sigue siendo seguro):

1. **AAD (Authenticated Additional Data):**
   ```pwsh
   # Decodificar AAD desde Base64url
   $aad_b64 = "eyJzZW5kZXIiOiIrNTY5MTExMTExMTEiLCJyZWNpcGllbnQiOiIrNTY5MjIyMjIyMjIiLCJ0aW1lc3RhbXAiOjE2OTk4MjQwMDAsImNvbnRleHQiOiJURUwyNTItRTJFRTorNTY5MTExMTExMTE6KzU2OTIyMjIyMjIyIn0"
   $aad_bytes = [System.Convert]::FromBase64String($aad_b64)
   $aad_json = [System.Text.Encoding]::UTF8.GetString($aad_bytes)
   Write-Host $aad_json
   ```

   **Output:**
   ```json
   {
     "sender": "+56911111111",
     "recipient": "+56922222222",
     "timestamp": 1699824000,
     "context": "TEL252-E2EE:+56911111111:+56922222222"
   }
   ```

   ⚠️ **Nota:** AAD contiene metadata pero NO el plaintext del mensaje. Es seguro que sea visible.

2. **Ciphertext, Nonce, Signature:**
   - Están en Base64url pero son **binarios aleatorios**
   - Sin la `shared_key` (derivada con X25519 + HKDF), NO se puede descifrar
   - La `shared_key` NUNCA viaja por la red, solo existe en memoria del cliente

---

## Paso 5: Intentar "Descifrar" (Demostración de Seguridad)

### 🚫 Ataque 1: Decodificar Base64 del ciphertext

```pwsh
# En PowerShell
$ciphertext_b64 = "Xk2pLm8qN5rT9wZv3jH7YbK4mP1sA6cE8nF0gQ2uI5xD7vB9lW4hM3oR6tY8zU1pL"
$ciphertext_bytes = [System.Convert]::FromBase64String($ciphertext_b64 + "==")
[System.Text.Encoding]::UTF8.GetString($ciphertext_bytes)
```

**Resultado:** Basura binaria ilegible (bytes aleatorios)

**Razón:** ChaCha20 produce ciphertext indistinguible de aleatorio

### 🚫 Ataque 2: Brute force de la shared_key

**Complejidad:** $2^{256}$ operaciones para una llave de 256 bits

**Tiempo estimado:** Más años que la edad del universo con toda la capacidad computacional de la Tierra

**Conclusión:** Criptográficamente imposible

### 🚫 Ataque 3: Compromiso del servidor

**Qué obtiene el atacante:**
- ✅ Ciphertext, nonce, AAD, signature (ya públicos en captura)
- ✅ Public keys de Alice y Bob (almacenadas en DB)
- ❌ Private keys (solo en clientes, nunca en servidor)
- ❌ Shared key (derivada localmente, nunca enviada)

**Resultado:** Atacante NO puede descifrar mensajes

---

## Paso 6: Verificar Propiedades de Seguridad

### ✅ Confidencialidad (E2EE)

- **Captura Wireshark:** Muestra solo ciphertext
- **Servidor comprometido:** NO puede leer mensajes
- **ISP/Red comprometida:** NO puede leer mensajes
- **Solo Alice y Bob:** Tienen las claves privadas para derivar shared_key

### ✅ Integridad

- **Firma Ed25519:** Cualquier modificación del ciphertext/nonce/AAD invalida la firma
- **Poly1305 MAC:** ChaCha20-Poly1305 detecta modificaciones con AEAD tag
- **Test en Wireshark:**
  1. Editar manualmente un byte del ciphertext en la captura
  2. Re-enviar el paquete modificado
  3. Servidor rechaza con error `invalid signature` o `decryption failed`

### ✅ Autenticidad

- **Ed25519 signature:** Prueba que el mensaje fue enviado por Alice (quien tiene `signing_private`)
- **Verificación:** Bob verifica firma con `signing_public` de Alice antes de descifrar

---

## Paso 7: Comparación con Tráfico NO Cifrado (Contraejemplo)

Para demostrar la diferencia, aquí está cómo se vería una API **INSEGURA** sin E2EE:

```http
POST /messages-insecure HTTP/1.1
Content-Type: application/json

{
  "sender": "+56911111111",
  "recipient": "+56922222222",
  "message": "Hola Bob! Esta es una prueba de cifrado E2EE 🔐"
}
```

☠️ **Resultado:** El mensaje en **TEXTO PLANO** es visible en Wireshark, logs del servidor, backups, etc.

✅ **Nuestra implementación:** `"message"` NO existe, solo `"ciphertext"`

---

## Comandos de Wireshark Útiles

### Exportar captura como JSON

```pwsh
# Desde línea de comandos (tshark)
tshark -r capture.pcapng -T json > capture.json
```

### Filtro para ver solo JSON payloads

```
http.request.method == "POST" && json
```

### Buscar strings en payloads

```
frame contains "ciphertext"
```

---

## Conclusión

Esta captura de Wireshark demuestra que:

1. ✅ **E2EE funciona:** Mensajes viajan cifrados por la red
2. ✅ **Servidor es "ciego":** NO puede leer plaintext
3. ✅ **Atacante pasivo fracasa:** Captura de red NO revela mensajes
4. ✅ **Cumple TEL252:** Uso correcto de ChaCha20-Poly1305, X25519, Ed25519, HKDF-SHA3-256

**Para la evaluación del Lab 7:**
- Captura de pantalla de Wireshark mostrando el POST /messages con ciphertext
- Captura mostrando que la decodificación Base64 produce basura
- Explicación de por qué el servidor no puede descifrar

---

## Bonus: Captura con HTTPS (Clase 12 - TLS)

Si habilitas TLS (ver `deployment_guide.md`), incluso la metadata HTTP estará cifrada:

```pwsh
# Generar certificado self-signed
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Correr Flask con TLS
flask --app app.server:create_app() run --cert cert.pem --key key.pem --port 5000
```

**En Wireshark con TLS:**
- Verás handshake TLS (ClientHello, ServerHello, Certificate, etc.)
- Verás Application Data cifrado con TLS (AES-GCM o ChaCha20-Poly1305)
- **Doble capa de cifrado:** TLS (transporte) + ChaCha20-Poly1305 (E2EE)

Para descifrar TLS en Wireshark:
- Necesitas la clave privada del servidor (`key.pem`)
- Edit → Preferences → Protocols → TLS → RSA keys list → Add
- **Resultado:** Verás el JSON request, pero el `ciphertext` sigue siendo indescifrable (E2EE interno)

Esto demuestra **defense in depth** (defensa en profundidad): TLS protege en tránsito, E2EE protege end-to-end.
