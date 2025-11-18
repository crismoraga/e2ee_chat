# Diagrama de Arquitectura Criptográfica – TEL252 E2EE Chat

Este documento sintetiza la versión actualizada del sistema: nueva UI tipo workspace, QR/TOTP obligatorio desde el perfil del usuario y endurecimiento de los flujos criptográficos descritos en `docs/DIAGRAMAS_TECNICOS.md`.

## Resumen de la versión

- Interfaz web con paneles de contactos, mensajes y perfil con QR integrado.
- Registro/login reforzado: contraseña procesada con HMAC-SHA256 y TOTP RFC 6238 obligatorio.
- Mensajería E2EE basada en RSA-2048 + AES-256-GCM con llaves efímeras por mensaje.
- Servidor Flask actúa como "blind relay": no ve plaintext ni llaves privadas.
- SQLite mantiene solo metadatos y blobs cifrados (todo en Base64).

## Inventario de componentes criptográficos

| Componente | Ubicación | Responsabilidad | Material sensible |
| --- | --- | --- | --- |
| Cliente web | Navegador (JS) | Render UI, generar RSA local, cifrar/descifrar | Llave privada RSA-2048, llaves AES efímeras, token de sesión |
| Servidor Flask | `server.py` | Autenticación, emisión de tokens, relay de mensajes | `session_secret`, `password_secret`, llaves públicas registradas |
| Base de datos SQLite | `database.py` | Persistir usuarios, dispositivos y mensajes | Hashes HMAC, secretos TOTP base32, blobs cifrados |
| Canal HTTP(S) | Internet | Transporte JSON/REST | Ninguno (solo ciphertext y metadata) |

## Flujo 1 · Registro y aprovisionamiento

1. El usuario envía `POST /api/register` con `identifier`, `display_name` y `password`.
1. El servidor deriva `password_hash = HMAC_SHA256(password_secret, password)` y genera `totp_secret` (160 bits → base32).
1. Se persiste el usuario y se responde con `user_id` y el secreto TOTP para bootstrap.
1. Desde la UI (`perfil.html`) el usuario pulsa **Generar código QR** (`GET /api/totp/setup`). El backend devuelve la URL `otpauth://` que el frontend renderiza como imagen QR (librería `qrcode`).
1. Tras escanear el QR, el cliente genera localmente un par RSA-2048. La llave privada vive en memoria/IndexedDB; la pública se conserva para el siguiente flujo.

## Flujo 2 · Login + 2FA

1. El usuario ejecuta `POST /api/login` con `identifier`, `password` y `totp_code` vigente.
1. El servidor busca al usuario, vuelve a computar el HMAC de la contraseña y lo compara con el almacenado de forma constante.
1. Se valida el código TOTP con ventana ±30 s (RFC 6238). Sin coincidencia no hay token.
1. Se emite un token de sesión tipo JWT-light (`header.payload.signature`) firmado con `session_secret` (HS256) y con expiración de 1 h.
1. El frontend guarda el token en memoria y registra la llave pública con `POST /api/devices` (autenticado), asociando device name + PEM.

## Flujo 3 · Mensajería E2EE

1. El remitente resuelve la llave pública del contacto con `GET /api/users/<identifier>`.
1. Se genera una llave AES-256 efímera, un `nonce` de 96 bits y se cifra el mensaje vía AES-GCM → `(ciphertext, tag)`.
1. La llave AES se envuelve con RSA-OAEP utilizando la llave pública del destinatario.
1. Se envía `POST /api/messages` con el payload:

```json
{
    "recipient_id": 2,
    "device_id": 5,
    "wrapped_key": "...",
    "nonce": "...",
    "ciphertext": "...",
    "tag": "...",
    "aad": null
}
```

1. El servidor valida el token HMAC, almacena el mensaje opaco y responde `201 + message_id`.

## Flujo 4 · Recepción y limpieza

1. El destinatario realiza `GET /api/messages` autenticado; el servidor retorna la lista de artefactos cifrados.
1. Por cada mensaje, el cliente usa su llave privada RSA para ejecutar RSA-OAEP inverse → obtiene la llave AES.
1. Con la llave simétrica, `nonce` y `tag`, ejecuta AES-256-GCM decrypt. Si la etiqueta no coincide se descarta el mensaje.
1. El mensaje en texto plano se muestra en la UI y opcionalmente se pide `DELETE /api/messages/<id>` para limpiar el backend.

## Artefactos relevantes

- **Registro**: `identifier`, `display_name`, `password`. Respuesta incluye `user_id` y `totp_secret` (para bootstrap inicial en CLI o UI).
- **Login**: `identifier`, `password`, `totp_code`. Respuesta `session_token` firmado HS256.
- **TOTP Setup**: `GET /api/totp/setup` (autenticado) → `{ "otpauth_url": "otpauth://totp/..." }` usado para el QR en el perfil.
- **Mensajes**: cifrado híbrido (AES-GCM + RSA-OAEP) encapsulado totalmente en Base64.

## Propiedades criptográficas garantizadas

- **Confidencialidad end-to-end**: solo los clientes poseen llaves privadas; las llaves AES se rotan por mensaje.
- **Integridad**: GCM Tag (128 bits) + verificación estricta `hmac.compare_digest` para contraseñas y tokens.
- **Autenticación fuerte**: contraseña + TOTP obligatorio + tokens firmados HS256 para cada request.
- **Blind storage**: el servidor solo reenvía blobs y no puede reconstruir plaintext ni secretos de sesión.
- **Observabilidad controlada**: SQLite guarda metadatos mínimos (sender, recipient, timestamps) útiles para debugging sin comprometer contenido.
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
