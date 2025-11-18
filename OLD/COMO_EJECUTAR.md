# 🚀 Cómo Ejecutar el Proyecto TEL252 E2EE Chat

## ✅ Estado: FUNCIONANDO AL 100%

Ambos servicios están operativos:
- ✅ **API Server** funcionando en `http://127.0.0.1:5000`
- ✅ **Web Client** funcionando en `http://127.0.0.1:5001`

---

## 🎯 Método Recomendado: Launcher Automático

### Opción 1: Script PowerShell (Windows)

```powershell
.\start.ps1
```

Esto abrirá:
1. Una terminal con la API Server (puerto 5000)
2. Una terminal con el Web Client (puerto 5001)
3. Tu navegador en `http://127.0.0.1:5001`

**Nota:** Escribe `y` cuando pregunte si quieres limpiar datos anteriores (recomendado para testing).

---

## 🔧 Método Manual: 2 Terminales Separadas

Si el script automático no funciona, usa este método:

### Terminal 1 - API Server

```powershell
cd C:\Users\Cris\Desktop\e2e_chat
.\.venv\Scripts\Activate.ps1
python run_api.py
```

Deberías ver:
```
==================================================
🚀 TEL252 Secure Chat API Server
==================================================
✓ Server running on: http://127.0.0.1:5000
✓ Health endpoint: http://127.0.0.1:5000/health
✓ Press CTRL+C to quit
==================================================
 * Running on http://127.0.0.1:5000
```

### Terminal 2 - Web Client

```powershell
cd C:\Users\Cris\Desktop\e2e_chat
.\.venv\Scripts\Activate.ps1
python clients/web_app.py
```

Deberías ver:
```
 * Running on http://127.0.0.1:5001
 * Debug mode: on
```

### Abrir en Navegador

Abre manualmente: **`http://127.0.0.1:5001`**

---

## 🧪 Verificar que Todo Funciona

Ejecuta este comando en una **tercera terminal**:

```powershell
cd C:\Users\Cris\Desktop\e2e_chat
.\.venv\Scripts\Activate.ps1

python -c "import requests; api = requests.get('http://127.0.0.1:5000/health'); web = requests.get('http://127.0.0.1:5001'); print('✓ API:', api.status_code); print('✓ Web:', web.status_code)"
```

**Output esperado:**
```
✓ API: 200
✓ Web: 200
```

---

## 📝 Cómo Usar la Aplicación

### 1. Registrar Usuarios

1. Abre `http://127.0.0.1:5001` en tu navegador
2. Haz clic en **"Register"**
3. Ingresa:
   - **Phone:** `+56911111111` (formato E.164)
   - **Password:** `alice123`
4. **IMPORTANTE:** Guarda el **código QR TOTP** que aparece
   - Escanéalo con Google Authenticator o Microsoft Authenticator
   - O copia el secret manualmente
5. Haz clic en **"Continue to Login"**

### 2. Login con 2FA

1. Ingresa el mismo teléfono y contraseña
2. Abre tu app de authenticator (Google/Microsoft)
3. Ingresa el **código de 6 dígitos** (TOTP)
4. Haz clic en **"Login"**

### 3. Agregar Contactos

1. En el Dashboard, ve a **"Add Contact"**
2. Ingresa el número del destinatario (ej: `+56922222222`)
3. El destinatario también debe agregarte (mutual approval)

### 4. Enviar Mensajes Cifrados

1. Haz clic en un contacto aprobado
2. Escribe tu mensaje: `"Hola! Este mensaje está cifrado E2EE 🔐"`
3. Haz clic en **"Send"**
4. El mensaje se cifra con **ChaCha20-Poly1305** antes de enviarse

### 5. Verificar Cifrado (Wireshark)

Sigue la guía completa en: **`docs/wireshark_guide.md`**

---

## 🛑 Cómo Detener la Aplicación

### Si usaste `start.ps1`:
- Cierra las 2 ventanas de PowerShell que se abrieron automáticamente

### Si iniciaste manualmente:
- Presiona **`Ctrl+C`** en cada terminal (API y Web Client)

---

## 🧹 Limpiar Datos

Para empezar con datos frescos:

```powershell
Remove-Item data/*.json -Force
Remove-Item clients/state/*.json -Force
```

O simplemente responde `y` cuando `start.ps1` pregunte.

---

## 🐛 Troubleshooting

### Error: "No module named 'clients'"

**Solución:** Ya fue corregido. Asegúrate de usar la versión actualizada de `clients/web_app.py`.

### Error: "Connection refused" en puerto 5000 o 5001

**Causa:** El servicio no está iniciado o murió.

**Solución:**
1. Verifica que ambos servicios estén corriendo
2. Busca errores en las terminales de API/Web Client
3. Reinicia ambos servicios

### Error: "Port already in use"

**Causa:** Ya hay un proceso usando el puerto 5000 o 5001.

**Solución:**
```powershell
# Encontrar proceso en puerto 5000
netstat -ano | findstr :5000

# Matar proceso (reemplaza <PID> con el número que viste)
taskkill /PID <PID> /F
```

### La página web no carga

**Solución:**
1. Verifica que ambos servicios estén corriendo (ver sección de verificación)
2. Limpia caché del navegador: `Ctrl+Shift+Delete`
3. Intenta en modo incógnito: `Ctrl+Shift+N`
4. Prueba con otro navegador

### El código TOTP no funciona

**Causas posibles:**
- Reloj del PC desincronizado (TOTP depende del tiempo)
- Secret TOTP incorrecto
- Código expiró (cambia cada 30 segundos)

**Solución:**
1. Sincroniza el reloj de tu PC con internet
2. Re-registra el usuario y escanea el QR nuevamente
3. Usa el código inmediatamente después de generarse

---

## 📚 Documentación Completa

- **Diagrama de Secuencia (50% nota):** `docs/sequence_diagram.md`
- **Arquitectura y Justificaciones:** `docs/architecture.md`
- **Guía Wireshark:** `docs/wireshark_guide.md`
- **Deployment TLS:** `docs/deployment_guide.md`
- **README Principal:** `README_FINAL.md`
- **Resumen Ejecutivo:** `RESUMEN_EJECUTIVO.md`

---

## 🎓 Para el Profesor

### Revisión Rápida (15 minutos)

1. Ejecutar: `.\start.ps1`
2. Abrir: `http://127.0.0.1:5001`
3. Registrar 2 usuarios (Alice y Bob)
4. Probar flujo de mensajería E2EE
5. Revisar: `docs/sequence_diagram.md`

### Evaluación Completa (45 minutos)

1. Ejecutar tests: `python -m pytest tests/ -v`
2. Revisar código: `app/crypto.py`, `app/server.py`
3. Verificar primitivas criptográficas en `docs/architecture.md`
4. Captura Wireshark siguiendo `docs/wireshark_guide.md`
5. Verificar documentación completa

---

## ✅ Checklist de Funcionalidad

Marca cada item después de probarlo:

- [ ] API Server inicia sin errores
- [ ] Web Client inicia sin errores
- [ ] Registro de usuario funciona
- [ ] Código QR TOTP se genera
- [ ] Login con 2FA funciona
- [ ] Agregar contactos funciona
- [ ] Mutual approval funciona
- [ ] Envío de mensajes funciona
- [ ] Descifrado de mensajes funciona
- [ ] Tests pasan: `pytest tests/ -v`
- [ ] Wireshark captura tráfico cifrado

Si todos los items tienen ✓, el proyecto está **100% funcional** para entrega.

---

**🔐 TEL252 Lab 7 - E2EE Chat | UTFSM 2025**

**Developed by:** Cristian  
**Date:** 13 de Noviembre, 2025  
**Status:** ✅ READY FOR SUBMISSION
