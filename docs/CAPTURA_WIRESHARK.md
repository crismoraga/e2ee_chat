# Guía Express para Capturar el Tráfico TLS con Wireshark

Esta guía documenta exactamente cómo demostrar que el servidor Flask corre sobre TLS (modo `iniciar_servidor.py --tls`) y que, aun teniendo el `.pcap`, no es posible recuperar el contenido de los mensajes intercambiados.

---

## 1. Preparar el servidor con TLS autodemo

1. Abre una terminal en `lab7_e2ee_chat` y ejecuta:

   ```pwsh
   python iniciar_servidor.py --tls --host 0.0.0.0 --port 5443
   ```

2. El script genera un certificado autofirmado temporal (`adhoc`) con `werkzeug.serving.make_ssl_devcert`. Si necesitas usar un certificado propio, añade `--cert ruta.crt --key ruta.key`.

3. Verifica que el servidor imprime la URL `https://localhost:5443/ui/` antes de pasar a Wireshark.

## 2. Generar tráfico cifrado

1. Abre `https://localhost:5443/ui/` desde el mismo equipo. Acepta la advertencia del navegador por ser un certificado autofirmado.
2. Registra dos cuentas (Alice y Bob), loguea al menos una y envía un mensaje a la otra. Con esto tendrás HTTPs POST/GET sobre el puerto 5443.
3. Mantén la pestaña abierta: la UI seguirá usando fetch sobre TLS para enviar/recibir mensajes.

## 3. Capturar con Wireshark

1. Inicia Wireshark y selecciona la interfaz de loopback (`Npcap Loopback Adapter`) o la que corresponda si accedes desde otro host.
2. Aplica el filtro de captura o visualización `tcp.port == 5443` para quedarte solo con el tráfico HTTPS de la demo.
3. Pulsa **Start** y vuelve al navegador para repetir estas acciones:
   - Enviar un mensaje desde Alice a Bob.
   - Refrescar la bandeja de Bob.
   - Consultar el directorio de contactos (GET `/api/users`).
4. Detén la captura y guarda el archivo como `captura_tls_lab7.pcapng`.

## 4. Qué debe observar el asistente

En la lista de paquetes aparecerán, en orden aproximado:

- `Client Hello` y `Server Hello` con SNI `localhost`.
- `Certificate`, `Server Key Exchange` y `Encrypted Extensions`.
- `Change Cipher Spec` seguido de `Encrypted Handshake Message` y después flujos `Application Data`.
- El handshake usará TLS 1.2 o 1.3 dependiendo del navegador (ambos válidos para el laboratorio).

Puedes hacer clic derecho en cualquier paquete y elegir **Follow TLS Stream** para mostrar solo los registros TLS asociados.

## 5. Cómo argumentar que no se puede leer el contenido

- **Cifrado simétrico:** Después del handshake, todo lo que verás es `Application Data` con registros AES-GCM. No hay texto plano ni cabeceras HTTP visibles.
- **Claves efímeras:** Aunque tuvieras el `.pcap`, necesitarías las claves privadas del servidor y además la clave de sesión (derivada durante el handshake). La demo usa certificados efímeros generados al vuelo y nunca expone la clave privada del dispositivo del destinatario.
- **E2EE adicional:** Aun si un atacante rompiera TLS, los cuerpos de los mensajes contienen ciphertext producido por AES-256-GCM en el cliente y solo se pueden abrir con la llave RSA del receptor.
- **Validación práctica:** Intenta decodificar `Application Data` en Wireshark: el panel mostrará bytes aleatorios y Wireshark indicará `Decryption failed or bad record mac` porque no posee el secreto compartido.

## 6. Evidencia sugerida para el informe

1. Captura de pantalla del mensaje en la UI web indicando que se usó `https://`.
2. Captura de Wireshark mostrando el handshake TLS (ClientHello/ServerHello/certificate).
3. Captura de Wireshark con paquetes `Application Data` resaltados y el tooltip mostrando que el contenido está cifrado.
4. Nota textual explicando que, aunque el `.pcapng` está adjunto, nadie fuera del emisor/receptor posee las llaves para descifrar ni TLS ni la capa E2EE.

Con estas evidencias se cumple el requisito del laboratorio de demostrar visiblemente tráfico interceptado en Wireshark que permanece ilegible.
