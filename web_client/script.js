const API_BASE = window.API_BASE || "";
const STORAGE_KEY = "tel252_e2ee_state_v3";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
    sessions: new Map(), // identifier -> { token, displayName }
    totpSecrets: new Map(),
    keyPairs: new Map(), // identifier -> { publicPem, privatePem, privateKey, deviceName }
    inboxCache: new Map(), // identifier -> decrypted[]
    sentMessages: [],
    contacts: [],
    activeUser: null,
    activeChat: null,
};

const dom = {
    authView: document.getElementById("auth-view"),
    appView: document.getElementById("app-view"),
    tabs: document.querySelectorAll(".tabs .tab"),
    loginForm: document.getElementById("login-form"),
    registerForm: document.getElementById("register-form"),
    loginFeedback: document.getElementById("login-feedback"),
    registerFeedback: document.getElementById("register-feedback"),
    loginIdentifier: document.getElementById("login-identifier"),
    loginPassword: document.getElementById("login-password"),
    loginTotp: document.getElementById("login-totp"),
    registerIdentifier: document.getElementById("register-identifier"),
    registerPassword: document.getElementById("register-password"),
    registerDisplay: document.getElementById("register-display"),
    contactList: document.getElementById("contacts-list"),
    contactSearch: document.getElementById("contact-search"),
    composer: document.getElementById("composer"),
    composerInput: document.getElementById("composer-input"),
    sendButton: document.getElementById("send-button"),
    chatThread: document.getElementById("chat-messages"),
    activeChatName: document.getElementById("active-chat-name"),
    activeChatStatus: document.getElementById("active-chat-status"),
    userBadge: document.getElementById("user-badge"),
    newChatBtn: document.getElementById("new-chat-btn"),
    logoutBtn: document.getElementById("logout-btn"),
};

function persistState() {
    const payload = {
        sessions: Object.fromEntries(state.sessions),
        totpSecrets: Object.fromEntries(state.totpSecrets),
        keyPairs: Object.fromEntries(
            [...state.keyPairs.entries()].map(([identifier, entry]) => [
                identifier,
                {
                    publicPem: entry.publicPem,
                    privatePem: entry.privatePem,
                    deviceName: entry.deviceName,
                },
            ]),
        ),
        inboxCache: Object.fromEntries(state.inboxCache),
        sentMessages: state.sentMessages,
        contacts: state.contacts,
        activeUser: state.activeUser,
        activeChat: state.activeChat,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

function loadState() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) {
            return;
        }
        const payload = JSON.parse(raw);
        state.sessions = new Map(Object.entries(payload.sessions || {}));
        state.totpSecrets = new Map(Object.entries(payload.totpSecrets || {}));
        state.keyPairs = new Map(
            Object.entries(payload.keyPairs || {}).map(([identifier, entry]) => [
                identifier,
                {
                    publicPem: entry.publicPem,
                    privatePem: entry.privatePem,
                    privateKey: null,
                    deviceName: entry.deviceName,
                },
            ]),
        );
        state.inboxCache = new Map(Object.entries(payload.inboxCache || {}));
        state.sentMessages = payload.sentMessages || [];
        state.contacts = payload.contacts || [];
        state.activeUser = payload.activeUser || null;
        state.activeChat = payload.activeChat || null;
    } catch (error) {
        console.warn("No se pudo cargar el estado previo", error);
        localStorage.removeItem(STORAGE_KEY);
    }
}

async function api(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
        headers: { "Content-Type": "application/json", ...(options.headers || {}) },
        ...options,
    });
    if (!response.ok) {
        let message = `${response.status} ${response.statusText}`;
        try {
            const body = await response.json();
            if (body.error) {
                message = body.error;
            }
        } catch (_) {
            // ignore json parse
        }
        throw new Error(message);
    }
    const text = await response.text();
    return text ? JSON.parse(text) : {};
}

function showFeedback(target, message, type = "info") {
    if (!target) {
        return;
    }
    target.textContent = message;
    target.dataset.variant = type;
}

function toggleAuthTab(tabName) {
    dom.tabs.forEach((tab) => {
        const isActive = tab.dataset.tab === tabName;
        tab.classList.toggle("active", isActive);
        tab.setAttribute("aria-selected", String(isActive));
    });
    dom.loginForm.classList.toggle("hidden", tabName !== "login");
    dom.registerForm.classList.toggle("hidden", tabName !== "register");
}

function setView(view) {
    if (view === "app") {
        dom.authView.classList.add("hidden");
        dom.appView.classList.remove("hidden");
    } else {
        dom.authView.classList.remove("hidden");
        dom.appView.classList.add("hidden");
    }
}

function getSession(identifier) {
    const session = state.sessions.get(identifier);
    if (!session) {
        throw new Error("Sesión no encontrada. Inicia sesión nuevamente.");
    }
    return session;
}

function listSessions() {
    return [...state.sessions.keys()];
}

function renderContacts(filterValue = "") {
    const container = dom.contactList;
    if (!container) {
        return;
    }
    container.innerHTML = "";
    const normalized = filterValue.trim().toLowerCase();
    const filtered = state.contacts.filter((contact) => {
        if (!contact.public_key_pem) {
            return false;
        }
        if (!normalized) {
            return true;
        }
        return (
            contact.identifier.toLowerCase().includes(normalized) ||
            (contact.display_name || "").toLowerCase().includes(normalized)
        );
    });
    if (!filtered.length) {
        const empty = document.createElement("p");
        empty.className = "empty";
        empty.textContent = "No encontramos contactos con esas letras.";
        container.appendChild(empty);
        return;
    }
    filtered.forEach((contact) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = `contact ${contact.identifier === state.activeChat ? "active" : ""}`;
        btn.dataset.identifier = contact.identifier;
        btn.innerHTML = `
            <div>
                <strong>${contact.display_name}</strong>
                <span>${contact.identifier}</span>
            </div>
            <span class="pill pill--secure">RSA · AES</span>
        `;
        btn.addEventListener("click", () => {
            state.activeChat = contact.identifier;
            renderContacts(dom.contactSearch.value);
            updateChatHeader();
            renderChat();
        });
        container.appendChild(btn);
    });
}

function describeTime(ts) {
    if (!ts) {
        return "";
    }
    const date = new Date(ts);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function renderChat() {
    const thread = dom.chatThread;
    if (!thread) {
        return;
    }
    thread.innerHTML = "";
    const owner = state.activeUser;
    if (!owner) {
        thread.innerHTML = '<div class="empty">Inicia sesión para ver tus mensajes cifrados.</div>';
        dom.composerInput.disabled = true;
        dom.sendButton.disabled = true;
        return;
    }
    const peer = state.activeChat;
    dom.composerInput.disabled = !peer;
    dom.sendButton.disabled = !peer;
    const messages = collectConversation(owner, peer);
    if (!messages.length) {
        thread.innerHTML = '<div class="empty">Aún no hay mensajes en este hilo.</div>';
        return;
    }
    messages.forEach((entry) => {
        const bubble = document.createElement("article");
        bubble.className = `bubble bubble--${entry.direction}`;
        bubble.innerHTML = `
            <p>${entry.plaintext}</p>
            <span>${describeTime(entry.created_at)} · ${entry.direction === "incoming" ? "Recibido" : "Enviado"}</span>
        `;
        thread.appendChild(bubble);
    });
    thread.scrollTop = thread.scrollHeight;
}

function updateChatHeader() {
    if (!dom.activeChatName || !dom.activeChatStatus) {
        return;
    }
    if (!state.activeChat) {
        dom.activeChatName.textContent = "Selecciona un contacto";
        dom.activeChatStatus.textContent = "Esperando conversación";
        return;
    }
    const match = state.contacts.find((c) => c.identifier === state.activeChat);
    dom.activeChatName.textContent = match?.display_name || state.activeChat;
    dom.activeChatStatus.textContent = match?.identifier || state.activeChat;
}

function showUserBadge() {
    if (!dom.userBadge) {
        return;
    }
    if (!state.activeUser) {
        dom.userBadge.textContent = "Sin sesión";
        return;
    }
    const session = state.sessions.get(state.activeUser);
    dom.userBadge.textContent = session?.displayName || state.activeUser;
}

function collectConversation(ownerIdentifier, peerIdentifier) {
    if (!ownerIdentifier) {
        return [];
    }
    const inbox = state.inboxCache.get(ownerIdentifier) || [];
    const incoming = inbox
        .filter((message) => !peerIdentifier || message.sender === peerIdentifier)
        .map((message) => ({ ...message, direction: "incoming" }));
    const outgoing = state.sentMessages
        .filter((message) => message.sender === ownerIdentifier)
        .filter((message) => !peerIdentifier || message.recipient === peerIdentifier)
        .map((message) => ({ ...message, direction: "outgoing" }));
    return [...incoming, ...outgoing].sort(
        (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    );
}

function rememberSecret(identifier, secret) {
    if (!identifier || !secret) {
        return;
    }
    state.totpSecrets.set(identifier, secret);
    persistState();
}

function getDeviceLabel() {
    const platform = navigator.platform || "Navegador";
    return `Dispositivo ${platform}`;
}

function pemToArrayBuffer(pem) {
    const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToPem(buffer, type) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const wrapped = base64.replace(/(.{64})/g, "$1\n");
    return `-----BEGIN ${type}-----\n${wrapped}\n-----END ${type}-----\n`;
}

function toBase64Url(input) {
    let buffer;
    if (input instanceof ArrayBuffer) {
        buffer = input;
    } else if (ArrayBuffer.isView(input)) {
        buffer = input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
    } else {
        throw new Error("Tipo no soportado para base64");
    }
    const bytes = new Uint8Array(buffer);
    let binary = "";
    bytes.forEach((b) => {
        binary += String.fromCharCode(b);
    });
    return btoa(binary).replace(/=+/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(base64Url) {
    const normalized = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function base32ToBytes(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const cleaned = base32.toUpperCase().replace(/=+$/, "");
    let bits = 0;
    let value = 0;
    const output = [];
    for (const char of cleaned) {
        const index = alphabet.indexOf(char);
        if (index === -1) {
            throw new Error("Caracter Base32 inválido");
        }
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            output.push((value >>> bits) & 0xff);
        }
    }
    return new Uint8Array(output);
}

async function generateTotp(secret) {
    const keyBytes = base32ToBytes(secret);
    const counter = Math.floor(Date.now() / 1000 / 30);
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setUint32(4, counter, false);
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"],
    );
    const signature = await crypto.subtle.sign("HMAC", cryptoKey, buffer);
    const bytes = new Uint8Array(signature);
    const offset = bytes[bytes.length - 1] & 0x0f;
    const binary =
        ((bytes[offset] & 0x7f) << 24) |
        ((bytes[offset + 1] & 0xff) << 16) |
        ((bytes[offset + 2] & 0xff) << 8) |
        (bytes[offset + 3] & 0xff);
    const code = binary % 1_000_000;
    return code.toString().padStart(6, "0");
}

async function ensurePrivateKey(identifier) {
    const entry = state.keyPairs.get(identifier);
    if (!entry || !entry.privatePem) {
        throw new Error("Aún no se genera la llave local para este usuario.");
    }
    if (entry.privateKey) {
        return entry.privateKey;
    }
    const keyData = pemToArrayBuffer(entry.privatePem);
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        keyData,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"],
    );
    entry.privateKey = privateKey;
    state.keyPairs.set(identifier, entry);
    return privateKey;
}

async function ensureKeyPair(identifier) {
    let entry = state.keyPairs.get(identifier);
    if (entry?.publicPem && entry?.privatePem) {
        return entry;
    }
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"],
    );
    const publicKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    entry = {
        publicPem: arrayBufferToPem(publicKeyBuffer, "PUBLIC KEY"),
        privatePem: arrayBufferToPem(privateKeyBuffer, "PRIVATE KEY"),
        privateKey: keyPair.privateKey,
        deviceName: getDeviceLabel(),
    };
    state.keyPairs.set(identifier, entry);
    persistState();
    return entry;
}

async function registerDeviceIfNeeded(identifier) {
    const entry = await ensureKeyPair(identifier);
    if (entry.registered) {
        return;
    }
    const session = getSession(identifier);
    await api("/api/devices", {
        method: "POST",
        headers: { Authorization: `Bearer ${session.token}` },
        body: JSON.stringify({ device_name: entry.deviceName || getDeviceLabel(), public_key_pem: entry.publicPem }),
    });
    entry.registered = true;
    state.keyPairs.set(identifier, entry);
    persistState();
}

async function encryptMessage(recipientPem, plaintext, senderIdentifier) {
    const recipientKeyData = pemToArrayBuffer(recipientPem);
    const recipientKey = await crypto.subtle.importKey(
        "spki",
        recipientKeyData,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"],
    );
    const sessionKey = crypto.getRandomValues(new Uint8Array(32));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const associatedData = encoder.encode(`sender=${senderIdentifier}`);
    const aesKey = await crypto.subtle.importKey("raw", sessionKey, "AES-GCM", false, ["encrypt"]);
    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: associatedData },
        aesKey,
        encoder.encode(plaintext),
    );
    const cipherBytes = new Uint8Array(ciphertextBuffer);
    const tagBytes = cipherBytes.slice(cipherBytes.length - 16);
    const encryptedBytes = cipherBytes.slice(0, cipherBytes.length - 16);
    const wrappedSessionKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientKey, sessionKey);
    return {
        session_key_encrypted: toBase64Url(wrappedSessionKey),
        nonce_b64: toBase64Url(nonce),
        ciphertext_b64: toBase64Url(encryptedBytes),
        tag_b64: toBase64Url(tagBytes),
        associated_data_b64: toBase64Url(associatedData),
    };
}

async function decryptMessage(privateKey, payload) {
    const sessionKeyBytes = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        fromBase64Url(payload.session_key_encrypted),
    );
    const aesKey = await crypto.subtle.importKey("raw", sessionKeyBytes, "AES-GCM", false, ["decrypt"]);
    const nonce = new Uint8Array(fromBase64Url(payload.nonce_b64));
    const ciphertextBytes = new Uint8Array(fromBase64Url(payload.ciphertext_b64));
    const tagBytes = new Uint8Array(fromBase64Url(payload.tag_b64));
    const associatedData = payload.associated_data_b64
        ? new Uint8Array(fromBase64Url(payload.associated_data_b64))
        : new Uint8Array();
    const combined = new Uint8Array(ciphertextBytes.length + tagBytes.length);
    combined.set(ciphertextBytes, 0);
    combined.set(tagBytes, ciphertextBytes.length);
    const plaintextBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: associatedData },
        aesKey,
        combined.buffer,
    );
    return {
        plaintext: decoder.decode(plaintextBuffer),
        associated_data: associatedData.length ? decoder.decode(associatedData) : "",
    };
}

async function refreshContacts(identifier) {
    if (!identifier) {
        return;
    }
    const session = getSession(identifier);
    const response = await api("/api/users", { headers: { Authorization: `Bearer ${session.token}` } });
    state.contacts = (response.contacts || []).filter((contact) => contact.public_key_pem);
    persistState();
    renderContacts(dom.contactSearch.value);
}

async function refreshInbox(identifier) {
    if (!identifier) {
        return;
    }
    const session = getSession(identifier);
    const privateKey = await ensurePrivateKey(identifier);
    const response = await api("/api/messages", { headers: { Authorization: `Bearer ${session.token}` } });
    const decrypted = [];
    for (const message of response.messages || []) {
        try {
            const result = await decryptMessage(privateKey, message);
            decrypted.push({
                id: message.id,
                sender: message.sender_identifier,
                created_at: message.created_at,
                plaintext: result.plaintext,
                associated_data: result.associated_data,
            });
        } catch (error) {
            console.warn("No se pudo descifrar", error);
        }
    }
    state.inboxCache.set(identifier, decrypted);
    persistState();
    renderChat();
}

function recordSentMessage(sender, recipient, plaintext) {
    state.sentMessages.push({ sender, recipient, plaintext, created_at: new Date().toISOString() });
    if (state.sentMessages.length > 200) {
        state.sentMessages = state.sentMessages.slice(-200);
    }
    persistState();
}

async function handleRegister(event) {
    event.preventDefault();
    const identifier = dom.registerIdentifier.value.trim();
    const displayName = dom.registerDisplay.value.trim();
    const password = dom.registerPassword.value;
    if (!identifier || !displayName || !password) {
        showFeedback(dom.registerFeedback, "Completa todos los campos", "error");
        return;
    }
    try {
        showFeedback(dom.registerFeedback, "Creando cuenta...", "info");
        const response = await api("/api/register", {
            method: "POST",
            body: JSON.stringify({ identifier, display_name: displayName, password }),
        });
        rememberSecret(identifier, response.totp_secret);
        showFeedback(dom.registerFeedback, "Cuenta creada, configurando sesión...", "success");
        await handleAutomaticLogin(identifier, password);
    } catch (error) {
        showFeedback(dom.registerFeedback, error.message, "error");
    }
}

async function handleAutomaticLogin(identifier, password) {
    const code = await getTotpCode(identifier);
    await completeLoginFlow(identifier, password, code);
}

async function getTotpCode(identifier) {
    const manual = dom.loginTotp.value.trim();
    if (manual) {
        return manual;
    }
    const secret = state.totpSecrets.get(identifier);
    if (!secret) {
        throw new Error("Ingresa el código TOTP desde tu app autenticadora.");
    }
    const totp = await generateTotp(secret);
    dom.loginTotp.value = totp;
    return totp;
}

async function completeLoginFlow(identifier, password, totpCode) {
    const response = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({ identifier, password, totp_code: totpCode }),
    });
    state.sessions.set(identifier, {
        token: response.token,
        displayName: response.user?.display_name || identifier,
    });
    state.activeUser = identifier;
    persistState();
    showUserBadge();
    await registerDeviceIfNeeded(identifier);
    await refreshContacts(identifier);
    await refreshInbox(identifier);
    dom.loginIdentifier.value = identifier;
    dom.loginPassword.value = "";
    dom.loginTotp.value = "";
    setView("app");
    updateChatHeader();
    renderChat();
}

async function handleLogin(event) {
    event.preventDefault();
    const identifier = dom.loginIdentifier.value.trim();
    const password = dom.loginPassword.value;
    if (!identifier || !password) {
        showFeedback(dom.loginFeedback, "Completa correo y contraseña", "error");
        return;
    }
    try {
        showFeedback(dom.loginFeedback, "Verificando credenciales...", "info");
        const totpCode = await getTotpCode(identifier);
        await completeLoginFlow(identifier, password, totpCode);
        showFeedback(dom.loginFeedback, "Sesión iniciada. Bienvenido/a.", "success");
    } catch (error) {
        showFeedback(dom.loginFeedback, error.message, "error");
    }
}

async function handleSendMessage(event) {
    event.preventDefault();
    const sender = state.activeUser;
    const recipient = state.activeChat;
    const plaintext = dom.composerInput.value.trim();
    if (!sender || !recipient || !plaintext) {
        return;
    }
    try {
        dom.sendButton.disabled = true;
        const session = getSession(sender);
        const recipientDetails = await api(`/api/users/${encodeURIComponent(recipient)}`, {
            headers: { Authorization: `Bearer ${session.token}` },
        });
        if (!recipientDetails.public_key_pem) {
            throw new Error("El contacto aún no registra su dispositivo.");
        }
        const encryptedPayload = await encryptMessage(recipientDetails.public_key_pem, plaintext, sender);
        await api("/api/messages", {
            method: "POST",
            headers: { Authorization: `Bearer ${session.token}` },
            body: JSON.stringify({ recipient_identifier: recipient, ...encryptedPayload }),
        });
        recordSentMessage(sender, recipient, plaintext);
        dom.composerInput.value = "";
        dom.sendButton.disabled = false;
        await refreshInbox(sender);
    } catch (error) {
        dom.sendButton.disabled = false;
        alert(`No se pudo enviar el mensaje: ${error.message}`);
    }
}

function handleNewChat() {
    state.activeChat = null;
    renderContacts(dom.contactSearch.value);
    updateChatHeader();
    renderChat();
}

function handleLogout() {
    if (!state.activeUser) {
        return;
    }
    state.sessions.delete(state.activeUser);
    state.activeUser = listSessions()[0] || null;
    if (!state.activeUser) {
        setView("auth");
    }
    showUserBadge();
    persistState();
    updateChatHeader();
    renderChat();
}

async function handleContactSearch(event) {
    renderContacts(event.target.value);
}

async function periodicRefresh() {
    if (!state.activeUser) {
        return;
    }
    await refreshInbox(state.activeUser);
}

function attachEvents() {
    dom.tabs.forEach((tab) => tab.addEventListener("click", () => toggleAuthTab(tab.dataset.tab)));
    dom.loginForm.addEventListener("submit", handleLogin);
    dom.registerForm.addEventListener("submit", handleRegister);
    dom.composer.addEventListener("submit", handleSendMessage);
    dom.newChatBtn.addEventListener("click", handleNewChat);
    dom.logoutBtn.addEventListener("click", handleLogout);
    dom.contactSearch.addEventListener("input", handleContactSearch);
}

async function bootstrap() {
    loadState();
    attachEvents();
    renderContacts();
    updateChatHeader();
    showUserBadge();
    renderChat();
    if (state.activeUser) {
        setView("app");
        await refreshContacts(state.activeUser);
        await refreshInbox(state.activeUser);
    } else {
        setView("auth");
    }
    setInterval(periodicRefresh, 12_000);
}

bootstrap();
