(function () {
    "use strict";

    const API_BASE = window.API_BASE || "";
    const STORAGE_KEY = "tel252_e2ee_state_v4";

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const state = {
        sessions: new Map(),
        totpSecrets: new Map(),
        keyPairs: new Map(),
        inboxCache: new Map(),
        sentMessages: [],
        contacts: [],
        activeUser: null,
        activeChat: null,
        sharedSecrets: new Map(),
        contactBook: new Set(),
    };

    const listeners = new Set();
    const WORKSPACE_PAGE_MAP = {
        mensajes: "mensajes.html",
        contactos: "contactos.html",
        perfil: "perfil.html",
    };

    function workspaceConfig() {
        return {
            hosts:
                window.WORKSPACE_HOSTS ||
                window.chatWorkspaceHosts ||
                window.ChatWorkspaceHosts ||
                null,
            base:
                window.WORKSPACE_BASE_PATH ||
                window.chatWorkspaceBase ||
                window.ChatWorkspaceBase ||
                null,
        };
    }

    function resolveWorkspaceUrl(page) {
        const key = WORKSPACE_PAGE_MAP[page] ? page : "mensajes";
        const { hosts, base } = workspaceConfig();
        const override = hosts?.[key];
        if (override) {
            if (/^https?:\/\//i.test(override)) {
                return override;
            }
            if (override.startsWith("//")) {
                return `https:${override}`;
            }
            if (override.startsWith("/")) {
                return new URL(override, window.location.origin).href;
            }
            return `https://${override}`;
        }
        if (typeof base === "string" && base.length > 0) {
            const normalizedBase = /^https?:\/\//i.test(base)
                ? base
                : new URL(base, window.location.origin).href;
            return new URL(WORKSPACE_PAGE_MAP[key], normalizedBase).href;
        }
        return new URL(WORKSPACE_PAGE_MAP[key], window.location.href).href;
    }

    function getWorkspaceDestinations() {
        return Object.keys(WORKSPACE_PAGE_MAP).reduce((acc, page) => {
            acc[page] = resolveWorkspaceUrl(page);
            return acc;
        }, {});
    }

    function navigateToWorkspace(page) {
        window.location.href = resolveWorkspaceUrl(page);
    }

    function notify() {
        listeners.forEach((cb) => {
            try {
                cb(state);
            } catch (error) {
                console.warn("Listener error", error);
            }
        });
    }

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
                        registered: entry.registered || false,
                    },
                ]),
            ),
            inboxCache: Object.fromEntries(state.inboxCache),
            sentMessages: state.sentMessages,
            contacts: state.contacts,
            activeUser: state.activeUser,
            activeChat: state.activeChat,
            sharedSecrets: Object.fromEntries(state.sharedSecrets),
            contactBook: [...state.contactBook],
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
                        registered: entry.registered,
                    },
                ]),
            );
            state.inboxCache = new Map(Object.entries(payload.inboxCache || {}));
            state.sentMessages = payload.sentMessages || [];
            state.contacts = payload.contacts || [];
            state.activeUser = payload.activeUser || null;
            state.activeChat = payload.activeChat || null;
            state.sharedSecrets = new Map(Object.entries(payload.sharedSecrets || {}));
            state.contactBook = new Set(payload.contactBook || []);
        } catch (error) {
            console.warn("No se pudo cargar el estado previo", error);
            localStorage.removeItem(STORAGE_KEY);
        }
    }

    async function api(path, options = {}) {
        const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
        const response = await fetch(`${API_BASE}${path}`, {
            ...options,
            headers,
        });
        if (!response.ok) {
            let message = `${response.status} ${response.statusText}`;
            try {
                const body = await response.json();
                if (body.error) {
                    message = body.error;
                }
            } catch (_) {
                // ignore json parse errors
            }
            throw new Error(message);
        }
        const text = await response.text();
        return text ? JSON.parse(text) : {};
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

    function normalizeIdentifier(identifier) {
        return (identifier || "").trim().toLowerCase();
    }

    function encodeMetadata(payload) {
        return encoder.encode(JSON.stringify(payload));
    }

    function decodeMetadata(buffer) {
        if (!buffer || buffer.byteLength === 0) {
            return {};
        }
        try {
            const text = decoder.decode(buffer);
            if (!text) {
                return {};
            }
            return JSON.parse(text);
        } catch (error) {
            try {
                const fallback = decoder.decode(buffer);
                if (fallback.startsWith("sender=")) {
                    return { sender: fallback.split("=")[1] };
                }
                return { raw: fallback };
            } catch (_) {
                return {};
            }
        }
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

    function rememberSecret(identifier, secret) {
        if (!identifier || !secret) {
            return;
        }
        state.totpSecrets.set(identifier, secret);
        persistState();
        notify();
    }

    function getSession(identifier) {
        const session = state.sessions.get(identifier);
        if (!session) {
            throw new Error("Sesión no encontrada. Inicia sesión nuevamente.");
        }
        return session;
    }

    function ensureActiveSession() {
        if (!state.activeUser) {
            throw new Error("No hay sesión activa");
        }
        return { identifier: state.activeUser, ...getSession(state.activeUser) };
    }

    function listSessions() {
        return [...state.sessions.keys()];
    }

    function describeDevice() {
        const platform = navigator.platform || "Navegador";
        const ua = navigator.userAgent || "Dispositivo";
        return `${platform} · ${ua.slice(0, 25)}`;
    }

    async function ensurePrivateKey(identifier) {
        const entry = state.keyPairs.get(identifier);
        if (!entry || !entry.privatePem) {
            throw new Error("Aún no se ha generado una llave para este usuario.");
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
            deviceName: describeDevice(),
            registered: false,
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
            body: JSON.stringify({ device_name: entry.deviceName, public_key_pem: entry.publicPem }),
        });
        entry.registered = true;
        state.keyPairs.set(identifier, entry);
        persistState();
    }

    async function encryptMessage(recipientPem, plaintext, senderIdentifier, metadata = {}) {
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
        const associatedPayload = { sender: senderIdentifier, ...metadata };
        const associatedData = encodeMetadata(associatedPayload);
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
            metadata: decodeMetadata(associatedData),
        };
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

    function hasStoredTotp(identifier) {
        return state.totpSecrets.has(identifier);
    }

    function trackContact(identifier) {
        const normalized = normalizeIdentifier(identifier);
        if (!normalized) {
            return;
        }
        if (state.contactBook.has(normalized)) {
            return;
        }
        state.contactBook.add(normalized);
        persistState();
        notify();
    }

    function rememberSharedSecret(identifier, sharedKey) {
        const normalized = normalizeIdentifier(identifier);
        if (!normalized || !sharedKey) {
            return;
        }
        if (state.sharedSecrets.get(normalized) === sharedKey) {
            return;
        }
        state.sharedSecrets.set(normalized, sharedKey);
        state.contactBook.add(normalized);
        persistState();
        notify();
    }

    function lookupContact(identifier) {
        const normalized = normalizeIdentifier(identifier);
        if (!normalized) {
            return null;
        }
        return state.contacts.find((contact) => normalizeIdentifier(contact.identifier) === normalized) || null;
    }

    function hasSharedSecret(identifier) {
        const normalized = normalizeIdentifier(identifier);
        return normalized ? state.sharedSecrets.has(normalized) : false;
    }

    function getSharedSecret(identifier) {
        const normalized = normalizeIdentifier(identifier);
        return normalized ? state.sharedSecrets.get(normalized) || null : null;
    }

    function syncSharedSecretFromMetadata(metadata, peerIdentifier) {
        if (!metadata || metadata.type !== "handshake" || !metadata.shared_key || !peerIdentifier) {
            return;
        }
        rememberSharedSecret(peerIdentifier, metadata.shared_key);
    }

    function describePresence(ownerIdentifier, peerIdentifier) {
        if (!ownerIdentifier || !peerIdentifier) {
            return { status: "unknown", label: "Sin actividad" };
        }
        const history = collectConversation(ownerIdentifier, peerIdentifier);
        if (!history.length) {
            return { status: "unknown", label: "Sin actividad" };
        }
        const lastMessage = history[history.length - 1];
        const timestamp = new Date(lastMessage.created_at).getTime();
        if (Number.isNaN(timestamp)) {
            return { status: "unknown", label: "Actividad reciente" };
        }
        const delta = Date.now() - timestamp;
        if (delta < 5 * 60 * 1000) {
            return { status: "online", label: "En línea ahora" };
        }
        if (delta < 60 * 60 * 1000) {
            const minutes = Math.max(1, Math.round(delta / 60000));
            return { status: "recent", label: `Hace ${minutes} min` };
        }
        const hours = Math.max(1, Math.round(delta / 3_600_000));
        return { status: "offline", label: `Hace ${hours} h` };
    }

    function recordSentMessage(sender, recipient, plaintext, metadata = {}) {
        state.sentMessages.push({ sender, recipient, plaintext, metadata, created_at: new Date().toISOString() });
        if (state.sentMessages.length > 250) {
            state.sentMessages = state.sentMessages.slice(-250);
        }
        persistState();
    }

    async function refreshContacts(identifier) {
        if (!identifier) {
            return [];
        }
        const session = getSession(identifier);
        const response = await api("/api/users", { headers: { Authorization: `Bearer ${session.token}` } });
        state.contacts = (response.contacts || []).filter((contact) => contact.public_key_pem);
        persistState();
        notify();
        return state.contacts;
    }

    async function refreshInbox(identifier) {
        if (!identifier) {
            return [];
        }
        const session = getSession(identifier);
        const privateKey = await ensurePrivateKey(identifier);
        const response = await api("/api/messages", { headers: { Authorization: `Bearer ${session.token}` } });
        const decrypted = [];
        for (const message of response.messages || []) {
            try {
                const result = await decryptMessage(privateKey, message);
                syncSharedSecretFromMetadata(result.metadata, message.sender_identifier);
                decrypted.push({
                    id: message.id,
                    sender: message.sender_identifier,
                    sender_display_name: message.sender_display_name,
                    created_at: message.created_at,
                    plaintext: result.plaintext,
                    metadata: result.metadata,
                });
            } catch (error) {
                console.warn("Fallo al descifrar", error);
            }
        }
        state.inboxCache.set(identifier, decrypted);
        persistState();
        notify();
        return decrypted;
    }

    async function registerAccount({ displayName, identifier, password }) {
        const response = await api("/api/register", {
            method: "POST",
            body: JSON.stringify({ display_name: displayName, identifier, password }),
        });
        rememberSecret(identifier, response.totp_secret);
        return response;
    }

    async function computeTotp(identifier) {
        const secret = state.totpSecrets.get(identifier);
        if (!secret) {
            throw new Error("No hay secreto TOTP guardado para este usuario.");
        }
        return generateTotp(secret);
    }

    async function completeLogin(identifier, password, providedTotp) {
        const totp = providedTotp && providedTotp.trim() ? providedTotp.trim() : await computeTotp(identifier);
        const response = await api("/api/login", {
            method: "POST",
            body: JSON.stringify({ identifier, password, totp_code: totp }),
        });
        state.sessions.set(identifier, {
            token: response.token,
            displayName: response.user?.display_name || identifier,
        });
        state.activeUser = identifier;
        persistState();
        notify();
        await registerDeviceIfNeeded(identifier);
        await refreshContacts(identifier);
        await refreshInbox(identifier);
        return response;
    }

    function logout() {
        if (!state.activeUser) {
            return;
        }
        state.sessions.delete(state.activeUser);
        state.activeUser = listSessions()[0] || null;
        state.activeChat = null;
        persistState();
        notify();
    }

    function hasActiveSession() {
        return Boolean(state.activeUser && state.sessions.has(state.activeUser));
    }

    function setActiveChat(peer) {
        state.activeChat = peer || null;
        persistState();
        notify();
    }

    async function deliverMessage(recipient, plaintext, metadata = {}) {
        const sender = state.activeUser;
        if (!sender) {
            throw new Error("Inicia sesión para enviar mensajes");
        }
        const normalizedRecipient = normalizeIdentifier(recipient);
        if (!normalizedRecipient) {
            throw new Error("Selecciona un contacto válido");
        }
        const session = getSession(sender);
        const recipientDetails = await api(`/api/users/${encodeURIComponent(normalizedRecipient)}`, {
            headers: { Authorization: `Bearer ${session.token}` },
        });
        if (!recipientDetails.public_key_pem) {
            throw new Error("El contacto aún no registra su dispositivo.");
        }
        const encryptedPayload = await encryptMessage(
            recipientDetails.public_key_pem,
            plaintext,
            sender,
            metadata,
        );
        await api("/api/messages", {
            method: "POST",
            headers: { Authorization: `Bearer ${session.token}` },
            body: JSON.stringify({ recipient_identifier: recipientDetails.identifier, ...encryptedPayload }),
        });
        recordSentMessage(sender, recipientDetails.identifier, plaintext, metadata);
        trackContact(recipientDetails.identifier);
        notify();
        await refreshInbox(sender);
        return recipientDetails;
    }

    async function sendMessage(plaintext, options = {}) {
        const recipient = options.recipient || state.activeChat;
        if (!recipient) {
            throw new Error("Selecciona un contacto para enviar mensajes");
        }
        return deliverMessage(recipient, plaintext, options.metadata || {});
    }

    async function addContact(identifier) {
        const sender = state.activeUser;
        if (!sender) {
            throw new Error("Inicia sesión para agregar contactos");
        }
        const normalized = normalizeIdentifier(identifier);
        if (!normalized) {
            throw new Error("Ingresa el correo institucional del contacto");
        }
        if (normalized === normalizeIdentifier(sender)) {
            throw new Error("No puedes agregarte a ti mismo");
        }
        const session = getSession(sender);
        const contact = await api(`/api/users/${encodeURIComponent(normalized)}`, {
            headers: { Authorization: `Bearer ${session.token}` },
        });
        if (!contact?.public_key_pem) {
            throw new Error("El contacto aún no registra su dispositivo.");
        }
        const alreadyShared = hasSharedSecret(contact.identifier);
        trackContact(contact.identifier);
        if (!alreadyShared) {
            const sharedKeyBytes = crypto.getRandomValues(new Uint8Array(32));
            const sharedKey = toBase64Url(sharedKeyBytes);
            const metadata = {
                type: "handshake",
                shared_key: sharedKey,
                version: 1,
                sender_display_name: state.sessions.get(sender)?.displayName || sender,
                sender_device: state.keyPairs.get(sender)?.deviceName || "Dispositivo",
                peer_identifier: contact.identifier,
                peer_display_name: contact.display_name || contact.identifier,
            };
            await deliverMessage(contact.identifier, "Canal seguro inicializado 🔐", metadata);
            rememberSharedSecret(contact.identifier, sharedKey);
        }
        state.activeChat = contact.identifier;
        persistState();
        notify();
        return contact;
    }

    function getContacts() {
        const scored = [...state.contacts];
        const scoreContact = (contact) => {
            const normalized = normalizeIdentifier(contact.identifier);
            const hasKey = hasSharedSecret(normalized) ? 1 : 0;
            const isBook = state.contactBook.has(normalized) ? 1 : 0;
            return hasKey * 2 + isBook;
        };
        scored.sort((a, b) => {
            const diff = scoreContact(b) - scoreContact(a);
            if (diff !== 0) {
                return diff;
            }
            return (a.display_name || a.identifier).localeCompare(b.display_name || b.identifier, "es");
        });
        return scored;
    }

    function getConversation(peer) {
        return collectConversation(state.activeUser, peer || state.activeChat);
    }

    function onStateChange(callback) {
        if (typeof callback === "function") {
            listeners.add(callback);
            callback(state);
            return () => listeners.delete(callback);
        }
        return () => {};
    }

    function bootstrap() {
        if (!window.ChatCoreLoaded) {
            loadState();
            window.ChatCoreLoaded = true;
        }
        return state;
    }

    window.ChatCore = {
        state,
        bootstrap,
        onStateChange,
        registerAccount,
        completeLogin,
        logout,
        hasActiveSession,
        ensureActiveSession,
        refreshContacts,
        refreshInbox,
        sendMessage,
        addContact,
        setActiveChat,
        getContacts,
        getConversation,
        rememberSecret,
        ensureKeyPair,
        registerDeviceIfNeeded,
        computeTotp,
        hasStoredTotp,
        hasSharedSecret,
        getSharedSecret,
        describePresence,
        lookupContact,
        resolveWorkspaceUrl,
        navigateToWorkspace,
        getWorkspaceDestinations,
    };
})();
