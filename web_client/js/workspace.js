document.addEventListener("DOMContentLoaded", async () => {
    ChatCore.bootstrap();
    if (!ChatCore.hasActiveSession()) {
        window.location.replace("index.html");
        return;
    }

    const page = document.body.dataset.page || "mensajes";
    hydrateShell(page);

    if (page === "mensajes") {
        await initializeMessagesPage();
    } else if (page === "contactos") {
        await initializeContactsPage();
    } else if (page === "perfil") {
        initializeProfilePage();
    }

    setInterval(() => {
        ChatCore.refreshInbox(ChatCore.state.activeUser);
    }, 12_000);
});

function hydrateShell(activePage) {
    const badge = document.getElementById("user-badge");
    badge.textContent = ChatCore.state.sessions.get(ChatCore.state.activeUser)?.displayName || ChatCore.state.activeUser;

    document.querySelectorAll("[data-nav]").forEach((link) => {
        const target = link.dataset.nav;
        link.classList.toggle("active", target === activePage);
        const destination = ChatCore.resolveWorkspaceUrl(target);
        link.setAttribute("title", destination);
        link.addEventListener("click", (event) => {
            event.preventDefault();
            ChatCore.navigateToWorkspace(target);
        });
    });

    document.getElementById("logout-btn")?.addEventListener("click", () => {
        ChatCore.logout();
        window.location.href = "index.html";
    });

    updateTotpBadge();
    ChatCore.onStateChange(updateTotpBadge);
}

function setFeedback(target, message, variant = "info") {
    if (!target) {
        return;
    }
    target.textContent = message;
    target.dataset.variant = variant;
}

async function initializeMessagesPage() {
    await ChatCore.refreshContacts(ChatCore.state.activeUser);
    await ChatCore.refreshInbox(ChatCore.state.activeUser);
    const contactSearch = document.getElementById("contact-filter");
    const composer = document.getElementById("composer-form");
    const messageInput = document.getElementById("composer-input");

    renderContactRail();
    renderChatThread();

    contactSearch?.addEventListener("input", () => renderContactRail(contactSearch.value));

    composer?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const text = messageInput.value.trim();
        if (!text) {
            return;
        }
        try {
            composer.classList.add("loading");
            await ChatCore.sendMessage(text);
            messageInput.value = "";
            renderChatThread();
        } catch (error) {
            alert(`No se pudo enviar el mensaje: ${error.message}`);
        } finally {
            composer.classList.remove("loading");
        }
    });

    ChatCore.onStateChange(() => {
        renderContactRail(contactSearch?.value);
        renderChatThread();
    });
}

async function initializeContactsPage() {
    await ChatCore.refreshContacts(ChatCore.state.activeUser);
    renderContactsDirectory();
    document.getElementById("refresh-contacts")?.addEventListener("click", async () => {
        await ChatCore.refreshContacts(ChatCore.state.activeUser);
        renderContactsDirectory();
    });
    const addForm = document.getElementById("add-contact-form");
    const addInput = document.getElementById("add-contact-identifier");
    const addFeedback = document.getElementById("add-contact-feedback");
    addForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const value = addInput.value.trim();
        if (!value) {
            setFeedback(addFeedback, "Ingresa el correo del contacto", "error");
            return;
        }
        try {
            setFeedback(addFeedback, "Compartiendo llave segura...", "info");
            const contact = await ChatCore.addContact(value);
            setFeedback(
                addFeedback,
                `Llave compartida con ${contact.display_name || contact.identifier}. Redirigiendo...`,
                "success",
            );
            addInput.value = "";
            setTimeout(() => ChatCore.navigateToWorkspace("mensajes"), 600);
        } catch (error) {
            setFeedback(addFeedback, error.message, "error");
        }
    });
    ChatCore.onStateChange(renderContactsDirectory);
}

function initializeProfilePage() {
    const list = document.getElementById("session-list");
    const keys = document.getElementById("keys-status");
    const mfa = document.getElementById("mfa-status");
    const sessions = ChatCore.state.sessions;
    list.innerHTML = "";
    sessions.forEach((value, identifier) => {
        const item = document.createElement("li");
        item.innerHTML = `<strong>${identifier}</strong><span>${value.displayName}</span>`;
        list.appendChild(item);
    });
    const keyInfo = ChatCore.state.keyPairs.get(ChatCore.state.activeUser);
    keys.textContent = keyInfo ? "Llave local protegida" : "Pendiente de generar";
    if (mfa) {
        mfa.textContent = ChatCore.hasStoredTotp(ChatCore.state.activeUser)
            ? "Secreto TOTP almacenado localmente. Autocompletamos tus códigos."
            : "Aún no guardamos tu TOTP aquí. Completa un login exitoso para recordarlo.";
    }
    document.getElementById("regen-key")?.addEventListener("click", async () => {
        await ChatCore.ensureKeyPair(ChatCore.state.activeUser);
        await ChatCore.registerDeviceIfNeeded(ChatCore.state.activeUser);
        alert("Nuevo par de llaves listo y sincronizado");
        updateTotpBadge();
    });
}

function renderContactRail(filterValue = "") {
    const container = document.getElementById("contacts-rail");
    if (!container) {
        return;
    }
    const normalized = filterValue.trim().toLowerCase();
    const contacts = ChatCore.getContacts().filter((contact) => {
        if (!normalized) {
            return true;
        }
        return (
            contact.identifier.toLowerCase().includes(normalized) ||
            (contact.display_name || "").toLowerCase().includes(normalized)
        );
    });
    container.innerHTML = "";
    if (!contacts.length) {
        container.innerHTML = '<p class="empty">No encontramos contactos con ese filtro.</p>';
        return;
    }
    contacts.forEach((contact) => {
        const presence = ChatCore.describePresence(ChatCore.state.activeUser, contact.identifier);
        const hasKey = ChatCore.hasSharedSecret(contact.identifier);
        const displayName = contact.display_name || contact.identifier;
        const button = document.createElement("button");
        button.type = "button";
        button.className = `contact ${contact.identifier === ChatCore.state.activeChat ? "active" : ""}`;
        button.innerHTML = `
            <div class="contact__info">
                <strong>${displayName}</strong>
                <small>${contact.identifier}</small>
            </div>
            <div class="contact__signals">
                <div class="presence presence--${presence.status}">
                    <span class="presence__dot"></span>
                    ${presence.label}
                </div>
                <span class="pill ${hasKey ? "pill--secure" : "pill--pending"}">
                    ${hasKey ? "Llave compartida" : "Compartir llave"}
                </span>
            </div>
        `;
        button.addEventListener("click", () => {
            ChatCore.setActiveChat(contact.identifier);
            const title = document.getElementById("chat-title");
            if (title) {
                title.textContent = displayName;
            }
            updateChatPresence(contact.identifier);
            renderChatThread();
        });
        container.appendChild(button);
    });
}

function renderChatThread() {
    const thread = document.getElementById("chat-thread");
    const composer = document.getElementById("composer-input");
    if (!thread) {
        return;
    }
    if (!ChatCore.state.activeChat) {
        thread.innerHTML = '<div class="empty">Selecciona un contacto para comenzar a cifrar mensajes.</div>';
        composer.disabled = true;
        return;
    }
    composer.disabled = false;
    updateChatPresence(ChatCore.state.activeChat);
    const activeContact = ChatCore.lookupContact(ChatCore.state.activeChat);
    const messages = ChatCore.getConversation();
    if (!messages.length) {
        thread.innerHTML = '<div class="empty">Aún no hay mensajes en este hilo.</div>';
        return;
    }
    thread.innerHTML = "";
    messages.forEach((message) => {
        const bubble = document.createElement("article");
        const metadata = message.metadata || {};
        const isHandshake = metadata.type === "handshake";
        bubble.className = `bubble bubble--${message.direction} ${isHandshake ? "bubble--handshake" : ""}`;
        const fingerprint = metadata.shared_key ? `${metadata.shared_key.slice(0, 8)}…` : "";
        const timeLabel = new Date(message.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        const outgoingPeerLabel =
            metadata.peer_display_name || activeContact?.display_name || activeContact?.identifier || ChatCore.state.activeChat;
        const incomingPeerLabel =
            metadata.sender_display_name || message.sender_display_name || message.sender || "Contacto";
        const handshakeLabel = message.direction === "outgoing" ? outgoingPeerLabel : incomingPeerLabel;
        const deviceLabel = metadata.sender_device ? `<small>Dispositivo: ${metadata.sender_device}</small>` : "";
        const handshakeMeta = isHandshake
            ? `<div class="bubble__meta">
                    <strong>${handshakeLabel}</strong>
                    ${fingerprint ? `<small>Huella: ${fingerprint}</small>` : ""}
                    ${deviceLabel}
               </div>`
            : "";
        bubble.innerHTML = `
            ${handshakeMeta}
            <p>${message.plaintext}</p>
            <span>${timeLabel}</span>
        `;
        thread.appendChild(bubble);
    });
    thread.scrollTop = thread.scrollHeight;
}

function renderContactsDirectory() {
    const list = document.getElementById("directory-grid");
    if (!list) {
        return;
    }
    const contacts = ChatCore.getContacts();
    list.innerHTML = "";
    if (!contacts.length) {
        list.innerHTML = '<p class="empty">Todavía no sincronizas contactos.</p>';
        return;
    }
    contacts.forEach((contact) => {
        const displayName = contact.display_name || contact.identifier;
        const card = document.createElement("article");
        card.className = "contact-card";
        const presence = ChatCore.describePresence(ChatCore.state.activeUser, contact.identifier);
        const hasKey = ChatCore.hasSharedSecret(contact.identifier);
        card.innerHTML = `
            <header>
                <h3>${displayName}</h3>
                <span class="presence presence--${presence.status}">
                    <span class="presence__dot"></span>
                    ${presence.label}
                </span>
            </header>
            <p>${contact.identifier}</p>
            <div class="contact-card__status">
                <span class="pill ${hasKey ? "pill--secure" : "pill--pending"}">
                    ${hasKey ? "Llave compartida" : "Pendiente"}
                </span>
                <p class="hint">${
                    hasKey
                        ? "Canal listo para mensajes cifrados."
                        : "Comparte una llave para habilitar el canal."
                }</p>
            </div>
            <div class="card-actions">
                <button type="button" class="${hasKey ? "ghost" : "primary"}" data-contact="${contact.identifier}">
                    ${hasKey ? "Abrir chat" : "Compartir llave"}
                </button>
            </div>
        `;
        const actionBtn = card.querySelector("button");
        if (hasKey) {
            actionBtn.addEventListener("click", () => {
                ChatCore.setActiveChat(contact.identifier);
                ChatCore.navigateToWorkspace("mensajes");
            });
        } else {
            actionBtn.addEventListener("click", async () => {
                try {
                    await ChatCore.addContact(contact.identifier);
                    ChatCore.navigateToWorkspace("mensajes");
                } catch (error) {
                    alert(error.message);
                }
            });
        }
        list.appendChild(card);
    });
}

function updateTotpBadge() {
    const pill = document.getElementById("totp-pill");
    if (!pill) {
        return;
    }
    const identifier = ChatCore.state.activeUser;
    if (!identifier) {
        pill.textContent = "Sin sesión activa";
        pill.dataset.state = "missing";
        return;
    }
    const hasTotp = ChatCore.hasStoredTotp(identifier);
    pill.textContent = hasTotp
        ? "TOTP guardado en este dispositivo"
        : "Captura tu secreto TOTP para autocompletar";
    pill.dataset.state = hasTotp ? "ok" : "missing";
}

function updateChatPresence(peerIdentifier) {
    const subtitle = document.getElementById("chat-subtitle");
    if (!subtitle) {
        return;
    }
    if (!peerIdentifier) {
        subtitle.textContent = "Esperando conversación";
        subtitle.dataset.state = "unknown";
        return;
    }
    const presence = ChatCore.describePresence(ChatCore.state.activeUser, peerIdentifier);
    const hasKey = ChatCore.hasSharedSecret(peerIdentifier);
    subtitle.textContent = `${peerIdentifier} · ${presence.label} · ${hasKey ? "Llave compartida" : "Pendiente"}`;
    subtitle.dataset.state = presence.status;
    subtitle.dataset.shared = hasKey ? "ok" : "missing";
}
