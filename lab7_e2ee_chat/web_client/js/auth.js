document.addEventListener("DOMContentLoaded", () => {
    const state = ChatCore.bootstrap();
    const tabs = document.querySelectorAll("[data-tab]");
    const loginForm = document.getElementById("login-form");
    const registerForm = document.getElementById("register-form");
    const loginFeedback = document.getElementById("login-feedback");
    const registerFeedback = document.getElementById("register-feedback");
    const workspaceList = document.getElementById("workspace-links");

    if (ChatCore.hasActiveSession()) {
        ChatCore.navigateToWorkspace("mensajes");
        return;
    }

    function showFeedback(target, message, variant = "info") {
        if (!target) {
            return;
        }
        target.textContent = message;
        target.dataset.variant = variant;
    }

    function toggleTab(tabName) {
        tabs.forEach((tab) => {
            const isActive = tab.dataset.tab === tabName;
            tab.classList.toggle("active", isActive);
            tab.setAttribute("aria-selected", String(isActive));
            document.getElementById(tab.getAttribute("aria-controls"))?.classList.toggle("hidden", !isActive);
        });
    }

    tabs.forEach((tab) => {
        tab.addEventListener("click", () => toggleTab(tab.dataset.tab));
    });

    function renderWorkspaceLinks() {
        if (!workspaceList) {
            return;
        }
        const destinations = ChatCore.getWorkspaceDestinations();
        workspaceList.innerHTML = "";
        Object.entries(destinations).forEach(([page, url]) => {
            let label = url;
            try {
                const parsed = new URL(url);
                label = `${parsed.host}${parsed.pathname}`;
            } catch (error) {
                console.warn("URL destino inválida", error);
            }
            const item = document.createElement("li");
            item.innerHTML = `<strong>${page}</strong><span>${label}</span>`;
            workspaceList.appendChild(item);
        });
    }

    renderWorkspaceLinks();

    loginForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const identifier = document.getElementById("login-identifier").value.trim();
        const password = document.getElementById("login-password").value;
        const totp = document.getElementById("login-totp").value.trim();
        if (!identifier || !password) {
            showFeedback(loginFeedback, "Completa correo y contraseña", "error");
            return;
        }
        try {
            showFeedback(loginFeedback, "Autenticando...", "info");
            await ChatCore.completeLogin(identifier, password, totp);
            showFeedback(loginFeedback, "Sesión iniciada, redirigiendo...", "success");
            ChatCore.navigateToWorkspace("mensajes");
        } catch (error) {
            showFeedback(loginFeedback, error.message, "error");
        }
    });

    registerForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const displayName = document.getElementById("register-display").value.trim();
        const identifier = document.getElementById("register-identifier").value.trim();
        const password = document.getElementById("register-password").value;
        if (!displayName || !identifier || !password) {
            showFeedback(registerFeedback, "Completa todos los campos", "error");
            return;
        }
        try {
            showFeedback(registerFeedback, "Creando cuenta...", "info");
            await ChatCore.registerAccount({ displayName, identifier, password });
            showFeedback(registerFeedback, "Cuenta creada, sincronizando dispositivo...", "success");
            await ChatCore.completeLogin(identifier, password);
            ChatCore.navigateToWorkspace("mensajes");
        } catch (error) {
            showFeedback(registerFeedback, error.message, "error");
        }
    });
});
