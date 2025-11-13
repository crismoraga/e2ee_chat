"""Flask-based front-end client for the TEL252 secure chat API."""

from __future__ import annotations

import os
import sys
import time
from functools import wraps
from typing import Callable, Optional

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clients.service import APIError, E2EEChatClient

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.secret_key = os.environ.get("E2E_CHAT_WEB_SECRET", "dev-secret-key")

client = E2EEChatClient(
    base_url=os.environ.get("E2E_CHAT_API_BASE", "http://127.0.0.1:5000")
)


def datetimeformat(timestamp: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


app.jinja_env.filters["datetimeformat"] = datetimeformat


def require_login(view: Callable) -> Callable:
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "phone" not in session:
            flash("Please log in to continue.")
            return redirect(url_for("home"))
        return view(*args, **kwargs)

    return wrapper


@app.route("/", methods=["GET"])
def home():
    if session.get("phone"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register_user():
    phone = request.form.get("phone", "").strip()
    password = request.form.get("password", "")
    if not phone or not password:
        flash("Phone and password are required.")
        return redirect(url_for("home"))
    try:
        state, meta = client.register(phone, password)
    except APIError as exc:
        flash(str(exc))
        return redirect(url_for("home"))

    session["phone"] = phone
    return render_template(
        "totp_info.html",
        totp_secret=state.totp_secret,
        totp_uri=meta["totp_uri"],
    )


@app.route("/login", methods=["POST"])
def login_user():
    phone = request.form.get("phone", "").strip()
    password = request.form.get("password", "")
    totp_code = request.form.get("totp", "").strip() or None
    if not phone or not password:
        flash("Phone and password are required.")
        return redirect(url_for("home"))

    try:
        client.login(phone, password, totp=totp_code)
    except APIError as exc:
        flash(str(exc))
        return redirect(url_for("home"))

    session["phone"] = phone
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["GET"])
@require_login
def logout():
    session.pop("phone", None)
    flash("Logged out.")
    return redirect(url_for("home"))


@app.route("/dashboard", methods=["GET"])
@require_login
def dashboard():
    phone = session["phone"]
    state = client.get_state(phone)
    if state is None:
        flash("No local state found; please register again.")
        return redirect(url_for("home"))

    contacts = state.contacts
    selected_peer = request.args.get("peer")
    if not selected_peer and contacts:
        selected_peer = next(iter(contacts.keys()))

    messages = []
    if selected_peer:
        try:
            messages = client.fetch_messages(phone, selected_peer)
        except APIError as exc:
            flash(str(exc))
            messages = []

    totp_code = client.generate_totp(phone)
    totp_remaining = 30 - (int(time.time()) % 30)

    return render_template(
        "dashboard.html",
        contacts=contacts,
        messages=messages,
        selected_peer=selected_peer,
        totp_code=totp_code,
        totp_remaining=totp_remaining,
    )


@app.route("/contacts", methods=["POST"])
@require_login
def add_contact_route():
    phone = session["phone"]
    contact_phone = request.form.get("contact_phone", "").strip()
    if not contact_phone:
        flash("Provide a contact phone number.")
        return redirect(url_for("dashboard"))
    try:
        client.add_contact(phone, contact_phone)
        flash(f"Contact {contact_phone} added. Ensure they add you back to enable E2EE.")
    except APIError as exc:
        flash(str(exc))
    return redirect(url_for("dashboard", peer=contact_phone))


@app.route("/messages", methods=["POST"])
@require_login
def send_message_route():
    phone = session["phone"]
    recipient = request.form.get("recipient", "").strip()
    plaintext = request.form.get("message", "")
    if not recipient or not plaintext:
        flash("Recipient and message are required.")
        return redirect(url_for("dashboard"))
    try:
        client.send_message(phone, recipient, plaintext)
        flash("Message sent securely.")
    except APIError as exc:
        flash(str(exc))
    return redirect(url_for("dashboard", peer=recipient))


if __name__ == "__main__":
    port = int(os.environ.get("E2E_CHAT_WEB_PORT", "5001"))
    app.run(port=port, debug=True)
