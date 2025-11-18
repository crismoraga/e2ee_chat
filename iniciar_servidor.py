#!/usr/bin/env python3
"""Launcher para el servidor Flask del chat E2EE (TEL252)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Optional, Tuple

# Asegura que el paquete lab7_e2ee_chat sea importable
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from lab7_e2ee_chat.server import create_app  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inicia la API Flask del laboratorio 7 con soporte opcional TLS",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host/IP para el servidor (default: 127.0.0.1)")
    parser.add_argument("--port", default=5000, type=int, help="Puerto TCP para escuchar (default: 5000)")
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Activa HTTPS usando un certificado self-signed generado por Werkzeug",
    )
    parser.add_argument("--cert", help="Ruta a certificado TLS PEM (requiere --key)")
    parser.add_argument("--key", help="Ruta a llave privada TLS PEM (requiere --cert)")
    return parser.parse_args()


def _resolve_ssl_context(args: argparse.Namespace) -> Optional[Any]:
    if args.cert and args.key:
        return args.cert, args.key
    if args.cert or args.key:
        raise SystemExit("Debe proporcionar --cert y --key juntos o ninguno")
    if args.tls:
        # Werkzeug generará un certificado autofirmado (ideal para pruebas / Wireshark)
        return "adhoc"
    return None


def main() -> None:
    """Imprime banner y levanta la aplicación Flask."""
    args = _parse_args()
    ssl_context = _resolve_ssl_context(args)

    scheme = "https" if ssl_context else "http"
    base_url = f"{scheme}://{args.host}:{args.port}"

    banner = "=" * 80
    print(banner)
    print(" TEL252 - Chat con Cifrado de Extremo a Extremo")
    print(banner)
    print("\n🔐 Primitivas activas: HMAC-SHA256, TOTP, RSA-2048, RSA-OAEP, AES-256-GCM, JWT-HMAC")
    if ssl_context == "adhoc":
        print("🔒 TLS: modo adhoc (self-signed, ideal para capturas Wireshark)")
    elif isinstance(ssl_context, tuple):
        print(f"🔒 TLS: certificado personalizado {ssl_context[0]}")
    else:
        print("🔓 TLS desactivado (HTTP plano)")
    print(f"🌐 API: {base_url}")
    print(f"🖥️  Cliente Web: {base_url}/ui/\n")

    app = create_app()
    app.run(host=args.host, port=args.port, debug=False, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
