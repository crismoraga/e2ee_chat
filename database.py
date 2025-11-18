"""SQLite persistence layer for the TEL252 chat demo."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Optional

from . import crypto
from .config import DB_PATH

SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        totp_secret TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        device_name TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, device_name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_key_encrypted TEXT NOT NULL,
        nonce_b64 TEXT NOT NULL,
        ciphertext_b64 TEXT NOT NULL,
        tag_b64 TEXT NOT NULL,
        associated_data_b64 TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """,
)


class Database:
    """Thin wrapper around SQLite operations used by the API."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _ensure_schema(self) -> None:
        conn = self._connect()
        try:
            for stmt in SCHEMA_STATEMENTS:
                conn.execute(stmt)
            conn.commit()
        finally:
            conn.close()
    
    def close_all_connections(self) -> None:
        """Explicitly close all database connections (useful for testing)."""
        # SQLite connections are managed per-query, but we can force checkpoint
        try:
            conn = self._connect()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # User operations
    # ------------------------------------------------------------------

    def create_user(
        self,
        identifier: str,
        display_name: str,
        password_hash: str,
        totp_secret: str,
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users(identifier, display_name, password_hash, totp_secret)
                VALUES (?, ?, ?, ?)
                """,
                (identifier, display_name, password_hash, totp_secret),
            )
            conn.commit()
            return cursor.lastrowid

    def get_user_by_identifier(self, identifier: str) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM users WHERE identifier = ?",
                (identifier,),
            )
            return cursor.fetchone()

    def get_user_by_id(self, user_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,),
            )
            return cursor.fetchone()

    def list_users(self, exclude_user_id: Optional[int] = None) -> Iterable[sqlite3.Row]:
        query = "SELECT id, identifier, display_name FROM users ORDER BY identifier"
        params = ()
        if exclude_user_id is not None:
            query = "SELECT id, identifier, display_name FROM users WHERE id != ? ORDER BY identifier"
            params = (exclude_user_id,)
        with self._connect() as conn:
            cursor = conn.execute(query, params)
            yield from cursor.fetchall()

    # ------------------------------------------------------------------
    # Device operations
    # ------------------------------------------------------------------

    def register_device(self, user_id: int, device_name: str, public_key_pem: str) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO devices(user_id, device_name, public_key_pem)
                VALUES (?, ?, ?)
                """,
                (user_id, device_name, public_key_pem),
            )
            conn.commit()
            return cursor.lastrowid

    def get_primary_public_key(self, user_id: int) -> Optional[str]:
        """Return the most recently registered public key for ``user_id``."""

        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT public_key_pem FROM devices
                WHERE user_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = cursor.fetchone()
            return row["public_key_pem"] if row else None

    def list_devices(self, user_id: int) -> Iterable[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT id, device_name, public_key_pem, created_at FROM devices WHERE user_id = ?",
                (user_id,),
            )
            yield from cursor.fetchall()

    # ------------------------------------------------------------------
    # Message operations
    # ------------------------------------------------------------------

    def store_message(self, message: crypto.EncryptedMessage) -> int:
        record = asdict(message)
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO messages(
                    sender_id,
                    recipient_id,
                    session_key_encrypted,
                    nonce_b64,
                    ciphertext_b64,
                    tag_b64,
                    associated_data_b64
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["sender_id"],
                    record["recipient_id"],
                    record["session_key_encrypted"],
                    record["nonce_b64"],
                    record["ciphertext_b64"],
                    record["tag_b64"],
                    record["associated_data_b64"],
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def fetch_messages_for_user(self, user_id: int) -> Iterable[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT m.*, u.display_name AS sender_display_name, u.identifier AS sender_identifier
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE recipient_id = ?
                ORDER BY m.created_at ASC
                """,
                (user_id,),
            )
            yield from cursor.fetchall()

    def delete_message(self, message_id: int, recipient_id: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM messages WHERE id = ? AND recipient_id = ?",
                (message_id, recipient_id),
            )
            conn.commit()
