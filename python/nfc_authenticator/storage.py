"""SQLite credentials with process-local, single-use authentication attempts.

No transport, reader hardware or account/session policy is required here. Protect
the database file: credential secrets are encoded, not encrypted at rest.
"""

from __future__ import annotations

import base64
import sqlite3
import threading
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

JsonObject = dict[str, Any]


@dataclass(frozen=True)
class RegisteredDevice:
    user_id: str
    alias: str | None
    authentication_public_key: str
    session_key: bytes


@dataclass(frozen=True)
class PendingAttempt:
    service_id: str
    reader_id: str
    kind: str
    expires_at: float
    payload: JsonObject


class BackendStore(Protocol):
    """Storage boundary; alternative databases can implement the same methods."""

    def get_device(self, service_id: str, user_id: str) -> RegisteredDevice | None: ...

    def save_attempt(
        self,
        service_id: str,
        reader_id: str,
        kind: str,
        value: JsonObject,
        now: float,
    ) -> str: ...

    def consume_attempt(
        self,
        service_id: str,
        reader_id: str,
        attempt_id: str,
        kind: str,
        now: float,
    ) -> JsonObject: ...


class SQLiteStore:
    """Durable credentials plus process-local, reader-scoped attempt storage.

    One instance supports threads. Attempts intentionally disappear when this object
    is closed or the process exits; separate instances never share pending attempts.
    """

    def __init__(self, db_path: str | Path = "auth.db") -> None:
        self.lock = threading.RLock()
        self.attempts: dict[str, PendingAttempt] = {}
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=5)
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS registered_devices_v2 (
                    service_id TEXT NOT NULL,
                    user_id TEXT PRIMARY KEY,
                    alias TEXT,
                    authentication_public_key TEXT NOT NULL,
                    session_key TEXT NOT NULL,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    def register_device(
        self,
        service_id: str,
        user_id: str,
        alias: str | None,
        authentication_public_key: str,
        session_key: bytes,
    ) -> None:
        """Persist a credential after the caller validates/authorizes enrollment."""
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO registered_devices_v2 "
                "(service_id,user_id,alias,authentication_public_key,session_key) VALUES (?,?,?,?,?)",
                (service_id, user_id, alias, authentication_public_key, base64.b64encode(session_key).decode("ascii")),
            )

    def remove_registration(self, user_id: str) -> None:
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM registered_devices_v2 WHERE user_id=?", (user_id,))

    @staticmethod
    def _device(row: tuple[str, str | None, str, str] | None) -> RegisteredDevice | None:
        if row is None:
            return None
        try:
            return RegisteredDevice(row[0], row[1], row[2], base64.b64decode(row[3], validate=True))
        except ValueError as error:
            raise ValueError("Stored service credential is malformed") from error

    def get_device(self, service_id: str, user_id: str) -> RegisteredDevice | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT user_id,alias,authentication_public_key,session_key "
                "FROM registered_devices_v2 WHERE service_id=? AND user_id=?",
                (service_id, user_id),
            ).fetchone()
            return self._device(row)

    def get_default_device(self, service_id: str) -> RegisteredDevice | None:
        """Legacy lookup; discovery authentication always selects an exact ID."""
        with self.lock:
            row = self.conn.execute(
                "SELECT user_id,alias,authentication_public_key,session_key "
                "FROM registered_devices_v2 WHERE service_id=? ORDER BY registered_at LIMIT 1",
                (service_id,),
            ).fetchone()
            return self._device(row)

    def save_attempt(
        self,
        service_id: str,
        reader_id: str,
        kind: str,
        value: JsonObject,
        now: float,
    ) -> str:
        with self.lock:
            self.attempts = {
                attempt_id: attempt
                for attempt_id, attempt in self.attempts.items()
                if attempt.expires_at > now
            }
            count = sum(
                attempt.service_id == service_id and attempt.reader_id == reader_id
                for attempt in self.attempts.values()
            )
            if count >= 256:
                raise ValueError("Too many pending authentication attempts")
            attempt_id = str(uuid4())
            while attempt_id in self.attempts:
                attempt_id = str(uuid4())
            self.attempts[attempt_id] = PendingAttempt(
                service_id,
                reader_id,
                kind,
                now + 120,
                deepcopy(value),
            )
        return attempt_id

    def consume_attempt(
        self,
        service_id: str,
        reader_id: str,
        attempt_id: str,
        kind: str,
        now: float,
    ) -> JsonObject:
        with self.lock:
            attempt = self.attempts.get(attempt_id)
            if (
                attempt is None
                or attempt.service_id != service_id
                or attempt.reader_id != reader_id
            ):
                raise ValueError("Attempt expired, consumed or of the wrong type")
            # Consume before validating the proof so a failed attempt cannot be retried.
            del self.attempts[attempt_id]
            if attempt.kind != kind or attempt.expires_at <= now:
                raise ValueError("Attempt expired, consumed or of the wrong type")
            return deepcopy(attempt.payload)

    def close(self) -> None:
        with self.lock:
            self.attempts.clear()
            self.conn.close()

    def __enter__(self) -> SQLiteStore:  # noqa: PYI034 - support Python 3.9 without typing_extensions.
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
