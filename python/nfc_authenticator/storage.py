"""Protocol-v3 credential storage with durable key epochs and transient attempts."""

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
    credential_id: str
    alias: str | None
    authentication_profile: str
    authentication_public_key: str
    session_key: bytes
    key_epoch: int
    previous_session_key: bytes | None = None
    previous_key_epoch: int | None = None
    rotation_id: str | None = None

    def key_for_epoch(self, epoch: int) -> bytes | None:
        if epoch == self.key_epoch:
            return self.session_key
        if epoch == self.previous_key_epoch:
            return self.previous_session_key
        return None

    @property
    def available_epochs(self) -> tuple[int, ...]:
        epochs = [self.key_epoch]
        if self.previous_key_epoch is not None:
            epochs.append(self.previous_key_epoch)
        return tuple(sorted(epochs, reverse=True))


@dataclass(frozen=True)
class PendingAttempt:
    service_id: str
    reader_id: str
    kind: str
    expires_at: float
    payload: JsonObject


class BackendStore(Protocol):
    def get_device(self, service_id: str, credential_id: str) -> RegisteredDevice | None: ...

    def rotate_device(
        self,
        service_id: str,
        credential_id: str,
        expected_epoch: int,
        new_key: bytes,
        rotation_id: str,
    ) -> RegisteredDevice: ...

    def confirm_rotation(self, service_id: str, credential_id: str, epoch: int, rotation_id: str) -> None: ...

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
    """New v3 database; no v1/v2 tables or migrations are opened."""

    def __init__(self, db_path: str | Path = "auth-v3.db") -> None:
        self.lock = threading.RLock()
        self.attempts: dict[str, PendingAttempt] = {}
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=5)
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS registered_credentials (
                    service_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    alias TEXT,
                    authentication_profile TEXT NOT NULL,
                    authentication_public_key TEXT NOT NULL,
                    session_key TEXT NOT NULL,
                    key_epoch INTEGER NOT NULL,
                    previous_session_key TEXT,
                    previous_key_epoch INTEGER,
                    rotation_id TEXT,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(service_id, credential_id)
                )
            """)

    def register_device(
        self,
        service_id: str,
        credential_id: str,
        alias: str | None,
        authentication_profile: str,
        authentication_public_key: str,
        session_key: bytes,
    ) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO registered_credentials "
                "(service_id,credential_id,alias,authentication_profile,"
                "authentication_public_key,session_key,key_epoch,"
                "previous_session_key,previous_key_epoch,rotation_id) VALUES (?,?,?,?,?,?,0,NULL,NULL,NULL)",
                (
                    service_id,
                    credential_id,
                    alias,
                    authentication_profile,
                    authentication_public_key,
                    _encode_key(session_key),
                ),
            )

    def remove_registration(self, service_id: str, credential_id: str) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                "DELETE FROM registered_credentials WHERE service_id=? AND credential_id=?",
                (service_id, credential_id),
            )

    @staticmethod
    def _device(row: tuple[Any, ...] | None) -> RegisteredDevice | None:
        if row is None:
            return None
        return RegisteredDevice(
            credential_id=row[0],
            alias=row[1],
            authentication_profile=row[2],
            authentication_public_key=row[3],
            session_key=_decode_key(row[4]),
            key_epoch=int(row[5]),
            previous_session_key=_decode_key(row[6]) if row[6] is not None else None,
            previous_key_epoch=int(row[7]) if row[7] is not None else None,
            rotation_id=row[8],
        )

    def get_device(self, service_id: str, credential_id: str) -> RegisteredDevice | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT credential_id,alias,authentication_profile,authentication_public_key,"
                "session_key,key_epoch,previous_session_key,previous_key_epoch "
                ",rotation_id "
                "FROM registered_credentials WHERE service_id=? AND credential_id=?",
                (service_id, credential_id),
            ).fetchone()
            return self._device(row)

    def rotate_device(
        self,
        service_id: str,
        credential_id: str,
        expected_epoch: int,
        new_key: bytes,
        rotation_id: str,
    ) -> RegisteredDevice:
        with self.lock, self.conn:
            current = self.get_device(service_id, credential_id)
            if current is None:
                raise ValueError("Credential was revoked")
            if current.key_epoch == expected_epoch + 1:
                if current.rotation_id != rotation_id:
                    raise ValueError("Credential already has a different pending rotation")
                return current
            if current.key_epoch != expected_epoch:
                raise ValueError("Credential key epoch changed concurrently")
            result = self.conn.execute(
                "UPDATE registered_credentials SET previous_session_key=session_key,"
                "previous_key_epoch=key_epoch,session_key=?,key_epoch=?,rotation_id=? "
                "WHERE service_id=? AND credential_id=? AND key_epoch=?",
                (
                    _encode_key(new_key),
                    expected_epoch + 1,
                    rotation_id,
                    service_id,
                    credential_id,
                    expected_epoch,
                ),
            )
            if result.rowcount != 1:
                raise ValueError("Credential key epoch changed concurrently")
            updated = self.get_device(service_id, credential_id)
            if updated is None:
                raise ValueError("Credential was revoked")
            return updated

    def confirm_rotation(
        self,
        service_id: str,
        credential_id: str,
        epoch: int,
        rotation_id: str,
    ) -> None:
        with self.lock, self.conn:
            result = self.conn.execute(
                "UPDATE registered_credentials SET previous_session_key=NULL,"
                "previous_key_epoch=NULL,rotation_id=NULL "
                "WHERE service_id=? AND credential_id=? AND key_epoch=? AND rotation_id=?",
                (service_id, credential_id, epoch, rotation_id),
            )
            if result.rowcount != 1:
                raise ValueError("Credential rotation acknowledgement is stale or invalid")

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
                attempt_id: attempt for attempt_id, attempt in self.attempts.items() if attempt.expires_at > now
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
                now + 30,
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
            if attempt is None or attempt.service_id != service_id or attempt.reader_id != reader_id:
                raise ValueError("Attempt expired, consumed or of the wrong type")
            del self.attempts[attempt_id]
            if attempt.kind != kind or attempt.expires_at <= now:
                raise ValueError("Attempt expired, consumed or of the wrong type")
            return deepcopy(attempt.payload)

    def close(self) -> None:
        with self.lock:
            self.attempts.clear()
            self.conn.close()

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _encode_key(key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("Credential key must contain 32 bytes")
    return base64.b64encode(key).decode("ascii")


def _decode_key(value: str) -> bytes:
    try:
        key = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ValueError("Stored service credential is malformed") from error
    if len(key) != 32:
        raise ValueError("Stored service credential is malformed")
    return key
