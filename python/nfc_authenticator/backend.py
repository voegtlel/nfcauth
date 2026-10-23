"""Transport-independent service adapter for discovery and proof of possession.

SQLiteStore supplies durable local credentials and process-local attempts;
BackendStore allows other adapters. Call directly or wrap these methods in a proxy
of your choice. The caller supplies a trusted reader identity and owns account
permissions.
"""

from __future__ import annotations

import base64
import secrets
import threading
import time
from collections.abc import Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .discovery import create_request, identify
from .service_crypto import (
    authentication_signature_payload,
    decrypt_authentication_response,
    encrypt_authentication_request,
)
from .service_manifest import PROTOCOL_VERSION, ServiceIdentity, ServicePrivacyConfig
from .storage import BackendStore, JsonObject


class ReferenceBackend:
    def __init__(
        self,
        identity: ServiceIdentity,
        privacy: ServicePrivacyConfig,
        store: BackendStore,
        auth: str = "biometric",
        clock: Callable[[], float] = time.time,
        *,
        reader_id: str = "local",
    ) -> None:
        if auth not in {"biometric", "background"}:
            raise ValueError("Choose biometric or background authentication")
        if not isinstance(reader_id, str) or not 1 <= len(reader_id) <= 255:
            raise ValueError("A nonempty trusted reader identity is required")
        self.identity, self.privacy, self.store = identity, privacy, store
        self.auth, self.clock = auth, clock
        self.reader_id = reader_id
        self.lock = threading.RLock()

    def _save(self, kind: str, value: JsonObject) -> str:
        return self.store.save_attempt(self.privacy.service_id, self.reader_id, kind, value, self.clock())

    def _consume(self, id_: str, kind: str) -> JsonObject:
        return self.store.consume_attempt(self.privacy.service_id, self.reader_id, id_, kind, self.clock())

    def start_discovery(self, transport_binding: str) -> JsonObject:
        with self.lock:
            request = create_request(self.identity, self.privacy, transport_binding)
            id_ = self._save("discovery", request)
            return {"id": id_, "request": request}

    def create_challenge(self, discovery_id: str, response: JsonObject) -> JsonObject:
        with self.lock:
            request = self._consume(discovery_id, "discovery")
            user_id = identify(request, response)
            credential = self.store.get_device(self.privacy.service_id, user_id)
            if credential is None:
                raise ValueError("Credential is not enrolled")
            nonce = secrets.token_hex(32)
            envelope, _ = encrypt_authentication_request(
                self.privacy.service_id,
                self.identity.encryption_private_key.public_key(),
                credential.session_key,
                nonce,
                self.auth,
            )
            id_ = self._save("proof", {"user_id": user_id, "nonce": nonce})
            return {"login_id": id_, "request": envelope, "auth_mode": self.auth}

    def complete(self, login_id: str, encrypted_response: JsonObject) -> str:
        with self.lock:
            attempt = self._consume(login_id, "proof")
            if not isinstance(encrypted_response, dict):
                raise TypeError("Authentication response must be an object")
            credential = self.store.get_device(self.privacy.service_id, attempt["user_id"])
            if credential is None:
                raise ValueError("Credential was revoked")
            response = decrypt_authentication_response(
                encrypted_response,
                self.privacy.service_id,
                self.identity.encryption_private_key.public_key(),
                credential.session_key,
            )
            if (
                response.get("protocol_version") != PROTOCOL_VERSION
                or response.get("service_id") != self.privacy.service_id
                or response.get("nonce") != attempt["nonce"]
                or response.get("user_id") != credential.user_id
            ):
                raise ValueError("Authentication response does not match the challenge")
            key = serialization.load_der_public_key(
                base64.b64decode(credential.authentication_public_key, validate=True)
            )
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
                raise TypeError("Credential must use a P-256 signing key")
            key.verify(
                base64.b64decode(response["signature"], validate=True),
                authentication_signature_payload(
                    self.privacy.service_id, attempt["nonce"], self.auth, credential.user_id
                ),
                ec.ECDSA(hashes.SHA256()),
            )
            return credential.user_id
