"""Executable service-side reference for discovery followed by proof of possession.

The store supplies enrolled credentials, never caller-chosen permissions. Attempts
are bounded, expire and are consumed once. Production deployments should replace
this in-memory attempt store with transactional durable storage and authenticate
their reader/backend connections. No HTTP server or unauthenticated enrollment is
silently enabled by this module.
"""

from __future__ import annotations

import base64
import secrets
import threading
import time
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .discovery import create_request, identify
from .service_crypto import (
    authentication_signature_payload,
    decrypt_authentication_response,
    encrypt_authentication_request,
)
from .service_manifest import PROTOCOL_VERSION


class ReferenceBackend:
    def __init__(self, identity, privacy, store, auth="biometric", clock=time.monotonic):
        if auth not in {"biometric", "background"}:
            raise ValueError("Choose biometric or background authentication")
        self.identity, self.privacy, self.store = identity, privacy, store
        self.auth, self.clock = auth, clock
        self.attempts = {}
        self.lock = threading.RLock()

    def _save(self, kind, value):
        now = self.clock()
        for id_ in list(self.attempts):
            if self.attempts[id_][1] <= now:
                del self.attempts[id_]
        if len(self.attempts) >= 256:
            raise ValueError("Too many pending authentication attempts")
        id_ = str(uuid4())
        self.attempts[id_] = kind, now + 120, value
        return id_

    def _consume(self, id_, kind):
        value = self.attempts.pop(id_, None)
        if not value or value[0] != kind or value[1] <= self.clock():
            raise ValueError("Attempt expired, consumed or of the wrong type")
        return value[2]

    def start_discovery(self, transport_binding):
        with self.lock:
            request = create_request(self.identity, self.privacy, transport_binding)
            id_ = self._save("discovery", request)
            return {"id": id_, "request": request}

    def create_challenge(self, discovery_id, response):
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

    def complete(self, login_id, encrypted_response):
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
