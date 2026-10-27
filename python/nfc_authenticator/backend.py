"""Transport-independent service adapter for NFC Auth v3."""

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
    decrypt_key_commit_ack,
    derive_rotated_key,
    encrypt_authentication_request,
    encrypt_key_commit,
)
from .service_manifest import PROTOCOL_VERSION, ServiceIdentity, ServicePrivacyConfig, manifest_hash
from .storage import BackendStore, JsonObject


class ReferenceBackend:
    def __init__(
        self,
        identity: ServiceIdentity,
        privacy: ServicePrivacyConfig,
        store: BackendStore,
        clock: Callable[[], float] = time.time,
        *,
        reader_id: str = "local",
    ) -> None:
        if not isinstance(reader_id, str) or not 1 <= len(reader_id) <= 255:
            raise ValueError("A nonempty trusted reader identity is required")
        self.identity, self.privacy, self.store = identity, privacy, store
        self.clock, self.reader_id = clock, reader_id
        self.manifest = identity.manifest(privacy)
        self.lock = threading.RLock()

    def _save(self, kind: str, value: JsonObject) -> str:
        return self.store.save_attempt(self.privacy.service_id, self.reader_id, kind, value, self.clock())

    def _consume(self, id_: str, kind: str) -> JsonObject:
        return self.store.consume_attempt(self.privacy.service_id, self.reader_id, id_, kind, self.clock())

    def start_discovery(self, transport_binding: str) -> JsonObject:
        with self.lock:
            request = create_request(self.manifest, transport_binding)
            return {"id": self._save("discovery", request), "request": request}

    def create_challenge(self, discovery_id: str, response: JsonObject) -> JsonObject:
        with self.lock:
            request = self._consume(discovery_id, "discovery")
            credential_id, phone_epochs = identify(request, response)
            credential = self.store.get_device(self.privacy.service_id, credential_id)
            if credential is None or credential.authentication_profile != self.privacy.authentication_profile:
                raise ValueError("Credential is not enrolled for this authentication profile")
            common = [epoch for epoch in credential.available_epochs if epoch in phone_epochs]
            if not common:
                raise ValueError("Phone and service have no common credential key epoch")
            epoch = max(common)
            key = credential.key_for_epoch(epoch)
            if key is None:
                raise ValueError("Credential key epoch is unavailable")
            nonce = secrets.token_hex(32)
            envelope, _ = encrypt_authentication_request(
                self.manifest,
                credential_id,
                key,
                epoch,
                nonce,
                request["transport_binding"],
            )
            attempt = {
                "credential_id": credential_id,
                "nonce": nonce,
                "key_epoch": epoch,
                "session_key": base64.b64encode(key).decode("ascii"),
                "transport_binding": request["transport_binding"],
                "manifest_hash": request["manifest_hash"],
            }
            return {
                "login_id": self._save("proof", attempt),
                "request": envelope,
                "authentication_profile": self.privacy.authentication_profile,
            }

    def complete(self, login_id: str, encrypted_response: JsonObject) -> JsonObject:
        with self.lock:
            attempt = self._consume(login_id, "proof")
            credential_id = attempt["credential_id"]
            credential = self.store.get_device(self.privacy.service_id, credential_id)
            if credential is None:
                raise ValueError("Credential was revoked")
            epoch = int(attempt["key_epoch"])
            key_bytes = base64.b64decode(attempt["session_key"], validate=True)
            response = decrypt_authentication_response(
                encrypted_response,
                self.manifest,
                credential_id,
                key_bytes,
                epoch,
            )
            if (
                response.get("protocol_version") != PROTOCOL_VERSION
                or response.get("service_id") != self.privacy.service_id
                or response.get("credential_id") != credential_id
                or response.get("authentication_profile") != self.privacy.authentication_profile
                or response.get("key_epoch") != epoch
                or response.get("nonce") != attempt["nonce"]
                or response.get("transport_binding") != attempt["transport_binding"]
                or response.get("manifest_hash") != attempt["manifest_hash"]
            ):
                raise ValueError("Authentication response does not match the challenge")
            public_key = serialization.load_der_public_key(
                base64.b64decode(credential.authentication_public_key, validate=True)
            )
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
                raise TypeError("Credential must use a P-256 signing key")
            public_key.verify(
                base64.b64decode(response["signature"], validate=True),
                authentication_signature_payload(
                    self.privacy.service_origin.rstrip("/"),
                    self.privacy.service_id,
                    credential_id,
                    self.privacy.authentication_profile,
                    epoch,
                    attempt["nonce"],
                    attempt["transport_binding"],
                    manifest_hash(self.manifest),
                ),
                ec.ECDSA(hashes.SHA256()),
            )

            current = self.store.get_device(self.privacy.service_id, credential_id)
            if current is None:
                raise ValueError("Credential was revoked")
            if current.key_epoch == epoch:
                # A valid proof under the pending epoch is stronger evidence than a
                # lost ACK: both peers demonstrably hold the same committed key.
                if current.rotation_id:
                    self.store.confirm_rotation(
                        self.privacy.service_id,
                        credential_id,
                        current.key_epoch,
                        current.rotation_id,
                    )
                    current = self.store.get_device(self.privacy.service_id, credential_id)
                    if current is None:
                        raise ValueError("Credential was revoked")
                rotation_id = attempt["nonce"]
                next_key = derive_rotated_key(
                    key_bytes,
                    self.privacy.service_id,
                    credential_id,
                    self.privacy.authentication_profile,
                    epoch,
                    attempt["nonce"],
                )
                current = self.store.rotate_device(
                    self.privacy.service_id,
                    credential_id,
                    epoch,
                    next_key,
                    rotation_id,
                )
            elif current.previous_key_epoch == epoch and current.key_epoch == epoch + 1:
                if not current.rotation_id:
                    raise ValueError("Stored credential rotation is incomplete")
                rotation_id = current.rotation_id
                next_key = current.session_key
            else:
                raise ValueError("Credential key epoch changed during authentication")

            return {
                "credential_id": credential_id,
                "key_epoch": current.key_epoch,
                "rotation_id": rotation_id,
                "commit": encrypt_key_commit(
                    self.manifest,
                    credential_id,
                    next_key,
                    current.key_epoch,
                    rotation_id,
                ),
            }

    def confirm_rotation(self, result: JsonObject, encrypted_ack: JsonObject) -> str:
        with self.lock:
            credential_id = result["credential_id"]
            credential = self.store.get_device(self.privacy.service_id, credential_id)
            if credential is None or credential.key_epoch != result["key_epoch"]:
                raise ValueError("Credential rotation is unavailable")
            ack = decrypt_key_commit_ack(
                encrypted_ack,
                self.manifest,
                credential_id,
                credential.session_key,
                credential.key_epoch,
            )
            if (
                ack.get("protocol_version") != PROTOCOL_VERSION
                or ack.get("status") != "key-commit-acknowledged"
                or ack.get("service_id") != self.privacy.service_id
                or ack.get("credential_id") != credential_id
                or ack.get("authentication_profile") != self.privacy.authentication_profile
                or ack.get("key_epoch") != credential.key_epoch
                or ack.get("rotation_id") != result["rotation_id"]
            ):
                raise ValueError("Key-rotation acknowledgement is invalid")
            self.store.confirm_rotation(
                self.privacy.service_id,
                credential_id,
                credential.key_epoch,
                result["rotation_id"],
            )
            return credential_id
