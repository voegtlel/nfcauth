"""Typed, canonical messages for NFC Auth protocol v4.

Only the random session hello is sent before the NFC AEAD channel is active.
Authorization requests are signed by the provider bridge and assertions are
signed by a profile-specific phone key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict, dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PROTOCOL_VERSION = 4
REQUEST_DOMAIN = b"NFCAuth-v4-authorization-request\x00"
ASSERTION_DOMAIN = b"NFCAuth-v4-authorization-assertion\x00"
DELIVERY_DOMAIN = b"NFCAuth-v4-assertion-delivery\x00"
ALLOWED_ASSURANCE = frozenset({"possession", "biometric"})


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class SessionBinding:
    session_id: str
    phone_challenge: str
    terminal_ephemeral_public_key: str
    phone_ephemeral_public_key: str

    def validate(self) -> None:
        if len(_unb64(self.session_id)) != 16 or len(_unb64(self.phone_challenge)) != 32:
            raise ValueError("Invalid NFC session identifiers")
        for encoded in (self.terminal_ephemeral_public_key, self.phone_ephemeral_public_key):
            key = _unb64(encoded)
            if len(key) != 65 or key[0] != 4:
                raise ValueError("NFC session keys must be uncompressed P-256 points")


@dataclass(frozen=True)
class AuthorizationRequest:
    transaction_id: str
    service_id: str
    service_origin: str
    manifest_hash: str
    terminal_id: str
    terminal_key_fingerprint: str
    audience: str
    scopes: tuple[str, ...]
    action: str
    assurance: str
    issued_at: int
    expires_at: int
    session: SessionBinding
    protocol_version: int = PROTOCOL_VERSION

    def validate(self, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError("Unsupported protocol version")
        if not all((self.transaction_id, self.service_id, self.service_origin, self.terminal_id, self.audience, self.action)):
            raise ValueError("Authorization request has an empty required field")
        if not self.service_origin.startswith("https://"):
            raise ValueError("Service origin must use HTTPS")
        if len(self.manifest_hash) != 64 or len(self.terminal_key_fingerprint) != 64:
            raise ValueError("Invalid request fingerprint")
        if self.assurance not in ALLOWED_ASSURANCE:
            raise ValueError("Unsupported assurance profile")
        if not self.scopes or len(set(self.scopes)) != len(self.scopes) or any(not value for value in self.scopes):
            raise ValueError("Scopes must be nonempty and unique")
        if self.expires_at <= self.issued_at or self.expires_at - self.issued_at > 120:
            raise ValueError("Authorization request lifetime exceeds two minutes")
        if current < self.issued_at - 30 or current >= self.expires_at:
            raise ValueError("Authorization request is not currently valid")
        self.session.validate()

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["scopes"] = sorted(self.scopes)
        return value

    def payload(self) -> bytes:
        return REQUEST_DOMAIN + canonical_json(self.document())

    @property
    def request_hash(self) -> str:
        return sha256_hex(self.payload())


@dataclass(frozen=True)
class AuthorizationAssertion:
    transaction_id: str
    request_hash: str
    service_id: str
    terminal_id: str
    credential_id: str
    assurance: str
    key_version: int
    approved_at: int
    signature: str = ""
    protocol_version: int = PROTOCOL_VERSION

    def unsigned_document(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value

    def payload(self) -> bytes:
        return ASSERTION_DOMAIN + canonical_json(self.unsigned_document())

    def with_signature(self, private_key: ec.EllipticCurvePrivateKey) -> AuthorizationAssertion:
        signature = private_key.sign(self.payload(), ec.ECDSA(hashes.SHA256()))
        return AuthorizationAssertion(**{**asdict(self), "signature": _b64(signature)})

    def verify(self, public_key_der_b64: str, request: AuthorizationRequest, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        if self.protocol_version != PROTOCOL_VERSION or self.request_hash != request.request_hash:
            raise ValueError("Assertion is not bound to the authorization request")
        if (
            self.transaction_id != request.transaction_id
            or self.service_id != request.service_id
            or self.terminal_id != request.terminal_id
            or self.assurance != request.assurance
        ):
            raise ValueError("Assertion context does not match")
        if self.key_version < 1 or not self.credential_id or abs(current - self.approved_at) > 120:
            raise ValueError("Assertion is invalid or expired")
        public_key = serialization.load_der_public_key(base64.b64decode(public_key_der_b64, validate=True))
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise TypeError("Credential must use P-256")
        public_key.verify(_unb64(self.signature), self.payload(), ec.ECDSA(hashes.SHA256()))


@dataclass(frozen=True)
class AssertionDeliveryRequest:
    transaction_id: str
    request_hash: str
    service_id: str
    service_origin: str
    terminal_id: str
    terminal_key_fingerprint: str
    issued_at: int
    expires_at: int
    session: SessionBinding
    protocol_version: int = PROTOCOL_VERSION

    def document(self) -> dict[str, Any]:
        return asdict(self)

    def payload(self) -> bytes:
        return DELIVERY_DOMAIN + canonical_json(self.document())

    def validate(self, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        if self.protocol_version != PROTOCOL_VERSION or self.expires_at <= self.issued_at:
            raise ValueError("Invalid delivery request")
        if self.expires_at - self.issued_at > 30 or current < self.issued_at - 10 or current >= self.expires_at:
            raise ValueError("Delivery request is expired")
        if len(self.request_hash) != 64 or len(self.terminal_key_fingerprint) != 64:
            raise ValueError("Invalid delivery binding")
        self.session.validate()


def public_key_der_b64(public_key: ec.EllipticCurvePublicKey) -> str:
    return base64.b64encode(
        public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode("ascii")
