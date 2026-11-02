from __future__ import annotations

import asyncio
import base64
import secrets
import time
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from nfc_authenticator.protocol_v4 import PROTOCOL_VERSION, canonical_json

from .models import Credential
from .ports import EnrollmentStore

RENEWAL_DOMAIN = b"NFCAuth-v4-registration-renewal\x00"


@dataclass(frozen=True)
class RenewalAttempt:
    renewal_id: str
    credential_id: str
    service_id: str
    profile: str
    challenge: str
    issued_at: int
    challenge_expires_at: int
    current_registration_expires_at: int
    proposed_registration_expires_at: int
    protocol_version: int = PROTOCOL_VERSION
    action: str = "registration.renew"

    def document(self) -> dict:
        return asdict(self)

    def payload(self) -> bytes:
        return RENEWAL_DOMAIN + canonical_json(self.document())


class RenewalAttempts:
    def __init__(self, *, maximum_entries: int = 4096, clock=time.time) -> None:
        self._values: dict[str, RenewalAttempt] = {}
        self._lock = asyncio.Lock()
        self.maximum_entries = maximum_entries
        self.clock = clock

    async def create(self, value: RenewalAttempt) -> None:
        async with self._lock:
            self._prune()
            if len(self._values) >= self.maximum_entries:
                raise ValueError("Too many renewal attempts")
            self._values[value.renewal_id] = value

    async def get(self, renewal_id: str) -> RenewalAttempt:
        async with self._lock:
            self._prune()
            value = self._values.get(renewal_id)
            if value is None:
                raise ValueError("Renewal is unavailable or expired")
            return value

    async def consume(self, renewal_id: str) -> RenewalAttempt:
        async with self._lock:
            self._prune()
            value = self._values.pop(renewal_id, None)
            if value is None:
                raise ValueError("Renewal is unavailable or expired")
            return value

    def _prune(self) -> None:
        now = int(self.clock())
        for key in [key for key, value in self._values.items() if value.challenge_expires_at <= now]:
            del self._values[key]


class RenewalCoordinator:
    def __init__(
        self,
        service_id: str,
        attempts: RenewalAttempts,
        enrollments: EnrollmentStore,
        *,
        credential_lifetime_seconds: int,
        clock=time.time,
    ) -> None:
        self.service_id = service_id
        self.attempts = attempts
        self.enrollments = enrollments
        self.credential_lifetime_seconds = credential_lifetime_seconds
        self.clock = clock

    async def start(self, credential_id: str) -> RenewalAttempt:
        now = int(self.clock())
        credential = await self.enrollments.get_credential(credential_id)
        if (
            credential is None
            or credential.revoked
            or credential.service_id != self.service_id
            or credential.expires_at <= now
        ):
            raise ValueError("Registration is unavailable or expired")
        attempt = RenewalAttempt(
            secrets.token_urlsafe(24),
            credential.credential_id,
            credential.service_id,
            credential.profile,
            secrets.token_urlsafe(32),
            now,
            now + 120,
            credential.expires_at,
            now + self.credential_lifetime_seconds,
        )
        await self.attempts.create(attempt)
        return attempt

    async def complete(self, renewal_id: str, signature: str) -> Credential:
        attempt = await self.attempts.get(renewal_id)
        now = int(self.clock())
        if attempt.challenge_expires_at <= now or attempt.service_id != self.service_id:
            raise ValueError("Renewal is unavailable or expired")
        credential = await self.enrollments.get_credential(attempt.credential_id)
        if (
            credential is None
            or credential.revoked
            or credential.profile != attempt.profile
            or credential.expires_at <= now
        ):
            raise ValueError("Registration is unavailable or expired")
        public_key = serialization.load_der_public_key(base64.b64decode(credential.public_key, validate=True))
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise TypeError("Credential must use P-256")
        public_key.verify(base64.b64decode(signature, validate=True), attempt.payload(), ec.ECDSA(hashes.SHA256()))
        await self.attempts.consume(renewal_id)
        renewed = await self.enrollments.renew_credential(
            credential.credential_id,
            now=now,
            expires_at=attempt.proposed_registration_expires_at,
            authenticated=False,
        )
        if renewed is None:
            raise ValueError("Registration could not be renewed")
        return renewed
