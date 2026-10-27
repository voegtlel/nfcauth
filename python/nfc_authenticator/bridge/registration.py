from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .models import Credential, Subject
from .ports import EnrollmentStore

REGISTRATION_DOMAIN = b"NFCAuth-v4-registration-complete\x00"


@dataclass
class RegistrationAttempt:
    registration_id: str
    state: str
    nonce: str
    pkce_verifier: str
    profile: str
    public_key: str
    expires_at: int
    subject: Subject | None = None
    credential_id: str | None = None
    completion_code: str | None = None


class RegistrationAttempts:
    def __init__(self) -> None:
        self._values: dict[str, RegistrationAttempt] = {}
        self._states: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def create(self, value: RegistrationAttempt) -> None:
        async with self._lock:
            self._values[value.registration_id] = value
            self._states[value.state] = value.registration_id

    async def by_id(self, registration_id: str) -> RegistrationAttempt:
        async with self._lock:
            value = self._values.get(registration_id)
            if value is None or value.expires_at <= int(time.time()):
                raise ValueError("Registration is unavailable or expired")
            return value

    async def by_state(self, state: str) -> RegistrationAttempt:
        async with self._lock:
            registration_id = self._states.get(state)
        if registration_id is None:
            raise ValueError("OIDC state is invalid")
        return await self.by_id(registration_id)

    async def consume(self, registration_id: str) -> RegistrationAttempt:
        async with self._lock:
            value = self._values.pop(registration_id, None)
            if value is None or value.expires_at <= int(time.time()):
                raise ValueError("Registration is unavailable or expired")
            self._states.pop(value.state, None)
            return value


class GenericOidcIdentityProvider:
    def __init__(
        self,
        *,
        issuer: str,
        authorization_endpoint: str,
        token_endpoint: str,
        jwks_uri: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        for endpoint in (issuer, authorization_endpoint, token_endpoint, jwks_uri, redirect_uri):
            if not endpoint.startswith("https://"):
                raise ValueError("OIDC endpoints and issuer must use HTTPS")
        self.issuer = issuer.rstrip("/")
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.jwks_uri = jwks_uri
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.timeout_seconds = timeout_seconds

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        return self.authorization_endpoint + "?" + urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": "openid",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )

    async def complete(self, code: str, expected_nonce: str, code_verifier: str) -> Subject:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            token_response = await client.post(
                self.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "code_verifier": code_verifier,
                },
                auth=(self.client_id, self.client_secret),
                headers={"Accept": "application/json"},
            )
            token_response.raise_for_status()
            encoded = token_response.json()["id_token"]
            jwks_response = await client.get(self.jwks_uri, headers={"Accept": "application/json"})
            jwks_response.raise_for_status()
        header = jwt.get_unverified_header(encoded)
        candidates = [key for key in jwks_response.json()["keys"] if key.get("kid") == header.get("kid")]
        if len(candidates) != 1:
            raise ValueError("OIDC signing key is unavailable or ambiguous")
        key = jwt.PyJWK.from_dict(candidates[0]).key
        claims = jwt.decode(
            encoded,
            key,
            algorithms=[header["alg"]],
            audience=self.client_id,
            issuer=self.issuer,
            options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
        )
        if claims["nonce"] != expected_nonce:
            raise ValueError("OIDC nonce mismatch")
        return Subject(claims["iss"], claims["sub"])


class RegistrationCoordinator:
    def __init__(self, service_id: str, attempts: RegistrationAttempts, enrollments: EnrollmentStore, oidc) -> None:
        self.service_id = service_id
        self.attempts = attempts
        self.enrollments = enrollments
        self.oidc = oidc

    async def start(self, profile: str, public_key: str) -> tuple[RegistrationAttempt, str]:
        if profile not in {"possession", "biometric"}:
            raise ValueError("Unsupported credential profile")
        key = serialization.load_der_public_key(base64.b64decode(public_key, validate=True))
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("Registration key must be P-256")
        verifier = secrets.token_urlsafe(48)
        attempt = RegistrationAttempt(
            secrets.token_urlsafe(24),
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(32),
            verifier,
            profile,
            public_key,
            int(time.time()) + 300,
        )
        await self.attempts.create(attempt)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        return attempt, self.oidc.authorization_url(attempt.state, attempt.nonce, challenge)

    async def callback(self, state: str, code: str) -> RegistrationAttempt:
        attempt = await self.attempts.by_state(state)
        attempt.subject = await self.oidc.complete(code, attempt.nonce, attempt.pkce_verifier)
        attempt.credential_id = secrets.token_urlsafe(24)
        attempt.completion_code = secrets.token_urlsafe(32)
        attempt.expires_at = int(time.time()) + 60
        return attempt

    async def complete(self, registration_id: str, completion_code: str, signature: str) -> Credential:
        attempt = await self.attempts.by_id(registration_id)
        if not secrets.compare_digest(attempt.completion_code or "", completion_code):
            raise ValueError("Registration completion code is invalid")
        public_key = serialization.load_der_public_key(base64.b64decode(attempt.public_key, validate=True))
        payload = REGISTRATION_DOMAIN + registration_id.encode() + b"\x00" + completion_code.encode()
        public_key.verify(base64.b64decode(signature, validate=True), payload, ec.ECDSA(hashes.SHA256()))
        attempt = await self.attempts.consume(registration_id)
        if attempt.subject is None or attempt.credential_id is None:
            raise ValueError("Registration identity has not been established")
        credential = Credential(
            attempt.credential_id,
            attempt.subject.issuer,
            attempt.subject.subject,
            self.service_id,
            attempt.profile,
            attempt.public_key,
        )
        await self.enrollments.save_credential(credential)
        return credential
