from __future__ import annotations

import base64
import time
from datetime import timedelta

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .models import IssuedToken, Subject, TerminalIdentity


class LocalJwtTokenIssuer:
    def __init__(self, issuer: str, private_key_pem: bytes, key_id: str = "bridge-1") -> None:
        self.issuer = issuer.rstrip("/")
        self.private_key = private_key_pem
        self.key_id = key_id

    def jwks(self) -> dict:
        return {"keys": [_public_jwk(self.private_key, self.key_id)]}

    async def issue(
        self,
        subject: Subject,
        terminal: TerminalIdentity,
        audience: str,
        scopes: tuple[str, ...],
        assurance: str,
        transaction_id: str,
        lifetime: timedelta,
    ) -> IssuedToken:
        seconds = min(600, max(1, int(lifetime.total_seconds())))
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": subject.subject,
            "aud": audience,
            "scope": " ".join(scopes),
            "azp": terminal.terminal_id,
            "act": {"sub": terminal.terminal_id},
            "amr": ["nfc", assurance],
            "nfcauth_assurance_source": "authenticator-asserted",
            "txn": transaction_id,
            "iat": now,
            "nbf": now,
            "exp": now + seconds,
        }
        token = jwt.encode(claims, self.private_key, algorithm="ES256", headers={"kid": self.key_id})
        return IssuedToken(token, "Bearer", seconds, claims["scope"])


class Rfc8693TokenIssuer:
    """Generic token-exchange adapter, also used by the optional Authentik integration."""

    def __init__(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        assertion_issuer: str,
        assertion_private_key_pem: bytes,
        *,
        timeout_seconds: float = 5.0,
        key_id: str = "bridge-federation-1",
    ) -> None:
        if not token_endpoint.startswith("https://"):
            raise ValueError("Token endpoint must use HTTPS")
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.assertion_issuer = assertion_issuer
        self.assertion_private_key_pem = assertion_private_key_pem
        self.timeout_seconds = timeout_seconds
        self.key_id = key_id

    def jwks(self) -> dict:
        return {"keys": [_public_jwk(self.assertion_private_key_pem, self.key_id)]}

    async def issue(
        self,
        subject: Subject,
        terminal: TerminalIdentity,
        audience: str,
        scopes: tuple[str, ...],
        assurance: str,
        transaction_id: str,
        lifetime: timedelta,
    ) -> IssuedToken:
        now = int(time.time())
        subject_token = jwt.encode(
            {
                "iss": self.assertion_issuer,
                "sub": subject.subject,
                "aud": self.token_endpoint,
                "iat": now,
                "nbf": now,
                "exp": now + 60,
                "jti": transaction_id,
                "amr": ["nfc", assurance],
                "nfcauth_assurance_source": "authenticator-asserted",
                "act": {"sub": terminal.terminal_id},
            },
            self.assertion_private_key_pem,
            algorithm="ES256",
            headers={"kid": self.key_id},
        )
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "audience": audience,
            "scope": " ".join(scopes),
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                self.token_endpoint,
                data=data,
                auth=(self.client_id, self.client_secret),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            value = response.json()
        expires_in = int(value["expires_in"])
        if expires_in > 600:
            raise ValueError("Token exchange returned a token valid for more than ten minutes")
        return IssuedToken(value["access_token"], value.get("token_type", "Bearer"), expires_in, value.get("scope", ""))


AuthentikTokenIssuer = Rfc8693TokenIssuer


def _public_jwk(private_key_pem: bytes, key_id: str) -> dict:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise TypeError("Token and federation signing keys must be P-256")
    numbers = key.public_key().public_numbers()

    def encode(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()

    return {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": key_id,
        "x": encode(numbers.x),
        "y": encode(numbers.y),
    }
