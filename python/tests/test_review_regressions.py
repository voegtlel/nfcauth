from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from nfc_authenticator.bridge.app import RegistrationStart, TransactionCreate
from nfc_authenticator.bridge.issuers import Rfc8693TokenIssuer, _public_jwk
from nfc_authenticator.bridge.limits import ResourceLimitsMiddleware
from nfc_authenticator.bridge.models import Subject, TerminalIdentity
from nfc_authenticator.bridge.registration import GenericOidcIdentityProvider, RegistrationAttempts, RegistrationCoordinator
from nfc_authenticator.bridge.stores import MemoryEnrollmentStore
from nfc_authenticator.protocol_v4 import public_key_der_b64


def signing_key():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return key, pem


@pytest.mark.asyncio
async def test_account_linking_preserves_exact_issuer() -> None:
    key, pem = signing_key()
    issuer = "https://id.example/application/o/test/"
    now = int(time.time())
    token = jwt.encode({"iss": issuer, "sub": "test", "aud": "client", "iat": now,
                        "exp": now + 60, "nonce": "nonce"}, key, algorithm="ES256", headers={"kid": "bridge-1"})
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(
        200, json={"id_token": token} if req.method == "POST" else {"keys": [_public_jwk(pem, "bridge-1")]})))
    provider = GenericOidcIdentityProvider(issuer=issuer, authorization_endpoint=issuer, token_endpoint=issuer,
                                         jwks_uri=issuer, client_id="client", client_secret="test", redirect_uri=issuer)
    with patch("nfc_authenticator.bridge.registration.httpx.AsyncClient", return_value=client):
        assert await provider.complete("code", "nonce", "verifier") == Subject(issuer, "test")


@pytest.mark.asyncio
async def test_callback_state_is_claimed_once_under_concurrency() -> None:
    oidc = AsyncMock()
    oidc.authorization_url = lambda *args: "https://id.example/authorize"
    oidc.complete.return_value = Subject("https://id.example", "test")
    coordinator = RegistrationCoordinator("example", RegistrationAttempts(), MemoryEnrollmentStore(), oidc,
                                          credential_lifetime_seconds=548 * 86400)
    key, _ = signing_key()
    attempt, _ = await coordinator.start("possession", public_key_der_b64(key.public_key()))
    results = await asyncio.gather(*(coordinator.callback(attempt.state, "code") for _ in range(20)),
                                   return_exceptions=True)
    assert sum(isinstance(result, ValueError) for result in results) == 19
    oidc.complete.assert_awaited_once()
    saved_code = attempt.completion_code
    with pytest.raises(ValueError):
        await coordinator.callback(attempt.state, "other-code")
    assert attempt.completion_code == saved_code


@pytest.mark.asyncio
async def test_failed_callback_cannot_be_retried_with_same_state() -> None:
    attempts = RegistrationAttempts()
    oidc = AsyncMock()
    oidc.authorization_url = lambda *args: "https://id.example/authorize"
    oidc.complete.side_effect = ValueError("failed")
    coordinator = RegistrationCoordinator("example", attempts, MemoryEnrollmentStore(), oidc,
                                          credential_lifetime_seconds=548 * 86400)
    key, _ = signing_key()
    attempt, _ = await coordinator.start("possession", public_key_der_b64(key.public_key()))
    for _ in range(2):
        with pytest.raises(ValueError):
            await coordinator.callback(attempt.state, "code")
    oidc.complete.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("changes,accepted", [
    ({}, True), ({"scope": "read"}, True), ({"scope": "admin"}, False),
    ({"expires_in": 0}, False), ({"expires_in": -1}, False), ({"expires_in": 601}, False),
    ({"expires_in": True}, False), ({"expires_in": "600"}, False),
    ({"token_type": "MAC"}, False), ({"token_type": None}, False), ({"access_token": ""}, False),
])
async def test_token_exchange_bounds(changes, accepted) -> None:
    _, pem = signing_key()
    value = {"access_token": "synthetic", "token_type": "Bearer", "expires_in": 600, **changes}
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=value)))
    issuer = Rfc8693TokenIssuer("https://id.example/token", "client", "test", "https://bridge.example", pem)
    with patch("nfc_authenticator.bridge.issuers.httpx.AsyncClient", return_value=client):
        call = issuer.issue(Subject("https://id.example", "test"),
                            TerminalIdentity("terminal", frozenset({"api"}), frozenset({"read"})),
                            "api", ("read",), "possession", "transaction", timedelta(minutes=10))
        if accepted:
            assert (await call).scope == "read"
        else:
            with pytest.raises(ValueError):
                await call


def test_body_and_rate_limits() -> None:
    app = FastAPI()
    app.add_middleware(ResourceLimitsMiddleware, maximum_body_bytes=8, requests_per_minute=2)
    client = TestClient(app)
    assert client.post("/", content=b"123456789").status_code == 413
    assert client.get("/").status_code == 404
    assert client.get("/").status_code == 429


def test_api_field_limits() -> None:
    with pytest.raises(ValidationError):
        RegistrationStart(profile="possession", public_key="x" * 2049)
    with pytest.raises(ValidationError):
        TransactionCreate(audience="api", scopes=["x" * 256], action="read", assurance="possession")


@pytest.mark.asyncio
async def test_streamed_body_is_bounded_without_content_length() -> None:
    downstream = AsyncMock()
    middleware = ResourceLimitsMiddleware(downstream, maximum_body_bytes=8)
    receive = AsyncMock(side_effect=[
        {"type": "http.request", "body": b"12345", "more_body": True},
        {"type": "http.request", "body": b"6789", "more_body": False},
    ])
    send = AsyncMock()
    await middleware({"type": "http", "query_string": b""}, receive, send)
    downstream.assert_not_awaited()
    assert send.call_args_list[0].args[0]["status"] == 413


@pytest.mark.asyncio
async def test_slow_body_times_out_before_endpoint() -> None:
    downstream = AsyncMock()
    middleware = ResourceLimitsMiddleware(downstream, body_timeout_seconds=0.01)

    async def receive():
        await asyncio.Event().wait()

    send = AsyncMock()
    await middleware({"type": "http", "query_string": b""}, receive, send)
    downstream.assert_not_awaited()
    assert send.call_args_list[0].args[0]["status"] == 408


@pytest.mark.asyncio
async def test_callback_cannot_resurrect_expired_attempt() -> None:
    now = 100
    attempts = RegistrationAttempts(clock=lambda: now)
    oidc = AsyncMock()
    oidc.authorization_url = lambda *args: "https://id.example/authorize"

    async def complete(*args):
        nonlocal now
        now = 401
        return Subject("https://id.example", "test")

    oidc.complete.side_effect = complete
    coordinator = RegistrationCoordinator("example", attempts, MemoryEnrollmentStore(), oidc,
                                          credential_lifetime_seconds=548 * 86400, clock=lambda: now)
    key, _ = signing_key()
    attempt, _ = await coordinator.start("possession", public_key_der_b64(key.public_key()))
    with pytest.raises(ValueError, match="expired"):
        await coordinator.callback(attempt.state, "code")
