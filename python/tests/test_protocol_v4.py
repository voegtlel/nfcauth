from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from nfc_authenticator.bridge.app import create_app
from nfc_authenticator.bridge.config import load_terminals
from nfc_authenticator.bridge.issuers import LocalJwtTokenIssuer
from nfc_authenticator.bridge.models import Credential, Subject, TerminalIdentity
from nfc_authenticator.bridge.registration import REGISTRATION_DOMAIN, RegistrationAttempts, RegistrationCoordinator
from nfc_authenticator.bridge.renewal import RenewalAttempts, RenewalCoordinator
from nfc_authenticator.bridge.security import CertificateRequestSigner, verify_signed_request
from nfc_authenticator.bridge.service import BridgeService
from nfc_authenticator.bridge.stores import MemoryEnrollmentStore, MemoryTransactionStore
from nfc_authenticator.bridge.terminal_auth import OidcTerminalAuthenticator, TerminalAuthenticationError
from nfc_authenticator.protocol_v4 import AuthorizationAssertion, SessionBinding, public_key_der_b64
from nfc_authenticator.terminal import validate_protected_api_url


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def session(seed: bytes = b"a") -> SessionBinding:
    return SessionBinding(b64(seed * 16), b64(seed * 32), b64(b"\x04" + seed * 64), b64(b"\x04" + bytes([seed[0] + 1]) * 64))


def certificate_signer(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "auth.example.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("auth.example.test")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "request-key.pem"
    chain_path = tmp_path / "request-chain.pem"
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    chain_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return CertificateRequestSigner(key_path, chain_path)


@pytest.mark.asyncio
async def test_two_tap_authorization_issues_one_ten_minute_token(tmp_path) -> None:
    def clock() -> int:
        return 1_800_000_000

    phone_key = ec.generate_private_key(ec.SECP256R1())
    token_key = ec.generate_private_key(ec.SECP256R1())
    token_private = token_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    enrollments = MemoryEnrollmentStore()
    transactions = MemoryTransactionStore()
    signer = certificate_signer(tmp_path)
    terminal = TerminalIdentity("terminal-1", frozenset({"inventory"}), frozenset({"inventory.read"}))
    credential = Credential(
        "credential-1",
        "https://id.example.test",
        "account-7",
        "example",
        "biometric",
        public_key_der_b64(phone_key.public_key()),
        int(clock()) - 86_400,
        int(clock()) + 86_400,
    )
    await enrollments.save_credential(credential)
    service = BridgeService(
        "example",
        "https://auth.example.test",
        "a" * 64,
        transactions,
        enrollments,
        signer,
        LocalJwtTokenIssuer("https://auth.example.test", token_private),
        clock=clock,
    )

    transaction = await service.create_transaction(
        terminal, "inventory", ("inventory.read",), "Load the current inventory", "biometric"
    )
    signed = await service.bind_session(transaction.transaction_id, terminal, session(b"a"))
    request = (await transactions.get(transaction.transaction_id)).request
    assert request is not None
    verify_signed_request(signed, request)

    # The user may move the phone away here and approve from the app. The
    # assertion is kept only in memory until the second tap.
    assertion = AuthorizationAssertion(
        transaction.transaction_id,
        request.request_hash,
        "example",
        terminal.terminal_id,
        credential.credential_id,
        "biometric",
        1,
        int(clock()),
    ).with_signature(phone_key)

    delivery = await service.bind_delivery_session(transaction.transaction_id, terminal, session(b"c"))
    assert delivery["message_type"] == "assertion_delivery"
    token, registration_expires_at = await service.complete(transaction.transaction_id, terminal, assertion)
    assert token.expires_in == 600
    assert registration_expires_at == int(clock()) + 548 * 86_400
    renewed = await enrollments.get_credential(credential.credential_id)
    assert renewed is not None
    assert renewed.last_authenticated_at == int(clock())
    claims = jwt.decode(token.access_token, token_key.public_key(), algorithms=["ES256"], audience="inventory")
    assert claims["sub"] == "account-7"
    assert claims["scope"] == "inventory.read"
    assert claims["act"]["sub"] == "terminal-1"
    assert claims["amr"] == ["nfc", "biometric"]
    assert claims["nfcauth_assurance_source"] == "authenticator-asserted"
    assert "hwk" not in claims["amr"]

    with pytest.raises(ValueError):
        await service.complete(transaction.transaction_id, terminal, assertion)


@pytest.mark.asyncio
async def test_terminal_cannot_escalate_scopes(tmp_path) -> None:
    key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    service = BridgeService(
        "example",
        "https://auth.example.test",
        "a" * 64,
        MemoryTransactionStore(),
        MemoryEnrollmentStore(),
        certificate_signer(tmp_path),
        LocalJwtTokenIssuer("https://auth.example.test", key),
    )
    terminal = TerminalIdentity("terminal-1", frozenset({"api"}), frozenset({"read"}))
    with pytest.raises(PermissionError):
        await service.create_transaction(terminal, "api", ("read", "admin"), "Escalate", "possession")


class FakeTerminalAuthenticator:
    def __init__(self, terminal: TerminalIdentity) -> None:
        self.terminal = terminal

    async def authenticate(self, access_token: str) -> TerminalIdentity:
        if access_token != "valid-terminal-token":
            raise TerminalAuthenticationError("invalid")
        return self.terminal

    async def close(self) -> None:
        pass


def test_bridge_api_authenticates_terminal_and_signs_manifest(tmp_path) -> None:
    token_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    signer = certificate_signer(tmp_path)
    terminal = TerminalIdentity("terminal-1", frozenset({"api"}), frozenset({"read"}))
    manifest = {"protocol_version": 4, "service_id": "example"}
    service = BridgeService(
        "example",
        "https://auth.example.test",
        "a" * 64,
        MemoryTransactionStore(),
        MemoryEnrollmentStore(),
        signer,
        LocalJwtTokenIssuer("https://auth.example.test", token_key),
    )
    client = TestClient(
        create_app(
            service=service,
            terminal_authenticator=FakeTerminalAuthenticator(terminal),
            manifest=manifest,
        )
    )
    signed_manifest = client.get("/.well-known/nfc-authenticator")
    assert signed_manifest.status_code == 200
    assert signed_manifest.json()["manifest"] == manifest
    unauthorized = client.post(
        "/v1/transactions",
        json={"audience": "api", "scopes": ["read"], "action": "Read", "assurance": "possession"},
    )
    assert unauthorized.status_code == 401, unauthorized.text
    assert unauthorized.headers["www-authenticate"] == "Bearer"
    created = client.post(
        "/v1/transactions",
        headers={"Authorization": "Bearer valid-terminal-token"},
        json={"audience": "api", "scopes": ["read"], "action": "Read", "assurance": "possession"},
    )
    assert created.status_code == 201
    assert created.json()["transaction_id"]


@pytest.mark.asyncio
async def test_oidc_terminal_authenticator_validates_token_and_derives_subject_identity() -> None:
    terminal = TerminalIdentity("terminal-subject-1", frozenset({"api"}), frozenset({"read"}))
    signing_key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(signing_key.public_key()))
    jwk.update({"kid": "terminal-key-1", "alg": "ES256", "use": "sig"})

    async def jwks(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://id.example.test/jwks/"
        return httpx.Response(200, json={"keys": [jwk]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(jwks))
    authenticator = OidcTerminalAuthenticator(
        issuer="https://id.example.test/application/o/terminal/",
        audience="nfcauth-bridge",
        jwks_uri="https://id.example.test/jwks/",
        terminals={terminal.terminal_id: terminal},
        client=client,
    )
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://id.example.test/application/o/terminal/",
            "sub": terminal.terminal_id,
            "aud": "nfcauth-bridge",
            "scope": "nfcauth:terminal",
            "iat": now,
            "exp": now + 300,
        },
        signing_key,
        algorithm="ES256",
        headers={"kid": "terminal-key-1"},
    )
    assert await authenticator.authenticate(token) == terminal

    wrong_scope = jwt.encode(
        {
            "iss": "https://id.example.test/application/o/terminal/",
            "sub": terminal.terminal_id,
            "aud": "nfcauth-bridge",
            "scope": "unrelated",
            "iat": now,
            "exp": now + 300,
        },
        signing_key,
        algorithm="ES256",
        headers={"kid": "terminal-key-1"},
    )
    with pytest.raises(TerminalAuthenticationError):
        await authenticator.authenticate(wrong_scope)

    overlong = jwt.encode(
        {
            "iss": "https://id.example.test/application/o/terminal/",
            "sub": terminal.terminal_id,
            "aud": "nfcauth-bridge",
            "scope": "nfcauth:terminal",
            "iat": now,
            "exp": now + 601,
        },
        signing_key,
        algorithm="ES256",
        headers={"kid": "terminal-key-1"},
    )
    with pytest.raises(TerminalAuthenticationError):
        await authenticator.authenticate(overlong)
    await client.aclose()


def test_terminal_registry_rejects_legacy_certificate_identity_and_duplicate_subjects(tmp_path) -> None:
    path = tmp_path / "terminals.json"
    path.write_text(
        json.dumps(
            {
                "terminals": [
                    {
                        "subject": "terminal-subject-1",
                        "certificate_fingerprint": "f" * 64,
                        "allowed_audiences": ["api"],
                        "allowed_scopes": ["read"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_terminals(path)

    entry = {
        "subject": "terminal-subject-1",
        "allowed_audiences": ["api"],
        "allowed_scopes": ["read"],
    }
    path.write_text(json.dumps({"terminals": [entry, entry]}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_terminals(path)


class FakeOidc:
    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        return f"https://id.example.test/authorize?state={state}&nonce={nonce}&code_challenge={code_challenge}"

    async def complete(self, code: str, expected_nonce: str, code_verifier: str) -> Subject:
        assert code == "valid-code"
        assert expected_nonce and code_verifier
        return Subject("https://id.example.test", "provider-account-42")


@pytest.mark.asyncio
async def test_provider_assigns_credential_id_and_completion_requires_phone_key() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    enrollments = MemoryEnrollmentStore()
    attempts = RegistrationAttempts()
    now = 1_800_000_000
    coordinator = RegistrationCoordinator(
        "example",
        attempts,
        enrollments,
        FakeOidc(),
        credential_lifetime_seconds=548 * 86_400,
        clock=lambda: now,
    )
    attempt, url = await coordinator.start("possession", public_key_der_b64(key.public_key()))
    assert "code_challenge=" in url
    completed = await coordinator.callback(attempt.state, "valid-code")
    assert completed.credential_id
    assert completed.completion_code
    payload = REGISTRATION_DOMAIN + completed.registration_id.encode() + b"\x00" + completed.completion_code.encode()
    signature = base64.b64encode(key.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()
    credential = await coordinator.complete(completed.registration_id, completed.completion_code, signature)
    assert credential.credential_id == completed.credential_id
    assert credential.subject == "provider-account-42"
    assert credential.registered_at == now
    assert credential.expires_at == now + 548 * 86_400
    assert await enrollments.get_credential(credential.credential_id) == credential


@pytest.mark.asyncio
async def test_manual_renewal_uses_existing_key_and_is_one_use() -> None:
    now = 1_800_000_000
    key = ec.generate_private_key(ec.SECP256R1())
    enrollments = MemoryEnrollmentStore()
    credential = Credential(
        "credential-123456",
        "https://id.example.test",
        "account-7",
        "example",
        "possession",
        public_key_der_b64(key.public_key()),
        now - 86_400,
        now + 86_400,
    )
    await enrollments.save_credential(credential)
    renewals = RenewalCoordinator(
        "example",
        RenewalAttempts(clock=lambda: now),
        enrollments,
        credential_lifetime_seconds=548 * 86_400,
        clock=lambda: now,
    )

    attempt = await renewals.start(credential.credential_id)
    signature = base64.b64encode(key.sign(attempt.payload(), ec.ECDSA(hashes.SHA256()))).decode()
    renewed = await renewals.complete(attempt.renewal_id, signature)

    assert renewed.expires_at == now + 548 * 86_400
    assert renewed.last_renewed_at == now
    assert renewed.last_authenticated_at is None
    with pytest.raises(ValueError):
        await renewals.complete(attempt.renewal_id, signature)


@pytest.mark.asyncio
async def test_expired_registration_cannot_renew_and_is_purged_after_grace() -> None:
    now = 1_800_000_000
    key = ec.generate_private_key(ec.SECP256R1())
    enrollments = MemoryEnrollmentStore()
    credential = Credential(
        "credential-expired",
        "https://id.example.test",
        "account-7",
        "example",
        "possession",
        public_key_der_b64(key.public_key()),
        now - 600,
        now - 300,
    )
    await enrollments.save_credential(credential)
    renewals = RenewalCoordinator(
        "example",
        RenewalAttempts(clock=lambda: now),
        enrollments,
        credential_lifetime_seconds=548 * 86_400,
        clock=lambda: now,
    )

    with pytest.raises(ValueError):
        await renewals.start(credential.credential_id)
    assert await enrollments.purge_expired_credentials(now - 301) == 0
    assert await enrollments.purge_expired_credentials(now - 300) == 1
    assert await enrollments.get_credential(credential.credential_id) is None


def test_bearer_destination_requires_secure_transport_or_exact_exception() -> None:
    assert validate_protected_api_url("https://inventory.example/api") == "https://inventory.example/api"
    assert validate_protected_api_url("http://127.0.0.1:8080/api") == "http://127.0.0.1:8080/api"
    with pytest.raises(ValueError):
        validate_protected_api_url("http://10.0.0.8:8080/api")
    assert validate_protected_api_url(
        "http://inventory.internal:8080/api",
        allowed_insecure_origins=("http://inventory.internal:8080",),
    ) == "http://inventory.internal:8080/api"
    with pytest.raises(ValueError):
        validate_protected_api_url(
            "http://inventory.internal:9090/api",
            allowed_insecure_origins=("http://inventory.internal:8080",),
        )
