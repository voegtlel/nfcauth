from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from nfc_authenticator.bridge.app import create_app
from nfc_authenticator.bridge.issuers import LocalJwtTokenIssuer
from nfc_authenticator.bridge.models import Credential, Subject, TerminalIdentity
from nfc_authenticator.bridge.registration import REGISTRATION_DOMAIN, RegistrationAttempts, RegistrationCoordinator
from nfc_authenticator.bridge.security import CertificateRequestSigner, verify_signed_request
from nfc_authenticator.bridge.service import BridgeService
from nfc_authenticator.bridge.stores import MemoryEnrollmentStore, MemoryTransactionStore
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
    terminal = TerminalIdentity("terminal-1", "f" * 64, frozenset({"inventory"}), frozenset({"inventory.read"}))
    credential = Credential(
        "credential-1", "https://id.example.test", "account-7", "example", "biometric", public_key_der_b64(phone_key.public_key())
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
    token = await service.complete(transaction.transaction_id, terminal, assertion)
    assert token.expires_in == 600
    claims = jwt.decode(token.access_token, token_key.public_key(), algorithms=["ES256"], audience="inventory")
    assert claims["sub"] == "account-7"
    assert claims["scope"] == "inventory.read"
    assert claims["act"]["sub"] == "terminal-1"

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
    terminal = TerminalIdentity("terminal-1", "f" * 64, frozenset({"api"}), frozenset({"read"}))
    with pytest.raises(PermissionError):
        await service.create_transaction(terminal, "api", ("read", "admin"), "Escalate", "possession")


def test_bridge_api_authenticates_terminal_and_signs_manifest(tmp_path) -> None:
    token_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    signer = certificate_signer(tmp_path)
    terminal = TerminalIdentity("terminal-1", "f" * 64, frozenset({"api"}), frozenset({"read"}))
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
    client = TestClient(create_app(service=service, terminals={terminal.terminal_id: terminal}, manifest=manifest))
    signed_manifest = client.get("/.well-known/nfc-authenticator")
    assert signed_manifest.status_code == 200
    assert signed_manifest.json()["manifest"] == manifest
    unauthorized = client.post(
        "/v1/transactions",
        json={"audience": "api", "scopes": ["read"], "action": "Read", "assurance": "possession"},
    )
    assert unauthorized.status_code == 422
    created = client.post(
        "/v1/transactions",
        headers={
            "X-NFCAuth-Terminal-ID": terminal.terminal_id,
            "X-NFCAuth-Terminal-Cert-SHA256": terminal.key_fingerprint,
        },
        json={"audience": "api", "scopes": ["read"], "action": "Read", "assurance": "possession"},
    )
    assert created.status_code == 201
    assert created.json()["transaction_id"]


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
    coordinator = RegistrationCoordinator("example", attempts, enrollments, FakeOidc())
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
    assert await enrollments.get_credential(credential.credential_id) == credential


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
