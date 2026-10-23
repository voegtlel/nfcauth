import base64
import json
import secrets

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nfc_authenticator.backend import ReferenceBackend
from nfc_authenticator.discovery import signature_payload
from nfc_authenticator.nfc_reader import AuthDatabase
from nfc_authenticator.protocol_crypto import SessionInitiator, _derive_session, _encode_handshake, _parse_handshake
from nfc_authenticator.service_crypto import authentication_signature_payload
from nfc_authenticator.service_manifest import ServiceIdentity, ServicePrivacyConfig, manifest_hash


@pytest.fixture
def service(tmp_path):
    identity = ServiceIdentity.load_or_create(tmp_path / "identity.json")
    privacy = ServicePrivacyConfig(
        "test.service",
        "Test",
        "Operator",
        "https://example.test/privacy",
        "1",
        ("service_user_id", "authentication_public_key"),
        {"service_user_id": "Identify", "authentication_public_key": "Verify"},
        "test@example.test",
    )
    db = AuthDatabase(tmp_path / "credentials.sqlite")
    credentials = {}
    for user in ("first-user", "second-user"):
        key = ec.generate_private_key(ec.SECP256R1())
        secret = secrets.token_bytes(32)
        public = base64.b64encode(
            key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode()
        db.register_device(privacy.service_id, user, None, public, secret)
        credentials[user] = (key, secret)
    clock = [1000]
    backend = ReferenceBackend(identity, privacy, db, clock=lambda: clock[0])
    try:
        yield backend, credentials, clock
    finally:
        db.close()


def discovery_response(request, user="second-user"):
    return {
        "protocol_version": 2,
        "service_id": request["signed_manifest"]["manifest"]["service_id"],
        "service_user_id": user,
        "manifest_hash": manifest_hash(request["signed_manifest"]["manifest"]),
        "discovery_nonce": request["discovery_nonce"],
        "transport_binding": request["transport_binding"],
    }


def proof(backend, challenge, credentials, user="second-user", wrong_nonce=False, wrong_key=False):
    key, secret = credentials[user]
    nonce = backend.attempts[challenge["login_id"]][2]["nonce"]
    if wrong_nonce:
        nonce = "wrong"
    if wrong_key:
        key = ec.generate_private_key(ec.SECP256R1())
    signature = key.sign(
        authentication_signature_payload(backend.privacy.service_id, nonce, "biometric", user),
        ec.ECDSA(hashes.SHA256()),
    )
    payload = {
        "protocol_version": 2,
        "service_id": backend.privacy.service_id,
        "user_id": user,
        "nonce": nonce,
        "signature": base64.b64encode(signature).decode(),
    }
    iv = secrets.token_bytes(12)
    encrypted = AESGCM(secret).encrypt(
        iv, json.dumps(payload).encode(), f"nfcauth-v2|authentication-response|{backend.privacy.service_id}".encode()
    )
    return {
        **challenge["request"],
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(encrypted).decode(),
    }


def test_phone_selects_second_credential_and_id_alone_never_authenticates(service):
    backend, credentials, _ = service
    discovery = backend.start_discovery("ab" * 32)
    challenge = backend.create_challenge(discovery["id"], discovery_response(discovery["request"]))
    assert "user_id" not in challenge and "access_token" not in challenge
    assert backend.complete(challenge["login_id"], proof(backend, challenge, credentials)) == "second-user"
    with pytest.raises(ValueError, match="consumed"):
        backend.complete(challenge["login_id"], {})


@pytest.mark.parametrize("field", ["service_id", "manifest_hash", "discovery_nonce", "transport_binding"])
def test_changed_discovery_context_is_rejected(service, field):
    backend, _, _ = service
    discovery = backend.start_discovery("ab" * 32)
    response = discovery_response(discovery["request"])
    response[field] = "invalid"
    with pytest.raises(ValueError, match="match"):
        backend.create_challenge(discovery["id"], response)


def test_expired_and_other_reader_discovery_are_rejected(service):
    backend, _, clock = service
    discovery = backend.start_discovery("ab" * 32)
    other = ReferenceBackend(backend.identity, backend.privacy, backend.store)
    with pytest.raises(ValueError):
        other.create_challenge(discovery["id"], discovery_response(discovery["request"]))
    clock[0] += 121
    with pytest.raises(ValueError):
        backend.create_challenge(discovery["id"], discovery_response(discovery["request"]))


@pytest.mark.parametrize("fault", ["wrong_nonce", "wrong_key", "revoked", "unknown", "empty"])
def test_credential_id_cannot_bypass_proof(service, fault):
    backend, credentials, _ = service
    discovery = backend.start_discovery("ab" * 32)
    if fault == "unknown":
        with pytest.raises(ValueError):
            backend.create_challenge(discovery["id"], discovery_response(discovery["request"], "unknown"))
        return
    challenge = backend.create_challenge(discovery["id"], discovery_response(discovery["request"]))
    response = proof(
        backend, challenge, credentials, wrong_nonce=fault == "wrong_nonce", wrong_key=fault == "wrong_key"
    )
    if fault == "revoked":
        backend.store.remove_registration("second-user")
    with pytest.raises((ValueError, KeyError, InvalidSignature)):
        backend.complete(challenge["login_id"], {} if fault == "empty" else response)


def test_discovery_signature_binds_service_manifest_nonce_and_fresh_transport(service):
    backend, _, _ = service
    discovery = backend.start_discovery("ab" * 32)["request"]
    digest = manifest_hash(discovery["signed_manifest"]["manifest"])
    signature = base64.b64decode(discovery["discovery_signature"])
    key = backend.identity.signing_private_key.public_key()
    key.verify(
        signature,
        signature_payload(backend.privacy.service_id, digest, discovery["discovery_nonce"], "ab" * 32),
        ec.ECDSA(hashes.SHA256()),
    )
    with pytest.raises(InvalidSignature):
        key.verify(
            signature,
            signature_payload(backend.privacy.service_id, digest, discovery["discovery_nonce"], "cd" * 32),
            ec.ECDSA(hashes.SHA256()),
        )


def test_binding_matches_phone_and_changes_on_fresh_handshake():
    initiator = SessionInitiator.create()
    id_, reader = _parse_handshake(initiator.request)
    phone_key = ec.generate_private_key(ec.SECP256R1())
    phone = _derive_session(id_, phone_key, reader, is_initiator=False)
    reader_session = initiator.complete(_encode_handshake(id_, phone_key.public_key()))
    assert phone.discovery_binding == reader_session.discovery_binding
    assert len(phone.discovery_binding) == 64
