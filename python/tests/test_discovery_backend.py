import base64
import json
import secrets
import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nfc_authenticator.backend import ReferenceBackend
from nfc_authenticator.discovery import signature_payload
from nfc_authenticator.protocol_crypto import SessionInitiator, _derive_session, _encode_handshake, _parse_handshake
from nfc_authenticator.service_crypto import authentication_signature_payload
from nfc_authenticator.service_manifest import ServiceIdentity, ServicePrivacyConfig, manifest_hash
from nfc_authenticator.storage import JsonObject, SQLiteStore

Credentials = dict[str, tuple[ec.EllipticCurvePrivateKey, bytes]]
Service = tuple[ReferenceBackend, Credentials, list[int]]


@pytest.fixture
def service(tmp_path: Path) -> Iterator[Service]:
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
    db = SQLiteStore(tmp_path / "credentials.sqlite")
    credentials: Credentials = {}
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


def discovery_response(request: JsonObject, user: str = "second-user") -> JsonObject:
    return {
        "protocol_version": 2,
        "service_id": request["signed_manifest"]["manifest"]["service_id"],
        "service_user_id": user,
        "manifest_hash": manifest_hash(request["signed_manifest"]["manifest"]),
        "discovery_nonce": request["discovery_nonce"],
        "transport_binding": request["transport_binding"],
    }


def proof(
    backend: ReferenceBackend,
    challenge: JsonObject,
    credentials: Credentials,
    user: str = "second-user",
    wrong_nonce: bool = False,
    wrong_key: bool = False,
) -> JsonObject:
    key, secret = credentials[user]
    nonce = json.loads(
        AESGCM(secret).decrypt(
            base64.b64decode(challenge["request"]["iv"]),
            base64.b64decode(challenge["request"]["ciphertext"]),
            f"nfcauth-v2|authentication-request|{backend.privacy.service_id}".encode(),
        )
    )["nonce"]
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


def test_phone_selects_second_credential_and_id_alone_never_authenticates(service: Service) -> None:
    backend, credentials, _ = service
    discovery = backend.start_discovery("ab" * 32)
    challenge = backend.create_challenge(discovery["id"], discovery_response(discovery["request"]))
    assert "user_id" not in challenge and "access_token" not in challenge
    assert backend.complete(challenge["login_id"], proof(backend, challenge, credentials)) == "second-user"
    with pytest.raises(ValueError, match="consumed"):
        backend.complete(challenge["login_id"], {})


@pytest.mark.parametrize("field", ["service_id", "manifest_hash", "discovery_nonce", "transport_binding"])
def test_changed_discovery_context_is_rejected(service: Service, field: str) -> None:
    backend, _, _ = service
    discovery = backend.start_discovery("ab" * 32)
    response = discovery_response(discovery["request"])
    response[field] = "invalid"
    with pytest.raises(ValueError, match="match"):
        backend.create_challenge(discovery["id"], response)


def test_expired_and_other_reader_discovery_are_rejected(service: Service) -> None:
    backend, _, clock = service
    discovery = backend.start_discovery("ab" * 32)
    other = ReferenceBackend(backend.identity, backend.privacy, backend.store, reader_id="another-reader")
    with pytest.raises(ValueError):
        other.create_challenge(discovery["id"], discovery_response(discovery["request"]))
    clock[0] += 121
    with pytest.raises(ValueError):
        backend.create_challenge(discovery["id"], discovery_response(discovery["request"]))


@pytest.mark.parametrize("fault", ["wrong_nonce", "wrong_key", "revoked", "unknown", "empty"])
def test_credential_id_cannot_bypass_proof(service: Service, fault: str) -> None:
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
        assert isinstance(backend.store, SQLiteStore)
        backend.store.remove_registration("second-user")
    with pytest.raises((ValueError, KeyError, InvalidSignature)):
        backend.complete(challenge["login_id"], {} if fault == "empty" else response)


def test_discovery_signature_binds_service_manifest_nonce_and_fresh_transport(service: Service) -> None:
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


def test_binding_matches_phone_and_changes_on_fresh_handshake() -> None:
    initiator = SessionInitiator.create()
    id_, reader = _parse_handshake(initiator.request)
    phone_key = ec.generate_private_key(ec.SECP256R1())
    phone = _derive_session(id_, phone_key, reader, is_initiator=False)
    reader_session = initiator.complete(_encode_handshake(id_, phone_key.public_key()))
    assert phone.discovery_binding == reader_session.discovery_binding
    assert len(phone.discovery_binding) == 64


def test_credentials_survive_reopening_but_attempts_do_not(service: Service, tmp_path: Path) -> None:
    backend, credentials, _ = service
    discovery = backend.start_discovery("ab" * 32)
    assert isinstance(backend.store, SQLiteStore)
    backend.store.close()
    path = tmp_path / "credentials.sqlite"
    with SQLiteStore(path) as store:
        restarted = ReferenceBackend(backend.identity, backend.privacy, store, clock=backend.clock)
        assert store.get_device(backend.privacy.service_id, "second-user") is not None
        with pytest.raises(ValueError, match="consumed"):
            restarted.create_challenge(discovery["id"], discovery_response(discovery["request"]))
        discovery = restarted.start_discovery("ab" * 32)
        challenge = restarted.create_challenge(discovery["id"], discovery_response(discovery["request"]))
        response = proof(restarted, challenge, credentials)
    with SQLiteStore(path) as store:
        restarted = ReferenceBackend(backend.identity, backend.privacy, store, clock=backend.clock)
        with pytest.raises(ValueError, match="consumed"):
            restarted.complete(challenge["login_id"], response)


def test_failed_proof_is_consumed_in_memory(service: Service) -> None:
    backend, credentials, _ = service
    discovery = backend.start_discovery("ab" * 32)
    challenge = backend.create_challenge(discovery["id"], discovery_response(discovery["request"]))
    valid = proof(backend, challenge, credentials)
    with pytest.raises(InvalidSignature):
        backend.complete(challenge["login_id"], proof(backend, challenge, credentials, wrong_key=True))
    with pytest.raises(ValueError, match="consumed"):
        backend.complete(challenge["login_id"], valid)


def test_wrong_reader_does_not_consume_another_readers_attempt(service: Service) -> None:
    backend, _, _ = service
    discovery = backend.start_discovery("ab" * 32)
    other = ReferenceBackend(backend.identity, backend.privacy, backend.store, clock=backend.clock, reader_id="other")
    response = discovery_response(discovery["request"])
    with pytest.raises(ValueError):
        other.create_challenge(discovery["id"], response)
    assert backend.create_challenge(discovery["id"], response)["login_id"]


def test_only_one_thread_can_consume_an_attempt(tmp_path: Path) -> None:
    path = tmp_path / "shared.sqlite"
    with SQLiteStore(path) as store:
        attempt = store.save_attempt("service", "reader", "discovery", {"test": True}, 1000)
        barrier = Barrier(2)

        def consume(_: int) -> str:
            barrier.wait(timeout=5)
            try:
                store.consume_attempt("service", "reader", attempt, "discovery", 1001)
                return "accepted"
            except ValueError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as workers:
            assert sorted(workers.map(consume, range(2))) == ["accepted", "rejected"]


def test_pending_limit_and_expiry_are_scoped_in_memory(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "shared.sqlite") as store:
        for _ in range(256):
            store.save_attempt("service", "reader", "discovery", {}, 1000)
        with pytest.raises(ValueError, match="Too many"):
            store.save_attempt("service", "reader", "discovery", {}, 1001)
        assert store.save_attempt("service", "reader", "discovery", {}, 1120)
        assert store.save_attempt("service", "different-reader", "discovery", {}, 1001)


def test_attempt_table_is_removed_and_never_recreated(tmp_path: Path) -> None:
    path = tmp_path / "old.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE authentication_attempts_v2 (id TEXT PRIMARY KEY)")
        connection.execute(
            "CREATE INDEX authentication_attempt_scope_v2 ON authentication_attempts_v2(id)"
        )
    with SQLiteStore(path) as store:
        store.save_attempt("service", "reader", "discovery", {"test": True}, 1000)
        persisted = store.conn.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'authentication_attempt%'")
        assert persisted.fetchall() == []
        assert len(store.attempts) == 1


def test_other_service_cannot_consume_attempt(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "shared.sqlite") as store:
        attempt = store.save_attempt("service", "reader", "discovery", {"test": True}, 1000)
        with pytest.raises(ValueError):
            store.consume_attempt("different-service", "reader", attempt, "discovery", 1001)
        assert store.consume_attempt("service", "reader", attempt, "discovery", 1001) == {"test": True}
