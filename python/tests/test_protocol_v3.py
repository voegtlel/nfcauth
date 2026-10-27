from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from nfc_authenticator.backend import ReferenceBackend
from nfc_authenticator.certificate_auth import (
    CertificateSessionSigner,
    SessionAuthenticationContext,
    transcript_hash,
    verify_signature,
)
from nfc_authenticator.protocol_crypto import (
    PURPOSE_SESSION_AUTHENTICATION,
    ProtocolCryptoError,
    SessionInitiator,
    accept_session,
)
from nfc_authenticator.service_crypto import (
    authentication_signature_payload,
    decrypt_authentication_request,
    decrypt_key_commit,
    decrypt_registration_response,
    derive_rotated_key,
    encrypt_authentication_response,
    encrypt_key_commit_ack,
    encrypt_registration_response,
)
from nfc_authenticator.service_manifest import (
    FIELD_ALIAS,
    FIELD_AUTHENTICATION_PUBLIC_KEY,
    PROFILE_BIOMETRIC,
    ServiceIdentity,
    ServicePrivacyConfig,
    manifest_hash,
    public_key_der_b64,
)
from nfc_authenticator.storage import SQLiteStore


def privacy() -> ServicePrivacyConfig:
    return ServicePrivacyConfig(
        service_origin="https://login.example.test",
        service_id="example-service",
        service_name="Example Service",
        operator_name="Example Operator",
        privacy_policy_url="https://login.example.test/privacy",
        privacy_notice_version="3",
        requested_fields=(FIELD_ALIAS, FIELD_AUTHENTICATION_PUBLIC_KEY),
        purposes={
            FIELD_ALIAS: "Display name",
            FIELD_AUTHENTICATION_PUBLIC_KEY: "Verify authentication",
        },
        data_deletion_url_or_contact="https://login.example.test/delete",
        authentication_profile=PROFILE_BIOMETRIC,
    )


def test_provisional_session_only_allows_certificate_proof() -> None:
    initiator = SessionInitiator.create()
    accepted = accept_session(initiator.request)
    completed = initiator.complete(accepted.response)
    with pytest.raises(ProtocolCryptoError):
        completed.session.encrypt(b"secret", "registration")
    proof = completed.session.encrypt(b"proof", PURPOSE_SESSION_AUTHENTICATION)
    assert accepted.session.decrypt(proof, PURPOSE_SESSION_AUTHENTICATION) == b"proof"
    digest = b"x" * 32
    completed.session.authenticate(digest)
    accepted.session.authenticate(digest)
    encrypted = completed.session.encrypt(b"payload", "authentication")
    assert accepted.session.decrypt(encrypted, "authentication") == b"payload"
    with pytest.raises(Exception):
        accepted.session.decrypt(encrypted, "authentication")
    assert completed.session.discovery_binding == accepted.session.discovery_binding


def test_certificate_signs_the_complete_ephemeral_transcript(tmp_path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "login.example.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("login.example.test")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "key.pem"
    chain_path = tmp_path / "chain.pem"
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    chain_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    context = SessionAuthenticationContext(
        "https://login.example.test",
        "example-service",
        PROFILE_BIOMETRIC,
        "a" * 64,
        b"s" * 16,
        b"c" * 32,
        b"\x04" + b"r" * 64,
        b"\x04" + b"p" * 64,
    )
    authentication = CertificateSessionSigner(key_path, chain_path).sign(context)
    verify_signature(authentication, context)
    assert len(transcript_hash(context)) == 32
    changed = SessionAuthenticationContext(**{**context.__dict__, "service_id": "attacker"})
    with pytest.raises(Exception):
        verify_signature(authentication, changed)


def test_registration_uses_service_credential_id_and_exact_approved_fields() -> None:
    identity = ServiceIdentity(ec.generate_private_key(ec.SECP256R1()))
    manifest = identity.manifest(privacy())
    auth_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = "acct-link-7e25d6ad"
    envelope, phone_key = encrypt_registration_response(
        manifest,
        credential_id,
        "b" * 64,
        identity.encryption_private_key.public_key(),
        {
            FIELD_ALIAS: "Alice",
            FIELD_AUTHENTICATION_PUBLIC_KEY: public_key_der_b64(auth_key.public_key()),
        },
    )
    plaintext, service_key = decrypt_registration_response(
        envelope,
        manifest,
        credential_id,
        "b" * 64,
        identity.encryption_private_key,
    )
    assert service_key == phone_key
    assert plaintext["credential_id"] == credential_id
    assert set(plaintext["fields"]) == set(privacy().requested_fields)


def test_backend_rotates_after_proof_and_recovers_with_epoch_overlap(tmp_path) -> None:
    identity = ServiceIdentity(ec.generate_private_key(ec.SECP256R1()))
    config = privacy()
    manifest = identity.manifest(config)
    auth_private = ec.generate_private_key(ec.SECP256R1())
    credential_id = "credential-65d262c7"
    initial_key = bytes(range(32))
    path = tmp_path / "auth-v3.db"
    store = SQLiteStore(path)
    store.register_device(
        config.service_id,
        credential_id,
        "Alice",
        config.authentication_profile,
        public_key_der_b64(auth_private.public_key()),
        initial_key,
    )
    backend = ReferenceBackend(identity, config, store, reader_id="reader-1")
    discovery = backend.start_discovery("f" * 64)
    request = discovery["request"]
    discovery_response = {
        "protocol_version": 3,
        "service_id": config.service_id,
        "credential_id": credential_id,
        "authentication_profile": config.authentication_profile,
        "manifest_hash": request["manifest_hash"],
        "discovery_nonce": request["discovery_nonce"],
        "transport_binding": request["transport_binding"],
        "key_epochs": [0],
    }
    challenge = backend.create_challenge(discovery["id"], discovery_response)
    plaintext = decrypt_authentication_request(challenge["request"], manifest, credential_id, initial_key, 0)
    plaintext["signature"] = base64.b64encode(
        auth_private.sign(
            authentication_signature_payload(
                config.service_origin,
                config.service_id,
                credential_id,
                config.authentication_profile,
                0,
                plaintext["nonce"],
                plaintext["transport_binding"],
                manifest_hash(manifest),
            ),
            ec.ECDSA(hashes.SHA256()),
        )
    ).decode()
    proof = encrypt_authentication_response(manifest, credential_id, initial_key, 0, plaintext)
    result = backend.complete(challenge["login_id"], proof)
    rotated = derive_rotated_key(
        initial_key,
        config.service_id,
        credential_id,
        config.authentication_profile,
        0,
        plaintext["nonce"],
    )
    commit = decrypt_key_commit(result["commit"], manifest, credential_id, rotated, 1)
    assert commit["status"] == "authentication-succeeded"
    pending = store.get_device(config.service_id, credential_id)
    assert pending is not None and pending.available_epochs == (1, 0)

    # Simulate a lost ACK. A subsequent proof under epoch 1 implicitly confirms
    # that both peers committed it and permits the next rotation without drift.
    discovery2 = backend.start_discovery("e" * 64)
    request2 = discovery2["request"]
    challenge2 = backend.create_challenge(
        discovery2["id"],
        {
            "protocol_version": 3,
            "service_id": config.service_id,
            "credential_id": credential_id,
            "authentication_profile": config.authentication_profile,
            "manifest_hash": request2["manifest_hash"],
            "discovery_nonce": request2["discovery_nonce"],
            "transport_binding": request2["transport_binding"],
            "key_epochs": [1, 0],
        },
    )
    plaintext2 = decrypt_authentication_request(challenge2["request"], manifest, credential_id, rotated, 1)
    plaintext2["signature"] = base64.b64encode(
        auth_private.sign(
            authentication_signature_payload(
                config.service_origin,
                config.service_id,
                credential_id,
                config.authentication_profile,
                1,
                plaintext2["nonce"],
                plaintext2["transport_binding"],
                manifest_hash(manifest),
            ),
            ec.ECDSA(hashes.SHA256()),
        )
    ).decode()
    proof2 = encrypt_authentication_response(manifest, credential_id, rotated, 1, plaintext2)
    result2 = backend.complete(challenge2["login_id"], proof2)
    rotated2 = derive_rotated_key(
        rotated,
        config.service_id,
        credential_id,
        config.authentication_profile,
        1,
        plaintext2["nonce"],
    )
    ack = encrypt_key_commit_ack(manifest, credential_id, rotated2, 2, result2["rotation_id"])
    assert backend.confirm_rotation(result2, ack) == credential_id
    confirmed = store.get_device(config.service_id, credential_id)
    assert confirmed is not None and confirmed.available_epochs == (2,)
    # Protocol attempts are process-local; durable credentials survive restart.
    attempt = store.save_attempt(config.service_id, "reader-1", "test", {"secret": "x"}, 1)
    store.close()
    reopened = SQLiteStore(path)
    assert reopened.get_device(config.service_id, credential_id) is not None
    with pytest.raises(ValueError):
        reopened.consume_attempt(config.service_id, "reader-1", attempt, "test", 1)
    reopened.close()


def test_manifest_rejects_plain_http_and_unknown_fields() -> None:
    with pytest.raises(ValueError):
        ServicePrivacyConfig(
            **{
                **privacy().__dict__,
                "service_origin": "http://login.example.test",
            }
        )
    with pytest.raises(ValueError):
        ServicePrivacyConfig(
            **{
                **privacy().__dict__,
                "privacy_policy_url": "https://user:password@login.example.test/privacy",
            }
        )
    with pytest.raises(ValueError):
        ServicePrivacyConfig(
            **{
                **privacy().__dict__,
                "purposes": {
                    FIELD_ALIAS: "",
                    FIELD_AUTHENTICATION_PUBLIC_KEY: "Verify",
                },
            }
        )
    with pytest.raises(ValueError):
        ServicePrivacyConfig(
            **{
                **privacy().__dict__,
                "requested_fields": (FIELD_AUTHENTICATION_PUBLIC_KEY, "phone_number"),
                "purposes": {
                    FIELD_AUTHENTICATION_PUBLIC_KEY: "Verify",
                    "phone_number": "Marketing",
                },
            }
        )
