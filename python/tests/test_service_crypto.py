import base64
import json
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from nfc_authenticator.service_crypto import (
    authentication_signature_payload,
    decrypt_authentication_response,
    decrypt_registration_response,
    encrypt_authentication_request,
    encrypt_registration_acknowledgement,
)
from nfc_authenticator.service_manifest import (
    FIELD_ALIAS,
    FIELD_AUTHENTICATION_PUBLIC_KEY,
    FIELD_SERVICE_USER_ID,
    ServiceIdentity,
    ServicePrivacyConfig,
    manifest_hash,
)


def create_manifest(identity):
    return identity.signed_manifest(
        ServicePrivacyConfig(
            service_id="example.service",
            service_name="Example Service",
            operator_name="Example Operator",
            privacy_policy_url="https://example.com/privacy",
            privacy_notice_version="2026-07",
            requested_fields=(
                FIELD_ALIAS,
                FIELD_SERVICE_USER_ID,
                FIELD_AUTHENTICATION_PUBLIC_KEY,
            ),
            purposes={
                FIELD_ALIAS: "Display a familiar name.",
                FIELD_SERVICE_USER_ID: "Identify this registration.",
                FIELD_AUTHENTICATION_PUBLIC_KEY: "Verify signatures.",
            },
            data_deletion_url_or_contact="mailto:privacy@example.com",
        ),
        registration_nonce="ab" * 16,
    )


def phone_registration_envelope(signed_manifest, service_public_key):
    manifest = signed_manifest["manifest"]
    current_manifest_hash = manifest_hash(manifest)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral.exchange(ec.ECDH(), service_public_key)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(current_manifest_hash),
        info=f"nfcauth-v2-session|{manifest['service_id']}".encode(),
    ).derive(shared_secret)
    plaintext = {
        "protocol_version": 2,
        "service_id": manifest["service_id"],
        "registration_nonce": manifest["registration_nonce"],
        "fields": {
            FIELD_ALIAS: "Alice",
            FIELD_SERVICE_USER_ID: "service-only-id",
            FIELD_AUTHENTICATION_PUBLIC_KEY: "public-key",
        },
    }
    iv = secrets.token_bytes(12)
    aad = (
        f"nfcauth-v2|registration-response|"
        f"{manifest['service_id']}|{current_manifest_hash}"
    ).encode()
    ciphertext = AESGCM(session_key).encrypt(
        iv,
        json.dumps(plaintext, separators=(",", ":")).encode(),
        aad,
    )
    return {
        "protocol_version": 2,
        "service_id": manifest["service_id"],
        "manifest_hash": current_manifest_hash,
        "phone_ephemeral_public_key": base64.b64encode(
            ephemeral.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }, session_key


def test_registration_is_encrypted_to_service_and_acknowledged(tmp_path):
    identity = ServiceIdentity.load_or_create(tmp_path / "identity.json")
    signed_manifest = create_manifest(identity)
    envelope, phone_session_key = phone_registration_envelope(
        signed_manifest,
        identity.encryption_private_key.public_key(),
    )

    plaintext, reader_session_key = decrypt_registration_response(
        envelope,
        signed_manifest,
        identity.encryption_private_key,
    )
    assert plaintext["fields"][FIELD_ALIAS] == "Alice"
    assert reader_session_key == phone_session_key

    acknowledgement = encrypt_registration_acknowledgement(
        "example.service",
        "ab" * 16,
        manifest_hash(signed_manifest["manifest"]),
        reader_session_key,
    )
    assert b"Alice" not in json.dumps(acknowledgement).encode()


def test_authentication_request_and_response_are_authenticated(tmp_path):
    identity = ServiceIdentity.load_or_create(tmp_path / "identity.json")
    session_key = secrets.token_bytes(32)
    envelope, request = encrypt_authentication_request(
        "example.service",
        identity.encryption_private_key.public_key(),
        session_key,
        "nonce-1",
        "biometric",
    )
    assert b"nonce-1" not in json.dumps(envelope).encode()

    iv = secrets.token_bytes(12)
    response = {
        "protocol_version": 2,
        "service_id": "example.service",
        "nonce": "nonce-1",
        "user_id": "service-only-id",
        "signature": "signature",
    }
    ciphertext = AESGCM(session_key).encrypt(
        iv,
        json.dumps(response, separators=(",", ":")).encode(),
        b"nfcauth-v2|authentication-response|example.service",
    )
    encrypted_response = {
        "protocol_version": 2,
        "service_id": "example.service",
        "encryption_key_fingerprint": envelope["encryption_key_fingerprint"],
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    assert (
        decrypt_authentication_response(
            encrypted_response,
            "example.service",
            identity.encryption_private_key.public_key(),
            session_key,
        )
        == response
    )
    assert authentication_signature_payload(
        "example.service",
        request["nonce"],
        request["auth"],
        response["user_id"],
    )
