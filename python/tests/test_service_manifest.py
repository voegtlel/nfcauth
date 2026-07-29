import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from nfc_authenticator.service_manifest import (
    FIELD_ALIAS,
    FIELD_AUTHENTICATION_PUBLIC_KEY,
    FIELD_SERVICE_USER_ID,
    ServiceIdentity,
    ServicePrivacyConfig,
    canonical_manifest_bytes,
)


def test_signed_manifest_verifies_and_binds_every_disclosure(tmp_path):
    identity = ServiceIdentity.load_or_create(tmp_path / "service-identity.json")
    config = ServicePrivacyConfig(
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
            FIELD_AUTHENTICATION_PUBLIC_KEY: "Verify authentication signatures.",
        },
        data_deletion_url_or_contact="mailto:privacy@example.com",
    )
    envelope = identity.signed_manifest(config, registration_nonce="ab" * 16)

    identity.signing_private_key.public_key().verify(
        base64.b64decode(envelope["manifest_signature"]),
        canonical_manifest_bytes(envelope["manifest"]),
        ec.ECDSA(hashes.SHA256()),
    )


def test_service_identity_is_stable_across_restarts(tmp_path):
    path = tmp_path / "service-identity.json"
    first = ServiceIdentity.load_or_create(path)
    second = ServiceIdentity.load_or_create(path)

    assert (
        first.signing_private_key.private_numbers()
        == second.signing_private_key.private_numbers()
    )
    assert (
        first.encryption_private_key.private_numbers()
        == second.encryption_private_key.private_numbers()
    )
