"""Signed privacy manifest and long-term service identity for NFC Auth v2."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import secrets
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


PROTOCOL_VERSION = 2
FIELD_ALIAS = "alias"
FIELD_SERVICE_USER_ID = "service_user_id"
FIELD_AUTHENTICATION_PUBLIC_KEY = "authentication_public_key"


@dataclass(frozen=True)
class ServicePrivacyConfig:
    service_id: str
    service_name: str
    operator_name: str
    privacy_policy_url: str
    privacy_notice_version: str
    requested_fields: tuple[str, ...]
    purposes: dict[str, str]
    data_deletion_url_or_contact: str
    privacy_notice_material_change: bool = False


@dataclass(frozen=True)
class ServiceIdentity:
    signing_private_key: ec.EllipticCurvePrivateKey
    encryption_private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def load_or_create(cls, path: str | Path) -> "ServiceIdentity":
        identity_path = Path(path)
        if identity_path.exists():
            document = json.loads(identity_path.read_text(encoding="utf-8"))
            return cls(
                signing_private_key=_load_private_key(document["signing_private_key"]),
                encryption_private_key=_load_private_key(document["encryption_private_key"]),
            )

        identity = cls(
            signing_private_key=ec.generate_private_key(ec.SECP256R1()),
            encryption_private_key=ec.generate_private_key(ec.SECP256R1()),
        )
        document = {
            "signing_private_key": _private_key_pem(identity.signing_private_key),
            "encryption_private_key": _private_key_pem(identity.encryption_private_key),
        }
        identity_path.parent.mkdir(parents=True, exist_ok=True)
        identity_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        identity_path.chmod(0o600)
        return identity

    def signed_manifest(
        self,
        config: ServicePrivacyConfig,
        registration_nonce: str | None = None,
    ) -> dict:
        manifest = {
            "service_id": config.service_id,
            "service_name": config.service_name,
            "operator_name": config.operator_name,
            "privacy_policy_url": config.privacy_policy_url,
            "privacy_notice_version": config.privacy_notice_version,
            "requested_fields": list(config.requested_fields),
            "purposes": config.purposes,
            "data_deletion_url_or_contact": config.data_deletion_url_or_contact,
            "encryption_public_key": _public_key_der_b64(
                self.encryption_private_key.public_key()
            ),
            "registration_nonce": registration_nonce or secrets.token_hex(16),
            "privacy_notice_material_change": config.privacy_notice_material_change,
        }
        signature = self.signing_private_key.sign(
            canonical_manifest_bytes(manifest),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "protocol_version": PROTOCOL_VERSION,
            "manifest": manifest,
            "manifest_signing_public_key": _public_key_der_b64(
                self.signing_private_key.public_key()
            ),
            "manifest_signature": base64.b64encode(signature).decode("ascii"),
        }


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """Canonical binary encoding shared with Android ServiceManifestParser."""

    requested_fields = sorted(manifest["requested_fields"])
    values = [
        manifest["service_id"],
        manifest["service_name"],
        manifest["operator_name"],
        manifest["privacy_policy_url"],
        manifest["privacy_notice_version"],
    ]
    output = bytearray()
    for value in values:
        output.extend(_encode_string(value))
    output.extend(struct.pack(">I", len(requested_fields)))
    for field in requested_fields:
        output.extend(_encode_string(field))
    output.extend(struct.pack(">I", len(requested_fields)))
    for field in requested_fields:
        output.extend(_encode_string(field))
        output.extend(_encode_string(manifest["purposes"][field]))
    output.extend(_encode_string(manifest["data_deletion_url_or_contact"]))
    output.extend(_encode_string(manifest["encryption_public_key"]))
    output.extend(_encode_string(manifest["registration_nonce"]))
    output.append(1 if manifest.get("privacy_notice_material_change", False) else 0)
    return bytes(output)


def manifest_hash(manifest: dict) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonical_manifest_bytes(manifest))
    return digest.finalize().hex()


def public_key_fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return digest.finalize().hex()


def _encode_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def _public_key_der_b64(public_key: ec.EllipticCurvePublicKey) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(encoded).decode("ascii")


def _private_key_pem(private_key: ec.EllipticCurvePrivateKey) -> str:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _load_private_key(encoded: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(encoded.encode("ascii"), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("Service identity key must be a P-256 private key")
    return key
