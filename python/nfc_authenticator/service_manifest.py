"""Privacy manifest and service encryption identity for NFC Auth v3."""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PROTOCOL_VERSION = 3
PROFILE_BIOMETRIC = "biometric"
PROFILE_POSSESSION = "possession"
AUTHENTICATION_PROFILES = frozenset({PROFILE_BIOMETRIC, PROFILE_POSSESSION})
FIELD_ALIAS = "alias"
FIELD_AUTHENTICATION_PUBLIC_KEY = "authentication_public_key"
SUPPORTED_FIELDS = frozenset({FIELD_ALIAS, FIELD_AUTHENTICATION_PUBLIC_KEY})


@dataclass(frozen=True)
class ServicePrivacyConfig:
    service_origin: str
    service_id: str
    service_name: str
    operator_name: str
    privacy_policy_url: str
    privacy_notice_version: str
    requested_fields: tuple[str, ...]
    purposes: dict[str, str]
    data_deletion_url_or_contact: str
    authentication_profile: str
    privacy_notice_material_change: bool = False

    def __post_init__(self) -> None:
        required_text = (
            self.service_id,
            self.service_name,
            self.operator_name,
            self.privacy_notice_version,
            self.data_deletion_url_or_contact,
        )
        if any(not isinstance(value, str) or not value.strip() for value in required_text):
            raise ValueError("Manifest metadata must be nonempty text")
        origin = urlparse(self.service_origin)
        if origin.scheme != "https" or not origin.hostname or origin.username or origin.password:
            raise ValueError("service_origin must be an HTTPS origin")
        if origin.path not in ("", "/") or origin.params or origin.query or origin.fragment:
            raise ValueError("service_origin must not contain a path, query or fragment")
        policy = urlparse(self.privacy_policy_url)
        if policy.scheme != "https" or not policy.hostname or policy.username or policy.password:
            raise ValueError("privacy_policy_url must be an HTTPS URL")
        if self.authentication_profile not in AUTHENTICATION_PROFILES:
            raise ValueError("Unsupported authentication profile")
        if (
            not self.requested_fields
            or len(set(self.requested_fields)) != len(self.requested_fields)
            or set(self.requested_fields) - SUPPORTED_FIELDS
        ):
            raise ValueError("Manifest contains missing or unsupported requested fields")
        if FIELD_AUTHENTICATION_PUBLIC_KEY not in self.requested_fields:
            raise ValueError("The authentication public key is required")
        if set(self.purposes) != set(self.requested_fields):
            raise ValueError("Every requested field must have exactly one purpose")
        if any(not isinstance(value, str) or not value.strip() for value in self.purposes.values()):
            raise ValueError("Every requested field purpose must be nonempty")


@dataclass(frozen=True)
class ServiceIdentity:
    """Long-term service encryption key; certificate signing stays in the signing service."""

    encryption_private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def load_or_create(cls, path: str | Path) -> ServiceIdentity:
        identity_path = Path(path)
        if identity_path.exists():
            document = json.loads(identity_path.read_text(encoding="utf-8"))
            return cls(encryption_private_key=_load_private_key(document["encryption_private_key"]))

        identity = cls(encryption_private_key=ec.generate_private_key(ec.SECP256R1()))
        document = {"encryption_private_key": _private_key_pem(identity.encryption_private_key)}
        identity_path.parent.mkdir(parents=True, exist_ok=True)
        identity_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        identity_path.chmod(0o600)
        return identity

    def manifest(self, config: ServicePrivacyConfig) -> dict:
        return {
            "service_origin": config.service_origin.rstrip("/"),
            "service_id": config.service_id,
            "service_name": config.service_name,
            "operator_name": config.operator_name,
            "privacy_policy_url": config.privacy_policy_url,
            "privacy_notice_version": config.privacy_notice_version,
            "requested_fields": list(config.requested_fields),
            "purposes": config.purposes,
            "data_deletion_url_or_contact": config.data_deletion_url_or_contact,
            "authentication_profile": config.authentication_profile,
            "encryption_public_key": public_key_der_b64(self.encryption_private_key.public_key()),
            "privacy_notice_material_change": config.privacy_notice_material_change,
        }


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """Canonical binary encoding shared with Android ServiceManifestParser."""

    requested_fields = sorted(manifest["requested_fields"])
    values = [
        manifest["service_origin"],
        manifest["service_id"],
        manifest["service_name"],
        manifest["operator_name"],
        manifest["privacy_policy_url"],
        manifest["privacy_notice_version"],
        manifest["authentication_profile"],
    ]
    output = bytearray((PROTOCOL_VERSION,))
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


def public_key_der_b64(public_key: ec.EllipticCurvePublicKey) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(encoded).decode("ascii")


def _encode_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def _private_key_pem(private_key: ec.EllipticCurvePrivateKey) -> str:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _load_private_key(encoded: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(encoded.encode("ascii"), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise TypeError("Service encryption key must be a P-256 private key")
    return key
