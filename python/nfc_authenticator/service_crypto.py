"""End-to-end credential encryption and crash-safe key epochs for NFC Auth v3."""

from __future__ import annotations

import base64
import json
import secrets
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .service_manifest import PROTOCOL_VERSION, manifest_hash, public_key_fingerprint


def encrypt_registration_response(
    manifest: dict,
    credential_id: str,
    registration_nonce: str,
    encryption_public_key: ec.EllipticCurvePublicKey,
    fields: dict[str, str],
) -> tuple[dict, bytes]:
    """Phone-side reference used by simulators and interoperability tests."""
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    digest = manifest_hash(manifest)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral.exchange(ec.ECDH(), encryption_public_key)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(digest),
        info=f"nfcauth-v3-credential|{service_id}|{credential_id}|{profile}".encode(),
    ).derive(shared_secret)
    plaintext = {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "credential_id": credential_id,
        "authentication_profile": profile,
        "registration_nonce": registration_nonce,
        "fields": fields,
    }
    encrypted = _encrypt_json(
        plaintext,
        session_key,
        _aad("registration-response", service_id, credential_id, profile, 0, digest),
    )
    return {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "credential_id": credential_id,
        "authentication_profile": profile,
        "key_epoch": 0,
        "manifest_hash": digest,
        "phone_ephemeral_public_key": base64.b64encode(
            ephemeral.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("ascii"),
        **encrypted,
    }, session_key


def decrypt_registration_response(
    envelope: dict,
    manifest: dict,
    credential_id: str,
    registration_nonce: str,
    encryption_private_key: ec.EllipticCurvePrivateKey,
) -> tuple[dict, bytes]:
    digest = manifest_hash(manifest)
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    _require_identity(envelope, service_id, credential_id, profile, 0)
    if envelope.get("manifest_hash") != digest:
        raise ValueError("Registration response manifest mismatch")
    phone_public_key = serialization.load_der_public_key(
        base64.b64decode(envelope["phone_ephemeral_public_key"], validate=True)
    )
    if not isinstance(phone_public_key, ec.EllipticCurvePublicKey) or not isinstance(
        phone_public_key.curve, ec.SECP256R1
    ):
        raise TypeError("Phone registration key must use P-256")
    shared_secret = encryption_private_key.exchange(ec.ECDH(), phone_public_key)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(digest),
        info=f"nfcauth-v3-credential|{service_id}|{credential_id}|{profile}".encode(),
    ).derive(shared_secret)
    plaintext = _decrypt_json(
        envelope,
        session_key,
        _aad("registration-response", service_id, credential_id, profile, 0, digest),
    )
    if (
        plaintext.get("protocol_version") != PROTOCOL_VERSION
        or plaintext.get("service_id") != service_id
        or plaintext.get("credential_id") != credential_id
        or plaintext.get("registration_nonce") != registration_nonce
        or plaintext.get("authentication_profile") != profile
    ):
        raise ValueError("Registration response challenge mismatch")
    return plaintext, session_key


def encrypt_registration_acknowledgement(
    manifest: dict,
    credential_id: str,
    registration_nonce: str,
    session_key: bytes,
) -> dict:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    digest = manifest_hash(manifest)
    encrypted = _encrypt_json(
        {
            "protocol_version": PROTOCOL_VERSION,
            "status": "registered",
            "service_id": service_id,
            "credential_id": credential_id,
            "authentication_profile": profile,
            "registration_nonce": registration_nonce,
            "key_epoch": 0,
        },
        session_key,
        _aad("registration-ack", service_id, credential_id, profile, 0, digest),
    )
    return {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "credential_id": credential_id,
        "authentication_profile": profile,
        "key_epoch": 0,
        "manifest_hash": digest,
        **encrypted,
    }


def encrypt_authentication_request(
    manifest: dict,
    credential_id: str,
    session_key: bytes,
    key_epoch: int,
    nonce: str,
    transport_binding: str,
) -> tuple[dict, dict]:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    request = {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "credential_id": credential_id,
        "authentication_profile": profile,
        "key_epoch": key_epoch,
        "nonce": nonce,
        "transport_binding": transport_binding,
        "manifest_hash": manifest_hash(manifest),
    }
    encrypted = _encrypt_json(
        request,
        session_key,
        _aad("authentication-request", service_id, credential_id, profile, key_epoch),
    )
    return {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "credential_id": credential_id,
        "authentication_profile": profile,
        "key_epoch": key_epoch,
        "encryption_key_fingerprint": public_key_fingerprint_from_manifest(manifest),
        **encrypted,
    }, request


def decrypt_authentication_request(
    envelope: dict,
    manifest: dict,
    credential_id: str,
    key: bytes,
    epoch: int,
) -> dict:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    _require_identity(envelope, service_id, credential_id, profile, epoch)
    return _decrypt_json(
        envelope,
        key,
        _aad("authentication-request", service_id, credential_id, profile, epoch),
    )


def encrypt_authentication_response(
    manifest: dict,
    credential_id: str,
    key: bytes,
    epoch: int,
    response: dict,
) -> dict:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    return {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "credential_id": credential_id,
        "authentication_profile": profile,
        "key_epoch": epoch,
        **_encrypt_json(
            response,
            key,
            _aad("authentication-response", service_id, credential_id, profile, epoch),
        ),
    }


def decrypt_authentication_response(envelope: dict, manifest: dict, credential_id: str, key: bytes, epoch: int) -> dict:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    _require_identity(envelope, service_id, credential_id, profile, epoch)
    return _decrypt_json(
        envelope,
        key,
        _aad("authentication-response", service_id, credential_id, profile, epoch),
    )


def authentication_signature_payload(
    service_origin: str,
    service_id: str,
    credential_id: str,
    authentication_profile: str,
    key_epoch: int,
    nonce: str,
    transport_binding: str,
    current_manifest_hash: str,
) -> bytes:
    output = bytearray()
    for value in (
        "nfcauth-v3-auth",
        service_origin,
        service_id,
        credential_id,
        authentication_profile,
        str(key_epoch),
        nonce,
        transport_binding,
        current_manifest_hash,
    ):
        encoded = value.encode("utf-8")
        output.extend(struct.pack(">I", len(encoded)))
        output.extend(encoded)
    return bytes(output)


def derive_rotated_key(
    current_key: bytes,
    service_id: str,
    credential_id: str,
    authentication_profile: str,
    current_epoch: int,
    nonce: str,
) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(nonce),
        info=(
            f"nfcauth-v3-key-update|{service_id}|{credential_id}|{authentication_profile}|{current_epoch + 1}"
        ).encode(),
    ).derive(current_key)


def encrypt_key_commit(
    manifest: dict,
    credential_id: str,
    new_key: bytes,
    new_epoch: int,
    rotation_id: str,
) -> dict:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    encrypted = _encrypt_json(
        {
            "protocol_version": PROTOCOL_VERSION,
            "status": "authentication-succeeded",
            "service_id": service_id,
            "credential_id": credential_id,
            "authentication_profile": profile,
            "key_epoch": new_epoch,
            "rotation_id": rotation_id,
        },
        new_key,
        _aad("key-commit", service_id, credential_id, profile, new_epoch),
    )
    return {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "credential_id": credential_id,
        "authentication_profile": profile,
        "key_epoch": new_epoch,
        **encrypted,
    }


def decrypt_key_commit(
    envelope: dict,
    manifest: dict,
    credential_id: str,
    new_key: bytes,
    new_epoch: int,
) -> dict:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    _require_identity(envelope, service_id, credential_id, profile, new_epoch)
    return _decrypt_json(
        envelope,
        new_key,
        _aad("key-commit", service_id, credential_id, profile, new_epoch),
    )


def encrypt_key_commit_ack(
    manifest: dict,
    credential_id: str,
    new_key: bytes,
    new_epoch: int,
    rotation_id: str,
) -> dict:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    encrypted = _encrypt_json(
        {
            "protocol_version": PROTOCOL_VERSION,
            "status": "key-commit-acknowledged",
            "service_id": service_id,
            "credential_id": credential_id,
            "authentication_profile": profile,
            "key_epoch": new_epoch,
            "rotation_id": rotation_id,
        },
        new_key,
        _aad("key-commit-ack", service_id, credential_id, profile, new_epoch),
    )
    return {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "credential_id": credential_id,
        "authentication_profile": profile,
        "key_epoch": new_epoch,
        **encrypted,
    }


def decrypt_key_commit_ack(
    envelope: dict,
    manifest: dict,
    credential_id: str,
    new_key: bytes,
    new_epoch: int,
) -> dict:
    service_id = manifest["service_id"]
    profile = manifest["authentication_profile"]
    _require_identity(envelope, service_id, credential_id, profile, new_epoch)
    return _decrypt_json(
        envelope,
        new_key,
        _aad("key-commit-ack", service_id, credential_id, profile, new_epoch),
    )


def public_key_fingerprint_from_manifest(manifest: dict) -> str:
    key = serialization.load_der_public_key(base64.b64decode(manifest["encryption_public_key"], validate=True))
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("Service encryption key must be EC")
    return public_key_fingerprint(key)


def _require_identity(
    envelope: dict,
    service_id: str,
    credential_id: str,
    profile: str,
    key_epoch: int,
) -> None:
    if (
        envelope.get("protocol_version") != PROTOCOL_VERSION
        or envelope.get("service_id") != service_id
        or envelope.get("credential_id") != credential_id
        or envelope.get("authentication_profile") != profile
        or envelope.get("key_epoch") != key_epoch
    ):
        raise ValueError("Credential envelope identity mismatch")


def _aad(
    purpose: str,
    service_id: str,
    credential_id: str,
    profile: str,
    epoch: int,
    suffix: str = "",
) -> str:
    base = f"nfcauth-v3|{purpose}|{service_id}|{credential_id}|{profile}|{epoch}"
    return f"{base}|{suffix}" if suffix else base


def _encrypt_json(document: dict, key: bytes, aad: str) -> dict:
    iv = secrets.token_bytes(12)
    plaintext = json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode()
    ciphertext = AESGCM(key).encrypt(iv, plaintext, aad.encode())
    return {
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def _decrypt_json(envelope: dict, key: bytes, aad: str) -> dict:
    iv = base64.b64decode(envelope["iv"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    if len(iv) != 12 or len(ciphertext) <= 16:
        raise ValueError("Encrypted payload is malformed")
    plaintext = AESGCM(key).decrypt(iv, ciphertext, aad.encode())
    return json.loads(plaintext)
