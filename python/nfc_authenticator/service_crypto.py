"""End-to-end service encryption inside the ephemeral NFC transport."""

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


def decrypt_registration_response(
    envelope: dict,
    signed_manifest: dict,
    encryption_private_key: ec.EllipticCurvePrivateKey,
) -> tuple[dict, bytes]:
    manifest = signed_manifest["manifest"]
    expected_hash = manifest_hash(manifest)
    service_id = manifest["service_id"]
    if (
        envelope.get("protocol_version") != PROTOCOL_VERSION
        or envelope.get("service_id") != service_id
        or envelope.get("manifest_hash") != expected_hash
    ):
        raise ValueError("Registration response identity mismatch")

    phone_public_key = serialization.load_der_public_key(
        base64.b64decode(envelope["phone_ephemeral_public_key"], validate=True)
    )
    if not isinstance(phone_public_key, ec.EllipticCurvePublicKey) or not isinstance(
        phone_public_key.curve, ec.SECP256R1
    ):
        raise ValueError("Phone registration key must use P-256")
    shared_secret = encryption_private_key.exchange(ec.ECDH(), phone_public_key)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(expected_hash),
        info=f"nfcauth-v2-session|{service_id}".encode(),
    ).derive(shared_secret)
    plaintext = _decrypt_json(
        envelope,
        session_key,
        f"nfcauth-v2|registration-response|{service_id}|{expected_hash}",
    )
    if (
        plaintext.get("protocol_version") != PROTOCOL_VERSION
        or plaintext.get("service_id") != service_id
        or plaintext.get("registration_nonce") != manifest["registration_nonce"]
    ):
        raise ValueError("Registration response challenge mismatch")
    return plaintext, session_key


def encrypt_registration_acknowledgement(
    service_id: str,
    registration_nonce: str,
    current_manifest_hash: str,
    session_key: bytes,
) -> dict:
    encrypted = _encrypt_json(
        {
            "status": "registered",
            "service_id": service_id,
            "registration_nonce": registration_nonce,
        },
        session_key,
        f"nfcauth-v2|registration-ack|{service_id}|{current_manifest_hash}",
    )
    return {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "manifest_hash": current_manifest_hash,
        **encrypted,
    }


def encrypt_authentication_request(
    service_id: str,
    encryption_public_key: ec.EllipticCurvePublicKey,
    session_key: bytes,
    nonce: str,
    auth_mode: str,
) -> tuple[dict, dict]:
    request = {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "nonce": nonce,
        "auth": auth_mode,
    }
    encrypted = _encrypt_json(
        request,
        session_key,
        f"nfcauth-v2|authentication-request|{service_id}",
    )
    envelope = {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": service_id,
        "encryption_key_fingerprint": public_key_fingerprint(encryption_public_key),
        **encrypted,
    }
    return envelope, request


def decrypt_authentication_response(
    envelope: dict,
    service_id: str,
    encryption_public_key: ec.EllipticCurvePublicKey,
    session_key: bytes,
) -> dict:
    if (
        envelope.get("protocol_version") != PROTOCOL_VERSION
        or envelope.get("service_id") != service_id
        or envelope.get("encryption_key_fingerprint")
        != public_key_fingerprint(encryption_public_key)
    ):
        raise ValueError("Authentication response identity mismatch")
    return _decrypt_json(
        envelope,
        session_key,
        f"nfcauth-v2|authentication-response|{service_id}",
    )


def authentication_signature_payload(
    service_id: str,
    nonce: str,
    auth_mode: str,
    user_id: str,
) -> bytes:
    output = bytearray()
    for value in ("nfcauth-v2-auth", service_id, nonce, auth_mode, user_id):
        encoded = value.encode("utf-8")
        output.extend(struct.pack(">I", len(encoded)))
        output.extend(encoded)
    return bytes(output)


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
